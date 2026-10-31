//! HTTP signaling client polled once per frame, with status queries and joins.
use crate::connection::ConnectionEvent;
use crate::http_stream::{Drain, HttpStream};
use crate::http_wire;
use crate::outbound::{ClientIceConfig, EstablishedClient, Outbound, Received, prepare_turn_tls};
use crate::tcp_wire::{ClientTls, Inbound};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{IceMode, Timeouts};
use nethernet::error::ProtocolError;
use nethernet::identity::{TokenTrust, verify_answer};
use nethernet::prelude::ServerData;
use nethernet::prelude::ServerIdentity;
use nethernet::protocol::Signal;
use nethernet::session::{Channel, TurnCredentials, TurnStreamRoute};
pub use nethernet::signaling::http::join::ClientInfo;
use nethernet::signaling::http::join::{self, StatusResponseError};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Advances an HTTP client and publishes its connection messages in `PreUpdate`.
pub struct NetherHttpClientPlugin;

impl Plugin for NetherHttpClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherHttpClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherHttpClientSet)
                .run_if(resource_exists::<NetherHttpClient>),
        );
    }
}

impl NetherHttpClientPlugin {
    fn update(
        mut client: ResMut<NetherHttpClient>,
        mut events: MessageWriter<NetherHttpClientEvent>,
    ) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

/// Set holding the system that polls sockets and emits events.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherHttpClientSet;

/// ConnectFailed covers a rejected join and a session that closes before opening; Disconnected only an open one.
#[derive(Message, Debug)]
pub enum NetherHttpClientEvent {
    Connected,
    ConnectFailed,
    Disconnected,
    ServerData(Box<ServerData>),
    QueryFailed(QueryError),
}

/// Why a status query produced no server data.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("the connection to the server failed")]
    Connection,
    #[error("the server did not answer in time")]
    TimedOut,
    #[error(transparent)]
    Response(#[from] StatusResponseError),
}

/// A server URL that cannot be joined; converts to an InvalidInput io error.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("the server url has no scheme")]
    MissingScheme,
    #[error("only http and https server urls are supported")]
    UnsupportedScheme,
    #[error("the server url has no host")]
    MissingHost,
    #[error("the server url has an invalid port")]
    InvalidPort,
    #[error("https joins need the tls feature")]
    TlsUnavailable,
    #[cfg(feature = "tls")]
    #[error("the server url host is not a valid tls server name")]
    InvalidServerName,
    #[cfg(feature = "tls")]
    #[error("tls setup failed: {0}")]
    Tls(#[from] rustls::Error),
}

impl From<JoinError> for std::io::Error {
    fn from(error: JoinError) -> Self {
        std::io::Error::new(ErrorKind::InvalidInput, error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JoinTarget {
    secure: bool,
    host: String,
    port: u16,
    authority: String,
}

impl JoinTarget {
    fn parse(url: &str) -> Result<Self, JoinError> {
        let (scheme, rest) = url.split_once("://").ok_or(JoinError::MissingScheme)?;
        let (secure, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "http" => (false, 80),
            "https" => (true, 443),
            _ => return Err(JoinError::UnsupportedScheme),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host_and_port = authority.rsplit('@').next().unwrap_or_default();
        let (host, port_text) = match host_and_port.strip_prefix('[') {
            Some(bracketed) => {
                let (host, after) = bracketed.split_once(']').ok_or(JoinError::MissingHost)?;
                (host, after.strip_prefix(':'))
            }
            None => match host_and_port.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_and_port, None),
            },
        };
        if host.is_empty() {
            return Err(JoinError::MissingHost);
        }
        let port = match port_text {
            Some(text) => text.parse().map_err(|_| JoinError::InvalidPort)?,
            None => default_port,
        };
        Ok(Self {
            secure,
            host: host.to_string(),
            port,
            authority: host_and_port.to_string(),
        })
    }
}

enum JoinState {
    Sending(HttpStream),
    Receiving(HttpStream),
}

impl JoinState {
    fn sending(mut stream: HttpStream, request: &[u8]) -> Self {
        stream.queue(request);
        Self::Sending(stream)
    }
}

enum JoinStep {
    Pending(JoinState),
    Done(u16, String),
    Failed,
}

fn drive_join(state: JoinState) -> JoinStep {
    match state {
        JoinState::Sending(mut stream) => match stream.drain() {
            Ok(Drain::Blocked | Drain::Partial) => JoinStep::Pending(JoinState::Sending(stream)),
            Ok(Drain::Complete | Drain::Empty) => JoinStep::Pending(JoinState::Receiving(stream)),
            Err(_) => JoinStep::Failed,
        },
        JoinState::Receiving(mut stream) => match stream.fill() {
            Ok(Inbound::Closed) | Err(_) => JoinStep::Failed,
            Ok(Inbound::Idle) => JoinStep::Pending(JoinState::Receiving(stream)),
            Ok(Inbound::Received) => match http_wire::ResponseReader::parse(&stream.inbound) {
                Ok(http_wire::Parsed::Complete(response)) => {
                    let (parts, body) = response.into_parts();
                    match http_wire::TextBody::decode(body) {
                        Ok(body) => JoinStep::Done(parts.status.as_u16(), body),
                        Err(_) => JoinStep::Failed,
                    }
                }
                Ok(http_wire::Parsed::Partial) if stream.inbound.len() > http_wire::MAX_BODY => {
                    JoinStep::Failed
                }
                Ok(http_wire::Parsed::Partial) => JoinStep::Pending(JoinState::Receiving(stream)),
                Err(_) => JoinStep::Failed,
            },
        },
    }
}

struct Join {
    state: JoinState,
    server_url: String,
    connection_id: u64,
}

struct Gathering {
    target: JoinTarget,
    addr: SocketAddr,
}

struct Query {
    state: JoinState,
    deadline: Instant,
}

const DEFAULT_ATTEMPTS: u32 = 3;

/// Queries a known HTTP endpoint and owns one outbound connection.
#[derive(Resource)]
pub struct NetherHttpClient {
    join: Option<Join>,
    query: Option<Query>,
    transport: Option<Outbound>,
    gathering: Option<Gathering>,
    ice_config: Option<ClientIceConfig>,
    max_incoming_message_bytes: usize,
    turn_tls: ClientTls,
    connected: bool,
    connecting_deadline: Option<Instant>,
    timeouts: Timeouts,
    attempts: u32,
    attempts_left: u32,
    local_network_id: String,
    client_info: ClientInfo,
    server_url: String,
    join_target: Option<(JoinTarget, SocketAddr)>,
    established: Option<EstablishedClient>,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    identity: Option<ServerIdentity>,
    server_trust: Option<TokenTrust>,
    tls: ClientTls,
    events: VecDeque<NetherHttpClientEvent>,
    received: Received,
}

impl Default for NetherHttpClient {
    fn default() -> Self {
        Self {
            join: None,
            query: None,
            transport: None,
            gathering: None,
            ice_config: None,
            max_incoming_message_bytes:
                nethernet::protocol::constants::DEFAULT_MAX_INCOMING_MESSAGE_BYTES,
            turn_tls: ClientTls::default(),
            connected: false,
            connecting_deadline: None,
            timeouts: Timeouts::default(),
            attempts: DEFAULT_ATTEMPTS,
            attempts_left: 0,
            local_network_id: rand::random::<u64>().to_string(),
            client_info: ClientInfo::default(),
            server_url: String::new(),
            join_target: None,
            established: None,
            remote_addr: None,
            rtt: None,
            identity: None,
            server_trust: None,
            tls: ClientTls::default(),
            events: VecDeque::new(),
            received: Received::default(),
        }
    }
}

impl NetherHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects optional game metadata for subsequent status queries.
    pub fn set_client_info(&mut self, info: ClientInfo) {
        self.client_info = info;
    }

    /// Selects the complete incoming body limit for future attempts, leaving active ones unchanged.
    /// Zero refuses nonempty bodies; final delivery budgets remain independent.
    pub fn set_max_incoming_message_size(&mut self, maximum: usize) {
        self.max_incoming_message_bytes = maximum;
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    /// Configures numeric UDP STUN/TURN gathering for subsequent attempts. `None` keeps host-only operation.
    /// HTTP carries Full ICE: all gathering completes before the offer is encoded and signed.
    /// Prepares its TURN TLS policy before replacing the targets; failure preserves the old pair.
    /// This explicit setup may load platform trust. Frame-driven attempts perform no TLS setup.
    pub fn set_ice_config(&mut self, config: Option<ClientIceConfig>) -> std::io::Result<()> {
        let turn_tls = prepare_turn_tls(config.as_ref())?;
        self.ice_config = config;
        self.turn_tls = turn_tls;
        Ok(())
    }

    /// Renews an active allocation's password with its original absolute monotonic expiry.
    /// A different username requires a fresh connection. Configuration for retries is changed separately.
    pub fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: TurnCredentials,
    ) -> Result<(), ProtocolError> {
        self.transport_mut()
            .ok_or_else(|| ProtocolError::Other("not connected".into()))?
            .update_turn_credentials(server, credentials, Instant::now())
    }

    /// The original selected stream tuple; direct, UDP, unselected and retired paths return `None`.
    /// This observation neither drives I/O nor grants sending capability.
    pub fn selected_turn_stream(&mut self) -> Option<TurnStreamRoute> {
        self.transport_mut()
            .and_then(Outbound::selected_turn_stream)
    }

    /// Renews only the allocation on this exact actual stream, including colocated UDP/TCP/TLS.
    /// The core preserves its original username, credential expiry and authenticated lease rules.
    /// Success is local Refresh admission; it does not acknowledge the server response.
    pub fn update_turn_stream_credentials(
        &mut self,
        route: TurnStreamRoute,
        credentials: TurnCredentials,
    ) -> Result<(), ProtocolError> {
        self.transport_mut()
            .ok_or_else(|| ProtocolError::Other("not connected".into()))?
            .update_turn_stream_credentials(route, credentials, Instant::now())
    }

    /// How the server's answer is authenticated; `None`, the default, accepts any answer.
    /// When set, an answer without a valid identity ends the join with ConnectFailed.
    pub fn set_server_trust(&mut self, trust: Option<TokenTrust>) {
        self.server_trust = trust;
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    /// Sends GET /v1/join; the result arrives as ServerData or QueryFailed.
    pub fn query_server_data(&mut self, url: &str) -> std::io::Result<()> {
        let path = self
            .client_info
            .status_path(&self.local_network_id)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidInput, error))?;
        let (target, addr) = Self::resolve(url)?;
        self.tls.prepare(target.secure)?;
        let stream = self.open_stream(&target, addr)?;
        let request = http_wire::RequestWriter::get(&target.authority, &path)
            .map_err(std::io::Error::other)?;
        self.query = Some(Query {
            state: JoinState::sending(stream, &request),
            deadline: Instant::now() + self.timeouts.negotiation,
        });
        Ok(())
    }

    fn resolve(url: &str) -> std::io::Result<(JoinTarget, SocketAddr)> {
        let target = JoinTarget::parse(url)?;
        let addr = (target.host.as_str(), target.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "could not resolve host"))?;
        Ok((target, addr))
    }

    fn update_query(&mut self, now: Instant) {
        let Some(query) = self.query.take() else {
            return;
        };
        let Query { state, deadline } = query;
        match drive_join(state) {
            JoinStep::Pending(_) if now >= deadline => self
                .events
                .push_back(NetherHttpClientEvent::QueryFailed(QueryError::TimedOut)),
            JoinStep::Pending(state) => self.query = Some(Query { state, deadline }),
            JoinStep::Done(code, body) => self.events.push_back(
                match join::validate_status_response(code, body.as_bytes()) {
                    Ok(data) => NetherHttpClientEvent::ServerData(Box::new(data)),
                    Err(e) => NetherHttpClientEvent::QueryFailed(e.into()),
                },
            ),
            JoinStep::Failed => self
                .events
                .push_back(NetherHttpClientEvent::QueryFailed(QueryError::Connection)),
        }
    }

    /// Offers made when negotiation times out.
    pub fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts;
    }

    /// TLS settings for https URLs; needs the tls feature.
    #[cfg(feature = "tls")]
    pub fn set_tls_config(&mut self, config: Arc<rustls::ClientConfig>) {
        self.tls = ClientTls::with_config(config);
    }

    pub fn is_connected(&self) -> bool {
        self.established.is_some()
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// The id names this client in the join path; the URL is http(s) and its port defaults to 80 or 443.
    /// Initial HTTP hostname resolution and TLS configuration are synchronous setup; subsequent frame updates perform neither.
    pub fn connect(&mut self, local_network_id: String, server_url: String) -> std::io::Result<()> {
        self.join = None;
        self.retire_transport(false);
        self.gathering = None;
        self.connected = false;
        self.connecting_deadline = None;
        self.join_target = None;
        self.remote_addr = None;
        self.rtt = None;
        self.received = Received::default();

        self.local_network_id = local_network_id;
        self.server_url = server_url;
        let (target, addr) = Self::resolve(&self.server_url)?;
        self.tls.prepare(target.secure)?;
        self.join_target = Some((target, addr));
        self.attempts_left = self.attempts.max(1);
        let now = Instant::now();
        if let Err(error) = self.begin_join(now) {
            self.join = None;
            self.retire_transport(false);
            self.gathering = None;
            self.connecting_deadline = None;
            return Err(error);
        }
        Ok(())
    }

    /// Starts finite gathering. Numeric ICE endpoints never invoke DNS in the frame update.
    fn begin_join(&mut self, now: Instant) -> std::io::Result<()> {
        self.attempts_left = self.attempts_left.saturating_sub(1);
        let (target, addr) = self.join_target.clone().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "join target is not configured")
        })?;
        let mut transport = Outbound::new(
            self.ice_config.as_ref(),
            self.timeouts.establish(),
            now,
            &self.turn_tls,
        )?;
        transport
            .set_max_incoming_message_size(self.max_incoming_message_bytes)
            .map_err(std::io::Error::other)?;
        self.transport = Some(transport);
        self.gathering = Some(Gathering { target, addr });
        self.connecting_deadline = Some(now + self.timeouts.negotiation);
        self.start_gathered_join()
    }

    /// Encodes and signs the final Full offer only after the pure core completed gathering.
    fn start_gathered_join(&mut self) -> std::io::Result<()> {
        let complete = self
            .transport_mut()
            .is_some_and(Outbound::gathering_complete);
        if !complete {
            return Ok(());
        }
        let Some(Gathering { target, addr }) = self.gathering.take() else {
            return Ok(());
        };
        let connection_id = rand::random();
        let server_url = self.server_url.clone();
        let signals = self
            .transport_mut()
            .expect("transport checked above")
            .connect(connection_id, server_url, IceMode::Full)
            .map_err(std::io::Error::other)?;
        let offer = signals
            .into_iter()
            .next()
            .expect("Connection::connect returns an offer first");
        let offer_data = match &self.identity {
            Some(identity) => identity
                .augment(&offer.data, SystemTime::now())
                .map_err(std::io::Error::other)?,
            None => offer.data,
        };
        let request = http_wire::RequestWriter::post(
            &target.authority,
            &join::join_path(&self.local_network_id),
            join::CONTENT_TYPE,
            &offer_data,
        )
        .map_err(std::io::Error::other)?;
        let stream = self.open_stream(&target, addr)?;
        self.join = Some(Join {
            state: JoinState::sending(stream, &request),
            server_url: self.server_url.clone(),
            connection_id,
        });
        Ok(())
    }

    fn open_stream(&self, target: &JoinTarget, addr: SocketAddr) -> std::io::Result<HttpStream> {
        self.tls
            .dial(target.secure, &target.host, addr, None)
            .map(HttpStream::connecting)
    }

    pub fn disconnect(&mut self) {
        let was_ready = self.established.is_some();
        self.received = Received::default();
        self.join_target = None;
        self.join = None;
        self.retire_transport(false);
        self.gathering = None;
        self.connected = false;
        self.connecting_deadline = None;
        if was_ready {
            self.remote_addr = None;
            self.rtt = None;
            self.events.push_back(NetherHttpClientEvent::Disconnected);
        }
    }

    /// Borrows the actual transport owner created by Ready; pending discovery has no send capability.
    pub fn established(&mut self) -> Option<&mut EstablishedClient> {
        self.established.as_mut()
    }

    pub fn recv(&mut self) -> Option<Box<[u8]>> {
        match &mut self.established {
            Some(entry) => entry.recv(),
            None => self.received.pop(Channel::Reliable),
        }
    }

    pub fn recv_unreliable(&mut self) -> Option<Box<[u8]>> {
        match &mut self.established {
            Some(entry) => entry.recv_unreliable(),
            None => self.received.pop(Channel::Unreliable),
        }
    }

    pub fn next_event(&mut self) -> Option<NetherHttpClientEvent> {
        self.events.pop_front()
    }

    /// Advances nonblocking HTTP/UDP work once per frame. Call regularly to meet core deadlines.
    pub fn update(&mut self) {
        let now = Instant::now();
        self.update_query(now);
        if self
            .connecting_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            if !self.connected && self.attempts_left > 0 {
                self.join = None;
                self.gathering = None;
                self.retire_transport(false);
                if self.begin_join(now).is_ok() {
                    return;
                }
            }
            self.fail_connection();
            return;
        }
        if self
            .transport_mut()
            .is_some_and(|transport| transport.update(now).is_err())
        {
            self.fail_connection();
            return;
        }
        if self.start_gathered_join().is_err() {
            self.fail_connection();
            return;
        }
        if let Some(mut attempt) = self.join.take() {
            match drive_join(attempt.state) {
                JoinStep::Pending(state) => {
                    attempt.state = state;
                    self.join = Some(attempt);
                }
                JoinStep::Done(code, body) => {
                    let valid = join::validate_join_response(code, &body).is_ok()
                        && verify_answer(&body, self.server_trust.as_ref(), SystemTime::now())
                            .is_ok();
                    let answer = Signal::answer(attempt.connection_id, body, attempt.server_url);
                    if valid
                        && self
                            .transport_mut()
                            .is_some_and(|transport| transport.signal(answer, now).is_ok())
                    {
                        self.connected = true;
                        self.connecting_deadline = Some(now + self.timeouts.establish());
                    } else {
                        self.fail_connection();
                        return;
                    }
                }
                JoinStep::Failed => {
                    self.fail_connection();
                    return;
                }
            }
        }
        while let Some(event) = self.transport_mut().and_then(Outbound::poll_event) {
            match event {
                ConnectionEvent::Ready(addr) if self.established.is_none() => {
                    let transport = self
                        .transport
                        .take()
                        .expect("Ready retains its original pending transport");
                    self.established = Some(EstablishedClient {
                        transport,
                        received: std::mem::take(&mut self.received),
                    });
                    self.remote_addr = addr;
                    self.connecting_deadline = None;
                    self.events.push_back(NetherHttpClientEvent::Connected);
                }
                ConnectionEvent::Ready(_) => {}
                ConnectionEvent::Rtt(rtt) => self.rtt = Some(rtt),
                ConnectionEvent::Message(channel, data) => {
                    let received = match &mut self.established {
                        Some(entry) => &mut entry.received,
                        None => &mut self.received,
                    };
                    if let Err(data) = received.push(channel, data) {
                        self.transport_mut()
                            .expect("the original transport retains rejected promotion")
                            .retain_rejected_message(channel, data);
                        self.fail_connection();
                        return;
                    }
                }
                ConnectionEvent::Failed => {
                    self.fail_connection();
                    return;
                }
            }
        }
    }

    /// Retires HTTP, socket, allocation and delivery ownership together, reporting one terminal transition.
    fn fail_connection(&mut self) {
        let was_ready = self.established.is_some();
        self.join = None;
        self.gathering = None;
        self.retire_transport(true);
        self.connected = false;
        self.connecting_deadline = None;
        self.remote_addr = None;
        self.rtt = None;
        self.events.push_back(if was_ready {
            NetherHttpClientEvent::Disconnected
        } else {
            NetherHttpClientEvent::ConnectFailed
        });
    }
    /// Lets actual wire controls observe core ACK completion after the original public update.
    #[cfg(test)]
    pub(crate) fn test_gathering_complete(&mut self) -> bool {
        self.transport_mut()
            .is_some_and(Outbound::test_gathering_complete)
    }

    /// Drives the same exclusive socket in either phase; only the ready entry exposes send publicly.
    fn transport_mut(&mut self) -> Option<&mut Outbound> {
        match &mut self.established {
            Some(entry) => Some(&mut entry.transport),
            None => self.transport.as_mut(),
        }
    }

    /// Consumes the actual ready owner, retaining accepted data only for retrospective failure reads.
    fn retire_transport(&mut self, retain_received: bool) {
        let pending = self.transport.take();
        if let Some(entry) = self.established.take() {
            let received = entry.close();
            if retain_received {
                self.received = received;
            }
        }
        if retain_received && let Some(transport) = pending {
            self.received.retain_transport(transport.retire());
        }
    }
}

#[cfg(test)]
#[path = "http_client/retirement_tests.rs"]
mod retirement_tests;

#[cfg(test)]
#[path = "http_client/query_tests.rs"]
mod query_tests;
