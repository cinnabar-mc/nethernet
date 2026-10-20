//! HTTP signaling server polled once per frame, with sessions over a shared UDP socket.
use crate::connection::{PoolEvent, PoolUpdate, Readiness, SessionPool};
use crate::http_stream::{Drain, HttpStream, ServerTls, Shutdown};
use crate::http_wire;
use crate::pending::{PendingLimits, ServerLimits, admits_offer};
use crate::server::{EstablishedSessionId, NetherSessionId};
use crate::socket::bind_shared_socket;
use crate::tcp_wire::Inbound;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use http::{Response, StatusCode};
use nethernet::admission::{Answered, OfferPolicy};
use nethernet::connection::{IceMode, Timeouts};
use nethernet::prelude::{
    HttpSignaler, HttpSignalerConfig, HttpSignalerInput, HttpSignalerOutput, Offer, PlayerInfo,
    RejectReason, Sans, ServerData, ServerIdentity, TokenTrust,
};
use nethernet::session::Channel;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_ACCEPTS_PER_TICK: usize = 64;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct NetherHttpServerPlugin;

impl Plugin for NetherHttpServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherHttpServerEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherHttpServerSet)
                .run_if(resource_exists::<NetherHttpServer>),
        );
    }
}

impl NetherHttpServerPlugin {
    fn update(
        mut server: ResMut<NetherHttpServer>,
        mut events: MessageWriter<NetherHttpServerEvent>,
    ) {
        server.update();

        while let Some(event) = server.next_event() {
            events.write(event);
        }
    }
}

/// Set holding the system that polls sockets and emits events.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherHttpServerSet;

/// SessionConnected fires once both data channels are open; SessionDisconnected when the session ends.
#[derive(Message, Clone, Debug)]
pub enum NetherHttpServerEvent {
    SessionConnected(EstablishedSessionId),
    SessionDisconnected(NetherSessionId),
}

struct TcpConn {
    stream: HttpStream,
    close_after_write: bool,
    requested: bool,
    last_active: Instant,
}

impl TcpConn {
    fn refuse(&mut self, status: StatusCode) {
        let response = Response::builder()
            .status(status)
            .body(String::new())
            .expect("a status and an empty body are always a valid response");
        self.stream
            .queue(&http_wire::ResponseWriter::encode(&response));
        self.close_after_write = true;
        self.stream.inbound.clear();
    }
}

struct SessionEntry {
    ready: Option<EstablishedSessionId>,
    readiness: Readiness,
    created: Instant,
    answer: Option<String>,
    answer_deadline: Instant,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    player: Option<Arc<PlayerInfo>>,
    host: Option<String>,
}

#[derive(Resource)]
pub struct NetherHttpServer {
    listener: TcpListener,
    signaler: HttpSignaler,
    pool: SessionPool<NetherSessionId>,
    session_local_addr: SocketAddr,
    identity: Option<ServerIdentity>,
    warned_missing_identity: bool,
    allow_unsigned_answers: bool,
    warned_unsigned_answers: bool,
    infer_peer_candidates: bool,
    pending_limits: PendingLimits,
    max_incoming_message_bytes: usize,
    timeouts: Timeouts,
    idle_timeout: Duration,
    tls: ServerTls,
    next_conn_id: u64,
    connections: HashMap<u64, TcpConn>,
    sessions: HashMap<NetherSessionId, SessionEntry>,
}

impl NetherHttpServer {
    /// Each TCP connection serves one request and is closed after the response; conf adjusts the HTTP signaler config.
    pub fn bind<T>(bind_addr: SocketAddr, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut HttpSignalerConfig),
    {
        let mut config = HttpSignalerConfig::default();
        conf(&mut config);

        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;

        let (session_socket, session_local_addr) = bind_shared_socket()?;

        Ok(Self {
            listener,
            signaler: HttpSignaler::new(config),
            pool: SessionPool::new(session_socket),
            session_local_addr,
            identity: None,
            warned_missing_identity: false,
            allow_unsigned_answers: false,
            warned_unsigned_answers: false,
            infer_peer_candidates: true,
            pending_limits: PendingLimits::default(),
            max_incoming_message_bytes:
                nethernet::protocol::constants::DEFAULT_MAX_INCOMING_MESSAGE_BYTES,
            timeouts: Timeouts::default(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            tls: ServerTls::default(),
            next_conn_id: 0,
            connections: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Time without traffic before a TCP connection is dropped; defaults to 30 seconds.
    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = idle_timeout;
    }

    /// Signs answers, which the vanilla client requires (guide section 5.2).
    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    /// Without an identity, answers joins unsigned instead of refusing with 503; vanilla clients refuse them.
    pub fn allow_unsigned_answers(&mut self, allow: bool) {
        self.allow_unsigned_answers = allow;
    }

    /// Serves HTTPS; needs the tls feature.
    #[cfg(feature = "tls")]
    pub fn set_tls(&mut self, tls: Arc<rustls::ServerConfig>) {
        self.tls = ServerTls::with_config(tls);
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    pub fn set_pending_limits(&mut self, limits: PendingLimits) {
        self.pending_limits = limits;
    }

    /// Selects the complete incoming body limit for future offers; existing allocations retain theirs.
    /// Zero refuses nonempty bodies; final delivery budgets remain independent.
    pub fn set_max_incoming_message_size(&mut self, maximum: usize) {
        self.max_incoming_message_bytes = maximum;
    }

    /// Bounds all sessions and final retained payloads together; accepted prefixes are preserved.
    pub fn set_session_limits(&mut self, limits: ServerLimits) {
        self.pool.set_limits(limits);
    }

    /// Adds candidates from the request's source address when an offer has no routable host candidate.
    pub fn set_infer_peer_candidates(&mut self, infer: bool) {
        self.infer_peer_candidates = infer;
    }

    pub fn set_server_data(&mut self, data: ServerData) {
        let _ = self
            .signaler
            .handle(HttpSignalerInput::SetServerData(Box::new(data)));
    }

    /// Replaces how later offers are authenticated; `None` skips validation.
    pub fn set_token_trust(&mut self, trust: Option<TokenTrust>) {
        let _ = self
            .signaler
            .handle(HttpSignalerInput::SetTokenTrust(trust));
    }

    pub fn sessions(&self) -> impl Iterator<Item = &EstablishedSessionId> {
        self.sessions
            .values()
            .filter_map(|entry| entry.ready.as_ref())
    }

    pub fn player(&self, id: &EstablishedSessionId) -> Option<Arc<PlayerInfo>> {
        self.established_entry(id)?.player.clone()
    }

    /// The Host header of the request that opened the session.
    pub fn host(&self, id: &EstablishedSessionId) -> Option<&str> {
        self.established_entry(id)?.host.as_deref()
    }

    pub fn rtt(&self, id: &EstablishedSessionId) -> Option<Duration> {
        self.established_entry(id)?.rtt
    }

    pub fn remote_addr(&self, id: &EstablishedSessionId) -> Option<SocketAddr> {
        self.established_entry(id)?.remote_addr
    }

    /// Admits bounded local work; full capacity returns `Io(WouldBlock)` before copying payloads.
    /// Success is not a transmission or peer acknowledgement.
    pub fn send(
        &mut self,
        id: &EstablishedSessionId,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(id, Channel::Reliable, data)
    }

    /// Admits bounded local work; full capacity returns `Io(WouldBlock)` before copying payloads.
    /// Success is not a transmission or peer acknowledgement.
    pub fn send_unreliable(
        &mut self,
        id: &EstablishedSessionId,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(id, Channel::Unreliable, data)
    }

    fn send_on(
        &mut self,
        id: &EstablishedSessionId,
        channel: Channel,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        if self.established_entry(id).is_none() {
            return Err(nethernet::error::ProtocolError::Other(
                "unknown session".to_string(),
            ));
        }
        self.pool
            .send(id.id.clone(), id.readiness.clone(), channel, data)
    }

    pub fn recv(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.pool.recv(Channel::Reliable)
    }

    pub fn recv_unreliable(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.pool.recv(Channel::Unreliable)
    }

    /// Consumes this local established capability, never a replacement's descriptive id.
    pub fn disconnect(&mut self, id: EstablishedSessionId) {
        if self.established_entry(&id).is_some() {
            self.remove_session(&id.id);
        }
    }

    /// Matches the exact original Ready entry before metadata or application send access.
    fn established_entry(&self, id: &EstablishedSessionId) -> Option<&SessionEntry> {
        if id.readiness.is_retired() {
            return None;
        }
        let entry = self.sessions.get(&id.id)?;
        entry
            .ready
            .as_ref()
            .filter(|current| current.same_entry(id))?;
        Some(entry)
    }

    /// Keeps pending retirement internal and separate from established send authority.
    fn remove_session(&mut self, id: &NetherSessionId) {
        if let Some(entry) = self.sessions.remove(id) {
            self.pool.remove(id.clone(), entry.readiness);
        }
    }

    pub fn next_event(&mut self) -> Option<NetherHttpServerEvent> {
        loop {
            let PoolEvent {
                id,
                event,
                readiness,
            } = self.pool.next_event()?;
            match event {
                PoolUpdate::Ready(_) => {
                    return Some(NetherHttpServerEvent::SessionConnected(
                        EstablishedSessionId { id, readiness },
                    ));
                }
                PoolUpdate::Failed => return Some(NetherHttpServerEvent::SessionDisconnected(id)),
                PoolUpdate::Rtt(_) => {}
            }
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        self.accept(now);
        self.pump_connections(now);

        let _ = self.signaler.handle(HttpSignalerInput::Update(now));

        self.drive_signaling(now);
        self.publish_answers(now);
        self.drive_signaling(now);

        self.drive_sessions();

        let idle_timeout = self.idle_timeout;
        let idle: Vec<u64> = self
            .connections
            .iter()
            .filter(|(_, conn)| now.saturating_duration_since(conn.last_active) >= idle_timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in idle {
            self.connections.remove(&id);
            let _ = self.signaler.handle(HttpSignalerInput::Closed(id));
        }
        let establish = self.timeouts.establish();
        self.sessions.retain(|id, entry| {
            let keep =
                entry.ready.is_some() || now.saturating_duration_since(entry.created) < establish;
            if !keep {
                self.pool.remove(id.clone(), entry.readiness.clone());
            }
            keep
        });
    }

    /// Applies the original signaler's responses without a second response queue.
    fn drive_signaling(&mut self, now: Instant) {
        while let Some(output) = self.signaler.poll() {
            self.handle_output(output, now);
        }
    }

    /// Commits an answer only after worker admission while the original HTTP join still exists.
    fn publish_answers(&mut self, now: Instant) {
        let mut failed = Vec::new();
        for (id, entry) in &mut self.sessions {
            if entry.answer.is_none() {
                continue;
            }
            if entry.readiness.is_retired() || now >= entry.answer_deadline {
                failed.push(id.clone());
                continue;
            }
            if !entry.readiness.is_admitted() {
                continue;
            }
            let sdp = entry
                .answer
                .take()
                .expect("the original answer remains staged");
            if self
                .signaler
                .handle(HttpSignalerInput::Answer {
                    connection_id: id.connection_id,
                    sdp,
                })
                .is_err()
            {
                failed.push(id.clone());
            }
        }
        for id in failed {
            let _ = self.signaler.handle(HttpSignalerInput::Reject {
                connection_id: id.connection_id,
                reason: RejectReason::Unavailable,
            });
            self.remove_session(&id);
        }
    }

    fn accept(&mut self, now: Instant) {
        for _ in 0..MAX_ACCEPTS_PER_TICK {
            let (stream, _addr) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            let _ = stream.set_nonblocking(true);

            let id = self.next_conn_id;
            self.next_conn_id += 1;

            self.connections.insert(
                id,
                TcpConn {
                    stream: self.tls.accept(stream),
                    close_after_write: false,
                    requested: false,
                    last_active: now,
                },
            );
            let _ = self
                .signaler
                .handle(HttpSignalerInput::Connected(id, peer, now));
        }
    }

    fn pump_connections(&mut self, now: Instant) {
        let mut closed = Vec::new();
        let mut requests = Vec::new();

        for (&id, conn) in self.connections.iter_mut() {
            if !conn.stream.has_outbound() && conn.close_after_write {
                if conn.stream.close() == Shutdown::Done {
                    closed.push(id);
                }
                continue;
            }

            match conn.stream.drain() {
                Err(_) => {
                    closed.push(id);
                    continue;
                }
                Ok(Drain::Empty | Drain::Blocked) => {}
                Ok(Drain::Partial) => conn.last_active = now,
                Ok(Drain::Complete) => {
                    conn.last_active = now;
                    if conn.close_after_write {
                        if conn.stream.close() == Shutdown::Done {
                            closed.push(id);
                        }
                        continue;
                    }
                }
            }

            match conn.stream.fill() {
                Ok(Inbound::Closed) | Err(_) => {
                    closed.push(id);
                    continue;
                }
                Ok(Inbound::Received) => conn.last_active = now,
                Ok(Inbound::Idle) => {}
            }

            if matches!(conn.stream.establish(), Ok(Inbound::Closed) | Err(_))
                || conn.stream.flush().is_err()
            {
                closed.push(id);
                continue;
            }

            if conn.requested {
                conn.stream.inbound.clear();
                continue;
            }

            match http_wire::RequestReader::parse(&conn.stream.inbound) {
                Ok(http_wire::Parsed::Complete(request)) => {
                    let request = match http_wire::TextBody::request(*request) {
                        Ok(request) => request,
                        Err(error) => {
                            tracing::debug!("refusing an unreadable http request: {error}");
                            conn.refuse(StatusCode::BAD_REQUEST);
                            continue;
                        }
                    };
                    conn.stream.inbound.clear();
                    conn.requested = true;
                    tracing::debug!(
                        "http request {} {} with {} headers",
                        request.method(),
                        request.uri(),
                        request.headers().len()
                    );
                    requests.push((id, request));
                }
                Ok(http_wire::Parsed::Partial)
                    if conn.stream.inbound.len() > http_wire::MAX_BODY =>
                {
                    conn.refuse(StatusCode::PAYLOAD_TOO_LARGE);
                }
                Ok(http_wire::Parsed::Partial) => {}
                Err(error) => {
                    tracing::debug!("refusing an unreadable http request: {error:?}");
                    conn.refuse(match error {
                        http_wire::RequestError::HeaderCountExceeded => {
                            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                        }
                        http_wire::RequestError::Malformed => StatusCode::BAD_REQUEST,
                        http_wire::RequestError::SizeExceeded => StatusCode::PAYLOAD_TOO_LARGE,
                        http_wire::RequestError::LengthRequired => StatusCode::LENGTH_REQUIRED,
                    });
                }
            }
        }

        for (connection, request) in requests {
            let _ = self.signaler.handle(HttpSignalerInput::Request {
                connection,
                request: Box::new(request),
                now,
                wall: SystemTime::now(),
            });
        }

        for id in closed {
            self.connections.remove(&id);
            let _ = self.signaler.handle(HttpSignalerInput::Closed(id));
        }
    }

    fn handle_output(&mut self, output: HttpSignalerOutput, now: Instant) {
        match output {
            HttpSignalerOutput::Response {
                connection,
                response,
                ..
            } => {
                if let Some(conn) = self.connections.get_mut(&connection) {
                    conn.stream
                        .queue(&http_wire::ResponseWriter::encode(&response));
                    conn.close_after_write = true;
                }
            }
            HttpSignalerOutput::Close(connection) => {
                if let Some(conn) = self.connections.get_mut(&connection) {
                    conn.close_after_write = true;
                }
            }
            HttpSignalerOutput::Offer(offer) => self.handle_offer(*offer, now),
            HttpSignalerOutput::Wait(_) => {}
        }
    }

    fn handle_offer(&mut self, offer: Offer, now: Instant) {
        if self.identity.is_none() {
            if !self.allow_unsigned_answers {
                if !self.warned_missing_identity {
                    self.warned_missing_identity = true;
                    tracing::warn!(
                        "refusing joins with 503 until NetherHttpServer::set_identity is called"
                    );
                }
                let _ = self.signaler.handle(HttpSignalerInput::Reject {
                    connection_id: offer.connection_id,
                    reason: RejectReason::Unavailable,
                });
                return;
            }
            if !self.warned_unsigned_answers {
                self.warned_unsigned_answers = true;
                tracing::warn!("answering joins without an identity; vanilla clients refuse these");
            }
        }
        let pending = self
            .sessions
            .iter()
            .filter(|(_, entry)| entry.ready.is_none());
        let pending = pending.map(|(id, _)| id.network_id.as_str());
        let id = NetherSessionId {
            network_id: offer.network_id.clone(),
            connection_id: offer.connection_id,
        };
        if !self.pool.admits(&id) || !admits_offer(pending, &offer.network_id, self.pending_limits)
        {
            tracing::debug!(
                "Refusing offer from {}: pending offers exceed the limit",
                offer.network_id
            );
            let _ = self.signaler.handle(HttpSignalerInput::Reject {
                connection_id: offer.connection_id,
                reason: RejectReason::Unavailable,
            });
            return;
        }

        let mut policy = OfferPolicy::new(IceMode::Full)
            .with_max_incoming_message_size(self.max_incoming_message_bytes)
            .with_inferred_peer_candidates(self.infer_peer_candidates);
        policy = policy.with_establish_deadline(self.timeouts.establish());
        if let Some(identity) = &self.identity {
            policy = policy.with_identity(identity);
        }

        let signaled_player = offer.player.clone().map(|player| Arc::new(*player));
        let answered = policy
            .admit(&offer.signal(), offer.client_address, SystemTime::now())
            .and_then(|admitted| admitted.answer(self.session_local_addr, rand::random(), now));
        match answered {
            Ok(Answered {
                connection,
                signals,
                local_ufrag,
                player,
                ..
            }) => {
                let Some(answer) = signals.into_iter().next() else {
                    let _ = self.signaler.handle(HttpSignalerInput::Reject {
                        connection_id: offer.connection_id,
                        reason: RejectReason::Unavailable,
                    });
                    return;
                };
                let readiness = (answer.data.len() <= http_wire::MAX_BODY)
                    .then(|| self.pool.add(id.clone(), connection, local_ufrag))
                    .flatten();
                let Some(readiness) = readiness else {
                    let _ = self.signaler.handle(HttpSignalerInput::Reject {
                        connection_id: offer.connection_id,
                        reason: RejectReason::Unavailable,
                    });
                    return;
                };
                self.sessions.insert(
                    id,
                    SessionEntry {
                        ready: None,
                        readiness,
                        created: now,
                        answer: Some(answer.data),
                        answer_deadline: now + self.timeouts.establish(),
                        remote_addr: None,
                        rtt: None,
                        player: player.map(Arc::new).or(signaled_player),
                        host: offer.host,
                    },
                );
            }
            Err(e) => {
                tracing::debug!("Refusing offer from {}: {}", offer.network_id, e);
                let _ = self.signaler.handle(HttpSignalerInput::Reject {
                    connection_id: offer.connection_id,
                    reason: RejectReason::from(e.code()),
                });
            }
        }
    }

    fn drive_sessions(&mut self) {
        let mut events = Vec::new();
        self.pool.drive(&mut events);

        let mut failed = Vec::new();
        for PoolEvent {
            id,
            event,
            readiness,
        } in events
        {
            let Some(entry) = self.sessions.get_mut(&id) else {
                continue;
            };
            if !entry.readiness.matches(&readiness) {
                continue;
            }
            match event {
                PoolUpdate::Ready(addr) if entry.ready.is_none() => {
                    let capability = EstablishedSessionId {
                        id: id.clone(),
                        readiness,
                    };
                    entry.ready = Some(capability.clone());
                    entry.remote_addr = addr;
                }
                PoolUpdate::Ready(_) => {}
                PoolUpdate::Rtt(rtt) => entry.rtt = Some(rtt),
                PoolUpdate::Failed => failed.push(id),
            }
        }

        for id in failed {
            self.remove_session(&id);
        }
    }
}
