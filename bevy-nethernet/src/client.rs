//! LAN client: discovers servers by UDP broadcast and connects to one by network id.
use crate::connection::ConnectionEvent;
use crate::outbound::{ClientIceConfig, EstablishedClient, Outbound, Received};
use crate::socket::recv_discovery;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{IceMode, Timeouts};
use nethernet::identity::verify_answer;
use nethernet::prelude::{
    LanSignaler, LanSignalerConfig, LanSignalerError, LanSignalerInput, LanSignalerOutput, Sans,
    ServerData, ServerIdentity, SignalErrorCode, TokenTrust,
};
use nethernet::protocol::constants::{LAN_DISCOVERY_PORT, MAX_DATAGRAM_SIZE};
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::{Channel, TurnCredentials};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

const MAX_DATAGRAMS_PER_TICK: usize = 1024;
const DEFAULT_ATTEMPTS: u32 = 3;

pub struct NetherClientPlugin;

impl Plugin for NetherClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherClientSet)
                .run_if(resource_exists::<NetherClient>),
        );
    }
}

impl NetherClientPlugin {
    fn update(mut client: ResMut<NetherClient>, mut events: MessageWriter<NetherClientEvent>) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

/// Set holding the system that polls sockets and emits events.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherClientSet;

/// ServerDiscovered carries the server's network id and data; Connected and Disconnected track the one connection.
#[derive(Message, Clone, Debug)]
pub enum NetherClientEvent {
    ServerDiscovered(u64, Box<ServerData>),
    Connected,
    Disconnected,
}

#[derive(Resource)]
pub struct NetherClient {
    signaler: LanSignaler,
    socket: UdpSocket,
    transport: Option<Outbound>,
    ice_config: Option<ClientIceConfig>,
    connected: bool,
    connecting_deadline: Option<Instant>,
    answered: bool,
    timeouts: Timeouts,
    attempts: u32,
    attempts_left: u32,
    target: u64,
    established: Option<EstablishedClient>,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    identity: Option<ServerIdentity>,
    server_trust: Option<TokenTrust>,
    received: Received,
    events: VecDeque<NetherClientEvent>,
    buf: Box<[u8]>,
}

impl NetherClient {
    /// Broadcasts discovery to the default port; conf adjusts the LAN signaler config.
    pub fn new<T>(network_id: u64, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut LanSignalerConfig),
    {
        let mut config = LanSignalerConfig {
            broadcast_address: Some(SocketAddr::new(
                Ipv4Addr::BROADCAST.into(),
                LAN_DISCOVERY_PORT,
            )),
            ..LanSignalerConfig::default()
        };
        conf(&mut config);

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            transport: None,
            ice_config: None,
            connected: false,
            connecting_deadline: None,
            answered: false,
            timeouts: Timeouts::default(),
            attempts: DEFAULT_ATTEMPTS,
            attempts_left: 0,
            target: 0,
            established: None,
            remote_addr: None,
            rtt: None,
            identity: None,
            server_trust: None,
            received: Received::default(),
            events: VecDeque::new(),
            buf: vec![0u8; MAX_DATAGRAM_SIZE].into_boxed_slice(),
        })
    }

    pub fn discovered(&self) -> &HashMap<u64, ServerData> {
        self.signaler.discovered()
    }

    /// Signs outgoing offers with this identity.
    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    /// Configures numeric UDP STUN/TURN for subsequent attempts. LAN signaling sends candidates incrementally.
    /// `None` preserves host-only operation; each attempt owns an exclusive UDP socket.
    pub fn set_ice_config(&mut self, config: Option<ClientIceConfig>) {
        self.ice_config = config;
    }

    /// Renews an active allocation's password with the original absolute monotonic expiry.
    /// A different username needs a fresh connection. Configuration for retries is changed separately.
    pub fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: TurnCredentials,
    ) -> Result<(), nethernet::error::ProtocolError> {
        self.transport_mut()
            .ok_or_else(|| nethernet::error::ProtocolError::Other("not connected".into()))?
            .update_turn_credentials(server, credentials, Instant::now())
    }

    /// How the server's answer is authenticated; `None`, the default, accepts any answer.
    /// When set, an answer without a valid identity ends the attempt with Disconnected.
    pub fn set_server_trust(&mut self, trust: Option<TokenTrust>) {
        self.server_trust = trust;
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    /// Offers made when negotiation times out; 0 counts as 1.
    pub fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts;
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

    /// Starts negotiating; Connected follows once the data channels open.
    pub fn connect(&mut self, target_network_id: u64) -> std::io::Result<()> {
        self.retire_transport(false);
        self.connected = false;
        self.connecting_deadline = None;
        self.remote_addr = None;
        self.rtt = None;
        self.received = Received::default();
        self.target = target_network_id;
        self.attempts_left = self.attempts.max(1);
        self.begin_attempt()
    }

    fn begin_attempt(&mut self) -> std::io::Result<()> {
        self.attempts_left = self.attempts_left.saturating_sub(1);
        let now = Instant::now();
        let mut transport =
            Outbound::new(self.ice_config.as_ref(), self.timeouts.establish(), now)?;
        let signals = transport
            .connect(rand::random(), self.target.to_string(), IceMode::Trickle)
            .map_err(std::io::Error::other)?;

        let now = Instant::now();
        for mut signal in signals {
            if let (Some(identity), SignalType::Offer) = (&self.identity, signal.signal_type) {
                signal.data = identity
                    .augment(&signal.data, SystemTime::now())
                    .map_err(std::io::Error::other)?;
            }
            self.send_signal(signal, now)
                .map_err(std::io::Error::other)?;
        }

        self.transport = Some(transport);
        self.connected = true;
        self.connecting_deadline = Some(now + self.timeouts.negotiation);
        self.answered = false;
        self.remote_addr = None;
        self.rtt = None;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        let was_ready = self.established.is_some();
        self.received = Received::default();
        self.connecting_deadline = None;
        if self.connected {
            self.retire_transport(false);
            self.connected = false;
        }
        if was_ready {
            self.remote_addr = None;
            self.rtt = None;
            self.events.push_back(NetherClientEvent::Disconnected);
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

    pub fn next_event(&mut self) -> Option<NetherClientEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        for (datagram, addr) in recv_discovery(&self.socket, &mut self.buf, MAX_DATAGRAMS_PER_TICK)
        {
            let _ = self
                .signaler
                .handle(LanSignalerInput::Datagram(datagram, addr, now));
        }

        let _ = self.signaler.handle(LanSignalerInput::Update(now));

        while let Some(output) = self.signaler.poll() {
            match output {
                LanSignalerOutput::Datagram(buf, addr) => {
                    let _ = self.socket.send_to(&buf, addr);
                }
                LanSignalerOutput::ServerDiscovered(id, data) => self
                    .events
                    .push_back(NetherClientEvent::ServerDiscovered(id, data)),
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal, now),
                LanSignalerOutput::Wait(_) => {}
            }
        }

        if !self.connected {
            return;
        }

        if self
            .connecting_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            if !self.answered && self.attempts_left > 0 {
                self.retire_transport(false);
                if self.begin_attempt().is_ok() {
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
        while let Some(signal) = self.transport_mut().and_then(Outbound::poll_local_signal) {
            if self.send_signal(signal, now).is_err() {
                self.fail_connection();
                return;
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
                    self.events.push_back(NetherClientEvent::Connected);
                }
                ConnectionEvent::Ready(_) => {}
                ConnectionEvent::Rtt(rtt) => self.rtt = Some(rtt),
                ConnectionEvent::Message(channel, data) => {
                    let received = match &mut self.established {
                        Some(entry) => &mut entry.received,
                        None => &mut self.received,
                    };
                    if received.push(channel, data).is_err() {
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

    /// Retires the single attempt and prevents late delivery or timers after failure.
    fn fail_connection(&mut self) {
        self.retire_transport(true);
        self.connecting_deadline = None;
        self.connected = false;
        self.remote_addr = None;
        self.rtt = None;
        self.events.push_back(NetherClientEvent::Disconnected);
    }

    /// An undiscovered target stays under the attempt deadline; other carrier errors remain failures.
    fn send_signal(&mut self, signal: Signal, now: Instant) -> Result<(), LanSignalerError> {
        match self.signaler.handle(LanSignalerInput::Signal(signal, now)) {
            Ok(()) | Err(LanSignalerError::UnknownNetwork(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn handle_signal(&mut self, signal: Signal, now: Instant) {
        if signal.signal_type == SignalType::Offer
            || !self.connected
            || signal.network_id != self.target.to_string()
            || self.transport_mut().and_then(Outbound::connection_id) != Some(signal.connection_id)
            || self
                .connecting_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            return;
        }
        if signal.signal_type == SignalType::Answer
            && let Err(e) =
                verify_answer(&signal.data, self.server_trust.as_ref(), SystemTime::now())
        {
            tracing::debug!("refusing an answer with an invalid identity: {e}");
            if !self.answered && self.connecting_deadline.is_some() {
                let refusal = Signal::error(
                    signal.connection_id,
                    SignalErrorCode::FailedToSetRemoteDescription,
                    self.target.to_string(),
                );
                let _ = self.signaler.handle(LanSignalerInput::Signal(refusal, now));
                self.connecting_deadline = None;
                self.retire_transport(false);
                self.connected = false;
                self.events.push_back(NetherClientEvent::Disconnected);
            }
            return;
        }
        if signal.signal_type == SignalType::Answer
            && !self.answered
            && self.connecting_deadline.is_some()
        {
            self.answered = true;
            self.connecting_deadline = Some(now + self.timeouts.establish());
        }
        let kind = signal.signal_type;
        if self
            .transport_mut()
            .is_some_and(|transport| transport.signal(signal, now).is_err())
        {
            if kind == SignalType::Candidate {
                tracing::debug!("discarding a rejected remote candidate");
            } else {
                self.fail_connection();
            }
        }
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
        self.transport = None;
        if let Some(entry) = self.established.take() {
            let received = entry.close();
            if retain_received {
                self.received = received;
            }
        }
    }
}

#[cfg(test)]
#[path = "client/retirement_tests.rs"]
mod retirement_tests;
