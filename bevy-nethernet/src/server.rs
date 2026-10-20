//! LAN server: UDP discovery and signaling with sessions polled once per frame.
use crate::connection::{PoolEvent, PoolUpdate, Readiness, SessionPool};
use crate::pending::{PendingLimits, ServerLimits, admits_offer};
use crate::socket::{bind_discovery_socket, bind_shared_socket, recv_discovery, send_discovery};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{IceMode, Timeouts};
use nethernet::error::SignalErrorCode;
use nethernet::prelude::{
    Answered, LanSignaler, LanSignalerConfig, LanSignalerInput, LanSignalerOutput, OfferPolicy,
    PlayerInfo, Sans, ServerData, ServerIdentity, TokenTrust,
};
use nethernet::protocol::constants::{MAX_BYTES, MAX_DATAGRAM_SIZE};
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::Channel;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_DATAGRAMS_PER_TICK: usize = 1024;

pub struct NetherServerPlugin;

impl Plugin for NetherServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherServerEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherServerSet)
                .run_if(resource_exists::<NetherServer>),
        );
    }
}

impl NetherServerPlugin {
    fn update(mut server: ResMut<NetherServer>, mut events: MessageWriter<NetherServerEvent>) {
        server.update();

        while let Some(event) = server.next_event() {
            events.write(event);
        }
    }
}

/// Set holding the system that polls sockets and emits events.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherServerSet;

/// Identifies one session by the peer's network id and the connection id it chose.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetherSessionId {
    pub network_id: String,
    pub connection_id: u64,
}

/// Opaque established capability for one exact Ready pool entry.
/// Copies share remote closure at runtime; descriptive peer ids cannot construct this capability.
///
/// ```compile_fail
/// use bevy_nethernet::prelude::{NetherServer, NetherSessionId};
/// fn unready(server: &mut NetherServer, id: &NetherSessionId) {
///     server.send(id, b"payload");
/// }
/// ```
#[derive(Clone, Debug)]
pub struct EstablishedSessionId {
    pub(crate) id: NetherSessionId,
    pub(crate) readiness: Readiness,
}

impl EstablishedSessionId {
    /// Descriptive correlation only; it does not confer send authority.
    pub fn id(&self) -> &NetherSessionId {
        &self.id
    }
    /// Fences other pools and later reuse of the same descriptive peer id.
    pub(crate) fn same_entry(&self, other: &Self) -> bool {
        self.id == other.id && self.readiness.matches(&other.readiness)
    }
}

/// SessionConnected fires once both data channels are open; SessionDisconnected when the session ends.
#[derive(Message, Clone, Debug)]
pub enum NetherServerEvent {
    SessionConnected(EstablishedSessionId),
    SessionDisconnected(NetherSessionId),
}

struct SessionEntry {
    ready: Option<EstablishedSessionId>,
    readiness: Readiness,
    created: Instant,
    answer: Option<Vec<Signal>>,
    answer_deadline: Instant,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    player: Option<Arc<PlayerInfo>>,
}

#[derive(Resource)]
pub struct NetherServer {
    signaler: LanSignaler,
    socket: UdpSocket,
    pool: SessionPool<NetherSessionId>,
    session_local_addr: SocketAddr,
    identity: Option<ServerIdentity>,
    token_trust: Option<TokenTrust>,
    infer_peer_candidates: bool,
    timeouts: Timeouts,
    pending_limits: PendingLimits,
    max_incoming_message_bytes: usize,
    sessions: HashMap<NetherSessionId, SessionEntry>,
    buf: Box<[u8]>,
}

impl NetherServer {
    /// Binds the discovery socket at bind_addr; conf adjusts the LAN signaler config.
    pub fn new<T>(network_id: u64, bind_addr: SocketAddr, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut LanSignalerConfig),
    {
        let mut config = LanSignalerConfig::default();
        conf(&mut config);

        let socket = bind_discovery_socket(bind_addr)?;

        let (session_socket, session_local_addr) = bind_shared_socket()?;

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            pool: SessionPool::new(session_socket),
            session_local_addr,
            identity: None,
            token_trust: None,
            infer_peer_candidates: true,
            timeouts: Timeouts::default(),
            pending_limits: PendingLimits::default(),
            max_incoming_message_bytes:
                nethernet::protocol::constants::DEFAULT_MAX_INCOMING_MESSAGE_BYTES,
            sessions: HashMap::new(),
            buf: vec![0u8; MAX_DATAGRAM_SIZE].into_boxed_slice(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    /// How offers are authenticated; None skips validation.
    pub fn set_token_trust(&mut self, token_trust: Option<TokenTrust>) {
        self.token_trust = token_trust;
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    /// Adds candidates from the signaling source address when an offer has no routable host candidate.
    pub fn set_infer_peer_candidates(&mut self, infer: bool) {
        self.infer_peer_candidates = infer;
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

    /// Replaces the data advertised to discovery requests.
    pub fn set_server_data(&mut self, data: ServerData) {
        let _ = self
            .signaler
            .handle(LanSignalerInput::SetServerData(Box::new(data)));
    }

    pub fn sessions(&self) -> impl Iterator<Item = &EstablishedSessionId> {
        self.sessions
            .values()
            .filter_map(|entry| entry.ready.as_ref())
    }

    /// Validated identity of the peer, if its offer carried one.
    pub fn player(&self, id: &EstablishedSessionId) -> Option<Arc<PlayerInfo>> {
        self.established_entry(id)?.player.clone()
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

    /// Consumes this local established capability; stale copies cannot close a replacement entry.
    pub fn disconnect(&mut self, id: EstablishedSessionId) {
        if self.established_entry(&id).is_some() {
            self.remove_session(&id.id);
        }
    }

    /// Borrows only the original Ready entry, never a replacement with the same peer ids.
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

    /// Internal retirement remains possible before readiness without exposing send authority.
    fn remove_session(&mut self, id: &NetherSessionId) {
        if let Some(entry) = self.sessions.remove(id) {
            self.pool.remove(id.clone(), entry.readiness);
        }
    }

    pub fn next_event(&mut self) -> Option<NetherServerEvent> {
        loop {
            let PoolEvent {
                id,
                event,
                readiness,
            } = self.pool.next_event()?;
            match event {
                PoolUpdate::Ready(_) => {
                    return Some(NetherServerEvent::SessionConnected(EstablishedSessionId {
                        id,
                        readiness,
                    }));
                }
                PoolUpdate::Failed => return Some(NetherServerEvent::SessionDisconnected(id)),
                PoolUpdate::Rtt(_) => {}
            }
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        for (datagram, addr) in recv_discovery(&self.socket, &mut self.buf, MAX_DATAGRAMS_PER_TICK)
        {
            let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
            let _ = self
                .signaler
                .handle(LanSignalerInput::Datagram(datagram, addr, now));
        }

        let _ = self.signaler.handle(LanSignalerInput::Update(now));

        self.drive_signaling(now);
        self.publish_answers(now);
        self.drive_signaling(now);

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

        expire_unestablished(
            &mut self.sessions,
            &mut self.pool,
            self.timeouts.establish(),
            now,
        );
    }

    /// Drains only the original signaler's outputs, including newly committed answers.
    fn drive_signaling(&mut self, now: Instant) {
        while let Some(output) = self.signaler.poll() {
            match output {
                LanSignalerOutput::Datagram(buf, addr) => {
                    let _ = send_discovery(&self.socket, &buf, addr);
                }
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal, now),
                LanSignalerOutput::ServerDiscovered(..) | LanSignalerOutput::Wait(_) => {}
            }
        }
    }

    /// Publishes each retained answer once, after the same worker acknowledged its original core.
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
            let signals = entry
                .answer
                .take()
                .expect("the original answer remains staged");
            if signals
                .into_iter()
                .try_for_each(|signal| self.signaler.handle(LanSignalerInput::Signal(signal, now)))
                .is_err()
            {
                failed.push(id.clone());
            }
        }
        for id in failed {
            let refusal = Signal::error(
                id.connection_id,
                SignalErrorCode::IncomingConnectionIgnored,
                id.network_id.clone(),
            );
            let _ = self.signaler.handle(LanSignalerInput::Signal(refusal, now));
            self.remove_session(&id);
        }
    }

    fn handle_signal(&mut self, signal: Signal, now: Instant) {
        if signal.signal_type == SignalType::Offer {
            self.handle_offer(signal, now);
            return;
        }

        let id = NetherSessionId {
            network_id: signal.network_id.clone(),
            connection_id: signal.connection_id,
        };
        if self.sessions.contains_key(&id) {
            self.pool.signal(id, &signal);
        }
    }

    fn handle_offer(&mut self, offer: Signal, now: Instant) {
        let id = NetherSessionId {
            network_id: offer.network_id.clone(),
            connection_id: offer.connection_id,
        };
        if self.sessions.contains_key(&id) {
            return;
        }
        let pending = self
            .sessions
            .iter()
            .filter(|(_, entry)| entry.ready.is_none());
        let pending = pending.map(|(id, _)| id.network_id.as_str());
        if !self.pool.admits(&id) || !admits_offer(pending, &offer.network_id, self.pending_limits)
        {
            tracing::debug!(
                "Refusing offer from {}: pending offers exceed the limit",
                offer.network_id
            );
            let code = SignalErrorCode::IncomingConnectionIgnored;
            let signal = Signal::error(offer.connection_id, code, offer.network_id);
            let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
            return;
        }

        let signaled_from = offer
            .network_id
            .parse()
            .ok()
            .and_then(|network_id| self.signaler.address(network_id));
        let mut policy = OfferPolicy::new(IceMode::Trickle)
            .with_max_incoming_message_size(self.max_incoming_message_bytes)
            .with_inferred_peer_candidates(self.infer_peer_candidates);
        policy = policy.with_establish_deadline(self.timeouts.establish());
        if let Some(identity) = &self.identity {
            policy = policy.with_identity(identity);
        }
        if let Some(trust) = &self.token_trust {
            policy = policy.with_token_trust(trust);
        }

        let answered = policy
            .admit(&offer, signaled_from, SystemTime::now())
            .and_then(|admitted| admitted.answer(self.session_local_addr, rand::random(), now));
        let Answered {
            connection,
            signals,
            local_ufrag,
            player,
            ..
        } = match answered {
            Ok(answered) => answered,
            Err(e) => {
                tracing::debug!("Refusing offer from {}: {}", offer.network_id, e);
                let signal = Signal::error(offer.connection_id, e.code(), offer.network_id);
                let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
                return;
            }
        };

        let fits = signals
            .iter()
            .try_fold(MAX_BYTES, |remaining, signal| {
                remaining.checked_sub(signal.to_string().len())
            })
            .is_some();
        let readiness = fits
            .then(|| self.pool.add(id.clone(), connection, local_ufrag))
            .flatten();
        let Some(readiness) = readiness else {
            let refusal = Signal::error(
                offer.connection_id,
                SignalErrorCode::IncomingConnectionIgnored,
                offer.network_id,
            );
            let _ = self.signaler.handle(LanSignalerInput::Signal(refusal, now));
            return;
        };
        self.sessions.insert(
            id,
            SessionEntry {
                ready: None,
                readiness,
                created: now,
                answer: Some(signals),
                answer_deadline: now + self.timeouts.establish(),
                remote_addr: None,
                rtt: None,
                player: player.map(Arc::new),
            },
        );
    }
}

fn expire_unestablished(
    sessions: &mut HashMap<NetherSessionId, SessionEntry>,
    pool: &mut SessionPool<NetherSessionId>,
    establish: Duration,
    now: Instant,
) {
    sessions.retain(|id, entry| {
        let keep =
            entry.ready.is_some() || now.saturating_duration_since(entry.created) < establish;
        if !keep {
            pool.remove(id.clone(), entry.readiness.clone());
        }
        keep
    });
}

#[cfg(test)]
mod expiry_tests {
    use super::*;

    fn entry(ready: bool, created: Instant) -> SessionEntry {
        let readiness = Readiness::new();
        SessionEntry {
            ready: ready.then(|| EstablishedSessionId {
                id: id(0),
                readiness: readiness.clone(),
            }),
            readiness,
            created,
            answer: None,
            answer_deadline: created,
            remote_addr: None,
            rtt: None,
            player: None,
        }
    }

    fn id(connection_id: u64) -> NetherSessionId {
        NetherSessionId {
            network_id: "1".to_string(),
            connection_id,
        }
    }

    #[test]
    fn unestablished_sessions_past_the_deadline_leave_the_pool() {
        let now = Instant::now();
        let establish = Duration::from_secs(5);
        let (mut pool, removed) = SessionPool::detached();
        let mut sessions = HashMap::new();
        sessions.insert(id(1), entry(false, now - Duration::from_secs(10)));
        sessions.insert(id(2), entry(true, now - Duration::from_secs(10)));
        sessions.insert(id(3), entry(false, now));

        expire_unestablished(&mut sessions, &mut pool, establish, now);

        assert_eq!(removed(), vec![id(1)]);
        assert!(!sessions.contains_key(&id(1)));
        assert_eq!(sessions.len(), 2);
    }
}

#[cfg(test)]
mod admission_tests;
