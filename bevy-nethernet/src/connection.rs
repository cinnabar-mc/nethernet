use async_channel::{Receiver, Sender, TryRecvError};
use nethernet::connection::{Connection, ConnectionInput};
use nethernet::error::ProtocolError;
use nethernet::phase::{Connecting, Established};
use nethernet::protocol::Signal;
use nethernet::sans::Sans;
use nethernet::session::{Channel, SessionEvent, SessionOutput};
use nethernet::util::stun;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);

const MAX_IDLE: Duration = Duration::from_secs(1);

const RTT_REPORT_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) enum ConnectionEvent {
    Ready(Option<SocketAddr>),
    Rtt(Duration),
    Message(Channel, Box<[u8]>),
    Failed,
}

/// Identity of one actual pool entry, carried only by its Ready event.
#[derive(Clone, Debug)]
pub(crate) struct Readiness(Arc<()>);

impl Readiness {
    /// Creates the identity of this concrete pool allocation before its original Add acknowledgement.
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    /// Matches an original entry, so reused peer ids and other pools cannot accept stale sends.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub(crate) struct PoolEvent<K> {
    pub id: K,
    pub event: ConnectionEvent,
    pub readiness: Readiness,
}

/// The frame edge owns the actual typed core as readiness arrives asynchronously.
pub(crate) enum ActiveConnection {
    Connecting(Option<Connection<Connecting>>),
    Established(Connection<Established>),
}

impl ActiveConnection {
    /// Adopts the original pending allocation without creating another transport.
    pub(crate) fn new(core: Connection<Connecting>) -> Self {
        Self::Connecting(Some(core))
    }

    /// Applies control input to the actual currently owned phase.
    pub(crate) fn handle(&mut self, input: ConnectionInput) -> Result<(), ProtocolError> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .handle(input),
            Self::Established(core) => core.handle(input),
        }
    }

    /// Converts only the same core's actual Ready outcome, preserving the original queue.
    pub(crate) fn poll(&mut self) -> Option<SessionOutput> {
        let output = match self {
            Self::Connecting(core) => core.as_mut().expect("pending core remains owned").poll(),
            Self::Established(core) => core.poll(),
        };
        if matches!(output, Some(SessionOutput::Event(SessionEvent::Ready)))
            && let Self::Connecting(core) = self
        {
            let pending = core.take().expect("pending core transfers once");
            *self = match pending.try_establish() {
                Ok(core) => Self::Established(core),
                Err(core) => {
                    *self = Self::Connecting(Some(core));
                    return Some(SessionOutput::Event(SessionEvent::Failed));
                }
            };
        }
        output
    }

    /// Dispatches only to the actual established core; pending state has no send method.
    pub(crate) fn send(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Established(core) => core.send(channel, data, now),
            Self::Connecting(_) => Err(ProtocolError::Other("channel not open yet".into())),
        }
    }

    /// Borrows the selected route from the same phase-owned core.
    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .remote_addr(),
            Self::Established(core) => core.remote_addr(),
        }
    }

    /// Reports the existing association measurement without changing ownership.
    pub(crate) fn rtt(&self) -> Option<Duration> {
        match self {
            Self::Connecting(core) => core.as_ref().expect("pending core remains owned").rtt(),
            Self::Established(core) => core.rtt(),
        }
    }

    /// Retains exact signaling correlation across the readiness transition.
    pub(crate) fn connection_id(&self) -> u64 {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .connection_id(),
            Self::Established(core) => core.connection_id(),
        }
    }

    /// Drains late candidates once through the existing carrier.
    pub(crate) fn poll_local_signal(&mut self) -> Option<Signal> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .poll_local_signal(),
            Self::Established(core) => core.poll_local_signal(),
        }
    }

    /// Applies credential rotation to the original allocation and absolute expiry owner.
    pub(crate) fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: nethernet::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .update_turn_credentials(server, credentials, now),
            Self::Established(core) => core.update_turn_credentials(server, credentials, now),
        }
    }

    /// Consumes the actual live owner; the caller still drains best-effort teardown output on error.
    pub(crate) fn close(
        self,
        now: Instant,
    ) -> (
        Connection<nethernet::phase::Retired>,
        Result<(), ProtocolError>,
    ) {
        match self {
            Self::Connecting(core) => core.expect("pending core remains owned").close(now),
            Self::Established(core) => core.close(now),
        }
    }
}

enum Command<K> {
    Add(K, Box<Connection>, String, Sender<Readiness>),
    Signal(K, Signal),
    Send(K, Readiness, Channel, Box<[u8]>),
    Remove(K),
}

pub(crate) struct SessionPool<K> {
    commands: Sender<Command<K>>,
    events: Receiver<PoolEvent<K>>,
}

impl<K> SessionPool<K>
where
    K: Eq + Hash + Clone + Send + 'static,
{
    pub(crate) fn new(socket: UdpSocket) -> Self {
        let (command_tx, command_rx) = async_channel::unbounded();
        let (event_tx, event_rx) = async_channel::unbounded();

        std::thread::Builder::new()
            .name("nethernet-session-pool".to_string())
            .spawn(move || drive(socket, command_rx, event_tx))
            .expect("failed to spawn the session pool's thread");

        Self {
            commands: command_tx,
            events: event_rx,
        }
    }

    pub(crate) fn add(
        &mut self,
        id: K,
        connection: Connection,
        local_ufrag: String,
    ) -> Option<Readiness> {
        let (ack_tx, ack_rx) = async_channel::bounded(1);
        let _ = self
            .commands
            .try_send(Command::Add(id, Box::new(connection), local_ufrag, ack_tx));
        ack_rx.recv_blocking().ok()
    }

    #[cfg(test)]
    pub(crate) fn detached() -> (Self, impl Fn() -> Vec<K>) {
        let (command_tx, command_rx) = async_channel::unbounded();
        let (_, event_rx) = async_channel::unbounded();
        let removed = move || {
            std::iter::from_fn(|| command_rx.try_recv().ok())
                .filter_map(|command| match command {
                    Command::Remove(id) => Some(id),
                    _ => None,
                })
                .collect()
        };
        (
            Self {
                commands: command_tx,
                events: event_rx,
            },
            removed,
        )
    }

    pub(crate) fn remove(&mut self, id: K) {
        let _ = self.commands.try_send(Command::Remove(id));
    }

    pub(crate) fn signal(&mut self, id: K, signal: &Signal) {
        let _ = self.commands.try_send(Command::Signal(id, signal.clone()));
    }

    /// Dispatches only to the actual established core; pending state has no send method.
    pub(crate) fn send(&mut self, id: K, readiness: Readiness, channel: Channel, data: Box<[u8]>) {
        let _ = self
            .commands
            .try_send(Command::Send(id, readiness, channel, data));
    }

    pub(crate) fn drive(&mut self, events: &mut Vec<PoolEvent<K>>) {
        loop {
            match self.events.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Closed) => return,
            }
        }
    }
}

struct Entry {
    connection: ActiveConnection,
    readiness: Readiness,
    local_ufrag: String,
    remote_addr: Option<SocketAddr>,
    wait: Instant,
    reported_rtt: Option<Duration>,
    rtt_reported_at: Option<Instant>,
}

fn drive<K: Eq + Hash + Clone>(
    socket: UdpSocket,
    commands: Receiver<Command<K>>,
    events: Sender<PoolEvent<K>>,
) {
    let mut buf = vec![0u8; 65536];
    let mut entries: HashMap<K, Entry> = HashMap::new();
    let mut router: Router<K> = Router::default();

    loop {
        let now = Instant::now();
        let next_wait = entries
            .values()
            .map(|entry| entry.wait.saturating_duration_since(now))
            .min()
            .unwrap_or(MAX_IDLE);
        let timeout = next_wait
            .min(COMMAND_POLL_INTERVAL)
            .max(Duration::from_millis(1));
        if socket.set_read_timeout(Some(timeout)).is_err() {
            return;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                for id in router.route(from, &buf[..len]) {
                    if let Some(entry) = entries.get_mut(&id) {
                        let now = Instant::now();
                        let input = ConnectionInput::Packet(buf[..len].into(), from, now);
                        if let Err(e) = entry.connection.handle(input) {
                            tracing::debug!("packet handling error: {e}");
                        }
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => tracing::debug!("recv error: {e}"),
        }

        loop {
            match commands.try_recv() {
                Ok(Command::Add(id, connection, local_ufrag, ack)) => {
                    router.register_ufrag(local_ufrag.clone(), id.clone());
                    let readiness = Readiness::new();
                    entries.insert(
                        id,
                        Entry {
                            connection: ActiveConnection::new(*connection),
                            readiness: readiness.clone(),
                            local_ufrag,
                            remote_addr: None,
                            wait: Instant::now(),
                            reported_rtt: None,
                            rtt_reported_at: None,
                        },
                    );
                    let _ = ack.try_send(readiness);
                }
                Ok(Command::Remove(id)) => {
                    if let Some(entry) = entries.remove(&id) {
                        router.release(&id, &entry.local_ufrag, entry.remote_addr);
                    }
                }
                Ok(Command::Signal(id, signal)) => {
                    if let Some(entry) = entries.get_mut(&id)
                        && let Err(e) = entry
                            .connection
                            .handle(ConnectionInput::Signal(signal, now))
                    {
                        tracing::debug!("signal handling error: {e}");
                    }
                }
                Ok(Command::Send(id, readiness, channel, data)) => {
                    if let Some(entry) = entries.get_mut(&id)
                        && entry.readiness.matches(&readiness)
                        && let Err(e) = entry.connection.send(channel, data.into(), now)
                    {
                        tracing::debug!("send error: {e}");
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => return,
            }
        }

        let now = Instant::now();
        let mut failed = Vec::new();
        for (id, entry) in entries.iter_mut() {
            if let Err(e) = entry.connection.handle(ConnectionInput::Timeout(now)) {
                tracing::debug!("timeout handling error: {e}");
            }

            if entry.remote_addr.is_none()
                && let Some(addr) = entry.connection.remote_addr()
            {
                entry.remote_addr = Some(addr);
                router.claim_addr(addr, id);
            }

            while let Some(output) = entry.connection.poll() {
                match output {
                    SessionOutput::Send(data, to) => {
                        if entry.remote_addr.is_none() {
                            router.note_sent(to, id);
                        }
                        let _ = socket.send_to(&data, to);
                    }
                    SessionOutput::SendStream(..) => failed.push(id.clone()),
                    SessionOutput::Event(SessionEvent::Ready) => {
                        let ready = ConnectionEvent::Ready(entry.connection.remote_addr());
                        if events
                            .try_send(PoolEvent {
                                id: id.clone(),
                                event: ready,
                                readiness: entry.readiness.clone(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                        failed.push(id.clone())
                    }
                    SessionOutput::Message(channel, data) => {
                        let message = ConnectionEvent::Message(channel, data.into_boxed_slice());
                        if events
                            .try_send(PoolEvent {
                                id: id.clone(),
                                event: message,
                                readiness: entry.readiness.clone(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    SessionOutput::Wait(wait) => entry.wait = now + wait,
                }
            }

            if let Some(rtt) = entry.connection.rtt()
                && entry.reported_rtt != Some(rtt)
                && entry
                    .rtt_reported_at
                    .is_none_or(|at| now.saturating_duration_since(at) >= RTT_REPORT_INTERVAL)
            {
                entry.reported_rtt = Some(rtt);
                entry.rtt_reported_at = Some(now);
                if events
                    .try_send(PoolEvent {
                        id: id.clone(),
                        event: ConnectionEvent::Rtt(rtt),
                        readiness: entry.readiness.clone(),
                    })
                    .is_err()
                {
                    return;
                }
            }
        }

        for id in failed {
            if let Some(entry) = entries.remove(&id) {
                router.release(&id, &entry.local_ufrag, entry.remote_addr);
                if events
                    .try_send(PoolEvent {
                        id,
                        event: ConnectionEvent::Failed,
                        readiness: entry.readiness.clone(),
                    })
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

struct Router<K> {
    by_addr: HashMap<SocketAddr, K>,
    provisional: HashMap<SocketAddr, HashSet<K>>,
    by_ufrag: HashMap<String, K>,
}

impl<K> Default for Router<K> {
    fn default() -> Self {
        Self {
            by_addr: HashMap::new(),
            provisional: HashMap::new(),
            by_ufrag: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash + Clone> Router<K> {
    fn route(&self, from: SocketAddr, datagram: &[u8]) -> Vec<K> {
        if let Some(id) = self.by_addr.get(&from) {
            return vec![id.clone()];
        }
        if !stun::is_stun(datagram) {
            return Vec::new();
        }
        if let Some(ufrag) = stun::local_ufrag(datagram)
            && let Some(id) = self.by_ufrag.get(&ufrag)
        {
            return vec![id.clone()];
        }
        self.provisional
            .get(&from)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn register_ufrag(&mut self, ufrag: String, id: K) {
        self.by_ufrag.insert(ufrag, id);
    }

    fn claim_addr(&mut self, addr: SocketAddr, id: &K) {
        self.by_addr.entry(addr).or_insert_with(|| id.clone());
    }

    fn note_sent(&mut self, addr: SocketAddr, id: &K) {
        self.provisional.entry(addr).or_default().insert(id.clone());
    }

    fn release(&mut self, id: &K, ufrag: &str, addr: Option<SocketAddr>) {
        self.by_ufrag.remove(ufrag);
        if let Some(addr) = addr
            && self.by_addr.get(&addr) == Some(id)
        {
            self.by_addr.remove(&addr);
        }
        self.provisional.retain(|_, ids| {
            ids.remove(id);
            !ids.is_empty()
        });
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use nethernet::connection::IceMode;
    use nethernet::session::Session;
    use std::collections::VecDeque;

    type Outbox = VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn a_second_session_cannot_take_a_claimed_address() {
        let mut router = Router::default();
        router.claim_addr(addr(1), &"victim");
        router.claim_addr(addr(1), &"hostile");

        assert_eq!(router.route(addr(1), &[]), vec!["victim"]);
    }

    #[test]
    fn removing_a_session_leaves_another_sessions_address() {
        let mut router = Router::default();
        router.claim_addr(addr(1), &"victim");
        router.release(&"hostile", "x", Some(addr(1)));

        assert_eq!(router.route(addr(1), &[]), vec!["victim"]);

        router.release(&"victim", "y", Some(addr(1)));
        assert_eq!(router.route(addr(1), &[]), Vec::<&str>::new());
    }

    const BINDING_RESPONSE: [u8; 20] = [
        0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];

    fn sorted(mut ids: Vec<&'static str>) -> Vec<&'static str> {
        ids.sort();
        ids
    }

    #[test]
    fn a_hostile_session_that_noted_an_address_first_does_not_hide_the_reply_from_the_victim() {
        let mut router = Router::default();
        router.note_sent(addr(1), &"hostile");
        router.note_sent(addr(1), &"victim");

        let routed = sorted(router.route(addr(1), &BINDING_RESPONSE));
        assert_eq!(routed, vec!["hostile", "victim"]);
    }

    #[test]
    fn a_non_stun_datagram_from_a_provisional_address_reaches_no_session() {
        let mut router = Router::default();
        router.note_sent(addr(1), &"first");
        router.note_sent(addr(1), &"second");

        assert!(router.route(addr(1), b"dtls or sctp bytes").is_empty());
    }

    #[test]
    fn a_selected_session_receives_non_stun_from_its_selected_address() {
        let mut router = Router::default();
        router.note_sent(addr(1), &"hostile");
        router.claim_addr(addr(1), &"victim");

        assert_eq!(router.route(addr(1), b"dtls or sctp bytes"), vec!["victim"]);
    }

    #[test]
    fn releasing_a_session_removes_only_its_own_provisional_membership() {
        let mut router = Router::default();
        router.note_sent(addr(1), &"first");
        router.note_sent(addr(1), &"second");

        router.release(&"second", "x", None);
        assert_eq!(router.route(addr(1), &BINDING_RESPONSE), vec!["first"]);
        router.release(&"first", "y", None);
        assert!(router.route(addr(1), &BINDING_RESPONSE).is_empty());
        assert!(router.provisional.is_empty());
    }

    struct Peer {
        connection: ActiveConnection,
        router: Router<u8>,
        selected: bool,
        ready: bool,
        local: SocketAddr,
    }

    impl Peer {
        fn new(connection: Connection, ufrag: String, local: SocketAddr) -> Self {
            let mut router = Router::default();
            router.register_ufrag(ufrag, 0);
            Self {
                connection: ActiveConnection::new(connection),
                router,
                selected: false,
                ready: false,
                local,
            }
        }

        fn pump(&mut self, now: Instant, outbox: &mut Outbox) {
            self.connection
                .handle(ConnectionInput::Timeout(now))
                .unwrap();
            if !self.selected
                && let Some(selected) = self.connection.remote_addr()
            {
                self.selected = true;
                self.router.claim_addr(selected, &0);
            }
            while let Some(output) = self.connection.poll() {
                match output {
                    SessionOutput::Send(data, to) => {
                        if !self.selected {
                            self.router.note_sent(to, &0);
                        }
                        outbox.push_back((self.local, to, data));
                    }
                    SessionOutput::Event(SessionEvent::Ready) => self.ready = true,
                    _ => {}
                }
            }
        }

        fn receive(&mut self, from: SocketAddr, data: Vec<u8>, now: Instant) {
            if !self.router.route(from, &data).is_empty() {
                let _ = self
                    .connection
                    .handle(ConnectionInput::Packet(data.into(), from, now));
            }
        }
    }

    #[test]
    fn two_sessions_become_ready_through_the_shared_socket_routing() {
        let mut now = Instant::now();
        let (client_session, client_description) =
            Session::new(addr(40200), true, rand::random(), now).unwrap();
        let client_ufrag = client_description.ice.ufrag.clone();
        let (client, offers) = Connection::connect(
            client_session,
            client_description,
            7,
            "net".to_string(),
            IceMode::Full,
        );
        let offer = offers.into_iter().next().unwrap();

        let (server_session, server_description) =
            Session::new(addr(40201), false, rand::random(), now).unwrap();
        let server_ufrag = server_description.ice.ufrag.clone();
        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let (server, answers) = Connection::accept(
            server_session,
            server_description,
            &offer,
            remote_description,
            remote_candidates,
            IceMode::Full,
            now,
        )
        .unwrap();
        let answer = answers.into_iter().next().unwrap();

        let mut client = Peer::new(client, client_ufrag, addr(40200));
        client
            .connection
            .handle(ConnectionInput::Signal(answer, now))
            .unwrap();
        let mut server = Peer::new(server, server_ufrag, addr(40201));

        let mut outbox = Outbox::new();
        for _ in 0..5000 {
            client.pump(now, &mut outbox);
            server.pump(now, &mut outbox);
            let progressed = !outbox.is_empty();
            while let Some((from, to, data)) = outbox.pop_front() {
                if to == client.local {
                    client.receive(from, data, now);
                } else {
                    server.receive(from, data, now);
                }
            }
            if client.ready && server.ready {
                break;
            }
            if !progressed {
                now += Duration::from_millis(5);
            }
        }

        assert!(client.ready, "client never became ready");
        assert!(server.ready, "server never became ready");
    }

    #[test]
    fn two_secured_sessions_share_one_udp_socket_without_delivery_or_retirement_interference() {
        let socket = UdpSocket::bind(addr(0)).unwrap();
        let local = socket.local_addr().unwrap();
        let mut pool = SessionPool::new(socket);
        let mut peers = Vec::new();
        let now = Instant::now();
        for id in 0..2u8 {
            let socket = UdpSocket::bind(addr(0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let remote = socket.local_addr().unwrap();
            let (session, description) = Session::new(local, true, rand::random(), now).unwrap();
            let ufrag = description.ice.ufrag.clone();
            let (connection, offers) = Connection::connect(
                session,
                description,
                u64::from(id),
                "peer".into(),
                IceMode::Full,
            );
            let offer = offers.into_iter().next().unwrap();
            let (session, description) = Session::new(remote, false, rand::random(), now).unwrap();
            let remote_ufrag = description.ice.ufrag.clone();
            let (remote_description, candidates) = Connection::parse_offer(&offer).unwrap();
            let (peer, answers) = Connection::accept(
                session,
                description,
                &offer,
                remote_description,
                candidates,
                IceMode::Full,
                now,
            )
            .unwrap();
            pool.add(id, connection, ufrag).unwrap();
            for answer in answers {
                pool.signal(id, &answer);
            }
            peers.push((socket, Peer::new(peer, remote_ufrag, remote), Vec::new()));
        }
        let mut ready = HashMap::new();
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buffer = [0; 65536];
        // Socket delivery is real; only this test's finite scheduling loop is caller-driven.
        let mut drive = |pool: &mut SessionPool<u8>,
                         peers: &mut Vec<(UdpSocket, Peer, Vec<Vec<u8>>)>,
                         ready: &mut HashMap<u8, Readiness>,
                         received: &mut Vec<(u8, Vec<u8>)>| {
            let now = Instant::now();
            for (socket, peer, messages) in peers {
                while let Ok((size, from)) = socket.recv_from(&mut buffer) {
                    peer.receive(from, buffer[..size].to_vec(), now);
                }
                peer.connection
                    .handle(ConnectionInput::Timeout(now))
                    .unwrap();
                if !peer.selected
                    && let Some(addr) = peer.connection.remote_addr()
                {
                    peer.selected = true;
                    peer.router.claim_addr(addr, &0);
                }
                while let Some(output) = peer.connection.poll() {
                    match output {
                        SessionOutput::Send(data, to) => {
                            if !peer.selected {
                                peer.router.note_sent(to, &0);
                            }
                            socket.send_to(&data, to).unwrap();
                        }
                        SessionOutput::SendStream(..) => {
                            panic!("host-only pool emitted stream traffic")
                        }
                        SessionOutput::Event(SessionEvent::Ready) => peer.ready = true,
                        SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                            panic!("shared-socket peer failed")
                        }
                        SessionOutput::Message(_, data) => messages.push(data),
                        SessionOutput::Wait(_) => {}
                    }
                }
            }
            let mut events = Vec::new();
            pool.drive(&mut events);
            for PoolEvent {
                id,
                event,
                readiness,
            } in events
            {
                match event {
                    ConnectionEvent::Ready(_) => {
                        ready.insert(id, readiness);
                    }
                    ConnectionEvent::Message(_, data) => received.push((id, data.into_vec())),
                    ConnectionEvent::Failed => panic!("shared-socket client failed"),
                    ConnectionEvent::Rtt(_) => {}
                }
            }
            std::thread::yield_now();
        };
        while Instant::now() < deadline
            && (ready.len() != 2 || peers.iter().any(|(_, peer, _)| !peer.ready))
        {
            drive(&mut pool, &mut peers, &mut ready, &mut received);
        }
        assert_eq!(ready.len(), 2);
        assert!(peers.iter().all(|(_, peer, _)| peer.ready));
        // Actual Ready from another entry must not authorize delivery to this peer.
        pool.send(
            0,
            ready.get(&1).unwrap().clone(),
            Channel::Reliable,
            Box::from(&b"foreign Ready"[..]),
        );
        for id in 0..2u8 {
            pool.send(
                id,
                ready.get(&id).unwrap().clone(),
                Channel::Reliable,
                vec![id; 20 * 1024].into_boxed_slice(),
            );
            peers[usize::from(id)]
                .1
                .connection
                .send(
                    Channel::Reliable,
                    vec![id + 10; 20 * 1024].into(),
                    Instant::now(),
                )
                .unwrap();
        }
        while Instant::now() < deadline
            && (received.len() != 2 || peers.iter().any(|(_, _, messages)| messages.is_empty()))
        {
            drive(&mut pool, &mut peers, &mut ready, &mut received);
        }
        received.sort_by_key(|(id, _)| *id);
        assert_eq!(
            received,
            vec![(0, vec![10; 20 * 1024]), (1, vec![11; 20 * 1024])]
        );
        assert_eq!(peers[0].2, vec![vec![0; 20 * 1024]]);
        assert_eq!(peers[1].2, vec![vec![1; 20 * 1024]]);
        pool.remove(0);
        pool.send(
            1,
            ready.get(&1).unwrap().clone(),
            Channel::Reliable,
            Box::from(&b"survivor"[..]),
        );
        peers[1]
            .1
            .connection
            .send(
                Channel::Reliable,
                (&b"still active"[..]).into(),
                Instant::now(),
            )
            .unwrap();
        // The retired peer's unrelated bytes must not become the survivor's data.
        peers[0].0.send_to(b"retired peer datagram", local).unwrap();
        while Instant::now() < deadline && (received.len() != 3 || peers[1].2.len() != 2) {
            drive(&mut pool, &mut peers, &mut ready, &mut received);
        }
        assert_eq!(received.last(), Some(&(1, b"still active".to_vec())));
        assert_eq!(peers[1].2.last().map(Vec::as_slice), Some(&b"survivor"[..]));
        assert_eq!(peers[0].2.len(), 1);
    }
}
