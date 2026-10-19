#[cfg(test)]
use super::PoolUpdate;
use super::delivery::Delivery;
use super::{ActiveConnection, PoolEvent, Readiness};
use crate::pending::ServerLimits;
use async_channel::{Receiver, Sender, TryRecvError, TrySendError};
use nethernet::connection::{Connection, ConnectionInput};
use nethernet::error::ProtocolError;
use nethernet::protocol::Signal;
use nethernet::protocol::constants::{
    DEFAULT_COMMAND_CHANNEL_CAPACITY, DEFAULT_PACKET_CHANNEL_CAPACITY,
};
use nethernet::session::{Channel, SessionEvent, SessionOutput};
use nethernet::util::stun;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_IDLE: Duration = Duration::from_secs(1);
const RTT_REPORT_INTERVAL: Duration = Duration::from_secs(1);

type SharedDelivery<K> = Arc<Mutex<Delivery<K>>>;

enum Command<K> {
    Add(K, Box<Connection>, String, Readiness, Sender<()>),
    Signal(K, Readiness, Signal),
    Send(K, Readiness, Channel, Box<[u8]>),
}

pub(crate) struct SessionPool<K: Clone + Eq> {
    commands: Sender<Command<K>>,
    delivery: SharedDelivery<K>,
    #[cfg(test)]
    worker: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    removed: Option<Arc<Mutex<Vec<K>>>>,
}

impl<K> SessionPool<K>
where
    K: Eq + Hash + Clone + Send + 'static,
{
    pub(crate) fn new(socket: UdpSocket) -> Self {
        let (command_tx, command_rx) = async_channel::bounded(DEFAULT_COMMAND_CHANNEL_CAPACITY);
        let delivery = Arc::new(Mutex::new(Delivery::new()));
        let worker_delivery = delivery.clone();
        let worker = std::thread::Builder::new()
            .name("nethernet-session-pool".to_string())
            .spawn(move || drive(socket, command_rx, worker_delivery))
            .expect("failed to spawn the session pool's thread");
        #[cfg(not(test))]
        let _ = worker;
        Self {
            commands: command_tx,
            delivery,
            #[cfg(test)]
            worker: Some(worker),
            #[cfg(test)]
            removed: None,
        }
    }

    /// Closes and joins this fixture's original worker before observing final assertions.
    #[cfg(test)]
    pub(crate) fn retire_worker(&mut self) {
        self.commands.close();
        if let Some(worker) = self.worker.take() {
            worker.join().expect("the original session worker panicked");
        }
    }

    /// Observes cleanup calls in the existing pure expiry test; it owns no actual core.
    #[cfg(test)]
    pub(crate) fn detached() -> (Self, impl Fn() -> Vec<K>) {
        let (commands, _) = async_channel::bounded(DEFAULT_COMMAND_CHANNEL_CAPACITY);
        let removed = Arc::new(Mutex::new(Vec::new()));
        let observed = removed.clone();
        (
            Self {
                commands,
                delivery: Arc::new(Mutex::new(Delivery::new())),
                worker: None,
                removed: Some(removed),
            },
            move || std::mem::take(&mut *observed.lock().unwrap()),
        )
    }

    /// New limits gate admission without evicting the original accepted prefix.
    pub(crate) fn set_limits(&mut self, limits: ServerLimits) {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_limits(limits);
    }

    /// Performs the same reservation preflight before an incoming offer allocates an answer.
    pub(crate) fn admits(&self, id: &K) -> bool {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admits(id)
    }

    /// Reserves final ownership before the original worker can acknowledge this allocation.
    pub(crate) fn add(
        &mut self,
        id: K,
        connection: Connection,
        local_ufrag: String,
    ) -> Option<Readiness> {
        let readiness = self
            .delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve(id.clone())?;
        let (ack_tx, ack_rx) = async_channel::bounded(1);
        if self
            .commands
            .try_send(Command::Add(
                id,
                Box::new(connection),
                local_ufrag,
                readiness.clone(),
                ack_tx,
            ))
            .is_err()
            || ack_rx.recv_blocking().is_err()
        {
            self.delivery
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .abandon(&readiness);
            return None;
        }
        Some(readiness)
    }

    /// Cleanup seals the exact allocation even when all command slots are occupied.
    pub(crate) fn remove(&mut self, id: K, readiness: Readiness) {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retire(&readiness);
        #[cfg(test)]
        if let Some(removed) = &self.removed {
            removed.lock().unwrap().push(id);
        }
        #[cfg(not(test))]
        let _ = id;
    }

    /// Lost mandatory signaling retires only its original entry, not the shared worker.
    pub(crate) fn signal(&mut self, id: K, signal: &Signal) {
        let readiness = self
            .delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .readiness(&id);
        if let Some(readiness) = readiness
            && self
                .commands
                .try_send(Command::Signal(id, readiness.clone(), signal.clone()))
                .is_err()
        {
            self.delivery
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retire(&readiness);
        }
    }

    /// Success admits bounded local work; it does not acknowledge core or remote delivery.
    pub(crate) fn send(
        &mut self,
        id: K,
        readiness: Readiness,
        channel: Channel,
        data: impl AsRef<[u8]>,
    ) -> Result<(), ProtocolError> {
        let data = data.as_ref();
        if data.len() > channel.max_message_size() {
            return Err(ProtocolError::MessageSizeExceeded(data.len()));
        }
        if !self
            .delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&id, &readiness)
        {
            return Err(ProtocolError::Other("unknown session".into()));
        }
        if self.commands.is_closed() {
            return Err(io::Error::from(ErrorKind::BrokenPipe).into());
        }
        if self.commands.is_full() {
            return Err(io::Error::from(ErrorKind::WouldBlock).into());
        }
        // This exclusively borrowed sender is the pool's sole producer. Check capacity before copying.
        self.commands
            .try_send(Command::Send(id, readiness, channel, data.into()))
            .map_err(|error| {
                io::Error::from(match error {
                    TrySendError::Full(_) => ErrorKind::WouldBlock,
                    TrySendError::Closed(_) => ErrorKind::BrokenPipe,
                })
                .into()
            })
    }

    /// Advances only a finite frame of metadata and visibility in the one final delivery owner.
    pub(crate) fn drive(&mut self, events: &mut Vec<PoolEvent<K>>) {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .advance(events, DEFAULT_PACKET_CHANNEL_CAPACITY);
    }

    /// Consumes the same reserved lifecycle record observed by frame processing.
    pub(crate) fn next_event(&mut self) -> Option<PoolEvent<K>> {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next_event()
    }

    /// Observes actual final delivery in the stalled-consumer socket fixture.
    #[cfg(test)]
    pub(crate) fn retained_packets(&self) -> usize {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retained_packets()
    }

    /// Observes cleanup of the original core independently of global worker shutdown.
    #[cfg(test)]
    pub(crate) fn owner_has_finished(&self, readiness: &Readiness) -> bool {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .owner_has_finished(readiness)
    }

    /// Returns the original accepted payload and releases its global retained charge.
    pub(crate) fn recv(&mut self, channel: Channel) -> Option<(K, Box<[u8]>)> {
        self.delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv(channel)
    }
}

impl<K: Clone + Eq> Drop for SessionPool<K> {
    fn drop(&mut self) {
        self.commands.close();
        let mut delivery = self.delivery.lock().unwrap_or_else(PoisonError::into_inner);
        delivery.seal_all();
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

struct Exit<K: Clone + Eq>(SharedDelivery<K>);
impl<K: Clone + Eq> Drop for Exit<K> {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finish_all();
    }
}

/// Releases the original router/core before freeing its reserved delivery admission slot.
fn retire_entry<K: Clone + Eq + Hash>(
    id: &K,
    entries: &mut HashMap<K, Entry>,
    router: &mut Router<K>,
    delivery: &SharedDelivery<K>,
) {
    if let Some(entry) = entries.remove(id) {
        router.release(id, &entry.local_ufrag, entry.remote_addr);
        let readiness = entry.readiness;
        drop(entry.connection);
        delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .owner_finished(&readiness);
    }
}

fn drive<K: Eq + Hash + Clone + Send + 'static>(
    socket: UdpSocket,
    commands: Receiver<Command<K>>,
    delivery: SharedDelivery<K>,
) {
    let _exit = Exit(delivery.clone());
    let mut entries: HashMap<K, Entry> = HashMap::new();
    let mut router = Router::default();
    let mut buf = [0; nethernet::protocol::constants::MAX_DATAGRAM_SIZE];
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
                    if let Some(entry) = entries.get_mut(&id)
                        && !entry.readiness.is_retired()
                        && let Err(error) = entry.connection.handle(ConnectionInput::Packet(
                            buf[..len].into(),
                            from,
                            Instant::now(),
                        ))
                    {
                        tracing::debug!("packet handling error: {error}");
                    }
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => tracing::debug!("recv error: {error}"),
        }
        for _ in 0..DEFAULT_COMMAND_CHANNEL_CAPACITY {
            let now = Instant::now();
            match commands.try_recv() {
                Ok(Command::Add(id, connection, local_ufrag, readiness, ack)) => {
                    if entries
                        .get(&id)
                        .is_some_and(|entry| entry.readiness.is_retired())
                    {
                        retire_entry(&id, &mut entries, &mut router, &delivery);
                    }
                    if readiness.is_retired() || entries.contains_key(&id) {
                        delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .abandon(&readiness);
                        continue;
                    }
                    router.register_ufrag(local_ufrag.clone(), id.clone());
                    entries.insert(
                        id.clone(),
                        Entry {
                            connection: ActiveConnection::new(*connection),
                            readiness: readiness.clone(),
                            local_ufrag,
                            remote_addr: None,
                            wait: now,
                            reported_rtt: None,
                            rtt_reported_at: None,
                        },
                    );
                    if ack.try_send(()).is_err() {
                        retire_entry(&id, &mut entries, &mut router, &delivery);
                        delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .abandon(&readiness);
                    }
                }
                Ok(Command::Signal(id, readiness, signal)) => {
                    if let Some(entry) = entries.get_mut(&id)
                        && entry.readiness.matches(&readiness)
                        && !readiness.is_retired()
                        && let Err(error) = entry
                            .connection
                            .handle(ConnectionInput::Signal(signal, now))
                    {
                        tracing::debug!("signal handling error: {error}");
                    }
                }
                Ok(Command::Send(id, readiness, channel, data)) => {
                    if let Some(entry) = entries.get_mut(&id)
                        && entry.readiness.matches(&readiness)
                        && !readiness.is_retired()
                        && let Err(error) = entry.connection.send(channel, data.into(), now)
                    {
                        tracing::debug!("send error: {error}");
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => return,
            }
        }
        let now = Instant::now();
        let per_entry = (DEFAULT_PACKET_CHANNEL_CAPACITY / entries.len().max(1)).max(1);
        let mut failed = Vec::new();
        for (id, entry) in &mut entries {
            if entry.readiness.is_retired() {
                failed.push(id.clone());
                continue;
            }
            if let Err(error) = entry.connection.handle(ConnectionInput::Timeout(now)) {
                tracing::debug!("timeout handling error: {error}");
            }
            if entry.remote_addr.is_none()
                && let Some(address) = entry.connection.remote_addr()
            {
                entry.remote_addr = Some(address);
                router.claim_addr(address, id);
            }
            for _ in 0..per_entry {
                if entry.readiness.is_retired() {
                    failed.push(id.clone());
                    break;
                }
                let Some(output) = entry.connection.poll() else {
                    break;
                };
                match output {
                    SessionOutput::Send(data, to) => {
                        if entry.remote_addr.is_none() {
                            router.note_sent(to, id);
                        }
                        let _ = socket.send_to(&data, to);
                    }
                    SessionOutput::SendStream(..)
                    | SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                        failed.push(id.clone());
                        break;
                    }
                    SessionOutput::Event(SessionEvent::Ready) => {
                        delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .ready(&entry.readiness, entry.connection.remote_addr());
                    }
                    SessionOutput::Message(channel, data) => {
                        if !delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .message(&entry.readiness, channel, data.into_boxed_slice())
                        {
                            failed.push(id.clone());
                            break;
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
                delivery
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .rtt(&entry.readiness, rtt);
            }
        }
        for id in failed {
            retire_entry(&id, &mut entries, &mut router, &delivery);
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
        let explicitly_retired = std::cell::Cell::new(false);
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
                    PoolUpdate::Ready(_) => {
                        ready.insert(id, readiness);
                    }
                    PoolUpdate::Failed if explicitly_retired.get() && id == 0 => {}
                    PoolUpdate::Failed => panic!("shared-socket client failed"),
                    PoolUpdate::Rtt(_) => {}
                }
            }
            while let Some((id, data)) = pool.recv(Channel::Reliable) {
                received.push((id, data.into_vec()));
            }
            while pool.next_event().is_some() {}
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
        assert!(
            pool.send(
                0,
                ready.get(&1).unwrap().clone(),
                Channel::Reliable,
                &b"foreign Ready"[..],
            )
            .is_err()
        );
        for id in 0..2u8 {
            pool.send(
                id,
                ready.get(&id).unwrap().clone(),
                Channel::Reliable,
                vec![id; 20 * 1024],
            )
            .unwrap();
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
        explicitly_retired.set(true);
        pool.remove(0, ready.get(&0).unwrap().clone());
        pool.send(
            1,
            ready.get(&1).unwrap().clone(),
            Channel::Reliable,
            &b"survivor"[..],
        )
        .unwrap();
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
