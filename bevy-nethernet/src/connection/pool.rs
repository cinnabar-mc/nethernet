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
    Add(K, Box<Connection>, String, Readiness),
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

    /// Reserves bounded ownership without waiting for the original worker to install this allocation.
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
        if let Err(command) = self.commands.try_send(Command::Add(
            id,
            Box::new(connection),
            local_ufrag,
            readiness.clone(),
        )) {
            drop(command);
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
        let maximum = self
            .delivery
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .max_message_size(&id, &readiness, channel)
            .ok_or_else(|| ProtocolError::Other("unknown session".into()))?;
        if data.len() > maximum {
            return Err(ProtocolError::MessageSizeExceeded(data.len()));
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
    delivery_open: bool,
}

impl Entry {
    /// Bounds original unpolled output independently of lower final delivery configuration.
    fn output_exhausted(&self) -> bool {
        let usage = self.connection.pending_output_usage();
        let limits = ServerLimits::default();
        usage.entries > limits.max_received_packets || usage.bytes > limits.max_received_bytes
    }
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
    socket: &UdpSocket,
    now: Instant,
) {
    if let Some(mut entry) = entries.remove(id) {
        entry.readiness.retire();
        router.release(id, &entry.local_ufrag, entry.remote_addr);
        let readiness = entry.readiness;
        let (mut retired, _result) = entry.connection.close(now);
        let mut remaining = DEFAULT_PACKET_CHANNEL_CAPACITY;
        while let Some(output) = retired.poll() {
            match output {
                SessionOutput::Message(channel, data) if entry.delivery_open => {
                    let bytes = data.into_boxed_slice();
                    entry.delivery_open = delivery
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .retained_message(&readiness, channel, bytes);
                }
                SessionOutput::Send(data, to) if remaining > 0 => {
                    remaining -= 1;
                    let _ = socket.send_to(&data, to);
                }
                _ => {}
            }
        }
        drop(retired);
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
    'worker: loop {
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
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                for id in router.route(from, &buf[..len]) {
                    let exhausted = if let Some(entry) = entries.get_mut(&id)
                        && !entry.readiness.is_retired()
                    {
                        if let Err(error) = entry.connection.handle(ConnectionInput::Packet(
                            buf[..len].into(),
                            from,
                            Instant::now(),
                        )) {
                            tracing::debug!("packet handling error: {error}");
                        }
                        entry.output_exhausted()
                    } else {
                        false
                    };
                    if exhausted {
                        retire_entry(
                            &id,
                            &mut entries,
                            &mut router,
                            &delivery,
                            &socket,
                            Instant::now(),
                        );
                    }
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => tracing::debug!("recv error: {error}"),
        }
        for _ in 0..DEFAULT_COMMAND_CHANNEL_CAPACITY {
            let now = Instant::now();
            match commands.try_recv() {
                Ok(Command::Add(id, connection, local_ufrag, readiness)) => {
                    if entries
                        .get(&id)
                        .is_some_and(|entry| entry.readiness.is_retired())
                    {
                        retire_entry(&id, &mut entries, &mut router, &delivery, &socket, now);
                    }
                    if readiness.is_retired() || entries.contains_key(&id) {
                        drop(connection);
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
                            delivery_open: true,
                        },
                    );
                    if entries.get(&id).is_some_and(Entry::output_exhausted) || !readiness.admit() {
                        retire_entry(&id, &mut entries, &mut router, &delivery, &socket, now);
                        delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .abandon(&readiness);
                    }
                }
                Ok(Command::Signal(id, readiness, signal)) => {
                    let exhausted = if let Some(entry) = entries.get_mut(&id)
                        && entry.readiness.matches(&readiness)
                        && !readiness.is_retired()
                    {
                        if let Err(error) = entry
                            .connection
                            .handle(ConnectionInput::Signal(signal, now))
                        {
                            tracing::debug!("signal handling error: {error}");
                        }
                        entry.output_exhausted()
                    } else {
                        false
                    };
                    if exhausted {
                        retire_entry(&id, &mut entries, &mut router, &delivery, &socket, now);
                    }
                }
                Ok(Command::Send(id, readiness, channel, data)) => {
                    let exhausted = if let Some(entry) = entries.get_mut(&id)
                        && entry.readiness.matches(&readiness)
                        && !readiness.is_retired()
                    {
                        if let Err(error) = entry.connection.send(channel, data.into(), now) {
                            tracing::debug!("send error: {error}");
                        }
                        entry.output_exhausted()
                    } else {
                        false
                    };
                    if exhausted {
                        retire_entry(&id, &mut entries, &mut router, &delivery, &socket, now);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => break 'worker,
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
            if entry.output_exhausted() {
                failed.push(id.clone());
                continue;
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
                        let (Some(reliable), Some(unreliable)) = (
                            entry.connection.max_message_size(Channel::Reliable),
                            entry.connection.max_message_size(Channel::Unreliable),
                        ) else {
                            // Actual Ready records these facts before it enters the core FIFO.
                            continue;
                        };
                        delivery
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .ready(
                                &entry.readiness,
                                entry.connection.remote_addr(),
                                [reliable, unreliable],
                            );
                    }
                    SessionOutput::Message(channel, data) => {
                        let bytes = data.into_boxed_slice();
                        let (accepted, retiring) = {
                            let mut delivery =
                                delivery.lock().unwrap_or_else(PoisonError::into_inner);
                            let retiring = entry.readiness.is_retired();
                            let accepted = if retiring {
                                delivery.retained_message(&entry.readiness, channel, bytes)
                            } else {
                                delivery.message(&entry.readiness, channel, bytes)
                            };
                            (accepted, retiring)
                        };
                        if !accepted {
                            entry.delivery_open = false;
                        }
                        if !accepted || retiring {
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
            retire_entry(&id, &mut entries, &mut router, &delivery, &socket, now);
        }
    }
    let remaining: Vec<_> = entries.keys().cloned().collect();
    for id in remaining {
        retire_entry(
            &id,
            &mut entries,
            &mut router,
            &delivery,
            &socket,
            Instant::now(),
        );
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
mod routing_tests;
