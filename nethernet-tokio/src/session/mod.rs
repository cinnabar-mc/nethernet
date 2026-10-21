//! A connected session driven by one task, with reliable and unreliable channels and peer metadata.
pub(crate) mod command;
pub(crate) mod guard;
mod observation;
pub(crate) mod outgoing;
#[cfg(test)]
mod pressure_observation;
mod receive;
mod send;
mod server;

pub(crate) use command::Command;
pub use observation::RttObservation;
use observation::RttPublisher;
pub use send::{SendPermit, SendReceipt};
pub(crate) use server::{ServerLease, ServerRetirement};

use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::signaling::ClientSignaling;
use crate::transport::ice_io::IceIo;
use bytes::Bytes;
use futures::future::{BoxFuture, pending};
use guard::{ConnectionGuard, transport_now};
use nethernet::connection::{Connection as SansConnection, ConnectionInput};
use nethernet::identity::PlayerInfo;
use nethernet::phase::{Connecting, Established, Live, Phase, Retired};
#[cfg(test)]
use nethernet::sans::Sans;
pub use nethernet::session::Channel;
use nethernet::session::{SessionEvent, SessionOutput};
use outgoing::{CandidateSignaling, signal_send};
use receive::{AdmissionError, Producer, Receiver, Terminal};
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MAX_IDLE: Duration = Duration::from_secs(1);

const PACKET_CHANNEL_CAPACITY: usize =
    nethernet::protocol::constants::DEFAULT_PACKET_CHANNEL_CAPACITY;

struct TaskGuard {
    close_token: CancellationToken,
    task: JoinHandle<()>,
    server: Option<Arc<ServerLease>>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.close_token.cancel();
        self.task.abort();
    }
}

/// Cloneable established send/control capability. Global closure is observed at runtime.
/// Dropping one capability does not revoke another; the unique Session owns local lifecycle.
#[derive(Clone)]
pub struct SessionSender {
    local_addr: Addr,
    remote_addr: Addr,
    command_tx: mpsc::Sender<Command>,
    ready: Option<Ready>,
    rtt: RttObservation,
    #[cfg(test)]
    pressure: pressure_observation::Observation,
    close_token: CancellationToken,
    _guard: Arc<TaskGuard>,
}

/// Unique transport lifecycle owner. Constructors return it only after actual readiness.
/// Consuming close retires this owner while existing receivers keep their accepted FIFO.
///
/// ```compile_fail
/// fn closed(session: nethernet_tokio::Session) {
///     let retired = session.close();
///     let sender = retired.sender();
/// }
/// ```
#[must_use = "retain the session owner through retirement and drain its accepted output"]
pub struct Session<S: Phase = Established> {
    handle: Option<SessionSender>,
    _phase: PhantomData<S>,
}

/// Produced only by the existing actor after the core's actual Ready transition.
#[derive(Clone, Copy)]
pub(crate) struct Ready {
    reliable_maximum: usize,
    unreliable_maximum: usize,
}

/// Incoming accepted messages, followed by EOF on orderly close or one explicit receive error.
pub struct SessionReceiver {
    rx: Receiver,
    // The one already-admitted chunk previously retained by the client's stream reader.
    reader_chunk: Option<Bytes>,
    _guard: Arc<TaskGuard>,
}

impl SessionReceiver {
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        futures::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        if let Some(chunk) = self.reader_chunk.take() {
            return Poll::Ready(Ok(Some(chunk)));
        }
        self.rx.poll_recv(cx)
    }

    /// Moves the existing stream-reader chunk back before its original receive FIFO.
    pub(crate) fn retain_reader_chunk(mut self, chunk: Option<Bytes>) -> Self {
        if let Some(chunk) = chunk {
            assert!(
                self.reader_chunk.is_none(),
                "the stream reader owns only one pending chunk"
            );
            self.reader_chunk = Some(chunk);
        }
        self
    }
}

/// A connected session with its reliable and unreliable receivers.
pub struct AcceptedSession<S: Phase = Established> {
    pub session: Session<S>,
    pub reliable: SessionReceiver,
    pub unreliable: SessionReceiver,
}

impl Session<Connecting> {
    #[cfg(test)]
    pub(crate) fn spawn(
        socket: impl Into<IceIo>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<Ready>,
    ) {
        Self::spawn_with_signaling(socket, connection, local, remote, None)
    }

    /// Retains the concrete signaling owner only when late outgoing candidates can be produced.
    pub(crate) fn spawn_with_signaling(
        socket: impl Into<IceIo>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        signaling: Option<(ClientSignaling, Duration)>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<Ready>,
    ) {
        Self::spawn_owned(
            socket,
            connection,
            local,
            remote,
            signaling.map(|(adapter, within)| CandidateSignaling {
                adapter: adapter.into(),
                within,
                enabled: None,
                service_closed: None,
            }),
            None,
        )
    }

    /// Moves the original server reservation into the same session/receiver lifetime.
    #[cfg(test)]
    pub(crate) fn spawn_for_server(
        socket: impl Into<IceIo>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        lease: Arc<ServerLease>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<Ready>,
    ) {
        Self::spawn_owned(socket, connection, local, remote, None, Some(lease))
    }

    /// Drives configured accepting ICE, gating late candidates behind original answer dispatch.
    pub(crate) fn spawn_for_server_with_signaling(
        socket: impl Into<IceIo>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        lease: Arc<ServerLease>,
        signaling: CandidateSignaling,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<Ready>,
    ) {
        Self::spawn_owned(
            socket,
            connection,
            local,
            remote,
            Some(signaling),
            Some(lease),
        )
    }

    /// Constructs one existing actor without a cancellation gap before installing its owned guard.
    fn spawn_owned(
        socket: impl Into<IceIo>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        signaling: Option<CandidateSignaling>,
        server: Option<Arc<ServerLease>>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<Ready>,
    ) {
        let (command_tx, command_rx) = mpsc::channel(command::COMMAND_CAPACITY);
        let (packet_tx, packet_rx) = receive::channel(Channel::Reliable);
        let (unreliable_tx, unreliable_rx) = receive::channel(Channel::Unreliable);
        let (ready_tx, ready_rx) = oneshot::channel();
        let close_token = CancellationToken::new();
        let rtt = RttObservation::new();
        #[cfg(test)]
        let pressure = pressure_observation::Observation::default();

        let task = Self::drive(
            socket.into(),
            connection,
            command_rx,
            packet_tx,
            unreliable_tx,
            Some(ready_tx),
            close_token.clone(),
            rtt.clone(),
            signaling,
            server.clone(),
            #[cfg(test)]
            pressure.clone(),
        );

        let guard = Arc::new(TaskGuard {
            close_token: close_token.clone(),
            task,
            server,
        });

        let session = Self {
            handle: Some(SessionSender {
                local_addr: local,
                remote_addr: remote,
                command_tx,
                ready: None,
                rtt,
                #[cfg(test)]
                pressure,
                close_token,
                _guard: guard.clone(),
            }),
            _phase: PhantomData,
        };

        (
            session,
            SessionReceiver {
                rx: packet_rx,
                reader_chunk: None,
                _guard: guard.clone(),
            },
            SessionReceiver {
                rx: unreliable_rx,
                reader_chunk: None,
                _guard: guard,
            },
            ready_rx,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn drive(
        io: IceIo,
        connection: SansConnection,
        mut commands: mpsc::Receiver<Command>,
        packet_tx: Producer,
        unreliable_tx: Producer,
        mut ready_tx: Option<oneshot::Sender<Ready>>,
        close_token: CancellationToken,
        rtt_observation: RttObservation,
        signaling: Option<CandidateSignaling>,
        server: Option<Arc<ServerLease>>,
        #[cfg(test)] pressure: pressure_observation::Observation,
    ) -> JoinHandle<()> {
        let mut guard = ConnectionGuard::new(connection, io).with_server_capacity(server);
        let driver_closed = close_token.clone().drop_guard();
        let rtt_publisher = RttPublisher(rtt_observation);
        tokio::spawn(async move {
            let _driver_closed = driver_closed;
            let rtt_observation = rtt_publisher;
            let (connection, io) = guard.parts();
            let mut wake = transport_now();
            let mut outgoing: Option<BoxFuture<'static, Result<()>>> = None;
            let mut remote_addr = None;
            let mut rtt = None;
            let mut player: Option<Arc<PlayerInfo>> = None;
            let mut host: Option<String> = None;
            let mut reliable_open = true;

            let mut candidates_enabled = signaling
                .as_ref()
                .is_none_or(|signaling| signaling.enabled.is_none());
            let terminal = 'drive: loop {
                let admit_commands = !io.blocked(connection.selected_turn_stream());
                tokio::select! {
                    biased;

                    _ = close_token.cancelled() => break Terminal::Eof,
                    _ = async { match signaling.as_ref().and_then(|signaling| signaling.service_closed.as_ref()) { Some(closed) => closed.cancelled().await, None => pending().await } } => break Terminal::Transport,
                    _ = async { match signaling.as_ref().and_then(|signaling| signaling.enabled.as_ref()) { Some(enabled) => enabled.cancelled().await, None => pending().await } }, if !candidates_enabled => { candidates_enabled = true; },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let now = transport_now();
                        if connection.handle(ConnectionInput::Timeout(now)).is_err() { break Terminal::Transport; }
                        wake = now + MAX_IDLE;
                    },
                    result = async {
                        match &mut outgoing { Some(send) => send.await, None => pending().await }
                    } => {
                        outgoing = None;
                        if result.is_err() { break Terminal::Transport; }
                    },
                    received = io.next() => match received {
                        Ok(event) => {
                            if let Some(input) = event.connection(transport_now())
                                && let Err(error) = connection.handle(input) {
                                tracing::debug!(%error, "transport input rejected");
                            }
                        }
                        Err(error) => tracing::debug!(%error, "UDP receive error"),
                    },
                    command = commands.recv(), if admit_commands => match command {
                        #[cfg(test)]
                        Some(Command::QueuedCommands(reply)) => {
                            let _ = reply.send(commands.len());
                        }
                        #[cfg(test)]
                        Some(Command::SelectedTurnStream(reply)) => {
                            let _ = reply.send(connection.selected_turn_stream());
                        }
                        Some(Command::Send(channel, data, deadline, reply)) => {
                            let now = transport_now();
                            let result = if deadline.is_some_and(|deadline| now >= deadline) {
                                Err(NetherError::Timeout)
                            } else if deadline.is_some() && reply.is_closed() {
                                // An abandoned wait may retract only a command not yet admitted.
                                Err(NetherError::ConnectionClosed)
                            } else {
                                connection.send(channel, data, now)
                                    .map_err(NetherError::from)
                            };
                            let _ = reply.send(result);
                        }
                        Some(Command::Signal(signal)) => {
                            if let Err(e) = connection.handle(ConnectionInput::Signal(signal, transport_now())) {
                                tracing::debug!("signal handling error: {e}");
                            }
                        }
                        Some(Command::RemoteAddr(reply)) => {
                            let _ = reply.send(remote_addr);
                        }
                        Some(Command::Rtt(reply)) => {
                            let _ = reply.send(rtt);
                        }
                        Some(Command::SetPlayer(new_player)) => {
                            player = Some(new_player);
                        }
                        Some(Command::Player(reply)) => {
                            let _ = reply.send(player.clone());
                        }
                        Some(Command::SetHost(new_host)) => {
                            host = Some(new_host);
                        }
                        Some(Command::Host(reply)) => {
                            let _ = reply.send(host.clone());
                        }
                        Some(Command::TurnCredentials(server, credentials, reply)) => {
                            let result = connection.update_turn_credentials(server, credentials, transport_now()).map_err(NetherError::from);
                            let _ = reply.send(result);
                        }
                        Some(Command::TurnStreamCredentials(targets, deadline, reply)) => {
                            let now = transport_now();
                            let result = if now >= deadline {
                                Err(NetherError::Timeout)
                            } else if reply.is_closed() {
                                Err(NetherError::ConnectionClosed)
                            } else if targets.len() > nethernet::session::MAX_ICE_SERVERS {
                                Err(NetherError::Ice("TURN replacement target limit exceeded".into()))
                            } else if let Some(route) = connection.selected_turn_stream() {
                                io.selected_credentials(targets, route, now).and_then(|credentials|
                                    connection.update_turn_stream_credentials(route, credentials, now).map_err(NetherError::from))
                            } else { Ok(()) };
                            let _ = reply.send(result);
                        }
                        None => break Terminal::Eof,
                    },
                }

                #[cfg(test)]
                pressure.record(
                    connection.pending_output_usage(),
                    io.kernel_blocked(connection.selected_turn_stream()),
                );
                let usage = connection.pending_output_usage();
                if usage.entries > PACKET_CHANNEL_CAPACITY
                    || usage.wire_bytes > receive::MAX_ACCEPTED_BYTES
                {
                    break Terminal::Capacity;
                }
                while !io.blocked(connection.selected_turn_stream()) {
                    let Some(output) = connection.poll() else {
                        break;
                    };
                    match output {
                        SessionOutput::Send(data, to) => {
                            tokio::select! {
                                biased;
                                _ = close_token.cancelled() => break 'drive Terminal::Eof,
                                result = io.send_datagram(&data, to) => {
                                    if let Err(e) = result {
                                        tracing::debug!("send_to error: {e}");
                                    }
                                }
                            }
                        }
                        SessionOutput::SendStream(data, route) => {
                            if io
                                .send_stream(data, route, connection.selected_turn_stream())
                                .is_err()
                            {
                                break 'drive Terminal::Transport;
                            }
                        }
                        SessionOutput::Event(SessionEvent::Ready) => {
                            let (Some(reliable_maximum), Some(unreliable_maximum)) = (
                                connection.max_message_size(Channel::Reliable),
                                connection.max_message_size(Channel::Unreliable),
                            ) else {
                                // Actual Ready records these facts before it enters the core FIFO.
                                continue;
                            };
                            remote_addr = connection.remote_addr();
                            if let Some(tx) = ready_tx.take() {
                                let _ = tx.send(Ready {
                                    reliable_maximum,
                                    unreliable_maximum,
                                });
                            }
                        }
                        SessionOutput::Event(SessionEvent::Failed) => {
                            tracing::debug!("session transport failed, closing");
                            break 'drive Terminal::Transport;
                        }
                        SessionOutput::Event(SessionEvent::PeerClosed) => {
                            break 'drive Terminal::Eof;
                        }
                        SessionOutput::Message(Channel::Reliable, data) => {
                            if let Err(error) = packet_tx.push(Bytes::from(data)) {
                                reliable_open = false;
                                break 'drive match error {
                                    AdmissionError::Full => Terminal::Capacity,
                                    AdmissionError::Closed => Terminal::Transport,
                                };
                            }
                        }
                        SessionOutput::Message(Channel::Unreliable, data) => {
                            let _ = unreliable_tx.push(Bytes::from(data));
                        }
                        SessionOutput::Wait(wait) => {
                            wake = transport_now() + wait.min(MAX_IDLE);
                        }
                    }
                }

                #[cfg(test)]
                pressure.record(
                    connection.pending_output_usage(),
                    io.kernel_blocked(connection.selected_turn_stream()),
                );
                if outgoing.is_none()
                    && candidates_enabled
                    && let Some(signaling) = &signaling
                    && let Some(signal) = connection.poll_local_signal()
                {
                    outgoing = Some(signal_send(
                        signaling.adapter.clone(),
                        signal,
                        signaling.within,
                    ));
                }

                rtt = connection.rtt();
                rtt_observation
                    .0
                    .publish(rtt.filter(|sample| !sample.is_zero()));
            };
            rtt_observation.0.retire();
            let terminal = drain_retired_prefix(
                connection,
                io,
                &packet_tx,
                &unreliable_tx,
                terminal,
                reliable_open,
            );
            // Release transport sockets before a terminal can wake the next connection attempt.
            drop(guard);
            packet_tx.finish(terminal);
            unreliable_tx.finish(terminal);
            close_token.cancel();
        })
    }

    /// Consumes the pending owner only with the exact actor's private readiness result.
    pub(crate) fn establish(self, ready: Ready) -> Session<Established> {
        let mut handle = self.into_handle();
        handle.ready = Some(ready);
        Session {
            handle: Some(handle),
            _phase: PhantomData,
        }
    }
}

/// Preserves the original accepted prefix in its existing final owner before reporting retirement.
fn drain_retired_prefix(
    connection: &mut guard::DrivenConnection,
    io: &mut IceIo,
    reliable: &Producer,
    unreliable: &Producer,
    mut terminal: Terminal,
    mut reliable_open: bool,
) -> Terminal {
    let Some(mut retired) = connection.retire(transport_now()) else {
        return terminal;
    };
    while let Some(output) = retired.poll() {
        match output {
            SessionOutput::Message(Channel::Reliable, data) if reliable_open => {
                if let Err(error) = reliable.push(Bytes::from(data)) {
                    reliable_open = false;
                    if matches!(terminal, Terminal::Eof) {
                        terminal = match error {
                            AdmissionError::Full => Terminal::Capacity,
                            AdmissionError::Closed => Terminal::Transport,
                        };
                    }
                }
            }
            SessionOutput::Message(Channel::Reliable, _) => {}
            SessionOutput::Message(Channel::Unreliable, data) => {
                let _ = unreliable.push(Bytes::from(data));
            }
            output => io.best_effort(output),
        }
    }
    terminal
}

impl<S: Phase> Session<S> {
    /// Borrows the retained handle until this owner's single phase transition.
    fn handle(&self) -> &SessionSender {
        self.handle
            .as_ref()
            .expect("session retains its lifecycle handle")
    }

    /// Moves the same actor ownership without triggering local cancellation during a transition.
    fn into_handle(mut self) -> SessionSender {
        self.handle
            .take()
            .expect("session transfers its lifecycle handle once")
    }

    /// Borrows the original runtime binding metadata.
    pub async fn local_addr(&self) -> Addr {
        self.handle().local_addr().await
    }
    /// Queries the retained actor for its original selected route.
    pub async fn remote_addr(&self) -> Addr {
        self.handle().remote_addr().await
    }
    /// Queries the original association measurement without changing lifetime.
    pub async fn rtt(&self) -> Option<Duration> {
        self.handle().rtt().await
    }
    /// Borrows identity metadata already installed on the same actor.
    pub async fn player(&self) -> Option<Arc<PlayerInfo>> {
        self.handle().player().await
    }
    /// Borrows the original HTTP signaling metadata when available.
    pub async fn host(&self) -> Option<String> {
        self.handle().host().await
    }
    /// Observes closure requested by any owner or by the actual driver.
    pub async fn closed(&self) {
        self.handle().closed().await
    }
    /// Observes shared closure without claiming that a remote peer remains live.
    pub async fn is_closed(&self) -> bool {
        self.handle().is_closed().await
    }
}

impl<S: Live> Session<S> {
    /// Queues a snapshot before the test's send burst; the actual receiver observes it before draining that burst.
    #[cfg(test)]
    fn queued_commands(&self) -> oneshot::Receiver<usize> {
        let (reply, observation) = oneshot::channel();
        self.handle()
            .command_tx
            .try_send(Command::QueuedCommands(reply))
            .expect("fixture's observation precedes its command burst");
        observation
    }

    pub(crate) fn signal_sender(&self) -> mpsc::Sender<Command> {
        self.handle().command_tx.clone()
    }

    /// Arbitrates public acceptance against listener retirement without an asynchronous gap.
    pub(crate) fn accept_from_server(&self) -> bool {
        self.handle()
            ._guard
            .server
            .as_ref()
            .is_some_and(|lease| lease.accept())
    }

    /// Keeps cancellation of unaccepted sessions owned by the listener, including task abortion.
    pub(crate) fn server_retirement(&self) -> ServerRetirement {
        ServerRetirement::new(
            self.handle()
                ._guard
                .server
                .as_ref()
                .expect("only server sessions have a listener owner"),
            self.handle().close_token.clone(),
        )
    }

    /// Allows peer control to stop the actor without retaining its application owners.
    pub(crate) fn close_token(&self) -> CancellationToken {
        self.handle().close_token.clone()
    }

    /// Installs admitted peer metadata before the public ready handoff.
    pub(crate) async fn set_player(&self, player: Arc<PlayerInfo>) {
        self.handle().set_player(player).await;
    }
    /// Installs the original accepted HTTP host before handoff.
    pub(crate) async fn set_host(&self, host: String) {
        self.handle().set_host(host).await;
    }

    /// Consumes local lifecycle ownership and requests finite teardown on the existing actor.
    /// Other established senders observe global closure at runtime; receivers retain accepted data.
    pub fn close(self) -> Session<Retired> {
        let handle = self.into_handle();
        handle.start_close();
        Session {
            handle: Some(handle),
            _phase: PhantomData,
        }
    }
}

impl Session<Established> {
    /// Shares only an established send/control capability, never another lifecycle owner.
    pub fn sender(&self) -> SessionSender {
        self.handle().clone()
    }
    /// Refreshes this actor's selected stream from exactly one matching original target.
    pub async fn update_turn_streams_before(
        &self,
        targets: Vec<nethernet::session::TurnStreamTarget>,
        deadline: Instant,
    ) -> Result<()> {
        self.handle()
            .update_turn_streams_before(targets, deadline)
            .await
    }

    /// Sends through the established capability while retaining unique lifecycle ownership.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.handle().send(data).await
    }
    /// Retains the caller's original admission deadline on the same established actor.
    pub async fn send_before(&self, data: Bytes, deadline: Instant) -> Result<()> {
        self.handle().send_before(data, deadline).await
    }
    /// Admits one unreliable message through the established actor.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.handle().send_unreliable(data).await
    }
    /// Admits a password rotation on the original live allocation; its actual response determines the lease.
    /// Completion acknowledges local actor admission rather than the remote Refresh response.
    pub async fn update_turn_credentials(
        &self,
        server: std::net::SocketAddr,
        credentials: nethernet::session::TurnCredentials,
    ) -> Result<()> {
        self.handle()
            .update_turn_credentials(server, credentials)
            .await
    }
}

impl<S: Phase> Drop for Session<S> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.start_close();
        }
    }
}

impl AcceptedSession<Connecting> {
    /// Transfers the exact pending actor and receivers using its retained Ready result.
    pub(crate) fn establish(self, ready: Ready) -> AcceptedSession<Established> {
        AcceptedSession {
            session: self.session.establish(ready),
            reliable: self.reliable,
            unreliable: self.unreliable,
        }
    }
}

impl<S: Live> AcceptedSession<S> {
    /// Retires the unique sender owner while preserving both original receive queues.
    pub fn close(self) -> AcceptedSession<Retired> {
        AcceptedSession {
            session: self.session.close(),
            reliable: self.reliable,
            unreliable: self.unreliable,
        }
    }
}

#[cfg(test)]
impl Session<Retired> {
    /// Joins the same original actor after the fixture has dropped its other owned capabilities.
    pub(crate) async fn join_original_actor(self) {
        let handle = self.into_handle();
        let mut guard = Arc::try_unwrap(handle._guard)
            .unwrap_or_else(|_| panic!("fixture retained another original actor capability"));
        (&mut guard.task).await.expect("original actor panicked");
    }
}

impl SessionSender {
    /// Independent read-only fixture observation remains available while ordinary commands are gated.
    #[cfg(test)]
    pub(crate) fn pressure_observation(&self) -> pressure_observation::Observation {
        self.pressure.clone()
    }

    /// Refreshes only the same actual selected stream, under one original admission cutoff.
    /// Direct/UDP selection needs no stream mutation. Missing or ambiguous selected-target
    /// replacements fail; this never reconnects. Success means local core admission, not a
    /// remote Refresh ACK. Canceling an unadmitted wait retracts it; admitted work stays owned.
    pub async fn update_turn_streams_before(
        &self,
        targets: Vec<nethernet::session::TurnStreamTarget>,
        deadline: Instant,
    ) -> Result<()> {
        if targets.len() > nethernet::session::MAX_ICE_SERVERS {
            return Err(NetherError::Ice(
                "TURN replacement target limit exceeded".into(),
            ));
        }
        let now = transport_now();
        if now >= deadline {
            return Err(NetherError::Timeout);
        }
        for target in &targets {
            target
                .validate(now)
                .map_err(nethernet::error::ProtocolError::from)?;
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.enqueue(
            Command::TurnStreamCredentials(targets, deadline, reply_tx),
            Some(deadline),
        )
        .await?;
        tokio::select! {
            biased;
            _ = self.close_token.cancelled() => Err(NetherError::ConnectionClosed),
            _ = tokio::time::sleep_until(deadline.into()) => Err(NetherError::Timeout),
            result = reply_rx => result.map_err(|_| NetherError::ConnectionClosed)?,
        }
    }

    /// Replaces one TURN server's credential without opening a service client or changing its allocation.
    pub async fn update_turn_credentials(
        &self,
        server: std::net::SocketAddr,
        credentials: nethernet::session::TurnCredentials,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.enqueue(
            Command::TurnCredentials(server, credentials, reply_tx),
            None,
        )
        .await?;
        reply_rx.await.map_err(|_| NetherError::ConnectionClosed)?
    }

    /// Waits outside the bounded actor queue; cancellation cannot leave an unadmitted command behind.
    async fn enqueue(&self, command: Command, deadline: Option<Instant>) -> Result<()> {
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => pending().await,
            }
        };
        tokio::select! {
            biased;
            _ = self.close_token.cancelled() => Err(NetherError::ConnectionClosed),
            _ = expired => Err(NetherError::Timeout),
            result = self.command_tx.send(command) => result.map_err(|_| NetherError::ConnectionClosed),
        }
    }

    /// Requests transport closure immediately, including from a synchronous owner's Drop.
    /// The existing actor performs teardown; accepted receive data remains readable before EOF.
    /// Repeated calls are harmless and this never aborts the actor task or waits for I/O.
    pub fn start_close(&self) {
        self.close_token.cancel();
        self.rtt.retire();
    }

    /// Starts closing and returns without waiting for teardown.
    pub async fn close(&self) -> Result<()> {
        self.start_close();
        Ok(())
    }

    pub async fn local_addr(&self) -> Addr {
        self.local_addr.clone()
    }

    pub async fn remote_addr(&self) -> Addr {
        let (reply_tx, reply_rx) = oneshot::channel();
        let socket_addr = match self.enqueue(Command::RemoteAddr(reply_tx), None).await {
            Ok(()) => reply_rx.await.ok().flatten(),
            Err(_) => None,
        };
        Addr {
            socket_addr,
            ..self.remote_addr.clone()
        }
    }

    /// Observes the same actor's full SCTP round-trip estimate without queuing a command.
    /// The returned handle reads without locks and cannot retain this transport.
    pub fn observe_rtt(&self) -> RttObservation {
        self.rtt.clone()
    }

    /// None until a round trip time has been measured.
    pub async fn rtt(&self) -> Option<Duration> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.enqueue(Command::Rtt(reply_tx), None).await.is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Records the validated identity of the peer; the HTTP server sets it after admission.
    pub async fn set_player(&self, player: Arc<PlayerInfo>) {
        let _ = self.enqueue(Command::SetPlayer(player), None).await;
    }

    pub async fn player(&self) -> Option<Arc<PlayerInfo>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.enqueue(Command::Player(reply_tx), None).await.is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Records the Host header of the offer request, HTTP signaling only.
    pub async fn set_host(&self, host: String) {
        let _ = self.enqueue(Command::SetHost(host), None).await;
    }

    pub async fn host(&self) -> Option<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.enqueue(Command::Host(reply_tx), None).await.is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    pub async fn closed(&self) {
        self.close_token.cancelled().await
    }

    pub async fn is_closed(&self) -> bool {
        self.close_token.is_cancelled()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_peer;
