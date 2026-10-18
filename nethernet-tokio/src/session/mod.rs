//! A connected session driven by one task, with reliable and unreliable channels and peer metadata.
pub(crate) mod command;
pub(crate) mod guard;
pub(crate) mod outgoing;
mod receive;
mod server;

pub(crate) use command::Command;
pub(crate) use server::{ServerLease, ServerRetirement};

use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::signaling::ClientSignaling;
use bytes::Bytes;
use futures::future::{BoxFuture, pending};
use guard::{ConnectionGuard, transport_now};
use nethernet::connection::{Connection as SansConnection, ConnectionInput};
use nethernet::identity::PlayerInfo;
use nethernet::sans::Sans;
pub use nethernet::session::Channel;
use nethernet::session::{SessionEvent, SessionOutput};
use outgoing::{CandidateSignaling, signal_send};
use receive::{AdmissionError, Producer, Receiver, Terminal};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
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

/// Cloneable transport handle; accepted receivers retain their data after closure.
#[derive(Clone)]
pub struct Session {
    local_addr: Addr,
    remote_addr: Addr,
    command_tx: mpsc::Sender<Command>,
    close_token: CancellationToken,
    _guard: Arc<TaskGuard>,
}

/// Incoming accepted messages, followed by EOF on orderly close or one explicit receive error.
pub struct SessionReceiver {
    rx: Receiver,
    _guard: Arc<TaskGuard>,
}

impl SessionReceiver {
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        futures::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        self.rx.poll_recv(cx)
    }
}

/// A connected session with its reliable and unreliable receivers.
pub struct AcceptedSession {
    pub session: Session,
    pub reliable: SessionReceiver,
    pub unreliable: SessionReceiver,
}

impl Session {
    /// Queues a snapshot before the test's send burst; the actual receiver observes it before draining that burst.
    #[cfg(test)]
    fn queued_commands(&self) -> oneshot::Receiver<usize> {
        let (reply, observation) = oneshot::channel();
        self.command_tx
            .try_send(Command::QueuedCommands(reply))
            .expect("fixture's observation precedes its command burst");
        observation
    }

    #[cfg(test)]
    pub(crate) fn spawn(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
    ) {
        Self::spawn_with_signaling(socket, connection, local, remote, None)
    }

    /// Retains the concrete signaling owner only when late outgoing candidates can be produced.
    pub(crate) fn spawn_with_signaling(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        signaling: Option<(ClientSignaling, Duration)>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
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
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        lease: Arc<ServerLease>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
    ) {
        Self::spawn_owned(socket, connection, local, remote, None, Some(lease))
    }

    /// Drives configured accepting ICE, gating late candidates behind original answer dispatch.
    pub(crate) fn spawn_for_server_with_signaling(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        lease: Arc<ServerLease>,
        signaling: CandidateSignaling,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
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
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
        signaling: Option<CandidateSignaling>,
        server: Option<Arc<ServerLease>>,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
    ) {
        let (command_tx, command_rx) = mpsc::channel(command::COMMAND_CAPACITY);
        let (packet_tx, packet_rx) = receive::channel(Channel::Reliable);
        let (unreliable_tx, unreliable_rx) = receive::channel(Channel::Unreliable);
        let (ready_tx, ready_rx) = oneshot::channel();
        let close_token = CancellationToken::new();

        let task = Self::drive(
            socket,
            connection,
            command_rx,
            packet_tx,
            unreliable_tx,
            Some(ready_tx),
            close_token.clone(),
            signaling,
            server.clone(),
        );

        let guard = Arc::new(TaskGuard {
            close_token: close_token.clone(),
            task,
            server,
        });

        let session = Self {
            local_addr: local,
            remote_addr: remote,
            command_tx,
            close_token,
            _guard: guard.clone(),
        };

        (
            session,
            SessionReceiver {
                rx: packet_rx,
                _guard: guard.clone(),
            },
            SessionReceiver {
                rx: unreliable_rx,
                _guard: guard,
            },
            ready_rx,
        )
    }

    pub(crate) fn signal_sender(&self) -> mpsc::Sender<Command> {
        self.command_tx.clone()
    }

    /// Arbitrates public acceptance against listener retirement without an asynchronous gap.
    pub(crate) fn accept_from_server(&self) -> bool {
        self._guard
            .server
            .as_ref()
            .is_some_and(|lease| lease.accept())
    }

    /// Keeps cancellation of unaccepted sessions owned by the listener, including task abortion.
    pub(crate) fn server_retirement(&self) -> ServerRetirement {
        ServerRetirement::new(
            self._guard
                .server
                .as_ref()
                .expect("only server sessions have a listener owner"),
            self.close_token.clone(),
        )
    }

    /// Allows peer control to stop the actor without retaining its application owners.
    pub(crate) fn close_token(&self) -> CancellationToken {
        self.close_token.clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn drive(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        mut commands: mpsc::Receiver<Command>,
        packet_tx: Producer,
        unreliable_tx: Producer,
        mut ready_tx: Option<oneshot::Sender<()>>,
        close_token: CancellationToken,
        signaling: Option<CandidateSignaling>,
        server: Option<Arc<ServerLease>>,
    ) -> JoinHandle<()> {
        let mut guard = ConnectionGuard::new(connection, socket).with_server_capacity(server);
        let driver_closed = close_token.clone().drop_guard();
        tokio::spawn(async move {
            let _driver_closed = driver_closed;
            let (connection, socket) = guard.parts();
            let mut buf = vec![0u8; 65536];
            let mut wake = transport_now();
            let mut outgoing: Option<BoxFuture<'static, Result<()>>> = None;
            let mut remote_addr = None;
            let mut rtt = None;
            let mut player: Option<Arc<PlayerInfo>> = None;
            let mut host: Option<String> = None;

            let mut candidates_enabled = signaling
                .as_ref()
                .is_none_or(|signaling| signaling.enabled.is_none());
            let terminal = 'drive: loop {
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
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((n, from)) => {
                            let now = transport_now();
                            let input = ConnectionInput::Packet(buf[..n].into(), from, now);
                            if let Err(e) = connection.handle(input) {
                                tracing::debug!("packet handling error: {e}");
                            }
                        }
                        Err(e) => tracing::debug!("recv error: {e}"),
                    },
                    command = commands.recv() => match command {
                        #[cfg(test)]
                        Some(Command::QueuedCommands(reply)) => {
                            let _ = reply.send(commands.len());
                        }
                        Some(Command::Send(channel, data, deadline, reply)) => {
                            let now = transport_now();
                            let result = if deadline.is_some_and(|deadline| now >= deadline) {
                                Err(NetherError::Timeout)
                            } else if deadline.is_some() && reply.is_closed() {
                                // An abandoned wait may retract only a command not yet admitted.
                                Err(NetherError::ConnectionClosed)
                            } else {
                                connection.handle(ConnectionInput::Send(channel, data, now))
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
                        None => break Terminal::Eof,
                    },
                }

                while let Some(output) = connection.poll() {
                    match output {
                        SessionOutput::Send(data, to) => {
                            if let Err(e) = socket.send_to(&data, to).await {
                                tracing::debug!("send_to error: {e}");
                            }
                        }
                        SessionOutput::Event(SessionEvent::Ready) => {
                            remote_addr = connection.remote_addr();
                            if let Some(tx) = ready_tx.take() {
                                let _ = tx.send(());
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
                            match packet_tx.push(Bytes::from(data)) {
                                Ok(()) => {}
                                Err(AdmissionError::Full) => break 'drive Terminal::Capacity,
                                Err(AdmissionError::Closed) => break 'drive Terminal::Transport,
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
            };
            packet_tx.finish(terminal);
            unreliable_tx.finish(terminal);
            close_token.cancel();
        })
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Reliable, data, None).await
    }

    /// Admits one reliable message before the original absolute deadline.
    /// The driver checks the deadline immediately before SCTP admission; a
    /// successful admission may finish transmitting afterwards. Dropping the
    /// wait does not retract an already admitted message.
    pub async fn send_before(&self, data: Bytes, deadline: Instant) -> Result<()> {
        self.send_on(Channel::Reliable, data, Some(deadline)).await
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

    /// The message must fit one segment (guide section 6.1).
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Unreliable, data, None).await
    }

    async fn send_on(
        &self,
        channel: Channel,
        data: Bytes,
        deadline: Option<Instant>,
    ) -> Result<()> {
        if deadline.is_some_and(|deadline| transport_now() >= deadline) {
            return Err(NetherError::Timeout);
        }
        let max_size = match channel {
            Channel::Reliable => {
                nethernet::protocol::constants::MAX_MESSAGE_SIZE * usize::from(u8::MAX)
            }
            Channel::Unreliable => {
                nethernet::protocol::constants::MAX_MESSAGE_SIZE.saturating_sub(1)
            }
        };
        if data.len() > max_size {
            return Err(nethernet::error::ProtocolError::MessageSizeExceeded(data.len()).into());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.enqueue(Command::Send(channel, data, deadline, reply_tx), deadline)
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
