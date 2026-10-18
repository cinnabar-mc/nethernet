//! Concrete cancellation owners for gathering and connected transports.
use super::ServerLease;
use bytes::Bytes;
use nethernet::connection::{Connection, ConnectionInput};
use nethernet::error::ProtocolError;
use nethernet::phase::{Connecting, Established};
use nethernet::protocol::Signal;
use nethernet::sans::Sans;
use nethernet::session::Channel;
use nethernet::session::{Session, SessionOutput};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;

/// Uses the runtime's monotonic clock, including Tokio's deterministic test clock.
pub(crate) fn transport_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Keeps an allocation owned while the asynchronous full-gather operation can be cancelled.
pub(crate) struct GatheringGuard {
    pub core: Option<Session>,
    socket: Arc<UdpSocket>,
    server_capacity: Option<Arc<ServerLease>>,
}

impl GatheringGuard {
    pub fn new(core: Session, socket: Arc<UdpSocket>) -> Self {
        Self {
            core: Some(core),
            socket,
            server_capacity: None,
        }
    }
    /// Holds the accepting reservation through canceled gather and allocation destruction.
    pub(crate) fn with_server_capacity(mut self, capacity: Arc<ServerLease>) -> Self {
        self.server_capacity = Some(capacity);
        self
    }
}

impl Drop for GatheringGuard {
    fn drop(&mut self) {
        if let Some(core) = self.core.take() {
            let (mut retired, _result) = core.close(transport_now());
            while let Some(output) = retired.poll() {
                if let SessionOutput::Send(data, to) = output {
                    let _ = self.socket.try_send_to(&data, to);
                }
            }
        }
    }
}

enum ActiveConnection {
    Connecting(Connection<Connecting>),
    Established(Connection<Established>),
}

/// Holds the actual typed core as its actor crosses readiness; never exposed as an unchecked API.
pub(crate) struct DrivenConnection {
    state: Option<ActiveConnection>,
}

impl DrivenConnection {
    fn new(core: Connection<Connecting>) -> Self {
        Self {
            state: Some(ActiveConnection::Connecting(core)),
        }
    }

    /// Negotiation owns only the pending phase and hands it off before the actor polls Ready.
    fn pending(&mut self) -> &mut Connection<Connecting> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core,
            ActiveConnection::Established(_) => unreachable!("negotiation ended before readiness"),
        }
    }

    /// Moves the original owner back to its single actor handoff.
    fn into_pending(mut self) -> Connection<Connecting> {
        match self.state.take().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core,
            ActiveConnection::Established(_) => unreachable!("negotiation ended before readiness"),
        }
    }

    /// Applies wire/control work without making application send available on the pending core.
    pub fn handle(&mut self, input: ConnectionInput) -> Result<(), ProtocolError> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.handle(input),
            ActiveConnection::Established(core) => core.handle(input),
        }
    }

    /// Preserves original output order and converts ownership at the actual Ready outcome.
    pub fn poll(&mut self) -> Option<SessionOutput> {
        let output = match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.poll(),
            ActiveConnection::Established(core) => core.poll(),
        };
        if matches!(
            output,
            Some(SessionOutput::Event(
                nethernet::session::SessionEvent::Ready
            ))
        ) {
            let state = self.state.take().expect("driver retains its core");
            self.state = Some(match state {
                ActiveConnection::Connecting(core) => match core.try_establish() {
                    Ok(core) => ActiveConnection::Established(core),
                    Err(core) => {
                        self.state = Some(ActiveConnection::Connecting(core));
                        return Some(SessionOutput::Event(
                            nethernet::session::SessionEvent::Failed,
                        ));
                    }
                },
                state => state,
            });
        }
        output
    }

    /// Only the established variant can call the core's application send method.
    pub fn send(
        &mut self,
        channel: Channel,
        data: Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(_) => {
                Err(ProtocolError::Other("channel not open yet".into()))
            }
            ActiveConnection::Established(core) => core.send(channel, data, now),
        }
    }

    /// Reports the same engine-selected route without admitting transport work.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match self.state.as_ref().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.remote_addr(),
            ActiveConnection::Established(core) => core.remote_addr(),
        }
    }

    /// Borrows the current SCTP measurement in either live driver phase.
    pub fn rtt(&self) -> Option<Duration> {
        match self.state.as_ref().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.rtt(),
            ActiveConnection::Established(core) => core.rtt(),
        }
    }

    /// Drains late candidates through their original signaling owner.
    pub fn poll_local_signal(&mut self) -> Option<Signal> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.poll_local_signal(),
            ActiveConnection::Established(core) => core.poll_local_signal(),
        }
    }

    /// Retains original allocation ownership and expiry while applying caller-selected credentials.
    pub fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: nethernet::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => {
                core.update_turn_credentials(server, credentials, now)
            }
            ActiveConnection::Established(core) => {
                core.update_turn_credentials(server, credentials, now)
            }
        }
    }

    /// Consumes whichever live phase remains, retaining teardown output even when close reports failure.
    fn close(mut self, now: Instant, socket: &UdpSocket) {
        let (mut retired, _result) = match self.state.take().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.close(now),
            ActiveConnection::Established(core) => core.close(now),
        };
        while let Some(output) = retired.poll() {
            if let SessionOutput::Send(data, to) = output {
                let _ = socket.try_send_to(&data, to);
            }
        }
    }
}

/// Owns the core during negotiation and after spawning; aborting either future still releases its allocations.
pub(crate) struct ConnectionGuard {
    core: Option<DrivenConnection>,
    socket: Arc<UdpSocket>,
    // Field order retains capacity through core and socket destruction after Drop runs.
    server_capacity: Option<Arc<ServerLease>>,
}

impl ConnectionGuard {
    pub fn new(core: Connection, socket: Arc<UdpSocket>) -> Self {
        Self {
            core: Some(DrivenConnection::new(core)),
            socket,
            server_capacity: None,
        }
    }

    /// Retains server admission through actual driver destruction, including an unpolled abort.
    pub(crate) fn with_server_capacity(mut self, capacity: Option<Arc<ServerLease>>) -> Self {
        self.server_capacity = capacity;
        self
    }

    /// Borrows the actor's two owned resources without another socket owner outside this guard.
    pub(crate) fn parts(&mut self) -> (&mut DrivenConnection, &UdpSocket) {
        (
            self.core
                .as_mut()
                .expect("connection is owned until its single handoff"),
            self.socket.as_ref(),
        )
    }

    /// Borrows the owned connection until it is handed to the session driver.
    pub fn core(&mut self) -> &mut Connection {
        self.core
            .as_mut()
            .expect("connection is owned until its single handoff")
            .pending()
    }

    /// Transfers ownership synchronously, with no cancellation point between the two drivers.
    pub fn take(&mut self) -> Connection {
        self.core
            .take()
            .expect("connection is handed off only once")
            .into_pending()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(capacity) = &self.server_capacity {
            capacity.retire_route();
        }
        if let Some(core) = self.core.take() {
            core.close(transport_now(), &self.socket);
        }
    }
}
