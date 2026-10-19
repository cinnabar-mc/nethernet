//! Concrete cancellation owners for gathering and connected transports.
use super::ServerLease;
use crate::transport::ice_io::IceIo;
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

/// Uses the runtime's monotonic clock, including Tokio's deterministic test clock.
pub(crate) fn transport_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Keeps an allocation owned while the asynchronous full-gather operation can be cancelled.
pub(crate) struct GatheringGuard {
    pub core: Option<Session>,
    pub io: Option<IceIo>,
    server_capacity: Option<Arc<ServerLease>>,
}

impl GatheringGuard {
    pub fn new(core: Session, io: impl Into<IceIo>) -> Self {
        Self {
            core: Some(core),
            io: Some(io.into()),
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
                if let Some(io) = &mut self.io {
                    io.best_effort(output);
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

    /// Reads the original core FIFO without bypassing the actor's ownership.
    pub fn pending_output_usage(&self) -> nethernet::session::OutputUsage {
        match self.state.as_ref().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.pending_output_usage(),
            ActiveConnection::Established(core) => core.pending_output_usage(),
        }
    }

    /// Reports the same engine-selected route without admitting transport work.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match self.state.as_ref().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.remote_addr(),
            ActiveConnection::Established(core) => core.remote_addr(),
        }
    }

    /// Reads the core-selected live stream allocation without inferring it from wire output.
    pub fn selected_turn_stream(&self) -> Option<nethernet::session::TurnStreamRoute> {
        match self.state.as_ref().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => core.selected_turn_stream(),
            ActiveConnection::Established(core) => core.selected_turn_stream(),
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

    /// Refreshes only the existing allocation on the exact retained stream, never another endpoint.
    pub fn update_turn_stream_credentials(
        &mut self,
        route: nethernet::session::TurnStreamRoute,
        credentials: nethernet::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self.state.as_mut().expect("driver retains its core") {
            ActiveConnection::Connecting(core) => {
                core.update_turn_stream_credentials(route, credentials, now)
            }
            ActiveConnection::Established(core) => {
                core.update_turn_stream_credentials(route, credentials, now)
            }
        }
    }

    /// Takes the original owner once, keeping its accepted prefix available for bounded final delivery.
    pub fn retire(&mut self, now: Instant) -> Option<Connection<nethernet::phase::Retired>> {
        let (retired, _result) = match self.state.take()? {
            ActiveConnection::Connecting(core) => core.close(now),
            ActiveConnection::Established(core) => core.close(now),
        };
        Some(retired)
    }

    /// Finite fallback teardown remains safe after the actor already consumed its original core.
    fn close(mut self, now: Instant, io: &mut IceIo) {
        let Some(mut retired) = self.retire(now) else {
            return;
        };
        while let Some(output) = retired.poll() {
            io.best_effort(output);
        }
    }
}

/// Owns the core during negotiation and after spawning; aborting either future still releases its allocations.
pub(crate) struct ConnectionGuard {
    core: Option<DrivenConnection>,
    io: Option<IceIo>,
    // Field order retains capacity through core and socket destruction after Drop runs.
    server_capacity: Option<Arc<ServerLease>>,
}

impl ConnectionGuard {
    pub fn new(core: Connection, io: impl Into<IceIo>) -> Self {
        Self {
            core: Some(DrivenConnection::new(core)),
            io: Some(io.into()),
            server_capacity: None,
        }
    }

    /// Retains server admission through actual driver destruction, including an unpolled abort.
    pub(crate) fn with_server_capacity(mut self, capacity: Option<Arc<ServerLease>>) -> Self {
        self.server_capacity = capacity;
        self
    }

    /// Borrows the actor's two owned resources without another socket owner outside this guard.
    pub(crate) fn parts(&mut self) -> (&mut DrivenConnection, &mut IceIo) {
        (
            self.core
                .as_mut()
                .expect("connection is owned until its single handoff"),
            self.io
                .as_mut()
                .expect("connection owns its original transport"),
        )
    }

    /// Transfers ownership synchronously, with no cancellation point between the two drivers.
    pub fn take(&mut self) -> (Connection, IceIo) {
        (
            self.core
                .take()
                .expect("connection is handed off only once")
                .into_pending(),
            self.io.take().expect("transport is handed off only once"),
        )
    }

    /// Negotiation borrows the pending core and the exact transport owner together.
    pub fn pending_parts(&mut self) -> (&mut Connection, &mut IceIo) {
        (
            self.core
                .as_mut()
                .expect("connection remains owned")
                .pending(),
            self.io.as_mut().expect("transport remains owned"),
        )
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(capacity) = &self.server_capacity {
            capacity.retire_route();
        }
        if let Some(core) = self.core.take() {
            core.close(
                transport_now(),
                self.io.as_mut().expect("live core owns its transport"),
            );
        }
    }
}
