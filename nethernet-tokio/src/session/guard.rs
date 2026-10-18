//! Concrete cancellation owners for gathering and connected transports.
use nethernet::connection::Connection;
use nethernet::sans::Sans;
use nethernet::session::{Session, SessionOutput};
use std::sync::Arc;
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
}

impl GatheringGuard {
    pub fn new(core: Session, socket: Arc<UdpSocket>) -> Self {
        Self {
            core: Some(core),
            socket,
        }
    }
}

impl Drop for GatheringGuard {
    fn drop(&mut self) {
        if let Some(core) = &mut self.core {
            let _ = core.close(transport_now());
            while let Some(output) = core.poll() {
                if let SessionOutput::Send(data, to) = output {
                    let _ = self.socket.try_send_to(&data, to);
                }
            }
        }
    }
}

/// Owns the core during negotiation and after spawning; aborting either future still releases its allocations.
pub(crate) struct ConnectionGuard {
    core: Option<Connection>,
    socket: Arc<UdpSocket>,
}

impl ConnectionGuard {
    pub fn new(core: Connection, socket: Arc<UdpSocket>) -> Self {
        Self {
            core: Some(core),
            socket,
        }
    }

    /// Borrows the owned connection until it is handed to the session driver.
    pub fn core(&mut self) -> &mut Connection {
        self.core
            .as_mut()
            .expect("connection is owned until its single handoff")
    }

    /// Transfers ownership synchronously, with no cancellation point between the two drivers.
    pub fn take(&mut self) -> Connection {
        self.core
            .take()
            .expect("connection is handed off only once")
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(core) = &mut self.core {
            let _ = core.close(transport_now());
            while let Some(output) = core.poll() {
                if let SessionOutput::Send(data, to) = output {
                    let _ = self.socket.try_send_to(&data, to);
                }
            }
        }
    }
}
