//! Application-owned numeric destination admission at the transport I/O boundary.

use std::{fmt, io, net::SocketAddr, sync::Arc};

/// Admission for actual UDP destinations and resolved TCP/TLS TURN endpoints.
///
/// The same policy stays with a connection through gathering, play and cleanup.
/// It performs no name resolution and grants no signaling or player authority.
#[derive(Clone)]
pub struct EgressPolicy(Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>);

impl EgressPolicy {
    /// Captures the application's destination rule before any transport I/O starts.
    pub fn new(admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(admit))
    }

    /// Checks the exact destination about to be used without retaining its address in errors.
    pub(crate) fn check(&self, peer: SocketAddr) -> io::Result<()> {
        if (self.0)(peer) {
            Ok(())
        } else {
            Err(denied())
        }
    }
}

impl fmt::Debug for EgressPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressPolicy")
            .finish_non_exhaustive()
    }
}

/// Reconstructs a terminal refusal without retaining an endpoint or caller closure.
pub(crate) fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "transport destination refused",
    )
}
