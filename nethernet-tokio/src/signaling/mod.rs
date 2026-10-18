//! Signaling backends and the enums that dispatch over them.
use crate::addr::Addr;
use crate::error::Result;
use crate::protocol::Signal;
use futures::Stream;
use http::{HttpSignaling, HttpSignalingServer};
use lan::LanSignaling;
use nethernet::identity::PlayerInfo;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub mod caller;
pub mod http;
pub mod lan;

/// Signaling a server listens on: caller-owned service, LAN discovery or HTTP.
#[derive(Clone)]
pub enum ServerSignaling {
    /// A bounded multi-peer bridge to the caller-owned authenticated service.
    Caller(Arc<caller::server::CallerServerSignaling>),
    Lan(Arc<LanSignaling>),
    Http(Arc<HttpSignalingServer>),
}

impl From<caller::server::CallerServerSignaling> for ServerSignaling {
    fn from(signaling: caller::server::CallerServerSignaling) -> Self {
        Self::Caller(Arc::new(signaling))
    }
}

impl From<Arc<caller::server::CallerServerSignaling>> for ServerSignaling {
    fn from(signaling: Arc<caller::server::CallerServerSignaling>) -> Self {
        Self::Caller(signaling)
    }
}

impl From<LanSignaling> for ServerSignaling {
    fn from(signaling: LanSignaling) -> Self {
        Self::Lan(Arc::new(signaling))
    }
}

impl From<Arc<LanSignaling>> for ServerSignaling {
    fn from(signaling: Arc<LanSignaling>) -> Self {
        Self::Lan(signaling)
    }
}

impl From<HttpSignalingServer> for ServerSignaling {
    fn from(signaling: HttpSignalingServer) -> Self {
        Self::Http(Arc::new(signaling))
    }
}

impl From<Arc<HttpSignalingServer>> for ServerSignaling {
    fn from(signaling: Arc<HttpSignalingServer>) -> Self {
        Self::Http(signaling)
    }
}

impl ServerSignaling {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match self {
            Self::Caller(s) => s.signal(signal).await,
            Self::Lan(s) => s.signal(signal).await,
            Self::Http(s) => s.signal(signal).await,
        }
    }

    /// Subscribes once; caller bridges reject a concurrent listener synchronously.
    pub fn signals(&self) -> Result<Pin<Box<dyn Stream<Item = Signal> + Send>>> {
        match self {
            Self::Caller(s) => s.signals(),
            Self::Lan(s) => Ok(s.signals()),
            Self::Http(s) => Ok(s.signals()),
        }
    }

    pub fn network_id(&self) -> String {
        match self {
            Self::Caller(s) => s.network_id(),
            Self::Lan(s) => s.network_id(),
            Self::Http(s) => s.network_id(),
        }
    }

    /// True when candidates must be embedded in the SDP instead of trickled.
    pub fn disable_trickle_ice(&self) -> bool {
        match self {
            Self::Caller(s) => s.disable_trickle_ice(),
            Self::Lan(s) => s.disable_trickle_ice(),
            Self::Http(s) => s.disable_trickle_ice(),
        }
    }

    pub async fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        match self {
            Self::Caller(_) => None,
            Self::Lan(s) => s.remote_address(addr).await,
            Self::Http(s) => s.remote_address(addr).await,
        }
    }

    /// HTTP only; LAN has no identity and returns None.
    pub async fn player(&self, addr: &Addr) -> Option<Arc<PlayerInfo>> {
        match self {
            Self::Caller(_) | Self::Lan(_) => None,
            Self::Http(s) => s.player(addr).await,
        }
    }

    pub async fn host(&self, addr: &Addr) -> Option<String> {
        match self {
            Self::Caller(_) | Self::Lan(_) => None,
            Self::Http(s) => s.host(addr).await,
        }
    }

    /// True for HTTP, whose signaler authenticates offers before the server sees them.
    pub fn validates_offers(&self) -> bool {
        match self {
            Self::Caller(_) | Self::Lan(_) => false,
            Self::Http(_) => true,
        }
    }

    /// HTTP and caller bridges require an explicit answer identity unless deliberately configured otherwise.
    pub fn requires_identity(&self) -> bool {
        match self {
            Self::Lan(_) => false,
            Self::Caller(_) | Self::Http(_) => true,
        }
    }

    /// Replaces the advertised server data from a pong string; an unparsable string is logged and ignored.
    pub fn set_pong_data(&self, data: &[u8]) {
        match self {
            Self::Caller(_) => {}
            Self::Lan(s) => s.set_pong_data(data),
            Self::Http(s) => s.set_pong_data(data),
        }
    }
    /// Claims a caller route before asynchronous admission or a bounded refusal starts.
    pub(crate) fn claim_route(
        &self,
        offer: &Signal,
    ) -> Result<Option<caller::server::CallerRoute>> {
        match self {
            Self::Caller(s) => Ok(Some(s.claim(offer)?)),
            _ => Ok(None),
        }
    }

    /// Returns a service-lifetime signal only for caller-owned bridges.
    pub(crate) fn service_closed(&self) -> Option<tokio_util::sync::CancellationToken> {
        match self {
            Self::Caller(s) => Some(s.closed()),
            _ => None,
        }
    }
}

/// Client signaling through LAN discovery, HTTP or a caller-owned service bridge.
#[derive(Clone)]
pub enum ClientSignaling {
    /// A bounded bridge to an application-owned signaling service.
    Caller(Arc<caller::CallerSignaling>),
    Lan(Arc<LanSignaling>),
    Http(Arc<HttpSignaling>),
}

impl From<caller::CallerSignaling> for ClientSignaling {
    fn from(signaling: caller::CallerSignaling) -> Self {
        Self::Caller(Arc::new(signaling))
    }
}

impl From<Arc<caller::CallerSignaling>> for ClientSignaling {
    fn from(signaling: Arc<caller::CallerSignaling>) -> Self {
        Self::Caller(signaling)
    }
}

impl From<LanSignaling> for ClientSignaling {
    fn from(signaling: LanSignaling) -> Self {
        Self::Lan(Arc::new(signaling))
    }
}

impl From<Arc<LanSignaling>> for ClientSignaling {
    fn from(signaling: Arc<LanSignaling>) -> Self {
        Self::Lan(signaling)
    }
}

impl From<HttpSignaling> for ClientSignaling {
    fn from(signaling: HttpSignaling) -> Self {
        Self::Http(Arc::new(signaling))
    }
}

impl From<Arc<HttpSignaling>> for ClientSignaling {
    fn from(signaling: Arc<HttpSignaling>) -> Self {
        Self::Http(signaling)
    }
}

impl ClientSignaling {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match self {
            Self::Caller(s) => s.signal(signal).await,
            Self::Lan(s) => s.signal(signal).await,
            Self::Http(s) => s.signal(signal).await,
        }
    }

    /// Subscribes to incoming signals; caller bridges reject concurrent subscriptions.
    pub fn signals(&self) -> Result<Pin<Box<dyn Stream<Item = Signal> + Send>>> {
        match self {
            Self::Caller(s) => s.signals(),
            Self::Lan(s) => Ok(s.signals()),
            Self::Http(s) => Ok(s.signals()),
        }
    }

    pub fn network_id(&self) -> String {
        match self {
            Self::Caller(s) => s.network_id(),
            Self::Lan(s) => s.network_id(),
            Self::Http(s) => s.network_id(),
        }
    }

    pub fn disable_trickle_ice(&self) -> bool {
        match self {
            Self::Caller(s) => s.disable_trickle_ice(),
            Self::Lan(s) => s.disable_trickle_ice(),
            Self::Http(s) => s.disable_trickle_ice(),
        }
    }
}
