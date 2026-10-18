//! One bounded, independently polled late-candidate send.
use crate::error::{NetherError, Result};
use crate::protocol::Signal;
use crate::signaling::{ClientSignaling, ServerSignaling};
use futures::future::BoxFuture;
use std::time::Duration;

/// Concrete signaling owner for the existing single retained candidate send.
#[derive(Clone)]
pub(crate) enum OutgoingSignaling {
    Client(ClientSignaling),
    Server(ServerSignaling),
}

impl From<ClientSignaling> for OutgoingSignaling {
    fn from(signaling: ClientSignaling) -> Self {
        Self::Client(signaling)
    }
}
impl From<ServerSignaling> for OutgoingSignaling {
    fn from(signaling: ServerSignaling) -> Self {
        Self::Server(signaling)
    }
}
impl OutgoingSignaling {
    /// Dispatches through the existing concrete adapter without another queue or service engine.
    async fn signal(&self, signal: Signal) -> Result<()> {
        match self {
            Self::Client(signaling) => signaling.signal(signal).await,
            Self::Server(signaling) => signaling.signal(signal).await,
        }
    }
}

/// The accepting actor progresses before initial answer delivery, but candidates cannot overtake it.
pub(crate) struct CandidateSignaling {
    pub adapter: OutgoingSignaling,
    pub within: Duration,
    pub enabled: Option<tokio_util::sync::CancellationToken>,
    pub service_closed: Option<tokio_util::sync::CancellationToken>,
}

/// Holds one service send while ICE reads and timers continue independently.
pub(crate) fn signal_send(
    signaling: impl Into<OutgoingSignaling>,
    signal: Signal,
    within: Duration,
) -> BoxFuture<'static, Result<()>> {
    let signaling = signaling.into();
    Box::pin(async move {
        let deadline = tokio::time::Instant::now() + within;
        let result = tokio::time::timeout_at(deadline, signaling.signal(signal))
            .await
            .map_err(|_| NetherError::Timeout)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(NetherError::Timeout);
        }
        result
    })
}
