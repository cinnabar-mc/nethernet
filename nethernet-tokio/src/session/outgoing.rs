//! One bounded, independently polled late-candidate send.
use crate::error::{NetherError, Result};
use crate::protocol::Signal;
use crate::signaling::ClientSignaling;
use futures::future::BoxFuture;
use std::time::Duration;

/// Holds one service send while ICE reads and timers continue independently.
pub(crate) fn signal_send(
    signaling: ClientSignaling,
    signal: Signal,
    within: Duration,
) -> BoxFuture<'static, Result<()>> {
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
