//! Owned admission to the existing bounded session command queue.

use super::{Channel, Command, SessionSender, TaskGuard, transport_now};
use crate::error::{NetherError, Result};
use bytes::Bytes;
use futures::future::pending;
use std::{sync::Arc, time::Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// One slot in the original actor queue, bound to its session and absolute deadline.
/// Dropping it releases capacity without sending. It is not application authorization.
#[must_use = "commit this reservation once or drop it to release capacity"]
pub struct SendPermit {
    permit: mpsc::OwnedPermit<Command>,
    close: CancellationToken,
    deadline: Option<Instant>,
    guard: Arc<TaskGuard>,
}

/// The original actor's result for one committed command.
/// Success means local core admission, not transmission or remote processing.
#[must_use = "retain the receipt to observe the actual actor admission result"]
pub struct SendReceipt {
    reply: oneshot::Receiver<Result<()>>,
    guard: Arc<TaskGuard>,
}

impl SessionSender {
    /// Sends one reliable message through the original reservation and receipt owner.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Reliable, data, None).await
    }

    /// Admits one reliable message before the original absolute deadline.
    /// The actor rechecks immediately before core admission. Canceling this wait
    /// may retract an unadmitted command and never retracts an admitted message.
    pub async fn send_before(&self, data: Bytes, deadline: Instant) -> Result<()> {
        self.send_on(Channel::Reliable, data, Some(deadline)).await
    }

    /// Sends one unreliable message, which must fit the existing single-segment limit.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Unreliable, data, None).await
    }

    /// Reserves one existing command slot without queuing a payload or changing a cipher.
    /// Keep this actual future across unrelated wakes. Cancellation loses its queue
    /// position; dropping a granted permit returns its capacity. The caller can
    /// recheck its own authority before synchronous commit, without another await.
    /// Commands enter the FIFO in commit order, rather than reservation order.
    ///
    /// ```no_run
    /// use bytes::Bytes;
    /// use nethernet_tokio::{Result, SessionSender, session::Channel};
    /// use std::time::Instant;
    ///
    /// async fn send_reserved(sender: &SessionSender, payload: Bytes, deadline: Instant) -> Result<()> {
    ///     let permit = sender.reserve_send(Some(deadline)).await?;
    ///     // Recheck the application's current grant here; do not await before commit.
    ///     let receipt = permit.commit(Channel::Reliable, payload)?;
    ///     receipt.acknowledged().await
    /// }
    /// ```
    pub async fn reserve_send(&self, deadline: Option<Instant>) -> Result<SendPermit> {
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => pending().await,
            }
        };
        let permit = tokio::select! {
            biased;
            _ = self.close_token.cancelled() => return Err(NetherError::ConnectionClosed),
            _ = expired => return Err(NetherError::Timeout),
            result = self.command_tx.clone().reserve_owned() => {
                result.map_err(|_| NetherError::ConnectionClosed)?
            }
        };
        check_open(&self.close_token, deadline)?;
        Ok(SendPermit {
            permit,
            close: self.close_token.clone(),
            deadline,
            guard: Arc::clone(&self._guard),
        })
    }

    /// Keeps invalid payload rejection before capacity waits, sharing the exact commit validation.
    async fn send_on(
        &self,
        channel: Channel,
        data: Bytes,
        deadline: Option<Instant>,
    ) -> Result<()> {
        check_deadline(deadline)?;
        check_size(channel, data.len())?;
        self.reserve_send(deadline)
            .await?
            .commit(channel, data)?
            .acknowledged()
            .await
    }
}

impl SendPermit {
    /// Commits once without yielding, after the caller's fresh application-authority check.
    /// Observed retirement or expiry rejects the command. A concurrent close is
    /// resolved by the same actor and receipt; reservation does not keep it live.
    /// Commands retain their original commit order, not reservation order.
    pub fn commit(self, channel: Channel, data: Bytes) -> Result<SendReceipt> {
        check_open(&self.close, self.deadline)?;
        check_size(channel, data.len())?;
        let (reply, result) = oneshot::channel();
        drop(
            self.permit
                .send(Command::Send(channel, data, self.deadline, reply)),
        );
        Ok(SendReceipt {
            reply: result,
            guard: self.guard,
        })
    }
}

impl SendReceipt {
    /// Consumes the exact actor reply. The original deadline limits capacity acquisition
    /// and local core admission; it does not bound how long this reply wait lasts.
    /// Dropping this wait may retract a not-yet-admitted deadline-bound command;
    /// without a deadline, a queued command remains eligible for admission.
    /// Cancellation preserves any previously admitted prefix and never retracts
    /// an admitted message. No peer delivery is promised.
    pub async fn acknowledged(self) -> Result<()> {
        let Self { reply, guard } = self;
        let result = reply.await.map_err(|_| NetherError::ConnectionClosed)?;
        drop(guard);
        result
    }
}

/// Preserves the caller's absolute deadline across capacity acquisition and commit.
fn check_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| transport_now() >= deadline) {
        return Err(NetherError::Timeout);
    }
    Ok(())
}

/// Observes shared retirement without treating a reserved channel slot as liveness.
fn check_open(close: &CancellationToken, deadline: Option<Instant>) -> Result<()> {
    if close.is_cancelled() {
        return Err(NetherError::ConnectionClosed);
    }
    check_deadline(deadline)
}

/// Uses the original per-channel limits for both ordinary sends and reserved commits.
fn check_size(channel: Channel, size: usize) -> Result<()> {
    let maximum = match channel {
        Channel::Reliable => {
            nethernet::protocol::constants::MAX_MESSAGE_SIZE * usize::from(u8::MAX)
        }
        Channel::Unreliable => nethernet::protocol::constants::MAX_MESSAGE_SIZE.saturating_sub(1),
    };
    if size > maximum {
        return Err(nethernet::error::ProtocolError::MessageSizeExceeded(size).into());
    }
    Ok(())
}
