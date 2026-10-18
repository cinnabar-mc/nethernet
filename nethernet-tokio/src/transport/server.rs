//! A bounded listener whose unaccepted peer tasks retire with the listener.
mod listener;
mod peer;

use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::session::AcceptedSession;
use crate::signaling::ServerSignaling;
use crate::transport::ConnectionConfig;
use futures::Stream;
use nethernet::identity::TokenTrust;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

type SharedTrust = Arc<RwLock<Option<TokenTrust>>>;

/// Answers offers arriving on its signaling and yields the connected sessions.
/// Negotiating, queued and accepted sessions share `ConnectionConfig::max_sessions`.
pub struct NetherServer {
    incoming: mpsc::Receiver<AcceptedSession>,
    local_addr: Addr,
    signaling: ServerSignaling,
    token_trust: SharedTrust,
    cancel_token: CancellationToken,
    signal_handler_task: Option<JoinHandle<()>>,
}

impl NetherServer {
    pub async fn bind(signaling: impl Into<ServerSignaling>) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Fails with IdentityRequired when the signaling needs signed answers and the config has no identity.
    /// Rejects capacity or deadline settings that cannot be represented by the runtime.
    pub async fn bind_with(
        signaling: impl Into<ServerSignaling>,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let signaling: ServerSignaling = signaling.into();
        if signaling.requires_identity()
            && config.identity.is_none()
            && !config.allow_unsigned_answers
        {
            return Err(NetherError::IdentityRequired);
        }
        let establish = config.timeouts.start.checked_add(config.timeouts.channel);
        let now = crate::session::guard::transport_now();
        if config.max_sessions > Semaphore::MAX_PERMITS
            || establish
                .and_then(|within| now.checked_add(within))
                .is_none()
            || now.checked_add(config.timeouts.negotiation).is_none()
        {
            return Err(NetherError::InvalidState(
                "unrepresentable server admission settings".into(),
            ));
        }
        let local_addr = Addr::network(signaling.network_id());
        // Zero disables admission, while Tokio requires a nonzero channel capacity.
        let (incoming_tx, incoming_rx) = mpsc::channel(config.max_sessions.max(1));
        let cancel_token = CancellationToken::new();
        let token_trust = Arc::new(RwLock::new(config.token_trust.clone()));
        let signal_handler_task = listener::start(
            signaling.clone(),
            incoming_tx,
            cancel_token.clone(),
            config,
            token_trust.clone(),
        );

        Ok(Self {
            incoming: incoming_rx,
            local_addr,
            signaling,
            token_trust,
            cancel_token,
            signal_handler_task: Some(signal_handler_task),
        })
    }

    /// Next connected session; fails with ConnectionClosed once the server is closed.
    pub async fn accept(&mut self) -> Result<AcceptedSession> {
        futures::future::poll_fn(|cx| self.poll_accept(cx))
            .await
            .ok_or(NetherError::ConnectionClosed)
    }

    /// Crosses the same synchronous ownership boundary for `accept` and `Stream`.
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Option<AcceptedSession>> {
        if self.cancel_token.is_cancelled() {
            return Poll::Ready(None);
        }
        loop {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(accepted)) => {
                    if accepted.session.accept_from_server() {
                        return Poll::Ready(Some(accepted));
                    }
                    // A peer may retire while queued; retain no closed pending owner here.
                }
                result => return result,
            }
        }
    }

    /// Stops signaling and closes sessions that were not yet accepted.
    /// Accepted receivers retain their FIFO and capacity until their owners retire.
    pub async fn close(&mut self) -> Result<()> {
        self.cancel_token.cancel();
        self.incoming.close();
        while let Ok(accepted) = self.incoming.try_recv() {
            accepted.session.close().await?;
        }
        if let Some(task) = self.signal_handler_task.as_mut() {
            let _ = task.await;
        }
        self.signal_handler_task.take();
        Ok(())
    }

    pub fn local_addr(&self) -> &Addr {
        &self.local_addr
    }

    /// Replaces how later offers are authenticated; `None` skips validation.
    /// Over HTTP signaling the signaler authenticates offers, so its trust is replaced instead.
    pub fn set_token_trust(&self, trust: Option<TokenTrust>) {
        match &self.signaling {
            ServerSignaling::Http(signaling) => signaling.set_token_trust(trust),
            ServerSignaling::Lan(_) => {
                *self
                    .token_trust
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = trust;
            }
        }
    }
}

impl Drop for NetherServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl Stream for NetherServer {
    type Item = AcceptedSession;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_accept(cx)
    }
}

#[cfg(test)]
mod tests;
