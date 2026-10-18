//! One bounded incoming negotiation, followed by its owned late-signal forwarding.
use crate::addr::Addr;
use crate::error::{NetherError, Result, SignalErrorCode};
use crate::protocol::Signal;
use crate::session::guard::transport_now;
use crate::session::{AcceptedSession, Command, ServerLease, ServerRetirement, Session};
use crate::signaling::ServerSignaling;
use crate::transport::{ConnectionConfig, local_bind_addr, pending::PendingSlot};
use futures::future::pending;
use nethernet::admission::OfferPolicy;
use nethernet::connection::IceMode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

type OfferResult<T> = std::result::Result<T, (Option<SignalErrorCode>, NetherError)>;

pub(super) struct Peer {
    pub signaling: ServerSignaling,
    pub incoming: mpsc::Sender<AcceptedSession>,
    pub config: ConnectionConfig,
    pub listener: CancellationToken,
    pub stop: CancellationToken,
    pub signals: mpsc::Receiver<Signal>,
    pub negotiation_deadline: Instant,
}

struct Answered {
    accepted: AcceptedSession,
    ready: oneshot::Receiver<()>,
    deadline: Instant,
    retirement: ServerRetirement,
}

impl Peer {
    /// Keeps every fallible stage in the original listener-owned worker.
    pub(super) async fn run(mut self, offer: Signal, slot: PendingSlot, lease: Arc<ServerLease>) {
        let connection_id = offer.connection_id;
        let network_id = offer.network_id.clone();
        // Retain capacity through a bounded refusal as well as actual socket/receiver retirement.
        let _capacity = lease.clone();
        if let Err((code, error)) = self.serve(offer, slot, lease).await {
            tracing::debug!(%error, "incoming connection retired");
            if let Some(code) = code {
                tokio::select! {
                    biased;
                    _ = self.listener.cancelled() => {},
                    _ = self.config.cancel_token.cancelled() => {},
                    _ = self.stop.cancelled() => {},
                    _ = refuse(
                        self.signaling.clone(),
                        Signal::error(connection_id, code, network_id),
                        code,
                        self.config.timeouts.negotiation,
                        self.listener.clone(),
                    ) => {},
                }
            }
        }
    }

    /// A ready handoff releases negotiation admission, but never the retained session reservation.
    async fn serve(
        &mut self,
        offer: Signal,
        slot: PendingSlot,
        lease: Arc<ServerLease>,
    ) -> OfferResult<()> {
        let deadline = self.negotiation_deadline;
        if transport_now() >= deadline {
            return Err(timeout());
        }
        let answered = tokio::select! {
            biased;
            _ = self.listener.cancelled() => return Err(closed()),
            _ = self.config.cancel_token.cancelled() => return Err(closed()),
            _ = self.stop.cancelled() => return Err(closed()),
            _ = tokio::time::sleep_until(deadline.into()) => return Err(timeout()),
            answered = self.answer(offer, lease) => answered?,
        };
        if transport_now() >= deadline {
            return Err(timeout());
        }
        let Answered {
            accepted,
            mut ready,
            deadline,
            mut retirement,
        } = answered;
        let close = accepted.session.close_token();
        let commands = accepted.session.signal_sender();
        loop {
            tokio::select! {
                biased;
                _ = self.listener.cancelled() => return Err(closed()),
                _ = self.config.cancel_token.cancelled() => return Err(closed()),
                _ = self.stop.cancelled() => { close.cancel(); return Err(closed()); },
                _ = close.cancelled() => return Err(closed()),
                _ = tokio::time::sleep_until(deadline.into()) => return Err(timeout()),
                result = &mut ready => {
                    result.map_err(|_| closed())?;
                    if transport_now() >= deadline { return Err(timeout()); }
                    break;
                }
                signal = self.signals.recv() => {
                    self.forward(signal.ok_or_else(closed)?, &commands, &close, Some(deadline)).await.map_err(|error| match error {
                        NetherError::Timeout => timeout(),
                        error => (None, error),
                    })?;
                }
            }
        }
        drop(slot);
        self.incoming.try_send(accepted).map_err(|_| closed())?;
        // Forwarding retains no Session or receiver handle; dropping all public owners stops the actor.
        loop {
            tokio::select! {
                biased;
                _ = self.listener.cancelled() => break,
                _ = self.config.cancel_token.cancelled() => break,
                _ = self.stop.cancelled() => { close.cancel(); retirement.preserve_queued(); break; },
                _ = close.cancelled() => { retirement.preserve_queued(); break; },
                signal = self.signals.recv() => {
                    let Some(signal) = signal else { break; };
                    if self.forward(signal, &commands, &close, None).await.is_err() {
                        if close.is_cancelled() { retirement.preserve_queued(); }
                        break;
                    }
                }
            }
        }
        drop(retirement);
        Ok(())
    }

    /// Reads metadata and dispatches the answer without extending the core's established deadline.
    async fn answer(&self, offer: Signal, lease: Arc<ServerLease>) -> OfferResult<Answered> {
        let remote = Addr::new(offer.network_id.clone(), offer.connection_id);
        let remote_address = self.signaling.remote_address(&remote).await;
        let signaled_player = self.signaling.player(&remote).await;
        let signaled_host = self.signaling.host(&remote).await;
        let ice_mode = if self.signaling.disable_trickle_ice() {
            IceMode::Full
        } else {
            IceMode::Trickle
        };
        let establish = self.config.timeouts.establish();
        let mut policy = OfferPolicy::new(ice_mode)
            .with_inferred_peer_candidates(self.config.infer_peer_candidates)
            .with_establish_deadline(establish);
        if let Some(identity) = &self.config.identity {
            policy = policy.with_identity(identity.as_ref());
        }
        if !self.signaling.validates_offers()
            && let Some(trust) = &self.config.token_trust
        {
            policy = policy.with_token_trust(trust);
        }
        let admitted = policy
            .admit(&offer, remote_address, SystemTime::now())
            .map_err(|error| (Some(error.code()), error.into()))?;
        let socket = Arc::new(
            UdpSocket::bind(local_bind_addr())
                .await
                .map_err(socket_error)?,
        );
        let bound = socket.local_addr().map_err(socket_error)?;
        let now = transport_now();
        let deadline = now.checked_add(establish).ok_or_else(timeout)?;
        let answered = admitted
            .answer(bound, rand::random(), now)
            .map_err(|error| (Some(error.code()), error.into()))?;
        let player = answered.player.map(Arc::new).or(signaled_player);
        for line in &answered.inferred {
            tracing::debug!("Inferred candidate for the peer: {}", line);
        }
        let local = Addr::new(self.signaling.network_id(), offer.connection_id);
        let (session, reliable, unreliable, ready) =
            Session::spawn_for_server(socket, answered.connection, local, remote, lease);
        let retirement = session.server_retirement();
        let dispatch = async {
            if let Some(player) = player {
                session.set_player(player).await;
            }
            if let Some(host) = signaled_host {
                session.set_host(host).await;
            }
            for outgoing in answered.signals {
                self.signaling.signal(outgoing).await?;
            }
            Ok::<_, NetherError>(())
        };
        tokio::select! {
            biased;
            _ = session.closed() => return Err(closed()),
            _ = tokio::time::sleep_until(deadline.into()) => return Err(timeout()),
            result = dispatch => result.map_err(|error| (None, error))?,
        }
        if transport_now() >= deadline {
            return Err(timeout());
        }
        Ok(Answered {
            accepted: AcceptedSession {
                session,
                reliable,
                unreliable,
            },
            ready,
            deadline,
            retirement,
        })
    }

    /// Forwards one late candidate under cancellation and the original ready deadline, if pending.
    async fn forward(
        &self,
        signal: Signal,
        commands: &mpsc::Sender<Command>,
        close: &CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<()> {
        if deadline.is_some_and(|deadline| transport_now() >= deadline) {
            return Err(NetherError::Timeout);
        }
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => pending().await,
            }
        };
        tokio::select! {
            biased;
            _ = self.listener.cancelled() => Err(NetherError::ConnectionClosed),
            _ = self.config.cancel_token.cancelled() => Err(NetherError::ConnectionClosed),
            _ = self.stop.cancelled() => { close.cancel(); Err(NetherError::ConnectionClosed) },
            _ = close.cancelled() => Err(NetherError::ConnectionClosed),
            _ = expired => Err(NetherError::Timeout),
            result = commands.send(Command::Signal(signal)) => result.map_err(|_| NetherError::ConnectionClosed),
        }
    }
}

/// Makes one bounded best-effort refusal without retaining a live or pending transport.
pub(super) async fn refuse(
    signaling: ServerSignaling,
    offer: Signal,
    code: SignalErrorCode,
    within: Duration,
    listener: CancellationToken,
) {
    let Some(deadline) = transport_now().checked_add(within) else {
        return;
    };
    tokio::select! {
        biased;
        _ = listener.cancelled() => {},
        _ = tokio::time::sleep_until(deadline.into()) => {},
        result = signaling.signal(Signal::error(offer.connection_id, code, offer.network_id)) => {
            if let Err(error) = result { tracing::debug!(%error, "failed to refuse incoming connection"); }
        }
    }
}

/// Represents retirement without emitting another signaling error.
fn closed() -> (Option<SignalErrorCode>, NetherError) {
    (None, NetherError::ConnectionClosed)
}

/// Uses the existing incoming-ready signaling error for an expired stage.
fn timeout() -> (Option<SignalErrorCode>, NetherError) {
    (
        Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
        NetherError::Timeout,
    )
}

/// Preserves the existing socket creation error code.
fn socket_error(error: std::io::Error) -> (Option<SignalErrorCode>, NetherError) {
    (
        Some(SignalErrorCode::FailedToCreatePeerConnection),
        error.into(),
    )
}
