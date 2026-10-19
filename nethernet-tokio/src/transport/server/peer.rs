//! One bounded incoming negotiation, followed by its owned late-signal forwarding.
use crate::addr::Addr;
use crate::error::{NetherError, SignalErrorCode};
use crate::protocol::Signal;
use crate::session::Ready;
use crate::session::guard::{GatheringGuard, transport_now};
use crate::session::outgoing::CandidateSignaling;
use crate::session::{AcceptedSession, Command, ServerLease, ServerRetirement, Session};
use crate::signaling::ServerSignaling;
use crate::transport::{ConnectionConfig, local_bind_addr, pending::PendingSlot};
use futures::{FutureExt, future::Shared};
use nethernet::admission::OfferPolicy;
use nethernet::connection::IceMode;
use nethernet::phase::Connecting;
use nethernet::session::Session as SansSession;
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
    accepted: AcceptedSession<Connecting>,
    // Retains the actor's exact outcome across dispatch and handoff suspension.
    ready: Shared<oneshot::Receiver<Ready>>,
    deadline: Instant,
    retirement: ServerRetirement,
}

struct Forwarding {
    commands: mpsc::Sender<Command>,
    close: CancellationToken,
    retirement: ServerRetirement,
    // A consumed candidate remains owned through readiness; later signals cannot overtake it.
    pending: Option<Signal>,
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
        let Forwarding {
            commands,
            close,
            mut retirement,
            mut pending,
        } = self.handoff(answered, slot).await?;
        // Forwarding retains no Session or receiver handle; dropping all public owners stops the actor.
        loop {
            tokio::select! {
                biased;
                _ = self.listener.cancelled() => break,
                _ = self.config.cancel_token.cancelled() => break,
                _ = self.stop.cancelled() => { close.cancel(); retirement.preserve_queued(); break; },
                _ = close.cancelled() => { retirement.preserve_queued(); break; },
                permit = commands.reserve(), if pending.is_some() => {
                    let Ok(permit) = permit else {
                        if close.is_cancelled() { retirement.preserve_queued(); }
                        break;
                    };
                    permit.send(Command::Signal(pending.take().expect("reservation has a retained candidate")));
                }
                signal = self.signals.recv(), if pending.is_none() => {
                    let Some(signal) = signal else { break; };
                    pending = Some(signal);
                }
            }
        }
        drop(retirement);
        Ok(())
    }

    /// Waits for the actual actor's readiness and transfers its receiver ownership once.
    async fn handoff(&mut self, answered: Answered, slot: PendingSlot) -> OfferResult<Forwarding> {
        let Answered {
            accepted,
            ready,
            deadline,
            retirement,
        } = answered;
        let close = accepted.session.close_token();
        let commands = accepted.session.signal_sender();
        // Reserve capacity alongside Ready rather than hiding it behind a blocked send.
        let mut pending = None;
        let established = loop {
            tokio::select! {
                biased;
                _ = self.listener.cancelled() => return Err(closed()),
                _ = self.config.cancel_token.cancelled() => return Err(closed()),
                _ = self.stop.cancelled() => { close.cancel(); return Err(closed()); },
                _ = tokio::time::sleep_until(deadline.into()) => return Err(timeout()),
                result = ready.clone() => {
                    let witness = result.map_err(|_| closed())?;
                    if transport_now() >= deadline { return Err(timeout()); }
                    break accepted.establish(witness);
                }
                _ = close.cancelled() => return Err(closed()),
                permit = commands.reserve(), if pending.is_some() => {
                    let permit = permit.map_err(|_| closed())?;
                    permit.send(Command::Signal(pending.take().expect("reservation has a retained candidate")));
                }
                signal = self.signals.recv(), if pending.is_none() => {
                    pending = Some(signal.ok_or_else(closed)?);
                }
            }
        };
        if self.listener.is_cancelled()
            || self.config.cancel_token.is_cancelled()
            || self.stop.is_cancelled()
        {
            return Err(closed());
        }
        if transport_now() >= deadline {
            return Err(timeout());
        }
        drop(slot);
        self.incoming.try_send(established).map_err(|_| closed())?;
        Ok(Forwarding {
            commands,
            close,
            retirement,
            pending,
        })
    }

    /// Reads metadata and dispatches the answer without extending the core's established deadline.
    async fn answer(&self, offer: Signal, lease: Arc<ServerLease>) -> OfferResult<Answered> {
        if self.config.server_ice.as_ref().is_some_and(|ice| {
            ice.ice
                .servers
                .iter()
                .any(|server| server.stream_route().is_some())
        }) {
            return Err((
                None,
                NetherError::Protocol(nethernet::session::IceError::UnsupportedCarrier.into()),
            ));
        }
        if matches!(&self.signaling, ServerSignaling::Caller(_))
            && self.config.token_trust.is_none()
        {
            return Err((
                Some(SignalErrorCode::NotLoggedIn),
                NetherError::InvalidState("caller server requires explicit offer trust".into()),
            ));
        }
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
            .with_anonymous_offers(self.config.allow_anonymous_offers)
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
            UdpSocket::bind(
                self.config
                    .server_ice
                    .as_ref()
                    .map_or_else(local_bind_addr, |ice| ice.bind_addr),
            )
            .await
            .map_err(socket_error)?,
        );
        let bound = socket.local_addr().map_err(socket_error)?;
        let now = transport_now();
        let deadline = now.checked_add(establish).ok_or_else(timeout)?;
        let answered = if let Some(ice) = &self.config.server_ice {
            let (mut core, description) =
                SansSession::new_with_ice(bound, false, rand::random(), ice.ice.clone(), now)
                    .map_err(|error| {
                        (
                            Some(SignalErrorCode::FailedToCreatePeerConnection),
                            error.into(),
                        )
                    })?;
            core.set_establish_deadline(establish);
            let mut gathering =
                GatheringGuard::new(core, socket.clone()).with_server_capacity(lease.clone());
            if ice_mode == IceMode::Full {
                super::super::gather::gather(
                    &socket,
                    gathering.core.as_mut().expect("gathering owns session"),
                    self.negotiation_deadline.min(deadline).into(),
                )
                .await
                .map_err(|error| (Some(SignalErrorCode::Ice), error))?;
            }
            let now = transport_now();
            let prepared = admitted
                .prepare_answer(
                    gathering.core.as_mut().expect("gathering owns session"),
                    description,
                    now,
                    SystemTime::now(),
                )
                .map_err(|error| (Some(error.code()), error.into()))?;
            let core = gathering
                .core
                .take()
                .expect("prepared session is transferred once");
            prepared.finish(core, now)
        } else {
            admitted
                .answer(bound, rand::random(), now)
                .map_err(|error| (Some(error.code()), error.into()))?
        };
        let player = answered.player.map(Arc::new).or(signaled_player);
        for line in &answered.inferred {
            tracing::debug!("Inferred candidate for the peer: {}", line);
        }
        let local = Addr::new(self.signaling.network_id(), offer.connection_id);
        let candidates_enabled = CancellationToken::new();
        let candidate_signaling = CandidateSignaling {
            adapter: self.signaling.clone().into(),
            within: self.config.timeouts.negotiation,
            enabled: Some(candidates_enabled.clone()),
            service_closed: self.signaling.service_closed(),
        };
        let (session, reliable, unreliable, ready) =
            Session::<Connecting>::spawn_for_server_with_signaling(
                socket,
                answered.connection,
                local,
                remote,
                lease,
                candidate_signaling,
            );
        let retirement = session.server_retirement();
        // Cache only the actual actor result; dispatch and handoff may each resume after its close.
        let ready = ready.shared();
        {
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
            tokio::pin!(dispatch);
            loop {
                tokio::select! {
                    biased;
                    _ = self.listener.cancelled() => return Err(closed()),
                    _ = self.config.cancel_token.cancelled() => return Err(closed()),
                    _ = self.stop.cancelled() => return Err(closed()),
                    _ = tokio::time::sleep_until(deadline.into()) => return Err(timeout()),
                    result = &mut dispatch => { result.map_err(|error| (None, error))?; break; },
                    result = ready.clone(), if ready.peek().is_none() => { result.map_err(|_| closed())?; },
                    _ = session.closed(), if !ready.peek().is_some_and(|result| result.is_ok()) => return Err(closed()),
                }
            }
        }
        if transport_now() >= deadline {
            return Err(timeout());
        }
        // Initial answer and its snapshot candidates are now dispatched in their original order.
        candidates_enabled.cancel();
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

#[cfg(test)]
mod tests;
