//! The listener owns every pending peer and routes only bounded late signals.
use super::{SharedTrust, peer};
use crate::error::SignalErrorCode;
use crate::protocol::{Signal, SignalType};
use crate::session::guard::transport_now;
use crate::session::{AcceptedSession, ServerLease, command::COMMAND_CAPACITY};
use crate::signaling::ServerSignaling;
use crate::transport::{ConnectionConfig, pending::PendingOffers};
use futures::StreamExt;
use futures::future::{BoxFuture, pending};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

type ConnectionKey = (String, u64);

struct Route {
    signals: mpsc::Sender<Signal>,
    stop: CancellationToken,
}

/// Reserves capacity before asynchronous offer work and owns every worker until retirement.
pub(super) fn start(
    signaling: ServerSignaling,
    incoming: mpsc::Sender<AcceptedSession>,
    listener: CancellationToken,
    config: ConnectionConfig,
    trust: SharedTrust,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _retired = listener.clone().drop_guard();
        let slots = Arc::new(Semaphore::new(config.max_sessions));
        let pending_offers = PendingOffers::default();
        let mut routes: HashMap<ConnectionKey, Route> = HashMap::new();
        let mut peers = JoinSet::new();
        let mut signals = signaling.signals();
        // Refusals have one retained send; overload cannot spawn an unbounded rejection task set.
        let mut refusal: Option<BoxFuture<'static, ()>> = None;

        loop {
            tokio::select! {
                biased;
                _ = listener.cancelled() => break,
                _ = config.cancel_token.cancelled() => break,
                result = peers.join_next(), if !peers.is_empty() => {
                    match result {
                        Some(Ok(key)) => { routes.remove(&key); }
                        Some(Err(error)) => {
                            tracing::debug!(%error, "incoming peer worker stopped");
                            routes.retain(|_, route| !route.signals.is_closed());
                        }
                        None => {}
                    }
                }
                _ = async {
                    match &mut refusal { Some(send) => send.await, None => pending().await }
                } => { refusal = None; }
                signal = signals.next() => {
                    let Some(signal) = signal else { break; };
                    let key = (signal.network_id.clone(), signal.connection_id);
                    match signal.signal_type {
                        SignalType::Offer => {
                            if routes.contains_key(&key) {
                                // Repeated offers must never replace an existing peer's route.
                                continue;
                            }
                            let admission = slots.clone().try_acquire_owned().ok().and_then(|slot| {
                                pending_offers.try_admit(
                                    &signal.network_id,
                                    config.max_pending,
                                    config.max_pending_per_network_id,
                                ).map(|pending| (slot, pending))
                            });
                            let Some((slot, pending)) = admission else {
                                if refusal.is_none() {
                                    refusal = Some(Box::pin(peer::refuse(
                                        signaling.clone(),
                                        signal,
                                        SignalErrorCode::IncomingConnectionIgnored,
                                        config.timeouts.negotiation,
                                        listener.clone(),
                                    )));
                                }
                                continue;
                            };
                            let Some(negotiation_deadline) = transport_now().checked_add(config.timeouts.negotiation) else {
                                continue;
                            };
                            let mut peer_config = config.clone();
                            peer_config.token_trust = trust.read().unwrap_or_else(PoisonError::into_inner).clone();
                            let (signal_tx, signal_rx) = mpsc::channel(COMMAND_CAPACITY);
                            let stop = CancellationToken::new();
                            routes.insert(key.clone(), Route { signals: signal_tx, stop: stop.clone() });
                            let peer = peer::Peer {
                                signaling: signaling.clone(),
                                incoming: incoming.clone(),
                                config: peer_config,
                                listener: listener.clone(),
                                stop,
                                signals: signal_rx,
                                negotiation_deadline,
                            };
                            peers.spawn(async move {
                                peer.run(signal, pending, ServerLease::new(slot)).await;
                                key
                            });
                        }
                        SignalType::Candidate => {
                            if let Some(route) = routes.get(&key)
                                && route.signals.try_send(signal).is_err()
                            {
                                // Bounded overflow retires only this peer, without stalling control for others.
                                route.stop.cancel();
                            }
                        }
                        SignalType::Error => {
                            if let Some(route) = routes.get(&key) { route.stop.cancel(); }
                        }
                        SignalType::Answer => {}
                    }
                }
            }
        }
        // No peer can remain detached behind metadata, answer delivery or ready wait.
        listener.cancel();
        peers.abort_all();
        while peers.join_next().await.is_some() {}
    })
}
