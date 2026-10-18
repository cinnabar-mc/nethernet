//! A bounded per-peer signaling bridge driven by an application-owned service connection.
//!
//! This owner starts no tasks and opens no sockets. Create a separate bridge for
//! each concurrent connection, and multiplex their requests over the caller's
//! messaging socket. Sender routing uses the authenticated messaging envelope,
//! not a peer's separately advertised NetherNet ID. ICE gathering and relay paths remain owned by the configured transport session;
//! this bridge only carries its signals.

use crate::error::Result;
use crate::protocol::{Signal, SignalType};
use futures::Stream;
use nethernet::connection::IceMode;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Bounds apply independently to incoming signals and outstanding outgoing requests.
#[derive(Clone, Copy, Debug)]
pub struct CallerSignalingConfig {
    /// Maximum incoming messages and outgoing requests, including requests held by the driver.
    pub capacity: NonZeroUsize,
    /// Maximum UTF-8 wire signal size, including its type and connection ID.
    pub max_signal_bytes: NonZeroUsize,
    /// Maximum time to admit and complete one outgoing signal; expiry never retries it.
    pub send_timeout: Duration,
    /// Whether candidates are inline or sent separately.
    pub ice_mode: IceMode,
    /// Require a peer receipt as well as service acceptance for an offer.
    pub require_offer_receipt: bool,
}

impl Default for CallerSignalingConfig {
    fn default() -> Self {
        Self {
            capacity: NonZeroUsize::new(16).expect("nonzero capacity"),
            max_signal_bytes: NonZeroUsize::new(nethernet::signaling::http::join::MAX_ANSWER_SIZE)
                .expect("nonzero signal limit"),
            send_timeout: nethernet::connection::Timeouts::default().negotiation,
            ice_mode: IceMode::Trickle,
            require_offer_receipt: true,
        }
    }
}

/// Redacted bridge failures; no signal, account identifier or service body is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CallerSignalingError {
    /// An invalid bound, timeout or routing identifier was supplied.
    #[error("invalid caller signaling configuration")]
    Configuration,
    /// A signal exceeded its byte limit or an incoming queue is full.
    #[error("caller signaling capacity exceeded")]
    Capacity,
    /// Incoming wire text could not be decoded by the transport codec.
    #[error("invalid caller signaling message")]
    InvalidSignal,
    /// The sender, recipient or connection ID does not match this active bridge.
    #[error("caller signaling route mismatch")]
    RouteMismatch,
    /// This bridge already has a live transport subscription.
    #[error("caller signaling already subscribed")]
    AlreadySubscribed,
    /// The service rejected or failed the request; details remain at the service owner.
    #[error("caller signaling service rejected request")]
    Rejected,
    /// An offer completed without its required peer receipt.
    #[error("caller signaling peer receipt required")]
    ReceiptRequired,
    /// The request deadline elapsed; its wire outcome may be ambiguous.
    #[error("caller signaling request timed out")]
    TimedOut,
    /// The driver closed or dropped a request without completing it.
    #[error("caller signaling closed")]
    Closed,
}

/// Completion evidence supplied by the service owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalDelivery {
    /// The messaging service accepted the send request.
    ServiceAccepted,
    /// Service acceptance and the intended peer's receipt have both completed.
    PeerReceived,
}

struct Inbox {
    receiver: Option<mpsc::Receiver<Signal>>,
    connection_id: Option<u64>,
}

/// Transport side of one caller-driven, per-peer bridge.
///
/// Clones refer to the same bridge and permit only one active subscription.
/// The application supplies the same local network ID advertised by its service
/// connection. For Player Messaging, `remote_id` is the intended peer's messaging
/// UUID, not its advertised NetherNet ID. Account authentication, UUID validation,
/// signed SDP key ownership and JSON-RPC correlation remain at the application edge.
#[derive(Clone)]
pub struct CallerSignaling {
    local_id: String,
    remote_id: String,
    config: CallerSignalingConfig,
    outgoing: mpsc::Sender<SignalRequest>,
    slots: Arc<Semaphore>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
}

/// Application side of a bridge; dropping it closes outstanding sends and the subscription.
///
/// Poll `recv` alongside the caller's service driver. Incoming `try_deliver`
/// succeeds only after bounded transport admission: acknowledge that service
/// message afterwards, using the original envelope's message ID and sender UUID.
/// On capacity failure the caller may retain that envelope and retry admission.
/// This owner deliberately has no Debug implementation because requests contain SDP tokens.
pub struct CallerSignalingDriver {
    remote_id: String,
    max_signal_bytes: usize,
    outgoing: mpsc::Receiver<SignalRequest>,
    incoming: mpsc::Sender<Signal>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
}

/// One bounded outbound request, with explicit delivery evidence and cancellation.
///
/// Keep this request until the correlated service operation completes. When
/// `requires_peer_receipt` is true, service acceptance alone cannot complete it.
/// Canceling the transport wait cannot retract already written service bytes;
/// cancel the correlated service handle and never automatically resend it.
/// Dropping a request fails its transport wait. No Debug implementation exposes its SDP.
pub struct SignalRequest {
    signal: Signal,
    require_receipt: bool,
    deadline: Instant,
    completion: oneshot::Sender<std::result::Result<(), CallerSignalingError>>,
    closed: CancellationToken,
    _slot: OwnedSemaphorePermit,
}

impl CallerSignaling {
    /// Creates a bridge without I/O, tasks or a runtime.
    ///
    /// # Errors
    /// Rejects zero/unrepresentable timeouts, oversized channel capacity and empty
    /// or oversized routing IDs before constructing channels.
    pub fn new(
        local_id: String,
        remote_id: String,
        config: CallerSignalingConfig,
    ) -> std::result::Result<(Self, CallerSignalingDriver), CallerSignalingError> {
        let capacity = config.capacity.get();
        let max_bytes = config.max_signal_bytes.get();
        if capacity > Semaphore::MAX_PERMITS
            || capacity.checked_mul(max_bytes).is_none()
            || config.send_timeout.is_zero()
            || Instant::now().checked_add(config.send_timeout).is_none()
            || local_id.is_empty()
            || remote_id.is_empty()
            || local_id.len() > max_bytes
            || remote_id.len() > max_bytes
        {
            return Err(CallerSignalingError::Configuration);
        }
        let (outgoing, requests) = mpsc::channel(capacity);
        let (incoming, receiver) = mpsc::channel(capacity);
        let inbox = Arc::new(Mutex::new(Inbox {
            receiver: Some(receiver),
            connection_id: None,
        }));
        let closed = CancellationToken::new();
        Ok((
            Self {
                local_id,
                remote_id: remote_id.clone(),
                config,
                outgoing,
                slots: Arc::new(Semaphore::new(capacity)),
                inbox: inbox.clone(),
                closed: closed.clone(),
            },
            CallerSignalingDriver {
                remote_id,
                max_signal_bytes: max_bytes,
                outgoing: requests,
                incoming,
                inbox,
                closed,
            },
        ))
    }

    /// Sends a signal once, waiting for the caller's explicit completion evidence.
    /// Dropping the future cancels its wait; the driver can observe this via the request.
    /// The first offer binds an active subscription to its connection ID.
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        if signal.network_id != self.remote_id {
            return Err(CallerSignalingError::RouteMismatch.into());
        }
        if wire_size(&signal).is_none_or(|size| size > self.config.max_signal_bytes.get()) {
            return Err(CallerSignalingError::Capacity.into());
        }
        {
            let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
            if signal.signal_type == SignalType::Offer
                && inbox.receiver.is_none()
                && inbox.connection_id.is_none()
            {
                inbox.connection_id = Some(signal.connection_id);
            } else if inbox.connection_id != Some(signal.connection_id) {
                return Err(CallerSignalingError::RouteMismatch.into());
            }
        }
        let deadline = tokio::time::Instant::now()
            .into_std()
            .checked_add(self.config.send_timeout)
            .ok_or(CallerSignalingError::Configuration)?;
        let send = async {
            let slot = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CallerSignalingError::Closed)?;
            let (completion, result) = oneshot::channel();
            self.outgoing
                .send(SignalRequest {
                    require_receipt: signal.signal_type == SignalType::Offer
                        && self.config.require_offer_receipt,
                    signal,
                    deadline,
                    completion,
                    closed: self.closed.clone(),
                    _slot: slot,
                })
                .await
                .map_err(|_| CallerSignalingError::Closed)?;
            result.await.map_err(|_| CallerSignalingError::Closed)?
        };
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(CallerSignalingError::Closed.into()),
            result = tokio::time::timeout_at(deadline.into(), send) => {
                result.map_err(|_| CallerSignalingError::TimedOut)?.map_err(Into::into)
            }
        }
    }

    /// Borrows the sole incoming stream; dropping it allows a later negotiation attempt.
    /// Queued signals from the old subscription are discarded on drop.
    pub fn signals(&self) -> Result<Pin<Box<dyn Stream<Item = Signal> + Send>>> {
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        let receiver = inbox
            .receiver
            .take()
            .ok_or(CallerSignalingError::AlreadySubscribed)?;
        inbox.connection_id = None;
        let subscription = Subscription {
            receiver: Some(receiver),
            inbox: self.inbox.clone(),
            closed: self.closed.clone(),
        };
        Ok(Box::pin(futures::stream::unfold(
            subscription,
            |mut subscription| async move {
                let signal = tokio::select! {
                    biased;
                    _ = subscription.closed.cancelled() => None,
                    signal = subscription.receiver.as_mut().expect("subscription owns receiver").recv() => signal,
                }?;
                Some((signal, subscription))
            },
        )))
    }

    /// Returns the caller's local advertised network ID.
    pub fn network_id(&self) -> String {
        self.local_id.clone()
    }

    /// Returns whether candidates must travel inline.
    pub fn disable_trickle_ice(&self) -> bool {
        self.config.ice_mode == IceMode::Full
    }
}

/// Computes wire size without allocating another copy of an SDP.
fn wire_size(signal: &Signal) -> Option<usize> {
    let digits = if signal.connection_id == 0 {
        1
    } else {
        signal.connection_id.ilog10() as usize + 1
    };
    signal
        .signal_type
        .as_str()
        .len()
        .checked_add(digits)?
        .checked_add(2)?
        .checked_add(signal.data.len())
}

impl CallerSignalingDriver {
    /// Receives the next live request; cancellation of this wait does not consume a request.
    /// Canceled queued requests are released before returning the next one.
    pub async fn recv(&mut self) -> Option<SignalRequest> {
        loop {
            let request = tokio::select! {
                biased;
                _ = self.closed.cancelled() => return None,
                request = self.outgoing.recv() => request?,
            };
            if !request.is_cancelled() {
                return Some(request);
            }
        }
    }

    /// Decodes and admits an incoming signal from its authenticated envelope sender.
    ///
    /// For Player Messaging pass `ReceivedSignal::sender().to_string()`, never
    /// its separately advertised `network_id`. Wrong peers and stale connection
    /// IDs do not enter the queue. Success permits the caller's explicit receipt.
    pub fn try_deliver(
        &self,
        sender: &str,
        wire: &str,
    ) -> std::result::Result<(), CallerSignalingError> {
        let signal = self.decode(sender, wire)?;
        let inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        check_subscription(&inbox, &signal)?;
        self.incoming.try_send(signal).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CallerSignalingError::Capacity,
            mpsc::error::TrySendError::Closed(_) => CallerSignalingError::Closed,
        })
    }

    /// Validates an envelope now and returns an owned, cancel-safe incoming admission future.
    /// Retain this future while driving service I/O; acknowledge only after it succeeds.
    /// Dropping it before admission sends nothing. The caller owns its original deadline.
    pub fn prepare_delivery(
        &self,
        sender: &str,
        wire: &str,
    ) -> std::result::Result<
        impl std::future::Future<Output = std::result::Result<(), CallerSignalingError>> + Send + use<>,
        CallerSignalingError,
    > {
        self.prepare_delivery_inner(sender, wire, None)
    }

    /// Retains an incoming envelope's original absolute deadline through actual transport admission.
    /// Dropping this owned future before admission sends nothing; receipts follow successful admission.
    pub fn prepare_delivery_before(
        &self,
        sender: &str,
        wire: &str,
        deadline: Instant,
    ) -> std::result::Result<
        impl std::future::Future<Output = std::result::Result<(), CallerSignalingError>> + Send + use<>,
        CallerSignalingError,
    > {
        let delivery = self.prepare_delivery_inner(sender, wire, Some(deadline))?;
        Ok(async move {
            tokio::time::timeout_at(deadline.into(), delivery)
                .await
                .map_err(|_| CallerSignalingError::TimedOut)?
        })
    }

    /// Shares route validation, capacity reservation and subscription admission for either deadline policy.
    fn prepare_delivery_inner(
        &self,
        sender: &str,
        wire: &str,
        deadline: Option<Instant>,
    ) -> std::result::Result<
        impl std::future::Future<Output = std::result::Result<(), CallerSignalingError>> + Send + use<>,
        CallerSignalingError,
    > {
        let signal = self.decode(sender, wire)?;
        check_subscription(
            &self.inbox.lock().unwrap_or_else(|error| error.into_inner()),
            &signal,
        )?;
        let incoming = self.incoming.clone();
        let inbox = self.inbox.clone();
        let closed = self.closed.clone();
        Ok(async move {
            let permit = tokio::select! {
                biased;
                _ = closed.cancelled() => return Err(CallerSignalingError::Closed),
                permit = incoming.reserve_owned() => permit.map_err(|_| CallerSignalingError::Closed)?,
            };
            let inbox = inbox.lock().unwrap_or_else(|error| error.into_inner());
            if closed.is_cancelled() {
                return Err(CallerSignalingError::Closed);
            }
            check_subscription(&inbox, &signal)?;
            if deadline.is_some_and(|deadline| tokio::time::Instant::now().into_std() >= deadline) {
                return Err(CallerSignalingError::TimedOut);
            }
            permit.send(signal);
            Ok(())
        })
    }

    /// Bounds and decodes authenticated routing input without admitting it to the subscription.
    fn decode(
        &self,
        sender: &str,
        wire: &str,
    ) -> std::result::Result<Signal, CallerSignalingError> {
        if self.closed.is_cancelled() {
            return Err(CallerSignalingError::Closed);
        }
        if sender != self.remote_id {
            return Err(CallerSignalingError::RouteMismatch);
        }
        if wire.len() > self.max_signal_bytes {
            return Err(CallerSignalingError::Capacity);
        }
        Signal::from_string(wire, self.remote_id.clone())
            .map_err(|_| CallerSignalingError::InvalidSignal)
    }

    /// Closes this bridge without closing the application's shared service connection.
    pub fn close(&mut self) {
        self.closed.cancel();
        self.outgoing.close();
        while self.outgoing.try_recv().is_ok() {}
    }
}

/// Checks the current subscription again immediately before publishing a reserved signal.
fn check_subscription(
    inbox: &Inbox,
    signal: &Signal,
) -> std::result::Result<(), CallerSignalingError> {
    if inbox.receiver.is_some() || inbox.connection_id != Some(signal.connection_id) {
        Err(CallerSignalingError::RouteMismatch)
    } else {
        Ok(())
    }
}

impl Drop for CallerSignalingDriver {
    fn drop(&mut self) {
        self.close();
    }
}

impl SignalRequest {
    /// Borrows the outgoing signal; its network ID is the recipient routing identity.
    pub fn signal(&self) -> &Signal {
        &self.signal
    }

    /// Returns whether successful completion needs a peer receipt as well as service acceptance.
    pub fn requires_peer_receipt(&self) -> bool {
        self.require_receipt
    }

    /// Returns the original monotonic deadline, including time spent waiting for bridge capacity.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns whether the bridge closed, the transport abandoned this request or its deadline elapsed.
    pub fn is_cancelled(&self) -> bool {
        self.closed.is_cancelled()
            || self.completion.is_closed()
            || tokio::time::Instant::now().into_std() >= self.deadline
    }

    /// Waits until the bridge closes, the transport abandons this request or its deadline elapses.
    /// This does not itself cancel the application's correlated service operation.
    pub async fn cancelled(&mut self) {
        tokio::select! {
            _ = self.closed.cancelled() => {},
            _ = self.completion.closed() => {},
            _ = tokio::time::sleep_until(self.deadline.into()) => {},
        }
    }

    /// Completes one correlated request; receipt evidence must include service acceptance.
    /// A late completion after cancellation is harmless. Service failures must be
    /// mapped to a redacted bridge error while details stay with the service owner.
    /// The deadline applies when completion is reported here, independent of when
    /// the transport next polls its wait. Reports at or after it fail as TimedOut.
    pub fn finish(self, result: std::result::Result<SignalDelivery, CallerSignalingError>) {
        let result = if self.closed.is_cancelled() {
            Err(CallerSignalingError::Closed)
        } else if tokio::time::Instant::now().into_std() >= self.deadline {
            Err(CallerSignalingError::TimedOut)
        } else {
            result.and_then(|delivery| {
                if self.require_receipt && delivery != SignalDelivery::PeerReceived {
                    Err(CallerSignalingError::ReceiptRequired)
                } else {
                    Ok(())
                }
            })
        };
        let _ = self.completion.send(result);
    }
}

struct Subscription {
    receiver: Option<mpsc::Receiver<Signal>>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(mut receiver) = self.receiver.take() {
            let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
            while receiver.try_recv().is_ok() {}
            inbox.receiver = Some(receiver);
        }
    }
}

#[cfg(test)]
mod tests;
