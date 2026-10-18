//! Bounded unsolicited offers from a caller-authenticated service connection.
use super::{
    CallerSignalingConfig, CallerSignalingError, SignalRequest, send_request, validate_config,
    wire_size,
};
use crate::error::Result;
use crate::protocol::{Signal, SignalType};
use futures::Stream;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

type Key = (String, u64);
type BridgeResult<T> = std::result::Result<T, CallerSignalingError>;

/// Queue/request bounds and independent retained peer-route limits.
#[derive(Clone, Copy, Debug)]
pub struct CallerServerSignalingConfig {
    /// Reuses the client bridge's byte, queue, send deadline and ICE mode policy.
    /// A server never emits offers, so require_offer_receipt does not apply.
    pub signaling: CallerSignalingConfig,
    /// Includes reserved offers, pending, accepted and retained closed receivers.
    pub max_routes: NonZeroUsize,
    /// The same retained limit for one authenticated service sender.
    pub max_routes_per_sender: NonZeroUsize,
}

impl Default for CallerServerSignalingConfig {
    fn default() -> Self {
        Self {
            signaling: CallerSignalingConfig::default(),
            max_routes: NonZeroUsize::new(nethernet::protocol::constants::DEFAULT_MAX_PENDING)
                .expect("nonzero route bound"),
            max_routes_per_sender: NonZeroUsize::new(
                nethernet::protocol::constants::DEFAULT_MAX_PENDING_PER_NETWORK_ID,
            )
            .expect("nonzero sender bound"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Reserved,
    Queued,
    Claimed,
    Retired,
}

struct Route {
    epoch: Arc<()>,
    state: State,
    closed: CancellationToken,
    active: CancellationToken,
}

struct Inbox {
    receiver: Option<mpsc::Receiver<Signal>>,
    subscription: Option<Arc<()>>,
    routes: HashMap<Key, Route>,
}

/// Transport side of one multi-peer accepting bridge. No sockets, tasks or account keys.
///
/// Sender IDs must come from authenticated service envelopes, never advertised
/// NetherNet IDs. The caller owns service authorization, peer/account correlation,
/// offer trust, original envelope deadlines and receipts after successful admission.
#[derive(Clone)]
pub struct CallerServerSignaling {
    local_id: String,
    config: CallerServerSignalingConfig,
    outgoing: mpsc::Sender<SignalRequest>,
    slots: Arc<Semaphore>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
}

/// Caller-polled application edge. Dropping it closes every route and outstanding request.
/// Keep it driven alongside the shared authenticated service connection.
pub struct CallerServerSignalingDriver {
    config: CallerServerSignalingConfig,
    outgoing: mpsc::Receiver<SignalRequest>,
    incoming: mpsc::Sender<Signal>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
}

impl CallerServerSignaling {
    /// Creates bounded queues without I/O or tasks. Rejects unrepresentable settings first.
    pub fn new(
        local_id: String,
        config: CallerServerSignalingConfig,
    ) -> BridgeResult<(Self, CallerServerSignalingDriver)> {
        validate_config(&local_id, None, &config.signaling)?;
        if config.max_routes.get() > Semaphore::MAX_PERMITS
            || config
                .max_routes
                .get()
                .checked_mul(config.signaling.max_signal_bytes.get())
                .is_none()
            || config.max_routes_per_sender > config.max_routes
        {
            return Err(CallerSignalingError::Configuration);
        }
        let (outgoing, requests) = mpsc::channel(config.signaling.capacity.get());
        let (incoming, receiver) = mpsc::channel(config.signaling.capacity.get());
        let inbox = Arc::new(Mutex::new(Inbox {
            receiver: Some(receiver),
            subscription: None,
            routes: HashMap::new(),
        }));
        let closed = CancellationToken::new();
        Ok((
            Self {
                local_id,
                slots: Arc::new(Semaphore::new(config.signaling.capacity.get())),
                config,
                outgoing,
                inbox: inbox.clone(),
                closed: closed.clone(),
            },
            CallerServerSignalingDriver {
                config,
                outgoing: requests,
                incoming,
                inbox,
                closed,
            },
        ))
    }

    /// Sends an answer, late candidate or refusal only for an existing exact route.
    /// Completion uses the same SignalRequest/deadline owner as client signaling.
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        if signal.signal_type == SignalType::Offer {
            return Err(CallerSignalingError::RouteMismatch.into());
        }
        if wire_size(&signal).is_none_or(|size| size > self.config.signaling.max_signal_bytes.get())
        {
            return Err(CallerSignalingError::Capacity.into());
        }
        let route_closed = {
            let inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
            let route = inbox
                .routes
                .get(&(signal.network_id.clone(), signal.connection_id))
                .ok_or(CallerSignalingError::RouteMismatch)?;
            let allowed = if signal.signal_type == SignalType::Error {
                matches!(route.state, State::Claimed | State::Retired)
            } else {
                route.state == State::Claimed
            };
            if !allowed {
                return Err(CallerSignalingError::RouteMismatch.into());
            }
            // Refusal retains the exact route lifetime even after its actor ended.
            Some(if signal.signal_type == SignalType::Error {
                route.closed.clone()
            } else {
                route.active.clone()
            })
        };
        send_request(
            &self.outgoing,
            &self.slots,
            &self.closed,
            signal,
            self.config.signaling.send_timeout,
            false,
            route_closed,
        )
        .await
    }

    /// Takes the one listener subscription. Duplicate binds fail without spawning a listener.
    pub fn signals(&self) -> Result<Pin<Box<dyn Stream<Item = Signal> + Send>>> {
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        if self.closed.is_cancelled() {
            return Err(CallerSignalingError::Closed.into());
        }
        let receiver = inbox
            .receiver
            .take()
            .ok_or(CallerSignalingError::AlreadySubscribed)?;
        let epoch = Arc::new(());
        inbox.subscription = Some(epoch.clone());
        let subscription = Subscription {
            receiver: Some(receiver),
            inbox: self.inbox.clone(),
            closed: self.closed.clone(),
            epoch,
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

    /// Returns the caller's advertised local ID, without granting it peer authority.
    pub fn network_id(&self) -> String {
        self.local_id.clone()
    }

    /// Whether local candidates must be gathered before the signed answer is encoded.
    pub fn disable_trickle_ice(&self) -> bool {
        self.config.signaling.ice_mode == nethernet::connection::IceMode::Full
    }

    /// Transfers one queued offer reservation into the concrete listener/session lifetime.
    pub(crate) fn claim(&self, signal: &Signal) -> BridgeResult<CallerRoute> {
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        let key = (signal.network_id.clone(), signal.connection_id);
        let route = inbox
            .routes
            .get_mut(&key)
            .ok_or(CallerSignalingError::RouteMismatch)?;
        if route.state != State::Queued {
            return Err(CallerSignalingError::RouteMismatch);
        }
        route.state = State::Claimed;
        Ok(CallerRoute {
            key,
            epoch: route.epoch.clone(),
            inbox: self.inbox.clone(),
            armed: true,
        })
    }

    /// Shared service closure, independent of closing only the accepting listener.
    pub(crate) fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }
}

impl CallerServerSignalingDriver {
    /// Receives one live request; a canceled recv wait consumes nothing.
    pub async fn recv(&mut self) -> Option<SignalRequest> {
        loop {
            let request = tokio::select! { biased; _ = self.closed.cancelled() => return None, request = self.outgoing.recv() => request? };
            if !request.is_cancelled() {
                return Some(request);
            }
        }
    }

    /// Admits immediately from an authenticated sender, acknowledging only actual queue commitment.
    pub fn try_deliver(&self, sender: &str, wire: &str) -> BridgeResult<()> {
        let prepared = self.prepare(sender, wire, None)?;
        let permit = self
            .incoming
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => CallerSignalingError::Capacity,
                mpsc::error::TrySendError::Closed(_) => CallerSignalingError::Closed,
            })?;
        prepared.commit(permit)
    }

    /// Retains an owned cancel-safe capacity wait. An unpolled/dropped offer releases its reservation.
    pub fn prepare_delivery(
        &self,
        sender: &str,
        wire: &str,
    ) -> BridgeResult<impl Future<Output = BridgeResult<()>> + Send + use<>> {
        self.delivery(sender, wire, None)
    }

    /// Enforces the original deadline under the route lock immediately before permit.send.
    pub fn prepare_delivery_before(
        &self,
        sender: &str,
        wire: &str,
        deadline: Instant,
    ) -> BridgeResult<impl Future<Output = BridgeResult<()>> + Send + use<>> {
        self.delivery(sender, wire, Some(deadline))
    }

    /// Shares actual queue admission and optional absolute deadline without awaiting under a lock.
    fn delivery(
        &self,
        sender: &str,
        wire: &str,
        deadline: Option<Instant>,
    ) -> BridgeResult<impl Future<Output = BridgeResult<()>> + Send + use<>> {
        let prepared = self.prepare(sender, wire, deadline)?;
        let incoming = self.incoming.clone();
        let closed = self.closed.clone();
        Ok(async move {
            let deliver = async move {
                let permit = tokio::select! { biased; _ = closed.cancelled() => return Err(CallerSignalingError::Closed), permit = incoming.reserve_owned() => permit.map_err(|_| CallerSignalingError::Closed)? };
                prepared.commit(permit)
            };
            match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline.into(), deliver)
                    .await
                    .map_err(|_| CallerSignalingError::TimedOut)?,
                None => deliver.await,
            }
        })
    }

    /// Bounds decoding and reserves offer ownership before a caller can retain a waiting future.
    fn prepare(
        &self,
        sender: &str,
        wire: &str,
        deadline: Option<Instant>,
    ) -> BridgeResult<Prepared> {
        if self.closed.is_cancelled() {
            return Err(CallerSignalingError::Closed);
        }
        let max_bytes = self.config.signaling.max_signal_bytes.get();
        if sender.is_empty() {
            return Err(CallerSignalingError::RouteMismatch);
        }
        if sender.len() > max_bytes || wire.len() > max_bytes {
            return Err(CallerSignalingError::Capacity);
        }
        let signal = Signal::from_string(wire, sender.to_owned())
            .map_err(|_| CallerSignalingError::InvalidSignal)?;
        if signal.signal_type == SignalType::Answer {
            return Err(CallerSignalingError::RouteMismatch);
        }
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        let subscription = inbox
            .subscription
            .clone()
            .ok_or(CallerSignalingError::RouteMismatch)?;
        let key = (sender.to_owned(), signal.connection_id);
        let mut reservation = None;
        let epoch = if signal.signal_type == SignalType::Offer {
            if inbox.routes.contains_key(&key) {
                return Err(CallerSignalingError::RouteMismatch);
            }
            if inbox.routes.len() >= self.config.max_routes.get()
                || inbox
                    .routes
                    .keys()
                    .filter(|(peer, _)| peer == sender)
                    .count()
                    >= self.config.max_routes_per_sender.get()
            {
                return Err(CallerSignalingError::Capacity);
            }
            let epoch = Arc::new(());
            inbox.routes.insert(
                key.clone(),
                Route {
                    epoch: epoch.clone(),
                    state: State::Reserved,
                    closed: CancellationToken::new(),
                    active: CancellationToken::new(),
                },
            );
            reservation = Some(CallerRoute {
                key: key.clone(),
                epoch: epoch.clone(),
                inbox: self.inbox.clone(),
                armed: true,
            });
            epoch
        } else {
            let route = inbox
                .routes
                .get(&key)
                .ok_or(CallerSignalingError::RouteMismatch)?;
            if !matches!(route.state, State::Queued | State::Claimed) {
                return Err(CallerSignalingError::RouteMismatch);
            }
            route.epoch.clone()
        };
        Ok(Prepared {
            signal,
            subscription,
            epoch,
            inbox: self.inbox.clone(),
            closed: self.closed.clone(),
            deadline,
            reservation,
        })
    }

    /// Stops all admission and makes caller-held requests observe closure.
    pub fn close(&mut self) {
        // The same mutex serializes receiver retirement with the last permit.send check.
        let _inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        self.closed.cancel();
        self.outgoing.close();
        while self.outgoing.try_recv().is_ok() {}
    }
}

impl Drop for CallerServerSignalingDriver {
    fn drop(&mut self) {
        self.close();
    }
}

struct Prepared {
    signal: Signal,
    subscription: Arc<()>,
    epoch: Arc<()>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
    deadline: Option<Instant>,
    reservation: Option<CallerRoute>,
}

impl Prepared {
    /// Serializes route/subscription retirement and original deadline with the actual queue commit.
    fn commit(mut self, permit: mpsc::OwnedPermit<Signal>) -> BridgeResult<()> {
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        if self.closed.is_cancelled() {
            return Err(CallerSignalingError::Closed);
        }
        if inbox
            .subscription
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &self.subscription))
        {
            return Err(CallerSignalingError::RouteMismatch);
        }
        let route = inbox
            .routes
            .get_mut(&(self.signal.network_id.clone(), self.signal.connection_id))
            .ok_or(CallerSignalingError::RouteMismatch)?;
        if !Arc::ptr_eq(&route.epoch, &self.epoch)
            || (self.reservation.is_some() && route.state != State::Reserved)
            || (self.reservation.is_none()
                && !matches!(route.state, State::Queued | State::Claimed))
        {
            return Err(CallerSignalingError::RouteMismatch);
        }
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now().into_std() >= deadline)
        {
            return Err(CallerSignalingError::TimedOut);
        }
        if let Some(reservation) = &mut self.reservation {
            route.state = State::Queued;
            reservation.armed = false;
        }
        permit.send(self.signal);
        Ok(())
    }
}

/// An exact route retained by the listener, actual actor and accepted public receivers.
pub(crate) struct CallerRoute {
    key: Key,
    epoch: Arc<()>,
    inbox: Arc<Mutex<Inbox>>,
    armed: bool,
}

impl CallerRoute {
    /// Rejects new candidates/outgoing work after actor destruction while receivers retain capacity.
    pub(crate) fn retire(&self) {
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(route) = inbox.routes.get_mut(&self.key)
            && Arc::ptr_eq(&route.epoch, &self.epoch)
        {
            route.state = State::Retired;
            route.active.cancel();
        }
    }
}

impl Drop for CallerRoute {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
        if inbox
            .routes
            .get(&self.key)
            .is_some_and(|route| Arc::ptr_eq(&route.epoch, &self.epoch))
            && let Some(route) = inbox.routes.remove(&self.key)
        {
            route.closed.cancel();
            route.active.cancel();
        }
    }
}

struct Subscription {
    receiver: Option<mpsc::Receiver<Signal>>,
    inbox: Arc<Mutex<Inbox>>,
    closed: CancellationToken,
    epoch: Arc<()>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(mut receiver) = self.receiver.take() {
            let mut inbox = self.inbox.lock().unwrap_or_else(|error| error.into_inner());
            if inbox
                .subscription
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.epoch))
            {
                inbox.subscription = None;
                while receiver.try_recv().is_ok() {}
                inbox.routes.retain(|_, route| {
                    let keep = matches!(route.state, State::Claimed | State::Retired);
                    if !keep {
                        route.closed.cancel();
                        route.active.cancel();
                    }
                    keep
                });
                inbox.receiver = Some(receiver);
            }
        }
    }
}

#[cfg(test)]
mod tests;
