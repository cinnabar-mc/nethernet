//! Read-only actor observations for the actual selected-stream capacity fixture.
use nethernet::session::OutputUsage;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    kernel_blocked: AtomicBool,
    peak_entries: AtomicUsize,
    message_bytes: AtomicUsize,
    changed: Notify,
}

#[derive(Clone, Default)]
pub(crate) struct Observation(Arc<State>);
impl Observation {
    /// Records original FIFO usage only after an actual selected socket write returned Pending.
    pub(crate) fn record(&self, usage: OutputUsage, blocked: bool) {
        self.0.kernel_blocked.store(blocked, Ordering::Relaxed);
        self.0.message_bytes.store(
            usage.bytes.saturating_sub(usage.wire_bytes),
            Ordering::Relaxed,
        );
        if blocked {
            self.0
                .peak_entries
                .fetch_max(usage.entries, Ordering::Relaxed);
        }
        self.0.changed.notify_waiters();
    }
    /// No observer owns a transport/task or supplies any readiness/pressure to the actor.
    pub(crate) fn peak_entries(&self) -> usize {
        self.0.peak_entries.load(Ordering::Relaxed)
    }
    /// Registration precedes observation, so a real actor wake cannot be lost.
    pub(crate) async fn socket_blocked(&self) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.0.kernel_blocked.load(Ordering::Relaxed) {
                return;
            }
            changed.await;
        }
    }
    /// Waits for actual original core growth, independently of the gated command queue.
    pub(crate) async fn over_entries(&self, limit: usize) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.peak_entries() > limit {
                return;
            }
            changed.await;
        }
    }

    /// Waits for application bytes already accepted into the original unpolled core FIFO.
    pub(crate) async fn pending_message_bytes(&self, minimum: usize) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.0.message_bytes.load(Ordering::Relaxed) >= minimum {
                return;
            }
            changed.await;
        }
    }
}
