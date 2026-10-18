//! Retained server capacity, shared only by the actual session and its accepted receivers.

use std::sync::{
    Arc, Weak,
    atomic::{AtomicU8, Ordering},
};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

const PENDING: u8 = 0;
const ACCEPTED: u8 = 1;
const RETIRED: u8 = 2;

/// No strong reference points back to the listener or its peer table.
pub(crate) struct ServerLease {
    _slot: OwnedSemaphorePermit,
    state: AtomicU8,
    route: Option<crate::signaling::caller::server::CallerRoute>,
}

impl ServerLease {
    /// Retains the original pre-allocation admission until every session/receiver owner retires.
    #[cfg(test)]
    pub(crate) fn new(slot: OwnedSemaphorePermit) -> Arc<Self> {
        Self::with_route(slot, None)
    }

    /// Retains the authenticated caller route through the same concrete capacity lifetime.
    pub(crate) fn with_route(
        slot: OwnedSemaphorePermit,
        route: Option<crate::signaling::caller::server::CallerRoute>,
    ) -> Arc<Self> {
        Arc::new(Self {
            _slot: slot,
            state: AtomicU8::new(PENDING),
            route,
        })
    }

    /// The actual actor ended; retained receivers may still own its data and reservation.
    pub(crate) fn retire_route(&self) {
        if let Some(route) = &self.route {
            route.retire();
        }
    }

    /// Records the synchronous public accept boundary, without an intervening cancellation await.
    pub(super) fn accept(&self) -> bool {
        self.state
            .compare_exchange(PENDING, ACCEPTED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Listener retirement closes only peers that have not crossed the public accept boundary.
    fn retire_pending(&self) -> bool {
        self.state
            .compare_exchange(PENDING, RETIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Listener-owned cancellation without retaining a command handle or accepted receiver.
pub(crate) struct ServerRetirement {
    lease: Weak<ServerLease>,
    close: CancellationToken,
}

impl ServerRetirement {
    /// Borrows the real session lifetime; this guard cannot keep an abandoned peer alive.
    pub(super) fn new(lease: &Arc<ServerLease>, close: CancellationToken) -> Self {
        Self {
            lease: Arc::downgrade(lease),
            close,
        }
    }

    /// A ready peer that ended ordinarily remains queued with its accepted FIFO and terminal.
    pub(crate) fn preserve_queued(&mut self) {
        self.lease = Weak::new();
    }
}

impl Drop for ServerRetirement {
    fn drop(&mut self) {
        if self
            .lease
            .upgrade()
            .is_some_and(|lease| lease.retire_pending())
        {
            self.close.cancel();
        }
    }
}
