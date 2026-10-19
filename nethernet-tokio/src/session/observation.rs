//! Nonblocking measurement snapshots independent of the transport lifecycle owner.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const RETIRED: u64 = u64::MAX;

/// A copied view of the original actor's full SCTP round-trip estimate.
///
/// Reads never drive I/O or borrow a lock. Clones retain only the measurement
/// cell, not the session, actor or socket. Retirement permanently withdraws it.
#[derive(Clone, Debug)]
pub struct RttObservation(Arc<AtomicU64>);

impl RttObservation {
    /// Creates the initially unmeasured cell for one original actor.
    pub(super) fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    /// Copies the latest positive full RTT, or `None` before measurement or after retirement.
    /// Durations exceeding the cell's nanosecond range saturate below its retired marker.
    pub fn get(&self) -> Option<Duration> {
        match self.0.load(Ordering::Relaxed) {
            0 | RETIRED => None,
            nanos => Some(Duration::from_nanos(nanos)),
        }
    }

    /// Updates the same cell only while its original owner has not retired.
    pub(super) fn publish(&self, sample: Option<Duration>) {
        let next = sample.map_or(0, |sample| {
            u64::try_from(sample.as_nanos())
                .unwrap_or(RETIRED - 1)
                .min(RETIRED - 1)
        });
        let mut current = self.0.load(Ordering::Relaxed);
        // The estimate and terminal seal share one atomic; no other state is synchronized here.
        while current != RETIRED && current != next {
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Permanently withdraws the estimate without waiting for any observer.
    pub(super) fn retire(&self) {
        self.0.store(RETIRED, Ordering::Relaxed);
    }
}

/// Seals the original cell even if the actor is aborted before its first poll.
pub(super) struct RttPublisher(pub(super) RttObservation);

impl Drop for RttPublisher {
    fn drop(&mut self) {
        self.0.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A late original actor publication cannot reopen its retired measurement cell.
    #[test]
    fn retirement_is_permanent_and_preserves_submillisecond_samples() {
        let observation = RttObservation::new();
        observation.publish(Some(Duration::from_nanos(25)));
        assert_eq!(observation.get(), Some(Duration::from_nanos(25)));
        observation.retire();
        observation.publish(Some(Duration::from_millis(30)));
        assert_eq!(observation.get(), None);

        let observation = RttObservation::new();
        observation.publish(Some(Duration::from_nanos(25)));
        let publisher = RttPublisher(observation.clone());
        let unpolled = async move {
            let _publisher = publisher;
            std::future::pending::<()>().await;
        };
        drop(unpolled);
        assert_eq!(
            observation.get(),
            None,
            "unpolled actor retained its estimate"
        );
    }
}
