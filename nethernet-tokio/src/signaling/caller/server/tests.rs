use super::*;
use crate::signaling::caller::SignalDelivery;
use futures::{FutureExt, StreamExt, poll};
use std::time::Duration;

/// Keeps real bridge bounds small enough to exercise held routes and requests directly.
fn bridge() -> (CallerServerSignaling, CallerServerSignalingDriver) {
    CallerServerSignaling::new(
        "local".into(),
        CallerServerSignalingConfig {
            signaling: CallerSignalingConfig {
                capacity: NonZeroUsize::new(1).unwrap(),
                max_signal_bytes: NonZeroUsize::new(512).unwrap(),
                ..Default::default()
            },
            max_routes: NonZeroUsize::new(2).unwrap(),
            max_routes_per_sender: NonZeroUsize::new(1).unwrap(),
        },
    )
    .unwrap()
}

/// Real owned admission futures reserve bounded exact routes, even before their first poll.
#[tokio::test]
async fn caller_server_routes_follow_authenticated_sender_and_concrete_lease() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (caller, driver) = bridge();
        let mut incoming = caller.signals().unwrap();
        assert!(matches!(
            caller.signals(),
            Err(crate::error::NetherError::CallerSignaling(
                CallerSignalingError::AlreadySubscribed
            ))
        ));
        assert_eq!(
            driver.try_deliver("", "CONNECTREQUEST 7 offer"),
            Err(CallerSignalingError::RouteMismatch)
        );
        assert_eq!(
            driver.try_deliver("first", "not a signal"),
            Err(CallerSignalingError::InvalidSignal)
        );
        assert_eq!(
            driver.try_deliver(&"x".repeat(513), "CONNECTREQUEST 7 offer"),
            Err(CallerSignalingError::Capacity)
        );
        assert_eq!(
            driver.try_deliver("first", &format!("CONNECTREQUEST 7 {}", "x".repeat(513))),
            Err(CallerSignalingError::Capacity)
        );
        let first = driver
            .prepare_delivery("first", "CONNECTREQUEST 7 offer")
            .unwrap();
        assert!(matches!(
            driver.prepare_delivery("first", "CONNECTREQUEST 8 other"),
            Err(CallerSignalingError::Capacity)
        ));
        assert_eq!(
            driver.try_deliver("first", "CONNECTREQUEST 7 duplicate"),
            Err(CallerSignalingError::RouteMismatch)
        );
        let second = driver
            .prepare_delivery("second", "CONNECTREQUEST 7 other peer")
            .unwrap();
        assert_eq!(
            driver.try_deliver("third", "CONNECTREQUEST 7 excess"),
            Err(CallerSignalingError::Capacity)
        );
        drop(second);
        let second = driver
            .prepare_delivery("second", "CONNECTREQUEST 7 other peer")
            .unwrap();
        first.await.unwrap();
        let offer = incoming.next().await.unwrap();
        assert_eq!(
            (offer.network_id.as_str(), offer.connection_id),
            ("first", 7)
        );
        let lease = caller.claim(&offer).unwrap();
        second.await.unwrap();
        let other = incoming.next().await.unwrap();
        assert_eq!(other.network_id, "second");
        let other_lease = caller.claim(&other).unwrap();
        assert_eq!(
            driver.try_deliver("unknown", "CANDIDATEADD 7 unknown"),
            Err(CallerSignalingError::RouteMismatch)
        );
        let stale = driver
            .prepare_delivery("first", "CANDIDATEADD 7 stale")
            .unwrap();
        lease.retire();
        assert_eq!(
            driver.try_deliver("first", "CANDIDATEADD 7 retired"),
            Err(CallerSignalingError::RouteMismatch)
        );
        assert_eq!(
            driver.try_deliver("first", "CONNECTREQUEST 7 retained receiver"),
            Err(CallerSignalingError::RouteMismatch)
        );
        drop(lease);
        driver
            .try_deliver("first", "CONNECTREQUEST 7 replacement")
            .unwrap();
        assert_eq!(incoming.next().await.unwrap().data, "replacement");
        assert_eq!(stale.await, Err(CallerSignalingError::RouteMismatch));
        assert!(incoming.next().now_or_never().is_none());
        drop(other_lease);
    })
    .await
    .expect("bounded caller route fixture stalled");
}

/// Deadline and subscription are checked at the actual reserved queue commitment, including ABA reuse.
#[tokio::test(start_paused = true)]
async fn caller_server_capacity_wait_cannot_commit_after_deadline_or_resubscription() {
    let (caller, driver) = bridge();
    let mut incoming = caller.signals().unwrap();
    driver
        .try_deliver("first", "CONNECTREQUEST 7 prefix")
        .unwrap();
    let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
    let mut late = Box::pin(
        driver
            .prepare_delivery_before("first", "CANDIDATEADD 7 late", deadline)
            .unwrap(),
    );
    assert!(poll!(late.as_mut()).is_pending());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(incoming.next().await.unwrap().data, "prefix");
    assert_eq!(late.await, Err(CallerSignalingError::TimedOut));
    assert!(incoming.next().now_or_never().is_none());
    let stale = driver
        .prepare_delivery("first", "CANDIDATEADD 7 stale subscription")
        .unwrap();
    drop(incoming);
    let mut incoming = caller.signals().unwrap();
    driver
        .try_deliver("first", "CONNECTREQUEST 7 replacement")
        .unwrap();
    assert_eq!(incoming.next().await.unwrap().data, "replacement");
    assert_eq!(stale.await, Err(CallerSignalingError::RouteMismatch));
    assert!(incoming.next().now_or_never().is_none());
    let exactly = driver
        .prepare_delivery_before(
            "second",
            "CONNECTREQUEST 8 expired",
            tokio::time::Instant::now().into_std(),
        )
        .unwrap();
    assert_eq!(exactly.await, Err(CallerSignalingError::TimedOut));
    driver
        .try_deliver("second", "CONNECTREQUEST 8 timely replacement")
        .unwrap();
    assert_eq!(incoming.next().await.unwrap().data, "timely replacement");
}

/// Held actual requests consume shared capacity, route retirement cancels them, and service closure is terminal.
#[tokio::test]
async fn caller_server_requests_retain_capacity_and_observe_route_and_service_retirement() {
    let (caller, mut driver) = bridge();
    let mut incoming = caller.signals().unwrap();
    driver
        .try_deliver("first", "CONNECTREQUEST 7 offer")
        .unwrap();
    let lease = caller.claim(&incoming.next().await.unwrap()).unwrap();
    let mut answer = Box::pin(caller.signal(Signal::answer(7, "answer".into(), "first".into())));
    assert!(poll!(answer.as_mut()).is_pending());
    let mut held = driver.recv().await.unwrap();
    assert!(!held.requires_peer_receipt());
    let mut candidate =
        Box::pin(caller.signal(Signal::candidate(7, "candidate".into(), "first".into())));
    assert!(poll!(candidate.as_mut()).is_pending());
    assert!(
        driver.recv().now_or_never().is_none(),
        "held request must retain the semaphore slot"
    );
    lease.retire();
    held.cancelled().await;
    assert!(held.is_cancelled());
    held.finish(Ok(SignalDelivery::ServiceAccepted));
    assert!(answer.await.is_err());
    assert!(candidate.await.is_err());
    driver.close();
    assert_eq!(
        driver.try_deliver("second", "CONNECTREQUEST 8 closed"),
        Err(CallerSignalingError::Closed)
    );
    assert!(incoming.next().await.is_none());
    assert!(driver.recv().await.is_none());
}
