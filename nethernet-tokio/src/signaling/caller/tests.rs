use super::*;
use crate::error::NetherError;
use futures::{FutureExt, StreamExt, poll};

const PEER: &str = "00000000-0000-0000-0000-000000000002";

/// A complete service burst can exceed the immediate queue without losing FIFO delivery.
#[tokio::test]
async fn a_service_batch_larger_than_the_caller_queue_waits_and_preserves_order() {
    let config = CallerSignalingConfig::default();
    let capacity = config.capacity.get();
    let (caller, mut driver) = CallerSignaling::new("7".into(), PEER.into(), config).unwrap();
    let mut incoming = caller.signals().unwrap();
    let mut offer = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), PEER.into())));
    assert!(poll!(offer.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::PeerReceived));
    offer.await.unwrap();
    for index in 0..capacity {
        driver
            .try_deliver(
                PEER,
                &Signal::candidate(9, index.to_string(), PEER.into()).to_string(),
            )
            .unwrap();
    }
    let waiting: Vec<_> = (capacity..capacity * 2)
        .map(|index| {
            driver
                .prepare_delivery(
                    PEER,
                    &Signal::candidate(9, index.to_string(), PEER.into()).to_string(),
                )
                .unwrap()
        })
        .collect();
    let deliver = async {
        for wait in waiting {
            wait.await
                .expect("valid service burst lost to immediate queue capacity");
        }
    };
    let receive = async {
        for index in 0..capacity * 2 {
            assert_eq!(incoming.next().await.unwrap().data, index.to_string());
        }
    };
    futures::join!(deliver, receive);

    for index in 0..capacity {
        driver
            .try_deliver(
                PEER,
                &Signal::candidate(9, index.to_string(), PEER.into()).to_string(),
            )
            .unwrap();
    }
    let mut abandoned = Box::pin(
        driver
            .prepare_delivery(PEER, "CANDIDATEADD 9 abandoned")
            .unwrap(),
    );
    assert!(poll!(abandoned.as_mut()).is_pending());
    drop(abandoned);
    for index in 0..capacity {
        assert_eq!(incoming.next().await.unwrap().data, index.to_string());
    }
    assert!(incoming.next().now_or_never().is_none());
    let stale = driver
        .prepare_delivery(PEER, "CANDIDATEADD 9 retired")
        .unwrap();
    drop(incoming);
    assert_eq!(stale.await, Err(CallerSignalingError::RouteMismatch));
}

/// Capacity released after expiry cannot publish an expired envelope, even when timeout polls it first.
#[tokio::test(start_paused = true)]
async fn incoming_admission_rechecks_original_deadline_after_capacity_wait() {
    let (caller, mut driver) = bridge();
    let mut incoming = caller.signals().unwrap();
    let mut offer = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), PEER.into())));
    assert!(poll!(offer.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::PeerReceived));
    offer.await.unwrap();
    driver.try_deliver(PEER, "CANDIDATEADD 9 prefix").unwrap();
    let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
    let mut late = Box::pin(
        driver
            .prepare_delivery_before(PEER, "CANDIDATEADD 9 expired", deadline)
            .unwrap(),
    );
    assert!(poll!(late.as_mut()).is_pending());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(incoming.next().await.unwrap().data, "prefix");
    assert_eq!(
        late.await,
        Err(CallerSignalingError::TimedOut),
        "expired incoming envelope escaped its original admission deadline"
    );
    assert!(incoming.next().now_or_never().is_none());

    let timely = driver
        .prepare_delivery_before(
            PEER,
            "CANDIDATEADD 9 timely",
            tokio::time::Instant::now().into_std() + Duration::from_secs(1),
        )
        .unwrap();
    timely.await.unwrap();
    assert_eq!(incoming.next().await.unwrap().data, "timely");
    let at_deadline = driver
        .prepare_delivery_before(
            PEER,
            "CANDIDATEADD 9 exactly-expired",
            tokio::time::Instant::now().into_std(),
        )
        .unwrap();
    assert_eq!(at_deadline.await, Err(CallerSignalingError::TimedOut));
    assert!(incoming.next().now_or_never().is_none());
}

/// Creates a small bridge so every queue limit can be exercised without I/O.
fn bridge() -> (CallerSignaling, CallerSignalingDriver) {
    CallerSignaling::new(
        "1234".into(),
        PEER.into(),
        CallerSignalingConfig {
            capacity: NonZeroUsize::new(1).unwrap(),
            max_signal_bytes: NonZeroUsize::new(256).unwrap(),
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn offers_require_peer_receipt_and_other_signals_require_service_acceptance() {
    let (signaling, mut driver) = bridge();
    let _incoming = signaling.signals().unwrap();
    let offer = Signal::offer(7, "sdp".into(), PEER.into());
    let mut send = Box::pin(signaling.signal(offer.clone()));
    assert!(poll!(send.as_mut()).is_pending());
    let request = driver.recv().await.unwrap();
    assert!(request.requires_peer_receipt());
    request.finish(Ok(SignalDelivery::ServiceAccepted));
    assert!(matches!(
        send.await,
        Err(NetherError::CallerSignaling(
            CallerSignalingError::ReceiptRequired
        ))
    ));

    let mut send = Box::pin(signaling.signal(offer));
    assert!(poll!(send.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::PeerReceived));
    send.await.unwrap();

    let mut send =
        Box::pin(signaling.signal(Signal::candidate(7, "candidate".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    let request = driver.recv().await.unwrap();
    assert!(!request.requires_peer_receipt());
    request.finish(Ok(SignalDelivery::ServiceAccepted));
    send.await.unwrap();
}

#[tokio::test]
async fn incoming_admission_binds_sender_connection_and_subscription_with_backpressure() {
    let (signaling, driver) = bridge();
    let mut incoming = signaling.signals().unwrap();
    assert!(matches!(
        signaling.signals(),
        Err(NetherError::CallerSignaling(
            CallerSignalingError::AlreadySubscribed
        ))
    ));
    let mut send = Box::pin(signaling.signal(Signal::offer(7, "sdp".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    assert_eq!(
        driver.try_deliver("1234", "CONNECTRESPONSE 7 answer"),
        Err(CallerSignalingError::RouteMismatch)
    );
    assert_eq!(
        driver.try_deliver(PEER, "CONNECTRESPONSE 8 answer"),
        Err(CallerSignalingError::RouteMismatch)
    );
    assert_eq!(
        driver.try_deliver(PEER, "unknown 7 secret"),
        Err(CallerSignalingError::InvalidSignal)
    );
    assert_eq!(
        driver.try_deliver(PEER, &"s".repeat(257)),
        Err(CallerSignalingError::Capacity)
    );
    driver
        .try_deliver(PEER, "CONNECTRESPONSE 7 answer")
        .unwrap();
    assert_eq!(
        driver.try_deliver(PEER, "CANDIDATEADD 7 candidate"),
        Err(CallerSignalingError::Capacity)
    );
    assert_eq!(
        incoming.next().await.unwrap(),
        Signal::answer(7, "answer".into(), PEER.into())
    );
    driver.try_deliver(PEER, "CANDIDATEADD 7 stale").unwrap();
    drop(send);
    drop(incoming);
    assert_eq!(
        driver.try_deliver(PEER, "CONNECTRESPONSE 7 answer"),
        Err(CallerSignalingError::RouteMismatch)
    );

    let mut incoming = signaling.signals().unwrap();
    assert!(
        incoming.next().now_or_never().is_none(),
        "old queued candidate survived a new subscription"
    );
    let mut send = Box::pin(signaling.signal(Signal::offer(9, "sdp".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    assert_eq!(
        driver.try_deliver(PEER, "CONNECTRESPONSE 7 answer"),
        Err(CallerSignalingError::RouteMismatch)
    );
    driver
        .try_deliver(PEER, "CONNECTRESPONSE 9 answer")
        .unwrap();
    assert_eq!(incoming.next().await.unwrap().connection_id, 9);
}

#[tokio::test]
async fn outstanding_requests_keep_their_capacity_until_caller_releases_them() {
    let (signaling, mut driver) = bridge();
    let _incoming = signaling.signals().unwrap();
    let mut offer = Box::pin(signaling.signal(Signal::offer(7, "sdp".into(), PEER.into())));
    assert!(poll!(offer.as_mut()).is_pending());
    let request = driver.recv().await.unwrap();
    let mut candidate =
        Box::pin(signaling.signal(Signal::candidate(7, "candidate".into(), PEER.into())));
    assert!(poll!(candidate.as_mut()).is_pending());
    assert!(
        driver.recv().now_or_never().is_none(),
        "draining the queue lost the in-flight capacity bound"
    );
    drop(offer);
    assert!(request.is_cancelled());
    drop(request);
    assert!(poll!(candidate.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::ServiceAccepted));
    candidate.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn original_deadline_and_driver_closure_cancel_inflight_requests_without_retry() {
    let (signaling, mut driver) = bridge();
    let mut incoming = signaling.signals().unwrap();
    let mut timely = Box::pin(signaling.signal(Signal::offer(7, "sdp".into(), PEER.into())));
    assert!(poll!(timely.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::PeerReceived));
    tokio::time::advance(signaling.config.send_timeout).await;
    timely
        .await
        .expect("timely completion must survive delayed transport polling");

    let mut send = Box::pin(signaling.signal(Signal::offer(7, "sdp".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    let request = driver.recv().await.unwrap();
    tokio::time::advance(signaling.config.send_timeout).await;
    assert!(request.is_cancelled());
    request.finish(Ok(SignalDelivery::PeerReceived));
    assert!(
        matches!(
            send.await,
            Err(NetherError::CallerSignaling(CallerSignalingError::TimedOut))
        ),
        "a late completion must not turn an expired wait into success"
    );
    assert!(
        driver.recv().now_or_never().is_none(),
        "a timed out request was retried"
    );

    let mut send =
        Box::pin(signaling.signal(Signal::candidate(7, "candidate".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    let request = driver.recv().await.unwrap();
    drop(driver);
    assert!(
        request.is_cancelled(),
        "driver closure must not depend on transport polling"
    );
    assert!(matches!(
        send.await,
        Err(NetherError::CallerSignaling(CallerSignalingError::Closed))
    ));
    assert!(incoming.next().await.is_none());
    assert!(request.is_cancelled());
}

#[tokio::test]
async fn client_dispatches_to_caller_and_does_not_retry_a_service_rejection() {
    let (signaling, mut driver) =
        CallerSignaling::new("1234".into(), PEER.into(), CallerSignalingConfig::default()).unwrap();
    let connect = crate::NetherClient::connect_with(
        signaling,
        PEER.into(),
        crate::ConnectionConfig::default(),
    );
    let service = async {
        let request = driver.recv().await.unwrap();
        assert_eq!(request.signal().signal_type, SignalType::Offer);
        assert_eq!(request.signal().network_id, PEER);
        assert!(request.requires_peer_receipt());
        request.finish(Err(CallerSignalingError::Rejected));
    };
    let (result, ()) = tokio::join!(connect, service);
    assert!(matches!(
        result,
        Err(NetherError::CallerSignaling(CallerSignalingError::Rejected))
    ));
    assert!(matches!(driver.recv().now_or_never(), Some(None)));
}

#[tokio::test]
async fn cancellation_interrupts_best_effort_terminal_signal_cleanup() {
    let (signaling, mut driver) =
        CallerSignaling::new("1234".into(), PEER.into(), CallerSignalingConfig::default()).unwrap();
    let config = crate::ConnectionConfig::default();
    let cancel = config.cancel_token.clone();
    let mut connect = Box::pin(crate::NetherClient::connect_with(
        signaling,
        PEER.into(),
        config,
    ));
    let offer = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut connect => panic!("connection ended before offering"),
    };
    driver
        .try_deliver(
            PEER,
            &format!(
                "CONNECTRESPONSE {} invalid-sdp",
                offer.signal().connection_id
            ),
        )
        .unwrap();
    offer.finish(Ok(SignalDelivery::PeerReceived));
    let terminal = loop {
        let request = tokio::select! {
            request = driver.recv() => request.unwrap(),
            _ = &mut connect => panic!("connection ended before terminal signaling"),
        };
        match request.signal().signal_type {
            SignalType::Candidate => request.finish(Ok(SignalDelivery::ServiceAccepted)),
            SignalType::Error => break request,
            _ => panic!("unexpected negotiation signal"),
        }
    };
    cancel.cancel();
    assert!(
        poll!(connect.as_mut()).is_ready(),
        "cancellation must stop waiting for best-effort terminal signal delivery"
    );
    assert!(terminal.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn caller_negotiation_timeout_does_not_automatically_offer_again() {
    let (signaling, mut driver) = CallerSignaling::new(
        "1234".into(),
        PEER.into(),
        CallerSignalingConfig {
            ice_mode: IceMode::Full,
            ..Default::default()
        },
    )
    .unwrap();
    let config = crate::ConnectionConfig::default();
    let negotiation_budget = config.timeouts.negotiation;
    let mut connect = Box::pin(crate::NetherClient::connect_with(
        signaling,
        PEER.into(),
        config,
    ));
    let offer = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut connect => panic!("connection ended before offering"),
    };
    assert_eq!(offer.signal().signal_type, SignalType::Offer);
    offer.finish(Ok(SignalDelivery::PeerReceived));
    assert!(poll!(connect.as_mut()).is_pending());
    tokio::time::advance(negotiation_budget).await;
    let terminal = tokio::select! {
        request = driver.recv() => request.unwrap(),
        _ = &mut connect => panic!("connection ended before terminal signaling"),
    };
    assert_eq!(terminal.signal().signal_type, SignalType::Error);
    terminal.finish(Ok(SignalDelivery::ServiceAccepted));
    assert!(
        matches!(connect.now_or_never(), Some(Err(NetherError::Timeout))),
        "caller policy must own any further connection attempt"
    );
    assert!(matches!(driver.recv().now_or_never(), Some(None)));
}

/// A prepared delivery belongs to the original subscription even when the next offer reuses its ID.
#[tokio::test]
async fn prepared_delivery_cannot_enter_a_replacement_with_the_same_connection_id() {
    let (caller, mut driver) = bridge();
    let incoming = caller.signals().unwrap();
    {
        let mut send = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), PEER.into())));
        assert!(poll!(send.as_mut()).is_pending());
        driver
            .recv()
            .await
            .unwrap()
            .finish(Ok(SignalDelivery::PeerReceived));
        send.await.unwrap();
    }
    let old = driver
        .prepare_delivery(PEER, "CANDIDATEADD 9 retired")
        .unwrap();
    drop(incoming);
    let mut replacement = caller.signals().unwrap();
    let mut send = Box::pin(caller.signal(Signal::offer(9, "sdp".into(), PEER.into())));
    assert!(poll!(send.as_mut()).is_pending());
    driver
        .recv()
        .await
        .unwrap()
        .finish(Ok(SignalDelivery::PeerReceived));
    send.await.unwrap();
    assert_eq!(old.await, Err(CallerSignalingError::RouteMismatch));
    assert!(replacement.next().now_or_never().is_none());
}
