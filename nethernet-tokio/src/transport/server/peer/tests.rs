//! Real peer-worker handoff ordering, with SCTP-acknowledged data and encrypted peer closure.
use super::*;
use crate::session::test_peer::Peer as RtcPeer;
use crate::signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
use crate::transport::pending::PendingOffers;
use futures::{StreamExt, poll};
use nethernet::protocol::webrtc::{Description, candidate::format_ice_candidate};
use tokio::sync::Semaphore;

struct PendingPeer {
    owner: Peer,
    answered: Answered,
    pending: PendingSlot,
    incoming: mpsc::Receiver<AcceptedSession>,
    signals: mpsc::Sender<Signal>,
    candidate: Signal,
    rtc: RtcPeer,
    answer: String,
}

/// Gets the actual worker's Answered owner through a real HTTP offer/answer exchange.
async fn pending_peer() -> PendingPeer {
    let signaling = Arc::new(
        HttpSignalingServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            HttpServerConfig {
                signaler: nethernet::prelude::HttpSignalerConfig {
                    token_trust: None,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let mut offers = signaling.signals();
    let (rtc, offer) = RtcPeer::offer().await;
    let client = HttpSignaling::new("handoff-peer".into()).unwrap();
    let mut answers = client.signals();
    let mut send = Box::pin(client.signal(Signal::offer(
        7,
        offer,
        format!("http://{}", signaling.local_addr()),
    )));
    let offer = tokio::select! {
        signal = offers.next() => signal.unwrap(),
        _ = &mut send => panic!("HTTP offer ended before reaching the actual server owner"),
    };
    let (description, candidates) = Description::parse(&offer.data).unwrap();
    let candidate = Signal::candidate(
        offer.connection_id,
        format_ice_candidate(0, &candidates[0], &description.ice.ufrag),
        offer.network_id.clone(),
    );
    let pending = PendingOffers::default()
        .try_admit(&offer.network_id, 1, 1)
        .unwrap();
    let capacity = Arc::new(Semaphore::new(1));
    let lease = ServerLease::new(capacity.try_acquire_owned().unwrap());
    let (incoming_tx, incoming) = mpsc::channel(1);
    let (signals, signal_rx) = mpsc::channel(crate::session::command::COMMAND_CAPACITY);
    let config = ConnectionConfig {
        allow_unsigned_answers: true,
        ..Default::default()
    };
    let owner = Peer {
        signaling: signaling.into(),
        incoming: incoming_tx,
        negotiation_deadline: transport_now() + config.timeouts.negotiation,
        config,
        listener: CancellationToken::new(),
        stop: CancellationToken::new(),
        signals: signal_rx,
    };
    let (answered, sent) = tokio::join!(owner.answer(offer, lease), send);
    sent.unwrap();
    let answer = answers.next().await.unwrap().data;
    PendingPeer {
        owner,
        answered: answered.unwrap(),
        pending,
        incoming,
        signals,
        candidate,
        rtc,
        answer,
    }
}

#[derive(Clone, Copy)]
enum HandoffCase {
    ReadyClosed,
    CandidateBlocked,
    ListenerRetired,
    Expired,
    NeverReady,
}

/// Holds only the real handoff future; its existing UDP actor and the independent RTC peer keep running.
async fn exercise_handoff(case: HandoffCase) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let PendingPeer {
            mut owner,
            answered,
            pending,
            mut incoming,
            signals,
            candidate,
            mut rtc,
            answer,
        } = pending_peer().await;
        let closed = answered.accepted.session.close_token();
        let commands = answered.accepted.session.signal_sender();
        let deadline = answered.deadline;
        let listener = owner.listener.clone();
        if matches!(case, HandoffCase::CandidateBlocked) {
            while commands.capacity() != 0 {
                let (reply, _) = oneshot::channel();
                commands.try_send(Command::Rtt(reply)).unwrap();
            }
            signals.try_send(candidate).unwrap();
        }
        let mut handoff = Box::pin(owner.handoff(answered, pending));
        if matches!(case, HandoffCase::CandidateBlocked) {
            assert!(poll!(handoff.as_mut()).is_pending());
            assert_eq!(
                signals.capacity(),
                signals.max_capacity(),
                "the actual worker must enter its bounded candidate-forwarding wait"
            );
        }
        if matches!(case, HandoffCase::NeverReady) {
            closed.cancel();
        } else {
            rtc.apply_answer(answer);
            while !rtc.both_ready() {
                rtc.turn().await;
            }
            for index in 0..3 {
                rtc.send(index);
            }
            while rtc.outstanding() != 0 {
                rtc.turn().await;
            }
            // Actual SCTP acknowledgments prove the prefix entered the real receive owner.
            rtc.close_dtls().await;
            closed.cancelled().await;
        }
        match case {
            HandoffCase::ListenerRetired => listener.cancel(),
            HandoffCase::Expired => {
                tokio::time::pause();
                tokio::time::advance(deadline.saturating_duration_since(transport_now())).await;
            }
            _ => {}
        }
        let result = handoff.await;
        if matches!(
            case,
            HandoffCase::ReadyClosed | HandoffCase::CandidateBlocked
        ) {
            let _forwarding =
                result.expect("accepted ready prefix was lost before the actual peer handoff");
            let mut accepted = incoming
                .recv()
                .await
                .expect("successful worker handoff lost its incoming owner");
            assert!(accepted.session.accept_from_server());
            for index in 0u32..3 {
                assert_eq!(
                    accepted.reliable.recv().await.unwrap().unwrap().as_ref(),
                    index.to_be_bytes()
                );
            }
            assert!(accepted.reliable.recv().await.unwrap().is_none());
            assert!(accepted.reliable.recv().await.unwrap().is_none());
        } else {
            assert!(
                matches!(
                    result,
                    Err((_, NetherError::ConnectionClosed | NetherError::Timeout))
                ),
                "explicit retirement or expiry must refuse the handoff"
            );
            assert!(incoming.try_recv().is_err());
        }
    })
    .await
    .expect("finite actual ready/prefix/peer-close handoff fixture stalled");
}

#[tokio::test]
async fn peer_worker_retains_ready_prefix_and_close_before_handoff() {
    exercise_handoff(HandoffCase::ReadyClosed).await;
}

#[tokio::test]
async fn peer_worker_retains_ready_prefix_and_close_after_candidate_backpressure() {
    exercise_handoff(HandoffCase::CandidateBlocked).await;
}

#[tokio::test]
async fn peer_worker_refuses_listener_retired_ready_handoff() {
    exercise_handoff(HandoffCase::ListenerRetired).await;
}

#[tokio::test]
async fn peer_worker_refuses_originally_expired_ready_handoff() {
    exercise_handoff(HandoffCase::Expired).await;
}

#[tokio::test]
async fn peer_worker_refuses_never_ready_closed_handoff() {
    exercise_handoff(HandoffCase::NeverReady).await;
}

#[tokio::test]
async fn peer_worker_retains_ready_prefix_and_close_during_answer_dispatch() {
    use crate::signaling::lan::{LanConfig, LanSignaling};
    use nethernet::protocol::SignalType;
    use nethernet::protocol::packet::discovery::ServerData;
    use nethernet::protocol::webrtc::candidate::parse_ice_candidate;

    tokio::time::timeout(Duration::from_secs(15), async {
        // The current discovery adapter cannot expose a port-zero bind; reuse the existing LAN fixture convention.
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let signaling = Arc::new(
            LanSignaling::with_config(
                1,
                address,
                LanConfig {
                    discovery_port: address.port(),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        signaling.set_server_data(ServerData::new("fixture".into(), "world".into()));
        let client = LanSignaling::with_config(
            2,
            "127.0.0.1:0".parse().unwrap(),
            LanConfig {
                discovery_port: address.port(),
                broadcast_address: Some(address),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut offers = signaling.signals();
        let mut answers = client.signals();
        while !client.discover().await.contains_key(&1) {
            tokio::task::yield_now().await;
        }
        let (mut rtc, offer) = RtcPeer::offer().await;
        client
            .signal(Signal::offer(7, offer, "1".into()))
            .await
            .unwrap();
        let offer = offers.next().await.unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);
        let pending = PendingOffers::default()
            .try_admit(&offer.network_id, 1, 1)
            .unwrap();
        let capacity = Arc::new(Semaphore::new(1));
        let lease = ServerLease::new(capacity.try_acquire_owned().unwrap());
        let (incoming_tx, mut incoming) = mpsc::channel(1);
        let (_signals, signal_rx) = mpsc::channel(crate::session::command::COMMAND_CAPACITY);
        let config = ConnectionConfig::default();
        let mut owner = Peer {
            signaling: signaling.clone().into(),
            incoming: incoming_tx,
            negotiation_deadline: transport_now() + config.timeouts.negotiation,
            config,
            listener: CancellationToken::new(),
            stop: CancellationToken::new(),
            signals: signal_rx,
        };
        let mut answer = Box::pin(owner.answer(offer, lease));
        assert!(poll!(answer.as_mut()).is_pending());
        // The second concrete Address command follows the worker's own query in the real LAN actor.
        signaling.get_address(2).await.unwrap();
        assert!(poll!(answer.as_mut()).is_pending());
        let first = answers.next().await.unwrap();
        assert_eq!(first.signal_type, SignalType::Answer);
        // Consume that real ACK, then hold the worker at its next genuine candidate-ACK await.
        assert!(poll!(answer.as_mut()).is_pending());
        let candidate = answers.next().await.unwrap();
        assert_eq!(candidate.signal_type, SignalType::Candidate);
        let endpoint = parse_ice_candidate(&candidate.data).unwrap().addr();
        rtc.apply_answer(first.data);
        rtc.apply_candidate(candidate.data);
        while !rtc.both_ready() {
            rtc.turn().await;
        }
        for index in 0..3 {
            rtc.send(index);
        }
        while rtc.outstanding() != 0 {
            rtc.turn().await;
        }
        rtc.close_dtls().await;
        rtc.close_reply(endpoint).await;
        let answered = answer
            .await
            .expect("accepted ready prefix was lost during actual answer dispatch");
        let _forwarding = owner
            .handoff(answered, pending)
            .await
            .expect("answer dispatch lost its actual ready handoff");
        let mut accepted = incoming.recv().await.unwrap();
        assert!(accepted.session.accept_from_server());
        for index in 0u32..3 {
            assert_eq!(
                accepted.reliable.recv().await.unwrap().unwrap().as_ref(),
                index.to_be_bytes()
            );
        }
        assert!(accepted.reliable.recv().await.unwrap().is_none());
        assert!(accepted.reliable.recv().await.unwrap().is_none());
    })
    .await
    .expect("finite actual LAN answer-dispatch handoff fixture stalled");
}

/// The actual accepted transport can finish after the old establishment window has elapsed.
#[tokio::test]
async fn http_listener_waits_for_server_trust_before_ready() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let PendingPeer {
            mut owner,
            answered,
            pending,
            mut incoming,
            mut rtc,
            signals: _signals,
            answer,
            ..
        } = pending_peer().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(11)).await;
        let mut handoff = Box::pin(owner.handoff(answered, pending));
        assert!(
            poll!(&mut handoff).is_pending(),
            "HTTP transport expired during the server-trust decision"
        );
        tokio::time::resume();
        rtc.apply_answer(answer);
        while !rtc.both_ready() {
            rtc.turn().await;
        }
        let _forwarding = handoff
            .await
            .expect("HTTP peer must establish within the one-minute budget");
        let accepted = incoming.recv().await.unwrap();
        let retired = accepted.close();
        retired.session.closed().await;
    })
    .await
    .expect("finite HTTP trust fixture stalled");
}

/// A held trust decision still reaches the original finite HTTP establishment cutoff.
#[tokio::test]
async fn http_listener_stops_waiting_at_the_original_trust_budget() {
    let PendingPeer {
        mut owner,
        answered,
        pending,
        signals: _signals,
        rtc: _rtc,
        ..
    } = pending_peer().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(matches!(
        owner.handoff(answered, pending).await,
        Err((_, NetherError::Timeout))
    ));
}
