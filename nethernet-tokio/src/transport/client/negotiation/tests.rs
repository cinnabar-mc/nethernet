use super::*;
use crate::addr::Addr;
use crate::session::Session as RuntimeSession;
use crate::signaling::caller::SignalDelivery;
use crate::signaling::caller::{CallerSignaling, CallerSignalingConfig};
use bytes::Bytes;
use futures::poll;
use nethernet::connection::IceMode;
use nethernet::session::{IceConfig, Session};
use rtc::stun::message::{CLASS_REQUEST, METHOD_BINDING, Message};
use std::sync::Arc;

/// Holds real service completion while the remote RTC peer checks the actually advertised candidate.
async fn peer_checks_before_handoff(mode: IceMode, answer_before_check: bool) {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let now = transport_now();
    let (client, description) = Session::new_with_ice(
        client_socket.local_addr().unwrap(),
        true,
        1,
        IceConfig::default(),
        now,
    )
    .unwrap();
    let (mut client, initial) = Connection::connect(client, description, 1, "peer".into(), mode);
    let (caller, mut driver) = CallerSignaling::new(
        "local".into(),
        "peer".into(),
        CallerSignalingConfig {
            ice_mode: mode,
            ..Default::default()
        },
    )
    .unwrap();
    let signaling = ClientSignaling::from(caller);
    let mut incoming = signaling.signals().unwrap();
    let mut negotiation = Box::pin(exchange(
        &client_socket,
        &mut client,
        &mut incoming,
        &signaling,
        initial,
        1,
        "peer",
        None,
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(5),
    ));
    let offer = tokio::select! {
        request = driver.recv() => request.unwrap(),
        result = &mut negotiation => panic!("negotiation ended before its offer: {result:?}"),
    };
    assert_eq!(offer.signal().signal_type, SignalType::Offer);
    let (peer, description) =
        Session::new(peer_socket.local_addr().unwrap(), false, 2, now).unwrap();
    let (remote, candidates) = Connection::parse_offer(offer.signal()).unwrap();
    let (mut peer, answers) = Connection::accept(
        peer,
        description,
        offer.signal(),
        remote,
        candidates,
        IceMode::Full,
        now,
    )
    .unwrap();
    let held = match mode {
        IceMode::Full => offer,
        IceMode::Trickle => {
            offer.finish(Ok(SignalDelivery::PeerReceived));
            let candidate = tokio::select! {
                request = driver.recv() => request.unwrap(),
                result = &mut negotiation => panic!("negotiation ended before its candidate: {result:?}"),
            };
            assert_eq!(candidate.signal().signal_type, SignalType::Candidate);
            peer.handle(ConnectionInput::Signal(
                candidate.signal().clone(),
                transport_now(),
            ))
            .unwrap();
            candidate
        }
    };
    if answer_before_check {
        driver.try_deliver("peer", &answers[0].to_string()).unwrap();
        assert!(
            poll!(negotiation.as_mut()).is_pending(),
            "pending service receipt must still own the handoff"
        );
    }
    peer.handle(ConnectionInput::Timeout(transport_now()))
        .unwrap();
    let check = std::iter::from_fn(|| peer.poll())
        .find_map(|output| match output {
            SessionOutput::Send(data, to) => Some((data, to)),
            _ => None,
        })
        .expect("the actual peer did not generate a connectivity check");
    assert_eq!(check.1, client_socket.local_addr().unwrap());
    let mut parsed = Message::new();
    parsed.raw = check.0.clone();
    parsed.decode().unwrap();
    assert_eq!(parsed.typ.method, METHOD_BINDING);
    assert_eq!(parsed.typ.class, CLASS_REQUEST);
    peer_socket.send_to(&check.0, check.1).await.unwrap();
    // Readiness establishes that the authentic packet is available before polling exchange.
    client_socket.readable().await.unwrap();
    assert!(
        poll!(negotiation.as_mut()).is_pending(),
        "a legitimate peer check ended negotiation while service completion was pending"
    );
    assert!(
        !held.is_cancelled(),
        "early ICE handling abandoned the live service request"
    );
    held.finish(Ok(SignalDelivery::PeerReceived));
    if !answer_before_check {
        driver.try_deliver("peer", &answers[0].to_string()).unwrap();
    }
    negotiation
        .await
        .expect("negotiation could not finish after the receipt and answer arrived");
    let (client, mut client_reliable, _client_unreliable, client_ready) = RuntimeSession::spawn(
        Arc::new(client_socket),
        client,
        Addr::default(),
        Addr::default(),
    );
    let (peer, mut peer_reliable, _peer_unreliable, peer_ready) = RuntimeSession::spawn(
        Arc::new(peer_socket),
        peer,
        Addr::default(),
        Addr::default(),
    );
    tokio::try_join!(client_ready, peer_ready)
        .expect("early checks prevented actual channel establishment");
    client
        .send(Bytes::from_static(b"secured data after early check"))
        .await
        .unwrap();
    assert_eq!(
        peer_reliable.recv().await.unwrap().unwrap(),
        "secured data after early check"
    );
    peer.send(Bytes::from_static(b"secured reply after handoff"))
        .await
        .unwrap();
    assert_eq!(
        client_reliable.recv().await.unwrap().unwrap(),
        "secured reply after handoff"
    );
    client.close().await.unwrap();
    peer.close().await.unwrap();
}

#[tokio::test]
async fn early_peer_checks_keep_full_negotiation_alive_before_answer_and_offer_receipt() {
    tokio::time::timeout(
        Duration::from_secs(5),
        peer_checks_before_handoff(IceMode::Full, false),
    )
    .await
    .expect("finite full early-peer-check negotiation stalled");
}

#[tokio::test]
async fn early_peer_checks_keep_trickle_negotiation_alive_after_answer_before_candidate_receipt() {
    tokio::time::timeout(
        Duration::from_secs(5),
        peer_checks_before_handoff(IceMode::Trickle, true),
    )
    .await
    .expect("finite trickle early-peer-check negotiation stalled");
}
