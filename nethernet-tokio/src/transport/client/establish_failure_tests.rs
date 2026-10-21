use super::*;
use crate::signaling::caller::{CallerSignaling, CallerSignalingConfig, SignalDelivery};
use crate::transport::{ClientIceConfig, Timeouts};
use nethernet::identity::ServerIdentity;
use std::time::Duration;

/// A real signed answer cannot leave its configured socket behind when establishment returns an error.
#[test]
fn failed_establishment_releases_the_original_socket_before_returning_its_cause() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let (local, peer_address, failure, immediate, peer_close) = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = reservation.local_addr().unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_address = socket.local_addr().unwrap();
            drop(reservation);
            let identity = ServerIdentity::generate("fixture.invalid", SystemTime::now()).unwrap();
            let (caller, mut driver) = CallerSignaling::new(
                "local".into(),
                "peer".into(),
                CallerSignalingConfig {
                    ice_mode: IceMode::Full,
                    ..Default::default()
                },
            )
            .unwrap();
            let signaling = ClientSignaling::from(caller);
            let config = ConnectionConfig {
                attempts: 1,
                timeouts: Timeouts {
                    negotiation: Duration::from_secs(5),
                    start: Duration::ZERO,
                    channel: Duration::ZERO,
                },
                client_ice: Some(ClientIceConfig {
                    turn_streams: Vec::new(),
                    turn_tls: None,
                    ice: Default::default(),
                    bind_addr: Some(local),
                }),
                server_trust: Some(TokenTrust::Any),
                ..Default::default()
            };
            let mut connecting = Box::pin(NetherClient::negotiate(&signaling, "peer", 1, config));
            let offer = tokio::select! {
                offer = driver.recv() => offer.expect("original client offer"),
                _ = &mut connecting => panic!("client failed before its original offer"),
            };
            assert_eq!(offer.signal().signal_type, SignalType::Offer);
            let now = transport_now();
            let (core, description) = SansSession::new(peer_address, false, 2, now).unwrap();
            let (remote, candidates) = SansConnection::parse_offer(offer.signal()).unwrap();
            let (peer, mut answers) = SansConnection::accept(
                core,
                description,
                offer.signal(),
                remote,
                candidates,
                IceMode::Full,
                now,
            )
            .unwrap();
            let mut answer = answers.remove(0);
            assert_eq!(answer.signal_type, SignalType::Answer);
            answer.data = identity.augment(&answer.data, SystemTime::now()).unwrap();
            assert!(
                check_answer(&answer, Some(&TokenTrust::Any), false, SystemTime::now())
                    .unwrap()
                    .is_some(),
                "the original generated answer must pass key verification"
            );
            driver.try_deliver("peer", &answer.to_string()).unwrap();
            offer.finish(Ok(SignalDelivery::PeerReceived));
            let failure = connecting
                .await
                .err()
                .expect("zero establishment budget cannot create a ready client");
            // This synchronous OS operation cannot let an aborted actor retire first.
            let immediate = std::net::UdpSocket::bind(local);
            driver.close();
            drop((driver, signaling));
            let (mut retired, peer_close) = peer.close(transport_now());
            while retired.poll().is_some() {}
            drop((retired, socket));
            (local, peer_address, failure, immediate, peer_close)
        })
        .await
        .expect("finite signed-answer establishment fixture stalled")
    });
    // Own all spawned transport work through destruction, including an actor not yet polled.
    drop(runtime);
    let immediate = immediate.map(drop);
    let _local_retired = std::net::UdpSocket::bind(local)
        .expect("the original runtime released its configured socket during fixture cleanup");
    let _peer_retired = std::net::UdpSocket::bind(peer_address)
        .expect("the original generated-answer peer released its socket");
    peer_close.unwrap();
    assert_eq!(
        failure.0,
        Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept)
    );
    assert!(matches!(failure.1, NetherError::Timeout));
    immediate.expect("establishment returned before retiring the original configured socket");
}
