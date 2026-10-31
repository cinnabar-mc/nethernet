//! Real loopback UDP proves the concrete configured client drives core gathering and cleanup.
#[path = "../../nethernet/tests/support/turn.rs"]
mod turn;
use nethernet::connection::IceMode;
use nethernet::protocol::SignalType;
use nethernet::protocol::webrtc::{Description, candidate::parse_ice_candidate};
use nethernet::session::{IceConfig, IcePolicy, IceServer, TurnCredentials};
use nethernet_tokio::{
    CallerSignaling, CallerSignalingConfig, ClientIceConfig, ConnectionConfig, NetherClient,
    NetherError, SignalDelivery,
};
use rtc::ice::candidate::CandidateType;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use turn::{PASSWORD, TurnPeer, USER};

#[tokio::test]
async fn configured_client_gathers_while_offering_and_releases_turn_on_cancellation() {
    for mode in [IceMode::Full, IceMode::Trickle] {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut server = TurnPeer::new(socket.local_addr().unwrap());
        let (signaling, mut driver) = CallerSignaling::new(
            "local-network".into(),
            "authenticated-peer".into(),
            CallerSignalingConfig {
                ice_mode: mode,
                ..Default::default()
            },
        )
        .unwrap();
        let now = tokio::time::Instant::now().into_std();
        let config = ConnectionConfig {
            client_ice: Some(ClientIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: IceConfig {
                    servers: vec![IceServer::Turn(
                        server.addr,
                        TurnCredentials::new(
                            USER.to_owned(),
                            PASSWORD.to_owned(),
                            now + Duration::from_secs(1200),
                        )
                        .unwrap(),
                    )],
                    policy: IcePolicy::RelayOnly,
                    ..Default::default()
                },
                bind_addr: Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)),
            }),
            ..Default::default()
        };
        let cancel = config.cancel_token.clone();
        let mut connect = Box::pin(NetherClient::connect_with(
            signaling,
            "authenticated-peer".into(),
            config,
        ));
        let mut offer = None;
        let mut buffer = vec![0; 65536];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if offer.is_some() && server.allocation_count() == 1 { break; }
                tokio::select! {
                    request = driver.recv() => {
                        let request = request.unwrap();
                        assert_eq!(request.signal().signal_type, SignalType::Offer);
                        let (_, candidates) = Description::parse(&request.signal().data).unwrap();
                        match mode {
                            IceMode::Full => { assert_eq!(candidates.len(), 1); assert_eq!(candidates[0].candidate_type(), CandidateType::Relay); }
                            IceMode::Trickle => assert!(candidates.is_empty()),
                        }
                        offer = Some(request);
                    }
                    packet = socket.recv_from(&mut buffer) => {
                        let (size, from) = packet.unwrap();
                        server.receive(from, buffer[..size].to_vec());
                        while let Some((to, data)) = server.packets.pop_front() { socket.send_to(&data, to).await.unwrap(); }
                    }
                    _ = &mut connect => panic!("configured client ended before gathering its TURN allocation"),
                }
            }
        }).await.expect("configured gathering stalled behind signaling");
        assert_eq!(
            server.allocation_count(),
            1,
            "TURN did not progress while the offer receipt was pending"
        );
        if mode == IceMode::Trickle {
            offer
                .take()
                .unwrap()
                .finish(Ok(SignalDelivery::PeerReceived));
            let candidate = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        request = driver.recv() => break request.unwrap(),
                        packet = socket.recv_from(&mut buffer) => {
                            let (size, from) = packet.unwrap(); server.receive(from, buffer[..size].to_vec());
                            while let Some((to, data)) = server.packets.pop_front() { socket.send_to(&data, to).await.unwrap(); }
                        }
                        _ = &mut connect => panic!("client ended before trickling the gathered relay"),
                    }
                }
            }).await.unwrap();
            assert_eq!(candidate.signal().signal_type, SignalType::Candidate);
            assert_eq!(
                parse_ice_candidate(&candidate.signal().data)
                    .unwrap()
                    .candidate_type(),
                CandidateType::Relay
            );
            candidate.finish(Ok(SignalDelivery::ServiceAccepted));
        }
        cancel.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), connect)
                .await
                .expect("cancelled connection did not finish"),
            Err(NetherError::Cancelled)
        ));
        if let Some(offer) = offer {
            assert!(offer.is_cancelled());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.allocation_count() != 0 {
                let (size, from) = socket.recv_from(&mut buffer).await.unwrap();
                server.receive(from, buffer[..size].to_vec());
            }
        })
        .await
        .expect("cancelled client did not release its known TURN allocation");
    }
}
