//! Controlled real UDP proves configured accepting gather, late-signal order and allocation cleanup.
#[path = "support/signing.rs"]
mod signing;
#[path = "../../nethernet/tests/support/turn.rs"]
mod turn;
use nethernet::{
    connection::{Connection, IceMode},
    identity::{SdpIdentity, ServerIdentity},
    protocol::{
        Signal, SignalType,
        webrtc::{Description, candidate::parse_ice_candidate},
    },
    session::{IceConfig, IcePolicy, IceServer, Session, TurnCredentials},
};
use nethernet_tokio::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerSignalingConfig, ConnectionConfig,
    NetherServer, ServerIceConfig, SignalDelivery,
};
use rtc::ice::candidate::CandidateType;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::net::UdpSocket;
use turn::{PASSWORD, TurnPeer, USER};

/// Produces real signed offer bytes from the existing pure session and SDP owner.
fn signed_offer(identity: &ServerIdentity) -> Signal {
    signed_offer_at(identity, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 40300))
}

/// Keeps the controlled offer on the same explicit socket family as the accepting endpoint.
fn signed_offer_at(identity: &ServerIdentity, local: SocketAddr) -> Signal {
    let wall = SystemTime::now();
    let (session, description) =
        Session::new(local, true, 1, tokio::time::Instant::now().into_std()).unwrap();
    let (_, mut signals) = Connection::connect(
        session,
        description,
        9,
        "authenticated-peer".into(),
        IceMode::Full,
    );
    let mut offer = signals.remove(0);
    offer.data = identity.augment(&offer.data, wall).unwrap();
    offer
}

/// Drives only the existing controlled TURN packet fixture over its actual socket.
async fn turn_packet(socket: &UdpSocket, server: &mut TurnPeer, buffer: &mut [u8]) {
    let (size, from) = socket.recv_from(buffer).await.unwrap();
    server.receive(from, buffer[..size].to_vec());
    while let Some((to, bytes)) = server.packets.pop_front() {
        socket.send_to(&bytes, to).await.unwrap();
    }
}

#[tokio::test]
async fn configured_server_gathers_before_or_during_answer_and_never_overtakes_it() {
    for mode in [IceMode::Full, IceMode::Trickle] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut turn = TurnPeer::new(socket.local_addr().unwrap());
            let (signaling, mut driver) = CallerServerSignaling::new("server".into(), CallerServerSignalingConfig {
                signaling: CallerSignalingConfig { ice_mode: mode, ..Default::default() }, ..Default::default()
            }).unwrap();
            let client_identity = signing::identity("fixture-client");
            let server_identity = signing::identity("fixture-server");
            let now = tokio::time::Instant::now().into_std();
            let mut listener = NetherServer::bind_with(signaling, ConnectionConfig {
                identity: Some(Arc::new(server_identity.clone())),
                // The caller grants only the exact controlled peer key/issuer.
                token_trust: Some(signing::trust(&client_identity)),
                server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None, bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), ice: IceConfig {
                    servers: vec![IceServer::Turn(turn.addr, TurnCredentials::new(USER.into(), PASSWORD.into(), now + Duration::from_secs(1200)).unwrap())],
                    policy: IcePolicy::RelayOnly, ..Default::default()
                }}),
                ..Default::default()
            }).await.unwrap();
            driver.try_deliver("authenticated-peer", &signed_offer(&client_identity).to_string()).unwrap();
            let mut answer = None;
            let mut buffer = vec![0; 65536];
            loop {
                if answer.is_some() && turn.allocation_count() == 1 { break; }
                tokio::select! {
                    request = driver.recv() => {
                        let request = request.unwrap();
                        assert!(answer.is_none(), "late candidate overtook a pending answer delivery");
                        assert_eq!(request.signal().signal_type, SignalType::Answer);
                        let (_, candidates) = Description::parse(&request.signal().data).unwrap();
                        match mode {
                            IceMode::Full => { assert_eq!(candidates.len(), 1); assert_eq!(candidates[0].candidate_type(), CandidateType::Relay); }
                            IceMode::Trickle => assert!(candidates.is_empty()),
                        }
                        assert!(nethernet::identity::verify_answer(&request.signal().data, Some(&signing::trust(&server_identity)), SystemTime::now()).is_ok());
                        answer = Some(request);
                    }
                    _ = turn_packet(&socket, &mut turn, &mut buffer) => {},
                }
            }
            if mode == IceMode::Trickle {
                answer.take().unwrap().finish(Ok(SignalDelivery::ServiceAccepted));
                let candidate = loop {
                    tokio::select! {
                        request = driver.recv() => break request.unwrap(),
                        _ = turn_packet(&socket, &mut turn, &mut buffer) => {},
                    }
                };
                assert_eq!(candidate.signal().signal_type, SignalType::Candidate);
                assert_eq!(parse_ice_candidate(&candidate.signal().data).unwrap().candidate_type(), CandidateType::Relay);
                candidate.finish(Ok(SignalDelivery::ServiceAccepted));
            }
            listener.close().await.unwrap();
            if let Some(answer) = answer { assert!(answer.is_cancelled()); }
            while turn.allocation_count() != 0 { turn_packet(&socket, &mut turn, &mut buffer).await; }
        }).await.expect("finite configured accepting gathering/cleanup fixture stalled");
    }
}

/// A real signer failure after full TURN gathering must leave cleanup with the original guard.
struct RefusedSigner;
impl SdpIdentity for RefusedSigner {
    fn augment(&self, _: &str, _: SystemTime) -> nethernet::identity::error::Result<String> {
        Err(nethernet::identity::error::IdentityError::Signing(
            "synthetic signer refusal".into(),
        ))
    }
}

#[tokio::test]
async fn configured_server_signer_failure_releases_the_gathered_allocation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut turn = TurnPeer::new(socket.local_addr().unwrap());
        let (signaling, mut driver) = CallerServerSignaling::new("server".into(), CallerServerSignalingConfig {
            signaling: CallerSignalingConfig { ice_mode: IceMode::Full, ..Default::default() }, ..Default::default()
        }).unwrap();
        let client_identity = signing::identity("fixture-client");
        let now = tokio::time::Instant::now().into_std();
        let mut listener = NetherServer::bind_with(signaling, ConnectionConfig {
            identity: Some(Arc::new(RefusedSigner)), token_trust: Some(signing::trust(&client_identity)),
            server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None, bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), ice: IceConfig {
                servers: vec![IceServer::Turn(turn.addr, TurnCredentials::new(USER.into(), PASSWORD.into(), now + Duration::from_secs(1200)).unwrap())],
                policy: IcePolicy::RelayOnly, ..Default::default()
            }}), ..Default::default()
        }).await.unwrap();
        driver.try_deliver("authenticated-peer", &signed_offer(&client_identity).to_string()).unwrap();
        let mut buffer = vec![0; 65536];
        let mut allocated = false;
        loop {
            tokio::select! {
                request = driver.recv() => {
                    let request = request.unwrap();
                    assert_eq!(request.signal().signal_type, SignalType::Error);
                    assert_eq!(request.signal().data.parse::<u32>().unwrap(), nethernet::error::SignalErrorCode::FailedToCreateAnswer as u32);
                    request.finish(Ok(SignalDelivery::ServiceAccepted));
                    break;
                }
                _ = turn_packet(&socket, &mut turn, &mut buffer) => { allocated |= turn.allocation_count() == 1; },
            }
        }
        assert!(allocated, "signer was not reached after a real TURN allocation");
        while turn.allocation_count() != 0 { turn_packet(&socket, &mut turn, &mut buffer).await; }
        listener.close().await.unwrap();
    }).await.expect("failed configured answer leaked its TURN allocation");
}

/// The next-offer config replacement must not reinterpret an expired original TURN credential.
#[tokio::test]
async fn configured_server_rejects_original_expiry_and_accepts_explicit_replacement() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (signaling, mut driver) =
            CallerServerSignaling::new("server".into(), Default::default()).unwrap();
        let client_identity = signing::identity("fixture-client");
        let now = tokio::time::Instant::now().into_std();
        let mut listener = NetherServer::bind_with(
            signaling,
            ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::generate("fixture-server", SystemTime::now()).unwrap(),
                )),
                token_trust: Some(signing::trust(&client_identity)),
                server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None,
                    bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                    ice: IceConfig {
                        servers: vec![IceServer::Turn(
                            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3478),
                            TurnCredentials::new(
                                USER.into(),
                                PASSWORD.into(),
                                now - Duration::from_secs(1),
                            )
                            .unwrap(),
                        )],
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        driver
            .try_deliver(
                "authenticated-peer",
                &signed_offer(&client_identity).to_string(),
            )
            .unwrap();
        let refused = driver.recv().await.unwrap();
        assert_eq!(refused.signal().signal_type, SignalType::Error);
        assert_eq!(
            refused.signal().data.parse::<u32>().unwrap(),
            nethernet::error::SignalErrorCode::FailedToCreatePeerConnection as u32
        );
        refused.finish(Ok(SignalDelivery::ServiceAccepted));
        listener.set_server_ice(Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None,
            bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            ice: Default::default(),
        }));
        let mut replacement = signed_offer(&client_identity);
        replacement.connection_id += 1;
        driver
            .try_deliver("authenticated-peer", &replacement.to_string())
            .unwrap();
        let answer = driver.recv().await.unwrap();
        assert_eq!(answer.signal().signal_type, SignalType::Answer);
        listener.close().await.unwrap();
        assert!(answer.is_cancelled());
    })
    .await
    .expect("explicit accepting ICE replacement did not progress");
}

/// Real controlled Binding responses stay on the configured IPv4/IPv6 socket family.
#[tokio::test]
async fn configured_server_full_stun_gathers_on_the_explicit_socket_family() {
    use std::net::{IpAddr, Ipv6Addr};
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let socket = match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
            Ok(socket) => socket,
            Err(error)
                if ip.is_ipv6()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                    ) =>
            {
                eprintln!("missing fixture: local IPv6 UDP support ({error})");
                continue;
            }
            Err(error) => panic!("controlled local UDP fixture: {error}"),
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stun = TurnPeer::new(socket.local_addr().unwrap());
            let client = signing::identity("fixture-client");
            let server = signing::identity("fixture-server");
            let (signaling, mut driver) = CallerServerSignaling::new(
                "server".into(),
                CallerServerSignalingConfig {
                    signaling: CallerSignalingConfig {
                        ice_mode: IceMode::Full,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
            let mut listener = NetherServer::bind_with(
                signaling,
                ConnectionConfig {
                    identity: Some(Arc::new(server.clone())),
                    token_trust: Some(signing::trust(&client)),
                    server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None,
                        bind_addr: SocketAddr::new(ip, 0),
                        ice: IceConfig {
                            servers: vec![IceServer::Stun(stun.addr)],
                            ..Default::default()
                        },
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            driver
                .try_deliver(
                    "authenticated-peer",
                    &signed_offer_at(&client, SocketAddr::new(ip, 40300)).to_string(),
                )
                .unwrap();
            let mut buffer = vec![0; 65536];
            let answer = loop {
                tokio::select! {
                    request = driver.recv() => break request.unwrap(),
                    _ = turn_packet(&socket, &mut stun, &mut buffer) => {},
                }
            };
            assert_eq!(answer.signal().signal_type, SignalType::Answer);
            let (_, candidates) = Description::parse(&answer.signal().data).unwrap();
            assert!(candidates.iter().any(|candidate| candidate.candidate_type()
                == CandidateType::ServerReflexive
                && candidate.addr().is_ipv6() == ip.is_ipv6()));
            assert!(
                nethernet::identity::verify_answer(
                    &answer.signal().data,
                    Some(&signing::trust(&server)),
                    SystemTime::now()
                )
                .is_ok()
            );
            assert_eq!(stun.allocation_count(), 0);
            listener.close().await.unwrap();
            assert!(answer.is_cancelled());
        })
        .await
        .expect("finite configured STUN family fixture stalled");
    }
}
