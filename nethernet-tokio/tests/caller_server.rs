//! Actual public accepting/connecting transports driven by caller-owned service envelopes.
#[path = "support/signing.rs"]
mod signing;
use bytes::Bytes;
use nethernet::connection::IceMode;
use nethernet_tokio::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerSignaling, CallerSignalingConfig,
    ClientIceConfig, ConnectionConfig, NetherClient, NetherError, NetherServer, ServerIceConfig,
    ServerIdentity, SignalDelivery, SignalType,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Uses one explicit real key/token owner per controlled peer.
fn signed(identity: &ServerIdentity) -> ConnectionConfig {
    ConnectionConfig {
        identity: Some(Arc::new(identity.clone())),
        attempts: 1,
        client_ice: Some(ClientIceConfig {
            turn_streams: Vec::new(),
            turn_tls: None,
            ice: Default::default(),
            bind_addr: Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)),
        }),
        ..Default::default()
    }
}

/// A held answer for one route cannot prevent a second route from establishing.
#[tokio::test]
async fn caller_server_keeps_peer_isolation_and_accepted_lifetime_on_listener_close() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server_identity = signing::identity("server");
        let client_identity = signing::identity("client");
        let (server, mut service) = CallerServerSignaling::new("server".into(), CallerServerSignalingConfig {
            signaling: CallerSignalingConfig { ice_mode: IceMode::Full, ..Default::default() }, ..Default::default()
        }).unwrap();
        let mut listener = NetherServer::bind_with(server, ConnectionConfig {
            token_trust: Some(signing::trust(&client_identity)),
            server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None, ice: Default::default(), bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0) }),
            ..signed(&server_identity)
        }).await.unwrap();
        let client_config = CallerSignalingConfig { ice_mode: IceMode::Full, ..Default::default() };
        let (first, mut first_service) = CallerSignaling::new("first".into(), "server".into(), client_config).unwrap();
        let (second, mut second_service) = CallerSignaling::new("second".into(), "server".into(), client_config).unwrap();
        let mut first = Box::pin(NetherClient::connect_with(first, "server".into(), ConnectionConfig { server_trust: Some(signing::trust(&server_identity)), ..signed(&client_identity) }));
        let mut second = Box::pin(NetherClient::connect_with(second, "server".into(), ConnectionConfig { server_trust: Some(signing::trust(&server_identity)), ..signed(&client_identity) }));
        let mut held = None;
        let second = loop {
            tokio::select! {
                result = &mut first => panic!("first route completed before its answer delivery: {}", result.is_ok()),
                result = &mut second, if held.is_some() => break result.unwrap(),
                request = first_service.recv() => {
                    let request = request.unwrap();
                    service.try_deliver("first", &request.signal().to_string()).unwrap();
                    request.finish(Ok(SignalDelivery::PeerReceived));
                }
                request = second_service.recv() => {
                    let request = request.unwrap();
                    service.try_deliver("second", &request.signal().to_string()).unwrap();
                    request.finish(Ok(SignalDelivery::PeerReceived));
                }
                request = service.recv() => {
                    let request = request.unwrap();
                    match request.signal().network_id.as_str() {
                        "first" => { assert!(held.is_none(), "late signaling overtook the held first answer"); assert_eq!(request.signal().signal_type, SignalType::Answer); held = Some(request); }
                        "second" => {
                            second_service.try_deliver("server", &request.signal().to_string()).unwrap();
                            request.finish(Ok(SignalDelivery::ServiceAccepted));
                        }
                        _ => panic!("service request escaped its authenticated fixture route"),
                    }
                }
            }
        };
        let mut accepted = listener.accept().await.unwrap();
        assert_eq!(accepted.session.remote_addr().await.network_id, "second");
        second.send(Bytes::from_static(b"independent peer")).await.unwrap();
        assert_eq!(accepted.reliable.recv().await.unwrap().unwrap(), "independent peer");
        listener.close().await.unwrap();
        assert!(held.as_ref().unwrap().is_cancelled());
        second.send(Bytes::from_static(b"accepted after listener close")).await.unwrap();
        assert_eq!(accepted.reliable.recv().await.unwrap().unwrap(), "accepted after listener close");
        service.close();
        assert!(matches!(accepted.reliable.recv().await, Err(NetherError::ConnectionClosed)));
        assert!(accepted.reliable.recv().await.unwrap().is_none());
        second.sender().close().await.unwrap();
    }).await.expect("finite multi-peer caller server fixture stalled");
}

/// Caller acceptance requires an explicit offer-trust decision and an explicit answer signer.
#[tokio::test]
async fn caller_server_binding_does_not_choose_an_offer_trust_or_mint_an_answer_key() {
    let (server, _driver) =
        CallerServerSignaling::new("server".into(), Default::default()).unwrap();
    assert!(matches!(
        NetherServer::bind_with(server.clone(), ConnectionConfig::default()).await,
        Err(NetherError::IdentityRequired)
    ));
    assert!(matches!(
        NetherServer::bind_with(server, signed(&signing::identity("server"))).await,
        Err(NetherError::InvalidState(_))
    ));
}

/// The new bridge must route into the existing configured token/fingerprint admission owner.
#[tokio::test]
async fn caller_server_rejects_unsigned_and_untrusted_offer_keys() {
    tokio::time::timeout(Duration::from_secs(10), async {
        use nethernet::{connection::Connection, session::Session};
        let expected = signing::identity("expected-client");
        let wrong = signing::identity("wrong-client");
        let server = signing::identity("server");
        let (signaling, mut driver) =
            CallerServerSignaling::new("server".into(), Default::default()).unwrap();
        let mut listener = NetherServer::bind_with(
            signaling,
            ConnectionConfig {
                token_trust: Some(signing::trust(&expected)),
                ..signed(&server)
            },
        )
        .await
        .unwrap();
        for (index, sign) in [None, Some(&wrong)].into_iter().enumerate() {
            let (core, description) = Session::new(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 40300),
                true,
                1,
                tokio::time::Instant::now().into_std(),
            )
            .unwrap();
            let (_, mut offers) = Connection::connect(
                core,
                description,
                index as u64 + 1,
                "peer".into(),
                IceMode::Full,
            );
            let mut offer = offers.remove(0);
            if let Some(identity) = sign {
                offer.data = identity
                    .augment(&offer.data, std::time::SystemTime::now())
                    .unwrap();
            }
            driver.try_deliver("peer", &offer.to_string()).unwrap();
            let refusal = driver.recv().await.unwrap();
            assert_eq!(refusal.signal().signal_type, SignalType::Error);
            assert_eq!(
                refusal.signal().data.parse::<u32>().unwrap(),
                nethernet::error::SignalErrorCode::NotLoggedIn as u32
            );
            refusal.finish(Ok(SignalDelivery::ServiceAccepted));
        }
        listener.close().await.unwrap();
    })
    .await
    .expect("untrusted offer bypassed or stalled concrete accepting admission");
}

/// Anonymous offer admission does not replace the caller's explicit trust decision for present identities.
#[tokio::test]
async fn anonymous_caller_server_still_requires_offer_trust() {
    let (server, _driver) =
        CallerServerSignaling::new("server".into(), Default::default()).unwrap();
    let identity = signing::identity("server");
    assert!(matches!(
        NetherServer::bind_with(
            server,
            ConnectionConfig {
                allow_anonymous_offers: true,
                ..signed(&identity)
            },
        )
        .await,
        Err(NetherError::InvalidState(_))
    ));
}
