//! Explicit signer replacement on one listener with its original accepted peer still alive.

use super::*;
use crate::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerSignaling, CallerSignalingConfig,
    ClientIceConfig, NetherClient, ServerIceConfig, SignalDelivery,
};
use bytes::Bytes;
use nethernet::{
    connection::IceMode,
    identity::{Identity, ServerIdentity, TokenIdentity, jwk::EcJwk, jws::Jws, verify_answer},
    protocol::SignalType,
};
use p384::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde_json::json;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Hands off acquired synthetic tokens through the actual key/expiry-checked identity constructor.
fn acquired_identity(proof: &Arc<SigningKey>, revision: u8) -> (Arc<TokenIdentity>, String) {
    let now = SystemTime::now();
    let token = Jws::sign(
        proof,
        &json!({"cpk":EcJwk::from(proof.verifying_key()),"iss":"fixture.invalid",
            "exp":(now+Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "fixture_revision":revision})
        .to_string(),
    )
    .unwrap();
    let identity = TokenIdentity::new(Arc::clone(proof), token.clone(), now).unwrap();
    assert!(std::ptr::eq(identity.signing_key(), proof.as_ref()));
    (Arc::new(identity), token)
}

/// Both new answer proof and existing encrypted data keep their original concrete owners.
#[tokio::test]
async fn replacing_answer_identity_changes_later_offers_and_preserves_accepted_peer() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let bind = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let bridge = CallerSignalingConfig { ice_mode: IceMode::Full, ..Default::default() };
        let (first, mut first_service) = CallerSignaling::new("first".into(), "server".into(), bridge).unwrap();
        let (second, mut second_service) = CallerSignaling::new("second".into(), "server".into(), bridge).unwrap();
        let (accepting, mut server_service) = CallerServerSignaling::new("server".into(), CallerServerSignalingConfig { signaling: bridge, ..Default::default() }).unwrap();
        let proof = Arc::new(SigningKey::generate());
        let (initial, initial_token) = acquired_identity(&proof, 1);
        let (replacement, replacement_token) = acquired_identity(&proof, 2);
        let renewed = Arc::downgrade(&replacement);
        let mut server = NetherServer::bind_with(accepting, ConnectionConfig {
            identity: Some(initial), token_trust: Some(TokenTrust::Any),
            server_ice: Some(ServerIceConfig { ice: Default::default(), bind_addr: bind }),
            max_sessions: 2, ..Default::default()
        }).await.unwrap();
        let client = ConnectionConfig {
            identity: Some(Arc::new(ServerIdentity::generate("client.fixture.invalid", SystemTime::now()).unwrap())),
            server_trust: Some(TokenTrust::Any),
            client_ice: Some(ClientIceConfig { ice: Default::default(), bind_addr: Some(bind) }),
            ..Default::default()
        };
        let stop = CancellationToken::new();
        let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(12);
        let application = async {
            let mut first_client = NetherClient::connect_with(first, "server".into(), client.clone()).await.unwrap();
            let mut first_peer = server.accept().await.unwrap();
            server.set_identity(replacement);
            let mut second_client = NetherClient::connect_with(second, "server".into(), client).await.unwrap();
            let mut second_peer = server.accept().await.unwrap();
            first_client.send(Bytes::from_static(b"first peer survives replacement")).await.unwrap();
            assert_eq!(first_peer.reliable.recv().await.unwrap().unwrap(), &b"first peer survives replacement"[..]);
            second_client.send(Bytes::from_static(b"second peer uses renewed answer")).await.unwrap();
            assert_eq!(second_peer.reliable.recv().await.unwrap().unwrap(), &b"second peer uses renewed answer"[..]);
            first_peer.session.send(Bytes::from_static(b"original encrypted reply")).await.unwrap();
            assert_eq!(first_client.recv().await.unwrap().unwrap(), &b"original encrypted reply"[..]);
            let first_close = first_client.close();
            let first_peer_close = first_peer.close();
            tokio::join!(first_close.session.closed(), first_peer_close.session.closed());
            second_peer.session.send(Bytes::from_static(b"second remains after first close")).await.unwrap();
            assert_eq!(second_client.recv().await.unwrap().unwrap(), &b"second remains after first close"[..]);
            let second_close = second_client.close();
            let second_peer_close = second_peer.close();
            tokio::join!(second_close.session.closed(), second_peer_close.session.closed());
            stop.cancel();
            server.close().await.unwrap();
            assert!(renewed.upgrade().is_none(), "closed listener retained its renewed signer");
        };
        let relay = async {
            let mut answers = Vec::new();
            let (mut first_open, mut second_open) = (true, true);
            loop {
                tokio::select! { biased;
                    _ = stop.cancelled() => break,
                    request = first_service.recv(), if first_open => {
                        if let Some(request) = request {
                            let delivery = server_service.prepare_delivery_before("first", &request.signal().to_string(), deadline).unwrap();
                            request.finish(delivery.await.map(|()| SignalDelivery::PeerReceived));
                        } else { first_open = false; }
                    }
                    request = second_service.recv(), if second_open => {
                        if let Some(request) = request {
                            let delivery = server_service.prepare_delivery_before("second", &request.signal().to_string(), deadline).unwrap();
                            request.finish(delivery.await.map(|()| SignalDelivery::PeerReceived));
                        } else { second_open = false; }
                    }
                    request = server_service.recv() => {
                        let Some(request) = request else { break; };
                        let signal = request.signal();
                        if signal.signal_type == SignalType::Answer {
                            let expected = if signal.network_id == "first" { &initial_token } else { &replacement_token };
                            assert_eq!(&Identity::from_sdp(&signal.data).unwrap().assertion.token, expected);
                            let claims = verify_answer(&signal.data, Some(&TokenTrust::Any), SystemTime::now()).unwrap().unwrap();
                            assert_eq!(claims.client_public_key().unwrap(), *proof.verifying_key());
                            answers.push(signal.network_id.clone());
                        }
                        let delivery = match signal.network_id.as_str() {
                            "first" => first_service.prepare_delivery_before("server", &signal.to_string(), deadline),
                            "second" => second_service.prepare_delivery_before("server", &signal.to_string(), deadline),
                            _ => panic!("listener emitted an unrelated peer route"),
                        }.unwrap();
                        request.finish(delivery.await.map(|()| SignalDelivery::ServiceAccepted));
                    }
                }
            }
            first_service.close(); second_service.close(); server_service.close();
            answers
        };
        let ((), answers) = tokio::join!(application, relay);
        assert_eq!(answers, ["first", "second"]);
    }).await.expect("finite original-listener identity replacement stalled");
}

/// Natural config cancellation retires the original selected signer before explicit listener close.
#[tokio::test]
async fn cancelled_listener_releases_its_selected_identity_without_explicit_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (signaling, driver) =
            CallerServerSignaling::new("server".into(), CallerServerSignalingConfig::default())
                .unwrap();
        let proof = Arc::new(SigningKey::generate());
        let (selected, _) = acquired_identity(&proof, 1);
        let original = Arc::downgrade(&selected);
        let cancel = CancellationToken::new();
        let mut server = NetherServer::bind_with(
            signaling,
            ConnectionConfig {
                identity: Some(selected),
                token_trust: Some(TokenTrust::Any),
                cancel_token: cancel.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        cancel.cancel();
        assert!(matches!(
            server.accept().await,
            Err(NetherError::ConnectionClosed)
        ));
        assert!(
            original.upgrade().is_none(),
            "retired listener retained its original signer"
        );
        let (replacement, _) = acquired_identity(&proof, 2);
        let unused = Arc::downgrade(&replacement);
        server.set_identity(replacement);
        assert!(
            unused.upgrade().is_none(),
            "retired listener retained a later signer"
        );
        server.close().await.unwrap();
        drop(driver);
    })
    .await
    .expect("finite original-listener cancellation stalled");
}
