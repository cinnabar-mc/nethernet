//! Owns both actual transport peers; no account, retail route or service authority is simulated.

use super::*;
use crate::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerSignaling, CallerSignalingConfig,
    ClientIceConfig, NetherServer, ServerIceConfig, SignalDelivery,
};
use nethernet::identity::{ServerIdentity, TokenVerifier};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
enum Answer {
    Missing,
    Signed,
    InvalidPresent,
}

/// A configured provider cannot bless a fixture token; self-signed server answers verify their own key.
struct RefuseProvider;

impl TokenVerifier for RefuseProvider {
    fn verify(
        &self,
        _: &str,
        _: SystemTime,
    ) -> nethernet::identity::error::Result<nethernet::identity::jwt::Claims> {
        Err(nethernet::identity::error::IdentityError::Untrusted(
            "fixture provider refuses tokens".into(),
        ))
    }
}

/// A service's missing answer identity may be explicitly allowed while retaining configured trust.
#[tokio::test]
async fn explicit_anonymous_answer_policy_establishes_actual_owned_peer() {
    assert!(
        association(Answer::Missing, true).await.is_ok(),
        "explicit service answer policy rejected a genuinely absent identity"
    );
}

/// Default client admission continues refusing a genuinely absent answer identity.
#[tokio::test]
async fn default_answer_policy_refuses_actual_unsigned_peer() {
    assert!(matches!(
        association(Answer::Missing, false).await,
        Err(NetherError::Identity(
            nethernet::identity::error::IdentityError::Missing
        ))
    ));
}

/// Explicit missing-only policy still authenticates the remote server's own signed key.
#[tokio::test]
async fn anonymous_answer_policy_validates_actual_present_signed_peer() {
    association(Answer::Signed, true).await.unwrap();
}

/// Missing-only policy cannot turn a present invalid assertion into an anonymous answer.
#[tokio::test]
async fn anonymous_answer_policy_refuses_actual_present_invalid_peer() {
    assert!(matches!(
        association(Answer::InvalidPresent, true).await,
        Err(NetherError::Identity(_))
    ));
}

/// Drives the original bounded caller bridges beside one real UDP/DTLS/SCTP association and cleanup.
async fn association(answer: Answer, allow: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let bind = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let signaling = CallerSignalingConfig {
            ice_mode: IceMode::Full,
            ..Default::default()
        };
        let (caller, mut client_service) = CallerSignaling::new("client".into(), "server".into(), signaling).unwrap();
        let (accepting, mut server_service) = CallerServerSignaling::new("server".into(), CallerServerSignalingConfig { signaling, ..Default::default() }).unwrap();
        let local_key = Arc::new(ServerIdentity::generate("client.fixture.invalid", SystemTime::now()).unwrap());
        let server_key = Arc::new(ServerIdentity::generate("server.fixture.invalid", SystemTime::now()).unwrap());
        let mut server = NetherServer::bind_with(accepting, ConnectionConfig {
            identity: if matches!(answer, Answer::Missing) { None } else { Some(server_key.clone()) },
            allow_unsigned_answers: matches!(answer, Answer::Missing),
            token_trust: Some(TokenTrust::Any),
            server_ice: Some(ServerIceConfig { turn_streams: Vec::new(), turn_tls: None, ice: Default::default(), bind_addr: bind }),
            max_sessions: 1,
            ..Default::default()
        }).await.unwrap();
        let stop = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(8);
        let application = async {
            let connected = NetherClient::connect_with(caller, "server".into(), ConnectionConfig {
                identity: Some(local_key),
                server_trust: Some(TokenTrust::ServerAnswer(Arc::new(RefuseProvider))),
                allow_anonymous_answers: allow,
                client_ice: Some(ClientIceConfig { turn_streams: Vec::new(), turn_tls: None, ice: Default::default(), bind_addr: Some(bind) }),
                ..Default::default()
            }).await;
            let result = match connected {
                Ok(mut client) => {
                    let expected = if matches!(answer, Answer::Missing) { None } else { Some(server_key.verifying_key()) };
                    assert_eq!(client.server_public_key(), expected, "the actual answer key did not survive the Ready handoff");
                    let accepted = server.accept().await;
                    match accepted {
                        Ok(mut peer) => {
                            let result = async {
                                client.send(Bytes::from_static(b"client-key secured data")).await?;
                                if peer.reliable.recv().await?.as_deref() != Some(b"client-key secured data".as_slice()) {
                                    return Err(NetherError::Other("original peer payload differed".into()));
                                }
                                peer.session.send(Bytes::from_static(b"server-key secured reply")).await?;
                                if client.recv().await?.as_deref() != Some(b"server-key secured reply".as_slice()) {
                                    return Err(NetherError::Other("original client payload differed".into()));
                                }
                                Ok(())
                            }.await;
                            let client = client.close();
                            let peer = peer.close();
                            tokio::join!(client.session.closed(), peer.session.closed());
                            result
                        }
                        Err(error) => {
                            let client = client.close();
                            client.session.closed().await;
                            Err(error)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            stop.cancel();
            server.close().await?;
            result
        };
        let relay = async {
            loop {
                tokio::select! { biased;
                    _ = stop.cancelled() => break,
                    request = client_service.recv() => {
                        let Some(request) = request else { break; };
                        let delivery = server_service.prepare_delivery_before("client", &request.signal().to_string(), deadline);
                        let result = match delivery { Ok(delivery) => delivery.await, Err(error) => Err(error) };
                        request.finish(result.map(|()| SignalDelivery::PeerReceived));
                    }
                    request = server_service.recv() => {
                        let Some(request) = request else { break; };
                        let mut signal = request.signal().clone();
                        if matches!(answer, Answer::InvalidPresent) && signal.signal_type == SignalType::Answer {
                            signal.data = signal.data.replace("a=identity:", "a=identity:malformed-");
                        }
                        let delivery = client_service.prepare_delivery_before("server", &signal.to_string(), deadline);
                        let result = match delivery { Ok(delivery) => delivery.await, Err(error) => Err(error) };
                        request.finish(result.map(|()| SignalDelivery::ServiceAccepted));
                    }
                }
            }
            client_service.close();
            server_service.close();
        };
        let (result, ()) = tokio::join!(application, relay);
        result
    }).await.expect("finite actual answer-policy association stalled")
}
