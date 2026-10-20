//! The public HTTP constructors carry caller receive policy through either accepting ICE path.

use super::*;
use nethernet_tokio::{ClientIceConfig, ServerIceConfig};

/// A configured body larger than the library default survives both original directions and teardown.
#[tokio::test]
async fn incoming_size_http_policy_reaches_host_only_and_configured_acceptors() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let maximum = 3 * 1024 * 1024;
        let payload = Bytes::from(vec![0x63; maximum]);
        for configured in [false, true] {
            let mut accepting = server_connection_config();
            accepting.max_incoming_message_bytes = maximum;
            let mut connecting = client_config();
            connecting.max_incoming_message_bytes = maximum;
            connecting.attempts = 1;
            if configured {
                accepting.server_ice = Some(ServerIceConfig {
                    bind_addr: "127.0.0.1:0".parse().unwrap(),
                    ice: Default::default(),
                    turn_streams: Vec::new(),
                    turn_tls: None,
                });
                connecting.client_ice = Some(ClientIceConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    ice: Default::default(),
                    turn_streams: Vec::new(),
                    turn_tls: None,
                });
            }
            let (url, mut listener) = serve_with_connection(server_config(), accepting).await;
            let signaling = HttpSignaling::new("incoming-policy-client".into()).unwrap();
            let (client, accepted) = tokio::join!(
                NetherClient::connect_with(signaling, url, connecting),
                listener.accept(),
            );
            let mut client = client.unwrap();
            let mut accepted = accepted.unwrap();
            let forward = client.send(payload.clone()).await;
            let received = accepted.reliable.recv().await;
            let reverse = accepted.session.send(payload.clone()).await;
            let returned = client.recv().await;
            let client_closed = client.sender().close().await;
            let server_closed = accepted.session.sender().close().await;
            let listener_closed = listener.close().await;
            drop((client.close(), accepted.close(), listener));

            assert!(client_closed.is_ok() && server_closed.is_ok() && listener_closed.is_ok());
            assert!(forward.is_ok() && reverse.is_ok());
            assert_eq!(received.unwrap(), Some(payload.clone()));
            assert_eq!(returned.unwrap(), Some(payload.clone()));
        }
    })
    .await
    .expect("the original configured HTTP peers did not complete their exchange and retirement");
}
