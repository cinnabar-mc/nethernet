use super::*;
use crate::http_server::NetherHttpServer;
use crate::outbound::tests::overflow_real_delivery;

/// The actual HTTP resource retains transport-accepted reliable data when its delivery budget fails.
#[test]
fn http_failure_retains_the_actual_bounded_transport_prefix() {
    let mut server = NetherHttpServer::bind("127.0.0.1:0".parse().unwrap(), |config| {
        config.token_trust = None;
    })
    .unwrap();
    server.set_identity(ServerIdentity::generate("fixture", SystemTime::now()).unwrap());
    let mut client = NetherHttpClient::new();
    client
        .connect(
            "2".into(),
            format!("http://{}", server.local_addr().unwrap()),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_connected() || server.sessions().next().is_none() {
        server.update();
        client.update();
        assert!(
            Instant::now() < deadline,
            "actual HTTP fixture did not establish"
        );
        std::thread::yield_now();
    }
    let session = server.sessions().next().unwrap().clone();
    let count = overflow_real_delivery(client.transport_mut().unwrap(), |payload| {
        if let Some(payload) = payload {
            server.send(&session, payload).unwrap();
        }
        server.update();
    });
    // Dispatch the real update error through this resource's existing retirement edge.
    client.fail_connection();
    assert!(!client.is_connected());
    for index in 0..count {
        assert_eq!(
            client.recv().as_deref(),
            Some((index as u32).to_be_bytes().as_slice()),
            "HTTP retirement discarded the already-accepted delivery prefix"
        );
    }
    assert!(client.recv().is_none());
    assert_eq!(
        std::iter::from_fn(|| client.next_event())
            .filter(|event| matches!(event, NetherHttpClientEvent::Disconnected))
            .count(),
        1
    );
}
