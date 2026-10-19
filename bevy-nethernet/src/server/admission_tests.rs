use super::*;
use crate::client::NetherClient;
use nethernet::error::ProtocolError;
use nethernet::protocol::constants::MAX_MESSAGE_SIZE;

/// Real Ready capabilities report impossible message sizes before claiming local admission.
#[test]
fn established_server_refuses_oversized_messages_without_losing_valid_delivery() {
    let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
    server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
    let mut client = NetherClient::new(2, |config| {
        config.broadcast_address = Some(server.local_addr().unwrap());
        config.broadcast_interval = Duration::from_millis(20);
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut established = None;
    let observations = (|| {
        while Instant::now() < deadline && !client.discovered().contains_key(&1) {
            server.update();
            client.update();
            std::thread::yield_now();
        }
        if !client.discovered().contains_key(&1) {
            return Err("actual LAN discovery did not complete");
        }
        client.connect(1).unwrap();
        while Instant::now() < deadline
            && (!client.is_connected() || server.sessions().next().is_none())
        {
            server.update();
            client.update();
            std::thread::yield_now();
        }
        let Some(session) = server.sessions().next().cloned() else {
            return Err("the original server never produced Ready");
        };
        established = Some(session.clone());
        server.send(&session, b"baseline").unwrap();
        let mut baseline = None;
        while Instant::now() < deadline && baseline.is_none() {
            server.update();
            client.update();
            baseline = client.recv();
            std::thread::yield_now();
        }
        if baseline.as_deref() != Some(&b"baseline"[..]) {
            return Err("the original established path did not deliver its baseline");
        }

        let reliable_size = MAX_MESSAGE_SIZE * usize::from(u8::MAX) + 1;
        let reliable = server.send(&session, &vec![0x51; reliable_size]);
        let unreliable = server.send_unreliable(&session, &vec![0x72; MAX_MESSAGE_SIZE]);
        server.send(&session, b"after refusal").unwrap();
        let mut delivered = None;
        while Instant::now() < deadline && delivered.is_none() {
            server.update();
            client.update();
            delivered = client.recv();
            std::thread::yield_now();
        }
        Ok((reliable_size, reliable, unreliable, delivered))
    })();

    client.disconnect();
    if let Some(session) = established {
        server.disconnect(session);
    }
    server.pool.retire_worker();
    drop(client);
    drop(server);

    let (reliable_size, reliable, unreliable, delivered) = observations.unwrap();
    assert_eq!(delivered.as_deref(), Some(&b"after refusal"[..]));
    assert!(
        matches!(reliable, Err(ProtocolError::MessageSizeExceeded(size)) if size == reliable_size),
        "an oversized reliable message falsely reported local admission"
    );
    assert!(
        matches!(
            unreliable,
            Err(ProtocolError::MessageSizeExceeded(MAX_MESSAGE_SIZE))
        ),
        "an oversized unreliable message falsely reported local admission"
    );
}
