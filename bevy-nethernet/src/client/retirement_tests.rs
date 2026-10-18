use super::*;
use crate::outbound::tests::overflow_real_delivery;
use crate::server::NetherServer;

/// The actual LAN resource retains transport-accepted reliable data when its delivery budget fails.
#[test]
fn lan_failure_retains_the_actual_bounded_transport_prefix() {
    let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
    server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
    let mut client = NetherClient::new(2, |config| {
        config.broadcast_address = Some(server.local_addr().unwrap());
        config.broadcast_interval = Duration::from_millis(20);
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.discovered().contains_key(&1) {
        server.update();
        client.update();
        assert!(
            Instant::now() < deadline,
            "actual LAN fixture was not discovered"
        );
        std::thread::yield_now();
    }
    client.connect(1).unwrap();
    while !client.is_connected() || server.sessions().next().is_none() {
        server.update();
        client.update();
        assert!(
            Instant::now() < deadline,
            "actual LAN fixture did not establish"
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
            "LAN retirement discarded the already-accepted delivery prefix"
        );
    }
    assert!(client.recv().is_none());
    assert_eq!(
        std::iter::from_fn(|| client.next_event())
            .filter(|event| matches!(event, NetherClientEvent::Disconnected))
            .count(),
        1
    );
}

/// A failed promotion into the full application queue retains the message in its original transport owner.
#[test]
fn lan_failure_retains_the_message_rejected_by_a_full_application_owner() {
    use crate::outbound::tests::{accepted_primary_messages, application_message_capacity};
    let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
    server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
    let mut client = NetherClient::new(2, |config| {
        config.broadcast_address = Some(server.local_addr().unwrap());
        config.broadcast_interval = Duration::from_millis(20);
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !client.discovered().contains_key(&1) {
        server.update();
        client.update();
        assert!(
            Instant::now() < deadline,
            "actual LAN fixture was not discovered"
        );
        std::thread::yield_now();
    }
    client.connect(1).unwrap();
    while !client.is_connected() || server.sessions().next().is_none() {
        server.update();
        client.update();
        assert!(
            Instant::now() < deadline,
            "actual LAN fixture did not establish"
        );
        std::thread::yield_now();
    }
    let session = server.sessions().next().unwrap().clone();
    let capacity = application_message_capacity();
    for index in 0..=capacity {
        server
            .send(&session, &(index as u32).to_be_bytes())
            .unwrap();
        while client.is_connected()
            && accepted_primary_messages(&client.established.as_ref().unwrap().received) <= index
        {
            server.update();
            client.update();
            assert!(
                Instant::now() < deadline,
                "actual LAN application delivery stalled"
            );
            std::thread::yield_now();
        }
        if index < capacity {
            assert!(
                client.is_connected(),
                "the existing application budget failed before filling"
            );
            assert_eq!(
                accepted_primary_messages(&client.established.as_ref().unwrap().received),
                index + 1
            );
        }
    }
    assert!(!client.is_connected());
    for index in 0..=capacity {
        assert_eq!(
            client.recv().as_deref(),
            Some((index as u32).to_be_bytes().as_slice()),
            "application overflow discarded the message accepted by the original transport owner"
        );
    }
    assert!(client.recv().is_none());
    assert_eq!(
        std::iter::from_fn(|| client.next_event())
            .filter(|event| matches!(event, NetherClientEvent::Disconnected))
            .count(),
        1
    );
}
