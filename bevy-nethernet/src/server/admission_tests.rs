use super::*;
use crate::client::NetherClient;
use nethernet::error::ProtocolError;
use nethernet::protocol::constants::{DEFAULT_MAX_RECEIVED_BYTES, DEFAULT_PACKET_CHANNEL_CAPACITY};

const OFFERED_SCTP_MESSAGE_BYTES: u32 = 64;

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
    client.offered_sctp_maximum = Some(OFFERED_SCTP_MESSAGE_BYTES);
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

        let reliable_size = (OFFERED_SCTP_MESSAGE_BYTES as usize - 1) * usize::from(u8::MAX) + 1;
        let reliable = server.send(&session, &vec![0x51; reliable_size]);
        let unreliable =
            server.send_unreliable(&session, &vec![0x72; OFFERED_SCTP_MESSAGE_BYTES as usize]);
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
            Err(ProtocolError::MessageSizeExceeded(size)) if size == OFFERED_SCTP_MESSAGE_BYTES as usize
        ),
        "an oversized unreliable message falsely reported local admission"
    );
}

/// Stalling the real final consumer bounds retained data without killing another secured peer.
#[test]
fn stalled_server_receive_preserves_its_prefix_and_the_other_real_session() {
    let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
    server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
    server.set_session_limits(ServerLimits {
        max_sessions: 2,
        max_received_packets: 1,
        max_received_bytes: DEFAULT_MAX_RECEIVED_BYTES / DEFAULT_PACKET_CHANNEL_CAPACITY,
    });
    let mut clients: Vec<_> = (2..4)
        .map(|id| {
            NetherClient::new(id, |config| {
                config.broadcast_address = Some(server.local_addr().unwrap());
                config.broadcast_interval = Duration::from_millis(20);
            })
            .unwrap()
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let observations = (|| {
        while Instant::now() < deadline
            && clients
                .iter()
                .any(|client| !client.discovered().contains_key(&1))
        {
            server.update();
            for client in &mut clients {
                client.update();
            }
            std::thread::yield_now();
        }
        if clients
            .iter()
            .any(|client| !client.discovered().contains_key(&1))
        {
            return Err("actual peers did not discover the server");
        }
        for client in &mut clients {
            client.connect(1).unwrap();
        }
        while Instant::now() < deadline
            && (server.sessions().count() != 2
                || clients.iter().any(|client| !client.is_connected()))
        {
            server.update();
            for client in &mut clients {
                client.update();
            }
            std::thread::yield_now();
        }
        let first = server
            .sessions()
            .find(|session| session.id().network_id == "2")
            .cloned();
        let second = server
            .sessions()
            .find(|session| session.id().network_id == "3")
            .cloned();
        let (Some(first), Some(second)) = (first, second) else {
            return Err("both original peers did not reach Ready");
        };
        while server.next_event().is_some() {}
        clients[0]
            .established()
            .unwrap()
            .send(b"accepted prefix")
            .unwrap();
        while Instant::now() < deadline && server.pool.retained_packets() != 1 {
            server.update();
            for client in &mut clients {
                client.update();
            }
            std::thread::yield_now();
        }
        if server.pool.retained_packets() != 1 {
            return Err("the actual final payload owner never filled");
        }
        clients[0]
            .established()
            .unwrap()
            .send(b"over budget")
            .unwrap();
        server.send(&second, b"healthy output").unwrap();
        let mut healthy_output = None;
        while Instant::now() < deadline
            && (server.sessions().count() != 1 || healthy_output.is_none())
        {
            server.update();
            for client in &mut clients {
                client.update();
            }
            if healthy_output.is_none() {
                healthy_output = clients[1].recv();
            }
            std::thread::yield_now();
        }
        let count = server.pool.retained_packets();
        let rejected_peer = server.send(&first, b"after retirement").is_err();
        let prefix = server.recv();
        let extra = server.recv();
        let terminals = std::iter::from_fn(|| server.next_event()).filter(|event| matches!(event, NetherServerEvent::SessionDisconnected(id) if id == first.id())).count();
        clients[1]
            .established()
            .unwrap()
            .send(b"healthy input")
            .unwrap();
        let mut healthy_input = None;
        while Instant::now() < deadline && healthy_input.is_none() {
            server.update();
            for client in &mut clients {
                client.update();
            }
            healthy_input = server.recv();
            std::thread::yield_now();
        }
        let mut command_full = false;
        for _ in 0..nethernet::protocol::constants::DEFAULT_PACKET_CHANNEL_CAPACITY {
            match server.send(&second, b"queued before retirement") {
                Ok(()) => {}
                Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    command_full = true;
                    break;
                }
                Err(_) => return Err("the original healthy peer failed before command pressure"),
            }
        }
        server.disconnect(second.clone());
        while Instant::now() < deadline && !server.pool.owner_has_finished(&second.readiness) {
            server.update();
            for client in &mut clients {
                client.update();
            }
            std::thread::yield_now();
        }
        let cleanup_finished = server.pool.owner_has_finished(&second.readiness);
        Ok((
            first.id().clone(),
            second.id().clone(),
            count,
            rejected_peer,
            prefix,
            extra,
            terminals,
            healthy_output,
            healthy_input,
            command_full,
            cleanup_finished,
        ))
    })();
    for client in &mut clients {
        client.disconnect();
    }
    let remaining: Vec<_> = server.sessions().cloned().collect();
    for session in remaining {
        server.disconnect(session);
    }
    server.pool.retire_worker();
    drop(clients);
    drop(server);

    let (
        first,
        second,
        count,
        rejected_peer,
        prefix,
        extra,
        terminals,
        healthy_output,
        healthy_input,
        command_full,
        cleanup_finished,
    ) = observations.unwrap();
    assert_eq!(count, 1);
    assert!(rejected_peer);
    assert_eq!(prefix, Some((first, Box::from(&b"accepted prefix"[..]))));
    assert!(
        extra.is_none(),
        "an over-budget payload entered a second retained queue"
    );
    assert_eq!(terminals, 1);
    assert_eq!(healthy_output.as_deref(), Some(&b"healthy output"[..]));
    assert_eq!(
        healthy_input,
        Some((second, Box::from(&b"healthy input"[..])))
    );
    assert!(
        command_full,
        "the actual bounded worker queue never applied admission pressure"
    );
    assert!(
        cleanup_finished,
        "a full data queue lost the original core retirement"
    );
}
