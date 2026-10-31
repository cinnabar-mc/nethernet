use super::*;
#[path = "../../../tests/support/turn.rs"]
mod turn;

/// Delivers finite TURN transactions without advancing the caller's clock.
fn exchange(
    server: &mut Server,
    peer: &mut turn::TurnPeer,
    local: SocketAddr,
    now: Instant,
) -> Vec<SocketAddr> {
    let mut destinations = Vec::new();
    for _ in 0..20 {
        let mut progressed = false;
        while let Some(packet) = server.poll_write().unwrap() {
            let mut message = Message::new();
            if message.unmarshal_binary(&packet.message).is_ok()
                && message.typ.method == rtc::stun::message::METHOD_SEND
            {
                let mut destination = PeerAddress::default();
                destination.get_from(&message).unwrap();
                destinations.push(SocketAddr::new(destination.ip, destination.port));
            }
            peer.receive(local, packet.message.to_vec());
            progressed = true;
        }
        while let Some((to, bytes)) = peer.packets.pop_front() {
            assert_eq!(to, local);
            server
                .handle_read(TaggedBytesMut {
                    now,
                    transport: context(local, peer.addr),
                    message: BytesMut::from(bytes.as_slice()),
                })
                .unwrap();
            progressed = true;
        }
        if !progressed {
            return destinations;
        }
    }
    panic!("TURN transactions did not quiesce");
}

#[test]
fn a_permission_is_shared_by_peer_ports_and_flushes_original_destinations() {
    for stream in [false, true] {
        let now = Instant::now();
        let local = "127.0.0.1:48100".parse().unwrap();
        let mut peer = turn::TurnPeer::new("127.0.0.1:3478".parse().unwrap());
        let credentials = TurnCredentials::new(
            turn::USER.into(),
            turn::PASSWORD.into(),
            now + Duration::from_secs(600),
        )
        .unwrap();
        let id = TurnStreamId::new(0).unwrap();
        let config = if stream {
            IceServer::TurnStream {
                id,
                remote: peer.addr,
                credentials,
                requested_family: None,
            }
        } else {
            IceServer::Turn(peer.addr, credentials)
        };
        let mut server = Server::new(local, config, now).unwrap();
        if stream {
            server
                .activate(id, TurnStreamRoute::new(local, peer.addr).unwrap(), now)
                .unwrap();
        }
        exchange(&mut server, &mut peer, local, now);
        assert!(server.relay.is_some());
        let first: SocketAddr = "203.0.113.10:40000".parse().unwrap();
        let second: SocketAddr = "203.0.113.10:40001".parse().unwrap();
        for destination in [first, second] {
            server
                .send(TaggedBytesMut {
                    now,
                    transport: context(server.relay.unwrap(), destination),
                    message: BytesMut::from(&b"queued"[..]),
                })
                .unwrap();
        }
        let destinations = exchange(&mut server, &mut peer, local, now);
        assert_eq!(destinations, [first, second]);
        assert_eq!(server.permissions.len(), 1);
        assert!(server.pending.is_empty());
        peer.drop_permissions = true;
        server
            .send(TaggedBytesMut {
                now,
                transport: context(server.relay.unwrap(), second),
                message: BytesMut::from(&b"immediate"[..]),
            })
            .unwrap();
        assert!(
            server.pending.is_empty(),
            "a live permission buffered a second port"
        );
        let packet = server
            .poll_write()
            .unwrap()
            .expect("no immediate carrier output");
        assert_eq!(
            packet.transport.transport_protocol,
            if stream {
                TransportProtocol::TCP
            } else {
                TransportProtocol::UDP
            }
        );
        let mut message = Message::new();
        message.unmarshal_binary(&packet.message).unwrap();
        assert_eq!(message.typ.method, rtc::stun::message::METHOD_SEND);
        let mut destination = PeerAddress::default();
        destination.get_from(&message).unwrap();
        assert_eq!(SocketAddr::new(destination.ip, destination.port), second);
        for packet in server.close(now) {
            peer.receive(local, packet.message.to_vec());
        }
        assert_eq!(peer.allocation_count(), 0);
    }
}
