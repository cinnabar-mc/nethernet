use super::*;
#[path = "../../../nethernet/tests/support/turn.rs"]
pub(super) mod turn;
use nethernet::protocol::SignalType;
use nethernet::protocol::webrtc::candidate::parse_ice_candidate;
use nethernet::session::{IcePolicy, IceServer};
use rtc::ice::candidate::CandidateType;
use std::net::Ipv4Addr;
use turn::{PASSWORD, TurnPeer, USER};

/// Drives the original finite TURN peer through an actual nonblocking loopback socket.
fn turn_update(socket: &UdpSocket, server: &mut TurnPeer) {
    let mut buffer = [0; 65536];
    for _ in 0..1024 {
        match socket.recv_from(&mut buffer) {
            Ok((size, from)) => server.receive(from, buffer[..size].to_vec()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("TURN receive failed: {error}"),
        }
    }
    while let Some((to, data)) = server.packets.pop_front() {
        socket.send_to(&data, to).unwrap();
    }
}

/// Preserves actual Ready/data/failure outputs while advancing one frame owner.
pub(super) fn advance(
    transport: &mut Outbound,
    now: Instant,
    ready: &mut bool,
    messages: &mut Vec<(Channel, Box<[u8]>)>,
) {
    transport.update(now).unwrap();
    while let Some(event) = transport.poll_event() {
        match event {
            ConnectionEvent::Ready(_) => *ready = true,
            ConnectionEvent::Message(channel, data) => messages.push((channel, data)),
            ConnectionEvent::Failed => panic!("secured frame transport failed"),
            ConnectionEvent::Rtt(_) => {}
        }
    }
}

#[test]
fn frame_driven_relay_pairs_exchange_secured_data_and_release_exclusive_allocations() {
    for mode in [IceMode::Full, IceMode::Trickle] {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut server = TurnPeer::new(socket.local_addr().unwrap());
        let mut now = Instant::now();
        let establish_within = Duration::from_secs(10);
        let deadline = now + establish_within;
        let config = ClientIceConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            turn_streams: Vec::new(),
            #[cfg(feature = "tls")]
            turn_tls: None,
            ice: IceConfig {
                servers: vec![IceServer::Turn(
                    server.addr,
                    TurnCredentials::new(
                        USER.into(),
                        PASSWORD.into(),
                        now + Duration::from_secs(1200),
                    )
                    .unwrap(),
                )],
                policy: IcePolicy::RelayOnly,
                ..Default::default()
            },
        };
        let mut client =
            Outbound::new(Some(&config), establish_within, now, &ClientTls::default()).unwrap();
        let mut answerer =
            Outbound::new(Some(&config), establish_within, now, &ClientTls::default()).unwrap();
        assert_ne!(
            client.socket.local_addr().unwrap(),
            answerer.socket.local_addr().unwrap()
        );
        // Install the controlled role before either owner's first socket poll.
        let (session, description) = Session::new_with_ice(
            answerer.socket.local_addr().unwrap(),
            false,
            rand::random(),
            config.ice.clone(),
            now,
        )
        .unwrap();
        *answerer.state.get() = Some(State::Gathering(session, description));
        if mode == IceMode::Full {
            for _ in 0..1000 {
                client.update(now).unwrap();
                answerer.update(now).unwrap();
                turn_update(&socket, &mut server);
                if client.gathering_complete() && answerer.gathering_complete() {
                    break;
                }
                now += Duration::from_millis(5);
            }
            assert!(client.gathering_complete() && answerer.gathering_complete());
        }
        let mut signals = client.connect(7, "peer".into(), mode).unwrap().into_iter();
        let offer = signals.next().unwrap();
        let (remote, candidates) = Connection::parse_offer(&offer).unwrap();
        assert_eq!(candidates.len(), usize::from(mode == IceMode::Full));
        for candidate in &candidates {
            assert_eq!(candidate.candidate_type(), CandidateType::Relay);
        }
        let Some(State::Gathering(session, description)) = answerer.state.get().take() else {
            panic!("answerer already connected")
        };
        let (connection, answers) =
            Connection::accept(session, description, &offer, remote, candidates, mode, now)
                .unwrap();
        *answerer.state.get() = Some(State::Connected(ActiveConnection::new(connection)));
        for signal in answers {
            client.signal(signal, now).unwrap();
        }
        for signal in signals {
            answerer.signal(signal, now).unwrap();
        }
        let (mut client_ready, mut answerer_ready) = (false, false);
        let (mut client_messages, mut answerer_messages) = (Vec::new(), Vec::new());
        let mut late_candidates = 0;
        for _ in 0..5000 {
            turn_update(&socket, &mut server);
            advance(&mut client, now, &mut client_ready, &mut client_messages);
            advance(
                &mut answerer,
                now,
                &mut answerer_ready,
                &mut answerer_messages,
            );
            while let Some(signal) = client.poll_local_signal() {
                assert_eq!(signal.signal_type, SignalType::Candidate);
                assert_eq!(
                    parse_ice_candidate(&signal.data).unwrap().candidate_type(),
                    CandidateType::Relay
                );
                late_candidates += 1;
                answerer.signal(signal, now).unwrap();
            }
            while let Some(signal) = answerer.poll_local_signal() {
                late_candidates += 1;
                client.signal(signal, now).unwrap();
            }
            if client_ready && answerer_ready {
                break;
            }
            now += Duration::from_millis(5);
        }
        assert!(client_ready && answerer_ready);
        assert_eq!(
            late_candidates,
            if mode == IceMode::Trickle { 2 } else { 0 }
        );
        assert_eq!(server.allocation_count(), 2);
        let large = vec![0x51; 50 * 1024];
        client.send(Channel::Reliable, &large, now).unwrap();
        answerer.send(Channel::Unreliable, b"reverse", now).unwrap();
        for _ in 0..1000 {
            turn_update(&socket, &mut server);
            advance(&mut client, now, &mut client_ready, &mut client_messages);
            advance(
                &mut answerer,
                now,
                &mut answerer_ready,
                &mut answerer_messages,
            );
            if !client_messages.is_empty() && !answerer_messages.is_empty() {
                break;
            }
            now += Duration::from_millis(5);
        }
        assert_eq!(
            answerer_messages,
            vec![(Channel::Reliable, large.into_boxed_slice())]
        );
        assert_eq!(
            client_messages,
            vec![(Channel::Unreliable, Box::from(&b"reverse"[..]))]
        );
        assert!(server.indications > 0);
        client.close(now);
        // A nonblocking read may precede kernel delivery; keep the original finite budget.
        while server.allocation_count() > 1 && Instant::now() < deadline {
            turn_update(&socket, &mut server);
            std::thread::yield_now();
        }
        assert_eq!(
            server.allocation_count(),
            1,
            "closing one exclusive tuple removed another allocation"
        );
        assert!(client.poll_event().is_none() && client.poll_local_signal().is_none());
        assert!(client.send(Channel::Reliable, b"late", now).is_err());
        answerer.close(now);
        while server.allocation_count() > 0 && Instant::now() < deadline {
            turn_update(&socket, &mut server);
            std::thread::yield_now();
        }
        assert_eq!(server.allocation_count(), 0);
    }
}

#[test]
fn absolute_credential_expiry_stops_frame_gathering_and_delivery_bounds_count_bytes() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut server = TurnPeer::new(socket.local_addr().unwrap());
    let start = Instant::now();
    let expiry = start + Duration::from_secs(2);
    let config = ClientIceConfig {
        bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        turn_streams: Vec::new(),
        #[cfg(feature = "tls")]
        turn_tls: None,
        ice: IceConfig {
            servers: vec![IceServer::Turn(
                server.addr,
                TurnCredentials::new(USER.into(), PASSWORD.into(), expiry).unwrap(),
            )],
            policy: IcePolicy::RelayOnly,
            ..Default::default()
        },
    };
    let mut transport = Outbound::new(
        Some(&config),
        Duration::from_secs(10),
        start,
        &ClientTls::default(),
    )
    .unwrap();
    while Instant::now() < expiry {
        transport.update(Instant::now()).unwrap();
        turn_update(&socket, &mut server);
        if transport.gathering_complete() {
            break;
        }
        std::thread::yield_now();
    }
    assert!(transport.gathering_complete());
    let offers = transport.connect(1, "peer".into(), IceMode::Full).unwrap();
    let (_, candidates) = Connection::parse_offer(&offers[0]).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].candidate_type(), CandidateType::Relay);
    transport.update(expiry).unwrap();
    assert!(
        transport
            .update_turn_credentials(
                server.addr,
                TurnCredentials::new(
                    USER.into(),
                    PASSWORD.into(),
                    expiry + Duration::from_secs(60)
                )
                .unwrap(),
                expiry
            )
            .is_err(),
        "renewal revived an expired allocation"
    );
    assert!(
        transport
            .send(Channel::Reliable, b"expired", expiry)
            .is_err()
    );
    turn_update(&socket, &mut server);
    assert_eq!(
        server.refreshes, 0,
        "expired credentials were used to sign maintenance"
    );
    let mut received = Received::default();
    received
        .push(
            Channel::Reliable,
            vec![1; MAX_RECEIVED_BYTES].into_boxed_slice(),
        )
        .unwrap();
    assert!(
        received
            .push(Channel::Unreliable, Box::from(&b"x"[..]))
            .is_err()
    );
    assert_eq!(
        received.pop(Channel::Reliable).unwrap().len(),
        MAX_RECEIVED_BYTES
    );
    received
        .push(Channel::Unreliable, Box::from(&b"x"[..]))
        .unwrap();
    assert_eq!(
        received.pop(Channel::Unreliable).as_deref(),
        Some(&b"x"[..])
    );
}

/// Fills the existing delivery budget with actual reliable peer data, without draining the frame edge.
/// The callback sends one payload when supplied and advances the original peer on every call.
pub(crate) fn overflow_real_delivery(
    transport: &mut Outbound,
    mut peer: impl FnMut(Option<&[u8]>),
) -> usize {
    let deadline = Instant::now() + Duration::from_secs(30);
    for index in 0..=MAX_RECEIVED_MESSAGES {
        let payload = (index as u32).to_be_bytes();
        peer(Some(&payload));
        loop {
            peer(None);
            if let Err(error) = transport.update(Instant::now()) {
                assert_eq!(error.to_string(), "client receive limit reached");
                let accepted = transport
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        ConnectionEvent::Message(Channel::Reliable, data) => Some(data.as_ref()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !accepted.is_empty(),
                    "the actual peer produced no accepted prefix before overflow"
                );
                for (index, payload) in accepted.iter().enumerate() {
                    assert_eq!(*payload, &(index as u32).to_be_bytes());
                }
                return accepted.len();
            }
            let accepted = transport
                .events
                .iter()
                .filter(|event| matches!(event, ConnectionEvent::Message(Channel::Reliable, _)))
                .count();
            if accepted > index {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "actual peer delivery stalled before its bounded overflow"
            );
            std::thread::yield_now();
        }
    }
    panic!("the real peer did not exhaust the existing bounded delivery owner");
}

/// Reads the existing application budget rather than repeating it in owning-edge witnesses.
pub(crate) fn application_message_capacity() -> usize {
    MAX_RECEIVED_MESSAGES
}

/// Observes actual primary ownership while a resource intentionally defers application reads.
pub(crate) fn accepted_primary_messages(received: &Received) -> usize {
    received.reliable.len() + received.unreliable.len()
}
