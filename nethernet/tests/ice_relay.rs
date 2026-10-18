//! Finite, original STUN/TURN transport witnesses; no live server or game fixture is used.
#[path = "support/turn.rs"]
mod turn;
use nethernet::error::ProtocolError;
use nethernet::protocol::webrtc::Description;
use nethernet::sans::Sans;
use nethernet::session::{
    Channel, GatheringState, IceConfig, IceError, IcePolicy, IceServer, Session, SessionEvent,
    SessionInput, SessionOutput, TurnCredentials,
};
use rtc::ice::candidate::CandidateType;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use turn::{PASSWORD, TurnPeer, USER};

fn addr(v6: bool, port: u16) -> SocketAddr {
    SocketAddr::new(
        if v6 {
            Ipv6Addr::LOCALHOST.into()
        } else {
            Ipv4Addr::LOCALHOST.into()
        },
        port,
    )
}

fn config(server: SocketAddr, now: Instant, policy: IcePolicy) -> IceConfig {
    IceConfig {
        servers: vec![IceServer::Turn(
            server,
            TurnCredentials::new(
                USER.to_string(),
                PASSWORD.to_string(),
                now + Duration::from_secs(1200),
            )
            .unwrap(),
        )],
        policy,
        ..Default::default()
    }
}

struct Endpoint {
    local: SocketAddr,
    session: Session,
    ready: bool,
    received: Vec<(Channel, Vec<u8>)>,
}

impl Endpoint {
    /// Routes every send to the test TURN server, rejecting any unintended direct fallback.
    fn drain(&mut self, server: &mut TurnPeer) -> bool {
        let mut progressed = false;
        while let Some(output) = self.session.poll() {
            match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, server.addr, "relay-only traffic escaped the TURN path");
                    server.receive(self.local, data);
                    progressed = true;
                }
                SessionOutput::Event(SessionEvent::Ready) => {
                    self.ready = true;
                    progressed = true;
                }
                SessionOutput::Event(SessionEvent::Failed) => panic!("relayed session failed"),
                SessionOutput::Message(channel, data) => {
                    self.received.push((channel, data));
                    progressed = true;
                }
                SessionOutput::Wait(_) => {}
            }
        }
        progressed
    }
}

/// Advances only caller-owned monotonic time and finite packet queues.
fn step(endpoints: &mut [Endpoint; 2], server: &mut TurnPeer, now: &mut Instant) {
    let mut progressed = false;
    for endpoint in &mut *endpoints {
        progressed |= endpoint.drain(server);
    }
    while let Some((to, data)) = server.packets.pop_front() {
        let endpoint = endpoints
            .iter_mut()
            .find(|endpoint| endpoint.local == to)
            .unwrap();
        endpoint
            .session
            .handle(SessionInput::Packet(data.into(), server.addr, *now))
            .unwrap();
        progressed = true;
    }
    if !progressed {
        *now += Duration::from_millis(10);
        for endpoint in endpoints {
            endpoint
                .session
                .handle(SessionInput::Timeout(*now))
                .unwrap();
        }
    }
}

/// Completes gathering and applies full descriptions before the actual secured transport handshake.
fn pair(v6: bool) -> ([Endpoint; 2], TurnPeer, Instant) {
    let mut now = Instant::now();
    let mut server = TurnPeer::new(addr(v6, 3478));
    let (a, a_description) = Session::new_with_ice(
        addr(v6, 41000),
        true,
        1,
        config(server.addr, now, IcePolicy::RelayOnly),
        now,
    )
    .unwrap();
    let (b, b_description) = Session::new_with_ice(
        addr(v6, 41001),
        false,
        2,
        config(server.addr, now, IcePolicy::RelayOnly),
        now,
    )
    .unwrap();
    let mut endpoints = [
        Endpoint {
            local: addr(v6, 41000),
            session: a,
            ready: false,
            received: Vec::new(),
        },
        Endpoint {
            local: addr(v6, 41001),
            session: b,
            ready: false,
            received: Vec::new(),
        },
    ];
    for _ in 0..100 {
        step(&mut endpoints, &mut server, &mut now);
        if endpoints
            .iter()
            .all(|endpoint| endpoint.session.gathering_state() == GatheringState::Complete)
        {
            break;
        }
    }
    for endpoint in &mut endpoints {
        assert_eq!(endpoint.session.gathering_state(), GatheringState::Complete);
        assert_eq!(endpoint.session.local_candidates().len(), 1);
        assert_eq!(
            endpoint.session.local_candidates()[0].candidate_type(),
            CandidateType::Relay
        );
        assert_eq!(
            endpoint
                .session
                .poll_local_candidate()
                .unwrap()
                .candidate_type(),
            CandidateType::Relay
        );
        assert!(endpoint.session.poll_local_candidate().is_none());
    }
    let (a_description, a_candidates) =
        Description::parse(&a_description.encode_full(endpoints[0].session.local_candidates()))
            .unwrap();
    let (b_description, b_candidates) =
        Description::parse(&b_description.encode_full(endpoints[1].session.local_candidates()))
            .unwrap();
    endpoints[0]
        .session
        .handle(SessionInput::RemoteDescription(
            b_description,
            b_candidates,
            now,
        ))
        .unwrap();
    endpoints[1]
        .session
        .handle(SessionInput::RemoteDescription(
            a_description,
            a_candidates,
            now,
        ))
        .unwrap();
    for _ in 0..3000 {
        step(&mut endpoints, &mut server, &mut now);
        if endpoints.iter().all(|endpoint| endpoint.ready) {
            break;
        }
    }
    assert!(
        endpoints.iter().all(|endpoint| endpoint.ready),
        "ICE/DTLS/SCTP did not complete through TURN"
    );
    (endpoints, server, now)
}

#[test]
fn relay_only_sessions_secure_and_exchange_both_channels_over_ipv4_and_ipv6_udp() {
    for v6 in [false, true] {
        let (mut endpoints, mut server, mut now) = pair(v6);
        let reliable = vec![0x5a; 50000];
        for endpoint in &mut endpoints {
            endpoint
                .session
                .handle(SessionInput::Send(
                    Channel::Reliable,
                    reliable.clone().into(),
                    now,
                ))
                .unwrap();
            endpoint
                .session
                .handle(SessionInput::Send(
                    Channel::Unreliable,
                    b"relayed".as_slice().into(),
                    now,
                ))
                .unwrap();
        }
        for _ in 0..3000 {
            step(&mut endpoints, &mut server, &mut now);
            if endpoints
                .iter()
                .all(|endpoint| endpoint.received.len() == 2)
            {
                break;
            }
        }
        for endpoint in &endpoints {
            assert!(
                endpoint
                    .received
                    .contains(&(Channel::Reliable, reliable.clone()))
            );
            assert!(
                endpoint
                    .received
                    .contains(&(Channel::Unreliable, b"relayed".to_vec()))
            );
        }
        assert!(
            server.indications > 0,
            "initial packets did not use Send indications"
        );
        assert!(
            server.channel_data > 0,
            "channel binding never became usable"
        );
        // Rotate authentication without replacing either selected allocation.
        for endpoint in &mut endpoints {
            endpoint
                .session
                .update_turn_credentials(
                    server.addr,
                    TurnCredentials::new(
                        USER.to_string(),
                        PASSWORD.to_string(),
                        now + Duration::from_secs(2400),
                    )
                    .unwrap(),
                    now,
                )
                .unwrap();
        }
        for _ in 0..20 {
            step(&mut endpoints, &mut server, &mut now);
        }
        assert!(server.refreshes >= 2);
        assert_eq!(server.allocation_count(), 2);
        for endpoint in &mut endpoints {
            endpoint.session.close(now).unwrap();
            endpoint.drain(&mut server);
            assert_eq!(endpoint.session.gathering_state(), GatheringState::Closed);
            endpoint
                .session
                .handle(SessionInput::Timeout(now + Duration::from_secs(3600)))
                .unwrap();
            assert!(endpoint.session.poll().is_none());
        }
        assert_eq!(server.allocation_count(), 0);
    }
}

#[test]
fn gathering_has_a_deadline_and_rejects_wrong_source_or_corrupt_authenticated_success() {
    let start = Instant::now();
    let server_addr = addr(false, 3478);
    let (mut unreachable, _) = Session::new_with_ice(
        addr(false, 42000),
        true,
        1,
        IceConfig {
            servers: vec![IceServer::Stun(server_addr)],
            gather_timeout: Duration::from_secs(2),
            ..Default::default()
        },
        start,
    )
    .unwrap();
    while unreachable.poll().is_some() {}
    unreachable
        .handle(SessionInput::Timeout(start + Duration::from_secs(2)))
        .unwrap();
    assert_eq!(unreachable.gathering_state(), GatheringState::Complete);
    assert_eq!(unreachable.local_candidates().len(), 1);
    unreachable.close(start + Duration::from_secs(2)).unwrap();
    unreachable
        .handle(SessionInput::Timeout(start + Duration::from_secs(500)))
        .unwrap();
    assert!(unreachable.poll().is_none());

    let mut server = TurnPeer::new(server_addr);
    let local = addr(false, 42001);
    let (mut session, _) = Session::new_with_ice(
        local,
        true,
        2,
        config(server_addr, start, IcePolicy::RelayOnly),
        start,
    )
    .unwrap();
    // Complete Binding and the unauthenticated allocation challenge.
    for _ in 0..2 {
        while let Some(output) = session.poll() {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, server_addr);
                server.receive(local, data);
            }
        }
        let packets: Vec<_> = server.packets.drain(..).collect();
        for (_, packet) in packets {
            let mut message = rtc::stun::message::Message::new();
            message.raw = packet.clone();
            message.decode().unwrap();
            if message.typ.method == rtc::stun::message::METHOD_ALLOCATE
                && message.typ.class == rtc::stun::message::CLASS_SUCCESS_RESPONSE
            {
                let mut corrupt = packet.clone();
                let end = corrupt.len();
                corrupt[end - 9] ^= 1;
                session
                    .handle(SessionInput::Packet(corrupt.into(), server_addr, start))
                    .unwrap();
                assert!(session.local_candidates().is_empty());
                // A response with the real transaction id from a different endpoint cannot allocate a route.
                let _ = session.handle(SessionInput::Packet(
                    packet.clone().into(),
                    addr(false, 3479),
                    start,
                ));
                assert!(session.local_candidates().is_empty());
            }
            session
                .handle(SessionInput::Packet(packet.into(), server_addr, start))
                .unwrap();
        }
    }
    assert_eq!(session.gathering_state(), GatheringState::Complete);
    assert_eq!(session.local_candidates().len(), 1);
    // Credential expiry retires the allocation even before a remote peer is supplied.
    session
        .handle(SessionInput::Timeout(start + Duration::from_secs(1200)))
        .unwrap();
    session.close(start + Duration::from_secs(1200)).unwrap();
    assert!(session.poll().is_none());
}

#[test]
fn resolved_server_bounds_and_credential_expiry_fail_before_gathering() {
    let now = Instant::now();
    let stale = TurnCredentials::new(USER.to_string(), PASSWORD.to_string(), now).unwrap();
    assert!(matches!(
        Session::new_with_ice(
            addr(false, 43000),
            true,
            1,
            IceConfig {
                servers: vec![IceServer::Turn(addr(false, 3478), stale)],
                ..Default::default()
            },
            now
        ),
        Err(ProtocolError::Ice(IceError::Credentials))
    ));
    let duplicates = IceConfig {
        servers: vec![IceServer::Stun(addr(false, 3478)); 2],
        ..Default::default()
    };
    assert!(matches!(
        Session::new_with_ice(addr(false, 43000), true, 1, duplicates, now),
        Err(ProtocolError::Ice(IceError::Configuration))
    ));
    let too_many = IceConfig {
        servers: (0..9)
            .map(|index| IceServer::Stun(addr(false, 3478 + index)))
            .collect(),
        ..Default::default()
    };
    assert!(matches!(
        Session::new_with_ice(addr(false, 43000), true, 1, too_many, now),
        Err(ProtocolError::Ice(IceError::Configuration))
    ));
    assert!(matches!(
        Session::new_with_ice(
            addr(false, 43000),
            true,
            1,
            config(addr(true, 3478), now, IcePolicy::All),
            now
        ),
        Err(ProtocolError::Ice(IceError::Configuration))
    ));
}

/// Drains a single session without a remote peer, retaining allocation lifetime as the only active transport work.
fn drive_gatherer(session: &mut Session, local: SocketAddr, server: &mut TurnPeer, now: Instant) {
    for _ in 0..20 {
        let mut progressed = false;
        while let Some(output) = session.poll() {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, server.addr);
                server.receive(local, data);
                progressed = true;
            }
        }
        while let Some((to, data)) = server.packets.pop_front() {
            assert_eq!(to, local);
            session
                .handle(SessionInput::Packet(data.into(), server.addr, now))
                .unwrap();
            progressed = true;
        }
        if !progressed {
            return;
        }
    }
    panic!("gatherer did not drain its finite work");
}

#[test]
fn allocation_refresh_and_expiry_are_driven_without_a_remote_peer() {
    let start = Instant::now();
    let local = addr(false, 44000);
    let mut server = TurnPeer::new(addr(false, 3478));
    let (mut session, _) = Session::new_with_ice(
        local,
        true,
        1,
        config(server.addr, start, IcePolicy::All),
        start,
    )
    .unwrap();
    drive_gatherer(&mut session, local, &mut server, start);
    assert_eq!(session.gathering_state(), GatheringState::Complete);
    assert_eq!(session.local_candidates().len(), 3);
    assert!(
        session
            .local_candidates()
            .iter()
            .any(|candidate| candidate.candidate_type() == CandidateType::ServerReflexive)
    );
    let refreshed = start + Duration::from_secs(301);
    session.handle(SessionInput::Timeout(refreshed)).unwrap();
    drive_gatherer(&mut session, local, &mut server, refreshed);
    assert_eq!(server.refreshes, 1);
    assert_eq!(server.allocation_count(), 1);
    assert!(
        session
            .local_candidates()
            .iter()
            .any(|candidate| candidate.candidate_type() == CandidateType::Relay)
    );
    // No more responses are supplied; the renewed lifetime ends at start + 901 seconds.
    let expired = start + Duration::from_secs(902);
    session.handle(SessionInput::Timeout(expired)).unwrap();
    assert!(
        session
            .local_candidates()
            .iter()
            .all(|candidate| candidate.candidate_type() != CandidateType::Relay)
    );
    session.close(expired).unwrap();
    session
        .handle(SessionInput::Timeout(expired + Duration::from_secs(1000)))
        .unwrap();
    assert!(session.poll().is_none());
}

#[test]
fn unanswered_permissions_reach_a_finite_pending_data_limit() {
    use rtc::ice::candidate::{CandidateConfig, candidate_host::CandidateHostConfig};
    let mut now = Instant::now();
    let local = addr(false, 45000);
    let mut server = TurnPeer::new(addr(false, 3478));
    let (mut session, _) = Session::new_with_ice(
        local,
        true,
        1,
        config(server.addr, now, IcePolicy::RelayOnly),
        now,
    )
    .unwrap();
    drive_gatherer(&mut session, local, &mut server, now);
    server.drop_permissions = true;
    let (_, remote) = Session::new(addr(false, 45001), false, 2, now).unwrap();
    let candidates = (0..64)
        .map(|index| {
            CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_string(),
                    address: Ipv4Addr::LOCALHOST.to_string(),
                    port: 46000 + index,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap()
        })
        .collect();
    session
        .handle(SessionInput::RemoteDescription(remote, candidates, now))
        .unwrap();
    let mut bounded = false;
    for _ in 0..100 {
        drive_gatherer(&mut session, local, &mut server, now);
        now += Duration::from_millis(100);
        match session.handle(SessionInput::Timeout(now)) {
            Err(ProtocolError::Ice(IceError::PendingLimit)) => {
                bounded = true;
                break;
            }
            result => result.unwrap(),
        }
    }
    assert!(
        bounded,
        "unanswered permissions never reached the advertised pending-data cap"
    );
    session.close(now).unwrap();
    drive_gatherer(&mut session, local, &mut server, now);
    assert_eq!(server.allocation_count(), 0);
    session
        .handle(SessionInput::Timeout(now + Duration::from_secs(1000)))
        .unwrap();
    assert!(session.poll().is_none());
}

#[test]
fn a_connection_trickles_candidates_gathered_after_the_initial_offer_once() {
    use nethernet::connection::{Connection, ConnectionInput, IceMode};
    use nethernet::protocol::SignalType;
    let now = Instant::now();
    let local = addr(false, 47000);
    let mut server = TurnPeer::new(addr(false, 3478));
    let (session, description) = Session::new_with_ice(
        local,
        true,
        1,
        IceConfig {
            servers: vec![IceServer::Stun(server.addr)],
            ..Default::default()
        },
        now,
    )
    .unwrap();
    let (mut connection, initial) = Connection::connect(
        session,
        description,
        7,
        "peer".to_string(),
        IceMode::Trickle,
    );
    assert_eq!(initial.len(), 2);
    assert!(connection.poll_local_signal().is_none());
    while let Some(output) = connection.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, server.addr);
            server.receive(local, data);
        }
    }
    while let Some((to, data)) = server.packets.pop_front() {
        assert_eq!(to, local);
        connection
            .handle(ConnectionInput::Packet(data.into(), server.addr, now))
            .unwrap();
    }
    let candidate = connection
        .poll_local_signal()
        .expect("STUN candidate was never exposed for trickling");
    assert_eq!(candidate.signal_type, SignalType::Candidate);
    let candidate =
        nethernet::protocol::webrtc::candidate::parse_ice_candidate(&candidate.data).unwrap();
    assert_eq!(candidate.candidate_type(), CandidateType::ServerReflexive);
    assert!(connection.poll_local_signal().is_none());
    connection.close(now).unwrap();
}
