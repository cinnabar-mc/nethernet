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
use rtc::ice::candidate::{Candidate, CandidateType};
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
                SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                    panic!("relayed session failed")
                }
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
    progressed |= deliver_server_packets(endpoints, server, *now);
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

/// Delivers finite queued server responses without advancing caller time.
fn deliver_server_packets(
    endpoints: &mut [Endpoint; 2],
    server: &mut TurnPeer,
    now: Instant,
) -> bool {
    let mut progressed = false;
    while let Some((to, data)) = server.packets.pop_front() {
        let endpoint = endpoints
            .iter_mut()
            .find(|endpoint| endpoint.local == to)
            .unwrap();
        endpoint
            .session
            .handle(SessionInput::Packet(data.into(), server.addr, now))
            .unwrap();
        progressed = true;
    }
    progressed
}

/// Completes gathering and applies full descriptions before the actual secured transport handshake.
fn pair(v6: bool) -> ([Endpoint; 2], TurnPeer, Instant) {
    pair_with_candidates(v6, Vec::new(), false)
}

/// Keeps original full-SDP establishment while admitting independently unusable candidate paths.
fn pair_with_candidates(
    v6: bool,
    extra: Vec<Candidate>,
    refuse_extra: bool,
) -> ([Endpoint; 2], TurnPeer, Instant) {
    pair_with_binding(v6, extra, refuse_extra, false)
}

/// Allows gathering to finish with an allocated relay while its Binding transaction remains unanswered.
fn pair_with_binding(
    v6: bool,
    extra: Vec<Candidate>,
    refuse_extra: bool,
    drop_bindings: bool,
) -> ([Endpoint; 2], TurnPeer, Instant) {
    let mut now = Instant::now();
    let mut server = TurnPeer::new(addr(v6, 3478));
    server.drop_bindings = drop_bindings;
    let mut ice = config(server.addr, now, IcePolicy::RelayOnly);
    if drop_bindings {
        ice.gather_timeout = Duration::from_millis(100);
    }
    let (a, a_description) =
        Session::new_with_ice(addr(v6, 41000), true, 1, ice.clone(), now).unwrap();
    let (b, b_description) = Session::new_with_ice(addr(v6, 41001), false, 2, ice, now).unwrap();
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
    let (b_description, mut b_candidates) =
        Description::parse(&b_description.encode_full(endpoints[1].session.local_candidates()))
            .unwrap();
    if refuse_extra {
        server.refuse_permissions_for = Some(extra[0].addr().ip());
        server.drop_permissions = true;
    }
    b_candidates.extend(extra);
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
    let mut denied_at = None;
    for _ in 0..3000 {
        step(&mut endpoints, &mut server, &mut now);
        if server.permission_refusals != 0 {
            let original = *denied_at.get_or_insert(now);
            if now.duration_since(original) >= Duration::from_secs(1) {
                server.drop_permissions = false;
            }
        }
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
fn unanswered_gathering_binding_cannot_retire_an_established_relay() {
    let (mut endpoints, mut server, mut now) = pair_with_binding(false, Vec::new(), false, true);
    let after_retries = now + Duration::from_secs(15);
    for _ in 0..5000 {
        if now >= after_retries {
            break;
        }
        step(&mut endpoints, &mut server, &mut now);
    }
    assert!(now >= after_retries, "finite relay work did not drain");
    assert_eq!(server.allocation_count(), 2);
    for endpoint in &mut endpoints {
        assert_eq!(endpoint.session.gathering_state(), GatheringState::Complete);
        assert_eq!(endpoint.session.local_candidates().len(), 1);
        endpoint
            .session
            .handle(SessionInput::Send(
                Channel::Reliable,
                b"relay after gathering timeout".as_slice().into(),
                now,
            ))
            .unwrap();
    }
    for _ in 0..1000 {
        step(&mut endpoints, &mut server, &mut now);
        if endpoints
            .iter()
            .all(|endpoint| !endpoint.received.is_empty())
        {
            break;
        }
    }
    for endpoint in endpoints {
        assert_eq!(
            endpoint.received,
            [(Channel::Reliable, b"relay after gathering timeout".to_vec())]
        );
    }
}

/// A well-formed unsupported TCP path cannot invalidate a usable UDP full description.
#[test]
fn full_ice_ignores_unsupported_candidates_and_keeps_the_udp_session() {
    let tcp = nethernet::protocol::webrtc::candidate::parse_ice_candidate(
        "candidate:tcp-fixture 1 tcp 2122260223 192.0.2.9 49000 typ host tcptype passive",
    )
    .unwrap();
    let (mut endpoints, mut server, mut now) = pair_with_candidates(false, vec![tcp], false);
    endpoints[0]
        .session
        .handle(SessionInput::Send(
            Channel::Reliable,
            b"usable UDP path".as_slice().into(),
            now,
        ))
        .unwrap();
    for _ in 0..1000 {
        step(&mut endpoints, &mut server, &mut now);
        if !endpoints[1].received.is_empty() {
            break;
        }
    }
    assert_eq!(
        endpoints[1].received,
        [(Channel::Reliable, b"usable UDP path".to_vec())]
    );
}

/// A signed TURN refusal for one candidate leaves the other candidate's secured path live.
#[test]
fn denied_turn_candidate_permission_keeps_other_pairs_viable() {
    let private = nethernet::protocol::webrtc::candidate::parse_ice_candidate(
        "candidate:private-fixture 1 udp 2122260223 10.0.0.9 49001 typ host",
    )
    .unwrap();
    let (mut endpoints, mut server, mut now) = pair_with_candidates(false, vec![private], true);
    assert_eq!(
        server.permission_refusals, 1,
        "refused permissions must not be retried forever"
    );
    endpoints[0]
        .session
        .handle(SessionInput::Send(
            Channel::Reliable,
            b"other relay remains live".as_slice().into(),
            now,
        ))
        .unwrap();
    for _ in 0..1000 {
        step(&mut endpoints, &mut server, &mut now);
        if !endpoints[1].received.is_empty() {
            break;
        }
    }
    assert_eq!(
        endpoints[1].received,
        [(Channel::Reliable, b"other relay remains live".to_vec())]
    );
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

#[test]
fn a_selected_relay_expires_before_send_even_without_a_timeout_input() {
    for credential_expiry in [false, true] {
        let (mut endpoints, mut server, mut now) = pair(false);
        let expired = if credential_expiry {
            let expires = now + Duration::from_secs(2);
            endpoints[0]
                .session
                .update_turn_credentials(
                    server.addr,
                    TurnCredentials::new(USER.to_string(), PASSWORD.to_string(), expires).unwrap(),
                    now,
                )
                .unwrap();
            for _ in 0..20 {
                step(&mut endpoints, &mut server, &mut now);
            }
            expires
        } else {
            // Allocation success advertised 600 seconds before this handshake became ready.
            now + Duration::from_secs(601)
        };
        while endpoints[0].session.poll().is_some() {}
        let result = endpoints[0].session.handle(SessionInput::Send(
            Channel::Unreliable,
            b"must not leave an expired relay".as_slice().into(),
            expired,
        ));
        let output: Vec<_> = std::iter::from_fn(|| endpoints[0].session.poll()).collect();
        assert!(
            !output
                .iter()
                .any(|output| matches!(output, SessionOutput::Send(..))),
            "Send used an expired selected relay before its Timeout input (credential expiry: {credential_expiry})"
        );
        assert!(
            result.is_err()
                || output
                    .iter()
                    .any(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed))),
            "expiry neither rejected Send nor failed its session"
        );
        assert_eq!(
            endpoints[0].session.gathering_state(),
            GatheringState::Closed
        );
        endpoints[0]
            .session
            .handle(SessionInput::Timeout(expired + Duration::from_secs(1000)))
            .unwrap();
        assert!(endpoints[0].session.poll().is_none());
    }
}

#[test]
fn changing_turn_username_preserves_the_original_allocation_and_credentials() {
    let (mut endpoints, mut server, mut now) = pair(false);
    let result = endpoints[0].session.update_turn_credentials(
        server.addr,
        TurnCredentials::new(
            "a-different-original-test-user".to_owned(),
            PASSWORD.to_owned(),
            now + Duration::from_secs(2400),
        )
        .unwrap(),
        now,
    );
    assert!(
        matches!(result, Err(ProtocolError::Ice(IceError::Credentials))),
        "a different username must require a fresh allocation rather than mutate a live one"
    );
    endpoints[0]
        .session
        .handle(SessionInput::Send(
            Channel::Unreliable,
            b"original allocation still works".as_slice().into(),
            now,
        ))
        .unwrap();
    for _ in 0..100 {
        step(&mut endpoints, &mut server, &mut now);
        if !endpoints[1].received.is_empty() {
            break;
        }
    }
    assert!(endpoints[1].received.contains(&(
        Channel::Unreliable,
        b"original allocation still works".to_vec()
    )));
    assert_eq!(server.allocation_count(), 2);
}

/// Keeps consent alive while deterministically advancing to a scheduled maintenance boundary.
fn advance_pair_to(
    endpoints: &mut [Endpoint; 2],
    server: &mut TurnPeer,
    now: &mut Instant,
    target: Instant,
) {
    for _ in 0..60000 {
        if *now >= target {
            return;
        }
        step(endpoints, server, now);
    }
    panic!("finite relay pair did not reach its maintenance boundary");
}

#[test]
fn scheduled_permission_stale_nonce_preserves_relay_and_recovers_on_its_next_refresh() {
    let (mut endpoints, mut server, mut now) = pair(false);
    server.stale_permissions_once = true;
    let challenge_deadline = now + Duration::from_secs(120);
    // Allocation maintenance starts before relay nomination and the secured handshake.
    // Observe its actual batch rather than deriving the allocation epoch from Ready.
    for _ in 0..60000 {
        for endpoint in &mut endpoints {
            endpoint.drain(&mut server);
        }
        if server.stale_permission_responses != 0 {
            break;
        }
        deliver_server_packets(&mut endpoints, &mut server, now);
        now += Duration::from_millis(10);
        for endpoint in &mut endpoints {
            endpoint.session.handle(SessionInput::Timeout(now)).unwrap();
        }
    }
    assert_eq!(
        server.stale_permission_responses, 1,
        "the scheduled permission batch was never challenged"
    );
    assert!(
        now <= challenge_deadline,
        "scheduled permission maintenance exceeded its finite cadence"
    );
    // A concurrent allocation refresh is already signed with the old nonce when the permission challenge arrives.
    endpoints[0]
        .session
        .update_turn_credentials(
            server.addr,
            TurnCredentials::new(
                USER.to_owned(),
                PASSWORD.to_owned(),
                now + Duration::from_secs(2400),
            )
            .unwrap(),
            now,
        )
        .unwrap();
    let retry = now + Duration::from_secs(121);
    advance_pair_to(&mut endpoints, &mut server, &mut now, retry);
    assert_eq!(server.stale_permission_responses, 1);
    assert!(
        server.renewed_nonce_permissions > 0,
        "scheduled permission refresh never used RTC's renewed nonce"
    );
    assert_eq!(server.allocation_count(), 2);
    endpoints[0]
        .session
        .handle(SessionInput::Send(
            Channel::Unreliable,
            b"permission maintenance recovered".as_slice().into(),
            now,
        ))
        .unwrap();
    for _ in 0..100 {
        step(&mut endpoints, &mut server, &mut now);
        if !endpoints[1].received.is_empty() {
            break;
        }
    }
    assert!(endpoints[1].received.contains(&(
        Channel::Unreliable,
        b"permission maintenance recovered".to_vec()
    )));
}

#[test]
fn owned_turn_transactions_ignore_wrong_methods_and_reflected_requests() {
    use rtc::stun::message::{CLASS_SUCCESS_RESPONSE, METHOD_BINDING, Message, MessageType};
    use rtc::stun::xoraddr::XorMappedAddress;
    for reflected_request in [false, true] {
        let (mut endpoints, mut server, now) = pair(false);
        while endpoints[0].session.poll().is_some() {}
        endpoints[0]
            .session
            .update_turn_credentials(
                server.addr,
                TurnCredentials::new(
                    USER.to_owned(),
                    PASSWORD.to_owned(),
                    now + Duration::from_secs(2400),
                )
                .unwrap(),
                now,
            )
            .unwrap();
        let request = std::iter::from_fn(|| endpoints[0].session.poll())
            .find_map(|output| match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, server.addr);
                    Some(data)
                }
                _ => None,
            })
            .unwrap();
        let mut parsed = Message::new();
        parsed.raw = request.clone();
        parsed.decode().unwrap();
        assert_eq!(parsed.typ.method, rtc::stun::message::METHOD_REFRESH);
        server.receive(endpoints[0].local, request.clone());
        let (_, correct) = server.packets.pop_front().unwrap();
        let wrong = if reflected_request {
            request
        } else {
            let mut wrong = Message::new();
            wrong
                .build(&[
                    Box::new(parsed.transaction_id),
                    Box::new(MessageType::new(METHOD_BINDING, CLASS_SUCCESS_RESPONSE)),
                    Box::new(XorMappedAddress {
                        ip: endpoints[0].local.ip(),
                        port: endpoints[0].local.port(),
                    }),
                ])
                .unwrap();
            wrong.raw
        };
        endpoints[0]
            .session
            .handle(SessionInput::Packet(wrong.into(), server.addr, now))
            .unwrap();
        endpoints[0]
            .session
            .handle(SessionInput::Packet(correct.into(), server.addr, now))
            .unwrap();
        endpoints[0]
            .session
            .update_turn_credentials(
                server.addr,
                TurnCredentials::new(
                    USER.to_owned(),
                    PASSWORD.to_owned(),
                    now + Duration::from_secs(3600),
                )
                .unwrap(),
                now,
            )
            .expect("a wrong-method response consumed the real authenticated refresh transaction");
    }
}
