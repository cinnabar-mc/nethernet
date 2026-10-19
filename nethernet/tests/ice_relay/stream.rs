//! The original RTC peer and secured pair, with exact stream routing instead of UDP delivery.
use super::*;

/// Takes only the original carrier's pending RTC request, retaining all other output assertions.
fn request<S: Phase>(session: &mut Session<S>, route: TurnStreamRoute) -> Vec<u8> {
    while let Some(output) = session.poll() {
        match output {
            SessionOutput::SendStream(data, actual) => {
                assert_eq!(actual, route);
                return data;
            }
            SessionOutput::Wait(_) => {}
            _ => panic!("unexpected output while waiting for the original TURN request"),
        }
    }
    panic!("the original RTC owner emitted no request");
}

/// A finite response from the same authenticated peer, without an alternate packet implementation.
fn response(server: &mut TurnPeer, route: TurnStreamRoute) -> Box<[u8]> {
    let (to, data) = server.packets.pop_front().unwrap();
    assert_eq!(to, route.local());
    assert!(server.packets.is_empty());
    data.into()
}

#[test]
fn stream_allocations_secure_both_channels_over_independent_outer_and_relay_families() {
    for outer_v6 in [false, true] {
        for family in [TurnAddressFamily::Ipv4, TurnAddressFamily::Ipv6] {
            let (mut endpoints, mut server, mut now) =
                pair_with_carrier(outer_v6, Vec::new(), false, false, Some(family));
            assert_eq!(
                server.allocation_requests, 4,
                "each original allocation authenticates once"
            );
            for endpoint in &mut endpoints {
                let candidate = &endpoint.session.local_candidates()[0];
                assert_eq!(
                    candidate.addr().is_ipv6(),
                    family == TurnAddressFamily::Ipv6
                );
                let related = candidate.related_address().unwrap();
                assert_eq!(
                    related.address,
                    endpoint.stream.unwrap().local().ip().to_string()
                );
                assert_eq!(related.port, endpoint.stream.unwrap().local().port());
                endpoint
                    .session
                    .send(Channel::Reliable, b"stream reliable".as_slice().into(), now)
                    .unwrap();
                endpoint
                    .session
                    .send(
                        Channel::Unreliable,
                        b"stream unreliable".as_slice().into(),
                        now,
                    )
                    .unwrap();
            }
            for _ in 0..2000 {
                step(&mut endpoints, &mut server, &mut now);
                if endpoints
                    .iter()
                    .all(|endpoint| endpoint.received.len() == 2)
                {
                    break;
                }
            }
            for endpoint in endpoints {
                assert!(
                    endpoint
                        .received
                        .contains(&(Channel::Reliable, b"stream reliable".to_vec()))
                );
                assert!(
                    endpoint
                        .received
                        .contains(&(Channel::Unreliable, b"stream unreliable".to_vec()))
                );
                let (session, closed) = endpoint.session.close(now);
                closed.unwrap();
                let mut retired = Endpoint {
                    session,
                    local: endpoint.local,
                    stream: endpoint.stream,
                    ready: endpoint.ready,
                    received: endpoint.received,
                };
                retired.drain(&mut server);
                assert_eq!(retired.session.gathering_state(), GatheringState::Closed);
                assert!(retired.session.poll().is_none());
            }
            assert_eq!(server.allocation_count(), 0);
        }
    }
}

#[test]
fn stream_activation_and_authenticated_responses_keep_the_exact_original_tuple() {
    let now = Instant::now();
    let mut server = TurnPeer::new(addr(false, 3478));
    let route = TurnStreamRoute::new(addr(false, 42000), server.addr).unwrap();
    let other = TurnStreamRoute::new(addr(false, 42001), server.addr).unwrap();
    let ice = IceConfig {
        servers: [route, other]
            .into_iter()
            .map(|route| IceServer::TurnStream {
                route,
                credentials: credentials(now),
                family: TurnAddressFamily::Ipv4,
            })
            .collect(),
        ..Default::default()
    };
    let (mut session, _) = Session::new_with_ice(addr(false, 41000), true, 1, ice, now).unwrap();
    assert!(
        !std::iter::from_fn(|| session.poll()).any(|output| matches!(
            output,
            SessionOutput::Send(..) | SessionOutput::SendStream(..)
        ))
    );
    session
        .handle(SessionInput::ActivateTurnStream(route, now))
        .unwrap();
    assert!(
        session
            .handle(SessionInput::ActivateTurnStream(route, now))
            .is_err()
    );
    server.receive(route.local(), request(&mut session, route));
    let challenge = response(&mut server, route);
    // The same bytes and remote address on UDP cannot complete this stream transaction.
    session
        .handle(SessionInput::Packet(challenge.clone(), server.addr, now))
        .unwrap();
    assert!(
        !std::iter::from_fn(|| session.poll())
            .any(|output| matches!(output, SessionOutput::SendStream(..)))
    );
    let unknown = TurnStreamRoute::new(addr(false, 42002), server.addr).unwrap();
    assert!(
        session
            .handle(SessionInput::StreamPacket(challenge.clone(), unknown, now))
            .is_err()
    );
    session
        .handle(SessionInput::StreamPacket(challenge, route, now))
        .unwrap();
    server.receive(route.local(), request(&mut session, route));
    session
        .handle(SessionInput::StreamPacket(
            response(&mut server, route),
            route,
            now,
        ))
        .unwrap();
    assert_eq!(server.allocation_requests, 2);
    assert_eq!(server.allocation_count(), 1);
    assert_eq!(session.local_candidates().len(), 2);
    assert!(
        !session
            .local_candidates()
            .iter()
            .any(|candidate| candidate.candidate_type() == CandidateType::ServerReflexive)
    );
    assert!(matches!(
        session.update_turn_credentials(server.addr, credentials(now), now),
        Err(ProtocolError::Ice(IceError::Configuration))
    ));
    assert_eq!(
        server.refreshes, 0,
        "ambiguous address changed a selected allocation"
    );
    session
        .update_turn_stream_credentials(route, credentials(now), now)
        .unwrap();
    server.receive(route.local(), request(&mut session, route));
    session
        .handle(SessionInput::StreamPacket(
            response(&mut server, route),
            route,
            now,
        ))
        .unwrap();
    assert_eq!(server.refreshes, 1);
    assert_eq!(session.gathering_state(), GatheringState::InProgress);
    session
        .handle(SessionInput::StreamClosed(other, now))
        .unwrap();
    assert_eq!(session.gathering_state(), GatheringState::Complete);
    assert_eq!(
        session.local_candidates().len(),
        2,
        "closing the unused carrier retired the live allocation"
    );
    session
        .handle(SessionInput::StreamClosed(route, now))
        .unwrap();
    assert_eq!(session.local_candidates().len(), 1);
    assert!(
        !std::iter::from_fn(|| session.poll())
            .any(|output| matches!(output, SessionOutput::SendStream(..)))
    );
}

#[test]
fn pending_streams_preserve_original_gather_and_credential_cutoffs() {
    for credential_cutoff in [false, true] {
        let now = Instant::now();
        let cutoff = now + Duration::from_secs(1);
        let mut peer = TurnPeer::new(addr(false, 3478));
        let route = TurnStreamRoute::new(addr(false, 42000), peer.addr).unwrap();
        let ice = IceConfig {
            servers: vec![
                IceServer::Stun(peer.addr),
                IceServer::TurnStream {
                    route,
                    credentials: TurnCredentials::new(
                        USER.into(),
                        PASSWORD.into(),
                        if credential_cutoff {
                            cutoff
                        } else {
                            now + Duration::from_secs(1200)
                        },
                    )
                    .unwrap(),
                    family: TurnAddressFamily::Ipv4,
                },
            ],
            gather_timeout: if credential_cutoff {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(1)
            },
            ..Default::default()
        };
        let (session, _) = Session::new_with_ice(addr(false, 41000), true, 1, ice, now).unwrap();
        let mut endpoint = Endpoint {
            local: addr(false, 41000),
            stream: None,
            session,
            ready: false,
            received: Vec::new(),
        };
        assert!(endpoint.drain(&mut peer));
        let (to, packet) = peer.packets.pop_front().unwrap();
        assert_eq!(to, endpoint.local);
        endpoint
            .session
            .handle(SessionInput::Packet(packet.into(), peer.addr, now))
            .unwrap();
        assert_eq!(
            endpoint.session.gathering_state(),
            GatheringState::InProgress
        );
        assert!(
            endpoint
                .session
                .local_candidates()
                .iter()
                .any(|candidate| candidate.candidate_type() == CandidateType::ServerReflexive)
        );
        endpoint
            .session
            .handle(SessionInput::Timeout(cutoff))
            .unwrap();
        assert_eq!(endpoint.session.gathering_state(), GatheringState::Complete);
        assert!(
            endpoint
                .session
                .handle(SessionInput::ActivateTurnStream(route, cutoff))
                .is_err()
        );
        assert_eq!(
            peer.allocation_requests, 0,
            "activation restarted an expired original cutoff"
        );
        assert!(
            !std::iter::from_fn(|| endpoint.session.poll())
                .any(|output| matches!(output, SessionOutput::SendStream(..)))
        );
    }
}

#[test]
fn stream_route_rejects_wildcard_zero_port_and_mixed_family_authority() {
    assert!(TurnStreamRoute::new("0.0.0.0:42000".parse().unwrap(), addr(false, 3478)).is_err());
    assert!(TurnStreamRoute::new(addr(false, 0), addr(false, 3478)).is_err());
    assert!(TurnStreamRoute::new(addr(false, 42000), addr(true, 3478)).is_err());
}

#[test]
fn selected_stream_close_retains_accepted_data_before_its_single_failure() {
    let (mut endpoints, mut server, now) = pair_with_carrier(
        false,
        Vec::new(),
        false,
        false,
        Some(TurnAddressFamily::Ipv4),
    );
    endpoints[1]
        .session
        .send(
            Channel::Reliable,
            b"accepted stream tail".as_slice().into(),
            now,
        )
        .unwrap();
    assert!(endpoints[1].drain(&mut server));
    assert!(deliver_server_packets(&mut endpoints, &mut server, now));
    let route = endpoints[0].stream.unwrap();
    endpoints[0]
        .session
        .handle(SessionInput::StreamClosed(route, now))
        .unwrap();
    let output: Vec<_> = std::iter::from_fn(|| endpoints[0].session.poll()).collect();
    let data = output.iter().position(|output| matches!(output, SessionOutput::Message(Channel::Reliable, data) if data == b"accepted stream tail")).expect("actual accepted stream data was lost");
    let failed = output
        .iter()
        .position(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
        .unwrap();
    assert!(data < failed);
    assert_eq!(
        output
            .iter()
            .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
            .count(),
        1
    );
    assert!(
        !output
            .iter()
            .any(|output| matches!(output, SessionOutput::SendStream(_, old) if *old == route))
    );
    endpoints[0]
        .session
        .handle(SessionInput::StreamClosed(route, now))
        .unwrap();
    assert!(endpoints[0].session.poll().is_none());
}
