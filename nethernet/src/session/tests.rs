use super::*;
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::time::Duration;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

fn drain(session: &mut Session) -> (usize, Option<Duration>) {
    let mut failed = 0;
    let mut shortest_wait: Option<Duration> = None;
    while let Some(output) = session.poll() {
        match output {
            SessionOutput::Event(SessionEvent::Failed) => failed += 1,
            SessionOutput::Wait(wait) => {
                shortest_wait = Some(shortest_wait.map_or(wait, |w| w.min(wait)))
            }
            _ => {}
        }
    }
    (failed, shortest_wait)
}

#[test]
fn a_session_that_never_becomes_ready_fails_once_at_its_deadline() {
    let start = Instant::now();
    let (mut session, _) = Session::new(addr(40110), true, 1, start).unwrap();
    let (peer, peer_description) = Session::new(addr(40111), false, 2, start).unwrap();
    session.set_establish_deadline(Duration::from_secs(3));

    let sdp = peer_description.encode_full(&[peer.local_candidate().clone()]);
    let (description, candidates) = Description::parse(&sdp).unwrap();
    let offer = SessionInput::RemoteDescription(description, candidates, start);
    session.handle(offer).unwrap();
    let (failed, wait) = drain(&mut session);
    assert_eq!(failed, 0);
    assert!(wait.unwrap() <= Duration::from_secs(3));

    session
        .handle(SessionInput::Timeout(start + Duration::from_millis(2999)))
        .unwrap();
    assert_eq!(drain(&mut session).0, 0);

    session
        .handle(SessionInput::Timeout(start + Duration::from_secs(3)))
        .unwrap();
    assert_eq!(drain(&mut session).0, 1);

    session
        .handle(SessionInput::Timeout(start + Duration::from_secs(60)))
        .unwrap();
    let (failed, wait) = drain(&mut session);
    assert_eq!(failed, 0);
    assert!(wait.is_none_or(|w| w > Duration::ZERO));
}

#[test]
fn the_wait_schedules_the_establish_deadline() {
    let start = Instant::now();
    let (mut session, _) = Session::new(addr(40112), true, 1, start).unwrap();
    let (peer, peer_description) = Session::new(addr(40113), false, 2, start).unwrap();
    session.set_establish_deadline(Duration::from_millis(50));
    let sdp = peer_description.encode_full(&[peer.local_candidate().clone()]);
    let (description, candidates) = Description::parse(&sdp).unwrap();
    session
        .handle(SessionInput::RemoteDescription(
            description,
            candidates,
            start,
        ))
        .unwrap();
    let (_, wait) = drain(&mut session);
    assert!(wait.unwrap() <= Duration::from_millis(50));
}

#[test]
fn a_ready_session_never_fails_on_the_deadline() {
    let (mut offerer, mut answerer, now) = connected_pair();
    offerer.set_establish_deadline(Duration::from_secs(1));
    answerer.set_establish_deadline(Duration::from_secs(1));
    let _ = drain(&mut offerer);
    let _ = drain(&mut answerer);

    for session in [&mut offerer, &mut answerer] {
        session
            .handle(SessionInput::Timeout(now + Duration::from_secs(2)))
            .unwrap();
        assert_eq!(drain(session).0, 0);
    }
}

fn connected_pair() -> (Session, Session, Instant) {
    let mut now = Instant::now();

    let (mut offerer, offer) = Session::new(addr(40100), true, 1, now).unwrap();
    let (mut answerer, answer) = Session::new(addr(40101), false, 2, now).unwrap();

    let offer_sdp = offer.encode_full(&[offerer.local_candidate().clone()]);
    let answer_sdp = answer.encode_full(&[answerer.local_candidate().clone()]);

    let (parsed_offer, offer_candidates) = Description::parse(&offer_sdp).unwrap();
    let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();

    answerer
        .handle(SessionInput::RemoteDescription(
            parsed_offer,
            offer_candidates,
            now,
        ))
        .unwrap();
    offerer
        .handle(SessionInput::RemoteDescription(
            parsed_answer,
            answer_candidates,
            now,
        ))
        .unwrap();

    let mut offerer_ready = false;
    let mut answerer_ready = false;

    for _ in 0..5000 {
        let mut progressed = false;

        let mut offerer_outbox = Vec::new();
        while let Some(output) = offerer.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                SessionOutput::Event(SessionEvent::Failed) => {
                    panic!("session failed unexpectedly")
                }
                SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                SessionOutput::Wait(_) => {}
            }
        }
        for (data, to) in offerer_outbox {
            assert_eq!(to, addr(40101));
            assert_eq!(to, addr(40101));
            answerer
                .handle(SessionInput::Packet(data.into(), addr(40100), now))
                .unwrap();
        }

        let mut answerer_outbox = Vec::new();
        while let Some(output) = answerer.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                SessionOutput::Event(SessionEvent::Failed) => {
                    panic!("session failed unexpectedly")
                }
                SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                SessionOutput::Wait(_) => {}
            }
        }
        for (data, to) in answerer_outbox {
            assert_eq!(to, addr(40100));
            assert_eq!(to, addr(40100));
            offerer
                .handle(SessionInput::Packet(data.into(), addr(40101), now))
                .unwrap();
        }

        if offerer_ready && answerer_ready {
            break;
        }

        if !progressed {
            now += Duration::from_millis(5);
            offerer.handle(SessionInput::Timeout(now)).unwrap();
            answerer.handle(SessionInput::Timeout(now)).unwrap();
        }
    }

    assert!(offerer_ready, "offerer never became ready");
    assert!(answerer_ready, "answerer never became ready");
    assert_eq!(offerer.remote_addr(), Some(addr(40101)));
    assert_eq!(answerer.remote_addr(), Some(addr(40100)));

    while offerer.poll().is_some() {}
    while answerer.poll().is_some() {}
    (offerer, answerer, now)
}

fn forward(
    from: &mut Session,
    to: &mut Session,
    (from_addr, to_addr): (SocketAddr, SocketAddr),
    ready: &mut bool,
    now: Instant,
) -> bool {
    let outputs: Vec<_> = std::iter::from_fn(|| from.poll()).collect();
    let progressed = !outputs.is_empty();
    for output in outputs {
        match output {
            SessionOutput::Send(data, dest) if dest == to_addr => to
                .handle(SessionInput::Packet(data.into(), from_addr, now))
                .unwrap(),
            SessionOutput::Event(SessionEvent::Ready) => *ready = true,
            _ => {}
        }
    }
    progressed
}

fn drive_until_ready(
    offerer: &mut Session,
    answerer: &mut Session,
    mut now: Instant,
) -> (bool, bool) {
    let (mut offerer_ready, mut answerer_ready) = (false, false);
    for _ in 0..5000 {
        let sent = (addr(40100), addr(40101));
        let answered = (addr(40101), addr(40100));
        let progressed = forward(offerer, answerer, sent, &mut offerer_ready, now)
            | forward(answerer, offerer, answered, &mut answerer_ready, now);
        if offerer_ready && answerer_ready {
            break;
        }
        if !progressed {
            now += Duration::from_millis(5);
            offerer.handle(SessionInput::Timeout(now)).unwrap();
            answerer.handle(SessionInput::Timeout(now)).unwrap();
        }
    }
    (offerer_ready, answerer_ready)
}

#[test]
fn no_remote_address_is_reported_before_ice_selects_a_pair() {
    let now = Instant::now();
    let (mut offerer, _) = Session::new(addr(40100), true, 1, now).unwrap();
    let (answerer, answer) = Session::new(addr(40101), false, 2, now).unwrap();
    let answer_sdp = answer.encode_full(&[answerer.local_candidate().clone()]);
    let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();

    offerer
        .handle(SessionInput::RemoteDescription(
            parsed_answer,
            answer_candidates,
            now,
        ))
        .unwrap();

    assert_eq!(offerer.remote_addr(), None);
}

#[test]
fn transports_follow_the_ice_selected_pair_past_a_dead_first_candidate() {
    let now = Instant::now();
    let (mut offerer, offer) = Session::new(addr(40100), true, 1, now).unwrap();
    let (mut answerer, answer) = Session::new(addr(40101), false, 2, now).unwrap();
    let (dead, _) = Session::new(addr(40199), false, 2, now).unwrap();

    let offer_sdp = offer.encode_full(&[offerer.local_candidate().clone()]);
    let answer_sdp = answer.encode_full(&[
        dead.local_candidate().clone(),
        answerer.local_candidate().clone(),
    ]);
    let (parsed_offer, offer_candidates) = Description::parse(&offer_sdp).unwrap();
    let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();
    assert_eq!(answer_candidates[0].addr(), addr(40199));

    answerer
        .handle(SessionInput::RemoteDescription(
            parsed_offer,
            offer_candidates,
            now,
        ))
        .unwrap();
    offerer
        .handle(SessionInput::RemoteDescription(
            parsed_answer,
            answer_candidates,
            now,
        ))
        .unwrap();

    let (offerer_ready, answerer_ready) = drive_until_ready(&mut offerer, &mut answerer, now);
    assert!(offerer_ready, "offerer never became ready");
    assert!(answerer_ready, "answerer never became ready");
    assert_eq!(offerer.remote_addr(), Some(addr(40101)));
}

#[test]
fn a_send_is_written_without_waiting_for_a_timeout() {
    let (mut offerer, _answerer, now) = connected_pair();

    offerer
        .handle(SessionInput::Send(
            Channel::Reliable,
            Bytes::from_static(b"now"),
            now,
        ))
        .unwrap();

    let sent = std::iter::from_fn(|| offerer.poll())
        .any(|output| matches!(output, SessionOutput::Send(..)));
    assert!(sent, "the send stayed buffered until the next timeout");
}

fn reliable_messages_after_exchange(
    receiver: &mut Session,
    sender: &mut Session,
    mut now: Instant,
) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let sender_addr = sender.ice.selected_local_addr().unwrap();
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();
    for _ in 0..500 {
        let mut progressed = false;
        let outbox: Vec<_> = std::iter::from_fn(|| sender.poll()).collect();
        for output in outbox {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, receiver_addr);
                progressed = true;
                receiver
                    .handle(SessionInput::Packet(data.into(), sender_addr, now))
                    .unwrap();
            }
        }
        let outbox: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
        for output in outbox {
            match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, sender_addr);
                    progressed = true;
                    sender
                        .handle(SessionInput::Packet(data.into(), receiver_addr, now))
                        .unwrap();
                }
                SessionOutput::Message(Channel::Reliable, data) => received.push(data),
                _ => {}
            }
        }
        if !received.is_empty() {
            break;
        }
        if !progressed {
            now += Duration::from_millis(5);
            sender.handle(SessionInput::Timeout(now)).unwrap();
            receiver.handle(SessionInput::Timeout(now)).unwrap();
        }
    }
    received
}

#[test]
fn we_advertise_the_vanilla_max_message_size() {
    let (_, offer) = Session::new(addr(40100), true, 1, Instant::now()).unwrap();
    assert_eq!(offer.sctp_max_message_size, 262144);
}

#[test]
fn a_peer_may_send_one_sctp_message_up_to_our_advertised_size() {
    let (mut offerer, mut answerer, now) = connected_pair();
    let payload = vec![7u8; 200_000];

    let stream_id = answerer.channels.stream_id(Channel::Reliable).unwrap();
    let mut stream = answerer
        .sctp
        .as_mut()
        .unwrap()
        .association_mut()
        .unwrap()
        .stream(stream_id)
        .unwrap();
    stream
        .write_with_ppi(
            now,
            &MessageSegment::new(0, Bytes::from(payload.clone())).encode(),
            PayloadProtocolIdentifier::Binary,
        )
        .expect("a 200 KB message fits the offerer's advertised max-message-size");
    answerer.pump(now).unwrap();

    let received = reliable_messages_after_exchange(&mut offerer, &mut answerer, now);
    assert_eq!(received, vec![payload]);
}

#[test]
fn full_handshake_and_bidirectional_data_exchange() {
    let (mut offerer, mut answerer, mut now) = connected_pair();

    offerer
        .handle(SessionInput::Send(
            Channel::Reliable,
            Bytes::from_static(b"hello from offerer (reliable)"),
            now,
        ))
        .unwrap();
    offerer
        .handle(SessionInput::Send(
            Channel::Unreliable,
            Bytes::from_static(b"hello from offerer (unreliable)"),
            now,
        ))
        .unwrap();
    answerer
        .handle(SessionInput::Send(
            Channel::Reliable,
            Bytes::from_static(b"hello from answerer (reliable)"),
            now,
        ))
        .unwrap();
    answerer
        .handle(SessionInput::Send(
            Channel::Unreliable,
            Bytes::from_static(b"hello from answerer (unreliable)"),
            now,
        ))
        .unwrap();

    let mut offerer_received = Vec::new();
    let mut answerer_received = Vec::new();

    for _ in 0..200 {
        let mut progressed = false;

        let mut offerer_outbox = Vec::new();
        while let Some(output) = offerer.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                SessionOutput::Event(_) | SessionOutput::Wait(_) => {}
                SessionOutput::Message(channel, data) => offerer_received.push((channel, data)),
            }
        }
        for (data, to) in offerer_outbox {
            assert_eq!(to, addr(40101));
            answerer
                .handle(SessionInput::Packet(data.into(), addr(40100), now))
                .unwrap();
        }

        let mut answerer_outbox = Vec::new();
        while let Some(output) = answerer.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                SessionOutput::Event(_) | SessionOutput::Wait(_) => {}
                SessionOutput::Message(channel, data) => answerer_received.push((channel, data)),
            }
        }
        for (data, to) in answerer_outbox {
            assert_eq!(to, addr(40100));
            offerer
                .handle(SessionInput::Packet(data.into(), addr(40101), now))
                .unwrap();
        }

        if offerer_received.len() >= 2 && answerer_received.len() >= 2 {
            break;
        }

        if !progressed {
            now += Duration::from_millis(5);
            offerer.handle(SessionInput::Timeout(now)).unwrap();
            answerer.handle(SessionInput::Timeout(now)).unwrap();
        }
    }

    assert!(
        answerer_received.contains(&(Channel::Reliable, b"hello from offerer (reliable)".to_vec())),
        "answerer never received the reliable message: {answerer_received:?}"
    );
    assert!(
        answerer_received.contains(&(
            Channel::Unreliable,
            b"hello from offerer (unreliable)".to_vec()
        )),
        "answerer never received the unreliable message: {answerer_received:?}"
    );
    assert!(
        offerer_received.contains(&(
            Channel::Reliable,
            b"hello from answerer (reliable)".to_vec()
        )),
        "offerer never received the reliable message: {offerer_received:?}"
    );
    assert!(
        offerer_received.contains(&(
            Channel::Unreliable,
            b"hello from answerer (unreliable)".to_vec()
        )),
        "offerer never received the unreliable message: {offerer_received:?}"
    );
}

#[test]
fn an_authenticated_dtls_peer_close_finishes_the_session_once() {
    let (mut receiver, mut peer, now) = connected_pair();
    peer.dtls.as_mut().unwrap().close_for_test(now).unwrap();
    let close_packets: Vec<_> =
        std::iter::from_fn(|| peer.dtls.as_mut().unwrap().poll_transmit()).collect();
    assert!(
        !close_packets.is_empty(),
        "the actual DTLS peer did not emit close_notify"
    );
    for (data, to) in &close_packets {
        assert_eq!(*to, addr(40100));
        receiver
            .handle(SessionInput::Packet(data.clone().into(), addr(40101), now))
            .unwrap();
    }
    let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
    assert_eq!(
        output
            .iter()
            .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
            .count(),
        1,
        "RTC's authenticated peer-close event left a ready session alive"
    );
    assert_eq!(receiver.gathering_state(), GatheringState::Closed);
    let failed = output
        .iter()
        .position(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
        .unwrap();
    assert!(
        output[..failed]
            .iter()
            .any(|output| matches!(output, SessionOutput::Send(_, to) if *to == addr(40101))),
        "the authenticated close_notify reply was discarded during teardown"
    );
    assert!(
        !output
            .iter()
            .any(|output| matches!(output, SessionOutput::Message(..) | SessionOutput::Wait(..)))
    );
    assert!(matches!(
        receiver.handle(SessionInput::Send(
            Channel::Reliable,
            Bytes::from_static(b"closed"),
            now
        )),
        Err(ProtocolError::Ice(IceError::Closed))
    ));
    for (data, _) in close_packets {
        receiver
            .handle(SessionInput::Packet(data.into(), addr(40101), now))
            .unwrap();
    }
    receiver
        .handle(SessionInput::Timeout(now + Duration::from_secs(1000)))
        .unwrap();
    assert!(
        receiver.poll().is_none(),
        "closed session retained work or emitted failure twice"
    );
}

#[test]
fn an_authenticated_closing_datagram_delivers_its_final_complete_message_before_failure() {
    let (mut receiver, mut peer, now) = connected_pair();
    peer.handle(SessionInput::Send(
        Channel::Reliable,
        Bytes::from_static(b"final reliable payload"),
        now,
    ))
    .unwrap();
    let mut datagram = Vec::new();
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, addr(40100));
            datagram.extend(data);
        }
    }
    assert!(
        !datagram.is_empty(),
        "the actual peer did not encode its final data"
    );
    peer.dtls.as_mut().unwrap().close_for_test(now).unwrap();
    while let Some((data, to)) = peer.dtls.as_mut().unwrap().poll_transmit() {
        assert_eq!(to, addr(40100));
        datagram.extend(data);
    }
    assert!(datagram.len() <= crate::protocol::constants::MAX_DATAGRAM_SIZE);
    receiver
        .handle(SessionInput::Packet(datagram.into(), addr(40101), now))
        .unwrap();
    let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
    let data = output.iter().position(|output| matches!(output, SessionOutput::Message(Channel::Reliable, data) if data == b"final reliable payload")).expect("authenticated data preceding close_notify was lost");
    let failed = output
        .iter()
        .position(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
        .expect("peer close did not terminate the session");
    assert!(data < failed);
    assert_eq!(receiver.gathering_state(), GatheringState::Closed);
}
