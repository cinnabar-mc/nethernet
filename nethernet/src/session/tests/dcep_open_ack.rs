//! Locally opened channels become usable only after their real DCEP acknowledgement.

use super::*;

#[derive(Default)]
struct Facts {
    input_errors: usize,
    wrong_route: bool,
    terminal: bool,
    unexpected: bool,
}

/// Routes the original encrypted flight, or drops it without decoding or replacing its bytes.
fn route<S: Live>(
    source: &mut Session<S>,
    target: &mut Session<S>,
    now: Instant,
    ready: &mut usize,
    messages: &mut Vec<(Channel, Vec<u8>)>,
    discard: bool,
    facts: &mut Facts,
) -> (bool, usize) {
    let local = source.local_candidate().addr();
    let remote = target.local_candidate().addr();
    let mut progressed = false;
    let mut discarded = 0;
    while let Some(output) = source.poll() {
        progressed = true;
        match output {
            SessionOutput::Send(bytes, to) => {
                facts.wrong_route |= to != remote;
                if discard {
                    discarded += 1;
                } else {
                    facts.input_errors += usize::from(
                        target
                            .handle(SessionInput::Packet(bytes.into(), local, now))
                            .is_err(),
                    );
                }
            }
            SessionOutput::Event(SessionEvent::Ready) => *ready += 1,
            SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                facts.terminal = true
            }
            SessionOutput::Message(channel, bytes) => messages.push((channel, bytes)),
            SessionOutput::Wait(_) => {}
            SessionOutput::SendStream(..) => facts.unexpected = true,
        }
    }
    (progressed, discarded)
}

/// Uses only the original two owners' requested deadlines to progress an otherwise idle exchange.
fn tick<S: Live>(
    offerer: &mut Session<S>,
    answerer: &mut Session<S>,
    now: &mut Instant,
    facts: &mut Facts,
) {
    let Some(next) = [offerer.poll_timeout(), answerer.poll_timeout()]
        .into_iter()
        .flatten()
        .min()
    else {
        facts.unexpected = true;
        return;
    };
    *now = next.max(*now + Duration::from_millis(1));
    facts.input_errors += usize::from(offerer.handle(SessionInput::Timeout(*now)).is_err());
    facts.input_errors += usize::from(answerer.handle(SessionInput::Timeout(*now)).is_err());
}

/// A lost real OPEN flight must not grant the public sending phase before its peer can acknowledge it.
#[test]
fn a_lost_dcep_open_recovers_before_ready_and_first_channel_sends() {
    let mut now = Instant::now();
    let started = now;
    let (mut offerer, offer) = Session::new(addr(40400), true, 1, now).unwrap();
    let (mut answerer, answer) = Session::new(addr(40401), false, 2, now).unwrap();
    let (offer, offer_candidates) =
        Description::parse(&offer.encode_full(&[offerer.local_candidate().clone()])).unwrap();
    let (answer, answer_candidates) =
        Description::parse(&answer.encode_full(&[answerer.local_candidate().clone()])).unwrap();
    answerer
        .handle(SessionInput::RemoteDescription(
            offer,
            offer_candidates,
            now,
        ))
        .unwrap();
    offerer
        .handle(SessionInput::RemoteDescription(
            answer,
            answer_candidates,
            now,
        ))
        .unwrap();
    let mut facts = Facts::default();
    let mut ready = [0, 0];
    let mut early_ready = None;
    let mut dropped = 0;
    let mut unopened_peer = false;
    let mut offerer_messages = Vec::new();
    let mut answerer_messages = Vec::new();
    for _ in 0..5000 {
        let opening = dropped == 0
            && offerer.channels.reliable_stream_id.is_some()
            && offerer.channels.unreliable_stream_id.is_some();
        if opening {
            unopened_peer = answerer.channels.reliable_stream_id.is_none()
                && answerer.channels.unreliable_stream_id.is_none();
        }
        let (sent, lost) = route(
            &mut offerer,
            &mut answerer,
            now,
            &mut ready[0],
            &mut offerer_messages,
            opening,
            &mut facts,
        );
        if opening {
            dropped += lost;
            early_ready = Some(ready[0]);
        }
        let (received, _) = route(
            &mut answerer,
            &mut offerer,
            now,
            &mut ready[1],
            &mut answerer_messages,
            false,
            &mut facts,
        );
        if ready == [1, 1] && dropped > 0 || facts.terminal {
            break;
        }
        if !sent && !received {
            tick(&mut offerer, &mut answerer, &mut now, &mut facts);
        }
    }
    if ready != [1, 1] || dropped == 0 || facts.terminal {
        let elapsed = now.saturating_duration_since(started);
        let deadlines = [offerer.poll_timeout(), answerer.poll_timeout()]
            .map(|deadline| deadline.map(|at| at.saturating_duration_since(started)));
        let (mut offerer, offerer_closed) = offerer.close(now);
        let (mut answerer, answerer_closed) = answerer.close(now);
        while offerer.poll().is_some() {}
        while answerer.poll().is_some() {}
        drop((offerer, answerer));
        assert!(offerer_closed.is_ok() && answerer_closed.is_ok());
        panic!(
            "the original encrypted handshake did not recover its lost OPEN flight: ready={ready:?}, dropped={dropped}, unopened_peer={unopened_peer}, elapsed={elapsed:?}, deadlines={deadlines:?}, input_errors={}, wrong_route={}, terminal={}, unexpected={}",
            facts.input_errors, facts.wrong_route, facts.terminal, facts.unexpected
        );
    }
    let mut offerer = offerer
        .try_establish()
        .unwrap_or_else(|_| panic!("original offerer lost Ready"));
    let mut answerer = answerer
        .try_establish()
        .unwrap_or_else(|_| panic!("original answerer lost Ready"));
    let mut admissions = Vec::new();
    for channel in [Channel::Reliable, Channel::Unreliable] {
        admissions.push(offerer.send(channel, Bytes::from_static(b"first offerer payload"), now));
        admissions.push(answerer.send(channel, Bytes::from_static(b"first answerer payload"), now));
    }
    for _ in 0..5000 {
        let (sent, _) = route(
            &mut offerer,
            &mut answerer,
            now,
            &mut ready[0],
            &mut offerer_messages,
            false,
            &mut facts,
        );
        let (received, _) = route(
            &mut answerer,
            &mut offerer,
            now,
            &mut ready[1],
            &mut answerer_messages,
            false,
            &mut facts,
        );
        if offerer_messages.len() >= 2 && answerer_messages.len() >= 2 || facts.terminal {
            break;
        }
        if !sent && !received {
            tick(&mut offerer, &mut answerer, &mut now, &mut facts);
        }
    }
    let (mut offerer, offerer_closed) = offerer.close(now);
    let (mut answerer, answerer_closed) = answerer.close(now);
    while let Some(output) = offerer.poll() {
        if let SessionOutput::Message(channel, bytes) = output {
            offerer_messages.push((channel, bytes));
        }
    }
    while let Some(output) = answerer.poll() {
        if let SessionOutput::Message(channel, bytes) = output {
            answerer_messages.push((channel, bytes));
        }
    }
    drop((offerer, answerer));

    assert!(offerer_closed.is_ok() && answerer_closed.is_ok());
    assert!(
        unopened_peer && dropped > 0,
        "the fixture did not lose the original unopened channel flight"
    );
    assert_eq!(facts.input_errors, 0);
    assert!(!facts.wrong_route && !facts.terminal && !facts.unexpected);
    assert_eq!(ready, [1, 1]);
    assert!(admissions.into_iter().all(|result| result.is_ok()));
    assert_eq!(offerer_messages.len(), 2);
    assert_eq!(answerer_messages.len(), 2);
    for channel in [Channel::Reliable, Channel::Unreliable] {
        assert!(offerer_messages.contains(&(channel, b"first answerer payload".to_vec())));
        assert!(answerer_messages.contains(&(channel, b"first offerer payload".to_vec())));
    }
    assert_eq!(
        early_ready,
        Some(0),
        "the lost OPEN granted sending before the peer could acknowledge it"
    );
}
