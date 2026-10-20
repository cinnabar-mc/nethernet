//! Channel reliability applies to the original SCTP stream, not only its DCEP label.

use super::*;

const WARMUP: &[u8] = b"before loss";
const LOST: &[u8] = b"one lost message";
const MARKER: &[u8] = b"after loss";
const REVERSE: &[u8] = b"healthy reverse direction";

#[derive(Default)]
struct Facts {
    input_errors: usize,
    wrong_route: bool,
    unexpected_output: bool,
    early_terminal: bool,
}

/// Observes the real stream's pending bytes, released only by acknowledgment or abandonment.
fn pending(session: &mut Session<Established>, channel: Channel) -> Option<usize> {
    let stream = session.channels.stream_id(channel)?;
    session
        .sctp
        .as_mut()?
        .association_mut()?
        .stream(stream)
        .ok()?
        .buffered_amount()
        .ok()
}

/// Routes the original encrypted output without interpreting or rewriting its payload.
fn route(
    sender: &mut Session<Established>,
    receiver: &mut Session<Established>,
    now: Instant,
    received: &mut Vec<(Channel, Vec<u8>)>,
    facts: &mut Facts,
) -> bool {
    let (Some(local), Some(remote)) = (
        sender.ice.selected_local_addr(),
        receiver.ice.selected_local_addr(),
    ) else {
        facts.early_terminal = true;
        return false;
    };
    let mut progressed = false;
    while let Some(output) = sender.poll() {
        progressed = true;
        match output {
            SessionOutput::Send(bytes, to) => {
                facts.wrong_route |= to != remote;
                facts.input_errors += usize::from(
                    receiver
                        .handle(SessionInput::Packet(bytes.into(), local, now))
                        .is_err(),
                );
            }
            SessionOutput::Message(channel, bytes) => received.push((channel, bytes)),
            SessionOutput::Wait(_) => {}
            SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                facts.early_terminal = true;
            }
            _ => facts.unexpected_output = true,
        }
    }
    progressed
}

/// Uses caller time and the same owners until all committed stream bytes are released.
/// The finite iteration bound is only a liveness watchdog, not a delivery expectation.
fn settle(
    sender: &mut Session<Established>,
    receiver: &mut Session<Established>,
    now: &mut Instant,
    forward: &mut Vec<(Channel, Vec<u8>)>,
    reverse: &mut Vec<(Channel, Vec<u8>)>,
    facts: &mut Facts,
) -> bool {
    for _ in 0..5000 {
        let sent = route(sender, receiver, *now, reverse, facts);
        let received = route(receiver, sender, *now, forward, facts);
        if facts.early_terminal {
            return false;
        }
        if sent || received {
            continue;
        }
        if [Channel::Reliable, Channel::Unreliable]
            .into_iter()
            .all(|channel| {
                pending(sender, channel) == Some(0) && pending(receiver, channel) == Some(0)
            })
        {
            return true;
        }
        let Some(next) = [sender.poll_timeout(), receiver.poll_timeout()]
            .into_iter()
            .flatten()
            .min()
        else {
            return false;
        };
        *now = next.max(*now + Duration::from_millis(1));
        facts.input_errors += usize::from(sender.handle(SessionInput::Timeout(*now)).is_err());
        facts.input_errors += usize::from(receiver.handle(SessionInput::Timeout(*now)).is_err());
    }
    false
}

/// Loses one actual send, then proves byte release, healthy traffic and original owner cleanup.
fn after_loss(channel: Channel, offerer_sends: bool) -> Vec<(Channel, Vec<u8>)> {
    let (offerer, answerer, mut now) = connected_pair();
    let (mut sender, mut receiver) = if offerer_sends {
        (offerer, answerer)
    } else {
        (answerer, offerer)
    };
    let remote = receiver.ice.selected_local_addr().unwrap();
    let mut facts = Facts::default();
    let mut forward = Vec::new();
    let mut reverse = Vec::new();
    let warmup_admitted = sender
        .send(channel, Bytes::from_static(WARMUP), now)
        .is_ok();
    let warmup_released = settle(
        &mut sender,
        &mut receiver,
        &mut now,
        &mut forward,
        &mut reverse,
        &mut facts,
    );
    let warmup_received = forward == [(channel, WARMUP.to_vec())] && reverse.is_empty();
    forward.clear();

    let admitted = sender.send(channel, Bytes::from_static(LOST), now).is_ok();
    let retained = pending(&mut sender, channel).is_some_and(|bytes| bytes > 0);
    let mut lost_datagrams = 0;
    while let Some(output) = sender.poll() {
        match output {
            SessionOutput::Send(_, to) => {
                facts.wrong_route |= to != remote;
                lost_datagrams += 1;
            }
            SessionOutput::Wait(_) => {}
            _ => facts.unexpected_output = true,
        }
    }
    let released = settle(
        &mut sender,
        &mut receiver,
        &mut now,
        &mut forward,
        &mut reverse,
        &mut facts,
    );
    let marker_admitted = sender
        .send(channel, Bytes::from_static(MARKER), now)
        .is_ok();
    let reverse_admitted = receiver
        .send(Channel::Reliable, Bytes::from_static(REVERSE), now)
        .is_ok();
    let followup_released = settle(
        &mut sender,
        &mut receiver,
        &mut now,
        &mut forward,
        &mut reverse,
        &mut facts,
    );

    let (mut sender, sender_closed) = sender.close(now);
    let (mut receiver, receiver_closed) = receiver.close(now);
    while let Some(output) = sender.poll() {
        if let SessionOutput::Message(channel, bytes) = output {
            reverse.push((channel, bytes));
        }
    }
    while let Some(output) = receiver.poll() {
        if let SessionOutput::Message(channel, bytes) = output {
            forward.push((channel, bytes));
        }
    }
    drop((sender, receiver));

    assert!(sender_closed.is_ok() && receiver_closed.is_ok());
    assert!(warmup_admitted && warmup_released && warmup_received);
    assert!(admitted && retained && lost_datagrams > 0);
    assert!(
        released && followup_released,
        "original SCTP bytes stayed pending"
    );
    assert!(marker_admitted && reverse_admitted);
    assert_eq!(facts.input_errors, 0);
    assert!(!facts.wrong_route && !facts.unexpected_output && !facts.early_terminal);
    assert_eq!(reverse, [(Channel::Reliable, REVERSE.to_vec())]);
    assert_eq!(forward.last(), Some(&(channel, MARKER.to_vec())));
    forward
}

#[test]
fn unreliable_loss_is_not_retransmitted_while_reliable_loss_recovers_in_both_roles() {
    let mut outcomes = Vec::new();
    for offerer_sends in [true, false] {
        let reliable = after_loss(Channel::Reliable, offerer_sends);
        let unreliable = after_loss(Channel::Unreliable, offerer_sends);
        outcomes.push((reliable, unreliable));
    }
    // Every original pair has retired before the channel-reliability assertions.
    for (reliable, unreliable) in outcomes {
        assert_eq!(
            reliable,
            [
                (Channel::Reliable, LOST.to_vec()),
                (Channel::Reliable, MARKER.to_vec()),
            ]
        );
        assert_eq!(
            unreliable,
            [(Channel::Unreliable, MARKER.to_vec())],
            "the zero-retransmit channel redelivered the original lost message"
        );
    }
}
