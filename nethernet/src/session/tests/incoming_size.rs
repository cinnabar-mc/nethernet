//! Caller-selected reassembly bounds preserve the original wire and terminal owners.

use super::*;

struct Observation {
    messages: Vec<Vec<u8>>,
    rejected_sizes: Vec<usize>,
    failed: usize,
}

/// Uses the original two-Session wire exchange and consumes both close owners before returning.
fn exchange(incoming: Option<usize>, payload: Bytes, channel: Channel) -> Observation {
    let (mut receiver, mut sender, mut now) =
        connected_pair_with_message_limits(LOCAL_SCTP_MAX_MESSAGE_SIZE, incoming);
    while receiver.poll().is_some() {}
    while sender.poll().is_some() {}
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();
    let sender_addr = sender.ice.selected_local_addr().unwrap();
    let accepted = Bytes::from_static(b"ab");
    let mut admissions = vec![sender.send(Channel::Reliable, accepted, now)];
    let mut pending = Some(payload);
    let mut observed = Observation {
        messages: Vec::new(),
        rejected_sizes: Vec::new(),
        failed: 0,
    };
    let mut unexpected = 0;
    let mut wire = 0;
    for _ in 0..5000 {
        let mut progressed = false;
        while let Some(output) = sender.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, receiver_addr);
                    wire += 1;
                    match receiver.handle(SessionInput::Packet(data.into(), sender_addr, now)) {
                        Err(ProtocolError::MessageSizeExceeded(size)) => {
                            observed.rejected_sizes.push(size)
                        }
                        Ok(()) => {}
                        Err(_) => unexpected += 1,
                    }
                }
                SessionOutput::Wait(_) => {}
                _ => unexpected += 1,
            }
        }
        while let Some(output) = receiver.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, sender_addr);
                    unexpected += usize::from(
                        sender
                            .handle(SessionInput::Packet(data.into(), receiver_addr, now))
                            .is_err(),
                    );
                }
                SessionOutput::Message(_, data) => observed.messages.push(data),
                SessionOutput::Event(SessionEvent::Failed) => observed.failed += 1,
                SessionOutput::Wait(_) => {}
                _ => unexpected += 1,
            }
        }
        if observed.messages.first().is_some_and(|data| data == b"ab")
            && let Some(payload) = pending.take()
        {
            admissions.push(sender.send(channel, payload, now));
            if channel == Channel::Reliable {
                admissions.push(sender.send(Channel::Reliable, Bytes::from_static(b"cd"), now));
            }
        }
        if observed.failed != 0 || observed.messages.last().is_some_and(|data| data == b"cd") {
            break;
        }
        if !progressed {
            now += Duration::from_millis(5);
            unexpected += usize::from(sender.handle(SessionInput::Timeout(now)).is_err());
            unexpected += usize::from(receiver.handle(SessionInput::Timeout(now)).is_err());
        }
    }
    let (mut receiver, receiver_closed) = receiver.close(now);
    let (mut sender, sender_closed) = sender.close(now);
    while let Some(output) = receiver.poll() {
        match output {
            SessionOutput::Message(_, data) => observed.messages.push(data),
            SessionOutput::Event(SessionEvent::Failed) => observed.failed += 1,
            _ => {}
        }
    }
    while sender.poll().is_some() {}
    drop((receiver, sender));
    assert!(receiver_closed.is_ok() && sender_closed.is_ok());
    assert!(
        pending.is_none(),
        "the accepted prefix never reached its original owner"
    );
    assert!(
        admissions.into_iter().all(|result| result.is_ok()),
        "the original sender did not admit the fixture bodies"
    );
    assert!(
        wire > 0 && unexpected == 0,
        "the original wire exchange failed before the receive policy oracle"
    );
    observed
}

/// Default admission carries a 20 MB body intact while explicit smaller policies still apply.
#[test]
fn incoming_size_default_twenty_mb_preserves_full_bytes() {
    let body = Bytes::from(vec![0x61; 20_000_000]);
    let default = exchange(None, body.clone(), Channel::Reliable);
    assert_eq!(default.failed, 0);
    assert!(default.rejected_sizes.is_empty());
    assert_eq!(
        default.messages,
        [b"ab".to_vec(), body.to_vec(), b"cd".to_vec()]
    );
    let configured = exchange(Some(2_560_000), body, Channel::Reliable);
    assert_eq!(configured.messages, [b"ab".to_vec()]);
    assert_eq!(configured.failed, 1);
    assert_eq!(configured.rejected_sizes.len(), 1);
}

/// Either channel's first oversized logical body retains its accepted reliable prefix and seals successors.
#[test]
fn incoming_size_exact_and_one_over_preserve_prefix_and_one_terminal() {
    let exact = exchange(Some(2), Bytes::from_static(b"ef"), Channel::Reliable);
    assert_eq!(
        exact.messages,
        [b"ab".to_vec(), b"ef".to_vec(), b"cd".to_vec()]
    );
    assert_eq!(exact.failed, 0);
    assert!(exact.rejected_sizes.is_empty());
    for channel in [Channel::Reliable, Channel::Unreliable] {
        let over = exchange(Some(2), Bytes::from_static(b"efg"), channel);
        assert_eq!(over.messages, [b"ab".to_vec()]);
        assert_eq!(over.rejected_sizes, [3]);
        assert_eq!(over.failed, 1);
    }
}

/// Remote-description acceptance fences later policy changes without replacing its pending allocation.
#[test]
fn incoming_size_selection_is_frozen_at_the_original_remote_description() {
    let now = Instant::now();
    let (mut pending, _) = Session::new(addr(40102), true, 3, now).unwrap();
    let (peer, description) = Session::new(addr(40103), false, 4, now).unwrap();
    pending.handle(SessionInput::Timeout(now)).unwrap();
    pending.set_max_incoming_message_size(0).unwrap();
    let sdp = description.encode_full(peer.local_candidates());
    let (description, candidates) = Description::parse(&sdp).unwrap();
    pending
        .handle(SessionInput::RemoteDescription(
            description,
            candidates,
            now,
        ))
        .unwrap();
    let late = pending.set_max_incoming_message_size(usize::MAX);
    let maximum = pending.channels.reassembly.maximum();
    let (mut pending, pending_closed) = pending.close(now);
    let (mut peer, peer_closed) = peer.close(now);
    while pending.poll().is_some() {}
    while peer.poll().is_some() {}
    drop((pending, peer));
    assert!(pending_closed.is_ok() && peer_closed.is_ok());
    assert!(late.is_err());
    assert_eq!(maximum, 0);
}
