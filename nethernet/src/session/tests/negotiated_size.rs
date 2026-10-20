//! Actual negotiated SCTP limits constrain each original reliable fragment.

use super::*;

const SCTP_MESSAGE_BYTES: u32 = 64;
const FORWARD_MARKER: &[u8] = b"after attempted send";
const RETURN_MARKER: &[u8] = b"healthy reverse direction";

struct Exchange {
    admission: Result<(), ProtocolError>,
    forward: Vec<Vec<u8>>,
    backward: Vec<Vec<u8>>,
}

/// Keeps both original sessions through a healthy bidirectional exchange and consuming cleanup.
fn attempt(payload: Bytes) -> Exchange {
    let (mut sender, mut receiver, mut now) = connected_pair_with_sctp_limit(SCTP_MESSAGE_BYTES);
    while sender.poll().is_some() {}
    while receiver.poll().is_some() {}

    let admission = sender.send(Channel::Reliable, payload, now);
    let marker_admitted = sender
        .send(Channel::Reliable, Bytes::from_static(FORWARD_MARKER), now)
        .is_ok();
    let reply_admitted = receiver
        .send(Channel::Reliable, Bytes::from_static(RETURN_MARKER), now)
        .is_ok();
    let mut forward = Vec::new();
    let mut backward = Vec::new();
    let mut input_errors = 0;
    let mut premature_terminal = false;
    let mut unexpected_output = false;
    let sender_addr = sender.ice.selected_local_addr().unwrap();
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();

    for _ in 0..5000 {
        let mut progressed = false;
        while let Some(output) = sender.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(bytes, to) => {
                    assert_eq!(to, receiver_addr);
                    input_errors += usize::from(
                        receiver
                            .handle(SessionInput::Packet(bytes.into(), sender_addr, now))
                            .is_err(),
                    );
                }
                SessionOutput::Message(Channel::Reliable, bytes) => backward.push(bytes),
                SessionOutput::Wait(_) => {}
                SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                    premature_terminal = true;
                }
                _ => unexpected_output = true,
            }
        }
        while let Some(output) = receiver.poll() {
            progressed = true;
            match output {
                SessionOutput::Send(bytes, to) => {
                    assert_eq!(to, sender_addr);
                    input_errors += usize::from(
                        sender
                            .handle(SessionInput::Packet(bytes.into(), receiver_addr, now))
                            .is_err(),
                    );
                }
                SessionOutput::Message(Channel::Reliable, bytes) => forward.push(bytes),
                SessionOutput::Wait(_) => {}
                SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                    premature_terminal = true;
                }
                _ => unexpected_output = true,
            }
        }
        if forward.last().is_some_and(|bytes| bytes == FORWARD_MARKER)
            && backward.last().is_some_and(|bytes| bytes == RETURN_MARKER)
        {
            break;
        }
        if !progressed {
            now += Duration::from_millis(5);
            input_errors += usize::from(sender.handle(SessionInput::Timeout(now)).is_err());
            input_errors += usize::from(receiver.handle(SessionInput::Timeout(now)).is_err());
        }
    }

    let (mut sender, sender_closed) = sender.close(now);
    let (mut receiver, receiver_closed) = receiver.close(now);
    while let Some(output) = sender.poll() {
        if let SessionOutput::Message(Channel::Reliable, bytes) = output {
            backward.push(bytes);
        }
    }
    while let Some(output) = receiver.poll() {
        if let SessionOutput::Message(Channel::Reliable, bytes) = output {
            forward.push(bytes);
        }
    }
    drop((sender, receiver));

    assert!(sender_closed.is_ok() && receiver_closed.is_ok());
    assert!(marker_admitted && reply_admitted);
    assert_eq!(input_errors, 0);
    assert!(!premature_terminal && !unexpected_output);
    assert_eq!(backward, [RETURN_MARKER]);
    assert_eq!(forward.last().map(Vec::as_slice), Some(FORWARD_MARKER));
    Exchange {
        admission,
        forward,
        backward,
    }
}

#[test]
fn negotiated_sctp_small_reliable_body_preserves_bidirectional_progress() {
    let payload = Bytes::from_static(b"ordinary");
    let outcome = attempt(payload.clone());
    outcome.admission.unwrap();
    assert_eq!(outcome.forward, [payload.as_ref(), FORWARD_MARKER]);
    assert_eq!(outcome.backward, [RETURN_MARKER]);
}

#[test]
fn negotiated_sctp_reliable_body_spans_the_remote_message_limit() {
    let payload = Bytes::from(vec![0x65; 128]);
    let outcome = attempt(payload.clone());
    assert!(
        outcome.admission.is_ok(),
        "a reliable body requiring several negotiated SCTP messages was refused: {:?}",
        outcome.admission
    );
    assert_eq!(outcome.forward, [payload.as_ref(), FORWARD_MARKER]);
}

#[test]
fn negotiated_sctp_reliable_sender_accepts_exactly_255_fragments() {
    let maximum = (SCTP_MESSAGE_BYTES as usize - 1) * usize::from(u8::MAX);
    let payload = Bytes::from(vec![0x66; maximum]);
    let outcome = attempt(payload.clone());
    assert!(
        outcome.admission.is_ok(),
        "the exact negotiated reliable fragment bound was refused: {:?}",
        outcome.admission
    );
    assert_eq!(outcome.forward, [payload.as_ref(), FORWARD_MARKER]);
}

#[test]
fn negotiated_sctp_reliable_sender_rejects_256_fragments_without_a_prefix() {
    let length = (SCTP_MESSAGE_BYTES as usize - 1) * usize::from(u8::MAX) + 1;
    let outcome = attempt(Bytes::from(vec![0x67; length]));
    assert_eq!(outcome.forward, [FORWARD_MARKER]);
    assert!(
        matches!(&outcome.admission, Err(ProtocolError::MessageSizeExceeded(size)) if *size == length),
        "the negotiated logical bound was not rejected before SCTP writes: {:?}",
        outcome.admission
    );
}
