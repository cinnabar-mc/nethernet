//! Historical readiness retains installed facts and the accepted prefix after retirement.

use super::*;

/// A delayed consumer can hand off actual readiness even when the original transport already failed.
#[test]
fn queued_ready_retains_negotiated_facts_and_accepted_prefix_after_retirement() {
    let maximum = 64;
    let (mut receiver, mut peer, now) = connected_pair_with_sctp_limit(maximum);
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();
    let peer_addr = peer.ice.selected_local_addr().unwrap();
    let original_limits = [
        receiver.max_message_size(Channel::Reliable),
        receiver.max_message_size(Channel::Unreliable),
    ];
    let messages = [b"accepted first".as_slice(), b"accepted second".as_slice()];
    for message in messages {
        peer.send(Channel::Reliable, Bytes::copy_from_slice(message), now)
            .unwrap();
    }
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, receiver_addr);
            receiver
                .handle(SessionInput::Packet(data.into(), peer_addr, now))
                .unwrap();
        }
    }
    let ready_and_prefix_queued = matches!(
        receiver.output.front(),
        Some(SessionOutput::Event(SessionEvent::Ready))
    ) && receiver
        .output
        .iter()
        .filter_map(|output| match output {
            SessionOutput::Message(Channel::Reliable, data) => Some(data.as_slice()),
            _ => None,
        })
        .eq(messages);

    {
        let stream_id = peer.channels.stream_id(Channel::Reliable).unwrap();
        let mut stream = peer
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
                &MessageSegment::new(0, Bytes::new()).encode(),
                PayloadProtocolIdentifier::Binary,
            )
            .unwrap();
    }
    peer.pump(now).unwrap();
    let mut framing_rejections = 0;
    let mut final_datagrams = 0;
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, receiver_addr);
            final_datagrams += 1;
            match receiver.handle(SessionInput::Packet(data.into(), peer_addr, now)) {
                Err(ProtocolError::MessageParse(_)) => framing_rejections += 1,
                Ok(()) => {}
                Err(error) => panic!("unexpected original transport error: {error}"),
            }
        }
    }
    let closed = receiver.gathering_state() == GatheringState::Closed;
    let limits_at_historical_ready = [
        receiver.max_message_size(Channel::Reliable),
        receiver.max_message_size(Channel::Unreliable),
    ];
    let rejected_send = receiver.send(Channel::Reliable, Bytes::from_static(b"after failure"), now);
    let rejected_empty = receiver.send(Channel::Unreliable, Bytes::new(), now);
    let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
    let (mut receiver, receiver_close) = receiver.close(now);
    let (mut peer, peer_close) = peer.close(now);
    while receiver.poll().is_some() {}
    while peer.poll().is_some() {}
    drop((receiver, peer));

    assert!(receiver_close.is_ok() && peer_close.is_ok());
    assert!(ready_and_prefix_queued && final_datagrams > 0 && framing_rejections == 1 && closed);
    assert!(rejected_send.is_err() && rejected_empty.is_err());
    assert!(matches!(
        output.first(),
        Some(SessionOutput::Event(SessionEvent::Ready))
    ));
    assert!(
        output
            .iter()
            .filter_map(|output| match output {
                SessionOutput::Message(Channel::Reliable, data) => Some(data.as_slice()),
                _ => None,
            })
            .eq(messages)
    );
    assert_eq!(
        output
            .iter()
            .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
            .count(),
        1
    );
    assert!(matches!(
        output.last(),
        Some(SessionOutput::Event(SessionEvent::Failed))
    ));
    assert_eq!(original_limits, [Some(63 * usize::from(u8::MAX)), Some(63)]);
    assert_eq!(
        limits_at_historical_ready, original_limits,
        "queued actual readiness lost its immutable negotiated facts before the accepted FIFO handoff"
    );
}
