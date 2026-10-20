//! Empty stream writes and malformed final records retain the original session lifecycle.

use super::*;

/// An accepted empty write emits no invalid application record on either established channel.
#[test]
fn framing_terminal_empty_send_preserves_the_original_live_session() {
    let mut observations = Vec::new();
    for channel in [Channel::Reliable, Channel::Unreliable] {
        let (mut receiver, mut peer, now) = connected_pair();
        let receiver_addr = receiver.ice.selected_local_addr().unwrap();
        let peer_addr = peer.ice.selected_local_addr().unwrap();
        let empty = peer.send(channel, Bytes::new(), now);
        let marker = peer.send(channel, Bytes::from_static(b"after empty write"), now);
        let mut wire = 0;
        let mut input_errors = Vec::new();
        while let Some(output) = peer.poll() {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, receiver_addr);
                wire += 1;
                if let Err(error) =
                    receiver.handle(SessionInput::Packet(data.into(), peer_addr, now))
                {
                    input_errors.push(error);
                }
            }
        }
        let live = receiver.gathering_state() != GatheringState::Closed;
        let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
        let (mut receiver, receiver_close) = receiver.close(now);
        let (mut peer, peer_close) = peer.close(now);
        while receiver.poll().is_some() {}
        while peer.poll().is_some() {}
        drop((receiver, peer));
        assert!(receiver_close.is_ok() && peer_close.is_ok());
        assert!(empty.is_ok() && marker.is_ok() && wire > 0);
        observations.push((channel, live, input_errors, output));
    }

    for (channel, live, input_errors, output) in observations {
        let delivered: Vec<_> = output
            .iter()
            .filter_map(|output| match output {
                SessionOutput::Message(actual, data) => Some((*actual, data.as_slice())),
                _ => None,
            })
            .collect();
        assert!(
            live && input_errors.is_empty(),
            "an accepted empty write retired the peer: channel={channel:?}, errors={input_errors:?}"
        );
        assert_eq!(delivered, [(channel, b"after empty write".as_slice())]);
        assert!(!output.iter().any(|output| matches!(
            output,
            SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed)
        )));
    }
}

/// Invalid application data before actual close_notify fails after its accepted prefix and reply.
#[test]
fn framing_terminal_rejection_before_peer_close_keeps_failure_and_reply() {
    let (mut receiver, mut peer, now) = connected_pair();
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();
    let peer_addr = peer.ice.selected_local_addr().unwrap();
    let accepted = b"accepted before final malformed record";
    peer.send(Channel::Reliable, Bytes::from_static(accepted), now)
        .unwrap();
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, receiver_addr);
            receiver
                .handle(SessionInput::Packet(data.into(), peer_addr, now))
                .unwrap();
        }
    }
    let accepted_before_close = receiver.output.iter().any(|output| {
        matches!(
            output,
            SessionOutput::Message(Channel::Reliable, data) if data == accepted
        )
    });
    let prior_wire = receiver
        .output
        .iter()
        .filter(|output| matches!(output, SessionOutput::Send(..)))
        .count();
    {
        let id = peer.channels.stream_id(Channel::Reliable).unwrap();
        let mut stream = peer
            .sctp
            .as_mut()
            .unwrap()
            .association_mut()
            .unwrap()
            .stream(id)
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
    let mut datagram = Vec::new();
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, receiver_addr);
            datagram.extend(data);
        }
    }
    let application_bytes = datagram.len();
    peer.dtls.as_mut().unwrap().close_for_test(now).unwrap();
    while let Some((data, to)) = peer.dtls.as_mut().unwrap().poll_transmit() {
        assert_eq!(to, receiver_addr);
        datagram.extend(data);
    }
    let has_close = datagram.len() > application_bytes;
    assert!(datagram.len() <= crate::protocol::constants::MAX_DATAGRAM_SIZE);
    let result = receiver.handle(SessionInput::Packet(datagram.into(), peer_addr, now));
    let closed = receiver.gathering_state() == GatheringState::Closed;
    let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
    let (mut receiver, receiver_close) = receiver.close(now);
    let (mut peer, peer_close) = peer.close(now);
    while receiver.poll().is_some() {}
    while peer.poll().is_some() {}
    drop((receiver, peer));
    assert!(receiver_close.is_ok() && peer_close.is_ok());
    assert!(accepted_before_close && application_bytes > 0 && has_close);
    assert!(matches!(result, Err(ProtocolError::MessageParse(_))));
    assert!(closed);
    let messages: Vec<_> = output
        .iter()
        .filter_map(|output| match output {
            SessionOutput::Message(Channel::Reliable, data) => Some(data.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(messages, [accepted.as_slice()]);
    let failed = output
        .iter()
        .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::Failed)))
        .count();
    let peer_closed = output
        .iter()
        .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::PeerClosed)))
        .count();
    let replies = output
        .iter()
        .filter(|output| matches!(output, SessionOutput::Send(..)))
        .count()
        .saturating_sub(prior_wire);
    assert!(
        failed == 1 && peer_closed == 0 && replies > 0,
        "final framing rejection lost its failure or close reply: failed={failed}, clean={peer_closed}, replies={replies}"
    );
    assert!(matches!(
        output.last(),
        Some(SessionOutput::Event(SessionEvent::Failed))
    ));
}
