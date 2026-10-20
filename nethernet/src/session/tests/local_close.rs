//! Public local retirement must reach the real authenticated peer after its accepted prefix.

use super::*;

#[test]
fn public_local_close_reaches_the_real_peer_after_its_accepted_reliable_prefix() {
    let messages = [
        b"first before close".as_slice(),
        b"second before close".as_slice(),
    ];
    let mut observations = Vec::new();
    for close_offerer in [true, false] {
        let (offerer, answerer, now) = connected_pair();
        let (mut closing, mut receiver) = if close_offerer {
            (offerer, answerer)
        } else {
            (answerer, offerer)
        };
        let local = closing.ice.selected_local_addr().unwrap();
        let remote = receiver.ice.selected_local_addr().unwrap();
        for message in messages {
            closing
                .send(Channel::Reliable, Bytes::copy_from_slice(message), now)
                .unwrap();
        }
        while let Some(output) = closing.poll() {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, remote);
                receiver
                    .handle(SessionInput::Packet(data.into(), local, now))
                    .unwrap();
            }
        }
        let accepted_before_close = receiver
            .output
            .iter()
            .filter_map(|output| match output {
                SessionOutput::Message(Channel::Reliable, data) => Some(data.as_slice()),
                _ => None,
            })
            .eq(messages);

        let (mut retired, closed) = closing.close(now);
        let mut close_datagrams = 0;
        let mut input_failures = 0;
        while let Some(output) = retired.poll() {
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, remote);
                close_datagrams += 1;
                input_failures += usize::from(
                    receiver
                        .handle(SessionInput::Packet(data.into(), local, now))
                        .is_err(),
                );
            }
        }
        let peer_closed = receiver.gathering_state() == GatheringState::Closed;
        let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
        let terminal = output
            .iter()
            .position(|output| matches!(output, SessionOutput::Event(SessionEvent::PeerClosed)));
        let ordered = terminal.is_some_and(|terminal| {
            output.iter().enumerate().all(|(index, output)| {
                !matches!(output, SessionOutput::Message(..)) || index < terminal
            })
        });
        let rejected = receiver
            .send(
                Channel::Reliable,
                Bytes::from_static(b"after peer close"),
                now,
            )
            .is_err();
        let (mut receiver, receiver_closed) = receiver.close(now);
        while receiver.poll().is_some() {}
        drop((retired, receiver));

        assert!(closed.is_ok() && receiver_closed.is_ok());
        assert!(
            accepted_before_close,
            "real peer never accepted its original prefix"
        );
        assert_eq!(
            input_failures, 0,
            "actual close traffic failed framing or authentication"
        );
        assert!(
            output
                .iter()
                .filter_map(|output| match output {
                    SessionOutput::Message(Channel::Reliable, data) => Some(data.as_slice()),
                    _ => None,
                })
                .eq(messages),
            "public close lost or changed the accepted reliable prefix"
        );
        observations.push((
            output
                .iter()
                .filter(|output| matches!(output, SessionOutput::Event(SessionEvent::PeerClosed)))
                .count(),
            output.iter().any(|output| {
                matches!(
                    output,
                    SessionOutput::Event(SessionEvent::Failed) | SessionOutput::Wait(..)
                )
            }),
            close_datagrams,
            peer_closed && ordered && rejected,
        ));
    }

    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.0)
            .collect::<Vec<_>>(),
        [1, 1],
        "public local close did not reach the authenticated peer in both roles"
    );
    for (_, failed_or_waiting, close_datagrams, sealed_after_prefix) in observations {
        assert!(
            !failed_or_waiting,
            "clean peer close became a failure or kept timers active"
        );
        assert!(close_datagrams > 0 && sealed_after_prefix);
    }
}
