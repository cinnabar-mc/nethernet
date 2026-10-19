use super::*;
use nethernet::session::IceServer;
use std::net::Ipv4Addr;

/// Keeps one actual loopback STUN destination alive while the original gathering timer remains pending.
fn gathering(now: Instant) -> (Outbound, UdpSocket) {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let config = ClientIceConfig {
        bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        ice: IceConfig {
            servers: vec![IceServer::Stun(peer.local_addr().unwrap())],
            ..Default::default()
        },
        turn_streams: Vec::new(),
        #[cfg(feature = "tls")]
        turn_tls: None,
    };
    let owner = Outbound::new(
        Some(&config),
        Duration::from_secs(10),
        now,
        &ClientTls::default(),
    )
    .unwrap();
    (owner, peer)
}

/// An original unpolled timer FIFO cannot escape the edge's finite budget between frames.
#[test]
fn pending_core_output_retires_before_another_frame_can_bypass_its_bound() {
    let now = Instant::now();
    let (mut owner, peer) = gathering(now);
    let Some(State::Gathering(core, _)) = owner.state.get() else {
        panic!("the original gathering owner disappeared");
    };
    for _ in 0..=MAX_RECEIVED_MESSAGES {
        core.handle(SessionInput::Timeout(now)).unwrap();
    }
    let peak = core.pending_output_usage().entries;
    let outcome = owner.update(now);
    let retired = owner.state.get().is_none();
    drop(owner);
    drop(peer);
    assert!(peak > MAX_RECEIVED_MESSAGES);
    assert!(
        outcome.is_err(),
        "unpolled original output bypassed its finite bound"
    );
    assert!(retired, "the original over-capacity core remained live");
}

/// A rejected final delivery permanently seals later successors even when consumption frees capacity.
#[test]
fn rejected_delivery_does_not_reopen_during_retirement() {
    let now = Instant::now();
    let (mut owner, peer) = gathering(now);
    for index in 0..MAX_RECEIVED_MESSAGES {
        owner
            .push_event(ConnectionEvent::Message(
                Channel::Reliable,
                index.to_le_bytes().as_slice().into(),
            ))
            .unwrap();
    }
    let rejected = owner.push_event(ConnectionEvent::Message(
        Channel::Reliable,
        b"rejected".as_slice().into(),
    ));
    let first = owner.poll_event();
    let successor = owner.push_event(ConnectionEvent::Message(
        Channel::Reliable,
        b"successor".as_slice().into(),
    ));
    let tail = owner.retire();
    drop(peer);
    assert!(rejected.is_err());
    assert!(
        matches!(first, Some(ConnectionEvent::Message(_, bytes)) if bytes.as_ref() == 0usize.to_le_bytes())
    );
    assert!(
        successor.is_err(),
        "consumption reopened a rejected message prefix"
    );
    let messages: Vec<_> = tail
        .into_iter()
        .filter_map(|event| match event {
            ConnectionEvent::Message(_, bytes) => Some(bytes),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), MAX_RECEIVED_MESSAGES - 1);
    for (index, bytes) in (1..MAX_RECEIVED_MESSAGES).zip(messages) {
        assert_eq!(bytes.as_ref(), index.to_le_bytes());
    }
}
