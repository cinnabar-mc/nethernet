use super::*;

/// Frame budgets cannot expose terminal before the accepted prefix or uncharge undelivered bytes.
#[test]
fn accepted_prefix_survives_lower_limits_and_precedes_its_single_terminal() {
    let limits = ServerLimits {
        max_sessions: 1,
        max_received_packets: 3,
        max_received_bytes: 4,
    };
    let mut delivery = Delivery::new();
    delivery.set_limits(limits);
    let original = delivery.reserve(1).unwrap();
    delivery.ready(&original, None);
    assert!(delivery.message(&original, Channel::Reliable, Box::from(&b"ab"[..])));
    assert!(delivery.message(&original, Channel::Reliable, Box::from(&b"c"[..])));
    assert!(delivery.message(&original, Channel::Unreliable, Box::from(&b"d"[..])));
    assert!(!delivery.message(&original, Channel::Reliable, Box::from(&b"rejected"[..])));
    delivery.set_limits(ServerLimits {
        max_sessions: 0,
        max_received_packets: 0,
        max_received_bytes: 0,
    });
    delivery.owner_finished(&original);
    delivery.owner_finished(&original);
    let mut updates = Vec::new();
    delivery.advance(&mut updates, 1);
    assert!(matches!(
        delivery.next_event().unwrap().event,
        PoolUpdate::Ready(None)
    ));
    assert!(delivery.recv(Channel::Reliable).is_none());
    assert!(delivery.next_event().is_none());
    assert_eq!((delivery.packets, delivery.bytes), (3, 4));
    delivery.advance(&mut updates, 1);
    assert_eq!(delivery.recv(Channel::Reliable).unwrap().1.as_ref(), b"ab");
    assert!(delivery.next_event().is_none());
    delivery.advance(&mut updates, 1);
    assert_eq!(delivery.recv(Channel::Reliable).unwrap().1.as_ref(), b"c");
    assert!(delivery.next_event().is_none());
    delivery.advance(&mut updates, 1);
    assert_eq!(delivery.recv(Channel::Unreliable).unwrap().1.as_ref(), b"d");
    assert!(delivery.next_event().is_none());
    delivery.set_limits(limits);
    assert!(
        delivery.reserve(2).is_none(),
        "undrained terminal released the original slot"
    );
    delivery.advance(&mut updates, 1);
    assert!(matches!(
        delivery.next_event().unwrap().event,
        PoolUpdate::Failed
    ));
    assert!(delivery.next_event().is_none());
    assert_eq!((delivery.packets, delivery.bytes), (0, 0));
    assert!(delivery.reserve(2).is_some());
}

/// Global bytes apply across both peers/channels, while latest-only metadata remains finite.
#[test]
fn host_byte_overflow_preserves_the_other_entry_and_original_payload_owner() {
    let mut delivery = Delivery::new();
    delivery.set_limits(ServerLimits {
        max_sessions: 2,
        max_received_packets: 8,
        max_received_bytes: 4,
    });
    let first = delivery.reserve(1).unwrap();
    let second = delivery.reserve(2).unwrap();
    delivery.ready(&first, None);
    delivery.ready(&second, None);
    assert!(delivery.message(&first, Channel::Reliable, Box::from(&b"abc"[..])));
    assert!(!delivery.message(&second, Channel::Unreliable, Box::from(&b"xy"[..])));
    delivery.owner_finished(&second);
    for value in 1..1000 {
        delivery.rtt(&first, Duration::from_nanos(value));
    }
    let mut updates = Vec::new();
    delivery.advance(&mut updates, 8);
    assert!(delivery.contains(&1, &first));
    assert!(!delivery.contains(&2, &second));
    assert_eq!(delivery.recv(Channel::Reliable).unwrap().1.as_ref(), b"abc");
    assert!(delivery.recv(Channel::Unreliable).is_none());
    assert_eq!(
        updates
            .iter()
            .filter(|event| matches!(event.event, PoolUpdate::Rtt(_)))
            .count(),
        1
    );
    assert!(updates.iter().any(
        |event| matches!(event.event, PoolUpdate::Rtt(value) if value == Duration::from_nanos(999))
    ));
    assert_eq!(delivery.lifecycle.len(), 3);
    assert_eq!((delivery.packets, delivery.bytes), (0, 0));
}

/// Reused descriptive ids and retained stale capabilities cannot evade lifecycle capacity or retire replacements.
#[test]
fn undrained_generations_hold_capacity_without_giving_stale_tokens_new_authority() {
    let mut delivery = Delivery::new();
    delivery.set_limits(ServerLimits {
        max_sessions: 1,
        ..ServerLimits::default()
    });
    let mut old = None;
    for _ in 0..8 {
        let current = delivery.reserve(1).unwrap();
        if let Some(old) = &old {
            delivery.retire(old);
            assert!(delivery.contains(&1, &current));
        }
        delivery.ready(&current, None);
        delivery.owner_finished(&current);
        assert!(delivery.reserve(1).is_none());
        let mut updates = Vec::new();
        delivery.advance(&mut updates, 2);
        assert!(matches!(
            delivery.next_event().unwrap().event,
            PoolUpdate::Ready(_)
        ));
        assert!(delivery.reserve(1).is_none());
        assert!(matches!(
            delivery.next_event().unwrap().event,
            PoolUpdate::Failed
        ));
        assert!(delivery.lifecycle.is_empty());
        old = Some(current);
    }
}
