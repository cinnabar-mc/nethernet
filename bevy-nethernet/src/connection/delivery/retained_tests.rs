use super::*;

/// Original retired output stays exact-token scoped and charged until the same public receive consumes it.
#[test]
fn retained_core_prefix_obeys_current_budget_and_original_lifecycle_order() {
    let mut delivery = Delivery::new();
    delivery.set_limits(ServerLimits {
        max_sessions: 1,
        max_received_packets: 2,
        max_received_bytes: 2,
    });
    let original = delivery.reserve(1).unwrap();
    delivery.ready(&original, None);
    let mut updates = Vec::new();
    delivery.advance(&mut updates, 1);
    assert!(matches!(
        delivery.next_event().unwrap().event,
        PoolUpdate::Ready(_)
    ));
    delivery.retire(&original);
    let foreign = Readiness::new();
    foreign.retire();
    assert!(!delivery.retained_message(&foreign, Channel::Reliable, b"x".as_slice().into()));
    assert!(!delivery.message(&original, Channel::Reliable, b"new".as_slice().into()));
    assert!(delivery.retained_message(&original, Channel::Reliable, b"a".as_slice().into()));
    assert!(delivery.retained_message(&original, Channel::Unreliable, b"b".as_slice().into()));
    delivery.set_limits(ServerLimits {
        max_sessions: 0,
        max_received_packets: 0,
        max_received_bytes: 0,
    });
    assert!(!delivery.retained_message(&original, Channel::Reliable, b"c".as_slice().into()));
    delivery.advance(&mut updates, 3);
    let reliable = delivery.recv(Channel::Reliable);
    let unreliable = delivery.recv(Channel::Unreliable);
    let premature = delivery.next_event();
    delivery.owner_finished(&original);
    delivery.advance(&mut updates, 1);
    let terminal = delivery.next_event();
    assert_eq!(reliable.unwrap().1.as_ref(), b"a");
    assert_eq!(unreliable.unwrap().1.as_ref(), b"b");
    assert!(premature.is_none());
    assert!(matches!(terminal.unwrap().event, PoolUpdate::Failed));
    assert!(!delivery.retained_message(&original, Channel::Reliable, b"late".as_slice().into()));
    assert_eq!((delivery.packets, delivery.bytes), (0, 0));
}
