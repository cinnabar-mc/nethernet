use super::*;

/// Sealing admission cannot expose EOF while the original core still owns an undiscovered prefix.
#[test]
fn terminal_waits_for_the_original_owner_to_finish_discovering_its_prefix() {
    let mut delivery = Delivery::new();
    let original = delivery.reserve(1).unwrap();
    delivery.ready(&original, None, [0; 2]);
    let mut updates = Vec::new();
    delivery.advance(&mut updates, 1);
    let ready = delivery.next_event();

    delivery.retire(&original);
    delivery.advance(&mut updates, 1);
    let premature = delivery.next_event();
    delivery.owner_finished(&original);
    delivery.advance(&mut updates, 1);
    let terminal = delivery.next_event();

    assert!(matches!(ready.unwrap().event, PoolUpdate::Ready(_)));
    assert!(
        premature.is_none(),
        "terminal became visible before the original core finished discovering its accepted prefix"
    );
    assert!(matches!(terminal.unwrap().event, PoolUpdate::Failed));
    assert!(delivery.next_event().is_none());
    assert!(delivery.reserve(2).is_some());
}
