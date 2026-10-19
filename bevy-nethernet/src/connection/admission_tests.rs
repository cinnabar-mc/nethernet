use super::Readiness;

/// Worker admission never revives a sealed allocation or transfers to another entry.
#[test]
fn retirement_is_irreversible_before_and_after_worker_admission() {
    let pending = Readiness::new();
    let original = pending.clone();
    assert!(!pending.is_admitted());
    original.retire();
    assert!(!pending.admit());
    assert!(!pending.is_admitted());
    assert!(pending.is_retired());

    let replacement = Readiness::new();
    assert!(!pending.matches(&replacement));
    assert!(replacement.admit());
    assert!(replacement.is_admitted());
    assert!(!replacement.admit());
    replacement.retire();
    assert!(!replacement.is_admitted());
    assert!(!replacement.admit());
    assert!(replacement.is_retired());
}
