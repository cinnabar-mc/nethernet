use nethernet::identity::ServerIdentity;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn unrepresentable_server_token_expiry_returns_an_error() {
    assert!(ServerIdentity::generate_with_expiry("self", UNIX_EPOCH, Some(Duration::MAX)).is_err());
}
