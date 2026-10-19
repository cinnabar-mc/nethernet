//! Pure caller-time allocation ownership using the original authenticated finite TURN peer.

use super::*;

/// Initial cache expiry cannot revoke a separately acknowledged live allocation.
#[test]
fn acknowledged_allocation_outlives_initial_service_credential_expiry() {
    retained_allocation(false);
}

/// Supported credential rotation also leaves the actual allocation/Refresh lifetime authoritative.
#[test]
fn acknowledged_allocation_outlives_rotated_service_credential_expiry() {
    retained_allocation(true);
}

/// Exercises actual Allocate and Refresh exchanges, retaining no socket or test-owned clock task.
fn retained_allocation(rotated: bool) {
    let start = Instant::now();
    let local = addr(false, 48000);
    let mut server = TurnPeer::new(addr(false, 3478));
    let credential_expiry = start + Duration::from_secs(10);
    let short =
        TurnCredentials::new(USER.to_owned(), PASSWORD.to_owned(), credential_expiry).unwrap();
    let mut ice = config(server.addr, start, IcePolicy::All);
    if !rotated {
        ice.servers = vec![IceServer::Turn(server.addr, short.clone())];
    }
    let (mut session, _) = Session::new_with_ice(local, true, 1, ice, start).unwrap();
    drive_gatherer(&mut session, local, &mut server, start);
    let acknowledged = has_relay(&session);
    if rotated {
        session
            .update_turn_credentials(server.addr, short.clone(), start)
            .unwrap();
        drive_gatherer(&mut session, local, &mut server, start);
    }
    let original_refreshes = server.refreshes;
    let rotation_acknowledged = !rotated || (original_refreshes == 1 && has_relay(&session));
    let stale = IceConfig {
        servers: vec![IceServer::Turn(server.addr, short)],
        ..Default::default()
    };
    let stale_refused = matches!(
        Session::new_with_ice(addr(false, 48001), true, 2, stale, credential_expiry),
        Err(ProtocolError::Ice(IceError::Credentials))
    );

    session
        .handle(SessionInput::Timeout(credential_expiry))
        .unwrap();
    drive_gatherer(&mut session, local, &mut server, credential_expiry);
    let retained_after_cache_expiry = has_relay(&session);
    let refreshed = start + Duration::from_secs(301);
    session.handle(SessionInput::Timeout(refreshed)).unwrap();
    drive_gatherer(&mut session, local, &mut server, refreshed);
    let refreshed_original = server.refreshes == original_refreshes + 1 && has_relay(&session);
    let actual_lifetime = server.last_refresh_lifetime;
    let expired = refreshed + actual_lifetime.unwrap_or_default() + Duration::from_secs(1);
    session.handle(SessionInput::Timeout(expired)).unwrap();
    let allocation_expired = !has_relay(&session);
    let (mut retired, closed) = session.close(expired);
    let no_tail = retired.poll().is_none();

    assert!(
        acknowledged && rotation_acknowledged,
        "original authenticated allocation setup failed"
    );
    assert!(
        stale_refused,
        "expired service credentials admitted a new allocation"
    );
    assert!(closed.is_ok() && no_tail);
    assert!(
        retained_after_cache_expiry,
        "service credential cache expiry retired the original acknowledged allocation"
    );
    assert!(
        refreshed_original && actual_lifetime.is_some(),
        "original allocation did not process its real Refresh result"
    );
    assert!(
        allocation_expired,
        "original allocation survived its actual acknowledged lifetime"
    );
}

/// Observes the public candidate owned only after the actual authenticated allocation response.
fn has_relay(session: &Session) -> bool {
    session
        .local_candidates()
        .iter()
        .any(|candidate| candidate.candidate_type() == CandidateType::Relay)
}

/// A genuine authenticated remote Refresh refusal still retires its original allocation.
#[test]
fn authenticated_refresh_refusal_still_retires_original_allocation() {
    let start = Instant::now();
    let local = addr(false, 48002);
    let mut server = TurnPeer::new(addr(false, 3478));
    let (mut session, _) = Session::new_with_ice(
        local,
        true,
        1,
        config(server.addr, start, IcePolicy::All),
        start,
    )
    .unwrap();
    drive_gatherer(&mut session, local, &mut server, start);
    let acknowledged = has_relay(&session);
    server.refuse_refreshes = true;
    let refreshed = start + Duration::from_secs(301);
    session.handle(SessionInput::Timeout(refreshed)).unwrap();
    drive_gatherer(&mut session, local, &mut server, refreshed);
    let refused = server.refreshes == 1 && !has_relay(&session);
    let (mut retired, closed) = session.close(refreshed);
    let no_tail = retired.poll().is_none();
    assert!(acknowledged && closed.is_ok() && no_tail);
    assert!(
        refused,
        "actual authenticated remote Refresh failure was treated as a live allocation"
    );
}
