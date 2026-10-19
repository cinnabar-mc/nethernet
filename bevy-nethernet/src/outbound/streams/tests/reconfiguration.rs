//! Actual public retry edges must use the TLS policy paired with their replacement targets.

use super::*;
use crate::client::NetherClient;
use crate::http_client::NetherHttpClient;
use crate::server::NetherServer;
use nethernet::connection::Timeouts;
use nethernet::prelude::ServerData;

/// Uses two distinct actual issuers; an old verified policy cannot authenticate the new peer.
fn replacement(tls_before: bool) -> (Peer, Peer, ClientIceConfig, ClientIceConfig) {
    let (old_server, old_verifier) = tls_support::self_signed_pair();
    let (new_server, new_verifier) = tls_support::self_signed_pair();
    let old = Peer::new(
        if tls_before {
            Security::Tls(old_server)
        } else {
            Security::Plain
        },
        false,
    );
    let new = Peer::new(Security::Tls(new_server), false);
    let mut first = config(&old, None);
    if tls_before {
        first.turn_tls = Some(old_verifier);
        first.turn_streams[0].security = TurnStreamSecurity::Tls {
            server_name: "localhost".into(),
        };
    }
    let mut next = config(&new, None);
    next.turn_tls = Some(new_verifier);
    next.turn_streams[0].security = TurnStreamSecurity::Tls {
        server_name: "localhost".into(),
    };
    (old, new, first, next)
}

/// An already-due original negotiation deadline triggers the production retry, without sleeping.
fn initial_timeouts() -> Timeouts {
    Timeouts {
        negotiation: Duration::ZERO,
        ..Timeouts::default()
    }
}

/// Gives the replacement's actual nonblocking TLS/Allocate transaction its own normal finite attempt.
fn replacement_timeouts() -> Timeouts {
    Timeouts {
        negotiation: Duration::from_secs(10),
        ..Timeouts::default()
    }
}

/// HTTP Full gathering reaches the original retry before any signaling request is fabricated.
fn http_reconfiguration(tls_before: bool) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (mut old, mut new, first, next) = replacement(tls_before);
    let mut client = NetherHttpClient::new();
    client.set_timeouts(initial_timeouts());
    client.set_ice_config(Some(first));
    client
        .connect(
            "reconfiguration".into(),
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .unwrap();
    // connect captured the old due cutoff and trust. Only explicit reconfiguration can replace trust.
    client.set_ice_config(Some(next));
    client.set_timeouts(replacement_timeouts());
    let cutoff = Instant::now() + Duration::from_secs(5);
    while Instant::now() < cutoff && new.turn.allocation_count() == 0 {
        old.update();
        new.update();
        client.update();
        std::thread::yield_now();
    }
    let admitted = new.turn.allocation_count();
    client.disconnect();
    while Instant::now() < cutoff && new.turn.allocation_count() != 0 {
        new.update();
        std::thread::yield_now();
    }
    let retained = new.turn.allocation_count();
    drop(client);
    drop(listener);
    drop(old);
    drop(new);
    assert_eq!(
        admitted, 1,
        "HTTP retry ignored the TLS policy paired with its replacement TURN target"
    );
    assert_eq!(
        retained, 0,
        "HTTP retry retained the original replacement allocation after disconnect"
    );
}

/// LAN obtains its actual signaling route by discovery before driving the original retry.
fn lan_reconfiguration(tls_before: bool) {
    let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
    server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
    let mut client = NetherClient::new(2, |config| {
        config.broadcast_address = Some(server.local_addr().unwrap());
        config.broadcast_interval = Duration::from_millis(20);
    })
    .unwrap();
    let cutoff = Instant::now() + Duration::from_secs(10);
    while !client.discovered().contains_key(&1) {
        server.update();
        client.update();
        assert!(Instant::now() < cutoff, "actual LAN discovery stalled");
        std::thread::yield_now();
    }
    let (mut old, mut new, first, next) = replacement(tls_before);
    client.set_timeouts(initial_timeouts());
    client.set_ice_config(Some(first));
    client.connect(1).unwrap();
    client.set_ice_config(Some(next));
    client.set_timeouts(replacement_timeouts());
    let cutoff = Instant::now() + Duration::from_secs(5);
    while Instant::now() < cutoff && new.turn.allocation_count() == 0 {
        old.update();
        new.update();
        client.update();
        std::thread::yield_now();
    }
    let admitted = new.turn.allocation_count();
    client.disconnect();
    while Instant::now() < cutoff && new.turn.allocation_count() != 0 {
        new.update();
        std::thread::yield_now();
    }
    let retained = new.turn.allocation_count();
    drop(client);
    drop(server);
    drop(old);
    drop(new);
    assert_eq!(
        admitted, 1,
        "LAN retry ignored the TLS policy paired with its replacement TURN target"
    );
    assert_eq!(
        retained, 0,
        "LAN retry retained the original replacement allocation after disconnect"
    );
}

#[test]
fn http_retry_uses_replacement_turn_tls_trust() {
    http_reconfiguration(true);
}

#[test]
fn http_retry_prepares_tcp_to_tls_replacement_before_frame_update() {
    http_reconfiguration(false);
}

#[test]
fn lan_retry_uses_replacement_turn_tls_trust() {
    lan_reconfiguration(true);
}

#[test]
fn lan_retry_prepares_tcp_to_tls_replacement_before_frame_update() {
    lan_reconfiguration(false);
}
