//! Rust and go-nethernet connected both ways over loopback LAN signaling and DTLS/SCTP.
#[path = "support/go_peer.rs"]
mod go_peer;

use bytes::Bytes;
use go_peer::{Link, STEP, go_dials_rust, pattern, rust_dials_go};
use nethernet_tokio::ServerData;
use serde_json::json;
use std::time::Duration;

/// Known differences from go-nethernet. Each check asserts its entry still reproduces,
/// so fixing one fails here until the entry is removed.
const EXPECTED_DIVERGENCES: &[&str] = &[
    // Reliable sends above 2.55 MB fail; Go sends up to 255 segments of 262143 bytes (go-nethernet a5399f4).
    "reliable-send-cap",
    // Reliable messages above 2.56 MB never arrive whole (go-nethernet 535497e).
    "reliable-receive-cap",
    // Stricter than Go: unreliable sends are capped at 9999 bytes; Go allows one 262143-byte segment.
    "unreliable-send-cap",
    // The unreliable channel retransmits lost messages although it announces zero retransmits.
    "unreliable-channel-retransmits",
    // ICE Disconnected closes the session; Go waits for Failed (go-nethernet be65139).
    "ice-disconnected-is-fatal",
    // A "Spectator" pong game mode becomes 6; Go reads it as survival.
    "pong-spectator-game-type",
    // Better than Go: pong protocol and version are kept; Go leaves them empty.
    "pong-protocol-version",
    // NEW: Go does not see a Rust session close until its own ICE times out.
    "rust-close-unseen",
];

fn check(id: &str, diverges: bool) {
    let expected = EXPECTED_DIVERGENCES.contains(&id);
    if expected {
        assert!(
            diverges,
            "{id} no longer reproduces; remove it from EXPECTED_DIVERGENCES"
        );
    } else {
        assert!(!diverges, "new divergence from go-nethernet: {id}");
    }
}

/// Above both Rust caps, below Go's 255 x 262143-byte limit.
const LARGE: usize = 20_000_000;

/// Echoes sizes around segment boundaries, then closes from the Rust side.
async fn reliable_echo_and_rust_close(mut peer: go_peer::GoPeer, mut link: Link) {
    for size in [
        1, 1000, 9999, 10000, 10001, 262143, 262144, 1_000_000, 2_500_000,
    ] {
        let data = pattern(size);
        link.sender.send(data.clone()).await.unwrap();
        assert_eq!(link.recv().await, Some(data), "echo of {size} bytes");
    }
    check(
        "reliable-send-cap",
        link.sender.send(pattern(LARGE)).await.is_err(),
    );
    link.sender.close().await.unwrap();
    // Well past close propagation and short of Go's ICE failure timeout.
    let seen = peer.event_within("closed", Duration::from_secs(10)).await;
    check("rust-close-unseen", seen.is_none());
}

/// Asks Go for a message larger than the Rust receive cap, then has Go close.
async fn large_inbound_and_go_close(mut peer: go_peer::GoPeer, mut link: Link) {
    link.command(&format!("send {LARGE}")).await;
    link.command("mark").await;
    let expected = pattern(LARGE);
    let mut whole = false;
    while let Some(message) = link.recv().await {
        if &message[..] == b"!mark" {
            break;
        }
        whole |= message == expected;
    }
    assert_eq!(peer.event("sent").await["ok"], true);
    check("reliable-receive-cap", !whole);
    if !link.sender.is_closed().await {
        link.command("close").await;
    }
    tokio::time::timeout(STEP, link.sender.closed())
        .await
        .expect("Go's close never reached Rust");
}

/// Sends unreliable messages while Go drops inbound datagrams and counts what arrives.
async fn unreliable_under_loss(_peer: go_peer::GoPeer, mut link: Link) {
    link.sender
        .send_unreliable(Bytes::from_static(b"ping"))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(STEP, link.unreliable.recv()).await;
    assert_eq!(echoed.unwrap().unwrap().as_deref(), Some(&b"ping"[..]));
    check(
        "unreliable-send-cap",
        link.sender.send_unreliable(pattern(20_000)).await.is_err(),
    );

    const SENT: usize = 20;
    link.command("drop-in 1500").await;
    link.reply("!dropping").await;
    for i in 0..SENT {
        let message = Bytes::from(format!("u:{i}"));
        link.sender.send_unreliable(message).await.unwrap();
    }
    link.reply("!resumed").await;
    link.command(&format!("count-unreliable {SENT} 5000")).await;
    let counted: usize = link.reply("!counted").await[9..].parse().unwrap();
    check("unreliable-channel-retransmits", counted == SENT);
}

/// Blackholes Go's socket past the ICE disconnected timeout but short of failure.
async fn ice_blackhole(mut peer: go_peer::GoPeer, mut link: Link) {
    link.command("blackhole 8000").await;
    let rust_closed = loop {
        match link.recv().await {
            None => break true,
            Some(message) if message.starts_with(b"!resumed") => break false,
            Some(_) => {}
        }
    };
    assert_eq!(peer.event("blackhole_over").await["alive"], true);
    check("ice-disconnected-is-fatal", rust_closed);
}

fn rust_server_data() -> ServerData {
    let mut data = ServerData::new("Rust Host".into(), "Rust World".into());
    data.protocol_version = 975;
    data.game_version = "1.26.50".into();
    data.session_id = "0123456789abcdef".into();
    data.game_type = 2;
    data
}

#[tokio::test(flavor = "multi_thread")]
async fn rust_dials_go_reliable() {
    let Some((peer, link, _)) = rust_dials_go(&[]).await else {
        return;
    };
    reliable_echo_and_rust_close(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn go_dials_rust_reliable() {
    let Some((peer, link, _)) = go_dials_rust(rust_server_data()).await else {
        return;
    };
    reliable_echo_and_rust_close(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rust_dials_go_large_inbound() {
    let Some((peer, link, _)) = rust_dials_go(&[]).await else {
        return;
    };
    large_inbound_and_go_close(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn go_dials_rust_large_inbound() {
    let Some((peer, link, _)) = go_dials_rust(rust_server_data()).await else {
        return;
    };
    large_inbound_and_go_close(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rust_dials_go_unreliable() {
    let Some((peer, link, _)) = rust_dials_go(&[]).await else {
        return;
    };
    unreliable_under_loss(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn go_dials_rust_unreliable() {
    let Some((peer, link, _)) = go_dials_rust(rust_server_data()).await else {
        return;
    };
    unreliable_under_loss(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rust_dials_go_ice_blackhole() {
    let Some((peer, link, _)) = rust_dials_go(&[]).await else {
        return;
    };
    ice_blackhole(peer, link).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn go_dials_rust_ice_blackhole() {
    let Some((peer, link, _)) = go_dials_rust(rust_server_data()).await else {
        return;
    };
    ice_blackhole(peer, link).await;
}

/// Go reads the Rust server's advertisement exactly as Rust wrote it.
#[tokio::test(flavor = "multi_thread")]
async fn go_discovers_rust_server_data() {
    let data = rust_server_data();
    let Some((_peer, _link, discovered)) = go_dials_rust(data.clone()).await else {
        return;
    };
    let expected = json!({
        "server_name": data.server_name, "protocol": data.protocol_version,
        "version": data.game_version, "level_name": data.level_name,
        "game_type": data.game_type, "player_count": data.player_count,
        "max_player_count": data.max_player_count, "editor_world": data.editor_world,
        "hardcore": data.hardcore, "accepts_online_auth": data.flag_a,
        "accepts_self_signed_auth": data.flag_b, "nonce": data.session_id,
        "connection_type": data.connection_type,
    });
    assert_eq!(discovered["server_data"], expected);
}

/// Rust reads Go's advertisement built from a pong, and compares its own pong parser.
#[tokio::test(flavor = "multi_thread")]
async fn rust_discovers_go_pong_data() {
    let pong = "MCPE;Go Host;975;1.26.50;2;10;1234;Go World;Spectator;1;19132;19133;";
    let Some((_peer, _link, discovered)) = rust_dials_go(&["--pong", pong]).await else {
        return;
    };
    let parsed = ServerData::from_pong_data(pong.as_bytes()).unwrap();
    assert_eq!(
        (
            &discovered.server_name,
            &discovered.level_name,
            discovered.player_count,
            discovered.max_player_count,
        ),
        (&parsed.server_name, &parsed.level_name, 2, 10)
    );
    check(
        "pong-spectator-game-type",
        discovered.game_type != parsed.game_type,
    );
    check(
        "pong-protocol-version",
        (
            discovered.protocol_version,
            discovered.game_version.as_str(),
        ) != (parsed.protocol_version, parsed.game_version.as_str()),
    );
}
