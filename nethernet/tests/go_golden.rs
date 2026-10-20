//! Byte and parse parity with go-nethernet, using `tools/go-peer oracle` as the reference.
#[path = "support/go_oracle.rs"]
mod go_oracle;

use go_oracle::{Oracle, b64, bytes_field, oracle, u64_field};
use nethernet::connection::{Connection, IceMode};
use nethernet::error::SignalErrorCode;
use nethernet::protocol::codec::NetherCodec;
use nethernet::protocol::packet::discovery::{
    MessagePacket, Packets, RequestPacket, ResponsePacket, ServerData, decode, encode,
};
use nethernet::protocol::webrtc::candidate::parse_ice_candidate;
use nethernet::protocol::webrtc::{Description, DtlsRole};
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::Session;
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

/// Known differences from go-nethernet. Each check asserts its entry still reproduces,
/// so fixing one fails here until the entry is removed.
const EXPECTED_DIVERGENCES: &[&str] = &[
    // Rust's LAN length prefix excludes the prefix; Go's includes it (go-nethernet 1c5981b).
    "lan-length-prefix",
    // Better than Go: ServerData versions 4 to 6 decode; Go reads only version 7.
    "server-data-legacy-versions",
    // Stricter than Go: LAN message data must be valid UTF-8; Go keeps any bytes.
    "lan-message-utf8",
    // Stricter than Go: game type and connection type must fit a u8.
    "server-data-u8-fields",
    // Error codes 27 to 37 read as SignalingUnknownError (go-nethernet 20af621, f0d2dac).
    "error-codes-27-to-37",
    // NEW: inline candidates are written `a=candidate:<foundation>`; Go writes `a=candidate:candidate:<foundation>`.
    "sdp-inline-candidate-prefix",
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

fn bench_input(name: &str) -> Vec<u8> {
    let path = format!("{}/../testdata/bench/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The fields of a decoded discovery packet, comparable across both implementations.
#[derive(Debug, PartialEq)]
struct Decoded {
    packet: &'static str,
    sender: u64,
    recipient: u64,
    data: Vec<u8>,
}

fn rust_decoded(wire: &[u8]) -> Result<Decoded, String> {
    let (packet, sender) = decode(wire).map_err(|e| e.to_string())?;
    Ok(match packet {
        Packets::Request(_) => Decoded {
            packet: "request",
            sender,
            recipient: 0,
            data: Vec::new(),
        },
        Packets::Response(p) => Decoded {
            packet: "response",
            sender,
            recipient: 0,
            data: p.application_data,
        },
        Packets::Message(p) => Decoded {
            packet: "message",
            sender,
            recipient: p.recipient_id,
            data: p.data.into_bytes(),
        },
    })
}

fn go_decoded(oracle: &mut Oracle, wire: &[u8]) -> Result<Decoded, String> {
    let r = oracle.call(json!({"op": "lan_unmarshal", "data": b64(wire)}));
    if let Some(e) = r.get("error") {
        return Err(e.to_string());
    }
    let packet = match r["packet"].as_str().unwrap() {
        "request" => "request",
        "response" => "response",
        _ => "message",
    };
    Ok(Decoded {
        packet,
        sender: u64_field(&r, "sender_id"),
        recipient: u64_field(&r, "recipient_id"),
        data: bytes_field(&r, "data"),
    })
}

/// Plaintext payload: u16 length, packet id, sender id, eight zero bytes, then the body.
fn payload(packet_id: u16, sender: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((18 + body.len()) as u16).to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out.extend_from_slice(&sender.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(body);
    out
}

#[test]
fn lan_packets_match_go_bytes_and_decode_both_ways() {
    let Some(mut go) = oracle() else { return };
    let signal = String::from_utf8(bench_input("signal.txt")).unwrap();
    let cases = [
        (Packets::Request(RequestPacket), "request", 0, Vec::new()),
        (
            Packets::Response(ResponsePacket::new(bench_input("server_data.bin"))),
            "response",
            0,
            bench_input("server_data.bin"),
        ),
        (
            Packets::Message(MessagePacket::new(u64::MAX, signal.clone())),
            "message",
            u64::MAX,
            signal.into_bytes(),
        ),
        (
            Packets::Message(MessagePacket::new(7, String::new())),
            "message",
            7,
            Vec::new(),
        ),
    ];
    let mut prefix_differs = false;
    for (packet, name, recipient, data) in cases {
        let sender = 0x0102030405060708;
        let rust = encode(&packet, sender).unwrap();
        let go_wire = go.bytes(json!({
            "op": "lan_marshal", "packet": name, "sender_id": sender,
            "recipient_id": recipient, "data": b64(&data),
        }));
        let (rust_plain, go_plain) = (go.open(&rust), go.open(&go_wire));
        assert_eq!(rust_plain[2..], go_plain[2..], "{name} payload body");
        prefix_differs |= rust_plain[..2] != go_plain[..2];

        let expected = Decoded {
            packet: name,
            sender,
            recipient,
            data,
        };
        assert_eq!(rust_decoded(&go_wire).as_ref(), Ok(&expected), "{name}");
        assert_eq!(go_decoded(&mut go, &rust).as_ref(), Ok(&expected), "{name}");
    }
    check("lan-length-prefix", prefix_differs);
}

#[test]
fn malformed_lan_datagrams_are_refused_by_both() {
    let Some(mut go) = oracle() else { return };
    let request = encode(&Packets::Request(RequestPacket), 1).unwrap();
    let mut bad_checksum = request.clone();
    bad_checksum[0] ^= 1;
    let mut bad_padding = go.open(&request);
    bad_padding.push(0);
    let cases = [
        ("short", request[..31].to_vec()),
        ("checksum", bad_checksum),
        ("unknown id", go.seal(&payload(3, 1, &[]))),
        ("trailing request byte", go.seal(&payload(0, 1, &[0]))),
        ("truncated message", go.seal(&payload(2, 1, &[1, 2, 3]))),
        (
            "declared past end",
            go.seal(&payload(
                2,
                1,
                &[&[0; 8][..], &9u32.to_le_bytes(), b"abc"].concat(),
            )),
        ),
        ("bad response hex", {
            let body = [&4u32.to_le_bytes()[..], b"zz00"].concat();
            go.seal(&payload(1, 1, &body))
        }),
        ("unpadded", [&request[..32], &bad_padding[..17]].concat()),
    ];
    for (name, wire) in cases {
        assert!(rust_decoded(&wire).is_err(), "Rust accepted {name}");
        assert!(go_decoded(&mut go, &wire).is_err(), "Go accepted {name}");
    }
}

#[test]
fn message_data_past_the_declared_length() {
    let Some(mut go) = oracle() else { return };
    let body = [&9u64.to_le_bytes()[..], &5u32.to_le_bytes(), b"hello world"].concat();
    let wire = go.seal(&payload(2, 3, &body));
    let go_result = go_decoded(&mut go, &wire);
    assert_eq!(
        go_result.as_ref().map(|d| d.data.as_slice()),
        Ok(&b"hello world"[..])
    );
    check(
        "lan-data-past-declared-length",
        rust_decoded(&wire) != go_result,
    );
}

#[test]
fn message_data_that_is_not_utf8() {
    let Some(mut go) = oracle() else { return };
    let data = [b'C', 0xff, 0xfe, b'!'];
    let wire = go.bytes(json!({
        "op": "lan_marshal", "packet": "message", "sender_id": 1, "recipient_id": 2,
        "data": b64(&data),
    }));
    let go_result = go_decoded(&mut go, &wire);
    assert_eq!(go_result.as_ref().map(|d| d.data.as_slice()), Ok(&data[..]));
    check("lan-message-utf8", rust_decoded(&wire).is_err());
}

fn to_go(d: &ServerData) -> Value {
    json!({
        "server_name": d.server_name, "protocol": d.protocol_version as i32,
        "version": d.game_version, "level_name": d.level_name, "game_type": d.game_type,
        "player_count": d.player_count, "max_player_count": d.max_player_count,
        "editor_world": d.editor_world, "hardcore": d.hardcore,
        "accepts_online_auth": d.flag_a, "accepts_self_signed_auth": d.flag_b,
        "nonce": d.session_id, "connection_type": d.connection_type,
    })
}

fn server_data_cases() -> Vec<ServerData> {
    let bench = ServerData::decode(&bench_input("server_data.bin")).unwrap();
    let mut empty = ServerData::new(String::new(), String::new());
    empty.flag_a = false;
    let mut wide = ServerData::new("Ünïcødé 名前".into(), "🌍".repeat(40));
    wide.protocol_version = i32::MAX as u32;
    wide.player_count = -1;
    wide.max_player_count = i32::MIN;
    wide.editor_world = true;
    wide.hardcore = true;
    wide.game_type = 255;
    wide.connection_type = 255;
    wide.session_id = "f".repeat(300);
    vec![bench, empty, wide]
}

#[test]
fn server_data_v7_matches_go_bytes_and_decodes_both_ways() {
    let Some(mut go) = oracle() else { return };
    for data in server_data_cases() {
        let mut rust = Vec::new();
        data.serialize(&mut rust).unwrap();
        let go_wire = go.bytes(json!({"op": "server_data_marshal", "server_data": to_go(&data)}));
        assert_eq!(rust, go_wire, "{data:?}");
        assert_eq!(ServerData::decode(&go_wire).unwrap(), data);
        let back = go.call(json!({"op": "server_data_unmarshal", "data": b64(&rust)}));
        assert_eq!(back["server_data"], to_go(&data));

        let trailing = [&rust[..], &[0]].concat();
        assert!(ServerData::decode(&trailing).is_err());
        let r = go.call(json!({"op": "server_data_unmarshal", "data": b64(&trailing)}));
        assert!(r.get("error").is_some());
    }
}

#[test]
fn server_data_legacy_versions_decode_only_in_rust() {
    let Some(mut go) = oracle() else { return };
    let i32s = [3i32.to_le_bytes(), 8i32.to_le_bytes()].concat();
    let v4 = [
        &[4, 4][..],
        b"host",
        &[5],
        b"world",
        &[2],
        &i32s,
        &[0, 0, 4, 8],
    ]
    .concat();
    let v5 = [
        &[5, 4][..],
        b"host",
        &[5],
        b"world",
        &[2],
        &i32s,
        &[0, 0, 1, 1, 4, 8],
    ]
    .concat();
    let v6 = [
        &[6, 4][..],
        b"host",
        &[5],
        b"world",
        &[2],
        &i32s,
        &[0, 0, 1, 1, 2],
        b"id",
        &[4, 8],
    ]
    .concat();
    let mut diverges = true;
    for wire in [v4, v5, v6] {
        let rust = ServerData::decode(&wire).expect("Rust reads legacy versions");
        assert_eq!((rust.server_name.as_str(), rust.player_count), ("host", 3));
        let r = go.call(json!({"op": "server_data_unmarshal", "data": b64(&wire)}));
        diverges &= r.get("error").is_some();
    }
    check("server-data-legacy-versions", diverges);
}

#[test]
fn server_data_fields_wider_than_a_byte() {
    let Some(mut go) = oracle() else { return };
    let mut fields = to_go(&ServerData::new("host".into(), "world".into()));
    fields["game_type"] = json!(300);
    fields["connection_type"] = json!(-1);
    let wire = go.bytes(json!({"op": "server_data_marshal", "server_data": fields}));
    let go_reads = go
        .call(json!({"op": "server_data_unmarshal", "data": b64(&wire)}))
        .get("error")
        .is_none();
    assert!(go_reads);
    check("server-data-u8-fields", ServerData::decode(&wire).is_err());
}

#[test]
fn signal_text_matches_go() {
    let Some(mut go) = oracle() else { return };
    let cases: &[(&str, Option<&str>)] = &[
        ("CONNECTREQUEST 1 v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n", None),
        ("CONNECTRESPONSE 18446744073709551615 sdp", None),
        (
            "CANDIDATEADD 5 candidate:1 1 udp 1 127.0.0.1 1 typ host",
            None,
        ),
        ("CONNECTERROR 9 15", None),
        ("CONNECTERROR 9 -1", None),
        ("CONNECTERROR 9 5x", None),
        ("CONNECTERROR 0x10 -2147483648suffix", None),
        ("CONNECTERROR 1 2147483647suffix", None),
        ("CONNECTERROR 1 -2147483649suffix", None),
        ("CONNECTERROR 1 +7", None),
        ("CONNECTERROR 1 -", None),
        ("CONNECTERROR 1  7", None),
        ("CONNECTERROR 1 ", None),
        ("CONNECTREQUEST 18446744073709551616suffix data", None),
        ("CONNECTREQUEST 1 ", None),
        ("CONNECTREQUEST 1 a b  c", None),
        ("CONNECTREQUEST 007 x", None),
        ("UNKNOWN 1 x", None),
        ("connectrequest 1 x", None),
        ("CONNECTREQUEST 1", None),
        ("CONNECTREQUEST x data", None),
        ("CONNECTREQUEST -1 data", None),
        ("CONNECTREQUEST 18446744073709551616 x", None),
        (
            "CONNECTREQUEST 12abc data",
            Some("signal-connection-id-prefix"),
        ),
        ("CONNECTREQUEST +7 data", Some("signal-connection-id-plus")),
        ("CONNECTERROR 1 abc", Some("signal-error-code-unchecked")),
        (
            "CONNECTERROR 1 99999999999",
            Some("signal-error-code-unchecked"),
        ),
    ];
    let mut divergent = std::collections::BTreeMap::<&str, bool>::new();
    for &(text, divergence) in cases {
        let rust = Signal::from_string(text, "n".into())
            .ok()
            .map(|s| (s.signal_type.as_str().to_string(), s.connection_id, s.data));
        let r = go.call(json!({"op": "signal_parse", "text": text}));
        let go_signal = r.get("signal").map(|s| {
            (
                s["type"].as_str().unwrap().to_string(),
                u64_field(s, "connection_id"),
                s["data"].as_str().unwrap().to_string(),
            )
        });
        match divergence {
            None => assert_eq!(rust, go_signal, "{text:?}"),
            Some(id) => *divergent.entry(id).or_default() |= rust != go_signal,
        }
    }
    for (id, diverges) in divergent {
        check(id, diverges);
    }

    for signal in [
        Signal::offer(1, "v=0\r\n".into(), "n".into()),
        Signal::candidate(u64::MAX, "candidate:x".into(), "n".into()),
        Signal::error(3, SignalErrorCode::InactivityTimeout, "n".into()),
    ] {
        let r = go.call(json!({"op": "signal_format", "signal": {
            "type": signal.signal_type.as_str(), "connection_id": signal.connection_id,
            "data": signal.data,
        }}));
        assert_eq!(r["text"].as_str().unwrap(), signal.to_string());
    }
}

#[test]
fn error_codes_match_go() {
    let Some(mut go) = oracle() else { return };
    let max = go.call(json!({"op": "error_codes"}))["max"]
        .as_u64()
        .unwrap() as u32;
    let lost: Vec<u32> = (0..=max)
        .filter(|&code| u32::from(SignalErrorCode::from(code)) != code)
        .collect();
    assert!(
        lost.iter().all(|&code| code >= 27),
        "codes below 27 changed: {lost:?}"
    );
    check("error-codes-27-to-37", !lost.is_empty());
}

fn attribute<'a>(sdp: &'a str, key: &str) -> Option<&'a str> {
    sdp.lines()
        .find_map(|l| l.strip_prefix(&format!("a={key}:")))
        .map(str::trim_end)
}

fn connection_line(sdp: &str) -> &str {
    sdp.lines()
        .find(|l| l.starts_with("c="))
        .unwrap()
        .trim_end()
}

#[test]
fn go_sdp_parses_in_rust() {
    let Some(mut go) = oracle() else { return };
    for trickle in [true, false] {
        let r = go.call(json!({"op": "sdp_capture", "trickle": trickle}));
        let signals = r["signals"]
            .as_array()
            .unwrap_or_else(|| panic!("capture failed: {r}"));
        let mut kinds = Vec::new();
        for s in signals {
            let data = s["data"].as_str().unwrap();
            let kind = s["type"].as_str().unwrap();
            kinds.push(kind);
            if kind == "CANDIDATEADD" {
                parse_ice_candidate(data).expect("Go candidate");
                continue;
            }
            let (description, candidates) = Description::parse(data).expect("Go SDP");
            assert_eq!(
                Some(description.ice.ufrag.as_str()),
                attribute(data, "ice-ufrag")
            );
            assert_eq!(description.fingerprint.0, "sha-256");
            assert_eq!(description.sctp_max_message_size, 262144);
            let expected_role = match attribute(data, "setup") {
                Some("actpass") => DtlsRole::Server,
                Some("active") => DtlsRole::Client,
                other => panic!("Go setup {other:?}"),
            };
            assert_eq!(description.dtls_role, expected_role);
            assert_eq!(
                candidates.len(),
                data.matches("a=candidate:").count(),
                "{kind} inline candidates"
            );
            assert_eq!(description.identity.is_some(), kind == "CONNECTRESPONSE");
        }
        assert!(kinds.contains(&"CONNECTREQUEST") && kinds.contains(&"CONNECTRESPONSE"));
    }
}

/// Builds a Rust offer and its trickled candidates for a host-only session.
fn rust_offer(mode: IceMode) -> (Signal, Vec<Signal>) {
    let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 40400);
    let (session, description) = Session::new(local, true, 11, Instant::now()).unwrap();
    let (_connection, mut signals) =
        Connection::connect(session, description, 7, "go".into(), mode);
    let offer = signals.remove(0);
    assert_eq!(offer.signal_type, SignalType::Offer);
    (offer, signals)
}

#[test]
fn rust_offers_are_answered_by_go() {
    let Some(mut go) = oracle() else { return };
    for (mode, trickle) in [(IceMode::Trickle, true), (IceMode::Full, false)] {
        let (offer, candidates) = rust_offer(mode);
        let candidates: Vec<&str> = candidates.iter().map(|s| s.data.as_str()).collect();
        let r = go.call(json!({
            "op": "sdp_answer", "text": offer.data, "candidates": candidates, "trickle": trickle,
        }));
        let reply = &r["signal"];
        assert_eq!(reply["type"], "CONNECTRESPONSE", "{mode:?}: {r}");
        Description::parse(reply["data"].as_str().unwrap()).expect("Go answer");
    }
}

#[test]
fn non_trickle_sdp_layout_matches_go() {
    let Some(mut go) = oracle() else { return };
    let r = go.call(json!({"op": "sdp_capture", "trickle": false}));
    let go_offer = r["signals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["type"] == "CONNECTREQUEST")
        .unwrap()["data"]
        .as_str()
        .unwrap()
        .to_string();
    let (rust, _) = rust_offer(IceMode::Full);
    let rust = rust.data;

    let unspecified = |sdp: &str| connection_line(sdp) == "c=IN IP4 0.0.0.0";
    assert!(!unspecified(&go_offer), "Go has a default candidate");
    check("sdp-default-candidate", unspecified(&rust));

    let trickle_attrs = |sdp: &str| {
        (
            attribute(sdp, "ice-options").is_some(),
            sdp.contains("a=end-of-candidates"),
        )
    };
    check(
        "sdp-non-trickle-attributes",
        trickle_attrs(&rust) != trickle_attrs(&go_offer),
    );

    let double = |sdp: &str| sdp.contains("a=candidate:candidate:");
    assert!(sdp_has_candidate(&rust) && sdp_has_candidate(&go_offer));
    check(
        "sdp-inline-candidate-prefix",
        double(&rust) != double(&go_offer),
    );
}

fn sdp_has_candidate(sdp: &str) -> bool {
    sdp.contains("a=candidate:")
}
