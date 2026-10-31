use nethernet::protocol::webrtc::Description;
use nethernet::session::Session;
use std::time::Instant;

/// Builds an original complete data-channel SDP with no external fixtures.
fn sdp() -> String {
    let (_, description) =
        Session::new("127.0.0.1:40000".parse().unwrap(), true, 1, Instant::now()).unwrap();
    description.encode_trickle()
}

#[test]
fn session_attributes_supply_defaults_and_media_attributes_override_them() {
    let sdp = sdp();
    let mut inherited = Vec::new();
    let mut rest = Vec::new();
    for line in sdp.lines() {
        if ["a=ice-ufrag:", "a=ice-pwd:", "a=setup:"]
            .iter()
            .any(|key| line.starts_with(key))
        {
            inherited.push(line);
        } else {
            rest.push(line);
        }
    }
    let media = rest.iter().position(|line| line.starts_with("m=")).unwrap();
    rest.splice(media..media, inherited);
    let inherited_sdp = rest.join("\r\n") + "\r\n";
    let (description, _) = Description::parse(&inherited_sdp).unwrap();
    let (original, _) = Description::parse(&sdp).unwrap();
    assert_eq!(description.ice.ufrag, original.ice.ufrag);
    assert_eq!(description.ice.pwd, original.ice.pwd);
    assert_eq!(description.dtls_role, original.dtls_role);
    let overridden =
        inherited_sdp + "a=ice-ufrag:override\r\na=ice-pwd:override-password\r\na=setup:active\r\n";
    let (description, _) = Description::parse(&overridden).unwrap();
    assert_eq!(description.ice.ufrag, "override");
    assert_eq!(description.ice.pwd, "override-password");
    assert_eq!(
        description.dtls_role,
        nethernet::protocol::webrtc::DtlsRole::Client
    );
}

#[test]
fn malformed_present_sdp_attributes_are_refused() {
    let sdp = sdp();
    for attribute in ["a=candidate:garbage\r\n", "a=candidate\r\n"] {
        assert!(Description::parse(&(sdp.clone() + attribute)).is_err());
    }
    assert!(
        Description::parse(
            &(sdp.clone() + "a=candidate:future 1 udp 1 192.0.2.1 4000 typ future\r\n")
        )
        .is_ok()
    );
    let omitted = sdp
        .lines()
        .filter(|line| !line.starts_with("a=max-message-size:"))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n";
    assert_eq!(
        Description::parse(&omitted)
            .unwrap()
            .0
            .sctp_max_message_size,
        65536
    );
    assert!(Description::parse(&(omitted + "a=max-message-size\r\n")).is_err());
}
