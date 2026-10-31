use nethernet::util::{endpoint, stun};
use rtc::stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message as StunMessage};

#[test]
fn globally_reachable_ipv6_exceptions_remain_advertisable() {
    for address in ["2001:3::1", "2001:4:112::1"] {
        let ip = address.parse().unwrap();
        assert_eq!(endpoint::scope(ip), endpoint::Scope::Public);
        assert!(endpoint::advertisable(ip, false));
        assert!(nethernet::util::candidate::has_routable_host_candidate(
            &format!("a=candidate:1 1 udp 1 {address} 4000 typ host\r\n")
        ));
    }
    for address in ["2001:2::1", "2001:4:111::1", "2001:4:113::1"] {
        assert_eq!(
            endpoint::scope(address.parse().unwrap()),
            endpoint::Scope::Unusable
        );
    }
}

#[test]
fn stun_routing_only_accepts_binding_requests() {
    let mut message = StunMessage::new();
    message.typ = BINDING_REQUEST;
    message.add(rtc::stun::attributes::ATTR_USERNAME, b"abcd:wxyz");
    message.write_header();
    assert_eq!(stun::local_ufrag(&message.raw).as_deref(), Some("abcd"));
    for typ in [
        BINDING_SUCCESS,
        rtc::stun::message::MessageType::new(
            rtc::stun::message::METHOD_BINDING,
            rtc::stun::message::CLASS_INDICATION,
        ),
        rtc::stun::message::MessageType::new(
            rtc::stun::message::METHOD_ALLOCATE,
            rtc::stun::message::CLASS_REQUEST,
        ),
    ] {
        message.typ = typ;
        message.write_header();
        assert!(stun::local_ufrag(&message.raw).is_none());
    }
}
