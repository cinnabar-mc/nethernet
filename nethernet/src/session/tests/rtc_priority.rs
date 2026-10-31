use super::*;
use crate::session::ice::IceLayer;
use rtc::ice::attributes::priority::PriorityAttr;
use rtc::stun::message::{BINDING_REQUEST, Message};

#[test]
fn rtc_priority_reaches_the_session_wire_in_both_ice_roles() {
    let now = Instant::now();
    for controlling in [false, true] {
        let mut local = IceLayer::new(addr(40982), controlling, now).unwrap();
        let peer = IceLayer::new(addr(40983), !controlling, now).unwrap();
        let credentials = peer.local_credentials();
        local
            .set_remote_credentials(credentials.ufrag.clone(), credentials.pwd.clone())
            .unwrap();
        local
            .add_remote_candidate(peer.local_candidate().clone())
            .unwrap();
        local.handle_timeout(now + Duration::from_secs(1)).unwrap();
        let mut checks = 0;
        while let Some(output) = local.poll_write().unwrap() {
            let SessionOutput::Send(bytes, _) = output else {
                continue;
            };
            let mut message = Message::new();
            message.raw = bytes;
            message.decode().unwrap();
            if message.typ != BINDING_REQUEST {
                continue;
            }
            let mut priority = PriorityAttr::default();
            priority.get_from(&message).unwrap();
            assert_eq!(priority.0 >> 24, 110);
            assert_eq!(
                priority.0 & 0x00ff_ffff,
                local.local_candidate().priority() & 0x00ff_ffff
            );
            checks += 1;
        }
        assert!(checks > 0);
    }
}
