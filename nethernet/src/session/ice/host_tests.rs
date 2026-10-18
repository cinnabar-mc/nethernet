use super::*;
use rtc::ice::state::ConnectionState;
use std::net::Ipv4Addr;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

#[test]
fn two_agents_connect_over_loopback() {
    let mut now = Instant::now();
    let mut a = IceLayer::new(addr(40000), true, now).unwrap();
    let mut b = IceLayer::new(addr(40001), false, now).unwrap();

    let a_creds = a.local_credentials().clone();
    let b_creds = b.local_credentials().clone();
    a.set_remote_credentials(b_creds.ufrag.clone(), b_creds.pwd.clone())
        .unwrap();
    b.set_remote_credentials(a_creds.ufrag.clone(), a_creds.pwd.clone())
        .unwrap();

    let a_candidate = a.local_candidate().clone();
    let b_candidate = b.local_candidate().clone();
    a.add_remote_candidate(b_candidate).unwrap();
    b.add_remote_candidate(a_candidate).unwrap();

    let mut a_connected = false;
    let mut b_connected = false;

    for _ in 0..2000 {
        let mut progressed = false;

        while let Some((data, to)) = a.poll_write().unwrap() {
            progressed = true;
            assert_eq!(to, addr(40001));
            b.handle_read(&data, addr(40000), now).unwrap();
        }
        while let Some((data, to)) = b.poll_write().unwrap() {
            progressed = true;
            assert_eq!(to, addr(40000));
            a.handle_read(&data, addr(40001), now).unwrap();
        }

        while let Some(event) = a.poll_event() {
            progressed = true;
            if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                a_connected = true;
            }
        }
        while let Some(event) = b.poll_event() {
            progressed = true;
            if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                b_connected = true;
            }
        }

        if a_connected && b_connected {
            break;
        }

        if !progressed {
            let next_timeout = [a.poll_timeout(), b.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            now = next_timeout
                .unwrap_or(now + std::time::Duration::from_millis(20))
                .max(now + std::time::Duration::from_millis(1));
            a.handle_timeout(now).unwrap();
            b.handle_timeout(now).unwrap();
        }
    }

    assert!(a_connected, "a never reached Connected");
    assert!(b_connected, "b never reached Connected");
    assert_eq!(a.selected_remote_addr(), Some(addr(40001)));
    assert_eq!(b.selected_remote_addr(), Some(addr(40000)));
}

#[test]
fn stun_demux_rejects_non_stun_datagrams() {
    assert!(!is_stun_packet(&[22, 0, 0]));
    assert!(!is_stun_packet(&[23, 0, 0]));

    let mut stun_header = vec![0x00, 0x01, 0x00, 0x00];
    stun_header.extend_from_slice(&0x2112A442u32.to_be_bytes());
    stun_header.extend_from_slice(&[0u8; 12]);
    assert!(is_stun_packet(&stun_header));
}
