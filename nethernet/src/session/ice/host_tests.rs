use super::*;
use crate::sans::Sans;
use crate::session::{Channel, SessionEvent, SessionInput};
use rtc::ice::state::ConnectionState;
use std::net::Ipv4Addr;
use std::time::Duration;

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

        while let Some(output) = a.poll_write().unwrap() {
            let SessionOutput::Send(data, to) = output else {
                panic!("host-only ICE emitted a stream packet")
            };
            progressed = true;
            assert_eq!(to, addr(40001));
            b.handle_read(&data, addr(40000), now).unwrap();
        }
        while let Some(output) = b.poll_write().unwrap() {
            let SessionOutput::Send(data, to) = output else {
                panic!("host-only ICE emitted a stream packet")
            };
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

/// A real transient ICE state preserves accepted data and the original ready transports.
#[test]
fn transient_ice_disconnect_preserves_the_session_and_recovers() {
    let (mut receiver, mut peer, mut now) = crate::session::tests::connected_pair();
    let receiver_addr = receiver.ice.selected_local_addr().unwrap();
    let peer_addr = peer.ice.selected_local_addr().unwrap();
    let before = b"accepted before the transient gap";
    let after = b"received after the transient gap";
    peer.send(Channel::Reliable, bytes::Bytes::from_static(before), now)
        .unwrap();
    while let Some(output) = peer.poll() {
        if let SessionOutput::Send(data, to) = output {
            assert_eq!(to, receiver_addr);
            receiver
                .handle(SessionInput::Packet(data.into(), peer_addr, now))
                .unwrap();
        }
    }
    assert!(receiver.output.iter().any(|output| matches!(
        output,
        SessionOutput::Message(Channel::Reliable, data) if data == before
    )));

    now += Duration::from_secs(6);
    receiver.ice.handle_timeout(now).unwrap();
    assert_eq!(receiver.ice.agent.state(), ConnectionState::Disconnected);
    receiver.pump(now).unwrap();
    let remained_live = receiver.gathering_state() != GatheringState::Closed
        && receiver.dtls.is_some()
        && receiver.sctp.is_some()
        && receiver.ice.selected_remote_addr() == Some(peer_addr);

    peer.send(Channel::Reliable, bytes::Bytes::from_static(after), now)
        .unwrap();
    let mut received = Vec::new();
    let mut terminals = 0;
    for _ in 0..500 {
        let mut progressed = false;
        let output: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
        for output in output {
            progressed = true;
            match output {
                SessionOutput::Send(data, to) => {
                    assert_eq!(to, peer_addr);
                    peer.handle(SessionInput::Packet(data.into(), receiver_addr, now))
                        .unwrap();
                }
                SessionOutput::Message(Channel::Reliable, data) => received.push(data),
                SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                    terminals += 1;
                }
                _ => {}
            }
        }
        let output: Vec<_> = std::iter::from_fn(|| peer.poll()).collect();
        for output in output {
            progressed = true;
            if let SessionOutput::Send(data, to) = output {
                assert_eq!(to, receiver_addr);
                receiver
                    .handle(SessionInput::Packet(data.into(), peer_addr, now))
                    .unwrap();
            }
        }
        if received.len() == 2 && receiver.ice.agent.state() == ConnectionState::Connected {
            break;
        }
        if !progressed {
            now += Duration::from_millis(20);
            receiver.handle(SessionInput::Timeout(now)).unwrap();
            peer.handle(SessionInput::Timeout(now)).unwrap();
        }
    }
    let recovered = receiver.ice.agent.state() == ConnectionState::Connected;
    let (mut receiver, receiver_closed) = receiver.close(now);
    let (mut peer, peer_closed) = peer.close(now);
    while receiver.poll().is_some() {}
    while peer.poll().is_some() {}
    let retired = receiver.gathering_state() == GatheringState::Closed
        && peer.gathering_state() == GatheringState::Closed;
    drop((receiver, peer));

    assert!(receiver_closed.is_ok() && peer_closed.is_ok() && retired);
    assert!(
        remained_live,
        "a transient ICE state retired the original session"
    );
    assert_eq!(received, vec![before.to_vec(), after.to_vec()]);
    assert_eq!(terminals, 0);
    assert!(recovered, "the original ICE agent did not recover");
}
