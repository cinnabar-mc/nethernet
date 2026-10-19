//! Configured HTTP gathering and cancellation over actual loopback UDP/TCP, without a runtime.
#[path = "../../nethernet/tests/support/turn.rs"]
mod turn;
use bevy_nethernet::prelude::*;
use nethernet::identity::{TokenTrust, validate_sdp};
use nethernet::protocol::webrtc::Description;
use nethernet::session::{IceConfig, IcePolicy, IceServer, TurnCredentials};
use rtc::ice::candidate::CandidateType;
use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::{Duration, Instant, SystemTime};
use turn::{PASSWORD, TurnPeer, USER};

#[test]
fn http_offer_is_signed_after_relay_gathering_and_disconnect_releases_the_allocation() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_nonblocking(true).unwrap();
    let mut turn = TurnPeer::new(udp.local_addr().unwrap());
    let mut client = NetherHttpClient::new();
    client.set_identity(ServerIdentity::generate("frame-client", SystemTime::now()).unwrap());
    client.set_ice_config(Some(ClientIceConfig {
        bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        turn_streams: Vec::new(),
        #[cfg(feature = "tls")]
        turn_tls: None,
        ice: IceConfig {
            servers: vec![IceServer::Turn(
                turn.addr,
                TurnCredentials::new(
                    USER.into(),
                    PASSWORD.into(),
                    Instant::now() + Duration::from_secs(1200),
                )
                .unwrap(),
            )],
            policy: IcePolicy::RelayOnly,
            ..Default::default()
        },
    }));
    client
        .connect(
            "configured-frame-client".into(),
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "HTTP started before relay gathering was driven"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = None;
    let mut request = Vec::new();
    let mut buffer = [0; 65536];
    let mut offer = None;
    while Instant::now() < deadline {
        client.update();
        while let Ok((size, from)) = udp.recv_from(&mut buffer) {
            turn.receive(from, buffer[..size].to_vec());
        }
        while let Some((to, data)) = turn.packets.pop_front() {
            udp.send_to(&data, to).unwrap();
        }
        if stream.is_none()
            && let Ok((accepted, _)) = listener.accept()
        {
            accepted.set_nonblocking(true).unwrap();
            stream = Some(accepted);
        }
        if let Some(stream) = &mut stream {
            match stream.read(&mut buffer) {
                Ok(size) => request.extend_from_slice(&buffer[..size]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("HTTP receive failed: {error}"),
            }
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut parsed = httparse::Request::new(&mut headers);
            if let httparse::Status::Complete(offset) = parsed.parse(&request).unwrap() {
                let length: usize = parsed
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                    .map(|header| std::str::from_utf8(header.value).unwrap().parse().unwrap())
                    .unwrap();
                if request.len() >= offset + length {
                    offer =
                        Some(String::from_utf8(request[offset..offset + length].to_vec()).unwrap());
                    break;
                }
            }
        }
        std::thread::yield_now();
    }
    let offer = offer.expect("configured Full HTTP offer never arrived");
    let (_, candidates) = Description::parse(&offer).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].candidate_type(), CandidateType::Relay);
    validate_sdp(&offer, &TokenTrust::Any, SystemTime::now()).unwrap();
    assert_eq!(turn.allocation_count(), 1);
    client.disconnect();
    while Instant::now() < deadline && turn.allocation_count() != 0 {
        while let Ok((size, from)) = udp.recv_from(&mut buffer) {
            turn.receive(from, buffer[..size].to_vec());
        }
        client.update();
        std::thread::yield_now();
    }
    assert_eq!(
        turn.allocation_count(),
        0,
        "HTTP cancellation retained a known relay allocation"
    );
    assert!(!client.is_connected());
    assert!(client.recv().is_none());
}
