//! Finite actual sockets drive the same frame owner, RTC peer and verified TLS engine.
use super::*;
use crate::connection::ActiveConnection;
use crate::outbound::tests::{advance, turn};
use crate::outbound::{ClientIceConfig, Outbound, State, prepare_turn_tls};
use nethernet::connection::{Connection, IceMode};
use nethernet::error::ProtocolError;
use nethernet::session::{Channel, IcePolicy, TurnAddressFamily, TurnCredentials};
use rtc::ice::candidate::CandidateType;
use rtc::stun::attributes::{ATTR_PADDING, RawAttribute};
use rtc::stun::message::{BINDING_REQUEST, Message, TransactionId};
use rtc_turn::proto::{
    chandata::ChannelData,
    channum::{ChannelNumber, MIN_CHANNEL_NUMBER},
};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;
use turn::{PASSWORD, TurnPeer, USER};

#[cfg(feature = "tls")]
#[path = "../../../tests/support/tls.rs"]
mod tls_support;

enum Security {
    Plain,
    #[cfg(feature = "tls")]
    Tls(std::sync::Arc<rustls::ServerConfig>),
}

struct Accepted {
    remote: SocketAddr,
    wire: Option<Wire>,
    decoder: TurnStreamDecoder,
    output: Option<(Vec<u8>, usize)>,
    split: bool,
}

struct Peer {
    listener: TcpListener,
    security: Security,
    connections: Vec<Accepted>,
    turn: TurnPeer,
}

impl Peer {
    /// Binds one real listener; the original TURN peer owns every protocol response.
    fn new(security: Security, ipv6: bool) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        socket2::SockRef::from(&listener)
            .set_recv_buffer_size(1024)
            .unwrap();
        let mut turn = TurnPeer::new(listener.local_addr().unwrap());
        turn.ipv6_relay = ipv6;
        Self {
            listener,
            security,
            connections: Vec::new(),
            turn,
        }
    }

    /// Advances bounded actual socket work with no task, thread, alternate codec or sleep.
    fn update(&mut self) {
        for _ in 0..nethernet::session::MAX_ICE_SERVERS {
            let (stream, remote) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("fixture accept failed: {error}"),
            };
            stream.set_nonblocking(true).unwrap();
            let wire = match &self.security {
                Security::Plain => Wire::plain(stream),
                #[cfg(feature = "tls")]
                Security::Tls(config) => {
                    let mut wire = Wire::tls(stream, config.clone());
                    wire.begin_session(Vec::new()).unwrap();
                    wire
                }
            };
            self.connections.push(Accepted {
                remote,
                wire: Some(wire),
                decoder: TurnStreamDecoder::new(),
                output: None,
                split: false,
            });
        }
        for connection in &mut self.connections {
            for _ in 0..crate::outbound::MAX_DATAGRAMS_PER_UPDATE {
                if let Some(message) = connection.decoder.next_message().unwrap() {
                    self.turn.receive(connection.remote, message);
                    continue;
                }
                let Some(wire) = &mut connection.wire else {
                    break;
                };
                let mut bytes = [0; READ_CHUNK];
                match wire.read_limited(&mut bytes) {
                    Ok((Inbound::Received, size)) => {
                        connection.decoder.extend_from_slice(&bytes[..size])
                    }
                    Ok((Inbound::Idle, _)) => break,
                    Ok((Inbound::Closed, _)) | Err(_) => {
                        connection.wire = None;
                        break;
                    }
                }
            }
            if connection.output.is_none()
                && let Some(index) = self
                    .turn
                    .packets
                    .iter()
                    .position(|(to, _)| *to == connection.remote)
            {
                let (_, bytes) = self.turn.packets.remove(index).unwrap();
                connection.output = Some((bytes, 0));
            }
            let (Some(wire), Some((bytes, written))) =
                (&mut connection.wire, &mut connection.output)
            else {
                continue;
            };
            // Split the first real response inside its STUN header across separate frame updates.
            let end = if !connection.split {
                (*written + 7).min(bytes.len())
            } else {
                bytes.len()
            };
            match wire.write(&bytes[*written..end]) {
                Ok(0) => panic!("fixture socket accepted no bytes"),
                Ok(size) => {
                    *written += size;
                    connection.split = true;
                }
                Err(WireError::Io(error)) if error.kind() == ErrorKind::WouldBlock => {}
                Err(_) => {
                    connection.wire = None;
                    continue;
                }
            }
            if *written == bytes.len() {
                connection.output = None;
            }
            if let Some(wire) = &mut connection.wire {
                let _ = wire.flush();
            }
        }
    }
}

/// Uses actual socket input, original long-term credentials and independently selected relay family.
fn config(peer: &Peer, family: Option<TurnAddressFamily>) -> ClientIceConfig {
    ClientIceConfig {
        bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ice: IceConfig {
            policy: IcePolicy::RelayOnly,
            ..Default::default()
        },
        turn_streams: vec![TurnStreamTarget {
            remote: peer.listener.local_addr().unwrap(),
            bind_ip: None,
            security: TurnStreamSecurity::Tcp,
            credentials: TurnCredentials::new(
                USER.into(),
                PASSWORD.into(),
                Instant::now() + Duration::from_secs(1200),
            )
            .unwrap(),
            requested_family: family,
        }],
        #[cfg(feature = "tls")]
        turn_tls: None,
    }
}

/// Completes real gathering, SCTP readiness, both original channels and physical retirement.
fn secured_pair(mut peer: Peer, config: ClientIceConfig, selected_pressure: bool) {
    let now = Instant::now();
    let within = Duration::from_secs(10);
    let cutoff = now + within;
    let tls = prepare_turn_tls(Some(&config)).unwrap();
    let mut client = Outbound::with_role(Some(&config), within, now, &tls, true).unwrap();
    let mut answerer = Outbound::with_role(Some(&config), within, now, &tls, false).unwrap();
    while Instant::now() < cutoff {
        peer.update();
        let now = Instant::now();
        client.update(now).unwrap();
        answerer.update(now).unwrap();
        if client.gathering_complete() && answerer.gathering_complete() {
            break;
        }
        std::thread::yield_now();
    }
    assert!(client.gathering_complete() && answerer.gathering_complete());
    assert_eq!(peer.turn.allocation_requests, 4);
    assert_eq!(peer.turn.allocation_count(), 2);
    for owner in [&client, &answerer] {
        let route = owner.streams.carriers[0].route.unwrap();
        assert_eq!(route.remote(), peer.listener.local_addr().unwrap());
        assert!(
            peer.connections
                .iter()
                .any(|connection| connection.remote == route.local())
        );
    }
    let now = Instant::now();
    let offer = client
        .connect(7, "peer".into(), IceMode::Full)
        .unwrap()
        .remove(0);
    let (remote, candidates) = Connection::parse_offer(&offer).unwrap();
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.candidate_type() == CandidateType::Relay)
            .count(),
        1
    );
    let Some(State::Gathering(session, description)) = answerer.state.get().take() else {
        panic!("original answerer is not gathering");
    };
    let (connection, answers) = Connection::accept(
        session,
        description,
        &offer,
        remote,
        candidates,
        IceMode::Full,
        now,
    )
    .unwrap();
    *answerer.state.get() = Some(State::Connected(ActiveConnection::new(connection)));
    for signal in answers {
        client.signal(signal, now).unwrap();
    }
    let (mut client_ready, mut answerer_ready) = (false, false);
    let (mut client_messages, mut answerer_messages) = (Vec::new(), Vec::new());
    while Instant::now() < cutoff {
        peer.update();
        let now = Instant::now();
        advance(&mut client, now, &mut client_ready, &mut client_messages);
        advance(
            &mut answerer,
            now,
            &mut answerer_ready,
            &mut answerer_messages,
        );
        if client_ready && answerer_ready {
            break;
        }
        std::thread::yield_now();
    }
    assert!(
        client_ready && answerer_ready,
        "actual two-channel readiness never arrived"
    );
    let route = client.streams.carriers[0].route.unwrap();
    assert_eq!(
        client.selected_turn_stream(),
        selected_pressure.then_some(route)
    );
    socket2::SockRef::from(client.streams.carriers[0].wire.as_ref().unwrap().socket())
        .set_send_buffer_size(1024)
        .unwrap();
    let mut padding = Message::new();
    padding
        .build(&[
            Box::new(TransactionId::new()),
            Box::new(BINDING_REQUEST),
            Box::new(RawAttribute {
                typ: ATTR_PADDING,
                value: vec![0; 60 * 1024],
                ..Default::default()
            }),
        ])
        .unwrap();
    for _ in 0..nethernet::session::MAX_ICE_SERVERS {
        client.streams.stage(padding.raw.clone(), route).unwrap();
        if client.streams.carriers[0].pending.is_some() {
            break;
        }
    }
    assert!(
        client.streams.carriers[0].pending.is_some(),
        "actual selected/unused socket pressure was not reached"
    );
    let admission = client.send(Channel::Reliable, b"pressure admission", Instant::now());
    if selected_pressure {
        assert!(
            matches!(admission, Err(ProtocolError::Io(ref error)) if error.kind() == ErrorKind::WouldBlock)
        );
        assert!(
            matches!(client.streams.carriers[0].phase, Phase::Active),
            "selected carrier was retired by normal output pressure"
        );
    } else {
        admission.unwrap();
        while Instant::now() < cutoff && answerer_messages.is_empty() {
            // The blocked unused TCP carrier receives no reader progress here; UDP must still work.
            let now = Instant::now();
            advance(&mut client, now, &mut client_ready, &mut client_messages);
            advance(
                &mut answerer,
                now,
                &mut answerer_ready,
                &mut answerer_messages,
            );
            std::thread::yield_now();
        }
        assert_eq!(
            answerer_messages.pop(),
            Some((Channel::Reliable, Box::from(&b"pressure admission"[..])))
        );
    }
    while Instant::now() < cutoff && client.streams.carriers[0].pending.is_some() {
        peer.update();
        let now = Instant::now();
        advance(&mut client, now, &mut client_ready, &mut client_messages);
        advance(
            &mut answerer,
            now,
            &mut answerer_ready,
            &mut answerer_messages,
        );
        std::thread::yield_now();
    }
    assert!(
        client.streams.carriers[0].pending.is_none(),
        "original per-carrier output remained blocked after peer progress"
    );
    let payload = vec![0x51; 50 * 1024];
    client
        .send(Channel::Reliable, &payload, Instant::now())
        .unwrap();
    answerer
        .send(Channel::Unreliable, b"reverse", Instant::now())
        .unwrap();
    while Instant::now() < cutoff {
        peer.update();
        let now = Instant::now();
        advance(&mut client, now, &mut client_ready, &mut client_messages);
        advance(
            &mut answerer,
            now,
            &mut answerer_ready,
            &mut answerer_messages,
        );
        if !client_messages.is_empty() && !answerer_messages.is_empty() {
            break;
        }
        std::thread::yield_now();
    }
    client.close(Instant::now());
    answerer.close(Instant::now());
    while Instant::now() < cutoff {
        peer.update();
        if peer
            .connections
            .iter()
            .all(|connection| connection.wire.is_none())
        {
            break;
        }
        std::thread::yield_now();
    }
    let physically_closed = peer
        .connections
        .iter()
        .all(|connection| connection.wire.is_none());
    drop(peer);
    assert_eq!(
        answerer_messages,
        vec![(Channel::Reliable, payload.into_boxed_slice())]
    );
    assert_eq!(
        client_messages,
        vec![(Channel::Unreliable, Box::from(&b"reverse"[..]))]
    );
    // Pressure can retire an unused carrier with an incomplete frame. Closing retires
    // our sockets; any allocation the relay has not deallocated keeps its server lease.
    assert!(
        physically_closed,
        "owned TCP sockets survived ordinary retirement"
    );
}

#[test]
fn frame_driven_tcp_turn_secures_both_channels_with_an_independent_ipv6_relay() {
    let peer = Peer::new(Security::Plain, true);
    let config = config(&peer, Some(TurnAddressFamily::Ipv6));
    secured_pair(peer, config, true);
}

#[test]
fn an_unused_blocked_turn_carrier_does_not_stop_actual_selected_udp_data() {
    let peer = Peer::new(Security::Plain, false);
    let mut config = config(&peer, None);
    config.ice.policy = IcePolicy::All;
    secured_pair(peer, config, false);
}

#[test]
fn actual_partial_turn_frame_resumes_at_its_original_offset() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(1024)
        .unwrap();
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(5);
    let target = TurnStreamTarget {
        remote: listener.local_addr().unwrap(),
        bind_ip: None,
        security: TurnStreamSecurity::Tcp,
        credentials: TurnCredentials::new(USER.into(), PASSWORD.into(), cutoff).unwrap(),
        requested_family: None,
    };
    let mut streams = Streams::open(
        &[target],
        None,
        &ClientTls::default(),
        &mut IceConfig::default(),
        now,
    )
    .unwrap();
    let (mut accepted, mut route) = (None, None);
    while Instant::now() < cutoff {
        if accepted.is_none() {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(true).unwrap();
                    accepted = Some(socket);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        }
        if let Some(Input::Activated(_, actual)) = streams.poll(Instant::now()) {
            route = Some(actual);
        }
        if accepted.is_some() && route.is_some() {
            break;
        }
        std::thread::yield_now();
    }
    let mut accepted = accepted.expect("actual listener did not accept the owned stream");
    let route = route.expect("actual connected tuple did not activate");
    assert_eq!(route.local(), accepted.peer_addr().unwrap());
    socket2::SockRef::from(streams.carriers[0].wire.as_ref().unwrap().socket())
        .set_send_buffer_size(1024)
        .unwrap();
    let mut encoded = ChannelData {
        number: ChannelNumber(MIN_CHANNEL_NUMBER),
        data: vec![0x5a; 60 * 1024],
        ..Default::default()
    };
    encoded.encode();
    let original = encoded.raw;
    let mut completed = 0;
    // No peer reads: the real socket must expose backpressure within this finite wire allowance.
    for _ in 0..nethernet::session::MAX_ICE_SERVERS {
        streams.stage(original.clone(), route).unwrap();
        if streams.carriers[0].pending.is_none() {
            completed += 1;
        } else {
            break;
        }
    }
    let blocked = streams.carriers[0].pending.is_some();
    let mut partial = streams.carriers[0]
        .pending
        .as_ref()
        .is_some_and(|frame| frame.written > 0 && frame.written < frame.bytes.len());
    let expected = completed + usize::from(blocked);
    let (mut received, mut identical) = (0, true);
    let mut decoder = TurnStreamDecoder::new();
    while Instant::now() < cutoff && (streams.carriers[0].pending.is_some() || received < expected)
    {
        let mut bytes = [0; READ_CHUNK];
        match accepted.read(&mut bytes) {
            Ok(0) => break,
            Ok(size) => decoder.extend_from_slice(&bytes[..size]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => panic!("fixture receive failed: {error}"),
        }
        while let Some(frame) = decoder.next_message().unwrap() {
            received += 1;
            identical &= frame == original;
        }
        streams.flush(Some(route));
        if let Some(frame) = &streams.carriers[0].pending {
            partial |= frame.written > 0 && frame.written < frame.bytes.len();
        }
        std::thread::yield_now();
    }
    let finished = streams.carriers[0].pending.is_none();
    streams.finish();
    drop(accepted);
    drop(listener);
    assert!(
        blocked,
        "the real socket never applied bounded write backpressure"
    );
    assert!(partial, "no actual partial byte offset was exercised");
    assert!(finished, "the original partial frame did not finish");
    assert_eq!(received, expected);
    assert!(
        identical,
        "resuming the actual owner duplicated or changed its frame prefix"
    );
    assert_eq!(decoder.buffered_len(), 0);
}

#[cfg(feature = "tls")]
#[test]
fn frame_driven_verified_tls_turn_secures_both_channels_and_closes_the_same_sockets() {
    let (server, verifier) = tls_support::self_signed_pair();
    let peer = Peer::new(Security::Tls(server), false);
    let mut config = config(&peer, None);
    config.turn_tls = Some(verifier);
    config.turn_streams[0].security = TurnStreamSecurity::Tls {
        server_name: "localhost".into(),
    };
    secured_pair(peer, config, true);
}

#[cfg(feature = "tls")]
#[test]
fn a_pending_tls_carrier_preserves_tcp_gathering_and_its_original_cutoff() {
    let stalled = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    stalled.set_nonblocking(true).unwrap();
    let (_, verifier) = tls_support::self_signed_pair();
    let mut peer = Peer::new(Security::Plain, false);
    let mut config = config(&peer, None);
    config.turn_tls = Some(verifier);
    let mut pending = config.turn_streams[0].clone();
    pending.remote = stalled.local_addr().unwrap();
    pending.security = TurnStreamSecurity::Tls {
        server_name: "localhost".into(),
    };
    config.turn_streams.insert(0, pending);
    let start = Instant::now();
    let cutoff = start + Duration::from_secs(5);
    let original = start + config.ice.gather_timeout;
    let tls = prepare_turn_tls(Some(&config)).unwrap();
    let mut client = Outbound::new(Some(&config), Duration::from_secs(30), start, &tls).unwrap();
    let mut accepted = None;
    while Instant::now() < cutoff {
        peer.update();
        client.update(start).unwrap();
        if accepted.is_none() {
            match stalled.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(true).unwrap();
                    accepted = Some(socket);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        }
        if accepted.is_some()
            && peer.turn.allocation_count() == 1
            && matches!(client.streams.carriers[0].phase, Phase::Handshaking)
        {
            break;
        }
        std::thread::yield_now();
    }
    let progressed = peer.turn.allocation_count() == 1;
    let was_pending = !client.gathering_complete()
        && matches!(client.streams.carriers[0].phase, Phase::Handshaking);
    client.update(original).unwrap();
    let completed = client.gathering_complete();
    let pending_closed = client.streams.carriers[0].wire.is_none();
    let preserved = peer.turn.allocation_count();
    client.close(original);
    while Instant::now() < cutoff && peer.turn.allocation_count() != 0 {
        peer.update();
        std::thread::yield_now();
    }
    let released = peer.turn.allocation_count();
    drop(accepted);
    drop(stalled);
    drop(peer);
    assert!(
        progressed,
        "a TLS handshake waiting for input starved the independent TCP allocation"
    );
    assert!(
        was_pending,
        "the actual TLS handshake was not pending under the original gather owner"
    );
    assert!(
        completed && pending_closed,
        "the original cutoff did not retire the stalled carrier"
    );
    assert_eq!(
        preserved, 1,
        "the unused TLS cutoff discarded a healthy TCP allocation"
    );
    assert_eq!(released, 0);
}

#[cfg(feature = "tls")]
#[test]
fn wrong_turn_tls_name_or_root_never_activates_an_allocation() {
    for wrong_name in [true, false] {
        let (server, verifier) = tls_support::self_signed_pair();
        let (_, stranger) = tls_support::self_signed_pair();
        let mut peer = Peer::new(Security::Tls(server), false);
        let mut config = config(&peer, None);
        config.turn_tls = Some(if wrong_name { verifier } else { stranger });
        config.turn_streams[0].security = TurnStreamSecurity::Tls {
            server_name: if wrong_name {
                "wrong.invalid"
            } else {
                "localhost"
            }
            .into(),
        };
        let start = Instant::now();
        let cutoff = start + Duration::from_secs(5);
        let tls = prepare_turn_tls(Some(&config)).unwrap();
        let mut client =
            Outbound::new(Some(&config), Duration::from_secs(10), start, &tls).unwrap();
        while Instant::now() < cutoff {
            peer.update();
            // The original core clock cannot expire; only actual verified-carrier failure can finish gathering.
            client.update(start).unwrap();
            if client.gathering_complete() {
                break;
            }
            std::thread::yield_now();
        }
        let completed = client.gathering_complete();
        client.close(start);
        let requests = peer.turn.allocation_requests;
        drop(peer);
        assert!(
            completed,
            "actual TLS refusal did not retire its pending original target"
        );
        assert_eq!(
            requests, 0,
            "unverified TLS activated the original TURN client"
        );
    }
}

#[cfg(feature = "tls")]
mod reconfiguration;
