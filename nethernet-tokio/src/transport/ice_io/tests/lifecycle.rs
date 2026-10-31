use super::*;
use nethernet::session::TurnStreamId;
use rtc_turn::proto::{chandata::ChannelData, channum::ChannelNumber};

fn frame(body: &[u8]) -> Vec<u8> {
    let mut frame = ChannelData {
        data: body.to_vec(),
        number: ChannelNumber(0x4000),
        ..Default::default()
    };
    frame.encode();
    frame.raw
}

#[tokio::test]
async fn pending_tls_keeps_udp_and_another_stream_live_and_retires_at_original_cutoff() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ready = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let (_server_tls, client_tls) = tls_pair();
        let targets = [target(held.local_addr().unwrap(), TurnStreamSecurity::Tls { server_name: "localhost".into() }), target(ready.local_addr().unwrap(), TurnStreamSecurity::Tcp)];
        let deadline = transport_now() + Duration::from_secs(5);
        let (mut io, _) = IceIo::from(udp.clone()).configured( &IceConfig::default(), &targets, Some(&client_tls), None, transport_now(), deadline).unwrap();
        let activation = async {
            loop {
                match io.next().await.unwrap() {
                    IceEvent::Activated(id, route) => { assert_eq!(id, TurnStreamId::new(1).unwrap()); break route; },
                    IceEvent::Closed(_) => panic!("pending target retired before its original cutoff"),
                    _ => {},
                }
            }
        };
        let (held, ready, route) = tokio::join!(held.accept(), ready.accept(), activation);
        let (mut held, _) = held.unwrap();
        let (mut ready, _) = ready.unwrap();
        assert_eq!(route.local(), ready.peer_addr().unwrap());
        assert_eq!(route.remote(), ready.local_addr().unwrap());
        assert!(!route.local().ip().is_unspecified());
        let mut first_tls_byte = [0; 1];
        {
        let handshake = async { held.read_exact(&mut first_tls_byte).await.unwrap(); };
        let drive = async {
            loop {
                match io.next().await.unwrap() {
                    IceEvent::Activated(id, _) => panic!("unverified held TLS activated: {id:?}"),
                    IceEvent::Closed(_) => panic!("held TLS retired before original cutoff"),
                    _ => {},
                }
            }
        };
        tokio::pin!(handshake, drive);
        tokio::select! { biased; _ = &mut handshake => {}, _ = &mut drive => unreachable!() }
        }

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"original UDP remains live", SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), udp.local_addr().unwrap().port())).await.unwrap();
        loop {
            match io.next().await.unwrap() {
                IceEvent::Datagram(bytes, from) => { assert_eq!(&*bytes, b"original UDP remains live"); assert_eq!(from, sender.local_addr().unwrap()); break; },
                IceEvent::Activated(id, _) => panic!("unverified TLS target activated: {id:?}"),
                IceEvent::Closed(_) => panic!("target retired before controlled cutoff"),
                _ => {},
            }
        }
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(transport_now())).await;
        assert!(matches!(io.next().await.unwrap(), IceEvent::Closed(id) if id == TurnStreamId::new(0).unwrap()));
        tokio::time::resume();
        let original = frame(b"no replay after a borrowed poll is canceled");
        io.send_stream(original.clone(), route, Some(route)).unwrap();
        let mut borrowed = Box::pin(io.next());
        // The borrowed wait can be abandoned; the original frame/cursor belongs to IceIo.
        let first = futures::poll!(borrowed.as_mut());
        drop(borrowed);
        if first.is_pending() {
            loop { if matches!(io.next().await.unwrap(), IceEvent::Written) { break; } }
        }
        let mut received = vec![0; original.len()];
        ready.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, &*original);
        drop(io);
        let mut tail = Vec::new();
        ready.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty(), "the canceled borrowed wait replayed the original frame");
        // Pending TLS's same original socket also retires; its ClientHello is not TURN/auth output.
        let mut handshake_prefix = Vec::new();
        held.read_to_end(&mut handshake_prefix).await.unwrap();
        assert_ne!(first_tls_byte[0], 0, "held target emitted no actual TLS handshake prefix");
    }).await.expect("finite stalled TLS isolation control stalled");
}

#[tokio::test]
async fn tls_requires_the_original_name_and_configured_roots_before_activation() {
    for trusted in [true, false] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (server_tls, trusted_tls) = tls_pair();
            let client_tls = if trusted {
                trusted_tls
            } else {
                Arc::new(
                    rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
                )
            };
            let name = if trusted {
                "wrong.invalid"
            } else {
                "localhost"
            };
            let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let target = target(
                listener.local_addr().unwrap(),
                TurnStreamSecurity::Tls {
                    server_name: name.into(),
                },
            );
            let (mut io, _) = IceIo::from(udp)
                .configured(
                    &IceConfig::default(),
                    &[target],
                    Some(&client_tls),
                    None,
                    transport_now(),
                    transport_now() + Duration::from_secs(5),
                )
                .unwrap();
            let accept = async {
                let (socket, _) = listener.accept().await.unwrap();
                TlsAcceptor::from(server_tls).accept(socket).await
            };
            let (event, server) = tokio::join!(io.next(), accept);
            assert!(
                matches!(event.unwrap(), IceEvent::Closed(_)),
                "failed certificate verification published a usable route"
            );
            assert!(
                server.is_err(),
                "the controlled wrong authority/trust handshake succeeded"
            );
        })
        .await
        .expect("finite certificate rejection control stalled");
    }
}

/// Reset while a selected frame is retained is carrier retirement, not caller backpressure misuse.
#[tokio::test]
async fn selected_stream_reset_during_flush_retires_the_carrier() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (mut io, _) = IceIo::from(udp)
            .configured(
                &IceConfig::default(),
                &[target(
                    listener.local_addr().unwrap(),
                    TurnStreamSecurity::Tcp,
                )],
                None,
                None,
                transport_now(),
                transport_now() + Duration::from_secs(5),
            )
            .unwrap();
        let (accepted, event) = tokio::join!(listener.accept(), io.next());
        let (peer, _) = accepted.unwrap();
        let IceEvent::Activated(_, route) = event.unwrap() else {
            panic!("carrier did not activate")
        };
        io.streams[0].1.set_send_buffer(1024);
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(1024)
            .unwrap();
        let payload = frame(&vec![0x5a; 60_000]);
        for _ in 0..4096 {
            io.send_stream(payload.clone(), route, Some(route)).unwrap();
            if !io.streams[0].1.flush_now().unwrap() {
                break;
            }
        }
        assert!(io.streams[0].1.blocked(), "fixture never retained a frame");
        socket2::SockRef::from(&peer)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(peer);
        io.streams[0].1.socket().readable().await.unwrap();
        let result = io.send_stream(frame(b"after reset"), route, Some(route));
        assert!(
            result.is_ok(),
            "reset was reported as backpressure: {result:?}"
        );
        assert!(matches!(io.next().await.unwrap(), IceEvent::Closed(_)));
    })
    .await
    .expect("selected reset fixture stalled");
}
