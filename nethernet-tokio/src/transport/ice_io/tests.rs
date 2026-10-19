//! Finite actual TURN sockets, original RTC transactions and the original session actor.
mod lifecycle;
mod pressure;
#[path = "../../../../nethernet/tests/support/turn.rs"]
mod turn;
use super::*;
use crate::addr::Addr;
use crate::session::Session as RuntimeSession;
use crate::session::guard::GatheringGuard;
use bytes::Bytes;
use nethernet::connection::{Connection, ConnectionInput, IceMode};
use nethernet::phase::Connecting;
use nethernet::sans::Sans;
use nethernet::session::{IcePolicy, Session, TurnCredentials, TurnStreamSecurity};
use rtc::shared::turn_framing::TurnStreamDecoder;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::sync::CancellationToken;

pub(super) fn target(remote: SocketAddr, security: TurnStreamSecurity) -> TurnStreamTarget {
    TurnStreamTarget {
        remote,
        security,
        bind_ip: None,
        requested_family: None,
        credentials: TurnCredentials::new(
            turn::USER.into(),
            turn::PASSWORD.into(),
            transport_now() + Duration::from_secs(1200),
        )
        .unwrap(),
    }
}

pub(super) fn tls_pair() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![issued.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der())),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(issued.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

enum TestWire {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}
struct TurnWire {
    stream: TestWire,
    decoder: TurnStreamDecoder,
    remote: SocketAddr,
}
impl TurnWire {
    async fn accept(stream: TcpStream, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let remote = stream.peer_addr().unwrap();
        let stream = match tls {
            Some(config) => TestWire::Tls(Box::new(
                TlsAcceptor::from(config).accept(stream).await.unwrap(),
            )),
            None => TestWire::Tcp(stream),
        };
        Self {
            stream,
            decoder: TurnStreamDecoder::new(),
            remote,
        }
    }
    async fn frame(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(frame) = self.decoder.next_message().unwrap() {
                return Some(frame);
            }
            let mut bytes = [0; 4096];
            let read = match &mut self.stream {
                TestWire::Tcp(stream) => stream.read(&mut bytes).await,
                TestWire::Tls(stream) => stream.read(&mut bytes).await,
            };
            let size = match read {
                Ok(size) => size,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return None;
                }
                Err(error) => panic!("controlled TURN read failed: {error}"),
            };
            if size == 0 {
                return None;
            }
            self.decoder.extend_from_slice(&bytes[..size]);
        }
    }
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.stream {
            TestWire::Tcp(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            TestWire::Tls(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
        }
    }
}

/// Only the original TurnPeer processes/authenticates/forwards messages; this helper owns two sockets.
async fn service_pair(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    done: CancellationToken,
    refreshed: tokio::sync::oneshot::Sender<()>,
) {
    let mut turn = turn::TurnPeer::new(listener.local_addr().unwrap());
    turn.ipv6_relay = turn.addr.is_ipv6();
    let mut refreshed = Some(refreshed);
    let mut nonzero_refreshes = 0;
    let (first, _) = listener.accept().await.unwrap();
    let (second, _) = listener.accept().await.unwrap();
    let (first, second) = tokio::join!(
        TurnWire::accept(first, tls.clone()),
        TurnWire::accept(second, tls)
    );
    let mut peers = [first, second];
    'serve: loop {
        let (first, second) = peers.split_at_mut(1);
        let (index, packet) = tokio::select! {
            biased;
            _ = done.cancelled() => break,
            frame = first[0].frame() => (0, frame),
            frame = second[0].frame() => (1, frame),
        };
        let Some(packet) = packet else {
            break;
        };
        let previous_refreshes = turn.refreshes;
        turn.receive(peers[index].remote, packet);
        if turn.refreshes > previous_refreshes
            && turn
                .last_refresh_lifetime
                .is_some_and(|lifetime| !lifetime.is_zero())
        {
            nonzero_refreshes += 1;
        }
        while let Some((to, bytes)) = turn.packets.pop_front() {
            if peers
                .iter_mut()
                .find(|peer| peer.remote == to)
                .unwrap()
                .write(&bytes)
                .await
                .is_err()
            {
                // Original close does not wait for a TURN deallocation ACK. Any earlier failure
                // still leaves the actual pair unable to complete its secured data assertions.
                break 'serve;
            }
        }
        if nonzero_refreshes >= 2
            && turn
                .last_refresh_lifetime
                .is_some_and(|lifetime| !lifetime.is_zero())
        {
            assert_eq!(
                turn.allocation_count(),
                2,
                "refresh replaced an original allocation"
            );
            if let Some(refreshed) = refreshed.take() {
                let _ = refreshed.send(());
            }
        }
    }
    assert_eq!(
        nonzero_refreshes, 2,
        "unadmitted/abandoned renewal dispatched an extra actual Refresh"
    );
    assert_eq!(
        turn.allocation_requests, 4,
        "each socket must perform both actual Allocate attempts"
    );
    assert!(
        turn.indications + turn.channel_data > 0,
        "secured peer data never used the TURN carrier"
    );
}

async fn secured_actor_pair(listener: TcpListener, tls: bool) {
    let addr = listener.local_addr().unwrap();
    let (server_tls, client_tls) = tls_pair();
    let security = if tls {
        TurnStreamSecurity::Tls {
            server_name: "localhost".into(),
        }
    } else {
        TurnStreamSecurity::Tcp
    };
    let done = CancellationToken::new();
    let (refreshed, renewal_observed) = tokio::sync::oneshot::channel();
    let service = service_pair(listener, tls.then_some(server_tls), done.clone(), refreshed);
    let pair = async {
        let mut gathered = Vec::new();
        for controlling in [true, false] {
            // Explicit wildcard UDP is deliberately not a TCP interface selection.
            let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
            let config = IceConfig {
                policy: IcePolicy::RelayOnly,
                ..Default::default()
            };
            let (io, config) = IceIo::configured(
                udp.clone(),
                &config,
                &[target(addr, security.clone())],
                tls.then_some(&client_tls),
                Some(udp.local_addr().unwrap().ip()),
                transport_now(),
                transport_now() + Duration::from_secs(5),
            )
            .unwrap();
            assert!(
                io.streams[0].1.route.is_none(),
                "pending target acquired a fabricated route"
            );
            let (core, description) = Session::new_with_ice(
                udp.local_addr().unwrap(),
                controlling,
                rand::random(),
                config,
                transport_now(),
            )
            .unwrap();
            gathered.push((GatheringGuard::new(core, io), description));
        }
        let (first, second) = gathered.split_at_mut(1);
        let first = &mut first[0].0;
        let second = &mut second[0].0;
        // Separate original cores share no mutable service state or socket owner.
        tokio::try_join!(
            crate::transport::gather::gather(
                first.io.as_mut().unwrap(),
                first.core.as_mut().unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(5)
            ),
            crate::transport::gather::gather(
                second.io.as_mut().unwrap(),
                second.core.as_mut().unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(5)
            )
        )
        .unwrap();
        let (mut b, b_description) = gathered.pop().unwrap();
        let (mut a, a_description) = gathered.pop().unwrap();
        let (mut a_core, offers) = Connection::connect(
            a.core.take().unwrap(),
            a_description,
            1,
            "peer".into(),
            IceMode::Full,
        );
        let (remote, candidates) = Connection::parse_offer(&offers[0]).unwrap();
        let (b_core, answers) = Connection::accept(
            b.core.take().unwrap(),
            b_description,
            &offers[0],
            remote,
            candidates,
            IceMode::Full,
            transport_now(),
        )
        .unwrap();
        a_core
            .handle(ConnectionInput::Signal(answers[0].clone(), transport_now()))
            .unwrap();
        let a_route = a.io.as_ref().unwrap().streams[0].1.route.unwrap();
        let b_route = b.io.as_ref().unwrap().streams[0].1.route.unwrap();
        let (a, mut a_rx, _a_unreliable, a_ready) = RuntimeSession::<Connecting>::spawn(
            a.io.take().unwrap(),
            a_core,
            Addr::default(),
            Addr::default(),
        );
        let (b, mut b_rx, _b_unreliable, b_ready) = RuntimeSession::<Connecting>::spawn(
            b.io.take().unwrap(),
            b_core,
            Addr::default(),
            Addr::default(),
        );
        let (a_ready, b_ready) = tokio::try_join!(a_ready, b_ready).unwrap();
        let a = a.establish(a_ready);
        let b = b.establish(b_ready);
        for (session, expected) in [(&a, a_route), (&b, b_route)] {
            let (reply, selected) = tokio::sync::oneshot::channel();
            session
                .signal_sender()
                .send(crate::session::Command::SelectedTurnStream(reply))
                .await
                .unwrap();
            assert_eq!(
                selected.await.unwrap(),
                Some(expected),
                "actual Ready actor selected a different carrier than its retained socket"
            );
        }
        let renewal_deadline = transport_now() + Duration::from_secs(5);
        let (reply, outcome) = tokio::sync::oneshot::channel();
        a.signal_sender()
            .send(crate::session::Command::TurnStreamCredentials(
                vec![target(addr, security.clone())],
                transport_now(),
                reply,
            ))
            .await
            .unwrap();
        assert!(
            matches!(
                outcome.await.unwrap(),
                Err(crate::error::NetherError::Timeout)
            ),
            "actor admitted an expired queued stream renewal"
        );
        let (reply, abandoned) = tokio::sync::oneshot::channel();
        drop(abandoned);
        a.signal_sender()
            .send(crate::session::Command::TurnStreamCredentials(
                vec![target(addr, security.clone())],
                renewal_deadline,
                reply,
            ))
            .await
            .unwrap();
        assert!(
            a.update_turn_streams_before(Vec::new(), renewal_deadline)
                .await
                .is_err(),
            "missing selected replacement reported success"
        );
        assert!(
            a.update_turn_streams_before(
                vec![
                    target(addr, security.clone()),
                    target(addr, security.clone())
                ],
                renewal_deadline
            )
            .await
            .is_err(),
            "ambiguous selected replacements reported success"
        );
        assert!(
            matches!(
                a.update_turn_streams_before(vec![target(addr, security.clone())], transport_now())
                    .await,
                Err(crate::error::NetherError::Timeout)
            ),
            "expired original cutoff admitted renewal"
        );
        let mut replacement = target(addr, security.clone());
        replacement.bind_ip = Some(std::net::Ipv4Addr::LOCALHOST.into());
        assert!(
            a.update_turn_streams_before(vec![replacement], renewal_deadline)
                .await
                .is_err(),
            "changed source policy rotated an existing socket"
        );
        let mut replacement = target(addr, security.clone());
        replacement.credentials = TurnCredentials::new(
            "different allocation user".into(),
            turn::PASSWORD.into(),
            transport_now() + Duration::from_secs(1200),
        )
        .unwrap();
        assert!(
            a.update_turn_streams_before(vec![replacement], renewal_deadline)
                .await
                .is_err(),
            "changed username moved an existing allocation"
        );
        let mut replacement = target(addr, security.clone());
        replacement.credentials =
            TurnCredentials::new(turn::USER.into(), turn::PASSWORD.into(), transport_now())
                .unwrap();
        assert!(
            a.update_turn_streams_before(vec![replacement], renewal_deadline)
                .await
                .is_err(),
            "expired replacement entered the actual core"
        );
        a.update_turn_streams_before(vec![target(addr, security.clone())], renewal_deadline)
            .await
            .unwrap();
        b.update_turn_streams_before(vec![target(addr, security.clone())], renewal_deadline)
            .await
            .unwrap();
        renewal_observed
            .await
            .expect("same socket service did not observe both actual Refresh requests");
        for (session, expected) in [(&a, a_route), (&b, b_route)] {
            let (reply, selected) = tokio::sync::oneshot::channel();
            session
                .signal_sender()
                .send(crate::session::Command::SelectedTurnStream(reply))
                .await
                .unwrap();
            assert_eq!(
                selected.await.unwrap(),
                Some(expected),
                "renewal replaced the actual original socket"
            );
        }
        a.send(Bytes::from_static(
            b"same retained TURN socket after gathering",
        ))
        .await
        .unwrap();
        assert_eq!(
            b_rx.recv().await.unwrap().unwrap(),
            "same retained TURN socket after gathering"
        );
        b.send(Bytes::from_static(b"verified original actor reply"))
            .await
            .unwrap();
        assert_eq!(
            a_rx.recv().await.unwrap().unwrap(),
            "verified original actor reply"
        );
        a.sender().close().await.unwrap();
        b.sender().close().await.unwrap();
        done.cancel();
    };
    tokio::join!(service, pair);
}

#[tokio::test]
async fn tcp_and_verified_tls_turn_keep_original_sockets_through_actor_and_refresh() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for tls in [false, true] {
            let listener = match TcpListener::bind(bind).await {
                Ok(listener) => listener,
                Err(error)
                    if bind.starts_with('[')
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                        ) =>
                {
                    eprintln!("missing fixture: IPv6 loopback TCP ({error})");
                    continue;
                }
                Err(error) => panic!("controlled loopback listener unavailable: {error}"),
            };
            tokio::time::timeout(Duration::from_secs(10), secured_actor_pair(listener, tls))
                .await
                .expect("finite actual TURN actor pair stalled");
        }
    }
}
