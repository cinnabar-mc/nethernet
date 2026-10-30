use super::*;
use crate::EgressPolicy;
use crate::transport::ice_io::tests::{target, tls_pair};
use rtc_turn::proto::{chandata::ChannelData, channum::ChannelNumber};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerTlsStream};

enum Peer {
    Tcp(TcpStream),
    Tls(Box<ServerTlsStream<TcpStream>>),
}

impl Peer {
    /// Shrinks the actual receiving kernel socket without changing any carrier readiness.
    fn limit_receive_buffer(&self) {
        let socket = match self {
            Self::Tcp(socket) => socket,
            Self::Tls(socket) => socket.get_ref().0,
        };
        socket2::SockRef::from(socket)
            .set_recv_buffer_size(1024)
            .unwrap();
    }

    /// Collects the actual plaintext accepted before the socket closes, including TLS truncation.
    async fn received(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let result = match self {
            Self::Tcp(socket) => socket.read_to_end(&mut bytes).await,
            Self::Tls(socket) => socket.read_to_end(&mut bytes).await,
        };
        if let Err(error) = result {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ));
        }
        bytes
    }
}

/// Both borrowed polling and cleanup flushing recheck retained TCP/TLS bytes at the physical write.
#[tokio::test]
async fn retained_tcp_and_tls_frames_do_not_flush_the_unsent_suffix_after_revocation() {
    for tls in [false, true] {
        for cleanup in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let remote = listener.local_addr().unwrap();
                let admitted = Arc::new(AtomicBool::new(true));
                let policy = {
                    let admitted = Arc::clone(&admitted);
                    EgressPolicy::new(move |_| admitted.load(Ordering::SeqCst))
                };
                let (server_tls, client_tls) = tls_pair();
                let security = if tls {
                    TurnStreamSecurity::Tls {
                        server_name: "localhost".into(),
                    }
                } else {
                    TurnStreamSecurity::Tcp
                };
                let connector = tls.then(|| {
                    (
                        TlsConnector::from(client_tls),
                        ServerName::try_from("localhost").unwrap(),
                    )
                });
                let mut carrier = Carrier::start(
                    &target(remote, security),
                    None,
                    connector,
                    transport_now() + Duration::from_secs(5),
                    Some(&policy),
                )
                .unwrap();
                let accept = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    if tls {
                        Peer::Tls(Box::new(
                            TlsAcceptor::from(server_tls).accept(socket).await.unwrap(),
                        ))
                    } else {
                        Peer::Tcp(socket)
                    }
                };
                let (mut peer, activated) =
                    tokio::join!(accept, futures::future::poll_fn(|cx| carrier.poll(cx)));
                assert!(matches!(activated, CarrierEvent::Activated(_)));
                carrier.set_send_buffer(1024);
                peer.limit_receive_buffer();
                let mut frame = ChannelData {
                    data: vec![0x5a; 60_000],
                    number: ChannelNumber(0x4000),
                    ..Default::default()
                };
                frame.encode();
                let mut admitted_bytes = Vec::new();
                let mut pending = false;
                for _ in 0..64 {
                    carrier.send(frame.raw.clone()).unwrap();
                    admitted_bytes.extend_from_slice(&frame.raw);
                    let mut borrowed = Box::pin(futures::future::poll_fn(|cx| carrier.poll(cx)));
                    let progress = futures::poll!(borrowed.as_mut());
                    drop(borrowed);
                    match progress {
                        Poll::Ready(CarrierEvent::Written) => {}
                        Poll::Pending => {
                            pending = true;
                            break;
                        }
                        _ => panic!("controlled carrier retired before real write pressure"),
                    }
                }
                assert!(
                    pending && carrier.kernel_blocked(),
                    "fixture did not retain an original frame under kernel pressure"
                );
                admitted.store(false, Ordering::SeqCst);
                if cleanup {
                    let error = carrier.flush_now().unwrap_err();
                    assert!(crate::transport::egress::is_denied(&error));
                } else {
                    assert!(matches!(
                        futures::future::poll_fn(|cx| carrier.poll(cx)).await,
                        CarrierEvent::Egress
                    ));
                }
                drop(carrier);
                let received = peer.received().await;
                assert!(
                    received.len() < admitted_bytes.len(),
                    "the retained suffix reached the revoked endpoint"
                );
                assert_eq!(received.as_slice(), &admitted_bytes[..received.len()]);
            })
            .await
            .expect("retained TURN output failed to respect physical egress revocation");
        }
    }
}
