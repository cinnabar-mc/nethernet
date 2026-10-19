//! One retained connection, TLS handshake, TURN decoder and partial write.
use crate::error::{NetherError, Result};
use crate::session::guard::transport_now;
use nethernet::session::{
    MAX_TURN_STREAM_FRAME_BYTES, TurnStreamRoute, TurnStreamSecurity, TurnStreamTarget,
};
use rtc::shared::turn_framing::TurnStreamDecoder;
use rustls::pki_types::ServerName;
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

pub(super) enum CarrierEvent {
    Activated(TurnStreamRoute),
    Frame(Box<[u8]>),
    Closed,
    Written,
}

enum State {
    Connecting(TcpStream, Option<(TlsConnector, ServerName<'static>)>),
    Handshaking(Pin<Box<tokio_rustls::Connect<TcpStream>>>),
    Active(Wire),
    Closed,
}

enum Wire {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Wire {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buffer),
        }
    }
    fn poll_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, data),
        }
    }
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }
}

pub(super) struct Carrier {
    pub route: Option<TurnStreamRoute>,
    remote: SocketAddr,
    state: State,
    deadline: Instant,
    decoder: TurnStreamDecoder,
    write: Option<(Box<[u8]>, usize)>,
}

impl Carrier {
    /// Starts one nonblocking socket; the tuple is captured only after TCP actually connects.
    pub fn start(
        target: &TurnStreamTarget,
        fallback: Option<IpAddr>,
        tls: Option<(TlsConnector, ServerName<'static>)>,
        caller_deadline: Instant,
    ) -> Result<Self> {
        let deadline = target.admission_deadline(caller_deadline);
        if transport_now() >= deadline {
            return Err(NetherError::Timeout);
        }
        let socket = Socket::new(
            Domain::for_address(target.remote),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        if let Some(ip) = target
            .local_bind_ip(fallback)
            .map_err(nethernet::error::ProtocolError::from)?
        {
            socket.bind(&SocketAddr::new(ip, 0).into())?;
        }
        match socket.connect(&target.remote.into()) {
            Ok(()) => {}
            Err(error) if connect_in_progress(&error) => {}
            Err(error) => return Err(error.into()),
        }
        let stream = TcpStream::from_std(socket.into())?;
        Ok(Self {
            route: None,
            remote: target.remote,
            state: State::Connecting(stream, tls),
            deadline,
            decoder: TurnStreamDecoder::new(),
            write: None,
        })
    }

    pub fn blocked(&self) -> bool {
        self.write.is_some()
    }

    /// Retains exactly the original frame until its complete write and flush; never appends a queue.
    pub fn send(&mut self, data: Box<[u8]>) -> Result<()> {
        if data.len() > MAX_TURN_STREAM_FRAME_BYTES || self.write.is_some() {
            return Err(NetherError::InvalidState(
                "TURN stream output exceeds its retained frame".into(),
            ));
        }
        if !matches!(self.state, State::Active(_)) {
            return Err(NetherError::ConnectionClosed);
        }
        self.write = Some((data, 0));
        Ok(())
    }

    pub fn setup_deadline(&self) -> Option<Instant> {
        matches!(self.state, State::Connecting(..) | State::Handshaking(_)).then_some(self.deadline)
    }

    /// A canceled borrowed poll never abandons the connection, handshake or write cursor.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<CarrierEvent> {
        match self.poll_inner(cx) {
            Poll::Ready(Ok(event)) => Poll::Ready(event),
            Poll::Ready(Err(error)) => {
                tracing::debug!(%error, "TURN stream retired");
                self.state = State::Closed;
                self.write = None;
                self.decoder = TurnStreamDecoder::new();
                Poll::Ready(CarrierEvent::Closed)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<CarrierEvent>> {
        if self
            .setup_deadline()
            .is_some_and(|deadline| transport_now() >= deadline)
        {
            return Poll::Ready(Err(NetherError::Timeout));
        }
        if let State::Connecting(stream, _) = &mut self.state {
            ready!(stream.poll_write_ready(cx))?;
            if let Some(error) = stream.take_error()? {
                return Poll::Ready(Err(error.into()));
            }
            if stream.peer_addr()? != self.remote {
                return Poll::Ready(Err(io::Error::other(
                    "TCP remote changed during connection",
                )
                .into()));
            }
            let route = TurnStreamRoute::new(stream.local_addr()?, stream.peer_addr()?)
                .map_err(nethernet::error::ProtocolError::from)?;
            self.route = Some(route);
            let State::Connecting(stream, tls) = std::mem::replace(&mut self.state, State::Closed)
            else {
                unreachable!()
            };
            // The connector/name are taken before moving the original stream.
            self.state = match tls {
                Some((connector, name)) => {
                    State::Handshaking(Box::pin(connector.connect(name, stream)))
                }
                None => State::Active(Wire::Tcp(stream)),
            };
            if matches!(self.state, State::Active(_)) {
                return Poll::Ready(Ok(CarrierEvent::Activated(
                    self.route.expect("connected stream retains actual tuple"),
                )));
            }
        }
        if let State::Handshaking(handshake) = &mut self.state {
            let stream = ready!(handshake.as_mut().poll(cx))?;
            if transport_now() >= self.deadline {
                return Poll::Ready(Err(NetherError::Timeout));
            }
            self.state = State::Active(Wire::Tls(Box::new(stream)));
            return Poll::Ready(Ok(CarrierEvent::Activated(
                self.route.expect("connected stream retains actual tuple"),
            )));
        }
        let State::Active(wire) = &mut self.state else {
            return Poll::Pending;
        };
        if let Some((data, offset)) = &mut self.write {
            // One bounded frame per poll. A partial write remains owned on Pending.
            while *offset < data.len() {
                match wire.poll_write(cx, &data[*offset..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()));
                    }
                    Poll::Ready(Ok(size)) => *offset += size,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => break,
                }
            }
            if *offset == data.len() {
                match wire.poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.write = None;
                        return Poll::Ready(Ok(CarrierEvent::Written));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
            }
        }
        if let Some(frame) = self
            .decoder
            .next_message()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            return Poll::Ready(Ok(CarrierEvent::Frame(frame.into_boxed_slice())));
        }
        let remaining = MAX_TURN_STREAM_FRAME_BYTES.saturating_sub(self.decoder.buffered_len());
        if remaining == 0 {
            return Poll::Ready(Err(
                io::Error::other("TURN stream frame exceeded bound").into()
            ));
        }
        let mut bytes = [0; 4096];
        let limit = remaining.min(bytes.len());
        let mut buffer = ReadBuf::new(&mut bytes[..limit]);
        ready!(wire.poll_read(cx, &mut buffer))?;
        if buffer.filled().is_empty() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
        }
        self.decoder.extend_from_slice(buffer.filled());
        // Re-polling is bounded by the complete frame limit; register another turn for partial input.
        cx.waker().wake_by_ref();
        match self
            .decoder
            .next_message()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            Some(frame) => Poll::Ready(Ok(CarrierEvent::Frame(frame.into_boxed_slice()))),
            None => Poll::Pending,
        }
    }
}

fn connect_in_progress(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Parses all original authorities before opening any TCP socket.
pub(super) fn tls_names(targets: &[TurnStreamTarget]) -> Result<Vec<Option<ServerName<'static>>>> {
    targets
        .iter()
        .map(|target| match &target.security {
            TurnStreamSecurity::Tcp => Ok(None),
            TurnStreamSecurity::Tls { server_name } => ServerName::try_from(server_name.clone())
                .map(Some)
                .map_err(|_| NetherError::Ice("invalid TURN TLS authority".into())),
        })
        .collect()
}

pub(super) fn platform_config() -> Result<Arc<rustls::ClientConfig>> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_platform_verifier()
        .map_err(io::Error::other)?
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ice_io::tests::{target, tls_pair};
    use rtc_turn::proto::{chandata::ChannelData, channum::ChannelNumber};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
    async fn actual_split_and_coalesced_frames_survive_a_canceled_borrow_without_replay() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = target(listener.local_addr().unwrap(), TurnStreamSecurity::Tcp);
            let mut carrier = Carrier::start(
                &target,
                None,
                None,
                transport_now() + Duration::from_secs(5),
            )
            .unwrap();
            let (accepted, activated) = tokio::join!(
                listener.accept(),
                futures::future::poll_fn(|cx| carrier.poll(cx))
            );
            let (mut peer, _) = accepted.unwrap();
            let CarrierEvent::Activated(route) = activated else {
                panic!("actual TCP carrier did not activate");
            };
            assert_eq!(route.local(), peer.peer_addr().unwrap());
            assert_eq!(route.remote(), peer.local_addr().unwrap());
            let first = frame(b"first original frame");
            let second = frame(b"second original frame");
            peer.write_all(&first[..3]).await.unwrap();
            // Explicitly observe the real decoder holding the incomplete prefix before releasing its tail.
            futures::future::poll_fn(|cx| {
                assert!(
                    carrier.poll(cx).is_pending(),
                    "incomplete wire prefix produced an event"
                );
                if carrier.decoder.buffered_len() == 3 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let mut borrowed = Box::pin(futures::future::poll_fn(|cx| carrier.poll(cx)));
            assert!(futures::poll!(borrowed.as_mut()).is_pending());
            drop(borrowed);
            let combined = [&first[3..], second.as_slice()].concat();
            peer.write_all(&combined).await.unwrap();
            for expected in [&first, &second] {
                let event = futures::future::poll_fn(|cx| carrier.poll(cx)).await;
                let CarrierEvent::Frame(received) = event else {
                    panic!("valid original TURN frame was lost");
                };
                assert_eq!(&*received, expected);
            }
            let outgoing = frame(b"one original output frame");
            carrier.send(outgoing.clone().into_boxed_slice()).unwrap();
            let mut borrowed = Box::pin(futures::future::poll_fn(|cx| carrier.poll(cx)));
            let outcome = futures::poll!(borrowed.as_mut());
            drop(borrowed);
            if outcome.is_pending() {
                assert!(matches!(
                    futures::future::poll_fn(|cx| carrier.poll(cx)).await,
                    CarrierEvent::Written
                ));
            } else {
                assert!(matches!(outcome, Poll::Ready(CarrierEvent::Written)));
            }
            let mut received = vec![0; outgoing.len()];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, outgoing);
            drop(carrier);
            let mut tail = Vec::new();
            peer.read_to_end(&mut tail).await.unwrap();
            assert!(
                tail.is_empty(),
                "borrow cancellation replayed the accepted output"
            );
        })
        .await
        .expect("finite real framing ownership control stalled");
    }

    #[tokio::test]
    async fn bounded_actual_socket_backpressure_retains_one_original_write_across_cancellation() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = target(listener.local_addr().unwrap(), TurnStreamSecurity::Tcp);
            let mut carrier = Carrier::start(
                &target,
                None,
                None,
                transport_now() + Duration::from_secs(5),
            )
            .unwrap();
            let (accepted, activated) = tokio::join!(
                listener.accept(),
                futures::future::poll_fn(|cx| carrier.poll(cx))
            );
            assert!(matches!(activated, CarrierEvent::Activated(_)));
            let (mut peer, _) = accepted.unwrap();
            let State::Active(Wire::Tcp(stream)) = &carrier.state else {
                panic!("actual plain carrier not active");
            };
            socket2::SockRef::from(stream)
                .set_send_buffer_size(1024)
                .unwrap();
            let original = frame(&vec![0x5a; 60_000]);
            let mut expected = Vec::new();
            let mut observed = false;
            for _ in 0..64 {
                carrier.send(original.clone().into_boxed_slice()).unwrap();
                expected.extend_from_slice(&original);
                let mut borrowed = Box::pin(futures::future::poll_fn(|cx| carrier.poll(cx)));
                let outcome = futures::poll!(borrowed.as_mut());
                drop(borrowed);
                match outcome {
                    Poll::Ready(CarrierEvent::Written) => {}
                    Poll::Pending => {
                        observed = true;
                        break;
                    }
                    _ => panic!("actual bounded write retired instead of retaining its prefix"),
                }
            }
            assert!(
                observed,
                "finite original frames did not reach actual socket backpressure"
            );
            let (retained, offset) = carrier
                .write
                .as_ref()
                .expect("canceled borrowed poll lost its original frame");
            assert_eq!(&**retained, original);
            assert!(*offset < retained.len());
            let drain = async {
                let mut received = vec![0; expected.len()];
                peer.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
            };
            let write = async {
                assert!(matches!(
                    futures::future::poll_fn(|cx| carrier.poll(cx)).await,
                    CarrierEvent::Written
                ));
            };
            tokio::join!(drain, write);
            drop(carrier);
            let mut tail = Vec::new();
            peer.read_to_end(&mut tail).await.unwrap();
            assert!(
                tail.is_empty(),
                "canceled partial write was replayed after its accepted prefix"
            );
        })
        .await
        .expect("finite actual partial-write ownership control stalled");
    }

    #[tokio::test]
    async fn tls_setup_retains_the_original_credential_cutoff() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (_, tls) = tls_pair();
            let mut target = target(
                listener.local_addr().unwrap(),
                TurnStreamSecurity::Tls {
                    server_name: "localhost".into(),
                },
            );
            let expiry = transport_now() + Duration::from_secs(2);
            target.credentials = nethernet::session::TurnCredentials::new(
                "bounded".into(),
                "original".into(),
                expiry,
            )
            .unwrap();
            let connector = TlsConnector::from(tls);
            let mut carrier = Carrier::start(
                &target,
                None,
                Some((connector, ServerName::try_from("localhost").unwrap())),
                transport_now() + Duration::from_secs(4),
            )
            .unwrap();
            let (_peer, _) = listener.accept().await.unwrap();
            assert_eq!(carrier.setup_deadline(), Some(expiry));
            tokio::time::pause();
            tokio::time::advance(expiry.saturating_duration_since(transport_now())).await;
            assert!(matches!(
                futures::future::poll_fn(|cx| carrier.poll(cx)).await,
                CarrierEvent::Closed
            ));
            assert!(
                carrier.route.is_none(),
                "expired pending target acquired a tuple or activated"
            );
            tokio::time::resume();
        })
        .await
        .expect("finite original credential cutoff control stalled");
    }
}
