mod negotiation;

#[cfg(test)]
mod establish_failure_tests;

use crate::addr::Addr;
use crate::error::{NetherError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::guard::{ConnectionGuard, GatheringGuard, transport_now};
use crate::session::{AcceptedSession, Command, Session, SessionReceiver, SessionSender};
use crate::signaling::ClientSignaling;
use crate::transport::ice_io::IceIo;
use crate::transport::{ConnectionConfig, local_bind_addr};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use nethernet::connection::{Connection as SansConnection, IceMode};
use nethernet::identity::{TokenTrust, verify_answer_with_policy};
use nethernet::phase::{Connecting, Retired};
use nethernet::session::Session as SansSession;
use p384::ecdsa::VerifyingKey;
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
#[cfg(test)]
use std::time::Instant;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio_util::io::StreamReader;
use tokio_util::sync::ReusableBoxFuture;

pub(crate) fn parse_error_code(data: &str) -> SignalErrorCode {
    nethernet::protocol::signal::parse_error_code(data)
        .ok()
        .and_then(|code| u32::try_from(code).ok())
        .map_or(
            SignalErrorCode::SignalingUnknownError,
            SignalErrorCode::from,
        )
}

fn check_answer(
    answer: &Signal,
    server_trust: Option<&TokenTrust>,
    allow_anonymous: bool,
    now: SystemTime,
) -> std::result::Result<Option<VerifyingKey>, (Option<SignalErrorCode>, NetherError)> {
    verify_answer_with_policy(&answer.data, server_trust, allow_anonymous, now)
        .and_then(|claims| claims.map(|claims| claims.client_public_key()).transpose())
        .map_err(|e| {
            (
                Some(SignalErrorCode::FailedToSetRemoteDescription),
                NetherError::Identity(e),
            )
        })
}

/// Retains signaling for late candidates and releases it when the session driver stops.
fn spawn_late_signal_forwarder<St>(
    mut signals: St,
    connection_id: u64,
    remote_network_id: String,
    command_tx: tokio::sync::mpsc::Sender<Command>,
    closed: tokio_util::sync::CancellationToken,
    signaling: ClientSignaling,
) where
    St: Stream<Item = Signal> + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        let _signaling = signaling;
        loop {
            let signal = tokio::select! {
                biased;
                _ = closed.cancelled() => break,
                _ = command_tx.closed() => break,
                signal = signals.next() => match signal {
                    Some(signal) => signal,
                    None => break,
                },
            };
            if signal.connection_id != connection_id || signal.network_id != remote_network_id {
                continue;
            }
            if signal.signal_type != SignalType::Candidate {
                continue;
            }
            tokio::select! {
                biased;
                _ = closed.cancelled() => break,
                result = command_tx.send(Command::Signal(signal)) => {
                    if result.is_err() { break; }
                }
            }
        }
    });
}

struct SessionStream {
    receiver: SessionReceiver,
}

impl Stream for SessionStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx).map(|result| match result {
            Ok(Some(data)) => Some(Ok(data)),
            Ok(None) => None,
            Err(error) => Some(Err(io::Error::other(error))),
        })
    }
}

/// An established client connection with reliable and unreliable message APIs.
///
/// Use [`send`](Self::send) and [`recv`](Self::recv) to preserve message boundaries.
/// `AsyncRead` and `AsyncWrite` expose the reliable channel as a byte stream.
/// Retain this owner while using a shared [`SessionSender`]; dropping it requests closure.
pub struct NetherClient {
    session: Session,
    server_public_key: Option<VerifyingKey>,
    unreliable: SessionReceiver,
    reader: Option<StreamReader<SessionStream, Bytes>>,
    send_future: Option<ReusableBoxFuture<'static, Result<()>>>,
    shutdown_future: Option<ReusableBoxFuture<'static, Result<()>>>,
}

impl NetherClient {
    /// Connects to a discovered LAN network ID or an HTTP server URL with default settings.
    /// Use [`connect_with`](Self::connect_with) to choose identity, trust, ICE, and deadlines.
    pub async fn connect(
        signaling: impl Into<ClientSignaling>,
        remote_network_id: String,
    ) -> Result<Self> {
        Self::connect_with(signaling, remote_network_id, ConnectionConfig::default()).await
    }

    /// Offers again with a fresh connection id after a timeout, up to attempts times.
    /// Caller-driven signaling uses one attempt; its application owns retry policy.
    pub async fn connect_with(
        signaling: impl Into<ClientSignaling>,
        remote_network_id: String,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let signaling: ClientSignaling = signaling.into();
        let attempts = match &signaling {
            ClientSignaling::Caller(_) => 1,
            ClientSignaling::Lan(_) | ClientSignaling::Http(_) => config.attempts.max(1),
        };

        for attempt in 1..=attempts {
            let mut connection_id_bytes = [0u8; 8];
            rand::rng().fill_bytes(&mut connection_id_bytes);
            let connection_id = u64::from_le_bytes(connection_id_bytes);

            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NetherError::ConnectionClosed)),
                result = Self::negotiate(
                    &signaling,
                    &remote_network_id,
                    connection_id,
                    config.clone(),
                ) => result,
            };

            let (code, error) = match result {
                Ok(stream) => return Ok(stream),
                Err(failure) => failure,
            };

            if let Some(code) = code {
                let notification = signaling.signal(Signal::error(
                    connection_id,
                    code,
                    remote_network_id.clone(),
                ));
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {},
                    _ = tokio::time::timeout(config.timeouts.negotiation, notification) => {},
                }
            }

            if !matches!(error, NetherError::Timeout) || attempt == attempts {
                return Err(error);
            }

            tracing::debug!(
                "negotiation attempt {} of {} timed out, offering again",
                attempt,
                attempts
            );
        }

        Err(NetherError::Timeout)
    }

    async fn negotiate(
        signaling: &ClientSignaling,
        remote_network_id: &str,
        connection_id: u64,
        config: ConnectionConfig,
    ) -> std::result::Result<Self, (Option<SignalErrorCode>, NetherError)> {
        if config.client_ice.as_ref().is_some_and(|ice| {
            ice.ice
                .servers
                .iter()
                .any(|server| server.stream_id().is_some())
        }) {
            return Err((
                None,
                NetherError::Protocol(nethernet::session::IceError::UnsupportedCarrier.into()),
            ));
        }
        let deadline = tokio::time::Instant::now() + config.timeouts.negotiation;
        let bind_addr = config
            .client_ice
            .as_ref()
            .and_then(|ice| ice.bind_addr)
            .unwrap_or_else(local_bind_addr);
        let socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| (None, NetherError::from(e)))?,
        );
        let bound_addr = socket
            .local_addr()
            .map_err(|e| (None, NetherError::from(e)))?;

        let now = transport_now();
        let (io, ice) = match &config.client_ice {
            Some(ice) => {
                let (io, policy) = IceIo::configured(
                    socket,
                    &ice.ice,
                    &ice.turn_streams,
                    ice.turn_tls.as_ref(),
                    ice.bind_addr.map(|addr| addr.ip()),
                    now,
                    deadline.into_std(),
                )
                .map_err(|error| (Some(SignalErrorCode::FailedToCreatePeerConnection), error))?;
                (io, Some(policy))
            }
            None => (IceIo::from(socket), None),
        };
        let (mut session, description) = match ice {
            Some(ice) => SansSession::new_with_ice(bound_addr, true, rand::random(), ice, now),
            None => SansSession::new(bound_addr, true, rand::random(), now),
        }
        .map_err(|error| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NetherError::from(error),
            )
        })?;
        session
            .set_max_incoming_message_size(config.max_incoming_message_bytes)
            .map_err(|error| {
                (
                    Some(SignalErrorCode::FailedToCreatePeerConnection),
                    NetherError::from(error),
                )
            })?;
        session.set_establish_deadline(config.timeouts.establish());
        let ice_mode = if signaling.disable_trickle_ice() {
            IceMode::Full
        } else {
            IceMode::Trickle
        };
        let mut gathering = GatheringGuard::new(session, io);
        if ice_mode == IceMode::Full {
            super::gather::gather(
                gathering.io.as_mut().expect("gathering owns transport"),
                gathering
                    .core
                    .as_mut()
                    .expect("gathering session is still owned"),
                deadline,
            )
            .await
            .map_err(|error| (Some(SignalErrorCode::Ice), error))?;
        }
        let session = gathering
            .core
            .take()
            .expect("gathered session is handed off once");

        let (connection, signals) = SansConnection::connect(
            session,
            description,
            connection_id,
            remote_network_id.to_string(),
            ice_mode,
        );

        let mut guard = ConnectionGuard::new(
            connection,
            gathering
                .io
                .take()
                .expect("gathered transport is handed off once"),
        );
        let mut signals_out = signals.into_iter();
        let offer = signals_out
            .next()
            .expect("Connection::connect produces an offer first");
        let offer_data = match &config.identity {
            Some(identity) => identity
                .augment(&offer.data, SystemTime::now())
                .map_err(|e| {
                    (
                        Some(SignalErrorCode::FailedToCreateOffer),
                        NetherError::Identity(e),
                    )
                })?,
            None => offer.data,
        };

        let mut incoming = signaling.signals().map_err(|error| (None, error))?;
        let mut outgoing = vec![Signal::offer(
            connection_id,
            offer_data,
            remote_network_id.to_string(),
        )];
        outgoing.extend(signals_out);
        let (connection, io) = guard.pending_parts();
        let server_public_key = negotiation::exchange(
            io,
            connection,
            &mut incoming,
            signaling,
            outgoing,
            connection_id,
            remote_network_id,
            config.server_trust.as_ref(),
            config.allow_anonymous_answers,
            config.timeouts.negotiation,
            deadline,
        )
        .await?;
        let (connection, io) = guard.take();

        let local = Addr::new(signaling.network_id(), connection_id);
        let remote = Addr::new(remote_network_id.to_string(), connection_id);

        let (session, mut reliable, mut unreliable, ready_rx) =
            Session::<Connecting>::spawn_with_signaling(
                io,
                connection,
                local,
                remote,
                Some((signaling.clone(), config.timeouts.negotiation)),
            );

        spawn_late_signal_forwarder(
            incoming,
            connection_id,
            remote_network_id.to_string(),
            session.signal_sender(),
            session.close_token(),
            signaling.clone(),
        );

        let ready = tokio::time::timeout(config.timeouts.establish(), ready_rx)
            .await
            .map_err(|_| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    NetherError::Timeout,
                )
            })
            .and_then(|ready| ready.map_err(|_| (None, NetherError::ConnectionClosed)));
        let ready = match ready {
            Ok(ready) => ready,
            Err(failure) => {
                drop(session.close());
                // Both original terminals follow actor-owned ICE destruction and its accepted prefix.
                for receiver in [&mut reliable, &mut unreliable] {
                    while matches!(receiver.recv().await, Ok(Some(_))) {}
                }
                return Err(failure);
            }
        };

        let mut client = Self::from_session(session.establish(ready), reliable, unreliable);
        client.server_public_key = server_public_key;
        Ok(client)
    }

    pub(crate) fn from_session(
        session: Session,
        reliable: SessionReceiver,
        unreliable: SessionReceiver,
    ) -> Self {
        Self {
            session,
            server_public_key: None,
            unreliable,
            reader: Some(StreamReader::new(SessionStream { receiver: reliable })),
            send_future: None,
            shutdown_future: None,
        }
    }

    /// Borrows the key authenticated by the selected answer policy on this established connection.
    /// Missing or unchecked identities return `None`; application trust remains a separate decision.
    pub fn server_public_key(&self) -> Option<&VerifyingKey> {
        self.server_public_key.as_ref()
    }

    /// Admits one complete reliable message; success does not acknowledge peer receipt.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.session.send(data).await
    }

    /// Admits one unordered message without retransmission; it must fit one segment.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.session.send_unreliable(data).await
    }

    /// Receives the next complete unreliable message, or `None` after closure.
    pub async fn recv_unreliable(&mut self) -> Result<Option<Bytes>> {
        self.unreliable.recv().await
    }

    /// Next reliable message; a partially read stream chunk is returned before later messages.
    /// Returns None after the accepted prefix and ordinary terminal have been consumed.
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        let (mut stream, chunk) = self
            .reader
            .take()
            .expect("the client retains its reliable reader")
            .into_inner_with_chunk();
        stream.receiver = stream.receiver.retain_reader_chunk(chunk);
        self.reader = Some(StreamReader::new(stream));
        self.reader
            .as_mut()
            .expect("the reader is restored before receiving")
            .get_mut()
            .receiver
            .recv()
            .await
    }

    /// Consumes the live client and retains its original accepted receivers for draining.
    pub fn close(self) -> AcceptedSession<Retired> {
        self.into_accepted().close()
    }

    pub async fn remote_addr(&self) -> Addr {
        self.session.remote_addr().await
    }

    pub async fn local_addr(&self) -> Addr {
        self.session.local_addr().await
    }

    pub async fn rtt(&self) -> Option<std::time::Duration> {
        self.session.rtt().await
    }

    /// Splits into the session and original receivers, retaining any unread stream chunk first.
    pub fn into_accepted(self) -> AcceptedSession {
        let (stream, chunk) = self
            .reader
            .expect("the client retains its reliable reader")
            .into_inner_with_chunk();
        AcceptedSession {
            session: self.session,
            reliable: stream.receiver.retain_reader_chunk(chunk),
            unreliable: self.unreliable,
        }
    }

    /// Shares established sending and synchronous cancellation without duplicating lifecycle ownership.
    pub fn sender(&self) -> SessionSender {
        self.session.sender()
    }
}

impl AsyncRead for NetherClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(
            self.reader
                .as_mut()
                .expect("the client retains its reliable reader"),
        )
        .poll_read(cx, buf)
    }
}

impl AsyncWrite for NetherClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => {
                    self.send_future = Some(fut);
                    return Poll::Pending;
                }
            }
        }

        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        let session = self.session.sender();
        let mut fut = ReusableBoxFuture::new(async move { session.send(data).await });

        match fut.poll(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Pending => {
                self.send_future = Some(fut);
            }
        }

        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.send_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if self.shutdown_future.is_none() {
            let session = self.session.sender();
            self.shutdown_future =
                Some(ReusableBoxFuture::new(async move { session.close().await }));
        }

        if let Some(mut fut) = self.shutdown_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.shutdown_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nethernet::identity::ServerIdentity;

    /// Configured preflight retains the original failure classification before an offer exists.
    #[tokio::test]
    async fn configured_client_preserves_expired_credential_signal_classification() {
        use nethernet::session::{IceConfig, IceServer, TurnCredentials};
        let (caller, _driver) =
            crate::CallerSignaling::new("local".into(), "peer".into(), Default::default()).unwrap();
        let signaling = ClientSignaling::from(caller);
        let now = transport_now();
        let config = ConnectionConfig {
            client_ice: Some(crate::ClientIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                ice: IceConfig {
                    servers: vec![IceServer::Turn(
                        "127.0.0.1:3478".parse().unwrap(),
                        TurnCredentials::new(
                            "original-user".into(),
                            "original-password".into(),
                            now,
                        )
                        .unwrap(),
                    )],
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            NetherClient::negotiate(&signaling, "peer", 1, config),
        )
        .await
        .expect("finite configured client preflight stalled")
        .err()
        .expect("expired original credential constructed a session");
        assert_eq!(
            failure.0,
            Some(SignalErrorCode::FailedToCreatePeerConnection)
        );
    }

    const ANSWER: &str = "v=0\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=fingerprint:sha-256 AB:CD\r\n";

    fn answer(data: String) -> Signal {
        Signal::answer(1, data, "server".to_string())
    }

    #[test]
    fn without_a_server_trust_an_unsigned_answer_is_accepted() {
        assert!(check_answer(&answer(ANSWER.to_string()), None, false, SystemTime::now()).is_ok());
    }

    #[test]
    fn with_a_server_trust_an_unsigned_answer_fails_the_dial() {
        let (code, error) = check_answer(
            &answer(ANSWER.to_string()),
            Some(&TokenTrust::Any),
            false,
            SystemTime::now(),
        )
        .unwrap_err();

        assert_eq!(code, Some(SignalErrorCode::FailedToSetRemoteDescription));
        assert!(matches!(error, NetherError::Identity(_)));
    }

    #[test]
    fn with_a_server_trust_a_signed_answer_is_accepted() {
        let now = SystemTime::now();
        let signed = ServerIdentity::generate("example.com", now)
            .unwrap()
            .augment(ANSWER, now)
            .unwrap();

        assert!(check_answer(&answer(signed), Some(&TokenTrust::Any), false, now).is_ok());
    }

    /// Exercises a trickled offer answered with inline candidates and no candidate signal.
    #[tokio::test]
    async fn a_full_answer_to_a_trickled_offer_establishes_without_another_signal() {
        use crate::ServerData;
        use crate::signaling::lan::{LanConfig, LanSignaling};
        use std::time::Duration;

        // Reserve an ephemeral discovery port; the SDK currently cannot expose a port-zero bind.
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = reservation.local_addr().unwrap();
        drop(reservation);
        let server = Arc::new(
            LanSignaling::with_config(
                1,
                server_address,
                LanConfig {
                    discovery_port: server_address.port(),
                    ..LanConfig::default()
                },
            )
            .await
            .unwrap(),
        );
        server.set_server_data(ServerData::new("fixture".into(), "world".into()));
        let mut incoming = server.signals();
        let client = LanSignaling::with_config(
            2,
            "127.0.0.1:0".parse().unwrap(),
            LanConfig {
                broadcast_address: Some(server_address),
                ..LanConfig::default()
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            let (echoed_tx, echoed_rx) = tokio::sync::oneshot::channel();
            let accept = async {
                let offer = loop {
                    let signal = incoming.next().await.unwrap();
                    if signal.signal_type == SignalType::Offer {
                        break signal;
                    }
                };
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let (session, description) = SansSession::new(
                    socket.local_addr().unwrap(),
                    false,
                    rand::random(),
                    Instant::now(),
                )
                .unwrap();
                let (remote, candidates) = SansConnection::parse_offer(&offer).unwrap();
                let (connection, answers) = SansConnection::accept(
                    session,
                    description,
                    &offer,
                    remote,
                    candidates,
                    IceMode::Full,
                    Instant::now(),
                )
                .unwrap();
                assert_eq!(
                    answers.len(),
                    1,
                    "the fixture sends only the complete answer"
                );
                for answer in answers {
                    server.signal(answer).await.unwrap();
                }
                let (session, mut reliable, _unreliable, ready) = Session::<Connecting>::spawn(
                    socket,
                    connection,
                    Addr::new(server.network_id(), offer.connection_id),
                    Addr::new(offer.network_id.clone(), offer.connection_id),
                );
                spawn_late_signal_forwarder(
                    incoming,
                    offer.connection_id,
                    offer.network_id,
                    session.signal_sender(),
                    session.close_token(),
                    server.clone().into(),
                );
                let session = session.establish(ready.await.unwrap());
                let body = reliable.recv().await.unwrap().unwrap();
                session.send(body).await.unwrap();
                echoed_rx.await.unwrap();
            };
            let connect = async {
                while !client.discover().await.contains_key(&1) {
                    tokio::task::yield_now().await;
                }
                let mut connection = NetherClient::connect(client, "1".into()).await.unwrap();
                connection
                    .send(Bytes::from_static(b"inline answer"))
                    .await
                    .unwrap();
                assert_eq!(
                    connection.recv().await.unwrap().unwrap(),
                    b"inline answer"[..]
                );
                echoed_tx.send(()).unwrap();
                drop(connection.close());
            };
            tokio::join!(accept, connect);
        })
        .await
        .expect("a complete answer must not wait for a nonexistent candidate signal");
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&server) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the closed session must release its signaling owner");
        let server = Arc::try_unwrap(server)
            .ok()
            .expect("no signaling owner should escape the fixture");
        server.shutdown().await;
    }
}

#[cfg(test)]
mod anonymous_answer_tests;

#[cfg(test)]
mod error_code_tests;
