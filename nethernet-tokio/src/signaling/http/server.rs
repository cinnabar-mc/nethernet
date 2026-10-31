//! Server side of HTTP signaling: an HTTP/1 listener that turns join requests into offer signals.
use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::protocol::{Signal, SignalType};
use crate::transport::client::parse_error_code;
use futures::Stream;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use nethernet::prelude::{
    HttpSignaler, HttpSignalerConfig, HttpSignalerInput, HttpSignalerOutput, PlayerInfo,
    RejectReason, Sans, ServerData, TokenTrust,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const MAX_BODY: u64 = 1 << 20;
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_IDLE: Duration = Duration::from_secs(1);

/// Listener settings; the signaler holds limits, token trust and status serving.
#[derive(Clone)]
pub struct HttpServerConfig {
    pub network_id: String,

    pub signaler: HttpSignalerConfig,

    /// Serves HTTPS when set, plain HTTP otherwise.
    pub tls: Option<Arc<rustls::ServerConfig>>,

    /// Time a connection may take to send its request headers.
    pub idle_timeout: Duration,

    /// Time for transport readiness after an offer; includes the server-trust decision.
    pub establish_timeout: Duration,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            network_id: String::new(),
            signaler: HttpSignalerConfig::default(),
            tls: None,
            idle_timeout: Duration::from_secs(30),
            establish_timeout: nethernet::signaling::http::DEFAULT_ESTABLISH_TIMEOUT,
        }
    }
}

enum Command {
    Request {
        connection: u64,
        request: Box<http::Request<String>>,
        reply: oneshot::Sender<Response>,
    },
    Connected(u64, SocketAddr, CancellationToken, oneshot::Sender<bool>),
    Closed(u64),
    Answer {
        connection_id: u64,
        sdp: String,
    },
    Reject {
        connection_id: u64,
        reason: RejectReason,
    },
    SetServerData(Box<ServerData>),
    SetTokenTrust(Option<TokenTrust>),
    Address(u64, oneshot::Sender<Option<SocketAddr>>),
    Player(u64, oneshot::Sender<Option<Arc<PlayerInfo>>>),
    Host(u64, oneshot::Sender<Option<String>>),
}

struct Response {
    response: http::Response<String>,
    keep_alive: bool,
}

/// Metadata belongs to the physical request connection until the join completes.
struct OfferMetadata {
    connection: u64,
    address: Option<SocketAddr>,
    player: Option<Arc<PlayerInfo>>,
    host: Option<String>,
}

/// Join requests surface as offer signals and are completed by answer or error signals.
pub struct HttpSignalingServer {
    network_id: String,
    establish_timeout: Duration,
    local_addr: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
    signal_tx: broadcast::Sender<Signal>,
    cancel_token: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl HttpSignalingServer {
    /// Port 0 picks a free port; read it back from local_addr.
    pub async fn bind(addr: SocketAddr, config: HttpServerConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        let (signal_tx, _) = broadcast::channel(64);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();

        let accept = Self::accept(
            listener,
            config.clone(),
            commands.clone(),
            cancel_token.clone(),
        );
        let task = Self::drive(
            HttpSignaler::new(config.signaler.clone()),
            command_rx,
            signal_tx.clone(),
            accept,
            cancel_token.clone(),
        );

        Ok(Self {
            network_id: config.network_id,
            establish_timeout: config.establish_timeout,
            local_addr,
            commands,
            signal_tx,
            cancel_token,
            task: Some(task),
        })
    }

    /// Retains the listener's original HTTP transport budget for each new offer.
    pub(crate) fn establish_timeout(&self) -> Duration {
        self.establish_timeout
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting and waits for the serving task to finish.
    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Replaces the data served by the status endpoint.
    pub fn set_server_data(&self, server_data: ServerData) {
        let _ = self
            .commands
            .send(Command::SetServerData(Box::new(server_data)));
    }

    /// Replaces how later offers are authenticated; `None` skips validation.
    pub fn set_token_trust(&self, trust: Option<TokenTrust>) {
        let _ = self.commands.send(Command::SetTokenTrust(trust));
    }

    fn accept(
        listener: TcpListener,
        config: HttpServerConfig,
        commands: mpsc::UnboundedSender<Command>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let next_connection = AtomicU64::new(1);
            let mut serving = JoinSet::new();
            let acceptor = config.tls.clone().map(TlsAcceptor::from);

            loop {
                let (stream, peer) = tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = serving.join_next(), if !serving.is_empty() => continue,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            tracing::debug!("Failed to accept a connection: {}", e);
                            continue;
                        }
                    },
                };

                let connection = next_connection.fetch_add(1, Ordering::Relaxed);
                let connection_cancel = cancel_token.child_token();
                let (admitted_tx, admitted_rx) = oneshot::channel();
                if commands
                    .send(Command::Connected(
                        connection,
                        peer,
                        connection_cancel.clone(),
                        admitted_tx,
                    ))
                    .is_err()
                {
                    break;
                }

                if !admitted_rx.await.unwrap_or(false) {
                    continue;
                }

                let commands = commands.clone();
                let config = config.clone();
                let acceptor = acceptor.clone();
                let cancel_token = connection_cancel;

                serving.spawn(async move {
                    let served = tokio::select! {
                        _ = cancel_token.cancelled() => Ok(()),
                        served = serve(stream, connection, config, acceptor, commands.clone()) => served,
                    };
                    if let Err(e) = served {
                        tracing::debug!("Connection from {} ended: {}", peer, e);
                    }
                    let _ = commands.send(Command::Closed(connection));
                });
            }
            serving.abort_all();
            while serving.join_next().await.is_some() {}
        })
    }

    fn drive(
        mut signaler: HttpSignaler,
        mut commands: mpsc::UnboundedReceiver<Command>,
        signal_tx: broadcast::Sender<Signal>,
        accept: JoinHandle<()>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut waiting: HashMap<u64, oneshot::Sender<Response>> = HashMap::new();
            let mut connections: HashMap<u64, CancellationToken> = HashMap::new();
            let mut metadata: HashMap<u64, OfferMetadata> = HashMap::new();
            let mut offer_connections: HashMap<u64, u64> = HashMap::new();
            let mut wake = Instant::now() + MAX_IDLE;

            loop {
                let mut requested_connection = None;
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    command = commands.recv() => match command {
                        Some(Command::Connected(connection, addr, cancel, admitted)) => {
                            let _ = signaler.handle(HttpSignalerInput::Connected(
                                connection,
                                addr,
                                Instant::now(),
                            ));

                            let mut refused = false;
                            while let Some(output) = signaler.poll() {
                                if matches!(output, HttpSignalerOutput::Close(id) if id == connection) {
                                    refused = true;
                                }
                            }
                            if !refused { connections.insert(connection, cancel); }
                            let _ = admitted.send(!refused);
                        }
                        Some(Command::Request { connection, request, reply }) => {
                            requested_connection = Some(connection);
                            waiting.insert(connection, reply);
                            if let Err(e) = signaler.handle(HttpSignalerInput::Request {
                                connection,
                                request,
                                now: Instant::now(),
                                wall: SystemTime::now(),
                            }) {
                                tracing::debug!("Failed to handle a request: {}", e);
                            }
                        }
                        Some(Command::Closed(connection)) => {
                            waiting.remove(&connection);
                            connections.remove(&connection);
                            if let Some(id) = offer_connections.remove(&connection) { metadata.remove(&id); }
                            let _ = signaler.handle(HttpSignalerInput::Closed(connection));
                        }
                        Some(Command::Answer { connection_id, sdp }) => {
                            if let Err(e) = signaler
                                .handle(HttpSignalerInput::Answer { connection_id, sdp })
                            {
                                tracing::debug!("Failed to deliver an answer: {}", e);
                            }
                            if let Some(offer) = metadata.remove(&connection_id) { offer_connections.remove(&offer.connection); }
                        }
                        Some(Command::Reject { connection_id, reason }) => {
                            if let Err(e) = signaler
                                .handle(HttpSignalerInput::Reject { connection_id, reason })
                            {
                                tracing::debug!("Failed to reject a join: {}", e);
                            }
                            if let Some(offer) = metadata.remove(&connection_id) { offer_connections.remove(&offer.connection); }
                        }
                        Some(Command::SetServerData(data)) => {
                            let _ = signaler.handle(HttpSignalerInput::SetServerData(data));
                        }
                        Some(Command::SetTokenTrust(trust)) => {
                            let _ = signaler.handle(HttpSignalerInput::SetTokenTrust(trust));
                        }
                        Some(Command::Address(connection_id, reply)) => {
                            let _ = reply.send(metadata.get(&connection_id).and_then(|offer| offer.address));
                        }
                        Some(Command::Host(connection_id, reply)) => {
                            let _ = reply.send(metadata.get(&connection_id).and_then(|offer| offer.host.clone()));
                        }
                        Some(Command::Player(connection_id, reply)) => {
                            let _ = reply.send(metadata.get(&connection_id).and_then(|offer| offer.player.clone()));
                        }
                        None => break,
                    },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let _ = signaler.handle(HttpSignalerInput::Update(Instant::now()));
                    }
                }

                while let Some(output) = signaler.poll() {
                    match output {
                        HttpSignalerOutput::Response {
                            connection,
                            response,
                            keep_alive,
                        } => {
                            if let Some(id) = offer_connections.remove(&connection) {
                                metadata.remove(&id);
                            }
                            if let Some(reply) = waiting.remove(&connection) {
                                let _ = reply.send(Response {
                                    response: *response,
                                    keep_alive,
                                });
                            }
                        }
                        HttpSignalerOutput::Close(connection) => {
                            waiting.remove(&connection);
                            if let Some(cancel) = connections.remove(&connection) {
                                cancel.cancel();
                            }
                            if let Some(id) = offer_connections.remove(&connection) {
                                metadata.remove(&id);
                            }
                        }
                        HttpSignalerOutput::Offer(offer) => {
                            let offered = offer.signal();
                            let connection = requested_connection
                                .expect("an offer comes from the current request");
                            offer_connections.insert(connection, offer.connection_id);
                            metadata.insert(
                                offer.connection_id,
                                OfferMetadata {
                                    connection,
                                    address: offer.client_address,
                                    host: offer.host,
                                    player: offer.player.map(|player| Arc::from(*player)),
                                },
                            );

                            let _ = signal_tx.send(offered);
                        }
                        HttpSignalerOutput::Wait(wait) => {
                            wake = Instant::now() + wait.min(MAX_IDLE);
                        }
                    }
                }
            }

            cancel_token.cancel();
            let _ = accept.await;
        })
    }
}

impl Drop for HttpSignalingServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl HttpSignalingServer {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        let command = match signal.signal_type {
            SignalType::Answer => Command::Answer {
                connection_id: signal.connection_id,
                sdp: signal.data,
            },
            SignalType::Error => Command::Reject {
                connection_id: signal.connection_id,
                reason: parse_error_code(&signal.data).into(),
            },
            signal_type => {
                return Err(NetherError::Other(format!(
                    "{} is not supported over HTTP signaling",
                    signal_type
                )));
            }
        };

        self.commands
            .send(command)
            .map_err(|_| NetherError::ConnectionClosed)
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    pub fn network_id(&self) -> String {
        self.network_id.clone()
    }

    pub fn disable_trickle_ice(&self) -> bool {
        true
    }

    pub async fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Address(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub async fn player(&self, addr: &Addr) -> Option<Arc<PlayerInfo>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Player(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub async fn host(&self, addr: &Addr) -> Option<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Host(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }
}

async fn serve(
    stream: TcpStream,
    connection: u64,
    config: HttpServerConfig,
    acceptor: Option<TlsAcceptor>,
    commands: mpsc::UnboundedSender<Command>,
) -> Result<()> {
    match acceptor {
        Some(acceptor) => {
            let stream = tokio::time::timeout(config.idle_timeout, acceptor.accept(stream))
                .await
                .map_err(|_| NetherError::Timeout)?
                .map_err(|e| NetherError::Other(format!("TLS handshake: {}", e)))?;
            serve_http(stream, connection, config, commands).await
        }
        None => serve_http(stream, connection, config, commands).await,
    }
}

async fn serve_http<S>(
    stream: S,
    connection: u64,
    config: HttpServerConfig,
    commands: mpsc::UnboundedSender<Command>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let commands = commands.clone();
        async move {
            let (parts, body) = request.into_parts();
            let refuse = |status: http::StatusCode| {
                Ok::<_, hyper::Error>(
                    hyper::Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::new()))
                        .expect("a status and an empty body are always a valid response"),
                )
            };

            let declared = parts
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            if declared.is_some_and(|len| len > MAX_BODY) {
                return refuse(http::StatusCode::PAYLOAD_TOO_LARGE);
            }

            let collected = tokio::time::timeout(
                BODY_TIMEOUT,
                Limited::new(body, MAX_BODY as usize).collect(),
            )
            .await;
            let body = match collected {
                Err(_) => return refuse(http::StatusCode::REQUEST_TIMEOUT),
                Ok(Ok(body)) => body.to_bytes(),
                Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                    return refuse(http::StatusCode::PAYLOAD_TOO_LARGE);
                }
                Ok(Err(e)) => {
                    tracing::debug!("Failed to read a request body: {}", e);
                    Bytes::new()
                }
            };

            let request = http::Request::from_parts(
                parts,
                String::from_utf8_lossy(body.as_ref()).into_owned(),
            );

            let (reply_tx, reply_rx) = oneshot::channel();
            let sent = commands.send(Command::Request {
                connection,
                request: Box::new(request),
                reply: reply_tx,
            });

            let response = match sent {
                Ok(()) => reply_rx.await.ok(),
                Err(_) => None,
            };

            Ok(match response {
                Some(Response {
                    response,
                    keep_alive,
                }) => {
                    let (mut parts, body) = response.into_parts();
                    if !keep_alive {
                        parts
                            .headers
                            .insert(http::header::CONNECTION, "close".parse().expect("a header"));
                    }
                    hyper::Response::from_parts(parts, Full::new(Bytes::from(body)))
                }
                None => hyper::Response::builder()
                    .status(http::StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::new()))
                    .expect("a status and an empty body are always a valid response"),
            })
        }
    });

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(config.idle_timeout)
        .serve_connection(TokioIo::new(stream), service);

    connection
        .await
        .map_err(|e| NetherError::Other(format!("HTTP connection: {}", e)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn spawn_server() -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (commands, receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _receiver = receiver;
            let _ = serve_http(server, 0, HttpServerConfig::default(), commands).await;
        });
        client
    }

    async fn status_line<R: AsyncRead + Unpin>(reader: &mut R) -> String {
        let mut buf = vec![0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf))
            .await
            .expect("the server should answer before the body ends")
            .unwrap();
        String::from_utf8_lossy(&buf[..read])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Unanswered offers release their metadata on disconnect and on answer expiry.
    #[tokio::test]
    async fn abandoned_offers_release_metadata() {
        use futures::StreamExt;
        for disconnect in [false, true] {
            let mut config = HttpServerConfig::default();
            config.signaler.answer_timeout = Duration::from_millis(20);
            let server = HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), config)
                .await
                .unwrap();
            let mut offers = server.signals();
            let mut peer = TcpStream::connect(server.local_addr()).await.unwrap();
            let offer = signed_offer();
            peer.write_all(format!("POST /v1/join/1234 HTTP/1.1\r\nhost: metadata.example\r\ncontent-length: {}\r\n\r\n{offer}", offer.len()).as_bytes()).await.unwrap();
            let signal = tokio::time::timeout(Duration::from_secs(2), offers.next())
                .await
                .unwrap()
                .unwrap();
            let addr = Addr::new(signal.network_id, signal.connection_id);
            assert!(server.remote_address(&addr).await.is_some());
            assert_eq!(
                server.host(&addr).await.as_deref(),
                Some("metadata.example")
            );
            if disconnect {
                drop(peer);
            } else {
                assert!(status_line(&mut peer).await.contains("504"));
            }
            let cleaned = tokio::time::timeout(Duration::from_secs(2), async {
                while server.remote_address(&addr).await.is_some() {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            server.shutdown().await;
            assert!(cleaned.is_ok(), "abandoned offer retained metadata");
        }
    }

    /// A stalled TLS peer must release its socket without global server shutdown.
    #[tokio::test]
    async fn stalled_tls_is_closed_at_the_header_budget() {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![issued.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let server = HttpSignalingServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            HttpServerConfig {
                tls: Some(Arc::new(tls)),
                idle_timeout: Duration::from_millis(20),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut peer = TcpStream::connect(server.local_addr()).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut [0; 1])).await;
        server.shutdown().await;
        assert!(
            matches!(result, Ok(Ok(0))),
            "stalled TLS socket survived its budget: {result:?}"
        );
    }

    #[tokio::test]
    async fn oversized_content_length_is_refused_before_the_body() {
        let mut client = spawn_server();
        client
            .write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 2147483648\r\n\r\n")
            .await
            .unwrap();

        assert_eq!(
            status_line(&mut client).await,
            "HTTP/1.1 413 Payload Too Large"
        );
    }

    #[tokio::test]
    async fn chunked_body_past_the_limit_is_refused_while_streaming() {
        let (mut reader, mut writer) = tokio::io::split(spawn_server());
        tokio::spawn(async move {
            writer
                .write_all(b"POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n")
                .await?;
            let chunk = vec![b'a'; 0x10000];
            for _ in 0..24 {
                writer.write_all(b"10000\r\n").await?;
                writer.write_all(&chunk).await?;
                writer.write_all(b"\r\n").await?;
            }
            std::future::pending::<()>().await;
            Ok::<_, std::io::Error>(())
        });

        assert_eq!(
            status_line(&mut reader).await,
            "HTTP/1.1 413 Payload Too Large"
        );
    }

    pub(crate) fn signed_offer() -> String {
        let now = std::time::SystemTime::now();
        nethernet::identity::ServerIdentity::generate("example.com", now)
            .unwrap()
            .augment(
                "v=0\r\n\
                 m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                 a=fingerprint:sha-256 AB:CD\r\n",
                now,
            )
            .unwrap()
    }

    pub(crate) async fn post_offer(addr: SocketAddr, offer: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST /v1/join/1234 HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{offer}",
            offer.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        status_line(&mut stream).await
    }

    #[tokio::test]
    async fn a_trust_set_on_a_running_server_refuses_later_offers() {
        let mut config = HttpServerConfig::default();
        config.signaler.answer_timeout = Duration::from_millis(200);
        let server = HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();

        server.set_token_trust(Some(TokenTrust::Minecraft(Default::default())));

        assert_eq!(
            post_offer(server.local_addr(), &signed_offer()).await,
            "HTTP/1.1 401 Unauthorized"
        );
    }
}
