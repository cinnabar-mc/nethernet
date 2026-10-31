//! A `go-peer peer` subprocess and the loopback LAN plumbing that connects Rust to it.
use bytes::Bytes;
use nethernet_tokio::signaling::lan::{LanConfig, LanSignaling};
use nethernet_tokio::{
    AcceptedSession, ClientIceConfig, ConnectionConfig, NetherClient, NetherServer, ServerData,
    ServerIceConfig, Session, SessionReceiver, SessionSender,
};
use serde_json::Value;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Environment variable naming the built `tools/go-peer` binary.
pub const GO_PEER_ENV: &str = "NETHERNET_GO_PEER";

/// When set, a missing helper fails the test instead of skipping it.
pub const REQUIRE_GO_PEER_ENV: &str = "NETHERNET_REQUIRE_GO_PEER";

/// Prints the missing-fixture message, or panics when CI requires the helper.
fn missing_fixture() {
    let message = format!(
        "missing fixture {GO_PEER_ENV} (build it with `go build -C tools/go-peer -o <path> .`)"
    );
    assert!(std::env::var_os(REQUIRE_GO_PEER_ENV).is_none(), "{message}");
    eprintln!("skipping: {message}");
}

/// Bound on any single wait; a stalled step fails instead of hanging CI.
pub const STEP: Duration = Duration::from_secs(30);

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// The payload bytes both harness sides use: byte i is i mod 251.
pub fn pattern(len: usize) -> Bytes {
    (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>().into()
}

/// Polls `condition` until it holds, failing after `STEP`.
pub async fn eventually<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + STEP;
    while !condition().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub struct GoPeer {
    _child: Child,
    events: mpsc::UnboundedReceiver<Value>,
}

impl GoPeer {
    /// Starts the peer, or returns None after printing the missing-fixture message.
    pub fn spawn(args: &[&str]) -> Option<Self> {
        let Some(path) = std::env::var_os(GO_PEER_ENV) else {
            missing_fixture();
            return None;
        };
        let mut child = Command::new(path)
            .arg("peer")
            .args(args)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("{GO_PEER_ENV} is set but does not start: {e}"));
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let (tx, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(serde_json::from_str(&line).expect("go-peer event"));
            }
        });
        Some(Self {
            _child: child,
            events,
        })
    }

    /// Waits for the next event named `name`, skipping others.
    pub async fn event(&mut self, name: &str) -> Value {
        self.event_within(name, STEP)
            .await
            .unwrap_or_else(|| panic!("go-peer never reported {name}"))
    }

    /// Like `event`, but None when `name` does not arrive within `wait`.
    pub async fn event_within(&mut self, name: &str, wait: Duration) -> Option<Value> {
        tokio::time::timeout(wait, async {
            loop {
                let event = self.events.recv().await.expect("go-peer exited");
                if event["event"] == name {
                    return event;
                }
            }
        })
        .await
        .ok()
    }
}

/// One established connection; whatever owns its signaling stays alive with it.
pub struct Link {
    pub sender: SessionSender,
    pub reliable: SessionReceiver,
    pub unreliable: SessionReceiver,
    _session: Session,
    _owner: Option<NetherServer>,
}

impl Link {
    fn new(accepted: AcceptedSession, owner: Option<NetherServer>) -> Self {
        Self {
            sender: accepted.session.sender(),
            reliable: accepted.reliable,
            unreliable: accepted.unreliable,
            _session: accepted.session,
            _owner: owner,
        }
    }

    /// Sends a `!` command to the Go peer over the reliable channel.
    pub async fn command(&self, command: &str) {
        self.sender
            .send(Bytes::from(format!("!{command}")))
            .await
            .unwrap();
    }

    /// Preserves the original receiver's typed terminal under the existing step deadline.
    pub async fn recv_result(&mut self) -> nethernet_tokio::Result<Option<Bytes>> {
        tokio::time::timeout(STEP, self.reliable.recv())
            .await
            .expect("reliable receive stalled")
    }

    /// The next reliable message, or None once the session has closed.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv_result().await.ok().flatten()
    }

    /// Skips reliable messages until one starts with `prefix`.
    pub async fn reply(&mut self, prefix: &str) -> String {
        loop {
            let message = self.recv().await.expect("session closed awaiting reply");
            if message.starts_with(prefix.as_bytes()) {
                return String::from_utf8(message.to_vec()).unwrap();
            }
        }
    }
}

fn client_config(maximum: usize) -> ConnectionConfig {
    ConnectionConfig {
        max_incoming_message_bytes: maximum,
        client_ice: Some(ClientIceConfig {
            turn_streams: Vec::new(),
            turn_tls: None,
            ice: Default::default(),
            bind_addr: Some(loopback(0)),
        }),
        ..Default::default()
    }
}

/// Rust dials a listening Go peer; returns the peer, the link and what discovery reported.
pub async fn rust_dials_go() -> Option<(GoPeer, Link, ServerData)> {
    rust_dials_go_with_incoming_limit(ConnectionConfig::default().max_incoming_message_bytes).await
}

/// Uses the original LAN client with only its complete incoming-body policy selected by the caller.
pub async fn rust_dials_go_with_incoming_limit(
    maximum: usize,
) -> Option<(GoPeer, Link, ServerData)> {
    const GO_ID: u64 = 7001;
    let mut peer = GoPeer::spawn(&["--role", "listen", "--network-id", "7001"])?;
    let ready = peer.event("ready").await;
    let go_addr: SocketAddr = ready["addr"].as_str().unwrap().parse().unwrap();
    let signaling = LanSignaling::with_config(
        7002,
        loopback(0),
        LanConfig {
            broadcast_address: Some(go_addr),
            broadcast_interval: Duration::from_millis(50),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    eventually("Rust discovers the Go peer", || async {
        signaling.discover().await.contains_key(&GO_ID)
    })
    .await;
    let discovered = signaling.discover().await.remove(&GO_ID).unwrap();
    let client = tokio::time::timeout(
        STEP,
        NetherClient::connect_with(signaling, GO_ID.to_string(), client_config(maximum)),
    )
    .await
    .expect("Rust dial stalled")
    .expect("Rust dials Go");
    peer.event("connected").await;
    Some((peer, Link::new(client.into_accepted(), None), discovered))
}

/// A Go peer dials a Rust server advertising `data`; returns what Go discovered as JSON.
pub async fn go_dials_rust(data: ServerData) -> Option<(GoPeer, Link, Value)> {
    go_dials_rust_with_incoming_limit(data, ConnectionConfig::default().max_incoming_message_bytes)
        .await
}

/// Uses the original LAN server with only its complete incoming-body policy selected by the caller.
pub async fn go_dials_rust_with_incoming_limit(
    data: ServerData,
    maximum: usize,
) -> Option<(GoPeer, Link, Value)> {
    const RUST_ID: u64 = 7003;
    // A probed port can be taken by a parallel test before it is rebound, so retry.
    let (port, signaling) = 'bind: {
        for _ in 0..10 {
            let port = std::net::UdpSocket::bind(loopback(0))
                .and_then(|s| s.local_addr())
                .unwrap()
                .port();
            let config = LanConfig {
                discovery_port: port,
                ..Default::default()
            };
            if let Ok(signaling) = LanSignaling::with_config(RUST_ID, loopback(port), config).await
            {
                break 'bind (port, signaling);
            }
        }
        panic!("no free loopback discovery port");
    };
    signaling.set_server_data(data);
    let mut server = NetherServer::bind_with(
        signaling,
        ConnectionConfig {
            max_incoming_message_bytes: maximum,
            server_ice: Some(ServerIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: Default::default(),
                bind_addr: loopback(0),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let broadcast = loopback(port).to_string();
    let mut peer = GoPeer::spawn(&[
        "--role",
        "dial",
        "--network-id",
        "7004",
        "--remote-id",
        &RUST_ID.to_string(),
        "--broadcast",
        &broadcast,
    ])?;
    let discovered = peer.event("discovered").await;
    let accepted = tokio::time::timeout(STEP, server.accept())
        .await
        .expect("Rust accept stalled")
        .expect("Rust accepts Go");
    peer.event("connected").await;
    Some((peer, Link::new(accepted, Some(server)), discovered))
}
