# NetherNet

NetherNet connects peers and sends reliable or unreliable application messages.
Discover a server on your LAN, connect to a known HTTP endpoint, or carry
connection signals through your existing messaging service.

Use it to add NetherNet transport to an application. For Minecraft Login,
packet codecs, and gameplay, use a higher layer such as
[bedrock-net](https://github.com/cinnabar-mc/bedrock-net).

## Install

For the Tokio examples below, add these dependencies to a Rust 2024 project:

```toml
[dependencies]
nethernet-tokio = { git = "https://github.com/cinnabar-mc/nethernet" }
bytes = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

Use the same Git revision for every crate you take from this repository and
commit your application's `Cargo.lock`.

## Try a LAN echo server

Save this as `src/bin/server.rs`. It advertises a server on the LAN, accepts one
connection at a time, and echoes complete reliable messages.

```rust,no_run
use nethernet_tokio::{AcceptedSession, LanSignaling, NetherServer, ServerData};
use nethernet_tokio::protocol::constants::LAN_DISCOVERY_PORT;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signaling = LanSignaling::new(
        1,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_DISCOVERY_PORT)),
    ).await?;
    signaling.set_server_data(ServerData::new("Echo server".into(), "Demo".into()));
    let mut listener = NetherServer::bind(signaling).await?;

    loop {
        let AcceptedSession { session, mut reliable, .. } = listener.accept().await?;
        while let Some(message) = reliable.recv().await? {
            session.send(message).await?;
        }
    }
}
```

Save this as `src/bin/client.rs`. It discovers a server, sends one message, and
prints its reply. The timeout gives discovery five seconds to find a server.

```rust,no_run
use bytes::Bytes;
use nethernet_tokio::{LanSignaling, NetherClient};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signaling = LanSignaling::new(2, "0.0.0.0:0".parse()?).await?;
    let server_id = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(id) = signaling.discover().await.keys().next().copied() {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await?;

    let mut client = NetherClient::connect(signaling, server_id.to_string()).await?;
    client.send(Bytes::from_static(b"hello")).await?;
    if let Some(reply) = client.recv().await? {
        println!("{}", String::from_utf8_lossy(&reply));
    }
    let mut retired = client.close();
    while retired.reliable.recv().await?.is_some() {}
    Ok(())
}
```

Run `cargo run --bin server`, then `cargo run --bin client` in another terminal.
Both peers need LAN UDP access. These local examples use the default identity
policy; choose an explicit trust policy before using untrusted peers.

From this checkout you can also run the longer examples:

```sh
cargo run --locked -p nethernet-tokio --example server
cargo run --locked -p nethernet-tokio --example client
cargo run --locked -p nethernet-tokio --example scanner
```

The example client uses `AsyncRead`/`AsyncWrite`. The snippets above use
message APIs so that each receive returns one complete application message.

## Connect another way

| Task | Guide |
| --- | --- |
| Discover LAN servers, change the discovery port, or connect to a selected server | [LAN discovery](docs/lan.md) |
| Add Bevy plugins and handle connection events | [Bevy](docs/bevy.md) |
| Run a local HTTP client/server pair, then add STUN or TURN | [HTTP and ICE](docs/http.md) |
| Carry signals over Xbox/Player Messaging with your existing account and service connection | [Messaging integration](docs/xbox-messaging.md) |
| Drive sockets and timers yourself | [Custom event loop](docs/sans-io.md) |
| Share a sender, handle backpressure, or use send deadlines | [Tokio](docs/tokio.md) |
| Close a connection and keep its accepted messages | [Shutdown](docs/shutdown.md) |

## Choose a crate

| Crate | Use it when | Runs the network with |
| --- | --- | --- |
| [`nethernet`](nethernet/README.md) | You have your own event loop or runtime. | Your sockets and clock. The core opens no sockets and starts no tasks. |
| [`nethernet-tokio`](nethernet-tokio/README.md) | You want async client and server APIs. | Tasks on your Tokio runtime. |
| [`bevy-nethernet`](bevy-nethernet/README.md) | You want Bevy resources, plugins, and connection events. | Frame updates for clients; a shared UDP worker for servers. No Tokio dependency. |

All three use the same protocol core. The reliable channel preserves message
order; the unreliable channel is unordered and does not retransmit messages.

## What your application supplies

For LAN, supply a distinct numeric network ID for each peer and a discovery bind
address. HTTP clients supply their local network ID and the server's base URL;
HTTP servers also supply an SDP signing identity.

For an account-backed service, your application signs in, owns the messaging
connection and routing IDs, obtains the multiplayer token and its matching proof
key, and chooses how to trust peers. NetherNet can sign and verify SDP with those
inputs; it does not acquire an account or start a game session.

For connections that need STUN/TURN, your application obtains and renews service
credentials and selects a candidate policy. The adapters can gather candidates
and run configured relay connections. With no ICE servers configured, sessions
use host candidates. HTTP signaling carries offers and answers; application
messages use the negotiated transport, not the HTTP connection.

## License and upstream

Apache-2.0; see [LICENSE](LICENSE). This fork continues the
[bedrock-crustaceans/nethernet](https://github.com/bedrock-crustaceans/nethernet)
project.
