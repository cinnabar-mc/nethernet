# LAN discovery

Start with the [echo pair](../README.md#try-a-lan-echo-server). Each peer has its
own numeric network ID. A client connects using the discovered server's ID, not
its IP address. Discovery and offer/answer exchange use UDP; an established
session has its own transport socket.

## Scan without connecting

From this checkout:

```sh
cargo run --locked -p nethernet-tokio --example scanner
```

Pass a port after `--` to scan a different discovery port. In your application,
`scan` collects discovery replies for a bounded interval:

```rust,no_run
use nethernet_tokio::signaling::lan::scan;
use nethernet_tokio::protocol::constants::LAN_DISCOVERY_PORT;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let servers = scan(2, LAN_DISCOVERY_PORT, Duration::from_secs(3)).await?;
    for (id, data) in servers {
        println!("{id}: {} ({})", data.server_name, data.level_name);
    }
    Ok(())
}
```

`LanSignaling::discover().await` instead returns the replies that its live
signaler has collected so far. It does not wait for another discovery round.
Keep that signaler when connecting: it retains the address learned for each ID.
Use `get_address(id).await` to inspect a discovered server's source address.

## Use a different port

Give both peers the same `discovery_port`. The server binds it and the client
broadcasts to it. This replaces the `LanSignaling::new` calls in the echo pair:

```rust,no_run
use nethernet_tokio::{LanConfig, LanSignaling};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LanConfig { discovery_port: 17551, ..Default::default() };
    let server = LanSignaling::with_config(1, "0.0.0.0:17551".parse()?, config.clone()).await?;
    let client = LanSignaling::with_config(2, "0.0.0.0:0".parse()?, config).await?;
    // Give server to NetherServer::bind and client to NetherClient::connect.
    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}
```

For a controlled local destination, set `LanConfig::broadcast_address` explicitly
on the client. For example, `Some("127.0.0.1:17551".parse()?)` sends discovery to
a server on the same machine. A custom destination must use the socket's address
family.

## Add identities

The echo pair uses default LAN settings: no local SDP identity and no token trust
policy. To sign offers or answers, pass an `identity` in `ConnectionConfig` to
`NetherClient::connect_with` or `NetherServer::bind_with`.

Select `token_trust` on the accepting server and `server_trust` on the client to
verify received identities. `TokenTrust::Any` checks token shape/expiry and the
SDP fingerprint proof, but does not verify the token issuer or its signature.
Use `TokenTrust::Minecraft` with issuer keys, or `TokenTrust::Provider` with your
own verifier, for an authenticated policy. An SDP identity alone does not sign
an account in. See [messaging inputs](xbox-messaging.md#identity-and-trust).

## When nothing is discovered

Check that the server is running, both sides use the same discovery port, and
UDP broadcast is allowed by the local firewall and network. Separate subnets or
wireless client isolation can prevent broadcast discovery. The scanner reports
only replies it received; an empty result does not prove that no server exists.

For a known remote endpoint, use [HTTP signaling](http.md). For relay candidates,
configure ICE on the transport; discovery itself does not acquire STUN/TURN
credentials.
