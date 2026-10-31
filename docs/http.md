# HTTP signaling and ICE

HTTP signaling exchanges an SDP offer and answer with a known server URL.
The transport then sends application messages over the negotiated ICE path.
HTTP uses Full ICE: candidates are gathered before the SDP is sent, rather
than sent later as separate signaling messages.

## Run a local pair

Use the [Tokio dependencies](../README.md#install), and add the core crate for
its ICE configuration types:

```toml
nethernet = { git = "https://github.com/cinnabar-mc/nethernet" }
```

Save this as `src/bin/http.rs` and run `cargo run --bin http`. It binds both
transport sockets to loopback, starts a signed HTTP server on an ephemeral port,
and sends one reliable message. No account or external STUN/TURN server is
needed for this local example.

```rust,no_run
use bytes::Bytes;
use nethernet::session::IceConfig;
use nethernet_tokio::{
    ClientIceConfig, ConnectionConfig, HttpServerConfig, HttpSignaling,
    HttpSignalingServer, NetherClient, NetherServer, SelfSignedIdentity,
    ServerIceConfig, ServerIdentity,
};
use std::{sync::Arc, time::{Duration, SystemTime}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http = HttpSignalingServer::bind(
        "127.0.0.1:0".parse()?,
        HttpServerConfig { network_id: "server".into(), ..Default::default() },
    ).await?;
    let url = format!("http://{}", http.local_addr());
    let mut listener = NetherServer::bind_with(http, ConnectionConfig {
        identity: Some(Arc::new(ServerIdentity::generate("local-demo", SystemTime::now())?)),
        server_ice: Some(ServerIceConfig {
            ice: IceConfig::default(),
            bind_addr: "127.0.0.1:0".parse()?,
            turn_streams: Vec::new(),
            turn_tls: None,
        }),
        ..Default::default()
    }).await?;

    let client = NetherClient::connect_with(
        HttpSignaling::new("client".into())?,
        url,
        ConnectionConfig {
            identity: Some(Arc::new(SelfSignedIdentity::new(
                SystemTime::now(), Duration::from_secs(300),
            )?)),
            client_ice: Some(ClientIceConfig {
                ice: IceConfig::default(),
                bind_addr: Some("127.0.0.1:0".parse()?),
                turn_streams: Vec::new(),
                turn_tls: None,
            }),
            ..Default::default()
        },
    ).await?;
    let mut accepted = listener.accept().await?;
    client.send(Bytes::from_static(b"hello over HTTP signaling")).await?;
    if let Some(message) = accepted.reliable.recv().await? {
        println!("{}", String::from_utf8_lossy(&message));
    }
    let mut retired = client.close();
    while retired.reliable.recv().await?.is_some() {}
    listener.close().await?;
    Ok(())
}
```

The empty `IceConfig` uses host candidates. Full ICE describes how candidates
are exchanged; it does not imply that a relay is configured.

## Choose identity and trust

HTTP servers require `ConnectionConfig::identity` by default. For a server that
keeps its identity between restarts, use
`nethernet_tokio::util::identity::from_pem_or_create(path, domain).await?` and store
the returned signer in `Arc`. The example generates an in-memory signer for one
run. `allow_unsigned_answers` explicitly allows a server without a signer.

HTTP offer verification belongs to `HttpServerConfig::signaler.token_trust`,
whose default is `Some(TokenTrust::Any)`. The example client's self-signed identity
satisfies that local demonstration policy. `Any` does not authenticate an issuer.
`ConnectionConfig::token_trust` instead controls LAN and caller-bridge offers.

Client answer verification belongs to `ConnectionConfig::server_trust`. The
example leaves it unset, so it does not authenticate the server identity. Choose
an explicit verifier or key policy for your deployment; see
[identity and trust](xbox-messaging.md#identity-and-trust).

For HTTPS, set `HttpServerConfig::tls` using
`nethernet_tokio::util::tls::from_pem(cert_path, key_path).await?`. TLS certificates
for HTTP and the SDP signing identity serve different purposes. A valid HTTPS
certificate does not choose your SDP peer trust policy.

`HttpSignaling::server_data(&url).await` reads the advertised server data through
GET `/v1/join`. Joins use POST `/v1/join/{local_network_id}`. The remote argument
to `NetherClient::connect_with` is the base HTTP/HTTPS URL.

## Join by host and port

Use `signaling::http::HttpProbe::new(reqwest::Client::builder())` for an address
whose HTTP endpoint is not known. Supply your TLS and egress policy on that
builder. `probe(host, port, deadline).await` returns the first completed 2xx base
URL; port zero means an omitted port. Discovery has a six-second overall limit
and disables redirects. It tries HTTPS together, gives it up to a one-second
head start, then also tries HTTP. A failed secure game port releases its plain
HTTP alternative immediately. No answer returns an error.

`select(host, port, cache, deadline)` also accepts an optional caller-owned
`ProbeCache`. Answers live for ten minutes and their URL is rechecked before
each join. Use the returned `ProbeSelection::connect` with `probe.signaling(id)`
and your existing `ConnectionConfig`; a failed or cancelled dial forgets its
selection. If a later game Login fails, call `selection.forget()` as well. An
older receipt cannot forget a newer answer. `selection.login_address()` gives
the selected URL with one explicit port for Login metadata.

## Add STUN or TURN

Your application obtains ICE service records and their expiry. Resolve them
before connecting. This helper takes service records that you already acquired;
it does not contact an account or credential service:

```rust,no_run
use nethernet::session::IceConfig;
use nethernet_tokio::{ClientIceConfig, IceServer, resolve_ice_targets};
use std::{net::SocketAddr, time::Instant};

async fn configure_ice(
    service_records: &[IceServer],
    local_bind: SocketAddr,
    credential_expiry: Instant,
    resolution_deadline: Instant,
) -> Result<ClientIceConfig, Box<dyn std::error::Error>> {
    let targets = resolve_ice_targets(
        service_records, local_bind, credential_expiry, resolution_deadline,
    ).await?;
    Ok(ClientIceConfig {
        ice: IceConfig { servers: targets.datagrams, ..Default::default() },
        bind_addr: Some(local_bind),
        turn_streams: targets.turn_streams,
        turn_tls: None,
    })
}
```

Install the result in `ConnectionConfig::client_ice`. Use a local interface
address appropriate to the peer's network, rather than loopback. For accepting
connections, fill `ServerIceConfig` with the same resolved fields and an explicit
`bind_addr`, then set `ConnectionConfig::server_ice`. Each side gathers from its
own configuration. UDP server addresses must match the local UDP socket family.

`resolve_ice_targets` supports UDP STUN/TURN and unopened TCP/TLS TURN targets.
`resolve_ice_servers` is the UDP-only alternative. Both use one absolute resolution
deadline and the original credential expiry. Do not restart a cached credential's
lifetime when using it again. Set `IceConfig::policy` to `IcePolicy::RelayOnly`
when only relay candidates should be advertised or checked.

TCP/TLS TURN carriers still allocate UDP relays. `TurnStreamTarget` retains its
original TLS hostname for verification; its resolved address is not a replacement
TLS name. `turn_tls: None` uses verified platform roots; supply a `rustls`
configuration to choose a different verifier. The core itself performs no DNS,
TCP connection, or TLS work. The runtime adapter owns those operations.

## Renew credentials

Keep credential acquisition and refresh in your application. Acknowledged TURN
allocations follow the lifetimes in Allocate/Refresh responses, separately from
service credential cache expiry. Replacing a password for an existing allocation
requires the same endpoint and username. A new username needs a new allocation
and transport socket.

Tokio sessions and senders expose `update_turn_credentials`. For stream targets,
`update_turn_streams_before(fresh_targets, deadline)` selects exactly one matching
fresh target for the active stream's endpoint, TLS name, address family, and bind
policy. It refreshes that allocation without reconnecting. Direct/UDP selections
need no stream update. Success reports local admission; the TURN response decides
the resulting lease. Missing or ambiguous matches fail.

`NetherServer::set_server_ice` applies configuration to later offers. Pending and
accepted peers keep their current configuration. In Full mode, allow enough
HTTP answer and negotiation time for gathering to finish.

## Restrict transport destinations

Services that connect on behalf of untrusted users can set
`ConnectionConfig::egress_policy` to an `EgressPolicy`. The callback receives the
actual numeric UDP destination or TCP/TLS TURN endpoint before I/O. The same
policy remains installed for gathering, established traffic and cleanup. Each
physical write rechecks it, including resumed UDP sends, retained TURN frames
and TLS control output. A live refusal retires the connection while preserving
already accepted input. The default leaves routing unrestricted for ordinary
clients and LAN connections.

This transport policy does not configure the HTTP signaling client. A gateway
must separately admit and pin its HTTP resolver results, reject redirects and
unwanted proxies, and retain normal TLS hostname verification.
