# Add NetherNet to a Bevy app

`bevy-nethernet` provides LAN and HTTP client/server resources and plugins. It
uses the runtime-free core directly and has no Tokio dependency. Clients advance
nonblocking I/O during updates; accepting servers use a shared UDP worker.

Add the dependencies from the [crate README](../bevy-nethernet/README.md).
The adapter currently uses Bevy 0.20. Add its `tls` feature for HTTPS signaling
or TLS TURN carriers.

## Connect a LAN client

Call `install_client` while configuring an existing Bevy app. Run the
[Tokio LAN echo server](../README.md#try-a-lan-echo-server) as its peer.

```rust,no_run
use bevy_app::{App, Update};
use bevy_ecs::prelude::*;
use bevy_nethernet::prelude::*;

fn install_client(app: &mut App) -> std::io::Result<()> {
    app.add_plugins(NetherClientPlugin)
        .insert_resource(NetherClient::new(2, |_| {})?)
        .add_systems(Update, network_events);
    Ok(())
}

fn network_events(
    mut events: MessageReader<NetherClientEvent>,
    mut client: ResMut<NetherClient>,
    mut attempted: Local<bool>,
) {
    for event in events.read() {
        match event {
            NetherClientEvent::ServerDiscovered(id, data) if !*attempted => {
                println!("connecting to {}", data.server_name);
                *attempted = true;
                if let Err(error) = client.connect(*id) {
                    eprintln!("connect: {error}");
                }
            }
            NetherClientEvent::Connected => {
                if let Some(connection) = client.established() {
                    if let Err(error) = connection.send(b"hello from Bevy") {
                        eprintln!("send: {error}");
                    }
                }
            }
            NetherClientEvent::Disconnected => eprintln!("disconnected"),
            _ => {}
        }
    }
    while let Some(message) = client.recv() {
        println!("{}", String::from_utf8_lossy(&message));
    }
}
```

The plugin updates the resource and emits Bevy messages in `PreUpdate`; your
`Update` systems can respond to them. Keep the app updating regularly: pausing
frames pauses outbound transport progress. `bevy_app::App` alone does not provide
a continuous game loop; use your app's runner. When using the resources outside
a plugin, call `update()` and drain `next_event()` yourself.

`established()` grants send access only after both channels open. Receiving is
also available on the client resource, including accepted messages retained after
a transport failure. A new connection or `disconnect()` discards that old receive
owner. Receive queues are bounded at both transport and application delivery;
overflow closes the connection explicitly while preserving messages accepted
before failure. See [shutdown](shutdown.md#bevy).

## Accept LAN connections

This installs a LAN server in an existing app:

```rust,no_run
use bevy_app::App;
use bevy_nethernet::prelude::*;
use nethernet::protocol::constants::LAN_DISCOVERY_PORT;
use std::net::{Ipv4Addr, SocketAddr};

fn install_server(app: &mut App) -> std::io::Result<()> {
    let mut server = NetherServer::new(
        1, SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_DISCOVERY_PORT)), |_| {},
    )?;
    server.set_server_data(ServerData::new("Bevy server".into(), "Demo".into()));
    app.add_plugins(NetherServerPlugin).insert_resource(server);
    Ok(())
}
```

Add a direct `nethernet` dependency for the shared discovery-port constant.
`NetherServerEvent::SessionConnected` supplies an `EstablishedSessionId`. Keep
that value and use `server.send(&id, bytes)` or `send_unreliable`. `sessions()`
also yields these capabilities. `recv()` returns a descriptive `NetherSessionId`
with each message; correlate it with `established_id.id()`. Descriptive IDs alone
cannot authorize sending or closing, including after an ID is reused.

Sends return immediately. If the result is `ProtocolError::Io` with
`ErrorKind::WouldBlock`, retain the payload and retry on a later update; it was
not admitted. Success acknowledges local admission rather than remote receipt.
Set `ServerLimits` through `set_session_limits` to bound sessions and retained
receive messages/bytes, and `PendingLimits` for unanswered offers. Consume received
messages so their storage and retired-session slots can be released.

## HTTP clients and servers

Install `NetherHttpClientPlugin` with a `NetherHttpClient::new()` resource.
`connect(local_network_id, server_url)` starts a join; handle `NetherHttpClientEvent`
messages and use `established()` and `recv()` as above. `query_server_data(url)`
reports `ServerData` or `QueryFailed`. Initial hostname resolution and TLS trust
setup happen during the explicit call, so perform that setup outside a sensitive
frame where appropriate.

Install `NetherHttpServerPlugin` with a resource from
`NetherHttpServer::bind(bind_addr, configure)`. Call `set_identity` with a
`ServerIdentity` before accepting joins: without it joins receive 503 unless
`allow_unsigned_answers(true)` is selected. Configure HTTP offer trust in the
bind closure. `set_tls` enables HTTPS with the `tls` feature. HTTP examples and
identity choices are explained in [HTTP and ICE](http.md).

## Configure outbound ICE

Both client resources accept `set_ice_config(Some(ClientIceConfig { .. }))`.
Use `bevy_nethernet::prelude::ClientIceConfig`, whose `bind_addr` is a concrete
numeric local interface with an optional ephemeral port. Supply resolved numeric
UDP servers in `ice`, and resolved TCP/TLS `TurnStreamTarget`s in `turn_streams`.
With `tls`, `turn_tls` can override TURN trust independently of HTTPS trust.
Handle the setter's `Result`: it prepares TLS policy and validates targets before
installing the replacement. A failed replacement keeps the prior configuration.

The application resolves services and obtains/renews credentials. HTTP joins
gather Full candidates before sending an offer; LAN uses Trickle candidates.
These client settings do not configure accepting TURN allocations: Bevy servers
currently accept using host candidates.

For renewal, `update_turn_credentials` targets an unambiguous numeric endpoint.
When carriers share an endpoint, inspect `selected_turn_stream()` and call
`update_turn_stream_credentials` with that exact route. Renewal preserves the
allocation's username and socket; local success is not a TURN Refresh response.
See [ICE configuration](http.md#add-stun-or-turn) for expiry and relay policy.
