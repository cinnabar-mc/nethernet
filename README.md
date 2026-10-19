<br />
<div align="center">

# NetherNet

The WebRTC-based network protocol used in newer versions of Minecraft. It provides LAN discovery and secure peer-to-peer (P2P) connectivity.

[![rust][rust_badge_url]][rust_url]
[![transport][transport_badge_url]][transport_url]
[![license][license_badge_url]][license_url]

</div>

<!-- BADGES -->
[transport_badge_url]: https://img.shields.io/badge/transport-nethernet-black?style=flat-square
[transport_url]: https://github.com/Mojang/bedrock-protocol-docs

[rust_badge_url]: https://img.shields.io/badge/rust-2024-%23D34516?style=flat-square&logo=rust&logoColor=%23D34516&labelColor=white
[rust_url]: https://rust-lang.org/

[license_badge_url]: https://img.shields.io/github/license/bedrock-crustaceans/nethernet?style=flat-square
[license_url]: LICENSE
<!-- BADGES -->

### Crates

- **[`nethernet`](nethernet)** - a pure sans-io implementation. It owns the wire formats, the identity assertions, the signaling state machines, and the WebRTC session itself (ICE, DTLS, SCTP, data channels, driven directly rather than through a generic peer connection), and performs no IO of its own, so it can be driven by any runtime.
- **[`nethernet-tokio`](nethernet-tokio)** - an async tokio wrapper over the sans-io crate, exposing `NetherServer` and `NetherClient`.
- **[`bevy-nethernet`](bevy-nethernet)** - a Bevy plugin wrapping the sans-io crate directly, for games that want to drive it from their own tick rather than through tokio.

### Driving the core

`Session::new(local_addr, is_controlling, session_id, now)` takes a caller-selected
SDP origin identifier and a monotonic time. Choose a distinct identifier for each
local session; the returned `Description` retains it for every encoding.
`Admitted::answer` takes the same inputs when creating a server session. The Tokio
and Bevy adapters generate these identifiers at their runtime boundary.

`Session<Connecting>` and `Connection<Connecting>` can drive control input and
drain their original accepted output, including messages received during
establishment. Only the consuming `try_establish` transition, backed by both
actual data channels opening, returns `Established`. If it is still pending, the
original owner is returned unchanged. Application `send` exists only on
`Established`; control inputs cannot bypass that boundary.

Core `close(self, now)` consumes a live owner and returns `(Retired, teardown_result)`.
Drain the retired owner's already accepted messages and best-effort deallocation
output even when teardown reports an error. It cannot accept input, credentials
or new application sends.
Remote failure still arrives at runtime and preserves the existing accepted
message/terminal order; readiness does not promise that a remote peer stays live.

Tokio `Session` is a unique lifecycle owner. `session.sender()` or
`client.sender()` shares an established `SessionSender` for concurrent send and
control work. `start_close` on that capability requests global closure
synchronously, including from an application's Drop; other capabilities then
observe closure at runtime. Consuming `Session::close` returns a retired owner,
and consuming `NetherClient::close` returns the retired session with both original
receivers so accepted messages remain readable.

For an application that must recheck authority after backpressure,
`SessionSender::reserve_send(deadline)` reserves one slot in the same bounded
command queue without queuing a payload. Retain that actual future across other
service work; cancellation loses its wait position, and dropping its owned
`SendPermit` releases capacity. Commands enter the FIFO in commit order, rather
than reservation order.
After a fresh application check, `permit.commit(channel, bytes)` synchronously
returns a `SendReceipt`; consuming `receipt.acknowledged().await` observes the
original actor's local core admission result. No await belongs between that check
and commit. The original absolute deadline and shared closure are checked again;
a reservation does not keep the session authorized or live. Canceling the receipt
may retract a not-yet-admitted deadline-bound command, and cannot undo an admitted
message or an already admitted prefix. Without a deadline, a queued command
remains eligible for admission after receipt cancellation. The deadline bounds
capacity acquisition and local core admission; it does not bound the receipt
wait. Neither reservation nor acknowledgement promises remote delivery. See
[`reserve_send`](nethernet-tokio/src/session/send.rs) for a complete usage example.

Bevy clients remain stable discovery resources. Borrow
`client.established()` to access the actual ready transport's send methods;
retrospective receive remains available on the resource before or after a ready
connection. Bevy servers return opaque `EstablishedSessionId` capabilities from
`sessions()` and connected events. Their descriptive `id()` cannot authorize
sending or closing a different pool entry, including a later reuse of the same
peer ids. Closing consumes the local capability; its copies observe remote or
global closure at runtime.

`HttpSignalerInput::Request` carries both `now: Instant` for answer deadlines and
`wall: SystemTime` for credential expiry. Supply the receive time from each clock;
UTC changes do not alter pending-answer deadlines. HTTP execution stays in the
runtime adapters.

### Features

- Secure communication over WebRTC (DTLS/SCTP)
- LAN server discovery, with retransmission of unanswered signals
- Signaling over LAN discovery or over the HTTP endpoint of a dedicated server, as a client and as a server
- Identity assertions: offers are validated against the fingerprints they carry, and answers are signed with the identity of the server
- Candidate inference for peers that gathered nothing a host on another network can reach
- Connection limits and trusted proxies on the HTTP endpoint

### Usage

To build the project:

```bash
cargo build --release
```

To run the examples:

```bash
# NetherNet server
cargo run --example server -p nethernet-tokio

# NetherNet client
cargo run --example client -p nethernet-tokio

# List the servers advertising themselves on the local network
cargo run --example scanner -p nethernet-tokio
```

### Serving the HTTP endpoint

```rust
let signaling = HttpSignalingServer::bind(
    "0.0.0.0:19132".parse()?,
    HttpServerConfig {
        network_id: "1234".to_string(),
        tls: Some(nethernet_tokio::util::tls::from_pem("fullchain.pem", "key.pem").await?),
        ..Default::default()
    },
)
.await?;

// Required for HTTP by default: NetherServer::bind_with fails with NetherError::IdentityRequired
// without it, unless ConnectionConfig::allow_unsigned_answers is set.
let identity = nethernet_tokio::util::identity::from_pem_or_create("identity.pem", "example.com").await?;
let config = ConnectionConfig {
    identity: Some(Arc::new(identity)),
    ..Default::default()
};

let mut listener = NetherServer::bind_with(signaling, config).await?;
let AcceptedSession { session, .. } = listener.accept().await?;
```

Answers are signed with the identity in `ConnectionConfig::identity`, which
`nethernet_tokio::util::identity::from_pem_or_create` loads from a PEM and creates on first
use. Clients pin that key, so it should be kept between restarts, and **every answer must
carry one** (guide section 5.2) - a vanilla client refuses the connection otherwise, whether
signaling ran over HTTPS or plaintext HTTP, so an HTTP server refuses to start without one by
default. A server that only serves non-vanilla clients, which do not verify answers, can opt out
with `ConnectionConfig::allow_unsigned_answers`; an identity that is set still signs. It stays
optional over LAN discovery. In `bevy-nethernet`, `NetherHttpServer::set_identity` is required
the same way and joins are answered with 503 until it is called, unless
`NetherHttpServer::allow_unsigned_answers(true)` opts out. Offers over
HTTP are validated against `HttpSignalerConfig::token_trust` alone, and `ConnectionConfig::token_trust` applies to LAN and caller-bridge offers. It
defaults to accepting any self-signed token while still binding it to the certificate the
peer presents. `nethernet_tokio::util::jwks::Jwks::minecraft` fetches the keys needed to
require a token issued by the Minecraft authorization service instead.

### Server ownership

`ConnectionConfig::max_sessions` bounds negotiating, queued and accepted Tokio
server sessions together. A reservation is retained through actual driver
retirement and every session or receiver handle; closing a connection while
keeping its receivers does not free it. The existing `max_pending` and
`max_pending_per_network_id` separately limit negotiations. Excess offers are
refused with `IncomingConnectionIgnored` (HTTP responds with 403); setting `max_sessions` to zero refuses
all offers.
Refusal delivery retains at most one best-effort send; further excess offers may
expire while that signaling operation is stalled.

The listener owns its pending negotiations and bounded late-candidate queues.
Closing or dropping it cancels unaccepted peers through metadata, answer delivery
and channel establishment. Sessions already returned by `accept()` or `Stream`
continue independently and preserve their accepted receive FIFO. Candidate
overflow retires only the affected peer. Session commands apply backpressure at
their caller; `send_before` retains its original admission deadline while waiting
for capacity.

### Client identities

`ConnectionConfig::identity` accepts an `Arc<dyn SdpIdentity>`. Use
`SelfSignedIdentity::new(now, lifetime)` for signed-out client offers. Its token
carries base64 DER public keys in `cpk` and `x5u`, and signs the SDP fingerprints.
Use `SelfSignedIdentity::from_key` with a caller-owned `Arc<SigningKey>` when a
later application Login must own the same proof. `new` still generates one key;
`signing_key()` borrows it.
Time and lifetime are explicit inputs; expired identities cannot sign offers.

`ServerIdentity` retains its existing JWK token format and also implements
`SdpIdentity`. Account authentication, credentials and refresh belong to an
application-owned implementation of that interface.

For an explicitly authorized service route, `TokenTrust::ServerAnswer(provider)`
accepts a self-signed ES384 server token or delegates an RS256 token to the supplied
provider. Both paths verify the token's own detached SDP fingerprint signature.
An invalid provider token never falls back to self-signed trust. Self-signed server
token timestamps are not player credential validity; the caller's original
transport deadline still applies. This mode is accepted only by `verify_answer`,
not offer admission. It does not authorize a route, authenticate a player, remember
a key or make a trust choice for the application. `Provider` remains strict, and
`Any` retains its existing unverified-token behavior.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Caller-owned signaling services

`nethernet-tokio::CallerSignaling::new(local_id, remote_id, config)` returns a
transport backend and a `CallerSignalingDriver`. Create one bridge per concurrent
connection and poll each driver's `recv` alongside your shared service socket.
The bridge opens no sockets and starts no tasks or runtime. The Tokio client
continues to own its UDP socket and connected-session task.

For Player Messaging, `local_id` is the advertised NetherNet ID and `remote_id`
is the peer's messaging UUID. Submit each request's signal text and original
`deadline()` to the service, with `requires_peer_receipt()` as the delivery policy.
Complete it with `SignalDelivery::ServiceAccepted` or `PeerReceived` only after
the corresponding service evidence arrives. Offers require both service acceptance
and peer receipt by default. If `request.cancelled()` completes, cancel the service
handle; a partially written request has an ambiguous outcome and must not be resent
automatically. Caller signaling makes one connection attempt regardless of the
convenience client's `attempts` setting.

On receipt, call `driver.try_deliver(sender_uuid, signal_text)` using the
**authenticated envelope sender**, not its advertised NetherNet ID. Acknowledge
the original service envelope only after admission succeeds. Incoming queue
capacity is bounded, and outgoing capacity includes requests held by the caller.
A second active subscription returns an error. Dropping a subscription discards
its queued old signals and allows a fresh attempt; dropping the driver closes
that bridge without closing the shared service socket.

Keep account, messaging UUID, advertised network ID, multiplayer token and P-384
key ownership in the application. Supply its `SdpIdentity` through
`ConnectionConfig::identity`; the bridge creates no replacement identity key.
Service signaling alone does not supply STUN/TURN credentials or select a relay
policy; those inputs remain with the application.

`CallerServerSignaling::new(local_id, config)` returns a bounded accepting
backend and `CallerServerSignalingDriver` for unsolicited offers from multiple
authenticated senders on one caller-owned service connection. Bind it with
`NetherServer::bind_with`. Supply the existing answer `identity` and an explicit
`token_trust` for offers; the bridge chooses neither. `set_token_trust(None)`
disables later caller-bridge offer admission. Existing HTTP and LAN policies
remain unchanged. `ServerSignaling::signals()` is fallible so a duplicate caller
listener fails synchronously before spawning transport work.

Anonymous offers are disabled by default. `ConnectionConfig::allow_anonymous_offers`
permits a missing SDP identity while retaining the required explicit `token_trust`;
a present identity still passes token and fingerprint verification. An anonymous
accepted offer supplies no authenticated player claims. Sans-I/O callers select
this distinction with `OfferPolicy::with_anonymous_offers`. HTTP's independent
signaler policy is unchanged.

Use the same `SignalRequest`, original deadlines and delivery evidence as client
bridges. Incoming `try_deliver` commits immediately; `prepare_delivery_before`
retains a cancel-safe capacity wait and checks the original deadline at actual
queue commitment. Only then acknowledge its authenticated service envelope.
Sender and connection ID jointly identify a route. Unpolled offer waits reserve
bounded route capacity and release it on drop; duplicates and unknown candidates
cannot create or replace a route. `max_routes` and `max_routes_per_sender` include
negotiating, accepted and retained closed receiver lifetimes. Closing the
listener preserves already accepted peers, while dropping the service driver
ends their transport and preserves accepted data before one receive error.

Configured UDP ICE sessions can gather server-reflexive and TURN relay candidates.
The pure `nethernet::session::IceConfig` owns resolved endpoints, credential
expiry, gathering deadlines and candidate policy. `Session::new` remains
host-only; use `Session::new_with_ice` for configured paths. Full ICE callers drive
gathering to `GatheringState::Complete` before encoding their SDP. Trickle callers
drain `Session::poll_local_candidate` or `Connection::poll_local_signal` while
continuing to feed packets and time.

The optional Tokio client adapter accepts `ConnectionConfig::client_ice`:

```rust,ignore
let servers = nethernet_tokio::resolve_ice_servers(
    &acquired_credentials.ice_servers,
    local_bind_address,
    original_credential_expiry,
    resolution_deadline,
).await?;
let config = nethernet_tokio::ConnectionConfig {
    client_ice: Some(nethernet_tokio::ClientIceConfig {
        ice: nethernet::session::IceConfig { servers, ..Default::default() },
        bind_addr: Some(local_bind_address),
    }),
    ..Default::default()
};
```

The accepting adapter uses `ConnectionConfig::server_ice` with
`ServerIceConfig { ice, bind_addr }`. Its bind address is explicit, including the
outer UDP family; the same pure configuration, bounded endpoints and absolute
TURN credential expiry apply. Full mode gathers before encoding/signing its
answer. Trickle mode continues gathering during initial answer delivery, but
late candidate sends wait until the answer and its initial candidates have
actually completed in order. `NetherServer::set_server_ice` replaces configuration
for later offers; it never extends an existing credential's expiry. Use
`Session::update_turn_credentials` to renew a live allocation.

A pure caller that gathers its own accepting session can use
`Admitted::prepare_answer(&mut session, description, now, wall)`, then transfer
that exact session synchronously with `PreparedAnswer::finish`. Preparation
rechecks offer validity at the supplied current wall time and signs the original
DTLS fingerprints. The caller retains its allocation on any preparation error
and must close/drain it. This API creates no service account, credential source,
HTTP client, socket or runtime.

The application acquires and renews service credentials. DNS runs only in the
adapter; the core receives numeric endpoints. Full mode gathers before signing
the offer. Trickle mode continues UDP gathering while signaling is pending and
sends later candidates through the retained signaling owner. Runtime session
handles accept credential rotation through `update_turn_credentials`. Cancelling
negotiation or dropping the driver stops its state and attempts relay release.

This path supports UDP STUN and TURN with IPv4 relay allocations over IPv4 or
IPv6 outer UDP. Explicit IPv6 relay allocation and TURN TCP/TLS remain incomplete.
The Bevy LAN and HTTP clients accept `set_ice_config(Some(ClientIceConfig {
    bind_addr: local_interface,
    ice: IceConfig { servers, ..Default::default() },
}))` using types from `bevy_nethernet::prelude` and `nethernet::session`.
`local_interface` is a concrete numeric local address with an optional ephemeral
port; all server endpoints must have the same family. HTTP joins gather Full
candidates before encoding/signing the offer. LAN carries Trickle candidates,
including those gathered after its initial offer. Active clients expose
`update_turn_credentials` for password renewal under the original expiry.

Outbound Bevy clients poll their nonblocking UDP socket and pure connection on
`update`, without a socket thread or Tokio dependency. Call updates regularly;
pausing frames also pauses transport progress. Each client owns an exclusive UDP
socket, including its TURN allocation tuples. The server adapter retains its
existing shared-socket worker and command/event queues; this does not multiplex
multiple relay allocations onto a shared TURN tuple. Outbound work reads at most
64 datagrams and drains at most 1024 core outputs per update. Transport delivery
and application delivery each retain at most 1024 messages and 16 MiB; exceeding a
receive budget closes the client explicitly. On transport failure, both existing
delivery stages retain their accepted messages for retrospective reads; neither
stage admits new data after retirement. Explicit disconnect or a new connection
discards the old receive owner. Sends apply core expiry immediately
and return `WouldBlock` before admitting more work when the drain budget is full.
Cancellation drops the socket owner after finite best-effort relay release.
Initial HTTP hostname resolution/platform TLS setup are synchronous explicit
setup; frame retries reuse their prepared target and trust configuration.

The Tokio driver admits reliable messages into one FIFO shared with the application
receiver. Its packet budget is twice the default receiver capacity; its byte budget
is the default capacity times the protocol segment size. Application backpressure
does not block transport timers or signaling. Accepted messages remain available
after transport retirement, followed by EOF on local cancellation or authenticated
peer close, or one explicit error on transport failure or receive overflow. Dropping
the reliable receiver closes the session when the next reliable message arrives;
unreliable receive remains best effort. Existing TURN allocations require the same
username during password rotation. A new username requires a new socket and allocation.

Before a remote description installs ICE credentials, the core discards peer
checks for RTC to retry while continuing configured STUN/TURN transactions.
Signaling completion still has to fit the peers' original establishment budgets.
An authenticated DTLS peer close delivers any complete final message, routes its
close reply through the selected ICE path, then releases transport state once and
emits `SessionEvent::PeerClosed`. Transport failures emit `SessionEvent::Failed`.
