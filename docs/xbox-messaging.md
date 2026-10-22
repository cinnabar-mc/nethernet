# Integrate Xbox / Player Messaging

Use `CallerSignaling` when your application already has a messaging service
connection and wants to carry NetherNet signals through it. The bridge turns
transport signals into bounded requests for your service driver. It opens no
service socket and does not sign in an account.

## Prepare the inputs

| Input from your application | Where it goes |
| --- | --- |
| Local advertised NetherNet ID | `CallerSignaling::new`'s `local_id` |
| Remote peer's messaging UUID | `CallerSignaling::new`'s `remote_id` |
| Authenticated incoming envelope sender UUID and signal text | `driver.try_deliver` |
| Multiplayer token and the P-384 key named by its `cpk` | `TokenIdentity`, then `ConnectionConfig::identity` |
| Policy for the peer's SDP identity | `server_trust` on a client; `token_trust` on a server |
| STUN/TURN records, expiry, bind address, and relay policy | `client_ice` or `server_ice` |

Your service layer also owns account refresh, WebSocket lifetime, envelope
validation, request correlation, peer receipts, and service message acknowledgements.
The bridge does not obtain any of those inputs for you.

## Create a dialing bridge

Use the [Tokio dependencies](../README.md#install). This function returns the
bridge and the driver your service loop must poll:

```rust,no_run
use nethernet_tokio::{
    CallerSignaling, CallerSignalingConfig, CallerSignalingDriver, CallerSignalingError,
};

fn messaging_bridge(
    local_network_id: String,
    peer_messaging_uuid: String,
) -> Result<(CallerSignaling, CallerSignalingDriver), CallerSignalingError> {
    CallerSignaling::new(
        local_network_id,
        peer_messaging_uuid,
        CallerSignalingConfig::default(),
    )
}
```

Give the bridge to `NetherClient::connect_with(bridge, peer_messaging_uuid, config)`.
Drive the returned future while polling `driver.recv()` and your shared service
connection. A bridge supports one active transport subscription; create a separate
bridge per concurrent connection. Caller signaling makes one attempt; your
application chooses whether a failed attempt may be retried.

For each `SignalRequest` returned by `recv()`:

1. Send `request.signal().to_string()` through your messaging service to the
   peer. Preserve `request.deadline()` for the whole service operation.
2. Keep the request until the correlated delivery result arrives. If
   `requires_peer_receipt()` is true, wait for service acceptance and peer receipt.
3. Complete it with `request.finish(Ok(SignalDelivery::PeerReceived))` only when
   both are confirmed. Otherwise use `ServiceAccepted` after service acceptance,
   or finish with a `CallerSignalingError` on failure.
4. Watch `request.cancelled()` while driving the service request. Cancel its
   service handle when it completes. Already written bytes may have reached the
   service, so do not automatically resend an ambiguous request.

For each incoming service envelope, call
`driver.try_deliver(authenticated_sender_uuid, signal_text)`. Acknowledge that
service envelope only after admission succeeds. On `Capacity`, retain it and
retry, or use `prepare_delivery_before` to wait for space under its original
deadline. Use the sender from the authenticated envelope, rather than an ID
claimed inside the payload. Dropping the bridge driver closes its connection;
it does not close your shared service socket.

## Identity and trust

`TokenIdentity::new(proof_key, multiplayer_token, now)` accepts an already acquired
token and its matching P-384 proof key. It checks token shape, expiry, and `cpk`
binding. Your credential provider must first verify the token issuer, signature,
and account policy. Store the result as `Arc<dyn SdpIdentity>` in
`ConnectionConfig::identity`. Keep the same key available to a higher layer that
needs it for Login; the bridge creates no replacement key.

For signed-out offers, `SelfSignedIdentity::new(now, lifetime)` creates a local
proof key. `SelfSignedIdentity::from_key` uses a key your application already owns.
Neither provides account authentication. `ServerIdentity` signs server answers;
an application-owned `SdpIdentity` can supply another signer.

For received assertions, `TokenTrust::Minecraft` uses issuer keys and
`TokenTrust::Provider` delegates issuer validation to your verifier. The SDP owner
also checks the fingerprint signature using the received token's own key.
`TokenTrust::Any` skips issuer/signature validation and is useful only where
that weaker policy is intentional. With no client `server_trust`, answers are
unchecked. With no LAN `token_trust`, offers are unchecked.

`TokenTrust::ServerAnswer(provider)` permits self-signed ES384 server tokens or
provider-verified RS256 tokens on an application-authorized route. It checks the
SDP proof but does not authorize the service route, remember a key, or authenticate
a player. It applies to answer verification, not offer admission. A failed
provider check does not fall back to a self-signed token.

## Accept unsolicited offers

Use `CallerServerSignaling::new(local_network_id, config)` for multiple incoming
peers on one service connection. Give its backend to `NetherServer::bind_with`.
Supply an answer `identity` and an explicit `token_trust`: the accepting bridge
chooses neither. `set_token_trust(None)` disables later caller-bridge admission.

Its driver uses the same request/deadline/delivery contract as the dialing bridge.
Route incoming envelopes with their authenticated sender UUID. Sender and
connection ID together select a route. Configure `max_routes` and
`max_routes_per_sender` to bound negotiating, accepted, and retained closed
routes. Closing the listener preserves sessions already returned by `accept()`;
dropping the service driver ends their transport after accepted data is retained.

Offers without an identity are refused by default when trust is configured.
`ConnectionConfig::allow_anonymous_offers` explicitly permits a missing identity;
a present identity still must pass verification. An anonymous accepted offer has
no authenticated player claims. HTTP has its own independent offer policy.

For concrete transport wiring with a controlled message carrier, see
[`tests/caller_server.rs`](../nethernet-tokio/tests/caller_server.rs).
For ICE and renewal, see [HTTP and ICE](http.md#add-stun-or-turn); messaging alone
does not provide a relay.
