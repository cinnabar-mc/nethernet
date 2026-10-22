# Tokio clients and servers

`nethernet-tokio` owns sockets, timers, negotiation tasks, and established session
tasks on your Tokio runtime. Start with the [LAN echo pair](../README.md) or the
[HTTP pair](http.md). Use `connect_with` and `bind_with` to provide a
`ConnectionConfig`.

## Send and receive messages

`NetherClient::send` and `recv` use the reliable message channel.
`send_unreliable` and `recv_unreliable` use the unordered channel with no
retransmissions. A successful send means the local core admitted the message;
it does not acknowledge peer receipt or application processing.

A server receives an `AcceptedSession` with three fields:

| Field | Purpose |
| --- | --- |
| `session` | Owns the connection lifetime and provides send/control methods. |
| `reliable` | Receives complete reliable messages. |
| `unreliable` | Receives complete unreliable messages. |

`NetherClient::into_accepted()` exposes the same split on a client. Retain
`session` while using its receivers. Dropping it requests connection closure.

`NetherClient` also implements Tokio `AsyncRead` and `AsyncWrite` for its reliable
channel. Reads may split or combine message bodies. Use the message APIs when
your application depends on message boundaries, and avoid mixing stream reads
with message reads: `recv` returns a partially read body's remainder first.

## Share sending with another task

Clone `SessionSender`, obtained from `session.sender()` or `client.sender()`.
This shares send/control access while the original session owns its lifetime.

```rust,no_run
use bytes::Bytes;
use nethernet_tokio::{Result, Session};

async fn send_from_worker(session: &Session) -> Result<()> {
    let sender = session.sender();
    sender.send(Bytes::from_static(b"from a worker")).await
}
```

All senders observe a shared close request. Dropping a sender does not close the
session while its other owners remain. Calling `start_close()` does request
global closure. See [shutdown](shutdown.md).

## Handle backpressure and deadlines

Sends wait for space in a bounded command queue. Keep receiving while another
task sends so your application does not create a circular wait. `send_before`
takes an absolute `std::time::Instant`: it bounds queue admission and local core
admission, rather than delivery to the peer.

If permission to send can change while waiting for queue space, reserve first,
recheck application state, and commit synchronously:

```rust,no_run
use bytes::Bytes;
use nethernet_tokio::{Result, SessionSender, session::Channel};
use std::time::Instant;

async fn send_if_allowed(
    sender: &SessionSender,
    payload: Bytes,
    deadline: Instant,
    allowed: impl FnOnce() -> bool,
) -> Result<()> {
    let permit = sender.reserve_send(Some(deadline)).await?;
    if !allowed() {
        return Ok(()); // Dropping the permit returns queue capacity.
    }
    let receipt = permit.commit(Channel::Reliable, payload)?;
    receipt.acknowledged().await
}
```

Keep the reservation future across unrelated wakes; canceling it loses its queue
position. Commands enter the queue in commit order. Do not await between your
application check and `commit`. `acknowledged` reports local core admission, not
wire transmission. Its wait may outlast the admission deadline.

Canceling a deadline-bound receipt can retract an unadmitted command. It cannot
undo an admitted message or prefix. Without a deadline, a queued command remains
eligible after its receipt is dropped.

## Set limits and refresh configuration

Set `ConnectionConfig::max_incoming_message_bytes` before dialing or binding to
limit each complete incoming body. It is independent of outgoing negotiated size
and queue budgets; zero refuses nonempty bodies. Oversized input closes the
connection after messages already accepted. Outgoing oversized messages are
rejected before they are queued or copied. The receive FIFO has separate packet
and byte budgets derived from `DEFAULT_PACKET_CHANNEL_CAPACITY` and
`DEFAULT_MAX_RECEIVED_BYTES` in the core's protocol constants. One larger body
that passed the incoming limit can occupy an otherwise empty FIFO alone.
Receive backpressure does not pause transport timers or signaling.

For servers, `max_pending` and `max_pending_per_network_id` limit negotiations;
`max_sessions` includes negotiating, queued, accepted, and retained closed
sessions. A closed receiver still retaining data keeps its slot. Zero refuses
all offers. Closing the listener stops pending peers while accepted sessions
continue independently.

`set_identity`, `set_server_ice`, and `set_token_trust` change a listener's policy
for later offers. Existing peers keep the configuration used for their attempt.
These setters do not acquire credentials. For TURN refresh and candidate
configuration, see [HTTP and ICE](http.md#add-stun-or-turn).
