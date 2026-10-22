# Close connections and drain messages

Closing stops new sends. It does not erase complete messages already accepted
by the receive path. Keep the returned receive owner if those messages matter.
No close method guarantees that the peer received a close notification.

## Tokio

Consume a client with `client.close()`, or a whole accepted connection with
`accepted.close()`. Both return `AcceptedSession<Retired>` with its original
receivers. Drain each receiver through `Ok(None)` or its explicit error:

```rust,no_run
use nethernet_tokio::{NetherClient, Result};

async fn close_and_drain(client: NetherClient) -> Result<()> {
    let mut retired = client.close();
    while let Some(message) = retired.reliable.recv().await? {
        println!("accepted {} reliable bytes", message.len());
    }
    while let Some(message) = retired.unreliable.recv().await? {
        println!("accepted {} unreliable bytes", message.len());
    }
    Ok(())
}
```

If you already split an `AcceptedSession`, consuming `session.close()` returns
`Session<Retired>` and leaves the separate receivers usable. `sender.start_close()`
is a synchronous global close request, usable from `Drop`. `sender.close().await`
also requests closure. `closed().await` observes the request or driver cancellation;
it is not a join of the transport task or an acknowledgement from the peer.

Orderly local cancellation and authenticated peer close produce EOF after the
accepted messages. Transport failure or receive overflow produces accepted
messages, then one error, then EOF. Dropping the reliable receiver closes the
session when another reliable message arrives; unreliable receive is best effort.

`listener.close().await` cancels unaccepted sessions. Sessions already returned by
`accept()` keep running. Close those separately during application shutdown.

## Core event loops

`Session::close(now)` and `Connection::close(now)` consume a live core and return
`(retired, teardown_result)`. Drain the retired owner's `poll()` even when teardown
reports an error. Its output can include accepted messages, an encrypted DTLS
close notification, and TURN deallocation packets. Keep writing those outputs
on their original sockets, with any existing partial-write offset.

The retired owner accepts no new input, credentials, or application sends.
Dropping a core cannot perform socket I/O: the application must send the output.
See the [event-loop guide](sans-io.md) for output and timer handling.

## Bevy

`client.disconnect()` releases the current outbound connection and discards its
receive owner. Read any retained messages you need first. Starting another
connection also discards the old receive owner. After transport failure, `recv`
and `recv_unreliable` can still return messages accepted before failure.

A server disconnects one peer with `server.disconnect(established_id)`. Keep the
`EstablishedSessionId` from its connected event or `sessions()`, rather than
trying to reconstruct it from peer IDs. Its clones observe closure; they cannot
be used to control a later connection that happens to reuse the same IDs.
