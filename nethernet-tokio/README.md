# nethernet-tokio

Async NetherNet clients and servers on your Tokio runtime. The adapter owns
network sockets and timers and exposes complete reliable/unreliable messages.
Choose LAN discovery, an HTTP endpoint, or your existing messaging service for
signaling.

```toml
[dependencies]
nethernet-tokio = { git = "https://github.com/cinnabar-mc/nethernet" }
bytes = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

- [Run the LAN echo pair](../README.md#try-a-lan-echo-server).
- [Connect over HTTP and configure ICE](../docs/http.md).
- [Integrate Xbox/Player Messaging](../docs/xbox-messaging.md).
- [Share senders and use deadlines](../docs/tokio.md).
- [Close and drain received messages](../docs/shutdown.md).

Accounts, signaling service connections, trust decisions, and STUN/TURN
credentials come from your application. This crate runs the transport using
those inputs; it does not implement Minecraft Login or gameplay.

See the [workspace README](../README.md) and [LICENSE](../LICENSE).
