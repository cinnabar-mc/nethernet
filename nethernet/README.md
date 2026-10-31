# nethernet

The runtime-free NetherNet protocol core. Use it when your application owns the
sockets and event loop. It provides LAN/HTTP signaling state machines, SDP
identities, ICE, DTLS, SCTP, and reliable/unreliable message framing.

```toml
[dependencies]
nethernet = { git = "https://github.com/cinnabar-mc/nethernet" }
bytes = "1"
```

Start with the [custom event-loop guide](../docs/sans-io.md). Feed complete input
packets and monotonic time, drain outputs, and perform the requested I/O yourself.
The core performs no DNS, HTTP requests, socket I/O, or background scheduling.

For socket-owning APIs, use [Tokio](../nethernet-tokio/README.md).
[Identity and messaging inputs](../docs/xbox-messaging.md)
remain application-owned with every integration.

See the [workspace README](../README.md) for runnable client/server examples and
[LICENSE](../LICENSE) for Apache-2.0 and upstream information.
