# bevy-nethernet

NetherNet resources and plugins for Bevy. LAN and HTTP clients progress during
frame updates. Accepting servers use a shared UDP worker. This crate has no
Tokio dependency.

```toml
[dependencies]
bevy-nethernet = { git = "https://github.com/cinnabar-mc/nethernet" }
bevy_app = { version = "0.20", default-features = false }
bevy_ecs = { version = "0.20", default-features = false, features = ["std"] }
```

Enable the `tls` feature for HTTPS signaling or TLS TURN carriers.
[The Bevy guide](../docs/bevy.md) shows how to install a client resource, discover
a server, and send after connection. It also covers accepting servers and ICE.

Accounts, identity policy, and service credentials remain with the application.
Use [nethernet](../nethernet/README.md) to drive a different event loop or
[nethernet-tokio](../nethernet-tokio/README.md) for async I/O.

See the [workspace README](../README.md) and [LICENSE](../LICENSE).
