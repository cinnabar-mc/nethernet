//! NetherNet clients and servers as Bevy resources and plugins, without Tokio.
//!
//! Add a resource and its matching plugin to your app. Clients advance network I/O
//! during frame updates; accepting servers use a shared UDP worker. The plugins
//! update resources and emit connection messages in `PreUpdate`.
//!
//! # Install a LAN client
//!
//! ```no_run
//! use bevy_app::App;
//! use bevy_nethernet::prelude::{NetherClient, NetherClientPlugin};
//!
//! fn install(app: &mut App) -> std::io::Result<()> {
//!     app.add_plugins(NetherClientPlugin)
//!         .insert_resource(NetherClient::new(2, |_| {})?);
//!     Ok(())
//! }
//! ```
//!
//! Handle [`client::NetherClientEvent`] to choose a discovered peer and send after
//! connection. The [Bevy guide](https://github.com/cinnabar-mc/nethernet/blob/main/docs/bevy.md)
//! shows the systems and server setup. Use [`http_client::NetherHttpClient`] and
//! [`http_server::NetherHttpServer`] for HTTP signaling; enable the `tls` feature
//! for HTTPS or TLS TURN carriers. Identity and service credentials remain with
//! your application.
mod connection;
mod http_stream;
mod http_wire;
mod outbound;
mod pending;
mod socket;
mod tcp_wire;

pub mod client;
pub mod http_client;
pub mod http_server;
pub mod server;

pub mod prelude {
    pub use crate::client::{NetherClient, NetherClientEvent, NetherClientPlugin, NetherClientSet};
    pub use crate::http_client::{
        JoinError, NetherHttpClient, NetherHttpClientEvent, NetherHttpClientPlugin,
        NetherHttpClientSet, QueryError,
    };
    pub use crate::http_server::{
        NetherHttpServer, NetherHttpServerEvent, NetherHttpServerPlugin, NetherHttpServerSet,
    };
    pub use crate::outbound::{ClientIceConfig, EstablishedClient};
    pub use crate::pending::{PendingLimits, ServerLimits};
    pub use crate::server::{
        EstablishedSessionId, NetherServer, NetherServerEvent, NetherServerPlugin, NetherServerSet,
        NetherSessionId,
    };
    pub use nethernet::prelude::{
        HttpSignalerConfig, LanSignalerConfig, ServerData, ServerIdentity,
    };
}
