//! Async NetherNet clients and servers on your Tokio runtime.
//!
//! Choose [`LanSignaling`] for discovery, [`HttpSignaling`] for a known server URL,
//! or [`CallerSignaling`] for an existing application-owned messaging connection.
//! [`NetherClient`] sends and receives messages; [`NetherServer`] yields
//! [`AcceptedSession`] values with separate reliable and unreliable receivers.
//!
//! # Advertise a LAN echo server
//!
//! ```no_run
//! use nethernet_tokio::{LanSignaling, NetherServer, ServerData};
//! use nethernet_tokio::protocol::constants::LAN_DISCOVERY_PORT;
//! use std::net::{Ipv4Addr, SocketAddr};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signaling = LanSignaling::new(
//!     1, SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_DISCOVERY_PORT)),
//! ).await?;
//! signaling.set_server_data(ServerData::new("Echo".into(), "Demo".into()));
//! let mut listener = NetherServer::bind(signaling).await?;
//! let mut peer = listener.accept().await?;
//! while let Some(message) = peer.reliable.recv().await? {
//!     peer.session.send(message).await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See the [client/server quickstart](https://github.com/cinnabar-mc/nethernet#try-a-lan-echo-server),
//! [HTTP and ICE guide](https://github.com/cinnabar-mc/nethernet/blob/main/docs/http.md),
//! and [Tokio guide](https://github.com/cinnabar-mc/nethernet/blob/main/docs/tokio.md).
//! Accounts, signaling services, identity policy, and ICE credentials come from
//! your application; configure them through [`ConnectionConfig`].
pub mod addr;
pub mod builders;
pub mod credentials;
pub mod error;
pub mod ice;
pub mod protocol;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod util;

pub use addr::Addr;
pub use builders::*;
pub use credentials::{Credentials, IceServer};
pub use error::{NetherError, Result};
pub use ice::{IceResolveError, ResolvedIceTargets, resolve_ice_servers, resolve_ice_targets};
pub use nethernet::identity::{
    PlayerInfo, SdpIdentity, SelfSignedIdentity, ServerIdentity, TokenIdentity, TokenTrust,
};
pub use nethernet::phase::{Connecting, Established, Live, Phase, Retired};
pub use protocol::packet::discovery::{MessagePacket, RequestPacket, ResponsePacket, ServerData};
pub use protocol::{Message, MessageSegment, Signal, SignalType};
pub use session::{
    AcceptedSession, RttObservation, SendPermit, SendReceipt, Session, SessionReceiver,
    SessionSender,
};
pub use signaling::caller::server::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerServerSignalingDriver,
};
pub use signaling::caller::{
    CallerSignaling, CallerSignalingConfig, CallerSignalingDriver, CallerSignalingError,
    SignalDelivery, SignalRequest,
};
pub use signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
pub use signaling::lan::{LanConfig, LanSignaling};
pub use signaling::{ClientSignaling, ServerSignaling};
pub use transport::{
    ClientIceConfig, ConnectionConfig, NetherClient, NetherServer, ServerIceConfig, Timeouts,
};
