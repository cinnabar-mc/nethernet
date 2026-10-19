//! Tokio transport for NetherNet with LAN, HTTP and caller-owned dialing/accepting signaling.
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
pub use ice::{IceResolveError, resolve_ice_servers};
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
