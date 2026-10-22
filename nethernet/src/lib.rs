//! NetherNet protocol state for applications that own their sockets and event loop.
//!
//! Use [`session::Session`] to exchange messages after signaling, or
//! [`connection::Connection`] to also handle offer, answer, and candidate signals.
//! Feed input through [`sans::Sans::handle`] and drain every output with `poll`.
//! Your loop performs the I/O and supplies monotonic time; the core starts no tasks.
//!
//! # Create a host-only session
//!
//! ```no_run
//! use nethernet::session::Session;
//! use std::{net::UdpSocket, time::Instant};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let socket = UdpSocket::bind("127.0.0.1:0")?;
//! let (session, description) = Session::new(socket.local_addr()?, true, 1, Instant::now())?;
//! let offer_sdp = description.encode_full(session.local_candidates());
//! // Sign and exchange the offer using your signaling channel, then drive the session.
//! # Ok(())
//! # }
//! ```
//!
//! The [custom event-loop guide](https://github.com/cinnabar-mc/nethernet/blob/main/docs/sans-io.md)
//! covers packets, timers, identity checks, and readiness. For socket-owning APIs,
//! use `nethernet-tokio` or `bevy-nethernet`.
pub mod admission;
pub mod connection;
pub mod error;
pub mod identity;
pub mod phase;
pub mod protocol;
pub mod sans;
pub mod session;
pub mod signaling;
pub mod util;

pub mod prelude {
    pub use crate::admission::{AdmissionError, Admitted, Answered, OfferPolicy};
    pub use crate::connection::Timeouts;
    pub use crate::error::{ProtocolError, SignalErrorCode};
    pub use crate::identity::{
        Identity, PlayerInfo, SdpIdentity, SelfSignedIdentity, ServerIdentity, TokenTrust,
        error::IdentityError,
        jwk::{Jwk, JwkSet, MinecraftKeys},
        jwt::Claims,
    };
    pub use crate::phase::{Connecting, Established, Retired};
    pub use crate::protocol::packet::discovery::{
        MessagePacket, Packets, RequestPacket, ResponsePacket, ServerData,
    };
    pub use crate::protocol::{Message, MessageSegment, NetherCodec, Signal, SignalType};
    pub use crate::sans::Sans;
    pub use crate::signaling::http::{
        HttpSignaler,
        config::HttpSignalerConfig,
        error::HttpSignalerError,
        input::{HttpSignalerInput, RejectReason},
        output::{HttpSignalerOutput, Offer},
    };
    pub use crate::signaling::lan::{
        LanSignaler, config::LanSignalerConfig, error::LanSignalerError, input::LanSignalerInput,
        output::LanSignalerOutput,
    };
    pub use crate::util::candidate;
    pub use crate::util::endpoint::{self, Scope};
    pub use crate::util::ip_range::IpRangeSet;
}
