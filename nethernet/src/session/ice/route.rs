//! Numeric carrier identity, independent of the UDP address family requested for a relay.
use super::config::{IceError, MAX_ICE_SERVERS};
use rtc_turn::proto::reqfamily::{
    REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6, RequestedAddressFamily,
};
use std::net::SocketAddr;

/// One complete TURN stream frame, including RTC's STUN header and the full wire-length field.
pub const MAX_TURN_STREAM_FRAME_BYTES: usize =
    rtc::stun::message::MESSAGE_HEADER_SIZE + u16::MAX as usize;

/// The requested UDP relay family; it does not select the outer TURN carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnAddressFamily {
    Ipv4,
    Ipv6,
}

impl TurnAddressFamily {
    /// Shares the actual carrier-family default between pending allocation and target metadata.
    pub(super) fn for_local(actual: SocketAddr) -> Self {
        if actual.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }

    /// Uses the dependency's existing attribute encoder before transaction authentication.
    pub(super) fn requested(self) -> RequestedAddressFamily {
        match self {
            Self::Ipv4 => REQUESTED_FAMILY_IPV4,
            Self::Ipv6 => REQUESTED_FAMILY_IPV6,
        }
    }
}

/// One bounded slot in a session's pending stream configuration, independent of any socket tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TurnStreamId(u8);

impl TurnStreamId {
    /// Names a caller-owned carrier slot within the same session's existing endpoint allowance.
    pub fn new(index: usize) -> Result<Self, IceError> {
        if index >= MAX_ICE_SERVERS {
            return Err(IceError::Configuration);
        }
        u8::try_from(index)
            .map(Self)
            .map_err(|_| IceError::Configuration)
    }
}

/// The actual bound TCP tuple retained by one caller-owned plain or verified TLS stream.
/// Construct this from that stream's own socket addresses, never from its UDP host candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TurnStreamRoute {
    local: SocketAddr,
    remote: SocketAddr,
}

impl TurnStreamRoute {
    /// Checks concrete, same-family unicast addresses and actual nonzero socket ports.
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Result<Self, IceError> {
        if [local, remote]
            .into_iter()
            .any(|addr| addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast())
            || local.is_ipv4() != remote.is_ipv4()
        {
            return Err(IceError::Configuration);
        }
        Ok(Self { local, remote })
    }

    /// The actual local address assigned to this TCP socket.
    pub fn local(self) -> SocketAddr {
        self.local
    }

    /// The numeric endpoint of this same TCP socket.
    pub fn remote(self) -> SocketAddr {
        self.remote
    }
}
