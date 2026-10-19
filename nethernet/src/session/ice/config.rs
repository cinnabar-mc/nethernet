//! Resolved inputs for the session's STUN/TURN transaction owners.
use super::route::{TurnAddressFamily, TurnStreamRoute};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Maximum resolved STUN/TURN endpoints retained by one session.
pub const MAX_ICE_SERVERS: usize = 8;
pub(super) const MAX_REMOTE_CANDIDATES: usize = 64;
/// Maximum bytes in either TURN credential component.
pub const MAX_TURN_CREDENTIAL_BYTES: usize = 512;

/// Failures at the configured ICE boundary. Dependency errors never expose server text or credentials.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IceError {
    #[error("invalid ICE server configuration")]
    Configuration,
    #[error("invalid or expired TURN credentials")]
    Credentials,
    #[error("ICE server operation failed")]
    Server,
    #[error("ICE candidate limit reached")]
    CandidateLimit,
    #[error("TURN pending data limit reached")]
    PendingLimit,
    #[error("ICE session is closed")]
    Closed,
    #[error("TURN stream carrier is not installed")]
    UnsupportedCarrier,
}

/// A bounded TURN credential with a caller-monotonic admission expiry; intentionally has no Debug implementation.
/// An acknowledged allocation instead follows its actual Allocate and Refresh response lifetimes.
/// An existing allocation accepts password rotation only; changing username requires a fresh transport tuple.
#[derive(Clone)]
pub struct TurnCredentials {
    pub(super) username: String,
    pub(super) password: String,
    pub(super) valid_until: Instant,
}

impl TurnCredentials {
    /// Owns the credential after checking its byte bounds. The session checks expiry before allocation or rotation.
    pub fn new(username: String, password: String, valid_until: Instant) -> Result<Self, IceError> {
        if username.is_empty()
            || password.is_empty()
            || username.len() > MAX_TURN_CREDENTIAL_BYTES
            || password.len() > MAX_TURN_CREDENTIAL_BYTES
            || username.contains('\0')
            || password.contains('\0')
        {
            return Err(IceError::Credentials);
        }
        Ok(Self {
            username,
            password,
            valid_until,
        })
    }
}

/// Numeric endpoints resolved by the caller. Hostnames and socket I/O belong to a runtime adapter.
#[derive(Clone)]
pub enum IceServer {
    /// Gather a server-reflexive candidate with a STUN Binding transaction.
    Stun(SocketAddr),
    /// Gather a relay candidate and a server-reflexive candidate from the same UDP endpoint.
    Turn(SocketAddr, TurnCredentials),
    /// Requests an explicit UDP relay family on the original UDP carrier.
    TurnWithFamily {
        addr: SocketAddr,
        credentials: TurnCredentials,
        family: TurnAddressFamily,
    },
    /// Reserves an actual TCP tuple; activation follows the caller's verified carrier completion.
    TurnStream {
        route: TurnStreamRoute,
        credentials: TurnCredentials,
        family: TurnAddressFamily,
    },
}

impl IceServer {
    /// The already-resolved server address.
    pub fn addr(&self) -> SocketAddr {
        match self {
            Self::Stun(addr) | Self::Turn(addr, _) | Self::TurnWithFamily { addr, .. } => *addr,
            Self::TurnStream { route, .. } => route.remote(),
        }
    }

    /// The exact stream binding, absent for the original UDP constructors.
    pub fn stream_route(&self) -> Option<TurnStreamRoute> {
        match self {
            Self::TurnStream { route, .. } => Some(*route),
            _ => None,
        }
    }

    /// Whether this endpoint owns a TURN allocation rather than a STUN binding only.
    pub(super) fn credentials(&self) -> Option<&TurnCredentials> {
        match self {
            Self::Stun(_) => None,
            Self::Turn(_, credentials)
            | Self::TurnWithFamily { credentials, .. }
            | Self::TurnStream { credentials, .. } => Some(credentials),
        }
    }
}

/// Local candidate policy. Relay-only sessions never check or advertise their host/srflx paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcePolicy {
    #[default]
    All,
    RelayOnly,
}

/// Bounded, caller-owned gathering configuration. No servers preserves host-only operation.
#[derive(Clone)]
pub struct IceConfig {
    pub servers: Vec<IceServer>,
    /// Time allowed from construction for all gathering transactions, including authentication.
    pub gather_timeout: Duration,
    pub policy: IcePolicy,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            gather_timeout: Duration::from_secs(10),
            policy: IcePolicy::All,
        }
    }
}

impl IceConfig {
    /// Checks bounded inputs before any RTC transaction is constructed.
    pub(super) fn validate(&self, local: SocketAddr, now: Instant) -> Result<(), IceError> {
        if self.servers.len() > MAX_ICE_SERVERS
            || self.gather_timeout.is_zero()
            || self.gather_timeout > Duration::from_secs(60)
            || now.checked_add(self.gather_timeout).is_none()
            || (self.policy == IcePolicy::RelayOnly
                && !self
                    .servers
                    .iter()
                    .any(|server| server.credentials().is_some()))
        {
            return Err(IceError::Configuration);
        }
        for (index, server) in self.servers.iter().enumerate() {
            let addr = server.addr();
            if addr.port() == 0
                || addr.ip().is_unspecified()
                || addr.ip().is_multicast()
                || (server.stream_route().is_none() && addr.is_ipv4() != local.is_ipv4())
                || self.servers[..index].iter().any(|previous| {
                    previous.addr() == addr && previous.stream_route() == server.stream_route()
                })
            {
                return Err(IceError::Configuration);
            }
            if let Some(credential) = server.credentials()
                && credential.valid_until <= now
            {
                return Err(IceError::Credentials);
            }
        }
        Ok(())
    }
}

/// Gathering is finite even when every configured server is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringState {
    InProgress,
    Complete,
    Closed,
}
