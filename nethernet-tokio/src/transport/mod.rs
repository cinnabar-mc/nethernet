//! Client and server connections over a signaling backend.
pub mod client;
mod gather;
mod pending;
pub mod server;

pub use client::NetherClient;
pub use nethernet::connection::Timeouts;
pub use server::NetherServer;

use nethernet::identity::{SdpIdentity, TokenTrust};
use nethernet::protocol::constants::{DEFAULT_MAX_PENDING, DEFAULT_MAX_PENDING_PER_NETWORK_ID};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}
use tokio_util::sync::CancellationToken;

/// Outbound UDP ICE configuration. DNS and service credential acquisition happen before dialing.
#[derive(Clone)]
pub struct ClientIceConfig {
    /// Resolved server endpoints, bounded credentials, gathering deadline and candidate policy.
    pub ice: nethernet::session::IceConfig,
    /// Optional concrete local interface and port. Use an IPv6 address for IPv6 outer server transport.
    pub bind_addr: Option<SocketAddr>,
}

/// Accepting ICE configuration. The caller resolves services and selects the local socket family.
#[derive(Clone)]
pub struct ServerIceConfig {
    /// The same bounded STUN/TURN policy and original absolute credentials used by client sessions.
    pub ice: nethernet::session::IceConfig,
    /// Concrete local interface/port, including explicit IPv6 for IPv6 service transport.
    pub bind_addr: SocketAddr,
}

/// Settings shared by NetherClient::connect_with and NetherServer::bind_with.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Deadlines for the stages of negotiation.
    pub timeouts: Timeouts,

    /// Aborts client negotiation and unaccepted server sessions when cancelled.
    pub cancel_token: CancellationToken,

    /// Client offers made when negotiation times out; 0 counts as 1.
    /// Caller-driven signaling always uses one attempt; the application owns retries.
    pub attempts: u32,

    /// Optional STUN/TURN paths for outbound client sessions.
    pub client_ice: Option<ClientIceConfig>,

    /// Optional configured accepting paths; None preserves host-only HTTP/LAN behavior.
    pub server_ice: Option<ServerIceConfig>,

    /// Signs local SDP: ClientIdentity for offers or ServerIdentity for answers.
    pub identity: Option<Arc<dyn SdpIdentity>>,

    /// Answers without a signature, which the vanilla client refuses (guide section 5.2).
    pub allow_unsigned_answers: bool,

    /// How the server authenticates offers; None skips validation.
    pub token_trust: Option<TokenTrust>,

    /// Accepts offers without an identity when token trust is configured; false by default.
    /// Present identities still undergo that trust and fingerprint validation.
    /// Does not override an HTTP signaler's independent offer policy.
    pub allow_anonymous_offers: bool,

    /// How the client authenticates the server's answer; None accepts any answer.
    /// Present identities are checked; missing identities fail unless explicitly allowed.
    pub server_trust: Option<TokenTrust>,

    /// Permits a missing server answer identity under the caller's explicit route policy.
    /// Present identities must still pass configured token and fingerprint validation.
    /// Defaults to false and is independent of unsigned server answer generation.
    pub allow_anonymous_answers: bool,

    /// Adds candidates from the signaling source address when an offer has no routable host candidate.
    pub infer_peer_candidates: bool,

    /// Offers answered but not yet established; more are refused with IncomingConnectionIgnored.
    pub max_pending: usize,

    /// The same cap for offers from one network id.
    pub max_pending_per_network_id: usize,

    /// Total negotiating, queued accepted and live server sessions retained until retirement.
    /// A closed receiver still retaining accepted data holds its reservation; zero refuses all offers.
    pub max_sessions: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            cancel_token: CancellationToken::new(),
            attempts: 3,
            client_ice: None,
            server_ice: None,
            identity: None,
            allow_unsigned_answers: false,
            token_trust: None,
            allow_anonymous_offers: false,
            server_trust: None,
            allow_anonymous_answers: false,
            infer_peer_candidates: true,
            max_pending: DEFAULT_MAX_PENDING,
            max_pending_per_network_id: DEFAULT_MAX_PENDING_PER_NETWORK_ID,
            max_sessions: DEFAULT_MAX_PENDING,
        }
    }
}

impl fmt::Debug for ConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("timeouts", &self.timeouts)
            .field("attempts", &self.attempts)
            .field("client_ice", &self.client_ice.is_some())
            .field("server_ice", &self.server_ice.is_some())
            .field("identity", &self.identity.is_some())
            .field("allow_unsigned_answers", &self.allow_unsigned_answers)
            .field("token_trust", &self.token_trust.is_some())
            .field("allow_anonymous_offers", &self.allow_anonymous_offers)
            .field("server_trust", &self.server_trust.is_some())
            .field("allow_anonymous_answers", &self.allow_anonymous_answers)
            .field("infer_peer_candidates", &self.infer_peer_candidates)
            .field("max_pending", &self.max_pending)
            .field(
                "max_pending_per_network_id",
                &self.max_pending_per_network_id,
            )
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}
