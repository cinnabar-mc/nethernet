//! Identity assertions carried in the SDP `a=identity` attribute (guide section 5).
pub mod client;
pub mod envelope;
pub mod error;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod player;
pub mod server;
pub mod token;
pub mod trust;

pub use client::SelfSignedIdentity;
pub use envelope::{
    Assertion, Identity, Idp, canonical_fingerprint_json, fingerprint_payload, sdp_fingerprints,
};
pub use player::PlayerInfo;
pub use server::ServerIdentity;
pub use token::TokenIdentity;
pub use trust::{TokenTrust, validate_sdp, verify_answer};

/// An identity that signs the fingerprints of a locally generated SDP description.
pub trait SdpIdentity: Send + Sync {
    /// Adds an identity assertion using caller-supplied time for token validity.
    fn augment(&self, sdp: &str, now: std::time::SystemTime) -> error::Result<String>;
}

impl SdpIdentity for ServerIdentity {
    fn augment(&self, sdp: &str, now: std::time::SystemTime) -> error::Result<String> {
        ServerIdentity::augment(self, sdp, now)
    }
}

/// Endpoint publishing the JWKS that signs Minecraft multiplayer tokens.
pub const MINECRAFT_KEYS_URL: &str =
    "https://authorization.franchise.minecraft-services.net/.well-known/keys";

/// Required `iss` of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_ISSUER: &str = "https://authorization.franchise.minecraft-services.net/";

/// Required `aud` entry of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";
