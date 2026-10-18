//! An application-acquired token bound to one connection proof key.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use p384::ecdsa::SigningKey;

use super::envelope::{DEFAULT_IDP_PROTOCOL, insert_identity};
use super::error::{IdentityError, Result};
use super::jws::Jws;
use super::jwt::Claims;
use super::{Assertion, Identity, Idp, SdpIdentity, fingerprint_payload, sdp_fingerprints};

/// Maximum compact token accepted before decoding its claims.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// A previously acquired multiplayer token and its P-384 connection key.
///
/// Authentication, issuer verification and refresh remain with the application.
/// Construction checks the token's shape, expiry and `cpk` binding; it does not
/// verify the issuer's signature. Use the same key and token for Bedrock Login.
/// This owner performs no I/O, reads no clock and never generates a replacement key.
pub struct TokenIdentity {
    signing: Arc<SigningKey>,
    token: String,
    claims: Claims,
    issuer: String,
}

impl fmt::Debug for TokenIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenIdentity").finish_non_exhaustive()
    }
}

impl TokenIdentity {
    /// Takes an acquired credential and checks that it binds this connection key.
    /// An owned key moves into one Arc allocation; an existing Arc shares that
    /// exact allocation with Login without copying private material.
    ///
    /// The `iss` claim supplies the SDP identity provider verbatim. Expiry uses
    /// this crate's existing token leeway. Full issuer/temporal verification is
    /// the credential provider's responsibility, before this handoff.
    ///
    /// # Errors
    /// Rejects oversized/malformed tokens, absent expiry/issuer, an expired token
    /// or a different `cpk`. Errors never include the supplied credential.
    pub fn new(
        signing: impl Into<Arc<SigningKey>>,
        token: String,
        now: SystemTime,
    ) -> Result<Self> {
        let signing = signing.into();
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(invalid_token());
        }
        let parsed = Jws::parse(&token).map_err(|_| invalid_token())?;
        if !matches!(parsed.header.alg.as_str(), "RS256" | "ES384") || parsed.signature.is_empty() {
            return Err(invalid_token());
        }
        let claims = parsed.claims().map_err(|_| invalid_token())?;
        let issuer = claims
            .issuer()
            .filter(|issuer| !issuer.is_empty() && !issuer.chars().any(char::is_control))
            .ok_or_else(invalid_token)?
            .to_owned();
        let key = claims.client_public_key().map_err(|_| invalid_token())?;
        if key != *signing.verifying_key() {
            return Err(IdentityError::KeyMismatch);
        }
        claims.check_expiry(now).map_err(|_| invalid_token())?;
        Ok(Self {
            signing,
            token,
            claims,
            issuer,
        })
    }

    /// Borrows the same proof key for Login and its server key exchange.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

impl SdpIdentity for TokenIdentity {
    fn augment(&self, sdp: &str, now: SystemTime) -> Result<String> {
        self.claims.check_expiry(now).map_err(|_| invalid_token())?;
        let fingerprints = sdp_fingerprints(sdp)
            .map_err(|_| IdentityError::Malformed("invalid local SDP fingerprints".to_owned()))?;
        if fingerprints.is_empty() {
            return Err(IdentityError::NoFingerprints);
        }
        let identity = Identity {
            idp: Idp {
                domain: self.issuer.clone(),
                protocol: DEFAULT_IDP_PROTOCOL.to_owned(),
            },
            assertion: Assertion {
                token: self.token.clone(),
                fingerprints: Jws::sign_detached(
                    &self.signing,
                    &fingerprint_payload(&fingerprints),
                )?,
            },
        }
        .to_base64()?;
        Ok(insert_identity(sdp, &identity))
    }
}

/// Discards token parser diagnostics at the credential handoff boundary.
fn invalid_token() -> IdentityError {
    IdentityError::Malformed("invalid acquired multiplayer token".to_owned())
}

#[cfg(test)]
mod tests {
    use super::super::jwk::EcJwk;
    use super::*;
    use p384::elliptic_curve::Generate;
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    const SDP: &str = "v=0\r\na=fingerprint:sha-256 AB:CD\r\nm=application 9\r\n";

    /// Makes an original synthetic token; its issuer signature is unrelated to cpk.
    fn token(key: &SigningKey, issuer: &str) -> String {
        let claims = json!({"cpk": EcJwk::from(key.verifying_key()),
            "iss": issuer, "exp": 1_000_060});
        Jws::sign(&SigningKey::generate(), &claims.to_string()).unwrap()
    }

    #[test]
    fn acquired_token_and_connection_key_bind_the_actual_sdp_assertion() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let key = Arc::new(SigningKey::generate());
        let token = token(&key, "https://issuer.example/");
        let identity = TokenIdentity::new(Arc::clone(&key), token.clone(), now).unwrap();
        assert!(std::ptr::eq(identity.signing_key(), key.as_ref()));
        let sdp = identity.augment(SDP, now).unwrap();
        let parsed = Identity::from_sdp(&sdp).unwrap();
        assert_eq!(parsed.assertion.token, token);
        assert_eq!(parsed.idp.domain, "https://issuer.example/");
        assert_eq!(parsed.idp.protocol, DEFAULT_IDP_PROTOCOL);
        let payload = super::super::canonical_fingerprint_json(SDP).unwrap();
        let signature = Jws::parse_detached(&parsed.assertion.fingerprints, &payload).unwrap();
        signature
            .verify_es384(identity.signing_key().verifying_key())
            .unwrap();
        assert!(
            signature
                .verify_es384(SigningKey::generate().verifying_key())
                .is_err()
        );
        assert!(!format!("{identity:?}").contains(&token));
        assert!(
            identity
                .augment(SDP, now + Duration::from_secs(121))
                .is_err()
        );
        assert!(matches!(
            identity.augment("v=0\r\n", now),
            Err(IdentityError::NoFingerprints)
        ));
    }

    #[test]
    fn wrong_key_and_malformed_handoffs_fail_without_credential_diagnostics() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let key = SigningKey::generate();
        let valid = token(&key, "https://issuer.example/");
        assert!(matches!(
            TokenIdentity::new(SigningKey::generate(), valid, now),
            Err(IdentityError::KeyMismatch)
        ));
        for invalid in [
            "sensitive-not-a-jwt".to_owned(),
            "x".repeat(MAX_TOKEN_BYTES + 1),
            token(&key, ""),
            token(&key, "issuer\nsecret"),
        ] {
            let error = TokenIdentity::new(key.clone(), invalid.clone(), now).unwrap_err();
            assert!(!error.to_string().contains(&invalid));
        }
    }
}
