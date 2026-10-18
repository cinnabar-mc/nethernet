//! Client-owned tokens and the key that binds their SDP offers.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use p384::pkcs8::EncodePublicKey;
use serde_json::json;
use zeroize::Zeroizing;

use super::envelope::{DEFAULT_IDP_PROTOCOL, identity_base64, insert_identity};
use super::error::{IdentityError, Result};
use super::jws::Jws;
use super::jwt::Claims;
use super::server::DEFAULT_DOMAIN;
use super::{Idp, SdpIdentity, fingerprint_payload, sdp_fingerprints};

/// A client token and its matching P-384 signing key.
///
/// Account authentication and refresh belong to the caller. This type binds an
/// offered identity to the key that signs the SDP fingerprints and checks expiry.
pub struct ClientIdentity {
    signing: SigningKey,
    token: Zeroizing<String>,
    claims: Claims,
    domain: String,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity").finish_non_exhaustive()
    }
}

impl ClientIdentity {
    /// Binds an application-authenticated token to its signing key.
    ///
    /// Fails if the provider domain is empty, the token is malformed, or its `cpk`
    /// names another key. The caller authenticates the issuer; expiry is checked
    /// whenever an offer is signed.
    pub fn from_token(
        signing: SigningKey,
        token: String,
        domain: impl Into<String>,
    ) -> Result<Self> {
        let token = Zeroizing::new(token);
        let claims = Jws::parse(&token)?.claims()?;
        if claims.client_public_key()? != *signing.verifying_key() {
            return Err(IdentityError::KeyMismatch);
        }
        let domain = domain.into();
        if domain.is_empty() {
            return Err(IdentityError::Malformed(
                "client identity provider domain must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            signing,
            token,
            claims,
            domain,
        })
    }

    /// Creates a signed-out identity with base64 DER `cpk` and `x5u` public keys.
    ///
    /// Token validity comes from the caller; an unrepresentable time is rejected.
    pub fn self_signed(now: SystemTime, lifetime: Duration) -> Result<Self> {
        let expires = now.checked_add(lifetime).ok_or_else(|| {
            IdentityError::Malformed("client token lifetime is too large".to_owned())
        })?;
        let seconds = |time: SystemTime| {
            time.duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .map_err(|_| {
                    IdentityError::Malformed("client token time precedes the epoch".to_owned())
                })
        };
        let signing = SigningKey::generate();
        let der = signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|error| IdentityError::Key(error.to_string()))?;
        let public_key = STANDARD.encode(der.as_bytes());
        let claims = json!({"cpk": public_key, "iat": seconds(now)?, "exp": seconds(expires)?});
        let token = Jws::sign_with_x5u(&signing, &claims.to_string(), &public_key)?;
        Self::from_token(signing, token, DEFAULT_DOMAIN)
    }

    /// Borrows the same key for an application login that must match the transport identity.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

impl SdpIdentity for ClientIdentity {
    /// Signs an offer; its returned SDP contains the token and must not be logged.
    fn augment(&self, sdp: &str, now: SystemTime) -> Result<String> {
        self.claims.check_expiry(now)?;
        let fingerprints = sdp_fingerprints(sdp)?;
        if fingerprints.is_empty() {
            return Err(IdentityError::NoFingerprints);
        }
        let payload = fingerprint_payload(&fingerprints);
        let identity = Zeroizing::new(identity_base64(
            &Idp {
                domain: self.domain.clone(),
                protocol: DEFAULT_IDP_PROTOCOL.to_owned(),
            },
            &self.token,
            &Jws::sign_detached(&self.signing, &payload)?,
        )?);
        Ok(insert_identity(sdp, &identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, TokenTrust, validate_sdp};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const SDP: &str = "v=0\r\na=fingerprint:sha-256 AB:CD\r\nm=application 9\r\n";

    #[test]
    fn signed_out_offer_binds_a_der_token_key_to_the_signed_fingerprints() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let identity = ClientIdentity::self_signed(now, Duration::from_secs(3600)).unwrap();
        let augmented = identity.augment(SDP, now).unwrap();
        let parsed = Identity::from_sdp(&augmented).unwrap();
        let token = Jws::parse(&parsed.assertion.token).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&token.payload).unwrap();
        let der = STANDARD.decode(claims["cpk"].as_str().unwrap()).unwrap();
        assert_eq!(
            der,
            identity
                .signing
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
        );
        let header = parsed.assertion.token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        assert_eq!(header["x5u"], claims["cpk"]);
        assert_eq!(claims["iat"], 1_000_000);
        assert_eq!(claims["exp"], 1_003_600);
        token
            .verify_es384(identity.signing.verifying_key())
            .unwrap();
        assert_eq!(
            validate_sdp(&augmented, &TokenTrust::Any, now)
                .unwrap()
                .client_public_key()
                .unwrap(),
            *identity.signing.verifying_key()
        );
        assert!(!format!("{identity:?}").contains(&parsed.assertion.token));
    }

    #[test]
    fn a_token_cannot_be_bound_to_another_signer_or_used_after_expiry() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let identity = ClientIdentity::self_signed(now, Duration::from_secs(60)).unwrap();
        assert!(matches!(
            ClientIdentity::from_token(SigningKey::generate(), identity.token.to_string(), "self"),
            Err(IdentityError::KeyMismatch)
        ));
        assert!(matches!(
            ClientIdentity::from_token(identity.signing.clone(), identity.token.to_string(), ""),
            Err(IdentityError::Malformed(_))
        ));
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
}
