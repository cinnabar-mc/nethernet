//! Signed-out client identity and the key that binds its SDP offers.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use p384::pkcs8::EncodePublicKey;

use super::envelope::{DEFAULT_IDP_PROTOCOL, insert_identity};
use super::error::{IdentityError, Result};
use super::jws::Jws;
use super::jwt::Claims;
use super::server::DEFAULT_DOMAIN;
use super::{Assertion, Identity, Idp, SdpIdentity, fingerprint_payload, sdp_fingerprints};

/// A signed-out client identity with its own P-384 signing key.
///
/// Its token attests only to the public key and validity timestamps. Account
/// credentials and refresh belong to an application-owned [`SdpIdentity`].
pub struct SelfSignedIdentity {
    signing: SigningKey,
    token: String,
    claims: Claims,
}

impl fmt::Debug for SelfSignedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelfSignedIdentity").finish_non_exhaustive()
    }
}

impl SelfSignedIdentity {
    /// Creates a signed-out identity with base64 DER `cpk` and `x5u` public keys.
    ///
    /// Token validity comes from the caller; an unrepresentable time is rejected.
    pub fn new(now: SystemTime, lifetime: Duration) -> Result<Self> {
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
        let claims = serde_json::Map::from_iter([
            ("cpk".to_owned(), public_key.clone().into()),
            ("iat".to_owned(), seconds(now)?.into()),
            ("exp".to_owned(), seconds(expires)?.into()),
        ]);
        let payload = serde_json::to_string(&claims)
            .map_err(|error| IdentityError::Malformed(error.to_string()))?;
        let token = Jws::sign_with_x5u(&signing, &payload, &public_key)?;
        Ok(Self {
            signing,
            token,
            claims: Claims::new(claims),
        })
    }

    /// Borrows the same key for an application login that must match the transport identity.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

impl SdpIdentity for SelfSignedIdentity {
    fn augment(&self, sdp: &str, now: SystemTime) -> Result<String> {
        self.claims.check_expiry(now)?;
        let fingerprints = sdp_fingerprints(sdp)?;
        if fingerprints.is_empty() {
            return Err(IdentityError::NoFingerprints);
        }
        let payload = fingerprint_payload(&fingerprints);
        let identity = Identity {
            idp: Idp {
                domain: DEFAULT_DOMAIN.to_owned(),
                protocol: DEFAULT_IDP_PROTOCOL.to_owned(),
            },
            assertion: Assertion {
                token: self.token.clone(),
                fingerprints: Jws::sign_detached(&self.signing, &payload)?,
            },
        }
        .to_base64()?;
        Ok(insert_identity(sdp, &identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{TokenTrust, validate_sdp};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const SDP: &str = "v=0\r\na=fingerprint:sha-256 AB:CD\r\nm=application 9\r\n";

    #[test]
    fn signed_out_offer_binds_a_der_token_key_to_the_signed_fingerprints() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let identity = SelfSignedIdentity::new(now, Duration::from_secs(3600)).unwrap();
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
    fn expired_identity_and_missing_fingerprints_are_rejected() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let identity = SelfSignedIdentity::new(now, Duration::from_secs(60)).unwrap();
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
