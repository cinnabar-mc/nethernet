//! Authentication of the token in a received assertion.
use crate::identity::envelope::{EMPTY_FINGERPRINTS, Identity, canonical_fingerprint_json};
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwk::MinecraftKeys;
use crate::identity::jwt::{Claims, Jws};
use crate::identity::{MINECRAFT_AUDIENCE, MINECRAFT_ISSUER};
use std::{fmt, sync::Arc, time::SystemTime};

/// Application-supplied, pure issuer policy for a received multiplayer token.
/// Verify signature, algorithm, issuer, audience, identity and validity before
/// returning claims. This hook opens no HTTP client and does not read a clock.
/// The SDP owner always separately verifies the detached fingerprint signature
/// with the returned token's own `cpk`; never bind it to the local client's key.
pub trait TokenVerifier: Send + Sync {
    /// Authenticates the token under the caller's explicit time policy.
    fn verify(&self, token: &str, now: SystemTime) -> Result<Claims>;
}

/// How the token in a received assertion is authenticated.
#[derive(Clone)]
pub enum TokenTrust {
    /// RS256 token signed by a key in the set, with the Minecraft issuer and audience.
    Minecraft(MinecraftKeys),

    /// A configured provider's signature, issuer, audience, identity and temporal policy.
    Provider(Arc<dyn TokenVerifier>),

    /// Server answers on an explicitly authorized route: RS256 uses the configured provider;
    /// ES384 must be self-signed by the token's own `cpk`, then bind the SDP fingerprints.
    /// Server token timestamps do not grant or extend transport admission. This policy cannot
    /// authenticate offers; the application must authorize the exact service route separately.
    ServerAnswer(Arc<dyn TokenVerifier>),

    /// Any well-formed unexpired token; signature, issuer and audience are not checked.
    Any,
}

impl fmt::Debug for TokenTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Minecraft(keys) => f.debug_tuple("Minecraft").field(keys).finish(),
            Self::Provider(_) => f.write_str("Provider(..)"),
            Self::ServerAnswer(_) => f.write_str("ServerAnswer(..)"),
            Self::Any => f.write_str("Any"),
        }
    }
}

impl TokenTrust {
    /// Applies the selected token policy; server answers keep server and provider validity distinct.
    pub fn claims(&self, identity: &Identity, now: SystemTime) -> Result<Claims> {
        if let Self::Provider(verifier) = self {
            return verifier.verify(&identity.assertion.token, now);
        }
        let jws = Jws::parse(&identity.assertion.token)?;
        if let Self::ServerAnswer(provider) = self {
            if identity.idp.protocol != super::envelope::DEFAULT_IDP_PROTOCOL {
                return Err(IdentityError::Untrusted(
                    "invalid server identity protocol".to_owned(),
                ));
            }
            return if jws.header.alg == "RS256" {
                provider.verify(&identity.assertion.token, now)
            } else {
                super::server::verify_token(&jws)
            };
        }
        let claims = jws.claims()?;
        claims.check_expiry(now)?;

        let TokenTrust::Minecraft(keys) = self else {
            return Ok(claims);
        };

        if jws.header.alg != "RS256" {
            return Err(IdentityError::Untrusted(format!(
                "expected RS256, got {}",
                jws.header.alg
            )));
        }

        let keys_now = keys.snapshot();
        let candidates = keys_now.candidates(jws.header.kid.as_deref());
        if candidates.is_empty() {
            keys.mark_missed();
            return Err(IdentityError::Untrusted(
                "the token names a key that is not published".to_string(),
            ));
        }
        if !candidates.iter().any(|key| {
            key.verify_rs256(jws.signing_input.as_bytes(), &jws.signature)
                .is_ok()
        }) {
            return Err(IdentityError::Untrusted(
                "the token is not signed by the issuer".to_string(),
            ));
        }

        if claims.subject().is_none() {
            return Err(IdentityError::Untrusted(
                "the token carries no subject".to_string(),
            ));
        }
        if claims.issuer() != Some(MINECRAFT_ISSUER) {
            return Err(IdentityError::Untrusted(
                "the token was issued by someone else".to_string(),
            ));
        }
        if !claims.audience().contains(&MINECRAFT_AUDIENCE) {
            return Err(IdentityError::Untrusted(
                "the token is addressed to another audience".to_string(),
            ));
        }

        Ok(claims)
    }
}

/// Checks the token, then that the key in its `cpk` claim signed the SDP fingerprints.
/// Server-answer policy must use `verify_answer` and cannot authenticate an offer here.
pub fn validate_sdp(sdp: &str, trust: &TokenTrust, now: SystemTime) -> Result<Claims> {
    if matches!(trust, TokenTrust::ServerAnswer(_)) {
        return Err(IdentityError::Untrusted(
            "server answer policy cannot authenticate an offer".to_owned(),
        ));
    }
    validate_assertion(sdp, trust, now)
}

/// Shares the token/fingerprint verification owner without treating a server policy as player admission.
fn validate_assertion(sdp: &str, trust: &TokenTrust, now: SystemTime) -> Result<Claims> {
    let identity = Identity::from_sdp(sdp)?;
    let claims = trust.claims(&identity, now)?;

    let fingerprints = canonical_fingerprint_json(sdp)?;
    if fingerprints == EMPTY_FINGERPRINTS {
        return Err(IdentityError::NoFingerprints);
    }

    let jws = Jws::parse_detached(&identity.assertion.fingerprints, &fingerprints)?;
    jws.verify_es384(&claims.client_public_key()?)?;

    Ok(claims)
}

/// Checks a received answer against `trust` when one is set; without one every answer is accepted.
pub fn verify_answer(
    sdp: &str,
    trust: Option<&TokenTrust>,
    now: SystemTime,
) -> Result<Option<Claims>> {
    verify_answer_with_policy(sdp, trust, false, now)
}

/// Applies explicit missing-answer policy while always authenticating a present identity.
/// Without configured trust this preserves the original unchecked-answer behavior.
/// This verifies identity only; the connection still parses and admits the SDP description.
///
/// # Errors
/// Rejects present malformed/untrusted assertions or invalid fingerprint proofs;
/// a missing assertion is rejected unless explicitly allowed or trust is absent.
pub fn verify_answer_with_policy(
    sdp: &str,
    trust: Option<&TokenTrust>,
    allow_anonymous: bool,
    now: SystemTime,
) -> Result<Option<Claims>> {
    let Some(trust) = trust else {
        return Ok(None);
    };
    if allow_anonymous && crate::identity::envelope::sdp_identity_value(sdp).is_none() {
        return Ok(None);
    }
    validate_assertion(sdp, trust, now).map(Some)
}

#[cfg(test)]
#[path = "token_trust_tests.rs"]
mod token_trust_tests;

#[cfg(test)]
#[path = "server_answer_tests.rs"]
mod server_answer_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::server::ServerIdentity;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: SystemTime = UNIX_EPOCH;

    fn offer(identity: &str) -> String {
        format!(
            "v=0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=identity:{}\r\n\
             a=fingerprint:sha-256 AB:CD\r\n",
            identity
        )
    }

    /// Normalized empty/valueless attributes are present and must never enter missing-only admission.
    #[test]
    fn anonymous_answer_policy_rejects_normalized_present_identity_attributes() {
        let absent = "v=0\r\na=fingerprint:sha-256 AB:CD\r\n";
        assert!(matches!(
            verify_answer_with_policy(absent, Some(&TokenTrust::Any), true, NOW),
            Ok(None)
        ));
        assert!(matches!(
            verify_answer(absent, Some(&TokenTrust::Any), NOW),
            Err(IdentityError::Missing)
        ));
        for attribute in ["a=identity\r\n", "a=identity \t\r\n", "a= identity:\t\r\n"] {
            assert!(
                verify_answer_with_policy(
                    &format!("{absent}{attribute}"),
                    Some(&TokenTrust::Any),
                    true,
                    NOW
                )
                .is_err()
            );
        }
    }

    #[test]
    fn a_description_without_an_identity_is_refused() {
        let error = validate_sdp("v=0\r\n", &TokenTrust::Any, NOW).unwrap_err();

        assert!(matches!(error, IdentityError::Missing));
    }

    #[test]
    fn an_answer_validates_against_the_identity_it_carries() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer(""), NOW).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let claims = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap();

        assert_eq!(claims.issuer(), Some("example.com"));
    }

    #[test]
    fn an_assertion_over_other_fingerprints_is_refused() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer(""), NOW).unwrap();
        let answer = answer
            .replace("a=identity:\r\n", "")
            .replace("AB:CD", "EF:01");

        let error = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap_err();

        assert!(matches!(error, IdentityError::FingerprintMismatch));
    }

    #[test]
    fn an_answer_signed_after_the_first_lifetime_still_validates() {
        let lifetime = Duration::from_secs(10);
        let server =
            ServerIdentity::generate_with_expiry("example.com", NOW, Some(lifetime)).unwrap();
        let later = NOW + Duration::from_secs(600);
        let answer = server.augment(&offer(""), later).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        assert!(validate_sdp(&answer, &TokenTrust::Any, later).is_ok());
    }

    #[test]
    fn without_a_trust_any_answer_is_accepted() {
        assert!(matches!(verify_answer(&offer(""), None, NOW), Ok(None)));
    }

    #[test]
    fn with_a_trust_an_answer_without_an_identity_is_refused() {
        let answer = offer("").replace("a=identity:\r\n", "");

        let error = verify_answer(&answer, Some(&TokenTrust::Any), NOW).unwrap_err();

        assert!(matches!(error, IdentityError::Missing));
    }

    #[test]
    fn with_a_trust_a_signed_answer_yields_its_claims() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer(""), NOW).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let claims = verify_answer(&answer, Some(&TokenTrust::Any), NOW)
            .unwrap()
            .unwrap();

        assert_eq!(claims.issuer(), Some("example.com"));
    }

    #[test]
    fn a_self_signed_answer_is_refused_under_minecraft_trust() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer(""), NOW).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");
        let trust = TokenTrust::Minecraft(Default::default());

        let error = verify_answer(&answer, Some(&trust), NOW).unwrap_err();

        assert!(matches!(error, IdentityError::Untrusted(_)));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let server =
            ServerIdentity::generate_with_expiry("example.com", NOW, Some(Duration::from_secs(10)))
                .unwrap();
        let answer = server.augment(&offer(""), NOW).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let error =
            validate_sdp(&answer, &TokenTrust::Any, NOW + Duration::from_secs(600)).unwrap_err();

        assert!(matches!(error, IdentityError::Untrusted(_)));
    }

    /// Provider policy authenticates the peer token while the existing SDP owner
    /// independently binds its own cpk to the exact received fingerprints.
    #[test]
    fn configured_provider_keeps_token_and_fingerprint_verification_separate() {
        struct Provider(p384::ecdsa::VerifyingKey);
        impl TokenVerifier for Provider {
            fn verify(&self, token: &str, now: SystemTime) -> Result<Claims> {
                let jws = Jws::parse(token)?;
                jws.verify_es384(&self.0)?;
                let claims = jws.claims()?;
                claims.check_expiry(now)?;
                if claims.issuer() != Some("peer.example") {
                    return Err(IdentityError::Untrusted("wrong provider".to_owned()));
                }
                Ok(claims)
            }
        }
        let peer = ServerIdentity::generate("peer.example", NOW).unwrap();
        let trust = TokenTrust::Provider(Arc::new(Provider(*peer.verifying_key())));
        let answer = peer
            .augment(&offer(""), NOW)
            .unwrap()
            .replace("a=identity:\r\n", "");
        assert_eq!(
            validate_sdp(&answer, &trust, NOW).unwrap().issuer(),
            Some("peer.example")
        );
        assert!(matches!(
            validate_sdp(&answer.replace("AB:CD", "EF:01"), &trust, NOW),
            Err(IdentityError::FingerprintMismatch)
        ));
        let stranger = ServerIdentity::generate("peer.example", NOW).unwrap();
        let wrong = stranger
            .augment(&offer(""), NOW)
            .unwrap()
            .replace("a=identity:\r\n", "");
        assert!(validate_sdp(&wrong, &trust, NOW).is_err());
    }
}
