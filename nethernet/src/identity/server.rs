//! The server's own identity: a P-384 key and a self-signed token that sign answers.
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwk::EcJwk;
use crate::identity::jws::Jws;
use crate::identity::jwt::Claims;
use crate::identity::{Assertion, Identity, Idp, fingerprint_payload, sdp_fingerprints};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p384::SecretKey;
use p384::ecdsa::{SigningKey, VerifyingKey};
use p384::elliptic_curve::Generate;
use p384::pkcs8::{EncodePublicKey, LineEnding};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Domain used when none is given, since peers refuse an empty one.
pub const DEFAULT_DOMAIN: &str = "self";

/// Token validity used when no lifetime is given.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// Server key and token; keep the key stable across restarts so clients can trust it (guide section 5.2).
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    domain: String,
    lifetime: Option<Duration>,
    token: String,
}

impl ServerIdentity {
    pub fn generate(domain: impl Into<String>, now: SystemTime) -> Result<Self> {
        Self::generate_with_expiry(domain, now, Some(DEFAULT_TOKEN_LIFETIME))
    }

    /// A `None` lifetime omits `exp`; explicit self-signed server-answer trust does not require it.
    pub fn generate_with_expiry(
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        Self::from_key(SigningKey::generate(), domain, now, lifetime)
    }

    pub fn from_pem(pem: &str, domain: impl Into<String>, now: SystemTime) -> Result<Self> {
        Self::from_pem_with_expiry(pem, domain, now, Some(DEFAULT_TOKEN_LIFETIME))
    }

    pub fn from_pem_with_expiry(
        pem: &str,
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        let secret = SecretKey::from_pem(pem)
            .map_err(|e| IdentityError::Key(format!("the PEM holds no key on P-384: {}", e)))?;

        Self::from_key(secret.into(), domain, now, lifetime)
    }

    pub fn from_key(
        signing: SigningKey,
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        let verifying = *signing.verifying_key();
        let domain = match domain.into() {
            domain if domain.is_empty() => DEFAULT_DOMAIN.to_string(),
            domain => domain,
        };
        let token = mint_token(&signing, &verifying, &domain, now, lifetime)?;

        Ok(Self {
            signing,
            verifying,
            domain,
            lifetime,
            token,
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        let secret = SecretKey::from(self.signing.as_nonzero_scalar());
        Ok(secret
            .to_sec1_pem(LineEnding::LF)
            .map_err(|e| IdentityError::Key(e.to_string()))?
            .to_string())
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The token minted at construction.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// A token issued at `now`, so a long-running server never signs with an expired one.
    pub fn token_at(&self, now: SystemTime) -> Result<String> {
        mint_token(
            &self.signing,
            &self.verifying,
            &self.domain,
            now,
            self.lifetime,
        )
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The base64 identity value signing the fingerprints of `answer`.
    pub fn identity_value(&self, answer: &str, now: SystemTime) -> Result<String> {
        let fingerprints = sdp_fingerprints(answer)?;
        self.identity_for_fingerprints(&fingerprints, now)
    }

    /// The base64 identity value signing the given `(algorithm, digest)` pairs.
    pub fn identity_for_fingerprints(
        &self,
        fingerprints: &[(String, String)],
        now: SystemTime,
    ) -> Result<String> {
        let payload = fingerprint_payload(fingerprints);

        Identity {
            idp: Idp {
                domain: self.domain.clone(),
                protocol: super::envelope::DEFAULT_IDP_PROTOCOL.to_owned(),
            },
            assertion: Assertion {
                token: self.token_at(now)?,
                fingerprints: Jws::sign_detached(&self.signing, &payload)?,
            },
        }
        .to_base64()
    }

    /// Inserts a signed `a=identity` line above the first media section of an answer.
    pub fn augment(&self, answer: &str, now: SystemTime) -> Result<String> {
        Ok(super::envelope::insert_identity(
            answer,
            &self.identity_value(answer, now)?,
        ))
    }
}

/// Verifies a server token with its own P-384 key, without applying player credential timestamps.
/// Supplied timestamps still use the shared bounded NumericDate parser.
/// The caller must still authorize its route and verify the detached SDP fingerprint signature.
pub(super) fn verify_token(token: &Jws) -> Result<Claims> {
    let claims = token.claims()?;
    token.verify_es384(&claims.client_public_key()?)?;
    for name in ["iat", "nbf", "exp"] {
        claims.numeric_date(name)?;
    }
    Ok(claims)
}

fn mint_token(
    signing: &SigningKey,
    verifying: &VerifyingKey,
    domain: &str,
    now: SystemTime,
    lifetime: Option<Duration>,
) -> Result<String> {
    let mut claims = json!({
        "cpk": EcJwk::from(verifying),
        "iat": seconds(now),
    });
    if !domain.is_empty() {
        claims["iss"] = json!(domain);
    }
    if let Some(lifetime) = lifetime {
        claims["exp"] = json!(seconds(now + lifetime));
    }
    let der = verifying
        .to_public_key_der()
        .map_err(|error| IdentityError::Key(error.to_string()))?;
    Jws::sign_with_x5u(
        signing,
        &claims.to_string(),
        &STANDARD.encode(der.as_bytes()),
    )
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::jwt::Jws;
    use crate::identity::{TokenTrust, validate_sdp};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use p384::pkcs8::EncodePublicKey;
    use serde_json::json;

    const ANSWER: &str = "v=0\r\n\
        o=- 1 2 IN IP4 127.0.0.1\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=fingerprint:sha-256 AB:CD\r\n";

    #[test]
    fn a_default_server_token_expires_after_one_minute() {
        let now = fixture_now();
        let identity = ServerIdentity::generate("fixture", now).unwrap();
        let claims = Jws::parse(identity.token()).unwrap().claims().unwrap();
        assert_eq!(claims.expiry(), Some(now + Duration::from_secs(60)));
    }

    #[test]
    fn a_server_token_carries_the_same_public_key_as_jwk_and_der() {
        let identity = fixture_identity();
        let token = Jws::parse(identity.token()).unwrap();
        let header = identity.token().split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let der = STANDARD
            .decode(
                header["x5u"]
                    .as_str()
                    .expect("server x5u must carry a DER key"),
            )
            .unwrap();
        assert_eq!(
            der,
            identity
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
        );
        assert!(token.claims().unwrap().values()["cpk"].is_object());
        assert_eq!(
            token.claims().unwrap().client_public_key().unwrap(),
            *identity.verifying_key()
        );
        token.verify_es384(identity.verifying_key()).unwrap();
    }

    #[test]
    fn the_identity_is_inserted_above_the_media_description() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let answer = identity.augment(ANSWER, UNIX_EPOCH).unwrap();

        let lines: Vec<&str> = answer.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.starts_with("a=identity:"))
            .unwrap();

        assert!(lines[index + 1].starts_with("m="));
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn signing_a_fingerprint_list_matches_signing_the_answer_that_carries_it() {
        let identity = fixture_identity();
        let fingerprints = vec![(
            "sha-256".to_string(),
            "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB".to_string(),
        )];

        assert_eq!(
            identity
                .identity_for_fingerprints(&fingerprints, fixture_now())
                .unwrap(),
            identity
                .identity_value(FIXTURE_ANSWER, fixture_now())
                .unwrap()
        );
    }

    #[test]
    fn an_empty_domain_becomes_self_as_peers_require() {
        let identity = ServerIdentity::generate("", UNIX_EPOCH).unwrap();
        let value = identity.identity_value(ANSWER, UNIX_EPOCH).unwrap();

        assert_eq!(identity.domain(), "self");
        assert_eq!(Identity::from_base64(&value).unwrap().idp.domain, "self");
    }

    #[test]
    fn the_assertion_is_detached() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let value = identity.identity_value(ANSWER, UNIX_EPOCH).unwrap();
        let parsed = Identity::from_base64(&value).unwrap();

        assert_eq!(parsed.assertion.fingerprints.split("..").count(), 2);
        assert_eq!(parsed.idp.protocol, "default");
    }

    #[test]
    fn a_key_survives_a_pem_round_trip() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let loaded =
            ServerIdentity::from_pem(&identity.to_pem().unwrap(), "example.com", UNIX_EPOCH)
                .unwrap();

        assert_eq!(loaded.verifying_key(), identity.verifying_key());
    }

    const SEC1_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDk5SqsJQCnsweXt71qJWhPrKAhe9tX/HOPqM6kjTi5M8qMeSx8mdPr
uVWNoqH3h9qgBwYFK4EEACKhZANiAARAqrmHdAfGA4B7HM7srmt5yYcAURGiB/Hu
KfCBZMo0q3Jy/Z6wxSnyWeOd8WU5X6O6J8Gr2+D7D9X8Fh+xaDyPt2Z7rVGnwVih
Oy/Uu1zzizzcYTJMluYn8XetihGgczU=
-----END EC PRIVATE KEY-----
";

    const PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDk5SqsJQCnsweXt71q
JWhPrKAhe9tX/HOPqM6kjTi5M8qMeSx8mdPruVWNoqH3h9qhZANiAARAqrmHdAfG
A4B7HM7srmt5yYcAURGiB/HuKfCBZMo0q3Jy/Z6wxSnyWeOd8WU5X6O6J8Gr2+D7
D9X8Fh+xaDyPt2Z7rVGnwVihOy/Uu1zzizzcYTJMluYn8XetihGgczU=
-----END PRIVATE KEY-----
";

    const FIXTURE_CPK: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV+juifBq9vg+w/V/BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ/F3rYoRoHM1";

    const FIXTURE_NOW_SECONDS: u64 = 1_700_000_000;

    const FIXTURE_ANSWER: &str = "v=0\r\n\
        o=- 1 2 IN IP4 127.0.0.1\r\n\
        s=-\r\n\
        a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=sctp-port:5000\r\n";

    const GOLDEN_IDENTITY_VALUE: &str = "eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5jb20iLCJwcm90b2NvbCI6ImRlZmF1bHQifSwiYXNzZXJ0aW9uIjoie1widG9rZW5cIjpcImV5SmhiR2NpT2lKRlV6TTROQ0lzSW5nMWRTSTZJazFJV1hkRlFWbElTMjlhU1hwcU1FTkJVVmxHU3pSRlJVRkRTVVJaWjBGRlVVdHhOV2d6VVVoNFowOUJaWGg2VHpkTE5YSmxZMjFJUVVaRlVtOW5abmczYVc1M1oxZFVTMDVMZEhsamRqSmxjMDFWY0Roc2JtcHVaa1pzVDFZcmFuVnBaa0p4T1habkszY3ZWaTlDV1daelYyYzRhamRrYldVMk1WSndPRVpaYjFSemRqRk1kR000TkhNNE0wZEZlVlJLWW0xS0wwWXpjbGx2VW05SVRURWlmUS5leUpqY0dzaU9uc2lZM0oySWpvaVVDMHpPRFFpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUpSUzNFMWFETlJTSGhuVDBGbGVIcFBOMHMxY21WamJVaEJSa1ZTYjJkbWVEZHBibmRuVjFSTFRrdDBlV04yTW1WelRWVndPR3h1YW01bVJteFBWaTFxSWl3aWVTSTZJblZwWmtKeE9YWm5MWGRmVmw5Q1dXWnpWMmM0YWpka2JXVTJNVkp3T0VaWmIxUnpkakZNZEdNNE5ITTRNMGRGZVZSS1ltMUtYMFl6Y2xsdlVtOUlUVEVpZlN3aVpYaHdJam94TnpBd01EQXdNRFl3TENKcFlYUWlPakUzTURBd01EQXdNREFzSW1semN5STZJbVY0WVcxd2JHVXVZMjl0SW4wLkVPaEpsdkhPeU0xUHV1WDJqM3BXRUZhUXl2Y3Y5OUZCMTJrNjAyckRjRFkzYUJUWEQ0QlYwNFduLVU2aGJQYWFWVFBIRXdLQWQ4b0NUd082WlEzcTZ5RFpiUG1wQmxNWlBlcmloYWRhLWhNdndXRmFHUXYxY3ZDSW4zcUZ3bEdpXCIsXCJmaW5nZXJwcmludHNcIjpcImV5SmhiR2NpT2lKRlV6TTROQ0o5Li4td2JVV1U4d2t5RTA1bnBtS2RyX0VLN0ZkZWR3X3dnaWdtQkJRM0pGQndISklRMFVZR19aMk9VdHc4UUdrUTJyWDJFZzFKUXYzeS1Zbks5VzJHME9nTVVZdDRCUF84VnB1bHE0TzltdnV3ZFJVcEo2RjRNLXFLWGpTaUVXQWtMY1wifSJ9";

    fn fixture_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_SECONDS)
    }

    fn fixture_identity() -> ServerIdentity {
        ServerIdentity::from_pem(SEC1_PEM, "example.com", fixture_now()).unwrap()
    }

    fn fixture_cpk_key() -> VerifyingKey {
        use p384::pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_der(&STANDARD.decode(FIXTURE_CPK).unwrap()).unwrap()
    }

    fn token_with_claims(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES384\"}");
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{}.{}.AA", header, payload)
    }

    fn answer_asserting(token: &str, fingerprints: &str) -> String {
        let identity = Identity {
            idp: Idp {
                domain: "example.com".to_string(),
                protocol: "default".to_string(),
            },
            assertion: Assertion {
                token: token.to_string(),
                fingerprints: fingerprints.to_string(),
            },
        };
        format!(
            "v=0\r\na=fingerprint:sha-256 AB:CD\r\na=identity:{}\r\nm=application 9\r\n",
            identity.to_base64().unwrap()
        )
    }

    #[test]
    fn a_sec1_pem_loads_with_a_fixed_public_key() {
        let identity = fixture_identity();

        assert_eq!(identity.verifying_key(), &fixture_cpk_key());
        assert_eq!(identity.domain(), "example.com");
    }

    #[test]
    fn the_token_cpk_is_the_fixed_public_key_as_a_jwk_object() {
        let jws = Jws::parse(fixture_identity().token()).unwrap();
        let claims = jws.claims().unwrap();

        assert_eq!(
            claims.values()["cpk"],
            json!({
                "kty": "EC",
                "crv": "P-384",
                "x": "QKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV-j",
                "y": "uifBq9vg-w_V_BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ_F3rYoRoHM1",
            })
        );
        assert_eq!(claims.client_public_key().unwrap(), fixture_cpk_key());
        assert_eq!(claims.issuer(), Some("example.com"));
        assert_eq!(
            claims.expiry(),
            Some(fixture_now() + DEFAULT_TOKEN_LIFETIME)
        );
        assert_eq!(jws.header.alg, "ES384");
    }

    #[test]
    fn the_token_cpk_object_has_48_byte_coordinates() {
        let jws = Jws::parse(fixture_identity().token()).unwrap();
        let claims = jws.claims().unwrap();
        let cpk = claims.values()["cpk"].as_object().unwrap();

        for coordinate in ["x", "y"] {
            let bytes = URL_SAFE_NO_PAD
                .decode(cpk[coordinate].as_str().unwrap())
                .unwrap();
            assert_eq!(bytes.len(), 48);
        }
    }

    #[test]
    fn a_sec1_pem_is_written_back_unchanged() {
        assert_eq!(fixture_identity().to_pem().unwrap(), SEC1_PEM);
    }

    #[test]
    fn a_pkcs8_pem_loads_with_the_same_public_key() {
        let identity = ServerIdentity::from_pem(PKCS8_PEM, "example.com", fixture_now()).unwrap();

        assert_eq!(identity.verifying_key(), &fixture_cpk_key());
    }

    #[test]
    fn a_pem_that_is_not_a_key_is_a_key_error() {
        let error =
            ServerIdentity::from_pem("not a pem", "example.com", fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Key(_)));
    }

    #[test]
    fn the_fixed_key_signs_a_fixed_answer_deterministically() {
        let first = fixture_identity()
            .identity_value(FIXTURE_ANSWER, fixture_now())
            .unwrap();
        let second = fixture_identity()
            .identity_value(FIXTURE_ANSWER, fixture_now())
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first, GOLDEN_IDENTITY_VALUE);
    }

    #[test]
    fn the_fixed_answer_is_augmented_above_its_media_section() {
        let augmented = fixture_identity()
            .augment(FIXTURE_ANSWER, fixture_now())
            .unwrap();
        let attribute = format!("a=identity:{}\r\n", GOLDEN_IDENTITY_VALUE);
        let (head, tail) = FIXTURE_ANSWER.split_once("m=").unwrap();

        assert_eq!(augmented, format!("{}{}m={}", head, attribute, tail));
    }

    #[test]
    fn the_augmented_fixed_answer_validates_under_any_trust() {
        let augmented = fixture_identity()
            .augment(FIXTURE_ANSWER, fixture_now())
            .unwrap();

        let claims = validate_sdp(&augmented, &TokenTrust::Any, fixture_now()).unwrap();

        assert_eq!(claims.client_public_key().unwrap(), fixture_cpk_key());
    }

    #[test]
    fn our_own_signed_answer_validates_under_any_trust_with_the_jwk_cpk() {
        let augmented = fixture_identity()
            .augment(FIXTURE_ANSWER, fixture_now())
            .unwrap();

        let claims = validate_sdp(&augmented, &TokenTrust::Any, fixture_now()).unwrap();

        assert!(claims.values()["cpk"].is_object());
        assert_eq!(claims.client_public_key().unwrap(), fixture_cpk_key());
    }

    #[test]
    fn an_lf_only_answer_is_augmented_with_lf_endings() {
        let answer = FIXTURE_ANSWER.replace("\r\n", "\n");
        let augmented = fixture_identity().augment(&answer, fixture_now()).unwrap();

        assert!(!augmented.contains('\r'));
        let lines: Vec<&str> = augmented.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.starts_with("a=identity:"))
            .unwrap();
        assert!(lines[index + 1].starts_with("m="));
        assert_eq!(
            augmented.replace(&format!("a=identity:{}\n", GOLDEN_IDENTITY_VALUE), ""),
            answer
        );
    }

    #[test]
    fn an_answer_without_a_media_section_gets_the_identity_appended() {
        let answer = "v=0\r\na=fingerprint:sha-256 AB:CD\r\n";
        let augmented = fixture_identity().augment(answer, fixture_now()).unwrap();

        assert!(augmented.starts_with(answer));
        let appended = &augmented[answer.len()..];
        assert!(appended.starts_with("a=identity:"));
        assert!(appended.ends_with("\r\n"));
        assert_eq!(appended.matches('\n').count(), 1);
    }

    #[test]
    fn an_answer_without_a_trailing_newline_gets_its_identity_glued_on() {
        let answer = "a=fingerprint:sha-256 AB:CD";
        let augmented = fixture_identity().augment(answer, fixture_now()).unwrap();

        assert!(augmented.starts_with("a=fingerprint:sha-256 AB:CDa=identity:"));
    }

    #[test]
    fn a_description_without_fingerprint_lines_is_refused_as_having_none() {
        let token = fixture_identity().token().to_string();
        let sdp =
            answer_asserting(&token, "e30..AA").replace("a=fingerprint:sha-256 AB:CD\r\n", "");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::NoFingerprints));
    }

    #[test]
    fn a_fingerprint_line_without_a_space_is_refused_by_validation() {
        let token = fixture_identity().token().to_string();
        let sdp = answer_asserting(&token, "e30..AA").replace("sha-256 AB:CD", "sha-256");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_fingerprint_signature_with_another_algorithm_is_malformed() {
        let token = fixture_identity().token().to_string();
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES256\"}");
        let sdp = answer_asserting(&token, &format!("{}..AA", header));

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_fingerprint_signature_with_a_payload_segment_is_malformed() {
        let token = fixture_identity().token().to_string();
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES384\"}");
        let sdp = answer_asserting(&token, &format!("{}.e30.AA", header));

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_token_without_a_cpk_is_refused_with_a_client_public_key_error() {
        let token = token_with_claims(json!({"exp": FIXTURE_NOW_SECONDS + 60}));
        let sdp = answer_asserting(&token, "e30..AA");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_token_with_a_p256_cpk_is_refused_with_a_client_public_key_error() {
        let p256 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtn+9sKRdn6eczaU797AJwdk2VIjMDgYtLt9T+j92M4M0iFDyYPp5OkOVORuYpZSO1HNH94EzVi5bmaHqKbZdUw==";
        let token = token_with_claims(json!({"exp": FIXTURE_NOW_SECONDS + 60, "cpk": p256}));
        let sdp = answer_asserting(&token, "e30..AA");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_token_is_accepted_sixty_seconds_past_its_expiry_and_refused_after() {
        let identity = ServerIdentity::from_pem_with_expiry(
            SEC1_PEM,
            "example.com",
            fixture_now(),
            Some(Duration::from_secs(100)),
        )
        .unwrap();
        let answer = identity.augment(FIXTURE_ANSWER, fixture_now()).unwrap();
        let expiry = fixture_now() + Duration::from_secs(100);

        assert!(validate_sdp(&answer, &TokenTrust::Any, expiry + Duration::from_secs(60)).is_ok());
        let error =
            validate_sdp(&answer, &TokenTrust::Any, expiry + Duration::from_secs(61)).unwrap_err();
        assert!(matches!(error, IdentityError::Untrusted(_)));
    }
}
