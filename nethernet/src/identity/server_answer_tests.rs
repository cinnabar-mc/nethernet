use super::*;
use crate::identity::jwk::{EcJwk, Jwk, JwkSet};
use crate::identity::{Assertion, Idp, ServerIdentity, canonical_fingerprint_json};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p384::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use rsa::{
    RsaPrivateKey, pkcs1v15,
    sha2::Sha256,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use serde_json::{Value, json};
use std::{
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};

const SDP: &str = "v=0\r\na=fingerprint:sha-256 AB:CD\r\nm=application 9\r\n";
const SECONDS: u64 = 1_900_000_000;

/// Supplies explicit caller time, independent of the test machine's clock.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SECONDS)
}

/// Keeps the remote transport proof distinct from the provider's RSA issuer key.
fn key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 48]).unwrap()
}

/// Generates one original synthetic provider fixture, never loading a real credential.
fn issuer() -> &'static pkcs1v15::SigningKey<Sha256> {
    static ISSUER: OnceLock<pkcs1v15::SigningKey<Sha256>> = OnceLock::new();
    ISSUER.get_or_init(|| {
        pkcs1v15::SigningKey::new(RsaPrivateKey::new(&mut rand::rng(), 1024).unwrap())
    })
}

struct Provider {
    calls: Arc<AtomicUsize>,
    trust: TokenTrust,
}

impl TokenVerifier for Provider {
    fn verify(&self, token: &str, now: SystemTime) -> Result<Claims> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.trust.claims(
            &Identity {
                idp: Idp::default(),
                assertion: Assertion {
                    token: token.into(),
                    fingerprints: String::new(),
                },
            },
            now,
        )
    }
}

/// Uses the actual core RSA/provider policy so a provider failure cannot be modeled as self-signed success.
fn provider(calls: &Arc<AtomicUsize>) -> Arc<dyn TokenVerifier> {
    let public = issuer().as_ref();
    let key: Jwk = serde_json::from_value(json!({"kty":"RSA","kid":"synthetic",
        "n":URL_SAFE_NO_PAD.encode(public.n().to_be_bytes()),"e":URL_SAFE_NO_PAD.encode(public.e().to_be_bytes())})).unwrap();
    Arc::new(Provider {
        calls: Arc::clone(calls),
        trust: TokenTrust::Minecraft(JwkSet { keys: vec![key] }.into()),
    })
}

/// Carries a real detached signature over the same SDP fingerprint bytes the core verifies.
fn answer(token: String, proof: &SigningKey, protocol: &str) -> String {
    let identity = Identity {
        idp: Idp {
            domain: "self".into(),
            protocol: protocol.into(),
        },
        assertion: Assertion {
            token,
            fingerprints: Jws::sign_detached(proof, &canonical_fingerprint_json(SDP).unwrap())
                .unwrap(),
        },
    };
    format!(
        "v=0\r\na=identity:{}\r\n{}",
        identity.to_base64().unwrap(),
        SDP.strip_prefix("v=0\r\n").unwrap()
    )
}

/// Signs title-server claims with an explicitly selected cpk, including deliberate mismatches.
fn self_signed(proof: &SigningKey, cpk: Value) -> String {
    Jws::sign(
        proof,
        &json!({"cpk":cpk,"iat":SECONDS,"exp":SECONDS+1}).to_string(),
    )
    .unwrap()
}

/// Signs a real provider token independently from the remote fingerprint proof.
fn provider_token(proof: &SigningKey) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"synthetic"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        json!({"iss":MINECRAFT_ISSUER,"aud":MINECRAFT_AUDIENCE,
        "sub":"synthetic-subject","xid":"123","iat":SECONDS,"exp":SECONDS+3600,
        "cpk":EcJwk::from(proof.verifying_key())})
        .to_string(),
    );
    let input = format!("{header}.{payload}");
    let signature: pkcs1v15::Signature = issuer().sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_vec()))
}

/// Keeps valid token framing while changing actual signature bytes.
fn corrupt_signature(token: &str) -> String {
    let mut parsed = Jws::parse(token).unwrap();
    parsed.signature[0] ^= 1;
    format!(
        "{}.{}",
        parsed.signing_input,
        URL_SAFE_NO_PAD.encode(parsed.signature)
    )
}

#[test]
fn server_answer_requires_self_signature_and_its_own_fingerprint_proof() {
    let proof = key(1);
    let stranger = key(2);
    let trust = TokenTrust::ServerAnswer(provider(&Arc::new(AtomicUsize::new(0))));
    let token = self_signed(&proof, json!(EcJwk::from(proof.verifying_key())));
    assert!(
        verify_answer(
            &answer(token.clone(), &proof, "default"),
            Some(&trust),
            now()
        )
        .is_ok()
    );
    assert!(
        verify_answer(
            &answer(corrupt_signature(&token), &proof, "default"),
            Some(&trust),
            now()
        )
        .is_err()
    );
    assert!(verify_answer(&answer(token, &stranger, "default"), Some(&trust), now()).is_err());
    let mismatched = self_signed(&proof, json!(EcJwk::from(stranger.verifying_key())));
    assert!(
        verify_answer(
            &answer(mismatched, &stranger, "default"),
            Some(&trust),
            now()
        )
        .is_err()
    );
}

#[test]
fn server_answer_supports_der_keys_and_server_timestamp_policy_without_extending_provider_validity()
{
    let proof = key(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let trust = TokenTrust::ServerAnswer(provider(&calls));
    let cpk = STANDARD.encode(
        proof
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    let token = self_signed(&proof, json!(cpk));
    let signed = answer(token, &proof, "default");
    let later = now() + Duration::from_secs(600);
    assert!(verify_answer(&signed, Some(&trust), later).is_ok());
    assert!(verify_answer(&signed, Some(&TokenTrust::Any), later).is_err());
    let token = Jws::sign(
        &proof,
        &json!({"cpk":EcJwk::from(proof.verifying_key())}).to_string(),
    )
    .unwrap();
    assert!(verify_answer(&answer(token, &proof, "default"), Some(&trust), later).is_ok());
    let malformed = Jws::sign(
        &proof,
        &json!({"cpk":EcJwk::from(proof.verifying_key()),"exp":"invalid"}).to_string(),
    )
    .unwrap();
    assert!(verify_answer(&answer(malformed, &proof, "default"), Some(&trust), later).is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let signed = answer(provider_token(&proof), &proof, "default");
    assert!(verify_answer(&signed, Some(&trust), now() + Duration::from_secs(7200)).is_err());
}

#[test]
fn server_answer_preserves_actual_provider_signature_validation_without_fallback() {
    let proof = key(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let trust = TokenTrust::ServerAnswer(provider(&calls));
    let token = provider_token(&proof);
    let claims = verify_answer(
        &answer(token.clone(), &proof, "default"),
        Some(&trust),
        now(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(claims.xuid(), Some("123"));
    assert!(
        verify_answer(
            &answer(corrupt_signature(&token), &proof, "default"),
            Some(&trust),
            now()
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn algorithm_confusion_cannot_turn_a_rejected_provider_token_into_server_trust() {
    let proof = key(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let trust = TokenTrust::ServerAnswer(provider(&calls));
    let parsed = Jws::parse(&self_signed(
        &proof,
        json!(EcJwk::from(proof.verifying_key())),
    ))
    .unwrap();
    for algorithm in ["RS256", "none", "HS256"] {
        let header = URL_SAFE_NO_PAD.encode(json!({"alg":algorithm}).to_string());
        let token = format!(
            "{header}.{}.{}",
            URL_SAFE_NO_PAD.encode(&parsed.payload),
            URL_SAFE_NO_PAD.encode(&parsed.signature)
        );
        assert!(verify_answer(&answer(token, &proof, "default"), Some(&trust), now()).is_err());
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn server_answer_policy_cannot_authenticate_an_offer_or_accept_an_unsigned_answer() {
    let proof = key(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = provider(&calls);
    let trust = TokenTrust::ServerAnswer(Arc::clone(&provider));
    let signed = ServerIdentity::from_key(proof, "self", now(), Some(Duration::from_secs(60)))
        .unwrap()
        .augment(SDP, now())
        .unwrap();
    assert!(validate_sdp(&signed, &trust, now()).is_err());
    assert!(verify_answer(SDP, Some(&trust), now()).is_err());
    assert!(verify_answer(&signed, Some(&TokenTrust::Provider(provider)), now()).is_err());
}

#[test]
fn server_answer_requires_the_identity_envelope_protocol() {
    let proof = key(1);
    let trust = TokenTrust::ServerAnswer(provider(&Arc::new(AtomicUsize::new(0))));
    let token = self_signed(&proof, json!(EcJwk::from(proof.verifying_key())));
    assert!(verify_answer(&answer(token, &proof, "unexpected"), Some(&trust), now()).is_err());
}
