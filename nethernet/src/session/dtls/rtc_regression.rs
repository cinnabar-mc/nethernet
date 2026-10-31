//! Malformed authenticated peer records must fail before transport readiness.
use super::*;
use crate::protocol::webrtc::certificate;
use rtc::crypto::*;
use rtc::dtls::cipher_suite::CipherSuiteId;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FinishedProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    corrupt: bool,
    altered: Arc<AtomicUsize>,
}

impl RTCCryptoProvider for FinishedProvider {
    /// Names the peer fixture without exposing key material.
    fn name(&self) -> &'static str {
        "finished-regression"
    }
    /// Uses the fixture's AEAD adapter for the actual handshake.
    fn crypto(&self) -> &dyn RTCCrypto {
        self
    }
    /// Keeps the original provider's secure random source.
    fn random(&self) -> &dyn RTCRandom {
        self.inner.random()
    }
}

impl RTCCrypto for FinishedProvider {
    /// Retains the original provider's capability negotiation.
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        self.inner.crypto().supports(algorithm)
    }
    /// Delegates transcript hashing.
    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.crypto().hash(algorithm, data)
    }
    /// Delegates the DTLS key schedule.
    fn new_hmac(&self, algorithm: HmacAlgorithm, key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        self.inner.crypto().new_hmac(algorithm, key)
    }
    /// Wraps the negotiated record cipher while keeping its real authentication tag.
    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        Ok(Box::new(FinishedCipher {
            inner: self.inner.crypto().new_aead(algorithm, key)?,
            corrupt: self.corrupt,
            altered: self.altered.clone(),
        }))
    }
    /// Delegates ephemeral key agreement.
    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        self.inner.crypto().start_key_exchange(algorithm)
    }
    /// Delegates certificate key generation.
    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.inner.crypto().generate_signing_key(scheme)
    }
    /// Delegates certificate key import.
    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        key: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.inner.crypto().import_signing_key(scheme, key)
    }
    /// Delegates the peer's ordinary certificate signature checks.
    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner
            .crypto()
            .verify_signature(scheme, key, message, signature)
    }
}

struct FinishedCipher {
    inner: Box<dyn AeadCipher>,
    corrupt: bool,
    altered: Arc<AtomicUsize>,
}

impl AeadCipher for FinishedCipher {
    /// Keeps the negotiated tag length.
    fn tag_len(&self) -> usize {
        self.inner.tag_len()
    }
    /// Changes only Finished verify_data before the original cipher authenticates the record.
    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), CryptoError> {
        if self.corrupt && aad.get(8) == Some(&22) && data.first() == Some(&20) && data.len() >= 24
        {
            data[12] ^= 1;
            self.altered.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.seal_in_place(nonce, aad, data, tag)
    }
    /// Keeps incoming authentication and decryption unchanged.
    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner.open_in_place(nonce, aad, data, tag)
    }
}

#[test]
fn encrypted_incorrect_client_finished_never_completes_nethernet_dtls() {
    let now = Instant::now();
    let client_addr = "127.0.0.1:40980".parse().unwrap();
    let server_addr = "127.0.0.1:40981".parse().unwrap();
    for corrupt in [false, true] {
        let client_certificate = certificate::generate().unwrap();
        let server_certificate = certificate::generate().unwrap();
        let fingerprint = certificate::fingerprint(&client_certificate).unwrap();
        let mut server = DtlsLayer::new(
            server_addr,
            client_addr,
            ResolvedRole::Server,
            server_certificate,
            fingerprint,
            now,
        )
        .unwrap();
        let altered = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(FinishedProvider {
            inner: certificate::crypto_provider().unwrap(),
            corrupt,
            altered: altered.clone(),
        });
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![client_certificate])
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_insecure_skip_verify(true)
            .build(true, Some(server_addr))
            .unwrap();
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        client
            .connect(now, server_addr, Arc::new(config), None)
            .unwrap();
        let mut completed = false;
        let mut rejected = false;
        for _ in 0..8 {
            while let Some(packet) = client.poll_transmit() {
                match server.handle_read_owned(packet.message, now) {
                    Ok(events) => {
                        for event in events {
                            assert!(!matches!(event, EndpointEvent::ApplicationData(_)));
                            completed |= matches!(event, EndpointEvent::HandshakeComplete);
                        }
                    }
                    Err(_) => rejected = true,
                }
            }
            while let Some((packet, _)) = server.poll_transmit() {
                let _ = client.read(now, server_addr, None, BytesMut::from(packet.as_slice()));
            }
        }
        if corrupt {
            assert!(altered.load(Ordering::SeqCst) > 0);
            assert!(rejected);
            assert!(!completed);
        } else {
            assert!(completed);
            assert!(!rejected);
        }
    }
}
