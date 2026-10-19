//! Original finite TLS trust pair shared by the actual HTTP and TURN socket controls.
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;

/// Issues a private loopback certificate and a verifier trusting only that certificate.
pub fn self_signed_pair() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let issued =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert.der().clone()], key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(issued.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server), Arc::new(client))
}
