//! Explicit synthetic peer-key trust for public transport fixtures; no production trust fallback.
use nethernet::identity::{
    ServerIdentity, TokenTrust, TokenVerifier,
    error::{IdentityError, Result},
    jwt::{Claims, Jws},
};
use std::{sync::Arc, time::SystemTime};

/// Creates one real owned key/token for the controlled local peer.
pub fn identity(domain: &str) -> ServerIdentity {
    ServerIdentity::generate(domain, SystemTime::now()).unwrap()
}

struct ExpectedIdentity(ServerIdentity);

impl TokenVerifier for ExpectedIdentity {
    fn verify(&self, token: &str, now: SystemTime) -> Result<Claims> {
        let jws = Jws::parse(token)?;
        if jws.header.alg != "ES384" {
            return Err(IdentityError::Untrusted(
                "unexpected fixture algorithm".into(),
            ));
        }
        jws.verify_es384(self.0.verifying_key())?;
        let claims = jws.claims()?;
        claims.check_expiry(now)?;
        if claims.issuer() != Some(self.0.domain())
            || claims.client_public_key()? != *self.0.verifying_key()
        {
            return Err(IdentityError::Untrusted(
                "unexpected fixture identity".into(),
            ));
        }
        Ok(claims)
    }
}

/// Configures the existing caller policy hook for exactly this real fixture key and issuer.
pub fn trust(identity: &ServerIdentity) -> TokenTrust {
    TokenTrust::Provider(Arc::new(ExpectedIdentity(identity.clone())))
}
