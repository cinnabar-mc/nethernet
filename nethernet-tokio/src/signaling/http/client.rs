//! Client side of HTTP signaling.
use crate::error::{NetherError, Result};
use crate::protocol::packet::discovery::ServerData;
use crate::protocol::{Signal, SignalType};
use crate::util::tls::ensure_crypto_provider;
use futures::Stream;
use nethernet::signaling::http::join;
pub use nethernet::signaling::http::join::ClientInfo;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::broadcast;
use url::Url;

/// Posts offers to /v1/join/{network_id} on the target URL and delivers the reply as an answer signal.
pub struct HttpSignaling {
    network_id: String,
    client: Client,
    signal_tx: broadcast::Sender<Signal>,
    client_info: ClientInfo,
}

impl HttpSignaling {
    /// Builds a client with a 15 second request timeout.
    pub fn new(network_id: String) -> Result<Self> {
        ensure_crypto_provider();

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| NetherError::Other(format!("create HTTP client: {}", e)))?;

        Ok(Self::with_client(network_id, client))
    }

    pub fn with_client(network_id: String, client: Client) -> Self {
        let (signal_tx, _) = broadcast::channel(16);

        Self {
            network_id,
            client,
            signal_tx,
            client_info: ClientInfo::default(),
        }
    }

    /// Selects optional game metadata for subsequent status queries.
    pub fn with_client_info(mut self, info: ClientInfo) -> Self {
        self.client_info = info;
        self
    }

    fn join_url(&self, network_id: &str) -> Result<Url> {
        let url = Url::parse(network_id)
            .map_err(|e| NetherError::Other(format!("parse network ID as URL: {}", e)))?;
        if !matches!(url.scheme(), "http" | "https") || url.port_or_known_default().is_none() {
            return Err(NetherError::Other(format!(
                "network ID must be a HTTP/HTTPS URL: {}",
                network_id
            )));
        }

        url.join(&join::join_path(&self.network_id))
            .map_err(|e| NetherError::Other(format!("build join URL: {}", e)))
    }

    fn status_url(&self, network_id: &str) -> Result<Url> {
        let url = self.join_url(network_id)?;
        let path = self
            .client_info
            .status_path(&self.network_id)
            .map_err(|error| NetherError::Other(error.to_string()))?;
        url.join(&path)
            .map_err(|error| NetherError::Other(format!("build status URL: {error}")))
    }

    /// Reads GET /v1/join; the network id here is an HTTP/HTTPS target URL.
    pub async fn server_data(&self, network_id: &str) -> Result<ServerData> {
        let response = self
            .client
            .get(self.status_url(network_id)?)
            .header(USER_AGENT, join::CLIENT_USER_AGENT)
            .send()
            .await
            .map_err(|e| NetherError::Other(format!("request server data: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(NetherError::Other(
                join::StatusResponseError::Status(status.as_u16()).to_string(),
            ));
        }
        let body = read_capped(response, "server data").await?;
        Ok(join::validate_status_response(status.as_u16(), &body)?)
    }

    async fn join(&self, signal: &Signal) -> Result<String> {
        let response = self
            .client
            .post(self.join_url(&signal.network_id)?)
            .header(CONTENT_TYPE, join::CONTENT_TYPE)
            .header(USER_AGENT, join::CLIENT_USER_AGENT)
            .body(signal.data.clone())
            .send()
            .await
            .map_err(|e| NetherError::Other(format!("signal offer: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(NetherError::Other(
                join::JoinResponseError::Status(status.as_u16()).to_string(),
            ));
        }
        let body = read_capped(response, "answer").await?;
        let body = String::from_utf8_lossy(&body).into_owned();

        join::validate_join_response(status.as_u16(), &body).map_err(|e| match e {
            join::JoinResponseError::Rejected(code) => NetherError::Signaled(code),
            e => NetherError::Other(e.to_string()),
        })?;

        Ok(body)
    }
}

async fn read_capped(mut response: reqwest::Response, what: &str) -> Result<Vec<u8>> {
    let exceeded = || {
        NetherError::Other(format!(
            "{what} exceeds the {}-byte limit",
            join::MAX_ANSWER_SIZE
        ))
    };
    if response
        .content_length()
        .is_some_and(|len| len > join::MAX_ANSWER_SIZE as u64)
    {
        return Err(exceeded());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| NetherError::Other(format!("read {what}: {e}")))?
    {
        if body.len() + chunk.len() > join::MAX_ANSWER_SIZE {
            return Err(exceeded());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl HttpSignaling {
    /// Only offers are sent; the answer arrives on signals().
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match signal.signal_type {
            SignalType::Offer => {
                let answer = self.join(&signal).await?;
                let _ = self.signal_tx.send(Signal::answer(
                    signal.connection_id,
                    answer,
                    signal.network_id,
                ));
                Ok(())
            }
            SignalType::Error => Ok(()),
            signal_type => Err(NetherError::Other(format!(
                "{} is not supported over HTTP signaling",
                signal_type
            ))),
        }
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    pub fn network_id(&self) -> String {
        self.network_id.clone()
    }

    pub fn disable_trickle_ice(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_is_built_from_the_network_id() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert_eq!(
            signaling.join_url("https://example.com:19132").unwrap(),
            Url::parse("https://example.com:19132/v1/join/1234").unwrap()
        );
    }

    #[test]
    fn status_url_has_no_network_id() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert_eq!(
            signaling.status_url("http://example.com:19132").unwrap(),
            Url::parse("http://example.com:19132/v1/join").unwrap()
        );
    }

    #[test]
    fn status_metadata_is_encoded_and_incomplete_information_is_rejected() {
        let signaling = HttpSignaling::new("1234".into())
            .unwrap()
            .with_client_info(ClientInfo {
                version: "1.26 +&?".into(),
                protocol: -2,
                platform: -1,
            });
        assert_eq!(
            signaling.status_url("http://example.com").unwrap().as_str(),
            "http://example.com/v1/join?id=1234&platform=-1&protocol=-2&version=1.26+%2B%26%3F"
        );
        assert!(
            signaling
                .join_url("http://example.com")
                .unwrap()
                .query()
                .is_none()
        );
        let incomplete = signaling.with_client_info(ClientInfo {
            version: "1.26".into(),
            ..Default::default()
        });
        assert!(incomplete.status_url("http://example.com").is_err());
    }

    #[test]
    fn join_url_uses_scheme_default_ports_and_rejects_other_identifiers() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        for (target, port) in [("http://127.0.0.1:80", 80), ("https://[::1]:443", 443)] {
            let url = signaling.join_url(target).unwrap();
            assert_eq!(url.port_or_known_default(), Some(port));
            assert_eq!(url.path(), join::join_path("1234"));
        }
        assert!(signaling.join_url("https://example.com").is_ok());
        assert!(signaling.join_url("ftp://example.com:19132").is_err());
        assert!(signaling.join_url("5678").is_err());
    }
}
