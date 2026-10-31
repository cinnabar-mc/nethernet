//! Addressed HTTP discovery, independent of advertised server-data decoding.
mod cache;
pub use cache::{ProbeCache, ProbeSelection};

use futures::{StreamExt, stream::FuturesUnordered};
use reqwest::{Client, ClientBuilder};
use std::{future::Future, time::Duration};
use tokio::time::Instant;

const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
const HTTPS_HEAD_START: Duration = Duration::from_secs(1);

/// A failed addressed discovery; ordinary formatting does not expose request URLs.
#[derive(thiserror::Error)]
pub enum ProbeError {
    /// The original deadline or six-second probe limit elapsed.
    #[error("NetherNet HTTP endpoint probe timed out")]
    TimedOut,
    /// No candidate completed successfully; the last request cause is inspectable.
    #[error("no NetherNet HTTP endpoint answered: request failed")]
    Request(#[source] reqwest::Error),
    /// The last candidate completed with an unsuccessful HTTP status.
    #[error("no NetherNet HTTP endpoint answered: status {0}")]
    Status(u16),
}

impl std::fmt::Debug for ProbeError {
    /// Keeps automatic diagnostics as redacted as the ordinary error message.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// Reusable caller-configured HTTP discovery with redirects disabled.
#[derive(Clone)]
pub struct HttpProbe {
    client: Client,
}

impl HttpProbe {
    /// Builds the caller's TLS/egress client while ensuring redirects cannot win a probe.
    pub fn new(builder: ClientBuilder) -> Result<Self, reqwest::Error> {
        crate::util::tls::ensure_crypto_provider();
        Ok(Self {
            client: builder
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// Builds signaling with this probe's same HTTP policy and connection pool.
    pub fn signaling(&self, local_id: String) -> super::HttpSignaling {
        super::HttpSignaling::with_client(local_id, self.client.clone())
    }

    /// Finds the first completed 2xx endpoint within six seconds and the caller's deadline.
    /// Port zero means omitted; zero and 19132 also try each scheme's default port.
    pub async fn probe(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<String, ProbeError> {
        run(candidates(host, port), deadline, |endpoint| {
            request(&self.client, endpoint)
        })
        .await
    }

    /// Rechecks a remembered URL, or probes and stores a new caller-owned selection.
    pub async fn select(
        &self,
        host: &str,
        port: u16,
        cache: Option<&ProbeCache>,
        deadline: Instant,
    ) -> Result<ProbeSelection, ProbeError> {
        if let Some(selected) = cache.and_then(|cache| cache.lookup(host, port)) {
            let cutoff = deadline.min(Instant::now() + PROBE_TIMEOUT);
            let result = if Instant::now() >= cutoff {
                Err(ProbeError::TimedOut)
            } else {
                tokio::time::timeout_at(
                    cutoff,
                    request(&self.client, selected.endpoint().to_owned()),
                )
                .await
                .unwrap_or(Err(ProbeError::TimedOut))
            };
            if let Err(error) = result {
                selected.forget();
                return Err(error);
            }
            return Ok(selected);
        }
        let endpoint = self.probe(host, port, deadline).await?;
        Ok(ProbeCache::store(cache, host, port, endpoint))
    }
}

/// Derives both schemes from the same port list and brackets literal IPv6 hosts once.
fn candidates(host: &str, port: u16) -> Vec<(String, String)> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let ports = if port == 0 || port == 19132 {
        vec![19132, 0]
    } else {
        vec![port]
    };
    ports
        .into_iter()
        .map(|port| {
            let authority = if port == 0 {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            (
                format!("https://{authority}"),
                format!("http://{authority}"),
            )
        })
        .collect()
}

/// Completes the body without decoding or retaining it; a stalled body cannot win.
async fn request(client: &Client, endpoint: String) -> Result<(), ProbeError> {
    let mut response = client
        .get(format!("{endpoint}/v1/join"))
        .header(
            reqwest::header::USER_AGENT,
            nethernet::signaling::http::join::CLIENT_USER_AGENT,
        )
        .send()
        .await
        .map_err(ProbeError::Request)?;
    let status = response.status().as_u16();
    while response
        .chunk()
        .await
        .map_err(ProbeError::Request)?
        .is_some()
    {}
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(ProbeError::Status(status))
    }
}

/// Carries request identity through one completion without starting a detached task.
async fn attempt<F: Future<Output = Result<(), ProbeError>>>(
    endpoint: String,
    secure: bool,
    index: usize,
    future: F,
) -> (String, bool, usize, Result<(), ProbeError>) {
    (endpoint, secure, index, future.await)
}

/// Runs HTTPS first, releasing game-port HTTP on failure and all HTTP by one second.
async fn run<F: Future<Output = Result<(), ProbeError>>>(
    pairs: Vec<(String, String)>,
    deadline: Instant,
    mut request: impl FnMut(String) -> F,
) -> Result<String, ProbeError> {
    let now = Instant::now();
    let cutoff = deadline.min(now + PROBE_TIMEOUT);
    if now >= cutoff {
        return Err(ProbeError::TimedOut);
    }
    let mut pending = FuturesUnordered::new();
    let mut remaining_https = pairs.len();
    let mut http_started = vec![false; pairs.len()];
    for (index, (secure, _)) in pairs.iter().enumerate() {
        pending.push(attempt(
            secure.clone(),
            true,
            index,
            request(secure.clone()),
        ));
    }
    let mut last = None;
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(cutoff) => return Err(ProbeError::TimedOut),
            completed = pending.next() => {
                let Some((endpoint, secure, index, result)) = completed else {
                    return Err(last.expect("each candidate completed with a failure"));
                };
                match result { Ok(()) => return Ok(endpoint), Err(error) => last = Some(error) }
                if secure {
                    remaining_https -= 1;
                    for (next, (_, plain)) in pairs.iter().enumerate() {
                        if !http_started[next] && (remaining_https == 0 || index == 0 && next == 0) {
                            http_started[next] = true;
                            pending.push(attempt(plain.clone(), false, next, request(plain.clone())));
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(now + HTTPS_HEAD_START), if http_started.iter().any(|started| !started) => {
                for (index, (_, plain)) in pairs.iter().enumerate() {
                    if !http_started[index] {
                        http_started[index] = true;
                        pending.push(attempt(plain.clone(), false, index, request(plain.clone())));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
