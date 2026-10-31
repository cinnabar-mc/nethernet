//! Optional selection receipts protect newer cache entries from old failures.
use super::*;
use crate::{ConnectionConfig, HttpSignaling, NetherClient, NetherError};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

const CACHE_TTL: Duration = Duration::from_secs(10 * 60);
type Entries = Mutex<HashMap<(String, u16), Arc<Entry>>>;

struct Entry {
    endpoint: String,
    expires: Instant,
}

/// Caller-owned discovery answers; share only between equivalent HTTP/TLS/egress policies.
#[derive(Clone, Default)]
pub struct ProbeCache {
    entries: Arc<Entries>,
}

/// The endpoint and exact cache entry used by one attempt, without extending its lifetime.
#[derive(Clone)]
pub struct ProbeSelection {
    entry: Arc<Entry>,
    cache: Weak<Entries>,
    key: (String, u16),
}

impl ProbeCache {
    /// Returns only a still-live answer under the original supplied host and port.
    pub(super) fn lookup(&self, host: &str, port: u16) -> Option<ProbeSelection> {
        let key = key(host, port);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.retain(|_, entry| Instant::now() < entry.expires);
        Some(ProbeSelection {
            entry: entries.get(&key)?.clone(),
            cache: Arc::downgrade(&self.entries),
            key,
        })
    }

    /// Stores a fresh selection, or returns an unrecorded receipt when caching is disabled.
    pub(super) fn store(
        cache: Option<&Self>,
        host: &str,
        port: u16,
        endpoint: String,
    ) -> ProbeSelection {
        let key = key(host, port);
        let now = Instant::now();
        let entry = Arc::new(Entry {
            endpoint,
            expires: now + CACHE_TTL,
        });
        let cache = if let Some(cache) = cache {
            let mut entries = cache
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            entries.retain(|_, entry| now < entry.expires);
            entries.insert(key.clone(), entry.clone());
            Arc::downgrade(&cache.entries)
        } else {
            Weak::new()
        };
        ProbeSelection { entry, cache, key }
    }
}

impl ProbeSelection {
    /// Returns the original base URL that answered discovery.
    pub fn endpoint(&self) -> &str {
        &self.entry.endpoint
    }

    /// Returns the selected Login URL with exactly one explicit port, including scheme defaults.
    pub fn login_address(&self) -> String {
        let url = url::Url::parse(self.endpoint()).expect("probe candidate is an HTTP URL");
        if self
            .endpoint()
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
        {
            return self.endpoint().to_owned();
        }
        format!(
            "{}:{}",
            self.endpoint(),
            url.port_or_known_default().expect("HTTP scheme has a port")
        )
    }

    /// Forgets a failed probe/dial/Login choice while preserving any newer answer for its key.
    pub fn forget(&self) {
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let mut entries = cache.lock().unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.entry))
        {
            entries.remove(&self.key);
        }
    }

    /// Dials the chosen URL and invalidates its receipt on failure or cancellation.
    /// Call forget as well if later Bedrock Login fails after successful transport setup.
    pub async fn connect(
        &self,
        signaling: HttpSignaling,
        config: ConnectionConfig,
        deadline: Instant,
    ) -> crate::Result<NetherClient> {
        let mut guard = FailedDial {
            selection: self,
            succeeded: false,
        };
        if config.cancel_token.is_cancelled() {
            return Err(NetherError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(NetherError::Timeout);
        }
        let result = tokio::time::timeout_at(
            deadline,
            NetherClient::connect_with(signaling, self.endpoint().to_owned(), config),
        )
        .await
        .unwrap_or(Err(NetherError::Timeout));
        if Instant::now() >= deadline {
            return Err(NetherError::Timeout);
        }
        guard.succeeded = result.is_ok();
        result
    }
}

/// Normalizes only host case/brackets; omitted and explicit game ports remain distinct.
fn key(host: &str, port: u16) -> (String, u16) {
    (
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_ascii_lowercase(),
        port,
    )
}

pub(super) struct FailedDial<'a> {
    pub(super) selection: &'a ProbeSelection,
    pub(super) succeeded: bool,
}

impl Drop for FailedDial<'_> {
    /// Cancellation is also a failed choice and must not strand its cached endpoint.
    fn drop(&mut self) {
        if !self.succeeded {
            self.selection.forget();
        }
    }
}
