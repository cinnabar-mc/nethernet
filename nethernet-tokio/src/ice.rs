//! A bounded DNS edge from already-acquired service URLs into the pure session configuration.
use crate::credentials::IceServer;
use crate::session::guard::transport_now;
use nethernet::session::{
    IceServer as ResolvedServer, MAX_ICE_SERVERS, MAX_TURN_CREDENTIAL_BYTES, TurnCredentials,
};
use rtc::ice::url::{ProtoType, SchemeType, Url};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use thiserror::Error;

const MAX_URL_BYTES: usize = 2048;
const MAX_INPUT_URLS: usize = MAX_ICE_SERVERS * MAX_ICE_SERVERS;

/// Resolution failures contain no URL, credential or dependency response text.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IceResolveError {
    #[error("ICE server input exceeds its bound")]
    Limit,
    #[error("invalid ICE server URL or credential")]
    Invalid,
    #[error("no supported UDP ICE server URL")]
    UnsupportedTransport,
    #[error("ICE server has no address for the bound socket family")]
    AddressFamily,
    #[error("ICE server DNS lookup failed")]
    Dns,
    #[error("ICE server resolution deadline elapsed")]
    TimedOut,
    #[error("TURN credential expired during resolution")]
    Expired,
}

/// Resolves service UDP URLs without fetching credentials or creating a transport task.
///
/// Supply the original absolute credential expiry, rather than extending a cached service TTL.
/// The caller's deadline bounds the whole operation. Numeric inputs bypass DNS. Known TCP/TLS
/// alternatives are skipped when a UDP URL is available; this edge does not implement those transports.
/// Use the resulting owned endpoints in `nethernet::session::IceConfig` for either runtime adapter.
pub async fn resolve_ice_servers(
    servers: &[IceServer],
    local: SocketAddr,
    valid_until: Instant,
    deadline: Instant,
) -> Result<Vec<ResolvedServer>, IceResolveError> {
    if servers.len() > MAX_ICE_SERVERS
        || servers
            .iter()
            .try_fold(0usize, |count, server| count.checked_add(server.urls.len()))
            .is_none_or(|count| count > MAX_INPUT_URLS)
    {
        return Err(IceResolveError::Limit);
    }
    let now = transport_now();
    if now >= valid_until {
        return Err(IceResolveError::Expired);
    }
    if now >= deadline {
        return Err(IceResolveError::TimedOut);
    }
    // Validate every URL and credential before starting DNS, so an oversized late entry cannot cause partial work.
    let mut parsed = Vec::new();
    for (record, server) in servers.iter().enumerate() {
        if server.username.len() > MAX_TURN_CREDENTIAL_BYTES
            || server.password.len() > MAX_TURN_CREDENTIAL_BYTES
        {
            return Err(IceResolveError::Limit);
        }
        for raw in &server.urls {
            if raw.len() > MAX_URL_BYTES {
                return Err(IceResolveError::Limit);
            }
            if raw.contains('@') || raw.chars().any(char::is_control) {
                return Err(IceResolveError::Invalid);
            }
            let url = Url::parse_url(raw).map_err(|_| IceResolveError::Invalid)?;
            if url.proto != ProtoType::Udp
                || !matches!(url.scheme, SchemeType::Stun | SchemeType::Turn)
            {
                continue;
            }
            if url.host.is_empty() || url.port == 0 {
                return Err(IceResolveError::Invalid);
            }
            if url.scheme == SchemeType::Turn {
                TurnCredentials::new(
                    server.username.clone(),
                    server.password.clone(),
                    valid_until,
                )
                .map_err(|_| IceResolveError::Invalid)?;
            }
            parsed.push((record, url));
        }
    }
    if parsed.is_empty() && !servers.is_empty() {
        return Err(IceResolveError::UnsupportedTransport);
    }
    let mut resolved: Vec<ResolvedServer> = Vec::new();
    let mut owners = Vec::new();
    for (record, url) in parsed {
        let addr = if let Ok(ip) = url.host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, url.port);
            if addr.is_ipv4() != local.is_ipv4() {
                return Err(IceResolveError::AddressFamily);
            }
            addr
        } else {
            let addresses = tokio::time::timeout_at(
                deadline.min(valid_until).into(),
                tokio::net::lookup_host((url.host.as_str(), url.port)),
            )
            .await
            .map_err(|_| {
                if transport_now() >= valid_until {
                    IceResolveError::Expired
                } else {
                    IceResolveError::TimedOut
                }
            })?
            .map_err(|_| IceResolveError::Dns)?;
            addresses
                .into_iter()
                .find(|addr| addr.is_ipv4() == local.is_ipv4())
                .ok_or(IceResolveError::AddressFamily)?
        };
        if addr.ip().is_unspecified() || addr.ip().is_multicast() {
            return Err(IceResolveError::Invalid);
        }
        let server = &servers[record];
        let endpoint = if url.scheme == SchemeType::Stun {
            ResolvedServer::Stun(addr)
        } else {
            ResolvedServer::Turn(
                addr,
                TurnCredentials::new(
                    server.username.clone(),
                    server.password.clone(),
                    valid_until,
                )
                .map_err(|_| IceResolveError::Invalid)?,
            )
        };
        if let Some(index) = resolved.iter().position(|existing| existing.addr() == addr) {
            match (&resolved[index], &endpoint) {
                (ResolvedServer::Stun(_), ResolvedServer::Turn(..)) => {
                    resolved[index] = endpoint;
                    owners[index] = record;
                }
                (ResolvedServer::Turn(..), ResolvedServer::Turn(..)) if owners[index] != record => {
                    let previous = &servers[owners[index]];
                    if previous.username != server.username || previous.password != server.password
                    {
                        return Err(IceResolveError::Invalid);
                    }
                }
                _ => {}
            }
        } else {
            if resolved.len() >= MAX_ICE_SERVERS {
                return Err(IceResolveError::Limit);
            }
            resolved.push(endpoint);
            owners.push(record);
        }
    }
    if transport_now() >= valid_until {
        return Err(IceResolveError::Expired);
    }
    if transport_now() >= deadline {
        return Err(IceResolveError::TimedOut);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    /// An unrelated numeric family cannot suppress the same service's usable alternative.
    #[tokio::test]
    async fn resolver_retains_usable_service_urls_after_another_socket_family() {
        let now = transport_now();
        let expires = now + Duration::from_secs(30);
        let deadline = now + Duration::from_secs(5);
        let port = 40280;
        let endpoints = [
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port),
        ];
        let mut outcomes = Vec::new();
        for (index, expected) in endpoints.iter().copied().enumerate() {
            let other = endpoints[1 - index];
            let service = IceServer {
                urls: vec![format!("stun:{other}"), format!("stun:{expected}")],
                ..Default::default()
            };
            let resolved = resolve_ice_servers(
                &[service],
                SocketAddr::new(expected.ip(), 0),
                expires,
                deadline,
            )
            .await;
            outcomes.push((expected, resolved));
        }
        for (expected, resolved) in outcomes {
            let resolved = resolved
                .expect("an unrelated address family discarded a usable numeric service URL");
            assert_eq!(resolved.len(), 1);
            assert!(matches!(resolved[0], ResolvedServer::Stun(addr) if addr == expected));
        }
    }

    #[tokio::test]
    async fn resolver_preserves_deadlines_socket_family_and_udp_service_alternatives() {
        let now = transport_now();
        let expires = now + Duration::from_secs(30);
        let deadline = now + Duration::from_secs(5);
        let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let service = IceServer {
            username: "original-user".into(),
            password: "original-password".into(),
            urls: vec![
                "stun:localhost:3478".into(),
                "turn:localhost:3478?transport=udp".into(),
                "turn:localhost:3478?transport=tcp".into(),
                "turns:localhost:5349".into(),
            ],
        };
        let resolved = resolve_ice_servers(&[service], local, expires, deadline)
            .await
            .unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved[0], ResolvedServer::Turn(..)));
        assert!(resolved[0].addr().ip().is_loopback());
        let v6 = IceServer {
            urls: vec!["stun:[::1]:3478".into()],
            ..Default::default()
        };
        let resolved = resolve_ice_servers(
            std::slice::from_ref(&v6),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0),
            expires,
            deadline,
        )
        .await
        .unwrap();
        assert!(resolved[0].addr().is_ipv6());
        assert!(matches!(
            resolve_ice_servers(&[v6], local, expires, deadline).await,
            Err(IceResolveError::AddressFamily)
        ));
        assert!(matches!(
            resolve_ice_servers(&[], local, now, deadline).await,
            Err(IceResolveError::Expired)
        ));
        assert!(matches!(
            resolve_ice_servers(&[], local, expires, now).await,
            Err(IceResolveError::TimedOut)
        ));
        let unsupported = IceServer {
            urls: vec!["turns:localhost:5349".into()],
            ..Default::default()
        };
        assert!(matches!(
            resolve_ice_servers(&[unsupported], local, expires, deadline).await,
            Err(IceResolveError::UnsupportedTransport)
        ));
        let oversized = IceServer {
            username: "x".repeat(MAX_TURN_CREDENTIAL_BYTES + 1),
            urls: vec!["turn:must-not-be-resolved.invalid:3478".into()],
            ..Default::default()
        };
        assert!(matches!(
            resolve_ice_servers(&[oversized], local, expires, deadline).await,
            Err(IceResolveError::Limit)
        ));
    }
}
