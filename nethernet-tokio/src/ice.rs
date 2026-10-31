//! A bounded DNS edge from acquired service URLs into exact datagram and unopened stream targets.
use crate::credentials::IceServer;
use crate::session::guard::transport_now;
use nethernet::session::{
    IceServer as ResolvedServer, MAX_ICE_SERVERS, MAX_ICE_URL_BYTES, MAX_TURN_CREDENTIAL_BYTES,
    TurnAddressFamily, TurnCredentials, TurnStreamSecurity, TurnStreamTarget,
};
use rtc::ice::url::{ProtoType, SchemeType, Url};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use thiserror::Error;

const MAX_INPUT_URLS: usize = MAX_ICE_SERVERS * MAX_ICE_SERVERS;

/// Resolution failures contain no URL, credential or dependency response text.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum IceResolveError {
    #[error("ICE server input exceeds its bound")]
    Limit,
    #[error("invalid ICE server URL or credential")]
    Invalid,
    #[error("no supported ICE server URL")]
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

/// Resolved datagram endpoints and unopened TCP/TLS targets sharing one endpoint allowance.
/// No socket or task is created; the actual runtime retains its original carrier and TLS ownership.
#[derive(Default)]
pub struct ResolvedIceTargets {
    /// UDP STUN/TURN endpoints for the original bound datagram socket family.
    pub datagrams: Vec<ResolvedServer>,
    /// Unopened TCP/TLS carriers, retaining their original service authority and credential cutoff.
    pub turn_streams: Vec<TurnStreamTarget>,
}

/// Resolves service UDP URLs without fetching credentials or creating a transport task.
///
/// Supply the original absolute credential expiry, rather than extending a cached service TTL.
/// The caller's deadline bounds the whole operation. Numeric inputs bypass DNS. Known TCP/TLS
/// alternatives are skipped when a UDP URL is available. TURN retains its original IPv4 relay
/// default, including over IPv6 UDP; use `resolve_ice_targets` for actual carrier-family selection.
/// URLs with no address for the bound socket family are skipped; if none remain, resolution fails.
pub async fn resolve_ice_servers(
    servers: &[IceServer],
    local: SocketAddr,
    valid_until: Instant,
    deadline: Instant,
) -> Result<Vec<ResolvedServer>, IceResolveError> {
    Ok(
        resolve(servers, local, valid_until, deadline, Mode::UdpOnly)
            .await?
            .datagrams,
    )
}

/// Resolves UDP ICE and UDP TURN allocations carried over TCP or verified TLS/TCP.
///
/// Datagram targets follow the existing UDP socket family; each stream hostname can retain its
/// first IPv4 and IPv6 addresses independently. TLS targets retain the original URL hostname.
/// Their source interface and default relay family come from the runtime's same actual socket.
/// All targets share the original credential expiry, caller deadline and combined endpoint cap.
/// Lookups are sequential under that one cutoff, with no retry or stalled-DNS progress guarantee.
/// Unsupported carriers and failed DNS/family alternatives do not discard other usable targets.
///
/// # Errors
/// Rejects malformed/conflicting input, combined endpoint overflow, elapsed original time fences,
/// or a nonempty service list with no supported usable target. Errors retain no service secrets.
pub async fn resolve_ice_targets(
    servers: &[IceServer],
    local: SocketAddr,
    valid_until: Instant,
    deadline: Instant,
) -> Result<ResolvedIceTargets, IceResolveError> {
    resolve(servers, local, valid_until, deadline, Mode::Full).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    UdpOnly,
    Full,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Datagram,
    Tcp,
    Tls,
}

struct Parsed {
    record: usize,
    url: Url,
    carrier: Carrier,
}

/// Shares all input validation, URL parsing and original time fences between both public policies.
async fn resolve(
    servers: &[IceServer],
    local: SocketAddr,
    valid_until: Instant,
    deadline: Instant,
    mode: Mode,
) -> Result<ResolvedIceTargets, IceResolveError> {
    if servers.len() > MAX_ICE_SERVERS
        || servers
            .iter()
            .try_fold(0usize, |count, server| count.checked_add(server.urls.len()))
            .is_none_or(|count| count > MAX_INPUT_URLS)
    {
        return Err(IceResolveError::Limit);
    }
    check_time(valid_until, deadline)?;
    let parsed = parse(servers, valid_until, mode)?;
    let mut resolved = ResolvedIceTargets::default();
    let mut datagram_owners = Vec::new();
    let mut stream_owners = Vec::new();
    let mut unavailable = None;
    for parsed in parsed {
        let addresses = match addresses(&parsed, local, valid_until, deadline).await {
            Ok(addresses) => addresses,
            Err(error)
                if error == IceResolveError::AddressFamily || error == IceResolveError::Dns =>
            {
                unavailable.get_or_insert(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        for addr in addresses {
            let server = &servers[parsed.record];
            if parsed.carrier == Carrier::Datagram {
                let endpoint = if parsed.url.scheme == SchemeType::Stun {
                    ResolvedServer::Stun(addr)
                } else {
                    let credentials = credentials(server, valid_until)?;
                    match mode {
                        Mode::UdpOnly => ResolvedServer::Turn(addr, credentials),
                        Mode::Full => ResolvedServer::TurnWithFamily {
                            addr,
                            credentials,
                            family: if local.is_ipv4() {
                                TurnAddressFamily::Ipv4
                            } else {
                                TurnAddressFamily::Ipv6
                            },
                        },
                    }
                };
                if let Some(index) = resolved
                    .datagrams
                    .iter()
                    .position(|existing| existing.addr() == addr)
                {
                    let existing_turn =
                        !matches!(resolved.datagrams[index], ResolvedServer::Stun(_));
                    let incoming_turn = !matches!(endpoint, ResolvedServer::Stun(_));
                    if existing_turn
                        && incoming_turn
                        && conflicting(servers, datagram_owners[index], parsed.record)
                    {
                        return Err(IceResolveError::Invalid);
                    }
                    if !existing_turn && incoming_turn {
                        resolved.datagrams[index] = endpoint;
                        datagram_owners[index] = parsed.record;
                    }
                } else {
                    check_capacity(&resolved)?;
                    resolved.datagrams.push(endpoint);
                    datagram_owners.push(parsed.record);
                }
            } else {
                let security = match parsed.carrier {
                    Carrier::Tcp => TurnStreamSecurity::Tcp,
                    Carrier::Tls => TurnStreamSecurity::Tls {
                        server_name: parsed.url.host.clone(),
                    },
                    Carrier::Datagram => unreachable!("datagram targets were handled above"),
                };
                if let Some(index) = resolved
                    .turn_streams
                    .iter()
                    .position(|target| target.remote == addr && target.security == security)
                {
                    if conflicting(servers, stream_owners[index], parsed.record) {
                        return Err(IceResolveError::Invalid);
                    }
                } else {
                    check_capacity(&resolved)?;
                    resolved.turn_streams.push(TurnStreamTarget {
                        remote: addr,
                        bind_ip: None,
                        security,
                        credentials: credentials(server, valid_until)?,
                        requested_family: None,
                    });
                    stream_owners.push(parsed.record);
                }
            }
        }
    }
    check_time(valid_until, deadline)?;
    if resolved.datagrams.is_empty()
        && resolved.turn_streams.is_empty()
        && let Some(error) = unavailable
    {
        return Err(error);
    }
    Ok(resolved)
}

/// Validates every bounded input before starting DNS; unsupported carriers preserve their old skip policy.
fn parse(
    servers: &[IceServer],
    valid_until: Instant,
    mode: Mode,
) -> Result<Vec<Parsed>, IceResolveError> {
    let mut parsed = Vec::new();
    for (record, server) in servers.iter().enumerate() {
        if server.username.len() > MAX_TURN_CREDENTIAL_BYTES
            || server.password.len() > MAX_TURN_CREDENTIAL_BYTES
        {
            return Err(IceResolveError::Limit);
        }
        for raw in &server.urls {
            if raw.len() > MAX_ICE_URL_BYTES {
                return Err(IceResolveError::Limit);
            }
            if raw.contains('@') || raw.chars().any(char::is_control) {
                return Err(IceResolveError::Invalid);
            }
            let url = Url::parse_url(raw).map_err(|_| IceResolveError::Invalid)?;
            let carrier = match (url.scheme, url.proto) {
                (SchemeType::Stun | SchemeType::Turn, ProtoType::Udp) => Carrier::Datagram,
                (SchemeType::Turn, ProtoType::Tcp) if mode == Mode::Full => Carrier::Tcp,
                (SchemeType::Turns, ProtoType::Tcp) if mode == Mode::Full => Carrier::Tls,
                _ => continue,
            };
            if url.host.is_empty() || url.port == 0 {
                return Err(IceResolveError::Invalid);
            }
            if url.scheme != SchemeType::Stun {
                credentials(server, valid_until)?;
            }
            parsed.push(Parsed {
                record,
                url,
                carrier,
            });
        }
    }
    if parsed.is_empty() && !servers.is_empty() {
        return Err(IceResolveError::UnsupportedTransport);
    }
    Ok(parsed)
}

/// Selects only the first address of each usable carrier family, never manufacturing a source interface.
async fn addresses(
    parsed: &Parsed,
    local: SocketAddr,
    valid_until: Instant,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, IceResolveError> {
    if let Ok(ip) = parsed.url.host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, parsed.url.port);
        validate_address(addr)?;
        if parsed.carrier == Carrier::Datagram && addr.is_ipv4() != local.is_ipv4() {
            return Err(IceResolveError::AddressFamily);
        }
        return Ok(vec![addr]);
    }
    let addresses = tokio::time::timeout_at(
        deadline.min(valid_until).into(),
        tokio::net::lookup_host((parsed.url.host.as_str(), parsed.url.port)),
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
    if parsed.carrier == Carrier::Datagram {
        let addr = addresses
            .into_iter()
            .find(|addr| addr.is_ipv4() == local.is_ipv4())
            .ok_or(IceResolveError::AddressFamily)?;
        validate_address(addr)?;
        return Ok(vec![addr]);
    }
    let mut selected: Vec<SocketAddr> = Vec::new();
    for addr in addresses {
        validate_address(addr)?;
        if !selected
            .iter()
            .any(|existing| existing.is_ipv4() == addr.is_ipv4())
        {
            selected.push(addr);
            if selected.len() == 2 {
                break;
            }
        }
    }
    if selected.is_empty() {
        return Err(IceResolveError::Dns);
    }
    Ok(selected)
}

/// Keeps numeric server input away from unspecified or multicast destinations.
fn validate_address(addr: SocketAddr) -> Result<(), IceResolveError> {
    if addr.ip().is_unspecified() || addr.ip().is_multicast() {
        Err(IceResolveError::Invalid)
    } else {
        Ok(())
    }
}

/// Preserves one source record's credentials and original absolute admission expiry.
fn credentials(
    server: &IceServer,
    valid_until: Instant,
) -> Result<TurnCredentials, IceResolveError> {
    TurnCredentials::new(
        server.username.clone(),
        server.password.clone(),
        valid_until,
    )
    .map_err(|_| IceResolveError::Invalid)
}

/// Rejects conflicting owners before replacing or inserting any same-target result.
fn conflicting(servers: &[IceServer], previous: usize, incoming: usize) -> bool {
    servers[previous].username != servers[incoming].username
        || servers[previous].password != servers[incoming].password
}

/// Applies one common bound to datagrams and unopened streams together.
fn check_capacity(resolved: &ResolvedIceTargets) -> Result<(), IceResolveError> {
    if resolved.datagrams.len() + resolved.turn_streams.len() >= MAX_ICE_SERVERS {
        Err(IceResolveError::Limit)
    } else {
        Ok(())
    }
}

/// Preserves the original expiry-first terminal ordering at entry and final handoff.
fn check_time(valid_until: Instant, deadline: Instant) -> Result<(), IceResolveError> {
    let now = transport_now();
    if now >= valid_until {
        return Err(IceResolveError::Expired);
    }
    if now >= deadline {
        return Err(IceResolveError::TimedOut);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    /// A stale DNS alternative cannot discard a numeric UDP target in either resolver.
    #[tokio::test]
    async fn dns_failure_preserves_usable_udp_targets() {
        for reverse in [false, true] {
            let mut urls = vec![
                "stun:127.0.0.1:3478".into(),
                "stun:does-not-exist.invalid:3478".into(),
            ];
            if reverse {
                urls.reverse();
            }
            let server = IceServer {
                urls,
                ..Default::default()
            };
            let now = transport_now();
            let expires = now + Duration::from_secs(30);
            let deadline = now + Duration::from_secs(5);
            let local = "127.0.0.1:0".parse().unwrap();
            assert_eq!(
                resolve_ice_servers(std::slice::from_ref(&server), local, expires, deadline)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                resolve_ice_targets(&[server], local, expires, deadline)
                    .await
                    .unwrap()
                    .datagrams
                    .len(),
                1
            );
        }
    }

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

    /// Actual resolution retains distinct carriers and TLS authority while default source selection stays at the edge.
    #[tokio::test]
    async fn full_targets_preserve_carriers_families_authority_and_original_expiry() {
        let now = transport_now();
        let expires = now + Duration::from_secs(30);
        let deadline = now + Duration::from_secs(5);
        let local = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        let service = IceServer {
            username: "original-user".into(),
            password: "original-password".into(),
            urls: vec![
                "stun:127.0.0.1:3478".into(),
                "turn:127.0.0.1:3478?transport=udp".into(),
                "turn:127.0.0.1:3478?transport=tcp".into(),
                "turns:localhost:5349".into(),
                "turn:[::1]:3478?transport=tcp".into(),
                "turn:[::1]:3478?transport=udp".into(),
                "turns:127.0.0.1:5349?transport=udp".into(),
            ],
        };
        let targets = resolve_ice_targets(&[service], local, expires, deadline)
            .await
            .unwrap();
        assert!(matches!(
            targets.datagrams.as_slice(),
            [ResolvedServer::TurnWithFamily {
                family: TurnAddressFamily::Ipv4,
                ..
            }]
        ));
        assert!(targets.turn_streams.iter().any(|target| target.remote.is_ipv4() && target.security == TurnStreamSecurity::Tcp));
        assert!(targets.turn_streams.iter().any(|target| target.remote.is_ipv6() && target.security == TurnStreamSecurity::Tcp));
        assert!(targets.turn_streams.iter().any(|target| matches!(&target.security, TurnStreamSecurity::Tls { server_name } if server_name == "localhost") && target.remote.ip().is_loopback()));
        for target in &targets.turn_streams {
            assert!(target.bind_ip.is_none() && target.requested_family.is_none());
            assert_eq!(target.local_bind_ip(None).unwrap(), None);
            assert_eq!(
                target.admission_deadline(expires + Duration::from_secs(1)),
                expires
            );
        }
        let v6 = IceServer {
            username: "original-user".into(),
            password: "original-password".into(),
            urls: vec!["turn:[::1]:3478".into()],
        };
        let local = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);
        let targets = resolve_ice_targets(std::slice::from_ref(&v6), local, expires, deadline)
            .await
            .unwrap();
        assert!(matches!(
            targets.datagrams.as_slice(),
            [ResolvedServer::TurnWithFamily {
                family: TurnAddressFamily::Ipv6,
                ..
            }]
        ));
        let old = resolve_ice_servers(&[v6], local, expires, deadline)
            .await
            .unwrap();
        assert!(
            matches!(old.as_slice(), [ResolvedServer::Turn(..)]),
            "the original UDP API changed its IPv4 relay default"
        );
    }

    /// Duplicate identity and one shared endpoint allowance are enforced across both result vectors.
    #[tokio::test]
    async fn full_targets_share_one_cap_and_reject_conflicting_same_target_credentials() {
        let now = transport_now();
        let expires = now + Duration::from_secs(30);
        let deadline = now + Duration::from_secs(5);
        let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let mut service = IceServer {
            username: "original-user".into(),
            password: "original-password".into(),
            urls: (0..MAX_ICE_SERVERS)
                .map(|index| {
                    format!(
                        "turn:127.0.0.1:{}?transport={}",
                        3478 + index,
                        if index % 2 == 0 { "udp" } else { "tcp" }
                    )
                })
                .collect(),
        };
        let targets = resolve_ice_targets(std::slice::from_ref(&service), local, expires, deadline)
            .await
            .unwrap();
        assert_eq!(
            targets.datagrams.len() + targets.turn_streams.len(),
            MAX_ICE_SERVERS
        );
        service.urls.push(service.urls[0].clone());
        let targets = resolve_ice_targets(std::slice::from_ref(&service), local, expires, deadline)
            .await
            .unwrap();
        assert_eq!(
            targets.datagrams.len() + targets.turn_streams.len(),
            MAX_ICE_SERVERS
        );
        service.urls.push("turns:127.0.0.1:5349".into());
        assert!(matches!(
            resolve_ice_targets(&[service], local, expires, deadline).await,
            Err(IceResolveError::Limit)
        ));
        for url in [
            "turn:127.0.0.1:3478",
            "turn:127.0.0.1:3478?transport=tcp",
            "turns:127.0.0.1:5349",
        ] {
            let original = IceServer {
                username: "original-user".into(),
                password: "original-password".into(),
                urls: vec![url.into()],
            };
            let mut replacement = original.clone();
            replacement.password = "different-password".into();
            assert!(matches!(
                resolve_ice_targets(&[original, replacement], local, expires, deadline).await,
                Err(IceResolveError::Invalid)
            ));
        }
    }

    /// Unsupported alternatives never acquire a hidden transport, deadline extension or input allowance.
    #[tokio::test]
    async fn full_targets_keep_original_time_fences_and_prevalidate_late_input() {
        let now = transport_now();
        let expires = now + Duration::from_secs(30);
        let deadline = now + Duration::from_secs(5);
        let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        assert!(matches!(
            resolve_ice_targets(&[], local, now, deadline).await,
            Err(IceResolveError::Expired)
        ));
        assert!(matches!(
            resolve_ice_targets(&[], local, expires, now).await,
            Err(IceResolveError::TimedOut)
        ));
        let mut service = IceServer {
            username: "original-user".into(),
            password: "original-password".into(),
            urls: vec!["turns:127.0.0.1:5349?transport=udp".into()],
        };
        assert!(matches!(
            resolve_ice_targets(std::slice::from_ref(&service), local, expires, deadline).await,
            Err(IceResolveError::UnsupportedTransport)
        ));
        service
            .urls
            .push("turn:127.0.0.1:3478?transport=tcp".into());
        assert_eq!(
            resolve_ice_targets(std::slice::from_ref(&service), local, expires, deadline)
                .await
                .unwrap()
                .turn_streams
                .len(),
            1
        );
        assert!(matches!(
            resolve_ice_servers(std::slice::from_ref(&service), local, expires, deadline).await,
            Err(IceResolveError::UnsupportedTransport)
        ));
        service.urls.push("x".repeat(MAX_ICE_URL_BYTES + 1));
        assert!(matches!(
            resolve_ice_targets(&[service], local, expires, deadline).await,
            Err(IceResolveError::Limit)
        ));
    }
}
