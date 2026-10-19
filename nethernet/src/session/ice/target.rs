//! Unopened numeric TURN carrier inputs shared by the concrete runtime adapters.
use super::config::{IceError, TurnCredentials};
use super::route::TurnAddressFamily;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// Bounds one service URL or its retained original TLS authority before socket work.
pub const MAX_ICE_URL_BYTES: usize = 2048;

/// The outer carrier; TLS verification belongs to the actual runtime's configured verifier.
#[derive(Clone, PartialEq, Eq)]
pub enum TurnStreamSecurity {
    Tcp,
    /// Original service hostname, retained independently of its resolved numeric address.
    Tls {
        server_name: String,
    },
}

/// Unopened, bounded carrier configuration. It never owns a socket or connection authority.
/// Each attempt binds its own socket and creates its route from that socket's actual tuple.
#[derive(Clone)]
pub struct TurnStreamTarget {
    pub remote: SocketAddr,
    /// Explicit concrete source interface; absence permits the TCP socket's own OS route selection.
    pub bind_ip: Option<IpAddr>,
    pub security: TurnStreamSecurity,
    pub credentials: TurnCredentials,
    /// Absence follows the family of the actual bound TCP socket, independently of UDP ICE.
    pub requested_family: Option<TurnAddressFamily>,
}

impl TurnStreamTarget {
    /// Checks bounded numeric input and the original credential expiry before any dial.
    /// TLS name syntax and certificate verification remain at the actual TLS edge.
    pub fn validate(&self, now: Instant) -> Result<(), IceError> {
        if self.remote.port() == 0
            || self.remote.ip().is_unspecified()
            || self.remote.ip().is_multicast()
        {
            return Err(IceError::Configuration);
        }
        if self.credentials.valid_until <= now {
            return Err(IceError::Credentials);
        }
        if let Some(ip) = self.bind_ip {
            self.local_bind_ip(Some(ip))?;
        }
        if let TurnStreamSecurity::Tls { server_name } = &self.security
            && (server_name.is_empty()
                || server_name.len() > MAX_ICE_URL_BYTES
                || server_name.chars().any(char::is_control))
        {
            return Err(IceError::Configuration);
        }
        Ok(())
    }

    /// Uses only a caller-explicit concrete source, never an unrelated UDP routing probe.
    /// Without one, the adapter validates this TCP socket's actual tuple after connect starts.
    pub fn local_bind_ip(&self, fallback: Option<IpAddr>) -> Result<Option<IpAddr>, IceError> {
        let usable = |ip: IpAddr| {
            !ip.is_unspecified() && !ip.is_multicast() && ip.is_ipv4() == self.remote.is_ipv4()
        };
        match self.bind_ip {
            Some(ip) if usable(ip) => Ok(Some(ip)),
            Some(_) => Err(IceError::Configuration),
            None => Ok(fallback.filter(|ip| usable(*ip))),
        }
    }

    /// Derives the default relay family from this carrier's actual bound TCP tuple.
    pub fn family_for(&self, actual_local: SocketAddr) -> TurnAddressFamily {
        self.requested_family
            .unwrap_or_else(|| TurnAddressFamily::for_local(actual_local))
    }

    /// Bounds connection and TLS setup by both the caller's cutoff and this original credential.
    /// An acknowledged allocation keeps its separate server-owned lease.
    pub fn admission_deadline(&self, caller_deadline: Instant) -> Instant {
        caller_deadline.min(self.credentials.valid_until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unopened_target_keeps_expiry_explicit_interface_and_relay_family_separate() {
        let now = Instant::now();
        let mut target = TurnStreamTarget {
            remote: "[::1]:3478".parse().unwrap(),
            bind_ip: None,
            security: TurnStreamSecurity::Tcp,
            credentials: TurnCredentials::new(
                "user".into(),
                "password".into(),
                now + Duration::from_secs(1),
            )
            .unwrap(),
            requested_family: None,
        };
        assert!(target.validate(now).is_ok());
        assert_eq!(target.local_bind_ip(None).unwrap(), None);
        assert_eq!(
            target
                .local_bind_ip(Some("127.0.0.1".parse().unwrap()))
                .unwrap(),
            None
        );
        target.bind_ip = Some("::1".parse().unwrap());
        assert_eq!(
            target
                .local_bind_ip(Some("127.0.0.1".parse().unwrap()))
                .unwrap(),
            Some("::1".parse::<IpAddr>().unwrap())
        );
        let actual = "[::1]:50000".parse().unwrap();
        assert_eq!(target.family_for(actual), TurnAddressFamily::Ipv6);
        target.requested_family = Some(TurnAddressFamily::Ipv4);
        assert_eq!(target.family_for(actual), TurnAddressFamily::Ipv4);
        let mut ice = super::super::config::IceConfig {
            policy: super::super::config::IcePolicy::RelayOnly,
            ..Default::default()
        };
        assert!(ice.validate(actual, now).is_err());
        assert!(
            ice.validate_with_stream_targets(actual, std::slice::from_ref(&target), now)
                .is_ok()
        );
        ice.servers = (0..super::super::config::MAX_ICE_SERVERS)
            .map(|index| {
                super::super::config::IceServer::Stun(SocketAddr::new(
                    actual.ip(),
                    3478 + u16::try_from(index).unwrap(),
                ))
            })
            .collect();
        assert!(
            ice.validate_with_stream_targets(actual, std::slice::from_ref(&target), now)
                .is_err(),
            "unopened streams cannot acquire a second endpoint allowance"
        );
        assert_eq!(
            target.validate(now + Duration::from_secs(1)),
            Err(IceError::Credentials)
        );
        target.bind_ip = Some("::".parse().unwrap());
        assert!(target.validate(now).is_err());
    }
}
