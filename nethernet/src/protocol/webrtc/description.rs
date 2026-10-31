//! The single data-channel SDP media section that NetherNet peers exchange.
use crate::error::ProtocolError;
use crate::protocol::constants::SCTP_MAX_MESSAGE_SIZE;
use crate::protocol::webrtc::candidate;
use rtc::ice::agent::Credentials;
use rtc::ice::candidate::{Candidate, CandidateType};
use rtc::sdp::description::common::{Address, Attribute, ConnectionInformation};
use rtc::sdp::description::media::{MediaDescription, MediaName, RangedPort};
use rtc::sdp::description::session::{
    ATTR_KEY_CONNECTION_SETUP, ATTR_KEY_EXTMAP_ALLOW_MIXED, ATTR_KEY_GROUP, ATTR_KEY_IDENTITY,
    ATTR_KEY_MAX_MESSAGE_SIZE, ATTR_KEY_MID, ATTR_KEY_MSID_SEMANTIC, Origin, SessionDescription,
    TimeDescription,
};
use rtc::sdp::util::ConnectionRole;
use std::io::Cursor;
use std::net::IpAddr;

pub const SCTP_PORT: u16 = 5000;

/// Server is announced as `actpass`; Client and Auto are announced as `active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    Client,
    Server,
    Auto,
}

/// A peer's ICE credentials, DTLS setup and certificate fingerprint as carried in SDP.
#[derive(Clone)]
pub struct Description {
    /// Caller-selected SDP origin identifier, retained across encodings of this session.
    pub session_id: u64,
    pub ice: Credentials,
    pub dtls_role: DtlsRole,
    /// Algorithm and digest from the `fingerprint` attribute.
    pub fingerprint: (String, String),
    /// Defaults to 65536 when the remote omits the attribute.
    pub sctp_max_message_size: u32,
    /// Raw session-level `a=identity` value, opaque at this layer (guide section 5).
    pub identity: Option<String>,
}

impl Description {
    /// Leaves out candidates and sets `ice-options:trickle`.
    pub fn encode_trickle(&self) -> String {
        let media = self
            .base_media()
            .with_value_attribute("ice-options".to_string(), "trickle".to_string());
        self.session(media).marshal()
    }

    /// Embeds candidates and uses the preferred UDP candidate as the media address.
    pub fn encode_full(&self, candidates: &[Candidate]) -> String {
        let mut media = self
            .base_media()
            .with_value_attribute("ice-options".to_string(), "trickle".to_string());
        if let Some(candidate) = default_candidate(candidates)
            && let Ok(address) = candidate.address().parse::<IpAddr>()
        {
            media.media_name.port.value = candidate.port() as isize;
            if let Some(connection) = &mut media.connection_information {
                connection.address_type = if address.is_ipv4() { "IP4" } else { "IP6" }.into();
                connection.address.as_mut().unwrap().address = address.to_string();
            }
        }
        for (index, c) in candidates.iter().enumerate() {
            media = media.with_candidate(candidate::attribute_value(index, c, &self.ice.ufrag));
        }
        self.session(media).marshal()
    }

    /// Reads one media section, including session-level fingerprints and candidates.
    pub fn parse(sdp: &str) -> Result<(Description, Vec<Candidate>), ProtocolError> {
        let session = SessionDescription::unmarshal(&mut Cursor::new(sdp))
            .map_err(|e| ProtocolError::Other(format!("decode session description: {e}")))?;

        if session.media_descriptions.len() != 1 {
            return Err(ProtocolError::Other(format!(
                "unexpected number of media descriptions: {}, expected 1",
                session.media_descriptions.len()
            )));
        }
        let media = &session.media_descriptions[0];

        let ufrag = attribute(media, &session, "ice-ufrag")?.to_string();
        let pwd = attribute(media, &session, "ice-pwd")?.to_string();

        let fingerprint_attr = attribute(media, &session, "fingerprint")?;
        let (algorithm, value) = fingerprint_attr.split_once(' ').ok_or_else(|| {
            ProtocolError::Other(format!("invalid fingerprint: {fingerprint_attr}"))
        })?;

        let setup = attribute(media, &session, ATTR_KEY_CONNECTION_SETUP)?;
        let dtls_role = match setup {
            "active" => DtlsRole::Client,
            "actpass" | "passive" => DtlsRole::Server,
            _ => {
                return Err(ProtocolError::Other(format!(
                    "invalid setup attribute: {setup}"
                )));
            }
        };

        let sctp_max_message_size =
            match optional_attribute(media, &session, ATTR_KEY_MAX_MESSAGE_SIZE)? {
                Some(value) => value.parse::<u32>().map_err(|e| {
                    ProtocolError::Other(format!("parse max-message-size attribute: {e}"))
                })?,
                None => SCTP_MAX_MESSAGE_SIZE,
            };

        let mut candidates = Vec::new();
        for attr in session.attributes.iter().chain(&media.attributes) {
            if attr.key == "candidate" {
                let value = attr
                    .value
                    .as_deref()
                    .ok_or_else(|| ProtocolError::Other("empty candidate attribute".into()))?;
                if let Some(parsed) = candidate::parse_sdp_candidate(value)? {
                    candidates.push(parsed);
                }
            }
        }

        let identity = session.attribute(ATTR_KEY_IDENTITY).cloned();

        Ok((
            Self {
                session_id: session.origin.session_id,
                ice: Credentials { ufrag, pwd },
                dtls_role,
                fingerprint: (algorithm.to_string(), value.to_string()),
                sctp_max_message_size,
                identity,
            },
            candidates,
        ))
    }

    fn session(&self, media: MediaDescription) -> SessionDescription {
        let mut attributes = vec![
            Attribute {
                key: ATTR_KEY_GROUP.to_string(),
                value: Some("BUNDLE 0".to_string()),
            },
            Attribute {
                key: ATTR_KEY_EXTMAP_ALLOW_MIXED.to_string(),
                value: None,
            },
            Attribute {
                key: ATTR_KEY_MSID_SEMANTIC.to_string(),
                value: Some(" WMS".to_string()),
            },
        ];
        if let Some(identity) = &self.identity {
            attributes.push(Attribute {
                key: ATTR_KEY_IDENTITY.to_string(),
                value: Some(identity.to_string()),
            });
        }

        SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: self.session_id,
                session_version: 2,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "-".to_string(),
            time_descriptions: vec![TimeDescription::default()],
            attributes,
            ..Default::default()
        }
        .with_media(media)
    }

    fn base_media(&self) -> MediaDescription {
        let media = MediaDescription {
            media_name: MediaName {
                media: "application".to_string(),
                port: RangedPort {
                    value: 9,
                    range: None,
                },
                protos: vec!["UDP".to_string(), "DTLS".to_string(), "SCTP".to_string()],
                formats: vec!["webrtc-datachannel".to_string()],
            },
            connection_information: Some(ConnectionInformation {
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                address: Some(Address {
                    address: "0.0.0.0".to_string(),
                    ttl: None,
                    range: None,
                }),
            }),
            ..Default::default()
        }
        .with_ice_credentials(self.ice.ufrag.clone(), self.ice.pwd.clone());

        let (algorithm, value) = &self.fingerprint;
        let media = media.with_fingerprint(algorithm.clone(), value.clone());

        media
            .with_value_attribute(
                ATTR_KEY_CONNECTION_SETUP.to_string(),
                connection_role(self.dtls_role).to_string(),
            )
            .with_value_attribute(ATTR_KEY_MID.to_string(), "0".to_string())
            .with_value_attribute("sctp-port".to_string(), SCTP_PORT.to_string())
            .with_value_attribute(
                ATTR_KEY_MAX_MESSAGE_SIZE.to_string(),
                self.sctp_max_message_size.to_string(),
            )
    }
}

/// Prefers IPv4 and then relay, reflexive and host candidates within the same family.
fn default_candidate(candidates: &[Candidate]) -> Option<&Candidate> {
    let mut selected = None;
    let mut family = 0;
    let mut preference = 0;
    for candidate in candidates {
        if !candidate.network_type().is_udp() || candidate.component() != 1 {
            continue;
        }
        let next_family = match candidate.address().parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => 4,
            Ok(IpAddr::V6(_)) => 6,
            Err(_) => 0,
        };
        let next_preference = match candidate.candidate_type() {
            CandidateType::Relay => 3,
            CandidateType::ServerReflexive => 2,
            CandidateType::Host => 1,
            _ => 0,
        };
        if selected.is_some()
            && ((family == next_family && next_preference <= preference)
                || (family == 4 && next_family == 6))
        {
            continue;
        }
        selected = Some(candidate);
        family = next_family;
        preference = next_preference;
    }
    selected
}

/// Resolves a required media attribute using the session value only when it is absent.
fn attribute<'a>(
    media: &'a MediaDescription,
    session: &'a SessionDescription,
    key: &str,
) -> Result<&'a str, ProtocolError> {
    optional_attribute(media, session, key)?
        .ok_or_else(|| ProtocolError::Other(format!("missing {key} attribute")))
}

/// Distinguishes an omitted attribute from a present valueless attribute.
fn optional_attribute<'a>(
    media: &'a MediaDescription,
    session: &'a SessionDescription,
    key: &str,
) -> Result<Option<&'a str>, ProtocolError> {
    media
        .attributes
        .iter()
        .chain(&session.attributes)
        .find(|attr| attr.key == key)
        .map(|attr| {
            attr.value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| ProtocolError::Other(format!("empty {key} attribute")))
        })
        .transpose()
}

fn connection_role(role: DtlsRole) -> ConnectionRole {
    match role {
        DtlsRole::Server => ConnectionRole::Actpass,
        _ => ConnectionRole::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::ice::candidate::CandidateConfig;
    use rtc::ice::candidate::candidate_host::CandidateHostConfig;

    fn description(role: DtlsRole) -> Description {
        Description {
            session_id: 42,
            ice: Credentials {
                ufrag: "abcd".to_string(),
                pwd: "0123456789abcdef01234567".to_string(),
            },
            dtls_role: role,
            fingerprint: ("sha-256".to_string(), "AB:CD:EF".to_string()),
            sctp_max_message_size: 65536,
            identity: None,
        }
    }

    fn host_candidate(address: &str, port: u16) -> Candidate {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: address.to_string(),
                port,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap()
    }

    #[test]
    fn trickle_roundtrip() {
        let local = description(DtlsRole::Server);
        let encoded = local.encode_trickle();
        assert_eq!(encoded, local.encode_trickle());
        assert!(encoded.contains("o=- 42 2 IN IP4 127.0.0.1\r\n"));
        assert!(encoded.contains("a=setup:actpass"));
        assert!(encoded.contains("a=sctp-port:5000"));
        assert!(encoded.contains("a=max-message-size:65536"));
        assert!(encoded.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(encoded.contains("a=ice-options:trickle"));
        assert!(!encoded.contains("a=candidate:"));

        let (parsed, candidates) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.session_id, local.session_id);
        assert_eq!(parsed.ice.ufrag, "abcd");
        assert_eq!(parsed.ice.pwd, "0123456789abcdef01234567");
        assert_eq!(parsed.dtls_role, DtlsRole::Server);
        assert_eq!(
            parsed.fingerprint,
            ("sha-256".to_string(), "AB:CD:EF".to_string())
        );
        assert_eq!(parsed.sctp_max_message_size, 65536);
        assert!(candidates.is_empty());
    }

    #[test]
    fn sdp_full_uses_the_default_candidate_and_keeps_trickle() {
        let local = description(DtlsRole::Server);
        let candidates = vec![host_candidate("192.0.2.1", 54321)];
        let encoded = local.encode_full(&candidates);
        assert!(encoded.contains("m=application 54321 UDP/DTLS/SCTP"));
        assert!(encoded.contains("c=IN IP4 192.0.2.1"));
        assert!(encoded.contains("a=ice-options:trickle"));
        assert!(!encoded.contains("a=end-of-candidates"));
        assert!(!encoded.contains("a=candidate:candidate:"));
    }

    #[test]
    fn sdp_default_candidate_prefers_ipv4_then_relay_without_using_ice_priority() {
        let candidates = [
            "candidate:1 1 udp 9999 2001:db8::1 1111 typ relay",
            "candidate:2 1 udp 9999 192.0.2.1 2222 typ host",
            "candidate:3 1 udp 1 192.0.2.2 3333 typ relay raddr 192.0.2.1 rport 2222",
            "candidate:4 1 udp 99999 192.0.2.3 4444 typ relay raddr 192.0.2.1 rport 2222",
            "candidate:5 2 udp 99999 192.0.2.4 5555 typ relay raddr 192.0.2.1 rport 2222",
        ]
        .map(|line| candidate::parse_ice_candidate(line).unwrap());
        let encoded = description(DtlsRole::Server).encode_full(&candidates);
        assert!(encoded.contains("m=application 3333 UDP/DTLS/SCTP"));
        assert!(encoded.contains("c=IN IP4 192.0.2.2"));
        let ipv6 = description(DtlsRole::Server).encode_full(&candidates[..1]);
        assert!(ipv6.contains("c=IN IP6 2001:db8::1"));
    }

    #[test]
    fn sdp_session_fingerprint_candidates_and_passive_setup_are_accepted() {
        let local = description(DtlsRole::Server);
        let encoded = local.encode_full(&[host_candidate("192.0.2.1", 54321)]);
        let mut before_media = String::new();
        let mut rest = String::new();
        for line in encoded.lines() {
            if line.starts_with("a=fingerprint:") || line.starts_with("a=candidate:") {
                before_media.push_str(&format!("{line}\r\n"));
            } else {
                rest.push_str(&format!("{line}\r\n"));
            }
        }
        let encoded = rest
            .replace("m=application", &format!("{before_media}m=application"))
            .replace("a=setup:actpass", "a=setup:passive");
        let (parsed, candidates) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.dtls_role, DtlsRole::Server);
        assert_eq!(parsed.fingerprint, local.fingerprint);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].address(), "192.0.2.1");
    }

    #[test]
    fn full_ice_embeds_candidates() {
        let candidates = vec![host_candidate("192.168.1.10", 54321)];
        let local = description(DtlsRole::Server);
        let encoded = local.encode_full(&candidates);
        assert_eq!(encoded, local.encode_full(&candidates));
        assert!(encoded.contains("o=- 42 2 IN IP4 127.0.0.1\r\n"));

        assert!(encoded.contains("a=candidate:"));
        assert!(encoded.contains("192.168.1.10"));
        assert!(!encoded.contains("a=end-of-candidates"));
        assert!(encoded.contains("a=ice-options:trickle"));

        let (_, parsed_candidates) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed_candidates.len(), 1);
        assert_eq!(parsed_candidates[0].address(), "192.168.1.10");
        assert_eq!(parsed_candidates[0].port(), 54321);
    }

    #[test]
    fn answer_is_parsed_as_client_role() {
        let encoded = description(DtlsRole::Auto).encode_trickle();
        assert!(encoded.contains("a=setup:active"));
        assert_eq!(
            Description::parse(&encoded).unwrap().0.dtls_role,
            DtlsRole::Client
        );
    }

    #[test]
    fn missing_attribute_is_rejected() {
        let encoded = description(DtlsRole::Server).encode_trickle();
        let without_fingerprint: String = encoded
            .lines()
            .filter(|line| !line.starts_with("a=fingerprint"))
            .map(|line| format!("{line}\r\n"))
            .collect();

        assert!(Description::parse(&without_fingerprint).is_err());
    }

    #[test]
    fn identity_attribute_is_session_level_and_roundtrips() {
        let mut with_identity = description(DtlsRole::Server);
        with_identity.identity = Some("opaque-identity-blob".to_string());

        let encoded = with_identity.encode_trickle();
        let identity_pos = encoded.find("a=identity:opaque-identity-blob").unwrap();
        let media_pos = encoded.find("m=application").unwrap();
        assert!(identity_pos < media_pos);

        let (parsed, _) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.identity.as_deref(), Some("opaque-identity-blob"));
    }

    #[test]
    fn missing_identity_parses_as_none() {
        let encoded = description(DtlsRole::Server).encode_trickle();
        let (parsed, _) = Description::parse(&encoded).unwrap();
        assert_eq!(parsed.identity, None);
    }
}
