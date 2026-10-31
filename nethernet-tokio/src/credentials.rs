//! TURN credentials in the JSON form returned by the signaling service.
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    /// Lifetime of the credentials in seconds.
    #[serde(rename = "ExpirationInSeconds")]
    pub expiration_in_seconds: i32,

    #[serde(rename = "TurnAuthServers")]
    pub ice_servers: Vec<IceServer>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct IceServer {
    #[serde(rename = "Username", default)]
    pub username: String,

    #[serde(rename = "Password", default)]
    pub password: String,

    #[serde(rename = "Urls")]
    pub urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STUN needs no authentication, while TURN still requires both credentials at resolution.
    #[tokio::test]
    async fn omitted_authentication_fields_are_valid_only_for_stun() {
        use std::time::Duration;
        for scheme in ["stun", "turn"] {
            let credentials: Credentials = serde_json::from_str(&format!(r#"{{"ExpirationInSeconds":86400,"TurnAuthServers":[{{"Urls":["{scheme}:127.0.0.1:3478"]}}]}}"#)).unwrap();
            let now = tokio::time::Instant::now().into_std();
            let resolved = crate::ice::resolve_ice_servers(
                &credentials.ice_servers,
                "127.0.0.1:0".parse().unwrap(),
                now + Duration::from_secs(30),
                now + Duration::from_secs(5),
            )
            .await;
            assert_eq!(resolved.is_ok(), scheme == "stun");
        }
    }

    #[test]
    fn credentials_decode_from_signaling_json() {
        let json = r#"{"ExpirationInSeconds":86400,"TurnAuthServers":[{"Username":"user","Password":"secret","Urls":["turn:127.0.0.1:3478"]}]}"#;
        let credentials: Credentials = serde_json::from_str(json).unwrap();

        assert_eq!(credentials.expiration_in_seconds, 86400);
        assert_eq!(credentials.ice_servers[0].urls.len(), 1);
    }
}
