//! Signaling messages in their `TYPE connection_id data` text form.
use crate::error::{ProtocolError, SignalErrorCode};
use std::fmt;
use std::str::FromStr;

/// Wire names are CONNECTREQUEST, CONNECTRESPONSE, CANDIDATEADD and CONNECTERROR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    Offer,
    Answer,
    Candidate,
    Error,
}

impl SignalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalType::Offer => "CONNECTREQUEST",
            SignalType::Answer => "CONNECTRESPONSE",
            SignalType::Candidate => "CANDIDATEADD",
            SignalType::Error => "CONNECTERROR",
        }
    }
}

impl FromStr for SignalType {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONNECTREQUEST" => Ok(SignalType::Offer),
            "CONNECTRESPONSE" => Ok(SignalType::Answer),
            "CANDIDATEADD" => Ok(SignalType::Candidate),
            "CONNECTERROR" => Ok(SignalType::Error),
            _ => Err(ProtocolError::Other(format!("Unknown signal type: {}", s))),
        }
    }
}

impl fmt::Display for SignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A signaling message; `network_id` is the remote peer's id and is not part of the text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub signal_type: SignalType,
    pub connection_id: u64,
    /// SDP for offers and answers, a candidate line, or a decimal error code.
    pub data: String,
    pub network_id: String,
}

impl Signal {
    pub fn new(
        signal_type: SignalType,
        connection_id: u64,
        data: String,
        network_id: String,
    ) -> Self {
        Self {
            signal_type,
            connection_id,
            data,
            network_id,
        }
    }

    pub fn offer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Offer, connection_id, sdp, network_id)
    }

    pub fn answer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Answer, connection_id, sdp, network_id)
    }

    pub fn candidate(connection_id: u64, candidate: String, network_id: String) -> Self {
        Self::new(SignalType::Candidate, connection_id, candidate, network_id)
    }

    pub fn error(connection_id: u64, error_code: SignalErrorCode, network_id: String) -> Self {
        Self::new(
            SignalType::Error,
            connection_id,
            (error_code as u32).to_string(),
            network_id,
        )
    }

    /// Parses `TYPE id data`, with `network_id` supplied by the caller.
    pub fn from_string(s: &str, network_id: String) -> Result<Self, ProtocolError> {
        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(ProtocolError::Other(format!(
                "Invalid signal format: expected 3 parts, got {}",
                parts.len()
            )));
        }

        let signal_type = SignalType::from_str(parts[0])?;
        let connection_id = decimal_prefix(parts[1], false)
            .parse::<u64>()
            .map_err(|e| ProtocolError::Other(format!("Failed to parse connection ID: {}", e)))?;
        if signal_type == SignalType::Error {
            parse_error_code(parts[2])?;
        }
        let data = parts[2].to_string();

        Ok(Self {
            signal_type,
            connection_id,
            data,
            network_id,
        })
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.signal_type.as_str(),
            self.connection_id,
            self.data
        )
    }
}

/// Parses a signed 32-bit decimal prefix without changing the original signal text.
///
/// # Errors
/// Rejects missing digits, leading whitespace or plus, and signed overflow.
pub fn parse_error_code(data: &str) -> Result<i32, ProtocolError> {
    decimal_prefix(data, true)
        .parse::<i32>()
        .map_err(|error| ProtocolError::Other(format!("Failed to parse error code: {error}")))
}

/// Reads an ASCII decimal prefix, allowing a leading minus only for signed fields.
fn decimal_prefix(value: &str, signed: bool) -> &str {
    let start = usize::from(signed && value.starts_with('-'));
    let digits = value.as_bytes()[start..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    &value[..start + digits]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_prefixes_preserve_the_original_data_and_reject_overflow() {
        for (text, id) in [
            ("CONNECTREQUEST 12tail data", 12),
            ("CONNECTERROR 0x10 -2147483648suffix", 0),
            ("CONNECTERROR 18446744073709551615 2147483647tail", u64::MAX),
        ] {
            let signal = Signal::from_string(text, "n".into()).unwrap();
            assert_eq!(signal.connection_id, id);
            assert_eq!(signal.data, text.splitn(3, ' ').nth(2).unwrap());
        }
        for text in [
            "CONNECTREQUEST +7 data",
            "CONNECTREQUEST -7 data",
            "CONNECTREQUEST 18446744073709551616tail data",
            "CONNECTERROR 1 abc",
            "CONNECTERROR 1 2147483648tail",
            "CONNECTERROR 1 -2147483649tail",
            "CONNECTERROR 1 +7",
            "CONNECTERROR 1 -",
            "CONNECTERROR 1  7",
            "CONNECTERROR 1 ",
            "CONNECTREQUEST é7 data",
        ] {
            assert!(Signal::from_string(text, "n".into()).is_err(), "{text:?}");
        }
    }
}
