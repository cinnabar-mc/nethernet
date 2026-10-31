//! Error types for the transport and signaling layers.
use nethernet::admission::AdmissionError;
use nethernet::error::ProtocolError;
use nethernet::identity::error::IdentityError;
use nethernet::signaling::http::join::StatusResponseError;
use std::io;
use thiserror::Error;

pub use nethernet::error::SignalErrorCode;

#[derive(Debug, Error)]
pub enum NetherError {
    /// A caller-driven signaling bridge failed without retaining service diagnostics.
    #[error("caller signaling error: {0}")]
    CallerSignaling(#[from] crate::signaling::caller::CallerSignalingError),

    /// The caller explicitly cancelled connection setup.
    #[error("connection setup cancelled")]
    Cancelled,

    /// The original HTTP request failure, retained for timeout and source inspection.
    #[error("HTTP signaling request failed")]
    Http(#[from] reqwest::Error),

    #[error("ICE error: {0}")]
    Ice(String),

    #[error("DTLS error: {0}")]
    Dtls(String),

    #[error("SCTP error: {0}")]
    Sctp(String),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    /// The HTTP server has neither an identity nor allow_unsigned_answers (guide section 5.2).
    #[error("HTTP signaling requires a server identity")]
    IdentityRequired,

    #[error("Admission error: {0}")]
    Admission(#[from] AdmissionError),

    #[error("Signaling error: {0}")]
    Signaling(#[from] SignalingError),

    #[error("Status error: {0}")]
    Status(#[from] StatusResponseError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    /// Reliable receive admission exceeded its packet or byte budget; accepted data is delivered first.
    #[error("accepted receive capacity exceeded")]
    ReceiveCapacity,

    #[error("Pending offers from {0} exceed the limit")]
    PendingCountExceeded(String),

    #[error("Data channel error: {0}")]
    DataChannel(String),

    #[error("Message parse error: {0}")]
    MessageParse(String),

    #[error("Message of {0} bytes exceeds the size limit")]
    MessageSizeExceeded(usize),

    #[error("Operation timed out")]
    Timeout,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// The remote refused the connection with a signaling error code.
    #[error("connection failed with code {0:?}")]
    Signaled(SignalErrorCode),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum SignalingError {
    #[error("Failed to send signal: {0}")]
    SendFailed(String),

    #[error("Failed to receive signal: {0}")]
    ReceiveFailed(String),

    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    #[error("Signaling stopped")]
    Stopped,

    #[error("Network ID not found: {0}")]
    NetworkIdNotFound(u64),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, NetherError>;

impl NetherError {
    /// Identifies explicit setup cancellation without inspecting diagnostic text.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Preserves deadline classification through HTTP and socket failure sources.
    pub fn is_timeout(&self) -> bool {
        if matches!(
            self,
            Self::Timeout | Self::CallerSignaling(crate::CallerSignalingError::TimedOut)
        ) {
            return true;
        }
        let mut cause = std::error::Error::source(self);
        while let Some(error) = cause {
            if error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
                || error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
            {
                return true;
            }
            cause = error.source();
        }
        false
    }
}
