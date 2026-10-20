//! Sending through the original active SCTP association's installed size authority.

use super::{
    Channel, Established, Framing, GatheringState, IceError, Phase, ProtocolError, Session,
};
use rtc::sctp::PayloadProtocolIdentifier;
use std::time::Instant;

impl Channel {
    /// Derives addressable logical capacity from one installed segment-body limit.
    const fn message_capacity(self, segment_payload: usize) -> usize {
        match self {
            Self::Reliable => segment_payload.saturating_mul(u8::MAX as usize),
            Self::Unreliable => segment_payload,
        }
    }
}

impl<S: Phase> Session<S> {
    /// Ignores later SDP changes that did not reconfigure the original association.
    fn segment_payload_size(&self) -> Option<usize> {
        if self.channels.terminal_emitted {
            return None;
        }
        self.sctp
            .as_ref()?
            .max_message_size()?
            .checked_sub(1)
            .map(|size| size as usize)
    }

    fn send_message(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if data.is_empty() {
            return Ok(());
        }
        let stream_id = self
            .channels
            .stream_id(channel)
            .ok_or_else(|| ProtocolError::Other("channel not open yet".to_string()))?;

        let segment_payload = self
            .segment_payload_size()
            .ok_or_else(|| ProtocolError::Other("transports not started".to_string()))?;
        if data.len() > channel.message_capacity(segment_payload) {
            return Err(ProtocolError::MessageSizeExceeded(data.len()));
        }

        let sctp = self
            .sctp
            .as_mut()
            .ok_or_else(|| ProtocolError::Other("transports not started".to_string()))?;
        let assoc = sctp
            .association_mut()
            .ok_or_else(|| ProtocolError::Other("association not established".to_string()))?;
        let mut stream = assoc
            .stream(stream_id)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        match channel {
            Channel::Reliable => {
                for segment in Framing::split_into_segments(data, segment_payload)? {
                    stream
                        .write_with_ppi(now, &segment.encode(), PayloadProtocolIdentifier::Binary)
                        .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                }
            }
            Channel::Unreliable => {
                let encoded = Framing::encode_unreliable(data, segment_payload)?;
                stream
                    .write_with_ppi(now, &encoded, PayloadProtocolIdentifier::Binary)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
            }
        }

        Ok(())
    }
}

impl Session<Established> {
    /// Maximum logical outgoing body recorded at actual readiness, excluding framing.
    /// These immutable facts survive remote retirement for delayed readiness/output handoff.
    /// They do not establish liveness; sending still checks expiry and the active transport.
    pub fn max_message_size(&self, channel: Channel) -> Option<usize> {
        self.channels
            .ready_segment_payload
            .map(|maximum| channel.message_capacity(maximum))
    }

    /// Admits data only on actual readiness; empty payloads are successful no-ops.
    pub fn send(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.expire_before_input(now)?;
        if self.ice.gathering_state() == GatheringState::Closed {
            return Err(IceError::Closed.into());
        }
        self.send_message(channel, data, now)?;
        self.pump(now)
    }
}
