//! Data-channel message framing: segmentation and reassembly (guide section 6.1).
use crate::error::{ProtocolError, Result};
use crate::protocol::constants::DEFAULT_MAX_INCOMING_MESSAGE_BYTES;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// One data-channel payload: a count of segments still to come, then the bytes.
#[derive(Debug, Clone)]
pub struct MessageSegment {
    /// Zero on the final segment of a message.
    pub remaining_segments: u8,
    pub data: Bytes,
}

impl MessageSegment {
    pub fn new(remaining_segments: u8, data: Bytes) -> Self {
        Self {
            remaining_segments,
            data,
        }
    }

    #[inline]
    pub fn encode(&self) -> Bytes {
        encode_segment(self.remaining_segments, &self.data)
    }

    /// Fails below two bytes, so a segment with an empty body is invalid.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 2 {
            return Err(ProtocolError::MessageParse(format!(
                "Message too short, expected at least 2 bytes, got {}",
                data.len()
            )));
        }

        let remaining_segments = data[0];
        data.advance(1);
        Ok(Self {
            remaining_segments,
            data,
        })
    }
}

/// Reassembly buffer for one reliable message at a time.
#[derive(Debug, Clone)]
pub struct Message {
    expected_segments: u8,
    data: BytesMut,
    failed: bool,
    maximum: usize,
}

impl Message {
    pub fn new() -> Self {
        Self::with_maximum(DEFAULT_MAX_INCOMING_MESSAGE_BYTES)
    }

    /// Selects this allocation's complete-body bound without reserving payload storage.
    pub(crate) fn with_maximum(maximum: usize) -> Self {
        Self {
            expected_segments: 0,
            data: BytesMut::new(),
            failed: false,
            maximum,
        }
    }

    /// Shares the selected body bound with the unreliable channel's complete-message check.
    pub(crate) fn maximum(&self) -> usize {
        self.maximum
    }

    /// Returns the message on its final segment; a framing rejection permanently seals reassembly.
    pub fn add_segment(&mut self, segment: MessageSegment) -> Result<Option<Bytes>> {
        if self.failed {
            return Err(ProtocolError::MessageParse("reassembly has failed".into()));
        }
        if self.expected_segments == 0 && segment.remaining_segments > 0 {
            let Some(expected) = segment.remaining_segments.checked_add(1) else {
                return self.reject(ProtocolError::MessageParse(
                    "segment count out of range".to_string(),
                ));
            };
            self.expected_segments = expected;
        }

        if self.expected_segments > 0 {
            let expected_remaining = self.expected_segments - 1;
            if expected_remaining != segment.remaining_segments {
                return self.reject(ProtocolError::MessageParse(format!(
                    "Invalid segment sequence: expected {}, got {}",
                    expected_remaining, segment.remaining_segments
                )));
            }
            self.expected_segments -= 1;
        }

        let Some(size) = self.data.len().checked_add(segment.data.len()) else {
            return self.reject(ProtocolError::MessageSizeExceeded(usize::MAX));
        };
        if size > self.maximum {
            return self.reject(ProtocolError::MessageSizeExceeded(size));
        }

        if self.data.is_empty() && segment.remaining_segments == 0 {
            return Ok(Some(segment.data));
        }

        self.data.put(segment.data);

        if segment.remaining_segments == 0 {
            let data = self.data.split().freeze();
            self.expected_segments = 0;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Releases the incomplete message and refuses every later segment on this owner.
    fn reject(&mut self, error: ProtocolError) -> Result<Option<Bytes>> {
        self.failed = true;
        self.expected_segments = 0;
        self.data = BytesMut::new();
        Err(error)
    }

    /// Splits under the caller's segment-body limit, excluding the header, with at most 255 segments.
    #[inline]
    pub fn split_into_segments(
        mut data: Bytes,
        maximum_payload: usize,
    ) -> Result<Vec<MessageSegment>> {
        let count = segment_count(data.len(), maximum_payload)?;
        Ok((0..count)
            .rev()
            .map(move |remaining| {
                let length = data.len().min(maximum_payload);
                MessageSegment::new(remaining as u8, data.split_to(length))
            })
            .collect())
    }

    /// Encodes wire fragments directly from a borrowed body without temporary descriptors.
    #[inline]
    pub fn encode_segments(
        data: &[u8],
        maximum_payload: usize,
    ) -> Result<impl ExactSizeIterator<Item = Bytes> + '_> {
        let count = segment_count(data.len(), maximum_payload)?;
        Ok((0..count).map(move |index| {
            let start = index * maximum_payload;
            let end = start.saturating_add(maximum_payload).min(data.len());
            encode_segment((count - index - 1) as u8, &data[start..end])
        }))
    }

    /// Refuses empty bodies and bodies beyond the single-segment payload limit, excluding its header.
    pub fn encode_unreliable(data: Bytes, maximum_payload: usize) -> Result<Bytes> {
        if data.is_empty() {
            return Err(ProtocolError::MessageParse("message body is empty".into()));
        }
        if data.len() > maximum_payload {
            return Err(ProtocolError::MessageSizeExceeded(data.len()));
        }
        Ok(MessageSegment::new(0, data).encode())
    }
}

/// Checks the shared fragment-count policy before creating descriptors or copying wire bytes.
fn segment_count(length: usize, maximum_payload: usize) -> Result<usize> {
    if length == 0 {
        return Err(ProtocolError::MessageParse("message body is empty".into()));
    }
    let count = if length <= maximum_payload {
        1
    } else if maximum_payload == 0 {
        return Err(ProtocolError::MessageSizeExceeded(length));
    } else {
        length.div_ceil(maximum_payload)
    };
    if count > usize::from(u8::MAX) {
        return Err(ProtocolError::MessageSizeExceeded(length));
    }
    Ok(count)
}

/// Copies a count byte and its body into one exactly sized wire allocation.
#[inline]
fn encode_segment(remaining: u8, data: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(1 + data.len());
    bytes.push(remaining);
    bytes.extend_from_slice(data);
    Bytes::from(bytes)
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEGMENT_PAYLOAD_BYTES: usize = 10_000;

    /// A selected limit reserves no space and a rejected partial message cannot reopen on its suffix.
    #[test]
    fn configured_incoming_limit_is_checked_before_append_and_permanently_seals_overflow() {
        let mut message = Message::with_maximum(3 * 1024 * 1024);
        assert_eq!(message.data.capacity(), 0);
        message
            .add_segment(MessageSegment::new(254, Bytes::from_static(b"a")))
            .unwrap();
        assert!(message.data.capacity() < SEGMENT_PAYLOAD_BYTES);
        let mut message = Message::with_maximum(2);
        assert!(
            message
                .add_segment(MessageSegment::new(1, Bytes::from_static(b"ab")))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            message.add_segment(MessageSegment::new(0, Bytes::from_static(b"c"))),
            Err(ProtocolError::MessageSizeExceeded(3))
        ));
        assert_eq!(message.data.capacity(), 0);
        assert!(
            message
                .add_segment(MessageSegment::new(0, Bytes::from_static(b"d")))
                .is_err()
        );
        let mut zero = Message::with_maximum(0);
        assert!(matches!(
            zero.add_segment(MessageSegment::new(0, Bytes::from_static(b"a"))),
            Err(ProtocolError::MessageSizeExceeded(1))
        ));
        assert_eq!(zero.data.capacity(), 0);
    }

    #[test]
    fn encoded_segments_preserve_boundaries_and_validate_before_encoding() {
        let wire: Vec<_> = Message::encode_segments(b"abcde", 2).unwrap().collect();
        assert_eq!(wire, [b"\x02ab".as_slice(), b"\x01cd", b"\x00e"]);
        assert!(Message::encode_segments(b"", 0).is_err());
        assert!(Message::encode_segments(b"x", 0).is_err());
        assert!(Message::encode_segments(&[0; 256], 1).is_err());
    }

    #[test]
    fn explicit_zero_fragment_capacity_refuses_nonempty_bodies_without_panicking() {
        let body = Bytes::from_static(b"nonempty");
        assert!(
            matches!(Message::split_into_segments(body.clone(), 0), Err(ProtocolError::MessageSizeExceeded(size)) if size == body.len())
        );
        assert!(
            matches!(Message::encode_unreliable(body.clone(), 0), Err(ProtocolError::MessageSizeExceeded(size)) if size == body.len())
        );
    }

    #[test]
    fn test_single_segment() {
        let data = Bytes::from("Hello, World!");
        let segments = Message::split_into_segments(data.clone(), SEGMENT_PAYLOAD_BYTES).unwrap();

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].remaining_segments, 0);
        assert_eq!(segments[0].data, data);
    }

    #[test]
    fn test_multiple_segments() {
        let data = Bytes::from(vec![0u8; SEGMENT_PAYLOAD_BYTES * 2 + 100]);
        let segments = Message::split_into_segments(data.clone(), SEGMENT_PAYLOAD_BYTES).unwrap();

        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].remaining_segments, 2);
        assert_eq!(segments[1].remaining_segments, 1);
        assert_eq!(segments[2].remaining_segments, 0);
    }

    #[test]
    fn test_reassembly() {
        let original_data = Bytes::from(vec![1u8; SEGMENT_PAYLOAD_BYTES * 2 + 100]);
        let segments =
            Message::split_into_segments(original_data.clone(), SEGMENT_PAYLOAD_BYTES).unwrap();

        let mut message = Message::new();
        for (i, segment) in segments.iter().enumerate() {
            let result = message.add_segment(segment.clone()).unwrap();
            if i < segments.len() - 1 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
                assert_eq!(result.unwrap(), original_data);
            }
        }
    }

    #[test]
    fn test_out_of_order_segments_error() {
        let data = Bytes::from(vec![42u8; SEGMENT_PAYLOAD_BYTES * 2 + 100]);
        let segments = Message::split_into_segments(data.clone(), SEGMENT_PAYLOAD_BYTES).unwrap();
        assert!(segments.len() >= 3);

        let mut message = Message::new();

        let result = message.add_segment(segments[1].clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let result = message.add_segment(segments[0].clone());
        assert!(result.is_err());

        if let Err(ProtocolError::MessageParse(msg)) = result {
            assert!(msg.contains("Invalid segment sequence"));
        } else {
            panic!("Expected MessageParse error for out-of-order segment");
        }
    }

    #[test]
    fn test_max_remaining_segments_rejected_instead_of_overflowing() {
        let segment = MessageSegment::new(u8::MAX, Bytes::from_static(b"x"));
        let mut message = Message::new();
        assert!(message.add_segment(segment).is_err());
    }

    #[test]
    fn first_segment_does_not_reserve_from_the_peer_count() {
        let mut message = Message::new();
        message
            .add_segment(MessageSegment::new(254, Bytes::from_static(b"a")))
            .unwrap();
        assert!(message.data.capacity() < SEGMENT_PAYLOAD_BYTES);
    }

    #[test]
    fn reassembly_past_the_total_cap_is_refused() {
        let mut message = Message::with_maximum(2_560_000);
        let big = Bytes::from(vec![0u8; 1 << 20]);
        let results: Vec<_> = (0..3u8)
            .map(|i| message.add_segment(MessageSegment::new(254 - i, big.clone())))
            .collect();
        assert!(matches!(
            results.last(),
            Some(Err(ProtocolError::MessageSizeExceeded(_)))
        ));
        assert!(message.data.is_empty());
    }

    /// A rejected logical message cannot reopen on a later valid-looking suffix.
    #[test]
    fn framing_rejection_permanently_seals_reassembly() {
        let mut message = Message::new();
        assert!(
            message
                .add_segment(MessageSegment::new(2, Bytes::from_static(b"prefix")))
                .unwrap()
                .is_none()
        );
        let rejected = message.add_segment(MessageSegment::new(0, Bytes::from_static(b"gap")));
        assert!(rejected.is_err());
        let successor = message.add_segment(MessageSegment::new(0, Bytes::from_static(b"tail")));
        assert!(
            successor.is_err(),
            "a framing rejection reopened and delivered its suffix"
        );
    }
}
