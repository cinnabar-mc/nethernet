use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{NetherCodec, read_bytes_u32, write_bytes_u32};
use crate::protocol::constants::MAX_BYTES;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// A serialized signal addressed to one network id.
#[derive(Debug, Clone, Default)]
pub struct MessagePacket {
    pub recipient_id: u64,
    /// Opaque wire bytes; signaling interprets its text separately.
    pub data: Vec<u8>,
}

impl MessagePacket {
    /// Retains the supplied payload bytes without imposing a text encoding.
    pub fn new(recipient_id: u64, data: impl Into<Vec<u8>>) -> Self {
        Self {
            recipient_id,
            data: data.into(),
        }
    }
}

impl NetherCodec for MessagePacket {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u64::<LittleEndian>(self.recipient_id)?;
        write_bytes_u32(writer, &self.data)?;
        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let recipient_id = reader.read_u64::<LittleEndian>()?;
        let mut data_bytes = read_bytes_u32(reader)?;
        // The signal occupies the final field even when the peer understates its length.
        reader
            .take((MAX_BYTES + 1 - data_bytes.len()) as u64)
            .read_to_end(&mut data_bytes)?;
        if data_bytes.len() > MAX_BYTES {
            return Err(ProtocolError::MessageSizeExceeded(data_bytes.len()));
        }
        Ok(Self {
            recipient_id,
            data: data_bytes,
        })
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<u32>() + self.data.len()
    }
}
