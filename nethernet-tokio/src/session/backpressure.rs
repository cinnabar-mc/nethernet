//! Bounded reliable delivery that leaves transport timers and signaling independently pollable.
use super::PACKET_CHANNEL_CAPACITY;
use bytes::Bytes;
use nethernet::protocol::constants::MAX_MESSAGE_SIZE;
use std::collections::VecDeque;
use tokio::sync::mpsc::{Sender, error::TrySendError};

const MAX_PENDING_BYTES: usize = PACKET_CHANNEL_CAPACITY * MAX_MESSAGE_SIZE;

#[derive(Default)]
pub(super) struct ReliableBacklog {
    packets: VecDeque<Bytes>,
    bytes: usize,
}

impl ReliableBacklog {
    /// Sends immediately when possible; subsequent messages preserve FIFO while the receiver is full.
    pub fn deliver(&mut self, receiver: &Sender<Bytes>, packet: Bytes) -> Result<(), ()> {
        let packet = if self.packets.is_empty() {
            match receiver.try_send(packet) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(packet)) => packet,
                Err(TrySendError::Closed(_)) => return Err(()),
            }
        } else {
            packet
        };
        if receiver.is_closed()
            || self.packets.len() >= PACKET_CHANNEL_CAPACITY
            || packet.len() > MAX_PENDING_BYTES.saturating_sub(self.bytes)
        {
            return Err(());
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        Ok(())
    }

    /// Whether the driver needs to poll receiver capacity independently of transport input.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Transfers the oldest pending message once the receiver has granted capacity.
    pub fn pop(&mut self) -> Option<Bytes> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        Some(packet)
    }
}
