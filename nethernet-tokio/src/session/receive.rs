//! One bounded accepted-message owner retained through transport retirement by its receiver.
use super::{Channel, PACKET_CHANNEL_CAPACITY};
use crate::error::{NetherError, Result};
use bytes::Bytes;
use nethernet::protocol::constants::DEFAULT_MAX_RECEIVED_BYTES;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

pub(super) const MAX_ACCEPTED_BYTES: usize = DEFAULT_MAX_RECEIVED_BYTES;
pub(super) const RELIABLE_PACKET_CAPACITY: usize = PACKET_CHANNEL_CAPACITY * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdmissionError {
    Full,
    Closed,
}

#[derive(Clone, Copy)]
pub(super) enum Terminal {
    Eof,
    Transport,
    Capacity,
}

struct State {
    packets: VecDeque<Bytes>,
    bytes: usize,
    capacity: usize,
    receiver_alive: bool,
    terminal: Option<Terminal>,
    waker: Option<Waker>,
}

pub(super) struct Producer(Arc<Mutex<State>>);
pub(super) struct Receiver(Arc<Mutex<State>>);

/// Reliable admission keeps the previous combined packet budget in one queue; unreliable stays best effort.
pub(super) fn channel(channel: Channel) -> (Producer, Receiver) {
    let capacity = match channel {
        Channel::Reliable => RELIABLE_PACKET_CAPACITY,
        Channel::Unreliable => PACKET_CHANNEL_CAPACITY,
    };
    let state = Arc::new(Mutex::new(State {
        packets: VecDeque::new(),
        bytes: 0,
        capacity,
        receiver_alive: true,
        terminal: None,
        waker: None,
    }));
    (Producer(state.clone()), Receiver(state))
}

impl Producer {
    /// Admits a validated body within the aggregate budget, or alone when larger.
    /// Transport work never waits for application consumption.
    pub fn push(&self, packet: Bytes) -> std::result::Result<(), AdmissionError> {
        let wake = {
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            if !state.receiver_alive || state.terminal.is_some() {
                return Err(AdmissionError::Closed);
            }
            let Some(bytes) = state.bytes.checked_add(packet.len()) else {
                return Err(AdmissionError::Full);
            };
            if state.packets.len() >= state.capacity
                || (!state.packets.is_empty() && bytes > MAX_ACCEPTED_BYTES)
            {
                return Err(AdmissionError::Full);
            }
            state.bytes = bytes;
            state.packets.push_back(packet);
            state.waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
        Ok(())
    }

    /// Seals admission once while leaving the accepted FIFO owned by its receiver.
    pub fn finish(&self, terminal: Terminal) {
        let wake = {
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            if state.terminal.is_none() {
                state.terminal = Some(terminal);
            }
            state.waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        // Aborting or unwinding a driver cannot report a successful, silently truncated EOF.
        self.finish(Terminal::Transport);
    }
}

impl Receiver {
    /// Drains accepted data before one explicit terminal error or ordinary EOF.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(packet) = state.packets.pop_front() {
            state.bytes -= packet.len();
            return Poll::Ready(Ok(Some(packet)));
        }
        if let Some(terminal) = state.terminal {
            state.terminal = Some(Terminal::Eof);
            return Poll::Ready(match terminal {
                Terminal::Eof => Ok(None),
                Terminal::Transport => Err(NetherError::ConnectionClosed),
                Terminal::Capacity => Err(NetherError::ReceiveCapacity),
            });
        }
        if state
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            state.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .packets
            .len()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.receiver_alive = false;
        state.packets.clear();
        state.bytes = 0;
        state.waker = None;
    }
}

#[cfg(test)]
mod tests;
