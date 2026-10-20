//! The accepting pool's single final payload and lifecycle owner.
use super::{PoolEvent, PoolUpdate, Readiness};
use crate::pending::ServerLimits;
use nethernet::session::Channel;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

struct Entry<K> {
    id: K,
    readiness: Readiness,
    ready: bool,
    message_maxima: [usize; 2],
    terminal: bool,
    owner_finished: bool,
    notifications: usize,
    unpublished: usize,
    rtt: Option<Duration>,
    rtt_changed: bool,
}

struct Lifecycle<K> {
    event: PoolEvent<K>,
    visible: bool,
}

struct Payload<K> {
    id: K,
    readiness: Readiness,
    bytes: Box<[u8]>,
    visible: bool,
    ordinal: u64,
}

/// Metadata slots are reserved with each entry; payloads remain charged until public receive.
pub(super) struct Delivery<K> {
    limits: ServerLimits,
    entries: Vec<Entry<K>>,
    lifecycle: VecDeque<Lifecycle<K>>,
    reliable: VecDeque<Payload<K>>,
    unreliable: VecDeque<Payload<K>>,
    packets: usize,
    bytes: usize,
    // Admission order only; reset after both original payload queues drain.
    next_payload: u64,
}

impl<K: Clone + Eq> Delivery<K> {
    pub(super) fn new() -> Self {
        Self {
            limits: ServerLimits::default(),
            entries: Vec::new(),
            lifecycle: VecDeque::new(),
            reliable: VecDeque::new(),
            unreliable: VecDeque::new(),
            packets: 0,
            bytes: 0,
            next_payload: 0,
        }
    }

    /// Reconfiguration never drops already accepted payloads or mandatory lifecycle outcomes.
    pub(super) fn set_limits(&mut self, limits: ServerLimits) {
        self.limits = limits;
    }

    /// Rejects unavailable host-wide capacity before constructing an answer allocation.
    pub(super) fn admits(&self, id: &K) -> bool {
        self.entries.len() < self.limits.max_sessions
            && self.packets < self.limits.max_received_packets
            && self.bytes < self.limits.max_received_bytes
            && !self
                .entries
                .iter()
                .any(|entry| entry.id == *id && !entry.terminal)
    }

    /// Reserves one actual allocation and its two mandatory lifecycle slots before queueing Add.
    pub(super) fn reserve(&mut self, id: K) -> Option<Readiness> {
        if !self.admits(&id) {
            return None;
        }
        let readiness = Readiness::new();
        self.entries.push(Entry {
            id,
            readiness: readiness.clone(),
            ready: false,
            message_maxima: [0; 2],
            terminal: false,
            owner_finished: false,
            notifications: 0,
            unpublished: 0,
            rtt: None,
            rtt_changed: false,
        });
        Some(readiness)
    }

    /// Only the original nonretired allocation can admit another command.
    pub(super) fn contains(&self, id: &K, readiness: &Readiness) -> bool {
        !readiness.is_retired()
            && self.entries.iter().any(|entry| {
                entry.id == *id && entry.readiness.matches(readiness) && !entry.terminal
            })
    }

    /// Returns installed outgoing limits only for this exact live, actually ready allocation.
    pub(super) fn max_message_size(
        &self,
        id: &K,
        readiness: &Readiness,
        channel: Channel,
    ) -> Option<usize> {
        if !self.contains(id, readiness) {
            return None;
        }
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.id == *id && entry.readiness.matches(readiness) && entry.ready)?;
        Some(match channel {
            Channel::Reliable => entry.message_maxima[0],
            Channel::Unreliable => entry.message_maxima[1],
        })
    }

    /// Internal signaling resolves only the original currently admitted allocation.
    pub(super) fn readiness(&self, id: &K) -> Option<Readiness> {
        self.entries
            .iter()
            .find(|entry| entry.id == *id && !entry.readiness.is_retired())
            .map(|entry| entry.readiness.clone())
    }

    /// An Add that never acknowledged ownership has no public lifecycle to publish.
    pub(super) fn abandon(&mut self, readiness: &Readiness) {
        readiness.retire();
        self.entries
            .retain(|entry| !entry.readiness.matches(readiness));
        self.lifecycle
            .retain(|record| !record.event.readiness.matches(readiness));
    }

    /// Actual core Ready reserves a single notification; repetition cannot grow the owner.
    pub(super) fn ready(
        &mut self,
        readiness: &Readiness,
        address: Option<SocketAddr>,
        message_maxima: [usize; 2],
    ) {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(readiness))
        else {
            return;
        };
        if entry.ready || entry.terminal || readiness.is_retired() {
            return;
        }
        entry.ready = true;
        entry.message_maxima = message_maxima;
        entry.notifications += 1;
        self.lifecycle.push_back(Lifecycle {
            event: PoolEvent {
                id: entry.id.clone(),
                event: PoolUpdate::Ready(address),
                readiness: readiness.clone(),
            },
            visible: false,
        });
    }

    /// Latest-only RTT is independent of stalled application event consumption.
    pub(super) fn rtt(&mut self, readiness: &Readiness, rtt: Duration) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(readiness))
            && !entry.terminal
        {
            entry.rtt = Some(rtt);
            entry.rtt_changed = true;
        }
    }

    /// Rejects only the first unaccepted payload when the host-wide count or byte bound fills.
    pub(super) fn message(
        &mut self,
        readiness: &Readiness,
        channel: Channel,
        bytes: Box<[u8]>,
    ) -> bool {
        if readiness.is_retired() {
            return false;
        }
        self.enqueue_message(readiness, channel, bytes)
    }

    /// Retains only already accepted output from the exact original core while its worker retires it.
    pub(super) fn retained_message(
        &mut self,
        readiness: &Readiness,
        channel: Channel,
        bytes: Box<[u8]>,
    ) -> bool {
        if !readiness.is_retired() {
            return false;
        }
        self.enqueue_message(readiness, channel, bytes)
    }

    /// Both original live output and its retirement prefix use this single final charge and order.
    fn enqueue_message(
        &mut self,
        readiness: &Readiness,
        channel: Channel,
        bytes: Box<[u8]>,
    ) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(readiness))
        else {
            return false;
        };
        let Some(total_bytes) = self.bytes.checked_add(bytes.len()) else {
            return false;
        };
        if entry.owner_finished
            || self.packets >= self.limits.max_received_packets
            || total_bytes > self.limits.max_received_bytes
        {
            return false;
        }
        let Some(next_payload) = self.next_payload.checked_add(1) else {
            return false;
        };
        let payload = Payload {
            id: entry.id.clone(),
            readiness: readiness.clone(),
            bytes,
            visible: false,
            ordinal: self.next_payload,
        };
        self.next_payload = next_payload;
        entry.unpublished += 1;
        self.packets += 1;
        self.bytes = total_bytes;
        match channel {
            Channel::Reliable => self.reliable.push_back(payload),
            Channel::Unreliable => self.unreliable.push_back(payload),
        }
        true
    }

    /// Seals new effects synchronously, reserving one terminal behind the original Ready.
    pub(super) fn retire(&mut self, readiness: &Readiness) {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(readiness))
        else {
            return;
        };
        readiness.retire();
        if entry.terminal {
            return;
        }
        entry.terminal = true;
        entry.rtt_changed = false;
        entry.notifications += 1;
        self.lifecycle.push_back(Lifecycle {
            event: PoolEvent {
                id: entry.id.clone(),
                event: PoolUpdate::Failed,
                readiness: readiness.clone(),
            },
            visible: false,
        });
    }

    /// Capacity is released only after the actual core/router owner and public lifecycle retire.
    pub(super) fn owner_finished(&mut self, readiness: &Readiness) {
        self.retire(readiness);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(readiness))
        {
            entry.owner_finished = true;
        }
        self.reap();
    }

    /// Pool drop seals admitted work before the original worker observes command closure.
    pub(super) fn seal_all(&mut self) {
        let readiness: Vec<_> = self
            .entries
            .iter()
            .map(|entry| entry.readiness.clone())
            .collect();
        for readiness in readiness {
            self.retire(&readiness);
        }
    }

    /// Worker exit also seals every admitted entry; no raw channel closure hides terminal state.
    pub(super) fn finish_all(&mut self) {
        let readiness: Vec<_> = self
            .entries
            .iter()
            .map(|entry| entry.readiness.clone())
            .collect();
        for readiness in readiness {
            self.owner_finished(&readiness);
        }
    }

    /// Prioritizes already eligible mandatory records without overtaking their own accepted prefix.
    fn advance_lifecycle(&mut self, output: &mut Vec<PoolEvent<K>>, budget: &mut usize) {
        for record in &mut self.lifecycle {
            if record.visible {
                continue;
            }
            if *budget == 0 {
                return;
            }
            let eligible = match record.event.event {
                PoolUpdate::Ready(_) => true,
                PoolUpdate::Failed => self.entries.iter().any(|entry| {
                    entry.readiness.matches(&record.event.readiness)
                        && entry.owner_finished
                        && entry.unpublished == 0
                }),
                PoolUpdate::Rtt(_) => false,
            };
            if eligible {
                record.visible = true;
                *budget -= 1;
                output.push(PoolEvent {
                    id: record.event.id.clone(),
                    event: record.event.event,
                    readiness: record.event.readiness.clone(),
                });
            }
        }
    }

    /// Publishes finite original outcomes; mandatory records and both channels retain progress.
    pub(super) fn advance(&mut self, output: &mut Vec<PoolEvent<K>>, mut budget: usize) {
        self.advance_lifecycle(output, &mut budget);
        if budget == 0 {
            return;
        }
        {
            let mut reliable = self
                .reliable
                .iter_mut()
                .filter(|payload| !payload.visible)
                .peekable();
            let mut unreliable = self
                .unreliable
                .iter_mut()
                .filter(|payload| !payload.visible)
                .peekable();
            while budget != 0 {
                let from_reliable = match (reliable.peek(), unreliable.peek()) {
                    (Some(first), Some(second)) => first.ordinal < second.ordinal,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => break,
                };
                let payload = if from_reliable {
                    reliable.next()
                } else {
                    unreliable.next()
                }
                .expect("original unexposed payload observed");
                payload.visible = true;
                budget -= 1;
                if let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.readiness.matches(&payload.readiness))
                {
                    entry.unpublished -= 1;
                }
            }
        }
        self.advance_lifecycle(output, &mut budget);
        for entry in &mut self.entries {
            if budget == 0 {
                return;
            }
            if entry.rtt_changed {
                entry.rtt_changed = false;
                budget -= 1;
                if let Some(rtt) = entry.rtt {
                    output.push(PoolEvent {
                        id: entry.id.clone(),
                        event: PoolUpdate::Rtt(rtt),
                        readiness: entry.readiness.clone(),
                    });
                }
            }
        }
    }

    /// Public event consumption removes the original record, never a duplicate event queue.
    pub(super) fn next_event(&mut self) -> Option<PoolEvent<K>> {
        if !self.lifecycle.front()?.visible {
            return None;
        }
        let record = self.lifecycle.pop_front()?;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.readiness.matches(&record.event.readiness))
        {
            entry.notifications -= 1;
        }
        self.reap();
        Some(record.event)
    }

    /// Reads the actual final-owner charge without consuming a payload in the socket fixture.
    #[cfg(test)]
    pub(super) fn retained_packets(&self) -> usize {
        self.packets
    }

    /// Observes original core retirement while its terminal record remains unconsumed.
    #[cfg(test)]
    pub(super) fn owner_has_finished(&self, readiness: &Readiness) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.readiness.matches(readiness) && entry.owner_finished)
    }

    /// Public receive releases the original global charge and returns the original payload allocation.
    pub(super) fn recv(&mut self, channel: Channel) -> Option<(K, Box<[u8]>)> {
        let queue = match channel {
            Channel::Reliable => &mut self.reliable,
            Channel::Unreliable => &mut self.unreliable,
        };
        if !queue.front()?.visible {
            return None;
        }
        let payload = queue.pop_front()?;
        self.packets -= 1;
        self.bytes -= payload.bytes.len();
        if self.reliable.is_empty() && self.unreliable.is_empty() {
            self.next_payload = 0;
        }
        Some((payload.id, payload.bytes))
    }

    /// Caller-held stale capabilities retain no admission slot or delivery storage.
    fn reap(&mut self) {
        self.entries
            .retain(|entry| !(entry.owner_finished && entry.notifications == 0));
    }
}

#[cfg(test)]
mod retained_tests;
#[cfg(test)]
mod retirement_tests;
#[cfg(test)]
mod tests;
