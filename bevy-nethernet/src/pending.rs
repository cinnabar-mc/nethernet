use nethernet::protocol::constants::{
    DEFAULT_MAX_PENDING, DEFAULT_MAX_PENDING_PER_NETWORK_ID, DEFAULT_PACKET_CHANNEL_CAPACITY,
    MAX_MESSAGE_SIZE,
};

#[derive(Clone, Copy, Debug)]
pub struct PendingLimits {
    /// Offers answered but not yet established; more are refused.
    pub max_pending: usize,
    /// The same cap for offers from one network id.
    pub max_pending_per_network_id: usize,
}

impl Default for PendingLimits {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            max_pending_per_network_id: DEFAULT_MAX_PENDING_PER_NETWORK_ID,
        }
    }
}

/// `pending` holds the network id of each unestablished session.
pub(crate) fn admits_offer<'a>(
    pending: impl IntoIterator<Item = &'a str>,
    network_id: &str,
    limits: PendingLimits,
) -> bool {
    let (total, from_network_id) = pending.into_iter().fold((0, 0), |(total, from), id| {
        (total + 1, from + usize::from(id == network_id))
    });
    total < limits.max_pending && from_network_id < limits.max_pending_per_network_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers_past_the_pending_limits_are_refused() {
        let limits = PendingLimits {
            max_pending: 3,
            max_pending_per_network_id: 2,
        };

        assert!(!admits_offer(["1", "1"], "1", limits));
        assert!(admits_offer(["1", "1"], "2", limits));
        assert!(!admits_offer(["1", "1", "2"], "3", limits));
    }
}

/// Host-wide capacity retained by a shared accepting pool and its public consumers.
/// Accepted payloads survive lowering these limits; new admission waits for available capacity.
#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    /// Negotiating or established sessions, including undrained lifecycle records.
    pub max_sessions: usize,
    /// Reliable and unreliable messages retained together until public receive consumes them.
    pub max_received_packets: usize,
    /// Combined retained payload bytes across all sessions and both channels.
    pub max_received_bytes: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_PENDING,
            max_received_packets: DEFAULT_PACKET_CHANNEL_CAPACITY,
            max_received_bytes: DEFAULT_PACKET_CHANNEL_CAPACITY * MAX_MESSAGE_SIZE,
        }
    }
}
