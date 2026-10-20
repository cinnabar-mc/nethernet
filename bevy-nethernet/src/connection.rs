#[cfg(test)]
mod admission_tests;
mod delivery;
mod pool;
pub(crate) use pool::SessionPool;

use nethernet::connection::{Connection, ConnectionInput};
use nethernet::error::ProtocolError;
use nethernet::phase::{Connecting, Established};
use nethernet::protocol::Signal;
use nethernet::sans::Sans;
use nethernet::session::{Channel, SessionEvent, SessionOutput};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::time::{Duration, Instant};

pub(crate) enum ConnectionEvent {
    Ready(Option<SocketAddr>),
    Rtt(Duration),
    Message(Channel, Box<[u8]>),
    Failed,
}

#[repr(u8)]
enum Admission {
    Pending,
    Admitted,
    Retired,
}

/// Identity and worker admission of one allocation; only actual Ready grants public send authority.
#[derive(Clone, Debug)]
pub(crate) struct Readiness(Arc<AtomicU8>);

impl Readiness {
    /// Creates the identity of this concrete pool allocation before its original Add acknowledgement.
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU8::new(Admission::Pending as u8)))
    }

    /// Matches an original entry, so reused peer ids and other pools cannot accept stale sends.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Acknowledges installation by the original worker without reviving a retired allocation.
    fn admit(&self) -> bool {
        self.0
            .compare_exchange(
                Admission::Pending as u8,
                Admission::Admitted as u8,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Permits answer publication only after the same worker installed this allocation.
    pub(crate) fn is_admitted(&self) -> bool {
        self.0.load(Ordering::Acquire) == Admission::Admitted as u8
    }

    /// Seals this exact allocation without waiting for command queue capacity.
    pub(crate) fn retire(&self) {
        self.0.store(Admission::Retired as u8, Ordering::Release);
    }

    /// A retired entry never acquires authority again, even if its descriptive id is reused.
    pub(crate) fn is_retired(&self) -> bool {
        self.0.load(Ordering::Acquire) == Admission::Retired as u8
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PoolUpdate {
    Ready(Option<SocketAddr>),
    Rtt(Duration),
    Failed,
}

pub(crate) struct PoolEvent<K> {
    pub id: K,
    pub event: PoolUpdate,
    pub readiness: Readiness,
}

/// The frame edge owns the actual typed core as readiness arrives asynchronously.
pub(crate) enum ActiveConnection {
    Connecting(Option<Connection<Connecting>>),
    Established(Connection<Established>),
}

impl ActiveConnection {
    /// Reads only the original phase owner's retained output, before the frame admits more work.
    pub(crate) fn pending_output_usage(&self) -> nethernet::session::OutputUsage {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .pending_output_usage(),
            Self::Established(core) => core.pending_output_usage(),
        }
    }

    /// Adopts the original pending allocation without creating another transport.
    pub(crate) fn new(core: Connection<Connecting>) -> Self {
        Self::Connecting(Some(core))
    }

    /// Applies control input to the actual currently owned phase.
    pub(crate) fn handle(&mut self, input: ConnectionInput) -> Result<(), ProtocolError> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .handle(input),
            Self::Established(core) => core.handle(input),
        }
    }

    /// Converts only the same core's actual Ready outcome, preserving the original queue.
    pub(crate) fn poll(&mut self) -> Option<SessionOutput> {
        let output = match self {
            Self::Connecting(core) => core.as_mut().expect("pending core remains owned").poll(),
            Self::Established(core) => core.poll(),
        };
        if matches!(output, Some(SessionOutput::Event(SessionEvent::Ready)))
            && let Self::Connecting(core) = self
        {
            let pending = core.take().expect("pending core transfers once");
            *self = match pending.try_establish() {
                Ok(core) => Self::Established(core),
                Err(core) => {
                    *self = Self::Connecting(Some(core));
                    return Some(SessionOutput::Event(SessionEvent::Failed));
                }
            };
        }
        output
    }

    /// Reads the exact core's immutable readiness facts, including after remote retirement.
    pub(crate) fn max_message_size(&self, channel: Channel) -> Option<usize> {
        match self {
            Self::Connecting(_) => None,
            Self::Established(core) => core.max_message_size(channel),
        }
    }

    /// Dispatches only to the actual established core; pending state has no send method.
    pub(crate) fn send(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Established(core) => core.send(channel, data, now),
            Self::Connecting(_) => Err(ProtocolError::Other("channel not open yet".into())),
        }
    }

    /// Borrows the selected route from the same phase-owned core.
    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .remote_addr(),
            Self::Established(core) => core.remote_addr(),
        }
    }

    /// Identifies only the same core's actual selected stream for local output backpressure.
    pub(crate) fn selected_turn_stream(&self) -> Option<nethernet::session::TurnStreamRoute> {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .selected_turn_stream(),
            Self::Established(core) => core.selected_turn_stream(),
        }
    }

    /// Reports the existing association measurement without changing ownership.
    pub(crate) fn rtt(&self) -> Option<Duration> {
        match self {
            Self::Connecting(core) => core.as_ref().expect("pending core remains owned").rtt(),
            Self::Established(core) => core.rtt(),
        }
    }

    /// Retains exact signaling correlation across the readiness transition.
    pub(crate) fn connection_id(&self) -> u64 {
        match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .connection_id(),
            Self::Established(core) => core.connection_id(),
        }
    }

    /// Drains late candidates once through the existing carrier.
    pub(crate) fn poll_local_signal(&mut self) -> Option<Signal> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .poll_local_signal(),
            Self::Established(core) => core.poll_local_signal(),
        }
    }

    /// Borrows the actual core state after the public update consumed its authenticated ACK.
    #[cfg(test)]
    pub(crate) fn test_gathering_complete(&self) -> bool {
        let state = match self {
            Self::Connecting(core) => core
                .as_ref()
                .expect("pending core remains owned")
                .gathering_state(),
            Self::Established(core) => core.gathering_state(),
        };
        state == nethernet::session::GatheringState::Complete
    }

    /// Applies credential rotation to the original allocation and absolute expiry owner.
    pub(crate) fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: nethernet::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .update_turn_credentials(server, credentials, now),
            Self::Established(core) => core.update_turn_credentials(server, credentials, now),
        }
    }

    /// Preserves exact stream-route selection through the original connecting/established owner.
    pub(crate) fn update_turn_stream_credentials(
        &mut self,
        route: nethernet::session::TurnStreamRoute,
        credentials: nethernet::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Connecting(core) => core
                .as_mut()
                .expect("pending core remains owned")
                .update_turn_stream_credentials(route, credentials, now),
            Self::Established(core) => core.update_turn_stream_credentials(route, credentials, now),
        }
    }

    /// Consumes the actual live owner; the caller still drains best-effort teardown output on error.
    pub(crate) fn close(
        self,
        now: Instant,
    ) -> (
        Connection<nethernet::phase::Retired>,
        Result<(), ProtocolError>,
    ) {
        match self {
            Self::Connecting(core) => core.expect("pending core remains owned").close(now),
            Self::Established(core) => core.close(now),
        }
    }
}
