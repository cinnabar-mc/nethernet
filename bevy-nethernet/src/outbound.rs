//! One outbound UDP transport, advanced by the caller's frame rather than a worker runtime.
use crate::connection::ConnectionEvent;
use crate::socket::bind_shared_socket;
use bevy_platform::cell::SyncCell;
use nethernet::connection::{Connection, ConnectionInput, IceMode};
use nethernet::error::ProtocolError;
use nethernet::protocol::Signal;
use nethernet::protocol::webrtc::Description;
use nethernet::sans::Sans;
use nethernet::session::{
    Channel, GatheringState, IceConfig, Session, SessionEvent, SessionInput, SessionOutput,
    TurnCredentials,
};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_DATAGRAMS_PER_UPDATE: usize = 64;
const MAX_OUTPUTS_PER_UPDATE: usize = 1024;
const RTT_REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Numeric UDP binding and already-resolved STUN/TURN inputs for the next connection attempt.
///
/// Each client owns its socket and TURN allocations. Use a concrete local interface address,
/// with port zero for an ephemeral port. DNS and service credential acquisition belong to
/// the application; credential expiry is the original absolute monotonic deadline.
#[derive(Clone)]
pub struct ClientIceConfig {
    /// Concrete local interface, matching every configured server's IP family.
    pub bind_addr: SocketAddr,
    /// Pure-core gathering policy, finite timeout and numeric UDP servers.
    pub ice: IceConfig,
}

enum State {
    Gathering(Session, Description),
    Connected(Connection),
}

/// Exclusive ownership avoids sharing a TURN allocation transport tuple between sessions.
pub(crate) struct Outbound {
    socket: UdpSocket,
    state: SyncCell<Option<State>>,
    events: VecDeque<ConnectionEvent>,
    buffered_bytes: usize,
    reported_rtt: Option<Duration>,
    rtt_reported_at: Option<Instant>,
    buf: Box<[u8]>,
}

impl Outbound {
    /// Binds a nonblocking socket and starts finite gathering without encoding an offer.
    pub(crate) fn new(
        config: Option<&ClientIceConfig>,
        establish_within: Duration,
        now: Instant,
    ) -> std::io::Result<Self> {
        let (socket, local) = match config {
            Some(config) => {
                let ip = config.bind_addr.ip();
                if ip.is_unspecified() || ip.is_multicast() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "ICE binding needs a concrete local interface",
                    ));
                }
                let socket = UdpSocket::bind(config.bind_addr)?;
                let local = socket.local_addr()?;
                (socket, local)
            }
            None => bind_shared_socket()?,
        };
        socket.set_nonblocking(true)?;
        let ice = config.map(|config| config.ice.clone()).unwrap_or_default();
        let (mut session, description) =
            Session::new_with_ice(local, true, rand::random(), ice, now)
                .map_err(std::io::Error::other)?;
        session.set_establish_deadline(establish_within);
        Ok(Self {
            socket,
            state: SyncCell::new(Some(State::Gathering(session, description))),
            events: VecDeque::new(),
            buffered_bytes: 0,
            reported_rtt: None,
            rtt_reported_at: None,
            buf: vec![0; 65536].into_boxed_slice(),
        })
    }

    /// Full SDP may be produced only after gathering completes.
    pub(crate) fn gathering_complete(&mut self) -> bool {
        matches!(self.state.get(), Some(State::Gathering(session, _))
            if session.gathering_state() == GatheringState::Complete)
    }

    /// Transfers the gathered session into its single connection and returns initial signals.
    pub(crate) fn connect(
        &mut self,
        id: u64,
        remote: String,
        mode: IceMode,
    ) -> Result<Vec<Signal>, ProtocolError> {
        if mode == IceMode::Full && !self.gathering_complete() {
            return Err(ProtocolError::Other("ICE gathering is incomplete".into()));
        }
        if !matches!(self.state.get(), Some(State::Gathering(..))) {
            return Err(ProtocolError::Other("offer already created".into()));
        }
        let Some(State::Gathering(session, description)) = self.state.get().take() else {
            return Err(ProtocolError::Other("offer already created".into()));
        };
        let (connection, signals) = Connection::connect(session, description, id, remote, mode);
        *self.state.get() = Some(State::Connected(connection));
        Ok(signals)
    }

    /// Advances expiry before any packet admission and bounds socket work within one frame.
    pub(crate) fn update(&mut self, now: Instant) -> Result<(), ProtocolError> {
        let mut remaining = MAX_OUTPUTS_PER_UPDATE;
        self.timeout(now)?;
        self.flush(&mut remaining)?;
        for _ in 0..MAX_DATAGRAMS_PER_UPDATE {
            if remaining == 0 {
                break;
            }
            let (len, from) = match self.socket.recv_from(&mut self.buf) {
                Ok(packet) => packet,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            let packet = self.buf[..len].into();
            let result = match self.state.get() {
                Some(State::Gathering(session, _)) => {
                    session.handle(SessionInput::Packet(packet, from, now))
                }
                Some(State::Connected(connection)) => {
                    connection.handle(ConnectionInput::Packet(packet, from, now))
                }
                None => return Ok(()),
            };
            if result.is_err() {
                tracing::debug!("discarding a rejected session datagram");
            }
            self.flush(&mut remaining)?;
        }
        if let Some(State::Connected(connection)) = self.state.get()
            && let Some(rtt) = connection.rtt()
            && self.reported_rtt != Some(rtt)
            && self
                .rtt_reported_at
                .is_none_or(|last| now.saturating_duration_since(last) >= RTT_REPORT_INTERVAL)
        {
            self.reported_rtt = Some(rtt);
            self.rtt_reported_at = Some(now);
            self.push_event(ConnectionEvent::Rtt(rtt))?;
        }
        Ok(())
    }

    /// Feeds the owning core's deadline without introducing a second timer engine.
    fn timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        match self.state.get() {
            Some(State::Gathering(session, _)) => session.handle(SessionInput::Timeout(now)),
            Some(State::Connected(connection)) => connection.handle(ConnectionInput::Timeout(now)),
            None => Err(ProtocolError::Other("connection closed".into())),
        }
    }

    /// Drains core output; nonblocking UDP congestion drops a datagram for protocol retransmission.
    fn flush(&mut self, remaining: &mut usize) -> Result<(), ProtocolError> {
        while *remaining > 0 {
            let output = match self.state.get() {
                Some(State::Gathering(session, _)) => session.poll(),
                Some(State::Connected(connection)) => connection.poll(),
                None => return Ok(()),
            };
            let Some(output) = output else {
                return Ok(());
            };
            *remaining -= 1;
            match output {
                SessionOutput::Send(data, to) => match self.socket.send_to(&data, to) {
                    Ok(_) => {}
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                },
                SessionOutput::Event(SessionEvent::Ready) => {
                    let addr = match self.state.get() {
                        Some(State::Connected(connection)) => connection.remote_addr(),
                        _ => None,
                    };
                    self.push_event(ConnectionEvent::Ready(addr))?;
                }
                SessionOutput::Event(SessionEvent::Failed) => {
                    self.push_event(ConnectionEvent::Failed)?;
                }
                SessionOutput::Message(channel, data) => {
                    self.push_event(ConnectionEvent::Message(channel, data.into_boxed_slice()))?;
                }
                SessionOutput::Wait(_) => {}
            }
        }
        Ok(())
    }

    /// Bounds transport delivery separately from the application receive queues.
    fn push_event(&mut self, event: ConnectionEvent) -> Result<(), ProtocolError> {
        let bytes = match &event {
            ConnectionEvent::Message(_, data) => data.len(),
            _ => 0,
        };
        if self.events.len() >= MAX_RECEIVED_MESSAGES
            || bytes > MAX_RECEIVED_BYTES.saturating_sub(self.buffered_bytes)
        {
            return Err(ProtocolError::Other("client receive limit reached".into()));
        }
        self.buffered_bytes += bytes;
        self.events.push_back(event);
        Ok(())
    }

    /// Removes one buffered event without retaining a second copy of its payload.
    pub(crate) fn poll_event(&mut self) -> Option<ConnectionEvent> {
        let event = self.events.pop_front()?;
        if let ConnectionEvent::Message(_, data) = &event {
            self.buffered_bytes -= data.len();
        }
        Some(event)
    }

    /// Returns late candidates once, for carriers supporting trickle signaling.
    pub(crate) fn poll_local_signal(&mut self) -> Option<Signal> {
        match self.state.get() {
            Some(State::Connected(connection)) => connection.poll_local_signal(),
            _ => None,
        }
    }

    /// Applies already authenticated signaling under the original caller-time expiry fences.
    pub(crate) fn signal(&mut self, signal: Signal, now: Instant) -> Result<(), ProtocolError> {
        self.timeout(now)?;
        let result = match self.state.get() {
            Some(State::Connected(connection)) => {
                connection.handle(ConnectionInput::Signal(signal, now))
            }
            _ => Err(ProtocolError::Other("offer not created".into())),
        };
        let mut remaining = MAX_OUTPUTS_PER_UPDATE;
        self.flush(&mut remaining)?;
        result
    }

    /// The active attempt id; callers fence identity validation and deadline changes before admission.
    pub(crate) fn connection_id(&mut self) -> Option<u64> {
        match self.state.get() {
            Some(State::Connected(connection)) => Some(connection.connection_id()),
            _ => None,
        }
    }

    /// Sends directly into the pure owner. A full frame drain returns WouldBlock before admitting more data.
    pub(crate) fn send(
        &mut self,
        channel: Channel,
        data: &[u8],
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if data.len() > MAX_RECEIVED_BYTES {
            return Err(ProtocolError::MessageSizeExceeded(data.len()));
        }
        let mut remaining = MAX_OUTPUTS_PER_UPDATE;
        self.timeout(now)?;
        self.flush(&mut remaining)?;
        if remaining == 0 {
            return Err(std::io::Error::from(ErrorKind::WouldBlock).into());
        }
        let result = match self.state.get() {
            Some(State::Connected(connection)) => {
                connection.handle(ConnectionInput::Send(channel, data.to_vec().into(), now))
            }
            _ => Err(ProtocolError::Other("not connected".into())),
        };
        self.flush(&mut remaining)?;
        result
    }

    /// Password renewal preserves the allocation username and original absolute credential expiry.
    pub(crate) fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match self.state.get() {
            Some(State::Gathering(session, _)) => {
                session.update_turn_credentials(server, credentials, now)
            }
            Some(State::Connected(connection)) => {
                connection.update_turn_credentials(server, credentials, now)
            }
            None => Err(ProtocolError::Other("connection closed".into())),
        }
    }

    /// Stops all timers, discards application work and attempts finite best-effort relay release.
    fn close(&mut self, now: Instant) {
        if let Some(mut state) = self.state.get().take() {
            let _ = match &mut state {
                State::Gathering(session, _) => session.close(now),
                State::Connected(connection) => connection.close(now),
            };
            for _ in 0..MAX_OUTPUTS_PER_UPDATE {
                let output = match &mut state {
                    State::Gathering(session, _) => session.poll(),
                    State::Connected(connection) => connection.poll(),
                };
                match output {
                    Some(SessionOutput::Send(data, to)) => {
                        let _ = self.socket.send_to(&data, to);
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
        self.events.clear();
        self.buffered_bytes = 0;
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        self.close(Instant::now());
    }
}

const MAX_RECEIVED_MESSAGES: usize = 1024;
const MAX_RECEIVED_BYTES: usize = 16 * 1024 * 1024;

/// Bounded application delivery shared by both outbound clients.
#[derive(Default)]
pub(crate) struct Received {
    reliable: VecDeque<Box<[u8]>>,
    unreliable: VecDeque<Box<[u8]>>,
    bytes: usize,
}

impl Received {
    /// Admits one complete message; overflow terminates the connection rather than losing reliable data silently.
    pub(crate) fn push(&mut self, channel: Channel, data: Box<[u8]>) -> Result<(), ProtocolError> {
        if self.reliable.len() + self.unreliable.len() >= MAX_RECEIVED_MESSAGES
            || data.len() > MAX_RECEIVED_BYTES.saturating_sub(self.bytes)
        {
            return Err(ProtocolError::Other("client receive limit reached".into()));
        }
        self.bytes += data.len();
        match channel {
            Channel::Reliable => self.reliable.push_back(data),
            Channel::Unreliable => self.unreliable.push_back(data),
        }
        Ok(())
    }

    /// Transfers one message to the application and releases its byte budget.
    pub(crate) fn pop(&mut self, channel: Channel) -> Option<Box<[u8]>> {
        let data = match channel {
            Channel::Reliable => self.reliable.pop_front(),
            Channel::Unreliable => self.unreliable.pop_front(),
        }?;
        self.bytes -= data.len();
        Some(data)
    }
}

#[cfg(test)]
mod tests;
