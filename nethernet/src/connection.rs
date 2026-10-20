//! One NetherNet connection: a session plus offer, answer and candidate signal handling.
use crate::error::ProtocolError;
use crate::phase::{Connecting, Established, Live, Phase, Retired};
use crate::protocol::webrtc::Description;
use crate::protocol::webrtc::candidate::{format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::sans::Sans;
use crate::session::{Channel, Session, SessionInput, SessionOutput};
use bytes::Bytes;
use rtc::ice::candidate::Candidate;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Whether candidates travel inside the SDP or as separate signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceMode {
    /// Candidates are embedded in the SDP.
    Full,
    /// The SDP carries no candidates and each follows as its own signal.
    Trickle,
}

enum SignalKind {
    Offer,
    Answer,
}

/// A session bound to one connection id and remote network id; signals for any other pair are ignored.
/// Application sending requires the owned transition after actual session readiness.
///
/// ```compile_fail
/// use nethernet::{connection::Connection, phase::Connecting, session::Channel};
/// fn pending(connection: &mut Connection<Connecting>, now: std::time::Instant) {
///     connection.send(Channel::Reliable, bytes::Bytes::new(), now);
/// }
/// ```
#[must_use = "retain the connection owner through retirement and drain its output"]
pub struct Connection<S: Phase = Connecting> {
    session: Session<S>,
    connection_id: u64,
    remote_network_id: String,
    remote_identity: Option<String>,
    ice_mode: IceMode,
    local_ufrag: String,
    next_candidate_index: usize,
}

impl Connection<Connecting> {
    pub fn connect(
        mut session: Session,
        description: Description,
        connection_id: u64,
        remote_network_id: String,
        ice_mode: IceMode,
    ) -> (Self, Vec<Signal>) {
        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            connection_id,
            remote_network_id.clone(),
            SignalKind::Offer,
        );
        let next_candidate_index = session.local_candidates().len();
        while session.poll_local_candidate().is_some() {}

        (
            Self {
                session,
                connection_id,
                remote_network_id,
                remote_identity: None,
                ice_mode,
                local_ufrag: description.ice.ufrag,
                next_candidate_index,
            },
            signals,
        )
    }

    pub fn parse_offer(offer: &Signal) -> Result<(Description, Vec<Candidate>), ProtocolError> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }
        Description::parse(&offer.data)
    }

    /// Applies a parsed offer and builds the answer signals, adopting the offer's connection and network ids.
    pub fn accept(
        mut session: Session,
        description: Description,
        offer: &Signal,
        remote_description: Description,
        remote_candidates: Vec<Candidate>,
        ice_mode: IceMode,
        now: Instant,
    ) -> Result<(Connection, Vec<Signal>), ProtocolError> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }

        let remote_identity = remote_description.identity.clone();
        session.handle(SessionInput::RemoteDescription(
            remote_description,
            remote_candidates,
            now,
        ))?;

        let signals = Self::answer_signals(&session, &description, offer, ice_mode);
        let candidates = Self::take_described_candidates(&mut session);
        Ok((
            Self::accepted(
                session,
                description,
                offer,
                remote_identity,
                ice_mode,
                candidates,
            ),
            signals,
        ))
    }

    /// Encodes the prepared session's current candidates without transferring its allocation owner.
    pub(crate) fn answer_signals(
        session: &Session,
        description: &Description,
        offer: &Signal,
        ice_mode: IceMode,
    ) -> Vec<Signal> {
        Self::describe(
            session,
            description,
            ice_mode,
            offer.connection_id,
            offer.network_id.clone(),
            SignalKind::Answer,
        )
    }

    /// Marks only the current description's candidates as sent, leaving later gathered ones for trickle.
    pub(crate) fn take_described_candidates(session: &mut Session) -> usize {
        let count = session.local_candidates().len();
        while session.poll_local_candidate().is_some() {}
        count
    }

    /// Adopts an already applied remote description after all fallible answer preparation succeeds.
    pub(crate) fn accepted(
        session: Session,
        description: Description,
        offer: &Signal,
        remote_identity: Option<String>,
        ice_mode: IceMode,
        next_candidate_index: usize,
    ) -> Self {
        Self {
            session,
            connection_id: offer.connection_id,
            remote_network_id: offer.network_id.clone(),
            remote_identity,
            ice_mode,
            local_ufrag: description.ice.ufrag,
            next_candidate_index,
        }
    }

    /// Transfers this exact connection only after both channels became ready.
    #[allow(
        clippy::result_large_err,
        reason = "returns the original pending allocation without boxing"
    )]
    pub fn try_establish(self) -> Result<Connection<Established>, Self> {
        if self.session.became_ready() {
            Ok(self.rephase())
        } else {
            Err(self)
        }
    }
}

impl<S: Phase> Connection<S> {
    /// Moves the existing allocation, correlation and output owner without protocol work.
    fn rephase<T: Phase>(self) -> Connection<T> {
        Connection {
            session: self.session.rephase(),
            connection_id: self.connection_id,
            remote_network_id: self.remote_network_id,
            remote_identity: self.remote_identity,
            ice_mode: self.ice_mode,
            local_ufrag: self.local_ufrag,
            next_candidate_index: self.next_candidate_index,
        }
    }

    /// Drains the same original accepted prefix and transport work in every phase.
    pub fn poll(&mut self) -> Option<SessionOutput> {
        self.session.poll()
    }

    fn describe(
        session: &Session,
        description: &Description,
        ice_mode: IceMode,
        connection_id: u64,
        remote_network_id: String,
        kind: SignalKind,
    ) -> Vec<Signal> {
        let sdp = match ice_mode {
            IceMode::Full => description.encode_full(session.local_candidates()),
            IceMode::Trickle => description.encode_trickle(),
        };

        let mut signals = vec![match kind {
            SignalKind::Offer => Signal::offer(connection_id, sdp, remote_network_id.clone()),
            SignalKind::Answer => Signal::answer(connection_id, sdp, remote_network_id.clone()),
        }];

        if ice_mode == IceMode::Trickle {
            for (index, candidate) in session.local_candidates().iter().enumerate() {
                signals.push(Signal::candidate(
                    connection_id,
                    format_ice_candidate(index, candidate, &description.ice.ufrag),
                    remote_network_id.clone(),
                ));
            }
        }

        signals
    }

    fn handle_signal(&mut self, signal: &Signal, now: Instant) -> Result<(), ProtocolError>
    where
        S: Live,
    {
        if signal.connection_id != self.connection_id || signal.network_id != self.remote_network_id
        {
            return Ok(());
        }

        match signal.signal_type {
            SignalType::Answer => {
                let (description, candidates) = Description::parse(&signal.data)?;
                self.remote_identity = description.identity.clone();
                self.session.handle(SessionInput::RemoteDescription(
                    description,
                    candidates,
                    now,
                ))?;
            }
            SignalType::Candidate => {
                let candidate = parse_ice_candidate(&signal.data)?;
                self.session
                    .handle(SessionInput::RemoteCandidate(candidate, now))?;
            }
            SignalType::Error => {
                return Err(ProtocolError::Other(format!(
                    "remote signaled a connection error: {}",
                    signal.data
                )));
            }
            SignalType::Offer => {}
        }

        Ok(())
    }

    /// The remote's raw `a=identity` value, not validated here (guide section 5.2).
    pub fn remote_identity(&self) -> Option<&str> {
        self.remote_identity.as_deref()
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.session.remote_addr()
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.session.rtt()
    }

    /// Observes the original session's gathering state without advancing timers or admitting work.
    pub fn gathering_state(&self) -> crate::session::GatheringState {
        self.session.gathering_state()
    }

    /// Observes the same selected live relay carrier without inferring a route from queued output.
    /// Pending, direct, UDP and retired relay owners return None.
    pub fn selected_turn_stream(&self) -> Option<crate::session::TurnStreamRoute> {
        self.session.selected_turn_stream()
    }

    /// Reads usage from the same session FIFO without granting application or transport work.
    pub fn pending_output_usage(&self) -> crate::session::OutputUsage {
        self.session.pending_output_usage()
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// One candidate gathered after the initial signals. The runtime sends it through the same signaling owner.
    pub fn poll_local_signal(&mut self) -> Option<Signal>
    where
        S: Live,
    {
        if self.ice_mode != IceMode::Trickle {
            return None;
        }
        let candidate = self.session.poll_local_candidate()?;
        let index = self.next_candidate_index;
        self.next_candidate_index += 1;
        Some(Signal::candidate(
            self.connection_id,
            format_ice_candidate(index, &candidate, &self.local_ufrag),
            self.remote_network_id.clone(),
        ))
    }

    /// Cancels all transport timers and queues best-effort relay deallocation sends.
    pub fn close(self, now: Instant) -> (Connection<Retired>, Result<(), ProtocolError>)
    where
        S: Live,
    {
        let (session, result) = self.session.close(now);
        (
            Connection {
                session,
                connection_id: self.connection_id,
                remote_network_id: self.remote_network_id,
                remote_identity: self.remote_identity,
                ice_mode: self.ice_mode,
                local_ufrag: self.local_ufrag,
                next_candidate_index: self.next_candidate_index,
            },
            result,
        )
    }

    /// Rotates one TURN allocation's credential using the caller's clock.
    /// Success admits the refresh locally; its actual response determines the allocation lifetime.
    pub fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: crate::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError>
    where
        S: Live,
    {
        self.session
            .update_turn_credentials(server, credentials, now)
    }

    /// Rotates the exact stream allocation while preserving the original transaction owner.
    pub fn update_turn_stream_credentials(
        &mut self,
        route: crate::session::TurnStreamRoute,
        credentials: crate::session::TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError>
    where
        S: Live,
    {
        self.session
            .update_turn_stream_credentials(route, credentials, now)
    }
}

pub enum ConnectionInput {
    Packet(Box<[u8]>, SocketAddr, Instant),

    /// Binds the original pending slot to its connected, applicable-TLS-verified actual stream.
    ActivateTurnStream(
        crate::session::TurnStreamId,
        crate::session::TurnStreamRoute,
        Instant,
    ),
    /// One complete TURN frame from the original bound stream tuple.
    StreamPacket(Box<[u8]>, crate::session::TurnStreamRoute, Instant),
    /// A pending or active stream ended; its allocation cannot move to another carrier.
    StreamClosed(crate::session::TurnStreamId, Instant),

    Timeout(Instant),

    Signal(Signal, Instant),
}

impl Connection<Established> {
    /// Maximum outgoing body under the original active association's installed limit.
    pub fn max_message_size(&self, channel: Channel) -> Option<usize> {
        self.session.max_message_size(channel)
    }

    /// Admits a message through this connection's original established session.
    pub fn send(
        &mut self,
        channel: Channel,
        data: Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.session.send(channel, data, now)
    }
}

impl<S: Live> Sans for Connection<S> {
    type Input = ConnectionInput;
    type Output = SessionOutput;
    type Error = ProtocolError;

    fn handle(&mut self, msg: ConnectionInput) -> Result<(), ProtocolError> {
        match msg {
            ConnectionInput::Packet(data, from, now) => {
                self.session.handle(SessionInput::Packet(data, from, now))
            }
            ConnectionInput::ActivateTurnStream(id, route, now) => self
                .session
                .handle(SessionInput::ActivateTurnStream(id, route, now)),
            ConnectionInput::StreamPacket(data, route, now) => self
                .session
                .handle(SessionInput::StreamPacket(data, route, now)),
            ConnectionInput::StreamClosed(id, now) => {
                self.session.handle(SessionInput::StreamClosed(id, now))
            }
            ConnectionInput::Timeout(now) => self.session.handle(SessionInput::Timeout(now)),
            ConnectionInput::Signal(signal, now) => self.handle_signal(&signal, now),
        }
    }

    fn poll(&mut self) -> Option<SessionOutput> {
        self.session.poll()
    }
}

/// Deadlines for the transport drivers to enforce; this crate only carries them.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Time for the offer and answer exchange to complete.
    pub negotiation: Duration,

    /// Time for ICE and DTLS to start once signaling is done.
    pub start: Duration,

    /// Time for both data channels to open after the transports start.
    pub channel: Duration,
}

impl Timeouts {
    /// Budget between the end of negotiation and a usable connection.
    pub fn establish(&self) -> Duration {
        self.start + self.channel
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            negotiation: Duration::from_secs(15),
            start: Duration::from_secs(5),
            channel: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{self, Identity, ServerIdentity, TokenTrust};
    use crate::session::SessionEvent;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use std::time::SystemTime;

    #[test]
    fn default_timeouts_establish_within_ten_seconds() {
        assert_eq!(Timeouts::default().establish(), Duration::from_secs(10));
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    fn assert_connects(ice_mode: IceMode) {
        let mut now = Instant::now();

        let (offer_session, offer_description) = Session::new(addr(40200), true, 1, now).unwrap();
        let (mut offerer, offer_signals) = Connection::connect(
            offer_session,
            offer_description,
            42,
            7.to_string(),
            ice_mode,
        );
        let mut offer_iter = offer_signals.into_iter();
        let offer = offer_iter.next().unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);

        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let (answer_session, answer_description) =
            Session::new(addr(40201), false, 2, now).unwrap();
        let (mut answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            ice_mode,
            now,
        )
        .unwrap();
        let mut answer_iter = answer_signals.into_iter();
        let answer = answer_iter.next().unwrap();
        assert_eq!(answer.signal_type, SignalType::Answer);

        offerer
            .handle(ConnectionInput::Signal(answer, now))
            .unwrap();

        for signal in offer_iter {
            answerer
                .handle(ConnectionInput::Signal(signal, now))
                .unwrap();
        }
        for signal in answer_iter {
            offerer
                .handle(ConnectionInput::Signal(signal, now))
                .unwrap();
        }

        let mut offerer_ready = false;
        let mut answerer_ready = false;

        for _ in 0..5000 {
            let mut progressed = false;

            let mut outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => {}
                    SessionOutput::Wait(_) => {}
                    SessionOutput::SendStream(..) => {
                        panic!("host-only connection emitted stream traffic")
                    }
                }
            }
            for (data, to) in outbox {
                assert_eq!(to, addr(40201));
                answerer
                    .handle(ConnectionInput::Packet(data.into(), addr(40200), now))
                    .unwrap();
            }

            let mut outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => {}
                    SessionOutput::Wait(_) => {}
                    SessionOutput::SendStream(..) => {
                        panic!("host-only connection emitted stream traffic")
                    }
                }
            }
            for (data, to) in outbox {
                assert_eq!(to, addr(40200));
                offerer
                    .handle(ConnectionInput::Packet(data.into(), addr(40201), now))
                    .unwrap();
            }

            if offerer_ready && answerer_ready {
                break;
            }

            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle(ConnectionInput::Timeout(now)).unwrap();
                answerer.handle(ConnectionInput::Timeout(now)).unwrap();
            }
        }

        assert!(offerer_ready, "offerer never became ready ({ice_mode:?})");
        assert!(answerer_ready, "answerer never became ready ({ice_mode:?})");
    }

    #[test]
    fn connects_with_full_ice() {
        assert_connects(IceMode::Full);
    }

    #[test]
    fn connects_with_trickle_ice() {
        assert_connects(IceMode::Trickle);
    }

    #[test]
    fn signals_for_a_different_connection_are_ignored() {
        let now = Instant::now();
        let (session, description) = Session::new(addr(40210), true, 1, now).unwrap();
        let (mut offerer, _) =
            Connection::connect(session, description, 1, 7.to_string(), IceMode::Full);
        let unrelated = Signal::answer(999, "irrelevant".to_string(), "7".to_string());
        offerer
            .handle(ConnectionInput::Signal(unrelated, now))
            .unwrap();
    }

    fn signed_by(domain: &str, description: &mut Description) -> ServerIdentity {
        let server = ServerIdentity::generate(domain, SystemTime::now()).unwrap();
        description.identity = Some(
            server
                .identity_for_fingerprints(
                    std::slice::from_ref(&description.fingerprint),
                    SystemTime::now(),
                )
                .unwrap(),
        );
        server
    }

    #[test]
    fn identity_assertions_flow_and_verify_in_both_directions() {
        let now = Instant::now();
        let wall_clock = SystemTime::now();

        let (offer_session, mut offer_description) =
            Session::new(addr(40220), true, 1, now).unwrap();
        let offerer_identity = signed_by("offerer.example", &mut offer_description);
        let offerer_envelope = offer_description.identity.clone().unwrap();

        let (mut offerer, offer_signals) = Connection::connect(
            offer_session,
            offer_description,
            1,
            7.to_string(),
            IceMode::Full,
        );
        let offer = offer_signals.into_iter().next().unwrap();

        let claims = identity::validate_sdp(&offer.data, &TokenTrust::Any, wall_clock).unwrap();
        assert_eq!(
            claims.client_public_key().unwrap(),
            *offerer_identity.verifying_key()
        );
        assert_eq!(
            Identity::from_sdp(&offer.data).unwrap().idp.domain,
            "offerer.example"
        );

        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        assert_eq!(
            remote_description.identity.as_deref(),
            Some(offerer_envelope.as_str())
        );

        let (answer_session, mut answer_description) =
            Session::new(addr(40221), false, 2, now).unwrap();
        let answerer_identity = signed_by("answerer.example", &mut answer_description);
        let answerer_envelope = answer_description.identity.clone().unwrap();

        let (answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            IceMode::Full,
            now,
        )
        .unwrap();
        let answer = answer_signals.into_iter().next().unwrap();
        assert_eq!(answerer.remote_identity(), Some(offerer_envelope.as_str()));

        let claims = identity::validate_sdp(&answer.data, &TokenTrust::Any, wall_clock).unwrap();
        assert_eq!(
            claims.client_public_key().unwrap(),
            *answerer_identity.verifying_key()
        );

        offerer
            .handle(ConnectionInput::Signal(answer.clone(), now))
            .unwrap();
        assert_eq!(offerer.remote_identity(), Some(answerer_envelope.as_str()));
    }
}
