//! A DTLS-secured SCTP session over ICE with the two NetherNet data channels.
mod dcep;
mod dtls;
mod ice;
mod sctp;

use crate::error::ProtocolError;
use crate::phase::{Connecting, Established, Live, Phase, Retired};
use crate::protocol::constants::{LOCAL_SCTP_MAX_MESSAGE_SIZE, SCTP_MAX_MESSAGE_SIZE};
use crate::protocol::message::{Message as Framing, MessageSegment};
use crate::protocol::webrtc::{Description, DtlsRole, certificate};
use crate::sans::Sans;
use dtls::EndpointEvent;
pub use dtls::ResolvedRole;
use ice::IceLayer;
pub use ice::{
    GatheringState, IceConfig, IceError, IcePolicy, IceServer, MAX_ICE_SERVERS,
    MAX_TURN_CREDENTIAL_BYTES, TurnCredentials,
};
use rtc::datachannel::message::Message as DcepMessage;
use rtc::ice::candidate::Candidate;
use rtc::ice::state::ConnectionState as IceConnectionState;
use rtc::sctp::{Event as SctpEvent, PayloadProtocolIdentifier, StreamId};
use sctp::SctpLayer;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const RELIABLE_STREAM_ID: StreamId = 1;
const MAX_EARLY_PACKETS: usize = 8;
const UNRELIABLE_STREAM_ID: StreamId = 3;
const DEFAULT_ESTABLISH_DEADLINE: Duration = Duration::from_secs(10);

/// Reliable messages are segmented; unreliable ones must fit one segment (guide section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Reliable,
    Unreliable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Both data channels are open.
    Ready,
    /// A transport failed or establishment expired; emitted once.
    Failed,
    /// The authenticated DTLS peer closed; transport state and timers have been retired.
    PeerClosed,
}

pub enum SessionOutput {
    Send(Vec<u8>, SocketAddr),
    Event(SessionEvent),
    Message(Channel, Vec<u8>),
    /// Feed `Timeout` no later than this long from now.
    Wait(Duration),
}

pub enum SessionInput {
    Packet(Box<[u8]>, SocketAddr, Instant),

    /// Transports start once the description or a later candidate supplies a remote address.
    RemoteDescription(Description, Vec<Candidate>, Instant),

    RemoteCandidate(Candidate, Instant),

    Timeout(Instant),
}

struct RemoteInfo {
    addr: SocketAddr,
}

#[derive(Default)]
struct Channels {
    reliable_stream_id: Option<StreamId>,
    unreliable_stream_id: Option<StreamId>,
    reassembly: Framing,
    ready_emitted: bool,
    terminal_emitted: bool,
}

impl Channels {
    fn stream_id(&self, channel: Channel) -> Option<StreamId> {
        match channel {
            Channel::Reliable => self.reliable_stream_id,
            Channel::Unreliable => self.unreliable_stream_id,
        }
    }

    fn set_open(&mut self, channel: Channel, stream_id: StreamId) {
        match channel {
            Channel::Reliable => self.reliable_stream_id = Some(stream_id),
            Channel::Unreliable => self.unreliable_stream_id = Some(stream_id),
        }
    }
}

/// ICE, DTLS and SCTP stacks bound to one local address, with one reliable and one unreliable channel.
/// Connecting may drain accepted messages but cannot send application data.
///
/// ```compile_fail
/// use nethernet::{phase::Connecting, session::{Session, Channel}};
/// fn premature(session: &mut Session<Connecting>, now: std::time::Instant) {
///     session.send(Channel::Reliable, bytes::Bytes::new(), now);
/// }
/// ```
///
/// A consumed local close owner exposes only retrospective output.
///
/// ```compile_fail
/// use nethernet::{phase::Established, session::{Session, Channel}};
/// fn retired(session: Session<Established>, now: std::time::Instant) {
///     let (mut retired, _) = session.close(now);
///     retired.send(Channel::Reliable, bytes::Bytes::new(), now);
/// }
/// ```
#[must_use = "retain the session owner through retirement and drain its accepted output"]
pub struct Session<S: Phase = Connecting> {
    _phase: PhantomData<S>,
    is_controlling: bool,
    ice: IceLayer,
    certificate: Option<rtc::dtls::crypto::Certificate>,

    pending_role_fingerprint: Option<(ResolvedRole, (String, String))>,
    remote_max_message_size: u32,
    early_packets: VecDeque<rtc::shared::TaggedBytesMut>,

    remote: Option<RemoteInfo>,
    dtls: Option<DtlsLayer>,
    sctp: Option<SctpLayer>,

    channels: Channels,
    output: VecDeque<SessionOutput>,
    establish_within: Duration,
    establish_started: Option<Instant>,
}

pub use dtls::DtlsLayer;

impl Session<Connecting> {
    /// The controlling side is the offerer: it announces the DTLS server role and opens the data channels.
    /// The caller supplies a distinct SDP origin identifier for each local session.
    pub fn new(
        local_addr: SocketAddr,
        is_controlling: bool,
        session_id: u64,
        now: Instant,
    ) -> Result<(Session, Description), ProtocolError> {
        let ice = IceLayer::new(local_addr, is_controlling, now)?;
        Self::from_ice(is_controlling, session_id, ice)
    }

    /// Creates a session with resolved UDP STUN/TURN servers. Drain its initial sends and waits immediately.
    /// Full ICE callers wait for `GatheringState::Complete` before encoding SDP; trickle callers poll candidates.
    pub fn new_with_ice(
        local_addr: SocketAddr,
        is_controlling: bool,
        session_id: u64,
        config: IceConfig,
        now: Instant,
    ) -> Result<(Session, Description), ProtocolError> {
        let ice = IceLayer::with_config(local_addr, is_controlling, config, now)?;
        let (mut session, description) = Self::from_ice(is_controlling, session_id, ice)?;
        session.pump(now)?;
        session.push_wait(now);
        Ok((session, description))
    }

    /// Constructs the shared DTLS description after the caller selects its ICE configuration.
    fn from_ice(
        is_controlling: bool,
        session_id: u64,
        ice: IceLayer,
    ) -> Result<(Session, Description), ProtocolError> {
        let certificate = certificate::generate()?;
        let fingerprint = certificate::fingerprint(&certificate)?;

        let local_description = Description {
            session_id,
            ice: ice.local_credentials().clone(),
            dtls_role: if is_controlling {
                DtlsRole::Server
            } else {
                DtlsRole::Auto
            },
            fingerprint,
            sctp_max_message_size: LOCAL_SCTP_MAX_MESSAGE_SIZE,
            identity: None,
        };

        let session = Self {
            _phase: PhantomData,
            is_controlling,
            ice,
            certificate: Some(certificate),
            pending_role_fingerprint: None,
            remote_max_message_size: SCTP_MAX_MESSAGE_SIZE,
            early_packets: VecDeque::new(),
            remote: None,
            dtls: None,
            sctp: None,
            channels: Channels::default(),
            output: VecDeque::new(),
            establish_within: DEFAULT_ESTABLISH_DEADLINE,
            establish_started: None,
        };

        Ok((session, local_description))
    }

    /// Consumes this owner only after the actual two-channel readiness condition.
    /// Pending ownership is returned unchanged, including its output FIFO and allocation.
    #[allow(
        clippy::result_large_err,
        reason = "returns the original pending allocation without boxing"
    )]
    pub fn try_establish(self) -> Result<Session<Established>, Self> {
        if self.channels.ready_emitted {
            Ok(self.rephase())
        } else {
            Err(self)
        }
    }
}

impl<S: Phase> Session<S> {
    /// Transfers the same transport and output storage without performing protocol work.
    pub(crate) fn rephase<T: Phase>(self) -> Session<T> {
        Session {
            _phase: PhantomData,
            is_controlling: self.is_controlling,
            ice: self.ice,
            certificate: self.certificate,
            pending_role_fingerprint: self.pending_role_fingerprint,
            remote_max_message_size: self.remote_max_message_size,
            early_packets: self.early_packets,
            remote: self.remote,
            dtls: self.dtls,
            sctp: self.sctp,
            channels: self.channels,
            output: self.output,
            establish_within: self.establish_within,
            establish_started: self.establish_started,
        }
    }

    /// Whether this exact owner produced the protocol's actual readiness condition.
    pub(crate) fn became_ready(&self) -> bool {
        self.channels.ready_emitted
    }

    /// Drains the original wire, accepted-message and terminal FIFO.
    /// Connecting receives are retrospective accepted data, not permission to send.
    pub fn poll(&mut self) -> Option<SessionOutput> {
        self.output.pop_front()
    }

    /// Time allowed from the remote description until `Ready` before `Failed` is emitted; defaults to 10 seconds.
    pub fn set_establish_deadline(&mut self, within: Duration)
    where
        S: Live,
    {
        self.establish_within = within;
    }

    pub fn local_candidate(&self) -> &Candidate {
        self.ice.local_candidate()
    }

    /// Every candidate gathered so far and allowed by this session's policy.
    pub fn local_candidates(&self) -> &[Candidate] {
        self.ice.local_candidates()
    }

    /// Drains each gathered candidate once. Callers send these incrementally when using trickle ICE.
    pub fn poll_local_candidate(&mut self) -> Option<Candidate>
    where
        S: Live,
    {
        self.ice.poll_local_candidate()
    }

    /// Finite gathering state, independent of the remote description or connectivity checks.
    pub fn gathering_state(&self) -> GatheringState {
        self.ice.gathering_state()
    }

    /// Rotates the password for one resolved TURN endpoint; the allocation username must remain unchanged.
    /// Success admits the refresh locally; its actual response determines the allocation lifetime.
    pub fn update_turn_credentials(
        &mut self,
        server: SocketAddr,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError>
    where
        S: Live,
    {
        let result = self.ice.update_credentials(server, credentials, now);
        if self.ice.selected_route_failed() {
            self.fail(now)?;
        }
        result?;
        self.pump(now)?;
        self.push_wait(now);
        Ok(())
    }

    /// Cancels gathering, checks and relay timers immediately. Drain best-effort deallocation sends before dropping.
    pub fn close(mut self, now: Instant) -> (Session<Retired>, Result<(), ProtocolError>)
    where
        S: Live,
    {
        if self.ice.gathering_state() == GatheringState::Closed {
            return (self.rephase(), Ok(()));
        }
        let mut accepted = std::mem::take(&mut self.output);
        accepted.retain(|output| {
            matches!(
                output,
                SessionOutput::Message(..) | SessionOutput::Event(..)
            )
        });
        let result = self.close_transport(now);
        accepted.append(&mut self.output);
        self.output = accepted;
        (self.rephase(), result)
    }

    /// Retires the engine while keeping its owner available to drain teardown output.
    fn close_transport(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.ice.gathering_state() == GatheringState::Closed {
            return Ok(());
        }
        self.output.clear();
        self.early_packets.clear();
        self.ice.close(now);
        self.dtls = None;
        self.sctp = None;
        self.establish_started = None;
        while let Some((data, to)) = self.ice.poll_write()? {
            self.output.push_back(SessionOutput::Send(data, to));
        }
        Ok(())
    }

    /// The selected ICE remote address, else the first candidate's.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.ice
            .selected_remote_addr()
            .or_else(|| self.remote.as_ref().map(|r| r.addr))
    }

    /// Available once the SCTP association exists.
    pub fn rtt(&self) -> Option<Duration> {
        self.sctp.as_ref().and_then(|s| s.rtt())
    }

    fn set_remote_description(
        &mut self,
        remote: &Description,
        candidates: Vec<Candidate>,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.ice
            .set_remote_credentials(remote.ice.ufrag.clone(), remote.ice.pwd.clone())?;

        let resolved_role = ResolvedRole::from_remote_announced(remote.dtls_role);
        let fingerprint = remote.fingerprint.clone();
        self.remote_max_message_size = match remote.sctp_max_message_size {
            0 => u32::MAX,
            size => size,
        };

        for candidate in candidates {
            self.ice.add_remote_candidate(candidate)?;
        }
        self.pending_role_fingerprint = Some((resolved_role, fingerprint));
        self.establish_started.get_or_insert(now);

        self.pump(now)?;
        self.push_wait(now);
        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        candidate: Candidate,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.ice.add_remote_candidate(candidate)?;
        self.pump(now)
    }

    fn start_transports_on_selected_pair(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.dtls.is_some() || self.channels.terminal_emitted {
            return Ok(());
        }
        let Some(remote_addr) = self.ice.selected_remote_addr() else {
            return Ok(());
        };
        let Some((resolved_role, fingerprint)) = self.pending_role_fingerprint.take() else {
            return Ok(());
        };
        self.start_transports(remote_addr, resolved_role, fingerprint, now)?;

        for packet in std::mem::take(&mut self.early_packets) {
            if Some(packet.transport.local_addr) == self.ice.selected_local_addr()
                && Some(packet.transport.peer_addr) == self.ice.selected_remote_addr()
            {
                self.read_dtls(&packet.message, now)?;
            }
        }
        Ok(())
    }

    fn start_transports(
        &mut self,
        remote_addr: SocketAddr,
        resolved_role: ResolvedRole,
        remote_fingerprint: (String, String),
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let certificate = self
            .certificate
            .take()
            .ok_or_else(|| ProtocolError::Other("transports already started".to_string()))?;
        let selected_local = self.ice.selected_local_addr().ok_or(IceError::Server)?;
        let dtls = DtlsLayer::new(
            selected_local,
            remote_addr,
            resolved_role,
            certificate,
            remote_fingerprint,
            now,
        )?;
        let sctp = SctpLayer::new(
            selected_local,
            remote_addr,
            resolved_role,
            self.remote_max_message_size,
            now,
        )?;

        self.remote = Some(RemoteInfo { addr: remote_addr });
        self.dtls = Some(dtls);
        self.sctp = Some(sctp);

        Ok(())
    }

    fn handle_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.ice.handle_read(data, from, now)?;
        self.pump(now)?;
        while let Some(packet) = self.ice.poll_read() {
            if self.dtls.is_none() {
                if self.early_packets.len() < MAX_EARLY_PACKETS {
                    self.early_packets.push_back(packet);
                }
            } else if Some(packet.transport.local_addr) == self.ice.selected_local_addr()
                && Some(packet.transport.peer_addr) == self.ice.selected_remote_addr()
            {
                self.read_dtls(&packet.message, now)?;
            }
        }
        self.pump(now)?;
        Ok(())
    }

    fn read_dtls(&mut self, data: &[u8], now: Instant) -> Result<(), ProtocolError> {
        if let Some(dtls) = &mut self.dtls {
            let events = dtls.handle_read(data, now)?;
            for event in events {
                self.handle_dtls_event(event, now)?;
            }
        }
        Ok(())
    }

    fn handle_dtls_event(
        &mut self,
        event: EndpointEvent,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        match event {
            EndpointEvent::ApplicationData(data) => {
                if let Some(sctp) = &mut self.sctp {
                    sctp.handle_read(&data, now);
                }
                Ok(())
            }
            EndpointEvent::HandshakeComplete => Ok(()),
            EndpointEvent::PeerClosed => self.peer_closed(now),
            _ => Ok(()),
        }
    }

    /// Delivers complete final data and routes close_notify before releasing the relay allocation.
    fn peer_closed(&mut self, now: Instant) -> Result<(), ProtocolError> {
        let mut final_output = std::mem::take(&mut self.output);
        final_output.retain(|output| !matches!(output, SessionOutput::Wait(..)));
        let flush = (|| {
            if let Some(sctp) = &mut self.sctp {
                drain_dcep_and_data(sctp, &mut self.channels, &mut final_output, now)?;
            }
            if let Some(dtls) = &mut self.dtls {
                while let Some((data, to)) = dtls.poll_transmit() {
                    self.ice.send_selected(data, to, now)?;
                }
            }
            while let Some((data, to)) = self.ice.poll_write()? {
                final_output.push_back(SessionOutput::Send(data, to));
            }
            Ok(())
        })();
        // A best-effort reply failure must never keep a removed DTLS association alive.
        let teardown = self.terminate(SessionEvent::PeerClosed, now);
        final_output.append(&mut self.output);
        self.output = final_output;
        flush.and(teardown)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        self.ice.handle_timeout(now)?;
        if let Some(dtls) = &mut self.dtls {
            dtls.handle_timeout(now)?;
        }
        if let Some(sctp) = &mut self.sctp {
            sctp.handle_timeout(now);
        }
        self.pump(now)?;
        self.push_wait(now);
        Ok(())
    }

    fn push_wait(&mut self, now: Instant) {
        if let Some(deadline) = self.poll_timeout() {
            self.output
                .push_back(SessionOutput::Wait(deadline.saturating_duration_since(now)));
        }
    }

    fn establish_deadline(&self) -> Option<Instant> {
        if self.channels.ready_emitted || self.channels.terminal_emitted {
            return None;
        }
        self.establish_started.map(|at| at + self.establish_within)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        [
            self.establish_deadline(),
            self.ice.poll_timeout(),
            self.dtls.as_ref().and_then(|d| d.poll_timeout()),
            self.sctp.as_ref().and_then(|s| s.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn send_message(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let stream_id = self
            .channels
            .stream_id(channel)
            .ok_or_else(|| ProtocolError::Other("channel not open yet".to_string()))?;

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
                for segment in Framing::split_into_segments(data)? {
                    stream
                        .write_with_ppi(now, &segment.encode(), PayloadProtocolIdentifier::Binary)
                        .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                }
            }
            Channel::Unreliable => {
                let encoded = Framing::encode_unreliable(data)?;
                stream
                    .write_with_ppi(now, &encoded, PayloadProtocolIdentifier::Binary)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
            }
        }

        Ok(())
    }

    fn pump(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.ice.selected_route_failed() {
            self.fail(now)?;
        }
        while let Some((data, to)) = self.ice.poll_write()? {
            self.output.push_back(SessionOutput::Send(data, to));
        }
        while let Some(event) = self.ice.poll_event() {
            if let rtc::ice::agent::Event::ConnectionStateChange(state) = event
                && matches!(
                    state,
                    IceConnectionState::Failed
                        | IceConnectionState::Disconnected
                        | IceConnectionState::Closed
                )
            {
                self.fail(now)?;
            }
        }
        self.start_transports_on_selected_pair(now)?;

        let mut failed = false;
        if let (Some(sctp), Some(dtls)) = (&mut self.sctp, &mut self.dtls) {
            while let Some(event) = sctp.poll_event() {
                match event {
                    SctpEvent::Connected => open_channels_if_controlling(
                        self.is_controlling,
                        sctp,
                        &mut self.channels,
                        now,
                    )?,
                    SctpEvent::HandshakeFailed { .. } | SctpEvent::AssociationLost { .. } => {
                        failed = true;
                    }
                    _ => {}
                }
            }

            drain_dcep_and_data(sctp, &mut self.channels, &mut self.output, now)?;

            while let Some(packet) = sctp.poll_transmit(now) {
                dtls.write(&packet, now)?;
            }

            while let Some((data, to)) = dtls.poll_transmit() {
                self.ice.send_selected(data, to, now)?;
            }
        }
        while let Some((data, to)) = self.ice.poll_write()? {
            self.output.push_back(SessionOutput::Send(data, to));
        }
        if failed {
            self.fail(now)?;
        }

        if self.channels.reliable_stream_id.is_some()
            && self.channels.unreliable_stream_id.is_some()
            && !self.channels.ready_emitted
            && !self.channels.terminal_emitted
        {
            self.channels.ready_emitted = true;
            self.output
                .push_back(SessionOutput::Event(SessionEvent::Ready));
        }

        if self
            .establish_deadline()
            .is_some_and(|deadline| now >= deadline)
        {
            self.fail(now)?;
        }

        Ok(())
    }

    fn fail(&mut self, now: Instant) -> Result<(), ProtocolError> {
        self.terminate(SessionEvent::Failed, now)
    }

    /// Retains accepted data/readiness in order, retiring protocol work before the single terminal outcome.
    fn terminate(&mut self, terminal: SessionEvent, now: Instant) -> Result<(), ProtocolError> {
        if !self.channels.terminal_emitted {
            self.channels.terminal_emitted = true;
            let mut accepted = std::mem::take(&mut self.output);
            accepted.retain(|output| {
                matches!(
                    output,
                    SessionOutput::Message(..) | SessionOutput::Event(SessionEvent::Ready)
                )
            });
            let teardown = self.close_transport(now);
            accepted.append(&mut self.output);
            accepted.push_back(SessionOutput::Event(terminal));
            self.output = accepted;
            teardown?;
        }
        Ok(())
    }
}

impl Session<Established> {
    /// Admits application data only on an owner that reached actual readiness.
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

impl<S: Phase> Session<S> {
    /// Applies the original absolute credential/terminal fence before any input admission.
    fn expire_before_input(&mut self, now: Instant) -> Result<(), ProtocolError> {
        self.ice.expire(now);
        if self.ice.selected_route_failed() {
            self.fail(now)?;
        }
        Ok(())
    }
}

impl<S: Live> Sans for Session<S> {
    type Input = SessionInput;
    type Output = SessionOutput;
    type Error = ProtocolError;

    fn handle(&mut self, msg: SessionInput) -> Result<(), ProtocolError> {
        let now = match &msg {
            SessionInput::Packet(_, _, now)
            | SessionInput::RemoteDescription(_, _, now)
            | SessionInput::RemoteCandidate(_, now)
            | SessionInput::Timeout(now) => *now,
        };
        self.expire_before_input(now)?;
        if self.ice.gathering_state() == GatheringState::Closed {
            return match msg {
                SessionInput::Packet(..) | SessionInput::Timeout(..) => Ok(()),
                _ => Err(IceError::Closed.into()),
            };
        }
        match msg {
            SessionInput::Packet(data, from, now) => self.handle_packet(&data, from, now),
            SessionInput::RemoteDescription(remote, candidates, now) => {
                self.set_remote_description(&remote, candidates, now)
            }
            SessionInput::RemoteCandidate(candidate, now) => {
                self.add_remote_candidate(candidate, now)
            }
            SessionInput::Timeout(now) => self.handle_timeout(now),
        }
    }

    fn poll(&mut self) -> Option<SessionOutput> {
        self.output.pop_front()
    }
}

fn open_channels_if_controlling(
    is_controlling: bool,
    sctp: &mut SctpLayer,
    channels: &mut Channels,
    now: Instant,
) -> Result<(), ProtocolError> {
    if !is_controlling {
        return Ok(());
    }
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    for (stream_id, channel, open) in [
        (RELIABLE_STREAM_ID, Channel::Reliable, dcep::reliable_open()),
        (
            UNRELIABLE_STREAM_ID,
            Channel::Unreliable,
            dcep::unreliable_open(),
        ),
    ] {
        let mut stream = assoc
            .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
        let encoded = dcep::encode_open(open)?;
        stream
            .write_with_ppi(now, &encoded, dcep::PPI_DCEP)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
        channels.set_open(channel, stream_id);
    }

    Ok(())
}

fn drain_dcep_and_data(
    sctp: &mut SctpLayer,
    channels: &mut Channels,
    output: &mut VecDeque<SessionOutput>,
    now: Instant,
) -> Result<(), ProtocolError> {
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    while let Some(mut stream) = assoc.accept_stream() {
        if let Ok(Some(chunks)) = stream.read()
            && let Ok(data) = chunks.to_payload(4096)
            && let Ok(DcepMessage::DataChannelOpen(open)) = dcep::decode(&data)
        {
            let channel = if open.label == dcep::RELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Reliable)
            } else if open.label == dcep::UNRELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Unreliable)
            } else {
                None
            };
            if let Some(channel) = channel {
                let stream_id = stream.stream_identifier();
                let ack = dcep::encode_ack()?;
                stream
                    .write_with_ppi(now, &ack, dcep::PPI_DCEP)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                channels.set_open(channel, stream_id);
            }
        }
    }

    for channel in [Channel::Reliable, Channel::Unreliable] {
        let Some(stream_id) = channels.stream_id(channel) else {
            continue;
        };
        let Ok(mut stream) = assoc.stream(stream_id) else {
            continue;
        };
        while let Ok(Some(chunks)) = stream.read() {
            let is_dcep = matches!(chunks.ppi, PayloadProtocolIdentifier::Dcep);
            let Ok(data) = chunks.to_payload(1 << 20) else {
                continue;
            };

            if is_dcep {
                continue;
            }

            let Ok(segment) = MessageSegment::decode(data.freeze()) else {
                continue;
            };

            match channel {
                Channel::Reliable => match channels.reassembly.add_segment(segment) {
                    Ok(Some(message)) => output
                        .push_back(SessionOutput::Message(Channel::Reliable, message.to_vec())),
                    Ok(None) => {}
                    Err(e) => tracing::debug!("dropping malformed reliable segment: {e}"),
                },
                Channel::Unreliable => {
                    if segment.remaining_segments == 0 {
                        output.push_back(SessionOutput::Message(
                            Channel::Unreliable,
                            segment.data.to_vec(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
