//! Server-side admission of an incoming offer: identity check, answer creation and candidate inference.
use crate::connection::{Connection, ConnectionInput, IceMode};
use crate::error::{ProtocolError, SignalErrorCode};
use crate::identity::error::IdentityError;
use crate::identity::{PlayerInfo, SdpIdentity, TokenTrust, validate_sdp};
use crate::protocol::Signal;
use crate::protocol::webrtc::Description;
use crate::sans::Sans;
use crate::session::{Session, SessionInput};
use crate::util::candidate;
use rtc::ice::candidate::Candidate;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

/// Why an offer was refused; `code` gives the signaling error code to send back.
#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("offer description rejected: {0}")]
    Description(ProtocolError),

    #[error("offer identity rejected: {0}")]
    Untrusted(IdentityError),

    #[error("session creation failed: {0}")]
    Session(ProtocolError),

    #[error("answer creation failed: {0}")]
    Answer(ProtocolError),

    #[error("answer signing failed: {0}")]
    Signing(IdentityError),
}

impl AdmissionError {
    pub fn code(&self) -> SignalErrorCode {
        match self {
            Self::Description(_) => SignalErrorCode::FailedToSetRemoteDescription,
            Self::Untrusted(_) => SignalErrorCode::NotLoggedIn,
            Self::Session(_) => SignalErrorCode::FailedToCreatePeerConnection,
            Self::Answer(_) | Self::Signing(_) => SignalErrorCode::FailedToCreateAnswer,
        }
    }
}

/// Server settings applied to every offer: an identity signs answers, token trust authenticates offers.
#[derive(Clone, Copy)]
pub struct OfferPolicy<'a> {
    identity: Option<&'a dyn SdpIdentity>,
    token_trust: Option<&'a TokenTrust>,
    infer_peer_candidates: bool,
    ice_mode: IceMode,
    establish_deadline: Option<Duration>,
}

impl std::fmt::Debug for OfferPolicy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfferPolicy")
            .field("identity", &self.identity.is_some())
            .field("token_trust", &self.token_trust.is_some())
            .field("infer_peer_candidates", &self.infer_peer_candidates)
            .field("ice_mode", &self.ice_mode)
            .field("establish_deadline", &self.establish_deadline)
            .finish()
    }
}

impl<'a> OfferPolicy<'a> {
    pub fn new(ice_mode: IceMode) -> Self {
        Self {
            identity: None,
            token_trust: None,
            infer_peer_candidates: false,
            ice_mode,
            establish_deadline: None,
        }
    }

    /// Time an answered session has to become ready before it fails; the session default applies when unset.
    pub fn with_establish_deadline(mut self, within: Duration) -> Self {
        self.establish_deadline = Some(within);
        self
    }

    /// Uses the supplied signer for the answer's SDP fingerprints.
    pub fn with_identity(mut self, identity: &'a dyn SdpIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_token_trust(mut self, trust: &'a TokenTrust) -> Self {
        self.token_trust = Some(trust);
        self
    }

    /// Adds reflexive candidates from the signaling source address when the offer has no routable host candidate.
    pub fn with_inferred_peer_candidates(mut self, infer: bool) -> Self {
        self.infer_peer_candidates = infer;
        self
    }

    /// Parses the offer and, when token trust is set, validates its identity against it.
    pub fn admit(
        &self,
        offer: &Signal,
        signaled_from: Option<SocketAddr>,
        wall: SystemTime,
    ) -> Result<Admitted<'a>, AdmissionError> {
        let (remote_description, remote_candidates) =
            Connection::parse_offer(offer).map_err(AdmissionError::Description)?;
        let player = match self.token_trust {
            Some(trust) => {
                let claims =
                    validate_sdp(&offer.data, trust, wall).map_err(AdmissionError::Untrusted)?;
                Some(PlayerInfo::new(
                    claims,
                    offer.network_id.clone(),
                    signaled_from,
                ))
            }
            None => None,
        };
        Ok(Admitted {
            policy: *self,
            offer: offer.clone(),
            signaled_from,
            remote_description,
            remote_candidates,
            player,
            wall,
        })
    }
}

/// An offer that passed admission and is ready to be answered.
pub struct Admitted<'a> {
    policy: OfferPolicy<'a>,
    offer: Signal,
    signaled_from: Option<SocketAddr>,
    remote_description: Description,
    remote_candidates: Vec<Candidate>,
    player: Option<PlayerInfo>,
    wall: SystemTime,
}

impl Admitted<'_> {
    pub fn player(&self) -> Option<&PlayerInfo> {
        self.player.as_ref()
    }

    /// Creates an answer using the caller's distinct local SDP origin identifier.
    pub fn answer(
        self,
        local_addr: SocketAddr,
        session_id: u64,
        now: Instant,
    ) -> Result<Answered, AdmissionError> {
        let (mut session, description) =
            Session::new(local_addr, false, session_id, now).map_err(AdmissionError::Session)?;
        let wall = self.wall;
        let prepared = self.prepare(&mut session, description, now, wall, false)?;
        Ok(prepared.finish(session, now))
    }

    /// Prepares an answer while the caller retains its configured/gathered session allocation.
    /// Rechecks offer trust and signs at the supplied current wall time after asynchronous gathering.
    /// On error the caller still owns the session and must close/drain its allocation outputs.
    /// Description must be the original description returned with this same session.
    pub fn prepare_answer(
        self,
        session: &mut Session,
        description: Description,
        now: Instant,
        wall: SystemTime,
    ) -> Result<PreparedAnswer, AdmissionError> {
        self.prepare(session, description, now, wall, true)
    }

    /// Shares remote-description, fingerprint/signing and establishment preparation for either edge.
    fn prepare(
        mut self,
        session: &mut Session,
        description: Description,
        now: Instant,
        wall: SystemTime,
        recheck: bool,
    ) -> Result<PreparedAnswer, AdmissionError> {
        if recheck && let Some(trust) = self.policy.token_trust {
            let claims =
                validate_sdp(&self.offer.data, trust, wall).map_err(AdmissionError::Untrusted)?;
            self.player = Some(PlayerInfo::new(
                claims,
                self.offer.network_id.clone(),
                self.signaled_from,
            ));
        }
        if let Some(within) = self.policy.establish_deadline {
            session.set_establish_deadline(within);
        }
        let remote_identity = self.remote_description.identity.clone();
        session
            .handle(SessionInput::RemoteDescription(
                self.remote_description,
                self.remote_candidates,
                now,
            ))
            .map_err(AdmissionError::Answer)?;
        let mut signals =
            Connection::answer_signals(session, &description, &self.offer, self.policy.ice_mode);
        if let (Some(identity), Some(answer)) = (self.policy.identity, signals.first_mut()) {
            answer.data = identity
                .augment(&answer.data, wall)
                .map_err(AdmissionError::Signing)?;
        }
        let candidates = Connection::take_described_candidates(session);
        Ok(PreparedAnswer {
            candidates,
            description,
            remote_identity,
            offer: self.offer,
            signaled_from: self.signaled_from,
            ice_mode: self.policy.ice_mode,
            infer: self.policy.infer_peer_candidates,
            signals,
            player: self.player,
        })
    }
}

/// Fallible answer preparation completed while the caller still owns its original session.
/// Transfer that same session synchronously with finish; no I/O, clock read or new key occurs here.
pub struct PreparedAnswer {
    candidates: usize,
    description: Description,
    remote_identity: Option<String>,
    offer: Signal,
    signaled_from: Option<SocketAddr>,
    ice_mode: IceMode,
    infer: bool,
    signals: Vec<Signal>,
    player: Option<PlayerInfo>,
}

impl PreparedAnswer {
    /// Adopts the exact prepared session once, without another fallible ownership or cancellation gap.
    pub fn finish(self, session: Session, now: Instant) -> Answered {
        let local_ufrag = self.description.ice.ufrag.clone();
        let mut connection = Connection::accepted(
            session,
            self.description,
            &self.offer,
            self.remote_identity,
            self.ice_mode,
            self.candidates,
        );
        let mut inferred = Vec::new();
        if self.infer && !candidate::has_routable_host_candidate(&self.offer.data) {
            for line in candidate::inferred_peer_candidates(&self.offer.data, self.signaled_from) {
                let signal = Signal::candidate(
                    self.offer.connection_id,
                    line.clone(),
                    self.offer.network_id.clone(),
                );
                if connection
                    .handle(ConnectionInput::Signal(signal, now))
                    .is_ok()
                {
                    inferred.push(line);
                }
            }
        }
        Answered {
            connection,
            signals: self.signals,
            player: self.player,
            local_ufrag,
            inferred,
        }
    }
}

/// The accepted connection and the signals to send back.
pub struct Answered {
    pub connection: Connection,

    /// The answer, followed by the local candidate in trickle mode.
    pub signals: Vec<Signal>,

    pub player: Option<PlayerInfo>,

    /// Local ICE username fragment, which STUN packets from the peer carry.
    pub local_ufrag: String,

    /// Candidate lines added from the signaling source address.
    pub inferred: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ServerIdentity;
    use crate::protocol::SignalType;
    use std::net::{Ipv4Addr, SocketAddr};

    const CONNECTION_ID: u64 = 42;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    fn public_peer() -> SocketAddr {
        "93.184.216.34:19132".parse().unwrap()
    }

    fn loopback_offer() -> Signal {
        let (session, description) =
            Session::new(loopback(40300), true, 1, Instant::now()).unwrap();
        let (_, signals) = Connection::connect(
            session,
            description,
            CONNECTION_ID,
            "peer".to_string(),
            IceMode::Full,
        );
        signals.into_iter().next().unwrap()
    }

    fn test_identity() -> ServerIdentity {
        ServerIdentity::generate("example.test", SystemTime::now()).unwrap()
    }

    #[test]
    fn an_answer_carries_a_valid_identity() {
        let identity = test_identity();
        let policy = OfferPolicy::new(IceMode::Full).with_identity(&identity);
        let answered = policy
            .admit(&loopback_offer(), None, SystemTime::now())
            .unwrap()
            .answer(loopback(40301), 2, Instant::now())
            .unwrap();
        let answer = &answered.signals[0];
        assert_eq!(answer.signal_type, SignalType::Answer);
        assert!(validate_sdp(&answer.data, &TokenTrust::Any, SystemTime::now()).is_ok());
    }

    #[test]
    fn an_unsigned_offer_is_not_logged_in() {
        let policy = OfferPolicy::new(IceMode::Full).with_token_trust(&TokenTrust::Any);
        let error = policy
            .admit(&loopback_offer(), None, SystemTime::now())
            .err()
            .expect("an unsigned offer must be rejected");
        assert_eq!(error.code(), SignalErrorCode::NotLoggedIn);
    }

    #[test]
    fn candidates_are_inferred_for_a_loopback_offer() {
        let policy = OfferPolicy::new(IceMode::Full).with_inferred_peer_candidates(true);
        let answered = policy
            .admit(&loopback_offer(), Some(public_peer()), SystemTime::now())
            .unwrap()
            .answer(loopback(40302), 2, Instant::now())
            .unwrap();
        assert!(
            answered
                .inferred
                .iter()
                .all(|line| line.contains("93.184.216.34")),
            "inferred candidates must name the signaled address"
        );
        assert!(!answered.inferred.is_empty(), "nothing was inferred");
    }

    #[test]
    fn nothing_is_inferred_when_disabled() {
        let policy = OfferPolicy::new(IceMode::Full).with_inferred_peer_candidates(false);
        let answered = policy
            .admit(&loopback_offer(), Some(public_peer()), SystemTime::now())
            .unwrap()
            .answer(loopback(40303), 2, Instant::now())
            .unwrap();
        assert!(answered.inferred.is_empty());
    }

    /// Post-gather admission uses the caller's current wall time while preserving its session on refusal.
    #[test]
    fn prepared_answer_rechecks_offer_expiry_before_transferring_the_session() {
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let identity =
            ServerIdentity::generate_with_expiry("fixture", wall, Some(Duration::from_secs(1)))
                .unwrap();
        let mut offer = loopback_offer();
        offer.data = identity.augment(&offer.data, wall).unwrap();
        let trust = TokenTrust::Any;
        let policy = OfferPolicy::new(IceMode::Full).with_token_trust(&trust);
        let admitted = policy.admit(&offer, None, wall).unwrap();
        let now = Instant::now();
        let (mut core, description) = Session::new(loopback(40309), false, 9, now).unwrap();
        let candidates = core.local_candidates().len();
        let error = admitted
            // The existing token policy permits sixty seconds of clock skew after expiry.
            .prepare_answer(&mut core, description, now, wall + Duration::from_secs(62))
            .err()
            .expect("original offer expired during gathering");
        assert!(matches!(error, AdmissionError::Untrusted(_)));
        assert_eq!(core.local_candidates().len(), candidates);
        core.close(now).unwrap();
    }

    /// Prepared answer adoption signs the original DTLS fingerprints and keeps exact offer routing.
    #[test]
    fn prepared_answer_adopts_the_original_description_and_connection_tuple() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let identity = test_identity();
        let offer = loopback_offer();
        let admitted = OfferPolicy::new(IceMode::Full)
            .with_identity(&identity)
            .admit(&offer, None, wall)
            .unwrap();
        let (mut core, description) =
            Session::new_with_ice(loopback(40310), false, 10, Default::default(), now).unwrap();
        let fingerprints =
            crate::identity::sdp_fingerprints(&description.encode_full(core.local_candidates()))
                .unwrap();
        let prepared = admitted
            .prepare_answer(&mut core, description, now, wall)
            .unwrap();
        let mut answered = prepared.finish(core, now);
        assert_eq!(answered.signals[0].connection_id, offer.connection_id);
        assert_eq!(answered.signals[0].network_id, offer.network_id);
        assert_eq!(
            crate::identity::sdp_fingerprints(&answered.signals[0].data).unwrap(),
            fingerprints
        );
        assert!(
            crate::identity::verify_answer(&answered.signals[0].data, Some(&TokenTrust::Any), wall)
                .is_ok()
        );
        answered.connection.close(now).unwrap();
    }
}
