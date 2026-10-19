//! ICE checks and exact STUN/TURN carrier routes composed from RTC sans-I/O owners.
mod config;
mod route;
mod server;
mod target;
use super::SessionOutput;
use crate::error::ProtocolError;
use crate::protocol::webrtc::certificate;
use bytes::BytesMut;
pub use config::{
    GatheringState, IceConfig, IceError, IcePolicy, IceServer, MAX_ICE_SERVERS,
    MAX_TURN_CREDENTIAL_BYTES, TurnCredentials,
};
pub use route::{MAX_TURN_STREAM_FRAME_BYTES, TurnAddressFamily, TurnStreamId, TurnStreamRoute};
use rtc::ice::agent::agent_config::AgentConfig;
use rtc::ice::agent::{Agent, Credentials, Event};
use rtc::ice::candidate::candidate_host::CandidateHostConfig;
use rtc::ice::candidate::candidate_relay::CandidateRelayConfig;
use rtc::ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use rtc::ice::candidate::{Candidate, CandidateConfig, CandidateType};
use rtc::ice::network_type::NetworkType;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use server::{Server, ServerEvent, context};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
pub use target::{MAX_ICE_URL_BYTES, TurnStreamSecurity, TurnStreamTarget};

pub struct IceLayer {
    agent: Agent,
    host: Candidate,
    local_addr: SocketAddr,
    policy: IcePolicy,
    servers: Vec<Server>,
    gather_deadline: Option<Instant>,
    gathering: GatheringState,
    candidates: Vec<Candidate>,
    discovered: VecDeque<Candidate>,
    writes: VecDeque<TaggedBytesMut>,
    reads: VecDeque<TaggedBytesMut>,
}

impl IceLayer {
    /// Creates the original host-only path.
    pub fn new(
        local_addr: SocketAddr,
        is_controlling: bool,
        now: Instant,
    ) -> Result<Self, ProtocolError> {
        Self::with_config(local_addr, is_controlling, IceConfig::default(), now)
    }

    /// Adds bounded, already-resolved server transaction owners to the existing ICE agent.
    pub fn with_config(
        local_addr: SocketAddr,
        is_controlling: bool,
        config: IceConfig,
        now: Instant,
    ) -> Result<Self, ProtocolError> {
        config.validate(local_addr, now)?;
        let candidate_types = match config.policy {
            IcePolicy::All => vec![
                CandidateType::Host,
                CandidateType::ServerReflexive,
                CandidateType::Relay,
            ],
            IcePolicy::RelayOnly => vec![CandidateType::Relay],
        };
        let agent_config = AgentConfig {
            local_ufrag: rtc::ice::rand::generate_ufrag(),
            local_pwd: rtc::ice::rand::generate_pwd(),
            is_controlling,
            candidate_types,
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            ..Default::default()
        };
        let mut agent = Agent::new(now, Arc::new(agent_config), certificate::crypto_provider()?)
            .map_err(|_| IceError::Server)?;
        let host = CandidateHostConfig {
            base_config: candidate_config(local_addr),
            ..Default::default()
        }
        .new_candidate_host()
        .map_err(|_| IceError::Server)?;
        let mut candidates = Vec::new();
        if config.policy == IcePolicy::All {
            agent
                .add_local_candidate(host.clone())
                .map_err(|_| IceError::Server)?;
            candidates.push(host.clone());
        }
        let gathering = if config.servers.is_empty() {
            GatheringState::Complete
        } else {
            GatheringState::InProgress
        };
        let gather_deadline =
            (gathering == GatheringState::InProgress).then(|| now + config.gather_timeout);
        let servers = config
            .servers
            .into_iter()
            .map(|server| Server::new(local_addr, server, now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            agent,
            host,
            local_addr,
            policy: config.policy,
            servers,
            gather_deadline,
            gathering,
            discovered: candidates.iter().cloned().collect(),
            candidates,
            writes: VecDeque::new(),
            reads: VecDeque::new(),
        })
    }

    pub fn local_credentials(&self) -> &Credentials {
        self.agent.get_local_credentials()
    }

    /// The bound host candidate, retained for legacy host-only callers.
    pub fn local_candidate(&self) -> &Candidate {
        &self.host
    }

    /// Every candidate admitted by this configuration so far.
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// One newly gathered candidate, including the initial host when allowed.
    pub fn poll_local_candidate(&mut self) -> Option<Candidate> {
        self.discovered.pop_front()
    }

    pub fn gathering_state(&self) -> GatheringState {
        self.gathering
    }

    pub fn set_remote_credentials(
        &mut self,
        ufrag: String,
        pwd: String,
    ) -> Result<(), ProtocolError> {
        self.agent
            .set_remote_credentials(ufrag, pwd)
            .map_err(|_| IceError::Server.into())
    }

    /// Ignores unsupported transports and unresolved mDNS hosts, admitting bounded numeric UDP candidates.
    /// mDNS resolution stays at the caller's edge.
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<(), ProtocolError> {
        if self.gathering == GatheringState::Closed {
            return Err(IceError::Closed.into());
        }
        if !matches!(
            candidate.network_type(),
            NetworkType::Udp4 | NetworkType::Udp6
        ) {
            return Ok(());
        }
        if candidate.candidate_type() == CandidateType::Host
            && candidate.address().ends_with(".local")
            && candidate.component() == 1
            && candidate.port() != 0
        {
            return Ok(());
        }
        if self
            .agent
            .get_remote_candidates()
            .iter()
            .any(|existing| existing.equal(&candidate))
        {
            return Ok(());
        }
        if self.agent.get_remote_candidates().len() >= config::MAX_REMOTE_CANDIDATES {
            return Err(IceError::CandidateLimit.into());
        }
        if candidate.component() != 1
            || candidate.address().parse::<std::net::IpAddr>().is_err()
            || candidate.addr().port() == 0
            || candidate.addr().ip().is_unspecified()
            || candidate.addr().ip().is_multicast()
        {
            return Err(IceError::Configuration.into());
        }
        self.agent
            .add_remote_candidate(candidate)
            .map(|_| ())
            .map_err(|_| IceError::Server.into())
    }

    /// Handles outer server datagrams first, then feeds effective relay or direct datagrams into ICE.
    pub fn handle_read(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if self.gathering == GatheringState::Closed {
            return Ok(());
        }
        if data.len() > u16::MAX as usize {
            return Err(IceError::Configuration.into());
        }
        self.advance_servers(now)?;
        if let Some(server) = self
            .servers
            .iter_mut()
            .find(|server| server.addr == from && server.stream_id().is_none())
        {
            server.handle_read(TaggedBytesMut {
                now,
                transport: context(self.local_addr, from),
                message: BytesMut::from(data),
            })?;
            self.drain_servers()?;
        } else if self.policy == IcePolicy::All {
            self.read_effective(TaggedBytesMut {
                now,
                transport: context(self.local_addr, from),
                message: BytesMut::from(data),
            })?;
        }
        Ok(())
    }

    /// Binds the pending slot once to the same connected, verified carrier's actual TCP tuple.
    pub fn activate_stream(
        &mut self,
        id: TurnStreamId,
        route: TurnStreamRoute,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.advance_servers(now)?;
        if self
            .servers
            .iter()
            .any(|server| server.stream_route() == Some(route))
        {
            return Err(IceError::Configuration.into());
        }
        self.servers
            .iter_mut()
            .find(|server| server.stream_id() == Some(id))
            .ok_or(IceError::Configuration)?
            .activate(id, route, now)
    }

    /// A complete TURN frame belongs to its exact configured TCP tuple, independently of UDP sources.
    pub fn handle_stream_read(
        &mut self,
        data: &[u8],
        route: TurnStreamRoute,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if data.len() > MAX_TURN_STREAM_FRAME_BYTES {
            return Err(IceError::Configuration.into());
        }
        self.advance_servers(now)?;
        self.servers
            .iter_mut()
            .find(|server| server.stream_route() == Some(route))
            .ok_or(IceError::Configuration)?
            .handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: route.local(),
                    peer_addr: route.remote(),
                    transport_protocol: TransportProtocol::TCP,
                    ecn: None,
                },
                message: BytesMut::from(data),
            })?;
        self.drain_servers()
    }

    /// Retires a pending or active reservation, returning only its actual route when one existed.
    pub fn close_stream(
        &mut self,
        id: TurnStreamId,
        now: Instant,
    ) -> Result<Option<TurnStreamRoute>, ProtocolError> {
        self.advance_servers(now)?;
        let server = self
            .servers
            .iter_mut()
            .find(|server| server.stream_id() == Some(id))
            .ok_or(IceError::Configuration)?;
        let route = server.stream_route();
        server.retire();
        if let Some(route) = route {
            self.writes.retain(|packet| {
                !(packet.transport.transport_protocol == TransportProtocol::TCP
                    && packet.transport.local_addr == route.local()
                    && packet.transport.peer_addr == route.remote())
            });
        }
        self.drain_servers()?;
        Ok(route)
    }

    /// Sends STUN to the ICE engine and admits media only from a checked pair.
    fn read_effective(&mut self, msg: TaggedBytesMut) -> Result<(), ProtocolError> {
        // Peer checks can precede the answer or its service receipt. RTC retries them;
        // its inbound owner requires remote credentials before touching peer state.
        if self.agent.get_remote_credentials().is_none() {
            return Ok(());
        }
        if is_stun_packet(&msg.message) {
            if self.agent.get_remote_candidates().len() >= config::MAX_REMOTE_CANDIDATES
                && !self
                    .agent
                    .get_remote_candidates()
                    .iter()
                    .any(|candidate| candidate.addr() == msg.transport.peer_addr)
            {
                return Ok(());
            }
            self.agent.handle_read(msg).map_err(|_| IceError::Server)?;
        } else if self.agent.is_valid_non_stun_traffic(msg.now, msg.transport) {
            self.reads.push_back(msg);
        }
        Ok(())
    }

    /// Relayed and direct application datagrams retain their effective path until consumed.
    pub fn poll_read(&mut self) -> Option<TaggedBytesMut> {
        self.reads.pop_front()
    }

    /// Routes according to the local ICE candidate, retaining relay identity until wrapping.
    fn route(&mut self, msg: TaggedBytesMut) -> Result<(), ProtocolError> {
        self.expire(msg.now);
        if let Some(server) = self
            .servers
            .iter_mut()
            .find(|server| server.relay == Some(msg.transport.local_addr))
        {
            server.send(msg)?;
        } else if msg.transport.local_addr == self.local_addr && self.policy == IcePolicy::All {
            self.writes.push_back(msg);
        }
        // A retired allocation's outstanding check is discarded, never sent directly.
        Ok(())
    }

    /// Wraps DTLS on the selected local path, including relay permissions and ChannelData.
    pub fn send_selected(
        &mut self,
        data: Vec<u8>,
        to: SocketAddr,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.expire(now);
        if self.selected_route_failed() {
            return Err(IceError::Closed.into());
        }
        let Some((local, remote)) = self.agent.get_selected_candidate_pair() else {
            return Err(IceError::Server.into());
        };
        if remote.addr() != to {
            return Err(IceError::Server.into());
        }
        let local_addr = local.base_addr();
        self.route(TaggedBytesMut {
            now,
            transport: context(local_addr, to),
            message: BytesMut::from(data.as_slice()),
        })
    }

    /// Drains ICE checks through their candidate routes without erasing RTC's actual outer carrier.
    pub fn poll_write(&mut self) -> Result<Option<SessionOutput>, ProtocolError> {
        self.collect_writes()?;
        self.writes
            .pop_front()
            .map(|msg| {
                let data = msg.message.to_vec();
                match msg.transport.transport_protocol {
                    TransportProtocol::UDP => {
                        Ok(SessionOutput::Send(data, msg.transport.peer_addr))
                    }
                    TransportProtocol::TCP => Ok(SessionOutput::SendStream(
                        data,
                        TurnStreamRoute::new(msg.transport.local_addr, msg.transport.peer_addr)?,
                    )),
                    _ => Err(IceError::Configuration.into()),
                }
            })
            .transpose()
    }

    /// Captures queued transaction metadata before any later credential rotation.
    fn collect_writes(&mut self) -> Result<(), ProtocolError> {
        while let Some(msg) = self.agent.poll_write() {
            self.route(msg)?;
        }
        for server in &mut self.servers {
            while let Some(msg) = server.poll_write()? {
                self.writes.push_back(msg);
            }
        }
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.agent.poll_event().map(|tagged| tagged.event)
    }

    /// Enforces credential, allocation and permission expiry before caller operations use a path.
    pub fn expire(&mut self, now: Instant) {
        for server in &mut self.servers {
            server.expire(now);
        }
        self.prune_retired_candidates();
        self.update_gathering();
    }

    /// Advances gathering and dependency lifetimes using only caller time.
    fn advance_servers(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.gathering == GatheringState::Closed {
            return Ok(());
        }
        for server in &mut self.servers {
            server.handle_timeout(now)?;
        }
        if self.gather_deadline.is_some_and(|deadline| now >= deadline) {
            for server in &mut self.servers {
                server.finish_gathering();
            }
        }
        self.prune_retired_candidates();
        self.update_gathering();
        Ok(())
    }

    /// Publishes successful candidates and re-enters ICE with decoded relay data.
    fn drain_servers(&mut self) -> Result<(), ProtocolError> {
        for index in 0..self.servers.len() {
            while let Some(event) = self.servers[index].poll_event() {
                match event {
                    ServerEvent::Data(msg) => self.read_effective(msg)?,
                    ServerEvent::Candidate(kind, addr) => {
                        if self.gathering != GatheringState::InProgress
                            || (self.policy == IcePolicy::RelayOnly && kind != CandidateType::Relay)
                        {
                            continue;
                        }
                        if addr.port() == 0
                            || addr.ip().is_unspecified()
                            || addr.ip().is_multicast()
                            || (kind == CandidateType::ServerReflexive
                                && addr.is_ipv4() != self.local_addr.is_ipv4())
                        {
                            continue;
                        }
                        if self.candidates.iter().any(|candidate| {
                            candidate.addr() == addr && candidate.candidate_type() == kind
                        }) {
                            continue;
                        }
                        let base_config = candidate_config(addr);
                        let candidate = match kind {
                            CandidateType::ServerReflexive => CandidateServerReflexiveConfig {
                                base_config,
                                rel_addr: self.local_addr.ip().to_string(),
                                rel_port: self.local_addr.port(),
                                url: None,
                            }
                            .new_candidate_server_reflexive(),
                            CandidateType::Relay => {
                                let related =
                                    self.servers[index].related_addr().ok_or(IceError::Server)?;
                                CandidateRelayConfig {
                                    base_config,
                                    rel_addr: related.ip().to_string(),
                                    rel_port: related.port(),
                                    url: None,
                                }
                                .new_candidate_relay()
                            }
                            _ => continue,
                        }
                        .map_err(|_| IceError::Server)?;
                        self.agent
                            .add_local_candidate(candidate.clone())
                            .map_err(|_| IceError::Server)?;
                        self.discovered.push_back(candidate.clone());
                        self.candidates.push(candidate);
                    }
                }
            }
        }
        self.prune_retired_candidates();
        self.update_gathering();
        Ok(())
    }

    /// Stops advertising retired relays; RTC's remaining checks for them are discarded by routing.
    fn prune_retired_candidates(&mut self) {
        let servers = &self.servers;
        let usable = |candidate: &Candidate| {
            candidate.candidate_type() != CandidateType::Relay
                || servers
                    .iter()
                    .any(|server| server.relay == Some(candidate.addr()))
        };
        self.candidates.retain(usable);
        self.discovered.retain(usable);
    }

    /// Finishes after initial operations complete or their common deadline is reached.
    fn update_gathering(&mut self) {
        if self.gathering == GatheringState::InProgress
            && self.servers.iter().all(Server::gathering_complete)
        {
            self.gathering = GatheringState::Complete;
            self.gather_deadline = None;
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.gathering == GatheringState::Closed {
            return Ok(());
        }
        self.advance_servers(now)?;
        self.drain_servers()?;
        self.agent
            .handle_timeout(now)
            .map_err(|_| IceError::Server.into())
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        if self.gathering == GatheringState::Closed {
            return None;
        }
        let agent_timeout = self.agent.poll_timeout();
        self.servers
            .iter_mut()
            .filter_map(Server::poll_timeout)
            .chain([self.gather_deadline, agent_timeout].into_iter().flatten())
            .min()
    }

    pub fn selected_remote_addr(&self) -> Option<SocketAddr> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(_, remote)| remote.addr())
    }

    /// The effective local address for the selected direct or relay path.
    pub fn selected_local_addr(&self) -> Option<SocketAddr> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(local, _)| local.base_addr())
    }

    /// Detects expired or failed selected allocations instead of switching to a direct route.
    pub fn selected_route_failed(&self) -> bool {
        self.agent
            .get_selected_candidate_pair()
            .is_some_and(|(local, _)| {
                local.candidate_type() == CandidateType::Relay
                    && !self
                        .servers
                        .iter()
                        .any(|server| server.relay == Some(local.addr()))
            })
    }

    pub fn update_credentials(
        &mut self,
        addr: SocketAddr,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let mut matches = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, server)| server.addr == addr);
        let index = matches.next().ok_or(IceError::Configuration)?.0;
        if matches.next().is_some() {
            return Err(IceError::Configuration.into());
        }
        self.update_credentials_at(index, credentials, now)
    }

    /// Selects the original stream allocation when multiple carriers use one remote address.
    pub fn update_stream_credentials(
        &mut self,
        route: TurnStreamRoute,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let index = self
            .servers
            .iter()
            .position(|server| server.stream_route() == Some(route))
            .ok_or(IceError::Configuration)?;
        self.update_credentials_at(index, credentials, now)
    }

    /// Preserves original validation and request-key capture before changing one selected owner.
    fn update_credentials_at(
        &mut self,
        index: usize,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.servers[index].validate_replacement(&credentials, now)?;
        self.expire(now);
        // Capture any queued request's old integrity key before a credential rotation.
        self.collect_writes()?;
        self.servers[index].update_credentials(credentials, now)?;
        Ok(())
    }

    /// Releases allocations once; drain best-effort output on each original carrier before dropping.
    pub fn close(&mut self, now: Instant) {
        if self.gathering == GatheringState::Closed {
            return;
        }
        self.writes.clear();
        self.reads.clear();
        self.candidates.clear();
        self.discovered.clear();
        let _ = self.agent.close();
        for server in &mut self.servers {
            self.writes.extend(server.close(now));
        }
        self.gathering = GatheringState::Closed;
        self.gather_deadline = None;
    }
}

/// The common UDP component for every gathered candidate.
fn candidate_config(addr: SocketAddr) -> CandidateConfig {
    CandidateConfig {
        network: "udp".to_string(),
        address: addr.ip().to_string(),
        port: addr.port(),
        component: 1,
        ..Default::default()
    }
}

fn is_stun_packet(data: &[u8]) -> bool {
    rtc::stun::message::is_stun_message(data)
}

#[cfg(test)]
#[path = "ice/host_tests.rs"]
mod host_tests;
