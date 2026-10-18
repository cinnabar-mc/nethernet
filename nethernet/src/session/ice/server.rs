//! One RTC transaction owner per UDP server; relay handles are borrowed only for an operation.
use super::config::{IceError, IceServer, MAX_REMOTE_CANDIDATES, TurnCredentials};
use crate::error::ProtocolError;
use crate::protocol::webrtc::certificate;
use bytes::BytesMut;
use rtc::ice::candidate::CandidateType;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::attributes::{
    ATTR_ERROR_CODE, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_XOR_PEER_ADDRESS,
};
use rtc::stun::error_code::{CODE_STALE_NONCE, CODE_UNAUTHORIZED, ErrorCodeAttribute};
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter,
    METHOD_ALLOCATE, METHOD_BINDING, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_DATA,
    METHOD_REFRESH, Message, Method, Setter, TransactionId, is_stun_message,
};
use rtc::stun::textattrs::Realm;
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::client::{Client, ClientConfig, Event};
use rtc::turn::proto::lifetime::Lifetime;
use rtc::turn::proto::peeraddr::PeerAddress;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const MAX_PENDING_PACKETS: usize = 64;
const MAX_PENDING_BYTES: usize = 256 * 1024;
const MAX_PERMISSION_ATTEMPTS: u8 = 3;
// RFC 8656 section 9 fixes permission lifetime independently of allocation lifetime.
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const MAX_AUTH_ATTRIBUTE_BYTES: usize = 763;
const MAX_SERVER_TRANSACTIONS: usize = MAX_REMOTE_CANDIDATES * 2 + 8;

pub(super) enum ServerEvent {
    Candidate(CandidateType, SocketAddr),
    Data(TaggedBytesMut),
}

struct Permission {
    pending: Option<TransactionId>,
    valid_until: Option<Instant>,
    attempts: u8,
}

struct TrackedRequest {
    method: Method,
    integrity_key: Option<Vec<u8>>,
    permission_peers: Vec<IpAddr>,
    permission_refresh: bool,
}

pub(super) struct Server {
    pub addr: SocketAddr,
    pub relay: Option<SocketAddr>,
    pub reflexive: Option<SocketAddr>,
    client: Option<Client>,
    binding: Option<TransactionId>,
    allocating: bool,
    credential_expiry: Option<Instant>,
    username: Option<String>,
    allocation_expiry: Option<Instant>,
    initial_credentials: Option<TurnCredentials>,
    realm: Option<String>,
    integrity_key: Option<Vec<u8>>,
    manual_refresh_pending: bool,
    refresh_nonce_retries: u8,
    permissions: HashMap<SocketAddr, Permission>,
    requests: HashMap<TransactionId, TrackedRequest>,
    pending: VecDeque<TaggedBytesMut>,
    pending_bytes: usize,
    events: VecDeque<ServerEvent>,
}

impl Server {
    /// Starts one Binding and, for TURN, one allocation using numeric endpoints only.
    pub fn new(local: SocketAddr, config: IceServer, now: Instant) -> Result<Self, ProtocolError> {
        let addr = config.addr();
        let initial_credentials = match config {
            IceServer::Stun(_) => None,
            IceServer::Turn(_, credentials) => Some(credentials),
        };
        let allocation_username = initial_credentials
            .as_ref()
            .map(|credentials| credentials.username.clone());
        let allocating = initial_credentials.is_some();
        let credential_expiry = initial_credentials
            .as_ref()
            .map(|credentials| credentials.valid_until);
        let (username, password) = initial_credentials
            .as_ref()
            .map(|credentials| (credentials.username.clone(), credentials.password.clone()))
            .unwrap_or_default();
        let mut client = Client::new(
            ClientConfig {
                stun_serv_addr: addr.to_string(),
                turn_serv_addr: if allocating {
                    addr.to_string()
                } else {
                    String::new()
                },
                local_addr: local,
                transport_protocol: TransportProtocol::UDP,
                username,
                password,
                ..Default::default()
            },
            certificate::crypto_provider()?,
        )
        .map_err(|_| IceError::Server)?;
        let binding = Some(
            client
                .send_binding_request(now)
                .map_err(|_| IceError::Server)?,
        );
        if allocating {
            client.allocate(now).map_err(|_| IceError::Server)?;
        }
        Ok(Self {
            addr,
            relay: None,
            reflexive: None,
            client: Some(client),
            binding,
            allocating,
            credential_expiry,
            username: allocation_username,
            allocation_expiry: None,
            initial_credentials,
            realm: None,
            integrity_key: None,
            manual_refresh_pending: false,
            refresh_nonce_retries: 0,
            permissions: HashMap::new(),
            requests: HashMap::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            events: VecDeque::new(),
        })
    }

    /// Whether both initial gathering operations have reached a terminal result.
    pub fn gathering_complete(&self) -> bool {
        self.binding.is_none() && !self.allocating
    }

    /// Stops pending gathering without tearing down an allocation already in use.
    pub fn finish_gathering(&mut self) {
        self.binding = None;
        self.allocating = false;
        if self.relay.is_none() {
            self.retire();
        }
    }

    /// Demultiplexes only source-bound server traffic. Unknown transactions never affect lifetime.
    pub fn handle_read(&mut self, mut msg: TaggedBytesMut) -> Result<(), IceError> {
        self.expire(msg.now);
        let Some(client) = &self.client else {
            return Ok(());
        };
        let mut response = decode_stun(&msg.message);
        let mut owned = false;
        if let Some(response) = &mut response {
            if response.typ.class == CLASS_INDICATION {
                // Indications never own a transaction, even if their ID collides with a request.
                if response.typ.method != METHOD_DATA {
                    return Ok(());
                }
            } else {
                let Some(request) = self.requests.get(&response.transaction_id) else {
                    return Ok(());
                };
                // Validate the entire transaction envelope before integrity exemptions or RTC mutation.
                if !client.has_transaction(&response.transaction_id)
                    || !matches!(
                        response.typ.class,
                        CLASS_SUCCESS_RESPONSE | CLASS_ERROR_RESPONSE
                    )
                    || response.typ.method != request.method
                {
                    return Ok(());
                }
                let provider = certificate::crypto_provider().map_err(|_| IceError::Server)?;
                if let Some(key) = &request.integrity_key {
                    let challenge = authentication_challenge(response)
                        && valid_challenge(response, self.realm.as_deref());
                    if !(challenge && response.get(ATTR_MESSAGE_INTEGRITY).is_err())
                        && MessageIntegrity::check(response, key, provider.crypto()).is_err()
                    {
                        return Ok(());
                    }
                    if authentication_challenge(response) && !challenge {
                        return Ok(());
                    }
                } else if request.method == METHOD_ALLOCATE {
                    if !unauthorized(response) || !valid_challenge(response, None) {
                        return Ok(());
                    }
                    let realm =
                        Realm::get_from_as(response, ATTR_REALM).map_err(|_| IceError::Server)?;
                    let credentials = self.initial_credentials.take().ok_or(IceError::Server)?;
                    self.integrity_key = Some(
                        MessageIntegrity::long_term_integrity_key(
                            credentials.username,
                            realm.text.clone(),
                            credentials.password,
                            provider.crypto(),
                        )
                        .map_err(|_| IceError::Server)?,
                    );
                    self.realm = Some(realm.text);
                } else if request.method != METHOD_BINDING {
                    return Ok(());
                }
                owned = true;
                let permission_peers = request.permission_peers.clone();
                if request.permission_refresh
                    && response.typ.class == CLASS_ERROR_RESPONSE
                    && !stale_nonce(response)
                {
                    self.retire();
                    return Ok(());
                }
                // A scheduled permission 438 must reach RTC to install its nonce. RTC retries
                // at its next 120-second refresh, within the existing 300-second admission.
                self.requests.remove(&response.transaction_id);
                if response.typ.method == METHOD_REFRESH {
                    self.manual_refresh_pending = false;
                    if response.typ.class == CLASS_SUCCESS_RESPONSE {
                        self.refresh_nonce_retries = 0;
                        let mut lifetime = Lifetime::default();
                        lifetime.get_from(response).map_err(|_| IceError::Server)?;
                        self.allocation_expiry = msg.now.checked_add(lifetime.0);
                        if lifetime.0.is_zero() || self.allocation_expiry.is_none() {
                            self.retire();
                            return Ok(());
                        }
                    } else if !stale_nonce(response) {
                        self.retire();
                        return Ok(());
                    }
                }
                if response.typ.class == CLASS_SUCCESS_RESPONSE {
                    self.renew_permissions(&permission_peers, msg.now)?;
                }
            }
        }
        // Save the advertised lifetime before RTC consumes its allocation response.
        let lifetime = response
            .as_ref()
            .filter(|response| owned && response.typ.class == CLASS_SUCCESS_RESPONSE)
            .and_then(|response| {
                let mut lifetime = Lifetime::default();
                lifetime.get_from(response).ok().map(|_| lifetime.0)
            });
        let now = msg.now;
        if let Some(response) = &response
            && owned
            && response.typ.method == METHOD_ALLOCATE
            && response.typ.class == CLASS_SUCCESS_RESPONSE
        {
            let mut mapped = XorMappedAddress::default();
            if mapped.get_from(response).is_ok() {
                self.reflexive = Some(SocketAddr::new(mapped.ip, mapped.port));
            }
        }
        let retry_refresh = owned
            && response.as_ref().is_some_and(|response| {
                response.typ.method == METHOD_REFRESH && stale_nonce(response)
            });
        if owned
            && let Some(response) = &response
            && response.typ.class == CLASS_ERROR_RESPONSE
        {
            // RTC logs ChannelBind errors including the untrusted reason. Only its numeric code is needed.
            msg.message = redacted_error(response)?;
        }
        self.client
            .as_mut()
            .ok_or(IceError::Closed)?
            .handle_read(msg)
            .map_err(|_| IceError::Server)?;
        if retry_refresh {
            self.refresh_nonce_retries += 1;
            if self.refresh_nonce_retries > MAX_PERMISSION_ATTEMPTS {
                self.retire();
            } else if let Some(client) = &mut self.client {
                client
                    .refresh_allocations(now)
                    .map_err(|_| IceError::Server)?;
            }
        }
        self.drain_events(now, lifetime)?;
        Ok(())
    }

    /// Converts RTC results into candidates and effective relay datagrams, flushing admitted data after permission.
    fn drain_events(
        &mut self,
        now: Instant,
        lifetime: Option<std::time::Duration>,
    ) -> Result<(), IceError> {
        while let Some(event) = self.client.as_mut().and_then(|client| client.poll_event()) {
            match event {
                Event::BindingResponse(id, addr) if self.binding == Some(id) => {
                    self.binding = None;
                    self.reflexive = Some(addr);
                    self.events
                        .push_back(ServerEvent::Candidate(CandidateType::ServerReflexive, addr));
                }
                Event::BindingError(id, _) if self.binding == Some(id) => {
                    self.binding = None;
                }
                Event::AllocateResponse(_, addr) if self.allocating => {
                    self.allocating = false;
                    self.relay = Some(addr);
                    self.allocation_expiry = lifetime.and_then(|within| now.checked_add(within));
                    if self.allocation_expiry.is_none() {
                        self.retire();
                    } else {
                        self.events
                            .push_back(ServerEvent::Candidate(CandidateType::Relay, addr));
                        if let Some(reflexive) = self.reflexive {
                            self.events.push_back(ServerEvent::Candidate(
                                CandidateType::ServerReflexive,
                                reflexive,
                            ));
                        }
                    }
                }
                Event::AllocateError(..) => {
                    self.allocating = false;
                }
                Event::CreatePermissionResponse(id, peer) => {
                    if let Some(permission) = self.permissions.get_mut(&peer)
                        && permission.pending == Some(id)
                    {
                        permission.pending = None;
                        permission.attempts = 0;
                        permission.valid_until = Some(
                            now.checked_add(PERMISSION_LIFETIME)
                                .ok_or(IceError::Server)?,
                        );
                        self.flush_peer(peer, now)?;
                    }
                }
                Event::CreatePermissionError(id, error) => {
                    let peer = self.permissions.iter().find_map(|(peer, permission)| {
                        (permission.pending == Some(id)).then_some(*peer)
                    });
                    if let Some(peer) = peer {
                        if error == rtc::shared::error::Error::ErrTryAgain
                            && self.permissions[&peer].attempts < MAX_PERMISSION_ATTEMPTS
                        {
                            self.permissions
                                .get_mut(&peer)
                                .ok_or(IceError::Server)?
                                .pending = None;
                            self.request_permission(peer, now)?;
                        } else {
                            self.discard_peer(peer);
                        }
                    }
                }
                Event::TransactionTimeout(id) => {
                    let request = self.requests.remove(&id);
                    if self.binding == Some(id) {
                        self.binding = None;
                    } else if self.allocating {
                        self.allocating = false;
                    } else if let Some(peer) =
                        self.permissions.iter().find_map(|(peer, permission)| {
                            (permission.pending == Some(id)).then_some(*peer)
                        })
                    {
                        self.discard_peer(peer);
                    } else if request.is_some_and(|request| request.method != METHOD_CHANNEL_BIND) {
                        self.retire();
                    }
                }
                Event::DataIndicationOrChannelData(_, peer, data) => {
                    if let Some(relay) = self.relay
                        && self.permissions.iter().any(|(allowed, permission)| {
                            allowed.ip() == peer.ip()
                                && permission.valid_until.is_some_and(|expiry| now < expiry)
                        })
                    {
                        self.events.push_back(ServerEvent::Data(TaggedBytesMut {
                            now,
                            transport: context(relay, peer),
                            message: data,
                        }));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Sends through an existing permission or admits bounded data until its permission completes.
    pub fn send(&mut self, msg: TaggedBytesMut) -> Result<(), IceError> {
        self.expire(msg.now);
        let peer = msg.transport.peer_addr;
        let relay = self.relay.ok_or(IceError::Server)?;
        if peer.is_ipv4() != relay.is_ipv4() {
            return Err(IceError::Configuration);
        }
        // A refused candidate cannot terminate checks for other peers or retain queued data.
        if self.permissions.get(&peer).is_some_and(|permission| {
            permission.attempts >= MAX_PERMISSION_ATTEMPTS
                && permission.pending.is_none()
                && permission.valid_until.is_none()
        }) {
            return Ok(());
        }
        if self.permissions.get(&peer).is_some_and(|permission| {
            permission
                .valid_until
                .is_some_and(|expiry| msg.now < expiry)
        }) {
            return self
                .client
                .as_mut()
                .ok_or(IceError::Closed)?
                .relay(relay)
                .and_then(|mut relay| relay.send_to(msg.now, &msg.message, peer))
                .map_err(|_| IceError::Server);
        }
        if self.pending.len() >= MAX_PENDING_PACKETS
            || msg.message.len() > MAX_PENDING_BYTES.saturating_sub(self.pending_bytes)
        {
            return Err(IceError::PendingLimit);
        }
        self.request_permission(peer, msg.now)?;
        self.pending_bytes += msg.message.len();
        self.pending.push_back(msg);
        Ok(())
    }

    /// Deduplicates in-flight permissions; RTC owns the actual request and retransmissions.
    fn request_permission(&mut self, peer: SocketAddr, now: Instant) -> Result<(), IceError> {
        if self
            .permissions
            .get(&peer)
            .is_some_and(|permission| permission.pending.is_some())
        {
            return Ok(());
        }
        if !self.permissions.contains_key(&peer) && self.permissions.len() >= MAX_REMOTE_CANDIDATES
        {
            return Err(IceError::CandidateLimit);
        }
        let permission = self.permissions.entry(peer).or_insert(Permission {
            pending: None,
            valid_until: None,
            attempts: 0,
        });
        if permission.attempts >= MAX_PERMISSION_ATTEMPTS {
            return Err(IceError::Server);
        }
        permission.attempts += 1;
        permission.pending = self
            .client
            .as_mut()
            .ok_or(IceError::Closed)?
            .relay(self.relay.ok_or(IceError::Server)?)
            .and_then(|mut relay| relay.create_permission(now, peer))
            .map_err(|_| IceError::Server)?;
        Ok(())
    }

    /// Flushes only the peer whose permission completed, retaining queue order for every other peer.
    fn flush_peer(&mut self, peer: SocketAddr, now: Instant) -> Result<(), IceError> {
        let count = self.pending.len();
        for _ in 0..count {
            let Some(mut packet) = self.pending.pop_front() else {
                break;
            };
            if packet.transport.peer_addr == peer {
                self.pending_bytes -= packet.message.len();
                packet.now = now;
                self.send(packet)?;
            } else {
                self.pending.push_back(packet);
            }
        }
        Ok(())
    }

    /// Drops data for a failed peer and keeps its finite attempt counter.
    fn discard_peer(&mut self, peer: SocketAddr) {
        if let Some(permission) = self.permissions.get_mut(&peer) {
            permission.pending = None;
            permission.valid_until = None;
            permission.attempts = MAX_PERMISSION_ATTEMPTS;
        }
        self.pending
            .retain(|packet| packet.transport.peer_addr != peer);
        self.pending_bytes = self.pending.iter().map(|packet| packet.message.len()).sum();
    }

    /// Retains the method, original integrity key and permission scope of every RTC request.
    pub fn poll_write(&mut self) -> Result<Option<TaggedBytesMut>, IceError> {
        let Some(msg) = self.client.as_mut().and_then(|client| client.poll_write()) else {
            return Ok(None);
        };
        if let Some(request) = decode_stun(&msg.message)
            && request.typ.class == CLASS_REQUEST
        {
            if self.requests.len() >= MAX_SERVER_TRANSACTIONS
                && !self.requests.contains_key(&request.transaction_id)
            {
                self.retire();
                return Err(IceError::PendingLimit);
            }
            if let Entry::Vacant(entry) = self.requests.entry(request.transaction_id) {
                let permission_refresh = request.typ.method == METHOD_CREATE_PERMISSION
                    && !self
                        .permissions
                        .values()
                        .any(|permission| permission.pending == Some(request.transaction_id));
                let permission_peers = if matches!(
                    request.typ.method,
                    METHOD_CREATE_PERMISSION | METHOD_CHANNEL_BIND
                ) {
                    permission_peers(&request)?
                } else {
                    Vec::new()
                };
                let integrity_key = if request.get(ATTR_MESSAGE_INTEGRITY).is_ok() {
                    Some(self.integrity_key.clone().ok_or(IceError::Server)?)
                } else {
                    None
                };
                entry.insert(TrackedRequest {
                    method: request.typ.method,
                    integrity_key,
                    permission_peers,
                    permission_refresh,
                });
            }
        }
        Ok(Some(msg))
    }

    /// Returns one result for the ICE owner to consume immediately.
    pub fn poll_event(&mut self) -> Option<ServerEvent> {
        self.events.pop_front()
    }

    /// Replaces credentials in place, preserving the allocation and refreshing its authentication.
    pub fn update_credentials(
        &mut self,
        credentials: TurnCredentials,
        now: Instant,
    ) -> Result<(), IceError> {
        self.validate_replacement(&credentials, now)?;
        self.expire(now);
        let client = self.client.as_mut().ok_or(IceError::Closed)?;
        // Do not accumulate an unbounded stream of caller-triggered refreshes.
        if self.manual_refresh_pending
            || self.relay.is_none()
            || self.allocation_expiry.is_none_or(|expiry| expiry <= now)
            || self
                .requests
                .values()
                .any(|request| request.method == METHOD_REFRESH)
        {
            return Err(IceError::PendingLimit);
        }
        let provider = certificate::crypto_provider().map_err(|_| IceError::Server)?;
        let key = MessageIntegrity::long_term_integrity_key(
            credentials.username.clone(),
            self.realm.clone().ok_or(IceError::Server)?,
            credentials.password.clone(),
            provider.crypto(),
        )
        .map_err(|_| IceError::Server)?;
        client
            .update_credentials(credentials.username, credentials.password)
            .map_err(|_| IceError::Server)?;
        client
            .refresh_allocations(now)
            .map_err(|_| IceError::Server)?;
        self.integrity_key = Some(key);
        self.manual_refresh_pending = true;
        self.credential_expiry = Some(credentials.valid_until);
        Ok(())
    }

    /// Rejects username changes before any allocation, queued transaction or secret is mutated.
    pub fn validate_replacement(
        &self,
        credentials: &TurnCredentials,
        now: Instant,
    ) -> Result<(), IceError> {
        if credentials.valid_until <= now
            || self.username.as_deref() != Some(credentials.username.as_str())
        {
            return Err(IceError::Credentials);
        }
        Ok(())
    }

    /// Bounds permission admission without owning RTC's refresh or retransmission engine.
    fn renew_permissions(&mut self, peers: &[IpAddr], now: Instant) -> Result<(), IceError> {
        let expiry = now
            .checked_add(PERMISSION_LIFETIME)
            .ok_or(IceError::Server)?;
        for (peer, permission) in &mut self.permissions {
            if peers.contains(&peer.ip()) && permission.valid_until.is_some() {
                permission.valid_until = Some(expiry);
            }
        }
        Ok(())
    }

    /// Expires state before every incoming or outgoing use, independently of Timeout ordering.
    pub fn expire(&mut self, now: Instant) {
        if [self.credential_expiry, self.allocation_expiry]
            .into_iter()
            .flatten()
            .chain(
                self.permissions
                    .values()
                    .filter_map(|permission| permission.valid_until),
            )
            .any(|deadline| now >= deadline)
        {
            self.retire();
        }
    }

    /// Advances only the dependency-owned transaction and maintenance timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), IceError> {
        self.expire(now);
        if let Some(client) = &mut self.client {
            client.handle_timeout(now).map_err(|_| IceError::Server)?;
        }
        self.drain_events(now, None)
    }

    /// The nearest dependency retransmission, refresh, allocation or credential deadline.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.client.as_ref()?;
        [
            self.credential_expiry,
            self.allocation_expiry,
            self.client
                .as_mut()
                .and_then(|client| client.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .chain(
            self.permissions
                .values()
                .filter_map(|permission| permission.valid_until),
        )
        .min()
    }

    /// Emits one best-effort deallocation and immediately relinquishes all state and timers.
    pub fn close(&mut self, now: Instant) -> Vec<TaggedBytesMut> {
        self.expire(now);
        let mut packets = Vec::new();
        if let Some(client) = &mut self.client {
            while client.poll_write().is_some() {}
            if let Some(relay) = self.relay
                && let Ok(mut allocation) = client.relay(relay)
            {
                let _ = allocation.close(now);
                while let Some(packet) = client.poll_write() {
                    packets.push(packet);
                }
            }
        }
        self.retire();
        packets
    }

    /// Clears secrets, transactions and data together; no background work survives retirement.
    fn retire(&mut self) {
        self.client = None;
        self.relay = None;
        self.binding = None;
        self.allocating = false;
        self.credential_expiry = None;
        self.username = None;
        self.allocation_expiry = None;
        self.initial_credentials = None;
        self.realm = None;
        self.integrity_key = None;
        self.manual_refresh_pending = false;
        self.refresh_nonce_retries = 0;
        self.permissions.clear();
        self.requests.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        self.events.clear();
    }
}

/// Builds the effective path seen by ICE and DTLS; the outer TURN server stays separate.
pub(super) fn context(local_addr: SocketAddr, peer_addr: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr,
        peer_addr,
        transport_protocol: TransportProtocol::UDP,
        ecn: None,
    }
}

/// Reads only bounded UDP framing metadata; no dependency message Debug or server text is exposed.
fn decode_stun(data: &[u8]) -> Option<Message> {
    if !is_stun_message(data) {
        return None;
    }
    let mut message = Message::new();
    message.raw = data.to_vec();
    message.decode().ok()?;
    Some(message)
}

/// Retains the exact bounded IP scope encoded by RTC, including batched permission refreshes.
fn permission_peers(request: &Message) -> Result<Vec<IpAddr>, IceError> {
    let mut peers = Vec::new();
    for attribute in &request.attributes.0 {
        if attribute.typ != ATTR_XOR_PEER_ADDRESS {
            continue;
        }
        let mut one = Message {
            transaction_id: request.transaction_id,
            ..Default::default()
        };
        one.attributes.0.push(attribute.clone());
        let mut peer = PeerAddress::default();
        peer.get_from(&one).map_err(|_| IceError::Server)?;
        if !peers.contains(&peer.ip) {
            if peers.len() >= MAX_REMOTE_CANDIDATES {
                return Err(IceError::CandidateLimit);
            }
            peers.push(peer.ip);
        }
    }
    Ok(peers)
}

/// A stale nonce is the only refresh error for which RTC can keep and retry the same allocation.
fn stale_nonce(message: &Message) -> bool {
    let mut code = ErrorCodeAttribute::default();
    code.get_from(message).is_ok() && code.code == CODE_STALE_NONCE
}

/// The long-term-authentication handshake permits unsigned 401/438 challenges.
fn authentication_challenge(message: &Message) -> bool {
    message.typ.class == CLASS_ERROR_RESPONSE && (stale_nonce(message) || unauthorized(message))
}

/// Challenges stay in the established realm and carry bounded, nonempty nonce material.
fn valid_challenge(message: &Message, realm: Option<&str>) -> bool {
    let Ok(nonce) = message.get(ATTR_NONCE) else {
        return false;
    };
    let Ok(challenge_realm) = Realm::get_from_as(message, ATTR_REALM) else {
        return false;
    };
    !nonce.is_empty()
        && nonce.len() <= MAX_AUTH_ATTRIBUTE_BYTES
        && !challenge_realm.text.is_empty()
        && challenge_realm.text.len() <= MAX_AUTH_ATTRIBUTE_BYTES
        && realm.is_none_or(|realm| realm == challenge_realm.text)
}

/// Only a 401 allocation challenge is allowed to establish the initial realm and integrity key.
fn unauthorized(message: &Message) -> bool {
    let mut code = ErrorCodeAttribute::default();
    message.typ.class == CLASS_ERROR_RESPONSE
        && code.get_from(message).is_ok()
        && code.code == CODE_UNAUTHORIZED
}

/// Makes an internal decoded copy after integrity validation; never emits altered server bytes on the network.
fn redacted_error(response: &Message) -> Result<BytesMut, IceError> {
    let mut setters: Vec<Box<dyn Setter>> =
        vec![Box::new(response.transaction_id), Box::new(response.typ)];
    for mut attribute in response.attributes.0.iter().cloned() {
        if attribute.typ == ATTR_ERROR_CODE {
            attribute.value.truncate(4);
        }
        setters.push(Box::new(attribute));
    }
    let mut message = Message::new();
    message.build(&setters).map_err(|_| IceError::Server)?;
    Ok(BytesMut::from(message.raw.as_slice()))
}
