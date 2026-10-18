//! One RTC transaction owner per UDP server; relay handles are borrowed only for an operation.
use super::config::{IceError, IceServer, MAX_REMOTE_CANDIDATES, TurnCredentials};
use crate::error::ProtocolError;
use crate::protocol::webrtc::certificate;
use bytes::BytesMut;
use rtc::ice::candidate::CandidateType;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::attributes::{ATTR_ERROR_CODE, ATTR_MESSAGE_INTEGRITY, ATTR_REALM};
use rtc::stun::error_code::{CODE_STALE_NONCE, CODE_UNAUTHORIZED, ErrorCodeAttribute};
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter, METHOD_ALLOCATE,
    METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH, Message, Method, Setter,
    TransactionId, is_stun_message,
};
use rtc::stun::textattrs::Realm;
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::client::{Client, ClientConfig, Event};
use rtc::turn::proto::lifetime::Lifetime;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

const MAX_PENDING_PACKETS: usize = 64;
const MAX_PENDING_BYTES: usize = 256 * 1024;
const MAX_PERMISSION_ATTEMPTS: u8 = 3;
const MAX_MAINTENANCE_TRANSACTIONS: usize = MAX_REMOTE_CANDIDATES * 2 + 8;

pub(super) enum ServerEvent {
    Candidate(CandidateType, SocketAddr),
    Data(TaggedBytesMut),
}

struct Permission {
    pending: Option<TransactionId>,
    ready: bool,
    attempts: u8,
}

struct TrackedRequest {
    method: Method,
    integrity_key: Vec<u8>,
}

pub(super) struct Server {
    pub addr: SocketAddr,
    pub relay: Option<SocketAddr>,
    pub reflexive: Option<SocketAddr>,
    client: Option<Client>,
    binding: Option<TransactionId>,
    allocating: bool,
    credential_expiry: Option<Instant>,
    allocation_expiry: Option<Instant>,
    initial_credentials: Option<TurnCredentials>,
    realm: Option<String>,
    integrity_key: Option<Vec<u8>>,
    manual_refresh_pending: bool,
    refresh_nonce_retries: u8,
    permissions: HashMap<SocketAddr, Permission>,
    maintenance: HashMap<TransactionId, TrackedRequest>,
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
            allocation_expiry: None,
            initial_credentials,
            realm: None,
            integrity_key: None,
            manual_refresh_pending: false,
            refresh_nonce_retries: 0,
            permissions: HashMap::new(),
            maintenance: HashMap::new(),
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
        let Some(client) = &self.client else {
            return Ok(());
        };
        let mut response = decode_stun(&msg.message);
        let owned = response
            .as_ref()
            .is_some_and(|response| client.has_transaction(&response.transaction_id));
        if owned && let Some(response) = &mut response {
            if matches!(
                response.typ.method,
                METHOD_ALLOCATE | METHOD_CREATE_PERMISSION | METHOD_REFRESH | METHOD_CHANNEL_BIND
            ) {
                let provider = certificate::crypto_provider().map_err(|_| IceError::Server)?;
                if let Some(key) = self
                    .maintenance
                    .get(&response.transaction_id)
                    .map(|request| &request.integrity_key)
                    .or(self.integrity_key.as_ref())
                {
                    if self
                        .maintenance
                        .get(&response.transaction_id)
                        .is_some_and(|request| request.method != response.typ.method)
                    {
                        return Ok(());
                    }
                    // Authentication challenges can omit integrity; all other responses on UDP must verify.
                    if !(authentication_challenge(response)
                        && response.get(ATTR_MESSAGE_INTEGRITY).is_err())
                        && MessageIntegrity::check(response, key, provider.crypto()).is_err()
                    {
                        return Ok(());
                    }
                } else if response.typ.method == METHOD_ALLOCATE && unauthorized(response) {
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
                } else {
                    return Err(IceError::Server);
                }
            }
        }
        if owned && let Some(response) = &response {
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
                } else if response.typ.class == CLASS_ERROR_RESPONSE && !stale_nonce(response) {
                    self.retire();
                    return Ok(());
                }
            }
            self.maintenance.remove(&response.transaction_id);
            if response.typ.method == METHOD_CREATE_PERMISSION
                && response.typ.class == CLASS_ERROR_RESPONSE
                && !self
                    .permissions
                    .values()
                    .any(|permission| permission.pending == Some(response.transaction_id))
            {
                // RTC refreshes all permissions in a single transaction without an event on failure.
                self.retire();
                return Ok(());
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
                        permission.ready = true;
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
                    let request = self.maintenance.remove(&id);
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
                            allowed.ip() == peer.ip() && permission.ready
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
        let peer = msg.transport.peer_addr;
        let relay = self.relay.ok_or(IceError::Server)?;
        if peer.is_ipv4() != relay.is_ipv4() {
            return Err(IceError::Configuration);
        }
        if self
            .permissions
            .get(&peer)
            .is_some_and(|permission| permission.ready)
        {
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
            ready: false,
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
            permission.ready = false;
            permission.attempts = MAX_PERMISSION_ATTEMPTS;
        }
        self.pending
            .retain(|packet| packet.transport.peer_addr != peer);
        self.pending_bytes = self.pending.iter().map(|packet| packet.message.len()).sum();
    }

    /// Tracks silent RTC refresh transactions so timeout cannot leave an expired route selected.
    pub fn poll_write(&mut self) -> Result<Option<TaggedBytesMut>, IceError> {
        let Some(msg) = self.client.as_mut().and_then(|client| client.poll_write()) else {
            return Ok(None);
        };
        if let Some(request) = decode_stun(&msg.message)
            && request.typ.class == CLASS_REQUEST
            && matches!(
                request.typ.method,
                METHOD_ALLOCATE | METHOD_REFRESH | METHOD_CREATE_PERMISSION | METHOD_CHANNEL_BIND
            )
            && request.get(ATTR_MESSAGE_INTEGRITY).is_ok()
        {
            if self.maintenance.len() >= MAX_MAINTENANCE_TRANSACTIONS
                && !self.maintenance.contains_key(&request.transaction_id)
            {
                self.retire();
                return Err(IceError::PendingLimit);
            }
            if let Some(key) = &self.integrity_key {
                self.maintenance
                    .entry(request.transaction_id)
                    .or_insert_with(|| TrackedRequest {
                        method: request.typ.method,
                        integrity_key: key.clone(),
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
        if credentials.valid_until <= now || self.credential_expiry.is_none() {
            return Err(IceError::Credentials);
        }
        let client = self.client.as_mut().ok_or(IceError::Closed)?;
        // Do not accumulate an unbounded stream of caller-triggered refreshes.
        if self.manual_refresh_pending
            || self.relay.is_none()
            || self.allocation_expiry.is_none_or(|expiry| expiry <= now)
            || self
                .maintenance
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

    /// Retires expired credentials or allocations before accepting any more network input.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), IceError> {
        if [self.credential_expiry, self.allocation_expiry]
            .into_iter()
            .flatten()
            .any(|deadline| now >= deadline)
        {
            self.retire();
            return Ok(());
        }
        if let Some(client) = &mut self.client {
            client.handle_timeout(now).map_err(|_| IceError::Server)?;
        }
        self.drain_events(now, None)
    }

    /// The nearest dependency retransmission, refresh, allocation or credential deadline.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        if self.client.is_none() {
            return None;
        }
        [
            self.credential_expiry,
            self.allocation_expiry,
            self.client
                .as_mut()
                .and_then(|client| client.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Emits one best-effort deallocation and immediately relinquishes all state and timers.
    pub fn close(&mut self, now: Instant) -> Vec<TaggedBytesMut> {
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
        self.allocation_expiry = None;
        self.initial_credentials = None;
        self.realm = None;
        self.integrity_key = None;
        self.manual_refresh_pending = false;
        self.refresh_nonce_retries = 0;
        self.permissions.clear();
        self.maintenance.clear();
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

/// A stale nonce is the only refresh error for which RTC can keep and retry the same allocation.
fn stale_nonce(message: &Message) -> bool {
    let mut code = ErrorCodeAttribute::default();
    code.get_from(message).is_ok() && code.code == CODE_STALE_NONCE
}

/// The long-term-authentication handshake permits unsigned 401/438 challenges.
fn authentication_challenge(message: &Message) -> bool {
    message.typ.class == CLASS_ERROR_RESPONSE && (stale_nonce(message) || unauthorized(message))
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
