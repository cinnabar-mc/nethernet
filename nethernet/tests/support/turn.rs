//! Original finite TURN peer for transport tests; only RTC codecs perform STUN/TURN framing.
use rtc::stun::attributes::*;
use rtc::stun::error_code::{CODE_FORBIDDEN, CODE_STALE_NONCE, CODE_UNAUTHORIZED};
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::*;
use rtc::stun::textattrs::{Nonce, Realm, Username};
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::proto::{
    chandata::ChannelData, channum::ChannelNumber, data::Data, lifetime::Lifetime,
    peeraddr::PeerAddress, relayaddr::RelayedAddress,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const USER: &str = "original-test-user";
pub const PASSWORD: &str = "original-test-password";
const REALM: &str = "original-test.invalid";
const INITIAL_NONCE: &str = "original-test-nonce";
const RENEWED_NONCE: &str = "original-test-renewed-nonce";

struct Allocation {
    relay: SocketAddr,
    nonce: String,
    permissions: HashSet<IpAddr>,
    channels: HashMap<u16, SocketAddr>,
}

pub struct TurnPeer {
    pub addr: SocketAddr,
    pub packets: VecDeque<(SocketAddr, Vec<u8>)>,
    pub drop_bindings: bool,
    pub drop_permissions: bool,
    pub refuse_permissions_for: Option<IpAddr>,
    pub permission_refusals: usize,
    pub indications: usize,
    pub channel_data: usize,
    pub refreshes: usize,
    pub stale_permissions_once: bool,
    pub stale_permission_responses: usize,
    pub renewed_nonce_permissions: usize,
    allocations: HashMap<SocketAddr, Allocation>,
}

impl TurnPeer {
    /// A UDP endpoint whose packets are delivered explicitly by the test's caller.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            packets: VecDeque::new(),
            drop_bindings: false,
            drop_permissions: false,
            refuse_permissions_for: None,
            permission_refusals: 0,
            indications: 0,
            channel_data: 0,
            refreshes: 0,
            stale_permissions_once: false,
            stale_permission_responses: 0,
            renewed_nonce_permissions: 0,
            allocations: HashMap::new(),
        }
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// Processes one finite datagram; no socket, DNS or timer exists in this test peer.
    pub fn receive(&mut self, from: SocketAddr, data: Vec<u8>) {
        if ChannelData::is_channel_data(&data) {
            let mut channel = ChannelData {
                raw: data,
                ..Default::default()
            };
            channel.decode().unwrap();
            let allocation = &self.allocations[&from];
            let peer = allocation.channels[&channel.number.0];
            self.channel_data += 1;
            self.forward(from, peer, channel.data);
            return;
        }
        let mut request = Message::new();
        request.raw = data;
        request.decode().unwrap();
        assert!(request.typ.class == CLASS_REQUEST || request.typ.class == CLASS_INDICATION);
        if request.typ.method == METHOD_BINDING {
            if self.drop_bindings {
                return;
            }
            self.respond(
                from,
                &request,
                vec![Box::new(XorMappedAddress {
                    ip: from.ip(),
                    port: from.port(),
                })],
                false,
            );
            return;
        }
        if request.typ.method == METHOD_SEND {
            let mut peer = PeerAddress::default();
            peer.get_from(&request).unwrap();
            let mut data = Data::default();
            data.get_from(&request).unwrap();
            self.indications += 1;
            self.forward(from, SocketAddr::new(peer.ip, peer.port), data.0);
            return;
        }
        if request.typ.method == METHOD_ALLOCATE && request.get(ATTR_USERNAME).is_err() {
            let response = encode(vec![
                Box::new(request.transaction_id),
                Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
                Box::new(CODE_UNAUTHORIZED),
                Box::new(Realm::new(ATTR_REALM, REALM.to_string())),
                Box::new(Nonce::new(ATTR_NONCE, INITIAL_NONCE.to_string())),
                Box::new(FINGERPRINT),
            ]);
            self.packets.push_back((from, response));
            return;
        }
        let provider = rtc::crypto::default_provider().unwrap();
        let username = Username::get_from_as(&request, ATTR_USERNAME).unwrap();
        assert_eq!(username.text, USER);
        let key = MessageIntegrity::long_term_integrity_key(
            USER.to_string(),
            REALM.to_string(),
            PASSWORD.to_string(),
            provider.crypto(),
        )
        .unwrap();
        MessageIntegrity::check(&mut request, &key, provider.crypto()).unwrap();
        let nonce = Nonce::get_from_as(&request, ATTR_NONCE).unwrap();
        if let Some(allocation) = self.allocations.get(&from)
            && nonce.text != allocation.nonce
        {
            self.stale_nonce(from, &request);
            return;
        }
        match request.typ.method {
            METHOD_ALLOCATE => {
                // RTC's default allocation request asks for IPv4 even over an IPv6 server transport.
                assert!(request.get(ATTR_REQUESTED_ADDRESS_FAMILY).is_err());
                let port = 50000 + u16::try_from(self.allocations.len()).unwrap();
                let relay = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 80).into(), port);
                self.allocations.insert(
                    from,
                    Allocation {
                        relay,
                        nonce: INITIAL_NONCE.to_owned(),
                        permissions: HashSet::new(),
                        channels: HashMap::new(),
                    },
                );
                self.respond(
                    from,
                    &request,
                    vec![
                        Box::new(RelayedAddress {
                            ip: relay.ip(),
                            port: relay.port(),
                        }),
                        Box::new(XorMappedAddress {
                            ip: from.ip(),
                            port: from.port(),
                        }),
                        Box::new(Lifetime(Duration::from_secs(600))),
                    ],
                    true,
                );
            }
            METHOD_CREATE_PERMISSION => {
                let mut peer = PeerAddress::default();
                peer.get_from(&request).unwrap();
                if self.refuse_permissions_for == Some(peer.ip) {
                    self.permission_refusals += 1;
                    let response = encode(vec![
                        Box::new(request.transaction_id),
                        Box::new(MessageType::new(
                            METHOD_CREATE_PERMISSION,
                            CLASS_ERROR_RESPONSE,
                        )),
                        Box::new(CODE_FORBIDDEN),
                        Box::new(
                            MessageIntegrity::new_long_term_integrity_with_provider(
                                USER.to_owned(),
                                REALM.to_owned(),
                                PASSWORD.to_owned(),
                                provider.crypto(),
                            )
                            .unwrap(),
                        ),
                        Box::new(FINGERPRINT),
                    ]);
                    self.packets.push_back((from, response));
                    return;
                }
                if self.stale_permissions_once {
                    self.stale_permissions_once = false;
                    self.stale_permission_responses += 1;
                    self.allocations.get_mut(&from).unwrap().nonce = RENEWED_NONCE.to_owned();
                    self.stale_nonce(from, &request);
                    return;
                }
                if nonce.text == RENEWED_NONCE {
                    self.renewed_nonce_permissions += 1;
                }
                if self.drop_permissions {
                    return;
                }
                for attribute in &request.attributes.0 {
                    if attribute.typ == ATTR_XOR_PEER_ADDRESS {
                        let mut single = Message::new();
                        single.transaction_id = request.transaction_id;
                        single.add(ATTR_XOR_PEER_ADDRESS, &attribute.value);
                        let mut peer = PeerAddress::default();
                        peer.get_from(&single).unwrap();
                        self.allocations
                            .get_mut(&from)
                            .unwrap()
                            .permissions
                            .insert(peer.ip);
                    }
                }
                self.respond(from, &request, Vec::new(), true);
            }
            METHOD_CHANNEL_BIND => {
                let mut peer = PeerAddress::default();
                peer.get_from(&request).unwrap();
                let mut channel = ChannelNumber::default();
                channel.get_from(&request).unwrap();
                self.allocations
                    .get_mut(&from)
                    .unwrap()
                    .channels
                    .insert(channel.0, SocketAddr::new(peer.ip, peer.port));
                self.respond(from, &request, Vec::new(), true);
            }
            METHOD_REFRESH => {
                self.refreshes += 1;
                let mut lifetime = Lifetime::default();
                lifetime.get_from(&request).unwrap();
                if lifetime.0.is_zero() {
                    self.allocations.remove(&from);
                }
                self.respond(from, &request, vec![Box::new(lifetime)], true);
            }
            _ => panic!("unexpected TURN method"),
        }
    }

    /// Returns an unsigned scoped nonce challenge, preserving the server's allocation.
    fn stale_nonce(&mut self, to: SocketAddr, request: &Message) {
        let nonce = self.allocations[&to].nonce.clone();
        let response = encode(vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, CLASS_ERROR_RESPONSE)),
            Box::new(CODE_STALE_NONCE),
            Box::new(Nonce::new(ATTR_NONCE, nonce)),
            Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
            Box::new(FINGERPRINT),
        ]);
        self.packets.push_back((to, response));
    }

    /// Sends a response, authenticating with the same original test credential as the request.
    fn respond(
        &mut self,
        to: SocketAddr,
        request: &Message,
        attributes: Vec<Box<dyn Setter>>,
        signed: bool,
    ) {
        let provider = rtc::crypto::default_provider().unwrap();
        let mut setters: Vec<Box<dyn Setter + '_>> = attributes;
        setters.insert(
            0,
            Box::new(MessageType::new(request.typ.method, CLASS_SUCCESS_RESPONSE)),
        );
        setters.insert(0, Box::new(request.transaction_id));
        if signed {
            setters.push(Box::new(
                MessageIntegrity::new_long_term_integrity_with_provider(
                    USER.to_string(),
                    REALM.to_string(),
                    PASSWORD.to_string(),
                    provider.crypto(),
                )
                .unwrap(),
            ));
        }
        setters.push(Box::new(FINGERPRINT));
        self.packets.push_back((to, encode(setters)));
    }

    /// Enforces permissions on both allocations, then wraps the effective peer in Data/ChannelData framing.
    fn forward(&mut self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) {
        let source = &self.allocations[&from];
        assert!(source.permissions.contains(&to.ip()));
        let relay = source.relay;
        let Some((recipient, destination)) = self
            .allocations
            .iter()
            .find(|(_, allocation)| allocation.relay == to)
        else {
            return;
        };
        if !destination.permissions.contains(&relay.ip()) {
            return;
        }
        let packet = if let Some((channel, _)) = destination
            .channels
            .iter()
            .find(|(_, peer)| **peer == relay)
        {
            let mut packet = ChannelData {
                number: ChannelNumber(*channel),
                data,
                ..Default::default()
            };
            packet.encode();
            packet.raw
        } else {
            encode(vec![
                Box::new(TransactionId::new()),
                Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
                Box::new(PeerAddress {
                    ip: relay.ip(),
                    port: relay.port(),
                }),
                Box::new(Data(data)),
                Box::new(FINGERPRINT),
            ])
        };
        self.packets.push_back((*recipient, packet));
    }
}

/// Encodes exactly the caller's attributes through the existing RTC STUN codec.
fn encode(setters: Vec<Box<dyn Setter + '_>>) -> Vec<u8> {
    let mut message = Message::new();
    message.build(&setters).unwrap();
    message.raw
}
