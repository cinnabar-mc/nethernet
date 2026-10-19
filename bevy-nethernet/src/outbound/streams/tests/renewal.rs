//! Public exact-route renewal over actual colocated UDP and TCP/TLS TURN allocations.

use super::*;
use crate::client::NetherClient;
use crate::http_client::NetherHttpClient;
use crate::server::NetherServer;
use nethernet::prelude::ServerData;
use nethernet::session::{IceServer, TurnStreamRoute};
use std::net::UdpSocket;

struct Colocated {
    stream: Peer,
    udp: UdpSocket,
    datagram: TurnPeer,
}

impl Colocated {
    /// Binds distinct protocols to the same actual numeric endpoint, with the original TURN peer.
    fn new(secure: bool) -> (Self, ClientIceConfig) {
        #[cfg(feature = "tls")]
        let (stream, verifier) = if secure {
            let (server, verifier) = tls_support::self_signed_pair();
            (Peer::new(Security::Tls(server), false), Some(verifier))
        } else {
            (Peer::new(Security::Plain, false), None)
        };
        #[cfg(not(feature = "tls"))]
        let stream = {
            assert!(!secure);
            Peer::new(Security::Plain, false)
        };
        let addr = stream.listener.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).unwrap();
        udp.set_nonblocking(true).unwrap();
        let datagram = TurnPeer::new(addr);
        let mut config = config(&stream, None);
        config.ice.servers.push(IceServer::Turn(addr, fresh()));
        #[cfg(feature = "tls")]
        if let Some(verifier) = verifier {
            config.turn_tls = Some(verifier);
            config.turn_streams[0].security = TurnStreamSecurity::Tls {
                server_name: "localhost".into(),
            };
        }
        (
            Self {
                stream,
                udp,
                datagram,
            },
            config,
        )
    }

    /// Drives the same finite transport/authentication owners; neither allocation is synthesized.
    fn update(&mut self) {
        self.stream.update();
        let mut buffer = [0; 65536];
        for _ in 0..crate::outbound::MAX_DATAGRAMS_PER_UPDATE {
            match self.udp.recv_from(&mut buffer) {
                Ok((size, from)) => self.datagram.receive(from, buffer[..size].to_vec()),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("actual UDP TURN receive failed: {error}"),
            }
        }
        for _ in 0..crate::outbound::MAX_DATAGRAMS_PER_UPDATE {
            let Some((to, packet)) = self.datagram.packets.pop_front() else {
                break;
            };
            self.udp.send_to(&packet, to).unwrap();
        }
    }

    /// Observes the actual accepted TCP tuple after both original authenticated Allocate responses.
    fn gather(&mut self, mut update: impl FnMut() -> bool) -> TurnStreamRoute {
        let cutoff = Instant::now() + Duration::from_secs(5);
        loop {
            self.update();
            let complete = update();
            if complete
                && self.stream.turn.allocation_count() == 1
                && self.datagram.allocation_count() == 1
            {
                break;
            }
            assert!(
                Instant::now() < cutoff,
                "actual colocated allocations did not complete"
            );
            std::thread::yield_now();
        }
        assert_eq!(self.stream.connections.len(), 1);
        TurnStreamRoute::new(
            self.stream.connections[0].remote,
            self.stream.listener.local_addr().unwrap(),
        )
        .unwrap()
    }

    /// Requires a real stream Refresh and leaves the colocated UDP transaction owner untouched.
    fn refreshed(&mut self, mut update: impl FnMut()) {
        let cutoff = Instant::now() + Duration::from_secs(5);
        while self.stream.turn.refreshes == 0 {
            self.update();
            update();
            assert!(
                Instant::now() < cutoff,
                "exact-route Refresh did not reach its original stream"
            );
            std::thread::yield_now();
        }
        // Deliver the original signed response back through the same public frame owner.
        self.update();
        update();
        assert_eq!(self.stream.turn.refreshes, 1);
        assert_eq!(
            self.datagram.refreshes, 0,
            "stream renewal mutated the colocated UDP allocation"
        );
        assert_eq!(self.stream.turn.allocation_count(), 1);
        assert_eq!(self.datagram.allocation_count(), 1);
    }

    /// Advances original best-effort release and observes physical stream retirement, without a fake ACK.
    fn retired(&mut self) {
        let cutoff = Instant::now() + Duration::from_secs(5);
        while self
            .stream
            .connections
            .iter()
            .any(|connection| connection.wire.is_some())
        {
            self.update();
            assert!(
                Instant::now() < cutoff,
                "original TURN stream socket survived client retirement"
            );
            std::thread::yield_now();
        }
    }
}

/// Fresh test credentials preserve the same original username and one absolute admission expiry.
fn fresh() -> TurnCredentials {
    TurnCredentials::new(
        USER.into(),
        PASSWORD.into(),
        Instant::now() + Duration::from_secs(1200),
    )
    .unwrap()
}

/// HTTP remains genuinely in gathering; the route operation never fabricates a selected/Ready peer.
#[test]
fn http_exact_route_refresh_preserves_colocated_udp_and_original_stream() {
    for secure in std::iter::once(false).chain(cfg!(feature = "tls").then_some(true)) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (mut peer, config) = Colocated::new(secure);
        let addr = peer.udp.local_addr().unwrap();
        let mut client = NetherHttpClient::new();
        client.set_ice_config(Some(config)).unwrap();
        client
            .connect(
                "route-refresh".into(),
                format!("http://{}", listener.local_addr().unwrap()),
            )
            .unwrap();
        let route = peer.gather(|| {
            client.update();
            client.test_gathering_complete()
        });
        assert!(!client.is_connected());
        assert!(client.selected_turn_stream().is_none());
        assert!(
            client.update_turn_credentials(addr, fresh()).is_err(),
            "ambiguous address-only mutation must remain refused"
        );
        client
            .update_turn_stream_credentials(route, fresh())
            .unwrap();
        peer.refreshed(|| client.update());
        client.disconnect();
        peer.retired();
        drop(client);
        drop(listener);
        drop(peer);
    }
}

/// LAN uses original actual discovery and its original connecting core for the same route mutation.
#[test]
fn lan_exact_route_refresh_preserves_colocated_udp_and_original_stream() {
    for secure in std::iter::once(false).chain(cfg!(feature = "tls").then_some(true)) {
        let mut server = NetherServer::new(1, "127.0.0.1:0".parse().unwrap(), |_| {}).unwrap();
        server.set_server_data(ServerData::new("fixture".into(), "fixture".into()));
        let mut client = NetherClient::new(2, |config| {
            config.broadcast_address = Some(server.local_addr().unwrap());
            config.broadcast_interval = Duration::from_millis(20);
        })
        .unwrap();
        let cutoff = Instant::now() + Duration::from_secs(10);
        while !client.discovered().contains_key(&1) {
            server.update();
            client.update();
            assert!(Instant::now() < cutoff, "actual LAN discovery stalled");
            std::thread::yield_now();
        }
        let (mut peer, config) = Colocated::new(secure);
        let addr = peer.udp.local_addr().unwrap();
        client.set_ice_config(Some(config)).unwrap();
        client.connect(1).unwrap();
        let route = peer.gather(|| {
            client.update();
            client.test_gathering_complete()
        });
        assert!(!client.is_connected());
        assert!(client.selected_turn_stream().is_none());
        assert!(
            client.update_turn_credentials(addr, fresh()).is_err(),
            "ambiguous address-only mutation must remain refused"
        );
        client
            .update_turn_stream_credentials(route, fresh())
            .unwrap();
        peer.refreshed(|| client.update());
        client.disconnect();
        peer.retired();
        drop(client);
        drop(server);
        drop(peer);
    }
}
