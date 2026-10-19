use super::*;
use nethernet::connection::IceMode;
use nethernet::session::Session;
use std::collections::VecDeque;

type Outbox = VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn a_second_session_cannot_take_a_claimed_address() {
    let mut router = Router::default();
    router.claim_addr(addr(1), &"victim");
    router.claim_addr(addr(1), &"hostile");

    assert_eq!(router.route(addr(1), &[]), vec!["victim"]);
}

#[test]
fn removing_a_session_leaves_another_sessions_address() {
    let mut router = Router::default();
    router.claim_addr(addr(1), &"victim");
    router.release(&"hostile", "x", Some(addr(1)));

    assert_eq!(router.route(addr(1), &[]), vec!["victim"]);

    router.release(&"victim", "y", Some(addr(1)));
    assert_eq!(router.route(addr(1), &[]), Vec::<&str>::new());
}

const BINDING_RESPONSE: [u8; 20] = [
    0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

fn sorted(mut ids: Vec<&'static str>) -> Vec<&'static str> {
    ids.sort();
    ids
}

#[test]
fn a_hostile_session_that_noted_an_address_first_does_not_hide_the_reply_from_the_victim() {
    let mut router = Router::default();
    router.note_sent(addr(1), &"hostile");
    router.note_sent(addr(1), &"victim");

    let routed = sorted(router.route(addr(1), &BINDING_RESPONSE));
    assert_eq!(routed, vec!["hostile", "victim"]);
}

#[test]
fn a_non_stun_datagram_from_a_provisional_address_reaches_no_session() {
    let mut router = Router::default();
    router.note_sent(addr(1), &"first");
    router.note_sent(addr(1), &"second");

    assert!(router.route(addr(1), b"dtls or sctp bytes").is_empty());
}

#[test]
fn a_selected_session_receives_non_stun_from_its_selected_address() {
    let mut router = Router::default();
    router.note_sent(addr(1), &"hostile");
    router.claim_addr(addr(1), &"victim");

    assert_eq!(router.route(addr(1), b"dtls or sctp bytes"), vec!["victim"]);
}

#[test]
fn releasing_a_session_removes_only_its_own_provisional_membership() {
    let mut router = Router::default();
    router.note_sent(addr(1), &"first");
    router.note_sent(addr(1), &"second");

    router.release(&"second", "x", None);
    assert_eq!(router.route(addr(1), &BINDING_RESPONSE), vec!["first"]);
    router.release(&"first", "y", None);
    assert!(router.route(addr(1), &BINDING_RESPONSE).is_empty());
    assert!(router.provisional.is_empty());
}

struct Peer {
    connection: ActiveConnection,
    router: Router<u8>,
    selected: bool,
    ready: bool,
    local: SocketAddr,
}

impl Peer {
    fn new(connection: Connection, ufrag: String, local: SocketAddr) -> Self {
        let mut router = Router::default();
        router.register_ufrag(ufrag, 0);
        Self {
            connection: ActiveConnection::new(connection),
            router,
            selected: false,
            ready: false,
            local,
        }
    }

    fn pump(&mut self, now: Instant, outbox: &mut Outbox) {
        self.connection
            .handle(ConnectionInput::Timeout(now))
            .unwrap();
        if !self.selected
            && let Some(selected) = self.connection.remote_addr()
        {
            self.selected = true;
            self.router.claim_addr(selected, &0);
        }
        while let Some(output) = self.connection.poll() {
            match output {
                SessionOutput::Send(data, to) => {
                    if !self.selected {
                        self.router.note_sent(to, &0);
                    }
                    outbox.push_back((self.local, to, data));
                }
                SessionOutput::Event(SessionEvent::Ready) => self.ready = true,
                _ => {}
            }
        }
    }

    fn receive(&mut self, from: SocketAddr, data: Vec<u8>, now: Instant) {
        if !self.router.route(from, &data).is_empty() {
            let _ = self
                .connection
                .handle(ConnectionInput::Packet(data.into(), from, now));
        }
    }
}

#[test]
fn two_sessions_become_ready_through_the_shared_socket_routing() {
    let mut now = Instant::now();
    let (client_session, client_description) =
        Session::new(addr(40200), true, rand::random(), now).unwrap();
    let client_ufrag = client_description.ice.ufrag.clone();
    let (client, offers) = Connection::connect(
        client_session,
        client_description,
        7,
        "net".to_string(),
        IceMode::Full,
    );
    let offer = offers.into_iter().next().unwrap();

    let (server_session, server_description) =
        Session::new(addr(40201), false, rand::random(), now).unwrap();
    let server_ufrag = server_description.ice.ufrag.clone();
    let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
    let (server, answers) = Connection::accept(
        server_session,
        server_description,
        &offer,
        remote_description,
        remote_candidates,
        IceMode::Full,
        now,
    )
    .unwrap();
    let answer = answers.into_iter().next().unwrap();

    let mut client = Peer::new(client, client_ufrag, addr(40200));
    client
        .connection
        .handle(ConnectionInput::Signal(answer, now))
        .unwrap();
    let mut server = Peer::new(server, server_ufrag, addr(40201));

    let mut outbox = Outbox::new();
    for _ in 0..5000 {
        client.pump(now, &mut outbox);
        server.pump(now, &mut outbox);
        let progressed = !outbox.is_empty();
        while let Some((from, to, data)) = outbox.pop_front() {
            if to == client.local {
                client.receive(from, data, now);
            } else {
                server.receive(from, data, now);
            }
        }
        if client.ready && server.ready {
            break;
        }
        if !progressed {
            now += Duration::from_millis(5);
        }
    }

    assert!(client.ready, "client never became ready");
    assert!(server.ready, "server never became ready");
}

#[test]
fn two_secured_sessions_share_one_udp_socket_without_delivery_or_retirement_interference() {
    let socket = UdpSocket::bind(addr(0)).unwrap();
    let local = socket.local_addr().unwrap();
    let mut pool = SessionPool::new(socket);
    let mut peers = Vec::new();
    let now = Instant::now();
    for id in 0..2u8 {
        let socket = UdpSocket::bind(addr(0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let remote = socket.local_addr().unwrap();
        let (session, description) = Session::new(local, true, rand::random(), now).unwrap();
        let ufrag = description.ice.ufrag.clone();
        let (connection, offers) = Connection::connect(
            session,
            description,
            u64::from(id),
            "peer".into(),
            IceMode::Full,
        );
        let offer = offers.into_iter().next().unwrap();
        let (session, description) = Session::new(remote, false, rand::random(), now).unwrap();
        let remote_ufrag = description.ice.ufrag.clone();
        let (remote_description, candidates) = Connection::parse_offer(&offer).unwrap();
        let (peer, answers) = Connection::accept(
            session,
            description,
            &offer,
            remote_description,
            candidates,
            IceMode::Full,
            now,
        )
        .unwrap();
        pool.add(id, connection, ufrag).unwrap();
        for answer in answers {
            pool.signal(id, &answer);
        }
        peers.push((socket, Peer::new(peer, remote_ufrag, remote), Vec::new()));
    }
    let mut ready = HashMap::new();
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let explicitly_retired = std::cell::Cell::new(false);
    let mut buffer = [0; 65536];
    // Socket delivery is real; only this test's finite scheduling loop is caller-driven.
    let mut drive = |pool: &mut SessionPool<u8>,
                     peers: &mut Vec<(UdpSocket, Peer, Vec<Vec<u8>>)>,
                     ready: &mut HashMap<u8, Readiness>,
                     received: &mut Vec<(u8, Vec<u8>)>| {
        let now = Instant::now();
        for (socket, peer, messages) in peers {
            while let Ok((size, from)) = socket.recv_from(&mut buffer) {
                peer.receive(from, buffer[..size].to_vec(), now);
            }
            peer.connection
                .handle(ConnectionInput::Timeout(now))
                .unwrap();
            if !peer.selected
                && let Some(addr) = peer.connection.remote_addr()
            {
                peer.selected = true;
                peer.router.claim_addr(addr, &0);
            }
            while let Some(output) = peer.connection.poll() {
                match output {
                    SessionOutput::Send(data, to) => {
                        if !peer.selected {
                            peer.router.note_sent(to, &0);
                        }
                        socket.send_to(&data, to).unwrap();
                    }
                    SessionOutput::SendStream(..) => {
                        panic!("host-only pool emitted stream traffic")
                    }
                    SessionOutput::Event(SessionEvent::Ready) => peer.ready = true,
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                        panic!("shared-socket peer failed")
                    }
                    SessionOutput::Message(_, data) => messages.push(data),
                    SessionOutput::Wait(_) => {}
                }
            }
        }
        let mut events = Vec::new();
        pool.drive(&mut events);
        for PoolEvent {
            id,
            event,
            readiness,
        } in events
        {
            match event {
                PoolUpdate::Ready(_) => {
                    ready.insert(id, readiness);
                }
                PoolUpdate::Failed if explicitly_retired.get() && id == 0 => {}
                PoolUpdate::Failed => panic!("shared-socket client failed"),
                PoolUpdate::Rtt(_) => {}
            }
        }
        while let Some((id, data)) = pool.recv(Channel::Reliable) {
            received.push((id, data.into_vec()));
        }
        while pool.next_event().is_some() {}
        std::thread::yield_now();
    };
    while Instant::now() < deadline
        && (ready.len() != 2 || peers.iter().any(|(_, peer, _)| !peer.ready))
    {
        drive(&mut pool, &mut peers, &mut ready, &mut received);
    }
    assert_eq!(ready.len(), 2);
    assert!(peers.iter().all(|(_, peer, _)| peer.ready));
    // Actual Ready from another entry must not authorize delivery to this peer.
    assert!(
        pool.send(
            0,
            ready.get(&1).unwrap().clone(),
            Channel::Reliable,
            &b"foreign Ready"[..],
        )
        .is_err()
    );
    for id in 0..2u8 {
        pool.send(
            id,
            ready.get(&id).unwrap().clone(),
            Channel::Reliable,
            vec![id; 20 * 1024],
        )
        .unwrap();
        peers[usize::from(id)]
            .1
            .connection
            .send(
                Channel::Reliable,
                vec![id + 10; 20 * 1024].into(),
                Instant::now(),
            )
            .unwrap();
    }
    while Instant::now() < deadline
        && (received.len() != 2 || peers.iter().any(|(_, _, messages)| messages.is_empty()))
    {
        drive(&mut pool, &mut peers, &mut ready, &mut received);
    }
    received.sort_by_key(|(id, _)| *id);
    assert_eq!(
        received,
        vec![(0, vec![10; 20 * 1024]), (1, vec![11; 20 * 1024])]
    );
    assert_eq!(peers[0].2, vec![vec![0; 20 * 1024]]);
    assert_eq!(peers[1].2, vec![vec![1; 20 * 1024]]);
    explicitly_retired.set(true);
    pool.remove(0, ready.get(&0).unwrap().clone());
    pool.send(
        1,
        ready.get(&1).unwrap().clone(),
        Channel::Reliable,
        &b"survivor"[..],
    )
    .unwrap();
    peers[1]
        .1
        .connection
        .send(
            Channel::Reliable,
            (&b"still active"[..]).into(),
            Instant::now(),
        )
        .unwrap();
    // The retired peer's unrelated bytes must not become the survivor's data.
    peers[0].0.send_to(b"retired peer datagram", local).unwrap();
    while Instant::now() < deadline && (received.len() != 3 || peers[1].2.len() != 2) {
        drive(&mut pool, &mut peers, &mut ready, &mut received);
    }
    assert_eq!(received.last(), Some(&(1, b"still active".to_vec())));
    assert_eq!(peers[1].2.last().map(Vec::as_slice), Some(&b"survivor"[..]));
    assert_eq!(peers[0].2.len(), 1);
}
