use super::*;
use nethernet::connection::IceMode;
use nethernet::session::Session as SansSession;

/// Establishes actual UDP/ICE/DTLS/SCTP channels through the concrete session driver.
async fn connected_pair() -> (
    (Session, SessionReceiver),
    (Session, SessionReceiver, SessionReceiver),
) {
    let sockets = [
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
    ];
    let now = transport_now();
    let (a, a_description) =
        SansSession::new(sockets[0].local_addr().unwrap(), true, 1, now).unwrap();
    let (b, b_description) =
        SansSession::new(sockets[1].local_addr().unwrap(), false, 2, now).unwrap();
    let (mut a, offers) =
        SansConnection::connect(a, a_description, 1, "peer".into(), IceMode::Full);
    let (description, candidates) = SansConnection::parse_offer(&offers[0]).unwrap();
    let (b, answers) = SansConnection::accept(
        b,
        b_description,
        &offers[0],
        description,
        candidates,
        IceMode::Full,
        now,
    )
    .unwrap();
    a.handle(ConnectionInput::Signal(answers[0].clone(), now))
        .unwrap();
    let (a, a_reliable, _a_unreliable, a_ready) =
        Session::spawn(sockets[0].clone(), a, Addr::default(), Addr::default());
    let (b, b_reliable, b_unreliable, b_ready) =
        Session::spawn(sockets[1].clone(), b, Addr::default(), Addr::default());
    a_ready.await.unwrap();
    b_ready.await.unwrap();
    ((a, a_reliable), (b, b_reliable, b_unreliable))
}

#[tokio::test]
async fn a_full_reliable_receiver_keeps_the_session_alive_and_preserves_order() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((sender, _sender_reliable), (receiver, mut reliable, mut unreliable)) =
            connected_pair().await;
        for index in 0..PACKET_CHANNEL_CAPACITY {
            sender
                .send(Bytes::copy_from_slice(&(index as u32).to_be_bytes()))
                .await
                .unwrap();
        }
        while reliable.rx.len() < PACKET_CHANNEL_CAPACITY {
            assert!(!receiver.is_closed().await);
            tokio::task::yield_now().await;
        }
        for index in PACKET_CHANNEL_CAPACITY..PACKET_CHANNEL_CAPACITY + 2 {
            sender
                .send(Bytes::copy_from_slice(&(index as u32).to_be_bytes()))
                .await
                .unwrap();
        }
        sender
            .send_unreliable(Bytes::from_static(b"transport still progresses"))
            .await
            .unwrap();
        assert_eq!(
            unreliable.recv().await.unwrap().unwrap(),
            "transport still progresses"
        );
        assert!(!receiver.is_closed().await);
        // Normal receiver backpressure must retain the two excess messages, in order.
        for index in 0..PACKET_CHANNEL_CAPACITY + 2 {
            assert_eq!(
                reliable.recv().await.unwrap().unwrap().as_ref(),
                &(index as u32).to_be_bytes()
            );
        }
        sender.close().await.unwrap();
        receiver.close().await.unwrap();
    })
    .await
    .expect("backpressured session stalled or lost reliable messages");
}

#[tokio::test]
async fn a_reliable_receive_overflow_delivers_its_accepted_prefix_before_an_error() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
            connected_pair().await;
        let capacity = receive::RELIABLE_PACKET_CAPACITY;
        for index in 0..=capacity {
            sender
                .send(Bytes::copy_from_slice(&(index as u32).to_be_bytes()))
                .await
                .unwrap();
        }
        receiver.closed().await;
        for index in 0..capacity {
            assert_eq!(
                reliable.recv().await.unwrap().unwrap().as_ref(),
                &(index as u32).to_be_bytes()
            );
        }
        assert!(matches!(
            reliable.recv().await,
            Err(NetherError::ReceiveCapacity)
        ));
        assert!(reliable.recv().await.unwrap().is_none());
        sender.close().await.unwrap();
    })
    .await
    .expect("receive overflow failed to retain its accepted prefix and terminal error");
}

#[tokio::test]
async fn local_cancel_and_driver_abort_retain_accepted_data_with_distinct_outcomes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for abort in [false, true] {
            let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
                connected_pair().await;
            let payload = Bytes::from_static(b"accepted before shutdown");
            sender.send(payload.clone()).await.unwrap();
            while reliable.rx.len() == 0 {
                assert!(!receiver.is_closed().await);
                tokio::task::yield_now().await;
            }
            if abort {
                reliable._guard.task.abort();
            } else {
                receiver.close().await.unwrap();
            }
            receiver.closed().await;
            assert_eq!(reliable.recv().await.unwrap().unwrap(), payload);
            if abort {
                assert!(matches!(
                    reliable.recv().await,
                    Err(NetherError::ConnectionClosed)
                ));
            }
            assert!(reliable.recv().await.unwrap().is_none());
            sender.close().await.unwrap();
        }
    })
    .await
    .expect("shutdown lost accepted data or failed to publish its terminal outcome");
}

mod peer;

#[tokio::test]
async fn an_expired_queued_send_is_refused_before_sctp_admission() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
            connected_pair().await;
        let deadline = tokio::time::Instant::now().into_std();
        // Queue directly so the deadline belongs to the driver boundary, not an
        // early check in the public method or a surrounding timeout future.
        let (reply, result) = oneshot::channel();
        sender
            .command_tx
            .send(Command::Send(
                Channel::Reliable,
                Bytes::from_static(b"expired Login"),
                Some(deadline),
                reply,
            ))
            .unwrap();
        assert!(matches!(result.await.unwrap(), Err(NetherError::Timeout)));
        sender
            .send(Bytes::from_static(b"ordinary send"))
            .await
            .unwrap();
        assert_eq!(reliable.recv().await.unwrap().unwrap(), "ordinary send");
        sender
            .send_before(
                Bytes::from_static(b"timely Login"),
                tokio::time::Instant::now().into_std() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(reliable.recv().await.unwrap().unwrap(), "timely Login");
        sender.close().await.unwrap();
        receiver.close().await.unwrap();
    })
    .await
    .expect("send admission deadline regression stalled");
}

#[tokio::test]
async fn accepted_reliable_tail_survives_authenticated_peer_close_before_receiver_eof() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let now = transport_now();
        let (core, description) =
            SansSession::new(socket.local_addr().unwrap(), true, 1, now).unwrap();
        let (mut core, offer) =
            SansConnection::connect(core, description, 1, "peer".into(), IceMode::Full);
        let (mut peer, answer) = peer::Peer::answer(offer[0].data.clone()).await;
        core.handle(ConnectionInput::Signal(
            crate::protocol::Signal::answer(1, answer, "peer".into()),
            transport_now(),
        ))
        .unwrap();
        let (session, mut reliable, _unreliable, mut ready) =
            Session::spawn(socket, core, Addr::default(), Addr::default());
        let mut established = false;
        while !established || !peer.ready() {
            tokio::select! {
                result = &mut ready, if !established => { result.unwrap(); established = true; },
                _ = peer.turn() => {},
            }
        }
        for index in 0..PACKET_CHANNEL_CAPACITY {
            peer.send(index);
            peer.flush().await;
        }
        while reliable.rx.len() < PACKET_CHANNEL_CAPACITY {
            peer.turn().await;
        }
        for index in PACKET_CHANNEL_CAPACITY..PACKET_CHANNEL_CAPACITY + 2 {
            peer.send(index);
        }
        while peer.outstanding() != 0 {
            peer.turn().await;
        }
        assert!(
            !session.is_closed().await,
            "the driver failed before authenticated peer close"
        );
        peer.close_dtls().await;
        session.closed().await;
        for index in 0..PACKET_CHANNEL_CAPACITY + 2 {
            let packet = reliable
                .recv()
                .await
                .unwrap()
                .expect("accepted reliable tail disappeared before ordinary receiver EOF");
            assert_eq!(packet.as_ref(), &(index as u32).to_be_bytes());
        }
        assert!(reliable.recv().await.unwrap().is_none());
    })
    .await
    .expect("finite secured-driver closing-delivery regression stalled");
}
