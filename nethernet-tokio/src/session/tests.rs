use super::*;
use nethernet::connection::IceMode;
use nethernet::session::Session as SansSession;

/// Establishes actual UDP/ICE/DTLS/SCTP channels through the concrete session driver.
async fn connected_pair() -> (
    (Session, SessionReceiver),
    (Session, SessionReceiver, SessionReceiver),
) {
    connected_pair_with_server_lease(None).await
}

/// Uses the same real pair when its answerer also owns a retained listener reservation.
async fn connected_pair_with_server_lease(
    server: Option<Arc<ServerLease>>,
) -> (
    (Session, SessionReceiver),
    (Session, SessionReceiver, SessionReceiver),
) {
    connected_pair_with_server_signaling(server, None).await
}

/// Keeps the same actual UDP pair when service lifetime belongs to the caller-owned server bridge.
async fn connected_pair_with_server_signaling(
    server: Option<Arc<ServerLease>>,
    signaling: Option<CandidateSignaling>,
) -> (
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
        Session::<Connecting>::spawn(sockets[0].clone(), a, Addr::default(), Addr::default());
    let (b, b_reliable, b_unreliable, b_ready) = match (server, signaling) {
        (Some(lease), Some(signaling)) => Session::<Connecting>::spawn_for_server_with_signaling(
            sockets[1].clone(),
            b,
            Addr::default(),
            Addr::default(),
            lease,
            signaling,
        ),
        (Some(lease), None) => Session::<Connecting>::spawn_for_server(
            sockets[1].clone(),
            b,
            Addr::default(),
            Addr::default(),
            lease,
        ),
        (None, None) => {
            Session::<Connecting>::spawn(sockets[1].clone(), b, Addr::default(), Addr::default())
        }
        (None, Some(_)) => unreachable!("server signaling fixture requires its real lease"),
    };
    let a = a.establish(a_ready.await.unwrap());
    let b = b.establish(b_ready.await.unwrap());
    ((a, a_reliable), (b, b_reliable, b_unreliable))
}

#[tokio::test]
async fn a_ready_server_session_can_transfer_its_accepted_fifo_after_transport_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let lease = ServerLease::new(capacity.clone().try_acquire_owned().unwrap());
        let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
            connected_pair_with_server_lease(Some(lease)).await;
        sender
            .send(Bytes::from_static(b"queued ready peer"))
            .await
            .unwrap();
        while reliable.rx.len() == 0 {
            assert!(!receiver.is_closed().await);
            tokio::task::yield_now().await;
        }
        receiver.sender().close().await.unwrap();
        assert!(
            receiver.accept_from_server(),
            "a ready queued peer must retain its accepted data and terminal"
        );
        assert_eq!(reliable.recv().await.unwrap().unwrap(), "queued ready peer");
        assert!(reliable.recv().await.unwrap().is_none());
        assert_eq!(
            capacity.available_permits(),
            0,
            "transferring a closed receiver does not retire its capacity"
        );
        sender.sender().close().await.unwrap();
    })
    .await
    .expect("queued ready peer lost its accepted FIFO after closure");
}

/// Synchronous retirement uses the existing actor's ordered FIFO and terminal owner.
#[tokio::test]
async fn synchronous_close_retires_retained_handles_after_the_accepted_fifo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
            connected_pair().await;
        let retained = receiver.sender();
        for message in [b"accepted first".as_slice(), b"accepted second".as_slice()] {
            sender.send(Bytes::copy_from_slice(message)).await.unwrap();
        }
        while reliable.rx.len() < 2 {
            assert!(!receiver.is_closed().await);
            tokio::task::yield_now().await;
        }
        receiver.sender().start_close();
        receiver.sender().start_close();
        drop(receiver);
        assert!(retained.is_closed().await);
        assert_eq!(reliable.recv().await.unwrap().unwrap(), "accepted first");
        assert_eq!(reliable.recv().await.unwrap().unwrap(), "accepted second");
        assert!(reliable.recv().await.unwrap().is_none());
        assert!(
            retained
                .send(Bytes::from_static(b"after retirement"))
                .await
                .is_err()
        );
        sender.sender().close().await.unwrap();
    })
    .await
    .expect("synchronous retirement lost accepted data or actor shutdown");
}

#[tokio::test]
async fn concurrent_sends_wait_outside_the_bounded_real_session_command_queue() {
    use futures::poll;
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((sender, _sender_reliable), (receiver, _reliable, _unreliable)) =
            connected_pair().await;
        let queued_commands = sender.queued_commands();
        let mut held = Vec::new();
        for _ in 0..command::COMMAND_CAPACITY * 2 {
            let mut sending = Box::pin(sender.send(Bytes::from_static(b"bounded actual send")));
            assert!(poll!(sending.as_mut()).is_pending());
            held.push(sending);
        }
        assert!(
            queued_commands.await.unwrap() <= command::COMMAND_CAPACITY,
            "concurrent sends must retain excess payloads at their caller, not in an unbounded actor queue"
        );
        drop(held);
        sender.sender().close().await.unwrap();
        receiver.sender().close().await.unwrap();
    })
    .await
    .expect("actual bounded-command fixture failed to establish");
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
        sender.sender().close().await.unwrap();
        receiver.sender().close().await.unwrap();
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
        sender.sender().close().await.unwrap();
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
                receiver.sender().close().await.unwrap();
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
            sender.sender().close().await.unwrap();
        }
    })
    .await
    .expect("shutdown lost accepted data or failed to publish its terminal outcome");
}

use super::test_peer as peer;

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
            .handle()
            .command_tx
            .send(Command::Send(
                Channel::Reliable,
                Bytes::from_static(b"expired Login"),
                Some(deadline),
                reply,
            ))
            .await
            .unwrap();
        assert!(matches!(result.await.unwrap(), Err(NetherError::Timeout)));
        let (reply, result) = oneshot::channel();
        drop(result);
        sender
            .handle()
            .command_tx
            .send(Command::Send(
                Channel::Reliable,
                Bytes::from_static(b"abandoned Login"),
                Some(deadline + Duration::from_secs(5)),
                reply,
            ))
            .await
            .unwrap();
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
        sender.sender().close().await.unwrap();
        receiver.sender().close().await.unwrap();
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
            Session::<Connecting>::spawn(socket, core, Addr::default(), Addr::default());
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

/// The actual caller service closure is an error only after the actor's already accepted reliable FIFO.
#[tokio::test]
async fn caller_server_service_closure_preserves_accepted_fifo_before_one_error() {
    use crate::signaling::caller::server::CallerServerSignaling;
    tokio::time::timeout(Duration::from_secs(10), async {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let lease = ServerLease::new(capacity.clone().try_acquire_owned().unwrap());
        let (bridge, mut driver) =
            CallerServerSignaling::new("server".into(), Default::default()).unwrap();
        let signaling = CandidateSignaling {
            service_closed: Some(bridge.closed()),
            enabled: None,
            within: Duration::from_secs(1),
            adapter: crate::signaling::ServerSignaling::from(bridge).into(),
        };
        let ((sender, _), (receiver, mut reliable, _unreliable)) =
            connected_pair_with_server_signaling(Some(lease), Some(signaling)).await;
        assert!(receiver.accept_from_server());
        for index in 0_u32..3 {
            sender
                .send(Bytes::copy_from_slice(&index.to_be_bytes()))
                .await
                .unwrap();
        }
        while reliable.rx.len() != 3 {
            assert!(!receiver.is_closed().await);
            tokio::task::yield_now().await;
        }
        driver.close();
        receiver.closed().await;
        for index in 0_u32..3 {
            assert_eq!(
                reliable.recv().await.unwrap().unwrap().as_ref(),
                &index.to_be_bytes()
            );
        }
        assert!(matches!(
            reliable.recv().await,
            Err(NetherError::ConnectionClosed)
        ));
        assert!(reliable.recv().await.unwrap().is_none());
        assert_eq!(capacity.available_permits(), 0);
        sender.sender().close().await.unwrap();
    })
    .await
    .expect("actual caller service retirement lost its accepted FIFO");
}

/// Consuming or dropping the unique owner retires the actual actor while other capabilities retain FIFO.
#[tokio::test]
async fn unique_lifecycle_retirement_preserves_receivers_and_revokes_retained_senders() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for consume_close in [false, true] {
            let ((sender, _sender_reliable), (receiver, mut reliable, _unreliable)) =
                connected_pair().await;
            let retained = receiver.sender();
            for payload in [b"first accepted".as_slice(), b"second accepted".as_slice()] {
                sender.send(Bytes::copy_from_slice(payload)).await.unwrap();
            }
            while reliable.rx.len() < 2 {
                assert!(!receiver.is_closed().await);
                tokio::task::yield_now().await;
            }
            let retired = if consume_close {
                Some(receiver.close())
            } else {
                drop(receiver);
                None
            };
            assert!(retained.is_closed().await);
            assert!(
                retained
                    .send(Bytes::from_static(b"after local retirement"))
                    .await
                    .is_err()
            );
            assert_eq!(reliable.recv().await.unwrap().unwrap(), "first accepted");
            assert_eq!(reliable.recv().await.unwrap().unwrap(), "second accepted");
            assert!(reliable.recv().await.unwrap().is_none());
            drop(retired);
            drop(sender.close());
        }
    })
    .await
    .expect("unique lifecycle retirement lost the actual accepted FIFO");
}
