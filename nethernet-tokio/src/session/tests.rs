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

#[test]
fn pending_reliable_delivery_has_explicit_packet_and_byte_limits() {
    use super::backpressure::ReliableBacklog;
    let (sender, _receiver) = mpsc::channel(1);
    sender.try_send(Bytes::from_static(b"full")).unwrap();
    let mut packets = ReliableBacklog::default();
    for _ in 0..PACKET_CHANNEL_CAPACITY {
        packets.deliver(&sender, Bytes::from_static(b"x")).unwrap();
    }
    assert!(
        packets
            .deliver(&sender, Bytes::from_static(b"overflow"))
            .is_err()
    );
    let mut bytes = ReliableBacklog::default();
    let maximum = PACKET_CHANNEL_CAPACITY * nethernet::protocol::constants::MAX_MESSAGE_SIZE;
    bytes
        .deliver(&sender, Bytes::from(vec![0; maximum]))
        .unwrap();
    assert!(
        bytes
            .deliver(&sender, Bytes::from_static(b"overflow"))
            .is_err()
    );
}
