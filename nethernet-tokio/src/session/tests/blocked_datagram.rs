use super::*;

/// Close must retire the actual pending actor even while its original UDP output future is blocked.
#[tokio::test]
async fn close_retires_original_pending_udp_output_without_waiting_for_send_capacity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer_socket.local_addr().unwrap();
        let now = transport_now();
        let (core, description) = SansSession::new(local, true, 1, now).unwrap();
        let (peer, peer_description) = SansSession::new(peer_address, false, 2, now).unwrap();
        let (mut core, offers) =
            SansConnection::connect(core, description, 1, "peer".into(), IceMode::Full);
        let (remote, candidates) = SansConnection::parse_offer(&offers[0]).unwrap();
        let (peer, answers) = SansConnection::accept(
            peer,
            peer_description,
            &offers[0],
            remote,
            candidates,
            IceMode::Full,
            now,
        )
        .unwrap();
        core.handle(ConnectionInput::Signal(answers[0].clone(), now))
            .unwrap();
        let mut io = IceIo::from(Arc::new(socket));
        let (entered, release) = io.hold_next_datagram();
        let (session, mut reliable, mut unreliable, ready) =
            Session::<Connecting>::spawn(io, core, Addr::default(), Addr::default());
        let guard = Arc::clone(&session.handle()._guard);
        entered
            .await
            .expect("original actor reached its actual UDP output await");
        let retired = session.close();
        let drained = {
            let draining = async {
                let reliable = reliable.recv().await;
                let unreliable = unreliable.recv().await;
                (reliable, unreliable)
            };
            tokio::pin!(draining);
            let observed = tokio::time::timeout(Duration::from_secs(1), &mut draining).await;
            let closed_without_release = observed.is_ok();
            // A baseline still blocked on UDP must retire before the final behavioral assertion.
            let _ = release.send(());
            let terminals = match observed {
                Ok(terminals) => terminals,
                Err(_) => draining.await,
            };
            (closed_without_release, terminals)
        };
        drop((retired, reliable, unreliable, ready));
        let mut guard = Arc::try_unwrap(guard)
            .ok()
            .expect("fixture released every original actor capability");
        let joined = (&mut guard.task).await;
        drop(guard);
        let (mut peer, peer_closed) = peer.close(transport_now());
        while peer.poll().is_some() {}
        drop((peer, peer_socket));
        let _local_released = UdpSocket::bind(local)
            .await
            .expect("the original actor released its exact UDP socket");
        let _peer_released = UdpSocket::bind(peer_address)
            .await
            .expect("the original peer released its exact UDP socket");
        joined.expect("original actor retired without panic");
        peer_closed.unwrap();
        assert!(matches!(drained.1, (Ok(None), Ok(None))));
        assert!(drained.0, "original close waited for UDP send capacity");
    })
    .await
    .expect("finite blocked UDP retirement fixture stalled");
}
