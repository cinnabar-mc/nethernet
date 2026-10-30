use super::*;

/// A platform refusal on one ICE send does not turn ordinary fallback into global policy closure.
#[tokio::test]
async fn socket_permission_denied_preserves_udp_candidate_retry() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ((a, mut a_rx), (b, mut b_rx, _b_unreliable)) = connected_pair_with_send_error(
            None,
            None,
            nethernet::protocol::constants::LOCAL_SCTP_MAX_MESSAGE_SIZE,
            None,
            Some(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        )
        .await;
        a.send(Bytes::from_static(b"retry after platform refusal"))
            .await
            .unwrap();
        assert_eq!(
            b_rx.recv().await.unwrap().unwrap(),
            "retry after platform refusal"
        );
        b.send(Bytes::from_static(b"same live connection"))
            .await
            .unwrap();
        assert_eq!(a_rx.recv().await.unwrap().unwrap(), "same live connection");
        a.sender().close().await.unwrap();
        b.sender().close().await.unwrap();
    })
    .await
    .expect("ordinary OS denial prevented the original actor from retrying ICE");
}
