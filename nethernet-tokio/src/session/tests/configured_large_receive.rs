//! One configured incoming body may cross the retained prefix budget only while it is alone.

use super::*;

/// Actual input, actor retirement and joins precede the large-body delivery oracle.
#[tokio::test]
async fn configured_incoming_body_above_final_queue_budget_keeps_full_delivery() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let incoming = 32 * 1024 * 1024;
        let ((sender, mut reverse), (receiver, mut reliable, unreliable)) =
            connected_pair_with_incoming_limit(
                None,
                None,
                nethernet::protocol::constants::LOCAL_SCTP_MAX_MESSAGE_SIZE,
                Some(incoming),
            )
            .await;
        let sender_guard = Arc::clone(&sender.handle()._guard);
        let receiver_guard = Arc::clone(&receiver.handle()._guard);
        let prefix = Bytes::from_static(b"drain before exclusive body");
        let prefix_admitted = sender.send(prefix.clone()).await;
        let prefix_received = reliable.recv().await;
        let empty_before = reliable.rx.len() == 0;
        let reverse_prefix = Bytes::from_static(b"original reverse channel");
        let reverse_admitted = receiver.send(reverse_prefix.clone()).await;
        let reverse_received = reverse.recv().await;
        let live_before = !sender.is_closed().await && !receiver.is_closed().await;

        let body = Bytes::from(vec![0x61; receive::MAX_ACCEPTED_BYTES + 1]);
        let admitted = sender.send(body.clone()).await;
        let received = if admitted.is_ok() {
            Some(reliable.recv().await)
        } else {
            None
        };
        let received_length = received.as_ref().and_then(|result| result.as_ref().ok()).and_then(|body| body.as_ref().map(Bytes::len));
        let capacity_refused = matches!(&received, Some(Err(NetherError::ReceiveCapacity)));
        let complete = matches!(&received, Some(Ok(Some(received))) if received == &body);
        let suffix = Bytes::from_static(b"credit released after large body pop");
        let reverse_suffix = Bytes::from_static(b"reverse after exclusive body");
        let (suffix_received, reverse_suffix_received) = if complete {
            let suffix_admitted = sender.send(suffix.clone()).await;
            let reverse_suffix_admitted = receiver.send(reverse_suffix.clone()).await;
            let suffix_received = if suffix_admitted.is_ok() {
                Some(reliable.recv().await)
            } else {
                None
            };
            let reverse_suffix_received = if reverse_suffix_admitted.is_ok() {
                Some(reverse.recv().await)
            } else {
                None
            };
            (suffix_received, reverse_suffix_received)
        } else {
            (None, None)
        };
        let sender_closed = sender.sender().close().await;
        let receiver_closed = receiver.sender().close().await;
        let terminal = reliable.recv().await;
        drop((sender.close(), receiver.close(), reverse, reliable, unreliable));
        let mut sender_guard = Arc::try_unwrap(sender_guard)
            .ok()
            .expect("the original sender owners must release their guard");
        let mut receiver_guard = Arc::try_unwrap(receiver_guard)
            .ok()
            .expect("the original receiver owners must release their guard");
        let sender_joined = (&mut sender_guard.task).await;
        let receiver_joined = (&mut receiver_guard.task).await;
        drop((sender_guard, receiver_guard));

        assert!(sender_closed.is_ok() && receiver_closed.is_ok());
        assert!(sender_joined.is_ok() && receiver_joined.is_ok());
        assert!(prefix_admitted.is_ok() && reverse_admitted.is_ok());
        assert!(matches!(prefix_received, Ok(Some(received)) if received == prefix));
        assert!(matches!(reverse_received, Ok(Some(received)) if received == reverse_prefix));
        assert!(empty_before && live_before, "the original FIFO was not empty and live before the body");
        assert!(body.len() <= incoming && admitted.is_ok(), "the real negotiated sender refused the legal body");
        assert!(matches!(terminal, Ok(None)), "the original receiver did not finish after its first outcome");
        assert!(complete || capacity_refused, "the body failed outside the intended final receive capacity owner");
        assert!(
            complete,
            "a configured body of {} bytes was refused with an empty final FIFO: length={received_length:?}, ReceiveCapacity={capacity_refused}",
            body.len()
        );
        assert!(matches!(suffix_received, Some(Ok(Some(received))) if received == suffix));
        assert!(matches!(reverse_suffix_received, Some(Ok(Some(received))) if received == reverse_suffix));
    })
    .await
    .expect("the finite original large-body actors did not exchange and retire");
}
