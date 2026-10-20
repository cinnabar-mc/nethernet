//! Actual readiness carries the installed size facts through ordinary and reserved sends.

use super::*;

#[tokio::test]
async fn negotiated_size_rejects_before_commit_and_keeps_both_original_channels_usable() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let maximum = 64;
        let ((sender, sender_reliable), (receiver, mut reliable, mut unreliable)) =
            connected_pair_with_sctp_limit(None, None, maximum).await;
        let reliable_overflow = (maximum as usize - 1) * usize::from(u8::MAX) + 1;
        let rejected_send = sender.send(Bytes::from(vec![0x71; reliable_overflow])).await;
        let permit = sender.sender().reserve_send(None).await.unwrap();
        let rejected_commit = match permit.commit(Channel::Unreliable, Bytes::from(vec![0x72; maximum as usize])) {
            Err(error) => Some(error),
            Ok(receipt) => {
                let _ = receipt.acknowledged().await;
                None
            }
        };
        let payload = Bytes::from(vec![0x73; 128]);
        let reliable_admission = sender.send(payload.clone()).await;
        let unreliable_payload = Bytes::from(vec![0x74; maximum as usize - 1]);
        let unreliable_admission = sender.send_unreliable(unreliable_payload.clone()).await;
        let marker_admission = sender.send(Bytes::from_static(b"after refusal")).await;
        let first = reliable.recv().await.unwrap();
        let marker = reliable.recv().await.unwrap();
        let unordered = unreliable.recv().await.unwrap();
        let sender_guard = Arc::clone(&sender.handle()._guard);
        let receiver_guard = Arc::clone(&receiver.handle()._guard);
        let sender_closed = sender.sender().close().await;
        let receiver_closed = receiver.sender().close().await;
        drop((sender.close(), receiver.close(), sender_reliable, reliable, unreliable));
        let mut sender_guard = Arc::try_unwrap(sender_guard).ok().expect("original sender owners released");
        let mut receiver_guard = Arc::try_unwrap(receiver_guard).ok().expect("original receiver owners released");
        let sender_joined = (&mut sender_guard.task).await;
        let receiver_joined = (&mut receiver_guard.task).await;
        drop((sender_guard, receiver_guard));

        assert!(sender_closed.is_ok() && receiver_closed.is_ok());
        assert!(sender_joined.is_ok() && receiver_joined.is_ok());
        assert!(reliable_admission.is_ok() && unreliable_admission.is_ok() && marker_admission.is_ok());
        assert_eq!(first, Some(payload));
        assert_eq!(marker.as_deref(), Some(b"after refusal".as_slice()));
        assert_eq!(unordered, Some(unreliable_payload));
        assert!(matches!(rejected_send, Err(NetherError::Protocol(nethernet::error::ProtocolError::MessageSizeExceeded(size))) if size == reliable_overflow));
        assert!(matches!(rejected_commit, Some(NetherError::Protocol(nethernet::error::ProtocolError::MessageSizeExceeded(size))) if size == maximum as usize));
    })
    .await
    .expect("the original negotiated actors did not complete their owned exchange and cleanup");
}
