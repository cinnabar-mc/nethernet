//! HTTP failures retain their dependency cause for caller-owned retry and reporting.
use nethernet_tokio::{HttpSignaling, Signal};
use std::error::Error;

/// A failed signaling request remains inspectable instead of being flattened into a message.
#[tokio::test]
async fn failed_http_signaling_retains_its_request_cause() {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let signaling = HttpSignaling::new("local".into()).unwrap();
    let error = signaling
        .signal(Signal::offer(
            1,
            "synthetic offer".into(),
            format!("http://{address}"),
        ))
        .await
        .unwrap_err();
    assert!(
        error.source().is_some(),
        "HTTP request failure lost its typed source"
    );
    assert!(
        error
            .source()
            .unwrap()
            .downcast_ref::<reqwest::Error>()
            .is_some()
    );
}

/// Bare ICE, credentials and signaling failures remain available to application retry policy.
#[test]
fn dial_classification_uses_structured_causes() {
    use nethernet_tokio::{CallerSignalingError, NetherError, error::SignalingError};
    for failure in [
        NetherError::Ice("fixture ICE failure".into()),
        NetherError::Signaling(SignalingError::CredentialError(
            "fixture credentials".into(),
        )),
        NetherError::Signaling(SignalingError::SendFailed("fixture signaling".into())),
        NetherError::ConnectionClosed,
        NetherError::Other("timeout is only fixture text".into()),
    ] {
        assert!(!failure.is_cancelled());
        assert!(!failure.is_timeout());
    }
    for failure in [
        NetherError::Timeout,
        NetherError::CallerSignaling(CallerSignalingError::TimedOut),
        NetherError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        NetherError::Protocol(nethernet::error::ProtocolError::Io(std::io::Error::from(
            std::io::ErrorKind::TimedOut,
        ))),
    ] {
        assert!(failure.is_timeout());
        assert!(!failure.is_cancelled());
    }
}

/// Caller cancellation remains distinct even when setup could fail in the same poll.
#[tokio::test]
async fn cancelled_setup_is_not_reported_as_a_remote_connection_close() {
    use nethernet_tokio::{ConnectionConfig, NetherClient};
    let config = ConnectionConfig::default();
    config.cancel_token.cancel();
    let signaling = HttpSignaling::new("local".into()).unwrap();
    let error = NetherClient::connect_with(signaling, "http://127.0.0.1:9".into(), config)
        .await
        .err()
        .unwrap();
    assert!(error.is_cancelled());
    assert!(!error.is_timeout());
}

/// HTTP's own request deadline stays recognizable through the signaling error boundary.
#[tokio::test]
async fn request_timeouts_keep_their_typed_cause() {
    use nethernet_tokio::NetherError;
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started, start) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert!(socket.read(&mut [0; 4096]).await.unwrap() > 0);
        started.send(()).unwrap();
        released.await.unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    let signaling = HttpSignaling::with_client("local".into(), client);
    let request = tokio::spawn(async move {
        signaling
            .signal(Signal::offer(
                7,
                "synthetic offer".into(),
                format!("http://{address}"),
            ))
            .await
    });
    start.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let error = request.await.unwrap().unwrap_err();
    assert!(error.is_timeout());
    assert!(matches!(error, NetherError::Http(_)));
    release.send(()).unwrap();
    server.await.unwrap();
}
