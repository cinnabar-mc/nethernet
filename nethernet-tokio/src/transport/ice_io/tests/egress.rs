use super::*;
use crate::{EgressPolicy, NetherError};
use futures::FutureExt;

/// A denied live or cleanup datagram never reaches the socket; permitted output still does.
#[tokio::test]
async fn egress_policy_checks_udp_before_live_and_cleanup_writes() {
    let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = peer.local_addr().unwrap();
    let denied =
        IceIo::from(Arc::clone(&local)).with_egress_policy(Some(EgressPolicy::new(|_| false)));
    let error = denied
        .send_datagram(b"denied live", destination)
        .await
        .unwrap_err();
    assert!(
        matches!(error, NetherError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    let mut denied = denied;
    denied.best_effort(SessionOutput::Send(b"denied cleanup".to_vec(), destination));
    let allowed = IceIo::from(local)
        .with_egress_policy(Some(EgressPolicy::new(move |peer| peer == destination)));
    allowed
        .send_datagram(b"permitted", destination)
        .await
        .unwrap();
    let mut bytes = [0; 64];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], b"permitted");
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

/// Refusal precedes both TCP and TLS sockets, including configured gathering targets.
#[tokio::test]
async fn egress_policy_checks_tcp_and_tls_before_connecting() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let policy = EgressPolicy::new(|_| false);
        let (_, client_tls) = tls_pair();
        for security in [TurnStreamSecurity::Tcp, TurnStreamSecurity::Tls { server_name: "localhost".into() }] {
            let target = target(destination, security);
            let deadline = transport_now() + Duration::from_secs(5);
            let result = carrier::Carrier::start(&target, None, None, deadline, Some(&policy));
            assert!(matches!(result, Err(NetherError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied));
            let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let result = IceIo::from(udp).with_egress_policy(Some(policy.clone())).configured(
                &IceConfig::default(), &[target], Some(&client_tls), None, transport_now(), deadline,
            );
            assert!(matches!(result, Err(NetherError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied));
        }
        let target = target(destination, TurnStreamSecurity::Tcp);
        let policy = EgressPolicy::new(move |peer| peer == destination);
        let mut permitted = carrier::Carrier::start(&target, None, None,
            transport_now() + Duration::from_secs(5), Some(&policy)).unwrap();
        let (accepted, event) = tokio::join!(listener.accept(), futures::future::poll_fn(|cx| permitted.poll(cx)));
        let (peer, remote) = accepted.unwrap();
        let carrier::CarrierEvent::Activated(route) = event else { panic!("permitted TCP carrier did not connect"); };
        assert_eq!(route.local(), remote);
        assert_eq!(route.remote(), peer.local_addr().unwrap());
        assert!(listener.accept().now_or_never().is_none(), "a denied attempt opened another connection");
    }).await.unwrap();
}

/// Revocation on the original secured TURN actor preserves accepted data and one typed terminal.
#[tokio::test]
async fn egress_revocation_on_tcp_and_tls_drains_prefix_before_permission_denied() {
    for tls in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            secured_actor_pair(listener, tls, true),
        )
        .await
        .expect("policy revocation did not retire the original secured TURN actor");
    }
}
