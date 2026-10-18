use super::*;
use futures::StreamExt;
use nethernet::connection::IceMode;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn a_trust_set_on_a_server_over_http_reaches_the_signaler() {
    use crate::signaling::http::server::tests::{post_offer, signed_offer};
    use crate::signaling::http::{HttpServerConfig, HttpSignalingServer};

    let signaling = Arc::new(
        HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), HttpServerConfig::default())
            .await
            .unwrap(),
    );
    let server = NetherServer::bind_with(
        signaling.clone(),
        ConnectionConfig {
            allow_unsigned_answers: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    server.set_token_trust(Some(TokenTrust::Minecraft(Default::default())));

    assert_eq!(
        post_offer(signaling.local_addr(), &signed_offer()).await,
        "HTTP/1.1 401 Unauthorized"
    );
}

/// Waits for the real server's matching ICE response, ignoring unrelated transport packets.
async fn binding_response(
    socket: &UdpSocket,
    server: std::net::SocketAddr,
    request: &rtc::stun::message::Message,
) -> std::io::Result<()> {
    use rtc::stun::message::{CLASS_SUCCESS_RESPONSE, METHOD_BINDING, Message};
    let mut bytes = [0; 65_536];
    loop {
        let (len, sender) = socket.recv_from(&mut bytes).await?;
        if sender != server {
            continue;
        }
        let mut message = Message::new();
        message.raw = bytes[..len].to_vec();
        if message.decode().is_ok()
            && message.typ.class == CLASS_SUCCESS_RESPONSE
            && message.typ.method == METHOD_BINDING
            && message.transaction_id == request.transaction_id
        {
            return Ok(());
        }
    }
}

#[tokio::test]
async fn listener_close_retires_an_answered_connection_still_waiting_for_channels() {
    use crate::session::guard::transport_now;
    use crate::signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
    use nethernet::connection::{Connection, ConnectionInput};
    use nethernet::sans::Sans;
    use nethernet::session::{Session as SansSession, SessionOutput};
    use rtc::stun::message::{CLASS_REQUEST, METHOD_BINDING, Message};

    tokio::time::timeout(Duration::from_secs(10), async {
        let http = HttpSignalingServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            HttpServerConfig {
                signaler: nethernet::prelude::HttpSignalerConfig {
                    token_trust: None,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let url = format!("http://{}", http.local_addr());
        let mut listener = NetherServer::bind_with(
            http,
            ConnectionConfig {
                allow_unsigned_answers: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let now = transport_now();
        let (session, description) =
            SansSession::new(socket.local_addr().unwrap(), true, 31, now).unwrap();
        let (mut connection, offers) =
            Connection::connect(session, description, 41, url.clone(), IceMode::Full);
        let signaling = HttpSignaling::new("pending-peer".into()).unwrap();
        let mut answers = signaling.signals();
        signaling.signal(offers[0].clone()).await.unwrap();
        let answer = answers.next().await.unwrap();
        connection
            .handle(ConnectionInput::Signal(answer, transport_now()))
            .unwrap();
        connection
            .handle(ConnectionInput::Timeout(transport_now()))
            .unwrap();
        let (wire, server) = std::iter::from_fn(|| connection.poll())
            .find_map(|output| match output {
                SessionOutput::Send(bytes, to) => Some((bytes, to)),
                _ => None,
            })
            .expect("the real offerer must emit an ICE connectivity check");
        let mut request = Message::new();
        request.raw = wire.clone();
        request.decode().unwrap();
        assert_eq!(request.typ.class, CLASS_REQUEST);
        assert_eq!(request.typ.method, METHOD_BINDING);
        socket.send_to(&wire, server).await.unwrap();
        binding_response(&socket, server, &request).await.unwrap();
        // Do not feed that response into the client; its DTLS/data channels remain unestablished.
        listener.close().await.unwrap();
        socket.send_to(&wire, server).await.unwrap();
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            binding_response(&socket, server, &request),
        )
        .await;
        assert!(
            !matches!(response, Ok(Ok(()))),
            "a closed listener must retire its original unaccepted ICE session"
        );
    })
    .await
    .expect("finite real pending-server shutdown fixture stalled");
}
