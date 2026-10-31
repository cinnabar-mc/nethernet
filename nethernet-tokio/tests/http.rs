use futures::{FutureExt, StreamExt};
use nethernet_tokio::signaling::http::HttpSignaling;
use nethernet_tokio::{NetherError, Signal, SignalType};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Reads through the header delimiter and the entire declared body before a fixture responds.
async fn read_request(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut request = Vec::new();
    let header_end = loop {
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break end + 4;
        }
        let mut chunk = [0; 4096];
        let count = reader.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "request ended before its headers");
        request.extend_from_slice(&chunk[..count]);
    };
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
    while request.len() < header_end + length {
        let mut chunk = [0; 4096];
        let count = reader.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "request ended before its body");
        request.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(request).unwrap()
}

/// Fragmentation before both a header and a body cannot make the fixture answer early.
#[tokio::test]
async fn request_capture_waits_for_all_fragments() {
    let (mut sender, mut reader) = tokio::io::duplex(4096);
    let mut capture = Box::pin(read_request(&mut reader));
    sender.write_all(b"POST / HTTP/1.1\r\n").await.unwrap();
    assert!(futures::poll!(capture.as_mut()).is_pending());
    sender
        .write_all(b"Content-Type: application/sdp\r\nContent-Length: 5\r\n\r\nhe")
        .await
        .unwrap();
    assert!(futures::poll!(capture.as_mut()).is_pending());
    sender.write_all(b"llo").await.unwrap();
    assert!(capture.await.ends_with("\r\n\r\nhello"));
}

/// Captures a complete request header and returns a finite, caller-selected HTTP response.
async fn response_server(
    status: u16,
    body: &'static str,
    declared_length: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        let response = format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n{body}"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        request
    });
    (addr, server)
}

#[tokio::test]
async fn status_query_sends_configured_client_information() {
    let body = "{\"name\":\"Server\",\"protocol\":0,\"version\":\"\",\"level\":\"World\",\"players\":1,\"maxPlayers\":8,\"gameType\":0}";
    let (addr, server) = response_server(200, body, body.len()).await;
    let signaling = HttpSignaling::new("1234".into()).unwrap().with_client_info(
        nethernet::signaling::http::join::ClientInfo {
            version: "1.26 +&?".into(),
            protocol: 975,
            platform: 7,
        },
    );
    signaling
        .server_data(&format!("http://{addr}"))
        .await
        .unwrap();
    let request = server.await.unwrap();
    assert!(
        request.starts_with(
            "GET /v1/join?id=1234&platform=7&protocol=975&version=1.26+%2B%26%3F HTTP/1.1\r\n"
        ),
        "{request}"
    );
}

#[tokio::test]
async fn join_status_boundaries_deliver_only_successful_answers() {
    for status in [200, 201, 299, 300, 401, 403, 404, 503] {
        let body = "v=0\r\ns=-\r\n";
        let (addr, server) = response_server(status, body, body.len()).await;
        let signaling = HttpSignaling::new("1234".into()).unwrap();
        let mut signals = signaling.signals();
        let result = signaling
            .signal(Signal::offer(42, "offer".into(), format!("http://{addr}")))
            .await;
        if (200..300).contains(&status) {
            result.unwrap();
            assert_eq!(signals.next().await.unwrap().data, body);
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(&status.to_string())
            );
            assert!(signals.next().now_or_never().is_none());
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn failed_join_reports_the_status_before_reading_the_body() {
    for declared_length in [1, (1 << 20) + 1] {
        let (addr, server) = response_server(403, "", declared_length).await;
        let signaling = HttpSignaling::new("1234".into()).unwrap();
        let mut signals = signaling.signals();
        let error = signaling
            .signal(Signal::offer(42, "offer".into(), format!("http://{addr}")))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("403"), "{error}");
        assert!(signals.next().now_or_never().is_none());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn failed_status_query_reports_the_status_before_reading_the_body() {
    for declared_length in [1, (1 << 20) + 1] {
        let (addr, server) = response_server(503, "", declared_length).await;
        let signaling = HttpSignaling::new("1234".into()).unwrap();
        let error = signaling
            .server_data(&format!("http://{addr}"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("503"), "{error}");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn empty_and_numeric_success_bodies_never_deliver_answers() {
    for (status, body) in [(204, ""), (200, ""), (201, "15"), (299, "15")] {
        let (addr, server) = response_server(status, body, body.len()).await;
        let signaling = HttpSignaling::new("1234".into()).unwrap();
        let mut signals = signaling.signals();
        assert!(
            signaling
                .signal(Signal::offer(42, "offer".into(), format!("http://{addr}")))
                .await
                .is_err()
        );
        assert!(signals.next().now_or_never().is_none());
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn offer_is_answered_by_the_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;

        let answer = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            answer.len(),
            answer
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        request
    });

    let signaling = HttpSignaling::new("1234".to_string()).unwrap();
    assert!(signaling.disable_trickle_ice());

    let mut signals = signaling.signals();
    signaling
        .signal(Signal::offer(
            42,
            "v=0\r\n".to_string(),
            format!("http://{addr}"),
        ))
        .await
        .unwrap();

    let request = server.await.unwrap();
    assert!(
        request.starts_with("POST /v1/join/1234 HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("content-type: application/sdp"),
        "{request}"
    );
    assert!(
        request.contains("user-agent: libhttpclient/1.0.0.0"),
        "{request}"
    );

    let signal = tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("answer timed out")
        .expect("stream closed");
    assert_eq!(signal.signal_type, SignalType::Answer);
    assert_eq!(signal.connection_id, 42);
    assert!(signal.data.starts_with("v=0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn error_code_in_the_response_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_request(&mut stream).await;

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n15")
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });

    let signaling = HttpSignaling::new("1234".to_string()).unwrap();
    let err = signaling
        .signal(Signal::offer(
            1,
            "v=0\r\n".to_string(),
            format!("http://{addr}"),
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, NetherError::Signaled(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn candidates_are_not_signaled_separately() {
    let signaling = HttpSignaling::new("1234".to_string()).unwrap();

    let err = signaling
        .signal(Signal::candidate(
            1,
            "candidate:1 1 udp 1 127.0.0.1 1 typ host".to_string(),
            "http://127.0.0.1:19132".to_string(),
        ))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("not supported"), "{err}");
}

async fn endless_body_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let chunk = vec![b'a'; 0x10000];
        for _ in 0..24 {
            if stream.write_all(b"10000\r\n").await.is_err()
                || stream.write_all(&chunk).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        std::future::pending::<()>().await;
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn join_answer_past_the_limit_fails_while_streaming() {
    let addr = endless_body_server().await;
    let signaling = HttpSignaling::new("1234".to_string()).unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        signaling.signal(Signal::offer(
            42,
            "v=0\r\n".to_string(),
            format!("http://{addr}"),
        )),
    )
    .await
    .expect("the client should give up before the body ends");
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn server_data_past_the_limit_fails_while_streaming() {
    let addr = endless_body_server().await;
    let signaling = HttpSignaling::new("1234".to_string()).unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        signaling.server_data(&format!("http://{addr}")),
    )
    .await
    .expect("the client should give up before the body ends");
    assert!(result.is_err());
}
