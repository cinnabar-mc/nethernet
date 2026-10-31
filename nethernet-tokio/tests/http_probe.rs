//! Address selection keeps HTTP discovery separate from server-data decoding.
use nethernet_tokio::signaling::http::HttpProbe;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// A plain game-port endpoint remains usable after its TLS request fails.
#[tokio::test]
async fn a_completed_non_json_probe_selects_the_http_game_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw")
                .await
                .unwrap();
        }
    });
    let probe = HttpProbe::new(reqwest::Client::builder()).unwrap();
    let endpoint = probe
        .probe(
            "127.0.0.1",
            address.port(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(endpoint, format!("http://{address}"));
    server.await.unwrap();
}

/// A cache hit still probes its exact URL; failure forgets it before the next selection.
#[tokio::test]
async fn cached_endpoints_are_rechecked_and_failed_answers_are_forgotten() {
    use nethernet_tokio::signaling::http::{ProbeCache, ProbeError};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for index in 0..6 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let count = socket.read(&mut request).await.unwrap();
            assert!(count > 0);
            if index == 2 || index == 3 {
                assert!(request[..count].starts_with(b"GET /v1/join "));
            }
            let response = if index == 3 {
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
            };
            socket.write_all(response).await.unwrap();
        }
    });
    let probe = HttpProbe::new(reqwest::Client::builder()).unwrap();
    let cache = ProbeCache::default();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let first = probe
        .select("127.0.0.1", address.port(), Some(&cache), deadline)
        .await
        .unwrap();
    let second = probe
        .select("127.0.0.1", address.port(), Some(&cache), deadline)
        .await
        .unwrap();
    assert_eq!(first.endpoint(), second.endpoint());
    assert!(matches!(
        probe
            .select("127.0.0.1", address.port(), Some(&cache), deadline)
            .await,
        Err(ProbeError::Status(503))
    ));
    let fresh = probe
        .select("127.0.0.1", address.port(), Some(&cache), deadline)
        .await
        .unwrap();
    assert_eq!(fresh.endpoint(), first.endpoint());
    first.forget();
    server.await.unwrap();
}

/// Redirects remain a failed answer even when the supplied builder normally follows them.
#[tokio::test]
async fn redirects_cannot_turn_an_http_website_into_a_probe_winner() {
    use nethernet_tokio::signaling::http::ProbeError;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: /website\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        }
    });
    let probe =
        HttpProbe::new(reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(5)))
            .unwrap();
    assert!(matches!(
        probe
            .probe(
                "127.0.0.1",
                address.port(),
                tokio::time::Instant::now() + std::time::Duration::from_secs(10)
            )
            .await,
        Err(ProbeError::Status(302))
    ));
    server.await.unwrap();
}

/// Successful headers do not win while the response body is still incomplete.
#[tokio::test]
async fn a_stalled_success_body_loses_at_the_probe_deadline() {
    use nethernet_tokio::signaling::http::ProbeError;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (headers, received_headers) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut tls, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        assert!(tls.read(&mut request).await.unwrap() > 0);
        tls.write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        drop(tls);
        let (mut http, _) = listener.accept().await.unwrap();
        assert!(http.read(&mut request).await.unwrap() > 0);
        http.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
            .await
            .unwrap();
        headers.send(()).unwrap();
        released.await.unwrap();
    });
    let probe = HttpProbe::new(reqwest::Client::builder()).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let probing =
        tokio::spawn(async move { probe.probe("127.0.0.1", address.port(), deadline).await });
    received_headers.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    let result =
        tokio::time::timeout_at(deadline + std::time::Duration::from_millis(1), probing).await;
    assert!(
        matches!(result, Ok(Ok(Err(ProbeError::TimedOut)))),
        "probe missed its original deadline: {result:?}"
    );
    release.send(()).unwrap();
    server.await.unwrap();
}
