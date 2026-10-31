use super::*;
use std::io::Read;
use std::net::{TcpListener, TcpStream};

/// Captures the original frame-driven client's status request without waiting on a server thread.
fn query_request(info: ClientInfo) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = NetherHttpClient::new();
    client.local_network_id = "1234".into();
    client.set_client_info(info);
    client
        .query_server_data(&format!("http://{}", listener.local_addr().unwrap()))
        .unwrap();
    let mut stream: Option<TcpStream> = None;
    let mut request = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.update();
        if stream.is_none() {
            match listener.accept() {
                Ok((accepted, _)) => {
                    accepted.set_nonblocking(true).unwrap();
                    stream = Some(accepted);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
        }
        if let Some(stream) = &mut stream {
            let mut bytes = [0; 4096];
            match stream.read(&mut bytes) {
                Ok(0) => panic!("query closed before sending its headers"),
                Ok(n) => request.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
        }
        if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            return String::from_utf8(request).unwrap();
        }
        assert!(Instant::now() < deadline, "query did not send its headers");
        std::thread::yield_now();
    }
}

#[test]
fn query_metadata_uses_the_same_encoding_as_the_async_client() {
    let request = query_request(ClientInfo {
        version: "1.26 +&?".into(),
        protocol: -2,
        platform: -1,
    });
    assert!(
        request.starts_with(
            "GET /v1/join?id=1234&platform=-1&protocol=-2&version=1.26+%2B%26%3F HTTP/1.1\r\n"
        ),
        "{request}"
    );
    assert!(query_request(ClientInfo::default()).starts_with("GET /v1/join HTTP/1.1\r\n"));
}

#[test]
fn incomplete_query_metadata_fails_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = NetherHttpClient::new();
    client.set_client_info(ClientInfo {
        version: "1.26".into(),
        ..Default::default()
    });
    let error = client
        .query_server_data(&format!("http://{}", listener.local_addr().unwrap()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}
