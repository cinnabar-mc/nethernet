//! The original text parser and both consumers preserve the same numeric reason.

use super::*;
use std::time::Duration;

/// Keeps the original wire text while the client consumes its signed decimal prefix.
#[test]
fn signed_decimal_error_reason_survives_core_to_client_classification() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for (data, code) in [
        ("25", SignalErrorCode::NotLoggedIn),
        ("25tail", SignalErrorCode::NotLoggedIn),
        ("25 tail", SignalErrorCode::NotLoggedIn),
        ("25\ttail", SignalErrorCode::NotLoggedIn),
        ("-25tail", SignalErrorCode::SignalingUnknownError),
        ("-2147483648tail", SignalErrorCode::SignalingUnknownError),
        ("2147483647tail", SignalErrorCode::SignalingUnknownError),
    ] {
        let signal = Signal::from_string(&format!("CONNECTERROR 7 {data}"), "peer".into())
            .expect("the original signed decimal prefix is valid");
        assert_eq!(signal.signal_type, SignalType::Error);
        assert_eq!(signal.connection_id, 7);
        assert_eq!(signal.data, data);
        observed.push(parse_error_code(&signal.data));
        expected.push(code);
    }
    for data in [
        "",
        "+25",
        " 25",
        "\t25",
        "-",
        "abc",
        "2147483648tail",
        "-2147483649tail",
        "4294967295",
        "é25",
    ] {
        assert!(
            Signal::from_string(&format!("CONNECTERROR 7 {data}"), "peer".into()).is_err(),
            "the original parser admitted an invalid signed int32 prefix"
        );
    }
    assert_eq!(
        observed, expected,
        "the client changed an accepted error reason"
    );
}

/// The actual pending HTTP offer is refused identically for a plain code and its accepted suffix.
#[tokio::test]
async fn signed_decimal_error_reason_survives_core_to_http_refusal() {
    use crate::signaling::http::server::{
        HttpServerConfig, HttpSignalingServer,
        tests::{post_offer, signed_offer},
    };

    let server =
        HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), HttpServerConfig::default())
            .await
            .unwrap();
    let address = server.local_addr();
    let mut signals = server.signals();
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        let mut replies = Vec::new();
        for data in ["25", "25tail"] {
            let offer = signed_offer();
            let route = async {
                let offer = signals
                    .next()
                    .await
                    .expect("the original HTTP offer arrived");
                let signal = Signal::from_string(
                    &format!("CONNECTERROR {} {data}", offer.connection_id),
                    offer.network_id,
                )
                .expect("the original signed error text is valid");
                server.signal(signal).await
            };
            let (reply, routed) = tokio::join!(post_offer(address, &offer), route);
            replies.push((reply, routed));
        }
        replies
    })
    .await;
    drop(signals);
    server.shutdown().await;
    let replies = observed.expect("the original refusal and client completed before cleanup");
    for (_, routed) in &replies {
        assert!(
            routed.is_ok(),
            "the original pending offer refused its error signal"
        );
    }
    assert_eq!(replies[0].0, "HTTP/1.1 403 Forbidden");
    assert_eq!(
        replies[1].0, "HTTP/1.1 403 Forbidden",
        "the accepted prefix changed HTTP refusal policy"
    );
}
