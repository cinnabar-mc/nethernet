//! Reliable data-channel messages over loopback DTLS and SCTP; `tools/go-peer` runs the same cases.
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nethernet_tokio::signaling::lan::{LanConfig, LanSignaling};
use nethernet_tokio::{
    AcceptedSession, ClientIceConfig, ConnectionConfig, NetherClient, NetherServer, ServerData,
    ServerIceConfig,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const SERVER_ID: u64 = 1;

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// The payload bytes both harness sides use: byte i is i mod 251.
fn pattern(len: usize) -> Bytes {
    (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>().into()
}

/// Connects a client to a server over loopback LAN signaling, with both ICE sockets on 127.0.0.1.
async fn pair() -> (NetherServer, NetherClient, AcceptedSession) {
    let port = std::net::UdpSocket::bind(loopback(0))
        .and_then(|s| s.local_addr())
        .unwrap()
        .port();
    let server_signaling = LanSignaling::with_config(
        SERVER_ID,
        loopback(port),
        LanConfig {
            discovery_port: port,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    server_signaling.set_server_data(ServerData::new("bench".into(), "bench".into()));
    let mut server = NetherServer::bind_with(
        server_signaling,
        ConnectionConfig {
            server_ice: Some(ServerIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: Default::default(),
                bind_addr: loopback(0),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let client_signaling = LanSignaling::with_config(
        2,
        loopback(0),
        LanConfig {
            broadcast_address: Some(loopback(port)),
            broadcast_interval: Duration::from_millis(50),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    while !client_signaling.discover().await.contains_key(&SERVER_ID) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let client_config = ConnectionConfig {
        client_ice: Some(ClientIceConfig {
            turn_streams: Vec::new(),
            turn_tls: None,
            ice: Default::default(),
            bind_addr: Some(loopback(0)),
        }),
        ..Default::default()
    };
    let (client, accepted) = tokio::join!(
        NetherClient::connect_with(client_signaling, SERVER_ID.to_string(), client_config),
        server.accept()
    );
    (server, client.unwrap(), accepted.unwrap())
}

fn datachannel(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_server, mut client, accepted) = rt.block_on(pair());
    let AcceptedSession {
        session,
        mut reliable,
        unreliable: _unreliable,
    } = accepted;
    let echo = session.sender();
    rt.spawn(async move {
        while let Ok(Some(data)) = reliable.recv().await {
            if echo.send(data).await.is_err() {
                return;
            }
        }
    });

    let mut group = c.benchmark_group("datachannel");
    for size in [64, 1024, 16384, 262144] {
        let data = pattern(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("roundtrip", size), |b| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let start = Instant::now();
                    for _ in 0..iters {
                        client.send(data.clone()).await.unwrap();
                        let echoed = client.recv().await.unwrap().unwrap();
                        assert_eq!(echoed.len(), size);
                    }
                    start.elapsed()
                })
            })
        });
    }

    // Throughput sends from the server so the echo task above stays idle.
    let sender = session.sender();
    for size in [1024, 65536, 1048576] {
        let data = pattern(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("throughput", size), |b| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let start = Instant::now();
                    let send = async {
                        for _ in 0..iters {
                            sender.send(data.clone()).await.unwrap();
                        }
                    };
                    let receive = async {
                        for _ in 0..iters {
                            client.recv().await.unwrap().unwrap();
                        }
                    };
                    tokio::join!(send, receive);
                    start.elapsed()
                })
            })
        });
    }
    group.finish();
}

criterion_group!(benches, datachannel);
criterion_main!(benches);
