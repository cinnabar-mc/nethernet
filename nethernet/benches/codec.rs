//! Framing and discovery codec benches; `tools/go-peer` runs the same cases against go-nethernet.
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nethernet::protocol::constants::LOCAL_SCTP_MAX_MESSAGE_SIZE;
use nethernet::protocol::packet::discovery::{
    MessagePacket, Packets, RequestPacket, ResponsePacket, ServerData, decode, encode,
};
use nethernet::protocol::{Message, MessageSegment};
use std::hint::black_box;

/// Payload sizes shared with the Go benches; the largest stays under the send cap.
const SEGMENT_SIZES: [usize; 6] = [64, 1024, 16384, 262144, 1048576, 2500000];

/// Reads a committed file from the repository's testdata/bench.
fn input(name: &str) -> Vec<u8> {
    let path = format!("{}/../testdata/bench/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The payload bytes both harness sides use: byte i is i mod 251.
fn pattern(len: usize) -> Bytes {
    (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>().into()
}

/// Uses the current advertised SCTP default, excluding the segment-count byte.
fn wire_segments(data: Bytes) -> Vec<Bytes> {
    Message::segments(data, LOCAL_SCTP_MAX_MESSAGE_SIZE as usize - size_of::<u8>())
        .unwrap()
        .map(|segment| segment.encode())
        .collect()
}

fn segment(c: &mut Criterion) {
    let mut group = c.benchmark_group("segment");
    for size in SEGMENT_SIZES {
        let data = pattern(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("split", size), |b| {
            b.iter(|| wire_segments(black_box(data.clone())))
        });
        let wire = wire_segments(data);
        group.bench_function(BenchmarkId::new("reassemble", size), |b| {
            b.iter(|| {
                let mut message = Message::new();
                let mut out = None;
                for segment in &wire {
                    out = message
                        .add_segment(MessageSegment::decode(segment.clone()).unwrap())
                        .unwrap();
                }
                assert_eq!(out.map(|m| m.len()), Some(size));
            })
        });
    }
    group.finish();
}

fn lan(c: &mut Criterion) {
    const SENDER: u64 = 0x1122334455667788;
    const RECIPIENT: u64 = 0x8877665544332211;
    let signal = String::from_utf8(input("signal.txt")).unwrap();
    let cases = [
        ("request", Packets::Request(RequestPacket)),
        (
            "response",
            Packets::Response(ResponsePacket::new(input("server_data.bin"))),
        ),
        (
            "message",
            Packets::Message(MessagePacket::new(RECIPIENT, signal)),
        ),
    ];
    let mut group = c.benchmark_group("lan");
    for (name, packet) in &cases {
        let wire = encode(packet, SENDER).unwrap();
        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_function(BenchmarkId::new("encode", name), |b| {
            b.iter(|| encode(black_box(packet), SENDER).unwrap())
        });
        group.bench_function(BenchmarkId::new("decode", name), |b| {
            b.iter(|| decode(black_box(&wire)).unwrap())
        });
    }
    group.finish();
}

fn server_data(c: &mut Criterion) {
    let wire = input("server_data.bin");
    let data = ServerData::decode(&wire).unwrap();
    let mut group = c.benchmark_group("server_data");
    group.bench_function("encode", |b| b.iter(|| black_box(&data).encode().unwrap()));
    group.bench_function("decode", |b| {
        b.iter(|| ServerData::decode(black_box(&wire)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, segment, lan, server_data);
criterion_main!(benches);
