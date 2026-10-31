//! LAN timing and admission are driven solely by caller time and emitted outputs.
use nethernet::protocol::{
    Signal,
    packet::discovery::{
        MessagePacket, Packets, RequestPacket, ResponsePacket, ServerData, encode,
    },
};
use nethernet::sans::Sans;
use nethernet::signaling::lan::{
    LanSignaler, config::LanSignalerConfig, input::LanSignalerInput as Input,
    output::LanSignalerOutput as Output,
};
use std::time::{Duration, Instant};

/// Delivers one authenticated discovery datagram from the shared synthetic address.
fn receive(signaler: &mut LanSignaler, packet: Packets, sender: u64, now: Instant) {
    signaler
        .handle(Input::Datagram(
            encode(&packet, sender).unwrap().into(),
            "127.0.0.1:7551".parse().unwrap(),
            now,
        ))
        .unwrap();
}

/// Consumes the output FIFO and counts datagrams while retaining its latest scheduled wait.
fn drain(signaler: &mut LanSignaler) -> (usize, Option<Duration>) {
    let mut packets = 0;
    let mut wait = None;
    while let Some(output) = signaler.poll() {
        match output {
            Output::Datagram(..) => packets += 1,
            Output::Wait(within) => wait = Some(within),
            _ => {}
        }
    }
    (packets, wait)
}

#[test]
fn a_new_offer_replaces_an_idle_wait_with_its_retry_deadline() {
    let start = Instant::now();
    let mut signaler = LanSignaler::new(1, LanSignalerConfig::default());
    receive(&mut signaler, Packets::Request(RequestPacket), 2, start);
    signaler.handle(Input::Update(start)).unwrap();
    assert_eq!(drain(&mut signaler).1, Some(Duration::from_secs(15)));
    let now = start + Duration::from_secs(1);
    signaler
        .handle(Input::Signal(
            Signal::offer(42, "sdp".into(), "2".into()),
            now,
        ))
        .unwrap();
    let (sent, wait) = drain(&mut signaler);
    assert_eq!(sent, 1);
    assert_eq!(wait, Some(Duration::from_secs(2)));
    signaler.handle(Input::Update(now + wait.unwrap())).unwrap();
    assert_eq!(drain(&mut signaler).0, 1);
}

#[test]
fn independent_candidates_do_not_acknowledge_outgoing_signals() {
    let now = Instant::now();
    let mut signaler = LanSignaler::new(1, LanSignalerConfig::default());
    receive(&mut signaler, Packets::Request(RequestPacket), 2, now);
    for data in ["first", "second"] {
        signaler
            .handle(Input::Signal(
                Signal::candidate(42, data.into(), "2".into()),
                now,
            ))
            .unwrap();
    }
    drain(&mut signaler);
    let incoming = Signal::candidate(42, "independent".into(), "1".into());
    receive(
        &mut signaler,
        Packets::Message(MessagePacket::new(1, incoming.to_string())),
        2,
        now,
    );
    assert_eq!(signaler.pending_signals(), 2);
    drain(&mut signaler);
    signaler
        .handle(Input::Update(now + Duration::from_millis(500)))
        .unwrap();
    assert_eq!(drain(&mut signaler).0, 2);
}

#[test]
fn unauthenticated_sender_ids_cannot_grow_address_state_without_bound() {
    let now = Instant::now();
    let config = LanSignalerConfig::default();
    let capacity = config.max_addresses;
    let mut signaler = LanSignaler::new(1, config);
    for sender in 2..=600 {
        receive(&mut signaler, Packets::Request(RequestPacket), sender, now);
        drain(&mut signaler);
    }
    assert!(signaler.addresses().count() <= capacity);
    assert!(signaler.discovered().is_empty());
}

#[test]
fn ignored_messages_and_over_capacity_responses_do_not_learn_addresses() {
    let now = Instant::now();
    let mut signaler = LanSignaler::new(
        1,
        LanSignalerConfig {
            max_discovered: 0,
            ..Default::default()
        },
    );
    for sender in 2..=300 {
        receive(
            &mut signaler,
            Packets::Message(MessagePacket::new(999, "CONNECTREQUEST 42 sdp".to_string())),
            sender,
            now,
        );
        receive(
            &mut signaler,
            Packets::Response(ResponsePacket::new(
                ServerData::new("s".into(), "w".into()).encode().unwrap(),
            )),
            sender,
            now,
        );
        drain(&mut signaler);
    }
    assert_eq!(signaler.addresses().count(), 0);
}
