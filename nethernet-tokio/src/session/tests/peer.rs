//! Original finite RTC peer for driving real data-channel delivery and encrypted peer closure.
use crate::session::guard::transport_now;
use bytes::{BufMut, BytesMut};
use nethernet::protocol::constants::RELIABLE_CHANNEL;
use rtc::data_channel::RTCDataChannelId;
use rtc::dtls::content::ContentType;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::Duration;
use tokio::net::UdpSocket;

pub(super) struct Peer {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    buffer: Vec<u8>,
    reliable: Option<RTCDataChannelId>,
}

impl Peer {
    /// Answers the actual NetherNet offer using RTC's existing ICE, DTLS, SCTP and DCEP owners.
    pub async fn answer(offer: String) -> (Self, String) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let now = transport_now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(RTCDtlsRole::Client)
                    .build(),
            )
            .build(now)
            .unwrap();
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".into(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json().unwrap())
            .unwrap();
        pc.set_remote_description(now, RTCSessionDescription::offer(offer).unwrap())
            .unwrap();
        let answer = pc.create_answer(None).unwrap();
        pc.set_local_description(now, answer.clone()).unwrap();
        (
            Self {
                pc,
                socket,
                buffer: vec![0; 65536],
                reliable: None,
            },
            answer.sdp,
        )
    }

    /// Flushes currently available protocol datagrams without creating a background task.
    pub async fn flush(&mut self) {
        while let Some(packet) = self.pc.poll_write() {
            self.socket
                .send_to(&packet.message, packet.transport.peer_addr)
                .await
                .unwrap();
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event
                && self
                    .pc
                    .data_channel(id)
                    .is_some_and(|channel| channel.label() == RELIABLE_CHANNEL)
            {
                self.reliable = Some(id);
            }
        }
        while self.pc.poll_read().is_some() {}
    }

    /// Advances one actual socket or RTC timer event; the outer test owns its absolute budget.
    pub async fn turn(&mut self) {
        self.flush().await;
        let deadline = self
            .pc
            .poll_timeout()
            .unwrap_or(transport_now() + Duration::from_secs(1));
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline.into()) => self.pc.handle_timeout(transport_now()).unwrap(),
            packet = self.socket.recv_from(&mut self.buffer) => {
                let (size, from) = packet.unwrap();
                self.pc.handle_read(TaggedBytesMut {
                    now: transport_now(),
                    transport: TransportContext { local_addr: self.socket.local_addr().unwrap(), peer_addr: from, ecn: None, transport_protocol: TransportProtocol::UDP },
                    message: BytesMut::from(&self.buffer[..size]),
                }).unwrap();
            }
        }
    }

    pub fn ready(&self) -> bool {
        self.reliable.is_some()
    }

    /// Sends one original NetherNet reliable message, framed by its source protocol convention.
    pub fn send(&mut self, index: usize) {
        let mut data = BytesMut::new();
        data.put_u8(0);
        data.put_u32(index.try_into().unwrap());
        self.pc
            .data_channel(self.reliable.unwrap())
            .unwrap()
            .send(transport_now(), data)
            .unwrap();
    }

    /// Accepted remote SCTP acknowledgments prove the queued reliable tail reached the real driver.
    pub fn outstanding(&mut self) -> usize {
        self.pc
            .data_channel(self.reliable.unwrap())
            .unwrap()
            .outstanding_bytes()
    }

    /// Sends RTC's genuine encrypted close_notify, with the independent SCTP ABORT deliberately lost.
    pub async fn close_dtls(&mut self) {
        self.pc.close().unwrap();
        let mut alerts = 0;
        while let Some(packet) = self.pc.poll_write() {
            if packet
                .message
                .first()
                .is_some_and(|byte| ContentType::from(*byte) == ContentType::Alert)
            {
                alerts += 1;
                self.socket
                    .send_to(&packet.message, packet.transport.peer_addr)
                    .await
                    .unwrap();
            }
        }
        assert!(
            alerts > 0,
            "the actual RTC peer did not emit an authenticated DTLS close"
        );
    }
}
