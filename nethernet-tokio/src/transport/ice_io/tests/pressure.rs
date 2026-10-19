//! One finite owned service script exercises original actor output under real TCP pressure.
use super::*;
use crate::session::SessionReceiver;
use nethernet::phase::Established;
use rtc::stun::message::{BINDING_REQUEST, Getter, Message};
use rtc_turn::proto::{chandata::ChannelData, data::Data};
use tokio::sync::oneshot;

const PREFIX: &[u8] = b"accepted before original output capacity";
type Actor = (
    RuntimeSession<Established>,
    SessionReceiver,
    SessionReceiver,
);

struct Gates {
    watched: oneshot::Receiver<SocketAddr>,
    hold: oneshot::Receiver<oneshot::Sender<bool>>,
    replay: oneshot::Receiver<(usize, oneshot::Sender<usize>)>,
    release: oneshot::Receiver<()>,
    prefix_forwarded: oneshot::Sender<()>,
}

/// Classifies an original forwarded frame with RTC's codecs; no request is fabricated.
fn contains_binding(frame: &[u8]) -> bool {
    let payload = if ChannelData::is_channel_data(frame) {
        let mut channel = ChannelData {
            raw: frame.into(),
            ..Default::default()
        };
        channel.decode().unwrap();
        channel.data
    } else {
        let mut indication = Message::new();
        indication.raw = frame.into();
        indication.decode().unwrap();
        let mut data = Data::default();
        if data.get_from(&indication).is_err() {
            return false;
        }
        data.0
    };
    let mut binding = Message::new();
    binding.raw = payload;
    binding.decode().is_ok() && binding.typ == BINDING_REQUEST
}

/// A single reader owns both original sockets and retains only one received authentic request.
async fn service(listener: TcpListener, gates: Gates, done: CancellationToken) {
    let mut turn = turn::TurnPeer::new(listener.local_addr().unwrap());
    let (first, _) = listener.accept().await.unwrap();
    let (second, _) = listener.accept().await.unwrap();
    let mut peers = [
        TurnWire::accept(first, None).await,
        TurnWire::accept(second, None).await,
    ];
    let Gates {
        watched,
        hold,
        replay,
        release,
        prefix_forwarded,
    } = gates;
    let (mut watched, mut hold, mut replay, mut release) =
        (Some(watched), Some(hold), Some(replay), Some(release));
    let mut prefix_forwarded = Some(prefix_forwarded);
    let (mut watched_addr, mut held, mut original_binding) = (None, false, None);
    loop {
        let (first, second) = peers.split_at_mut(1);
        let read_first = !held || watched_addr != Some(first[0].remote);
        let read_second = !held || watched_addr != Some(second[0].remote);
        let (index, packet) = tokio::select! {
            biased;
            _ = done.cancelled() => break,
            address = async { watched.as_mut().unwrap().await }, if watched.is_some() => {
                watched_addr = Some(address.unwrap());
                let peer = peers.iter_mut().find(|peer| Some(peer.remote) == watched_addr).unwrap();
                let TestWire::Tcp(socket) = &peer.stream else { unreachable!() };
                socket2::SockRef::from(socket).set_recv_buffer_size(1024).unwrap();
                watched = None;
                continue;
            }
            requested = async { hold.as_mut().unwrap().await }, if hold.is_some() => {
                hold = None;
                held = true;
                let peer = peers.iter_mut().find(|peer| Some(peer.remote) == watched_addr).unwrap();
                let TestWire::Tcp(socket) = &peer.stream else { unreachable!() };
                socket2::SockRef::from(socket).set_recv_buffer_size(1024).unwrap();
                let _ = requested.unwrap().send(original_binding.is_some());
                continue;
            }
            requested = async { replay.as_mut().unwrap().await }, if replay.is_some() => {
                replay = None;
                let (count, observed) = requested.unwrap();
                let bytes = original_binding.as_ref().expect("original authenticated binding was observed");
                let peer = peers.iter_mut().find(|peer| Some(peer.remote) == watched_addr).unwrap();
                let mut written = 0;
                for _ in 0..count {
                    if peer.write(bytes).await.is_err() { break; }
                    written += 1;
                }
                let _ = observed.send(written);
                continue;
            }
            _ = async { release.as_mut().unwrap().await }, if release.is_some() => {
                held = false;
                release = None;
                continue;
            }
            frame = first[0].frame(), if read_first => (0, frame),
            frame = second[0].frame(), if read_second => (1, frame),
        };
        let Some(packet) = packet else {
            break;
        };
        let previous_refreshes = turn.refreshes;
        let from = peers[index].remote;
        turn.receive(from, packet);
        while let Some((to, bytes)) = turn.packets.pop_front() {
            if Some(to) == watched_addr && original_binding.is_none() && contains_binding(&bytes) {
                original_binding = Some(bytes.clone());
            }
            if peers
                .iter_mut()
                .find(|peer| peer.remote == to)
                .unwrap()
                .write(&bytes)
                .await
                .is_err()
            {
                return;
            }
        }
        // B's actual Refresh follows its reliable prefix through the SAME actor output/TCP FIFO.
        if held && Some(from) != watched_addr && turn.refreshes > previous_refreshes {
            if let Some(observed) = prefix_forwarded.take() {
                let _ = observed.send(());
            }
        }
    }
}

/// Reuses the original two-core gathering, offer and actual Ready handoff, without another runtime.
async fn actors(addr: SocketAddr, watched: oneshot::Sender<SocketAddr>) -> (Actor, Actor) {
    let mut gathered = Vec::new();
    for controlling in [true, false] {
        let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let config = IceConfig {
            policy: IcePolicy::RelayOnly,
            ..Default::default()
        };
        let now = transport_now();
        let (io, config) = IceIo::configured(
            udp.clone(),
            &config,
            &[target(addr, TurnStreamSecurity::Tcp)],
            None,
            None,
            now,
            now + Duration::from_secs(5),
        )
        .unwrap();
        let (core, description) = Session::new_with_ice(
            udp.local_addr().unwrap(),
            controlling,
            rand::random(),
            config,
            now,
        )
        .unwrap();
        gathered.push((GatheringGuard::new(core, io), description));
    }
    let (first, second) = gathered.split_at_mut(1);
    let (first, second) = (&mut first[0].0, &mut second[0].0);
    tokio::try_join!(
        crate::transport::gather::gather(
            first.io.as_mut().unwrap(),
            first.core.as_mut().unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(5)
        ),
        crate::transport::gather::gather(
            second.io.as_mut().unwrap(),
            second.core.as_mut().unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(5)
        )
    )
    .unwrap();
    let (mut b, b_description) = gathered.pop().unwrap();
    let (mut a, a_description) = gathered.pop().unwrap();
    let route = a.io.as_ref().unwrap().streams[0].1.route.unwrap();
    watched.send(route.local()).unwrap();
    a.io.as_ref().unwrap().streams[0].1.set_send_buffer(1024);
    let (mut a_core, offers) = Connection::connect(
        a.core.take().unwrap(),
        a_description,
        1,
        "peer".into(),
        IceMode::Full,
    );
    let (remote, candidates) = Connection::parse_offer(&offers[0]).unwrap();
    let (b_core, answers) = Connection::accept(
        b.core.take().unwrap(),
        b_description,
        &offers[0],
        remote,
        candidates,
        IceMode::Full,
        transport_now(),
    )
    .unwrap();
    a_core
        .handle(ConnectionInput::Signal(answers[0].clone(), transport_now()))
        .unwrap();
    let (a, a_rx, a_unreliable, a_ready) = RuntimeSession::<Connecting>::spawn(
        a.io.take().unwrap(),
        a_core,
        Addr::default(),
        Addr::default(),
    );
    let (b, b_rx, b_unreliable, b_ready) = RuntimeSession::<Connecting>::spawn(
        b.io.take().unwrap(),
        b_core,
        Addr::default(),
        Addr::default(),
    );
    let (a_ready, b_ready) = tokio::try_join!(a_ready, b_ready).unwrap();
    (
        (a.establish(a_ready), a_rx, a_unreliable),
        (b.establish(b_ready), b_rx, b_unreliable),
    )
}

/// Actual input cannot grow the original unpolled core FIFO without finite capacity retirement.
#[tokio::test]
async fn selected_write_pressure_bounds_original_actor_output_and_retains_live_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let done = CancellationToken::new();
    let (watch_tx, watched) = oneshot::channel();
    let (hold_tx, hold) = oneshot::channel();
    let (replay_tx, replay) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    let (prefix_forwarded, prefix_rx) = oneshot::channel();
    let service = service(
        listener,
        Gates {
            watched,
            hold,
            replay,
            release,
            prefix_forwarded,
        },
        done.clone(),
    );
    let exercise = async {
        let ((a, mut a_rx, a_unreliable), (b, mut b_rx, b_unreliable)) =
            actors(address, watch_tx).await;
        let observation = a.sender().pressure_observation();
        let cutoff = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut captured_binding = false;
        let mut replayed_frames = 0;
        let mut received_prefix = None;
        let results = async {
            // Prime the original SCTP congestion window using actual delivered data before shrinking read progress.
            for _ in 0..4 {
                a.send(Bytes::from(vec![0x41; 50 * 1024])).await.unwrap();
                assert_eq!(b_rx.recv().await.unwrap().unwrap().len(), 50 * 1024);
                b.send(Bytes::from_static(b"prime acknowledged"))
                    .await
                    .unwrap();
                assert_eq!(a_rx.recv().await.unwrap().unwrap(), "prime acknowledged");
            }
            let (held, acknowledged) = oneshot::channel();
            hold_tx.send(held).unwrap();
            captured_binding = acknowledged.await.unwrap();
            if !captured_binding {
                return Err("fixture never received the original authenticated binding");
            }
            {
                let fill = async {
                    for _ in 0..crate::session::command::COMMAND_CAPACITY {
                        a.send(Bytes::from(vec![0x42; 50 * 1024])).await.unwrap();
                    }
                    futures::future::pending::<()>().await;
                };
                tokio::pin!(fill);
                tokio::select! { biased; _ = observation.socket_blocked() => {}, _ = &mut fill => unreachable!() }
            }
            b.send(Bytes::from_static(PREFIX)).await.unwrap();
            b.update_turn_streams_before(
                vec![target(address, TurnStreamSecurity::Tcp)],
                cutoff.into_std(),
            )
            .await
            .unwrap();
            prefix_rx.await.unwrap();
            let (replayed, count) = oneshot::channel();
            replay_tx
                .send((crate::session::PACKET_CHANNEL_CAPACITY + 2, replayed))
                .unwrap();
            replayed_frames = count.await.unwrap();
            observation
                .over_entries(crate::session::PACKET_CHANNEL_CAPACITY)
                .await;
            let _ = release_tx.send(());
            received_prefix = Some(a_rx.recv().await);
            Ok(a_rx.recv().await)
        };
        let result = tokio::time::timeout_at(cutoff, results).await;
        let peak = observation.peak_entries();
        let a = a.close();
        let b = b.close();
        drop((a_rx, b_rx, a_unreliable, b_unreliable));
        done.cancel();
        tokio::join!(a.join_original_actor(), b.join_original_actor());
        (
            result,
            peak,
            captured_binding,
            replayed_frames,
            received_prefix,
        )
    };
    let (_, (result, peak, captured, written, prefix)) =
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(service, exercise)
        })
        .await
        .expect("finite actual actor setup or original owner cleanup stalled");
    assert!(
        captured,
        "fixture never received the original authenticated request"
    );
    assert!(
        written > 0,
        "the captured original request never reached the actual socket"
    );
    assert!(
        peak > crate::session::PACKET_CHANNEL_CAPACITY,
        "original actor never crossed the observed output bound"
    );
    assert_eq!(
        prefix
            .expect("the actual live reliable prefix never reached its original receiver")
            .unwrap()
            .as_deref(),
        Some(PREFIX)
    );
    let terminal = result
        .expect("original actor did not retire finite selected-output capacity")
        .expect("actual wire fixture precondition failed");
    assert!(
        matches!(terminal, Err(crate::error::NetherError::ReceiveCapacity)),
        "selected pressure bypassed finite original output capacity"
    );
}
