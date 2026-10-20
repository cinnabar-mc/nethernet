use super::*;
use futures::task::{ArcWake, waker};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn packet_capacity_retains_fifo_before_one_terminal_error() {
    let (producer, mut receiver) = channel(Channel::Reliable);
    let capacity = RELIABLE_PACKET_CAPACITY;
    for index in 0..capacity {
        producer
            .push(Bytes::copy_from_slice(&(index as u32).to_be_bytes()))
            .unwrap();
    }
    assert_eq!(
        producer.push(Bytes::from_static(b"overflow")),
        Err(AdmissionError::Full)
    );
    producer.finish(Terminal::Capacity);
    drop(producer);
    let mut cx = Context::from_waker(Waker::noop());
    for index in 0..capacity {
        match receiver.poll_recv(&mut cx) {
            Poll::Ready(Ok(Some(packet))) => {
                assert_eq!(packet.as_ref(), &(index as u32).to_be_bytes());
            }
            _ => panic!("accepted FIFO disappeared during producer retirement"),
        }
    }
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Err(NetherError::ReceiveCapacity))
    ));
    assert!(matches!(receiver.poll_recv(&mut cx), Poll::Ready(Ok(None))));
}

#[test]
fn the_byte_budget_covers_all_accepted_data_and_is_released_by_consumption() {
    let (producer, mut receiver) = channel(Channel::Reliable);
    let packet = Bytes::from(vec![0; MAX_ACCEPTED_BYTES / PACKET_CHANNEL_CAPACITY]);
    for _ in 0..MAX_ACCEPTED_BYTES / packet.len() {
        producer.push(packet.clone()).unwrap();
    }
    assert_eq!(
        producer.push(Bytes::from_static(b"overflow")),
        Err(AdmissionError::Full)
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Ok(Some(data))) if data == packet
    ));
    producer.push(packet).unwrap();
    assert_eq!(
        producer.push(Bytes::from_static(b"overflow")),
        Err(AdmissionError::Full)
    );
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl ArcWake for WakeCount {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn admission_and_terminal_wake_the_receiver_without_retaining_a_dropped_receiver() {
    let wake = Arc::new(WakeCount::default());
    let waker = waker(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let (producer, mut receiver) = channel(Channel::Reliable);
    assert!(receiver.poll_recv(&mut cx).is_pending());
    producer.push(Bytes::from_static(b"accepted")).unwrap();
    assert_eq!(wake.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Ok(Some(_)))
    ));
    assert!(receiver.poll_recv(&mut cx).is_pending());
    producer.finish(Terminal::Eof);
    producer.finish(Terminal::Transport);
    assert_eq!(wake.0.load(Ordering::Relaxed), 2);
    assert!(matches!(receiver.poll_recv(&mut cx), Poll::Ready(Ok(None))));
    drop(receiver);
    assert_eq!(
        producer.push(Bytes::from_static(b"closed")),
        Err(AdmissionError::Closed)
    );
    assert_eq!(wake.0.load(Ordering::Relaxed), 2);
}

/// Only an otherwise empty FIFO can retain one large valid body, with credit ending at pop.
#[test]
fn an_exclusive_body_cannot_coexist_and_pop_keeps_first_terminal() {
    let (producer, mut receiver) = channel(Channel::Reliable);
    let prefix = Bytes::from_static(b"accepted prefix");
    let body = Bytes::from(vec![0x61; MAX_ACCEPTED_BYTES + 1]);
    producer.push(prefix.clone()).unwrap();
    assert_eq!(producer.push(body.clone()), Err(AdmissionError::Full));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Ok(Some(received))) if received == prefix
    ));
    producer.push(body.clone()).unwrap();
    assert_eq!(producer.push(prefix.clone()), Err(AdmissionError::Full));
    assert_eq!(producer.push(body.clone()), Err(AdmissionError::Full));
    let held = match receiver.poll_recv(&mut cx) {
        Poll::Ready(Ok(Some(received))) => received,
        _ => panic!("the original exclusive body was not retained"),
    };
    assert!(held == body, "the exclusive body changed during delivery");
    producer.push(prefix.clone()).unwrap();
    producer.finish(Terminal::Transport);
    producer.finish(Terminal::Capacity);
    assert_eq!(producer.push(prefix.clone()), Err(AdmissionError::Closed));
    drop(producer);
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Ok(Some(received))) if received == prefix
    ));
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Err(NetherError::ConnectionClosed))
    ));
    assert!(matches!(receiver.poll_recv(&mut cx), Poll::Ready(Ok(None))));
    assert_eq!(
        held, body,
        "caller-held clones survive release of queue credit"
    );
}
