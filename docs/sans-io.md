# Drive a custom event loop

Choose `nethernet` when your application owns sockets, scheduling, and time.
The core accepts typed input and returns work for your loop. It does not open
sockets, resolve names, execute HTTP, or read a clock.

For a socket-owning adapter, use [Tokio](tokio.md).

## Create a session and exchange SDP

Add the dependencies from the [core README](../nethernet/README.md). Bind the
socket first, then pass its actual address to `Session::new`. Supply a distinct
SDP origin ID per local session and a monotonic `Instant` from your loop.
This host-only helper returns the pending session and signed offer SDP:

```rust,no_run
use nethernet::{
    identity::{SdpIdentity, TokenTrust, verify_answer},
    protocol::webrtc::Description,
    sans::Sans,
    session::{Session, SessionInput},
};
use std::{net::UdpSocket, time::{Instant, SystemTime}};

fn start_offer(
    socket: &UdpSocket,
    session_id: u64,
    identity: &dyn SdpIdentity,
    now: Instant,
    wall: SystemTime,
) -> Result<(Session, String), Box<dyn std::error::Error>> {
    let (session, description) = Session::new(socket.local_addr()?, true, session_id, now)?;
    let sdp = identity.augment(&description.encode_full(session.local_candidates()), wall)?;
    Ok((session, sdp))
}

fn apply_answer(
    session: &mut Session,
    sdp: &str,
    trust: &TokenTrust,
    now: Instant,
    wall: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_answer(sdp, Some(trust), wall)?;
    let (description, candidates) = Description::parse(sdp)?;
    session.handle(SessionInput::RemoteDescription(description, candidates, now))?;
    Ok(())
}
```

Send the SDP over your signaling channel. Receiving/parsing SDP does not itself
verify peer trust; the example calls `verify_answer` before applying it.
`SystemTime` is for credential validity and `Instant` for protocol deadlines.
When driving `HttpSignaler` yourself, supply both receive-time clocks in
`HttpSignalerInput::Request`; wall-clock adjustments do not restart answer deadlines.

For an accepting side, use `OfferPolicy::admit`, then `Admitted::answer` with
the server socket's address, a distinct session ID, and current monotonic time.
Its `Answered` contains the connection and signals to return. Set its signer and
offer trust explicitly. When using `Connection::connect`, `Connection` also
handles answer/candidate signals correlated by connection ID and remote network
ID; the signaling layer must route authenticated sender identities correctly.

## Pump UDP input, output, and timers

This small nonblocking driver works for a UDP-only session. It retains blocked
outgoing datagrams and an absolute timer deadline. Call `tick` whenever the
socket is readable/writable or the stored `wake` expires. Keep the same driver
through the transition from `Session<Connecting>` to `Session<Established>`.

```rust,no_run
use nethernet::{
    error::ProtocolError,
    phase::Live,
    protocol::constants::MAX_DATAGRAM_SIZE,
    sans::Sans,
    session::{Channel, Session, SessionEvent, SessionInput, SessionOutput},
};
use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    net::{SocketAddr, UdpSocket},
    time::Instant,
};

#[derive(Default)]
struct UdpDriver {
    pending: VecDeque<(Vec<u8>, SocketAddr)>,
    wake: Option<Instant>,
}

impl UdpDriver {
    fn tick<S: Live>(
        &mut self,
        session: &mut Session<S>,
        socket: &UdpSocket,
        now: Instant,
        mut deliver: impl FnMut(Channel, Vec<u8>),
    ) -> Result<(), ProtocolError> {
        if self.wake.is_some_and(|deadline| deadline <= now) {
            self.wake = None;
            session.handle(SessionInput::Timeout(now))?;
        }
        let mut buffer = [0u8; MAX_DATAGRAM_SIZE];
        for _ in 0..32 { // Bound input work per call for the rest of the application.
            match socket.recv_from(&mut buffer) {
                Ok((len, source)) => session.handle(SessionInput::Packet(
                    buffer[..len].into(), source, now,
                ))?,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let mut terminal = false;
        while let Some(output) = session.poll() {
            match output {
                SessionOutput::Send(bytes, target) => self.pending.push_back((bytes, target)),
                SessionOutput::Message(channel, bytes) => deliver(channel, bytes),
                SessionOutput::Wait(delay) => self.wake = Some(now + delay),
                SessionOutput::Event(SessionEvent::Ready) => {}
                SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => {
                    terminal = true;
                }
                SessionOutput::SendStream(..) => return Err(ProtocolError::Other(
                    "this driver supports UDP carriers only".into(),
                )),
            }
        }
        while let Some((bytes, target)) = self.pending.front() {
            match socket.send_to(bytes, target) {
                Ok(len) if len == bytes.len() => { self.pending.pop_front(); }
                Ok(_) => return Err(io::Error::from(ErrorKind::WriteZero).into()),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        if terminal {
            return Err(ProtocolError::Other("session ended".into()));
        }
        Ok(())
    }
}
```

Call `socket.set_nonblocking(true)` before using this driver. Its pending queue
is intentionally simple: choose a retained-byte limit for your application and
stop admitting new sends when it is full. Keep the queue when a session ends so
you can flush remaining best-effort wire output. The `deliver` callback receives
early application messages too; queue those if your application cannot process
them yet.

Drain all initial output immediately after constructing or configuring a session;
interpret each `Wait` relative to the time of the input that produced it. The
sample uses one `now` for all input in a tick. If you accumulate outputs across
inputs with different times, retain the corresponding time with each timer.
A blocked socket does not restart the timer. Keep servicing input and deadlines
while writes are blocked. Polling without input never advances protocol time.

After a tick, consume `session.try_establish()`. It returns an established session
when both data channels have opened, or the same pending session in `Err`.
Retain that pending value and continue driving it. Application `send` is available
only on the established type; a `Ready` event alone does not change your Rust type.

## Gather candidates and support streams

`Session::new_with_ice` takes an `IceConfig` with resolved numeric servers,
credential expiry, gathering timeout, and candidate policy. For Full ICE, drive
packets/time until `gathering_state()` is `Complete`, then encode and sign the
SDP. For Trickle ICE, send `poll_local_candidate()` results as they arrive.
`Connection::poll_local_signal()` formats late candidates for a connection.

For accepting Full ICE, create and gather your answering session first. Use
`Admitted::prepare_answer(&mut session, description, now, wall)`, then
`PreparedAnswer::finish(session, now)` to transfer it. Reuse the original
`Description` returned with that session. If preparation fails, you still own
the allocation and must close and drain it.

TURN streams require additional handlers beyond the UDP sample. Reserve an
`IceServer::TurnStream` with its own `TurnStreamId`. Connect the actual TCP socket,
complete TLS verification if applicable, then submit `ActivateTurnStream` with
its real route. Feed complete RTC-framed TURN messages as `StreamPacket`.
Write `SendStream` output to that same stream, retaining partial-write offsets;
report `StreamClosed(id, now)` even if setup failed before a route existed.
The TCP/TLS carrier requests a UDP relay; it is not a TCP relay allocation.

## Bound messages and retire the session

Before accepting a remote description, use `set_max_incoming_message_size` to
choose a complete-body bound. It is separate from outgoing capacity and retained
queues; zero refuses nonempty bodies. `OfferPolicy` can set the same bound for
an answering session. A refusal preserves messages already accepted before the
terminal outcome. This logical bound does not enlarge the single-SCTP-record
read limit or the first-segment reassembly policy.

If input handling fails, keep the session and drain its output before retiring
it. An error does not discard complete messages already accepted.

On an established session, `max_message_size(channel)` reports the negotiated
outgoing body limit. Reliable bodies use at most 255 fragments; unreliable bodies
fit one fragment. Each fragment reserves a byte for NetherNet framing. Later SDP
does not resize the installed association. These facts remain readable after
remote retirement, so they do not prove that a send will succeed.

Core close returns a retired owner whose output still needs draining, including
on teardown error. See [shutdown](shutdown.md#core-event-loops). Dropping it cannot
perform network I/O.
