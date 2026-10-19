//! Finite full ICE gathering shared by the configured dialing and accepting edges.
use crate::error::{NetherError, Result};
use crate::session::guard::transport_now;
use nethernet::sans::Sans;
use nethernet::session::{GatheringState, Session, SessionEvent, SessionInput, SessionOutput};
use tokio::{net::UdpSocket, time::Instant};

/// Full ICE completes gathering before SDP is encoded or signed; transport reads and retransmits stay live.
pub(crate) async fn gather(
    socket: &UdpSocket,
    session: &mut Session,
    deadline: Instant,
) -> Result<()> {
    tokio::time::timeout_at(deadline, async {
        let mut buffer = vec![0; 65536];
        let mut wake = Instant::now();
        loop {
            while let Some(output) = session.poll() {
                match output {
                    SessionOutput::Send(data, to) => { socket.send_to(&data, to).await?; }
                    SessionOutput::SendStream(..) => return Err(NetherError::Protocol(nethernet::session::IceError::UnsupportedCarrier.into())),
                    SessionOutput::Wait(wait) => { wake = Instant::now() + wait; }
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => return Err(NetherError::ConnectionClosed),
                    _ => {}
                }
            }
            if session.gathering_state() == GatheringState::Complete {
                if session.local_candidates().is_empty() { return Err(NetherError::Ice("no usable local candidates".to_owned())); }
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(wake) => session.handle(SessionInput::Timeout(transport_now()))?,
                packet = socket.recv_from(&mut buffer) => {
                    let (size, from) = packet?;
                    session.handle(SessionInput::Packet(buffer[..size].into(), from, transport_now()))?;
                }
            }
        }
    }).await.map_err(|_| NetherError::Timeout)?
}
