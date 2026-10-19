//! Finite full ICE gathering shared by the configured dialing and accepting edges.
use super::ice_io::IceIo;
use crate::error::{NetherError, Result};
use crate::session::guard::transport_now;
use nethernet::sans::Sans;
use nethernet::session::{GatheringState, Session, SessionEvent, SessionInput, SessionOutput};
use tokio::time::Instant;

/// Full ICE completes gathering before SDP is encoded or signed; transport reads and retransmits stay live.
pub(crate) async fn gather(io: &mut IceIo, session: &mut Session, deadline: Instant) -> Result<()> {
    tokio::time::timeout_at(deadline, async {
        let mut wake = Instant::now();
        loop {
            while !io.blocked(session.selected_turn_stream()) {
                let Some(output) = session.poll() else { break; };
                match output {
                    SessionOutput::Send(data, to) => { io.send_datagram(&data, to).await?; }
                    SessionOutput::SendStream(data, route) => io.send_stream(data, route, session.selected_turn_stream())?,
                    SessionOutput::Wait(wait) => { wake = Instant::now() + wait; }
                    SessionOutput::Event(SessionEvent::Failed | SessionEvent::PeerClosed) => return Err(NetherError::ConnectionClosed),
                    _ => {}
                }
            }
            if !io.blocked(session.selected_turn_stream()) && session.gathering_state() == GatheringState::Complete {
                if session.local_candidates().is_empty() { return Err(NetherError::Ice("no usable local candidates".to_owned())); }
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(wake) => { session.handle(SessionInput::Timeout(transport_now()))?; wake = Instant::now() + std::time::Duration::from_secs(1); },
                event = io.next() => {
                    if let Some(input) = event?.session(transport_now()) { session.handle(input)?; }
                }
            }
        }
    }).await.map_err(|_| NetherError::Timeout)?
}
