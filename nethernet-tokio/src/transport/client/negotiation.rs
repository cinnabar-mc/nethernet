//! Drives resolved ICE gathering while service signaling is pending, without a second socket task.
use super::{check_answer, parse_error_code};
use crate::error::{NetherError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::guard::transport_now;
use crate::session::outgoing::signal_send;
use crate::signaling::ClientSignaling;
use futures::{
    Stream, StreamExt,
    future::{BoxFuture, pending},
};
use nethernet::connection::{Connection, ConnectionInput};
use nethernet::identity::TokenTrust;
use nethernet::sans::Sans;
use nethernet::session::{GatheringState, Session, SessionEvent, SessionInput, SessionOutput};
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Full ICE completes gathering before SDP is encoded or signed; transport reads and retransmits stay live.
pub(super) async fn gather(
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
                    SessionOutput::Wait(wait) => { wake = Instant::now() + wait; }
                    SessionOutput::Event(SessionEvent::Failed) => return Err(NetherError::ConnectionClosed),
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

/// Keeps a single service send in flight while gathering and incoming signals continue to progress.
#[allow(clippy::too_many_arguments)]
pub(super) async fn exchange<St>(
    socket: &UdpSocket,
    connection: &mut Connection,
    incoming: &mut St,
    signaling: &ClientSignaling,
    initial: Vec<Signal>,
    connection_id: u64,
    remote_network_id: &str,
    trust: Option<&TokenTrust>,
    within: Duration,
    deadline: Instant,
) -> std::result::Result<(), (Option<SignalErrorCode>, NetherError)>
where
    St: Stream<Item = Signal> + Send + Unpin + ?Sized,
{
    let result = tokio::time::timeout_at(deadline, async {
        let mut buffer = vec![0; 65536];
        let mut wake = Instant::now();
        let mut queued: VecDeque<_> = initial.into();
        let mut outgoing: Option<BoxFuture<'static, Result<()>>> = None;
        let mut answer: Option<Signal> = None;
        loop {
            while let Some(output) = connection.poll() {
                match output {
                    SessionOutput::Send(data, to) => { socket.send_to(&data, to).await.map_err(|error| (None, NetherError::from(error)))?; }
                    SessionOutput::Wait(wait) => { wake = Instant::now() + wait; }
                    SessionOutput::Event(SessionEvent::Failed) => return Err((Some(SignalErrorCode::Ice), NetherError::ConnectionClosed)),
                    _ => {}
                }
            }
            if queued.is_empty() && outgoing.is_none() {
                if let Some(signal) = connection.poll_local_signal() { queued.push_back(signal); }
                else if let Some(answer) = answer {
                    // Apply the answer only at handoff, so Ready/data cannot be consumed by this pre-session driver.
                    connection.handle(ConnectionInput::Signal(answer, transport_now()))
                        .map_err(|error| (Some(SignalErrorCode::FailedToSetRemoteDescription), NetherError::from(error)))?;
                    return Ok(());
                }
            }
            if outgoing.is_none() && let Some(signal) = queued.pop_front() {
                outgoing = Some(signal_send(signaling.clone(), signal, within));
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(wake) => {
                    connection.handle(ConnectionInput::Timeout(transport_now())).map_err(|error| (Some(SignalErrorCode::Ice), NetherError::from(error)))?;
                    wake = Instant::now() + Duration::from_secs(1);
                }
                sent = async { match &mut outgoing { Some(send) => send.await, None => pending().await } } => {
                    outgoing = None;
                    sent.map_err(|error| (None, error))?;
                }
                signal = incoming.next() => {
                    let signal = signal.ok_or((None, NetherError::ConnectionClosed))?;
                    if signal.connection_id != connection_id || signal.network_id != remote_network_id { continue; }
                    match signal.signal_type {
                        SignalType::Answer => {
                            check_answer(&signal, trust, SystemTime::now())?;
                            if answer.is_none() { answer = Some(signal); }
                        }
                        SignalType::Candidate => connection.handle(ConnectionInput::Signal(signal, transport_now()))
                            .map_err(|error| (Some(SignalErrorCode::Ice), NetherError::from(error)))?,
                        SignalType::Error => return Err((None, NetherError::Signaled(parse_error_code(&signal.data)))),
                        SignalType::Offer => return Err((Some(SignalErrorCode::IncomingConnectionIgnored), NetherError::Other("received offer while dialing".to_owned()))),
                    }
                }
                packet = socket.recv_from(&mut buffer) => {
                    let (size, from) = packet.map_err(|error| (None, NetherError::from(error)))?;
                    connection.handle(ConnectionInput::Packet(buffer[..size].into(), from, transport_now()))
                        .map_err(|error| (Some(SignalErrorCode::Ice), NetherError::from(error)))?;
                }
            }
        }
    }).await;
    match result {
        Ok(result) if Instant::now() < deadline => result,
        _ => Err((
            Some(SignalErrorCode::NegotiationTimeoutWaitingForResponse),
            NetherError::Timeout,
        )),
    }
}

#[cfg(test)]
mod tests;
