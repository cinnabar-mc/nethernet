//! Actual nonblocking TURN carriers; the original core retains all protocol queues and timers.
use crate::tcp_wire::{ClientTls, Inbound, READ_CHUNK, Wire, WireError};
use nethernet::session::{
    IceConfig, IceServer, MAX_TURN_STREAM_FRAME_BYTES, TurnStreamId, TurnStreamRoute,
    TurnStreamSecurity, TurnStreamTarget,
};
use rtc::shared::turn_framing::TurnStreamDecoder;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::time::Instant;

enum Phase {
    Connecting,
    Handshaking,
    Active,
    Retiring,
    Closed,
}

struct Carrier {
    id: TurnStreamId,
    remote: std::net::SocketAddr,
    route: Option<TurnStreamRoute>,
    wire: Option<Wire>,
    decoder: TurnStreamDecoder,
    phase: Phase,
    deadline: Instant,
}

pub(super) enum Input {
    Activated(TurnStreamId, TurnStreamRoute),
    Packet(Vec<u8>, TurnStreamRoute),
    Closed(TurnStreamId),
    Progress,
}

/// One original polled core output, retained at its exact accepted byte offset.
pub(super) struct Pending {
    route: TurnStreamRoute,
    bytes: Vec<u8>,
    written: usize,
}

impl Pending {
    /// Takes the original signed frame without rebuilding its wire bytes.
    pub(super) fn new(bytes: Vec<u8>, route: TurnStreamRoute) -> Self {
        Self {
            route,
            bytes,
            written: 0,
        }
    }

    pub(super) fn route(&self) -> TurnStreamRoute {
        self.route
    }
}

#[derive(Default)]
pub(super) struct Streams {
    carriers: Vec<Carrier>,
    next: usize,
}

impl Streams {
    /// Validates all authorities before opening any carrier, using already-prepared trust.
    pub(super) fn validate(targets: &[TurnStreamTarget]) -> io::Result<()> {
        for target in targets {
            if let TurnStreamSecurity::Tls { server_name } = &target.security {
                ClientTls::validate_name(server_name)?;
            }
        }
        Ok(())
    }

    /// Starts independent numeric connects, then installs only their own actual bound routes.
    pub(super) fn open(
        targets: &[TurnStreamTarget],
        fallback: Option<IpAddr>,
        tls: &ClientTls,
        ice: &mut IceConfig,
        now: Instant,
    ) -> io::Result<Self> {
        let mut streams = Self::default();
        let deadline = now.checked_add(ice.gather_timeout).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "ICE gathering exceeds clock range")
        })?;
        for target in targets {
            let bind_ip = target.local_bind_ip(fallback).map_err(io::Error::other)?;
            let (secure, name) = match &target.security {
                TurnStreamSecurity::Tcp => (false, ""),
                TurnStreamSecurity::Tls { server_name } => (true, server_name.as_str()),
            };
            let mut wire = match tls.dial(secure, name, target.remote, bind_ip) {
                Ok(wire) => wire,
                Err(_) => {
                    tracing::debug!("a TURN carrier could not start on its actual socket");
                    continue;
                }
            };
            wire.limit_output(MAX_TURN_STREAM_FRAME_BYTES);
            let id = TurnStreamId::new(streams.carriers.len()).map_err(io::Error::other)?;
            ice.servers.push(IceServer::TurnStream {
                id,
                remote: target.remote,
                credentials: target.credentials.clone(),
                requested_family: target.requested_family,
            });
            streams.carriers.push(Carrier {
                id,
                remote: target.remote,
                route: None,
                wire: Some(wire),
                decoder: TurnStreamDecoder::new(),
                phase: Phase::Connecting,
                deadline: target.admission_deadline(deadline),
            });
        }
        Ok(streams)
    }

    /// Visits every bounded carrier fairly; one blocked socket cannot monopolize the frame.
    pub(super) fn poll(&mut self, now: Instant) -> Option<Input> {
        for _ in 0..self.carriers.len() {
            let index = self.next;
            self.next = (self.next + 1) % self.carriers.len();
            let carrier = &mut self.carriers[index];
            match carrier.poll(now) {
                Ok(Some(input)) => return Some(input),
                Ok(None) => {}
                Err(_) => {
                    carrier.retire();
                    return Some(Input::Progress);
                }
            }
        }
        None
    }

    /// Continues only the original frame's partial write and its TLS output prefix.
    pub(super) fn write(&mut self, pending: &mut Pending) -> Result<bool, WireError> {
        let carrier = self
            .carriers
            .iter_mut()
            .find(|carrier| carrier.route == Some(pending.route))
            .ok_or_else(|| io::Error::new(ErrorKind::NotConnected, "TURN carrier is absent"))?;
        let wire = carrier
            .wire
            .as_mut()
            .ok_or_else(|| io::Error::new(ErrorKind::NotConnected, "TURN carrier is closed"))?;
        wire.flush()?;
        if wire.has_pending_output() {
            return Ok(false);
        }
        if pending.written < pending.bytes.len() {
            match wire.write(&pending.bytes[pending.written..]) {
                Ok(0) => return Err(WireError::WriteZero),
                Ok(size) => pending.written += size,
                Err(WireError::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(pending.written == pending.bytes.len() && !wire.has_pending_output())
    }

    /// Confirms output belongs to an actual carrier installed on this original attempt.
    pub(super) fn contains(&self, route: TurnStreamRoute) -> bool {
        self.carriers
            .iter()
            .any(|carrier| carrier.route == Some(route))
    }

    /// Withholds new application sends while accepted input drains before carrier failure.
    pub(super) fn retiring(&self) -> bool {
        self.carriers
            .iter()
            .any(|carrier| matches!(carrier.phase, Phase::Retiring))
    }

    /// Seals only the original failed carrier, once, before the core receives its closure.
    pub(super) fn retire(&mut self, route: TurnStreamRoute) -> bool {
        self.carriers
            .iter_mut()
            .find(|carrier| carrier.route == Some(route))
            .is_some_and(Carrier::retire)
    }

    /// Closes without interleaving TLS shutdown into an unfinished original application frame.
    pub(super) fn finish(&mut self, pending: Option<&Pending>) {
        for carrier in &mut self.carriers {
            if pending.is_none_or(|pending| Some(pending.route) != carrier.route)
                && let Some(wire) = &mut carrier.wire
            {
                let _ = wire.finish();
            }
            carrier.retire();
            carrier.decoder = TurnStreamDecoder::new();
            carrier.phase = Phase::Closed;
        }
    }
}

impl Carrier {
    /// Drives real connect/verification before once-only activation, then bounded RTC framing.
    fn poll(&mut self, now: Instant) -> Result<Option<Input>, WireError> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(None);
        }
        if matches!(self.phase, Phase::Retiring) {
            if let Ok(Some(frame)) = self.decoder.next_message() {
                return Ok(Some(Input::Packet(
                    frame,
                    self.route.expect("active carrier owns its actual tuple"),
                )));
            }
            self.decoder = TurnStreamDecoder::new();
            self.phase = Phase::Closed;
            return Ok(Some(Input::Closed(self.id)));
        }
        if matches!(self.phase, Phase::Active)
            && let Some(frame) = self.decoder.next_message().map_err(io::Error::other)?
        {
            return Ok(Some(Input::Packet(
                frame,
                self.route.expect("active carrier owns its actual tuple"),
            )));
        }
        if !matches!(self.phase, Phase::Active) && now >= self.deadline {
            self.retire();
            return Ok(Some(Input::Progress));
        }
        let wire = self
            .wire
            .as_mut()
            .expect("live carrier owns its original socket");
        if matches!(self.phase, Phase::Connecting) {
            if !wire.poll_connect()? {
                return Ok(None);
            }
            let route = TurnStreamRoute::new(wire.local_addr()?, wire.peer_addr()?)
                .map_err(io::Error::other)?;
            if route.remote() != self.remote {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "TURN socket destination changed",
                )
                .into());
            }
            self.route = Some(route);
            self.phase = Phase::Handshaking;
        }
        wire.flush()?;
        if matches!(self.phase, Phase::Handshaking) && wire.handshake_ready() {
            self.phase = Phase::Active;
            return Ok(Some(Input::Activated(
                self.id,
                self.route.expect("verified carrier owns its actual tuple"),
            )));
        }
        let remaining = MAX_TURN_STREAM_FRAME_BYTES.saturating_sub(self.decoder.buffered_len());
        if remaining == 0 {
            return Err(io::Error::new(ErrorKind::InvalidData, "TURN frame exceeds limit").into());
        }
        let mut chunk = [0; READ_CHUNK];
        let limit = remaining.min(chunk.len());
        let (inbound, size) = wire.read_limited(&mut chunk[..limit])?;
        self.decoder.extend_from_slice(&chunk[..size]);
        match inbound {
            Inbound::Closed => {
                self.retire();
                Ok(Some(Input::Progress))
            }
            Inbound::Received => Ok(Some(Input::Progress)),
            Inbound::Idle => Ok(None),
        }
    }

    /// Releases the exact socket, retaining complete already-accepted frames before closure.
    fn retire(&mut self) -> bool {
        if matches!(self.phase, Phase::Closed | Phase::Retiring) {
            return false;
        }
        self.wire = None;
        if !matches!(self.phase, Phase::Active) {
            self.decoder = TurnStreamDecoder::new();
        }
        self.phase = Phase::Retiring;
        true
    }
}

#[cfg(test)]
mod tests;
