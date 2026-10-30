//! Original UDP socket and bounded TURN streams moved together between existing drivers.
mod carrier;
use crate::error::Result;
#[cfg(test)]
use crate::session::guard::transport_now;
use crate::transport::EgressPolicy;
use carrier::{Carrier, CarrierEvent};
use nethernet::connection::ConnectionInput;
use nethernet::protocol::constants::MAX_DATAGRAM_SIZE;
use nethernet::session::{
    IceConfig, IceServer, SessionInput, SessionOutput, TurnStreamId, TurnStreamRoute,
    TurnStreamTarget,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;

/// Requested receive space for an SCTP flight and the kernel overhead of its datagrams.
const UDP_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

#[cfg(test)]
type HeldDatagram = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

pub(crate) enum IceEvent {
    Datagram(Box<[u8]>, SocketAddr),
    Activated(TurnStreamId, TurnStreamRoute),
    Frame(Box<[u8]>, TurnStreamRoute),
    Closed(TurnStreamId),
    Written,
}
impl IceEvent {
    pub fn session(self, now: Instant) -> Option<SessionInput> {
        Some(match self {
            Self::Datagram(data, from) => SessionInput::Packet(data, from, now),
            Self::Activated(id, route) => SessionInput::ActivateTurnStream(id, route, now),
            Self::Frame(data, route) => SessionInput::StreamPacket(data, route, now),
            Self::Closed(id) => SessionInput::StreamClosed(id, now),
            Self::Written => return None,
        })
    }
    pub fn connection(self, now: Instant) -> Option<ConnectionInput> {
        Some(match self {
            Self::Datagram(data, from) => ConnectionInput::Packet(data, from, now),
            Self::Activated(id, route) => ConnectionInput::ActivateTurnStream(id, route, now),
            Self::Frame(data, route) => ConnectionInput::StreamPacket(data, route, now),
            Self::Closed(id) => ConnectionInput::StreamClosed(id, now),
            Self::Written => return None,
        })
    }
}

pub(crate) struct IceIo {
    udp: Arc<UdpSocket>,
    egress: Option<EgressPolicy>,
    streams: Vec<(TurnStreamId, Carrier)>,
    buffer: Box<[u8]>,
    cursor: usize,
    #[cfg(test)]
    datagram_gate: std::sync::Mutex<Option<HeldDatagram>>,
}
impl From<Arc<UdpSocket>> for IceIo {
    fn from(udp: Arc<UdpSocket>) -> Self {
        configure_receive_buffer(udp.as_ref());
        Self {
            udp,
            egress: None,
            streams: Vec::new(),
            buffer: vec![0; MAX_DATAGRAM_SIZE].into_boxed_slice(),
            cursor: 0,
            #[cfg(test)]
            datagram_gate: std::sync::Mutex::new(None),
        }
    }
}
/// Requests burst capacity and keeps larger buffers chosen by the caller.
fn configure_receive_buffer(udp: &UdpSocket) {
    let socket = socket2::SockRef::from(udp);
    if let Ok(current) = socket.recv_buffer_size()
        && current < UDP_RECEIVE_BUFFER_BYTES
        && let Err(error) = socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER_BYTES)
    {
        tracing::debug!(%error, "could not enlarge UDP receive buffer");
    }
}

impl IceIo {
    /// Installs one immutable admission owner before gathering or carrier construction.
    pub(crate) fn with_egress_policy(mut self, policy: Option<EgressPolicy>) -> Self {
        self.egress = policy;
        self
    }

    /// Rejects a destination before the original numeric tuple reaches the OS.
    fn check_egress(&self, remote: SocketAddr) -> std::io::Result<()> {
        match &self.egress {
            Some(policy) => policy.check(remote),
            None => Ok(()),
        }
    }

    /// Holds only the next original UDP send future; no readiness, packets or terminal are supplied.
    #[cfg(test)]
    pub(crate) fn hold_next_datagram(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered, observing) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        *self.datagram_gate.get_mut().unwrap() = Some((entered, released));
        (observing, release)
    }

    /// Validates the complete bounded configuration before starting any independent target.
    pub fn configured(
        self,
        ice: &IceConfig,
        targets: &[TurnStreamTarget],
        tls: Option<&Arc<rustls::ClientConfig>>,
        fallback: Option<IpAddr>,
        now: Instant,
        deadline: Instant,
    ) -> Result<(Self, IceConfig)> {
        ice.validate_with_stream_targets(self.udp.local_addr()?, targets, now)
            .map_err(nethernet::error::ProtocolError::from)?;
        for remote in ice
            .servers
            .iter()
            .map(IceServer::addr)
            .chain(targets.iter().map(|target| target.remote))
        {
            self.check_egress(remote)?;
        }
        let deadline = deadline.min(now + ice.gather_timeout);
        let names = carrier::tls_names(targets)?;
        let connector = if names.iter().any(Option::is_some) {
            Some(TlsConnector::from(match tls {
                Some(config) => config.clone(),
                None => carrier::platform_config()?,
            }))
        } else {
            None
        };
        let mut io = self;
        let mut ice = ice.clone();
        for (index, (target, name)) in targets.iter().zip(names).enumerate() {
            let id = TurnStreamId::new(index).map_err(nethernet::error::ProtocolError::from)?;
            let tls = name.map(|name| {
                (
                    connector
                        .as_ref()
                        .expect("TLS target has a verified connector")
                        .clone(),
                    name,
                )
            });
            match Carrier::start(target, fallback, tls, deadline, io.egress.as_ref()) {
                Ok(carrier) => {
                    ice.servers.push(IceServer::TurnStream {
                        id,
                        remote: target.remote,
                        credentials: target.credentials.clone(),
                        requested_family: target.requested_family,
                    });
                    io.streams.push((id, carrier));
                }
                Err(crate::error::NetherError::Io(error))
                    if error.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    return Err(error.into());
                }
                Err(error) => tracing::debug!(%error, "TURN stream target could not start"),
            }
        }
        Ok((io, ice))
    }

    /// Only the core's actual selected carrier applies session-wide application backpressure.
    pub fn blocked(&self, selected: Option<TurnStreamRoute>) -> bool {
        selected.is_some_and(|route| {
            self.streams
                .iter()
                .any(|(_, carrier)| carrier.route == Some(route) && carrier.blocked())
        })
    }
    /// Read-only actual socket pressure observation, independent of actor command admission.
    #[cfg(test)]
    pub(crate) fn kernel_blocked(&self, selected: Option<TurnStreamRoute>) -> bool {
        selected.is_some_and(|route| {
            self.streams
                .iter()
                .any(|(_, carrier)| carrier.route == Some(route) && carrier.kernel_blocked())
        })
    }

    pub async fn next(&mut self) -> Result<IceEvent> {
        let deadline = self
            .streams
            .iter()
            .filter_map(|(_, carrier)| carrier.setup_deadline())
            .min();
        tokio::select! {
            biased;
            event = futures::future::poll_fn(|cx| self.poll_next(cx)) => event,
            _ = async { match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => futures::future::pending().await,
            } } => futures::future::poll_fn(|cx| self.poll_next(cx)).await,
        }
    }
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<IceEvent>> {
        // Rotate bounded stream precedence so a busy stream cannot starve another stream or UDP.
        let slots = self.streams.len() + 1;
        for offset in 0..slots {
            let index = (self.cursor + offset) % slots;
            let event = if index == self.streams.len() {
                let mut buffer = ReadBuf::new(&mut self.buffer);
                match self.udp.poll_recv_from(cx, &mut buffer) {
                    Poll::Ready(Ok(from)) => {
                        Some(Ok(IceEvent::Datagram(buffer.filled().into(), from)))
                    }
                    Poll::Ready(Err(error)) => Some(Err(error.into())),
                    Poll::Pending => None,
                }
            } else {
                let (id, carrier) = &mut self.streams[index];
                match carrier.poll(cx) {
                    Poll::Ready(event) => Some(Ok(match event {
                        CarrierEvent::Activated(route) => IceEvent::Activated(*id, route),
                        CarrierEvent::Frame(data) => IceEvent::Frame(
                            data,
                            carrier.route.expect("active stream retains actual tuple"),
                        ),
                        CarrierEvent::Closed => IceEvent::Closed(*id),
                        CarrierEvent::Written => IceEvent::Written,
                    })),
                    Poll::Pending => None,
                }
            };
            if let Some(event) = event {
                self.cursor = (index + 1) % slots;
                return Poll::Ready(event);
            }
        }
        Poll::Pending
    }

    /// Takes exactly one fresh credential for the same original selected stream descriptor.
    pub fn selected_credentials(
        &self,
        targets: Vec<TurnStreamTarget>,
        selected: TurnStreamRoute,
        now: Instant,
    ) -> Result<nethernet::session::TurnCredentials> {
        self.check_egress(selected.remote())?;
        let (_, carrier) = self
            .streams
            .iter()
            .find(|(_, carrier)| carrier.active_route() == Some(selected))
            .ok_or_else(|| {
                crate::error::NetherError::Ice("selected TURN stream is not active".into())
            })?;
        let mut matches = targets
            .into_iter()
            .filter(|target| carrier.matches_target(target));
        let target = matches.next().ok_or_else(|| {
            crate::error::NetherError::Ice("selected TURN stream has no replacement".into())
        })?;
        if matches.next().is_some() {
            return Err(crate::error::NetherError::Ice(
                "selected TURN replacement is ambiguous".into(),
            ));
        }
        target
            .validate(now)
            .map_err(nethernet::error::ProtocolError::from)?;
        Ok(target.credentials)
    }

    pub async fn send_datagram(&self, data: &[u8], to: SocketAddr) -> Result<()> {
        #[cfg(test)]
        {
            let gate = self.datagram_gate.lock().unwrap().take();
            if let Some((entered, released)) = gate {
                let _ = entered.send(());
                let _ = released.await;
            }
        }
        self.check_egress(to)?;
        self.udp.send_to(data, to).await?;
        Ok(())
    }
    /// Transfers the original core output into its sole matching carrier without another FIFO.
    pub fn send_stream(
        &mut self,
        data: Vec<u8>,
        route: TurnStreamRoute,
        selected: Option<TurnStreamRoute>,
    ) -> Result<()> {
        self.check_egress(route.remote())?;
        match self
            .streams
            .iter_mut()
            .find(|(_, carrier)| carrier.route == Some(route))
        {
            Some((_, carrier)) => {
                if carrier.retiring() {
                    return Ok(());
                }
                if carrier.blocked() && !carrier.flush_now() {
                    if selected == Some(route) {
                        return Err(crate::error::NetherError::InvalidState(
                            "selected TURN output polled during write backpressure".into(),
                        ));
                    }
                    // Candidate-local overload: another payload would exceed this carrier's slot.
                    carrier.retire();
                    return Ok(());
                }
                if carrier.retiring() {
                    return Ok(());
                }
                carrier.send(data)
            }
            None => Err(crate::error::NetherError::ConnectionClosed),
        }
    }
    /// Uses the same owner on Drop; pending prefixes are never replaced by a teardown message.
    pub fn best_effort(&mut self, output: SessionOutput) {
        match output {
            SessionOutput::Send(data, to) => {
                if self.check_egress(to).is_ok() {
                    let _ = self.udp.try_send_to(&data, to);
                }
            }
            SessionOutput::SendStream(data, route) => {
                if self.check_egress(route.remote()).is_err() {
                    return;
                }
                if let Some((_, carrier)) = self
                    .streams
                    .iter_mut()
                    .find(|(_, carrier)| carrier.route == Some(route))
                    && carrier.flush_now()
                    && !carrier.retiring()
                    && carrier.send(data).is_ok()
                {
                    let _ = carrier.flush_now();
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
