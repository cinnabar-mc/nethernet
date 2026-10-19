//! Original UDP socket and bounded TURN streams moved together between existing drivers.
mod carrier;
use crate::error::Result;
#[cfg(test)]
use crate::session::guard::transport_now;
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
    streams: Vec<(TurnStreamId, Carrier)>,
    buffer: Box<[u8]>,
    cursor: usize,
}
impl From<Arc<UdpSocket>> for IceIo {
    fn from(udp: Arc<UdpSocket>) -> Self {
        Self {
            udp,
            streams: Vec::new(),
            buffer: vec![0; MAX_DATAGRAM_SIZE].into_boxed_slice(),
            cursor: 0,
        }
    }
}
impl IceIo {
    /// Validates the complete bounded configuration before starting any independent target.
    pub fn configured(
        udp: Arc<UdpSocket>,
        ice: &IceConfig,
        targets: &[TurnStreamTarget],
        tls: Option<&Arc<rustls::ClientConfig>>,
        fallback: Option<IpAddr>,
        now: Instant,
        deadline: Instant,
    ) -> Result<(Self, IceConfig)> {
        ice.validate_with_stream_targets(udp.local_addr()?, targets, now)
            .map_err(nethernet::error::ProtocolError::from)?;
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
        let mut io = Self::from(udp);
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
            match Carrier::start(target, fallback, tls, deadline) {
                Ok(carrier) => {
                    ice.servers.push(IceServer::TurnStream {
                        id,
                        remote: target.remote,
                        credentials: target.credentials.clone(),
                        requested_family: target.requested_family,
                    });
                    io.streams.push((id, carrier));
                }
                Err(error) => tracing::debug!(%error, "TURN stream target could not start"),
            }
        }
        Ok((io, ice))
    }

    pub fn blocked(&self) -> bool {
        self.streams.iter().any(|(_, carrier)| carrier.blocked())
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

    pub async fn send_datagram(&self, data: &[u8], to: SocketAddr) -> Result<()> {
        self.udp.send_to(data, to).await?;
        Ok(())
    }
    /// Transfers the original core output into its sole matching carrier without another FIFO.
    pub fn send_stream(&mut self, data: Box<[u8]>, route: TurnStreamRoute) -> Result<()> {
        match self
            .streams
            .iter_mut()
            .find(|(_, carrier)| carrier.route == Some(route))
        {
            Some((_, carrier)) => carrier.send(data),
            None => Err(crate::error::NetherError::ConnectionClosed),
        }
    }
    /// Uses the same owner on Drop; pending prefixes are never replaced by a teardown message.
    pub fn best_effort(&mut self, output: SessionOutput) {
        match output {
            SessionOutput::Send(data, to) => {
                let _ = self.udp.try_send_to(&data, to);
            }
            SessionOutput::SendStream(data, route) => {
                if let Some((_, carrier)) = self
                    .streams
                    .iter_mut()
                    .find(|(_, carrier)| carrier.route == Some(route))
                {
                    let mut context = Context::from_waker(futures::task::noop_waker_ref());
                    if carrier.blocked() {
                        let _ = carrier.poll(&mut context);
                    }
                    if !carrier.blocked() && carrier.send(data).is_ok() {
                        let _ = carrier.poll(&mut context);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
