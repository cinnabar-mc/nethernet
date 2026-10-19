//! The existing concrete nonblocking dial and prepared TLS policy shared by HTTP and TURN.
use super::Wire;
use crate::http_client::JoinError;
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(feature = "tls")]
use std::sync::Arc;

/// Opens the same socket, optionally binds its concrete source, then starts a nonblocking connect.
/// Callers inspect this socket's actual local address; no UDP tuple is substituted.
fn connect_socket(addr: SocketAddr, bind_ip: Option<IpAddr>) -> std::io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    if let Some(ip) = bind_ip {
        if ip.is_unspecified() || ip.is_multicast() || ip.is_ipv4() != addr.is_ipv4() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "invalid TCP source interface",
            ));
        }
        socket.bind(&SocketAddr::new(ip, 0).into())?;
    }
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(error) if connect_in_progress(&error) => {}
        Err(error) => return Err(error),
    }
    Ok(socket.into())
}

/// Identifies the platform's nonblocking in-progress result without hiding real connect failures.
fn connect_in_progress(error: &std::io::Error) -> bool {
    if error.kind() == ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[derive(Clone, Default)]
pub(crate) struct ClientTls {
    #[cfg(feature = "tls")]
    config: Option<Arc<rustls::ClientConfig>>,
}

impl ClientTls {
    /// Validates every TLS authority before any target socket is opened.
    pub(crate) fn validate_name(host: &str) -> std::io::Result<()> {
        #[cfg(feature = "tls")]
        {
            rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|_| JoinError::InvalidServerName)?;
            Ok(())
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = host;
            Err(JoinError::TlsUnavailable.into())
        }
    }

    #[cfg(feature = "tls")]
    pub(crate) fn with_config(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            config: Some(config),
        }
    }

    /// Prepares platform trust during explicit setup, before delayed gathering moves the dial into a frame.
    pub(crate) fn prepare(&mut self, secure: bool) -> std::io::Result<()> {
        if !secure {
            return Ok(());
        }
        #[cfg(feature = "tls")]
        {
            if self.config.is_none() {
                self.config = Some(Self::platform_config().map_err(JoinError::from)?);
            }
            Ok(())
        }
        #[cfg(not(feature = "tls"))]
        {
            Err(JoinError::TlsUnavailable.into())
        }
    }

    pub(crate) fn dial(
        &self,
        secure: bool,
        host: &str,
        addr: SocketAddr,
        bind_ip: Option<IpAddr>,
    ) -> std::io::Result<Wire> {
        let wire = match secure {
            true => self.secure_wire(host, addr, bind_ip)?,
            false => Wire::plain(connect_socket(addr, bind_ip)?),
        };
        Ok(wire)
    }

    #[cfg(feature = "tls")]
    fn secure_wire(
        &self,
        host: &str,
        addr: SocketAddr,
        bind_ip: Option<IpAddr>,
    ) -> std::io::Result<Wire> {
        let config = match &self.config {
            Some(config) => config.clone(),
            None => Self::platform_config().map_err(JoinError::from)?,
        };
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| JoinError::InvalidServerName)?;
        let wire = Wire::tls_client(connect_socket(addr, bind_ip)?, config, name)
            .map_err(JoinError::from)?;
        Ok(wire)
    }

    #[cfg(not(feature = "tls"))]
    fn secure_wire(
        &self,
        _host: &str,
        _addr: SocketAddr,
        _bind_ip: Option<IpAddr>,
    ) -> std::io::Result<Wire> {
        Err(JoinError::TlsUnavailable.into())
    }

    #[cfg(feature = "tls")]
    fn platform_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}
