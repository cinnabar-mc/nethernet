//! The sole TCP socket owner, including TLS's physical reads and writes.

use crate::transport::EgressPolicy;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub(super) struct Stream {
    socket: TcpStream,
    remote: SocketAddr,
    egress: Option<EgressPolicy>,
}

impl Stream {
    /// Checks the original numeric destination immediately before the OS connect.
    pub fn connect(
        remote: SocketAddr,
        bind: Option<IpAddr>,
        egress: Option<EgressPolicy>,
    ) -> io::Result<Self> {
        let socket = Socket::new(
            Domain::for_address(remote),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        if let Some(ip) = bind {
            socket.bind(&SocketAddr::new(ip, 0).into())?;
        }
        if let Some(policy) = &egress {
            policy.check(remote)?;
        }
        match socket.connect(&remote.into()) {
            Ok(()) => {}
            Err(error) if connect_in_progress(&error) => {}
            Err(error) => return Err(error),
        }
        Ok(Self {
            socket: TcpStream::from_std(socket.into())?,
            remote,
            egress,
        })
    }

    /// Reports the actual connected tuple only after checking it against the admitted target.
    pub fn poll_connected(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(SocketAddr, SocketAddr)>> {
        ready!(self.socket.poll_write_ready(cx))?;
        if let Some(error) = self.socket.take_error()? {
            return Poll::Ready(Err(error));
        }
        let remote = self.socket.peer_addr()?;
        if remote != self.remote {
            return Poll::Ready(Err(io::Error::other(
                "TCP remote changed during connection",
            )));
        }
        Poll::Ready(Ok((self.socket.local_addr()?, remote)))
    }

    /// Rechecks the same target at every physical transmission, including deferred TLS output.
    fn check(&self) -> io::Result<()> {
        match &self.egress {
            Some(policy) => policy.check(self.remote),
            None => Ok(()),
        }
    }

    /// Exposes the original socket only to socket-pressure fixtures.
    #[cfg(test)]
    pub fn socket(&self) -> &TcpStream {
        &self.socket
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        stream.check()?;
        Pin::new(&mut stream.socket).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        stream.check()?;
        Pin::new(&mut stream.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        stream.check()?;
        Pin::new(&mut stream.socket).poll_shutdown(cx)
    }
}

/// Nonblocking connect has one portable retry class plus the Unix in-progress error.
fn connect_in_progress(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// TCP and TLS share this original socket, which must transmit small frames immediately.
    #[tokio::test]
    async fn original_turn_socket_disables_nagle() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = Stream::connect(listener.local_addr().unwrap(), None, None).unwrap();
        assert!(stream.socket().nodelay().unwrap());
    }
}
