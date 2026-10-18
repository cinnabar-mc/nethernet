use crate::error::Result;
use crate::session::Channel;
use bytes::Bytes;
use nethernet::identity::PlayerInfo;
use nethernet::protocol::Signal;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Bounds retained actor commands independently of application-owned pending send futures.
pub(super) const COMMAND_CAPACITY: usize = 16;

pub(crate) enum Command {
    #[cfg(test)]
    QueuedCommands(oneshot::Sender<usize>),
    Send(Channel, Bytes, Option<Instant>, oneshot::Sender<Result<()>>),
    Signal(Signal),
    TurnCredentials(
        SocketAddr,
        nethernet::session::TurnCredentials,
        oneshot::Sender<Result<()>>,
    ),
    RemoteAddr(oneshot::Sender<Option<SocketAddr>>),
    Rtt(oneshot::Sender<Option<Duration>>),
    SetPlayer(Arc<PlayerInfo>),
    Player(oneshot::Sender<Option<Arc<PlayerInfo>>>),
    SetHost(String),
    Host(oneshot::Sender<Option<String>>),
}
