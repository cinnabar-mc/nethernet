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
pub(crate) const COMMAND_CAPACITY: usize =
    nethernet::protocol::constants::DEFAULT_COMMAND_CHANNEL_CAPACITY;

pub(crate) enum Command {
    #[cfg(test)]
    QueuedCommands(oneshot::Sender<usize>),
    #[cfg(test)]
    SelectedTurnStream(oneshot::Sender<Option<nethernet::session::TurnStreamRoute>>),
    Send(Channel, Bytes, Option<Instant>, oneshot::Sender<Result<()>>),
    Signal(Signal),
    TurnCredentials(
        SocketAddr,
        nethernet::session::TurnCredentials,
        oneshot::Sender<Result<()>>,
    ),
    TurnStreamCredentials(
        Vec<nethernet::session::TurnStreamTarget>,
        Instant,
        oneshot::Sender<Result<()>>,
    ),
    RemoteAddr(oneshot::Sender<Option<SocketAddr>>),
    Rtt(oneshot::Sender<Option<Duration>>),
    SetPlayer(Arc<PlayerInfo>),
    Player(oneshot::Sender<Option<Arc<PlayerInfo>>>),
    SetHost(String),
    Host(oneshot::Sender<Option<String>>),
}
