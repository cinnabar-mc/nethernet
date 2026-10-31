//! HTTP signaling (guide section 4): a client posts the offer and the server's reply carries the answer.
pub mod client;
pub mod probe;
pub mod server;
pub use probe::{HttpProbe, ProbeCache, ProbeError, ProbeSelection};

pub use client::{ClientInfo, HttpSignaling};
pub use server::{HttpServerConfig, HttpSignalingServer};
