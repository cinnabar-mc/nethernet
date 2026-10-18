//! Sealed public transport phases. Remote closure is still observed at runtime.

mod private {
    pub trait Sealed {}
}

/// A phase owned by this crate; applications cannot implement or construct transport states.
pub trait Phase: private::Sealed {}

/// A phase that can still drive wire input, timers and credentials.
pub trait Live: Phase {}

/// ICE, DTLS and both data channels have not yet produced readiness.
pub struct Connecting {
    _private: (),
}

/// Both data channels became ready. A remote peer may subsequently close or fail.
pub struct Established {
    _private: (),
}

/// The local transport owner was consumed by closure; only queued output can be drained.
pub struct Retired {
    _private: (),
}

impl private::Sealed for Connecting {}
impl private::Sealed for Established {}
impl private::Sealed for Retired {}
impl Phase for Connecting {}
impl Phase for Established {}
impl Phase for Retired {}
impl Live for Connecting {}
impl Live for Established {}
