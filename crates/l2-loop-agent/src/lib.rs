//! User-space daemon library for L2 Loop Detection Agent.

#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod linux;
mod ports;
mod preflight;
pub mod protocol;
mod service;
#[cfg(target_os = "linux")]
pub mod transport;

pub use ports::*;
pub use preflight::*;
pub use service::*;
