//! User-space daemon library for L2 Loop Detection Agent.

#[cfg(target_os = "linux")]
mod attach;
#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod host_acceptance;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod ownership;
#[cfg(target_os = "linux")]
mod observation;
mod ports;
mod preflight;
pub mod protocol;
mod service;
#[cfg(target_os = "linux")]
pub mod transport;

#[cfg(target_os = "linux")]
pub use attach::*;
#[cfg(target_os = "linux")]
pub use observation::*;
pub use ports::*;
pub use preflight::*;
pub use service::*;
