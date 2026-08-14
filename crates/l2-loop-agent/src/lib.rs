//! User-space daemon library for L2 Loop Detection Agent.

#[cfg(target_os = "linux")]
mod alert;
#[cfg(target_os = "linux")]
mod attach;
#[cfg(target_os = "linux")]
pub mod daemon;
mod deployment;
mod deployment_cli;
#[cfg(target_os = "linux")]
mod evidence_store;
#[cfg(target_os = "linux")]
pub mod host_acceptance;
mod incident;
#[cfg(target_os = "linux")]
mod incident_output;
mod installation;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod observation;
#[cfg(target_os = "linux")]
pub mod ownership;
mod ports;
mod preflight;
pub mod protocol;
mod service;
#[cfg(target_os = "linux")]
pub mod transport;

#[cfg(target_os = "linux")]
pub use alert::*;
#[cfg(target_os = "linux")]
pub use attach::*;
pub use deployment::*;
pub use deployment_cli::*;
#[cfg(target_os = "linux")]
pub use evidence_store::*;
pub use incident::*;
#[cfg(target_os = "linux")]
pub use incident_output::*;
pub use installation::*;
#[cfg(target_os = "linux")]
pub use observation::*;
pub use ports::*;
pub use preflight::*;
pub use service::*;
