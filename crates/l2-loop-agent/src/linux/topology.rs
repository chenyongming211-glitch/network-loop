use std::str;

use l2_loop_core::InterfaceName;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OvsOutputError {
    #[error("OVS bridge output is not UTF-8")]
    InvalidUtf8,
    #[error("OVS bridge output contains multiple names")]
    MultipleBridgeNames,
    #[error("OVS bridge output contains an invalid interface name")]
    InvalidBridgeName,
}

pub fn ovs_vsctl_args(interface: &InterfaceName) -> [&str; 3] {
    ["--timeout=2", "iface-to-br", interface.as_str()]
}

pub fn parse_ovs_bridge_name(output: &[u8]) -> Result<Option<InterfaceName>, OvsOutputError> {
    let output = str::from_utf8(output).map_err(|_| OvsOutputError::InvalidUtf8)?;
    let mut names = output.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(name) = names.next() else {
        return Ok(None);
    };
    if names.next().is_some() {
        return Err(OvsOutputError::MultipleBridgeNames);
    }

    InterfaceName::new(name)
        .map(Some)
        .map_err(|_| OvsOutputError::InvalidBridgeName)
}
