use l2_loop_core::{
    BondInspection, BondMode, InterfaceName, InterfaceRef, PF_BOND_NO_ACTIVE_SLAVE,
};
use thiserror::Error;

use super::interface::LinkRecord;

const ACTIVE_BACKUP_MODE: &str = "fault-tolerance (active-backup)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BondSnapshotError {
    #[error("bond mode is missing")]
    MissingMode,
    #[error("bond mode is unsupported")]
    UnsupportedMode,
    #[error("bond active slave is missing")]
    NoActiveSlave,
    #[error("bond slave list is missing")]
    NoSlaves,
    #[error("bond snapshot contains an invalid interface name")]
    InvalidInterfaceName,
    #[error("bond snapshot contains a duplicate slave")]
    DuplicateSlave,
    #[error("bond active slave is not present in the slave list")]
    ActiveSlaveNotListed,
    #[error("bond active slave disappeared from the link snapshot")]
    ActiveSlaveMissingFromLinks,
    #[error("bond slave disappeared from the link snapshot")]
    SlaveMissingFromLinks,
}

impl BondSnapshotError {
    pub const fn blocker_code(self) -> Option<&'static str> {
        match self {
            Self::NoActiveSlave
            | Self::ActiveSlaveNotListed
            | Self::ActiveSlaveMissingFromLinks => Some(PF_BOND_NO_ACTIVE_SLAVE),
            _ => None,
        }
    }
}

pub fn parse_bond_snapshot(
    snapshot: &str,
    links: &[LinkRecord],
) -> Result<BondInspection, BondSnapshotError> {
    let mode = field(snapshot, "Bonding Mode").ok_or(BondSnapshotError::MissingMode)?;
    if mode != ACTIVE_BACKUP_MODE {
        return Err(BondSnapshotError::UnsupportedMode);
    }

    let active_name = field(snapshot, "Currently Active Slave")
        .filter(|name| !name.is_empty() && *name != "None")
        .ok_or(BondSnapshotError::NoActiveSlave)
        .and_then(parse_interface_name)?;
    let slave_names = fields(snapshot, "Slave Interface")
        .into_iter()
        .map(parse_interface_name)
        .collect::<Result<Vec<_>, _>>()?;
    if slave_names.is_empty() {
        return Err(BondSnapshotError::NoSlaves);
    }
    if has_duplicate(&slave_names) {
        return Err(BondSnapshotError::DuplicateSlave);
    }
    if !slave_names.contains(&active_name) {
        return Err(BondSnapshotError::ActiveSlaveNotListed);
    }

    let mut slaves = Vec::with_capacity(slave_names.len());
    for name in &slave_names {
        let link = links
            .iter()
            .find(|link| link.name == *name)
            .ok_or_else(|| {
                if *name == active_name {
                    BondSnapshotError::ActiveSlaveMissingFromLinks
                } else {
                    BondSnapshotError::SlaveMissingFromLinks
                }
            })?;
        slaves.push(InterfaceRef {
            name: name.clone(),
            ifindex: link.ifindex,
        });
    }

    let active_slave = slaves
        .iter()
        .find(|slave| slave.name == active_name)
        .cloned();

    Ok(BondInspection {
        mode: BondMode::ActiveBackup,
        slaves,
        active_slave,
    })
}

fn field<'a>(snapshot: &'a str, key: &str) -> Option<&'a str> {
    snapshot.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then_some(value.trim())
    })
}

fn fields<'a>(snapshot: &'a str, key: &str) -> Vec<&'a str> {
    snapshot
        .lines()
        .filter_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            (candidate.trim() == key).then_some(value.trim())
        })
        .collect()
}

fn parse_interface_name(value: &str) -> Result<InterfaceName, BondSnapshotError> {
    InterfaceName::new(value).map_err(|_| BondSnapshotError::InvalidInterfaceName)
}

fn has_duplicate(names: &[InterfaceName]) -> bool {
    names
        .iter()
        .enumerate()
        .any(|(index, name)| names[..index].contains(name))
}
