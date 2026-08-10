use std::path::PathBuf;

use crate::ownership::{OwnedTc, OwnedXdp, OwnershipRecord, TcKernelIdentity, XdpKernelIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaceConfigIdentity {
    pub ifindex: u32,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinIdentity {
    pub path: PathBuf,
    pub map_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOperation {
    RemoveJournal,
    RemoveIfaceConfig(IfaceConfigIdentity),
    RemoveDependentMapEntries(IfaceConfigIdentity),
    UnpinMap(PinIdentity),
    DetachTc(OwnedTc),
    DetachXdp(OwnedXdp),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedResource {
    pub resource: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    pub operations: Vec<CleanupOperation>,
    pub retained: Vec<RetainedResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupSnapshot {
    pub journal: Option<OwnershipRecord>,
    pub xdp: Option<XdpKernelIdentity>,
    pub tc: Vec<TcKernelIdentity>,
    pub iface_config: Option<IfaceConfigIdentity>,
    pub pins: Vec<PinIdentity>,
    pub owned_program_map_ids: Vec<(u32, Vec<u32>)>,
}

pub fn plan_owned_cleanup(record: &OwnershipRecord, snapshot: &CleanupSnapshot) -> CleanupPlan {
    let mut operations = Vec::new();
    let mut retained = Vec::new();

    if snapshot.journal.as_ref() == Some(record) {
        operations.push(CleanupOperation::RemoveJournal);
    } else {
        retain(&mut retained, "journal", "fresh journal identity mismatch");
    }

    let config = IfaceConfigIdentity {
        ifindex: record.ifindex,
        generation: record.generation,
    };
    if snapshot.iface_config == Some(config) {
        operations.push(CleanupOperation::RemoveIfaceConfig(config));
        operations.push(CleanupOperation::RemoveDependentMapEntries(config));
    } else {
        retain(
            &mut retained,
            "IFACE_CONFIG",
            "fresh map entry identity mismatch",
        );
    }

    for owned_pin in record.map_pins.iter().rev() {
        let current = snapshot.pins.iter().find(|pin| pin.path == owned_pin.path);
        match current {
            Some(pin) if pin.map_id == owned_pin.map_id => {
                operations.push(CleanupOperation::UnpinMap(pin.clone()));
            }
            Some(_) => retain(
                &mut retained,
                &format!("pin {}", owned_pin.path.display()),
                "fresh pinned map ID does not match the journal",
            ),
            None => retain(
                &mut retained,
                &format!("pin {}", owned_pin.path.display()),
                "journal pin is absent from the fresh snapshot",
            ),
        }
    }

    for owned in record.tc.iter().rev() {
        if snapshot.tc.contains(&TcKernelIdentity::from(*owned)) {
            operations.push(CleanupOperation::DetachTc(*owned));
        } else {
            retain(&mut retained, "TC hook", "fresh TC identity mismatch");
        }
    }

    if let Some(owned) = record.xdp {
        if snapshot.xdp == Some(XdpKernelIdentity::from(owned)) {
            operations.push(CleanupOperation::DetachXdp(owned));
        } else {
            retain(&mut retained, "XDP hook", "fresh XDP identity mismatch");
        }
    }

    CleanupPlan {
        operations,
        retained,
    }
}

pub trait CleanupIo {
    fn identity_still_matches(&mut self, operation: &CleanupOperation) -> Result<bool, String>;
    fn execute_exact(&mut self, operation: &CleanupOperation) -> Result<(), String>;
}

pub fn execute_cleanup_plan<I: CleanupIo>(io: &mut I, plan: CleanupPlan) -> CleanupPlan {
    let mut completed = Vec::new();
    let mut retained = plan.retained;
    for operation in plan.operations {
        match io.identity_still_matches(&operation) {
            Ok(true) => match io.execute_exact(&operation) {
                Ok(()) => completed.push(operation),
                Err(evidence) => retained.push(RetainedResource {
                    resource: format!("{operation:?}"),
                    evidence,
                }),
            },
            Ok(false) => retained.push(RetainedResource {
                resource: format!("{operation:?}"),
                evidence: "identity changed immediately before cleanup".to_owned(),
            }),
            Err(evidence) => retained.push(RetainedResource {
                resource: format!("{operation:?}"),
                evidence,
            }),
        }
    }
    CleanupPlan {
        operations: completed,
        retained,
    }
}

fn retain(retained: &mut Vec<RetainedResource>, resource: &str, evidence: &str) {
    retained.push(RetainedResource {
        resource: resource.to_owned(),
        evidence: evidence.to_owned(),
    });
}
