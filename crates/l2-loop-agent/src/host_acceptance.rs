use std::{ffi::OsStr, fs, io, path::Path};

use aya::maps::{MapData, PerCpuHashMap};
use l2_loop_common::{CounterValue, StatsKey, hook_role};
use l2_loop_core::{AttachmentState, Direction, InterfaceName, TcAttachment};
use nix::libc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    linux::inspector::{BpfQuery, LinkSource, SystemBpfQuery, SystemLinkSource},
    ownership::{
        FileOwnershipRepository, JournalPath, OwnershipRecord, RunId, TcHook, XdpAttachMode,
    },
};

const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
const BPF_MAP_GET_NEXT_ID: libc::c_long = 12;
const BPFFS_ROOT: &str = "/sys/fs/bpf";
const HOOK_STATS: &str = "HOOK_STATS";

#[derive(Debug, Error)]
pub enum HostAcceptanceError {
    #[error("host identity inspection failed: {0}")]
    Inspection(String),
    #[error("host identity I/O failed")]
    Io(#[from] io::Error),
    #[error("ownership journal is invalid")]
    InvalidJournal,
    #[error("owned hook identity does not match the kernel")]
    HookMismatch,
    #[error("owned counter map is invalid")]
    CounterMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentitySnapshot {
    pub program_ids: Vec<u32>,
    pub map_ids: Vec<u32>,
    pub pin_roots: Vec<PinRootIdentity>,
    pub interfaces: Vec<InterfaceBpfIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRootIdentity {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceBpfIdentity {
    pub name: String,
    pub ifindex: u32,
    pub xdp_native: AttachmentState,
    pub xdp_generic: AttachmentState,
    pub tc_state_known: bool,
    pub tc_clsact: bool,
    pub tc_ingress: Vec<TcAttachment>,
    pub tc_egress: Vec<TcAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookCounters {
    pub role: u8,
    pub packets: u64,
    pub bytes: u64,
}

pub fn capture_host_identity() -> Result<HostIdentitySnapshot, HostAcceptanceError> {
    let mut links = SystemLinkSource
        .read_links()
        .map_err(|error| HostAcceptanceError::Inspection(error.to_string()))?;
    links.sort_by(|left, right| {
        left.ifindex
            .cmp(&right.ifindex)
            .then_with(|| left.name.as_str().cmp(right.name.as_str()))
    });

    let mut query = SystemBpfQuery;
    let mut interfaces = Vec::with_capacity(links.len());
    for link in links {
        let observed = query
            .query_bpf(&[link.ifindex])
            .map_err(|error| HostAcceptanceError::Inspection(error.to_string()))?;
        let mut tc_ingress = observed
            .tc_ingress
            .into_iter()
            .map(|entry| entry.attachment)
            .collect::<Vec<_>>();
        let mut tc_egress = observed
            .tc_egress
            .into_iter()
            .map(|entry| entry.attachment)
            .collect::<Vec<_>>();
        sort_tc(&mut tc_ingress);
        sort_tc(&mut tc_egress);
        interfaces.push(InterfaceBpfIdentity {
            name: link.name.as_str().to_owned(),
            ifindex: link.ifindex,
            xdp_native: observed.xdp_native,
            xdp_generic: observed.xdp_generic,
            tc_state_known: observed.tc_state_known,
            tc_clsact: observed.tc_clsact,
            tc_ingress,
            tc_egress,
        });
    }

    Ok(HostIdentitySnapshot {
        program_ids: enumerate_bpf_ids(BPF_PROG_GET_NEXT_ID)?,
        map_ids: enumerate_bpf_ids(BPF_MAP_GET_NEXT_ID)?,
        pin_roots: read_pin_roots(Path::new(BPFFS_ROOT))?,
        interfaces,
    })
}

pub fn verify_owned_hooks(
    snapshot: &HostIdentitySnapshot,
    record: &OwnershipRecord,
    interface: &InterfaceName,
) -> Result<(), HostAcceptanceError> {
    let observed = snapshot
        .interfaces
        .iter()
        .find(|candidate| {
            candidate.name == interface.as_str() && candidate.ifindex == record.ifindex
        })
        .ok_or(HostAcceptanceError::HookMismatch)?;
    let xdp = record.xdp.ok_or(HostAcceptanceError::HookMismatch)?;
    if xdp.ifindex != record.ifindex || !snapshot.program_ids.contains(&xdp.program_id) {
        return Err(HostAcceptanceError::HookMismatch);
    }
    let xdp_state = match xdp.mode {
        XdpAttachMode::Native => observed.xdp_native,
        XdpAttachMode::Generic => observed.xdp_generic,
    };
    if xdp_state
        != (AttachmentState::Occupied {
            program_id: xdp.program_id,
        })
    {
        return Err(HostAcceptanceError::HookMismatch);
    }

    if record.tc.len() != 1 {
        return Err(HostAcceptanceError::HookMismatch);
    }
    let tc = record.tc[0];
    let expected = TcAttachment {
        direction: match tc.hook {
            TcHook::Ingress => Direction::Ingress,
            TcHook::Egress => Direction::Egress,
        },
        priority: tc.priority,
        handle: tc.handle,
        program_id: tc.program_id,
    };
    let filters = match tc.hook {
        TcHook::Ingress => &observed.tc_ingress,
        TcHook::Egress => &observed.tc_egress,
    };
    if tc.ifindex != record.ifindex
        || !snapshot.program_ids.contains(&tc.program_id)
        || !observed.tc_state_known
        || !filters.contains(&expected)
    {
        return Err(HostAcceptanceError::HookMismatch);
    }
    Ok(())
}

pub fn read_owned_counters(
    record: &OwnershipRecord,
) -> Result<[HookCounters; 2], HostAcceptanceError> {
    let path = record
        .pin_paths
        .iter()
        .find(|path| path.file_name() == Some(OsStr::new(HOOK_STATS)))
        .ok_or(HostAcceptanceError::CounterMap)?;
    let map = MapData::from_pin(path).map_err(|_| HostAcceptanceError::CounterMap)?;
    let stats = PerCpuHashMap::<MapData, StatsKey, CounterValue>::try_from(map)
        .map_err(|_| HostAcceptanceError::CounterMap)?;
    let read = |role| -> Result<HookCounters, HostAcceptanceError> {
        let key = StatsKey::total(record.generation, record.ifindex, role);
        let values = stats
            .get(&key, 0)
            .map_err(|_| HostAcceptanceError::CounterMap)?;
        let mut packets = 0_u64;
        let mut bytes = 0_u64;
        for value in values.iter() {
            packets = packets
                .checked_add(value.packets)
                .ok_or(HostAcceptanceError::CounterMap)?;
            bytes = bytes
                .checked_add(value.bytes)
                .ok_or(HostAcceptanceError::CounterMap)?;
        }
        Ok(HookCounters {
            role,
            packets,
            bytes,
        })
    };
    Ok([
        read(hook_role::EXTERNAL_XDP_INGRESS)?,
        read(hook_role::PHYSICAL_TC_EGRESS)?,
    ])
}

pub fn load_exact_journal(path: &Path) -> Result<OwnershipRecord, HostAcceptanceError> {
    let run_id = path
        .file_stem()
        .and_then(OsStr::to_str)
        .and_then(|value| RunId::parse(value).ok())
        .ok_or(HostAcceptanceError::InvalidJournal)?;
    let expected =
        JournalPath::new(run_id.clone()).map_err(|_| HostAcceptanceError::InvalidJournal)?;
    if expected.path() != path {
        return Err(HostAcceptanceError::InvalidJournal);
    }
    FileOwnershipRepository
        .load(&run_id)
        .map_err(|_| HostAcceptanceError::InvalidJournal)
}

fn sort_tc(filters: &mut [TcAttachment]) {
    filters.sort_by_key(|filter| (filter.priority, filter.handle, filter.program_id));
}

fn read_pin_roots(root: &Path) -> Result<Vec<PinRootIdentity>, HostAcceptanceError> {
    let mut roots = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostAcceptanceError::Inspection("non-UTF-8 bpffs root".to_owned()))?;
        let file_type = entry.file_type()?;
        let kind = if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        roots.push(PinRootIdentity {
            name,
            kind: kind.to_owned(),
        });
    }
    roots.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(roots)
}

#[repr(C)]
#[derive(Debug, Default)]
struct BpfGetNextIdAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

fn enumerate_bpf_ids(command: libc::c_long) -> Result<Vec<u32>, HostAcceptanceError> {
    let mut ids = Vec::new();
    let mut start_id = 0_u32;
    loop {
        let mut attr = BpfGetNextIdAttr {
            start_id,
            ..Default::default()
        };
        // SAFETY: the BPF get-next-id commands read and update only the fully initialized attr.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                command,
                &mut attr as *mut BpfGetNextIdAttr,
                std::mem::size_of::<BpfGetNextIdAttr>(),
            )
        };
        if result == 0 {
            if attr.next_id == 0 || attr.next_id <= start_id {
                return Err(HostAcceptanceError::Inspection(
                    "kernel returned an invalid BPF object ID".to_owned(),
                ));
            }
            ids.push(attr.next_id);
            start_id = attr.next_id;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            break;
        }
        return Err(HostAcceptanceError::Io(error));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ownership::{OWNERSHIP_SCHEMA_VERSION, OwnedTc, OwnedXdp};

    #[test]
    fn exact_owned_hook_identity_is_accepted() {
        let record = ownership();
        let interface = InterfaceName::new("l2h0123456789").unwrap();
        let snapshot = HostIdentitySnapshot {
            program_ids: vec![101, 102],
            map_ids: vec![201],
            pin_roots: Vec::new(),
            interfaces: vec![InterfaceBpfIdentity {
                name: interface.as_str().to_owned(),
                ifindex: 7,
                xdp_native: AttachmentState::Empty,
                xdp_generic: AttachmentState::Occupied { program_id: 101 },
                tc_state_known: true,
                tc_clsact: true,
                tc_ingress: Vec::new(),
                tc_egress: vec![TcAttachment {
                    direction: Direction::Egress,
                    priority: 49_600,
                    handle: 0x4c32_0002,
                    program_id: 102,
                }],
            }],
        };
        assert!(verify_owned_hooks(&snapshot, &record, &interface).is_ok());
    }

    #[test]
    fn changed_program_identity_is_rejected() {
        let record = ownership();
        let interface = InterfaceName::new("l2h0123456789").unwrap();
        let snapshot = HostIdentitySnapshot {
            program_ids: vec![999, 102],
            map_ids: Vec::new(),
            pin_roots: Vec::new(),
            interfaces: vec![InterfaceBpfIdentity {
                name: interface.as_str().to_owned(),
                ifindex: 7,
                xdp_native: AttachmentState::Empty,
                xdp_generic: AttachmentState::Occupied { program_id: 999 },
                tc_state_known: true,
                tc_clsact: true,
                tc_ingress: Vec::new(),
                tc_egress: Vec::new(),
            }],
        };
        assert!(matches!(
            verify_owned_hooks(&snapshot, &record, &interface),
            Err(HostAcceptanceError::HookMismatch)
        ));
    }

    fn ownership() -> OwnershipRecord {
        OwnershipRecord {
            schema_version: OWNERSHIP_SCHEMA_VERSION,
            abi_version: l2_loop_common::ABI_VERSION,
            generation: 1,
            ifindex: 7,
            xdp: Some(OwnedXdp {
                ifindex: 7,
                mode: XdpAttachMode::Generic,
                program_id: 101,
                program_tag: [1; 8],
                link_id: None,
            }),
            tc: vec![OwnedTc {
                ifindex: 7,
                hook: TcHook::Egress,
                priority: 49_600,
                handle: 0x4c32_0002,
                program_id: 102,
                created_clsact: true,
            }],
            pin_paths: vec![PathBuf::from(
                "/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef/HOOK_STATS",
            )],
            created_at_unix_seconds: 1,
        }
    }
}
