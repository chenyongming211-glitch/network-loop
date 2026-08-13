use std::{
    ffi::OsStr,
    fs, io,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use aya::maps::{HashMap, Map, MapData, MapError, MapInfo, PerCpuHashMap};
use l2_loop_common::{CounterValue, InterfaceConfig, StatsKey, hook_role};
use l2_loop_core::{
    AttachmentState, Direction, InterfaceKind, InterfaceName, PinRootState, PreflightDecision,
    PreflightReport, TcAttachment,
};
use nix::libc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AttachmentSession, AttachmentTransaction, PlatformInspector,
    linux::{
        acceptance_fault::AcceptanceOnlyMode,
        bpf_object::AyaObjectRuntime,
        inspector::{BpfQuery, LinkSource, SystemBpfQuery, SystemLinkSource, SystemLinuxInspector},
        limits::ProcessResourceLimits,
        tc::{RtnetlinkTcIo, SafeTc},
        xdp::{RtnetlinkXdpIo, SafeXdp},
    },
    ownership::{
        FileOwnershipRepository, JournalPath, OWNED_MAP_NAMES, OwnershipRecord, RunId,
        TEST_PIN_BASE, TcHook, XdpAttachMode,
    },
};

const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
const BPF_MAP_GET_NEXT_ID: libc::c_long = 12;
const BPFFS_ROOT: &str = "/sys/fs/bpf";
const HOOK_STATS: &str = "HOOK_STATS";
const ACCEPTANCE_ROOT: &str = "/run/l2-loop/accept";

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
    #[error("isolated pass-through authorization is invalid")]
    InvalidPassThrough,
    #[error("isolated pass-through attachment failed: {0}")]
    PassThroughAttach(String),
    #[error("isolated pass-through cleanup failed: {0}")]
    PassThroughCleanup(String),
    #[error("isolated pass-through control input is invalid")]
    InvalidPassThroughControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptancePassThroughRequest {
    pub mode: AcceptanceOnlyMode,
    pub run_id: RunId,
    pub evidence_root: PathBuf,
    pub artifact_root: PathBuf,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub journal_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptancePassThroughPermit {
    run_id: RunId,
    interface: InterfaceName,
    ifindex: u32,
    evidence_root: PathBuf,
    artifact_root: PathBuf,
    journal_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptancePassThroughState<'a> {
    pub state: &'a str,
    pub run_id: &'a str,
    pub interface: &'a str,
    pub ifindex: u32,
    pub observation_enabled: bool,
}

impl AcceptancePassThroughPermit {
    pub(crate) fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub(crate) fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    pub(crate) fn authorizes(&self, interface: &InterfaceName, report: &PreflightReport) -> bool {
        interface == &self.interface
            && report.interface.requested.name == self.interface
            && report.interface.requested.ifindex == self.ifindex
    }

    fn matches_request(&self, request: &AcceptancePassThroughRequest) -> bool {
        self.run_id == request.run_id
            && self.interface == request.interface
            && self.ifindex == request.ifindex
            && self.evidence_root == request.evidence_root
            && self.artifact_root == request.artifact_root
            && self.journal_path == request.journal_path
    }

    pub(crate) fn matches_attachment(&self, attachment: &AttachmentSession) -> bool {
        let pin_root = Path::new(TEST_PIN_BASE).join(self.run_id.as_str());
        attachment.ownership.ifindex == self.ifindex
            && attachment.generation == attachment.ownership.generation
            && attachment.ownership.map_pins.len() == OWNED_MAP_NAMES.len()
            && attachment.ownership.map_pins.iter().all(|pin| {
                OWNED_MAP_NAMES.contains(&pin.name.as_str()) && pin.path == pin_root.join(&pin.name)
            })
    }
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

pub fn authorize_acceptance_pass_through(
    request: &AcceptancePassThroughRequest,
    report: &PreflightReport,
    snapshot: &HostIdentitySnapshot,
) -> Result<AcceptancePassThroughPermit, HostAcceptanceError> {
    let expected_artifact_root = Path::new(ACCEPTANCE_ROOT).join(request.run_id.as_str());
    let expected_evidence_root = expected_artifact_root.join("evidence/v1");
    let expected_journal = JournalPath::new(request.run_id.clone())
        .map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    let expected_interface = format!("l2h{}", &request.run_id.as_str()[..10]);
    if request.mode != AcceptanceOnlyMode::PassThrough
        || request.artifact_root != expected_artifact_root
        || request.evidence_root != expected_evidence_root
        || request.journal_path != expected_journal.path()
        || request.interface.as_str() != expected_interface
        || request.ifindex == 0
        || report.decision != PreflightDecision::Ready
        || report.interface.requested.name != request.interface
        || report.interface.requested.ifindex != request.ifindex
        || report.interface.kind != InterfaceKind::Veth
        || !report.interface.isolated
        || report.interface.live_shared
        || report.interface.master.is_some()
        || report.interface.bond.is_some()
        || !report.bpf.relevant_objects_enumerable
        || report.bpf.pin_root != PinRootState::Absent
        || report.bpf.xdp_native != AttachmentState::Empty
        || report.bpf.xdp_generic != AttachmentState::Empty
        || !report.bpf.tc_ingress.is_empty()
        || !report.bpf.tc_egress.is_empty()
    {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }

    let mut matches = snapshot.interfaces.iter().filter(|candidate| {
        candidate.name == request.interface.as_str() && candidate.ifindex == request.ifindex
    });
    let observed = matches
        .next()
        .ok_or(HostAcceptanceError::InvalidPassThrough)?;
    if matches.next().is_some()
        || observed.xdp_native != AttachmentState::Empty
        || observed.xdp_generic != AttachmentState::Empty
        || !observed.tc_state_known
        || !observed.tc_ingress.is_empty()
        || !observed.tc_egress.is_empty()
    {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }

    Ok(AcceptancePassThroughPermit {
        run_id: request.run_id.clone(),
        interface: request.interface.clone(),
        ifindex: request.ifindex,
        evidence_root: request.evidence_root.clone(),
        artifact_root: request.artifact_root.clone(),
        journal_path: request.journal_path.clone(),
    })
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
        .map_pins
        .iter()
        .find(|pin| pin.name == HOOK_STATS)
        .ok_or(HostAcceptanceError::CounterMap)?;
    let info = MapInfo::from_pin(&path.path).map_err(|_| HostAcceptanceError::CounterMap)?;
    if info.id() != path.map_id {
        return Err(HostAcceptanceError::CounterMap);
    }
    let map = Map::PerCpuHashMap(
        MapData::from_pin(&path.path).map_err(|_| HostAcceptanceError::CounterMap)?,
    );
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

pub fn run_acceptance_pass_through<R: Read, W: Write>(
    request: AcceptancePassThroughRequest,
    mut control: R,
    mut output: W,
) -> Result<(), HostAcceptanceError> {
    validate_acceptance_runtime(&request)?;
    let mut inspector = SystemLinuxInspector::system();
    let report = inspector
        .inspect(&request.interface)
        .map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    let snapshot = capture_host_identity()?;
    let permit = authorize_acceptance_pass_through(&request, &report, &snapshot)?;
    if !permit.matches_request(&request) {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    let object_path = permit.artifact_root.join("l2-loop-ebpf.o");
    let runtime = AyaObjectRuntime::new(object_path);
    let mut transaction = AttachmentTransaction::new(
        SystemLinuxInspector::system(),
        ProcessResourceLimits,
        runtime.loader(),
        SafeXdp::new(RtnetlinkXdpIo),
        SafeTc::new(RtnetlinkTcIo),
        runtime.map_publisher(),
        FileOwnershipRepository,
    );
    let created_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostAcceptanceError::InvalidPassThrough)?
        .as_secs();
    let session = transaction
        .execute_acceptance_pass_through(&permit, created_at_unix_seconds)
        .map_err(|error| HostAcceptanceError::PassThroughAttach(error.code().to_owned()))?;

    let operation = (|| {
        let committed = load_exact_journal(&permit.journal_path)?;
        if committed != session.attachment().ownership {
            return Err(HostAcceptanceError::InvalidPassThrough);
        }
        let attached = capture_host_identity()?;
        verify_owned_hooks(&attached, &committed, &permit.interface)?;
        verify_iface_config_unpublished(&committed)?;
        write_pass_through_state(&mut output, "ready", &request)?;

        let mut command = [0_u8; 5];
        control
            .read_exact(&mut command)
            .map_err(|_| HostAcceptanceError::InvalidPassThroughControl)?;
        if command != *b"stop\n" {
            return Err(HostAcceptanceError::InvalidPassThroughControl);
        }
        Ok(())
    })();

    let cleanup = transaction.detach_acceptance_pass_through_exact(&permit, &session);
    if let Err(error) = cleanup {
        return Err(HostAcceptanceError::PassThroughCleanup(
            error.code().to_owned(),
        ));
    }
    write_pass_through_state(&mut output, "cleaned", &request)?;
    operation
}

fn validate_acceptance_runtime(
    request: &AcceptancePassThroughRequest,
) -> Result<(), HostAcceptanceError> {
    let root = exact_private_directory(&request.artifact_root)?;
    let evidence = exact_private_directory(&request.evidence_root)?;
    if root != request.artifact_root || evidence != request.evidence_root {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }

    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    if executable.parent() != Some(request.artifact_root.as_path())
        || executable.file_name() != Some(OsStr::new("l2-loop-hostcheck"))
    {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    exact_regular_file(&executable)?;
    exact_regular_file(&request.artifact_root.join("l2-loop-ebpf.o"))?;

    for absent in [
        request.journal_path.clone(),
        Path::new(TEST_PIN_BASE).join(request.run_id.as_str()),
    ] {
        match fs::symlink_metadata(absent) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(HostAcceptanceError::InvalidPassThrough),
        }
    }
    Ok(())
}

fn exact_private_directory(path: &Path) -> Result<PathBuf, HostAcceptanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != 0
        || metadata.nlink() < 2
    {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    Ok(canonical)
}

fn exact_regular_file(path: &Path) -> Result<(), HostAcceptanceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
    {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    Ok(())
}

fn verify_iface_config_unpublished(record: &OwnershipRecord) -> Result<(), HostAcceptanceError> {
    let pin = record
        .map_pins
        .iter()
        .find(|pin| pin.name == "IFACE_CONFIG")
        .ok_or(HostAcceptanceError::InvalidPassThrough)?;
    let info = MapInfo::from_pin(&pin.path).map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    if info.id() != pin.map_id {
        return Err(HostAcceptanceError::InvalidPassThrough);
    }
    let map = Map::HashMap(
        MapData::from_pin(&pin.path).map_err(|_| HostAcceptanceError::InvalidPassThrough)?,
    );
    let configs = HashMap::<MapData, u32, InterfaceConfig>::try_from(map)
        .map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    match configs.get(&record.ifindex, 0) {
        Err(MapError::KeyNotFound) => Ok(()),
        Ok(_) | Err(_) => Err(HostAcceptanceError::InvalidPassThrough),
    }
}

fn write_pass_through_state<W: Write>(
    output: &mut W,
    state: &'static str,
    request: &AcceptancePassThroughRequest,
) -> Result<(), HostAcceptanceError> {
    serde_json::to_writer(
        &mut *output,
        &AcceptancePassThroughState {
            state,
            run_id: request.run_id.as_str(),
            interface: request.interface.as_str(),
            ifindex: request.ifindex,
            observation_enabled: false,
        },
    )
    .map_err(|_| HostAcceptanceError::InvalidPassThrough)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
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
    use crate::ownership::{
        OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnedTc, OwnedXdp,
    };

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
            map_pins: OWNED_MAP_NAMES
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    OwnedMapPin::new(
                        *name,
                        PathBuf::from("/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef")
                            .join(name),
                        301 + index as u32,
                    )
                    .unwrap()
                })
                .collect(),
            created_at_unix_seconds: 1,
        }
    }
}
