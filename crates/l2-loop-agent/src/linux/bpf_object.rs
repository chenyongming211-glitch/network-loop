use std::{
    fs,
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use aya::{
    Ebpf,
    maps::{Map, MapInfo},
    programs::{Program, SchedClassifier, Xdp},
};
use l2_loop_common::ABI_VERSION;
use thiserror::Error;

use crate::{
    linux::{cleanup::PinIdentity, tc::LoadedTc, xdp::LoadedXdp},
    ownership::TestPinRoot,
    ports::{BpfObjectLoader, LoadedBpfObject, PortError},
};

const XDP_PROGRAM: &str = "l2_loop_xdp_ingress";
const TC_PROGRAM: &str = "l2_loop_tc_egress";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramKind {
    Xdp,
    SchedClassifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Hash,
    PerCpuHash,
    LruHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramDescription {
    pub name: String,
    pub kind: ProgramKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDescription {
    pub name: String,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDescription {
    pub abi_version: u16,
    pub programs: Vec<ProgramDescription>,
    pub maps: Vec<MapDescription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ObjectContractError {
    #[error("BPF ABI version mismatch")]
    AbiVersion,
    #[error("BPF program set mismatch")]
    ProgramSet,
    #[error("BPF program type mismatch")]
    ProgramType,
    #[error("BPF map set mismatch")]
    MapSet,
    #[error("BPF map type mismatch")]
    MapType,
    #[error("BPF map key or value layout mismatch")]
    MapLayout,
    #[error("BPF map capacity is below the ABI floor")]
    MapCapacity,
}

pub fn expected_object_description() -> ObjectDescription {
    ObjectDescription {
        abi_version: ABI_VERSION,
        programs: vec![
            program("l2_loop_tc_egress", ProgramKind::SchedClassifier),
            program("l2_loop_tc_path_egress", ProgramKind::SchedClassifier),
            program("l2_loop_tc_path_ingress", ProgramKind::SchedClassifier),
            program("l2_loop_xdp_ingress", ProgramKind::Xdp),
        ],
        maps: vec![
            map("FINGERPRINTS", MapKind::LruHash, 32, 48, 8192),
            map("HOOK_STATS", MapKind::PerCpuHash, 16, 16, 4096),
            map("IFACE_CONFIG", MapKind::Hash, 4, 32, 64),
            map("PROBE_REGISTRY", MapKind::Hash, 32, 32, 128),
            map("PROBE_STATS", MapKind::PerCpuHash, 32, 16, 128),
            map("RATE_POLICY", MapKind::Hash, 16, 40, 256),
        ],
    }
}

pub fn validate_object_description(actual: &ObjectDescription) -> Result<(), ObjectContractError> {
    let expected = expected_object_description();
    if actual.abi_version != expected.abi_version {
        return Err(ObjectContractError::AbiVersion);
    }
    if names(&actual.programs) != names(&expected.programs) {
        return Err(ObjectContractError::ProgramSet);
    }
    for expected_program in &expected.programs {
        let actual_program = actual
            .programs
            .iter()
            .find(|program| program.name == expected_program.name)
            .ok_or(ObjectContractError::ProgramSet)?;
        if actual_program.kind != expected_program.kind {
            return Err(ObjectContractError::ProgramType);
        }
    }
    if map_names(&actual.maps) != map_names(&expected.maps) {
        return Err(ObjectContractError::MapSet);
    }
    for expected_map in &expected.maps {
        let actual_map = actual
            .maps
            .iter()
            .find(|map| map.name == expected_map.name)
            .ok_or(ObjectContractError::MapSet)?;
        if actual_map.kind != expected_map.kind {
            return Err(ObjectContractError::MapType);
        }
        if actual_map.key_size != expected_map.key_size
            || actual_map.value_size != expected_map.value_size
        {
            return Err(ObjectContractError::MapLayout);
        }
        if actual_map.max_entries < expected_map.max_entries {
            return Err(ObjectContractError::MapCapacity);
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct AyaObjectRuntime {
    pub(super) state: Arc<Mutex<AyaRuntimeState>>,
    object_path: Arc<PathBuf>,
}

impl AyaObjectRuntime {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AyaRuntimeState { active: None })),
            object_path: Arc::new(object_path.into()),
        }
    }

    pub fn loader(&self) -> AyaBpfObjectLoader {
        AyaBpfObjectLoader {
            runtime: self.clone(),
        }
    }

    pub fn map_publisher(&self) -> crate::linux::maps::AyaMapPublisher {
        crate::linux::maps::AyaMapPublisher::new(self.clone())
    }
}

pub struct AyaBpfObjectLoader {
    runtime: AyaObjectRuntime,
}

pub(super) struct AyaRuntimeState {
    pub(super) active: Option<ActiveAyaObject>,
}

pub(super) struct ActiveAyaObject {
    pub(super) bpf: Ebpf,
    pub(super) loaded: LoadedBpfObject,
    pub(super) pins: Vec<PinIdentity>,
    pub(super) initialized: Option<(u32, u64)>,
    pub(super) published: Option<(u32, u64)>,
    pin_root: PathBuf,
    pin_parents: PinParentLease,
}

impl BpfObjectLoader for AyaBpfObjectLoader {
    fn load_and_validate_abi(&mut self, pins: &TestPinRoot) -> Result<LoadedBpfObject, PortError> {
        let mut state = self.runtime.state.lock().map_err(lock_error)?;
        if state.active.is_some() {
            return Err(adapter("an Aya object is already active"));
        }

        let mut bpf = Ebpf::load_file(self.runtime.object_path.as_path())
            .map_err(|error| adapter(format!("failed to load BPF object: {error}")))?;
        let description = describe_object(&bpf)?;
        validate_object_description(&description)
            .map_err(|error| adapter(format!("BPF object contract rejected: {error}")))?;

        let xdp = load_xdp(&mut bpf)?;
        let tc_egress = load_tc(&mut bpf)?;
        let pin_parents = prepare_pin_parents(pins.path())?;
        if let Err(error) = fs::DirBuilder::new().mode(0o700).create(pins.path()) {
            let cleanup = pin_parents.cleanup_exact();
            return Err(adapter(format!(
                "failed to create isolated pin root: {error}; parent cleanup: {cleanup:?}"
            )));
        }

        let mut pinned = Vec::new();
        for expected in expected_object_description().maps {
            let path = pins.path().join(&expected.name);
            let Some(map) = bpf.map(&expected.name) else {
                return Err(rollback_error(
                    format!("validated map {} disappeared", expected.name),
                    &pinned,
                    pins.path(),
                    &pin_parents,
                ));
            };
            let info = match map_info(map) {
                Ok(info) => info,
                Err(error) => {
                    return Err(rollback_error(
                        error.to_string(),
                        &pinned,
                        pins.path(),
                        &pin_parents,
                    ));
                }
            };
            if let Err(error) = map.pin(&path) {
                return Err(rollback_error(
                    format!("failed to pin {}: {error}", expected.name),
                    &pinned,
                    pins.path(),
                    &pin_parents,
                ));
            }
            let fresh = match MapInfo::from_pin(&path) {
                Ok(fresh) => fresh,
                Err(error) => {
                    let just_pinned = PinIdentity {
                        path: path.clone(),
                        map_id: info.id(),
                    };
                    let mut rollback = pinned.clone();
                    rollback.push(just_pinned);
                    return Err(rollback_error(
                        format!("failed to verify pinned map {}: {error}", expected.name),
                        &rollback,
                        pins.path(),
                        &pin_parents,
                    ));
                }
            };
            if fresh.id() != info.id() {
                return Err(rollback_error(
                    format!("pinned map {} changed identity during creation", expected.name),
                    &pinned,
                    pins.path(),
                    &pin_parents,
                ));
            }
            pinned.push(PinIdentity {
                path,
                map_id: info.id(),
            });
        }

        let loaded = LoadedBpfObject {
            xdp,
            tc_egress,
            pin_paths: pinned.iter().map(|pin| pin.path.clone()).collect(),
        };
        state.active = Some(ActiveAyaObject {
            bpf,
            loaded: loaded.clone(),
            pins: pinned,
            initialized: None,
            published: None,
            pin_root: pins.path().to_path_buf(),
            pin_parents,
        });
        Ok(loaded)
    }

    fn unload_exact(&mut self, loaded: &LoadedBpfObject) -> Result<(), PortError> {
        let mut state = self.runtime.state.lock().map_err(lock_error)?;
        let active = state
            .active
            .as_ref()
            .ok_or_else(|| adapter("no Aya object is active"))?;
        if &active.loaded != loaded {
            return Err(adapter("loaded BPF object identity mismatch"));
        }
        if active.initialized.is_some() || active.published.is_some() {
            return Err(adapter(
                "owned map entries must be removed before unloading the Aya object",
            ));
        }
        let active = state.active.take().expect("active object checked above");
        let retained = rollback_pin_tree(&active.pins, &active.pin_root, &active.pin_parents);
        drop(active);
        if retained.is_empty() {
            Ok(())
        } else {
            Err(adapter(format!(
                "retained pins after fresh identity mismatch: {}",
                retained.join(", ")
            )))
        }
    }
}

fn describe_object(bpf: &Ebpf) -> Result<ObjectDescription, PortError> {
    let mut programs = bpf
        .programs()
        .map(|(name, program)| {
            let kind = match program {
                Program::Xdp(_) => ProgramKind::Xdp,
                Program::SchedClassifier(_) => ProgramKind::SchedClassifier,
                _ => return Err(ObjectContractError::ProgramType),
            };
            Ok(ProgramDescription {
                name: name.to_owned(),
                kind,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| adapter(format!("BPF program contract rejected: {error}")))?;
    programs.sort_by(|left, right| left.name.cmp(&right.name));

    let mut maps = bpf
        .maps()
        .map(|(name, map)| {
            let kind = match map {
                Map::HashMap(_) => MapKind::Hash,
                Map::PerCpuHashMap(_) => MapKind::PerCpuHash,
                Map::LruHashMap(_) => MapKind::LruHash,
                _ => return Err(ObjectContractError::MapType),
            };
            let info = map_info(map).map_err(|_| ObjectContractError::MapLayout)?;
            Ok(MapDescription {
                name: name.to_owned(),
                kind,
                key_size: info.key_size(),
                value_size: info.value_size(),
                max_entries: info.max_entries(),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| adapter(format!("BPF map contract rejected: {error}")))?;
    maps.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(ObjectDescription {
        abi_version: ABI_VERSION,
        programs,
        maps,
    })
}

fn load_xdp(bpf: &mut Ebpf) -> Result<LoadedXdp, PortError> {
    let program: &mut Xdp = bpf
        .program_mut(XDP_PROGRAM)
        .ok_or_else(|| adapter("validated XDP program disappeared"))?
        .try_into()
        .map_err(|error| adapter(format!("invalid XDP program type: {error}")))?;
    program
        .load()
        .map_err(|error| adapter(format!("failed to load XDP program: {error}")))?;
    let info = program
        .info()
        .map_err(|error| adapter(format!("failed to query XDP program identity: {error}")))?;
    let program_fd = program
        .fd()
        .map_err(|error| adapter(format!("failed to query XDP program FD: {error}")))?
        .as_fd()
        .as_raw_fd();
    Ok(LoadedXdp {
        program_fd,
        program_id: info.id(),
        program_tag: info.tag().to_be_bytes(),
    })
}

fn load_tc(bpf: &mut Ebpf) -> Result<LoadedTc, PortError> {
    let program: &mut SchedClassifier = bpf
        .program_mut(TC_PROGRAM)
        .ok_or_else(|| adapter("validated TC program disappeared"))?
        .try_into()
        .map_err(|error| adapter(format!("invalid TC program type: {error}")))?;
    program
        .load()
        .map_err(|error| adapter(format!("failed to load TC program: {error}")))?;
    let info = program
        .info()
        .map_err(|error| adapter(format!("failed to query TC program identity: {error}")))?;
    let program_fd = program
        .fd()
        .map_err(|error| adapter(format!("failed to query TC program FD: {error}")))?
        .as_fd()
        .as_raw_fd();
    Ok(LoadedTc {
        program_fd,
        program_id: info.id(),
    })
}

fn map_info(map: &Map) -> Result<MapInfo, PortError> {
    let data = match map {
        Map::HashMap(data) | Map::PerCpuHashMap(data) | Map::LruHashMap(data) => data,
        _ => return Err(adapter("unsupported BPF map type")),
    };
    data.info()
        .map_err(|error| adapter(format!("failed to query map identity: {error}")))
}

#[derive(Debug)]
struct PinParentLease {
    created: Vec<OwnedPinDirectory>,
}

#[derive(Debug)]
struct OwnedPinDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PinParentLease {
    fn cleanup_exact(&self) -> Result<(), PortError> {
        let retained = cleanup_pin_parents(&self.created);
        if retained.is_empty() {
            Ok(())
        } else {
            Err(adapter(format!(
                "retained isolated pin parents: {}",
                retained.join(", ")
            )))
        }
    }
}

fn prepare_pin_parents(path: &Path) -> Result<PinParentLease, PortError> {
    let test_root = path
        .parent()
        .ok_or_else(|| adapter("isolated pin root has no parent"))?;
    let agent_root = test_root
        .parent()
        .ok_or_else(|| adapter("isolated test pin root has no parent"))?;
    let bpffs_root = agent_root
        .parent()
        .ok_or_else(|| adapter("isolated agent pin root has no parent"))?;
    let metadata = fs::symlink_metadata(bpffs_root)
        .map_err(|error| adapter(format!("failed to inspect bpffs root: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(adapter("bpffs root is not a real directory"));
    }
    let canonical = fs::canonicalize(bpffs_root)
        .map_err(|error| adapter(format!("failed to resolve bpffs root: {error}")))?;
    if canonical != bpffs_root {
        return Err(adapter("bpffs root contains a symlink"));
    }
    if fs::symlink_metadata(agent_root).is_ok() {
        return Err(adapter("isolated agent pin root already exists"));
    }

    let mut created = Vec::new();
    for directory in [agent_root, test_root] {
        if let Err(error) = fs::DirBuilder::new().mode(0o700).create(directory) {
            let retained = cleanup_pin_parents(&created);
            return Err(adapter(format!(
                "failed to create isolated pin parent: {error}; retained: {}",
                retained.join(", ")
            )));
        }
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| adapter(format!("failed to inspect created pin parent: {error}")))?;
        created.push(OwnedPinDirectory {
            path: directory.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    Ok(PinParentLease { created })
}

fn rollback_pins(pins: &[PinIdentity], root: &Path) -> Vec<String> {
    let mut retained = Vec::new();
    for pin in pins.iter().rev() {
        match MapInfo::from_pin(&pin.path) {
            Ok(current) if current.id() == pin.map_id => {
                if let Err(error) = fs::remove_file(&pin.path) {
                    retained.push(format!("{} ({error})", pin.path.display()));
                }
            }
            Ok(current) => retained.push(format!(
                "{} (expected map {}, found {})",
                pin.path.display(),
                pin.map_id,
                current.id()
            )),
            Err(error) => retained.push(format!("{} ({error})", pin.path.display())),
        }
    }
    if let Err(error) = fs::remove_dir(root)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        retained.push(format!("{} ({error})", root.display()));
    }
    retained
}

fn rollback_pin_tree(
    pins: &[PinIdentity],
    root: &Path,
    parents: &PinParentLease,
) -> Vec<String> {
    let mut retained = rollback_pins(pins, root);
    retained.extend(cleanup_pin_parents(&parents.created));
    retained
}

fn rollback_error(
    message: String,
    pins: &[PinIdentity],
    root: &Path,
    parents: &PinParentLease,
) -> PortError {
    let retained = rollback_pin_tree(pins, root, parents);
    if retained.is_empty() {
        adapter(message)
    } else {
        adapter(format!("{message}; retained: {}", retained.join(", ")))
    }
}

fn cleanup_pin_parents(parents: &[OwnedPinDirectory]) -> Vec<String> {
    let mut retained = Vec::new();
    for parent in parents.iter().rev() {
        let metadata = match fs::symlink_metadata(&parent.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                retained.push(format!("{} ({error})", parent.path.display()));
                continue;
            }
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != parent.device
            || metadata.ino() != parent.inode
        {
            retained.push(format!("{} (identity changed)", parent.path.display()));
            continue;
        }
        if let Err(error) = fs::remove_dir(&parent.path) {
            retained.push(format!("{} ({error})", parent.path.display()));
        }
    }
    retained
}

fn program(name: &str, kind: ProgramKind) -> ProgramDescription {
    ProgramDescription {
        name: name.to_owned(),
        kind,
    }
}

fn map(
    name: &str,
    kind: MapKind,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> MapDescription {
    MapDescription {
        name: name.to_owned(),
        kind,
        key_size,
        value_size,
        max_entries,
    }
}

fn names(programs: &[ProgramDescription]) -> Vec<&str> {
    let mut names = programs
        .iter()
        .map(|program| program.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn map_names(maps: &[MapDescription]) -> Vec<&str> {
    let mut names = maps.iter().map(|map| map.name.as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> PortError {
    adapter("Aya runtime lock is poisoned")
}

fn adapter(message: impl Into<String>) -> PortError {
    PortError::Adapter(message.into())
}

#[cfg(test)]
mod pin_parent_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn pin_parent_lease_creates_and_removes_only_owned_empty_directories() {
        let (temporary, bpffs, run_root) = test_paths();
        let lease = prepare_pin_parents(&run_root).expect("empty parents should be prepared");
        assert!(bpffs.join("l2-loop/test").is_dir());

        lease
            .cleanup_exact()
            .expect("owned empty parents should be removed");
        assert!(!bpffs.join("l2-loop").exists());
        fs::remove_dir(&bpffs).unwrap();
        fs::remove_dir(temporary).unwrap();
    }

    #[test]
    fn pin_parent_lease_refuses_a_preexisting_agent_root() {
        let (temporary, bpffs, run_root) = test_paths();
        fs::create_dir(bpffs.join("l2-loop")).unwrap();

        assert!(prepare_pin_parents(&run_root).is_err());
        assert!(bpffs.join("l2-loop").is_dir());
        fs::remove_dir(bpffs.join("l2-loop")).unwrap();
        fs::remove_dir(&bpffs).unwrap();
        fs::remove_dir(temporary).unwrap();
    }

    #[test]
    fn pin_parent_lease_retains_a_replaced_directory() {
        let (temporary, bpffs, run_root) = test_paths();
        let lease = prepare_pin_parents(&run_root).expect("empty parents should be prepared");
        let agent_root = bpffs.join("l2-loop");
        let moved_root = bpffs.join("moved-owned-root");
        fs::rename(&agent_root, &moved_root).unwrap();
        fs::create_dir(&agent_root).unwrap();

        assert!(lease.cleanup_exact().is_err());
        assert!(agent_root.is_dir());
        fs::remove_dir(agent_root).unwrap();
        fs::remove_dir(moved_root.join("test")).unwrap();
        fs::remove_dir(moved_root).unwrap();
        fs::remove_dir(&bpffs).unwrap();
        fs::remove_dir(temporary).unwrap();
    }

    fn test_paths() -> (PathBuf, PathBuf, PathBuf) {
        let suffix = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let temporary = std::env::temp_dir().join(format!(
            "l2-loop-pin-parent-{}-{suffix}",
            std::process::id()
        ));
        let bpffs = temporary.join("bpffs");
        fs::create_dir_all(&bpffs).unwrap();
        let run_root = bpffs
            .join("l2-loop/test")
            .join("0123456789abcdef0123456789abcdef");
        (temporary, bpffs, run_root)
    }
}
