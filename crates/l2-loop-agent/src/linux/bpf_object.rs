use std::{
    fs,
    os::fd::{AsFd, AsRawFd},
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
        validate_pin_root(pins.path())?;
        fs::create_dir(pins.path())
            .map_err(|error| adapter(format!("failed to create isolated pin root: {error}")))?;

        let mut pinned = Vec::new();
        for expected in expected_object_description().maps {
            let path = pins.path().join(&expected.name);
            let map = bpf
                .map(&expected.name)
                .ok_or_else(|| adapter(format!("validated map {} disappeared", expected.name)))?;
            let info = map_info(map)?;
            if let Err(error) = map.pin(&path) {
                rollback_pins(&pinned, pins.path());
                return Err(adapter(format!("failed to pin {}: {error}", expected.name)));
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
                    rollback_pins(&rollback, pins.path());
                    return Err(adapter(format!(
                        "failed to verify pinned map {}: {error}",
                        expected.name
                    )));
                }
            };
            if fresh.id() != info.id() {
                rollback_pins(&pinned, pins.path());
                return Err(adapter(format!(
                    "pinned map {} changed identity during creation",
                    expected.name
                )));
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
        let retained = rollback_pins(&active.pins, &active.pin_root);
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

fn validate_pin_root(path: &Path) -> Result<(), PortError> {
    let parent = path
        .parent()
        .ok_or_else(|| adapter("isolated pin root has no parent"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| adapter(format!("failed to inspect pin parent: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(adapter("isolated pin parent is not a real directory"));
    }
    let canonical = fs::canonicalize(parent)
        .map_err(|error| adapter(format!("failed to resolve pin parent: {error}")))?;
    if canonical != parent {
        return Err(adapter("isolated pin parent contains a symlink"));
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(adapter("isolated pin root already exists"));
    }
    Ok(())
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
