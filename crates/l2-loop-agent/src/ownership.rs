use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use l2_loop_common::ABI_VERSION;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OWNERSHIP_SCHEMA_VERSION: u16 = 1;
pub const TEST_JOURNAL_ROOT: &str = "/run/l2-loop/tests";
pub const TEST_PIN_BASE: &str = "/sys/fs/bpf/l2-loop/test";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(String);

impl RunId {
    pub fn parse(value: &str) -> Result<Self, OwnershipError> {
        if value.len() == 32
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(OwnershipError::InvalidRunId)
        }
    }

    pub fn from_u128(value: u128) -> Self {
        Self(format!("{value:032x}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalPath {
    root: PathBuf,
    path: PathBuf,
}

impl JournalPath {
    pub fn new(run_id: RunId) -> Result<Self, OwnershipError> {
        Self::for_root(Path::new(TEST_JOURNAL_ROOT), run_id)
    }

    pub fn for_root(root: &Path, run_id: RunId) -> Result<Self, OwnershipError> {
        validate_absolute_root(root, OwnershipError::InvalidJournalPath)?;
        Ok(Self {
            root: root.to_path_buf(),
            path: root.join(format!("{}.json", run_id.as_str())),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn temporary_path(&self) -> PathBuf {
        self.path.with_extension("json.tmp")
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPinRoot {
    path: PathBuf,
}

impl TestPinRoot {
    pub fn new(run_id: RunId) -> Result<Self, OwnershipError> {
        Self::for_root(Path::new(TEST_PIN_BASE), run_id)
    }

    pub fn for_root(root: &Path, run_id: RunId) -> Result<Self, OwnershipError> {
        validate_absolute_root(root, OwnershipError::InvalidPinPath)?;
        Ok(Self {
            path: root.join(run_id.as_str()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn validate_lexical(&self, target: &Path) -> Result<(), OwnershipError> {
        if !target.is_absolute() {
            return Err(OwnershipError::InvalidPinPath);
        }
        let suffix = target
            .strip_prefix(&self.path)
            .map_err(|_| OwnershipError::InvalidPinPath)?;
        let mut components = suffix.components();
        let Some(first) = components.next() else {
            return Err(OwnershipError::PinRootTarget);
        };
        if !matches!(first, Component::Normal(_))
            || components.any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(OwnershipError::InvalidPinPath);
        }
        Ok(())
    }

    pub fn validate_existing<F: OwnershipFileSystem>(
        &self,
        filesystem: &F,
        target: &Path,
    ) -> Result<(), OwnershipError> {
        self.validate_lexical(target)?;
        reject_symlink(filesystem, &self.path)?;

        let suffix = target
            .strip_prefix(&self.path)
            .map_err(|_| OwnershipError::InvalidPinPath)?;
        let mut current = self.path.clone();
        for component in suffix.components() {
            let Component::Normal(name) = component else {
                return Err(OwnershipError::InvalidPinPath);
            };
            current.push(name);
            reject_symlink(filesystem, &current)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpAttachMode {
    Native,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedXdp {
    pub ifindex: u32,
    pub mode: XdpAttachMode,
    pub program_id: u32,
    pub program_tag: [u8; 8],
    pub link_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpKernelIdentity {
    pub ifindex: u32,
    pub mode: XdpAttachMode,
    pub program_id: u32,
    pub program_tag: [u8; 8],
    pub link_id: Option<u32>,
}

impl OwnedXdp {
    pub fn matches(&self, current: &XdpKernelIdentity) -> bool {
        XdpKernelIdentity::from(*self) == *current
    }
}

impl From<OwnedXdp> for XdpKernelIdentity {
    fn from(value: OwnedXdp) -> Self {
        Self {
            ifindex: value.ifindex,
            mode: value.mode,
            program_id: value.program_id,
            program_tag: value.program_tag,
            link_id: value.link_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcHook {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedTc {
    pub ifindex: u32,
    pub hook: TcHook,
    pub priority: u16,
    pub handle: u32,
    pub program_id: u32,
    pub created_clsact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcKernelIdentity {
    pub ifindex: u32,
    pub hook: TcHook,
    pub priority: u16,
    pub handle: u32,
    pub program_id: u32,
}

impl OwnedTc {
    pub fn matches(&self, current: &TcKernelIdentity) -> bool {
        TcKernelIdentity::from(*self) == *current
    }
}

impl From<OwnedTc> for TcKernelIdentity {
    fn from(value: OwnedTc) -> Self {
        Self {
            ifindex: value.ifindex,
            hook: value.hook,
            priority: value.priority,
            handle: value.handle,
            program_id: value.program_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipRecord {
    pub schema_version: u16,
    pub abi_version: u16,
    pub generation: u64,
    pub ifindex: u32,
    pub xdp: Option<OwnedXdp>,
    pub tc: Vec<OwnedTc>,
    pub pin_paths: Vec<PathBuf>,
    pub created_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipFileType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipMetadata {
    pub file_type: OwnershipFileType,
    pub mode: u32,
}

pub trait OwnershipFileSystem {
    fn metadata(&self, path: &Path) -> io::Result<OwnershipMetadata>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn write_new_sync(&self, path: &Path, contents: &[u8], mode: u32) -> io::Result<()>;
    fn rename_replace(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StdOwnershipFileSystem;

impl OwnershipFileSystem for StdOwnershipFileSystem {
    fn metadata(&self, path: &Path) -> io::Result<OwnershipMetadata> {
        let metadata = fs::symlink_metadata(path)?;
        let file_type = if metadata.file_type().is_symlink() {
            OwnershipFileType::Symlink
        } else if metadata.is_file() {
            OwnershipFileType::File
        } else if metadata.is_dir() {
            OwnershipFileType::Directory
        } else {
            OwnershipFileType::Other
        };
        Ok(OwnershipMetadata {
            file_type,
            mode: metadata.permissions().mode() & 0o777,
        })
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn write_new_sync(&self, path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
        fs::create_dir_all(parent)?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal parent is not a directory",
            ));
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()
    }

    fn rename_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }
}

pub struct OwnershipStore<'a, F> {
    filesystem: &'a F,
    journal: JournalPath,
    pins: TestPinRoot,
}

impl<'a, F: OwnershipFileSystem> OwnershipStore<'a, F> {
    pub fn new(filesystem: &'a F, journal: JournalPath, pins: TestPinRoot) -> Self {
        Self {
            filesystem,
            journal,
            pins,
        }
    }

    pub fn save(&self, record: &OwnershipRecord) -> Result<(), OwnershipError> {
        self.validate_record(record, record.abi_version, record.ifindex, record.generation)?;
        match self.filesystem.metadata(self.journal.path()) {
            Ok(metadata) if metadata.file_type != OwnershipFileType::File => {
                return Err(OwnershipError::InvalidJournalPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(self.journal.path(), source)),
        }

        let contents = serde_json::to_vec_pretty(record)?;
        let temporary = self.journal.temporary_path();
        self.filesystem
            .write_new_sync(&temporary, &contents, 0o600)
            .map_err(|source| io_error(&temporary, source))?;
        self.filesystem
            .rename_replace(&temporary, self.journal.path())
            .map_err(|source| io_error(self.journal.path(), source))?;
        self.filesystem
            .sync_directory(self.journal.root())
            .map_err(|source| io_error(self.journal.root(), source))?;
        Ok(())
    }

    pub fn load_validated(
        &self,
        expected_abi_version: u16,
        expected_ifindex: u32,
        expected_generation: u64,
    ) -> Result<OwnershipRecord, OwnershipError> {
        let metadata = self
            .filesystem
            .metadata(self.journal.path())
            .map_err(|source| io_error(self.journal.path(), source))?;
        if metadata.file_type == OwnershipFileType::Symlink {
            return Err(OwnershipError::Symlink(self.journal.path().to_path_buf()));
        }
        if metadata.file_type != OwnershipFileType::File || metadata.mode != 0o600 {
            return Err(OwnershipError::InvalidJournalPath);
        }

        let contents = self
            .filesystem
            .read(self.journal.path())
            .map_err(|source| io_error(self.journal.path(), source))?;
        let record: OwnershipRecord = serde_json::from_slice(&contents)?;
        self.validate_record(
            &record,
            expected_abi_version,
            expected_ifindex,
            expected_generation,
        )?;
        Ok(record)
    }

    fn validate_record(
        &self,
        record: &OwnershipRecord,
        expected_abi_version: u16,
        expected_ifindex: u32,
        expected_generation: u64,
    ) -> Result<(), OwnershipError> {
        if record.schema_version != OWNERSHIP_SCHEMA_VERSION {
            return Err(OwnershipError::SchemaMismatch {
                expected: OWNERSHIP_SCHEMA_VERSION,
                actual: record.schema_version,
            });
        }
        if record.abi_version != expected_abi_version || record.abi_version != ABI_VERSION {
            return Err(OwnershipError::AbiMismatch {
                expected: expected_abi_version,
                actual: record.abi_version,
            });
        }
        if record.ifindex == 0
            || record.generation == 0
            || record.ifindex != expected_ifindex
            || record.generation != expected_generation
        {
            return Err(OwnershipError::IdentityMismatch(
                "journal generation or ifindex does not match".to_owned(),
            ));
        }
        if record.xdp.is_some_and(|xdp| xdp.ifindex != record.ifindex)
            || record.tc.iter().any(|tc| tc.ifindex != record.ifindex)
        {
            return Err(OwnershipError::IdentityMismatch(
                "owned hook ifindex does not match journal".to_owned(),
            ));
        }
        for pin in &record.pin_paths {
            self.pins.validate_existing(self.filesystem, pin)?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OwnershipError {
    #[error("run ID must be 32 lowercase hexadecimal characters")]
    InvalidRunId,
    #[error("journal path is outside the isolated journal root or is not a private file")]
    InvalidJournalPath,
    #[error("pin path is outside the active isolated run")]
    InvalidPinPath,
    #[error("the isolated pin root itself is not a cleanup target")]
    PinRootTarget,
    #[error("symlink is forbidden in owned path: {0}")]
    Symlink(PathBuf),
    #[error("ownership schema mismatch: expected {expected}, found {actual}")]
    SchemaMismatch { expected: u16, actual: u16 },
    #[error("ownership ABI mismatch: expected {expected}, found {actual}")]
    AbiMismatch { expected: u16, actual: u16 },
    #[error("ownership identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("ownership JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ownership filesystem error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

fn validate_absolute_root(
    root: &Path,
    error: OwnershipError,
) -> Result<(), OwnershipError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Err(error)
    } else {
        Ok(())
    }
}

fn reject_symlink<F: OwnershipFileSystem>(
    filesystem: &F,
    path: &Path,
) -> Result<(), OwnershipError> {
    let metadata = filesystem
        .metadata(path)
        .map_err(|source| io_error(path, source))?;
    if metadata.file_type == OwnershipFileType::Symlink {
        Err(OwnershipError::Symlink(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn io_error(path: &Path, source: io::Error) -> OwnershipError {
    OwnershipError::Io {
        path: path.to_path_buf(),
        source,
    }
}
