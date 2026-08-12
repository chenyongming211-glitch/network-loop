use std::{
    collections::BTreeMap,
    ffi::CString,
    fmt::Write as _,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use l2_loop_core::{
    EVIDENCE_MAX_EVENT_BYTES, EVIDENCE_MAX_EVENTS, EVIDENCE_MAX_REVISION_BYTES,
    EVIDENCE_MAX_REVISIONS_PER_EVENT, EVIDENCE_MAX_STORE_BYTES, EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_MAX_CLOSED_AGE_MS, EVIDENCE_MIN_FREE_RESERVE_BYTES,
    EVIDENCE_MIN_FREE_RESERVE_PERCENT, EventId, EvidenceCursor, EvidenceDetailV1,
    EvidenceIntegrity, EvidenceListQuery, EvidenceManifestV1, EvidenceSummaryV1,
    IncidentRevisionV1,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFileType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceMetadata {
    pub file_type: EvidenceFileType,
    pub mode: u32,
    pub uid: u32,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceIoStep {
    CreateEvent,
    CreateTemporary,
    WriteEvidence,
    WriteManifest,
    SyncTemporary,
    Publish,
    SyncEvent,
}

pub trait EvidenceIo {
    fn checkpoint(&self, _step: EvidenceIoStep) -> io::Result<()> {
        Ok(())
    }

    fn metadata(&self, path: &Path) -> io::Result<EvidenceMetadata>;
    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn create_directory(&self, path: &Path, mode: u32) -> io::Result<()>;
    fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) -> io::Result<()>;
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_private_directory(&self, path: &Path) -> io::Result<()>;
    fn remove_event_directory(&self, path: &Path) -> io::Result<()> {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "event removal is not supported by this adapter",
        ))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StdEvidenceIo;

impl EvidenceIo for StdEvidenceIo {
    fn metadata(&self, path: &Path) -> io::Result<EvidenceMetadata> {
        let metadata = fs::symlink_metadata(path)?;
        let file_type = if metadata.file_type().is_symlink() {
            EvidenceFileType::Symlink
        } else if metadata.is_file() {
            EvidenceFileType::File
        } else if metadata.is_dir() {
            EvidenceFileType::Directory
        } else {
            EvidenceFileType::Other
        };
        Ok(EvidenceMetadata {
            file_type,
            mode: metadata.permissions().mode() & 0o777,
            uid: metadata.uid(),
            length: metadata.len(),
        })
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut paths = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        paths.sort();
        Ok(paths)
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)?;
        let length = file.metadata()?.len();
        if length > EVIDENCE_MAX_REVISION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "evidence file exceeds its fixed bound",
            ));
        }
        let capacity = usize::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid file length"))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn create_directory(&self, path: &Path, mode: u32) -> io::Result<()> {
        DirBuilder::new().mode(mode).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from = CString::new(from.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid source path"))?;
        let to = CString::new(to.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target path"))?;
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_renameat2,
                nix::libc::AT_FDCWD,
                from.as_ptr(),
                nix::libc::AT_FDCWD,
                to.as_ptr(),
                nix::libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn remove_private_directory(&self, path: &Path) -> io::Result<()> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !name.starts_with(".tmp-") || name.len() > 80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing non-canonical evidence temporary directory",
            ));
        }
        let metadata = self.metadata(path)?;
        if metadata.file_type != EvidenceFileType::Directory || metadata.mode != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing unsafe evidence temporary directory",
            ));
        }
        fs::remove_dir_all(path)
    }

    fn remove_event_directory(&self, path: &Path) -> io::Result<()> {
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
        let event_id = name
            .parse::<EventId>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid event path"))?;
        if event_id.to_string() != name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-canonical event path",
            ));
        }
        let metadata = self.metadata(path)?;
        if metadata.file_type != EvidenceFileType::Directory || metadata.mode != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe event directory",
            ));
        }
        fs::remove_dir_all(path)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStoreError {
    #[error("evidence root is missing or unsafe")]
    UnsafeRoot,
    #[error("incident evidence is invalid")]
    InvalidRevision,
    #[error("incident evidence exceeds its fixed revision bound")]
    RevisionTooLarge,
    #[error("incident revision already exists")]
    RevisionConflict,
    #[error("incident revisions must be contiguous")]
    RevisionSequence,
    #[error("incident evidence was not found")]
    NotFound,
    #[error("incident evidence I/O failed")]
    Io,
    #[error("retention cannot satisfy the fixed evidence reserve")]
    RetentionUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvidenceStoreHealth {
    pub available: bool,
    pub corrupt_object_count: u16,
    pub incomplete_object_count: u16,
    pub unknown_object_count: u16,
    pub event_count: u16,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePage {
    pub items: Vec<EvidenceSummaryV1>,
    pub next_cursor: Option<EvidenceCursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemSpace {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

pub trait FilesystemCapacity {
    fn capacity(&self, path: &Path) -> io::Result<FilesystemSpace>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StdFilesystemCapacity;

impl FilesystemCapacity for StdFilesystemCapacity {
    fn capacity(&self, path: &Path) -> io::Result<FilesystemSpace> {
        let stats = nix::sys::statvfs::statvfs(path).map_err(io::Error::other)?;
        let fragment_size = stats.fragment_size();
        Ok(FilesystemSpace {
            total_bytes: stats.blocks().saturating_mul(fragment_size),
            available_bytes: stats.blocks_available().saturating_mul(fragment_size),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUsage {
    pub event_count: u16,
    pub total_bytes: u64,
    pub filesystem: FilesystemSpace,
    pub required_free_reserve: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub deleted_event_ids: Vec<EventId>,
    pub usage: StoreUsage,
}

pub const fn minimum_free_reserve(total_bytes: u64) -> u64 {
    let percent = total_bytes / 100 * EVIDENCE_MIN_FREE_RESERVE_PERCENT as u64
        + total_bytes % 100 * EVIDENCE_MIN_FREE_RESERVE_PERCENT as u64 / 100;
    if percent > EVIDENCE_MIN_FREE_RESERVE_BYTES {
        percent
    } else {
        EVIDENCE_MIN_FREE_RESERVE_BYTES
    }
}

pub trait EvidenceStore {
    fn put(
        &mut self,
        revision: &IncidentRevisionV1,
    ) -> Result<EvidenceSummaryV1, EvidenceStoreError>;
    fn get(&self, event_id: EventId) -> Result<EvidenceDetailV1, EvidenceStoreError>;
    fn list(&self, query: &EvidenceListQuery) -> Result<EvidencePage, EvidenceStoreError>;
    fn health(&self) -> EvidenceStoreHealth;
    fn recover(&mut self) -> Result<(), EvidenceStoreError>;
}

pub struct LinuxEvidenceStore<I> {
    io: I,
    root: PathBuf,
    package_version: String,
    index: BTreeMap<EventId, EvidenceDetailV1>,
    health: EvidenceStoreHealth,
}

impl<I: EvidenceIo> LinuxEvidenceStore<I> {
    pub fn open(io: I, root: &Path, package_version: &str) -> Result<Self, EvidenceStoreError> {
        if package_version.is_empty()
            || package_version.len() > 64
            || !package_version.is_ascii()
            || !root.is_absolute()
            || root
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(EvidenceStoreError::UnsafeRoot);
        }
        let mut store = Self {
            io,
            root: root.to_path_buf(),
            package_version: package_version.to_owned(),
            index: BTreeMap::new(),
            health: EvidenceStoreHealth::default(),
        };
        store.recover()?;
        Ok(store)
    }

    fn validate_root(&self) -> Result<(), EvidenceStoreError> {
        let metadata = self
            .io
            .metadata(&self.root)
            .map_err(|_| EvidenceStoreError::UnsafeRoot)?;
        if metadata.file_type != EvidenceFileType::Directory
            || metadata.mode != 0o700
            || metadata.uid != nix::unistd::geteuid().as_raw()
        {
            return Err(EvidenceStoreError::UnsafeRoot);
        }
        Ok(())
    }

    fn validate_private_directory(&self, path: &Path) -> Result<(), EvidenceStoreError> {
        let metadata = self.io.metadata(path).map_err(|_| EvidenceStoreError::Io)?;
        if metadata.file_type != EvidenceFileType::Directory
            || metadata.mode != 0o700
            || metadata.uid != nix::unistd::geteuid().as_raw()
        {
            return Err(EvidenceStoreError::Io);
        }
        Ok(())
    }

    fn ensure_event_directory(&self, event_id: EventId) -> Result<PathBuf, EvidenceStoreError> {
        let path = self.root.join(event_id.to_string());
        match self.io.metadata(&path) {
            Ok(_) => self.validate_private_directory(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.io
                    .checkpoint(EvidenceIoStep::CreateEvent)
                    .map_err(|_| EvidenceStoreError::Io)?;
                self.io
                    .create_directory(&path, 0o700)
                    .map_err(|_| EvidenceStoreError::Io)?;
                self.io
                    .sync_directory(&self.root)
                    .map_err(|_| EvidenceStoreError::Io)?;
            }
            Err(_) => return Err(EvidenceStoreError::Io),
        }
        Ok(path)
    }

    fn commit_revision(
        &self,
        event_dir: &Path,
        revision: u64,
        evidence: &[u8],
        manifest: &[u8],
    ) -> Result<(), EvidenceStoreError> {
        let target = event_dir.join(format!("{revision:016x}"));
        if self.io.metadata(&target).is_ok() {
            return Err(EvidenceStoreError::RevisionConflict);
        }
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = event_dir.join(format!(
            ".tmp-{revision:016x}-{}-{sequence:016x}",
            std::process::id()
        ));
        let result = (|| {
            self.io
                .checkpoint(EvidenceIoStep::CreateTemporary)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .create_directory(&temporary, 0o700)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .checkpoint(EvidenceIoStep::WriteEvidence)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .write_file(&temporary.join("evidence.json"), evidence, 0o600)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .checkpoint(EvidenceIoStep::WriteManifest)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .write_file(&temporary.join("manifest.json"), manifest, 0o600)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .checkpoint(EvidenceIoStep::SyncTemporary)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .sync_directory(&temporary)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .checkpoint(EvidenceIoStep::Publish)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .rename_noreplace(&temporary, &target)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        EvidenceStoreError::RevisionConflict
                    } else {
                        EvidenceStoreError::Io
                    }
                })?;
            self.io
                .checkpoint(EvidenceIoStep::SyncEvent)
                .map_err(|_| EvidenceStoreError::Io)?;
            self.io
                .sync_directory(event_dir)
                .map_err(|_| EvidenceStoreError::Io)
        })();
        if result.is_err() && self.io.metadata(&temporary).is_ok() {
            let _ = self.io.remove_private_directory(&temporary);
        }
        result
    }

    fn recover_event(
        &self,
        event_id: EventId,
        event_dir: &Path,
        health: &mut EvidenceStoreHealth,
    ) -> Result<Option<EvidenceDetailV1>, EvidenceStoreError> {
        if self.validate_private_directory(event_dir).is_err() {
            increment(&mut health.corrupt_object_count);
            return Ok(None);
        }
        let mut latest = None;
        let mut event_bytes = 0_u64;
        for path in self
            .io
            .read_directory(event_dir)
            .map_err(|_| EvidenceStoreError::Io)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if name.starts_with(".tmp-") {
                increment(&mut health.incomplete_object_count);
                continue;
            }
            let Some(revision_number) = parse_revision_name(name) else {
                increment(&mut health.unknown_object_count);
                continue;
            };
            match self.read_revision(event_id, revision_number, &path) {
                Ok((revision, manifest)) => {
                    event_bytes = event_bytes.saturating_add(manifest.total_bytes);
                    if latest.as_ref().is_none_or(|current: &IncidentRevisionV1| {
                        revision.revision > current.revision
                    }) {
                        latest = Some(revision);
                    }
                }
                Err(RevisionReadError::Incomplete) => {
                    increment(&mut health.incomplete_object_count)
                }
                Err(RevisionReadError::Corrupt) => increment(&mut health.corrupt_object_count),
            }
        }
        Ok(latest.map(|revision| detail_from_revision(revision, event_bytes)))
    }

    fn read_revision(
        &self,
        event_id: EventId,
        revision_number: u64,
        path: &Path,
    ) -> Result<(IncidentRevisionV1, EvidenceManifestV1), RevisionReadError> {
        if self.validate_private_directory(path).is_err() {
            return Err(RevisionReadError::Corrupt);
        }
        let entries = self
            .io
            .read_directory(path)
            .map_err(|_| RevisionReadError::Corrupt)?;
        let evidence_path = path.join("evidence.json");
        let manifest_path = path.join("manifest.json");
        if !entries.contains(&evidence_path) || !entries.contains(&manifest_path) {
            return Err(RevisionReadError::Incomplete);
        }
        if entries.len() != 2 {
            return Err(RevisionReadError::Corrupt);
        }
        self.validate_private_file(&evidence_path)?;
        self.validate_private_file(&manifest_path)?;
        let manifest_bytes = self
            .io
            .read_file(&manifest_path)
            .map_err(|_| RevisionReadError::Corrupt)?;
        let manifest: EvidenceManifestV1 =
            serde_json::from_slice(&manifest_bytes).map_err(|_| RevisionReadError::Corrupt)?;
        manifest
            .validate()
            .map_err(|_| RevisionReadError::Corrupt)?;
        if manifest.event_id != event_id || manifest.revision != revision_number {
            return Err(RevisionReadError::Corrupt);
        }
        let evidence_bytes = self
            .io
            .read_file(&evidence_path)
            .map_err(|_| RevisionReadError::Corrupt)?;
        if u64::try_from(evidence_bytes.len()).ok() != Some(manifest.evidence_bytes)
            || sha256_hex(&evidence_bytes) != manifest.evidence_sha256
        {
            return Err(RevisionReadError::Corrupt);
        }
        let revision: IncidentRevisionV1 =
            serde_json::from_slice(&evidence_bytes).map_err(|_| RevisionReadError::Corrupt)?;
        revision
            .validate()
            .map_err(|_| RevisionReadError::Corrupt)?;
        if revision.event_id != event_id
            || revision.revision != revision_number
            || revision.current_state != manifest.current_state
            || revision.schema_version != manifest.schema_version
        {
            return Err(RevisionReadError::Corrupt);
        }
        Ok((revision, manifest))
    }

    fn validate_private_file(&self, path: &Path) -> Result<(), RevisionReadError> {
        let metadata = self
            .io
            .metadata(path)
            .map_err(|_| RevisionReadError::Incomplete)?;
        if metadata.file_type != EvidenceFileType::File
            || metadata.mode != 0o600
            || metadata.uid != nix::unistd::geteuid().as_raw()
            || metadata.length == 0
            || metadata.length > EVIDENCE_MAX_REVISION_BYTES
        {
            return Err(RevisionReadError::Corrupt);
        }
        Ok(())
    }

    pub fn enforce_retention<C: FilesystemCapacity>(
        &mut self,
        now_unix_ms: u64,
        incoming_bytes: u64,
        capacity: &C,
    ) -> Result<RetentionOutcome, EvidenceStoreError> {
        self.validate_root()?;
        if incoming_bytes > EVIDENCE_MAX_EVENT_BYTES {
            return Err(EvidenceStoreError::RetentionUnavailable);
        }
        let filesystem = capacity
            .capacity(&self.root)
            .map_err(|_| EvidenceStoreError::RetentionUnavailable)?;
        if filesystem.available_bytes > filesystem.total_bytes {
            return Err(EvidenceStoreError::RetentionUnavailable);
        }
        let reserve = minimum_free_reserve(filesystem.total_bytes);
        let mut candidates: Vec<_> = self
            .index
            .iter()
            .filter_map(|(event_id, detail)| {
                detail
                    .summary
                    .closed_at_unix_ms
                    .map(|closed_at| (closed_at, *event_id, detail.summary.bundle_bytes))
            })
            .collect();
        candidates.sort_by_key(|&(closed_at, event_id, _)| (closed_at, event_id));

        let mut deleted_event_ids = Vec::new();
        let mut reclaimed = 0_u64;
        for (closed_at, event_id, bundle_bytes) in candidates {
            let expired = now_unix_ms
                .checked_sub(closed_at)
                .is_some_and(|age| age > EVIDENCE_MAX_CLOSED_AGE_MS);
            let store_fits = self
                .health
                .total_bytes
                .saturating_sub(reclaimed)
                .checked_add(incoming_bytes)
                .is_some_and(|bytes| bytes <= EVIDENCE_MAX_STORE_BYTES);
            let space_fits = filesystem
                .available_bytes
                .checked_add(reclaimed)
                .and_then(|bytes| bytes.checked_sub(incoming_bytes))
                .is_some_and(|bytes| bytes >= reserve);
            let count_fits = usize::from(self.health.event_count)
                .saturating_sub(deleted_event_ids.len())
                < EVIDENCE_MAX_EVENTS;
            if !expired && store_fits && space_fits && count_fits {
                break;
            }

            let event_dir = self.root.join(event_id.to_string());
            self.validate_private_directory(&event_dir)
                .map_err(|_| EvidenceStoreError::RetentionUnavailable)?;
            if self
                .index
                .get(&event_id)
                .is_none_or(|detail| detail.summary.bundle_bytes != bundle_bytes)
            {
                return Err(EvidenceStoreError::RetentionUnavailable);
            }
            self.io
                .remove_event_directory(&event_dir)
                .map_err(|_| EvidenceStoreError::RetentionUnavailable)?;
            self.io
                .sync_directory(&self.root)
                .map_err(|_| EvidenceStoreError::RetentionUnavailable)?;
            self.index.remove(&event_id);
            reclaimed = reclaimed
                .checked_add(bundle_bytes)
                .ok_or(EvidenceStoreError::RetentionUnavailable)?;
            deleted_event_ids.push(event_id);
        }

        self.health.total_bytes = self.health.total_bytes.saturating_sub(reclaimed);
        self.health.event_count = u16::try_from(self.index.len()).unwrap_or(u16::MAX);
        let available_after = filesystem.available_bytes.saturating_add(reclaimed);
        let store_fits = self
            .health
            .total_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|bytes| bytes <= EVIDENCE_MAX_STORE_BYTES);
        let space_fits = available_after
            .checked_sub(incoming_bytes)
            .is_some_and(|bytes| bytes >= reserve);
        if !store_fits || !space_fits || usize::from(self.health.event_count) >= EVIDENCE_MAX_EVENTS {
            self.health.available = false;
            return Err(EvidenceStoreError::RetentionUnavailable);
        }
        self.health.available = true;
        Ok(RetentionOutcome {
            deleted_event_ids,
            usage: StoreUsage {
                event_count: self.health.event_count,
                total_bytes: self.health.total_bytes,
                filesystem: FilesystemSpace {
                    total_bytes: filesystem.total_bytes,
                    available_bytes: available_after,
                },
                required_free_reserve: reserve,
            },
        })
    }
}

impl<I: EvidenceIo> EvidenceStore for LinuxEvidenceStore<I> {
    fn put(
        &mut self,
        revision: &IncidentRevisionV1,
    ) -> Result<EvidenceSummaryV1, EvidenceStoreError> {
        self.validate_root()?;
        revision
            .validate()
            .map_err(|_| EvidenceStoreError::InvalidRevision)?;
        let expected = self
            .index
            .get(&revision.event_id)
            .map_or(1, |detail| detail.latest.revision.saturating_add(1));
        if revision.revision != expected {
            return if revision.revision < expected {
                Err(EvidenceStoreError::RevisionConflict)
            } else {
                Err(EvidenceStoreError::RevisionSequence)
            };
        }
        if let Some(previous) = self.index.get(&revision.event_id) {
            let latest = &previous.latest;
            if latest.interface != revision.interface
                || latest.ifindex != revision.ifindex
                || latest.interface_generation != revision.interface_generation
                || latest.opened_at_unix_ms != revision.opened_at_unix_ms
            {
                return Err(EvidenceStoreError::InvalidRevision);
            }
        }

        let evidence =
            serde_json::to_vec_pretty(revision).map_err(|_| EvidenceStoreError::InvalidRevision)?;
        if evidence.is_empty()
            || u64::try_from(evidence.len()).unwrap_or(u64::MAX) > EVIDENCE_MAX_REVISION_BYTES
        {
            return Err(EvidenceStoreError::RevisionTooLarge);
        }
        let (manifest, manifest_bytes) =
            build_manifest(revision, &evidence, &self.package_version)?;
        let previous_event_bytes = self
            .index
            .get(&revision.event_id)
            .map_or(0, |detail| detail.summary.bundle_bytes);
        let event_bytes = previous_event_bytes
            .checked_add(manifest.total_bytes)
            .ok_or(EvidenceStoreError::RevisionTooLarge)?;
        if event_bytes > EVIDENCE_MAX_EVENT_BYTES
            || self
                .health
                .total_bytes
                .checked_add(manifest.total_bytes)
                .is_none_or(|total| total > EVIDENCE_MAX_STORE_BYTES)
        {
            return Err(EvidenceStoreError::RevisionTooLarge);
        }
        if !self.index.contains_key(&revision.event_id) && self.index.len() >= EVIDENCE_MAX_EVENTS {
            return Err(EvidenceStoreError::RevisionTooLarge);
        }

        let event_dir = self.ensure_event_directory(revision.event_id)?;
        self.commit_revision(&event_dir, revision.revision, &evidence, &manifest_bytes)?;
        let detail = detail_from_revision(revision.clone(), event_bytes);
        let summary = detail.summary.clone();
        let is_new = !self.index.contains_key(&revision.event_id);
        self.index.insert(revision.event_id, detail);
        self.health.available = true;
        self.health.total_bytes = self.health.total_bytes.saturating_add(manifest.total_bytes);
        if is_new {
            self.health.event_count = self.health.event_count.saturating_add(1);
        }
        Ok(summary)
    }

    fn get(&self, event_id: EventId) -> Result<EvidenceDetailV1, EvidenceStoreError> {
        self.index
            .get(&event_id)
            .cloned()
            .ok_or(EvidenceStoreError::NotFound)
    }

    fn list(&self, query: &EvidenceListQuery) -> Result<EvidencePage, EvidenceStoreError> {
        let mut items: Vec<_> = self
            .index
            .values()
            .map(|detail| detail.summary.clone())
            .filter(|summary| {
                query
                    .interface
                    .as_ref()
                    .is_none_or(|interface| &summary.interface == interface)
            })
            .filter(|summary| {
                query.cursor.is_none_or(|cursor| {
                    summary.last_transition_at_unix_ms < cursor.last_transition_at_unix_ms()
                        || (summary.last_transition_at_unix_ms
                            == cursor.last_transition_at_unix_ms()
                            && summary.event_id > cursor.event_id())
                })
            })
            .collect();
        items.sort_by(|left, right| {
            right
                .last_transition_at_unix_ms
                .cmp(&left.last_transition_at_unix_ms)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let limit = usize::from(query.limit);
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = has_more.then(|| {
            let last = items
                .last()
                .expect("a page with more items cannot be empty");
            EvidenceCursor::new(
                query.interface.as_ref(),
                last.last_transition_at_unix_ms,
                last.event_id,
            )
        });
        Ok(EvidencePage { items, next_cursor })
    }

    fn health(&self) -> EvidenceStoreHealth {
        self.health
    }

    fn recover(&mut self) -> Result<(), EvidenceStoreError> {
        self.validate_root()?;
        let mut index = BTreeMap::new();
        let mut health = EvidenceStoreHealth {
            available: true,
            ..EvidenceStoreHealth::default()
        };
        let mut canonical_events = 0_usize;
        for path in self
            .io
            .read_directory(&self.root)
            .map_err(|_| EvidenceStoreError::UnsafeRoot)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let Ok(event_id) = name.parse::<EventId>() else {
                increment(&mut health.unknown_object_count);
                continue;
            };
            if event_id.to_string() != name || canonical_events >= EVIDENCE_MAX_EVENTS {
                increment(&mut health.unknown_object_count);
                continue;
            }
            canonical_events += 1;
            if let Some(detail) = self.recover_event(event_id, &path, &mut health)? {
                health.total_bytes = health
                    .total_bytes
                    .saturating_add(detail.summary.bundle_bytes);
                index.insert(event_id, detail);
            }
        }
        health.event_count = u16::try_from(index.len()).unwrap_or(u16::MAX);
        self.index = index;
        self.health = health;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevisionReadError {
    Incomplete,
    Corrupt,
}

fn parse_revision_name(name: &str) -> Option<u64> {
    if name.len() != 16
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let revision = u64::from_str_radix(name, 16).ok()?;
    (revision > 0 && revision <= EVIDENCE_MAX_REVISIONS_PER_EVENT).then_some(revision)
}

fn build_manifest(
    revision: &IncidentRevisionV1,
    evidence: &[u8],
    package_version: &str,
) -> Result<(EvidenceManifestV1, Vec<u8>), EvidenceStoreError> {
    let evidence_bytes = u64::try_from(evidence.len()).map_err(|_| EvidenceStoreError::Io)?;
    let mut manifest = EvidenceManifestV1 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        event_id: revision.event_id,
        revision: revision.revision,
        current_state: revision.current_state,
        evidence_file: "evidence.json".to_owned(),
        evidence_bytes,
        evidence_sha256: sha256_hex(evidence),
        total_bytes: evidence_bytes,
        package_version: package_version.to_owned(),
    };
    let bytes = loop {
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| EvidenceStoreError::Io)?;
        let total = evidence_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| EvidenceStoreError::Io)?)
            .ok_or(EvidenceStoreError::RevisionTooLarge)?;
        if manifest.total_bytes == total {
            break bytes;
        }
        manifest.total_bytes = total;
    };
    manifest
        .validate()
        .map_err(|_| EvidenceStoreError::InvalidRevision)?;
    Ok((manifest, bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string is infallible");
    }
    encoded
}

fn detail_from_revision(revision: IncidentRevisionV1, bundle_bytes: u64) -> EvidenceDetailV1 {
    let summary = EvidenceSummaryV1 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        event_id: revision.event_id,
        latest_revision: revision.revision,
        interface: revision.interface.clone(),
        ifindex: revision.ifindex,
        interface_generation: revision.interface_generation,
        current_state: revision.current_state,
        alert_code: revision.alert_code,
        severity: revision.severity,
        opened_at_unix_ms: revision.opened_at_unix_ms,
        last_transition_at_unix_ms: revision.occurred_at_unix_ms,
        closed_at_unix_ms: revision.closed_at_unix_ms,
        bundle_bytes,
        integrity: EvidenceIntegrity::Valid,
    };
    EvidenceDetailV1 {
        summary,
        latest: revision,
    }
}

fn increment(value: &mut u16) {
    *value = value.saturating_add(1);
}
