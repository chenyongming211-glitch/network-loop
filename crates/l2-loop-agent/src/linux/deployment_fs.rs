use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use l2_loop_common::ABI_VERSION;
use l2_loop_core::{
    DeploymentArtifactIdentityV1, DeploymentAuthorizationV1, InstallJournalStateV1,
    InstallRoleV1, PerformanceEvidenceV1,
};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{
    BundleFileIdentityV1, BundleSnapshotV1, DeploymentFilesystem, DeploymentIoError,
    DeploymentPrerequisitesV1, InstalledOwnershipSnapshotV1, LayoutSnapshotV1,
    ServiceUnitSnapshotV1,
};

use super::{
    deployment_unit::{MAX_SERVICE_UNIT_BYTES, validate_service_unit},
    installation_fs::LinuxInstallationFilesystem,
};
pub use crate::{DeploymentEntryKindV1, DeploymentEntrySnapshotV1};

const ACCEPTANCE_ROOT_PREFIX: &str = "/run/l2-loop/accept/";
const STAGING_ROOT_SUFFIX: &str = "/staging-root";
const INSTALLED_ROOT: &str = "/";
const USERSPACE_TARGET: &str = "x86_64-unknown-linux-musl";
const EBPF_TARGET: &str = "bpfel-unknown-none";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EBPF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GATE_JSON_BYTES: u64 = 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 16 * 1024;
const SERVICE_OVERRIDE_PATHS: [&str; 7] = [
    "etc/systemd/system/l2-loop.service",
    "run/systemd/system/l2-loop.service",
    "usr/local/lib/systemd/system/l2-loop.service",
    "etc/systemd/system/l2-loop.service.d",
    "run/systemd/system/l2-loop.service.d",
    "usr/lib/systemd/system/l2-loop.service.d",
    "usr/local/lib/systemd/system/l2-loop.service.d",
];

pub const EXPECTED_BUNDLE_FILES: [&str; 10] = [
    "SHA256SUMS",
    "deployment-v1.example.json",
    "l2-loop-deploycheck",
    "l2-loop-ebpf.o",
    "l2-loop-hostcheck",
    "l2-loop-install",
    "l2-loop.service",
    "l2-loopctl",
    "l2-loopd",
    "manifest.json",
];

const CHECKSUM_PAYLOADS: [&str; 9] = [
    "deployment-v1.example.json",
    "l2-loop-deploycheck",
    "l2-loop-ebpf.o",
    "l2-loop-hostcheck",
    "l2-loop-install",
    "l2-loop.service",
    "l2-loopctl",
    "l2-loopd",
    "manifest.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedLayoutEntry {
    relative_path: &'static str,
    kind: DeploymentEntryKindV1,
    mode: u32,
}

pub const EXPECTED_LAYOUT_ENTRIES: usize = 33;

const LAYOUT_ENTRIES: [ExpectedLayoutEntry; EXPECTED_LAYOUT_ENTRIES] = [
    expected_dir(".", 0o700),
    expected_dir("usr", 0o755),
    expected_dir("usr/bin", 0o755),
    expected_dir("usr/lib", 0o755),
    expected_dir("usr/libexec", 0o755),
    expected_dir("usr/libexec/l2-loop", 0o755),
    expected_dir("usr/lib/systemd", 0o755),
    expected_dir("usr/lib/systemd/system", 0o755),
    expected_dir("usr/share", 0o755),
    expected_dir("usr/share/doc", 0o755),
    expected_dir("usr/share/doc/l2-loop", 0o755),
    expected_dir("etc", 0o755),
    expected_dir("etc/l2-loop", 0o700),
    expected_dir("var", 0o755),
    expected_dir("var/lib", 0o755),
    expected_dir("var/lib/l2-loop", 0o700),
    expected_dir("var/lib/l2-loop/gates", 0o700),
    expected_dir("var/lib/l2-loop/evidence", 0o700),
    expected_dir("var/lib/l2-loop/evidence/v1", 0o700),
    expected_dir("run", 0o755),
    expected_dir("run/l2-loop", 0o700),
    expected_file("usr/bin/l2-loopctl", 0o755),
    expected_file("usr/libexec/l2-loop/l2-loopd", 0o755),
    expected_file("usr/libexec/l2-loop/l2-loop-deploycheck", 0o755),
    expected_file("usr/libexec/l2-loop/l2-loop-install", 0o755),
    expected_file("usr/libexec/l2-loop/l2-loop-hostcheck", 0o755),
    expected_file("usr/libexec/l2-loop/l2-loop-ebpf.o", 0o644),
    expected_file("usr/libexec/l2-loop/manifest.json", 0o644),
    expected_file("usr/libexec/l2-loop/SHA256SUMS", 0o644),
    expected_file("usr/lib/systemd/system/l2-loop.service", 0o644),
    expected_file("usr/share/doc/l2-loop/deployment-v1.example.json", 0o644),
    expected_file("etc/l2-loop/deployment-v1.json", 0o600),
    expected_file("var/lib/l2-loop/gates/performance-v1.json", 0o600),
];

const fn expected_dir(relative_path: &'static str, mode: u32) -> ExpectedLayoutEntry {
    ExpectedLayoutEntry {
        relative_path,
        kind: DeploymentEntryKindV1::Directory,
        mode,
    }
}

const fn expected_file(relative_path: &'static str, mode: u32) -> ExpectedLayoutEntry {
    ExpectedLayoutEntry {
        relative_path,
        kind: DeploymentEntryKindV1::Regular,
        mode,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedLayoutInputV1 {
    pub logical_root: PathBuf,
    pub artifact: DeploymentArtifactIdentityV1,
    pub entries: Vec<DeploymentEntrySnapshotV1>,
    pub runtime_entries: Vec<DeploymentEntrySnapshotV1>,
}

#[derive(Debug, Clone)]
pub struct LinuxDeploymentFilesystem {
    expected_artifact: DeploymentArtifactIdentityV1,
}

impl LinuxDeploymentFilesystem {
    pub fn new(expected_artifact: DeploymentArtifactIdentityV1) -> Result<Self, DeploymentIoError> {
        expected_artifact
            .validate()
            .map_err(|_| DeploymentIoError::Unavailable)?;
        Ok(Self { expected_artifact })
    }

    pub fn validate_staging_root(&self, root: &Path) -> Result<(), DeploymentIoError> {
        validate_staging_root_path(root)
    }

    pub fn inspect_bundle(&self, bundle: &Path) -> Result<BundleSnapshotV1, DeploymentIoError> {
        inspect_bundle_path(bundle, &self.expected_artifact)
    }
}

impl DeploymentFilesystem for LinuxDeploymentFilesystem {
    fn validate_staging_root(&mut self, root: &Path) -> Result<(), DeploymentIoError> {
        validate_staging_root_path(root)
    }

    fn inspect_bundle(&mut self, bundle: &Path) -> Result<BundleSnapshotV1, DeploymentIoError> {
        inspect_bundle_path(bundle, &self.expected_artifact)
    }

    fn inspect_staged_layout(
        &mut self,
        root: &Path,
    ) -> Result<LayoutSnapshotV1, DeploymentIoError> {
        inspect_layout(root, true, &self.expected_artifact)
    }

    fn inspect_staged_service(
        &mut self,
        root: &Path,
    ) -> Result<ServiceUnitSnapshotV1, DeploymentIoError> {
        inspect_service(root)
    }

    fn load_staged_authorization(
        &mut self,
        root: &Path,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError> {
        read_gate_json(&root.join("etc/l2-loop/deployment-v1.json"))
    }

    fn load_staged_performance(
        &mut self,
        root: &Path,
    ) -> Result<PerformanceEvidenceV1, DeploymentIoError> {
        read_gate_json(&root.join("var/lib/l2-loop/gates/performance-v1.json"))
    }

    fn inspect_staged_prerequisites(
        &mut self,
        root: &Path,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError> {
        inspect_layout(root, true, &self.expected_artifact)?;
        Ok(DeploymentPrerequisitesV1::ready())
    }

    fn inspect_installed_ownership(
        &mut self,
    ) -> Result<InstalledOwnershipSnapshotV1, DeploymentIoError> {
        inspect_installed_ownership(&self.expected_artifact)
    }

    fn inspect_installed_layout(&mut self) -> Result<LayoutSnapshotV1, DeploymentIoError> {
        inspect_layout(Path::new(INSTALLED_ROOT), false, &self.expected_artifact)
    }

    fn inspect_installed_service(&mut self) -> Result<ServiceUnitSnapshotV1, DeploymentIoError> {
        inspect_service(Path::new(INSTALLED_ROOT))
    }

    fn load_installed_authorization(
        &mut self,
    ) -> Result<DeploymentAuthorizationV1, DeploymentIoError> {
        read_gate_json(Path::new("/etc/l2-loop/deployment-v1.json"))
    }

    fn load_installed_performance(&mut self) -> Result<PerformanceEvidenceV1, DeploymentIoError> {
        read_gate_json(Path::new("/var/lib/l2-loop/gates/performance-v1.json"))
    }

    fn inspect_installed_prerequisites(
        &mut self,
    ) -> Result<DeploymentPrerequisitesV1, DeploymentIoError> {
        inspect_layout(Path::new(INSTALLED_ROOT), false, &self.expected_artifact)?;
        Ok(DeploymentPrerequisitesV1::ready())
    }
}

fn inspect_installed_ownership(
    expected_artifact: &DeploymentArtifactIdentityV1,
) -> Result<InstalledOwnershipSnapshotV1, DeploymentIoError> {
    let mut filesystem = LinuxInstallationFilesystem::production();
    let mut installed = None;
    for transaction_id in filesystem
        .transaction_ids()
        .map_err(|_| DeploymentIoError::Unavailable)?
    {
        let journal = filesystem
            .load_journal_exact(&transaction_id)
            .map_err(|_| DeploymentIoError::Unavailable)?;
        match journal.state() {
            InstallJournalStateV1::RolledBack => continue,
            InstallJournalStateV1::Installed => {}
            _ => return Err(DeploymentIoError::Unavailable),
        }
        if journal.artifact() != expected_artifact || installed.is_some() {
            return Err(DeploymentIoError::Unavailable);
        }
        for entry in journal.entries() {
            let expected = entry
                .current_identity()
                .ok_or(DeploymentIoError::Unavailable)?;
            let observed = filesystem
                .inspect_optional_exact(entry.role())
                .map_err(|_| DeploymentIoError::Unavailable)?
                .ok_or(DeploymentIoError::Unavailable)?;
            if !expected.matches_persistent_object(&observed) {
                return Err(DeploymentIoError::Unavailable);
            }
        }
        if journal_entry_sha256(&journal, InstallRoleV1::BundleManifest)
            != Some(journal.bundle_manifest_sha256())
            || journal_entry_sha256(&journal, InstallRoleV1::DeploymentAuthorization)
                != Some(journal.deployment_authorization_sha256())
            || journal_entry_sha256(&journal, InstallRoleV1::PerformanceEvidence)
                != Some(journal.performance_evidence_sha256())
        {
            return Err(DeploymentIoError::Unavailable);
        }
        installed = Some(InstalledOwnershipSnapshotV1::new(
            journal.transaction_id(),
            journal.authorization_id(),
            journal.artifact().clone(),
        )?);
    }
    installed.ok_or(DeploymentIoError::Unavailable)
}

fn journal_entry_sha256(
    journal: &l2_loop_core::InstallJournalV1,
    role: InstallRoleV1,
) -> Option<&str> {
    let mut matches = journal.entries().iter().filter(|entry| entry.role() == role);
    let digest = matches.next()?.current_identity()?.sha256()?;
    if matches.next().is_some() {
        return None;
    }
    Some(digest)
}

fn read_gate_json<T>(path: &Path) -> Result<T, DeploymentIoError>
where
    T: DeserializeOwned,
{
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.len() > MAX_GATE_JSON_BYTES
    {
        return Err(DeploymentIoError::Unavailable);
    }
    let bytes = read_bounded_no_follow(path, MAX_GATE_JSON_BYTES)?;
    let after = fs::symlink_metadata(path).map_err(unavailable)?;
    if !same_file_identity(&metadata, &after)
        || after.permissions().mode() & 0o7777 != 0o600
        || after.uid() != 0
        || after.gid() != 0
    {
        return Err(DeploymentIoError::Unavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| DeploymentIoError::Unavailable)
}

fn inspect_service(root: &Path) -> Result<ServiceUnitSnapshotV1, DeploymentIoError> {
    reject_service_overrides(root)?;
    let path = root.join("usr/lib/systemd/system/l2-loop.service");
    let bytes = read_bounded_no_follow(
        &path,
        u64::try_from(MAX_SERVICE_UNIT_BYTES).map_err(|_| DeploymentIoError::Unavailable)?,
    )?;
    let snapshot = validate_service_unit(&bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    reject_service_overrides(root)?;
    Ok(snapshot)
}

fn reject_service_overrides(root: &Path) -> Result<(), DeploymentIoError> {
    for relative in SERVICE_OVERRIDE_PATHS {
        match fs::symlink_metadata(root.join(relative)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(DeploymentIoError::Unavailable),
        }
    }
    Ok(())
}

pub fn validate_staged_layout_snapshot(
    input: &StagedLayoutInputV1,
) -> Result<LayoutSnapshotV1, DeploymentIoError> {
    validate_layout_snapshot(input, true)
}

fn validate_layout_snapshot(
    input: &StagedLayoutInputV1,
    staging: bool,
) -> Result<LayoutSnapshotV1, DeploymentIoError> {
    if staging {
        validate_staging_root_path(&input.logical_root)?;
    }
    input
        .artifact
        .validate()
        .map_err(|_| DeploymentIoError::Unavailable)?;
    if staging && !input.runtime_entries.is_empty() {
        return Err(DeploymentIoError::Unavailable);
    }

    let expected = expected_layout_map(staging);
    let mut observed = BTreeMap::new();
    let mut regular_identities = BTreeSet::new();
    for entry in &input.entries {
        if observed
            .insert(entry.relative_path.clone(), entry.clone())
            .is_some()
        {
            return Err(DeploymentIoError::Unavailable);
        }
        let Some(contract) = expected.get(entry.relative_path.as_str()) else {
            return Err(DeploymentIoError::Unavailable);
        };
        let expected_canonical = if entry.relative_path == "." {
            input.logical_root.clone()
        } else {
            input.logical_root.join(&entry.relative_path)
        };
        if entry.kind != contract.kind
            || entry.mode != contract.mode
            || entry.uid != 0
            || entry.gid != 0
            || entry.canonical_path != expected_canonical
            || !entry.canonical_path.starts_with(&input.logical_root)
            || !relative_path_is_fixed(&entry.relative_path)
            || entry.size > maximum_layout_size(&entry.relative_path, entry.kind)
        {
            return Err(DeploymentIoError::Unavailable);
        }
        if entry.kind == DeploymentEntryKindV1::Regular
            && (entry.hard_links != 1 || !regular_identities.insert((entry.device, entry.inode)))
        {
            return Err(DeploymentIoError::Unavailable);
        }
    }
    if observed.len() != expected.len()
        || !observed
            .keys()
            .map(String::as_str)
            .eq(expected.keys().copied())
    {
        return Err(DeploymentIoError::Unavailable);
    }
    if !staging {
        validate_installed_runtime(&input.logical_root, &input.runtime_entries)?;
    }

    Ok(LayoutSnapshotV1::with_files(
        input.artifact.clone(),
        observed,
        !input.runtime_entries.is_empty(),
    ))
}

fn validate_staging_root_path(root: &Path) -> Result<(), DeploymentIoError> {
    let value = root.to_str().ok_or(DeploymentIoError::Unavailable)?;
    let run_id = value
        .strip_prefix(ACCEPTANCE_ROOT_PREFIX)
        .and_then(|suffix| suffix.strip_suffix(STAGING_ROOT_SUFFIX))
        .ok_or(DeploymentIoError::Unavailable)?;
    if run_id.len() != 32
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || value.contains("//")
        || root.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(DeploymentIoError::Unavailable);
    }
    Ok(())
}

fn inspect_bundle_path(
    bundle: &Path,
    expected_artifact: &DeploymentArtifactIdentityV1,
) -> Result<BundleSnapshotV1, DeploymentIoError> {
    let root_metadata = fs::symlink_metadata(bundle).map_err(unavailable)?;
    if !root_metadata.file_type().is_dir() {
        return Err(DeploymentIoError::Unavailable);
    }
    let canonical_root = fs::canonicalize(bundle).map_err(unavailable)?;
    let mut names = fs::read_dir(bundle)
        .map_err(unavailable)?
        .map(|entry| {
            let entry = entry.map_err(unavailable)?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| DeploymentIoError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names.iter().map(String::as_str).ne(EXPECTED_BUNDLE_FILES) {
        return Err(DeploymentIoError::Unavailable);
    }

    let mut files = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for name in EXPECTED_BUNDLE_FILES {
        let path = bundle.join(name);
        let maximum = maximum_bundle_size(name);
        let identity = inspect_regular_file(&path, &canonical_root, maximum)?;
        if !identities.insert((identity.device, identity.inode)) {
            return Err(DeploymentIoError::Unavailable);
        }
        files.insert(name.to_owned(), identity);
    }

    let manifest_bytes = read_bounded_no_follow(&bundle.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: BundleManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    let artifact = manifest.validate(&files, expected_artifact)?;
    let checksum_bytes = read_bounded_no_follow(&bundle.join("SHA256SUMS"), MAX_CHECKSUM_BYTES)?;
    validate_checksums(&checksum_bytes, &files)?;
    Ok(BundleSnapshotV1::with_files(artifact, files))
}

fn inspect_layout(
    root: &Path,
    staging: bool,
    expected_artifact: &DeploymentArtifactIdentityV1,
) -> Result<LayoutSnapshotV1, DeploymentIoError> {
    if staging {
        validate_staging_root_path(root)?;
        validate_no_follow_staging_ancestors(root)?;
    }
    let canonical_root = fs::canonicalize(root).map_err(unavailable)?;
    let mut entries = Vec::with_capacity(EXPECTED_LAYOUT_ENTRIES);
    for expected in LAYOUT_ENTRIES {
        if !staging && expected.relative_path == "." {
            continue;
        }
        let path = if expected.relative_path == "." {
            root.to_path_buf()
        } else {
            root.join(expected.relative_path)
        };
        entries.push(inspect_layout_entry(
            &path,
            root,
            &canonical_root,
            expected.relative_path,
        )?);
    }
    let runtime_path = root.join("run/l2-loop");
    let runtime_entries = fs::read_dir(&runtime_path)
        .map_err(unavailable)?
        .map(|entry| {
            let entry = entry.map_err(unavailable)?;
            inspect_runtime_entry(&entry.path(), root, &canonical_root)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_path = root.join("usr/libexec/l2-loop/manifest.json");
    let manifest_bytes = read_bounded_no_follow(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: BundleManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    let artifact = manifest.artifact()?;
    if artifact != *expected_artifact {
        return Err(DeploymentIoError::Unavailable);
    }
    validate_layout_inventories(root, staging)?;
    let input = StagedLayoutInputV1 {
        logical_root: root.to_path_buf(),
        artifact,
        entries,
        runtime_entries,
    };
    let snapshot = validate_layout_snapshot(&input, staging)?;
    validate_installed_checksums(root, &manifest, &snapshot.files)?;
    Ok(snapshot)
}

fn validate_no_follow_staging_ancestors(root: &Path) -> Result<(), DeploymentIoError> {
    let mut current = PathBuf::new();
    for component in root.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(unavailable)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(DeploymentIoError::Unavailable);
        }
    }
    let generated_root = root.parent().ok_or(DeploymentIoError::Unavailable)?;
    let generated_metadata = fs::symlink_metadata(generated_root).map_err(unavailable)?;
    if generated_metadata.permissions().mode() & 0o7777 != 0o700
        || generated_metadata.uid() != 0
        || generated_metadata.gid() != 0
    {
        return Err(DeploymentIoError::Unavailable);
    }
    Ok(())
}

fn validate_layout_inventories(root: &Path, staging: bool) -> Result<(), DeploymentIoError> {
    let mut expected_children = BTreeMap::<&str, BTreeSet<&str>>::new();
    for entry in LAYOUT_ENTRIES {
        if entry.relative_path == "." {
            continue;
        }
        let path = Path::new(entry.relative_path);
        let parent = path
            .parent()
            .and_then(Path::to_str)
            .filter(|parent| !parent.is_empty())
            .unwrap_or(".");
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(DeploymentIoError::Unavailable)?;
        expected_children.entry(parent).or_default().insert(name);
    }
    for entry in LAYOUT_ENTRIES {
        if entry.kind != DeploymentEntryKindV1::Directory {
            continue;
        }
        let exact_inventory = staging
            || matches!(
                entry.relative_path,
                "usr/libexec/l2-loop" | "etc/l2-loop" | "var/lib/l2-loop/gates"
            );
        if !exact_inventory || entry.relative_path == "run/l2-loop" {
            continue;
        }
        let directory = if entry.relative_path == "." {
            root.to_path_buf()
        } else {
            root.join(entry.relative_path)
        };
        let mut actual = fs::read_dir(directory)
            .map_err(unavailable)?
            .map(|child| {
                child
                    .map_err(unavailable)?
                    .file_name()
                    .into_string()
                    .map_err(|_| DeploymentIoError::Unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        let expected = expected_children
            .get(entry.relative_path)
            .map(|children| children.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        if actual.iter().map(String::as_str).ne(expected) {
            return Err(DeploymentIoError::Unavailable);
        }
    }
    Ok(())
}

fn validate_installed_runtime(
    root: &Path,
    runtime_entries: &[DeploymentEntrySnapshotV1],
) -> Result<(), DeploymentIoError> {
    if runtime_entries.is_empty() {
        return Ok(());
    }
    if runtime_entries.len() != 1 {
        return Err(DeploymentIoError::Unavailable);
    }
    let socket = &runtime_entries[0];
    if socket.relative_path != "run/l2-loop/agent.sock"
        || socket.canonical_path != root.join("run/l2-loop/agent.sock")
        || socket.kind != DeploymentEntryKindV1::Socket
        || socket.mode != 0o600
        || socket.uid != 0
        || socket.gid != 0
        || socket.hard_links != 1
    {
        return Err(DeploymentIoError::Unavailable);
    }
    Ok(())
}

fn inspect_layout_entry(
    path: &Path,
    root: &Path,
    canonical_root: &Path,
    relative: &str,
) -> Result<DeploymentEntrySnapshotV1, DeploymentIoError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    let canonical_path = fs::canonicalize(path).map_err(unavailable)?;
    let expected_physical = if relative == "." {
        canonical_root.to_path_buf()
    } else {
        canonical_root.join(relative)
    };
    if canonical_path != expected_physical || !canonical_path.starts_with(canonical_root) {
        return Err(DeploymentIoError::Unavailable);
    }
    let logical_canonical = if relative == "." {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    Ok(snapshot_from_metadata(
        relative,
        logical_canonical,
        &metadata,
    ))
}

fn inspect_runtime_entry(
    path: &Path,
    root: &Path,
    canonical_root: &Path,
) -> Result<DeploymentEntrySnapshotV1, DeploymentIoError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    let canonical = fs::canonicalize(path).map_err(unavailable)?;
    if !canonical.starts_with(canonical_root) {
        return Err(DeploymentIoError::Unavailable);
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| DeploymentIoError::Unavailable)?
        .to_str()
        .ok_or(DeploymentIoError::Unavailable)?;
    Ok(snapshot_from_metadata(
        relative,
        path.to_path_buf(),
        &metadata,
    ))
}

fn snapshot_from_metadata(
    relative: &str,
    canonical_path: PathBuf,
    metadata: &Metadata,
) -> DeploymentEntrySnapshotV1 {
    DeploymentEntrySnapshotV1 {
        relative_path: relative.to_owned(),
        canonical_path,
        kind: classify_kind(metadata),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        hard_links: metadata.nlink(),
        size: metadata.len(),
    }
}

fn classify_kind(metadata: &Metadata) -> DeploymentEntryKindV1 {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        DeploymentEntryKindV1::Directory
    } else if file_type.is_file() {
        DeploymentEntryKindV1::Regular
    } else if file_type.is_symlink() {
        DeploymentEntryKindV1::Symlink
    } else if file_type.is_socket() {
        DeploymentEntryKindV1::Socket
    } else if file_type.is_fifo() {
        DeploymentEntryKindV1::Fifo
    } else if file_type.is_block_device() || file_type.is_char_device() {
        DeploymentEntryKindV1::Device
    } else {
        DeploymentEntryKindV1::Other
    }
}

fn inspect_regular_file(
    path: &Path,
    canonical_root: &Path,
    maximum: u64,
) -> Result<BundleFileIdentityV1, DeploymentIoError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    let canonical = fs::canonicalize(path).map_err(unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum
        || canonical.parent() != Some(canonical_root)
    {
        return Err(DeploymentIoError::Unavailable);
    }
    let (digest, verified) = hash_bounded_no_follow(path, maximum)?;
    Ok(BundleFileIdentityV1 {
        sha256: digest,
        size: verified.len(),
        mode: verified.permissions().mode() & 0o7777,
        uid: verified.uid(),
        gid: verified.gid(),
        device: verified.dev(),
        inode: verified.ino(),
        hard_links: verified.nlink(),
    })
}

fn hash_bounded_no_follow(
    path: &Path,
    maximum: u64,
) -> Result<(String, Metadata), DeploymentIoError> {
    let before = fs::symlink_metadata(path).map_err(unavailable)?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err(DeploymentIoError::Unavailable);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(unavailable)?;
    let opened = file.metadata().map_err(unavailable)?;
    if !same_file_identity(&before, &opened) || !opened.file_type().is_file() {
        return Err(DeploymentIoError::Unavailable);
    }

    let mut reader = (&file).take(maximum + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer).map_err(unavailable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| DeploymentIoError::Unavailable)?)
            .ok_or(DeploymentIoError::Unavailable)?;
        if total > maximum {
            return Err(DeploymentIoError::Unavailable);
        }
        digest.update(&buffer[..count]);
    }

    let after = file.metadata().map_err(unavailable)?;
    if !same_file_identity(&before, &after) || after.len() != total {
        return Err(DeploymentIoError::Unavailable);
    }
    let digest = digest.finalize();
    Ok((format!("{digest:x}"), after))
}

fn read_bounded_no_follow(path: &Path, maximum: u64) -> Result<Vec<u8>, DeploymentIoError> {
    let before = fs::symlink_metadata(path).map_err(unavailable)?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err(DeploymentIoError::Unavailable);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(unavailable)?;
    let opened = file.metadata().map_err(unavailable)?;
    if before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || opened.len() > maximum
        || !opened.file_type().is_file()
    {
        return Err(DeploymentIoError::Unavailable);
    }
    let mut reader = (&file).take(maximum + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(unavailable)?;
    if u64::try_from(bytes.len()).map_err(|_| DeploymentIoError::Unavailable)? > maximum {
        return Err(DeploymentIoError::Unavailable);
    }
    let after = file.metadata().map_err(unavailable)?;
    if !same_file_identity(&before, &after)
        || after.len() != u64::try_from(bytes.len()).map_err(|_| DeploymentIoError::Unavailable)?
    {
        return Err(DeploymentIoError::Unavailable);
    }
    Ok(bytes)
}

fn same_file_identity(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn validate_checksums(
    bytes: &[u8],
    files: &BTreeMap<String, BundleFileIdentityV1>,
) -> Result<(), DeploymentIoError> {
    let content = std::str::from_utf8(bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    if !content.ends_with('\n') || content.contains('\r') {
        return Err(DeploymentIoError::Unavailable);
    }
    let lines = content.lines().collect::<Vec<_>>();
    if lines.len() != CHECKSUM_PAYLOADS.len() {
        return Err(DeploymentIoError::Unavailable);
    }
    for (line, expected_name) in lines.iter().zip(CHECKSUM_PAYLOADS) {
        let expected_length = 64 + 2 + expected_name.len();
        if line.len() != expected_length
            || &line[64..66] != "  "
            || &line[66..] != expected_name
            || !line[..64].bytes().all(is_lower_hex)
            || files
                .get(expected_name)
                .map(|identity| identity.sha256.as_str())
                != Some(&line[..64])
        {
            return Err(DeploymentIoError::Unavailable);
        }
    }
    Ok(())
}

fn validate_installed_checksums(
    root: &Path,
    manifest: &BundleManifestV1,
    _entries: &BTreeMap<String, DeploymentEntrySnapshotV1>,
) -> Result<(), DeploymentIoError> {
    let checksum_path = root.join("usr/libexec/l2-loop/SHA256SUMS");
    let bytes = read_bounded_no_follow(&checksum_path, MAX_CHECKSUM_BYTES)?;
    let content = std::str::from_utf8(&bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    if !content.ends_with('\n') || content.lines().count() != CHECKSUM_PAYLOADS.len() {
        return Err(DeploymentIoError::Unavailable);
    }
    let mut service_digest = None;
    let mut example_digest = None;
    for (line, expected_name) in content.lines().zip(CHECKSUM_PAYLOADS) {
        if line.len() != 66 + expected_name.len()
            || &line[64..66] != "  "
            || &line[66..] != expected_name
            || !line[..64].bytes().all(is_lower_hex)
        {
            return Err(DeploymentIoError::Unavailable);
        }
        let installed_relative = installed_payload_path(expected_name, &manifest.files)
            .ok_or(DeploymentIoError::Unavailable)?;
        let installed = root.join(installed_relative);
        let actual = inspect_regular_file(
            &installed,
            installed
                .parent()
                .and_then(|parent| fs::canonicalize(parent).ok())
                .as_deref()
                .ok_or(DeploymentIoError::Unavailable)?,
            maximum_bundle_size(expected_name),
        )?;
        if actual.sha256 != line[..64] {
            return Err(DeploymentIoError::Unavailable);
        }
        if expected_name == manifest.files.service_unit {
            service_digest = Some(actual.sha256.clone());
        }
        if expected_name == manifest.files.authorization_example {
            example_digest = Some(actual.sha256);
        }
    }
    if service_digest.as_deref() != Some(manifest.service_unit_sha256.as_str())
        || example_digest.as_deref() != Some(manifest.authorization_example_sha256.as_str())
    {
        return Err(DeploymentIoError::Unavailable);
    }
    Ok(())
}

fn installed_payload_path(filename: &str, files: &BundleFilesV1) -> Option<&'static str> {
    if filename == files.cli {
        Some("usr/bin/l2-loopctl")
    } else if filename == files.service_unit {
        Some("usr/lib/systemd/system/l2-loop.service")
    } else if filename == files.authorization_example {
        Some("usr/share/doc/l2-loop/deployment-v1.example.json")
    } else if filename == "manifest.json" {
        Some("usr/libexec/l2-loop/manifest.json")
    } else if [
        files.daemon.as_str(),
        files.deployment_checker.as_str(),
        files.installer.as_str(),
        files.host_checker.as_str(),
        files.ebpf_object.as_str(),
    ]
    .contains(&filename)
    {
        match filename {
            "l2-loopd" => Some("usr/libexec/l2-loop/l2-loopd"),
            "l2-loop-deploycheck" => Some("usr/libexec/l2-loop/l2-loop-deploycheck"),
            "l2-loop-install" => Some("usr/libexec/l2-loop/l2-loop-install"),
            "l2-loop-hostcheck" => Some("usr/libexec/l2-loop/l2-loop-hostcheck"),
            "l2-loop-ebpf.o" => Some("usr/libexec/l2-loop/l2-loop-ebpf.o"),
            _ => None,
        }
    } else {
        None
    }
}

fn expected_layout_map(staging: bool) -> BTreeMap<&'static str, ExpectedLayoutEntry> {
    LAYOUT_ENTRIES
        .into_iter()
        .filter(|entry| staging || entry.relative_path != ".")
        .map(|entry| (entry.relative_path, entry))
        .collect()
}

fn relative_path_is_fixed(relative: &str) -> bool {
    relative == "."
        || (!relative.is_empty()
            && Path::new(relative)
                .components()
                .all(|component| matches!(component, Component::Normal(_))))
}

fn maximum_bundle_size(name: &str) -> u64 {
    match name {
        "manifest.json" => MAX_MANIFEST_BYTES,
        "SHA256SUMS" => MAX_CHECKSUM_BYTES,
        "l2-loop-ebpf.o" => MAX_EBPF_BYTES,
        "l2-loop.service" | "deployment-v1.example.json" => MAX_MANIFEST_BYTES,
        _ => MAX_BUNDLE_FILE_BYTES,
    }
}

fn maximum_layout_size(relative: &str, kind: DeploymentEntryKindV1) -> u64 {
    if kind == DeploymentEntryKindV1::Directory {
        u64::MAX
    } else {
        relative
            .rsplit('/')
            .next()
            .map(maximum_bundle_size)
            .unwrap_or(0)
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn unavailable(_: std::io::Error) -> DeploymentIoError {
    DeploymentIoError::Unavailable
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifestV1 {
    schema_version: u16,
    commit_sha: String,
    package_version: String,
    userspace_target: String,
    ebpf_target: String,
    abi_version: u16,
    files: BundleFilesV1,
    service_unit_sha256: String,
    authorization_example_sha256: String,
}

impl BundleManifestV1 {
    fn artifact(&self) -> Result<DeploymentArtifactIdentityV1, DeploymentIoError> {
        if self.schema_version != 1
            || self.userspace_target != USERSPACE_TARGET
            || self.ebpf_target != EBPF_TARGET
            || self.abi_version != ABI_VERSION
            || !self.files.is_exact()
            || !is_digest(&self.service_unit_sha256)
            || !is_digest(&self.authorization_example_sha256)
        {
            return Err(DeploymentIoError::Unavailable);
        }
        DeploymentArtifactIdentityV1::new(&self.commit_sha, &self.package_version)
            .map_err(|_| DeploymentIoError::Unavailable)
    }

    fn validate(
        &self,
        files: &BTreeMap<String, BundleFileIdentityV1>,
        expected_artifact: &DeploymentArtifactIdentityV1,
    ) -> Result<DeploymentArtifactIdentityV1, DeploymentIoError> {
        let artifact = self.artifact()?;
        if artifact != *expected_artifact
            || files
                .get(&self.files.service_unit)
                .map(|identity| identity.sha256.as_str())
                != Some(self.service_unit_sha256.as_str())
            || files
                .get(&self.files.authorization_example)
                .map(|identity| identity.sha256.as_str())
                != Some(self.authorization_example_sha256.as_str())
        {
            return Err(DeploymentIoError::Unavailable);
        }
        Ok(artifact)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFilesV1 {
    daemon: String,
    cli: String,
    deployment_checker: String,
    installer: String,
    host_checker: String,
    ebpf_object: String,
    service_unit: String,
    authorization_example: String,
}

impl BundleFilesV1 {
    fn is_exact(&self) -> bool {
        self.daemon == "l2-loopd"
            && self.cli == "l2-loopctl"
            && self.deployment_checker == "l2-loop-deploycheck"
            && self.installer == "l2-loop-install"
            && self.host_checker == "l2-loop-hostcheck"
            && self.ebpf_object == "l2-loop-ebpf.o"
            && self.service_unit == "l2-loop.service"
            && self.authorization_example == "deployment-v1.example.json"
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lower_hex)
}
