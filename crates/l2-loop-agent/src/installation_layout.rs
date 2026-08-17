use std::collections::BTreeSet;

use l2_loop_core::InstallAuthorizationV1;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{BundleSnapshotV1, InstallPlanningError, InstallRoleV1, InstallSourceSnapshotV1};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use crate::{
    HostIdentityReader, InstallIoError, InstallSourceReader,
    linux::deployment_fs::LinuxDeploymentFilesystem,
};

pub const MAX_INSTALL_DOCUMENT_BYTES: u64 = 1024 * 1024;
pub const MAX_HOST_IDENTITY_BYTES: usize = 4 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EBPF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const HASH_BUFFER_BYTES: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const HOST_IDENTITY_PATH: &str = "/etc/machine-id";

const INSTALL_BUNDLE_FILES: [(&str, u32); 9] = [
    ("SHA256SUMS", 0o644),
    ("deployment-v1.example.json", 0o644),
    ("l2-loop-deploycheck", 0o755),
    ("l2-loop-ebpf.o", 0o644),
    ("l2-loop-hostcheck", 0o755),
    ("l2-loop.service", 0o644),
    ("l2-loopctl", 0o755),
    ("l2-loopd", 0o755),
    ("manifest.json", 0o644),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallLayoutEntryKindV1 {
    Directory,
    Regular,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPayloadSourceV1 {
    None,
    Bundle(&'static str),
    DeploymentAuthorization,
    PerformanceEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallLayoutEntryV1 {
    pub role: InstallRoleV1,
    pub destination: &'static str,
    pub kind: InstallLayoutEntryKindV1,
    pub mode: u32,
    pub source: InstallPayloadSourceV1,
}

const fn directory(
    role: InstallRoleV1,
    destination: &'static str,
    mode: u32,
) -> InstallLayoutEntryV1 {
    InstallLayoutEntryV1 {
        role,
        destination,
        kind: InstallLayoutEntryKindV1::Directory,
        mode,
        source: InstallPayloadSourceV1::None,
    }
}

const fn bundle_file(
    role: InstallRoleV1,
    destination: &'static str,
    source: &'static str,
    mode: u32,
) -> InstallLayoutEntryV1 {
    InstallLayoutEntryV1 {
        role,
        destination,
        kind: InstallLayoutEntryKindV1::Regular,
        mode,
        source: InstallPayloadSourceV1::Bundle(source),
    }
}

const fn supplied_file(
    role: InstallRoleV1,
    destination: &'static str,
    source: InstallPayloadSourceV1,
) -> InstallLayoutEntryV1 {
    InstallLayoutEntryV1 {
        role,
        destination,
        kind: InstallLayoutEntryKindV1::Regular,
        mode: 0o600,
        source,
    }
}

const INSTALL_LAYOUT: [InstallLayoutEntryV1; 31] = [
    directory(InstallRoleV1::UsrRoot, "/usr", 0o755),
    directory(InstallRoleV1::UsrBinRoot, "/usr/bin", 0o755),
    directory(InstallRoleV1::UsrLibRoot, "/usr/lib", 0o755),
    directory(InstallRoleV1::UsrLibexecRoot, "/usr/libexec", 0o755),
    directory(
        InstallRoleV1::ProductLibexecRoot,
        "/usr/libexec/l2-loop",
        0o755,
    ),
    directory(InstallRoleV1::UsrLibSystemdRoot, "/usr/lib/systemd", 0o755),
    directory(
        InstallRoleV1::SystemdUnitRoot,
        "/usr/lib/systemd/system",
        0o755,
    ),
    directory(InstallRoleV1::UsrShareRoot, "/usr/share", 0o755),
    directory(InstallRoleV1::UsrShareDocRoot, "/usr/share/doc", 0o755),
    directory(
        InstallRoleV1::ProductDocRoot,
        "/usr/share/doc/l2-loop",
        0o755,
    ),
    directory(InstallRoleV1::EtcRoot, "/etc", 0o755),
    directory(InstallRoleV1::ConfigRoot, "/etc/l2-loop", 0o700),
    directory(InstallRoleV1::VarRoot, "/var", 0o755),
    directory(InstallRoleV1::VarLibRoot, "/var/lib", 0o755),
    directory(InstallRoleV1::StateRoot, "/var/lib/l2-loop", 0o700),
    directory(InstallRoleV1::GatesRoot, "/var/lib/l2-loop/gates", 0o700),
    directory(
        InstallRoleV1::EvidenceParent,
        "/var/lib/l2-loop/evidence",
        0o700,
    ),
    directory(
        InstallRoleV1::EvidenceRoot,
        "/var/lib/l2-loop/evidence/v1",
        0o700,
    ),
    directory(
        InstallRoleV1::InstallRoot,
        "/var/lib/l2-loop/install",
        0o700,
    ),
    directory(
        InstallRoleV1::TransactionsRoot,
        "/var/lib/l2-loop/install/transactions",
        0o700,
    ),
    bundle_file(
        InstallRoleV1::Cli,
        "/usr/bin/l2-loopctl",
        "l2-loopctl",
        0o755,
    ),
    bundle_file(
        InstallRoleV1::Daemon,
        "/usr/libexec/l2-loop/l2-loopd",
        "l2-loopd",
        0o755,
    ),
    bundle_file(
        InstallRoleV1::DeploymentChecker,
        "/usr/libexec/l2-loop/l2-loop-deploycheck",
        "l2-loop-deploycheck",
        0o755,
    ),
    bundle_file(
        InstallRoleV1::HostChecker,
        "/usr/libexec/l2-loop/l2-loop-hostcheck",
        "l2-loop-hostcheck",
        0o755,
    ),
    bundle_file(
        InstallRoleV1::EbpfObject,
        "/usr/libexec/l2-loop/l2-loop-ebpf.o",
        "l2-loop-ebpf.o",
        0o644,
    ),
    bundle_file(
        InstallRoleV1::BundleManifest,
        "/usr/libexec/l2-loop/manifest.json",
        "manifest.json",
        0o644,
    ),
    bundle_file(
        InstallRoleV1::BundleChecksums,
        "/usr/libexec/l2-loop/SHA256SUMS",
        "SHA256SUMS",
        0o644,
    ),
    bundle_file(
        InstallRoleV1::ServiceUnit,
        "/usr/lib/systemd/system/l2-loop.service",
        "l2-loop.service",
        0o644,
    ),
    bundle_file(
        InstallRoleV1::AuthorizationExample,
        "/usr/share/doc/l2-loop/deployment-v1.example.json",
        "deployment-v1.example.json",
        0o644,
    ),
    supplied_file(
        InstallRoleV1::DeploymentAuthorization,
        "/etc/l2-loop/deployment-v1.json",
        InstallPayloadSourceV1::DeploymentAuthorization,
    ),
    supplied_file(
        InstallRoleV1::PerformanceEvidence,
        "/var/lib/l2-loop/gates/performance-v1.json",
        InstallPayloadSourceV1::PerformanceEvidence,
    ),
];

pub struct InstallLayoutV1;

impl InstallLayoutV1 {
    pub const fn entries() -> &'static [InstallLayoutEntryV1] {
        &INSTALL_LAYOUT
    }

    pub fn entry(role: InstallRoleV1) -> Option<&'static InstallLayoutEntryV1> {
        INSTALL_LAYOUT.iter().find(|entry| entry.role == role)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallInputDocumentV1 {
    bytes: Vec<u8>,
    regular: bool,
    mode: u32,
    uid: u32,
    gid: u32,
    hard_links: u64,
}

impl InstallInputDocumentV1 {
    pub fn new(
        bytes: Vec<u8>,
        regular: bool,
        mode: u32,
        uid: u32,
        gid: u32,
        hard_links: u64,
    ) -> Self {
        Self {
            bytes,
            regular,
            mode,
            uid,
            gid,
            hard_links,
        }
    }

    fn validate_private(&self) -> Result<(), InstallValidationError> {
        if !self.regular
            || self.mode != 0o600
            || self.uid != 0
            || self.gid != 0
            || self.hard_links != 1
            || self.bytes.is_empty()
            || u64::try_from(self.bytes.len()).map_err(|_| InstallValidationError::InvalidInput)?
                > MAX_INSTALL_DOCUMENT_BYTES
        {
            return Err(InstallValidationError::InvalidInput);
        }
        Ok(())
    }

    fn digest(&self) -> String {
        format!("{:x}", Sha256::digest(&self.bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInstallInputsV1 {
    pub source: InstallSourceSnapshotV1,
    pub host_identity_sha256: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallValidationError {
    #[error("installation validation input is invalid")]
    InvalidInput,
}

pub fn validate_install_inputs(
    bundle: &BundleSnapshotV1,
    authorization: &InstallInputDocumentV1,
    deployment_authorization: &InstallInputDocumentV1,
    performance_evidence: &InstallInputDocumentV1,
    raw_host_identity: &mut [u8],
) -> Result<ValidatedInstallInputsV1, InstallValidationError> {
    let host_identity_sha256 = hash_and_zero_host_identity(raw_host_identity)?;
    let source = validate_install_source_inputs(
        bundle,
        authorization,
        deployment_authorization,
        performance_evidence,
    )?;
    source
        .authorization
        .validate_for(
            source.authorization.issued_at_unix_ms,
            source.authorization.operation,
            &source.artifact,
            &source.bundle_manifest_sha256,
            &host_identity_sha256,
            &source.deployment_authorization_sha256,
            &source.performance_evidence_sha256,
        )
        .map_err(|_| InstallValidationError::InvalidInput)?;
    Ok(ValidatedInstallInputsV1 {
        source,
        host_identity_sha256,
    })
}

pub fn validate_install_source_inputs(
    bundle: &BundleSnapshotV1,
    authorization: &InstallInputDocumentV1,
    deployment_authorization: &InstallInputDocumentV1,
    performance_evidence: &InstallInputDocumentV1,
) -> Result<InstallSourceSnapshotV1, InstallValidationError> {
    validate_bundle_snapshot(bundle)?;
    authorization.validate_private()?;
    deployment_authorization.validate_private()?;
    performance_evidence.validate_private()?;

    let parsed: InstallAuthorizationV1 = serde_json::from_slice(&authorization.bytes)
        .map_err(|_| InstallValidationError::InvalidInput)?;
    parsed
        .validate_at(parsed.issued_at_unix_ms)
        .map_err(|_| InstallValidationError::InvalidInput)?;
    let manifest_digest = bundle
        .files
        .get("manifest.json")
        .ok_or(InstallValidationError::InvalidInput)?
        .sha256
        .clone();
    let deployment_digest = deployment_authorization.digest();
    let performance_digest = performance_evidence.digest();
    if parsed.artifact_commit_sha != bundle.artifact.commit_sha
        || parsed.bundle_manifest_sha256 != manifest_digest
        || parsed.deployment_authorization_sha256 != deployment_digest
        || parsed.performance_evidence_sha256 != performance_digest
    {
        return Err(InstallValidationError::InvalidInput);
    }
    InstallSourceSnapshotV1::new(
        parsed,
        bundle.artifact.clone(),
        manifest_digest,
        deployment_digest,
        performance_digest,
    )
    .map_err(planning_error)
}

fn validate_bundle_snapshot(bundle: &BundleSnapshotV1) -> Result<(), InstallValidationError> {
    bundle
        .artifact
        .validate()
        .map_err(|_| InstallValidationError::InvalidInput)?;
    if bundle.files.len() != INSTALL_BUNDLE_FILES.len()
        || bundle
            .files
            .keys()
            .map(String::as_str)
            .ne(INSTALL_BUNDLE_FILES.map(|(name, _)| name))
    {
        return Err(InstallValidationError::InvalidInput);
    }

    let mut identities = BTreeSet::new();
    for (name, expected_mode) in INSTALL_BUNDLE_FILES {
        let file = bundle
            .files
            .get(name)
            .ok_or(InstallValidationError::InvalidInput)?;
        if file.mode != expected_mode
            || file.hard_links != 1
            || file.size == 0
            || file.size > maximum_bundle_size(name)
            || !is_lower_hex(&file.sha256, 64)
            || !identities.insert((file.device, file.inode))
        {
            return Err(InstallValidationError::InvalidInput);
        }
    }
    Ok(())
}

fn maximum_bundle_size(name: &str) -> u64 {
    match name {
        "manifest.json" => MAX_MANIFEST_BYTES,
        "SHA256SUMS" => MAX_CHECKSUM_BYTES,
        "l2-loop-ebpf.o" => MAX_EBPF_BYTES,
        "deployment-v1.example.json" | "l2-loop.service" => MAX_INSTALL_DOCUMENT_BYTES,
        _ => MAX_BUNDLE_FILE_BYTES,
    }
}

fn hash_and_zero_host_identity(
    raw_host_identity: &mut [u8],
) -> Result<String, InstallValidationError> {
    let valid = !raw_host_identity.is_empty()
        && raw_host_identity.len() <= MAX_HOST_IDENTITY_BYTES
        && raw_host_identity
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
    let digest = valid.then(|| format!("{:x}", Sha256::digest(&*raw_host_identity)));
    raw_host_identity.fill(0);
    digest.ok_or(InstallValidationError::InvalidInput)
}

fn planning_error(_: InstallPlanningError) -> InstallValidationError {
    InstallValidationError::InvalidInput
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSourcePathsV1 {
    pub bundle: PathBuf,
    pub authorization: PathBuf,
    pub deployment_authorization: PathBuf,
    pub performance_evidence: PathBuf,
}

#[cfg(target_os = "linux")]
pub struct LinuxInstallSourceReaderV1 {
    paths: InstallSourcePathsV1,
    bundle_reader: LinuxDeploymentFilesystem,
}

#[cfg(target_os = "linux")]
impl LinuxInstallSourceReaderV1 {
    pub fn new(
        paths: InstallSourcePathsV1,
        expected_artifact: l2_loop_core::DeploymentArtifactIdentityV1,
    ) -> Result<Self, InstallIoError> {
        let bundle_reader = LinuxDeploymentFilesystem::new(expected_artifact)
            .map_err(|_| InstallIoError::Unavailable)?;
        Ok(Self {
            paths,
            bundle_reader,
        })
    }
}

#[cfg(target_os = "linux")]
pub fn read_install_authorization_v1(
    path: &Path,
) -> Result<InstallAuthorizationV1, InstallIoError> {
    let document = read_private_document(path)?;
    serde_json::from_slice(&document.bytes).map_err(|_| InstallIoError::Unavailable)
}

#[cfg(target_os = "linux")]
impl InstallSourceReader for LinuxInstallSourceReaderV1 {
    fn load_source(&mut self) -> Result<InstallSourceSnapshotV1, InstallIoError> {
        let bundle = self
            .bundle_reader
            .inspect_bundle(&self.paths.bundle)
            .map_err(|_| InstallIoError::Unavailable)?;
        let authorization = read_private_document(&self.paths.authorization)?;
        let deployment = read_private_document(&self.paths.deployment_authorization)?;
        let performance = read_private_document(&self.paths.performance_evidence)?;
        validate_install_source_inputs(&bundle, &authorization, &deployment, &performance)
            .map_err(|_| InstallIoError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct LinuxHostIdentityReaderV1;

#[cfg(target_os = "linux")]
impl HostIdentityReader for LinuxHostIdentityReaderV1 {
    fn host_identity_sha256(&mut self) -> Result<String, InstallIoError> {
        let mut bytes = read_host_identity(Path::new(HOST_IDENTITY_PATH))?;
        hash_and_zero_host_identity(&mut bytes).map_err(|_| InstallIoError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn read_private_document(path: &Path) -> Result<InstallInputDocumentV1, InstallIoError> {
    let (bytes, metadata) = read_bounded_no_follow(path, MAX_INSTALL_DOCUMENT_BYTES)?;
    Ok(InstallInputDocumentV1::new(
        bytes,
        metadata.file_type().is_file(),
        metadata.permissions().mode() & 0o7777,
        metadata.uid(),
        metadata.gid(),
        metadata.nlink(),
    ))
}

#[cfg(target_os = "linux")]
fn read_host_identity(path: &Path) -> Result<Vec<u8>, InstallIoError> {
    let (bytes, metadata) = read_bounded_no_follow(
        path,
        u64::try_from(MAX_HOST_IDENTITY_BYTES).map_err(|_| InstallIoError::Unavailable)?,
    )?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
    {
        return Err(InstallIoError::Unavailable);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_bounded_no_follow(
    path: &Path,
    maximum: u64,
) -> Result<(Vec<u8>, Metadata), InstallIoError> {
    let before = fs::symlink_metadata(path).map_err(unavailable)?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err(InstallIoError::Unavailable);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(unavailable)?;
    let opened = file.metadata().map_err(unavailable)?;
    if !same_file_identity(&before, &opened) || !opened.file_type().is_file() {
        return Err(InstallIoError::Unavailable);
    }

    let mut reader = (&file).take(maximum.saturating_add(1));
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let count = reader.read(&mut buffer).map_err(unavailable)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if u64::try_from(bytes.len()).map_err(|_| InstallIoError::Unavailable)? > maximum {
            return Err(InstallIoError::Unavailable);
        }
    }
    let after = file.metadata().map_err(unavailable)?;
    if !same_file_identity(&before, &after)
        || after.len() != u64::try_from(bytes.len()).map_err(|_| InstallIoError::Unavailable)?
    {
        return Err(InstallIoError::Unavailable);
    }
    Ok((bytes, after))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn unavailable(_: std::io::Error) -> InstallIoError {
    InstallIoError::Unavailable
}
