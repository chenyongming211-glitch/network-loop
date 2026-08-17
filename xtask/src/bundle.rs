use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use l2_loop_common::ABI_VERSION;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const USERSPACE_TARGET: &str = "x86_64-unknown-linux-musl";
pub const EBPF_TARGET: &str = "bpfel-unknown-none";
pub const DAEMON_FILENAME: &str = "l2-loopd";
pub const CLI_FILENAME: &str = "l2-loopctl";
pub const DEPLOYMENT_CHECKER_FILENAME: &str = "l2-loop-deploycheck";
pub const INSTALLER_FILENAME: &str = "l2-loop-install";
pub const HOST_CHECKER_FILENAME: &str = "l2-loop-hostcheck";
pub const EBPF_FILENAME: &str = "l2-loop-ebpf.o";
pub const SERVICE_UNIT_FILENAME: &str = "l2-loop.service";
pub const AUTHORIZATION_EXAMPLE_FILENAME: &str = "deployment-v1.example.json";
pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const CHECKSUMS_FILENAME: &str = "SHA256SUMS";

const MAX_USERSPACE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EBPF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GATE_ASSET_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

const CHECKSUM_FILES: [&str; 9] = [
    AUTHORIZATION_EXAMPLE_FILENAME,
    DEPLOYMENT_CHECKER_FILENAME,
    EBPF_FILENAME,
    HOST_CHECKER_FILENAME,
    INSTALLER_FILENAME,
    SERVICE_UNIT_FILENAME,
    CLI_FILENAME,
    DAEMON_FILENAME,
    MANIFEST_FILENAME,
];

const OUTPUT_FILES: [&str; 10] = [
    CHECKSUMS_FILENAME,
    AUTHORIZATION_EXAMPLE_FILENAME,
    DEPLOYMENT_CHECKER_FILENAME,
    EBPF_FILENAME,
    HOST_CHECKER_FILENAME,
    INSTALLER_FILENAME,
    SERVICE_UNIT_FILENAME,
    CLI_FILENAME,
    DAEMON_FILENAME,
    MANIFEST_FILENAME,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleManifest {
    schema_version: u16,
    commit_sha: String,
    package_version: String,
    userspace_target: &'static str,
    ebpf_target: &'static str,
    abi_version: u16,
    files: BundleFiles,
    service_unit_sha256: String,
    authorization_example_sha256: String,
}

impl BundleManifest {
    pub fn new(
        commit_sha: impl Into<String>,
        package_version: impl Into<String>,
        service_unit_sha256: impl Into<String>,
        authorization_example_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            commit_sha: commit_sha.into(),
            package_version: package_version.into(),
            userspace_target: USERSPACE_TARGET,
            ebpf_target: EBPF_TARGET,
            abi_version: ABI_VERSION,
            files: BundleFiles {
                daemon: DAEMON_FILENAME,
                cli: CLI_FILENAME,
                deployment_checker: DEPLOYMENT_CHECKER_FILENAME,
                installer: INSTALLER_FILENAME,
                host_checker: HOST_CHECKER_FILENAME,
                ebpf_object: EBPF_FILENAME,
                service_unit: SERVICE_UNIT_FILENAME,
                authorization_example: AUTHORIZATION_EXAMPLE_FILENAME,
            },
            service_unit_sha256: service_unit_sha256.into(),
            authorization_example_sha256: authorization_example_sha256.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundleFiles {
    daemon: &'static str,
    cli: &'static str,
    deployment_checker: &'static str,
    installer: &'static str,
    host_checker: &'static str,
    ebpf_object: &'static str,
    service_unit: &'static str,
    authorization_example: &'static str,
}

#[derive(Debug)]
pub struct BundleInputs<'a> {
    pub commit_sha: &'a str,
    pub package_version: &'a str,
    pub daemon: &'a Path,
    pub cli: &'a Path,
    pub deployment_checker: &'a Path,
    pub installer: &'a Path,
    pub host_checker: &'a Path,
    pub ebpf: &'a Path,
    pub service_unit: &'a Path,
    pub authorization_example: &'a Path,
    pub output_dir: &'a Path,
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("commit SHA must be exactly 40 lowercase hexadecimal characters")]
    InvalidCommitSha,
    #[error("package version must not be empty")]
    InvalidPackageVersion,
    #[error("bundle checksums must cover exactly the approved files")]
    UnexpectedChecksumFiles,
    #[error("invalid SHA-256 checksum for {filename}")]
    InvalidChecksum { filename: String },
    #[error("bundle output inventory differs from the approved files")]
    UnexpectedOutputInventory,
    #[error("bundle output directory already exists")]
    OutputExists,
    #[error("bundle input is not a bounded stable regular file: {path}")]
    InvalidInput { path: PathBuf },
    #[error("bundle I/O failed while {operation}: {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize bundle manifest")]
    Serialize(#[from] serde_json::Error),
}

pub fn render_manifest(manifest: &BundleManifest) -> Result<String, BundleError> {
    let mut rendered = serde_json::to_string_pretty(manifest)?;
    rendered.push('\n');
    Ok(rendered)
}

pub fn render_sha256sums(checksums: &BTreeMap<String, String>) -> Result<String, BundleError> {
    if !checksums.keys().map(String::as_str).eq(CHECKSUM_FILES) {
        return Err(BundleError::UnexpectedChecksumFiles);
    }

    let mut rendered = String::new();
    for (filename, checksum) in checksums {
        if checksum.len() != 64 || !checksum.bytes().all(is_lower_hexadecimal) {
            return Err(BundleError::InvalidChecksum {
                filename: filename.clone(),
            });
        }
        rendered.push_str(checksum);
        rendered.push_str("  ");
        rendered.push_str(filename);
        rendered.push('\n');
    }
    Ok(rendered)
}

pub fn create_bundle(inputs: &BundleInputs<'_>) -> Result<(), BundleError> {
    validate_metadata(inputs.commit_sha, inputs.package_version)?;
    if inputs.output_dir.exists() {
        return Err(BundleError::OutputExists);
    }

    let daemon = read_bounded_regular(inputs.daemon, MAX_USERSPACE_BYTES)?;
    let cli = read_bounded_regular(inputs.cli, MAX_USERSPACE_BYTES)?;
    let deployment_checker = read_bounded_regular(inputs.deployment_checker, MAX_USERSPACE_BYTES)?;
    let installer = read_bounded_regular(inputs.installer, MAX_USERSPACE_BYTES)?;
    let host_checker = read_bounded_regular(inputs.host_checker, MAX_USERSPACE_BYTES)?;
    let ebpf = read_bounded_regular(inputs.ebpf, MAX_EBPF_BYTES)?;
    let service_unit = read_bounded_regular(inputs.service_unit, MAX_GATE_ASSET_BYTES)?;
    let authorization_example =
        read_bounded_regular(inputs.authorization_example, MAX_GATE_ASSET_BYTES)?;

    let manifest = BundleManifest::new(
        inputs.commit_sha,
        inputs.package_version,
        sha256_bytes(&service_unit),
        sha256_bytes(&authorization_example),
    );
    let manifest = render_manifest(&manifest)?.into_bytes();
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(BundleError::UnexpectedOutputInventory);
    }

    let payloads = BTreeMap::from([
        (AUTHORIZATION_EXAMPLE_FILENAME, authorization_example),
        (DEPLOYMENT_CHECKER_FILENAME, deployment_checker),
        (EBPF_FILENAME, ebpf),
        (HOST_CHECKER_FILENAME, host_checker),
        (INSTALLER_FILENAME, installer),
        (SERVICE_UNIT_FILENAME, service_unit),
        (CLI_FILENAME, cli),
        (DAEMON_FILENAME, daemon),
        (MANIFEST_FILENAME, manifest),
    ]);
    if payloads.keys().copied().ne(CHECKSUM_FILES) {
        return Err(BundleError::UnexpectedOutputInventory);
    }

    fs::create_dir(inputs.output_dir)
        .map_err(|source| io_error("creating output directory", inputs.output_dir, source))?;
    for (filename, bytes) in &payloads {
        write_payload(
            &inputs.output_dir.join(filename),
            bytes,
            payload_mode(filename),
        )?;
    }

    let checksums = payloads
        .iter()
        .map(|(filename, bytes)| (filename.to_string(), sha256_bytes(bytes)))
        .collect::<BTreeMap<_, _>>();
    let rendered = render_sha256sums(&checksums)?;
    write_payload(
        &inputs.output_dir.join(CHECKSUMS_FILENAME),
        rendered.as_bytes(),
        0o644,
    )?;
    validate_output_inventory(inputs.output_dir)
}

fn validate_metadata(commit_sha: &str, package_version: &str) -> Result<(), BundleError> {
    if commit_sha.len() != 40 || !commit_sha.bytes().all(is_lower_hexadecimal) {
        return Err(BundleError::InvalidCommitSha);
    }
    if package_version.is_empty() {
        return Err(BundleError::InvalidPackageVersion);
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, BundleError> {
    let before = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading input metadata", path, source))?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(BundleError::InvalidInput {
            path: path.to_path_buf(),
        });
    }
    let file = File::open(path).map_err(|source| io_error("opening input", path, source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error("reading opened input metadata", path, source))?;
    if !same_file_identity(&before, &opened) {
        return Err(BundleError::InvalidInput {
            path: path.to_path_buf(),
        });
    }

    let mut bytes = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("reading bounded input", path, source))?;
    let after = file
        .metadata()
        .map_err(|source| io_error("re-reading input metadata", path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum
        || after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || !same_file_identity(&before, &after)
    {
        return Err(BundleError::InvalidInput {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

fn write_payload(path: &Path, bytes: &[u8], mode: u32) -> Result<(), BundleError> {
    fs::write(path, bytes).map_err(|source| io_error("writing bundle payload", path, source))?;
    set_mode(path, mode)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading output metadata", path, source))?;
    if !metadata.file_type().is_file()
        || !single_link(&metadata)
        || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(BundleError::UnexpectedOutputInventory);
    }
    Ok(())
}

fn validate_output_inventory(output: &Path) -> Result<(), BundleError> {
    let mut names = fs::read_dir(output)
        .map_err(|source| io_error("reading output inventory", output, source))?
        .map(|entry| {
            entry
                .map_err(|source| io_error("reading output entry", output, source))?
                .file_name()
                .into_string()
                .map_err(|_| BundleError::UnexpectedOutputInventory)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names.iter().map(String::as_str).ne(OUTPUT_FILES) {
        return Err(BundleError::UnexpectedOutputInventory);
    }
    for name in OUTPUT_FILES {
        let metadata = fs::symlink_metadata(output.join(name))
            .map_err(|_| BundleError::UnexpectedOutputInventory)?;
        if !metadata.file_type().is_file() || !single_link(&metadata) {
            return Err(BundleError::UnexpectedOutputInventory);
        }
    }
    Ok(())
}

fn payload_mode(filename: &str) -> u32 {
    match filename {
        DAEMON_FILENAME
        | CLI_FILENAME
        | DEPLOYMENT_CHECKER_FILENAME
        | INSTALLER_FILENAME
        | HOST_CHECKER_FILENAME => 0o755,
        _ => 0o644,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn single_link(metadata: &Metadata) -> bool {
    metadata.nlink() == 1
}

#[cfg(not(unix))]
fn single_link(_: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.file_type().is_file() && right.file_type().is_file() && left.len() == right.len()
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), BundleError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("setting payload mode", path, source))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<(), BundleError> {
    Ok(())
}

fn is_lower_hexadecimal(byte: u8) -> bool {
    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> BundleError {
    BundleError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
