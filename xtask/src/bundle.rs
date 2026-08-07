use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const USERSPACE_TARGET: &str = "x86_64-unknown-linux-musl";
pub const EBPF_TARGET: &str = "bpfel-unknown-none";
pub const DAEMON_FILENAME: &str = "l2-loopd";
pub const CLI_FILENAME: &str = "l2-loopctl";
pub const HOST_CHECK_FILENAME: &str = "l2-loop-hostcheck";
pub const EBPF_FILENAME: &str = "l2-loop-ebpf.o";
pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const CHECKSUMS_FILENAME: &str = "SHA256SUMS";

const CHECKSUM_FILES: [&str; 5] = [
    EBPF_FILENAME,
    HOST_CHECK_FILENAME,
    CLI_FILENAME,
    DAEMON_FILENAME,
    MANIFEST_FILENAME,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleManifest {
    commit_sha: String,
    package_version: String,
    userspace_target: &'static str,
    ebpf_target: &'static str,
    files: BundleFiles,
}

impl BundleManifest {
    pub fn new(commit_sha: impl Into<String>, package_version: impl Into<String>) -> Self {
        Self {
            commit_sha: commit_sha.into(),
            package_version: package_version.into(),
            userspace_target: USERSPACE_TARGET,
            ebpf_target: EBPF_TARGET,
            files: BundleFiles {
                daemon: DAEMON_FILENAME,
                cli: CLI_FILENAME,
                host_check: HOST_CHECK_FILENAME,
                ebpf: EBPF_FILENAME,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundleFiles {
    daemon: &'static str,
    cli: &'static str,
    host_check: &'static str,
    ebpf: &'static str,
}

#[derive(Debug)]
pub struct BundleInputs<'a> {
    pub commit_sha: &'a str,
    pub package_version: &'a str,
    pub daemon: &'a Path,
    pub cli: &'a Path,
    pub host_check: &'a Path,
    pub ebpf: &'a Path,
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
    #[error("bundle output directory already exists")]
    OutputExists,
    #[error("bundle input is not a regular file: {path}")]
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
    validate_input(inputs.daemon)?;
    validate_input(inputs.cli)?;
    validate_input(inputs.host_check)?;
    validate_input(inputs.ebpf)?;

    if inputs.output_dir.exists() {
        return Err(BundleError::OutputExists);
    }
    fs::create_dir_all(inputs.output_dir)
        .map_err(|source| io_error("creating output directory", inputs.output_dir, source))?;

    copy_file(inputs.daemon, &inputs.output_dir.join(DAEMON_FILENAME))?;
    copy_file(inputs.cli, &inputs.output_dir.join(CLI_FILENAME))?;
    copy_file(
        inputs.host_check,
        &inputs.output_dir.join(HOST_CHECK_FILENAME),
    )?;
    copy_file(inputs.ebpf, &inputs.output_dir.join(EBPF_FILENAME))?;

    let manifest = BundleManifest::new(inputs.commit_sha, inputs.package_version);
    let manifest_path = inputs.output_dir.join(MANIFEST_FILENAME);
    fs::write(&manifest_path, render_manifest(&manifest)?)
        .map_err(|source| io_error("writing manifest", &manifest_path, source))?;

    let mut checksums = BTreeMap::new();
    for filename in CHECKSUM_FILES {
        let path = inputs.output_dir.join(filename);
        checksums.insert(filename.to_owned(), sha256_file(&path)?);
    }
    let checksums_path = inputs.output_dir.join(CHECKSUMS_FILENAME);
    fs::write(&checksums_path, render_sha256sums(&checksums)?)
        .map_err(|source| io_error("writing checksums", &checksums_path, source))?;

    Ok(())
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

fn validate_input(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading input metadata", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(BundleError::InvalidInput {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), BundleError> {
    fs::copy(source, destination)
        .map(|_| ())
        .map_err(|error| io_error("copying bundle input", source, error))
}

fn sha256_file(path: &Path) -> Result<String, BundleError> {
    let mut file =
        File::open(path).map_err(|source| io_error("opening bundle file", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("reading bundle file", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
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
