//! CI build tooling only; never a product or host attachment command.

use std::{fs, io::Write, path::Path, process::{Command, Stdio}};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    bundle::read_bounded_regular,
    diagnostic::{DiagnosticProfile, lower_hex},
    diagnostic_elf::inspect_diagnostic_elf,
    ebpf::EBPF_CARGO_TOOLCHAIN,
};

#[derive(Debug, Error)]
#[error("DX_BUILD: diagnostic build rejected ({0})")]
pub struct DiagnosticBuildError(&'static str);

pub fn build_diagnostic_ebpf(
    profile: DiagnosticProfile,
    commit: &str,
    output: &Path,
) -> Result<(), DiagnosticBuildError> {
    if !lower_hex(commit, 40) {
        return Err(DiagnosticBuildError("commit"));
    }
    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(DiagnosticBuildError("output must not exist")),
    }
    let (filename, xdp, tc) = profile.declaration();
    let binary = filename.strip_suffix(".o").expect("fixed object suffix");
    let target = Path::new(".artifacts/diagnostic-target");
    let status = Command::new("cargo")
        .args([EBPF_CARGO_TOOLCHAIN, "build", "--locked", "-Z", "build-std=core",
            "--release", "--target", "bpfel-unknown-none", "--package", "l2-loop-ebpf",
            "--features", "diagnostics", "--bin", binary, "--target-dir"])
        .arg(target)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status().map_err(|_| DiagnosticBuildError("compiler start"))?;
    if !status.success() {
        return Err(DiagnosticBuildError("compiler failure"));
    }
    let source = target.join("bpfel-unknown-none/release").join(binary);
    // Cargo may hard-link its own target/deps output. Published files below are new copies.
    let bytes = read_bounded_regular(&source, 16 * 1024 * 1024)
        .map_err(|_| DiagnosticBuildError("object input"))?;
    inspect_diagnostic_elf(&bytes, profile)
        .map_err(|_| DiagnosticBuildError("ELF contract"))?;
    let manifest = serde_json::json!({
        "schema_version": 1,
        "purpose": "isolated_layered_diagnostic",
        "deployment_gate_evidence": false,
        "commit_sha": commit,
        "profile": profile,
        "ebpf_target": "bpfel-unknown-none",
        "abi_version": l2_loop_common::ABI_VERSION,
        "object_file": filename,
        "object_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "programs": {"xdp": xdp, "tc": tc},
    });
    let manifest = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| DiagnosticBuildError("manifest"))?;
    fs::create_dir(output).map_err(|_| DiagnosticBuildError("exclusive output directory"))?;
    for (name, payload) in [(filename, bytes.as_slice()), ("diagnostic.json", manifest.as_slice())] {
        fs::OpenOptions::new().write(true).create_new(true).open(output.join(name))
            .and_then(|mut file| file.write_all(payload))
            .map_err(|_| DiagnosticBuildError("exclusive output file"))?;
    }
    Ok(())
}
