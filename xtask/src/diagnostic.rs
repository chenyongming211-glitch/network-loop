//! Diagnostic declaration and byte identity only: never ELF/load authorization.

use std::path::Path;

use l2_loop_common::ABI_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bundle::read_bounded_single_link_regular;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticProfile {
    HooksOnly,
    ConfigLookup,
    Counters,
    Fingerprints,
    FpHash,
    FpMetadata,
    FpClock,
    FpMap,
}

impl DiagnosticProfile {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "hooks_only" => Some(Self::HooksOnly),
            "config_lookup" => Some(Self::ConfigLookup),
            "counters" => Some(Self::Counters),
            "fingerprints" => Some(Self::Fingerprints),
            "fp_hash" => Some(Self::FpHash),
            "fp_metadata" => Some(Self::FpMetadata),
            "fp_clock" => Some(Self::FpClock),
            "fp_map" => Some(Self::FpMap),
            _ => None,
        }
    }

    pub(crate) fn is_fingerprint_stage(self) -> bool {
        matches!(
            self,
            Self::FpHash | Self::FpMetadata | Self::FpClock | Self::FpMap
        )
    }

    pub(crate) fn declaration(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::HooksOnly => ("l2-loop-diag-hooks-only.o", "l2d_hooks_xdp", "l2d_hooks_tc"),
            Self::ConfigLookup => (
                "l2-loop-diag-config-lookup.o",
                "l2d_config_xdp",
                "l2d_config_tc",
            ),
            Self::Counters => ("l2-loop-diag-counters.o", "l2d_count_xdp", "l2d_count_tc"),
            Self::Fingerprints => ("l2-loop-diag-fingerprints.o", "l2d_full_xdp", "l2d_full_tc"),
            Self::FpHash => ("l2-loop-diag-fp-hash.o", "l2d_hash_xdp", "l2d_hash_tc"),
            Self::FpMetadata => ("l2-loop-diag-fp-metadata.o", "l2d_meta_xdp", "l2d_meta_tc"),
            Self::FpClock => ("l2-loop-diag-fp-clock.o", "l2d_clock_xdp", "l2d_clock_tc"),
            Self::FpMap => ("l2-loop-diag-fp-map.o", "l2d_map_xdp", "l2d_map_tc"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticManifest {
    schema_version: u16,
    purpose: String,
    deployment_gate_evidence: bool,
    commit_sha: String,
    profile: DiagnosticProfile,
    ebpf_target: String,
    abi_version: u16,
    object_file: String,
    object_sha256: String,
    programs: ProgramDeclaration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramDeclaration {
    xdp: String,
    tc: String,
}

#[derive(Debug, Error)]
pub enum DiagnosticIdentityError {
    #[error("DX_SCHEMA: diagnostic manifest schema rejected")]
    Schema,
    #[error("DX_BINDING: diagnostic identity does not match the expected declaration")]
    Binding,
    #[error("DX_DIGEST: diagnostic payload digest rejected")]
    Digest,
    #[error("DX_INPUT: bounded stable single-link regular input required on Unix")]
    Input,
}

#[derive(Debug, Serialize)]
pub struct VerifiedDiagnosticIdentity {
    commit_sha: String,
    profile: DiagnosticProfile,
    payload_sha256_verified: bool,
    load_authorized: bool,
    deployment_gate_evidence: bool,
}

/// Checks caller-bound declaration and exact bytes, not actual ELF inventory.
/// A matching manifest is not proof of trusted CI provenance.
/// Host authorization, object inventory and verifier checks remain separate gates.
pub fn verify_diagnostic_identity(
    manifest_path: &Path,
    object_path: &Path,
    expected_commit: &str,
    expected_profile: DiagnosticProfile,
) -> Result<VerifiedDiagnosticIdentity, DiagnosticIdentityError> {
    use DiagnosticIdentityError::{Binding, Digest as DigestError, Input, Schema};

    let bytes = read_bounded_single_link_regular(manifest_path, 65_536).map_err(|_| Input)?;
    let manifest: DiagnosticManifest = serde_json::from_slice(&bytes).map_err(|_| Schema)?;
    if manifest.schema_version != 1
        || manifest.purpose != "isolated_layered_diagnostic"
        || manifest.deployment_gate_evidence
        || manifest.ebpf_target != "bpfel-unknown-none"
        || manifest.abi_version != ABI_VERSION
    {
        return Err(Schema);
    }
    let (filename, xdp, tc) = expected_profile.declaration();
    if !lower_hex(expected_commit, 40)
        || manifest.commit_sha != expected_commit
        || manifest.profile != expected_profile
        || manifest.object_file != filename
        || object_path.file_name().and_then(|value| value.to_str()) != Some(filename)
        || manifest.programs.xdp != xdp
        || manifest.programs.tc != tc
    {
        return Err(Binding);
    }
    if !lower_hex(&manifest.object_sha256, 64) {
        return Err(DigestError);
    }
    let payload =
        read_bounded_single_link_regular(object_path, 16 * 1024 * 1024).map_err(|_| Input)?;
    if payload.is_empty() {
        return Err(Input);
    }
    if format!("{:x}", Sha256::digest(&payload)) != manifest.object_sha256 {
        return Err(DigestError);
    }
    Ok(VerifiedDiagnosticIdentity {
        commit_sha: manifest.commit_sha,
        profile: manifest.profile,
        payload_sha256_verified: true,
        load_authorized: false,
        deployment_gate_evidence: false,
    })
}

pub(crate) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
