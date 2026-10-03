#![cfg(unix)]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2-loop-diagnostic-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn manifest(&self) -> Value {
        json!({
            "schema_version": 1,
            "purpose": "isolated_layered_diagnostic",
            "deployment_gate_evidence": false,
            "commit_sha": COMMIT,
            "profile": "hooks_only",
            "ebpf_target": "bpfel-unknown-none",
            "abi_version": 1,
            "object_file": "l2-loop-diag-hooks-only.o",
            "object_sha256": ABC_SHA256,
            "programs": {"xdp": "l2d_hooks_xdp", "tc": "l2d_hooks_tc"}
        })
    }

    fn write(&self, manifest: &Value) {
        fs::write(self.0.join("diagnostic.json"), manifest.to_string()).unwrap();
        fs::write(
            self.0.join(manifest["object_file"].as_str().unwrap()),
            b"abc",
        )
        .unwrap();
    }

    fn run(&self, profile: &str, object: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("verify-diagnostic-identity")
            .arg("--manifest")
            .arg(self.0.join("diagnostic.json"))
            .arg("--object")
            .arg(self.0.join(object))
            .args(["--commit-sha", COMMIT, "--profile", profile])
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn rejected(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains(code));
}

#[test]
fn verifies_four_profile_declarations_without_granting_load_authority() {
    for (profile, file, xdp, tc) in [
        (
            "hooks_only",
            "l2-loop-diag-hooks-only.o",
            "l2d_hooks_xdp",
            "l2d_hooks_tc",
        ),
        (
            "config_lookup",
            "l2-loop-diag-config-lookup.o",
            "l2d_config_xdp",
            "l2d_config_tc",
        ),
        (
            "counters",
            "l2-loop-diag-counters.o",
            "l2d_count_xdp",
            "l2d_count_tc",
        ),
        (
            "fingerprints",
            "l2-loop-diag-fingerprints.o",
            "l2d_full_xdp",
            "l2d_full_tc",
        ),
        ("fp_hash", "l2-loop-diag-fp-hash.o", "l2d_hash_xdp", "l2d_hash_tc"),
        ("fp_metadata", "l2-loop-diag-fp-metadata.o", "l2d_meta_xdp", "l2d_meta_tc"),
        ("fp_clock", "l2-loop-diag-fp-clock.o", "l2d_clock_xdp", "l2d_clock_tc"),
        ("fp_map", "l2-loop-diag-fp-map.o", "l2d_map_xdp", "l2d_map_tc"),
    ] {
        let fixture = Fixture::new();
        let mut manifest = fixture.manifest();
        manifest["profile"] = json!(profile);
        manifest["object_file"] = json!(file);
        manifest["programs"] = json!({"xdp": xdp, "tc": tc});
        fixture.write(&manifest);
        let before = fs::read(fixture.0.join(file)).unwrap();
        let output = fixture.run(profile, file);
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["profile"], profile);
        assert_eq!(value["commit_sha"], COMMIT);
        assert_eq!(value["payload_sha256_verified"], true);
        assert_eq!(value["load_authorized"], false);
        assert_eq!(value["deployment_gate_evidence"], false);
        // A byte/digest identity check is deliberately not ELF or verifier approval.
        assert_eq!(fs::read(fixture.0.join(file)).unwrap(), before);
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
    }
}

#[test]
fn rejects_schema_drift_including_unknown_nested_fields_and_duplicate_fields() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("schema_version", json!(2)),
        ("purpose", json!("release")),
        ("deployment_gate_evidence", json!(true)),
        ("profile", json!("production")),
        ("ebpf_target", json!("bpfeb-unknown-none")),
        ("abi_version", json!(2)),
        ("unknown", json!(true)),
    ] {
        let mut manifest = fixture.manifest();
        manifest[field] = value;
        fixture.write(&manifest);
        rejected(
            fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
            "DX_SCHEMA",
        );
    }
    let mut manifest = fixture.manifest();
    manifest["programs"]["extra"] = json!("unexpected");
    fixture.write(&manifest);
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_SCHEMA",
    );
    let duplicate = fixture
        .manifest()
        .to_string()
        .replacen('{', "{\"schema_version\":1,", 1);
    fs::write(fixture.0.join("diagnostic.json"), duplicate).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_SCHEMA",
    );
}

#[test]
fn rejects_wrong_commit_profile_filename_and_declared_program_identity() {
    let fixture = Fixture::new();
    for (field, value) in [
        (
            "commit_sha",
            json!("abcdef0123456789abcdef0123456789abcdef0123"),
        ),
        ("commit_sha", json!(COMMIT.to_uppercase())),
        ("object_file", json!("l2-loop-ebpf.o")),
        ("object_file", json!("../l2-loop-diag-hooks-only.o")),
        (
            "programs",
            json!({"xdp":"l2_loop_xdp_ingress","tc":"l2_loop_tc_egress"}),
        ),
        (
            "programs",
            json!({"xdp":"l2d_full_xdp","tc":"l2d_hooks_tc"}),
        ),
    ] {
        fixture.write(&fixture.manifest());
        let mut manifest = fixture.manifest();
        manifest[field] = value;
        fs::write(fixture.0.join("diagnostic.json"), manifest.to_string()).unwrap();
        rejected(
            fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
            "DX_BINDING",
        );
    }
    fixture.write(&fixture.manifest());
    rejected(
        fixture.run("counters", "l2-loop-diag-hooks-only.o"),
        "DX_BINDING",
    );
    fs::copy(
        fixture.0.join("l2-loop-diag-hooks-only.o"),
        fixture.0.join("renamed.o"),
    )
    .unwrap();
    rejected(fixture.run("hooks_only", "renamed.o"), "DX_BINDING");
}

#[test]
fn rejects_changed_missing_empty_or_oversized_payloads() {
    let fixture = Fixture::new();
    fixture.write(&fixture.manifest());
    let object = fixture.0.join("l2-loop-diag-hooks-only.o");
    fs::write(&object, b"abd").unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_DIGEST",
    );
    fs::write(&object, b"").unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
    fs::File::create(&object)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
    fs::remove_file(&object).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
}

#[test]
fn rejects_malformed_digest_missing_fields_and_bounded_manifest_overflow() {
    let fixture = Fixture::new();
    for digest in [ABC_SHA256.to_uppercase(), "0".repeat(63), "g".repeat(64)] {
        let mut manifest = fixture.manifest();
        manifest["object_sha256"] = json!(digest);
        fixture.write(&manifest);
        rejected(
            fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
            "DX_DIGEST",
        );
    }
    let mut manifest = fixture.manifest();
    manifest
        .as_object_mut()
        .unwrap()
        .remove("deployment_gate_evidence");
    fixture.write(&manifest);
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_SCHEMA",
    );
    fs::write(fixture.0.join("diagnostic.json"), vec![b' '; 65537]).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
}

#[cfg(unix)]
#[test]
fn refuses_symlink_hardlink_and_directory_inputs_without_writes() {
    let fixture = Fixture::new();
    fixture.write(&fixture.manifest());
    let object = fixture.0.join("l2-loop-diag-hooks-only.o");
    let held = fixture.0.join("held");
    fs::rename(&object, &held).unwrap();
    std::os::unix::fs::symlink(&held, &object).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
    fs::remove_file(&object).unwrap();
    fs::hard_link(&held, &object).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
    fs::remove_file(&object).unwrap();
    fs::create_dir(&object).unwrap();
    rejected(
        fixture.run("hooks_only", "l2-loop-diag-hooks-only.o"),
        "DX_INPUT",
    );
    assert_eq!(fs::read(&held).unwrap(), b"abc");
}
