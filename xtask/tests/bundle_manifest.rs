use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use sha2::{Digest, Sha256};
use xtask::bundle::{
    BundleInputs, BundleManifest, create_bundle, render_manifest, render_sha256sums,
};

const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const SERVICE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXAMPLE_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PAYLOADS: [&str; 9] = [
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

#[test]
fn manifest_uses_the_stable_deployment_release_schema() {
    let manifest = BundleManifest::new(COMMIT_SHA, "0.1.0", SERVICE_DIGEST, EXAMPLE_DIGEST);
    let rendered = render_manifest(&manifest).expect("manifest should serialize");
    let actual: serde_json::Value =
        serde_json::from_str(&rendered).expect("manifest should be valid JSON");

    assert_eq!(
        actual,
        json!({
            "schema_version": 1,
            "commit_sha": COMMIT_SHA,
            "package_version": "0.1.0",
            "userspace_target": "x86_64-unknown-linux-musl",
            "ebpf_target": "bpfel-unknown-none",
            "abi_version": 1,
            "files": {
                "daemon": "l2-loopd",
                "cli": "l2-loopctl",
                "deployment_checker": "l2-loop-deploycheck",
                "installer": "l2-loop-install",
                "host_checker": "l2-loop-hostcheck",
                "ebpf_object": "l2-loop-ebpf.o",
                "service_unit": "l2-loop.service",
                "authorization_example": "deployment-v1.example.json"
            },
            "service_unit_sha256": SERVICE_DIGEST,
            "authorization_example_sha256": EXAMPLE_DIGEST
        })
    );
}

#[test]
fn checksum_manifest_is_lexically_ordered_and_exact_for_nine_payloads() {
    let checksums = PAYLOADS
        .iter()
        .enumerate()
        .map(|(index, name)| (name.to_string(), format!("{:064x}", index + 1)))
        .collect::<BTreeMap<_, _>>();

    let rendered = render_sha256sums(&checksums).expect("approved checksums should render");
    let names = rendered.lines().map(|line| &line[66..]).collect::<Vec<_>>();
    assert_eq!(names, PAYLOADS);
    assert!(rendered.ends_with('\n'));
    assert_eq!(rendered.lines().count(), 9);
    assert!(rendered.lines().all(|line| {
        line.len() == 66 + line[66..].len()
            && &line[64..66] == "  "
            && line[..64]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }));
}

#[test]
fn checksum_manifest_rejects_missing_or_extra_files() {
    let exact = PAYLOADS
        .iter()
        .map(|name| (name.to_string(), "a".repeat(64)))
        .collect::<BTreeMap<_, _>>();
    let mut missing = exact.clone();
    missing.remove("l2-loop-install");
    assert!(render_sha256sums(&missing).is_err());

    let mut extra = exact;
    extra.insert("host-inventory.txt".to_owned(), "b".repeat(64));
    assert!(render_sha256sums(&extra).is_err());
}

#[test]
fn bundle_creation_emits_only_ten_regular_top_level_files() {
    let tree = BundleTestTree::new("exact");
    let inputs = tree.inputs();
    create_bundle(&inputs).expect("bundle should be created");

    let mut names = fs::read_dir(&tree.output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["SHA256SUMS"]
            .into_iter()
            .chain(PAYLOADS)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert!(fs::read_dir(&tree.output).unwrap().all(|entry| {
        let metadata = fs::symlink_metadata(entry.unwrap().path()).unwrap();
        metadata.file_type().is_file()
    }));

    let checksums = fs::read_to_string(tree.output.join("SHA256SUMS")).unwrap();
    assert_eq!(checksums.lines().count(), 9);
    for line in checksums.lines() {
        let expected = &line[..64];
        let filename = &line[66..];
        assert_eq!(
            sha256(&fs::read(tree.output.join(filename)).unwrap()),
            expected
        );
    }
}

#[test]
fn bundle_rejects_non_regular_and_oversized_gate_assets() {
    let missing_installer = BundleTestTree::new("missing-installer");
    fs::remove_file(&missing_installer.installer).unwrap();
    assert!(create_bundle(&missing_installer.inputs()).is_err());

    let linked = BundleTestTree::new("linked");
    replace_with_symlink(&linked.service_unit, &linked.daemon);
    assert!(create_bundle(&linked.inputs()).is_err());

    let oversized = BundleTestTree::new("oversized");
    fs::OpenOptions::new()
        .write(true)
        .open(&oversized.authorization_example)
        .unwrap()
        .set_len(1_048_577)
        .unwrap();
    assert!(create_bundle(&oversized.inputs()).is_err());
}

#[test]
fn authorization_example_is_illustrative_but_never_valid_authorization() {
    let source = include_str!("../../packaging/deployment-v1.example.json");
    let example: serde_json::Value = serde_json::from_str(source).unwrap();

    assert_eq!(example["schema_version"], 1);
    assert_eq!(example["mode"], "read_only_canary_candidate");
    assert_eq!(example["interface"]["kind"], "physical");
    assert_eq!(example["interface"]["xdp_native"], "empty");
    assert_eq!(example["interface"]["xdp_generic"], "empty");
    assert_eq!(example["interface"]["tc_ingress"], json!([]));
    assert_eq!(example["interface"]["tc_egress"], json!([]));

    let authorization = example["authorization_id"].as_str().unwrap();
    let artifact = example["artifact_commit_sha"].as_str().unwrap();
    assert!(authorization.contains("REPLACE_WITH_RANDOM"));
    assert!(artifact.contains("REPLACE_WITH_EXACT_GITHUB_SHA"));
    assert!(!is_lower_hex(authorization, 32));
    assert!(!is_lower_hex(artifact, 40));
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn replace_with_symlink(path: &Path, target: &Path) {
    use std::os::unix::fs::symlink;

    fs::remove_file(path).unwrap();
    symlink(target, path).unwrap();
}

#[cfg(windows)]
fn replace_with_symlink(path: &Path, target: &Path) {
    use std::os::windows::fs::symlink_file;

    fs::remove_file(path).unwrap();
    symlink_file(target, path).unwrap();
}

struct BundleTestTree {
    root: PathBuf,
    output: PathBuf,
    daemon: PathBuf,
    cli: PathBuf,
    deployment_checker: PathBuf,
    installer: PathBuf,
    host_checker: PathBuf,
    ebpf: PathBuf,
    service_unit: PathBuf,
    authorization_example: PathBuf,
}

impl BundleTestTree {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "l2-loop-bundle-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let tree = Self {
            output: root.join("output"),
            daemon: root.join("daemon"),
            cli: root.join("cli"),
            deployment_checker: root.join("deployment-checker"),
            installer: root.join("installer"),
            host_checker: root.join("host-checker"),
            ebpf: root.join("ebpf"),
            service_unit: root.join("service-unit"),
            authorization_example: root.join("authorization-example"),
            root,
        };
        for path in [
            &tree.daemon,
            &tree.cli,
            &tree.deployment_checker,
            &tree.installer,
            &tree.host_checker,
            &tree.ebpf,
            &tree.service_unit,
            &tree.authorization_example,
        ] {
            fs::write(path, path.file_name().unwrap().as_encoded_bytes()).unwrap();
        }
        tree
    }

    fn inputs(&self) -> BundleInputs<'_> {
        BundleInputs {
            commit_sha: COMMIT_SHA,
            package_version: "0.1.0",
            daemon: &self.daemon,
            cli: &self.cli,
            deployment_checker: &self.deployment_checker,
            installer: &self.installer,
            host_checker: &self.host_checker,
            ebpf: &self.ebpf,
            service_unit: &self.service_unit,
            authorization_example: &self.authorization_example,
            output_dir: &self.output,
        }
    }
}

impl Drop for BundleTestTree {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
