use std::collections::BTreeMap;

use serde_json::json;
use xtask::bundle::{BundleManifest, render_manifest, render_sha256sums};

const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn manifest_uses_the_stable_release_schema() {
    let manifest = BundleManifest::new(COMMIT_SHA, "0.1.0");
    let rendered = render_manifest(&manifest).expect("manifest should serialize");
    let actual: serde_json::Value =
        serde_json::from_str(&rendered).expect("manifest should be valid JSON");

    assert_eq!(
        actual,
        json!({
            "commit_sha": COMMIT_SHA,
            "package_version": "0.1.0",
            "userspace_target": "x86_64-unknown-linux-musl",
            "ebpf_target": "bpfel-unknown-none",
            "files": {
                "daemon": "l2-loopd",
                "cli": "l2-loopctl",
                "ebpf": "l2-loop-ebpf.o"
            }
        })
    );
}

#[test]
fn checksum_manifest_is_lexically_ordered_and_exact() {
    let checksums = BTreeMap::from([
        ("manifest.json".to_owned(), "d".repeat(64)),
        ("l2-loopd".to_owned(), "c".repeat(64)),
        ("l2-loopctl".to_owned(), "b".repeat(64)),
        ("l2-loop-ebpf.o".to_owned(), "a".repeat(64)),
    ]);

    assert_eq!(
        render_sha256sums(&checksums).expect("approved checksums should render"),
        format!(
            "{}  l2-loop-ebpf.o\n{}  l2-loopctl\n{}  l2-loopd\n{}  manifest.json\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        )
    );
}

#[test]
fn checksum_manifest_rejects_missing_or_extra_files() {
    let missing = BTreeMap::from([
        ("l2-loopd".to_owned(), "a".repeat(64)),
        ("l2-loopctl".to_owned(), "b".repeat(64)),
        ("manifest.json".to_owned(), "c".repeat(64)),
    ]);
    assert!(render_sha256sums(&missing).is_err());

    let extra = BTreeMap::from([
        ("l2-loop-ebpf.o".to_owned(), "a".repeat(64)),
        ("l2-loopctl".to_owned(), "b".repeat(64)),
        ("l2-loopd".to_owned(), "c".repeat(64)),
        ("manifest.json".to_owned(), "d".repeat(64)),
        ("host-inventory.txt".to_owned(), "e".repeat(64)),
    ]);
    assert!(render_sha256sums(&extra).is_err());
}
