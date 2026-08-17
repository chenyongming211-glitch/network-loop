#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    os::unix::{fs::symlink, net::UnixListener},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::linux::deployment_fs::{
    DeploymentEntryKindV1, DeploymentEntrySnapshotV1, LinuxDeploymentFilesystem,
    StagedLayoutInputV1, validate_staged_layout_snapshot,
};
use l2_loop_core::DeploymentArtifactIdentityV1;
use sha2::{Digest, Sha256};

const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const LOGICAL_ROOT: &str = "/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root";
const MANIFEST: &str = include_str!("fixtures/deployment/manifest-v1.json");
const UNIT: &[u8] = b"unit-v1\n";
const EXAMPLE: &[u8] = b"example-v1\n";
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
fn staging_root_grammar_accepts_only_the_generated_acceptance_shape() {
    let filesystem = filesystem();
    assert!(
        filesystem
            .validate_staging_root(Path::new(LOGICAL_ROOT))
            .is_ok()
    );

    for rejected in [
        "/run/l2-loop/accept/00112233445566778899AABBCCDDEEFF/staging-root",
        "/run/l2-loop/accept/00112233445566778899aabbccddee/staging-root",
        "/run/l2-loop/accept/00112233445566778899aabbccddeeff00/staging-root",
        "/run/l2-loop/accept//00112233445566778899aabbccddeeff/staging-root",
        "/run/l2-loop/accept/./00112233445566778899aabbccddeeff/staging-root",
        "/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root/extra",
        "/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root/",
        "/run/l2-loop/accept/00112233445566778899aabbccddeeff",
        "/run/l2-loop/staging-root",
        "/etc/l2-loop",
        "/usr/libexec/l2-loop",
        "/var/lib/l2-loop",
        "/",
    ] {
        assert!(
            filesystem
                .validate_staging_root(Path::new(rejected))
                .is_err(),
            "accepted invalid staging root: {rejected}"
        );
    }
}

#[test]
fn bundle_reader_accepts_exact_inventory_manifest_and_checksums() {
    let bundle = BundleTree::valid("valid");
    let filesystem = filesystem();

    let snapshot = filesystem.inspect_bundle(bundle.path()).unwrap();

    assert_eq!(snapshot.artifact, artifact());
    assert_eq!(snapshot.files.len(), 10);
    assert_eq!(snapshot.files.keys().next().unwrap(), "SHA256SUMS");
    assert_eq!(snapshot.files["l2-loop.service"].sha256, sha256(UNIT));
    assert_eq!(snapshot.files["l2-loop.service"].hard_links, 1);
}

#[test]
fn bundle_reader_rejects_extra_missing_nested_and_renamed_entries() {
    let filesystem = filesystem();

    let extra = BundleTree::valid("extra");
    fs::write(extra.path().join("host.txt"), b"forbidden").unwrap();
    assert!(filesystem.inspect_bundle(extra.path()).is_err());

    let missing = BundleTree::valid("missing");
    fs::remove_file(missing.path().join("l2-loop-install")).unwrap();
    assert!(filesystem.inspect_bundle(missing.path()).is_err());

    let nested = BundleTree::valid("nested");
    fs::create_dir(nested.path().join("nested")).unwrap();
    assert!(filesystem.inspect_bundle(nested.path()).is_err());

    let renamed = BundleTree::valid("renamed");
    fs::rename(
        renamed.path().join("l2-loop-install"),
        renamed.path().join("installer"),
    )
    .unwrap();
    assert!(filesystem.inspect_bundle(renamed.path()).is_err());
}

#[test]
fn bundle_reader_rejects_noncanonical_duplicate_or_untrusted_checksum_names() {
    let filesystem = filesystem();
    for (label, edit) in [
        ("uppercase", ChecksumEdit::Uppercase),
        ("duplicate", ChecksumEdit::Duplicate),
        ("traversal", ChecksumEdit::Traversal),
        ("absolute", ChecksumEdit::Absolute),
        ("mismatch", ChecksumEdit::Mismatch),
        ("missing-line", ChecksumEdit::Missing),
    ] {
        let bundle = BundleTree::valid(label);
        rewrite_checksums(bundle.path(), edit);
        assert!(
            filesystem.inspect_bundle(bundle.path()).is_err(),
            "accepted invalid checksum case: {label}"
        );
    }
}

#[test]
fn bundle_reader_rejects_manifest_binding_changes_and_oversized_reads() {
    let filesystem = filesystem();
    for (label, before, after) in [
        (
            "commit",
            COMMIT_SHA,
            "fedcba9876543210fedcba9876543210fedcba98",
        ),
        ("role", "l2-loopd", "daemon"),
        ("installer-role", "l2-loop-install", "renamed-installer"),
        (
            "target",
            "x86_64-unknown-linux-musl",
            "x86_64-unknown-linux-gnu",
        ),
        (
            "package",
            "\"package_version\": \"0.1.0\"",
            "\"package_version\": \"9.9.9\"",
        ),
        ("abi", "\"abi_version\": 1", "\"abi_version\": 2"),
        (
            "digest",
            "f86c81f23a2cbd0cadbdf87ab6eb57eb95778d0af6e5816c5f2959b1f570fa58",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let bundle = BundleTree::valid(label);
        let changed = MANIFEST.replacen(before, after, 1);
        fs::write(bundle.path().join("manifest.json"), changed).unwrap();
        BundleTree::write_checksums(bundle.path());
        assert!(
            filesystem.inspect_bundle(bundle.path()).is_err(),
            "accepted invalid manifest case: {label}"
        );
    }

    let oversized = BundleTree::valid("oversized");
    File::options()
        .write(true)
        .open(oversized.path().join("manifest.json"))
        .unwrap()
        .set_len(1_048_577)
        .unwrap();
    assert!(filesystem.inspect_bundle(oversized.path()).is_err());
}

#[test]
fn bundle_reader_rejects_symlinks_hard_links_and_non_regular_entries() {
    let filesystem = filesystem();

    let linked = BundleTree::valid("symlink");
    fs::remove_file(linked.path().join("l2-loopd")).unwrap();
    symlink("l2-loopctl", linked.path().join("l2-loopd")).unwrap();
    assert!(filesystem.inspect_bundle(linked.path()).is_err());

    let hard_linked = BundleTree::valid("hard-link");
    fs::remove_file(hard_linked.path().join("l2-loopd")).unwrap();
    fs::hard_link(
        hard_linked.path().join("l2-loopctl"),
        hard_linked.path().join("l2-loopd"),
    )
    .unwrap();
    assert!(filesystem.inspect_bundle(hard_linked.path()).is_err());

    let socket = BundleTree::valid("socket");
    fs::remove_file(socket.path().join("l2-loopd")).unwrap();
    let _listener = UnixListener::bind(socket.path().join("l2-loopd")).unwrap();
    assert!(filesystem.inspect_bundle(socket.path()).is_err());
}

#[test]
fn staged_layout_snapshot_accepts_exact_production_shape() {
    let input = valid_layout();
    let snapshot = validate_staged_layout_snapshot(&input).unwrap();

    assert_eq!(snapshot.artifact, artifact());
    assert_eq!(snapshot.files.len(), input.entries.len());
    assert!(!snapshot.runtime_occupied);
}

#[test]
fn staged_layout_snapshot_fails_closed_on_metadata_or_containment_change() {
    for (label, mutate) in [
        ("owner", mutate_owner as fn(&mut StagedLayoutInputV1)),
        ("mode", mutate_mode),
        ("type-symlink", mutate_type_symlink),
        ("type-fifo", mutate_type_fifo),
        ("type-device", mutate_type_device),
        ("type-socket", mutate_type_socket),
        ("type-other", mutate_type_other),
        ("hard-link", mutate_hard_link),
        ("escape", mutate_escape),
        ("socket", mutate_runtime_socket),
        ("missing", mutate_missing),
        ("extra", mutate_extra),
    ] {
        let mut input = valid_layout();
        mutate(&mut input);
        assert!(
            validate_staged_layout_snapshot(&input).is_err(),
            "accepted invalid staged layout: {label}"
        );
    }
}

#[test]
fn deployment_filesystem_source_is_finite_bounded_and_read_only() {
    let source = include_str!("../src/linux/deployment_fs.rs");
    for required in [
        "symlink_metadata",
        "O_NOFOLLOW",
        "HASH_BUFFER_BYTES",
        "hard_links",
        "canonicalize",
        "MAX_",
        "EXPECTED_BUNDLE_FILES",
        "EXPECTED_LAYOUT_ENTRIES",
    ] {
        assert!(
            source.contains(required),
            "missing safety primitive: {required}"
        );
    }
    for prohibited in [
        "create_dir",
        "remove_file",
        "remove_dir",
        "set_permissions",
        "fs::write",
        "File::create",
        "OpenOptions::new().write",
        "rename(",
        "Command::new",
        "WalkDir",
    ] {
        assert!(!source.contains(prohibited), "writer present: {prohibited}");
    }
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn filesystem() -> LinuxDeploymentFilesystem {
    LinuxDeploymentFilesystem::new(artifact()).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Copy)]
enum ChecksumEdit {
    Uppercase,
    Duplicate,
    Traversal,
    Absolute,
    Mismatch,
    Missing,
}

fn rewrite_checksums(root: &Path, edit: ChecksumEdit) {
    let path = root.join("SHA256SUMS");
    let content = fs::read_to_string(&path).unwrap();
    let lines = content.lines().collect::<Vec<_>>();
    let changed = match edit {
        ChecksumEdit::Uppercase => content.replacen('a', "A", 1),
        ChecksumEdit::Duplicate => format!("{content}{}\n", lines[0]),
        ChecksumEdit::Traversal => content.replacen("  l2-loopd", "  ../l2-loopd", 1),
        ChecksumEdit::Absolute => content.replacen("  l2-loopd", "  /tmp/l2-loopd", 1),
        ChecksumEdit::Mismatch => format!("{}{}\n", "0".repeat(64), &lines[0][64..]),
        ChecksumEdit::Missing => lines[1..].join("\n") + "\n",
    };
    fs::write(path, changed).unwrap();
}

struct BundleTree {
    root: PathBuf,
}

impl BundleTree {
    fn valid(label: &str) -> Self {
        let root = temporary_path(label);
        fs::create_dir(&root).unwrap();
        for name in PAYLOADS {
            let bytes: &[u8] = match name {
                "manifest.json" => MANIFEST.as_bytes(),
                "l2-loop.service" => UNIT,
                "deployment-v1.example.json" => EXAMPLE,
                _ => name.as_bytes(),
            };
            fs::write(root.join(name), bytes).unwrap();
        }
        Self::write_checksums(&root);
        Self { root }
    }

    fn write_checksums(root: &Path) {
        let mut checksums = String::new();
        for name in PAYLOADS {
            let bytes = fs::read(root.join(name)).unwrap();
            checksums.push_str(&sha256(&bytes));
            checksums.push_str("  ");
            checksums.push_str(name);
            checksums.push('\n');
        }
        fs::write(root.join("SHA256SUMS"), checksums).unwrap();
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for BundleTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "l2-loop-deployment-layout-{}-{label}-{nonce}",
        std::process::id()
    ))
}

fn valid_layout() -> StagedLayoutInputV1 {
    let root = PathBuf::from(LOGICAL_ROOT);
    let definitions = [
        (".", DeploymentEntryKindV1::Directory, 0o700),
        ("usr", DeploymentEntryKindV1::Directory, 0o755),
        ("usr/bin", DeploymentEntryKindV1::Directory, 0o755),
        ("usr/lib", DeploymentEntryKindV1::Directory, 0o755),
        ("usr/libexec", DeploymentEntryKindV1::Directory, 0o755),
        (
            "usr/libexec/l2-loop",
            DeploymentEntryKindV1::Directory,
            0o755,
        ),
        ("usr/lib/systemd", DeploymentEntryKindV1::Directory, 0o755),
        (
            "usr/lib/systemd/system",
            DeploymentEntryKindV1::Directory,
            0o755,
        ),
        ("usr/share", DeploymentEntryKindV1::Directory, 0o755),
        ("usr/share/doc", DeploymentEntryKindV1::Directory, 0o755),
        (
            "usr/share/doc/l2-loop",
            DeploymentEntryKindV1::Directory,
            0o755,
        ),
        ("etc", DeploymentEntryKindV1::Directory, 0o755),
        ("etc/l2-loop", DeploymentEntryKindV1::Directory, 0o700),
        ("var", DeploymentEntryKindV1::Directory, 0o755),
        ("var/lib", DeploymentEntryKindV1::Directory, 0o755),
        ("var/lib/l2-loop", DeploymentEntryKindV1::Directory, 0o700),
        (
            "var/lib/l2-loop/gates",
            DeploymentEntryKindV1::Directory,
            0o700,
        ),
        (
            "var/lib/l2-loop/evidence",
            DeploymentEntryKindV1::Directory,
            0o700,
        ),
        (
            "var/lib/l2-loop/evidence/v1",
            DeploymentEntryKindV1::Directory,
            0o700,
        ),
        ("run", DeploymentEntryKindV1::Directory, 0o755),
        ("run/l2-loop", DeploymentEntryKindV1::Directory, 0o700),
        ("usr/bin/l2-loopctl", DeploymentEntryKindV1::Regular, 0o755),
        (
            "usr/libexec/l2-loop/l2-loopd",
            DeploymentEntryKindV1::Regular,
            0o755,
        ),
        (
            "usr/libexec/l2-loop/l2-loop-deploycheck",
            DeploymentEntryKindV1::Regular,
            0o755,
        ),
        (
            "usr/libexec/l2-loop/l2-loop-install",
            DeploymentEntryKindV1::Regular,
            0o755,
        ),
        (
            "usr/libexec/l2-loop/l2-loop-hostcheck",
            DeploymentEntryKindV1::Regular,
            0o755,
        ),
        (
            "usr/libexec/l2-loop/l2-loop-ebpf.o",
            DeploymentEntryKindV1::Regular,
            0o644,
        ),
        (
            "usr/libexec/l2-loop/manifest.json",
            DeploymentEntryKindV1::Regular,
            0o644,
        ),
        (
            "usr/libexec/l2-loop/SHA256SUMS",
            DeploymentEntryKindV1::Regular,
            0o644,
        ),
        (
            "usr/lib/systemd/system/l2-loop.service",
            DeploymentEntryKindV1::Regular,
            0o644,
        ),
        (
            "usr/share/doc/l2-loop/deployment-v1.example.json",
            DeploymentEntryKindV1::Regular,
            0o644,
        ),
        (
            "etc/l2-loop/deployment-v1.json",
            DeploymentEntryKindV1::Regular,
            0o600,
        ),
        (
            "var/lib/l2-loop/gates/performance-v1.json",
            DeploymentEntryKindV1::Regular,
            0o600,
        ),
    ];
    let entries = definitions
        .into_iter()
        .enumerate()
        .map(
            |(index, (relative, kind, mode))| DeploymentEntrySnapshotV1 {
                relative_path: relative.to_owned(),
                canonical_path: if relative == "." {
                    root.clone()
                } else {
                    root.join(relative)
                },
                kind,
                mode,
                uid: 0,
                gid: 0,
                device: 1,
                inode: u64::try_from(index + 1).unwrap(),
                hard_links: if kind == DeploymentEntryKindV1::Directory {
                    2
                } else {
                    1
                },
                size: if kind == DeploymentEntryKindV1::Directory {
                    0
                } else {
                    8
                },
            },
        )
        .collect();
    StagedLayoutInputV1 {
        logical_root: root,
        artifact: artifact(),
        entries,
        runtime_entries: Vec::new(),
    }
}

fn entry_mut<'a>(
    input: &'a mut StagedLayoutInputV1,
    relative: &str,
) -> &'a mut DeploymentEntrySnapshotV1 {
    input
        .entries
        .iter_mut()
        .find(|entry| entry.relative_path == relative)
        .unwrap()
}

fn mutate_owner(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/bin/l2-loopctl").uid = 1000;
}

fn mutate_mode(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "etc/l2-loop/deployment-v1.json").mode = 0o644;
}

fn mutate_type_symlink(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").kind = DeploymentEntryKindV1::Symlink;
}

fn mutate_type_fifo(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").kind = DeploymentEntryKindV1::Fifo;
}

fn mutate_type_device(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").kind = DeploymentEntryKindV1::Device;
}

fn mutate_type_socket(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").kind = DeploymentEntryKindV1::Socket;
}

fn mutate_type_other(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").kind = DeploymentEntryKindV1::Other;
}

fn mutate_hard_link(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/bin/l2-loopctl").hard_links = 2;
}

fn mutate_escape(input: &mut StagedLayoutInputV1) {
    entry_mut(input, "usr/libexec/l2-loop/l2-loopd").canonical_path =
        PathBuf::from("/tmp/escaped/l2-loopd");
}

fn mutate_runtime_socket(input: &mut StagedLayoutInputV1) {
    input.runtime_entries.push(DeploymentEntrySnapshotV1 {
        relative_path: "run/l2-loop/agent.sock".to_owned(),
        canonical_path: input.logical_root.join("run/l2-loop/agent.sock"),
        kind: DeploymentEntryKindV1::Socket,
        mode: 0o600,
        uid: 0,
        gid: 0,
        device: 1,
        inode: 999,
        hard_links: 1,
        size: 0,
    });
}

fn mutate_missing(input: &mut StagedLayoutInputV1) {
    input.entries.pop();
}

fn mutate_extra(input: &mut StagedLayoutInputV1) {
    let mut extra = input.entries.last().unwrap().clone();
    extra.relative_path = "usr/libexec/l2-loop/extra".to_owned();
    extra.canonical_path = input.logical_root.join(&extra.relative_path);
    input.entries.push(extra);
}
