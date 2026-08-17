use std::collections::{BTreeMap, BTreeSet};

use l2_loop_agent::{
    BundleFileIdentityV1, BundleSnapshotV1, InstallInputDocumentV1, InstallLayoutEntryKindV1,
    InstallLayoutV1, InstallRoleV1, validate_install_inputs,
};
use l2_loop_core::DeploymentArtifactIdentityV1;

const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const AUTHORIZATION: &[u8] = include_bytes!("fixtures/installation/install-authorization-v1.json");
const DEPLOYMENT_AUTHORIZATION: &[u8] = b"deployment-authorization-v1\n";
const PERFORMANCE_EVIDENCE: &[u8] = b"performance-evidence-v1\n";
const RAW_HOST_IDENTITY: &[u8] = b"stable-host-identity-v1\n";
const BUNDLE_FILES: [(&str, u32); 10] = [
    ("SHA256SUMS", 0o644),
    ("deployment-v1.example.json", 0o644),
    ("l2-loop-deploycheck", 0o755),
    ("l2-loop-ebpf.o", 0o644),
    ("l2-loop-hostcheck", 0o755),
    ("l2-loop-install", 0o755),
    ("l2-loop.service", 0o644),
    ("l2-loopctl", 0o755),
    ("l2-loopd", 0o755),
    ("manifest.json", 0o644),
];

#[test]
fn fixed_layout_has_only_reviewed_absolute_destinations_and_modes() {
    let entries = InstallLayoutV1::entries();
    assert_eq!(entries.len(), 32);
    assert_eq!(entries[0].destination, "/usr");
    assert_eq!(
        entries.last().unwrap().destination,
        "/var/lib/l2-loop/gates/performance-v1.json"
    );

    let mut destinations = BTreeSet::new();
    for entry in entries {
        assert!(entry.destination.starts_with('/'));
        assert!(!entry.destination.contains("/../"));
        assert!(!entry.destination.contains("/./"));
        assert!(destinations.insert(entry.destination));
        match entry.kind {
            InstallLayoutEntryKindV1::Directory => assert!(matches!(entry.mode, 0o700 | 0o755)),
            InstallLayoutEntryKindV1::Regular => {
                assert!(matches!(entry.mode, 0o600 | 0o644 | 0o755))
            }
        }
    }

    for (role, destination, mode) in [
        (InstallRoleV1::Cli, "/usr/bin/l2-loopctl", 0o755),
        (
            InstallRoleV1::Daemon,
            "/usr/libexec/l2-loop/l2-loopd",
            0o755,
        ),
        (
            InstallRoleV1::DeploymentChecker,
            "/usr/libexec/l2-loop/l2-loop-deploycheck",
            0o755,
        ),
        (
            InstallRoleV1::Installer,
            "/usr/libexec/l2-loop/l2-loop-install",
            0o755,
        ),
        (
            InstallRoleV1::HostChecker,
            "/usr/libexec/l2-loop/l2-loop-hostcheck",
            0o755,
        ),
        (
            InstallRoleV1::EbpfObject,
            "/usr/libexec/l2-loop/l2-loop-ebpf.o",
            0o644,
        ),
        (
            InstallRoleV1::BundleManifest,
            "/usr/libexec/l2-loop/manifest.json",
            0o644,
        ),
        (
            InstallRoleV1::BundleChecksums,
            "/usr/libexec/l2-loop/SHA256SUMS",
            0o644,
        ),
        (
            InstallRoleV1::ServiceUnit,
            "/usr/lib/systemd/system/l2-loop.service",
            0o644,
        ),
        (
            InstallRoleV1::AuthorizationExample,
            "/usr/share/doc/l2-loop/deployment-v1.example.json",
            0o644,
        ),
        (
            InstallRoleV1::DeploymentAuthorization,
            "/etc/l2-loop/deployment-v1.json",
            0o600,
        ),
        (
            InstallRoleV1::PerformanceEvidence,
            "/var/lib/l2-loop/gates/performance-v1.json",
            0o600,
        ),
        (
            InstallRoleV1::EvidenceRoot,
            "/var/lib/l2-loop/evidence/v1",
            0o700,
        ),
        (
            InstallRoleV1::TransactionsRoot,
            "/var/lib/l2-loop/install/transactions",
            0o700,
        ),
    ] {
        let entry = InstallLayoutV1::entry(role).unwrap();
        assert_eq!(entry.destination, destination);
        assert_eq!(entry.mode, mode);
    }

    assert!(
        entries
            .iter()
            .all(|entry| entry.destination != "/run/l2-loop")
    );
    assert_eq!(
        InstallLayoutV1::entry(InstallRoleV1::Installer)
            .unwrap()
            .destination,
        "/usr/libexec/l2-loop/l2-loop-install"
    );
}

#[test]
fn validator_binds_exact_bundle_documents_and_hashed_host_identity() {
    let bundle = valid_bundle();
    let authorization = private_document(AUTHORIZATION);
    let deployment = private_document(DEPLOYMENT_AUTHORIZATION);
    let performance = private_document(PERFORMANCE_EVIDENCE);
    let mut host_identity = RAW_HOST_IDENTITY.to_vec();

    let validated = validate_install_inputs(
        &bundle,
        &authorization,
        &deployment,
        &performance,
        &mut host_identity,
    )
    .unwrap();

    assert_eq!(validated.source.artifact, artifact());
    assert_eq!(
        validated.source.authorization.authorization_id,
        "00112233445566778899aabbccddeeff"
    );
    assert_eq!(
        validated.host_identity_sha256,
        "0e7be8257845d4a459a0204f2de5401abb0afa7d92d11deb144e84639c938cb4"
    );
    assert!(host_identity.iter().all(|byte| *byte == 0));
}

#[test]
fn validator_rejects_non_exact_bundle_inventory_metadata_and_identity() {
    for (label, mutate) in [
        ("extra", add_extra as fn(&mut BundleSnapshotV1)),
        ("missing", remove_file),
        ("mode", change_mode),
        ("hard-link", change_links),
        ("duplicate-identity", duplicate_identity),
        ("digest", change_digest),
    ] {
        let mut bundle = valid_bundle();
        mutate(&mut bundle);
        assert_rejected(
            &bundle,
            private_document(AUTHORIZATION),
            RAW_HOST_IDENTITY,
            label,
        );
    }

    let mut bundle = valid_bundle();
    bundle.artifact =
        DeploymentArtifactIdentityV1::new("fedcba9876543210fedcba9876543210fedcba98", "0.1.0")
            .unwrap();
    assert_rejected(
        &bundle,
        private_document(AUTHORIZATION),
        RAW_HOST_IDENTITY,
        "artifact",
    );
}

#[test]
fn validator_rejects_unsafe_private_inputs_and_never_retains_raw_host_identity() {
    for (label, document) in [
        (
            "mode",
            InstallInputDocumentV1::new(AUTHORIZATION.to_vec(), true, 0o644, 0, 0, 1),
        ),
        (
            "owner",
            InstallInputDocumentV1::new(AUTHORIZATION.to_vec(), true, 0o600, 1000, 0, 1),
        ),
        (
            "group",
            InstallInputDocumentV1::new(AUTHORIZATION.to_vec(), true, 0o600, 0, 1000, 1),
        ),
        (
            "link",
            InstallInputDocumentV1::new(AUTHORIZATION.to_vec(), true, 0o600, 0, 0, 2),
        ),
        (
            "special",
            InstallInputDocumentV1::new(AUTHORIZATION.to_vec(), false, 0o600, 0, 0, 1),
        ),
    ] {
        assert_rejected(&valid_bundle(), document, RAW_HOST_IDENTITY, label);
    }

    let oversized = vec![b'x'; 1_048_577];
    assert_rejected(
        &valid_bundle(),
        InstallInputDocumentV1::new(oversized, true, 0o600, 0, 0, 1),
        RAW_HOST_IDENTITY,
        "oversized",
    );

    for raw in [&b""[..], &vec![b'x'; 4097][..]] {
        let mut host_identity = raw.to_vec();
        let result = validate_install_inputs(
            &valid_bundle(),
            &private_document(AUTHORIZATION),
            &private_document(DEPLOYMENT_AUTHORIZATION),
            &private_document(PERFORMANCE_EVIDENCE),
            &mut host_identity,
        );
        assert!(result.is_err());
        assert!(host_identity.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn installation_validation_source_is_bounded_read_only_and_has_no_destination_override() {
    let source = include_str!("../src/installation_layout.rs");
    for required in [
        "O_NOFOLLOW",
        "MAX_INSTALL_DOCUMENT_BYTES",
        "fill(0)",
        "InstallLayoutV1",
    ] {
        assert!(
            source.contains(required),
            "missing safety primitive: {required}"
        );
    }
    for prohibited in [
        "std::env",
        "var_os(",
        "set_var(",
        "create_dir",
        "remove_file",
        "remove_dir",
        "set_permissions",
        "fs::write",
        "File::create",
        ".write(true)",
        "rename(",
        "Command::new",
        "WalkDir",
        "root: PathBuf",
        "destination: PathBuf",
        "prefix: PathBuf",
    ] {
        assert!(
            !source.contains(prohibited),
            "prohibited surface present: {prohibited}"
        );
    }
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn private_document(bytes: &[u8]) -> InstallInputDocumentV1 {
    InstallInputDocumentV1::new(bytes.to_vec(), true, 0o600, 0, 0, 1)
}

fn valid_bundle() -> BundleSnapshotV1 {
    let mut files = BTreeMap::new();
    for (index, (name, mode)) in BUNDLE_FILES.into_iter().enumerate() {
        files.insert(
            name.to_owned(),
            BundleFileIdentityV1 {
                sha256: if name == "manifest.json" {
                    "1".repeat(64)
                } else {
                    format!("{index:064x}")
                },
                size: 16,
                mode,
                uid: 0,
                gid: 0,
                device: 7,
                inode: u64::try_from(index + 1).unwrap(),
                hard_links: 1,
            },
        );
    }
    BundleSnapshotV1::with_files(artifact(), files)
}

fn assert_rejected(
    bundle: &BundleSnapshotV1,
    authorization: InstallInputDocumentV1,
    raw_host_identity: &[u8],
    label: &str,
) {
    let mut host_identity = raw_host_identity.to_vec();
    assert!(
        validate_install_inputs(
            bundle,
            &authorization,
            &private_document(DEPLOYMENT_AUTHORIZATION),
            &private_document(PERFORMANCE_EVIDENCE),
            &mut host_identity,
        )
        .is_err(),
        "accepted unsafe input: {label}"
    );
    assert!(host_identity.iter().all(|byte| *byte == 0));
}

fn add_extra(bundle: &mut BundleSnapshotV1) {
    bundle.files.insert(
        "extra".to_owned(),
        BundleFileIdentityV1 {
            sha256: "a".repeat(64),
            size: 1,
            mode: 0o644,
            uid: 0,
            gid: 0,
            device: 7,
            inode: 99,
            hard_links: 1,
        },
    );
}

fn remove_file(bundle: &mut BundleSnapshotV1) {
    bundle.files.remove("l2-loopd");
}

fn change_mode(bundle: &mut BundleSnapshotV1) {
    bundle.files.get_mut("l2-loopd").unwrap().mode = 0o777;
}

fn change_links(bundle: &mut BundleSnapshotV1) {
    bundle.files.get_mut("l2-loopd").unwrap().hard_links = 2;
}

fn duplicate_identity(bundle: &mut BundleSnapshotV1) {
    let inode = bundle.files["l2-loopctl"].inode;
    bundle.files.get_mut("l2-loopd").unwrap().inode = inode;
}

fn change_digest(bundle: &mut BundleSnapshotV1) {
    bundle.files.get_mut("manifest.json").unwrap().sha256 = "2".repeat(64);
}
