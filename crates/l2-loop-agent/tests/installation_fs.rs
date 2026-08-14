#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions},
    io::Cursor,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use l2_loop_agent::{
    InstallFaultInjector, InstallFaultPointV1, InstallIoError, InstallRootDirectory,
    linux::installation_fs::{LinuxInstallationFilesystem, NoInstallFaults},
};
use l2_loop_core::{
    DeploymentArtifactIdentityV1, InstallIntendedIdentityV1, InstallJournalBindingsV1,
    InstallJournalEntryV1, InstallJournalV1, InstallRoleV1,
};
use sha2::{Digest, Sha256};

const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn absent_file_is_published_from_an_exclusive_sibling_and_verified() {
    let Some(root) = TestRoot::new_if_privileged("absent") else {
        return;
    };
    root.create_dir("usr", 0o755);
    root.create_dir("usr/bin", 0o755);
    let bytes = b"exact cli payload";
    let entry = absent_cli_entry(bytes);
    let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), NoInstallFaults);

    let applied = filesystem
        .apply_entry(&entry, Some(&mut Cursor::new(bytes)))
        .unwrap();
    filesystem
        .verify_exact(InstallRoleV1::Cli, &applied.current_identity)
        .unwrap();

    let destination = root.path.join("usr/bin/l2-loopctl");
    let metadata = fs::symlink_metadata(&destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), bytes);
    assert_eq!(metadata.mode() & 0o7777, 0o755);
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    assert_eq!(metadata.nlink(), 1);
    assert!(!root.path.join("usr/bin/.l2-loop-cli-new").exists());
}

#[test]
fn exact_prior_owned_upgrade_keeps_a_verified_backup_and_rolls_back_exactly() {
    let Some(root) = TestRoot::new_if_privileged("upgrade") else {
        return;
    };
    root.create_dir("usr", 0o755);
    root.create_dir("usr/bin", 0o755);
    root.write_file("usr/bin/l2-loopctl", b"prior cli payload", 0o755);
    let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), NoInstallFaults);
    let prior = filesystem.inspect_exact(InstallRoleV1::Cli).unwrap();
    let next = b"next cli payload";
    let entry = InstallJournalEntryV1::prior_owned_file(
        InstallRoleV1::Cli,
        intended_file(next, 0o755),
        ".l2-loop-cli-new",
        ".l2-loop-cli-backup",
        prior.clone(),
    )
    .unwrap();

    let applied = filesystem
        .apply_entry(&entry, Some(&mut Cursor::new(next)))
        .unwrap();
    assert_eq!(
        fs::read(root.path.join("usr/bin/l2-loopctl")).unwrap(),
        next
    );
    assert_eq!(
        fs::read(root.path.join("usr/bin/.l2-loop-cli-backup")).unwrap(),
        b"prior cli payload"
    );

    filesystem
        .rollback_restore_exact(
            InstallRoleV1::Cli,
            &applied.current_identity,
            ".l2-loop-cli-backup",
            &prior,
        )
        .unwrap();
    assert_eq!(
        fs::read(root.path.join("usr/bin/l2-loopctl")).unwrap(),
        b"prior cli payload"
    );
    assert!(!root.path.join("usr/bin/.l2-loop-cli-backup").exists());
}

#[test]
fn foreign_linked_and_special_destinations_fail_closed_without_mutation() {
    let Some(root) = TestRoot::new_if_privileged("unsafe") else {
        return;
    };
    root.create_dir("usr", 0o755);
    root.create_dir("usr/bin", 0o755);
    let destination = root.path.join("usr/bin/l2-loopctl");
    fs::write(&destination, b"foreign").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    let linked = root.path.join("usr/bin/foreign-link");
    fs::hard_link(&destination, &linked).unwrap();
    let entry = absent_cli_entry(b"replacement");
    let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), NoInstallFaults);

    assert!(
        filesystem
            .apply_entry(&entry, Some(&mut Cursor::new(b"replacement")))
            .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"foreign");
    assert_eq!(fs::read(&linked).unwrap(), b"foreign");

    fs::remove_file(&linked).unwrap();
    fs::remove_file(&destination).unwrap();
    std::os::unix::fs::symlink("foreign-link", &destination).unwrap();
    assert!(filesystem.inspect_exact(InstallRoleV1::Cli).is_err());
    fs::remove_file(&destination).unwrap();

    let fifo = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { nix::libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(filesystem.inspect_exact(InstallRoleV1::Cli).is_err());
}

#[test]
fn nonempty_created_directory_and_unsupported_xattr_are_never_removed() {
    let Some(root) = TestRoot::new_if_privileged("metadata") else {
        return;
    };
    root.create_dir("etc", 0o755);
    let entry = InstallJournalEntryV1::absent_directory(
        InstallRoleV1::ConfigRoot,
        InstallIntendedIdentityV1::directory(0o700, 0, 0).unwrap(),
    )
    .unwrap();
    let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), NoInstallFaults);
    let applied = filesystem.apply_entry(&entry, None).unwrap();
    root.write_file("etc/l2-loop/foreign", b"keep", 0o600);

    assert!(
        filesystem
            .rollback_remove_exact(InstallRoleV1::ConfigRoot, &applied.current_identity)
            .is_err()
    );
    assert_eq!(
        fs::read(root.path.join("etc/l2-loop/foreign")).unwrap(),
        b"keep"
    );

    root.write_file("usr-placeholder", b"metadata", 0o600);
    let xattr_path = root.path.join("usr-placeholder");
    set_user_xattr(&xattr_path);
    assert!(filesystem.inspect_path_exact(&xattr_path).is_err());
}

#[test]
fn bootstrap_journal_moves_once_to_the_fixed_transaction_directory() {
    let Some(root) = TestRoot::new_if_privileged("journal") else {
        return;
    };
    for (path, mode) in [
        ("var", 0o755),
        ("var/lib", 0o755),
        ("var/lib/l2-loop", 0o700),
        ("var/lib/l2-loop/install", 0o700),
        ("var/lib/l2-loop/install/transactions", 0o700),
    ] {
        root.create_dir(path, mode);
    }
    let journal = prepared_journal();
    let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), NoInstallFaults);

    filesystem.bootstrap_journal(&journal).unwrap();
    let bootstrap = root
        .path
        .join(format!("var/lib/.l2-loop-install-{TRANSACTION_ID}"));
    assert!(bootstrap.join("journal-v1.json").is_file());
    filesystem.publish_journal(&journal).unwrap();

    assert!(!bootstrap.exists());
    let final_root = root.path.join(format!(
        "var/lib/l2-loop/install/transactions/{TRANSACTION_ID}"
    ));
    let decoded: InstallJournalV1 =
        serde_json::from_slice(&fs::read(final_root.join("journal-v1.json")).unwrap()).unwrap();
    assert_eq!(decoded, journal);
    assert!(filesystem.publish_journal(&journal).is_err());
}

#[derive(Clone)]
struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new_if_privileged(label: &str) -> Option<Self> {
        if unsafe { nix::libc::geteuid() } != 0 {
            return None;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2-loop-installation-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Some(Self { path })
    }

    fn create_dir(&self, relative: &str, mode: u32) {
        fs::create_dir(self.path.join(relative)).unwrap();
        fs::set_permissions(self.path.join(relative), fs::Permissions::from_mode(mode)).unwrap();
    }

    fn write_file(&self, relative: &str, bytes: &[u8], mode: u32) {
        let path = self.path.join(relative);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

impl InstallRootDirectory for TestRoot {
    fn open_root(&self) -> Result<File, InstallIoError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|_| InstallIoError::Unavailable)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let expected_prefix = format!("l2-loop-installation-{}-", "");
        let safe = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(expected_prefix.trim_end_matches('-')))
            && self.path.parent() == Some(std::env::temp_dir().as_path());
        if safe && self.path.exists() {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}

fn absent_cli_entry(bytes: &[u8]) -> InstallJournalEntryV1 {
    InstallJournalEntryV1::absent_file(
        InstallRoleV1::Cli,
        intended_file(bytes, 0o755),
        ".l2-loop-cli-new",
    )
    .unwrap()
}

fn intended_file(bytes: &[u8], mode: u32) -> InstallIntendedIdentityV1 {
    InstallIntendedIdentityV1::regular_file(format!("{:x}", Sha256::digest(bytes)), mode, 0, 0)
        .unwrap()
}

fn prepared_journal() -> InstallJournalV1 {
    let mut journal = InstallJournalV1::new(
        InstallJournalBindingsV1::new(
            TRANSACTION_ID,
            "00112233445566778899aabbccddeeff",
            "1".repeat(64),
            DeploymentArtifactIdentityV1::new("0123456789abcdef0123456789abcdef01234567", "0.1.0")
                .unwrap(),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
        )
        .unwrap(),
    );
    journal.prepare(vec![absent_cli_entry(b"payload")]).unwrap();
    journal
}

fn set_user_xattr(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = c"user.l2_loop_test";
    let value = b"present";
    assert_eq!(
        unsafe {
            nix::libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        0
    );
}

#[allow(dead_code)]
struct NeverFaults;

impl InstallFaultInjector for NeverFaults {
    fn check(&mut self, _point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        Ok(())
    }
}
