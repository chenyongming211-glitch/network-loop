#![cfg(target_os = "linux")]

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Cursor,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use l2_loop_agent::{
    InstallFaultInjector, InstallFaultPointV1, InstallIoError, InstallRootDirectory,
    linux::installation_fs::LinuxInstallationFilesystem,
};
use l2_loop_core::{
    DeploymentArtifactIdentityV1, InstallIntendedIdentityV1, InstallJournalBindingsV1,
    InstallJournalEntryV1, InstallJournalV1, InstallRoleV1,
};
use sha2::{Digest, Sha256};

const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn every_file_publication_fault_preserves_the_unrelated_sentinel() {
    for point in [
        InstallFaultPointV1::SiblingCreate,
        InstallFaultPointV1::PayloadWrite,
        InstallFaultPointV1::Ownership,
        InstallFaultPointV1::Mode,
        InstallFaultPointV1::Hash,
        InstallFaultPointV1::FileSync,
        InstallFaultPointV1::FinalRename,
        InstallFaultPointV1::DirectorySync,
    ] {
        if !fault_is_selected(point) {
            continue;
        }
        let Some(root) = FaultRoot::new_if_privileged(point) else {
            return;
        };
        let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), FailOnce::at(point));
        let payload = b"new cli payload";
        let entry = absent_cli_entry(payload);

        assert!(
            filesystem
                .apply_entry(&entry, Some(&mut Cursor::new(payload)))
                .is_err(),
            "{point:?} must fail"
        );
        assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
        assert!(!root.path.join("usr/bin/l2-loopctl").exists());
    }
}

#[test]
fn final_publication_never_replaces_a_foreign_file_created_after_preflight() {
    if !fault_is_selected(InstallFaultPointV1::FinalRename) {
        return;
    }
    let Some(root) = FaultRoot::new_if_privileged(InstallFaultPointV1::FinalRename) else {
        return;
    };
    let destination = root.path.join("usr/bin/l2-loopctl");
    let mut filesystem = LinuxInstallationFilesystem::new(
        root.clone(),
        InsertForeignAtFinalRename::new(destination.clone()),
    );
    let payload = b"owned payload";

    assert!(
        filesystem
            .apply_entry(&absent_cli_entry(payload), Some(&mut Cursor::new(payload)))
            .is_err(),
        "a final no-replace publication must reject the raced destination"
    );
    assert_eq!(fs::read(destination).unwrap(), b"foreign");
    assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
}

#[test]
fn backup_publication_never_replaces_a_foreign_file_created_after_preflight() {
    if !fault_is_selected(InstallFaultPointV1::BackupRename) {
        return;
    }
    let Some(root) = FaultRoot::new_if_privileged(InstallFaultPointV1::BackupRename) else {
        return;
    };
    root.write_file("usr/bin/l2-loopctl", b"prior", 0o755);
    let mut inspector = LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled());
    let prior = inspector.inspect_exact(InstallRoleV1::Cli).unwrap();
    let backup = root.path.join("usr/bin/.l2-loop-cli-backup");
    let mut filesystem = LinuxInstallationFilesystem::new(
        root.clone(),
        InsertForeignAtBackupRename::new(backup.clone()),
    );
    let payload = b"next";
    let entry = InstallJournalEntryV1::prior_owned_file(
        InstallRoleV1::Cli,
        intended_file(payload),
        ".l2-loop-cli-new",
        ".l2-loop-cli-backup",
        prior,
    )
    .unwrap();

    assert!(
        filesystem
            .apply_entry(&entry, Some(&mut Cursor::new(payload)))
            .is_err(),
        "a backup no-replace publication must reject the raced backup name"
    );
    assert_eq!(
        fs::read(root.path.join("usr/bin/l2-loopctl")).unwrap(),
        b"prior"
    );
    assert_eq!(fs::read(backup).unwrap(), b"foreign");
    assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
}

#[test]
fn backup_rename_and_rollback_faults_never_guess_at_foreign_state() {
    for point in [
        InstallFaultPointV1::BackupRename,
        InstallFaultPointV1::Rollback,
    ] {
        if !fault_is_selected(point) {
            continue;
        }
        let Some(root) = FaultRoot::new_if_privileged(point) else {
            return;
        };
        root.write_file("usr/bin/l2-loopctl", b"prior", 0o755);
        let mut inspector = LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled());
        let prior = inspector.inspect_exact(InstallRoleV1::Cli).unwrap();
        let payload = b"next";
        let entry = InstallJournalEntryV1::prior_owned_file(
            InstallRoleV1::Cli,
            intended_file(payload),
            ".l2-loop-cli-new",
            ".l2-loop-cli-backup",
            prior.clone(),
        )
        .unwrap();
        let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), FailOnce::at(point));

        if point == InstallFaultPointV1::BackupRename {
            assert!(
                filesystem
                    .apply_entry(&entry, Some(&mut Cursor::new(payload)))
                    .is_err()
            );
            assert_eq!(
                fs::read(root.path.join("usr/bin/l2-loopctl")).unwrap(),
                b"prior"
            );
        } else {
            let mut writer = LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled());
            let applied = writer
                .apply_entry(&entry, Some(&mut Cursor::new(payload)))
                .unwrap();
            assert!(
                filesystem
                    .rollback_restore_exact(
                        InstallRoleV1::Cli,
                        &applied.current_identity,
                        ".l2-loop-cli-backup",
                        &prior,
                    )
                    .is_err()
            );
            assert_eq!(
                fs::read(root.path.join("usr/bin/l2-loopctl")).unwrap(),
                b"next"
            );
        }
        assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
    }
}

#[test]
fn verify_fault_is_reported_before_identity_is_trusted() {
    if !fault_is_selected(InstallFaultPointV1::Verify) {
        return;
    }
    let Some(root) = FaultRoot::new_if_privileged(InstallFaultPointV1::Verify) else {
        return;
    };
    let payload = b"payload";
    let entry = absent_cli_entry(payload);
    let mut writer = LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled());
    let applied = writer
        .apply_entry(&entry, Some(&mut Cursor::new(payload)))
        .unwrap();
    let mut verifier =
        LinuxInstallationFilesystem::new(root.clone(), FailOnce::at(InstallFaultPointV1::Verify));

    assert!(
        verifier
            .verify_exact(InstallRoleV1::Cli, &applied.current_identity)
            .is_err()
    );
    assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
}

#[test]
fn journal_directory_create_and_sync_faults_preserve_the_unrelated_sentinel() {
    for point in [
        InstallFaultPointV1::DirectoryCreate,
        InstallFaultPointV1::JournalSync,
    ] {
        if !fault_is_selected(point) {
            continue;
        }
        let Some(root) = FaultRoot::new_if_privileged(point) else {
            return;
        };
        root.create_dir("var", 0o755);
        root.create_dir("var/lib", 0o755);
        let mut filesystem = LinuxInstallationFilesystem::new(root.clone(), FailOnce::at(point));

        assert!(filesystem.bootstrap_journal(&prepared_journal()).is_err());
        assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
        assert!(
            !root
                .path
                .join(format!("var/lib/.l2-loop-install-{TRANSACTION_ID}"))
                .is_symlink()
        );
    }
}

#[test]
fn journal_move_fault_retains_only_the_exact_bootstrap_identity() {
    if !fault_is_selected(InstallFaultPointV1::JournalMove) {
        return;
    }
    let Some(root) = FaultRoot::new_if_privileged(InstallFaultPointV1::JournalMove) else {
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
    LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled())
        .bootstrap_journal(&journal)
        .unwrap();
    let mut filesystem = LinuxInstallationFilesystem::new(
        root.clone(),
        FailOnce::at(InstallFaultPointV1::JournalMove),
    );

    assert!(filesystem.publish_journal(&journal).is_err());
    assert!(
        root.path
            .join(format!("var/lib/.l2-loop-install-{TRANSACTION_ID}"))
            .is_dir()
    );
    assert!(
        !root
            .path
            .join(format!(
                "var/lib/l2-loop/install/transactions/{TRANSACTION_ID}"
            ))
            .exists()
    );
    assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
}

#[test]
fn journal_publication_never_replaces_a_foreign_directory_created_after_preflight() {
    if !fault_is_selected(InstallFaultPointV1::JournalMove) {
        return;
    }
    let Some(root) = FaultRoot::new_if_privileged(InstallFaultPointV1::JournalMove) else {
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
    LinuxInstallationFilesystem::new(root.clone(), FailOnce::disabled())
        .bootstrap_journal(&journal)
        .unwrap();
    let destination = root.path.join(format!(
        "var/lib/l2-loop/install/transactions/{TRANSACTION_ID}"
    ));
    let mut filesystem = LinuxInstallationFilesystem::new(
        root.clone(),
        InsertForeignDirectoryAtJournalMove::new(destination.clone()),
    );

    assert!(
        filesystem.publish_journal(&journal).is_err(),
        "a journal no-replace publication must reject the raced directory"
    );
    assert!(destination.is_dir());
    assert!(
        root.path
            .join(format!("var/lib/.l2-loop-install-{TRANSACTION_ID}"))
            .is_dir()
    );
    assert_eq!(fs::read(root.path.join("sentinel")).unwrap(), b"unchanged");
}

#[derive(Debug, Clone, Copy)]
struct FailOnce {
    selected: Option<InstallFaultPointV1>,
    fired: bool,
}

impl FailOnce {
    const fn at(point: InstallFaultPointV1) -> Self {
        Self {
            selected: Some(point),
            fired: false,
        }
    }

    const fn disabled() -> Self {
        Self {
            selected: None,
            fired: false,
        }
    }
}

impl InstallFaultInjector for FailOnce {
    fn check(&mut self, point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        if !self.fired && self.selected == Some(point) {
            self.fired = true;
            return Err(InstallIoError::FaultInjected(point));
        }
        Ok(())
    }
}

struct InsertForeignAtFinalRename {
    destination: PathBuf,
    fired: bool,
}

impl InsertForeignAtFinalRename {
    const fn new(destination: PathBuf) -> Self {
        Self {
            destination,
            fired: false,
        }
    }
}

impl InstallFaultInjector for InsertForeignAtFinalRename {
    fn check(&mut self, point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        if !self.fired && point == InstallFaultPointV1::FinalRename {
            self.fired = true;
            fs::write(&self.destination, b"foreign").map_err(|_| InstallIoError::Unavailable)?;
            fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o755))
                .map_err(|_| InstallIoError::Unavailable)?;
        }
        Ok(())
    }
}

struct InsertForeignAtBackupRename {
    destination: PathBuf,
    fired: bool,
}

impl InsertForeignAtBackupRename {
    const fn new(destination: PathBuf) -> Self {
        Self {
            destination,
            fired: false,
        }
    }
}

impl InstallFaultInjector for InsertForeignAtBackupRename {
    fn check(&mut self, point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        if !self.fired && point == InstallFaultPointV1::BackupRename {
            self.fired = true;
            fs::write(&self.destination, b"foreign").map_err(|_| InstallIoError::Unavailable)?;
            fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o755))
                .map_err(|_| InstallIoError::Unavailable)?;
        }
        Ok(())
    }
}

struct InsertForeignDirectoryAtJournalMove {
    destination: PathBuf,
    fired: bool,
}

impl InsertForeignDirectoryAtJournalMove {
    const fn new(destination: PathBuf) -> Self {
        Self {
            destination,
            fired: false,
        }
    }
}

impl InstallFaultInjector for InsertForeignDirectoryAtJournalMove {
    fn check(&mut self, point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        if !self.fired && point == InstallFaultPointV1::JournalMove {
            self.fired = true;
            fs::create_dir(&self.destination).map_err(|_| InstallIoError::Unavailable)?;
            fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o700))
                .map_err(|_| InstallIoError::Unavailable)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct FaultRoot {
    path: Arc<PathBuf>,
}

impl FaultRoot {
    fn new_if_privileged(point: InstallFaultPointV1) -> Option<Self> {
        if unsafe { nix::libc::geteuid() } != 0 {
            return None;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = env::var_os("L2_LOOP_INSTALL_ACCEPTANCE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        if env::var_os("L2_LOOP_INSTALL_ACCEPTANCE_ROOT").is_some() {
            let metadata = fs::symlink_metadata(&parent).unwrap();
            assert!(parent.is_absolute());
            assert!(metadata.file_type().is_dir());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
            assert_eq!((metadata.uid(), metadata.gid()), (0, 0));
        }
        if let Some(identity) = env::var_os("L2_LOOP_INSTALL_ACCEPTANCE_HOST_IDENTITY") {
            let identity = identity.to_str().unwrap();
            assert_eq!(identity.len(), 64);
            assert!(
                identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            );
        }
        let path = parent.join(format!(
            "l2-loop-install-fault-{}-{}-{}",
            std::process::id(),
            fault_name(point),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Self {
            path: Arc::new(path),
        };
        root.create_dir("usr", 0o755);
        root.create_dir("usr/bin", 0o755);
        root.write_file("sentinel", b"unchanged", 0o600);
        Some(root)
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

impl InstallRootDirectory for FaultRoot {
    fn open_root(&self) -> Result<File, InstallIoError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(self.path.as_path())
            .map_err(|_| InstallIoError::Unavailable)
    }
}

impl Drop for FaultRoot {
    fn drop(&mut self) {
        if Arc::strong_count(&self.path) != 1 {
            return;
        }
        let safe_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("l2-loop-install-fault-"));
        assert!(safe_name);
        for relative in [
            "usr/bin/.l2-loop-cli-new",
            "usr/bin/.l2-loop-cli-backup",
            "usr/bin/l2-loopctl",
            "var/lib/.l2-loop-install-ffeeddccbbaa99887766554433221100/.journal-v1.json.new",
            "var/lib/.l2-loop-install-ffeeddccbbaa99887766554433221100/journal-v1.json",
            "var/lib/l2-loop/install/transactions/ffeeddccbbaa99887766554433221100/.journal-v1.json.new",
            "var/lib/l2-loop/install/transactions/ffeeddccbbaa99887766554433221100/journal-v1.json",
            "sentinel",
        ] {
            let path = self.path.join(relative);
            if path.exists() || path.is_symlink() {
                fs::remove_file(path).unwrap();
            }
        }
        for relative in [
            "var/lib/l2-loop/install/transactions/ffeeddccbbaa99887766554433221100",
            "var/lib/.l2-loop-install-ffeeddccbbaa99887766554433221100",
            "var/lib/l2-loop/install/transactions",
            "var/lib/l2-loop/install",
            "var/lib/l2-loop",
            "var/lib",
            "var",
            "usr/bin",
            "usr",
        ] {
            let path = self.path.join(relative);
            if path.exists() {
                fs::remove_dir(path).unwrap();
            }
        }
        if self.path.exists() {
            fs::remove_dir(self.path.as_path()).unwrap();
        }
    }
}

fn absent_cli_entry(bytes: &[u8]) -> InstallJournalEntryV1 {
    InstallJournalEntryV1::absent_file(InstallRoleV1::Cli, intended_file(bytes), ".l2-loop-cli-new")
        .unwrap()
}

fn intended_file(bytes: &[u8]) -> InstallIntendedIdentityV1 {
    InstallIntendedIdentityV1::regular_file(format!("{:x}", Sha256::digest(bytes)), 0o755, 0, 0)
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

const fn fault_name(point: InstallFaultPointV1) -> &'static str {
    match point {
        InstallFaultPointV1::DirectoryCreate => "directory-create",
        InstallFaultPointV1::SiblingCreate => "sibling-create",
        InstallFaultPointV1::PayloadWrite => "payload-write",
        InstallFaultPointV1::Ownership => "ownership",
        InstallFaultPointV1::Mode => "mode",
        InstallFaultPointV1::Hash => "hash",
        InstallFaultPointV1::FileSync => "file-sync",
        InstallFaultPointV1::BackupRename => "backup-rename",
        InstallFaultPointV1::FinalRename => "final-rename",
        InstallFaultPointV1::DirectorySync => "directory-sync",
        InstallFaultPointV1::JournalSync => "journal-sync",
        InstallFaultPointV1::JournalMove => "journal-move",
        InstallFaultPointV1::Verify => "verify",
        InstallFaultPointV1::Rollback => "rollback",
    }
}

fn fault_is_selected(point: InstallFaultPointV1) -> bool {
    env::var("L2_LOOP_INSTALL_ACCEPTANCE_FAULT")
        .map(|selected| selected == fault_selector(point))
        .unwrap_or(true)
}

const fn fault_selector(point: InstallFaultPointV1) -> &'static str {
    match point {
        InstallFaultPointV1::DirectoryCreate => "DirectoryCreate",
        InstallFaultPointV1::SiblingCreate => "SiblingCreate",
        InstallFaultPointV1::PayloadWrite => "PayloadWrite",
        InstallFaultPointV1::Ownership => "Ownership",
        InstallFaultPointV1::Mode => "Mode",
        InstallFaultPointV1::Hash => "Hash",
        InstallFaultPointV1::FileSync => "FileSync",
        InstallFaultPointV1::BackupRename => "BackupRename",
        InstallFaultPointV1::FinalRename => "FinalRename",
        InstallFaultPointV1::DirectorySync => "DirectorySync",
        InstallFaultPointV1::JournalSync => "JournalSync",
        InstallFaultPointV1::JournalMove => "JournalMove",
        InstallFaultPointV1::Verify => "Verify",
        InstallFaultPointV1::Rollback => "Rollback",
    }
}
