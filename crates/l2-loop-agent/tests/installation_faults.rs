#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions},
    io::Cursor,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use l2_loop_agent::{
    InstallFaultInjector, InstallFaultPointV1, InstallIoError, InstallRootDirectory,
    linux::installation_fs::LinuxInstallationFilesystem,
};
use l2_loop_core::{InstallIntendedIdentityV1, InstallJournalEntryV1, InstallRoleV1};
use sha2::{Digest, Sha256};

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
fn backup_rename_and_rollback_faults_never_guess_at_foreign_state() {
    for point in [
        InstallFaultPointV1::BackupRename,
        InstallFaultPointV1::Rollback,
    ] {
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

#[derive(Clone)]
struct FaultRoot {
    path: PathBuf,
}

impl FaultRoot {
    fn new_if_privileged(point: InstallFaultPointV1) -> Option<Self> {
        if unsafe { nix::libc::geteuid() } != 0 {
            return None;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2-loop-install-fault-{}-{point:?}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Self { path };
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
            .open(&self.path)
            .map_err(|_| InstallIoError::Unavailable)
    }
}

impl Drop for FaultRoot {
    fn drop(&mut self) {
        let safe = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("l2-loop-install-fault-"))
            && self.path.parent() == Some(std::env::temp_dir().as_path());
        if safe && self.path.exists() {
            fs::remove_dir_all(&self.path).unwrap();
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
