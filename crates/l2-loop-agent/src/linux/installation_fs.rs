use std::{
    ffi::{CString, OsStr},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};

use l2_loop_core::{
    InstallJournalEntryV1, InstallJournalV1, InstallObjectIdentityV1, InstallObjectKindV1,
    InstallPriorStateV1, InstallRoleV1,
};
use sha2::{Digest, Sha256};

use crate::{
    InstallFaultInjector, InstallFaultPointV1, InstallIoError, InstallLayoutV1,
    InstallRootDirectory,
};

const COPY_BUFFER_BYTES: usize = 16 * 1024;
const MAX_INSTALL_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const JOURNAL_BASENAME: &str = "journal-v1.json";
const JOURNAL_SIBLING_BASENAME: &str = ".journal-v1.json.new";
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const UNSUPPORTED_FILE_FLAGS: nix::libc::c_long = 0x10 | 0x20;

#[derive(Debug, Default, Clone, Copy)]
pub struct NoInstallFaults;

impl InstallFaultInjector for NoInstallFaults {
    fn check(&mut self, _point: InstallFaultPointV1) -> Result<(), InstallIoError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FixedInstallRoot;

impl InstallRootDirectory for FixedInstallRoot {
    fn open_root(&self) -> Result<File, InstallIoError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open("/")
            .map_err(unavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallApplyOutcomeV1 {
    pub current_identity: InstallObjectIdentityV1,
    pub created_parent_identity: Option<InstallObjectIdentityV1>,
}

pub struct LinuxInstallationFilesystem<R, F> {
    root: R,
    faults: F,
}

impl LinuxInstallationFilesystem<FixedInstallRoot, NoInstallFaults> {
    pub const fn production() -> Self {
        Self {
            root: FixedInstallRoot,
            faults: NoInstallFaults,
        }
    }
}

impl<R, F> LinuxInstallationFilesystem<R, F>
where
    R: InstallRootDirectory,
    F: InstallFaultInjector,
{
    pub const fn new(root: R, faults: F) -> Self {
        Self { root, faults }
    }

    pub fn inspect_exact(
        &mut self,
        role: InstallRoleV1,
    ) -> Result<InstallObjectIdentityV1, InstallIoError> {
        ensure_selinux_is_not_enforcing()?;
        let parent = self.open_role_parent(role)?;
        let basename = role_basename(role)?;
        let file = openat_existing(parent.as_raw_fd(), basename)?;
        inspect_open_file(&file)
    }

    pub fn apply_entry(
        &mut self,
        entry: &InstallJournalEntryV1,
        payload: Option<&mut dyn Read>,
    ) -> Result<InstallApplyOutcomeV1, InstallIoError> {
        ensure_selinux_is_not_enforcing()?;
        match entry.intended_identity().kind() {
            InstallObjectKindV1::Directory => self.apply_directory(entry, payload),
            InstallObjectKindV1::RegularFile => self.apply_file(entry, payload),
        }
    }

    pub fn verify_exact(
        &mut self,
        role: InstallRoleV1,
        expected: &InstallObjectIdentityV1,
    ) -> Result<(), InstallIoError> {
        self.faults.check(InstallFaultPointV1::Verify)?;
        let observed = self.inspect_exact(role)?;
        if &observed != expected {
            return Err(InstallIoError::IdentityChanged);
        }
        Ok(())
    }

    pub fn rollback_remove_exact(
        &mut self,
        role: InstallRoleV1,
        expected: &InstallObjectIdentityV1,
    ) -> Result<(), InstallIoError> {
        self.faults.check(InstallFaultPointV1::Rollback)?;
        let observed = self.inspect_exact(role)?;
        if &observed != expected {
            return Err(InstallIoError::IdentityChanged);
        }
        let parent = self.open_role_parent(role)?;
        let basename = role_basename(role)?;
        let flags = match expected.kind() {
            InstallObjectKindV1::Directory => nix::libc::AT_REMOVEDIR,
            InstallObjectKindV1::RegularFile => 0,
        };
        unlinkat_name(parent.as_raw_fd(), basename, flags)?;
        sync_directory(&mut self.faults, &parent)
    }

    pub fn rollback_restore_exact(
        &mut self,
        role: InstallRoleV1,
        expected_current: &InstallObjectIdentityV1,
        backup_basename: &str,
        expected_backup: &InstallObjectIdentityV1,
    ) -> Result<(), InstallIoError> {
        self.faults.check(InstallFaultPointV1::Rollback)?;
        ensure_safe_basename(backup_basename)?;
        let parent = self.open_role_parent(role)?;
        let destination = role_basename(role)?;
        let current = inspect_at(&parent, destination)?;
        let backup = inspect_at(&parent, backup_basename)?;
        if &current != expected_current || &backup != expected_backup {
            return Err(InstallIoError::IdentityChanged);
        }
        renameat_name(
            parent.as_raw_fd(),
            backup_basename,
            parent.as_raw_fd(),
            destination,
        )?;
        sync_directory(&mut self.faults, &parent)?;
        let restored = inspect_at(&parent, destination)?;
        if &restored != expected_backup {
            return Err(InstallIoError::IdentityChanged);
        }
        Ok(())
    }

    pub fn bootstrap_journal(&mut self, journal: &InstallJournalV1) -> Result<(), InstallIoError> {
        ensure_selinux_is_not_enforcing()?;
        let var_lib = self.open_static_directory("/var/lib")?;
        let bootstrap = bootstrap_basename(journal.transaction_id())?;
        if entry_exists_at(var_lib.as_raw_fd(), &bootstrap)? {
            return Err(InstallIoError::UnsafeObject);
        }
        if let Some(final_parent) = self
            .open_static_directory_optional(InstallRoleV1::TransactionsRoot.fixed_destination())?
            && entry_exists_at(final_parent.as_raw_fd(), journal.transaction_id())?
        {
            return Err(InstallIoError::UnsafeObject);
        }
        self.faults.check(InstallFaultPointV1::DirectoryCreate)?;
        mkdirat_name(var_lib.as_raw_fd(), &bootstrap, 0o700)?;
        let directory = openat_directory(var_lib.as_raw_fd(), &bootstrap)?;
        set_owner_mode(&mut self.faults, &directory, 0, 0, 0o700)?;
        write_new_journal(&mut self.faults, &directory, journal, JOURNAL_BASENAME)?;
        sync_journal_directory(&mut self.faults, &directory)?;
        sync_journal_directory(&mut self.faults, &var_lib)
    }

    pub fn publish_journal(&mut self, journal: &InstallJournalV1) -> Result<(), InstallIoError> {
        let var_lib = self.open_static_directory("/var/lib")?;
        let final_parent =
            self.open_static_directory(InstallRoleV1::TransactionsRoot.fixed_destination())?;
        let bootstrap = bootstrap_basename(journal.transaction_id())?;
        let bootstrap_directory = openat_directory(var_lib.as_raw_fd(), &bootstrap)?;
        validate_directory(&bootstrap_directory, 0o700)?;
        validate_journal_file(&bootstrap_directory, journal)?;
        if entry_exists_at(final_parent.as_raw_fd(), journal.transaction_id())? {
            return Err(InstallIoError::UnsafeObject);
        }

        self.faults.check(InstallFaultPointV1::JournalMove)?;
        renameat_name(
            var_lib.as_raw_fd(),
            &bootstrap,
            final_parent.as_raw_fd(),
            journal.transaction_id(),
        )?;
        sync_journal_directory(&mut self.faults, &var_lib)?;
        sync_journal_directory(&mut self.faults, &final_parent)
    }

    pub fn persist_journal(&mut self, journal: &InstallJournalV1) -> Result<(), InstallIoError> {
        let directory = self.open_transaction_directory(journal.transaction_id())?;
        validate_existing_journal_binding(&directory, journal.transaction_id())?;
        if entry_exists_at(directory.as_raw_fd(), JOURNAL_SIBLING_BASENAME)? {
            return Err(InstallIoError::UnsafeObject);
        }
        write_new_journal(
            &mut self.faults,
            &directory,
            journal,
            JOURNAL_SIBLING_BASENAME,
        )?;
        renameat_name(
            directory.as_raw_fd(),
            JOURNAL_SIBLING_BASENAME,
            directory.as_raw_fd(),
            JOURNAL_BASENAME,
        )?;
        sync_journal_directory(&mut self.faults, &directory)?;
        validate_journal_file(&directory, journal)
    }

    fn apply_directory(
        &mut self,
        entry: &InstallJournalEntryV1,
        payload: Option<&mut dyn Read>,
    ) -> Result<InstallApplyOutcomeV1, InstallIoError> {
        if payload.is_some() || entry.prior_state() != &InstallPriorStateV1::Absent {
            return Err(InstallIoError::UnsafeObject);
        }
        let parent = self.open_role_parent(entry.role())?;
        let basename = role_basename(entry.role())?;
        if entry_exists_at(parent.as_raw_fd(), basename)? {
            return Err(InstallIoError::UnsafeObject);
        }
        self.faults.check(InstallFaultPointV1::DirectoryCreate)?;
        mkdirat_name(
            parent.as_raw_fd(),
            basename,
            entry.intended_identity().mode(),
        )?;
        let directory = openat_directory(parent.as_raw_fd(), basename)?;
        let result = (|| {
            set_owner_mode(
                &mut self.faults,
                &directory,
                entry.intended_identity().uid(),
                entry.intended_identity().gid(),
                entry.intended_identity().mode(),
            )?;
            validate_directory(&directory, entry.intended_identity().mode())?;
            sync_directory(&mut self.faults, &parent)?;
            let identity = inspect_open_file(&directory)?;
            Ok(InstallApplyOutcomeV1 {
                current_identity: identity,
                created_parent_identity: None,
            })
        })();
        if result.is_err() {
            let _ = unlinkat_name(parent.as_raw_fd(), basename, nix::libc::AT_REMOVEDIR);
            let _ = parent.sync_all();
        }
        result
    }

    fn apply_file(
        &mut self,
        entry: &InstallJournalEntryV1,
        payload: Option<&mut dyn Read>,
    ) -> Result<InstallApplyOutcomeV1, InstallIoError> {
        let mut payload = payload.ok_or(InstallIoError::Unavailable)?;
        let parent = self.open_role_parent(entry.role())?;
        let destination = role_basename(entry.role())?;
        let sibling = entry
            .sibling_basename()
            .ok_or(InstallIoError::UnsafeObject)?;
        ensure_safe_basename(sibling)?;

        let prior = match entry.prior_state() {
            InstallPriorStateV1::Absent => {
                if entry_exists_at(parent.as_raw_fd(), destination)? {
                    return Err(InstallIoError::UnsafeObject);
                }
                None
            }
            InstallPriorStateV1::PriorOwned {
                identity,
                backup_basename,
            } => {
                ensure_safe_basename(backup_basename)?;
                if entry_exists_at(parent.as_raw_fd(), backup_basename)?
                    || inspect_at(&parent, destination)? != *identity
                {
                    return Err(InstallIoError::IdentityChanged);
                }
                Some((identity.clone(), backup_basename.as_str()))
            }
        };
        if entry_exists_at(parent.as_raw_fd(), sibling)? {
            return Err(InstallIoError::UnsafeObject);
        }

        self.faults.check(InstallFaultPointV1::SiblingCreate)?;
        let mut temporary = createat_file(parent.as_raw_fd(), sibling, 0o600)?;
        let mut backup_moved = false;
        let mut final_moved = false;
        let result = (|| {
            self.faults.check(InstallFaultPointV1::PayloadWrite)?;
            copy_bounded(&mut payload, &mut temporary)?;
            set_owner_mode(
                &mut self.faults,
                &temporary,
                entry.intended_identity().uid(),
                entry.intended_identity().gid(),
                entry.intended_identity().mode(),
            )?;
            self.faults.check(InstallFaultPointV1::Hash)?;
            let temporary_identity = inspect_open_file(&temporary)?;
            if !matches_intended(&temporary_identity, entry.intended_identity()) {
                return Err(InstallIoError::IdentityChanged);
            }
            self.faults.check(InstallFaultPointV1::FileSync)?;
            temporary.sync_all().map_err(unavailable)?;
            sync_directory(&mut self.faults, &parent)?;

            if let Some((_, backup_basename)) = prior.as_ref() {
                self.faults.check(InstallFaultPointV1::BackupRename)?;
                renameat_name(
                    parent.as_raw_fd(),
                    destination,
                    parent.as_raw_fd(),
                    backup_basename,
                )?;
                backup_moved = true;
                sync_directory(&mut self.faults, &parent)?;
            }

            self.faults.check(InstallFaultPointV1::FinalRename)?;
            renameat_name(parent.as_raw_fd(), sibling, parent.as_raw_fd(), destination)?;
            final_moved = true;
            sync_directory(&mut self.faults, &parent)?;
            let current = inspect_at(&parent, destination)?;
            if !matches_intended(&current, entry.intended_identity()) {
                return Err(InstallIoError::IdentityChanged);
            }
            Ok(InstallApplyOutcomeV1 {
                current_identity: current,
                created_parent_identity: None,
            })
        })();

        if result.is_err() {
            if final_moved {
                let _ = unlinkat_name(parent.as_raw_fd(), destination, 0);
            } else {
                let _ = unlinkat_name(parent.as_raw_fd(), sibling, 0);
            }
            if backup_moved
                && let Some((expected_prior, backup_basename)) = prior.as_ref()
                && inspect_at(&parent, backup_basename).as_ref() == Ok(expected_prior)
                && !entry_exists_at(parent.as_raw_fd(), destination).unwrap_or(true)
            {
                let _ = renameat_name(
                    parent.as_raw_fd(),
                    backup_basename,
                    parent.as_raw_fd(),
                    destination,
                );
            }
            let _ = parent.sync_all();
        }
        result
    }

    fn open_role_parent(&self, role: InstallRoleV1) -> Result<File, InstallIoError> {
        let path = Path::new(role.fixed_destination());
        let parent = path.parent().ok_or(InstallIoError::UnsafeObject)?;
        self.open_static_directory(path_string(parent)?)
    }

    fn open_static_directory(&self, absolute: &str) -> Result<File, InstallIoError> {
        self.open_static_directory_optional(absolute)?
            .ok_or(InstallIoError::Unavailable)
    }

    fn open_static_directory_optional(
        &self,
        absolute: &str,
    ) -> Result<Option<File>, InstallIoError> {
        if !absolute.starts_with('/') {
            return Err(InstallIoError::UnsafeObject);
        }
        let mut current = self.root.open_root()?;
        let mut prefix = String::new();
        for component in absolute
            .split('/')
            .filter(|component| !component.is_empty())
        {
            ensure_safe_basename(component)?;
            let Some(next) = openat_directory_optional(current.as_raw_fd(), component)? else {
                return Ok(None);
            };
            prefix.push('/');
            prefix.push_str(component);
            let expected_mode = InstallLayoutV1::entries()
                .iter()
                .find(|entry| entry.destination == prefix)
                .map(|entry| entry.mode)
                .ok_or(InstallIoError::UnsafeObject)?;
            validate_directory(&next, expected_mode)?;
            current = next;
        }
        Ok(Some(current))
    }

    fn open_transaction_directory(&self, transaction_id: &str) -> Result<File, InstallIoError> {
        ensure_transaction_id(transaction_id)?;
        let var_lib = self.open_static_directory("/var/lib")?;
        let bootstrap = bootstrap_basename(transaction_id)?;
        if entry_exists_at(var_lib.as_raw_fd(), &bootstrap)? {
            let directory = openat_directory(var_lib.as_raw_fd(), &bootstrap)?;
            validate_directory(&directory, 0o700)?;
            return Ok(directory);
        }

        let final_parent = self
            .open_static_directory_optional(InstallRoleV1::TransactionsRoot.fixed_destination())?
            .ok_or(InstallIoError::Unavailable)?;
        if !entry_exists_at(final_parent.as_raw_fd(), transaction_id)? {
            return Err(InstallIoError::Unavailable);
        }
        let directory = openat_directory(final_parent.as_raw_fd(), transaction_id)?;
        validate_directory(&directory, 0o700)?;
        Ok(directory)
    }
}

fn role_basename(role: InstallRoleV1) -> Result<&'static str, InstallIoError> {
    Path::new(role.fixed_destination())
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(InstallIoError::UnsafeObject)
}

fn path_string(path: &Path) -> Result<&str, InstallIoError> {
    path.to_str().ok_or(InstallIoError::UnsafeObject)
}

fn openat_existing(parent: RawFd, name: &str) -> Result<File, InstallIoError> {
    let name = safe_cstring(name)?;
    let fd = unsafe {
        nix::libc::openat(
            parent,
            name.as_ptr(),
            nix::libc::O_RDONLY
                | nix::libc::O_NONBLOCK
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC,
        )
    };
    file_from_fd(fd)
}

fn openat_directory(parent: RawFd, name: &str) -> Result<File, InstallIoError> {
    openat_directory_optional(parent, name)?.ok_or(InstallIoError::Unavailable)
}

fn openat_directory_optional(parent: RawFd, name: &str) -> Result<Option<File>, InstallIoError> {
    let name = safe_cstring(name)?;
    let fd = unsafe {
        nix::libc::openat(
            parent,
            name.as_ptr(),
            nix::libc::O_RDONLY
                | nix::libc::O_DIRECTORY
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(nix::libc::ENOENT) => Ok(None),
        Some(nix::libc::ELOOP | nix::libc::ENOTDIR) => Err(InstallIoError::UnsafeObject),
        _ => Err(InstallIoError::Unavailable),
    }
}

fn createat_file(parent: RawFd, name: &str, mode: u32) -> Result<File, InstallIoError> {
    let name = safe_cstring(name)?;
    let fd = unsafe {
        nix::libc::openat(
            parent,
            name.as_ptr(),
            nix::libc::O_RDWR
                | nix::libc::O_CREAT
                | nix::libc::O_EXCL
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC,
            mode,
        )
    };
    file_from_fd(fd)
}

fn file_from_fd(fd: RawFd) -> Result<File, InstallIoError> {
    if fd < 0 {
        return Err(InstallIoError::Unavailable);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdirat_name(parent: RawFd, name: &str, mode: u32) -> Result<(), InstallIoError> {
    let name = safe_cstring(name)?;
    if unsafe { nix::libc::mkdirat(parent, name.as_ptr(), mode) } != 0 {
        return Err(InstallIoError::Unavailable);
    }
    Ok(())
}

fn renameat_name(
    old_parent: RawFd,
    old_name: &str,
    new_parent: RawFd,
    new_name: &str,
) -> Result<(), InstallIoError> {
    let old_name = safe_cstring(old_name)?;
    let new_name = safe_cstring(new_name)?;
    if unsafe { nix::libc::renameat(old_parent, old_name.as_ptr(), new_parent, new_name.as_ptr()) }
        != 0
    {
        return Err(InstallIoError::Unavailable);
    }
    Ok(())
}

fn unlinkat_name(parent: RawFd, name: &str, flags: i32) -> Result<(), InstallIoError> {
    let name = safe_cstring(name)?;
    if unsafe { nix::libc::unlinkat(parent, name.as_ptr(), flags) } != 0 {
        return Err(InstallIoError::Unavailable);
    }
    Ok(())
}

fn entry_exists_at(parent: RawFd, name: &str) -> Result<bool, InstallIoError> {
    let name = safe_cstring(name)?;
    let mut metadata = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
    let result = unsafe {
        nix::libc::fstatat(
            parent,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            nix::libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(nix::libc::ENOENT) => Ok(false),
        _ => Err(InstallIoError::Unavailable),
    }
}

fn inspect_at(parent: &File, name: &str) -> Result<InstallObjectIdentityV1, InstallIoError> {
    inspect_open_file(&openat_existing(parent.as_raw_fd(), name)?)
}

fn inspect_open_file(file: &File) -> Result<InstallObjectIdentityV1, InstallIoError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = file.metadata().map_err(unavailable)?;
    ensure_supported_metadata(file)?;
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_file() {
        if metadata.nlink() != 1 {
            return Err(InstallIoError::UnsafeObject);
        }
        let digest = hash_open_file(file)?;
        return InstallObjectIdentityV1::regular_file(
            metadata.dev(),
            metadata.ino(),
            metadata.nlink(),
            digest,
            mode,
            metadata.uid(),
            metadata.gid(),
        )
        .map_err(|_| InstallIoError::UnsafeObject);
    }
    if metadata.file_type().is_dir() {
        return InstallObjectIdentityV1::directory(
            metadata.dev(),
            metadata.ino(),
            metadata.nlink(),
            mode,
            metadata.uid(),
            metadata.gid(),
        )
        .map_err(|_| InstallIoError::UnsafeObject);
    }
    if metadata.file_type().is_symlink()
        || metadata.file_type().is_fifo()
        || metadata.file_type().is_socket()
        || metadata.file_type().is_block_device()
        || metadata.file_type().is_char_device()
    {
        return Err(InstallIoError::UnsafeObject);
    }
    Err(InstallIoError::UnsafeObject)
}

fn validate_directory(file: &File, expected_mode: u32) -> Result<(), InstallIoError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(InstallIoError::UnsafeObject);
    }
    ensure_supported_metadata(file)
}

fn ensure_supported_metadata(file: &File) -> Result<(), InstallIoError> {
    let count = unsafe { nix::libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(InstallIoError::Unavailable);
    }
    if count != 0 {
        return Err(InstallIoError::UnsupportedMetadata);
    }
    let mut flags: nix::libc::c_long = 0;
    let result = ioctl_getflags(file.as_raw_fd(), &mut flags);
    if result == 0 && flags & UNSUPPORTED_FILE_FLAGS != 0 {
        return Err(InstallIoError::UnsupportedMetadata);
    }
    if result != 0
        && !matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ENOTTY | nix::libc::EOPNOTSUPP)
        )
    {
        return Err(InstallIoError::Unavailable);
    }
    Ok(())
}

#[cfg(target_env = "musl")]
fn ioctl_getflags(fd: RawFd, flags: &mut nix::libc::c_long) -> nix::libc::c_int {
    unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS as nix::libc::c_int, flags) }
}

#[cfg(not(target_env = "musl"))]
fn ioctl_getflags(fd: RawFd, flags: &mut nix::libc::c_long) -> nix::libc::c_int {
    unsafe { nix::libc::ioctl(fd, nix::libc::c_ulong::from(FS_IOC_GETFLAGS), flags) }
}

fn set_owner_mode<F: InstallFaultInjector>(
    faults: &mut F,
    file: &File,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), InstallIoError> {
    faults.check(InstallFaultPointV1::Ownership)?;
    if unsafe { nix::libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(InstallIoError::Unavailable);
    }
    faults.check(InstallFaultPointV1::Mode)?;
    if unsafe { nix::libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(InstallIoError::Unavailable);
    }
    Ok(())
}

fn copy_bounded(source: &mut dyn Read, destination: &mut File) -> Result<(), InstallIoError> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = source.read(&mut buffer).map_err(unavailable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| InstallIoError::Unavailable)?)
            .ok_or(InstallIoError::Unavailable)?;
        if total > MAX_INSTALL_PAYLOAD_BYTES {
            return Err(InstallIoError::Unavailable);
        }
        destination
            .write_all(&buffer[..count])
            .map_err(unavailable)?;
    }
    Ok(())
}

fn hash_open_file(file: &File) -> Result<String, InstallIoError> {
    let mut file = file.try_clone().map_err(unavailable)?;
    file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer).map_err(unavailable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| InstallIoError::Unavailable)?)
            .ok_or(InstallIoError::Unavailable)?;
        if total > MAX_INSTALL_PAYLOAD_BYTES {
            return Err(InstallIoError::Unavailable);
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn matches_intended(
    observed: &InstallObjectIdentityV1,
    intended: &l2_loop_core::InstallIntendedIdentityV1,
) -> bool {
    observed.kind() == intended.kind()
        && observed.sha256() == intended.sha256()
        && observed.mode() == intended.mode()
        && observed.uid() == intended.uid()
        && observed.gid() == intended.gid()
}

fn sync_directory<F: InstallFaultInjector>(
    faults: &mut F,
    directory: &File,
) -> Result<(), InstallIoError> {
    faults.check(InstallFaultPointV1::DirectorySync)?;
    directory.sync_all().map_err(unavailable)
}

fn sync_journal_directory<F: InstallFaultInjector>(
    faults: &mut F,
    directory: &File,
) -> Result<(), InstallIoError> {
    faults.check(InstallFaultPointV1::JournalSync)?;
    directory.sync_all().map_err(unavailable)
}

fn write_new_journal<F: InstallFaultInjector>(
    faults: &mut F,
    directory: &File,
    journal: &InstallJournalV1,
    basename: &str,
) -> Result<(), InstallIoError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| InstallIoError::Unavailable)?;
    if bytes.len() > 1024 * 1024 {
        return Err(InstallIoError::Unavailable);
    }
    let mut file = createat_file(directory.as_raw_fd(), basename, 0o600)?;
    file.write_all(&bytes).map_err(unavailable)?;
    set_owner_mode(faults, &file, 0, 0, 0o600)?;
    faults.check(InstallFaultPointV1::JournalSync)?;
    file.sync_all().map_err(unavailable)
}

fn validate_journal_file(
    directory: &File,
    expected: &InstallJournalV1,
) -> Result<(), InstallIoError> {
    use std::os::unix::fs::MetadataExt;

    let file = openat_existing(directory.as_raw_fd(), JOURNAL_BASENAME)?;
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 1024 * 1024
    {
        return Err(InstallIoError::UnsafeObject);
    }
    ensure_supported_metadata(&file)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    let decoded: InstallJournalV1 =
        serde_json::from_slice(&bytes).map_err(|_| InstallIoError::UnsafeObject)?;
    if &decoded != expected {
        return Err(InstallIoError::IdentityChanged);
    }
    Ok(())
}

fn validate_existing_journal_binding(
    directory: &File,
    transaction_id: &str,
) -> Result<(), InstallIoError> {
    use std::os::unix::fs::MetadataExt;

    let file = openat_existing(directory.as_raw_fd(), JOURNAL_BASENAME)?;
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 1024 * 1024
    {
        return Err(InstallIoError::UnsafeObject);
    }
    ensure_supported_metadata(&file)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    let decoded: InstallJournalV1 =
        serde_json::from_slice(&bytes).map_err(|_| InstallIoError::UnsafeObject)?;
    if decoded.transaction_id() != transaction_id {
        return Err(InstallIoError::IdentityChanged);
    }
    Ok(())
}

fn bootstrap_basename(transaction_id: &str) -> Result<String, InstallIoError> {
    ensure_transaction_id(transaction_id)?;
    Ok(format!(".l2-loop-install-{transaction_id}"))
}

fn ensure_transaction_id(value: &str) -> Result<(), InstallIoError> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(());
    }
    Err(InstallIoError::UnsafeObject)
}

fn ensure_safe_basename(value: &str) -> Result<(), InstallIoError> {
    if !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.as_bytes().contains(&0)
    {
        return Ok(());
    }
    Err(InstallIoError::UnsafeObject)
}

fn safe_cstring(value: &str) -> Result<CString, InstallIoError> {
    ensure_safe_basename(value)?;
    CString::new(value).map_err(|_| InstallIoError::UnsafeObject)
}

fn ensure_selinux_is_not_enforcing() -> Result<(), InstallIoError> {
    let path = Path::new("/sys/fs/selinux/enforce");
    if !path.exists() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(unavailable)?;
    let mut value = [0_u8; 2];
    let count = file.read(&mut value).map_err(unavailable)?;
    if value[..count].starts_with(b"1") {
        return Err(InstallIoError::UnsupportedMetadata);
    }
    Ok(())
}

fn unavailable(_error: io::Error) -> InstallIoError {
    InstallIoError::Unavailable
}
