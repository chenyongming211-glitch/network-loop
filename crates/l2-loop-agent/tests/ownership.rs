#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use l2_loop_agent::ownership::{
    JournalPath, OWNERSHIP_SCHEMA_VERSION, OwnedTc, OwnedXdp, OwnershipError, OwnershipFileSystem,
    OwnershipMetadata, OwnershipRecord, OwnershipStore, RunId, StdOwnershipFileSystem, TcHook,
    TcKernelIdentity, TestPinRoot, XdpAttachMode, XdpKernelIdentity,
};
use l2_loop_common::ABI_VERSION;

#[test]
fn run_ids_are_exactly_128_bit_lowercase_hexadecimal() {
    let generated = RunId::from_u128(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
    assert_eq!(generated.as_str(), "0123456789abcdeffedcba9876543210");

    for invalid in [
        "",
        "0123456789abcdeffedcba987654321",
        "0123456789abcdeffedcba98765432100",
        "0123456789ABCDEFFEDCBA9876543210",
        "0123456789abcdeffedcba987654321g",
        "0123456789abcdeffedcba98/6543210",
        "0123456789abcdeffedcba98..543210",
    ] {
        assert!(
            RunId::parse(invalid).is_err(),
            "accepted invalid ID {invalid}"
        );
    }
}

#[test]
fn journal_and_pin_paths_are_derived_from_the_active_run() {
    let temp = TempDir::new("paths");
    let run_id = RunId::parse("0123456789abcdeffedcba9876543210").unwrap();
    let journal_root = temp.path().join("run/l2-loop/tests");
    let test_pin_root = temp.path().join("sys/fs/bpf/l2-loop/test");
    let journal = JournalPath::for_root(&journal_root, run_id.clone()).unwrap();
    let pins = TestPinRoot::for_root(&test_pin_root, run_id).unwrap();

    assert_eq!(
        journal.path(),
        journal_root.join("0123456789abcdeffedcba9876543210.json")
    );
    assert_eq!(
        pins.path(),
        test_pin_root.join("0123456789abcdeffedcba9876543210")
    );
    assert!(
        pins.validate_lexical(&pins.path().join("HOOK_STATS"))
            .is_ok()
    );

    for invalid in [
        pins.path().to_path_buf(),
        pins.path().join(".."),
        pins.path().join("../foreign"),
        test_pin_root.join("foreign-run/map"),
        temp.path().join("sys/fs/bpf/l2-loop/v1/7/map"),
        temp.path().join("foreign/map"),
    ] {
        assert!(
            pins.validate_lexical(&invalid).is_err(),
            "accepted unsafe pin path {}",
            invalid.display()
        );
    }
}

#[test]
fn pin_validation_rejects_symlinks_in_every_component() {
    let temp = TempDir::new("symlink");
    let run_id = RunId::parse("0123456789abcdeffedcba9876543210").unwrap();
    let test_pin_root = temp.path().join("pins");
    let pins = TestPinRoot::for_root(&test_pin_root, run_id).unwrap();
    fs::create_dir_all(pins.path()).unwrap();

    let foreign = temp.path().join("foreign");
    fs::create_dir_all(&foreign).unwrap();
    symlink(&foreign, pins.path().join("redirect")).unwrap();

    let error = pins
        .validate_existing(&StdOwnershipFileSystem, &pins.path().join("redirect/map"))
        .unwrap_err();
    assert!(matches!(error, OwnershipError::Symlink(_)));
}

#[test]
fn journal_round_trip_is_atomic_private_and_identity_checked() {
    let temp = TempDir::new("journal");
    let run_id = RunId::parse("0123456789abcdeffedcba9876543210").unwrap();
    let journal_root = temp.path().join("journals");
    let pin_base = temp.path().join("pins");
    let journal = JournalPath::for_root(&journal_root, run_id.clone()).unwrap();
    let pins = TestPinRoot::for_root(&pin_base, run_id).unwrap();
    fs::create_dir_all(pins.path()).unwrap();
    let map_pin = pins.path().join("HOOK_STATS");
    fs::write(&map_pin, b"fixture").unwrap();

    let filesystem = RecordingFileSystem::default();
    let store = OwnershipStore::new(&filesystem, journal.clone(), pins);
    let record = fixture_record(map_pin);
    store.save(&record).unwrap();

    let loaded = store.load_validated(ABI_VERSION, 17, 41).unwrap();
    assert_eq!(loaded, record);
    assert_eq!(
        fs::symlink_metadata(journal.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!journal.temporary_path().exists());

    let events = filesystem.events();
    assert_eq!(events[0].0, "write_new_sync");
    assert_eq!(events[0].1, journal.temporary_path());
    assert_eq!(events[1].0, "rename_replace");
    assert_eq!(events[1].1, journal.path());
    assert_eq!(events[2].0, "sync_directory");
    assert_eq!(events[2].1, journal_root);

    assert!(matches!(
        store.load_validated(ABI_VERSION + 1, 17, 41),
        Err(OwnershipError::AbiMismatch { .. })
    ));
    assert!(matches!(
        store.load_validated(ABI_VERSION, 18, 41),
        Err(OwnershipError::IdentityMismatch(_))
    ));
    assert!(matches!(
        store.load_validated(ABI_VERSION, 17, 42),
        Err(OwnershipError::IdentityMismatch(_))
    ));
}

#[test]
fn owned_kernel_identities_require_exact_matches() {
    let record = fixture_record(PathBuf::from(
        "/sys/fs/bpf/l2-loop/test/0123456789abcdeffedcba9876543210/HOOK_STATS",
    ));
    let xdp = record.xdp.unwrap();
    let tc = record.tc[0];

    assert!(xdp.matches(&XdpKernelIdentity {
        ifindex: 17,
        mode: XdpAttachMode::Generic,
        program_id: 101,
        program_tag: [1; 8],
        link_id: Some(201),
    }));
    assert!(!xdp.matches(&XdpKernelIdentity {
        program_id: 999,
        ..XdpKernelIdentity::from(xdp)
    }));

    assert!(tc.matches(&TcKernelIdentity {
        ifindex: 17,
        hook: TcHook::Egress,
        priority: 49_600,
        handle: 0x4c32_0002,
        program_id: 102,
    }));
    assert!(!tc.matches(&TcKernelIdentity {
        program_id: 999,
        ..TcKernelIdentity::from(tc)
    }));
}

fn fixture_record(map_pin: PathBuf) -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation: 41,
        ifindex: 17,
        xdp: Some(OwnedXdp {
            ifindex: 17,
            mode: XdpAttachMode::Generic,
            program_id: 101,
            program_tag: [1; 8],
            link_id: Some(201),
        }),
        tc: vec![OwnedTc {
            ifindex: 17,
            hook: TcHook::Egress,
            priority: 49_600,
            handle: 0x4c32_0002,
            program_id: 102,
            created_clsact: true,
        }],
        pin_paths: vec![map_pin],
        created_at_unix_seconds: 1_787_000_000,
    }
}

#[derive(Default)]
struct RecordingFileSystem {
    inner: StdOwnershipFileSystem,
    events: Arc<Mutex<Vec<(&'static str, PathBuf)>>>,
}

impl RecordingFileSystem {
    fn events(&self) -> Vec<(&'static str, PathBuf)> {
        self.events.lock().unwrap().clone()
    }
}

impl OwnershipFileSystem for RecordingFileSystem {
    fn metadata(&self, path: &Path) -> std::io::Result<OwnershipMetadata> {
        self.inner.metadata(path)
    }

    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read(path)
    }

    fn write_new_sync(&self, path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(("write_new_sync", path.to_path_buf()));
        self.inner.write_new_sync(path, contents, mode)
    }

    fn rename_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(("rename_replace", to.to_path_buf()));
        self.inner.rename_replace(from, to)
    }

    fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(("sync_directory", path.to_path_buf()));
        self.inner.sync_directory(path)
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "l2-loop-ownership-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
