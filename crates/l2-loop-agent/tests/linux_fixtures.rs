#![cfg(target_os = "linux")]

use l2_loop_agent::linux::bond::{BondSnapshotError, parse_bond_snapshot};
use l2_loop_agent::linux::bpf_inventory::{
    BtfSnapshot, ForeignPinSummary, PinRootSnapshot, bpffs_mounted_at_standard_path,
    classify_pin_root, summarize_foreign_top_level_roots,
};
use l2_loop_agent::linux::interface::{
    KernelLinkKind, LinkRecord, TunMode, classify_interface,
};
use l2_loop_agent::linux::limits::{
    artifact_architecture_matches, parse_memlock_limits,
};
use l2_loop_agent::linux::topology::{ovs_vsctl_args, parse_ovs_bridge_name};
use l2_loop_core::{InterfaceKind, InterfaceName, PF_BOND_NO_ACTIVE_SLAVE, PinRootState};

const ACTIVE_BACKUP: &str = include_str!("fixtures/bond/active-backup.txt");
const NO_ACTIVE_SLAVE: &str = include_str!("fixtures/bond/no-active-slave.txt");
const MALFORMED_BOND: &str = include_str!("fixtures/bond/malformed.txt");
const PROC_MOUNTS: &str = include_str!("fixtures/proc/mounts.txt");
const LIMITS_RAISABLE: &str = include_str!("fixtures/proc/limits-raisable.txt");
const LIMITS_BLOCKED: &str = include_str!("fixtures/proc/limits-blocked.txt");

#[test]
fn classifies_supported_and_unsupported_link_records() {
    let cases = [
        (link("enp1s0", 1, None, None, true), InterfaceKind::Physical),
        (
            link("bond0", 2, Some(KernelLinkKind::Bond), None, false),
            InterfaceKind::Bond,
        ),
        (
            link("veth0", 3, Some(KernelLinkKind::Veth), None, false),
            InterfaceKind::Veth,
        ),
        (
            link("br0", 4, Some(KernelLinkKind::Bridge), None, false),
            InterfaceKind::Bridge,
        ),
        (
            link(
                "tap0",
                5,
                Some(KernelLinkKind::Tun),
                Some(TunMode::Tap),
                false,
            ),
            InterfaceKind::Tap,
        ),
        (
            link(
                "ovs0",
                6,
                Some(KernelLinkKind::OpenVSwitch),
                None,
                false,
            ),
            InterfaceKind::OvsInternal,
        ),
        (
            link(
                "tun0",
                7,
                Some(KernelLinkKind::Tun),
                Some(TunMode::Tun),
                false,
            ),
            InterfaceKind::Unsupported,
        ),
        (
            link(
                "dummy0",
                8,
                Some(KernelLinkKind::Other("dummy".to_owned())),
                None,
                false,
            ),
            InterfaceKind::Unsupported,
        ),
    ];

    for (record, expected) in cases {
        assert_eq!(classify_interface(&record), expected, "{}", record.name.as_str());
    }
}

#[test]
fn parses_active_backup_bond_and_preserves_slave_order() {
    let links = [
        link("port-a", 11, None, None, true),
        link("port-b", 12, None, None, true),
    ];

    let bond = parse_bond_snapshot(ACTIVE_BACKUP, &links).expect("valid active-backup bond");

    assert_eq!(
        bond.slaves
            .iter()
            .map(|slave| slave.name.as_str())
            .collect::<Vec<_>>(),
        ["port-a", "port-b"]
    );
    assert_eq!(
        bond.active_slave
            .as_ref()
            .map(|slave| (slave.name.as_str(), slave.ifindex)),
        Some(("port-b", 12))
    );
}

#[test]
fn rejects_malformed_bond_mode() {
    let error = parse_bond_snapshot(MALFORMED_BOND, &[]).expect_err("mode must be strict");

    assert!(matches!(error, BondSnapshotError::UnsupportedMode));
    assert_eq!(error.blocker_code(), None);
}

#[test]
fn missing_or_disappearing_active_bond_slave_has_stable_blocker() {
    let no_active = parse_bond_snapshot(NO_ACTIVE_SLAVE, &[]).expect_err("active slave missing");
    assert_eq!(no_active.blocker_code(), Some(PF_BOND_NO_ACTIVE_SLAVE));

    let partial_links = [link("port-a", 11, None, None, true)];
    let disappeared =
        parse_bond_snapshot(ACTIVE_BACKUP, &partial_links).expect_err("active slave disappeared");
    assert_eq!(
        disappeared.blocker_code(),
        Some(PF_BOND_NO_ACTIVE_SLAVE)
    );
}

#[test]
fn detects_bpffs_only_at_the_standard_exact_mountpoint() {
    assert!(bpffs_mounted_at_standard_path(PROC_MOUNTS));

    let nonstandard = PROC_MOUNTS.replace(" /sys/fs/bpf ", " /srv/bpffs ");
    assert!(!bpffs_mounted_at_standard_path(&nonstandard));
}

#[test]
fn parses_memlock_soft_and_hard_limits_without_losing_unlimited() {
    let raisable = parse_memlock_limits(LIMITS_RAISABLE).expect("raisable limits");
    assert_eq!(raisable.soft_bytes, Some(65_536));
    assert_eq!(raisable.hard_bytes, None);
    assert!(raisable.can_raise_to(8 * 1024 * 1024));

    let blocked = parse_memlock_limits(LIMITS_BLOCKED).expect("blocked limits");
    assert_eq!(blocked.soft_bytes, Some(65_536));
    assert_eq!(blocked.hard_bytes, Some(65_536));
    assert!(!blocked.can_raise_to(8 * 1024 * 1024));
}

#[test]
fn rejects_an_artifact_built_for_another_architecture() {
    assert!(artifact_architecture_matches(
        "x86_64",
        "x86_64-unknown-linux-musl"
    ));
    assert!(!artifact_architecture_matches(
        "aarch64",
        "x86_64-unknown-linux-musl"
    ));
}

#[test]
fn btf_readability_requires_a_readable_regular_file() {
    assert!(BtfSnapshot {
        exists: true,
        regular_file: true,
        readable: true,
    }
    .is_readable());
    assert!(!BtfSnapshot {
        exists: true,
        regular_file: false,
        readable: true,
    }
    .is_readable());
    assert!(!BtfSnapshot {
        exists: false,
        regular_file: false,
        readable: false,
    }
    .is_readable());
}

#[test]
fn classifies_all_pin_root_states() {
    let cases = [
        (PinRootSnapshot::absent(), PinRootState::Absent),
        (PinRootSnapshot::empty(), PinRootState::Empty),
        (PinRootSnapshot::owned(3), PinRootState::Owned),
        (PinRootSnapshot::foreign(2), PinRootState::Foreign),
    ];

    for (snapshot, expected) in cases {
        assert_eq!(classify_pin_root(snapshot), expected);
    }
}

#[test]
fn foreign_pin_roots_are_reduced_to_counts_and_never_retained() {
    let summary = summarize_foreign_top_level_roots(
        ["l2-loop", "unrelated-a", "unrelated-b"],
        "l2-loop",
    );

    assert_eq!(
        summary,
        ForeignPinSummary {
            top_level_root_count: 2,
            has_foreign_roots: true,
        }
    );
    let rendered = format!("{summary:?}");
    assert!(!rendered.contains("unrelated-a"));
    assert!(!rendered.contains("unrelated-b"));
    assert!(!rendered.contains("cleanup"));
}

#[test]
fn ovs_topology_uses_fixed_argv_and_strict_output_parsing() {
    let interface = InterfaceName::new("ovs0").unwrap();

    assert_eq!(
        ovs_vsctl_args(&interface),
        ["--timeout=2", "iface-to-br", "ovs0"]
    );
    assert_eq!(
        parse_ovs_bridge_name(b"br-test\n")
            .expect("single bridge")
            .as_ref()
            .map(InterfaceName::as_str),
        Some("br-test")
    );
    assert_eq!(parse_ovs_bridge_name(b"\n").unwrap(), None);
    assert!(parse_ovs_bridge_name(b"br-a\nbr-b\n").is_err());
    assert!(parse_ovs_bridge_name(&[0xff]).is_err());
}

fn link(
    name: &str,
    ifindex: u32,
    kind: Option<KernelLinkKind>,
    tun_mode: Option<TunMode>,
    driver_present: bool,
) -> LinkRecord {
    LinkRecord {
        name: InterfaceName::new(name).unwrap(),
        ifindex,
        kind,
        tun_mode,
        driver_present,
        master_ifindex: None,
        admin_up: true,
        oper_up: true,
    }
}
