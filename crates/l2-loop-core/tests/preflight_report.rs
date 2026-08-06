use l2_loop_core::{
    AgentCommand, AgentResult, AttachmentState, AttachmentTarget, BondInspection, BondMode,
    BpfInspection, Direction, FindingSeverity, HookRole, InterfaceInspection, InterfaceKind,
    InterfaceName, InterfaceRef, KernelInspection, MemlockInspection, PF_BOND_NO_ACTIVE_SLAVE,
    PF_INTERFACE_MISSING, PF_INTERFACE_UNSUPPORTED, PF_KERNEL_CAPABILITY, PF_LIVE_INTERFACE,
    PF_MEMLOCK_TOO_LOW, PF_PIN_ROOT_FOREIGN, PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN,
    PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN, PinRootState, PreflightDecision, PreflightFinding,
    PreflightReport, TcAttachment,
};
use serde::Serialize;
use serde_json::Value;

#[test]
fn derives_ready_when_findings_are_empty_or_informational() {
    let empty = report(Vec::new());
    assert_eq!(empty.decision, PreflightDecision::Ready);

    let informational = report(vec![PreflightFinding::information(
        "PF_TOPOLOGY_VISIBLE",
        "kernel topology is visible",
    )]);
    assert_eq!(informational.decision, PreflightDecision::Ready);
}

#[test]
fn derives_ready_with_warnings_when_no_blocker_exists() {
    let report = report(vec![
        PreflightFinding::information("PF_INTERFACE_VISIBLE", "interface is visible"),
        PreflightFinding::warning(
            "PF_OVS_DISCOVERY",
            "optional topology lookup was unavailable",
        ),
    ]);

    assert_eq!(report.decision, PreflightDecision::ReadyWithWarnings);
}

#[test]
fn blocker_overrides_warnings_and_findings_have_stable_order() {
    let report = report(vec![
        PreflightFinding::information("PF_Z_INFORMATION", "information"),
        PreflightFinding::blocker(PF_XDP_OCCUPIED, "XDP hook is occupied"),
        PreflightFinding::warning("PF_B_WARNING", "warning"),
        PreflightFinding::blocker(PF_INTERFACE_MISSING, "interface is missing"),
    ]);

    assert_eq!(report.decision, PreflightDecision::Blocked);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| (finding.severity, finding.code.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (FindingSeverity::Blocker, PF_INTERFACE_MISSING),
            (FindingSeverity::Blocker, PF_XDP_OCCUPIED),
            (FindingSeverity::Warning, "PF_B_WARNING"),
            (FindingSeverity::Information, "PF_Z_INFORMATION"),
        ]
    );
}

#[test]
fn every_enum_uses_stable_snake_case_json() {
    assert_json(&PreflightDecision::Ready, r#""ready""#);
    assert_json(
        &PreflightDecision::ReadyWithWarnings,
        r#""ready_with_warnings""#,
    );
    assert_json(&PreflightDecision::Blocked, r#""blocked""#);

    assert_json(&FindingSeverity::Blocker, r#""blocker""#);
    assert_json(&FindingSeverity::Warning, r#""warning""#);
    assert_json(&FindingSeverity::Information, r#""information""#);

    assert_json(&InterfaceKind::Physical, r#""physical""#);
    assert_json(&InterfaceKind::Bond, r#""bond""#);
    assert_json(&InterfaceKind::Veth, r#""veth""#);
    assert_json(&InterfaceKind::Bridge, r#""bridge""#);
    assert_json(&InterfaceKind::OvsInternal, r#""ovs_internal""#);
    assert_json(&InterfaceKind::Tap, r#""tap""#);
    assert_json(&InterfaceKind::Unsupported, r#""unsupported""#);

    assert_json(&BondMode::ActiveBackup, r#""active_backup""#);
    assert_json(&BondMode::Unsupported, r#""unsupported""#);

    assert_json(&PinRootState::Absent, r#""absent""#);
    assert_json(&PinRootState::Empty, r#""empty""#);
    assert_json(&PinRootState::Owned, r#""owned""#);
    assert_json(&PinRootState::Foreign, r#""foreign""#);

    assert_json(&AttachmentState::Empty, r#""empty""#);
    assert_json(
        &AttachmentState::Owned { program_id: 71 },
        r#"{"owned":{"program_id":71}}"#,
    );
    assert_json(
        &AttachmentState::Occupied { program_id: 73 },
        r#"{"occupied":{"program_id":73}}"#,
    );
    assert_json(&AttachmentState::Unknown, r#""unknown""#);
}

#[test]
fn complete_report_and_preflight_protocol_variants_round_trip() {
    let report = report(vec![PreflightFinding::warning(
        "PF_OVS_DISCOVERY",
        "optional topology lookup was unavailable",
    )]);
    let report_json = serde_json::to_vec(&report).unwrap();
    assert_eq!(
        serde_json::from_slice::<PreflightReport>(&report_json).unwrap(),
        report
    );

    let command = AgentCommand::Preflight {
        interface: InterfaceName::new("veth-test").unwrap(),
    };
    let command_json = serde_json::to_value(&command).unwrap();
    assert_eq!(command_json["kind"], "preflight");
    assert_eq!(command_json["interface"], "veth-test");
    assert_eq!(
        serde_json::from_value::<AgentCommand>(command_json).unwrap(),
        command
    );

    let result = AgentResult::Preflight { report };
    let result_json = serde_json::to_value(&result).unwrap();
    assert_eq!(result_json["kind"], "preflight");
    assert_eq!(
        serde_json::from_value::<AgentResult>(result_json).unwrap(),
        result
    );
}

#[test]
fn report_json_omits_prohibited_host_and_packet_identity_fields() {
    let value = serde_json::to_value(report(Vec::new())).unwrap();
    let mut keys = Vec::new();
    collect_keys(&value, &mut keys);

    for prohibited in [
        "ip",
        "mac",
        "hostname",
        "machine_id",
        "routes",
        "packet",
        "customer",
    ] {
        assert!(
            !keys.contains(&prohibited),
            "serialized report exposed prohibited key {prohibited}"
        );
    }
}

#[test]
fn blocker_codes_are_exact_and_complete() {
    assert_eq!(
        [
            PF_INTERFACE_MISSING,
            PF_INTERFACE_UNSUPPORTED,
            PF_BOND_NO_ACTIVE_SLAVE,
            PF_XDP_STATE_UNKNOWN,
            PF_XDP_OCCUPIED,
            PF_TC_STATE_UNKNOWN,
            PF_TC_HANDLE_COLLISION,
            PF_PIN_ROOT_FOREIGN,
            PF_MEMLOCK_TOO_LOW,
            PF_KERNEL_CAPABILITY,
            PF_LIVE_INTERFACE,
        ],
        [
            "PF_INTERFACE_MISSING",
            "PF_INTERFACE_UNSUPPORTED",
            "PF_BOND_NO_ACTIVE_SLAVE",
            "PF_XDP_STATE_UNKNOWN",
            "PF_XDP_OCCUPIED",
            "PF_TC_STATE_UNKNOWN",
            "PF_TC_HANDLE_COLLISION",
            "PF_PIN_ROOT_FOREIGN",
            "PF_MEMLOCK_TOO_LOW",
            "PF_KERNEL_CAPABILITY",
            "PF_LIVE_INTERFACE",
        ]
    );
}

fn report(findings: Vec<PreflightFinding>) -> PreflightReport {
    PreflightReport::new(interface(), kernel(), bpf(), findings)
}

fn interface() -> InterfaceInspection {
    let requested = interface_ref("bond-test", 17);
    InterfaceInspection {
        requested,
        kind: InterfaceKind::Bond,
        admin_up: true,
        oper_up: true,
        master: None,
        bond: Some(BondInspection {
            mode: BondMode::ActiveBackup,
            slaves: vec![interface_ref("veth-peer", 18)],
            active_slave: Some(interface_ref("veth-peer", 18)),
        }),
        proposed_targets: vec![AttachmentTarget {
            interface: interface_ref("veth-peer", 18),
            role: HookRole::ExternalXdpIngress,
        }],
        isolated: false,
        live_shared: true,
    }
}

fn kernel() -> KernelInspection {
    KernelInspection {
        architecture: "x86_64".into(),
        release: "linux-test".into(),
        bpf_syscall: true,
        bpf_jit: true,
        btf_readable: true,
        tc_clsact: true,
    }
}

fn bpf() -> BpfInspection {
    BpfInspection {
        bpffs_mounted: true,
        relevant_objects_enumerable: true,
        pin_root: PinRootState::Absent,
        xdp_native: AttachmentState::Empty,
        xdp_generic: AttachmentState::Empty,
        tc_ingress: vec![TcAttachment {
            direction: Direction::Ingress,
            priority: 49_600,
            handle: 0x4c32_0001,
            program_id: 73,
        }],
        tc_egress: Vec::new(),
        memlock: MemlockInspection {
            soft_bytes: Some(8 * 1024 * 1024),
            hard_bytes: None,
            required_bytes: 1024 * 1024,
            can_raise: true,
        },
    }
}

fn interface_ref(name: &str, ifindex: u32) -> InterfaceRef {
    InterfaceRef {
        name: InterfaceName::new(name).unwrap(),
        ifindex,
    }
}

fn assert_json<T: Serialize>(value: &T, expected: &str) {
    assert_eq!(serde_json::to_string(value).unwrap(), expected);
}

fn collect_keys<'a>(value: &'a Value, keys: &mut Vec<&'a str>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                keys.push(key);
                collect_keys(value, keys);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_keys(value, keys);
            }
        }
        _ => {}
    }
}
