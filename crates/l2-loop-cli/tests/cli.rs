use clap::{CommandFactory, Parser};
use l2_loop_cli::{Cli, ParsedCli};
use l2_loop_core::{AgentCommand, InterfaceName, ProbeScope, TrafficClass};

#[test]
fn parses_text_and_json_preflight_without_putting_format_in_the_command() {
    for (extra, expected_json) in [(&[][..], false), (&["--json"][..], true)] {
        let mut args = vec!["l2-loopctl", "preflight", "--interface", "eth0"];
        args.extend_from_slice(extra);
        let parsed = ParsedCli::try_from(Cli::try_parse_from(args).unwrap()).unwrap();

        assert_eq!(
            parsed.command,
            AgentCommand::Preflight {
                interface: InterfaceName::new("eth0").unwrap(),
            }
        );
        assert_eq!(parsed.json, expected_json);
    }
}

#[test]
fn rejects_missing_or_unsafe_preflight_interfaces() {
    assert!(Cli::try_parse_from(["l2-loopctl", "preflight"]).is_err());

    for interface in ["eth 0", "eth/0", "eth\0x", "1234567890123456"] {
        let cli =
            Cli::try_parse_from(["l2-loopctl", "preflight", "--interface", interface]).unwrap();
        assert!(
            ParsedCli::try_from(cli).is_err(),
            "accepted unsafe interface {interface:?}"
        );
    }
}

#[test]
fn binary_uses_exit_code_two_for_usage_and_local_validation_errors() {
    for args in [vec!["preflight"], vec!["preflight", "--interface", "eth 0"]] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_l2-loopctl"))
            .args(args)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2));
    }
}

#[test]
fn parses_every_canonical_command() {
    for args in [
        vec!["l2-loopctl", "observe", "--interface", "bond0"],
        vec!["l2-loopctl", "status"],
        vec!["l2-loopctl", "status", "--interface", "bond0", "--json"],
        vec![
            "l2-loopctl",
            "probe",
            "--interface",
            "bond0",
            "--scope",
            "external",
            "--vlan",
            "100",
            "--timeout",
            "2s",
        ],
        vec![
            "l2-loopctl",
            "police",
            "apply",
            "--interface",
            "bond0",
            "--class",
            "ipv6-multicast",
            "--pps",
            "1000",
            "--ttl",
            "10m",
        ],
        vec!["l2-loopctl", "police", "disable", "--rule", "rule-1"],
        vec!["l2-loopctl", "evidence", "list", "--json"],
        vec![
            "l2-loopctl",
            "evidence",
            "show",
            "--id",
            "evidence-1",
            "--json",
        ],
    ] {
        Cli::try_parse_from(args).unwrap();
    }
}

#[test]
fn parses_only_explicit_generated_isolated_verification_commands() {
    let attach = ParsedCli::try_from(
        Cli::try_parse_from([
            "l2-loopctl",
            "isolated-attach",
            "--interface",
            "veth-test",
            "--run-id",
            "0123456789abcdef0123456789abcdef",
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        attach.command,
        AgentCommand::IsolatedAttach {
            interface: InterfaceName::new("veth-test").unwrap(),
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    );

    let detach = ParsedCli::try_from(
        Cli::try_parse_from([
            "l2-loopctl",
            "isolated-detach",
            "--run-id",
            "0123456789abcdef0123456789abcdef",
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        detach.command,
        AgentCommand::IsolatedDetach {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    );
}

#[test]
fn isolated_help_is_explicit_and_unsafe_generic_controls_do_not_exist() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("generated isolated verification only"));
    for forbidden in [
        "\n  attach ",
        "\n  force ",
        "\n  replace ",
        "\n  adopt ",
        "cleanup-all",
        "discover-interface",
    ] {
        assert!(
            !help.contains(forbidden),
            "unsafe help surface: {forbidden}"
        );
    }
}

#[test]
fn rejects_invalid_isolated_run_ids_and_missing_explicit_interfaces() {
    for args in [
        vec![
            "l2-loopctl",
            "isolated-attach",
            "--run-id",
            "0123456789abcdef0123456789abcdef",
        ],
        vec!["l2-loopctl", "isolated-detach", "--run-id", "../unsafe"],
    ] {
        match Cli::try_parse_from(args) {
            Ok(cli) => assert!(ParsedCli::try_from(cli).is_err()),
            Err(_) => {}
        }
    }
}

#[test]
fn converts_probe_and_policy_to_validated_domain_commands() {
    let cli = Cli::try_parse_from([
        "l2-loopctl",
        "probe",
        "--interface",
        "bond0",
        "--scope",
        "internal",
        "--timeout",
        "2s",
    ])
    .unwrap();
    let parsed = ParsedCli::try_from(cli).unwrap();
    let AgentCommand::Probe { request } = parsed.command else {
        panic!("expected probe command");
    };
    assert_eq!(request.scope(), ProbeScope::Internal);

    let cli = Cli::try_parse_from([
        "l2-loopctl",
        "police",
        "apply",
        "--interface",
        "bond0",
        "--class",
        "broadcast",
        "--bps",
        "1000000",
        "--ttl",
        "60s",
    ])
    .unwrap();
    let parsed = ParsedCli::try_from(cli).unwrap();
    let AgentCommand::ApplyPolicy { request } = parsed.command else {
        panic!("expected policy command");
    };
    assert_eq!(request.class(), TrafficClass::L2Broadcast);
}

#[test]
fn requires_explicit_interfaces_and_policy_limits() {
    assert!(Cli::try_parse_from(["l2-loopctl", "observe"]).is_err());
    assert!(Cli::try_parse_from(["l2-loopctl", "probe", "--scope", "external",]).is_err());
    assert!(
        Cli::try_parse_from([
            "l2-loopctl",
            "police",
            "apply",
            "--interface",
            "bond0",
            "--class",
            "broadcast",
            "--ttl",
            "60s",
        ])
        .is_err()
    );
}

#[test]
fn rejects_invalid_vlan_timeout_ttl_and_class() {
    for vlan in ["0", "4095"] {
        let cli = Cli::try_parse_from([
            "l2-loopctl",
            "probe",
            "--interface",
            "bond0",
            "--scope",
            "external",
            "--vlan",
            vlan,
        ]);
        assert!(cli.is_err());
    }

    assert_conversion_fails(&[
        "l2-loopctl",
        "probe",
        "--interface",
        "bond0",
        "--scope",
        "external",
        "--timeout",
        "99ms",
    ]);
    assert_conversion_fails(&[
        "l2-loopctl",
        "police",
        "apply",
        "--interface",
        "bond0",
        "--class",
        "broadcast",
        "--pps",
        "10",
        "--ttl",
        "25h",
    ]);
    assert!(
        Cli::try_parse_from([
            "l2-loopctl",
            "police",
            "apply",
            "--interface",
            "bond0",
            "--class",
            "unicast",
            "--pps",
            "10",
            "--ttl",
            "60s",
        ])
        .is_err()
    );
}

#[test]
fn probe_has_no_repetition_controls() {
    for option in ["--count", "--repeat", "--interval"] {
        assert!(
            Cli::try_parse_from([
                "l2-loopctl",
                "probe",
                "--interface",
                "bond0",
                "--scope",
                "external",
                option,
                "2",
            ])
            .is_err(),
            "accepted unsafe option {option}"
        );
    }
}

fn assert_conversion_fails(args: &[&str]) {
    let cli = Cli::try_parse_from(args).unwrap();
    assert!(ParsedCli::try_from(cli).is_err());
}
