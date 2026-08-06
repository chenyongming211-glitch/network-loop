use clap::Parser;
use csmp_loop_cli::{Cli, ParsedCli};
use csmp_loop_core::{AgentCommand, ProbeScope, TrafficClass};

#[test]
fn parses_every_canonical_command() {
    for args in [
        vec!["csmp-loopctl", "observe", "--interface", "bond0"],
        vec!["csmp-loopctl", "status"],
        vec!["csmp-loopctl", "status", "--interface", "bond0", "--json"],
        vec![
            "csmp-loopctl",
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
            "csmp-loopctl",
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
        vec!["csmp-loopctl", "police", "disable", "--rule", "rule-1"],
        vec!["csmp-loopctl", "evidence", "list", "--json"],
        vec![
            "csmp-loopctl",
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
fn converts_probe_and_policy_to_validated_domain_commands() {
    let cli = Cli::try_parse_from([
        "csmp-loopctl",
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
        "csmp-loopctl",
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
    assert!(Cli::try_parse_from(["csmp-loopctl", "observe"]).is_err());
    assert!(
        Cli::try_parse_from([
            "csmp-loopctl",
            "probe",
            "--scope",
            "external",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "csmp-loopctl",
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
            "csmp-loopctl",
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
        "csmp-loopctl",
        "probe",
        "--interface",
        "bond0",
        "--scope",
        "external",
        "--timeout",
        "99ms",
    ]);
    assert_conversion_fails(&[
        "csmp-loopctl",
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
            "csmp-loopctl",
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
                "csmp-loopctl",
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
