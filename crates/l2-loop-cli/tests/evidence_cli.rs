use clap::Parser;
use l2_loop_cli::{Cli, ParsedCli};
use l2_loop_core::{
    AgentCommand, EVIDENCE_LIST_DEFAULT_LIMIT, EVIDENCE_LIST_MAX_LIMIT, EventId, InterfaceName,
};

#[test]
fn evidence_list_applies_fixed_default_and_forwards_bound_filter_and_cursor() {
    let default = ParsedCli::try_from(
        Cli::try_parse_from(["l2-loopctl", "evidence", "list", "--json"]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        default.command,
        AgentCommand::EvidenceList {
            interface: None,
            limit: EVIDENCE_LIST_DEFAULT_LIMIT,
            cursor: None,
        }
    );
    assert!(default.json);

    let bounded = ParsedCli::try_from(
        Cli::try_parse_from([
            "l2-loopctl",
            "evidence",
            "list",
            "--interface",
            "l2h0123456789",
            "--limit",
            &EVIDENCE_LIST_MAX_LIMIT.to_string(),
            "--cursor",
            "1-0000000000000001-01010101010101010101010101010101-af63bc4c8601b62c",
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        bounded.command,
        AgentCommand::EvidenceList {
            interface: Some(InterfaceName::new("l2h0123456789").unwrap()),
            limit: EVIDENCE_LIST_MAX_LIMIT,
            cursor: Some(
                "1-0000000000000001-01010101010101010101010101010101-af63bc4c8601b62c"
                    .to_owned()
            ),
        }
    );
}

#[test]
fn evidence_list_refuses_zero_and_above_max_before_transport() {
    for invalid in ["0", "201"] {
        assert!(
            Cli::try_parse_from([
                "l2-loopctl",
                "evidence",
                "list",
                "--limit",
                invalid,
            ])
            .is_err()
        );
    }
}

#[test]
fn evidence_show_parses_only_a_canonical_event_id_before_transport() {
    let canonical = "01010101010101010101010101010101";
    let parsed = ParsedCli::try_from(
        Cli::try_parse_from(["l2-loopctl", "evidence", "show", "--id", canonical]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        parsed.command,
        AgentCommand::EvidenceShow {
            event_id: canonical.parse::<EventId>().unwrap(),
        }
    );

    for invalid in ["../0101010101010101010101010101", "ABC", "é"] {
        assert!(
            ParsedCli::try_from(
                Cli::try_parse_from(["l2-loopctl", "evidence", "show", "--id", invalid])
                    .unwrap()
            )
            .is_err()
        );
    }
}
