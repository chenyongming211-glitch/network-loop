use std::path::{Path, PathBuf};

use l2_loop_agent::{
    DeploymentCliAction, DeploymentCliCommand, DeploymentCliFormat, DeploymentGateRunner,
    DeploymentServiceError, EXIT_DEPLOYMENT_BLOCKED, EXIT_DEPLOYMENT_INTERNAL,
    EXIT_DEPLOYMENT_SUCCESS, EXIT_DEPLOYMENT_USAGE, MAX_DEPLOYMENT_OUTPUT_BYTES, deployment_help,
    execute_deployment_command, parse_deployment_args, render_deployment_report,
};
use l2_loop_core::{
    DG_PLATFORM_BLOCKED, DeploymentArtifactIdentityV1, DeploymentCommandV1, DeploymentFindingV1,
    DeploymentGateReportV1, DeploymentGateSummariesV1,
};

const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const STAGING_ROOT: &str = "/run/l2-loop/accept/00112233445566778899aabbccddeeff/staging-root";

#[test]
fn parser_accepts_only_the_three_approved_read_only_commands() {
    assert_eq!(
        parse(&["staging", "--bundle", "/bundle", "--root", STAGING_ROOT]),
        DeploymentCliAction::Run {
            command: DeploymentCliCommand::Staging {
                bundle: PathBuf::from("/bundle"),
                root: PathBuf::from(STAGING_ROOT),
            },
            format: DeploymentCliFormat::Text,
        }
    );
    assert_eq!(
        parse(&[
            "staging",
            "--bundle",
            "/bundle",
            "--root",
            STAGING_ROOT,
            "--json",
        ]),
        DeploymentCliAction::Run {
            command: DeploymentCliCommand::Staging {
                bundle: PathBuf::from("/bundle"),
                root: PathBuf::from(STAGING_ROOT),
            },
            format: DeploymentCliFormat::Json,
        }
    );
    assert_eq!(
        parse(&["installed", "--json"]),
        DeploymentCliAction::Run {
            command: DeploymentCliCommand::Installed,
            format: DeploymentCliFormat::Json,
        }
    );
    assert_eq!(
        parse(&["inspect"]),
        DeploymentCliAction::Run {
            command: DeploymentCliCommand::Inspect,
            format: DeploymentCliFormat::Text,
        }
    );
    assert_eq!(
        parse(&["inspect", "--json"]),
        DeploymentCliAction::Run {
            command: DeploymentCliCommand::Inspect,
            format: DeploymentCliFormat::Json,
        }
    );
    assert_eq!(parse(&["--help"]), DeploymentCliAction::Help);
    assert_eq!(parse(&["help"]), DeploymentCliAction::Help);
}

#[test]
fn parser_rejects_aliases_overrides_mutating_verbs_and_extra_positionals() {
    let rejected: &[&[&str]] = &[
        &[],
        &["staging"],
        &[
            "staging",
            "--bundle",
            "/bundle",
            "--root",
            STAGING_ROOT,
            "extra",
        ],
        &["staging", "--root", STAGING_ROOT, "--bundle", "/bundle"],
        &[
            "staging",
            "--bundle",
            "/bundle",
            "--root",
            STAGING_ROOT,
            "--json",
            "--json",
        ],
        &["inspect", "extra"],
        &["inspect", "--interface", "eth0"],
        &["installed"],
        &["installed", "--json", "--json"],
        &["installed", "--interface", "eth0", "--json"],
        &["installed", "--root", STAGING_ROOT, "--json"],
        &["installed", "--bundle", "/bundle", "--json"],
        &["inspect", "--root", STAGING_ROOT],
        &["inspect", "--bundle", "/bundle"],
        &["inspect", "--output", "/tmp/report"],
        &["inspect", "--evidence-root", "/tmp/evidence"],
        &["inspect", "--socket", "/tmp/agent.sock"],
        &["inspect", "--manifest", "/tmp/manifest.json"],
        &["inspect", "--authorization", "/tmp/auth.json"],
        &["inspect", "--performance", "/tmp/performance.json"],
        &["install"],
        &["repair"],
        &["start"],
        &["attach", "eth0"],
        &["force"],
        &["policy"],
        &["observe"],
        &["status"],
        &["--version"],
    ];
    for args in rejected {
        assert!(
            parse_deployment_args(args.iter().copied()).is_err(),
            "accepted prohibited command: {args:?}"
        );
    }
}

#[test]
fn help_is_explicitly_read_only_and_non_executable() {
    let help = deployment_help();
    assert!(help.contains("staging --bundle <DIR> --root <ROOT> [--json]"));
    assert!(help.contains("installed --json"));
    assert!(help.contains("inspect [--json]"));
    assert!(help.contains("read-only"));
    assert!(help.contains("does not install, start, attach, repair, or mutate"));
}

#[test]
fn command_execution_routes_directly_to_the_gate_runner() {
    let mut runner = RecordingRunner::new(staging_report());
    let staging = execute_deployment_command(
        &mut runner,
        DeploymentCliCommand::Staging {
            bundle: PathBuf::from("/bundle"),
            root: PathBuf::from(STAGING_ROOT),
        },
        DeploymentCliFormat::Json,
    );
    assert_eq!(runner.calls, vec!["staging:/bundle".to_owned()]);
    assert_eq!(staging.exit_code, EXIT_DEPLOYMENT_SUCCESS);

    runner.report = installed_report();
    let installed = execute_deployment_command(
        &mut runner,
        DeploymentCliCommand::Installed,
        DeploymentCliFormat::Json,
    );
    assert_eq!(
        runner.calls,
        vec!["staging:/bundle".to_owned(), "installed".to_owned()]
    );
    assert_eq!(installed.exit_code, EXIT_DEPLOYMENT_SUCCESS);

    runner.report = blocked_report();
    let inspect = execute_deployment_command(
        &mut runner,
        DeploymentCliCommand::Inspect,
        DeploymentCliFormat::Text,
    );
    assert_eq!(
        runner.calls,
        vec!["staging:/bundle".to_owned(), "inspect".to_owned()]
    );
    assert_eq!(inspect.exit_code, EXIT_DEPLOYMENT_BLOCKED);
}

#[test]
fn text_and_json_render_the_same_validated_decision_and_bounded_fields() {
    let report = blocked_report();
    let text = render_deployment_report(&report, DeploymentCliFormat::Text).unwrap();
    let json = render_deployment_report(&report, DeploymentCliFormat::Json).unwrap();
    let decoded: DeploymentGateReportV1 = serde_json::from_str(&json.stdout).unwrap();

    assert_eq!(decoded, report);
    assert!(text.stdout.contains("decision: blocked"));
    assert!(text.stdout.contains(COMMIT_SHA));
    assert!(text.stdout.contains("DG_PLATFORM_BLOCKED"));
    assert!(text.stdout.contains("mutations_performed: false"));
    assert!(!text.stdout.contains("0x"));
    assert!(text.stdout.len() <= MAX_DEPLOYMENT_OUTPUT_BYTES);
    assert!(json.stdout.len() <= MAX_DEPLOYMENT_OUTPUT_BYTES);
    assert_eq!(text.exit_code, EXIT_DEPLOYMENT_BLOCKED);
    assert_eq!(json.exit_code, EXIT_DEPLOYMENT_BLOCKED);
}

#[test]
fn exit_codes_distinguish_positive_blocked_usage_and_internal_failures() {
    assert_eq!(EXIT_DEPLOYMENT_SUCCESS, 0);
    assert_eq!(EXIT_DEPLOYMENT_INTERNAL, 1);
    assert_eq!(EXIT_DEPLOYMENT_USAGE, 2);
    assert_eq!(EXIT_DEPLOYMENT_BLOCKED, 4);

    let mut runner = RecordingRunner::new(staging_report());
    runner.fail = true;
    let output = execute_deployment_command(
        &mut runner,
        DeploymentCliCommand::Inspect,
        DeploymentCliFormat::Json,
    );
    assert_eq!(output.exit_code, EXIT_DEPLOYMENT_INTERNAL);
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, "deployment check unavailable");
}

#[test]
fn binary_help_contract_is_exercised_without_touching_the_host() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_l2-loop-deploycheck"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("read-only"));
    assert!(output.stderr.is_empty());
}

#[test]
fn deploycheck_sources_have_no_socket_daemon_or_mutation_surface() {
    let library = include_str!("../src/deployment_cli.rs");
    let binary = include_str!("../src/bin/deploycheck.rs");
    let combined = format!("{library}\n{binary}");
    for prohibited in [
        "UnixControlClient",
        "agent.sock",
        "tokio::net::UnixStream",
        "env::var",
        "Command::new",
        "fs::write",
        "File::create",
        "create_dir",
        "remove_file",
        "remove_dir",
        "set_permissions",
        "attach(",
        "install(",
        "repair(",
    ] {
        assert!(
            !combined.contains(prohibited),
            "prohibited deploycheck capability present: {prohibited}"
        );
    }
}

fn parse(args: &[&str]) -> DeploymentCliAction {
    parse_deployment_args(args.iter().copied()).unwrap()
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn staging_report() -> DeploymentGateReportV1 {
    DeploymentGateReportV1::derive(
        DeploymentCommandV1::Staging,
        artifact(),
        None,
        DeploymentGateSummariesV1::staging_passed(),
        Vec::new(),
        None,
        1_787_000_000_000,
    )
    .unwrap()
}

fn blocked_report() -> DeploymentGateReportV1 {
    DeploymentGateReportV1::derive(
        DeploymentCommandV1::Inspect,
        artifact(),
        None,
        DeploymentGateSummariesV1::inspect_blocked(DG_PLATFORM_BLOCKED).unwrap(),
        vec![DeploymentFindingV1::blocker(DG_PLATFORM_BLOCKED).unwrap()],
        None,
        1_787_000_000_000,
    )
    .unwrap()
}

fn installed_report() -> DeploymentGateReportV1 {
    DeploymentGateReportV1::derive(
        DeploymentCommandV1::Installed,
        artifact(),
        None,
        DeploymentGateSummariesV1::installed_passed(),
        Vec::new(),
        None,
        1_787_000_000_000,
    )
    .unwrap()
}

struct RecordingRunner {
    calls: Vec<String>,
    report: DeploymentGateReportV1,
    fail: bool,
}

impl RecordingRunner {
    fn new(report: DeploymentGateReportV1) -> Self {
        Self {
            calls: Vec::new(),
            report,
            fail: false,
        }
    }
}

impl DeploymentGateRunner for RecordingRunner {
    fn staging(
        &mut self,
        bundle: &Path,
        _root: &Path,
    ) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        self.calls
            .push(format!("staging:{}", bundle.to_string_lossy()));
        if self.fail {
            Err(DeploymentServiceError::InvalidReport)
        } else {
            Ok(self.report.clone())
        }
    }

    fn inspect(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        self.calls.push("inspect".to_owned());
        if self.fail {
            Err(DeploymentServiceError::InvalidReport)
        } else {
            Ok(self.report.clone())
        }
    }

    fn installed(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        self.calls.push("installed".to_owned());
        if self.fail {
            Err(DeploymentServiceError::InvalidReport)
        } else {
            Ok(self.report.clone())
        }
    }
}
