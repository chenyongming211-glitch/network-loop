use std::path::{Path, PathBuf};

use l2_loop_agent::{
    EXIT_INSTALLATION_BLOCKED, EXIT_INSTALLATION_INTERNAL, EXIT_INSTALLATION_SUCCESS,
    EXIT_INSTALLATION_USAGE, InstallServiceError, InstallationCliAction, InstallationCliCommand,
    InstallationCliFormat, InstallationCliSourcePaths, InstallationCommandRunner,
    MAX_INSTALLATION_OUTPUT_BYTES, execute_installation_command, installation_help,
    parse_installation_args, render_installation_report,
};
use l2_loop_core::{
    DeploymentArtifactIdentityV1, GI_AUTH_HOST, GI_DESTINATION_FOREIGN, InstallCommandV1,
    InstallDecisionV1, InstallFindingV1, InstallOperationV1, InstallReportV1,
};

const AUTHORIZATION_ID: &str = "00112233445566778899aabbccddeeff";
const TRANSACTION_ID: &str = "ffeeddccbbaa99887766554433221100";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const CAPTURED_AT_UNIX_MS: u64 = 1_787_000_000_000;

#[test]
fn parser_accepts_only_the_exact_four_command_grammars() {
    let source = source_paths();
    assert_eq!(
        parse(&[
            "plan",
            "--bundle",
            "/private/bundle",
            "--authorization",
            "/private/install.json",
            "--deployment-authorization",
            "/private/deployment.json",
            "--performance-evidence",
            "/private/performance.json",
        ]),
        InstallationCliAction::Run {
            command: InstallationCliCommand::Plan(source.clone()),
            format: InstallationCliFormat::Text,
        }
    );
    assert_eq!(
        parse(&[
            "apply",
            "--bundle",
            "/private/bundle",
            "--authorization",
            "/private/install.json",
            "--deployment-authorization",
            "/private/deployment.json",
            "--performance-evidence",
            "/private/performance.json",
            "--json",
        ]),
        InstallationCliAction::Run {
            command: InstallationCliCommand::Apply(source),
            format: InstallationCliFormat::Json,
        }
    );
    assert_eq!(
        parse(&["status"]),
        InstallationCliAction::Run {
            command: InstallationCliCommand::Status,
            format: InstallationCliFormat::Text,
        }
    );
    assert_eq!(
        parse(&[
            "rollback",
            "--transaction",
            TRANSACTION_ID,
            "--authorization",
            "/private/install.json",
            "--json",
        ]),
        InstallationCliAction::Run {
            command: InstallationCliCommand::Rollback {
                transaction_id: TRANSACTION_ID.to_owned(),
                authorization: PathBuf::from("/private/install.json"),
            },
            format: InstallationCliFormat::Json,
        }
    );
    assert_eq!(parse(&["--help"]), InstallationCliAction::Help);
    assert_eq!(parse(&["help"]), InstallationCliAction::Help);
}

#[test]
fn parser_rejects_missing_reordered_or_unsafe_arguments() {
    let rejected: &[&[&str]] = &[
        &[],
        &["plan"],
        &["apply", "--bundle", "/private/bundle"],
        &[
            "plan",
            "--authorization",
            "/private/install.json",
            "--bundle",
            "/private/bundle",
            "--deployment-authorization",
            "/private/deployment.json",
            "--performance-evidence",
            "/private/performance.json",
        ],
        &["status", "extra"],
        &["status", "--transaction", TRANSACTION_ID],
        &[
            "rollback",
            "--transaction",
            "FFEEDDCCBBAA99887766554433221100",
            "--authorization",
            "/private/install.json",
        ],
        &[
            "rollback",
            "--transaction",
            "ffeeddccbbaa9988776655443322110",
            "--authorization",
            "/private/install.json",
        ],
        &["rollback", "--transaction", TRANSACTION_ID],
        &[
            "rollback",
            "--authorization",
            "/private/install.json",
            "--transaction",
            TRANSACTION_ID,
        ],
        &["status", "--root", "/tmp/root"],
        &["status", "--prefix", "/tmp/root"],
        &["status", "--destination", "/tmp/file"],
        &["status", "--interface", "eth0"],
        &["apply", "--force"],
        &["apply", "--repair"],
        &["apply", "--enable"],
        &["apply", "--start"],
        &["attach", "eth0"],
        &["detach", "eth0"],
        &["install"],
        &["uninstall"],
        &["purge"],
        &["recover-any"],
        &["--version"],
    ];
    for args in rejected {
        assert!(
            parse_installation_args(args.iter().copied()).is_err(),
            "accepted prohibited installation command: {args:?}"
        );
    }
}

#[test]
fn help_names_only_fixed_bounded_installation_authority() {
    let help = installation_help();
    for command in ["plan", "apply", "status", "rollback"] {
        assert!(help.contains(command));
    }
    for prohibited in [
        "--root",
        "--prefix",
        "--destination",
        "--interface",
        "--force",
        "--repair",
        "systemctl",
        "attach",
        "detach",
    ] {
        assert!(
            !help.contains(prohibited),
            "unsafe help surface: {prohibited}"
        );
    }
}

#[test]
fn execution_routes_read_only_and_mutating_commands_with_a_root_gate() {
    let mut runner = RecordingRunner::new(success_report(InstallCommandV1::Plan));
    let plan = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Plan(source_paths()),
        InstallationCliFormat::Text,
        1000,
    );
    assert_eq!(plan.exit_code, EXIT_INSTALLATION_SUCCESS);
    assert_eq!(runner.calls, vec!["plan"]);

    runner.report = success_report(InstallCommandV1::Status);
    let status = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Status,
        InstallationCliFormat::Json,
        1000,
    );
    assert_eq!(status.exit_code, EXIT_INSTALLATION_SUCCESS);
    assert_eq!(runner.calls, vec!["plan", "status"]);

    let denied_apply = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Apply(source_paths()),
        InstallationCliFormat::Text,
        1000,
    );
    assert_eq!(denied_apply.exit_code, EXIT_INSTALLATION_INTERNAL);
    assert_eq!(runner.calls, vec!["plan", "status"]);

    runner.report = success_report(InstallCommandV1::Apply);
    let apply = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Apply(source_paths()),
        InstallationCliFormat::Text,
        0,
    );
    assert_eq!(apply.exit_code, EXIT_INSTALLATION_SUCCESS);
    assert_eq!(runner.calls, vec!["plan", "status", "apply"]);

    let denied_rollback = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Rollback {
            transaction_id: TRANSACTION_ID.to_owned(),
            authorization: PathBuf::from("/private/install.json"),
        },
        InstallationCliFormat::Text,
        1000,
    );
    assert_eq!(denied_rollback.exit_code, EXIT_INSTALLATION_INTERNAL);
    assert_eq!(runner.calls, vec!["plan", "status", "apply"]);

    runner.report = success_report(InstallCommandV1::Rollback);
    let rollback = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Rollback {
            transaction_id: TRANSACTION_ID.to_owned(),
            authorization: PathBuf::from("/private/install.json"),
        },
        InstallationCliFormat::Json,
        0,
    );
    assert_eq!(rollback.exit_code, EXIT_INSTALLATION_SUCCESS);
    assert_eq!(runner.calls, vec!["plan", "status", "apply", "rollback"]);
}

#[test]
fn text_and_json_render_the_same_bounded_privacy_reduced_report() {
    let report = blocked_report();
    let text = render_installation_report(&report, InstallationCliFormat::Text).unwrap();
    let json = render_installation_report(&report, InstallationCliFormat::Json).unwrap();
    let decoded: InstallReportV1 = serde_json::from_str(&json.stdout).unwrap();

    assert_eq!(decoded, report);
    assert!(text.stdout.contains("decision: blocked"));
    assert!(text.stdout.contains("command: plan"));
    assert!(text.stdout.contains("operation: install"));
    assert!(text.stdout.contains("GI_AUTH_HOST"));
    assert!(text.stdout.contains("GI_DESTINATION_FOREIGN"));
    assert!(text.stdout.find("GI_AUTH_HOST") < text.stdout.find("GI_DESTINATION_FOREIGN"));
    assert!(text.stdout.contains("mutations_performed: false"));
    for private in [
        "/private/bundle",
        "/private/install.json",
        "machine-id",
        "host_identity_sha256",
        "service_enable",
        "service_start",
        "physical_attach",
    ] {
        assert!(!text.stdout.contains(private));
        assert!(!json.stdout.contains(private));
    }
    assert!(text.stdout.len() <= MAX_INSTALLATION_OUTPUT_BYTES);
    assert!(json.stdout.len() <= MAX_INSTALLATION_OUTPUT_BYTES);
    assert_eq!(text.exit_code, EXIT_INSTALLATION_BLOCKED);
    assert_eq!(json.exit_code, EXIT_INSTALLATION_BLOCKED);
}

#[test]
fn exit_codes_distinguish_success_internal_usage_and_blocked() {
    assert_eq!(EXIT_INSTALLATION_SUCCESS, 0);
    assert_eq!(EXIT_INSTALLATION_INTERNAL, 1);
    assert_eq!(EXIT_INSTALLATION_USAGE, 2);
    assert_eq!(EXIT_INSTALLATION_BLOCKED, 4);
    assert_eq!(MAX_INSTALLATION_OUTPUT_BYTES, 1024 * 1024);

    let mut runner = RecordingRunner::new(blocked_report());
    let blocked = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Plan(source_paths()),
        InstallationCliFormat::Text,
        1000,
    );
    assert_eq!(blocked.exit_code, EXIT_INSTALLATION_BLOCKED);

    runner.fail = true;
    let unavailable = execute_installation_command(
        &mut runner,
        InstallationCliCommand::Status,
        InstallationCliFormat::Json,
        1000,
    );
    assert_eq!(unavailable.exit_code, EXIT_INSTALLATION_INTERNAL);
    assert!(unavailable.stdout.is_empty());
    assert_eq!(unavailable.stderr, "installation unavailable");
}

#[test]
fn binary_help_is_available_without_constructing_a_writer_or_touching_the_host() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_l2-loop-install"))
        .arg("--help")
        .env_remove("L2_LOOP_INSTALL_ROOT")
        .env_remove("L2_LOOP_INSTALL_PREFIX")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("l2-loop-install"));
    assert!(stdout.contains("plan"));
    assert!(stdout.contains("rollback"));
}

#[test]
fn installer_cli_sources_expose_no_environment_alias_process_or_network_surface() {
    let library = include_str!("../src/installation_cli.rs");
    let binary = include_str!("../src/bin/install.rs");
    let combined = format!("{library}\n{binary}");
    for prohibited in [
        "env::var",
        "Command::new",
        "systemctl",
        "journalctl",
        "rtnetlink",
        "aya::",
        "UnixStream",
        "agent.sock",
        "--root",
        "--prefix",
        "--destination",
        "--interface",
        "--force",
        "--repair",
        "remove_dir_all",
    ] {
        assert!(
            !combined.contains(prohibited),
            "prohibited installer CLI capability present: {prohibited}"
        );
    }
}

fn parse(args: &[&str]) -> InstallationCliAction {
    parse_installation_args(args.iter().copied()).unwrap()
}

fn source_paths() -> InstallationCliSourcePaths {
    InstallationCliSourcePaths {
        bundle: PathBuf::from("/private/bundle"),
        authorization: PathBuf::from("/private/install.json"),
        deployment_authorization: PathBuf::from("/private/deployment.json"),
        performance_evidence: PathBuf::from("/private/performance.json"),
    }
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(COMMIT_SHA, "0.1.0").unwrap()
}

fn success_report(command: InstallCommandV1) -> InstallReportV1 {
    let (operation, mutations) = match command {
        InstallCommandV1::Plan | InstallCommandV1::Status => (InstallOperationV1::Install, false),
        InstallCommandV1::Apply => (InstallOperationV1::Install, true),
        InstallCommandV1::Rollback => (InstallOperationV1::Rollback, true),
    };
    InstallReportV1::derive(
        command,
        operation,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        Vec::new(),
        CAPTURED_AT_UNIX_MS,
        mutations,
    )
    .unwrap()
}

fn blocked_report() -> InstallReportV1 {
    let report = InstallReportV1::derive(
        InstallCommandV1::Plan,
        InstallOperationV1::Install,
        AUTHORIZATION_ID,
        TRANSACTION_ID,
        artifact(),
        vec![
            InstallFindingV1::blocker(GI_DESTINATION_FOREIGN).unwrap(),
            InstallFindingV1::blocker(GI_AUTH_HOST).unwrap(),
        ],
        CAPTURED_AT_UNIX_MS,
        false,
    )
    .unwrap();
    assert_eq!(report.decision, InstallDecisionV1::Blocked);
    report
}

struct RecordingRunner {
    calls: Vec<&'static str>,
    report: InstallReportV1,
    fail: bool,
}

impl RecordingRunner {
    fn new(report: InstallReportV1) -> Self {
        Self {
            calls: Vec::new(),
            report,
            fail: false,
        }
    }

    fn result(&self) -> Result<InstallReportV1, InstallServiceError> {
        if self.fail {
            Err(InstallServiceError::InputUnavailable)
        } else {
            Ok(self.report.clone())
        }
    }
}

impl InstallationCommandRunner for RecordingRunner {
    fn plan(
        &mut self,
        _source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        self.calls.push("plan");
        self.result()
    }

    fn apply(
        &mut self,
        _source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        self.calls.push("apply");
        self.result()
    }

    fn status(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        self.calls.push("status");
        self.result()
    }

    fn rollback(
        &mut self,
        _transaction_id: &str,
        _authorization: &Path,
    ) -> Result<InstallReportV1, InstallServiceError> {
        self.calls.push("rollback");
        self.result()
    }
}
