use std::path::{Path, PathBuf};

use l2_loop_core::{InstallDecisionV1, InstallReportV1};
use thiserror::Error;

use crate::InstallServiceError;

pub const EXIT_INSTALLATION_SUCCESS: u8 = 0;
pub const EXIT_INSTALLATION_INTERNAL: u8 = 1;
pub const EXIT_INSTALLATION_USAGE: u8 = 2;
pub const EXIT_INSTALLATION_BLOCKED: u8 = 4;
pub const MAX_INSTALLATION_OUTPUT_BYTES: usize = 1024 * 1024;

const HELP: &str = "l2-loop-install - bounded transactional installer

usage:
  l2-loop-install plan --bundle <BUNDLE_DIR> --authorization <INSTALL_AUTHORIZATION_FILE> --deployment-authorization <DEPLOYMENT_AUTHORIZATION_FILE> --performance-evidence <PERFORMANCE_EVIDENCE_FILE> [--json]
  l2-loop-install apply --bundle <BUNDLE_DIR> --authorization <INSTALL_AUTHORIZATION_FILE> --deployment-authorization <DEPLOYMENT_AUTHORIZATION_FILE> --performance-evidence <PERFORMANCE_EVIDENCE_FILE> [--json]
  l2-loop-install status [--json]
  l2-loop-install rollback --transaction <32-lower-hex> --authorization <INSTALL_AUTHORIZATION_FILE> [--json]

Destinations and ownership are fixed by the installed product contract. Planning and status are read-only. Applying and rolling back require effective root and never start a service or change a network interface.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationCliFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationCliSourcePaths {
    pub bundle: PathBuf,
    pub authorization: PathBuf,
    pub deployment_authorization: PathBuf,
    pub performance_evidence: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationCliCommand {
    Plan(InstallationCliSourcePaths),
    Apply(InstallationCliSourcePaths),
    Status,
    Rollback {
        transaction_id: String,
        authorization: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationCliAction {
    Run {
        command: InstallationCliCommand,
        format: InstallationCliFormat,
    },
    Help,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid installation command")]
pub struct InstallationCliParseError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InstallationCliRenderError {
    #[error("installation report serialization failed")]
    Serialization,
    #[error("installation report exceeds the output bound")]
    OutputTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedInstallationOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

pub trait InstallationCommandRunner {
    fn plan(
        &mut self,
        source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError>;

    fn apply(
        &mut self,
        source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError>;

    fn status(&mut self) -> Result<InstallReportV1, InstallServiceError>;

    fn rollback(
        &mut self,
        transaction_id: &str,
        authorization: &Path,
    ) -> Result<InstallReportV1, InstallServiceError>;
}

pub const fn installation_help() -> &'static str {
    HELP
}

pub fn parse_installation_args<I, S>(
    args: I,
) -> Result<InstallationCliAction, InstallationCliParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    let (args, format) = strip_json(args)?;
    match args.as_slice() {
        [help] if help == "--help" || help == "help" => {
            if format == InstallationCliFormat::Json {
                Err(InstallationCliParseError)
            } else {
                Ok(InstallationCliAction::Help)
            }
        }
        [command] if command == "status" => Ok(InstallationCliAction::Run {
            command: InstallationCliCommand::Status,
            format,
        }),
        [
            command,
            bundle_flag,
            bundle,
            authorization_flag,
            authorization,
            deployment_flag,
            deployment,
            performance_flag,
            performance,
        ] if (command == "plan" || command == "apply")
            && bundle_flag == "--bundle"
            && authorization_flag == "--authorization"
            && deployment_flag == "--deployment-authorization"
            && performance_flag == "--performance-evidence" =>
        {
            let source = parse_source(bundle, authorization, deployment, performance)?;
            let command = if command == "plan" {
                InstallationCliCommand::Plan(source)
            } else {
                InstallationCliCommand::Apply(source)
            };
            Ok(InstallationCliAction::Run { command, format })
        }
        [
            command,
            transaction_flag,
            transaction_id,
            authorization_flag,
            authorization,
        ] if command == "rollback"
            && transaction_flag == "--transaction"
            && authorization_flag == "--authorization"
            && is_lower_hex(transaction_id, 32)
            && !authorization.is_empty() =>
        {
            Ok(InstallationCliAction::Run {
                command: InstallationCliCommand::Rollback {
                    transaction_id: transaction_id.clone(),
                    authorization: PathBuf::from(authorization),
                },
                format,
            })
        }
        _ => Err(InstallationCliParseError),
    }
}

fn strip_json(
    mut args: Vec<String>,
) -> Result<(Vec<String>, InstallationCliFormat), InstallationCliParseError> {
    if args.last().is_some_and(|value| value == "--json") {
        args.pop();
        if args.iter().any(|value| value == "--json") {
            return Err(InstallationCliParseError);
        }
        Ok((args, InstallationCliFormat::Json))
    } else if args.iter().any(|value| value == "--json") {
        Err(InstallationCliParseError)
    } else {
        Ok((args, InstallationCliFormat::Text))
    }
}

fn parse_source(
    bundle: &str,
    authorization: &str,
    deployment_authorization: &str,
    performance_evidence: &str,
) -> Result<InstallationCliSourcePaths, InstallationCliParseError> {
    if [
        bundle,
        authorization,
        deployment_authorization,
        performance_evidence,
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        return Err(InstallationCliParseError);
    }
    Ok(InstallationCliSourcePaths {
        bundle: PathBuf::from(bundle),
        authorization: PathBuf::from(authorization),
        deployment_authorization: PathBuf::from(deployment_authorization),
        performance_evidence: PathBuf::from(performance_evidence),
    })
}

pub fn execute_installation_command<R>(
    runner: &mut R,
    command: InstallationCliCommand,
    format: InstallationCliFormat,
    effective_uid: u32,
) -> RenderedInstallationOutput
where
    R: InstallationCommandRunner,
{
    let result = match command {
        InstallationCliCommand::Plan(source) => runner.plan(&source),
        InstallationCliCommand::Apply(source) if effective_uid == 0 => runner.apply(&source),
        InstallationCliCommand::Status => runner.status(),
        InstallationCliCommand::Rollback {
            transaction_id,
            authorization,
        } if effective_uid == 0 => runner.rollback(&transaction_id, &authorization),
        InstallationCliCommand::Apply(_) | InstallationCliCommand::Rollback { .. } => {
            return internal_failure();
        }
    };
    let Ok(report) = result else {
        return internal_failure();
    };
    render_installation_report(&report, format).unwrap_or_else(|_| internal_failure())
}

pub fn render_installation_report(
    report: &InstallReportV1,
    format: InstallationCliFormat,
) -> Result<RenderedInstallationOutput, InstallationCliRenderError> {
    report
        .validate()
        .map_err(|_| InstallationCliRenderError::Serialization)?;
    let mut stdout = match format {
        InstallationCliFormat::Json => {
            serde_json::to_string(report).map_err(|_| InstallationCliRenderError::Serialization)?
        }
        InstallationCliFormat::Text => render_text(report),
    };
    if stdout.len() >= MAX_INSTALLATION_OUTPUT_BYTES {
        return Err(InstallationCliRenderError::OutputTooLarge);
    }
    stdout.push('\n');
    if stdout.len() > MAX_INSTALLATION_OUTPUT_BYTES {
        return Err(InstallationCliRenderError::OutputTooLarge);
    }
    Ok(RenderedInstallationOutput {
        stdout,
        stderr: String::new(),
        exit_code: decision_exit_code(report.decision),
    })
}

fn render_text(report: &InstallReportV1) -> String {
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<Vec<_>>()
        .join(",");
    [
        format!("schema_version: {}", report.schema_version),
        format!("decision: {}", report.decision),
        format!("command: {}", command_name(report.command)),
        format!("operation: {}", report.operation),
        format!("authorization_id: {}", report.authorization_id),
        format!("transaction_id: {}", report.transaction_id),
        format!("artifact.commit_sha: {}", report.artifact.commit_sha),
        format!(
            "artifact.package_version: {}",
            report.artifact.package_version
        ),
        format!("findings: {findings}"),
        format!("captured_at_unix_ms: {}", report.captured_at_unix_ms),
        format!("mutations_performed: {}", report.mutations_performed),
    ]
    .join("\n")
}

const fn command_name(command: l2_loop_core::InstallCommandV1) -> &'static str {
    match command {
        l2_loop_core::InstallCommandV1::Plan => "plan",
        l2_loop_core::InstallCommandV1::Apply => "apply",
        l2_loop_core::InstallCommandV1::Status => "status",
        l2_loop_core::InstallCommandV1::Rollback => "rollback",
    }
}

const fn decision_exit_code(decision: InstallDecisionV1) -> u8 {
    match decision {
        InstallDecisionV1::InstallPlanReady
        | InstallDecisionV1::InstalledVerified
        | InstallDecisionV1::RolledBack => EXIT_INSTALLATION_SUCCESS,
        InstallDecisionV1::Blocked => EXIT_INSTALLATION_BLOCKED,
    }
}

fn internal_failure() -> RenderedInstallationOutput {
    RenderedInstallationOutput {
        stdout: String::new(),
        stderr: "installation unavailable".to_owned(),
        exit_code: EXIT_INSTALLATION_INTERNAL,
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
