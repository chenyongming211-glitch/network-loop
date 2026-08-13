use std::path::{Path, PathBuf};

use l2_loop_core::{DeploymentDecisionV1, DeploymentGateReportV1, DeploymentGateStateV1};
use thiserror::Error;

use crate::{
    Clock, DeploymentFilesystem, DeploymentGateService, DeploymentPlatformInspector,
    DeploymentServiceError,
};

pub const EXIT_DEPLOYMENT_SUCCESS: u8 = 0;
pub const EXIT_DEPLOYMENT_INTERNAL: u8 = 1;
pub const EXIT_DEPLOYMENT_USAGE: u8 = 2;
pub const EXIT_DEPLOYMENT_BLOCKED: u8 = 4;
pub const MAX_DEPLOYMENT_OUTPUT_BYTES: usize = 1024 * 1024;

const HELP: &str = "l2-loop-deploycheck - strict read-only deployment gate checker

usage:
  l2-loop-deploycheck staging --bundle <DIR> --root <ROOT> [--json]
  l2-loop-deploycheck inspect [--json]

This checker is read-only and non-executable. It does not install, start, attach, repair, or mutate anything.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentCliFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentCliCommand {
    Staging { bundle: PathBuf, root: PathBuf },
    Inspect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentCliAction {
    Run {
        command: DeploymentCliCommand,
        format: DeploymentCliFormat,
    },
    Help,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid deployment check command")]
pub struct DeploymentCliParseError;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentCliRenderError {
    #[error("deployment report serialization failed")]
    Serialization,
    #[error("deployment report exceeds the output bound")]
    OutputTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedDeploymentOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

pub trait DeploymentGateRunner {
    fn staging(
        &mut self,
        bundle: &Path,
        root: &Path,
    ) -> Result<DeploymentGateReportV1, DeploymentServiceError>;

    fn inspect(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError>;
}

impl<F, P, C> DeploymentGateRunner for DeploymentGateService<F, P, C>
where
    F: DeploymentFilesystem,
    P: DeploymentPlatformInspector,
    C: Clock,
{
    fn staging(
        &mut self,
        bundle: &Path,
        root: &Path,
    ) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        DeploymentGateService::staging(self, bundle, root)
    }

    fn inspect(&mut self) -> Result<DeploymentGateReportV1, DeploymentServiceError> {
        DeploymentGateService::inspect(self)
    }
}

pub fn deployment_help() -> &'static str {
    HELP
}

pub fn parse_deployment_args<I, S>(args: I) -> Result<DeploymentCliAction, DeploymentCliParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    match args.as_slice() {
        [help] if help == "--help" || help == "help" => Ok(DeploymentCliAction::Help),
        [command] if command == "inspect" => Ok(DeploymentCliAction::Run {
            command: DeploymentCliCommand::Inspect,
            format: DeploymentCliFormat::Text,
        }),
        [command, json] if command == "inspect" && json == "--json" => {
            Ok(DeploymentCliAction::Run {
                command: DeploymentCliCommand::Inspect,
                format: DeploymentCliFormat::Json,
            })
        }
        [command, bundle_flag, bundle, root_flag, root]
            if command == "staging" && bundle_flag == "--bundle" && root_flag == "--root" =>
        {
            parse_staging(bundle, root, DeploymentCliFormat::Text)
        }
        [command, bundle_flag, bundle, root_flag, root, json]
            if command == "staging"
                && bundle_flag == "--bundle"
                && root_flag == "--root"
                && json == "--json" =>
        {
            parse_staging(bundle, root, DeploymentCliFormat::Json)
        }
        _ => Err(DeploymentCliParseError),
    }
}

fn parse_staging(
    bundle: &str,
    root: &str,
    format: DeploymentCliFormat,
) -> Result<DeploymentCliAction, DeploymentCliParseError> {
    if bundle.is_empty() || root.is_empty() {
        return Err(DeploymentCliParseError);
    }
    Ok(DeploymentCliAction::Run {
        command: DeploymentCliCommand::Staging {
            bundle: PathBuf::from(bundle),
            root: PathBuf::from(root),
        },
        format,
    })
}

pub fn execute_deployment_command<R>(
    runner: &mut R,
    command: DeploymentCliCommand,
    format: DeploymentCliFormat,
) -> RenderedDeploymentOutput
where
    R: DeploymentGateRunner,
{
    let result = match command {
        DeploymentCliCommand::Staging { bundle, root } => runner.staging(&bundle, &root),
        DeploymentCliCommand::Inspect => runner.inspect(),
    };
    let Ok(report) = result else {
        return internal_failure();
    };
    render_deployment_report(&report, format).unwrap_or_else(|_| internal_failure())
}

pub fn render_deployment_report(
    report: &DeploymentGateReportV1,
    format: DeploymentCliFormat,
) -> Result<RenderedDeploymentOutput, DeploymentCliRenderError> {
    let mut stdout = match format {
        DeploymentCliFormat::Json => {
            serde_json::to_string(report).map_err(|_| DeploymentCliRenderError::Serialization)?
        }
        DeploymentCliFormat::Text => render_text(report)?,
    };
    if stdout.len() >= MAX_DEPLOYMENT_OUTPUT_BYTES {
        return Err(DeploymentCliRenderError::OutputTooLarge);
    }
    stdout.push('\n');
    if stdout.len() > MAX_DEPLOYMENT_OUTPUT_BYTES {
        return Err(DeploymentCliRenderError::OutputTooLarge);
    }
    Ok(RenderedDeploymentOutput {
        stdout,
        stderr: String::new(),
        exit_code: decision_exit_code(report.decision),
    })
}

fn render_text(report: &DeploymentGateReportV1) -> Result<String, DeploymentCliRenderError> {
    let mut lines = vec![
        format!("schema_version: {}", report.schema_version),
        format!("decision: {}", report.decision),
        format!("artifact.commit_sha: {}", report.artifact.commit_sha),
        format!(
            "artifact.package_version: {}",
            report.artifact.package_version
        ),
    ];
    if let Some(interface) = &report.interface {
        let rendered = serde_json::to_string(interface)
            .map_err(|_| DeploymentCliRenderError::Serialization)?;
        lines.push(format!("interface: {rendered}"));
    } else {
        lines.push("interface: none".to_owned());
    }
    append_gate(&mut lines, "bundle", &report.gates.bundle);
    append_gate(&mut lines, "layout", &report.gates.layout);
    append_gate(&mut lines, "service", &report.gates.service);
    append_gate(&mut lines, "authorization", &report.gates.authorization);
    append_gate(&mut lines, "platform", &report.gates.platform);
    append_gate(&mut lines, "evidence", &report.gates.evidence);
    append_gate(&mut lines, "performance", &report.gates.performance);
    let findings = serde_json::to_string(&report.findings)
        .map_err(|_| DeploymentCliRenderError::Serialization)?;
    lines.push(format!("findings: {findings}"));
    if let Some(plan) = &report.canary_plan {
        let rendered =
            serde_json::to_string(plan).map_err(|_| DeploymentCliRenderError::Serialization)?;
        lines.push(format!("canary_plan: {rendered}"));
    } else {
        lines.push("canary_plan: none".to_owned());
    }
    lines.push(format!(
        "captured_at_unix_ms: {}",
        report.captured_at_unix_ms
    ));
    lines.push(format!(
        "mutations_performed: {}",
        report.mutations_performed
    ));
    Ok(lines.join("\n"))
}

fn append_gate(lines: &mut Vec<String>, name: &str, gate: &l2_loop_core::DeploymentGateSummaryV1) {
    let state = match gate.state {
        DeploymentGateStateV1::Passed => "passed",
        DeploymentGateStateV1::Blocked => "blocked",
        DeploymentGateStateV1::Unavailable => "unavailable",
        DeploymentGateStateV1::NotApplicable => "not_applicable",
    };
    lines.push(format!("gates.{name}.state: {state}"));
    lines.push(format!(
        "gates.{name}.finding_codes: {}",
        gate.finding_codes.join(",")
    ));
}

fn decision_exit_code(decision: DeploymentDecisionV1) -> u8 {
    match decision {
        DeploymentDecisionV1::StagingReady | DeploymentDecisionV1::CanaryCandidate => {
            EXIT_DEPLOYMENT_SUCCESS
        }
        DeploymentDecisionV1::Blocked => EXIT_DEPLOYMENT_BLOCKED,
    }
}

fn internal_failure() -> RenderedDeploymentOutput {
    RenderedDeploymentOutput {
        stdout: String::new(),
        stderr: "deployment check unavailable".to_owned(),
        exit_code: EXIT_DEPLOYMENT_INTERNAL,
    }
}
