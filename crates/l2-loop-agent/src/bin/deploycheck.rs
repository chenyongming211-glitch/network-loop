use std::process::ExitCode;

use l2_loop_agent::{
    DeploymentCliAction, DeploymentGateService, SystemClock, EXIT_DEPLOYMENT_INTERNAL,
    EXIT_DEPLOYMENT_SUCCESS, EXIT_DEPLOYMENT_USAGE, deployment_help, execute_deployment_command,
    linux::{
        deployment_fs::LinuxDeploymentFilesystem,
        deployment_platform::SystemLinuxDeploymentPlatformInspector,
    },
    parse_deployment_args,
};
use l2_loop_core::DeploymentArtifactIdentityV1;

fn main() -> ExitCode {
    let action = match parse_deployment_args(std::env::args().skip(1)) {
        Ok(action) => action,
        Err(_) => {
            eprintln!("{}", deployment_help());
            return ExitCode::from(EXIT_DEPLOYMENT_USAGE);
        }
    };
    let DeploymentCliAction::Run { command, format } = action else {
        println!("{}", deployment_help());
        return ExitCode::from(EXIT_DEPLOYMENT_SUCCESS);
    };

    let Some(artifact) = embedded_artifact_identity() else {
        eprintln!("deployment check unavailable");
        return ExitCode::from(EXIT_DEPLOYMENT_INTERNAL);
    };
    let filesystem = match LinuxDeploymentFilesystem::new(artifact) {
        Ok(filesystem) => filesystem,
        Err(_) => {
            eprintln!("deployment check unavailable");
            return ExitCode::from(EXIT_DEPLOYMENT_INTERNAL);
        }
    };
    let platform = SystemLinuxDeploymentPlatformInspector::system();
    let clock = SystemClock::new();
    let mut service = DeploymentGateService::new(filesystem, platform, clock);
    let output = execute_deployment_command(&mut service, command, format);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprintln!("{}", output.stderr);
    }
    ExitCode::from(output.exit_code)
}

fn embedded_artifact_identity() -> Option<DeploymentArtifactIdentityV1> {
    let commit_sha = option_env!("L2_LOOP_BUILD_COMMIT_SHA")?;
    DeploymentArtifactIdentityV1::new(commit_sha, env!("CARGO_PKG_VERSION")).ok()
}
