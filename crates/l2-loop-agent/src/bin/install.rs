use std::process::ExitCode;

use l2_loop_agent::{
    EXIT_INSTALLATION_INTERNAL, EXIT_INSTALLATION_SUCCESS, EXIT_INSTALLATION_USAGE,
    InstallServiceError, InstallationCliAction, InstallationCliSourcePaths,
    InstallationCommandRunner, execute_installation_command, installation_help,
    parse_installation_args,
};
use l2_loop_core::InstallReportV1;

fn main() -> ExitCode {
    let action = match parse_installation_args(std::env::args().skip(1)) {
        Ok(action) => action,
        Err(_) => {
            eprintln!("{}", installation_help());
            return ExitCode::from(EXIT_INSTALLATION_USAGE);
        }
    };
    let InstallationCliAction::Run { command, format } = action else {
        println!("{}", installation_help());
        return ExitCode::from(EXIT_INSTALLATION_SUCCESS);
    };

    let mut runner = ProductionInstallationRunner;
    let output = execute_installation_command(
        &mut runner,
        command,
        format,
        nix::unistd::geteuid().as_raw(),
    );
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprintln!("{}", output.stderr);
    }
    ExitCode::from(output.exit_code)
}

struct ProductionInstallationRunner;

impl InstallationCommandRunner for ProductionInstallationRunner {
    fn plan(
        &mut self,
        _source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        unavailable()
    }

    fn apply(
        &mut self,
        _source: &InstallationCliSourcePaths,
    ) -> Result<InstallReportV1, InstallServiceError> {
        unavailable()
    }

    fn status(&mut self) -> Result<InstallReportV1, InstallServiceError> {
        unavailable()
    }

    fn rollback(
        &mut self,
        _transaction_id: &str,
        _authorization: &std::path::Path,
    ) -> Result<InstallReportV1, InstallServiceError> {
        unavailable()
    }
}

fn unavailable<T>() -> Result<T, InstallServiceError> {
    Err(InstallServiceError::InputUnavailable)
}

const _: u8 = EXIT_INSTALLATION_INTERNAL;
