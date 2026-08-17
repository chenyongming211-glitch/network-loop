use std::process::ExitCode;

use l2_loop_agent::{
    EXIT_INSTALLATION_INTERNAL, EXIT_INSTALLATION_SUCCESS, EXIT_INSTALLATION_USAGE,
    InstallationCliAction, execute_installation_command, installation_help,
    linux::installation_runtime::SystemInstallationCommandRunner, parse_installation_args,
};

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

    let mut runner = match SystemInstallationCommandRunner::system() {
        Ok(runner) => runner,
        Err(_) => {
            eprintln!("installation unavailable");
            return ExitCode::from(EXIT_INSTALLATION_INTERNAL);
        }
    };
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
