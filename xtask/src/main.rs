use std::{
    path::Path,
    process::{Command, ExitCode},
};

use xtask::{
    bundle::{BundleInputs, create_bundle},
    ebpf::build_ebpf_args,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("build-ebpf") if args.len() == 1 => build_ebpf(),
        Some("bundle") => build_bundle(&args[1..]),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn build_ebpf() -> ExitCode {
    let status = Command::new("cargo").args(build_ebpf_args()).status();

    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("failed to start the eBPF build: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build_bundle(args: &[String]) -> ExitCode {
    let [
        commit_flag,
        commit_sha,
        daemon_flag,
        daemon,
        cli_flag,
        cli,
        deployment_checker_flag,
        deployment_checker,
        installer_flag,
        installer,
        host_check_flag,
        host_check,
        ebpf_flag,
        ebpf,
        service_unit_flag,
        service_unit,
        authorization_example_flag,
        authorization_example,
        output_flag,
        output,
    ] = args
    else {
        print_usage();
        return ExitCode::from(2);
    };
    if commit_flag != "--commit-sha"
        || daemon_flag != "--daemon"
        || cli_flag != "--cli"
        || deployment_checker_flag != "--deploy-checker"
        || installer_flag != "--installer"
        || host_check_flag != "--host-check"
        || ebpf_flag != "--ebpf"
        || service_unit_flag != "--service-unit"
        || authorization_example_flag != "--authorization-example"
        || output_flag != "--output"
    {
        print_usage();
        return ExitCode::from(2);
    }

    let inputs = BundleInputs {
        commit_sha,
        package_version: env!("CARGO_PKG_VERSION"),
        daemon: Path::new(daemon),
        cli: Path::new(cli),
        deployment_checker: Path::new(deployment_checker),
        installer: Path::new(installer),
        host_checker: Path::new(host_check),
        ebpf: Path::new(ebpf),
        service_unit: Path::new(service_unit),
        authorization_example: Path::new(authorization_example),
        output_dir: Path::new(output),
    };
    match create_bundle(&inputs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed to create release bundle: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("usage: cargo xtask build-ebpf");
    eprintln!(
        "       cargo xtask bundle --commit-sha <SHA> --daemon <PATH> --cli <PATH> --deploy-checker <PATH> --installer <PATH> --host-check <PATH> --ebpf <PATH> --service-unit <PATH> --authorization-example <PATH> --output <DIR>"
    );
}
