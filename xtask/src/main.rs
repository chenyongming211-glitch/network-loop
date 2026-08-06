use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("build-ebpf"), None) => build_ebpf(),
        _ => {
            eprintln!("usage: cargo xtask build-ebpf");
            ExitCode::from(2)
        }
    }
}
fn build_ebpf() -> ExitCode {
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "-Z",
            "build-std=core",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "--package",
            "l2-loop-ebpf",
        ])
        .status();

    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("failed to start the eBPF build: {error}");
            ExitCode::FAILURE
        }
    }
}
