fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--run-id" {
        eprintln!("usage: l2-loop-diagnostic --run-id <generated-run-id>");
        return std::process::ExitCode::from(2);
    }
    #[cfg(target_os = "linux")]
    match xtask::diagnostic_runtime::run(&args[1]) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("DX_RUNTIME: Linux required");
        std::process::ExitCode::FAILURE
    }
}
