use std::{path::Path, process::ExitCode};

use l2_loop_agent::host_acceptance::{
    capture_host_identity, load_exact_journal, read_owned_counters, verify_owned_hooks,
};
use l2_loop_core::InterfaceName;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    match args.as_slice() {
        [command] if command == "snapshot" => {
            let snapshot = capture_host_identity().map_err(|error| error.to_string())?;
            serde_json::to_string(&snapshot).map_err(|_| "failed to render host identity".to_owned())
        }
        [command, journal_flag, journal, interface_flag, interface]
            if command == "verify-owned"
                && journal_flag == "--journal"
                && interface_flag == "--interface" =>
        {
            let record = load_exact_journal(Path::new(journal)).map_err(|error| error.to_string())?;
            let interface = InterfaceName::new(interface)
                .map_err(|_| "isolated interface name is invalid".to_owned())?;
            let snapshot = capture_host_identity().map_err(|error| error.to_string())?;
            verify_owned_hooks(&snapshot, &record, &interface)
                .map_err(|error| error.to_string())?;
            Ok(String::new())
        }
        [command, journal_flag, journal]
            if command == "counters" && journal_flag == "--journal" =>
        {
            let record = load_exact_journal(Path::new(journal)).map_err(|error| error.to_string())?;
            let counters = read_owned_counters(&record).map_err(|error| error.to_string())?;
            Ok(counters
                .iter()
                .map(|value| format!("{} {} {}", value.role, value.packets, value.bytes))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        _ => Err("usage: l2-loop-hostcheck snapshot | verify-owned --journal <PATH> --interface <NAME> | counters --journal <PATH>".to_owned()),
    }
}
