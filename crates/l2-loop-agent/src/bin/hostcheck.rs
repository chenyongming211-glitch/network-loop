use std::{path::Path, process::ExitCode};

use l2_loop_agent::host_acceptance::{
    AcceptancePassThroughRequest, capture_host_identity, load_exact_journal, read_owned_counters,
    run_acceptance_pass_through, verify_owned_hooks,
};
use l2_loop_agent::linux::acceptance_fault::AcceptanceOnlyMode;
use l2_loop_agent::ownership::{JournalPath, RunId};
use l2_loop_core::InterfaceName;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if args
        .first()
        .is_some_and(|command| command == "pass-through")
    {
        run_pass_through(args)
    } else {
        run(args).map(|output| {
            if !output.is_empty() {
                println!("{output}");
            }
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run_pass_through(args: Vec<String>) -> Result<(), String> {
    let [
        command,
        acceptance_flag,
        mode,
        run_flag,
        run_id,
        evidence_flag,
        evidence_root,
        interface_flag,
        interface,
        ifindex_flag,
        ifindex,
    ] = args.as_slice()
    else {
        return Err(usage());
    };
    if command != "pass-through"
        || acceptance_flag != "--acceptance-only"
        || run_flag != "--run-id"
        || evidence_flag != "--evidence-root"
        || interface_flag != "--interface"
        || ifindex_flag != "--ifindex"
    {
        return Err(usage());
    }
    let mode = AcceptanceOnlyMode::parse(Some(mode.as_str())).map_err(|_| usage())?;
    let run_id = RunId::parse(run_id).map_err(|_| usage())?;
    let interface = InterfaceName::new(interface.as_str()).map_err(|_| usage())?;
    let ifindex = ifindex
        .parse::<u32>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(usage)?;
    let executable = std::env::current_exe().map_err(|_| usage())?;
    let artifact_root = executable.parent().ok_or_else(usage)?.to_path_buf();
    let journal_path = JournalPath::new(run_id.clone())
        .map_err(|_| usage())?
        .path()
        .to_path_buf();
    let request = AcceptancePassThroughRequest {
        mode,
        run_id,
        evidence_root: evidence_root.as_str().into(),
        artifact_root,
        interface,
        ifindex,
        journal_path,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_acceptance_pass_through(request, stdin.lock(), stdout.lock())
        .map_err(|error| error.to_string())
}

fn run(args: Vec<String>) -> Result<String, String> {
    match args.as_slice() {
        [command] if command == "snapshot" => {
            let snapshot = capture_host_identity().map_err(|error| error.to_string())?;
            serde_json::to_string(&snapshot)
                .map_err(|_| "failed to render host identity".to_owned())
        }
        [command, journal_flag, journal, interface_flag, interface]
            if command == "verify-owned"
                && journal_flag == "--journal"
                && interface_flag == "--interface" =>
        {
            let record =
                load_exact_journal(Path::new(journal)).map_err(|error| error.to_string())?;
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
            let record =
                load_exact_journal(Path::new(journal)).map_err(|error| error.to_string())?;
            let counters = read_owned_counters(&record).map_err(|error| error.to_string())?;
            Ok(counters
                .iter()
                .map(|value| format!("{} {} {}", value.role, value.packets, value.bytes))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: l2-loop-hostcheck snapshot | verify-owned --journal <PATH> --interface <NAME> | counters --journal <PATH> | pass-through --acceptance-only pass-through-v1 --run-id <RUN_ID> --evidence-root <PATH> --interface <NAME> --ifindex <IFINDEX>".to_owned()
}
