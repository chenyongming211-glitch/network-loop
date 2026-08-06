use std::process::ExitCode;

use clap::Parser;
use l2_loop_cli::{Cli, ParsedCli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match ParsedCli::try_from(cli) {
        Ok(_parsed) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
