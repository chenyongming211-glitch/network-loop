use std::process::ExitCode;

use clap::Parser;
use l2_loop_cli::{
    Cli, EXIT_USAGE, OutputFormat, ParsedCli, RenderedOutput, UnixControlClient, render_response,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let parsed = match ParsedCli::try_from(cli) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let format = OutputFormat::from_json(parsed.json);
    let output = match UnixControlClient::default().execute(parsed.command).await {
        Ok(response) => render_response(response, format),
        Err(error) => RenderedOutput::failure(error.to_string()),
    };

    if !output.stdout.is_empty() {
        println!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprintln!("{}", output.stderr);
    }
    ExitCode::from(output.exit_code)
}
