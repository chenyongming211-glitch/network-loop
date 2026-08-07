use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "l2-loopctl",
    version,
    about = "L2 Loop Detection Agent control client"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    Preflight(PreflightArgs),
    /// Attach only to a generated veth used for isolated verification.
    #[command(about = "Attach for generated isolated verification only")]
    IsolatedAttach(IsolatedAttachArgs),
    /// Detach only state owned by one generated isolated verification run.
    #[command(about = "Detach for generated isolated verification only")]
    IsolatedDetach(IsolatedDetachArgs),
    Observe(ObserveArgs),
    Status(StatusArgs),
    Probe(ProbeArgs),
    Police(PoliceArgs),
    Evidence(EvidenceArgs),
}

#[derive(Debug, Args)]
pub struct IsolatedAttachArgs {
    #[arg(long)]
    pub interface: String,
    #[arg(long)]
    pub run_id: String,
}

#[derive(Debug, Args)]
pub struct IsolatedDetachArgs {
    #[arg(long)]
    pub run_id: String,
}

#[derive(Debug, Args)]
pub struct PreflightArgs {
    #[arg(long)]
    pub interface: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ObserveArgs {
    #[arg(long)]
    pub interface: String,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProbeArgs {
    #[arg(long)]
    pub interface: String,
    #[arg(long, value_enum)]
    pub scope: ProbeScopeArg,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=4094))]
    pub vlan: Option<u16>,
    #[arg(long, default_value = "2s")]
    pub timeout: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProbeScopeArg {
    External,
    Internal,
}

#[derive(Debug, Args)]
pub struct PoliceArgs {
    #[command(subcommand)]
    pub command: PoliceCommand,
}

#[derive(Debug, Subcommand)]
pub enum PoliceCommand {
    Apply(PoliceApplyArgs),
    Disable(PoliceDisableArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("rate")
        .required(true)
        .multiple(true)
        .args(["pps", "bps"])
))]
pub struct PoliceApplyArgs {
    #[arg(long)]
    pub interface: String,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=4094))]
    pub vlan: Option<u16>,
    #[arg(long, value_enum)]
    pub class: PolicyClassArg,
    #[arg(long)]
    pub pps: Option<u64>,
    #[arg(long)]
    pub bps: Option<u64>,
    #[arg(long)]
    pub ttl: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PolicyClassArg {
    Broadcast,
    Ipv4Multicast,
    Ipv6Multicast,
    OtherMulticast,
    LinkLocalControl,
}

#[derive(Debug, Args)]
pub struct PoliceDisableArgs {
    #[arg(long)]
    pub rule: String,
}

#[derive(Debug, Args)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    pub command: EvidenceCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    List(EvidenceListArgs),
    Show(EvidenceShowArgs),
}

#[derive(Debug, Args)]
pub struct EvidenceListArgs {
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EvidenceShowArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub json: bool,
}
