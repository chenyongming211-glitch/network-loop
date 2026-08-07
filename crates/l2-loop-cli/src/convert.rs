use l2_loop_core::{
    AgentCommand, DomainError, InterfaceName, PolicyRequest, ProbeRequest, ProbeScope, TrafficClass,
};
use l2_loop_agent::ownership::RunId;
use thiserror::Error;

use crate::args::{Cli, CliCommand, EvidenceCommand, PoliceCommand, PolicyClassArg, ProbeScopeArg};

#[derive(Debug)]
pub struct ParsedCli {
    pub command: AgentCommand,
    pub json: bool,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error("invalid duration {value}: {source}")]
    InvalidDuration {
        value: String,
        source: humantime::DurationError,
    },
    #[error("invalid isolated run ID: {0}")]
    InvalidRunId(String),
}

impl TryFrom<Cli> for ParsedCli {
    type Error = CliError;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let (command, json) = match cli.command {
            CliCommand::Preflight(args) => (
                AgentCommand::Preflight {
                    interface: InterfaceName::new(args.interface)?,
                },
                args.json,
            ),
            CliCommand::IsolatedAttach(args) => (
                AgentCommand::IsolatedAttach {
                    interface: InterfaceName::new(args.interface)?,
                    run_id: validate_run_id(args.run_id)?,
                },
                false,
            ),
            CliCommand::IsolatedDetach(args) => (
                AgentCommand::IsolatedDetach {
                    run_id: validate_run_id(args.run_id)?,
                },
                false,
            ),
            CliCommand::Observe(args) => (
                AgentCommand::Observe {
                    interface: InterfaceName::new(args.interface)?,
                },
                false,
            ),
            CliCommand::Status(args) => (
                AgentCommand::Status {
                    interface: args.interface.map(InterfaceName::new).transpose()?,
                },
                args.json,
            ),
            CliCommand::Probe(args) => {
                let request = ProbeRequest::new(
                    args.interface,
                    args.scope.into(),
                    args.vlan,
                    parse_duration(args.timeout)?,
                )?;
                (AgentCommand::Probe { request }, false)
            }
            CliCommand::Police(args) => match args.command {
                PoliceCommand::Apply(args) => {
                    let request = PolicyRequest::new(
                        args.interface,
                        args.vlan,
                        args.class.into(),
                        args.pps,
                        args.bps,
                        parse_duration(args.ttl)?,
                    )?;
                    (AgentCommand::ApplyPolicy { request }, false)
                }
                PoliceCommand::Disable(args) => {
                    (AgentCommand::DisablePolicy { rule_id: args.rule }, false)
                }
            },
            CliCommand::Evidence(args) => match args.command {
                EvidenceCommand::List(args) => (
                    AgentCommand::EvidenceList {
                        interface: args.interface.map(InterfaceName::new).transpose()?,
                    },
                    args.json,
                ),
                EvidenceCommand::Show(args) => (
                    AgentCommand::EvidenceShow {
                        evidence_id: args.id,
                    },
                    args.json,
                ),
            },
        };

        Ok(Self { command, json })
    }
}

fn validate_run_id(value: String) -> Result<String, CliError> {
    RunId::parse(&value).map_err(|error| CliError::InvalidRunId(error.to_string()))?;
    Ok(value)
}

impl From<ProbeScopeArg> for ProbeScope {
    fn from(value: ProbeScopeArg) -> Self {
        match value {
            ProbeScopeArg::External => Self::External,
            ProbeScopeArg::Internal => Self::Internal,
        }
    }
}

impl From<PolicyClassArg> for TrafficClass {
    fn from(value: PolicyClassArg) -> Self {
        match value {
            PolicyClassArg::Broadcast => Self::L2Broadcast,
            PolicyClassArg::Ipv4Multicast => Self::Ipv4Multicast,
            PolicyClassArg::Ipv6Multicast => Self::Ipv6Multicast,
            PolicyClassArg::OtherMulticast => Self::OtherL2Multicast,
            PolicyClassArg::LinkLocalControl => Self::LinkLocalControl,
        }
    }
}

fn parse_duration(value: String) -> Result<std::time::Duration, CliError> {
    humantime::parse_duration(&value).map_err(|source| CliError::InvalidDuration { value, source })
}
