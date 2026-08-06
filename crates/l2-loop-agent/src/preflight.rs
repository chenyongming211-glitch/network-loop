use l2_loop_core::{AgentResult, InterfaceKind, InterfaceName, PreflightReport};

use crate::{PlatformInspector, PortError};

pub struct PreflightService<P> {
    inspector: P,
}

impl<P> PreflightService<P>
where
    P: PlatformInspector,
{
    pub fn new(inspector: P) -> Self {
        Self { inspector }
    }

    pub fn execute(&mut self, requested: &InterfaceName) -> Result<AgentResult, PortError> {
        let report = self.inspector.inspect(requested)?;
        validate_report(requested, &report)?;

        let PreflightReport {
            interface,
            kernel,
            bpf,
            findings,
            ..
        } = report;

        Ok(AgentResult::Preflight {
            report: PreflightReport::new(interface, kernel, bpf, findings),
        })
    }
}

fn validate_report(requested: &InterfaceName, report: &PreflightReport) -> Result<(), PortError> {
    if &report.interface.requested.name != requested {
        return invalid("requested interface does not match report");
    }

    if report.interface.isolated && report.interface.live_shared {
        return invalid("interface cannot be both isolated and live/shared");
    }

    if report.interface.kind == InterfaceKind::Bond && report.interface.bond.is_none() {
        return invalid("bond interface is missing bond details");
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.code.trim().is_empty())
    {
        return invalid("finding code must not be empty");
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.message.trim().is_empty())
    {
        return invalid("finding message must not be empty");
    }

    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, PortError> {
    Err(PortError::InvalidReport(message.into()))
}
