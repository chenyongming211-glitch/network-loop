use thiserror::Error;

use crate::{PortError, ResourceLimits};

const MEMLOCK_LABEL: &str = "Max locked memory";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedMemlockLimits {
    pub soft_bytes: Option<u64>,
    pub hard_bytes: Option<u64>,
}

impl ParsedMemlockLimits {
    pub const fn can_raise_to(self, required_bytes: u64) -> bool {
        let soft_sufficient = match self.soft_bytes {
            None => true,
            Some(soft_bytes) => soft_bytes >= required_bytes,
        };
        let hard_sufficient = match self.hard_bytes {
            None => true,
            Some(hard_bytes) => hard_bytes >= required_bytes,
        };

        soft_sufficient || hard_sufficient
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LimitsParseError {
    #[error("max locked memory limit is missing")]
    MissingMemlock,
    #[error("max locked memory limit is malformed")]
    MalformedMemlock,
    #[error("max locked memory soft limit exceeds the hard limit")]
    InconsistentMemlock,
}

pub fn parse_memlock_limits(snapshot: &str) -> Result<ParsedMemlockLimits, LimitsParseError> {
    let values = snapshot
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(MEMLOCK_LABEL))
        .ok_or(LimitsParseError::MissingMemlock)?;
    let mut fields = values.split_ascii_whitespace();
    let soft_bytes = parse_limit(fields.next())?;
    let hard_bytes = parse_limit(fields.next())?;
    if fields.next() != Some("bytes") || fields.next().is_some() {
        return Err(LimitsParseError::MalformedMemlock);
    }
    if matches!((soft_bytes, hard_bytes), (Some(soft), Some(hard)) if soft > hard) {
        return Err(LimitsParseError::InconsistentMemlock);
    }

    Ok(ParsedMemlockLimits {
        soft_bytes,
        hard_bytes,
    })
}

pub fn artifact_architecture_matches(host_architecture: &str, artifact_target: &str) -> bool {
    !host_architecture.is_empty() && artifact_target.split('-').next() == Some(host_architecture)
}

fn parse_limit(value: Option<&str>) -> Result<Option<u64>, LimitsParseError> {
    match value {
        Some("unlimited") => Ok(None),
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| LimitsParseError::MalformedMemlock),
        None => Err(LimitsParseError::MalformedMemlock),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessResourceLimits;

impl ResourceLimits for ProcessResourceLimits {
    fn raise_memlock_to_infinity(&mut self) -> Result<(), PortError> {
        let limit = nix::libc::rlimit {
            rlim_cur: nix::libc::RLIM_INFINITY,
            rlim_max: nix::libc::RLIM_INFINITY,
        };
        let result = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_MEMLOCK, &limit) };
        if result == 0 {
            Ok(())
        } else {
            Err(PortError::Adapter(
                "failed to raise the process memlock limit".to_owned(),
            ))
        }
    }
}
