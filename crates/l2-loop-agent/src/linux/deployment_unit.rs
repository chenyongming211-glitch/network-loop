use std::collections::BTreeSet;

use crate::ServiceUnitSnapshotV1;

pub const MAX_SERVICE_UNIT_BYTES: usize = 64 * 1024;

const UNIT_DIRECTIVES: [(&str, &str); 1] = [("Description", "L2 Loop Detection Agent")];

const SERVICE_DIRECTIVES: [(&str, &str); 24] = [
    ("Type", "simple"),
    ("ExecStart", "/usr/libexec/l2-loop/l2-loopd"),
    ("User", "root"),
    ("Group", "root"),
    ("RuntimeDirectory", "l2-loop"),
    ("RuntimeDirectoryMode", "0700"),
    ("UMask", "0077"),
    ("NoNewPrivileges", "yes"),
    ("PrivateTmp", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectControlGroups", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("RestrictRealtime", "yes"),
    ("LockPersonality", "yes"),
    ("MemoryDenyWriteExecute", "yes"),
    (
        "CapabilityBoundingSet",
        "CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE",
    ),
    ("RestrictAddressFamilies", "AF_UNIX AF_NETLINK"),
    (
        "ReadWritePaths",
        "/run/l2-loop /var/lib/l2-loop/evidence/v1",
    ),
    ("TimeoutStopSec", "10s"),
    ("Restart", "no"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceUnitError {
    #[error("service unit contract is invalid")]
    InvalidContract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Unit,
    Service,
}

pub fn validate_service_unit(bytes: &[u8]) -> Result<ServiceUnitSnapshotV1, ServiceUnitError> {
    if bytes.is_empty() || bytes.len() > MAX_SERVICE_UNIT_BYTES || bytes.last() != Some(&b'\n') {
        return Err(ServiceUnitError::InvalidContract);
    }
    let input = std::str::from_utf8(bytes).map_err(|_| ServiceUnitError::InvalidContract)?;
    if input
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\0' | b'\\'))
    {
        return Err(ServiceUnitError::InvalidContract);
    }

    let mut section = None;
    let mut unit_seen = false;
    let mut service_seen = false;
    let mut blank_between_sections = false;
    let mut directives = BTreeSet::new();

    for line in input.lines() {
        if line.is_empty() {
            if section == Some(Section::Unit)
                && unit_seen
                && !service_seen
                && !blank_between_sections
            {
                blank_between_sections = true;
                continue;
            }
            return Err(ServiceUnitError::InvalidContract);
        }
        if line.trim() != line || line.starts_with('#') || line.starts_with(';') {
            return Err(ServiceUnitError::InvalidContract);
        }
        match line {
            "[Unit]" if section.is_none() && !unit_seen => {
                section = Some(Section::Unit);
                unit_seen = true;
                continue;
            }
            "[Service]" if section == Some(Section::Unit) && blank_between_sections => {
                section = Some(Section::Service);
                service_seen = true;
                continue;
            }
            _ if line.starts_with('[') || line.ends_with(']') => {
                return Err(ServiceUnitError::InvalidContract);
            }
            _ => {}
        }

        let (key, value) = line
            .split_once('=')
            .ok_or(ServiceUnitError::InvalidContract)?;
        if key.is_empty()
            || value.is_empty()
            || value.contains('=')
            || !directives.insert((section, key))
            || !directive_is_exact(section, key, value)
        {
            return Err(ServiceUnitError::InvalidContract);
        }
    }

    if !unit_seen
        || !service_seen
        || directives.len() != UNIT_DIRECTIVES.len() + SERVICE_DIRECTIVES.len()
    {
        return Err(ServiceUnitError::InvalidContract);
    }
    Ok(ServiceUnitSnapshotV1::valid())
}

fn directive_is_exact(section: Option<Section>, key: &str, value: &str) -> bool {
    let expected = match section {
        Some(Section::Unit) => UNIT_DIRECTIVES.as_slice(),
        Some(Section::Service) => SERVICE_DIRECTIVES.as_slice(),
        None => return false,
    };
    expected
        .iter()
        .any(|(expected_key, expected_value)| key == *expected_key && value == *expected_value)
}
