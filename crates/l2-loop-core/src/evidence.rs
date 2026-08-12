use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
    BaselineSummary, DetectionReport, DetectionState, DetectionTransitionReason,
    FingerprintWindowReport, InterfaceName, ObservationCounters, ObservationHealth,
    RATE_WINDOW_COUNT, StatusRateWindow, VlanVisibility,
};

pub const EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const EVIDENCE_MAX_STORE_BYTES: u64 = 1_073_741_824;
pub const EVIDENCE_MAX_EVENTS: usize = 1_000;
pub const EVIDENCE_MAX_REVISIONS_PER_EVENT: u64 = 16;
pub const EVIDENCE_MAX_REVISION_BYTES: u64 = 1_048_576;
pub const EVIDENCE_MAX_EVENT_BYTES: u64 = 16_777_216;
pub const EVIDENCE_LIST_DEFAULT_LIMIT: u16 = 50;
pub const EVIDENCE_LIST_MAX_LIMIT: u16 = 200;
pub const INCIDENT_OUTPUT_QUEUE_CAPACITY: usize = 32;

const EVENT_ID_BYTES: usize = 16;
const EVENT_ID_TEXT_BYTES: usize = EVENT_ID_BYTES * 2;
const CURSOR_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId([u8; EVENT_ID_BYTES]);

impl EventId {
    pub const fn from_bytes(bytes: [u8; EVENT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> &[u8; EVENT_ID_BYTES] {
        &self.0
    }
}

impl FromStr for EventId {
    type Err = EvidenceContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != EVENT_ID_TEXT_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(EvidenceContractError::InvalidEventId);
        }
        let mut bytes = [0_u8; EVENT_ID_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = [0_u8; EVENT_ID_TEXT_BYTES];
        for (index, byte) in self.0.iter().copied().enumerate() {
            text[index * 2] = HEX[usize::from(byte >> 4)];
            text[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        let text = std::str::from_utf8(&text).map_err(|_| fmt::Error)?;
        formatter.write_str(text)
    }
}

impl Serialize for EventId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

fn nibble(byte: u8) -> Result<u8, EvidenceContractError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(EvidenceContractError::InvalidEventId),
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceContractError {
    #[error("event ID must be 32 lowercase hexadecimal characters")]
    InvalidEventId,
    #[error("evidence list limit must be in the range 1-200")]
    InvalidListLimit,
    #[error("evidence cursor is invalid or belongs to another filter")]
    InvalidCursor,
    #[error("incident evidence model violates a fixed bound")]
    InvalidModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Information,
    Notice,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertCode {
    StormConfirmed,
    ExternalLoopSuspected,
    ExternalLoopHighConfidence,
    IncidentCooldown,
    IncidentClosed,
    GenerationEnded,
    OutputDegraded,
}

impl AlertCode {
    pub const fn for_state(state: DetectionState) -> Option<Self> {
        match state {
            DetectionState::IngressStormConfirmed
            | DetectionState::EgressStormConfirmed
            | DetectionState::BidirectionalStormConfirmed => Some(Self::StormConfirmed),
            DetectionState::ExternalLoopSuspected => Some(Self::ExternalLoopSuspected),
            DetectionState::ExternalLoopHighConfidence => Some(Self::ExternalLoopHighConfidence),
            DetectionState::Cooldown => Some(Self::IncidentCooldown),
            DetectionState::Normal => Some(Self::IncidentClosed),
            DetectionState::WarmingUp | DetectionState::Unavailable => None,
        }
    }

    pub const fn severity(self) -> AlertSeverity {
        match self {
            Self::StormConfirmed | Self::ExternalLoopSuspected => AlertSeverity::Notice,
            Self::ExternalLoopHighConfidence | Self::OutputDegraded => AlertSeverity::Warning,
            Self::IncidentCooldown | Self::IncidentClosed | Self::GenerationEnded => {
                AlertSeverity::Information
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Stored,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrity {
    Valid,
    Corrupt,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputHealthState {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSinkMode {
    Journald,
    StderrJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputHealth {
    pub state: OutputHealthState,
    pub store_available: bool,
    pub corrupt_object_count: u16,
    pub incomplete_object_count: u16,
    pub unknown_object_count: u16,
    pub alert_sink: AlertSinkMode,
    pub last_error_code: Option<String>,
    pub dropped_job_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRevisionV1 {
    pub schema_version: u16,
    pub event_id: EventId,
    pub revision: u64,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub interface_generation: u64,
    pub transition_sequence: u64,
    pub previous_state: DetectionState,
    pub current_state: DetectionState,
    pub transition_reason: DetectionTransitionReason,
    pub opened_at_unix_ms: u64,
    pub occurred_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    pub alert_code: AlertCode,
    pub severity: AlertSeverity,
    pub evidence_status: EvidenceStatus,
    pub xdp_ingress: ObservationCounters,
    pub tc_egress: ObservationCounters,
    pub rate_windows: [StatusRateWindow; RATE_WINDOW_COUNT],
    pub baseline: BaselineSummary,
    pub fingerprint_window: FingerprintWindowReport,
    pub detection: DetectionReport,
    pub observation_health: ObservationHealth,
    pub vlan_visibility: VlanVisibility,
    pub last_error_code: Option<String>,
}

impl IncidentRevisionV1 {
    pub fn validate(&self) -> Result<(), EvidenceContractError> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.revision == 0
            || self.revision > EVIDENCE_MAX_REVISIONS_PER_EVENT
            || self.ifindex == 0
            || self.interface_generation == 0
            || self.transition_sequence == 0
            || self.opened_at_unix_ms > self.occurred_at_unix_ms
            || self
                .closed_at_unix_ms
                .is_some_and(|closed| closed < self.opened_at_unix_ms)
            || self.severity != self.alert_code.severity()
        {
            return Err(EvidenceContractError::InvalidModel);
        }
        self.detection
            .validate()
            .map_err(|_| EvidenceContractError::InvalidModel)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifestV1 {
    pub schema_version: u16,
    pub event_id: EventId,
    pub revision: u64,
    pub current_state: DetectionState,
    pub evidence_file: String,
    pub evidence_bytes: u64,
    pub evidence_sha256: String,
    pub total_bytes: u64,
    pub package_version: String,
}

impl EvidenceManifestV1 {
    pub fn validate(&self) -> Result<(), EvidenceContractError> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.revision == 0
            || self.revision > EVIDENCE_MAX_REVISIONS_PER_EVENT
            || self.evidence_file != "evidence.json"
            || self.evidence_bytes == 0
            || self.evidence_bytes > EVIDENCE_MAX_REVISION_BYTES
            || self.total_bytes < self.evidence_bytes
            || self.total_bytes > EVIDENCE_MAX_EVENT_BYTES
            || self.evidence_sha256.len() != 64
            || !self
                .evidence_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(EvidenceContractError::InvalidModel);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummaryV1 {
    pub schema_version: u16,
    pub event_id: EventId,
    pub latest_revision: u64,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub interface_generation: u64,
    pub current_state: DetectionState,
    pub alert_code: AlertCode,
    pub severity: AlertSeverity,
    pub opened_at_unix_ms: u64,
    pub last_transition_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    pub bundle_bytes: u64,
    pub integrity: EvidenceIntegrity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDetailV1 {
    pub summary: EvidenceSummaryV1,
    pub latest: IncidentRevisionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceCursor {
    filter_hash: u64,
    last_transition_at_unix_ms: u64,
    event_id: EventId,
}

impl EvidenceCursor {
    pub fn new(
        interface: Option<&InterfaceName>,
        last_transition_at_unix_ms: u64,
        event_id: EventId,
    ) -> Self {
        Self {
            filter_hash: interface_filter_hash(interface),
            last_transition_at_unix_ms,
            event_id,
        }
    }

    pub fn parse_for(
        value: &str,
        interface: Option<&InterfaceName>,
    ) -> Result<Self, EvidenceContractError> {
        if !value.is_ascii() || value.len() > 80 {
            return Err(EvidenceContractError::InvalidCursor);
        }
        let mut fields = value.split('-');
        let version = fields.next().ok_or(EvidenceContractError::InvalidCursor)?;
        let timestamp = fields.next().ok_or(EvidenceContractError::InvalidCursor)?;
        let event_id = fields.next().ok_or(EvidenceContractError::InvalidCursor)?;
        let filter = fields.next().ok_or(EvidenceContractError::InvalidCursor)?;
        if version != CURSOR_VERSION || fields.next().is_some() {
            return Err(EvidenceContractError::InvalidCursor);
        }
        let parsed = Self {
            filter_hash: parse_fixed_hex_u64(filter)?,
            last_transition_at_unix_ms: parse_fixed_hex_u64(timestamp)?,
            event_id: event_id
                .parse()
                .map_err(|_| EvidenceContractError::InvalidCursor)?,
        };
        if parsed.filter_hash != interface_filter_hash(interface) {
            return Err(EvidenceContractError::InvalidCursor);
        }
        Ok(parsed)
    }

    pub const fn last_transition_at_unix_ms(&self) -> u64 {
        self.last_transition_at_unix_ms
    }

    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
}

impl fmt::Display for EvidenceCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{CURSOR_VERSION}-{:016x}-{}-{:016x}",
            self.last_transition_at_unix_ms, self.event_id, self.filter_hash
        )
    }
}

fn parse_fixed_hex_u64(value: &str) -> Result<u64, EvidenceContractError> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(EvidenceContractError::InvalidCursor);
    }
    u64::from_str_radix(value, 16).map_err(|_| EvidenceContractError::InvalidCursor)
}

fn interface_filter_hash(interface: Option<&InterfaceName>) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325_u64;
    let bytes: &[u8] = interface.map_or(b"-", |name| name.as_str().as_bytes());
    for byte in bytes {
        value = (value ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceListQuery {
    pub interface: Option<InterfaceName>,
    pub limit: u16,
    pub cursor: Option<EvidenceCursor>,
}

impl EvidenceListQuery {
    pub fn new(
        interface: Option<InterfaceName>,
        limit: Option<u16>,
        cursor: Option<EvidenceCursor>,
    ) -> Result<Self, EvidenceContractError> {
        let limit = limit.unwrap_or(EVIDENCE_LIST_DEFAULT_LIMIT);
        if !(1..=EVIDENCE_LIST_MAX_LIMIT).contains(&limit) {
            return Err(EvidenceContractError::InvalidListLimit);
        }
        if cursor
            .is_some_and(|value| value.filter_hash != interface_filter_hash(interface.as_ref()))
        {
            return Err(EvidenceContractError::InvalidCursor);
        }
        Ok(Self {
            interface,
            limit,
            cursor,
        })
    }
}
