use std::collections::BTreeMap;

use l2_loop_common::{FingerprintKey, direction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DomainError, FINGERPRINT_CAPACITY, FingerprintCounters, FingerprintEvidence, FingerprintReport,
    RateIdentity,
};

pub const DETECTION_FINGERPRINT_WINDOW_MS: u64 = 10_000;
pub const DETECTION_FINGERPRINT_FRESHNESS_MS: u64 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintWindowState {
    WarmingUp,
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintWindowReport {
    pub state: FingerprintWindowState,
    pub window_ms: u64,
    pub coverage_ms: u64,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
    pub captured_entry_count: u16,
    pub delta_relation_count: u16,
    pub repeated_relation_count: u16,
    pub egress_first_correlated_relation_count: u16,
    pub ingress: FingerprintCounters,
    pub egress: FingerprintCounters,
    pub dominant_ingress_packet_ratio_milli: Option<u64>,
    pub maximum_ingress_to_egress_packet_ratio_milli: Option<u64>,
    pub last_error_code: Option<String>,
}

impl FingerprintWindowReport {
    pub const fn warming() -> Self {
        Self {
            state: FingerprintWindowState::WarmingUp,
            window_ms: DETECTION_FINGERPRINT_WINDOW_MS,
            coverage_ms: 0,
            start_unix_ms: None,
            end_unix_ms: None,
            captured_entry_count: 0,
            delta_relation_count: 0,
            repeated_relation_count: 0,
            egress_first_correlated_relation_count: 0,
            ingress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            egress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            dominant_ingress_packet_ratio_milli: None,
            maximum_ingress_to_egress_packet_ratio_milli: None,
            last_error_code: None,
        }
    }

    pub fn unavailable(code: &str) -> Result<Self, DomainError> {
        validate_error_code(code)?;
        Ok(Self {
            state: FingerprintWindowState::Unavailable,
            last_error_code: Some(code.to_owned()),
            ..Self::warming()
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.window_ms != DETECTION_FINGERPRINT_WINDOW_MS
            || usize::from(self.captured_entry_count) > FINGERPRINT_CAPACITY
            || self.repeated_relation_count > self.delta_relation_count
            || self.egress_first_correlated_relation_count > self.delta_relation_count
            || self
                .dominant_ingress_packet_ratio_milli
                .is_some_and(|ratio| ratio > 1_000)
        {
            return Err(DomainError::InvalidObservation(
                "fingerprint window fixed contract is invalid",
            ));
        }

        let counters_are_empty = self.delta_relation_count == 0
            && self.repeated_relation_count == 0
            && self.egress_first_correlated_relation_count == 0
            && self.ingress == FingerprintCounters::default()
            && self.egress == FingerprintCounters::default()
            && self.dominant_ingress_packet_ratio_milli.is_none()
            && self.maximum_ingress_to_egress_packet_ratio_milli.is_none();
        match self.state {
            FingerprintWindowState::WarmingUp => {
                if self.coverage_ms != 0
                    || self.start_unix_ms.is_some()
                    || self.end_unix_ms.is_some()
                    || self.captured_entry_count != 0
                    || !counters_are_empty
                    || self.last_error_code.is_some()
                {
                    return Err(DomainError::InvalidObservation(
                        "warming fingerprint window contains evidence",
                    ));
                }
            }
            FingerprintWindowState::Ready => {
                if !(DETECTION_FINGERPRINT_WINDOW_MS..=DETECTION_FINGERPRINT_FRESHNESS_MS)
                    .contains(&self.coverage_ms)
                    || self.start_unix_ms.is_none()
                    || self.end_unix_ms.is_none()
                    || self.start_unix_ms > self.end_unix_ms
                    || self.last_error_code.is_some()
                    || (self.ingress.packets == 0
                        && self.dominant_ingress_packet_ratio_milli.is_some())
                    || (self.egress.packets == 0
                        && self.maximum_ingress_to_egress_packet_ratio_milli.is_some())
                {
                    return Err(DomainError::InvalidObservation(
                        "ready fingerprint window evidence is invalid",
                    ));
                }
            }
            FingerprintWindowState::Unavailable => {
                if self.coverage_ms != 0
                    || self.start_unix_ms.is_some()
                    || self.end_unix_ms.is_some()
                    || self.captured_entry_count != 0
                    || !counters_are_empty
                    || self.last_error_code.as_deref().is_none()
                {
                    return Err(DomainError::InvalidObservation(
                        "unavailable fingerprint window shape is invalid",
                    ));
                }
                validate_error_code(self.last_error_code.as_deref().unwrap_or_default())?;
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_error_code(code: &str) -> Result<(), DomainError> {
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(DomainError::InvalidObservation(
            "detection error code is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintWindowError {
    #[error("fingerprint scan identity or shape is invalid")]
    InvalidEvidence,
    #[error("fingerprint scan monotonic or wall clock regressed")]
    ClockRegression,
    #[error("fingerprint scan counter or timestamp regressed")]
    CounterRegression,
    #[error("fingerprint scan immutable value changed")]
    ImmutableValueChanged,
    #[error("fingerprint window aggregation overflowed")]
    CalculationFailed,
}

pub struct FingerprintWindowHistory {
    identity: RateIdentity,
    endpoint: Option<FingerprintEndpoint>,
    report: FingerprintWindowReport,
}

impl FingerprintWindowHistory {
    pub const fn new(identity: RateIdentity) -> Self {
        Self {
            identity,
            endpoint: None,
            report: FingerprintWindowReport::warming(),
        }
    }

    pub fn record_scan(
        &mut self,
        captured_at_monotonic_ns: u64,
        captured_at_unix_ms: u64,
        evidence: Vec<FingerprintEvidence>,
    ) -> Result<FingerprintWindowReport, FingerprintWindowError> {
        let entries = match validate_scan(self.identity, evidence) {
            Ok(entries) => entries,
            Err(error) => return self.fail(error),
        };
        let current = FingerprintEndpoint {
            captured_at_monotonic_ns,
            captured_at_unix_ms,
            entries,
        };
        let Some(previous) = self.endpoint.as_ref() else {
            self.endpoint = Some(current);
            self.report = FingerprintWindowReport::warming();
            return Ok(self.report.clone());
        };

        let Some(elapsed_ns) = captured_at_monotonic_ns
            .checked_sub(previous.captured_at_monotonic_ns)
            .filter(|elapsed| *elapsed != 0)
        else {
            return self.fail(FingerprintWindowError::ClockRegression);
        };
        if captured_at_unix_ms < previous.captured_at_unix_ms {
            return self.fail(FingerprintWindowError::ClockRegression);
        }
        let coverage_ms = elapsed_ns / 1_000_000;
        if coverage_ms < DETECTION_FINGERPRINT_WINDOW_MS {
            self.report = FingerprintWindowReport::warming();
            return Ok(self.report.clone());
        }
        if coverage_ms > DETECTION_FINGERPRINT_FRESHNESS_MS {
            self.endpoint = Some(current);
            self.report = FingerprintWindowReport::warming();
            return Ok(self.report.clone());
        }

        let report = match build_window(previous, &current, coverage_ms) {
            Ok(report) => report,
            Err(error) => return self.fail(error),
        };
        self.endpoint = Some(current);
        self.report = report.clone();
        Ok(report)
    }

    pub fn unavailable(&mut self, code: &str) -> Result<(), DomainError> {
        self.endpoint = None;
        self.report = FingerprintWindowReport::unavailable(code)?;
        Ok(())
    }

    pub fn cached_report(&self) -> &FingerprintWindowReport {
        &self.report
    }

    pub fn clear(&mut self) {
        self.endpoint = None;
        self.report = FingerprintWindowReport::warming();
    }

    fn fail<T>(&mut self, error: FingerprintWindowError) -> Result<T, FingerprintWindowError> {
        self.endpoint = None;
        self.report = FingerprintWindowReport::unavailable(error.stable_code())
            .expect("fixed fingerprint window error codes are valid");
        Err(error)
    }
}

impl FingerprintWindowError {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidEvidence => "DETECTION_FINGERPRINT_INVALID",
            Self::ClockRegression => "DETECTION_FINGERPRINT_CLOCK_REGRESSION",
            Self::CounterRegression => "DETECTION_FINGERPRINT_COUNTER_REGRESSION",
            Self::ImmutableValueChanged => "DETECTION_FINGERPRINT_IMMUTABLE_CHANGED",
            Self::CalculationFailed => "DETECTION_FINGERPRINT_CALCULATION_FAILED",
        }
    }
}

struct FingerprintEndpoint {
    captured_at_monotonic_ns: u64,
    captured_at_unix_ms: u64,
    entries: BTreeMap<ExactKey, FingerprintEvidence>,
}

fn validate_scan(
    identity: RateIdentity,
    evidence: Vec<FingerprintEvidence>,
) -> Result<BTreeMap<ExactKey, FingerprintEvidence>, FingerprintWindowError> {
    FingerprintReport::build(identity.ifindex(), identity.generation(), evidence.clone())
        .map_err(|_| FingerprintWindowError::InvalidEvidence)?;
    let mut entries = BTreeMap::new();
    for item in evidence {
        if entries.insert(ExactKey::from(item.key), item).is_some() {
            return Err(FingerprintWindowError::InvalidEvidence);
        }
    }
    Ok(entries)
}

fn build_window(
    previous: &FingerprintEndpoint,
    current: &FingerprintEndpoint,
    coverage_ms: u64,
) -> Result<FingerprintWindowReport, FingerprintWindowError> {
    let mut relations = BTreeMap::<RelationKey, RelationDelta>::new();
    for (key, item) in &current.entries {
        let (packets, bytes) = match previous.entries.get(key) {
            Some(old) => {
                if old.value.first_seen_ns != item.value.first_seen_ns
                    || old.value.source_mac != item.value.source_mac
                    || old.value.destination_mac != item.value.destination_mac
                {
                    return Err(FingerprintWindowError::ImmutableValueChanged);
                }
                if item.value.last_seen_ns < old.value.last_seen_ns
                    || item.value.packets < old.value.packets
                    || item.value.bytes < old.value.bytes
                {
                    return Err(FingerprintWindowError::CounterRegression);
                }
                (
                    item.value.packets - old.value.packets,
                    item.value.bytes - old.value.bytes,
                )
            }
            None => (item.value.packets, item.value.bytes),
        };
        if packets == 0 && bytes == 0 {
            continue;
        }
        let side = SideDelta {
            first_seen_ns: item.value.first_seen_ns,
            packets,
            bytes,
        };
        let relation = relations.entry(RelationKey::from(item.key)).or_default();
        match item.key.direction {
            direction::INGRESS => relation.ingress = Some(side),
            direction::EGRESS => relation.egress = Some(side),
            _ => return Err(FingerprintWindowError::InvalidEvidence),
        }
    }

    let mut ingress = FingerprintCounters::default();
    let mut egress = FingerprintCounters::default();
    let mut repeated_relation_count = 0_u16;
    let mut egress_first_correlated_relation_count = 0_u16;
    let mut maximum_ratio = None;
    let mut dominant_ingress_packets = 0_u64;
    for relation in relations.values() {
        if let Some(side) = relation.ingress {
            add_side(&mut ingress, side)?;
            dominant_ingress_packets = dominant_ingress_packets.max(side.packets);
        }
        if let Some(side) = relation.egress {
            add_side(&mut egress, side)?;
        }
        if relation
            .ingress
            .is_some_and(|side| side.packets > 1)
            || relation.egress.is_some_and(|side| side.packets > 1)
        {
            repeated_relation_count = repeated_relation_count
                .checked_add(1)
                .ok_or(FingerprintWindowError::CalculationFailed)?;
        }
        if let (Some(ingress_side), Some(egress_side)) = (relation.ingress, relation.egress) {
            if egress_side.first_seen_ns < ingress_side.first_seen_ns {
                egress_first_correlated_relation_count = egress_first_correlated_relation_count
                    .checked_add(1)
                    .ok_or(FingerprintWindowError::CalculationFailed)?;
            }
            maximize_directional_ratio(
                &mut maximum_ratio,
                ingress_side.packets,
                egress_side.packets,
            );
        }
    }

    let delta_relation_count = u16::try_from(relations.len())
        .map_err(|_| FingerprintWindowError::CalculationFailed)?;
    let captured_entry_count = u16::try_from(current.entries.len())
        .map_err(|_| FingerprintWindowError::CalculationFailed)?;
    let dominant_ratio = ratio_milli(dominant_ingress_packets, ingress.packets);
    let report = FingerprintWindowReport {
        state: FingerprintWindowState::Ready,
        window_ms: DETECTION_FINGERPRINT_WINDOW_MS,
        coverage_ms,
        start_unix_ms: Some(previous.captured_at_unix_ms),
        end_unix_ms: Some(current.captured_at_unix_ms),
        captured_entry_count,
        delta_relation_count,
        repeated_relation_count,
        egress_first_correlated_relation_count,
        ingress,
        egress,
        dominant_ingress_packet_ratio_milli: dominant_ratio,
        maximum_ingress_to_egress_packet_ratio_milli: maximum_ratio,
        last_error_code: None,
    };
    report
        .validate()
        .map_err(|_| FingerprintWindowError::CalculationFailed)?;
    Ok(report)
}

fn add_side(
    counters: &mut FingerprintCounters,
    side: SideDelta,
) -> Result<(), FingerprintWindowError> {
    counters.packets = counters
        .packets
        .checked_add(side.packets)
        .ok_or(FingerprintWindowError::CalculationFailed)?;
    counters.bytes = counters
        .bytes
        .checked_add(side.bytes)
        .ok_or(FingerprintWindowError::CalculationFailed)?;
    Ok(())
}

fn ratio_milli(numerator: u64, denominator: u64) -> Option<u64> {
    if denominator == 0 {
        None
    } else {
        Some(
            u64::try_from((u128::from(numerator) * 1_000) / u128::from(denominator))
                .unwrap_or(u64::MAX),
        )
    }
}

fn maximize_directional_ratio(maximum: &mut Option<u64>, ingress: u64, egress: u64) {
    let ratio = if egress == 0 {
        u64::MAX
    } else {
        u64::try_from((u128::from(ingress) * 1_000) / u128::from(egress)).unwrap_or(u64::MAX)
    };
    *maximum = Some(maximum.unwrap_or_default().max(ratio));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExactKey {
    relation: RelationKey,
    direction: u8,
}

impl From<FingerprintKey> for ExactKey {
    fn from(key: FingerprintKey) -> Self {
        Self {
            relation: RelationKey::from(key),
            direction: key.direction,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RelationKey {
    interface_generation: u64,
    fingerprint: u64,
    ifindex: u32,
    outer_vlan_id: u16,
    ether_type: u16,
    frame_len: u16,
    vlan_depth: u8,
    protocol: u8,
    subtype: u8,
}

impl From<FingerprintKey> for RelationKey {
    fn from(key: FingerprintKey) -> Self {
        Self {
            interface_generation: key.interface_generation,
            fingerprint: key.fingerprint,
            ifindex: key.ifindex,
            outer_vlan_id: key.outer_vlan_id,
            ether_type: key.ether_type,
            frame_len: key.frame_len,
            vlan_depth: key.vlan_depth,
            protocol: key.protocol,
            subtype: key.subtype,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RelationDelta {
    ingress: Option<SideDelta>,
    egress: Option<SideDelta>,
}

#[derive(Debug, Clone, Copy)]
struct SideDelta {
    first_seen_ns: u64,
    packets: u64,
    bytes: u64,
}
