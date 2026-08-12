use std::collections::{BTreeMap, BTreeSet};

use l2_loop_common::{FingerprintKey, FingerprintValue, NO_VLAN, direction};
use serde::{Deserialize, Serialize};

use crate::DomainError;

pub const FINGERPRINT_CAPACITY: usize = 8_192;
pub const FINGERPRINT_SAMPLE_SHIFT: u8 = l2_loop_common::FINGERPRINT_SAMPLE_SHIFT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintEvidence {
    pub key: FingerprintKey,
    pub value: FingerprintValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintState {
    Empty,
    Observed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintCounters {
    pub packets: u64,
    pub bytes: u64,
}

impl FingerprintCounters {
    fn checked_add(self, packets: u64, bytes: u64) -> Result<Self, DomainError> {
        Ok(Self {
            packets: self
                .packets
                .checked_add(packets)
                .ok_or(DomainError::InvalidObservation(
                    "fingerprint packet aggregate overflow",
                ))?,
            bytes: self
                .bytes
                .checked_add(bytes)
                .ok_or(DomainError::InvalidObservation(
                    "fingerprint byte aggregate overflow",
                ))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintReport {
    pub state: FingerprintState,
    pub capacity: u16,
    pub sample_shift: u8,
    pub captured_entry_count: u16,
    pub relation_count: u16,
    pub ingress_only_relation_count: u16,
    pub egress_only_relation_count: u16,
    pub correlated_relation_count: u16,
    pub ingress_first_relation_count: u16,
    pub egress_first_relation_count: u16,
    pub simultaneous_relation_count: u16,
    pub repeated_relation_count: u16,
    pub ingress: FingerprintCounters,
    pub egress: FingerprintCounters,
    pub maximum_packet_ratio_milli: Option<u64>,
    pub maximum_byte_ratio_milli: Option<u64>,
    pub last_error_code: Option<String>,
}

impl FingerprintReport {
    pub fn build(
        ifindex: u32,
        generation: u64,
        evidence: Vec<FingerprintEvidence>,
    ) -> Result<Self, DomainError> {
        if ifindex == 0 || generation == 0 {
            return Err(DomainError::InvalidObservation(
                "fingerprint identity must be non-zero",
            ));
        }
        if evidence.len() > FINGERPRINT_CAPACITY {
            return Err(DomainError::InvalidObservation(
                "fingerprint evidence exceeds fixed capacity",
            ));
        }

        let mut report = Self::empty();
        report.captured_entry_count = count(evidence.len())?;
        let mut groups = BTreeMap::<RelationKey, Relation>::new();
        let mut exact = BTreeSet::<ExactKey>::new();
        for item in evidence {
            validate_evidence(item, ifindex, generation)?;
            let relation_key = RelationKey::from(item.key);
            if !exact.insert(ExactKey {
                relation: relation_key,
                direction: item.key.direction,
            }) {
                return Err(DomainError::InvalidObservation(
                    "duplicate fingerprint evidence key",
                ));
            }
            let counters = FingerprintCounters {
                packets: item.value.packets,
                bytes: item.value.bytes,
            };
            match item.key.direction {
                direction::INGRESS => {
                    report.ingress = report
                        .ingress
                        .checked_add(item.value.packets, item.value.bytes)?;
                    groups.entry(relation_key).or_default().ingress = Some(Side {
                        first_seen_ns: item.value.first_seen_ns,
                        counters,
                    });
                }
                direction::EGRESS => {
                    report.egress = report
                        .egress
                        .checked_add(item.value.packets, item.value.bytes)?;
                    groups.entry(relation_key).or_default().egress = Some(Side {
                        first_seen_ns: item.value.first_seen_ns,
                        counters,
                    });
                }
                _ => unreachable!("direction was validated"),
            }
        }

        report.relation_count = count(groups.len())?;
        for relation in groups.values() {
            report.accumulate_relation(*relation)?;
        }
        if report.captured_entry_count != 0 {
            report.state = FingerprintState::Observed;
        }
        Ok(report)
    }

    pub fn unavailable(code: &str) -> Result<Self, DomainError> {
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(DomainError::InvalidObservation(
                "fingerprint error code is invalid",
            ));
        }
        Ok(Self {
            state: FingerprintState::Unavailable,
            last_error_code: Some(code.to_owned()),
            ..Self::empty()
        })
    }

    pub const fn empty() -> Self {
        Self {
            state: FingerprintState::Empty,
            capacity: FINGERPRINT_CAPACITY as u16,
            sample_shift: FINGERPRINT_SAMPLE_SHIFT,
            captured_entry_count: 0,
            relation_count: 0,
            ingress_only_relation_count: 0,
            egress_only_relation_count: 0,
            correlated_relation_count: 0,
            ingress_first_relation_count: 0,
            egress_first_relation_count: 0,
            simultaneous_relation_count: 0,
            repeated_relation_count: 0,
            ingress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            egress: FingerprintCounters {
                packets: 0,
                bytes: 0,
            },
            maximum_packet_ratio_milli: None,
            maximum_byte_ratio_milli: None,
            last_error_code: None,
        }
    }

    fn accumulate_relation(&mut self, relation: Relation) -> Result<(), DomainError> {
        if relation
            .ingress
            .is_some_and(|side| side.counters.packets > 1)
            || relation
                .egress
                .is_some_and(|side| side.counters.packets > 1)
        {
            increment(&mut self.repeated_relation_count)?;
        }
        match (relation.ingress, relation.egress) {
            (Some(_), None) => increment(&mut self.ingress_only_relation_count),
            (None, Some(_)) => increment(&mut self.egress_only_relation_count),
            (Some(ingress), Some(egress)) => {
                increment(&mut self.correlated_relation_count)?;
                match ingress.first_seen_ns.cmp(&egress.first_seen_ns) {
                    std::cmp::Ordering::Less => {
                        increment(&mut self.ingress_first_relation_count)?;
                    }
                    std::cmp::Ordering::Greater => {
                        increment(&mut self.egress_first_relation_count)?;
                    }
                    std::cmp::Ordering::Equal => {
                        increment(&mut self.simultaneous_relation_count)?;
                    }
                }
                maximize_ratio(
                    &mut self.maximum_packet_ratio_milli,
                    ingress.counters.packets,
                    egress.counters.packets,
                );
                maximize_ratio(
                    &mut self.maximum_byte_ratio_milli,
                    ingress.counters.bytes,
                    egress.counters.bytes,
                );
                Ok(())
            }
            (None, None) => Err(DomainError::InvalidObservation(
                "fingerprint relation has no evidence",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintSummary {
    pub state: FingerprintState,
    pub captured_entry_count: u16,
    pub relation_count: u16,
    pub ingress_only_relation_count: u16,
    pub egress_only_relation_count: u16,
    pub correlated_relation_count: u16,
    pub ingress_first_relation_count: u16,
    pub egress_first_relation_count: u16,
    pub simultaneous_relation_count: u16,
    pub repeated_relation_count: u16,
    pub ingress: FingerprintCounters,
    pub egress: FingerprintCounters,
    pub maximum_packet_ratio_milli: Option<u64>,
    pub maximum_byte_ratio_milli: Option<u64>,
    pub last_error_code: Option<String>,
}

impl From<&FingerprintReport> for FingerprintSummary {
    fn from(report: &FingerprintReport) -> Self {
        Self {
            state: report.state,
            captured_entry_count: report.captured_entry_count,
            relation_count: report.relation_count,
            ingress_only_relation_count: report.ingress_only_relation_count,
            egress_only_relation_count: report.egress_only_relation_count,
            correlated_relation_count: report.correlated_relation_count,
            ingress_first_relation_count: report.ingress_first_relation_count,
            egress_first_relation_count: report.egress_first_relation_count,
            simultaneous_relation_count: report.simultaneous_relation_count,
            repeated_relation_count: report.repeated_relation_count,
            ingress: report.ingress,
            egress: report.egress,
            maximum_packet_ratio_milli: report.maximum_packet_ratio_milli,
            maximum_byte_ratio_milli: report.maximum_byte_ratio_milli,
            last_error_code: report.last_error_code.clone(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExactKey {
    relation: RelationKey,
    direction: u8,
}

#[derive(Debug, Clone, Copy, Default)]
struct Relation {
    ingress: Option<Side>,
    egress: Option<Side>,
}

#[derive(Debug, Clone, Copy)]
struct Side {
    first_seen_ns: u64,
    counters: FingerprintCounters,
}

fn validate_evidence(
    evidence: FingerprintEvidence,
    ifindex: u32,
    generation: u64,
) -> Result<(), DomainError> {
    let key = evidence.key;
    let value = evidence.value;
    let valid_vlan = key.outer_vlan_id == NO_VLAN || key.outer_vlan_id <= 4_094;
    if key.interface_generation != generation
        || key.ifindex != ifindex
        || !matches!(key.direction, direction::INGRESS | direction::EGRESS)
        || !valid_vlan
        || key.vlan_depth > 2
        || key.reserved != [0; 2]
        || value.reserved != [0; 4]
        || value.packets == 0
        || value.bytes < value.packets
        || value.first_seen_ns > value.last_seen_ns
    {
        return Err(DomainError::InvalidObservation(
            "fingerprint evidence shape is invalid",
        ));
    }
    Ok(())
}

fn count(value: usize) -> Result<u16, DomainError> {
    u16::try_from(value).map_err(|_| {
        DomainError::InvalidObservation("fingerprint evidence count is not representable")
    })
}

fn increment(value: &mut u16) -> Result<(), DomainError> {
    *value = value.checked_add(1).ok_or(DomainError::InvalidObservation(
        "fingerprint relation count overflow",
    ))?;
    Ok(())
}

fn maximize_ratio(maximum: &mut Option<u64>, left: u64, right: u64) {
    let larger = left.max(right);
    let smaller = left.min(right);
    let ratio = if smaller == 0 {
        u64::MAX
    } else {
        u64::try_from((u128::from(larger) * 1_000) / u128::from(smaller)).unwrap_or(u64::MAX)
    };
    *maximum = Some(maximum.unwrap_or_default().max(ratio));
}
