use serde::{Deserialize, Serialize};

use crate::{
    DomainError, HookRole, OBSERVED_CLASS_COUNT, OBSERVED_HOOK_COUNT, RateIdentity, TrafficClass,
};

pub const BASELINE_SOURCE_WINDOW_MS: u64 = 10_000;
pub const BASELINE_CAPACITY: usize = 300;
pub const BASELINE_MINIMUM_SAMPLES: usize = 60;
pub const BASELINE_PACKET_NOISE_FLOOR_PPS: u64 = 10;
pub const BASELINE_BYTE_NOISE_FLOOR_BPS: u64 = 16_384;
pub const BASELINE_SUBJECTS_PER_HOOK: usize = OBSERVED_CLASS_COUNT + 2;
pub const BASELINE_SUBJECT_COUNT: usize = OBSERVED_HOOK_COUNT * BASELINE_SUBJECTS_PER_HOOK;
pub const BASELINE_METRIC_COUNT: usize = BASELINE_SUBJECT_COUNT * 2;

const CLASS_ORDER: [TrafficClass; OBSERVED_CLASS_COUNT] = [
    TrafficClass::L2Broadcast,
    TrafficClass::Ipv4Multicast,
    TrafficClass::Ipv6Multicast,
    TrafficClass::OtherL2Multicast,
    TrafficClass::LinkLocalControl,
    TrafficClass::UnicastOrUnclassified,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    Learning,
    WithinBaseline,
    Elevated,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineMetric {
    Packets,
    Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BaselineSubject {
    Total,
    TrafficClass { traffic_class: TrafficClass },
    ParseErrors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineMetricReport {
    pub current: Option<u64>,
    pub median: Option<u64>,
    pub mad: Option<u64>,
    pub threshold: Option<u64>,
    pub ratio_milli: Option<u64>,
    pub elevated: Option<bool>,
}

impl BaselineMetricReport {
    pub const fn absent() -> Self {
        Self {
            current: None,
            median: None,
            mad: None,
            threshold: None,
            ratio_milli: None,
            elevated: None,
        }
    }

    fn validate_for(self, state: BaselineState) -> Result<(), DomainError> {
        let all_absent = self.current.is_none()
            && self.median.is_none()
            && self.mad.is_none()
            && self.threshold.is_none()
            && self.ratio_milli.is_none()
            && self.elevated.is_none();
        let complete_evaluation = self.current.is_some()
            && self.median.is_some()
            && self.mad.is_some()
            && self.threshold.is_some()
            && self.elevated.is_some();

        match state {
            BaselineState::Learning => {
                let learning_shape = self.median.is_none()
                    && self.mad.is_none()
                    && self.threshold.is_none()
                    && self.ratio_milli.is_none()
                    && self.elevated.is_none();
                if learning_shape {
                    Ok(())
                } else {
                    Err(DomainError::InvalidObservation(
                        "learning baseline metric contains evaluated evidence",
                    ))
                }
            }
            BaselineState::WithinBaseline | BaselineState::Elevated => {
                if complete_evaluation {
                    Ok(())
                } else {
                    Err(DomainError::InvalidObservation(
                        "evaluated baseline metric requires complete evidence",
                    ))
                }
            }
            BaselineState::Unavailable => {
                if all_absent {
                    Ok(())
                } else {
                    Err(DomainError::InvalidObservation(
                        "unavailable baseline metric must not contain evidence",
                    ))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSubjectReport {
    pub hook: HookRole,
    pub subject: BaselineSubject,
    pub state: BaselineState,
    pub sample_count: u16,
    pub latest_accepted_at_unix_ms: Option<u64>,
    pub packets: BaselineMetricReport,
    pub bytes: BaselineMetricReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineReport {
    pub source_window_ms: u64,
    pub capacity: u16,
    pub minimum_samples: u16,
    pub packet_noise_floor_pps: u64,
    pub byte_noise_floor_bps: u64,
    pub state: BaselineState,
    pub evaluated_at_unix_ms: Option<u64>,
    pub source_end_unix_ms: Option<u64>,
    pub last_successful_evaluation_at_unix_ms: Option<u64>,
    pub last_error_code: Option<String>,
    pub learning_subject_count: u16,
    pub elevated_metric_count: u16,
    pub subjects: [BaselineSubjectReport; BASELINE_SUBJECT_COUNT],
}

impl BaselineReport {
    pub fn learning(_identity: RateIdentity, evaluated_at_unix_ms: u64) -> Self {
        let subjects = std::array::from_fn(|index| BaselineSubjectReport {
            hook: hook_for_index(index),
            subject: subject_for_index(index),
            state: BaselineState::Learning,
            sample_count: 0,
            latest_accepted_at_unix_ms: None,
            packets: BaselineMetricReport::absent(),
            bytes: BaselineMetricReport::absent(),
        });
        Self {
            source_window_ms: BASELINE_SOURCE_WINDOW_MS,
            capacity: BASELINE_CAPACITY as u16,
            minimum_samples: BASELINE_MINIMUM_SAMPLES as u16,
            packet_noise_floor_pps: BASELINE_PACKET_NOISE_FLOOR_PPS,
            byte_noise_floor_bps: BASELINE_BYTE_NOISE_FLOOR_BPS,
            state: BaselineState::Learning,
            evaluated_at_unix_ms: Some(evaluated_at_unix_ms),
            source_end_unix_ms: None,
            last_successful_evaluation_at_unix_ms: None,
            last_error_code: None,
            learning_subject_count: BASELINE_SUBJECT_COUNT as u16,
            elevated_metric_count: 0,
            subjects,
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source_window_ms != BASELINE_SOURCE_WINDOW_MS
            || usize::from(self.capacity) != BASELINE_CAPACITY
            || usize::from(self.minimum_samples) != BASELINE_MINIMUM_SAMPLES
            || self.packet_noise_floor_pps != BASELINE_PACKET_NOISE_FLOOR_PPS
            || self.byte_noise_floor_bps != BASELINE_BYTE_NOISE_FLOOR_BPS
        {
            return Err(DomainError::InvalidObservation(
                "baseline report configuration is not fixed",
            ));
        }
        for (index, subject) in self.subjects.iter().enumerate() {
            if subject.hook != hook_for_index(index) || subject.subject != subject_for_index(index)
            {
                return Err(DomainError::InvalidObservation(
                    "baseline subjects do not match fixed order",
                ));
            }
            if usize::from(subject.sample_count) > BASELINE_CAPACITY {
                return Err(DomainError::InvalidObservation(
                    "baseline subject exceeds fixed capacity",
                ));
            }
            subject.packets.validate_for(subject.state)?;
            subject.bytes.validate_for(subject.state)?;
        }
        if self.state != aggregate_baseline_state(&self.subjects) {
            return Err(DomainError::InvalidObservation(
                "baseline aggregate state does not match subjects",
            ));
        }
        let learning_count = self
            .subjects
            .iter()
            .filter(|subject| subject.state == BaselineState::Learning)
            .count();
        if usize::from(self.learning_subject_count) != learning_count {
            return Err(DomainError::InvalidObservation(
                "baseline learning subject count is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineElevatedIdentifier {
    pub hook: HookRole,
    pub subject: BaselineSubject,
    pub metric: BaselineMetric,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSubjectSampleCount {
    pub hook: HookRole,
    pub subject: BaselineSubject,
    pub sample_count: u16,
    pub latest_accepted_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub state: BaselineState,
    pub evaluated_at_unix_ms: Option<u64>,
    pub source_end_unix_ms: Option<u64>,
    pub last_successful_evaluation_at_unix_ms: Option<u64>,
    pub last_error_code: Option<String>,
    pub learning_subject_count: u16,
    pub elevated_metric_count: u16,
    pub subject_sample_counts: [BaselineSubjectSampleCount; BASELINE_SUBJECT_COUNT],
    pub elevated: Vec<BaselineElevatedIdentifier>,
}

impl BaselineSummary {
    pub fn learning(identity: RateIdentity, evaluated_at_unix_ms: u64) -> Self {
        Self::from_report(&BaselineReport::learning(identity, evaluated_at_unix_ms))
    }

    pub fn from_report(report: &BaselineReport) -> Self {
        Self {
            state: report.state,
            evaluated_at_unix_ms: report.evaluated_at_unix_ms,
            source_end_unix_ms: report.source_end_unix_ms,
            last_successful_evaluation_at_unix_ms: report.last_successful_evaluation_at_unix_ms,
            last_error_code: report.last_error_code.clone(),
            learning_subject_count: report.learning_subject_count,
            elevated_metric_count: report.elevated_metric_count,
            subject_sample_counts: std::array::from_fn(|index| {
                let subject = &report.subjects[index];
                BaselineSubjectSampleCount {
                    hook: subject.hook,
                    subject: subject.subject,
                    sample_count: subject.sample_count,
                    latest_accepted_at_unix_ms: subject.latest_accepted_at_unix_ms,
                }
            }),
            elevated: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.elevated.len() > BASELINE_METRIC_COUNT {
            return Err(DomainError::InvalidObservation(
                "baseline summary exceeds fixed elevated identifier bound",
            ));
        }
        for (index, subject) in self.subject_sample_counts.iter().enumerate() {
            if subject.hook != hook_for_index(index)
                || subject.subject != subject_for_index(index)
                || usize::from(subject.sample_count) > BASELINE_CAPACITY
            {
                return Err(DomainError::InvalidObservation(
                    "baseline summary subjects do not match fixed contract",
                ));
            }
        }
        Ok(())
    }
}

pub fn aggregate_baseline_state(
    subjects: &[BaselineSubjectReport; BASELINE_SUBJECT_COUNT],
) -> BaselineState {
    if subjects
        .iter()
        .any(|value| value.state == BaselineState::Unavailable)
    {
        BaselineState::Unavailable
    } else if subjects
        .iter()
        .any(|value| value.state == BaselineState::Elevated)
    {
        BaselineState::Elevated
    } else if subjects
        .iter()
        .any(|value| value.state == BaselineState::Learning)
    {
        BaselineState::Learning
    } else {
        BaselineState::WithinBaseline
    }
}

fn hook_for_index(index: usize) -> HookRole {
    if index < BASELINE_SUBJECTS_PER_HOOK {
        HookRole::ExternalXdpIngress
    } else {
        HookRole::PhysicalTcEgress
    }
}

fn subject_for_index(index: usize) -> BaselineSubject {
    match index % BASELINE_SUBJECTS_PER_HOOK {
        0 => BaselineSubject::Total,
        index @ 1..=OBSERVED_CLASS_COUNT => BaselineSubject::TrafficClass {
            traffic_class: CLASS_ORDER[index - 1],
        },
        _ => BaselineSubject::ParseErrors,
    }
}
