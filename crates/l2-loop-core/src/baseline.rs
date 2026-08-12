use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DetailedRateWindow, DomainError, HookRate, HookRole, OBSERVED_CLASS_COUNT, OBSERVED_HOOK_COUNT,
    RateIdentity, RateWindowState, TrafficClass,
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

    const fn learning(current: u64) -> Self {
        Self {
            current: Some(current),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineSeriesEvaluation {
    pub state: BaselineState,
    pub packets: BaselineMetricReport,
    pub bytes: BaselineMetricReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaselineSamplePair {
    packets_per_second: u64,
    bytes_per_second: u64,
    accepted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BaselineSeries {
    samples: VecDeque<BaselineSamplePair>,
}

impl BaselineSeries {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub fn latest_accepted_at_unix_ms(&self) -> Option<u64> {
        self.samples.back().map(|sample| sample.accepted_at_unix_ms)
    }

    pub fn accept(
        &mut self,
        packets_per_second: u64,
        bytes_per_second: u64,
        accepted_at_unix_ms: u64,
    ) {
        if self.samples.len() == BASELINE_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(BaselineSamplePair {
            packets_per_second,
            bytes_per_second,
            accepted_at_unix_ms,
        });
    }

    pub fn evaluate(
        &self,
        packets_per_second: u64,
        bytes_per_second: u64,
    ) -> BaselineSeriesEvaluation {
        if self.samples.len() < BASELINE_MINIMUM_SAMPLES {
            return BaselineSeriesEvaluation {
                state: BaselineState::Learning,
                packets: BaselineMetricReport::learning(packets_per_second),
                bytes: BaselineMetricReport::learning(bytes_per_second),
            };
        }

        let packet_samples = self
            .samples
            .iter()
            .map(|sample| sample.packets_per_second)
            .collect::<Vec<_>>();
        let byte_samples = self
            .samples
            .iter()
            .map(|sample| sample.bytes_per_second)
            .collect::<Vec<_>>();
        let packet_median = upper_median(&packet_samples).unwrap_or_default();
        let byte_median = upper_median(&byte_samples).unwrap_or_default();
        let packets = evaluate_metric(
            packets_per_second,
            packet_median,
            median_absolute_deviation(&packet_samples).unwrap_or_default(),
            BASELINE_PACKET_NOISE_FLOOR_PPS,
        );
        let bytes = evaluate_metric(
            bytes_per_second,
            byte_median,
            median_absolute_deviation(&byte_samples).unwrap_or_default(),
            BASELINE_BYTE_NOISE_FLOOR_BPS,
        );
        let state = if packets.elevated == Some(true) || bytes.elevated == Some(true) {
            BaselineState::Elevated
        } else {
            BaselineState::WithinBaseline
        };

        BaselineSeriesEvaluation {
            state,
            packets,
            bytes,
        }
    }
}

pub fn upper_median(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
}

pub fn median_absolute_deviation(values: &[u64]) -> Option<u64> {
    let median = upper_median(values)?;
    let deviations = values
        .iter()
        .map(|value| value.abs_diff(median))
        .collect::<Vec<_>>();
    upper_median(&deviations)
}

pub fn evaluate_metric(
    current: u64,
    median: u64,
    mad: u64,
    noise_floor: u64,
) -> BaselineMetricReport {
    let threshold = ((u128::from(median) + 6 * u128::from(mad))
        .max(4 * u128::from(median))
        .max(u128::from(noise_floor)))
    .min(u128::from(u64::MAX)) as u64;
    let ratio_milli = if median == 0 {
        None
    } else {
        Some(((u128::from(current) * 1_000) / u128::from(median)).min(u128::from(u64::MAX)) as u64)
    };

    BaselineMetricReport {
        current: Some(current),
        median: Some(median),
        mad: Some(mad),
        threshold: Some(threshold),
        ratio_milli,
        elevated: Some(current > threshold),
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BaselineError {
    #[error("baseline source window is not the fixed ready ten-second window")]
    InvalidSourceWindow,
    #[error("baseline source window endpoint did not advance")]
    SourceEndpointNotAdvancing,
}

#[derive(Debug, Clone)]
pub struct BaselineEngine {
    identity: RateIdentity,
    series: [BaselineSeries; BASELINE_SUBJECT_COUNT],
    cached: BaselineReport,
    last_source_end_unix_ms: Option<u64>,
    last_successful_evaluation_at_unix_ms: Option<u64>,
}

impl BaselineEngine {
    pub fn new(identity: RateIdentity, started_at_unix_ms: u64) -> Self {
        Self {
            identity,
            series: std::array::from_fn(|_| BaselineSeries::new()),
            cached: BaselineReport::learning(identity, started_at_unix_ms),
            last_source_end_unix_ms: None,
            last_successful_evaluation_at_unix_ms: None,
        }
    }

    pub const fn identity(&self) -> RateIdentity {
        self.identity
    }

    pub const fn cached_report(&self) -> &BaselineReport {
        &self.cached
    }

    pub fn evaluate_ready_window(
        &mut self,
        window: &DetailedRateWindow,
        evaluated_at_unix_ms: u64,
    ) -> Result<BaselineReport, BaselineError> {
        if window.window_ms != BASELINE_SOURCE_WINDOW_MS
            || window.state != RateWindowState::Ready
            || window.validate().is_err()
        {
            self.clear_integrity(
                self.identity,
                evaluated_at_unix_ms,
                "baseline_invalid_source_window",
            );
            return Err(BaselineError::InvalidSourceWindow);
        }

        let Some(source_end_unix_ms) = window.end_unix_ms else {
            self.clear_integrity(
                self.identity,
                evaluated_at_unix_ms,
                "baseline_invalid_source_window",
            );
            return Err(BaselineError::InvalidSourceWindow);
        };
        if self
            .last_source_end_unix_ms
            .is_some_and(|last| source_end_unix_ms <= last)
        {
            self.clear_integrity(
                self.identity,
                evaluated_at_unix_ms,
                "baseline_source_endpoint_not_advancing",
            );
            return Err(BaselineError::SourceEndpointNotAdvancing);
        }

        let hooks = window.hooks.as_ref().ok_or_else(|| {
            self.clear_integrity(
                self.identity,
                evaluated_at_unix_ms,
                "baseline_invalid_source_window",
            );
            BaselineError::InvalidSourceWindow
        })?;
        let values: [(u64, u64); BASELINE_SUBJECT_COUNT] =
            std::array::from_fn(|index| subject_rates(hooks, index));
        let mut evaluations: [BaselineSeriesEvaluation; BASELINE_SUBJECT_COUNT] =
            std::array::from_fn(|index| {
                let (packets, bytes) = values[index];
                self.series[index].evaluate(packets, bytes)
            });

        for index in 0..BASELINE_SUBJECT_COUNT {
            let evaluation = evaluations[index];
            if evaluation.state != BaselineState::Elevated {
                let (packets, bytes) = values[index];
                self.series[index].accept(packets, bytes, source_end_unix_ms);
                if evaluation.state == BaselineState::Learning
                    && self.series[index].sample_count() >= BASELINE_MINIMUM_SAMPLES
                {
                    evaluations[index] = self.series[index].evaluate(packets, bytes);
                }
            }
        }

        let subjects = std::array::from_fn(|index| BaselineSubjectReport {
            hook: hook_for_index(index),
            subject: subject_for_index(index),
            state: evaluations[index].state,
            sample_count: self.series[index].sample_count() as u16,
            latest_accepted_at_unix_ms: self.series[index].latest_accepted_at_unix_ms(),
            packets: evaluations[index].packets,
            bytes: evaluations[index].bytes,
        });
        let learning_subject_count = subjects
            .iter()
            .filter(|subject| subject.state == BaselineState::Learning)
            .count() as u16;
        let elevated_metric_count = subjects
            .iter()
            .flat_map(|subject| [subject.packets.elevated, subject.bytes.elevated])
            .filter(|elevated| *elevated == Some(true))
            .count() as u16;
        let report = BaselineReport {
            source_window_ms: BASELINE_SOURCE_WINDOW_MS,
            capacity: BASELINE_CAPACITY as u16,
            minimum_samples: BASELINE_MINIMUM_SAMPLES as u16,
            packet_noise_floor_pps: BASELINE_PACKET_NOISE_FLOOR_PPS,
            byte_noise_floor_bps: BASELINE_BYTE_NOISE_FLOOR_BPS,
            state: aggregate_baseline_state(&subjects),
            evaluated_at_unix_ms: Some(evaluated_at_unix_ms),
            source_end_unix_ms: Some(source_end_unix_ms),
            last_successful_evaluation_at_unix_ms: Some(evaluated_at_unix_ms),
            last_error_code: None,
            learning_subject_count,
            elevated_metric_count,
            subjects,
        };
        self.last_source_end_unix_ms = Some(source_end_unix_ms);
        self.last_successful_evaluation_at_unix_ms = Some(evaluated_at_unix_ms);
        self.cached = report.clone();
        Ok(report)
    }

    pub fn unavailable(
        &mut self,
        evaluated_at_unix_ms: u64,
        code: impl Into<String>,
    ) -> BaselineReport {
        self.cached = self.unavailable_report(evaluated_at_unix_ms, code.into());
        self.cached.clone()
    }

    pub fn clear_integrity(
        &mut self,
        identity: RateIdentity,
        evaluated_at_unix_ms: u64,
        code: impl Into<String>,
    ) -> BaselineReport {
        self.identity = identity;
        self.series = std::array::from_fn(|_| BaselineSeries::new());
        self.last_source_end_unix_ms = None;
        self.last_successful_evaluation_at_unix_ms = None;
        self.cached = self.unavailable_report(evaluated_at_unix_ms, code.into());
        self.cached.clone()
    }

    fn unavailable_report(&self, evaluated_at_unix_ms: u64, code: String) -> BaselineReport {
        let subjects = std::array::from_fn(|index| BaselineSubjectReport {
            hook: hook_for_index(index),
            subject: subject_for_index(index),
            state: BaselineState::Unavailable,
            sample_count: self.series[index].sample_count() as u16,
            latest_accepted_at_unix_ms: self.series[index].latest_accepted_at_unix_ms(),
            packets: BaselineMetricReport::absent(),
            bytes: BaselineMetricReport::absent(),
        });
        BaselineReport {
            source_window_ms: BASELINE_SOURCE_WINDOW_MS,
            capacity: BASELINE_CAPACITY as u16,
            minimum_samples: BASELINE_MINIMUM_SAMPLES as u16,
            packet_noise_floor_pps: BASELINE_PACKET_NOISE_FLOOR_PPS,
            byte_noise_floor_bps: BASELINE_BYTE_NOISE_FLOOR_BPS,
            state: BaselineState::Unavailable,
            evaluated_at_unix_ms: Some(evaluated_at_unix_ms),
            source_end_unix_ms: None,
            last_successful_evaluation_at_unix_ms: self.last_successful_evaluation_at_unix_ms,
            last_error_code: Some(code),
            learning_subject_count: 0,
            elevated_metric_count: 0,
            subjects,
        }
    }
}

fn subject_rates(hooks: &[HookRate; OBSERVED_HOOK_COUNT], index: usize) -> (u64, u64) {
    let hook = &hooks[index / BASELINE_SUBJECTS_PER_HOOK];
    let counters = match index % BASELINE_SUBJECTS_PER_HOOK {
        0 => &hook.total,
        subject @ 1..=OBSERVED_CLASS_COUNT => &hook.classes[subject - 1].counters,
        _ => &hook.parse_errors,
    };
    (counters.packets_per_second, counters.bytes_per_second)
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
