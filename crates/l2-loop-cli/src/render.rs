use std::fmt::Write;

use l2_loop_agent::protocol::{ControlResponse, ERROR_INTERNAL, ResponseBody};
use l2_loop_core::{
    AgentResult, BaselineMetricReport, BaselineReport, BaselineSubject, BaselineSummary,
    DetailedRateWindow, HookRate, InterfaceStatus, ObservationCounters, ObservationSnapshot,
    PreflightDecision, PreflightReport, RateCounters, SamplingStatus, StatusRateWindow,
};
use serde::Serialize;
use serde_json::Value;

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_BLOCKED: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

impl RenderedOutput {
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: message.into(),
            exit_code: EXIT_FAILURE,
        }
    }

    fn success(stdout: String, exit_code: u8) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code,
        }
    }
}

pub fn render_response(response: ControlResponse, format: OutputFormat) -> RenderedOutput {
    match response.body {
        ResponseBody::Success { result } => match *result {
            AgentResult::Preflight { report } => render_report(&report, format),
            AgentResult::Accepted => RenderedOutput::success("accepted".to_owned(), EXIT_SUCCESS),
            AgentResult::Observation { snapshot } => render_observation(&snapshot, format),
            AgentResult::Status { interfaces } => render_status(&interfaces, format),
            _ => RenderedOutput::failure(format!(
                "{ERROR_INTERNAL}: daemon returned an unexpected result"
            )),
        },
        ResponseBody::Error { code, message } => RenderedOutput {
            stdout: String::new(),
            stderr: format!("{code}: {message}"),
            exit_code: if code.starts_with("PF_") {
                EXIT_BLOCKED
            } else {
                EXIT_FAILURE
            },
        },
    }
}

fn render_observation(snapshot: &ObservationSnapshot, format: OutputFormat) -> RenderedOutput {
    let rendered = match format {
        OutputFormat::Text => render_observation_text(snapshot),
        OutputFormat::Json => serde_json::to_string_pretty(snapshot),
    };
    rendered_output(rendered, EXIT_SUCCESS)
}

#[derive(Serialize)]
struct StatusOutput<'a> {
    interfaces: &'a [InterfaceStatus],
}

fn render_status(interfaces: &[InterfaceStatus], format: OutputFormat) -> RenderedOutput {
    let rendered = match format {
        OutputFormat::Text => render_status_text(interfaces),
        OutputFormat::Json => serde_json::to_string_pretty(&StatusOutput { interfaces }),
    };
    rendered_output(rendered, EXIT_SUCCESS)
}

fn render_observation_text(snapshot: &ObservationSnapshot) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    writeln!(output, "schema_version: {}", snapshot.schema_version).ok();
    writeln!(output, "interface: {}", snapshot.interface.as_str()).ok();
    writeln!(output, "ifindex: {}", snapshot.ifindex).ok();
    writeln!(output, "generation: {}", snapshot.generation).ok();
    writeln!(
        output,
        "captured_at_unix_ms: {}",
        snapshot.captured_at_unix_ms
    )
    .ok();
    writeln!(
        output,
        "vlan_visibility: {}",
        serialized_scalar(&snapshot.vlan_visibility)?
    )
    .ok();
    writeln!(output, "health: {}", serialized_scalar(&snapshot.health)?).ok();
    writeln!(output, "hooks:").ok();
    for hook in &snapshot.hooks {
        render_cumulative_hook(&mut output, hook)?;
    }
    render_sampling_status(&mut output, &snapshot.sampling, 0);
    writeln!(output, "rate_windows:").ok();
    for window in &snapshot.rate_windows {
        render_detailed_window(&mut output, window)?;
    }
    render_baseline_report(&mut output, &snapshot.baseline)?;
    Ok(output.trim_end().to_owned())
}

fn render_status_text(interfaces: &[InterfaceStatus]) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    writeln!(output, "interfaces:").ok();
    if interfaces.is_empty() {
        writeln!(output, "  []").ok();
    }
    for interface in interfaces {
        writeln!(output, "  -").ok();
        writeln!(output, "    interface: {}", interface.interface.as_str()).ok();
        writeln!(
            output,
            "    state: {}",
            serialized_scalar(&interface.state)?
        )
        .ok();
        writeln!(output, "    generation: {}", interface.generation).ok();
        writeln!(
            output,
            "    captured_at_unix_ms: {}",
            interface.captured_at_unix_ms
        )
        .ok();
        writeln!(
            output,
            "    health: {}",
            serialized_scalar(&interface.health)?
        )
        .ok();
        writeln!(
            output,
            "    vlan_visibility: {}",
            serialized_scalar(&interface.vlan_visibility)?
        )
        .ok();
        render_cumulative_counters(&mut output, "xdp_ingress", interface.xdp_ingress, 4);
        render_cumulative_counters(&mut output, "tc_egress", interface.tc_egress, 4);
        render_sampling_status(&mut output, &interface.sampling, 4);
        writeln!(output, "    rate_windows:").ok();
        for window in &interface.rate_windows {
            render_status_window(&mut output, window)?;
        }
        render_baseline_summary(&mut output, &interface.baseline)?;
    }
    Ok(output.trim_end().to_owned())
}

fn render_baseline_report(
    output: &mut String,
    baseline: &BaselineReport,
) -> Result<(), serde_json::Error> {
    writeln!(output, "baseline:").ok();
    render_baseline_header(
        output,
        &baseline.state,
        baseline.evaluated_at_unix_ms,
        baseline.source_end_unix_ms,
        baseline.last_successful_evaluation_at_unix_ms,
        baseline.last_error_code.as_deref(),
        baseline.learning_subject_count,
        baseline.elevated_metric_count,
        2,
    )?;
    writeln!(output, "  source_window_ms: {}", baseline.source_window_ms).ok();
    writeln!(output, "  capacity: {}", baseline.capacity).ok();
    writeln!(output, "  minimum_samples: {}", baseline.minimum_samples).ok();
    writeln!(
        output,
        "  packet_noise_floor_pps: {}",
        baseline.packet_noise_floor_pps
    )
    .ok();
    writeln!(
        output,
        "  byte_noise_floor_bps: {}",
        baseline.byte_noise_floor_bps
    )
    .ok();
    writeln!(output, "  subjects:").ok();
    for subject in &baseline.subjects {
        writeln!(output, "    -").ok();
        writeln!(output, "      hook: {}", serialized_scalar(&subject.hook)?).ok();
        writeln!(output, "      subject:").ok();
        render_serialized_value(output, &subject.subject, 8)?;
        writeln!(
            output,
            "      state: {}",
            serialized_scalar(&subject.state)?
        )
        .ok();
        writeln!(output, "      sample_count: {}", subject.sample_count).ok();
        writeln!(
            output,
            "      latest_accepted_at_unix_ms: {}",
            option_number(subject.latest_accepted_at_unix_ms)
        )
        .ok();
        render_baseline_metric(output, "packets", &subject.packets, 6);
        render_baseline_metric(output, "bytes", &subject.bytes, 6);
    }
    Ok(())
}

fn render_baseline_summary(
    output: &mut String,
    baseline: &BaselineSummary,
) -> Result<(), serde_json::Error> {
    writeln!(output, "    baseline:").ok();
    render_baseline_header(
        output,
        &baseline.state,
        baseline.evaluated_at_unix_ms,
        baseline.source_end_unix_ms,
        baseline.last_successful_evaluation_at_unix_ms,
        baseline.last_error_code.as_deref(),
        baseline.learning_subject_count,
        baseline.elevated_metric_count,
        6,
    )?;
    writeln!(output, "      subject_sample_counts:").ok();
    for subject in &baseline.subject_sample_counts {
        writeln!(output, "        -").ok();
        writeln!(
            output,
            "          hook: {}",
            serialized_scalar(&subject.hook)?
        )
        .ok();
        writeln!(
            output,
            "          subject: {}",
            baseline_subject_label(subject.subject)?
        )
        .ok();
        writeln!(output, "          sample_count: {}", subject.sample_count).ok();
        writeln!(
            output,
            "          latest_accepted_at_unix_ms: {}",
            option_number(subject.latest_accepted_at_unix_ms)
        )
        .ok();
    }
    writeln!(output, "      elevated:").ok();
    if baseline.elevated.is_empty() {
        writeln!(output, "        []").ok();
    }
    for elevated in &baseline.elevated {
        writeln!(output, "        -").ok();
        writeln!(
            output,
            "          hook: {}",
            serialized_scalar(&elevated.hook)?
        )
        .ok();
        writeln!(
            output,
            "          subject: {}",
            baseline_subject_label(elevated.subject)?
        )
        .ok();
        writeln!(
            output,
            "          metric: {}",
            serialized_scalar(&elevated.metric)?
        )
        .ok();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_baseline_header<T: Serialize>(
    output: &mut String,
    state: &T,
    evaluated_at_unix_ms: Option<u64>,
    source_end_unix_ms: Option<u64>,
    last_successful_evaluation_at_unix_ms: Option<u64>,
    last_error_code: Option<&str>,
    learning_subject_count: u16,
    elevated_metric_count: u16,
    indent: usize,
) -> Result<(), serde_json::Error> {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}state: {}", serialized_scalar(state)?).ok();
    writeln!(
        output,
        "{padding}evaluated_at_unix_ms: {}",
        option_number(evaluated_at_unix_ms)
    )
    .ok();
    writeln!(
        output,
        "{padding}source_end_unix_ms: {}",
        option_number(source_end_unix_ms)
    )
    .ok();
    writeln!(
        output,
        "{padding}last_successful_evaluation_at_unix_ms: {}",
        option_number(last_successful_evaluation_at_unix_ms)
    )
    .ok();
    writeln!(
        output,
        "{padding}last_error_code: {}",
        last_error_code.unwrap_or("null")
    )
    .ok();
    writeln!(
        output,
        "{padding}learning_subject_count: {learning_subject_count}"
    )
    .ok();
    writeln!(
        output,
        "{padding}elevated_metric_count: {elevated_metric_count}"
    )
    .ok();
    Ok(())
}

fn render_baseline_metric(
    output: &mut String,
    label: &str,
    metric: &BaselineMetricReport,
    indent: usize,
) {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}{label}:").ok();
    writeln!(
        output,
        "{padding}  current: {}",
        option_number(metric.current)
    )
    .ok();
    writeln!(
        output,
        "{padding}  median: {}",
        option_number(metric.median)
    )
    .ok();
    writeln!(output, "{padding}  mad: {}", option_number(metric.mad)).ok();
    writeln!(
        output,
        "{padding}  threshold: {}",
        option_number(metric.threshold)
    )
    .ok();
    writeln!(
        output,
        "{padding}  ratio_milli: {}",
        option_number(metric.ratio_milli)
    )
    .ok();
    writeln!(
        output,
        "{padding}  elevated: {}",
        metric
            .elevated
            .map_or("null", |value| if value { "true" } else { "false" })
    )
    .ok();
}

fn render_serialized_value<T: Serialize>(
    output: &mut String,
    value: &T,
    indent: usize,
) -> Result<(), serde_json::Error> {
    let value = serde_json::to_value(value)?;
    write_value(&value, indent, output);
    Ok(())
}

fn render_cumulative_hook(
    output: &mut String,
    hook: &l2_loop_core::HookObservation,
) -> Result<(), serde_json::Error> {
    writeln!(output, "  -").ok();
    writeln!(output, "    role: {}", serialized_scalar(&hook.role)?).ok();
    render_cumulative_counters(output, "total", hook.total, 4);
    writeln!(output, "    classes:").ok();
    for class in &hook.classes {
        writeln!(output, "      -").ok();
        writeln!(
            output,
            "        traffic_class: {}",
            serialized_scalar(&class.traffic_class)?
        )
        .ok();
        render_cumulative_counters(output, "counters", class.counters, 8);
    }
    render_cumulative_counters(output, "parse_errors", hook.parse_errors, 4);
    Ok(())
}

fn render_cumulative_counters(
    output: &mut String,
    label: &str,
    counters: ObservationCounters,
    indent: usize,
) {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}{label}:").ok();
    writeln!(output, "{padding}  packets: {}", counters.packets).ok();
    writeln!(output, "{padding}  bytes: {}", counters.bytes).ok();
}

fn render_sampling_status(output: &mut String, sampling: &SamplingStatus, indent: usize) {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}sampling:").ok();
    writeln!(
        output,
        "{padding}  latest_success_at_unix_ms: {}",
        option_number(sampling.latest_success_at_unix_ms)
    )
    .ok();
    writeln!(
        output,
        "{padding}  last_error_code: {}",
        sampling.last_error_code.as_deref().unwrap_or("null")
    )
    .ok();
    writeln!(
        output,
        "{padding}  consecutive_failures: {}",
        sampling.consecutive_failures
    )
    .ok();
    writeln!(
        output,
        "{padding}  sampling_paused: {}",
        sampling.sampling_paused
    )
    .ok();
}

fn render_detailed_window(
    output: &mut String,
    window: &DetailedRateWindow,
) -> Result<(), serde_json::Error> {
    render_window_header(
        output,
        window.window_ms,
        &window.state,
        window.coverage_ms,
        2,
    )?;
    let Some(hooks) = &window.hooks else {
        return Ok(());
    };
    render_window_evidence(
        output,
        window.elapsed_ns,
        window.start_unix_ms,
        window.end_unix_ms,
        4,
    );
    writeln!(output, "    hooks:").ok();
    for hook in hooks {
        render_hook_rate(output, hook)?;
    }
    Ok(())
}

fn render_status_window(
    output: &mut String,
    window: &StatusRateWindow,
) -> Result<(), serde_json::Error> {
    render_window_header(
        output,
        window.window_ms,
        &window.state,
        window.coverage_ms,
        6,
    )?;
    let (Some(xdp), Some(tc)) = (window.xdp_ingress, window.tc_egress) else {
        return Ok(());
    };
    render_window_evidence(
        output,
        window.elapsed_ns,
        window.start_unix_ms,
        window.end_unix_ms,
        8,
    );
    render_rate_counters(output, "xdp_ingress", xdp, 8);
    render_rate_counters(output, "tc_egress", tc, 8);
    Ok(())
}

fn render_window_header<T: Serialize>(
    output: &mut String,
    window_ms: u64,
    state: &T,
    coverage_ms: u64,
    indent: usize,
) -> Result<(), serde_json::Error> {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}-").ok();
    writeln!(output, "{padding}  window: {}", window_label(window_ms)).ok();
    writeln!(output, "{padding}  state: {}", serialized_scalar(state)?).ok();
    writeln!(output, "{padding}  coverage_ms: {coverage_ms}").ok();
    Ok(())
}

fn render_window_evidence(
    output: &mut String,
    elapsed_ns: Option<u64>,
    start_unix_ms: Option<u64>,
    end_unix_ms: Option<u64>,
    indent: usize,
) {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}elapsed_ns: {}", option_number(elapsed_ns)).ok();
    writeln!(
        output,
        "{padding}start_unix_ms: {}",
        option_number(start_unix_ms)
    )
    .ok();
    writeln!(
        output,
        "{padding}end_unix_ms: {}",
        option_number(end_unix_ms)
    )
    .ok();
}

fn render_hook_rate(output: &mut String, hook: &HookRate) -> Result<(), serde_json::Error> {
    writeln!(output, "      -").ok();
    writeln!(output, "        role: {}", serialized_scalar(&hook.role)?).ok();
    render_rate_counters(output, "total", hook.total, 8);
    writeln!(output, "        classes:").ok();
    for class in &hook.classes {
        writeln!(output, "          -").ok();
        writeln!(
            output,
            "            traffic_class: {}",
            serialized_scalar(&class.traffic_class)?
        )
        .ok();
        render_rate_counters(output, "counters", class.counters, 12);
    }
    render_rate_counters(output, "parse_errors", hook.parse_errors, 8);
    Ok(())
}

fn render_rate_counters(output: &mut String, label: &str, rates: RateCounters, indent: usize) {
    let padding = " ".repeat(indent);
    writeln!(output, "{padding}{label}:").ok();
    writeln!(output, "{padding}  packet_delta: {}", rates.packet_delta).ok();
    writeln!(output, "{padding}  byte_delta: {}", rates.byte_delta).ok();
    writeln!(output, "{padding}  pps: {}", rates.packets_per_second).ok();
    writeln!(output, "{padding}  B/s: {}", rates.bytes_per_second).ok();
}

fn window_label(window_ms: u64) -> &'static str {
    match window_ms {
        1_000 => "1s",
        10_000 => "10s",
        60_000 => "60s",
        _ => "invalid",
    }
}

fn option_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn serialized_scalar<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(scalar_text(&serde_json::to_value(value)?))
}

fn baseline_subject_label(subject: BaselineSubject) -> Result<String, serde_json::Error> {
    Ok(match subject {
        BaselineSubject::Total => "total".to_owned(),
        BaselineSubject::TrafficClass { traffic_class } => {
            format!("class/{}", serialized_scalar(&traffic_class)?)
        }
        BaselineSubject::ParseErrors => "parse_errors".to_owned(),
    })
}

fn rendered_output(rendered: Result<String, serde_json::Error>, exit_code: u8) -> RenderedOutput {
    match rendered {
        Ok(stdout) => RenderedOutput::success(stdout, exit_code),
        Err(_) => RenderedOutput::failure(format!("{ERROR_INTERNAL}: response rendering failed")),
    }
}

fn render_report(report: &PreflightReport, format: OutputFormat) -> RenderedOutput {
    let rendered = match format {
        OutputFormat::Text => render_text(report),
        OutputFormat::Json => serde_json::to_string_pretty(report),
    };
    let stdout = match rendered {
        Ok(stdout) => stdout,
        Err(_) => {
            return RenderedOutput::failure(format!("{ERROR_INTERNAL}: response rendering failed"));
        }
    };
    let exit_code = match report.decision {
        PreflightDecision::Ready | PreflightDecision::ReadyWithWarnings => EXIT_SUCCESS,
        PreflightDecision::Blocked => EXIT_BLOCKED,
    };
    RenderedOutput::success(stdout, exit_code)
}

fn render_text<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let mut output = String::new();
    write_value(&value, 0, &mut output);
    Ok(output.trim_end().to_owned())
}

fn write_value(value: &Value, indent: usize, output: &mut String) {
    match value {
        Value::Object(entries) => {
            for (key, value) in entries {
                if is_scalar(value) {
                    write_indent(indent, output);
                    let _ = writeln!(output, "{key}: {}", scalar_text(value));
                } else {
                    write_indent(indent, output);
                    let _ = writeln!(output, "{key}:");
                    write_value(value, indent + 2, output);
                }
            }
        }
        Value::Array(values) if values.is_empty() => {
            write_indent(indent, output);
            let _ = writeln!(output, "[]");
        }
        Value::Array(values) => {
            for value in values {
                write_indent(indent, output);
                if is_scalar(value) {
                    let _ = writeln!(output, "- {}", scalar_text(value));
                } else {
                    let _ = writeln!(output, "-");
                    write_value(value, indent + 2, output);
                }
            }
        }
        _ => {
            write_indent(indent, output);
            let _ = writeln!(output, "{}", scalar_text(value));
        }
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(value) if !value.is_empty() && !value.chars().any(char::is_control) => {
            value.clone()
        }
        Value::String(value) => {
            serde_json::to_string(value).expect("JSON strings are serializable")
        }
        _ => value.to_string(),
    }
}

fn write_indent(indent: usize, output: &mut String) {
    for _ in 0..indent {
        output.push(' ');
    }
}
