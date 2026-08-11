use std::fmt::Write;

use l2_loop_agent::protocol::{ControlResponse, ERROR_INTERNAL, ResponseBody};
use l2_loop_core::{
    AgentResult, InterfaceStatus, ObservationSnapshot, PreflightDecision, PreflightReport,
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
    render_serializable(snapshot, format)
}

#[derive(Serialize)]
struct StatusOutput<'a> {
    interfaces: &'a [InterfaceStatus],
}

fn render_status(interfaces: &[InterfaceStatus], format: OutputFormat) -> RenderedOutput {
    render_serializable(&StatusOutput { interfaces }, format)
}

fn render_serializable<T>(value: &T, format: OutputFormat) -> RenderedOutput
where
    T: Serialize,
{
    let rendered = match format {
        OutputFormat::Text => render_text(value),
        OutputFormat::Json => serde_json::to_string_pretty(value),
    };
    match rendered {
        Ok(stdout) => RenderedOutput::success(stdout, EXIT_SUCCESS),
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
