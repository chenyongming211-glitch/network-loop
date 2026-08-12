use std::{
    collections::BTreeSet,
    io::{self, Write},
    os::unix::net::UnixDatagram,
    path::Path,
};

use l2_loop_core::{
    AlertCode, AlertSeverity, DetectionState, DetectionTransitionReason, EventId, EvidenceStatus,
    InterfaceName,
};
use serde::Serialize;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
const ALERT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SanitizedAlertV1 {
    #[serde(skip)]
    pub event_id: EventId,
    pub evidence_status: EvidenceStatus,
    pub revision: u64,
    pub transition_sequence: u64,
    pub code: AlertCode,
    pub severity: AlertSeverity,
    pub previous_state: DetectionState,
    pub current_state: DetectionState,
    pub transition_reason: DetectionTransitionReason,
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub generation: u64,
    pub message: String,
}

#[derive(Serialize)]
struct JsonAlert<'a> {
    schema_version: u16,
    event_id: String,
    #[serde(flatten)]
    alert: &'a SanitizedAlertV1,
}

pub trait AlertIo {
    fn send_journal(&mut self, bytes: &[u8]) -> io::Result<()>;

    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemAlertIo;

impl AlertIo for SystemAlertIo {
    fn send_journal(&mut self, bytes: &[u8]) -> io::Result<()> {
        let socket = UnixDatagram::unbound()?;
        socket.send_to(bytes, Path::new(JOURNAL_SOCKET)).map(|_| ())
    }

    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        stderr.write_all(bytes)?;
        stderr.flush()
    }
}

pub trait AlertSink {
    fn publish(&mut self, alert: &SanitizedAlertV1) -> io::Result<AlertPublishOutcome>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertPublishOutcome {
    Journald,
    StderrJson,
}

pub struct LinuxAlertSink<I> {
    io: I,
    stderr_fallback: bool,
    published_health_codes: BTreeSet<String>,
}

impl<I: AlertIo> LinuxAlertSink<I> {
    pub fn new(io: I) -> Self {
        Self {
            io,
            stderr_fallback: false,
            published_health_codes: BTreeSet::new(),
        }
    }

    pub fn into_inner(self) -> I {
        self.io
    }

    pub fn publish_output_health(&mut self, code: &str) -> bool {
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !self.published_health_codes.insert(code.to_owned())
        {
            return false;
        }
        let line = format!(
            "{{\"schema_version\":1,\"kind\":\"output_health\",\"code\":{}}}\n",
            serde_json::to_string(code).unwrap_or_else(|_| "\"OUTPUT_UNAVAILABLE\"".to_owned())
        );
        self.stderr_fallback = true;
        self.io.write_stderr(line.as_bytes()).is_ok()
    }

    fn write_json(&mut self, alert: &SanitizedAlertV1) -> io::Result<AlertPublishOutcome> {
        let mut bytes = serde_json::to_vec(&JsonAlert {
            schema_version: ALERT_SCHEMA_VERSION,
            event_id: alert.event_id.to_string(),
            alert,
        })
        .map_err(io::Error::other)?;
        bytes.push(b'\n');
        self.io.write_stderr(&bytes)?;
        Ok(AlertPublishOutcome::StderrJson)
    }
}

impl<I: AlertIo> AlertSink for LinuxAlertSink<I> {
    fn publish(&mut self, alert: &SanitizedAlertV1) -> io::Result<AlertPublishOutcome> {
        validate_alert(alert)?;
        if self.stderr_fallback {
            return self.write_json(alert);
        }
        let payload = journal_payload(alert);
        match self.io.send_journal(payload.as_bytes()) {
            Ok(()) => Ok(AlertPublishOutcome::Journald),
            Err(_) => {
                self.stderr_fallback = true;
                self.write_json(alert)
            }
        }
    }
}

fn validate_alert(alert: &SanitizedAlertV1) -> io::Result<()> {
    if alert.revision == 0
        || alert.transition_sequence == 0
        || alert.ifindex == 0
        || alert.generation == 0
        || alert.severity != alert.code.severity()
        || alert.message.is_empty()
        || alert.message.len() > 96
        || !alert.message.is_ascii()
        || alert
            .message
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '='))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid sanitized alert",
        ));
    }
    Ok(())
}

fn journal_payload(alert: &SanitizedAlertV1) -> String {
    format!(
        concat!(
            "MESSAGE={}\n",
            "PRIORITY={}\n",
            "SYSLOG_IDENTIFIER=l2-loopd\n",
            "L2_LOOP_EVENT_ID={}\n",
            "L2_LOOP_EVIDENCE_STATUS={}\n",
            "L2_LOOP_REVISION={}\n",
            "L2_LOOP_TRANSITION_SEQUENCE={}\n",
            "L2_LOOP_CODE={}\n",
            "L2_LOOP_PREVIOUS_STATE={}\n",
            "L2_LOOP_CURRENT_STATE={}\n",
            "L2_LOOP_REASON={}\n",
            "L2_LOOP_INTERFACE={}\n",
            "L2_LOOP_IFINDEX={}\n",
            "L2_LOOP_GENERATION={}\n"
        ),
        alert.message,
        journal_priority(alert.severity),
        alert.event_id,
        enum_json(alert.evidence_status),
        alert.revision,
        alert.transition_sequence,
        enum_json(alert.code),
        enum_json(alert.previous_state),
        enum_json(alert.current_state),
        enum_json(alert.transition_reason),
        alert.interface.as_str(),
        alert.ifindex,
        alert.generation,
    )
}

fn enum_json<T: Serialize>(value: T) -> String {
    serde_json::to_string(&value)
        .unwrap_or_else(|_| "unknown".to_owned())
        .trim_matches('"')
        .to_owned()
}

const fn journal_priority(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Warning => 4,
        AlertSeverity::Notice => 5,
        AlertSeverity::Information => 6,
    }
}
