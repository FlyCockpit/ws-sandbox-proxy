//! Inactive 10.5 fs/process codecs. No runtime or protocol advertisement change.
use serde::{Deserialize, Serialize};
pub mod host;

/// Pre-issue recovery reservations; shared by host producers and journal.
pub const HOST_CONTENT_MAX_SLOTS: usize = 64;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultLimits {
    pub result_version: u32,
    pub host_result_max_bytes: usize,
    pub response_max_bytes: usize,
    pub scalar_max_bytes: usize,
    pub description_max_bytes: usize,
    pub owner_reserved_max_bytes: usize,
    pub observation_retention_ms: u64,
    pub mutation_content_retention_ms: u64,
    pub list_default_limit: usize,
    pub list_max_limit: usize,
    pub directory_depth_max: u32,
    pub list_visit_max: usize,
    pub observation_timeout_ms: u64,
}
pub const RESULT_LIMITS_JSON: &str =
    include_str!("../../../packages/config/src/sandbox-result-limits.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessRef {
    pub sandbox_id: String,
    pub generation: u32,
    pub process_id: String,
    pub attempt: u32,
    pub pid: u32,
}
impl ProcessRef {
    pub fn validate(&self) -> bool {
        opaque_id(&self.sandbox_id)
            && opaque_id(&self.process_id)
            && (1..=i32::MAX as u32).contains(&self.generation)
            && (1..=i32::MAX as u32).contains(&self.attempt)
            && (2..=i32::MAX as u32).contains(&self.pid)
    }
}
fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryType {
    File,
    Dir,
    Symlink,
    Other,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryInfo {
    pub name: String,
    pub path: String,
    pub r#type: EntryType,
    pub size: u64,
    pub mode: u32,
    pub permissions: String,
    pub uid: u32,
    pub gid: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub modified_time: Option<String>,
    pub symlink_target: Option<String>,
}
/// Observed paths are canonical: no empty, `.` or `..` component (except `/`).
fn guest_path(value: &str) -> bool {
    value.len() <= 4096
        && !value.contains('\0')
        && value.strip_prefix('/').is_some_and(|rest| {
            rest.is_empty()
                || rest
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        })
}
pub fn mode_permissions(mode: u32) -> String {
    [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ]
    .iter()
    .enumerate()
    .map(|(i, bit)| {
        let set = mode & bit != 0;
        match i {
            2 if mode & 0o4000 != 0 => {
                if set {
                    's'
                } else {
                    'S'
                }
            }
            5 if mode & 0o2000 != 0 => {
                if set {
                    's'
                } else {
                    'S'
                }
            }
            8 if mode & 0o1000 != 0 => {
                if set {
                    't'
                } else {
                    'T'
                }
            }
            _ if set => match i % 3 {
                0 => 'r',
                1 => 'w',
                _ => 'x',
            },
            _ => '-',
        }
    })
    .collect()
}
impl EntryInfo {
    pub fn validate(&self) -> bool {
        let name = self.name == "/"
            || (!self.name.is_empty()
                && self.name != "."
                && self.name != ".."
                && !self.name.contains(['/', '\0']));
        name && self.name.len() <= 255
            && if self.path == "/" {
                self.name == "/"
            } else {
                self.path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name == self.name)
            }
            && guest_path(&self.path)
            && self.size <= 9_007_199_254_740_991
            && self.mode <= 0o7777
            && self.permissions == mode_permissions(self.mode)
            && self
                .modified_time
                .as_ref()
                .is_none_or(|s| valid_timestamp(s))
            && self
                .owner
                .as_ref()
                .is_none_or(|s| s.len() <= 128 && !s.contains('\0'))
            && self
                .group
                .as_ref()
                .is_none_or(|s| s.len() <= 128 && !s.contains('\0'))
            && match (&self.r#type, &self.symlink_target) {
                (EntryType::Symlink, Some(s)) => s.len() <= 4096 && !s.contains('\0'),
                (EntryType::Symlink, None) => false,
                (_, None) => true,
                _ => false,
            }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureResource {
    Filesystem,
    Process,
    Command,
    Sandbox,
    Operation,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureEffect {
    None,
    Partial,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<crate::capacity_v11::CapacityReason>,
    pub resource: FailureResource,
    pub effect: FailureEffect,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Standalone start observations also require the versioned daemon encoder.
/// ```compile_fail
/// let started: sandbox_protocol::results::ProcessStarted =
///     serde_json::from_str("{}").unwrap();
/// let _ = serde_json::json!(started);
/// ```
pub struct ProcessStarted {
    #[serde(rename = "type")]
    pub message_type: ProcessStartedType,
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u32,
    pub process_id: String,
    pub attempt: u32,
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: String,
    pub started_at: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessStartedType {
    #[serde(rename = "process.started")]
    Started,
}
impl ProcessStarted {
    pub fn validate(&self) -> bool {
        let identity = ProcessRef {
            sandbox_id: self.sandbox_id.clone(),
            generation: self.generation,
            process_id: self.process_id.clone(),
            attempt: self.attempt,
            pid: self.pid,
        };
        let boot = self.boot_id.as_bytes();
        identity.validate()
            && opaque_id(&self.operation_id)
            && boot.len() == 36
            && boot.iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
            // Digits only: `str::parse` would also accept a leading `+`.
            && self.start_ticks.bytes().all(|b| b.is_ascii_digit())
            && !self.start_ticks.starts_with('0')
            && self.start_ticks.parse::<u64>().is_ok_and(|ticks| ticks > 0)
            && valid_timestamp(&self.started_at)
            && valid_timestamp(&self.observed_at)
    }
}

/// Host-clock RFC 3339 UTC timestamp with millisecond precision, the only
/// time representation accepted by `valid_timestamp` for identity frames.
pub fn format_timestamp_ms(unix_ms: u64) -> String {
    let days = unix_ms / 86_400_000;
    let rem = unix_ms % 86_400_000;
    let (hour, minute, second, millis) = (
        rem / 3_600_000,
        (rem / 60_000) % 60,
        (rem / 1000) % 60,
        rem % 1000,
    );
    // Civil-from-days (proleptic Gregorian), days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

impl ProcessStarted {
    /// Build the best-effort start observation from host-local evidence. The
    /// wrapper nonce is not an input; times are host clock only.
    #[allow(clippy::too_many_arguments)]
    pub fn observed(
        operation_id: &str,
        process: &ProcessRef,
        boot_id: &str,
        start_ticks: u64,
        started_at_ms: u64,
        observed_at_ms: u64,
    ) -> Option<Self> {
        let started = Self {
            message_type: ProcessStartedType::Started,
            operation_id: operation_id.to_string(),
            sandbox_id: process.sandbox_id.clone(),
            generation: process.generation,
            process_id: process.process_id.clone(),
            attempt: process.attempt,
            pid: process.pid,
            boot_id: boot_id.to_string(),
            start_ticks: start_ticks.to_string(),
            started_at: format_timestamp_ms(started_at_ms),
            observed_at: format_timestamp_ms(observed_at_ms.max(started_at_ms)),
        };
        started.validate().then_some(started)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_timestamps_and_started_builder_are_strict() {
        assert_eq!(format_timestamp_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_timestamp_ms(1_793_059_200_001),
            "2026-10-27T00:00:00.001Z"
        );
        assert_eq!(
            format_timestamp_ms(951_782_400_000),
            "2000-02-29T00:00:00.000Z"
        );
        assert!(valid_timestamp(&format_timestamp_ms(1_793_059_200_001)));
        let process = ProcessRef {
            sandbox_id: "sandbox".into(),
            generation: 1,
            process_id: "process".into(),
            attempt: 1,
            pid: 123,
        };
        let boot = "12345678-1234-4234-8234-123456789abc";
        let started = ProcessStarted::observed(
            "operation",
            &process,
            boot,
            123_456,
            1_793_059_200_000,
            1_793_059_200_001,
        )
        .expect("valid");
        let fixture: ProcessStarted =
            serde_json::from_str(include_str!("../fixtures/process_started.json")).unwrap();
        assert_eq!(started, fixture);
        assert!(
            ProcessStarted::observed(
                "operation",
                &ProcessRef {
                    pid: 1,
                    ..process.clone()
                },
                boot,
                1,
                0,
                0
            )
            .is_none()
        );
        assert!(ProcessStarted::observed("operation", &process, "not-a-uuid", 1, 0, 0).is_none());
        assert!(ProcessStarted::observed("operation", &process, boot, 0, 0, 0).is_none());
    }
    #[test]
    fn shared_limits_and_process_identity() {
        let started: ProcessStarted =
            serde_json::from_str(include_str!("../fixtures/process_started.json")).unwrap();
        assert!(started.validate());
        let mut forged: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/process_started.json")).unwrap();
        forged["nonce"] = serde_json::json!("private");
        assert!(serde_json::from_value::<ProcessStarted>(forged).is_err());
        let limits: ResultLimits = serde_json::from_str(RESULT_LIMITS_JSON).unwrap();
        assert_eq!(limits.host_result_max_bytes, 24 * 1024);
        assert_eq!(limits.response_max_bytes, 32 * 1024);
        assert_eq!(limits.owner_reserved_max_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.observation_retention_ms, 3_600_000);
        assert_eq!(limits.mutation_content_retention_ms, 86_400_000);
        assert_eq!(limits.list_max_limit, 100);
        let process: ProcessRef = serde_json::from_str(
            r#"{"sandboxId":"s","generation":1,"processId":"p","attempt":1,"pid":2}"#,
        )
        .unwrap();
        assert!(process.validate());
        assert!(!ProcessRef { pid: 1, ..process }.validate());
        assert!(serde_json::from_str::<ProcessRef>(r#"{"sandboxId":"s","generation":1,"processId":"p","attempt":1,"pid":2,"nonce":"private"}"#).is_err());
        assert_eq!(mode_permissions(0o7754), "rwsr-sr-T");
    }

    #[derive(Deserialize)]
    struct StartedCase {
        name: String,
        valid: bool,
        value: serde_json::Value,
    }
    #[test]
    fn process_started_cases_match_typescript() {
        let cases: Vec<StartedCase> =
            serde_json::from_str(include_str!("../fixtures/process_started_cases.json")).unwrap();
        assert!(cases.iter().any(|case| !case.valid));
        for case in cases {
            assert_eq!(
                serde_json::from_value::<ProcessStarted>(case.value)
                    .is_ok_and(|started| started.validate()),
                case.valid,
                "{}",
                case.name
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessInfo {
    pub process: ProcessRef,
    pub operation_id: String,
    pub kind: CommandKind,
    pub cmd: String,
    pub args: Vec<String>,
    pub args_truncated: bool,
    pub cwd: String,
    pub started_at: String,
    pub observed_at: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandKind {
    Command,
}
impl ProcessInfo {
    pub fn validate(&self) -> bool {
        self.process.validate()
            && opaque_id(&self.operation_id)
            && self.cmd.encode_utf16().count() <= 512
            && !self.cmd.contains('\0')
            && self.args.len() <= 256
            && self
                .args
                .iter()
                .all(|arg| arg.encode_utf16().count() <= 512 && !arg.contains('\0'))
            && serde_json::to_vec(&self.args).is_ok_and(|bytes| bytes.len() <= 4096)
            && serde_json::to_vec(&serde_json::json!({"cmd": self.cmd, "args": self.args, "argsTruncated": self.args_truncated, "cwd": self.cwd})).is_ok_and(|bytes| bytes.len() <= 12288)
            && guest_path(&self.cwd)
            && valid_timestamp(&self.started_at)
            && valid_timestamp(&self.observed_at)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessSignal {
    SIGTERM,
    SIGINT,
    SIGHUP,
    SIGKILL,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LiveConsistency {
    Live,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalDelivery {
    #[serde(rename = "process_group")]
    ProcessGroup,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ResultBody {
    #[serde(rename = "file.stat")]
    Stat { entry: EntryInfo },
    #[serde(rename = "file.list", rename_all = "camelCase")]
    List {
        path: String,
        depth: u32,
        items: Vec<EntryInfo>,
        next_cursor: Option<String>,
        consistency: LiveConsistency,
    },
    #[serde(rename = "file.mkdir")]
    Mkdir { created: bool },
    #[serde(rename = "file.remove")]
    Remove { removed: bool },
    #[serde(rename = "file.rename")]
    Rename { entry: EntryInfo },
    #[serde(rename = "process.list", rename_all = "camelCase")]
    Processes {
        items: Vec<ProcessInfo>,
        next_cursor: Option<String>,
        consistency: LiveConsistency,
    },
    #[serde(rename = "process.signal", rename_all = "camelCase")]
    Signal {
        process: ProcessRef,
        target_operation_id: String,
        signal: ProcessSignal,
        accepted: bool,
        delivery: SignalDelivery,
    },
    #[serde(rename = "command", rename_all = "camelCase")]
    Command {
        process: ProcessRef,
        started_at: String,
        exit_code: Option<i32>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultKind {
    StatPath,
    ListDir,
    Mkdir,
    RemovePath,
    MovePath,
    ListProcesses,
    SignalProcess,
    RunCommand,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultOutcome {
    Pending,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationResult {
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u32,
    pub kind: ResultKind,
    pub outcome: ResultOutcome,
    pub observed_at: String,
    pub expires_at: Option<String>,
    pub result: Option<ResultBody>,
}
impl ResultBody {
    pub fn kind(&self) -> ResultKind {
        match self {
            Self::Stat { .. } => ResultKind::StatPath,
            Self::List { .. } => ResultKind::ListDir,
            Self::Mkdir { .. } => ResultKind::Mkdir,
            Self::Remove { .. } => ResultKind::RemovePath,
            Self::Rename { .. } => ResultKind::MovePath,
            Self::Processes { .. } => ResultKind::ListProcesses,
            Self::Signal { .. } => ResultKind::SignalProcess,
            Self::Command { .. } => ResultKind::RunCommand,
        }
    }
    fn validate(&self, sandbox_id: &str, generation: u32) -> bool {
        let identity = |process: &ProcessRef| {
            process.validate()
                && process.sandbox_id == sandbox_id
                && process.generation == generation
        };
        match self {
            Self::Stat { entry } | Self::Rename { entry } => entry.validate(),
            Self::List {
                path,
                depth,
                items,
                next_cursor,
                ..
            } => {
                guest_path(path)
                    && (1..=8).contains(depth)
                    && items.len() <= 100
                    && items.iter().all(EntryInfo::validate)
                    && valid_directory_page(path, *depth, items)
                    && next_cursor.as_ref().is_none_or(|s| opaque_id(s))
            }
            Self::Mkdir { .. } => true,
            Self::Remove { removed } => *removed,
            Self::Processes {
                items, next_cursor, ..
            } => {
                items.len() <= 100
                    && items
                        .iter()
                        .all(|item| item.validate() && identity(&item.process))
                    && ordered_processes(items)
                    && next_cursor.as_ref().is_none_or(|s| opaque_id(s))
            }
            Self::Signal {
                process,
                target_operation_id,
                accepted,
                ..
            } => identity(process) && opaque_id(target_operation_id) && *accepted,
            Self::Command {
                process,
                started_at,
                ..
            } => identity(process) && valid_timestamp(started_at),
        }
    }
}
impl OperationResult {
    pub fn validate(&self) -> bool {
        if !opaque_id(&self.operation_id)
            || !opaque_id(&self.sandbox_id)
            || !(1..=i32::MAX as u32).contains(&self.generation)
            || !valid_timestamp(&self.observed_at)
            || !self.expires_at.as_ref().is_none_or(|s| valid_timestamp(s))
            || !serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= 32768)
        {
            return false;
        }
        let expiring = matches!(
            self.kind,
            ResultKind::StatPath
                | ResultKind::ListDir
                | ResultKind::MovePath
                | ResultKind::ListProcesses
        );
        if expiring != self.expires_at.is_some() {
            return false;
        }
        let Some(body) = &self.result else {
            return self.outcome != ResultOutcome::Succeeded;
        };
        body.kind() == self.kind
            && body.validate(&self.sandbox_id, self.generation)
            && expiring == self.expires_at.is_some()
            && (self.outcome == ResultOutcome::Succeeded
                || (self.kind == ResultKind::RunCommand && self.outcome == ResultOutcome::Pending))
    }
}
// UTC ISO timestamps only. Avoid a second date dependency in this portable crate.
fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return false;
    }
    let number = |from: usize, to: usize| {
        value
            .get(from..to)
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    (1..=max_day).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
        && (bytes.len() == 20
            || (bytes.len() > 21
                && bytes.get(19) == Some(&b'.')
                && bytes
                    .get(20..bytes.len().saturating_sub(1))
                    .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))))
}

#[cfg(test)]
mod result_codec_tests {
    use super::*;
    #[test]
    fn kind_outcome_disclosure_and_encoding_are_strict() {
        let json = r#"{"operationId":"o","sandboxId":"s","generation":1,"kind":"MKDIR","outcome":"succeeded","observedAt":"2026-10-27T00:00:00Z","expiresAt":null,"result":{"type":"file.mkdir","created":false}}"#;
        let result: OperationResult = serde_json::from_str(json).unwrap();
        assert!(result.validate());
        assert!(
            !OperationResult {
                kind: ResultKind::RemovePath,
                ..result.clone()
            }
            .validate()
        );
        assert!(
            !OperationResult {
                outcome: ResultOutcome::Unknown,
                ..result
            }
            .validate()
        );
        assert!(
            serde_json::from_str::<OperationResult>(&json.replace(
                "\"created\":false",
                "\"created\":false,\"path\":\"/private\""
            ))
            .is_err()
        );
        assert!(!valid_timestamp("2026-02-30T00:00:00Z"));
        assert!(valid_timestamp("2024-02-29T00:00:00.123Z"));
    }
}

fn valid_directory_page(root: &str, depth: u32, items: &[EntryInfo]) -> bool {
    let prefix = if root == "/" {
        "/".to_string()
    } else {
        format!("{root}/")
    };
    let within = |entry: &EntryInfo| {
        entry.path.strip_prefix(&prefix).is_some_and(|relative| {
            let mut count = 0;
            let valid = relative.split('/').all(|part| {
                count += 1;
                !part.is_empty() && part != "." && part != ".."
            });
            valid && count <= depth
        })
    };
    items.iter().all(within)
        && items
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.path < right.path))
}
#[cfg(test)]
mod shared_result_fixtures {
    use super::*;
    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        valid: bool,
        value: serde_json::Value,
    }
    #[test]
    fn shares_valid_and_invalid_results_with_typescript() {
        let fixtures: Vec<Fixture> =
            serde_json::from_str(include_str!("../fixtures/typed_results.json")).unwrap();
        for fixture in fixtures {
            assert_eq!(
                serde_json::from_value::<OperationResult>(fixture.value)
                    .is_ok_and(|value| value.validate()),
                fixture.valid,
                "{}",
                fixture.name
            );
        }
    }
}

fn ordered_processes(items: &[ProcessInfo]) -> bool {
    fn time_key(value: &str) -> (&str, u16) {
        let prefix = value.get(..19).map_or("", |part| part);
        let fraction = value.split_once('.').map_or("", |(_, part)| part);
        let mut millis = 0;
        for index in 0..3 {
            millis = millis * 10
                + fraction
                    .as_bytes()
                    .get(index)
                    .filter(|b| b.is_ascii_digit())
                    .map_or(0, |b| u16::from(*b - b'0'));
        }
        (prefix, millis)
    }
    items.windows(2).all(|pair| {
        pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
            let order = time_key(&left.started_at).cmp(&time_key(&right.started_at));
            order.is_lt() || (order.is_eq() && left.process.process_id < right.process.process_id)
        })
    })
}
