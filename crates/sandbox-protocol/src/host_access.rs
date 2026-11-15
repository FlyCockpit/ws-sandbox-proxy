//! Owner-only host access. All byte limits are measured before serialization.
use serde::{Deserialize, Serialize};

/// Host file text may expand sixfold when escaped in JSON. Other relay frames retain their old ceiling.
pub const HOST_CONTROL_MAX_BYTES: usize = 2 * 1024 * 1024;
pub const HOST_COMMAND_MAX_BYTES: usize = 16_384;
pub const HOST_OUTPUT_MAX_BYTES: usize = 65_536;
pub const HOST_FILE_MAX_BYTES: usize = 262_144;
pub const HOST_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
fn safe(v: u64) -> bool {
    v <= HOST_SAFE_INTEGER
}
fn id(v: &str) -> bool {
    crate::valid_terminal_id(v)
}
fn epoch(v: u32) -> bool {
    v > 0 && v <= i32::MAX as u32
}
fn text(v: &str, max: usize) -> bool {
    v.len() <= max && !v.contains('\0')
}
pub fn valid_host_command_id(v: &str) -> bool {
    v.len() == 22
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub fn valid_host_file_etag(v: &str) -> bool {
    v.strip_prefix("h:").is_some_and(valid_host_command_id)
}
pub fn valid_host_command_max_ms(v: u64) -> bool {
    (1_000..=86_400_000).contains(&v)
}
pub fn valid_host_agent_policy(
    commands: bool,
    files: bool,
    max: Option<u64>,
    revision: u64,
) -> bool {
    safe(revision)
        && (!files || commands)
        && match max {
            Some(v) => commands && valid_host_command_max_ms(v),
            None => !commands,
        }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostAgentPolicyV11 {
    pub connection_epoch: u32,
    pub sequence: u64,
    pub host_commands: bool,
    pub host_files: bool,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_command_max_ms: Option<u64>,
    pub agent_policy_revision: u64,
}
impl HostAgentPolicyV11 {
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch)
            && self.sequence > 0
            && safe(self.sequence)
            && valid_host_agent_policy(
                self.host_commands,
                self.host_files,
                self.host_command_max_ms,
                self.agent_policy_revision,
            )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostPolicyLowerTarget {
    HostCommands,
    HostTerminal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPolicyLowerV11 {
    pub connection_epoch: u32,
    pub request_id: String,
    pub target: HostPolicyLowerTarget,
}
impl HostPolicyLowerV11 {
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch) && id(&self.request_id)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPolicyLowerResultV11 {
    pub request_id: String,
    pub ok: bool,
}
impl HostPolicyLowerResultV11 {
    pub fn is_valid(&self) -> bool {
        id(&self.request_id)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecStartV11 {
    pub connection_epoch: u32,
    pub request_id: String,
    pub command_id: String,
    pub owner_id: String,
    pub agent_policy_revision: u64,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub argv: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub script: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub cwd: Option<String>,
    pub timeout_ms: u64,
    pub stdin: bool,
}
impl HostExecStartV11 {
    pub fn valid_command(&self) -> bool {
        match (&self.argv, &self.script) {
            (Some(argv), None) => {
                !argv.is_empty()
                    && argv.len() <= 256
                    && !argv[0].is_empty()
                    && argv.iter().all(|v| text(v, 4096))
                    && argv.iter().map(String::len).sum::<usize>() <= HOST_COMMAND_MAX_BYTES
            }
            (None, Some(script)) => !script.is_empty() && text(script, HOST_COMMAND_MAX_BYTES),
            _ => false,
        }
    }
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch)
            && id(&self.request_id)
            && valid_host_command_id(&self.command_id)
            && id(&self.owner_id)
            && safe(self.agent_policy_revision)
            && self.valid_command()
            && self.cwd.as_ref().is_none_or(|v| text(v, 4096))
            && self.timeout_ms > 0
            && safe(self.timeout_ms)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecPollV11 {
    pub connection_epoch: u32,
    pub request_id: String,
    pub command_id: String,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub max_bytes: usize,
}
impl HostExecPollV11 {
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch)
            && id(&self.request_id)
            && valid_host_command_id(&self.command_id)
            && safe(self.stdout_offset)
            && safe(self.stderr_offset)
            && self.max_bytes <= HOST_OUTPUT_MAX_BYTES
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecStdinV11 {
    pub connection_epoch: u32,
    pub request_id: String,
    pub command_id: String,
    pub data: String,
    pub eof: bool,
}
impl HostExecStdinV11 {
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch)
            && id(&self.request_id)
            && valid_host_command_id(&self.command_id)
            && self.data.len() <= 87_384
            && decode_host_data(&self.data).is_some_and(|b| b.len() <= HOST_OUTPUT_MAX_BYTES)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecCancelV11 {
    pub connection_epoch: u32,
    pub request_id: String,
    pub command_id: String,
}
impl HostExecCancelV11 {
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch)
            && id(&self.request_id)
            && valid_host_command_id(&self.command_id)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostExecRejectReason {
    HostCommandsOff,
    PolicyChanged,
    OwnerMismatch,
    BadCommand,
    BadCwd,
    Limit,
    Duplicate,
    SpawnFailed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecStartedV11 {
    pub request_id: String,
    pub command_id: String,
    pub started_at: u64,
    pub ends_by: u64,
}
impl HostExecStartedV11 {
    pub fn is_valid(&self) -> bool {
        id(&self.request_id)
            && valid_host_command_id(&self.command_id)
            && safe(self.ends_by)
            && self.started_at <= self.ends_by
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecRejectedV11 {
    pub request_id: String,
    pub command_id: String,
    pub reason: HostExecRejectReason,
}
impl HostExecRejectedV11 {
    pub fn is_valid(&self) -> bool {
        id(&self.request_id) && valid_host_command_id(&self.command_id)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostExecState {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecOutputV11 {
    pub offset: u64,
    pub data: String,
    pub dropped: bool,
}
impl HostExecOutputV11 {
    pub fn is_valid(&self) -> bool {
        safe(self.offset)
            && self.data.len() <= 87_384
            && decode_host_data(&self.data).is_some_and(|b| b.len() <= HOST_OUTPUT_MAX_BYTES)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecStatusV11 {
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_id: Option<String>,
    pub command_id: String,
    pub state: HostExecState,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub exit_code: Option<i32>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub signal: Option<i32>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub started_at: Option<u64>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub ends_by: Option<u64>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<u64>,
    pub stdout: HostExecOutputV11,
    pub stderr: HostExecOutputV11,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}
impl HostExecStatusV11 {
    pub fn is_valid(&self) -> bool {
        self.request_id.as_ref().is_none_or(|v| id(v))
            && valid_host_command_id(&self.command_id)
            && self.stdout.is_valid()
            && self.stderr.is_valid()
            && [
                self.started_at,
                self.ends_by,
                self.finished_at,
                Some(self.stdout_bytes),
                Some(self.stderr_bytes),
            ]
            .iter()
            .all(|v| v.is_none_or(safe))
            && self.signal.is_none_or(|v| (1..=127).contains(&v))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecStdinResultV11 {
    pub request_id: String,
    pub command_id: String,
    pub accepted: bool,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<String>,
}
impl HostExecStdinResultV11 {
    pub fn is_valid(&self) -> bool {
        id(&self.request_id)
            && valid_host_command_id(&self.command_id)
            && self.reason.as_ref().is_none_or(|v| text(v, 64))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFileError {
    HostFilesOff,
    PolicyChanged,
    OwnerMismatch,
    NoRoots,
    PathDenied,
    NotFound,
    NotAFile,
    NotADir,
    TooLarge,
    BinaryFile,
    Conflict,
    NoMatch,
    MatchCount,
    RedactedSpan,
    Exists,
    InvalidInput,
    IoError,
    Limit,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileEditV11 {
    pub old_text: String,
    pub new_text: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "op",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostFileRequestV11 {
    Read {
        connection_epoch: u32,
        request_id: String,
        owner_id: String,
        agent_policy_revision: u64,
        path: String,
        #[serde(
            default,
            deserialize_with = "crate::egress::present",
            skip_serializing_if = "Option::is_none"
        )]
        offset: Option<u64>,
        #[serde(
            default,
            deserialize_with = "crate::egress::present",
            skip_serializing_if = "Option::is_none"
        )]
        max_bytes: Option<usize>,
    },
    List {
        connection_epoch: u32,
        request_id: String,
        owner_id: String,
        agent_policy_revision: u64,
        path: String,
    },
    Write {
        connection_epoch: u32,
        request_id: String,
        owner_id: String,
        agent_policy_revision: u64,
        path: String,
        content: String,
        #[serde(
            default,
            deserialize_with = "crate::egress::present",
            skip_serializing_if = "Option::is_none"
        )]
        expected_etag: Option<String>,
        #[serde(
            default,
            deserialize_with = "crate::egress::present",
            skip_serializing_if = "Option::is_none"
        )]
        create_only: Option<bool>,
    },
    Edit {
        connection_epoch: u32,
        request_id: String,
        owner_id: String,
        agent_policy_revision: u64,
        path: String,
        edits: Vec<HostFileEditV11>,
        #[serde(
            default,
            deserialize_with = "crate::egress::present",
            skip_serializing_if = "Option::is_none"
        )]
        expected_etag: Option<String>,
    },
}
impl HostFileRequestV11 {
    pub fn connection_epoch(&self) -> u32 {
        match self {
            Self::Read {
                connection_epoch, ..
            } => *connection_epoch,
            Self::List {
                connection_epoch, ..
            } => *connection_epoch,
            Self::Write {
                connection_epoch, ..
            } => *connection_epoch,
            Self::Edit {
                connection_epoch, ..
            } => *connection_epoch,
        }
    }
    pub fn request_id(&self) -> &str {
        match self {
            Self::Read { request_id, .. } => request_id,
            Self::List { request_id, .. } => request_id,
            Self::Write { request_id, .. } => request_id,
            Self::Edit { request_id, .. } => request_id,
        }
    }
    pub fn owner_id(&self) -> &str {
        match self {
            Self::Read { owner_id, .. } => owner_id,
            Self::List { owner_id, .. } => owner_id,
            Self::Write { owner_id, .. } => owner_id,
            Self::Edit { owner_id, .. } => owner_id,
        }
    }
    pub fn agent_policy_revision(&self) -> u64 {
        match self {
            Self::Read {
                agent_policy_revision,
                ..
            } => *agent_policy_revision,
            Self::List {
                agent_policy_revision,
                ..
            } => *agent_policy_revision,
            Self::Write {
                agent_policy_revision,
                ..
            } => *agent_policy_revision,
            Self::Edit {
                agent_policy_revision,
                ..
            } => *agent_policy_revision,
        }
    }
    pub fn path(&self) -> &str {
        match self {
            Self::Read { path, .. } => path,
            Self::List { path, .. } => path,
            Self::Write { path, .. } => path,
            Self::Edit { path, .. } => path,
        }
    }
    pub fn is_valid(&self) -> bool {
        epoch(self.connection_epoch())
            && id(self.request_id())
            && id(self.owner_id())
            && safe(self.agent_policy_revision())
            && !self.path().is_empty()
            && text(self.path(), 4096)
            && match self {
                Self::Read {
                    offset, max_bytes, ..
                } => offset.is_none_or(safe) && max_bytes.is_none_or(|v| v <= HOST_FILE_MAX_BYTES),
                Self::List { .. } => true,
                Self::Write {
                    content,
                    expected_etag,
                    ..
                } => {
                    content.len() <= HOST_FILE_MAX_BYTES
                        && expected_etag
                            .as_ref()
                            .is_none_or(|v| valid_host_file_etag(v))
                }
                Self::Edit {
                    edits,
                    expected_etag,
                    ..
                } => {
                    !edits.is_empty()
                        && edits.len() <= 20
                        && edits.iter().all(|e| {
                            !e.old_text.is_empty()
                                && e.old_text.len() <= HOST_FILE_MAX_BYTES
                                && e.new_text.len() <= HOST_FILE_MAX_BYTES
                        })
                        && edits
                            .iter()
                            .map(|e| e.old_text.len() + e.new_text.len())
                            .sum::<usize>()
                            <= HOST_FILE_MAX_BYTES
                        && expected_etag
                            .as_ref()
                            .is_none_or(|v| valid_host_file_etag(v))
                }
            }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileResultV11 {
    pub request_id: String,
    pub ok: bool,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub result: Option<HostFileValueV11>,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<HostFileError>,
}
impl HostFileResultV11 {
    pub fn is_valid(&self) -> bool {
        id(&self.request_id)
            && match (&self.result, &self.error) {
                (Some(v), None) => self.ok && v.is_valid(),
                (None, Some(_)) => !self.ok,
                _ => false,
            }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostFileValueV11 {
    Read(HostFileReadV11),
    List(HostFileListV11),
    Write(HostFileWriteV11),
    Edit(HostFileEditedV11),
}
impl HostFileValueV11 {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Read(v) => {
                v.content.len() <= HOST_FILE_MAX_BYTES
                    && safe(v.offset)
                    && safe(v.size)
                    && valid_host_file_etag(&v.etag)
            }
            Self::List(v) => {
                v.entries.len() <= 1000
                    && v.entries.iter().all(|e| {
                        !e.name.is_empty() && text(&e.name, 4096) && e.size.is_none_or(safe)
                    })
            }
            Self::Write(v) => safe(v.size) && valid_host_file_etag(&v.etag),
            Self::Edit(v) => {
                safe(v.size) && valid_host_file_etag(&v.etag) && (1..=20).contains(&v.replacements)
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileReadV11 {
    pub content: String,
    pub offset: u64,
    pub size: u64,
    pub etag: String,
    pub truncated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileListV11 {
    pub entries: Vec<HostFileEntryV11>,
    pub truncated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileEntryV11 {
    pub name: String,
    pub kind: HostFileKind,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub size: Option<u64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFileKind {
    File,
    Dir,
    Symlink,
    Other,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileWriteV11 {
    pub etag: String,
    pub size: u64,
    pub created: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFileEditedV11 {
    pub etag: String,
    pub size: u64,
    pub replacements: usize,
}

/// Standard padded base64 for host output/stdin (distinct from vault base64url).
pub fn encode_host_data(bytes: &[u8]) -> String {
    let mut value = crate::encode_chunk_data(bytes)
        .replace('-', "+")
        .replace('_', "/");
    while !value.len().is_multiple_of(4) {
        value.push('=');
    }
    value
}
pub fn decode_host_data(text: &str) -> Option<Vec<u8>> {
    if text.len() > 87_384 || !text.len().is_multiple_of(4) {
        return None;
    }
    let unpadded = text.trim_end_matches('=');
    if text.len() - unpadded.len() > 2
        || !unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return None;
    }
    let url = unpadded.replace('+', "-").replace('/', "_");
    let len = crate::chunk_data_len(&url)?;
    if len > HOST_OUTPUT_MAX_BYTES {
        return None;
    }
    let mut bytes = vec![0; len];
    crate::decode_chunk_data_into(&url, &mut bytes)?;
    (encode_host_data(&bytes) == text).then_some(bytes)
}
