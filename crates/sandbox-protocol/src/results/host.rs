//! Versioned private host content. Live frames and recovered receipts use this
//! same codec; public envelopes are reconstructed from fenced database rows.
use super::{
    Failure, ProcessStarted, ResultBody, ResultKind, guest_path, opaque_id, valid_timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultContinuation {
    pub last_key: String,
    pub root: String,
    pub depth: u32,
    pub limit: usize,
    pub generation: u32,
    pub kind: ResultKind,
}
impl ResultContinuation {
    pub fn validate(&self) -> bool {
        self.last_key.len() <= 4096
            && !self.last_key.contains('\0')
            && guest_path(&self.root)
            && (1..=8).contains(&self.depth)
            && (1..=100).contains(&self.limit)
            && (1..=i32::MAX as u32).contains(&self.generation)
            && matches!(self.kind, ResultKind::ListDir | ResultKind::ListProcesses)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostOperationResult {
    pub version: u32,
    pub observed_at: String,
    #[serde(deserialize_with = "required_nullable")]
    pub payload: Option<ResultBody>,
    #[serde(deserialize_with = "required_nullable")]
    pub continuation: Option<ResultContinuation>,
    #[serde(
        deserialize_with = "required_nullable",
        serialize_with = "serialize_birth"
    )]
    pub birth: Option<ProcessStarted>,
    #[serde(deserialize_with = "required_nullable")]
    pub failure: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub result_expired: bool,
}
// Nested identity evidence uses the same encoder as a live process.started;
// ProcessStarted and DaemonControlMessage deliberately have no Serialize impl.
fn serialize_birth<S: serde::Serializer>(
    birth: &Option<ProcessStarted>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = birth
        .as_ref()
        .map(|started| {
            let encoded = crate::WireCodes::negotiated(crate::SANDBOX_RELAY_PROTOCOL_VERSION)
                .encode(&crate::DaemonControlMessage::from(started.clone()), None)
                .map_err(serde::ser::Error::custom)?;
            serde_json::from_str::<serde_json::Value>(&encoded.text)
                .map_err(serde::ser::Error::custom)
        })
        .transpose()?;
    value.serialize(serializer)
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
impl HostOperationResult {
    pub fn validate(&self, kind: ResultKind, sandbox: &str, generation: u32) -> bool {
        self.version == 1
            && valid_timestamp(&self.observed_at)
            && serde_json::to_vec(self).is_ok_and(|b| b.len() <= 24576)
            && self
                .payload
                .as_ref()
                .is_none_or(|p| p.kind() == kind && p.validate(sandbox, generation))
            && self
                .continuation
                .as_ref()
                .is_none_or(|c| c.validate() && c.kind == kind && c.generation == generation)
            && self.birth.as_ref().is_none_or(|b| {
                b.validate()
                    && kind == ResultKind::RunCommand
                    && b.sandbox_id == sandbox
                    && b.generation == generation
            })
            && match &self.payload {
                Some(ResultBody::Command {
                    process,
                    started_at,
                    ..
                }) => self.birth.as_ref().is_some_and(|b| {
                    b.process_id == process.process_id
                        && b.pid == process.pid
                        && b.attempt == process.attempt
                        && b.started_at == *started_at
                }),
                Some(_) => self.birth.is_none(),
                None => true,
            }
            && self
                .output_bytes
                .is_none_or(|n| kind == ResultKind::RunCommand && n <= 9_007_199_254_740_991)
            && (!self.result_expired
                || (content_kind(kind) && self.payload.is_none() && self.continuation.is_none()))
            && match &self.payload {
                Some(
                    ResultBody::List { next_cursor, .. }
                    | ResultBody::Processes { next_cursor, .. },
                ) => {
                    next_cursor.is_some() == self.continuation.is_some()
                        && next_cursor.as_ref().is_none_or(|s| opaque_id(s))
                }
                _ => self.continuation.is_none(),
            }
    }
}
pub fn content_kind(kind: ResultKind) -> bool {
    matches!(
        kind,
        ResultKind::StatPath
            | ResultKind::ListDir
            | ResultKind::MovePath
            | ResultKind::ListProcesses
    )
}
pub fn kind_from_dispatch(kind: &str) -> Option<ResultKind> {
    Some(match kind {
        "file.stat" => ResultKind::StatPath,
        "file.list" => ResultKind::ListDir,
        "file.mkdir" => ResultKind::Mkdir,
        "file.remove" => ResultKind::RemovePath,
        "file.move" => ResultKind::MovePath,
        "process.list" => ResultKind::ListProcesses,
        "process.signal" => ResultKind::SignalProcess,
        "command.run" => ResultKind::RunCommand,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Deserialize)]
    struct Case {
        name: String,
        kind: ResultKind,
        valid: bool,
        value: serde_json::Value,
    }
    #[test]
    fn shares_host_result_codec_cases_with_typescript() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../../fixtures/host_results.json")).unwrap();
        assert!(cases.iter().any(|c| !c.valid));
        for c in cases {
            assert_eq!(
                serde_json::from_value::<HostOperationResult>(c.value)
                    .is_ok_and(|r| r.validate(c.kind, "sandbox", 1)),
                c.valid,
                "{}",
                c.name
            );
        }
    }
}
