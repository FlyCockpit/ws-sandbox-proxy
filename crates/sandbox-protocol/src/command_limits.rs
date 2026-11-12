//! Command payload and control-frame bounds shared with the TypeScript peer.
use serde::Deserialize;
use std::sync::LazyLock;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandLimits {
    pub command_payload_bytes: usize,
    pub json_control_max_bytes: usize,
    pub command_argv_max_count: usize,
    pub command_argv_max_utf16_units: usize,
}

pub static COMMAND_LIMITS: LazyLock<CommandLimits> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../packages/config/src/sandbox-command-limits.json"
    ))
    .expect("command limit manifest")
});

pub fn command_payload_max_bytes() -> usize {
    COMMAND_LIMITS.command_payload_bytes
}

pub fn json_control_max_bytes() -> usize {
    COMMAND_LIMITS.json_control_max_bytes
}

pub fn command_argv_max_count() -> usize {
    COMMAND_LIMITS.command_argv_max_count
}

pub fn command_argv_max_utf16_units() -> usize {
    COMMAND_LIMITS.command_argv_max_utf16_units
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c15_manifest_matches_documented_caps() {
        assert_eq!(command_payload_max_bytes(), 32 * 1024);
        assert_eq!(json_control_max_bytes(), 64 * 1024);
        assert_eq!(command_argv_max_count(), 256);
        assert_eq!(command_argv_max_utf16_units(), 512);
    }
}
