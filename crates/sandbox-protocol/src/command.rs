//! Run-command payload bounds and script/argv contract validation.

use crate::command_limits::{
    command_argv_max_count, command_argv_max_utf16_units, command_payload_max_bytes,
};
use crate::error::SandboxErrorCode;

/// Wire None retains the finite default; Some(0) explicitly disables only the command timer.
pub fn validate_command_timeout(timeout_ms: Option<u64>) -> Result<(), (SandboxErrorCode, String)> {
    if timeout_ms.is_some_and(|ms| ms > 1_800_000) {
        return Err((
            SandboxErrorCode::ProtocolError,
            "invalid command timeout".into(),
        ));
    }
    Ok(())
}

fn contains_nul(value: &str) -> bool {
    value.contains('\0')
}

fn validate_no_nul_fields(spec: &CommandRunSpec<'_>) -> Result<(), (SandboxErrorCode, String)> {
    if let Some(script) = spec.script
        && contains_nul(script)
    {
        return Err((
            SandboxErrorCode::ProtocolError,
            "command script must not contain NUL".into(),
        ));
    }
    if let Some(argv) = spec.argv {
        if argv.len() > command_argv_max_count() {
            return Err((
                SandboxErrorCode::ProtocolError,
                "command argv exceeds element count limit".into(),
            ));
        }
        for (index, arg) in argv.iter().enumerate() {
            if contains_nul(arg) {
                return Err((
                    SandboxErrorCode::ProtocolError,
                    format!("command argv[{index}] must not contain NUL"),
                ));
            }
            if arg.encode_utf16().count() > command_argv_max_utf16_units() {
                return Err((
                    SandboxErrorCode::ProtocolError,
                    format!("command argv[{index}] exceeds per-argument length limit"),
                ));
            }
        }
    }
    if let Some(cwd) = spec.cwd
        && contains_nul(cwd)
    {
        return Err((
            SandboxErrorCode::ProtocolError,
            "command cwd must not contain NUL".into(),
        ));
    }
    if let Some(env) = spec.env {
        crate::validate_env(env)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRunSpec<'a> {
    pub argv: Option<&'a [String]>,
    pub script: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub env: Option<&'a [(String, String)]>,
}

pub fn serialized_command_payload_bytes(spec: &CommandRunSpec<'_>) -> usize {
    let body = serde_json::json!({
        "argv": spec.argv,
        "script": spec.script,
        "cwd": spec.cwd,
        "env": spec.env.unwrap_or_default(),
    });
    body.to_string().len()
}

pub fn validate_command_run_spec(
    spec: &CommandRunSpec<'_>,
) -> Result<(), (SandboxErrorCode, String)> {
    let valid_mode = match (spec.argv, spec.script) {
        (Some(argv), None) => !argv.is_empty(),
        (None, Some(script)) => !script.is_empty(),
        _ => false,
    };
    if !valid_mode {
        return Err((
            SandboxErrorCode::ProtocolError,
            "command.run requires exactly one of argv or script".into(),
        ));
    }
    validate_no_nul_fields(spec)?;
    if serialized_command_payload_bytes(spec) > command_payload_max_bytes() {
        return Err((
            SandboxErrorCode::RequestTooLarge,
            "command payload exceeds size limit".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_timeout_wire_encoding_matrix() {
        let base = serde_json::json!({"sandboxOwnerId":"owner", "operationId":"timer", "sandboxId":"sbx", "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"timer", "argv":["true"]});
        for timeout in [None, Some(0), Some(1), Some(120_000), Some(1_800_000)] {
            let mut body = base.clone();
            if let Some(ms) = timeout {
                body["timeoutMs"] = ms.into();
            }
            let dispatch: crate::OperationDispatch = serde_json::from_value(body).unwrap();
            assert_eq!(dispatch.timeout_ms, timeout);
            validate_command_timeout(dispatch.timeout_ms).unwrap();
            let encoded = serde_json::to_value(&dispatch).unwrap();
            if let Some(ms) = timeout {
                assert_eq!(encoded["timeoutMs"], ms);
            }
        }
        assert!(validate_command_timeout(Some(1_800_001)).is_err());
        for invalid in [
            serde_json::json!(-1),
            serde_json::json!(0.5),
            serde_json::json!("0"),
        ] {
            let mut body = base.clone();
            body["timeoutMs"] = invalid;
            assert!(serde_json::from_value::<crate::OperationDispatch>(body).is_err());
        }
    }

    #[test]
    fn c15_shared_payload_boundaries() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Case {
            name: String,
            script_unit: String,
            repeat: usize,
            env_count: usize,
            env_value_bytes: usize,
            expected_bytes: usize,
            valid: bool,
        }
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/command_payload_cases.json")).unwrap();
        for case in cases {
            let script = case.script_unit.repeat(case.repeat);
            let env: Vec<_> = (0..case.env_count)
                .map(|i| (format!("KEY{i}"), "z".repeat(case.env_value_bytes)))
                .collect();
            let spec = CommandRunSpec {
                argv: None,
                script: Some(&script),
                cwd: None,
                env: Some(&env),
            };
            assert_eq!(
                serialized_command_payload_bytes(&spec),
                case.expected_bytes,
                "{}",
                case.name
            );
            assert_eq!(
                validate_command_run_spec(&spec).is_ok(),
                case.valid,
                "{}",
                case.name
            );
            if env.is_empty() {
                assert_eq!(
                    serialized_command_payload_bytes(&CommandRunSpec { env: None, ..spec }),
                    case.expected_bytes
                );
            }
        }
    }

    #[test]
    fn c15_supplied_empty_modes_do_not_bypass_exclusivity() {
        let argv = vec!["true".into()];
        for spec in [
            CommandRunSpec {
                argv: Some(&[]),
                script: Some("true"),
                cwd: None,
                env: None,
            },
            CommandRunSpec {
                argv: Some(&argv),
                script: Some(""),
                cwd: None,
                env: None,
            },
            CommandRunSpec {
                argv: Some(&[]),
                script: None,
                cwd: None,
                env: None,
            },
            CommandRunSpec {
                argv: None,
                script: Some(""),
                cwd: None,
                env: None,
            },
        ] {
            assert_eq!(
                validate_command_run_spec(&spec).unwrap_err().0,
                SandboxErrorCode::ProtocolError
            );
        }
    }

    #[test]
    fn c15_manifest_command_payload_cap_is_32_kib() {
        assert_eq!(command_payload_max_bytes(), 32 * 1024);
    }

    #[test]
    fn c15_shared_argv_boundaries() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Case {
            name: String,
            argv_count: usize,
            segment: Option<String>,
            segment_count: Option<usize>,
            argv_value: Option<String>,
            valid: bool,
        }
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/command_argv_cases.json")).unwrap();
        for case in cases {
            let unit = case
                .argv_value
                .clone()
                .or_else(|| {
                    case.segment
                        .as_ref()
                        .zip(case.segment_count)
                        .map(|(segment, count)| segment.repeat(count))
                })
                .expect("argv fixture");
            let argv: Vec<String> = (0..case.argv_count).map(|_| unit.clone()).collect();
            let spec = CommandRunSpec {
                argv: Some(&argv),
                script: None,
                cwd: None,
                env: None,
            };
            assert_eq!(
                validate_command_run_spec(&spec).is_ok(),
                case.valid,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn c15_rejects_nul_in_script_argv_env_and_cwd() {
        let argv = vec!["ok".into(), "bad\0".into()];
        assert!(
            validate_command_run_spec(&CommandRunSpec {
                argv: Some(&argv),
                script: None,
                cwd: None,
                env: None,
            })
            .is_err()
        );
        assert!(
            validate_command_run_spec(&CommandRunSpec {
                argv: None,
                script: Some("echo\0"),
                cwd: None,
                env: None,
            })
            .is_err()
        );
        assert!(
            validate_command_run_spec(&CommandRunSpec {
                argv: None,
                script: Some("true"),
                cwd: Some("/tmp\0"),
                env: None,
            })
            .is_err()
        );
        let env = vec![("OK".into(), "fine".into()), ("K".into(), "n\0".into())];
        assert!(
            validate_command_run_spec(&CommandRunSpec {
                argv: None,
                script: Some("true"),
                cwd: None,
                env: Some(&env),
            })
            .is_err()
        );
    }

    #[test]
    fn c15_rejects_both_and_neither_command_modes() {
        let argv = vec!["true".to_string()];
        let ok_argv = CommandRunSpec {
            argv: Some(&argv),
            script: None,
            cwd: None,
            env: None,
        };
        assert!(validate_command_run_spec(&ok_argv).is_ok());
        let ok_script = CommandRunSpec {
            argv: None,
            script: Some("echo hi"),
            cwd: None,
            env: None,
        };
        assert!(validate_command_run_spec(&ok_script).is_ok());
        let neither = CommandRunSpec {
            argv: None,
            script: None,
            cwd: None,
            env: None,
        };
        assert!(validate_command_run_spec(&neither).is_err());
        let both = CommandRunSpec {
            argv: Some(&argv),
            script: Some("echo"),
            cwd: None,
            env: None,
        };
        assert!(validate_command_run_spec(&both).is_err());
    }
}
