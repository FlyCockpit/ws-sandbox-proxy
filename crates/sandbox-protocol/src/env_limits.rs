//! One contracts-owned byte budget for command, default and effective env maps.
use crate::SandboxErrorCode;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvLimits {
    pub max_entries: usize,
    pub key_bytes: usize,
    pub value_bytes: usize,
    pub json_bytes: usize,
}

pub static ENV_LIMITS: LazyLock<EnvLimits> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../packages/sandbox-contracts/src/env-limits.json"
    ))
    .expect("env limit manifest")
});

pub fn env_limits() -> &'static EnvLimits {
    &ENV_LIMITS
}

/// Reject duplicates even on the legacy private tuple wire. Errors are constant.
pub fn canonical_env_json(env: &[(String, String)]) -> Result<Vec<u8>, (SandboxErrorCode, String)> {
    let invalid = || {
        (
            SandboxErrorCode::ProtocolError,
            "invalid environment map".into(),
        )
    };
    let too_large = || {
        (
            SandboxErrorCode::RequestTooLarge,
            "environment map exceeds byte limit".into(),
        )
    };
    let limits = env_limits();
    if env.len() > limits.max_entries {
        return Err(too_large());
    }
    let mut map = BTreeMap::new();
    for (key, value) in env {
        if key.is_empty()
            || !key
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || ["__proto__", "prototype", "constructor"].contains(&key.as_str())
            || value.contains('\0')
            || map.insert(key, value).is_some()
        {
            return Err(invalid());
        }
        if key.len() > limits.key_bytes || value.len() > limits.value_bytes {
            return Err(too_large());
        }
    }
    let json = serde_json::to_vec(&map).map_err(|_| invalid())?;
    if json.len() > limits.json_bytes {
        return Err(too_large());
    }
    Ok(json)
}

pub fn validate_env(env: &[(String, String)]) -> Result<(), (SandboxErrorCode, String)> {
    canonical_env_json(env).map(|_| ())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[derive(Deserialize)]
    pub struct Pair {
        pub key: String,
        pub unit: String,
        pub repeat: usize,
        pub tail: String,
    }
    #[derive(Deserialize)]
    pub struct Case {
        pub name: String,
        pub pairs: Vec<Pair>,
        pub bytes: usize,
        pub valid: bool,
    }
    impl Case {
        pub fn env(&self) -> Vec<(String, String)> {
            self.pairs
                .iter()
                .map(|p| (p.key.clone(), p.unit.repeat(p.repeat) + &p.tail))
                .collect()
        }
    }
    #[test]
    fn env_limits_ts_rust_parity() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/env_cases.json")).unwrap();
        for case in cases {
            let env = case.env();
            let map: BTreeMap<_, _> = env.iter().cloned().collect();
            assert_eq!(
                serde_json::to_vec(&map).unwrap().len(),
                case.bytes,
                "{}",
                case.name
            );
            assert_eq!(
                canonical_env_json(&env).is_ok(),
                case.valid,
                "{}",
                case.name
            );
        }
    }
}
