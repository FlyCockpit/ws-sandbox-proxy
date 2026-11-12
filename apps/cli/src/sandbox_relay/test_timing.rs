//! Debug-build-only relay timing override for the reconnect chaos gate
//! (`pnpm test:relay-chaos`, reconnect plan WP1). A debug daemon started with
//!
//! ```text
//! WSSP_TEST_RELAY_TIMING=<silence>,<intent_window>,<max_carry>,<quiesce_max>,<terminal_grace>
//! ```
//!
//! shortens those five deadlines so a chaos cell runs in seconds. Each field
//! is `<n>ms` or `<n>s` (1 ms ..= 24 h); an empty field keeps the default, so
//! `,,2s,,` overrides only `max_carry`. Malformed input is an error, never a
//! silent default: a cell must not pass on production timing by accident.
//!
//! Release builds compile [`relay_test_timing_from`] to a constant `None`
//! without reading the variable, like `state::test_barrier`.

use std::ffi::OsString;
#[cfg(debug_assertions)]
use std::time::Duration;

/// The variable a debug daemon reads at startup. Release builds never
/// reference it (the release smoke step in `cli-ci.yml` checks the binary).
#[cfg(any(debug_assertions, test))]
pub(crate) const RELAY_TIMING_ENV: &str = "WSSP_TEST_RELAY_TIMING";

/// Per-deadline overrides; `None` keeps the production value.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RelayTestTiming {
    /// Floor of the server-silence deadline (`SERVER_SILENCE_MIN`).
    pub silence: Option<Duration>,
    /// Intent-phase carry window (`carry_intent_window`, D4).
    pub intent_window: Option<Duration>,
    /// Carry cap (`max_carry`, D2).
    pub max_carry: Option<Duration>,
    /// Graceful quiesce cap (`quiesce_max`, D9).
    pub quiesce_max: Option<Duration>,
    /// Terminal reattach grace (`terminal_resume_grace`, D5). Clamped to
    /// what the hello may advertise (1 s ..= 10 min), so it is never
    /// shorter than 1 s (`terminal::resume_grace`).
    pub terminal_grace: Option<Duration>,
}

/// Release builds carry no fields and never construct one.
#[cfg(not(debug_assertions))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayTestTiming {}

#[cfg(debug_assertions)]
const MAX_OVERRIDE: Duration = Duration::from_secs(24 * 60 * 60);

#[cfg(debug_assertions)]
fn parse_field(name: &str, text: &str) -> Result<Option<Duration>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let (digits, unit) = if let Some(digits) = text.strip_suffix("ms") {
        (digits, Duration::from_millis(1))
    } else if let Some(digits) = text.strip_suffix('s') {
        (digits, Duration::from_secs(1))
    } else {
        return Err(format!("{name}: `{text}` needs a `ms` or `s` unit"));
    };
    let count: u32 = digits
        .parse()
        .map_err(|_| format!("{name}: `{text}` is not a whole number of {unit:?}"))?;
    let value = unit
        .checked_mul(count)
        .filter(|value| !value.is_zero() && *value <= MAX_OVERRIDE)
        .ok_or_else(|| format!("{name}: `{text}` must be between 1ms and 24h"))?;
    Ok(Some(value))
}

/// Parse the five comma-separated fields.
#[cfg(debug_assertions)]
pub(crate) fn parse_relay_test_timing(text: &str) -> Result<RelayTestTiming, String> {
    const NAMES: [&str; 5] = [
        "silence",
        "intent_window",
        "max_carry",
        "quiesce_max",
        "terminal_grace",
    ];
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() != NAMES.len() {
        return Err(format!(
            "{RELAY_TIMING_ENV} needs {} comma-separated fields \
             (silence,intent_window,max_carry,quiesce_max,terminal_grace), got {}",
            NAMES.len(),
            fields.len()
        ));
    }
    let mut parsed = [None; 5];
    for ((slot, name), field) in parsed.iter_mut().zip(NAMES).zip(fields) {
        *slot = parse_field(name, field)?;
    }
    let [
        silence,
        intent_window,
        max_carry,
        quiesce_max,
        terminal_grace,
    ] = parsed;
    Ok(RelayTestTiming {
        silence,
        intent_window,
        max_carry,
        quiesce_max,
        terminal_grace,
    })
}

/// The override named by `lookup(RELAY_TIMING_ENV)`, if any. Debug builds
/// reject a malformed or non-UTF-8 value.
#[cfg(debug_assertions)]
pub(crate) fn relay_test_timing_from(
    lookup: impl FnOnce(&str) -> Option<OsString>,
) -> anyhow::Result<Option<RelayTestTiming>> {
    let Some(value) = lookup(RELAY_TIMING_ENV) else {
        return Ok(None);
    };
    let text = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{RELAY_TIMING_ENV} is not UTF-8"))?;
    parse_relay_test_timing(&text)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{RELAY_TIMING_ENV}: {error}"))
}

/// Release builds never read the variable.
#[cfg(not(debug_assertions))]
pub(crate) fn relay_test_timing_from(
    _lookup: impl FnOnce(&str) -> Option<OsString>,
) -> anyhow::Result<Option<RelayTestTiming>> {
    Ok(None)
}

/// The process environment's override (read once at daemon start).
pub(crate) fn relay_test_timing() -> anyhow::Result<Option<RelayTestTiming>> {
    relay_test_timing_from(|name| std::env::var_os(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(value: &str) -> impl FnOnce(&str) -> Option<OsString> + '_ {
        move |name| {
            assert_eq!(name, RELAY_TIMING_ENV);
            Some(OsString::from(value))
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn parses_all_five_fields() {
        let timing = parse_relay_test_timing("250ms,2s,3s,4s,500ms").unwrap();
        assert_eq!(
            timing,
            RelayTestTiming {
                silence: Some(Duration::from_millis(250)),
                intent_window: Some(Duration::from_secs(2)),
                max_carry: Some(Duration::from_secs(3)),
                quiesce_max: Some(Duration::from_secs(4)),
                terminal_grace: Some(Duration::from_millis(500)),
            }
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn empty_fields_keep_defaults() {
        let timing = parse_relay_test_timing(",, 2s ,,").unwrap();
        assert_eq!(
            timing,
            RelayTestTiming {
                max_carry: Some(Duration::from_secs(2)),
                ..RelayTestTiming::default()
            }
        );
        assert_eq!(
            parse_relay_test_timing(",,,,").unwrap(),
            RelayTestTiming::default()
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn rejects_malformed_values() {
        for bad in [
            "",
            "1s",
            "1s,1s,1s,1s",
            "1s,1s,1s,1s,1s,1s",
            "1,1s,1s,1s,1s",
            "1m,,,,",
            "0s,,,,",
            "0ms,,,,",
            "-1s,,,,",
            "1.5s,,,,",
            "86401s,,,,",
            "4294967296ms,,,,",
            "s,,,,",
        ] {
            assert!(parse_relay_test_timing(bad).is_err(), "accepted `{bad}`");
        }
        assert_eq!(
            parse_relay_test_timing("86400s,,,,").unwrap().silence,
            Some(MAX_OVERRIDE)
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_lookup_reads_and_validates_the_variable() {
        assert_eq!(relay_test_timing_from(|_| None).unwrap(), None);
        let timing = relay_test_timing_from(lookup("1s,,,,")).unwrap().unwrap();
        assert_eq!(timing.silence, Some(Duration::from_secs(1)));
        let error = relay_test_timing_from(lookup("nope")).unwrap_err();
        assert!(error.to_string().contains(RELAY_TIMING_ENV), "{error}");
        if std::env::var_os(RELAY_TIMING_ENV).is_none() {
            assert_eq!(relay_test_timing().unwrap(), None);
        }
    }

    /// Release builds ignore the variable entirely, even a malformed one.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_is_inert() {
        assert!(
            relay_test_timing_from(lookup("1s,1s,1s,1s,1s"))
                .unwrap()
                .is_none()
        );
        assert!(relay_test_timing_from(lookup("garbage")).unwrap().is_none());
        assert!(
            relay_test_timing_from(|_| panic!("release builds must not read the variable"))
                .unwrap()
                .is_none()
        );
        assert!(relay_test_timing().unwrap().is_none());
    }
}
