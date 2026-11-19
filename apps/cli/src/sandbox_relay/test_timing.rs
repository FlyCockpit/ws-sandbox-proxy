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
//!
//! `WSSP_TEST_RUNTIME_TIMING` (below) is the same kind of debug-only knob
//! for two runtime waits and the storage poll; it only ever lengthens them.

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

/// Debug-build-only, widen-only runtime timing override for test daemons
/// that drive the Incus double (`pnpm test:cancel-wire`, relay chaos):
///
/// ```text
/// WSSP_TEST_RUNTIME_TIMING=<guest_terminate>,<expiry_observation>,<storage_poll>
/// ```
///
/// The double runs the guest terminate helper and every Incus call on the
/// host, so under CPU load the helper's 2 s exec deadline and the connected
/// expiry observation's 4 s permit run out on work a VM does in
/// milliseconds. Each field uses the relay knob's syntax (empty keeps the
/// default) but may only lengthen its deadline: below the production value
/// or above its cap (60 s; 10 s for `storage_poll`) is a start error, as is
/// a malformed or non-UTF-8 value or a wrong field count.
///
/// The effective `expiry_observation` must stay below the effective
/// `storage_poll`. A completed observation whose starting storage sequence
/// a newer poll overtook is dropped and retried at once (`connect.rs`), so
/// the server never judges root evidence older than the pool's last storage
/// observation (`stale_storage`). Back-to-back retries shorter than the poll
/// period always find a poll-free window; a permit at least as long as the
/// period lets every slow observation be overtaken forever (a livelock the
/// widened permit alone produced: observations of 5-8 s under load against
/// the 5 s poll). Hence `storage_poll`, which widens both together.
///
/// It is refused unless the control plane is loopback and
/// `WSSP_INCUS_BINARY` names an Incus double. Release builds compile
/// [`runtime_test_timing_from`] to a constant `None` without reading it.
#[cfg(any(debug_assertions, test))]
pub(crate) const RUNTIME_TIMING_ENV: &str = "WSSP_TEST_RUNTIME_TIMING";

/// Per-deadline widenings; `None` keeps the production value.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RuntimeTestTiming {
    /// The guest terminate helper's exec deadline
    /// (`sandbox_runtime::GUEST_TERMINATE_TIMEOUT`).
    pub guest_terminate: Option<Duration>,
    /// The connected expiry observation's permit
    /// (`connect::EXPIRY_OBSERVATION_TIMEOUT`).
    pub expiry_observation: Option<Duration>,
    /// The storage health poll period, start to start
    /// (`host_reports::STORAGE_POLL_MS`).
    pub storage_poll: Option<Duration>,
}

/// Release builds carry no fields and never construct one.
#[cfg(not(debug_assertions))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeTestTiming {}

/// Production floor of `guest_terminate`; a test pins it to the runtime's
/// `GUEST_TERMINATE_TIMEOUT` (that crate's Incus module is Linux-only).
#[cfg(debug_assertions)]
const GUEST_TERMINATE_FLOOR: Duration = Duration::from_secs(2);

/// The longest either runtime wait may be widened to.
#[cfg(debug_assertions)]
const RUNTIME_OVERRIDE_MAX: Duration = Duration::from_secs(60);

/// Production storage poll period, the floor of `storage_poll`.
#[cfg(debug_assertions)]
const STORAGE_POLL_FLOOR: Duration = Duration::from_millis(super::host_reports::STORAGE_POLL_MS);

/// The slowest storage poll a test daemon may use. A pool's storage record
/// is fresh for 15 s on both sides (the daemon's `STORAGE_FRESH_MS`, the
/// server's `STORAGE_HEALTH_STALE_MS`), and between two reports it ages by
/// the poll period plus the next observation and its delivery. 10 s leaves
/// 5 s for those, the same margin as production's 5 s poll leaves 10 s:
/// a slower poll would let a healthy test host's storage turn stale and
/// refuse creates for a reason production never shows.
#[cfg(debug_assertions)]
const STORAGE_POLL_MAX: Duration = Duration::from_secs(10);

/// Parse the three comma-separated fields, each widen-only, and require
/// the effective expiry observation to stay below the effective storage
/// poll (see [`RUNTIME_TIMING_ENV`]).
#[cfg(debug_assertions)]
pub(crate) fn parse_runtime_test_timing(text: &str) -> Result<RuntimeTestTiming, String> {
    let bounds = [
        (
            "guest_terminate",
            GUEST_TERMINATE_FLOOR,
            RUNTIME_OVERRIDE_MAX,
        ),
        (
            "expiry_observation",
            super::connect::EXPIRY_OBSERVATION_TIMEOUT,
            RUNTIME_OVERRIDE_MAX,
        ),
        ("storage_poll", STORAGE_POLL_FLOOR, STORAGE_POLL_MAX),
    ];
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() != bounds.len() {
        return Err(format!(
            "{RUNTIME_TIMING_ENV} needs {} comma-separated fields \
             (guest_terminate,expiry_observation,storage_poll), got {}",
            bounds.len(),
            fields.len()
        ));
    }
    let mut parsed = [None; 3];
    for ((slot, (name, floor, max)), field) in parsed.iter_mut().zip(bounds).zip(fields) {
        *slot = parse_field(name, field)?;
        if let Some(value) = *slot
            && !(floor..=max).contains(&value)
        {
            return Err(format!(
                "{name}: `{}` may only widen the production {floor:?}, up to {max:?}",
                field.trim()
            ));
        }
    }
    let [guest_terminate, expiry_observation, storage_poll] = parsed;
    let observation = expiry_observation.unwrap_or(super::connect::EXPIRY_OBSERVATION_TIMEOUT);
    let poll = storage_poll.unwrap_or(STORAGE_POLL_FLOOR);
    if observation >= poll {
        return Err(format!(
            "expiry_observation {observation:?} must stay below storage_poll {poll:?}: an \
             observation a newer storage poll overtook is retried, and one as long as the \
             poll period may never converge"
        ));
    }
    Ok(RuntimeTestTiming {
        guest_terminate,
        expiry_observation,
        storage_poll,
    })
}

/// The override named by `lookup(RUNTIME_TIMING_ENV)`, if any. Debug builds
/// refuse a malformed value, and any value unless `server_url` is a
/// loopback control plane and `lookup("WSSP_INCUS_BINARY")` is set.
#[cfg(debug_assertions)]
pub(crate) fn runtime_test_timing_from(
    lookup: impl Fn(&str) -> Option<OsString>,
    server_url: &str,
) -> anyhow::Result<Option<RuntimeTestTiming>> {
    let Some(value) = lookup(RUNTIME_TIMING_ENV) else {
        return Ok(None);
    };
    let text = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{RUNTIME_TIMING_ENV} is not UTF-8"))?;
    let timing = parse_runtime_test_timing(&text)
        .map_err(|error| anyhow::anyhow!("{RUNTIME_TIMING_ENV}: {error}"))?;
    if !super::connect::loopback_control_plane(server_url).unwrap_or(false) {
        anyhow::bail!(
            "{RUNTIME_TIMING_ENV} is a test-only override accepted only with a loopback control \
             plane (`localhost`, 127.0.0.0/8 or `::1`); unset it"
        );
    }
    if lookup("WSSP_INCUS_BINARY").is_none() {
        anyhow::bail!(
            "{RUNTIME_TIMING_ENV} is a test-only override for an Incus double and needs \
             `WSSP_INCUS_BINARY`; unset it"
        );
    }
    Ok(Some(timing))
}

/// Release builds never read the variable.
#[cfg(not(debug_assertions))]
pub(crate) fn runtime_test_timing_from(
    _lookup: impl Fn(&str) -> Option<OsString>,
    _server_url: &str,
) -> anyhow::Result<Option<RuntimeTestTiming>> {
    Ok(None)
}

/// The process environment's runtime override (read once at daemon start).
pub(crate) fn runtime_test_timing(server_url: &str) -> anyhow::Result<Option<RuntimeTestTiming>> {
    runtime_test_timing_from(|name| std::env::var_os(name), server_url)
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

    /// A runtime-knob environment: the variable, an Incus double, nothing else.
    fn runtime_env(value: &str, incus_binary: bool) -> impl Fn(&str) -> Option<OsString> + '_ {
        move |name| match name {
            RUNTIME_TIMING_ENV => Some(OsString::from(value)),
            "WSSP_INCUS_BINARY" => incus_binary.then(|| OsString::from("/tmp/incus")),
            other => panic!("unexpected lookup of {other}"),
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn runtime_timing_parses_widenings_and_keeps_empty_fields_default() {
        assert_eq!(
            parse_runtime_test_timing("30s,9s,10s").unwrap(),
            RuntimeTestTiming {
                guest_terminate: Some(Duration::from_secs(30)),
                expiry_observation: Some(Duration::from_secs(9)),
                storage_poll: Some(Duration::from_secs(10)),
            }
        );
        assert_eq!(
            parse_runtime_test_timing(" , 4s,").unwrap(),
            RuntimeTestTiming {
                expiry_observation: Some(Duration::from_secs(4)),
                ..RuntimeTestTiming::default()
            }
        );
        assert_eq!(
            parse_runtime_test_timing(",,").unwrap(),
            RuntimeTestTiming::default()
        );
        // The bounds themselves are accepted.
        let edges = parse_runtime_test_timing("60s,4999ms,").unwrap();
        assert_eq!(edges.guest_terminate, Some(RUNTIME_OVERRIDE_MAX));
        assert_eq!(edges.expiry_observation, Some(Duration::from_millis(4999)));
        let edges = parse_runtime_test_timing("2s,,10s").unwrap();
        assert_eq!(edges.guest_terminate, Some(GUEST_TERMINATE_FLOOR));
        assert_eq!(edges.storage_poll, Some(STORAGE_POLL_MAX));
        let edges = parse_runtime_test_timing(",4s,5s").unwrap();
        assert_eq!(edges.storage_poll, Some(STORAGE_POLL_FLOOR));
        assert_eq!(
            parse_runtime_test_timing(",9999ms,10s")
                .unwrap()
                .expiry_observation,
            Some(Duration::from_millis(9999))
        );
    }

    /// The expiry observation must end before the next storage poll can
    /// overtake it, for every combination of explicit and default fields.
    #[cfg(debug_assertions)]
    #[test]
    fn runtime_timing_keeps_the_expiry_observation_below_the_storage_poll() {
        for bad in [
            ",5s,",
            ",20s,",
            ",5s,5s",
            ",10s,10s",
            ",9s,8s",
            "30s,20s,10s",
        ] {
            let error = parse_runtime_test_timing(bad).unwrap_err();
            assert!(error.contains("below storage_poll"), "`{bad}`: {error}");
        }
    }

    /// Widen-only: nothing below the production deadline or above 60 s, and
    /// malformed input is an error, never a silent default.
    #[cfg(debug_assertions)]
    #[test]
    fn runtime_timing_refuses_shortening_overlong_and_malformed_values() {
        for bad in [
            "",
            "30s",
            "30s,4s",
            "30s,4s,5s,",
            "1999ms,,",
            "1s,,",
            ",3999ms,",
            ",3s,",
            "61s,,",
            ",60001ms,10s",
            "30,,",
            ",1m,",
            "0s,,",
            "-5s,,",
            "2.5s,,",
            ",,4999ms",
            ",,4s",
            ",,10001ms",
            ",,11s",
            ",,10",
        ] {
            assert!(parse_runtime_test_timing(bad).is_err(), "accepted `{bad}`");
        }
    }

    /// The floors are the production constants, and production itself
    /// keeps the expiry observation below the storage poll.
    #[cfg(debug_assertions)]
    #[test]
    fn runtime_timing_floors_are_the_production_constants() {
        let observation = super::super::connect::EXPIRY_OBSERVATION_TIMEOUT;
        let poll = Duration::from_millis(super::super::host_reports::STORAGE_POLL_MS);
        assert_eq!(observation, Duration::from_secs(4));
        assert_eq!(STORAGE_POLL_FLOOR, poll);
        assert!(observation < poll, "{observation:?} >= {poll:?}");
        // The poll cap leaves the freshness bound a 5 s margin.
        assert_eq!(
            Duration::from_millis(super::super::host_reports::STORAGE_FRESH_MS)
                .checked_sub(STORAGE_POLL_MAX),
            Some(Duration::from_secs(5))
        );
    }

    /// The storage poll override reaches the daemon's storage reports.
    #[cfg(debug_assertions)]
    #[test]
    fn storage_poll_override_reaches_the_host_reports() {
        use super::super::host_reports::{STORAGE_POLL_MS, storage_poll_ms_for};
        assert_eq!(storage_poll_ms_for(None), STORAGE_POLL_MS);
        let keeps = parse_runtime_test_timing("30s,,").unwrap();
        assert_eq!(storage_poll_ms_for(Some(keeps)), STORAGE_POLL_MS);
        let widened = parse_runtime_test_timing(",9s,10s").unwrap();
        assert_eq!(storage_poll_ms_for(Some(widened)), 10_000);
    }

    /// The floor the parser enforces is the runtime's own constant.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    #[test]
    fn guest_terminate_floor_is_the_runtime_constant() {
        assert_eq!(
            GUEST_TERMINATE_FLOOR,
            sandbox_runtime::GUEST_TERMINATE_TIMEOUT
        );
    }

    /// Gates: only with a loopback control plane and an Incus double; every
    /// other combination refuses the start instead of ignoring the value.
    #[cfg(debug_assertions)]
    #[test]
    fn runtime_timing_needs_a_loopback_control_plane_and_an_incus_double() {
        assert_eq!(
            runtime_test_timing_from(|_| None, "https://wssp.example.com").unwrap(),
            None
        );
        for server in [
            "http://127.0.0.1:4310",
            "ws://127.0.0.1:4310",
            "https://localhost",
            "http://[::1]:3000",
        ] {
            let timing = runtime_test_timing_from(runtime_env("30s,,", true), server)
                .unwrap()
                .unwrap();
            assert_eq!(timing.guest_terminate, Some(Duration::from_secs(30)));
        }
        for server in [
            "https://wssp.example.com",
            "https://10.0.0.5",
            "https://localhost.example.com",
            "not a url",
        ] {
            let error = runtime_test_timing_from(runtime_env("30s,,", true), server).unwrap_err();
            assert!(error.to_string().contains("loopback"), "{error}");
        }
        let error =
            runtime_test_timing_from(runtime_env("30s,,", false), "http://127.0.0.1").unwrap_err();
        assert!(error.to_string().contains("WSSP_INCUS_BINARY"), "{error}");
        let error =
            runtime_test_timing_from(runtime_env("1s,,", true), "http://127.0.0.1").unwrap_err();
        assert!(error.to_string().contains(RUNTIME_TIMING_ENV), "{error}");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let error = runtime_test_timing_from(
                |name| (name == RUNTIME_TIMING_ENV).then(|| OsString::from_vec(vec![0xff])),
                "http://127.0.0.1",
            )
            .unwrap_err();
            assert!(error.to_string().contains("not UTF-8"), "{error}");
        }
    }

    /// Release builds ignore the runtime knob entirely, even a malformed one.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_ignores_the_runtime_knob() {
        for value in ["30s,9s,10s", "1s,,", "garbage"] {
            assert!(
                runtime_test_timing_from(runtime_env(value, true), "http://127.0.0.1")
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            runtime_test_timing_from(
                |_| panic!("release builds must not read the variable"),
                "http://127.0.0.1"
            )
            .unwrap()
            .is_none()
        );
        assert!(runtime_test_timing("http://127.0.0.1").unwrap().is_none());
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
