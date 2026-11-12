//! Process-local policy authority. Local off/failure latches until an explicit
//! local enable revision; startup flags never override a later file change.
use crate::config::Config;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Policy {
    pub enabled: bool,
    pub required: bool,
    pub revision: u64,
}

pub(super) struct HostPolicy {
    path: Option<PathBuf>,
    file_seen: bool,
    saved: (bool, bool, u64, u64),
    policy: Policy,
    latched: bool,
    next_read: Instant,
    /// Host lease ceiling (`None` = unlimited). Kept out of the terminal tuple
    /// so a change never bumps the terminal `policy_revision`.
    lease_ceiling: Option<u64>,
    lease_changed: bool,
    lease_read_failed: bool,
    /// Node egress policy (§3): consent and settings, reloaded on the same
    /// schedule. An unreadable config withdraws consent (fail closed) and
    /// keeps the last settings.
    egress: (bool, sandbox_runtime::egress::EgressSettings),
    /// `allow_guest_sudo_for_others` (default on), reloaded with the egress
    /// consent and reported in the same change; unreadable config is off.
    guest_sudo_for_others: bool,
    egress_changed: bool,
}
fn tuple(c: &Config) -> (bool, bool, u64, u64) {
    (
        c.allow_host_terminal,
        c.host_terminal_require_totp,
        c.host_terminal_policy_revision,
        c.host_terminal_enable_revision,
    )
}
impl HostPolicy {
    pub fn new(config: &Config, startup: Option<bool>, path: Option<PathBuf>) -> Self {
        let enabled = startup.unwrap_or(config.allow_host_terminal);
        Self {
            file_seen: path.as_ref().is_some_and(|p| p.exists()),
            path,
            saved: tuple(config),
            policy: Policy {
                enabled,
                required: config.host_terminal_require_totp,
                revision: config.host_terminal_policy_revision,
            },
            latched: !enabled,
            next_read: Instant::now(),
            lease_ceiling: config.max_lease.ceiling_ms(),
            lease_changed: false,
            lease_read_failed: false,
            egress: (config.open_egress_for_others(), config.egress_settings()),
            guest_sudo_for_others: config.guest_sudo_for_others(),
            egress_changed: false,
        }
    }
    /// Live open-egress consent for other users' sandboxes.
    pub fn open_egress_for_others(&self) -> bool {
        self.egress.0
    }
    /// Live guest-sudo consent for other users' sandboxes.
    pub fn guest_sudo_for_others(&self) -> bool {
        self.guest_sudo_for_others
    }
    fn set_guest_sudo_for_others(&mut self, value: bool) {
        if value != self.guest_sudo_for_others {
            self.guest_sudo_for_others = value;
            self.egress_changed = true;
        }
    }
    /// Live node egress settings (without the guard's domain blocklist).
    pub fn egress_settings(&self) -> &sandbox_runtime::egress::EgressSettings {
        &self.egress.1
    }
    /// True once per observed change of the egress consent or settings.
    pub fn take_egress_change(&mut self) -> bool {
        std::mem::take(&mut self.egress_changed)
    }
    fn set_egress(&mut self, egress: (bool, sandbox_runtime::egress::EgressSettings)) {
        if egress != self.egress {
            self.egress = egress;
            self.egress_changed = true;
        }
    }
    pub fn current(&self) -> Policy {
        self.policy
    }
    /// The live host lease ceiling; `None` means unlimited.
    pub fn lease_ceiling(&self) -> Option<u64> {
        self.lease_ceiling
    }
    /// True once per observed change of the configured lease ceiling.
    pub fn take_lease_change(&mut self) -> bool {
        std::mem::take(&mut self.lease_changed)
    }
    pub fn refresh(&mut self, now: Instant) -> bool {
        if now < self.next_read {
            return false;
        }
        // A second leaves scheduling slack inside the two-second revocation bound.
        self.next_read = now + Duration::from_secs(1);
        let Some(path) = &self.path else {
            return false;
        };
        let was_seen = self.file_seen;
        let read = match std::fs::metadata(path) {
            Ok(metadata) => {
                self.file_seen = true;
                (metadata.len() <= 65536)
                    .then(|| Config::read(path).ok())
                    .flatten()
            }
            // A never-created default config is valid, including an explicit
            // startup override. Deleting an observed file fails closed.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !self.file_seen => {
                Some(Config::default())
            }
            Err(_) => None,
        };
        let Some(config) = read else {
            // Fail closed: no open egress for other users' sandboxes while
            // the config cannot be read; settings keep their last value.
            let settings = self.egress.1.clone();
            self.set_egress((false, settings));
            self.set_guest_sudo_for_others(false);
            // An unreadable or deleted config never raises (or changes) the
            // lease ceiling: keep the last value.
            if !self.lease_read_failed {
                self.lease_read_failed = true;
                tracing::warn!(
                    "config unreadable; keeping the last host lease ceiling ({})",
                    describe_ceiling(self.lease_ceiling)
                );
            }
            if !self.latched || self.policy.enabled || !self.policy.required {
                self.latched = true;
                self.policy.enabled = false;
                self.policy.required = true;
                self.advance();
                return true;
            }
            return false;
        };
        self.lease_read_failed = false;
        self.set_egress((config.open_egress_for_others(), config.egress_settings()));
        self.set_guest_sudo_for_others(config.guest_sudo_for_others());
        let ceiling = config.max_lease.ceiling_ms();
        if ceiling != self.lease_ceiling {
            self.lease_ceiling = ceiling;
            self.lease_changed = true;
        }
        let next = tuple(&config);
        if next == self.saved && self.file_seen == was_seen {
            return false;
        }
        let explicit_enable = next.3 > self.saved.3 && next.0;
        if explicit_enable {
            self.latched = false;
        }
        if !next.0 {
            self.latched = true;
        }
        self.saved = next;
        self.policy.enabled = next.0 && !self.latched;
        self.policy.required = next.1;
        self.advance();
        true
    }
    fn advance(&mut self) {
        // Fail closed at the wire integer ceiling; never wrap or reuse revision.
        if self.policy.revision >= 9_007_199_254_740_990 {
            self.policy.enabled = false;
            self.policy.required = true;
        } else {
            self.policy.revision = (self.policy.revision + 1)
                .max(self.saved.2)
                .min(9_007_199_254_740_991);
        }
    }
}

pub(super) fn describe_ceiling(ceiling: Option<u64>) -> String {
    ceiling.map_or_else(
        || "unlimited".to_owned(),
        |ms| crate::config::MaxLease::Finite(ms).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn egress_consent_and_settings_reload_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = Config::default();
        save(&path, &c);
        let mut p = HostPolicy::new(&c, None, Some(path.clone()));
        let mut now = Instant::now();
        p.refresh(now);
        assert!(!p.open_egress_for_others());
        assert!(!p.take_egress_change());
        c.allow_open_egress_for_others = Some(true);
        c.egress_block_smtp = false;
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change());
        assert!(!p.take_egress_change(), "reported once");
        assert!(p.open_egress_for_others());
        assert!(!p.egress_settings().block_smtp);
        // Unreadable: consent withdrawn, settings kept.
        std::fs::write(&path, "egress_dns_upstreams = [\"0.0.0.0\"]").unwrap();
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change());
        assert!(!p.open_egress_for_others());
        assert!(!p.egress_settings().block_smtp);
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change());
        assert!(p.open_egress_for_others());
    }
    #[test]
    fn guest_sudo_consent_defaults_on_reloads_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = Config::default();
        save(&path, &c);
        let mut p = HostPolicy::new(&c, None, Some(path.clone()));
        let mut now = Instant::now();
        p.refresh(now);
        assert!(p.guest_sudo_for_others());
        assert!(!p.take_egress_change());
        c.allow_guest_sudo_for_others = Some(false);
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change(), "a consent change is reported");
        assert!(!p.guest_sudo_for_others());
        c.allow_guest_sudo_for_others = None;
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change());
        assert!(p.guest_sudo_for_others());
        std::fs::write(&path, "egress_dns_upstreams = [\"0.0.0.0\"]").unwrap();
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_egress_change());
        assert!(
            !p.guest_sudo_for_others(),
            "unreadable config withdraws consent"
        );
    }
    fn save(path: &std::path::Path, c: &Config) {
        std::fs::write(path, toml::to_string(c).unwrap()).unwrap();
    }
    #[test]
    fn hot_off_failure_latch_manual_changes_and_explicit_enable_override_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = Config::default();
        save(&path, &c);
        let mut p = HostPolicy::new(&c, Some(true), Some(path.clone()));
        let mut now = Instant::now();
        assert!(!p.refresh(now));
        assert!(p.current().enabled);
        c.set_host_terminal(false).unwrap();
        save(&path, &c);
        now += Duration::from_secs(1);
        assert!(p.refresh(now));
        assert!(!p.current().enabled);
        let revision = p.current().revision;
        // A manual true cannot undo the off latch.
        c.allow_host_terminal = true;
        save(&path, &c);
        now += Duration::from_secs(1);
        assert!(p.refresh(now));
        assert!(!p.current().enabled);
        c.set_host_terminal(true).unwrap();
        save(&path, &c);
        now += Duration::from_secs(1);
        assert!(p.refresh(now));
        assert!(p.current().enabled);
        std::fs::write(&path, "allow_host_terminal = 'invalid'").unwrap();
        now += Duration::from_secs(1);
        assert!(p.refresh(now));
        assert!(!p.current().enabled);
        assert!(p.current().required);
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(!p.current().enabled);
        c.set_host_terminal(true).unwrap();
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.current().enabled);
        assert!(p.current().revision > revision);
        std::fs::remove_file(&path).unwrap();
        now += Duration::from_secs(1);
        assert!(p.refresh(now));
        assert!(!p.current().enabled);
    }
    #[test]
    fn defaults_required_repeated_off_and_local_only_lower() {
        let mut c: Config = toml::from_str("").unwrap();
        assert!(!c.allow_host_terminal);
        assert!(c.host_terminal_require_totp);
        c.set_host_terminal(false).unwrap();
        let rev = c.host_terminal_policy_revision;
        c.set_host_terminal(false).unwrap();
        assert_eq!(c.host_terminal_policy_revision, rev + 1);
        c.set_host_terminal_totp(false).unwrap();
        assert!(!c.host_terminal_require_totp);
        c.set_host_terminal_totp(true).unwrap();
        assert!(c.host_terminal_require_totp);
    }
}

#[cfg(test)]
mod absent_tests {
    use super::*;
    #[test]
    fn explicit_startup_override_survives_absent_defaults_until_a_local_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut p = HostPolicy::new(&Config::default(), Some(true), Some(path.clone()));
        let now = Instant::now();
        assert!(!p.refresh(now));
        assert!(p.current().enabled);
        std::fs::write(&path, "").unwrap();
        assert!(p.refresh(now + Duration::from_secs(1)));
        assert!(!p.current().enabled);
    }
}

#[cfg(test)]
mod coalesced_tests {
    use super::*;
    #[test]
    fn local_enable_followed_by_totp_change_before_watch_still_unlatches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let mut policy = HostPolicy::new(&config, None, Some(path.clone()));
        config.set_host_terminal(true).unwrap();
        config.set_host_terminal_totp(false).unwrap();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(policy.refresh(Instant::now()));
        assert!(policy.current().enabled);
        assert!(!policy.current().required);
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    use crate::config::MaxLease;
    fn save(path: &std::path::Path, c: &Config) {
        std::fs::write(path, toml::to_string(c).unwrap()).unwrap();
    }

    #[test]
    fn lease_ceiling_hot_reloads_without_bumping_the_terminal_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = Config::default();
        save(&path, &c);
        let mut p = HostPolicy::new(&c, None, Some(path.clone()));
        let mut now = Instant::now();
        assert_eq!(p.lease_ceiling(), Some(86_400_000));
        assert!(!p.refresh(now));
        assert!(!p.take_lease_change());
        let revision = p.current().revision;
        c.set_max_lease(MaxLease::Finite(21_600_000));
        save(&path, &c);
        now += Duration::from_secs(1);
        assert!(!p.refresh(now), "no terminal policy change");
        assert!(p.take_lease_change());
        assert!(!p.take_lease_change(), "reported once");
        assert_eq!(p.lease_ceiling(), Some(21_600_000));
        assert_eq!(p.current().revision, revision);
        c.set_max_lease(MaxLease::Unlimited);
        save(&path, &c);
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(p.take_lease_change());
        assert_eq!(p.lease_ceiling(), None);
        assert_eq!(p.current().revision, revision);
    }

    #[test]
    fn unreadable_or_deleted_config_keeps_the_last_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut c = Config::default();
        c.set_max_lease(MaxLease::Finite(3_600_000));
        save(&path, &c);
        let mut p = HostPolicy::new(&c, None, Some(path.clone()));
        let mut now = Instant::now();
        std::fs::write(&path, "max_lease = \"forever\"").unwrap();
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(!p.take_lease_change());
        assert_eq!(p.lease_ceiling(), Some(3_600_000));
        std::fs::remove_file(&path).unwrap();
        now += Duration::from_secs(1);
        p.refresh(now);
        assert!(!p.take_lease_change());
        assert_eq!(p.lease_ceiling(), Some(3_600_000));
    }
}
