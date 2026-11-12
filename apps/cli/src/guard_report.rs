//! The node-local egress guard summary that `wssp login`, `wssp connect` and
//! `wssp config show` print (see docs/guide/hosts.md#egress-guard).
//! The guard is root-owned and installed once per node; daemons never run
//! `sudo`, they print the exact install command.

use serde::Serialize;

/// One policy source as `config show` reports it: state and digest, never
/// the contents.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceReport {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardReport {
    /// The guard answered on its socket or left a status file.
    pub installed: bool,
    pub ok: bool,
    /// Bounded machine code (`guard_unreachable`, `guard_root_source`, ...).
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_source: Option<SourceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_source: Option<SourceReport>,
    /// Guard set sizes and repair counters (diagnostics only).
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub counts: std::collections::BTreeMap<String, u64>,
}

#[cfg(target_os = "linux")]
fn source_report(source: &sandbox_runtime::guard_probe::GuardSourceStatus) -> SourceReport {
    use sandbox_runtime::guard_probe::GuardSourceState;
    SourceReport {
        state: match source.state {
            GuardSourceState::Valid => "valid",
            GuardSourceState::NotConfigured => "not_configured",
            GuardSourceState::Invalid => "invalid",
            GuardSourceState::Missing => "missing",
            GuardSourceState::Unknown => "unknown",
        },
        digest: source.digest.clone(),
    }
}

impl GuardReport {
    /// Ask this node's guard (socket, then status file).
    pub fn local() -> Self {
        #[cfg(target_os = "linux")]
        {
            let (status, _source, verdict) = crate::commands::guard::local_snapshot();
            Self {
                installed: status.is_some(),
                ok: verdict.is_ok(),
                reason: verdict.err().map(|reason| reason.as_str()),
                root_source: status
                    .as_ref()
                    .map(|status| source_report(&status.sources.root)),
                deployment_source: status
                    .as_ref()
                    .map(|status| source_report(&status.sources.deployment)),
                counts: status.map(|status| status.counts).unwrap_or_default(),
            }
        }
        #[cfg(not(target_os = "linux"))]
        Self {
            installed: false,
            ok: false,
            reason: Some("guard_unreachable"),
            root_source: None,
            deployment_source: None,
            counts: Default::default(),
        }
    }

    /// The fix to print when the guard is not healthy: the install command
    /// when it is missing or outdated, else what to repair.
    pub fn hint(&self) -> Option<String> {
        if self.ok {
            return None;
        }
        let reason = self.reason.unwrap_or("guard_not_ok");
        let fix = match reason {
            "guard_unreachable" | "guard_outdated" => format!(
                "the egress guard is not installed or is outdated ({reason}); new sandboxes cannot start on this node. Install it once, as root:\n  {}",
                install_command()
            ),
            "guard_root_source" => format!(
                "the egress guard is not healthy ({reason}): fix `{}` (see `wssp guard status`); new sandboxes cannot start on this node",
                sandbox_runtime::guard::ROOT_BLOCKLIST_PATH
            ),
            "host_firewall_blocks_sandboxes" => sandbox_runtime::guard::path::HOST_FIREWALL_FIX
                .replace(
                    "--daemon-user <user>",
                    &format!("--daemon-user {}", install_user()),
                ),
            "guard_quarantined" => format!(
                "the egress guard is quarantined ({reason}): an unsupported packet path or a failed resync; see `wssp guard status`. New sandboxes cannot start on this node"
            ),
            _ => format!(
                "the egress guard is not healthy ({reason}); see `wssp guard status`. New sandboxes cannot start on this node. If it is not running, reinstall it:\n  {}",
                install_command()
            ),
        };
        Some(fix)
    }
}

/// `sudo <this binary> guard install --daemon-user <user>` with the running
/// binary's path and the current user's name.
pub fn install_command() -> String {
    let exe = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "wssp".into());
    format!("sudo {exe} guard install --daemon-user {}", install_user())
}

/// `$USER` when it is a plain user name, else `<user>`.
fn install_user() -> String {
    std::env::var("USER")
        .ok()
        .filter(|user| {
            !user.is_empty()
                && user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
        .unwrap_or_else(|| "<user>".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_names_the_install_command_only_when_the_guard_is_missing_or_old() {
        let mut report = GuardReport {
            installed: false,
            ok: false,
            reason: Some("guard_unreachable"),
            root_source: None,
            deployment_source: None,
            counts: Default::default(),
        };
        let hint = report.hint().unwrap();
        assert!(hint.contains("guard install --daemon-user "), "{hint}");
        assert!(hint.starts_with("the egress guard is not installed"));
        report.reason = Some("guard_root_source");
        assert!(
            report
                .hint()
                .unwrap()
                .contains("/etc/wssp/egress-blocklist")
        );
        report.reason = Some("host_firewall_blocks_sandboxes");
        let hint = report.hint().unwrap();
        assert!(hint.contains("--configure-ufw"), "{hint}");
        assert!(hint.contains("sudo ufw route allow in on wsn+"), "{hint}");
        assert!(hint.contains("port 67 proto udp"), "{hint}");
        // Never the broad rule.
        assert!(
            !hint
                .lines()
                .any(|l| l.trim() == "sudo ufw allow in on wsn+"),
            "{hint}"
        );
        report.ok = true;
        report.reason = None;
        assert!(report.hint().is_none());
    }
}
