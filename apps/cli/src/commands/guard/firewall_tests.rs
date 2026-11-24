//! Fake `ufw` / `firewall-cmd` binaries on the child PATH; the real tools
//! never run.

use std::path::PathBuf;

use super::*;

struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn host(&self) -> Host {
        Host {
            path: format!("{}:/usr/bin:/bin", self.dir.path().display()),
        }
    }
    fn tool(&self, name: &str, body: &str) {
        // Never written by this process: a concurrent test's fork would keep
        // a write descriptor and the exec fail with ETXTBSY.
        crate::sandbox_relay::test_support::install_executable(
            &self.file(name),
            format!("#!/bin/sh\n{body}\n"),
            0o755,
        );
    }
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.file(name)).unwrap_or_default()
    }
    /// A stateful ufw: `show added` prints the added rules, `delete <spec>`
    /// and `route delete <spec>` drop the matching line, anything else adds a
    /// rule. Like the real ufw, `delete route …` is a syntax error.
    fn ufw(&self, initial: &[&str]) {
        let state = self.file("ufw.rules");
        let log = self.file("ufw.log");
        std::fs::write(
            &state,
            initial.iter().map(|l| format!("{l}\n")).collect::<String>(),
        )
        .unwrap();
        self.tool(
            "ufw",
            &format!(
                r#"state='{state}'; log='{log}'
echo "$*" >> "$log"
case "$1" in
  show) echo "Added user rules (see 'ufw status' for running firewall):"; cat "$state" ;;
  delete) shift
    if [ "$1" = route ]; then echo "ERROR: Invalid syntax" >&2; exit 1; fi
    spec="$*"; : > "$state.new"
    while IFS= read -r line; do
      case "$line" in "ufw $spec"|"ufw $spec comment "*) ;; *) printf '%s\n' "$line" >> "$state.new" ;; esac
    done < "$state"; mv "$state.new" "$state" ;;
  route) if [ "$2" = delete ]; then shift 2; spec="route $*"; : > "$state.new"
      while IFS= read -r line; do
        case "$line" in "ufw $spec"|"ufw $spec comment "*) ;; *) printf '%s\n' "$line" >> "$state.new" ;; esac
      done < "$state"; mv "$state.new" "$state"
    else line="ufw"; while [ $# -gt 0 ]; do
       if [ "$1" = comment ]; then line="$line comment '$2'"; shift 2; else line="$line $1"; shift; fi
     done; printf '%s\n' "$line" >> "$state"; fi ;;
  *) line="ufw"; while [ $# -gt 0 ]; do
       if [ "$1" = comment ]; then line="$line comment '$2'"; shift 2; else line="$line $1"; shift; fi
     done; printf '%s\n' "$line" >> "$state" ;;
esac"#,
                state = state.display(),
                log = log.display()
            ),
        );
    }
}

#[test]
fn configure_ufw_adds_the_tight_set_once_and_prints_each_rule() {
    let fake = Fake::new();
    fake.ufw(&["ufw allow 22/tcp"]);
    let mut said = Vec::new();
    configure_ufw(&fake.host(), 48081, &mut |line| said.push(line)).unwrap();
    let rules = fake.read("ufw.rules");
    for rule in ufw_rules(48081) {
        assert!(
            rules.contains(&format!("ufw {rule} comment 'wssp-guard managed'\n")),
            "{rule}: {rules}"
        );
        assert!(said.iter().any(|l| l.contains(&rule)), "{said:?}");
    }
    assert!(rules.contains("port 48081 proto tcp"));
    assert!(!rules.contains("ufw allow in on wsn+\n"));
    // Never the broad rule.
    assert!(
        !fake
            .read("ufw.log")
            .lines()
            .any(|l| l == "allow in on wsn+")
    );

    // Idempotent: a second run adds nothing.
    let before = fake.read("ufw.rules");
    let mut again = Vec::new();
    configure_ufw(&fake.host(), 48081, &mut |line| again.push(line)).unwrap();
    assert_eq!(fake.read("ufw.rules"), before);
    assert!(
        again
            .iter()
            .all(|l| l.starts_with("ufw rule already present")),
        "{again:?}"
    );
}

#[test]
fn configure_ufw_replaces_a_broad_allow_and_uninstall_removes_only_its_rules() {
    let fake = Fake::new();
    fake.ufw(&["ufw allow 22/tcp", "ufw allow in on wsn+"]);
    let mut said = Vec::new();
    configure_ufw(&fake.host(), 48080, &mut |line| said.push(line)).unwrap();
    let rules = fake.read("ufw.rules");
    assert!(
        !rules.lines().any(|l| l == "ufw allow in on wsn+"),
        "{rules}"
    );
    assert!(
        said.iter()
            .any(|l| l.starts_with("replacing the broad rule")),
        "{said:?}"
    );
    // The tight set is in place before the broad rule goes.
    let log = fake.read("ufw.log");
    let delete = log
        .lines()
        .position(|l| l == "delete allow in on wsn+")
        .unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let last_add = lines
        .iter()
        .rposition(|l| l.ends_with("wssp-guard managed"))
        .unwrap();
    assert!(last_add < delete, "{log}");

    let mut removed_lines = Vec::new();
    let removed = remove_ufw(&fake.host(), &mut |line| removed_lines.push(line)).unwrap();
    assert_eq!(removed, 6);
    assert_eq!(fake.read("ufw.rules"), "ufw allow 22/tcp\n");
}

/// E2-C-02: a reference host's state (hand-made untagged rules, `53` for any
/// protocol, plus the managed 53/udp and 53/tcp) ends as exactly the tagged
/// set, and uninstall removes all of it.
#[test]
fn configure_ufw_replaces_untagged_equivalents_with_the_tagged_set() {
    let fake = Fake::new();
    fake.ufw(&[
        "ufw allow 22/tcp",
        "ufw allow in on wsn+ to any port 67 proto udp",
        "ufw allow in on wsn+ to any port 53",
        "ufw allow in on wsn+ to any port 48080 proto tcp",
        "ufw route allow in on wsn+",
        "ufw route allow out on wsn+",
        "ufw allow in on wsn+ to any port 53 proto udp comment 'wssp-guard managed'",
        "ufw allow in on wsn+ to any port 53 proto tcp comment 'wssp-guard managed'",
    ]);
    let mut said = Vec::new();
    configure_ufw(&fake.host(), 48080, &mut |line| said.push(line)).unwrap();
    let mut rules: Vec<String> = fake.read("ufw.rules").lines().map(String::from).collect();
    rules.sort();
    let mut expected: Vec<String> = ufw_rules(48080)
        .iter()
        .map(|r| format!("ufw {r} comment 'wssp-guard managed'"))
        .collect();
    expected.push("ufw allow 22/tcp".into());
    expected.sort();
    assert_eq!(rules, expected, "{said:?}");
    for untagged in [
        "ufw delete allow in on wsn+ to any port 53",
        "ufw route delete allow out on wsn+",
    ] {
        assert!(said.iter().any(|l| l.ends_with(untagged)), "{said:?}");
    }
    assert!(said.iter().any(|l| l.starts_with("adding ufw rule")));

    // Idempotent, and uninstall removes everything it manages.
    let before = fake.read("ufw.rules");
    configure_ufw(&fake.host(), 48080, &mut |_| {}).unwrap();
    assert_eq!(fake.read("ufw.rules"), before);
    let removed = remove_ufw(&fake.host(), &mut |_| {}).unwrap();
    assert_eq!(removed, 6);
    assert_eq!(fake.read("ufw.rules"), "ufw allow 22/tcp\n");
}

#[test]
fn a_wider_untagged_rule_than_the_tight_set_is_left_alone() {
    let fake = Fake::new();
    fake.ufw(&["ufw allow in on wsn+ to any port 67"]);
    configure_ufw(&fake.host(), 48080, &mut |_| {}).unwrap();
    assert!(
        fake.read("ufw.rules")
            .contains("ufw allow in on wsn+ to any port 67\n")
    );
}

#[test]
fn configure_refuses_when_the_firewall_is_absent() {
    let fake = Fake::new();
    let mut quiet = |_: String| {};
    let err = configure_ufw(&fake.host(), 48080, &mut quiet).unwrap_err();
    assert!(format!("{err}").contains("ufw is not installed"), "{err}");
    let err = configure_firewalld(&fake.host(), 48080, &mut quiet).unwrap_err();
    assert!(
        format!("{err}").contains("firewalld is not installed"),
        "{err}"
    );
    fake.tool("firewall-cmd", "echo 'not running'; exit 252");
    let err = configure_firewalld(&fake.host(), 48080, &mut quiet).unwrap_err();
    assert!(
        format!("{err}").contains("firewalld is not running"),
        "{err}"
    );
}

#[test]
fn configure_firewalld_builds_a_tight_zone_and_policy() {
    let fake = Fake::new();
    let log = fake.file("fw.log");
    fake.tool(
        "firewall-cmd",
        &format!(
            r#"echo "$*" >> '{log}'
case "$*" in
  "--state") echo running ;;
  "--permanent --zone=trusted --query-interface=wsn+") echo yes ;;
  "--permanent --get-zones") echo "public trusted" ;;
  "--permanent --get-policies") echo "allow-host-ipv6" ;;
esac
exit 0"#,
            log = log.display()
        ),
    );
    let mut said = Vec::new();
    configure_firewalld(&fake.host(), 48080, &mut |line| said.push(line)).unwrap();
    let log = fake.read("fw.log");
    for expected in [
        "--permanent --zone=trusted --remove-interface=wsn+",
        "--permanent --new-zone=wssp-guard",
        "--permanent --zone=wssp-guard --add-interface=wsn+",
        "--permanent --zone=wssp-guard --add-port=67/udp",
        "--permanent --zone=wssp-guard --add-port=53/udp",
        "--permanent --zone=wssp-guard --add-port=53/tcp",
        "--permanent --zone=wssp-guard --add-port=48080/tcp",
        "--permanent --new-policy=wssp-guard-out",
        "--permanent --policy=wssp-guard-out --add-ingress-zone=wssp-guard",
        "--reload",
    ] {
        assert!(log.lines().any(|l| l == expected), "{expected}: {log}");
    }
    assert!(!log.contains("--zone=wssp-guard --set-target"), "{log}");
    assert!(
        said.iter()
            .any(|l| l.starts_with("replacing the broad trusted-zone"))
    );
}
