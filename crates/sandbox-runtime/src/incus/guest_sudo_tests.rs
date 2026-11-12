//! Guest sudo helper: argv, the strict record, verdict decisions, and the
//! real helper run against a temp tree with fake `sudo`/`visudo` shims (never
//! real sudo on the dev host).
use super::*;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn out(stderr: &str) -> IncusCommandOutput {
    IncusCommandOutput {
        stdout: String::new(),
        stderr: stderr.into(),
        exit_code: 0,
    }
}

#[test]
fn argv_is_host_derived_and_never_uid_zero() {
    let guest = crate::GuestIdentity::default();
    let argv = guest_sudo_argv(GuestSudoStep::Grant, NONCE, &guest).unwrap();
    assert_eq!(argv[..5], ["python3", "-I", "-S", "-B", "-c"]);
    assert_eq!(argv[5], GUEST_SUDO_HELPER);
    assert_eq!(argv[6..], ["grant", NONCE, "1000", "1000"]);
    let audit = guest_sudo_argv(GuestSudoStep::RevokeAudit, NONCE, &guest).unwrap();
    assert_eq!(audit[6], "revoke-audit");
    let revoke = guest_sudo_argv(GuestSudoStep::Revoke { strict: false }, NONCE, &guest).unwrap();
    assert_eq!(revoke[6], "revoke");
    let root = crate::GuestIdentity {
        guest_uid: 0,
        ..guest
    };
    assert!(guest_sudo_argv(GuestSudoStep::Grant, NONCE, &root).is_err());
}

#[test]
fn records_are_strict_nonce_bound_and_mode_scoped() {
    let grant = GuestSudoStep::Grant;
    let parsed = parse_sudo_record(
        grant,
        NONCE,
        &out(&format!("WSSP_SUDO {NONCE} granted sudo_rs\n")),
    )
    .unwrap();
    assert_eq!(parsed.verdict, SudoVerdict::Granted);
    assert_eq!(parsed.implementation, "sudo_rs");
    for bad in [
        format!("WSSP_SUDO {NONCE} granted sudo_rs"),
        format!("WSSP_SUDO {NONCE} granted guest-text\n"),
        format!("WSSP_SUDO ffff{} granted sudo_ws\n", &NONCE[4..]),
        format!("WSSP_SUDO {NONCE} granted sudo_ws extra\n"),
        format!("WSSP_SUDO {NONCE} revoked sudo_ws\n"),
        format!("x\nWSSP_SUDO {NONCE} granted sudo_ws\n"),
    ] {
        assert!(
            parse_sudo_record(grant, NONCE, &out(&bad)).is_none(),
            "{bad}"
        );
    }
    let mut stdout = out(&format!("WSSP_SUDO {NONCE} granted sudo_ws\n"));
    stdout.stdout = "noise".into();
    assert!(parse_sudo_record(grant, NONCE, &stdout).is_none());
    let audit = GuestSudoStep::RevokeAudit;
    let root = parse_sudo_record(
        audit,
        NONCE,
        &out(&format!(
            "WSSP_SUDO {NONCE} root_granted sudo_ws group_docker\n"
        )),
    )
    .unwrap();
    assert_eq!(root.verdict, SudoVerdict::RootGranted("group_docker"));
    // Only constant forms.
    assert!(
        parse_sudo_record(
            audit,
            NONCE,
            &out(&format!(
                "WSSP_SUDO {NONCE} root_granted sudo_ws group_mine\n"
            ))
        )
        .is_none()
    );
    // `clean` belongs to the audit only.
    assert!(
        parse_sudo_record(
            GuestSudoStep::Revoke { strict: true },
            NONCE,
            &out(&format!("WSSP_SUDO {NONCE} clean none\n"))
        )
        .is_none()
    );
}

#[test]
fn each_verdict_maps_to_its_readiness_reason() {
    use SudoVerdict as V;
    let rec = |verdict| {
        Some(SudoRecord {
            verdict,
            implementation: "sudo_ws",
        })
    };
    assert!(decide(GuestSudoStep::Grant, rec(V::Granted)).is_ok());
    for verdict in [V::SudoMissing, V::UnsafeDir, V::Invalid, V::NotEffective] {
        let err = decide(GuestSudoStep::Grant, rec(verdict)).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::GuestUnavailable);
        assert_eq!(
            err.readiness_reason(),
            Some(ReadinessFailureReason::GuestSudoUnavailable)
        );
    }
    assert_eq!(
        decide(GuestSudoStep::Grant, None)
            .unwrap_err()
            .readiness_reason(),
        Some(ReadinessFailureReason::GuestSudoUnavailable)
    );
    let strict = GuestSudoStep::Revoke { strict: true };
    assert!(decide(strict, rec(V::Revoked)).is_ok());
    assert!(decide(GuestSudoStep::RevokeAudit, rec(V::Clean)).is_ok());
    assert!(decide(GuestSudoStep::RevokeAudit, rec(V::AuditInconclusive)).is_ok());
    for step in [strict, GuestSudoStep::RevokeAudit] {
        assert_eq!(
            decide(step, rec(V::RootGranted("sudoers_dir")))
                .unwrap_err()
                .readiness_reason(),
            Some(ReadinessFailureReason::GuestRootGranted)
        );
        assert_eq!(
            decide(step, None).unwrap_err().readiness_reason(),
            Some(ReadinessFailureReason::GuestCheck)
        );
    }
    // After create a removal never fails the boot.
    let lax = GuestSudoStep::Revoke { strict: false };
    assert!(decide(lax, rec(V::RootGranted("sudoers_dir"))).is_ok());
    assert!(decide(lax, None).is_ok());
}

#[test]
fn steps_follow_create_and_boot_rules() {
    use crate::GuestPrivilege;
    assert_eq!(
        GuestSudoStep::for_create(GuestPrivilege {
            sudo: true,
            audit: false
        }),
        GuestSudoStep::Grant
    );
    assert_eq!(
        GuestSudoStep::for_create(GuestPrivilege {
            sudo: false,
            audit: true
        }),
        GuestSudoStep::RevokeAudit
    );
    assert_eq!(
        GuestSudoStep::for_create(GuestPrivilege::default()),
        GuestSudoStep::Revoke { strict: true }
    );
    assert_eq!(GuestSudoStep::for_boot(true), GuestSudoStep::Grant);
    assert_eq!(
        GuestSudoStep::for_boot(false),
        GuestSudoStep::Revoke { strict: false }
    );
}

// ---- the real helper against a temp tree --------------------------------

struct Tree {
    root: PathBuf,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

fn shim(path: &Path, body: &str, bits: u32) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    mode(path, bits);
}

/// A minimal guest tree: `/etc/sudoers.d`, a setuid sudo shim, `visudo`.
/// `sudo` answers `-V` with `version`, `-n true` with `effective`, and
/// `-n -l -U <user>` per `list` (a shell `case` on `$4`).
fn tree(version: &str, effective: bool, list: &str) -> Tree {
    let root = std::env::temp_dir().join(format!(
        "wssp-sudo-{}-{}",
        std::process::id(),
        super::super::client::random_nonce().unwrap()
    ));
    for dir in ["etc/sudoers.d", "usr/bin", "usr/sbin", "usr/local"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    for dir in [
        "",
        "etc",
        "etc/sudoers.d",
        "usr",
        "usr/bin",
        "usr/sbin",
        "usr/local",
    ] {
        mode(&root.join(dir), 0o755);
    }
    std::fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
    )
    .unwrap();
    std::fs::write(root.join("etc/group"), "root:x:0:\nuser:x:1000:\n").unwrap();
    std::fs::write(root.join("etc/shadow"), "root:*:1::::::\nuser:!:1::::::\n").unwrap();
    let ok = if effective { 0 } else { 1 };
    shim(
        &root.join("usr/bin/sudo"),
        &format!(
            "case \"$1\" in -V) echo '{version}'; exit 0;; esac\nif [ \"$1 $2\" = '-n true' ]; then exit {ok}; fi\nif [ \"$1 $2 $3\" = '-n -l -U' ]; then case \"$4\" in {list} esac; fi\nexit 9"
        ),
        0o4755,
    );
    shim(&root.join("usr/sbin/visudo"), "exit 0", 0o755);
    Tree { root }
}

const NOT_ALLOWED: &str = "*) echo 'User user is not allowed to run sudo on host.'; exit 0;;";
const MAY_RUN: &str = "*) echo 'User user may run the following commands on host:'; echo ' (ALL) NOPASSWD: ALL'; exit 0;;";

fn run_helper(tree: &Tree, mode: &str) -> String {
    let harness = format!(
        "import os, sys\nsrc = sys.stdin.read()\ng = {{'__name__': 'wssp_test'}}\nexec(compile(src, 'guest-sudo-helper', 'exec'), g)\ng['ROOT'] = {root:?}\ng['TRUSTED_UID'] = os.getuid()\ng['TRUSTED_GID'] = os.getgid()\ng['AS_GUEST'] = False\nsys.argv = ['helper', {mode:?}, {NONCE:?}, '1000', '1000']\ntry:\n    g['main']()\nexcept SystemExit:\n    pass\n",
        root = tree.root.to_str().unwrap(),
    );
    let mut child = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", &harness])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(GUEST_SUDO_HELPER.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty(), "no stdout");
    String::from_utf8(out.stderr).unwrap()
}

fn record(stderr: &str) -> String {
    stderr
        .strip_prefix(&format!("WSSP_SUDO {NONCE} "))
        .unwrap_or_else(|| panic!("record: {stderr}"))
        .trim_end()
        .to_string()
}

#[test]
fn grant_replaces_a_stale_temp_writes_0440_and_proves_the_effect() {
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    std::fs::write(t.root.join("etc/.wssp-sudoers.tmp"), "stale").unwrap();
    assert_eq!(record(&run_helper(&t, "grant")), "granted sudo_ws");
    let dropin = t.root.join("etc/sudoers.d/wssp-guest");
    assert_eq!(
        std::fs::read_to_string(&dropin).unwrap(),
        "#1000 ALL=(ALL) NOPASSWD:ALL\n"
    );
    assert_eq!(
        std::fs::metadata(&dropin).unwrap().permissions().mode() & 0o7777,
        0o440
    );
    assert!(!t.root.join("etc/.wssp-sudoers.tmp").exists());
    // Idempotent: an identical file is rewritten atomically.
    assert_eq!(record(&run_helper(&t, "grant")), "granted sudo_ws");
}

#[test]
fn grant_follows_the_sudo_rs_alternatives_chain_but_not_a_writable_hop() {
    let t = tree("sudo-rs 0.2.8", true, NOT_ALLOWED);
    let real = t.root.join("usr/lib/cargo/bin");
    std::fs::create_dir_all(&real).unwrap();
    for dir in ["usr/lib", "usr/lib/cargo", "usr/lib/cargo/bin"] {
        mode(&t.root.join(dir), 0o755);
    }
    std::fs::rename(t.root.join("usr/bin/sudo"), real.join("sudo")).unwrap();
    std::fs::create_dir_all(t.root.join("etc/alternatives")).unwrap();
    mode(&t.root.join("etc/alternatives"), 0o755);
    symlink(
        "/usr/lib/cargo/bin/sudo",
        t.root.join("etc/alternatives/sudo"),
    )
    .unwrap();
    symlink("/etc/alternatives/sudo", t.root.join("usr/bin/sudo")).unwrap();
    assert_eq!(record(&run_helper(&t, "grant")), "granted sudo_rs");
    mode(&t.root.join("etc/alternatives"), 0o775);
    assert_eq!(record(&run_helper(&t, "grant")), "sudo_missing none");
}

#[test]
fn grant_refuses_unsafe_parents_missing_setuid_and_leaves_no_dropin() {
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    mode(&t.root.join("etc"), 0o775);
    assert_eq!(record(&run_helper(&t, "grant")), "unsafe_dir sudo_ws");
    mode(&t.root.join("etc"), 0o755);
    mode(&t.root.join("usr/bin/sudo"), 0o755);
    assert_eq!(record(&run_helper(&t, "grant")), "sudo_missing none");
    assert!(!t.root.join("etc/sudoers.d/wssp-guest").exists());
}

#[test]
fn grant_failures_after_the_rename_remove_the_dropin() {
    let t = tree("Sudo version 1.9.15p5", false, NOT_ALLOWED);
    assert_eq!(record(&run_helper(&t, "grant")), "not_effective sudo_ws");
    assert!(!t.root.join("etc/sudoers.d/wssp-guest").exists());
    assert!(!t.root.join("etc/.wssp-sudoers.tmp").exists());
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    shim(&t.root.join("usr/sbin/visudo"), "exit 1", 0o755);
    assert_eq!(record(&run_helper(&t, "grant")), "invalid sudo_ws");
    assert!(!t.root.join("etc/sudoers.d/wssp-guest").exists());
    assert!(!t.root.join("etc/.wssp-sudoers.tmp").exists());
}

#[test]
fn revoke_unlinks_a_symlinked_dropin_without_following_and_refuses_a_directory() {
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    let target = t.root.join("usr/local/keep");
    std::fs::write(&target, "keep").unwrap();
    symlink(&target, t.root.join("etc/sudoers.d/wssp-guest")).unwrap();
    std::fs::write(t.root.join("etc/.wssp-sudoers.tmp"), "stale").unwrap();
    assert_eq!(record(&run_helper(&t, "revoke")), "revoked sudo_ws");
    assert!(target.exists(), "never followed");
    assert!(
        std::fs::symlink_metadata(t.root.join("etc/sudoers.d/wssp-guest")).is_err()
            && !t.root.join("etc/.wssp-sudoers.tmp").exists()
    );
    std::fs::create_dir(t.root.join("etc/sudoers.d/wssp-guest")).unwrap();
    assert_eq!(
        record(&run_helper(&t, "revoke")),
        "root_granted sudo_ws sudoers_dir"
    );
}

#[test]
fn revoke_works_without_sudo() {
    let t = tree("x", true, NOT_ALLOWED);
    std::fs::remove_file(t.root.join("usr/bin/sudo")).unwrap();
    assert_eq!(record(&run_helper(&t, "revoke")), "revoked none");
    assert_eq!(record(&run_helper(&t, "revoke-audit")), "clean none");
}

#[test]
fn audit_reads_sudo_list_by_marker_with_a_validated_name_fallback() {
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    assert_eq!(record(&run_helper(&t, "revoke-audit")), "clean sudo_ws");
    let t = tree("Sudo version 1.9.15p5", true, MAY_RUN);
    assert_eq!(
        record(&run_helper(&t, "revoke-audit")),
        "root_granted sudo_ws sudo_rule"
    );
    // `-U '#uid'` refused: the name from passwd (uid matches) is retried.
    let t = tree(
        "sudo-rs 0.2.8",
        true,
        "user) echo 'User user may run the following commands on host:'; exit 0;; *) echo 'unknown user'; exit 1;;",
    );
    assert_eq!(
        record(&run_helper(&t, "revoke-audit")),
        "root_granted sudo_rs sudo_rule"
    );
    // Neither form answers: hygiene only, never a refusal.
    let t = tree("sudo-rs 0.2.8", true, "*) echo 'error'; exit 1;;");
    assert_eq!(
        record(&run_helper(&t, "revoke-audit")),
        "audit_inconclusive sudo_rs"
    );
}

#[test]
fn audit_flags_each_static_root_form() {
    type Setup<'a> = &'a dyn Fn(&Path);
    let cases: [(&str, Setup, &str); 6] = [
        (
            "group_docker",
            &|root| {
                std::fs::write(
                    root.join("etc/group"),
                    "root:x:0:\nuser:x:1000:\ndocker:x:999:user\n",
                )
                .unwrap()
            },
            "",
        ),
        (
            "group_sudo",
            &|root| {
                std::fs::write(
                    root.join("etc/group"),
                    "root:x:0:\nsudo:x:27:user\nuser:x:1000:\n",
                )
                .unwrap()
            },
            "",
        ),
        (
            "uid0_alias",
            &|root| {
                std::fs::write(
                    root.join("etc/passwd"),
                    "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/bash\n",
                )
                .unwrap()
            },
            "",
        ),
        (
            "doas",
            &|root| {
                std::fs::write(root.join("etc/doas.conf"), "# x\npermit nopass user\n").unwrap()
            },
            "",
        ),
        (
            "root_password_empty",
            &|root| {
                std::fs::write(root.join("etc/shadow"), "root::1::::::\nuser:!:1::::::\n").unwrap()
            },
            "",
        ),
        (
            "group_staff",
            &|root| {
                std::fs::write(root.join("etc/group"), "staff:x:50:user\nuser:x:1000:\n").unwrap();
                mode(&root.join("usr/local"), 0o775);
            },
            "",
        ),
    ];
    for (form, setup, _) in cases {
        let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
        setup(&t.root);
        assert_eq!(
            record(&run_helper(&t, "revoke-audit")),
            format!("root_granted sudo_ws {form}"),
            "{form}"
        );
    }
    // adm and systemd-journal grant reads only.
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    std::fs::write(
        t.root.join("etc/group"),
        "adm:x:4:user\nsystemd-journal:x:101:user\nuser:x:1000:\n",
    )
    .unwrap();
    assert_eq!(record(&run_helper(&t, "revoke-audit")), "clean sudo_ws");
}

#[test]
fn an_early_grant_failure_removes_an_earlier_boots_dropin() {
    let dropin = |t: &Tree| t.root.join("etc/sudoers.d/wssp-guest");
    // sudo missing (here: no longer setuid) after an earlier grant.
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    assert_eq!(record(&run_helper(&t, "grant")), "granted sudo_ws");
    assert!(dropin(&t).exists());
    mode(&t.root.join("usr/bin/sudo"), 0o755);
    assert_eq!(record(&run_helper(&t, "grant")), "sudo_missing none");
    assert!(!dropin(&t).exists(), "sudo_missing leaves no drop-in");
    // The temp file's visudo check fails after an earlier grant.
    let t = tree("Sudo version 1.9.15p5", true, NOT_ALLOWED);
    assert_eq!(record(&run_helper(&t, "grant")), "granted sudo_ws");
    shim(&t.root.join("usr/sbin/visudo"), "exit 1", 0o755);
    assert_eq!(record(&run_helper(&t, "grant")), "invalid sudo_ws");
    assert!(!dropin(&t).exists(), "invalid leaves no drop-in");
}
