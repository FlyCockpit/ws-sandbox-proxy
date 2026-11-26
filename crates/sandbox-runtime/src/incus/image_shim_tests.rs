//! Image store and capture argv: a small fake `incus` that logs each call,
//! never a live daemon or VM. Covers `image import/export/delete`, the
//! capture pipeline (`exec` freeze/thaw, `snapshot`, `copy`, `config`,
//! `start`, scrub `exec`, `stop`, `publish`) and restart recovery.

use super::client::IncusClient;
use super::shim_tests::install_executable;
use crate::{CapturePhase, CaptureRequest};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const HEX: &str = "abababababababababababababababababababababababababababababababab";
const SANDBOX: &str = "wssp-sbx-sbx-1";
const CAP: &str = "wssp-cap-op1";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A scratch directory holding the shim, its log and its fault files.
struct Shim {
    dir: PathBuf,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Shim {
    fn new() -> Self {
        Self::in_project("default")
    }
    /// A shim whose only Incus project is `project` (every call must name it).
    fn in_project(project: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wssp-image-shim-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("shim dir");
        install_executable(&dir.join("incus"), &script(&dir, project), 0o755);
        fs::write(dir.join("project"), project).expect("project");
        Self { dir }
    }
    fn client(&self) -> IncusClient {
        let project = fs::read_to_string(self.dir.join("project")).expect("project");
        IncusClient::new(self.dir.join("incus").to_string_lossy(), project)
    }
    fn set(&self, name: &str, contents: &str) {
        fs::write(self.dir.join(name), contents).expect("shim control file");
    }
    /// One line per call (argv after `--project default`); helper code is `<code>`.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("incus.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn position(&self, call: &str) -> usize {
        self.calls()
            .iter()
            .position(|line| line == call)
            .unwrap_or_else(|| panic!("missing call `{call}` in {:#?}", self.calls()))
    }
}

fn script(dir: &Path, project: &str) -> String {
    format!(
        r#"#!/bin/sh
d='{dir}'
log="$d/incus.log"
if [ "$1" = "--project" ]; then
  [ "$2" = "{project}" ] || {{ echo "Error: wrong project $2" >&2; exit 1; }}
  shift 2
fi
line=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-c" ]; then a="<code>"; fi
  line="$line${{line:+ }}$a"
  prev="$a"
done
printf '%s\n' "$line" >> "$log"
if [ -f "$d/fail-$1" ] || [ -f "$d/fail-$1-$2" ]; then
  echo "Error: injected failure" >&2
  exit 1
fi
if [ -f "$d/flaky-$1" ]; then
  left=$(cat "$d/flaky-$1")
  if [ "$left" -gt 0 ]; then
    echo $((left - 1)) > "$d/flaky-$1"
    echo "Error: injected transient failure" >&2
    exit 1
  fi
fi
case "$1" in
  query)
    case "$3" in
      /1.0/instances/{SANDBOX}/state\?*)
        if [ -f "$d/sbx-state.json" ]; then cat "$d/sbx-state.json"; else
          echo '{{"type":"error","error_code":404,"error":"not found"}}'; exit 1
        fi
        ;;
      /1.0/instances/{SANDBOX}\?*)
        if [ -f "$d/sbx.json" ]; then cat "$d/sbx.json"; else
          echo '{{"type":"error","error_code":404,"error":"not found"}}'; exit 1
        fi
        ;;
      /1.0/images/aliases\?*)
        if [ -f "$d/aliases.json" ]; then cat "$d/aliases.json"; else echo '{{"type":"sync","metadata":[]}}'; fi
        ;;
      /1.0/operations\?*)
        if [ -f "$d/operations.json" ]; then cat "$d/operations.json"; else echo '{{"type":"sync","metadata":{{}}}}'; fi
        ;;
      /1.0/instances/*/snapshots/*)
        if [ -f "$d/cap-snap" ]; then
          printf '%s\n' '{{"type":"sync","metadata":{{"name":"{CAP}"}}}}'
        else
          echo '{{"type":"error","error_code":404,"error":"not found"}}'; exit 1
        fi
        ;;
      /1.0/instances/*)
        if [ -f "$d/cap-vm" ]; then
          printf '%s\n' '{{"type":"sync","metadata":{{"type":"virtual-machine","devices":{{"eth0":{{"type":"nic","network":"wssp-n"}},"root":{{"type":"disk","path":"/"}}}},"config":{{"user.flycockpit.sandbox_id":"sbx-1","limits.cpu":"2"}}}}}}'
        else
          echo '{{"type":"error","error_code":404,"error":"not found"}}'; exit 1
        fi
        ;;
      /1.0/images/*)
        printf '%s\n' '{{"type":"sync","metadata":{{"fingerprint":"{HEX}","architecture":"x86_64","size":4096,"type":"virtual-machine"}}}}'
        ;;
      *) echo '{{"type":"error","error_code":404,"error":"not found"}}'; exit 1 ;;
    esac
    ;;
  image)
    case "$2" in
      import)
        # features.images=true: the image lands in this project's own store.
        mkdir -p "$d/images-{project}"
        : > "$d/images-{project}/{HEX}"
        [ -f "$d/import-silent" ] || echo "Image imported with fingerprint: {HEX}"
        ;;
      delete) rm -f "$d/images-{project}/$3" ;;
      export) : > "$4{HEX}.tar.zst" ;;
    esac
    ;;
  publish) echo "Instance published with fingerprint: {HEX}" ;;
  copy) : > "$d/cap-vm" ;;
  delete) rm -f "$d/cap-vm" ;;
  snapshot)
    case "$2" in
      create) : > "$d/cap-snap" ;;
      delete) rm -f "$d/cap-snap" ;;
    esac
    ;;
  exec)
    case "$2" in
      {SANDBOX})
        state=frozen
        [ -f "$d/freeze-state" ] && state=$(cat "$d/freeze-state")
        echo "$state"
        IFS= read -r reply
        printf 'thawed:%s\n' "$reply" >> "$log"
        ;;
      *)
        case " $* " in
          *" /proc/sys/kernel/random/boot_id "*)
            # The guest boot: `boots` lists one boot id per boot-id read
            # (the last one repeats), `agent-down` probes fail first.
            if [ -f "$d/agent-down" ]; then
              left=$(cat "$d/agent-down")
              if [ "$left" -gt 0 ]; then
                echo $((left - 1)) > "$d/agent-down"
                echo "Error: VM agent isn't currently running" >&2
                exit 255
              fi
            fi
            boot=11111111-2222-4333-8444-555555555555
            if [ -f "$d/boots" ]; then
              boot=$(head -n 1 "$d/boots")
              [ "$(wc -l < "$d/boots")" -gt 1 ] && sed -i 1d "$d/boots"
            fi
            echo "$boot"
            ;;
          *" is-system-running "*)
            # `settle` lists one answer per call (the last one repeats).
            state=running
            if [ -f "$d/settle" ]; then
              state=$(head -n 1 "$d/settle")
              [ "$(wc -l < "$d/settle")" -gt 1 ] && sed -i 1d "$d/settle"
            fi
            echo "$state"
            [ "$state" = running ] || exit 1
            ;;
          *" <code> "*|*" -c "*)
            if [ -s "$d/scrub-errors" ]; then
              cat "$d/scrub-errors"
              exit 1
            fi
            if [ -f "$d/scrub-errors" ]; then
              echo '{{"symlinked":[],"errors":[{{"path":"/etc/machine-id","error":"Read-only file system"}}]}}'
              exit 1
            fi
            echo '{{"symlinked":["/home/user/.cache"]}}'
            ;;
        esac
        ;;
    esac
    ;;
esac
exit 0
"#,
        dir = dir.display(),
        project = project,
    )
}

fn request(stopped: bool) -> CaptureRequest {
    CaptureRequest {
        sandbox_id: "sbx-1".into(),
        operation_id: "op-1".into(),
        stopped,
        guest_home: "/home/user".into(),
        extra_scrub_paths: vec!["/srv/cache/*".into()],
        credential_scrub_paths: vec![".config/tool".into()],
    }
}

fn capture(
    shim: &Shim,
    stopped: bool,
) -> (
    Result<crate::CaptureOutcome, crate::RuntimeError>,
    Vec<CapturePhase>,
) {
    let phases = Mutex::new(Vec::new());
    let result = shim.client().capture_template(&request(stopped), &|phase| {
        phases.lock().unwrap().push(phase);
    });
    (result, phases.into_inner().unwrap())
}

#[test]
fn image_import_export_and_delete_argv() {
    let shim = Shim::new();
    let client = shim.client();
    let file = shim.dir.join("download.tar.zst");
    fs::write(
        &file,
        crate::image_validate::tests::fixtures::valid_unified(),
    )
    .unwrap();
    assert_eq!(client.image_import(&file).unwrap(), format!("sha256:{HEX}"));
    // Never an alias: operator images keep theirs; managed imports have none.
    assert_eq!(shim.calls(), [format!("image import {}", file.display())]);

    let export = shim.dir.join("export");
    fs::create_dir_all(&export).unwrap();
    let files = client
        .image_export(&format!("sha256:{HEX}"), &export)
        .unwrap();
    assert_eq!(files, [export.join(format!("{HEX}.tar.zst"))]);
    assert!(
        shim.calls()
            .contains(&format!("image export {HEX} {}/", export.display()))
    );

    client.image_delete(&format!("sha256:{HEX}")).unwrap();
    assert_eq!(shim.calls().last().unwrap(), &format!("image delete {HEX}"));
    // A non-canonical fingerprint never reaches the CLI.
    let before = shim.calls().len();
    assert!(client.image_delete("sha256:not-hex").is_err());
    assert!(client.image_export("latest", &export).is_err());
    assert_eq!(shim.calls().len(), before);
}

/// B2/B3: a crafted image is refused by wssp's own validation and never
/// reaches `incus image import`.
#[test]
fn crafted_images_never_reach_incus_import() {
    use crate::image_validate::tests::fixtures::{METADATA, entry, finish, qcow2, unified};
    let shim = Shim::new();
    let client = shim.client();
    let mut backing = qcow2();
    backing[8..16].copy_from_slice(&512u64.to_be_bytes());
    backing[16..20].copy_from_slice(&13u32.to_be_bytes());
    let mut symlink = Vec::new();
    entry(&mut symlink, "metadata.yaml", b'0', METADATA, "");
    entry(&mut symlink, "rootfs.img", b'2', b"", "/etc/shadow");
    let mut device = Vec::new();
    entry(&mut device, "metadata.yaml", b'0', METADATA, "");
    entry(&mut device, "rootfs.img", b'3', b"", "");
    let mut traversal = Vec::new();
    entry(&mut traversal, "metadata.yaml", b'0', METADATA, "");
    entry(&mut traversal, "rootfs.img", b'0', &qcow2(), "");
    entry(&mut traversal, "../../escape", b'0', b"x", "");
    for (name, bytes) in [
        ("backing", unified(&backing)),
        ("symlink", finish(symlink)),
        ("device", finish(device)),
        ("traversal", finish(traversal)),
    ] {
        let file = shim.dir.join(format!("{name}.tar"));
        fs::write(&file, bytes).unwrap();
        let error = client.image_import(&file).unwrap_err();
        assert_eq!(
            error.code,
            sandbox_protocol::SandboxErrorCode::ImageRejected,
            "{name}"
        );
        assert!(error.message.starts_with("image refused: "), "{name}");
    }
    assert!(shim.calls().is_empty(), "{:?}", shim.calls());
}

/// Community bases (I3, M2): an upstream split image is validated, then
/// imported as `<meta> <disk>` into the daemon's configured project, here a
/// project with its own image store (`features.images=true`); a fingerprint
/// other than the pinned one is deleted and refused.
#[test]
fn split_images_import_into_the_configured_project_and_are_compared() {
    use crate::image_validate::tests::fixtures::{
        SPLIT_METADATA, qcow2, qcow2_sized, split_metadata_tar, xz,
    };
    let Some(meta_bytes) = xz(&split_metadata_tar(SPLIT_METADATA)) else {
        return;
    };
    let shim = Shim::in_project("wssp-builds");
    let client = shim.client();
    let (meta, disk) = (shim.dir.join("incus.tar.xz"), shim.dir.join("disk.qcow2"));
    fs::write(&meta, &meta_bytes).unwrap();
    fs::write(&disk, qcow2()).unwrap();
    assert_eq!(
        client
            .image_import_split(&meta, &disk, &format!("sha256:{HEX}"))
            .unwrap(),
        format!("sha256:{HEX}")
    );
    assert_eq!(
        shim.calls(),
        [format!(
            "image import {} {}",
            meta.display(),
            disk.display()
        )]
    );
    assert!(shim.dir.join(format!("images-wssp-builds/{HEX}")).exists());
    assert!(!shim.dir.join("images-default").exists());

    // Post-import compare: another fingerprint is deleted, never kept.
    let other = format!("sha256:{}", "c".repeat(64));
    let error = client.image_import_split(&meta, &disk, &other).unwrap_err();
    assert_eq!(
        error.code,
        sandbox_protocol::SandboxErrorCode::ImageRejected
    );
    assert_eq!(shim.calls().last().unwrap(), &format!("image delete {HEX}"));
    assert!(!shim.dir.join(format!("images-wssp-builds/{HEX}")).exists());

    // A disk past the virtual-size bound never reaches the CLI.
    let before = shim.calls().len();
    fs::write(&disk, qcow2_sized(crate::SPLIT_VIRTUAL_SIZE_MAX + 1)).unwrap();
    let error = client
        .image_import_split(&meta, &disk, &format!("sha256:{HEX}"))
        .unwrap_err();
    assert_eq!(error.message, "image refused: qcow2_virtual_size_too_large");
    assert_eq!(shim.calls().len(), before);
}

#[test]
fn image_import_failures_are_errors_never_a_guessed_fingerprint() {
    let shim = Shim::new();
    let file = shim.dir.join("download.tar.zst");
    fs::write(
        &file,
        crate::image_validate::tests::fixtures::valid_unified(),
    )
    .unwrap();
    shim.set("import-silent", "");
    assert!(shim.client().image_import(&file).is_err());
    fs::remove_file(shim.dir.join("import-silent")).unwrap();
    shim.set("fail-image-import", "");
    assert!(shim.client().image_import(&file).is_err());
}

#[test]
fn running_capture_freezes_only_around_the_snapshot_then_copies_scrubs_and_publishes() {
    let shim = Shim::new();
    let (result, phases) = capture(&shim, false);
    let outcome = result.expect("capture");
    assert_eq!(outcome.fingerprint, format!("sha256:{HEX}"));
    assert_eq!(outcome.size_bytes, 4096);
    assert_eq!(outcome.architecture, "x86_64");
    assert_eq!(outcome.symlinked_paths, ["/home/user/.cache"]);
    assert_eq!(
        phases,
        [
            CapturePhase::Freezing,
            CapturePhase::Snapshotting,
            CapturePhase::Copying,
            CapturePhase::Scrubbing,
            CapturePhase::Publishing,
        ]
    );
    let freeze = shim.position(&format!(
        "exec {SANDBOX} --user 0 -- python3 -I -B -c <code>"
    ));
    let snapshot = shim.position(&format!("snapshot create {SANDBOX} {CAP}"));
    let thaw = shim.position("thawed:thaw");
    let copy = shim.position(&format!(
        "copy {SANDBOX}/{CAP} {CAP} --instance-only --no-profiles"
    ));
    assert!(
        freeze < snapshot && snapshot < thaw && thaw < copy,
        "{:#?}",
        shim.calls()
    );
    // The capture VM loses every NIC and wssp metadata, gets a fixed size.
    let nic = shim.position(&format!("config device remove {CAP} eth0"));
    let unset = shim.position(&format!("config unset {CAP} user.flycockpit.sandbox_id"));
    let cpu = shim.position(&format!("config set {CAP} limits.cpu 1"));
    let memory = shim.position(&format!("config set {CAP} limits.memory 1024MiB"));
    let start = shim.position(&format!("start {CAP}"));
    assert!(copy < nic && nic < start && unset < start && cpu < start && memory < start);
    assert!(
        !shim
            .calls()
            .iter()
            .any(|c| c == &format!("config device remove {CAP} root"))
    );
    // Scrub runs in the network-less capture VM, never in the sandbox.
    let scrub = shim
        .calls()
        .iter()
        .position(|c| {
            c.starts_with(&format!(
                "exec {CAP} --user 0 -- python3 -I -S -B -c <code> freeze "
            )) && c.contains("/srv/cache/*")
        })
        .expect("scrub exec (freeze mode)");
    // Round-3 P1-1: the frozen guest is never thawed: it is powered off.
    // Round-4 P1: nothing else executes in the guest after the scrub's
    // final verification.
    let stop = shim.position(&format!("stop {CAP} --force"));
    let publish = shim.position(&format!("publish {CAP} --compression zstd"));
    assert!(start < scrub && scrub < stop && stop < publish);
    assert!(
        !shim.calls()[scrub + 1..stop]
            .iter()
            .any(|c| c.starts_with(&format!("exec {CAP}"))),
        "no guest execution between the scrub and the power-off"
    );
    assert!(
        !shim
            .calls()
            .iter()
            .any(|c| c.starts_with(&format!("stop {CAP} --timeout"))),
        "no clean shutdown of the capture VM"
    );
    // Cleanup after the publish: the VM first, then the snapshot (ZFS clones).
    let calls = shim.calls();
    let tail: Vec<&str> = calls[publish..].iter().map(String::as_str).collect();
    let delete = tail
        .iter()
        .position(|c| *c == format!("delete {CAP} --force"))
        .expect("vm delete");
    let snap_delete = tail
        .iter()
        .position(|c| *c == format!("snapshot delete {SANDBOX} {CAP}"))
        .expect("snapshot delete");
    assert!(delete < snap_delete);
    // No call ever deletes or stops the sandbox itself.
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with(&format!("delete {SANDBOX}"))
                || c.starts_with(&format!("stop {SANDBOX}")))
    );
}

/// Login paths ride the frozen scrub after a
/// separator, resolved against the guest home; an invalid one fails the
/// capture before any Incus call.
#[test]
fn credential_scrub_paths_follow_the_separator_and_fail_closed() {
    let shim = Shim::new();
    let (result, _) = capture(&shim, true);
    result.expect("capture");
    let scrub = shim
        .calls()
        .into_iter()
        .find(|c| {
            c.starts_with(&format!(
                "exec {CAP} --user 0 -- python3 -I -S -B -c <code> freeze "
            ))
        })
        .expect("scrub exec");
    // Each declared login path also scrubs the credential restore's exclusive
    // staging pattern in its parent directory.
    let staging = format!("/home/user/.config/.wssp-cred-{}", "[0-9a-f]".repeat(16));
    assert!(
        scrub.contains(" /srv/cache/* ")
            && scrub.ends_with(&format!(" --credential {staging} /home/user/.config/tool")),
        "{scrub}"
    );

    let shim = Shim::new();
    let mut bad = request(true);
    bad.credential_scrub_paths.push("../../etc/shadow".into());
    let refused = shim
        .client()
        .capture_template(&bad, &|_| {})
        .expect_err("invalid login path");
    assert_eq!(
        refused.code,
        sandbox_protocol::SandboxErrorCode::CaptureFailed
    );
    assert!(shim.calls().is_empty(), "{:#?}", shim.calls());

    // No login paths: no separator at all.
    let shim = Shim::new();
    let mut plain = request(true);
    plain.credential_scrub_paths.clear();
    shim.client()
        .capture_template(&plain, &|_| {})
        .expect("capture");
    assert!(!shim.calls().iter().any(|c| c.contains("--credential")));
}

#[test]
fn stopped_capture_copies_the_root_directly_without_freeze_or_snapshot() {
    let shim = Shim::new();
    let (result, phases) = capture(&shim, true);
    result.expect("capture");
    assert_eq!(
        phases,
        [
            CapturePhase::Copying,
            CapturePhase::Scrubbing,
            CapturePhase::Publishing
        ]
    );
    let calls = shim.calls();
    assert!(calls.contains(&format!(
        "copy {SANDBOX} {CAP} --instance-only --no-profiles"
    )));
    assert!(!calls.iter().any(|c| c.starts_with("snapshot")));
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with(&format!("exec {SANDBOX}")))
    );
}

#[test]
fn a_freeze_failure_fails_before_any_snapshot_and_cleans_up() {
    let shim = Shim::new();
    shim.set("freeze-state", "error");
    let (result, phases) = capture(&shim, false);
    let error = result.expect_err("freeze failure");
    assert!(
        error.message.starts_with("capture_freeze_failed"),
        "{}",
        error.message
    );
    assert_eq!(phases, [CapturePhase::Freezing]);
    let calls = shim.calls();
    assert!(!calls.iter().any(|c| c.starts_with("snapshot create")));
    assert!(!calls.iter().any(|c| c.starts_with("copy")));
    assert_eq!(
        calls
            .iter()
            .filter(|c| *c == &format!("delete {CAP} --force"))
            .count(),
        2,
        "pre-clean and post-clean"
    );
}

#[test]
fn an_already_frozen_guest_is_captured_and_left_as_it_was() {
    let shim = Shim::new();
    shim.set("freeze-state", "busy");
    let (result, _) = capture(&shim, false);
    result.expect("capture");
    assert!(
        shim.calls()
            .contains(&format!("snapshot create {SANDBOX} {CAP}"))
    );
}

/// The calls of `shim` that start with `prefix`, by position.
fn positions(shim: &Shim, prefix: &str) -> Vec<usize> {
    shim.calls()
        .iter()
        .enumerate()
        .filter(|(_, c)| c.starts_with(prefix))
        .map(|(i, _)| i)
        .collect()
}

fn scrub_position(shim: &Shim) -> Option<usize> {
    shim.calls().iter().position(|c| {
        c.starts_with(&format!(
            "exec {CAP} --user 0 -- python3 -I -S -B -c <code> freeze "
        ))
    })
}

/// Ubuntu 26.04 capture: on a busy host the capture VM's agent can answer
/// before its boot settled, while `/etc/machine-id` is still the read-only
/// transient mount, and the scrub would fail. The scrub waits for a
/// settled boot (`systemctl is-system-running --wait`), after an agent that
/// first does not answer.
#[test]
fn the_scrub_waits_for_a_settled_capture_vm_boot() {
    let shim = Shim::new();
    shim.set("agent-down", "2");
    shim.set("settle", "starting\nstarting\nrunning\n");
    let (result, _) = capture(&shim, true);
    result.expect("capture");
    let settles = positions(
        &shim,
        &format!("exec {CAP} -- systemctl is-system-running --wait"),
    );
    let scrub = scrub_position(&shim).expect("scrub");
    assert_eq!(settles.len(), 3, "{:#?}", shim.calls());
    assert!(settles.iter().all(|&s| s < scrub), "{:#?}", shim.calls());
    let start = shim.position(&format!("start {CAP}"));
    assert!(start < settles[0]);
}

/// The first-boot reboot of a fresh 26.04 instance can land while its boot
/// settles: a boot id that changed across the settle starts over.
#[test]
fn a_capture_vm_that_restarts_while_settling_settles_again() {
    let shim = Shim::new();
    shim.set(
        "boots",
        "aaaaaaaa-0000-4000-8000-000000000001\n\
         bbbbbbbb-0000-4000-8000-000000000002\n",
    );
    let (result, _) = capture(&shim, true);
    result.expect("capture");
    let settles = positions(
        &shim,
        &format!("exec {CAP} -- systemctl is-system-running --wait"),
    );
    let scrub = scrub_position(&shim).expect("scrub");
    assert_eq!(settles.len(), 2, "{:#?}", shim.calls());
    assert!(settles[1] < scrub);
}

/// A boot that never settles fails the capture (bounded), without a scrub,
/// and still cleans up.
#[test]
fn a_capture_vm_that_never_settles_fails_without_a_scrub() {
    let shim = Shim::new();
    shim.set("settle", "starting\n");
    let (result, _) = capture(&shim, true);
    let error = result.expect_err("never settled");
    assert_eq!(error.code, sandbox_protocol::SandboxErrorCode::Timeout);
    assert!(
        error.message.starts_with("capture VM boot did not settle"),
        "{}",
        error.message
    );
    assert!(scrub_position(&shim).is_none());
    assert!(shim.calls().iter().all(|c| !c.starts_with("publish")));
    assert_eq!(
        shim.calls().last().unwrap(),
        &format!("query --raw /1.0/instances/{CAP}?project=default")
    );
    assert!(shim.calls().contains(&format!("delete {CAP} --force")));
}

/// A failed scrub names the helper's first error for the host log.
#[test]
fn a_failed_scrub_names_its_first_error() {
    let shim = Shim::new();
    shim.set("scrub-errors", "");
    let (result, _) = capture(&shim, true);
    let error = result.expect_err("scrub failed");
    assert!(
        error
            .message
            .ends_with("(1 scrub error(s), first: read_only_fs at /etc/machine-id)"),
        "{}",
        error.message
    );
    assert!(shim.calls().iter().all(|c| !c.starts_with("publish")));
}

/// CLI logins (login values never logged): a guest can point a
/// manifest path at `/run/<login value>`, or fail on a path it chose. The
/// scrub error keeps only an allowlisted class and a fixed manifest path:
/// never a link target, a guest-chosen path or the helper's free text.
#[test]
fn a_failed_scrub_never_carries_guest_chosen_text() {
    const MARKER: &str = "WSSPSECRETMARKER0123";
    for (report, class, shown) in [
        (
            format!(
                r#"{{"symlinked":["/home/user/.bash_history"],"errors":[{{"path":"/home/user/.bash_history","error":"link target is protected: /run/{MARKER}"}}]}}"#
            ),
            "protected_link",
            "/home/user/.bash_history",
        ),
        (
            format!(
                r#"{{"symlinked":[],"errors":[{{"path":"/home/user/.cache/{MARKER}/x","error":"Read-only file system"}}]}}"#
            ),
            "read_only_fs",
            "<path withheld>",
        ),
        (
            format!(
                r#"{{"symlinked":[],"errors":[{{"path":"/run/{MARKER}","error":"{MARKER} free text"}}]}}"#
            ),
            "other",
            "<path withheld>",
        ),
        (
            format!(
                r#"{{"symlinked":[],"errors":[{{"path":"<freeze>","error":"process 7 is not frozen {MARKER}"}}]}}"#
            ),
            "freeze",
            "<freeze>",
        ),
    ] {
        let shim = Shim::new();
        shim.set("scrub-errors", &report);
        let (result, _) = capture(&shim, true);
        let error = result.expect_err("scrub failed");
        assert!(!error.message.contains(MARKER), "{}", error.message);
        assert!(
            error
                .message
                .ends_with(&format!("(1 scrub error(s), first: {class} at {shown})")),
            "{}",
            error.message
        );
        assert!(!format!("{error:?}").contains(MARKER));
    }
}

#[test]
fn step_failures_fail_the_capture_and_always_clean_up() {
    for (fault, step) in [
        ("fail-snapshot-create", "snapshot create"),
        ("fail-copy", "copy"),
        ("fail-start", "start"),
        ("fail-publish", "publish"),
    ] {
        let shim = Shim::new();
        shim.set(fault, "");
        let (result, _) = capture(&shim, false);
        assert!(result.is_err(), "{fault}");
        let calls = shim.calls();
        let failed = calls
            .iter()
            .position(|c| c.starts_with(step))
            .unwrap_or_else(|| panic!("{step} not attempted"));
        // A snapshot failure still thaws the guest before returning.
        assert!(calls.iter().any(|c| c == "thawed:thaw"), "{fault}");
        let after = &calls[failed..];
        assert!(after.contains(&format!("delete {CAP} --force")), "{fault}");
        assert!(
            after.contains(&format!("snapshot delete {SANDBOX} {CAP}")),
            "{fault}"
        );
        assert!(
            !after
                .iter()
                .any(|c| c.starts_with("publish") && step != "publish")
        );
    }
}

#[test]
fn restart_recovery_discards_only_the_capture_vm_and_snapshot() {
    let shim = Shim::new();
    shim.client().discard_capture("sbx-1", "op-1").unwrap();
    let calls = shim.calls();
    let effects: Vec<&String> = calls.iter().filter(|c| !c.starts_with("query")).collect();
    assert_eq!(
        effects,
        [
            &format!("delete {CAP} --force"),
            &format!("snapshot delete {SANDBOX} {CAP}"),
        ]
    );
    // Absence is proven by query, never inferred from the delete exit codes.
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with(&format!("query --raw /1.0/instances/{CAP}")))
    );
    assert!(
        calls
            .iter()
            .any(|c| c.contains(&format!("/snapshots/{CAP}")))
    );
    // Absent leftovers are fine (both deletes fail on a clean host).
    let shim = Shim::new();
    shim.set("fail-delete", "");
    shim.set("fail-snapshot-delete", "");
    shim.client().discard_capture("sbx-1", "op-1").unwrap();
    // Invalid identifiers never reach the CLI.
    let shim = Shim::new();
    assert!(shim.client().discard_capture("sbx-1", "---").is_err());
    assert!(shim.calls().is_empty());
}

/// P2-12: deletion errors are not trusted. A transient failure is retried
/// until the VM and snapshot are proven gone, and only then is the capture
/// result returned (the server's hold stays until then).
#[test]
fn capture_cleanup_is_verified_and_retried_until_the_leftovers_are_gone() {
    let shim = Shim::new();
    // The pre-clean delete consumes one failure (nothing to delete there).
    shim.set("flaky-delete", "3");
    let (result, _) = capture(&shim, false);
    result.expect("capture");
    let calls = shim.calls();
    let publish = shim.position(&format!("publish {CAP} --compression zstd"));
    let deletes = calls[publish..]
        .iter()
        .filter(|c| *c == &format!("delete {CAP} --force"))
        .count();
    assert_eq!(
        deletes, 3,
        "two failures then a verified delete: {calls:#?}"
    );
    assert!(!shim.dir.join("cap-vm").exists());
    assert!(!shim.dir.join("cap-snap").exists());
}

/// Leftovers that cannot be removed stop a new capture before any work,
/// and recovery reports them instead of claiming success.
#[test]
fn unremovable_leftovers_refuse_the_capture_and_fail_recovery() {
    let shim = Shim::new();
    shim.set("cap-vm", "");
    shim.set("fail-delete", "");
    let (result, phases) = capture(&shim, false);
    assert!(result.is_err());
    assert!(phases.is_empty());
    assert!(
        !shim
            .calls()
            .iter()
            .any(|c| c.starts_with("copy") || c.starts_with("exec"))
    );
    let error = shim.client().discard_capture("sbx-1", "op-1").unwrap_err();
    assert!(
        error.message.starts_with("capture_cleanup_pending"),
        "{}",
        error.message
    );
    // A snapshot that cannot be deleted is unresolved work too.
    let shim = Shim::new();
    shim.set("cap-snap", "");
    shim.set("fail-snapshot-delete", "");
    assert!(shim.client().discard_capture("sbx-1", "op-1").is_err());
}

/// `incus publish <instance> --alias wssp-off-<tag>-<id>
/// --compression zstd`, only for a Stopped instance; the instance facts and
/// the alias/operation reads go through `query --raw` in the client's
/// project.
#[test]
fn offload_publish_argv_requires_a_stopped_instance() {
    let shim = Shim::in_project("wssp");
    let client = shim.client();
    // The owner-tagged alias (shared image store, one tag per daemon).
    let alias = crate::offload_alias("0123456789ab", "off_1").unwrap();
    let alias = alias.as_str();
    assert_eq!(alias, "wssp-off-0123456789ab-off_1");
    // Absent instance: refused before any publish.
    let missing = client.publish_stopped_instance(SANDBOX, alias).unwrap_err();
    assert_eq!(
        missing.code,
        sandbox_protocol::SandboxErrorCode::SandboxNotFound
    );
    shim.set(
        "sbx.json",
        r#"{"type":"sync","metadata":{"name":"wssp-sbx-sbx-1","status":"Running","status_code":103}}"#,
    );
    let running = client.publish_stopped_instance(SANDBOX, alias).unwrap_err();
    assert_eq!(
        running.code,
        sandbox_protocol::SandboxErrorCode::StateConflict
    );
    assert!(!shim.calls().iter().any(|c| c.starts_with("publish")));
    shim.set(
        "sbx.json",
        r#"{"type":"sync","metadata":{"name":"wssp-sbx-sbx-1","status":"Stopped","status_code":102,"last_used_at":"2026-11-06T10:00:00Z","config":{"volatile.cloud-init.instance-id":"ci-1"}}}"#,
    );
    let published = client.publish_stopped_instance(SANDBOX, alias).unwrap();
    assert_eq!(published.fingerprint, format!("sha256:{HEX}"));
    assert_eq!(published.size_bytes, Some(4096));
    shim.position(&format!(
        "publish {SANDBOX} --alias {alias} --compression zstd"
    ));
    // A malformed alias or instance never reaches the CLI.
    let before = shim.calls().len();
    assert!(client.publish_stopped_instance(SANDBOX, "ubuntu").is_err());
    assert!(
        client
            .publish_stopped_instance("not-managed", alias)
            .is_err()
    );
    assert_eq!(shim.calls().len(), before);

    assert_eq!(
        client.instance_last_used(SANDBOX).unwrap().as_deref(),
        Some("2026-11-06T10:00:00Z")
    );
    assert_eq!(
        client.cloud_init_instance_id(SANDBOX).unwrap().as_deref(),
        Some("ci-1")
    );
    shim.position(&format!(
        "query --raw /1.0/instances/{SANDBOX}?project=wssp"
    ));
    shim.set(
        "sbx-state.json",
        r#"{"type":"sync","metadata":{"status":"Stopped","status_code":102,"disk":{"root":{"usage":123456}}}}"#,
    );
    assert_eq!(client.instance_root_usage(SANDBOX).unwrap(), Some(123456));
    shim.position(&format!(
        "query --raw /1.0/instances/{SANDBOX}/state?project=wssp"
    ));
}

#[test]
fn offload_alias_and_operation_reads_are_bounded_queries() {
    let shim = Shim::in_project("wssp");
    let client = shim.client();
    assert!(client.offload_aliases().unwrap().is_empty());
    shim.set(
        "aliases.json",
        &format!(
            r#"{{"type":"sync","metadata":[{{"name":"wssp-off-o1","target":"{HEX}"}},{{"name":"ubuntu/26.04","target":"{HEX}"}}]}}"#
        ),
    );
    assert_eq!(
        client.offload_aliases().unwrap(),
        [crate::OffloadAlias {
            alias: "wssp-off-o1".into(),
            fingerprint: format!("sha256:{HEX}"),
        }]
    );
    shim.position("query --raw /1.0/images/aliases?project=wssp&recursion=1");
    assert!(!client.instance_operation_running(SANDBOX).unwrap());
    shim.set(
        "operations.json",
        &format!(
            r#"{{"type":"sync","metadata":{{"running":[{{"status":"Running","resources":{{"instances":["/1.0/instances/{SANDBOX}?project=wssp"]}}}}]}}}}"#
        ),
    );
    assert!(client.instance_operation_running(SANDBOX).unwrap());
    shim.position("query --raw /1.0/operations?project=wssp&recursion=1");
}

/// Reports another wssp daemon on the Incus server once `on` is set.
#[derive(Debug)]
struct SharedFrom {
    inner: crate::guard::probe::FakeGuardProbe,
    on: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl crate::guard::probe::GuardProbe for SharedFrom {
    fn status(&self) -> Result<crate::guard::probe::GuardStatus, crate::RuntimeError> {
        self.inner.status()
    }
    fn expectations(&self) -> Result<crate::guard::probe::GuardExpectations, crate::RuntimeError> {
        self.inner.expectations()
    }
    fn shared_incus_server(&self) -> Option<String> {
        self.on
            .load(Ordering::SeqCst)
            .then(|| "host `other`".into())
    }
}

/// A capture that passed its entry check while the server
/// was sole is refused at the capture VM's start once another daemon's
/// marker is live (and the shared store is never published to). The
/// capture's cleanup still runs.
#[test]
fn a_capture_rechecks_the_shared_server_fence_at_its_vm_start() {
    let shim = Shim::new();
    let on = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut client = shim.client();
    client.guard_probe = std::sync::Arc::new(SharedFrom {
        inner: crate::guard::probe::FakeGuardProbe::healthy(),
        on: on.clone(),
    });
    let phases = Mutex::new(Vec::new());
    let result = client.capture_template(&request(true), &|phase| {
        // The other daemon appears while the root is being copied.
        if phase == CapturePhase::Copying {
            on.store(true, Ordering::SeqCst);
        }
        phases.lock().unwrap().push(phase);
    });
    let error = result.expect_err("refused at the start");
    assert!(
        error.message.contains("another wssp daemon"),
        "{}",
        error.message
    );
    assert_eq!(
        error.wire_reason(),
        Some(sandbox_protocol::ProtocolErrorReason::from(
            sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable
        ))
    );
    let calls = shim.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with(&format!("copy {SANDBOX} {CAP}")))
    );
    assert!(!calls.contains(&format!("start {CAP}")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.starts_with("publish")));
    assert!(
        calls.contains(&format!("delete {CAP} --force")),
        "cleaned up"
    );
    assert_eq!(phases.into_inner().unwrap(), [CapturePhase::Copying]);
}
