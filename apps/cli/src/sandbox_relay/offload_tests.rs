//! Disk offload tests (FakeRuntime + a loopback S3 responder; no Incus, no
//! network beyond 127.0.0.1): journal, startup sweep, bandwidth, the job
//! end to end, I13 refusal, S6 census exclusion and kill/reconnect
//! preemption.

use super::*;
use crate::sandbox_relay::images::{ImageService, ImageSettings};
use sandbox_protocol::{DiskUploadGrantV11, ImageEncryptionV11, ImageUploadPartUrlV11};
use sandbox_runtime::{FakePublishCrash, FakeRuntime};
use std::io::{BufRead as _, BufReader, Read as _};
use std::net::TcpListener;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SBX: &str = "sbx-1";
const INSTANCE: &str = "wssp-sbx-sbx-1";
const HOST: &str = "host-a";

/// This fixture daemon's alias of offload `id`.
fn al(id: &str) -> String {
    sandbox_runtime::offload_alias(&offload_owner_tag(HOST), id).unwrap()
}

struct Fixture {
    runtime: FakeRuntime,
    images: ImageService,
    offload: OffloadService,
    _dir: tempfile::TempDir,
    dir: PathBuf,
}

fn lookup(disk_gib: u32) -> SandboxLookup {
    Arc::new(move |sandbox_id: &str| {
        (sandbox_id == SBX).then_some(LocalSandbox {
            disk_gib,
            build: false,
        })
    })
}

fn images_for(runtime: &FakeRuntime, dir: &Path, gib: u32) -> ImageService {
    let images = ImageService::start(
        Arc::new(runtime.clone()),
        dir,
        ImageSettings {
            size: crate::config::ImageCacheSize::Gib(gib),
            accept_foreign: false,
            foreign_grace: Duration::from_secs(600),
            builder: false,
            accept_foreign_builds: false,
        },
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into(),
        "http://127.0.0.1:9",
        "wssp_host_test-secret",
    )
    .expect("start")
    .expect("enabled");
    images.on_registered("host-owner");
    images
}

fn timing() -> (Duration, Duration, Duration) {
    (
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_millis(10),
    )
}

fn fixture_with(
    runtime: FakeRuntime,
    dir: tempfile::TempDir,
    cache_gib: u32,
    disk_gib: u32,
) -> Fixture {
    let path = dir.path().to_path_buf();
    let images = images_for(&runtime, &path, cache_gib);
    let offload = OffloadService::open_with(
        images.clone(),
        Arc::new(runtime.clone()),
        lookup(disk_gib),
        OffloadSettings {
            host_id: HOST.into(),
            ..OffloadSettings::default()
        },
        timing(),
    )
    .expect("offload");
    Fixture {
        runtime,
        images,
        offload,
        _dir: dir,
        dir: path,
    }
}

fn fixture() -> Fixture {
    let runtime = FakeRuntime::new();
    runtime.seed_stopped_sandbox(SBX);
    fixture_with(runtime, tempfile::tempdir().expect("dir"), 4, 1)
}

fn request(offload_id: &str) -> ServerControlMessage {
    ServerControlMessage::DiskOffloadRequest(DiskOffloadRequestV11 {
        sandbox_id: SBX.into(),
        generation: 3,
        offload_id: offload_id.into(),
        seq: 1,
    })
}

fn wait_for_frame(
    images: &ImageService,
    pred: impl Fn(&DaemonControlMessage) -> bool,
) -> (DaemonControlMessage, Vec<DaemonControlMessage>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    loop {
        for frame in images.drain() {
            if pred(&frame) {
                return (frame, seen);
            }
            seen.push(frame);
        }
        assert!(Instant::now() < deadline, "frame never sent: {seen:#?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

type Seen = std::thread::JoinHandle<Vec<Vec<u8>>>;

/// Answer `count` PUTs with 200 and an ETag; returns the bodies.
fn s3(count: usize) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for n in 0..count {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("line");
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).expect("body");
            bodies.push(body);
            let mut stream = stream;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"e{n}\"\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .expect("write");
        }
        bodies
    });
    (base, handle)
}

fn grant(
    offload_id: &str,
    session: &str,
    url: &str,
    plain: u64,
    key: &str,
) -> ServerControlMessage {
    let size = sandbox_protocol::encrypted_image_len(plain);
    ServerControlMessage::DiskUploadGrant(DiskUploadGrantV11 {
        sandbox_id: SBX.into(),
        offload_id: offload_id.into(),
        seq: 1,
        session_id: session.into(),
        transfer_id: format!("tr-{session}"),
        part_size: crypto::SEALED_RECORD as u64,
        parts: vec![ImageUploadPartUrlV11 {
            n: 1,
            url: format!("{url}/part1"),
            size_bytes: size,
        }],
        expires_at_unix_ms: u64::MAX,
        encryption: ImageEncryptionV11 {
            scheme: sandbox_protocol::IMAGE_ENCRYPTION_SCHEME.into(),
            key: key.into(),
        },
    })
}

fn begin_of(frame: &DaemonControlMessage) -> Option<&DiskUploadBeginV11> {
    match frame {
        DaemonControlMessage::DiskUploadBegin(begin) => Some(begin),
        _ => None,
    }
}

fn failed_of(frame: &DaemonControlMessage) -> Option<DiskOffloadFailureCode> {
    match frame {
        DaemonControlMessage::DiskOffloadFailed(failed) => Some(failed.code),
        _ => None,
    }
}

fn staging_dirs(f: &Fixture) -> Vec<String> {
    std::fs::read_dir(f.images.staging_dir())
        .map(|dir| {
            dir.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(STAGING_PREFIX))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn journal_round_trips_privately_and_refuses_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = OffloadJournal::open(dir.path()).unwrap();
    let entry = OffloadEntry {
        offload_id: "off-1".into(),
        seq: 2,
        generation: 7,
        phase: OffloadPhase::Staged,
        alias: "wssp-off-off-1".into(),
        staged_sha256: Some("ab".repeat(32)),
        last_used_at: Some("2026-11-06T10:00:00Z".into()),
        cloud_init_instance_id: Some("5f1c2a9e-1b2c-4d3e-8f90-0a1b2c3d4e5f".into()),
        evict_grant_id: None,
        evict_expires_at_unix_ms: None,
    };
    journal.put(SBX, entry.clone()).unwrap();
    let reopened = OffloadJournal::open(dir.path()).unwrap();
    assert_eq!(reopened.get(SBX), Some(&entry));
    let path = dir.path().join(OFFLOAD_JOURNAL_FILE);
    let text = std::fs::read_to_string(&path).unwrap();
    // The documented fields, camelCase, and never any key material.
    for field in [
        "offloadId",
        "seq",
        "generation",
        "phase",
        "alias",
        "stagedSha256",
        "lastUsedAt",
    ] {
        assert!(text.contains(field), "{field}: {text}");
    }
    assert!(!text.to_ascii_lowercase().contains("key"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // deny_unknown_fields: a journal that grew a field is not trusted.
    let tampered = text.replace("\"seq\":2", "\"seq\":2,\"key\":\"x\"");
    std::fs::write(&path, tampered).unwrap();
    assert!(OffloadJournal::open(dir.path()).is_err());
    let mut journal = OffloadJournal {
        path,
        file: OffloadJournalFile {
            version: 1,
            entries: BTreeMap::new(),
        },
    };
    journal.put(SBX, entry).unwrap();
    // Remove only the named offload.
    journal.remove(SBX, "other").unwrap();
    assert!(journal.get(SBX).is_some());
    journal.remove(SBX, "off-1").unwrap();
    assert!(journal.get(SBX).is_none());
}

#[test]
fn bandwidth_paces_to_the_cap_and_zero_is_unlimited() {
    assert!(Bandwidth::new(None).is_none());
    assert!(Bandwidth::new(Some(0)).is_none());
    let limit = Bandwidth::new(Some(1000)).unwrap();
    let now = Instant::now();
    // The first chunk goes at once; each later one waits for the previous
    // chunk's slot at 1000 B/s.
    assert_eq!(limit.reserve_at(500, now), Duration::ZERO);
    assert_eq!(limit.reserve_at(1000, now), Duration::from_millis(500));
    assert_eq!(limit.reserve_at(1, now), Duration::from_millis(1500));
    // Idle time is not banked beyond the slot already reserved.
    let later = now + Duration::from_secs(10);
    assert_eq!(limit.reserve_at(100, later), Duration::ZERO);
    // A stop ends the wait.
    let slow = Bandwidth::new(Some(1)).unwrap();
    assert!(slow.pace(1, &|| false));
    let started = Instant::now();
    assert!(!slow.pace(1, &|| true));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn staging_estimate_follows_usage_with_the_disk_ceiling() {
    const GIB: u64 = 1 << 30;
    // Unknown usage: the configured root twice.
    assert_eq!(staging_estimate(10, None), 20 * GIB);
    // usage × 1.05 + 64 MiB, twice.
    let usage = 2 * GIB;
    assert_eq!(
        staging_estimate(10, Some(usage)),
        (usage + usage / 20 + 64 * MIB) * 2
    );
    // Never above diskGiB × 2.
    assert_eq!(staging_estimate(1, Some(5 * GIB)), 2 * GIB);
}

#[test]
fn an_offload_publishes_uploads_encrypted_and_is_dropped_on_stored() {
    let f = fixture();
    let cloud_init = "5f1c2a9e-1b2c-4d3e-8f90-0a1b2c3d4e5f";
    f.runtime.set_cloud_init_instance_id(SBX, Some(cloud_init));
    f.offload.handle_server(request("off-1"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let begin = begin_of(&begin).unwrap().clone();
    // The instance's cloud-init id rides the begin (pinned at restore).
    assert_eq!(begin.cloud_init_instance_id.as_deref(), Some(cloud_init));
    assert_eq!(
        (
            begin.sandbox_id.as_str(),
            begin.offload_id.as_str(),
            begin.seq,
            begin.generation
        ),
        (SBX, "off-1", 1, 3)
    );
    assert_eq!(
        f.runtime.publish_calls(),
        [(INSTANCE.to_owned(), al("off-1"))]
    );
    assert_eq!(
        f.runtime.alias_target(&al("off-1")).as_deref(),
        Some(begin.fingerprint.as_str())
    );
    let entry = f.offload.entry(SBX).unwrap();
    assert_eq!(entry.phase, OffloadPhase::Uploading);
    assert_eq!(
        entry.fingerprint().as_deref(),
        Some(begin.fingerprint.as_str())
    );
    assert_eq!(entry.last_used_at.as_deref(), Some("fake-boot-seed"));
    assert_eq!(staging_dirs(&f), ["offload-off-1"]);

    // A repeated begin refused as `upload_in_progress` never stops it.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadCancel(
            DiskOffloadCancelV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                reason: "upload_in_progress".into(),
            },
        ));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploading);
    let (url, seen) = s3(1);
    f.offload
        .handle_server(grant("off-1", "ses-1", &url, begin.size_bytes, KEY));
    let (complete, before) = wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskUploadComplete(_))
    });
    assert!(matches!(
        complete,
        DaemonControlMessage::DiskUploadComplete(DiskUploadCompleteV11 { ref session_id, .. }) if session_id == "ses-1"
    ));
    assert!(before.iter().any(|m| matches!(
        m,
        DaemonControlMessage::DiskUploadParts(p) if p.session_id == "ses-1" && p.parts.len() == 1
    )));
    // The stored bytes are ciphertext under the session key (I13).
    let bodies = seen.join().unwrap();
    let plain = f
        .runtime
        .export_image(&begin.fingerprint, &{
            let verify = f.dir.join("verify");
            std::fs::create_dir_all(&verify).unwrap();
            verify
        })
        .map(|files| std::fs::read(&files[0]).unwrap())
        .unwrap();
    assert_ne!(bodies[0], plain);
    let key = crypto::RecordKey::from_base64(KEY).unwrap();
    assert_eq!(key.open(0, true, &bodies[0]).unwrap(), plain);
    // No grant key outlives its job.
    assert!(f.offload.lock_keys().is_empty());
    wait_until("uploaded", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Uploaded)
    });

    // S6: the offload image is never a cache entry.
    f.images.begin_census();
    let frames = f.images.drain();
    let census: Vec<_> = frames
        .iter()
        .filter_map(|m| match m {
            DaemonControlMessage::ImageCacheCensus(c) => Some(c),
            _ => None,
        })
        .collect();
    assert!(!census.is_empty());
    for page in census {
        assert!(
            page.entries
                .iter()
                .all(|e| e.fingerprint != begin.fingerprint),
            "{page:?}"
        );
    }
    assert!(!frames.iter().chain(before.iter()).any(|m| matches!(
        m,
        DaemonControlMessage::ImageCached(_) | DaemonControlMessage::ImageEvicted(_)
    )));
    assert!(
        f.images
            .entries()
            .iter()
            .all(|e| e.fingerprint != begin.fingerprint)
    );

    // `stored`: journal it, drop the alias image and the staging.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadStored(
            DiskOffloadStoredV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                fingerprint: begin.fingerprint.clone(),
                generation: 3,
            },
        ));
    wait_until("stored", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Stored)
    });
    wait_until("alias gone", || {
        f.runtime.alias_target(&al("off-1")).is_none()
    });
    assert!(!f.runtime.has_image(&begin.fingerprint));
    wait_until("staging gone", || staging_dirs(&f).is_empty());
    // A repeated request for the same offload changes nothing.
    f.offload.handle_server(request("off-1"));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(f.runtime.publish_calls().len(), 1);
}

#[test]
fn a_disk_grant_without_valid_encryption_is_refused_before_any_byte_leaves() {
    // I13 at the parser: no `encryption`, no frame.
    let mut value = serde_json::to_value(match grant("off-1", "ses-1", "http://x", 5, KEY) {
        ServerControlMessage::DiskUploadGrant(g) => g,
        _ => unreachable!(),
    })
    .unwrap();
    value.as_object_mut().unwrap().remove("encryption");
    value["type"] = "disk.upload.grant".into();
    assert!(sandbox_protocol::parse_server_control(&value.to_string()).is_err());

    // I13 at the daemon: a grant whose key does not decode uploads nothing.
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    f.offload.handle_server(request("off-1"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let size = begin_of(&begin).unwrap().size_bytes;
    f.offload
        .handle_server(grant("off-1", "ses-1", &url, size, &"!".repeat(44)));
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(failed_of(&failed), Some(DiskOffloadFailureCode::Io));
    assert!(listener.accept().is_err(), "no byte may leave the host");
    // The job cleaned up: no alias, no staging, no entry.
    assert!(f.runtime.alias_target(&al("off-1")).is_none());
    assert!(staging_dirs(&f).is_empty());
    assert!(f.offload.entry(SBX).is_none());

    // A wrong scheme is refused the same way.
    f.offload.handle_server(request("off-2"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let size = begin_of(&begin).unwrap().size_bytes;
    let mut bad = grant("off-2", "ses-2", &url, size, KEY);
    if let ServerControlMessage::DiskUploadGrant(g) = &mut bad {
        g.encryption.scheme = "none".into();
    }
    f.offload.handle_server(bad);
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(failed_of(&failed), Some(DiskOffloadFailureCode::Io));
    assert!(listener.accept().is_err());
}

#[test]
fn staging_full_keeps_the_disk_local_without_publishing() {
    let runtime = FakeRuntime::new();
    runtime.seed_stopped_sandbox(SBX);
    runtime.set_root_usage(SBX, None);
    // 1 GiB cache, 20 GiB root, usage unknown: 40 GiB never fits.
    let f = fixture_with(runtime, tempfile::tempdir().unwrap(), 1, 20);
    f.offload.handle_server(request("off-1"));
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(
        failed_of(&failed),
        Some(DiskOffloadFailureCode::StagingFull)
    );
    assert!(f.runtime.publish_calls().is_empty());
    assert!(f.offload.entry(SBX).is_none());
}

#[test]
fn missing_instances_are_reported() {
    let f = fixture();
    // Not in this host's journal.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadRequest(
            DiskOffloadRequestV11 {
                sandbox_id: "sbx-other".into(),
                generation: 1,
                offload_id: "off-x".into(),
                seq: 1,
            },
        ));
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(
        failed_of(&failed),
        Some(DiskOffloadFailureCode::InstanceMissing)
    );
    // In the journal but absent from Incus.
    let runtime = FakeRuntime::new();
    let f = fixture_with(runtime, tempfile::tempdir().unwrap(), 4, 1);
    f.offload.handle_server(request("off-1"));
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(
        failed_of(&failed),
        Some(DiskOffloadFailureCode::InstanceMissing)
    );
    assert!(f.offload.entry(SBX).is_none());
}

fn seed_entry(f: &Fixture, entry: OffloadEntry) {
    f.offload.lock_journal().put(SBX, entry).unwrap();
}

fn entry(phase: OffloadPhase, id: &str) -> OffloadEntry {
    OffloadEntry {
        offload_id: id.into(),
        seq: 1,
        generation: 3,
        phase,
        alias: al(id),
        staged_sha256: None,
        last_used_at: Some("fake-boot-seed".into()),
        cloud_init_instance_id: None,
        evict_grant_id: None,
        evict_expires_at_unix_ms: None,
    }
}

#[test]
fn startup_sweep_resumes_a_complete_alias_and_fails_an_interrupted_export() {
    // Crash after the alias landed: the restart resumes from the alias.
    let f = fixture();
    f.runtime.crash_next_publish(FakePublishCrash::AfterAlias);
    let _ = f.runtime.publish_stopped_instance(INSTANCE, &al("off-1"));
    seed_entry(&f, entry(OffloadPhase::Exporting, "off-1"));
    // Incus still runs an operation on the instance: recovery waits for it.
    f.runtime.set_instance_operation_running(INSTANCE, true);
    let offload = f.offload.clone();
    let recovering = std::thread::spawn(move || offload.recover());
    std::thread::sleep(Duration::from_millis(60));
    assert!(f.images.drain().iter().all(|m| begin_of(m).is_none()));
    f.runtime.set_instance_operation_running(INSTANCE, false);
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    assert_eq!(begin_of(&begin).unwrap().offload_id, "off-1");
    assert_eq!(
        f.runtime.alias_target(&al("off-1")).as_deref(),
        Some(begin_of(&begin).unwrap().fingerprint.as_str())
    );
    // Only the crashed publish ran: nothing was published twice.
    assert_eq!(f.runtime.publish_calls().len(), 1);
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadCancel(
            DiskOffloadCancelV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                reason: "superseded".into(),
            },
        ));
    recovering.join().unwrap();
    assert!(f.offload.entry(SBX).is_none());
    assert!(f.runtime.alias_target(&al("off-1")).is_none());

    // Crash before the alias: FAILED(export_interrupted), entry dropped.
    let f = fixture();
    f.runtime.crash_next_publish(FakePublishCrash::BeforeAlias);
    let _ = f.runtime.publish_stopped_instance(INSTANCE, &al("off-2"));
    seed_entry(&f, entry(OffloadPhase::Exporting, "off-2"));
    f.offload.recover();
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(
        failed_of(&failed),
        Some(DiskOffloadFailureCode::ExportInterrupted)
    );
    assert!(f.offload.entry(SBX).is_none());
}

#[test]
fn startup_sweep_removes_stray_aliases_and_staging_and_rehashes_staged_files() {
    let f = fixture();
    // A stray alias (no entry) and stray staging are removed.
    let stray = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("stray"))
        .unwrap();
    std::fs::create_dir_all(f.images.staging_dir().join("offload-ghost")).unwrap();
    // A staged entry whose file changed fails as corrupt (never resent).
    let staged = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("off-3"))
        .unwrap();
    let dir = f.images.staging_dir().join("offload-off-3");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("x.tar"), b"tampered").unwrap();
    let mut staged_entry = entry(OffloadPhase::Uploading, "off-3");
    staged_entry.staged_sha256 = Some(staged.fingerprint[7..].to_owned());
    seed_entry(&f, staged_entry);
    f.offload.recover();
    let (failed, _) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert_eq!(failed_of(&failed), Some(DiskOffloadFailureCode::Corrupt));
    assert!(f.runtime.alias_target(&al("stray")).is_none());
    assert!(!f.runtime.has_image(&stray.fingerprint));
    assert!(f.runtime.alias_target(&al("off-3")).is_none());
    assert!(staging_dirs(&f).is_empty(), "{:?}", staging_dirs(&f));
    assert!(f.offload.entry(SBX).is_none());

    // A staged entry whose file still matches resumes its upload.
    let published = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("off-4"))
        .unwrap();
    let dir = f.images.staging_dir().join("offload-off-4");
    std::fs::create_dir_all(&dir).unwrap();
    f.images.export_into(&published.fingerprint, &dir).unwrap();
    let mut resumed = entry(OffloadPhase::Staged, "off-4");
    resumed.staged_sha256 = Some(published.fingerprint[7..].to_owned());
    seed_entry(&f, resumed);
    let offload = f.offload.clone();
    let recovering = std::thread::spawn(move || offload.recover());
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    assert_eq!(begin_of(&begin).unwrap().fingerprint, published.fingerprint);
    let (url, seen) = s3(1);
    f.offload.handle_server(grant(
        "off-4",
        "ses-4",
        &url,
        begin_of(&begin).unwrap().size_bytes,
        KEY,
    ));
    wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskUploadComplete(_))
    });
    recovering.join().unwrap();
    assert_eq!(seen.join().unwrap().len(), 1);
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploaded);

    // A stored entry keeps no alias image or staging after a restart.
    let mut stored = f.offload.entry(SBX).unwrap();
    stored.phase = OffloadPhase::Stored;
    seed_entry(&f, stored);
    f.offload.recover();
    assert!(f.runtime.alias_target(&al("off-4")).is_none());
    assert!(staging_dirs(&f).is_empty());
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
}

#[test]
fn startup_sweep_deletes_only_this_daemons_aliases() {
    // The default Incus image store is shared by every daemon on the
    // machine: the sweep deletes its own stray alias, never another
    // daemon's (in flight there) or an unmarked pre-tag one.
    let f = fixture();
    let own = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("stray"))
        .unwrap();
    let foreign_alias =
        sandbox_runtime::offload_alias(&offload_owner_tag("host-b"), "off-9").unwrap();
    let foreign = f
        .runtime
        .publish_stopped_instance(INSTANCE, &foreign_alias)
        .unwrap();
    let legacy = f
        .runtime
        .publish_stopped_instance(INSTANCE, "wssp-off-off-8")
        .unwrap();
    f.offload.recover();
    assert!(f.runtime.alias_target(&al("stray")).is_none());
    assert!(!f.runtime.has_image(&own.fingerprint));
    assert_eq!(
        f.runtime.alias_target(&foreign_alias).as_deref(),
        Some(foreign.fingerprint.as_str())
    );
    assert_eq!(
        f.runtime.alias_target("wssp-off-off-8").as_deref(),
        Some(legacy.fingerprint.as_str())
    );
    // A request publishes under this daemon's tag.
    assert_ne!(offload_owner_tag(HOST), offload_owner_tag("host-b"));
    assert!(sandbox_runtime::offload_alias_owned_by(
        &al("off-1"),
        &offload_owner_tag(HOST)
    ));
}

#[test]
fn startup_sweep_removes_interrupted_restore_fetches_only() {
    let f = fixture();
    let staging = f.images.staging_dir().to_owned();
    std::fs::create_dir_all(&staging).unwrap();
    let killed = staging.join(format!("restore-{}.part", "a".repeat(64)));
    let held_name = format!("restore-{}.part", "b".repeat(64));
    let create = staging.join(format!("{}.part", "c".repeat(64)));
    for path in [&killed, &staging.join(&held_name), &create] {
        std::fs::write(path, b"partial").unwrap();
    }
    // A fetch running now holds its reservation: never removed.
    let held = f.images.reserve(&held_name, 7).unwrap();
    f.offload.recover();
    assert!(!killed.exists());
    assert!(staging.join(&held_name).exists());
    // A create's resumable part is the 24-hour staging sweep's.
    assert!(create.exists());
    drop(held);
}

/// Review P2: a daemon away while its offload became STORED keeps an
/// `uploaded` entry across a restart (staging charge held again); the
/// stored ack the server re-offers on the next session, however late,
/// settles it: journaled `stored`, alias image and staging dropped.
#[test]
fn a_late_stored_ack_after_a_restart_settles_an_uploaded_entry() {
    let f = fixture();
    let published = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("off-5"))
        .unwrap();
    let dir = f.images.staging_dir().join("offload-off-5");
    std::fs::create_dir_all(&dir).unwrap();
    f.images.export_into(&published.fingerprint, &dir).unwrap();
    let mut uploaded = entry(OffloadPhase::Uploaded, "off-5");
    uploaded.staged_sha256 = Some(published.fingerprint[7..].to_owned());
    seed_entry(&f, uploaded);
    f.offload.recover();
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploaded);
    assert!(f.runtime.alias_target(&al("off-5")).is_some());
    assert!(!staging_dirs(&f).is_empty());
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadStored(
            DiskOffloadStoredV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-5".into(),
                seq: 1,
                fingerprint: published.fingerprint.clone(),
                generation: 3,
            },
        ));
    wait_until("stored", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Stored)
    });
    wait_until("alias gone", || {
        f.runtime.alias_target(&al("off-5")).is_none()
    });
    wait_until("staging gone", || staging_dirs(&f).is_empty());
    // A repeated ack (the next session re-offers it) changes nothing.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadStored(
            DiskOffloadStoredV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-5".into(),
                seq: 1,
                fingerprint: published.fingerprint.clone(),
                generation: 3,
            },
        ));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
}

/// An `uploaded` entry with its alias image, staged export and (after the
/// restart's recovery) its staging reservation; returns the fingerprint.
fn uploaded_with_staging(f: &Fixture, id: &str) -> String {
    let published = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al(id))
        .unwrap();
    let dir = f.images.staging_dir().join(format!("offload-{id}"));
    std::fs::create_dir_all(&dir).unwrap();
    f.images.export_into(&published.fingerprint, &dir).unwrap();
    let mut uploaded = entry(OffloadPhase::Uploaded, id);
    uploaded.staged_sha256 = Some(published.fingerprint[7..].to_owned());
    seed_entry(f, uploaded);
    f.offload.recover();
    assert!(f.offload.lock_jobs().reservations.contains_key(id));
    assert!(f.runtime.alias_target(&al(id)).is_some());
    assert!(!staging_dirs(f).is_empty());
    published.fingerprint
}

fn local_gone(f: &Fixture, id: &str) -> bool {
    f.offload.entry(SBX).is_none()
        && f.runtime.alias_target(&al(id)).is_none()
        && staging_dirs(f).is_empty()
        && f.offload.lock_jobs().reservations.is_empty()
}

fn inventories(f: &Fixture) -> Vec<Vec<sandbox_protocol::DiskOffloadInventoryEntryV11>> {
    let mut pages = Vec::new();
    loop {
        let frames = f.images.drain();
        if frames.is_empty() {
            return pages;
        }
        for frame in frames {
            if let DaemonControlMessage::DiskOffloadInventory(page) = frame {
                pages.push(page.entries);
            }
        }
    }
}

/// After reconciliation the daemon reports its unfinished
/// entries (never stored ones) in pages of at most 256, at most 16 pages a
/// session; a truncated inventory continues after its last entry next time.
#[test]
fn the_inventory_reports_unfinished_entries_in_bounded_pages_and_continues() {
    let f = fixture();
    let put = |range: std::ops::Range<usize>| {
        let mut journal = f.offload.lock_journal();
        for i in range {
            journal.file.entries.insert(
                format!("sbx-{i:05}"),
                entry(OffloadPhase::Uploaded, &format!("off-{i}")),
            );
        }
    };
    put(0..300);
    f.offload
        .lock_journal()
        .file
        .entries
        .insert("sbx-stored".into(), entry(OffloadPhase::Stored, "off-s"));
    f.offload.begin_inventory();
    let pages = inventories(&f);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), [256, 44]);
    let all: Vec<_> = pages.concat();
    assert!(all.iter().all(|e| e.offload_id != "off-s" && e.seq == 1));
    assert_eq!(all[0].sandbox_id, "sbx-00000");
    assert_eq!(all[299].sandbox_id, "sbx-00299");
    for page in &pages {
        let frame =
            DaemonControlMessage::DiskOffloadInventory(sandbox_protocol::DiskOffloadInventoryV11 {
                entries: page.clone(),
            });
        let _spelled = sandbox_protocol::WireCodes::negotiated("1.0")
            .encode(&frame, None)
            .expect("a page encodes");
    }
    // Over the session cap: 16 full pages, then the rest (and a wrap) next.
    put(300..4100);
    f.offload.begin_inventory();
    let pages = inventories(&f);
    assert_eq!(pages.len(), 16);
    assert!(pages.iter().all(|page| page.len() == 256));
    assert_eq!(pages[15][255].sandbox_id, "sbx-04095");
    f.offload.begin_inventory();
    let next: Vec<_> = inventories(&f).concat();
    assert_eq!(next[0].sandbox_id, "sbx-04096");
    assert_eq!(next[3].sandbox_id, "sbx-04099");
    assert_eq!(next[4].sandbox_id, "sbx-00000", "wraps around");
    // Nothing unfinished: no frame at all.
    let f = fixture();
    f.offload.begin_inventory();
    assert!(inventories(&f).is_empty());
}

/// The server's `released` answer to an inventory entry (its
/// offload was CONSUMED, FAILED, … or is not this host's) drops the alias
/// image, the export, the staging reservation and the entry; the VM stays.
#[test]
fn a_release_drops_an_uploaded_entrys_alias_export_staging_and_reservation() {
    let f = fixture();
    uploaded_with_staging(&f, "off-5");
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadCancel(
            DiskOffloadCancelV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-5".into(),
                seq: 1,
                reason: "released".into(),
            },
        ));
    wait_until("released", || local_gone(&f, "off-5"));
    // The VM itself is never touched by a release.
    assert!(
        f.runtime
            .instance_last_used(INSTANCE)
            .is_ok_and(|used| used.is_some())
    );
}

/// The server frees the host's export slot at STORED, so the
/// next request can arrive right behind the stored ack. Its staging
/// reservation waits for the ack's cleanup (a slow alias delete here)
/// instead of failing `staging_full`.
#[test]
fn the_next_export_waits_for_the_stored_ack_cleanup() {
    const OTHER: &str = "sbx-2";
    let runtime = FakeRuntime::new();
    runtime.seed_stopped_sandbox(SBX);
    runtime.seed_stopped_sandbox(OTHER);
    runtime.set_root_usage(OTHER, None);
    let dir = tempfile::tempdir().expect("dir");
    let images = images_for(&runtime, dir.path(), 4);
    let offload = OffloadService::open_with(
        images.clone(),
        Arc::new(runtime.clone()),
        Arc::new(|id: &str| {
            (id == SBX || id == OTHER).then_some(LocalSandbox {
                disk_gib: 1,
                build: false,
            })
        }),
        OffloadSettings {
            host_id: HOST.into(),
            ..OffloadSettings::default()
        },
        timing(),
    )
    .expect("offload");
    let f = Fixture {
        runtime,
        images,
        offload,
        dir: dir.path().to_path_buf(),
        _dir: dir,
    };
    let published = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al("off-a"))
        .unwrap();
    let mut uploaded = entry(OffloadPhase::Uploaded, "off-a");
    uploaded.staged_sha256 = Some(published.fingerprint[7..].to_owned());
    seed_entry(&f, uploaded);
    // Three of the four GiB held until the ack; the next export needs two.
    f.offload.reserve("off-a", 3 * GIB).expect("reserved");
    f.runtime
        .set_alias_list_hold(Some(Duration::from_millis(300)));
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadStored(
            DiskOffloadStoredV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-a".into(),
                seq: 1,
                fingerprint: published.fingerprint.clone(),
                generation: 3,
            },
        ));
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadRequest(
            DiskOffloadRequestV11 {
                sandbox_id: OTHER.into(),
                generation: 3,
                offload_id: "off-b".into(),
                seq: 1,
            },
        ));
    let (begin, seen) = wait_for_frame(&f.images, |m| {
        begin_of(m).is_some() || failed_of(m).is_some()
    });
    assert_eq!(
        begin_of(&begin).map(|b| b.offload_id.as_str()),
        Some("off-b"),
        "{begin:?} after {seen:?}"
    );
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    assert!(!f.offload.lock_jobs().reservations.contains_key("off-a"));
}

#[test]
fn reconnect_waits_for_an_in_flight_publish_and_kill_preempts_the_upload() {
    // F13: the publish runs; a reconnect waits for it, then the job is
    // cancelled without a report and everything it made is removed.
    let f = fixture();
    f.runtime.set_publish_hold(Some(Duration::from_millis(300)));
    f.offload.handle_server(request("off-1"));
    wait_until("publishing", || f.runtime.publishes_in_flight() == 1);
    let started = Instant::now();
    let hold = f.offload.preempt(SBX, &|| true).expect("hold");
    assert_eq!(f.runtime.publishes_in_flight(), 0, "returned mid-publish");
    assert!(started.elapsed() >= Duration::from_millis(100));
    wait_until("cleaned", || {
        f.offload.entry(SBX).is_none() && f.runtime.alias_target(&al("off-1")).is_none()
    });
    // While held, a new request never publishes.
    f.runtime.set_publish_hold(None);
    f.offload.handle_server(request("off-2"));
    let (failed, frames) = wait_for_frame(&f.images, |m| failed_of(m).is_some());
    assert!(frames.iter().all(|m| begin_of(m).is_none()));
    assert_eq!(failed_of(&failed), Some(DiskOffloadFailureCode::Cancelled));
    assert_eq!(f.runtime.publish_calls().len(), 1);
    drop(hold);

    // A kill preempts an upload waiting for its grant: nothing reported.
    f.offload.handle_server(request("off-3"));
    wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let _kill = f.offload.preempt(SBX, &|| true).expect("hold");
    wait_until("upload preempted", || f.offload.entry(SBX).is_none());
    std::thread::sleep(Duration::from_millis(50));
    assert!(f.images.drain().iter().all(|m| failed_of(m).is_none()));
    assert!(f.runtime.alias_target(&al("off-3")).is_none());
    assert!(staging_dirs(&f).is_empty());

    // A reconnect that is no longer wanted stops waiting.
    let f = fixture();
    f.runtime.set_publish_hold(Some(Duration::from_secs(2)));
    f.offload.handle_server(request("off-1"));
    wait_until("publishing", || f.runtime.publishes_in_flight() == 1);
    let error = f.offload.preempt(SBX, &|| false).err().expect("refused");
    assert_eq!(error.code, SandboxErrorCode::Cancelled);
}

/// Live r2: a sandbox destroyed while its `stored` copy was cached kept the
/// entry across restarts (the inventory reports only unfinished entries).
/// A confirmed kill drops a stored entry; unfinished and evicting entries
/// stay with their job or eviction.
#[test]
fn a_confirmed_kill_drops_only_a_stored_entry() {
    let f = fixture();
    seed_entry(&f, entry(OffloadPhase::Stored, "off-1"));
    f.offload.forget_on_kill(SBX);
    wait_until("stored entry dropped", || f.offload.entry(SBX).is_none());
    for phase in [
        OffloadPhase::Uploaded,
        OffloadPhase::Evicting,
        OffloadPhase::Evicted,
    ] {
        let kept = entry(phase, "off-2");
        seed_entry(&f, kept.clone());
        f.offload.forget_on_kill(SBX);
        assert_eq!(f.offload.entry(SBX), Some(kept), "{phase:?} kept");
    }
    f.offload.forget_on_kill("sbx-absent");
}

/// The startup recovery forgets a stored entry only with no
/// live lease and the VM proven absent; a live lease or a present VM keeps it.
#[test]
fn recovery_forgets_a_stored_entry_only_for_an_absent_vm_without_a_lease() {
    let f = fixture();
    let runtime = f.runtime.clone();
    runtime.seed_stopped_sandbox("sbx-present");
    for sandbox in [SBX, "sbx-present", "sbx-gone"] {
        f.offload
            .lock_journal()
            .put(
                sandbox,
                entry(OffloadPhase::Stored, &format!("off-{sandbox}")),
            )
            .unwrap();
    }
    f.offload.recover();
    assert!(f.offload.entry(SBX).is_some(), "live lease kept");
    assert!(f.offload.entry("sbx-present").is_some(), "present VM kept");
    assert!(f.offload.entry("sbx-gone").is_none(), "absent VM forgotten");
}

#[test]
fn a_stored_copy_survives_preemption_and_a_cancel_removes_an_unfinished_one() {
    let f = fixture();
    let mut stored = entry(OffloadPhase::Stored, "off-1");
    stored.staged_sha256 = Some("ab".repeat(32));
    seed_entry(&f, stored.clone());
    drop(f.offload.preempt(SBX, &|| true).unwrap());
    assert_eq!(f.offload.entry(SBX), Some(stored));
    // An uploaded (awaiting `stored`) entry is cancelled by the server.
    let mut uploaded = entry(OffloadPhase::Uploaded, "off-2");
    uploaded.staged_sha256 = Some("ab".repeat(32));
    seed_entry(&f, uploaded);
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadCancel(
            DiskOffloadCancelV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-2".into(),
                seq: 1,
                reason: "superseded".into(),
            },
        ));
    wait_until("cancelled", || f.offload.entry(SBX).is_none());
    // A grant nobody waits for has its key wiped at once.
    f.offload
        .handle_server(grant("off-9", "ses-9", "http://127.0.0.1:9", 5, KEY));
    assert!(f.offload.lock_keys().is_empty());
}

fn stored_ack(id: &str, fingerprint: &str) -> ServerControlMessage {
    ServerControlMessage::DiskOffloadStored(DiskOffloadStoredV11 {
        sandbox_id: SBX.into(),
        offload_id: id.into(),
        seq: 1,
        fingerprint: fingerprint.into(),
        generation: 3,
    })
}

fn cancel(id: &str, reason: &str) -> ServerControlMessage {
    ServerControlMessage::DiskOffloadCancel(DiskOffloadCancelV11 {
        sandbox_id: SBX.into(),
        offload_id: id.into(),
        seq: 1,
        reason: reason.into(),
    })
}

fn released_of(frame: &DaemonControlMessage) -> Option<&str> {
    match frame {
        DaemonControlMessage::DiskOffloadReleased(r) => Some(r.offload_id.as_str()),
        _ => None,
    }
}

/// The stored ack is answered `disk.offload.released` only
/// once the alias image, the export and the staging reservation are gone
/// (the server frees the host's export slot on it, not at STORED). A
/// repeated ack and an ack for an offload this host holds nothing of are
/// answered too; a mismatching ack is not.
#[test]
fn the_stored_ack_is_answered_released_after_the_staging_is_freed() {
    let f = fixture();
    let fingerprint = uploaded_with_staging(&f, "off-5");
    // Slow alias listing: the release must not overtake the cleanup.
    f.runtime
        .set_alias_list_hold(Some(Duration::from_millis(200)));
    f.offload.handle_server(stored_ack("off-5", &fingerprint));
    let (released, _) = wait_for_frame(&f.images, |m| released_of(m).is_some());
    assert_eq!(released_of(&released), Some("off-5"));
    // Everything was gone before the frame was pushed.
    assert!(f.runtime.alias_target(&al("off-5")).is_none());
    assert!(staging_dirs(&f).is_empty());
    assert!(f.offload.lock_jobs().reservations.is_empty());
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    f.runtime.set_alias_list_hold(None);
    // A repeated ack (a reconnect re-offers it) is answered again.
    f.offload.handle_server(stored_ack("off-5", &fingerprint));
    let (again, _) = wait_for_frame(&f.images, |m| released_of(m).is_some());
    assert_eq!(released_of(&again), Some("off-5"));
    // A host that holds nothing of the offload counts as released.
    f.offload.handle_server(stored_ack(
        "off-gone",
        &format!("sha256:{}", "c".repeat(64)),
    ));
    let (gone, _) = wait_for_frame(&f.images, |m| released_of(m).is_some());
    assert_eq!(released_of(&gone), Some("off-gone"));
    // A mismatching fingerprint of the journaled offload is never released.
    f.offload
        .handle_server(stored_ack("off-5", &format!("sha256:{}", "d".repeat(64))));
    std::thread::sleep(Duration::from_millis(100));
    assert!(f.images.drain().iter().all(|m| released_of(m).is_none()));
}

#[test]
fn journal_phases_only_move_forward() {
    use OffloadPhase::*;
    let all = [
        Exporting, Exported, Staged, Uploading, Uploaded, Stored, Evicting, Evicted,
    ];
    for from in all {
        for to in all {
            let allowed = from == to
                || matches!(
                    (from, to),
                    (Stored, Evicting) | (Evicting, Evicted) | (Evicting, Stored)
                )
                || (!matches!(to, Evicting | Evicted) && from.rank() < to.rank());
            assert_eq!(from.may_become(to), allowed, "{from:?} -> {to:?}");
        }
    }
    // Nothing leaves a stored phase for an upload phase.
    for from in [Stored, Evicting, Evicted] {
        for to in [Exporting, Exported, Staged, Uploading, Uploaded] {
            assert!(!from.may_become(to), "{from:?} -> {to:?}");
        }
    }
}

/// A journal entry `uploading` with its alias image and staged export, as
/// a crash after queuing `disk.upload.complete` (before journaling
/// `uploaded`) leaves it; returns the fingerprint.
fn crashed_while_uploading(f: &Fixture, id: &str) -> String {
    let published = f
        .runtime
        .publish_stopped_instance(INSTANCE, &al(id))
        .unwrap();
    let dir = f.images.staging_dir().join(format!("offload-{id}"));
    std::fs::create_dir_all(&dir).unwrap();
    f.images.export_into(&published.fingerprint, &dir).unwrap();
    let mut uploading = entry(OffloadPhase::Uploading, id);
    uploading.staged_sha256 = Some(published.fingerprint[7..].to_owned());
    seed_entry(f, uploading);
    published.fingerprint
}

fn recovering(f: &Fixture) -> std::thread::JoinHandle<()> {
    let service = f.offload.clone();
    std::thread::spawn(move || service.recover())
}

/// The reported interleaving: the restart resumes the
/// `uploading` job, the server answers its begin `stale` (verification
/// finished while the daemon was down), and only then does the inventory's
/// stored ack arrive. The stale answer leaves the entry `uploaded` and asks
/// for the verdict; the ack then stores it. The stored entry survives.
#[test]
fn a_stale_resumed_begin_waits_for_the_verdict_and_the_late_ack_stores_it() {
    let f = fixture();
    let fingerprint = crashed_while_uploading(&f, "off-5");
    let recovery = recovering(&f);
    wait_for_frame(&f.images, |m| begin_of(m).is_some());
    f.offload.handle_server(cancel("off-5", "stale"));
    let (asked, _) = wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskOffloadInventory(_))
    });
    let DaemonControlMessage::DiskOffloadInventory(page) = asked else {
        unreachable!()
    };
    assert_eq!(
        page.entries
            .iter()
            .map(|e| e.offload_id.as_str())
            .collect::<Vec<_>>(),
        ["off-5"]
    );
    recovery.join().unwrap();
    // Waiting for the verdict: the entry, its alias, staging and
    // reservation are all kept, and nothing is reported failed.
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploaded);
    assert!(f.runtime.alias_target(&al("off-5")).is_some());
    assert!(f.offload.lock_jobs().reservations.contains_key("off-5"));
    assert!(f.images.drain().iter().all(|m| failed_of(m).is_none()));
    f.offload.handle_server(stored_ack("off-5", &fingerprint));
    wait_for_frame(&f.images, |m| released_of(m) == Some("off-5"));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    assert!(f.runtime.alias_target(&al("off-5")).is_none());
    assert!(staging_dirs(&f).is_empty());
    assert!(f.offload.lock_jobs().reservations.is_empty());
}

/// The exact interleaving: the resumed job's begin is
/// answered `stale`, it asks for the verdict and its waits are over, and
/// the inventory's `released` answer lands before the job leaves `active`
/// (a deterministic seam between the two). The answer reaches no waiter,
/// yet the job's settling applies it: entry, alias, export and staging
/// reservation all go, so the next export is never `staging_full`.
#[test]
fn a_release_landing_while_a_stale_job_settles_is_never_dropped() {
    let f = fixture();
    crashed_while_uploading(&f, "off-5");
    let (reached_tx, reached) = mpsc::channel::<()>();
    let (go, go_rx) = mpsc::channel::<()>();
    let go_rx = Mutex::new(go_rx);
    *f.offload.inner.before_settle.lock().unwrap() = Some(Box::new(move || {
        let _ = reached_tx.send(());
        let _ = go_rx.lock().unwrap().recv();
    }));
    let recovery = recovering(&f);
    wait_for_frame(&f.images, |m| begin_of(m).is_some());
    f.offload.handle_server(cancel("off-5", "stale"));
    wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskOffloadInventory(_))
    });
    reached.recv_timeout(Duration::from_secs(10)).unwrap();
    // The job is still `active`, its waiter already gone.
    assert!(f.offload.lock_jobs().active.contains_key(SBX));
    f.offload.handle_server(cancel("off-5", "released"));
    go.send(()).unwrap();
    recovery.join().unwrap();
    wait_until("released and freed", || local_gone(&f, "off-5"));
    assert!(f.images.drain().iter().all(|m| failed_of(m).is_none()));
}

/// The other orders: the inventory's stored ack lands while
/// the resumed job waits for its grant (then the begin's `stale` answer
/// arrives), or before recovery resumes the job at all. Either way the
/// entry ends `stored` and the job's cleanup frees only the staging.
#[test]
fn a_stored_ack_that_overtakes_a_resumed_upload_is_never_undone() {
    // The ack lands while the resumed job waits for its grant.
    let f = fixture();
    let fingerprint = crashed_while_uploading(&f, "off-5");
    let recovery = recovering(&f);
    wait_for_frame(&f.images, |m| begin_of(m).is_some());
    f.offload.handle_server(stored_ack("off-5", &fingerprint));
    f.offload.handle_server(cancel("off-5", "stale"));
    recovery.join().unwrap();
    wait_until("stored and freed", || {
        staging_dirs(&f).is_empty() && f.offload.lock_jobs().reservations.is_empty()
    });
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    assert!(f.runtime.alias_target(&al("off-5")).is_none());
    std::thread::sleep(Duration::from_millis(50));
    assert!(f.images.drain().iter().all(|m| failed_of(m).is_none()));

    // The ack lands before recovery resumes the job: no begin is sent.
    let f = fixture();
    let fingerprint = crashed_while_uploading(&f, "off-6");
    f.offload.handle_server(stored_ack("off-6", &fingerprint));
    wait_for_frame(&f.images, |m| released_of(m) == Some("off-6"));
    recovering(&f).join().unwrap();
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    assert!(staging_dirs(&f).is_empty());
    assert!(f.images.drain().iter().all(|m| begin_of(m).is_none()));
}

/// The job's last write (`uploaded`, after the complete went
/// out) never overwrites a stored ack that overtook it.
#[test]
fn an_upload_completing_after_its_stored_ack_keeps_stored() {
    let f = fixture();
    f.offload.handle_server(request("off-1"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let begin = begin_of(&begin).unwrap().clone();
    // The journal write of `uploaded` waits until the ack is in.
    let (url, seen) = s3(1);
    f.offload
        .handle_server(grant("off-1", "ses-1", &url, begin.size_bytes, KEY));
    wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskUploadComplete(_))
    });
    seen.join().unwrap();
    f.offload
        .handle_server(stored_ack("off-1", &begin.fingerprint));
    wait_for_frame(&f.images, |m| released_of(m) == Some("off-1"));
    wait_until("job ended", || f.offload.lock_jobs().active.is_empty());
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    // A direct late write of an upload step is refused by the table.
    let mut late = f.offload.entry(SBX).unwrap();
    late.phase = OffloadPhase::Uploaded;
    assert_eq!(f.offload.transition(SBX, &late), Ok(Moved::Past));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
}

// ------------------------------------------------------------ eviction (C5)

/// A recording [`LocalDisks`]: every eviction succeeds with an absent root.
#[derive(Default)]
struct FakeDisks {
    evicted: Mutex<Vec<(String, String)>>,
    busy: AtomicBool,
    pressure: AtomicBool,
    /// Discards succeed with an absent root (else `binding_mismatch`).
    discard_ok: AtomicBool,
}

impl LocalDisks for FakeDisks {
    fn evict(
        &self,
        sandbox_id: &str,
        grant_id: &str,
    ) -> Result<sandbox_protocol::RootObservation, String> {
        self.evicted
            .lock()
            .unwrap()
            .push((sandbox_id.into(), grant_id.into()));
        Ok(sandbox_protocol::RootObservation {
            storage_pool_name: "default".into(),
            storage_marker: "a".repeat(32),
            disk_gi_b: 1,
            state: sandbox_protocol::RootState::Absent,
            network_cleanup_complete: true,
            observation_sequence: 0,
        })
    }
    fn discard(
        &self,
        _discard: &sandbox_protocol::DiskDiscardV11,
    ) -> Result<sandbox_protocol::RootObservation, String> {
        if !self.discard_ok.load(Ordering::SeqCst) {
            return Err("binding_mismatch".into());
        }
        Ok(sandbox_protocol::RootObservation {
            storage_pool_name: "default".into(),
            storage_marker: "a".repeat(32),
            disk_gi_b: 1,
            state: sandbox_protocol::RootState::Absent,
            network_cleanup_complete: true,
            observation_sequence: 0,
        })
    }
    fn under_pressure(&self, _sandbox_id: &str) -> bool {
        self.pressure.load(Ordering::SeqCst)
    }
    fn lifecycle_busy(&self, _sandbox_id: &str) -> bool {
        self.busy.load(Ordering::SeqCst)
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn iso(ms: u64) -> String {
    // Test-only formatter (seconds precision) for `heartbeat.pong`.
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn evict_grant(id: &str, expires_at_unix_ms: u64) -> ServerControlMessage {
    ServerControlMessage::DiskEvictGrant(sandbox_protocol::DiskEvictGrantV11 {
        sandbox_id: SBX.into(),
        offload_id: "off-1".into(),
        seq: 1,
        grant_id: id.into(),
        expires_at_unix_ms,
    })
}

fn evicted_of(frame: &DaemonControlMessage) -> Option<&sandbox_protocol::DiskEvictedV11> {
    match frame {
        DaemonControlMessage::DiskEvicted(evicted) => Some(evicted),
        _ => None,
    }
}

fn stored_fixture() -> (Fixture, Arc<FakeDisks>) {
    let f = fixture();
    let disks = Arc::new(FakeDisks::default());
    f.offload.install_local_disks(disks.clone());
    seed_entry(&f, entry(OffloadPhase::Stored, "off-1"));
    (f, disks)
}

#[test]
fn utc_timestamps_parse_like_to_iso_string() {
    assert_eq!(evict::parse_utc_ms("1970-01-01T00:00:00.000Z"), Some(0));
    assert_eq!(
        evict::parse_utc_ms("2026-11-06T22:55:01.250Z"),
        Some(1_794_005_701_250)
    );
    assert_eq!(
        evict::parse_utc_ms("2026-11-06T22:55:01Z"),
        Some(1_794_005_701_000)
    );
    let now = wall_ms() / 1000 * 1000;
    assert_eq!(evict::parse_utc_ms(&iso(now)), Some(now));
    for bad in [
        "2026-11-06 22:55:01Z",
        "2026-13-06T22:55:01Z",
        "2026-11-06T22:55:01",
        "x",
    ] {
        assert_eq!(evict::parse_utc_ms(bad), None, "{bad}");
    }
}

#[test]
fn a_suggestion_asks_once_and_a_grant_is_journaled_before_the_vm_is_deleted() {
    let (f, disks) = stored_fixture();
    let suggest = || {
        f.offload
            .handle_server(ServerControlMessage::DiskEvictSuggest(
                sandbox_protocol::DiskEvictSuggestV11 {
                    sandbox_id: SBX.into(),
                    offload_id: "off-1".into(),
                    seq: 1,
                },
            ))
    };
    suggest();
    suggest();
    let requests: Vec<_> = f
        .images
        .drain()
        .into_iter()
        .filter(|m| matches!(m, DaemonControlMessage::DiskEvictRequest(_)))
        .collect();
    assert_eq!(requests.len(), 1, "one request in flight");
    // No relayed server time yet: the grant is refused (left to expire).
    let far = wall_ms() + 600_000;
    f.offload.handle_server(evict_grant("g-1", far));
    std::thread::sleep(Duration::from_millis(100));
    assert!(disks.evicted.lock().unwrap().is_empty());
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
    // S11: within 60 s of expiry by the server's clock: refused.
    f.offload.note_server_time(&iso(wall_ms()));
    f.offload
        .handle_server(evict_grant("g-1", wall_ms() + 30_000));
    std::thread::sleep(Duration::from_millis(100));
    assert!(disks.evicted.lock().unwrap().is_empty());
    // A live lifecycle permit refuses it too.
    disks.busy.store(true, Ordering::SeqCst);
    f.offload.handle_server(evict_grant("g-1", far));
    std::thread::sleep(Duration::from_millis(100));
    assert!(disks.evicted.lock().unwrap().is_empty());
    disks.busy.store(false, Ordering::SeqCst);
    // A grant for another seq is not this copy's.
    f.offload
        .handle_server(ServerControlMessage::DiskEvictGrant(
            sandbox_protocol::DiskEvictGrantV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 2,
                grant_id: "g-x".into(),
                expires_at_unix_ms: far,
            },
        ));
    std::thread::sleep(Duration::from_millis(100));
    assert!(disks.evicted.lock().unwrap().is_empty());
    // The grant: journaled, VM deleted, `disk.evicted` with the proof.
    f.offload.handle_server(evict_grant("g-1", far));
    let (frame, _) = wait_for_frame(&f.images, |m| evicted_of(m).is_some());
    let evicted = evicted_of(&frame).unwrap();
    assert_eq!(
        (evicted.offload_id.as_str(), evicted.grant_id.as_str()),
        ("off-1", "g-1")
    );
    assert_eq!(
        evicted.root_absence_proof.state,
        sandbox_protocol::RootState::Absent
    );
    assert_eq!(
        *disks.evicted.lock().unwrap(),
        [(SBX.to_owned(), "g-1".to_owned())]
    );
    let journaled = f.offload.entry(SBX).unwrap();
    assert_eq!(journaled.phase, OffloadPhase::Evicted);
    assert_eq!(journaled.evict_grant_id.as_deref(), Some("g-1"));
    // A repeated stored ack never undoes it.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadStored(
            DiskOffloadStoredV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                fingerprint: format!("sha256:{}", "ab".repeat(32)),
                generation: 3,
            },
        ));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Evicted);
    // T16: the server's ack drops the entry.
    f.offload
        .handle_server(ServerControlMessage::DiskOffloadCancel(
            DiskOffloadCancelV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                reason: "evicted".into(),
            },
        ));
    wait_until("entry dropped", || f.offload.entry(SBX).is_none());
}

#[test]
fn a_restart_redeletes_under_an_unexpired_grant_and_reverts_an_expired_one() {
    // Crash after the grant was journaled: still unexpired, so delete again.
    let (f, disks) = stored_fixture();
    let mut evicting = entry(OffloadPhase::Evicting, "off-1");
    evicting.evict_grant_id = Some("g-1".into());
    evicting.evict_expires_at_unix_ms = Some(wall_ms() + 600_000);
    seed_entry(&f, evicting);
    f.offload.recover();
    let (frame, _) = wait_for_frame(&f.images, |m| evicted_of(m).is_some());
    assert_eq!(evicted_of(&frame).unwrap().grant_id, "g-1");
    assert_eq!(disks.evicted.lock().unwrap().len(), 1);

    // Past its expiry the copy is `stored` again; the census decides.
    let (f, disks) = stored_fixture();
    let mut expired = entry(OffloadPhase::Evicting, "off-1");
    expired.evict_grant_id = Some("g-1".into());
    expired.evict_expires_at_unix_ms = Some(wall_ms().saturating_sub(1));
    seed_entry(&f, expired);
    f.offload.recover();
    wait_until("reverted", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Stored && e.evict_grant_id.is_none())
    });
    assert!(disks.evicted.lock().unwrap().is_empty());
    // A stored copy keeps no staging and no alias, so the sweep leaves it.
    assert!(staging_dirs(&f).is_empty());
}

#[test]
fn local_pressure_asks_for_the_least_recently_used_copies_a_bounded_number_at_once() {
    let (f, disks) = stored_fixture();
    // Not under pressure: nothing asked.
    assert_eq!(f.offload.pressure_evict(), 0);
    disks.pressure.store(true, Ordering::SeqCst);
    assert_eq!(f.offload.pressure_evict(), 1);
    // Already pending: not asked twice.
    assert_eq!(f.offload.pressure_evict(), 0);
    // A refusal clears it; lifecycle work blocks a new ask.
    f.offload
        .handle_server(ServerControlMessage::DiskEvictRefused(
            sandbox_protocol::DiskEvictRefusedV11 {
                sandbox_id: SBX.into(),
                offload_id: "off-1".into(),
                seq: 1,
                code: "no_restore_host".into(),
            },
        ));
    let hold = f.offload.preempt(SBX, &|| true).unwrap();
    assert_eq!(f.offload.pressure_evict(), 0);
    drop(hold);
    assert_eq!(f.offload.pressure_evict(), 1);
}

fn discard_frame(
    create_key: &str,
    base: &str,
    template: &str,
    pool: &sandbox_runtime::StoragePoolIdentity,
) -> sandbox_protocol::DiskDiscardV11 {
    sandbox_protocol::DiskDiscardV11 {
        sandbox_id: SBX.into(),
        copy_id: "copy-1".into(),
        create_key: create_key.into(),
        base_fingerprint: base.into(),
        template_fingerprint: template.into(),
        storage_pool_name: pool.name.clone(),
        storage_marker: pool.storage_id.clone(),
    }
}

#[test]
fn discard_binds_a_present_copy_and_deletes_an_orphan_root_by_its_pool_identity() {
    use sandbox_runtime::SandboxRuntime as _;
    let dir = tempfile::tempdir().unwrap();
    let binding = crate::sandbox_relay::journal::TransportBindingV11 {
        server: "wss://offload.test/ws/sandbox-host".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    };
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    let runtime = FakeRuntime::new();
    let pool = runtime.initialize_storage_pool("primary", None).unwrap();
    let root = sandbox_runtime::RootDisk {
        pool: pool.clone(),
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .unwrap()
            .disk_gi_b_default,
    };
    let request = sandbox_runtime::CreateSandboxRequest::for_test(SBX, "create-1");
    runtime.create_sandbox_on_storage(&request, &root).unwrap();
    let disks = JournalDisks::new(journal, Arc::new(runtime.clone()));
    let base = request.template_digest.clone();

    // Another binding (a newer create key): refused, the VM untouched.
    assert_eq!(
        disks
            .discard(&discard_frame("create-2", &base, &base, &pool))
            .unwrap_err(),
        "binding_mismatch"
    );
    assert!(runtime.query_sandbox(SBX, None, None).unwrap().is_some());

    // Present and bound: deleted, root proven absent.
    let proof = disks
        .discard(&discard_frame("create-1", &base, &base, &pool))
        .unwrap();
    assert_eq!(proof.state, sandbox_protocol::RootState::Absent);
    assert_eq!(
        (
            proof.storage_pool_name.as_str(),
            proof.storage_marker.as_str()
        ),
        (pool.name.as_str(), pool.storage_id.as_str())
    );
    assert!(runtime.query_sandbox(SBX, None, None).unwrap().is_none());

    // Absent with an orphan root on that pool: the root volume is deleted.
    runtime.seed_orphan_root(INSTANCE, root.clone());
    assert!(runtime.prove_root_absent(&root, INSTANCE).is_err());
    let proof = disks
        .discard(&discard_frame("create-1", &base, &base, &pool))
        .unwrap();
    assert_eq!(proof.state, sandbox_protocol::RootState::Absent);
    assert!(runtime.prove_root_absent(&root, INSTANCE).is_ok());

    // Already rootless: the proof directly.
    assert!(
        disks
            .discard(&discard_frame("create-1", &base, &base, &pool))
            .is_ok()
    );
}

/// Review repro (offload C1–C8, P2): a restored sandbox ran here, moved away
/// while this host was offline, and the host returns: the server's discard
/// names the copy's base (the restored disk image). The discard binds the
/// stale VM through the journaled restore base, deletes it, proves the root
/// absent and settles the lease (the root reservation released).
#[test]
fn review_repro_a_returning_host_discards_a_restored_copy_end_to_end() {
    use sandbox_runtime::SandboxRuntime as _;
    let dir = tempfile::tempdir().unwrap();
    let binding = crate::sandbox_relay::journal::TransportBindingV11 {
        server: "wss://offload.test/ws/sandbox-host".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    };
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    let runtime = FakeRuntime::new();
    let pool = runtime.initialize_storage_pool("primary", None).unwrap();
    let mut allocation = crate::sandbox_relay::test_support::allocation();
    allocation.storage_pool_name = pool.name.clone();
    allocation.storage_marker = pool.storage_id.clone();
    journal.lower_implicit_ceiling(&pool, 167, true).unwrap();
    let root = sandbox_runtime::RootDisk {
        pool: pool.clone(),
        disk_gi_b: allocation.disk_gi_b,
    };
    let mut request = sandbox_runtime::CreateSandboxRequest::for_test(SBX, "restore-1");
    let disk = runtime.seed_image_bytes(
        b"stored disk",
        request.architecture.as_deref().unwrap_or("x86_64"),
        false,
    );
    request.restore = Some(sandbox_runtime::RestoreLaunch {
        fingerprint: disk.clone(),
        cloud_init_instance_id: None,
    });
    runtime.create_sandbox_on_storage(&request, &root).unwrap();
    // The restore this host ran, journaled with its restore base.
    let restore: sandbox_protocol::OperationDispatch = serde_json::from_value(serde_json::json!({
        "sandboxOwnerId":"owner", "operationId":"restore", "sandboxId":SBX,
        "kind":"sandbox.reconnect", "allocation": allocation,
        "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1,
        "idempotencyKey":"restore-1", "bodyHash":"a".repeat(64),
        "templateDigest": request.template_digest,
        "image": {"fingerprint": disk, "sizeBytes": 4096, "format": "unified", "source": "fetch"},
        "restore": {"offloadId": "off-1", "seq": 1, "fingerprint": disk},
        "launchMode": "new_root",
        "lease":sandbox_protocol::HostLease::for_test()}))
    .unwrap();
    journal
        .record_intent(&crate::sandbox_relay::journal::intent_from_dispatch(
            &journal, &binding, &restore,
        ))
        .unwrap();
    journal.accept_fixture_lease(&restore).unwrap();
    assert_eq!(
        journal.lease(SBX).unwrap().restore_base.as_deref(),
        Some(disk.as_str())
    );
    let disks = JournalDisks::new(journal.clone(), Arc::new(runtime.clone()));
    let proof = disks
        .discard(&discard_frame(
            "restore-1",
            &disk,
            &request.template_digest,
            &pool,
        ))
        .expect("the restored copy discards");
    assert_eq!(proof.state, sandbox_protocol::RootState::Absent);
    assert!(runtime.query_sandbox(SBX, None, None).unwrap().is_none());
    let lease = journal.lease(SBX).unwrap();
    assert!(
        lease.instance_absent && lease.root_deleted,
        "the reservation is released"
    );
}

/// C9 live: a stale copy of a restored lineage (§7 N1) carries the disk
/// image as its base image while its tag is the template. The discard binds
/// with the server's template revision; the restore hint is the journaled
/// restore base when the lease records one, else the copy row's base. A
/// template lineage (base == template) never takes a hint.
#[test]
fn a_discard_takes_the_copy_rows_base_as_hint_only_without_a_journaled_one() {
    use super::evict::discard_server_hint;
    let template = format!("sha256:{}", "a".repeat(64));
    let disk = format!("sha256:{}", "d".repeat(64));
    let other = format!("sha256:{}", "e".repeat(64));
    assert_eq!(
        discard_server_hint(None, &disk, &template),
        Some(disk.as_str())
    );
    assert_eq!(discard_server_hint(None, &template, &template), None);
    assert_eq!(discard_server_hint(Some(&disk), &disk, &template), None);
    // A journaled base never yields to the server's: the bind refuses.
    assert_eq!(discard_server_hint(Some(&other), &disk, &template), None);
}

/// Review repro (offload impl1, P2 at offload_evict.rs discard): a restored
/// copy (`volatile.base_image` = disk image, `restore_base` tag written by
/// create, template tag = template) on a host whose journal has NO lease
/// record for it. The server's discard {createKey, baseFingerprint = restore
/// base, template} binds it from runtime metadata, deletes it and proves the
/// root absent; a wrong create key, base or template is refused with the VM
/// untouched. The copy row's hint never outlives the discard.
#[test]
fn review_repro_a_restored_copy_without_a_lease_record_discards_by_runtime_metadata() {
    use sandbox_runtime::SandboxRuntime as _;
    let dir = tempfile::tempdir().unwrap();
    let binding = crate::sandbox_relay::journal::TransportBindingV11 {
        server: "wss://offload.test/ws/sandbox-host".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    };
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    let runtime = FakeRuntime::new();
    let pool = runtime.initialize_storage_pool("primary", None).unwrap();
    let root = sandbox_runtime::RootDisk {
        pool: pool.clone(),
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .unwrap()
            .disk_gi_b_default,
    };
    let mut request = sandbox_runtime::CreateSandboxRequest::for_test(SBX, "restore-key");
    let disk = runtime.seed_image_bytes(
        b"stored disk",
        request.architecture.as_deref().unwrap_or("x86_64"),
        false,
    );
    request.restore = Some(sandbox_runtime::RestoreLaunch {
        fingerprint: disk.clone(),
        cloud_init_instance_id: None,
    });
    runtime.create_sandbox_on_storage(&request, &root).unwrap();
    assert_eq!(runtime.restore_base(SBX).as_deref(), Some(disk.as_str()));
    assert!(journal.lease(SBX).is_none(), "no lease record");
    let template = request.template_digest.clone();
    let other = format!("sha256:{}", "e".repeat(64));
    let disks = JournalDisks::new(journal, Arc::new(runtime.clone()));

    for (key, base, tmpl) in [
        ("other-key", disk.as_str(), template.as_str()),
        ("restore-key", other.as_str(), template.as_str()),
        ("restore-key", disk.as_str(), other.as_str()),
    ] {
        assert_eq!(
            disks
                .discard(&discard_frame(key, base, tmpl, &pool))
                .unwrap_err(),
            "binding_mismatch",
            "key={key} base={base} template={tmpl}"
        );
        assert!(runtime.query_sandbox(SBX, None, None).unwrap().is_some());
        assert_eq!(runtime.bound_restore_base(SBX), None, "hint released");
    }

    let proof = disks
        .discard(&discard_frame("restore-key", &disk, &template, &pool))
        .expect("the restored copy discards without a lease record");
    assert_eq!(proof.state, sandbox_protocol::RootState::Absent);
    assert!(runtime.query_sandbox(SBX, None, None).unwrap().is_none());
    assert!(runtime.prove_root_absent(&root, INSTANCE).is_ok());
    assert_eq!(runtime.bound_restore_base(SBX), None, "hint released");
}

/// A discard of the copy also ends an unfinished (`uploaded`,
/// ack missed) entry with its alias image, export, staging and reservation,
/// not only a stored one.
#[test]
fn a_discard_also_cleans_an_uploaded_entry() {
    let f = fixture();
    let disks = Arc::new(FakeDisks::default());
    disks.discard_ok.store(true, Ordering::SeqCst);
    f.offload.install_local_disks(disks);
    uploaded_with_staging(&f, "off-6");
    f.offload
        .handle_server(ServerControlMessage::DiskDiscard(discard_frame(
            "create-1",
            &format!("sha256:{}", "cd".repeat(32)),
            &format!("sha256:{}", "cd".repeat(32)),
            &sandbox_runtime::StoragePoolIdentity {
                name: "default".into(),
                storage_id: "a".repeat(32),
            },
        )));
    let (frame, _) = wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskDiscarded(_))
    });
    let DaemonControlMessage::DiskDiscarded(answer) = frame else {
        unreachable!()
    };
    assert!(answer.root_absence_proof.is_some());
    wait_until("uploaded entry cleaned", || local_gone(&f, "off-6"));
}

#[test]
fn a_discard_answers_with_its_proof_or_its_refusal() {
    let (f, _disks) = stored_fixture();
    f.offload
        .handle_server(ServerControlMessage::DiskDiscard(discard_frame(
            "create-1",
            &format!("sha256:{}", "cd".repeat(32)),
            &format!("sha256:{}", "cd".repeat(32)),
            &sandbox_runtime::StoragePoolIdentity {
                name: "default".into(),
                storage_id: "a".repeat(32),
            },
        )));
    let (frame, _) = wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskDiscarded(_))
    });
    let DaemonControlMessage::DiskDiscarded(answer) = frame else {
        unreachable!()
    };
    assert_eq!(answer.copy_id, "copy-1");
    assert_eq!(answer.code.as_deref(), Some("binding_mismatch"));
    assert!(answer.root_absence_proof.is_none());
}

/// A cached cold reconnect (`expectDisk`) runs only on the
/// retained root stored as that offload: the journaled `stored` entry of
/// that seq and fingerprint, with `last_used_at` unchanged since the offload.
/// Otherwise `disk_stale`, refused in the Intent phase without starting.
/// A restore accepted here drops the entry (T16).
#[test]
fn expect_disk_holds_only_for_the_unchanged_stored_copy_and_a_restore_drops_it() {
    use crate::sandbox_relay::supervisor::{DISK_STALE, expect_disk_holds, restore_intent};
    let f = fixture();
    let fp = format!("sha256:{}", "d".repeat(64));
    let mut stored = entry(OffloadPhase::Stored, "off-1");
    stored.staged_sha256 = Some("d".repeat(64));
    stored.last_used_at = f.runtime.instance_last_used(INSTANCE).unwrap();
    assert!(stored.last_used_at.is_some());
    let expect = |seq: u64, fingerprint: &str| sandbox_protocol::DispatchExpectDiskV11 {
        seq,
        fingerprint: fingerprint.into(),
    };
    let holds = |f: &Fixture, e: &sandbox_protocol::DispatchExpectDiskV11| {
        expect_disk_holds(&f.runtime, &f.offload, SBX, INSTANCE, e)
    };
    assert!(!holds(&f, &expect(1, &fp)), "no entry: stale");
    seed_entry(&f, stored.clone());
    assert!(holds(&f, &expect(1, &fp)));
    assert!(!holds(&f, &expect(2, &fp)), "another seq");
    assert!(!holds(
        &f,
        &expect(1, &format!("sha256:{}", "e".repeat(64)))
    ));
    seed_entry(
        &f,
        OffloadEntry {
            last_used_at: Some("booted-since".into()),
            ..stored.clone()
        },
    );
    assert!(
        !holds(&f, &expect(1, &fp)),
        "the root ran since the offload"
    );
    seed_entry(
        &f,
        OffloadEntry {
            phase: OffloadPhase::Evicting,
            ..stored.clone()
        },
    );
    assert!(!holds(&f, &expect(1, &fp)), "an evicting copy");
    // The Intent-phase refusal is `disk_stale`, without any start.
    let d: sandbox_protocol::OperationDispatch = serde_json::from_value(serde_json::json!({
        "sandboxOwnerId":"owner", "operationId":"cold", "sandboxId":SBX,
        "kind":"sandbox.reconnect", "generation":4, "attempt":1,
        "idempotencyKey":"cold", "bodyHash":"a".repeat(64),
        "launchMode":"cold", "expectDisk": {"seq": 1, "fingerprint": fp}}))
    .unwrap();
    let refusal = restore_intent(
        &f.runtime,
        Some(&f.images),
        Some(&f.offload),
        &d,
        INSTANCE,
        &|| true,
    )
    .unwrap_err();
    assert_eq!(refusal.message, DISK_STALE);
    seed_entry(&f, stored.clone());
    restore_intent(
        &f.runtime,
        Some(&f.images),
        Some(&f.offload),
        &d,
        INSTANCE,
        &|| true,
    )
    .expect("the unchanged stored copy resumes");
    f.offload.forget_on_restore(SBX);
    assert!(
        f.offload.entry(SBX).is_none(),
        "T16: dropped on restore accept"
    );
}

/// A socket stream whose writes are buffered by tungstenite and whose flush
/// fails (the relay connection died under a batch).
struct FlushFails;

impl std::io::Read for FlushFails {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl std::io::Write for FlushFails {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// Fix 4 (r4 #3): the disk parts and completion of a finished upload were in
/// an image batch whose flush failed, after the server had taken them (its
/// offload is verifying). They are not replayed on the next connection, so
/// no stale cancel answers a repeated completion (as the server would, the
/// test plays it for any) and the `uploaded` journal entry, its alias and
/// staging are kept until the stored ack stores it.
#[test]
fn a_disk_completion_in_a_failed_batch_is_not_replayed_and_the_entry_is_kept() {
    let f = fixture();
    f.offload.handle_server(request("off-1"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let begin = begin_of(&begin).unwrap().clone();
    let (url, seen) = s3(1);
    f.offload
        .handle_server(grant("off-1", "ses-1", &url, begin.size_bytes, KEY));
    seen.join().unwrap();
    wait_until("uploaded and the job over", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Uploaded)
            && f.offload.lock_jobs().active.is_empty()
    });
    let queued = f.images.queued();
    assert!(
        queued
            .iter()
            .any(|m| matches!(m, DaemonControlMessage::DiskUploadComplete(_))),
        "{queued:?}"
    );
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        FlushFails,
        tungstenite::protocol::Role::Client,
        None,
    );
    assert!(
        crate::sandbox_relay::connect::send_image_batch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &f.images,
        )
        .is_err()
    );
    f.images.on_disconnect();
    f.images.on_registered("host-owner");
    let replayed = f.images.drain();
    assert!(
        replayed.iter().all(|m| !matches!(
            m,
            DaemonControlMessage::DiskUploadParts(_) | DaemonControlMessage::DiskUploadComplete(_)
        )),
        "{replayed:?}"
    );
    for frame in &replayed {
        if matches!(frame, DaemonControlMessage::DiskUploadComplete(_)) {
            f.offload.handle_server(cancel("off-1", "stale"));
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploaded);
    assert!(f.runtime.alias_target(&al("off-1")).is_some());
    f.offload
        .handle_server(stored_ack("off-1", &begin.fingerprint));
    wait_for_frame(&f.images, |m| released_of(m) == Some("off-1"));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
}

/// Fix 5 (r5 #2): the finished upload's parts fill the last slot of an image
/// batch whose write fails and its completion is queued behind it. On the
/// next connection the completion (an older connection's continuation) is
/// purged, not sent unbound; and a `stale` answer to a completion (as the
/// server gives one that reached a newer connection) keeps the `uploaded`
/// entry, its alias and staging, and asks for the verdict: the stored ack
/// still settles the offload.
#[test]
fn a_queued_disk_completion_across_a_reconnect_is_purged_and_a_stale_answer_keeps_the_entry() {
    let f = fixture();
    f.offload.handle_server(request("off-1"));
    let (begin, _) = wait_for_frame(&f.images, |m| begin_of(m).is_some());
    let begin = begin_of(&begin).unwrap().clone();
    let filler = |i: usize| {
        DaemonControlMessage::DiskOffloadReleased(DiskOffloadReleasedV11 {
            sandbox_id: format!("sbx-filler-{i}"),
            offload_id: format!("off-filler-{i}"),
            seq: 1,
        })
    };
    for i in 0..31 {
        f.images.push_frame(filler(i));
    }
    let (url, seen) = s3(1);
    f.offload
        .handle_server(grant("off-1", "ses-1", &url, begin.size_bytes, KEY));
    seen.join().unwrap();
    wait_until("uploaded and the job over", || {
        f.offload
            .entry(SBX)
            .is_some_and(|e| e.phase == OffloadPhase::Uploaded)
            && f.offload.lock_jobs().active.is_empty()
    });
    let queued = f.images.queued();
    let complete = queued
        .iter()
        .position(|m| matches!(m, DaemonControlMessage::DiskUploadComplete(_)))
        .expect("completion queued");
    assert!(complete >= 32, "beyond the first batch: {queued:?}");
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        FlushFails,
        tungstenite::protocol::Role::Client,
        None,
    );
    assert!(
        crate::sandbox_relay::connect::send_image_batch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &f.images,
        )
        .is_err()
    );
    assert!(
        f.images
            .queued()
            .iter()
            .any(|m| matches!(m, DaemonControlMessage::DiskUploadComplete(_))),
        "the completion was behind the failed batch"
    );
    f.images.on_disconnect();
    f.images.on_registered("host-owner");
    let sent = f.images.drain();
    assert!(
        sent.iter().all(|m| !matches!(
            m,
            DaemonControlMessage::DiskUploadParts(_) | DaemonControlMessage::DiskUploadComplete(_)
        )),
        "{sent:?}"
    );
    // A stale answer to a completion: the entry stays, the verdict is asked.
    f.offload.handle_server(cancel("off-1", "stale"));
    let (verdict, _) = wait_for_frame(&f.images, |m| {
        matches!(m, DaemonControlMessage::DiskOffloadInventory(i)
            if i.entries.iter().any(|e| e.offload_id == "off-1"))
    });
    assert!(matches!(
        verdict,
        DaemonControlMessage::DiskOffloadInventory(_)
    ));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Uploaded);
    assert!(f.runtime.alias_target(&al("off-1")).is_some());
    f.offload
        .handle_server(stored_ack("off-1", &begin.fingerprint));
    wait_for_frame(&f.images, |m| released_of(m) == Some("off-1"));
    assert_eq!(f.offload.entry(SBX).unwrap().phase, OffloadPhase::Stored);
}

/// Fix 5 (r5 #1): an older connection's disk inventory page still queued is
/// purged when the next connection starts its inventory.
#[test]
fn an_old_disk_inventory_page_is_purged_by_the_next_inventory() {
    let f = fixture();
    f.images
        .push_frame(DaemonControlMessage::DiskOffloadInventory(
            DiskOffloadInventoryV11 {
                entries: vec![DiskOffloadInventoryEntryV11 {
                    sandbox_id: "sbx-old".into(),
                    offload_id: "off-old".into(),
                    seq: 1,
                }],
            },
        ));
    f.images.on_disconnect();
    f.images.on_registered("host-owner");
    f.offload.begin_inventory();
    let frames = f.images.drain();
    assert!(
        frames.iter().all(
            |m| !matches!(m, DaemonControlMessage::DiskOffloadInventory(i)
            if i.entries.iter().any(|e| e.offload_id == "off-old"))
        ),
        "{frames:?}"
    );
}
