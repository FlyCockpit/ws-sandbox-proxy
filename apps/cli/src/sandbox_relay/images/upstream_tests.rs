//! Community bases (D-B, I3): the daemon's own download of a raw upstream
//! split image, against loopback responders standing in for the fixed host
//! and `FakeRuntime` (which validates like Incus). No network, no Incus.

use super::*;

/// A ustar entry (enough for a metadata tarball).
fn tar_entry(out: &mut Vec<u8>, name: &str, typeflag: u8, data: &[u8]) {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    h[136..147].copy_from_slice(b"15000000000");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

/// `incus.tar.xz` holding `metadata` (system `xz`; `None` without it).
fn meta_file(metadata: &str) -> Option<Vec<u8>> {
    let mut tar = Vec::new();
    tar_entry(&mut tar, "metadata.yaml", b'0', metadata.as_bytes());
    tar_entry(&mut tar, "templates/", b'5', b"");
    tar_entry(&mut tar, "templates/hostname.tpl", b'0', b"{{ name }}\n");
    tar.extend_from_slice(&[0u8; 1024]);
    // Synchronous `xz` over a scratch file (no async child in tests).
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("incus.tar");
    std::fs::write(&path, &tar).ok()?;
    let out = std::process::Command::new("xz")
        .args(["-c", "-0"])
        .arg(&path)
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

const METADATA: &str = "architecture: x86_64\ncreation_date: 1700000000\nproperties:\n  os: Ubuntu\n  release: resolute\n  variant: cloud\n";

/// `disk.qcow2`: a qcow2 v3 header declaring `virtual_size`.
fn disk_file(virtual_size: u64) -> Vec<u8> {
    let mut q = vec![0u8; 4096];
    q[..4].copy_from_slice(b"QFI\xfb");
    q[4..8].copy_from_slice(&3u32.to_be_bytes());
    q[20..24].copy_from_slice(&16u32.to_be_bytes());
    q[24..32].copy_from_slice(&virtual_size.to_be_bytes());
    q[96..100].copy_from_slice(&4u32.to_be_bytes());
    q[100..104].copy_from_slice(&112u32.to_be_bytes());
    q
}

const DIR: &str = "images/ubuntu/resolute/amd64/cloud/20261105_07:42";

/// A bootstrap build create carrying the upstream plan for `meta`/`disk`.
fn upstream_dispatch(meta: &[u8], disk: &[u8], owner: &str) -> OperationDispatch {
    let combined = [meta, disk].concat();
    let plan = sandbox_protocol::DispatchUpstreamImageV11 {
        meta_path: format!("{DIR}/incus.tar.xz"),
        meta_sha256: sha256_hex(meta),
        meta_size: meta.len() as u64,
        disk_path: format!("{DIR}/disk.qcow2"),
        disk_sha256: sha256_hex(disk),
        disk_size: disk.len() as u64,
    };
    let mut d = dispatch(
        &format!("sha256:{}", sha256_hex(&combined)),
        combined.len() as u64,
        owner,
    );
    let image = d.image.as_mut().unwrap();
    image.format = "split".into();
    image.source = "upstream".into();
    image.upstream = Some(plan);
    d.build = Some(sandbox_protocol::DispatchBuildV11 {
        build_id: "build-1".into(),
        bootstrap: true,
    });
    assert!(image_valid(&d), "the fixture is a valid wire plan");
    d
}

fn image_valid(d: &OperationDispatch) -> bool {
    d.image.as_ref().is_some_and(|image| image.is_valid())
}

fn fp_of(d: &OperationDispatch) -> String {
    d.image.as_ref().unwrap().fingerprint.clone()
}

/// A service whose upstream host is `base` (a loopback responder).
fn upstream_service(runtime: &FakeRuntime, dir: &Path, base: &str) -> ImageService {
    let images = service(
        runtime,
        dir,
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    images.set_upstream_for_test(&format!("{base}/"), upstream_agent_config().into());
    images
}

fn ok(body: &[u8]) -> Response {
    (200, vec![], body.to_vec())
}

#[test]
fn an_upstream_image_is_verified_imported_and_reported_cached() {
    let Some(meta) = meta_file(METADATA) else {
        return;
    };
    let disk = disk_file(1 << 30);
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, server) = responder(vec![ok(&meta), ok(&disk)]);
    let images = upstream_service(&runtime, dir.path(), &base);
    let d = upstream_dispatch(&meta, &disk, "host-owner");
    let fp = fp_of(&d);
    images.ensure_image(&d, &|| true).expect("upstream import");
    assert!(runtime.has_image(&fp));
    assert_eq!(runtime.split_imports(), 1);
    let DaemonControlMessage::ImageCached(cached) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageCached(_))
    }) else {
        unreachable!()
    };
    assert_eq!(cached.fingerprint, fp);
    assert_eq!(cached.origin, sandbox_protocol::ImageOrigin::Fetched);
    assert_eq!(cached.operation_id.as_deref(), Some("op-1"));
    assert_eq!(cached.image_owner_id, "host-owner");
    assert_eq!(cached.compressed_bytes, (meta.len() + disk.len()) as u64);
    assert_eq!(images.entries()[0].origin, Origin::Fetched);
    let seen = server.join().unwrap();
    assert!(seen[0].0.starts_with(&format!("GET /{DIR}/incus.tar.xz ")));
    assert!(seen[1].0.starts_with(&format!("GET /{DIR}/disk.qcow2 ")));
    for (head, _) in &seen {
        let head = head.to_ascii_lowercase();
        assert!(!head.contains("authorization") && !head.contains("range"));
    }
    // Staging is gone; the reservations were released.
    assert_eq!(std::fs::read_dir(&images.inner.staging).unwrap().count(), 0);
    assert!(images.inner.reserved.lock().unwrap().is_empty());
}

#[test]
fn staging_keys_are_distinct_per_file_and_from_a_unified_fetch() {
    let fp = format!("sha256:{}", "e".repeat(64));
    let (meta, disk) = upstream_staging_keys(&fp);
    let unified = format!("{}.part", "e".repeat(64));
    assert_ne!(meta, disk);
    assert!(meta != unified && disk != unified);
    // Both reservations are held at once by one job.
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = upstream_service(&runtime, dir.path(), "http://127.0.0.1:9");
    let _a = images.reserve(&meta, 10).unwrap();
    let _b = images.reserve(&disk, 10).unwrap();
    let _c = images.reserve(&unified, 10).unwrap();
}

#[test]
fn a_sha_mismatch_is_corrupt_and_never_imported() {
    let Some(meta) = meta_file(METADATA) else {
        return;
    };
    let disk = disk_file(1 << 30);
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let mut tampered = disk.clone();
    tampered[4095] ^= 1;
    let (base, _server) = responder(vec![ok(&meta), ok(&tampered)]);
    let images = upstream_service(&runtime, dir.path(), &base);
    let d = upstream_dispatch(&meta, &disk, "host-owner");
    let error = images.ensure_image(&d, &|| true).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::ImageCorrupt);
    assert_eq!(runtime.split_imports(), 0);
    assert!(!runtime.has_image(&fp_of(&d)));
    assert!(images.entries().is_empty());
}

#[test]
fn upstream_404_and_410_are_image_unavailable() {
    for status in [404u16, 410] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, server) = responder(vec![(status, vec![], Vec::new())]);
        let images = upstream_service(&runtime, dir.path(), &base);
        let meta = b"m".repeat(64);
        let disk = disk_file(1 << 30);
        let error = images
            .ensure_image(&upstream_dispatch(&meta, &disk, "host-owner"), &|| true)
            .unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::ImageUnavailable, "{status}");
        // Not retried: the one response was the only request.
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

/// The agent never follows a redirect, whatever the pinned host answers.
#[test]
fn a_redirect_is_refused_and_never_followed() {
    let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
    elsewhere.set_nonblocking(true).unwrap();
    let target = format!("http://{}/stolen", elsewhere.local_addr().unwrap());
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, server) = responder(vec![(302, vec![("Location", target)], Vec::new())]);
    let images = upstream_service(&runtime, dir.path(), &base);
    let error = images
        .ensure_image(
            &upstream_dispatch(&b"m".repeat(64), &disk_file(1 << 30), "host-owner"),
            &|| true,
        )
        .unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::ImageUnavailable);
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(
        elsewhere.accept().is_err(),
        "the redirect target was contacted"
    );
}

/// A resumed file asks for its remaining range; a `200` (range ignored)
/// restarts the file from byte 0 instead of appending the whole body, and
/// an exact `206` appends.
#[test]
fn a_range_answered_with_200_restarts_the_file() {
    let Some(meta) = meta_file(METADATA) else {
        return;
    };
    let disk = disk_file(1 << 30);
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let d = upstream_dispatch(&meta, &disk, "host-owner");
    let (meta_key, disk_key) = upstream_staging_keys(&fp_of(&d));
    let half = disk.len() / 2;
    let range = format!("bytes {half}-{}/{}", disk.len() - 1, disk.len());
    let (base, server) = responder(vec![
        ok(&meta),
        (206, vec![("Content-Range", range)], disk[half..].to_vec()),
    ]);
    let images = upstream_service(&runtime, dir.path(), &base);
    // Stale garbage for the metadata, a true prefix of the disk.
    std::fs::write(images.inner.staging.join(&meta_key), b"stale bytes").unwrap();
    std::fs::write(images.inner.staging.join(&disk_key), &disk[..half]).unwrap();
    images.ensure_image(&d, &|| true).expect("resumed import");
    assert_eq!(runtime.split_imports(), 1);
    let seen = server.join().unwrap();
    let head = |i: usize| seen[i].0.to_ascii_lowercase();
    assert!(head(0).contains("range: bytes=11-"), "{}", head(0));
    assert!(
        head(1).contains(&format!("range: bytes={half}-")),
        "{}",
        head(1)
    );
}

/// I3: the disk's declared virtual size is bounded (32 GiB), and metadata
/// naming a refused property prefix (no exemption) is refused; neither is
/// imported.
#[test]
fn a_too_large_disk_or_refused_metadata_is_rejected_before_import() {
    let Some(good_meta) = meta_file(METADATA) else {
        return;
    };
    let Some(bad_meta) =
        meta_file("architecture: x86_64\nproperties:\n  security.secureboot: \"false\"\n")
    else {
        return;
    };
    for (meta, disk) in [
        (
            good_meta,
            disk_file(sandbox_runtime::SPLIT_VIRTUAL_SIZE_MAX + 1),
        ),
        (bad_meta, disk_file(1 << 30)),
    ] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, _server) = responder(vec![ok(&meta), ok(&disk)]);
        let images = upstream_service(&runtime, dir.path(), &base);
        let d = upstream_dispatch(&meta, &disk, "host-owner");
        let error = images.ensure_image(&d, &|| true).unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::ImageRejected);
        assert_eq!(runtime.split_imports(), 0);
        assert!(!runtime.has_image(&fp_of(&d)));
        assert_eq!(std::fs::read_dir(&images.inner.staging).unwrap().count(), 0);
    }
}

/// The protocol caps the disk at 4 GiB; a larger pin never parses.
#[test]
fn a_disk_over_4_gib_is_refused_at_the_wire() {
    let d = upstream_dispatch(&b"m".repeat(64), &disk_file(1 << 30), "host-owner");
    let mut image = d.image.clone().unwrap();
    let upstream = image.upstream.as_mut().unwrap();
    upstream.disk_size = sandbox_protocol::UPSTREAM_DISK_MAX_BYTES + 1;
    image.size_bytes = upstream.meta_size + upstream.disk_size;
    assert!(!image.is_valid());
    upstream_dispatch(&b"m".repeat(64), &disk_file(1 << 30), "host-owner");
}

/// Single flight: concurrent creates of the same upstream image download
/// and import it once.
#[test]
fn concurrent_creates_download_the_upstream_image_once() {
    let Some(meta) = meta_file(METADATA) else {
        return;
    };
    let disk = disk_file(1 << 30);
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, server) = responder(vec![ok(&meta), ok(&disk)]);
    let images = upstream_service(&runtime, dir.path(), &base);
    let d = upstream_dispatch(&meta, &disk, "host-owner");
    let fetches: Vec<_> = (0..3).map(|_| run_fetch(&images, d.clone())).collect();
    for fetch in fetches {
        fetch.join().unwrap().expect("each create has the image");
    }
    assert_eq!(runtime.split_imports(), 1);
    assert_eq!(server.join().unwrap().len(), 2, "one download");
}

/// B3 applies to upstream fetches too: another account's community build
/// on a host that refuses foreign images never downloads.
#[test]
fn the_foreign_gate_refuses_an_upstream_fetch_before_any_request() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let images = upstream_service(&runtime, dir.path(), &base);
    let error = images
        .ensure_image(
            &upstream_dispatch(&b"m".repeat(64), &disk_file(1 << 30), "someone-else"),
            &|| true,
        )
        .unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::ImageRejected);
    assert!(
        listener.accept().is_err(),
        "a foreign fetch reached upstream"
    );
}

/// The total budget bounds a GET in flight: a host that trickles
/// one byte at a time never trips the idle read timeout, yet the fetch ends
/// at its deadline as image_fetch_timeout instead of holding the cache
/// reservation and the per-fingerprint lock for the whole trickle.
#[test]
fn a_trickling_upstream_is_cut_off_at_the_fetch_deadline() {
    use std::io::{Read as _, Write as _};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        // Every attempt: a full Content-Length, then one byte per 250 ms for
        // 6 s, then the connection closes short.
        listener.set_nonblocking(false).unwrap();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(20) {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut head = [0u8; 4096];
            let _ = stream.read(&mut head);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n",
            );
            for _ in 0..24 {
                if stream.write_all(b"m").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    });
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = upstream_service(&runtime, dir.path(), &base);
    images.set_upstream_budget_for_test(Duration::from_secs(1));
    let started = Instant::now();
    let error = images
        .ensure_image(
            &upstream_dispatch(&b"m".repeat(100_000), &disk_file(1 << 30), "host-owner"),
            &|| true,
        )
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error.code, SandboxErrorCode::ImageFetchTimeout, "{error:?}");
    assert!(
        elapsed < Duration::from_secs(4),
        "the fetch outlived its budget: {elapsed:?}"
    );
    drop(server);
}

/// The split (upstream) import: a guard refusal at import
/// stays the typed guard outage.
#[test]
fn an_upstream_import_refused_by_the_shared_server_fence_stays_a_guard_outage() {
    let Some(meta) = meta_file(METADATA) else {
        return;
    };
    let disk = disk_file(1 << 30);
    let (runtime, _) = super::shared_runtime_after(true, 1);
    let dir = tempfile::tempdir().unwrap();
    let (base, _server) = responder(vec![ok(&meta), ok(&disk)]);
    let images = upstream_service(&runtime, dir.path(), &base);
    let d = upstream_dispatch(&meta, &disk, "host-owner");
    let fp = fp_of(&d);
    let err = images
        .ensure_image(&d, &|| true)
        .expect_err("import refused");
    super::assert_guard_outage(&err);
    assert!(!runtime.has_image(&fp));
    assert_eq!(runtime.split_imports(), 0);
}
