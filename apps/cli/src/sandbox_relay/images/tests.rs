//! FakeRuntime + loopback HTTP tests for the image cache (no Incus, no
//! network beyond 127.0.0.1). The S3 store and the server relay are tiny
//! fixed responders; the control plane is played by the test thread.

use super::*;
use sandbox_runtime::FakeRuntime;
use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;

const GIB: u64 = 1 << 30;

/// Upload retry and renew timings of every test service: the production
/// shape with pauses short enough for a test. A renew waits 30 s per try (a
/// test answers in milliseconds, so it is never re-sent by accident, even on
/// a slow machine); tests of the re-send set their own.
const FAST_TIMINGS: UploadTimings = UploadTimings {
    part_retry: [Duration::from_millis(10); 3],
    begin_retry: [Duration::from_millis(20); 4],
    begin_budget: Duration::from_secs(30),
    renew_retry: [Duration::from_secs(30); 4],
    url_margin: Duration::from_secs(60),
    flush_every: Duration::from_secs(30),
};

type Response = (u16, Vec<(&'static str, String)>, Vec<u8>);
type Seen = std::thread::JoinHandle<Vec<(String, Vec<u8>)>>;

fn service(
    runtime: &FakeRuntime,
    dir: &Path,
    size: crate::config::ImageCacheSize,
    base: &str,
) -> ImageService {
    service_with(runtime, dir, size, base, false)
}

fn service_with(
    runtime: &FakeRuntime,
    dir: &Path,
    size: crate::config::ImageCacheSize,
    base: &str,
    accept_foreign: bool,
) -> ImageService {
    let service = ImageService::start(
        Arc::new(runtime.clone()),
        dir,
        ImageSettings {
            size,
            accept_foreign,
            foreign_grace: Duration::from_secs(600),
            builder: true,
            accept_foreign_builds: false,
        },
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into(),
        base,
        "wssp_host_test-secret",
    )
    .expect("start")
    .expect("enabled");
    service.on_registered("host-owner");
    service.set_upload_timings_for_test(FAST_TIMINGS);
    service
}

fn dispatch(fp: &str, size: u64, owner: &str) -> OperationDispatch {
    serde_json::from_value(serde_json::json!({
        "sandboxOwnerId": owner, "operationId": "op-1", "sandboxId": "sbx-1",
        "idempotencyKey": "k", "kind": "sandbox.create", "generation": 1, "attempt": 1,
        "architecture": "x86_64",
        "image": {"fingerprint": fp, "sizeBytes": size, "format": "unified", "source": "fetch"},
    }))
    .expect("dispatch")
}

/// Serve `responses` (status, headers, body) to successive requests; returns
/// the base URL and the captured request heads and bodies.
fn responder(responses: Vec<Response>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, headers, body) in responses {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut head = String::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("line");
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut request_body = vec![0u8; length];
            reader.read_exact(&mut request_body).expect("body");
            seen.push((head, request_body));
            let mut stream = stream;
            let mut text = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (k, v) in headers {
                text.push_str(&format!("{k}: {v}\r\n"));
            }
            text.push_str("\r\n");
            stream.write_all(text.as_bytes()).expect("write");
            stream.write_all(&body).expect("write body");
        }
        seen
    });
    (base, handle)
}

fn wait_frame(
    service: &ImageService,
    pred: impl Fn(&DaemonControlMessage) -> bool,
) -> DaemonControlMessage {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        for frame in service.drain() {
            if pred(&frame) {
                return frame;
            }
        }
        assert!(Instant::now() < deadline, "frame never sent");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn s3_grant(request_id: &str, size: u64, url: &str, key: Option<&str>) -> ServerControlMessage {
    ServerControlMessage::ImageFetchGrant(sandbox_protocol::ImageFetchGrantV11 {
        request_id: request_id.into(),
        transfer_id: "tr-1".into(),
        mode: ImageTransferMode::S3,
        size_bytes: size,
        part_size: 64 << 20,
        expires_at_unix_ms: 1,
        url: Some(url.into()),
        links: None,
        encryption: key.map(|key| sandbox_protocol::ImageEncryptionV11 {
            scheme: sandbox_protocol::IMAGE_ENCRYPTION_SCHEME.into(),
            key: key.into(),
        }),
    })
}

fn run_fetch(
    service: &ImageService,
    d: OperationDispatch,
) -> std::thread::JoinHandle<Result<(), ImageError>> {
    let service = service.clone();
    std::thread::spawn(move || service.ensure_image(&d, &|| true))
}

#[test]
fn s3_fetch_verifies_imports_journals_and_reports_cached() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let image = b"unified image tarball".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let (base, server) = responder(vec![(200, vec![], image.clone())]);
    // A host that opted in to foreign images.
    let images = service_with(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
        true,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "owner-a"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    assert_eq!(request.resume_offset, 0);
    images.handle_server(s3_grant(
        &request.request_id,
        image.len() as u64,
        &format!("{base}/obj?X-Amz-Signature=sig"),
        None,
    ));
    fetch.join().unwrap().expect("fetched");
    assert!(runtime.has_image(&fp));
    let cached = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageCached(_))
    });
    let DaemonControlMessage::ImageCached(cached) = cached else {
        unreachable!()
    };
    assert_eq!(cached.operation_id.as_deref(), Some("op-1"));
    assert_eq!(
        cached.totals.foreign_bytes,
        image.len() as u64,
        "owner-a is foreign here"
    );
    assert_eq!(images.entries().len(), 1);
    let seen = server.join().unwrap();
    assert!(seen[0].0.starts_with("GET /obj?"));
    assert!(
        !seen[0].0.to_ascii_lowercase().contains("authorization"),
        "no host secret to S3"
    );
}

/// B3: with `accept_foreign_images = false` the daemon itself refuses another
/// account's image before any fetch or import, whatever the server planned,
/// and a daemon that does not yet know its host owner fails closed.
#[test]
fn foreign_image_is_refused_locally_when_not_accepted() {
    for registered in [true, false] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let image = b"unified image tarball".to_vec();
        let fp = format!("sha256:{}", sha256_hex(&image));
        let images = ImageService::start(
            Arc::new(runtime.clone()),
            dir.path(),
            ImageSettings {
                size: crate::config::ImageCacheSize::Gib(1),
                accept_foreign: false,
                foreign_grace: Duration::from_secs(600),
                builder: true,
                accept_foreign_builds: false,
            },
            ureq::Agent::config_builder().build().into(),
            "http://127.0.0.1:9",
            "wssp_host_test-secret",
        )
        .unwrap()
        .unwrap();
        if registered {
            images.on_registered("host-owner");
        }
        let owner = if registered { "owner-a" } else { "host-owner" };
        let error = images
            .ensure_image(&dispatch(&fp, image.len() as u64, owner), &|| true)
            .unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::ImageRejected, "{registered}");
        assert!(!runtime.has_image(&fp));
        assert!(images.entries().is_empty());
        assert!(
            !images
                .drain()
                .iter()
                .any(|f| matches!(f, DaemonControlMessage::ImageFetchRequest(_))),
            "no fetch was requested"
        );
    }
}

#[test]
fn encrypted_s3_object_is_decrypted_by_records_before_hashing() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let image = vec![7u8; crypto::RECORD + 10];
    let fp = format!("sha256:{}", sha256_hex(&image));
    let key_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let key = crypto::RecordKey::from_base64(key_b64).unwrap();
    let mut sealed = key.seal(0, false, &image[..crypto::RECORD]).unwrap();
    sealed.extend(key.seal(1, true, &image[crypto::RECORD..]).unwrap());
    let (base, server) = responder(vec![(200, vec![], sealed)]);
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "host-owner"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    images.handle_server(s3_grant(
        &request.request_id,
        image.len() as u64,
        &format!("{base}/o"),
        Some(key_b64),
    ));
    fetch.join().unwrap().expect("decrypted fetch");
    assert!(runtime.has_image(&fp));
    server.join().unwrap();
}

#[test]
fn corrupt_download_is_refused_and_never_imported() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let image = b"real bytes".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let (base, server) = responder(vec![(200, vec![], b"evil bytes".to_vec())]);
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "host-owner"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    images.handle_server(s3_grant(
        &request.request_id,
        image.len() as u64,
        &format!("{base}/o"),
        None,
    ));
    let error = fetch.join().unwrap().expect_err("corrupt");
    assert_eq!(error.code, SandboxErrorCode::ImageCorrupt);
    assert!(!runtime.has_image(&fp));
    assert!(images.entries().is_empty());
    server.join().unwrap();
}

#[test]
fn refused_grant_maps_to_image_unavailable() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let fp = format!("sha256:{}", "d".repeat(64));
    let fetch = run_fetch(&images, dispatch(&fp, 10, "host-owner"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    images.handle_server(ServerControlMessage::ImageFetchRefused(
        sandbox_protocol::ImageFetchRefusedV11 {
            request_id: request.request_id,
            code: "image_unavailable".into(),
        },
    ));
    assert_eq!(
        fetch.join().unwrap().unwrap_err().code,
        SandboxErrorCode::ImageUnavailable
    );
}

#[test]
fn relay_fetch_acks_each_part_with_its_hash() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let image = b"relayed image bytes".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let sha = sha256_hex(&image);
    let (base, server) = responder(vec![(
        200,
        vec![("X-Wssp-Part-Sha256", sha.clone())],
        image.clone(),
    )]);
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "host-owner"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    images.handle_server(ServerControlMessage::ImageFetchGrant(
        sandbox_protocol::ImageFetchGrantV11 {
            request_id: request.request_id,
            transfer_id: "tr-9".into(),
            mode: ImageTransferMode::Relay,
            size_bytes: image.len() as u64,
            part_size: sandbox_protocol::IMAGE_RELAY_PART_BYTES,
            expires_at_unix_ms: 1,
            url: None,
            links: Some(vec![ImageRelayLinkV11 {
                part: 1,
                link_id: "link-1".into(),
                token: "T".repeat(43),
            }]),
            encryption: None,
        },
    ));
    fetch.join().unwrap().expect("relay fetch");
    let ack = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImagePartAck(_))
    });
    let DaemonControlMessage::ImagePartAck(ack) = ack else {
        unreachable!()
    };
    assert_eq!((ack.part, ack.sha256.as_str()), (1, sha.as_str()));
    let seen = server.join().unwrap();
    let head = seen[0].0.to_ascii_lowercase();
    assert!(
        head.starts_with("get /host/image-relay/v1/parts/link-1 "),
        "{head}"
    );
    assert!(
        head.contains("x-wssp-image-link: tttt"),
        "token travels in a header"
    );
    assert!(
        head.contains("authorization: bearer wssp_host_"),
        "host credential required too"
    );
}

#[test]
fn lru_never_evicts_pinned_in_use_or_protected_images() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let old = runtime.seed_image_bytes(b"old", "x86_64", false);
    let pinned = runtime.seed_image_bytes(b"pinned", "x86_64", false);
    let aliased = runtime.seed_image_bytes(b"aliased", "x86_64", true);
    images.record(&old, "o", GIB / 2, Origin::Fetched, false);
    images.record(&pinned, "o", GIB / 4, Origin::Captured, true);
    images.record(&aliased, "o", GIB / 8, Origin::Fetched, false);
    images.mark_in_use(&aliased, 1);
    // Needs room for 0.5 GiB: only `old` may go.
    images.make_room(GIB / 2).expect("room");
    assert!(!runtime.has_image(&old));
    assert!(runtime.has_image(&pinned) && runtime.has_image(&aliased));
    let evicted = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageEvicted(_))
    });
    assert!(matches!(evicted, DaemonControlMessage::ImageEvicted(e) if e.fingerprint == old));
    // Nothing else may go: full.
    assert_eq!(
        images.make_room(GIB).unwrap_err().code,
        SandboxErrorCode::ImageCacheFull
    );
    images.mark_in_use(&aliased, -1);
    // An aliased (operator) image is protected: it stops being managed, never deleted.
    assert_eq!(images.prune(false), Vec::<String>::new());
    assert!(runtime.has_image(&aliased));
    // The origin pin goes only on the server's release.
    images.release(&pinned, "o", ImageReleaseReason::Stored);
    assert_eq!(images.prune(false), vec![pinned.clone()]);
    assert!(!runtime.has_image(&pinned));
}

#[test]
fn census_pages_are_bounded_and_ack_driven() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4096),
        "http://127.0.0.1:9",
    );
    for n in 0..300u32 {
        let fp = format!("sha256:{}", sha256_hex(&n.to_be_bytes()));
        images.record(&fp, "host-owner", 1, Origin::Fetched, false);
    }
    images.begin_census();
    let first = images.drain();
    let [DaemonControlMessage::ImageCacheCensus(page)] = first.as_slice() else {
        panic!("{first:?}")
    };
    assert_eq!(
        (page.page, page.complete, page.entries.len()),
        (0, false, 256)
    );
    assert!(images.drain().is_empty(), "next page waits for the ack");
    images.handle_server(ServerControlMessage::ImageCacheCensusAck(
        sandbox_protocol::ImageCacheCensusAckV11 { page: 0 },
    ));
    let second = images.drain();
    let [DaemonControlMessage::ImageCacheCensus(page)] = second.as_slice() else {
        panic!()
    };
    assert_eq!(
        (page.page, page.complete, page.entries.len()),
        (1, true, 44)
    );
}

#[test]
fn serve_exports_a_unified_image_and_puts_each_linked_part() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"served unified image".to_vec();
    let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
    let (base, server) = responder(vec![(204, vec![], Vec::new())]);
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
    );
    images.serve(sandbox_protocol::ImageServeRequestV11 {
        transfer_id: "tr-2".into(),
        image_owner_id: "host-owner".into(),
        fingerprint: fp,
        size_bytes: bytes.len() as u64,
        part_size: sandbox_protocol::IMAGE_RELAY_PART_BYTES,
        links: vec![ImageRelayLinkV11 {
            part: 1,
            link_id: "l-1".into(),
            token: "U".repeat(43),
        }],
    });
    let seen = server.join().unwrap();
    assert!(seen[0].0.starts_with("PUT /host/image-relay/v1/parts/l-1 "));
    assert_eq!(seen[0].1, bytes);
    assert!(
        images
            .drain()
            .iter()
            .all(|f| !matches!(f, DaemonControlMessage::ImageJobFailed(_)))
    );
}

#[test]
fn disabled_cache_starts_nothing_and_advertises_no_capability() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let started = ImageService::start(
        Arc::new(runtime),
        dir.path(),
        ImageSettings {
            size: crate::config::ImageCacheSize::Gib(0),
            accept_foreign: false,
            foreign_grace: Duration::ZERO,
            builder: true,
            accept_foreign_builds: false,
        },
        ureq::Agent::new_with_defaults(),
        "http://127.0.0.1:9",
        "secret",
    )
    .unwrap();
    assert!(started.is_none());
}

#[test]
fn image_error_text_never_carries_a_url() {
    // HTTP failures map to fixed messages: a presigned URL cannot leak.
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let fp = format!("sha256:{}", "e".repeat(64));
    let fetch = run_fetch(&images, dispatch(&fp, 10, "host-owner"));
    for _ in 0..FETCH_ATTEMPTS {
        let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
            matches!(f, DaemonControlMessage::ImageFetchRequest(_))
        }) else {
            unreachable!()
        };
        images.handle_server(s3_grant(
            &request.request_id,
            10,
            "http://127.0.0.1:9/x?X-Amz-Signature=secret",
            None,
        ));
    }
    let error = fetch.join().unwrap().unwrap_err();
    assert!(!error.message.contains("X-Amz-Signature") && !error.message.contains("http"));
}

/// P1-4: staging occupies the cache budget. An abandoned `.part` (an
/// interrupted download) counts until the TTL sweep removes it; reservations
/// are taken before any write and serialize the last headroom.
#[test]
fn staging_and_reservations_count_against_the_cap_and_abandoned_staging_is_swept() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    // A sparse 0.75 GiB abandoned download.
    let staging = dir.path().join("images").join("staging");
    let abandoned = staging.join(format!("{}.part", "a".repeat(64)));
    std::fs::File::create(&abandoned)
        .unwrap()
        .set_len(3 * GIB / 4)
        .unwrap();
    assert_eq!(images.charged_bytes(), 3 * GIB / 4);
    assert!(images.totals().used_bytes >= 3 * GIB / 4);
    assert_eq!(
        images.reserve("next.part", GIB / 2).err().map(|e| e.code),
        Some(SandboxErrorCode::ImageCacheFull)
    );
    // Not yet stale: the sweep keeps a resumable download.
    assert_eq!(images.sweep_staging(), 0);
    assert_eq!(images.sweep_staging_older_than(Duration::ZERO), 1);
    assert!(!abandoned.exists());
    // Reservations: two jobs cannot both take the last half.
    let first = images.reserve("one.part", GIB / 2 + 1).expect("first fits");
    assert_eq!(
        images.reserve("two.part", GIB / 2).err().map(|e| e.code),
        Some(SandboxErrorCode::ImageCacheFull)
    );
    // A reserved entry is never swept, even past the TTL.
    std::fs::write(staging.join("one.part"), b"x").unwrap();
    assert_eq!(images.sweep_staging_older_than(Duration::ZERO), 0);
    drop(first);
    images
        .reserve("two.part", GIB / 2)
        .expect("fits once released");
}

/// P1-4: a captured image is admitted like any other: LRU images make room,
/// and when nothing can, the published image is deleted and the capture fails.
#[test]
fn captures_go_through_make_room() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let old = runtime.seed_image_bytes(b"old", "x86_64", false);
    images.record(&old, "o", GIB / 2, Origin::Fetched, false);
    let first = runtime.seed_image_bytes(b"capture-1", "x86_64", false);
    let d = dispatch(&first, GIB / 2 + 1, "o");
    images
        .captured(&d, &first, GIB / 2 + 1, false)
        .expect("evicts the LRU image");
    assert!(!runtime.has_image(&old));
    // Only the pinned capture remains: a second that cannot fit is refused.
    let second = runtime.seed_image_bytes(b"capture-2", "x86_64", false);
    assert_eq!(
        images
            .captured(&d, &second, GIB / 2 + 1, false)
            .unwrap_err()
            .code,
        SandboxErrorCode::ImageCacheFull
    );
    assert!(
        !runtime.has_image(&second),
        "the unadmitted capture is deleted"
    );
    assert!(runtime.has_image(&first));
}

/// Round-2 P2-9: a download cut short (the S3 response ends before its
/// declared length) ends the abandoned grant with `image.fetch.failed`
/// before the retry asks for a new one, and the retry resumes by Range. The
/// control plane is played like the server: a repeat request while the
/// previous grant is still open is refused as `in_progress`.
#[test]
fn truncated_download_ends_its_grant_before_the_retry_resumes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    // Downloads are written in 1 MiB chunks: the cut lands mid-chunk, so the
    // first MiB is kept and the retry resumes from there.
    let image: Vec<u8> = (0..(3u32 << 20)).map(|i| (i % 251) as u8).collect();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let half = 1usize << 20;
    let cut = half + (half / 2);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let body = image.clone();
    let store = std::thread::spawn(move || {
        let mut heads = Vec::new();
        for round in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("line");
                head.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut stream = stream;
            if round == 0 {
                // Declares the whole object, sends half, then hangs up.
                let text = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(text.as_bytes()).expect("write");
                stream.write_all(&body[..cut]).expect("write part");
            } else {
                let from = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("range: bytes=")?
                            .strip_suffix('-')?
                            .parse()
                            .ok()
                    })
                    .unwrap_or(0usize);
                let rest = &body[from..];
                let text = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    rest.len()
                );
                stream.write_all(text.as_bytes()).expect("write");
                stream.write_all(rest).expect("write rest");
            }
            heads.push(head);
        }
        heads
    });
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "host-owner"));
    let mut frames = Vec::new();
    let mut open: Option<String> = None;
    let mut grants = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !fetch.is_finished() {
        assert!(Instant::now() < deadline, "fetch never finished");
        for frame in images.drain() {
            match &frame {
                DaemonControlMessage::ImageFetchRequest(request) => {
                    if open.is_some() {
                        images.handle_server(ServerControlMessage::ImageFetchRefused(
                            sandbox_protocol::ImageFetchRefusedV11 {
                                request_id: request.request_id.clone(),
                                code: "in_progress".into(),
                            },
                        ));
                    } else {
                        grants += 1;
                        let transfer = format!("tr-{grants}");
                        let ServerControlMessage::ImageFetchGrant(mut grant) = s3_grant(
                            &request.request_id,
                            image.len() as u64,
                            &format!("{base}/o"),
                            None,
                        ) else {
                            unreachable!()
                        };
                        grant.transfer_id = transfer.clone();
                        open = Some(transfer);
                        images.handle_server(ServerControlMessage::ImageFetchGrant(grant));
                    }
                }
                DaemonControlMessage::ImageFetchFailed(failed) if failed.transfer_id == open => {
                    open = None;
                }
                _ => {}
            }
            frames.push(frame);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    fetch
        .join()
        .unwrap()
        .expect("the retry resumed and completed");
    assert!(runtime.has_image(&fp));
    let kinds: Vec<String> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageFetchRequest(r) => {
                Some(format!("request@{}", r.resume_offset))
            }
            DaemonControlMessage::ImageFetchFailed(f) => Some(format!(
                "failed:{}:{:?}",
                f.transfer_id.as_deref().unwrap_or("-"),
                f.code
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "request@0".to_owned(),
            "failed:tr-1:Io".to_owned(),
            format!("request@{half}"),
        ]
    );
    let heads = store.join().unwrap();
    assert!(
        heads[1]
            .to_ascii_lowercase()
            .contains(&format!("range: bytes={half}-")),
        "the retry resumes by Range"
    );
}

/// Round-2 P2-5: two concurrent exports of one image hold separate
/// reservations and directories: neither overwrites the other's charge, and
/// finishing one never releases the other's charge or removes its files.
#[test]
fn concurrent_exports_hold_separate_reservations_and_directories() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let bytes = vec![5u8; 4096];
    let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let reserved = |images: &ImageService| -> u64 {
        images
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .sum()
    };
    let (first_path, _, first) = images.export_unified(&fp).expect("first export");
    let (second_path, _, second) = images.export_unified(&fp).expect("second export");
    assert_ne!(
        first_path.parent(),
        second_path.parent(),
        "one directory per job"
    );
    assert_eq!(
        reserved(&images),
        2 * bytes.len() as u64,
        "both charges held"
    );
    drop(first);
    assert!(
        !first_path.exists(),
        "a finished export removes its own files"
    );
    assert!(second_path.exists(), "and never another job's");
    assert_eq!(reserved(&images), bytes.len() as u64);
    // Staging is still charged for the live export.
    assert!(images.charged_bytes() >= bytes.len() as u64);
    drop(second);
    assert!(!second_path.exists());
    assert_eq!(reserved(&images), 0);
    // A held key is never overwritten by a second reservation.
    let held = images.reserve("job.part", 10).expect("first");
    assert_eq!(
        images.reserve("job.part", 1).err().map(|e| e.code),
        Some(SandboxErrorCode::Transport)
    );
    assert_eq!(reserved(&images), 10);
    drop(held);
    assert_eq!(reserved(&images), 0);
}

/// Two owners' captures uploading at once (round-3 P2-4): returns the
/// service, each capture's begin request id and its image bytes.
fn two_pending_capture_uploads(
    runtime: &FakeRuntime,
    dir: &Path,
    base: &str,
) -> (ImageService, [(String, Vec<u8>); 2]) {
    let images = service(runtime, dir, crate::config::ImageCacheSize::Gib(1), base);
    let mut out = Vec::new();
    for (owner, op) in [("owner-a", "op-a"), ("owner-b", "op-b")] {
        let bytes = format!("captured image of {owner}").into_bytes();
        let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
        let mut d = dispatch(&fp, bytes.len() as u64, owner);
        d.operation_id = op.into();
        d.attempt = 3;
        images
            .captured(&d, &fp, bytes.len() as u64, true)
            .expect("captured");
        let begin = wait_frame(
            &images,
            |f| matches!(f, DaemonControlMessage::ImageUploadBegin(b) if b.operation_id.as_deref() == Some(op)),
        );
        let DaemonControlMessage::ImageUploadBegin(begin) = begin else {
            unreachable!()
        };
        // The begin names its originating attempt and its own request id.
        assert_eq!(begin.attempt, Some(3));
        let request = begin.request_id.expect("capture request id");
        out.push((request, bytes));
    }
    let [a, b]: [(String, Vec<u8>); 2] = out.try_into().expect("two captures");
    (images, [a, b])
}

fn capture_grant(request: &str, transfer: &str, url: String, size: u64) -> ServerControlMessage {
    ServerControlMessage::ImageUploadGrant(sandbox_protocol::ImageUploadGrantV11 {
        transfer_id: transfer.into(),
        request_id: Some(request.into()),
        part_size: 64 << 20,
        parts: vec![sandbox_protocol::ImageUploadPartUrlV11 {
            n: 1,
            url,
            size_bytes: size,
        }],
        expires_at_unix_ms: 1,
        ttl_seconds: 600,
        encryption: None,
    })
}

fn wait_complete(images: &ImageService, transfer: &str) {
    wait_frame(
        images,
        |f| matches!(f, DaemonControlMessage::ImageUploadComplete(r) if r.transfer_id == transfer),
    );
}

/// Round-3 P2-4: each capture's first grant reaches only the capture whose
/// begin it answers, whatever order the grants arrive in.
#[test]
fn concurrent_capture_uploads_each_receive_only_their_own_grant() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let ok = || (200, vec![("ETag", "\"e\"".to_owned())], Vec::new());
    let (base, server) = responder(vec![ok(), ok()]);
    let (images, [(req_a, bytes_a), (req_b, bytes_b)]) =
        two_pending_capture_uploads(&runtime, dir.path(), &base);
    // B's grant arrives first, then A's.
    images.handle_server(capture_grant(
        &req_b,
        "tr-b",
        format!("{base}/b"),
        bytes_b.len() as u64,
    ));
    wait_complete(&images, "tr-b");
    images.handle_server(capture_grant(
        &req_a,
        "tr-a",
        format!("{base}/a"),
        bytes_a.len() as u64,
    ));
    wait_complete(&images, "tr-a");
    let seen = server.join().unwrap();
    assert!(seen[0].0.starts_with("PUT /b "), "{}", seen[0].0);
    assert_eq!(seen[0].1, bytes_b);
    assert!(seen[1].0.starts_with("PUT /a "), "{}", seen[1].0);
    assert_eq!(seen[1].1, bytes_a);
}

/// Round-3 P2-4: refusing one capture's begin stops only that capture.
#[test]
fn a_refused_capture_begin_cancels_only_its_own_upload() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, server) = responder(vec![(200, vec![("ETag", "\"e\"".to_owned())], Vec::new())]);
    let (images, [(req_a, _), (req_b, bytes_b)]) =
        two_pending_capture_uploads(&runtime, dir.path(), &base);
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "none".into(),
            reason: "stale_capture".into(),
            request_id: Some(req_a.clone()),
        },
    ));
    // A grant naming the cancelled request reaches nobody.
    images.handle_server(capture_grant(&req_a, "tr-a", format!("{base}/a"), 1));
    images.handle_server(capture_grant(
        &req_b,
        "tr-b",
        format!("{base}/b"),
        bytes_b.len() as u64,
    ));
    wait_complete(&images, "tr-b");
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].0.starts_with("PUT /b "), "{}", seen[0].0);
    assert_eq!(seen[0].1, bytes_b);
}

fn evictions(frames: &[DaemonControlMessage]) -> Vec<(String, String, ImageEvictReason)> {
    let mut out: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageEvicted(e) => {
                Some((e.fingerprint.clone(), e.image_owner_id.clone(), e.reason))
            }
            _ => None,
        })
        .collect();
    out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out
}

#[test]
fn reconcile_drops_images_deleted_out_of_band_but_never_one_in_use() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4),
        "http://127.0.0.1:9",
    );
    let captured = runtime.seed_image_bytes(b"captured", "x86_64", false);
    let fetched = runtime.seed_image_bytes(b"fetched", "x86_64", false);
    let busy = runtime.seed_image_bytes(b"busy", "x86_64", false);
    let kept = runtime.seed_image_bytes(b"kept", "x86_64", false);
    images.record(&captured, "host-owner", 10, Origin::Captured, true);
    images.record(&fetched, "a", 20, Origin::Fetched, false);
    images.record(&fetched, "b", 20, Origin::Fetched, false);
    images.record(&busy, "host-owner", 30, Origin::Fetched, false);
    images.record(&kept, "host-owner", 40, Origin::Fetched, false);
    // `incus image delete <hex>` behind the daemon's back; `busy` is mid-use
    // (a fetch, serve or upload holds it).
    for fp in [&captured, &fetched, &busy] {
        runtime.delete_image(fp).unwrap();
    }
    images.mark_in_use(&busy, 1);
    assert_eq!(images.reconcile_inventory(), Some(2));
    let mut left: Vec<String> = images
        .entries()
        .into_iter()
        .map(|e| e.fingerprint)
        .collect();
    left.sort();
    let mut expected = vec![busy.clone(), kept.clone()];
    expected.sort();
    assert_eq!(left, expected);
    // The journal on disk (what `wssp host images list` reads) agrees.
    let reopened = CacheJournal::open(&dir.path().join("images")).unwrap();
    assert_eq!(reopened.file.entries.len(), 2);
    let frames = images.drain();
    let mut want = vec![
        (
            captured.clone(),
            "host-owner".to_owned(),
            ImageEvictReason::Operator,
        ),
        (fetched.clone(), "a".to_owned(), ImageEvictReason::Operator),
        (fetched.clone(), "b".to_owned(), ImageEvictReason::Operator),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(evictions(&frames), want);
    // A reconcile that dropped entries refreshes the server's census.
    let census = frames
        .iter()
        .find_map(|f| match f {
            DaemonControlMessage::ImageCacheCensus(c) => Some(c.clone()),
            _ => None,
        })
        .expect("census after a dropping reconcile");
    assert!(census.complete);
    assert_eq!(census.entries.len(), 2);
    // Nothing more to drop: no frames, no census.
    images.mark_in_use(&busy, -1);
    images.handle_server(ServerControlMessage::ImageCacheCensusAck(
        sandbox_protocol::ImageCacheCensusAckV11 { page: 0 },
    ));
    assert_eq!(images.reconcile_inventory(), Some(1));
    assert_eq!(
        evictions(&images.drain()),
        vec![(busy, "host-owner".to_owned(), ImageEvictReason::Operator)]
    );
}

#[test]
fn reconcile_never_drops_an_image_recorded_while_the_inventory_was_read() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4),
        "http://127.0.0.1:9",
    );
    let gone = runtime.seed_image_bytes(b"gone", "x86_64", false);
    images.record(&gone, "host-owner", 10, Origin::Fetched, false);
    runtime.delete_image(&gone).unwrap();
    // A fetch re-imports and re-records it after the journal snapshot but
    // before the drop: the changed entry is not the one judged absent.
    let snapshot = images.inventory_candidates();
    let fresh = images.reconcile_with(snapshot.clone(), Default::default());
    assert_eq!(fresh, 1);
    images.record(&gone, "host-owner", 10, Origin::Fetched, false);
    std::thread::sleep(Duration::from_millis(2));
    images.record(&gone, "host-owner", 11, Origin::Fetched, false);
    assert_eq!(images.reconcile_with(snapshot, Default::default()), 0);
    assert_eq!(images.entries().len(), 1);
}

#[test]
fn reconcile_skips_when_the_inventory_cannot_be_read() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4),
        "http://127.0.0.1:9",
    );
    let fp = runtime.seed_image_bytes(b"present", "x86_64", false);
    images.record(&fp, "host-owner", 10, Origin::Captured, true);
    runtime.fail_image_inventory(true);
    assert_eq!(images.reconcile_inventory(), None);
    assert_eq!(images.entries().len(), 1);
    assert!(images.drain().is_empty(), "an error is never absence");
}

#[test]
fn periodic_census_never_clobbers_one_in_flight() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4096),
        "http://127.0.0.1:9",
    );
    for n in 0..300u32 {
        let fp = format!("sha256:{}", sha256_hex(&n.to_be_bytes()));
        images.record(&fp, "host-owner", 1, Origin::Fetched, false);
    }
    let ack = |page| {
        ServerControlMessage::ImageCacheCensusAck(sandbox_protocol::ImageCacheCensusAckV11 { page })
    };
    images.begin_census();
    assert_eq!(images.drain().len(), 1);
    // Page 1 still queued: a periodic census waits.
    assert!(!images.begin_periodic_census());
    assert!(images.drain().is_empty());
    images.handle_server(ack(0));
    let second = images.drain();
    let [DaemonControlMessage::ImageCacheCensus(last)] = second.as_slice() else {
        panic!("second page")
    };
    assert!(last.complete && last.page == 1);
    // The complete page is not acknowledged yet: still in flight.
    assert!(!images.begin_periodic_census());
    assert!(images.drain().is_empty());
    images.handle_server(ack(1));
    assert!(images.begin_periodic_census());
    let fresh = images.drain();
    let [DaemonControlMessage::ImageCacheCensus(first)] = fresh.as_slice() else {
        panic!("a fresh census")
    };
    assert_eq!((first.page, first.complete), (0, false));
}

#[test]
fn list_request_is_answered_after_a_reconcile() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(4),
        "http://127.0.0.1:9",
    );
    let fp = runtime.seed_image_bytes(b"gone", "x86_64", false);
    images.record(&fp, "host-owner", 10, Origin::Captured, true);
    runtime.delete_image(&fp).unwrap();
    let journal_dir = dir.path().join("images");
    std::fs::write(journal_dir.join(LIST_REQUEST_FILE), "{}").unwrap();
    images.poll_list_request();
    assert!(!journal_dir.join(LIST_REQUEST_FILE).exists());
    let deadline = Instant::now() + Duration::from_secs(10);
    let bytes = loop {
        if let Ok(bytes) = std::fs::read(journal_dir.join(LIST_RESULT_FILE)) {
            break bytes;
        }
        assert!(Instant::now() < deadline, "list request never answered");
        std::thread::sleep(Duration::from_millis(10));
    };
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["reconciled"], true);
    assert_eq!(result["dropped"], 1);
    let reopened = CacheJournal::open(&journal_dir).unwrap();
    assert!(reopened.file.entries.is_empty());
}

#[test]
fn relay_part_send_budget_scales_with_the_part_above_a_floor() {
    assert_eq!(relay_part_send_budget(0), RELAY_PART_SEND_MIN);
    assert_eq!(relay_part_send_budget(1), RELAY_PART_SEND_MIN);
    // 120 s at 64 KiB/s is 7.5 MiB: up to there the floor wins.
    assert_eq!(relay_part_send_budget(120 * 64 * 1024), RELAY_PART_SEND_MIN);
    assert_eq!(
        relay_part_send_budget(120 * 64 * 1024 + 1),
        Duration::from_secs(121)
    );
    // A full 32 MiB part gets 512 s, i.e. it survives a ~0.5 Mbit/s link.
    assert_eq!(
        relay_part_send_budget(32 * 1024 * 1024),
        Duration::from_secs(512)
    );
    assert!(
        relay_part_send_budget(usize::try_from(sandbox_protocol::IMAGE_RELAY_PART_BYTES).unwrap())
            >= Duration::from_secs(512)
    );
    assert!(relay_part_send_budget(usize::MAX) > RELAY_PART_SEND_MIN);
}

/// The idle bound of tests about frames and heartbeats, not stalls: far
/// above any plausible scheduling pause, so only a real defect fails them.
const FRAME_TEST_IDLE: Duration = Duration::from_secs(30);

/// A service whose image-store agent has the production idle bound shape
/// (`HTTP_IDLE`) but its own `idle` (short for a stall test, so it stays
/// fast; `FRAME_TEST_IDLE` otherwise).
fn idle_service(runtime: &FakeRuntime, dir: &Path, base: &str, idle: Duration) -> ImageService {
    let service = ImageService::start(
        Arc::new(runtime.clone()),
        dir,
        ImageSettings {
            size: crate::config::ImageCacheSize::Gib(1),
            accept_foreign: false,
            foreign_grace: Duration::from_secs(600),
            builder: true,
            accept_foreign_builds: false,
        },
        crate::tls::Trust::http_agent_from(None, upstream_agent_config(), idle),
        base,
        "wssp_host_test-secret",
    )
    .expect("start")
    .expect("enabled");
    service.on_registered("host-owner");
    service.set_upload_timings_for_test(FAST_TIMINGS);
    service
}

/// One fake S3 connection handled by `handle` (after the request head was
/// read); returns the base URL.
fn fake_s3(handle: impl FnOnce(BufReader<std::net::TcpStream>) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
        }
        handle(reader);
    });
    base
}

/// Start one capture upload of `bytes` (attempt 4); its begin request id.
fn start_capture_upload(images: &ImageService, runtime: &FakeRuntime, bytes: &[u8]) -> String {
    let fp = runtime.seed_image_bytes(bytes, "x86_64", true);
    let mut d = dispatch(&fp, bytes.len() as u64, "owner-a");
    d.operation_id = "op-up".into();
    d.attempt = 4;
    images
        .captured(&d, &fp, bytes.len() as u64, true)
        .expect("captured");
    let DaemonControlMessage::ImageUploadBegin(begin) = wait_frame(images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    }) else {
        unreachable!()
    };
    begin.request_id.expect("capture request id")
}

/// A grant of `parts` (`(n, url, size)`) answering capture begin `request`.
fn parts_grant(
    request: &str,
    transfer: &str,
    part_size: u64,
    parts: Vec<(u32, String, u64)>,
) -> ServerControlMessage {
    ServerControlMessage::ImageUploadGrant(sandbox_protocol::ImageUploadGrantV11 {
        transfer_id: transfer.into(),
        request_id: Some(request.into()),
        part_size,
        parts: parts
            .into_iter()
            .map(
                |(n, url, size_bytes)| sandbox_protocol::ImageUploadPartUrlV11 {
                    n,
                    url,
                    size_bytes,
                },
            )
            .collect(),
        expires_at_unix_ms: 1,
        ttl_seconds: 600,
        encryption: None,
    })
}

/// Waits until `n` upload jobs of `images` have returned (a watchdog well
/// past `FRAME_TEST_IDLE`, so a stall still ends as its own frame).
fn wait_uploads_finished(images: &ImageService, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while images.uploads_finished() < n {
        assert!(Instant::now() < deadline, "upload job never returned");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Every frame the upload sends until its job has returned (the begin, if
/// already drained by `start_capture_upload`, excluded).
fn upload_frames(images: &ImageService) -> Vec<DaemonControlMessage> {
    wait_uploads_finished(images, 1);
    images.drain()
}

/// The frame kinds that matter to an upload's end, in order.
fn upload_kinds(frames: &[DaemonControlMessage]) -> Vec<&'static str> {
    frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadBegin(_) => Some("begin"),
            DaemonControlMessage::ImageUploadParts(_) => Some("parts"),
            DaemonControlMessage::ImageUploadComplete(_) => Some("complete"),
            DaemonControlMessage::ImageJobFailed(_) => Some("failed"),
            _ => None,
        })
        .collect()
}

/// The upload protocol frames in order: `upload_kinds` plus renews and
/// resumes (heartbeats left out).
fn upload_sequence(frames: &[DaemonControlMessage]) -> Vec<&'static str> {
    frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadRenew(_) => Some("renew"),
            DaemonControlMessage::ImageJobResume(_) => Some("resume"),
            f => upload_kinds(std::slice::from_ref(f)).first().copied(),
        })
        .collect()
}

/// The one `image.job.failed` among `frames` (asserted valid).
fn the_failure(frames: &[DaemonControlMessage]) -> sandbox_protocol::ImageJobFailedV11 {
    let failed: Vec<_> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageJobFailed(failed) => Some(failed.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(failed.len(), 1, "{frames:?}");
    assert!(failed[0].is_valid(), "{:?}", failed[0]);
    failed[0].clone()
}

/// A scripted fake S3: on drop it stops accepting and joins its thread
/// (and so the handler running there), so no test leaves a listener behind.
struct S3Guard {
    stop: Arc<std::sync::atomic::AtomicBool>,
    addr: std::net::SocketAddr,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for S3Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A fake S3 that hands each successive connection, after its request head,
/// to `handle(index, path, reader, body_length)`; returns the base URL, the
/// number of connections accepted so far and the guard that stops it.
fn scripted_s3_paths(
    handle: impl Fn(usize, &str, BufReader<std::net::TcpStream>, usize) + Send + 'static,
) -> (String, Arc<std::sync::atomic::AtomicUsize>, S3Guard) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stopped.load(Ordering::SeqCst) {
                return;
            }
            let Ok(stream) = stream else { return };
            let index = seen.fetch_add(1, Ordering::SeqCst);
            let mut reader = BufReader::new(stream);
            let mut length = 0usize;
            let mut path = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if path.is_empty() {
                    path = line.split(' ').nth(1).unwrap_or_default().to_owned();
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            handle(index, &path, reader, length);
        }
    });
    (
        base,
        count,
        S3Guard {
            stop,
            addr,
            thread: Some(thread),
        },
    )
}

/// `scripted_s3_paths` for handlers that do not look at the path.
fn scripted_s3(
    handle: impl Fn(usize, BufReader<std::net::TcpStream>, usize) + Send + 'static,
) -> (String, Arc<std::sync::atomic::AtomicUsize>, S3Guard) {
    scripted_s3_paths(move |i, _, reader, length| handle(i, reader, length))
}

/// Read the whole body, then answer 200 with an ETag.
fn store_ok(mut reader: BufReader<std::net::TcpStream>, length: usize) {
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

/// Read the body at a paced rate (16 KiB every 20 ms), then answer 200.
fn store_paced(mut reader: BufReader<std::net::TcpStream>, length: usize) {
    let mut chunk = vec![0u8; 16 << 10];
    let mut read = 0;
    while read < length {
        let n = chunk.len().min(length - read);
        if reader.read_exact(&mut chunk[..n]).is_err() {
            return;
        }
        read += n;
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = reader.into_inner();
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

/// Read the whole body, then answer `status`.
fn store_status(mut reader: BufReader<std::net::TcpStream>, length: usize, status: u16) {
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let _ = stream.write_all(
        format!("HTTP/1.1 {status} No\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
}

/// Read 1 MiB of a longer body and close: unread data, so an RST.
fn store_reset(mut reader: BufReader<std::net::TcpStream>) {
    let mut some = vec![0u8; 1 << 20];
    let _ = reader.read_exact(&mut some);
}

/// Sockets a stalling store holds open, unread, until the test ends.
type Held = Arc<Mutex<Vec<BufReader<std::net::TcpStream>>>>;

/// The grants a `FakeControl` issued, so a fake S3 refuses a URL as S3
/// would: one of a superseded grant, or past its TTL. The store's clock is
/// `Instant::now`, or a service's virtual upload clock (`clock`), judged
/// when a request head arrives; every grant's URLs are distinct
/// (`/g<grant>/p<n>`).
#[derive(Default)]
struct UrlBook {
    /// When each grant was issued and its TTL (grant `g` at `g - 1`).
    grants: Vec<(Instant, u64)>,
    clock: Option<ImageService>,
}

type Book = Arc<Mutex<UrlBook>>;

impl UrlBook {
    fn now(&self) -> Instant {
        self.clock
            .as_ref()
            .map_or_else(Instant::now, ImageService::now)
    }

    fn issue(&mut self, ttl: u64) -> usize {
        let now = self.now();
        self.grants.push((now, ttl));
        self.grants.len()
    }

    /// The grant a part URL path (`/g<grant>/p<n>`) belongs to.
    fn grant_of(path: &str) -> Option<usize> {
        path.strip_prefix("/g")?.split('/').next()?.parse().ok()
    }

    /// Whether `path` is a URL of the latest grant, inside its TTL.
    fn valid(&self, path: &str) -> bool {
        let now = self.now();
        Self::grant_of(path).is_some_and(|g| {
            g == self.grants.len()
                && now.saturating_duration_since(self.grants[g - 1].0)
                    < Duration::from_secs(self.grants[g - 1].1)
        })
    }
}

/// A store that refuses (403) a URL its book does not hold valid, else
/// hands the request to `then`.
fn book_store(
    book: &Book,
    path: &str,
    reader: BufReader<std::net::TcpStream>,
    length: usize,
    then: impl FnOnce(BufReader<std::net::TcpStream>, usize),
) {
    if book.lock().unwrap().valid(path) {
        then(reader, length);
    } else {
        store_status(reader, length, 403);
    }
}

/// The control plane of one upload, played by the test: records reported
/// parts and answers every `image.upload.renew` with a grant from the
/// lowest unrecorded part (`ttl` seconds), like the server.
struct FakeControl<'a> {
    images: &'a ImageService,
    transfer: String,
    base: String,
    part_size: u64,
    stored: u64,
    ttl: u64,
    recorded: std::collections::BTreeSet<u32>,
    frames: Vec<DaemonControlMessage>,
    /// Part reports to drop unrecorded (as the server does over its budget).
    drop_reports: usize,
    /// Renews to leave unanswered (as the server does over its budget).
    drop_renews: usize,
    /// The grants issued (shared with a store that checks URLs).
    book: Book,
}

impl<'a> FakeControl<'a> {
    fn new(
        images: &'a ImageService,
        transfer: &str,
        base: &str,
        part_size: u64,
        stored: u64,
    ) -> Self {
        Self {
            images,
            transfer: transfer.into(),
            base: base.into(),
            part_size,
            stored,
            ttl: 600,
            recorded: std::collections::BTreeSet::new(),
            frames: Vec::new(),
            drop_reports: 0,
            drop_renews: 0,
            book: Book::default(),
        }
    }

    fn total(&self) -> u32 {
        self.stored.div_ceil(self.part_size).max(1) as u32
    }

    /// A grant of up to 64 parts from `from`.
    fn grant(&self, request: Option<&str>, from: u32) -> ServerControlMessage {
        let total = self.total();
        let grant = self.book.lock().unwrap().issue(self.ttl);
        let parts = (from..=total.min(from + 63))
            .map(|n| sandbox_protocol::ImageUploadPartUrlV11 {
                n,
                url: format!("{}/g{grant}/p{n}", self.base),
                size_bytes: (self.stored - u64::from(n - 1) * self.part_size).min(self.part_size),
            })
            .collect();
        ServerControlMessage::ImageUploadGrant(sandbox_protocol::ImageUploadGrantV11 {
            transfer_id: self.transfer.clone(),
            request_id: request.map(str::to_owned),
            part_size: self.part_size,
            parts,
            expires_at_unix_ms: 1,
            ttl_seconds: self.ttl,
            encryption: None,
        })
    }

    fn lowest_unrecorded(&self) -> u32 {
        (1..=self.total())
            .find(|n| !self.recorded.contains(n))
            .unwrap_or(self.total() + 1)
    }

    /// Serve the upload until its job has returned, calling `on` for every
    /// frame first; returns every frame the job sent (in order).
    fn run(
        &mut self,
        on: &mut dyn FnMut(&DaemonControlMessage, &ImageService),
    ) -> Vec<DaemonControlMessage> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let finished = self.images.uploads_finished() >= 1;
            let batch = self.images.drain();
            for frame in &batch {
                on(frame, self.images);
                match frame {
                    DaemonControlMessage::ImageUploadParts(_) if self.drop_reports > 0 => {
                        self.drop_reports -= 1;
                    }
                    DaemonControlMessage::ImageUploadParts(p) => {
                        assert_eq!(p.transfer_id, self.transfer);
                        self.recorded.extend(p.parts.iter().map(|p| p.n));
                    }
                    DaemonControlMessage::ImageUploadRenew(_) if self.drop_renews > 0 => {
                        self.drop_renews -= 1;
                    }
                    DaemonControlMessage::ImageUploadRenew(r) => {
                        assert_eq!(r.transfer_id, self.transfer);
                        let grant = self.grant(None, self.lowest_unrecorded());
                        self.images.handle_server(grant);
                    }
                    _ => {}
                }
            }
            let empty = batch.is_empty();
            self.frames.extend(batch);
            if finished && empty {
                return std::mem::take(&mut self.frames);
            }
            assert!(Instant::now() < deadline, "upload never finished");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn renews(frames: &[DaemonControlMessage]) -> usize {
    frames
        .iter()
        .filter(|f| matches!(f, DaemonControlMessage::ImageUploadRenew(_)))
        .count()
}

/// Consecutive heartbeats `(bytesSent, wireBytes)`: neither count goes
/// back, and at least one moved (the heartbeat rule).
fn advanced(w: &[(u64, u64)]) -> bool {
    w[0].0 <= w[1].0 && w[0].1 <= w[1].1 && w[0] != w[1]
}

fn no_hook() -> impl FnMut(&DaemonControlMessage, &ImageService) {
    |_, _| {}
}

/// Run one capture upload of `bytes` in parts of `part` against a store at
/// `base`; the test plays the control plane. Returns every frame sent.
fn run_capture(
    images: &ImageService,
    runtime: &FakeRuntime,
    base: &str,
    bytes: &[u8],
    part: u64,
    transfer: &str,
) -> Vec<DaemonControlMessage> {
    let request = start_capture_upload(images, runtime, bytes);
    let mut control = FakeControl::new(images, transfer, base, part, bytes.len() as u64);
    images.handle_server(control.grant(Some(&request), 1));
    control.run(&mut no_hook())
}

/// A store that accepts each PUT and then stops reading, four times: every
/// attempt stalls, and after exactly 4 attempts (`PART_ATTEMPTS`) the upload
/// ends `stalled` by its transfer. The store holds the sockets until the
/// client has failed (never a reset race).
#[test]
fn a_part_that_stalls_on_every_attempt_ends_stalled() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let held: Held = Arc::default();
    let keep = held.clone();
    let (base, connections, _s3) = scripted_s3(move |_, reader, _| {
        keep.lock().unwrap().push(reader);
    });
    let images = idle_service(&runtime, dir.path(), &base, Duration::from_millis(300));
    let bytes = vec![5u8; 32 << 20];
    let frames = run_capture(&images, &runtime, &base, &bytes, 32 << 20, "tr-stall");
    held.lock().unwrap().clear();
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-stall"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Stalled);
    assert_eq!(failed.code, ImageFailureCode::Timeout);
    assert_eq!(failed.part, Some(1));
    assert_eq!(connections.load(Ordering::SeqCst), 4);
}

/// A stalled first attempt is retried, and the retry completes the upload.
#[test]
fn a_stalled_attempt_is_retried_and_the_upload_completes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let held: Held = Arc::default();
    let keep = held.clone();
    let (base, connections, _s3) = scripted_s3(move |i, reader, length| match i {
        0 => keep.lock().unwrap().push(reader),
        _ => store_ok(reader, length),
    });
    // An idle bound far above any loopback hiccup: the retry moving 32 MiB
    // never looks stalled however loaded the machine is; only the held
    // first socket does (test#5).
    let images = idle_service(&runtime, dir.path(), &base, Duration::from_secs(5));
    let bytes = vec![5u8; 32 << 20];
    let frames = run_capture(&images, &runtime, &base, &bytes, 32 << 20, "tr-stall-ok");
    held.lock().unwrap().clear();
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// A store answering 503 is retried; one retry that gets 200 completes it.
#[test]
fn a_store_error_status_then_success_completes_with_one_retry() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, connections, _s3) = scripted_s3(|i, reader, length| match i {
        0 => store_status(reader, length, 503),
        _ => store_ok(reader, length),
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = b"captured image bytes".to_vec();
    let frames = run_capture(&images, &runtime, &base, &bytes, 1 << 20, "tr-503");
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// A store that keeps answering 503 ends the upload `http_status` with the
/// status after exactly 4 attempts; a 400 is never retried.
#[test]
fn a_store_error_status_is_reported_with_its_status_after_the_attempts() {
    for (status, attempts) in [(503u16, 4), (400, 1)] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, connections, _s3) =
            scripted_s3(move |_, reader, length| store_status(reader, length, status));
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        let bytes = b"captured image bytes".to_vec();
        let frames = run_capture(&images, &runtime, &base, &bytes, 1 << 20, "tr-status");
        assert_eq!(upload_kinds(&frames), ["failed"]);
        let failed = the_failure(&frames);
        assert_eq!(failed.transfer_id.as_deref(), Some("tr-status"));
        assert_eq!(
            failed.cause,
            sandbox_protocol::ImageFailureCause::HttpStatus
        );
        assert_eq!(failed.http_status, Some(status));
        assert_eq!(failed.part, Some(1));
        assert_eq!(connections.load(Ordering::SeqCst), attempts, "{status}");
    }
}

/// A connection closed mid-body is retried; the retry completes it.
#[test]
fn a_connection_closed_mid_body_is_retried_and_completes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, connections, _s3) = scripted_s3(|i, reader, length| match i {
        0 => store_reset(reader),
        _ => store_ok(reader, length),
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = vec![9u8; 32 << 20];
    let frames = run_capture(&images, &runtime, &base, &bytes, 32 << 20, "tr-reset-ok");
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// Four connections closed mid-body in a row end the upload `reset` after
/// exactly 4 attempts.
#[test]
fn four_resets_in_a_row_end_the_upload_reset() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, connections, _s3) = scripted_s3(|_, reader, _| store_reset(reader));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = vec![9u8; 32 << 20];
    let frames = run_capture(&images, &runtime, &base, &bytes, 32 << 20, "tr-reset");
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-reset"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Reset);
    assert_eq!(failed.part, Some(1));
    assert_eq!(connections.load(Ordering::SeqCst), 4);
}

/// A capture whose image cannot be exported reports it by its operation
/// and attempt (there is no transfer yet), cause `export`, and never begins.
#[test]
fn a_capture_export_failure_is_reported_by_operation() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    // Never seeded: the runtime cannot export it.
    let fp = format!("sha256:{}", "b".repeat(64));
    let mut d = dispatch(&fp, 10, "owner-a");
    d.operation_id = "op-export".into();
    d.attempt = 2;
    images.captured(&d, &fp, 10, true).expect("captured");
    let frames = upload_frames(&images);
    assert_eq!(
        upload_kinds(&frames),
        ["failed"],
        "nothing to upload, no begin"
    );
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id, None);
    assert_eq!(failed.operation_id.as_deref(), Some("op-export"));
    assert_eq!(failed.attempt, Some(2));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Export);
}

/// A begin the server refuses is reported by operation, cause `refused`
/// with the server's reason; `already_stored` is not a failure.
#[test]
fn a_refused_capture_begin_is_reported_with_the_refusal() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let request = start_capture_upload(&images, &runtime, b"quota image");
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "none".into(),
            reason: "image_quota_exceeded".into(),
            request_id: Some(request),
        },
    ));
    let frames = upload_frames(&images);
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.operation_id.as_deref(), Some("op-up"));
    assert_eq!(failed.attempt, Some(4));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
    assert_eq!(failed.refusal.as_deref(), Some("image_quota_exceeded"));

    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let request = start_capture_upload(&images, &runtime, b"stored image");
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "none".into(),
            reason: "already_stored".into(),
            request_id: Some(request),
        },
    ));
    // The job has returned: whatever it sent is in the outbox.
    let frames = upload_frames(&images);
    assert!(
        upload_kinds(&frames).is_empty(),
        "an already stored image is not a failure: {frames:?}"
    );
}

/// The server cancels the transfer while part 1 of 2 is in flight: the
/// upload stops before part 2 (no second PUT, no parts report, no
/// complete) and reports `refused` with the server's reason.
#[test]
fn a_server_cancel_between_parts_stops_before_the_next_part() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let (got_part, part_seen) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let (finished, done) = mpsc::channel::<()>();
    let store = std::thread::spawn(move || {
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
        reader.read_exact(&mut body).expect("part 1 body");
        got_part.send(()).unwrap();
        let _ = released.recv_timeout(Duration::from_secs(60));
        let mut stream = stream;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"e1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("respond");
        // After the job returned: was a second part ever attempted?
        let _ = done.recv_timeout(Duration::from_secs(60));
        listener.set_nonblocking(true).expect("nonblocking");
        listener.accept().is_ok()
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let part = 1u64 << 20;
    let bytes = vec![4u8; 2 << 20];
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(parts_grant(
        &request,
        "tr-cut",
        part,
        vec![
            (1, format!("{base}/p1"), part),
            (2, format!("{base}/p2"), part),
        ],
    ));
    part_seen
        .recv_timeout(Duration::from_secs(30))
        .expect("part 1 reached the store");
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "tr-cut".into(),
            reason: "upload_stalled".into(),
            request_id: None,
        },
    ));
    release.send(()).unwrap();
    let frames = upload_frames(&images);
    finished.send(()).unwrap();
    assert!(!store.join().unwrap(), "a second part was sent");
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-cut"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
    assert_eq!(failed.code, ImageFailureCode::Cancelled);
    assert_eq!(failed.refusal.as_deref(), Some("upload_stalled"));
}

/// No grant answers the begin: `no_grant`, by operation and attempt.
#[test]
fn a_capture_without_a_first_grant_reports_no_grant_by_operation() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    images.set_grant_wait_for_test(Duration::from_millis(200));
    // Started directly (not via `start_capture_upload`, whose begin wait
    // drains the outbox): the begin and the failure can be queued together,
    // so the whole sequence is collected once the job has returned.
    let bytes = b"never granted";
    let fp = runtime.seed_image_bytes(bytes, "x86_64", true);
    let mut d = dispatch(&fp, bytes.len() as u64, "owner-a");
    d.operation_id = "op-up".into();
    d.attempt = 4;
    images
        .captured(&d, &fp, bytes.len() as u64, true)
        .expect("captured");
    let frames = upload_frames(&images);
    assert_eq!(upload_kinds(&frames), ["begin", "failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id, None);
    assert_eq!(
        (failed.operation_id.as_deref(), failed.attempt),
        (Some("op-up"), Some(4))
    );
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
    assert_eq!(failed.code, ImageFailureCode::Timeout);
}

/// The next grant never arrives after part 1 of 2: its parts are reported,
/// then `no_grant` by the transfer the first grant named. The first grant
/// has a generous wait; only the continuation wait is short, set while the
/// store holds part 1's response, so no scheduling delay can end the first
/// wait before the test sends its grant.
#[test]
fn a_missing_next_grant_reports_no_grant_by_transfer() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let part = 1u64 << 20;
    let (got_part, part_seen) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let base = fake_s3(move |mut reader| {
        let mut body = vec![0u8; part as usize];
        reader.read_exact(&mut body).expect("part 1 body");
        got_part.send(()).unwrap();
        let _ = released.recv_timeout(Duration::from_secs(60));
        let mut stream = reader.into_inner();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"e1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("respond");
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_grant_wait_for_test(Duration::from_secs(30));
    let bytes = vec![6u8; 2 << 20];
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(parts_grant(
        &request,
        "tr-ng",
        part,
        vec![(1, format!("{base}/p1"), part)],
    ));
    part_seen
        .recv_timeout(Duration::from_secs(30))
        .expect("part 1 reached the store");
    // Read per grant wait, so this governs only the continuation.
    images.set_grant_wait_for_test(Duration::from_millis(300));
    release.send(()).unwrap();
    let frames = upload_frames(&images);
    assert_eq!(upload_kinds(&frames), ["parts", "failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-ng"));
    assert_eq!(failed.operation_id, None);
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
}

/// A moving upload completes and sends progress heartbeats with growing
/// offsets while it moves. The heartbeat interval is zero, so every advance
/// of the body sends one and the count depends on neither socket buffering
/// nor timing (throttling is covered by
/// `heartbeats_carry_the_offset_reached_and_only_when_it_moved`). Its idle
/// bound is `FRAME_TEST_IDLE`, so scheduler load cannot fake a stall; that
/// moving bytes never trip the bound however long the body takes is proven
/// on a fake clock in `tls::http`
/// (`idle_bound_below_tls_is_per_socket_write_not_an_aggregate`,
/// `idle_bound_wraps_only_the_raw_socket_under_proxy_tls`,
/// `idle_bound_never_fails_a_moving_body_read_and_fails_a_stopped_one`).
#[test]
fn a_moving_upload_sends_heartbeats_and_completes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    // Eight of the agent's 128 KiB body buffers: a handful of advances,
    // well inside the outbox.
    let bytes = vec![3u8; 1 << 20];
    let len = bytes.len();
    let base = fake_s3(move |mut reader| {
        let mut chunk = vec![0u8; 1 << 20];
        let mut read = 0;
        while read < len {
            reader.read_exact(&mut chunk).expect("body");
            read += chunk.len();
        }
        let mut stream = reader.into_inner();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("respond");
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_heartbeat_for_test(Duration::ZERO);
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(capture_grant(
        &request,
        "tr-slow",
        format!("{base}/p1"),
        len as u64,
    ));
    wait_uploads_finished(&images, 1);
    let mut frames = Vec::new();
    loop {
        let batch = images.drain();
        if batch.is_empty() {
            break;
        }
        frames.extend(batch);
    }
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
    let beats: Vec<(u64, u64)> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadProgress(p) => {
                assert_eq!(p.transfer_id, "tr-slow");
                assert!(p.is_valid());
                Some((p.bytes_sent, p.wire_bytes))
            }
            _ => None,
        })
        .collect();
    assert!(beats.len() >= 2, "{beats:?}");
    assert!(beats.windows(2).all(advanced), "{beats:?}");
    assert!(beats.iter().all(|b| b.0 <= len as u64));
}

/// A heartbeat carries the stored-object offset reached and the body bytes
/// the transport took (`wireBytes`), only when either moved past the last
/// one sent, and at most every interval (no clock involved: a zero interval
/// sends on every advance, an hour never twice). A part sent again below
/// the offset reached still moves `wireBytes` (I5: bytes moving on the
/// socket are liveness), never `bytesSent`.
#[test]
fn heartbeats_carry_the_offset_reached_and_only_when_it_moved() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    let beats = |images: &ImageService| -> Vec<(u64, u64)> {
        images
            .drain()
            .into_iter()
            .filter_map(|f| match f {
                DaemonControlMessage::ImageUploadProgress(p) => Some((p.bytes_sent, p.wire_bytes)),
                _ => None,
            })
            .collect()
    };
    images.drain();
    images.set_heartbeat_for_test(Duration::ZERO);
    let heartbeat = images.heartbeat("tr-hb");
    heartbeat.reach(10, 10);
    heartbeat.reach(10, 0);
    // A retry re-sending bytes 0..5: physical activity, no logical progress.
    heartbeat.reach(5, 5);
    heartbeat.reach(20, 15);
    assert_eq!(beats(&images), [(10, 10), (10, 15), (20, 30)]);
    // A part body reports its offset in the stored object.
    let body = [1u8; 8];
    let mut reader = CountingBody {
        bytes: &body,
        pos: 0,
        base: 1000,
        heartbeat: Some(&heartbeat),
    };
    let mut buf = [0u8; 3];
    std::io::Read::read(&mut reader, &mut buf).unwrap();
    // The body read moves the offset only: its bytes count on the wire as
    // the socket takes them (`sending`).
    assert_eq!(beats(&images), [(1003, 30)]);
    images.set_heartbeat_for_test(Duration::from_secs(3600));
    let throttled = images.heartbeat("tr-hb2");
    throttled.reach(10, 10);
    throttled.reach(20, 10);
    assert!(beats(&images).is_empty());
}

/// Fix 3 b#1 (I5): wire progress is counted as the socket takes the bytes,
/// below ureq's body buffer. ureq reads one 128 KiB buffer from the body at
/// once (one logical step, no heartbeat yet), then its one write drains
/// slowly: 8 chunks of 16 KiB, each taking 20 s on the virtual upload clock.
/// With the production 30 s interval that one write sends a heartbeat at
/// 40, 80, 120 and 160 s, each with the wire bytes taken so far.
#[test]
fn a_slow_drain_of_one_buffered_write_keeps_heartbeats_flowing() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    images.set_test_clock(0.0);
    images.drain();
    let heartbeat = images.heartbeat("tr-drain");
    let buffered = vec![7u8; 128 << 10];
    let mut body = CountingBody {
        bytes: &buffered,
        pos: 0,
        base: 0,
        heartbeat: Some(&heartbeat),
    };
    let mut buf = vec![0u8; 128 << 10];
    assert_eq!(std::io::Read::read(&mut body, &mut buf).unwrap(), 128 << 10);
    let clock = images.clone();
    heartbeat
        .sending(|| {
            crate::tls::transmit_through_idle_for_test(
                &buf,
                Arc::new(move |_| clock.advance_test_clock(Duration::from_secs(20))),
            )
        })
        .unwrap();
    let beats: Vec<(u64, u64)> = images
        .drain()
        .into_iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadProgress(p) => Some((p.bytes_sent, p.wire_bytes)),
            _ => None,
        })
        .collect();
    let chunk = 16u64 << 10;
    assert_eq!(
        beats,
        [2, 4, 6, 8].map(|k| (128u64 << 10, k * chunk)),
        "one slow buffered write must keep heartbeats flowing"
    );
}

/// Real failures logged through the production subscriber carry their
/// structured fields and never a presigned URL, credential or token.
#[test]
fn upload_failure_logs_carry_fields_and_never_a_url_or_secret() {
    const SIG: &str = "SENTINELSIGNATURE";
    const KEY: &str = "SENTINELACCESSKEY";
    for format in [crate::cli::LogFormat::Text, crate::cli::LogFormat::Json] {
        let ((), logs) = crate::logging::with_subscriber(
            format,
            tracing_subscriber::EnvFilter::new("info"),
            || {
                let runtime = FakeRuntime::default();
                let dir = tempfile::tempdir().unwrap();
                // Every attempt of the part (each retry logs a line too).
                let (base, server) = responder(
                    (0..PART_ATTEMPTS)
                        .map(|_| (503, Vec::new(), Vec::new()))
                        .collect(),
                );
                let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
                let path = dir.path().join("staged");
                std::fs::write(&path, b"sixteen bytes!!!").unwrap();
                let mut file = std::fs::File::open(&path).unwrap();
                let query = format!("X-Amz-Credential={KEY}&X-Amz-Signature={SIG}");
                let heartbeat = images.heartbeat("tr-log");
                for url in [
                    format!("{base}/obj?{query}"),
                    format!("http://127.0.0.1:9/obj?{query}"),
                ] {
                    let parts = [sandbox_protocol::ImageUploadPartUrlV11 {
                        n: 1,
                        url,
                        size_bytes: 16,
                    }];
                    let failure = images
                        .put_parts(
                            &mut file,
                            16,
                            16,
                            &parts,
                            None,
                            None,
                            &|| false,
                            Some(&heartbeat),
                        )
                        .unwrap_err();
                    failure.log("image upload ended", Some("tr-log"));
                }
                server.join().unwrap();
                UploadFailure::refused(&format!("{KEY} {SIG}")).log("image upload ended", None);
                UploadFailure::transport(&ureq::Error::Io(std::io::Error::other(format!(
                    "https://bucket.example/obj?{query}"
                ))))
                .log("image upload ended", Some("tr-log"));
            },
        );
        let logs = String::from_utf8_lossy(&logs);
        for field in [
            "http_status",
            "503",
            "connect",
            "part",
            "tr-log",
            "io_kind",
            "attempt",
            "image store part upload retrying",
            "image store part upload failed",
        ] {
            assert!(logs.contains(field), "{field} missing: {logs}");
        }
        for secret in [SIG, KEY, "X-Amz", "bucket.example"] {
            assert!(!logs.contains(secret), "{secret} leaked: {logs}");
        }
        if format == crate::cli::LogFormat::Json {
            // Parsed records (test#10): for each URL, the retries carry
            // attempts 1-3 and the final failure attempt 4.
            for cause in ["http_status", "connect"] {
                let attempts = |message: &str| -> Vec<u64> {
                    logs.lines()
                        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                        .filter(|record| {
                            record["fields"]["message"] == message
                                && record["fields"]["cause"] == cause
                                && record["fields"]["transfer"] == "tr-log"
                        })
                        .filter_map(|record| record["fields"]["attempt"].as_u64())
                        .collect()
                };
                assert_eq!(
                    attempts("image store part upload retrying"),
                    [1, 2, 3],
                    "{cause}"
                );
                assert_eq!(attempts("image store part upload failed"), [4], "{cause}");
            }
        }
    }
}

#[path = "upstream_tests.rs"]
mod upstream;

/// Reports another daemon on the Incus server while `on` is set.
#[derive(Debug)]
struct SharedServer {
    inner: sandbox_runtime::guard_probe::FakeGuardProbe,
    on: Arc<std::sync::atomic::AtomicBool>,
    /// The first `skip` asks answer "sole" (an entry check that passed).
    skip: std::sync::atomic::AtomicUsize,
}
impl sandbox_runtime::guard_probe::GuardProbe for SharedServer {
    fn status(
        &self,
    ) -> Result<sandbox_runtime::guard_probe::GuardStatus, sandbox_runtime::RuntimeError> {
        self.inner.status()
    }
    fn expectations(
        &self,
    ) -> Result<sandbox_runtime::guard_probe::GuardExpectations, sandbox_runtime::RuntimeError>
    {
        self.inner.expectations()
    }
    fn shared_incus_server(&self) -> Option<String> {
        use std::sync::atomic::Ordering::SeqCst;
        if self
            .skip
            .try_update(SeqCst, SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return None;
        }
        self.on.load(SeqCst).then(|| "host `other`".into())
    }
}

fn shared_runtime(on: bool) -> (FakeRuntime, Arc<std::sync::atomic::AtomicBool>) {
    shared_runtime_after(on, 0)
}

/// Shared (when `on`) from the `skip + 1`-th ask on.
fn shared_runtime_after(
    on: bool,
    skip: usize,
) -> (FakeRuntime, Arc<std::sync::atomic::AtomicBool>) {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(on));
    let mut runtime = FakeRuntime::default();
    runtime.set_guard_probe(Arc::new(SharedServer {
        inner: sandbox_runtime::guard_probe::FakeGuardProbe::healthy(),
        on: flag.clone(),
        skip: std::sync::atomic::AtomicUsize::new(skip),
    }));
    (runtime, flag)
}

fn assert_guard_outage(err: &ImageError) {
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    assert_eq!(
        err.reason,
        Some(sandbox_protocol::ProtocolErrorReason::from(
            sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable
        )),
        "refused like a guard outage, so the server retries it"
    );
    assert!(
        err.message.contains("another wssp daemon"),
        "{}",
        err.message
    );
}

fn no_fetch_requested(images: &ImageService) {
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        images
            .drain()
            .iter()
            .all(|f| !matches!(f, DaemonControlMessage::ImageFetchRequest(_)))
    );
}

/// One wssp daemon per Incus server: while another daemon's
/// marker is live, a planned fetch for new work (a create, a template build
/// VM, an offload restore) downloads and imports nothing.
#[test]
fn no_image_is_fetched_or_imported_while_another_daemon_shares_the_incus_server() {
    let (runtime, _) = shared_runtime(true);
    let dir = tempfile::tempdir().unwrap();
    let image = b"unified image tarball".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let images = service_with(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
        true,
    );
    let err = images
        .ensure_image(&dispatch(&fp, image.len() as u64, "owner-a"), &|| true)
        .expect_err("refused");
    assert_guard_outage(&err);
    assert!(!runtime.has_image(&fp));
    assert!(images.entries().is_empty());
    no_fetch_requested(&images);
}

/// A fetch waiting on another fetch of the same image is
/// woken after the daemon degraded; it rechecks before any reservation,
/// eviction or download.
#[test]
fn a_waiting_fetch_rechecks_the_fence_when_it_wakes() {
    let (runtime, shared) = shared_runtime(false);
    let dir = tempfile::tempdir().unwrap();
    let image = b"unified image tarball".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let images = service_with(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
        true,
    );
    // Another fetch of the same image holds the single flight.
    images.inner.inflight.lock().unwrap().insert(fp.clone());
    let waiter = run_fetch(&images, dispatch(&fp, image.len() as u64, "owner-a"));
    std::thread::sleep(Duration::from_millis(150));
    assert!(!waiter.is_finished(), "the second fetch waits");
    // The daemon degrades; the leader's fetch then ends.
    shared.store(true, std::sync::atomic::Ordering::SeqCst);
    images.inner.inflight.lock().unwrap().remove(&fp);
    images.inner.inflight_cv.notify_all();
    let err = waiter.join().unwrap().expect_err("refused after the wake");
    assert_guard_outage(&err);
    assert!(!runtime.has_image(&fp));
    assert!(images.entries().is_empty());
    no_fetch_requested(&images);
}

/// The daemon degrades after the fetch's entry check; the
/// runtime's import refusal (the guard outage, typed) reaches the caller as
/// that guard outage, never as `image_rejected`.
#[test]
fn an_import_refused_by_the_shared_server_fence_stays_a_guard_outage() {
    let (runtime, _) = shared_runtime_after(true, 1);
    let dir = tempfile::tempdir().unwrap();
    let image = b"unified image tarball".to_vec();
    let fp = format!("sha256:{}", sha256_hex(&image));
    let (base, _server) = responder(vec![(200, vec![], image.clone())]);
    let images = service_with(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        &base,
        true,
    );
    let fetch = run_fetch(&images, dispatch(&fp, image.len() as u64, "owner-a"));
    let DaemonControlMessage::ImageFetchRequest(request) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageFetchRequest(_))
    }) else {
        unreachable!()
    };
    images.handle_server(s3_grant(
        &request.request_id,
        image.len() as u64,
        &format!("{base}/obj?X-Amz-Signature=sig"),
        None,
    ));
    let err = fetch.join().unwrap().expect_err("import refused");
    assert_guard_outage(&err);
    assert!(!runtime.has_image(&fp));
    assert!(images.entries().is_empty());
}

/// A slow uplink (the store reads ~800 KB/s, standing in for ~100 KB/s at
/// test scale) over several parts: the upload completes, heartbeats rise
/// while bytes move, and with a 1 s URL lifetime (renewed with half of it
/// left) the upload pulls fresh URLs before later parts. Every part takes
/// at least 320 ms (16 paced reads of 20 ms), so by the third part fewer
/// than 500 ms of the first grant are left: at least one renew is certain
/// however fast the machine is; a slower one renews more often.
/// A slow upload over several parts on the virtual upload clock (b#5): each
/// part takes the store 40 s (the store moves the clock), the grant's URLs
/// live 120 s and are renewed with less than 60 s left. Parts 1 and 2 use
/// grant 1; part 3 has 40 s left on it, so exactly one renew; parts 3 and 4
/// use grant 2. The store refuses a superseded or lapsed URL (test#1).
#[test]
fn a_slow_upload_over_several_parts_renews_its_urls_and_completes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let book = Book::default();
    let checked = book.clone();
    let clock: Arc<std::sync::OnceLock<ImageService>> = Arc::default();
    let moves = clock.clone();
    let (base, connections, _s3) = scripted_s3_paths(move |_, path, reader, length| {
        book_store(&checked, path, reader, length, |reader, length| {
            if let Some(images) = moves.get() {
                images.advance_test_clock(Duration::from_secs(40));
            }
            store_paced(reader, length);
        });
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_test_clock(0.0);
    images.set_heartbeat_for_test(Duration::ZERO);
    let _ = clock.set(images.clone());
    book.lock().unwrap().clock = Some(images.clone());
    let part = 256u64 << 10;
    let bytes = vec![7u8; (4 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-slow-ttl", &base, part, bytes.len() as u64);
    control.book = book;
    control.ttl = 120;
    images.handle_server(control.grant(Some(&request), 1));
    let frames = control.run(&mut no_hook());
    assert_eq!(
        upload_sequence(&frames),
        ["parts", "renew", "parts", "complete"],
        "{frames:?}"
    );
    assert_eq!(control.recorded, (1..=4).collect());
    assert_eq!(connections.load(Ordering::SeqCst), 4);
    let beats: Vec<(u64, u64)> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadProgress(p) => Some((p.bytes_sent, p.wire_bytes)),
            _ => None,
        })
        .collect();
    assert!(beats.len() >= 4, "{beats:?}");
    assert!(beats.windows(2).all(advanced), "{beats:?}");
    assert_eq!(beats.iter().map(|b| b.0).max(), Some(bytes.len() as u64));
}

/// A 403 renews the part's URL once and retries: success. A second 403 on
/// the fresh URL is final, `http_status` 403 (the URL had not lapsed).
#[test]
fn a_forbidden_part_renews_its_url_once() {
    for forbidden in [1usize, 2] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        // After the scripted 403s the store takes only URLs of the latest
        // grant (test#1): the retry must use the renewed URL.
        let book = Book::default();
        let checked = book.clone();
        let (base, connections, _s3) = scripted_s3_paths(move |i, path, reader, length| {
            if i < forbidden {
                store_status(reader, length, 403);
            } else {
                book_store(&checked, path, reader, length, store_ok);
            }
        });
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        let bytes = b"forbidden then renewed".to_vec();
        let request = start_capture_upload(&images, &runtime, &bytes);
        let mut control = FakeControl::new(&images, "tr-403", &base, 1 << 20, bytes.len() as u64);
        control.book = book;
        images.handle_server(control.grant(Some(&request), 1));
        let frames = control.run(&mut no_hook());
        assert_eq!(renews(&frames), 1, "{frames:?}");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        if forbidden == 1 {
            assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
        } else {
            assert_eq!(upload_kinds(&frames), ["failed"]);
            let failed = the_failure(&frames);
            assert_eq!(
                failed.cause,
                sandbox_protocol::ImageFailureCause::HttpStatus
            );
            assert_eq!(failed.http_status, Some(403));
            assert_eq!(failed.part, Some(1));
        }
    }
}

/// A part report the server dropped (over its budget, no reply) is sent
/// again when a renewed grant names that part: the upload completes and
/// the server ends up with every part.
#[test]
fn a_dropped_part_report_is_resent_when_a_renewed_grant_names_it() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let part = 64u64 << 10;
    let bytes = vec![1u8; (3 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-drop", &base, part, bytes.len() as u64);
    // The first grant names part 1 only: the first report (part 1) is
    // dropped, so the renew's grant starts at part 1 again.
    let ServerControlMessage::ImageUploadGrant(mut first) = control.grant(Some(&request), 1) else {
        unreachable!()
    };
    first.parts.truncate(1);
    images.handle_server(ServerControlMessage::ImageUploadGrant(first));
    control.drop_reports = 1;
    let frames = control.run(&mut no_hook());
    let reports: Vec<Vec<u32>> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadParts(p) => {
                Some(p.parts.iter().map(|p| p.n).collect())
            }
            _ => None,
        })
        .collect();
    assert_eq!(reports[0], [1], "{reports:?}");
    assert!(reports[1..].iter().any(|r| r.contains(&1)), "{reports:?}");
    assert_eq!(upload_kinds(&frames).last(), Some(&"complete"));
    assert_eq!(control.recorded, (1..=3).collect());
}

/// A begin refused `rate_limited` is sent again (a new request id) and the
/// grant of the retry completes the upload.
#[test]
fn a_rate_limited_begin_is_retried_and_completes() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = b"rate limited begin".to_vec();
    let first = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "none".into(),
            reason: "rate_limited".into(),
            request_id: Some(first.clone()),
        },
    ));
    let DaemonControlMessage::ImageUploadBegin(again) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    }) else {
        unreachable!()
    };
    let second = again.request_id.expect("request id");
    assert_ne!(second, first);
    assert_eq!(
        (again.operation_id.as_deref(), again.attempt),
        (Some("op-up"), Some(4))
    );
    let mut control = FakeControl::new(&images, "tr-rl", &base, 1 << 20, bytes.len() as u64);
    // A late grant for the first (refused) request reaches nobody.
    images.handle_server(control.grant(Some(&first), 1));
    images.handle_server(control.grant(Some(&second), 1));
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
}

/// A begin refused `artifact_deleting` every time is retried through the
/// whole begin budget, then reported `refused` with the reason, by its
/// operation and attempt.
#[test]
fn a_begin_refused_until_the_retry_budget_is_spent_is_reported() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
    let bytes = b"deleting artifact".to_vec();
    let mut request = start_capture_upload(&images, &runtime, &bytes);
    let mut begins = 1;
    let mut frames = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        images.handle_server(ServerControlMessage::ImageJobCancel(
            sandbox_protocol::ImageJobCancelV11 {
                transfer_id: "none".into(),
                reason: "artifact_deleting".into(),
                request_id: Some(request.clone()),
            },
        ));
        // The next begin, or the job's end.
        let next = loop {
            let finished = images.uploads_finished() >= 1;
            let batch = images.drain();
            let begin = batch.iter().find_map(|f| match f {
                DaemonControlMessage::ImageUploadBegin(b) => b.request_id.clone(),
                _ => None,
            });
            frames.extend(batch);
            if begin.is_some() || finished {
                break begin;
            }
            assert!(Instant::now() < deadline, "no begin and no end");
            std::thread::sleep(Duration::from_millis(5));
        };
        match next {
            Some(id) => {
                begins += 1;
                request = id;
            }
            None => break,
        }
    }
    assert_eq!(begins, 1 + FAST_TIMINGS.begin_retry.len());
    let mut kinds = upload_kinds(&frames);
    kinds.retain(|k| *k != "begin");
    assert_eq!(kinds, ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id, None);
    assert_eq!(
        (failed.operation_id.as_deref(), failed.attempt),
        (Some("op-up"), Some(4))
    );
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
    assert_eq!(failed.refusal.as_deref(), Some("artifact_deleting"));
}

/// Polls the outbox (frames left queued) until one matches `wanted`.
fn wait_queued(images: &ImageService, wanted: impl Fn(&DaemonControlMessage) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !images.queued().iter().any(&wanted) {
        assert!(
            Instant::now() < deadline,
            "never queued: {:?}",
            images.queued()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Drains until a frame matches `wanted`; every frame drained, in order.
fn drain_until(
    images: &ImageService,
    wanted: impl Fn(&DaemonControlMessage) -> bool,
) -> Vec<DaemonControlMessage> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut frames = Vec::new();
    loop {
        frames.extend(images.drain());
        if frames.iter().any(&wanted) {
            return frames;
        }
        assert!(Instant::now() < deadline, "never sent: {frames:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn is_resume_of_transfer(frame: &DaemonControlMessage, transfer: &str) -> bool {
    matches!(frame, DaemonControlMessage::ImageJobResume(r)
        if r.transfer_id.as_deref() == Some(transfer))
}

fn is_resume_of_operation(frame: &DaemonControlMessage, operation: &str, attempt: u64) -> bool {
    matches!(frame, DaemonControlMessage::ImageJobResume(r)
        if r.operation_id.as_deref() == Some(operation) && r.attempt == Some(attempt)
            && r.transfer_id.is_none())
}

fn answer_transfer_resume(images: &ImageService, transfer: &str, proceed: bool) {
    images.handle_server(ServerControlMessage::ImageJobResumeResult(
        sandbox_protocol::ImageJobResumeResultV11::transfer(transfer, proceed),
    ));
}

fn answer_operation_resume(images: &ImageService, operation: &str, attempt: u64, proceed: bool) {
    images.handle_server(ServerControlMessage::ImageJobResumeResult(
        sandbox_protocol::ImageJobResumeResultV11::operation(operation, attempt, proceed),
    ));
}

fn refuse_begin(images: &ImageService, request: &str, reason: &str) {
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "none".into(),
            reason: reason.into(),
            request_id: Some(request.into()),
        },
    ));
}

/// A first grant of part 1 only: after it the upload reports part 1 and
/// renews (both frames queued, in that order).
fn first_part_only(control: &FakeControl<'_>, request: &str) -> ServerControlMessage {
    let ServerControlMessage::ImageUploadGrant(mut first) = control.grant(Some(request), 1) else {
        unreachable!()
    };
    first.parts.truncate(1);
    ServerControlMessage::ImageUploadGrant(first)
}

/// A relay reconnect after part 1 was flushed, while its report and the
/// renew still wait in the outbox (test#6): the new connection gets the
/// transfer's `image.job.resume` first, carrying the bytes of part 1, then
/// the queued report and renew. The upload sends nothing more of the
/// transfer until the (delayed) answer: `continue` → it renews again (the
/// grant answering the old renew is dropped, it was routed before) and
/// completes from the server's lowest unrecorded part; `continue: false`
/// stops it `refused` + `stale_transfer`, before part 2.
#[test]
fn a_relay_reconnect_mid_upload_resumes_the_transfer() {
    for proceed in [true, false] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, connections, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        let part = 64u64 << 10;
        let bytes = vec![2u8; (3 * part) as usize];
        let request = start_capture_upload(&images, &runtime, &bytes);
        let mut control = FakeControl::new(&images, "tr-rc", &base, part, bytes.len() as u64);
        images.handle_server(first_part_only(&control, &request));
        wait_queued(&images, |f| {
            matches!(f, DaemonControlMessage::ImageUploadRenew(_))
        });
        images.on_registered("host-owner");
        let queued = images.drain();
        let kinds: Vec<&str> = queued
            .iter()
            .filter_map(|f| match f {
                DaemonControlMessage::ImageJobResume(r) => {
                    assert_eq!(r.transfer_id.as_deref(), Some("tr-rc"));
                    assert_eq!(r.role, ImageLinkRole::Source);
                    assert_eq!(r.bytes_done, part, "part 1 was reported");
                    Some("resume")
                }
                DaemonControlMessage::ImageUploadParts(_) => Some("parts"),
                DaemonControlMessage::ImageUploadRenew(_) => Some("renew"),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, ["resume", "parts", "renew"], "{queued:?}");
        // The server handles them in order: the renew is granted at once,
        // the resume's answer is late.
        control.recorded.insert(1);
        images.handle_server(control.grant(None, 2));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "part 2 before the answer"
        );
        assert!(images.drain().is_empty(), "a frame before the answer");
        answer_transfer_resume(&images, "tr-rc", proceed);
        let frames = control.run(&mut no_hook());
        if proceed {
            assert!(
                matches!(frames[0], DaemonControlMessage::ImageUploadRenew(_)),
                "{frames:?}"
            );
            assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
            assert_eq!(control.recorded, (1..=3).collect());
            assert_eq!(connections.load(Ordering::SeqCst), 3);
        } else {
            assert_eq!(upload_kinds(&frames), ["failed"]);
            let failed = the_failure(&frames);
            assert_eq!(failed.transfer_id.as_deref(), Some("tr-rc"));
            assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
            assert_eq!(failed.refusal.as_deref(), Some("stale_transfer"));
            assert_eq!(connections.load(Ordering::SeqCst), 1, "no part 2");
        }
        assert_eq!(images.resumable_jobs(), 0);
    }
}

/// V1 (life#1, err#1): an upload whose part fails for good while the relay
/// is down queues its failure; the next connection gets the transfer's
/// resume first, then that failure with its cause, and the job leaves the
/// resume registry only once the failure was drained (or, with
/// `continue: false` for its resume, at once, its queued resume and failure
/// going with it: fix 5, r5 #3).
#[test]
fn a_failure_while_the_relay_is_down_reaches_the_server_after_resume_with_its_cause() {
    for refused_first in [false, true] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, _, _s3) = scripted_s3(|_, reader, length| store_status(reader, length, 503));
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        let bytes = b"fails while the relay is down".to_vec();
        let request = start_capture_upload(&images, &runtime, &bytes);
        let control = FakeControl::new(&images, "tr-down", &base, 1 << 20, bytes.len() as u64);
        images.handle_server(control.grant(Some(&request), 1));
        images.on_disconnect();
        wait_uploads_finished(&images, 1);
        assert_eq!(
            images.resumable_jobs(),
            1,
            "retired before its failure was sent"
        );
        images.on_registered("host-owner");
        if refused_first {
            answer_transfer_resume(&images, "tr-down", false);
            assert_eq!(images.resumable_jobs(), 0);
            let job = JobRef::Transfer("tr-down".into());
            let frames = images.drain();
            assert!(frames.iter().all(|f| !job.names(f)), "{frames:?}");
            images.on_registered("host-owner");
            assert!(images.drain().is_empty());
            continue;
        }
        let frames = images.drain();
        assert!(is_resume_of_transfer(&frames[0], "tr-down"), "{frames:?}");
        let failed = the_failure(&frames);
        assert_eq!(failed.transfer_id.as_deref(), Some("tr-down"));
        assert_eq!(
            failed.cause,
            sandbox_protocol::ImageFailureCause::HttpStatus
        );
        assert_eq!(failed.http_status, Some(503));
        assert_eq!(images.resumable_jobs(), 0);
        // Retired: the next connection resumes nothing.
        images.on_registered("host-owner");
        assert!(images.drain().is_empty());
    }
}

/// V1 (life#2, err#2): a capture begin refused for now, then a relay
/// reconnect during its retry pause. The new connection gets the capture's
/// resume by operation (it has no transfer yet) ahead of the next begin;
/// once resumed, the retries go on, and the refusal still ending them is
/// reported by operation with its reason. `continue: false` ends the
/// capture `refused` + `stale_capture`.
#[test]
fn a_begin_retry_across_a_reconnect_resumes_the_operation_and_keeps_its_refusal() {
    for proceed in [true, false] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
        let bytes = b"retry across a reconnect".to_vec();
        let request = start_capture_upload(&images, &runtime, &bytes);
        refuse_begin(&images, &request, "rate_limited");
        images.on_disconnect();
        images.on_registered("host-owner");
        let mut frames = drain_until(&images, |f| is_resume_of_operation(f, "op-up", 4));
        let resume = frames
            .iter()
            .position(|f| is_resume_of_operation(f, "op-up", 4))
            .unwrap();
        if let Some(begin) = frames
            .iter()
            .position(|f| matches!(f, DaemonControlMessage::ImageUploadBegin(_)))
        {
            assert!(resume < begin, "{frames:?}");
        }
        answer_operation_resume(&images, "op-up", 4, proceed);
        // Refuse every begin until the job ends.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut answered = std::collections::HashSet::new();
        loop {
            let finished = images.uploads_finished() >= 1;
            frames.extend(images.drain());
            for frame in &frames {
                if let DaemonControlMessage::ImageUploadBegin(b) = frame {
                    let id = b.request_id.clone().unwrap();
                    if answered.insert(id.clone()) {
                        refuse_begin(&images, &id, "artifact_deleting");
                    }
                }
            }
            if finished && images.queued().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "never ended: {frames:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
        let failed = the_failure(&frames);
        assert_eq!(failed.transfer_id, None);
        assert_eq!(
            (failed.operation_id.as_deref(), failed.attempt),
            (Some("op-up"), Some(4))
        );
        assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
        let reason = if proceed {
            "artifact_deleting"
        } else {
            "stale_capture"
        };
        assert_eq!(failed.refusal.as_deref(), Some(reason), "{frames:?}");
        assert_eq!(images.resumable_jobs(), 0);
    }
}

/// V1: a capture begin that had already left the outbox when the relay
/// reconnected may have lost its answer: once the operation is resumed the
/// begin is sent again (a new request id) and its grant completes the
/// upload. Without the re-send the capture would wait for a grant that
/// never comes.
#[test]
fn a_begin_lost_with_its_connection_is_sent_again_after_resume() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_grant_wait_for_test(Duration::from_secs(5));
    let bytes = b"begin lost with its connection".to_vec();
    let first = start_capture_upload(&images, &runtime, &bytes);
    images.on_registered("host-owner");
    let frames = images.drain();
    assert!(is_resume_of_operation(&frames[0], "op-up", 4), "{frames:?}");
    answer_operation_resume(&images, "op-up", 4, true);
    let DaemonControlMessage::ImageUploadBegin(again) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    }) else {
        unreachable!()
    };
    let second = again.request_id.expect("request id");
    assert_ne!(second, first);
    let mut control = FakeControl::new(&images, "tr-lost", &base, 1 << 20, bytes.len() as u64);
    images.handle_server(control.grant(Some(&second), 1));
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
}

/// V1 (life#3, err#6): the first grant arrived on connection 1, and the
/// relay reconnected before the upload named its transfer in the resume
/// registry (held here by the test, so the order is certain; that
/// reconnect queued the operation's resume, which cannot rebind the
/// transfer). The upload
/// sees that its grant is from an older connection: it queues its
/// transfer's resume itself and sends nothing more until the answer.
#[test]
fn a_grant_from_an_older_connection_resumes_its_transfer_first() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, connections, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = b"granted on the old connection".to_vec();
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-old", &base, 1 << 20, bytes.len() as u64);
    {
        // The registry is held: the grant is routed on connection 1 and the
        // reconnect counted while the job still names its operation,
        // whether or not the job has taken the grant from its receiver yet.
        let mut resumable = images.inner.resumable.lock().unwrap();
        images.handle_server(control.grant(Some(&request), 1));
        images.next_connection(&mut resumable);
    }
    wait_queued(&images, |f| is_resume_of_transfer(f, "tr-old"));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "a part before the answer"
    );
    let frames = images.drain();
    let first = frames
        .iter()
        .position(|f| {
            is_resume_of_transfer(f, "tr-old")
                || matches!(f, DaemonControlMessage::ImageUploadParts(_))
        })
        .unwrap();
    assert!(
        is_resume_of_transfer(&frames[first], "tr-old"),
        "{frames:?}"
    );
    answer_transfer_resume(&images, "tr-old", true);
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
}

/// FB-B3: two reconnects while the upload waits for its resume answer. It
/// waits for the answer on the current (third) connection, which gets one
/// resume of the transfer (the queued one replaced), and completes.
#[test]
fn a_second_reconnect_during_the_resume_wait_waits_for_the_newer_answer() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_grant_wait_for_test(Duration::from_secs(5));
    let part = 64u64 << 10;
    let bytes = vec![3u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-twice", &base, part, bytes.len() as u64);
    images.handle_server(first_part_only(&control, &request));
    wait_queued(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadRenew(_))
    });
    images.on_registered("host-owner");
    let second = images.drain();
    assert!(is_resume_of_transfer(&second[0], "tr-twice"), "{second:?}");
    control.recorded.insert(1);
    images.on_registered("host-owner");
    let third = images.drain();
    assert_eq!(
        third
            .iter()
            .filter(|f| is_resume_of_transfer(f, "tr-twice"))
            .count(),
        1,
        "{third:?}"
    );
    answer_transfer_resume(&images, "tr-twice", true);
    let frames = control.run(&mut no_hook());
    assert_eq!(
        upload_kinds(&frames).last(),
        Some(&"complete"),
        "{frames:?}"
    );
    assert_eq!(control.recorded, (1..=2).collect());
}

/// FB-B3: a resume answer routed on an older connection never resumes the
/// upload on the current one. While part 1 is in flight the relay
/// reconnects twice; the answer to the second connection's resume
/// (`continue`) and then the third's (`continue: false`) are both waiting
/// when the part ends: the upload heeds only the third and stops.
#[test]
fn an_answer_for_an_older_connection_never_resumes_the_upload() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (got, part_seen) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);
    let (base, connections, _s3) = scripted_s3(move |i, mut reader, length| {
        if i == 0 {
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).expect("part 1 body");
            got.send(()).unwrap();
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(60));
            let mut stream = reader.into_inner();
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        } else {
            store_ok(reader, length);
        }
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let part = 64u64 << 10;
    let bytes = vec![9u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-older", &base, part, bytes.len() as u64);
    images.handle_server(control.grant(Some(&request), 1));
    part_seen
        .recv_timeout(Duration::from_secs(30))
        .expect("part 1 reached the store");
    images.on_registered("host-owner");
    answer_transfer_resume(&images, "tr-older", true);
    images.on_registered("host-owner");
    answer_transfer_resume(&images, "tr-older", false);
    release.send(()).unwrap();
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["failed"], "{frames:?}");
    let failed = the_failure(&frames);
    assert_eq!(failed.refusal.as_deref(), Some("stale_transfer"));
    assert_eq!(connections.load(Ordering::SeqCst), 1, "no part 2");
}

/// FB-B4: a renew wait does not run down while the relay is down. The
/// grant wait is 500 ms; the relay stays down three times that while the
/// upload waits for its renew, and after the reconnect it resumes and
/// completes instead of ending `no_grant`.
#[test]
fn a_renew_waits_out_a_relay_outage_longer_than_the_grant_wait() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let part = 64u64 << 10;
    let bytes = vec![4u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-out", &base, part, bytes.len() as u64);
    images.set_grant_wait_for_test(Duration::from_millis(500));
    images.handle_server(first_part_only(&control, &request));
    images.on_disconnect();
    wait_queued(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadRenew(_))
    });
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(images.uploads_finished(), 0, "the outage ran the wait down");
    images.on_registered("host-owner");
    let mut frames = images.drain();
    assert!(is_resume_of_transfer(&frames[0], "tr-out"), "{frames:?}");
    control.recorded.insert(1);
    answer_transfer_resume(&images, "tr-out", true);
    frames.extend(control.run(&mut no_hook()));
    assert_eq!(
        upload_kinds(&frames).last(),
        Some(&"complete"),
        "{frames:?}"
    );
}

/// W5 (a#4): a publish begin refused for now is never retried by the
/// host: publishes are server backfill (the server ends the transfer, and
/// for a store refusal its artifact, so backfill asks again). The job ends
/// at once, reported by its transfer with the refusal; one begin only.
#[test]
fn a_transient_publish_begin_refusal_ends_the_publish_with_its_cause() {
    for reason in ["rate_limited", "store_unavailable"] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
        let bytes = b"published image".to_vec();
        let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
        let job = images.clone();
        std::thread::spawn(move || job.upload(&fp, "owner-a", UploadJob::Publish("tr-pub".into())));
        let DaemonControlMessage::ImageUploadBegin(b) = wait_frame(&images, |f| {
            matches!(f, DaemonControlMessage::ImageUploadBegin(_))
        }) else {
            unreachable!()
        };
        assert_eq!(b.transfer_id.as_deref(), Some("tr-pub"));
        images.handle_server(ServerControlMessage::ImageJobCancel(
            sandbox_protocol::ImageJobCancelV11 {
                transfer_id: "tr-pub".into(),
                reason: reason.into(),
                request_id: None,
            },
        ));
        let frames = upload_frames(&images);
        assert_eq!(upload_sequence(&frames), ["failed"], "{reason}: {frames:?}");
        let failed = the_failure(&frames);
        assert_eq!(failed.transfer_id.as_deref(), Some("tr-pub"));
        assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
        assert_eq!(failed.refusal.as_deref(), Some(reason));
        assert_eq!(images.resumable_jobs(), 0);
    }
}

/// V2: a grant routed before a renew was sent (a late answer to an earlier
/// one, here one that arrived while part 1 was in flight) is dropped: the
/// upload uses only the grant answering its renew. The store refuses the
/// stray grant's URLs once superseded, and no request ever names them.
#[test]
fn a_grant_routed_before_the_renew_is_dropped() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let book = Book::default();
    let checked = book.clone();
    let paths: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = paths.clone();
    let (got, part_seen) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);
    let (base, _, _s3) = scripted_s3_paths(move |i, path, mut reader, length| {
        seen.lock().unwrap().push(path.to_owned());
        if i == 0 {
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).expect("part 1 body");
            got.send(()).unwrap();
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(60));
            let mut stream = reader.into_inner();
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        } else {
            book_store(&checked, path, reader, length, store_ok);
        }
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let part = 64u64 << 10;
    let bytes = vec![8u8; (3 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-stray", &base, part, bytes.len() as u64);
    control.book = book;
    images.handle_server(first_part_only(&control, &request));
    part_seen
        .recv_timeout(Duration::from_secs(30))
        .expect("part 1 reached the store");
    // Grant 2: routed before any renew.
    images.handle_server(control.grant(None, 2));
    release.send(()).unwrap();
    let frames = control.run(&mut no_hook());
    assert_eq!(
        upload_kinds(&frames).last(),
        Some(&"complete"),
        "{frames:?}"
    );
    let paths = paths.lock().unwrap().clone();
    assert!(!paths.iter().any(|p| p.starts_with("/g2/")), "{paths:?}");
    assert_eq!(control.recorded, (1..=3).collect());
}

/// V4 (life#6, err#8): the resume's `bytesDone` counts each reported part
/// once: a part reported again (a renewed grant named it) is sent again but
/// never counted twice.
#[test]
fn reported_bytes_count_each_part_once_however_often_it_is_reported() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
    images.drain();
    let (_tx, rx) = mpsc::channel();
    let (_resume_tx, resume_rx) = mpsc::channel();
    let mut run = UploadRun {
        service: &images,
        tid: "tr-acc".into(),
        rx,
        resume_rx,
        timings: FAST_TIMINGS,
        part_size: 10,
        stored_size: 25,
        window: std::collections::BTreeMap::new(),
        expiry: Instant::now(),
        margin: Duration::ZERO,
        done: std::collections::BTreeMap::new(),
        pending: Vec::new(),
        reported_parts: HashSet::new(),
        counted: HashSet::new(),
        reported: Arc::new(AtomicU64::new(0)),
        last_flush: Instant::now(),
        connection: 1,
    };
    for n in [1u32, 2] {
        run.done.insert(n, format!("e{n}"));
        run.pending.push(ImageUploadedPartV11 {
            n,
            etag: format!("e{n}"),
        });
    }
    run.flush();
    assert_eq!(run.reported.load(Ordering::SeqCst), 20);
    let grant = sandbox_protocol::ImageUploadGrantV11 {
        transfer_id: "tr-acc".into(),
        request_id: None,
        part_size: 10,
        parts: (1..=3)
            .map(|n| sandbox_protocol::ImageUploadPartUrlV11 {
                n,
                url: format!("http://127.0.0.1:9/p{n}"),
                size_bytes: if n == 3 { 5 } else { 10 },
            })
            .collect(),
        expires_at_unix_ms: 1,
        ttl_seconds: 600,
        encryption: None,
    };
    run.take_grant(grant, Instant::now()).unwrap();
    run.flush();
    assert_eq!(
        run.reported.load(Ordering::SeqCst),
        20,
        "re-reported, not recounted"
    );
    run.done.insert(3, "e3".into());
    run.pending.push(ImageUploadedPartV11 {
        n: 3,
        etag: "e3".into(),
    });
    run.flush();
    assert_eq!(run.reported.load(Ordering::SeqCst), 25);
    let reports: Vec<Vec<u32>> = images
        .drain()
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadParts(p) => {
                Some(p.parts.iter().map(|p| p.n).collect())
            }
            _ => None,
        })
        .collect();
    assert_eq!(reports, [vec![1, 2], vec![1, 2], vec![3]]);
}

/// test#4: part retries pause 2, 8 and 30 s (production timings, on the
/// virtual clock with no jitter), and with full jitter 25 % longer each.
#[test]
fn part_retries_follow_the_production_schedule() {
    for (jitter, scale) in [(0.0, 1.0), (1.0, 1.25)] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, server) = responder(
            (0..PART_ATTEMPTS)
                .map(|_| (503, Vec::new(), Vec::new()))
                .collect(),
        );
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
        images.set_test_clock(jitter);
        let path = dir.path().join("staged");
        std::fs::write(&path, b"sixteen bytes!!!").unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let parts = [sandbox_protocol::ImageUploadPartUrlV11 {
            n: 1,
            url: format!("{base}/obj"),
            size_bytes: 16,
        }];
        let failure = images
            .put_parts(&mut file, 16, 16, &parts, None, None, &|| false, None)
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(failure.http_status, Some(503));
        let expected: Vec<Duration> = [2u64, 8, 30]
            .iter()
            .map(|s| Duration::from_secs(*s).mul_f64(scale))
            .collect();
        assert_eq!(images.test_pauses(), expected);
    }
}

/// test#4, V4 (err#7): begin retries pause 5, 15, 30 and 60 s, then the
/// refusal is reported; one monotonic begin budget from the first refusal
/// caps them: with 45 s the third pause (30 s) no longer fits in what is
/// left (25 s), so that refusal is reported.
#[test]
fn begin_retries_follow_the_production_schedule_within_the_begin_budget() {
    for (budget, pauses) in [(180u64, vec![5u64, 15, 30, 60]), (45, vec![5, 15])] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
        images.set_upload_timings_for_test(UploadTimings {
            begin_budget: Duration::from_secs(budget),
            ..UploadTimings::PRODUCTION
        });
        images.set_test_clock(0.0);
        let bytes = b"begin schedule".to_vec();
        let mut request = start_capture_upload(&images, &runtime, &bytes);
        let mut frames = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            refuse_begin(&images, &request, "store_unavailable");
            let next = loop {
                let finished = images.uploads_finished() >= 1;
                let batch = images.drain();
                let begin = batch.iter().find_map(|f| match f {
                    DaemonControlMessage::ImageUploadBegin(b) => b.request_id.clone(),
                    _ => None,
                });
                frames.extend(batch);
                if begin.is_some() || finished {
                    break begin;
                }
                assert!(Instant::now() < deadline, "no begin and no end");
                std::thread::sleep(Duration::from_millis(5));
            };
            match next {
                Some(id) => request = id,
                None => break,
            }
        }
        let recorded = images.test_pauses();
        let expected: Vec<Duration> = pauses.into_iter().map(Duration::from_secs).collect();
        assert_eq!(recorded, expected, "budget {budget}");
        assert!(recorded.iter().sum::<Duration>() <= Duration::from_secs(budget));
        let failed = the_failure(&frames);
        assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
        assert_eq!(failed.refusal.as_deref(), Some("store_unavailable"));
    }
}

/// FB-B7: a server that answers every renew with a grant naming only parts
/// already uploaded (their reports dropped) gets a pause before the next
/// renew from the second such grant on, so the renews stay bounded and the
/// upload ends `no_grant` within the renew wait.
#[test]
fn renews_answered_only_with_parts_already_held_pause_and_end_no_grant() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_grant_wait_for_test(Duration::from_secs(2));
    images.set_test_clock(0.0);
    let part = 64u64 << 10;
    let bytes = vec![5u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let control = FakeControl::new(&images, "tr-loop", &base, part, bytes.len() as u64);
    images.handle_server(first_part_only(&control, &request));
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut frames = Vec::new();
    loop {
        let finished = images.uploads_finished() >= 1;
        let batch = images.drain();
        for frame in &batch {
            if let DaemonControlMessage::ImageUploadRenew(_) = frame {
                let ServerControlMessage::ImageUploadGrant(mut held) = control.grant(None, 1)
                else {
                    unreachable!()
                };
                held.parts.truncate(1);
                images.handle_server(ServerControlMessage::ImageUploadGrant(held));
            }
        }
        let empty = batch.is_empty();
        frames.extend(batch);
        if finished && empty {
            break;
        }
        assert!(Instant::now() < deadline, "never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!images.test_pauses().is_empty(), "no pause between renews");
    assert!(renews(&frames) <= 16, "{} renews", renews(&frames));
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-loop"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
}

/// Fix 3 a#2/b#2: the pause after an unusable grant (one naming only parts
/// already uploaded) is the rest of its step, never past the renew's 180 s.
/// PRODUCTION timings on the virtual clock: renews at 0, 5, 20 and 50 s go
/// unanswered; 59 s into the 60 s step (at 109 s) a grant names only part 1
/// (re-reported, no pause), the renew is sent again; 59 s into that step
/// (168 s) the second such grant comes: the pause is the 1 s left of the
/// step, not another 60 s. The last renew waits the 11 s left, and the
/// upload ends `no_grant` at exactly 180 s.
#[test]
fn a_late_unusable_grant_never_extends_the_renew_wait() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
    images.set_test_clock(0.0);
    let part = 64u64 << 10;
    let bytes = vec![8u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let control = FakeControl::new(&images, "tr-late", &base, part, bytes.len() as u64);
    images.handle_server(first_part_only(&control, &request));
    let mut frames = Vec::new();
    let until_renew = |frames: &mut Vec<DaemonControlMessage>, n: usize| {
        let deadline = Instant::now() + Duration::from_secs(30);
        while renews(frames) < n {
            assert!(
                Instant::now() < deadline,
                "renew {n} never sent: {frames:?}"
            );
            frames.extend(images.drain());
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    let held = || {
        let ServerControlMessage::ImageUploadGrant(mut grant) = control.grant(None, 1) else {
            unreachable!()
        };
        grant.parts.truncate(1);
        ServerControlMessage::ImageUploadGrant(grant)
    };
    for (n, delay) in [(1, 5u64), (2, 15), (3, 30)] {
        until_renew(&mut frames, n);
        images.advance_test_clock(Duration::from_secs(delay));
    }
    until_renew(&mut frames, 4);
    images.advance_test_clock(Duration::from_secs(59));
    images.handle_server(held());
    until_renew(&mut frames, 5);
    images.advance_test_clock(Duration::from_secs(59));
    images.handle_server(held());
    until_renew(&mut frames, 6);
    assert_eq!(
        images.test_pauses(),
        [Duration::from_secs(1)],
        "the pause is the rest of its step"
    );
    images.advance_test_clock(Duration::from_secs(10));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(images.uploads_finished(), 0, "ended before 180 s");
    images.advance_test_clock(Duration::from_secs(1));
    wait_uploads_finished(&images, 1);
    frames.extend(images.drain());
    assert_eq!(
        upload_sequence(&frames),
        [
            "parts", "renew", "renew", "renew", "renew", "parts", "renew", "parts", "renew",
            "failed"
        ],
        "{frames:?}"
    );
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-late"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
}

/// Fix 3 b#3: the begin's refusal-retry allowance starts at the first
/// transient refusal, whatever the first wait spent. PRODUCTION timings on
/// the virtual clock: the first begin is refused `store_unavailable` 250 s
/// into its 300 s grant wait; after the 5 s pause the retried begin is
/// granted 60 s later (65 s after the refusal, well inside its 180 s), and
/// the upload completes.
#[test]
fn a_late_first_begin_refusal_gets_the_whole_retry_allowance() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
    images.set_test_clock(0.0);
    let bytes = b"refused late in the first wait".to_vec();
    let first = start_capture_upload(&images, &runtime, &bytes);
    images.advance_test_clock(Duration::from_secs(250));
    refuse_begin(&images, &first, "store_unavailable");
    let DaemonControlMessage::ImageUploadBegin(again) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    }) else {
        unreachable!()
    };
    assert_eq!(images.test_pauses(), [Duration::from_secs(5)]);
    images.advance_test_clock(Duration::from_secs(60));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        images.uploads_finished(),
        0,
        "the retry allowance was cut by the first wait"
    );
    let mut control =
        FakeControl::new(&images, "tr-late-begin", &base, 1 << 20, bytes.len() as u64);
    images.handle_server(control.grant(again.request_id.as_deref(), 1));
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["parts", "complete"], "{frames:?}");
}

/// FB-B8: an overflowing outbox evicts advisory and ordinary frames, never
/// a resume or a terminal upload frame.
#[test]
fn an_overflowing_outbox_keeps_resumes_and_terminal_frames() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = service(
        &runtime,
        dir.path(),
        crate::config::ImageCacheSize::Gib(1),
        "http://127.0.0.1:9",
    );
    images.drain();
    images.push(JobRef::Transfer("tr-keep".into()).resume(7));
    images.push(DaemonControlMessage::ImageUploadComplete(
        ImageTransferRefV11 {
            transfer_id: "tr-keep".into(),
        },
    ));
    images.push(DaemonControlMessage::ImageUploadProgress(
        sandbox_protocol::ImageUploadProgressV11 {
            transfer_id: "tr-keep".into(),
            bytes_sent: 1,
            wire_bytes: 1,
        },
    ));
    for _ in 0..OUTBOX_MAX + 8 {
        images.push(DaemonControlMessage::ImageUploadRenew(
            sandbox_protocol::ImageUploadRenewV11 {
                transfer_id: "tr-keep".into(),
            },
        ));
    }
    let queued = images.queued();
    assert_eq!(queued.len(), OUTBOX_MAX);
    assert!(
        is_resume_of_transfer(&queued[0], "tr-keep"),
        "{:?}",
        &queued[..3]
    );
    assert!(matches!(
        queued[1],
        DaemonControlMessage::ImageUploadComplete(_)
    ));
    assert!(
        !queued
            .iter()
            .any(|f| matches!(f, DaemonControlMessage::ImageUploadProgress(_))),
        "the heartbeat goes first"
    );
}

/// test#2, W6 (b#6): renews the server leaves unanswered (over its budget)
/// are sent again on the production schedule, on the virtual upload clock:
/// 5, 15, 30, 60, 60 s, each re-send neither a second early nor late, within
/// one 180 s renew wait. Answered on the third, the upload completes; never
/// answered, the sixth renew's wait is cut to the 10 s left and the upload
/// ends `no_grant` by its transfer. The whole ordered sequence is asserted.
#[test]
fn a_dropped_renew_is_sent_again_and_unanswered_renews_end_no_grant() {
    for answered in [true, false] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
        images.set_test_clock(0.0);
        let part = 64u64 << 10;
        let bytes = vec![6u8; (2 * part) as usize];
        let request = start_capture_upload(&images, &runtime, &bytes);
        let mut control = FakeControl::new(&images, "tr-rn", &base, part, bytes.len() as u64);
        images.handle_server(first_part_only(&control, &request));
        let mut frames = Vec::new();
        let renews_so_far = |frames: &[DaemonControlMessage]| renews(frames);
        // Collect frames until the `n`th renew was sent.
        let until_renew = |frames: &mut Vec<DaemonControlMessage>, n: usize| {
            let deadline = Instant::now() + Duration::from_secs(30);
            while renews_so_far(frames) < n {
                assert!(
                    Instant::now() < deadline,
                    "renew {n} never sent: {frames:?}"
                );
                frames.extend(images.drain());
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        let delays = [5u64, 15, 30, 60, 60, 10];
        for (sent, delay) in delays.iter().enumerate() {
            until_renew(&mut frames, sent + 1);
            if answered && sent == 2 {
                for frame in &frames {
                    if let DaemonControlMessage::ImageUploadParts(p) = frame {
                        control.recorded.extend(p.parts.iter().map(|p| p.n));
                    }
                }
                images.handle_server(control.grant(None, control.lowest_unrecorded()));
                break;
            }
            // A second short of its delay nothing more is sent.
            images.advance_test_clock(Duration::from_secs(delay - 1));
            std::thread::sleep(Duration::from_millis(300));
            frames.extend(images.drain());
            assert_eq!(renews(&frames), sent + 1, "re-sent early: {frames:?}");
            assert_eq!(images.uploads_finished(), 0, "ended early: {frames:?}");
            images.advance_test_clock(Duration::from_secs(1));
        }
        wait_uploads_finished(&images, 1);
        frames.extend(images.drain());
        if answered {
            assert_eq!(
                upload_sequence(&frames),
                ["parts", "renew", "renew", "renew", "parts", "complete"],
                "{frames:?}"
            );
        } else {
            let mut expected = vec!["parts"];
            expected.extend(["renew"; 6]);
            expected.push("failed");
            assert_eq!(upload_sequence(&frames), expected, "{frames:?}");
            let failed = the_failure(&frames);
            assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
            assert_eq!(failed.transfer_id.as_deref(), Some("tr-rn"));
        }
    }
}

/// A socket stream that takes `accepts` writes, then fails every write and
/// flush (nothing to read).
struct FailingStream {
    accepts: usize,
}

impl std::io::Read for FailingStream {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl std::io::Write for FailingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.accepts == 0 {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        self.accepts -= 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.accepts == 0 {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

/// Frames of a failed image batch that are not replayed (fix 4): a capture
/// and a publish begin, a census page, disk offload parts, completion and
/// inventory, and operation progress.
fn not_replayed_frames(images: &ImageService) -> Vec<DaemonControlMessage> {
    images.begin_census();
    let census = images.drain();
    assert!(
        census
            .iter()
            .any(|f| matches!(f, DaemonControlMessage::ImageCacheCensus(_))),
        "{census:?}"
    );
    let begin = |transfer: Option<&str>, request: Option<&str>| {
        DaemonControlMessage::ImageUploadBegin(ImageUploadBeginV11 {
            transfer_id: transfer.map(str::to_owned),
            operation_id: request.map(|_| "op-other".to_owned()),
            request_id: request.map(str::to_owned),
            attempt: request.map(|_| 1),
            fingerprint: format!("sha256:{}", "e".repeat(64)),
            size_bytes: 10,
            unpacked_bytes: None,
            format: "unified".into(),
        })
    };
    let mut frames = vec![
        begin(None, Some("upload-other")),
        begin(Some("tr-pub"), None),
    ];
    frames.extend(census);
    frames.extend([
        DaemonControlMessage::DiskUploadParts(sandbox_protocol::DiskUploadPartsV11 {
            sandbox_id: "sbx-1".into(),
            offload_id: "off-1".into(),
            seq: 1,
            session_id: "ses-1".into(),
            parts: Vec::new(),
        }),
        DaemonControlMessage::DiskUploadComplete(sandbox_protocol::DiskUploadCompleteV11 {
            sandbox_id: "sbx-1".into(),
            offload_id: "off-1".into(),
            seq: 1,
            session_id: "ses-1".into(),
        }),
        DaemonControlMessage::DiskOffloadInventory(sandbox_protocol::DiskOffloadInventoryV11 {
            entries: vec![sandbox_protocol::DiskOffloadInventoryEntryV11 {
                sandbox_id: "sbx-1".into(),
                offload_id: "off-1".into(),
                seq: 1,
            }],
        }),
        DaemonControlMessage::OperationProgress {
            id: "p-1".into(),
            operation_id: "op-other".into(),
            sandbox_id: "sbx-1".into(),
            generation: 1,
            attempt: 1,
            state: sandbox_protocol::OperationState::Running,
            progress: None,
        },
    ]);
    frames
}

/// W1 (a#1, b#1), fix 3 a#1, fix 4: sent means written AND flushed. A
/// socket write that fails in the middle of a batch, or a flush that fails
/// after every write was buffered: none of the batch is known to have left,
/// so the job whose failure was among it stays in the resume registry. Of
/// that batch only the upload progress and terminal frames go back to the
/// front of the outbox, in order; its begins, census page, disk offload
/// frames and operation progress (interleaved with them here) are dropped.
/// The next connection gets the job's resume first, then exactly those
/// frames with the failure and its cause; only once they are written and
/// flushed is the job retired.
#[test]
fn a_failure_whose_write_or_flush_failed_is_sent_after_the_next_resume_with_its_cause() {
    for flush_fails in [false, true] {
        let runtime = FakeRuntime::default();
        let dir = tempfile::tempdir().unwrap();
        let (base, _, _s3) = scripted_s3(|_, reader, length| store_status(reader, length, 503));
        let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
        images.set_heartbeat_for_test(Duration::ZERO);
        let bytes = vec![1u8; 64 << 10];
        let request = start_capture_upload(&images, &runtime, &bytes);
        let others = not_replayed_frames(&images);
        let (before, after) = others.split_at(4);
        for frame in before {
            images.push_frame(frame.clone());
        }
        let control = FakeControl::new(&images, "tr-write", &base, 1 << 20, bytes.len() as u64);
        images.handle_server(control.grant(Some(&request), 1));
        wait_uploads_finished(&images, 1);
        for frame in after {
            images.push_frame(frame.clone());
        }
        let queued = images.queued();
        assert!(queued.len() <= 32, "one batch: {queued:?}");
        let shown = |frames: &[DaemonControlMessage]| format!("{frames:?}");
        let replayed: Vec<DaemonControlMessage> = queued
            .iter()
            .filter(|f| !others.iter().any(|o| format!("{f:?}") == format!("{o:?}")))
            .cloned()
            .collect();
        assert!(replayed.len() >= 2, "{replayed:?}");
        assert!(
            replayed.iter().all(|f| matches!(
                f,
                DaemonControlMessage::ImageUploadParts(_)
                    | DaemonControlMessage::ImageUploadProgress(_)
                    | DaemonControlMessage::ImageJobFailed(_)
            )),
            "{replayed:?}"
        );
        assert!(matches!(
            replayed.last(),
            Some(DaemonControlMessage::ImageJobFailed(_))
        ));
        // The production write path (`connect::send_image_batch`) over a
        // WebSocket whose stream fails: with tungstenite's default write
        // buffer every `write` only buffers and succeeds, and the flush
        // fails; with no write buffer, the stream takes the first frame and
        // the write of the second fails.
        let (accepts, config) = if flush_fails {
            (0, None)
        } else {
            (
                1,
                Some(tungstenite::protocol::WebSocketConfig::default().write_buffer_size(0)),
            )
        };
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            FailingStream { accepts },
            tungstenite::protocol::Role::Client,
            config,
        );
        let result = crate::sandbox_relay::connect::send_image_batch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &images,
        );
        assert!(
            result.is_err(),
            "the socket failed (flush fails: {flush_fails})"
        );
        assert_eq!(
            shown(&images.queued()),
            shown(&replayed),
            "only the allowlisted frames are kept, in order (flush fails: {flush_fails})"
        );
        assert_eq!(
            images.resumable_jobs(),
            1,
            "retired before its failure was flushed"
        );
        images.on_disconnect();
        images.on_registered("host-owner");
        let mut frames = Vec::new();
        loop {
            let batch = images.drain();
            if batch.is_empty() {
                break;
            }
            frames.extend(batch);
        }
        assert!(is_resume_of_transfer(&frames[0], "tr-write"), "{frames:?}");
        assert_eq!(shown(&frames[1..]), shown(&replayed));
        let failed = the_failure(&frames);
        assert_eq!(
            failed.cause,
            sandbox_protocol::ImageFailureCause::HttpStatus
        );
        assert_eq!(failed.http_status, Some(503));
        assert_eq!(images.resumable_jobs(), 0);
    }
}

/// Fix 4 (r4 #1): a publish begin the server took (it made the session and
/// granted) in a batch whose flush then failed. The begin is not replayed:
/// the next connection carries only the transfer's resume, and the upload
/// completes on the grant it got. (A replayed begin would be answered
/// `stale_transfer`, as the server does here, and end the healthy upload.)
#[test]
fn a_publish_begin_in_a_failed_batch_is_not_replayed() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = vec![3u8; 64 << 10];
    let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
    let job = images.clone();
    std::thread::spawn(move || job.upload(&fp, "owner-a", UploadJob::Publish("tr-pub".into())));
    wait_queued(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    });
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        FailingStream { accepts: 0 },
        tungstenite::protocol::Role::Client,
        None,
    );
    assert!(
        crate::sandbox_relay::connect::send_image_batch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &images,
        )
        .is_err()
    );
    // The server took the begin: its grant arrived on the old connection.
    let mut control = FakeControl::new(&images, "tr-pub", &base, 1 << 20, bytes.len() as u64);
    images.handle_server(control.grant(None, 1));
    images.on_disconnect();
    images.on_registered("host-owner");
    let first = images.drain();
    assert!(
        first
            .iter()
            .all(|f| !matches!(f, DaemonControlMessage::ImageUploadBegin(_))),
        "{first:?}"
    );
    assert!(is_resume_of_transfer(&first[0], "tr-pub"), "{first:?}");
    answer_transfer_resume(&images, "tr-pub", true);
    let frames = control.run(&mut |frame, images| {
        if let DaemonControlMessage::ImageUploadBegin(b) = frame
            && b.transfer_id.as_deref() == Some("tr-pub")
        {
            images.handle_server(ServerControlMessage::ImageJobCancel(
                sandbox_protocol::ImageJobCancelV11 {
                    transfer_id: "tr-pub".into(),
                    reason: "stale_transfer".into(),
                    request_id: None,
                },
            ));
        }
    });
    assert_eq!(upload_kinds(&frames), ["parts", "complete"], "{frames:?}");
    assert_eq!(images.resumable_jobs(), 0);
}

/// W3 (b#2, a#3): a reconnect while a renew waits, and the resume is never
/// answered. The resume wait spends the renew's one 180 s budget (virtual
/// clock): one second short of it the upload still waits, at 180 s it ends
/// `no_grant` by its transfer (not after a further grant wait of its own).
#[test]
fn a_resume_inside_a_renew_spends_the_renew_wait() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
    images.set_test_clock(0.0);
    let part = 64u64 << 10;
    let bytes = vec![2u8; (2 * part) as usize];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let control = FakeControl::new(&images, "tr-rsw", &base, part, bytes.len() as u64);
    images.handle_server(first_part_only(&control, &request));
    wait_queued(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadRenew(_))
    });
    images.on_registered("host-owner");
    images.advance_test_clock(Duration::from_secs(179));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(images.uploads_finished(), 0, "ended before the renew wait");
    images.advance_test_clock(Duration::from_secs(1));
    let frames = upload_frames(&images);
    assert_eq!(
        upload_sequence(&frames),
        ["resume", "parts", "renew", "failed"],
        "{frames:?}"
    );
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-rsw"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::NoGrant);
}

/// W3 (a#3, a#7): a capture begin refused `store_unavailable`, then a relay
/// reconnect while the retried begin waits, and the resume is never
/// answered. The resume wait is inside the begin's retry budget (180 s from
/// the refusal, 5 s of it paused): one second short of it the capture still
/// waits; at the deadline it is reported `refused` with the remembered
/// `store_unavailable`, by operation.
#[test]
fn a_resume_inside_a_begin_retry_keeps_the_retry_deadline_and_its_refusal() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
    images.set_upload_timings_for_test(UploadTimings::PRODUCTION);
    images.set_test_clock(0.0);
    let bytes = b"begin retry then reconnect".to_vec();
    let request = start_capture_upload(&images, &runtime, &bytes);
    refuse_begin(&images, &request, "store_unavailable");
    let DaemonControlMessage::ImageUploadBegin(_) = wait_frame(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    }) else {
        unreachable!()
    };
    assert_eq!(images.test_pauses(), [Duration::from_secs(5)]);
    images.on_registered("host-owner");
    images.advance_test_clock(Duration::from_secs(174));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        images.uploads_finished(),
        0,
        "ended before the begin deadline"
    );
    images.advance_test_clock(Duration::from_secs(1));
    let frames = upload_frames(&images);
    assert_eq!(upload_sequence(&frames), ["resume", "failed"], "{frames:?}");
    assert!(is_resume_of_operation(&frames[0], "op-up", 4));
    let failed = the_failure(&frames);
    assert_eq!(
        (failed.operation_id.as_deref(), failed.attempt),
        (Some("op-up"), Some(4))
    );
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Refused);
    assert_eq!(failed.refusal.as_deref(), Some("store_unavailable"));
}

/// W4 (a#5, b#3), fix 3 b#4: the relay reconnects while the upload still
/// exports (held here on a channel that also says when the export started),
/// and the server answers the capture's resume at once. The answer is kept
/// for the job (its waiter exists before the job is visible to a
/// reconnect): once the export finishes the capture begins at once, on the
/// virtual upload clock that never moves here, so no grant wait can run
/// out on a slow test thread. Were the answer lost, the job would wait for
/// it forever on that clock; the watchdog then moves the clock past the
/// grant wait so the job ends, and fails the test.
#[test]
fn a_resume_answered_during_the_export_is_kept() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_ok(reader, length));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_test_clock(0.0);
    let (export, exporting) = images.hold_exports_for_test();
    let bytes = b"reconnect while exporting".to_vec();
    let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
    let mut d = dispatch(&fp, bytes.len() as u64, "owner-a");
    d.operation_id = "op-up".into();
    d.attempt = 4;
    images
        .captured(&d, &fp, bytes.len() as u64, true)
        .expect("captured");
    // The job is in the resume registry before its export starts (W4).
    exporting
        .recv_timeout(Duration::from_secs(60))
        .expect("the export never started");
    assert_eq!(images.resumable_jobs(), 1);
    images.on_registered("host-owner");
    let frames = images.drain();
    assert!(is_resume_of_operation(&frames[0], "op-up", 4), "{frames:?}");
    answer_operation_resume(&images, "op-up", 4, true);
    export.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let begin = loop {
        let begin = images.drain().into_iter().find_map(|f| match f {
            DaemonControlMessage::ImageUploadBegin(b) => Some(b),
            _ => None,
        });
        if let Some(begin) = begin {
            break begin;
        }
        if Instant::now() >= deadline {
            images.advance_test_clock(Duration::from_secs(3600));
            wait_uploads_finished(&images, 1);
            panic!("the resume answer given during the export was lost");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut control = FakeControl::new(&images, "tr-exp", &base, 1 << 20, bytes.len() as u64);
    images.handle_server(control.grant(begin.request_id.as_deref(), 1));
    let frames = control.run(&mut no_hook());
    assert_eq!(upload_kinds(&frames), ["parts", "complete"], "{frames:?}");
}

/// W6 (b#5), V2: a grant's URLs lapse `ttlSeconds` after it was routed, not
/// after the upload read it. The begin's grant (120 s, renewed under 60 s
/// left) is routed, then ages 61 s on the virtual clock before the upload
/// can take it (the test holds the registry the upload needs first): its
/// URL is past the margin, so the upload renews and uses only grant 2.
#[test]
fn a_buffered_grant_ages_from_when_it_was_routed() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let book = Book::default();
    let checked = book.clone();
    let paths: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = paths.clone();
    let (base, _, _s3) = scripted_s3_paths(move |_, path, reader, length| {
        seen.lock().unwrap().push(path.to_owned());
        book_store(&checked, path, reader, length, store_ok);
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_test_clock(0.0);
    book.lock().unwrap().clock = Some(images.clone());
    let bytes = b"a grant that waited".to_vec();
    let request = start_capture_upload(&images, &runtime, &bytes);
    let mut control = FakeControl::new(&images, "tr-age", &base, 1 << 20, bytes.len() as u64);
    control.book = book;
    control.ttl = 120;
    {
        let _held = images.inner.resumable.lock().unwrap();
        images.handle_server(control.grant(Some(&request), 1));
        images.advance_test_clock(Duration::from_secs(61));
    }
    let frames = control.run(&mut no_hook());
    assert_eq!(
        upload_sequence(&frames),
        ["renew", "parts", "complete"],
        "{frames:?}"
    );
    assert_eq!(paths.lock().unwrap().clone(), ["/g2/p1"]);
}

/// test#3: three parts that each succeed only on their fourth attempt: the
/// attempt budget is per part, the store ends up with exactly the image's
/// bytes, and the heartbeats keep rising across the retransmissions
/// (`wireBytes` strictly, `bytesSent` never back).
#[test]
fn every_part_gets_its_own_four_attempts() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let tries: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
    let stored: Arc<Mutex<std::collections::BTreeMap<u32, Vec<u8>>>> = Arc::default();
    let (count, keep) = (tries.clone(), stored.clone());
    let (base, connections, _s3) = scripted_s3_paths(move |_, path, mut reader, length| {
        let n: u32 = path.rsplit("/p").next().unwrap().parse().unwrap();
        let tried = {
            let mut tries = count.lock().unwrap();
            let entry = tries.entry(format!("p{n}")).or_default();
            *entry += 1;
            *entry
        };
        if tried < PART_ATTEMPTS as usize {
            return store_status(reader, length, 503);
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        keep.lock().unwrap().insert(n, body);
        let mut stream = reader.into_inner();
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    images.set_heartbeat_for_test(Duration::ZERO);
    let part = 64u64 << 10;
    let bytes: Vec<u8> = (0..(3 * part) as usize).map(|i| (i % 251) as u8).collect();
    let frames = run_capture(&images, &runtime, &base, &bytes, part, "tr-each");
    assert_eq!(upload_kinds(&frames), ["parts", "complete"]);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        3 * PART_ATTEMPTS as usize
    );
    let stored: Vec<u8> = stored.lock().unwrap().values().flatten().copied().collect();
    assert!(stored == bytes, "stored bytes differ");
    let beats: Vec<(u64, u64)> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadProgress(p) => Some((p.bytes_sent, p.wire_bytes)),
            _ => None,
        })
        .collect();
    assert!(beats.windows(2).all(advanced), "{beats:?}");
    assert_eq!(beats.last().map(|b| b.0), Some(bytes.len() as u64));
    // Every attempt's body went out again (the wire count also has each
    // request's head, as the socket took it).
    let wire = beats.last().map_or(0, |b| b.1);
    let bodies = bytes.len() as u64 * u64::from(PART_ATTEMPTS);
    assert!(
        (bodies..bodies + 12 * 4096).contains(&wire),
        "{wire} wire bytes for {bodies} body bytes"
    );
}

/// Fix 5 (r5 #1): an older run's final census page still queued behind a
/// batch whose write failed is purged when the next connection starts its
/// census: only the fresh census reaches the server.
#[test]
fn an_old_census_page_queued_behind_a_failed_batch_is_gone_after_reconnect() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
    images.begin_census();
    let fresh: Vec<DaemonControlMessage> = images
        .drain()
        .into_iter()
        .filter(|f| matches!(f, DaemonControlMessage::ImageCacheCensus(_)))
        .collect();
    let [DaemonControlMessage::ImageCacheCensus(page)] = fresh.as_slice() else {
        panic!("{fresh:?}")
    };
    // An older run's last page (marked by its page number), queued behind a
    // full batch of other frames.
    let mut old = page.clone();
    old.page = 7;
    old.complete = true;
    for i in 0..BATCH_MAX {
        images.push_frame(DaemonControlMessage::ImageUploadBegin(
            ImageUploadBeginV11 {
                transfer_id: Some(format!("tr-filler-{i}")),
                operation_id: None,
                request_id: None,
                attempt: None,
                fingerprint: format!("sha256:{}", "e".repeat(64)),
                size_bytes: 10,
                unpacked_bytes: None,
                format: "unified".into(),
            },
        ));
    }
    images.push_frame(DaemonControlMessage::ImageCacheCensus(old));
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        FailingStream { accepts: 0 },
        tungstenite::protocol::Role::Client,
        None,
    );
    assert!(
        crate::sandbox_relay::connect::send_image_batch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &images,
        )
        .is_err()
    );
    assert!(
        images
            .queued()
            .iter()
            .any(|f| matches!(f, DaemonControlMessage::ImageCacheCensus(c) if c.page == 7)),
        "the old page was behind the failed batch"
    );
    images.on_disconnect();
    images.on_registered("host-owner");
    images.begin_census();
    let mut frames = Vec::new();
    loop {
        let batch = images.drain();
        if batch.is_empty() {
            break;
        }
        frames.extend(batch);
    }
    let census: Vec<u64> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageCacheCensus(c) => Some(c.page),
            _ => None,
        })
        .collect();
    assert_eq!(census, vec![0], "{frames:?}");
}

/// Fix 5 (r5 #3): a job retired by a definitive resume refusal
/// (`continue: false`) takes its queued resume and terminal frame with it.
#[test]
fn a_refused_resume_removes_the_retired_jobs_queued_protected_frames() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, _, _s3) = scripted_s3(|_, reader, length| store_status(reader, length, 503));
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = vec![1u8; 64 << 10];
    let request = start_capture_upload(&images, &runtime, &bytes);
    let control = FakeControl::new(&images, "tr-refused", &base, 1 << 20, bytes.len() as u64);
    images.handle_server(control.grant(Some(&request), 1));
    wait_uploads_finished(&images, 1);
    images.on_disconnect();
    images.on_registered("host-owner");
    let job = JobRef::Transfer("tr-refused".into());
    let queued = images.queued();
    assert!(
        is_resume_of_transfer(&queued[0], "tr-refused"),
        "{queued:?}"
    );
    assert!(
        queued
            .iter()
            .any(|f| matches!(f, DaemonControlMessage::ImageJobFailed(_))),
        "{queued:?}"
    );
    assert_eq!(images.resumable_jobs(), 1);
    answer_transfer_resume(&images, "tr-refused", false);
    assert_eq!(images.resumable_jobs(), 0);
    let left = images.queued();
    assert!(left.iter().all(|f| !job.names(f)), "{left:?}");
}

/// Fix 5 (r5 #3): a new upload job waits while the protected backlog is at
/// `PROTECTED_MAX` (nothing registered, nothing sent) and starts once it
/// drops below.
#[test]
fn a_new_upload_waits_while_the_protected_backlog_is_full() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let images = idle_service(&runtime, dir.path(), "http://127.0.0.1:9", FRAME_TEST_IDLE);
    for i in 0..PROTECTED_MAX {
        images.push_frame(JobRef::Transfer(format!("tr-backlog-{i}")).resume(0));
    }
    let bytes = vec![3u8; 64 << 10];
    let fp = runtime.seed_image_bytes(&bytes, "x86_64", true);
    let job = images.clone();
    std::thread::spawn(move || job.upload(&fp, "owner-a", UploadJob::Publish("tr-adm".into())));
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(images.resumable_jobs(), 0, "admitted over the bound");
    assert!(
        images
            .queued()
            .iter()
            .all(|f| !matches!(f, DaemonControlMessage::ImageUploadBegin(_)))
    );
    // One protected frame leaves: below the bound, the job starts.
    images.purge_queued(|f| is_resume_of_transfer(f, "tr-backlog-0"));
    wait_queued(&images, |f| {
        matches!(f, DaemonControlMessage::ImageUploadBegin(_))
    });
    assert_eq!(images.resumable_jobs(), 1);
    images.handle_server(ServerControlMessage::ImageJobCancel(
        sandbox_protocol::ImageJobCancelV11 {
            transfer_id: "tr-adm".into(),
            reason: "cancelled".into(),
            request_id: None,
        },
    ));
    wait_uploads_finished(&images, 1);
}
