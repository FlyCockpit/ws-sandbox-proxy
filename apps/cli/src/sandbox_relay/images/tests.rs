//! FakeRuntime + loopback HTTP tests for the image cache (no Incus, no
//! network beyond 127.0.0.1). The S3 store and the server relay are tiny
//! fixed responders; the control plane is played by the test thread.

use super::*;
use sandbox_runtime::FakeRuntime;
use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;

const GIB: u64 = 1 << 30;

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

/// A store that accepts the PUT and then stops reading: the write stalls
/// and the upload ends `stalled` after the idle bound, by its transfer. The
/// store holds the socket until the client has failed (never a reset race).
#[test]
fn a_stalled_part_upload_ends_stalled_after_the_idle_bound() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (failed, held) = mpsc::channel::<()>();
    let base = fake_s3(move |reader| {
        // Watchdog only: released once the client reported its failure.
        let _ = held.recv_timeout(Duration::from_secs(60));
        drop(reader);
    });
    let images = idle_service(&runtime, dir.path(), &base, Duration::from_millis(300));
    let bytes = vec![5u8; 32 << 20];
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(capture_grant(
        &request,
        "tr-stall",
        format!("{base}/p1"),
        bytes.len() as u64,
    ));
    let frames = upload_frames(&images);
    let _ = failed.send(());
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-stall"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Stalled);
    assert_eq!(failed.code, ImageFailureCode::Timeout);
    assert_eq!(failed.part, Some(1));
}

/// A store answering 503 ends the upload `http_status` with the status.
#[test]
fn a_store_error_status_is_reported_with_its_status() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let (base, server) = responder(vec![(503, Vec::new(), Vec::new())]);
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = b"captured image bytes".to_vec();
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(capture_grant(
        &request,
        "tr-503",
        format!("{base}/p1"),
        bytes.len() as u64,
    ));
    let frames = upload_frames(&images);
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-503"));
    assert_eq!(
        failed.cause,
        sandbox_protocol::ImageFailureCause::HttpStatus
    );
    assert_eq!(failed.http_status, Some(503));
    assert_eq!(failed.part, Some(1));
    server.join().unwrap();
}

/// A connection closed mid-body ends the upload `reset`.
#[test]
fn a_connection_closed_mid_body_is_a_reset() {
    let runtime = FakeRuntime::default();
    let dir = tempfile::tempdir().unwrap();
    let base = fake_s3(|mut reader| {
        let mut some = vec![0u8; 1 << 20];
        let _ = reader.read_exact(&mut some);
        // Unread data in the receive buffer: the close is an RST.
        drop(reader);
    });
    let images = idle_service(&runtime, dir.path(), &base, FRAME_TEST_IDLE);
    let bytes = vec![9u8; 32 << 20];
    let request = start_capture_upload(&images, &runtime, &bytes);
    images.handle_server(capture_grant(
        &request,
        "tr-reset",
        format!("{base}/p1"),
        bytes.len() as u64,
    ));
    let frames = upload_frames(&images);
    assert_eq!(upload_kinds(&frames), ["failed"]);
    let failed = the_failure(&frames);
    assert_eq!(failed.transfer_id.as_deref(), Some("tr-reset"));
    assert_eq!(failed.cause, sandbox_protocol::ImageFailureCause::Reset);
    assert_eq!(failed.part, Some(1));
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
    let beats: Vec<u64> = frames
        .iter()
        .filter_map(|f| match f {
            DaemonControlMessage::ImageUploadProgress(p) => {
                assert_eq!(p.transfer_id, "tr-slow");
                assert!(p.is_valid());
                Some(p.bytes_sent)
            }
            _ => None,
        })
        .collect();
    assert!(beats.len() >= 2, "{beats:?}");
    assert!(beats.windows(2).all(|w| w[0] < w[1]), "{beats:?}");
    assert!(beats.iter().all(|b| *b <= len as u64));
}

/// A heartbeat carries the stored-object offset reached, only when it moved
/// past the last one sent, and at most every interval (no clock involved:
/// a zero interval sends on every advance, an hour never twice).
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
    let beats = |images: &ImageService| -> Vec<u64> {
        images
            .drain()
            .into_iter()
            .filter_map(|f| match f {
                DaemonControlMessage::ImageUploadProgress(p) => Some(p.bytes_sent),
                _ => None,
            })
            .collect()
    };
    images.drain();
    images.set_heartbeat_for_test(Duration::ZERO);
    let heartbeat = images.heartbeat("tr-hb");
    heartbeat.reach(10);
    heartbeat.reach(10);
    heartbeat.reach(5);
    heartbeat.reach(20);
    assert_eq!(beats(&images), [10, 20]);
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
    assert_eq!(beats(&images), [1003]);
    images.set_heartbeat_for_test(Duration::from_secs(3600));
    let throttled = images.heartbeat("tr-hb2");
    throttled.reach(10);
    throttled.reach(20);
    assert!(beats(&images).is_empty());
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
                let (base, server) = responder(vec![(503, Vec::new(), Vec::new())]);
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
        for field in ["http_status", "503", "connect", "part", "tr-log", "io_kind"] {
            assert!(logs.contains(field), "{field} missing: {logs}");
        }
        for secret in [SIG, KEY, "X-Amz", "bucket.example"] {
            assert!(!logs.contains(secret), "{secret} leaked: {logs}");
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
