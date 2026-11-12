//! Proxy mode tests: the smuggling / framing vector table,
//! the method allowlist against a reflecting upstream, per-entry
//! handles and connection binding, revocation, response leakage, the
//! upstream address rules, and a sentinel check that the value never
//! appears in logs, Debug output or the guest-visible stream.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_protocol::{
    CredentialDelivery, CredentialLeaseKind, CredentialRotates, SpecFilesV11, SpecLeaseAction,
    SpecLeaseV11, SpecProxyV11,
};

use sandbox_runtime::guard::ceiling::EgressCeiling;
use sandbox_runtime::guard::net::Ipv4Net;
use sandbox_runtime::guard::ruleset::GuardInputs;

use super::http::{self, BodyFraming, Status};
use super::testing::{
    Mode, PlainConnector, TestUpstream, closed, contains, exchange, read_response, settings,
};
use super::upstream::{self, Connector, TlsConnector, UpstreamError};
use super::{ProxyHub, ProxyInstallError, SecretBytes, bridge_peer};

const SANDBOX: &str = "sbx-proxy";
/// The proxied value: never in a log, a Debug string, the journal or any
/// byte the guest receives from the proxy itself.
const SECRET: &[u8] = b"sk-SENTINEL-proxy-7f3a9c41";
const SECRET_B: &[u8] = b"sk-SENTINEL-other-0b88e2d5";
const HOST_A: &str = "api-a.example.test";
const HOST_B: &str = "api-b.example.test";

fn entry(name: &str, host: &str, base: &str) -> SpecProxyV11 {
    SpecProxyV11 {
        name: name.into(),
        upstream: format!("https://{host}/v1"),
        header: "Authorization".into(),
        format: "Bearer {value}".into(),
        base_url_env: base.into(),
        placeholder_env: Some(name.into()),
    }
}

fn proxied_lease(id: &str, entries: Vec<SpecProxyV11>) -> SpecLeaseV11 {
    SpecLeaseV11 {
        lease_id: id.into(),
        binding_id: Some(format!("bind-{id}")),
        credential_id: format!("cred-{id}"),
        instance_id: "inst-1".into(),
        definition_digest: "ab".repeat(32),
        max_bytes: 4096,
        delivery: CredentialDelivery::Proxy,
        exclusive: true,
        copy_back: false,
        rotates: CredentialRotates::Unknown,
        kind: CredentialLeaseKind::Workload,
        action: SpecLeaseAction::Inject,
        files: SpecFilesV11::default(),
        env: entries.iter().map(|e| e.name.clone()).collect(),
        proxy: entries,
        checkpoint_interval_min: None,
    }
}

struct Fixture {
    hub: ProxyHub,
    connector: Arc<PlainConnector>,
    a: TestUpstream,
    b: TestUpstream,
    /// Guest env per installed entry.
    env: Vec<(String, String)>,
    handles: Vec<String>,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        let connector = Arc::new(PlainConnector::default());
        let a = TestUpstream::start(mode.clone());
        let b = TestUpstream::start(mode);
        connector.route(HOST_A, a.addr);
        connector.route(HOST_B, b.addr);
        let hub = ProxyHub::new(settings(connector.clone()));
        let lease = proxied_lease(
            "lease-1",
            vec![
                entry("KEY_A", HOST_A, "A_BASE_URL"),
                entry("KEY_B", HOST_B, "B_BASE_URL"),
            ],
        );
        let handles = super::new_handles(2).unwrap();
        let values = vec![
            ("KEY_A".to_owned(), SecretBytes::copy_from(SECRET)),
            ("KEY_B".to_owned(), SecretBytes::copy_from(SECRET_B)),
        ];
        let env = hub
            .install(SANDBOX, &lease, "bind-lease-1", &handles, Some(&values))
            .unwrap();
        Self {
            hub,
            connector,
            a,
            b,
            env,
            handles,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.hub.listen_addr(SANDBOX).unwrap()
    }

    fn path(&self, entry: usize, rest: &str) -> String {
        format!("/c/{}{rest}", self.handles[entry])
    }

    fn get(&self, entry: usize, rest: &str) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: gw\r\n\r\n",
            self.path(entry, rest)
        )
        .into_bytes()
    }
}

/// Nothing the proxy itself writes to the guest may carry a value.
fn assert_clean(guest: &[u8]) {
    assert!(!contains(guest, SECRET), "value in the guest stream");
    assert!(!contains(guest, SECRET_B), "value in the guest stream");
}

// --- pure parser tables ----------------------------------------------------------

/// Request vectors → the status the proxy answers (and never forwards).
const REQUEST_VECTORS: &[(&str, &[u8], Status)] = &[
    // Method allowlist, before anything else.
    ("trace", b"TRACE /c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("track", b"TRACK /c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("connect", b"CONNECT api-a.example.test:443 HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("propfind", b"PROPFIND /c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("extension", b"FOO /c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("lowercase get", b"get /c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::MethodNotAllowed),
    ("trace with smuggled head", b"TRACE /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", Status::MethodNotAllowed),
    // Framing.
    ("cl+te", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", Status::BadRequest),
    ("te+cl", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n", Status::BadRequest),
    ("duplicate cl", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n", Status::BadRequest),
    ("cl list", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 4, 4\r\n\r\n", Status::BadRequest),
    ("cl sign", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: +4\r\n\r\n", Status::BadRequest),
    ("cl overflow", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 99999999999999999999\r\n\r\n", Status::BadRequest),
    ("te gzip", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Status::BadRequest),
    ("te twice", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", Status::BadRequest),
    ("te identity", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: identity\r\n\r\n", Status::BadRequest),
    ("te padded", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nTransfer-Encoding: xchunked\r\n\r\n", Status::BadRequest),
    ("body too large", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nContent-Length: 33554433\r\n\r\n", Status::PayloadTooLarge),
    // Line endings, folding, control bytes, names.
    ("obs-fold", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nX-A: 1\r\n folded\r\n\r\n", Status::BadRequest),
    ("bare lf", b"GET /c/H/x HTTP/1.1\nHost: g\r\n\r\n", Status::BadRequest),
    ("bare cr", b"GET /c/H/x HTTP/1.1\r\nHost: g\rX: y\r\n\r\n", Status::BadRequest),
    ("ctl in value", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nX-A: a\x01b\r\n\r\n", Status::BadRequest),
    ("nul in value", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nX-A: a\x00b\r\n\r\n", Status::BadRequest),
    ("space before colon", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nX-A : b\r\n\r\n", Status::BadRequest),
    ("non-token name", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nX(A): b\r\n\r\n", Status::BadRequest),
    // Host.
    ("no host", b"GET /c/H/x HTTP/1.1\r\nX: y\r\n\r\n", Status::BadRequest),
    ("two hosts", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nHost: evil.example\r\n\r\n", Status::BadRequest),
    // Version.
    ("http/1.0", b"GET /c/H/x HTTP/1.0\r\nHost: g\r\n\r\n", Status::VersionNotSupported),
    ("http/2 preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Status::MethodNotAllowed),
    // Upgrade and expectations.
    ("upgrade", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nUpgrade: websocket\r\n\r\n", Status::BadRequest),
    ("connection upgrade", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nConnection: keep-alive, Upgrade\r\n\r\n", Status::BadRequest),
    ("connection non-token", b"GET /c/H/x HTTP/1.1\r\nHost: g\r\nConnection: a b\r\n\r\n", Status::BadRequest),
    ("expect other", b"POST /c/H/x HTTP/1.1\r\nHost: g\r\nExpect: 200-ok\r\nContent-Length: 1\r\n\r\n", Status::ExpectationFailed),
    // Targets.
    ("absolute-form", b"GET http://api-a.example.test/c/H/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("asterisk-form", b"OPTIONS * HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("fragment", b"GET /c/H/x#y HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("backslash", b"GET /c/H/x\\y HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("double slash", b"GET /c/H//evil.example/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("inner double slash", b"GET /c/H/a//b HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("dot segment", b"GET /c/H/a/../../admin HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("encoded dot segment", b"GET /c/H/%2e%2E/admin HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("single dot", b"GET /c/H/./x HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("encoded slash", b"GET /c/H/a%2Fb HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("encoded backslash", b"GET /c/H/a%5cb HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("encoded nul", b"GET /c/H/a%00b HTTP/1.1\r\nHost: g\r\n\r\n", Status::BadRequest),
    ("encoded slash in prefix", b"GET /c%2fH/x HTTP/1.1\r\nHost: g\r\n\r\n", Status::NotFound),
    ("other prefix", b"GET /admin HTTP/1.1\r\nHost: g\r\n\r\n", Status::NotFound),
    ("handle suffix", b"GET /c/Hzz HTTP/1.1\r\nHost: g\r\n\r\n", Status::Forbidden),
    ("short handle", b"GET /c/abc HTTP/1.1\r\nHost: g\r\n\r\n", Status::Forbidden),
    ("uppercase handle", b"GET /c/0123456789ABCDEF0123456789abcdef HTTP/1.1\r\nHost: g\r\n\r\n", Status::Forbidden),
];

const HANDLE_PLACEHOLDER: &str = "/c/H";
const SAMPLE_HANDLE: &str = "0123456789abcdef0123456789abcdef";

fn with_handle(raw: &[u8], handle: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw).into_owned();
    if raw.iter().any(|b| *b >= 0x80) {
        return raw.to_vec();
    }
    text.replacen(HANDLE_PLACEHOLDER, &format!("/c/{handle}"), 1)
        .into_bytes()
}

#[test]
fn request_vector_table() {
    for (name, raw, expected) in REQUEST_VECTORS {
        let raw = with_handle(raw, SAMPLE_HANDLE);
        let parsed = http::parse_request(&raw);
        assert_eq!(parsed.err(), Some(*expected), "vector `{name}`");
    }
}

#[test]
fn too_many_headers_is_431() {
    let mut raw = format!("GET /c/{SAMPLE_HANDLE}/x HTTP/1.1\r\nHost: g\r\n");
    for i in 0..64 {
        raw.push_str(&format!("X-{i}: v\r\n"));
    }
    raw.push_str("\r\n");
    assert_eq!(
        http::parse_request(raw.as_bytes()).err(),
        Some(Status::HeaderTooLarge)
    );
}

#[test]
fn valid_requests_are_normalized() {
    let raw = format!(
        "POST /c/{SAMPLE_HANDLE}/messages?beta=true HTTP/1.1\r\nHost: g\r\n\
         Authorization: Bearer guest-supplied\r\nauthorization: second\r\n\
         Proxy-Authorization: x\r\nX-Forwarded-For: 1.2.3.4\r\nForwarded: for=x\r\nVia: 1.1 a\r\n\
         Connection: keep-alive, X-Drop\r\nX-Drop: gone\r\nKeep-Alive: 5\r\nTE: trailers\r\n\
         Expect: 100-continue\r\nContent-Length: 5\r\nX-Keep: kept\r\n\r\n"
    );
    let head = http::parse_request(raw.as_bytes()).unwrap();
    assert_eq!(head.method, "POST");
    assert_eq!(head.handle, SAMPLE_HANDLE);
    assert_eq!(head.rest, "/messages?beta=true");
    assert_eq!(head.framing, BodyFraming::Length(5));
    assert!(head.expect_continue && !head.close);
    let names: Vec<String> = head
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    // The configured header is removed at serialization (mapping-specific).
    assert_eq!(names, ["authorization", "authorization", "x-keep"]);

    for (basepath, rest, target) in [
        ("/v1", "", "/v1"),
        ("/v1", "/", "/v1/"),
        ("/v1", "?q=1", "/v1?q=1"),
        ("/v1", "/models", "/v1/models"),
        ("", "", "/"),
        ("", "?q", "/?q"),
        ("", "/m", "/m"),
    ] {
        assert_eq!(http::upstream_target(basepath, rest), target);
    }
    // Every methodin the allowlist parses.
    for method in http::ALLOWED_METHODS {
        let raw = format!("{method} /c/{SAMPLE_HANDLE} HTTP/1.1\r\nHost: g\r\n\r\n");
        assert_eq!(http::parse_request(raw.as_bytes()).unwrap().method, method);
    }
}

#[test]
fn response_vector_table() {
    let bad: &[(&str, &[u8])] = &[
        (
            "101",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        ),
        (
            "upgrade header",
            b"HTTP/1.1 200 OK\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "cl+te",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        (
            "dup cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
        ),
        (
            "te gzip",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        ),
        (
            "obs-fold",
            b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n",
        ),
        ("bare lf", b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n"),
        (
            "ctl",
            b"HTTP/1.1 200 OK\r\nX: a\x02\r\nContent-Length: 0\r\n\r\n",
        ),
    ];
    for (name, raw) in bad {
        assert!(
            http::parse_response(raw).is_err(),
            "response vector `{name}`"
        );
    }
    let ok = http::parse_response(
        b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/x\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(ok.code, 302);
    assert!(ok.close);
    assert_eq!(ok.headers.len(), 1);
    assert_eq!(ok.framing, Some(BodyFraming::Length(0)));
}

#[test]
fn bridge_peers_only() {
    let gw = Ipv4Addr::new(10, 7, 3, 1);
    assert!(bridge_peer(gw, IpAddr::V4(Ipv4Addr::new(10, 7, 3, 42))));
    assert!(
        !bridge_peer(gw, IpAddr::V4(gw)),
        "host processes use the gateway address"
    );
    assert!(!bridge_peer(gw, IpAddr::V4(Ipv4Addr::new(10, 7, 4, 42))));
    assert!(!bridge_peer(gw, IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!bridge_peer(gw, IpAddr::V4(Ipv4Addr::new(10, 7, 3, 0))));
    assert!(!bridge_peer(gw, "::1".parse().unwrap()));
}

// --- upstream address rules and TLS --------------------------------------------

#[test]
fn upstream_answers_with_any_protected_address_are_refused() {
    let protected = |ip: Ipv4Addr| sandbox_runtime::is_protected_guest_address(ip);
    let v4 = |a, b, c, d| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 443));
    let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    for bad in [
        v4(127, 0, 0, 1),
        v4(10, 0, 0, 5),
        v4(169, 254, 169, 254),
        v4(100, 100, 100, 200),
        v4(192, 168, 1, 1),
        v4(0, 0, 0, 0),
    ] {
        // Rebinding: one protected address poisons the whole answer.
        assert_eq!(
            upstream::validated_addresses(&[v4(1, 1, 1, 1), bad], &protected),
            Err(UpstreamError::Protected)
        );
    }
    // AAAA ignored: an IPv6-only answer does not resolve.
    assert_eq!(
        upstream::validated_addresses(&[v6], &protected),
        Err(UpstreamError::Resolve)
    );
    assert_eq!(
        upstream::validated_addresses(
            &[v6, v4(1, 1, 1, 1), v4(1, 1, 1, 1), v4(8, 8, 8, 8)],
            &protected
        ),
        Ok(vec![
            SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443),
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 443)
        ])
    );

    // The production connector refuses before any socket is opened.
    let config = upstream::webpki_client_config().unwrap();
    let resolver: upstream::Resolver = Arc::new(|_: &str, _: u16, _: Instant| {
        Ok(vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            9,
        ))])
    });
    let connector = TlsConnector::new(&config, resolver, fixed_ceiling(ceiling(&[], &[], &[])));
    assert_eq!(
        connector
            .connect(HOST_A, 443, &armed(Duration::from_secs(5)))
            .err(),
        Some(UpstreamError::Protected)
    );
}

/// A watch whose request deadline is `left` from now.
fn armed(left: Duration) -> Arc<upstream::Watch> {
    let watch = upstream::Watch::new(Box::new(|| false));
    watch.arm(Instant::now() + left);
    watch
}

fn net(text: &str) -> Ipv4Net {
    Ipv4Net::parse_cidr(text).unwrap()
}

/// A guard ceiling: the real protected table plus routed scope, operator
/// denies and node addresses.
fn ceiling(scope: &[&str], deny: &[&str], node: &[&str]) -> EgressCeiling {
    let inputs = GuardInputs {
        protected4: sandbox_runtime::guard::net::protected4().unwrap().to_vec(),
        scope4: scope.iter().map(|n| net(n)).collect(),
        deny4: deny.iter().map(|n| net(n)).collect(),
        ..GuardInputs::default()
    };
    EgressCeiling::new(&inputs, node.iter().map(|n| net(n)).collect())
}

fn fixed_ceiling(ceiling: EgressCeiling) -> upstream::CeilingFn {
    let ceiling = Arc::new(ceiling);
    Arc::new(move || Some(ceiling.clone()))
}

/// The node egress ceiling also applies to proxy sockets: an
/// upstream on a node address, inside a routed (non-default) prefix, or in
/// an operator-denied CIDR is refused, although none of them is in the
/// static protected table; no ceiling (guard unhealthy) refuses everything
/// before any lookup.
#[test]
fn upstreams_outside_the_node_egress_ceiling_are_refused() {
    let config = upstream::webpki_client_config().unwrap();
    let node = "45.33.0.7";
    let routed = "203.0.114.20";
    let denied = "93.184.216.34";
    let limits = ceiling(&["203.0.114.0/24"], &["93.184.216.0/24"], &["45.33.0.7/32"]);
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for address in [node, routed, denied] {
        let ip: Ipv4Addr = address.parse().unwrap();
        // The gap: the static table alone lets every one of them through.
        assert!(!sandbox_runtime::is_protected_guest_address(ip));
        let count = lookups.clone();
        let resolver: upstream::Resolver = Arc::new(move |_: &str, _: u16, _: Instant| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
                SocketAddr::V4(SocketAddrV4::new(ip, 443)),
            ])
        });
        let connector = TlsConnector::new(&config, resolver, fixed_ceiling(limits.clone()));
        assert_eq!(
            connector
                .connect(HOST_A, 443, &armed(Duration::from_secs(5)))
                .err(),
            Some(UpstreamError::Protected),
            "{address}"
        );
    }
    assert_eq!(lookups.load(std::sync::atomic::Ordering::SeqCst), 3);

    // Ceiling unavailable (guard unreachable or unhealthy): fail closed,
    // not even a lookup. A probe that answers no ceiling is the same.
    let count = lookups.clone();
    let resolver: upstream::Resolver = Arc::new(move |_: &str, _: u16, _: Instant| {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            443,
        ))])
    });
    for unavailable in [
        Arc::new(|| None) as upstream::CeilingFn,
        upstream::guard_ceiling(None),
        upstream::guard_ceiling(Some(Arc::new(
            sandbox_runtime::guard_probe::FakeGuardProbe::healthy(),
        ))),
    ] {
        let connector = TlsConnector::new(&config, resolver.clone(), unavailable);
        assert_eq!(
            connector
                .connect(HOST_A, 443, &armed(Duration::from_secs(5)))
                .err(),
            Some(UpstreamError::Ceiling)
        );
    }
    assert_eq!(lookups.load(std::sync::atomic::Ordering::SeqCst), 3);
}

/// The address is re-checked against a current ceiling immediately before
/// the connect to exactly it: a ceiling that changed after the answer was
/// validated refuses, and no TCP connection is made.
#[test]
fn the_ceiling_is_rechecked_at_connect_time() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let open = Arc::new(EgressCeiling::new(
        &GuardInputs {
            protected4: vec![net("10.0.0.0/8")],
            ..GuardInputs::default()
        },
        vec![],
    ));
    let closed = Arc::new(EgressCeiling::new(
        &GuardInputs {
            protected4: vec![net("10.0.0.0/8")],
            ..GuardInputs::default()
        },
        vec![net("127.0.0.0/8")],
    ));
    let seen = calls.clone();
    let changing: upstream::CeilingFn = Arc::new(move || {
        // Pre-check and answer validation see the open ceiling; the
        // connect-time re-check sees the node address appear.
        let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(if n < 2 { open.clone() } else { closed.clone() })
    });
    let config = upstream::webpki_client_config().unwrap();
    let resolver: upstream::Resolver = Arc::new(move |_: &str, _: u16, _: Instant| Ok(vec![addr]));
    let connector = TlsConnector::ceiling_only(&config, resolver, changing);
    assert_eq!(
        connector
            .connect(HOST_A, 443, &armed(Duration::from_secs(5)))
            .err(),
        Some(UpstreamError::Protected)
    );
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 3);
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "no connection was opened"
    );
}

/// DNS timeouts must not leave uncapped resolver threads: the pool
/// runs at most `workers` lookups at once, queues at most `queue`, refuses
/// at once beyond that, and keeps timed-out lookups charged until they
/// actually end; an abandoned queued lookup is skipped, never run.
#[test]
fn resolver_saturation_is_bounded_and_timed_out_work_stays_charged() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let (g, r, p, st) = (gate.clone(), running.clone(), peak.clone(), started.clone());
    let lookup: upstream::Lookup = Arc::new(move |_: &str, port: u16| {
        st.fetch_add(1, Ordering::SeqCst);
        let now = r.fetch_add(1, Ordering::SeqCst) + 1;
        p.fetch_max(now, Ordering::SeqCst);
        let (lock, cv) = &*g;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        r.fetch_sub(1, Ordering::SeqCst);
        Ok(vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            port,
        ))])
    });
    let pool = upstream::ResolverPool::new(2, 1, lookup).unwrap();
    let short = || Instant::now() + Duration::from_millis(50);
    // Two running and one queued, each abandoned by its caller.
    for _ in 0..3 {
        let error = pool.resolve(HOST_A, 443, short()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
    assert_eq!(pool.outstanding(), 3, "timed-out lookups stay charged");
    // Saturated: refused at once, no new thread, no wait.
    let at = Instant::now();
    let error = pool
        .resolve(HOST_A, 443, Instant::now() + Duration::from_secs(5))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert!(at.elapsed() < Duration::from_millis(500));
    assert_eq!(
        peak.load(Ordering::SeqCst),
        2,
        "never more than the workers"
    );

    // The lookups end: capacity comes back; the abandoned queued one was
    // skipped rather than run.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let until = Instant::now() + Duration::from_secs(5);
    while pool.outstanding() != 0 {
        assert!(Instant::now() < until, "capacity never released");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(started.load(Ordering::SeqCst), 2);
    let answer = pool
        .resolve(HOST_A, 443, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(answer.len(), 1);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

#[test]
fn tls_connector_sends_the_definition_host_as_sni_and_never_falls_back() {
    // A plaintext listener: the handshake must fail, nothing but a
    // ClientHello (carrying the definition hostname as SNI) is written.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let server = std::thread::spawn(move || {
        use std::io::Read;
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 4096];
        if let Ok(n) = s.read(&mut buf) {
            log.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    let config = upstream::webpki_client_config().unwrap();
    let resolver: upstream::Resolver = Arc::new(move |_: &str, _: u16, _: Instant| Ok(vec![addr]));
    let open = EgressCeiling::new(
        &GuardInputs {
            protected4: vec![net("10.0.0.0/8")],
            ..GuardInputs::default()
        },
        vec![],
    );
    let connector = TlsConnector::ceiling_only(&config, resolver, fixed_ceiling(open));
    let result = connector.connect(HOST_A, 443, &armed(Duration::from_secs(5)));
    assert_eq!(result.err(), Some(UpstreamError::Tls));
    server.join().unwrap();
    let hello = seen.lock().unwrap().clone();
    assert_eq!(hello.first(), Some(&0x16), "a TLS handshake record");
    assert!(
        contains(&hello, HOST_A.as_bytes()),
        "SNI is the definition host"
    );
    assert!(contains(&hello, b"http/1.1"), "ALPN pinned to http/1.1");
}

// --- end to end over loopback -----------------------------------------------------

#[test]
fn allowed_request_injects_once_on_the_mapping_upstream() {
    let f = Fixture::new(Mode::Fixed);
    // Guest env: base URLs and placeholders only.
    assert_eq!(f.env.len(), 4);
    for (_, value) in &f.env {
        assert_clean(value.as_bytes());
    }
    assert_eq!(
        f.env[0],
        (
            "A_BASE_URL".into(),
            format!("http://{}/c/{}", f.addr(), f.handles[0])
        )
    );
    assert_eq!(f.env[1], ("KEY_A".into(), super::PLACEHOLDER_VALUE.into()));

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer guest-forged\r\n\
         X-Forwarded-For: 6.6.6.6\r\nProxy-Authorization: Basic eA==\r\nVia: 1.0 x\r\n\
         Connection: X-Secret-Hop\r\nX-Secret-Hop: drop\r\nContent-Length: 5\r\n\r\nhello",
        f.path(0, "/messages?x=1")
    );
    let (code, guest) = exchange(f.addr(), request.as_bytes());
    assert_eq!(code, 200);
    assert_clean(&guest);
    let seen = String::from_utf8(f.a.received()).unwrap();
    assert!(
        seen.starts_with("POST /v1/messages?x=1 HTTP/1.1\r\nHost: api-a.example.test\r\n"),
        "{seen}"
    );
    let expected = format!(
        "Authorization: Bearer {}\r\n",
        String::from_utf8_lossy(SECRET)
    );
    assert_eq!(seen.matches(&expected).count(), 1, "{seen}");
    assert_eq!(
        seen.to_ascii_lowercase().matches("authorization:").count(),
        1,
        "guest copies removed"
    );
    for gone in [
        "guest-forged",
        "x-forwarded-for",
        "proxy-authorization",
        "via:",
        "x-secret-hop",
    ] {
        assert!(
            !seen.to_ascii_lowercase().contains(gone),
            "{gone} forwarded: {seen}"
        );
    }
    assert!(seen.ends_with(
        "Content-Length: 5\r\nAuthorization: Bearer sk-SENTINEL-proxy-7f3a9c41\r\n\r\nhello"
    ));
    assert!(f.b.received().is_empty());
}

/// TRACE, TRACK, CONNECT and extension methods → 405 against a
/// reflecting upstream: the upstream receives nothing (no connection at
/// all) and the response never contains the value; allowed methods still
/// inject (and a reflecting upstream echoes them, the documented residual).
#[test]
fn disallowed_methods_never_reach_a_reflecting_upstream() {
    let f = Fixture::new(Mode::Reflect);
    for method in ["TRACE", "TRACK", "CONNECT", "PROPFIND", "MKCOL", "FOO"] {
        let request = format!(
            "{method} {} HTTP/1.1\r\nHost: gw\r\nMax-Forwards: 0\r\n\r\n",
            f.path(0, "/x")
        );
        let (code, guest) = exchange(f.addr(), request.as_bytes());
        assert_eq!(code, 405, "{method}");
        assert!(contains(
            &guest,
            b"Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
        ));
        assert_clean(&guest);
    }
    assert!(f.a.received().is_empty(), "nothing forwarded");
    assert_eq!(
        f.connector
            .connects
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    for method in http::ALLOWED_METHODS {
        let request = format!("{method} {} HTTP/1.1\r\nHost: gw\r\n\r\n", f.path(0, "/x"));
        let (code, _) = exchange(f.addr(), request.as_bytes());
        assert_eq!(code, 200, "{method}");
    }
    let expected = format!(
        "Authorization: Bearer {}\r\n",
        String::from_utf8_lossy(SECRET)
    );
    let seen = String::from_utf8(f.a.received()).unwrap();
    assert_eq!(seen.matches(&expected).count(), http::ALLOWED_METHODS.len());
}

/// Every smuggling vector over a real socket: the proxy answers itself,
/// closes the connection, and never opens an upstream socket.
#[test]
fn smuggling_vectors_are_answered_locally_and_close() {
    let f = Fixture::new(Mode::Reflect);
    for (name, raw, expected) in REQUEST_VECTORS {
        let raw = with_handle(raw, &f.handles[0]);
        let mut stream = TcpStream::connect(f.addr()).unwrap();
        stream.write_all(&raw).unwrap();
        // A pipelined follow-up that must never be interpreted.
        let _ = stream.write_all(
            format!("GET {} HTTP/1.1\r\nHost: gw\r\n\r\n", f.path(0, "/second")).as_bytes(),
        );
        let (code, guest) = read_response(&mut stream);
        assert_eq!(code, expected.code(), "vector `{name}`");
        assert!(contains(&guest, b"Connection: close"), "vector `{name}`");
        assert_clean(&guest);
        assert!(
            closed(&mut stream),
            "vector `{name}` left the connection open"
        );
    }
    assert!(f.a.received().is_empty());
    assert_eq!(
        f.connector
            .connects
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    // An oversized head.
    let mut big = format!("GET {} HTTP/1.1\r\nHost: gw\r\nX-Big: ", f.path(0, "/x")).into_bytes();
    big.extend(std::iter::repeat_n(b'a', http::HEAD_MAX));
    big.extend_from_slice(b"\r\n\r\n");
    let (code, _) = exchange(f.addr(), &big);
    assert_eq!(code, 431);
    assert!(f.a.received().is_empty());
}

#[test]
fn chunked_bodies_are_decoded_and_reframed_without_trailers() {
    let f = Fixture::new(Mode::Fixed);
    let request = format!(
        "PUT {} HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\n\r\n\
         3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n",
        f.path(0, "/up")
    );
    let (code, _) = exchange(f.addr(), request.as_bytes());
    assert_eq!(code, 200);
    let seen = String::from_utf8(f.a.received()).unwrap();
    assert!(seen.contains("Transfer-Encoding: chunked\r\n"), "{seen}");
    assert!(
        seen.ends_with("\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"),
        "{seen}"
    );
    assert!(!seen.contains("ext=1") && !seen.contains("X-Trailer"));

    // Malformed chunk framing: 400, connection closed.
    for body in [
        "zz\r\nabc\r\n0\r\n\r\n",
        "3\r\nabcX\r\n0\r\n\r\n",
        "3\nabc\r\n0\r\n\r\n",
    ] {
        let request = format!(
            "PUT {} HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\n\r\n{body}",
            f.path(0, "/up")
        );
        let (code, guest) = exchange(f.addr(), request.as_bytes());
        assert_eq!(code, 400, "{body:?}");
        assert_clean(&guest);
    }
}

#[test]
fn expect_continue_is_answered_by_the_proxy_and_stripped() {
    let f = Fixture::new(Mode::Fixed);
    let mut stream = TcpStream::connect(f.addr()).unwrap();
    stream
        .write_all(
            format!(
                "POST {} HTTP/1.1\r\nHost: gw\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
                f.path(0, "/x")
            )
            .as_bytes(),
        )
        .unwrap();
    let (code, _) = read_response(&mut stream);
    assert_eq!(code, 100);
    stream.write_all(b"hi").unwrap();
    let (code, _) = read_response(&mut stream);
    assert_eq!(code, 200);
    assert!(
        !String::from_utf8(f.a.received())
            .unwrap()
            .to_ascii_lowercase()
            .contains("expect")
    );
}

/// Two proxied entries with different upstream authorities.
/// Alternating handles on one keep-alive connection → the second request is
/// 400 and the connection closes; the A upstream never sees B's value and B
/// sees nothing; separate connections per handle both work.
#[test]
fn a_connection_is_bound_to_its_first_handle() {
    let f = Fixture::new(Mode::Fixed);
    let mut stream = TcpStream::connect(f.addr()).unwrap();
    stream.write_all(&f.get(0, "/one")).unwrap();
    assert_eq!(read_response(&mut stream).0, 200);
    stream.write_all(&f.get(0, "/two")).unwrap();
    assert_eq!(
        read_response(&mut stream).0,
        200,
        "keep-alive on the same handle"
    );
    stream.write_all(&f.get(1, "/three")).unwrap();
    let (code, guest) = read_response(&mut stream);
    assert_eq!(code, 400);
    assert_clean(&guest);
    assert!(closed(&mut stream));
    let a = f.a.received();
    assert!(!contains(&a, SECRET_B), "B's value on A's socket");
    assert_eq!(String::from_utf8_lossy(&a).matches("GET /v1/").count(), 2);
    assert!(f.b.received().is_empty());
    assert_eq!(
        f.connector
            .connects
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    // Separate connections per handle both work.
    assert_eq!(exchange(f.addr(), &f.get(1, "/b")).0, 200);
    assert_eq!(exchange(f.addr(), &f.get(0, "/a")).0, 200);
    let b = f.b.received();
    assert!(contains(&b, SECRET_B) && !contains(&b, SECRET));
    assert!(contains(&b, b"Host: api-b.example.test\r\n"));
}

#[test]
fn revocation_is_403_and_closes_bound_connections() {
    let f = Fixture::new(Mode::Fixed);
    let mut idle = TcpStream::connect(f.addr()).unwrap();
    idle.write_all(&f.get(0, "/x")).unwrap();
    assert_eq!(read_response(&mut idle).0, 200);
    let addr = f.addr();
    f.hub.revoke_lease("lease-1");
    assert!(
        closed(&mut idle),
        "a bound keep-alive connection is closed at revoke"
    );
    assert_eq!(f.hub.handle_count(SANDBOX), 0);
    // The listener outlives the last handle; the freed handles
    // answer 403 (never connection refused).
    assert_eq!(f.hub.listen_addr(SANDBOX), Some(addr));
    assert_eq!(exchange(addr, &f.get(0, "/x")).0, 403);
    assert_eq!(exchange(addr, &f.get(1, "/x")).0, 403);
}

/// After the last proxy login is freed, re-attaching one (a new
/// lease with fresh handles) serves on the same listener; the old handles
/// stay 403. Only the sandbox's teardown closes the listener.
#[test]
fn reattach_after_the_last_free_reuses_the_listener() {
    let f = Fixture::new(Mode::Fixed);
    let addr = f.addr();
    assert_eq!(exchange(addr, &f.get(0, "/a")).0, 200);
    f.hub.revoke_lease("lease-1");
    assert_eq!(exchange(addr, &f.get(0, "/a")).0, 403);
    let again = proxied_lease("lease-2", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    let env = f
        .hub
        .install(SANDBOX, &again, "bind-lease-2", &handles, Some(&values))
        .unwrap();
    assert_eq!(env[0].1, format!("http://{addr}/c/{}", handles[0]));
    let get = format!("GET /c/{}/again HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).into_bytes();
    let (code, guest) = exchange(addr, &get);
    assert_eq!(code, 200);
    assert_clean(&guest);
    assert!(contains(&f.a.received(), b"GET /v1/again HTTP/1.1\r\n"));
    assert_eq!(exchange(addr, &f.get(0, "/a")).0, 403);
    f.hub.remove_sandbox(SANDBOX);
    assert!(f.hub.listen_addr(SANDBOX).is_none());
}

/// A free loopback port (bound once, then released).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A daemon restart re-binds each sandbox's listener on the
/// port recorded for that sandbox (its gateway ACL and guest base URLs),
/// never on a `credential_proxy_port` changed since its create.
#[test]
fn a_restart_rebinds_on_the_recorded_port_not_the_configured_one() {
    let recorded = free_port();
    let configured = free_port();
    assert_ne!(recorded, configured);
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    let restarted = |port: u16| {
        let connector = Arc::new(PlainConnector::default());
        let mut daemon = settings(connector);
        daemon.port = port;
        daemon.endpoint =
            Arc::new(move |_: &str| Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, recorded)));
        ProxyHub::new(daemon)
    };
    let expected = SocketAddr::from((Ipv4Addr::LOCALHOST, recorded));
    let base_url = format!("http://{expected}/c/{}", handles[0]);

    // Created under the recorded port.
    let before = restarted(recorded);
    let env = before
        .install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    assert_eq!(env[0].1, base_url);
    drop(before);
    // The stopped accept thread releases the port within a poll.
    wait_for(
        "the old listener released the port",
        Duration::from_secs(4),
        || std::net::TcpListener::bind(expected).is_ok(),
    );

    // Restarted after the operator changed the configured port: the
    // journaled handles (pending) and their completed values land on the
    // recorded port, and the guest's base URL is unchanged.
    let after = restarted(configured);
    assert_eq!(
        after.port(),
        configured,
        "new creates use the configuration"
    );
    after
        .install(SANDBOX, &lease, "b1", &handles, None)
        .unwrap();
    assert_eq!(after.listen_addr(SANDBOX), Some(expected));
    let get = format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).into_bytes();
    assert_eq!(exchange(expected, &get).0, 503);
    let authority = after.authority("lease-1");
    let env = after
        .install_authorized(
            &authority,
            SANDBOX,
            &lease,
            "b1",
            &handles,
            super::InstallValues::Restore(&values),
        )
        .unwrap();
    assert_eq!(env[0].1, base_url);
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, configured)).is_err(),
        "nothing listens on the configured port"
    );
}

#[test]
fn a_revoked_handle_is_403_while_others_remain() {
    let connector = Arc::new(PlainConnector::default());
    let a = TestUpstream::start(Mode::Fixed);
    connector.route(HOST_A, a.addr);
    let hub = ProxyHub::new(settings(connector));
    let one = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let two = proxied_lease("lease-2", vec![entry("KEY_C", HOST_A, "C_BASE_URL")]);
    let h1 = super::new_handles(1).unwrap();
    let h2 = super::new_handles(1).unwrap();
    let v = |name: &str| vec![(name.to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &one, "b1", &h1, Some(&v("KEY_A")))
        .unwrap();
    hub.install(SANDBOX, &two, "b2", &h2, Some(&v("KEY_C")))
        .unwrap();
    hub.revoke_lease("lease-1");
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let get = |h: &str| format!("GET /c/{h}/x HTTP/1.1\r\nHost: gw\r\n\r\n").into_bytes();
    assert_eq!(exchange(addr, &get(&h1[0])).0, 403);
    assert_eq!(exchange(addr, &get(&h2[0])).0, 200);
    hub.remove_sandbox(SANDBOX);
    assert!(hub.listen_addr(SANDBOX).is_none());
}

#[test]
fn pending_handles_answer_503_until_restored() {
    let connector = Arc::new(PlainConnector::default());
    let a = TestUpstream::start(Mode::Fixed);
    connector.route(HOST_A, a.addr);
    let hub = ProxyHub::new(settings(connector));
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let env = hub.install(SANDBOX, &lease, "b1", &handles, None).unwrap();
    assert!(env.is_empty(), "no guest env while pending");
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let get = format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).into_bytes();
    assert_eq!(exchange(addr, &get).0, 503);
    assert!(a.received().is_empty());
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    let restore = hub.authority("lease-1");
    let env = hub
        .install_authorized(
            &restore,
            SANDBOX,
            &lease,
            "b1",
            &handles,
            super::InstallValues::Restore(&values),
        )
        .unwrap();
    assert_eq!(env[0].1, format!("http://{addr}/c/{}", handles[0]));
    // A fresh install never reuses a registered handle.
    assert_eq!(
        hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    assert_eq!(exchange(addr, &get).0, 200);
    // Another lease may not take over a handle.
    let other = proxied_lease("lease-x", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    assert_eq!(
        hub.install(SANDBOX, &other, "bx", &handles, Some(&values))
            .err(),
        Some(ProxyInstallError::Spec)
    );
}

#[test]
fn invalid_values_and_specs_are_refused_before_install() {
    let connector = Arc::new(PlainConnector::default());
    let hub = ProxyHub::new(settings(connector));
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    for bad in [
        &b"tok\r\nX-Injected: 1"[..],
        b"tok\n",
        b"a\x00b",
        b"trail ",
        b"",
        b"\x7f",
    ] {
        let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(bad))];
        assert_eq!(
            hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
                .err(),
            Some(ProxyInstallError::ValueInvalid),
            "{bad:?}"
        );
    }
    assert!(
        hub.listen_addr(SANDBOX).is_none(),
        "nothing listens after a refusal"
    );
    let value = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    let mut bad = lease.clone();
    bad.proxy[0].header = "Host".into();
    assert_eq!(
        hub.install(SANDBOX, &bad, "b1", &handles, Some(&value))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    let mut bad = lease.clone();
    bad.proxy[0].upstream = "https://10.0.0.1/v1".into();
    assert_eq!(
        hub.install(SANDBOX, &bad, "b1", &handles, Some(&value))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    let mut bad = lease.clone();
    bad.proxy[0].upstream = "http://api-a.example.test".into();
    assert_eq!(
        hub.install(SANDBOX, &bad, "b1", &handles, Some(&value))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    let mut bad = lease.clone();
    bad.delivery = CredentialDelivery::Guest;
    assert_eq!(
        hub.install(SANDBOX, &bad, "b1", &handles, Some(&value))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    assert_eq!(
        hub.install(SANDBOX, &lease, "b1", &["NOT-HEX".to_owned()], Some(&value))
            .err(),
        Some(ProxyInstallError::Spec)
    );
    // No gateway: fails closed.
    let mut no_gw = settings(Arc::new(PlainConnector::default()));
    no_gw.endpoint = Arc::new(|_: &str| None);
    let hub = ProxyHub::new(no_gw);
    assert_eq!(
        hub.install(SANDBOX, &lease, "b1", &handles, Some(&value))
            .err(),
        Some(ProxyInstallError::NoGateway)
    );
}

#[test]
fn responses_never_echo_the_injected_header_and_redirects_pass_through() {
    let f = Fixture::new(Mode::Raw(
        format!(
            "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/next\r\n\
             Authorization: Bearer {s}\r\nX-Debug-Echo: got {s} here\r\nX-Ok: fine\r\n\
             Content-Length: 0\r\n\r\n",
            s = String::from_utf8_lossy(SECRET)
        )
        .into_bytes(),
    ));
    let (code, guest) = exchange(f.addr(), &f.get(0, "/r"));
    assert_eq!(code, 302);
    assert_clean(&guest);
    assert!(contains(
        &guest,
        b"Location: https://elsewhere.example/next"
    ));
    assert!(contains(&guest, b"X-Ok: fine"));
    assert_eq!(f.a.requests(), 1, "redirects are never followed");

    for (raw, name) in [
        (&b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"[..], "101"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", "cl+te"),
        (b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\nContent-Length: 0\r\n\r\n", "obs-fold"),
        (b"garbage\r\n\r\n", "garbage"),
    ] {
        f.a.set_mode(Mode::Raw(raw.to_vec()));
        let (code, guest) = exchange(f.addr(), &f.get(0, "/r"));
        assert_eq!(code, 502, "{name}");
        assert_clean(&guest);
    }
    // Chunked and close-delimited responses are re-framed.
    f.a.set_mode(Mode::Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n\r\n"
            .to_vec(),
    ));
    let (code, guest) = exchange(f.addr(), &f.get(0, "/c"));
    assert_eq!(code, 200);
    assert!(
        guest.ends_with(b"\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        "{}",
        String::from_utf8_lossy(&guest)
    );
    f.a.set_mode(Mode::Raw(
        b"HTTP/1.1 200 OK\r\n\r\nstreamed-until-close".to_vec(),
    ));
    let (code, guest) = exchange(f.addr(), &f.get(0, "/c"));
    assert_eq!(code, 200);
    assert!(contains(&guest, b"Connection: close") && guest.ends_with(b"streamed-until-close"));
}

/// Response smuggling: bytes past the end of an upstream response are never
/// read as the next response; the guest connection closes instead.
#[test]
fn trailing_upstream_bytes_close_the_connection() {
    let f = Fixture::new(Mode::Raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil"
            .to_vec(),
    ));
    let mut stream = TcpStream::connect(f.addr()).unwrap();
    stream.write_all(&f.get(0, "/one")).unwrap();
    let (code, guest) = read_response(&mut stream);
    assert_eq!(code, 200);
    assert!(guest.ends_with(b"\r\n\r\nok"));
    assert!(
        closed(&mut stream),
        "a desynchronized upstream is not reused"
    );
}

#[test]
fn rate_limit_is_600_per_minute() {
    let f = Fixture::new(Mode::Fixed);
    let proxy = super::lock(&f.hub.sandboxes).get(SANDBOX).cloned().unwrap();
    for _ in 0..super::REQUESTS_PER_MINUTE - 1 {
        assert!(proxy.admit_request());
    }
    assert_eq!(exchange(f.addr(), &f.get(0, "/x")).0, 200);
    assert_eq!(exchange(f.addr(), &f.get(0, "/x")).0, 429);
}

/// Sentinel: the value never appears in logs (trace level), in Debug of the
/// hub / mappings / env / errors, or in any guest-visible byte the proxy
/// produces itself.
#[test]
fn the_value_never_reaches_logs_debug_or_the_guest() {
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || Sink(sink.clone()))
        .finish();
    // As in `logging::with_subscriber`: a second live dispatch makes callsite
    // registration consult every live subscriber, so a parallel test thread
    // without one cannot cache `Interest::never` for the proxy's callsites.
    let _registration_guard = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let mut handles = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        let f = Fixture::new(Mode::Fixed);
        handles = f.handles.clone();
        let mut guest = Vec::new();
        guest.extend(exchange(f.addr(), &f.get(0, "/ok")).1);
        guest.extend(exchange(f.addr(), b"TRACE /c/0/x HTTP/1.1\r\nHost: gw\r\n\r\n").1);
        guest.extend(
            exchange(
                f.addr(),
                &with_handle(b"GET /c/H/../x HTTP/1.1\r\nHost: g\r\n\r\n", &f.handles[0]),
            )
            .1,
        );
        f.a.set_mode(Mode::Raw(b"HTTP/1.1 101 Switching\r\n\r\n".to_vec()));
        guest.extend(exchange(f.addr(), &f.get(0, "/up")).1);
        assert_clean(&guest);
        let mappings: Vec<Vec<Arc<super::Mapping>>> = super::lock(&f.hub.sandboxes)
            .values()
            .map(|p| super::lock(&p.handles).values().cloned().collect())
            .collect();
        let debug = format!(
            "{:?} {mappings:?} {:?} {:?}",
            f.hub,
            SecretBytes::copy_from(SECRET),
            settings(f.connector.clone())
        );
        assert_clean(debug.as_bytes());
        // An invalid value is refused without naming it.
        let lease = proxied_lease("lease-z", vec![entry("KEY_Z", HOST_A, "Z_BASE_URL")]);
        let bad = vec![(
            "KEY_Z".to_owned(),
            SecretBytes::copy_from(b"sk-SENTINEL-proxy-7f3a9c41\r\n"),
        )];
        let error = f
            .hub
            .install(
                SANDBOX,
                &lease,
                "bz",
                &super::new_handles(1).unwrap(),
                Some(&bad),
            )
            .unwrap_err();
        assert_clean(format!("{error:?} {}", error.as_str()).as_bytes());
        f.hub.revoke_lease("lease-1");
    });
    let logs = captured.lock().unwrap().clone();
    assert!(
        contains(&logs, b"credential proxy request"),
        "the proxy logged: {}",
        String::from_utf8_lossy(&logs)
    );
    assert!(contains(&logs, b"credential.value_invalid"));
    assert_clean(&logs);
    for handle in &handles {
        assert!(!contains(&logs, handle.as_bytes()), "a handle in the logs");
    }
    assert!(
        !contains(&logs, HOST_A.as_bytes()),
        "an upstream host in the logs"
    );
}

struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// --- revocation fencing ------------------------------------------------

/// A restore that obtained its handles (and its authority) before a
/// revocation never reinstalls them afterwards, nor does a fresh install
/// authorized before it; a later grant of the same lease (a RECOVER
/// binding) takes a fresh authority and is unaffected.
#[test]
fn revoke_during_restore_never_regains_proxy_authority() {
    use super::InstallValues;
    let connector = Arc::new(PlainConnector::default());
    let a = TestUpstream::start(Mode::Fixed);
    connector.route(HOST_A, a.addr);
    let hub = ProxyHub::new(settings(connector));
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    // Daemon restart: journaled handles pending.
    hub.install(SANDBOX, &lease, "b1", &handles, None).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];

    // The restore takes its authority, waits for the bundle… and the
    // lease is revoked meanwhile.
    let restoring = hub.authority("lease-1");
    let fresh = hub.authority("lease-1");
    hub.revoke_lease("lease-1");
    assert_eq!(
        hub.install_authorized(
            &restoring,
            SANDBOX,
            &lease,
            "b1",
            &handles,
            InstallValues::Restore(&values)
        )
        .err(),
        Some(ProxyInstallError::Revoked)
    );
    assert_eq!(
        hub.install_authorized(
            &fresh,
            SANDBOX,
            &lease,
            "b1",
            &super::new_handles(1).unwrap(),
            InstallValues::Fresh(&values)
        )
        .err(),
        Some(ProxyInstallError::Revoked)
    );
    assert_eq!(hub.handle_count(SANDBOX), 0);
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let get = format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).into_bytes();
    assert_eq!(
        exchange(addr, &get).0,
        403,
        "the revoked handle never came back"
    );

    // Even with a fresh authority, a restore only completes registered
    // handles: the revoked ones are gone for good.
    let later = hub.authority("lease-1");
    assert_eq!(
        hub.install_authorized(
            &later,
            SANDBOX,
            &lease,
            "b1",
            &handles,
            InstallValues::Restore(&values)
        )
        .err(),
        Some(ProxyInstallError::Revoked)
    );
    // A new grant of the lease (new binding, new handles) is a fresh install.
    let recovered = super::new_handles(1).unwrap();
    hub.install_authorized(
        &later,
        SANDBOX,
        &lease,
        "b2",
        &recovered,
        InstallValues::Fresh(&values),
    )
    .unwrap();
    assert_eq!(hub.handle_count(SANDBOX), 1);
}

/// A request whose upstream connect completes after a revocation never
/// writes the credentialed head: the header is serialized under the
/// revocation fence, not copied before the connect.
#[test]
fn revoke_mid_request_writes_nothing_upstream() {
    use super::testing::GatedConnector;
    let connector = Arc::new(GatedConnector::default());
    let a = TestUpstream::start(Mode::Reflect);
    connector.inner.route(HOST_A, a.addr);
    let hub = ProxyHub::new(settings(connector.clone()));
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let mut guest = TcpStream::connect(addr).unwrap();
    guest
        .write_all(format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).as_bytes())
        .unwrap();
    connector.wait_entered();
    hub.revoke_lease("lease-1");
    connector.release();
    let (code, seen) = read_response(&mut guest);
    assert!(matches!(code, 0 | 403), "{code}");
    assert_clean(&seen);
    // Give a (buggy) late write time to arrive.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !contains(&a.received(), SECRET),
        "the credential reached the upstream after revocation"
    );
    assert!(a.received().is_empty(), "no request byte was written");
}

/// Revocation shuts the upstream socket down too, not only the guest's.
#[test]
fn revocation_closes_the_upstream_socket() {
    let connector = Arc::new(PlainConnector::default());
    let a = TestUpstream::start(Mode::Hold);
    connector.route(HOST_A, a.addr);
    let hub = ProxyHub::new(settings(connector));
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let mut guest = TcpStream::connect(addr).unwrap();
    guest
        .write_all(format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).as_bytes())
        .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while a.requests() == 0 {
        assert!(
            Instant::now() < until,
            "the request never reached the upstream"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(a.closed(), 0);
    hub.revoke_lease("lease-1");
    let until = Instant::now() + Duration::from_secs(2);
    while a.closed() == 0 {
        assert!(
            Instant::now() < until,
            "the upstream socket outlived the revocation"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(closed(&mut guest));
}

// --- request deadline on every framing read -----------------------------

/// Sends `prefix`, then trickles `byte` every 50 ms (each within the idle
/// limit), and returns how long the proxy kept the connection open.
fn trickle(addr: SocketAddr, prefix: &[u8], byte: u8) -> Duration {
    use std::io::Read;
    let start = Instant::now();
    let mut guest = TcpStream::connect(addr).unwrap();
    guest.write_all(prefix).unwrap();
    let mut writer = guest.try_clone().unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = stop.clone();
    let feeder = std::thread::spawn(move || {
        while !stopping.load(std::sync::atomic::Ordering::SeqCst)
            && start.elapsed() < Duration::from_secs(8)
        {
            if writer.write_all(&[byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    guest
        .set_read_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    let mut sink = [0u8; 1024];
    let held = loop {
        match guest.read(&mut sink) {
            Ok(0) | Err(_) => break start.elapsed(),
            Ok(_) => {}
        }
    };
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    feeder.join().unwrap();
    held
}

#[test]
fn trickled_chunk_sizes_and_trailers_end_at_the_request_deadline() {
    let connector = Arc::new(PlainConnector::default());
    let a = TestUpstream::start(Mode::Fixed);
    connector.route(HOST_A, a.addr);
    let mut short = settings(connector);
    short.request_max = Duration::from_millis(400);
    let hub = ProxyHub::new(short);
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let head = format!(
        "PUT /c/{}/up HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\n\r\n",
        handles[0]
    );
    // A chunk-size line whose extension never ends.
    let mut size_line = head.clone().into_bytes();
    size_line.extend_from_slice(b"1;e=");
    // A trailer line that never ends.
    let mut trailer = head.into_bytes();
    trailer.extend_from_slice(b"1\r\na\r\n0\r\nx-t: ");
    for (name, prefix) in [("chunk size", size_line), ("trailer", trailer)] {
        let held = trickle(addr, &prefix, b'a');
        assert!(
            held < Duration::from_secs(3),
            "a trickled {name} held the connection for {held:?}"
        );
    }
}

// --- upstream socket lifetime enforcement --------------------

/// The ceiling the loopback upstreams live under: open, or with an operator
/// deny of `127.0.0.0/8` (loopback is not otherwise refused here).
fn loopback_policy(deny_loopback: bool) -> upstream::Policy {
    let inputs = GuardInputs {
        protected4: vec![net("10.0.0.0/8")],
        deny4: if deny_loopback {
            vec![net("127.0.0.0/8")]
        } else {
            vec![]
        },
        ..GuardInputs::default()
    };
    let ceiling = Arc::new(EgressCeiling::new(&inputs, vec![]));
    Arc::new(move |ip| ceiling.refuses(ip))
}

fn wait_for(what: &str, within: Duration, done: impl Fn() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < within, "{what} (after {within:?})");
        std::thread::sleep(Duration::from_millis(10));
    }
    start.elapsed()
}

/// A denied CIDR added while a keep-alive connection idles closes its
/// upstream socket (without any guest traffic), and the next request on
/// that connection is refused without reaching the upstream.
#[test]
fn a_denied_cidr_added_mid_keepalive_closes_the_upstream_socket() {
    let f = Fixture::new(Mode::Fixed);
    f.connector.set_policy(Some(loopback_policy(false)));
    let mut guest = TcpStream::connect(f.addr()).unwrap();
    guest.write_all(&f.get(0, "/one")).unwrap();
    assert_eq!(read_response(&mut guest).0, 200);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(f.a.closed(), 0, "an admitted keep-alive socket stays open");

    f.connector.set_policy(Some(loopback_policy(true)));
    wait_for(
        "the upstream socket outlived the denied CIDR",
        Duration::from_secs(4),
        || f.a.closed() == 1,
    );
    guest.write_all(&f.get(0, "/two")).unwrap();
    let (code, seen) = read_response(&mut guest);
    assert_ne!(code, 200);
    assert_clean(&seen);
    assert_eq!(f.a.requests(), 1, "nothing reached the denied upstream");
}

/// A guard that becomes unhealthy (ceiling unavailable) closes every proxy
/// upstream socket.
#[test]
fn an_unhealthy_guard_closes_every_upstream_socket() {
    let f = Fixture::new(Mode::Fixed);
    let mut first = TcpStream::connect(f.addr()).unwrap();
    first.write_all(&f.get(0, "/a")).unwrap();
    assert_eq!(read_response(&mut first).0, 200);
    let mut second = TcpStream::connect(f.addr()).unwrap();
    second.write_all(&f.get(1, "/b")).unwrap();
    assert_eq!(read_response(&mut second).0, 200);
    assert_eq!((f.a.closed(), f.b.closed()), (0, 0));

    f.connector.set_policy(None);
    wait_for(
        "an upstream socket outlived the guard's health",
        Duration::from_secs(4),
        || f.a.closed() == 1 && f.b.closed() == 1,
    );
}

/// A long streaming response is cut when the ceiling changes to refuse its
/// upstream, not when it ends.
#[test]
fn a_streaming_response_is_cut_on_a_ceiling_change() {
    use std::io::Read;
    let f = Fixture::new(Mode::Stream);
    f.connector.set_policy(Some(loopback_policy(false)));
    let mut guest = TcpStream::connect(f.addr()).unwrap();
    guest.write_all(&f.get(0, "/events")).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !contains(&seen, b"1\r\na\r\n1\r\na\r\n") {
        let n = guest.read(&mut chunk).unwrap();
        assert!(n > 0, "the stream ended early");
        seen.extend_from_slice(&chunk[..n]);
    }
    assert!(seen.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let changed = Instant::now();
    f.connector.set_policy(Some(loopback_policy(true)));
    loop {
        match guest.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let cut = changed.elapsed();
    assert!(
        cut < Duration::from_secs(4),
        "the stream ran on for {cut:?} after the ceiling change"
    );
    wait_for(
        "the upstream socket outlived the ceiling change",
        Duration::from_secs(4),
        || f.a.closed() == 1,
    );
}

// --- deadlines beneath TLS -------------------------------------

/// Accepts one connection, reads the ClientHello (after `handshake`, when
/// given, completes a real TLS handshake first), then sends a TLS record
/// header announcing 255 bytes and trickles them one every 50 ms.
fn trickling_tls_server(handshake: bool) -> SocketAddr {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let record: u8 = if handshake {
            let certs = &*TEST_CERTIFICATES;
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(certs.leaf.clone())],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certs.leaf_key.clone()).into(),
            )
            .unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            // Application data.
            0x17
        } else {
            let mut hello = [0u8; 4096];
            let _ = sock.read(&mut hello);
            // Handshake.
            0x16
        };
        let start = Instant::now();
        if sock.write_all(&[record, 0x03, 0x03, 0x00, 0xff]).is_err() {
            return;
        }
        while start.elapsed() < Duration::from_secs(12) {
            if sock.write_all(&[0x42]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    addr
}

static TEST_CERTIFICATES: std::sync::LazyLock<crate::tls::certificates::Certificates> =
    std::sync::LazyLock::new(crate::tls::certificates::generate);

/// A connector trusting the test CA, every address under an open ceiling.
fn trusting_connector(addr: SocketAddr) -> TlsConnector {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            rustls::pki_types::CertificateDer::from_pem_slice(TEST_CERTIFICATES.ca_pem.as_bytes())
                .unwrap(),
        )
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let resolver: upstream::Resolver = Arc::new(move |_: &str, _: u16, _: Instant| Ok(vec![addr]));
    let open = EgressCeiling::new(
        &GuardInputs {
            protected4: vec![net("10.0.0.0/8")],
            ..GuardInputs::default()
        },
        vec![],
    );
    TlsConnector::ceiling_only(&config, resolver, fixed_ceiling(open))
}

/// A handshake whose server trickles a partial record (each byte within
/// the socket timeout) is cut at the request deadline, not when the
/// trickle ends.
#[test]
fn a_slow_tls_handshake_is_cut_at_the_deadline() {
    let connector = trusting_connector(trickling_tls_server(false));
    let start = Instant::now();
    let result = connector.connect("localhost", 443, &armed(Duration::from_millis(600)));
    let held = start.elapsed();
    assert_eq!(result.err(), Some(UpstreamError::Timeout));
    assert!(held < Duration::from_secs(2), "the handshake ran {held:?}");
}

/// After the handshake, an upstream trickling one partial TLS record
/// cannot hold a read past the request deadline (rustls loops over partial
/// records internally; the deadline is checked beneath it).
#[test]
fn an_upstream_trickling_tls_bytes_is_cut_at_the_deadline() {
    use std::io::Read;
    let connector = trusting_connector(trickling_tls_server(true));
    let watch = armed(Duration::from_millis(1500));
    let start = Instant::now();
    let mut stream = connector
        .connect("localhost", 443, &watch)
        .map_err(|e| e.as_str())
        .unwrap();
    let mut buf = [0u8; 64];
    let read = stream.read(&mut buf);
    let held = start.elapsed();
    assert!(read.is_err(), "{read:?}");
    assert!(held < Duration::from_secs(3), "the read ran {held:?}");
}

/// Connects and registers its socket, then blocks in a raw read that no
/// deadline governs: only the hub's watchdog can end it.
struct StubbornConnector {
    addr: SocketAddr,
}

impl Connector for StubbornConnector {
    fn policy(&self) -> Option<upstream::Policy> {
        Some(Arc::new(|_| false))
    }

    fn connect(
        &self,
        _host: &str,
        _port: u16,
        watch: &Arc<upstream::Watch>,
    ) -> Result<Box<dyn upstream::UpstreamStream>, UpstreamError> {
        use std::io::Read;
        let mut sock = TcpStream::connect(self.addr).map_err(|_| UpstreamError::Connect)?;
        watch.attach(&sock).map_err(|_| UpstreamError::Cancelled)?;
        let mut byte = [0u8; 1];
        let _ = sock.read(&mut byte);
        Err(UpstreamError::Tls)
    }
}

/// Ignores the request deadline entirely and never registers an upstream
/// socket: only the guest side is left for the watchdog to cut.
struct DeafConnector;

impl Connector for DeafConnector {
    fn policy(&self) -> Option<upstream::Policy> {
        Some(Arc::new(|_| false))
    }

    fn connect(
        &self,
        _host: &str,
        _port: u16,
        _watch: &Arc<upstream::Watch>,
    ) -> Result<Box<dyn upstream::UpstreamStream>, UpstreamError> {
        std::thread::sleep(Duration::from_secs(8));
        Err(UpstreamError::Connect)
    }
}

/// The watch owns both endpoints. Whatever a worker is blocked
/// in past its request deadline, the watchdog shuts the guest socket down
/// shortly after the deadline (here: no upstream socket exists at all), so
/// a request never holds its guest connection past the deadline.
#[test]
fn the_watchdog_cuts_the_guest_side_past_the_deadline() {
    use std::io::Read;
    let mut short = settings(Arc::new(DeafConnector));
    short.request_max = Duration::from_millis(300);
    let hub = ProxyHub::new(short);
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    let start = Instant::now();
    let mut guest = TcpStream::connect(hub.listen_addr(SANDBOX).unwrap()).unwrap();
    guest
        .write_all(format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).as_bytes())
        .unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match guest.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }
    let held = start.elapsed();
    assert_clean(&seen);
    assert!(
        held < Duration::from_secs(3),
        "the guest connection outlived its deadline by {held:?}"
    );
}

/// The watchdog shuts an upstream socket down at the absolute deadline
/// even while an operation beneath the proxy (a handshake) ignores it.
#[test]
fn the_watchdog_cuts_a_socket_at_the_deadline() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = silent.local_addr().unwrap();
    let mut short = settings(Arc::new(StubbornConnector { addr }));
    short.request_max = Duration::from_millis(500);
    let hub = ProxyHub::new(short);
    let lease = proxied_lease("lease-1", vec![entry("KEY_A", HOST_A, "A_BASE_URL")]);
    let handles = super::new_handles(1).unwrap();
    let values = vec![("KEY_A".to_owned(), SecretBytes::copy_from(SECRET))];
    hub.install(SANDBOX, &lease, "b1", &handles, Some(&values))
        .unwrap();
    let start = Instant::now();
    let mut guest = TcpStream::connect(hub.listen_addr(SANDBOX).unwrap()).unwrap();
    guest
        .write_all(format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).as_bytes())
        .unwrap();
    let (code, seen) = read_response(&mut guest);
    let held = start.elapsed();
    assert_eq!(code, 504);
    assert_clean(&seen);
    assert!(held < Duration::from_secs(2), "the request ran {held:?}");
    drop(silent);
}
