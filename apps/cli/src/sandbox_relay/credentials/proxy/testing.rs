//! Test doubles for the credential proxy: a recording (optionally
//! reflecting) plaintext upstream, a connector that maps definition hosts to
//! those upstreams, loopback hub settings, and a tiny HTTP client.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::ProxySettings;
use super::upstream::{Connector, Policy, UpstreamError, UpstreamStream, Watch};

/// How a [`TestUpstream`] answers each request.
#[derive(Clone)]
pub enum Mode {
    /// 200 whose body is the request head it received (a reflecting endpoint).
    Reflect,
    /// 200 `ok`.
    Fixed,
    /// These exact bytes, then close.
    Raw(Vec<u8>),
    /// Never answers: holds the connection until the proxy closes it.
    Hold,
    /// A chunked 200 that streams a one-byte chunk every 50 ms for up to
    /// 10 s (a long streaming response), until the proxy closes it.
    Stream,
}

/// A plaintext HTTP/1.1 upstream that records every byte it receives.
pub struct TestUpstream {
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    requests: Arc<AtomicUsize>,
    /// Upstream connections the proxy closed (EOF or reset seen).
    closed: Arc<AtomicUsize>,
    mode: Arc<Mutex<Mode>>,
    stop: Arc<AtomicBool>,
}

impl Drop for TestUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>, log: &Mutex<Vec<u8>>) -> bool {
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk) {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            log.lock().unwrap().extend_from_slice(&chunk[..n]);
            true
        }
    }
}

/// Length of a complete chunked body at the start of `buf`, if complete.
fn chunked_len(buf: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let line_end = buf[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
        let size_text = std::str::from_utf8(&buf[pos..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            // Trailers until an empty line.
            loop {
                let end = buf[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
                let empty = end == pos;
                pos = end + 2;
                if empty {
                    return Some(pos);
                }
            }
        }
        if buf.len() < pos + size + 2 {
            return None;
        }
        pos += size + 2;
    }
}

fn serve_upstream(
    mut stream: TcpStream,
    log: Arc<Mutex<Vec<u8>>>,
    requests: Arc<AtomicUsize>,
    mode: Arc<Mutex<Mode>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(end) = head_end(&buf) {
                break end;
            }
            if !read_more(&mut stream, &mut buf, &log) {
                return;
            }
        };
        let head = buf[..end].to_vec();
        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let body_len = if text.contains("\r\ntransfer-encoding: chunked\r\n") {
            loop {
                if let Some(n) = chunked_len(&buf[end..]) {
                    break n;
                }
                if !read_more(&mut stream, &mut buf, &log) {
                    return;
                }
            }
        } else {
            let n = text
                .split("\r\n")
                .find_map(|l| l.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < end + n {
                if !read_more(&mut stream, &mut buf, &log) {
                    return;
                }
            }
            n
        };
        buf.drain(..end + body_len);
        requests.fetch_add(1, Ordering::SeqCst);
        let mode = mode.lock().unwrap().clone();
        let reply = match mode {
            Mode::Reflect => {
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len())
                    .into_bytes();
                r.extend_from_slice(&head);
                r
            }
            Mode::Fixed if head.starts_with(b"HEAD ") => {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec()
            }
            Mode::Fixed => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            Mode::Raw(bytes) => {
                let _ = stream.write_all(&bytes);
                return;
            }
            Mode::Hold => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte);
                return;
            }
            Mode::Stream => {
                let start = Instant::now();
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                while start.elapsed() < Duration::from_secs(10) {
                    if stream.write_all(b"1\r\na\r\n").is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = stream.write_all(b"0\r\n\r\n");
                return;
            }
        };
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

impl TestUpstream {
    pub fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(Mutex::new(mode));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, count, m, s, ended) = (
            received.clone(),
            requests.clone(),
            mode.clone(),
            stop.clone(),
            closed.clone(),
        );
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let (log, count, m, ended) =
                            (log.clone(), count.clone(), m.clone(), ended.clone());
                        std::thread::spawn(move || {
                            serve_upstream(stream, log, count, m);
                            ended.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            addr,
            received,
            requests,
            closed,
            mode,
            stop,
        }
    }

    /// Upstream connections that ended (the proxy closed its socket).
    pub fn closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn received(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
}

/// Maps definition hostnames to local plaintext upstreams. Its egress
/// policy admits every peer until a test changes it.
pub struct PlainConnector {
    pub routes: Mutex<HashMap<String, SocketAddr>>,
    pub connects: AtomicUsize,
    policy: Mutex<Option<Policy>>,
}

impl Default for PlainConnector {
    fn default() -> Self {
        Self {
            routes: Mutex::default(),
            connects: AtomicUsize::new(0),
            policy: Mutex::new(Some(Arc::new(|_: Ipv4Addr| false))),
        }
    }
}

impl PlainConnector {
    pub fn route(&self, host: &str, addr: SocketAddr) {
        self.routes.lock().unwrap().insert(host.to_owned(), addr);
    }

    /// The egress policy from now on (`None` = ceiling unavailable).
    pub fn set_policy(&self, policy: Option<Policy>) {
        *self.policy.lock().unwrap() = policy;
    }
}

impl Connector for PlainConnector {
    fn policy(&self) -> Option<Policy> {
        self.policy.lock().unwrap().clone()
    }

    fn connect(
        &self,
        host: &str,
        _port: u16,
        _watch: &Arc<Watch>,
    ) -> Result<Box<dyn UpstreamStream>, UpstreamError> {
        let addr = *self
            .routes
            .lock()
            .unwrap()
            .get(host)
            .ok_or(UpstreamError::Resolve)?;
        self.connects.fetch_add(1, Ordering::SeqCst);
        TcpStream::connect(addr)
            .map(|s| Box::new(s) as Box<dyn UpstreamStream>)
            .map_err(|_| UpstreamError::Connect)
    }
}

/// A [`PlainConnector`] that blocks inside `connect` until released (a
/// slow DNS lookup or TLS handshake), to race revocation against it.
#[derive(Default)]
pub struct GatedConnector {
    pub inner: PlainConnector,
    gate: Mutex<bool>,
    cv: std::sync::Condvar,
    pub entered: AtomicUsize,
}

impl GatedConnector {
    pub fn release(&self) {
        *self.gate.lock().unwrap() = true;
        self.cv.notify_all();
    }

    pub fn wait_entered(&self) {
        let until = Instant::now() + Duration::from_secs(10);
        while self.entered.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < until, "connect never started");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Connector for GatedConnector {
    fn policy(&self) -> Option<Policy> {
        self.inner.policy()
    }

    fn connect(
        &self,
        host: &str,
        port: u16,
        watch: &Arc<Watch>,
    ) -> Result<Box<dyn UpstreamStream>, UpstreamError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut open = self.gate.lock().unwrap();
        while !*open {
            open = self.cv.wait(open).unwrap();
        }
        drop(open);
        // Deliberately ignores `cancelled`: the fence at serialization
        // must hold even when a connector completes after a revocation.
        self.inner.connect(host, port, watch)
    }
}

/// Loopback settings: ephemeral port on 127.0.0.1, any peer.
pub fn settings(connector: Arc<dyn Connector>) -> ProxySettings {
    ProxySettings {
        port: 0,
        connector,
        endpoint: Arc::new(|_: &str| Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
        peer_allowed: Arc::new(|_: Ipv4Addr, _: IpAddr| true),
        request_max: super::REQUEST_MAX,
    }
}

/// Reads one response (head + Content-Length body, or to EOF).
pub fn read_response(stream: &mut TcpStream) -> (u16, Vec<u8>) {
    read_response_to(stream, false)
}

/// [`read_response`]; `head_only` for the response to a HEAD request.
pub fn read_response_to(stream: &mut TcpStream, head_only: bool) -> (u16, Vec<u8>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = head_end(&buf) {
            break end;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return (0, buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let text = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let code: u16 = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let length = text
        .split("\r\n")
        .find_map(|l| l.strip_prefix("content-length: "))
        .and_then(|v| v.trim().parse::<usize>().ok());
    let chunked = text.contains("\r\ntransfer-encoding: chunked\r\n");
    loop {
        let done = match (length, chunked) {
            (Some(n), _) => buf.len() >= end + n,
            (None, true) => chunked_len(&buf[end..]).is_some(),
            (None, false) => false,
        };
        if done || code == 100 || head_only {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    (code, buf)
}

/// Whether the peer closed the connection (EOF within the wait).
pub fn closed(stream: &mut TcpStream) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(0) | Err(_))
}

/// One request on a fresh connection; the whole guest-visible stream.
pub fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    read_response_to(&mut stream, request.starts_with(b"HEAD "))
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}
