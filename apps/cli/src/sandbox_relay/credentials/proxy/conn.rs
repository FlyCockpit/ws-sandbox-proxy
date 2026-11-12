//! One guest connection.
//!
//! Per request, in order: head (≤ 32 KiB) → method allowlist (inside
//! [`http::parse_request`], before anything else) → strict validation →
//! rate limit → handle lookup → connection binding → readiness (no value
//! copied) → upstream socket (first request only, registered for shutdown
//! at revocation) → re-framed request head with the injected header, built
//! and written under the mapping's revocation fence → body → response
//! re-framed with the credential header (and any header echoing the value)
//! removed. Every read and write of a request, framing lines included, runs
//! under the request clock: the absolute deadline, revocation and stop are
//! checked before each socket read, and both sockets' timeouts are capped
//! by the time left. Every guest write of a request goes through a
//! [`WatchedSocket`] on the connection's watch, which re-checks the deadline
//! and cancellation before each raw write (partial writes included), and
//! the watch owns the guest socket, so the hub's watchdog cuts it shortly
//! past the deadline whatever the worker is blocked in. The upstream
//! socket is re-validated against the node's egress ceiling before each
//! keep-alive reuse and periodically while relaying (the hub's enforcer and
//! watchdog cover it too). Every refusal
//! answers a fixed response and closes the connection, so no leftover
//! pipelined bytes are ever interpreted after an error.

use std::cell::Cell;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use login_definition::ValidatedHeaderValue;

use super::http::{self, BODY_MAX, BodyFraming, HeadError, Input, Status};
use super::upstream::{
    Connector, ENFORCE_INTERVAL, UpstreamError, UpstreamStream, Watch, WatchedSocket,
};
use super::{IDLE_MAX, Mapping, SandboxProxy, SecretBytes, Unready};

/// At most this many interim (1xx) responses are skipped per request.
const INTERIM_MAX: usize = 8;
/// Lingering close: wait at most this long, discard at most this much.
const LINGER: Duration = Duration::from_millis(250);
const LINGER_BYTES: usize = 256 * 1024;
/// A fixed refusal is small: a guest that does not take it in this long
/// loses it (it never holds the connection longer).
const REFUSE_WRITE_MAX: Duration = Duration::from_secs(1);

type Upstream = Input<Box<dyn UpstreamStream>>;

fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

fn log_status(code: u16) {
    tracing::debug!(class = status_class(code), "credential proxy request");
}

fn refuse_invalid(guest: &mut TcpStream, mapping: &Mapping) {
    tracing::warn!(
        entry = mapping.entry_index,
        "credential.value_invalid: proxied header value refused"
    );
    refuse(guest, Status::BadGateway);
}

fn refuse(guest: &mut TcpStream, status: Status) {
    log_status(status.code());
    let _ = guest.set_write_timeout(Some(REFUSE_WRITE_MAX));
    let _ = guest.write_all(&status.response());
    let _ = guest.flush();
    linger_close(guest);
}

/// Closes after a response: half-close, then discard what the guest already
/// sent (bounded), so the kernel sends FIN rather than a reset that could
/// destroy the response in flight. Nothing read here is ever interpreted.
fn linger_close(guest: &mut TcpStream) {
    use std::io::Read;
    let _ = guest.shutdown(std::net::Shutdown::Write);
    let until = Instant::now() + LINGER;
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    // Bounded in time as a whole: a guest trickling bytes cannot hold it.
    while drained < LINGER_BYTES {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || guest.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match guest.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
    let _ = guest.shutdown(std::net::Shutdown::Both);
}

fn timeout_of(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(IDLE_MAX)
        .max(Duration::from_millis(1))
}

/// Finds `needle` inside `hay` (both non-empty).
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// The raw value inside a constructed header value (`prefix ‖ value ‖ suffix`).
fn raw_value<'a>(format: &str, header: &'a [u8]) -> &'a [u8] {
    let (prefix, suffix) = format.split_once("{value}").unwrap_or(("", ""));
    let end = header.len().saturating_sub(suffix.len());
    header.get(prefix.len()..end).unwrap_or_default()
}

/// The upstream request head with the injected header, in a wiped buffer.
fn request_head(
    head: &http::RequestHead,
    mapping: &Mapping,
    header_value: &ValidatedHeaderValue,
) -> SecretBytes {
    let target = http::upstream_target(&mapping.basepath, &head.rest);
    let mut out = SecretBytes::with_capacity(1024 + header_value.as_bytes().len());
    let mut put = |bytes: &[u8]| out.extend_from_slice(bytes);
    put(head.method.as_bytes());
    put(b" ");
    put(target.as_bytes());
    put(b" HTTP/1.1\r\nHost: ");
    put(mapping.authority.as_bytes());
    put(b"\r\n");
    for (name, value) in &head.headers {
        // Every guest copy of the configured header is removed.
        if name.eq_ignore_ascii_case(&mapping.header) {
            continue;
        }
        put(name.as_bytes());
        put(b": ");
        put(value);
        put(b"\r\n");
    }
    match head.framing {
        BodyFraming::Length(n) => put(format!("Content-Length: {n}\r\n").as_bytes()),
        BodyFraming::Chunked => put(b"Transfer-Encoding: chunked\r\n"),
        BodyFraming::None if matches!(head.method, "POST" | "PUT" | "PATCH") => {
            put(b"Content-Length: 0\r\n");
        }
        BodyFraming::None => {}
    }
    put(mapping.header.as_bytes());
    put(b": ");
    put(header_value.as_bytes());
    put(b"\r\n\r\n");
    out
}

/// The request clock: before every socket read (and between pieces of a
/// copy) the request must still be wanted, and both sockets' timeouts are
/// narrowed to the time left, so no single read or write outlives the
/// absolute deadline. At least every [`ENFORCE_INTERVAL`] the upstream
/// socket is re-validated against the egress ceiling (a long streaming
/// response is cut when its peer becomes refused).
struct Clock<'a> {
    deadline: Instant,
    mapping: &'a Mapping,
    proxy: &'a SandboxProxy,
    guest: &'a TcpStream,
    upstream: &'a TcpStream,
    watch: &'a Watch,
    connector: &'a dyn Connector,
    enforced: Cell<Instant>,
}

impl Clock<'_> {
    fn check(&self) -> io::Result<()> {
        if self.mapping.is_revoked() || self.proxy.stopped() || self.watch.is_closed() {
            return Err(io::Error::other("credential proxy request ended"));
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.enforced.get().elapsed() >= ENFORCE_INTERVAL {
            self.watch
                .enforce(self.connector.policy().as_ref())
                .map_err(|_| io::Error::other("credential proxy egress ceiling"))?;
            self.enforced.set(Instant::now());
        }
        let left = timeout_of(self.deadline);
        for socket in [self.guest, self.upstream] {
            socket.set_read_timeout(Some(left))?;
            socket.set_write_timeout(Some(left))?;
        }
        Ok(())
    }
}

/// Serves one guest connection until close, error, revocation or stop.
pub(super) fn serve(
    stream: TcpStream,
    proxy: &Arc<SandboxProxy>,
    connector: &dyn Connector,
    conn_id: u64,
    request_max: Duration,
) {
    let (Ok(mut guest), Ok(guest_ctl)) = (stream.try_clone(), stream.try_clone()) else {
        return;
    };
    let mut input = Input::new(stream);
    let mut bound: Option<(String, Arc<Mapping>)> = None;
    let mut upstream: Option<(Upstream, TcpStream)> = None;
    let mut watch: Option<Arc<Watch>> = None;
    // The guest side of every request's writes, under the watch's clock.
    let mut guest_out: Option<WatchedSocket> = None;
    loop {
        if let Some(watch) = &watch {
            // Keep-alive idle: no request deadline runs.
            watch.disarm();
        }
        // --- head -------------------------------------------------------------
        let _ = guest.set_read_timeout(Some(IDLE_MAX));
        let _ = guest.set_write_timeout(Some(IDLE_MAX));
        let mut deadline = Instant::now() + request_max;
        let mut stopped = || -> io::Result<()> {
            if proxy.stopped() {
                return Err(io::Error::other("credential proxy stopped"));
            }
            Ok(())
        };
        let raw = match input.read_head(
            &mut || deadline = Instant::now() + request_max,
            &mut stopped,
        ) {
            Ok(Some(raw)) => raw,
            Ok(None) | Err(HeadError::Io(_)) | Err(HeadError::Truncated) => return,
            Err(HeadError::TooLarge) => return refuse(&mut guest, Status::HeaderTooLarge),
        };
        let head = match http::parse_request(&raw) {
            Ok(head) => head,
            Err(status) => return refuse(&mut guest, status),
        };
        drop(raw);
        if proxy.stopped() {
            return refuse(&mut guest, Status::Unavailable);
        }
        if !proxy.admit_request() {
            return refuse(&mut guest, Status::TooManyRequests);
        }

        // --- handle and connection binding -----------------------------
        let Some(mapping) = proxy.lookup(&head.handle) else {
            return refuse(&mut guest, Status::Forbidden);
        };
        match &bound {
            Some((handle, _)) if *handle != head.handle => {
                return refuse(&mut guest, Status::BadRequest);
            }
            Some((_, first)) if !Arc::ptr_eq(first, &mapping) => {
                return refuse(&mut guest, Status::BadRequest);
            }
            Some(_) => {}
            None => {
                proxy.bind_conn(conn_id, &mapping.lease_id);
                bound = Some((head.handle.clone(), mapping.clone()));
            }
        }
        match mapping.ready() {
            Ok(()) => {}
            Err(Unready::Revoked) => return refuse(&mut guest, Status::Forbidden),
            Err(Unready::Pending) => return refuse(&mut guest, Status::Unavailable),
            Err(Unready::Invalid) => return refuse_invalid(&mut guest, &mapping),
        }

        // --- upstream socket (one per guest connection) -----------------------
        // The watch is registered before the connect: revocation, the
        // deadline watchdog and the egress enforcer reach the socket from
        // its first byte, TLS handshake included.
        if watch.is_none() {
            let (Ok(owned), Ok(writer)) = (guest.try_clone(), guest.try_clone()) else {
                return refuse(&mut guest, Status::Unavailable);
            };
            let (bound, owner) = (mapping.clone(), Arc::downgrade(proxy));
            let created = Watch::new(Box::new(move || {
                bound.is_revoked() || owner.upgrade().is_none_or(|p| p.stopped())
            }));
            // The watch owns both endpoints: the watchdog reaches the guest
            // socket too.
            created.own_guest(owned);
            proxy.attach_watch(conn_id, created.clone());
            guest_out = Some(WatchedSocket::new(writer, created.clone()));
            watch = Some(created);
        }
        let (Some(watch), Some(guest_out)) = (watch.as_ref(), guest_out.as_mut()) else {
            return;
        };
        watch.arm(deadline);
        if upstream.is_some() {
            // Keep-alive reuse: the socket's peer must still be inside the
            // node's current egress ceiling (and the enforcer must not have
            // shut it down while the connection was idle).
            let checked = if watch.is_closed() {
                Err(UpstreamError::Protected)
            } else {
                watch.enforce(connector.policy().as_ref())
            };
            if let Err(error) = checked {
                tracing::debug!(reason = error.as_str(), "credential proxy upstream closed");
                let status = match error {
                    UpstreamError::Ceiling => Status::Unavailable,
                    _ => Status::BadGateway,
                };
                return refuse(&mut guest, status);
            }
        } else {
            let connected = connector
                .connect(&mapping.host, mapping.port, watch)
                .and_then(|stream| {
                    // Registered before any request byte (connectors that
                    // did not register it themselves): a revocation from
                    // here on shuts the upstream socket down too.
                    let ctl = stream.socket().map_err(|_| UpstreamError::Connect)?;
                    watch.attach(&ctl).map_err(|_| {
                        if watch.expired() {
                            UpstreamError::Timeout
                        } else {
                            UpstreamError::Cancelled
                        }
                    })?;
                    Ok((Input::new(stream), ctl))
                });
            match connected {
                Ok(pair) => upstream = Some(pair),
                Err(error) => {
                    tracing::debug!(reason = error.as_str(), "credential proxy upstream refused");
                    // A socket the watchdog cut at the deadline fails
                    // however the connector saw it: a timeout.
                    let error = if watch.expired() && !mapping.is_revoked() {
                        UpstreamError::Timeout
                    } else {
                        error
                    };
                    let status = match error {
                        UpstreamError::Timeout => Status::GatewayTimeout,
                        UpstreamError::Cancelled => Status::Forbidden,
                        UpstreamError::Ceiling => Status::Unavailable,
                        _ => Status::BadGateway,
                    };
                    return refuse(&mut guest, status);
                }
            }
        }
        let Some((up, up_ctl)) = upstream.as_mut() else {
            return;
        };
        let clock = Clock {
            deadline,
            mapping: &mapping,
            proxy,
            guest: &guest_ctl,
            upstream: up_ctl,
            watch,
            connector,
            enforced: Cell::new(Instant::now()),
        };
        let mut alive = || clock.check();
        if alive().is_err() {
            return refuse(&mut guest, Status::GatewayTimeout);
        }

        // --- request ------------------------------------------------------------
        if head.expect_continue
            && guest_out
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .is_err()
        {
            return;
        }
        // The fence: revocation re-checked, header built and the head
        // written, all under the mapping's value lock.
        let fenced = mapping.with_header(|header_value| {
            let outgoing = request_head(&head, &mapping, header_value);
            up.get_mut().write_all(outgoing.expose())
        });
        let header_value = match fenced {
            Ok((header_value, Ok(()))) => header_value,
            Ok((_, Err(_))) => return refuse(&mut guest, Status::BadGateway),
            Err(Unready::Revoked) => return refuse(&mut guest, Status::Forbidden),
            Err(Unready::Pending) => return refuse(&mut guest, Status::Unavailable),
            Err(Unready::Invalid) => return refuse_invalid(&mut guest, &mapping),
        };
        let sent = (|| -> io::Result<()> {
            match head.framing {
                BodyFraming::Length(n) => input.copy_exact(n, up.get_mut(), &mut alive)?,
                BodyFraming::Chunked => input.relay_chunked(BODY_MAX, up.get_mut(), &mut alive)?,
                BodyFraming::None => {}
            }
            alive()?;
            up.get_mut().flush()
        })();
        if let Err(error) = sent {
            let status = match error.kind() {
                io::ErrorKind::InvalidData => Status::BadRequest,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Status::GatewayTimeout,
                _ if mapping.is_revoked() => Status::Forbidden,
                _ => Status::BadGateway,
            };
            return refuse(&mut guest, status);
        }

        // --- response -----------------------------------------------------------
        let mut response = None;
        for _ in 0..=INTERIM_MAX {
            let raw = match up.read_head(&mut || {}, &mut alive) {
                Ok(Some(raw)) => raw,
                Ok(None) | Err(_) => return refuse(&mut guest, Status::BadGateway),
            };
            match http::parse_response(&raw) {
                Ok(parsed) if (100..200).contains(&parsed.code) => continue,
                Ok(parsed) => {
                    response = Some(parsed);
                    break;
                }
                Err(_) => return refuse(&mut guest, Status::BadGateway),
            }
        }
        let Some(mut response) = response else {
            return refuse(&mut guest, Status::BadGateway);
        };
        // Never hand the injected header (or anything echoing the value)
        // back to the guest.
        let injected = header_value.as_bytes();
        let value = raw_value(&mapping.format, injected);
        response.headers.retain(|(name, field)| {
            !name.eq_ignore_ascii_case(&mapping.header)
                && !contains(field, injected)
                && !(value.len() >= 4 && contains(field, value))
        });
        drop(header_value);

        let no_body = head.method == "HEAD" || response.code == 204 || response.code == 304;
        let mut close = head.close || response.close;
        let mut out = format!("HTTP/1.1 {} {}\r\n", response.code, response.reason).into_bytes();
        for (name, field) in &response.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(field);
            out.extend_from_slice(b"\r\n");
        }
        match (no_body, response.framing) {
            (true, Some(BodyFraming::Length(n))) => {
                out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
            }
            (true, _) => {}
            (false, Some(BodyFraming::Length(n))) if n > BODY_MAX => {
                return refuse(&mut guest, Status::BadGateway);
            }
            (false, Some(BodyFraming::Length(n))) => {
                out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
            }
            (false, Some(BodyFraming::Chunked)) => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            (false, Some(BodyFraming::None)) | (false, None) => close = true,
        }
        if close {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        log_status(response.code);
        // Every guest write (head, body pieces, and each partial write
        // inside them) re-checks the deadline and cancellation.
        let relayed = (|| -> io::Result<()> {
            guest_out.write_all(&out)?;
            if !no_body {
                match response.framing {
                    Some(BodyFraming::Length(n)) => up.copy_exact(n, guest_out, &mut alive)?,
                    Some(BodyFraming::Chunked) => {
                        up.relay_chunked(BODY_MAX, guest_out, &mut alive)?;
                    }
                    Some(BodyFraming::None) | None => {
                        up.copy_to_end(BODY_MAX, guest_out, &mut alive)?;
                    }
                }
            }
            guest_out.flush()
        })();
        // Bytes the upstream sent past the end of its response would be read
        // as the next response: never reuse such a socket (same mapping, but
        // a desynchronized stream).
        if !up.buffered().is_empty() {
            close = true;
        }
        if relayed.is_err() {
            let _ = guest.shutdown(std::net::Shutdown::Both);
            return;
        }
        if close {
            return linger_close(&mut guest);
        }
    }
}
