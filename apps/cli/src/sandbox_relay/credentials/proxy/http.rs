//! Strict HTTP/1.1 framing for the credential proxy.
//!
//! Requests and responses are parsed with `httparse`, validated against the
//! strict framing rules, and then **re-framed**: nothing the guest sent is
//! ever forwarded as raw bytes, so a framing disagreement between the guest,
//! this proxy and the upstream cannot smuggle a second request.
//!
//! The method allowlist is the first check on every request, before the
//! head is handed to `httparse`, so a disallowed method never reaches header
//! handling, the handle table or injection.

use std::io::{self, Read, Write};

/// Request and response heads: at most this many bytes, CRLF included.
pub const HEAD_MAX: usize = 32 * 1024;
/// At most this many header fields per head.
pub const HEADERS_MAX: usize = 64;
/// Request and response bodies (decoded) are at most this many bytes.
pub const BODY_MAX: u64 = 32 * 1024 * 1024;
/// A chunk-size line or trailer line is at most this many bytes.
const LINE_MAX: usize = 4096;
/// Request trailers are read and dropped; at most this many lines.
const TRAILERS_MAX: usize = 64;
/// A head must arrive within this long after its first byte.
pub const HEAD_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);
/// A handle is 128 random bits, lowercase hex.
pub const HANDLE_HEX_LEN: usize = 32;

/// The only methods ever forwarded. TRACE, TRACK, CONNECT, WebDAV and
/// every extension method are refused with 405 before any header handling.
pub const ALLOWED_METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// A refusal the proxy answers itself. Every one closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    BadRequest,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    ExpectationFailed,
    TooManyRequests,
    HeaderTooLarge,
    BadGateway,
    Unavailable,
    GatewayTimeout,
    VersionNotSupported,
}

impl Status {
    pub fn code(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::ExpectationFailed => 417,
            Self::TooManyRequests => 429,
            Self::HeaderTooLarge => 431,
            Self::BadGateway => 502,
            Self::Unavailable => 503,
            Self::GatewayTimeout => 504,
            Self::VersionNotSupported => 505,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::BadRequest => "Bad Request",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::PayloadTooLarge => "Content Too Large",
            Self::ExpectationFailed => "Expectation Failed",
            Self::TooManyRequests => "Too Many Requests",
            Self::HeaderTooLarge => "Request Header Fields Too Large",
            Self::BadGateway => "Bad Gateway",
            Self::Unavailable => "Service Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",
            Self::VersionNotSupported => "HTTP Version Not Supported",
        }
    }

    /// The fixed response: no reflected input, always `Connection: close`.
    pub fn response(self) -> Vec<u8> {
        let body = format!("credential proxy: {}\n", self.reason().to_ascii_lowercase());
        let allow = if self == Self::MethodNotAllowed {
            format!("Allow: {}\r\n", ALLOWED_METHODS.join(", "))
        } else {
            String::new()
        };
        let retry = if matches!(self, Self::Unavailable | Self::TooManyRequests) {
            "Retry-After: 1\r\n"
        } else {
            ""
        };
        format!(
            "HTTP/1.1 {} {}\r\n{allow}{retry}Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.code(),
            self.reason(),
            body.len()
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body (no `Content-Length`, no `Transfer-Encoding`).
    None,
    Length(u64),
    Chunked,
}

/// A validated request head. `headers` already excludes hop-by-hop fields,
/// `Connection`-nominated fields, `Host`, framing fields, `Proxy-*`,
/// `Forwarded`, `X-Forwarded-*` and `Via`; the configured credential header
/// is removed at serialization (it depends on the mapping).
#[derive(Debug)]
pub struct RequestHead {
    pub method: &'static str,
    pub handle: String,
    /// Path (beginning `/`, or empty) and optional `?query` after the handle.
    pub rest: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub framing: BodyFraming,
    pub expect_continue: bool,
    pub close: bool,
}

/// Index just past the blank line ending a head, if the buffer holds one.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Every LF is preceded by CR and every CR is followed by LF: `httparse`
/// alone accepts bare LF line endings, which a downstream parser might not.
fn strict_line_endings(head: &[u8]) -> bool {
    head.iter().enumerate().all(|(i, b)| match b {
        b'\n' => i > 0 && head[i - 1] == b'\r',
        b'\r' => head.get(i + 1) == Some(&b'\n'),
        _ => true,
    })
}

/// RFC 9110 field-value bytes: visible ASCII, obs-text, SP or HTAB.
fn field_value_ok(value: &[u8]) -> bool {
    value
        .iter()
        .all(|b| login_definition::net::is_field_value_byte(*b))
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(tchar)
}

/// Headers a proxy never forwards in either direction (lowercase).
fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "host"
            | "expect"
            | "forwarded"
            | "via"
    ) || name.starts_with("proxy-")
        || name.starts_with("x-forwarded-")
}

fn parse_content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// `Connection` tokens (lowercase), or `None` when one is not a token.
fn connection_tokens(value: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(value).ok()?;
    let mut out = Vec::new();
    for part in text.split(',') {
        let token = part.trim_matches([' ', '\t']);
        if token.is_empty() {
            continue;
        }
        if !is_token(token) {
            return None;
        }
        out.push(token.to_ascii_lowercase());
    }
    Some(out)
}

/// The request method, read from the raw request line before any header is
/// parsed. Anything outside [`ALLOWED_METHODS`] is a 405.
fn allowed_method(head: &[u8]) -> Result<&'static str, Status> {
    let line_end = head.iter().position(|b| *b == b'\r').unwrap_or(head.len());
    let method = head[..line_end]
        .split(|b| *b == b' ')
        .next()
        .unwrap_or_default();
    ALLOWED_METHODS
        .iter()
        .find(|m| m.as_bytes() == method)
        .copied()
        .ok_or(Status::MethodNotAllowed)
}

/// Splits an origin-form target `/c/<handle><rest>` and validates `rest`
/// (target rules plus dot-segment and encoded-separator refusal, so
/// the upstream path always stays under the definition's basepath).
pub fn split_target(target: &str) -> Result<(String, String), Status> {
    let bytes = target.as_bytes();
    if !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) || target.contains(['#', '\\']) {
        return Err(Status::BadRequest);
    }
    if !target.starts_with('/') {
        // absolute-form, authority-form and asterisk-form
        return Err(Status::BadRequest);
    }
    let Some(after) = target.strip_prefix("/c/") else {
        return Err(Status::NotFound);
    };
    if after.len() < HANDLE_HEX_LEN {
        return Err(Status::Forbidden);
    }
    let (handle, rest) = after.split_at(HANDLE_HEX_LEN);
    if !handle
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Status::Forbidden);
    }
    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
        return Err(Status::Forbidden);
    }
    let path = rest.split_once('?').map_or(rest, |(path, _)| path);
    if path.starts_with("//") {
        return Err(Status::BadRequest);
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return Err(Status::BadRequest);
    }
    if !path.is_empty() {
        let segments: Vec<&str> = lower[1..].split('/').collect();
        let last = segments.len() - 1;
        for (i, segment) in segments.iter().enumerate() {
            if segment.is_empty() && i != last {
                return Err(Status::BadRequest);
            }
            let decoded = segment.replace("%2e", ".");
            if decoded == "." || decoded == ".." {
                return Err(Status::BadRequest);
            }
        }
    }
    Ok((handle.to_owned(), rest.to_owned()))
}

/// The upstream request target: `basepath + rest`, as bytes; no URL join.
pub fn upstream_target(basepath: &str, rest: &str) -> String {
    let mut out = String::with_capacity(basepath.len() + rest.len() + 1);
    out.push_str(basepath);
    if (rest.is_empty() || rest.starts_with('?')) && basepath.is_empty() {
        out.push('/');
    }
    out.push_str(rest);
    out
}

/// Parses and validates one request head (`head` ends with CRLF CRLF).
pub fn parse_request(head: &[u8]) -> Result<RequestHead, Status> {
    // The method allowlist precedes everything else.
    let method = allowed_method(head)?;
    if !strict_line_endings(head) {
        return Err(Status::BadRequest);
    }
    let mut fields = [httparse::EMPTY_HEADER; HEADERS_MAX];
    let mut req = httparse::Request::new(&mut fields);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Err(httparse::Error::TooManyHeaders) => return Err(Status::HeaderTooLarge),
        _ => return Err(Status::BadRequest),
    }
    if req.method != Some(method) {
        return Err(Status::BadRequest);
    }
    if req.version != Some(1) {
        return Err(Status::VersionNotSupported);
    }
    let (handle, rest) = split_target(req.path.ok_or(Status::BadRequest)?)?;

    let mut hosts = 0;
    let mut length: Option<u64> = None;
    let mut chunked = false;
    let mut expect_continue = false;
    let mut close = false;
    let mut nominated: Vec<String> = Vec::new();
    let mut kept: Vec<(String, Vec<u8>)> = Vec::new();
    for field in req.headers.iter() {
        if !is_token(field.name) || !field_value_ok(field.value) {
            return Err(Status::BadRequest);
        }
        let name = field.name.to_ascii_lowercase();
        match name.as_str() {
            "host" => hosts += 1,
            "content-length" => {
                if length.is_some() {
                    return Err(Status::BadRequest);
                }
                length = Some(parse_content_length(field.value).ok_or(Status::BadRequest)?);
            }
            "transfer-encoding" => {
                if chunked || !field.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(Status::BadRequest);
                }
                chunked = true;
            }
            "upgrade" => return Err(Status::BadRequest),
            "connection" => {
                let tokens = connection_tokens(field.value).ok_or(Status::BadRequest)?;
                if tokens.iter().any(|t| t == "upgrade") {
                    return Err(Status::BadRequest);
                }
                close |= tokens.iter().any(|t| t == "close");
                nominated.extend(tokens);
            }
            "expect" => {
                if !field.value.eq_ignore_ascii_case(b"100-continue") {
                    return Err(Status::ExpectationFailed);
                }
                expect_continue = true;
            }
            _ if hop_by_hop(&name) => {}
            _ => kept.push((field.name.to_owned(), field.value.to_vec())),
        }
    }
    if hosts != 1 || (chunked && length.is_some()) {
        return Err(Status::BadRequest);
    }
    kept.retain(|(name, _)| !nominated.contains(&name.to_ascii_lowercase()));
    let framing = match (chunked, length) {
        (true, _) => BodyFraming::Chunked,
        (false, Some(n)) if n > BODY_MAX => return Err(Status::PayloadTooLarge),
        (false, Some(n)) => BodyFraming::Length(n),
        (false, None) => BodyFraming::None,
    };
    Ok(RequestHead {
        method,
        handle,
        rest,
        headers: kept,
        framing,
        expect_continue: expect_continue && framing != BodyFraming::None,
        close,
    })
}

/// A validated response head.
#[derive(Debug)]
pub struct ResponseHead {
    pub code: u16,
    pub reason: String,
    pub headers: Vec<(String, Vec<u8>)>,
    /// Upstream framing (`None` = close-delimited unless `no_body`).
    pub framing: Option<BodyFraming>,
    pub close: bool,
}

/// Why a response cannot be relayed (always a 502 or an abort).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadResponse;

/// Parses and validates one upstream response head with the request rules:
/// strict line endings, no obs-fold, no CTL, CL+TE or duplicate CL refused,
/// TE only exactly `chunked`; 101 / `Upgrade` refused.
pub fn parse_response(head: &[u8]) -> Result<ResponseHead, BadResponse> {
    if !strict_line_endings(head) {
        return Err(BadResponse);
    }
    let mut fields = [httparse::EMPTY_HEADER; HEADERS_MAX];
    let mut res = httparse::Response::new(&mut fields);
    match res.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        _ => return Err(BadResponse),
    }
    let code = res.code.ok_or(BadResponse)?;
    let version = res.version.ok_or(BadResponse)?;
    if code == 101 {
        return Err(BadResponse);
    }
    let reason = res.reason.unwrap_or_default();
    if !reason
        .bytes()
        .all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
    {
        return Err(BadResponse);
    }
    let mut length: Option<u64> = None;
    let mut chunked = false;
    let mut close = version == 0;
    let mut nominated: Vec<String> = Vec::new();
    let mut kept = Vec::new();
    for field in res.headers.iter() {
        if !is_token(field.name) || !field_value_ok(field.value) {
            return Err(BadResponse);
        }
        let name = field.name.to_ascii_lowercase();
        match name.as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err(BadResponse);
                }
                length = Some(parse_content_length(field.value).ok_or(BadResponse)?);
            }
            "transfer-encoding" => {
                if chunked || !field.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(BadResponse);
                }
                chunked = true;
            }
            "upgrade" => return Err(BadResponse),
            "connection" => {
                let tokens = connection_tokens(field.value).ok_or(BadResponse)?;
                if tokens.iter().any(|t| t == "upgrade") {
                    return Err(BadResponse);
                }
                close |= tokens.iter().any(|t| t == "close");
                nominated.extend(tokens);
            }
            _ if hop_by_hop(&name) => {}
            _ => kept.push((field.name.to_owned(), field.value.to_vec())),
        }
    }
    if chunked && length.is_some() {
        return Err(BadResponse);
    }
    kept.retain(|(name, _)| !nominated.contains(&name.to_ascii_lowercase()));
    let framing = match (chunked, length) {
        (true, _) => Some(BodyFraming::Chunked),
        (false, Some(n)) => Some(BodyFraming::Length(n)),
        (false, None) => None,
    };
    Ok(ResponseHead {
        code,
        reason: reason.to_owned(),
        headers: kept,
        framing,
        close,
    })
}

// --- buffered input ------------------------------------------------------------

/// A small read buffer that hands out heads, lines and exact byte counts.
pub struct Input<R> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
}

impl<R: Read> Input<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(8192),
            start: 0,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }

    /// Reads more bytes; `Ok(0)` at end of stream.
    fn fill(&mut self) -> io::Result<usize> {
        self.compact();
        let mut chunk = [0u8; 8192];
        let n = self.inner.read(&mut chunk)?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// The next head (through CRLF CRLF). `Ok(None)` on a clean end of
    /// stream before any byte; `Err(HeaderTooLarge)` past [`HEAD_MAX`].
    ///
    /// Once its first byte is seen, the whole head must arrive within
    /// [`HEAD_BUDGET`] (no slow-head connection held open indefinitely).
    /// `each` runs before every socket read (deadline, revocation).
    pub fn read_head(
        &mut self,
        on_first_byte: &mut dyn FnMut(),
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<Option<Vec<u8>>, HeadError> {
        let mut seen_any = !self.buffered().is_empty();
        let mut started = None;
        if seen_any {
            started = Some(std::time::Instant::now());
            on_first_byte();
        }
        loop {
            if started.is_some_and(|t| t.elapsed() > HEAD_BUDGET) {
                return Err(HeadError::Io(io::ErrorKind::TimedOut.into()));
            }
            if let Some(end) = head_end(self.buffered()) {
                if end > HEAD_MAX {
                    return Err(HeadError::TooLarge);
                }
                let head = self.buffered()[..end].to_vec();
                self.start += end;
                return Ok(Some(head));
            }
            if self.buffered().len() >= HEAD_MAX {
                return Err(HeadError::TooLarge);
            }
            each().map_err(HeadError::Io)?;
            match self.fill() {
                Ok(0) if !seen_any => return Ok(None),
                Ok(0) => return Err(HeadError::Truncated),
                Ok(_) => {
                    if !seen_any {
                        seen_any = true;
                        started = Some(std::time::Instant::now());
                        on_first_byte();
                    }
                }
                Err(e) => return Err(HeadError::Io(e)),
            }
        }
    }

    /// One CRLF-terminated line (without the CRLF), at most `max` bytes.
    /// `each` runs before every socket read: a line trickled byte by byte
    /// is still bound by the request deadline and revocation.
    fn read_line(
        &mut self,
        max: usize,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.buffered().iter().position(|b| *b == b'\n') {
                if pos == 0 || self.buffered()[pos - 1] != b'\r' || pos - 1 > max {
                    return Err(invalid("malformed line"));
                }
                let line = self.buffered()[..pos - 1].to_vec();
                if line.contains(&b'\r') {
                    return Err(invalid("malformed line"));
                }
                self.start += pos + 1;
                return Ok(line);
            }
            if self.buffered().len() > max + 2 {
                return Err(invalid("line too long"));
            }
            each()?;
            if self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Copies exactly `n` bytes to `out` through `each` (called before
    /// every read and every write, e.g. for a revocation or deadline check).
    pub fn copy_exact(
        &mut self,
        mut n: u64,
        out: &mut dyn Write,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        while n > 0 {
            if self.buffered().is_empty() {
                each()?;
                if self.fill()? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            each()?;
            let take = self
                .buffered()
                .len()
                .min(usize::try_from(n).unwrap_or(usize::MAX));
            out.write_all(&self.buffered()[..take])?;
            self.start += take;
            n -= take as u64;
        }
        Ok(())
    }

    /// Copies everything to end of stream (close-delimited bodies), at most
    /// `limit` bytes.
    pub fn copy_to_end(
        &mut self,
        limit: u64,
        out: &mut dyn Write,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut total: u64 = 0;
        loop {
            if self.buffered().is_empty() {
                each()?;
                if self.fill()? == 0 {
                    return Ok(());
                }
            }
            each()?;
            let piece = self.buffered().len();
            total += piece as u64;
            if total > limit {
                return Err(invalid("body too large"));
            }
            out.write_all(self.buffered())?;
            self.start += piece;
        }
    }

    /// Decodes a chunked body (strict: hex size, extensions ignored,
    /// CRLF everywhere, trailers dropped) and re-encodes it chunked to `out`.
    /// The decoded total is bounded by `limit`.
    pub fn relay_chunked(
        &mut self,
        limit: u64,
        out: &mut dyn Write,
        each: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut total: u64 = 0;
        loop {
            let line = self.read_line(LINE_MAX, each)?;
            let size_text = line.split(|b| *b == b';').next().unwrap_or_default();
            if size_text.is_empty()
                || size_text.len() > 16
                || !size_text.iter().all(u8::is_ascii_hexdigit)
                || !line
                    .iter()
                    .all(|b| login_definition::net::is_field_value_byte(*b))
            {
                return Err(invalid("malformed chunk size"));
            }
            let size = u64::from_str_radix(
                std::str::from_utf8(size_text).map_err(|_| invalid("chunk size"))?,
                16,
            )
            .map_err(|_| invalid("chunk size"))?;
            if size == 0 {
                // Trailers are read and dropped.
                for _ in 0..=TRAILERS_MAX {
                    if self.read_line(LINE_MAX, each)?.is_empty() {
                        out.write_all(b"0\r\n\r\n")?;
                        return Ok(());
                    }
                }
                return Err(invalid("too many trailers"));
            }
            total = total.saturating_add(size);
            if total > limit {
                return Err(invalid("body too large"));
            }
            out.write_all(format!("{size:x}\r\n").as_bytes())?;
            self.copy_exact(size, out, each)?;
            out.write_all(b"\r\n")?;
            if !self.read_line(0, each)?.is_empty() {
                return Err(invalid("malformed chunk"));
            }
        }
    }
}

#[derive(Debug)]
pub enum HeadError {
    TooLarge,
    Truncated,
    Io(io::Error),
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
