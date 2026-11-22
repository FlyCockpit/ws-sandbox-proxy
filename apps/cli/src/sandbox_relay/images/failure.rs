//! Why an image-store upload (or a peer serve) ended: the one place a
//! transport error, a store status or a server refusal becomes the
//! `image.job.failed` cause. Only the cause, the `io::ErrorKind`, the HTTP
//! status, the part and the server's own refusal code are kept: never an
//! error's `Display` (a ureq error can carry a presigned URL) or a header.

use sandbox_protocol::{ImageFailureCause, ImageFailureCode, ImageJobFailedV11};

/// Cancel reasons that end a job without failing it: the image is (or is
/// about to be) stored by someone else, so the capture waits for that.
const NOT_A_FAILURE: [&str; 2] = ["already_stored", "upload_in_progress"];

/// A failed upload attempt, ready to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UploadFailure {
    pub(crate) code: ImageFailureCode,
    pub(crate) cause: ImageFailureCause,
    pub(crate) http_status: Option<u16>,
    pub(crate) part: Option<u32>,
    pub(crate) refusal: Option<String>,
    /// Logged only.
    pub(crate) io_kind: Option<std::io::ErrorKind>,
    /// The part attempt that ended this way (1-based; logged only).
    pub(crate) attempt: Option<u32>,
}

/// How a job ended when it did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UploadEnd {
    /// Nothing to report (another upload stores the image).
    Silent,
    Failed(UploadFailure),
}

impl From<UploadFailure> for UploadEnd {
    fn from(failure: UploadFailure) -> Self {
        Self::Failed(failure)
    }
}

impl UploadEnd {
    /// The end a server `image.job.cancel` with `reason` means.
    pub(crate) fn cancelled(reason: &str) -> Self {
        if NOT_A_FAILURE.contains(&reason) {
            Self::Silent
        } else {
            Self::Failed(UploadFailure::refused(reason))
        }
    }
}

impl UploadFailure {
    pub(crate) fn new(code: ImageFailureCode, cause: ImageFailureCause) -> Self {
        Self {
            code,
            cause,
            http_status: None,
            part: None,
            refusal: None,
            io_kind: None,
            attempt: None,
        }
    }

    pub(crate) fn at_part(mut self, part: u32) -> Self {
        self.part = Some(part);
        self
    }

    pub(crate) fn at_attempt(mut self, attempt: u32) -> Self {
        self.attempt = Some(attempt);
        self
    }

    /// Whether another attempt of the same part may succeed: a transport
    /// that timed out, stalled, was reset or could not connect, or a store
    /// answer that says "later" (5xx, 408, 429). A 403 is renewed by the
    /// caller, never retried as is; everything else is final.
    pub(crate) fn retryable(&self) -> bool {
        use ImageFailureCause as C;
        match self.cause {
            C::Timeout | C::Stalled | C::Reset | C::Connect => true,
            C::HttpStatus => self
                .http_status
                .is_some_and(|s| s >= 500 || s == 408 || s == 429),
            _ => false,
        }
    }

    /// The server refused the job; `reason` is its own cancel code, echoed
    /// only when it is code-shaped.
    pub(crate) fn refused(reason: &str) -> Self {
        let mut failure = Self::new(ImageFailureCode::Cancelled, ImageFailureCause::Refused);
        let shaped = !reason.is_empty()
            && reason.len() <= 64
            && reason
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.');
        failure.refusal = Some(if shaped { reason } else { "cancelled" }.to_owned());
        failure
    }

    /// Reading or sealing the staged image failed.
    pub(crate) fn local_io(kind: std::io::ErrorKind) -> Self {
        let mut failure = Self::new(ImageFailureCode::Io, ImageFailureCause::LocalIo);
        failure.io_kind = Some(kind);
        failure
    }

    /// A store answer other than success. A 403 once the URL's lifetime
    /// (judged on the host's own clock) ran out is an expired presigned URL.
    pub(crate) fn status(status: u16, url_expired: bool) -> Self {
        let expired = status == 403 && url_expired;
        let cause = if expired {
            ImageFailureCause::UrlExpired
        } else {
            ImageFailureCause::HttpStatus
        };
        let mut failure = Self::new(ImageFailureCode::Io, cause);
        failure.http_status = Some(status.clamp(100, 599));
        failure
    }

    /// A transport error, classified (never displayed).
    pub(crate) fn transport(error: &ureq::Error) -> Self {
        let (cause, io_kind) = classify(error);
        let code = match cause {
            ImageFailureCause::Timeout | ImageFailureCause::Stalled => ImageFailureCode::Timeout,
            _ => ImageFailureCode::Io,
        };
        let mut failure = Self::new(code, cause);
        failure.io_kind = io_kind;
        failure
    }

    /// The `image.job.failed` frame naming `transfer`, else the capture's
    /// operation and attempt.
    pub(crate) fn frame(
        &self,
        transfer: Option<&str>,
        capture: Option<(&str, u64)>,
    ) -> Option<ImageJobFailedV11> {
        let (transfer_id, operation_id, attempt) = match (transfer, capture) {
            (Some(transfer), _) => (Some(transfer.to_owned()), None, None),
            (None, Some((operation, attempt))) => (None, Some(operation.to_owned()), Some(attempt)),
            (None, None) => return None,
        };
        Some(ImageJobFailedV11 {
            transfer_id,
            operation_id,
            attempt,
            code: self.code,
            cause: self.cause,
            http_status: self.http_status,
            part: self.part,
            refusal: self.refusal.clone(),
        })
    }

    /// The sanitized log line for this failure.
    pub(crate) fn log(&self, what: &'static str, transfer: Option<&str>) {
        tracing::warn!(
            transfer = transfer.unwrap_or("-"),
            cause = self.cause.as_str(),
            code = ?self.code,
            io_kind = ?self.io_kind,
            http_status = ?self.http_status,
            part = ?self.part,
            attempt = self.attempt.unwrap_or(1),
            refusal = self.refusal.as_deref().unwrap_or("-"),
            "{what}"
        );
    }
}

/// The cause of a ureq error, and its `io::ErrorKind` when it has one.
/// `PerRead` / `PerWrite` timeouts are the idle bound (`HTTP_IDLE`): a stall.
pub(crate) fn classify(error: &ureq::Error) -> (ImageFailureCause, Option<std::io::ErrorKind>) {
    use ImageFailureCause as C;
    match error {
        ureq::Error::Timeout(reason) => (
            match reason {
                ureq::Timeout::PerRead | ureq::Timeout::PerWrite => C::Stalled,
                ureq::Timeout::Connect | ureq::Timeout::Resolve => C::Connect,
                _ => C::Timeout,
            },
            None,
        ),
        ureq::Error::Io(io) => (classify_io(io), Some(io.kind())),
        ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::ConnectProxyFailed(_) => (C::Connect, None),
        ureq::Error::Tls(_)
        | ureq::Error::Rustls(_)
        | ureq::Error::Pem(_)
        | ureq::Error::TlsRequired => (C::Tls, None),
        ureq::Error::StatusCode(_) => (C::HttpStatus, None),
        _ => (C::Protocol, None),
    }
}

fn classify_io(io: &std::io::Error) -> ImageFailureCause {
    use ImageFailureCause as C;
    use std::io::ErrorKind as K;
    if io
        .get_ref()
        .is_some_and(|inner| inner.is::<rustls::Error>())
    {
        return C::Tls;
    }
    match io.kind() {
        K::TimedOut | K::WouldBlock => C::Stalled,
        K::ConnectionReset
        | K::ConnectionAborted
        | K::BrokenPipe
        | K::UnexpectedEof
        | K::NotConnected => C::Reset,
        K::ConnectionRefused
        | K::AddrNotAvailable
        | K::AddrInUse
        | K::HostUnreachable
        | K::NetworkUnreachable
        | K::NetworkDown => C::Connect,
        _ => C::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn every_transport_error_shape_has_its_cause() {
        use ImageFailureCause as C;
        let cases: Vec<(ureq::Error, C)> = vec![
            (ureq::Error::Timeout(ureq::Timeout::PerWrite), C::Stalled),
            (ureq::Error::Timeout(ureq::Timeout::PerRead), C::Stalled),
            (
                ureq::Error::Timeout(ureq::Timeout::RecvResponse),
                C::Timeout,
            ),
            (ureq::Error::Timeout(ureq::Timeout::SendBody), C::Timeout),
            (ureq::Error::Timeout(ureq::Timeout::Global), C::Timeout),
            (ureq::Error::Timeout(ureq::Timeout::Connect), C::Connect),
            (ureq::Error::Timeout(ureq::Timeout::Resolve), C::Connect),
            (Error::from(ErrorKind::ConnectionReset).into(), C::Reset),
            (Error::from(ErrorKind::BrokenPipe).into(), C::Reset),
            (Error::from(ErrorKind::UnexpectedEof).into(), C::Reset),
            (Error::from(ErrorKind::ConnectionAborted).into(), C::Reset),
            (Error::from(ErrorKind::ConnectionRefused).into(), C::Connect),
            (Error::from(ErrorKind::HostUnreachable).into(), C::Connect),
            (Error::from(ErrorKind::TimedOut).into(), C::Stalled),
            (Error::from(ErrorKind::InvalidData).into(), C::Protocol),
            (
                ureq::Error::Io(Error::new(
                    ErrorKind::InvalidData,
                    rustls::Error::DecryptError,
                )),
                C::Tls,
            ),
            (ureq::Error::HostNotFound, C::Connect),
            (ureq::Error::ConnectionFailed, C::Connect),
            (ureq::Error::Tls("bad"), C::Tls),
            (ureq::Error::Rustls(rustls::Error::DecryptError), C::Tls),
            (ureq::Error::StatusCode(503), C::HttpStatus),
            (
                ureq::Error::BadUri("https://x/?X-Amz-Signature=s".into()),
                C::Protocol,
            ),
            (ureq::Error::BodyExceedsLimit(1), C::Protocol),
        ];
        for (error, cause) in cases {
            assert_eq!(classify(&error).0, cause, "{error:?}");
        }
        let reset = UploadFailure::transport(&Error::from(ErrorKind::ConnectionReset).into());
        assert_eq!(reset.io_kind, Some(ErrorKind::ConnectionReset));
        assert_eq!(reset.code, ImageFailureCode::Io);
        let stalled = UploadFailure::transport(&ureq::Error::Timeout(ureq::Timeout::PerWrite));
        assert_eq!(stalled.code, ImageFailureCode::Timeout);
    }

    #[test]
    fn statuses_are_captured_and_an_expired_url_is_named() {
        let s = UploadFailure::status(503, true);
        assert_eq!(
            (s.cause, s.http_status),
            (ImageFailureCause::HttpStatus, Some(503))
        );
        let early = UploadFailure::status(403, false);
        assert_eq!(early.cause, ImageFailureCause::HttpStatus);
        let late = UploadFailure::status(403, true);
        assert_eq!(
            (late.cause, late.http_status),
            (ImageFailureCause::UrlExpired, Some(403))
        );
    }

    /// Retried: timeouts, stalls, resets, connects, 5xx, 408, 429. Final:
    /// everything else, 403 included (the caller renews its URL once).
    #[test]
    fn only_transient_failures_are_retried() {
        use ImageFailureCause as C;
        for cause in [C::Timeout, C::Stalled, C::Reset, C::Connect] {
            assert!(
                UploadFailure::new(ImageFailureCode::Io, cause).retryable(),
                "{cause:?}"
            );
        }
        for status in [500, 502, 503, 504, 599, 408, 429] {
            assert!(UploadFailure::status(status, false).retryable(), "{status}");
        }
        for status in [400, 401, 403, 404, 409, 411, 413] {
            assert!(
                !UploadFailure::status(status, false).retryable(),
                "{status}"
            );
        }
        assert!(!UploadFailure::status(403, true).retryable());
        for cause in [
            C::Tls,
            C::LocalIo,
            C::Export,
            C::NoGrant,
            C::Refused,
            C::Protocol,
        ] {
            assert!(
                !UploadFailure::new(ImageFailureCode::Io, cause).retryable(),
                "{cause:?}"
            );
        }
        assert!(!UploadFailure::refused("cancelled").retryable());
        assert!(!UploadFailure::local_io(std::io::ErrorKind::TimedOut).retryable());
    }

    #[test]
    fn cancels_are_refusals_except_when_another_upload_stores_the_image() {
        assert_eq!(UploadEnd::cancelled("already_stored"), UploadEnd::Silent);
        assert_eq!(
            UploadEnd::cancelled("upload_in_progress"),
            UploadEnd::Silent
        );
        let UploadEnd::Failed(refused) = UploadEnd::cancelled("image_quota_exceeded") else {
            panic!("a quota refusal is a failure");
        };
        assert_eq!(refused.cause, ImageFailureCause::Refused);
        assert_eq!(refused.refusal.as_deref(), Some("image_quota_exceeded"));
        assert_eq!(
            UploadFailure::refused("Not A Code").refusal.as_deref(),
            Some("cancelled")
        );
    }

    /// Frames are valid for both references and carry exactly one.
    #[test]
    fn frames_name_the_transfer_else_the_operation_and_stay_valid() {
        let failure = UploadFailure::status(503, false).at_part(2);
        let by_transfer = failure.frame(Some("tr-1"), Some(("op-1", 1))).unwrap();
        assert_eq!(by_transfer.transfer_id.as_deref(), Some("tr-1"));
        assert!(by_transfer.operation_id.is_none() && by_transfer.attempt.is_none());
        assert!(by_transfer.is_valid());
        let by_operation = UploadFailure::new(ImageFailureCode::Io, ImageFailureCause::Export)
            .frame(None, Some(("op-1", 3)))
            .unwrap();
        assert_eq!(
            (by_operation.operation_id.as_deref(), by_operation.attempt),
            (Some("op-1"), Some(3))
        );
        assert!(by_operation.is_valid());
        assert!(UploadFailure::refused("stale").frame(None, None).is_none());
        assert!(
            UploadFailure::refused("stale_transfer")
                .frame(Some("t"), None)
                .unwrap()
                .is_valid()
        );
    }

    /// Nothing URL-bearing survives into what is logged or sent: a failure
    /// keeps only enums, a status, a part and a code-shaped refusal.
    #[test]
    fn nothing_url_bearing_reaches_the_failure() {
        let url = "https://bucket.example/k?X-Amz-Signature=secretsig";
        for error in [
            ureq::Error::BadUri(url.into()),
            ureq::Error::Io(Error::other(url)),
            ureq::Error::ConnectProxyFailed(url.into()),
        ] {
            let failure = UploadFailure::transport(&error);
            let text = format!("{failure:?}");
            assert!(
                !text.contains("Signature") && !text.contains("bucket"),
                "{text}"
            );
            let frame = failure.frame(Some("t"), None).unwrap();
            let json = serde_json::to_string(&frame).unwrap();
            assert!(!json.contains("Signature"), "{json}");
        }
        assert_eq!(
            UploadFailure::refused(url).refusal.as_deref(),
            Some("cancelled")
        );
    }
}
