//! The sole supervised framing parser. Inspect raw bytes; never normalize text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The private, nonce-bound cleanup banner. Guest PID files are never read
/// back or adopted (4b, P2-3): no advisory variant exists to confer authority.
pub enum GuestPid {
    Banner(u32),
}
impl GuestPid {
    pub fn banner(self) -> Option<u32> {
        match self {
            Self::Banner(pid) => Some(pid),
        }
    }
}

/// The single public start identity: the wrapper's post-setup record emitted
/// immediately after its private cleanup PID banner and before `exec` of user
/// code. Guest-attested (the owner's code can read the nonce), so it binds only
/// at this exact stream position and never from later bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartReady {
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: u64,
}

/// Longest possible READY record after its prefix: pid, UUID, ticks, three
/// separators/terminator. Bound applies before any allocation or parse.
const READY_BODY_MAX: usize = 10 + 1 + 36 + 1 + 20 + 1;
/// Bytes after the PID banner that can still belong to the READY record,
/// excluding the nonce itself (callers add its length).
pub const READY_HEAD_MAX: usize = "WSSP_READY ".len() + 1 + READY_BODY_MAX;

pub(super) fn valid_boot_id(boot: &[u8]) -> bool {
    boot.len() == 36
        && boot.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}

/// Parse the READY record at the exact head position following the PID banner.
/// The record's PID must equal the banner PID (both are the wrapper's `$$`).
/// The guest's current boot id from the exact nonce-bound
/// `WSSP_BOOT <nonce> <uuid>` record (and nothing else on either stream).
pub(super) fn parse_boot_record(nonce: &str, stdout: &str, stderr: &str) -> Option<String> {
    let boot = stderr
        .strip_prefix(&format!("WSSP_BOOT {nonce} "))?
        .strip_suffix('\n')?;
    (stdout.is_empty() && valid_boot_id(boot.as_bytes())).then(|| boot.to_string())
}

fn parse_ready_frame(rest: &[u8], nonce: &str, banner: u32) -> Option<(StartReady, usize)> {
    let prefix = format!("WSSP_READY {nonce} ");
    let body = rest.strip_prefix(prefix.as_bytes())?;
    let end = body.iter().take(READY_BODY_MAX).position(|b| *b == b'\n')?;
    let mut fields = body[..end].split(|b| *b == b' ');
    let (Some(pid), Some(boot), Some(ticks), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    let digits = |value: &[u8], max: usize| {
        (1..=max).contains(&value.len())
            && value.iter().all(u8::is_ascii_digit)
            && value.first() != Some(&b'0')
    };
    if !digits(pid, 10) || !digits(ticks, 20) || !valid_boot_id(boot) {
        return None;
    }
    let pid = std::str::from_utf8(pid).ok()?.parse::<u32>().ok()?;
    let start_ticks = std::str::from_utf8(ticks).ok()?.parse::<u64>().ok()?;
    if pid != banner || pid < 2 || start_ticks == 0 {
        return None;
    }
    let boot_id = std::str::from_utf8(boot).ok()?.to_string();
    Some((
        StartReady {
            pid,
            boot_id,
            start_ticks,
        },
        prefix.len() + end + 1,
    ))
}

/// Supervised stream head: private cleanup banner, then the optional public
/// start record. Returns the combined head length.
fn parse_head(stderr: &[u8], nonce: &str) -> Option<(GuestPid, Option<StartReady>, usize)> {
    let (pid, head) = parse_pid_frame(stderr, nonce)?;
    let banner = pid.banner()?;
    match parse_ready_frame(&stderr[head..], nonce, banner) {
        Some((ready, length)) => Some((pid, Some(ready), head + length)),
        None => Some((pid, None, head)),
    }
}

/// Live head decision for publication: `None` while more bytes could still
/// complete the PID banner or the READY record at its fixed position.
pub fn decide_head(stderr: &[u8], nonce: &str, end: bool) -> Option<Option<StartReady>> {
    let pid_prefix = format!("WSSP_PID {nonce} ");
    let Some((pid, head)) = parse_pid_frame(stderr, nonce) else {
        let pending = stderr.len() < pid_prefix.len() + 11
            && (pid_prefix.as_bytes().starts_with(stderr)
                || stderr.starts_with(pid_prefix.as_bytes()));
        return (end || !pending).then_some(None);
    };
    let rest = &stderr[head..];
    if let Some(banner) = pid.banner()
        && let Some((ready, _)) = parse_ready_frame(rest, nonce, banner)
    {
        return Some(Some(ready));
    }
    let ready_prefix = format!("WSSP_READY {nonce} ");
    let pending = !rest.contains(&b'\n')
        && rest.len() < ready_prefix.len() + READY_BODY_MAX
        && (ready_prefix.as_bytes().starts_with(rest) || rest.starts_with(ready_prefix.as_bytes()));
    (end || !pending).then_some(None)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SupervisedFrames<'a> {
    pub pid_frame: Option<GuestPid>,
    /// Public start identity, accepted only at the fixed head position.
    pub ready: Option<StartReady>,
    pub exit: Option<i32>,
    pub setup_failed: Option<i32>,
    pub user_stdout: &'a [u8],
    pub user_stderr: &'a [u8],
}

fn parse_pid_frame(stderr: &[u8], nonce: &str) -> Option<(GuestPid, usize)> {
    let prefix = format!("WSSP_PID {nonce} ");
    stderr.strip_prefix(prefix.as_bytes()).and_then(|rest| {
        let end = rest.iter().take(11).position(|b| *b == b'\n')?;
        let digits = &rest[..end];
        if !(1..=10).contains(&digits.len()) || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let pid = std::str::from_utf8(digits).ok()?.parse::<u32>().ok()?;
        Some((GuestPid::Banner(pid), prefix.len() + end + 1))
    })
}

enum CompletionFrame {
    Exit(i32),
    SetupFailed(i32),
}

// One exact grammar for both the natural suffix and cancellation arbitration.
// The candidate includes its own leading and trailing newline. Integer overflow
// cannot become completion evidence; no text normalization is allowed.
fn parse_completion_frame(frame: &[u8], nonce: &str) -> Option<CompletionFrame> {
    let (rest, setup) = if let Some(rest) = frame.strip_prefix(b"\nWSSP_EXIT ") {
        (rest, false)
    } else {
        (frame.strip_prefix(b"\nWSSP_SETUP_FAILED ")?, true)
    };
    let code = rest
        .strip_prefix(nonce.as_bytes())?
        .strip_prefix(b" ")?
        .strip_suffix(b"\n")?;
    let digits = code.strip_prefix(b"-").unwrap_or(code);
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = std::str::from_utf8(code).ok()?.parse().ok()?;
    Some(if setup {
        CompletionFrame::SetupFailed(value)
    } else {
        CompletionFrame::Exit(value)
    })
}

/// Scan the COMPLETE final stderr for any exact nonce-bound completion frame.
/// A frame followed by more bytes still prevents cancellation, but does not
/// establish a natural result. Chunk boundaries have no meaning in this buffer.
pub fn has_completion_frame(stderr: &[u8], nonce: &str) -> bool {
    // The PID terminator cannot double as a completion's leading newline.
    // Without a PID prefix, an exact frame still conservatively bars cancellation.
    let head = parse_head(stderr, nonce).map_or(0, |(_, _, head)| head);
    let mut start = None;
    for (end, byte) in stderr.iter().enumerate().skip(head) {
        if *byte == b'\n' {
            if start
                .is_some_and(|start| parse_completion_frame(&stderr[start..=end], nonce).is_some())
            {
                return true;
            }
            start = Some(end);
        }
    }
    false
}

pub fn parse_supervised_frames<'a>(
    stdout: &'a [u8],
    stderr: &'a [u8],
    nonce: &str,
) -> SupervisedFrames<'a> {
    let parsed = parse_head(stderr, nonce);
    let mut exit = None;
    let mut setup_failed = None;
    let mut suffix_start = None;
    if let Some((_, _, head)) = parsed
        && let Some(without_lf) = stderr.strip_suffix(b"\n")
        && let Some(start) = without_lf.iter().rposition(|b| *b == b'\n')
        && start >= head
        && let Some(frame) = parse_completion_frame(&stderr[start..], nonce)
    {
        match frame {
            CompletionFrame::Exit(value) => exit = Some(value),
            CompletionFrame::SetupFailed(value) => setup_failed = Some(value),
        }
        suffix_start = Some(start);
    }
    // With no accepted suffix, even a valid PID prefix remains user output.
    let user_stderr = match (&parsed, suffix_start) {
        (Some((_, _, head)), Some(tail)) if tail >= *head => &stderr[*head..tail],
        _ => stderr,
    };
    SupervisedFrames {
        pid_frame: parsed.as_ref().map(|(pid, _, _)| *pid),
        ready: parsed.and_then(|(_, ready, _)| ready),
        exit,
        setup_failed,
        user_stdout: stdout,
        user_stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the exact nonce-bound boot record is a boot id.
    #[test]
    fn boot_record_accepts_only_the_exact_nonce_bound_uuid() {
        let boot = "12345678-1234-4234-8234-123456789abc";
        assert_eq!(
            parse_boot_record("n1", "", &format!("WSSP_BOOT n1 {boot}\n")).as_deref(),
            Some(boot)
        );
        for (stdout, stderr) in [
            ("", format!("WSSP_BOOT n2 {boot}\n")),
            ("", format!("WSSP_BOOT n1 {boot}")),
            ("x", format!("WSSP_BOOT n1 {boot}\n")),
            ("", format!("noise\nWSSP_BOOT n1 {boot}\n")),
            ("", format!("WSSP_BOOT n1 {boot}\nWSSP_BOOT n1 {boot}\n")),
            (
                "",
                "WSSP_BOOT n1 12345678-1234-4234-8234-123456789ABC\n".to_string(),
            ),
            ("", "WSSP_BOOT n1 \n".to_string()),
        ] {
            assert_eq!(parse_boot_record("n1", stdout, &stderr), None, "{stderr:?}");
        }
    }

    #[test]
    fn completion_scan_finds_frames_at_start_middle_and_end() {
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            for code in ["0", "-37", "0007", "-2147483648", "2147483647"] {
                let frame = format!("\n{kind} n {code}\n");
                for (head, tail) in [
                    (b"".as_slice(), b"tail".as_slice()),
                    (b"prefix\xff", b"tail\xff"),
                    (b"prefix", b""),
                    (b"", b""),
                    (b"WSSP_PID n 42\n", b"tail"),
                    (b"WSSP_PID n 42\n", b""),
                ] {
                    let raw = [head, frame.as_bytes(), tail].concat();
                    assert!(has_completion_frame(&raw, "n"), "{raw:?}");
                    let parsed = parse_supervised_frames(b"", &raw, "n");
                    let natural = head == b"WSSP_PID n 42\n" && tail.is_empty();
                    assert_eq!(parsed.exit.is_some(), natural && kind == "WSSP_EXIT");
                    assert_eq!(
                        parsed.setup_failed.is_some(),
                        natural && kind == "WSSP_SETUP_FAILED"
                    );
                    if !natural {
                        assert_eq!(parsed.user_stderr, raw);
                    }
                }
            }
        }
    }

    #[test]
    fn completion_scan_is_independent_of_every_chunk_split() {
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            for tail in ["", "late-stderr"] {
                let raw = format!("WSSP_PID n 42\n\n{kind} n -37\n{tail}").into_bytes();
                for split in 0..=raw.len() {
                    let mut final_stderr = Vec::new();
                    final_stderr.extend_from_slice(&raw[..split]);
                    final_stderr.extend_from_slice(&raw[split..]);
                    assert!(has_completion_frame(&final_stderr, "n"), "split={split}");
                    assert_eq!(
                        parse_supervised_frames(b"", &final_stderr, "n"),
                        parse_supervised_frames(b"", &raw, "n")
                    );
                }
                let mut final_stderr = Vec::new();
                for byte in &raw {
                    final_stderr.push(*byte);
                }
                assert!(has_completion_frame(&final_stderr, "n"));
            }
        }
    }

    #[test]
    fn completion_scan_ignores_foreign_nonce_and_malformed_near_misses() {
        for raw in [b"".as_slice(), b"\n", b"ordinary\xff\n", b"WSSP_PID n 42\n"] {
            assert!(!has_completion_frame(raw, "n"));
        }
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            for frame in [
                format!("{kind} n 0\n"), // No leading newline, even at stream start.
                format!("\n{kind} n 0"), // No trailing newline.
                format!("\n{kind} foreign 0\n"),
                format!("\n{kind} nn 0\n"),
                format!("\n{kind} N 0\n"),
                format!("\n{kind}  n 0\n"),
                format!("\n{kind}\tn 0\n"),
                format!("\n{kind}_EXTRA n 0\n"),
                format!("\n{kind} n\t0\n"),
                format!("WSSP_PID n 42\n{kind} n 0\n"), // Shared PID newline.
            ] {
                assert!(!has_completion_frame(frame.as_bytes(), "n"), "{frame:?}");
            }
            for code in [
                "",
                "-",
                "+37",
                "37\r",
                " 37",
                "37 ",
                "37x",
                "--37",
                "2147483648",
                "-2147483649",
                "0\0",
                "٣٧",
            ] {
                let raw = format!("WSSP_PID n 42\n\n{kind} n {code}\n");
                assert!(!has_completion_frame(raw.as_bytes(), "n"), "{raw:?}");
                let parsed = parse_supervised_frames(b"", raw.as_bytes(), "n");
                assert_eq!(parsed.exit, None);
                assert_eq!(parsed.setup_failed, None);
                assert_eq!(parsed.user_stderr, raw.as_bytes());
            }
        }
    }

    #[test]
    fn completion_scan_keeps_earlier_frames_despite_foreign_or_malformed_tails() {
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            let raw = format!(
                "WSSP_PID n 42\n\n{kind} foreign 0\n\n{kind} n 1\n\n{kind} n +2\n\n{kind} foreign 3\n"
            );
            assert!(has_completion_frame(raw.as_bytes(), "n"));
            let parsed = parse_supervised_frames(b"", raw.as_bytes(), "n");
            assert_eq!(parsed.exit, None);
            assert_eq!(parsed.setup_failed, None);
            assert_eq!(parsed.user_stderr, raw.as_bytes());
        }
    }

    #[test]
    fn completion_suffix_must_have_its_own_newline() {
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            let raw = format!("WSSP_PID n 4242\n{kind} n 37\n");
            let parsed = parse_supervised_frames(b"out\xff", raw.as_bytes(), "n");
            assert_eq!(parsed.pid_frame, Some(GuestPid::Banner(4242)));
            assert_eq!(parsed.exit, None);
            assert_eq!(parsed.setup_failed, None);
            assert_eq!(parsed.user_stdout, b"out\xff");
            assert_eq!(parsed.user_stderr, raw.as_bytes());
            assert!(!has_completion_frame(raw.as_bytes(), "n"));

            // Empty user output still has TWO frame-boundary newlines.
            let valid = format!("WSSP_PID n 4242\n\n{kind} n 37\n");
            let parsed = parse_supervised_frames(b"", valid.as_bytes(), "n");
            assert!(has_completion_frame(valid.as_bytes(), "n"));
            assert_eq!(parsed.user_stderr, b"");
            assert_eq!(parsed.exit, (kind == "WSSP_EXIT").then_some(37));
            assert_eq!(
                parsed.setup_failed,
                (kind == "WSSP_SETUP_FAILED").then_some(37)
            );
        }
    }

    #[test]
    fn strict_frames_and_lossless_missing_suffix() {
        for pid in [
            "+4242",
            "-4242",
            "4242\r",
            " 4242",
            "00000000001",
            "4294967296",
        ] {
            let raw = format!("WSSP_PID n {pid}\n\nWSSP_EXIT n 0\n");
            assert_eq!(
                parse_supervised_frames(b"", raw.as_bytes(), "n").pid_frame,
                None
            );
        }
        for code in ["37\r", "  +37  ", "+37", "37 ", "", "-", "2147483648"] {
            let raw = format!("WSSP_PID n 42\nuser\nWSSP_EXIT n {code}\n");
            let parsed = parse_supervised_frames(b"\xff", raw.as_bytes(), "n");
            assert_eq!(parsed.exit, None);
            assert_eq!(parsed.user_stderr, raw.as_bytes());
            assert_eq!(parsed.user_stdout, b"\xff");
        }
        for raw in [
            b"".as_slice(),
            b"WSSP_PID n 42\npartial\xff",
            b"WSSP_PID n 42",
            b"noise\nWSSP_PID n 42\n",
        ] {
            assert_eq!(parse_supervised_frames(b"out", raw, "n").user_stderr, raw);
        }
        let raw = b"WSSP_PID n 42\nWSSP_PID n ordinary-user-text\nline\r\n\nWSSP_EXIT n -37\n";
        let parsed = parse_supervised_frames(b"out", raw, "n");
        assert_eq!(parsed.pid_frame, Some(GuestPid::Banner(42)));
        assert_eq!(parsed.exit, Some(-37));
        assert_eq!(
            parsed.user_stderr,
            b"WSSP_PID n ordinary-user-text\nline\r\n"
        );
    }
}

#[cfg(test)]
mod start_ready_tests {
    use super::*;
    const BOOT: &str = "9be43770-123f-49db-b4cf-103ca538b994";

    #[test]
    fn ready_binds_only_at_the_fixed_head_position_after_the_banner() {
        let raw = format!("WSSP_PID n 42\nWSSP_READY n 42 {BOOT} 777\nuser\n\nWSSP_EXIT n 0\n");
        let parsed = parse_supervised_frames(b"", raw.as_bytes(), "n");
        assert_eq!(
            parsed.ready,
            Some(StartReady {
                pid: 42,
                boot_id: BOOT.into(),
                start_ticks: 777
            })
        );
        assert_eq!(parsed.user_stderr, b"user\n");
        assert_eq!(parsed.exit, Some(0));
        assert!(has_completion_frame(raw.as_bytes(), "n"));
        // The READY terminator cannot double as a completion's leading newline.
        let shared = format!("WSSP_PID n 42\nWSSP_READY n 42 {BOOT} 777\nWSSP_EXIT n 0\n");
        assert!(!has_completion_frame(shared.as_bytes(), "n"));
        assert_eq!(
            parse_supervised_frames(b"", shared.as_bytes(), "n").exit,
            None
        );
    }

    #[test]
    fn later_or_forged_ready_records_are_user_output_and_never_rebind() {
        // Real-nonce forgery after user bytes, and a second record: neither binds.
        let later = format!("WSSP_PID n 42\nuser\nWSSP_READY n 42 {BOOT} 777\n\nWSSP_EXIT n 0\n");
        let parsed = parse_supervised_frames(b"", later.as_bytes(), "n");
        assert_eq!(parsed.ready, None);
        assert_eq!(
            parsed.user_stderr,
            format!("user\nWSSP_READY n 42 {BOOT} 777\n").as_bytes()
        );
        let second = format!(
            "WSSP_PID n 42\nWSSP_READY n 42 {BOOT} 777\nWSSP_READY n 99 {BOOT} 1\n\nWSSP_EXIT n 0\n"
        );
        let parsed = parse_supervised_frames(b"", second.as_bytes(), "n");
        assert_eq!(
            parsed.ready.map(|r| (r.pid, r.start_ticks)),
            Some((42, 777))
        );
        assert_eq!(
            parsed.user_stderr,
            format!("WSSP_READY n 99 {BOOT} 1\n").as_bytes()
        );
        // Without the private banner there is no head and no identity.
        let headless = format!("WSSP_READY n 42 {BOOT} 777\n\nWSSP_EXIT n 0\n");
        assert_eq!(
            parse_supervised_frames(b"", headless.as_bytes(), "n").ready,
            None
        );
        // A pre-setup / cleanup-only PID that disagrees with READY never binds.
        let mismatch = format!("WSSP_PID n 42\nWSSP_READY n 43 {BOOT} 777\n\nWSSP_EXIT n 0\n");
        let parsed = parse_supervised_frames(b"", mismatch.as_bytes(), "n");
        assert_eq!(parsed.ready, None);
        assert_eq!(parsed.pid_frame, Some(GuestPid::Banner(42)));
    }

    #[test]
    fn malformed_ready_records_are_refused_before_allocation() {
        for body in [
            format!("42 {BOOT} 0"),
            format!("42 {BOOT} 0777"),
            format!("42 {BOOT} +777"),
            format!("042 {BOOT} 777"),
            format!("42 {} 777", BOOT.to_uppercase()),
            format!("42 {BOOT}0 777"),
            format!("42  {BOOT} 777"),
            format!("42 {BOOT} 777 extra"),
            format!("42 {BOOT} 777\r"),
            format!("42 {BOOT} 18446744073709551616"),
            format!("42 {BOOT} {}", "9".repeat(64)),
            "42".to_string(),
        ] {
            let raw = format!("WSSP_PID n 42\nWSSP_READY n {body}\n\nWSSP_EXIT n 0\n");
            assert_eq!(
                parse_supervised_frames(b"", raw.as_bytes(), "n").ready,
                None,
                "{body:?}"
            );
        }
        let pid_one = format!("WSSP_PID n 1\nWSSP_READY n 1 {BOOT} 7\n");
        assert_eq!(
            parse_supervised_frames(b"", pid_one.as_bytes(), "n").ready,
            None
        );
    }

    #[test]
    fn live_head_decision_waits_only_for_a_possible_fixed_record() {
        let raw = format!("WSSP_PID n 42\nWSSP_READY n 42 {BOOT} 777\nuser");
        for split in 0..raw.len() {
            let head = &raw.as_bytes()[..split];
            match decide_head(head, "n", false) {
                None => {}
                Some(decision) => {
                    let complete = raw.find("777\n").map(|i| i + 4).unwrap_or(usize::MAX);
                    assert!(split >= complete, "decided early at {split}: {decision:?}");
                    assert!(decision.is_some());
                }
            }
        }
        assert_eq!(decide_head(b"WSSP_PID n 42\nuser", "n", false), Some(None));
        assert_eq!(decide_head(b"noise", "n", false), Some(None));
        assert_eq!(
            decide_head(b"WSSP_PID n 42\nWSSP_RE", "n", true),
            Some(None)
        );
        // A setup failure emits no READY: decided with no identity.
        assert_eq!(
            decide_head(b"WSSP_PID n 42\n\nWSSP_SETUP_FAILED n 1\n", "n", false),
            Some(None)
        );
    }

    #[test]
    fn live_filter_strips_ready_at_every_split() {
        use std::sync::atomic::AtomicBool;
        let raw = format!("WSSP_PID n 42\nWSSP_READY n 42 {BOOT} 777\nerr\n\nWSSP_EXIT n 0\n");
        for split in 0..=raw.len() {
            let mut filter = LiveStderr::new("n");
            let seen = AtomicBool::new(false);
            let mut ready = filter.feed(&raw.as_bytes()[..split], false, &seen);
            ready.extend(filter.feed(&raw.as_bytes()[split..], false, &seen));
            ready.extend(filter.feed(&[], true, &seen));
            assert_eq!(ready, b"err\n", "split={split}");
        }
    }
}

/// Incremental stderr filtering. Keep only a possible nonce-bound frame, never
/// an arbitrary line. Completion observations are latched before eviction.
pub(super) struct LiveStderr {
    pending: Vec<u8>,
    prefix: bool,
    pid: bool,
    /// Banner PID while the fixed-position READY record may still follow.
    ready: Option<u32>,
    nonce: String,
    scan_tail: Vec<u8>,
}
impl LiveStderr {
    pub fn new(nonce: &str) -> Self {
        Self {
            pending: Vec::new(),
            prefix: true,
            pid: false,
            ready: None,
            nonce: nonce.into(),
            scan_tail: Vec::new(),
        }
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        end: bool,
        seen: &std::sync::atomic::AtomicBool,
    ) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        self.scan_tail.extend_from_slice(bytes);
        if has_completion_frame(&self.scan_tail, &self.nonce) {
            seen.store(true, Ordering::Release);
        }
        if self.scan_tail.len() > 256 {
            self.scan_tail.drain(..self.scan_tail.len() - 256);
        }
        self.pending.extend_from_slice(bytes);
        if self.prefix {
            let prefix = format!("WSSP_PID {} ", self.nonce);
            if let Some((pid, length)) = parse_pid_frame(&self.pending, &self.nonce) {
                self.pending.drain(..length);
                self.pid = true;
                self.ready = pid.banner();
                self.prefix = false;
            } else if !end
                && self.pending.len() < prefix.len() + 11
                && (prefix.as_bytes().starts_with(&self.pending)
                    || self.pending.starts_with(prefix.as_bytes()))
            {
                return Vec::new();
            } else {
                self.prefix = false;
            }
        }
        if let Some(banner) = self.ready {
            let prefix = format!("WSSP_READY {} ", self.nonce);
            if let Some((_, length)) = parse_ready_frame(&self.pending, &self.nonce, banner) {
                self.pending.drain(..length);
                self.ready = None;
            } else if !end
                && !self.pending.contains(&b'\n')
                && self.pending.len() < prefix.len() + READY_BODY_MAX
                && (prefix.as_bytes().starts_with(&self.pending)
                    || self.pending.starts_with(prefix.as_bytes()))
            {
                return Vec::new();
            } else {
                self.ready = None;
            }
        }
        let mut keep = self.pending.len();
        if self.pid {
            for prefix in [
                format!("\nWSSP_EXIT {} ", self.nonce),
                format!("\nWSSP_SETUP_FAILED {} ", self.nonce),
            ] {
                for start in self.pending.len().saturating_sub(128)..self.pending.len() {
                    let suffix = &self.pending[start..];
                    if end {
                        if parse_completion_frame(suffix, &self.nonce).is_some() {
                            keep = keep.min(start);
                        }
                    } else if prefix.as_bytes().starts_with(suffix)
                        || (suffix.starts_with(prefix.as_bytes())
                            && suffix.len() <= prefix.len() + 12
                            && suffix[prefix.len()..]
                                .iter()
                                .all(|b| b.is_ascii_digit() || *b == b'-'))
                        || parse_completion_frame(suffix, &self.nonce).is_some()
                    {
                        keep = keep.min(start);
                    }
                }
            }
        }
        let ready = self.pending.drain(..keep).collect();
        if end {
            self.pending.clear();
        }
        ready
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[test]
    fn live_stderr_handles_every_split_zero_output_and_latches_evicted_completion() {
        for body in [b"".as_slice(), b"err\xe2\x82\xac", b"\nWSSP_EXIT wrong 0\n"] {
            let raw = [
                b"WSSP_PID nonce 42\n".as_slice(),
                body,
                b"\nWSSP_EXIT nonce 0\n",
            ]
            .concat();
            for split in 0..=raw.len() {
                let mut filter = LiveStderr::new("nonce");
                let seen = AtomicBool::new(false);
                let mut ready = filter.feed(&raw[..split], false, &seen);
                ready.extend(filter.feed(&raw[split..], false, &seen));
                ready.extend(filter.feed(&[], true, &seen));
                assert_eq!(ready, body, "split={split}");
                assert!(seen.load(Ordering::Acquire));
            }
        }
        let mut filter = LiveStderr::new("nonce");
        let seen = AtomicBool::new(false);
        filter.feed(b"WSSP_PID nonce 42\n\nWSSP_EXIT nonce 0\n", false, &seen);
        for _ in 0..1000 {
            filter.feed(&[b'x'; 8192], false, &seen);
        }
        assert!(seen.load(Ordering::Acquire));
        assert!(filter.pending.len() <= 128 && filter.scan_tail.len() <= 256);
    }
}
