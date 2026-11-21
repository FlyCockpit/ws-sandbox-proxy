//! SSH requests → wssp channels (docs/guide/connect.md#ssh), without IO.
//!
//! | SSH request                    | wssp channel                                    |
//! | ------------------------------ | ----------------------------------------------- |
//! | `pty-req` + `shell`            | `pty`, the guest user's login shell             |
//! | `pty-req` + `exec`             | `pty`, `<shell> -c <command>`                   |
//! | `exec`                         | `exec`, `<shell> -c <command>`                  |
//! | `shell`                        | `exec`, the login shell reading stdin           |
//! | `subsystem sftp`               | `exec`, the guest's `sftp-server` (probed)      |
//! | `direct-tcpip` to loopback     | `tcp` to that guest loopback port               |
//! | `direct-streamlocal@openssh.com` | `unix` to that absolute guest path            |
//!
//! `<shell>` is the guest user's login shell (`$SHELL` in the guest, which the
//! node sets from the sandbox's guest identity), exactly as sshd runs
//! `$SHELL -c <command>`: the command string reaches it as one argument,
//! never re-split. Everything else (agent and X11 forwarding, `tcpip-forward`,
//! `streamlocal-forward`, other subsystems, a forward to a non-loopback host)
//! is refused.

use std::collections::BTreeMap;

use russh::{ChannelOpenFailure, Sig};

use crate::connect_client::mux::Outcome;
use crate::connect_client::wire::{Intent, Kind, PtyParams, Signal};

/// The host suffix of the generated ssh config (`Host *.wssp`).
pub const HOST_SUFFIX: &str = ".wssp";
/// `TERM` when `pty-req` names none the wire accepts.
pub const DEFAULT_TERM: &str = "xterm-256color";
/// Size of a `pty-req` that gives none (0 × 0).
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;

/// The guest command line: `/bin/sh` only hands the command string, as one
/// argument, to the guest user's own shell (`$SHELL -c <command>`). `$0` of
/// the wrapper is [`WRAPPER_NAME`].
pub const SHELL_COMMAND: &str = r#"exec "${SHELL:-/bin/sh}" -c "$1""#;
const WRAPPER_NAME: &str = "wssp-ssh";

/// Where guests keep OpenSSH's `sftp-server`, in probe order.
pub const SFTP_SERVER_PATHS: [&str; 4] = [
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/sftp-server",
];

/// What a session channel was asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRequest {
    Shell,
    Exec(Vec<u8>),
    Subsystem(String),
}

/// A `pty-req`, as far as the wire carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    pub term: String,
    pub rows: u16,
    pub cols: u16,
}

impl PtyRequest {
    pub fn new(term: &str, cols: u32, rows: u32) -> Self {
        let (rows, cols) = size_of(cols, rows);
        Self {
            term: term_of(term),
            rows,
            cols,
        }
    }
}

/// The `open` of a session channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub kind: Kind,
    pub argv: Option<Vec<String>>,
    pub login: bool,
    pub pty: Option<PtyParams>,
}

/// Why a session request is refused (the request fails; the text goes to
/// the channel's stderr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

/// The channel a session request opens. A subsystem never gets a terminal
/// (sftp is a byte protocol), whatever `pty-req` said.
pub fn plan(pty: Option<&PtyRequest>, request: &SessionRequest) -> Result<Plan, Refusal> {
    let terminal = |argv: Option<Vec<String>>, login: bool| match pty {
        Some(pty) => Plan {
            kind: Kind::Pty,
            argv,
            login,
            pty: Some(PtyParams {
                rows: pty.rows,
                cols: pty.cols,
                term: pty.term.clone(),
            }),
        },
        None => Plan {
            kind: Kind::Exec,
            argv,
            login,
            pty: None,
        },
    };
    match request {
        // sshd runs a session without a command as a login shell, with or
        // without a terminal.
        SessionRequest::Shell => Ok(terminal(None, true)),
        SessionRequest::Exec(command) => Ok(terminal(Some(command_argv(command)?), false)),
        SessionRequest::Subsystem(name) if name == "sftp" => Ok(Plan {
            kind: Kind::Exec,
            argv: Some(sftp_argv(&SFTP_SERVER_PATHS)),
            login: false,
            pty: None,
        }),
        SessionRequest::Subsystem(_) => Err(Refusal("wssp: only the sftp subsystem is available")),
    }
}

/// `$SHELL -c <command>` as a structural argv. The command must be UTF-8
/// (the wire carries strings) without NUL, within the argv bound.
pub fn command_argv(command: &[u8]) -> Result<Vec<String>, Refusal> {
    let command = std::str::from_utf8(command)
        .map_err(|_| Refusal("wssp: the command is not valid UTF-8"))?;
    let argv = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        SHELL_COMMAND.to_owned(),
        WRAPPER_NAME.to_owned(),
        command.to_owned(),
    ];
    if sandbox_protocol::valid_channel_argv(&argv) {
        Ok(argv)
    } else {
        Err(Refusal("wssp: the command is too long or contains NUL"))
    }
}

/// The sftp subsystem: the first executable `sftp-server` of `paths`, or a
/// message naming the package and exit 127.
pub fn sftp_argv(paths: &[&str]) -> Vec<String> {
    let mut script = String::from("for p in");
    for path in paths {
        script.push_str(" '");
        script.push_str(path);
        script.push('\'');
    }
    script.push_str(
        "; do if [ -x \"$p\" ]; then exec \"$p\"; fi; done; \
         echo 'wssp: this sandbox has no sftp-server; add the openssh-sftp-server package to its template (scp -O and rsync work without it)' >&2; \
         exit 127",
    );
    vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        script,
        "wssp-sftp".to_owned(),
    ]
}

/// The `TERM` of a `pty-req`, or [`DEFAULT_TERM`] when the wire refuses it.
pub fn term_of(term: &str) -> String {
    if sandbox_protocol::valid_channel_term(term) {
        term.to_owned()
    } else {
        DEFAULT_TERM.to_owned()
    }
}

/// `(rows, cols)` of an SSH size (`cols`, `rows` as SSH sends them),
/// clamped to 1–512 × 1–1024; an unknown 0 takes the 24 × 80 default.
pub fn size_of(cols: u32, rows: u32) -> (u16, u16) {
    let fit = |value: u32, default: u16| match value {
        0 => default,
        value => u16::try_from(value).unwrap_or(u16::MAX),
    };
    crate::connect_client::clamp_size(fit(rows, DEFAULT_ROWS), fit(cols, DEFAULT_COLS))
}

/// Whether an `env` request travels: only `COLORTERM`, `LANG` and `LC_*`
/// (sshd's default `AcceptEnv`), within the wire's bounds, and only while
/// `env` has room. `TERM` rides in `pty-req`.
pub fn accept_env(env: &BTreeMap<String, String>, name: &str, value: &str) -> bool {
    let room = env.len() < sandbox_protocol::CHANNEL_ENV_MAX_ENTRIES || env.contains_key(name);
    room && sandbox_protocol::valid_channel_env_name(name)
        && value.len() <= sandbox_protocol::CHANNEL_ENV_VALUE_MAX_BYTES
        && !value.contains('\0')
}

/// The wire signal of an SSH `signal` request; other names are ignored, as
/// RFC 4254 allows.
pub fn signal_of(signal: &Sig) -> Option<Signal> {
    match signal {
        Sig::INT => Some(Signal::Int),
        Sig::TERM => Some(Signal::Term),
        Sig::HUP => Some(Signal::Hup),
        Sig::KILL => Some(Signal::Kill),
        _ => None,
    }
}

/// The port of a `direct-tcpip` request when it targets the guest's own
/// loopback (`localhost`, `127.0.0.1` or `::1`); anything else would make
/// the guest an egress proxy outside the sandbox's own egress policy.
pub fn forward_target(host: &str, port: u32) -> Option<u16> {
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]";
    let port = u16::try_from(port).ok().filter(|port| *port > 0)?;
    loopback.then_some(port)
}

/// The path of a `direct-streamlocal@openssh.com` request when the wire
/// accepts it (absolute, at most 107 bytes, no NUL).
pub fn streamlocal_target(path: &str) -> Option<String> {
    sandbox_protocol::valid_channel_unix_path(path).then(|| path.to_owned())
}

/// The SSH name of a death by signal `number` (Linux numbering).
pub fn exit_signal_of(number: u8) -> Sig {
    match number {
        1 => Sig::HUP,
        2 => Sig::INT,
        3 => Sig::QUIT,
        4 => Sig::ILL,
        6 => Sig::ABRT,
        8 => Sig::FPE,
        9 => Sig::KILL,
        10 => Sig::USR1,
        11 => Sig::SEGV,
        13 => Sig::PIPE,
        14 => Sig::ALRM,
        15 => Sig::TERM,
        other => Sig::Custom(match other {
            5 => "TRAP".to_owned(),
            7 => "BUS".to_owned(),
            12 => "USR2".to_owned(),
            other => format!("SIG{other}"),
        }),
    }
}

/// How an ended channel is reported to the SSH client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    /// `exit-status`.
    Status(u32),
    /// `exit-signal` of this signal number ([`exit_signal_of`]).
    Signal(u8),
    /// One line on the channel's stderr and no status (the client exits 255).
    Message(String),
    /// No status (an unknown status, or a close this side asked for).
    Nothing,
}

/// The best-effort stderr line of a channel reset because its ssh client
/// sent past the channel's window (OpenSSH never does).
pub const OVERRUN_LINE: &str =
    "wssp: the channel was reset: the ssh client sent more than its window";

/// The report of an ended channel.
pub fn finish_of(outcome: &Outcome) -> Finish {
    match outcome {
        Outcome::Code(code) => Finish::Status(u32::try_from(*code).unwrap_or(255)),
        Outcome::Signal(number) => Finish::Signal(*number),
        Outcome::Unknown
        | Outcome::Closed {
            intent: Intent::Client,
            ..
        } => Finish::Nothing,
        Outcome::Closed { intent, error } => {
            let mut line = format!(
                "wssp: the channel was closed (`{}`): {}",
                intent.name(),
                intent.describe()
            );
            if let Some(error) = error {
                line.push_str(&format!(
                    " (`{}`: {})",
                    crate::output::remote_message(&error.code),
                    crate::output::remote_message(&error.message)
                ));
            }
            Finish::Message(line)
        }
        Outcome::Failed { error } => Finish::Message(format!(
            "wssp: the sandbox could not open the channel (`{}`: {})",
            crate::output::remote_message(&error.code),
            crate::output::remote_message(&error.message)
        )),
    }
}

/// The open-failure reason of a forward the sandbox refused.
pub fn open_failure_of(outcome: &Outcome) -> ChannelOpenFailure {
    match outcome {
        Outcome::Failed { error } => match error.code.as_str() {
            "connection_refused" | "guest_permission_denied" | "guest_operation_failed" => {
                ChannelOpenFailure::ConnectFailed
            }
            "rate_limited" | "host_capacity" => ChannelOpenFailure::ResourceShortage,
            _ => ChannelOpenFailure::AdministrativelyProhibited,
        },
        _ => ChannelOpenFailure::ConnectFailed,
    }
}

/// The sandbox of an SSH host name: `<name-or-id>.wssp` (any case of the
/// suffix) or a bare `<name-or-id>`.
pub fn sandbox_of(host: &str) -> &str {
    let split = host.len().checked_sub(HOST_SUFFIX.len());
    match split {
        Some(at)
            if at > 0
                && host.is_char_boundary(at)
                && host[at..].eq_ignore_ascii_case(HOST_SUFFIX) =>
        {
            &host[..at]
        }
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_client::wire::WireError;

    /// A small deterministic generator: the mapping is checked over many
    /// inputs without a property-test crate.
    struct Gen(u64);

    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let len = self.below(max as u64 + 1) as usize;
            (0..len)
                .map(|_| match self.below(4) {
                    0 => self.below(256) as u8,
                    1 => b"'\"$`\\;|&<>(){}*?! \t\n"[self.below(20) as usize],
                    _ => b'a' + self.below(26) as u8,
                })
                .collect()
        }

        fn text(&mut self, max: usize) -> String {
            String::from_utf8_lossy(&self.bytes(max)).into_owned()
        }
    }

    fn pty() -> PtyRequest {
        PtyRequest::new("xterm", 100, 30)
    }

    #[test]
    fn each_session_request_opens_its_documented_channel() {
        let shell = plan(Some(&pty()), &SessionRequest::Shell).unwrap();
        assert_eq!(shell.kind, Kind::Pty);
        assert_eq!(shell.argv, None);
        assert!(shell.login);
        assert_eq!(
            shell.pty,
            Some(PtyParams {
                rows: 30,
                cols: 100,
                term: "xterm".into()
            })
        );
        let piped_shell = plan(None, &SessionRequest::Shell).unwrap();
        assert_eq!(
            (piped_shell.kind, piped_shell.argv, piped_shell.login),
            (Kind::Exec, None, true)
        );
        let exec = plan(None, &SessionRequest::Exec(b"echo hi".to_vec())).unwrap();
        assert_eq!(exec.kind, Kind::Exec);
        assert!(!exec.login && exec.pty.is_none());
        assert_eq!(
            exec.argv.unwrap(),
            ["/bin/sh", "-c", SHELL_COMMAND, "wssp-ssh", "echo hi"]
        );
        let tty_exec = plan(Some(&pty()), &SessionRequest::Exec(b"top".to_vec())).unwrap();
        assert_eq!(tty_exec.kind, Kind::Pty);
        assert_eq!(tty_exec.argv.unwrap()[4], "top");
        let sftp = plan(Some(&pty()), &SessionRequest::Subsystem("sftp".into())).unwrap();
        assert_eq!((sftp.kind, sftp.pty), (Kind::Exec, None));
        assert!(sftp.argv.unwrap()[2].contains("/usr/lib/openssh/sftp-server"));
        assert!(plan(None, &SessionRequest::Subsystem("netconf".into())).is_err());
    }

    /// The command string reaches the guest shell as one argument, byte for
    /// byte: the real wrapper runs a stand-in "guest shell" that prints its
    /// argv, NUL-separated.
    #[test]
    fn the_command_reaches_the_guest_shell_as_one_untouched_argument() {
        let dir = tempfile::tempdir().unwrap();
        let shell = dir.path().join("shell");
        std::fs::write(&shell, "#!/bin/sh\nprintf '%s\\0' \"$@\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut generator = Gen(0x5eed_1234_abcd_0001);
        let mut checked = 0;
        for round in 0..96 {
            let raw = if round == 0 {
                br#"printf '%s|' "a b" '$HOME' "\"q\"" ; echo $(id) `x` * ~"#.to_vec()
            } else if round % 8 == 0 {
                generator.bytes(40)
            } else {
                generator.text(40).into_bytes()
            };
            let Ok(argv) = command_argv(&raw) else {
                assert!(std::str::from_utf8(&raw).is_err() || raw.contains(&0));
                continue;
            };
            let output = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .env("SHELL", &shell)
                .output()
                .unwrap();
            assert!(output.status.success(), "{argv:?}");
            let mut expected = b"-c\0".to_vec();
            expected.extend_from_slice(&raw);
            expected.push(0);
            assert_eq!(output.stdout, expected, "{raw:?}");
            checked += 1;
        }
        assert!(checked > 32);
    }

    #[test]
    fn commands_outside_the_wire_are_refused() {
        assert!(command_argv(&[0xff, 0xfe]).is_err());
        assert!(command_argv(b"echo \0 x").is_err());
        assert!(command_argv(&vec![b'a'; 70_000]).is_err());
        assert!(command_argv(b"").is_ok());
    }

    #[test]
    fn the_sftp_probe_runs_the_first_server_or_names_the_package() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("sftp-server");
        std::fs::write(&fake, "#!/bin/sh\necho fake-sftp\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let fake = fake.to_str().unwrap().to_owned();
        let run = |paths: &[&str]| {
            let argv = sftp_argv(paths);
            std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .unwrap()
        };
        let found = run(&["/nonexistent/sftp-server", &fake]);
        assert!(found.status.success());
        assert_eq!(String::from_utf8_lossy(&found.stdout), "fake-sftp\n");
        let missing = run(&["/nonexistent/a", "/nonexistent/b"]);
        assert_eq!(missing.status.code(), Some(127));
        assert!(missing.stdout.is_empty());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("openssh-sftp-server"));
    }

    #[test]
    fn terminal_names_and_sizes_are_kept_within_the_wire() {
        assert_eq!(term_of("screen-256color"), "screen-256color");
        assert_eq!(term_of(""), DEFAULT_TERM);
        assert_eq!(term_of("x\x1b]0;evil"), DEFAULT_TERM);
        assert_eq!(size_of(80, 24), (24, 80));
        assert_eq!(size_of(0, 0), (24, 80));
        assert_eq!(size_of(u32::MAX, u32::MAX), (512, 1024));
        let mut generator = Gen(7);
        for _ in 0..500 {
            let (cols, rows) = (generator.next() as u32, generator.next() as u32);
            let (r, c) = size_of(cols, rows);
            assert!(sandbox_protocol::valid_terminal_size(r, c), "{cols} {rows}");
            let term = generator.text(70);
            assert!(sandbox_protocol::valid_channel_term(&term_of(&term)));
        }
    }

    #[test]
    fn only_locale_and_colour_env_travels() {
        let mut env = BTreeMap::new();
        assert!(accept_env(&env, "LANG", "C.UTF-8"));
        assert!(accept_env(&env, "LC_ALL", "C"));
        assert!(accept_env(&env, "COLORTERM", "truecolor"));
        for name in ["TERM", "PATH", "LD_PRELOAD", "HOME", "LC_", "lang", "FOO"] {
            assert!(!accept_env(&env, name, "x"), "{name}");
        }
        assert!(!accept_env(&env, "LANG", "a\0b"));
        assert!(!accept_env(&env, "LANG", &"x".repeat(5000)));
        for n in 0..32 {
            env.insert(format!("LC_X{n}"), "v".into());
        }
        assert!(!accept_env(&env, "LANG", "C"));
        assert!(accept_env(&env, "LC_X3", "replaced"));
        // Whatever is accepted, the open stays valid.
        let mut generator = Gen(99);
        let mut env = BTreeMap::new();
        for _ in 0..400 {
            let name = match generator.below(3) {
                0 => format!("LC_{}", generator.text(6).to_uppercase()),
                1 => "LANG".to_owned(),
                _ => generator.text(8),
            };
            let value = generator.text(10);
            if accept_env(&env, &name, &value) {
                env.insert(name, value);
            }
            assert!(sandbox_protocol::valid_channel_env(&env));
        }
    }

    #[test]
    fn forwards_reach_only_the_guest_loopback() {
        assert_eq!(forward_target("localhost", 8080), Some(8080));
        assert_eq!(forward_target("LocalHost", 22), Some(22));
        assert_eq!(forward_target("127.0.0.1", 5432), Some(5432));
        assert_eq!(forward_target("::1", 1), Some(1));
        assert_eq!(forward_target("[::1]", 65535), Some(65535));
        for host in [
            "10.0.0.1",
            "127.0.0.2",
            "example.com",
            "localhost.",
            "0.0.0.0",
            "",
            "::ffff:127.0.0.1",
            "169.254.169.254",
        ] {
            assert_eq!(forward_target(host, 80), None, "{host}");
        }
        assert_eq!(forward_target("localhost", 0), None);
        assert_eq!(forward_target("localhost", 65536), None);
        let mut generator = Gen(3);
        for _ in 0..1000 {
            let host = generator.text(12);
            let port = generator.next() as u32;
            if let Some(port) = forward_target(&host, port) {
                assert!(port > 0);
                assert!(
                    ["localhost", "127.0.0.1", "::1", "[::1]"]
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(&host))
                );
            }
        }
        assert_eq!(
            streamlocal_target("/run/user/1000/app.sock").as_deref(),
            Some("/run/user/1000/app.sock")
        );
        assert_eq!(streamlocal_target("relative.sock"), None);
        assert_eq!(streamlocal_target(&format!("/{}", "a".repeat(200))), None);
    }

    #[test]
    fn signals_and_statuses_map_both_ways() {
        assert_eq!(signal_of(&Sig::INT), Some(Signal::Int));
        assert_eq!(signal_of(&Sig::TERM), Some(Signal::Term));
        assert_eq!(signal_of(&Sig::HUP), Some(Signal::Hup));
        assert_eq!(signal_of(&Sig::KILL), Some(Signal::Kill));
        assert_eq!(signal_of(&Sig::USR1), None);
        assert_eq!(signal_of(&Sig::Custom("WINCH".into())), None);
        assert_eq!(finish_of(&Outcome::Code(7)), Finish::Status(7));
        assert_eq!(finish_of(&Outcome::Code(-1)), Finish::Status(255));
        assert_eq!(finish_of(&Outcome::Signal(15)), Finish::Signal(15));
        assert!(matches!(exit_signal_of(15), Sig::TERM));
        assert!(matches!(exit_signal_of(9), Sig::KILL));
        assert!(matches!(exit_signal_of(2), Sig::INT));
        assert!(matches!(exit_signal_of(12), Sig::Custom(name) if name == "USR2"));
        assert!(matches!(exit_signal_of(40), Sig::Custom(name) if name == "SIG40"));
        assert_eq!(finish_of(&Outcome::Unknown), Finish::Nothing);
        assert_eq!(
            finish_of(&Outcome::Closed {
                intent: Intent::Client,
                error: None
            }),
            Finish::Nothing
        );
        let Finish::Message(line) = finish_of(&Outcome::Closed {
            intent: Intent::Revoked,
            error: None,
        }) else {
            panic!("a wssp close is a message");
        };
        assert!(line.contains("`revoked`"));
        let Finish::Message(line) = finish_of(&Outcome::Failed {
            error: WireError {
                code: "rate_limited".into(),
                message: "slow\x1b[2Jdown".into(),
            },
        }) else {
            panic!("a refusal is a message");
        };
        assert!(line.contains("rate_limited") && !line.contains('\x1b'));
        for number in 1..=64 {
            let _ = exit_signal_of(number);
        }
    }

    #[test]
    fn refused_forwards_carry_their_reason() {
        let failed = |code: &str| Outcome::Failed {
            error: WireError {
                code: code.into(),
                message: "m".into(),
            },
        };
        assert!(matches!(
            open_failure_of(&failed("connection_refused")),
            ChannelOpenFailure::ConnectFailed
        ));
        assert!(matches!(
            open_failure_of(&failed("host_capacity")),
            ChannelOpenFailure::ResourceShortage
        ));
        assert!(matches!(
            open_failure_of(&failed("unsupported_capability")),
            ChannelOpenFailure::AdministrativelyProhibited
        ));
    }

    #[test]
    fn host_names_lose_only_the_wssp_suffix() {
        assert_eq!(sandbox_of("dev-box.wssp"), "dev-box");
        assert_eq!(sandbox_of("SBX_1.WSSP"), "SBX_1");
        assert_eq!(sandbox_of("dev-box"), "dev-box");
        assert_eq!(sandbox_of(".wssp"), ".wssp");
        assert_eq!(sandbox_of("a.wssp.wssp"), "a.wssp");
        assert_eq!(sandbox_of("ü.wssp"), "ü");
        let mut generator = Gen(11);
        for _ in 0..500 {
            let host = generator.text(12);
            let name = sandbox_of(&host);
            assert!(host.starts_with(name));
        }
    }
}
