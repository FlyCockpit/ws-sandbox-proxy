//! Bounded host tool children for the guard (`nft`, `ip`, `tc`, `conntrack`,
//! `systemctl`). Scrubbed environment (fixed system PATH, `LC_ALL=C`), own
//! process group, stdin body never on argv, hard timeout with kill and
//! reap, bounded output.

use std::io::{Read, Write};
use std::process::{Child, ChildStdout, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;
use sandbox_runtime::{HostChildEnvironment, host_child_command};

/// Children never inherit the caller's PATH: the guard runs as root.
pub const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Upper bound for one captured stream (`nft -j list ruleset` on busy hosts).
const MAX_OUTPUT: u64 = 32 * 1024 * 1024;

pub struct ToolOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ToolOutput {
    pub fn stderr_line(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        line.chars().take(200).collect()
    }
}

fn command(program: &str) -> std::process::Command {
    command_on(program, SYSTEM_PATH)
}

fn command_on(program: &str, path: &str) -> std::process::Command {
    let mut command = host_child_command(program, HostChildEnvironment::PathOnly);
    command.env("PATH", path).env("LC_ALL", "C");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command
}

fn reader(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(pipe) = pipe {
            let _ = pipe.take(MAX_OUTPUT).read_to_end(&mut bytes);
        }
        bytes
    })
}

fn kill_group(child: &Child) {
    // Every tool starts in its own process group. Descendants can retain
    // stdin/stdout/stderr after the leader exits, so kill the whole group
    // before joining any pipe workers, on success as well as timeout.
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

fn kill_and_reap(child: &mut Child) -> std::io::Result<ExitStatus> {
    kill_and_reap_with(child, kill_group)
}

fn kill_and_reap_with(
    child: &mut Child,
    signal_group: impl FnOnce(&Child),
) -> std::io::Result<ExitStatus> {
    // No caller may reap first: the unreaped leader reserves its PID/PGID
    // until its descendants have been signalled.
    signal_group(child);
    let _ = child.kill();
    child.wait()
}

fn exited_without_reaping(child: &Child) -> nix::Result<bool> {
    let pid = i32::try_from(child.id()).map_err(|_| Errno::EINVAL)?;
    waitid(
        Id::Pid(Pid::from_raw(pid)),
        WaitPidFlag::WNOWAIT | WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG,
    )
    .map(|status| !matches!(status, WaitStatus::StillAlive))
}

/// Run `program args…` to completion within `timeout`.
pub fn run(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<ToolOutput> {
    run_on(SYSTEM_PATH, program, args, stdin, timeout)
}

/// [`run`] with an explicit child PATH (tests put a fake tool first).
pub fn run_on(
    path: &str,
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<ToolOutput> {
    let mut command = command_on(program, path);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot run `{program}`"))?;
    let writer = stdin.map(|body| {
        let mut pipe = child.stdin.take();
        let body = body.to_vec();
        thread::spawn(move || {
            if let Some(pipe) = pipe.as_mut() {
                let _ = pipe.write_all(&body);
            }
            drop(pipe);
        })
    });
    let out = reader(child.stdout.take());
    let err = reader(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match exited_without_reaping(&child) {
            Ok(true) => {
                break kill_and_reap(&mut child).with_context(|| format!("reaping `{program}`"))?;
            }
            Ok(false) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(false) => {
                let _ = kill_and_reap(&mut child);
                let _ = (out.join(), err.join());
                if let Some(writer) = writer {
                    let _ = writer.join();
                }
                bail!("`{program}` timed out after {}s", timeout.as_secs());
            }
            Err(Errno::EINTR) => continue,
            Err(error) => {
                // ECHILD means ownership is lost (e.g. an external reaper).
                // Never signal a numeric PID/PGID that may now be recycled.
                if error != Errno::ECHILD {
                    let _ = kill_and_reap(&mut child);
                }
                return Err(error).with_context(|| format!("waiting for `{program}`"));
            }
        }
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ok(ToolOutput {
        success: status.success(),
        code: status.code(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Run and parse stdout as JSON; a non-zero exit is an error.
pub fn json(program: &str, args: &[&str], timeout: Duration) -> Result<serde_json::Value> {
    let output = run(program, args, None, timeout)?;
    if !output.success {
        bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            output.stderr_line()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("`{program} {}` printed malformed JSON", args.join(" ")))
}

/// A long-running monitor (`ip monitor …`, `nft monitor`): every output
/// line sends `on_line`; EOF or a read error sends `on_exit` once. The
/// child is returned so the caller can kill it.
pub fn monitor(
    program: &str,
    args: &[&str],
    on_line: impl Fn() + Send + 'static,
    on_exit: impl FnOnce() + Send + 'static,
) -> Result<Child> {
    let mut child = command(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot run `{program}`"))?;
    let stdout: Option<ChildStdout> = child.stdout.take();
    thread::spawn(move || {
        if let Some(stdout) = stdout {
            let mut lines = std::io::BufReader::new(stdout);
            let mut line = Vec::new();
            loop {
                line.clear();
                match std::io::BufRead::read_until(&mut lines, b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => on_line(),
                }
            }
        }
        on_exit();
    });
    Ok(child)
}

/// Is `program` present on the fixed system PATH?
pub fn available(program: &str) -> bool {
    SYSTEM_PATH
        .split(':')
        .any(|dir| std::path::Path::new(dir).join(program).is_file())
}

/// Bounded summary of triggers; repeated monitor notices occupy one slot.
#[derive(Debug, Default)]
pub struct Triggers {
    pub changed: bool,
    pub died: Vec<&'static str>,
}

/// Wait at most `timeout` for the first trigger, then fold arrivals for at
/// most `settle`, even when the channel remains continuously readable.
pub fn coalesce<T>(
    rx: &mpsc::Receiver<T>,
    timeout: Duration,
    settle: Duration,
    monitor_died: impl Fn(T) -> Option<&'static str>,
) -> Triggers {
    let mut summary = Triggers::default();
    let Ok(first) = rx.recv_timeout(timeout) else {
        return summary;
    };
    let mut record = |event| {
        summary.changed = true;
        if let Some(name) = monitor_died(event)
            && !summary.died.contains(&name)
        {
            summary.died.push(name);
        }
    };
    record(first);
    let until = Instant::now() + settle;
    loop {
        let now = Instant::now();
        if now >= until {
            break;
        }
        let Ok(event) = rx.recv_timeout(until - now) else {
            break;
        };
        record(event);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_leader_remains_unreaped_until_its_process_group_is_killed() {
        let mut child = command("/bin/sh").args(["-c", "exit 7"]).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !exited_without_reaping(&child).unwrap() {
            assert!(Instant::now() < deadline, "tool leader did not exit");
            thread::sleep(Duration::from_millis(5));
        }
        let status = kill_and_reap_with(&mut child, |child| {
            assert!(
                exited_without_reaping(child).unwrap(),
                "leader was reaped before group kill"
            );
            kill_group(child);
        })
        .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(exited_without_reaping(&child), Err(Errno::ECHILD));
    }

    #[test]
    fn tool_descendants_cannot_hold_pipes_after_timeout_or_leader_exit() {
        for exit in [false, true] {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let script = if exit {
                    "sleep 30 & exit 0"
                } else {
                    "sleep 30 & wait"
                };
                let result = run("/bin/sh", &["-c", script], None, Duration::from_millis(50));
                tx.send(result).unwrap();
            });
            let result = rx
                .recv_timeout(Duration::from_secs(3))
                .expect("descendants retained tool pipes");
            if exit {
                assert!(result.unwrap().success);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn coalescing_continuous_triggers_is_bounded_and_preserves_monitor_deaths() {
        let (tx, rx) = mpsc::sync_channel(4);
        let producer = thread::spawn(move || while tx.send(Some("ip")).is_ok() {});
        let (done_tx, done_rx) = mpsc::channel();
        let consumer = thread::spawn(move || {
            let summary = coalesce(
                &rx,
                Duration::from_secs(1),
                Duration::from_millis(20),
                |event| event,
            );
            done_tx.send(summary).unwrap();
        });
        let summary = done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("coalescing starved resync");
        assert!(summary.changed);
        assert_eq!(summary.died, vec!["ip"]);
        consumer.join().unwrap();
        producer.join().unwrap();
    }
}
