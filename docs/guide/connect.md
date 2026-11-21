# Shells from the CLI

`wssp sandbox shell` opens a shell, or runs a command, inside a sandbox from
your own terminal, as the template's guest user. Like the
[browser terminal](./terminal.md) it is never a shell on the Incus host. It
talks to the server over one WebSocket (`GET /v1/sandboxes/{id}/connect`,
subprotocol `wssp.connect.v1`) with your [CLI login](./cli.md) or SDK key; the
wire is specified in the
[channel contract](../design/connect-channel-contract.md#client-wire-wsspconnectv1).
Port forwarding and SSH come later and get their own sections here.

## Access

The key needs the scope `sandboxes:connect`. A `wssp login` with **write**
access holds it; a read-only login does not. A dashboard SDK key holds it only
when it was explicitly given the scope. Agent tokens, OAuth grants and MCP
never hold it (see [authentication planes](./auth-planes.md)). A login saved
before the scope existed is refused (exit 8): log in again (`wssp login`) to
get shell access.

The sandbox must be `READY` on a connected host whose node daemon supports
channels. Build, verify and CLI-login sandboxes never get a shell.

## Shell

```sh
wssp sandbox shell <sandbox>                          # a login shell
wssp sandbox shell <sandbox> -- vim "notes with space.txt"
wssp sandbox shell <sandbox> --cwd /home/user/app --env LANG=C.UTF-8 -- npm test
wssp sandbox shell <sandbox> --no-tty -- tar -C /srv -cf - data > data.tar
echo 'uname -a' | wssp sandbox shell <sandbox>        # stdin is not a terminal: no tty
```

`<sandbox>` is a sandbox id or name (a name is looked up among your live
sandboxes, at most 2000).

- **With a terminal** on stdin and stdout (and no `--no-tty`/`-T`) the guest
  side gets a tty: a login shell, or the command after `--`. Your terminal is in
  raw mode from the moment the guest side is ready to the end of the session,
  so Ctrl-C, Ctrl-Z, Ctrl-D and every other key go to the guest, never to the
  CLI (while the shell is still starting, Ctrl-C cancels it and exits 130). Resizing your window resizes the guest's
  (sizes are clamped to 512 rows and 1024 columns). The terminal settings are
  restored on every exit, including a crash or a signal to the CLI; only
  `kill -9` can leave the terminal raw (`reset` repairs it). SIGINT, SIGTERM,
  SIGHUP or SIGQUIT sent to the CLI itself closes the channel and exits
  128 + N.
- **Without a terminal** (`--no-tty`, or stdin or stdout redirected) the command
  runs with piped stdin, and its stdout and stderr stay separate. The end of
  your stdin closes the command's stdin. Ctrl-C, SIGTERM and SIGHUP are sent
  to the command as INT, TERM and HUP; a second Ctrl-C within 2 seconds closes
  the channel and exits 130, and a second SIGTERM or SIGHUP (at any time after
  the first) closes it and exits 143 or 129, so a supervisor's repeated TERM
  always ends the CLI. SIGQUIT has no remote equivalent: it closes the
  channel and exits 131. Before the command has started, any of them closes
  the channel instead (the node stops what it was starting) and the CLI exits
  128 + N (130, 143, 129, 131). A close waits at most 2 seconds for the
  sandbox to confirm it; then the CLI exits with that status anyway.
- The command after `--` runs **structurally**: each word is one argument,
  never joined into a shell string, so spaces, quotes, empty arguments and
  metacharacters arrive unchanged. Use `-- sh -c '…'` for shell syntax.
- `--env` takes only `TERM`, `COLORTERM`, `LANG` and `LC_*`; any other name is
  a usage error (exit 2). `TERM` (default: yours, else `xterm-256color`)
  applies only with a tty. The sandbox's private defaults and create `envs`
  apply as they do for browser terminals.

Closing a shell hangs up its session, as `ssh` does: processes that detached
themselves (`tmux`, `nohup`, `setsid`) survive. There is **no detach and no
resume** in this release: losing the connection, a relay drop, a server or
daemon restart ends the shell and the next `wssp sandbox shell` starts a new
one. Keep durable work in `tmux` or `screen` inside the guest. A connection
that goes silent without closing (a dropped NAT mapping, a host that lost
power, a laptop resumed from sleep) counts as lost too: the server pings every
20 seconds, and when nothing at all, not even a ping, arrives for 60 seconds
(three pings, never less than the server's idle timeout) the CLI ends the
session and exits 125 (`connect.lost`).

The bytes are not journaled (no command operation, no retained output). A
shared node's owner can see them, as for browser terminals.

## Exit status

| Exit           | When                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------ |
| the remote one | the guest command or shell exited; a death by signal N exits 128 + N                                         |
| 2              | a usage error, or the server refused the request as invalid (for example a node that must update its daemon) |
| 3              | no such sandbox, or not yours                                                                                |
| 7              | not logged in, or the key was refused (401)                                                                  |
| 8              | the key lacks `sandboxes:connect` or access to the sandbox (403)                                             |
| 10             | the sandbox is not `READY` (409)                                                                             |
| 11             | rate-limited, the host is not connected or full, or the server is busy (429, 503); retry later               |
| 125            | wssp ended the session, wssp itself failed, or the remote status is unknown                                  |
| 130            | without a tty: a second Ctrl-C closed the channel (a second SIGTERM or SIGHUP: 143, 129)                     |
| 141            | stdout closed early                                                                                          |

When wssp ends the session it prints one line naming why: `revoked` (the key
was revoked or expired, or access was withdrawn), `sandbox_stopped`,
`sandbox_destroyed`, `expired` (the sandbox's lease or the 12-hour session
limit), `superseded`, `host_disconnected`, `detached` (the server stopped
hearing from this client), `backpressure`, `protocol_violation`,
`lifecycle_unconfirmed` or `shutdown`. With `--json` that line is the usual
JSON error, with the code `connect.<intent>` (`connect.lost` when the
connection dropped without one). A remote command can exit 125 itself; a
wssp-side 125 ends with wssp's error line, with one exception: when the
session ends while the CLI's own stdout or stderr has stopped draining (a
pipe or terminal nobody reads), the CLI waits 2 seconds for its pending
output and 2 more for the error line, then exits with the session's status
without that line, since it could never be written. The same 2 seconds bound
the error line after a failed write (a closed stdout exits 141).

During a session the CLI's own lines (a notice that the sandbox could not
deliver a signal, a failed read of your stdin) are written to stderr in order
with the command's output, and log output (`-v`, `WSSP_LOG`) is suppressed
until the CLI exits, so a stderr nobody reads cannot stall the session.

Output is acknowledged only once it is written, so a consumer that stops
reading (a pager such as `| less` left paused, a suspended terminal) stops the
acknowledgements: after 60 seconds without one the sandbox closes the channel
with `backpressure` and the CLI exits 125.
