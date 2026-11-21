# Shells and port forwards from the CLI

`wssp sandbox shell` opens a shell, or runs a command, inside a sandbox from
your own terminal, as the template's guest user. `wssp sandbox forward`
forwards local ports to ports on the sandbox's own loopback
([Port forwards](#port-forwards)). Like the
[browser terminal](./terminal.md) it is never a shell on the Incus host. It
talks to the server over one WebSocket (`GET /v1/sandboxes/{id}/connect`,
subprotocol `wssp.connect.v1`) with your [CLI login](./cli.md) or SDK key; the
wire is specified in the
[channel contract](../design/connect-channel-contract.md#client-wire-wsspconnectv1).
SSH comes later and gets its own section here.

## Access

The key needs the scope `sandboxes:connect`. A `wssp login` with **write**
access holds it; a read-only login does not. A dashboard SDK key holds it only
when it was explicitly given the scope. Agent tokens, OAuth grants and MCP
never hold it (see [authentication planes](./auth-planes.md)). A login saved
before the scope existed is refused (exit 8): log in again (`wssp login`) to
get shell access (or port forwarding).

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

## Port forwards

```sh
wssp sandbox forward <sandbox> 5432                 # local 127.0.0.1:5432 → the sandbox's port 5432
wssp sandbox forward <sandbox> 5432:15432 8080:0    # local 15432 → 5432; a free local port → 8080
wssp sandbox forward <sandbox> 5432 --unix ./pg.sock
psql -h 127.0.0.1 -p 15432 app
```

Each `<guestPort>[:<localPort>]` makes the CLI listen locally (on `127.0.0.1`
unless `--address` says otherwise; the local port defaults to the guest port,
and `0` picks a free one) and print `Forwarding <local> -> sandbox port
<guest>` (one JSON line `{"local", "guestPort"}` each with `--json`). Every
connection you make to it becomes one connection to `127.0.0.1:<guestPort>`
**inside the sandbox**, made as the guest user (if nothing answers on IPv4
loopback, `[::1]` is tried, so a service bound to `localhost` works either
way). There is no host in the request: a forward reaches only the sandbox's
own loopback, never another machine. It opens no network path to the sandbox
either (no firewall rule, no listener on the node): the bytes travel over the
same WebSocket as shells, so a service that listens only on the sandbox's
loopback is reachable this way and nowhere else. Many connections at once
share that one WebSocket, up to 32 at a time; more wait in a queue of 32, and
beyond that a connection is refused (reset).

- **Who can connect.** A loopback TCP port is reachable by every user of your
  machine, as with `kubectl port-forward` or `ssh -L`: anyone else logged in
  can use the forward while it runs. `--unix PATH` listens on a Unix socket
  instead, created with mode 0600 so only you can connect (one guest port; the
  path must not exist yet, and the socket is removed when the forward ends).
  `--address` with anything but a loopback address prints a warning: then
  anyone who can reach that address can use the sandbox's port.
- **Both directions close separately.** When your client closes its sending
  side, the guest service sees the end of its input while its replies keep
  coming; when the guest service closes its sending side, your client sees the
  end while it can still send. A connection the guest side resets is reset
  locally too, also after the guest service already closed its sending side;
  only a connection both sides ended cleanly closes normally. When your client
  resets its connection the CLI closes the channel at once, even while it is
  waiting for the guest service to read earlier input. The same holds towards
  the guest: a connection that ends any other way than cleanly (your client
  resets it, Ctrl-C, a revoked login, a stopped sandbox, a lost connection,
  the node daemon dying) reaches a guest TCP service as a reset, never as the
  end of its input, so it never takes a cut request for a whole one. A
  `--unix` socket has no reset: a connection the guest side reset just
  closes, so a client of a protocol that ends at the close cannot tell a cut
  reply from a whole one there (a TCP listener resets it). Towards a guest
  Unix socket an aborted connection is a full close: the service reads the
  end of its input and its next write fails (a broken pipe), while your client
  closing only its sending side lets the reply through.
- **Refusals.** When nothing listens on the guest port the local connection is
  reset and the CLI logs one line (`sandbox port 5432 refused a connection`,
  `connection_refused`), at most one per second; a connection that fails later
  logs `a connection to sandbox port 5432 failed`. An open refused only for
  the open rate waits in the queue and is tried once more. A sandbox whose
  node daemon cannot forward ports yet ends the forward (exit 125); update
  the node.
- **Flow control.** The sandbox reads from the guest service only as fast as
  your local client reads, and the CLI reads your client only as fast as the
  guest service reads: nothing is buffered without bound. A local client that
  stops reading for 60 seconds gets its connection closed (`backpressure`). A
  connection whose guest service stops reading stays open (as any idle
  connection would). Connections that stall either way slow the others but
  never stop them: every connection keeps a share of each buffer it passes
  through, at least one 32 KiB piece in flight each way. A reply the guest
  service already finished is never cut while your client is still reading
  it.
- **Ending.** Ctrl-C (or SIGTERM, SIGHUP) stops listening, closes every
  connection and exits 130 (143, 129); a second one exits at once. When wssp
  ends the session (a revoked login, a stopped or destroyed sandbox, a lost
  connection) every local connection is reset, one line names why, and the
  CLI exits 125, exactly as for a shell. There is no reconnect: start the
  forward again.

The forwarded bytes are not journaled; as for shells, a shared node's owner
can see them. Only TCP is forwarded (no UDP).
