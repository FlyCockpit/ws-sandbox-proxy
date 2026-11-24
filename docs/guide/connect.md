# Shells, port forwards and ssh from the CLI

`wssp sandbox shell` opens a shell, or runs a command, inside a sandbox from
your own terminal, as the template's guest user. `wssp sandbox forward`
forwards local ports to ports on the sandbox's own loopback
([Port forwards](#port-forwards)). `ssh <name>.wssp` (and `scp`, `sftp`,
`rsync`, VS Code Remote-SSH and, expected but not yet verified, JetBrains
Gateway) works too, without SSH keys
([ssh](#ssh)). Like the
[browser terminal](./terminal.md) it is never a shell on the Incus host. It
talks to the server over one WebSocket (`GET /v1/sandboxes/{id}/connect`,
subprotocol `wssp.connect.v1`) with your [CLI login](./cli.md) or SDK key; the
wire is specified in the
[channel contract](../design/connect-channel-contract.md#client-wire-wsspconnectv1).

This page is the reference. For step-by-step guides see
[ssh, VS Code, rsync and sftp](./ssh/README.md): [plain ssh](./ssh/ssh.md),
[copying files](./ssh/files.md) with rsync, scp and sftp,
[VS Code Remote-SSH](./ssh/vscode.md) and [JetBrains Gateway](./ssh/jetbrains.md).

## Access

The key needs the scope `sandboxes:connect`. A `wssp login` with **write**
access holds it; a read-only login does not. A dashboard SDK key holds it only
when it was explicitly given the scope. Agent tokens, OAuth grants and MCP
never hold it (see [authentication planes](./auth-planes.md)). A login saved
before the scope existed is refused (exit 8): log in again (`wssp login`) to
get shell access (or port forwarding, or ssh).

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
session and exits 125 (`connect.lost`). Its line then says that the session
cannot be resumed and to run the command again for a new one; that is also
what a proxy or Cloudflare edge restart looks like
([Cloudflare Tunnel](../operations/deployment.md#when-cloudflare-drops-a-connection)).

The bytes are not journaled (no command operation, no retained output). A
shared node's owner can see them, as for browser terminals.

## Exit status

| Exit           | When                                                                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| the remote one | the guest command or shell exited; a death by signal N exits 128 + N                                                                                |
| 2              | a usage error, or the server refused the request as invalid (for example a node that must update its daemon)                                        |
| 3              | no such sandbox, or not yours                                                                                                                       |
| 7              | not logged in, or the key was refused (401)                                                                                                         |
| 8              | the key lacks `sandboxes:connect` or access to the sandbox (403)                                                                                    |
| 10             | the sandbox is not `READY` (409; also a 403 for a sandbox without a host, such as an offloaded one, when the saved login holds `sandboxes:connect`) |
| 11             | rate-limited, the host is not connected or full, or the server is busy (429, 503); retry later                                                      |
| 125            | wssp ended the session, wssp itself failed, or the remote status is unknown                                                                         |
| 130            | without a tty: a second Ctrl-C closed the channel (a second SIGTERM or SIGHUP: 143, 129)                                                            |
| 141            | stdout closed early                                                                                                                                 |

A refusal before the session starts prints one line naming the cause and what
to do, built from the server's error code (and, for a sandbox that is not
running, its state), for example
``error: sandbox `web` is stopped; start it with `wssp sandbox start <id> --wait`: `sandbox.state_conflict`: the server answered HTTP 409``
(the explanation, then the server's code). An offloaded sandbox, or one still
waiting for a host, is refused by authorization (403); when the saved login
holds `sandboxes:connect`, the CLI reads the sandbox's state and exits 10 with
the same kind of line. With `WSSP_API_KEY`, whose scopes the CLI cannot see,
it keeps exit 8 and the scope hint and adds the state it read.

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

## ssh

```sh
wssp ssh-config --install            # once: writes ~/.ssh/config.d/wssp, asks to include it
ssh <sandbox>.wssp                   # a login shell
ssh <sandbox>.wssp 'uname -a'        # a command, through the guest user's shell
scp ./data.tar <sandbox>.wssp:/home/user/
rsync -a ./src/ <sandbox>.wssp:src/
ssh -L 8080:localhost:8080 <sandbox>.wssp
wssp ssh <sandbox> -- -t htop        # the same without any ssh config
```

`<sandbox>` is a sandbox id or name, as for `wssp sandbox shell`. There are no
SSH keys or passwords to manage: your [CLI login](./cli.md) (or `WSSP_API_KEY`
with `WSSP_SERVER`) is the only credential, with the same
[access](#access) rules as a shell.

**How it works.** `wssp ssh-config` generates this block (`--install` writes
it to `~/.ssh/config.d/wssp` and, after asking, adds one `Include
config.d/wssp` line at the top of `~/.ssh/config`; `--yes` skips the question,
and nothing else in your ssh config is touched):

```
# Managed by wssp. Regenerate with `wssp ssh-config --install`.
Host *.wssp "!*'*" "!*\*"
  ProxyCommand "/abs/path/to/wssp" ssh --stdio '%n'
  User wssp
  HostKeyAlias wssp
  UserKnownHostsFile "/home/u/.local/share/wssp/user/ssh/known_hosts"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  HostKeyAlgorithms ssh-ed25519
  CanonicalizeHostname no
  IdentitiesOnly yes
  IdentityFile none
  ForwardAgent no
  ForwardX11 no
  ServerAliveInterval 30
```

`~` here is your account's home directory, the one OpenSSH reads (not
`$HOME`): with a different `$HOME` (`sudo -E`, some containers) `--install`
refuses and names both. It also refuses a symlinked `~/.ssh` or
`~/.ssh/config.d`, a symlinked or hard-linked `~/.ssh/config` that does not
already include the block, and a `config.d/wssp` that wssp did not write; in
those cases save the output of `wssp ssh-config` and add the line yourself.
An existing `Include` of `config.d/wssp` (also spelled `~/.ssh/config.d/wssp`
or with the absolute path) counts only when it is the first line of
`~/.ssh/config` that is not a comment or blank, with `config.d/wssp` as its
first file. Because ssh keeps the first value it reads for each setting,
anything earlier could win over the block: an option, any `Host` or `Match`
section (even `Host *`), or another `Include`, whose file may set options. In
every such case wssp adds its line at the very top (a glob such as
`config.d/*` is not recognized either; the extra explicit line is harmless),
and the block at the top then wins over everything further down. `--install`
holds a lock in the wssp user directory, so two runs never interleave. After
you answer, it checks that `~/.ssh/config` and `config.d/wssp` are still the
files it asked about (same file, owner, mode and content), writes the new
version next to each (flushed, with the old file's mode and owner), checks
again, and swaps the two atomically (`RENAME_EXCHANGE`). wssp never deletes
the file it replaced: when it is still exactly the one it planned against,
wssp keeps the previous file as `~/.ssh/config.wssp-backup-<time>` (or
`config.d-wssp.wssp-backup-<time>`, 0600, outside `config.d/`) and names it;
delete it when you no longer need it. An editor that had the file open and
saves afterwards writes into that backup, so the save is not lost. If an
editor or another program changed either file meanwhile, wssp leaves it as
it is (an edit that landed in the last moment is swapped back into place)
and asks you to run the command again; in the rare case that a second edit arrives during
that swap back, the first stays in place and the second is kept as
`~/.ssh/config.wssp-conflict-<time>` (or `config.d-wssp.wssp-conflict-<time>`,
0600), which the error names, so you can merge it. Nothing you wrote is ever
discarded. On a filesystem without `RENAME_EXCHANGE`, `--install` replaces no
existing file and tells you to add the line (or save the block) yourself.

The ProxyCommand names the `wssp` you ran, as you ran it: the absolute path
you typed, or the `wssp` that `PATH` found, as long as it is still this
binary (a symlink from a version manager therefore keeps working after an
upgrade); otherwise the binary's resolved path. After moving or reinstalling
`wssp` to another place, run `wssp ssh-config --install` again.

ssh pastes the host name into the ProxyCommand and runs it with your shell,
so the block passes it as `'%n'`, in single quotes, and `wssp ssh --stdio`
accepts only `<name-or-id>.wssp` (or the bare id) with the characters of a
sandbox id before it does anything. A name holding `'` or `\`, the only
characters single quotes do not neutralize in every shell, never matches the
`Host` line. So a hostile `ssh://` URL (for example in a Git submodule) cannot
run a command through the block, whatever your OpenSSH version (OpenSSH 9.6
and later refuse such names on their own).

The block is meant to hold whatever else your ssh config says:
`GlobalKnownHostsFile /dev/null` and `HostKeyAlgorithms ssh-ed25519` keep the
check to wssp's own key, and `CanonicalizeHostname no` keeps a
`CanonicalizeHostname always` elsewhere from sending sandbox names to DNS.
Settings the block does not name (`Ciphers`, `KexAlgorithms`, a system crypto
policy or FIPS mode) still apply; one that leaves no algorithm in common with
the endpoint makes the connection fail, it never weakens it.

Your ssh runs `wssp ssh --stdio <sandbox>.wssp` as its ProxyCommand. That
process opens one connection to the server with your login and speaks SSH on
its own stdin and stdout: the SSH server is your own local `wssp` process, and
nothing listens anywhere (not on your machine, not on the server, the node or
in the guest). It accepts any SSH authentication (`none` first, so there is no
prompt; the user name is ignored), because only your own ssh can reach it;
every session runs as the sandbox's guest user. `IdentitiesOnly yes` with
`IdentityFile none` keeps your own keys from being offered. `wssp ssh <sandbox>
[-- SSH-ARGS…]` runs the system `ssh` with the same options on its command
line, so it needs no config (it fails clearly when no `ssh` is installed).

**Host key.** OpenSSH checks a host key even over a pipe, so this install keeps
one ed25519 key at `<user dir>/ssh/host_key` (0600, made on first use) and a
wssp-managed `known_hosts` next to it that holds only that key, under the alias
`wssp`. The key opens nothing and grants nothing; the server is authenticated
by TLS and every channel by your login. `wssp logout` keeps both files;
`wssp ssh-config --rotate-host-key` replaces them (sessions already running
keep the old key until they end). The block names the `known_hosts` of the
wssp user directory it was generated in. A ProxyCommand that runs with
another one (a different `WSSP_USER_DIR` or XDG data directory in ssh's
environment) has to make a new key there, says so on stderr, and ssh then
fails with "Host key verification failed": run `wssp ssh-config --install`
again in the environment ssh runs in. In the same way, `WSSP_API_KEY` and
`WSSP_SERVER` in ssh's environment take the place of your saved login for
`ssh <sandbox>.wssp`.

**Not end-to-end.** This is not SSH to the guest: the SSH session ends in your
local `wssp` process, and from there the bytes travel over TLS to the server
and on to the node and the guest, exactly like the browser terminal and
`wssp sandbox shell`. The wssp server and the node (and so a shared node's
owner) can see them in plaintext. If you need end-to-end OpenSSH (your own
keys, agent forwarding, `-R`), run `sshd` inside the sandbox and reach it with
`wssp sandbox forward <sandbox> 22`; you then manage its keys yourself.

**What maps to what.**

| ssh                                                | in the sandbox                                                                                        |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `ssh host` (a terminal)                            | the guest user's login shell on a tty; TERM from your ssh                                             |
| `ssh host 'cmd'`, `ssh -t host 'cmd'`              | the guest user's shell runs `cmd` (`$SHELL -c 'cmd'`, as sshd does), on a tty with `-t`               |
| `ssh -T host` (no command)                         | the login shell reading your stdin                                                                    |
| exit status, death by signal                       | `exit-status`, `exit-signal` (ssh exits 255 for a signal, as with sshd)                               |
| SendEnv / SetEnv                                   | only `COLORTERM`, `LANG` and `LC_*` travel (sshd's default AcceptEnv); others are ignored             |
| a window resize; a `signal` request (some clients) | resizes reach a tty; INT, TERM, HUP and KILL reach a command without a tty; other signals are ignored |
| `scp`, `sftp`, JetBrains (the `sftp` subsystem)    | the guest's `sftp-server` (see below)                                                                 |
| `scp -O`, `rsync`                                  | the guest's `scp` and `rsync` binaries, as commands                                                   |
| `-L`, `-D`, VS Code port forwards (`direct-tcpip`) | a connection to the guest's own loopback (`localhost`, `127.0.0.1`, `::1`); any other host is refused |
| `-L local:/guest/path.sock` (`direct-streamlocal`) | a connection to that guest Unix socket (absolute path, as the guest user)                             |
| `-R`, `-A`, `-X`, remote Unix forwards             | refused in this release                                                                               |

A forward to another host is refused (`administratively prohibited`) because
it would turn the guest into a proxy outside the sandbox's own
[egress policy](./network.md).

**sftp and scp.** OpenSSH's `scp` uses the sftp protocol by default, and
JetBrains Gateway does too. The sandbox needs OpenSSH's `sftp-server` binary
for that (Debian and Ubuntu: the `openssh-sftp-server` package, which installs
no `sshd` and listens on nothing); it is looked for at
`/usr/lib/openssh/sftp-server`, `/usr/libexec/openssh/sftp-server`,
`/usr/lib/ssh/sftp-server` and `/usr/libexec/sftp-server`. Without it, scp and
sftp fail with a line naming the package, while `scp -O`, `rsync`, shells,
commands and forwards still work. `rsync` likewise needs the guest's `rsync`
binary. Community templates include both; see
[template builds](./template-builds.md) to add them to another template.

**VS Code Remote-SSH and JetBrains Gateway.** Pick the host `<sandbox>.wssp`
after `wssp ssh-config --install`. Both use only what the table above maps:
a command to install and start their server in the guest, sftp (Gateway) to
upload it, and local forwards to reach it. The server they install runs as the
guest user and keeps running after a disconnect, like any process a normal
close leaves behind. Both sequences are covered by the automated tests (VS
Code's `ssh -T -D … bash` with a bootstrap script on stdin that starts a
service it then reaches through the same connection; Gateway's command, sftp
upload, then `-L` to the uploaded server); JetBrains Gateway itself is not yet
verified in the JetBrains Gateway app.

**Trust toward your machine.** The SSH layer gives the guest nothing on your
side: no agent, no X11, no reverse forwards and no way to open a channel
toward you. The tools on top of it are another matter. To them the sandbox is
an SSH server they trust: VS Code Remote-SSH and JetBrains Gateway run code
from the remote side and act on what it sends (a compromised remote can run
code on your workstation through them, as their vendors document), `scp`,
`sftp` and `rsync` take file names and contents from the guest's tools, and a
terminal shows whatever escape sequences the guest prints. Guest code with
guest sudo can replace any of those tools. Use the editor integrations only
with sandboxes whose contents you trust, and check what you copy out of a
sandbox that runs untrusted code.

**ControlMaster.** With `ControlMaster`/`ControlPersist` in your ssh config,
later sessions to the same sandbox reuse the first one's connection. Any
process of your local user can then use that control socket while it lives,
which is the same trust as reading your stored login. The shared connection
holds the login it started with: a server-side revoke (`wssp logout`, a
dashboard revoke, the key's expiry) ends it, but `wssp logout --local` or a
`wssp login` as another account does not, and until the master exits, new
sessions to that host name keep reaching the old login's sandbox. Stop it
with `ssh -O exit <sandbox>.wssp` after switching accounts.

**Your ssh's own listeners.** `-L` and `-D` listen on your machine, not in the
sandbox. With the default bind address that is loopback only; `-L
0.0.0.0:8080:localhost:8080`, `-D 0.0.0.0:1080` or `GatewayPorts yes` make your
ssh accept connections from your network into the sandbox, as with any ssh.

**Ending and revocation.** Closing a session hangs it up, as for a shell.
Revoking the login (`wssp logout`, a dashboard revoke, the key's expiry), a
stopped or destroyed sandbox or a lost connection ends the connection: the
`wssp` process prints one line naming why (your ssh shows it) and exits, and
ssh exits 255 as its ProxyCommand's stdio closes. Every channel of every
session on that connection ends with it. Once the session runs it writes no
log lines (`WSSP_LOG` applies only up to the start of the session).
Connecting to a sandbox that is not `READY`, or with a login that lacks
`sandboxes:connect`, fails the same way before any SSH starts.

Whatever ends the session (ssh's disconnect, its side of the pipe closing, a
wssp end, or a session that took none of a channel's last messages, such as
its exit status, for two seconds), the `wssp` process has exited within five
seconds of that end. The five seconds cover everything that follows: up to two
for ssh's last messages, then closing the channels at the sandbox, then the
final line. They hold even when your ssh stopped reading the process's output
or keeps the pipe open: the process reads its input whatever its output does,
and never waits on a blocked stdout or stderr past that deadline.

A channel the sandbox side aborts (a guest service reset its connection, the
server closed the channel) closes without an exit
status, so `ssh host cmd` exits 255 and a terminal shows a `wssp: …` line when
the client's window still takes it. SSH has no reset, though: a forwarded
(`-L`, `-D`) connection that the guest service resets reaches your local
client as a plain close, exactly as with OpenSSH's own sshd. A reset before
the guest service finished its reply arrives without the end of the stream,
but a reset after the service already closed its sending side cannot be told
from a clean end. A protocol that ends at the close cannot tell a cut reply
from a whole one there; `wssp sandbox forward` keeps the reset for TCP
listeners.

**Flow control.** Output is acknowledged to the sandbox only once your ssh
client's window took it. Input has its own SSH window per channel, one wssp
window (1 MiB for commands and forwards, 128 KiB for a terminal), and `wssp
ssh --stdio` grants a channel's ssh client more window only as the bytes leave
for the sandbox, which they do only as fast as the guest reads them. So at most
one window waits at the sandbox and one here per channel. A channel whose guest
stops reading (a guest program paused in a debugger, a command that never reads
stdin while you keep sending) stops only its own sender at its SSH window: the
terminal, every other forward and new channels of the same ssh connection,
ControlMaster sessions included, keep flowing for as long as it stays stuck,
and the stuck channel is never reset for it. Once its guest reads again, it
goes on where it stopped and loses nothing. A client that sends past a
channel's window (a protocol violation OpenSSH never commits) has that channel
reset (`wssp: the channel was reset: …` on a session's stderr).

The bytes are not journaled, and a shared node's owner can see them, as for
shells.
