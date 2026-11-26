# The `wssp` CLI as a user

The `wssp` binary has two sides. **Host commands** (`wssp host …`) make a
Linux machine a wssp host; see the [hosts guide](./hosts.md). **User commands**
(`login`, `logout`, `whoami`, `sandbox`, `template`, `ssh`, `ssh-config`) let
you, a person or a script, work with your sandboxes from a shell through the
`/v1` API (and open [shells in them, forward ports to them and reach them with
plain ssh](./connect.md)), with the
same authority as an [SDK key](./auth-planes.md). The two sides keep separate
state and credentials; a user login never authorizes host commands, and a host
credential never authorizes user commands.

Every flag is listed in the generated
[command reference](../../apps/cli/docs/cli-reference.md).

## Install

`wssp` runs on x86_64 and ARM64 Linux (on Windows, in a WSL 2 shell). Install
the version that matches your server from the server itself, as the user who
will run `wssp` (not root):

```sh
curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://<your-server>/install.sh | sh
```

The script (read it first if you like: open the same URL in a browser):

- downloads `wssp-<target>.tar.xz` and `sha256.sum` of the server's version
  from its GitHub Release (or the mirror the operator set in
  `WSSP_CLI_RELEASE_BASE_URL`), over https only;
- installs only when the archive's SHA-256 matches exactly one `sha256.sum`
  entry, the archive holds only `wssp-<target>/` with the binary in it, and the
  binary reports the server's version; any failure stops it with nothing
  installed;
- writes `~/.local/bin/wssp` (replacing an older one in place), refuses to run
  as root unless you pass `--install-dir`, and prints the next step: `wssp
  login --server <server>` on a computer you work from, or the host enrolment
  steps.

Options go after `sh -s --`, for example
`… | sh -s -- --install-dir /usr/local/bin`. To keep a failed download from
running as an empty script, download first:
`curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://<your-server>/install.sh -o install.sh && sh install.sh`.

The checksum proves the archive is the one the release lists; the release's
build provenance proves GitHub Actions built it from this repository. Check it
with the GitHub CLI:
`gh attestation verify wssp-x86_64-unknown-linux-musl.tar.xz --repo FlyCockpit/ws-sandbox-proxy`.

From a checkout (Rust 1.99+): `cargo install --path apps/cli --bin wssp`.

## Log in

```sh
wssp login --server https://wssp.example.com
```

`wssp login` runs a device authorization with the scope `user-login`. It
prints a user code and a URL; open the URL in a browser that is signed in to
your account. The approval page, not the CLI, chooses the key:

- a **name** (default `wssp login`);
- **access**: `read` (list and read sandboxes, command output and files) or
  `write` (also create, stop, start and destroy sandboxes, run commands, write
  files, cancel operations and manage preview tunnels). Read access still lets
  that machine read files and command output in your sandboxes;
- **pools**: every pool you may use, or selected pools;
- **only sandboxes this login creates** (off by default);
- an optional **live sandbox limit** (1 to 1000);
- an **expiry** of 1, 7, 30 (default) or 90 days.

Approve only a request you started yourself. The exact scopes and limits are
in [authentication planes](./auth-planes.md). A login never holds host access,
template writes or builds, webhooks or credential-vault scopes. Your account
holds at most 20 active CLI logins.

`--server` defaults to the origin of the current login, so `wssp login` alone
renews it. For a server behind a private CA, `--ca-file <path>` saves the CA
path with the login (`WSSP_CA_FILE` overrides it per invocation):

```sh
wssp login --server https://wssp.internal --ca-file /etc/ssl/internal-ca.pem
```

`wssp login --json` prints one JSON line when
the flow starts (`userCode`, `verificationUri`, …) and one with the grant at
the end, whose `warnings` array carries what human mode prints as
`warning: …` on stderr; the key itself is never printed.

Logging in again replaces the saved login; the previous key stays valid until
it expires or you revoke it on the dashboard's **SDK keys** page, where CLI
logins carry a "CLI login" badge. If the approved login cannot be saved,
`wssp login` revokes the new key again and says so. When `WSSP_API_KEY` or
`WSSP_SERVER` is set, `wssp login` warns that commands in that environment
use them instead of the saved login.

## Who am I

```sh
wssp whoami            # the saved login plus GET /v1/key: scopes, live sandboxes, limit, expiry
wssp whoami --offline  # only what is saved here; no network call
```

## Log out and revocation

```sh
wssp logout          # DELETE /v1/key (the key revokes itself), then remove the saved login
wssp logout --local  # remove the saved login only; the key stays valid
```

A key the server no longer accepts (401) counts as already revoked and the
login is removed. Any other failure keeps the login so you can retry. If
another `wssp login` saves a new login while the revocation is in flight, the
new login is kept. Only a
CLI-login key may revoke itself; you can also revoke it on the dashboard at any
time, after which every command exits 7.

## Sandboxes

```sh
wssp sandbox create --template ubuntu --pool <pool-id> --name build-1 --timeout 2h --wait
wssp sandbox create --template ubuntu:latest --host <host-id> --cpu 2 --memory 4096 --disk 20 --metadata team=ci
wssp sandbox list                       # READY sandboxes, newest first, one page
wssp sandbox list --state STOPPED --state READY --limit 50
wssp sandbox list --cursor <next-cursor>
wssp sandbox get <sandbox-id>
wssp sandbox stop <sandbox-id> --wait
wssp sandbox start <sandbox-id> --wait  # cold reconnect with the remembered lease; waits until READY
wssp sandbox start <sandbox-id> --timeout 4h --wait  # same, with a new lease that later starts reuse
wssp sandbox destroy <sandbox-id> --wait
```

`create` needs a template selector (slug, `slug:tag`, `template/<id>` or
`revision/<id>`) and exactly one placement target: `--pool` or `--host`.
Without `--wait` it prints the accepted operation and the new sandbox id;
with `--wait` it follows the operation and then the sandbox until it is
READY. `--timeout` is the lease (`30m`, `2h`, `1d`; `0` only where policy
allows no lease). `start` re-arms the lease counted from when the start is
accepted (a create counts from READY where the host supports it): without
`--timeout` it reuses the sandbox's remembered lease (the latest one its
create, a start or a renewal named) and keeps its expiry action; `start --timeout`
sets a new lease, which later starts then reuse. A login with a live sandbox limit that is reached fails with
`sandbox.key_limit_reached` (exit 9). Lists are bounded pages; a further page
prints its `--cursor`.

Operation submissions (create, stop, start, destroy, exec, file changes) and
upload reservations and commits are sent with one idempotency key and re-sent
unchanged while the server answers 429, 503 or 504, or the connection times
out, is refused or drops, so a retry never repeats an action. Upload chunks are
re-sent the same way without a key: each chunk names its byte range, so a
replay rewrites the same bytes. Releasing a failed upload is a single best-effort
call. `sandbox ports expose|set|close|link` and `logout` carry no idempotency
key and are sent once; on 429, 503 or 504 they fail with exit 11. When such an
answer leaves the outcome unknown, check before repeating: `sandbox ports get`
shows the tunnel (a repeated `close` of a tunnel that did close fails with
`sandbox.tunnel_not_found`, exit 3), and a repeated `link` mints a new link
while an earlier one may stay valid until it expires. TLS and certificate
failures, DNS failures and redirects fail at once. A wait the server asks for
(`retryAfterSeconds` or `Retry-After`) is honored exactly; when it does not fit
the two-minute retry window the answer is returned instead (exit 11). Only the
client's own backoff (1, 2, 4 … 16 s) is capped.

### Commands

```sh
wssp sandbox exec <sandbox-id> -- uname -a
wssp sandbox exec <sandbox-id> --cwd /home/user/app --env NODE_ENV=test --timeout 10m -- npm test
wssp sandbox exec <sandbox-id> --detach -- ./long-job.sh   # prints the operation id
wssp sandbox logs <operation-id> --follow
wssp sandbox ps <sandbox-id>
```

`exec` streams the command's stdout and stderr as they arrive and exits with
the command's own exit code once the operation SUCCEEDED. Ctrl-C requests the
operation's cancellation (waiting at most about 10 seconds) and exits 130,
even while the output is blocked on a pipe nobody reads; a second Ctrl-C exits
at once. While
the command is being started, Ctrl-C stops the retries: no further start is
sent, a receipt still in flight is cancelled, and when an earlier attempt may
have been accepted without an answer, the error names its idempotency key and
`wssp sandbox ps <sandbox-id>` to find it. When stdout closes early
(`wssp sandbox exec … | head -1`), `exec` requests the cancellation too and
exits 141. If wssp itself fails (including an unreadable login or a missing
or invalid CA file), the operation failed or was cancelled, the exit code is
outside 0–255, or the server cannot confirm what happened to the command,
`exec` exits **125** with a typed error. A command can also exit 125 itself
(`sh -c 'exit 125'`), and `exec` passes that through unchanged. The two are
told apart on stderr: a wssp-side 125 always ends with wssp's error message
(with `--json`, the single `{"error":…}` line), while a passed-through 125
adds nothing after the command's own output. The server keeps the first 256 KiB and the last 768 KiB
of a command's output; omitted ranges and truncation are noted on stderr. If
the command is dispatched again, its output restarts (noted on stderr).
`exec --json` prints `{operationId, exitCode, stdout, stderr, truncated, gaps,
gapsOmitted, restarts}` at the end instead of streaming, keeping the same first
256 KiB and last 768 KiB of each stream; omitted ranges (`gaps`, the first 256
listed) and restarts are fields there, never stderr notes (`logs --json`
likewise). `logs` reads the retained output of any command; `--follow`
keeps reading until it completes. `logs` and `files read` to stdout exit 141
when stdout closes early.

### Shells

```sh
wssp sandbox shell <sandbox>                  # an interactive login shell
wssp sandbox shell <sandbox> -- htop
wssp sandbox shell <sandbox> --no-tty -- make test
```

`shell` opens a shell, or runs a command, over the connect plane: with a
terminal on stdin and stdout the guest side gets a tty and your terminal is
raw for the session; otherwise stdout and stderr stay separate and stdin is
piped. It needs a login with write access (`sandboxes:connect`; a login saved
before that scope existed exits 8 and asks you to log in again). `<sandbox>` is
an id or a name. It exits with the remote status (128 + N for a death by
signal N) and with 125 when wssp ends the session. See
[shells from the CLI](./connect.md).

### Port forwards

```sh
wssp sandbox forward <sandbox> 5432           # local 127.0.0.1:5432 → the sandbox's port 5432
wssp sandbox forward <sandbox> 8080:0         # a free local port, printed
wssp sandbox forward <sandbox> 5432 --unix ./pg.sock
```

`forward` listens locally and relays every connection to a port on the
sandbox's own loopback over the same connect plane and scope as `shell` (no
host is ever named, and no network path to the sandbox is opened). A loopback
port is reachable by other users of your machine; `--unix` listens on a 0600
socket instead, and `--address` with a non-loopback address warns. Ctrl-C
closes every connection and exits 130; when wssp ends the session it exits
125. See [port forwards](./connect.md#port-forwards).

### ssh

```sh
wssp ssh-config --install     # once; `--yes` for scripts, `--json` for the details
ssh <sandbox>.wssp            # then plain ssh, scp, sftp, rsync, VS Code, Gateway
wssp ssh <sandbox> -- -t htop # or the system ssh without any config
```

`ssh-config` prints the `Host *.wssp` block (its ProxyCommand is the `wssp`
you ran, by its absolute path or the one `PATH` found; run `--install` again
after moving it), and `--install` writes it to `~/.ssh/config.d/wssp` and adds
`Include config.d/wssp` at the top of `~/.ssh/config` after asking, unless
`~/.ssh/config` already starts with that `Include`. `~` is your account's
home directory, which OpenSSH reads; a different `$HOME` is refused. An edit
made to either file while the question is open is never overwritten: wssp
checks both again and asks you to rerun. wssp keeps the previous file as
`~/.ssh/config.wssp-backup-<time>` (or `config.d-wssp.wssp-backup-<time>`)
and names it; delete it when you no longer need it.
No SSH key or password is involved: the ProxyCommand `wssp ssh --stdio` uses
your login, the same scope as `shell`, and serves SSH on its own stdin and
stdout (it never listens). The SSH session is not end-to-end to the guest; the
server and the node see the bytes, as for shells. `--rotate-host-key` replaces
the local host key. See [ssh](./connect.md#ssh), and the
[step-by-step guides](./ssh/README.md) for VS Code, rsync, scp and sftp.

### Files

```sh
wssp sandbox files ls <sandbox-id> /home/user --depth 2
wssp sandbox files stat <sandbox-id> /etc/os-release
wssp sandbox files read <sandbox-id> /var/log/app.log > app.log
wssp sandbox files read <sandbox-id> /home/user/out.tar --output out.tar
wssp sandbox files write <sandbox-id> /home/user/in.tar --from in.tar
wssp sandbox files write <sandbox-id> /home/user/config.json --from -
wssp sandbox files mkdir <sandbox-id> /home/user/data
wssp sandbox files mv <sandbox-id> /home/user/a.txt /home/user/b.txt
wssp sandbox files rm <sandbox-id> /home/user/data --recursive
```

Paths are absolute guest paths. `read` verifies the download's SHA-256;
with `--output` it writes the file only after the whole download verified.
`write` uploads through a resumable transfer (at most 1 GiB) and commits it
by SHA-256; `--from -`, or a source that is not a regular file (a FIFO,
`/dev/stdin`, `<(cmd)`), is read into a private temporary file first so the
length is known. An upload reservation whose chunk size is not the contract's
1 MiB is refused before any byte is sent. `read --output` creates the file with the usual mode (0666
less the umask).

### Preview tunnels

For a sandbox created with declared tunnel ports (see
[preview tunnels](./tunnels.md)):

```sh
wssp sandbox ports get <sandbox-id>
wssp sandbox ports expose <sandbox-id> 3000 8080
wssp sandbox ports set <sandbox-id> --add 5173 --remove 8080
wssp sandbox ports link <sandbox-id> 3000 --ttl 300
wssp sandbox ports close <sandbox-id>
```

`link` prints a short-lived access URL (single use unless `--multi-use`). Treat
it as a secret.

## Templates

```sh
wssp template list
wssp template get <template-id>   # the template and its revisions
```

`get` pages through the template list to find the template (at most 100 pages
of 100); a template whose revisions exist but that is not found within that
bound is reported as such (exit 1), not as not-found.

## JSON output

Every user command takes `--json`: stdout carries one JSON document, the
server's typed DTO where one exists. On failure stdout stays empty and stderr
carries exactly one line:

```text
{"error":{"code":"sandbox.key_limit_reached","status":409,"message":"`sandbox.key_limit_reached`: This key's live sandbox limit is reached.","data":{"maxLiveSandboxes":3,"liveSandboxes":3}}}
```

`code` is the server's error code (or, for a local failure, a stable name such
as `not_logged_in`), `status` the HTTP status or `null`. The exit code is the
contract; human error messages also name the server code.

User commands write no logs to stderr by default, only errors; `-v` adds debug
logs (for example which CA file was loaded). `wssp host …` commands keep their
operator logs at info.

## Exit codes

| Code | Meaning                                                                                                                                                                   |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | success                                                                                                                                                                   |
| 1    | other failure (transport, an operation that failed, a server error)                                                                                                       |
| 2    | usage error, or the server refused the request as invalid (400, 413, 415)                                                                                                 |
| 3    | not found (404); also a pool outside the login's pools: the server answers 404, so a login cannot learn which pools exist                                                 |
| 7    | not logged in, or the server refused the key (401)                                                                                                                        |
| 8    | forbidden: the login's scopes do not allow it (403)                                                                                                                       |
| 9    | a limit was reached: `sandbox.key_limit_reached`, a quota, `sandbox.capacity_queue_full`                                                                                  |
| 10   | any other conflict (409)                                                                                                                                                  |
| 11   | retryable: the server answered 429, 503 or 504                                                                                                                            |
| 125  | `sandbox exec`/`shell`/`forward` and `ssh --stdio` only: wssp failed or ended the session, or the outcome is unknown (or the command exited 125)                          |
| 130  | `sandbox exec` interrupted with Ctrl-C (cancellation requested); `sandbox shell` without a tty: a second Ctrl-C closed the channel; `sandbox forward` stopped with Ctrl-C |
| 141  | stdout closed early: `sandbox exec` (cancellation requested), `logs`, `files read`                                                                                        |

Codes 4–6 belong to host commands; see the [CLI README](../../apps/cli/README.md#exit-codes).

## CI and scripts

Set both variables instead of logging in; together they win over a saved
login:

```sh
export WSSP_SERVER=https://wssp.example.com
export WSSP_API_KEY=wssp_sdk_...   # an SDK key from the dashboard, kept in your CI secret store
wssp sandbox list --json
```

Only one of the two is a usage error (exit 2). `wssp logout` acts on the saved
login only and never revokes an environment key.

## State on disk

| What                   | Where (Linux)                                                |
| ---------------------- | ------------------------------------------------------------ |
| user login             | `~/.local/share/wssp/user/login.json` (0600, directory 0700) |
| host device credential | `~/.local/share/wssp/device-auth.json`                       |
| host configuration     | `~/.config/wssp/config.toml`                                 |
| ssh host key           | `~/.local/share/wssp/user/ssh/host_key` and `known_hosts`    |

`WSSP_USER_DIR` moves the user login directory; it may not be, contain or lie
inside the host data or config directory (exit 2). The default
`<data dir>/user` must be a real directory, not a symlink: one that resolves
anywhere else inside, onto or above the host directories is refused the same
way. A missing directory is
created owner-only; an existing one is used as it is, never chmodded, and
refused while group or other writable; saving a login into it keeps its mode. `WSSP_DATA_DIR` and
`WSSP_CONFIG_DIR` move the data and config directories. User commands never
read `config.toml` or the host credential, and host commands never read the
user login.

## Logins on host machines

On an enrolled host, `wssp login` warns before it starts (with `--json`, the
warning is in the `warnings` array of the success object instead, and a
failure prints only its JSON error line): host commands that
agents run on that machine (`hosts:execute`, `hosts:files`, once a person
enabled them at the node) run as the daemon user and could read a login saved
by that user. Prefer logging in on a machine that is not a host, or choose read
access and a short expiry. Host commands started for agents never inherit
`WSSP_API_KEY` or `WSSP_SERVER` from the daemon's environment.
