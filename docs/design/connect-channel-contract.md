# CLI channel relay contract (`channel.*`)

CLI channels carry the CLI's interactive shells (and later port forwards and SSH) between the server and
the node daemon. A channel is one guest process (`pty` or `exec`) started in its own guest systemd scope as the
sandbox's guest user. This note covers the host leg (server ↔ daemon), the guest side and the client leg
(`/v1/sandboxes/{id}/connect`, [Client wire](#client-wire-wsspconnectv1)).

The browser terminal family (`terminal.*`, `docs/design/terminal-relay-contract.md`) is unchanged and separate.

Owner-approved (2026-11-20) changes that bind the client increments: clients acknowledge output promptly and the
stall rule is per frame age; each sandbox owner gets at most half of the host's bulk-frame cap; the scope unit is
`wssp-chan-<connectionId>.<channelId>.scope`.

## Capability and rollout

- The daemon offers `channels: {kinds: ["pty", "exec"]}` in `hello.daemon.capabilities` when its runtime implements
  channels. The server echoes the offer in `hello.ok.capabilities.channels`.
- The server never sends a `channel.*` frame to a host that did not negotiate channels. A daemon that receives one
  without the echo closes the connection (protocol error), and the server treats an unsolicited daemon `channel.*`
  frame the same way.
- The relay version stays `1.0`. Rollout order is server first, then daemons; roll back daemons first.

## Fence

Every frame carries `{channelId, connectionId, hostId, epoch, target: {kind: "sandbox", sandboxId, generation}}`.
The server mints `channelId` and `connectionId` (`[A-Za-z0-9][A-Za-z0-9_-]{0,63}`). The daemon takes the guest
identity, template and instance from its own journal lease, never from the frame. A frame whose fence does not
match the live channel delivers nothing and counts as a violation; the third closes the channel with
`protocol_violation`.

## Frames

| Frame                   | Direction     | Fields                                                                                                                                                    |
| ----------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `channel.open`          | server → host | `kind` (`pty`/`exec`), `argv?` (structural, never a shell string), `login`, `cwd?`, `env?` (`COLORTERM`, `LANG`, `LC_*` only), `pty?: {rows, cols, term}` |
| `channel.ready`         | host → server | `pty?: {rows, cols}` (the applied size)                                                                                                                   |
| `channel.data` (binary) | both          | `{type, fence, stream, seq}` + body; `stdin` to the host, `stdout`/`stderr` from it; ≤ 16 KiB (pty) or 32 KiB (exec)                                      |
| `channel.ack`           | both          | `stream`, `seq` (cumulative: the highest delivered `seq`)                                                                                                 |
| `channel.eof`           | both          | `stream`, `frames` (data frames sent on that stream; act after delivering all of them)                                                                    |
| `channel.resize`        | server → host | `rows`, `cols` (pty only)                                                                                                                                 |
| `channel.signal`        | server → host | `TERM`/`INT`/`HUP`/`KILL` (exec only)                                                                                                                     |
| `channel.close`         | server → host | `intent`: `client` is a normal close, any other intent a kill close                                                                                       |
| `channel.error`         | host → server | `unsupported_signal` or `state_conflict`; the channel stays open                                                                                          |
| `channel.exit`          | host → server | `exitCode?` or `signal?`, `intent?`, `error?`, `reaped`, `frames: {stdout, stderr}`; the last frame, after every output frame and eof                     |

Windows count frames per channel: 8 for pty channels and 32 for exec channels, in each direction. Guest output is
read only when its frame can be sent at once, so a slow client stops guest reads. Read-ahead stays bounded (at most 8
chunks per stream, dropped unread at a close decision like bytes still in the pipe). Clients acknowledge
delivered output promptly: at least every quarter window, and without holding a delivered frame back. A channel whose
oldest unacknowledged output frame is 60 s old closes with `backpressure`. The rule needs no thresholds and no view of
the host: every holder of credit returns each frame within 60 s or is closed, so no channel, however small its share,
pins the host cap. Nothing is ever dropped to make room.

The node forwards at most 16 data frames per socket-loop tick (pty channels first, each group rotated per tick). It
keeps at most 128 bulk frames (4 MiB) unacknowledged across the host, and at most half of that per sandbox owner, so
bulk output never delays acknowledgements, heartbeats or closes, and no single tenant can hold the whole cap. Pty
frames are exempt from both caps. So are a starting channel's setup reads: they carry at most one data frame, so
the cap is exceeded by at most one frame per starting channel.

The node's socket thread is the only decider. It owns every channel's state and byte IO and makes every close
decision, so no output frame and no stdin byte is handed over after a channel's close decision. A chunk handed to the
guest's stdin before the decision is still written, as for a pipe. Each socket-loop tick first gathers what it
decides on: every channel's authority verdict (these lookups may wait on a lock), then the custodians' queued events,
then one clock read. Its decisions then use only that snapshot, with no lookup and no clock read in between, and never
block on the socket: its frames are queued and written in order after the tick. An output frame is handed over when
its tick queues it, so no wait separates a decision from the check it rests on. Whatever changed after the snapshot
(a deadline, a revocation, an event) is acted on by the next tick first. A deadline or revocation therefore takes
effect at most one tick plus one flush late. A flush is small (one tick's frames: at most 16 data frames plus control
frames), and a socket write that makes no progress for 30 s fails the session, after which every custodian kills. A
peer that keeps accepting bytes slowly can stretch a flush beyond 30 s; the custodian's own deadline kill does not
depend on the socket thread. A per-channel custodian thread holds the process and decides nothing. It closes as told, kills when
the connection is gone, and kills shortly after the channel's absolute deadline if the node has not closed the channel
by then. The deadline also kills a normal close or natural end that is still settling. A kill-class close that arrives
during a normal close waits for the hangup (at most about 20 s), with the channel's IO already cut.

`reaped: false` means the end is not settled yet (the host-side `incus exec` client is not reaped, or a kill close
could not prove the scope gone). The channel's capacity stays charged until a later bare
`channel.exit{reaped: true}`.

## Guest side

One fixed helper (`crates/sandbox-runtime/src/incus/channel-helper.py`, run with `python3 -I -S`) launches every
channel:

1. **launch** (guest root): creates the transient scope `wssp.slice/wssp-chan-<connectionId>.<channelId>.scope`
   with `systemd-run --scope`. Without a usable guest systemd (≥ 254) the open fails with
   `UNSUPPORTED_CAPABILITY` (`guest_scope_unavailable`). There is no unscoped fallback.
2. **inner** (guest root, inside the scope): checks the cancel tombstone `/run/wssp/chan-cancel/<scope>` and exits
   if it exists, hands a tty to the guest user, then drops to the declared guest uid/gid.
3. **wrap** (guest user) writes `PROMPT` (bound to the public argv nonce) and waits for its preamble on stdin:
   the private defaults and CLI-login env (`<8 hex length>:<base64 JSON>`), then a 32-character frame secret and a
   newline. On a pty it reads in raw mode with echo off. The node writes the preamble only after `PROMPT`, while the
   channel is still starting, within its deadlines, with its authority intact and (pty) once the host tty is raw.
   Its last byte is the go: before it, nothing of the workload runs, and a close before it leaves a truncated
   preamble, so the wrapper exits without starting anything.
4. The wrapper then starts the workload and reports the `READY` birth record and the workload's `EXIT` status
   (`code N` or `signal N`) in band, both bound to the secret. The secret never reaches the workload's argv,
   environment or output, so workload output cannot forge `READY` or `EXIT` in either mode. A guest process with
   ptrace rights over the wrapper (same guest user) can read the secret. Statuses are guest-attested, and the
   signal helper only ever signals processes of the guest user. Exec channels run the wrapper as a new session and process-group leader,
   so `TERM`/`INT`/`HUP` go through `signal-helper.py` with that birth record. `READY` is written only once the
   workload child runs with default signal dispositions, and the workload starts only after `READY`, so a signal
   sent after `READY` always reaches the workload.

A channel ends naturally when every output stream has reached EOF. After the wrapper's `EXIT` it also ends 2 s later
once every open stream has proved idle (empty reads with credit available for 250 ms), and 60 s later in any case. A
detached process that keeps the pipes open (or keeps writing) therefore never pins the channel. A stream that cannot
be read for lack of credit is never "idle", so a slow client never loses output to the 2 s arm. Bytes still inside
the `incus exec` client at the moment of the cut (an idle gap of more than 250 ms after the 2 s mark, or the 60 s
cap) can be lost.

After a kill decision, stdin, the output pipes and the host client stay open until the scope is proven gone, so no
EOF, broken pipe or hangup reaches a workload the kill may have missed. An unproven kill keeps them, and the channel's capacity, until a
retried kill proves the scope gone.

The kill helper writes the tombstone first, then kills the scope (`cgroup.kill`) and proves it gone (`populated 0`
or an absent cgroup). Either the launcher sees the tombstone, or its scope existed before the tombstone was
written and the kill covers it.

Close semantics follow sshd. A normal close hangs the session up: processes that detached themselves (`tmux`,
`nohup`, `setsid`) survive. Revocation, lifecycle closes, limits, protocol violations, relay loss and daemon
shutdown kill the channel's scope. A wrapper status reported before a proven kill stands; otherwise a proven kill
reports `signal 9`, and a missing status is unknown (no `exitCode` and no `signal`). Statuses are guest-attested.

With `guestSudo` the guest user can leave the scope as root, and processes started through cron, `at` or a
`systemd --user` manager are outside it. Scope kills are then best effort inside the guest, as for tracked
commands.

## Durable registry

Before a launch the daemon writes `channel-scope-<unit>` into its journal directory. The entry is removed after a
normal end, a proven kill, or a positively stopped or absent VM. At start the daemon kills exactly the registered
scopes (batched per sandbox) and forgets the proven ones; unregistered `wssp-chan-*` scopes are survivors of a
normal close and are left alone. A crash between a normal close and the entry's removal kills those survivors
too, which fails toward cleanup.

## Client wire (`wssp.connect.v1`)

The CLI reaches a sandbox's channels through one WebSocket per connection. The schemas live in
`packages/sandbox-contracts/src/connect-wire.ts`; `connect-wire-fixtures.json` next to it holds the vectors
every implementation (the Rust CLI included) must accept or refuse.

### Upgrade

`GET /v1/sandboxes/{id}/connect` with `Upgrade: websocket`, `Sec-WebSocket-Protocol: wssp.connect.v1` (exactly
that one entry) and `Authorization: Bearer wssp_sdk_…`. Only kind `API` keys holding `sandboxes:connect` connect:
a dashboard SDK key that was explicitly given the scope, or a `wssp login` with write access. Agent tokens, OAuth
grants and MCP never hold it. Refusals are HTTP answers in the /v1 error catalog, before any WebSocket exists:

| Refusal                                                                | Answer                                                                                                   |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| server shutting down                                                   | 503 `SERVICE_UNAVAILABLE`                                                                                |
| no `Upgrade: websocket`                                                | 426                                                                                                      |
| any `Origin` header, any `Cookie` header                               | 403 `FORBIDDEN`                                                                                          |
| a subprotocol other than exactly `wssp.connect.v1`                     | 400 `BAD_REQUEST`                                                                                        |
| a credential in the query; duplicate `Authorization`; a non-`API` kind | 400 / 401 (as every /v1 route)                                                                           |
| connect budget (30/min per key, 60/min per IP; fail closed)            | 429 `TOO_MANY_REQUESTS` / 503                                                                            |
| missing `sandboxes:connect`                                            | 403 `FORBIDDEN`                                                                                          |
| no such sandbox, or another owner's                                    | 404                                                                                                      |
| a managed sandbox (build, verify, CLI login)                           | 409 `sandbox.managed` (or 400 `UNSUPPORTED_CAPABILITY`, `connect_sandbox_unsupported`)                   |
| not `READY` on a usable host                                           | 409 `sandbox.state_conflict` (no usable host at all, e.g. offloaded: authorization already refuses, 403) |
| the node did not negotiate `channels`                                  | 400 `UNSUPPORTED_CAPABILITY`, reason `connect_host_outdated`                                             |
| the host is not connected                                              | 409 `sandbox.host_unavailable`                                                                           |
| 8 connections per sandbox, 16 per key or 32 per owner                  | 429 `TOO_MANY_REQUESTS`                                                                                  |

### Frames

Control frames are JSON text (at most 256 KiB). Channel data is binary: a big-endian u32 metadata length, the
JSON metadata `{type: "data", channel, stream, seq}` (at most 1 KiB) and a body of 1 byte to 16 KiB (pty) or
32 KiB (exec). Every object is strict: an unknown field ends the connection with `protocol_violation`.

| Frame         | Dir  | Fields                                                                                                                                                                    |
| ------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hello`       | S→C  | `connectionId`, `sandboxId`, `limits` (the table below); always the first frame                                                                                           |
| `open`        | C→S  | `channel`, `kind` (`pty`/`exec`), `argv?` (structural), `login?`, `cwd?` (absolute), `env?` (`COLORTERM`, `LANG`, `LC_*`), `pty?: {rows, cols, term}` (exactly for `pty`) |
| `ready`       | S→C  | `channel`, `pty?: {rows, cols}` (the applied size)                                                                                                                        |
| data (binary) | both | `stdin` from the client; `stdout`/`stderr` to it                                                                                                                          |
| `ack`         | both | `channel`, `stream`, `seq`: cumulative, the highest delivered `seq` (`stdout`/`stderr` from the client, `stdin` from the server)                                          |
| `eof`         | both | `channel`, `stream`, `frames`: the data frames sent on that stream (`stdin` from the client; `stdout`/`stderr` to it)                                                     |
| `resize`      | C→S  | `channel`, `rows` 1–512, `cols` 1–1024 (pty)                                                                                                                              |
| `signal`      | C→S  | `channel`, `TERM`/`INT`/`HUP`/`KILL` (exec; `KILL` kill-closes the scope)                                                                                                 |
| `close`       | C→S  | `channel` (a normal close: sshd semantics)                                                                                                                                |
| `exit`        | S→C  | `channel`, `exitCode?` or `signal?`, `intent?`, `error?: {code, message}`, `frames: {stdout, stderr}`; the channel's last frame                                           |
| `error`       | S→C  | `channel`, `code` (`unsupported_signal`, `state_conflict`); the channel stays open                                                                                        |
| `end`         | S→C  | `intent`, `error?`; the whole connection ends, then close code 4401                                                                                                       |

`limits` in `hello`: `maxChannels` 32, `maxPtyChannels` 8, `opensPerMinute` 120, `windowFrames` `{pty: 8, exec:
32}`, `dataMaxBytes` `{pty: 16384, exec: 32768}`, `ackStallMs` 60000, `pingIntervalMs` 20000, `idleTimeoutMs`
60000, `openTimeoutMs` 30000, `unackedInputBytes` 4194304.

### Rules

- The client sends nothing before `hello`; frames it sends earlier are held and processed after it.
- Channel ids are client-chosen u32 numbers, strictly increasing per connection and never reused. A frame
  naming an id that was never opened ends the connection with `protocol_violation`; a frame naming a channel
  that already ended (acks and input racing its `exit`) is ignored. The server maps each channel to a host
  `channelId` it mints and to its own `connectionId`; the client never names a host, epoch or generation.
- A refused open (a cap, a rate, a node refusal) answers with `exit` carrying `error` and no `ready`
  (server codes `host_capacity`, `rate_limited`, `disconnected`; an open the node does not answer within
  `openTimeoutMs` exits `expired` with `timeout`).
- Credit is end to end and counts frames per channel, both output streams together. Output: at most
  `windowFrames` unacknowledged frames per channel, and 4 MiB per connection. **Acknowledge every delivered output
  frame promptly, at least every quarter window, and never hold one back**: the node closes a channel whose
  oldest unacknowledged output frame is `ackStallMs` (60 s) old with `backpressure`. stdin: at most `windowFrames`
  frames not yet acknowledged by the server per channel, and at most `unackedInputBytes` (4 MiB) of them across
  the connection's channels, sequences from 0 without gaps; more is a protocol violation. The server
  acknowledges stdin as the node consumes it.
- Rate: data bytes are capped per connection in each direction (default 8 MiB/s,
  `SANDBOX_CONNECT_MAX_BYTES_PER_SECOND`), with up to one second of burst. The cap only delays frames: nothing is
  dropped, and output waiting for it holds the node's credit like a slow client.
- `eof` and the natural `exit` follow every data frame of their stream; act on `eof.frames` only after
  delivering that many frames. An `exit` with an `intent` is a close decision: output not yet delivered may be
  dropped and the `exit` delivered at once.
- Liveness: the server pings every 20 s; a client that sends nothing (no frame, no pong) for 60 s is gone and
  the connection ends `detached` (`timeout`). There is no idle timeout for an answering client.
- Lifetime: a connection ends `expired` (`timeout`) 12 h after it opened, however active (the node's own
  per-channel limit is the same 12 h); the key's expiry and the sandbox lease end it earlier.
- Authority: the server keeps the key's retained `sandboxes.connect` authorization for the connection's life
  and checks it before every delivery in both directions; it re-reads it every 15 s, on every authority change of
  the key, its owner, the host, the host owner or the pool owner, on every lifecycle change of the sandbox and at
  the key's or lease's expiry (5 s deadline, fail closed). The connection ends with `end{intent}` and close 4401:
  `revoked` (key revoked or expired, owner banned or deleted, grant or custody lost), `sandbox_stopped`,
  `sandbox_destroyed`, `expired` (lease), `superseded` (new generation, host or host owner),
  `host_disconnected`, `detached`, `protocol_violation`, `backpressure`, `lifecycle_unconfirmed` or `shutdown`.
  Every channel of the connection then gets `channel.close{intent}` on the node; nothing is forwarded in
  either direction after the decision, and there is no resume.
