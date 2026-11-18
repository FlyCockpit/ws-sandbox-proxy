# Terminal relay contract

The host relay carries a terminal channel that binds one browser attachment
to one typed host or guest PTY (the guest `PtySession` from
[ADR-004 § Terminal PTY](./adr-004-runtime-boundary.md#terminal-pty)).
This note defines the wire contract. The browser upgrade and its
authentication ([browser terminal authentication](./browser-terminal-auth.md)), the UI and lifecycle hardening build on it.

Sources: `crates/sandbox-protocol/src/terminal.rs` (Rust),
`apps/server/src/sandbox-relay/protocol.ts` (TypeScript mirror),
`apps/server/src/sandbox-relay/terminal-manager.ts` (server),
`apps/cli/src/sandbox_relay/terminal.rs` (host). The bounds live in
`packages/config/src/sandbox-terminal-limits.json`. Both peers are
parity-tested against it and against the shared fixtures
`crates/sandbox-protocol/fixtures/control_terminal.json` and (reattach)
`crates/sandbox-protocol/fixtures/terminal_resume.json`.

## Negotiation

The only supported relay protocol is **1.0**, with subprotocol
`ws-sandbox-proxy.relay.v1`. Any other version is refused; there is no
adapter or downgrade path. Browser wire is
`wssp.terminal.v1`, plus `wssp.terminal.v2` for sandbox terminals that can
reattach (see [Reattach](#reattach)). Server, worker and daemon must
ultimately ship from the same integrated commit; matching version strings are
insufficient.

A daemon that can keep a lost PTY detached offers the optional hello
capability `terminalResume: {graceMs}` (1 s–10 min; the node's
`terminal_resume_grace`, default 120 s). Only then does `hello.ok` carry
`capabilities.terminalResume: true`, and only then may the server send
`terminal.resume`. Without it the server behaves exactly as before.

Hello requires independent `terminal`, `hostTerminal`,
`requireHostTerminalTotp` and `policyRevision` capability fields. The default policy reports
host terminals off, TOTP required and revision zero. Local settings, hot reports
and PTY activation enforce that policy. The policy tuple is live-link state, never a
remembered host database column. `HostInventoryUpdate` stays health-only:
policy and static capacity rewrites are refused there.

### Agent host access and remote off

[ADR-006](./adr-006-agent-host-access.md) defines separate scoped host commands
and files. They use `host.exec.*` and `host.file.*`, not terminal tickets or
PTY frames. Hello advertises `hostCommands`, `hostFiles`, `hostCommandMaxMs`
(only when commands are on), and `agentPolicyRevision`; false/zero optional
fields are omitted. `host.agent-policy` carries current epoch and monotonic
sequence. The server checks owned-node authority and effective policy before
dispatch; the daemon checks owner, epoch and live revision again.

`host.policy.lower` targets `hostCommands` or `hostTerminal`. The daemon persists
off, stops affected commands/file work or host PTYs, reports policy, and returns
`host.policy.lower.result`. Pending dashboard lowering is durable and replayed
on reconnect; reported policy itself remains live-link state. No server frame
can enable host access. The existing `host.terminal-policy.raise` only requires
TOTP; it does not enable terminals. See the [node commands](../guide/hosts.md#node-settings-for-agents-and-terminals).

### Journal version

The daemon journal version is **1**. A journal with any other version fails
before receipts load; there is no converter, reset or guessed lineage. Server
and daemons are deployed from the same release.

### Contract pins and activation boundary

The strict transport/workload, policy and typed-terminal codecs share
`crates/sandbox-protocol/fixtures/sharing_cases.json` across TS and Rust. Workload binding adds
`sandboxOwnerId`, sandbox and generation to canonical server +
`hostOwnerId` + host. Host-derived keys use the transport tuple; private
config MACs also bind the workload creator. Host custody never grants guest
execution authority.

Transport/workload consumers are wired through the daemon journal and the relay.
The real two-owner SDK/HTTP/PostgreSQL fake-wire lifecycle and owner-oracle
qualification passed before shared reads were exposed. See
[sharing lifecycle qualification](../testing.md#sharing-lifecycle-qualification-and-creator-fairness)
for the evidence boundary. This is not live VM/network or deployment proof.

Typed-target PTY activation and foreign guest-terminal grants require matching
consumers, producers, binary paths, ACKs and fixtures. The foreign guest-terminal
gate remains in place; mixed-peer deployment is unsupported.

## Identity (the fence)

The final integrated terminal fence is exactly:
`{sessionId, operationId, hostId, epoch, target}` where target is either
`{kind:"host"}` or `{kind:"sandbox", sandboxId, generation}`. Mixed variants,
flat sandbox fields, missing/null targets and extra properties are refused.
Every control and binary frame compares the complete fence. There is no
default target or guest-to-host fallback. The live control/binary codecs enforce these shapes. Host/browser grants
are durably authorized.

| Field                      | Source                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `sessionId`, `operationId` | Minted by the server for each open.                                                                                |
| `hostId`, `epoch`          | The authenticated host connection.                                                                                 |
| `sandboxId`, `generation`  | The server's sandbox record, from the browser's ticket binding. The browser upgrade re-reads it after the upgrade. |

Nothing in the fence comes from the browser.

The ids use the runtime session-id grammar: 1–128 characters from
`[A-Za-z0-9_-]`, starting with a letter or digit. `generation` is at least 1.
A terminal frame cannot carry a guest identity, a template or an instance
name: the strict schemas refuse unknown fields. The host opens the PTY with
the sandbox, generation, template fingerprint and guest UID/GID/HOME/SHELL
recorded in its journal lease (`LeaseRecord.guest`, bound at create/reconnect
acceptance). It refuses the open when the journal generation, binding or lease
is not current, or when no guest identity is recorded.

A frame whose fence does not exactly match the live session it names delivers
**zero bytes**. Each peer handles a mismatch the same way:

- A frame for an unknown session id is dropped and audited. A frame naming one
  of the last 64 ended sessions is dropped without an audit line. On the
  server, both count as foreign frames, because a session's final
  `terminal.exit` is the host's last frame for it (the one exception, the
  reconciliation exit after `reaped: false`, arrives while the server still
  holds the session as `unreaped`, so it is never foreign). The server closes
  a host socket that sends more than 256 foreign frames.
- A mismatch on a live session counts as a violation. On the third violation
  the session is closed with intent `protocol_violation`.

## Frames

The `requestId` echo correlates control responses, like the command channel.

| Frame             | Direction     | Carries                                                                                                                       | Answer                                                                                   |
| ----------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `terminal.open`   | server → host | `requestId`, `fence`, `rows`, `cols`                                                                                          | `terminal.ready` (same `requestId`) or `terminal.exit` with `error`                      |
| `terminal.resize` | server → host | `requestId`, `fence`, `rows`, `cols`                                                                                          | `terminal.ready` (same `requestId`, applied size)                                        |
| `terminal.close`  | server → host | `requestId`, `fence`, `intent`                                                                                                | final `terminal.exit` (same `requestId`, same `intent`)                                  |
| `terminal.ack`    | both          | `fence`, `sequence`                                                                                                           | returns credit (see flow control)                                                        |
| `terminal.data`   | both (binary) | metadata `{type, fence, sequence}` + 1..16 KiB body                                                                           | input (server → host), output (host → server)                                            |
| `terminal.resume` | server → host | `requestId`, `fence`, `nextOutputSeq`, `rows`, `cols` (sandbox target only; only when negotiated, after `reconcile.complete`) | `terminal.ready` with `outputSeq` (same `requestId`) or `terminal.exit`                  |
| `terminal.ready`  | host → server | `requestId`, `fence`, `rows`, `cols`; `outputSeq` only when answering `terminal.resume`                                       | —                                                                                        |
| `terminal.exit`   | host → server | `fence`, `reaped`, optional `requestId`, `exitCode`, `intent`, `error`                                                        | final frame of the session (after `reaped: false`, one bare reconciliation exit follows) |

Rows are 1–512 and columns 1–1024. Out-of-range sizes are refused, not clamped.

`terminal.exit` is the host's last frame for a session, with one exception:
after `reaped: false`, the reconciliation exit described below follows and is
the last. That bare exit (`{type, fence, reaped: true}`) is in the shared
fixture `crates/sandbox-protocol/fixtures/control_terminal.json`.

- No `intent` and no `error`: the shell exited on its own, with `exitCode`.
- `intent`: the runtime or the daemon closed the session for that reason.
- `error`: the open was refused before any PTY existed, the session was
  closed for a protocol violation, or the host's pump failed (`internal`).
  A failed pump still closes the PTY on its own thread and sends this exit.
- `reaped: false`: the PTY child's reap is uncertain. Its capacity stays
  charged on **both** peers. The host's reconciliation sweep (the pump
  thread, every 250 ms, one non-blocking reap attempt) releases the host slot
  only on a confirmed reap, and then sends a **second, final** `terminal.exit`
  for the same fence with `reaped: true` and no `intent`, `error` or
  `exitCode`. The server keeps the session counted (`unreaped`, the browser
  already notified) until that exit or until the socket ends; it is never
  released on a timer. A second `reaped: false` is a violation. This is the
  only case in which a session has two exits.

An `UNKNOWN_OUTCOME` from the runtime open is reported as
`host_effect_not_issued`. A failed open leaves no PTY behind.

On a successful open the host sends `terminal.ready` before any output or exit
of that session, even when the shell exits before the open is acknowledged.
On the server, data or ready for a session that is not open counts as a
violation. An exit before ready fails the open.

## Sequences and flow control

`sequence` counts per session and per direction from 0, with no gaps:

- A duplicate (an already-seen sequence) is dropped. It delivers zero bytes and
  counts as a violation, so input is never replayed.
- A gap closes the session with `protocol_violation`. On an ordered transport a
  gap means the stream lost its integrity.

Flow control is a credit window per direction, independent of the command and
file channels:

- **Output.** The host has at most 8 output frames unacknowledged. The server
  acknowledges each frame it delivers to the attachment. Without credit the
  host stops reading the PTY, so the shell is back-pressured through the
  bounded queue.
- **Input.** The server has at most 8 input frames unacknowledged. The host
  acknowledges after `write_input` accepts a frame. Server-side queued input
  is capped at 64 KiB per session. Input past the cap is refused
  (`rate_limited`) and nothing is queued. Queued input is coalesced into
  frames of up to 16 KiB, so the queue holds at most 5 entries
  however small the browser's frames are.
- **Slow browser.** When the attachment's `bufferedAmount` plus the next chunk
  would exceed 1 MiB, the server **detaches** the attachment. It sends the
  explicit error `rate_limited` with intent `backpressure` and close code
  4401, then sends `terminal.close` so the host closes the PTY. The session
  never stays half open.

Terminal frames bypass the host socket's serialized receive queue. The server
validates and routes them synchronously against the host session's cached
authority ticket, with no per-frame IO. On the host, each tick forwards a
bounded number of events per session. A PTY flood therefore cannot delay
heartbeats, cancellation, expiry, probes or dispatch on either peer.
The reverse is not isolated: when the serialized queue reaches its
high-water mark (256 frames or 8 MiB) the server stops reading the whole host
socket until it drains to half, so terminal frames wait too. They are delayed,
never dropped, and the session is not closed.

## Authority on the terminal lane

Any authority change for the owner, host or credential (including every
global admin write) makes the cached ticket stale until it is revalidated.
Authorized traffic is never dropped while the ticket is stale.

- **Host → server.** Terminal frames are held in order. The hold is bounded:
  twice what a host honouring its credit windows can have in flight (352
  frames, 4 MiB per host socket). Overflow is a protocol error (1002).
- **Server → host.** Input stays queued (bounded at 64 KiB per session), and
  only the latest resize is kept. Opens are refused with `disconnected`.
- **Revalidation.** The server runs the same fresh revalidation the queued
  control path uses. It runs on the change's commit notification and when a
  frame is held.
  - `active`: the ticket is refreshed. Held frames are delivered first, then
    queued input and the deferred resize are sent.
  - A revoked or inactive credential: the socket closes with 4003. Every
    attachment gets 4401 `host_disconnected` with error `access_denied` (the
    host's authority ended, not the owner's sign-in), sessions and
    counts are released, and nothing held is delivered, so zero bytes go
    either way.
  - An infrastructure error: the socket closes with 1011, and attachments get
    `host_disconnected`.

## Single attachment and caps

| Bound                           | Value | Where                                                                                                                                          |
| ------------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Active sessions per sandbox     | 1     | server: a new open **replaces** the active one; the old attachment gets 4401 `replaced`                                                        |
| Live PTYs per sandbox           | 2     | both: the active one plus one still closing (a close can take ~12–17 s); on the host detached PTYs count too (see [On the node](#on-the-node)) |
| Sessions per host               | 8     | server per host socket; host per daemon process, counted until the reap is confirmed                                                           |
| Opens per host per rolling 60 s | 30    | both, at the dispatch boundary                                                                                                                 |
| Open must be answered within    | 30 s  | server: then closed as `expired` with error `timeout`                                                                                          |

The server checks capacity before replacing, and replaces only after the new
`terminal.open` has been sent. A refused or unsendable open never closes the
active session. A session stays counted until the host's final
`terminal.exit` with `reaped: true`, or until its socket ends. Both peers keep
the slot of a PTY whose reap is uncertain until the host's sweep confirms it
(see `terminal.exit`). A closing or unreaped session is never replaced again,
and opens interleaved with closes and exits can never exceed a cap: the check
and the insert are one synchronous step (interleaving test).

## Close intent and 4401

Close is explicit on the wire (`terminal.close` / `terminal.exit.intent`), so
a peer can tell an intentional close from transport loss. The intents are
`client`, `detached`, `replaced`, `backpressure`, `revoked`, `superseded`,
`protocol_violation`, `host_disconnected`, `expired`, `sandbox_stopped`,
`sandbox_destroyed`, `lifecycle_unconfirmed` and `shutdown`.

The server notifies the browser attachment exactly once. The notice carries
`code: 4401` (final, never retried as the same session), the intent or
`exitCode`, and an optional error. A resumable session's notice may carry
`reconnect {terminalId, graceMs}` instead: a v2 browser then gets
`reconnecting` and close code 4402, and may resume the PTY with a new ticket. The browser relay serializes it as the CloseIntent frame
and closes the browser socket with 4401. A host exit with intent `shutdown`
is the node daemon stopping, never the server (the server's own shutdown
closes its browsers first): its notice carries `error.code: disconnected`
when the host sent no error, so the browser says the node daemon stopped
rather than that the server restarted.

One close boundary. Every trigger ends a session through one idempotent
server path: a server-initiated close (browser loss or close, idle timeout,
replacement, backpressure, browser revocation, supersession, expiry, stop,
destroy, shutdown) sends exactly one `terminal.close`; the host's exit, or
the socket's end (host loss, host credential revocation), releases the count
exactly once. Repeated, concurrent or late closes have no further effect. On
graceful server shutdown each live session's `terminal.close` (intent
`shutdown`) is sent **before** the host socket is closed, so the host ends the
PTYs with `shutdown`, not `host_disconnected`. A revoked or lost socket is
sent nothing.

Attachment callbacks (`ready`, `sendOutput`, `bufferedAmount`) never unwind
into host frame handling. A throwing or unreadable attachment closes its
session as `detached`.

## No adoption, no replay; reattach

An in-memory terminal session never survives its host socket, and input is
never replayed:

- **Server.** Removing or replacing the host socket ends every attachment on
  it with `host_disconnected` (with error `access_denied` when its credential
  went inactive).
- **Reconnect.** The new connection's epoch differs, so frames naming old
  sessions are foreign.

Without `terminalResume` negotiated the host stops every PTY of a connection that
ends, and a reconnect always means a new PTY.

### Reattach

With `terminalResume` negotiated, a **sandbox** PTY can outlive its relay
connection. Host-target terminals never can: the daemon never detaches them
and the server refuses to resume them. Reattach is a new session for the same
PTY, never adoption of the old one:

- **Detach.** When the relay connection ends (relay drop, socket replacement,
  server restart), the daemon keeps each sandbox PTY detached for its grace
  (≤ 10 min): it keeps a 256 KiB output ring with sequence numbers and refuses
  input. Lifecycle closes (stop, kill, supersession, expiry) still apply at once.
- **Server side.** On host loss without a credential error, on graceful
  server shutdown, or when the binding re-read finds the host's connection
  epoch moved on (same owner; for example a new server process's boot sweep
  while this one still drains), a resumable session (v2 browser, sandbox
  target, node negotiated) ends with a reconnect notice instead of a final
  one, and the server sends no `terminal.close` for it. A fresh open still waiting for its
  answer, a closing session and every other intent end finally, as before.
- **Resume.** The browser mints a new one-use ticket naming the terminal
  (`sandboxTerminals.createSession({resume})`) and upgrades on
  `wssp.terminal.v2`. After the re-read (see
  [browser terminal authentication](./browser-terminal-auth.md#reattach)),
  the server sends `terminal.resume` under the **new** connection's fence:
  `fence.sessionId` is the terminal id, the operation id and epoch are new.
  It is sent only after the host's `reconcile.complete` (a sandbox terminal
  link exists only for a reconciled connection). The server refuses to resume
  an id that is still attached here (`state_conflict`).
- **Answer.** The daemon matches the id against its own detached table (same
  sandbox and generation) and answers `terminal.ready` with `outputSeq`: the
  sequence of the next output frame, at least the requested `nextOutputSeq`
  (more means the ring lost output; the browser is told). A missing or
  smaller `outputSeq`, or one on an open's or resize's answer, closes the
  session as `protocol_violation`. A daemon that no longer has the PTY
  answers `terminal.exit` with an error, which ends the browser finally.
- **Sequences.** Output continues at `outputSeq` (the server acks from
  there). Input sequences restart at 0 on the new fence; input queued on the
  lost connection is dropped, never resent, so nothing is typed twice.

#### On the node

The detached table is process-wide (`TerminalSlots`), so it outlives one
relay connection but never a daemon restart.

- **What detaches.** When a connection that negotiated `terminalResume` ends
  (for any reason but a daemon shutdown), each sandbox session that answered
  its open (or still owes the answer to a resume) is detached until
  `now + terminal_resume_grace`. An open still waiting for its answer, a
  session already closing, an exited session and every host-target session
  close with intent `host_disconnected`, as before.
- **While detached.** The pump keeps reading the PTY into the session's
  sequenced output ring (256 KiB; the oldest frames are evicted), so the shell
  is not back-pressured. Input queued for the old connection is dropped, never
  written later, and no input path exists. The pump itself closes the PTY at
  the deadline (intent `host_disconnected`) and re-checks the lease authority
  every 250 ms (lease expiry, lost binding, supersession, a freed login), so
  Lifecycle closes apply even with no connection. Every socket-loop tick of a later
  connection applies the same checks, and admitted stop, kill and newer
  generations, and daemon shutdown, close detached PTYs too. The PTY lifetime
  bound (4 h from the first open) is the runtime's and is never reset.
- **Matching a resume.** The id must name a detached PTY whose sandbox,
  generation and host equal the fence's, the connection's transport binding
  must equal the lease's, and the lease must be current and allow work. Any
  failure answers `terminal.exit` with error `state_conflict` (the same answer
  for an unknown id, so it reveals nothing) and leaves a still-valid PTY
  detached; a host target or an unnegotiated connection gets
  `unsupported_capability`, and a `nextOutputSeq` past anything the PTY
  produced gets `protocol_error`. A resume naming a session live on this
  connection is a duplicate (counted as a violation, never answered). A
  resume charges no open and no slot: it rebinds the existing PTY.
- **Answer.** `outputSeq` is `nextOutputSeq` when the ring still holds it
  (or nothing newer exists), else the oldest held frame. The PTY is resized to
  the resume's size (a failed resize keeps the old one; `ready` reports the
  size the PTY has). The ring's frames from `outputSeq` follow `ready`, within
  the usual credit window. A shell that exited while detached is answered
  with its exit (exit code or intent, with the resume's `requestId`).
- **Limit.** Detached PTYs count toward the per-sandbox limit of 2 live PTYs.
  An open that only that limit refuses evicts the oldest detached PTY of the
  sandbox (closed with intent `replaced`; it can no longer be resumed), never
  an attached one; the evicted PTY stops counting toward the sandbox limit at
  once but stays charged to the per-host and per-creator caps until its reap.
  A sandbox can therefore briefly have three PTYs, one of them closing.

On the host, these also close the sandbox's terminals:

- an admitted `sandbox.stop` / `sandbox.kill`, or a newer create/reconnect
  generation (intent `superseded`);
- a lease expiry, or a lost journal binding, found by a check on every tick
  (`expired` / `superseded`), and again on every input frame before any byte
  is forwarded.

Daemon shutdown closes every PTY through the runtime on a dedicated thread, then
waits up to 20 s for the pumps to confirm their reaps; slots held only by an
uncertain reap's sweep are not waited for. A requested graceful shutdown of
`wssp host run` first closes every terminal of the live connection with
intent `shutdown` and forwards their exits (at most 5 s), then closes the
socket normally (1000), and never reconnects. SIGTERM and SIGINT request it
(`apps/cli/src/shutdown.rs`); after the cleanup the daemon dies from that same
signal, so a service manager sees death by signal. Its bound end to end: the
5 s drain, the 20 s reap wait, then the expiry worker's join, which can hold
an in-flight graceful stop (up to 16 s) and its forced stop (up to 5 s); an
outer 60 s deadline ends a shutdown stuck elsewhere (for example in the
WebSocket handshake, which never observes the request). A second signal, or
that deadline, exits at once by the signal, without reaping the PTYs (each
setsid shell still gets SIGHUP when its master closes). Host helper children
(`incus` effects, `incus exec`, `kill`) run in their own process groups with
no terminal stdin, so a terminal's Ctrl-C reaches only the daemon. A service
manager's stop timeout should exceed 60 s; SIGKILL remains the one way to stop
the daemon without closing its terminals.

Every PTY call (open, read, write, resize, close and drop) runs on that
session's own pump thread, never on the socket loop.

## Private defaults and retained placement

Template revision defaults merge with sandbox create overrides into one private
snapshot. The terminal uses that same snapshot after stop/reconnect or daemon
restart, even if tags or pool membership later change. The 10.3 private-config
ACK precedes VM launch; terminal startup uses the gated raw PTY env handshake
before browser input/resize can reach the shell. No env values are added to
terminal metadata, receipts or diagnostics. Deliberate guest output remains
terminal data visible to its authorized viewer. The [SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants)
replaced old resources/tickets; there is no adoption of old sessions.

## Tracked command observer boundary

The 10.5 tracked pipe-command API adds no terminal frame or SDK PTY. Closing
this browser PTY closes its shell; command observer disconnect/abort only
detaches and sends neither EOF nor cancel. Host authority revocation remains a
separate teardown boundary. See the [filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits).

## Final host policy and bounds

`host.terminal-policy` reports current epoch, increasing sequence,
`hostTerminal`, `requireHostTerminalTotp` and persisted `policyRevision`.
`host.terminal-policy.raise` has only current epoch and request ID; it has no
lowering value or offline durable request. A dashboard raise is unconfirmed
until daemon persistence and a current-link acknowledgement/report. Local
access alone can enable host terminals or lower the proof requirement.

Host opens carry `hostPolicy:{policyRevision,proofRequired}` alongside the
host target. Guest opens refuse that tuple. Live policy decides proof mode;
a supplied false value never overrides it. The server binds required proof to
the durable factor fingerprint/observation and one-use ticket, and rechecks
policy/session/epoch before dispatch. Optional opens still need a live
non-impersonated owner session and one-use ticket.

The shared manifest pins eight total PTYs including closing, two reserved
for host and six for guests, at most three per guest creator. Opens remain
30/host/minute, with two reserved for host and 14 per guest creator. Host
idle input is ten minutes and maximum lifetime one hour; output/resize/ping
never resets input idle. Both peers enforce these reservations before
replacement and retain uncertain reaps as charged. Existing guest bounds,
credits, byte caps and teardown lanes remain in force. Local config defaults
to off/required; `wssp host config set-host-terminal on|off` and
`wssp host config set-host-terminal-totp required|optional` persist revisions. A bounded
socket-loop watcher fails closed and latches off until an explicit local enable.
Browser proof, tickets and the registered raise procedure are paired with browser
controls and the separately invoked operator checklist. Live qualification remains unverified.

## Consumer boundaries

Consumer boundaries preserve these invariants:

| Consumer                     | Required boundary                                                                                                                 |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Schema and deletion          | Preserve identity witnesses, mapped foreign keys, the usage-pool index and owner-row deletion classification.                     |
| Sharing graph and SDK        | Keep graph lifecycle, placement, SDK authority and invitation/signup/mail enforcement distinct.                                   |
| Host ledger and image census | Account for all owners while binding exact images and keyed workloads.                                                            |
| Transport joins              | Preserve creator fences, pinned transport locks and transport/workload identity equalities.                                       |
| Journal and private config   | Validate explicit transport/workload fields in `journal_key.rs` and `private_config.rs`; bind private-config MACs to the creator. |
| Creator IO and quotas        | Restrict IO and cleanup to the creator and enforce creator transfer and journal subcaps.                                          |
| Consent and tickets          | Re-read live consent, consume typed sessions and invalidate authority for either owner.                                           |
| Wire and version             | Pin typed control/binary codecs, fence fields and the shared sole-version predicate with parity tests.                            |
| Proof and policy             | Guard proof writers, enforce TOTP and default-off local policy, and watch live policy changes.                                    |
| Browser and projections      | Preserve foreign metadata redaction, browser consent and narrow owner-specific views.                                             |
| Lifecycle dispatch           | Keep outbox and access scans sandbox-scoped; preserve census/ACK/result identity lookups.                                         |
| Lock order                   | Take sorted pool locks before host locks, including owner/host deletion paths.                                                    |
| Derived authority            | Do not derive authority from sidecar data; guard mailbox/proof writers.                                                           |

The TypeScript contract schemas in `protocol.ts` pin fixture parity; they do
not themselves authorize service effects. Fake hosts and cancel-wire hello
fixtures carry the required policy tuple. JSON fixtures are covered by codec
parity tests independently of source inventories.

Lifecycle qualification also covers STOP admission with ERROR live resources,
bounded-discovery recovery, access timers only in the outbox-owning process,
and skipping the host lock only for an unplaced, pin-only record. Source
inventories alone establish none of these runtime or database properties; see
[the testing guide](../testing.md) for their evidence boundaries.

## Browser consumers and operator evidence

Guest and owner-host wrappers share a target-neutral lazy terminal panel/client.
Host pre-upgrade refusal never triggers classification mint; each manual retry
requires a fresh proof/ticket. Optional policy removes only OTP input. The detail
page uses current-link policy and displays raise confirmed only after persisted
ACK, preserving false/unavailable as unconfirmed. Host idle/lifetime timeout
notices are distinct from opening timeout. No browser timer duplicates daemon
limits. See the [explicit staged checklist](../operations/sharing-terminal-qualification.md).
It authorizes no deployment, Incus VM, production browsing or local-policy change
in implementation. Same integrated commit and original v5 settlement remain
operator gates; fake-wire/DOM tests do not prove live network isolation.

### Consumer inventory

The browser consumer inventory uses the expression
`sandboxPools|sandboxHosts|sandboxTerminals|SandboxTerminal|useTerminalSession|TerminalClient|resourceMode|poolIds`
in `apps/web/src` and `packages/api/src/routers`, TS/TSX only, excluding test
suffixes, routeTree.gen.ts and `**/tests/**`. Test support under `src/test` is
included, as in the original inventory. The recorded scan observes 131 lines in
27 files. Counts are bounds, not authority proof.

- Pools/sharing/image-target/accept components and create/template pickers consume
  bounded party-specific reads. Only owned hosts enter contribution/direct
  placement; shared members stay opaque. Pool owner views alone receive roster
  identities/usage. No shared row links to foreign host details.
- Credentials/sdk-keys and credential-rules consume independent poolMode and
  immutable selected grants. Host-credential/device/host-status consumers keep
  their owner-only paths.
- Host detail, guest wrapper, target-neutral panel, terminal hook/client/protocol
  and xterm-view share bounded transport/paste/lifecycle handling. Host attach
  mints once per explicit attempt; sandbox classification stays unchanged.
- The router inventory includes owner-only host allocation metadata and getHost,
  shared pool reads, cookie-only guest and host ticket consumers. Native/SDK
  retain strict contract decoders and the existing scope action inventory.
- Sandbox detail displays accepted grace and pinned loss deadlines, while foreign
  storage identifiers/names/markers remain null. The foreign-metadata projection inventory observes 32 lines in the
  same five files; raw native/SDK projection and DOM regression gates remain.
- Three `src/test` support files mirror those clients; they are not production
  authority. The host/invite supplemental search
  `hostTerminals|TerminalPanel|poolInviteToken|capturePoolInviteFragment` observes
  22 lines in 11 files: startup/router/auth capture, login/signup, acceptance,
  host/guest wrappers and the direct no-cache ticket hook.

No new public page, environment variable, authorization builder, schema relation,
relay version or SDK terminal surface is introduced by the browser controls.
Sharing management remains oRPC-only. Signup/mail, local policy and projection/proof
contracts retain service enforcement and real-PG coverage. Browser consent,
fragment/mode handling and locale/DOM behavior have separate qualification.
Live/hardware qualification remains separate.
