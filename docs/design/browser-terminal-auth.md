# Browser terminal authentication

This note defines how a browser attaches to a sandbox PTY. The relay half (the
fence, frames, flow control and the 4401 close) is the
[terminal relay contract](./terminal-relay-contract.md). The browser UI and terminal lifecycle use the same contract.

Sources: `packages/api/src/routers/sandbox-terminals.ts` (create),
`packages/api/src/sandbox/terminal-tickets.ts` (tickets and the binding
re-read), `apps/server/src/sandbox-relay/browser-terminal-upgrade.ts` (the
upgrade), `apps/server/src/sandbox-relay/browser-terminal.ts` (the attached
socket), and `packages/config/src/browser-terminal.ts` (constants shared with
the web client).

## Sharing and host terminal boundary

The server implements host proof/tickets and live revocation on relay protocol
1.0. Browser owner controls use the shared target-neutral panel;
operator qualification is a separately invoked checklist.
Server and daemons are deployed from the same release; see the
[journal version](./terminal-relay-contract.md#journal-version) rule.

The upgrade selects its consumer by path before consumption: host path
`/api/dashboard/hosts/:hostId/terminal/ws` accepts only
`wssp.host-terminal.ticket.`, while the sandbox path accepts only
`wssp.terminal.ticket.`. Both select `wssp.terminal.v1`, keep cookie-only
live-owner auth/Origin/CSRF/upgrade budgets and require one-use digest-only
30-second tickets. Relabeling a token cannot cross the separate stores.
Guest tickets pin transport owner and epoch. These tickets confer no API-key, MCP-credential or admin terminal
authority. Separate scoped host commands/files follow [ADR-006](./adr-006-agent-host-access.md).

Required host proof uses a fresh unused TOTP step for each attempt,
durable session/factor/watermark checks, observation cooldown and fail-closed
budgets. Optional mode removes only the code requirement. A changed policy
revision invalidates pending tickets/opens and live host PTYs. Dashboard
raises of the TOTP requirement are online-only and unconfirmed until the daemon persists/reports;
there is no server-owned raised flag. A fail-closed local watcher
applies hot off within two seconds; durable rereads and OR matching apply to
viewer-owner, transport-owner and host invalidation scopes.

`hostTerminals.createSession({hostId,rows,cols,code?})` chooses proof mode from
current authenticated local policy. `hostTerminals.raiseHostTerminalTotp({id})`
uses the live-owner gate and 30/minute write budget; offline requests refuse,
timeout/disconnect returns `confirmed:false` (displayed unconfirmed), and only a newer persisted
daemon report confirms the raise. `sandboxHosts.getHost` returns owner-only
metadata plus current live terminal policy (null when unavailable/deleting).

Required proof attempts consume 20/day then 5/minute per durable user before
comparison, fail closed, and never refund/reset on login, factor/session changes
or success. Exhaustion extends a durable 15-minute lock; ten invalid/replayed
proofs also lock. Both host and factor locks apply before calculation and mint.
The first observation of any factor, including an old one, commits a ten-minute
cooldown. Required tickets bind factor fingerprint, observation time and proof
time; optional tickets carry none of them and never clear proof state.

Proof writers use User `FOR NO KEY UPDATE`, then Session/factor share locks,
then H; OTP calculation and relay persistence IO run outside those locks. The
shared watermark rejects every already-used matching adjacent step. Successful
real auth enrollment/challenge advances the same maximum without changing
plugin login-reuse behavior. Both TOTP verification and URI retrieval have
independent cached/uncached session guards; only live pending enrollment is a
signed-in exception. After-hook failure strips accumulated cookies/tokens and
revokes any newly created session on HTTP and direct API calls.

Every pre-open/periodic read checks the durable active relay credential as well
as viewer/transport-owner policy. Scope matching is global OR viewer/transport
owner OR host. Host pending deletion holds terminal traffic during the write;
rollback hints trigger rereads without revocation. Host repair PTYs do not need
guest census readiness. Guest PTYs still require creator placement, generation,
lease, current pool usability and reconciled guest transport.

Host shells may coexist with foreign guests. Users of a pool with foreign
nodes must trust those node operators: an incus-admin host user can reach
every VM on the node. Dashboard restrictions and disabled host terminals
provide no isolation from local administrators. Contribution also accepts
foreign egress and budget usage. Withdrawal retains disks for the pool grace
(up to 30 days); host deletion waits for positive cleanup proof, possibly
longer on offline/dead storage. Those notices are shown in the sharing and
contribution UI.

Dashboard `sandboxHosts.lowerAgentHostCommands` and `lowerHostTerminal` are
live-owner-only. They durably request off and prevent new work immediately;
reconnect resends pending lowering until the daemon reports off. Lowering host
terminals invalidates tickets/opens and closes PTYs. There is no server procedure
to enable either host-access setting. This differs from raising the TOTP
requirement, which strengthens an existing terminal policy.

## Planes

The browser terminal is a **cookie-session** plane, like the dashboard. It is
separate from the other three planes:

- **SDK** (`/v1`, kind `API`, `wssp_sdk_`) has no terminal.
- **MCP** (`/mcp`, kind `AGENT_TOKEN` or `OAUTH_GRANT`) has no terminal. Both
  credential planes can use scoped host commands/files on an opted-in owned node.
- **Host** (`/ws/sandbox-host`, `wssp_host_` / `wssp_device_`) carries the PTY
  bytes, but a host credential never opens a browser terminal.

The upgrade refuses any `Authorization` header, any offered subprotocol that
contains a machine credential prefix, and the relay subprotocol. It refuses them
with `CREDENTIAL_PLANE` before it reads the cookie or touches a ticket. The host
endpoint ignores cookies and tickets. The shared WebSocket server selects a
subprotocol by path: the relay endpoint selects only the relay subprotocol, the
sandbox terminal endpoint selects `wssp.terminal.v2` when offered and
otherwise `wssp.terminal.v1`, and the host terminal endpoint selects only
`wssp.terminal.v1`.

## Two steps

1. **Create.** `sandboxTerminals.createSession({ sandboxId, rows, cols })` is
   a protected oRPC mutation. It runs under the same CSRF protection as every
   other dashboard procedure. Its gate is `liveOwnerSessionProcedure`, which
   checks four things:
   - the session user passes the required-2FA policy, and is not banned or
     being deleted;
   - the durable session row exists, is unexpired, and is not an admin
     impersonation (the cookie cache is not authority);
   - the sandbox belongs to the caller. Another owner's sandbox is `NOT_FOUND`;
   - the sandbox is `READY` on a host. Otherwise the call is a `CONFLICT`.

   The call is spend-bearing: a fail-closed per-user budget allows 20 per
   minute. It returns `{ path, protocols, expiresAt }`. With `version: 2` the
   first protocol is `wssp.terminal.v2`; with `resume` (v2 only) the ticket
   reattaches a detached terminal (see [Reattach](#reattach)).
2. **Upgrade.** The browser runs `new WebSocket(origin + path, protocols)`.
   The ticket is the second protocol, `wssp.terminal.ticket.<ticket>`. It is
   never in the URL, so it stays out of request logs, proxy access logs and
   browser history. The server never selects or echoes it.

## Tickets

| Property | Value                                                                                                                                              |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secret   | 32 random bytes, base64url (43 characters)                                                                                                         |
| Stored   | SHA-256 digest only (`sandbox_browser_terminal_ticket.tokenDigest`, unique)                                                                        |
| Bound to | auth session id, owner, sandbox, the sandbox's host and generation, PTY size; optionally the resume target (`resumeTerminalId`, `resumeOutputSeq`) |
| TTL      | 30 s (`BROWSER_TERMINAL_TICKET_TTL_MS`)                                                                                                            |
| Use      | once                                                                                                                                               |

Consume is a single `DELETE … WHERE "tokenDigest" = $1 RETURNING …`. The
following hold:

- Of any number of concurrent presentations, exactly one receives the row. A
  replay receives nothing.
- An expired ticket is burned and refused.
- Every refusal after the consume also burns the ticket: a wrong session, a
  wrong owner, a path naming another sandbox, a stale generation, a stopped or
  destroyed sandbox, a revoked session or an unavailable host.
- The ticket is never kept after the upgrade. A detached or closed terminal can
  never be resumed with the ticket that opened it. Reconnecting means a new
  `createSession`: a new PTY, or a new ticket naming the detached
  terminal, re-checked against its durable row.
- A resume ticket upgrades only on `wssp.terminal.v2`; offered on v1 it is
  refused `TICKET_INVALID` and burned.
- Session deletion (logout), sandbox deletion and account deletion cascade
  outstanding tickets away.

Checks that run before the consume do not burn the ticket: the plane, Origin,
rate-limit and subprotocol checks, and a missing cookie session.

## Two kinds of refusal

Refusals split at the point where a valid ticket has been consumed and matched
to the cookie session's user and the URL's sandbox:

- **Before that point: an HTTP refusal of the upgrade.** No WebSocket exists.
  A browser cannot read a refused handshake: script sees only an `error` event
  and then `close` with code **1006**. The status, headers and body are not
  exposed to it. The class still rides the `X-Terminal-Refusal` response
  header and the JSON body `{ error: { code, requestId } }`, for operators,
  curl and tests. The header never carries request data.
- **After that point: an accepted upgrade that closes with a readable
  CloseIntent.** The browser receives the CloseIntent text frame, then close
  code **4401**, before any `ready` frame. The frame carries a stable `intent`,
  or an `error.code` for a host refusal, and the upgrade's `requestId`. **No
  PTY is ever opened.** The PTY opens only after the post-upgrade re-read
  passes, and the host's `terminal.open` count stays unchanged in every such
  test.

### HTTP refusals (pre-upgrade), in order

1. The relay is enabled (`NOT_FOUND`, 404), and the request is a WebSocket
   upgrade (`UPGRADE_REQUIRED`, 426).
2. Plane separation (`CREDENTIAL_PLANE`, 401).
3. Exact-match `Origin` against the configured public origins (`BETTER_AUTH_URL`
   and `CORS_ORIGIN`). A missing, `null`, sibling, suffixed, port-changed or
   scheme-changed Origin is refused with `ORIGIN_REFUSED` (403).
4. Exactly `[wssp.terminal.v1, wssp.terminal.ticket.<ticket>]` is offered.
   Otherwise the result is `SUBPROTOCOL_REQUIRED` (400).
5. The cookie session is resolved. This is the same read `/rpc` makes before
   its limiter; a lookup failure counts as anonymous.
6. The `terminal-upgrade` rate limit: 30 per minute, fail-closed. It is keyed
   by user (`uid:`) when a cookie session exists, and by client IP otherwise.
   Cookie-less attempts behind a shared NAT therefore exhaust only that IP's
   bucket, never an owner's. The outcomes are `RATE_LIMITED` (429, with
   `Retry-After`) and, when the store is down, `SERVICE_UNAVAILABLE` (503).
7. A cookie session exists (`UNAUTHORIZED`, 401).
8. Atomic consume. The binding must equal the cookie session id, its user and
   the path's sandbox id. Otherwise the result is `TICKET_INVALID` (401). A
   database error here is `SERVICE_UNAVAILABLE` (503).

### CloseIntent refusals (post-consume)

The accepted socket runs the shared binding re-read (`checkBrowserTerminalBinding`) before
anything else:

| Cause                                                                                                      | CloseIntent                                                       |
| ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Session revoked, expired or impersonated; owner banned, deleting or failing forced 2FA                     | `intent: "revoked"`                                               |
| Sandbox `STOPPING` / `STOPPED`                                                                             | `intent: "sandbox_stopped"`                                       |
| Sandbox gone, `DELETED`, `RECLAIMING` or `HOST_LOST`                                                       | `intent: "sandbox_destroyed"`                                     |
| New generation or host, or another host owner, since the mint                                              | `intent: "superseded"`                                            |
| Host connection ended or moved on since the mint (new epoch, same owner), or not connected to this process | `error.code: "disconnected"`, no `intent` (a reattach retries it) |
| Lease expired                                                                                              | `intent: "expired"`                                               |
| Any other state, a read error or a read past its deadline                                                  | `intent: "lifecycle_unconfirmed"`                                 |
| Host not connected, at capacity, or a previous terminal still closing                                      | `error.code` (`disconnected`, `host_capacity`, …), no `intent`    |

Each frame is
`{"type":"close","code":4401,"intent"?,"error"?,"requestId":"<upgrade X-Request-Id>"}`.

### Rule for the web client

Host pre-upgrade refusal always ends the attempt. The browser must use manual retry with a
fresh code when required; it must never automatically mint a classification ticket.

- For guest terminals, a socket that closes **before `open`** (code 1006) is a pre-upgrade refusal,
  not a transport drop. Do **not** auto-retry it. Call `createSession` once to
  classify it: its oRPC errors (`UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`,
  `CONFLICT`, `TOO_MANY_REQUESTS`, `SERVICE_UNAVAILABLE`) are readable. If
  that succeeds and the new upgrade also closes before `open`, show a generic
  "could not connect" message and stop.
- A socket that opens and then closes with 4401 carries its reason in the
  CloseIntent frame. Classify by the frame's `intent` and `error.code`, never by
  the close reason string. A 4401 is final for that session: reconnecting means
  a new `createSession`.
- v2 only: a `reconnecting` frame and close code 4402 (or an abrupt close of
  an attached terminal whose id is known) start bounded reattach attempts
  ([Reattach](#reattach)); a refusal with
  `sandbox.terminal_resume_unavailable` ends them.

## After the upgrade

The binding is re-read before the PTY is opened, and no browser frame is acted
on before that. The re-read samples the owner and host authority ticket around
the read:

- If an owner or host authority change (a ban, a 2FA change, a forced-2FA
  policy write or a host change) is in flight or committed during the read,
  the read is **stale**. It is repeated. After 3 stale attempts the terminal
  fails closed with `lifecycle_unconfirmed`. Only such an observed authority
  change counts toward failing closed.
- A notification (see below) that arrives during a read is only a hint. The
  read is re-run once after it settles, but a hint never counts toward failing
  closed and never ends an open terminal. Before the PTY opens, it
  waits for a passing read that no notification raced, at most 5 raced reads
  (`BROWSER_TERMINAL_RACED_OPEN_READS`); then it fails closed with
  `lifecycle_unconfirmed` and no PTY is opened.
- Each read has a 5 s deadline (`BROWSER_TERMINAL_CHECK_TIMEOUT_MS`). A hung
  query fails closed with `lifecycle_unconfirmed` instead of suspending
  revocation checks for that socket.

The PTY is opened with the owner, host, sandbox, generation and size from the
server-side binding. Nothing comes from the browser.

The same re-read then runs:

- on a heartbeat every 15 s (`BROWSER_TERMINAL_REVALIDATE_MS`);
- on every owner or host authority commit: ban, unban, role, 2FA enable or
  disable, account deletion, and global forced-2FA writes;
- on every auth session row deletion of the terminal's **owner**: sign-out,
  session revocation and the admin ban or revoke flows. `packages/auth`
  resolves the deleted rows' owners from the adapter's `where`
  (`{ userId: { equals } }`), or by reading the matched rows' `userId` just
  before the delete (`{ token: { equals } }` on sign-out), and notifies each
  owner through `@wssp/db/session-revocation`. Only when the owners are
  genuinely unknown (an unscoped delete, more than 100 owners, or a failed
  read) does it notify every terminal. Thanks to the hint rule above, that
  fallback is harmless;
- on every committed sandbox write that changes `state`, `generation`, host
  placement or owner. `sandboxOutboxTransaction`, which every control-plane
  sandbox write runs in, notifies after commit.

Re-reads are coalesced: one is in flight per socket, and it is re-run once if
any number of notifications arrive meanwhile. Notifications carry no authority.
A missed one only delays closure to the next heartbeat.

| Re-read result                                                                                                                     | Close intent                                                                                                                                      | Scope                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Session row gone, expired or impersonated; user banned, deleting or failing forced 2FA                                             | `revoked`                                                                                                                                         | this socket                                                  |
| Sandbox `STOPPING` / `STOPPED`                                                                                                     | `sandbox_stopped`                                                                                                                                 | every terminal of the sandbox (`closeSandbox`)               |
| Sandbox gone, `DELETED`, `RECLAIMING` or `HOST_LOST`                                                                               | `sandbox_destroyed`                                                                                                                               | every terminal of the sandbox                                |
| Lease expired                                                                                                                      | `expired`                                                                                                                                         | every terminal of the sandbox                                |
| New generation or host, or another host owner                                                                                      | `superseded`                                                                                                                                      | this socket only (a terminal on the new generation survives) |
| Host connection ended or moved on (new epoch, same owner: a reconnect, or a new server process's boot sweep while this one drains) | v2 resumable: `reconnecting` + 4402, no `terminal.close` (the node detaches the PTY when its connection here ends); otherwise `host_disconnected` | this socket                                                  |
| Any other state, a read error or deadline, or 3 authority-stale reads                                                              | `lifecycle_unconfirmed`                                                                                                                           | this socket (fails closed)                                   |
| The resumed terminal's row fails the resume gate (closed, past its lifetime, cascaded away)                                        | `expired` with `error.code: state_conflict`                                                                                                       | this socket                                                  |

Every close sends the explicit CloseIntent text frame and then closes the
socket with **4401**. Graceful server shutdown closes every browser terminal
with `shutdown` before the relay is disposed. Once shutdown begins, a new
upgrade is refused (503 `SERVICE_UNAVAILABLE`) before its ticket is consumed,
and a socket whose upgrade completes after the browser terminals were
disposed gets CloseIntent `shutdown` and 4401 with no PTY.

Liveness. The server pings each browser socket every 20 s. A browser that
sends nothing for 60 s, no frame and no pong (a half-open connection, a
suspended laptop), is gone: its PTY is closed with intent `detached` and error
`timeout`. A watched but untouched terminal answers the pings and stays open.
The browser itself sends its CloseIntent best effort on `pagehide` and
`freeze`; a hidden tab keeps its terminal. A returning page (back-forward
cache restore, frozen tab resumed) shows the `pageLeft` notice, not "You
disconnected", and attaches anew, to a new PTY. A host exit with intent
`shutdown` (the node daemon stopping) reaches the browser as CloseIntent
`shutdown` with `error.code: disconnected`, shown as the node daemon having
stopped; a bare `shutdown` is the server's own restart. Every exit path (including a refused PTY open) clears the re-read
and heartbeat timers. The host also closes PTYs on its
own on stop, kill, a newer generation and lease expiry (see the
[terminal relay contract](./terminal-relay-contract.md)).

## Single attachment

A new attach for a sandbox **replaces** the active one, following the relay replacement rule.
The old socket receives CloseIntent `replaced` and 4401, and its PTY is closed
on the host. The new socket gets a new PTY. Input from the replaced socket
reaches nothing.

## Browser wire

| Direction                | Frame                                                                                                                                                                                                                   |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| browser → server, binary | input bytes, ≤ 16 KiB per frame (`request_too_large` otherwise)                                                                                                                                                         |
| browser → server, text   | `{"type":"resize","requestId","rows","cols"}` or `{"type":"close","requestId"}` (strict, ≤ 1 KiB; anything else closes with `protocol_violation`)                                                                       |
| server → browser, binary | PTY output                                                                                                                                                                                                              |
| server → browser, text   | `{"type":"ready","rows","cols"}` when the PTY is open or resized; on v2, the answer to an open or resume of a resumable terminal adds `"terminalId"` and `"outputSeq"` (the sequence of the next binary output message) |
| server → browser, text   | v2 only: `{"type":"reconnecting","terminalId","graceMs"}`, then close code **4402**: the PTY may be detached on the node for `graceMs`                                                                                  |
| server → browser, text   | `{"type":"error","code","requestId"?}` for refused input or resize (for example `state_conflict` before ready, `rate_limited` when the 64 KiB queue is full)                                                            |
| server → browser, text   | `{"type":"close","code":4401,"intent"?,"exitCode"?,"error"?,"requestId"}`, the final frame. `requestId` echoes the client's close request when there was one, and otherwise is the upgrade's `X-Request-Id`.            |

Input is coalesced into at most `ceil(64 KiB / 16 KiB) + 1` queued frames,
however small the browser's frames are. The browser attachment never
throws into the host relay. A failing browser transport becomes a `detached`
close.

## Reattach

Sandbox terminals on `wssp.terminal.v2` survive a relay reconnect or a server
restart when the node negotiated `terminalResume`
([relay contract](./terminal-relay-contract.md#reattach)). Host-target
terminals never reattach, and v1 keeps its final 4401.

**Durable row.** The first `ready` of a resumable terminal writes
`SandboxTerminalSession` (`sandbox_terminal_session`): the terminal id, owner,
auth session id, sandbox, host, generation and `openedAt`. Composite foreign
keys `(sessionId, userId)` → `Session` and `(sandboxId, userId)` → `Sandbox`
cascade, so logout, session revocation, sandbox deletion and account deletion
delete it. Every close that asked the PTY to close sets `closedAt`; a
`reconnecting` end does not.

**Resume gate.** `createSession({ sandboxId, rows, cols, version: 2, resume:
{ terminalId, nextOutputSeq } })` runs the ordinary
`liveOwnerSessionProcedure` gate and budget, then requires all of, against
the row (one primary-key read, one `CONFLICT`
`sandbox.terminal_resume_unavailable` for every failure, so it reveals
nothing about another session's terminals):

- the same owner and the same **auth session** (a revoked or expired session
  is refused; a revoked one has no row left);
- the same sandbox, host and current generation;
- `closedAt` is null;
- `openedAt` + the guest PTY lifetime (4 h) has not passed. The lifetime is
  computed from the stored `openedAt` and is **never reset** by reattaching.

The minted ticket carries the target. After the upgrade (unchanged: Origin,
limiter, one-use ticket, `binding.sessionId === session.id`) the re-read
checks the row again before any frame reaches the node, and on every later
re-read. Only then does the manager send `terminal.resume`, under the new
connection's fence. A terminal still attached on this server is never
resumed (`state_conflict`).

**Budgets.** Each reattach attempt costs one mint point (20 per 60 s per user,
fail-closed) and one upgrade point (30 per 60 s). Neither is raised. The web
client makes at most 3 attempts per detached terminal, the first after a
jittered 1–5 s and the others spread across the grace. Tabs take turns
through an exclusive Web Lock (`navigator.locks`, constant origin-scoped
name `wssp.terminal.resume`, no user data) held for one attempt only, so
exactly one tab reattaches at a time; without Web Locks a random 0–2 s
backoff is the best-effort fallback. Each attempt is bounded (15 s from
holding the turn to `ready`), and an independent deadline at the end of the
advertised grace aborts whatever is pending (turn wait, mint request,
upgrade), releases the turn, ignores late answers and shows "Attach again". About 15 tabs fit both budgets after a deploy; beyond
that the client shows "Attach again", which opens a new PTY. The node's own
open limits still apply (14 opens per minute and 3 live guest terminals per
creator on one node).

**Cleanup.** `sandbox-terminal-session-sweep` runs on the server every 10
minutes: it deletes, in `take`-limited batches within a 30 s budget, rows
closed more than an hour ago and never-closed rows past the 4 h lifetime.

## Redaction

The ticket appears in exactly two places: the `createSession` response, and
the browser's `Sec-WebSocket-Protocol` request header. It is not in any URL,
log line, error body or response header, and the database stores only its
digest. The upgrade's only log line names the error class.

## Web client

Sources: `apps/web/src/components/sandboxes/sandbox-terminal.tsx` (the card on
the sandbox detail page), `apps/web/src/hooks/use-terminal-session.ts` (its
lifetime), `apps/web/src/lib/terminal-client.ts` (one attachment),
`apps/web/src/lib/terminal-protocol.ts` (sizes, URL, frames, classification)
and `apps/web/src/lib/xterm-view.ts` (the lazily loaded xterm view).

- **Explicit attach.** Nothing connects when the page loads. The owner presses
  Attach; only then is xterm loaded (a dynamic `import()`), measured, and a
  ticket minted. `pnpm check:lazy-xterm` (CI, after the build) fails when
  xterm or its stylesheet is in the initial chunk or any route chunk.
- **Ticket.** `createSession` is called on the oRPC client directly, not
  through TanStack Query, so the response is never in a query or mutation
  cache. The ticket lives in a local until the `WebSocket` is constructed.
  It is never stored, never in the URL and never in the DOM.
- **URL.** `wss:` derived from `VITE_SERVER_URL`. Plain `ws:` is used only
  for loopback hosts. Any other `http:` server URL refuses to connect.
- **Refusals.** A close before `open` follows the rule above: one
  `createSession` to classify it, then at most one more upgrade with that
  fresh ticket. After `open`, the end is classified by the CloseIntent
  frame: `intent` first, then `error.code`, then `exitCode`. The close
  reason string is never read. `unsupported_capability` (a sandbox whose
  lease records no guest identity, for example a malformed lease) has
  its own message that suggests a reconnect or a stop and start. An
  `expired` intent that carries `error.code: "timeout"` is the host not
  answering the open (the sandbox still runs); it gets its own message, not
  the lease-expiry one.
- **No automatic reconnect.** Every end is final and shown with its reason.
  "Attach again" is a new session with a new ticket and a new PTY.
- **Detach.** The control frame `{"type":"close","requestId"}`, then
  `close(1000)`. Unmounting the page (Strict Mode's simulated unmount
  included) does the same, removes every listener and disposes xterm.
- **Resize.** Sizes are clamped to 1–512 rows and 1–1024 columns. A
  measurement that is not finite is never sent. A resize is sent only after
  `ready`, only when the size changed, debounced by 100 ms. A resize the
  server refuses (matched by its `requestId`) shows no warning; the current
  size is sent again on the next `ready`.
- **Input.** Binary frames of at most 16 KiB. When the socket's
  `bufferedAmount` would pass 1 MiB, the client detaches with the
  `backpressure` notice instead of queueing more (the server's own
  slow-consumer detach shows the same notice). A paste is all-or-nothing:
  one whose encoded size, plus the 12 bytes of bracketed-paste markers xterm
  may add, exceeds the server's `inputQueueMaxBytes` (64 KiB) is refused with
  a message and nothing is sent, and "Pasted" is never shown when the paste
  itself ended the session, nor once the session has ended or been taken over
  (a copy/paste result is shown only in the status it was reported in). Bracketed-paste markers inside the clipboard text (`ESC[200~`,
  `ESC[201~` and their 8-bit C1 forms `U+009B 200~` / `U+009B 201~`) are
  stripped first, in one linear pass; clipboard text over four times the cap
  is refused before it is scanned.
- **Untrusted output.** OSC 8 (hyperlinks), OSC 52 (clipboard), OSC 1337
  (iTerm2 file transfer), OSC 5113 and 5522 (kitty transfer and clipboard)
  are swallowed by parser handlers that shadow xterm's own. The link handler
  is inert, and no web-links addon is loaded, so output can never write the
  clipboard. Native copy, cut and drop events on the terminal are cancelled:
  the Copy button is the only way out. Native paste (Ctrl/Cmd+V, the context
  menu) works, but xterm never reads it: the view
  cancels the event in the capture phase and hands its `text/plain` to the
  client, which applies the Paste button's stripping, cap and outcome
  message. Output is kept only in xterm's bounded scrollback
  (2000 lines) and is gone when the terminal is disposed.
- **Layout.** The terminal box is `min(28rem, 50svh)` tall and clips both
  axes. It sits inside the page's existing scroll container, below the
  permanent header, and adds no navigation.

## Pools, reset and environment continuity

A sandbox retains its exact revision and origin pool for stored resource
authorization; host authorization uses its current host (or, while offloaded,
the host it last ran on). SDK grants do not authorize browser attachment: the
owner session and one-use terminal ticket still gate every upgrade. No pool
picker or foreign pool-ID lookup is part of this flow. Pool deletion or member
removal never moves a live terminal to another host.

Private env snapshots survive ordinary stop/reconnect. Values are not included
in ticket responses, sandbox detail or toasts. Browser input is withheld until
the host's raw PTY environment handshake completes. See
[terminal behavior](../guide/terminal.md) and
[SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants).

## Browser secret lifetime

Host detail is owner-only and renders current-link policy. Required code fields
use TanStack Form/Zod/TextField with one-time-code autocomplete, clear on every
attempt and remount on policy revision change. Required and optional attaches
call the ticket client directly, outside Query caches. A host refused upgrade
ends immediately; only manual retry mints another code-bound ticket. Guest
pre-upgrade classification is retained. The shared panel keeps lazy xterm/CSS,
safe paste/OSC/clipboard handling and disposable scrollback. Host idle/lifetime
expiry is displayed without another browser timer. See
[operator qualification](../operations/sharing-terminal-qualification.md).
