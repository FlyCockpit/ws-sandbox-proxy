# ADR-003: Host enrollment

## Status

Accepted; host access statements amended by [ADR-006](./adr-006-agent-host-access.md) (2026-11-12).

## Context

Sandbox workloads run on operator-controlled Linux hardware. The control plane
must pair hosts to accounts without opening inbound firewall ports.

## Decision

- Model paired hardware as `SandboxHost` with connection inventory fields.
- Issue enrollment secrets as `HostToken` rows (hashed at rest, revocable,
  optional host binding). Prefixes are `wssp_host_` and `wssp_device_`.
- Node daemons connect outbound over mutually authenticated WSS to
  `/ws/sandbox-host`.

## Consequences

- Host operators are in the trust model for their hardware.
- Tokens are distinct from browser cookie sessions and from SDK keys
  (`wssp_sdk_`). Credentials never authorize another plane.

## Active authority and deletion

An upgraded connection is only a candidate identity. The server rechecks the
credential, owner ban/2FA policy, host ownership and owner deletion state at hello,
heartbeat, dispatch, every upload/stdin/download chunk, and inbound results.
Host-token expiry also has a connection timer; device credentials have no expiry.
Revocation, expiry, ban and owner deletion close the socket with **4003** and
reason **`credential_inactive`**. Transient revalidation failures close with
**1011** and reason **`internal_error`**; the daemon treats that as retryable,
not a terminal credential failure. Upgrade 401/403 remain terminal credential
failures with no credential material printed. `wssp host run` exits **4** for a
terminal credential failure (4003, upgrade 401/403) and **5** for 1011, so a
supervisor can branch on the status. Unban permits a new connection with a
still-valid credential. A revalidation whose authorization ticket was invalidated
by an overlapping change is _stale_, not inactive: it neither closes nor
authorizes; the overlapping change's own post-commit revalidation decides.

Host deletion tombstones block only new admission (sandbox create, template
create, host-token enrollment, device replacement) with CONFLICT "Sandbox host is
pending deletion.". Create-intent device enrollment for a slug still held by a
tombstoned host is refused by the per-owner slug uniqueness ("A host with this slug
already exists.") until the host row finalizes. Owner kill, stop, reconnect, timeout, command, file,
signal enqueues take the same ownership/epoch lock without the
tombstone check. Host credentials stay valid for heartbeat, destroy/stop dispatch,
results and receipts until the host row finalizes. Finalization is structural:
every write that can clear a host-deletion blocker (live-slot release, DELETED
detach, operation terminalization) notes its host, and the
sandbox transaction runs `tryFinalizeTombstonedHost` as its last step.

The supported single server process invalidates authorization tickets before a
credential/account mutation starts, blocks tickets until commit or rollback, then
revalidates matching sockets and closes only those that fail revalidation. Each
effect checks its ticket immediately before socket IO. Database credential state
is re-read at active boundaries and after process restart. Unsupported
out-of-process SQL writes have no synchronous close notification; active
boundary reads still deny them. Multi-replica authority requires a separate
distributed design.

Socket removal advances the epoch and preserves operation, placement and lease
receipts. It does not prove a guest stopped or disappeared. Existing cancellation,
unknown-outcome reconciliation and lease cleanup remain responsible for effects.
After a transport loss the host may adopt, before `reconcile.complete`, an exact
attempt it journaled on an older epoch (`operation.adopt`): a dispatch-equivalent
re-bind under the dispatch lock order (K → H → S → O → outbox, no owner lock),
refused for terminal, superseded, re-generationed, unplaced or lease-expired
work and, for unissued work, by the processor's re-claim gates. Adoption never
creates an attempt or changes a payload; unadopted work is reconciled as above.
Host/account deletion uses **live state** to identify blockers.
An account with
sandbox hosts, sandboxes not DELETED, unfinished operations, or unprocessed
outbox events is **refused** with **CONFLICT** naming the blocker kinds; the user
removes resources while credentials still work. Everything else is a receipt and
is deleted with the user row in the finalizing transaction: **all** templates
(active or retired), DELETED sandboxes, terminal operations, processed outbox
events, SDK keys, host tokens and the Better Auth rows. Templates are never
blockers: logical identities, revisions, tags, availability, private configuration
and placements are retained history. The finalizer clears current placement
pointers and dependent rows after live-resource checks pass. One
exported table (`ACCOUNT_DELETION_CLASSIFICATION` in
`packages/db/src/account-deletion.ts`) classifies every model with a relation to
User; account deletion derives its blocker checks and finalizing deletes from it,
and inventory tests (Prisma schema and live FKs, each cross-checked against the
other) fail on an unclassified model. There is no template-delete
API. Concurrent child inserts during finalization surface the same **CONFLICT**, never
a 500; the kinds are re-read under the owner lock in a
fresh transaction, and when none remains the message says the account's
resources changed and asks for a retry. Host tombstones block only admission; cleanup
dispatch stays authorized until the host row finalizes after the last placement
release. Every owner-row-creating transaction takes a shared owner
lock and rejects in-progress account deletion. Better Auth's `/delete-user`,
`/delete-user/callback` and every `/admin/*` plugin endpoint are disabled; oRPC `users.remove`
is the only deletion path, and the `user.delete.before` hook (defense in depth)
refuses with a Better Auth `CONFLICT` naming the blockers.

The native `/v1` HTTP mount authenticates SDK keys per request through
`authenticateSdkKeySecret`, including its owner-scoped tickets and durable
revalidation. Cookies and query credentials do not authenticate it; see the
[native HTTP boundary](./native-http-contract.md).

Every SDK-reachable router service function is built by one wrapper
(`serviceProcedure`): entry authorization, then a scoped read ticket, then the
body; the ticket is checked on both the resolve and the reject path, so a
mid-request revoke turns any result or data-dependent error into FORBIDDEN
"Authority changed during request."

Host OS users and root are trusted operators. Guests have neither control-plane
credentials nor a mount of the host journal. Journal checksums detect corruption;
they do not authenticate against malicious writes by the host OS uid. That uid
can read device credentials, replace daemon code, and control Incus. A MAC derived
from the same uid's credential would not enforce a stronger boundary, so journal
MACs are not introduced here.

The relay carries lease deadlines, actions and revisions on create, reconnect and
renew. The host persists the accepted decision before boot or renewal ACK;
lease checkpoints survive receipt confirmation and are repaired from durable
receipt decisions on restart. The server records effective lifetime only from
an exact operation-bound ACK, without regressing an acknowledged revision.
The independent host expiry service survives credential socket rejection and
ordinary disconnect. It uses monotonic elapsed time plus durable wall deadlines,
revokes activity before a bounded graceful stop and the forced stop/destroy
(graceful first, once per lease arm and at most 16 s, then force always
follows), and retries unresolved actions with bounded backoff. Startup reconciles overdue journal leases before hello or ready;
Incus boot metadata cannot override a renewed journal deadline. Incus autostart is
disabled. Power loss pauses enforcement until service restart. See the
[host service example](../../apps/cli/README.md#linux-service).

Every reconnect replays a complete, paginated, acknowledged inventory census
(relay protocol 1.0, `ws-sandbox-proxy.relay.v1`). The server converges stopped/deleted state and releases capacity
only from that census or an explicit not-found entry, never from socket loss;
a host-confirmed expiry is recorded as `hostExpiryConfirmedAt`/`hostExpiryRevision`
only when the host's own deadline timer latched it (`timerExpired`), whichever
operation settles the end state. Startup waits a bounded time for overdue
expiry; an action still failing is published (`expiryFailure`, and
`sandbox.expiry_status` while connected) rather than blocking the census, and
the server shows it as ERROR `expiry_failed` with the slot still held (also
from STOPPING/RECLAIMING when it queued the expiry offline; that pending
stop/kill is settled by the host's later confirmation, never redispatched). The
host's local live-resource hold is freed by its own completed, generation-fenced
expiry, without waiting for a reconnect, and completed arms are published over
`sandbox.expiry_status` even when no attempt ever failed. An observation that
names a lease arm older than a since-succeeded create/reconnect is fenced off
from every lifecycle inference, and a completed expiry of the current arm also
frees live resources an uncertain cold reconnect left held on a STOPPED row. Silence
beyond the held bound is deferred, never concluded; converged rows leave the
scan, so each replayed census reaches the remainder, and silence after the
final page converges in bounded chunks.
Census progress is not durable: a restart replays it and every write is an
idempotent compare-and-set. An identity contradiction (unknown, foreign or
deleted sandbox; generation or lease revision the server never issued)
quarantines the host until a clean census completes.

## Host drain

A host's durable `draining` flag is authoritative; daemon `schedulable` remains
advisory. Drain refuses new creates, STOPPED cold reconnects/resumes and template
registrations with HTTP 409 / `sandbox.host_draining`. The admission check and
flag change serialize on the same host row inside their transactions. Previously
accepted creates can still boot after drain; replay does not admit new work.

Existing guests, commands, files, warm attachments, lease renewals and relay
sessions continue. Drain has no deadline and never sends stop/kill. Token minting
remains available. Undrain restores admission; it does not revive stopped guests.

Host reads expose `draining`, `liveSandboxCount`, and `drained`. The count uses
live capacity reservations, including pending boots and uncertain outcomes, until
confirmed stop/deletion or allocation refusal releases the live resources. `drained` is
exactly `draining && liveSandboxCount === 0`. An idle host with drain off is
not drained. Zero live guests
does not bypass host deletion's retained-disk, placement or unfinished-work checks.

The owner uses protected oRPC `sandboxHosts.setHostDraining({id, draining})`.
It is owner-scoped and session-only; SDK scopes do not authorize this drain API.
Separately, `hosts:execute` permits commands on an opted-in owned node; those
commands run with the daemon user's Incus-admin power. See [ADR-006](./adr-006-agent-host-access.md).
The host CLI uses `POST /api/sandbox-host/drain` with the same strict JSON body
and `Authorization: Bearer wssp_host_…` or `wssp_device_…`. A credential can change
only its bound host (including among hosts of the same owner). This endpoint is
outside `/v1`, ignores cookies, grants no CORS access, has a 1 KiB body cap and
uses the fail-closed authentication IP budget. Success returns
`{id, draining, liveSandboxCount, drained}` with `Cache-Control: no-store`.
Revoked/expired/owner-policy-blocked credentials return 401; foreign or missing
hosts return 404. Production HTTPS terminates at the configured proxy.
Committed changes log `sandbox.host_drain` with owner, actor kind, host and flag;
these metadata-only audit logs use the deployment's normal log retention.

## Host dashboard edits and daemon metadata

The owner's `label` is authoritative. A registered hello never overwrites
it with the daemon's `--label`; it records only the daemon-reported runtime
(`daemonRuntime`: `FAKE`, `INCUS_KVM`, `UNSUPPORTED`) and `daemonVersion`, which
are display metadata and never admission inputs.

`sandboxHosts.updateHost` edits the label only. The node owner configures RAM,
aggregate vCPU and local storage caps/drain in node config (CPU/RAM also accept
independent flags), then reconnects. Hello/admission binds immutable static
capacity and pool identities to a connection epoch; health updates cannot rewrite
that tuple. Current admission/census/heartbeat/key/source evidence is required
for new placement. Server and local daemon both reserve charged RAM/vCPU and
retained disk before effects; `liveCount` is accounting only. See
[host budgets and storage](../guide/hosts.md#capacity-drain-and-deletion).

The Hosts page treats a host as connected only while `status` is `CONNECTED`
and the last heartbeat is at most 30 seconds old (the daemon beats every 5 s);
it re-renders at that deadline even when refetches fail. It never holds a host
credential. Owner-only detail offers an explicit host terminal when locally
enabled, agent-policy lowering, queued-command review and metadata-only audit.
Scoped credentials can execute commands and use host file tools on an opted-in
owned node under [ADR-006](./adr-006-agent-host-access.md). Delete is offered only with
zero live sandboxes; the server still decides and may leave the deletion
pending until retained disks, transfers and unfinished work are gone.

## Host credentials page

The owner lists, mints and revokes host tokens, and lists and revokes device
credentials, on the dashboard's Host credentials page. `sandboxHosts.listHostTokens`
and `sandboxHosts.listDeviceCredentials` are cursor-paged (newest first, revoked
rows only with `includeRevoked`) and return metadata plus a summary of the
credential's host (slug, label, connection status and timestamps), never
`secretDigest`. `sandboxHosts.revokeDeviceCredential` revokes one active device
credential of the caller (a foreign or already revoked one is 404) through the
same authority change as a host-token revoke, so a live connection that used it
closes with 4003; the host row, its sandboxes and receipts are untouched.

A minted secret is returned once and held only in the page's component state:
the page calls the procedure directly rather than through a query or mutation
cache, writes nothing to storage, the URL or logs, and drops the secret when the
dialog closes, the page unmounts or the browser fires `pagehide`. A mint that
completes after the dialog closed is never shown and is revoked at once. After
any revoke the page refetches its lists and the Hosts list, and refetches every
15 s, so the revoked host's status catches up with the relay close.

## SDK-key mint rules and the Templates page

`sdkKeys.create` refuses, with a stable 400 `data.code`, two drafts the SDK-key
page also refuses before submitting (both use the same functions in
`packages/api/src/lib/sdk-key-rules.ts`): a scope that authorizes no service
action given the other selected scopes (`sdk_key.unusable_scopes`, for example
`operations:cancel` without a mutation scope, or `commands:read` without
`operations:read`), and a revision without a pending or available association
on a selected owned host (`sdk_key.template_not_on_selected_host`). Exact revision
and host ownership is checked before mint. Host and revision pickers use bounded
pages. Retained host grants also join the host to the key's owner.

The Templates page lists logical identities, immutable revision pages and
per-host availability separately. Registration creates logical plus first
revision; append verifies an image on an allowed host and explicitly updates
latest. It grants the new revision to no existing ALLOWLIST key. Invisible
logical targets return 404 before WSS or uniqueness checks. Session-only tag,
revision retirement and archive controls affect future creates; existing
sandboxes keep their pinned revision, disk and private defaults. The detail
reader uses `getTemplateRevision`, including retired revisions. Verification
errors expose only catalogued constants. See [template operations](../operations/templates.md)
and [SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants).

## The Sandboxes pages

`sandboxes.list` takes `status: "active" | "deleted" | "all"` (`active` is every
sandbox that is not DELETED; the dashboard requests this history explicitly). `list` and
`getSandbox` return each sandbox with its host's connection summary (including
`draining`), the template revision it was started from (`id`, `slug`, `label`,
`retiredAt`) and its latest lifecycle receipt (`CREATE_SANDBOX`, `KILL_SANDBOX`,
`STOP_SANDBOX`, `RECONNECT_SANDBOX` or `RENEW_SANDBOX_LEASE`: id, kind, state,
error code and timestamps only). The `/v1` DTO maps only the sandbox fields.

The pages show only what the server reported: an action never turns a sandbox
READY, STOPPED or DELETED in the browser, a QUEUED or UNKNOWN_OUTCOME receipt
stays visible, and a sandbox whose host is not heartbeating carries an
"out of date, requests wait for the host" warning. Every lifecycle action and
create is one idempotency key per intent: a retry after a lost response (or a
double submit) resends the first key and exact input, so the server replays it;
a definite refusal forgets the key. The browser retry signature binds the
action, sandbox ID and body, not a newly read generation or lease revision;
otherwise a lost response could accidentally become a new request. Stop is confirmed and keeps the disk; destroy needs the typed sandbox
ID. Renewal shows the requested term next to the host-acknowledged one, which
stays "not acknowledged" until the host acknowledges it. Detail reads the
template revision through `getTemplateRevision`, so an archived one still shows.

File transfers use only the session cookie against `/api/dashboard/transfers`
and `/api/dashboard/operations/{id}/content` (same-origin; no SDK key or bearer
header). Uploads read, hash (incremental SHA-256) and send one 1 MiB chunk at a
time, refuse a file over the 1 GiB product cap before any request, resend a
chunk or commit whose response was lost, and abort the reservation on any
failure or cancel before commit. A download is a `readFile` capture followed
until it succeeds, checked with `HEAD`, then saved by the browser from the
content route.

## The Operations pages

`sandboxes.listOperations` (session only; `/v1` has no list) pages the owner's
operations newest first (keyset on `createdAt`, `id`; indexes
`(userId, createdAt)` and `(sandboxId, createdAt)`), filtered by `sandboxId`,
`kind` and `state` (one state, or the groups `active` = still in flight including
CANCEL_REQUESTED, `settled` = everything else). A row is an explicit allowlist:
id, sandbox ID and state, kind, state, generation, the public error code
(unknown stored codes read as `internal`), timestamps, and for RUN_COMMAND the
exit code, projected by a second read restricted to that page's RUN_COMMAND
rows. Rows never carry the request (command, argv, env, stdin, guest paths), the
stored `result` JSON, the idempotency key or hash, or output bytes.
`sandboxes.getOperationView` adds the host's error message (at most 1,024
characters), the sandbox (`id`, `state`, `generation`) with its host's
connection summary, and the output expiry time.

The detail page polls the operation only while it is in flight. Command output
is read through `getCommandOutput` by one loop per open page, one request at a
time, following `nextCursor`; the browser keeps at most the server's own head
and tail budget (256 KiB + 768 KiB) and shows every dropped range as a gap.
Output is rendered as text nodes only: C0/C1 controls (so every ANSI/OSC escape)
become visible stand-ins and bidi controls a visible `⟨U+202E⟩` tag. After the
operation settles the loop keeps reading until the completion watermark, for a
bounded number of polls, then says the output may be incomplete. A request that
does not answer is aborted and reported as stalled; failures retry with
backoff and keep the text shown; OUTPUT_EXPIRED is explained with the status and
exit code intact. Leaving the page aborts the read in flight and stops every
timer. The sandbox's state on the page comes only from the operation read, so a
late chunk never changes how a deleted sandbox is shown.

Cancel uses the existing `cancelOperation` (confirmed first). The page shows
the server's answer: a queued command is CANCELLED at once, running work stays
CANCEL_REQUESTED ("waiting for the host", or "delivered when it reconnects"
while the host is offline) until the host acknowledges, and an operation that
finished first keeps its own result. The browser never shows CANCELLED before a
read reports it.

## Transfer storage admission

Reserved server transfer content also blocks host and account deletion until
unlink and directory sync succeed. Terminal transfer receipts are deleted with
the account; the content reservation, not the terminal label, decides liveness.
Spool services use the shared live SDK authorization gate for their file scope,
keep the originating key identity, and check authority tickets on both success
and failure. Their metadata commits acquire owner/key, host and sandbox fences.
Upload HTTP adapters are available under `/v1/transfers` (SDK keys) and
`/api/dashboard/transfers` (protected cookie sessions with same-origin mutations).
Each chunk and replay rechecks the originating authority. Download HTTP adapters
(`/v1/operations/{id}/content` and `/api/dashboard/operations/{id}/content`)
serve a capture only to the credential that requested it and recheck that
authority on every request and every chunk read.

## Administrative control plane

All administrative oRPC procedures derive from the registered hidden admin builder.
Missing/revoked/expired/impersonated sessions, absent/deleting/banned users, wrong
roles, unverified email and unmet required-2FA policy return `NOT_FOUND`.
The gate reads durable session and user state and checks again before returning
cross-owner metadata. Better Auth's entire HTTP admin plugin surface is disabled,
including impersonation, password resets and session-token listing. Internal
server-side invite creation remains available behind `users.invite`.

DB-only role, archive, restore and remove writes use `adminUserWriteProcedure`
with owner-scoped authority invalidation; settings use `adminWriteProcedure`
with global policy invalidation. Both share one boundary:
transaction-scoped PostgreSQL advisory lock 490049, then actor user/session locks,
then target user locks. Authority is checked again after acquiring the lock.
Account finalization uses the same governance lock before its owner lock; no
network IO occurs inside this transaction. Demotion, ban and deletion preserve at
least one verified, unbanned, non-deleting admin role. Self-demotion, self-archive
and self-delete are refused. A ban atomically removes browser sessions and sets a
durable permanent ban, using authority invalidation to close active relays;
it does not delete standing credentials or dispatch commands. Restore clears the
ban but cannot recreate sessions or revive explicitly revoked credentials.
An offline host remains a deletion blocker; rejection leaves credentials usable.

`adminObservability` exposes fixed counters and cursor-paged hosts, sandboxes and
operations, filtered by bounded owner/resource IDs and state. It selects only
IDs, state, timestamps, generation and host capacity metadata. User management
retains its existing bounded users list. Maintenance jobs expose state/timestamps/
attempt counts, never payloads, results, stack traces or raw failure text. No admin
procedure exposes guest commands, output, file content, arbitrary resource JSON,
or user credential values. Lease-supervisor and egress counters are reported separately.

`settings.adminGet` exposes effective signup/force-2FA policy and an explicit
read-only command, output-retention and transfer-limit projection. `settings.update` accepts only `signupEnabled`,
`force2faPublicUsers`, and `force2faInternalUsers`, with boolean string values.
Enabling force-2FA requires the acting admin to be enrolled. `signupEnabled` uses
`SIGNUP_ENABLED` as its absent-row default; explicit database settings take effect
on the next signup or app-config read. Bootstrap/invite exceptions are unchanged.

## Pool and template dashboard completion

Pool pages live under the existing authenticated locale/dashboard layout and
navigation. Create uses a Dialog, edit a Sheet, member detail a Dialog and
remove/delete a typed-confirmation AlertDialog. Pool/member/host/revision
pickers use bounded cursor pages. Template choice is independent of placement:
logical latest resolves once, exact revision pins the selected ID, and the
server alone decides compatibility and capacity. Revision tag/association edits
use a Sheet; availability distinguishes verified from pending evidence.

The SDK key page displays exact revision/pool IDs and selected-host association
status. A pooled ALLOWLIST key needs the pool, current host and exact revision
grants together. See [minting SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants).
Create envs remain transient browser form/mutation state: safe settlement clears
them; uncertain requests retain exact input for replay, with no browser storage,
values in toasts or detail readback. The sandbox detail shows safe retained
pool/revision identity without querying a foreign resource.

## Integrated sharing and terminal policy

Enrolled credentials authorize only their host transport owner/host/current epoch,
never a sandbox creator's identity. Owner-only host detail reports current-link
terminal policy; absent policy is unavailable. Local allow_host_terminal defaults
off and host_terminal_require_totp defaults required. Dashboard raises
of the TOTP requirement are online-only with persisted ACK. Host-access
enablement remains node-only; owners can turn off host terminals and agent host
access in the dashboard, with durable pending lowering replayed on reconnect.
See [ADR-006](./adr-006-agent-host-access.md),
[browser terminal auth](./browser-terminal-auth.md) and the explicit
[qualification checklist](../operations/sharing-terminal-qualification.md).
