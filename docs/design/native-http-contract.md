# Native HTTP boundary

The SDK plane is `/v1`, mounted by `apps/server/src/app.ts` before browser
body limits, session lookup, CORS, RPC, internal OpenAPI, static files and SSR.
This boundary exposes the read endpoints and
mutation actions below. An authenticated request to an unknown path returns JSON
`NOT_FOUND`; another method on a documented path returns 405
`METHOD_NOT_SUPPORTED`. `/v1` and `/v1/` are also covered. There is no redirect
into the browser app.

## Credentials and authorization

Send one `Authorization: Bearer wssp_sdk_…` header. The scheme is case
insensitive; the key is case sensitive and must match the canonical credential
format. The separator is one ASCII space. Duplicate headers, comma-joined
values, other schemes and host/device credentials return `UNAUTHORIZED`.
Cookies are ignored and never resolved on this plane. The only anonymous route
is `GET /v1/openapi.json` (see below); every other `/v1` request needs the key. A bearer key does not
supply a session to `/rpc`; a valid browser cookie continues to work there.

Credential query parameters are rejected with `BAD_REQUEST`, even with a valid
Authorization header. Names are checked case insensitively with separators
removed: token, key, api_key, access_token, authorization, auth, bearer, secret,
credential(s), sdk_key, sdk_token, host_token, device_token, client_secret,
password, refresh_token and id_token. Product credentials and Bearer values in
other query parameters are rejected too. Never put credentials in URLs.

Authentication calls `authenticateSdkKeySecret` on every request, without a
principal cache. It verifies owner policy, HMAC, expiry, revocation and the
owner-scoped authority tickets. Resource handlers must call existing
`serviceProcedure` functions using the resulting principal. Those services
revalidate scopes and ownership and fence results and failures against revocation.
No browser session is fabricated from a key. `/v1` accepts only API credentials;
agent tokens (`wssp_agent_…`) and OAuth grant credentials authenticate `/mcp` only.

The ordered scopes are:

| Scope               | Authority                                                            |
| ------------------- | -------------------------------------------------------------------- |
| `hosts:read`        | Host metadata                                                        |
| `hosts:execute`     | Owned host commands, stdin/cancel and queued commands                |
| `hosts:files`       | Owned host text file tools                                           |
| `pools:read`        | Pool metadata and capacity                                           |
| `templates:read`    | Templates and revisions                                              |
| `templates:write`   | Register revisions and capture templates                             |
| `templates:build`   | Build revisions and read build logs                                  |
| `sandboxes:read`    | Sandbox reads and probes                                             |
| `sandboxes:create`  | Create/replay create                                                 |
| `sandboxes:manage`  | Rename, stop, reconnect, lease; capture also needs `templates:write` |
| `sandboxes:destroy` | Destroy                                                              |
| `commands:read`     | Guest command metadata/output                                        |
| `commands:execute`  | Guest command start/stdin                                            |
| `files:read`        | Guest file observations/downloads                                    |
| `files:write`       | Guest file mutations/uploads                                         |
| `operations:read`   | Operation status/results                                             |
| `operations:cancel` | Cancellation plus the target's mutation scope                        |
| `webhooks:write`    | Endpoint and delivery management                                     |
| `credentials:read`  | CLI-login metadata                                                   |
| `credentials:write` | CLI-login management and write-only values                           |
| `credentials:use`   | Login attach/free plus `sandboxes:manage`                            |

`ownSandboxesOnly` restricts sandbox, command, guest file and operation access to
sandboxes created by this credential. Effective creator restriction is
`resourceMode === "ALLOWLIST" || ownSandboxesOnly`. API keys default false;
agent tokens and OAuth grants default true. Capabilities report the explicit
boolean at `key.ownSandboxesOnly`. Host access is outside that restriction.

`Origin` neither authenticates nor rejects a bearer request. No `/v1` response
includes CORS access-control grants. An authenticated `OPTIONS` request returns
405 `METHOD_NOT_SUPPORTED`; anonymous OPTIONS returns 401. This API does not
support browser preflight. Production HTTPS terminates at the configured proxy.

## Resource limits

Each request first consumes an IP budget (default 300 per 60 seconds).
Successful credential authentication then consumes a key budget (default 100 per
60 seconds) and an owner budget (default 300 per 60 seconds), in that order.
Separate Valkey prefixes (`sdk-http:ip`, `sdk-http:key`, `sdk-http:owner`) use the
existing procedure-budget helper. Each dimension has its own absolute limit:
`RATE_LIMIT_SDK_IP_POINTS`, `RATE_LIMIT_SDK_KEY_POINTS` and
`RATE_LIMIT_SDK_OWNER_POINTS`, positive integers validated at startup. The window
is fixed at 60 seconds. These budgets do not scale with the RPC family
(`RATE_LIMIT_RPC_*`). A missing/unavailable store fails closed with
503. Requests that fail, miss a route, or exceed a later budget retain earlier
charges. Windows expire through the limiter; no refund or principal cache exists.
Only one control-plane server replica is supported.

IP selection uses `resolveClientIp` and the `TRUST_PROXY_HOPS` policy: unset or
0 keys on the socket peer and ignores forwarding; N selects the entry N hops
from the right of `[...X-Forwarded-For, socket]`, falling back to the socket
peer when the chain is short or the entry is not an IP literal. A port suffix
on the selected entry (`v4:port`, `[v6]:port`) is stripped before the `isIP`
check; a bare IPv6 literal is used unchanged. There is no
private-hop heuristic. Operators restrict direct access to the proxy chain.

The default JSON body cap is **1,048,576 bytes (1 MiB)**. Actual stream bytes
are counted regardless of Content-Length; oversize streams are cancelled. One
fixed buffer bounds chunk bookkeeping. Nonempty bodies require application/json
(with optional charset=utf-8), valid UTF-8 JSON, and no compression; identity encoding
is accepted. Empty mutation bodies are left to endpoint validation. Invalid JSON
or interrupted reads return 400; oversized bodies 413; media/encoding violations
415. Browser routes retain their existing 10 MiB cap. Binary upload
adapters use separate chunk readers and total transfer accounting;
this JSON cap does not implement or replace the 1 GiB total transfer cap.

## Errors and observability

Every response includes `Cache-Control: no-store` and a new UUIDv4
`X-Request-Id`. Client-supplied request IDs are ignored. Errors have exactly:

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "A valid SDK bearer key is required.",
    "requestId": "generated-uuid"
  }
}
```

The source of truth for codes, statuses and safe messages is `SDK_ERRORS` in
`packages/sandbox-contracts/src/errors.ts` (re-exported by
`apps/server/src/sandbox-api/errors.ts`). It includes transport/auth/body/rate
errors and the existing sandbox domain code catalog. Unknown codes and unexpected
exceptions become 500 `INTERNAL_SERVER_ERROR`. Causes, arbitrary error data,
stack traces and internal messages never appear in the response. The OpenAPI
document (`x-wssp-error-catalog`) and the typed SDK errors consume this catalog
rather than invent another.

Throttling includes positive integer `error.retryAfterSeconds` and `Retry-After`
when the limiter supplies a valid duration. Store unavailability uses 5 seconds.
Capacity, quota and pool 409s (`RETRYABLE_REFUSAL_CODES`) carry a required
`retryable` boolean from the pool queue's static feasibility; only
`retryable: true` adds `CAPACITY_RETRY_AFTER_SECONDS` (default 30) as
`retryAfterSeconds` and `Retry-After`. A refusal without the flag is a 500.
Other failures make no automatic retry promise; mutations need their own
idempotency/receipt semantics before clients retry.

Logs contain the generated ID, an allowlisted method (or OTHER), the full
mounted path without its query string, status, elapsed time and safe error
codes. Credential-bearing path segments (`wssp_sdk_`, `wssp_host_`,
`wssp_device_`, including up to three percent-encoding layers) become
`[redacted]`. Shared access/error logging also redacts Better Auth reset tokens.
Query strings, headers, credentials and dependency error text are excluded.

## TypeScript SDK transport

`packages/sdk` publishes `@wssp/sdk`, a Node/server-first ESM package whose only
runtime dependency is zod; the contracts above are compiled into its `dist`
(code and declarations) so consumers never install the private workspace
package. It takes an explicit base URL and `wssp_sdk_` key (no environment
loading) and an injectable `fetch`. Every response body is validated against
the route registry's schema: a mismatch is a typed `protocol` error on reads
and an `unknown` outcome on mutations, never a crash. Requests use
`redirect: "manual"`; only bounded same-origin, method-preserving redirects are
followed, and the key is redacted from every error message, cause and
serialization. Errors are `WsspError` discriminated by `kind`:
`authorization`, `not_found`, `gone`, `unavailable`, `timeout`, `capacity`,
`unsupported`, `unknown`, `conflict` plus transport-side `invalid_request`,
`aborted` and `protocol`. A mutation whose request may have reached the server
(network cut, timeout, 5xx or an unverifiable response) reports `unknown` with
its idempotency key: poll or retry with the same key, never a new one.
`findSandbox` returns `null` only for a confirmed `sandbox.not_found`; a
DELETED sandbox, expired content (`gone`) and an unknown mutation outcome stay
distinct.

`createWsspClient` builds the lifecycle conveniences on this transport:
`create`/`get`/`list`/`connect`/`stop`/`destroy`/`setTimeout`/`isAlive` plus
explicit `waitReady`/`waitOperation`/`waitDeleted`. One idempotency key is
preserved through transport retries and polling: a lost accepted response is
recovered by re-sending under the same key (the server replays the receipt), so
an accepted create never allocates a second VM. Waits poll with a bounded
exponential interval (250 ms doubling to 2 s), honor `Retry-After`, share one
deadline across phases, and expose the operation ID on deadline or abort.
Operation status, output and result reads long-poll (`waitMs`, see "Operation
long-poll" below; SDK `polling.longPollMs`, default 20 s): a read the server
held for its whole hold, or an output answer the server paced (held its 2 s
progress hold) that moved the cursor, is re-sent at once with the backoff reset;
early answers, replays and answers without news back off as before; an output
page for a different operation ID is a protocol error, and a first 400 to `waitMs` (a server
that predates it) switches that client to plain polling. An
operation that ends `UNKNOWN_OUTCOME` is not automatically retried by the SDK;
the teardown recovery exception is described below. `create` resolves only
a READY sandbox, `destroy` only confirmed deletion (DELETED or a confirmed
404), `connect` reports the accepted warm/cold mode, `setTimeout` resolves with
the host-effective lease once the sandbox read shows it, and `isAlive` awaits
the host probe (false for confirmed stopped/absent, a typed `unavailable`
error when unreachable).

The `commands` surface (`run`/`script`/`argv`, `start`, `stat`, `tail`,
`writeStdin`, `cancelAndWait`) follows command output through the incremental
page route: per-stream incremental UTF-8 decoding (a trailing incomplete
sequence is flushed as U+FFFD at completion), cursor-strict paging with
committed delivery progress (no range is ever repeated, even across an abort
that interrupted an in-flight callback; a replay page that reaches back over
committed bytes because the server merged segments is trimmed to its
uncommitted suffix), explicit gap/reset handling and a follow that ends only
at the completion watermark, except that a caught-up follow of an
`UNKNOWN_OUTCOME` command (an interim UNKNOWN stays open, see Command output)
reports `unknown` with the operation ID instead of waiting for a watermark that
may never commit. Run-result accumulation is
bounded (`maxOutputChars`, with the dropped count reported as `discarded`).
The serialized `{argv, script, cwd, envs}` payload is checked against the
32768-byte server budget before any network IO. Natural nonzero exit remains
SUCCEEDED; checked SDK waits throw CommandExitError, while check:false returns
a RunResult. A proven guest-side timeout is a typed timeout error. Initial
stdin waits for the dispatch attempt (`dispatchedAt`); its action receipt's
`SUCCEEDED` means atomic durable acceptance, never guest consumption or target
completion. Refusals are direct 409s. Established observer abort detaches by
default. Explicit `onAbort: "cancel"` requests cancellation under a
domain-separated derived key (`sdk:cancel:<sha-256>`) and confirms the TARGET
operation's terminal state — never just the action receipt — under a bounded
acknowledgement wait. Lost confirmation remains unknown; a callback exception
never reports a stop.

The `transfers` and `files` surfaces cover resumable binary IO. `transfers`
is the low-level upload API: `createUpload` reserves a transfer under a
caller idempotency key (a lost reservation is recovered by re-sending under
the same key, never a new one), `putChunk` writes one fixed 1 MiB chunk with
`Content-Range` (a lost response resends the IDENTICAL bytes, which the server
digest-replays; a digest conflict is a definitive 409), `commitUpload` seals
with the whole-content SHA-256 under a derived key
(`sdk:commit:<sha-256(owner key)>`), and `abortUpload` discards an open
reservation (replay-safe, no key). `files` builds the conveniences: `upload`
pushes a buffer or async-iterable/Node stream through the chunk pipeline,
hashing every byte but sending only chunks at or after the durable cursor, so
a re-call under the same key resumes without a duplicate write (a one-shot
stream refuses a partially-sent resume); an abort mid-upload leaves the
transfer OPEN and reports `aborted`/`unknown` carrying the key, while an
abort racing the guest replacement cancels it under a derived key and
confirms the TARGET operation's terminal state before reporting a stop.
`download`/`resumeDownload`/`downloadRange` read captures as validated
streams: the response must span the ETag-advertised content to hash-verify,
length is fenced, a resume is guarded by If-Range (a replaced capture is a
conflict, not a silent restart), and a mid-stream break errors the stream as
`TRANSFER_IO`. `readBytes`/`writeBytes` are the bounded conveniences (default
32 MiB of client memory, independent of the 1 GiB server cap); `stat` returns
existence (`null` only for a confirmed missing file — a missing sandbox is a
typed `not_found`, never null). The server's transfer ceiling is discoverable
before any capture or upload as `limits.transferMaxBytes` in
`/v1/capabilities`.

## Public contract package and OpenAPI

`packages/sandbox-contracts` (`@wssp/sandbox-contracts`) owns the public DTO
schemas, the error catalog and the route registry `SDK_ROUTES`. It depends only on
`zod`; a boundary test rejects any other import (no Prisma, server, oRPC or auth
code). The server mounts exactly the registry routes through one chokepoint
(`apps/server/src/sandbox-api/reads.ts`): strict path/query parsing, the
`serviceProcedure` service, then validation of the response against the route's
documented schema. A response that fails validation is replaced by 500
`INTERNAL_SERVER_ERROR` and is never sent. Adding a registry route fails
type-checking until the server provides its handler.

`GET /v1/openapi.json` publishes a static OpenAPI 3.1 document generated from the
same registry and schemas. It contains only SDK routes (no browser, admin or
internal oRPC procedures, which stay behind the admin-gated `/api-reference`). It
is the only anonymous `/v1` route; it consumes the IP budget but no credential.
The committed snapshot `packages/sandbox-contracts/openapi.json` must match the
generator (`pnpm -F @wssp/sandbox-contracts openapi:write` regenerates it).

## Read endpoints

| Route                            | Scope                               | Result                                                                                                 |
| -------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `GET /v1/capabilities`           | any active key                      | `apiVersion`, enabled `features`, `limits`, the key's own `scopes`, `resourceMode`, `ownSandboxesOnly` |
| `GET /v1/hosts`                  | `hosts:read`                        | `{items, nextCursor}` of hosts                                                                         |
| `GET /v1/templates`              | `templates:read`                    | `{items, nextCursor}` of templates, retired ones included                                              |
| `GET /v1/sandboxes`              | `sandboxes:read`                    | `{items, nextCursor}` of READY sandboxes by default; explicit `states` includes history                |
| `GET /v1/sandboxes/{id}`         | `sandboxes:read`                    | one sandbox; 404 `sandbox.not_found`                                                                   |
| `GET /v1/operations/{id}`        | `operations:read`                   | operation status metadata; 404 `sandbox.operation_not_found`                                           |
| `GET /v1/operations/{id}/output` | `operations:read` + `commands:read` | incremental command output page; see [Command output](#command-output)                                 |

Lists are newest first. `limit` is a decimal string from 1 to 100 (default 20);
`cursor` is the opaque `nextCursor` of the previous page. Undeclared, repeated or
malformed query parameters and malformed IDs return 400. Every list query ANDs
the cursor onto the owner and SDK allowlist filter, so every query stays inside the key's scope. Sandbox cursors additionally bind a
hash of the normalized owner, filters and order and refuse a context mismatch;
other lists retain their existing cursors.
Allowlist keys see only their allowlisted hosts and templates and sandboxes on
both; an empty allowlist sees nothing. A sandbox or operation owned by another
user is indistinguishable from a missing one (404). A resource the owner has but
the key's allowlist excludes returns 403.

DTOs are strict objects with ISO-8601 UTC dates and opaque string IDs. They are
copied field by field from service rows; internal columns (owner IDs, connection
epochs, Incus names, error detail, slot flags) are never included. Operation
reads are **status metadata only**: no result, output, error detail, payload or
idempotency key. `errorCode` is a stable catalog value; unknown stored values
read as `internal`.

Stop is admitted during `REQUESTED`, `SCHEDULED` and `PROVISIONING` boot,
as well as `READY` and `RECOVERED`. It revokes create authority, waits for
issued init/config/network effects to settle, and interrupts readiness.
A retained disk ends `STOPPED` and cold connect reuses it. If boot was stopped
before an instance existed, proven absence ends `DELETED`, detaches the host
and releases its live slot exactly once. Stop never overrides an admitted or
UNKNOWN kill/DELETE. Kill may supersede a pending stop, advancing generation;
older results cannot author the new state. Same-key replay returns the
original receipt. UNKNOWN keeps its capacity reservation. The same no-disk
rule applies when lease expiry chooses Stop during boot; expiry Kill still
ends `DELETED`.

Outcomes stay distinct:

- An operation's `outcome` is derived from `state`: `pending`, `succeeded`,
  `failed`, `cancelled` or `unknown`. `unknown` (`UNKNOWN_OUTCOME`) means the
  effect may or may not have happened; it is not failure. Do not retry under a
  new idempotency key, except for teardown recovery: on a STOPPING sandbox with
  a current-generation UNKNOWN kill or stop, a new-key kill/DELETE is accepted
  (202). A new-key stop may retry an UNKNOWN stop, but cannot supersede an
  UNKNOWN kill. An in-flight kill still returns 409; kill may supersede an
  in-flight stop. Same-key replay returns the original receipt. The daemon automatically retries unresolved
  teardown, including after reconnect and on heartbeat. UNKNOWN retains its
  capacity reservation until positive stop/deletion proof.
- A sandbox that was deleted is still readable with `state: "DELETED"` (gone).
  `HOST_LOST` / `UNREACHABLE` mean unavailable. 404 means the caller cannot see a
  sandbox with that ID at all. `GET /v1/sandboxes/{id}` reports recorded state;
  it is not a liveness probe; use the `probe` action below.
- 503 `SERVICE_UNAVAILABLE` is a server dependency failure, never a resource state.

`/v1/capabilities` lists a feature only when every route that provides it is
registered by the running server. In addition to the read features, the API exposes
`sandboxes.create`, `sandboxes.manage`, `sandboxes.destroy`, `hosts.execute`, `hosts.files`, `sandboxes.probe`, `commands.execute`, `operations.cancel`,
`files.metadata` and `templates.write`; `commands.read` is also exposed. Any authenticated key may read capabilities (the action requires no
scope); it discloses the key's own grant but no allowlisted resource IDs.
`limits` also carries `transferMaxBytes` (the configured `TRANSFER_MAX_BYTES`
ceiling), so a client learns the server's transfer cap before reserving an
upload or capturing a download.

GET routes never read a request body (the Node adapter discards GET bodies), so
413 and 415 cannot occur on them; those codes apply to the action routes below.

## Owned host commands and text files

Host commands run as the node daemon user, who is an **Incus admin**. They and
host file tools can reach all sandboxes on the node, including other users'
sandboxes in shared pools. `ownSandboxesOnly` does not limit this authority.
Every host command/file action requires the host's database owner to equal the
credential owner and the host to pass the credential's host grant. Shared-pool
access never satisfies ownership. Direct commands/files also require the node
owner to enable agent host commands locally; files require configured roots.

Host DTOs include `agentAccess`: `{owned: false}` for foreign hosts, or
`{owned: true, hostCommands, hostFiles, hostCommandMaxMs?}` for owned hosts.
Flags describe effective live access, including pending policy lowering.

| Route                                                 | Scope           | Success/body                                                                            |
| ----------------------------------------------------- | --------------- | --------------------------------------------------------------------------------------- |
| `GET /v1/hosts/{hostId}`                              | `hosts:read`    | 200 Host                                                                                |
| `POST /v1/hosts/{hostId}/commands`                    | `hosts:execute` | 202 status; exactly one `argv`/`script`, optional `cwd`, `timeoutMs`, `stdin`, `waitMs` |
| `GET /v1/hosts/{hostId}/commands/{commandId}`         | `hosts:execute` | 200 status; `stdoutOffset`, `stderrOffset`, `maxBytes`, `waitMs` query                  |
| `POST /v1/hosts/{hostId}/commands/{commandId}/stdin`  | `hosts:execute` | 200 `{commandId, accepted, reason?}`; `{data, eof}`                                     |
| `POST /v1/hosts/{hostId}/commands/{commandId}/cancel` | `hosts:execute` | 200 status; empty body                                                                  |
| `POST /v1/hosts/{hostId}/queued-commands`             | `hosts:execute` | 202 `{id, state, expiresAt}`; `{command, reason, expiresInHours?}`                      |
| `GET /v1/hosts/{hostId}/queued-commands/{id}`         | `hosts:execute` | 200 `{id, state, expiresAt}`                                                            |
| `POST /v1/hosts/{hostId}/files/read`                  | `hosts:files`   | 200 `{content, offset, size, etag, truncated}`; `{path, offset?, maxBytes?}`            |
| `POST /v1/hosts/{hostId}/files/list`                  | `hosts:files`   | 200 `{entries, truncated}`; `{path}`                                                    |
| `POST /v1/hosts/{hostId}/files/write`                 | `hosts:files`   | 200 `{etag, size, created}`; `{path, content, expectedEtag?, createOnly?}`              |
| `POST /v1/hosts/{hostId}/files/edit`                  | `hosts:files`   | 200 `{etag, size, replacements}`; `{path, edits, expectedEtag?}`                        |

All host POST routes require `Idempotency-Key`; they return their typed result
directly, without a sandbox operation receipt. Commands and queued command reads
are credential-scoped: another credential of the same owner receives 404.
Queueing executes nothing and works while node agent access is off; only a
person can run or dismiss a queued command. Expiry is 1–168 hours (default 24),
with at most 50 queued commands per owner.

`argv` has 1–256 items, at most 4,096 UTF-8 bytes each and 16,384 total;
`script` has at most 16,384 UTF-8 bytes. NUL is refused. `timeoutMs` is positive,
at most 86,400,000 and capped by the node's configured maximum; `waitMs` is
0–60,000. Status is `{commandId, state, exitCode?, signal?, startedAt?, endsBy?,
finishedAt?, stdout, stderr, stdoutBytes, stderrBytes}`. Command IDs are 22
base64url characters; timestamps are epoch milliseconds and signal is a POSIX
signal number. States are `running`, `succeeded`, `failed`, `cancelled`,
`timed_out`, `interrupted`, `unknown`. Each stream is `{offset, data, dropped}`:
padded base64 of masked bytes, absolute masked byte offsets, up to 65,536 bytes
per stream/poll. Stdin takes at most 65,536 decoded bytes and an explicit `eof`.

File paths stay within node-configured roots and exclude sensitive daemon paths.
Reads default to 65,536 bytes, maximum 262,144; lists have at most 1,000 entries
(`name`, `kind: file|dir|symlink|other`, optional `size`). Writes have at most
262,144 UTF-8 bytes; replacing requires `expectedEtag`, while `createOnly`
refuses existing files. Edits contain 1–20 `{oldText, newText}` pairs, each
matching exactly once; changes commit together. The `Idempotency-Key` does
not replay host file writes or edits; a retried edit without `expectedEtag`
can apply twice. Files to edit are at most 4 MiB.
Writes and edits refuse `⟦redacted` spans. ETags are opaque `h:` plus 22
base64url characters; file reads mask secrets.

Host errors use the existing envelope: `host.not_owned` (403),
`host.agent_access_off` (409, `retryable: false`), `host.node_offline` (409,
`retryable: true`, positive `retryAfterSeconds` and `Retry-After`),
`host.command_not_found` (404), `host_queue.limit` (409), and `host.file_error`
(422, `error.data.reason`). File reasons are `host_files_off`, `policy_changed`,
`owner_mismatch`, `no_roots`, `path_denied`, `not_found`, `not_a_file`, `not_a_dir`,
`too_large`, `binary_file`, `conflict`, `no_match`, `match_count`, `redacted_span`,
`exists`, `invalid_input`, `io_error`, `limit`.

## Logical templates and revision authority

`GET /v1/templates` lists logical identities with at least one visible owned
revision. `GET /v1/templates/{id}/revisions` pages exact granted revisions;
`GET /v1/templates/{id}/availability?revisionId=...` pages the authorized host
intersection and also requires `hosts:read`. Lists apply visibility in SQL.
`POST /v1/templates` creates logical identity plus its first immutable revision;
`POST /v1/templates/{id}/revisions` appends to a visible logical target.
`POST /v1/templates/{id}/availability` verifies `{revisionId, hostId}` exactly.
All three return durable non-dispatch receipts. Session-only tag and retirement
mutations remain outside the SDK plane. New revisions are never auto-granted.

`POST /v1/templates/community` (scopes `templates:write` and `templates:build`,
`Idempotency-Key` required) creates the owner's template managed by WS Sandbox Proxy for one
tested community image and accepts its first prep build. The body is
`{source, poolId | sandboxHostId, label?}`. It answers **201** with
`{template, build, existing}`, where `build` is the template build DTO or null.
Another create for the same `source` returns the existing template and its
active build with `existing: true`. Allowlist keys get 403
`template.community_key_scope`. An unreachable index or no tested version is
409 `template.community_unavailable{reason}`. Disabled builds, image
distribution `off` and a timeout misfit are 409 `template.build_disabled{reason}`.
See [templates.md#community-bases](../operations/templates.md#community-bases).

Create selectors accept slug, slug:tag, template/logical-ID or revision/ID.
Ungrantable, absent, retired and unresolved revisions are absence-equivalent.
The retained sandbox context uses origin host, exact revision and nullable
origin pool, including replay, receipt, cancellation, files and terminal reads.
Pools are not active in this release. See [SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants).

## Mutation actions and receipts

Every action requires `Idempotency-Key` (1–128 ASCII letters, digits, `.`, `_`,
`:`, `-`; the system prefixes `lease-expire:`, `readiness-failed:`,
`inventory-observed:`, `access-expire:`, `lease-policy:`, `tb:` and
`teardown-retry:` are reserved).
Bodies are strict JSON objects. Empty-body actions also accept no body.
An accepted request returns **202** with
`{operationId, state, location}` and the same `Location` header. Poll that
`/v1/operations/{id}` location with `operations:read`. Acceptance does not mean
VM readiness or confirmed command cancellation. Keys are owner-wide, retained,
and bound to action, resource and canonical input; changed input is 409
`sandbox.idempotency_conflict`. Retries reauthorize before reading the receipt
and replay even when the sandbox subsequently changes generation or is deleted.

| Method and path                          | Required action scope                          | Body                                                                                                                                           |
| ---------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/sandboxes`                     | `sandboxes:create`                             | exactly one of `poolId`/`sandboxHostId`, `template` selector, optional `name`, `envs`, `metadata`, relative `timeoutMs`, `lifecycle`, `egress` |
| `DELETE /v1/sandboxes/{id}`              | `sandboxes:destroy`                            | empty; destroy the VM                                                                                                                          |
| `POST /v1/sandboxes/{id}/stop`           | `sandboxes:manage`                             | empty                                                                                                                                          |
| `POST /v1/sandboxes/{id}/reconnect`      | `sandboxes:manage`                             | optional `mode: warm or cold` (omitted adapts to READY/STOPPED), relative `timeoutMs`                                                          |
| `POST /v1/sandboxes/{id}/lease`          | `sandboxes:manage`                             | relative integer `timeoutMs` (may shorten)                                                                                                     |
| `POST /v1/sandboxes/{id}/probe`          | `sandboxes:read`                               | empty                                                                                                                                          |
| `POST /v1/sandboxes/{id}/commands`       | `commands:execute`                             | exactly one of `script` or `argv`; optional `envs` string map, `cwd`, `timeoutMs`                                                              |
| `POST /v1/operations/{id}/stdin`         | `commands:execute`                             | canonical `contentBase64`, optional `eof`                                                                                                      |
| `POST /v1/operations/{id}/cancel`        | `operations:cancel` plus target mutation scope | empty                                                                                                                                          |
| `POST /v1/sandboxes/{id}/files/stat`     | `files:read`                                   | `path`                                                                                                                                         |
| `POST /v1/sandboxes/{id}/files/list`     | `files:read`                                   | `path`, optional `maxDepth` (1–8)                                                                                                              |
| `POST /v1/sandboxes/{id}/files/mkdir`    | `files:write`                                  | `path`                                                                                                                                         |
| `POST /v1/sandboxes/{id}/files/move`     | `files:write`                                  | `path`, `destPath`                                                                                                                             |
| `POST /v1/sandboxes/{id}/files/remove`   | `files:write`                                  | `path`, optional `recursive`                                                                                                                   |
| `POST /v1/sandboxes/{id}/files/download` | `files:read`                                   | `path`; queues one GET_FILE capture (see the ranged download contract below)                                                                   |
| `POST /v1/templates`                     | `templates:write`                              | host, slug, label, image alias, optional architecture and guest identity; see OpenAPI                                                          |

`PUT /v1/sandboxes/{id}` (`sandboxes:manage`, body `{name}`) renames a
sandbox. It is not an action: no `Idempotency-Key`, no receipt, no operation
and no webhook; it answers 200 with the fresh `Sandbox`. A malformed name is
400 `sandbox.name_invalid` (create maps a bad `name` the same way; other
routes' `name` fields keep their own codes), a name another live sandbox of
the owner uses is 409 `sandbox.name_taken`, and a DELETED or invisible
sandbox is 404 `sandbox.not_found`. The shared gate applies the key's scope
and resource grants, the managed-sandbox policy and the build refusal.

Warm reconnect requires READY and keeps the generation/slot, extending to the
maximum of requested/effective expiry and acceptance plus duration. Cold
reconnect requires STOPPED or OFFLOADED. A STOPPED sandbox boots its disk on
the host that holds it; an OFFLOADED one is restored onto an eligible host
([disk offload](../guide/sandboxes.md#disk-offload)). Both use a new generation
and lease arm and preserve the timeout policy. Deleted
sandboxes cannot reconnect. Lease renewal reports requested versus effective
lease in the sandbox read DTO; a receipt never promises an offline extension.
Renewals stay QUEUED until dispatched and acknowledged by the host. Relay v8
carries `lease: {revision, deadlineUnixMs, action, expiryPolicy}` on create,
reconnect and `sandbox.lease.renew`; successful results echo that exact tuple.
Effective revision advances monotonically from matching ACKs; the deadline may
shorten with a newer revision. Accepted intent and its exact ACK remain on the
operation, separate from the mutable sandbox lease,
even when receipts arrive out of order. The fixed policy is `retry-force-60s`:
at expiry the host first asks the guest to shut down gracefully (`incus
stop --timeout 10`, never forced, on its own 16-second budget), then always
attempts the forced stop (before any destroy attempt), within the deadline +
60-second grace. The forced stop is the completion proof (on an already
stopped VM it only observes), so a guest that ignores the graceful request
never blocks expiry, but it delays the first forced stop by up to 16 seconds,
once per lease arm: every retry of that arm goes straight to the forced stop. Guest work and terminals are refused from the deadline itself,
but the VM keeps running, with its egress, for that graceful window (the
deadline + up to 16 seconds). An enforcement-loss arm skips the graceful
attempt. Failed actions retry with backoff capped at 30 seconds; each forced
runtime attempt has a cumulative five-second budget. A dedicated
supervisor owns this independently of the relay and operation queues. Monotonic
elapsed time prevents rollback extensions; persisted deadlines and observed clock
floors fence restart. Overdue journal leases settle before host readiness, and
Incus autostart is disabled. Host power loss cannot execute timers until restart.
Up to 64 outstanding local lease arms reserve independent cleanup slots. Expiry reconciliation
converges offline outcomes with server state; unresolved expiry must not be shown
as a confirmed stop or deletion.

Metadata is a flat object with at most 32 keys, 1–64 UTF-16 code units per key,
at most 1024 UTF-16 code units per string value, and at most 8192 bytes of
serialized UTF-8 JSON in total. Values are strings only, without coercion. NUL, unpaired UTF-16 surrogates and prototype-related names are refused. `/v1` reports
`sandbox.metadata_invalid`; the same schema bounds browser RPC creates and the
native service checks it before persistence. There is currently no metadata
update entry point. Any future update must use this shared schema.

Sandbox discovery defaults to READY. `metadata` is one bounded JSON query object of
string pairs (exact-match AND); reject duplicate parameters, duplicate decoded map
keys, malformed JSON and non-string values. `states` is one comma-separated list;
`templateRevisionId`, strict `startedAfter` and `order=asc|desc` apply on the current schema.
`startedAfter` compares the nullable actual VM `startedAt`; ordering uses total
`(createdAt, id)` order. All predicates, including SDK visibility, precede keyset
cursor/take (`limit + 1`). Dashboard `status=active|deleted|all` explicitly requests
history. Normalized equivalent map/state order and changed limits may reuse a cursor;
changed owners/filters/order cannot. Cursors contain a query hash, never envs.
Invalid stored metadata on disposable pre-launch rows reads as `{}` on lists and
detail views. Each adaptation logs one constant warning with only the sandbox id
and `legacy_metadata_dropped` code; input validation remains strict.
Any explicit metadata filter, including `{}`, excludes invalid stored maps
before pagination. Filtered pages select at most `limit + 1` valid positions in
SQL, then apply the original owner/key predicates again in a bounded projection
query. Unfiltered pages retain one query. Selected positions remain the cursor
source if a row disappears between selection and projection, so a short page
does not lose later results. Cursors bind whether a metadata filter is present.

### Deny-default egress policy

`POST /v1/sandboxes` accepts an optional strict `egress` object:
`{domains?: string[], cidrs?: string[]}`, at most 128 of each. Domains are
exact hostnames only: lowercased, trailing-dot-stripped, IDNA-canonicalized to
A-labels; wildcards, URLs, ports, userinfo, IP literals (including hexadecimal
or integer IPv4 spellings), single labels and control bytes are refused.
CIDRs must be strict dotted-quad IPv4 or RFC 5952 IPv6 with a plain prefix
length; host bits are masked to the network address. Entries are deduplicated
and sorted; the normalized form is what is persisted, hashed and disclosed.
Policies that intersect the protected destinations `169.254.0.0/16` or
`fe80::/10` are refused even under broad CIDRs, so `0.0.0.0/0` or `::/0` can
never cover instance metadata or link-local. IPv4-mapped IPv6 forms
(`::ffff:0:0/96`, e.g. `::ffff:169.254.169.254/128`) are refused outright —
they are a second spelling of IPv4 ranges that would bypass the IPv4
protected-range checks; IPv4 destinations belong in IPv4 CIDR syntax.
Malformed, ambiguous or
oversized policies fail validation with 400 `sandbox.egress_policy_invalid`
before any sandbox, operation or outbox row exists; the same code covers
browser RPC input-shape failures under `egress` (oRPC input validation runs
before the service resolver, and the router maps the egress-tagged issues to
the catalog code). Non-link-local metadata endpoints are protected alongside
link-local: the AWS EC2 IPv6 IMDS address `fd00:ec2::254/128` (unique-local,
so `fc00::/7` grants are rejected by intersection) and Alibaba Cloud's
`100.100.100.200/32`; GCP and Azure metadata are IPv4-link-local only and
already covered. IETF protocol assignments (`192.0.0.0/24`) and deprecated
6to4 relay anycast (`192.88.99.0/24`) are also protected: DNS answers in either
range and explicit CIDRs intersecting either range are refused, including
individual addresses such as `192.0.0.9`. Documentation TEST-NET-1/2/3
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are protected in both
DNS answers and intersecting CIDR grants too. No policy means deny-all
(`{domains: [], cidrs: []}`); metadata keys cannot widen egress.

Every create carries an egress policy — the caller's or the implicit
deny-all — and therefore requires the target host to have advertised the
egress-enforcement capability: hosts without it fail the create with 400
`UNSUPPORTED_CAPABILITY` under the admission lock, before any VM allocation
(sandbox row, live-slot reservation, operation, outbox). A cold reconnect is
a relaunch and re-checks the capability under the same host lock; the relay
also refuses a `sandbox.create`/`sandbox.reconnect` dispatch against the
current connection epoch unless the host row still advertises enforcement,
so a capability-downgrading replacement hello yields zero launch sends (the
operation terminalizes `unsupported_capability`, `FAILED` for a first attempt
— atomically transitioning the never-launched sandbox to `ERROR` with the
capability error so it does not poll as transitional forever — and
`UNKNOWN_OUTCOME` for a retry of an already-dispatched attempt, which authors
no sandbox state because the epoch-1 dispatch may have launched the VM). The race
between an in-flight launch dispatch and a downgrading hello is linearized on
the host row: the dispatch transaction write-locks the host row at the
connection epoch it read, and the hello's unconditional epoch increment takes
the same row lock, so exactly one order commits first. If the dispatch commits
first, the send legitimately targets the session that advertised enforcement
(bound via `sentConnectionEpoch`), the hello commits afterwards, reopening the
intent and fencing the replaced epoch's results by epoch CAS, and the retried
prepare observes `egressEnforcement=false` and terminalizes with zero sends;
if the hello commits first, the dispatch's epoch CAS matches zero rows, the
stale prepare is rejected without a send, and the next scan terminalizes at
the new epoch. Both commit orders are proven against real PostgreSQL row
locks in `apps/server/src/sandbox-relay/egress-capability-race.pg.test.ts`.
Host
daemons advertise `egressPolicy` in the relay hello; the
control plane records it as `SandboxHost.egressEnforcement` (disclosed on the
host DTO as `egressEnforcement`). Relay protocol v10 requires both peers to be
upgraded together. The normalized policy and its SHA-256 hash — over the
canonical JSON text itself (`{"cidrs":[],"domains":[]}` for deny-all), never
a re-serialized wrapper — are persisted on the sandbox row at create, ride
the create
dispatch, and are re-applied immutably on cold reconnect; the sandbox DTO
discloses the recorded policy as `egress` to the owner only. A VM-launch
dispatch without the recorded policy and hash is a deterministic producer bug
and is never sent.

Host-side enforcement (`crates/sandbox-runtime/src/incus/{network,acl}.rs`)
compiles the recorded policy into a dedicated managed bridge per sandbox plus
one network ACL: object names are `wsn-<sha256(sandboxId)[:10]>` /
`wssp-acl-<…>` (hex), so the bridge name always fits the Linux 15-character
interface-name limit. Both objects are tagged `user.wssp.sandbox_id`, and any
object carrying a foreign tag is neither adopted nor deleted, so one
sandbox's plan can never address another sandbox's rules. The bridge's
gateway address is allocated from `10.0.0.0/8` seeded by the sandbox hash,
probing up to 4096 `/24`s and skipping anything overlapping another managed
network's `ipv4.address` or an on-link host route (`/proc/net/route`;
default routes carry no subnet), persisted in the bridge config and reused
thereafter; exhaustion is `host_capacity`, and a bridge owned by another
sandbox that already sits on a colliding subnet is `idempotency_conflict`,
never silently shared. The bridge is IPv4-only (`ipv6.address=none`,
`ipv4.nat=true`) with `security.acls` attached and both
`security.acls.default.{ingress,egress}.action=drop` — there is no
unrestricted fallback; deny is the default action, never a rule. Explicit
permits, in Incus terms (egress = traffic the guest sends, ingress = traffic
delivered to the guest NIC), are exactly: guest-initiated egress DHCP
(udp dport 67), guest-initiated egress DNS to the bridge resolver only
(udp+tcp dport 53), one egress allow per granted destination, and the
matching ingress DHCP/DNS replies from the bridge; every reply rule pins the
bridge gateway as source so no other sender can inject them.
Domain grants mean host-resolved IPv4 destinations resolved at apply time
(bounded, deduplicated, each lookup time-boxed inside an overall 30-second
compilation budget that honours worker cancellation); a domain with no
enforceable IPv4 answer, any IPv6 grant, a non-canonical CIDR, a
protected-range intersection, or a policy/hash mismatch fails the launch
closed (`unsupported_capability` / `protocol_error`) before any host
mutation. The guest's only NIC is an `eth0` device override onto the
sandbox bridge with `security.mac_filtering`, `security.ipv4_filtering`,
`security.ipv6_filtering` and `security.port_isolation` — anti-spoof source
pinning, no IPv6 alternate path, no forwards, proxy devices, host mounts or
extra NICs. `incus init` selects the audited `default` profile explicitly
and the effective device set is verified against the plan before first
start; a profile carrying anything beyond a root disk and a single `eth0`
NIC fails host preflight before VM creation. Pre-existing VMs on create-retry
or reconnect must already carry exactly the audited device set: a running VM
with any drift is `idempotency_conflict` (never reconfigured live), a stopped
one gets its `eth0` override re-applied and re-read before start. Bridge ACLs
are stateful (Incus ≥ 6.0), so established replies to allowed outbound
connections pass while both defaults stay `drop`. The host advertises
`egressPolicy` in its hello only when the daemon proves support (the
`network_acl` API extension and server version ≥ 6.0, inspected via
`incus query /1.0` at connect time; any error reports `false`), and every
apply re-checks the daemon, creates ACL then network idempotently, reads the
effective configuration back and compares it rule-by-rule against the
compiled plan including each rule's `state` (missing, malformed or disabled
state is a mismatch), and rolls back through the tag-checked teardown on any
failure or mismatch. Rollback runs on its own bounded permit so a revoked
worker permit can never leave a partial apply behind; if teardown still
cannot finish, the obligation is persisted under the host state dir and a
fenced drain (names re-derived from the sandbox id, tags re-checked, ≤ 256
records) completes it on the next inventory or query. Kill completes only
when the network and ACL are both verifiably absent — a teardown failure
persists the same obligation and the sandbox reports `provisioning`, never
gone, until the drain finishes; cold reconnect re-applies the recorded
policy immutably before start.

Lifecycle ordering makes the enforcement-before-start
guarantee a property of the runtime boundary itself, not of any one call
site. `IncusClient::start` — the single chokepoint every start path (create,
adopt-and-start, cold resume) passes through — runs two pre-issue fences.
The launch-config fence (`pre::launch_config`) requires the instance's
EFFECTIVE config to carry only the audited allowlist (`user.flycockpit.*`,
`volatile.*`, `image.*`, `security.agent.metrics`, `boot.autostart`), so a
template or profile injecting raw config keys or a `security.acls` override
is refused on EVERY start — a rejected launch config cannot be launched
later through a create retry, a reconnect, or a direct call, because none
of them can skip the shared boundary. The verified-policy fence
(`pre::verified_enforcement`) then re-derives the sandbox id from the
instance name and requires the recorded policy hash, the live ACL
rule-by-rule readback, and the DNS fence state (revocation markers) to
verify against the persisted record, or the start is refused as NotIssued
and never reaches the daemon — a direct runtime bypass is rejected the same
way (defense in depth). Initialization stays stopped, and profiles carrying
ANY config keys are rejected at preflight (the launch pins its own config,
so a profile key can only be an override). Cold reconnect VERIFIES the
recorded enforcement — it never recreates it: a lost or modified bridge/ACL
refuses the resume (as required by the refusal contract), the refusal is
journaled as a provisioning obligation carrying the VM's ORIGINAL create
binding so the restart drain keeps the sandbox deliberately fenced without
rebuilding or tearing down anything under the bound VM, and recovery runs
through the existing journaled kill/teardown path; the request's recorded
policy identity is also compared explicitly against the persisted record
(`verify_recorded_policy_identity`), since a verify-only reconnect can no
longer rely on the apply's rule-equality check to reject a changed policy.
Every resume still passes the start's pre-issue fences (cold) or the
readiness fence (warm), so no window between verification and Ready can
resume unenforced. Readiness includes the fence state:
`check_readiness` re-runs `verify_provisioned_enforcement` before
`wait_for_agent`, so a guest answering while the network/DNS policy is
unverifiable (e.g. an unreconciled revocation marker, or an ACL tampered
with during boot) never reads Ready — and because the instance there is
POSITIVELY BOUND (the caller bound it pre-issue), that enforcement failure
surfaces as `guest_unavailable`, so the relay queues the existing bound
lifecycle cleanup instead of leaving a running, broadened-egress VM to
lease expiry; a FOREIGN-instance binding conflict is raised earlier by
`bind_instance`, stays `idempotency_conflict`, and never triggers that
cleanup. Every readiness/runnability
consumer shares ONE bound-enforcement boundary,
`IncusClient::verify_bound_enforcement`: the readiness check, the warm
reconnect, the state query, the live probe, and the inventory census all
verify through it, and the failure semantics are the bound VM's power
state. A RUNNING bound VM whose enforcement is lost or tampered surfaces
`guest_unavailable` on every consumer — the wire code the relay's
generation-fenced lifecycle cleanup consumes — because an unenforced
running guest is an active egress breach and the provisioning journal does
not fence its traffic (the drain only repairs devices and retries
verification), so a journaled refusal is not an answer for a running VM;
the warm reconnect therefore fails `guest_unavailable` without journaling,
and the receipt settle (which consumes the state query) reaches the same
cleanup. A STOPPED bound VM keeps the non-destructive refusal
(`idempotency_conflict`, journaled for the drain) — nothing is running, so
nothing needs tearing down. The census is observational: it certifies a
bound running VM Ready only through the same boundary and reports an
unenforced one `unreachable` (never a false Ready), while the cleanup
itself is driven by the op-result paths above; a live probe likewise
reports the guest reachable (`guest_ready`) only past the boundary,
otherwise the error surfaces as `unreachable` to its callers. Detection alone is not a cleanup
outcome: the boundary now also writes a DURABLE record
(`enforcement-losses/<id>.json`, write-if-absent, own-project validated)
on every confirmed running-VM drift, so every consumer — operation result,
receipt settle, census, probe — feeds the same signal and none can drop
it. The always-running consumer is the expiry service's worker (it ticks
every 50ms for lease deadlines already): a cadence-gated pass every 2s,
spawned off the deadline path so teardown work never delays an expiry,
drains the records. A census only records loss: it cannot delete without
the service's lifecycle authority. The drain re-binds the instance by
ownership evidence only (`bind_owned_instance`: managed name, VM type,
sandbox tag, template/base-image consistency — a foreign or unprovable
instance conflicts, is never touched, and keeps its record), then
RE-VERIFIES coherently before any destruction: a clean re-verify means
the detection was transient and the record simply retires; only confirmed
drift is torn down, through the kill-shaped ordering (cleanup obligation
journaled BEFORE the VM is touched, forced delete, fenced network
teardown, verified absence, records retired). A completed kill also
retires any loss record for the sandbox. Second, verification is
transactionally coherent with DNS plan commits: a managed transition
(expiry settle, restart recovery, policy refresh) fences and removes live
rules BEFORE its persisted plan commit, so a read pair straddling it
compares the new live ACL against the old plan and would convict a
healthy, correctly narrowed sandbox of drift — a false conviction
would delete the VM. A per-sandbox transition seqlock
(`begin_dns_transition`, an epoch plus in-flight depth) marks the whole
mutation window; `verify_provisioned_enforcement` retries its snapshot
until it observes the same idle epoch on both sides (25ms cadence, 25s
budget). Only the verifier waits — deadline enforcement never blocks on
it. A snapshot that cannot be observed coherently within the budget is
INCONCLUSIVE (`internal`), not drift: it propagates without triggering
cleanup and without writing a loss record. No-op recovery passes never
mark a transition, so a healthy leased sandbox's epoch stays stable.
The three-way distinction is explicit and durable. Each
observation carries a typed verdict — `EnforcementVerdict::Verified`,
`ConfirmedDrift(reason)`, or `Inconclusive(error)` — from
`enforcement_observation` through the bound-enforcement boundary into
every consumer (readiness, warm reconnect, state query/receipt settle,
live probe, census, loss drain). ONLY confirmed drift — a coherent
comparison failure against the persisted plan (missing or foreign
enforcement objects, absent plan, rule/config/device mismatch; comparison
errors carry the drift code) — authorizes enforcement-loss cleanup: the
`guest_unavailable` signal plus the durable record. Every inconclusive
observation — timeout, cancellation, unknown-outcome, a transport or
daemon read failure nested in the readback, an unsettleable DNS
obligation, or an exhausted coherence budget — propagates its own
retryable code at every layer, running or stopped: `check_readiness` no
longer converts it to `guest_unavailable`, the warm reconnect journals no
refusal fence for it, and the drain keeps the record and acts never. The
loss record itself moved onto the same atomic, crash-durable journal write
path as the provisioning journal (`write_durable_record`: unique no-follow
temp, file fsync, atomic rename, directory fsync). A persistence failure
is actionable — named in the detection error, never silently treated as
recorded — and because only a WELL-FORMED own-project record counts as
standing, an interrupted (truncated/empty) write is rewritten by the next
detection; enumeration treats an unreadable or unparseable record as
actionable evidence to re-verify from live daemon state, never as a
reason to skip the sandbox, so one partial write can no longer
permanently disable observational cleanup. Local observations and persistence failures obey the same
classification rules. First, local persisted-state reads are fallible throughout
the observation: an unreadable or unparseable DNS revocation marker
(`dns_marker_blocks_readiness` errors), enforcement plan
(`persisted_enforcement_plan_checked`), or DNS publication state
(`expected_dnsmasq_config_checked`) is unavailable EVIDENCE — the
observation still fails closed (readiness refuses) but classifies as
`Inconclusive`, so a healthy sandbox is never recorded, stopped, or
deleted over a local EACCES/EIO/partial write; only positively OBSERVED
divergence — a readable pending revocation marker, a cleanly absent or
foreign plan record, a live-versus-plan comparison mismatch — is
`ConfirmedDrift`. Second, when the loss record cannot be persisted, the
boundary no longer relies on re-detection: it takes a permit-INDEPENDENT
restrictive action itself — an ownership-fenced force-stop of the
breached VM on a separately scoped cleanup permit (the caller's revoked
permit must not strand a confirmed breach, and a probe/census caller's
discarded diagnostic must not be the only signal). Stopping — not
deleting — halts the unauthorized traffic while remaining
non-destructive: teardown authority stays with the relay's
GuestUnavailable-driven lifecycle cleanup and, once the journal is
writable again, the re-detecting drain. A stop failure is diagnostic-only;
the drift signal stands regardless.
Transition marking and the confirmed-breach halt share enforcing boundaries. Transition marking no longer predicts
at pass entry: the guard lives at the shared mutation boundary, acquired
LAZILY immediately before the first actual mutation and retained through
the settle's plan commit. The blind pre-fence fills the caller's guard
cell only on its way into a genuine fence add, and the recovery settle
marks from the exact post-probe settle condition on a fresh clock — so a
grant whose expiry lands DURING the recovery probe (the probe deadline
deliberately runs right up to the earliest future expiry, as much as 20
seconds beyond the old +2s prediction window) is fenced, withdrawn, and
committed as a marked transition, and a concurrent verifier whose own
recovery already finished retries to a coherent snapshot instead of
comparing the old plan against the narrowed ACL and convicting a healthy
expiry of drift. A genuinely no-op pass still never marks, so a healthy
leased sandbox's epoch stays stable. And the permit-independent
restrictive action is now ONE boundary — `halt_confirmed_breach`, an
ownership-fenced force-stop on a fresh bounded cleanup permit — shared by
the detection path's loss-record-persistence failure and the drain's
teardown-bookkeeping failure: when the loss record stands but the
network-cleanup journal is unwritable, the drain halts the breached VM
before surfacing the bookkeeping error, because no later detection
re-runs the boundary's persistence-failure stop and probe errors would
otherwise reduce to `unreachable` with unauthorized traffic live until
lease expiry. The invariant: confirmed drift on a bound running VM ALWAYS
halts traffic, even when every journal fails. Stopping — never deleting —
keeps destruction authority with the relay's lifecycle cleanup and the
drain's fenced teardown, which the retained loss record retries on the
next pass. Healthy, inconclusive, and foreign observations never reach
the halt.
Loss-drain scheduling and persisted-plan validation fail closed independently. The enforcement-loss drain now enforces the SAME scheduling
boundary as the network-cleanup drain: per-record failure isolation (one
persistently failing record — a halted breach whose teardown bookkeeping
keeps failing on an unwritable `network-cleanups` journal — never strands
the breaches behind it; the first failure is surfaced AFTER the rest of
the pass), and a rotating cursor (`.drain-cursor` in the loss journal, a
best-effort progress hint, never evidence) that resumes each pass AFTER
the last attempted record, wrapping around, with the 256-per-pass bound
applied AFTER rotation — so retained records can neither monopolize the
head of every sweep nor hide records behind an alphabetical cap. And the
persisted-plan reader now shape-validates the WHOLE record — required
string identity, parseable gateway, the rules array, and grants /
policy_cidrs as fully well-typed arrays with every grant a parseable CIDR
— BEFORE the identity comparison: a valid-JSON but structurally malformed
record (`{}`, `null`, a wrongly typed `sandbox_id`, a truncated write) is
unavailable EVIDENCE and classifies inconclusive, never as positive proof
of a foreign plan; only a well-formed record positively recorded for a
DIFFERENT sandbox reads as "no plan of ours here". A malformed record
therefore can no longer manufacture confirmed drift that convicts — and
deletes — a healthy VM.

Autonomous cleanup preserves lifecycle and capacity ownership. Every destructive
loss-drain leg (including already-absent crash recovery) MUST cross caller-owned
`Prepare` and `Complete` checkpoints. The expiry service captures the durable
lease arms BEFORE runtime observation; both checkpoints CAS the captured
generation, exact lease tuple, owner/host/server binding and template, with the
existing active-lifecycle-worker veto. Prepare durably latches
`expired=true, enforcementLoss=true` before destruction and revokes that arm's
local work authority. This is NOT timer expiry (`timerExpired` stays false).
The crash-recovery expiry actor always destroys an enforcement-loss arm, even
when the original lease's normal expiry action was stop; the accepted wire lease
is never rewritten. A failed Prepare still ownership-fenced force-stops the
confirmed breach on the independent cleanup permit, retains its loss record,
and grants no deletion authority. Complete runs only after confirmed VM and
network absence, durably records `expiryComplete` and `instanceAbsent`, then
allows loss-record retirement. A failed Complete retains retry evidence.
The existing connected `sandbox.expiry_status` publication now carries these
non-timer completions too: generation-fenced inventory convergence releases
server `liveResourcesHeld`/host `liveCount` and fences late results, while the
reader's exact-arm completion check releases `LiveSandboxAdmission`. No socket
reconnect or deadline advance is needed. Since no user kill or destroy-timer
result is fabricated, unrequested disappearance converges to `ERROR` /
`instance_missing`, not a fabricated successful kill/`DELETED`. Stale completion
cannot settle or free a newer successful allocation at either boundary.

Every timer attempt binds to its immutable worker-start intent. Timer
workers and loss drains complete through ONE journal CAS, including the exact
lease, generation, binding, template and stop-versus-destruction intent. A
stop-only worker predating loss escalation cannot complete, publish absence,
release capacity or authorize rearming. An upgraded worker must actually destroy.
An enforcement-loss arm, like a destroy lease, cannot be rearmed as a stopped VM.

The lifecycle boundary is installed before startup inventory and shared by all
runtime clones. Every readiness producer captures its lease BEFORE enforcement
observation and, only for confirmed drift on an owned running VM, prepares that
captured arm. This happens independently of runtime loss-record persistence.
The existing lease-backed enforcement-loss intent is sufficient retry authority:
the service's ordinary expiry worker consumes it without enumerating the loss
directory or redetecting drift on the now-stopped VM. No compensating marker
layer is introduced. Healthy, foreign and inconclusive observations never
prepare. An active lifecycle worker allows the restrictive latch, but vetoes
destructive work and completion until it settles.

A stale Prepare CAS is distinct from storage/worker failures, which
already retain the captured lease's retry intent. If generation, revision/exact
lease tuple, owner/host/server binding or template changes DURING observation,
the shared confirmed-loss boundary immediately performs the same independently
permitted restrictive halt. It then captures fresh lifecycle authority BEFORE
fresh ownership binding and coherent enforcement verification (including for
the VM it just stopped). Only a fresh confirmed-drift verdict may Prepare that
fresh arm; another stale CAS repeats capture and verification. Healthy,
inconclusive or foreign fresh evidence refuses adoption of the old verdict:
no new-arm Prepare, loss record or destruction. Thus renewal plus failed runtime
loss recording still leaves the ordinary lease-backed recovery actor in charge,
without a compensating marker or a second probe/reconnect/restart.

A failed lease Prepare write retains the same intent in memory, closes
admission, and permits only restrictive stopping; every destructive retry must
first successfully persist Prepare, even if the in-memory latch is unchanged.
Runtime-loss or teardown-journal failure also force-stops independently of
persistence success. Healing storage automatically retries cleanup and publishes
the actual arm's completion while connected, releasing both reservations without
clock advance or another probe. A durable Prepare survives restart; no claim of
crash durability is made when all storage rejected the intent. Complete remains
after confirmed VM AND network absence; failed completion retains retry authority.

Teardown keeps its ordering: network teardown runs
only after the stop or destroy is CONFIRMED (the post-delete absence
observation, not the requested deletion); an unconfirmed stop/destroy fails
the operation, retains the restrictive rules, and journals the obligation
for the fenced drain. A failed create leaves the unused network journaled
under the provisioning intent (the existing drain cleans it once the VM's
absence is proven); an uncertain-but-possibly-live instance always retains
its restrictive rules. A lease that lapses mid-reconnect refuses the resume
(StateConflict) even after the network verification completed.

DNS-aware egress (`crates/sandbox-runtime/src/incus/dns.rs`) closes the
resolution side of domain grants. Ground truth: an Incus managed bridge runs
a per-network `dnsmasq` that, without intervention, forwards arbitrary guest
queries to the host's upstream resolvers (no `--no-resolv` in the generated
command line). Every sandbox bridge is therefore created with `raw.dnsmasq`
containing `no-resolv`, so from first boot the bridge resolver REFUSES every
name except the ones the host publishes. The host publishes only validated
answers for allowlisted names as exact-name `host-record=` lines (never
`address=` wildcards, never `server=` upstreams); guests cannot trigger
wildcard or unlisted resolution, and direct external DNS/DoT from the guest
stays denied by the deny-default ACL (only the bridge gateway's port 53 is
reachable) unless the policy separately grants that destination as a CIDR.
Resolution always happens on the HOST through the host's own resolvers
(`/etc/resolv.conf`, bounded UDP with per-query timeouts): a minimal strict
wire codec validates every answer — transaction id and question echo,
no truncation, compression-loop detection, CNAME chains ≤ 8 with cycle
detection, well-formed CNAME targets, and CNAME RDATA occupying exactly its
RDLENGTH — and every A answer must be a public address; a single rebound
private/loopback/link-local/CGNAT/reserved address (anywhere in the chain)
denies the whole name and is never installed. The AAAA view is validated
with the same strictness: NODATA/NXDOMAIN are fine, malformed responses
deny like malformed A responses, and actual AAAA data denies the name as
UNSUPPORTED_CAPABILITY rather than silently narrowing the grant to v4. The
same rebinding check now also guards create-time compilation. Refresh
lifetimes clamp to 30–300s. A domain grant is a content grant, never a
resolver grant: each domain-resolved address also gains `reject` companions
for DNS/DoT (udp/53, tcp/53, tcp/853) — Incus orders drop > reject > allow
regardless of rule order — so a grant whose answer happens to be a public
resolver does not open direct external DNS for the guest; an explicit CIDR
grant over the same address exempts it and preserves that access. The
reject companions install BEFORE the allow rule, so an interrupted install
never leaves the unrestricted allow in place — and reject REPAIR withdraws
every overlapping dynamic allow before touching the mismatched OR MISSING
reject, restoring allows only after the replacement rejects exist, so an
interrupted repair also fails closed. Refresh validates BOTH ACL directions:
dynamically tagged ingress rules are refused outright (grants are
egress-only), and direction is part of every static rule's persisted
identity, so an ingress/egress move reads as drift. Publication itself is a
stdin-bodied config PATCH (`incus query -X PATCH --data-file -`; `-d @-`
was never a stdin form in any Incus release, and an incus CLI older than
7.4 lacks `--data-file`, so there the body falls back to an inline `-d`
argument bounded at 96 KiB and a larger policy fails closed): an in-bound policy
at the record limit renders ~280 KiB of `raw.dnsmasq`, past Linux's
per-argument limit (MAX_ARG_STRLEN, 128 KiB on 4 KiB-page hosts), so the
payload never travels on argv — and the body is streamed by a concurrent
writer thread under the same spawn-measured deadline and cancellation as
the output collection, so an Incus that stalls before reading stdin (or
fills an output pipe first) is killed and reaped at the deadline instead of
parking the sandbox lock. Published answers render one
`host-record` directive per name/address pair, the form the installed
dnsmasq manual documents for multiple addresses. The AAAA view follows
CNAME chains with the same bounded cycle-detecting walk as A: IPv6 data at
a chain endpoint denies the grant rather than silently installing the v4
half. Address records delivered INLINE for a chain target belong to the
reachable chain and are validated BEFORE it is followed — a protected
inline address (or inline AAAA data) denies immediately, so a rebinding
cannot be laundered through a public re-query of the target — and EVERY
reachable inline CNAME hop is walked within the response (cycle, depth,
address, and TTL checks at each hop) before the chain end is re-queried, so
a multi-hop answer carrying a→b→c with data owned by c cannot be laundered
through a friendlier re-query of b. Each refresh replaces the ACL destination set
BEFORE the new answers are published — stale rules are removed first
(shrink), new rules added (grow), the effective ACL read back — so an answer
never becomes usable before its rule exists; the reverse-order failure
(publish fails after rules change) leaves resolvable-but-unreachable
addresses, the deny direction. Old addresses expire with the rotated answer
set; an empty answer (NXDOMAIN/NODATA) removes a grant immediately even
before TTL expiry, while a transient resolver failure keeps only grants with
at least the 30s churn floor of lifetime left — expired grants are removed
on resolver failure. Because the refreshed state persists only AFTER
publication, a refresh that denies a grant writes a durable revocation
marker BEFORE mutating anything; a later transient retry (even after a host
restart, with the old state still listing the grant) never retains and
reinstalls a revoked name, and the marker is cleared once the refreshed
state commits. The marker also gates readiness: reconnect/recovery
verification refuses while a marker file exists (a completed refresh always
clears it, so any marker means an interrupted refresh with a stale-denied
plan), the stat PROPAGATES errors (only NotFound means absence — an
unsearchable directory or metadata I/O error fails readiness closed), and
teardown retires the marker with the plan and DNS state records.
Each refresh's marker is the UNION of its own denials and every earlier
uncommitted denial: an interrupted retry that denies nothing must not erase
a pending revocation, or a later transient failure would retain and
reinstall the denied grant from the stale state. Only ABSENCE (NotFound)
reads as no-marker: any other read failure (invalid UTF-8, permissions) is
fail-closed evidence — the refresh refuses to mutate and never overwrites
it. Grant expiries are anchored at ANSWER time (each CNAME hop and address
record expires at its own receipt + clamped TTL), never at planning time,
so the earliest answers are never extended by the resolution budget later
lookups consume; grants already past the safe window at planning completion
are revoked BEFORE the first enforcement pass — an expired destination
never receives an allow-add, since withholding DNS publication does not
stop a guest connecting by IP — and every grant's remaining lifetime is
rechecked before INDIVIDUAL rule additions and restores inside the pass (a
grant lapsing mid-pass is revoked durably, its companions withdrawn,
survivors rechecked on the next pass), and each allow mutation is bounded
by the grant's remaining absolute lifetime AND the earliest other live
grant's deadline — a stalled mutation can never keep an installed grant
reachable past its own expiry. The churn floor is transient-retention
headroom, not an eligibility bar: floor-clamped short TTLs (0..=30s)
install and publish successfully. Every allow mutation intent is
journaled PENDING in the revocation marker BEFORE the command is issued,
so uncertainty survives every later error path — including a cancelled
permit failing the pass's readback for a still-live grant — and retires
only on definitive evidence (exit 0, a daemon rejection, a withdrawal
re-observed absent, the uncertain path's own immediate withdrawal
positively removing the rule — a clean exit 0 proves the request had
already completed daemon-side, and a request completes at most once —
or the expiry lease's POSITIVE withdrawal of the exact request-specific
identity, recorded in the fsync'd lease-withdrawal evidence log:
the lease observed the rule present and removed it, which proves the
uncertain request completed, so the entry retires even though the rule
can never be observed again). A nonzero exit is NOT rejection evidence by itself:
only an explicit daemon error without any transport-failure signature
retires the journal; an unacknowledged add whose connection failed after
possible acceptance stays fenced as uncertain. A command
killed at its deadline has an uncertain outcome — the daemon may apply
it after the CLI died — so it is fenced: grant revoked, every lapsed
grant swept, and a DESTINATION-WIDE quarantine reject (every port,
TCP/443 included — the port-scoped DNS/DoT companions alone leave the
rest open) installed through an INDEPENDENTLY bounded, permit-free
client, so revoking the issuing permit mid-mutation cannot leave the
destination unprotected. Allow rules carry a per-name monotonic
GENERATION (`wssp-dns-g<N>-<hex>`; generation 0 keeps the legacy
`wssp-dns-<hex>` shape), so a re-grant's rule can never be mistaken for
a stale request's rule: a re-grant does NOT retire the older pending
entry. The pending entry
outlives the commit (readiness stays refused) and is NEVER retired by
observing absence: two observations of absence do not prove an accepted
daemon-side mutation cannot arrive later, so reconciliation requires
definitive completion — the rule observed PRESENT and withdrawn, or
durable positive-withdrawal evidence from the expiry lease for that exact
identity — before the marker clears. Failure-path
cleanup runs through an independently bounded client carrying no
cancellation permit, so a cancelled publication cannot strand lapsed
allows, and builds its desired rule set from surviving grants PLUS every
pending mutation's quarantine, so revoke-only cleanup passes never strip
a fence around an outstanding mutation. Failure-path cleanup is likewise a
bounded revoke-only loop: revocations recorded durably BEFORE each
withdrawal pass, nothing ever added, survivors rechecked after every pass
until nothing lapsed remains. Lifetimes are rechecked after EVERY enforcement pass AND
after every publication — potentially thousands of sequential Incus calls
plus a PATCH: a grant whose safe publication window (the churn floor)
lapsed during any stage is revoked (marker extended BEFORE its removal
pass), the ACL re-enforced and the answers republished without it, looping
until everything committed has a safe lifetime at commit; the same
revoke-then-withdraw cleanup runs on FAILED enforcement/publication paths
before returning, and the published TTL and the returned refresh delay are
computed at actual completion, never from planning-time expiries — capped
by the REMAINING grant lifetime (a floor-clamped TTL-30 grant that spent
seconds on resolution and enforcement schedules the next refresh before
its expiry, never at the 30s churn floor).
On a pre-7.4 CLI, the inline `-d` argument exposes the allowlisted domain names
and resolved addresses in `/proc/<pid>/cmdline` to host users permitted to read
that process's arguments; this publication contains no credentials. Incus 7.4+
uses stdin instead. Inline-only detection is cached per client (shared by its
clones), so later publishes do not repeat the rejected `--data-file` attempt.
Restart the node daemon after upgrading the Incus CLI to 7.4+; until restart,
that cached mode keeps the inline fallback, its size limit and argument
disclosure even though the upgraded CLI supports stdin bodies.

**Uncertain-mutation fencing: whole-class closure.** Every
DNS ACL withdrawal flows through ONE enforced boundary:
`withdraw_rule_proven` (plain removal, a single `--force` retry on a
positive duplicate-match refusal, proven-absence classification — any
other nonzero exit is UNPROVEN, never success) and, for EVERY path that
retires a destination's authorization — the refresh removal phase, the
reject-repair pre-pass, the lapsed-grant sweep, reconcile, drain, the
expiry lease, and restart recovery alike — `enforce_destination_withdrawal`, which confirms the
canonical destination-wide fence by re-observation BEFORE the first
withdrawal when the destination's final live authorization is leaving
while a broadening mutation is unresolved, proves every allow absent
before touching companions, and removes companions last. An allow that
will not withdraw fences the destination (the caller's own fence
allocation family) and fails — companions are never removed while an
overlapping allow might still be installed.
Mutations are classified by PERMISSION EFFECT, not by verb.
BROADENING mutations (allow adds; fence removals) carry a durable
request-unique identity allocated from the marker-resident `next_request`
counter BEFORE issuance — the allocation is crash-durable, so an
interrupted refresh's retry (rotation and daemon-side-lost-rule restore
alike; the restore case is detected by comparing committed rules against
the observed ACL) never reissues an identity an in-flight request may
still carry — and are journaled in the crash-durable marker before
issuance and retired only on definitive evidence (clean exit-0, a
positively-evidenced daemon rejection, or observed presence followed by
withdrawal). NARROWING mutations (reject/fence adds; allow removals) are
deadline-bounded and readback-verified but need no journal: a deferred
narrowing apply only delays or over-applies a denial, generation-scoped
companion tags keep a deferred companion removal from striking a newer
companion, and a daemon-reported absence is already the goal state.

Fences are PREVENTIVE: before any broadening allow is issued for a
destination that is not otherwise effectively authorized, a
destination-wide deny fence is installed and confirmed; if the fence
install fails the allow is never issued, and a daemon crash after issuance
or a deferred daemon-side apply always lands behind the fence. Fence
necessity derives from the COMPLETE effective destination authorization —
any live planned grant of any name, or a covering static CIDR — so a fence
never overrides an unrelated legitimate grant, and the fence returns
before the final authorization disappears because deny adds precede
removals. Fence releases are themselves journaled broadening removals; a
fence needed again while its release is unresolved is re-issued under a
fresh epoch, so a deferred removal can strike only the old identity.

Expiry is enforced independently of operation completion by the
enforcement-level lease: every boundary entry
arms the per-sandbox lease OWNER — a mutex/condvar pair that is the sole
linearization point for renewal versus withdrawal; the armed obligation
set is fsync'd to a durable record on EVERY arm and settle — and a
watcher carrying no cancellation permit. Arming MERGES into the durable
ledger: a fresh owner loads the persisted obligations before
merging (it can never overwrite obligations it never saw), a re-arm
supersedes only the identities it actually carries, and every OTHER
obligation — overdue-unsettled included — stays armed until it SETTLES:
expiry makes an obligation due, not settled. The reader and the writer
share ONE bound: two identities per policy domain (the live
set plus historical identities whose settlement is not yet proven, so a
policy at the domain bound rotating every identity at once still fits);
the writer refuses beyond the bound rather than persisting a ledger the
reader would reject, and an oversized or undecodable ledger fails
recovery CLOSED. Request identities are never recycled: the
persisted generation history survives every settlement rewrite, so a
re-grant always carries a FRESH generation and durable
positive-withdrawal evidence recorded for a retired identity can never
"prove" a new issuance. At each absolute expiry the
owner settles exactly those identities through the enforced withdrawal
boundary — mid-stall, pre-commit, and retry-safe because tags are
request-unique — while planning independently refuses to retain expired
grants and records their revocations durably. A renewal re-arms the same
identity under the owner lock, so a superseded expiry can never fire
against a renewed grant (an epoch recheck alone can race here).
Because the whole settle runs under the owner lock, no refresh can
interleave between the owner's observation and its withdrawals. When the
destination's FINAL live authorization expires while a broadening
mutation for it is unresolved (journaled in the revocation marker), the
boundary restores or confirms the canonical fence BEFORE withdrawing —
the destination never sits open between the last allow's expiry and a
deferred apply. An expiry-time observation failure (transport error
reading the ACL, an unreadable marker) settles NOTHING: the obligation
stays armed and is retried until the withdrawal proves out. Fences the
lease installs carry a separate tag family with epochs from a durable
lease counter the owner alone writes — the lease never enters the
refresh's marker read-modify-write. Settlement IS a lifecycle state
transition: the settle itself — in-process watcher and
restart recovery alike — rewrites the persisted DNS state and network
plan to the post-settlement truth BEFORE the obligations retire, so a
later readiness or reconnect with no refresh in between verifies against
the settled reality, never against a stale pre-expiry plan. The rewrite
is DERIVED, never copied from the live ACL: recorded plan
minus the proven-settled identities, plus the settlement's own fences,
plus canonical fences still observed on armed destinations — and the
live ACL must match that derivation EXACTLY (direction and rule state
included) or the settlement refuses, the obligations stay armed, and
readiness stays closed: recovery never ratifies unrelated drift. Process
restart is covered by the durable obligations: network verification
(reconnect and readiness alike) first recovers the persisted obligations
and settles every overdue one through the same boundary — the recovery
runs BEFORE the effective-ACL equality check — rearms the surviving
grants' watcher, and only then may the effective ACL verify; a
settlement failure refuses readiness closed. The lease's other durable record is the per-sandbox
positive-withdrawal evidence log (fsync'd whole-record rewrite, sole
writer under the owner lock, cleared with the marker): a POSITIVE lease
withdrawal of a request-specific allow identity is recorded there as
definitive evidence that the uncertain request completed — the lease
observed the rule and removed it, and a request completes at most once —
so a journaled uncertain-allow entry for that exact identity retires
(reconcile, or the commit-time drain) instead of fencing readiness
forever. This closes the race where the lease and the killed CLI's own
withdrawal both fire at the grant's expiry: whichever removes the rule,
the entry provably retires and the fence releases. A fence is protection
only as its COMPLETE canonical identity — enabled, reject, the exact
destination, no protocol/source/port narrowing: a narrowed or disabled
quarantine found where a fence is needed is repaired (removed and
reissued under a fresh epoch), never trusted. Grant deadlines are
ABSOLUTE and carried end to end: the issuance budget and the liveness
recheck are computed immediately before each allow issuance (preventive
fencing and journaling consume wall clock against the deadline), and the
fence-release phase re-verifies the authorizing grant is still live
before removing its protection. On top of the lease, every operation is
deadline-bounded: adds carry the grant-lifetime budget, narrowing
withdrawals are bounded by the earliest working grant's deadline measured
at pass start (the lease enforces the absolute deadline independently, so
an overrunning narrowing withdrawal is safe), and the dnsmasq publication
carries the earliest working grant's remaining lifetime, all capped by
the host call timeout.

Deadline enforcement is separated from the
potentially slow cleanup: the settle fences EVERY due,
otherwise-uncovered destination before any withdrawal is attempted — and
re-checks for newly-due destinations before every withdrawal round — so
an expired destination is denied at its own deadline even while another
destination's removal is stalled; each withdrawal carries a budget
derived from the next live armed expiry (capped at 20s), after which the
removal is abandoned Unproven and the obligation stays armed for retry.
A clean expiry leaves nothing behind: once the allow is proven withdrawn
and no broadening mutation is unresolved, the deadline fence is
withdrawn again (deny-direction, best-effort — an unproven removal
leaves over-denial the derivation carries). Renewal-time fence release
is linearized the same way: stale lease fences are released only under
the lease owner lock, only for a destination with no due armed
obligation, and only after the renewed allow is re-observed installed
with a still-live grant — an expired destination is never reachable
unfenced, and a fresh observation can never be retired by stale
decisions. Every re-add is a NEW issuance: a renewal whose
rules verified still installed keeps its identity, but anything re-added
— a restore in the reject-repair pre-pass, a deferred rule landing
behind a fresh observation, a re-grant after teardown — is planned under
a request-unique generation from the durable counter, floored above the
merged generation history, pending-mutation identities, and the
tombstoned floors of torn-down incarnations, so withdrawal evidence
scoped to an exact issuance can never retire a later request's journaled
entry; every committed issuance (first grants included) is recorded in
the persisted generation history, and two policy names colliding in the
32-bit rule-identity hash are rejected before any mutation. Both
lifecycle writers — the refresh commit and the settlement rewrite —
commit through ONE serialized boundary: the lease owner's
commit lock, under which the writer re-reads the current durable record,
merges the generation history monotonically, validates the derivation
against the live ACL BEFORE persisting anything, and writes the DNS
state and plan together; lifecycle temp files are writer-unique so one
writer's stale-temp recovery can never unlink another's active write.
The lease dies with the sandbox: teardown — after the
ownership-fenced deletions, so a stale teardown refused by those fences
never reaches it — tombstones the identity history (per-name generation
floors plus a global request floor folded from the armed obligations'
identities and the durable request counter), stops and unmaps the lease
owner, and durably retires the obligations, the withdrawal evidence, and
the fence-epoch counter; recovery treats obligations whose ACL is gone
as moot, so records left by older builds never block a recreate.

The expiry fence for an INITIAL grant is computed statically at
construction: one `dns_lease_entry` constructor arms every
obligation with the destinations not covered by a static grant, so an
initial grant whose withdrawal fails at expiry is fenced by the lease —
not left to whichever path happens to notice first. Every serial lease
operation carries a deadline: the withdrawal boundary takes a
per-operation budget capped from the settle round's deadline, so a
stalled companion removal or an unproven fence withdrawal can never
delay the next expiry; a round that cannot prove its cleanup keeps the
destination fenced and the obligation armed for retry instead of
retiring it with stranded deny-leftovers. Revocation fencing is
permit-independent: the enforcement path clones the daemon
client free of the caller's cancellation permit, so revoking a permit
mid-flight cannot cancel the fence install that makes the denial real.
The INITIAL allows issue through the same journaled, fenced,
tombstone-aware DNS mutation boundary as every later refresh:
create bootstraps the base ACL only, then publishes its grants through
the shared boundary and verifies against the boundary's committed
record; an interrupted initial issuance fails the create closed (the
pending-mutation marker refuses readiness), and the rollback PRESERVES
the marker so the retry's boundary reconciles the deferred daemon-side
apply instead of meeting it unprotected — the old destination is never
effective and its identity stays tombstoned. A refused lease arm leaves
the owner unchanged: the candidate is merged, validated, and
persisted BEFORE anything is published, so a bound- or
persistence-refused entry never becomes settle-able state. And a
stale-snapshot commit cannot resurrect a settled grant: the
commit revalidates its refreshed rules against the live ACL, dropping
anything another lifecycle writer already settled between the snapshot
and the commit.

Lease deadlines now
propagate through EVERY owner-lock-held operation: the
watcher's preliminary read is bounded by the next live armed expiry,
the settlement's commit-lock wait and under-lock ACL read share one
absolute deadline measured from the round, the refresh's owner-lock
re-observation is budgeted by the live grants, and the withdrawal
primitive converts its budget to one absolute deadline that the plain
removal and a duplicate-match `--force` retry share — the remainder is
recomputed before every subprocess, so no stalled read, commit wait, or
delayed retry can delay the next expiry's fencing. Unresolved mutations
survive teardown and ACL name reuse: the pending-mutation
journal is never purged with the sandbox, and a create on a fresh
same-named incarnation converts an unobservable pending allow into a
STANDING fence obligation carried by the marker — installed before
anything broadens, released only through the journaled path once the
policy authorizes the destination again — so a deferred daemon-side
apply can only ever land behind the fence, while clean teardown and
recreation stay usable (a standing-only marker no longer blocks
readiness; unresolved pending entries still do). Coverage for an allow
withdrawal means a SURVIVING VERIFIED authorization: an
installed allow whose entire reject-companion group is observed and not
scheduled for removal this pass — never desired-answer membership, and
never the identity being retired or repaired — so a refused withdrawal
on a destination whose companions are missing applies the quarantine
instead of opening the resolver path. The commit refuses unexplained
loss: the revalidation compares direction-aware rule
identities against the live ACL and rejects any missing rule the
durable plan still claims — only a proven lifecycle settlement (which
rewrote the durable plan first, under the same serialized locks)
explains an absence — persisting nothing and keeping the marker instead
of collapsing the trusted rule set onto a corrupted live ACL. And owed
withdrawal evidence flushes on EVERY settlement attempt, ahead
of any new withdrawal, so a recovered store lets the journal and
obligation retire without waiting for another grant lifecycle event —
retirement still conditional on durable proof.

Authorization coverage, fence release, and
evidence durability now sit behind a single complete boundary each.
Readiness refuses while ANY identity's revocation is owed to the live
ACL, not only while pending mutations exist: a crash between
the last removal and the commit leaves `pending` empty and `revoked`
owing the denial to the durable records, and only a full commit clears
it. Standing fence obligations keep their exact unresolved identity
across reauthorization: authorization SUPPRESSES the fence at
planning time but never retires the obligation — only positive
withdrawal evidence for the preserved identity does — so a same-
destination reauthorization followed by an expiry re-fences the
destination (the settle keeps its deadline fence when a standing
obligation covers it) and a late apply of the original identity can
only land behind a fence. Refresh-family fence releases for still-
authorized destinations move OUT of the pre-add removal pass:
the fence comes down only in the post-add release phase, behind a
re-observed, complete, live replacement authorization (allow plus full
reject-companion group, grant unexpired, no settlement due), under the
lease-owner lock — planned answers are never release evidence. The
lease's own fence releases are journaled in a dedicated release journal: every removal is recorded before issuance, an unproven
removal keeps the identity listed, and no later adoption may trust that
exact fence — a fresh epoch is issued instead, because its deferred
daemon-side removal could still complete. Fence epochs survive teardown: the teardown retires the obligation ledger but preserves the
fence-epoch counter, the withdrawal evidence, and the release journal,
and the identity tombstone floors the epoch so a recreated sandbox
continues the sequence. Expiry coverage is an OBSERVED, COMPLETE,
SURVIVING rule group — never an unexpired armed obligation,
which proves nothing about a surviving authorization; a failed coverage
read fails closed (fenced). The commit gate refuses ANY unexplained
loss: a tolerated absence now requires affirmative settlement
evidence (withdrawal evidence for the rule's own group or its
destination), so a newly installed rule deleted underneath the pass
refuses exactly like a previously durable one. Positive withdrawal
evidence is durable the moment the proof exists: an append-
only, fsync'd evidence log is written inside the withdrawal boundary
before any later fallible step can discard the in-memory proof, so a
failed post-removal read or a crash can never lose the only proof a
retirement will ever get. Recovery spawns the autonomous retry watcher
BEFORE propagating an initial settlement error — a refused
readiness does not stop a running VM, so the retries that enforce its
expirations must not depend on another API call. And due destinations
are fenced BEFORE any preliminary observation: a blind,
permit-free, bounded pre-fence at the top of the watcher's due branch
and of every settlement round installs the deadline quarantine first,
so a stalled read, coverage observation, or owner lock can never leave
an expiring destination unfenced past its own deadline.

Fence release checks adoption journals, release-phase deadlines,
coverage lifetimes, and blind-fence reconciliation. Every fence-adoption
site excludes identities with an unresolved release in EITHER journal: the refresh's preventive and at-issuance adoption checks now
read the lease's `.lease-releases` journal exactly like the shared
withdrawal helper always did, and lease fences withdrawn as companions
of a losing destination are journaled there before issuance and retired
on proof, so a release-uncertain fence can never be adopted and removed
around an uncertain allow. The owner-locked release phase carries ONE
absolute deadline — the earliest armed expiry across the pass's grants
and the lease's obligations: a stalled release can consume that
deadline, but no subsequent release receives a fresh, longer budget;
past the deadline the remaining fences stay and the phase yields the
owner lock to settlement. Authorization coverage additionally requires
the covering grant to be UNEXPIRED, rechecked at every decision: two complete-but-expired groups sharing a destination never
suppress each other's quarantine. And a blind deadline fence over a
destination with a VERIFIED live covering grant is reconciled away at
once, independently of the expiring identity's withdrawal succeeding: the release runs through the same journaled, deadline-bounded
path as a clean-expiry fence release, so the surviving grant's traffic
is denied only for the reconciliation delay.

Pre-fencing uses deadlines, an expiry-keyed cache, effective-authorization
coverage, fail-closed release journals, and commit-last revocation retirement. The blind pre-fence is
ONE deadline-aware, destination-deduplicated boundary: each
pass derives a single absolute deadline from the earliest FUTURE armed
expiry, attempts one tightly bounded fence add per destination —
most-recently-expired first — and stops at the first failure or at the
deadline, so a multi-address grant's stalled adds can never delay the
discovery and fencing of another destination's expiry; the watcher's
re-entry on any observation failure makes that discovery continuous.
The pre-fence cache is keyed by the armed EXPIRY: a
same-identity renewal always re-arms a later deadline, so the
superseded cache entry can never suppress the blind fence the next
expiry needs — and the withdraw-then-retire path is guarded by owed
evidence rather than cache invalidation, so a settle never re-fences an
identity it has just withdrawn. Coverage is ONE effective-authorization
predicate shared by refresh planning and settlement: a
complete, ENABLED rule group — fence tags excluded, the withdrawing
identity excluded — whose armed entry's name is not REVOKED in the
durable marker, so a revoked grant's surviving-but-unwithdrawable group
never stands in as authorization for a sibling's expiry. The lease
release journal fails CLOSED: an unreadable or undecodable
journal is an explicit error — every adoption gate treats unknown
release history as "nothing is adoptable" and protects the destination
under a fresh identity, and no fence release is ever issued while its
removal cannot be journaled. And revocation retirement is strictly
POST-COMMIT: only a durably committed state retires a denial,
so an interrupted re-grant leaves the revocation evidence in place to
filter the stale state out of every later transient retry. With these,
the closure table below also covers unreadable release journals,
revoked-but-unexpired coverage, renewed pre-fence cache entries, and
stalled pre-fencing itself.

Composed failures require one invariant per enforcing boundary. IDENTITY: every new allow
issuance — the first grant included — allocates its generation from the
crash-durable per-sandbox request counter BEFORE any mutation is
attempted, and identities are preserved only for verified
still-installed renewals; a crash between the journaled
acceptance and the state commit, followed by teardown and recreate, can
therefore never re-issue the interrupted identity, so same-destination
withdrawal evidence from the OLD incarnation cannot retire the NEW
incarnation's standing fence obligation. DEADLINE: each settlement pass
derives ONE absolute deadline from the earliest armed expiry BEFORE
pre-fencing, and the preliminary observation read budgets from that
same instant; when pre-fencing consumes the budget past a
second expiry, the read is skipped (not re-budgeted) and the pass
re-pre-fences the newly-due destinations before any more observation,
so a stalled fence add plus a parked read can never leave a grant
allowed and unfenced past its own deadline. SAFETY: an expiry fence is
released only on a destination-wide proof — either a verified
live authorization covers the destination or EVERY observed enabled
allow covering it is proven withdrawn; a surviving group installed by a
REVOKED sibling (itself awaiting a failed withdrawal's retry) is an
unauthorized survivor, so the expiring identity's clean withdrawal no
longer releases the fence over it. With these, the closure table below
also covers crashed first issuances, pre-fence stalls composed with
parked observation, and partial sibling withdrawals.

Each regression composes a deferred daemon-side effect with a
cleanup/confirmation that retired its durable record too early.
IDENTITY: the request-identity high-water mark is MONOTONE and
independent of marker retirement — `next_request` counts every
allocation, fence epochs included, but the committed generation history
records only allow generations, so clearing a drained marker folds the
counter (and any surviving pending identities) into the identity
tombstone BEFORE the marker file is removed; a later allocation can
never reissue a fence epoch whose deferred, since-retried removal is
still in flight and names its rule by the exact identity string.
AUTHORIZATION: an ensured fence is released only behind a CURRENT
authorization — the release gate is the shared one (an
observed, complete group of an UNEXPIRED, non-revoked grant), so a
confirmation cached at add time is revalidated at release time; when a
second address's uncertain issuance revokes the grant mid-pass and the
sweep removes its installed group, the stale confirmation can no longer
release the fence around another grant's still-unresolved allow for the
same destination (a genuinely live overlapping grant still releases —
the live-coverage inverse is retained). DEADLINE: recovery enters the deadline
boundary BEFORE its first ACL probe — after a process restart
the durable obligations are adopted, the owner goes live, and the
permit-independent pre-fence fires before any observation; the absence
probe itself is bounded by the same deadline the watcher would use, so
a stalled probe is merely an observation failure (the overdue
destinations are already fenced and the watcher retries), never a 120s
host-timeout window in which expired allows stay effective on a running
VM.

The fence-release boundary is
enumerated and EVERY site routes through the shared destination-safety
discipline. The complete enumeration: (1) the post-confirmation ensured
release (gated on a CURRENT live authorization, revalidated against the
pass's own revocations); (2) deferred refresh-family
releases (only behind a verified installed replacement); (3)
reconciliation retries of journaled releases (gated);
(4) lease-side fence withdrawals (journaled pre-issuance, retried under
the round deadline); (5) stale-fence sweep releases
(gated on the pass's authorized/static destinations); (6) the commit-
time drain's retries of journaled refresh-fence releases (subject to the same gate); (7) adoption
decisions, which are releases-by-reliance (strict on BOTH release
journals). IDENTITY: the tombstone floor moved
INSIDE the shared request allocator — only the allow-generation
allocator read it before, so a fence-only allocation (a revocation-only
pass whose allow withdrawal is refused) could reissue a retired fence's
epoch whose deferred removal was still in flight; now every allocation
is floored by the tombstone's high-water mark, and an unreadable
tombstone fails the allocation closed. DEADLINE: recovery carries ONE
absolute deadline across pre-fencing AND the absence probe —
the watcher's shared deadline discipline, applied to recovery: the
deadline is captured before pre-fencing, the probe gets only what
remains, and an exhausted deadline re-discovers and fences the
newly-due destinations before any observation (pre-fix a pre-fence that
consumed a second grant's remaining lifetime excluded that grant from
the recomputed gap and re-armed the probe with a fresh 20s budget while
the expired allow stayed effective — the owner lock held and no watcher
running). AUTHORIZATION: a journaled fence-release RETRY in
reconciliation goes through the same destination-wide gate as every
other release: an unresolved old allow and a pending release
can coexist after a temporary reauthorization, and releasing on sight
would drop the fence while the stale apply is still free to land — so
the retry verifies CURRENT authorization (a covering static grant, or a
complete observed group of an unexpired, non-revoked grant) and
otherwise installs a RELIABLE replacement fence (fresh epoch, read
back) BEFORE removing the old identity; a failed replacement keeps the
old fence installed and the entry pending — over-denial only, never
exposure. ADOPTION: an UNREADABLE refresh-release journal disqualifies
refresh-fence adoption, matching the lease-release journal's
treatment — the release-pending set is then unknown, so any observed
refresh fence could be one whose deferred removal is still in flight;
the boundary installs a fresh lease-family fence instead, and a
readable marker with an empty journal still adopts (inverse retained).

Recovery belongs to the host-startup boundary, and the consumed-identity
high-water mark is enforced AT the marker-write boundary itself. RECOVERY OWNERSHIP: the runtime observes or starts a sandbox through exactly five
entry points — `sandbox_inventory` (startup census), provisioning
verification (`verify_provisioned_enforcement`), network apply
(`apply_sandbox_network`), reconnect (which verifies), and refresh
(which arms obligations directly). Recovery is OWNED by the startup
census: `sandbox_inventory` recovers and rearms EVERY sandbox's durable
obligations first, enumerated from the on-disk ledgers
(`dns-revocations/*.lease.json`) — no daemon round-trip is needed to
learn what is armed, so recovery completes before the census's own
daemon observations (instance listing) that could stall; the other
entry points delegate to the same per-sandbox boundary (verify and
apply recover before accepting enforcement; refresh arms). Pre-fix,
startup with a running VM and an expired lease reported the sandbox
Ready without a watcher: the expired allow stayed effective until some
unrelated operation happened to recover. Verification additionally
recovers BEFORE its ordinary network/ACL reads — those reads carry no
deadline discipline and can stall, and recovery's blind pre-fence needs
no observation, so an overdue destination is fenced even while every
outer read is parked. COUNTER MONOTONICITY: reconciliation held
a marker snapshot read before its loop; its replacement-fence branch
allocates durably (advancing `next_request` on disk), and the
retirement write-back of the stale snapshot rolled the counter backward
— the tombstone floor cannot see the regression because the freshly
consumed epochs were never tombstoned, so a crash/retry could reissue
an allocated fence epoch whose deferred removal is still in flight. The
complete marker-write enumeration: `persist_dns_revocation_record` is
the SINGLE write boundary, reached from exactly seven sites — the
request allocator, the journal-pending write, the revocation extension,
the reconciliation write-back (the offender), the pending-retirement
write, the drain settlement, and the commit clear — plus ONE deletion
boundary (`clear_dns_revocations`, which folds the counter into the tombstone). The invariant is now enforced inside the single boundary: every
write clamps `next_request` to the maximum of the caller's value, the
on-disk record's, and the tombstone's high-water mark, and an
undecodable existing marker or tombstone fails the write closed — no
caller, present or future, can roll the consumed-identity high-water
mark backward.

Recovery fans out before any settlement
is awaited, issuance revalidates coverage instead of trusting the
pass-start cache, and startup recovery enforces RECORDED revocations,
not only elapsed TTLs. RECOVERY FAN-OUT:
`recover_all_dns_expiry_obligations` ran serially and returned on the
first error, so sandbox A's malformed ledger (or a stalled settlement)
prevented sandbox B's owner and watcher from ever starting — one
sandbox's failure starved every later sandbox's autonomous lease
enforcement. Recovery is now split: the PREPARE phase (ledger read,
obligation adoption, owner liveness, watcher spawn — nothing fallible
against the daemon) runs for EVERY enumerated sandbox before ANY
settlement, and the fallible SETTLE phase then runs per sandbox with
each error isolated and aggregated (naming the failed sandboxes) after
all settlements complete. ISSUANCE COVERAGE: the issuance
skip-fence check trusted `confirmed_dests` — captured when the pass
read the ACL — without checking the authorizing grant's expiry,
revocation, or continued installation. A pass stalled past an
authorizer's expiry (the lease cleanly withdrew it) still found the
destination in the stale cache and issued a re-grant's allow with NO
preventive fence; a crash or deferred daemon-side apply then left the
allow effective with no confirmed authorization behind it. Issuance now
authorizes only through (a) a covering static CIDR, (b) an allow THIS
pass installed and confirmed (current by construction), or (c) the SAME
current-authorization gate the release paths use — obligations
re-read from disk at issuance (fail closed on an unreadable ledger),
revocations from the durable marker plus the pass's own, complete
observed groups, unexpired and non-revoked. Expiry is clock-based and
revocation is journaled before any mutation, so the fresh read is
synchronized with settlement: the watcher withdraws an identity only at
its expiry, which the gate excludes by the clock even while the
settlement's commit still waits on the pass's lock. The remaining
`confirmed_dests` consumers are safe by construction: the in-pass
insertions are this pass's own installations, the withdrawn-allow sweep
de-authorizes destinations the pass itself removed, and the post-add
fence-RELEASE gate re-verifies grant liveness from the pass's
expiries before releasing — a stale hit there SKIPS a release, which is
the fail-closed direction. RECORDED-DENIAL RECOVERY: recovery
settled only obligations whose TTL had elapsed. A denial journaled into
the durable marker (NXDOMAIN) with a crash before the mutation left the
denied address reachable until the old TTL, and the census then
reported readiness because nothing enforced the marker. Recovery's
settle phase now enforces every recorded revoked name's destinations
through the shared withdrawal boundary (fence-first, lease-fence
identity family, the pass deadline) before readiness can report, and
preserves the marker and obligations until a committing refresh — the
denial evidence outlives the crash that deferred its mutation.

Issuance authorization is judged against
the rule set that SURVIVES the pass, recorded revocations are
immediately-due obligations in the autonomous enforcement boundary, and
denial recovery derives coverage from the recorded static policy and
verified surviving groups. SURVIVING-SET ISSUANCE: the earlier coverage gate
revalidated obligations against a fresh ledger read, but the RULE SET it
judged was still the pass-start observation — during a partial rotation
{X,Y}→{X,Z}, the old generation's complete group for X is still
installed when Z's issuance is gated, so the group THIS pass was
withdrawing authorized its own replacement; and the destination-only
`issued_this_pass` cache never invalidated on a later expiry or
revocation, so a grant revoked mid-pass still legitimized later
issuances on its destinations. One boundary now: authorization requires
a complete enabled group in the pass-SURVIVING rule set (the observed
set minus every rule this pass retires, plus every rule this pass has
installed and confirmed), unexpired by the clock and non-revoked by the
durable marker plus this pass's own revocations, matched to the request
identity's own armed grant; the destination-only cache is gone.
AUTONOMOUS DENIAL RETRIES: recovery's denial enforcement was
bounded by the API call's own pass deadline — a stalled probe could
consume all of it, and the watcher ignored recorded revocations
entirely, so a denied grant could stay installed until its old TTL
elapsed. Recorded revocations are now due IMMEDIATELY in the same
autonomous boundary as expiries: the marker's revoked names intersected
with the armed obligations (identity-precise to the generation the
denial was journaled AGAINST, recorded in the marker at journal time —
a re-grant's fresh generation belongs to the committing refresh, which
clears the marker — and excluding pairs whose withdrawal evidence is
durable or owed) feed
the blind pre-observation fence, the settlement phases, and the
watcher's due check and short tick — the withdrawal retries until it
proves out, no API call required. An unreadable marker yields no pairs
at this boundary (the withdrawal boundary itself fails closed on the
same read, and readiness already refuses on it, so denying live grants
on a storage error would only block legitimate traffic); an unreadable
state enforces. COVERAGE-AWARE DENIAL RECOVERY: the refusal
boundary derived `covered = false` unconditionally, quarantining
destinations a legitimate authorization still covered. Coverage is now
the observed, complete, non-revoked surviving group OR the recorded
policy's static CIDR grants (persisted as `policy_cidrs` on the plan
record — never the resolved grant expansion, whose DNS answers are
themselves expiring authorizations), in both the fence-reconcile phase
and the withdrawal gate: a covered destination gets no quarantine when its
withdrawal is refused and has its blind pre-fence reconciled away
through the journaled release path; an uncovered destination is
quarantined and stays fenced until the withdrawal proves out.

Denials record every outstanding
identity, lease recovery is scoped to the owning project, the
commit-time drain joins the shared release boundary, and pending-allow
reconciliation derives real coverage. DENIAL IDENTITY SET: a
denial recorded only the COMMITTED generation per name, so a re-grant
that installed and published its fresh generation and then failed
BEFORE committing (durable state one generation behind) left the live
uncommitted identity invisible to autonomous recovery — the watcher
skipped it and the denied destination stayed effective until its TTL.
The marker now journals, per denied name, the SET of every generation
outstanding at journal time: the committed generation UNION every armed
identity in the durable lease ledger (an unreadable ledger fails the
journal write closed — a denial is never recorded with an incomplete
identity set), and the autonomous boundary enforces a pair when its
entry's generation is IN the recorded set. A generation issued AFTER
the denial is absent from the set and stays exempt — it belongs to the
committing refresh. RECOVERY PROJECT SCOPE: the durable
revocation marker and lease ledger carry their owning project (legacy
records without the field are claimed by the `default` project alone),
and `recover_all_dns_expiry_obligations` filters ledgers by project
BEFORE any owner activation or watcher spawn — two daemons sharing one
host state root can no longer adopt, settle, or purge each other's
obligations (a foreign ledger is left byte-for-byte untouched; an
undecodable ledger is still reported, never silently stranded). The
per-sandbox recovery read refuses a foreign ledger fail-closed, the
in-memory owner map keys on the project, and the blind mutation
boundary re-checks the ACL's project tag alongside the sandbox tag.
COMMIT-DRAIN RELEASE GATE: the commit-time pending-mutation
drain removed journaled refresh fences on sight — no authorization
check, no replacement, no owner synchronization, no deadline. It now
routes through the same shared release boundary as reconciliation
(current authorization, else a verified fresh-epoch replacement
installed BEFORE the old identity's removal, under the lease-owner
lock, bounded by the remaining lifetime of the pass's grants), making
the release enumeration complete at seven sites; an
expiry-during-drain or a failed replacement keeps the old fence and
the journaled entry, and an exhausted deadline simply skips the retry.
RECONCILE COVERAGE: pending-allow reconciliation passed
`covered = false` unconditionally, so a REFUSED withdrawal of a stale
pending allow installed a destination-wide refresh fence even when a
complete live sibling group still authorized the destination —
blocking the legitimate sibling, and unreachable through coverage-aware recovery
(recovery's coverage-aware path never removes refresh-family fences).
Coverage is now derived through the shared current-authorization
predicate, extended with an exclusion for the exact identity being
withdrawn: the stale rule's own group never legitimizes its
destination, a genuinely covering sibling keeps the destination
unfenced and reachable while the entry stays journaled for retry, and
an uncovered destination is fenced exactly as before.

Journaled releases are bounded by
every armed expiry, the drain hands its proven removals to the commit,
and a CNAME hop validates the current owner's complete record set
before advancing. RELEASE BOUND BY ARMED EXPIRIES: the shared
release boundary held the lease-owner state lock across its ACL reads,
replacement install, and removal under the caller's deadline alone —
reconciliation passes NONE, so a stalled daemon operation parked the
lock under the plain host timeout while an UNRELATED grant expired,
and that grant's watcher could not take the lock to fence the
destination: it stayed reachable past its lifetime. The boundary now
derives ONE absolute deadline from the caller's deadline AND the
earliest armed lease expiry (an unreadable ledger fails the release
closed — it simply does not happen), and yields the lock at expiry so
the watcher fences on time. DRAIN-TO-COMMIT SNAPSHOT: the
drain ignored its results, so a fence released by a drain retry stayed
journaled forever AND vanished between the pass's post-replacement
observation and the commit's live re-read — a journaled fence
withdrawal produces none of the lease-withdrawal evidence the commit
accepts, so the commit rejected its own drain's work as unexplained
rule loss. The drain now returns explicit outcomes: proven releases
retire from the journal at the drain, and the commit folds exactly
those identity+destination pairs into its expected snapshot — every
OTHER unexplained absence still refuses. CNAME HOP CONFLICT REJECTION: the chain walks (both A and AAAA) followed a CNAME and
validated only the TARGET's addresses, so an answer carrying
`a A 10.0.0.5` beside `a CNAME b` never had the A record examined — a
public answer for `b` laundered the protected address into an accepted
grant. The walks now reject an owner carrying BOTH a CNAME and address
records before advancing. The validation is PER-HOP (each reachable
owner's complete set as the walk visits it) rather than whole-answer
up front: the inline-chain contract is per-hop — only records owned by
a reachable name participate, so a stray unrelated record elsewhere in
the section never denies, matching resolver semantics — and the per-hop
placement closes the launder window at exactly the moment the walk
would otherwise skip the records.

The commit carries the drain's
replacement fences, every fence mutation proves ACL ownership first,
conflicting CNAME answers deny, and the pre-fence cache prunes to
armed triples. DRAIN ADDITIONS REACH THE COMMIT: the
commit-time drain reported only its proven RELEASES, so a replacement
fence the release boundary installed for an unauthorized (revoked)
destination — after the pass's observation — was live but named by no
durable record: the commit filtered it out of the persisted snapshot
and every later reconnect verification refused the sandbox. The drain
now returns additions alongside removals, the release boundary
authorizes generation-exactly (a fresh re-grant over a revoked name
releases its own fence while the denied generations stay fenced), and
the commit validates the complete derived multiset — installed PLUS
drain-added — against its live re-read. OWNERSHIP BEFORE EVERY FENCE
MUTATION: the blind pre-fence and the journaled release
boundary mutated the ACL without ever checking the sandbox/project
tags, so a same-named ACL retagged to a foreign sandbox could receive
fence adds and removals driven by this sandbox's lease obligations.
The pre-fence now attempts a tightly bounded (deadline-capped, never
more than 5s) ownership read first: a successful read proving foreign
tags vetoes the pass with ZERO mutations, while a stalled or failed
read falls back to the blind add — the pre-fence's whole purpose is
that a stalled read must never delay enforcement, and every later
mutation boundary re-checks ownership from its own successful read.
The release boundary checks ownership on the read it already performs
and refuses a foreign object before either its replacement add or its
removal. A settle-time sweep releases blind pre-fences whose pair went
quiet mid-settle (a concurrent withdrawal's durable proof landed
between the tick's due check and the settle's own): without it the
interleaving leaves an orphaned deny-all fence no future settle is
due to clean — destinations the settle already processed are skipped,
so the common path pays nothing. CONFLICTING CNAME TARGETS DENY: a reachable owner answering with two DISTINCT CNAME targets had
the walk silently select the first branch, leaving the other branch's
record set unvalidated — `a CNAME pub` beside `a CNAME priv` beside
`priv A 10.0.0.5` sailed through on the public branch in one answer
order. Both walks (A and AAAA) now reject distinct targets for one
owner outright; identical duplicates are one RRset and collapse to a
single hop with the tighter TTL. PRE-FENCE CACHE PRUNING: the
blind-fence dedup cache grew by one (identity, destination, expiry)
triple per lifetime fencing event — unbounded for a long-lived
sandbox. It now prunes to currently-armed triples under the owner lock
at every pre-fence pass; an identity mid-settlement stays armed until
retirement (guarded by owed evidence), so the release-then-retire
path still never re-fences mid-settle, and a renewed identity is
blind-fenced again at its second expiry (its fresh triple differs).

The orphan-fence sweep is bound by
the next armed expiry, and retirement requires an attempted
withdrawal. SWEEP BOUND BY ARMED EXPIRIES: the earlier sweep ran
under the lease-owner lock with a FRESH 5s budget for its ACL read and
for every orphan fence removal, so a grant expiring mid-sweep waited —
repeatedly, one 5s stall per orphan — while the sole watcher could not
resume fencing; worse, the settle's retirement pass re-read the clock
AFTER the sweep and retired the newly-expired obligation UNPROCESSED —
no fence, no withdrawal, and the armed ledger going quiet disarmed the
watcher for good: the allow stayed effective forever. The sweep now
derives ONE absolute deadline from the earliest future armed expiry
(exactly like the round deadline), skips outright when every blind
fence was already handled, and stops at the deadline; when the sweep
is cut short (killed at the deadline or failed mid-release), deadline
fencing resumes IN the same boundary before any retirement; and an
obligation may retire only when every destination's withdrawal was
attempted by this settle OR already carries durable withdrawal
evidence — an entry that crossed its expiry after the last round's
selection has neither, so it stays armed and is fenced and withdrawn
by the next tick.

Preserved fence obligations are
enforced on EVERY recreation, domain-free ones included. STANDING
FENCES ON DOMAIN-FREE RECREATION: teardown preserves a
standing fence obligation (and the pending-mutation journal) while
removing the ACL and the expiry ledger — but the create-time
publication boundary returned early whenever no DNS answers needed
publication, so a domain-free recreation never reinstalled the fence,
readiness passed (a standing-only marker does not gate it), and the
delayed old allow could land EFFECTIVE against a policy that denies
the destination, with no expiry watcher armed to withdraw it. The
publication boundary now enforces preserved obligations through the
shared enforce-and-commit boundary regardless of publication need: a
clean domain-free creation (no marker) keeps the cheap return, a
reborn incarnation under a NEW policy hash inherits the obligations —
the marker is re-scoped to the new generation (the old generation's
uncommitted revocations die with their ACL; the pending journal, the
standing fences, and the identity counter survive) — and the installed
fences are committed into the recorded plan the final verification
overlays and readback-verifies. A static CIDR that explicitly
authorizes the destination still suppresses the fence (never the
obligation), and the immutable reconnect path still verifies against
the persisted plan's committed fences.

Closure, resource by event:

| Mutation                           | Interrupted before issuance                                                       | Uncertain in flight                                                                                                                                                                                                                                                                                                                                                                                                                        | Deferred daemon-side apply                                                               | Daemon crash mid-request                               |
| ---------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Allow add (broadening)             | Durable identity allocated and intent journaled; preventive fence confirmed first | An uncertain outcome keeps the entry, the marker fences readiness, and the grant is never committed — unless the immediate best-effort withdrawal POSITIVELY removes the rule (clean exit 0: the request had already completed daemon-side, and a request completes at most once) or the expiry lease positively withdraws the exact identity (durable evidence log) — both are the same class of definitive evidence reconcile retires on | Lands behind the fence; after any retry its identity is stale and reconcile withdraws it | Fence was installed before issuance; nothing committed |
| Fence add (narrowing)              | Epoch allocated from the same durable counter                                     | Bounded; a failure fails the pass closed BEFORE any broadening                                                                                                                                                                                                                                                                                                                                                                             | Over-denial only; released once the destination is confirmed authorized                  | Same                                                   |
| Fence release (broadening removal) | Journaled pre-issuance                                                            | An unproven outcome keeps the fence installed and the entry journaled                                                                                                                                                                                                                                                                                                                                                                      | Can strike only the journaled identity; a re-issued fence carries a fresh epoch          | Fence stays installed; reconcile retries               |
| Reject companions (narrowing)      | Installed before their allow; generation-scoped tags                              | Bounded; repair withdraws overlapping allows first                                                                                                                                                                                                                                                                                                                                                                                         | Cannot strike a newer generation's companions                                            | Same                                                   |
| Allow removal (narrowing)          | Revocation marker written first                                                   | Bounded; daemon-reported absence is the goal state                                                                                                                                                                                                                                                                                                                                                                                         | Over-denial only; lease and readback converge                                            | Marker keeps readiness fenced                          |
| dnsmasq publication                | Bounded by remaining grant lifetime                                               | Unknown-outcome fails the refresh; cleanup revokes and withdraws                                                                                                                                                                                                                                                                                                                                                                           | Stale ANSWERS at worst, never stale EGRESS — the ACL is the enforcement boundary         | Nothing committed; state commits last                  |
| Marker / state persistence         | Marker precedes mutation; state commits last                                      | —                                                                                                                                                                                                                                                                                                                                                                                                                                          | —                                                                                        | Readiness refused while anything is pending            |

Expiry-lease closure, event by event, each with its
discriminating executable proof:

| Lease event                                                             | Guarantee                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Proof                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Grant RENEWAL re-arms an armed identity                                 | Linearized under the per-sandbox owner lock; the renewed allow survives its ORIGINAL expiry — proven against the withdrawal held IN FLIGHT at a barrier                                                                                                                                                                                                                                                                                                                                                                          | `a_renewed_grant_survives_its_original_expiry`                                                                                                                                                                                              |
| PROCESS RESTART with expired + live obligations                         | Recovery (in reconnect/readiness verification) settles the overdue identities through the enforced boundary, rewrites the persisted plan/state to the post-settlement truth, and rearms the survivors BEFORE the sandbox may verify Ready                                                                                                                                                                                                                                                                                        | `a_restarted_daemon_settles_expired_obligations_and_rearms_live_grants`                                                                                                                                                                     |
| FAILED EXPIRY OBSERVATION (ACL read transport error, unreadable marker) | Nothing settles; the fsync'd obligation stays armed and is retried until the withdrawal proves out                                                                                                                                                                                                                                                                                                                                                                                                                               | `a_failed_expiry_observation_preserves_the_obligation`                                                                                                                                                                                      |
| FINAL-AUTHORIZATION expiry with an unresolved broadening mutation       | The canonical fence is restored/confirmed and proven BEFORE the last allow is withdrawn; the deferred apply lands behind it; a clean expiry (nothing pending) or a covering static CIDR installs NO fence (inverse)                                                                                                                                                                                                                                                                                                              | `a_final_authorization_expiry_restores_the_fence_around_an_unresolved_mutation`; inverses `a_committed_grant_is_withdrawn_at_expiry_without_any_refresh` (clean expiry leaves nothing) and `a_covering_static_cidr_suppresses_the_fence`    |
| QUARANTINE DRIFT (narrowed/disabled fence where one is needed)          | The complete canonical identity is required; drift is removed and the fence reissued under a fresh epoch; a valid fence is adopted, never reissued (inverse)                                                                                                                                                                                                                                                                                                                                                                     | `a_drifted_fence_is_repaired_never_trusted` (adoption inverse in-test)                                                                                                                                                                      |
| GENERATION HISTORY across recovery                                      | Settlement never prunes request-identity history; a re-grant carries a fresh generation and stale positive-withdrawal evidence cannot retire its pending entry; exact-issuance evidence still retires it (inverse)                                                                                                                                                                                                                                                                                                               | `a_recovered_expiry_never_recycles_a_request_identity`                                                                                                                                                                                      |
| OVERDUE-UNSETTLED obligation at a re-arm                                | A fresh owner loads the durable ledger before merging; overdue obligations survive and settle with no further refresh; settled obligations retire, unrelated re-arms persist (inverses)                                                                                                                                                                                                                                                                                                                                          | `an_overdue_unsettled_obligation_survives_a_rearm`                                                                                                                                                                                          |
| UNPROVEN withdrawal on the refresh/reconcile paths                      | Every destination-level withdrawal routes through the enforced boundary: a failed revocation fences the destination, preserves the companions, and fails the pass; the fence releases and everything withdraws once the daemon behaves (inverses)                                                                                                                                                                                                                                                                                | `a_failed_refresh_revocation_fences_the_destination`, `a_failed_reconcile_withdrawal_keeps_the_fence`                                                                                                                                       |
| UNRELATED ACL DRIFT at settlement                                       | The lifecycle rewrite is derived from the trusted record and validated against the live ACL; drift refuses the settlement and the trusted plan is untouched; a clean ACL recovers (inverse)                                                                                                                                                                                                                                                                                                                                      | `recovery_refuses_to_ratify_acl_drift`                                                                                                                                                                                                      |
| EXPIRY AS LIFECYCLE TRANSITION                                          | The in-process settle commits the persisted state/plan transition before obligations retire; readiness/reconnect verify against the settled truth with no refresh in between; an unexplained extra rule still refuses (inverse)                                                                                                                                                                                                                                                                                                  | `a_settled_expiry_commits_the_lifecycle_transition`                                                                                                                                                                                         |
| OBLIGATION LEDGER BOUND                                                 | Reader and writer share one bound (2× policy domains); a bound-sized ledger (129 obligations) recovers after restart; an oversized ledger refuses closed (inverse)                                                                                                                                                                                                                                                                                                                                                               | `a_bound_sized_obligation_ledger_recovers_after_restart`                                                                                                                                                                                    |
| INITIAL-GRANT expiry fence                                              | The lease entry's fence set is computed at construction (destinations not covered by static grants); a failed initial-grant withdrawal fences at expiry; a covering static CIDR suppresses the fence (inverse)                                                                                                                                                                                                                                                                                                                   | `an_initial_grant_is_fenced_at_expiry_when_its_withdrawal_fails`, `a_covering_static_cidr_suppresses_the_initial_expiry_fence`                                                                                                              |
| DEADLINE-BOUND serial lease ops                                         | A stalled companion removal or an unproven fence withdrawal cannot delay the next expiry; the stalled round keeps the destination fenced and the obligation armed rather than retiring with stranded deny-leftovers                                                                                                                                                                                                                                                                                                              | `a_stalled_companion_removal_cannot_delay_the_next_expiry`, `a_stalled_fence_withdrawal_cannot_delay_the_next_expiry`                                                                                                                       |
| PERMIT-INDEPENDENT revocation fencing                                   | The enforcement client carries no caller permit; a permit revoked mid-removal cannot cancel the fence install; a working daemon releases everything (inverse)                                                                                                                                                                                                                                                                                                                                                                    | `a_cancelled_revocation_still_fences_the_destination`                                                                                                                                                                                       |
| INTERRUPTED INITIAL ALLOW                                               | The initial issuance goes through the journaled boundary: the create fails closed over the pending marker, the rollback preserves the journal, the deferred old apply never lands effectively, and recovery reissues under a tombstoned-generation floor                                                                                                                                                                                                                                                                         | `an_interrupted_initial_allow_is_fenced_journaled_and_never_effective`                                                                                                                                                                      |
| REFUSED LEASE ARM                                                       | The owner state is unchanged by a refused arm (bound or persistence refusal); the refused entry never settles and the shim sees no rule activity for it; a valid arm settles (inverse)                                                                                                                                                                                                                                                                                                                                           | `a_refused_lease_arm_leaves_the_owner_state_unchanged`                                                                                                                                                                                      |
| STALE-SNAPSHOT COMMIT                                                   | A refresh parked past another writer's settlement revalidates against the live ACL: the settled grant is dropped from the commit, never resurrected                                                                                                                                                                                                                                                                                                                                                                              | `a_parked_refresh_commit_cannot_resurrect_a_settled_grant`                                                                                                                                                                                  |
| DEADLINE PROPAGATION                                                    | A stalled preliminary read, a commit-lock wait, an owner-lock re-observation, or a slow duplicate-match `--force` retry is killed at the next live expiry; the second grant fences on its own deadline; everything retires once the daemon behaves (inverses)                                                                                                                                                                                                                                                                    | `a_stalled_preliminary_read_cannot_delay_the_next_expiry`, `a_stalled_commit_wait_cannot_delay_the_next_expiry`, `a_stalled_owner_lock_read_cannot_delay_the_next_expiry`, `a_delayed_duplicate_match_retry_cannot_delay_the_next_expiry`   |
| DEFERRED APPLY ACROSS TEARDOWN/NAME REUSE                               | The journal survives teardown; the recreate converts the unresolved mutation into a standing fence before readiness; the old apply lands behind it — never effective; a clean recreate stays usable (inverse)                                                                                                                                                                                                                                                                                                                    | `a_deferred_allow_landing_after_recreate_never_becomes_effective`, `teardown_preserves_unresolved_dns_mutations`                                                                                                                            |
| COVERAGE = SURVIVING VERIFIED AUTHORIZATION                             | A refused repair withdrawal on a destination whose companion is missing quarantines instead of trusting desired-answer coverage; the daemon behaving again completes the repair and releases the fence (inverse)                                                                                                                                                                                                                                                                                                                 | `a_missing_companion_is_not_coverage_for_a_withdrawal`                                                                                                                                                                                      |
| UNEXPLAINED LIVE-RULE LOSS AT COMMIT                                    | A rule deleted underneath a parked refresh refuses the commit — durable state and recorded plan stay byte-identical; the next refresh repairs against the still-trusted records (inverse)                                                                                                                                                                                                                                                                                                                                        | `an_unexplained_live_rule_loss_refuses_the_commit`                                                                                                                                                                                          |
| OWED EVIDENCE FLUSH                                                     | A one-shot evidence-write failure keeps the obligation armed past a successful withdrawal; restoring storage flushes the owed evidence and retires journal and obligation with no new withdrawal (inverse)                                                                                                                                                                                                                                                                                                                       | `owed_evidence_flushes_without_a_new_withdrawal`                                                                                                                                                                                            |
| REVOCATION OWED BLOCKS READINESS                                        | `pending` drained and only `revoked` owing the denial still refuses readiness and a restart alike; committing the denial clears the marker and readiness verifies (inverse)                                                                                                                                                                                                                                                                                                                                                      | `a_revocation_without_pending_mutations_still_blocks_readiness`                                                                                                                                                                             |
| STANDING OBLIGATION SURVIVES REAUTHORIZATION                            | The recreate fences the old destination; a same-destination reauthorization suppresses but never retires the obligation; its expiry re-fences the destination so the original deferred apply can only land behind a fence                                                                                                                                                                                                                                                                                                        | `a_deferred_allow_landing_after_recreate_never_becomes_effective` (reauthorization + expiry legs)                                                                                                                                           |
| FENCE RELEASE BEHIND VERIFIED REPLACEMENT                               | A re-grant whose replacement companions fail to install aborts with the old fence still standing; a clean retry releases it post-add (inverse)                                                                                                                                                                                                                                                                                                                                                                                   | `a_failed_replacement_never_releases_the_refresh_fence`                                                                                                                                                                                     |
| JOURNALED LEASE-FENCE RELEASES                                          | A fence removal killed mid-release leaves the identity journaled; the retry removes it and re-issues a FRESH epoch rather than adopting the release-pending fence; everything retires clean (inverse)                                                                                                                                                                                                                                                                                                                            | `a_crash_between_fence_releases_reissues_under_a_fresh_epoch`                                                                                                                                                                               |
| FENCE EPOCHS SURVIVE TEARDOWN                                           | Teardown retires the obligations but preserves the epoch counter and evidence; the tombstone floors the epoch and the recreate continues the sequence                                                                                                                                                                                                                                                                                                                                                                            | `teardown_retires_the_expiry_lease_and_tombstones_its_identities`                                                                                                                                                                           |
| COVERAGE = OBSERVED COMPLETE GROUP                                      | A longer grant whose allow was lost live never suppresses the shorter grant's expiry fence — the armed obligation is not an authorization                                                                                                                                                                                                                                                                                                                                                                                        | `an_unconfirmed_grant_never_counts_as_expiry_coverage`                                                                                                                                                                                      |
| NEWLY INSTALLED RULE LOSS AT COMMIT                                     | A companion installed by THIS pass and deleted underneath the parked commit refuses the commit (nothing persisted); the retry repairs (inverse)                                                                                                                                                                                                                                                                                                                                                                                  | `a_newly_installed_rule_loss_refuses_the_commit`                                                                                                                                                                                            |
| EVIDENCE DURABLE AT PROOF TIME                                          | The post-withdrawal re-observation read parked and killed still finds the (tag, destination) pair in the append-only evidence log; releasing the barrier retires the obligation with no new proof (inverse)                                                                                                                                                                                                                                                                                                                      | `a_failed_post_withdrawal_read_preserves_the_evidence`                                                                                                                                                                                      |
| AUTONOMOUS RETRY AFTER FAILED SETTLEMENT                                | Recovery with failing ACL reads surfaces the error AND still settles the overdue obligation once storage recovers, with no further recovery call                                                                                                                                                                                                                                                                                                                                                                                 | `a_failed_initial_settlement_still_retries_autonomously`                                                                                                                                                                                    |
| PRE-FENCE BEFORE OBSERVATION                                            | A stalled preliminary read no longer delays the second grant's fence: the blind pre-fence installs it at its own deadline (tightened tolerance), before any observation                                                                                                                                                                                                                                                                                                                                                          | `a_stalled_preliminary_read_cannot_delay_the_next_expiry`                                                                                                                                                                                   |
| ADOPTION EXCLUDES BOTH RELEASE JOURNALS                                 | A canonical lease fence with an unresolved lease-side release is never adopted by a revoke-only pass: the newer refresh fence stays and the release-uncertain fence is withdrawn through the journaled companion path, retiring its entry on proof                                                                                                                                                                                                                                                                               | `a_refresh_never_adopts_a_lease_fence_with_an_unresolved_release`                                                                                                                                                                           |
| ONE DEADLINE FOR THE RELEASE PHASE                                      | A stalled stale-fence release consumes the earliest armed deadline; the next release is then skipped and the expiring grant settles on time — no per-call budget refresh lets the phase outlive the deadline                                                                                                                                                                                                                                                                                                                     | `a_stalled_fence_release_never_outlives_the_earliest_deadline`                                                                                                                                                                              |
| COVERAGE REQUIRES AN UNEXPIRED GRANT                                    | Two complete-but-expired groups sharing a destination never count as coverage for each other; the destination is fenced, and both obligations settle once the daemon behaves (inverse)                                                                                                                                                                                                                                                                                                                                           | `a_complete_but_expired_group_never_counts_as_coverage`                                                                                                                                                                                     |
| BLIND FENCE RECONCILED OVER LIVE COVERAGE                               | With an overlapping unexpired grant verified, the blind expiry fence is released through the journaled path even while the expiring identity's withdrawal is refused; the surviving grant's allow is continuously present (inverse: the withdrawal eventually succeeds and retires)                                                                                                                                                                                                                                              | `a_failed_withdrawal_never_leaves_a_blind_fence_over_a_live_grant`                                                                                                                                                                          |
| DEADLINE-AWARE DEDUPLICATED PRE-FENCE                                   | A multi-address grant whose fence adds stall past a second grant's expiry yields at that expiry's deadline; the re-entered pass fences the newer expiry first and both obligations settle once adds behave (fast-path inverse)                                                                                                                                                                                                                                                                                                   | `a_stalled_multi_destination_prefence_still_settles_the_newer_expiry`, `a_fast_prefence_fences_every_due_destination_before_the_settle`                                                                                                     |
| PRE-FENCE CACHE KEYED BY ARMED EXPIRY                                   | Two successive expiries of one identity with a renewal and a fence release between: the second expiry blind-fences again even with observation parked, then withdraws and retires once the daemon behaves (inverse)                                                                                                                                                                                                                                                                                                              | `a_renewed_identity_is_blind_fenced_again_at_its_second_expiry`                                                                                                                                                                             |
| REVOKED IS NEVER COVERAGE                                               | A failed revocation leaves the denied grant's complete group installed; when the sibling grant over the same destination expires, the destination is fenced and STAYS fenced — the revoked group never counts; the re-run withdraws it, retires the marker, and settles (inverse; genuinely live sibling inverse retained)                                                                                                                                                                                                       | `a_revoked_groups_surviving_rules_never_count_as_coverage`                                                                                                                                                                                  |
| UNREADABLE RELEASE JOURNAL FAILS CLOSED                                 | An invalid journal prohibits every adoption: the protecting fence is never removed, protection continues under a fresh identity, and the pass fails closed; a readable-empty journal restores adoption and the journaled cleanup (inverse)                                                                                                                                                                                                                                                                                       | `a_refresh_never_adopts_a_lease_fence_with_an_unresolved_release` (extended)                                                                                                                                                                |
| REVOCATION RETIRES ONLY AFTER COMMIT                                    | A re-grant interrupted after publication but before persistence leaves the revocation intact, so a later transient retry retains nothing and reinstalls nothing; a committed re-grant retires the denial (inverse)                                                                                                                                                                                                                                                                                                               | `successive_interrupted_refreshes_keep_the_full_revocation_set` (extended)                                                                                                                                                                  |
| DURABLE IDENTITY FOR EVERY ISSUANCE                                     | A crash after the accepted-then-deferred first issuance, then teardown and recreate: the retry allocates a FRESH generation (never the interrupted identity), converts the unresolved mutation to a standing fence, and the original's late apply lands behind it — same-destination withdrawal evidence from the old incarnation cannot retire the new obligation                                                                                                                                                               | `a_crashed_first_issuance_never_reuses_its_identity_across_recreate`                                                                                                                                                                        |
| ONE DEADLINE ACROSS PRE-FENCE AND OBSERVATION                           | A fence add stalled past a second grant's expiry composed with a parked preliminary read: the read budget is never recomputed to exclude the newly-expired grant, so the second grant is fenced inside its own deadline before any observation resumes; cleanup and retirement proceed once the daemon behaves (inverse)                                                                                                                                                                                                         | `a_stalled_prefence_and_parked_read_still_fence_the_new_expiry`                                                                                                                                                                             |
| DESTINATION-WIDE PROOF BEFORE FENCE RELEASE                             | Only the revoked sibling's withdrawal is refused while the expiring grant's succeeds: the fence survives the clean withdrawal because the revoked grant's surviving group is an unauthorized survivor; a genuinely authorized live grant still releases the fence (inverse)                                                                                                                                                                                                                                                      | `a_successful_sibling_withdrawal_never_releases_the_fence_over_a_revoked_survivor`                                                                                                                                                          |
| REQUEST-COUNTER HIGH-WATER OUTLIVES THE MARKER                          | Deferred fence removals + uncertain releases retried to a clean commit (marker cleared) + a revoke/re-grant composing a new uncertain issuance: the re-issued fence carries a FRESH epoch (the tombstone floor preserves the fence-epoch consumption), so the still-in-flight deferred removal of the retired fence matches nothing and the deferred allow lands behind the fence                                                                                                                                                | `a_retired_marker_never_lets_a_fence_epoch_repeat`                                                                                                                                                                                          |
| RELEASE REQUIRES CURRENT AUTHORIZATION                                  | One shared destination: grant A's first address installs, A's second address fails uncertainly (A revoked, its group swept), and grant B's allow for the destination also fails uncertainly — the ensured fence is NOT released on A's stale cached confirmation (it stays under its original identity, so no release-then-repair window), and B's deferred allow lands behind it; a genuinely live overlapping grant still releases (live-overlap inverse retained)                                                             | `a_revoked_grants_cached_confirmation_never_releases_the_shared_fence`                                                                                                                                                                      |
| RECOVERY FENCES BEFORE ITS FIRST PROBE                                  | A restarted owner whose first recovery read is parked: the overdue destination is fenced BEFORE the probe can return; the probe is deadline-bounded, so the settlement completes on its own once the bound fires (an unbounded probe would still be parked); the released-read path settles and retires the obligations (inverse)                                                                                                                                                                                                | `a_restarted_owner_fences_before_its_first_recovery_probe`                                                                                                                                                                                  |
| IDENTITY FLOOR INSIDE THE SHARED ALLOCATOR                              | An uncertain fence release retried to a clean commit (marker cleared, epochs tombstoned), then a revocation-ONLY pass with a refused allow withdrawal: the replacement fence is a fence-only allocation and still carries a FRESH epoch, so the retired fence's deferred removal strikes nothing and the revoked allow stays fenced; an unchanged healthy renewal keeps its allow identity (inverse)                                                                                                                             | `a_retired_marker_never_lets_a_fence_epoch_repeat` (revocation leg)                                                                                                                                                                         |
| ONE DEADLINE ACROSS RECOVERY PRE-FENCE AND PROBE                        | Two overdue grants whose fence adds stall past a third grant's expiry, composed with a parked probe: the exhausted deadline re-discovers and fences the newly-due destination BEFORE any observation (the probe is skipped outright), the stalled grant stays usable until its own expiry, and every obligation settles and retires once the barrier is released (inverse)                                                                                                                                                       | `a_restarted_owner_fences_before_its_first_recovery_probe` (composed leg)                                                                                                                                                                   |
| RECONCILE RELEASE BEHIND THE SHARED GATE                                | An unresolved old allow and an uncertain fence release coexist after a temporary reauthorization; a later denial with fence adds failing keeps the old fence installed (the retry never releases on sight), and with fencing restored a RELIABLE replacement (fresh epoch, read back) precedes the old identity's removal — the stale deferred apply lands behind the fence; a clean authorized release retry still proceeds (inverse)                                                                                           | `a_denied_reconcile_release_never_drops_the_fence_before_its_replacement`                                                                                                                                                                   |
| UNREADABLE REFRESH-RELEASE JOURNAL DISQUALIFIES ADOPTION                | A release-pending refresh fence whose journal is unreadable, with the withdrawal stalled: the boundary installs a FRESH lease-family fence rather than adopting, so the deferred removal deletes only the release-pending fence and the expired allow stays fenced; a readable marker with an empty journal still adopts the installed fence (inverse)                                                                                                                                                                           | `an_unreadable_release_journal_never_adopts_a_refresh_fence`                                                                                                                                                                                |
| STARTUP OWNS OBLIGATION RECOVERY                                        | A grant that expired while the daemon was down, on a healthy running VM with no outstanding network cleanup, recovered by the startup census ITSELF (no reconnect, refresh, or direct recovery call): the expired allow is withdrawn and the ledger retired before the census reports; plus the verification leg — every ACL read parked from the outset: recovery's blind pre-fence still fences the overdue destination BEFORE the stalled outer read returns, and verification passes against the settled truth once released | `startup_inventory_recovers_expired_dns_obligations`, `verification_recovers_dns_obligations_before_its_first_outer_read`                                                                                                                   |
| MONOTONE HIGH-WATER AT THE MARKER-WRITE BOUNDARY                        | Successful replacement reconciliation (uncertain issuance, uncertain ensured release, denial) composed with interruption, reauthorization, and a later uncertain release: the reconciliation write-back never decreases the consumed-identity high-water mark, and no fence epoch ever repeats a retired one                                                                                                                                                                                                                     | `reconciliation_never_rolls_back_the_request_counter`                                                                                                                                                                                       |
| RECOVERY FANS OUT BEFORE ANY SETTLEMENT                                 | Restart with two sandboxes: A's durable ledger is malformed while B's lease independently expired — BOTH owners and watchers activate before any settlement is awaited, A's failure is isolated and surfaced in an aggregated error naming the sandbox, and B settles and retires normally; the healthy single-sandbox recovery inverse is retained                                                                                                                                                                              | `startup_recovery_activates_every_owner_before_settling_any`                                                                                                                                                                                |
| ISSUANCE BEHIND CURRENT AUTHORIZATION                                   | A authorizes X (constant policy, so transient retention preserves A's identity); the pass stalls past A's expiry and the lease cleanly withdraws A and releases its deadline fence; B's re-grant for X (fresh identity) is then issued BEHIND a preventive fence because issuance revalidates current authorization — pre-fix the stale pass-start cache issued it unfenced; genuinely live overlapping grants sharing a destination still issue the second allow with no second fence (inverse)                                 | `issuance_skips_the_fence_only_behind_current_authorization`                                                                                                                                                                                |
| RECOVERY ENFORCES RECORDED DENIALS                                      | An NXDOMAIN journaled into the durable marker with the refresh crashed before the mutation: startup recovery enforces the recorded withdrawal (fence-first, through the shared boundary) before the census reports, rather than leaving the denied address reachable until the old TTL; the marker's denial evidence is preserved until a committing refresh retires it, and a committed live grant is untouched (inverse)                                                                                                       | `startup_inventory_enforces_recorded_denials`                                                                                                                                                                                               |
| PARTIAL-ROTATION ISSUANCE BEHIND A FENCE                                | A {X,Y}→{X,Z} rotation: the retiring generation's complete group for X never authorizes the replacement — the re-issued allow lands BEHIND a preventive fence (pre-fix the pass-start rule observation authorized it through the group the same pass was withdrawing); a same-pass authorizer whose grant expired mid-pass no longer legitimizes later issuance on its destinations either; genuinely live overlapping grants still skip the fence (live-overlap inverse retained)                                               | `rotation_reissues_behind_a_fence_not_the_retired_group`, `issuance_revalidates_a_same_pass_authorizer_at_expiry`                                                                                                                           |
| AUTONOMOUS DENIAL ENFORCEMENT AFTER RECOVERY                            | A marker-only crash with the recovery probe exhausted by a parked read (zero budget): recovery surfaces its error and the WATCHER enforces the recorded denial autonomously — blind pre-observation fence, then retried withdrawal until it proves out; the marker is preserved until a committing refresh retires it, and a committed live grant is untouched (inverse)                                                                                                                                                         | `the_watcher_enforces_a_recorded_denial_after_recoverys_probe_is_exhausted`                                                                                                                                                                 |
| COVERAGE-AWARE DENIAL RECOVERY                                          | A refused withdrawal on a recorded denial: a verified non-revoked surviving sibling group over the shared domain keeps the destination unfenced (the blind pre-fence is reconciled away through the journaled release path), a destination authorized only by the recorded policy's static CIDRs is never lease-fenced, and an uncovered destination is quarantined and stays fenced until the withdrawal proves out                                                                                                             | `denial_recovery_fences_only_an_uncovered_destination`                                                                                                                                                                                      |
| DENIALS RECORD EVERY OUTSTANDING IDENTITY                               | A re-grant installs and publishes its fresh generation but fails before the state commit; the NXDOMAIN denial then journals BOTH the committed and the armed uncommitted generations, and watcher-only recovery withdraws the live uncommitted identity and fences the destination within its deadline; an identity issued AFTER the denial is absent from the recorded set and stays exempt — the post-denial re-grant commits and stays reachable (inverse)                                                                    | `a_crashed_first_issuance_never_reuses_its_identity_across_recreate` (second-denial leg)                                                                                                                                                    |
| LEASE RECOVERY IS PROJECT-SCOPED                                        | Two clients sharing one host state root: a foreign project's armed-and-expired ledger is skipped by whole-host recovery BEFORE any owner activation (byte-for-byte untouched), the per-sandbox recovery refuses it fail-closed (the expired allow stays installed), and the owning project's recovery settles it to completion (inverse)                                                                                                                                                                                         | `dns_recovery_never_adopts_another_projects_lease_ledger`                                                                                                                                                                                   |
| COMMIT DRAIN RELEASES THROUGH THE SHARED GATE                           | A journaled fence release retried at commit: an exhausted deadline leaves the fence and entry untouched; a live authorization releases cleanly (inverse); an expired authorization with fence installs failing keeps the old fence and the entry, and with fencing restored a verified fresh-epoch replacement precedes the old identity's removal — the destination is never unfenced                                                                                                                                           | `commit_drain_releases_a_pending_fence_only_behind_current_authorization`                                                                                                                                                                   |
| RECONCILE DERIVES REAL COVERAGE                                         | A stale deferred allow lands while a complete live sibling group (same destination, other grant) still authorizes it: a REFUSED withdrawal of the stale rule installs no destination-wide fence and the sibling stays reachable throughout; once removals work the stale rule withdraws cleanly with the destination still unfenced, and the uncovered inverse still fences                                                                                                                                                      | `reconcile_preserves_sibling_coverage_for_a_stale_pending_allow`                                                                                                                                                                            |
| JOURNALED RELEASES YIELD AT THE EARLIEST ARMED EXPIRY                   | A pending fence release reconciles with no caller deadline while a separate short-lived grant is armed: the stalled removal hits the armed-expiry deadline, yields the owner lock, and the expiring grant's watcher fences its destination at its expiry — long before the barrier's own cap; once the daemon behaves the journaled release completes and the fence retires (inverse)                                                                                                                                            | `a_stalled_reconcile_release_yields_the_owner_lock_for_an_expiry`                                                                                                                                                                           |
| THE COMMIT FOLDS THE DRAIN'S PROVEN RELEASES INTO ITS SNAPSHOT          | The ensured release of a preventive fence fails uncertainly once; the commit-time drain's retry succeeds: the refresh commits (no unexplained-rule-loss rejection), the released fence is gone, the journaled entry retires at the drain, the marker clears, and a follow-up refresh is clean (readiness)                                                                                                                                                                                                                        | `a_drain_succeeded_fence_release_commits_and_clears_the_marker`                                                                                                                                                                             |
| A CNAME BESIDE ADDRESS DATA DENIES                                      | `a A 10.0.0.5` beside `a CNAME b` denies before the hop is even followed (a public `b` answer can no longer launder the carried address); the denial holds for public addresses too; the AAAA walk denies a CNAME beside same-owner IPv6 data identically; valid inline chains stay accepted (existing inverses)                                                                                                                                                                                                                 | `mixed_cname_and_address_data_for_the_current_hop_denies`, `mixed_cname_and_address_data_denies_even_with_public_addresses`, `mixed_cname_and_aaaa_data_for_the_current_hop_denies`                                                         |
| THE COMMIT CARRIES THE DRAIN'S REPLACEMENT FENCES                       | A journaled fence release retried against a since-revoked destination installs a verified replacement fence between the pass's observation and the commit: the persisted plan names EVERY live fence, the revocation commits, and reconnect verification would no longer refuse the sandbox over an unrecorded rule                                                                                                                                                                                                              | `a_drain_installed_replacement_fence_enters_the_committed_plan`, readiness leg in `a_drain_succeeded_fence_release_commits_and_clears_the_marker`                                                                                           |
| FENCE MUTATIONS PROVE ACL OWNERSHIP FIRST                               | The ACL is retagged to a foreign sandbox while a fence release is journaled / a lease is overdue: the release boundary refuses before any mutation, and the blind pre-fence's bounded ownership probe vetoes the pass — not one rule added or removed, and the refresh fails closed; restoring ownership enforces the overdue lease normally (healthy inverses)                                                                                                                                                                  | `a_journaled_fence_release_never_mutates_a_foreign_acl`, `a_blind_prefence_never_mutates_a_foreign_acl`                                                                                                                                     |
| DISTINCT CNAME TARGETS FOR ONE OWNER DENY                               | `a CNAME public` + `a CNAME private` + `private A 10.0.0.5` denies in EITHER answer order (no branch is ever selected), identically in the AAAA walk; identical duplicate CNAMEs collapse to one hop with the tighter TTL (inverse)                                                                                                                                                                                                                                                                                              | `conflicting_cname_targets_deny_regardless_of_branch_order`, `conflicting_cname_targets_deny_in_the_aaaa_walk`, `duplicate_identical_cnames_collapse_to_one_hop`                                                                            |
| PRE-FENCE CACHE PRUNED TO ARMED TRIPLES                                 | Three rotation-and-settlement rounds with short TTLs: the cache never exceeds the currently-armed triple (unpruned it would accumulate one per round); a renewed identity whose tag and expiry differ is blind-fenced again at its second expiry (existing inverse)                                                                                                                                                                                                                                                              | `the_prefence_cache_stays_bounded_across_rotation_and_settlement`, `a_renewed_identity_is_blind_fenced_again_at_its_second_expiry`                                                                                                          |
| ORPHAN SWEEP BOUND BY THE NEXT ARMED EXPIRY                             | A blind pre-fence orphaned mid-settle is swept while a second grant expires DURING the sweep: a stalled sweep read or two stalled orphan removals are killed at the shared deadline, the expiring grant is fenced on time, and its expiry still settles (never retired unprocessed — the allow cannot strand); a healthy sweep releases exactly the orphaned fences and keeps a fence whose destination still shows a surviving allow (inverse)                                                                                  | `a_stalled_orphan_sweep_read_cannot_delay_the_next_expiry`, `stalled_orphan_sweep_removals_cannot_delay_the_next_expiry`, `a_healthy_orphan_sweep_releases_only_the_orphaned_fence`, `a_durable_withdrawal_retires_without_a_fresh_attempt` |
| STANDING FENCE ON DOMAIN-FREE RECREATION                                | A sandbox torn down with an unresolved allow (obligation preserved, ACL and lease ledger gone) recreated with a domain-free policy reinstalls the fence before readiness, and the delayed old apply lands behind it, never effective; a static CIDR authorizing the destination suppresses the fence but never the obligation (inverse); clean domain-free creation keeps its cheap no-marker path (inverse)                                                                                                                     | `a_deferred_allow_landing_after_recreate_never_becomes_effective` (domain-free and CIDR-authorizing recreation legs in-test)                                                                                                                |

A refresh that exhausts its resolver budget treats the
remaining lookups as transient outcomes rather than aborting: expiry
cleanup still runs (decided against the post-resolution clock), so repeated
failed refreshes can never strand expired destinations in the ACL. A
resolution that expands beyond the aggregate destination bound likewise
must not abort with the previous ACL installed: the refresh plans a bounded
fail-closed state that revokes EVERY dynamic grant (deny-all beyond static
CIDRs, retry at the churn floor), so a co-occurring NXDOMAIN/rebound/expiry
is always applied. The post-replacement readback compares the dynamic rule
MULTISET including enabled state and every match constraint — a disabled or
source-narrowed reject companion is repaired, not ratified. The
published policy state (grants, expiries, the exact
`raw.dnsmasq` body) is persisted crash-durably per sandbox under the host
state dir and drives reconnect readback: the network verify compares
`raw.dnsmasq` against the persisted publication (falling back to the
deny-all base), so a tampered or crash-torn publication is a mismatch that
fails closed. Refresh is serialized per sandbox (`sandbox_lock`) and fenced
by the sandbox/project ownership tags on the network and ACL, so a
concurrent refresh — or a forged response — can never broaden another
sandbox's policy. Domain-grant ACL rules are tagged per name
(`wssp-dns-<sha256(name)[:8]>`, reject companions `wssp-dns-reject-<…>`)
from creation, and refresh classifies dynamic rules by that STRICT tag
shape — the bridge DNS access rules `wssp-dns-udp`/`wssp-dns-tcp` are
infrastructure and survive every refresh — so refresh diffs only its own
rules and never touches static CIDR or DHCP/DNS infrastructure rules. A
committed refresh also persists the rule set AS INSTALLED (the observed
post-refresh order: refresh retains unchanged rules in place and appends
new ones), because the reconnect readback compares positionally — and the
reconnect apply re-reads that persisted set UNDER the sandbox lock, so a
plan snapshot taken before the lock can never reject a concurrently
refreshed, healthy ACL into rollback. The refresh also fences the supplied
policy against the sandbox's RECORDED policy hash (`network-plans/<id>.json`)
under that lock BEFORE resolving or mutating — a different policy (say one
with a covering CIDR) can never strip the recorded policy's DNS/DoT reject
companions — and it validates the observed static/infrastructure rules
against the recorded plan, so an injected unrestricted allow is refused,
never ratified into the persisted rule set reconnect trusts. A matching
hash with an absent or UNDECODABLE recorded rule set refuses too: the
recorded-static comparison can never be silently disabled by a malformed
plan record. A failed
initial publication rolls the apply back (retiring the persisted plan and
DNS state records) so a create retry recompiles and republishes instead of
reporting readiness over an unresolvable deny-all resolver. Planning,
compile, and persisted-state loading share ONE pair of bounds — unique
destinations plus a separate bound on emitted (name, address) records, the
quantity ACL rules and `host-record` lines actually scale with — so a state
refresh commits is never discarded as invalid on the next transient
failure.

Device verification reads the
instance's `expanded_devices` (the daemon-enforced effective set — profile
devices merged with local overrides), never local `devices` alone, and fails
closed when the expansion is absent, so an inherited proxy/forward/device
cannot slip past the audit and a healthy VM is not rejected for lacking a
local root disk. Create-retry and reconnect bind the existing VM (sandbox
id, template digest, base image, create key) before any `config device
override`, and reconnect refreshes the binding immediately before the NIC
mutation, so an unbound or foreign VM is never mutated. The cleanup
obligation journal is write-ahead and crash-durable: kill persists the
obligation (atomic tmp-write, `sync_all`, rename, directory fsync) BEFORE
the VM is deleted and clears it only after verified absence, so no crash
window leaves an untracked bridge/ACL; the census reconstructs obligations
for pre-journal orphans from the owned tagged resources themselves. The
census and per-sandbox query report `provisioning` (never silence or
`absent`) for any sandbox with outstanding cleanup — including orphaned
owned resources — so teardown settlement can never take omission as kill
evidence. Every apply stamps the network and ACL with an incarnation marker
(`user.wssp.attempt`, fresh per provisioning attempt, re-stamped on
adoption); the drain and teardown are fenced on that marker, so a stale
record can never delete a rebuilt attempt's resources, and stale or foreign
records are dropped rather than acted on. Reconnect reuses the persisted
resolved expansion of the recorded policy (keyed by the recorded policy
hash under the host state dir), so DNS rotation of a granted domain never
fails an unchanged-policy reconnect; a hash mismatch (a different recorded
policy) re-resolves instead.

Every managed bridge/ACL also carries a project tag
(`user.wssp.project`, stamped at create and verified before any adoption or
deletion; untagged legacy objects belong to `default`). Dedicated projects
without network isolation inherit the default project's networks, so census,
legacy reconstruction, gateway reuse, and teardown are all scoped by that
tag — one project on a shared daemon never counts, adopts, or deletes
another's sandbox networking. Apply, teardown, and journal updates for one
sandbox are serialized on a per-sandbox lock held across the fence check and
the deletion (and across apply-to-VM-adoption), so the incarnation check and
the delete are atomic against a concurrent retry. The 128-entry policy input
bound is enforced on the recorded policy before any host IO; the persisted
expansion reuse path (recorded CIDRs merged with their resolved domain
destinations) is instead deduplicated and bounded by the 512 compiled
destination limit, so a 64-CIDR policy with one domain reconnects. Every
apply writes a crash-durable provisioning-intent record BEFORE its first
host mutation; the record is retired by VM adoption or a verified rollback,
and a restart drain that finds no VM completes the fenced teardown from it —
no window between bridge creation and `incus init` can leave untracked
state. Journal directory creation is itself durable (each newly created
component's parent is fsynced), matching the host journal. Subnet allocation
runs under a daemon-wide allocation lock held from the taken-subnet snapshot
through bridge creation, so two concurrent creates with colliding seeds
recheck under the lock and never claim the same range. The `incus-surface`
probe harness now tears down and verifies the run's owned bridge/ACL pairs
(including partially completed launches) through the same fenced teardown,
never another run's or project's objects, and keeps all runtime state inside
a per-run scratch dir it removes. The runtime's durable state root is passed
in by the node daemon (the relay state dir it already resolved); the only
fallback is the established `WSSP_DATA_DIR` / platform data dir — there is
no separate host-state environment variable.

The drain reads each obligation UNDER the sandbox lock,
never before it, so a failed retry that durably replaces the record while
the drain waits is fenced against what the journal says now, and the fresh
record is never unlinked from under a stale snapshot. Journal records carry
the full SET of incarnations they cover: a retry's write-ahead merges the
prior record and the live resources' markers before restamping, so a crash
before or between restamps leaves resources whose markers still fence-match
their own obligation — the drain recovers them instead of dropping the
record as stale. The subnet-allocation lock is daemon-wide, keyed by the
daemon's `environment.server_name` (falling back to one shared key for the
local default remote) in a machine-wide lock directory — two node daemons
with different host identities driving the same daemon serialize on one
lock. Records also persist their owning project, and a drain processes and
removes only its own project's obligations in a shared state root. Directory
creation for the journal hierarchy fails CLOSED: an open or fsync failure
aborts the apply before any host mutation rather than provisioning on a
non-durable journal. Recorded-policy validation (presence, hash binding,
128-entry input bound) is pure and precedes ALL host IO on create and
reconnect — no profile query, no VM binding, no allocation lock, no daemon
invocation at all for an out-of-bounds policy.

The NIC's ACL defaults are pinned at the device level too
(`security.acls.default.{ingress,egress}.action=drop` in the launch override
and required in verification), and effective-device verification rejects
every other unexpected property — a NIC carrying a device-level
`security.acls` list, permissive default actions, routes or VLAN membership
fails closed instead of widening the deny-default policy; only benign
daemon-filled properties (`type`, `name`, `nictype`, `mtu`, `hwaddr`,
`host_name`, `queues`) are tolerated. NIC repair respects Incus device
semantics: `config device override` applies only to inherited devices, so a
stopped VM whose LOCAL eth0 (recorded by its own init) drifted is repaired
with `config device set`, an inherited-only NIC with `override`, and the
effective `expanded_devices` are re-verified either way. Journal records can
never cross projects: persisting or clearing an obligation whose recorded
project differs fails with `idempotency_conflict` instead of overwriting
it, so one project's kill in a shared state root cannot destroy another
project's evidence. Journal directory durability is marker-based
(`.wssp-durable`): a directory whose chain sync completed is marked;
anything visible but unmarked has its parent chain resynced before any
record is admitted, so a retry after a create-succeeded/sync-failed attempt
never persists on a half-durable hierarchy. The per-sandbox lock registry
holds reclaimable weak entries (reaped under the registry mutex at each
miss), so it cannot grow without bound and concurrent callers always share
one lock per sandbox.

Drain fairness and verifiability. The drain establishes
ownership BEFORE charging its 256-record budget — foreign-project and
unverifiable records never consume a slot — and a rotating cursor
(`.drain-cursor`, a best-effort progress hint) resumes each drain where the
previous one stopped, so persistently failing records can never starve the
obligations behind them. Journal reads are exact: absence is distinguished
from read/parse failure, and an unverifiable record is PRESERVED (never
unlinked — its ownership cannot be established) and reported; census counts
it conservatively, and writers fail closed instead of merging over it. DNS
compilation clamps each lookup's wait to the REMAINING overall budget and
rechecks the deadline after every lookup, so a final lookup starting just
before the deadline can never finish after it and still produce an accepted
plan.

Recovery acceptance and journal integrity. A provisioning
intent is retired — and a recovered running VM reported as allocation
success — only after the full enforcement identity verifies: owned bridge +
owned ACL + the instance's effective devices equal to the audited launch
devices. VM existence alone is never proof (a crash between the network
apply and the NIC check leaves a running VM with unrestricted egress).
Journal records are schema-validated, not merely syntax-checked: the record
must be an object whose `sandbox_id` matches the filename, `phase` and
`project` must be well-typed when present, `attempts` must be a non-empty
string array when present, and only the explicitly recognized legacy shapes
(a single `attempt` string, or no attempt field at all) are accepted — a
malformed present field can never collapse into an adopt-any-marker legacy
obligation. DNS resolution runs on a bounded executor: a fixed worker set
with a bounded queue retains capacity until a stalled lookup ACTUALLY
finishes, so caller-side timeouts never leak detached threads and a stalled
NSS resolver fails fast instead of exhausting thread creation (which itself
is handled fallibly). The subnet-allocation lock lives at a fixed
machine-wide system path (`/var/tmp/wssp-incus-daemon-locks`), never derived
from the calling process's TMPDIR or mount namespace, so every host identity
driving one daemon contends on the same file.

Recovery binding, enforcement readback, and lock safety.
Recovery repair/adoption requires the VM's immutable binding (type +
sandbox-id tag) — the drain never reconfigures or adopts a foreign-tagged VM
on a record's account. Recovery performs the SAME enforcement readback as
apply: the applied plan's identity (gateway + full ACL rule set, plus the
resolved grant expansion) is persisted durably, and retirement/Ready require
the bridge's ACL attachment and deny-defaults, the ACL's rules and states,
the ownership tags, and the instance's effective devices to match it exactly
— an added allow-all rule or a detached ACL fails closed. The shared
allocation lock directory is trust-validated (real directory owned by this
euid, tightened to 0700; never chmodded when foreign-owned), the lock file
is opened with O_NOFOLLOW (symlinks rejected, never followed) and
permissions are set through the validated descriptor, restricting lock
participation to this host identity; the lock wait is bounded (60 s) and
cancellation-aware via the caller's permit, and the guard is released as
soon as bridge creation completes rather than spanning VM boot.

Provisioned lock location and legacy-shape fencing. The
allocation-lock directory is an administrator-PROVISIONED system path,
`/var/lib/wssp/incus-daemon-locks`, never created at use time: setup
(`wssp connect` enrollment) provisions it when it can and otherwise fails
fast with the exact operator command (`sudo install -d -m 2770 -o root -g
<daemon-users-group> ...`, with every authorized node-daemon user in that
group). The path sits outside every private-temp-affected location (`/tmp`,
`/var/tmp`, TMPDIR, per-user runtime dirs), so systemd PrivateTmp or mount
namespaces can never hand two isolated services different lock files for the
same daemon, and first-creator squatting by an unrelated local user is
impossible. Every acquisition validates the provisioning (real directory,
never a symlink; root- or self-owned; exactly mode 2770 — setgid so lock
files inherit the group, no world access) and fails closed rather than
repairing anything. Cleanup records carrying ANY modern field (phase or
project) must also carry a non-empty incarnation fence: a modern record
without attempts is rejected as malformed (preserved and reported, causing
no deletion) instead of degrading to the unfenced legacy shape, whose empty
attempt set the drain reads as permission to adopt the resources' current
marker — which would authorize deletion of a newer incarnation. Only
genuinely legacy records (no phase and no project fields at all) may be
unfenced. `WSSP_INCUS_DAEMON_LOCK_DIR` exists solely as a dev/test seam
(shim-driven harnesses cannot provision /var/lib, mirroring
`WSSP_INCUS_BINARY`); a directory resolved through it faces the identical
ownership/mode validation, so the seam relocates the lock but never weakens
its trust requirements.

Cross-UID lock acquisition and relative state roots.
Only the lock file's OWNER initializes its 0660 mode (through the validated
descriptor); every other authorized daemon user — who can open the file via
the shared group but whose chmod would fail with EPERM — validates the
existing mode and inherited group instead of modifying them, so one user's
provisioning never blocks another's creates. The durability walk for the
host-state journal ends at a relative path's topmost component (syncing the
cwd as "."), never descending into the empty path that `create_dir("")`
rejects, so relative state roots (`WSSP_DATA_DIR=data`) work end to end.
The `WSSP_INCUS_DAEMON_LOCK_DIR` dev/test seam is registered alongside the
other node-daemon seams in `docs/design/e2b-parity.md`.

Enrollment proves lock usability, not just metadata.
`wssp connect` setup probes the provisioned lock directory with the real
operation (create, fsync, remove a probe file as the current user,
O_NOFOLLOW) before the relay connects: a root-owned 2770 directory whose
group excludes the daemon user passes metadata checks but fails every lock
open with EACCES, so the preflight now fails fast with group-membership and
reprovisioning guidance instead of advertising an egress-capable host whose
creates all fail. `WSSP_INCUS_DAEMON_LOCK_DIR` is also registered through
the required env process (hidden, inSchema:false entry in
scripts/lib/env-manifest.ts, the same channel shell-script vars use;
`pnpm env:sync` passes).

Full binding for recovery, race-free enrollment probes.
The provisioning intent now persists the complete instance binding (the
`bind_instance` tuple: template fingerprint, create key) alongside the
incarnation fence, and restart recovery requires the FULL bind_instance
authorization against the existing VM before any NIC repair or intent
retirement — a VM with a conflicting template, base image, or create key is
rejected by the normal create path after networking exists, and the drain
must never mutate an instance that path rejected; records without a
persisted binding fail closed. Enrollment's usability probe uses a uniquely
named, create_new file per invocation and removes only its own, so
concurrent enrollments against the shared lock directory can never race on
one filename or abort each other with misleading permission guidance.

Original-binding journaling, verified retirement, mixed
incarnations. Reconnect journals the VM's ORIGINAL create binding (read back
from the instance's immutable creation metadata) with the provisioning
intent — never the reconnect operation's idempotency key — so a crash
between the network apply and the bookkeeping leaves a record the drain's
full bind_instance check actually matches, letting recovery repair and
retire. Reconnect clears its intent only AFTER the NIC repair and read-back
verify: a failed repair or crash in between keeps the obligation instead of
losing unverified enforcement. Surface cleanup collects the authorized
incarnation markers from BOTH owned resources (a crash between a retry's
restamps legitimately leaves bridge and ACL on different markers), fences
the teardown on all of them, journals unresolved cleanup evidence, and
propagates failure rather than reporting success over an owned leftover.

Surface-harness cleanup is honest. `incus-surface`
cleanup returns teardown failures instead of only printing them, preserves
the run's state directory while obligations remain (the freshly journaled
cleanup record lives there — reconstruction deliberately excludes marked
orphans, and in the default project such orphans can block admission for
lack of relay leases), and BOTH command paths report failure: the in-band
cleanups fold into the harness exit code, and `incus-surface cleanup
<run-id>` exits nonzero without printing "cleaned" when an owned bridge or
ACL survives.

Absence-verified cleanup, registered seam. Surface
cleanup no longer trusts command exit codes: after every owned VM `delete
--force` and the probe `project delete`, a fail-closed absence probe
(`config get` / `project show`; an unverifiable probe is itself a failure)
IS the propagation — a failed or silently incomplete deletion leaves the
object, which the probe catches, so a surviving VM (even one not referencing
the managed bridge) or a surviving project fails cleanup and retains the
state journal. WSSP_INCUS_DAEMON_LOCK_DIR is now a declared optional var
(packages/env/src/vars/shared.ts, like the entrypoint-read MIGRATE_ON_START
precedent) with its manifest entry in the schema set — `pnpm env:sync`
passes with 68 keys.

Absence requires explicit not-found evidence. Every
cleanup probe — the ownership probe, the post-delete VM verify, and the
`project show` verify — now accepts absence ONLY from the Incus CLI's
explicit not-found signature (`Error: <Kind> not found` on stderr with a
nonzero exit). Any other nonzero exit (daemon unreachable, permission
denied, malformed response) is propagated as failure: the ownership probe no
longer suppresses errors into "unowned" (which would silently skip this
run's own VM), and inconclusive verify probes fail cleanup with retained
state instead of printing "cleaned" over an unverified survivor.

The bridged NIC override no longer carries the OVN-only
`security.acls.default.*` keys (the installed Incus 6.0.0 `devices_nic`
reference lists ACL options only for OVN NICs; the deny-defaults remain on
the bridge network config itself, and the test shim rejects any bridged-NIC
device key outside the 6.0.0 allowlist at init/override/set). A failed
mixed-incarnation teardown journals EVERY owned marker observed at that
point — not just the first config's — so the restart drain keeps fenced
cleanup authority over a bridge and ACL restamped onto different
incarnations instead of rejecting one as a conflict and dropping the
obligation over a live owned object; a marker-less resource still yields a
schema-valid (empty-string attempt) record. Absence evidence is now matched
EXACTLY per object: `Error: Failed to fetch instance "<name>" in project
"<p>": Instance not found` for a `config get` probe and
`Error: Project not found` for `project show` (both verified against the
installed 6.0 CLI), so an unrelated diagnostic that merely mentions
"not found" is a failure, never absence. Finally the surface-cleanup state
dir is keyed by run id alone (`wssp-surface-state-<run-id>`) with an
`owner.pid` claim guard — a live owner refuses a second claimant, a dead
owner's journal is adopted — so a later `incus-surface cleanup <run-id>`
process reopens a retained journal across processes, and a state-dir
removal failure is reported instead of swallowed.

The incarnation fence now preserves the empty-string
marker for EACH unmarked owned resource even when marked resources coexist
(all three collectors — provisioning intent, teardown write-ahead, and the
owner-teardown fence): a crash mid-adoption that restamps only the ACL
leaves a marked ACL + unmarked bridge, and the journaled "" keeps recovery
authorized over both instead of rejecting the unmarked half as a newer
incarnation and stranding the other forever. The surface harness holds its
run ownership as a process-held flock on `wssp-surface-lock-<run-id>` —
OUTSIDE the state dir, so the initial cleanup's directory removal never
drops it — refusing any concurrent `cleanup <run-id>` for the whole run
(the kernel releases a dead owner's claim, so crash retention still works).
create_sandbox now rejects a sandbox/instance-name mismatch with
IdempotencyConflict BEFORE the allocation lock or any network apply, so a
conflicting-name probe can never provision bridge/ACL/intent state under an
id cleanup never reclaims. The live-expiry fixture tears down bridge+ACL
per sandbox (runtime state in its temp dir) and verifies absence, and the
surface census assertion checks that outstanding networking RETAINS
capacity — an untagged VM whose bridge/ACL remain is re-journaled and
reported as Provisioning, keeping the count unchanged until teardown
evidence completes. Legacy reconstruction takes the sandbox lock BEFORE rechecking the journal, VM
absence, ownership, and current markers and holds it THROUGH persistence, so
an inventory observation can never overwrite a concurrent create's fresh
provisioning intent with a stale teardown record (which would have orphaned
the new incarnation's obligation behind an unreconcilable fence); the
live-expiry fixture asserts project absence before constructing the runtime
and installs its cleanup guard immediately after project creation. Launch/repair matches what preflight accepts: device verification
identifies the audited root disk by its PROPERTIES (a disk mounted at /),
not its name, so a valid profile whose root disk is named "rootfs" passes
create and recovery instead of stranding a provisioned sandbox; a stopped
VM's drifted or legacy NIC is repaired by REPLACING eth0 with the complete
audited definition (remove + add, which shadows an inherited device
wholesale) instead of `device set`/`override`, whose key merge would retain
incompatible properties like parent=br0 next to the sandbox bridge; and the
surface harness never creates a pid-suffixed scratch state dir — a refused
concurrent claim leaves nothing behind. All surface state (run lock and state dir) now lives beneath an
owner-validated, mode-0700 parent that survives cleanup, a symlinked or
foreign-owned state path is rejected rather than adopted, and the host
journal's predictable temp file is created O_EXCL|O_NOFOLLOW (the daemon
lock pattern), so a planted symlink is refused instead of truncating its
target while a stale regular temp file from a crashed write is still
reclaimed. Egress enforcement requires a CVE-2025-52890-fixed
daemon — Incus 6.12/6.13 advertise `network_acl` but carry the nftables
anti-spoofing bypass (GHSA-p7fw-vjjm-2rwp), so the capability check and the
apply path fail closed below 6.14 (the daemon exposes no patched-backport
marker, making the release boundary the only evidence); fresh creates
install the pinned NIC as a COMPLETE local device after init (`init
--device` merges onto the profile device and would retain inherited
properties like parent=br0), initialized stopped and verified before first
start; and WSSP_SURFACE_ROOT is registered in the env schema and manifest
like the other Rust-only test seams.

Command stop outcomes are typed only from the host's own
proof. When a cancel is requested or the `timeoutMs` deadline passes, the host
runs one guest stop helper against the command's nonce-bound process group.
The helper records `group_terminated` only if the user command (a live direct
child of the wrapper) was running when it sent the signal and the group then
disappeared. Otherwise it records `group_gone`. Then the final streams decide
the outcome. An attributed stop with no exit frame (KILL escalation), or with
exit 143/137, is CANCELLED for a cancel and FAILED `timeout` for the deadline.
An unattributed 143/137 is UNKNOWN_OUTCOME when a stop was issued without an
observed result, i.e. a helper ran but returned no parsed record: that code
may be the stop's own effect. Any other
exit frame is the command's own result and stays SUCCEEDED with that code.
This covers an unattributed 143 with no blind stop (a command that exited 143
itself, or a stop the helper proved came after the command ended) and a
command that handled TERM and exited 0. Every remaining case is
UNKNOWN_OUTCOME: no banner, an unclean reap or drain, or a group gone without
attribution and no frame. The helper is tried at most three times per stop.
After that the host ends its local transport and settles UNKNOWN without a
best-effort guest group kill. Guest work may remain alive. There is no command
retry; sandbox stop/kill is recovery. One residual remains: a command that
exits 143 or 137 by itself in the short window between the helper's liveness
check (a scan of the guest process table) and its signal is reported as
stopped. The wire states and codes (`failed` + `timeout`, `cancelled`) have
existed since protocol 10.0, so no version bump or server change is needed.
Daemons built before this change report a timeout as UNKNOWN_OUTCOME and a
TERM-honoured cancel as SUCCEEDED/143. The server stores whatever the daemon
reports.

Command input preserves script bytes and enforces the shared serialized 32 KiB
command budget, with 120-second default and 1800-second maximum timeout. Stdin
chunks use bounded canonical base64 (at most 43692 encoded characters, one
32 KiB chunk); the browser `runCommand` initial stdin has the same bound. Stdin
travels in the durable outbox payload; no operation column holds payload bytes.
File bytes move only through the binary transfer API below: uploads and
ranged downloads. There is no whole-file base64 or JSON file-content API on
either plane. Paths address the guest filesystem. No snapshots, restore or fork
routes are exposed.

The operation read schema also accepts action receipts for template registration,
probe, stdin and cancellation. They contain action `kind`, `state`, derived
`outcome`, stable `errorCode`, resource/target IDs, recorded generation and dates;
never command text, file bytes or error detail. A probe adds `observation` only
with `sandboxes:read`; an operations-only reader receives null there. Confirmed
observations are `guest_ready`, `stopped` or `confirmed_absent`; a transport
failure remains `UNKNOWN_OUTCOME` with `unreachable`, never DB-derived liveness.
Action receipts persist uncertainty before host IO; a crash cannot cause a
retry to repeat uncertain work. A failed action may therefore be represented
by a pollable FAILED receipt, while admission/validation failures return 4xx.
Stdin acceptance does not assert that the guest consumed the bytes. Its target
operation supplies final command status; cancellation follows that target's
confirmed result. Non-dispatch receipts cascade with account deletion.

## Host drain admission

`GET /v1/hosts` adds `draining`, `liveSandboxCount` (the durable live reservation
count, including pending and uncertain guests) and `drained` (`draining` is true and the count is zero).
Host administration remains session-only; `hosts:read` cannot set drain.
See [host drain](adr-003-host-enrollment.md#host-drain) for owner and host endpoints.
Creates, cold reconnects of STOPPED guests and template registration refuse with
409 `sandbox.host_draining` under the host admission lock. Existing guest work
and warm reconnects continue. Template registration retains a FAILED receipt
carrying that code; the same idempotency key replays the refusal even after
undrain. A new request after undrain needs a new key. Accepted receipt replays
remain available while draining.

## Command output

Command output transport is relay v9 binary data with aggregate byte cursors
and gap ranges. Command terminal `result` contains only `exitCode`, `pid` and
`outputBytes`; status reads still disclose no output.

The server stores each chunk inside the same fenced relay transaction that
checks owner, host, connection epoch, generation, operation and dispatch attempt;
a chunk is visible and ACKed only after that transaction commits. Per command it
retains at most the first 256 KiB plus a rolling final 768 KiB of the aggregate
stdout/stderr stream (1 MiB), in at most 64 head and 192 tail rows of ≤ 8 KiB.
Stream identity is kept per byte. Every other byte is an explicit gap: host
drops (declared with `gapStart`), the head/tail cut, and a trailing range the host
counted but never delivered. A newer dispatch attempt replaces older bytes.

**Chunk size and batching.** A relay output chunk is at most 8 KiB unless
the connection negotiated more: a daemon offers `maxOutputChunkBytes` (8 KiB to
1 MiB) in its hello, and only then does `hello.ok` answer
`capabilities.outputChunkBytes` = min(offer, 64 KiB). The daemon sends chunks of
at most min(answer, its offer), 8 KiB when there is no answer; the server
refuses a larger body as a protocol error. A stored chunk is split into the same
≤ 8 KiB rows whatever its size, so caps, replay fingerprints (the last four
chunks, one per ACK slot) and paging are unchanged. Output chunks of one
operation attempt queued back-to-back on one host connection (at most 16 chunks
and 1 MiB) are admitted together: the connection's credential is revalidated
once, and the chunks commit in one fenced transaction with every per-chunk check
applied in order; each chunk is then ACKed as before. If the batch cannot
commit whole (authority no longer current at commit, a fence, a protocol error),
nothing of it is written and its chunks are processed one at a time, which
reproduces the per-chunk outcome exactly. Only consecutive output frames of the
same operation, generation and attempt are batched; the first frame that differs
(another operation or attempt, or any control frame) ends the batch, so no frame
is reordered: no chunk overtakes a control frame such as its final result, and
no chunk received after another operation's fatal frame is ever committed.

The **completion watermark** is committed with the host's final result
(`outputBytes`, including a final `UNKNOWN_OUTCOME`). The host sends every frame
of an attempt before that attempt's final result on the same ordered socket, so
bytes still missing at that point were dropped: they become a trailing gap and a
late chunk is refused, never appended. A terminal operation state alone does
not mean output is complete: poll output until `complete` is true. An interim
`UNKNOWN_OUTCOME` (no byte total) stays open to its exact dispatch. Operations
the server itself terminalized (for example superseded or never dispatched)
accept no output and read as complete.

| Method and path                  | Required scopes                       | Response                |
| -------------------------------- | ------------------------------------- | ----------------------- |
| `GET /v1/operations/{id}/output` | `operations:read` and `commands:read` | one `CommandOutputPage` |

Query: optional `cursor` (the previous `nextCursor`), `maxBytes` (decimal
1–65536, default 65536) and `waitMs` (long-poll, below). A page returns at most 64 KiB of bytes and 1,024
chunks plus gaps. `chunks` are `{stream: "stdout" | "stderr", offset, data}` with
standard base64 `data`, one run of consecutive bytes from one stream each;
`gaps` are half-open `[start, end)` ranges. Chunks and gaps tile
`[offset, nextCursor)` exactly, so polling from `nextCursor` never returns a
range twice; repeating a cursor returns the same page. `hasMore` means more is
available right now. Cursors are bound to the dispatch attempt: a cursor from an
earlier attempt restarts at 0 with `reset: true`; a cursor beyond the received
bytes is 400. The page also reports `state`, `exitCode`, `attempt`,
`receivedBytes`, `totalBytes` (null until the watermark), `retainedBytes`,
`truncated`, `complete` and `expiresAt`. Decode UTF-8 per stream incrementally:
a code point may be split across chunks and pages.

Output content expires 24 hours after the operation completes. After that the
route returns 410 `OUTPUT_EXPIRED` (never an empty page) while
`GET /v1/operations/{id}` still reports status. A server retention task deletes
expired rows every five minutes; reads are expired by the clock regardless of
when it runs. A non-command operation returns 409 `sandbox.state_conflict`.
Browser sessions read the same page through the `sandboxes.getCommandOutput`
RPC; the dashboard's operation page is that reader and renders the bytes
as text only (see ADR-003, "The Operations pages"). Output bytes never enter
logs, telemetry or status reads.

### Operation long-poll (`waitMs`)

`GET /v1/operations/{id}`, `GET /v1/operations/{id}/output` and
`GET /v1/operations/{id}/result` accept an optional `waitMs` query parameter:
decimal milliseconds `0`–`25000` (`OPERATION_WAIT_MAX_MS`; anything else is
400 `BAD_REQUEST`, like any malformed query). Absent or `0` reads at once. With
a hold, the server answers immediately when the read is already "ready", and
otherwise holds it until the operation changes or `waitMs` elapses:

| Route  | Ready when                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| status | `outcome` is not `pending`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| output | `complete`, `hasMore`, or the state is final or `UNKNOWN_OUTCOME` (including an interim one). A page with new chunks or gaps, or a `reset`, of a still-running command is held 2 s from when the bytes are first seen (`OPERATION_WAIT_PROGRESS_HOLD_MS`) for more bytes or the completion, then answered; a completion answers at once. A continuously printing command is therefore answered at most 30 times a minute, like the earlier interval polling. `hasMore` pages answer at once; the SDK paces its own output reads (a burst of 24, enough for a command's whole 1 MiB retained output, then one per 2 s), so sustained multi-page output also stays at ≤ 30 reads a minute per command. An empty page of a command that has not started (QUEUED/DISPATCHED/ACCEPTED) keeps holding. |
| result | the read does not answer `OPERATION_RESULT_NOT_READY`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Response bodies and error codes are unchanged; there is no new SDK feature
literal. At the deadline the unchanged read is returned as is (for `/result`,
the same `OPERATION_RESULT_NOT_READY`). Every answer comes from the route's
normal, freshly authorized read: a key revoked or narrowed during the hold gets
the normal 401/403, a foreign or missing ID is 404 at once and holds nothing.

The normal read runs first; only a not-ready answer takes a waiter slot and
registers interest in the operation ID (a foreign or missing ID is refused
before anything is registered), then reads once more, so a commit between the
two reads is never missed. Every operation and operation-result row write runs
in `sandboxOutboxTransaction`, which wakes the IDs it wrote only after its
commit (a rolled-back or fence-rejected relay transaction wakes nothing). A
write without an operation ID wakes only its owner's held reads. Wakes carry no
data. A woken read re-runs; if it is still not ready it keeps holding, but
after 8 wake-triggered re-reads the next read is answered as is (inside an
output progress hold it instead re-reads every 250 ms until the 2 s hold ends),
so one long-poll costs at most 19 + ⌊waitMs / 5 s⌋ reads however many commits
wake it.
Writers outside that wrapper (action receipts) wake
explicitly, and every held read also re-runs at least every 5 s. No database
connection or transaction is held while waiting.

A long-poll is one HTTP request: the `/v1` key, owner and IP budgets charge it
once. Holds are additionally capped at 16 per owner and 256 per server process;
over a cap, or while the server shuts down (held reads are answered
immediately), the read answers at once instead of returning 429. Wakeups are
in-process, which matches the single-replica deployment (docs/infra.md); a
multi-replica deployment needs a cross-replica fan-out
(`bindOperationChangeFanout`), until then reads on another replica only see a
change at their 5 s re-read.

## Durable transfer storage

The transfer store backs the relay and binary upload HTTP adapters. Session creation
requires a declared total length (including zero), direction and guest path.
Download capture must determine its reserved length before allocating content.
A guest path is opaque to server storage and never selects a server path.

Sessions bind the owner, originating SDK key (or browser-session plane), sandbox
and recorded generation. Live file scopes and resource grants are rechecked;
status and identical-create replay preserve the original generation, while
content access requires that generation to remain READY with an unexpired lease.
Creating the same session concurrently returns the same ID; changed input or
another originating key conflicts. Other overlapping operations on one session
return a retryable conflict without queuing payloads.

Defaults: 1 GiB per transfer, fixed 1 MiB chunks (only the last may be shorter),
10 GiB aggregate reserved disk, four sessions per owner, sixteen per server,
15 minutes idle and one hour absolute expiry. Chunks use exact offsets and
SHA-256 digests. Identical retransmission is idempotent; changed bytes at an
accepted offset, gaps and unaligned offsets fail. Successful new chunks and
reads refresh idle expiry but never extend absolute expiry. Sealing freezes
server content; it does not claim that a guest file was replaced.

PostgreSQL holds metadata and digests only. The private persistent spool holds
payloads in UUID-derived files (0700 directory, 0600 regular files, no symlinks
or hardlinks). Admission reserves the full length before creating a file.
Writes and fsync precede cursor commit; recovery verifies committed digests and
truncates unacknowledged tails before readiness. Missing/corrupt files fail the
session. Unavailable metadata stops recovery without deleting acknowledged
content or releasing its reservation. Interrupted allocation expires; retries
retain its original receipt.

Abort and expiry persist terminal intent, unlink and sync the directory, then
release the reservation once. Failed cleanup stays charged and is retried each
minute, including beyond a failed page item. Receipts outlive content; content
access returns `TRANSFER_EXPIRED` (410), quota refusal `TRANSFER_QUOTA` (429),
and storage failure `TRANSFER_IO` (503). Startup reconstructs usage from held
reservations; changing limits cannot make existing reservations disappear.

The relay exposes a bounded source interface (`size`, `sha256`, positional chunk
reader) and stores relay download captures in this same transfer store: a
`DOWNLOAD` session bound to the operation attempt (`operationId`,
`operationAttempt`), reserving the configured per-transfer maximum until the final
chunk seals it at its real length with a whole-file `sha256`. Captures share the
limits, quota, expiry, sweep, shutdown drain and restart recovery above; there is
no second store. Relay v7 file ACKs bind operation, generation, attempt, sequence
and cumulative byte offset, and each non-final download chunk is exactly one
fixed 1 MiB transfer chunk. A final download result must match the sealed length
and SHA-256 and records `transferId`. Upload commit binds the spool to one durable
PUT_FILE operation.

A transfer is bound to one sandbox generation. Once the sandbox reaches another
generation or is deleted, the next sweep (every minute) retires the content and
releases its reservation, rather than waiting for idle expiry; the receipt stays.
A server restart settles every unsealed relay capture immediately: a capture only
continues on the host connection that started it, and a restart drops them all.
Sealed content reads are shared: parallel range downloads of one capture never
conflict with each other, while exclusive work on that transfer (status, abort,
cleanup) returns a retryable conflict until they finish.

## Resumable binary uploads

`files.upload` is advertised in `/v1/capabilities`. All upload endpoints require
`files:write`, the originating key, ownership and both resource allowlists on
every request, including chunk replay and commit replay. SDK cookies are ignored.
The same handler serves `/api/dashboard/transfers` using cookie-only
`protectedProcedure` authentication and current required-2FA/ban policy.
Dashboard mutations require an exact `Origin` matching `BETTER_AUTH_URL` and,
when present, `Sec-Fetch-Site: same-origin`; there is no CORS grant.

1. `POST /v1/transfers`, JSON `{sandboxId, guestPath, totalBytes}` and a fresh
   `Idempotency-Key`, returns 201 with the transfer receipt and `Location`.
   The total must be known, including zero; reservation happens before allocation.
2. `PUT /v1/transfers/{id}` sends `application/octet-stream` with
   `Content-Range: bytes start-end/total` (inclusive end). The total must equal
   the reservation. Chunks start at multiples of 1 MiB, are exactly 1 MiB except
   the final chunk, and return 200 with the durable `receivedBytes` cursor.
   Server-computed SHA-256 identifies identical replay; changed replay is 409.
3. `GET /v1/transfers/{id}` returns the receipt and received offset. After a lost
   response or disconnect, resume at that offset or resend the identical chunk.
4. `POST /v1/transfers/{id}/commit` sends JSON `{sha256}` (lowercase whole-file
   SHA-256) and a separate `Idempotency-Key`. It verifies all bytes, then atomically
   seals the spool, binds one generation-fenced PUT_FILE operation, and enqueues
   dispatch. 202 and the operation `Location` mean accepted, not guest replacement.
   Replay with the same key/hash returns that operation even after generation
   change or content expiry; changed hash or another commit key conflicts.
5. `DELETE /v1/transfers/{id}` (no body or `{}` JSON) aborts an uncommitted upload
   and returns its receipt. Repeating abort is safe. Once commit is accepted,
   abort returns 409; use the operation cancellation API for in-flight work.

Binary mounts precede both the SDK JSON parser and the browser global body
limiter. Each body is byte-counted independently of Content-Length, capped at
1 MiB; compressed bodies, unknown/mismatched totals and incomplete chunks are
rejected before store writes. Both credential planes share bounded body admission
(default four requests per owner, sixteen globally) without a waiting payload
queue. Body reads have a 60-second deadline; disconnect/deadline releases the
reader slot and leaves the last acknowledged cursor resumable. A key revoked
during a slow chunk fails at the store's authorization boundary. Storage and
operation admission recheck ownership and authority after disk IO.

The relay reads the sealed spool in bounded chunks; PostgreSQL never holds these
upload payloads. Existing per-operation relay authority and generation fences
still govern guest replacement. A `file.put` dispatch without a committed
transfer fails; there is no other upload source.

One per-transfer cap applies end to end: 1 GiB, the node daemon's staging ceiling
(`sandbox_runtime::FILE_MAX_BYTES`) and the contracts' `TRANSFER_MAX_BYTES`.
The `TRANSFER_MAX_BYTES` environment variable may lower the server's cap; a value
above 1 GiB fails server startup.

## Ranged binary downloads

`files.download` is advertised in `/v1/capabilities`.

1. `POST /v1/sandboxes/{id}/files/download`, JSON `{path}` and an
   `Idempotency-Key`, needs `files:read`. It returns 202 and the operation
   `Location` of one GET_FILE capture. The host streams the guest file into the
   transfer store; the result must match the sealed length and SHA-256.
2. Poll `GET /v1/operations/{id}` until it is `SUCCEEDED`.
3. `GET /v1/operations/{id}/content` needs `operations:read` and `files:read`,
   and only the credential that requested the capture may read it: the same SDK
   key, or the browser-session plane for captures requested through the
   `sandboxes.readFile` RPC. Another key of the same owner gets 404. It returns
   the captured bytes as `application/octet-stream` (attachment) with
   `Content-Length`, `ETag: "<sha256 hex>"`, `Repr-Digest: sha-256=:<base64>:`
   and `Accept-Ranges: bytes`. `HEAD` returns the same headers without reading
   content.
   - `Range: bytes=a-b`, `bytes=a-` or `bytes=-n` returns 206 with
     `Content-Range`. `If-Range` with the ETag resumes an interrupted download
     without a new capture; any other validator returns the whole content (200).
   - Multiple ranges, other units, malformed and unsatisfiable ranges (including
     any range of an empty file) return 416 `RANGE_NOT_SATISFIABLE` with
     `Content-Range: bytes */<size>`.
   - Before the operation succeeds: 409 `TRANSFER_NOT_READY`. A failed, cancelled
     or unknown capture: 409 `CONFLICT`. A non-file or invisible operation: 404
     `sandbox.operation_not_found`. Expired content, or content whose sandbox
     reached another generation or was deleted: 410 `TRANSFER_EXPIRED`.

Ranges are served from the immutable captured bytes. Guest writes after the
capture are not visible; a caller that needs a consistent file must stop
concurrent guest writers before requesting the capture. Every request
reauthorizes the credential, scopes, grants and originating identity, and every
chunk read (at most 1 MiB) rechecks the transfer's authorization, expiry and
generation, so a key revoked or content expired mid-stream ends the response
early (the client sees a short body). Streams are pull-based: nothing is read
before the client asks, and at most one chunk is in flight per stream. Download
streams share the upload admission slots (four per owner, sixteen per server);
a slot returns when the stream completes, fails or is cancelled, or after 60
seconds without the client reading. Server-side cleanup of an aborted download
is bounded by one chunk read; host-side capture cleanup is the transfer
settlement (15-minute idle expiry of an unacknowledged download window).

The browser dashboard reads the same route at
`GET /api/dashboard/operations/{id}/content` with its cookie session and
required-2FA policy. It refuses requests whose `Sec-Fetch-Site` is present and
neither `same-origin` nor `none`; there is no CORS grant.

The dashboard's Sandboxes page is the browser client of both routes: it
sends the session cookie only (never an SDK key or `Authorization` header),
uploads one 1 MiB chunk at a time with an incrementally computed whole-file
SHA-256, and probes a completed capture with `HEAD` before offering it. Because
these routes grant no CORS, the dashboard must be served from the API's origin
(the default same-origin deployment); a split-origin deployment cannot transfer
files from the browser.

Command `envs` replaces the pre-launch `env` tuple field (which is rejected).
It accepts at most 64 unique POSIX names, 128 UTF-8 bytes per name, 4096 per
value and 16384 bytes of canonical sorted escaped JSON. Duplicate decoded JSON
keys, NUL, malformed Unicode and prototype names are rejected. HOME/SHELL
overrides remain accepted and ignored; piped-command TERM remains overridable.

Sandbox create `envs` is an optional bounded string map of immutable private
workload defaults. Command overrides merge before validation/enqueue. Sandbox
and operation public responses never include defaults or config binding digests.
A nonempty create waits on durable 10.3 private-config installation before boot.

## Additive pool placement

Create uses XOR `poolId`/`sandboxHostId`. Paged pool discovery adds `pools:read`; member discovery intersects host/pool grants before paging and needs `hosts:read`. Stored-resource authorization and sandbox SQL lists require retained origin-pool grants. Definitive `sandbox.pool_full`, `sandbox.host_capacity` and `sandbox.pool_unavailable` surface immediately in the SDK. See [pool behavior](../guide/pools.md) for ranking, invisible lookup, grant continuity and refusal categories.

The owner dashboard uses these same services through its cookie/CSRF/2FA
plane. It pages logical templates independently of placement, then chooses a
latest selector or exact revision; key minting displays exact revision grants
and verified/pending host associations. It never treats PENDING as launch
proof. See the [pool dashboard workflow](../guide/pools.md#dashboard-walkthrough)
and [post-reset credential procedure](../guide/auth-planes.md#minting-sdk-resource-grants).
Neither workflow introduces a schema reset or expands retained SDK grants.

## Files/process compatibility release

The [filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits) consolidates 10.5
strict DTO changes, result scopes/retention, bounded live pages and owner-wide
procedure budgets. Protected result/connect reads disclose guest content;
generic operation/admin views remain metadata-only. Approved Branch A signal
support is checked at call; a sandbox's guestApi.supportedSignals also drops
TERM/INT/HUP once the node's ready-time probe found no group signals, and
clients read it. Command
zero removes only the command timer, with lease/authority and finite setup
bounds intact; native HTTP receipts remain asynchronous acceptance. See also
[Disclosure and post-commit exit denial](../guide/auth-planes.md).

## VM size

Register/append accept independent CPU/RAM/root defaults (1 vCPU, 1024 MiB,
32 GiB). Create independently overrides `cpuCount`, `memoryMiB`, `diskGiB`;
bounds are CPU 1–32, RAM 512–65536 MiB in 256-MiB steps, disk 1–2048 GiB.
Append is self-contained. These policies do not alter the artifact/architecture/
guest manifest digest or consume verification-host RAM. No resize/migration API.

Keyed create preserves omitted-versus-explicit intent and returns accepted replay
before resolving current defaults/tags/caps. Invalid size is 400
`sandbox.vm_size_invalid`; per-VM/image fit is 409 `sandbox.vm_size_unsupported`;
pinned size/identity conflict is 409 `sandbox.vm_size_mismatch`. Existing metadata
→ egress → size → generic validation precedence and grant/visibility gates remain.
Definitive refusals create no sandbox/operation row and the SDK does not retry
409s; lost responses/429/5xx retain the original key. Post-acceptance refusal is
an operation outcome, never a new placement or absence proof.

Revision/sandbox DTOs carry all three dimensions. Sandbox DTOs include opaque
retained storage identity/name; host-only reads expose charged/free/overcommitted
RAM and aggregate vCPU, per-VM caps, live count, retained root count and at most
16 configured storage summaries. Those summaries include effective/total-based
caps, source, T/F/C/A/H/P derivation, commitments, usage and health/freshness/drain,
never backing paths/credentials/raw daemon observations. Sandbox/revision-only
grants disclose no host budget. Admin cross-owner observability is metadata-only.
Capabilities publish shared disk bounds/default, overhead and the fixed guard.

New placement needs current admission, census, heartbeat, private-key ACK and
exact per-host source evidence. Within each host choose healthy non-draining
storage fitting disk + 1 GiB by free GiB DESC then marker ASC. Rank jointly fitting
hosts by the own-host tier (`preferOwnHosts` and host owner = requester first),
then dominant share after placement ASC (max of charged RAM, vCPU and the chosen
storage pool's committed GiB over their budgets), then charged-RAM share ASC,
then host ID ASC; `lastPlacedAt` is observability only. Selected-host recheck holds H; all
storage writers hold H without a separate explicit storage lock order. Retry
pooled selection after rollback at most three times. Visibility precedes all
resource diagnostics; capacity conflicts use only `sandbox.host_capacity` and
`sandbox.pool_full` with `reason: ram | vcpu | disk | storage | ceiling`
(`pool_full` also `reserved`: held for an older waiting create). The pool
cascade splits compatibility (runtime/egress → `pool_no_compatible_host`) from
the exact revision existing on any member (`sandbox.template_unavailable`), and
connectivity (`pool_unavailable`) from current-epoch verification
(`sandbox.template_image_missing`). Pool capacity refusals may carry a static
`skipped` set over visible hosts only, never counts or online status.

Capacity queue. A pool create with `waitForCapacityMs` whose refusal is
waitable and statically feasible writes, under User → K → owner placement → G,
a hostless `WAITING_FOR_CAPACITY` sandbox, its `QUEUED` CREATE operation and a
`SandboxCapacityWait` row (global `seq`, pinned revision/size, private intent
scrubbed at any end). Entry authorization exempts only the host grant
(`queuedPoolContexts`, `sandboxes.create`, pool set, host null); the placer
re-runs the complete `sandboxes.create` authorization against the chosen host
before any hold. Queued CREATE digests use MAC domain `wssp-request-queued-v1`
with empty host fields and the same `hmac-sha256-v1` scheme; replay chooses it
from the operation's wait row, never per sandbox. Kill/stop/cancel of a
never-placed sandbox hash env-free bodies with no transport. The placer runs
one placement per transaction (User → K → owner placement → G → H → S → O),
the timeout sweep and cancel take User → G → S; nothing takes G after H. Every
FAILED exit sets `Sandbox.lastErrorCode`; a cancel leaves it NULL. Operation
long-polls on a waiting CREATE answer at once.

Each live hold pins chargedMemoryMiB and chargedVcpu on its boot. Each retained
root pins rootChargeGiB, disk size, pool and marker; disk charge is size + 1 GiB.
Positive stopped proof releases liveCount/RAM/vCPU once. Stopped and UNKNOWN
roots retain disk and one of 250 retained/pending positions because bridges
survive stop. Root/guard release needs positive exact-root absence on healthy
original storage and settled network cleanup. Offline/unavailable is never absent.
Startup/admission reconstruct all counters under H from pinned weights; ordinary
CAS reserve/release never clamps drift or recomputes old holds from new policy.

Cold start reuses host/root/pool/size, bypasses new-root disk cap/drain, and requires
fresh original-marker health and live/per-VM fit. Offline queueing uses last known
live budgets; known unavailable storage refuses reason=storage. Held live resources
add zero; warm renewal adds no hold. Shrinking any cap preserves overcommit and
existing running work. Global host drain refuses cold starts; pool drain does not.

Only relay protocol 1.0 (`ws-sandbox-proxy.relay.v1`) is accepted; old/unknown peers and
removed fields are rejected. Terminal and all retained files/process/private-config/
admission semantics are unconditional on a valid relay session while runtime and
authority checks remain. Hello/admission binds static RAM/vCPU/per-VM and storage
identity/cap tuples to an epoch. Monotonic inventory observations update health/
usage only (5-second polls, 15-second validity); heartbeat does not refresh them.
Journal v5 durably pins allocations and non-increasing per-marker implicit P.

Automatic storage cap is floor(min(P, 80%-total, max(0,F+A−H))/GiB), with
A trusted charged-root physical bytes bounded by C (otherwise zero), H 5% of
backing total and P durably initialized/lowered before hello. No free+C ratchet,
statfs fallback, per-pool image ledger, artificial cache charge or automatic GC.
A healthy zero cap is valid. Connect alone creates the retained project-owned
marker custom volume and matching backing sentinel, without repair/takeover.
Read-only inspection returns partial failures without provisioning anything.

The [shared policy](../../packages/sandbox-contracts/src/vm-size-limits.json)
currently uses 256-MiB VM overhead and max(2048 MiB,25%) host reserve pending
required live RAM calibration. Existing holds preserve historical charges across
that update. [capacity and storage qualification](../guide/hosts.md#capacity-and-storage-qualification)
remain owner-authorized release gates; no old journal/root conversion is supported.

## Integrated sharing consumers

The strict contract/OpenAPI and SDK expose shared-usable pool discovery, opaque
member views, independent SDK poolMode, nullable share resource caps and foreign
storage identity, acceptedGraceSeconds and accessGraceUntil. Public errors
sandbox.share_quota, sandbox.member_quota and sandbox.pool_policy_changed are
definitive 409 refusals; 429/5xx/lost acceptance retain unchanged-key reconciliation.
Native template verification uses an authorized pool/member branch for owned
exact revisions. Share/invite management and host terminal tickets remain oRPC
cookie-only; there is no SDK PTY or sharing-management scope. SDK examples compile
against these contracts. No automatic placement retry is allowed after acceptance.
