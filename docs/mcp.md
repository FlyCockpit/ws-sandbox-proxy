# Built-in MCP server

WS Sandbox Proxy serves a stateless, JSON-only MCP endpoint at `https://HOST/mcp`.
It accepts POST requests only, caps JSON bodies at 1 MiB, and supports the modern
MCP 2026-07-28 protocol. It has no sessions, SSE subscriptions, browser cookie
authentication, or CORS authentication path. `MCP_ENABLED=false` disables the
endpoint, OAuth provider, JWKS, and discovery routes; the default is `true`.

## Authentication and authority

Use either a person-minted `wssp_agent_` token or OAuth 2.1. SDK keys
(`wssp_sdk_`), host credentials, and device credentials cannot authenticate to
MCP. Conversely, agent tokens and OAuth grants cannot authenticate to `/v1`.
Agent tokens are shown once when created in settings. The default selection is the longest preset up to 90
days that the deployment permits; smaller limits use a custom date. Choose a 7-day,
30-day, 90-day or one-year preset, a custom local date (end of day), or **No
expiry** when permitted. Tokens without an expiry remain active until revoked,
or until the operator stops allowing them; store them securely. At most ten
active tokens are allowed, including tokens without an expiry and tokens
blocked by policy.

`WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY` defaults to `true`. Setting it to `false`
requires an expiry on new tokens **and blocks every existing no-expiry agent
token**: `/mcp` refuses it with HTTP 401, JSON-RPC error `-32000` and
`error.data.code` `agent_token.no_expiry_blocked` (also in the
`WWW-Authenticate` `error_description`), and work it authorized (queued
dispatch, builds, stored principals) loses authority at its next credential
check. The flag is read at startup, so changing it takes a restart; during a
rolling deploy, instances on the old and new setting can briefly disagree.
Blocked tokens are not revoked or deleted; **Settings → Agent tokens** marks them **Blocked by policy**, and
setting the flag back to `true` makes them work again. Dated agent tokens are
unaffected. `WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS` defaults to `90` and accepts
integers from `1` to `3650`. A dated token must expire in the future and within
that many 24-hour days of minting; changing it does not affect existing tokens.
Neither flag applies to OAuth grants or SDK keys.

OAuth supports PKCE S256, dynamic client registration (DCR), and client ID
metadata documents (CIMD). Access tokens last 600 seconds; rotating refresh
tokens have a 72-hour inactivity lifetime and a 30-second rotation retry window.
DPoP-bound tokens require a valid proof. Verification always rebuilds the request
against the configured `BETTER_AUTH_URL`, so forwarded host names cannot change
the resource audience or DPoP `htu`. A proxy must preserve the public Host header.

The OAuth issuer is `https://HOST/api/auth`; the protected resource is
`https://HOST/mcp`. Discovery is available at:

- `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server/api/auth` and `/api/auth/.well-known/oauth-authorization-server`

OAuth scopes are the [service scopes](mcp-tool-coverage.md) plus `offline_access`.
Registration config defaults are `sandboxes:read hosts:read offline_access`;
registered clients may request every supported service scope. Authorization
requests must explicitly name a nonempty scope and the MCP resource.

The consent page is `/{lang}/mcp-consent`, with login handoff through
`/{lang}/mcp-login`. A person chooses a subset of the client's requested scopes,
resource and pool modes, host/template/pool/login allowlists, and
`ownSandboxesOnly` (default `true`). Host execute/file scopes should start
unchecked. An OAuth grant is backed by an `OAUTH_GRANT` credential with no secret.
Every MCP request reloads the grant and intersects stored scopes with token
scopes. Revocation invalidates access immediately and deletes that user's access
and refresh tokens for the client. A revoked consent generation requires signing
in again; it is never revived by a refresh or replayed authorization code.
Consent checks a durable, unexpired, non-impersonated session inside the grant
transaction, holding a session share lock against revocation before changing
a backing key or letting the provider remember approval. Existing session-bound
grants may only narrow scopes and resource authority (including own-only and
offline access). To widen a grant, sign out, sign in again and start a fresh
authorization request. Replaying a signed consent query cannot widen a grant.

All tool calls use the native API's credential services. The credential's stored
scopes, resource allowlists, and creator restrictions remain authoritative. There
is no Read/Full permission level. Credentials cannot manage tokens, keys, grants,
node settings, terminals, or run/dismiss queued host commands.

Host tools require an owned, granted host and its node-local agent access opt-in;
files also need configured file roots. Host access is off until a person enables
it at the node. Once enabled, an agent with host access can do whatever the wssp
daemon user can do: host commands and host file tools (inside the configured
roots) run as the daemon user, including Incus administration if the daemon user
has it. They can reach every sandbox on that node, including other users'
sandboxes in shared pools, change that node's settings and read the daemon's own
credential. **Own sandboxes only does not limit host commands or host file
tools.** `host_list` filters out foreign hosts while preserving the native
bounded pagination cursor.

The node-local gate stops remote/dashboard/credential raises and accidents, not
an agent that already has host exec. The emergency stop is the dashboard
lower (a durable server-side veto the node cannot undo) plus revoking the
credential. The veto persists after off reports and reconnects; on reports
trigger another lower request. Only a live owner browser session can choose
**Allow again**, which lifts the block without enabling the node setting.
Processes started outside the daemon's process tree, such as cron jobs and
systemd user units, are not stopped by lowering.

Raise settings in a local login session on the node. Dashboard host terminals
are refused by the `WSSP_HOST_TERMINAL` marker and the raise gate's ancestry
check.

## Tools and results

The [generated coverage table](mcp-tool-coverage.md) lists all 24 tools, their
required scopes, their service actions, and every action without an MCP tool.
Groups cover sandbox list/get/wait/create/stop/destroy, command
run/start/output/stdin/cancel, guest file read/list/write, owned host list/get,
host command run/get/cancel/queue, and host file read/list/write/edit.
A tool is listed only when every required scope is present. Calling a hidden
tool has the same `Tool <name> not found` response as an unknown tool.

Success responses contain text plus `structuredContent.result`. Errors contain
`structuredContent.error` with `code`, a public `message`, and applicable
`reason`, `retryable`, `retryAfterSeconds`, and `idempotencyKey`. Internal exception
messages are never returned. Host file text/output is masked by the daemon.

Command execution can wait at most 60 seconds. `command_run` starts once, returns
bounded output pages and a final command result (including exit code), or a
receipt and cursor when the wait or output bound is reached. Continue with
`command_output`; a timeout detaches without starting another command. Host
commands return status and bounded, base64-encoded stdout/stderr with absolute
masked-byte offsets; pass those offsets to `host_command_get`.

Guest file read/list first create native operations. With `operations:read`, the
tool waits up to 60 seconds and returns captured base64 file bytes or a directory
result. Otherwise it returns the operation receipt. To continue a pending read,
repeat the original arguments with its `operationId`; this does not create a new
operation. `file_read` accepts byte `offset` and `maxBytes` (up to 256 KiB).
`file_write` accepts at most 256 KiB of UTF-8 text, uses the native resumable
upload store, and returns its commit receipt.

Every mutating or operation-creating tool accepts an optional `idempotencyKey`
with the same validation as `/v1`'s `Idempotency-Key`. When omitted, a key is
generated and returned on success or service failure. Retain the key and retry
the exact same arguments after a lost response; changing arguments under that
key can produce an idempotency conflict. Host read/list POST operations preserve
the native requirement for a key as well. Host file writes and edits are not replayed
from the key: a retry runs again, so pass the `expectedEtag` from the last read
to make an edit retry fail instead of applying twice. Node access policy and resource
permission failures require a person or operator decision; they should not be
retried blindly. Retryable capacity failures include the deployment's
`CAPACITY_RETRY_AFTER_SECONDS`; nonretryable failures omit retry delays.

## Rate limits

All buckets use Valkey, are shared across replicas, and fail closed:

| Boundary                   | Budget per minute | Key           |
| -------------------------- | ----------------- | ------------- |
| MCP before authentication  | 300               | Client IP     |
| MCP after authentication   | 120               | Credential ID |
| Sandbox creates            | 30                | Credential ID |
| Host command starts        | 30                | Credential ID |
| OAuth protocol requests    | 120               | Client IP     |
| OAuth consent/continue     | 30                | Client IP     |
| OAuth dynamic registration | 5                 | Client IP     |

Existing native service owner/write budgets and browser auth limits also apply.
A limit refusal includes `retryable: true` and `retryAfterSeconds`. HTTP admission
refusals also send `Retry-After`; tool-call refusals carry the delay in their MCP
structured error. Infrastructure failures refuse admission with 503.

## Claude Code

The installed CLI's `claude mcp add --help` confirms HTTP transport and headers:

```sh
claude mcp add --transport http wssp https://HOST/mcp
```

Authenticate through the client's OAuth flow, or configure an agent token:

```sh
claude mcp add --transport http wssp https://HOST/mcp --header "Authorization: Bearer wssp_agent_REPLACE_WITH_YOUR_TOKEN"
```

## Codex

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.wssp]
url = "https://HOST/mcp"
bearer_token_env_var = "WSSP_AGENT_TOKEN"
```

Set `WSSP_AGENT_TOKEN` in the environment used to launch Codex. For OAuth, omit
`bearer_token_env_var` and run:

```sh
codex mcp login wssp
```

The installed CLI supports explicit comma-separated scopes, for example:

```sh
codex mcp login wssp --scopes sandboxes:read,hosts:read,offline_access
```

## Consent integration contract

The web consent page submits a cookie-authenticated JSON POST to
`/api/auth/oauth2/consent`, retaining Better Auth's Origin/CSRF checks:

```json
{
  "accept": true,
  "oauth_query": "SIGNED_QUERY_FROM_THE_CONSENT_URL",
  "scope": "sandboxes:read hosts:read offline_access",
  "resourceMode": "ALL_OWNED",
  "poolMode": "ALL_USABLE",
  "ownSandboxesOnly": true,
  "hostIds": [],
  "templateRevisionIds": [],
  "poolIds": [],
  "credentialIds": []
}
```

`scope` is an explicit space-separated subset of the signed request. Include
`offline_access` only if it was requested and refresh access was approved.
`ALLOWLIST` uses the same validity and ownership rules as SDK key creation;
host execute/file scopes require at least one directly selected owned host.
The resource mode is required; omitting `ownSandboxesOnly` means `true`.
A denial sends `accept: false` with the same `oauth_query`. On success follow
the returned `{redirect: true, url}`. Storage failures withhold the code and
forget the approval. The server binds consent recording through
`bindMcpGrantServices`, and binds grant revocation through
`bindMcpGrantTokenRevocation` when constructing the app.
