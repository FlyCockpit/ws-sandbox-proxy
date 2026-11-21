# Authentication planes

WS Sandbox Proxy has four authentication planes. Each has its own credential, endpoint
and checks, and **a credential from one plane is refused on every other
plane**. All four resolve to the same owner model: every host, template,
sandbox, operation and transfer belongs to exactly one user account.

| Plane   | Who                                      | Endpoint                                           | Credential                                                          |
| ------- | ---------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------- |
| Browser | You, in the dashboard                    | `/rpc`, `/api/dashboard/…`, the terminal WebSocket | Better Auth cookie session, CSRF, required-2FA policy               |
| SDK     | Your programs                            | `/v1/…`                                            | `Authorization: Bearer wssp_sdk_…`                                  |
| MCP     | Your agents                              | `/mcp`                                             | `wssp_agent_…` bearer token or OAuth access token backed by a grant |
| Host    | The `wssp host run` daemon on your hosts | `/ws/sandbox-host` (outbound WSS)                  | `wssp_host_…` (dashboard token) or `wssp_device_…` (device login)   |

## Browser plane

- Email/password sign-in with email verification, a cookie session and CSRF
  protection on every mutation. When the dashboard and API are on different
  origins (`CORS_ORIGIN`), the CSRF header is required.
- Two-factor authentication is required for administrators by default
  (`FORCE_2FA_DEFAULTS`); an administrator can also require it of everyone.
  Owner pages and the device-approval page use the same 2FA-gated procedures.
- Public signup is off by default (`SIGNUP_ENABLED=false`); addresses in
  `ADMIN_EMAILS` may sign up to bootstrap the first administrator.
- The browser terminal is part of this plane: a short-lived one-use ticket
  minted by a cookie-authenticated, CSRF-protected call. See
  [Sandbox terminal](./terminal.md).
- Admin routes (`/{lang}/admin`) answer not found to everyone who is not a
  verified, unbanned, 2FA-satisfying administrator. Admin views are metadata
  only: no commands, output, files, terminals or credential values of other
  owners.

## SDK plane

- Keys (credential kind `SdkKeyKind.API`) are minted on the **SDK keys** page and shown once. A key has
  [scopes](../../packages/sdk/README.md#keys-and-scopes), a resource mode
  (all owned resources, or an allowlist of hosts, exact revisions and pools) and an
  optional expiry. Revoke a key on the same page.
- Every `/v1` request re-verifies the key (owner policy, HMAC, expiry,
  revocation) with no principal cache, so a revoke or a ban applies to the next
  request. Cookies are ignored on `/v1`, `/v1` sends no CORS grants (it is not
  a browser API), and a bearer key never supplies a session to `/rpc`.
- Credentials in query strings are refused (`BAD_REQUEST`), even next to a
  valid header. Never put a key in a URL.
- Requests pass three fail-closed rate budgets: per client IP, per key and per
  owner (`RATE_LIMIT_SDK_*_POINTS`, per 60 seconds; defaults 300 per IP, 100
  per key, 300 per owner). Every `/v1` request counts, reads included, so one
  key polling faster than about once every 0.6 seconds runs out within the
  window. A throttled request is `TOO_MANY_REQUESTS` with `Retry-After`. The
  SDK's waits back off to one poll every 2 seconds and honor `Retry-After`;
  hand-written polling should do the same.
- `GET /v1/openapi.json` is the only anonymous route. Details:
  [native HTTP contract](../design/native-http-contract.md).
- `webhooks:write` manages webhook endpoints. It can be minted only on a key
  over all owned resources and all usable pools
  (`sdk_key.webhooks_requires_all_owned`), because an endpoint receives events
  for every sandbox on the account. An endpoint outlives the key that created
  it: revoking the key does not delete or disable its endpoints. See
  [webhooks](./webhooks.md).
- `sandboxes:connect` opens CLI shells and command channels in a sandbox as the
  guest user over `GET /v1/sandboxes/{id}/connect` (a WebSocket; not
  journaled). Only `SdkKeyKind.API` keys hold it: a `wssp login` with write access,
  or a dashboard key it was explicitly given (never a default). Agent tokens,
  OAuth grants and MCP never get it. Revoking the key ends its live shells.
  The CLI command is `wssp sandbox shell` ([shells from the CLI](./connect.md)).
  Contract: [CLI channel relay contract](../design/connect-channel-contract.md#client-wire-wsspconnectv1).
  On the dashboard it is its own "CLI connections" checkbox, never preselected
  and offered only on the SDK key form. Each connection is audited as metadata
  only (key, origin, sandbox, host, times, end reason, channel counts, bytes;
  never what ran) for 90 days: the sandbox detail page lists recent
  connections and the SDK keys page shows each key's last connect. See
  [Audit](../design/connect-channel-contract.md#audit).

### CLI user logins (`wssp login`)

`wssp login` gets an SDK key for the machine it runs on through a browser
approval, so you never paste a key into a terminal. (This is unrelated to the
CLI logins of the credential vault, which are tool sign-ins inside sandboxes.)

- The CLI starts a device authorization with the scope `user-login`. You open
  the approval page in a browser that is signed in to your account and choose
  the key there; the CLI supplies nothing that is shown on the page. Approve
  only a request you started yourself on the other device.
- You choose a name (default `wssp login`), access **read** or **write**, all
  usable pools or selected ones, whether the key sees only the sandboxes it
  creates, an optional limit on its live sandboxes, and an expiry of 1, 7, 30
  (default) or 90 days. There is no "never expires".
- **read** holds `hosts:read`, `pools:read`, `templates:read`,
  `sandboxes:read`, `commands:read`, `files:read` and `operations:read`. Read
  access still lets that device read files and command output in your
  sandboxes. **write** adds `sandboxes:create`, `sandboxes:manage`,
  `sandboxes:destroy`, `commands:execute`, `files:write`, `operations:cancel`,
  `sandboxes:tunnel` and `sandboxes:connect` (CLI shells). Neither ever holds host access (`hosts:execute`,
  `hosts:files`), template writes or builds, `webhooks:write` or any
  `credentials:*` scope.
- The exchange (`userLogins.exchangeDeviceCode`) mints an ordinary `wssp_sdk_`
  key over all owned resources, marked as a CLI login. It re-checks the
  selected pools and your account's credential policy at that moment, so a pool
  you lost access to after approving refuses the login. One account holds at
  most 20 active CLI-login keys; revoke an old one to log in again.
- Revoke a CLI login like any key on the **SDK keys** page, where it carries a
  "CLI login" badge, or from the device itself: `wssp logout` calls
  `DELETE /v1/key`, which only a CLI-login key may call on itself (any other
  key gets `key.self_revoke_forbidden`). `GET /v1/key` describes the calling
  key (name, scopes, pools, expiry, limit), never the account email.
- **Live sandbox limit.** A key with a limit can have at most that many live
  sandboxes it created at once (1 to 1000). A sandbox counts from its create,
  including while it waits for capacity, until its host confirms the destroy
  (or the host is lost); stopped sandboxes count. A create over the limit fails with
  `sandbox.key_limit_reached` (409) and the limit and count in `data`; retrying
  the same create (same idempotency key) still returns the sandbox it made.
  Sandboxes created by other keys or in the browser do not count. The limit is
  fixed at approval. There is no spend limit: wssp has no notion of cost.

## MCP plane

- Connect agents to `/mcp` using a person-minted agent token (`SdkKeyKind.AGENT_TOKEN`,
  `wssp_agent_…`) or OAuth access token backed by an `SdkKeyKind.OAUTH_GRANT` credential.
  The backing OAuth row has no bearer secret of its own. `/v1` accepts only
  `SdkKeyKind.API` keys; `/mcp` refuses API keys and does not authenticate cookies.
- Use **Settings → Agent tokens** to mint, list or revoke tokens and review
  **Connected apps**. The person picks the expiry: a preset, a custom date, or
  no expiry. Operators can turn off no-expiry tokens
  (`WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY`) and cap expiring ones
  (`WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS`, default 90). Turning no-expiry off
  also blocks existing no-expiry tokens (`agent_token.no_expiry_blocked`)
  until it is turned back on; they are listed as **Blocked by policy**, not
  revoked. At most ten unrevoked, unexpired tokens (no-expiry and blocked
  tokens included) can be active. Copy its secret once into the
  agent's secret store. OAuth consent shows the client, requested scopes,
  selected resource grants and **Own sandboxes only**; host scopes start
  unchecked. Only a person can consent or manage credentials.
- MCP tools use the same credential authorization as the native API: stored
  scopes, owner policy, allowlists, custody and creator limits. OAuth access
  token scopes are intersected with the backing grant's stored scopes on
  every request. Revoking a connected app revokes its grant and refresh tokens.
- API keys default **Own sandboxes only** off; agent tokens and OAuth grants
  default it on. ALLOWLIST credentials are always creator-restricted for
  sandboxes. Host access is a separate authority, described below.
- The MCP URL is your server origin followed by `/mcp`. **Agent tokens**
  shows connection instructions; keep bearer secrets out of URLs.

## Scoped host access

`hosts:execute` allows host commands, their status/output, stdin, cancellation
and queuing a command for a person. `hosts:files` allows host file
read/list/write/edit. `hosts:read` remains discovery only. Select a host grant
(all owned or explicit owned hosts) when minting either host scope; a shared
pool alone never qualifies. Host-only credentials do not need a template
revision grant.

Both `/v1` and `/mcp` can reach these tools, but only on nodes owned by the
credential's own user, with the host grant and local opt-in. The server checks
ownership and effective policy before dispatch; the daemon rechecks against the
owner from `hello.ok` and the live policy revision. Pool use never permits host
access to someone else's node. Only the starting credential can inspect,
write stdin to or cancel its host command.

**The daemon user is an Incus admin. Host commands and host file tools can
reach every sandbox on its node, including other users' shared-pool sandboxes.
Own sandboxes only does not limit them.** Local command/file and terminal
settings start off. The dashboard or node can turn them off; only an interactive
person on the node can turn them on. Lowering interrupts affected work. See
[node settings](./hosts.md#node-settings-for-agents-and-terminals) and
[ADR-006](../design/adr-006-agent-host-access.md), which supersedes the earlier
blanket restriction on SDK host execution. Browser terminals remain session-only.

## Host plane

- The daemon connects **outbound**; hosts need no inbound ports. HTTPS/WSS is
  required except for explicit loopback development origins, and
  credential-bearing requests never follow redirects.
- A **device credential** (`wssp_device_…`) comes from `wssp host enroll`: the
  daemon prints a verification URL and code, and you approve it in the
  dashboard (verified email and 2FA required). It is bound to one host slug and
  does not expire; revoke it on the **Host credentials** page.
- A **host token** (`wssp_host_…`) is minted on the **Host credentials** page,
  shown once, may expire, and is read by the daemon from an environment
  variable you name (`wssp host enroll --token-env <ENV_VAR>`), never from a flag or the
  config file.
- The server rechecks the credential, the owner's ban/2FA/deletion state and
  host ownership at hello, on every heartbeat and dispatch, and on every
  upload, stdin and download chunk. A revoked or expired credential, a ban or
  an owner deletion closes the connection with **4003**; `wssp host run` exits
  with code **4** and does not reconnect.
- The host plane carries terminal bytes, but a host credential can never open
  a browser terminal, call `/v1` or `/rpc`.
- Guests receive **no** control-plane credential of any kind.

## Plane separation, as enforced

| Presented                                     | Browser `/rpc` | SDK `/v1`    | MCP `/mcp`               | Host `/ws/sandbox-host` | Terminal upgrade             |
| --------------------------------------------- | -------------- | ------------ | ------------------------ | ----------------------- | ---------------------------- |
| Cookie session                                | accepted       | ignored, 401 | ignored, 401             | ignored, refused        | accepted with valid ticket   |
| `wssp_sdk_…` (`SdkKeyKind.API`)               | no session     | accepted     | refused, 401             | refused                 | refused (`CREDENTIAL_PLANE`) |
| `wssp_agent_…` (`SdkKeyKind.AGENT_TOKEN`)     | no session     | refused, 401 | accepted                 | refused                 | refused (`CREDENTIAL_PLANE`) |
| OAuth access token (`SdkKeyKind.OAUTH_GRANT`) | no session     | refused, 401 | accepted with live grant | refused                 | refused (`CREDENTIAL_PLANE`) |
| `wssp_host_…` / `wssp_device_…`               | no session     | refused, 401 | refused, 401             | accepted                | refused (`CREDENTIAL_PLANE`) |

The terminal upgrade refuses any `Authorization` header and any offered
subprotocol carrying a machine-credential prefix before it reads the cookie
([browser terminal authentication](../design/browser-terminal-auth.md#planes)).

## Rotating credentials

- **SDK key:** mint a new key, deploy it, revoke the old one.
- **Agent token:** mint a replacement on Agent tokens, update the agent, then
  revoke the old token. For OAuth, revoke the connected app and authorize again.
- **Host token:** mint a new token, update the environment variable the daemon
  reads, restart the daemon, then revoke the old token (its live connection
  closes with 4003).
- **Device credential:** run `wssp host logout` then `wssp host enroll --slug <slug>` on
  the host, and revoke the old credential in the dashboard. `wssp host logout` only
  removes local state; it does not revoke anything server-side.
- **`BETTER_AUTH_SECRET`:** rotating it invalidates every session **and every
  product credential** (host tokens, device credentials, SDK keys, agent tokens). Treat it as
  a full re-enrollment.

Retained sandbox authority names the exact
revision and the sandbox's current host (or, while offloaded, the host it last
ran on). A dashboard-only restore outside a key's allowlist ends that key's
access. Cold reconnect and restore keep the sandbox's pinned configuration.

Pooled SDK resources additionally require the retained origin-pool grant, together with current host and exact revision grants. `pools:read` enables paged discovery; members also require `hosts:read`. Browser-only pool/member writes retain owner session authority. See [pools](./pools.md).

## Minting SDK resource grants

An ALLOWLIST key used for sandbox placement needs explicit grants for each
exact revision and host; pooled placement also requires the pool. Host-only
keys can omit revisions but still need a directly allowed owned host. New revisions and memberships never
expand a key's existing grants. ALL_OWNED keys cover owned resources within
their scopes, expiry and account policy.

1. Sign in as the owner and satisfy the required-2FA policy. Host enrollment
   credentials do not authorize SDK requests.
2. Register each logical template on **Templates**. Record its new
   logical ID and exact revision ID; use **Manage revision** to verify the
   fingerprint on the intended hosts. A revision grant can be minted for
   **Verification pending** or **Verified image** association on a selected owned host, but only
   current **Verified image** evidence qualifies a new launch.
3. If using pools, create or select an owned pool and add/enable its hosts.
   Open **SDK keys → Mint SDK key** and choose **Only selected hosts, exact
   revisions and pools**. Select each allowed host, the exact revision IDs
   (not logical IDs), and each pool to be used. Page through all three
   pickers. Pool, host and revision grants intersect: none implies another.
   Direct placement needs host + revision; pooled placement adds the pool.
4. Select only the needed action scopes. For discovery use `pools:read`,
   `hosts:read` (also required for members) and `templates:read`. Creating
   requires `sandboxes:create`; inspect sandboxes with `sandboxes:read` and
   operations with `operations:read`. Command output additionally needs
   `commands:read` and `operations:read`; execution needs `commands:execute`.
   Choose a name and expiry and mint. The page displays exact grants beside
   each retained key so similarly named revisions cannot be confused.
5. Copy the key from the one-time panel into your application's secret store.
   Verify discovery with that new credential, then test an explicit-host or
   pooled create with its new IDs. Wait for READY and the exact intent ACK;
   retain the idempotency key and operation ID for recovery. Check expected
   403/404 refusals with deliberately ungranted resources without sharing IDs
   across owners. Example calls live in the [SDK README](../../packages/sdk/README.md#pools-and-immediate-fallback).
6. Deploy the new application credential, then revoke the old key after
   checking accepted/in-flight work. Revocation also prevents dispatch of
   accepted SDK work that has not been sent; it never authorizes replay under
   a sibling key. An uncertain create must keep its original key and body,
   never retry automatically with the replacement credential or a fresh key.

Appending a revision or adding a pool later does not expand an ALLOWLIST key.
Re-mint deliberately for new grants. Removing a pool member or deleting a pool
changes future placement; access to accepted pooled sandboxes still requires
the retained origin pool, current host and exact revision grants. Owner browser
sessions do not inherit a creating SDK key's scope or grant restrictions.

Workload env values are separate from credentials. Supply private defaults
from your secret source when registering/creating resources. Values are never
returned by metadata projections. See [private defaults](./sandboxes.md#private-environment-defaults).

## Tracked command disclosure and controls

`commands:read` on a granted sandbox lists all its tracked commands and argv/cwd,
including commands launched by browser sessions and other SDK keys, and permits
protected output attachment. It is not limited to the launching principal.
Store secrets in envs/private configuration, not argv. Result reads additionally
require `operations:read` and the scope for the stored result kind. Signals need
`commands:execute` plus `operations:cancel`; PID alone grants no authority.
Revoking an SDK key fences reads and unsent controls but does not cancel commands
it already started. Owner-browser controls use the live-owner gate and show
translated unavailability for impersonation; admin metadata never supplies guest
access. See the [filesystem and command scope guide](sandboxes.md#filesystem-and-command-result-limits).

## VM capacity and resource scope

Charged RAM and aggregate vCPU are owner-host budgets shared by all authorized pools, SDK keys and
direct placements. A key grant adds no resource entitlement; optional share RAM/vCPU/disk caps further restrict acquisitions. Local
storage caps account for retained root commitments. Authorization and visibility precede capacity checks, and hidden hosts
never enter pool diagnostics. A permitted create can reveal whether its visible
target fits; template-only or sandbox-only read grants do not disclose host
budgets. Admin metadata authority still gives no guest execution authority.

Cold boot retains the revision and immutable allocation, checking current fitting pool selection;
it does not resolve a current tag. It boots on the host that holds the disk, or
restores an offloaded disk onto an eligible host
([disk offload](./sandboxes.md#disk-offload)). Accepted same-key replay
returns the original result before current defaults or capacity are considered.
A key with the necessary pool, host and exact-revision grants can consume the
shared budget with one large valid VM. Unsupported versus accepted requests
reveal size fit only within its authorized members. Host budgets require
`hosts:read` and host grants; template defaults and sandbox allocation alone
never grant that disclosure. Allowlist exclusions retain 403; absent or foreign
ALL_OWNED resources retain their existing owner-scoped 404 responses.

Host reads alone expose bounded storage budgets, derivation scalars, usage and
health; sandbox/revision-only grants expose size and opaque retained allocation
identity without backing paths or host budgets. Admin authority stays metadata-only.
The dashboard cannot configure host-local storage. Owner login/2FA/device approval
and SDK grant checks are unchanged by the relay protocol.

## Shared pools and owner browser terminals

SDK poolMode is independent of owned host/revision resourceMode. ALL_USABLE
follows current use grants; SELECTED uses immutable pool selections. A foreign
member needs pool use plus the creator's revision, without a foreign host grant.
Owned members retain the owned-host intersection. The initial CREATE key keeps
retained creator history and cleanup authority (reads of the sandbox, its
operations and output; stop and destroy) after future grants disappear. Use
(guest IO, terminals, reconnect or restore, timeouts, credential attach and
capture) needs a current host and pool grant; new/cold placement needs current
selection, caps and usable paths. Different
selected keys cannot inherit history. Shared use confers no host management or
other creator's guest IO. Share RAM/vCPU/disk caps are optional additional caps.

Host terminals and share/invite/consent management stay cookie-only through
registered live-owner gates, with CSRF. SDK and MCP credentials never grant
browser terminal authority; their separate host commands/files follow
[ADR-006](../design/adr-006-agent-host-access.md). Admin/impersonation grants no
execution authority. Host and guest tickets use separate stores/path-specific
prefixes. Invitation signup requires token plus target email and mailbox proof;
existing-account bearer acceptance explicitly warns about forwarding. See
[pools](./pools.md) and [terminal](./terminal.md).

## Browser disclosure after revocation

Sensitive commands, files, processes, output and transfers require a live,
unexpired, non-impersonated durable owner session. Handlers recheck authority
and account/2FA policy before returning or rejecting. Downloads check before
each pull and after each source read; uploads check around body reads, before
acceptance and before returning. Revocation stops subsequent bytes and conceals
sensitive errors; it cannot revoke bytes already delivered.

An exit-time denial does not roll back committed work. After restoring an
authorized session, inspect operation history or recover the original intent
using its original idempotency key. A new-key retry can duplicate an effect.
Operation status exposes catalog errors and metadata; protected result reads
separately authorize guest payloads. Admin status grants no guest authority.

Credentials may enable **own sandboxes only**, including with all-owned resources. Such a credential can access only sandboxes whose original create used that credential, including commands, files and operation results. This restriction does not limit host commands or host file tools: the daemon is an Incus admin and can reach every sandbox on its node.
