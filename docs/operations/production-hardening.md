# Production hardening

Walk this checklist before taking real traffic. Pair it with
[deployment.md](./deployment.md) and [docs/infra.md](../infra.md).

## Checklist

- Unique `BETTER_AUTH_SECRET` (≥32 random characters) per environment. Rotating
  it invalidates all sessions and all product credentials (host tokens, device
  credentials, SDK keys).
- `BETTER_AUTH_URL` is the public HTTPS origin, no path.
- `ADMIN_EMAILS` lists the first admin mailbox, or the first admin was created
  with `SETUP_KEY` ([deployment](./deployment.md#first-admin-without-email))
  and `SETUP_KEY` has been removed since.
- SMTP is configured in production (`SMTP_*`). The server refuses to boot
  without it when signup or verification needs email.
- Rate limiters stay enabled (`apps/server/src/rate-limit.ts` and
  `apps/server/src/sandbox-api/middleware.ts`). Native `/v1` uses separate
  fail-closed Redis IP/key/owner budgets, each tuned by its own
  `RATE_LIMIT_SDK_*_POINTS` variable (per 60 s); see the
  [HTTP contract](../design/native-http-contract.md).
- CSRF stays on for `/rpc` and cookie OpenAPI procedures, including same-origin
  requests (`CORS_ORIGIN` does not control this check).
- Forced 2FA defaults in `packages/auth/src/two-factor-policy.ts` stay on for
  admins.
- Response compression is enabled on the TLS-terminating proxy.
- Backups are opt-in. If enabled, off-site backups are configured and a restore
  drill has passed. See
  [backup-and-restore.md](./backup-and-restore.md).
- Production secrets are not copied into local `.env` files.
- `DATA_ENCRYPTION_KEY` (if set) is stored apart from database backups; see
  [Data encryption key](#data-encryption-key).
- Hosts that run CLI logins use encrypted storage pools, encrypted or no
  swap, and `LimitCORE=0` on the daemon service; see [CLI logins](#cli-logins).
- With disk offload on (S3 image store plus `DATA_ENCRYPTION_KEY`), the image
  bucket has its own backup plan, and shredded disk keys are understood to
  survive in database backups until they expire; see
  [backup and restore](./backup-and-restore.md#disk-offload).

## Rate limiting

Each hard-hittable surface has its own limiter (`keyPrefix`). Do not lower a
shared IP budget to be "safe"; split the surface instead.

`/ws/sandbox-host` uses its own per-client-IP `rl:host-relay` bucket, independent
of browser `rl:auth`: 1200 upgrade attempts per 60 seconds. This covers eight
hosts behind one NAT retrying carried work every 0.5 seconds (the daemon's
1-second fast retry with minimum jitter), plus initial retry headroom.
The budget is fixed in code. Excess attempts receive 429 with `Retry-After`
in seconds. Redis failures refuse admission with
503 and `Retry-After: 5`; there is no in-memory insurance fallback.

Set `TRUST_PROXY_HOPS` to the exact number of trusted reverse proxies (the
generated Dokploy config sets `1` for Traefik; `--trust-proxy-hops N` counts
more, such as `2` for a Cloudflare Tunnel in front of Traefik). Unset or `0` keys on the socket
peer and ignores `X-Forwarded-For`; behind a proxy that puts every client in
one shared bucket. A port appended to the selected entry (`1.2.3.4:5678`,
`[2001:db8::1]:5678`) is stripped before validation. A short or malformed chain
falls back to the socket peer, never the leftmost entry. For values above `0`, restrict app access to the
trusted proxy chain. See
[client IP configuration](./environment-variables.md#client-ip-and-reverse-proxies).

Spend-bearing oRPC procedures need a procedure-level budget
(`createProcedureBudget`). `/rpc` counts HTTP requests, and one request
carries `ORPC_BATCH_MAX_SIZE` procedures.

Three named env budgets (AUTH, RPC, EMAIL) rescale their families.
Tighter is not safer. Defaults live in `packages/env`; override only when a
real user action costs that many requests.

### Per-recipient email flood limits

Verification resend, password-reset mail, and similar per-mailbox sends share
a recipient-keyed limiter. A 429 for one address does not block a different
mailbox. Media types Better Auth would refuse are rejected (415) without
spending a point.

## CSRF

`SimpleCsrfProtectionHandlerPlugin` is unconditional on `/rpc` and cookie
OpenAPI procedures. Every caller sends `x-csrf-token: orpc`, including same-origin
requests when `CORS_ORIGIN` is unset. The web and CLI already send it. Simple
form POSTs from a same-site sibling origin need no preflight, so conditional
CORS configuration alone cannot replace this check. Keep exact origins and the
header; never disable the plugin to make a caller work. Better Auth also retains
its own origin/CSRF checks. The `/api-reference` “try it” panel also needs the
`x-csrf-token: orpc` header; requests without it are expected to receive 403.
SDK `/v1` is bearer-only and uses no cookie auth.

## Admin gating and email verification

`ADMIN_EMAILS` (case-insensitive) is the bootstrap admin list. Signup with a
listed address receives the admin role; everyone else is `user`. Admin
procedures require a verified email. Without email, `SETUP_KEY` creates the
first administrator through a one-time link and is refused once an active
administrator exists ([deployment](./deployment.md#first-admin-without-email));
remove it afterwards.

Every admin surface decides access with one function,
`isAdminSessionAuthorized` (live, non-impersonated session; not banned or
deleting; verified email; admin role; forced 2FA satisfied): the oRPC admin
procedures, the admin write transaction, the API-reference route and the web
`/admin` route guard. A refusal is always a plain not-found. The admin
settings page confirms every policy change and cannot turn on a 2FA
requirement until the acting admin has 2FA.

### Who email verification gates

Email verification gates **admin** procedures, not every signed-in page.
`requireEmailVerification` only governs email/password sign-in. Returning
`redirect-to-login` for an unverified session loops against the
anonymous-only route helper. If a product genuinely requires verification
for all access, add an explicit verified-email gate that renders a
"check your inbox" page rather than bouncing back to login.

### No account-existence oracle on the anonymous auth endpoints

An anonymous caller cannot tell whether an address has an account. Sign-up,
resend verification, password-reset request and wrong-password sign-in
answer byte-identically (status, headers, body) for an unknown, a
registered-unverified and a registered-verified address.

- **Sign-up** needs our own hook. Better Auth answers a registered address
  with a synthetic user that lacks plugin defaults (`role: null` instead of
  `"user"`), and returns it before user creation, so with sign-up closed a
  registered address got 200 where a free one got 422. The after-hook in
  `packages/auth/src/signup-response.ts` answers every success with
  `{"token":null,"user":null}`. With sign-up closed, a 200 stands only when
  the request really created the user (an `ADMIN_EMAILS` bootstrap or a valid
  pool invitation of a new address); every duplicate, admin-listed or
  invited or not, gets the 422 a free address gets.
  `packages/auth/src/signup-response.pg.test.ts` pins both modes and the
  work each outcome does. Clients read only `error` from this call. Do not
  patch the synthetic user instead: a later plugin field would reopen it.
- **Resend, reset request, wrong-password sign-in** are uniform in Better
  Auth already. The per-recipient budget counts requests, not accounts.
- **Intended differences:** the right password on an unverified account
  answers 403 `EMAIL_NOT_VERIFIED` and re-sends the link; a new
  `ADMIN_EMAILS` address or a valid invitation can sign up while sign-up is
  closed.
- **What a sign-up of a free address still reveals:** that sign-up creates
  the account and mails its owner, so the caller can learn the address _was_
  free (the 403 above, the extra time a new account and its mail cost, or a
  422 when two concurrent sign-ups race). Nothing is learned about an
  address that already has an account. Do not add work that only one
  outcome pays for.

## Forced two-factor authentication

`FORCE_2FA_DEFAULTS` requires a second factor of internal (admin) users when
the AppSetting row is absent. `TWO_FACTOR_ENROLLMENT_GRACE_MS` is the only
window in which an unenrolled admin still gets through. Do not flip that
default to `false`, lengthen the grace, extend it to any check other than
forced 2FA, or drop `createdAt` from a call site or session projection so
the grace silently never ends.

## CSP

`apps/server/src/security-headers.ts` owns the policy. Do not add
`'unsafe-eval'`, `'wasm-unsafe-eval'`, `blob:`, or wildcard sources.

## Secrets and environment

No `.env` file is baked into the image. Inject values from the orchestrator.
Do not log env var values. Generate production values with
`pnpm generate:secrets`. Adding a variable is a two-file change:
`packages/env/src/vars/*.ts` then `scripts/lib/env-manifest.ts`, then
`pnpm env:sync`. See [environment-variables.md](./environment-variables.md).

## Data encryption key

`DATA_ENCRYPTION_KEY` is the one root key for data encrypted at rest. Each
purpose derives its own sub-key from it (HKDF-SHA256): webhook endpoint
signing secrets, the CLI-login vault (value DEKs and return private keys),
and the per-upload keys of offloaded sandbox disks.

- **Custody.** Keep the key in the deployment platform's secret store and
  keep a copy somewhere other than the database and its backups (a password
  manager or a separate secrets vault). A backup that holds both the
  ciphertext and the key protects nothing; a backup restored without the key
  restores nothing usable.
- **Loss.** Losing the key, with no previous copy, makes every value sealed
  under it unrecoverable: owners must rotate their webhook endpoint secrets,
  and every stored CLI login must be entered again. Every `OFFLOADED`
  sandbox becomes unrestorable. There is no recovery path through `BETTER_AUTH_SECRET` or the database.
- **Same value everywhere.** The server encrypts and the worker decrypts, so
  both carry the identical value.
- **Which kid writers use.** The database decides, not the env. The singleton
  `data_key_epoch` row names the root kid (first 16 hex of SHA-256(root)) that
  every encrypted writer must seal under: webhook secret create, rotate and
  rekey, CLI-login values, their rewrap, and return keys. Each writer reads
  that row `FOR SHARE` in its own transaction. A process that lacks that root
  refuses the write as retryable (`503`, or a deferred capture). It never
  writes under the wrong key. The first writer creates the row with its own
  `DATA_ENCRYPTION_KEY`.
- **Rotation runbook.** Run every step on the server **and** the worker:
  1. Generate the new key (`openssl rand -hex 32`). Deploy with the **new** key
     as `DATA_ENCRYPTION_KEY_PREVIOUS` and the old key still as
     `DATA_ENCRYPTION_KEY`. Every process now holds both keys.
  2. Switch writers: `pnpm data-key:promote <new kid>`, or **Promote** on the
     admin data-key card (Admin → Observability → Maintenance). The switch
     waits for in-flight writers. Once it commits, no row can be written under
     the old kid. A process still missing the new key refuses writes as
     retryable until it is redeployed.
  3. Deploy with `DATA_ENCRYPTION_KEY=<new>` and
     `DATA_ENCRYPTION_KEY_PREVIOUS=<old>`.
  4. Wait for `safe_to_remove` on the old kid (`pnpm data-key:status`, or the
     card). The worker's 60 s maintenance tick rewraps CLI-login DEKs, live
     return private keys and offloaded-disk key wraps, and re-encrypts webhook secrets, in bounded batches.
     A count of zero stays zero because of the switch. The heartbeats show
     which processes hold which kids. They are advisory and never gate anything.
  5. Remove `DATA_ENCRYPTION_KEY_PREVIOUS`.
- **What rotation does not do.** Rewrapping does not revoke the old key
  against old backups or database copies. Anyone holding both still decrypts
  what those copies contain. After a suspected key compromise, also make
  owners rotate their webhook secrets and log their CLI logins in again with
  their providers. A destroyed return key keeps its empty `wrappedPrivate`. It
  holds nothing under any root, so it is never rewrapped or counted.
- **Return keys** are separate from the data key. **Rotate return key** on the
  same card retires the current host-sealing keypair and issues a new one.
  **Destroy** a retired key (type its kid to confirm) only after every host
  that was issued it has acked a newer key and reported a drained census. The
  other way through the gate is **Declare lost**: a host that will never
  reconnect, declared per host (irreversible, audited). Live quarantined
  envelopes under the key also need **destroy anyway**. Elapsed time never
  authorizes destruction.

## CLI logins

CLI logins ([guide](../guide/cli-logins.md)) store owners' tool sign-ins in
the vault under `DATA_ENCRYPTION_KEY` ([design](../design/credential-vault.md)).

- **On by default.** With `DATA_ENCRYPTION_KEY` set, logins are available and
  nothing else is needed. Without it they are unavailable (boot never fails).
- **Turning them off.** `CREDENTIALS_ENABLED=false` on the server and the
  worker. With the key still set this is **drain mode**: new use is refused
  (`credential.unavailable`), while captures, frees, force-release, deletes
  and rewraps keep working so the values already in sandboxes come back.
  Keep the key until every login is deleted: removing it leaves stored values
  undecryptable and turns arriving captures into deferred retries on the
  hosts.
- **Instance cap.** `CREDENTIAL_MAX_INSTANCES_PER_OWNER` (default 1000, or
  `unlimited`); see
  [environment variables](./environment-variables.md#data-encryption-key).
- **Key rotation** follows the [runbook above](#data-encryption-key): rewrap
  covers login values and return keys. After a suspected key compromise,
  owners must also sign their logins out with each provider and log in again.
- **Host hygiene.** The daemon holds values in memory only while installing,
  capturing or proxying, wipes them on drop and marks itself non-dumpable.
  Scrubbing removes files inside the guest but cannot reach the guest
  filesystem's free blocks, storage-pool copy-on-write extents, snapshots or
  backups. Use encrypted storage pools and encrypted or no swap, and keep
  `LimitCORE=0` on the daemon's systemd unit (the
  [example unit](../../apps/cli/examples/wssp-host.service) sets it).
- **Before draining or removing a host,** have owners stop the sandboxes that
  hold logins so their files are copied back.
- **Disk offload.** A stopped disk that once held logins may be offloaded:
  it is encrypted on the host before it leaves, and resumes only on the
  owner's own hosts. While it exports, the source host holds short-lived
  plaintext copies (Incus image store and daemon staging), so put the image
  cache and staging on encrypted storage too. The offloaded disk may still
  hold every login value it ever saw, freed blocks included, and the control
  plane can decrypt it. Residual risks:
  [credential vault § whole-disk offload](../design/credential-vault.md#whole-disk-offload).
  Database backups keep shredded disk keys until they expire
  ([backup and restore](./backup-and-restore.md#disk-offload)).

## Webhook egress

Webhook deliveries are outbound HTTP requests from the worker to URLs your
users choose, so the worker is an SSRF surface. The destination policy
([webhooks guide](../guide/webhooks.md#destinations)) refuses every non-public
address on every attempt, pins the connection to the validated address, never
follows redirects and hard-denies cloud metadata. Keep it that way:

- **Allowlist risk.** `WEBHOOK_ALLOWED_PRIVATE_CIDRS` / `_HOSTS` open private
  destinations. Keep `WEBHOOK_PRIVATE_ALLOWLIST_SCOPE=admins` (the default)
  unless every account on the deployment is trusted: with `all`, any user can
  reach the allowlisted network from your worker. Allowlist exact `/32`s or
  single hosts, not whole ranges.
- **NAT64 / DNS64.** The well-known translation prefixes (`64:ff9b::/96`,
  `64:ff9b:1::/48`) and every other IPv4-embedding IPv6 form are always
  hard-denied. If the worker's network runs a translator with a
  network-specific prefix (RFC 6052, for example `fd12:3456:789a:bcde::/64`),
  list it in `WEBHOOK_TRANSLATION_PREFIXES`: its whole range is then
  hard-denied (an address there reaches an IPv4 host, including
  169.254.169.254, through the translator), and an allowlist CIDR
  overlapping it fails boot. Without it, such a ULA prefix is only "private"
  and an allowlist covering it would open the translator.
- **Plaintext.** Leave `WEBHOOK_ALLOW_PLAINTEXT_PRIVATE=false` in production.
  It only ever applies to allowlisted private destinations.
- **Defense in depth.** Filter the worker container's egress at the network
  level too (no route to metadata endpoints, internal admin networks or the
  database's management plane). The application policy is the primary
  control, not the only one.
- **Residual risk.** Owners can make the worker send requests to public
  addresses and ports 443 or 1024-65535 they choose; budgets (test-send 5/min,
  redeliver 30/min per owner) bound the rate, so public port scanning at low
  rate remains possible. Logs and admin views record only the destination
  host, ids and an error class.
- **Key rotation.** Endpoint secrets are encrypted under a sub-key of
  `DATA_ENCRYPTION_KEY`; rotate it as described in
  [Data encryption key](#data-encryption-key).

## Sharing and host terminal authority

Keep live-owner/CSRF gates for all consent and execution writes. Pool/host owners
and admins cannot access another creator's guest IO through physical custody.
Local incus-admin operators can reach every VM; this trust must be disclosed.
Default host terminals off/required; dashboard enable/lower is unsupported.
Required proofs need durable observation/cooldown/watermark/locks and fail-closed
budgets; codes and digest-ticket secrets never enter logs/caches/storage.
Withdrawal retains disk through accepted grace and cleanup proof; offline/dead
storage can block deletion longer. Run the separately authorized
[qualification stages](./sharing-terminal-qualification.md), including live A/B
IPv4/IPv6 lateral denial, before claiming isolation or release readiness.

## Scheduled deletion notices

Every 15 minutes, the worker checks deletions from the last 14 days and emails
verified admins who opted into operational alerts. SMTP must be configured. It
marks a notice only after at least one actual successful send; no recipient or
all-send failure leaves it pending. Mark failure or a crash after delivery can
produce a duplicate on retry. Emails use localized recovery links to
[schema migrations](../schema-migrations.md), and name the pre-deletion backup
when available. Recover selected data rather than silently rolling back all
newer writes. Restore procedures remain owner-controlled.
