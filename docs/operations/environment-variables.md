# Environment variables

`@wssp/env/{shared,server,web}` **validate** `process.env`. They never load a
file. Loading belongs in process entrypoints. Mixing the two takes the
production web SSR bundle down: Vite leaves a stray `import "dotenv"` as a
runtime external that is not resolvable from `apps/web/dist/server/assets/`.

## Validation vs loading

- Validation modules (`packages/env/src/{shared,server,web}.ts`) read
  `process.env` only. They must not import `dotenv`, `./load-dotenv`, or
  `./root-env`.
- Process entrypoints load the repo-root `.env` before any validation runs.
- Production containers inject env at runtime and ship **no** `.env` file.
  `load-dotenv` is a no-op when the file is absent.

Three files may import `dotenv` directly (enforced by
`pnpm env:check-entrypoints`):

- `packages/env/src/root-env.ts` — the single implementation of root-`.env`
  loading
- `scripts/generate-secrets.ts` — `parse()` only, for the dotenv round-trip of
  generated blocks; never loads a file
- `packages/db/prisma.config.ts` — must stay self-contained. Dockerfiles run
  `prisma generate` during `pnpm install` **before** `COPY . .`, so importing
  `@wssp/env/root-env` there fails the image build.

Everything else uses `import "@wssp/env/load-dotenv"` (side effect) or
`loadRootDotenv()` from `@wssp/env/root-env`.

**First-party entrypoints that must load the root `.env`** (checklist when
adding a new script that imports `@wssp/env/*` or a package that does):

| Entrypoint                                | Mode               | Why                                                                                                                                                      |
| ----------------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/server/src/bootstrap.ts`            | wrapper            | The **built** Hono entry (`dist/index.mjs`) — source order is not enough once you bundle                                                                 |
| `apps/worker/src/bootstrap.ts`            | wrapper            | The **built** BullMQ worker entry, same reason                                                                                                           |
| `apps/server/src/index.ts`                | side effect        | Hono process under `tsx` (`pnpm dev`), where plain ESM order applies                                                                                     |
| `apps/worker/src/index.ts`                | side effect        | BullMQ worker under `tsx`, same reason                                                                                                                   |
| `scripts/doctor.ts`                       | side effect        | `pnpm doctor`                                                                                                                                            |
| `scripts/translate-locale-bundles.ts`     | side effect        | `pnpm i18n:translate`                                                                                                                                    |
| `packages/db/prisma/seed.cli.ts`          | side effect        | `prisma db seed` / direct `tsx` of the seed CLI                                                                                                          |
| `packages/api/src/crypto/data-key.cli.ts` | side effect        | `pnpm data-key:status` / `pnpm data-key:promote`                                                                                                         |
| `apps/web/vite.config.ts`                 | `loadRootDotenv()` | Config-time only — TanStack Start server functions during `vite dev` run in the Vite process, not `apps/server`. **Not** in the client/SSR output graph. |

**That table is enforced, not advisory.** `pnpm env:check-entrypoints`
(`scripts/check-load-dotenv-contract.ts`) asserts each row loads the root
`.env` in its declared mode, that every side-effect entry does it as its
**first** import, that no validation module imports dotenv, that nothing
outside the allowlist imports `dotenv` directly, and that this table and the
script's `ENTRYPOINTS` list agree. Adding an entrypoint is a two-file change:
the script and this table.

A bundled bootstrap file may have **no static import other than the loader**.
`tsdown.config.ts` must build `./src/bootstrap.ts`. Add a static import and
the bundler hoists validation ahead of the loader.

Keep `VITE_*` in `apps/web/.env`. A `VITE_*` key in the root `.env` outranks
the app-local file once `vite.config.ts` loads the root file.

## Which schema

Three declaration modules in `packages/env/src/vars/`:

- `vars/shared.ts` — server **and** worker (`DATABASE_URL`, `REDIS_URL`,
  `BACKUP_*` / `RESTORE_*`, `SMTP_*`, translation keys)
- `vars/server.ts` — server-only (`BETTER_AUTH_*`, `VAPID_*`,
  `RATE_LIMIT_*`). No key may appear in both shared and server.
- `vars/web.ts` — `VITE_*`, inlined into the browser bundle. Public. Never a
  secret.

## Adding a new environment variable

1. Declare it in the right `packages/env/src/vars/*.ts` object — never inline
   in `createEnv`.
2. Add an entry to `scripts/lib/env-manifest.ts`.
3. Run `pnpm env:sync` and commit the regenerated `.env.example` files.

## The CI gate

`pnpm env:check` fails when a Zod schema key is missing from the manifest, a
manifest entry names a key or group that does not exist, a variable is
declared inline in `createEnv`, or a generated `.env.example` is stale.

`pnpm env:check-entrypoints` is the load/validate contract described above.

`pnpm generate:secrets` builds a ready-to-paste production env block.
See [production-hardening.md](./production-hardening.md).

## Client IP and reverse proxies

Anonymous rate limits and audit records key on the client IP. The server never
trusts `X-Forwarded-For` by itself: `TRUST_PROXY_HOPS` is the exact number of
reverse proxies you run between the client and the server.

| Topology                                                                  | `TRUST_PROXY_HOPS`         |
| ------------------------------------------------------------------------- | -------------------------- |
| Generated Dokploy config or Compose (client → Traefik → server)           | `1` (set by the generator) |
| Cloudflare → Traefik → server, with Traefik trusting Cloudflare's ranges  | `2`                        |
| No proxy: the server port is reached directly (LAN, bare host, local dev) | unset or `0` (default)     |

- **Unset or `0`:** the key is the TCP socket peer; `X-Forwarded-For` is
  ignored, so a LAN client cannot pick its own key. If a proxy is in front and
  the value stays `0`, every client is keyed on the proxy's address and shares
  **one** rate-limit bucket: one noisy client can exhaust the anonymous and
  `/v1` IP budgets for everyone. That fails safe but is wrong for a proxied
  deployment. The server logs one warning per process when a private peer sends
  `X-Forwarded-For` while the value is `0`.
- **`N` ≥ 1:** the key is the entry `N` positions left of the socket peer in
  `[...X-Forwarded-For, socket]`. When the chain is shorter than that, or the
  selected entry is not an IP address, the key is the socket peer, never a
  client-supplied entry. A port the proxy appended to the selected entry is
  stripped first (`203.0.113.9:5678` and `[2001:db8::1]:5678` both work; a
  bare IPv6 address is used as is), so proxies that append ports by default,
  such as Azure Application Gateway, need no change. The server must be reachable only through those
  proxies (the generated Compose publishes no host port), and each proxy must
  append the address it received the request from. A value above your real
  proxy count lets clients choose their own key again, so count exactly.

## Host and connection caps

Server-only resource caps, both in the `sandbox-relay` group:

- `SANDBOX_MAX_HOSTS_PER_OWNER` (20): hosts one account may have, counting
  hosts pending deletion (their credentials still connect until the host is
  removed). A whole number from 1 to 100000, or the word `unlimited`.
  `sandboxHosts.createHost` and device-login enrollment both check it in the
  inserting transaction, serialized per owner by a transaction-scoped advisory
  lock taken after the shared owner lock, so concurrent creates cannot pass it.
  Refusals are HTTP 409 with `data.code = "sandbox.owner_host_limit"`.
  Device-login approval checks it too, so the owner sees the refusal in the
  browser; the enrollment check is the authoritative one.
- `SANDBOX_MAX_SOCKETS_PER_HOST` (2): concurrent host-daemon WebSockets for one
  host on one server process, counting sockets still waiting for their hello.
  A whole number from 1 to 64. There is no unlimited form, because each socket
  can hold an 8 MiB receive queue; a working host uses one, plus one while a
  reconnect overlaps a dying socket. An extra socket receives a
  `protocol.error` (`rate_limited`) naming the variable and is closed with
  1013; the daemon logs it, keeps its running work, and reconnects after a
  longer backoff (at least about 5 s). With several server
  replicas the bound applies per replica.

`SANDBOX_EGRESS_BLOCKLIST` (unset, `sandbox-relay` group, not in
`.env.example`) is the deployment-wide egress blocklist: IPv4 CIDRs
(`a.b.c.d/p` or a bare address) and domain names, separated by commas or
spaces. After each host's hello the relay sends it as `egress.blocklist` to
daemons that report the egress capability; each daemon hands it to its host's
egress guard as the `deployment` source, which is unioned with the host's root
list (`/etc/wssp/egress-blocklist`). CIDRs apply live to running sandboxes;
domains apply to sandboxes created afterwards. Unset or empty sends an
explicit "not configured", which clears the source. The relay validates the
list at boot with the guard's grammar and limits (at most 4096 CIDRs and 2048
domains, and the frame limit of 64 KiB) but does not fail boot: an invalid
list is logged with the position of the first bad entry (never the list) and
is not sent, so each host keeps the last list it received and a host without
one cannot start new sandboxes. An invalid entry therefore refuses admission
rather than clearing the list: it is never treated as empty. Changing the
variable takes effect when the server restarts and the hosts reconnect. See
[network egress](../guide/network.md#what-is-always-blocked).

`WSSP_CLI_RELEASE_BASE_URL` (unset, `sandbox-relay` group, not in
`.env.example`) is where `/install.sh` downloads `wssp-<target>.tar.xz` and
`sha256.sum` from: a mirror of this server version's CLI release. Unset, it is
this version's GitHub Release
(`https://github.com/FlyCockpit/ws-sandbox-proxy/releases/download/v<version>`).
A plain `https://` URL without query, quotes or spaces (the script embeds it
in single quotes); a trailing `/` is dropped. The script refuses an archive
whose checksum, layout or `--version` does not match, so a mirror must hold
exactly this version's archives. Takes effect on restart. See
[installing the CLI](../guide/cli.md#install).

A single-owner deployment that fills several large machines can set
`SANDBOX_MAX_HOSTS_PER_OWNER=unlimited`. Per-host sandbox capacity is the
daemon's charged RAM, total-vCPU and local storage budgets
([hosts guide](../guide/hosts.md#capacity-drain-and-deletion)), not these caps.

## Transfer storage

Server-only knobs: `TRANSFER_SPOOL_DIR` (private persistent directory),
`TRANSFER_MAX_BYTES` (1 GiB; also its ceiling, because the node daemon stages at
most 1 GiB per file: a larger value fails startup), `TRANSFER_DISK_BYTES` (10 GiB),
`TRANSFER_OWNER_ACTIVE` (4), `TRANSFER_GLOBAL_ACTIVE` (16),
`TRANSFER_IDLE_SECONDS` (900), and `TRANSFER_ABSOLUTE_SECONDS` (3600).
The two `_ACTIVE` limits count open transfers. An upload gives its slot back
when its guest write operation succeeds, fails or is cancelled. A download
gives it back once every byte has been delivered; its content then stays on
disk, still counted in `TRANSFER_DISK_BYTES`, for a fixed 60-second resume
grace, and a resume in that grace takes a slot of its own. Idle expiry only
cleans up abandoned transfers, and an `UNKNOWN_OUTCOME` upload keeps its slot until then.
A full store answers `429 TRANSFER_QUOTA` with `Retry-After: 5`.
The chunk ceiling stays fixed at 1 MiB. Total-byte arithmetic uses safe integers
at the service boundary and bigint reservation sums in PostgreSQL. The spool
starts on every server startup and recovers before server readiness.
See [deployment](./deployment.md#persistent-transfer-spool) for volume ownership
and the single-server update policy.

The `SIGNUP_ENABLED` deployment value is the default when no `signupEnabled`
application setting exists. An administrator may change the effective signup
policy through `settings.update`; both signup enforcement and `appConfig` read it
without caching. Transfer limits remain deployment configuration: admin settings
expose their effective numeric values alongside command and output-retention
limits, never environment secrets or paths.

## Sandbox create settings

`SANDBOX_CREATE_CONNECT_BUDGET_POINTS` defaults to 300 (1..10000),
`SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS` to 60 (60..3600 seconds), and
`SANDBOX_MAX_TIMEOUT_MS` to 86400000 (300000..2073600000 ms, or the literal
`unlimited`). These declarations are enforced: create/connect share one owner
procedure budget, including retries. `SANDBOX_MAX_TIMEOUT_MS` is the deployment
layer of the lease policy: host ceilings, pool and membership maximums can only
lower it, and `unlimited` lets layers that also allow it accept `timeoutMs: 0`
(no lease timer). Admin settings show it. Accepted leases keep their deadline
when it changes; a lowered value pulls running sandboxes in.

Pool creates may wait for capacity (`waitForCapacityMs`). The deployment layer
of that queue is `SANDBOX_CAPACITY_WAIT_MAX_MS` (default 3600000; 0..2073600000
ms, 0 disables waits), `SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY` (default 16) and
`SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER` (default 64; both 0..100000). Each also
accepts the literal `unlimited`. A pool's own limits can only lower them; a
request over the effective wait is refused, never clamped. A fixed ceiling of
4096 waiting creates per pool keeps queue scans bounded.
`CAPACITY_RETRY_AFTER_SECONDS` (default 30; 1..86400; not in `.env.example`) is
the `Retry-After` header and `retryAfterSeconds` on `/v1` capacity, quota and
pool 409s that carry `retryable: true`. A `retryable: false` refusal never
carries it. Registration, tags and lease mutations
also have finite fail-closed procedure budgets. Fresh launches require current
admission, inventory, key ACK and exact availability evidence.

`SANDBOX_REQUEST_HMAC_SECRET` is a required server-only master secret for the
keyed request digests and derived host journal keys. `pnpm run setup` generates
a local value without printing it; production supplies one externally. Use the `secret32`
generator via `pnpm generate:secrets`: 32 cryptographically random bytes encoded
as lowercase hex. There is no default. Examples leave the value empty:

```dotenv
SANDBOX_REQUEST_HMAC_SECRET=
```

Validation requires at least 64 even lowercase hex characters (32 decoded
bytes), and reuses the auth secret's placeholder/weakness checker in every
environment. That checker rejects identical characters, period-1/2 repeats,
placeholder substrings and fewer than 10 distinct characters. This is a
format/placeholder floor, not an entropy measurement or a general repeated-block
detector. The existing auth-secret policy is unchanged.

In development `vite dev` runs the TanStack Start server functions in the web
process, which validates the full server env, so Turbo passes the value to
`server#dev` and `web#dev` (never the worker). It is still required: there is
no development default.

Keep the master stable and shared across all server replicas, backed up in the
operator secret store. It must never reach a host, guest, child environment or
log. Hosts receive only memory-only derived keys; digest records store
non-secret key IDs. Replacement refuses old key-bound retries/configs. Restore the original secret for recovery. Intentional
rotation requires quiescing work and retiring retained configs under the old
key before changing all replicas together; no online keyring or rehash exists.

## Workload envs and pool continuity

The dashboard's template/create `envs` editor is workload configuration, not
server `.env` loading and not a way to inject control-plane credentials. Values
must be bounded string maps: up to 64 POSIX names, 128 UTF-8 bytes per name,
4096 per value and 16384 bytes of sorted escaped JSON. HOME/SHELL/TERM are
reserved for stored template/sandbox defaults. Template defaults merge with
create overrides once; per-command overrides apply last, with limits checked
on each source and the resulting union.

Accepted snapshots survive stop/reconnect and host restart. Appending a
revision or moving a tag never changes an existing sandbox. They are private
plaintext inside the DB/host operator and backup boundary, absent from public
and admin projections, and have no dashboard readback. The editor and mutation
state are cleared after safe settlement; uncertain create retains only its
in-memory exact retry until resolved or closed. Browser storage is not used.
See [SDK resource grants and private defaults](../guide/auth-planes.md#minting-sdk-resource-grants).
Pools add no deployment environment variable. Capacity remains the effective
host limit; overlapping pools share the same reservations.

## Local host capacity configuration

No new capacity environment variables are introduced. Use local TOML
`sandbox_memory_mib`, `sandbox_vcpu_budget`, `max_sandbox_cpu_count` and
`[[storage_pools]]` (`name`, `capacity_gib`, `draining`); flags override the
three CPU/RAM dimensions independently. Storage lists are TOML-only and replace
the implicit profile-root pool. A bare `wssp host run` detects defaults. Restart/reconnect
to apply changes; shared host policy and the daemon journal retain pinned charges and
implicit ceilings. See [host capacity](../guide/hosts.md#capacity-drain-and-deletion).

## Data encryption key

Shared (server **and** worker; identical values on both). One deployment-wide
root key for data at rest. It never encrypts anything directly: each purpose
derives its own 32-byte sub-key with HKDF-SHA256 (salt `wssp-data-key-v1`,
info = a versioned purpose label such as `webhook-endpoint-secret:v1`;
`packages/api/src/crypto/data-key.ts`). It is never derived from
`BETTER_AUTH_SECRET`. Custody and rotation:
[production hardening](./production-hardening.md#data-encryption-key).

| Variable                       | Default | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------ | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATA_ENCRYPTION_KEY`          | unset   | Exactly 64 lowercase hex characters (32 bytes, `openssl rand -hex 32`). Root of every data-at-rest sub-key: webhook endpoint signing secrets, the CLI-login vault and offloaded sandbox disk keys. `pnpm generate:secrets` always generates it and the Dokploy checklist lists it as set-once. Unset = webhooks, CLI logins and disk offload off, and offloaded sandboxes unrestorable (never a boot failure). Weak or placeholder values fail validation. |
| `DATA_ENCRYPTION_KEY_PREVIOUS` | unset   | The second root during a rotation: first the incoming key (before `pnpm data-key:promote`), then the outgoing one. Both decrypt. The `data_key_epoch` row, not this pair, decides which one new writes use. The worker rewraps rows onto the epoch's kid. Remove it once `pnpm data-key:status` reports `safeToRemove`.                                                                                                                                    |
| `CREDENTIALS_ENABLED`          | `true`  | Turn-off switch for CLI logins; effective only with `DATA_ENCRYPTION_KEY`. `false` with the key set = drain (new use refused; existing values settle). See [credential vault](../design/credential-vault.md#feature-gate).                                                                                                                                                                                                                                 |

`CREDENTIAL_MAX_INSTANCES_PER_OWNER` (server only, default `1000`): CLI-login
instances (independent token sets) one account may have, a whole number from
1 to 100000 or `unlimited`. Checked under the owner lock at every instance
create, including the ones a login sandbox adds; refusals are 409
`credential.limit_reached` with `resource: "instances"`. The other login
limits are fixed ([CLI logins § Limits](../guide/cli-logins.md#limits)).
Operator setup, drain mode and host hygiene:
[production hardening § CLI logins](./production-hardening.md#cli-logins).

`DATA_ENCRYPTION_KEY` also wraps the per-upload keys of offloaded sandbox
disks (purpose `sandbox-disk-dek-wrap:v1`). The disk-offload variables
(`SANDBOX_OFFLOAD`, `SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT`,
`SANDBOX_OFFLOAD_GIB_PER_DAY`, `SANDBOX_OFFLOAD_SHRED_GRACE_HOURS`) are
described with the image store in
[templates § disk offload](./templates.md#disk-offload). The consumed-copy
grace is the admin setting `sandbox.offload.consumedGraceSeconds`, not an
env var.

## Webhooks

Shared (server **and** worker; identical values on both). All optional: without
`DATA_ENCRYPTION_KEY` webhooks are off.

| Variable                          | Default  | Meaning                                                                                                                                                                                                                                                            |
| --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `WEBHOOK_ALLOWED_PRIVATE_CIDRS`   | empty    | CSV of private CIDRs deliveries may reach. A range overlapping a hard-denied range (link-local, multicast, mapped, metadata, loopback in production) fails boot; a broad range that only covers a single hard-denied host is accepted and that host stays refused. |
| `WEBHOOK_ALLOWED_PRIVATE_HOSTS`   | empty    | CSV of exact hostnames allowed to resolve to private addresses, used only when no CIDRs are set.                                                                                                                                                                   |
| `WEBHOOK_TRANSLATION_PREFIXES`    | empty    | CSV of network-specific IPv6 translation (NAT64/DNS64) prefixes, RFC 6052 lengths /32, /40, /48, /56, /64 or /96. Hard-denied for delivery; an allowlist CIDR overlapping one fails boot.                                                                          |
| `WEBHOOK_PRIVATE_ALLOWLIST_SCOPE` | `admins` | `admins` or `all`: who may use the allowlist (checked at create and on every attempt).                                                                                                                                                                             |
| `WEBHOOK_ALLOW_PLAINTEXT_PRIVATE` | `false`  | Permit `http://` to allowlisted private destinations only.                                                                                                                                                                                                         |
| `WEBHOOK_DELIVERY_CONCURRENCY`    | `8`      | Concurrent delivery attempts per worker process (1-64).                                                                                                                                                                                                            |

The values are read through the same declarations `@wssp/env/shared`
validates at boot (`packages/env/src/vars/shared.ts`); the allowlist is parsed
when the server and the worker start, so a bad CIDR stops boot. See
[webhooks](../guide/webhooks.md#operator-setup) and
[production hardening](./production-hardening.md#webhook-egress).

## Migration and backup runtime

`MIGRATE_ON_START` is script-only: server default true, worker default false.
False waits for compatible history before exec; it still registers the admitted
instance. The entrypoint generates a fresh optional UUID `WSSP_INSTANCE_ID` per
start; never configure a stable value manually.

`BACKUP_SCHEDULE=off|daily` defaults off; `BACKUP_HOUR_UTC=3` and
`BACKUP_KEEP=14` control the daily writer. `BACKUP_ENABLED=false` is the default:
automatic migration/pre-drop snapshots, the daily writer and freshness monitoring
are off, with one server startup notice and no health/readiness penalty. Explicit
backup and restore-snapshot commands remain available. Enable automatic backups
with `BACKUP_ENABLED=true`; daily writing also needs `BACKUP_SCHEDULE=daily`. S3 requires an explicit nonempty per-deployment
`BACKUP_S3_PREFIX`; writer and ListBucket-only monitor credentials are separate.
`BACKUP_HEARTBEAT_URL` is pinged only after successful off-site upload. A real
mounted `/backups` volume or S3 enables pre-migration backups only when
`BACKUP_ENABLED=true`; an enabled, configured backup failure
blocks migration. See [backup and restore](./backup-and-restore.md).

Local Postgres/Valkey host ports may be selected with `DEV_POSTGRES_PORT` and
`DEV_REDIS_PORT`; use matching local `DATABASE_URL` and `REDIS_URL`. Production
Compose publishes no host ports.

## MCP endpoint

| Variable      | Default | Meaning                                                                                                                                                                                                                                            |
| ------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MCP_ENABLED` | `true`  | Server only. Turns the built-in MCP endpoint and its OAuth provider on or off. Literal `true` or `false`; empty means the default. `false`: the MCP and MCP OAuth routes return real 404s (discovery included). Read at startup: restart to apply. |

The generated Dokploy Compose forwards it to the server as an optional key
(`${MCP_ENABLED:-}`, so an empty value keeps the default): set `MCP_ENABLED=false`
in Dokploy's environment to turn MCP off from the UI ([deployment](./deployment.md#blessed-compose-path), [MCP](../mcp.md)).

## Agent token expiry

| Variable                             | Default | Meaning                                                                                                                                         |
| ------------------------------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY`   | `true`  | Allow no-expiry agent tokens. Off: new tokens need an expiry and existing no-expiry tokens are blocked (below). Literal `true` or `false` only. |
| `WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS` | `90`    | Maximum lifetime of newly minted dated agent tokens in days, an integer from 1 to 3650.                                                         |

The browser reads both settings through the authenticated agent-token policy
procedure. The server checks the policy again at mint time. The lifetime cap
applies to new tokens only. Turning `WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY` off also
refuses every existing no-expiry agent token at authentication (MCP returns 401
with `agent_token.no_expiry_blocked`) and at each later credential check, so
queued work it authorized loses authority too; the tokens are kept, shown as
blocked by policy, and work again once the flag is back on. Like every variable
here it is read at startup: restart to apply a change (instances may disagree
briefly during a rolling deploy). Dated agent tokens, OAuth
grants and SDK keys are unaffected. Tokens without an expiry, blocked or not,
still count toward the ten-active-token cap until revoked.
