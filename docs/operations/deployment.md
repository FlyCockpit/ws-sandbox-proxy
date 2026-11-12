# Deployment

Dokploy on a VPS is the documented target. The image, env, and migration startup
contract live in [docs/infra.md](../infra.md). This page is the operator
walkthrough.

## Blessed Compose path

```sh
pnpm dokploy:config --environment production --git-ref <immutable-tag> --url https://sandbox.example.com --project wssp --proxy-network dokploy-network
```

Import the generated Compose file into Dokploy. `app` (default) runs one server
with embedded jobs plus Postgres 18 and Valkey 9 (`noeviction`). `--topology
app-worker` adds a dedicated worker and sets `WORKER_MODE=external`. Enable the
optional `backup` profile separately. No role uses a dedicated migration image.
Fill listed variables with complete literal values; inject secrets on the platform.

Choose a unique `--project` stem (1–32 lowercase letters/digits/hyphens),
`--url` domain and `--proxy-network` for each deployment. Generated volumes,
internal networks, Traefik IDs and explicit backup prefixes derive from project,
environment and origin; no fixed production host ports or container names are
used. wssp can share one Dokploy server with knowledge-base and cockpit-context.
Never reuse a co-tenant's database, bucket prefix or persistent volume.
The generated Compose file interpolates `POSTGRES_PASSWORD` and
`REDIS_PASSWORD` into `DATABASE_URL`/`REDIS_URL`, so use URL-safe values (the
hex secrets `pnpm generate:secrets` produces are); a `#`, `/`, `@` or `%` would
corrupt the URL.

Development follows `main`; production uses one immutable tag across app and
worker. Acceptance requires the expected full build SHA and current task
generation: `pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha>`.

## Managed Postgres and Valkey

Prefer Dokploy's managed Postgres/Valkey when you want platform snapshots.
Delete the `postgres` and `redis` services (and their volumes) from the
generated Compose file, then set `DATABASE_URL` / `REDIS_URL` on server, worker and backup operations using the internal hostnames Dokploy shows you.

Keep Valkey `maxmemory-policy noeviction`. BullMQ can lose or corrupt jobs
under eviction. Do not share a production database with development.

## Enable response compression (don't skip)

The Node server does not compress responses. On Dokploy, Traefik's compress
middleware is off by default, so every SSR page and JSON response ships
uncompressed until you attach it to the server router:

- `traefik.http.middlewares.<name>.compress=true`
- `traefik.http.routers.<name>.middlewares=<name>`

The generated Compose file pre-wires those labels. Confirm a full page
response has `content-encoding: br` (or gzip). Proxies skip compressing
bodies under ~1 KB, so check a real page, not `/health`.

## Schema deploy lifecycle

The app defaults to `MIGRATE_ON_START=true`: its entrypoint runs committed
migrations before HTTP or embedded jobs. The worker defaults to false, waits
for compatible history, and performs no application-schema DDL. Concurrent
leaders serialize on the runner's advisory lock. To use a separate rollout job,
run the **same app image** with command `migrate` and wait for that job's exit 0,
then deploy follower runtimes with `MIGRATE_ON_START=false`.

The runner checks checksums, failed history and rollback compatibility; it
refuses a populated database with no migration history. There is no automatic
baseline or destructive override. Removals wait in reviewed `contract.sql`
after a seven-day soak and instance/restore holds. The local change flow is
`pnpm db:migrate <name>`, review SQL, `pnpm db:migrate:apply`, commit history.
See [schema migrations](../schema-migrations.md) and
[the startup contract](../infra.md#migration-startup-contract).

Mounted `/backups` or S3 enables the pre-migration safety backup. Missing
destinations warn; configured failures block migrations. Allow 510 seconds for
startup, including runner admission, and 30 seconds for graceful shutdown.

## Enable Postgres backups

Enable the Compose `backup` profile **and** set `BACKUP_SCHEDULE=daily` to run
the optional daily backup service; it defaults off. Keep exactly one daily
schedule per database. Mount the shared `/backups` volume and configure an
explicit per-app/environment/origin `BACKUP_S3_PREFIX` for off-site copies.

Writer credentials belong to startup/backup operations; long-running app
processes unset them after admission. Freshness monitors use separate
ListBucket-only keys in the chosen worker runtime. `BACKUP_ENABLED` controls
monitoring, never writing. Provider backups/PITR can be used with a recorded
retention and alert policy. Run a restore drill before storing real data:
[backup and restore](./backup-and-restore.md).

## First deploy

1. Generate secrets (`pnpm generate:secrets`) and inject them on the
   platform. Walk [production-hardening.md](./production-hardening.md).
2. Import the Compose file (or create native-Git Applications for an advanced
   topology). Production: disable auto-deploy and pin one immutable tag.
3. Deploy the app with migration admission; a populated database needs trustworthy
   committed history. A first install starts with an empty database.
4. Deploy the matching worker in `app-worker`; its follower wait must succeed.
5. Run `pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha>`. Sign up with an `ADMIN_EMAILS` address and
   verify email.
6. Enable backups and run a restore drill before relying on the environment.

`pnpm dokploy:config` topologies: `app` (default) and `app-worker`. Omitting the worker container never removes jobs — it
only moves them (`WORKER_MODE`).

## Branding: logo, icons and name

The logo appears only as the favicon, the PWA install and home-screen icons and
the push-notification icon. The dashboard header has no image logo. All icons
except the Apple touch icon are generated from `apps/web/assets/logo.png`
([pwa-assets.config.ts](../../apps/web/pwa-assets.config.ts)).

1. Replace `apps/web/assets/logo.png` with a square transparent PNG, at least
   512×512. If the artwork reaches further out, raise `maskable.padding` in
   `pwa-assets.config.ts` until it fits the centre 80% safe-zone circle.
2. Run `pnpm --filter web generate-pwa-assets`. The generator writes beside
   the source; move `favicon.ico`, `pwa-64x64.png`, `pwa-192x192.png`,
   `pwa-512x512.png` and `maskable-icon-512x512.png` into `apps/web/public/`,
   keeping those names, and leave only `logo.png` in `apps/web/assets/`.
   `apple-touch-icon-180x180.png` is not generated;
   keep the existing public file until Apple-style tiles are supplied.
3. If the background no longer matches the icon, update the install colours
   `theme_color` and `background_color` in `apps/web/vite.config.ts`. Keep them
   in step with `theme-init.ts` and `use-theme-color-meta.ts`.

The display name comes from `VITE_APP_NAME`. It is the PWA manifest name, page
titles and email copy. Vite reads it at build time, so on Dokploy set it as a
build argument of the web image, not only as a runtime variable, then rebuild.
Colours and fonts use `pnpm theme:apply`.

## Upgrading node daemons

Deploy matching server, worker, CLI and SDK builds. Apply the schema through
one reviewed leader, then upgrade node daemons. Strict relay and SDK contracts
require coordinated releases. Preserve journals and resolve uncertain work
through the supported lifecycle and recovery flows.

Use the [hosts guide](../guide/hosts.md#upgrades) for quiescing a running daemon
and the [sharing and terminal checklist](sharing-terminal-qualification.md)
for operator qualification. Keep `LimitCORE=0` in the systemd unit for hosts
running CLI logins, and use encrypted storage with encrypted or no swap.

## Rollback

1. Redeploy the previous image (fastest, schema-compatible releases only).
2. Bad schema change — roll forward with a reviewed counter-change through
   committed migration runner. Never rewrite applied history.
3. Restore from a backup — [backup-and-restore.md](./backup-and-restore.md)
   § Replacement database recovery handoff.
4. Keep the original database intact through the agreed retention window.

Give shutdown at least 30s of grace (`stop_grace_period: 30s`) so the server
can drain.

## Persistent transfer spool

The server needs the `server-data` volume mounted at `/app/.data`. It holds two
sibling roots on one filesystem: the transfer spool (`/app/.data/transfers`) and
the template-build context store (`/app/.data/transfers.build-context`), so an
adopted build context is linked rather than copied.
For advanced native-Git Applications, create the named volume and mount from
the generated server `persistentStorage` checklist entry.
The Docker image prepares these directories for UID 1000 with mode 0700; a
custom bind mount must provide the same ownership and permissions. Keep this
volume when replacing a container, and provision at least `TRANSFER_DISK_BYTES`
plus `TEMPLATE_BUILD_CONTEXT_STAGED_BYTES` plus filesystem overhead. A
root-owned, read-only or symlink transfer spool fails startup. An unusable
build-context root does not: the server starts with template builds
unavailable (`reason: "storage_unavailable"`) and logs the step and errno.
`TRANSFER_SPOOL_DIR` defaults to `.data/transfers` relative to the server working
directory; the context root is always its sibling `<spool>.build-context`, so
changing it requires moving the volume mount too.

Only one server process may own the spool. Generated Dokploy updates and
rollbacks use `stop-first`, preventing old/new replicas from overlapping on it.
Recovery completes before listening. PostgreSQL stores transfer metadata but no
file payload; restoring PostgreSQL without its matching spool fails affected
sessions safely. Workers and one-shot migration jobs do not mount transfer content.

### Reverse proxy client IP

The generated config and Compose set `TRUST_PROXY_HOPS=1` on the server
(client → Traefik → server). Add one per extra proxy that the next one trusts
(for example Cloudflare in front of Traefik). A deployment with no proxy keeps
it unset (`0`): the socket peer is the key. A proxied deployment left at `0`
puts every client in one shared rate-limit bucket. See
[client IP and reverse proxies](./environment-variables.md#client-ip-and-reverse-proxies).

### Reverse proxy browser terminals

Browser terminals upgrade to WebSocket at
`/api/dashboard/sandboxes/{id}/terminal/ws`. The proxy must forward the
`Upgrade`, `Connection`, `Origin`, `Cookie` and `Sec-WebSocket-Protocol` request
headers unchanged. The one-use ticket rides `Sec-WebSocket-Protocol`, so do not
log that header. Allow long-lived connections: the server re-reads the session
every 15 seconds and pings each browser every 20 seconds, and it detaches a
browser that has sent nothing (no frame, no pong) for 60 seconds, so a proxy
idle timeout must exceed 60 seconds. The browser
`Origin` must exactly match `BETTER_AUTH_URL` or `CORS_ORIGIN` after TLS
termination. See [browser terminal authentication](../design/browser-terminal-auth.md).

### Host relay

Node daemons connect to `wss://<api-origin>/ws/sandbox-host`. The host relay,
browser terminal and transfer spool are always enabled. The proxy must pass the
WebSocket upgrade with its `Authorization` and `Sec-WebSocket-Protocol`
headers, must not redirect it (daemons never follow redirects with
credentials), and must allow long-lived connections; daemons heartbeat while
connected. Run exactly one server replica: host relay sessions and terminals
live in that process, credential revocation closes live sockets through
in-process notifications, and one process owns the transfer spool. (Rate
limits are in Valkey.) Daemons need no inbound ports. Host-side steps:
[hosts guide](../guide/hosts.md).

Every sandbox host needs, before it can create a single sandbox (details and
Ubuntu 24.04 steps in [host requirements](../guide/hosts.md#requirements)):

- Linux with KVM.
- Incus 6.14 or newer. Earlier releases cannot reliably enforce the
  per-sandbox network ACLs (CVE-2025-52890), so the daemon never advertises
  egress enforcement on them and every create is refused with
  `UNSUPPORTED_CAPABILITY`. Ubuntu 24.04 ships Incus 6.0.0; install the
  Zabbly stable packages instead.
- The `br_netfilter` kernel module, loaded (`sudo modprobe br_netfilter`) and
  persisted (`echo br_netfilter | sudo tee /etc/modules-load.d/wssp-br_netfilter.conf`).
  `wssp connect --runtime incus` refuses to start without it, or while
  `net.bridge.bridge-nf-call-ip6tables` is not `1`
  (`sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1`).

### Reverse proxy transfer bodies

Preserve PUT, DELETE, `Content-Range`, `Content-Type`, `Idempotency-Key` and
`Authorization` for `/v1/transfers`; browser uploads use
`/api/dashboard/transfers` and their cookie/Origin headers. Permit at least
1 MiB per request at the proxy (there is no 1 GiB HTTP request). Disable request
body buffering for these paths where supported. The application counts actual
bytes and enforces the 1 MiB chunk limit even without Content-Length. Do not
compress upload requests. Set proxy body/read timeouts to accommodate each chunk;
the application's body-read deadline is 60 seconds. The public origin in
`BETTER_AUTH_URL` must match browser Origin after TLS termination.

Downloads (`GET`/`HEAD /v1/operations/{id}/content` and
`/api/dashboard/operations/{id}/content`) stream up to 1 GiB. Preserve `Range`,
`If-Range`, `Authorization` and the response's `Content-Range`, `ETag`,
`Repr-Digest` and `Content-Length`; disable response buffering and compression for
these paths, and allow long response times. The application ends a stream after
60 seconds without the client reading.

## Schema and resource continuity

Use server migration admission and follower workers, or a one-shot `migrate`
job before follower runtimes.
Preserve `SANDBOX_REQUEST_HMAC_SECRET` and host journals across upgrades;
changing the secret refuses retained private-config/replay bindings.
New template, tag and pool grants never rewrite an existing sandbox's pinned
disk or private defaults. Mint explicit host, exact revision and pool grants
for SDK access; see the [authentication guide](../guide/auth-planes.md#minting-sdk-resource-grants).

## Sandbox host capacity responsibility

Daemon detection uses Incus daemon totals, independent of web/worker container
limits. RAM budgets pay guest RAM plus fixed overhead; aggregate vCPU defaults
to threads × 2 and per-VM CPU to min(32,threads). CPU/RAM flags independently
override local TOML/detection. Storage lists are TOML-only; no new environment
variables or mandatory service flags. Caps commit retained root size + 1 GiB,
not physical usage or cross-daemon arbitration. Preserve native-cache/marker and
other-workload headroom. Shrink preserves holds; unavailable pools never prove
absence. See the [host guide](../guide/hosts.md#capacity-drain-and-deletion).

Use matching server, worker, CLI and SDK builds. Run the capacity and storage
checks in the [hosts guide](../guide/hosts.md#capacity-and-storage-qualification)
before production; automated fixtures do not establish hardware headroom.

## Sharing and terminal qualification

Deploy server/worker/daemon/SDK from the same integrated commit; version-string
agreement alone is insufficient. Preserve unresolved journal evidence and
expire outstanding terminal tickets during planned maintenance.
Safe additive schema application remains required. Do not mix peer artifacts.
UI and PG success does not authorize live mutation or establish network isolation.
Use the separate explicitly invoked
[operator checklist](./sharing-terminal-qualification.md); keep the capacity
calibration/Docker qualification obligations. The host and sandbox browser
WebSocket paths both need the existing exact-Origin/cookie upgrade path.

## One-shot operations

Run these owner-controlled jobs on the database's private Docker network with
platform-injected environment and the deployment's mounted `/backups` volume:

```sh
docker run --rm --network <db-network> --env-file <protected-operation-env> -v <backups-volume>:/backups <immutable-app-image> migrate
docker run --rm --network <db-network> --env-file <protected-operation-env> -v <backups-volume>:/backups <immutable-app-image> backup
docker run --rm --network <db-network> --env-file <protected-operation-env> -v <backups-volume>:/backups <immutable-app-image> restore /backups/<file>
```

Restore without `--confirm` only verifies/previews. Drain every writer, then run
with exact `--confirm RESTORE:<database>` and `--replace` for a nonempty target.
Replacement requires a snapshot; `--skip-snapshot` is an explicit owner escape
only with verified provider recovery. See the full
[restore runbook](./backup-and-restore.md#restore). Never print the env file or
pass credentials in command text. A restore drill uses a separate empty
`restore_drill` database and the image command `restore-drill <source>`.
