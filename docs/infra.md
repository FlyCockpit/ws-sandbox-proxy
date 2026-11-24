# Infrastructure

The production images run Node 26.13.1 with pnpm 12.18.0, PostgreSQL 18 and
Valkey 9. Deployment steps: [deployment](operations/deployment.md).

## Images

| Image  | Dockerfile          | Role                                                   |
| ------ | ------------------- | ------------------------------------------------------ |
| App    | `Dockerfile`        | Hono API, web, relay and embedded jobs by default      |
| Worker | `Dockerfile.worker` | Dedicated BullMQ consumers when `WORKER_MODE=external` |

Both images include Prisma CLI, committed migrations, the migration runner,
Postgres client and canonical backup/restore tools. Image commands are `migrate`,
`backup`, `backup-schedule`, `restore`, `restore-drill` and `hold-deletions`.
Use the same immutable Git revision across roles; no separate migration image.

## Required environment

| Variable                                                                                          | Scope           | Notes                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                                                                    | server + worker | Postgres                                                                                                                                                                                                                                                                                                                         |
| `REDIS_URL`                                                                                       | server + worker | BullMQ and rate limiting; `noeviction` when Valkey has maxmemory                                                                                                                                                                                                                                                                 |
| `BETTER_AUTH_SECRET`                                                                              | server          | 32+ random characters, unique per environment                                                                                                                                                                                                                                                                                    |
| `BETTER_AUTH_URL`                                                                                 | server          | Public HTTPS origin, no path                                                                                                                                                                                                                                                                                                     |
| `ADMIN_EMAILS`                                                                                    | server          | Emails that receive admin on bootstrap signup                                                                                                                                                                                                                                                                                    |
| `SETUP_KEY`                                                                                       | server          | Optional one-shot key for a first admin without email ([deployment](operations/deployment.md#first-admin-without-email)); remove after setup                                                                                                                                                                                     |
| `SMTP_*`                                                                                          | server (prod)   | Required for email verification in production                                                                                                                                                                                                                                                                                    |
| `WORKER_MODE`                                                                                     | server          | `embedded` (default) or `external`                                                                                                                                                                                                                                                                                               |
| `CORS_ORIGIN`                                                                                     | server          | Only if the web app is on a different origin                                                                                                                                                                                                                                                                                     |
| `TRANSFER_*`                                                                                      | server          | Transfer spool location and limits ([environment variables](operations/environment-variables.md#transfer-storage))                                                                                                                                                                                                               |
| `BACKUP_S3_*`                                                                                     | backup writer   | Optional off-site Postgres dumps; S3 is used only for backups ([backup and restore](operations/backup-and-restore.md))                                                                                                                                                                                                           |
| `DATA_ENCRYPTION_KEY`                                                                             | server + worker | 64 hex (`openssl rand -hex 32`); generated by `pnpm generate:secrets`, set once. Root key for data at rest; enables webhooks and CLI logins (unset = both off, boot still succeeds); the **same value** on both. Store apart from DB backups. See [production hardening](operations/production-hardening.md#data-encryption-key) |
| `CREDENTIALS_ENABLED`                                                                             | server + worker | Optional; default `true`. `false` turns CLI logins off ([credential vault](design/credential-vault.md#feature-gate))                                                                                                                                                                                                             |
| `WEBHOOK_ALLOWED_PRIVATE_*`, `WEBHOOK_PRIVATE_ALLOWLIST_SCOPE`, `WEBHOOK_ALLOW_PLAINTEXT_PRIVATE` | server + worker | Optional webhook destination allowlist; identical on both                                                                                                                                                                                                                                                                        |

No `.env` file is baked into the image. Inject values from the orchestrator.
Do not log env var values.

The worker validates only `@wssp/env/shared` (DB, Valkey, optional S3/SMTP/
translation/webhooks). It does not need `BETTER_AUTH_SECRET`. When webhooks are
enabled the worker also needs `DATA_ENCRYPTION_KEY` (it decrypts endpoint
secrets to sign deliveries) and outbound internet access to owners' endpoints.

Background maintenance runs as BullMQ jobs in the worker runtime (embedded in
the server unless `WORKER_MODE=external`): a daily sweep of expired auth tokens,
an opt-in backup-freshness check every six hours (`BACKUP_ENABLED=true`), webhook
delivery (a dispatcher polls Postgres every 2 seconds) and a daily webhook log
prune. The
sandbox relay, operation dispatch and the transfer spool run in the server
process itself, so exactly one server replica is supported; Valkey is required
in every topology (jobs and fail-closed rate limits).

## Migration startup contract

`MIGRATE_ON_START=true` (server default) runs the canonical apply runner before
HTTP or embedded jobs start. `false` (worker default) waits up to 300 seconds
for compatible migration history and registers the process without application
DDL. Every long-running process gets one fresh `WSSP_INSTANCE_ID`; the embedded
worker shares the server row. One-shot commands register no instance.

The runner refuses populated databases without history, changed checksums,
failed migrations and incompatible database-ahead releases. It never adopts a
schema automatically. Reviewed committed `migration.sql` runs transactionally;
removals live in `contract.sql` and wait at least seven days plus older-instance
and restore holds. See [schema migrations](schema-migrations.md) for generation,
CI gates, recovery and deletion notices. CHECKs/functions/triggers are frozen in
committed migration SQL; schema comments document constraints, not a startup
repair mechanism.

Backups default off (`BACKUP_ENABLED=false`), with one server startup notice and
no readiness penalty. With `BACKUP_ENABLED=true` every migrating start checks for
a usable destination (a mounted `/backups` volume or S3) and each run with
pending migrations is preceded by a backup, a brand-new database included; no
usable destination or a failed backup blocks application. Freshness requires
proven catalog emptiness. A due deletion
also takes a pre-drop backup if needed; failure defers deletion. See
[backup and restore](operations/backup-and-restore.md).

## Advisory lock

The runner owns session advisory lock 72707370 through classification, backup,
application and final checks; Prisma uses 72707369. Concurrent leaders serialize
and recheck history. Restore owns both locks through snapshot and its atomic
replacement transaction. Losing runner lock ownership fails admission. Waiting
followers do no application DDL; bounded instance registry writes are expected.

## Health

`/health` proves the HTTP process is alive. `/ready` checks Postgres, Valkey and
the configured worker runtime; it returns the full immutable `commit` or null on
every branch. A draining process returns 503. Accept only the expected full SHA
and current task generation using `pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha>`.
Allow 510 seconds for startup and 30 seconds for shutdown. Recovery and migration
admission finish before listening; HTTP, relay, transfers and jobs drain before
instance heartbeats stop and Prisma disconnects. A drain cancels a running image
or disk offload verify (it writes nothing until its read completes) and puts the
job back in the queue without spending an attempt, so the next worker runs it at
once instead of after stalled-job detection.

## Response compression is the platform's job

Enable compression at the TLS proxy. Dokploy output wires Traefik compression;
check a real page, since small health responses may not be compressed.

## Deploy workflow

Generate the Compose topology, inject platform secrets and deploy the immutable
release. The server migrates on startup; workers wait. Alternatively run the app
image's `migrate` command once and configure both runtime roles as followers.
Never bypass admission to make an old release start.

## Advanced topologies

`pnpm dokploy:config` supports `app` (embedded jobs, default) and `app-worker`
(external jobs). Both require PostgreSQL and Valkey. Regenerating with `--backups true` adds an optional `backup` profile
runs exactly one daily writer per database. Use `--project` with a distinct
1–32 character lowercase/digit/hyphen stem, a configurable `--url` and
`--proxy-network`. Generated resources and explicit backup prefixes include
project/environment/origin identity, with no fixed host ports or container names.
This allows wssp, knowledge-base and cockpit-context on one Dokploy server.
Local service ports can be overridden with `DEV_POSTGRES_PORT` and
`DEV_REDIS_PORT`; keep local connection URLs aligned.

## Hard rules

Keep schema changes in reviewed committed migrations; agents use guarded local
wrappers. Production secrets and databases never belong in development. Keep
Valkey `noeviction`, one server replica and matching server/worker/daemon/SDK
artifacts. Restore runs as an owner-controlled one-shot job inside the target
network after writers drain.

## Persistent transfer spool

The server needs the `server-data` volume mounted at `/app/.data`. It holds two
sibling roots on one filesystem: the transfer spool (`/app/.data/transfers`) and
the template-build context store (`/app/.data/transfers.build-context`), so an
adopted build context is linked rather than copied.
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

## Schema and resource continuity

Use server migration admission and follower workers, or a one-shot `migrate`
job before follower runtimes.
Preserve `SANDBOX_REQUEST_HMAC_SECRET` and host journals across upgrades;
changing the secret refuses retained private-config/replay bindings.
New template, tag and pool grants never rewrite an existing sandbox's pinned
disk or private defaults. Mint explicit host, exact revision and pool grants
for SDK access; see the [authentication guide](guide/auth-planes.md#minting-sdk-resource-grants).

## Sandbox host capacity responsibility

Daemon detection uses Incus daemon totals, independent of web/worker container
limits. RAM budgets pay guest RAM plus fixed overhead; aggregate vCPU defaults
to threads × 2 and per-VM CPU to min(32,threads). CPU/RAM flags independently
override local TOML/detection. Storage lists are TOML-only; no new environment
variables or mandatory service flags. Caps commit retained root size + 1 GiB,
not physical usage or cross-daemon arbitration. Preserve native-cache/marker and
other-workload headroom. Shrink preserves holds; unavailable pools never prove
absence. See the [host guide](./guide/hosts.md#capacity-drain-and-deletion).

Use matching server, worker, CLI and SDK builds. Run the capacity and storage
checks in the [hosts guide](./guide/hosts.md#capacity-and-storage-qualification)
before production; automated fixtures do not establish hardware headroom.

## Integrated sharing/terminal release

Use one relay-affine web process with same-commit server/daemon peers. Local host policy is live-link state, not a persisted server flag.
Only the process running the outbox processor runs access sweeps; dispatch wakes
do not reset its independent 15-second timer. CAS tolerates multiple processes,
but external-worker topology should not double sweep cost. Keep reviewed migrations and and positive disk/network cleanup proofs before finalization. See the
[explicit operator checklist](operations/sharing-terminal-qualification.md).
