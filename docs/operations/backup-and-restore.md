# Backup and Restore

> Daily backups, the backup taken right before migrations, restoring, and the restore drill. Mechanics of migrations: [schema-migrations.md](../schema-migrations.md).

**Backups are opt-in and default off.** A new deployment needs no backup settings, volume or sidecar. Migrations proceed without a backup, readiness stays healthy, and the server logs one notice explaining how to enable backups. To opt in, enable exactly one daily logical-backup schedule, or choose provider backups/PITR with retention and alerts. With `BACKUP_ENABLED=true`, the app also snapshots before applying migrations (a brand-new database too) and refuses to migrate without a usable destination. Restore and restore drills run inside the target network; agents prepare commands and the owner runs them.

## Daily backups

### Dokploy with the generated compose (the default) — recommended

The generated compose (`pnpm dokploy:config`, [deployment.md](./deployment.md#blessed-compose-path)) omits backup storage and services by default. To turn them on:

1. Regenerate the same deployment with `--backups true`, which adds a shared `/backups` volume and the optional service. In Dokploy, enable the Compose **`backup` profile** and deploy. This generated opt-in defaults `BACKUP_ENABLED=true` and `BACKUP_SCHEDULE=daily`; any explicit environment overrides must also enable both. With plain Compose, use `docker compose --profile backup up -d backup` with the same schedule setting. Keep exactly one active daily scheduler for each database; do not combine this service with a second host cron or provider-managed logical schedule for the same purpose.
2. Optional but strongly recommended: also set `BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY` (and `BACKUP_S3_REGION` / `BACKUP_S3_ENDPOINT` for S3-compatible storage) so every backup also leaves the server. A backup that lives only on the server is lost with the server. Use a key that can read and write but not delete ([§ Bucket retention](#bucket-retention-versioning-and-incomplete-uploads)).
3. Run a [restore drill](#restore-drill) once it has taken its first backup.

What it does: a few minutes after it starts (when the last backup is missing or a day old) and then every day at `BACKUP_HOUR_UTC` (default 3, in UTC) it writes a verified `pg_dump` archive named `daily-<time>.dump` into the server's `backups` volume, keeps the newest dump from each of the newest `BACKUP_KEEP` UTC days that have dumps (default 14), and uploads each one when `BACKUP_S3_*` is set. It waits while a deploy is migrating the database and skips a database whose migration failed (that needs a person first). A failed backup is retried every hour; if only the upload failed, the retry uploads the same file again instead of taking another, so a broken bucket cannot fill the disk. A backup counts as done only once it is uploaded (when S3 is set). The service's Docker healthcheck turns **unhealthy** when the last backup failed or is more than 26 hours old, which Dokploy shows on the service. It is the same archive format as the pre-migration backup, so `restore` and the drill read it directly. Restoring one is detected automatically (scheduled deletions wait 7 days).

### Dokploy-managed Postgres

If Postgres is a Dokploy database instead of part of the compose, use Dokploy's built-in backups: database → **Backups** tab → add an S3 destination, a daily schedule, and a retention of at least 14 days ([deployment.md](./deployment.md#enable-postgres-backups)). Dokploy writes gzip-wrapped `pg_dump` files; `restore` reads them directly, and Dokploy's database Restore button is detected automatically.

Avoid Dokploy's **Volume Backups** for the database: restoring such a copy is not detected. If you ever do, start only the database, run `bash app-db.sh hold-deletions` ([§ The server helper](#the-server-helper-app-dbsh)) or the image's `hold-deletions` command, then start the app ([schema-migrations.md § Holding deletions by hand](../schema-migrations.md#holding-deletions-by-hand)).

Record the chosen backup system, bucket prefix, retention, alerts and owner in your deployment records.

### Container platforms

Use the managed database's automated backups and point-in-time recovery (Azure Database for PostgreSQL, Amazon RDS). Set the retention window and an alert on backup failure in the provider console or the infra repo. See [deployment.md](./deployment.md).

## Pre-migration backup (optional, encouraged)

`BACKUP_ENABLED` (strict `true`/`false`, default `false`; any other value refuses to start) is the backup switch. A configured destination alone does not turn the automatic dumps on. When a database has migrations to apply and `BACKUP_ENABLED=true`, the migration runner first calls `scripts/backup/pre-migrate.sh --required`. This is the safety net for "the migration did something we didn't want".

- **`BACKUP_ENABLED` unset/`false` (default)** → no backup hook runs; migration and pre-drop snapshots are skipped, including configured destinations. The server logs one startup notice saying backups are off; a server start or the `migrate` command also warns when a destination is configured anyway. Nothing refuses.
- **`BACKUP_ENABLED=true`, no usable destination** (no writable mounted `/backups`, no valid `BACKUP_S3_*`) → a container that migrates (`MIGRATE_ON_START=true`, or the `migrate` image command) fails at startup with `BACKUP_ENABLED=true but no backup destination is configured`, before migrating, **on a brand-new database too** (no exemption: the first start reports the missing destination before any data exists). A server that only waits (`MIGRATE_ON_START=false`) starts normally.
- **`BACKUP_ENABLED=true` and the dump fails** → the migration does **not** run and the deploy stops. Fix the backup (disk full, bad S3 key) and redeploy, or set `BACKUP_ENABLED=false` deliberately.

Explicit operations work whatever the switch says: the `backup` command and the pre-restore snapshot always use `--required`. The daily service (`BACKUP_SCHEDULE=daily`) also needs `BACKUP_ENABLED=true` (see [§ Monitoring backups](#monitoring-backups)) and then uses `--required` too.

**Dokploy:** mount a named volume at `/backups` on the app (`pnpm dokploy:config --backups true` emits one). When `BACKUP_ENABLED=true` and `/backups` is a real mounted volume and is writable, the app writes a `pg_dump` custom-format archive there before migrating. No object-store credentials are needed for a local volume destination. The bare image-created `/backups` directory is not a persistent destination. To also upload it off the server, set the optional `BACKUP_S3_*` variables (`BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY`, `BACKUP_S3_REGION`, and if needed `BACKUP_S3_ENDPOINT`, `BACKUP_S3_PREFIX`, `BACKUP_S3_FORCE_PATH_STYLE`, `BACKUP_S3_SSE`). Use a key that can write but not delete. The app keeps the newest 5 pre-migration dumps in `/backups` and deletes older ones, plus any hidden `.pre-migrate-*.dump.partial` left by a dump that was killed more than 120 minutes ago; it never deletes anything in S3. The backup runs while the migration runner holds its lock, so a second migrating container waits for it; the 300-second wait must cover backup plus migration time, or that container exits and restarts (expected, see [schema-migrations.md § What happens at deploy](../schema-migrations.md#what-happens-at-deploy)).

**Container platforms:** the infra workflow takes a provider snapshot before the `migrate` job (RDS manual snapshot; Azure on-demand backup where the service supports it). `BACKUP_ENABLED` is normally left `false` there; set it (with `BACKUP_S3_*`) on the `migrate` job only if that job should dump too.

`pnpm doctor:app` reports the switch and recommends turning it on with a destination. It is strongly encouraged before any migration that drops or rewrites data.

**Pre-drop backup.** With `BACKUP_ENABLED=true`, the same hook also runs right before a scheduled deletion (`contract.sql`, [schema-migrations.md § Expand and contract](../schema-migrations.md#expand-and-contract)), labelled `pre-drop`, when a deletion is due and that run took no pre-migration backup. The runner passes `--keep 5` explicitly for `pre-drop`. Direct invocations with another label default to `--keep 0` (no local pruning). The runner passes `--required` here too: a dump that fails → no deletion runs that start (the app starts normally) and the next start tries again. (With no destination at all, a migrating start already stops at the entrypoint's startup check; a start that only waits never runs deletions.) The `[migrate] DATA DELETED:` log line names the backup it took.

## Storage identity and retention

Use an explicit prefix for each deployment, for example `wssp/production/sandbox.example.com/database`. The generator includes the environment and validated host. Objects live directly at `<BACKUP_S3_PREFIX>/<label>-<timestamp>.dump`; no database hash or fallback namespace is added. Two deployments sharing a bucket need different prefixes. A local-only volume does not protect against loss of the VPS.

The writer/restore identity needs `GetObject`, `GetObjectVersion`, `PutObject` and `AbortMultipartUpload` on that prefix, without object deletion. Use separate `BACKUP_MONITOR_S3_ACCESS_KEY_ID` / `BACKUP_MONITOR_S3_SECRET_ACCESS_KEY` credentials with **ListBucket only**, constrained to `<prefix>/`. Never copy writer credentials into the monitor identity; the server and worker entrypoint refuses to start when `BACKUP_MONITOR_S3_ACCESS_KEY_ID` equals `BACKUP_S3_ACCESS_KEY_ID`. The running application has writer keys unset after admission; Docker container configuration still holds the startup credentials used by `host.sh` to launch operations.

| Operation                                   | Default local retention                                                                             |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Pre-migration                               | Newest 5 `pre-migrate` dumps                                                                        |
| Runner pre-drop                             | Newest 5 `pre-drop` dumps, passed explicitly                                                        |
| Direct other labels, manual and pre-restore | `--keep 0`: no pruning; choose explicit retention where needed                                      |
| Daily scheduler                             | Newest dump per UTC day for the newest `BACKUP_KEEP` days containing dumps; default 14, range 1–365 |

S3 expiration is controlled by bucket lifecycle rules, never local pruning. A successful dump logs `[backup] Verified <path>`; when S3 is configured, also require upload success and record the object key, ETag and version ID. A silent no-destination exit (an automatic call with backups off or nothing configured) is not evidence of a backup. `--required` makes a missing destination fail; image command `backup` already uses it.

## Restore

Restore is a command in the app image: `restore <source> [options]`. It runs **inside the target network** (a one-off container on the Dokploy server, or a one-shot job on a container platform) using that environment's `DATABASE_URL`. Agents prepare the exact command; **the owner runs it**. On Dokploy, [the server helper](#the-server-helper-app-dbsh) can guide the operation.

```text
restore <source> [--confirm RESTORE:<target-database>] [options]
restore --list                    list the backups in /backups, newest first

<source>   latest                 the newest backup in /backups (daily, manual or
                                  pre-migration; never a pre-restore snapshot)
           /backups/<file>        a file inside the container (raw pg_dump -Fc/-Ft,
                                  or gzip-wrapped such as Dokploy's .sql.gz)
           s3://<bucket>/<key>    an object in BACKUP_S3_BUCKET (needs BACKUP_S3_*)

--confirm RESTORE:<db>       required to change anything; <db> is the database named
                             in DATABASE_URL. Without it: verify the source and preview only.
--replace                    allow restoring over a non-empty database (snapshot first,
                             then drop app schemas and restore, in one transaction)
--etag <etag>                S3 only, required: the exact object ETag
--version-id <id>            S3 only: pin an object version
--allow-active-connections   proceed although other sessions are connected
--skip-snapshot              with --replace: skip the pre-restore snapshot
                             (only when a provider snapshot exists)
--guided                     after the preview, ask and fill in --confirm / --replace /
                             --etag: y/N for an empty database; replacing one that
                             holds data needs its name typed (needs docker run -it)
```

What it does for you: verifies the archive before touching anything, checks the target, refuses while other sessions are connected, snapshots the current database (to `/backups` and/or S3, so one must be configured) before replacing it, and holds the same locks as migrations (Prisma's and the migration runner's) so a deploy cannot migrate halfway through a restore; it refuses while a migration runner is working. It re-checks whether the target is empty after taking the locks and refuses if that changed. One database session takes those locks before the checks and keeps it through the snapshot and the restore transaction itself, so no migration or second restore can run at any point in between.

Always preview first: run it **without** `--confirm`, read the preview, then run it with `--confirm` (or use `--guided`, which shows the preview and then asks). If anything fails before COMMIT is sent, the restore transaction rolls back and the target is left as it was (exit `4`). After COMMIT was sent, `restore` reports "rolled back" only when that is provable: psql (run with `ON_ERROR_STOP`) stopped on an SQL error before printing the confirmation that follows COMMIT (a client-side `\echo`, which cannot fail), so the failing statement came at or before COMMIT; or the server's `pg_xact_status()` for the restore transaction, asked from a fresh session, says aborted. Otherwise it is uncertain (exit `1`, or `129`/`130`/`143` for a signal). A lost response or process failure is still ambiguous to the operator: inspect the target before making any unchanged claim or retrying.

Exit status of `restore`:

| Exit                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`                   | Restored (also when a signal arrived after COMMIT succeeded, cutting the summary short: "Restore completed; then interrupted").                                                                                                                                                                                                                                                                                                                          |
| `3`                   | Refused or cancelled **before anything changed**: a usage error, preview only, a cancelled prompt (including Ctrl-C / Ctrl-D at the prompt), a stop signal before the restore transaction started (also while scanning `/backups` for `--list` or `latest`), a failed check, an archive with large objects, a failed pre-restore snapshot, or any other error before the restore transaction starts (an S3 source the checks reject, a failed download). |
| `4`                   | **Rolled back, the target is unchanged**: the restore transaction started, then failed or was interrupted, and provably did not commit (COMMIT was never sent; psql stopped on an SQL error before confirming it; or the server reports the transaction aborted). The output says why it failed.                                                                                                                                                         |
| `1`                   | Failed with an **uncertain** outcome: COMMIT may have been sent and neither the session nor the server confirms either way; or the restore committed and a later step failed (the output says which). The helper treats every `1` as not proven unchanged.                                                                                                                                                                                               |
| `129` / `130` / `143` | Interrupted by a signal after COMMIT was sent, before it was confirmed: **uncertain**. (A signal before COMMIT was sent is a rollback: `4`.)                                                                                                                                                                                                                                                                                                             |

Afterwards, deploy an image that contains every migration the restored database has applied (the same or a newer commit).

### On Dokploy

#### The server helper (app-db.sh)

The app image ships a small script for the Dokploy server that needs only bash and Docker. Copy it out of the running app once (SSH into the server first):

```bash
docker exec <exact-server-container> cat /app/scripts/backup/host.sh > app-db.sh
```

| Command                                                         | What it does                                                      |
| --------------------------------------------------------------- | ----------------------------------------------------------------- |
| `bash app-db.sh list`                                           | Lists the backups in the server's `backups` volume, newest first. |
| `bash app-db.sh backup`                                         | Takes a verified backup now (`manual-<time>.dump`).               |
| `bash app-db.sh restore --project <compose-project> [<backup>]` | Guided restore. Default: the newest backup.                       |
| `bash app-db.sh drill [<backup>]`                               | [Restore drill](#restore-drill) into a throwaway database.        |
| `bash app-db.sh hold-deletions [days\|--clear]`                 | Pauses scheduled deletions after a restore the app cannot detect. |

It finds the app's containers, image, network and backups volume by itself (`--project <name>` picks one when the server runs several apps), and hands the database settings from the running app straight to a one-off container of the same image, so no secrets are written to a file. "Same image" means the running server's image ID, never its tag: if a no-change redeploy rebuilt an identical image and Docker dropped the old ID while the server still runs it (Docker 29's containerd image store), the helper stops with `the server container's image … is no longer on this machine` and prints the fix, `cd <the compose's directory> && docker compose -p <project> -f <each compose file the deploy used> up -d --no-build --force-recreate server` (the files, overlays included, come from the server container's own Compose labels; add `--profile backup` before `up` when the backup service is deployed; it restarts the app); then re-run the helper. `<backup>` is a file name from `list`, or an `s3://<bucket>/<key>` object when `BACKUP_S3_*` is set.

#### Restoring

```bash
bash app-db.sh restore --project <compose-project>                       # the newest backup
bash app-db.sh restore --project <compose-project> daily-20261110T030000Z.dump
```

1. It asks before it stops the app (and worker and backup service). Postgres and Redis keep running. Only `y` or `yes` goes on: anything else, just Enter, Ctrl-D, or Ctrl-C while it waits (or a TERM or HUP signal then) cancels with exit `3`, and nothing is stopped or started. If Auto Deploy is on in Dokploy, don't merge anything until it finishes. `host.sh` is Linux-only (it runs on the Dokploy server) and needs a terminal on stdin; `bash app-db.sh restore | tee restore.log` works and still prompts.
2. It shows the preview: which backup, how old, which database, whether that database is empty. Then it asks you to confirm. When the database holds data (the usual case), you must **type the database name** shown in the preview; anything else, or just Enter, cancels. Restoring into an empty database asks **[y/N]** instead. It then fills in `--confirm RESTORE:<database>` (and `--replace`, which snapshots the current data first) for you.
3. After a completed restore (exit `0`) it starts the app again; the app applies any migrations newer than the backup as it starts. Check it with `pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha>` ([deployment.md § First deploy](./deployment.md#first-deploy)) or by opening the site.

4. If restore exits `3` (you cancelled at the prompt or during the checks, or it refused before changing anything), the helper prints `Cancelled or refused; nothing was changed.` and **starts the original writers again**. If it exits `4` (it started, failed and provably rolled back), the helper prints `Restore failed and was rolled back; the database is unchanged` and **starts the original writers again** on the unchanged data. Any other exit (an uncertain outcome, or a `docker run` failure such as `125`, which Docker also returns when waiting on a started container fails) does not prove nothing changed: the helper reports `Restore failed and its outcome is uncertain, or it committed and a later step failed` (the restore output says which), **leaves the writers stopped** and prints the `docker start` command to use once you have inspected the database. It reports its outcome on stderr, so a dead `| tee` reader cannot stop it from starting the writers after a refusal.

Exit status of `bash app-db.sh restore`:

| Exit  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`   | Restored; the helper starts the app again.                                                                                                                                                                                                                                                                                                                                                                                               |
| `3`   | Nothing changed: you declined or pressed Ctrl-C at "Stop the app and continue?", or the helper got TERM or HUP while it waited (the app was never stopped), or `restore` cancelled or refused (the helper starts the original writers again).                                                                                                                                                                                            |
| `4`   | The restore started, failed and rolled back: the database is unchanged; the helper starts the original writers again.                                                                                                                                                                                                                                                                                                                    |
| other | The helper refused before stopping anything (`1`: no terminal, database container not running, wrong arguments; the error says which); stopping a writer failed before the restore began (that status; the helper tries to start the writers again); or the restore's outcome is uncertain, or it committed and a later step failed (the restore's status, or `docker run`'s; the restore output says which): the app **stays stopped**. |

Restarts are best effort (a failed `docker start` does not change the exit status): confirm with `docker ps`. A Ctrl-C, TERM or HUP after that prompt is not a cancel: the helper exits `130`, `143` or `129`; before the restore was invoked it first tries to start the writers again; once it was invoked, the last case of the `other` row applies. Under `| tee` the pipeline reports `tee`'s status: use `set -o pipefail` or `${PIPESTATUS[0]}` to see the helper's. Ctrl-C in the terminal also stops `tee` (its last lines, such as the cancel message, may not reach the log), so `pipefail` then reports `tee`'s `130`: read `${PIPESTATUS[0]}`, or log with `tee -i`, which ignores Ctrl-C.

A restore by `restore` is detected automatically: scheduled deletions wait 7 days. Dokploy's database Restore button is detected too. Restoring a Dokploy **Volume Backups** copy is not: start only the database, run `bash app-db.sh hold-deletions`, then start the app ([schema-migrations.md § Holding deletions by hand](../schema-migrations.md#holding-deletions-by-hand)).

Dokploy-managed Postgres (no `postgres` service in the compose): the helper does not apply; run the same `restore` image command by hand as a one-off container on `dokploy-network` with the app's `DATABASE_URL` (agents prepare it). Dokploy's own S3 backups restore via `s3://` when `BACKUP_S3_*` points at that bucket, or download the `.sql.gz` into the backups volume first.

### On a container platform

Prefer the provider's own restore (point-in-time recovery into a new server, then switch `DATABASE_URL`) for whole-database recovery. To load a logical dump, the infra workflow runs the app image as a one-shot job (Azure Container Apps job / ECS RunTask) with command `restore <source> …`, the environment's secrets, and app + worker scaled to zero. Same two runs: preview, then `--confirm`. Then deploy the current SHA as usual so the `migrate` job brings the schema forward.

If the restored database is **newer** than the image (its history has migrations the image lacks), the app starts only when every one of those is rollback-safe and none of their deletions has run; otherwise it refuses with `db-ahead` and you deploy a newer SHA. If it reports `failed`, follow [schema-migrations.md § Recovery runbook](../schema-migrations.md#recovery-runbook).

### Restores and scheduled deletions

A restore can bring back data a scheduled deletion already removed, and the matching `contract.sql` would delete it again on the next start. So every restore holds scheduled deletions for 7 days:

- the `restore` command writes the hold itself, and a point-in-time restore, any `pg_restore --clean`, and a dump restored into another server or database are detected by the runner at the next start;
- a provider snapshot restore, a Dokploy Volume Backups copy, a `pg_restore --data-only`, or any provider restore whose identity behavior has not been verified may not be detected: start only the database, run the image's `hold-deletions` command ([schema-migrations.md § Holding deletions by hand](../schema-migrations.md#holding-deletions-by-hand)), then start the app.

If you restored to get a deleted field's data back, ship the `--recover` PR within those 7 days ([schema-migrations.md § Getting a field back](../schema-migrations.md#getting-a-field-back)).

## Restore drill

Run a restore drill before relying on backups, every quarter, and after any backup change. On the Dokploy server:

```bash
bash app-db.sh drill            # the newest backup; or name one from `bash app-db.sh list`
bash app-db.sh drill s3://<bucket>/<key> --etag <etag>   # a copy in the bucket (ETag from the upload log)
```

It starts a throwaway Postgres container next to the app (same image as the app's database, on its own private network), restores the backup into it with the app's own `restore` command, then checks that every table in the backup came back and that the migration history is complete. It prints each table's row count and the backup's age (a warning when the newest backup is over a day old), then **DRILL PASSED** or **DRILL FAILED**, and removes the throwaway database. Production is never touched: the drill only restores into an empty database named `restore_drill`, and it accepts no option but `--etag` / `--version-id` (for `s3://` backups).

Record the date, exact backup key/version, checked records and result in the deployment recovery log.

On a container platform, run the image's `restore-drill <source>` command as a one-shot job with `DATABASE_URL` pointing at a new, empty database named `restore_drill` (never production), then delete that database.

## Monitoring backups

`BACKUP_ENABLED` defaults to `false` and gates automatic migration/pre-drop snapshots, the daily writer and freshness monitoring. While off, no freshness scheduler or stale-backup warning affects health/readiness. Explicit manual backups and required pre-restore snapshots still work. The daily writer additionally requires `BACKUP_SCHEDULE=daily` (otherwise `off`). The generated `--backups true` opt-in enables both defaults.

The worker checks off-site freshness every six hours using the dedicated ListBucket identity and `BACKUP_MAX_AGE_HOURS` (default 36). It considers complete `daily`, `manual`, `pre-migrate` and `pre-drop` dump objects under the explicit prefix; partials, `pre-restore` safety snapshots and unrelated objects do not count. Monitor misconfiguration means off-site health is unknown, not that backup writing is disabled. A local-only backup or a provider-native snapshot is not proof of a fresh object in this bucket.

- The generated compose's `backup` service reports its own freshness: its healthcheck is **unhealthy** when the last daily backup failed or is more than 26 hours old. Look at it in Dokploy, or alert on it with any Docker health monitor.
- Otherwise turn on the platform's failure notification (Dokploy notifications for backup failures; provider alerts on Azure/AWS).
- Optionally add an external alert on the bucket (for example, "no new object in 26 hours").
- Run the restore drill above on a schedule. It is the only proof that backups work.

## The PG_MAJOR rule when you upgrade Postgres

`pg_dump` can dump a database **older** than itself, never a newer one. `Dockerfile` and `Dockerfile.worker` pin the Postgres client major with `ARG PG_MAJOR`. **When you upgrade the database's major version, bump `PG_MAJOR` in both files and rebuild.** `pnpm docker:check-copy` fails if they disagree. A client older than the server makes `pg_dump` fail, which stops a configured pre-migration backup — and with it the migration — until you rebuild.

## Bucket retention, versioning, and incomplete uploads

The app only ever adds objects to the bucket; it never deletes them. That is safety, not retention. Decide these with the owner and record them with the deployment configuration:

1. **Retention window.** Long enough to cover the longest time a bad change could go unnoticed. Use the bucket's lifecycle expiration rule on the backup prefix, not a script.
2. **Enable versioning.** The writer uses conditional no-overwrite uploads. Bucket versioning provides additional recovery protection against other writers or mistakes and lets a restore pin `--version-id`. Add a noncurrent-version expiration alongside the retention window.
3. **Incomplete multipart uploads.** Add a lifecycle rule that aborts them (7 days is a good start). A killed upload can leave parts that cost money forever.
4. **Object Lock is optional and irreversible.** Do not enable it until the owner has chosen retention and legal requirements.

## Backup scope and encryption keys

Postgres dumps do not contain guest VM disks, template-image objects, the server
transfer spool or its template-build context sibling. Keep separate recovery and
retention policies for each. Preserve host journals and exact disk/image identity;
do not infer runtime absence from a missing database row. Record the matched spool
snapshot when restoring transfer metadata.

Retain `DATA_ENCRYPTION_KEY`, `SANDBOX_REQUEST_HMAC_SECRET` and authentication
secrets separately from dumps, with access limited to the recovery owner. Without
the original data key, encrypted vault and webhook data cannot be recovered.
Never copy production secrets into a development recovery checkout.

## Backup heartbeat

`BACKUP_HEARTBEAT_URL` receives a best-effort GET only after the canonical writer
successfully uploads a verified dump to S3, including an upload-only retry. A
heartbeat failure warns without failing the backup. Local-only dumps do not send
it. Freshness uses the embedded snapshot UTC timestamp in the canonical object
name, never upload time or object LastModified; retrying an old dump cannot make
it look freshly captured.

## Replacement database recovery handoff

Drain the server, external workers, backup scheduler and any other writer before
previewing a full restore. Preserve the original database through the agreed
retention period. Inject the replacement URL consistently into all roles and
one-shot operations; use the same immutable release or a newer compatible one.
Run migrations, then deploy the server and follower worker. Require
`pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha>` to inspect the current task generation
and `/ready` commit before reopening traffic. A historical successful job is not
deployment acceptance. Qualify one host command/file/terminal flow and a fresh
backup plus isolated restore drill.

## Disk offload

Offloaded sandbox disks ([templates § disk offload](./templates.md#disk-offload))
live in the image bucket, which is not part of database backups. Their data
keys live in the database, wrapped under `DATA_ENCRYPTION_KEY`.

- **Back up the bucket separately** if you need offloaded sandboxes to
  survive losing it. An `OFFLOADED` sandbox whose object is gone cannot be
  restored.
- **After a database restore** the sweeper reconciles the bucket against the
  restored rows: objects no row keeps are deleted after a day, and a row
  whose object is missing fails at restore fetch, leaving the sandbox
  `OFFLOADED`.
- **Shred holds only past database backup retention.** Destroying a sandbox
  or consuming a copy zeroes its wrapped key in the live database, but
  backups taken earlier still hold the wrap. Anyone with such a backup and
  the root key can decrypt a copy of the object they also hold, until the
  backup ages out of your retention window. Treat a disk as shredded only
  once every backup older than the shred has expired, and rotating
  `DATA_ENCRYPTION_KEY` does not change that
  ([production hardening](./production-hardening.md#data-encryption-key)).

Back up `BETTER_AUTH_SECRET` separately from the database and retain keys needed by older backups. Restoring with a different key requires the [password pepper rotation and recovery runbook](./production-hardening.md#password-pepper).
