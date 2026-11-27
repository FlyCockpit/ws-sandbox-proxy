# Deployment

Dokploy on a VPS is the documented target. The image, env, and migration startup
contract live in [docs/infra.md](../infra.md). This page is the operator
walkthrough.

## Blessed Compose path

```sh
pnpm dokploy:config --environment production --git-ref <immutable-tag> --url https://sandbox.example.com --project wssp --proxy-network dokploy-network
```

Paste the generated Compose file into Dokploy (Compose). Every image builds
from the pinned Git context `<repository URL>#<git-ref>` (production: the
immutable `release/<sha>` tag), so the pasted Compose needs no source tree: the
Dokploy server's Docker fetches the ref itself on each deploy. The URL defaults
to the checkout's `origin` remote; pass `--git-url <URL>` for another
(https://, ssh:// or `git@host:owner/repo.git`). It must be fetchable by Docker
on the Dokploy server (a public repository, or an SSH URL whose key that Docker
can use) and may not carry credentials: the generator refuses a token in the
URL, because the file is stored in Dokploy. `--git-url local` writes
`context: .`, only for plain `docker compose` in a checkout. The checklist's
`compose.buildContext` repeats the choice. The build's commit comes only from
`BUILD_VERSION` (the image never reads `.git`, which `.dockerignore` excludes):
production defaults it to the tag's SHA; for development set `BUILD_VERSION` to
the deployed `main` SHA in Dokploy's environment, or `/ready` reports no commit.
No public IP (a home server)? Put a Cloudflare Tunnel in front instead:
[Home server behind a Cloudflare Tunnel](#home-server-behind-a-cloudflare-tunnel).

`MCP_ENABLED` is forwarded to the server as an optional key: leave it empty for
the default (MCP on) or set `false` in Dokploy's environment to turn the MCP
endpoint and its OAuth provider off ([environment variables](./environment-variables.md)).

**Other optional variables (`--env`).** The Compose forwards only the
variables the generator knows a deployment needs. To tune anything else the
server or worker reads (request budgets such as `RATE_LIMIT_SDK_KEY_POINTS`,
the S3 image store `IMAGE_S3_*`, disk offload `SANDBOX_OFFLOAD*`, …), name
the keys once at generation:

```sh
pnpm dokploy:config … --env RATE_LIMIT_RPC_POINTS,RATE_LIMIT_SDK_KEY_POINTS,IMAGE_S3_ENDPOINT,IMAGE_S3_BUCKET,IMAGE_S3_ACCESS_KEY_ID,IMAGE_S3_SECRET_ACCESS_KEY,IMAGE_S3_FORCE_PATH_STYLE
```

Each key becomes `KEY: "${KEY:-}"` on the server, and also on the external
worker when the worker reads it (a shared variable); set its value in
Dokploy's environment. Empty or unset means the app's default (the env
parser treats an empty value as unset), so regenerating never changes a
setting by itself. The checklist lists them under the optional variables.
Values never pass through the generator. It refuses a key that is not a
server or worker variable of `packages/env/src/vars`, one it sets itself
(`BACKUP_*`, `RESTORE_*`, `WORKER_MODE`, `MIGRATE_ON_START`,
`WSSP_INSTANCE_ID`, and `PORT`/`SERVER_PORT`, since the proxy targets port 3000), one it already forwards, and a repeated key. Keep the
list with your deployment notes and pass it at every regeneration; no hand
edit of the Compose is needed.

`app` (default) runs one server
with embedded jobs plus Postgres 18 and Valkey 9 (`noeviction`). `--topology
app-worker` adds a dedicated worker and sets `WORKER_MODE=external`. Backups default off; no backup settings, volume or sidecar are required.
Regenerate with `--backups true` to add the optional backup profile and volume. No role uses a dedicated migration image.
For the default Compose deployment, set only `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`BETTER_AUTH_SECRET` and `SANDBOX_REQUEST_HMAC_SECRET` (strong URL-safe secrets).
The generator sets the HTTPS auth origin. SMTP, data encryption and backups
are optional; add `ADMIN_EMAILS` and SMTP to bootstrap the first admin, or
set `SETUP_KEY` for a first admin without email
([First admin without email](#first-admin-without-email)).
Inject secrets as complete literal values on the platform.

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

The generated Compose file pre-wires those labels. It also adds a second
router, `<project>-server-content`, for operation content downloads
(`/v1/operations/{id}/content` and `/api/dashboard/operations/{id}/content`,
a Traefik v3 `PathRegexp` rule at priority 1000) with no middleware, so those
responses keep their `Content-Length` and byte ranges (see
[reverse proxy transfer bodies](#reverse-proxy-transfer-bodies)). Confirm a full page
response has `content-encoding: br` (or gzip), and a download has a
`Content-Length` and no `content-encoding`. Proxies skip compressing
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

`BACKUP_ENABLED` defaults to `false`: migrations and scheduled deletions proceed
without backups, even if old backup destination settings remain. The server logs
one backups-off notice at startup; readiness stays healthy. With
`BACKUP_ENABLED=true` the runner requires a pre-migration (and pre-drop) dump to
a mounted `/backups` volume or S3: with no usable destination a migrating start
fails, on a brand-new database too, and a failed dump blocks migrations. Allow 510 seconds for
startup, including runner admission, and 30 seconds for graceful shutdown.

## Enable Postgres backups

Regenerate with `--backups true` using the same project, origin and release, then
enable the Compose `backup` profile. This opt-in adds the shared backup volume
and sets defaults `BACKUP_ENABLED=true` and `BACKUP_SCHEDULE=daily`. Explicit
environment values override these defaults; set both to enable automatic backups. Keep exactly one daily
schedule per database. Mount the shared `/backups` volume and configure an
explicit per-app/environment/origin `BACKUP_S3_PREFIX` for off-site copies.

Writer credentials belong to startup/backup operations; long-running app
processes never see them. The entrypoint is PID 1 while the migration runner (its
child) holds them, then unsets `BACKUP_S3_ACCESS_KEY_ID` /
`BACKUP_S3_SECRET_ACCESS_KEY` and every other `BACKUP_S3_*` the process does
not read, and execs `tini` with the app, so `/proc/1/environ` and the app's
environment are clean. Each process keeps only `BACKUP_S3_BUCKET`, `_PREFIX`,
`_ENDPOINT` and `_REGION` (boot warnings and the admin freshness card), plus
`_FORCE_PATH_STYLE` wherever a worker runtime runs (its freshness check lists
the bucket with the monitor key): the worker, and the server unless
`WORKER_MODE=external` (the default embedded worker runs inside it). `_SSE` and
any other writer-only setting are dropped; if the settings cannot be listed,
the start fails rather than keeping them. A server or worker whose
`BACKUP_MONITOR_S3_ACCESS_KEY_ID` equals `BACKUP_S3_ACCESS_KEY_ID` is refused
before anything runs (the running process keeps the monitor key, and once the
writer key is gone it can no longer detect the reuse). With an external worker
the generated server also gets the monitor key ID alone, never its secret, for
this check; the entrypoint drops it before the server starts. Docker container configuration still holds
them; do not treat process unsetting as removal from container metadata. A stop
signal during startup (`docker stop`, Ctrl-C, a hang-up) is forwarded to the
running step and the container exits `143`/`130`/`129` without starting the app. Freshness monitors use separate
ListBucket-only keys in the chosen worker runtime. `BACKUP_ENABLED` gates automatic migration/pre-drop snapshots, the daily writer
and freshness monitoring; explicit backup and restore commands remain available. Provider backups/PITR can be used with a recorded
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
   verify email. Email (SMTP) must be configured for that: sign-in requires a
   verified address. Without SMTP, create the first admin with `SETUP_KEY`
   instead ([First admin without email](#first-admin-without-email)).
   **Admin → Overview → Deployment setup** then shows what
   else is configured (S3 image store, data encryption key, backups, preview
   tunnels).
6. Optionally enable backups and run a restore drill. The deployment runs without them.

`pnpm dokploy:config` topologies: `app` (default) and `app-worker`. Omitting the worker container never removes jobs — it
only moves them (`WORKER_MODE`).

## First admin without email

`SETUP_KEY` creates the first administrator without SMTP. It is optional and
unset by default; the generated Compose forwards it to the server as
`${SETUP_KEY:-}`.

1. Set `SETUP_KEY` on the server to 32–512 random characters
   (`pnpm generate:secret`; a weak key refuses to boot in production) and
   redeploy. The server log says the key is set.
2. From any checkout, run `pnpm deploy:generate-admin` and answer the server
   URL (`BETTER_AUTH_URL`), the key (not echoed; scripted use pipes it on
   stdin, never argv) and the admin's email. It prints a one-time link that
   expires in an hour. Re-running prints a fresh link; the earlier one stops
   working.
3. Open the link, choose the password (12+ characters) and sign in. The
   account is created only now, as a verified administrator, so nothing exists
   for anyone to race before the link is spent. Enrol two-factor
   authentication when asked, like every admin.
4. Remove `SETUP_KEY` and redeploy. Until you do, **Admin → Overview →
   Deployment setup** shows a "remove it" row and the server log repeats it.

The route (`POST /api/setup/admin`) and the link's claim do not exist while
`SETUP_KEY` is unset (404, before any input is read), so removing the key also
kills an unspent link. Both refuse once an active administrator exists, and
neither ever promotes an existing account: an address that already has an
account is refused. The route compares the key in constant time, allows five
attempts per client IP per 15 minutes (fail-closed), and writes one `[audit]`
line per attempt (`setup.first_admin`, `setup.first_admin_claim`) without the
key, email or link. Issuing and claiming take the admin governance lock, so
they serialize with each other and with every admin role change.

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
   `apple-touch-icon-180x180.png` is not generated: it is the owner's
   Apple-style tile, kept by hand. To replace it, start from a 1024×1024 tile,
   fill its transparent rounded corners from the tile's own edge colour (iOS
   applies its own mask and renders transparency as black), and save a
   full-bleed, opaque 180×180 PNG (no alpha channel) under that name.
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
with `--trust-proxy-hops N` at generation (for example `2` for a Cloudflare
Tunnel in front of Traefik, see
[home server behind a Cloudflare Tunnel](#home-server-behind-a-cloudflare-tunnel)). A deployment with no proxy keeps
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
  `wssp host run --runtime incus` refuses to start without it, or while
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

## Home server behind a Cloudflare Tunnel

A machine at home with no public IP can serve wssp through a
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
(a named tunnel run by `cloudflared`, Free or Pro plan). wssp needs no inbound
TCP or UDP: `cloudflared` dials out to Cloudflare, Cloudflare terminates TLS for
your hostname, and requests reach the server as plain HTTP. Node daemons,
`wssp ssh`, `wssp sandbox shell`/`forward`, browser terminals and SDK clients
all connect to that hostname over HTTPS/WSS, so they work through the tunnel
unchanged, and sandbox hosts can sit behind NAT too.

Pick one of two topologies. The hop count differs between them:

- **Tunnel to the server.** Browser, CLI, daemon or SDK → Cloudflare edge (TLS)
  → `cloudflared` → `http://server:3000`. One proxy hop: `TRUST_PROXY_HOPS=1`,
  which the generated Compose already sets. No Traefik is involved.
- **Tunnel to Traefik (Dokploy at home).** Client → Cloudflare edge →
  `cloudflared` → Dokploy's Traefik → server. Two hops: generate with
  `pnpm dokploy:config … --trust-proxy-hops 2`, which sets
  `TRUST_PROXY_HOPS=2` on the server. Traefik must trust `cloudflared`'s
  address for forwarded headers, or it replaces the client's
  `X-Forwarded-For` entry with `cloudflared`'s and every user shares one
  rate-limit bucket.

### Tunnel to the server

Generate the Compose with your tunnel hostname and a network of its own for
`cloudflared` (production: an immutable `release/<sha>` tag, as above):

```sh
docker network create wssp-edge
pnpm dokploy:config --environment production --git-ref <immutable-tag> --url https://sandbox.example.com --project wssp --proxy-network wssp-edge
```

Start it with `docker compose -f docker-compose.dokploy.yml up -d` and the
variables listed under [Blessed Compose path](#blessed-compose-path) in its
environment. The server joins `wssp-edge` and publishes no host port. Run `cloudflared` as
a container on that network (for example `cloudflare/cloudflared` with
`tunnel run`, the credentials file and this config mounted read-only), so the
tunnel is the only way in. The Traefik labels in the file are inert without
Traefik. A sample `config.yml` (create the tunnel and its DNS route with
`cloudflared tunnel create` and `cloudflared tunnel route dns`, then substitute
your tunnel id and hostname):

```yaml
tunnel: <tunnel-uuid>
credentials-file: /etc/cloudflared/<tunnel-uuid>.json
ingress:
  - hostname: sandbox.example.com
    service: http://server:3000
  - service: http_status:404
```

Keep `config.yml` and the tunnel's credentials JSON outside the checkout, for
example in `/etc/cloudflared` on the host: `--git-url local` builds from
`context: .`, and a credentials file inside the checkout is one `git add` from
the repository. The `cloudflare/cloudflared` image runs as the unprivileged
UID 65532 and `cloudflared tunnel create` writes the credentials file readable
by its owner only, so hand both to that UID, naming the file (a `*.json` glob
cannot expand once the directory is locked):
`sudo chmod 400 /etc/cloudflared/<tunnel-uuid>.json`, then
`sudo chown -R 65532:65532 /etc/cloudflared` and
`sudo chmod 700 /etc/cloudflared`. Otherwise the container cannot read the file
and the tunnel never connects. A remotely managed tunnel (created in the Zero
Trust dashboard, with the public hostname's service set there) needs no files:
run the connector with `tunnel run` and its token in `TUNNEL_TOKEN`, kept with
your other deployment secrets.

To run `cloudflared` on the host instead, publish the server on loopback only
with a Compose override (`ports: ["127.0.0.1:13000:3000"]` on `server`) and use
`service: http://127.0.0.1:13000`.
Use Docker Engine 28 or newer: older releases let other machines on the LAN
reach a port published on `127.0.0.1`. Never publish the server on `0.0.0.0` or
forward a router port to it: `TRUST_PROXY_HOPS` trusts the rightmost
`X-Forwarded-For` entries, so a caller who reaches the server directly can pick
their own rate-limit key.

### Tunnel to Traefik

Generate with `--trust-proxy-hops 2`. Traefik may trust exactly one address,
`cloudflared`'s, so run `cloudflared` as a container with a fixed address on a
small network of its own that Traefik joins (Dokploy's Traefik container is
`dokploy-traefik` on a standard install). `--ip-range` keeps Docker's
automatic addresses (Traefik's) in `.4`–`.7`, so `.2` stays free for
`cloudflared`:

```sh
docker network create --subnet 172.30.53.0/29 --ip-range 172.30.53.4/30 wssp-cf
docker network connect wssp-cf dokploy-traefik
docker run -d --name wssp-cloudflared --restart unless-stopped \
  --network wssp-cf --ip 172.30.53.2 -v /etc/cloudflared:/etc/cloudflared:ro \
  cloudflare/cloudflared:<version> tunnel --config /etc/cloudflared/config.yml run
```

Reconnect `dokploy-traefik` to `wssp-cf` whenever Dokploy recreates it (for
example after you change its Traefik settings). Point the tunnel at Traefik's
HTTPS entry point, keeping your hostname for SNI:

```yaml
tunnel: <tunnel-uuid>
credentials-file: /etc/cloudflared/<tunnel-uuid>.json
ingress:
  - hostname: sandbox.example.com
    service: https://dokploy-traefik:443
    originRequest:
      originServerName: sandbox.example.com
      noTLSVerify: true
  - service: http_status:404
```

In Traefik's static configuration (`traefik.yml`, editable in Dokploy's
Traefik settings) set the `websecure` entry point's
`forwardedHeaders.trustedIPs` to `["172.30.53.2/32"]`, never
`forwardedHeaders.insecure`. Do not trust a Docker network gateway (such as
`172.17.0.1`) or a whole subnet, and do not run `cloudflared` on the host for
this topology: connections that Docker's userland proxy forwards to a
published port, including LAN clients over IPv6, arrive from the gateway too,
and Traefik would keep their forged `X-Forwarded-For`. Any connection to
Traefik that does not come from `172.30.53.2` is untrusted: Traefik replaces
its `X-Forwarded-For`, and the server keys it on Traefik's own address (one
shared bucket), never on a value the caller chose.

The generated router uses `websecure` with the `letsencrypt` resolver. Without
inbound ports Let's Encrypt's HTTP and TLS-ALPN challenges cannot reach
Traefik, so it serves its default certificate, which `noTLSVerify` accepts.
That is acceptable only because `cloudflared` reaches Traefik on this
machine's private Docker network. For a verified hop, give Traefik a DNS-01
resolver instead and drop `noTLSVerify`. Do not point the tunnel at Traefik's
plain-HTTP entry point: the generated router does not listen there, and
Dokploy redirects it to HTTPS.

### Settings for both topologies

| Setting                     | Tunnel to the server                       | Tunnel to Traefik             |
| --------------------------- | ------------------------------------------ | ----------------------------- |
| `--url` / `BETTER_AUTH_URL` | `https://sandbox.example.com`              | `https://sandbox.example.com` |
| `TRUST_PROXY_HOPS`          | `1` (generated default)                    | `2` (`--trust-proxy-hops 2`)  |
| `CORS_ORIGIN`               | unset                                      | unset                         |
| `PUBLIC_APP_URL`            | unset, or the tunnel origin                | unset, or the tunnel origin   |
| `SMTP_HOST` / `SMTP_PORT`   | a relay on `587` (STARTTLS) or `465` (TLS) | same                          |

`BETTER_AUTH_URL` (the generator writes it from `--url`) is the public origin:
sign-in, cookies, emailed links, the browser `Origin` the terminal, transfer
and JSON routes accept exactly, the OAuth/MCP issuer and the URL hosts enrol
against all come from it, so it must be the tunnel hostname, `https://` with no
port. `cloudflared` keeps the browser's `Origin` and the original `Host`
header; leave `httpHostHeader` unset, because `/mcp` and OAuth refuse a `Host`
other than the `BETTER_AUTH_URL` host and Traefik routes by it. `CORS_ORIGIN`
is only for a dashboard served from a different origin. `PUBLIC_APP_URL` is
translation-provider metadata, not used for authentication. Home connections
usually block outbound port 25, so send mail through a relay's submission port:
`587` (STARTTLS) or `465` (the mailer switches to implicit TLS for 465 by
itself). `pnpm doctor:app` warns when `TRUST_PROXY_HOPS` is `0` on a deployment
(`NODE_ENV=production`, or an `https` `BETTER_AUTH_URL` on a non-local host),
and the server logs one `[client-ip]` warning when a private peer such as
`cloudflared` sends `X-Forwarded-For` while it is `0`.

**Client address.** Cloudflare appends the address that connected to it to
`X-Forwarded-For` and `cloudflared` forwards the header unchanged, so with the
hop counts above the server keys anonymous and `/v1` rate limits, sign-in
failures and audit records on the real client. wssp does not read
`CF-Connecting-IP`: it names the same address, but trusting it is safe only
while nothing but the tunnel can reach the server, and it would stay trusted
if the deployment later moved behind another proxy. One rule, counting the
hops in `X-Forwarded-For` ([client IP](./environment-variables.md#client-ip-and-reverse-proxies)),
covers every topology.

### Cloudflare limits and what they touch

- **Request bodies (100 MB on Free and Pro).** No wssp request comes near it.
  Transfer uploads are 1 MiB `Content-Range` chunks
  ([transfer bodies](#reverse-proxy-transfer-bodies)), relayed image copies
  between hosts are 32 MiB parts, and every other request is refused over
  10 MB. The one exception is outside the tunnel: with the S3 image store,
  daemons upload image parts straight to presigned S3 URLs, and a part grows
  past 100 MB only for an image near the 1 TiB maximum, so do not put your
  object store behind Cloudflare's proxy.
- **Silent responses (524).** Cloudflare answers 524 when the origin sends
  nothing for its Proxy Read Timeout: 125 s by default on Free and Pro,
  changeable only on Enterprise (it was 100 s for years, so plan for 100 s).
  Sandbox work is asynchronous and its waits are bounded well below that: an
  operation read holds at most 25 s (`waitMs`), an MCP tool waits at most
  60 s, a host's read of a relayed image part waits at most 60 s for the part,
  and an upload chunk's body read has a 60 s deadline. Two requests hash a
  file of up to 1 GiB before they answer: an upload commit and a template
  build's context seal (`POST /v1/template-builds/{id}/context/seal`). That
  takes seconds on local disk, but very slow or contended storage could hold
  them past the limit. Both are safe to repeat after a 524: send the commit
  again with the same `Idempotency-Key`, and a repeated seal returns the
  context already sealed. The CLI retries 429, 503 and 504 by itself, not
  524, so run its command again. Downloads (`/v1/operations/{id}/content`, up to 1 GiB) stream from
  the server's spool, so headers and bytes start at once; the server ends a
  stream only after 60 s in which the client read nothing. The exception is
  mail: a request that sends or checks email (verification and
  password-reset mail, the email second factor, pool invitations and access
  notices, the welcome mail of a user an admin creates) waits for the SMTP
  relay, and a relay that hangs can hold it past the limit, so the browser
  sees a 524. Use a relay that answers promptly. Mail is the other exception
  to the bounded waits above. Do not add a "Cache
  Everything" rule for the hostname: downloads carry `Authorization` or a
  session cookie and must reach the server.
- **WebSockets.** Keep WebSockets on for the zone (the default). Browser
  terminals, `wssp sandbox shell`/`forward`/`ssh` and the host relay never go
  quiet: the server pings browsers and CLI sessions every 20 s, and daemons
  heartbeat every 5 s.
- **No challenges on the wssp hostname.** The CLI (including
  `wssp host drain`), node daemons, SDKs and coding agents cannot pass a
  challenge or a login page. Turn Bot Fight Mode off for the zone (on Free it
  cannot be skipped for a hostname or path), and put no managed challenge,
  Super Bot Fight Mode action or Cloudflare Access application on the wssp
  hostname.

### When Cloudflare drops a connection

Cloudflare can close long-lived connections when its edge restarts.

- **Node daemons** reconnect by themselves with jittered backoff from 250 ms
  to 30 s ([connection loss](../guide/hosts.md#stopping-signals-and-reconnects)).
  Sandboxes keep running.
- **Browser terminals** end, and **Attach again** starts a new shell. The
  server closes the shell when the browser's socket drops. On a daemon with
  `terminalResume` the page first tries to reattach ("Reconnecting to the
  terminal…") and, after an edge restart, usually ends with "Could not
  reattach to the terminal. Attach again to start a new session."; otherwise
  it says "The connection to the terminal was lost, and the session ended."
  Keep long work in `tmux` or a command (`commands.start`). (Shells do survive
  a host relay reconnect or a server restart on daemons with
  `terminalResume`; see the [terminal guide](../guide/terminal.md).)
- **`wssp sandbox shell`, `forward` and `ssh`** have no resume.
  `sandbox shell` and `forward` exit 125 with `connect.lost` and say so:
  `the connection to the server was lost (…); the session cannot be resumed,
  so run the command again to start a new one`. For `wssp ssh`, `ssh`, `scp`
  and `rsync` the ProxyCommand prints that line and OpenSSH exits 255; VS
  Code Remote-SSH reconnects on its own.
- **Uploads and downloads** recover: the CLI re-sends an upload chunk whose
  connection dropped ([retries](../guide/cli.md)), and the SDK's
  `resumeDownload` continues a download by byte range while its capture is
  kept.

### What does not apply

- **ACME and certificates.** In the tunnel-to-the-server topology the
  generated Traefik labels (`entrypoints=websecure`,
  `tls.certresolver=letsencrypt`) are inert, and nothing behind the tunnel
  needs a certificate: Cloudflare holds the one for your hostname. With
  Traefik, see the TLS note above.
- **Response compression.** Without Traefik the compress middleware in
  [response compression](#enable-response-compression-dont-skip) is absent;
  Cloudflare compresses pages and JSON for the browser itself and leaves
  `application/octet-stream` downloads alone, so their `Content-Length` and
  byte ranges are kept.
- **Preview tunnels.** They run on the separate
  [tunnel server](../guide/tunnels.md), not through Cloudflare. A home wssp
  server only calls the tunnel server's HTTPS API, and each node's tunnel
  client dials it over one outbound WSS connection, so both work from behind
  NAT. The tunnel server itself terminates TLS for its wildcard preview zone
  (`https://<port>-<id>.<zone>/`, a DNS-01 certificate) and its WebRTC relay
  needs UDP, so it needs a host with a public IP (a small VPS) and inbound
  ports 80 and 443; it does not run behind a Cloudflare Tunnel. Without one,
  leave tunnels unconfigured: everything else works.
- **Static IP, router ports and DDNS.** The tunnel follows the machine
  wherever it connects from; forward no router port to it.

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
platform-injected environment. Mount `/backups` only for operations that need
local backup storage; `migrate` needs no backup volume when backups are off:

```sh
docker run --rm --network <db-network> --env-file <protected-operation-env> <immutable-app-image> migrate
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

During [password pepper rotation](./production-hardening.md#password-pepper), set the optional `BETTER_AUTH_SECRET_PREVIOUS` to the old secret on every server.
