# Testing

`pnpm test` is hermetic: Vitest unit tests with a mocked Prisma client and a
TCP guard (`scripts/test-io-guard.ts`) that fails any test opening a socket.
Database race, lock and foreign-key claims cannot be proven there. They belong
in the real-PostgreSQL layer below.

## Real-PostgreSQL tests

Files named `*.pg.test.ts` run only under `pnpm test:pg`. The default
`vitest.config.ts` excludes them, so `pnpm test` stays fast and offline.

**Rule.** A claim about DB race outcomes, lock ordering, lock-before-insert,
FK behaviour (`P2003`) or same-transaction atomicity needs a `*.pg.test.ts`.
Mock or recording-transaction tests may stay, but they are unit tests and must
say so in their `describe` name, and name the real-DB file that covers the claim
or say that none does yet (for example
`unit (mocked Prisma; no real-DB test yet for the P2003 mapping) — …`). The
marking is per claim, not per file: when one `describe` covers several sites,
each test names its own coverage (`… (real-DB: admission-lock.pg.test.ts)` or
`… (no real-DB test yet)`). `admission-lock.test.ts` checks its per-site
markings against the site list `admission-lock.pg.test.ts` actually runs.

### Running

```sh
pnpm test:pg                        # every package with a test:pg script
pnpm test:pg --filter=@wssp/api     # extra arguments go to `turbo run test:pg`
```

`scripts/test-pg.mjs` owns the run:

0. It refuses to start (exit 1, naming each file) when a `*.pg.test.ts` would
   never run: outside `src/` of an `apps/*` or `packages/*` package, in a
   package whose `test:pg` script does not run `vitest.pg.config.ts`, or when
   that config's include or turbo.json's `test:pg` task is gone. The same
   check (`pgWiringViolations`) runs in `pnpm policy:pg-image-ci`, so
   `pnpm verify:fast` catches an unwired file without Docker.

1. It starts one disposable `postgres:18.6` container
   (`scripts/lib/disposable-postgres.mjs`, shared with `pnpm db:test-migrations`
   and `pnpm runtime:test-operations`). The container has a random password
   (passed through a 0600 `--env-file` in a private temporary directory that is
   removed once `docker run` returns, so it never appears in argv), a
   port published on `127.0.0.1` only, `--memory 1024m`, a 512m tmpfs data
   directory (each file's clone is dropped when the file finishes, see
   Isolation), `fsync`, `synchronous_commit` and `full_page_writes` turned off and
   `max_wal_size` capped at 48MB so WAL cannot fill the tmpfs. It is
   labelled `wssp.disposable-postgres`. The image is never pulled implicitly
   (`--pull=never`, plus a presence check that fails naming
   `pnpm test:pg:pull-image`): run `pnpm test:pg:pull-image` once. That script
   (`node scripts/lib/disposable-postgres.mjs pull`) is the one place the
   pinned tag is pulled. `pnpm policy:pg-image-ci` fails if a CI job runs the
   layer in any shape (`test:pg` with any runner or pnpm flags,
   `scripts/test-pg.mjs`, or a package-manager `verify`) without pulling it
   first, if any job references a postgres image by literal tag (`docker pull`,
   `docker image pull`, a job or service `image:`), and if it cannot attribute a
   workflow's `jobs:` block line by line (it throws instead of skipping the
   file). A failing `docker` command never echoes `--env` values: the
   container password is redacted from the error.
2. It applies committed migrations through a relocated copy of
   `scripts/db/migrate-runtime.mjs apply`, using the production runner and its
   complete Prisma/native-owner closure with an allowlisted child environment.
   No checkout `.env` is copied or inherited; no seed is imported or executed.
   The database then becomes a frozen template (`IS_TEMPLATE`,
   `ALLOW_CONNECTIONS false`). Preparation runs once for the suite; every test
   file gets its own clone. Child failure diagnostics include exit/signal,
   bounded stderr and stop reason. The runner owns transactional recovery and
   native-child drain; an engine crash is never proof that no SQL committed.
3. It runs `turbo run test:pg --concurrency=1 --ui=stream` as an owned process
   group (`spawnOwnedProcessGroup`). Each package's Vitest uses
   `vitest.pg.config.ts` (`maxWorkers: 2`), so at most two test files run at a
   time.
4. It removes the container and its temporary fixture directory
   (`$TMPDIR/wssp-test-pg-*`, from `os.tmpdir()`) on success, failure,
   `SIGINT`, `SIGTERM` and `SIGHUP`, always AFTER the whole Turbo → pnpm →
   Vitest tree is gone. A signal (even `kill -INT` of the owner alone) is
   forwarded to the group; the owner waits for the group to empty (10 s, then
   `SIGKILL`), then removes the container and directory, then exits. On a
   normal exit, a descendant that outlived Turbo is terminated first.
   `docker ps -a --filter label=wssp.disposable-postgres` is empty after a
   run. A container that survives 100 removal attempts is never forgotten
   silently: stderr names it and its id with the `docker rm --force` command,
   and the run exits non-zero.

The harness is POSIX-only. Finding every process group a child tree created
needs the POSIX `ps` command (`ps -A -o pid=,ppid=,pgid=`; `procps` on Linux).
`spawnOwnedProcessGroup` refuses to start when `ps` does not work, and a `ps`
failure during teardown is reported on stderr and exits non-zero rather than
quietly signalling only the leader's group.

Running `vitest --config vitest.pg.config.ts` directly fails in global setup:
there is no database without the owner script.

### Skip policy

There is no silent skip. If Docker (or the image) is unavailable,
`pnpm test:pg` exits 1 and says why. `WSSP_SKIP_PG=1` turns that into a loud
`SKIPPED` banner and exit 0, for machines that cannot run Docker. The DB
claims are then unverified. Under CI (`CI` set to anything but empty, `0` or
`false`; GitHub Actions sets `CI=true`) `WSSP_SKIP_PG=1` is refused: the run
fails before Docker is even checked, so no workflow, repository variable or
inline env can skip the layer (`scripts/test-pg.test.mjs`). The PR workflow and the release
`node-checks` job run `pnpm test:pg:pull-image` first, then `pnpm test:pg` (the
release job through `pnpm verify`). `pnpm verify` includes it;
`pnpm verify:fast` does not.

### Container names

Every disposable fixture (`test:pg`, `test:s3`, `backup:test`,
`db:test-migrations`, `runtime:test-operations`) is named `<prefix>-…`: its
containers, the backup test's network and tools image included. The prefix is
`wssp` unless `TEST_CONTAINER_PREFIX=<name>` sets it (lowercase letters and
digits joined by `.`, `_`, `__` or `-`, at most 24 characters), so a shared
machine or a chained run (`pnpm verify`, CI) keeps its own namespace without
passing flags through. `--container-prefix <name>` on `backup:test` and
`db:test-migrations` overrides the variable (`scripts/lib/test-container-prefix.mjs`).

### Isolation

Each test file calls `pgTestDatabase()` (`@wssp/db/testing/pg`) and gets its own
database, cloned with `CREATE DATABASE … TEMPLATE`. Files never share rows, so
they can run in parallel. The clone has the production schema, including the
runner's migration history and registry tables. When the file finishes, an
`afterAll` that `pgTestDatabase()` registers drops the clone and any
`<clone>_<suffix>` database the file created beside it (name upgrade-apply
targets `${db.name}_upgrade_…`), so the container holds only the databases
of files still running. The drop refuses unless the admin URL is the loopback
port `scripts/test-pg.mjs` published (`WSSP_PG_CONTAINER`), the name is a
`wssp_t_<hex>` clone this process created, and the server's `cluster_name` is
that container's name; it is the one pinned exception in the
`scripts/policy-checks.sh` destructive manifest.

Production code reaches the file's database through the ordinary module
boundary:

```ts
vi.mock("@wssp/db", async () => {
  const { pgTestDatabase } = await import("@wssp/db/testing/pg");
  return { default: (await pgTestDatabase()).prisma };
});
```

`prisma` is built by `createPrismaClient` (`packages/db/src/client.ts`), the
same factory and adapter (`@prisma/adapter-pg`) that `@wssp/db` uses. Its pool
size is the `DATABASE_POOL_MAX` default read from the `@wssp/env` declaration
(`sharedVars.DATABASE_POOL_MAX.parse(undefined)`), never a copied number.
No production code reads a test-only variable. The admin URL reaches the tests
through Vitest `provide`/`inject`. Use `db.inspect`, a separate client that is
never paused, for fixtures and assertions.

### Barrier API

Barriers use promises and real row locks. They never sleep.

- `db.run(actor, work)` runs `work` as a named actor. Every transaction the
  actor opens records its backend pid.
- `db.pauseAt(actor, { before | after: matcher })` parks the actor's next
  matching statement. It is one-shot. A matcher is a string or RegExp over
  `"<model>.<method>"` (for example `"user.deleteMany"`) or `"sql:<text>"`
  (raw SQL, with template holes shown as `?`). It returns
  `{ reached, waitReached(timeoutMs = 10_000), release(), fail(error) }`.
  `reached` resolves with the matched statement name once the actor is
  parked; `waitReached` is the same promise, but rejects after the timeout
  naming the actor and point, so a statement that never runs fails the test
  instead of hanging. Tests normally await `waitReached`. `fail` resumes the statement by throwing,
  which rolls the transaction back.
- `db.waitUntilBlocked(actor, { by? })` resolves once PostgreSQL reports the
  actor's backend waiting on a lock (`pg_stat_activity.wait_event_type =
  'Lock'`). With `by`, the holder must be in `pg_blocking_pids`; a `by` actor
  with no recorded transaction backend never matches, and the deadline failure
  names the missing holder. The timeout only turns into a failure that names
  the last observed state. A test never passes by timing.

Forcing A-then-B: park A after it takes its lock, start B, assert
`waitUntilBlocked("B", { by: "A" })`, then release A. For B-then-A, swap the
roles. Examples:

- `packages/db/src/testing/pg.pg.test.ts`: the harness self-tests.
- `packages/api/src/sandbox/services/admission-lock.pg.test.ts`: account
  finalization vs admission, in both orders.
- `apps/server/src/sandbox-relay/host-tombstone.pg.test.ts`: same-transaction
  host finalization, with an injected failure.
- `packages/db/src/account-deletion.pg.test.ts`: receipts deleted with the
  account, a real P2003, and the live-FK inventory against
  `ACCOUNT_DELETION_CLASSIFICATION` and against the schema parser the unit
  inventory uses (`packages/db/src/testing/user-relations.ts`), so the two
  inventories cannot drift.
- `packages/db/src/sandbox-template-invariant.pg.test.ts`: the database
  rejecting writes that violate a schema `// @check` constraint.
- `packages/db/src/schema-checks.pg.test.ts`: all 144 declared CHECK constraints
  match the committed baseline, and violating writes fail without disclosing row data.

With no pause registered, the wrapper returns Prisma's own promises
unchanged. Batch `$transaction([...])` passes through untouched and cannot be
paused.

Host drain coverage lives in `apps/server/src/sandbox-api/hosts.pg.test.ts`:
real host-lock contention in both orders for create, cold reconnect and template
registration; owner and host credential scope matrices; revocation during admission;
rollback and receipt replay. `apps/cli/tests/drain.rs` covers the real CLI wire
request, bounded parsing, redirect refusal and exit codes using loopback HTTP.

## Lifecycle conformance

The sandbox lifecycle an external agent harness drives (create → ready →
binary seed → long-running script → nonzero result → diagnostics → capture →
retain → cold/warm reconnect → destroy) is proven by the repo's own fixtures.
No external harness, provider switch or E2B key is involved.

- **Harness shape.** `packages/sdk/test/harness-lifecycle.ts` runs the lifecycle
  through the public SDK surface only, with a seeded, invalid-UTF-8 binary seed.
- **Control plane, real PostgreSQL.**
  `apps/server/src/sandbox-relay/lifecycle-conformance.pg.test.ts` (run by
  `pnpm test:pg`) wires the real SDK to the real `/v1` adapters, the transfer
  store, the outbox processor (on a fake lease clock) and the relay session
  manager. The host is the wire double
  `apps/server/src/sandbox-relay/fake-node-daemon-harness.ts`: `FakeRuntime`
  semantics plus the daemon's journal phases and restart receipt rules
  (`apps/cli/src/sandbox_relay/reconcile.rs`). It covers the full lifecycle,
  the fault matrix below, six concurrent workers with retained VMs and a
  detached broker (a same-key create retry at capacity replays the original
  operation, never a capacity refusal), cancel-ACK capture safety, a host lost mid-capture, the
  default transfer and output caps, repeated expiry cycles, worker and server
  loss, and the terminal leg (attach, flood, 4401 detach, single attach, a new
  session after host loss, resources back to zero).
- **Fault matrix.** `crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json`
  lists one loss per boundary (commit, dispatch, effect, ack) and direction
  (request, response), with the restart receipt, the terminal operation state
  and the runtime effect count each must produce. The TypeScript suite drives
  its host double from those rows. The real daemon is held to the same rows by
  `apps/cli/src/sandbox_relay/lifecycle_conformance_tests.rs` (the production
  connect loop, journal and reconcile over `FakeRuntime`, restarted on the
  journal a death at that boundary leaves). The fixture binds only the restart
  receipt's state and error code, the operation's terminal state and the
  effect count (VMs for creates, executed commands for runs); receipt result
  payloads and frame ordering are not cross-checked between the two sides. An
  uncertain retry under the same key never adds a dispatch, a VM or a command
  effect. Two limits on the daemon side: its command-effect count is 0 or 1
  (the probe re-runs the operation and `FakeRuntime` refuses a second run, so
  it detects "ran" but cannot count a second execution), and it checks the
  restart receipt only; the operation's terminal state is asserted by the
  TypeScript suite alone.
- **Admission lock barriers.** `packages/api/src/sandbox/services/admission-lock.pg.test.ts`
  runs account finalization against concurrent admission in both orders for the
  session, SDK-principal and device-enrollment (host create) paths, and forces a
  real `P2003` at an admission insert.

Coverage is fake-adapter evidence. What it does not prove:

| Claim                                           | Evidence                                                                                                                                                                   | Outstanding                                                                                                                                                                                                                                  |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SDK → `/v1` → DB → outbox → relay contract      | real code, real PostgreSQL                                                                                                                                                 | none                                                                                                                                                                                                                                         |
| Host journal/reconcile at every matrix row      | real daemon code, `FakeRuntime`: restart receipt state and error code, VM count for creates, command effects counted in the runtime, no re-entry on a redelivered dispatch | receipt result payloads, progress ordering, the operation's terminal state on the daemon side (TypeScript only), command effects above 1, and agreement between the TypeScript double's behaviour and the daemon beyond those fixture fields |
| One process: real server ↔ real `wssp host run` | `pnpm test:cancel-wire` (cancel, PTY, readiness legs only)                                                                                                                 | the full lifecycle over the real binary                                                                                                                                                                                                      |
| Incus KVM VMs, guest files, PTYs, egress        | none here                                                                                                                                                                  | hardware qualification                                                                                                                                                                                                                       |

## Live sharing re-check regressions

`packages/api/src/sandbox/sharing-access.pg.test.ts` forces terminal
revalidation to discover an obsolete attribution, then lets the access scanner
commit a fitting alternate before terminal reconciliation acquires its locks.
The resulting `RelayFenceRejected` is a stale discovery, not proof of access
loss. Terminal revalidation repeats all authority checks, at most twice; the
paired session-deletion case still refuses. Unexpected errors and sustained
churn still fail closed. This proves a concrete race behind the possible
one-path-removal closure; it does not establish which event caused the single
live failure.

The reported 120-second command/reset remains unconfirmed in this source tree.
The client and supervisor's 120-second command settings are defaults for an
omitted timeout. Explicit positive deadlines and zero already travel unchanged
through acceptance, persistence, dispatch and the runtime. The expanded
`process-send.pg.test.ts` matrix includes 300,000 ms, and its typed UNKNOWN
result test checks subsequent heartbeat handling and preservation of terminal
bindings. `d20_positive_shim_clock_fires_at_execution_deadline` crosses 240
logical seconds with 300,000 and 1,800,000 ms deadlines, then proves timeout at
the requested bound through both runtime entry points. Existing timerless and
daemon-wire tests cover zero, authority cancellation and heartbeat/ping progress.
These tests use disposable PostgreSQL, FakeRuntime and executable shims only.

The daemon's connection-loss warning is logged after relay-session teardown,
which revokes active operation authority and can log UNKNOWN first. Those two
log timestamps alone do not establish that UNKNOWN caused the socket reset.
Identifying the live reset still needs the matching server/proxy close evidence
and the running daemon's build identity; no live binary or service was inspected.

## Rust DNS lifetime tests

Simulated public egress fixtures use `128.66.0.0/24`, `128.66.1.0/24` and
`128.66.2.0/24` instead of TEST-NET-1/2/3, which the guest firewall protects.
These three prefixes are outside the protected set and were unannounced in
[RIPE RIS](https://stat.ripe.net/data/prefix-overview/data.json?resource=128.66.0.0%2F24)
on 2026-10-26. They are synthetic data for fake transports and executable
shims: tests never send traffic to them. They are not reserved documentation
space, and an absent route is not a permanent routing guarantee; do not use
them for live network tests or production examples. Tests of protected
TEST-NET destinations keep the real TEST-NET values.

Persisted DNS grants and expiry leases use UNIX seconds so deadlines survive
daemon restarts. `IncusClient::dns_clock` supplies those timestamps to wire and
system resolution, refresh completion, the scheduler, initial publication,
and lease recovery/watchers. Production uses `RealDnsClock`; host IO,
resolver budgets, cancellation and lock deadlines retain real `Instant` time.

The opt-in `DnsTestClock` in `incus/shim_tests.rs` shares logical lifetime time
with cloned clients and the executable shim. `advance(seconds)` moves that
clock without waiting for a TTL. Watcher tests notify the existing lease loop
with `debug_wake_dns_lease_owner` while polling their ordering condition, so
an advance racing a condition-variable wait cannot strand the test. With
this clock installed, the
`slow-acl-ops`, `slow-acl-removals`, `slow-acl-grant-removals` and
`slow-publish` pins advance logical time for completed work. The grant-only
removal pin excludes preventive-fence releases during setup. Command stalls still use real waits. `LogicalDnsTransport`
advances the same clock before scripted DNS answers, allowing exact
answer-time, publication-time and completion-time TTL assertions.

The earliest-mutation-deadline test uses a TTL-floor answer and 29 seconds
of logical lookup latency, leaving one real second for the production
subprocess deadline. Its command still stalls for 90 seconds unless that
deadline interrupts it; a bounded completion assertion catches a later
sibling deadline even if the independent expiry watcher fences correctly.

The `queue` mode of `defer-acl-rule-remove` and
`defer-acl-allow-add-fail` records accepted daemon requests for explicit
replay. The fence-epoch retirement test stops autonomous repair before
replaying the old removal followed by the late allow, and checks the durable
consumed-epoch floor at marker retirement and the actual newly issued fence
tags. The revocation-only leg refuses lease-fence additions in the shim so it
must exercise the refresh allocator. Its ordering proof does not depend on a
wall-clock landing window. Many other DNS race tests still use real
lease waits; converting those requires preserving their individual barrier
and cancellation assertions.

## Rust mutation checks and stale builds

Cargo decides whether a crate is fresh from file modification times. Restoring
a mutated Rust file with `cp -p` (or any copy that keeps the old mtime) can
leave the mutant's build in `target/`, so the "restored" run still tests the
mutant. After restoring a file:

1. `touch` the restored file so its mtime is newer than the last build.
2. Rebuild and rerun the test (`cargo test -p <crate> ... <selector>`).
3. Compare `sha256sum` of the restored file with the copy taken before the
   mutation, and record both hashes with the run.

## Local stacks (`pnpm dev:docker`)

`pnpm dev:docker <port>` boots an isolated, ephemeral stack from
`docker-compose.agent.yml` (Docker or rootless Podman). Every published port
binds to `BIND_ADDR`, which defaults to `127.0.0.1`. `.agent-ports.json`
records the URLs, and `pnpm dev:docker:down <port>` wipes the stack.

- **Dev profile** (default): hot-reloading `pnpm dev:raw` on
  `http://localhost:<port>`.
- **Prod profile** (`--prod`): the real `Dockerfile` and `Dockerfile.worker`
  images with `NODE_ENV=production`. Production requires an https
  `BETTER_AUTH_URL`, so the profile adds `tls-proxy`, a Caddy reverse proxy
  with a **self-signed** certificate for `localhost`. Caddy's internal CA is
  created fresh in that container on every run. The URLs are:
  - Browser: `https://localhost:<port + 6100>`. This is the auth origin, and
    `.agent-ports.json` lists it as `url`. Expect a certificate warning: accept
    it in the browser, or use `curl -k`. Sign-in does not work over the plain
    http port.
  - CLI: use the canonical `https://localhost:<port + 6100>` origin with
    `--ca-file <Caddy-root.crt>`; see the [hosts recipe](./guide/hosts.md#local-production-profile-stack).
    `.agent-ports.json` lists this same HTTPS origin as `cliUrl`.
    Changing the origin fails journal-key binding for environment-bearing work.
  - Mailpit: `http://localhost:<port + 5000>` (`mailpit`).

  Example: `pnpm dev:docker 3200 --prod` serves the browser on
  `https://localhost:9300`; daemons use that same origin with the Caddy root CA.

The TLS front exists only in this local profile. A real deployment terminates
TLS at its own proxy (see `docs/operations/deployment.md`), and the production
https guard in `packages/env` is unchanged.

### Rootless Podman dev profile

Start the supported wrapper with its Podman-only option:

```sh
CONTAINER_RUNTIME=podman pnpm dev:docker 3200 --rootless-podman
pnpm dev:docker:logs 3200
```

Install `podman-compose` first. The wrapper selects `podman-compose --in-pod false`
and adds `docker-compose.podman-rootless.yml`, giving source-mounted `app-dev`
`userns_mode: keep-id` so its `HOST_UID:HOST_GID` process can write the checkout
and dependency mounts. Separate containers let that namespace setting take
effect. The wrapper still prepares the project, ports and volume paths and saves
the option in `.agent-ports.json`; logs/down reuse it automatically. Use
`CONTAINER_RUNTIME=podman` on later commands too if Docker is also installed.
The option is inert when Docker is selected. No override is applied to Docker.

The dev web port proxies `/v1` for SDK requests and `/ws` (including
`/ws/sandbox-host`) for host relay WebSockets, alongside `/api`, `/rpc` and
`/sw`. Health/readiness endpoints and `/robots.txt`, `/sitemap.xml` and
`/llms.txt` also forward to the server. The SDK and node daemon can use the dev
profile's published web port.

## Relay chaos

Three layers, from cheapest to real VMs:

- **PR subset**: `pnpm test:relay-chaos` (in `pnpm verify` and `pr-checks.yml`).
  The PR cells of `apps/server/src/sandbox-relay/relay-chaos-matrix.ts` over
  the loopback fault proxy and FakeRuntime.
- **Full matrix, nightly**: `pnpm test:relay-chaos:full` runs every cell. The
  `relay-chaos-full` job in `.github/workflows/nightly-tooling.yml` shards it
  by test file (`--shard=<i>/2`) and seeds it: `RELAY_CHAOS_SEED` (and
  `--sequence.seed`) is the workflow run id, or the `relay_chaos_seed`
  dispatch input for a replay. Locally:
  `RELAY_CHAOS_SEED=<seed> pnpm test:relay-chaos:full --sequence.seed=<seed>`.
- **Live, opt-in**: `RELAY_CHAOS_LIVE=1 pnpm test:relay-chaos:live`
  (`scripts/relay-chaos-live.ts`). Real Incus VMs (at most two per run) on a
  dedicated daemon. It is never run by CI or by `verify`. Its guards, cleanup
  accounting and front door are unit tested in `pnpm test:setup`
  (`scripts/lib/relay-chaos-live.test.ts`,
  `scripts/lib/relay-chaos-front-door.test.ts`).

### Live cells

| Cell | Fault                                                                                                                            | Pass condition                                                                                                                                                                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L1   | The server is unreachable from the daemon for 90 s mid-command: live relay links are frozen half-open and new ones get no answer | the command SUCCEEDS with byte-exact stdout and no gap                                                                                                                                                                                          |
| L2   | Two relay resets while a create is in Intent (VM create, or an image fetch when the template image is not on the host yet)       | the sandbox reaches READY and runs a command                                                                                                                                                                                                    |
| L3   | `wssp host daemon quiesce --pid` on the dedicated unit with a running command; a new command is submitted while it quiesces      | the running command's stdout is intact, the new command is held and then runs on the respawned daemon                                                                                                                                           |
| L4   | Terminal reattach after a relay reset                                                                                            | **Manual.** The SDK has no terminal client (terminals are a browser-session feature), so the script skips it: open a terminal on a sandbox of the test host in the dashboard, reset the relay, and check that it reattaches with the PTY intact |

L1 and L3 share one sandbox, kept across L2; L2's create is the run's second
and last VM, so at most two VMs exist at once.
`WSSP_CHAOS_CELLS=L1,L3` selects cells; `WSSP_CHAOS_OUTAGE_MS` changes L1's
outage (default 90000). No cell restarts Docker or a production service.

### What the run touches, and what it refuses

The script starts its daemon as a transient **user** unit, `wssp-chaos-<run>`,
with `systemd-run --user` (no sudo), its own data and config dirs under
`~/.local/share/wssp-chaos/<run>/`, its own Incus project (`wssp-chaos`) and
its own enrolled test host. Before it starts anything it refuses when:

- the run directory overlaps a `wssp-host` data or config dir: the defaults
  `~/.local/share/wssp` and `~/.config/wssp`, `WSSP_DATA_DIR`/`WSSP_CONFIG_DIR`
  in the unit's `Environment=` or `ExecStart`, or a journal directory the
  running `wssp-host` process holds open (`/proc/<pid>/fd`);
- `wssp-host`'s `WorkingDirectory` is inside the run directory, or its
  `ExecStart` names it;
- the test host id is served by `wssp-host` (its `--host-id`, a relay journal
  it holds open, or `relay/<SHA-256 of the id>` in one of its data dirs), or
  the host already reads CONNECTED;
- the Incus project is `wssp`, `default` or `wssp-host`'s project;
- the unit or the run directory already exists.

Cleanup always runs: SDK destroy of every sandbox carrying the run label
(metadata `wssp_chaos_run=<run>`), `systemctl --user stop wssp-chaos-<run>`,
then a read-only `incus list --project wssp-chaos wssp-sbx-`. A run VM still
listed, a new VM missing from the pre-run baseline, a failed destroy or a
check that could not be made exits 1.

### Prerequisites

The front door. The script listens on the server's **canonical origin** and
forwards plain HTTP to the server; only the relay WebSocket passes through the
fault proxy. The daemon therefore dials the canonical origin, and its
journal-key binding matches (every non-cleanup operation is keyed; see
[hosts](./guide/hosts.md#enroll)). So the target server must:

- have `BETTER_AUTH_URL` set to `WSSP_CHAOS_API_URL`, a loopback `http://`
  origin with a port nothing listens on, for example `http://127.0.0.1:4310`;
- itself listen on `WSSP_CHAOS_UPSTREAM_URL`, for example
  `http://127.0.0.1:4300` (`SERVER_PORT=4300`);
- as a safe default, be the only server process on its database.

The TLS production-profile stack (`https://localhost:<port + 6100>`) cannot be
fronted this way: its canonical origin is Caddy's TLS port.

**Enroll the dedicated test host once.** Use directories that are not
`wssp-host`'s, so the production credential is never touched:

```sh
export WSSP_CONFIG_DIR=$HOME/.local/share/wssp-chaos-enroll/config
export WSSP_DATA_DIR=$HOME/.local/share/wssp-chaos-enroll/data
wssp host enroll --slug chaos-01 --server http://127.0.0.1:4310   # approve in the dashboard
wssp host logout                                                  # the device credential is not used
unset WSSP_CONFIG_DIR WSSP_DATA_DIR
```

Approving the new slug creates the host. Then, in the dashboard:

1. **Host credentials**: mint a `wssp_host_…` token for `chaos-01` and note
   the host id. The device credential from the login can be revoked. The script
   connects with the token (`--host-token-env WSSP_CHAOS_HOST_TOKEN`) because
   a device credential is bound to the origin it was issued for.
2. Make a template revision available on `chaos-01`
   ([templates](./operations/templates.md)). For L2 to cover an image fetch,
   the image must not already be on the host.
3. **SDK keys**: mint a `wssp_sdk_…` key with `hosts:read`, `sandboxes:read`,
   `sandboxes:create`, `sandboxes:manage`, `sandboxes:destroy`, `commands:execute`, `commands:read` and
   `operations:read`, for all owned resources or for `chaos-01` and that
   revision.

The host needs a healthy egress guard for the user that runs the script, as
for any host ([hosts](./guide/hosts.md#egress-guard)). Prefer a host that does
not run `wssp-host`.

### Running it

Set these variables (the script reads values only to use them, never prints
them, and passes the token to the unit by name):

| Variable                                                                | Value                                                                      |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `RELAY_CHAOS_LIVE`                                                      | `1`                                                                        |
| `WSSP_CHAOS_API_URL`                                                    | the server's canonical origin (`BETTER_AUTH_URL`)                          |
| `WSSP_CHAOS_UPSTREAM_URL`                                               | where the server listens                                                   |
| `WSSP_CHAOS_SDK_KEY`                                                    | the `wssp_sdk_…` key                                                       |
| `WSSP_CHAOS_HOST_ID`                                                    | the test host id                                                           |
| `WSSP_CHAOS_HOST_TOKEN`                                                 | the `wssp_host_…` token of that host                                       |
| `WSSP_CHAOS_TEMPLATE`                                                   | a template selector (`slug:tag`, `revision/<id>`)                          |
| `WSSP_CHAOS_WSSP_BIN`                                                   | optional; absolute path of the `wssp` binary (default `~/.local/bin/wssp`) |
| `WSSP_CHAOS_RUN_ID`, `WSSP_CHAOS_DATA_ROOT`, `WSSP_CHAOS_INCUS_PROJECT` | optional overrides                                                         |
| `WSSP_TEST_RELAY_TIMING`                                                | optional; passed to the unit, read only by debug builds                    |

`systemctl --user show wssp-chaos-<run>` lists the unit's environment,
token included, to your own user while the unit exists. Exit codes: 0 every
cell passed and cleanup is verified, 1 a cell failed or cleanup is not clean,
2 configuration refused, 3 a guard refused.

## Offload live check

`OFFLOAD_LIVE=1 pnpm test:offload:live` (`scripts/offload-live.ts`) is opt-in
and never runs in CI or `pnpm verify`. It needs real Incus VMs on two
dedicated chaos daemons on this machine (hosts A and B, each its own
`wssp-chaos-*` user unit and Incus project), the local server, and the local
gateway from `pnpm dev:s3`. Run the whole session under the chaos-stack lock.

| Variable                                                 | Value                                            |
| -------------------------------------------------------- | ------------------------------------------------ |
| `WSSP_OFFLOAD_API_URL`                                   | the loopback API origin                          |
| `WSSP_OFFLOAD_SDK_KEY`                                   | an all-owned `wssp_sdk_…` key                    |
| `WSSP_OFFLOAD_TEMPLATE`                                  | a template selector                              |
| `WSSP_OFFLOAD_HOST_A`, `WSSP_OFFLOAD_HOST_B`             | the two host ids                                 |
| `WSSP_OFFLOAD_HOST_A_TOKEN`, `WSSP_OFFLOAD_HOST_B_TOKEN` | their `wssp_host_…` tokens (drain)               |
| `WSSP_OFFLOAD_UNIT_A`, `WSSP_OFFLOAD_UNIT_B`             | the `wssp-chaos-*` units                         |
| `WSSP_OFFLOAD_PROJECT_A`, `WSSP_OFFLOAD_PROJECT_B`       | their Incus projects (never `default` or `wssp`) |

Cells: offload to `host_and_store`; drain `--offload` evicts, the start
restores on the other host with the marker, machine-id, SSH host keys and
pinned cloud-init id intact and sudo granted; a daemon SIGKILL mid-fetch
returns the sandbox to `OFFLOADED` and a retry restores it; a
`guestSudo=false` restore stays without sudo. Cleanup destroys the run's
sandboxes and lists both projects.

Two daemons on one Incus share the default image store and the global
network names, unlike separate machines. Offload aliases carry each host's
tag (`wssp-off-<hostTag>-<offloadId>`), so a daemon's startup sweep removes
only its own images. Bridge names (`wsn-<hash>`) derive from the sandbox id
alone, so a restore onto host B while host A still holds the sandbox's stale
VM collides on its network: keep the hosts' stale copies settled between
cells.

## Command duration

Test modules explicitly mock the internal `commandTimeoutZeroEnabled` constant
for both states; no environment toggle exists. Clients check
`limits.commandTimeoutZero` before requesting zero (no separate command timer).
`contracts.test.ts` covers public/oRPC/private-default validation and the tagged
resolver. SDK `fs-process.test.ts` covers every command form, bound helpers,
finite wait detach and pre-IO off-state refusal. Relay `process-send.pg.test.ts`
uses production config/key ACK admission and actual serialized socket frames,
canonical replay and command redispatch fences on disposable PostgreSQL.

Rust protocol, connect and journal tests distinguish absent/default from numeric
zero, including checksum/reopen/exact replay and changed-timer conflict.
FakeRuntime uses the explicit `with_force_command_timeout` fault knob; a
sleep-shaped command never injects timeout. Incus executable shims and the
runtime permit test clock cover optional execution deadlines and finite setup,
without live VMs or wall-clock waits of 120 seconds. The unfiltered nextest gate
includes the shim-only `incus_surface_cleanup` integration suite.

## FS/process real-guest acceptance (not yet run)

**Not yet run. Requires separate authorization to launch live Incus VMs.**
FakeRuntime, a test clock and Incus CLI shims do not establish moving-image or
real-kernel compatibility. Record evidence for each row when authorized:

1. On the default **images:ubuntu/26.04/cloud** guest, record the actual booted
   kernel, `python3 --version` and helper-start group-pidfd probe. Verify that
   Python version against both file/env helpers and signaling APIs.
2. Check actual Rust coreutils behavior for setsid/sh launch, stdin/EOF, real
   nonzero and signal exits, wrapper framing, metadata/mutation success/failure
   and typed errno mapping. Do not infer errno from diagnostic prose. Check
   the primary `GUEST_TERMINATE_SCRIPT` dependencies `/bin/kill`, `tr`, `sleep`.
3. Start a tracked command; detach; list from a second client; server-connect
   and tail from its committed cursor; send stdin, close stdin, observe a real
   nonzero exit. Repeat with explicit canonical kill. Detach alone must send
   neither EOF nor cancel. Exercise files list/stat/mkdir/rename/remove plus
   grant/session revocation and retention expiry.
4. Verify TERM/INT/HUP group delivery reaches the user child and descendants,
   including trapped signals that keep running, and preserves real exit status.
   Test canonical kill/cancel, timeout and teardown with final proof, and
   uncertain cleanup without a blind fallback or command retry.
5. Verify timerless command zero beyond 120 seconds using real elapsed time,
   finite setup timeout, lease shortening/expiry and host-authority revoke.
   Observer waits stay finite; key revocation alone does not kill accepted work.
6. On supported **24.04 GA / 6.8**, verify typed pre-effect non-kill refusal and
   canonical kill/cancel success. With HWE, verify the actual **booted ≥6.9**
   kernel and probe before testing approved-A delivery. Merely installing HWE
   is not proof. Preserve the separate Ubuntu 24.04 host-Incus guidance.

7. **Dashboard (not run):** against the real server on a **26.04** guest,
   refresh the files and tracked-process panels, open entry metadata and output,
   confirm a kill and observe the target command transition from accepted to
   cancelled/terminated or unknown. Verify TERM/INT/HUP controls and real group
   delivery. On **24.04 GA / 6.8**, verify the dashboard displays the typed
   unsupported-signal refusal and sends no automatic kill. Check capability
   refresh after host reconnect. Record browser, server and guest evidence.

See the [filesystem and command behavior](guide/sandboxes.md#filesystem-and-command-result-limits).
This checklist does not establish UNKNOWN/STOPPING lifecycle recovery or
booting-stop behavior; qualify those through their lifecycle tests.

## VM size substrate qualification

The same checked-in [policy cases](../crates/sandbox-protocol/fixtures/vm_size_cases.json)
run through TS and Rust codecs. They cover integer/overflow bounds, alignment,
wrong types, fractions, null, arrays, extra keys, independent omission and
revision defaults. The [wire cases](../crates/sandbox-protocol/fixtures/vm_size_wire_cases.json)
cover required size pairs/capacity and reject missing or unsupported versions.
The sole relay contract is 1.0 with its complete required capabilities. Unsized
fresh launches, malformed frames and unknown future versions fail closed.
The source guard in `packages/sandbox-contracts/src/relay-version.test.ts`
checks production consumers, including final sends and Rust WireCodes; encoders
require explicit session identity. Fixtures for unsupported versions prove
refusal, never a supported downgrade.

SDK regressions use `sandboxes.create` to exercise the mutation retry owner for
all three size refusals, asserting one fetch and the catalog kind. A separate
FAILED operation regression checks `vm_size_mismatch` reports `conflict`.

Focused commands from the repository root:

```sh
pnpm --filter @wssp/sandbox-contracts test
pnpm --filter server exec vitest run src/sandbox-relay/protocol.test.ts
cargo test -p sandbox-protocol --locked -j 4
pnpm test:pg
```

The real-PostgreSQL schema checks verify NOT NULL defaults, managed allocation
checks and host-report bounds, including reservations above a reduced budget.
`host-protocol-admission.pg.test.ts` and `process-send.pg.test.ts` exercise
current-epoch admission and actual sends with the complete protocol 1.0 peer.
The Rust live dispatch-handler regression also asserts that unnegotiated or
missing size fields leave no journal intent and invoke no runtime effect.
Migration fixtures seed representative revision, sandbox and placement rows,
apply committed SQL and assert immutable allocations plus every declared CHECK.
Run `pnpm db:check-migrations --base origin/main` and the real-PG runner harness
against disposable databases; mock proofs do not establish reservation races.

Required mutation proofs remove memory alignment, accept missing capacity,
or emit a frame under an unsupported session. Each mutation must fail an
assertion, not compilation, and is saved as a patch against the final commit
with its failing output. Restore and rerun sequentially, following the Rust
mtime precautions above. The unfiltered all-target Rust gate includes
`incus_surface_cleanup`, which uses a shim. Live Incus and `incus-surface`
execution are not required or authorized by these tests.

## VM allocation runtime qualification

`crates/sandbox-runtime/src/fake/vm_size_tests.rs` verifies allocation retention,
immutable retry/reconnect binding and refusal of forged invalid runtime input.
`incus/vm_size_shim_tests.rs` uses the executable daemon double with a test clock
to check exact nondefault init argv before first start, existing/running retry,
warm/cold reconnect and direct starts. Missing keys permit only their own
default dimension. Effective profile/image readbacks, alternate units, CPU
ranges, sibling/raw keys and foreign identity are covered. An initially
mismatched allocation keeps the existing disk and is refused before config, lease, network or
provisioning-record mutation. Existing-VM create and reconnect
refusals are possibly effective (`UnknownOutcome`), including identity and
allocation refusals before this attempt mutates anything. An earlier attempt
may already have started the VM; `vm_size_mismatch` alone never authorizes
releasing its live slot. Only a proven first 0→1 refused claim may fail and release. Profile/image preflight rejects sibling and
mismatched limits before allocation. Phased drift tests independently exercise
the locked adoption and running completion checks. Inherited limits reach local
inventory, which distinguishes invalid config, cleanup-only entries and transient
read failures. A protocol 1.0 session exercises sized create and reconnect
through ingress and the supervisor; missing required sizes are refused. Narrow local
inventory decoding and daemon `u64` parsing have pure tests in `resources.rs`;
malformed, missing, zero, overflow, error and bounded timeout daemon responses also run
through the CLI shim. Resource inspection needs no project provisioning.

The shared TS/Rust policy fixture tests establish allocation-validation
parity. Runtime-only tests do not establish DB lock, rollback or weighted reservation behavior.
Protocol 1.0 is the sole supported version; public size inputs and accepted
allocations are shared across API, SDK and daemon.

```sh
cargo test -p sandbox-runtime --lib --locked -j 4 vm_size
cargo nextest run -p wssp -p sandbox-runtime -p sandbox-protocol --all-targets --locked -j 4
```

The unfiltered nextest command includes the shim-based `incus_surface_cleanup`
suite. Compile the live `incus-surface` binary as part of all-target checks;
never execute it for these tests. These fixtures do not attest a live daemon's
canonical-string round-trip, available physical RAM or QEMU overhead.

## Server VM capacity qualification

`host-admission.pg.test.ts`, `vm-placement.pg.test.ts` and relay
`vm-capacity-admission.pg.test.ts` exercise the memory ledger on real PostgreSQL.
Their barriers observe actual lock waits, including a reserve that commits while
initialization waits in a separate `lockHostByEpoch` SELECT. Only after H returns
does the aggregate UPDATE obtain its fresh READ COMMITTED statement snapshot.
Startup uses this ordering before listener/outbox, even with relay disabled;
offline rows can then release capacity before their first admission.

The invariant is host `memoryReservedMiB` equal to the sum of immutable RAM on
attached, same-owner `liveSlotHeld` sandboxes. Reserve/release change count and
memory together under H, inside the sandbox CAS transaction. Tests cover mixed
sizes at the last MiB, overlapping pools, direct/pool and cold/create races,
shrink, duplicates, rollback and loud underflow/finalization inconsistency.
Pool SQL and locked admission must give exact size/full/unavailable errors.
A heartbeat committed by the H blocker proves the eligibility clock is sampled
after that lock, independent of transaction start or the application clock.
Existing placement/admission suites retain owner → K → H → S → O barriers.

Schedulable PG hosts use `seedLaunchHost` with valid memory-budget/CPU defaults;
explicit null overrides test absent required reports and refusal. The fenced Prisma
double and hand-built unit hosts carry those same fields and allocation defaults.
They remain unit tests, never evidence for DB concurrency. The cancel-wire
contract inserts its sandbox/operations directly and bypasses placement; its
host fixture therefore needs no admission-budget bypass. Protocol 1.0 and
complete current capacity evidence are required for ordinary host admission.

Mutation qualification must remove the separate H lock, mismatch a candidate
size stage, omit the size retry code, sample the clock before H, decrement outside
the hold CAS, or clamp underflow. Each must fail a test assertion, with its patch
and failing output retained externally. Shared checked-in TS/Rust VM-size
fixtures continue to enforce numeric/alignment parity. FakeRuntime and Incus
shims cover runtime lifecycle; no live VM is needed or launched.

## Host capacity/storage qualification

Hermetic capacity coverage uses TS/Rust shared-policy parity, strict relay protocol
fixtures, FakeRuntime/Incus shims, local journal-v5 recovery and disposable PG
races. Test RAM/vCPU/root lifetime separately: stop frees live holds only; missing
storage preserves root/guard charges, and only positive original-root/network
absence frees them. Include zero healthy cap/cold start, implicit sparse-root
non-ratchet, marker create conflicts/content failures, policy changes with live
pinned holds, final-250 race and metadata disclosure boundaries.

Dashboard tests cover label-only host edits, automatic enrollment commands,
resource-fit picker hints without a count denominator, vCPU/storage cards,
staleness/drain/overcommit, independent disk defaults/overrides and retained
allocation detail. Run locale parity for EN/es-MX and focused API projections.

Operator RAM calibration, guest Docker persistence and reversible storage
availability checks are described in the
[hosts guide](guide/hosts.md#capacity-and-storage-qualification). Record live
evidence separately from automated checks before production.

## Sharing schema foundation

`sharing-schema.pg.test.ts` exercises raw principal/CHECK failures, permission
witnesses, soft removal/re-add, rollback and both arrival orders for contribution
revocation versus insertion. `packages/db/src/schema-apply.pg.test.ts` applies
committed migrations to an empty database through the production runner,
proves repeat application leaves migration identities unchanged, and checks
the schema's CHECK constraints. Fixtures validate domain rows and invariants
without disabling triggers or constraint enforcement.

API `sharing-authority.pg.test.ts` covers independent use/contribute permission,
owned contribution sources, owner-only bounded roster projections, G-before-H
member writes, raw reverse-order refusal, and current-placement quota sums across
Share recreation and STOP. The account-deletion PG suite covers the new
`shared_pool_workloads` blocker before either deletion entry can change anything.
Raw row triggers use NOWAIT for earlier G acquisition: PostgreSQL locks their
source row before invoking them, so contention refuses and requires a retry
instead of waiting in reverse lock order. Normal services hold sorted G first.

Sharing discovery is gated on the lifecycle qualification described below.
The graph lifecycle and SDK pool-mode/authorizing-key binding are tested together. Pool deletion clears all future SDK pool
grants; creator-owned accepted work remains bound to the initial CREATE key.
Sharing lifecycle tests cover placement/relay dual-principal consumers, cap enforcement at admission,
access-loss scanning and fake-wire lifecycle qualification. Live hardware/network qualification remains separate. Host terminal tests cover proof/ticket
consumers of the additive terminal schema.

## Sharing lifecycle and scoped signup

`services/sharing.pg.test.ts` uses disposable PostgreSQL to exercise default BOTH
permissions, direct verified-email grants, digest-only invitations, explicit
bearer versus verified-target acceptance, concurrent acceptance and email-change
serialization, rotation/revocation/expiry, source-owned contribution, withdrawal,
soft re-add, ownHostsOnly, SMTP failure, and revoked/impersonated session gates.
Selected-key mint and raw permission lowering are tested in both G-lock arrival
orders. Retained reads/cleanup use the initial CREATE authorizingKeyId, across
future grant removal; a different selected key cannot inherit that authority.
The updated pool/replay suites retain same-owner admission and result fences.
Selected list cursors also bind the creating key ID; equivalent future grants on
another key do not confer history or cursor authority.

`auth/signup-policy.pg.test.ts` runs the real locked Better Auth adapter through
HTTP and direct API signup/mailbox verification. Closed signup needs both the
pending signup-capable invite token and its target email. Creation is unverified,
never consumes the invite or activates a Share, and records admin-only provenance.
Bad/missing/mismatched tokens share the normal response and password-hash cost.
Proof after rotation/revocation/expiry cannot restore invitation eligibility.
Existing server recipient/IP limiters remain in force; no token-validity endpoint
or early signup-gate refusal is added. Daily signup invitation issuance is bounded
at five per inviter; resend retains the original allowance-bearing row.

Tokens stay in the one-time response and in-memory mail/form path. Persist only
digests; mail failure leaves a pending invitation and an honest unsent result.
EN/es-MX mail covers permissions/caps, forwarding, operator/network trust and the
up-to-30-day disk/host-delete consequence. Loss/restore renderers are ready for
the post-commit scanner. The browser captures/removes fragments and requires explicit acceptance.
The sharing lifecycle tests below cover cross-owner placement, fitting attribution, periodic access
scans, STOP/grace/DESTROY and cold-start selection. The graph lifecycle suites alone do not
qualify foreign VM lifecycle, live network isolation, or host terminals.

## Sharing access and accounting

`sharing-access.pg.test.ts` covers every non-DELETED access state, a null-host
HOST_LOST pin, ERROR with held live resources, immutable grace deadlines,
cap-fitting attribution, ban-only STOP, restoration and never-issued automatic
KILL cancellation. It probes both G-lock arrival orders for restoration/loss,
healthy scans while User/G/H are locked, the 250-path conflict and membership
removal recovery, corrupt transport evidence, and host withdrawal before H.
Foreign reservation reconstruction and proof release remain creator-scoped at S
and host-owner-scoped at H; positive root proof is still required to free disk.
The scheduler unit tests cover its independent 15-second clock, coalescing,
shutdown and restart. Dispatch wakes do not call access scanning. Only the
process that starts the existing relay outbox processor starts this timer.

These are database and scheduler proofs. The separate A/B wire qualification is
below. Loss/restore notices send only after commit; failed SMTP is reported as
unconfirmed. Neither suite proves live VM/network behavior or host terminals.

## Sharing placement and image admission

`sharing-placement.pg.test.ts` creates a foreign placement through the production
service and checks its creator, transport, attribution, retained-root and grace
records. Independent selected SDK keys with no foreign host grant contend for
one share's last RAM/vCPU/disk unit. Candidate and cold admission enforce the
same contributed-member percentages, including disabled-member cold restart.
Both revoke/placement orders observe G waits; revoke-first leaves no rows or
holds, and placement-first retains its holds while immediately denying guest IO.
A reused SDK authorization context cannot retain an exemption after disablement.

Pool-context exact-image registration works for a creator with no owned host.
Only the public fingerprint/architecture reaches the verifier; private defaults
stay in the creator's revision. Permission loss during verifier IO cannot store
availability or a logical template. Current epoch, member and owner checks run
again under User/K/G/H before persistence. Verification is budgeted and pending
work is bounded per creator and host. Availability census now walks registered
revisions across creators on its authenticated transport host.

Creation accepts `expectedDisconnectGraceSeconds`; a decrease refuses before
acceptance and an increase improves the pinned promise. Cold placement keeps the
maximum previous/current promise. Owned-host cold fallback clears current pool
charges under G/H/S while preserving immutable placement origin. Foreign storage
and connection metadata are redacted before creator-facing serialization.

This is admission/database evidence. Transport/workload bindings are carried in
relay dispatch/replies/config ACK, private-config/HMAC and the daemon journal. The A/B
qualification below exercises these together before shared discovery is exposed.
No terminal, live VM, network or integrated deployment qualification is claimed.

## Sharing lifecycle qualification and creator fairness

The cases in `apps/server/src/sandbox-relay/lifecycle-conformance.pg.test.ts`
run two genuine owners through the real SDK, `/v1`, disposable PostgreSQL,
outbox processor and relay manager. A owns the host; B uses A's shared pool or
owns a pool to which A contributes. B's selected key has no foreign host grant.
Both arrangements cover discovery, private-config ACK, create, commands, binary
files, stop, host reconnect/census, cold/warm start and destroy. Positive wire
proofs release all host live/root holds. Access loss refuses IO before scanning,
then wire STOP retains disk; restoration preserves that disk, and a repeated
loss destroys only after its fixed injected-clock grace deadline. Withdrawal and
explicit re-contribution have their own retained-disk cycle.

The same suite compares 28 native foreign-resource responses with absent IDs,
checks admin metadata allowlists, and refuses command/output/file/process work
under both impersonated and durably revoked sessions without issuing effects.
Custody grants no guest terminal ticket. A new ALL_OWNED key may operate on its
creator's retained foreign placement; a different selected key cannot inherit
the initial CREATE key's history authority. These are fake-host control-plane
proofs; the Rust lifecycle fault suite separately drives the real daemon over
FakeRuntime. This does not prove the entire lifecycle between a real server and
real daemon binary, live network isolation, Incus VMs or host terminals.

`services/sharing.pg.test.ts` qualifies shared/usable read projections,
contribute-only views, SDK pool selection and the owned-host intersection,
keyset pagination, strict native/SDK DTOs, and grant/withdrawal/source-ban barriers
including writes without authority hints. Shared read helpers are separate from
owner-only mutation lookups. Use grantees receive opaque member IDs; contributors
receive only their own memberships; shared pool views contain their own caps and
usage, with decimal strings preserving aggregate precision.

Rust journal, supervisor and staging tests flood one creator across sandboxes.
Ordinary retained receipts cap at 4095 of 4096, queued jobs at 15 of 16, and
active commands at configured capacity minus one (capacity one has no parallel
fairness guarantee). Staging charges declared bytes and three of four slots per
verified creator, through the last reader across threads. Uncertain receipts
are retained; stop/kill/recovery lanes remain independently available. Updated
global-capacity fixtures use multiple creators. No live Incus action is needed.

## Local host terminals and hot policy

The strict typed target codecs are active on both relay peers. The shared
`control_terminal.json` fixtures cover host/guest control and binary parity;
flat, mixed and missing targets are refused. Daemon slot tests reserve two host
slots and two host opens/minute, cap guests at six and each journal-verified
creator at three slots/14 opens, and retain uncertain reaps until proof.

`host_policy.rs` tests default off/required, startup overrides, repeated off,
manual edits, parse/read failures, and the explicit-enable latch. Terminal pump
fixtures inject the host opener over FakeRuntime: hot off under input flood,
pending-open cancellation, stale optional grants after a required revision,
guest survival and monotonic host idle/lifetime expiry. The real connect-loop
wire test persists an online raise into an isolated temporary config before
reporting it, and ignores old epochs. CLI black-box tests inspect atomic 0600
persistence and the new local setters. No real host shell or Incus VM is started
by these relay fixtures. Host environment tests use NSS effective-UID identity,
fixed environment builders, credential-prefix refusal and home fallback. Existing
Incus executable-shim PTY tests exercise the shared controller/group reaper.

Server policy tests cover authenticated current-socket/epoch/sequence/revision,
local lowering, offline/foreign refusal, timeout, disconnect and no queued raise
on reconnect. Local policy tests make no database state or PG concurrency claim. The existing
42-case disposable-PG lifecycle suite covers the typed guest terminal leg and
cross-owner sharing regressions. Separate tests cover durable host proof/tickets,
foreign guest terminal grants, router exposure and dual-owner revocation.

The approved MIT dependencies are nix 0.28.0 (`user` safe NSS lookup) and direct
`@better-auth/utils` 0.4.2, matching Better Auth 1.7.7's resolved OTP module.
`terminal-dependencies.test.ts` checks exact resolution, RFC 4226 HOTP vectors and
public Better Auth crypto exports. It does not establish auth-hook behavior.

## Host proof, tickets and revocation

`packages/auth/src/two-factor-flow.pg.test.ts` exercises real Better Auth HTTP
and direct API enrollment/challenge, stale cached-cookie refusal on both oracle
routes, unresolved secure/chunked/empty cookies, verified-factor URI refusal,
shared watermarks and after-hook failure removing success cookies/tokens and the
new session. `terminal-hooks.test.ts` checks independent resolver disagreement
and IO failure; `terminal-proof.test.ts` checks plugin counters and equal-code
adjacent steps. The dependency parity test still resolves the exact plugin OTP
export and public crypto functions.

`packages/api/src/sandbox/host-terminal-tickets.pg.test.ts` covers separate
one-use digest stores, required/optional tuples, first/changed/absent observation,
unchanged counters, replay/concurrent mints, durable locks and budget refusal,
calculation-to-mint factor/session/host/policy races, User NO KEY UPDATE writer
serialization and the post-H User FK KEY SHARE case. It runs the registered
router's impersonation/revoked/foreign/offline refusal cases. Budgets are mocked
there; `terminal-budgets.test.ts` verifies day-before-minute charging, cross-host
actor keys, shared generic mint limits and fail-closed configuration.
The guest ticket PG suite covers nullable transport evidence, malformed-ticket
burn and epoch supersession. Disposable databases use the production migration runner.

Relay tests cover path-first host/guest consumers, relabeled/opposite-kind
refusal, cookie/Origin/plane checks, policy and epoch grants, OR scope matching,
host repair before guest census and both target kinds. Real PG revocation uses
actual Better Auth sign-out/session deletion. The A/B lifecycle test creates the
foreign guest through SDK admission, opens a durably authorized guest PTY over
the fake host wire, denies its host owner and closes it on host credential revoke.
The wire double's peer disconnect is explicit; real process reaping remains the
Rust/cancel-wire contract, not a claim from that fake peer.

The host UI and EN/es-MX error presentation have separate DOM tests.
Live Incus/operator qualification requires its own authorized window. These tests launch no live VM and do not prove physical
isolation from host administrators.

Session-specific delete hints carry session IDs when bounded; owner/global fallback
remains conservative. A real sign-out test closes both host and guest bindings
of that session while another session stays authorized. Host service PG injects
a pending-deletion rollback and verifies no committed lifecycle hint or tombstone,
with the in-flight authority hold released.

Host proof/ticket coverage includes registered live-owner gates, committed
session/host hints, kind-specific consumption, typed grants, relay lanes, real
auth/proof state, oracle guards, protocol parity and local-policy/online-raise
consumers. The A/B lifecycle supplies a genuine foreign placement. Ticket
transport fields add no User FK: they are nullable scalar evidence checked
against current Sandbox/Host identity, never new routing authority. Browser
host UI and translations have separate DOM coverage.

## UI and public consumer qualification

DOM tests cover owned/shared pool pages, BOTH default permissions, nullable caps,
operator/budget/grace consent, narrow shared metadata, independent immutable SDK
pool selection and exact-image member choices. Sandbox creation submits the shown
grace quote and preserves it with the original intent on uncertain replay;
accepted grace and loss deadlines appear on detail, with an explicit restoration
notice only when the server clears a previously observed loss deadline. EN/es-MX locale and mailer
parity remain automated gates. Invitation fragments are captured before routing,
scrubbed, and held only in browser memory, with explicit account/mode acceptance.

Host detail tests drive the real shared panel/hook/client with fake xterm and
WebSocket: lazy explicit attach, enrollment/cooldown explanation, proof clearing,
optional mode, persisted-ACK raise, unconfirmed timeout and manual fresh-proof
retry after pre-upgrade refusal. Existing guest classification/paste/OSC/accessibility
regressions remain. Production build plus `pnpm check:lazy-xterm` checks splitting.

The UI-facing cases in services/sharing.pg.test.ts cover foreign revision discovery
without an owned host, contribute-only/withdrawn refusal, a withdrawal barrier
before final picker response, bounded host-owner allocation metadata without
creator identity, and roster identity/usage. They use disposable PostgreSQL only.
No live server, test node daemon or Incus VM is needed. The separately invoked
[operator checklist](operations/sharing-terminal-qualification.md) leaves deployment,
original-daemon retirement, hardware and A/B IPv4/IPv6 isolation unverified until
a separately authorized operator window.

## Startup census and atomic ACL qualification

The startup census pauses and joins DNS renewal passes, while autonomous DNS
expiry watchers and sandbox lease expiry remain active. Each Incus call, lock
wait and recovery settlement has its own bound; the complete census has no
fixed wall-clock ceiling. SIGTERM revokes its runtime scope. The relay regression
holds five simulated ACL writer locks for 31 seconds and completes registration;
expiry service tests prove renewal cancellation/resumption and lease expiry
while census renewal admission is paused.

The daemon-wide subnet lock covers the collision check and bridge creation.
An empty owned ACL is created before acquisition; rule installation, DNS
publication, readback, VM init and readiness run after release. Four-create
shim barriers prove both plain and egress provisioning overlap after allocation;
the FIFO regression holds one ACL while admitting another immediately.

Initial ACL installation and clean DNS policy changes use per-ACL FIFO-serialized,
conditional whole-ACL PUTs with stdin request bodies. A unique config revision
prevents an old ETag becoming current again after a later batched write. The
30-domain shim regression verifies one PUT for each clean publication/rotation,
complete allow/reject groups, drift refusal, bounded failed publication,
durable recovery and stale-write rejection. The ETag fixture checks Incus's
Go JSON field order, omitted strings, null slices, HTML escaping and newline.

Unresolved identity-specific mutations and fence obligations written by earlier
daemons retain their existing recovery boundary. The historical DNS mutation
fault suites explicitly select that recovery path through the test-only
`force_legacy_dns_recovery` seam; the atomic-policy tests use the production
default. A proven pre-request `query --header` parser refusal selects the
existing identity-specific writer on older supported CLIs; this decision is
cached rather than repeatedly probing. Atomic PUTs are exercised on the current
CLI. Neither test family uses a daemon or launches a VM. The allocation-lock
regression holds the real fixture lock for 61 seconds to prove admission exceeds
the former minute-long bound; its new ceiling is 600 seconds, matching image init.

`revision-availability.pg.test.ts` covers refused create timeouts and uncertain
creates, including already-expired stop leases: durable kill enqueue and result
commit are atomic, all holds remain until deletion/absence proof, and proof
releases both live resources and root reservations. SDK tests check that failed
operations expose their stable code in both `code` and `operationErrorCode`.

DNS performance regressions cover six DNS rotations across multiple
original TTLs: a verified whole-ACL replacement durably retires omitted lease
identities, so obsolete grants do not accumulate per-rule expiry work. Startup
requests a settlement handover before activating any watcher. Watchers still
pre-fence due destinations while yielding cleanup; recovery starts its own IO
budget after ownership arrives, with shutdown cancellation active throughout.
The handover test asserts ownership ordering and cancellation, and the command
admission regression proves fresh verification clears a transient reconciler
refusal while actual drift still refuses dispatch.

## Layered lease policy

The effective maximum lease is `min(deployment, host ceiling, pool max,
membership max)` over each sandbox's lease path. Coverage:

- **Parity:** `packages/api/src/sandbox/lease-policy.pg.test.ts` proves
  `effectiveLeaseLimit`, the SQL twin (`pathLimitSql`, `pathUnlimitedSql`,
  `leaseFitsSql`) and the lease-path join agree on real rows over deployment
  {unlimited, 24h} × host {unlimited, 6h, 24h} × pool {none, 6h, deleted} ×
  membership {none, 1h, removed, disabled} × unlimited-for-shares × own/foreign
  host × pool owner/grantee, under a non-UTC session.
- **Enforcement:** `lease-enforcement.pg.test.ts` covers pool create (lease
  stage, refusal maximum including the deployment, hidden hosts excluded), the
  direct host ceiling, the own-host origin path after sharing clears usage, renewal vs a pool lowering in both lock orders and replay.
  `services/sharing.pg.test.ts` covers who may set a membership limit,
  re-activation resets and omitted-means-unchanged.
- **Pull-in:** `apps/server/src/sandbox-relay/lease-pull-in.pg.test.ts` covers
  the warm re-arm pull-in and its revision order, the sweep keyed on the
  enforced deadline with the in-flight skip and retry under a non-UTC session, pull-in vs a user renewal and non-READY rows, concurrent pool,
  membership, renewal, reconnect, access and sweep writers, the unlimited
  lifecycle and the system dispatch path (with the predicate in
  `outbox.test.ts`).
- **Host ceiling:** `host-hello.pg.test.ts` (absent, null, finite; wake) and
  `host-lease-policy.pg.test.ts` (epoch, sequence, current link, write on
  change). Discovery with an allowlisted key: `sandbox-api/pools.pg.test.ts`.
- **Daemon and wire:** `crates/sandbox-protocol` (absolute bound, shared
  `lease-limits.json`, hello and report fixtures shared with
  `apps/server/src/sandbox-relay/protocol.test.ts`), FakeRuntime and Incus
  pre-phase tests, the journal ceiling (`journal/leases.rs`: stored leases
  only, both arrival orders, overflow-free), the supervisor's typed refusal,
  config/hot reload and the connect wire test.

## Capacity queue and placement ranking

- `packages/api/src/sandbox/placement.pg.test.ts`: dominant-share ranking
  (memory-, vCPU- and disk-dominant, ties), the own-hosts tier on/off with
  fallback, `skipped` hints over visible hosts only, `template_unavailable`
  and `template_image_missing`.
- `packages/api/src/sandbox/capacity-queue.pg.test.ts`: entry, refusal of
  direct and over-policy waits, last-slot races with and without waits, FIFO
  by G acquisition (barrier), placement pinning and lease-at-placement,
  replay across WAITING/PLACED/TIMED_OUT, timeout vs placement (barrier),
  destroy/stop/operation-cancel and their replays, cancel vs placer in both
  orders (barriers), head protection with the 8-bypass budget and strict
  mode, unlimited-lease pinning and `unavailable` blockers (no head), a head
  in another pool sharing the host, self-blocked share caps, deferred
  authority (share, key revoke, pool delete, ban, host/revision allowlists,
  scopes), lease lowering, drain/undrain, concurrent limit enforcement per
  key/owner/pool, and capacity-view disclosure.
- `packages/db/src/account-deletion.pg.test.ts` covers owner deletion with
  grantee wait rows in every state.
- Unit (hermetic): the head decision table and scheduler
  (`capacity-queue.test.ts`), post-commit wake delivery (`outbox.test.ts`,
  `capacity-queue-wake.test.ts`), limits (`capacity-limits.test.ts`), the
  dominant-share mirror (`capacity-view.test.ts`), and the SDK's slow polling
  of a waiting create (`packages/sdk/src/client.test.ts`).
- Security-review regressions in `capacity-queue.pg.test.ts`: 70 self-blocked
  entries never starve a fitting entry #71; a deadline passing while the placer
  waits on H (barrier) times out with no placement; retained roots make a host
  ineligible for the head; a strict head in a pool beyond the first 64 sharing
  the host still reserves it.

## CLI logins: selection, claims and lock order

Full lock order with CLI logins:
`User → K → owner placement → G → template → H → S → credential → instance (sorted id) → lease (sorted id) → binding → residue → O`.
The owner credential-count lock (`credentials/limits.ts`, a transaction-scoped
advisory lock) is taken first by every credential create and is a leaf before
any credential row lock. Account rows are locked only by pause, rename and
delete (`FOR UPDATE`, after the credential); claims never lock accounts and
re-evaluate the denormalized `accountPaused` in their conditional `UPDATE`.

Claims (`credentials/selection.ts`) process a multi-login request in sorted
`credentialId` order, read at most 8 candidates from a partial pick index without
locks, and claim each with one conditional `UPDATE`; a failed candidate holds no
lock, so a transaction holds at most one instance row per login. Terminal lease
transitions lock the lease and then decrement its instance (lease → instance),
which inverts the claim order but cannot cycle: every path that locks an
existing lease holds that lease's sandbox S first, and claims only insert leases.

`credentials/selection.pg.test.ts` covers §7.7 tests 1-4, 16, 19, 20 (create
half) and 21 with statement barriers; `packages/db/src/schema-apply.pg.test.ts`
covers the credential schema's CHECKs on a fresh apply. Run them with
`pnpm test:pg --filter=@wssp/api --filter=@wssp/db -- src/credentials/selection.pg.test.ts src/schema-apply.pg.test.ts`.

## Data-key epoch fence

`data_key_epoch` (one row) is taken after a writer's own domain locks and just
before it writes ciphertext. Writers take it `FOR SHARE`. The only `FOR UPDATE`
is `promoteDataKey`, which holds no other row lock (the admin action holds just
the admin governance locks first). Return-key rotation therefore runs
`credential_return_key_state FOR UPDATE → data_key_epoch FOR SHARE`, and a
capture commit runs `H → … → instance → data_key_epoch FOR SHARE`. The rewrap
holds the epoch `FOR SHARE` and takes ciphertext rows `FOR UPDATE SKIP LOCKED`,
so it never waits on a row lock. A switch waits for in-flight writers. A writer
that arrives during a switch waits for it and then seals under the new kid.

`crypto/data-key-epoch.pg.test.ts` covers §7.7 test 23 with statement barriers.
A writer parked after its `FOR SHARE` blocks the promote. A writer that arrives
during a promote blocks behind it. After the switch, a stale writer (vault
value, return key, webhook rotate, rewrap) aborts and writes nothing. Rewrap
drives every old-kid count to zero, and the counts stay zero. Run it with
`pnpm test:pg --filter=@wssp/api -- src/crypto/data-key-epoch.pg.test.ts`.
