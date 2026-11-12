<a href="https://github.com/FlyCockpit/ws-sandbox-proxy">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://shieldcn.dev/header/dots.svg?title=wssp+CLI&subtitle=Node+daemon+and+CLI+for+WS+Sandbox+Proxy&logo=rust&logoColor=brand&size=wide&theme=orange&mode=light&align=left">
    <img src="https://shieldcn.dev/header/dots.svg?title=wssp+CLI&subtitle=Node+daemon+and+CLI+for+WS+Sandbox+Proxy&logo=rust&logoColor=brand&size=wide&theme=orange&mode=dark&align=left" alt="wssp CLI">
  </picture>
</a>

<p align="center">
  <a href="Cargo.toml"><img alt="Rust 1.99+" src="https://shieldcn.dev/badge/rust-1.99+-ef7d00.svg?variant=secondary&mode=light&size=sm&logo=rust"></a>
  <a href="#license"><img alt="License" src="https://shieldcn.dev/badge/license-MIT-22c55e.svg?variant=secondary&mode=light&size=sm"></a>
</p>

Node daemon and CLI for [WS Sandbox Proxy](https://github.com/FlyCockpit/ws-sandbox-proxy).
It lives at `apps/cli`, outside the pnpm/Turborepo graph. The crate and binary
are both `wssp`.

```sh
wssp config path           # print the config file path
wssp config show           # print the effective config
wssp config init           # write a default config file if missing
wssp config --json show
wssp completions zsh       # shell completions
wssp login --slug desk-01 --server https://api.example.com
wssp connect              # use the saved device credential and assigned host
wssp logout               # remove device state and the configured token binding
wssp token login WSSP_HOST_TOKEN # env must already contain a dashboard host token
wssp connect --server https://api.example.com --host-id <host-id>
wssp connect --help        # outbound sandbox node daemon
wssp drain --json          # refuse new work; existing guests keep running
wssp undrain --json        # restore admission
```

Every command and flag is listed in the generated
[command reference](docs/cli-reference.md); operator steps (requirements,
enrollment, the service unit, upgrades, credential rotation, release notes)
are in the [hosts guide](../../docs/guide/hosts.md).

Release binaries for x86_64 and ARM64 Linux link musl statically and need no
glibc runtime. Static musl resolves users through `/etc/passwd`; it does not
load glibc NSS modules such as LDAP/SSSD. Provision the daemon's local account
and group entries on the host when your login directory uses those modules.

Configuration is stored in a TOML file. `wssp config path` prints the resolved
Linux path (`~/.config/wssp`). Logs go to stderr;
pass `-v`/`-vv` for more, `--quiet` for less, or set `WSSP_LOG`.

`wssp connect` holds an outbound WebSocket to the control plane and executes
dispatched sandbox operations. The CLI is Linux-only; the default runtime is Incus
(`--runtime fake` or `WSSP_RUNTIME=fake` for relay-only work without VMs).
The fake runtime refuses creates unless `WSSP_FAKE_ENFORCE_EGRESS=1` makes it
advertise egress enforcement it does not perform; with
`WSSP_FAKE_FAIL_CREATE_FILE=<path>`, new creates fail while that file exists.
Both are for local stacks only, and `connect` refuses to start Incus with
either set.
Device login prints a verification URI and code; it never opens a browser or
reads stdin. `--slug` is always required, even after `config set-slug`. The server
must be explicit or set with `config set-server`. HTTPS/WSS is required except
for localhost, 127.0.0.0/8 and ::1 development. Credential-bearing HTTP and
WebSocket requests never follow redirects.

Device login stores one `wssp_device_…` credential, with its issuing origin
(including port) and assigned host, outside config. It clears any previous token
binding. A dashboard `wssp_host_…` token instead comes from a variable whose name
matches `^WSSP_[A-Z0-9_]{1,64}$`; use `token login <ENV_VAR>` to configure it, or
`connect --host-token-env <ENV_VAR>` for an explicit override. Host tokens require
`--host-id`. An explicit env selection takes precedence and never silently falls
back on a missing or invalid token. Device credentials are long-lived until
revoked; `logout` always removes the local device credential and, best effort, the
env binding (a warning reports a config cleanup failure). It does not revoke the
server credential or unset the environment variable itself.

Config TOML uses snake_case; all `--json` command output uses camelCase. Device
secrets never appear in config or command output. Unix state uses 0700 directories
(every directory the daemon creates, ancestors included, whatever the umask), 0600
files, file fsync and directory fsync. `WSSP_DATA_DIR` overrides must provide
equivalent private permissions. Recognizable `.wssp-staging-*.tmp` and `.wssp-tombstone-*` files are swept under the state
lock at startup and before publication. Login generation intent survives restarts,
so stale logins cannot overwrite a newer selection. A config update failure after
credential publication leaves a usable, self-describing credential.

Polling uses the server's expiry capped at ten minutes, honors issuance interval,
`slow_down`, and `retryAfterSeconds` floors without an artificial delay cap, and
per-request connect/read/overall timeouts clipped to expiry.

### Private CA trust

`connect`, `login`, `drain`, and `undrain` accept `--ca-file <path>` (or
`WSSP_CA_FILE`). The PEM bundle adds certificates to the default webpki roots;
chain, expiry, and hostname verification remain required. Missing, unreadable,
empty, malformed, or certificate-free files fail closed. There is no insecure
mode. Precedence: flag, environment, then saved `ca_file` in TOML (`caFile` in
JSON output).

```sh
wssp login --slug desk-01 --server https://api.internal.example --ca-file /etc/wssp/root-ca.pem
wssp connect
# Save or clear a default explicitly (connect overrides are per-run):
wssp config set-ca-file /etc/wssp/root-ca.pem
wssp config clear-ca-file
```

Successful device login with `--ca-file` saves its absolute path with the server
URL, so a service restart retains trust. `WSSP_CA_FILE` is run-only, including
for login; it never replaces the saved default. Login without a CA flag retains
an existing saved path. Keep the file readable and restart after CA
rotation. Always dial the exact canonical origin, including its port. See the
[hosts guide](../../docs/guide/hosts.md#private-certificate-authorities) for the
local Caddy `pnpm dev:docker <port> --prod` recipe.

### Host capacity defaults and optional overrides

Bare `wssp connect` and the systemd ExecStart require no new flags. Incus
`/1.0/resources` supplies total RAM/threads; interim RAM budget subtracts
max(2048 MiB,25%), aligns down to 256 MiB, and caps at 16777216 MiB. Each live
VM pays guest RAM + 256 MiB; total vCPU defaults to threads × 2, per-VM CPU to
min(32,threads). FakeRuntime uses 4096 MiB/four threads/eight total vCPU.

`--sandbox-memory-mib`, `--sandbox-vcpu-budget` and `--max-sandbox-cpu-count`
override TOML independently, then detection fills omissions. Missing dimensions
name required overrides; high overrides warn. Budgets describe commitments, not
RSS, physical isolation or cross-daemon arbitration. Never advertise one daemon's
resources twice. Shrink keeps existing holds; new live holds must fit RAM/vCPU.

Storage lists are TOML-only; nonempty lists replace the profile-root pool:

```toml
sandbox_memory_mib = 95232
sandbox_vcpu_budget = 64
max_sandbox_cpu_count = 32

[[storage_pools]]
name = "default"
capacity_gib = 96
draining = false

[[storage_pools]]
name = "wssp-capacity-test"
capacity_gib = 64
draining = false
```

Recheck shared backing free space before using the 160-GiB example. Dir/lvm/zfs/
btrfs use Incus pool resources; no statfs fallback. Implicit caps freeze at
connect, bounded by persisted non-increasing P, 80%-total and free + trusted
charged-root physical usage − 5%-total headroom. Only explicit TOML can raise
caps. Connect retains project-owned `wssp-pool-marker` volume/file identity;
inspection never creates/repairs it. Native caches remain uncharged operational
headroom. Root size defaults to 32 GiB; retained commitment is size + 1 GiB.
Pool drain blocks new roots; stopped/UNKNOWN disks keep charges and identity.

`wssp config show --json` returns typed partial read-only inspection, sources,
cap inputs and scalar diagnostics without Incus. Restart/reconnect for config
changes. The journal pins historical live/root weights and implicit ceilings;
stop releases only live RAM/vCPU, deletion requires healthy original-root and
network absence. No defaults or reset may guess bindings for old roots.

Deploy matching schema/server/worker/CLI/SDK builds and preserve journals.
Resolve uncertain work through supported recovery before retiring host state.
See [capacity and storage qualification](../../docs/guide/hosts.md#capacity-and-storage-qualification)
and the [host guide](../../docs/guide/hosts.md#capacity-drain-and-deletion).
RAM calibration and Docker persistence need live operator evidence.

### Host prerequisites

A host that misses one of these connects but cannot run a sandbox. Full steps,
including Ubuntu 24.04, are in the [hosts guide](../../docs/guide/hosts.md#requirements).

- **Linux with KVM.** Sandboxes are Incus virtual machines only.
- **Incus 6.14 or newer** with the `network_acl` API extension. Releases before
  6.14 cannot reliably enforce the per-sandbox network ACLs (CVE-2025-52890),
  so the daemon advertises no egress enforcement, logs `egress enforcement
  unavailable; this host cannot create sandboxes: incus <version> is older
  than 6.14 …`, and the server refuses every create with
  `UNSUPPORTED_CAPABILITY`. Ubuntu 24.04's archive package is 6.0.0; use the
  [Zabbly](https://github.com/zabbly/incus) stable packages.
- **`br_netfilter` loaded and persisted, with
  `net.bridge.bridge-nf-call-ip6tables=1`.** Sandbox NICs use
  `security.ipv6_filtering`, which needs bridge netfilter. `wssp connect
  --runtime incus` refuses to start while `/proc/sys/net/bridge` is missing
  or `bridge-nf-call-ip6tables` is not `1`:

  ```sh
  sudo modprobe br_netfilter
  echo br_netfilter | sudo tee /etc/modules-load.d/wssp-br_netfilter.conf
  # only if the sysctl was turned off:
  sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1
  ```
- **One `wssp` daemon per Incus server.** `wssp connect --runtime incus`
  keeps a marker in Incus (profile `wssp-daemon-lease-<n>-<id>` in the `default`
  project, renewed every 15 s, live for 60 s) and refuses to start while
  another daemon's marker is live, naming that daemon. A running daemon is
  never replaced: one that later finds another live marker starts no VM of
  any kind (create, cold reconnect, restore) until it clears, like an
  unhealthy egress guard; running sandboxes, stop and destroy continue. The same daemon
  on the same machine (`/etc/machine-id`, host id, data directory) takes its
  marker back at once after a restart. A client without access to profiles
  in `default` starts with a warning. Stop pre-check daemons before
  upgrading. Other CLI commands never write a marker.
  `WSSP_TEST_SHARED_INCUS=1` is a test-only override for the local chaos
  stack, honoured only by debug builds with a loopback control plane. See the
  [hosts guide](../../docs/guide/hosts.md#one-daemon-per-incus-server).

### Exit Codes

| Code | Meaning                                                                           |
| ---- | --------------------------------------------------------------------------------- |
| 0    | success                                                                           |
| 1    | runtime error                                                                     |
| 2    | usage error                                                                       |
| 3    | not found                                                                         |
| 4    | host credential inactive (`4003` close, HTTP 401/403 on connect or drain/undrain) |
| 5    | relay internal error during revalidation (`1011` close; retry connect)            |

## Install After Release

The CLI and node daemon support Linux only. These commands work after the first public GitHub release (cut via the root
`Release` workflow — see [docs/releasing.md](docs/releasing.md)).

**Shell:**

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/FlyCockpit/ws-sandbox-proxy/releases/latest/download/wssp-installer.sh | sh
```

**From source:**

```sh
git clone https://github.com/FlyCockpit/ws-sandbox-proxy
cd ws-sandbox-proxy
cargo install --path apps/cli --bin wssp
```

## Development

Run cargo from the **repo root** so the workspace (`apps/cli`, `crates/*`)
builds together:

```sh
cargo build
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt
cargo run -p wssp -- config path
```

Before considering a change done, run the full local gate:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo xtask sync-docs --check
```

See [AGENTS.md](AGENTS.md) for CLI conventions and
[CONTRIBUTING.md](CONTRIBUTING.md) for the PR checklist. The repo-root
`AGENTS.md` applies on top.

## Guides

- [Command reference](docs/cli-reference.md) (generated from the clap definitions)
- [Hosts guide](../../docs/guide/hosts.md)
- [Error handling](docs/error-handling.md)
- [Releasing](docs/releasing.md)

## Project Layout

```text
src/
  lib.rs         shared implementation modules
  main.rs        entry: parse -> log -> dispatch -> exit code
  cli.rs         clap argument definitions
  commands/      one file per subcommand
  config.rs      TOML config load/save
  paths.rs       cross-platform config/data dirs
  logging.rs     tracing setup; logs go to stderr
  exit.rs        stable exit codes
  sandbox_relay/ outbound node daemon
tests/cli.rs     black-box CLI tests
xtask/           project automation: sync-docs
docs/            error handling and release notes
```

CLI CI and release workflows live at the repo root:
`.github/workflows/cli-ci.yml`, `.github/workflows/release-preflight.yml`, and
`.github/workflows/release.yml`.

## Agent Docs

`AGENTS.md` is the source of truth for CLI contributor and agent instructions.
`CLAUDE.md` and `.cursorrules` are generated mirrors. Edit `AGENTS.md`, then run:

```sh
cargo xtask sync-docs
```

Do not hand-edit generated mirrors.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT). Copyright (c) 2026 FlyCockpit LLC.

## Host state and reconnects

Build the CLI with Rust 1.99 or newer. Durable host connections require Unix
directory fsync; other platforms fail before opening a relay or running effects. `WSSP_INCUS_PROJECT` / `--incus-project`
defaults to `wssp`. The daemon auto-provisions that dedicated Incus project so
sandbox VMs stay isolated from other projects while sharing the `default`
project's profiles and image aliases (`features.profiles=false` and
`features.images=false`). Set `WSSP_INCUS_PROJECT=default` to use the default
project directly.

The daemon stores private receipts under `WSSP_DATA_DIR/relay/<host-id SHA-256>`
(or the platform data directory when unset). Keep this directory on durable,
local storage with working file locks, atomic rename, and fsync. A single
process holds the exclusive directory lock, including while background work
is shutting down. Do not remove receipts to retry an operation or run a host
identity with a second state directory. Losing the directory loses local
proof of execution; the server leaves previously dispatched work unknown.

On relay connections, the authenticated server installs a derived journal HMAC
key bound to the canonical server URL, owner and enrolled host. The daemon keeps
it only in memory and drops it on disconnect. It never enters this directory,
checkpoints, logs, runtime requests or guest environments. Env-bearing work
requires the matching key and the server's current-epoch ACK. After restart,
retained digests remain opaque until reinstall; offline expiry and the exact
`sandbox.kill` / `sandbox.stop` cleanup kinds continue without a key. A key
refusal with existing receipt history reports `UNKNOWN_OUTCOME` and retains
that history, regardless of the receipt's phase.

New keyed receipts keep separate host request and dispatch MACs and the opaque
server request MAC used for confirmation. These domains are never compared as
equal. Key IDs identify secret replacement without hashing an incoming body.
Restore the original server master secret to recover old keyed work; do not
reset the journal or retry with a new idempotency key.

The `private.config.install` / `private.config.ack` transport stores
bounded private configs in the locked journal's `private-configs` directory.
Those files contain plaintext env values: host storage and its backups belong
to the host operator's trust boundary. Directories are 0700 and files are 0600.
The local HMAC checksum has its own domain and explicit scheme/key ID; an ACK
echoes only the separate server binding. The daemon validates, atomically writes,
fsyncs the file and directory, and verifies retained bytes before ACK. A matching
memory-key reinstall is required after restart; a changed key ID refuses before
any checksum work. An install IO failure logs a constant refusal, sends no ACK,
and keeps the session and cleanup running. New configs become usable in memory
only after all durability fences succeed. Failed temp writes are unlinked on
drop (crash leftovers are swept on open). A failed new install after rename
unlinks the unpublished file best-effort; a failed reinstall retains accepted
config. Remaining files count toward the 4,096-file bound, each at most 96 KiB.

Logical `template` selectors resolve on the server to an exact revision and explicit
host. The server stores the boot in `sandbox_placement` and its private defaults
snapshot in `sandbox_execution_config`; neither replaces host journal evidence.
Fresh creates require current admission and exact revision/host availability.
Immediately before effect the daemon checks that exact cached fingerprint and
architecture. A missing image reports only its revision/artifact/connection
binding. Original-disk cold reconnect uses the retained boot configuration and
continues when the original image is no longer cached. See the
[SDK resource grants](../../docs/guide/auth-planes.md#minting-sdk-resource-grants).

Template defaults plus sandbox create `envs` are immutable private defaults for commands and terminals.
Commands override them in the shared command builder, which validates the final
union before effect. `HOME`, `SHELL` and `TERM` remain fixed guest identity fields.
Nonempty PTY defaults use a raw/no-echo READY/frame/restore/DONE handshake: browser
input stays gated, startup has a separate 30 s overall deadline, and the 5 s
handshake budget starts at parsed READY. Stop/revoke cancels pending setup;
uncertain cleanup keeps its terminal slot charged until reap proof. Empty maps
retain the original spawns.

Config GC requires proven destruction/absence, a covering cleanup watermark,
settled receipts and no active lifecycle worker. STOPPED, disconnect and unknown
effects retain config. Unconfirmed terminal receipts also retain their original
results and digest fences until exact server confirmation removes them. GC waits
for every env-covering receipt (including command-only env) to be confirmed or
already pruned, strips config MACs from lease checkpoints, then unlinks config
last and fsyncs its directory. A crash resumes this sequence without a key.
Existing pruned receipts retain safe identity/completion evidence and consume a
receipt slot; they never replay or accept a hash-based confirmation. Redispatch
and reconciliation report `receipt_digest_pruned` with UNKNOWN/held behavior.
An authenticated `receipt.pruned.ack` retires only the exact local tombstone,
fenced on the current epoch, server/owner/host, operation, sandbox, generation,
attempt, idempotency key and kind. The server keeps the outcome UNKNOWN and its
live hold retained. Relay reconciliation always carries the pruned-receipt
fence; old peers are refused and cannot bypass this accounting.
GC cannot remove plaintext-equivalent copies in operator backups;
the host key is never in them.

Each operation records durable intent before any guest effect. Receipts bind
server, owner, host, sandbox, generation, operation, idempotency key, and request
hash. The server identity is the canonical relay URL: scheme, lowercase host,
non-default port (default 80/443 ports are omitted), and path. URL queries and
fragments are excluded. DNS names and IP addresses remain distinct identities;
changing the endpoint or host identity requires the matching durable state.
Reconnect sends receipts one at a time after authenticated hello; the
server checks those bindings before accepting an old outcome on the new
connection. Work interrupted before a durable result becomes `UNKNOWN_OUTCOME`
and is never automatically re-executed. Unknown lifecycle work retains its
sandbox state and placement until a read-only host instance query establishes
its lifecycle outcome. Command and write uncertainty remains unknown. This
version does not adopt surviving guest
processes after a daemon restart.

The journal has 4,096 ordinary receipt slots plus 64 slots reserved for stop/kill.
At capacity it rejects the individual dispatch with `host_capacity`. Only an
exact-binding `receipt.confirmed` from the authenticated, fenced server can free
a terminal receipt; the server operation row remains the permanent idempotency
record. ACKs, age, and unknown outcomes never authorize deletion. At most 64 results retain
content (32 KiB each), for up to 24 hours. Expired content is explicitly marked
`outputExpired`; oversized content is marked `truncated`. File download bytes
are not journaled: they live in the server's transfer store once captured, so a
host recovery without the download window reports an unknown outcome. Corrupt receipts or failed durable writes
fail closed. Relay protocol v10 requires both peers to be upgraded together:
upgrade the server first, because an older server refuses a newer daemon's hello.

Incus operations use bounded background queues. Heartbeats and cancellation
admission continue on the socket reader; a separate bounded worker handles
Incus cancellation and stdin, with an independent stop/kill worker. Stop/kill
revokes ordinary work permits for that sandbox. Ordinary queue/upload saturation
returns `host_capacity`; control-channel overflow closes the connection and
preserves receipts for recovery. Runtime implementations themselves are effect adapters;
the host receipt journal owns cross-restart idempotency.

### Drain and undrain

`wssp drain` sets the durable server admission flag; `wssp undrain` clears it.
Both use the same saved device credential or `--server`, `--host-id`, and
`--host-token-env` selection as connect. They do not start a runtime or stop guests.
They print the committed flag, live sandbox count and `drained`; `--json` prints
`{id, draining, liveSandboxCount, drained}`. They return immediately, with no wait
for zero guests and no deadline. Run drain again to refresh the count.

The count includes pending and uncertain live reservations. Drained means exactly
zero; deletion may still be blocked by retained disks or unfinished work.
Admission of creates, STOPPED resumes and templates returns `sandbox.host_draining`;
existing guest work and warm attachment continue. Daemon `schedulable` is advisory.
See [the host drain contract](../../docs/design/adr-003-host-enrollment.md#host-drain).

Drain exit codes: 0 success; 1 transport/parse/conflict or other runtime failure;
2 usage; 3 missing/foreign host; 4 inactive credential (HTTP 401/403); 5 throttled
or server unavailable (HTTP 429/5xx). No redirect or automatic retry is followed;
HTTP is accepted only on explicit loopback development origins.

Command stdout/stderr uses binary relay v10 frames while the command runs. Both
streams share one sequence and byte offset. The host keeps the first 256 KiB
and rolling final 768 KiB; an evicted interval is reported as `[gapStart, offset)`.
At most four 8 KiB chunks await a cumulative `command.output.ack` (matching
operation, generation, attempt, sequence and ending byte offset). Retries reuse
identical frames; duplicate ACKs grant no extra capacity. The socket loop sends
at most four output frames per turn and never waits for an output ACK.

Final command controls contain only `exitCode`, `pid` and `outputBytes`; no
command bytes enter JSON results or the receipt journal. After process completion,
output has a one-second delivery grace, then the terminal control's `outputBytes`
watermark exposes any trailing gap. For UNKNOWN outcomes it is only the observed
byte watermark, not proof that the guest has finished. Pipe draining and process cancellation do not
wait for that grace. An uncertain cancellation observation has no completion
watermark; the completion owner may still publish later bytes and a final outcome.

The server stores accepted chunks durably (first 256 KiB plus rolling final
768 KiB per command) and ACKs only after the storing transaction commits. The
final result's `outputBytes` commits the completion watermark; a chunk arriving
after it is refused and its bytes read back as a trailing gap. Content expires
24 hours after the command completes. Output is read through
`GET /v1/operations/{id}/output`; see `docs/design/native-http-contract.md`.
Disconnect/restart never reruns a command to reconstruct output.

### File relay staging

File operations carry immutable disk-backed captures between workers and the relay.
The host reserves at most 1 GiB per capture, 10 GiB in aggregate and four active
slots; stored guest files (FakeRuntime's simulated guest disk) never hold one.
Downloads send one 1 MiB chunk at a time until its exact
operation/generation/attempt/sequence/offset ACK arrives; uploads arrive in
server-paced chunks. Duplicate ACKs do not add credits. Upload dispatch includes
length and SHA-256; a quota refusal, gap, conflicting replay, oversize chunk or
manifest mismatch fails only that operation with a FAILED receipt. One settlement
owner handles every transfer that ends early: an upload idle for 15 minutes (one
hour total) gets a journaled FAILED `timeout` receipt (nothing reached the guest);
an unacknowledged download gets a FAILED `timeout`/`cancelled` terminal; both
complete exactly the authority they own and never a successor's. Host spool files
are private, ID-derived and unlinked before receiving content; last-handle close
(including process death) releases their bytes.

Guest file IO uses a small Python 3 helper through `incus exec -T`, with the
registered guest UID/GID/HOME. Python 3 is now required by readiness. Reads and
uploads reject non-regular files, symlinks in any path component, and `..`.
An upload is one helper invocation: it stages and fsyncs
`.wssp-upload-<token>` next to the destination, verifies length and SHA-256,
prints `WSSP_COMMIT_READY` and renames only when the host answers with a commit
byte. The host writes that byte only while holding the operation's current
runtime permit, so a cancellation or generation change that wins first leaves the
helper nothing to do but delete its staging file (FAILED `cancelled`, destination
untouched). A revocation after the byte was issued is reported as unknown, never
as success. The staging token is derived from operation, generation and attempt;
after a host crash, reconciliation runs the helper's `recover` mode: a surviving
staging file is removed (FAILED, and the rename can no longer happen), a
destination holding exactly the requested bytes proves the commit (SUCCEEDED), and
anything else stays unknown.

The relay receiver stores download captures in the relay transfer store: persistent
`sandbox_stream_transfer` metadata bound to the operation attempt, the configured transfer
limits and shared disk/owner reservation, fixed 1 MiB chunk digests, a whole-file
SHA-256 at seal, the transfer's idle/absolute expiry and the store's shutdown drain
and restart recovery. A final download result must match the sealed length and
SHA-256 and records the capture's `transferId`. Clients read the sealed capture
through the ranged download route (`GET /v1/operations/{id}/content`); no file
bytes are stored in SQL. A server restart fails every unsealed capture at once,
because a capture only continues on the connection that started it.

### Durable host leases

Relay v10 requires a lease deadline, revision, action and `retry-force-60s` policy
on create/reconnect/renew. Journal v4 persists accepted lease decisions before
boot or renewal ACK; per-sandbox checkpoints survive receipt confirmation.
An interrupted decision repairs its checkpoint on startup. Replayed renewal
receipts retain the original decision. Missing, stale or expired leases and
invalid/backward clocks refuse admission. Incus boot metadata mirrors the
initial arm; the private journal is authoritative for subsequent renewals.
A dedicated local service thread enforces elapsed monotonic time as well as the
persisted wall deadline. Forward wall jumps expire overdue leases immediately;
backward jumps cannot extend elapsed lifetime. The journal checkpoints an observed
clock floor at least once a second while active; a restart behind that floor
expires the lease. An unreadable clock also expires the lease, retaining the last
valid clock floor so a completed stop can be rearmed after clock recovery.
No process can measure time while the host is powered off.

The accepted deadline/action and instance fingerprint are durable before boot.
Expiry normally persists its terminal latch before revoking command, stdin and
transfer authority. If that checkpoint write fails, the already durable lease
intent still authorizes cleanup; all admission closes, and completion remains
unconfirmed until a fresh checkpoint succeeds.
Cleanup has separate workers, so blocked create/exec and socket I/O cannot delay
its scheduling. Each attempt has a cumulative five-second runtime budget. The
existing runtime stop is forced immediately (within the policy's 60-second grace),
then a destroy lease deletes the stopped instance. Failures remain unresolved and
retry with 1, 2, 4, 8, 16, then 30-second capped backoff until confirmed. Up to 64
outstanding lease arms are admitted, reserving independent cleanup slots; they
remain charged until expiry or a matching explicit teardown completes. Successful actions are not rescheduled.
Explicit newer-generation reconnect can rearm an expired stop only after cleanup
and prior lifecycle workers settle. An expired destroy cannot be rearmed.

Startup replays incomplete expiry before connecting or advertising readiness,
using the journal's renewed lease, not Incus boot metadata. That wait is
bounded: once every overdue action has completed or recorded a failure (or 15
seconds pass), the host connects anyway and reports the unresolved expiry
instead of withholding its census. The latch already refuses all lifecycle
work for that sandbox while the timer keeps retrying. A managed instance
without a journal lease refuses admission. Incus creation uses `init --vm` with
`boot.autostart=false`, followed by an explicitly authorized start; cold starts
also disable autostart. A late cancelled init can only leave a stopped VM.

During reconciliation, after its receipts, the host sends a complete census of
managed instances and journal leases (`sandbox.inventory`, at most 64 entries
per page and 1,024 pages, ids strictly ascending). Each entry carries the
observed state and the journal lease with its expiry latch, whether the
deadline timer set that latch (`timerExpired`, never set by an explicit
stop/kill), and the last failed expiry attempt (`expiryFailure`: a sanitized
reason of at most 160 printable ASCII bytes, the attempt count and when it
first failed). While connected, the host sends `sandbox.expiry_status` on its
heartbeat whenever a failure appears, changes or clears relative to what it last
published, including the census itself; a first-attempt success is published the
same way, so a completed expiry never waits for a reconnect. The runtime
inventory for that frame is read off the socket reader. A locally completed
expiry also frees the host's own admission slot for that generation without a
reconnect. The server shows a
failing expiry as ERROR `expiry_failed` with the host's reason (also when it had
already queued the expiry stop/kill offline), keeps the capacity reserved and
any pending stop/kill unsettled, and converges once the host confirms the
action, settling that pending operation without redispatching it. The server
acknowledges every page (`inventory.ack`) and requires the final page before
`reconcile.complete`. With `censusEntryResults` negotiated in `hello.ok`, each
ACK judges every entry of its page (`converged`, `not_converged`, or
`stale_storage`); storage health keeps renewing through the census, each page's
root evidence is observed and stamped with the last published storage sequence
just before it is sent, and an expiry arm refused for stale storage is
republished instead of being counted as reported. Without it, storage
publication pauses for the whole census. With `expiryStatusResults` also
negotiated (always together with `observationFence`), every connected
`sandbox.expiry_status` carries a batch the server answers with
`sandbox.expiry_status.ack`, judging each entry the same way; an entry refused
for stale storage (any census entry, not only an expiry arm), or not converged
while its pool was unhealthy (the pool its journal binds it to when its root
could not be observed), is offered again under the next storage observation
in which that is cured, one observation at a time, until the server judges it
converged. Every batch names its observation; one begins only after the
previous one was fully acknowledged, so the server judges non-expired
evidence from an observation that may predate a lifecycle result it received
(a reconnect's READY overtaking a stopped observation) `not_converged`
instead of downgrading the running sandbox. Absence without root evidence
that leaves the disk reserved is `not_converged`, so the host keeps retrying
it with root evidence. A failed observation delays the next one (1 s doubling
to 30 s). A server that answers `expiryStatusResults` without
`observationFence` gets the older unbatched frames. A stopped or absent instance converges the server record
and releases its capacity once; absence becomes DELETED only with a
host-verified destroy expiry or a pending kill, otherwise the sandbox shows
ERROR `instance_missing`. A partial census concludes nothing. An unknown,
foreign or deleted instance, or a lease the server never sent, quarantines the
host: it accepts no new work until a consistent census completes.

Allocation refusals, including size/policy validation, journal-full and authority
rejection, require journal-proven first-attempt evidence to release capacity.
Create requires runtime-proven VM absence; reconnect requires a VM positively
observed not running (stopped or absent), preserving the stopped disk.
Full journals remain readable; conflicting lineage, retries, running VMs and
observation errors stay UNKNOWN. UnsupportedRuntime cannot observe existing VMs,
so its allocation refusals stay UNKNOWN. A saturated or closed observation lane
answers UNKNOWN immediately without closing the session. Host shutdown or
unavailability at authority admission reports `host_effect_not_issued` only for
journal-proven first-claim create/reconnect refusals before admission. Replays,
uncertain lineage and other operation kinds retain `protocol_error`.
Reports retain the server's ownership and connection fences. A cold reconnect
held UNKNOWN before admission has no new host lease to expire; a successful
retry or destroy resolves it, and destroy deletes the disk.

The relay protocol includes a separate, in-session targeted attestation for held UNKNOWN
allocations (at most 256 ids per request). The journal is checked atomically
before per-id runtime existence checks. No VM, lease, allocation receipt,
worker or cleanup history may exist for a settled-never-issued answer.
History stays local and never changes the general census. The server also
checks dispatch order and durable journal continuity before releasing
capacity and failing the allocation with `host_effect_not_issued`. Old peers
cannot authorize this release. No session or terminal rotation is required.
A VM contradicting this release quarantines new admissions while leaving
owner destroy reachable on the connected host.

After disconnect (including credential rejection 4003/401/403), `wssp connect`
keeps enforcing accepted leases locally before returning the original relay
result. Already inactive guests whose selected final state is confirmed need no
future action. Once a session has existed, a lost connection or a transient
server close (1011) reconnects in-process with backoff from 250 ms to 30 s; the
first connect fails fast. While work is carried the daemon redials at least
every second for the first 60 s of an outage, then backs off from 1 s to 30 s.
Carried work is revoked only on a server verdict (`protocol.error`, close
1002) or a failed journal write: any journal write failure latches for the
life of the process, closes admission, and the host reports itself
unschedulable until a restart. A receipt whose runtime query stalls is
deferred instead of failing reconciliation (one per sandbox, four per host);
with `pendingReceipts` negotiated `reconcile.complete` names it, and its
receipt follows in the same session. With `commandRetire` negotiated, an
unknown `command.run` receipt the server recorded as unknown is retired once
the host proves the command can no longer run (its VM stopped or absent, the
guest rebooted since the command's start, or the command's own guest scope
`wssp.slice/wssp-cmd-*.scope` is gone or empty), with no sandbox stop. A due
command (cancelled, an unproven stop, or past its budget plus about 20 s on
the guest's monotonic clock) has its whole scope killed first; one still
running and not due is re-checked in the session about every 15 s at most.
See [host recovery](../../docs/guide/hosts.md). Terminal credential failures (4003, upgrade 401/403)
end the process and require fixing the credential. On reconnect the server
converges offline results from the host's receipts and census.

### Linux service

[examples/wssp-host.service](examples/wssp-host.service) is a user-service
example. Install the binary at `~/.local/bin/wssp`, grant that user access to
the Incus project, and run `wssp login` before enabling it. Copy the unit into
`~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and
`systemctl --user enable --now wssp-host`. Arrange user lingering with the host
administrator if enforcement must continue after logout. Keep the private `wssp` daemon
data directory across restarts; it contains the exclusive journal and lease
checkpoints. The service restarts after daemon failure and reconciles before
accepting work. `systemctl stop` (SIGTERM) or Ctrl-C (SIGINT) in a terminal
shuts the daemon down gracefully: every terminal is closed and reaped, the relay
closes normally, and the process then dies from that signal. A second signal, or
60 s without finishing, ends it at once. The relay connect (name lookup, TCP, TLS and
upgrade) gives up after 15 s, also against a server that trickles its reply, and
stops within about 100 ms of a shutdown request. At the default `info` level
the daemon logs one start and one finish line per host operation (kind, ids,
outcome, error code, `duration_ms`), never request content, guest paths or
credentials; see the [hosts guide](../../docs/guide/hosts.md#run-as-a-service). The unit's `KillMode=mixed` and
`TimeoutStopSec=75s` leave room for that; units installed from an older example
lack them, so copy the current file and run `systemctl --user daemon-reload`. A host power loss cannot execute
timers until restart, and an explicitly stopped/disabled service cannot enforce
deadlines; stop the guests before disabling it. Incus autostart remains disabled
across host boot.

Command workload environments use the bounded stdin frame before user stdin.
The host resolves absolute guest Python and setsid paths before applying workload
PATH; fixed HOME/SHELL identity flags remain in argv. Workload values stay out of
host argv and host child environments. PTY workload environments are not active.

## Files and tracked command compatibility

The relay protocol includes bounded rich filesystem results and tracked pipe-command
identity, not a guest-wide process census. Controls bind the full process
reference; legacy naked-PID signal/kill is unsupported. Read
`guestApi.supportedSignals`: TERM/INT/HUP use approved group-pidfd delivery on
guest kernels ≥6.9 with helper support, otherwise return the typed pre-effect
`signal_unsupported_on_guest`. SIGKILL uses canonical cancel. No numeric or
leader-only fallback exists for non-kill signals. Acceptance is not death.

After exhausted cleanup, UNKNOWN can leave work alive. There is no command
retry; recover through sandbox stop/kill. Unknown lifecycle outcomes require separate recovery. Observer detach does not send EOF or cancel;
host authority loss revokes old workers and a new relay epoch never adopts old
pipes. Revoking an SDK key does not cancel commands already accepted.

Command timeoutMs=0 means no separate command timer when
`limits.commandTimeoutZero` is true; omission remains 120000 ms and positive
maximum 1800000 ms. Lease/authority, the 5000 ms guest bootstrap budget and
15-second host setup bound after the tools probe still apply. Waits use finite
waitTimeoutMs, not guestTimeoutMs or the former wait-only timeoutMs alias.
The documented default guest is images:ubuntu/26.04/cloud; 24.04 stays supported
and HWE requires a verified booted ≥6.9 kernel/probe for non-kill signals.
Host-Incus 24.04 installation guidance remains unchanged.

See the [filesystem and command behavior](../../docs/guide/sandboxes.md#filesystem-and-command-result-limits)
for scopes, enum/wire compatibility, 1-hour observations/24-hour retained command
content, owner-wide 100/600/30 budgets, byte quotas and the
[unrun real-guest checklist](../../docs/testing.md#fsprocess-real-guest-acceptance-not-yet-run).

## Shared nodes and local host terminals

A host may serve multiple pools/creators within one resource budget. Incus guest
identity remains creator-scoped; the daemon journal binds one host transport and many
workload owners. The server and every daemon must run the same release (relay
protocol 1.0); a journal with an unknown version is refused, never converted.

Host terminals default off with TOTP required. Local commands are
`wssp config set-host-terminal on|off` and
`wssp config set-host-terminal-totp required|optional`. `wssp connect --host-terminal
on|off` is a startup override; subsequent local edits take precedence. Atomic
local persistence bumps revision even for repeated off. A fail-closed watcher
applies local off within two seconds without restarting guest work. Only a
fresh explicit enable command unlatches a running off state.

The dashboard can raise TOTP online, with persisted ACK; it cannot enable host
terminals or lower TOTP. Fixed `/bin/sh -i` runs with the daemon user's effective
local identity, trusted NSS home and cleared environment. Host shells can coexist
with foreign guests. An incus-admin operator can reach every VM; disabling the
dashboard shell provides no physical isolation. Contributors accept guest egress
from their network/IP and retained foreign disks through accepted pool grace
(up to 30 days); host deletion waits for cleanup proof, potentially longer for
offline/dead storage. See [terminal guide](../../docs/guide/terminal.md).

See the root [changelog](../../CHANGELOG.md) for release history and
[contribution guide](../../CONTRIBUTING.md) for development and review rules.
