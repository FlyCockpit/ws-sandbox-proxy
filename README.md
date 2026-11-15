<p align="center">
  <img src=".github/assets/logo.png" alt="" width="160" height="160">
</p>

<h1 align="center">WS Sandbox Proxy</h1>

<p align="center">A self-hosted sandbox control plane that runs owner-scoped Incus KVM VMs on Linux hosts you enroll.</p>

<p align="center">
  <a href="LICENSE"><img src="https://shieldcn.dev/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/FlyCockpit/ws-sandbox-proxy/releases"><img src="https://shieldcn.dev/github/FlyCockpit/ws-sandbox-proxy/release.svg" alt="GitHub release"></a>
  <a href="https://nodejs.org"><img src="https://shieldcn.dev/badge/Node.js-26.13.1%2B-339933.svg?logo=nodedotjs" alt="Node.js 26.13.1+"></a>
  <a href="https://www.rust-lang.org/tools/install"><img src="https://shieldcn.dev/badge/Rust-1.99%2B-orange.svg?logo=rust" alt="Rust 1.99+"></a>
  <a href="https://github.com/FlyCockpit"><img src="https://shieldcn.dev/badge/part%20of-FlyCockpit-0ea5e9.svg" alt="Part of FlyCockpit"></a>
</p>

WS Sandbox Proxy (`wssp`, the name of its CLI and node daemon) is a self-hosted sandbox control plane: an oRPC API and web dashboard plus a Rust node daemon that drives Incus KVM VMs over outbound WebSockets. It is owner-scoped (per user, no organizations). It is intended as a sandbox backend for a personal agent harness: your programs create and drive VMs on your own machines through an HTTP API or a TypeScript SDK.

## Features

- **KVM sandboxes on your hosts.** Incus KVM virtual machines on Linux machines you enroll, with host pools for placement.
- **API and SDK.** A native `/v1` HTTP API (OpenAPI at `/v1/openapi.json`) and the [`@wssp/sdk`](packages/sdk/README.md) TypeScript client for commands, streamed output, files and resumable transfers.
- **Dashboard.** A web dashboard with a browser [terminal](docs/guide/terminal.md), PWA support and localized routes.
- **Template builds.** A JSON recipe or Dockerfile subset is built in a VM and captured as a new template revision; see [template builds](docs/guide/template-builds.md).
- **Egress control.** Open egress by default behind a root-owned nftables guard on each node, or an allowlist chosen at create; see [network egress](docs/guide/network.md).
- **Credentials and events.** A [CLI-login](docs/guide/cli-logins.md) credential vault and signed [webhooks](docs/guide/webhooks.md).

## How it works

- `apps/web` — React / TanStack Router dashboard (locale-prefixed routes, PWA)
- `apps/server` — Hono API, Better Auth, sandbox relay
- `apps/worker` — BullMQ consumers (optional dedicated container)
- `apps/cli` — `wssp` CLI and outbound node daemon
- `packages/api` — oRPC routers and sandbox services
- `packages/sandbox-contracts` — public `/v1` DTOs, error catalog, routes and OpenAPI
- `packages/auth` / `packages/db` / `packages/env` — auth, Prisma, env validation
- `crates/sandbox-protocol` / `crates/sandbox-runtime` — relay contract and Incus runtime

Four authentication planes never share credentials: browser cookie sessions
(CSRF, required-2FA policy) for the dashboard, `Authorization: Bearer wssp_sdk_…`
API keys on `/v1`, `wssp_agent_…` tokens or OAuth grants on `/mcp`, and
`wssp_host_…` / `wssp_device_…` credentials for node daemons on
`/ws/sandbox-host`. Scoped host commands/files require node-local opt-in on a
node owned by the credential's user. The daemon user is an Incus admin: those
tools can reach every sandbox on the node, including other users' shared-pool
sandboxes; **Own sandboxes only** does not limit them. See
[ADR-006](docs/design/adr-006-agent-host-access.md). Admin routes (`/{lang}/admin`) 404 for
non-admins, and admin observability is metadata-only: it never grants
execution, file or terminal access. See the [guide](docs/guide/README.md).

## Quick start

For a local development stack (prerequisites under [Installation](#installation)):

```sh
npm install -g pnpm@12.18.0
pnpm install
pnpm run setup
pnpm dev
```

- Web: [https://wssp.localhost](https://wssp.localhost)
- API: [https://api.wssp.localhost](https://api.wssp.localhost)

## Installation

### Local development

Prerequisites: Node.js 26 LTS (26.13.1 or newer), pnpm 12.18.0 (pinned in `package.json`), Docker or Podman,
and [`portless`](https://www.npmjs.com/package/portless) (`npm install -g portless`)
for `https://*.localhost` names.

```sh
npm install -g pnpm@12.18.0
pnpm install
pnpm run setup
pnpm dev
```

Use the explicit `run` form — `setup` is also a pnpm builtin. `pnpm run setup`
creates `.env` files if missing, generates missing auth and sandbox request-HMAC
secrets, records `ADMIN_EMAILS`, starts Postgres 18 and Valkey 9, and applies the Prisma
schema.

- Web: [https://wssp.localhost](https://wssp.localhost)
- API: [https://api.wssp.localhost](https://api.wssp.localhost)

If pnpm fails with `mkdir '/Users'` on Linux/WSL, unset a stale macOS
`PNPM_HOME` and retry.

`pnpm doctor` validates environment, database, Valkey, and optional SMTP.

### Node daemon

On a Linux machine with Incus (6.14+) and KVM, from a checkout:

```sh
cargo run -p wssp -- login --slug desk-01 --server https://api.example.com
cargo run -p wssp -- connect
```

Device login prints a verification URI and code (no browser or stdin
prompts). A dashboard-minted `wssp_host_…` token works too:
`wssp token login WSSP_HOST_TOKEN`, then
`wssp connect --server https://api.example.com --host-id <host-id>`.
`--runtime fake` (or `WSSP_RUNTIME=fake`) uses the
in-process fake runtime and launches no VMs. For local stacks,
`WSSP_FAKE_ENFORCE_EGRESS=1` lets a fake host accept creates and
`WSSP_FAKE_FAIL_CREATE_FILE=<path>` fails new creates while that file exists
(fake runtime only). Incus instance names are
`wssp-sbx-<sandboxId>` in the dedicated `wssp` Incus project.

Bare connect derives guest RAM and a per-VM CPU cap from the Incus daemon.
Optional `--sandbox-memory-mib` / `--max-sandbox-cpu-count` overrides also have
TOML equivalents; `wssp config show` explains detection and effective values.
Operators own host/QEMU headroom. Native API and SDK creates accept independent
`cpuCount` / `memoryMiB` overrides, defaulting to the selected immutable revision.
See the [VM size guide](docs/guide/sandboxes.md#vm-size) for bounds, shared
host admission and the coordinated server/SDK/daemon contract.

The [hosts guide](docs/guide/hosts.md) covers requirements, the systemd unit,
signals, upgrades, drain and credential rotation; the
[CLI README](apps/cli/README.md) covers the daemon's state directory and
recovery model, and the [CLI reference](apps/cli/docs/cli-reference.md) lists
every command and flag.

#### Install after release

The CLI and outbound node daemon are Linux-only. Install on the spare Linux
machine that will run your sandboxes, after the first public GitHub release:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/FlyCockpit/ws-sandbox-proxy/releases/latest/download/wssp-installer.sh | sh
```

Releases are cut from the default branch with the root `Release` workflow.
A release publishes the app and worker images to GHCR and the
`wssp` CLI artifacts to the GitHub Release. Linux is the supported CLI
platform; the release generates a shell installer for the two Linux targets.

### Production

Two production Dockerfiles ship at the repo root:

| Image  | File                | Role                                                       |
| ------ | ------------------- | ---------------------------------------------------------- |
| server | `Dockerfile`        | API + web SPA; embedded jobs unless `WORKER_MODE=external` |
| worker | `Dockerfile.worker` | Dedicated BullMQ consumers                                 |

Released images are published to GHCR as:

```text
ghcr.io/flycockpit/ws-sandbox-proxy:vX.Y.Z
ghcr.io/flycockpit/ws-sandbox-proxy-worker:vX.Y.Z
```

```sh
docker pull ghcr.io/flycockpit/ws-sandbox-proxy:latest
```

The host relay, browser terminal and transfer spool are always enabled.
Run one server replica: host relay sessions, in-process credential revocation
and the transfer spool assume a single control-plane process.

The server applies committed Prisma migrations before serving; workers wait for
compatible history. The same app image supports one-shot `migrate`, `backup` and
`restore` jobs. See [schema migrations](docs/schema-migrations.md) and
[infrastructure](docs/infra.md).

```sh
pnpm dokploy:config --project wssp --proxy-network dokploy-network --url https://sandbox.example.com
pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha> # check current tasks and /ready commit
```

## Configuration

Required for a running server: `DATABASE_URL`, `BETTER_AUTH_SECRET` (min 32
characters), `BETTER_AUTH_URL` (public origin, no path), and
`SANDBOX_REQUEST_HMAC_SECRET` (at least 32 random bytes encoded as lowercase
hex; use the `secret32` generator). Local setup generates that sandbox secret;
production injects it from the platform secret store. Preserve it across
upgrades: changing it refuses retained config/replay bindings. See
[environment variables](docs/operations/environment-variables.md#sandbox-create-settings).
Valkey 9 (Redis-protocol compatible) is required for jobs and rate limits (`REDIS_URL`). Schema changes use committed migrations:
`pnpm db:migrate <name>`, review SQL, then `pnpm db:migrate:apply` locally.

Root `.env.example` and `apps/web/.env.example` are generated from
`scripts/lib/env-manifest.ts`. Do not hand-edit them.

```sh
pnpm env:sync          # rewrite the .env.example files from the manifest
pnpm env:check         # CI gate: schema keys, manifest, and examples stay in sync
pnpm generate:secrets  # interactive production env block
```

### First login

Public signup defaults to disabled (`SIGNUP_ENABLED=false`); admins can override
the effective signup setting. `ADMIN_EMAILS` permits bootstrap signup for those
addresses. After `pnpm run setup`:

1. Confirm `ADMIN_EMAILS` in the root `.env` is your address.
2. Start a local mail sink (`docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit`)
   and set `SMTP_HOST=localhost`, `SMTP_PORT=1025`, `SMTP_FROM=noreply@dev.local`.
3. Restart `pnpm dev`, sign up at [https://wssp.localhost](https://wssp.localhost)
   with that email, and verify via [http://localhost:8025](http://localhost:8025).

## Usage

1. Deploy the server ([deployment](docs/operations/deployment.md)), sign up
   with an `ADMIN_EMAILS` address and enable 2FA.
2. Enroll a Linux host with Incus and KVM: run
   `wssp login --slug desk-01 --server https://api.example.com`, approve it in
   the dashboard, then run `wssp connect` ([hosts](docs/guide/hosts.md)).
3. Prepare an Incus VM image on that host and register it as a template
   ([templates](docs/operations/templates.md)). OCI images are not VM images;
   [template builds](docs/guide/template-builds.md) derive new revisions from
   an existing VM template.
4. For pooled placement, create a pool on **Pools** and add/enable its hosts.
   Verify each exact revision on the intended members through
   **Templates → Manage revision**; membership never copies images.
5. Mint an SDK key with the required scopes. Restricted keys need host + exact
   revision grants and, for pooled work, the pool grant too.
6. Drive sandboxes from TypeScript with
   [`@wssp/sdk`](packages/sdk/README.md), from any HTTP client against `/v1`
   (OpenAPI at `/v1/openapi.json`, committed as
   `packages/sandbox-contracts/openapi.json`), or from the dashboard, which also
   has a browser [terminal](docs/guide/terminal.md).

On **Sandboxes → Create sandbox**, choose a logical template's latest tag or
an exact revision independently of pool/direct placement. Lifetimes are
relative: five minutes and destroy by default, or stop to keep disk. Optional
`envs` are private bounded string maps; metadata is visible string labels.
Unchanged retries after lost responses reuse the same key and input. See
[host pools](docs/guide/pools.md) for the full workflow and refusal guidance.

Sandboxes have open egress by default, or an allowlist chosen at create;
allowlist domain grants are host-resolved IPv4 grants, not hostname isolation;
the host re-resolves them while the sandbox runs and withdraws them when
refresh fails ([network egress](docs/guide/network.md)).

The sandbox detail page includes bounded file metadata and tracked-command
panels, retained output attachment and confirmed cancellation. The SDK offers
start/connect/stdin/EOF and typed file operations. Read capabilities for command
zero (no separate timer) and approved group signals or typed guest refusal.
This remains a tracked-command interface: no guest census, SDK PTY or ingress.
See the [filesystem and command behavior](docs/guide/sandboxes.md#filesystem-and-command-result-limits).

### Known gaps

- **Not a drop-in E2B replacement.** WS Sandbox Proxy does not serve the E2B wire
  protocols (the platform REST API or envd), so the official E2B SDKs cannot
  talk to it. The plan is to make `@wssp/sdk` E2B-shaped, not to build a full
  E2B facade.
- **No public URLs for guest ports.** There is no equivalent of E2B's
  `getHost`: WS Sandbox Proxy does not publish a port inside a sandbox at a URL.
- **No pool wait queue, migration or failover.** Placement chooses among
  currently verified, eligible hosts. Full/unavailable pools refuse immediately
  so callers can choose a fallback; accepted sandboxes keep their original
  host, exact revision and private defaults. Stop keeps disk, not RAM.
- **Pools are shared by explicit invitation only.** A node owner keeps full
  access to every sandbox that runs on their node, including other users'
  sandboxes; pool users never get host access to someone else's node. Adding
  a revision never expands restricted keys automatically.
- Snapshots, restore and fork are not supported yet
  (`UNSUPPORTED_CAPABILITY`).

See [E2B parity](docs/design/e2b-parity.md).

## Development

```sh
pnpm check-types
pnpm test
pnpm check:ci
pnpm env:check
```

Rust workspace (CLI + crates), from the repo root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked -- --test-threads=1
```

### Scripts

- `pnpm run setup` — first-run onboarding (idempotent)
- `pnpm doctor` — environment, DB, Valkey, SMTP
- `pnpm dev` / `pnpm dev:raw` — portless HTTPS, or raw Turbo
- `pnpm dev:services` — Postgres 18 + Valkey 9
- `pnpm db:migrate <name>` / `pnpm db:migrate:apply` / `pnpm db:studio`
- `pnpm env:sync` / `pnpm env:check`
- `pnpm sync:agent-docs` — regenerate AGENTS.md mirrors

## Documentation

- [docs/guide/](docs/guide/README.md) — product guide: auth planes, hosts,
  pools, sandboxes and operations, network egress, terminal
- [packages/sdk/README.md](packages/sdk/README.md) — TypeScript SDK
- [apps/cli/docs/cli-reference.md](apps/cli/docs/cli-reference.md) — `wssp` commands and flags
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide
- [AGENTS.md](AGENTS.md) — contributor and coding-agent rules
- [docs/sitemap.md](docs/sitemap.md) — web routes
- [docs/infra.md](docs/infra.md) — images, env, schema apply
- [docs/operations/deployment.md](docs/operations/deployment.md) — Dokploy walkthrough
- [docs/operations/backup-and-restore.md](docs/operations/backup-and-restore.md) — backups and recovery
- [docs/operations/production-hardening.md](docs/operations/production-hardening.md) — production checklist
- [docs/operations/templates.md](docs/operations/templates.md) — template image prerequisites
- [docs/design/](docs/design/) — ADRs and sandbox design notes

## Contributing

Issues and pull requests are welcome. Run the checks under [Development](#development) before you open a pull request, and read [AGENTS.md](AGENTS.md) for the repository rules.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Copyright (c) 2026 FlyCockpit LLC. Licensed under the [MIT License](LICENSE).
Third-party components keep their own licenses; required notices are in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
