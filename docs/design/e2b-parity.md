# E2B-like behavior on a self-hosted control plane

WS Sandbox Proxy aims for E2B-_like_ behavior: HTTP API (oRPC) plus a browser app, Linux
hosts only, no public guest ports. It is not byte-compatible with e2b.dev.

E2B reference: [API docs](https://docs.e2b.dev/api-reference) ·
[llms.txt](https://docs.e2b.dev/llms.txt).

## Known gaps

- **Not a drop-in replacement for the official E2B SDKs.** WS Sandbox Proxy serves its own
  `/v1` API; the E2B wire protocols (the platform REST API and envd) are not
  served, so an E2B SDK pointed at WS Sandbox Proxy does not work. The plan is to make
  `@wssp/sdk` E2B-shaped, not a full E2B facade.
- **No public URLs for guest ports.** E2B's `getHost` has no equivalent; a
  port inside a sandbox is not published at a URL.

## Locked architecture

| Decision        | Choice                                                                                                                            |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Guest interface | Incus guest agent only — `incus exec` (including the Python 3 file helper), `incus start/stop/delete`. No guest companion daemon. |
| Isolation       | The VM is the sandbox. Guest paths are the VM filesystem; there is no host-directory mount or workspace jail.                     |
| Host path       | Outbound WSS node daemon (`wssp host run`) → local Incus CLI. Clients never talk to Incus or the VM directly.                     |
| In scope        | Files, execution, manual templates, browser shell into the sandbox, later snapshot/fork APIs                                      |
| Out of scope    | `getHost` / guest port URLs, macOS/Windows runtimes, file watches, volumes, the E2B wire protocols and official SDKs              |

**Sandbox ready** means the VM is running and the guest agent responds. envd
parity is implemented as control-plane operations → relay → Incus, not as a
guest daemon.

## Code map

| Area                        | Path                                              |
| --------------------------- | ------------------------------------------------- |
| Incus CLI wrapper           | `crates/sandbox-runtime/src/incus/client.rs`      |
| Runtime trait + requests    | `crates/sandbox-runtime/src/trait.rs`             |
| Incus `SandboxRuntime` impl | `crates/sandbox-runtime/src/incus/kvm.rs`         |
| Live harness                | `crates/sandbox-runtime/src/bin/incus-surface.rs` |
| Relay dispatch              | `apps/cli/src/sandbox_relay/connect.rs`           |
| Protocol                    | `crates/sandbox-protocol/src/`                    |
| API routers                 | `packages/api/src/routers/sandboxes.ts`           |
| Prisma                      | `packages/db/prisma/schema/sandbox.prisma`        |
| Relay → DB                  | `apps/server/src/sandbox-relay/`                  |
| ADRs                        | [README.md](./README.md)                          |

Host env: `WSSP_INCUS_BINARY`, `WSSP_INCUS_PROJECT`, `WSSP_INCUS_IMAGE`,
`WSSP_INCUS_DAEMON_LOCK_DIR`.
`WSSP_INCUS_PROJECT` defaults to `wssp` (isolated instances, shared `default`
profiles and image aliases); set `default` to use the default project directly.
`WSSP_INCUS_DAEMON_LOCK_DIR` is a dev/test-only seam (like
`WSSP_INCUS_BINARY`) relocating the administrator-provisioned shared daemon
lock directory from its production default `/var/lib/wssp/incus-daemon-locks`
— the relocated directory faces the identical ownership/mode validation.
Instance naming: `wssp-sbx-<sandboxId>`.

## E2B mapping (behavior only)

E2B splits platform (`api.e2b.app`) and envd (`sandbox.*`). Here everything
goes through one HTTPS API → relay → Incus.

| E2B                         | WS Sandbox Proxy                                                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| envd filesystem RPCs        | Idempotent operations + `IncusKvmRuntime`                                                                                         |
| envd process Start / stream | `runCommand` plus bounded binary output                                                                                           |
| PTY                         | Browser terminal over `incus exec -t` (sandbox only, never the Incus host shell); runtime contract in ADR-004 "Terminal PTY"      |
| `GET /v2/sandboxes`         | `sandboxes.list`                                                                                                                  |
| `POST /sandboxes` + timeout | `createSandbox` with relative `timeoutMs` and persistent `lifecycle.onTimeout: kill \| stop`                                      |
| `DELETE` sandbox            | destroy                                                                                                                           |
| CPU / guest RAM             | Independent create overrides or immutable revision defaults; accepted size survives stop/cold boot; no resize or disk-size option |
| pause / resume              | Disk-only `stopSandbox` / original-disk reconnect; memory pause refuses                                                           |
| fork / snapshots            | Disabled with `UNSUPPORTED_CAPABILITY` until separately specified                                                                 |
| `getHost`                   | Unsupported helper: `UNSUPPORTED_CAPABILITY`; no guest ingress                                                                    |

## Product defaults

| Topic              | Choice                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command output     | Binary relay frames (protocol v10), four ACK slots of 8 KiB chunks (up to 64 KiB when negotiated), aggregate sequence/byte cursor and explicit gaps; host and server retain first 256 KiB plus rolling final 768 KiB; the server stores it durably and serves ≤ 64 KiB cursor pages at `GET /v1/operations/{id}/output` with gaps, completion watermark and 24-hour retention (`OUTPUT_EXPIRED`). Final command controls carry metadata only.                                                                                                                                                                                                                                                                                                             |
| Lifetime           | Default 300000 ms (5 minutes) and kill. The effective maximum is the smallest of the deployment (`SANDBOX_MAX_TIMEOUT_MS`, advertised as `sandboxTimeoutMaxMs`, default 24 hours), host ceiling, pool and membership maximums; a pool's `lease.maxTimeoutMs` gives its best path. Over the maximum: 400 `lease_exceeds_policy` with `maxTimeoutMs`, never clamped. `timeoutMs: 0` means no lease timer where `sandboxTimeoutZero` / `lease.timeoutZero` allow it. A connect without `timeoutMs` reuses the sandbox's remembered lease (the create's, or the last one a connect named), so stop then connect keeps it. READY connect only extends, relative setTimeout may shorten or extend. Choose `lifecycle.onTimeout: stop` at create to retain disk. |
| Processes          | Tracked commands only; full-reference controls; SIGKILL delegates to canonical cancellation, never a guest census                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Templates (MVP)    | Logical templates with immutable image/guest revisions, private defaults and per-host verification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Declarative builds | `Template()` / `templates.build` (SDK) and `POST /v1/template-builds`: a recipe or Dockerfile subset runs in a KVM build VM from a WS Sandbox Proxy base template and is captured as a new revision; no OCI base, no layer cache (a whole-recipe match reuses the revision). `setStartCmd(start, ready)` runs at every boot, not from a snapshot. See the [template builds guide](../guide/template-builds.md) and [declarative-build.md](./declarative-build.md)                                                                                                                                                                                                                                                                                         |

**Won't:** port URLs, macOS/Windows sandboxes, watches, volumes, RAM snapshots,
guest companion daemons, a full E2B SDK in this run.

## Released create and SDK breaks

- [Files and tracked processes](../guide/sandboxes.md#filesystem-and-command-result-limits): bounded live pages and retained server attachment, typed no-follow metadata, full-reference controls, additive error enums and new owner-wide admission budgets. Unlike E2B, guest-wide process discovery is absent, kill waits for proof or throws unknown, and non-kill signals use approved group pidfd or typed refusal. Read `guestApi.supportedSignals`; no command retry follows UNKNOWN. Sandbox stop/kill is recovery. Default guest is 26.04, with 24.04 supported and verified HWE ≥6.9 needed for non-kill signals. See the guide for scopes, retention and cost.

- [Command duration](../guide/sandboxes.md#filesystem-and-command-result-limits): E2B-shaped command `timeoutMs: 0` means no separate command timer, bounded by WS Sandbox Proxy lease and host authority. Clients must check `limits.commandTimeoutZero` before sending zero; omission is still 120 seconds and waits stay finite.

- [Sensitive browser authority and operation diagnostics](../guide/auth-planes.md): durable entry/exit and transfer IO checks; translated impersonation unavailability; catalog-only errors including loss of historical lifecycle diagnostics. Exit denial can follow committed work: recover through history or the original key, never a new-key retry.

Create accepts `template` (logical selector/tag or `revision/<id>`) plus exactly
one pool or explicit host. Responses retain logical `templateId`, exact
`templateRevisionId` and nullable origin pool. Relative `timeoutMs` controls
sandbox lifetime; command `timeoutMs` remains its separate process budget.
Create/connect SDK calls return a bound Sandbox only after READY and the exact
accepted lease/config ACK; native HTTP still returns a recoverable 202 operation.
SDK observation uses `waitTimeoutMs`; command submission uses `timeoutMs`. The deprecated wait alias and `guestTimeoutMs` were removed. Command `env` tuples are rejected
in favor of bounded `envs` string maps; metadata is string-only and sandbox
lists default to READY with filter-bound cursors.

Old resource IDs/history and template grants were discarded by the
[SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants); retained ALLOWLIST
keys require deliberate re-minting. Template revisions, pool grants and host
availability are independent. Pools provide bounded least-loaded placement,
not image distribution, host migration, failover or a wait queue. See the
[operator workflow](../guide/pools.md).

Port exposure remains inactive. Reserved `portExposure` describes provider
external, a public credential-free URL template, nullable hostname template,
protocols and authMode. An external provider would run on an independent
origin/VPS with a separate future credential contract; authMode grants no WS Sandbox Proxy
authority. Ingress/ports refuse before idempotency/receipt writes. No sidecar
origin is added to CSP/CORS.
