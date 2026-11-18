# @wssp/sdk

Server-side TypeScript client for the WS Sandbox Proxy (`wssp`) `/v1` sandbox API.
It runs in Node 22+ (use this repository’s pinned Node 26.13.1) or another
runtime with `fetch`, on a
machine you control, never in a browser: the key it holds can run commands in
your sandboxes.

Every code block on this page is a compiled file under
[`examples/`](./examples/): `pnpm check-types` type-checks them against the
package's real exports, and a test fails when this page and a file differ.
The package is not on npm yet (no release has been published); inside this
repository depend on it as `"@wssp/sdk": "workspace:*"`.

## Keys and scopes

Mint a key on the dashboard's **SDK keys** page. It is shown once, starts with
`wssp_sdk_`, and is sent as `Authorization: Bearer wssp_sdk_…`. Keys are
owner-scoped: sandbox data belongs to its owner, and shared-pool grants may
expose other owners' host metadata. A key uses either **all owned** resources or
an **allowlist** of selected hosts, exact revisions and pools. Sandbox creation
needs a usable host/revision or pool/revision grant; host-only tools need a host
grant. An
optional expiry and revocation take effect on the next request; there is no
principal cache.

| Scope               | Grants                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `hosts:read`        | List and read visible hosts and their `agentAccess`                                                                 |
| `hosts:execute`     | Start/read host commands, write stdin, cancel; queue commands for a person                                          |
| `hosts:files`       | Read, list, write and edit text files inside node-configured roots                                                  |
| `pools:read`        | List/read allowed pools; members also need `hosts:read`                                                             |
| `templates:read`    | Read templates and revisions                                                                                        |
| `templates:write`   | Register templates and revisions; capture also needs `sandboxes:manage`                                             |
| `templates:build`   | Build revisions, read build logs and cancel builds; creating a named template also needs `templates:write`          |
| `sandboxes:read`    | Read sandboxes and effective capabilities; liveness probe                                                           |
| `sandboxes:create`  | Create sandboxes                                                                                                    |
| `sandboxes:manage`  | Rename, stop, reconnect and renew leases; capture with `templates:write`; attach/free logins with `credentials:use` |
| `sandboxes:destroy` | Destroy sandboxes                                                                                                   |
| `commands:read`     | List/connect to tracked commands; output also needs `operations:read`                                               |
| `commands:execute`  | Start guest commands and write stdin                                                                                |
| `files:read`        | Guest stat, list and capture downloads; reading results/bytes also needs `operations:read`                          |
| `files:write`       | Guest upload, mkdir, move and remove                                                                                |
| `operations:read`   | Read operations and wait for outcomes                                                                               |
| `operations:cancel` | Cancel an operation; also needs its mutation scope                                                                  |
| `webhooks:write`    | Manage endpoints and delivery logs with all-owned, all-usable keys                                                  |
| `credentials:read`  | List CLI logins, accounts, instances and events                                                                     |
| `credentials:write` | Create/edit CLI logins, accounts and instances; upload write-only values                                            |
| `credentials:use`   | Attach/free a login; also needs `sandboxes:manage`                                                                  |

Set **Own sandboxes only** (`ownSandboxesOnly`) when minting a key to restrict
sandbox, guest command, guest file and operation access to sandboxes created by
that credential. API keys default to false; agent tokens and OAuth grants default
to true. Allowlist credentials always have this creator restriction. The effective
setting is returned as `key.ownSandboxesOnly` by `GET /v1/capabilities`.

`wssp.key.get()` (`GET /v1/key`, no scope needed) describes the calling key:
its name, origin (`dashboard` or `cliLogin`), scopes, pools, expiry and, when it
has one, its live sandbox limit with the current count. A key with a limit
refuses a create over it with `sandbox.key_limit_reached`; the error's
`keyLimit` holds `{ maxLiveSandboxes, liveSandboxes }`. A key minted by
`wssp login` can revoke itself with `wssp.key.revokeSelf()` (`DELETE /v1/key`);
any other key gets `key.self_revoke_forbidden`. See
[CLI user logins](../../docs/guide/auth-planes.md#cli-user-logins-wssp-login).

Host commands and host file tools run as the **node daemon user**: they can do
whatever that user can do, including Incus administration when the daemon user
has it. They can reach other users' sandboxes on the node, including shared
pools.
**Own sandboxes only does not limit host access.**
Direct host commands and files work only on hosts the key's owner owns and
allows, and only after the node owner enables agent host commands at the node
(`wssp host config set-agent-host-commands on`). File tools also need node-configured
`host_file_roots`. A shared-pool host never qualifies. Queuing a command for a
person needs ownership and a host grant, but no node opt-in because it executes
nothing.

The `/v1` SDK accepts API keys only. Agent tokens (`wssp_agent_…`) and OAuth
grants belong to `/mcp`; they cannot authenticate this client.

`commands:read` on a granted sandbox exposes tracked command descriptions (argv/cwd) from the owner's browser and other SDK keys as well as the calling key. Output attachment also needs `operations:read`. Keep secrets in envs/private configuration rather than argv.

Complete helper flows need every read scope they use: run/start combine
`commands:execute`, `commands:read` and `operations:read`; connect itself needs
`commands:read`, then wait/output also needs `operations:read`. File observations
need `files:read` plus `operations:read`, mkdir/remove results need `files:write`
plus `operations:read`, and rename results need both file scopes plus
`operations:read`. Signal/kill use `commands:execute` and `operations:cancel`;
their receipt/result or target-state waits also need `operations:read`.
Qualified stdin acceptance uses `commands:execute`. Effective capabilities use
`sandboxes:read`. Existing sandbox/template/host/pool grants still apply.

The dashboard refuses a key whose scopes authorize nothing
(`sdk_key.unusable_scopes`). The authoritative per-route scopes are the
`x-wssp-scopes` entries of the OpenAPI document (`GET /v1/openapi.json`,
committed as `packages/sandbox-contracts/openapi.json`).

Logical templates expose separate revision and availability pages through
`client.templates`. Create accepts a slug, slug:tag, `template/<logicalId>` or
`revision/<revisionId>` in `template`, with exactly one of `poolId` or an explicit `sandboxHostId`. Sandbox responses retain logical
`templateId`, exact `templateRevisionId` and nullable `originPoolId`. Appends do
not expand existing ALLOWLIST grants. Direct placement retains its existing host/revision grants. See [SDK resource grants](../../docs/guide/auth-planes.md#minting-sdk-resource-grants).

## Host commands and files

`client.hosts.get` and `.list` return `agentAccess: {owned: false}` for a
foreign host, or `{owned: true, hostCommands, hostFiles, hostCommandMaxMs?}` for
your host. Host command status, stdin and cancellation are credential-scoped:
another key owned by the same person cannot read or control your command.

`hosts.commands.start` returns a status with a `commandId`; `.get` accepts
numeric `stdoutOffset`, `stderrOffset`, `maxBytes` (at most 65,536 per stream),
and `waitMs` (at most 60,000). Output chunks are masked bytes encoded as padded
base64, with absolute byte offsets and explicit `dropped` flags. `.writeStdin`
accepts `{data, eof}` with at most 65,536 decoded bytes. `.cancel` returns the
current status.

`hosts.commands.run` starts once, polls until terminal, and drains remaining
output. Its result adds `stdoutText`, `stderrText` (last 1 MiB per stream) and
`truncated` to the final status. A wait deadline or abort detaches; it does not
cancel the host command. Save the `commandId` from `.start` when you need manual
recovery. Reuse the original idempotency key after an uncertain submission.
Execution `timeoutMs` is capped by `hostCommandMaxMs`; `waitTimeoutMs` bounds the
SDK observer separately.

File reads return `{content, offset, size, etag, truncated}`; lists return at most
1,000 entries and `truncated`. Writes accept at most 262,144 UTF-8 bytes and
require `expectedEtag` to replace an existing file (`createOnly` refuses an
existing file). Edits take 1–20 `{oldText, newText}` pairs; each old text must
match exactly once, and every replacement commits together. Do not write masked
`⟦redacted` spans back. `host.file_error` exposes a typed `WsspError.reason`,
including `conflict`, `path_denied`, `redacted_span` and `binary_file`. Writes
and edits replay by idempotency key for the same credential: a retry with the
same key and input returns the first result without changing the file again.
`host.file_outcome_unknown` (kind `unknown`) means the change was sent but its
outcome is unknown; read the file before writing again under a new key.

`hosts.queueCommand` returns `{id, state, expiresAt}`. `.getQueuedCommand` reads
only this credential's queued command. Expiry is 1–168 hours, default 24; only a
person can decide to run or dismiss it.

<!-- example: examples/hosts.ts -->

```ts
import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const hostId = "host_1";
const host = await wssp.hosts.get(hostId); // hosts:read

// hosts:execute requires your own host, a host grant, and agent commands
// enabled at the node. Commands run as the node daemon user (which may be an
// Incus admin) and can reach other users' sandboxes; ownSandboxesOnly does not
// limit them.
if (host.agentAccess.owned && host.agentAccess.hostCommands) {
  const result = await wssp.hosts.commands.run(
    hostId,
    { argv: ["uname", "-a"], timeoutMs: 10_000 },
    { idempotencyKey: "host-uname-1", waitTimeoutMs: 30_000 },
  );
  console.log(result.commandId, result.state, result.stdoutText, result.truncated);
}

// Queueing only asks a person to run it. It works even while agent commands
// are disabled; the SDK cannot approve, run or dismiss a queued command.
const queued = await wssp.hosts.queueCommand(hostId, {
  command: "incus list",
  reason: "Please inspect the node's current instances",
  expiresInHours: 24,
});
console.log(await wssp.hosts.getQueuedCommand(hostId, queued.id));

// hosts:files: paths must be inside roots the node owner configured. Reads
// mask secrets. Write a new file, or use the read etag to replace/edit one.
if (host.agentAccess.owned && host.agentAccess.hostFiles) {
  const file = await wssp.hosts.files.read(hostId, { path: "/srv/agent-work/note.txt" });
  await wssp.hosts.files.edit(hostId, {
    path: "/srv/agent-work/note.txt",
    expectedEtag: file.etag,
    edits: [{ oldText: "pending", newText: "reviewed" }],
  });
}
```

## Quickstart

<!-- example: examples/quickstart.ts -->

```ts
import { createWsspClient } from "@wssp/sdk";

// The SDK never reads the environment: your program passes the key in.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "", // a `wssp_sdk_…` key from the dashboard
});

// Create pins the sandbox to one of your hosts and one of its templates. It
// resolves only once the operation succeeded and the sandbox reads READY.
const sandbox = await wssp.sandboxes.create({
  name: "ci-runner", // optional; omitted, the server picks a free one like "quiet-otter"
  cpuCount: 2,
  diskGiB: 32,
  memoryMiB: 2048,
  sandboxHostId: "host_…",
  template: "revision/" + "tpl_…",
  metadata: { purpose: "ci" },
  envs: { APP_MODE: "ci" }, // private defaults for commands and terminals
  // Open IPv4 internet by default. `allowInternetAccess: false` switches to
  // an allowlist of `egress.domains` / `egress.cidrs` (see the agent-browser
  // example); private and metadata ranges are always blocked.
  // Default: the guest user may run `sudo` inside the VM (`guestSudo: false`
  // turns it off). Commands, files and terminals still run as the guest user.
  guestSudo: true,
  lifecycle: { onTimeout: "kill" }, // default; the default lifetime is five minutes
});

console.log(sandbox.name, sandbox.id);

const result = await sandbox.commands.script("uname -a && id");
console.log(result.exitCode, result.stdout);
console.log((await sandbox.files.list("/home/user", { limit: 100 })).items);

await sandbox.destroy(); // resolves at confirmed deletion
```

## Network access

Sandboxes get open IPv4 internet by default. Private, loopback, link-local,
metadata and tailnet ranges and the host's own addresses stay blocked in every
mode.

- `allowInternetAccess: false` switches to allowlist mode: only
  `egress.domains` (exact names, resolved on the host to IPv4 addresses) and
  `egress.cidrs` are reachable, and listing nothing blocks all outbound
  traffic.
- `allowInternetAccess: true` (or omitting it) keeps open internet. Any
  `egress` grants are fallback grants: another user's host may allow only
  listed destinations, and the sandbox then runs in allowlist mode with those
  grants.
- `sandbox.egress.mode` is the effective mode, fixed when the sandbox is
  placed. `sandbox.egressModeReason` says why an open request became an
  allowlist (`node_policy` or `host_unsupported`), and
  `sandbox.egressDeniedGrants` lists grants the host's blocklist refused.
- An `egress.mode` that contradicts `allowInternetAccess` is refused locally
  (`invalid_request`). Without `allowInternetAccess`, an `egress` with grants
  and no `mode` is an allowlist.

## Root in the guest

The guest user gets passwordless `sudo` inside the VM by default
(`guestSudo`, fixed at creation). Commands, files and terminals always run as
the guest user; use `sudo` inside a command when it needs root.

- `guestSudo: false` creates the sandbox without the grant. A template whose
  image already gives the guest user root (a sudoers rule, the `sudo` or
  `docker` group, doas) then fails the create with `guest_root_granted`, and
  an image without a working `sudo` fails a `guestSudo: true` create with
  `guest_sudo_unavailable`. Both destroy the VM.
- `sandbox.guestSudo` is the effective value and `sandbox.guestSudoRequested`
  what the create asked for. On another user's node whose owner does not
  allow it, the sandbox starts without the grant and
  `sandbox.guestSudoReason` is `node_policy`; `host_unsupported` means the
  node's daemon cannot grant it yet. If the owner withdraws consent later, a
  restart on that node fails with `guest_sudo_not_permitted`.
- `sandbox.guestRoot` is true when the guest may run as root: the grant, or a
  revision built with root steps or captured from such a sandbox
  (`revision.capturedWithGuestRoot`). For such a sandbox every command result
  is reported by the guest itself, and a command whose outcome is unknown is
  cleared only when the host sees the VM stop or restart. Stopping the
  sandbox is the general remedy when a host refuses new commands with the
  `sandbox_receipts` capacity reason.
- Omitting `guestSudo` and sending `guestSudo: true` are different request
  bodies for the idempotency key.

## Pools and immediate fallback

Pools are owner-managed host groups. The scheduler ranks your own member hosts
first when the pool prefers own hosts (the default; a tier, not a filter), then
the eligible member with the lowest dominant share after placement (RAM, vCPU
or the chosen storage pool, whichever is fullest), then host ID. It skips
draining/offline members. A pooled ALLOWLIST create needs the pool, selected
host and exact revision grants together; `pools:read` only grants discovery.
Discovery is paged; pass `nextCursor` to request another page.

`sandbox.pool_full` and `sandbox.host_capacity` surface immediately as typed
capacity errors; `sandbox.pool_unavailable` surfaces immediately as unavailable.
The raw code is preserved and none is retried automatically. Each carries
`WsspError.retryable` (`false`: fall back or change the request; `true`: back
off for `retryAfterSeconds`, then retry); see
[Harness create and fallback policy](#harness-create-and-fallback-policy). Rate/quota 429,
5xx and lost responses keep same-key retry/reconciliation. An uncertain
accepted operation is never allocated again or moved to another pool.
Pool deletion/member removal/drain affect future placement; retained pool
grants still govern access to accepted pooled sandboxes.

<!-- example: examples/pools.ts -->

```ts
import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const page = await wssp.pools.list({ limit: 20 });
const pool = page.items[0];
if (pool) {
  // Pool use trusts foreign host operators and their network/egress policy.
  // Shared members expose opaque IDs; owner metadata includes host labels.
  const members = await wssp.pools.members(pool.id, { limit: 20 });
  console.log(members.items.map((member) => ("host" in member ? member.host.label : member.id)));
  try {
    const sandbox = await wssp.sandboxes.create({
      template: "my-template:latest",
      poolId: pool.id, // exactly one of poolId or sandboxHostId
      memoryMiB: 2048, // CPU independently uses the selected revision default
      // Open internet on your own hosts and on hosts whose owner allows it.
      // Another user's host may allow only listed destinations: these
      // fallback grants then become the allowlist (`egressModeReason`).
      allowInternetAccess: true,
      egress: { domains: ["registry.npmjs.org"] },
    });
    console.log(sandbox.egress.mode, sandbox.egressModeReason);
    await sandbox.destroy();
  } catch (error) {
    if (
      isWsspError(error) &&
      (error.code === "sandbox.vm_size_unsupported" ||
        error.code === "sandbox.pool_full" ||
        error.code === "sandbox.pool_unavailable" ||
        error.code === "sandbox.host_capacity" ||
        // No member's network guard is running (retryable later).
        (error.code === "UNSUPPORTED_CAPABILITY" && error.reason === "egress_guard_unavailable"))
    ) {
      // A definitive refusal made no allocation; a provider fallback is safe.
      console.log(error.code);
    } else {
      // Preserve the idempotency key / operation ID for an uncertain outcome.
      throw error;
    }
  }
}
```

### Waiting for capacity

A pool create may pass `waitForCapacityMs` (1000..2073600000, or `"unlimited"`
where no limit applies) to wait in the pool's FIFO queue instead of failing with
`sandbox.pool_full`. The receipt is the same 202; the sandbox reads
`WAITING_FOR_CAPACITY` with a `capacityWait` position until it is placed, and
its lease starts at placement. `create()` polls a waiting create slowly (every
5–15 s) and then long-polls as usual; without a `waitTimeoutMs` it waits the
requested time plus the default budget. A local deadline or abort never cancels
the server entry: the error carries `sandboxId`, and destroying that sandbox
cancels it. A server-side timeout fails with `capacity_wait_timeout`
(`isCapacityWaitTimeout`). Over-limit waits are refused with
`capacity_wait_exceeds_policy` (`maxWaitMs`); full queues with
`sandbox.capacity_queue_full` (`scope`). `pools.capacity()` reports what fits.

<!-- example: examples/capacity.ts -->

```ts
import { createWsspClient, isCapacityWaitTimeout, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const poolId = "pool_id";
// What fits now (aggregates over hosts you can schedule on; your own hosts in
// detail with hosts:read), the lease limits and the queue.
const capacity = await wssp.pools.capacity(poolId, { template: "my-template:latest" });
console.log(capacity.fits, capacity.queue.waiting, capacity.queue.limits.maxWaitMs);
try {
  // Wait up to 30 minutes in the pool's FIFO queue if no host fits now. The
  // lease (timeoutMs) starts only when the create is placed.
  const sandbox = await wssp.sandboxes.create({
    template: "my-template:latest",
    poolId,
    waitForCapacityMs: 30 * 60_000,
  });
  await sandbox.destroy();
} catch (error) {
  if (isCapacityWaitTimeout(error)) {
    // The wait ended on the server: nothing was allocated.
    console.log("no capacity within 30 minutes");
  } else if (isWsspError(error) && error.sandboxId) {
    // The local wait ended but the queued create remains: destroy cancels it.
    await wssp.sandboxes.destroy(error.sandboxId);
  } else if (isWsspError(error) && error.code === "capacity_wait_exceeds_policy") {
    console.log("largest allowed wait", error.maxWaitMs);
  } else {
    throw error;
  }
}
```

The sharing admission work is not yet qualified for an integrated release;
shared discovery remains gated. The create contract accepts
`expectedDisconnectGraceSeconds` (0–2592000) with a pool target. Acceptance
refuses a decreased quote with `sandbox.pool_policy_changed`; an increased
setting improves the accepted promise. Sandbox snapshots expose
`acceptedGraceSeconds` and `accessGraceUntil`. A cold placement never reduces a
previously accepted promise. Share and contributed-member quota refusals are
409 `sandbox.share_quota` / `sandbox.member_quota`; `WsspError.resource` names
`memory`, `vcpu`, or share `disk`. These refusals are definitive and do not
trigger automatic submission retries; `WsspError.retryable` tells a request
that exceeds the cap on its own (`false`) from one blocked by current usage
(`true`).

Pool-context template verification uses `poolId` plus an opaque `memberId` in
place of `hostId`. Registration through this branch requires an exact
`sha256:…` image fingerprint. Revision defaults stay private to the creator.
Users of pools with foreign hosts must trust those host operators: an
incus-admin operator can reach every VM on the host. Pool use also accepts the
contributed host's network and egress policy. Wire/journal qualification is
still required before enabling shared discovery.

## Transport

`createWsspTransport({ baseUrl, apiKey })` is the low-level client behind
`createWsspClient` (also exposed as `wssp.transport`); it sends exactly one
schema-validated request per route.

`baseUrl` is the API origin, optionally with a path prefix for a deployment
behind a reverse-proxy mount: `https://host`, `https://host/`, `https://host/api`
and `https://host/api/` all reach `<prefix>/v1/...`. Trailing slashes are ignored.

- Node/server-first ESM with bundled declarations; the only runtime dependency
  is `zod`. The public DTO schemas, error catalog and route registry from
  `@wssp/sandbox-contracts` are compiled in, so contract changes flow straight
  into the published types.
- Every request is schema-validated against the route registry; a body that
  does not match the documented shape is a typed `protocol` error (or an
  `unknown` mutation outcome), never a silent parse.
- Errors extend `WsspError`, discriminated by `kind`: `command_exit`, `authorization`,
  `not_found`, `gone`, `unavailable`, `timeout`, `capacity`, `unsupported`,
  `unknown`, `conflict`, `invalid_request`, `aborted`, `protocol`.
- A mutation that fails after it may have been sent (network cut, 5xx, timeout,
  an unverifiable response) reports kind `unknown` with the request's
  `idempotencyKey`: the effect may have happened, so poll or retry with the
  same key — never a new one. `gone` (expired content) and `not_found` stay
  distinct; `findSandbox` returns `null` only for a confirmed
  `sandbox.not_found`.
- `fetch` is injectable for tests and custom agents. Requests go out with
  `redirect: "manual"`; only bounded same-origin, method-preserving redirects
  are followed, so the bearer key can never leak cross-origin. The key never
  appears in error messages, causes or serialization.

## Lifecycle client

`createWsspClient` wraps the transport with readiness, lifecycle waits and
stable idempotency:

<!-- example: examples/lifecycle.ts -->

```ts
import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
  polling: { waitTimeoutMs: 10 * 60_000 }, // default bound of every wait
});

const sandboxId = "sbx_…";

// Rename. Names are unique among your live sandboxes (`sandbox.name_taken`,
// kind `conflict`) and free again once a sandbox is deleted. `update` returns
// a fresh read; a bound `Sandbox` handle's own fields stay its snapshot.
const renamed = await wssp.sandboxes.update(sandboxId, { name: "nightly-build" });
console.log(renamed.name);

// Set the relative lifetime, at most the advertised deployment maximum. `effective` is the
// lease the HOST acknowledged, not merely the one requested.
const { effective } = await wssp.sandboxes.setTimeout(sandboxId, {
  timeoutMs: 2 * 60 * 60_000,
});
console.log("host enforces", effective.expiresAt, effective.onExpire);

// Stop can interrupt boot. A retained disk ends STOPPED; cold connect reuses it.
// If boot never made an instance, Stop succeeds with DELETED and releases capacity.
const stopped = await wssp.sandboxes.stop(sandboxId);
if (stopped.state === "STOPPED") {
  const sandbox = await wssp.sandboxes.connect(sandboxId, { mode: "cold" });
  console.log(
    sandbox.state,
    sandbox.generation,
    sandbox.sandbox.cpuCount,
    sandbox.sandbox.memoryMiB,
  );
}

// One idempotency key per intent. An `unknown` outcome means the request may
// have taken effect: the SAME key replays the original receipt. Teardown
// recovery allows a new key only for current-generation UNKNOWN teardown;
// the SDK does not retry UNKNOWN automatically.
const idempotencyKey = `nightly-stop:${sandboxId}:2026-10-24`;
try {
  await wssp.sandboxes.stop(sandboxId, { idempotencyKey });
} catch (error) {
  if (!isWsspError(error) || error.kind !== "unknown") throw error;
  console.warn("outcome unknown for operation", error.operationId);
  await wssp.sandboxes.stop(sandboxId, { idempotencyKey });
}

// Liveness asks the host to probe the guest; it awaits that answer.
console.log("alive:", await wssp.sandboxes.isAlive(sandboxId));

// Discovery defaults to READY. Filters are exact-match AND in SQL before pagination.
const filters = {
  metadata: { purpose: "ci", team: "infra" },
  states: ["READY", "STOPPED"] as const,
};
const first = await wssp.sandboxes.list({
  metadata: filters.metadata,
  states: [...filters.states],
  templateId: "tpl_…",
  startedAfter: "2026-09-26T00:00:00.000Z",
  order: "desc",
  limit: 10, // numeric; the low-level HTTP transport still uses wire strings
});
if (first.nextCursor) {
  const next = await wssp.sandboxes.list({
    metadata: filters.metadata,
    states: [...filters.states],
    templateId: "tpl_…",
    startedAfter: "2026-09-26T00:00:00.000Z",
    order: "desc",
    limit: 10,
    cursor: first.nextCursor, // reuse with the same owner, filters and order
  });
  console.log(next.items.map((item) => item.id));
}
```

- Stop is accepted during boot (`REQUESTED`, `SCHEDULED`, `PROVISIONING`) and
  for `READY` or `RECOVERED`. Issued create effects settle before teardown;
  readiness is interrupted. A retained disk ends `STOPPED` and can be cold
  connected. Proven absence ends in `DELETED`, detaches the host and releases
  capacity, including when boot never created an instance. `stop()` succeeds
  in either case. Create another sandbox if you need a new disk. Stop cannot
  override an admitted or UNKNOWN destroy.
- One idempotency key is preserved through transport retries and polling: a
  lost accepted response is recovered by re-sending under the same key, never a
  new one, so an accepted create can never allocate a second VM. An
  `UNKNOWN_OUTCOME` operation is thrown as kind `unknown`; the SDK does not
  automatically retry it. Teardown recovery is the sanctioned exception: if
  the sandbox is STOPPING with a current-generation UNKNOWN kill or stop,
  call `destroy` (kill/DELETE) with a new key to request another teardown
  (202). `stop` with a new key can retry an UNKNOWN stop, but cannot supersede
  an UNKNOWN kill. In-flight kill returns 409; kill may supersede an in-flight
  stop. The same key replays the original receipt. The daemon also retries unresolved teardown automatically
  after reconnect and on heartbeat. Capacity stays reserved until proof.
- Waits poll with a bounded exponential interval (250 ms → 2 s by default),
  honor `Retry-After` (the JSON envelope field or the HTTP header, including
  header-only proxy 429/503 pages), and share one deadline across all phases.
  Rate/quota 429 responses are waited out with the same key until the deadline.
  So is `sandbox.host_reconnecting` (503, kind `unavailable`): the host's
  journal key is still being acknowledged after a relay reconnect. It is
  refused before anything is stored, so it is never `unknown`; a reconnect
  that outlasts the deadline throws that refusal.
  Every other catalog 4xx is final: no automatic retry, new key or fallback
  action. The one exception is `start`, which keeps polling its own result
  read while it answers `OPERATION_RESULT_NOT_READY`.
  Operation waits (`run`, `start`, `operations.wait`, lifecycle waits, `tail`)
  long-poll: each status, output or result read asks the server to hold it
  open until something changes (`polling.longPollMs`, default 20 s, at most
  25 s; `0` turns it off). A command that finishes 300 ms after it started is
  seen ~300 ms later instead of on the next poll interval, and a waiting
  command costs about three requests a minute. A server that predates
  long-poll answers the first `waitMs` read with 400; the client remembers
  that and polls plainly from then on. A server-paced answer that moves the
  output cursor is followed at once, and a run whose final output page reads
  `SUCCEEDED` needs no separate status read. One command's output reads are
  capped at a burst of 24 (a finished command's whole retained output) and
  then one every 2 s, so a command that prints continuously costs at most
  about 30 requests a minute, paginated or not. An answer that comes back early without
  news (for example at the server's own long-poll cap) falls back to the
  interval backoff, never a tight loop.
  The server budgets every `/v1` request, reads included: by default 100 per
  key, 300 per owner and 300 per client IP in each 60-second window
  (`RATE_LIMIT_SDK_*_POINTS`). A long-poll is one request however long it is
  held. Polling one sandbox twice a second from your own loop exhausts a key's
  budget in under a minute and returns `TOO_MANY_REQUESTS`; one SDK wait stays
  well under it, but many concurrent waits on one key share the same budget.
  If a call is still refused for capacity when the deadline passes, it
  throws that `capacity` error (for example `TRANSFER_QUOTA`), with its code
  and `Retry-After`, rather than a timeout.
  An earlier unresolved submission remains `unknown` after a later refusal.
  A deadline or abort throws a `timeout`/`aborted` `WsspError` carrying the
  `operationId` and `idempotencyKey` so the caller can resume — unless the
  interrupted request was a mutation SUBMISSION, which may have reached the
  server: then the kind is `unknown` with reason `timeout`/`aborted`, and the
  only safe retry is under the same key. Once a submission attempt ended
  `unknown`, that uncertainty persists through every later backoff and exit
  until a receipt resolves it.
- Create/connect return a bound `Sandbox` with lifecycle methods, `commands`
  (including qualified process discovery and controls) and `files`
  (including rich metadata pages and binary transfers). Only the sandbox ID and client
  are retained by these methods; create inputs and environment values are not.
- Create/connect/setTimeout wait for the accepted operation's exact durable
  lease ACK. A later shortening does not strand an earlier waiter. The returned
  renewal `effective` describes that operation's ACK; `sandbox.lease.effective`
  may already describe a later revision. READY must be the same boot generation.
- Create/connect default to 300000 ms; create defaults to
  `lifecycle: {onTimeout: "kill"}`. Choose `"stop"` at create to retain disk on
  timeout. Connect preserves the policy, extends only while READY, and boots the
  original disk while STOPPED. Omitted mode adapts to those states. setTimeout
  takes relative `{timeoutMs}` and may shorten or extend. `timeoutMs: 0` means no
  lease timer and is accepted only where `limits.sandboxTimeoutZero` (and, for a
  pool, `pool.lease.timeoutZero`) is true; such a sandbox's `endAt` is
  `9999-12-31T23:59:59.999Z` (`isUnlimitedLeaseEnd`). Capabilities advertise the
  deployment maximum; `pool.lease.maxTimeoutMs` is a pool's best path. A longer
  request fails with `lease_exceeds_policy` (`kind: "invalid_request"`) and
  `error.maxTimeoutMs`, the largest allowed value; nothing is clamped. Accepted
  retries keep their original deadline. Ship this SDK with the matching server:
  older SDKs parse error and operation codes strictly.
- `sandbox.endAt` is host-effective and null before ACK. Unknown timing stays
  null. `sandboxDomain` and `portExposure` are null; advertised ports flags are
  false. Pause, autoResume=true and ingress refuse before allocation.
- `wssp.operations.wait(id)` polls an operation to any terminal outcome;
  `wssp.sandboxes.waitReady` / `waitDeleted` poll sandbox state directly.
  Per-call `{ intervalMs, maxIntervalMs, waitTimeoutMs, signal }` override the
  client `polling` defaults. `waitTimeoutMs` bounds only the SDK wait. The old
  wait-only `timeoutMs` alias was removed, including from client polling
  defaults. Use `waitTimeoutMs` for lifecycle, file, transfer, operation and
  handle waits. On command submission, `timeoutMs` now means guest execution.
  On `connect`, the guest-side reconnect lease goes in `leaseTimeoutMs`.
- The wait deadline bounds every single request, not just the sleeps: an
  in-flight request is cancelled when the deadline expires, and a terminal
  answer that arrives past the deadline is rejected rather than accepted.
  Cancelling the caller's `signal` mid-request rejects with `aborted` carrying
  the `operationId`/`idempotencyKey` needed to resume.
- Plain reads (`get`, `find`, `list`, `operations.get`, `operations.getResult`) accept `waitTimeoutMs` as
  the request timeout and `signal` for cancellation.

## Disk offload

When the deployment has an image store, a stopped sandbox's disk may be
copied, encrypted, to the store and later freed from its host. Every sandbox
read carries `disk` (null while it has no disk): `location`
(`host | host_and_store | store`), `offloadState`, `offloadFailure`,
`offloadedAt`, `sizeBytes`, the restore `eligibility`
(`any_host | own_hosts | never`), `offloadPin` (`ANY` or `OWN_HOSTS`, set
by the owner in the dashboard), the offload policy `offloadPolicy`
(`on_stop`, `after` with `afterMs`, or `on_pressure`) and `offloadDueAt`
(when the policy makes the stopped disk due for export). Set the policy at
create (`offload`), with a stop (`stop(id, { offload })`, part of the
stop's request) or with `update(id, { offload })`. An evicted sandbox reads `OFFLOADED`;
`connect` restores it onto an eligible host, and `stop` resolves on
`STOPPED`, `OFFLOADED` or `DELETED`. A start refused 409
`sandbox.disk_evicting` (its cached disk is being evicted) is retried for you
under the same key. A stop during a restore is refused `sandbox.restoring`;
a restore with no allowed room fails `restore_no_allowed_host`, and one the
deployment cannot serve right now is refused `sandbox.disk_unavailable`.
Webhook `sandbox.offloaded` fires on `STOPPED → OFFLOADED`.

<!-- example: examples/offload.ts -->

```ts
import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";

// A stopped disk may be copied to the image store in the background
// (`disk.location`: host → host_and_store) and later evicted from its host
// (state OFFLOADED, `disk.location: "store"`). Stop resolves on any of
// STOPPED, OFFLOADED or DELETED.
const stopped = await wssp.sandboxes.stop(sandboxId);
console.log(stopped.state, stopped.disk?.location, stopped.disk?.offloadState);
if (stopped.disk?.offloadState === "failed") {
  // The disk stays on its host; `quota_exceeded` means the stored quota is used.
  console.log("not offloaded:", stopped.disk.offloadFailure);
}

// Offload policy: when a stopped disk is exported. `on_stop` (the default)
// exports at once; `after` waits `afterMs` of being stopped; `on_pressure`
// keeps it on its host until the host needs the space. Host pressure and
// `wssp host drain --offload` export early whatever the policy. Set it at create
// (`offload`), with a stop (`stop(id, { offload })`), or later with `update`.
const parked = await wssp.sandboxes.update(sandboxId, { offload: { mode: "on_pressure" } });
console.log(parked.disk?.offloadPolicy, parked.disk?.offloadDueAt); // null: not due
// Export it once it has been stopped for two hours, unless resumed first.
const later = await wssp.sandboxes.update(sandboxId, {
  offload: { mode: "after", afterMs: 2 * 60 * 60_000 },
});
console.log(later.disk?.offloadDueAt);

// Starting an OFFLOADED sandbox restores its disk onto an eligible host
// (progress phases fetching_disk, importing_disk). `disk.eligibility`
// says whether other users' hosts may take it (`any_host`) or only yours.
try {
  const sandbox = await wssp.sandboxes.connect(sandboxId, {
    mode: "cold",
    // Wait up to 10 minutes for a host this restore may use to have room.
    waitForCapacityMs: 10 * 60_000,
  });
  console.log(sandbox.state, sandbox.sandbox.disk?.location);
} catch (error) {
  if (isWsspError(error) && error.code === "restore_no_allowed_host") {
    // No allowed host had room before the wait ended; the stored copy is kept.
    console.log("add capacity or widen the key's allowlists, then start again");
  } else if (isWsspError(error) && error.code === "sandbox.disk_unavailable") {
    console.log("the image store or data key is not configured on this deployment");
  } else {
    throw error;
  }
}
```

## Commands, output and cancellation

`wssp.commands` runs commands and follows their incremental output:

<!-- example: examples/commands.ts -->

```ts
import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";

// Natural nonzero completion throws CommandExitError; check:false returns it.
const build = await wssp.commands.run(
  sandboxId,
  {
    argv: ["make", "test"],
    cwd: "/home/user/repo",
    envs: { BUILD_MODE: "test" },
    timeoutMs: 15 * 60_000,
  },
  {
    onOutput: (event) => {
      if (event.kind === "data") process.stdout.write(event.text);
      else if (event.kind === "gap") console.warn(`[output gap ${event.start}..${event.end}]`);
      else console.warn(`[output reset to attempt ${event.attempt}]`);
    },
  },
);
console.log("exit", build.exitCode, "truncated", build.truncated);

// Convenience helpers keep the guest budget separate from the local wait.
await wssp.commands.script(sandboxId, "make bootstrap", {
  timeoutMs: 15 * 60_000,
  waitTimeoutMs: 16 * 60_000,
});
await wssp.commands.argv(sandboxId, ["sleep", "5"], {
  timeoutMs: 10_000,
  waitTimeoutMs: 60_000,
});

// Start waits for a guest-attested identity, then returns without following.
const server = await wssp.commands.start(sandboxId, { script: "./serve --port 8080" });
await server.writeStdin("ready\n");
console.log(await server.stat());

// Aborting detaches this observer; the command keeps running.
const controller = new AbortController();
setTimeout(() => controller.abort(), 30_000);
try {
  await wssp.commands.script(sandboxId, "sleep 600", { signal: controller.signal });
} catch (error) {
  if (!isWsspError(error)) throw error;
  // `aborted`: observation stopped. An uncertain submission is `unknown`.
  console.warn(error.kind, error.operationId);
}

// A fresh client can attach to the exact tracked incarnation. Output emitted
// between this committed snapshot and wait() is included; prior output is skipped.
const attached = await wssp.commands.connect(server.process);
try {
  await attached.wait({ check: false, waitTimeoutMs: 30_000 });
} catch (error) {
  if (!isWsspError(error) || !["timeout", "aborted"].includes(error.kind)) throw error;
  console.warn("observer stopped", error.kind);
} finally {
  attached.disconnect(); // subscriber only; server.kill() explicitly cancels
}
await server.closeStdin(); // EOF; disconnect never closes guest stdin

// Check the effective capability before requesting no command timer.
// When the host supports it, zero removes only the command timer.
const capabilities = await wssp.sandboxes.capabilities(sandboxId);
if (capabilities.limits.commandTimeoutZero) {
  const reader = await wssp.commands.start(
    sandboxId,
    { argv: ["cat"], timeoutMs: 0 },
    {
      waitTimeoutMs: 30_000,
    },
  );
  await reader.writeStdin("bounded observation, independent execution\n");
  await reader.closeStdin(); // read-until-EOF otherwise stays open
  await reader.wait({ waitTimeoutMs: 60_000 }); // finite; expiry detaches, never kills
}
```

- Output is polled from `GET /v1/operations/{id}/output`: UTF-8 is decoded
  incrementally per stream (a code point may span chunks and pages; a trailing
  incomplete sequence is flushed as U+FFFD at the completion watermark), pages
  never skip past the previous `nextCursor` and may legitimately start earlier
  when the server merged segments — committed prefixes are trimmed, so a range
  is never repeated (even across an abort that interrupted an in-flight
  callback), gaps are
  reported as events and via `truncated`, and a dispatch-attempt reset
  restarts decoding at offset 0. The follow ends only at the completion
  watermark (`complete`), never at a terminal operation state alone, with one
  exception: once caught up on a command whose state is `UNKNOWN_OUTCOME`
  (its output stays open, so the watermark may never commit), `run`, `wait`
  and `tail` reject with kind `unknown` and the operation ID instead of
  waiting out the deadline. Resume with the same key or operation ID.
- Run-result accumulation is bounded: `maxOutputChars` (default 4 Mi
  characters, max 64 Mi) keeps only the trailing characters of each stream and
  reports the dropped count via `discarded`; `process.tail()` separately
  bounds itself with `maxChars`. A callback exception never reports the
  command stopped — the run rejects kind `unknown` with the operation ID and
  no caller-owned cause or output in automatic error formats. That
  failure is sticky: even when it loses a race with an abort, settlement
  re-throws it instead of replaying the range. Invalid run options
  (`maxOutputChars`, `cancelAckTimeoutMs`) are rejected before any network IO,
  so a misconfigured call never starts a command.
- A dispatch-attempt reset is applied once per attempt (tracked via the
  page's `attempt`), so an interrupted-and-replayed reset page never
  re-delivers output; and when a run exits for any reason while a callback is
  still blocked, the abandoned page task is fenced — it commits its current
  range and stops instead of invoking callbacks after `run()` settled.
- Natural nonzero completion throws `CommandExitError` by default from every
  run/string/script/argv and handle wait path. `check:false` returns its
  `RunResult`. Cancellation, guest timeout, UNKNOWN and observation failures
  retain their own kinds even when output contains an exit-like integer.
  Natural completion winning a cancellation race still gets the exit check.
- `CommandExitError` exposes explicit `stdout`/`stderr` tails (at most 64 KiB
  UTF-8 per stream), exit code, operation/process identity, output counters,
  truncation, `startOffset` and `outputAvailability`. String, stack, default
  inspection and JSON contain metadata only. A truly empty retained stream
  is `available`; expired output is empty with `outputAvailability: expired`
  and `truncated:true` when permanent exit evidence proves nonzero completion.
  With `check:false`, a requested full-output wait still throws `OUTPUT_EXPIRED`.
  Other output authorization, transport and protocol errors remain primary.
- `timeoutMs` is the guest budget on every command submission form, either
  in the input object or options, never both. Observer waits use
  `waitTimeoutMs`. Command budgets
  are integers: omission is 120000 ms, positive values are 1..1800000 ms,
  and **0 means no separate command timer**, bounded by lease and execution
  authority. Clients must check `limits.commandTimeoutZero`: zero is accepted
  only when true, with the current relay/runtime support. When false it refuses
  before IO. Zero is
  never silently remapped. The guest environment/bootstrap helper has
  a 5000 ms setup budget. The host gives up after the tools probe (up to 5000 ms)
  plus a 15 s host setup bound, so a hung start surfaces as `UNKNOWN_OUTCOME` after roughly
  15–20 s. SDK waits remain finite (at most 60 minutes). An explicit observer
  `waitTimeoutMs` always wins; otherwise run's default wait covers an explicit
  command budget plus one minute. Wait expiry never requests cancellation.
  Guest timeout has `operationErrorCode: "timeout"`; observer timeout has null.
  Command zero uses the normal finite observer default unless `waitTimeoutMs`
  is supplied. Lease renewal does not restart a positive command timer;
  shortening/expiry, disconnect or host authority revocation still ends work.
  Supervised stdin remains open: read-until-EOF can hang until `closeStdin()`
  or explicit EOF. Detaching never closes stdin or cancels the command. No timer
  adds no output retention and permits no process adoption after host restart.
- `start` requires current process-identity support and returns only
  after guest-attested start evidence, including fast completion. No background
  follow is installed, and the handle retains no command input, env, initial
  stdin or submission AbortSignal. Unsupported peers refuse before admission.
  Offline hosts refuse env-bearing work with `sandbox.host_unavailable`. Within
  30 s of a host's relay reconnect, before its journal key ACK, the refusal is
  `sandbox.host_reconnecting` (503), which the SDK waits out under the same
  key. A connected host that never acknowledges its key (for example, a
  non-canonical server origin) returns `digest_key_unavailable` (kind
  `conflict`). None of these refusals creates an accepted command.
- `commands.list` returns one bounded live page of tracked commands. Controls
  require a full `ProcessRef` (sandbox, generation, process ID, attempt and PID),
  never a naked PID or an inferred replacement process. `connect(ref)` obtains
  the server's committed attempt/cursor before returning. Its default live
  replay includes bytes emitted between attach and follow; `replay:"retained"`
  starts at zero and `fromCursor` resumes exactly. Cursor and replay are mutually
  exclusive. Reset/gap events remain visible in `onOutput`; `RunResult`/`Tail`
  expose `startOffset` so skipped history is explicit. Checked nonzero live
  waits retrieve available final tails with the bounded tail reader.
- `handle.disconnect()` is idempotent and stops only that observer, including
  late callbacks. Other handles, guest stdin, command slots and leases continue.
  Run/wait observation AbortSignal defaults to detach (`aborted`, phase `follow`),
  without cancel or implicit kill. Submission/start uncertainty remains `unknown`
  with the original key/operation. Connect and start handles always have a real
  process reference. A connected observer has no command submission key: its
  errors recover by operation ID/reference and never invent a replay key. An
  explicit cancellation key identifies the control action, not a command retry.
  Ordinary run can return `process:null` when no process identity was
  established; connected handles require a complete process reference.
- Explicit `onAbort:"cancel"` preserves bounded cancellation settlement for
  run/wait. It submits canonical operation cancellation with a domain-separated
  derived key and waits up to `cancelAckTimeoutMs` (default 30 seconds). A confirmed
  CANCELLED reports `aborted`; uncertain termination stays `unknown`.
  `commands.cancelAndWait(operationId)` remains available before start evidence.
- `kill(ref)` and `signal(ref,"SIGKILL")` share the PID kill route and canonical
  operation-ID cancellation. They return `killed` only after confirmed target
  cancellation, `alreadyExited` when the target completed with known effect
  evidence, or throw uncertainty: a FAILED target whose effect is unknown or
  missing throws `unknown`.
  An UNKNOWN command cancel, with the same or a new key, never claims another
  command effect. Recover with the returned identity; request sandbox stop or
  destroy if you need sandbox-wide teardown. Those lifecycle recovery rules do
  not authorize re-running the command.
- Read `guestApi.supportedSignals` to discover signal controls. TERM/INT/HUP
  use approved Branch A group-pidfd delivery on guest kernels ≥6.9 with helper
  support; otherwise invocation refuses `signal_unsupported_on_guest` before
  effect. There is no leader-only or numeric fallback. SIGKILL is canonical
  cancel. The typed helper preserves server `UNSUPPORTED_CAPABILITY` or the
  guest refusal without changed keys, fallback or implicit kill. Acceptance
  means delivery, never process death; trapped signals can leave work running.
- Qualified `writeStdin` and handle `writeStdin` share durable stdin
  acceptance. `closeStdin` sends empty bytes with EOF. A command that
  reads until EOF can keep waiting after observer detach; close it explicitly.
- `writeStdin` chunks are bounded to 32 KiB decoded and sent as canonical
  base64; an empty chunk requires `eof: true`. The server accepts stdin only
  once the operation has a dispatch attempt, so a run with initial stdin
  first waits for `dispatchedAt` on a queued command. The `SUCCEEDED` action
  receipt acknowledges atomic durable acceptance into that dispatch attempt,
  never guest consumption. New stdin refusals are direct 409s; the receipt
  does not follow the command's later exit.
- The serialized command payload (`{argv, script, cwd, envs}`, wrapper and
  escaping included) is validated against the 32768-byte server budget before
  any network IO, so an over-budget command is rejected locally with zero
  requests — including initial stdin, which is validated before the command
  is even started.

## Files and transfers

`wssp.files` moves file bytes through the server's transfer store; no file
bytes are stored in SQL or carried in JSON:

Rich helpers use the same protected kind-specific result boundary:
`files.list(path,{depth,limit,cursor})` returns one `Page<EntryInfo>` (default
limit 100), never an unbounded aggregate. Continue explicitly with `nextCursor`;
lists are live observations, not filesystem snapshots. Each directory page
rescans up to 100000 entries within a 30-second guest observation budget; use
the default maximum limit rather than tiny pages. The default ordinary procedure
budget permits at most 100 pages/minute shared with other work; HTTP and host
limits can lower that. No large-tree performance promise or automatic refresh
is implied. `stat` returns rich
metadata plus its operation ID, `getInfo` returns an entry or throws, `makeDir`
returns the actual created boolean, `rename` returns the resulting entry, and
`remove` defaults to nonrecursive. The same helpers are available bound to a
`Sandbox`. `operations.getResult` reads a single strict versioned result.

`FileSystemError.filesystemKind` preserves the precise `fs_*` code; guest
permission/read-only errors do not become key authorization failures.
Mutation outcomes inherently reveal existence (for example created=false or an
existing-file collision) to `files:write`; that does not grant stat/list access.
`ProcessError.processKind` distinguishes stale, exited, unavailable and unknown
incarnations. `stat`/`exists` convert only confirmed `fs_not_found`, after authorized result version/expiry checks.
Unversioned legacy results throw `OPERATION_RESULT_UNSUPPORTED`, expired
versioned observations throw `OPERATION_RESULT_EXPIRED`, and sandbox/operation
404s always throw. Neither retained status nor a coarse missing code bypasses
result retention. Validation failures retain no received body, Zod details or
raw cause, including forged paths and command descriptions.

<!-- example: examples/files.ts -->

```ts
import { createReadStream, createWriteStream } from "node:fs";
import { stat } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";
const limits = await wssp.files.limits(); // per-transfer cap, 1 MiB chunks
console.log("max transfer bytes", limits.transferMaxBytes);

// Streaming upload. A factory source can be re-read, so a retry with the SAME
// idempotency key resumes after the chunks the server already acknowledged.
const local = "./repo.tar";
const { size } = await stat(local);
const uploaded = await wssp.files.upload(
  sandboxId,
  "/home/user/repo.tar",
  () => createReadStream(local),
  { totalBytes: size, idempotencyKey: `upload:${sandboxId}:repo.tar` },
);
console.log("sha256", uploaded.sha256);

// Streaming download: one capture of the guest file, validated as it flows.
const download = await wssp.files.download(sandboxId, "/home/user/repo/report.json");
await pipeline(download.nodeStream(), createWriteStream("./report.json"));

// Small files: bounded in-memory conveniences (client cap 32 MiB).
await wssp.files.writeBytes(sandboxId, "/home/user/note.txt", new TextEncoder().encode("hi\n"));
const note = await wssp.files.readBytes(sandboxId, "/home/user/note.txt");
console.log(new TextDecoder().decode(note), await wssp.files.exists(sandboxId, "/tmp/x"));

// Rich observations are bounded live pages; continuation is explicit.
const page = await wssp.files.list(sandboxId, "/home/user", { limit: 100 });
console.log(page.items, page.nextCursor);
const info = await wssp.files.getInfo(sandboxId, "/home/user/note.txt");
console.log(info.size, info.permissions);
console.log("created", await wssp.files.makeDir(sandboxId, "/home/user/reports"));
await wssp.files.rename(sandboxId, "/home/user/note.txt", "/home/user/reports/note.txt");
await wssp.files.remove(sandboxId, "/home/user/reports/note.txt"); // nonrecursive
```

- Uploads are resumable, chunked at a fixed 1 MiB, and reserve their declared
  length before any byte moves. The default per-transfer cap is 1 GiB
  (`TRANSFER_MAX_BYTES`, also the ceiling); `files.limits()` reports the
  deployment's values. A full store is `TRANSFER_QUOTA` (429, kind
  `capacity`). Calls retry it under `Retry-After` until their deadline, then
  throw that `capacity` error. A transfer stops counting against the store as
  soon as it settles.
- An upload commits atomically in the guest: bytes are staged next to the
  destination, verified by length and SHA-256, then renamed. A cancellation
  that wins first leaves the destination untouched; an outcome the host cannot
  prove is `unknown`, never success.
- A download is one capture of the guest file, sealed with a whole-file
  SHA-256 and served by byte range. `resumeDownload` continues at an offset
  only while the capture's ETag still matches. Once every byte has been
  delivered (by one stream, or by an interrupted one plus its resume), the
  capture stops counting against the store at once, and its content is kept
  for a 60-second grace and then retired. "Delivered" means the server handed
  the bytes to the network, so a client that drops near the end can still
  `resumeDownload` the tail within the grace; a resume in the grace needs a
  free transfer slot. A server restart ends the grace. Captures that are never
  fully read expire after 15 minutes idle or one hour absolute by default.
  Retired or expired content is `TRANSFER_EXPIRED` (410, kind `gone`), and the
  operation receipt stays readable.
- `readBytes`, `writeBytes` and `FileDownload.bytes()` hold the whole file in
  client memory and are capped at 32 MiB (`DEFAULT_FILE_MEMORY_BYTES`). That is a
  client bound only; use the streaming calls for anything larger.
- Guest paths are paths in the VM's filesystem, read and written as the
  template's guest user. Every file operation (stat, list, mkdir, move,
  remove, reads and uploads) refuses a symlink in any ancestor component and
  `..`. Reads and uploads also refuse a final symlink and non-regular files;
  stat and list report a final symlink as an entry, move and remove act on the link itself, never its target, and
  mkdir refuses an existing link. Paths must be absolute, at most 4096 UTF-8 bytes, with no
  NUL, unpaired surrogate or leading or trailing whitespace (paths are never
  trimmed; internal spaces are fine). `mkdir`, `move` and `remove` refuse a
  bare `/`. Uploads and downloads also refuse a `.` component, a bare `/` and
  control characters. The SDK refuses
  these locally (`invalid_request`) and the server answers 400 before any
  transfer is reserved.

## Errors

Every failure is a `WsspError`; branch on `kind`, never on the message. `code`
carries the server's stable code when one was returned, for example
`sandbox.not_found`, `sandbox.host_draining`, `sandbox.idempotency_conflict`
or `UNSUPPORTED_CAPABILITY`. The full catalog is `SDK_ERRORS` (exported by
this package) and the OpenAPI document's `x-wssp-error-catalog`; this page
names no code outside it.

A create or cold start refused with `UNSUPPORTED_CAPABILITY` carries a
`reason` for egress refusals:

- `egress_guard_unavailable`: the host's root-owned network guard is not
  running, so no sandbox can start there. Retry later or use another host or
  pool; the host owner fixes it with `wssp host guard install`.
- `open_egress_not_permitted`: an open-internet sandbox on another user's host
  whose owner no longer allows it. That sandbox cannot restart there; create a
  new sandbox.

A failed operation reports the same codes as its `operationErrorCode`. Without
a `reason`, the host does not enforce egress policies at all: `GET /v1/hosts`
reports it as `egressEnforcement: false`, and the cause (for example an Incus
release older than 6.14, or a missing network ACL extension) is in the
daemon's log; the requirements are in the
[hosts guide](../../docs/guide/hosts.md#requirements).

## Private environment and metadata contracts

Command environment overrides use `envs: Record<string, string>`. The legacy
`env` tuple field is rejected. Maps allow 64 unique POSIX names (128 UTF-8 bytes),
4096 UTF-8 bytes per value and 16384 bytes of sorted, escaped JSON in total.
NUL, malformed Unicode and prototype names are rejected before submission.
HOME and SHELL overrides are accepted but ignored; TERM still applies to piped
commands. Workload values travel over a bounded stdin frame, never host argv.

Metadata is string → string only, with at most 32 entries, 64 UTF-16 units per key,
1024 per value and 8192 UTF-8 bytes of JSON. Non-string values, NUL, malformed
Unicode and prototype-related keys are refused. Old scalar metadata is no longer
accepted or converted on read; disposable pre-launch rows must be recreated.

Sandbox discovery defaults to READY. Use `states` to request history; the dashboard
explicitly requests its active/deleted/all history view. `metadata` matches every
supplied pair exactly, together with `states`, logical `templateId` and/or exact `templateRevisionId` and strict
`startedAfter`. `order` sorts `(createdAt, id)` ascending or descending (default).
All filtering and SDK grant visibility happen in SQL before `limit + 1` is taken.
Sandbox cursors refuse different owners, filters or order; page size may change.
Other resources retain their existing cursors; SDK discovery accepts numeric
`limit` values and encodes them for the HTTP query. On the raw
HTTP transport only, `metadata` is one JSON string and `states` is one comma-separated
string; repeated parameters, duplicate metadata keys and malformed JSON are refused.

## Webhooks

A key with `webhooks:write` manages webhook endpoints. The scope can be minted
only on an **all owned** key with **all usable** pools
(`sdk_key.webhooks_requires_all_owned`): an endpoint receives events for every
sandbox on the account. Events are `sandbox.ready`, `sandbox.stopped`,
`sandbox.create_failed`, `sandbox.destroyed`, `sandbox.offloaded`, `operation.completed`
(filtered by operation kind; lifecycle kinds and `RUN_COMMAND` by default,
`"all"` for every kind) and the CLI-login events `credential.capture_failed`,
`credential.capture_lost`, `credential.recovery_required` and
`credential.needs_login` (ids and a reason code only). Deliveries are signed with the
[Standard Webhooks](https://www.standardwebhooks.com/) scheme, retried for 24
hours, at-least-once and unordered. `verifyWebhook` is exported from
`@wssp/sdk` and from the `@wssp/sdk/webhooks` subpath. See
[the webhooks guide](../../docs/guide/webhooks.md).

<!-- example: examples/webhooks.ts -->

```ts
import { createServer } from "node:http";
import { createWsspClient } from "@wssp/sdk";
import { verifyWebhook, WebhookVerificationError } from "@wssp/sdk/webhooks";

// 1. Register an endpoint with a key that has `webhooks:write` (an all-owned,
//    all-usable key). The signing secret is returned ONCE: store it now.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const { endpoint, secret } = await wssp.webhooks.endpoints.create({
  url: "https://hooks.example.com/wssp",
  events: ["sandbox.ready", "sandbox.create_failed", "operation.completed"],
});
console.log(`endpoint ${endpoint.id}; save the secret in your secret store`);
await wssp.webhooks.endpoints.test(endpoint.id); // a signed `webhook.test` delivery

// 2. Receive. Verify the RAW body bytes, dedupe by `webhook-id` (delivery is
//    at-least-once and unordered), answer 2xx fast, and process later.
const seen = new Set<string>(); // use a durable store with a ≥ 24 h TTL in production
createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (chunk: Buffer) => chunks.push(chunk));
  req.on("end", () => {
    try {
      const event = verifyWebhook({
        body: Buffer.concat(chunks),
        headers: req.headers,
        secret, // during a rotation pass both: [newSecret, oldSecret]
      });
      res.writeHead(204).end();
      if (seen.has(event.id)) return;
      seen.add(event.id);
      if (event.type === "sandbox.ready") console.log("ready", event.data);
    } catch (error) {
      res.writeHead(error instanceof WebhookVerificationError ? 400 : 500).end();
    }
  });
}).listen(8080);
```

## Template builds

`client.templates.build(template, options)` turns a `Template()` recipe into a
new revision of a template. It packs `contextDir` first (a deterministic
ustar, only when the recipe has `copy` steps) to compute `contextSha256` and
`contextBytes`, accepts the build (`POST /v1/template-builds`), uploads and
seals the context, removes the temporary tar, and then follows the build to
its end. The build runs in a managed VM on one of your builder hosts; steps
may run as guest root inside that VM only. SDK keys move the `latest` tag.

Packing walks the context through open directory descriptors
(`/proc/self/fd`), so nothing outside `contextDir` can be swapped in while it
is read. Where that anchoring is unavailable (every platform but Linux), the
pack is refused with a `WsspError` of kind `unsupported` and reason
`unanchored_context`. `context: { allowUnanchoredContext: true }` packs anyway
by pathname with identity re-checks; the residual is a concurrent attacker on
your own machine who can write inside the context and swap a directory out and
back between an open and its re-check, which could upload outside files. Opt
in only when nothing untrusted can write to the context while it is packed.

An identical earlier build is reused (`cacheHitRevisionId`, nothing runs)
unless the recipe calls `skipCache()`; an identical build in progress for the
same key and target is joined. An allowlist key sees and cancels only the
builds it started; an all-owned key sees every build of the account. Refusals
carry typed fields on `WsspError.build`, for example `recipeCode`, `line` and
`column` of `template.build_recipe_invalid`. `getBuild`, `listBuilds`,
`cancelBuild` and `buildLogs` address builds directly. While following, a
transient read failure (network, timeout, 5xx, 429) is retried with backoff
(six tries, 500 ms doubling to 8 s, honoring `Retry-After`); the build keeps
running server-side either way, and if the follow does give up,
`getBuild(id)` picks it up again. See
[the template builds guide](../../docs/guide/template-builds.md).

<!-- example: examples/template-builds.ts -->

```ts
import { createWsspClient, isBuildFailed, Template } from "@wssp/sdk";

// A key with `templates:build` (plus `templates:write`, because `name` creates
// the template when it does not exist yet).
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const template = Template()
  .fromTemplate("base") // your registered base template (slug, slug:tag or revision/<id>)
  .aptInstall(["jq"])
  .setEnvs({ APP_ENV: "production" })
  .setWorkdir("/home/user/app")
  .copy("app/", "./", { owner: "user" })
  .runCmd("make install")
  .egress({ presets: ["ubuntu-apt"] });

// Packs ./context (ustar, hashed), accepts the build, uploads the context,
// then follows the build to its end, streaming step output.
const build = await wssp.templates.build(template, {
  name: "my-app",
  hostId: "<owned-host-id>",
  contextDir: "./context",
  timeoutMinutes: 20,
  onBuildLogs: (entry) => {
    if (entry.type === "phase") console.log(`==> ${entry.message}`);
    else if (entry.type === "output") process.stdout.write(entry.text);
  },
});
if (isBuildFailed(build)) {
  console.error(`build ${build.id} ${build.state}: ${build.errorCode} ${build.errorDetail ?? ""}`);
} else {
  // `latest` of my-app now points at the new revision.
  console.log(`revision ${build.revisionId ?? build.cacheHitRevisionId}`);
}
```

The follow long-polls: build reads and step-log reads pass `waitMs`, so the
server answers when the build or the step's output changes. Step-log reads
are paced like a command follow (a burst, then at most one every 2 s), and a
blocked-name hint recorded after a step's output ended is still streamed. A
hand-written follow should do the same (`GET /v1/template-builds/{id}?waitMs=20000`)
rather than poll: the `/v1` budget is 100 requests per key per minute.

### Community bases

`client.templates.createFromCommunity({ source: "ubuntu-26.04", hostId })`
(or `poolId`) creates your template managed by WS Sandbox Proxy for a tested community image
and accepts its first prep build (`POST /v1/templates/community`). The key
needs `templates:write` and `templates:build` and must see every template and
revision: an allowlist key gets `template.community_key_scope`. The answer is
`{template, build, existing}`. A second call for the same `source` returns the
existing template and its active build, so follow `build.id` with `getBuild`.
The template refreshes itself; see
[Community bases](../../docs/operations/templates.md#community-bases).

## CLI logins

A key with `credentials:write` manages CLI logins: definition versions, logins,
provider accounts (pause lives on the account) and instances (independent token
sets). Values are **write-only**: an upload returns metadata, and no route ever
returns a value. An all-owned key sees every login; an allowlist key sees only
the logins granted at mint. Delivery, copy-back, foreign-host opt-in and re-pin
are dashboard-only. A key with `credentials:use` may attach/free logins or pin
them on a cold start with `sandboxes:manage`, and name them at create with
`sandboxes:create`. An allowlist key with `credentials:use` must name at least
one login at mint. A refused upload throws `credential.value_invalid` with
`error.valueInvalid` (`entry`, such as `env.TOOL_API_KEY` or
`bundle.undeclared_path`, and `path` for a file); neither ever holds a value.
`credentials.leases.list` returns an instance's live leases (the ids
`leases.forceRelease` takes) with the checkpoint `promoteCheckpoint` would keep.
See [the CLI logins guide](../../docs/guide/cli-logins.md).

<!-- example: examples/credentials.ts -->

```ts
import { readFile } from "node:fs/promises";
import { createWsspClient } from "@wssp/sdk";

// A key with `credentials:write` (and `credentials:read` to list). Values are
// write-only: nothing below ever reads one back.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

// 1. Store your own login definition (see docs/guide/cli-logins.md).
const definition = await wssp.credentials.definitions.create({
  text: await readFile("tool-login.json", "utf8"),
});

// 2. A login pinned to that version, one account, one instance.
const login = await wssp.credentials.create({ name: "tool", definitionId: definition.id });
const account = await wssp.credentials.accounts.create(login.id, { name: "work" });
const instance = await wssp.credentials.instances.create(login.id, account.id);

// 3. Upload the token files (base64) and env; the response is metadata only.
const written = await wssp.credentials.instances.writeValue(login.id, instance.id, {
  files: [
    { path: ".config/tool", kind: "dir" },
    {
      path: ".config/tool/token.json",
      contentBase64: (await readFile("token.json")).toString("base64"),
    },
  ],
});
console.log(`instance ${written.instanceId} is ${written.state} at seq ${written.storageSeq}`);

// 4. With `credentials:use` and `sandboxes:manage`: attach the login to a
//    running sandbox (new commands and terminals see it), then free it: the
//    env leaves at once, terminals opened with it close, and the files are
//    copied back and scrubbed. A stopped sandbox claims an attached login at
//    its next start; `connect({ credentials })` pins an account or instance.
const sandbox = await wssp.sandboxes.connect(process.env.WSSP_SANDBOX_ID ?? "");
await sandbox.credentials.attach({ credentialId: login.id, accountId: account.id });
await sandbox.commands.run({ argv: ["tool", "whoami"] });
await sandbox.credentials.free(login.id);

// 5. Pause the account: new sandboxes stop using it, running ones keep it.
await wssp.credentials.accounts.update(login.id, account.id, { paused: true });

// 6. Recover a stuck holder (`credentials:read` + `credentials:write`): list
//    the instance's live leases, then force-release one, keeping the newest
//    value its guest checkpointed.
const leases = await wssp.credentials.leases.list(login.id, instance.id);
const held = leases.items.find((lease) => lease.sandboxId === sandbox.id);
if (held)
  await wssp.credentials.leases.forceRelease(login.id, instance.id, held.id, {
    promoteCheckpoint: held.checkpoint !== null,
  });
```

## Browser templates

Template authors can prepare an agent-browser VM image using the tested
[recipe](../../docs/guide/recipes/agent-browser.md). WS Sandbox Proxy ships no browser
image. After registering your image, use its verified revision and grant the
page domains explicitly; the guest browser is already cached in the image.

<!-- example: examples/agent-browser.ts -->
```ts
import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
  polling: { waitTimeoutMs: 10 * 60_000 },
});
const hostId = "<owned-host-id>";
const revisionId = "<verified-agent-browser-revision-id>";

const sandbox = await wssp.sandboxes.create({
  cpuCount: 2,
  memoryMiB: 2048,
  sandboxHostId: hostId,
  template: `revision/${revisionId}`,
  // Allowlist mode: only these names (host-resolved IPv4 addresses) are reachable.
  allowInternetAccess: false,
  egress: { domains: ["example.com", "en.wikipedia.org", "upload.wikimedia.org"] },
  timeoutMs: 30 * 60_000,
  lifecycle: { onTimeout: "kill" },
});
try {
  // Sandbox on. Other mode: agent-browser --args --no-sandbox open <url>
  const result = await wssp.commands.script(
    sandbox.id,
    "agent-browser open https://example.com && agent-browser screenshot /home/user/shot.png",
    { timeoutMs: 120_000 },
  );
  const png = Buffer.from(
    await (await wssp.files.download(sandbox.id, "/home/user/shot.png")).bytes(),
  );
  console.log(result.exitCode, png.byteLength);
} finally {
  await wssp.sandboxes.destroy(sandbox.id);
}
```

## Files/process release compatibility

`commands:read` on a granted sandbox exposes all tracked browser/other-key
commands and argv/cwd and permits protected output attachment, regardless of
launcher. Keep secrets in envs/private config, not argv. This is owner-scoped,
never admin cross-owner execution authority.

See [filesystem and command behavior](../../docs/guide/sandboxes.md#filesystem-and-command-result-limits)
for scopes, retention and cost limits and the guest support matrix. Signals
require `operations:cancel` plus `commands:execute` and have a per-sandbox limit
of 5. A naked PID is refused before a receipt; pass a tracked ProcessRef. Stdin refuses
directly with 409 and its action receipt represents durable acceptance, never
consumption or target completion.

Dashboard and all keys share owner budgets per minute: ordinary 100, stdin 600,
termination 30, independently of existing HTTP/transfer/lifecycle budgets.
A 429 waits out Retry-After using the same key; every other catalog 4xx is final
except start's explicit OPERATION_RESULT_NOT_READY polling. `startedAfter`
requires seconds. Native expired results are 410 OPERATION_RESULT_EXPIRED;
output is 410 OUTPUT_EXPIRED, never an empty success.

Lists default/cap at 100 and return bounded live pages, not a snapshot or
unbounded array. Directory pages rescan O(N); byte caps can shorten a page.
Stat/list/process observations retain for one hour from acceptance; rename
content for 24 hours from acceptance; output and private command descriptions
for first completion plus 24 hours. Owner result
storage reserves 24 KiB per pending content operation under a 32 MiB ceiling,
then shrinks to actual stored bytes. Renewal grants no extra retention.

UNKNOWN cleanup can leave guest work alive. There is no command retry, even
with a new cancellation key: recover via sandbox stop/kill, not another command
effect. UNKNOWN/STOPPING lifecycle recovery uses the supported sandbox lifecycle
flows. Observer disconnect neither closes stdin nor cancels.
SDK-key revocation fences reads/unsent controls but does not cancel accepted
commands. Host setup is bounded to 15 seconds after the tools probe; startup
over that bound ends UNKNOWN_OUTCOME independently of command timeout.

The default documented guest is images:ubuntu/26.04/cloud; 24.04 stays supported.
24.04 GA non-kill signals refuse; verify the booted HWE kernel ≥6.9 and helper
probe before expecting approved-A delivery. See the existing
[agent-browser recipe](../../docs/guide/recipes/agent-browser.md).
Release the SDK with matching server and daemon artifacts. Signal and timeout
validation policy is compiled in.

## VM size

Create accepts independent optional `cpuCount`, `memoryMiB`, and `diskGiB`: CPU 1–32,
RAM 512–65536 MiB in 256 MiB steps, and root disk 1–2048 GiB. Each omitted field
uses the selected revision's default. New revisions default to 1 vCPU, 1024 MiB,
and a 32 GiB root; append never inherits another revision's policy.
Get/find/list and bound sandbox reads expose the accepted size and opaque storage
binding. Stop retains that root on its original host and pool; cold connect
reuses it. Reconnect accepts no resize or placement fields.

Host discovery exposes charged/free RAM and vCPU, retained root counts, and bounded
storage pool summaries. RAM charges include the shared per-VM overhead. Root
commitments include the configured root size plus the shared disk allowance and
remain held through STOPPED/UNKNOWN. Pool caps describe commitments, not physical
usage isolation. Configure host budgets and pools locally on the daemon.

Capacity refusals use `sandbox.host_capacity` or `sandbox.pool_full` (409), with
`WsspError.reason` equal to `ram`, `vcpu`, `disk`, `storage`, or `ceiling`.
These definitive refusals make one submission; 429/5xx/lost responses retain
same-key retry behavior. Invalid local size inputs fail before any fetch.
Invalid remote sizes use `sandbox.vm_size_invalid`; valid sizes exceeding a
per-VM cap use `sandbox.vm_size_unsupported`; pinned conflicts use
`sandbox.vm_size_mismatch`. Every revision has a `minDiskGiB` (its image's
root disk: a captured or built image is its source VM's whole root) and a
`defaultDiskGiB` (what a create gets when it omits `diskGiB`). A create below
`minDiskGiB` is refused up front with `sandbox.disk_below_image` (400,
`invalid_request`); omit `diskGiB` or request at least that size. A larger
disk grows the guest's root filesystem at create; if it cannot (an image
without `growpart`/`resize2fs`, or an unsupported root layout), the create
fails with `root_disk_not_grown` (`kind: "unsupported"`) and the VM is
destroyed. Explicit defaults and omission remain distinct idempotency intents.

Discovery includes disk limits/defaults, fixed overhead, and the managed-root
ceiling. Per-sandbox features require a connected host with the complete capacity
report. Update schema, server, daemon and SDK together: relay protocol 1.0 is
the sole supported version, and mixed-version deployments are not supported.

## Harness create and fallback policy

Choose a permitted pool and exact template/size. `pools.capacity().fits` models
a credential-free workload with the default lease; it does not test custom
leases or attached logins, reserve capacity, or guarantee create admission.
Omit capacity waiting when immediate fallback to e2b is desired.

Classify by the exact code and create outcome. `WsspError.kind === "capacity"`
also includes rate/result/transfer/build/login limits and is insufficient.

| Code / outcome                                                                                                                                                                                                                                                                        | Harness decision                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capacity, quota and pool refusals (409 `sandbox.host_capacity`, `sandbox.pool_full` including reason `reserved`, `sandbox.pool_unavailable`, `sandbox.pool_no_compatible_host`, `sandbox.share_quota`, `sandbox.member_quota`, `sandbox.capacity_queue_full`) with `retryable: false` | **Fall back now** (for example to e2b), or change the request. The request alone can never be admitted as configured: it exceeds a cap or every eligible member is disabled. No `Retry-After` is sent; retrying the same request cannot succeed. The request was not accepted (no create, start or capture began).                                          |
| The same codes with `retryable: true`                                                                                                                                                                                                                                                 | **Back off** for `retryAfterSeconds` / `Retry-After` (the deployment's `CAPACITY_RETRY_AFTER_SECONDS`, default 30), then retry, or fall back at once if your deadline cannot absorb a wait. Current usage, queue depth or online state blocks it. The request was not accepted (no create, start or capture began). Record `reason`, `resource` or `scope`. |
| Terminal FAILED CREATE with `host_capacity` or `capacity_wait_timeout`                                                                                                                                                                                                                | **Fall back now** after reading authoritative terminal status; retain operation, sandbox and idempotency identities for cleanup/reconciliation. These are operation codes, unlike the prefixed admission codes.                                                                                                                                             |
| `TOO_MANY_REQUESTS` / HTTP 429, `sandbox.host_reconnecting`                                                                                                                                                                                                                           | **Back off** using `retryAfterSeconds` / Retry-After and the same request/key. A rate budget is not fleet capacity.                                                                                                                                                                                                                                         |
| `sandbox.host_unavailable`, `sandbox.host_draining`                                                                                                                                                                                                                                   | Explicit pre-acceptance refusal: back off by default, or fall back under a configured provider-availability policy. Never apply this rule to an arbitrary 5xx.                                                                                                                                                                                              |
| `sandbox.vm_size_invalid`, `sandbox.vm_size_unsupported`, `sandbox.disk_below_image`, `lease_exceeds_policy`, `capacity_wait_exceeds_policy`, auth/grant/input failures                                                                                                               | **Fix the request or policy**; do not hide configuration failures as full capacity.                                                                                                                                                                                                                                                                         |
| `kind: "unknown"`, local timeout/abort, lost response, unclassified mutation 5xx                                                                                                                                                                                                      | **Unknown — reconcile the original idempotency key first.** Reuse the original intent/key to recover acceptance, then follow the operation to a terminal outcome before starting another provider.                                                                                                                                                          |

`retryable` is required on every code in the first two rows (`WsspError.retryable`
in the SDK; `null` on every other error). It reuses the static feasibility the
capacity queue applies: `false` when no visible member could ever hold the
request (VM larger than every member's budget or member cap, a share cap
smaller than the request, every member disabled, no compatible host, a queue
limit of 0); `true` when current reservations, usage, queue depth or member
online/draining state blocks it. It is a classification, not a promise that
capacity frees within `Retry-After`. A pool whose members never reported a
resource budget counts as statically infeasible, as it does for the queue.

An accepted operation is followed to settlement. A polling timeout only ends
observation; it does not cancel a create. Do not submit the same workload to e2b
while wssp may still create or execute it. Never regenerate a key to bypass an
unknown result, any 409, or a configured policy refusal.
