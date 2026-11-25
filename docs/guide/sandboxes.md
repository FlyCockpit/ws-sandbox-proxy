# Sandboxes and operations

A sandbox is one Incus KVM virtual machine (`wssp-sbx-<sandboxId>`) on one of
your hosts, booted from an exact verified template revision. Every change to it is an
**operation**: a durable, idempotent request the server dispatches to the host
and records the outcome of. The dashboard, `/v1` and `@wssp/sdk` all use the
same operations; the [SDK README](../../packages/sdk/README.md) shows them in
code and the [native HTTP contract](../design/native-http-contract.md) gives the
wire details.

Create accepts an owner-local slug, `slug:tag`, `template/<logicalId>` or
`revision/<revisionId>`. Logical templates, revision pages and per-host
availability are separate. ALLOWLIST keys grant exact revisions. A new append
does not expand a key. [SDK resource grants](auth-planes.md#minting-sdk-resource-grants).

## Names

Every sandbox has a name. Create takes an optional `name`; without one the
server picks a free adjective-noun name such as `quiet-otter` (with a
`-xxxx` suffix if the plain names it tried are taken). Rename with
`PUT /v1/sandboxes/{id}` (`{ "name": … }`), the SDK's `sandboxes.update`, or
Rename on the dashboard's sandbox page. A rename changes only the name: it is
not an operation, takes no idempotency key and emits no webhook. The same
call also sets the [offload policy](#offload-policy) (`{ "offload": … }`;
either field or both).

- A name is a lowercase DNS label: 1–63 characters of `a-z`, `0-9` and inner
  hyphens. It is never UUID-shaped and never starts with `wssp-` (instances
  are `wssp-sbx-<id>`). An invalid name is refused with 400
  `sandbox.name_invalid`; it is never rewritten.
- Names are unique per owner among live sandboxes. A taken name is 409
  `sandbox.name_taken`. A DELETED sandbox frees its name for reuse. ERROR and
  HOST_LOST sandboxes keep theirs until they are deleted. Sandboxes WS Sandbox Proxy runs
  for you (login and build VMs) never hold a name you want.
- Uniqueness is per owner, across all your keys. A key that is allowed to
  create or rename can therefore learn that one of your live sandboxes already
  uses a name.
- Names are yours: admins and the owners of hosts or pools your sandboxes run
  on never see them. Sandboxes created before names existed got a
  `sandbox-<12 hex>` name; rename them freely.

## Dashboard VM size

In **Sandboxes → Create sandbox**, choose an owned host or a group, then a
logical template or an exact revision from the paged picker. Exact revision
options show their default vCPU count and memory in MiB. **Latest tag (resolved
once at acceptance)** resolves at server acceptance; a picker reading is
advisory and can change before then.

The two **VM size overrides** fields are independent. Leave either blank to
omit it from the request and inherit that dimension from the revision the
server accepts. Entering 2 vCPUs with blank memory overrides only CPU; blank
CPU with 3072 MiB overrides only RAM. CPU accepts integers 1–32 and memory
accepts 512–65536 MiB in steps of 256. Blank never means zero or a global
fallback. A lost-response retry preserves the exact original body and key,
including omitted fields, even after template discovery changes.

The sandbox list and detail page show **Allocated VM size** from the accepted
sandbox, including overrides. It stays fixed across stop, cold start, template
appends and tag changes; there is no resize control. Stop frees reserved RAM
only after positive host proof, keeping disk and allocation. UNKNOWN work
keeps its reservation while recovery establishes the outcome.

Invalid input is refused before acceptance. A valid size above a host's
per-VM cap shows a size-unsupported message; an occupied RAM budget or slot
limit shows host capacity or group-full. Choose another target or change the
size after a definite refusal. See [host capacity](hosts.md#dashboard-capacity)
for budgets, stale reports and overcommit.

## Lifecycle

| State                                    | Meaning                                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `WAITING_FOR_CAPACITY`                   | A pool create waiting in the pool's queue; no host, disk or lease yet                                           |
| `REQUESTED`, `SCHEDULED`, `PROVISIONING` | Accepted; the host is creating and booting the VM                                                               |
| `READY`                                  | Running, and the guest passed the readiness check as the template's user                                        |
| `STOPPING`, `STOPPED`                    | Teardown pending / shut down with its disk kept                                                                 |
| `OFFLOADED`                              | Stopped, and its disk lives only in the image store; no host, capacity or lease ([disk offload](#disk-offload)) |
| `RECLAIMING`, `DELETED`                  | Being destroyed / destroyed (VM and its network removed)                                                        |
| `UNREACHABLE`, `HOST_LOST`               | The host is not answering; the VM's real state is not known                                                     |
| `RECOVERED`                              | The host came back and reported the sandbox again                                                               |
| `ERROR`                                  | A failure the host reported, for example `expiry_failed` or `instance_missing`                                  |

- **Create** resolves a `template` selector and pins the exact revision to an explicit host or an eligible pool member. A
  sandbox stays on that host while it runs; a stopped disk may later move
  to another eligible host (see [disk offload](#disk-offload)). A pool create with `waitForCapacityMs`
  may first wait in `WAITING_FOR_CAPACITY` (see
  [waiting for capacity](./pools.md#waiting-for-capacity)); its revision and
  size are pinned at entry, and its lease starts at placement (or at READY, see "Lease from READY"
  below). Destroy, stop or
  `POST /v1/operations/{id}/cancel` on the CREATE cancel it. Replaying the
  same key while it waits, after it is placed or after it timed out returns the
  same receipt; changing `waitForCapacityMs` under that key is an
  `idempotency_conflict`.
- **Stop** can interrupt boot as well as shut down a ready VM. It first settles
  issued create effects, then keeps the disk in `STOPPED` so cold reconnect can
  start it again. If no instance was created, there is no disk to start: the
  sandbox ends in `DELETED` after proven absence releases capacity and detaches
  the host. Create another sandbox when you need a new disk.
- **Stop is a clean shutdown.** The host first copies back and removes login
  files (see CLI logins below), then asks the guest to shut down and waits up
  to 10 seconds (about 16 seconds in all), so files the guest has written
  reach the disk. A guest that is still running after that is powered off;
  only writes it had not yet flushed are lost then. Stops WS Sandbox Proxy makes itself
  (lease expiry, access changes, template builds) also ask the guest first.
  An expiry after network enforcement is lost powers the VM off at once.
- **Destroy** deletes the VM at once, without waiting for the guest, and can
  supersede a pending Stop. Stop cannot
  override an admitted or UNKNOWN Destroy. Generation fences reject old results.
  Destroy is idempotent: on a sandbox that is already `DELETED` it returns 202
  with an operation that has already `SUCCEEDED` and sends nothing to any host
  (another owner's sandbox is still 404).
- **A node daemon restart during create.** If the daemon restarts while it is
  creating a sandbox, the create fails with `unknown_outcome` (the SDK message
  says the daemon could not confirm a result because it restarted or lost its connection mid-operation),
  and WS Sandbox Proxy destroys whatever the create may have
  left, so the sandbox ends `DELETED`. Create it again with a new idempotency
  key; a follow-up destroy is not needed but is harmless.
- **Reconnect** is `warm` (a `READY` sandbox; same generation, extend-only lifetime) or
  `cold` (boot a `STOPPED` sandbox, or restore an `OFFLOADED` one; new
  generation and a new lease arm).
  Every cold boot re-applies the sandbox's recorded network policy.
- A **generation** number increases on every boot. Results from an older
  generation are ignored, so late results can never overwrite newer state.
- Lifecycle state changes only through lifecycle operations. Command, file and
  terminal activity never change it.
- **A failed stop or destroy is retried.** When the host reports a stop or
  destroy failed, or reports a result the server cannot apply, the VM may
  still be running and keeps its capacity. The server queues the same
  teardown again as a system operation, at most twice. The first retry that
  succeeds frees the capacity. If both retries fail, the sandbox stays `ERROR`
  with its capacity held until you destroy it or the host's next reconnect
  proves the VM stopped or gone.
- **CLI logins.** A sandbox created with `credentials` becomes READY only
  after every login is installed. Stop and destroy copy login files back by
  default (`credentialCapture: "skip"` discards this run's changes); a stop or
  destroy you requested fails with `credential_capture_failed` when that copy
  cannot be saved, and the sandbox keeps running with its logins (back in
  READY when it was READY before; a sandbox in ERROR stays ERROR). A cold reconnect of
  a sandbox with logins is refused `credential.pending_drain` while its host is
  offline. Choosing an account or instance at create applies to that create
  only; to force one at resume, pass it on the reconnect call. See
  [CLI logins](./cli-logins.md#using-a-login-in-a-sandbox).

## Disk offload

When the deployment has an S3 image store, `DATA_ENCRYPTION_KEY` and
`SANDBOX_OFFLOAD=auto` (the default; see
[image store](../operations/templates.md#image-store)), a stopped sandbox's
root disk is copied, encrypted, to the store (`IMAGE_DISTRIBUTION=off` does
not stop this; only `SANDBOX_OFFLOAD=off` does). The host can then free the
disk, and the next start restores it on any eligible host. A sandbox is no
longer tied to the host that created it.

**Lifecycle.**

1. **Stop.** The sandbox is `STOPPED` with its disk on the host
   (`disk.location: "host"`). When its [offload policy](#offload-policy)
   says so (at once by default), the host exports the stopped disk in the
   background, encrypts it and uploads it; the server verifies the copy.
2. **Stored.** The sandbox is still `STOPPED`, and the disk is both on the
   host and in the store (`host_and_store`). A start now is an ordinary cold
   reconnect on that host and downloads nothing.
3. **Evict.** When the host needs the space, is drained with
   `wssp host drain --offload`, or cannot run the next start, it deletes the
   local VM under a short server grant and proves the root volume is gone.
   The sandbox becomes `OFFLOADED` (`store`): it has no host, holds no
   capacity and has no lease. Eviction is refused while no eligible restore
   host exists, so the disk then stays cached; you are never left with a
   disk nothing can restore. The webhook `sandbox.offloaded` fires on every
   `STOPPED → OFFLOADED` change (an eviction, or a detach from an offline or
   forgotten host) and never when a failed restore returns to `OFFLOADED`.
4. **Restore.** A start (`connect` / cold reconnect) of an `OFFLOADED`
   sandbox creates a `RECONNECT_SANDBOX` operation that picks an eligible
   host. The sandbox moves to `PROVISIONING` with progress phases
   `fetching_disk`, `importing_disk` and `booting`, then `READY`. The
   restore claims the sandbox's attached logins on the new host exactly as
   a cold reconnect does (see [CLI logins](./cli-logins.md#using-a-login-in-a-sandbox)).
5. **Consumed.** At `READY` the stored copy is no longer the sandbox's disk.
   It is kept for the consumed grace (admin setting
   `sandbox.offload.consumedGraceSeconds`, default 3600, 0 to 604800) as a
   salvage window only, then shredded and deleted. A copy in its grace is
   never restored and does not count toward quota. A running sandbox has no
   restorable copy: if its host is lost while it runs, its state is lost as
   before.

The sandbox DTO's `disk` object (null while waiting for capacity or
deleted) has:

| Field                      | Values                                                                                                                                                                                                                |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `location`                 | `host`, `host_and_store`, or `store` (`OFFLOADED`, or a restore still fetching)                                                                                                                                       |
| `offloadState`             | `none`, `pending`, `exporting`, `uploading`, `verifying`, `stored`, `evicting`, `failed`                                                                                                                              |
| `offloadFailure`           | Set only when `offloadState` is `failed`: `quota_exceeded` (stored quota or daily upload budget), `size_exceeded`, `staging_full` or `other`. The disk stays on its host; this is a field value, not an HTTP error    |
| `offloadedAt`, `sizeBytes` | When the current stored copy was verified, and its size; null without one                                                                                                                                             |
| `eligibility`              | `any_host`, `own_hosts` (pinned, login history, or an owned-nodes-only template) or `never` (managed sandboxes)                                                                                                       |
| `offloadPin`               | `ANY` or `OWN_HOSTS`                                                                                                                                                                                                  |
| `offloadPolicy`            | `{mode: "on_stop"}`, `{mode: "after", afterMs}` or `{mode: "on_pressure"}` ([offload policy](#offload-policy))                                                                                                        |
| `offloadDueAt`             | When the policy makes this stopped disk due for export; null when it is not stopped on a host, already has a copy or an attempt, or the policy is `on_pressure`. Deployment gates and host pressure are not reflected |

**Where a restore runs.** A start of a `STOPPED` sandbox whose disk is still
cached boots it on that host. If that host cannot take it back, the start
first evicts the copy (online host; the start is refused
`sandbox.disk_evicting` meanwhile) or detaches it when the host is offline
and nothing there may still be running, and then restores. A copy its host
refused (`disk_stale`, or an eviction grant the daemon refused and let
expire) cannot be evicted, so it is discarded on that host and the start
restores the stored copy instead. A restore of an
`OFFLOADED` sandbox tries your own hosts, then the sandbox's origin pool.
It reads at most 1,024 of your connected hosts with room (in host id
order), so with more than that an eligible host can be missed.
`sandboxHostId` or `poolId` on the reconnect body (restore only, at most
one) picks the target instead. A host is eligible only when all of these
hold:

- it is connected with a fresh heartbeat, not draining or quarantined, its
  egress guard is healthy, and its daemon supports disk offload and image
  fetch and has storage room;
- when the sandbox has guest sudo, its daemon supports guest sudo, and
  another user's host also allows guest sudo for others;
- an open-egress sandbox restores onto another user's host only when that
  host allows open egress for others; the recorded policy is never narrowed
  to fit a host;
- another user's host must accept foreign images, and is excluded when the
  sandbox is pinned to **own hosts**, has login history (see below), or its
  template's image placement is owned nodes only;
- no stale copy of this sandbox is still waiting for cleanup on that host;
- the requesting SDK key's host and pool allowlists allow it, and, if a
  restricted SDK key created the sandbox, the creating key's live host and
  pool allowlists both allow it too. A revoked, expired or deleted creating
  key imposes no limit.

### Offload policy

Each sandbox has an offload policy that decides when its stopped disk is
exported to the image store. It is set at create (`offload` on
`POST /v1/sandboxes`), with a stop (`offload` on
`POST /v1/sandboxes/{id}/stop`, written in the same transaction as the
accepted stop and part of its idempotent request), or at any time with
`PUT /v1/sandboxes/{id}` (`{ "offload": … }`), the SDK's `update`, or
**Disk → Exports to the store → Change** on the sandbox page. Setting it at
create needs only the create's own scope (`sandboxes:create`); a stop or an
update needs `sandboxes:manage`. Managed sandboxes refuse it.

| Policy                        | The stopped disk is exported                                                                        |
| ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `{mode: "on_stop"}` (default) | As soon as the sandbox stops, as described above                                                    |
| `{mode: "after", afterMs}`    | Once it has been stopped for `afterMs` (60000 to 2073600000, one minute to 24 days) without a start |
| `{mode: "on_pressure"}`       | Only when its host needs the space                                                                  |

- **Host pressure overrides every policy, for every owner.** A host needs
  the space when it is draining with `wssp host drain --offload`, when a create
  waiting for capacity in one of its pools is blocked on disk, storage or
  the root ceiling (a stopped disk keeps its disk reservation), or when the
  storage pool holding the disk was last reported at least 90% full (the
  same threshold the daemon uses to evict stored copies). Then `after` and
  `on_pressure` disks are exported like `on_stop` ones, oldest stop first,
  and the usual eviction can free the host. There is no "never": a disk on
  another user's host must not be able to keep that host full, and a drain
  must be able to empty a host.
- **The clock** is the time the sandbox last entered `STOPPED`. A start
  resets it; changing the policy does not, so changing to `after` on a
  sandbox stopped longer than the delay makes it due at once.
- **A change applies to the next export decision.** An export already
  running finishes, and a stored copy is kept (it stays valid until the next
  start). Setting `on_stop` on a stopped disk is how to export it now.
  `OFFLOADED` sandboxes accept a change for their next stop.
- **Durability.** Until a copy is stored, the disk lives only on its host: a
  lost host loses a parked disk. A start can then only boot it on that host,
  so a disk without a copy waits for its host (a drained or offline host
  cannot hand it to another). Choose `on_stop` when the disk must survive
  its host.
- **Deployment gates still apply** to every policy: `SANDBOX_OFFLOAD=off`,
  quotas, staging room, settled logins and receipts. The policy never
  starts an export those would refuse.
- To park a sandbox you expect to start again soon, stop it with
  `{ "offload": { "mode": "on_pressure" } }`, or with `after` set to how long
  it may stay parked before its disk should move to the store.

**Pinning.** `offloadPin` defaults to `ANY`. Set it to `OWN_HOSTS` from the
**Disk** card on the sandbox page (owner session only) to keep its disk off
other users' hosts. A sandbox that
has ever had a login granted (guest files, guest env or proxy) resumes on
your own hosts only, permanently, even after the login is deleted.

**Override.** Only you, from the dashboard, can restore outside the creating
key's allowlists. The confirm dialog warns that the SDK key that created the
sandbox will lose access to it: access follows the sandbox's current host
([auth planes](./auth-planes.md)). The `/v1` API has no override field,
and an SDK principal is refused it on every path, unrestricted keys
included.

**Errors and waits.**

| Code                                                             | When                                                                                                     | What to do                                                                       |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `sandbox.disk_evicting` (409, retryable)                         | Start while the host is evicting the disk                                                                | Retry; the SDK retries for you                                                   |
| `sandbox.restoring` (409, retryable)                             | Stop while a restore is running                                                                          | Wait for `READY`, or destroy                                                     |
| `restore_no_allowed_host` (409, or the operation's failure code) | No eligible, allowed host has room: refused at once without `waitForCapacityMs`, else when the wait ends | Add capacity or widen the allowlists, then start again                           |
| `restore_boot_failed` (operation)                                | The restored VM failed its readiness check                                                               | See the boot caveat below; the sandbox returns to `OFFLOADED` with its copy kept |
| `restore_cleanup_pending` (operation)                            | A failed restore's cleanup on the new host could not be proven                                           | **Retry cleanup**, or destroy                                                    |
| `disk_stale` (operation)                                         | A cached cold reconnect found the host's copy no longer matches the stored copy                          | Start again: the local copy is discarded and the stored copy restored            |
| `sandbox.disk_offloaded` (409)                                   | Capture of an `OFFLOADED` sandbox                                                                        | Start it first, or capture before it is evicted                                  |
| `sandbox.disk_unavailable` (409)                                 | Restore refused because the deployment has no S3 image store or no `DATA_ENCRYPTION_KEY`                 | Configure both; the stored copy is untouched                                     |

With no eligible capacity, the restore operation stays `QUEUED` and the
sandbox stays `OFFLOADED`. It waits up to `waitForCapacityMs` (bounded by
the deployment maximum) and is placed as soon as an allowed host frees
capacity, across server restarts, under the same operation. At the deadline
it fails `restore_no_allowed_host`, unless the latest placement attempt was
refused by a login that can clear while waiting (`credential.in_use`,
`credential.busy`, `credential.pending_drain`, `credential.needs_login`,
`credential.account_paused`, `credential.limit_reached`,
`credential.host_forbidden`, `credential.recovery_required`): then it fails
with that code. An attempt that finds no host with room clears the recorded
refusal. A login refusal that waiting cannot clear (for example
`credential.not_attached`, `credential.env_conflict`,
`credential.path_conflict`, or `credential.unavailable` when the server has
CLI logins off) fails the restore at once with that code. Destroy, or
`POST /v1/operations/{id}/cancel`, ends the wait; replaying the same key
returns the same receipt.

A failed restore (fetch, validation, import, an unknown outcome or an
expired deadline) cleans up the new host and returns the sandbox to
`OFFLOADED` with its stored copy intact. When cleanup cannot be proven the
sandbox stays `ERROR` (`restore_cleanup_pending`); **Retry cleanup** on the
sandbox page (owner session only) queues the cleanup again, and its proof
returns the sandbox to `OFFLOADED`. Destroy of an `OFFLOADED` sandbox completes on
the server and deletes the stored copy after the shred grace.

**What moves with the disk.** The whole root disk moves, including anything
root changed in the guest. The sandbox keeps its revision, size, private
defaults, recorded network policy and its cloud-init instance id, so the
guest does not re-run first boot. If a host's Incus refuses the pinned id,
the restore fails safely back to `OFFLOADED`.

**Boot caveat.** The export does not carry the VM's UEFI variables (NVRAM).
A restored VM boots with fresh firmware variables, so a guest that relies on
custom boot entries, or whose boot chain root modified (bootloader, kernel,
shim, Secure Boot keys), may not boot. That surfaces as
`restore_boot_failed`, with the copy kept. Keep the boot
chain in the template image.

**What is never offloaded.** A disk whose offload policy is not due while
its host does not need the space ([offload policy](#offload-policy));
template-build VMs and other managed sandboxes;
a disk whose login leases have not settled (offload waits); and a disk when
the account is over its stored quota or daily upload budget, the host's
staging is full, or the upload fails. In those cases the disk stays on the
host as before. See [quotas](../operations/templates.md#disk-offload) and,
for login values, [CLI logins](./cli-logins.md#security-model).

## Leases, renewal and expiry

Every running sandbox has a host-acknowledged deadline and a persistent timeout
action. Create defaults to **300000 ms (five minutes)** and
`lifecycle: {onTimeout: "kill"}` (destroy VM and disk). Choose `"stop"` to keep
the disk on timeout. Explicit stop keeps disk; it does not preserve RAM/processes.

- Create/connect accept relative `timeoutMs`. Create defaults to 300000; the
  sandbox remembers its create's `timeoutMs`, and a connect that names one
  replaces it. A connect without `timeoutMs` reuses the remembered lease, so
  stop then start (CLI `wssp sandbox start <id>`, SDK `connect()`) keeps the
  lifetime chosen earlier instead of falling back to five minutes. `setTimeout`
  takes `{timeoutMs}` relative to server acceptance, may shorten, and is not
  remembered. READY connect only extends; STOPPED connect boots the sandbox's
  disk on the host that holds it (OFFLOADED connect restores it onto an
  eligible host) with a new generation. Connect keeps the existing timeout
  action. A remembered lease is never shortened to fit a policy that was
  lowered since: the connect fails with `lease_exceeds_policy` (a restore
  through a pool finds no host it may use instead: `restore_no_allowed_host`,
  or it waits when `waitForCapacityMs` is set); pass a shorter `timeoutMs`.
- The longest lease is the smallest of four layers (see "Layered lease
  policy" below): the deployment (`SANDBOX_MAX_TIMEOUT_MS`), the host's own
  ceiling, the pool maximum and the membership maximum. A request over it fails
  with `lease_exceeds_policy` (400) and `maxTimeoutMs`, the largest finite value
  allowed on that target; nothing is clamped. Fractions are rejected. Each
  accepted deadline is computed once; replay after time or a limit change
  preserves it.
- SDK create/connect return bound handles after the exact accepted intent's
  durable ACK and READY. A later shortening cannot strand the earlier waiter.
  `endAt` is host-effective and null before ACK; `readyAt` records guest-ready
  evidence. Unknown start timing stays null, and cold boot resets timing.
- **Lease from READY.** When image distribution is on (`IMAGE_DISTRIBUTION`
  not `off`) and the host's daemon reports `leaseFromReady`, a finite create
  lease starts at READY, not at acceptance (or placement, for a create that
  waited for capacity), so an image fetch or a slow boot
  does not use up the timeout. Until READY the host holds a provisional
  backstop (acceptance + timeout + `SANDBOX_CREATE_PROVISION_MAX_MS`) and the
  public `endAt` and requested deadline stay null. At READY the host sets the
  deadline to readyAt + timeout (never past the backstop) and acknowledges it;
  the server accepts that deadline only within 60 seconds of the window
  [acceptance + timeout, now + timeout], which tolerates host clock skew. The
  pool and host ceilings check the timeout, not the backstop, and the lease
  pull-in skips a lease still waiting for READY. `timeoutMs: 0` remains unlimited, subject to policy and access loss.
- The sandbox shows a **requested** and an **effective** lease. Only the
  effective lease, the one the host acknowledged, is enforced. A renewal stays
  queued until the host acknowledges it; an offline host cannot be extended.
- The host enforces the deadline itself, including while disconnected from the
  server, using monotonic time and persisted clock floors (moving the clock
  back never extends a lease).
- At the deadline new commands, file work and terminals are refused at once.
  The host asks the guest to shut down (up to about 16 seconds), then forces
  the stop, then destroys the VM when the action is `destroy`, retrying with
  backoff until the result is confirmed. The VM, with its network access, may
  keep running for that short graceful window.
- A failing expiry shows as `ERROR` `expiry_failed` with the host's reason and
  keeps its capacity reserved until the host confirms the action. A host that
  is powered off enforces nothing until it restarts.

## Layered lease policy

The effective maximum lease is `min(deployment, host ceiling, pool max,
membership max)`. A layer with no value adds no limit.

| Layer              | Set by                     | Where                                                                                                      |
| ------------------ | -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Deployment         | Operator                   | `SANDBOX_MAX_TIMEOUT_MS`: 300000..2073600000 ms (5 minutes to 24 days) or `unlimited`; default 86400000    |
| Host ceiling       | Machine owner, on the host | `wssp host config set-max-lease 6h` (default `24h`; `unlimited` allowed). The dashboard shows it read-only |
| Pool maximum       | Pool owner                 | Pool settings; blank means no pool limit                                                                   |
| Membership maximum | Host owner                 | Own-host member settings, or the contribution form for a contributed host                                  |

- **Lease path.** On the creator's own host, the pool and membership layers
  come from the pool the sandbox was created through (its origin pool) and that
  host's membership in it, for the sandbox's whole life. On someone else's
  host they come from the pool and membership the sandbox currently uses. If
  the pool is deleted or the host leaves it (or a foreign sandbox has no usage
  path, during access grace), only the host and deployment layers apply. A
  disabled membership still applies its limit.
- **No time limit.** `timeoutMs: 0` means no lease timer. It is accepted only
  when every layer is unlimited and, on a pool, the requester owns the pool or
  the pool lets anyone who can use it create sandboxes without a time limit
  (default: the owner only). Discover it with `limits.sandboxTimeoutZero` and a
  pool's `lease.timeoutZero`. Such a sandbox reports `endAt` and lease
  `expiresAt` as `9999-12-31T23:59:59.999Z`; the SDK exports
  `isUnlimitedLeaseEnd`. Finite leases go up to 24 days; anything longer must
  be unlimited.
- **Lowering shortens running sandboxes.** When a layer is lowered (a pool or
  membership edit, a new host ceiling reported live or on reconnect), the
  server issues a system renewal that only ever shortens: every READY sandbox
  whose enforced deadline (the later of requested and host-acknowledged) lies
  beyond now plus the new limit is pulled in to now plus that limit. It never
  lengthens a shorter pending request. A pull-in that fails is retried on the
  next pass (about every 15 seconds, and at once after a policy change). A
  host that is offline receives the pull-in only after it reconnects; until
  then it enforces its last acknowledged deadline. A pull-in never sets a
  deadline later than the one the host has acknowledged: an unacknowledged
  longer renewal is superseded at the acknowledged deadline, never carried by
  the system renewal. The host also treats every pull-in as shorten-only: if
  it already holds an earlier deadline than the server knows about, it keeps
  that earlier one. The dashboard shows how many
  running sandboxes a lowering would shorten before saving it. The renewal is
  sent to the current host and enforced after its shorten-only acknowledgement;
  a reconnect rechecks the same policy and exact lease identity.
- **What still stops an unlimited sandbox:** its owner (kill or stop); losing
  pool access (access grace, then the timeout action); a ban — on someone
  else's host by the access rules, and on the owner's own host the sandbox is
  stopped with its disk kept and no deletion grace, so after an unban the owner
  can start it again (the ban also revokes the host's credential, and the host
  daemon then stops every sandbox VM it runs by itself; see the hosts guide); host deletion (stop, grace, then destroy, on own and
  foreign hosts alike); and account deletion. The server's lease reclaim never
  selects it. These rules apply to finite leases too.
- A host whose ceiling was lowered locally refuses, before any effect, a lease
  that ends later than its new ceiling (`lease_exceeds_policy`). A warm
  reconnect refused this way leaves the sandbox READY with its previous lease.
  Work carried across a transport drop after an offline ceiling change fails
  the same way rather than being adopted and pulled in.

## Operations and idempotency

Every mutation needs an `Idempotency-Key` (1–128 characters from letters,
digits, `.`, `_`, `:` and `-`; the SDK generates one when you do not pass one).
An accepted mutation answers **202** with `{operationId, state, location}`;
poll the operation for the outcome. Acceptance is not readiness and not a
confirmed cancellation.

Polling can long-poll: `GET /v1/operations/{id}`, `/output` and `/result`
accept `waitMs` (0–25000). The server then holds a read that has nothing new
(a pending operation, an empty output page of a running command, a result that
is not ready yet) until the operation changes, and answers as soon as it does;
otherwise it answers with the unchanged read when `waitMs` runs out. A
long-poll counts as one request against the `/v1` budget. The server may answer
earlier than `waitMs` (shutdown, or more than 16 held reads for one owner), so
always look at the answer, not the elapsed time. The SDK does this for you.

| Operation state                               | Meaning                                                                                           |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `QUEUED`, `DISPATCHED`, `ACCEPTED`, `RUNNING` | In progress                                                                                       |
| `CANCEL_REQUESTED`                            | A cancel was accepted; the host has not confirmed it yet                                          |
| `SUCCEEDED`, `FAILED`, `CANCELLED`            | Terminal, with a typed error code on failure                                                      |
| `UNKNOWN_OUTCOME`                             | Uncertain: the effect may or may not have happened; lifecycle recovery can later prove completion |

- Keys are owner-wide and retained. Re-sending the same key and input replays
  the original operation; the same key with different input is
  `sandbox.idempotency_conflict`. Retrying under a **new** key is a new
  request: after a network error, always retry with the same key.
- **Unknown outcomes require care.** Work interrupted before the host
  durably recorded its result (daemon crash, lost connection, lost state
  directory) becomes `UNKNOWN_OUTCOME`. For lifecycle work, the host later
  establishes the real VM state from Incus and the sandbox converges. A
  command or file write stays unknown. Guest work may remain alive. There is
  no command retry; recover through sandbox stop or kill, never an automatic
  new-key command submission. The SDK reports these as error kind `unknown`
  carrying the `operationId` and `idempotencyKey`.
- On relay 10.7, a held UNKNOWN create/reconnect may later become FAILED
  with `host_effect_not_issued` when a targeted, ordered host attestation
  proves the VM was never created and no allocation can still run. The sandbox
  becomes ERROR and its capacity is released. This uses the current connection
  and does not close terminals or transfers. Older hosts and uncertain effects
  retain their holds. See [host recovery](hosts.md).
- **Teardown recovery is the exception.** The daemon automatically retries an
  unresolved stop or kill after reconnect and on heartbeat. On a STOPPING
  sandbox whose current-generation teardown is UNKNOWN, you may send kill
  (`DELETE /v1/sandboxes/{id}` / SDK `destroy`) with a **new** key: it returns
  202 and advances the generation. Stop with a new key can retry an UNKNOWN
  stop; it cannot replace an UNKNOWN kill and retain its disk. An in-flight kill
  returns 409; kill may supersede an in-flight stop. The same key always replays its original
  receipt. Capacity remains reserved until positive stop/deletion proof.
- Cancel (`POST /v1/operations/{id}/cancel`) needs `operations:cancel` plus the
  target's own scope. For a command it kills the command's process group. Only
  a `CANCELLED` target is a confirmed stop.
- A command's timeout and cancel outcomes are typed only when the host proves
  that its own stop ended the command. The stop must find the command still
  running, signal it, and then see its process group gone. When the
  `timeoutMs` budget runs out, the command ends `FAILED` with error code
  `timeout` (SDK kind `timeout`). A cancel ends `CANCELLED` (SDK kind
  `aborted`). In other cases the command's own result stands: it finished
  first, or it handled the signal and reported a normal exit status (for
  example it trapped SIGTERM and exited 0). A command that exits 143 by itself
  is `SUCCEEDED` with exit code 143. If the host cannot prove what happened,
  the outcome is `UNKNOWN_OUTCOME`. In a [`guestRoot`](#root-in-the-guest)
  sandbox every one of these results is guest-attested: guest root can replace
  the guest agent and every helper the proof runs, and `CANCELLED` means only
  that the tracked process group is gone (a `sudo`'d child may have left it).
- If the host loses track of a command (outcome `UNKNOWN_OUTCOME`), it still
  stops it after a cancel, or once the command's own `timeoutMs` budget has
  passed plus about 20 s, measured on the guest's monotonic clock (suspend
  excluded). While the host stays connected it retries about every 15 s;
  otherwise this happens at the next reconnect. That stop kills every process
  the command started, including detached ones (best-effort only in a
  `guestRoot` sandbox, where only the VM stopping or a new QEMU process
  retires the receipt; see [Root in the guest](#root-in-the-guest)). The operation stays
  `UNKNOWN_OUTCOME`. See [host recovery](hosts.md). Node daemons built before this change report
  a timeout as `UNKNOWN_OUTCOME`. They report a cancel that the command
  honoured as `SUCCEEDED` with exit code 143.
- `host_disconnect_expired` (SDK kind `unavailable`) means the host stayed
  disconnected from the server past its carry cap (`max_carry`) and proved it
  stopped the work. Endings during an outage otherwise keep their natural code
  (`timeout`, lease expiry), and work that never started keeps
  `host_effect_not_issued`. A template-build step ended this way fails the
  build as `build_step_host_disconnected`.

## Commands

- Exactly one of `script` (run by `/bin/bash -lc`) or `argv`, with optional `envs`,
  `cwd` and command `timeoutMs`. Omission means 120000 ms; positive integers
  are bounded to 1800000 ms. Explicit **0 means no separate command timer**,
  still bounded by the sandbox lease and host execution authority. A timerless
  command survives a relay outage until the lease ends or the outage reaches
  the host's `max_carry` (default 24 h; see the hosts guide). Clients must
  check `limits.commandTimeoutZero`: zero is accepted only when it is true,
  requiring the current relay contract and a supported runtime. When false,
  zero is refused before receipt or guest IO. Old hosts never receive
  zero or have it silently remapped to a positive timeout.
  A zero command accepted while the capability was true can still end
  `FAILED`/`unsupported_capability` (proven unsent) or `UNKNOWN_OUTCOME` if the host
  is downgraded before dispatch.
- A positive command timer starts at user execution, excluding queue and setup.
  Renewing the sandbox lease never resets it. Shortening or expiry of the lease,
  a relay outage reaching the host's `max_carry` (`host_disconnect_expired`),
  host credential revoke and daemon shutdown still end timerless execution
  authority. A shorter outage does not: the command keeps running and reports
  its natural outcome after the reconnect. Revoking an SDK key does not cancel commands it already
  started: they remain lease-bounded; cancel/kill them explicitly or stop the sandbox.
  The guest environment/bootstrap helper has a 5000 ms setup budget. The host
  gives up after the tools probe (up to 5000 ms) plus a 15 s host setup bound,
  so a hung start surfaces as `UNKNOWN_OUTCOME` after roughly 15–20 s.
  Any command, including the default, whose startup exceeds the host setup
  bound ends `UNKNOWN_OUTCOME`.
  The serialized command may be at most 32768 bytes.
  Commands run as the template's guest user. With
  [`guestSudo`](#root-in-the-guest) (the default) that user can run `sudo`.
- Every SDK submission form uses command `timeoutMs`, in the input or options,
  never both. `guestTimeoutMs` and the deprecated wait-only `timeoutMs` alias
  were removed. Use finite `waitTimeoutMs` for observation (at most 60 minutes);
  expiry detaches the observer without cancellation. Command zero never makes
  that wait zero or infinite. With an explicit positive command budget and no
  explicit wait budget, the default wait covers it plus one minute. Lifecycle
  waits also use `waitTimeoutMs`; connect's lease option is `leaseTimeoutMs`.
- Supervised stdin stays open. A read-until-EOF command can wait until
  `handle.closeStdin()` (or explicit stdin EOF), cancellation or authority loss;
  this is especially visible with command zero. Observer disconnect never sends
  EOF. Use `commands.start`, then attach with a finite wait and close stdin when
  appropriate. Output retention is unchanged: no timer does not mean unlimited
  output or surviving host restart. Recover uncertain acceptance with the
  original idempotency key, never a replacement command.
- Output streams while the command runs. The host and server keep the first
  256 KiB and the last 768 KiB of output per command; anything between is an
  explicit gap, never silently dropped. Output is read in pages from
  `GET /v1/operations/{id}/output` (add `waitMs` to wait for the next bytes
  instead of polling) and expires 24 hours after the command completes
  (`OUTPUT_EXPIRED`; the operation status stays readable).
- A command's result is published after its retained output reaches the
  server, so the final bytes (usually the error message) arrive before the
  result. The host keeps sending while the server keeps acknowledging. It
  stops waiting after 5 s without progress, after 30 s in total, or 2 s before
  the sandbox lease ends (measured on the same rollback-resistant clock that
  lease expiry uses; if that clock cannot be read it stops at once); anything
  still unsent then becomes a gap. Unanswered
  output is resent after 250 ms, backing off to every 2 s while the server
  makes no progress.
- stdin is written in chunks of at most 32 KiB once the command has been
  dispatched. An accepted chunk was delivered to the dispatch attempt, not
  necessarily read by the program.
- A daemon restart never re-runs a command to rebuild its output.

## Root in the guest

`guestSudo` is a create option, on by default for ordinary sandboxes
(`/v1` body `guestSudo`, SDK `guestSudo`, the dashboard's "Allow sudo in the
guest" switch). It is fixed for the sandbox's life.

- **What it does.** On every boot it drives (create, retries, reconnect,
  daemon recovery), after the last guest restart, the node daemon installs
  `/etc/sudoers.d/wssp-guest` (`#<uid> ALL=(ALL) NOPASSWD:ALL`, `root:root`,
  `0440`) through its own fixed helper and proves `sudo -n true` as the guest
  user. With `guestSudo` off it removes the file. The rule names `(ALL)` only,
  so `sudo -g` is refused. Commands, files and terminals still run as the
  guest user; there is no run-as option. Files the guest user cannot read or
  write (root-owned) are refused by the files API.
- **Effective vs requested.** The sandbox shows `guestSudoRequested` and the
  effective `guestSudo`. On another owner's node whose operator turned off
  `allow_guest_sudo_for_others`, the effective value is `false` with reason
  `node_policy`; on a node too old to support it, `host_unsupported`.
  Turning consent off later refuses that sandbox's next create or reconnect
  there with `guest_sudo_not_permitted`.
- **Failures.** A create whose image has no usable `sudo` (missing, unsafe
  parent directories, or an implementation that rejects the `#<uid>` form)
  fails with `guest_sudo_unavailable`, and the VM is destroyed. A create with
  `guestSudo` off whose image grants the guest user root statically (a
  sudoers rule, `sudo`/`wheel`/`docker`/`lxd`/`incus`/`libvirt`/`disk`
  membership, `doas`, a second uid 0, a usable password) fails with
  `guest_root_granted`. That audit is hygiene for benign images, not a
  security control. If a sandbox's own root breaks sudo later (removes it,
  switches the implementation), its reconnects keep failing with
  `guest_sudo_unavailable`; capture the stopped sandbox or delete it.
- **`guestRoot`.** A sandbox is `guestRoot` when it has `guestSudo`, or its
  revision was built with root steps or captured from a `guestRoot` sandbox
  (the "Captured with guest root" badge), except WS Sandbox Proxy's own verified base
  recipe. For a `guestRoot` sandbox every command result, cancel and timeout
  is guest-attested, and an `UNKNOWN_OUTCOME` command is retired only on host
  evidence: the VM stopped or absent, or a new QEMU process. A guest reboot is
  not guaranteed to start a new QEMU process, so stopping the sandbox is the
  reliable way to free such receipts. Captures of a `guestRoot` sandbox carry
  the taint.
- **Receipt cap.** One sandbox holds at most `max(64, max_concurrent_commands)`
  unfinished command receipts on a node; past that, new commands fail with
  `host_capacity` reason `sandbox_receipts`. Stop the sandbox to free them.
- **Idempotency.** An omitted `guestSudo` and an explicit `true` are different
  request bodies for the same idempotency key.

Host-side enforcement (the egress guard, the bridge ACL, DNS) is outside the
VM and unchanged by guest root.

## Files and transfers

- Guest paths are paths inside the VM, acted on as the guest user. Every file
  operation (stat, list, mkdir, move, remove, reads and uploads) refuses a
  symlink in any ancestor component and `..`. Reads and uploads also refuse a
  final symlink and non-regular files; stat and list report a final symlink as
  an entry, move and remove act on the link itself, never its target, and mkdir refuses an existing link. Paths must be absolute (at most 4096 UTF-8 bytes, no NUL) and are
  never trimmed: leading or trailing whitespace is refused, internal spaces
  are fine. `mkdir`, `move` and `remove` refuse a bare `/`. Uploads and
  downloads also refuse a `.` component, a bare `/` and control characters,
  with 400 before any transfer is reserved.
- `stat`, `list` (depth 1–8), `mkdir`, `move` and `remove` are ordinary
  operations. File bytes move through the server's **transfer store**, never
  through SQL or JSON:
  - **Uploads** are resumable and sent in 1 MiB chunks after the full length is
    reserved. The guest receives the bytes in a staging file, the length and
    SHA-256 are verified, and the file is renamed into place atomically.
  - **Downloads** capture the guest file once, seal it with a SHA-256, and
    serve it by byte range (`GET /v1/operations/{id}/content`) with an ETag for
    resuming.
- Defaults (server configuration, see
  [environment variables](../operations/environment-variables.md#transfer-storage)):
  1 GiB per transfer (also the ceiling), 10 GiB of spool disk, 4 open
  transfers per owner and 16 overall, 15 minutes idle and one hour absolute
  lifetime. Expired content is `TRANSFER_EXPIRED`; a full store is
  `TRANSFER_QUOTA` (429, `Retry-After: 5`).
- A transfer stops counting as open when it finishes: an upload once its guest
  write succeeds, fails or is cancelled, and a download once every byte of the
  capture has been delivered. "Delivered" means the server handed the bytes to
  the network, so the content is kept for a 60-second grace: a client that
  dropped near the end can resume the tail then (the resume needs a free
  transfer slot). After the grace, or after a server restart, the capture is
  gone and reading it again returns `TRANSFER_EXPIRED`. In the dashboard,
  **Save file** works once per prepared download; prepare it again for
  another copy. An interrupted download stays open, so you
  can resume it until it completes or expires. An upload with an unknown
  outcome also stays open until it expires.
- The SDK's in-memory conveniences are capped at 32 MiB of client memory. That
  is a client bound only; streaming calls go up to the server's limit.

## Metadata

Optional string-only `metadata` at create: at most 32 keys (1–64 UTF-16 units),
values of at most 1024 UTF-16 units, and 8,192 UTF-8 bytes of JSON in total
(`sandbox.metadata_invalid` otherwise). Non-string values are rejected without
coercion. NUL, malformed Unicode and prototype-related keys are refused. It
is a label for you, never configuration: it cannot widen egress or change the
guest.

`GET /v1/sandboxes` discovers READY sandboxes by default. `metadata` is one bounded
JSON query value whose string pairs match exactly with AND; `states` is one
comma-separated state list. The current schema also supports `templateRevisionId`, strict
`startedAfter` (VM start time), and `order=asc|desc` on `(createdAt, id)`.
Filtering and owner/key visibility happen in SQL before pagination. Reuse the opaque
sandbox cursor only with the same owner, filters and order. The dashboard requests
history explicitly; detail still reads any retained state. No metadata update exists.
Metadata is validated on reads as well as writes; non-string historical values
are not silently coerced. Logical `templateId`, exact `templateRevisionId` and
`poolId` filters select stored identities. Filtering does not re-run placement.

### Private environment defaults

Create accepts an optional `envs` object of unique POSIX names and string values.
Defaults apply to every command and browser terminal, survive stop/reconnect and
host restart, and cannot be read or edited through sandbox getters. Command
`envs` override sandbox defaults for that command. Create snapshots immutable revision defaults plus sandbox overrides; a command
override wins last for that command. A tag move, append or pool membership
change never updates an existing sandbox snapshot. Changing template defaults
requires a new revision; changing sandbox defaults requires a new sandbox. `HOME`, `SHELL` and `TERM` are reserved in sandbox
defaults; the guest identity remains fixed.

Each source and the final command union permit at most 64 entries, 128 UTF-8 bytes
per name, 4096 per value and 16384 bytes of sorted escaped JSON. Oversized unions
are refused before enqueue. Every fresh launch requires current authenticated 10.3 admission, inventory and
exact image evidence, with its journal key acknowledged. Dispatch installs the private
snapshot durably and waits for the exact config ACK before starting the VM.

Values are plaintext inside the database and enrolled host journal trust
boundaries (including backups). They are absent from public/admin sandbox data,
SDK handles, VM metadata, host child argv/environment and automatic diagnostics.
Workloads can deliberately print their environment into protected command output.
Terminal setup delivers defaults over a gated raw PTY handshake; browser input
and resize are refused until setup completes. Empty maps retain the existing spawn.

Pool and direct placement share atomic capacity reservations. Specify exactly one of `poolId` or `sandboxHostId`; see [host pools](./pools.md) for ranking and refusal semantics. Accepted retries retain their original placement.

## Files and tracked command dashboard

The existing sandbox detail page offers explicit directory/process refresh,
max-limit pages (100 entries, replaced rather than accumulated), an EntryInfo
dialog, retained output attachment, and a type-to-confirm kill action. Expired,
stale, unavailable and unknown observations are distinct from empty successful
pages. Impersonated or revoked browser authority shows translated unavailability.
Guest names, argv, symlink targets and output are literal text. Only pipe commands tracked by WS Sandbox Proxy
appear; there is no guest-wide census or PID-file adoption.

Before starting a command, the guest wrapper checks for an executable
`/usr/bin/systemd-run` version 254 or newer, systemd as PID 1, and
`/run/systemd/system`. When available, it uses the command's own named scope
`wssp.slice/wssp-cmd-<operation>-<generation>-<attempt>.scope` with
`OOMPolicy=continue`, so a workload OOM can report its killed exit without
stopping the guest agent, and the host can later prove the command gone (or
stop it) while the VM runs. Older or non-systemd guests execute directly with
the same supplementary-group, GID and UID setup, after writing the per-boot
marker `/run/wssp/unscoped` (no marker, no command). Direct execution inherits
the guest agent's OOM policy; an OOM may stop the agent and lose the exit
channel, leaving an unknown command outcome. A scope failure never triggers a
direct retry, so a command cannot run twice because of fallback.

Read `guestApi.supportedSignals` from the sandbox's capabilities before
offering controls. When a create or reconnect becomes ready, the host runs the
signal helper's own support probe in the guest; a guest without group signals
(including 24.04 GA/6.8) then lists only SIGKILL. Until a current host report arrives, TERM/INT/HUP stay listed; every call still
checks the guest capability before effect. The deployment-wide
`/v1/capabilities` never describes a particular guest. Either way support is
still `signalSupport: "checked-at-call"`: approved Branch A TERM/INT/HUP
delivery uses the verified wrapper's group pidfd on booted guest kernels ≥6.9
with helper support, the helper probes the running guest on every call, and an
unsupported guest refuses `signal_unsupported_on_guest` before effect. SIGKILL remains canonical
cancel. Delivery/acceptance never proves death; stale-client refusal never
triggers automatic cancellation. Even a new cancel key cannot retry UNKNOWN
command cleanup: guest work may remain alive, so use sandbox stop/kill recovery.
UNKNOWN/STOPPING lifecycle outcomes require sandbox recovery.

File stat/list never follow symlinks. Recursive remove is explicit; rename uses
POSIX destination semantics. Each live page costs an ordinary action and may
rescan O(N) entries. Pages are bounded by depth 8, visits 100000, a 30-second
observation budget and byte caps. Observations retain for one hour from acceptance, rename content for 24 hours
from acceptance, and output/command descriptions for completion plus 24 hours. Lease
renewal does not extend that retention. Owner content reservations share 32 MiB,
with 24 KiB reserved before effects then shrunk to actual bytes.

Dashboard and SDK keys share the ordinary 100, stdin 600 and termination 30
owner budgets per minute; existing HTTP/transfer/lifecycle limits still apply.
There is also a per-sandbox signal limit of 5. Polling and server attachment are
not guest dispatches. The SDK waits out 429 using Retry-After and the same key;
other catalog 4xx responses are final (start's NOT_READY polling is the specific
exception). Signal requires operations:cancel plus commands:execute. Stdin
refusals are direct 409s; its durable receipt confirms acceptance, not consumption
or the command's final state. Signal/kill requires full tracked references;
no best-effort numeric-PID kill is provided.

### Filesystem and command result limits

Read global `/v1/capabilities` and the owned sandbox's capabilities. A feature
requires both the implemented route and current runtime support. Always read
`guestApi.supportedSignals`: TERM/INT/HUP need group-pidfd support in the booted
guest kernel (at least 6.9) and the helper probe. Otherwise the call refuses
`signal_unsupported_on_guest` before effect. SIGKILL uses canonical cancellation.
A trapped signal can leave work running; acceptance never proves termination.

Stat/list return no-follow metadata and literal symlink targets. Lists default
to and cap at 100 entries, depth 8, 100000 visits and 30000 ms observation work.
Each page is a separate idempotent observation of a live tree; directory paging
rescans it in O(N) per page. Byte caps can shorten a page. Cursors bind the
operation, filters and generation; stale cursors refuse with a typed error.

Stat/list/process-list results expire one hour after acceptance; rename content
expires after 24 hours. Command output and private descriptions expire 24 hours
after first completion. Renewal does not extend retention. Native result expiry
returns 410 `OPERATION_RESULT_EXPIRED`; output expiry is 410 `OUTPUT_EXPIRED`.
Browser oRPC may use outer `INTERNAL_SERVER_ERROR` while retaining status 410
and domain `data.code: OPERATION_RESULT_EXPIRED`; classify by domain code/status.
`startedAfter` requires a datetime with seconds, not just hours and minutes.

Content-bearing work reserves 24 KiB before effects, then shrinks to encoded
payload plus private continuation bytes. The owner ceiling is 32 MiB, the page
cap 24 KiB and the response cap 32 KiB. Pending/unknown reservations count.
At worst 1365 full reservations fit; smaller published pages can permit more.
HTTP, worker and rate budgets independently constrain throughput.

Owner-wide per-minute procedure budgets are ordinary 100, stdin 600 and
termination 30, shared by dashboard actions and SDK keys. Sequential durable
same-key replay is free; racing first submissions can conservatively charge
twice while permitting only one effect. Retry 429 using `Retry-After` and the
same key. Other catalog 4xx responses are final, except start polling of
`OPERATION_RESULT_NOT_READY`.

Command `timeoutMs: 0` disables the separate command timer only when
`limits.commandTimeoutZero` is true. Omission means 120000 ms; positive budgets
are 1–1800000 ms. The sandbox lease and host authority still bound execution.
Observer `waitTimeoutMs` stays finite (at most 60 minutes); it detaches on expiry.
Guest bootstrap has a 5000 ms budget and host setup a 15-second bound after
the tools probe. Startup beyond that bound yields UNKNOWN_OUTCOME. SDK-key
revocation fences future access without cancelling accepted commands. Detach
sends no EOF; send EOF explicitly when a command reads until end-of-input.

Use [templates](../operations/templates.md) for guest kernel guidance and the
[real-guest checklist](../testing.md#fsprocess-real-guest-acceptance-not-yet-run)
for live acceptance. The [SDK README](../../packages/sdk/README.md) compiles its
examples against the current API.

## VM size

Native API and SDK create accept independent optional `cpuCount` / `memoryMiB` / `diskGiB`.
Omitting a dimension uses that exact revision's immutable default (its
`cpuCount`, `memoryMiB` and `defaultDiskGiB`); revision registration/append
defaults each omitted dimension to 1 vCPU / 1024 MiB / 32 GiB.
CPU must be an integer 1–32 and memory an integer 512–65536 MiB in 256 MiB steps.
Disk must be an integer from the revision's `minDiskGiB` to 2048 GiB (see
[root disk: minimum and default](#root-disk-minimum-and-default)). Dashboard
forms support all three dimensions; a blank create field independently
inherits the accepted revision, and the create form shows the chosen
revision's minimum and default disk. No resize or live migration is
supported; a stopped disk moves only through [disk offload](#disk-offload).

Get/find/list and bound `Sandbox.sandbox`/get expose actual accepted size.
Create resolves size only for new acceptance. A same-key replay returns its
original accepted result despite changed tags, revision defaults, retirement,
pool membership or budgets. Omitted and explicit-default overrides are distinct
intents; recover a lost response with the original values, presence and key.

Cold boot keeps the sandbox's disk, image, private defaults and size, on the
host that holds the disk (a restore picks a new host, see
[disk offload](#disk-offload)). It may
queue while offline or between hello and admission using the last stored budget.
No stored report is `sandbox.host_unavailable`; above per-VM caps is
`sandbox.vm_size_unsupported`; resource exhaustion is `sandbox.host_capacity` (pooled: `sandbox.pool_full`)
with reason `ram | vcpu | disk | storage | ceiling`.
An existing hold is never charged twice. Warm READY connect and lease renewal
consume no extra capacity and continue when a reduced budget is overcommitted.
Budget shrink does not evict or resize guests. Stop frees live capacity only
when positively confirmed; disk and allocation remain. Retained roots charge
size + 1 GiB and keep their original pool/marker, including STOPPED/UNKNOWN.
Only positive exact-root/network absence on healthy original storage releases
them. Cold start bypasses new-root cap/drain but still needs healthy original
storage and live-resource fit. Missing storage never authorizes a replacement;
only a verified stored copy can be restored elsewhere ([disk offload](#disk-offload)).

### Root disk: minimum and default

Every revision has two disk sizes, both in its DTO:

- `minDiskGiB`: the image's own root disk. A captured or built revision
  (`sourceKind` CAPTURE or BUILD) carries its source VM's whole root, so its
  minimum is that VM's disk; a registered (MANUAL) revision's minimum is the
  `minDiskGiB` given at registration (default: its `defaultDiskGiB`), since wssp
  cannot see inside the image. A create (or a build on the revision) asking for
  less is a 400 `sandbox.disk_below_image` before anything is dispatched.
- `defaultDiskGiB`: what a create gets when it omits `diskGiB`. It is never
  below the minimum.

The community Ubuntu base has an 8 GiB minimum and a 32 GiB default, so a
create that names no size still gets 32 GiB, and templates built on the base
stay small (see [sized builds](./template-builds.md#disk-size)).

**Root growth.** A create larger than the image's root needs the guest's root
filesystem to grow to the disk. The node daemon does this itself at every
create, as part of readiness (it does not rely on cloud-init): a fixed helper
runs as guest root, grows the root partition with `growpart` and the
filesystem online (`resize2fs` for ext4, `xfs_growfs`, `btrfs filesystem
resize max`), then measures the partition and the filesystem's own size. A
root that does not reach the disk (to within a few MiB) fails the create with
`root_disk_not_grown` (`guest_unavailable` with that `details.reason`), and the
VM is destroyed like any create readiness failure. An image whose root sits on
LVM, LUKS or md is not grown; it passes only when it already fills the disk.
Start and reconnect never re-run it (a disk never changes after create), and
neither does a restore of an offloaded disk. The check is guest-attested
hygiene, like `guest_root_granted`: a guest with root can misreport its own
disk, and nothing in capacity accounting uses it. Images need `python3` (as
for every create), `growpart` (`cloud-guest-utils`) and the filesystem's grow
tool; an image registered at exactly its own root size needs none of them.

Roots never shrink: a capture's minimum is the captured sandbox's own disk. To
keep a captured template small, capture a sandbox created at (or near) its
revision's minimum; `POST /v1/sandboxes/{id}/capture` (and the dashboard's
Save as template) take an optional `defaultDiskGiB` for the new revision
(default: the source revision's default, at least the captured disk).

Invalid size is a safe 400 `sandbox.vm_size_invalid`; unsupported valid size is
409 / SDK `unsupported`, and immutable mismatch is `conflict`. SDK local schema
rejection makes no request and has `kind=invalid_request, code=null`.
None of these definitive errors is an automatic 429 retry. Host reconnect
refusals currently report UNKNOWN even for definite host failures; the shared
hold remains until positive inventory/cleanup evidence. A mismatch, disconnect,
timer or refused redispatch alone never proves absence or frees capacity.

[Host capacity](./hosts.md#capacity-drain-and-deletion) describes configured
budgets and shared owner reservations; [pools](./pools.md) explains ranking and
authorized fit diagnostics. Deploy matching server, SDK and daemon builds; see the [capacity and storage qualification](hosts.md#capacity-and-storage-qualification).

SDK scopes separate creation (`sandboxes:create`), stop/reconnect/lease/rename (`sandboxes:manage`) and destruction (`sandboxes:destroy`). Capture also needs `templates:write`. Keys with **own sandboxes only** see and operate only on sandboxes originally created by that key; allowlist keys always have this restriction. Host commands are outside this restriction because the daemon is an Incus admin.
