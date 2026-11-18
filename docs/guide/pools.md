# Host pools

A pool groups enrolled hosts for placement. On the dashboard's **Pools**
page, create a pool, add hosts, and enable or remove individual members. A host
may belong to several pools, including pools owned by other users. Pool slugs stay reserved after deletion.
Pool owners manage settings and the roster; contributors manage their own
contributions. These writes require a live browser owner session; SDK discovery
is read-only.

## Trust the node owner

A node owner has full access to sandboxes other users run on their node. The
daemon user is an Incus admin and can reach every VM, including your guest's
files, memory and credentials. Dashboard/API guest visibility restrictions and
turning host terminals off do not isolate a guest from its local administrator.
The node owner can opt their own credentials into host commands and file tools;
**Own sandboxes only** does not limit those tools.

Pool users never get host access to someone else's node. Pool membership, a
host discovery result and guest execution grants do not grant a host terminal,
host commands or host file tools. Server ownership checks and the daemon's
`hello.ok` owner check both enforce this rule. See
[agent host access](../design/adr-006-agent-host-access.md) and
[node settings](./hosts.md#node-settings-for-agents-and-terminals).

## Placement

Create accepts a template selector and exactly one of `poolId` or
`sandboxHostId`. A pool filters joint per-VM, charged RAM, aggregate vCPU, healthy storage,
root-disk budget and fixed retained-allocation guard fit. Choose each host's
healthy non-draining local pool by free committed GiB descending, marker ascending.
Rank fitting hosts in two tiers: when the pool's **Prefer own hosts** setting is on
(the default), the requester's own member hosts come first; it is a sort tier,
never a filter, so a request that fits no own host uses the rest of the pool.
Within a tier, the lowest dominant share after placement wins: the largest of
charged RAM, vCPU and the chosen storage pool's committed GiB, each divided by
its budget. Ties go to the lower charged-RAM share, then host ID. `lastPlacedAt`
is still recorded but no longer ranks. Reservations include queued,
stopped-root and uncertain obligations across overlapping pools and direct work.
The chosen immutable revision must be verified on that host's current
connection, or be fetchable to it now (see
[image distribution](../operations/templates.md#image-distribution)): hosts
that already have the image rank first. A contributed member never receives
another account's image unless its owner set `accept_foreign_images = true`
and the template allows **Any host**; the pool owner can cap such bytes per
member (**Image cache per member**, all other accounts' bytes on that member).
There is no failover or rebalancing. Selection and the locked
reservation use the same fit predicates; a selected host changing capacity is
retried after rollback, at most three times. Diagnostic categories use only
members the caller can see.

Refusals name the first failing stage: no compatible runtime or egress
enforcement is `sandbox.pool_no_compatible_host`; the exact revision on no
member at all is `sandbox.template_unavailable`; every member offline or
draining is `sandbox.pool_unavailable`; the revision registered but not
verified on any online member's current connection is
`sandbox.template_image_missing`. `sandbox.pool_full`,
`sandbox.pool_unavailable`, `sandbox.member_quota` and `sandbox.share_quota`
may carry `skipped: ["template_startup" | "template_unavailable" |
"lease_policy" | "vm_size"]`: some hosts you can see were excluded for that
static reason, for example "full among hosts that have your template; some
other hosts lack it". `template_startup` means the revision has a start
command and some hosts' daemons do not run start/ready commands; such a
revision is placed only on hosts that do, and a pool with none of them is
`sandbox.pool_no_compatible_host` (a direct host target is
`UNSUPPORTED_CAPABILITY`). It never
carries counts and never reflects a foreign member's online status. Only hosts
your session or key can see are evaluated.

Create resolves each optional `cpuCount` / `memoryMiB` / `diskGiB` override from the selected
revision before checking any candidate. A valid large VM can consume the whole
host resource budget across all creators. Pool use and an owned exact-revision grant are required. An owned member also
needs the key's host grant; an authorized foreign member is exempt from that
owned-host allowlist. Explicit host placement remains owner-only. Within that
authorized member set, unsupported versus accepted requests can reveal size fit.
Per-share RAM, vCPU and retained-disk caps are optional and default to unlimited.
A contributed member may also cap the pool's RAM/vCPU fraction of its host;
these caps reserve no capacity. Local storage pool caps are separate host commitments. See
[host capacity](./hosts.md#capacity-drain-and-deletion).

Drain a host on **Settings › Hosts** to prevent new placement across every pool. Other
members remain usable; if every compatible member is draining/offline, create
returns `sandbox.pool_unavailable`. Undrain restores eligibility without a
daemon restart when its launch evidence remains current. Drain does not stop
existing sandboxes or change accepted execution. `wssp host drain --offload` also
moves the host's stopped disks to the image store, whatever their offload
policy
([offloaded sandboxes](#offloaded-sandboxes)), and a draining member is never
a restore target.

SDK pool selection is independent of owned host/revision selection:
`ALL_USABLE` follows current usable pools and `SELECTED` fixes selected pool IDs.
The initial creating key retains authority for its creator-owned sandbox after
future pool grants disappear, for history and cleanup (reads, stop and
destroy). Other selected keys cannot inherit that work. Use (guest IO,
terminals, reconnect or restore) needs a grant for the sandbox's current host
and pool, and new placement and cold start require current selection, usable
paths and resource fit. An ALL_OWNED key may access its own creator's
retained sandbox even on a foreign host, unless its `SELECTED` pool mode
excludes the sandbox's current pool.

Discovery uses paged `GET /v1/pools`, `GET /v1/pools/{id}` (visible member
count), and `GET /v1/pools/{id}/members`. All require `pools:read`; member
discovery also requires `hosts:read`. Host and pool grants intersect before
pagination and counts, with the foreign-member exemption above. A shared pool
includes its owner's ID/name, your permissions/caps/usage and promised grace.
Usage quantities are decimal strings. Use grantees receive only member
`{id, poolId}` references; pool owners receive the approved host summary.
No per-member heartbeat or online status is disclosed to use grantees;
aggregate schedulable capacity is (see the capacity view below), so a pool with a
single foreign member implicitly shows whether that member can take work now.
Absent, unusable, unselected and deleted pools return the same
`sandbox.pool_not_found` 404. Pool reads grant no host management or host terminal.

## Capacity view

`GET /v1/pools/{id}/capacity` (`pools:read`; feature `pools.capacity`), the
dashboard's **Capacity** panel and `pools.capacity()` in the SDK report what you
could place now for a credential-free default-lease workload. Optional `template`, `cpuCount`, `memoryMiB` and `diskGiB`
select a size; revision defaults fill the rest. `fits` does not model attached
CLI logins or a custom lease. Create is authoritative: admission may change
between the read and request, or refuse requested credentials/lease policy.

- `aggregate`: free and budget RAM, vCPU and disk over hosts you can schedule
  on right now (enabled, compatible, online, not draining, and with the
  template verified when one is given). Free capacity is pool-usable: host free
  capped by each contributed member's RAM/vCPU percentage.
- `fits`: how many sandboxes of that size fit now, capped by your share caps.
  Hosts the queue holds for an older waiting create (the strict-head
  reservation a create would refuse with `pool_full` reason `reserved`) count
  as fitting nothing.
- `lease`: the same lease view as the pool itself.
- `queue`: waiting creates in the pool, how many are yours, your oldest
  position, the effective wait/queue limits and `preferOwnHosts`.
- `hosts`: only YOUR OWN member hosts, only with `hosts:read`, after the key's
  host allowlist: budgets, reservations, storage pools, member caps, `fits`,
  `dominantShareAfter` (the ranking value) and `excludedBy`
  (`template_startup`, `template_unavailable`, `lease_policy`, `vm_size`,
  `draining`, `offline` or
  `reserved`). A template you cannot resolve is `sandbox.template_not_found`.

Foreign host IDs, counts, status and per-host numbers never appear. Reads are
budgeted (30 per minute per account across both planes).

## Waiting for capacity

A pool create may pass `waitForCapacityMs` (1000..2073600000 ms, or
`"unlimited"`). When no host fits now and the request could ever fit a visible
member (static feasibility: compatible, template known, lease and per-VM fit,
fits an empty host within member caps and within your share caps), the create
returns its usual 202 receipt and waits: the sandbox reads
`WAITING_FOR_CAPACITY` with a `capacityWait` position, the CREATE operation
stays `QUEUED`, and nothing is held (no host, storage, quota or lease). The
lease starts when it is placed (at READY on hosts with
[lease from READY](./sandboxes.md#leases-renewal-and-expiry)). Direct
(`sandboxHostId`) creates refuse waits with `capacity_wait_exceeds_policy` and
`maxWaitMs: 0` (waits disabled there);
direct placement is the host owner's escape hatch and never joins a queue.
Waitable refusals are `pool_full` (any reason), `member_quota`, `share_quota`,
`pool_unavailable` (every eligible member offline or draining) and the
template not verified on any online member's current connection. Refusals that
waiting cannot fix (no compatible host, template on no member, VM larger than
every member, a lease no path allows) fail at once.

Each pool is a FIFO by entry order. The oldest entry blocked by a pool
resource is the **head**; an entry blocked only by its own share cap keeps its
place but blocks nobody, and an entry whose hosts are offline or draining is
never a head. A later request may place on a host the head could not use now
at no cost; placing on a host the head could use spends one of the head's 8
bypasses. After 8, those hosts are reserved for the head (a non-waiting create
gets `pool_full` with `reason: "reserved"`; a waiting one queues behind it)
until the head is placed, times out or is cancelled. Head eligibility uses the
head's current view (its creator's grants, verified template, online hosts)
and ignores hosts whose capacity is held only by leases outliving the head's
deadline or by retained roots (stopped disks, keep-on-expiry leases), so a head
can never freeze a host it could not use. A placement whose deadline passes
while it waits for a host lock is rolled back and times out instead. The gate
consults the heads of every pool that shares the chosen host, so a host in
several pools cannot starve a head. This guarantee covers pool creates only:
direct creates and cold reconnects do not consult the queue.

Limits layer like the lease policy: the deployment
(`SANDBOX_CAPACITY_WAIT_MAX_MS`, `SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY`,
`SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER`) and the pool's own wait, per-key and
per-account limits, which can only lower them; a pool wait of 0 disables waits
there. `"unlimited"` is allowed only when no layer limits the wait. A request
over the effective limit is refused with `capacity_wait_exceeds_policy`
(`maxWaitMs` is that effective limit), never clamped, even when the create
could be placed at once; a full queue is `sandbox.capacity_queue_full` with
`scope: "key" | "owner" | "pool"` (4096 waiting creates per pool at most).

The placer re-checks everything at placement: the creator's key (revoked,
expired, scopes, host/revision/pool grants, owner two-factor policy), session
owner policy, share use, pool deletion and the lease policy. A wait ends:

| End                                                 | Sandbox                           | CREATE operation (`errorCode`)                            |
| --------------------------------------------------- | --------------------------------- | --------------------------------------------------------- |
| Placed                                              | `REQUESTED`, then the normal boot | stays active; lease accepted now                          |
| Deadline passed                                     | `DELETED`                         | `FAILED`, `capacity_wait_timeout`                         |
| Destroy, stop or operation cancel                   | `DELETED`                         | `CANCELLED`, no error code                                |
| Share, key, pool or account access lost             | `DELETED`                         | `FAILED`, `access_denied` / `credential_inactive`         |
| Can no longer fit (lease lowered, revision retired) | `DELETED`                         | `FAILED`, `lease_exceeds_policy` / `placement_infeasible` |

On `/v1` the reason is the CREATE operation's `errorCode`
(`GET /v1/operations/{operationId}` with the create receipt's operation); the
sandbox record itself carries no error code there. The dashboard shows the
same code as the sandbox's last error.

Pool owners see every waiting create in their pools (requester name, size,
waited since, deadline, blocker) but cannot cancel another user's entry;
revoking the share ends it. Waits are evaluated after every release, undrain,
reconnect, template verification and policy change, and at least every 15
seconds. Each pass evaluates the head, the oldest entries and a rotating window
that resumes where the previous pass stopped, so entries blocked by their own
caps never starve later ones; pools are discovered the same way.

## Sharing, contribution and access loss

Use and contribute are independent permissions. A contribute-only grantee can
inspect and withdraw their own members, without using the pool or inspecting
its generic member roster. Disabling a member blocks new placement; withdrawal
removes a path. A cap-fitting alternate path keeps existing work running and
moves current quota attribution. Losing the last usable path denies guest IO
immediately and queues STOP, retaining disk through the accepted grace promise.
Restoration permits cold start on the same disk after the stopped result settles.

Grace defaults to three days and ranges from zero to 30 days. Placement pins the
accepted promise; a later decrease cannot shorten it. Last-path loss fixes the
deletion deadline, and repeated scans cannot extend it. At expiry, destroy frees
retained disk only with positive original-storage cleanup proof. Offline STOP is
enforced on reconnect or the effective local lease, whichever can first be
enforced; a powered-off daemon cannot act. Offline/dead storage can delay proven
cleanup and block host/account deletion beyond the grace deadline. Pool or
host-owner bans deny affected foreign IO and STOP guests without starting a
ban-caused deletion grace.

**Users of a pool with foreign hosts must trust those host operators. An
incus-admin user on a host can reach every VM on that host.** Pool and host owners
gain no guest execution, file, command-output or guest-terminal API authority.
A contributor accepts foreign guest egress from their network/IP and consumption
of their budgets. Withdrawal retains foreign disks for up to the pool owner's
promised grace, and host deletion waits for positive cleanup proof. Disabling
dashboard host terminals does not remove the local operator's powers.

Refusals inspect only granted active members: an empty visible set gives 403;
no compatible host gives `sandbox.pool_no_compatible_host`; compatible hosts
without current eligibility give `sandbox.pool_unavailable`; eligible hosts whose per-VM ceilings are too small give
`sandbox.vm_size_unsupported`; capable but occupied hosts give
`sandbox.pool_full`. Capacity refusals carry `reason: ram | vcpu | disk | storage | ceiling` and use
409. Every capacity, quota and pool refusal also carries the required
`retryable` flag and, only when it is `true`, `Retry-After`
([harness policy](#harness-create-and-fallback-policy)). Diagnostic precedence is visibility, current host/source, per-VM fit,
storage, RAM, ceiling, vCPU, disk; only a jointly fitting host is eligible.
Retained cold starts never select a replacement pool and report unavailable
original storage as `sandbox.host_capacity` with `reason=storage`. A restore
of an offloaded sandbox picks among your own hosts and the origin pool's
members, unless its reconnect names a `sandboxHostId` or `poolId`. Hidden hosts cannot
change these categories or counts.

The SDK preserves raw refusal codes and surfaces definitive pool/full and host
capacity errors immediately. Rate/quota 429, 5xx and lost responses retain
same-key retry/reconciliation. Replaying an accepted request returns its
original placement and lifetime after pool/member/tag changes; a changed
request conflicts. A revoked credential after placement gives an operation
outcome, never a new pool refusal. Possible send/unknown effects keep their
reservation until evidence resolves them. See the
[compiled SDK example](../../packages/sdk/README.md#pools-and-immediate-fallback).

## Dashboard walkthrough

1. Open **Pools → Create pool**. Choose an owner-local slug and a label. Open
   **Manage members → Add host** to select enrolled hosts; use **Load more** in each
   list or picker to reach later pages. Enable/disable a member without removing
   it, or remove it after typing its host slug. Edit pool settings in a sheet;
   deleting a pool requires its slug and keeps accepted sandbox history.
2. On **Templates**, register a logical template, then use **Manage revision**
   on its exact revision to verify the same fingerprint on each intended member.
   **Verification pending** permits minting a grant but does not prove launch readiness;
   **Verified image** must belong to the host's current connection. With image
   distribution on, a member without the image can still be chosen and fetches
   it at create time; a fetched copy then shows as a cached copy.
3. On **Sandboxes → Create sandbox**, choose the logical template independently
   of placement. Keep **Latest tag (resolved once at acceptance)** to resolve `latest` once at acceptance, or
   choose an exact revision ID. Then select **Pool** or **Explicit host**.
   Changing placement preserves the template choice. Revision choices are
   paged, and retirement/compatibility/admission are rechecked by the server.
4. Choose a relative lifetime (five minutes by default) and stop or destroy on
   timeout. Add bounded string labels and private JSON environment overrides
   only when needed. Labels are visible resource metadata; never put secrets
   there. Env values have no detail readback or automatic toast disclosure.
5. Submit once. The detail page shows server-reported state, exact revision ID,
   retained origin-pool ID (or explicit-host placement) and requested/effective
   lifetime. Acceptance is not READY. An uncertain response may have accepted
   work: retry the unchanged draft in the open dialog to reuse the exact key
   and body. Changing the draft creates a new intent. After closing the dialog,
   inspect the sandbox/operation lists before starting another create.

A definitive refusal releases the browser intent. Input-validation refusals
keep the environment editor so you can correct the form: `sandbox.metadata_invalid`
(labels), `sandbox.egress_policy_invalid`, `BAD_REQUEST` (including invalid env
input or lifetime above the deployment maximum), `PAYLOAD_TOO_LARGE`,
`UNSUPPORTED_MEDIA_TYPE`, and `UNSUPPORTED_CAPABILITY` (unsupported requested
features). These validations refuse before anything is dispatched to a host.
Other definitive refusals, including host/image/runtime and placement refusals,
clear the editor; re-enter overrides deliberately before submitting a new
request. Success and closing the dialog also clear it. Unrecognized errors keep
their existing behavior; uncertain failures retain the exact draft in memory
for same-key replay. Env values never enter browser storage or persisted drafts.
Neither closing the dialog nor clearing its editor deletes the server/host
snapshot of accepted work.

## Lease limits

Each sandbox's longest lifetime is the smallest of the deployment maximum, its
host's ceiling (set on the machine with `wssp host config set-max-lease`), the pool
maximum and the membership maximum; see the sandboxes guide's "Layered lease
policy".

- **Pool maximum.** The pool owner sets "Maximum sandbox lifetime" (blank means
  no pool limit) and "Who may create sandboxes without a time limit": only the
  owner (default) or anyone who can use the pool.
- **Membership maximum.** Only the host owner sets it: the pool owner for an
  own host, the contributor in the contribution form for a contributed host.
  The pool owner can disable or remove a contributed host but never change its
  limit. Lowering needs no consent; raising (or clearing) re-proves the
  contribution consent. A removed membership that is added again starts with
  no limit unless one is given. Omitting the field leaves it unchanged.
- **Sandboxes on your own host** keep the limits of the pool they were created
  through for their whole life, even after sharing stops attributing them to
  that pool. If the host leaves the pool, or the pool is deleted, only the host
  ceiling and the deployment apply.
- **Discovery.** `GET /v1/pools` and `GET /v1/pools/{id}` return
  `lease: {maxTimeoutMs, timeoutZero}`: the best available path for the calling
  key, computed with the key's host allowlist exactly as placement uses it. It
  counts enabled members whose host is not being deleted, including offline
  ones, so a create may still be offered less.
- **Disclosure.** A pool whose only usable member is one contributor's host
  reveals that host's effective ceiling through `lease.maxTimeoutMs` and the
  error's `maxTimeoutMs`. This was accepted as low sensitivity; a contributor who
  does not want the exact ceiling visible sets a membership maximum below it.
- **Lowering.** Saving a lower pool or membership maximum first shows how many
  running sandboxes it shortens; after saving, the server pulls their
  deadlines in to now plus the new limit through a host-acknowledged,
  shorten-only lease update. See [sandboxes](./sandboxes.md).

## Choosing a recovery action

| Response                                                                             | Meaning and action                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 409 `sandbox.pool_full`                                                              | No visible member jointly fits the requested live/root resources. Read the bounded capacity reason; confirm release, restore healthy storage or ask the operator to review local budgets. Check `retryable`; pass `waitForCapacityMs` to queue instead. |
| 409 `sandbox.vm_size_unsupported`                                                    | Current visible members cannot fit the requested per-VM CPU/RAM/root allocation. Choose a suitable host or revision.                                                                                                                                    |
| 409 `sandbox.pool_no_compatible_host`                                                | No enabled visible member meets the exact revision/architecture/runtime requirements. Verify the image on an appropriate member or choose another revision.                                                                                             |
| 409 `sandbox.pool_unavailable`                                                       | Visible members exist but are disabled, or compatible members are offline, draining or missing current launch evidence. Enable/undrain or reconnect and verify before retrying.                                                                         |
| 409 `sandbox.host_capacity`                                                          | The explicit host cannot fit RAM/vCPU/disk/storage/guard requirements. Read reason; confirm release or restore the original storage for retained work.                                                                                                  |
| `restore_no_allowed_host` (operation failure)                                        | A restore of an offloaded sandbox waited for its deadline and no eligible, allowed host had capacity. The sandbox stays `OFFLOADED`; free capacity, add an own host, or widen the key allowlists, then start again.                                     |
| 409 `sandbox.host_draining` / `sandbox.host_unavailable`                             | The explicit host is draining or cannot admit a fresh launch. Fix host readiness or change placement.                                                                                                                                                   |
| 403 `FORBIDDEN`                                                                      | No visible active member is permitted, or required authority is missing. Check scopes and grants. This response reveals nothing about hidden members.                                                                                                   |
| 409 `sandbox.template_image_missing`                                                 | The exact image is absent on the selected host. Restore that fingerprint and verify its revision again. Failed create operations report the same code.                                                                                                  |
| 400 `lease_exceeds_policy`                                                           | The requested `timeoutMs` (or `0`, no time limit) is longer than the best visible path allows. `maxTimeoutMs` is that path's largest finite lifetime, including the deployment; request at most that. Hosts hidden from the key never contribute.       |
| 404 `sandbox.pool_not_found`, `sandbox.host_not_found`, `sandbox.template_not_found` | The named resource is absent or unavailable to the caller. Rediscover with the same credential; do not probe another owner's IDs.                                                                                                                       |

All-disabled visible members produce `pool_unavailable`, even without compatible
image evidence. Removed members are not visible active members. A pool's
refusal category never uses hidden hosts to improve or worsen its answer.

For production keys, follow the [re-mint walkthrough](./auth-planes.md#minting-sdk-resource-grants)
before testing pool placement from the SDK. Listing a pool does not grant host management or another creator's revision
defaults; placement still needs current use, owned revision authority and fit.

## Offloaded sandboxes

A stopped sandbox's disk can move to the image store and restore on another
host ([disk offload](./sandboxes.md#disk-offload)). For pooled sandboxes:

- A restore tries your own hosts first, then the sandbox's origin pool, with
  the pool's member flags and caps (a restore counts as a new root). A
  `sandboxHostId` or `poolId` on the reconnect picks the target instead. The
  owner's dashboard override lifts only the creating key's allowlists.
- A foreign member is a restore target only when it accepts foreign images,
  the sandbox is not pinned to own hosts, has no login history, and its
  template's image placement allows other users' nodes. Open-egress sandboxes
  also need that member's open-egress consent.
- An offloaded sandbox holds no RAM, vCPU or disk in any pool. A stale local
  copy waiting for cleanup on a member still counts toward that share's
  disk until it is discarded.
- A system teardown (for example on access loss) of a sandbox with a stored
  copy detaches it to `OFFLOADED` rather than deleting it, and it can
  restore on a path you can still use.
- Waiting restores use the same scheduler as
  [waiting for capacity](#waiting-for-capacity) and fail
  `restore_no_allowed_host` at their deadline (or the login refusal that
  stopped their latest placement attempt; see
  [Disk offload](sandboxes.md#disk-offload)).

## Sharing, invitations and contribution consent

The Owned and Shared with me tabs separate settings/roster authority from use.
Owner-added shares default to both use and contribute; either can be granted
independently. Blank RAM/vCPU/disk limits mean unlimited. The roster shows each
share's current usage; stopped guests keep disk charged. Contributor percentages
limit that pool's RAM/vCPU use of one host and reserve no physical capacity.
Only the host owner can set those percentages or contribute that host. They
apply only to contributed hosts: your own hosts in your own pool are never
capped, so setting a percentage there is refused
(`pool.member_caps_owner_local`). Pool
owners may disable or withdraw contributed members but cannot edit a foreign
host's local budgets. ownHostsOnly withdraws foreign contributions.

Users of a pool with foreign hosts must trust those host operators. An
incus-admin user on a host can reach every VM on that host. API restrictions and
disabling dashboard host terminals do not isolate guests from local admins.
The pool owner manages the operator set; current members do not guarantee
future operators. Contributors accept foreign egress from their network/IP and
shared host budget consumption.

Invitation links carry a seven-day digest-only secret in the fragment, captured
and removed before rendering/auth redirects. Copy-once links and signup secrets
stay in browser memory, never Query caches or storage. Resend rotates the link;
SMTP failure means delivery is unconfirmed. Explicit acceptance shows your
signed-in account. Bearer mode permits forwarded links to a different existing
account; email-only mode requires the verified invited email. Closed signup
requires both the original token and exact invited address, with mailbox proof
before explicit acceptance. Reopen the original link after verification/sign-in
or reload; no secret is persisted. Signup-capable invitations are limited to
five per inviter/day and confer no unrestricted signup bypass.

The create form displays and submits a guaranteed grace quote, 0–30 days
(default three). Acceptance pins acceptedGraceSeconds. A decreased quote refuses
before acceptance; an increase improves the guarantee. Losing a path moves usage
to the lowest fitting permitted path. No fitting path denies IO immediately and
queues STOP, retaining disk until the frozen deletion deadline. Disabling a
member affects new placement only. Withdrawal/use/contribute loss, pool deletion
or ownHostsOnly may remove paths. Restoring a fitting path before destroy
commits clears access grace; a cold start boots the disk on the host that holds
it (or restores an offloaded disk) and checks current caps. A sent uncertain destroy must settle before restart.

Shortening grace never reduces an accepted promise; zero knowingly permits
immediate deletion. Withdrawal retains foreign disks for up to the accepted
pool grace, at most 30 days. Host deletion waits for positive cleanup proof,
potentially longer if storage is offline/dead. Pool/host-owner bans may stop
foreign use but do not create ban-caused deletion grace. Deleting a pool owner's
account first requires normal pool deletion and scanner evaluation;
shared_pool_workloads explains that blocker. Dead disks can also block a guest
creator's account. **Forget unreachable host** detaches only sandboxes that
have a stored copy ([hosts](./hosts.md#capacity-drain-and-deletion)); a disk
without one still blocks until a future storage-forget feature exists.

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
