# Host policy reconciliation

The service-owned expiry sweep also inspects policies. It captures lease arms
before IO, schedules a bounded rotating batch of 16 active ids, and continues
the existing enforcement-loss drain even if inspection/status persistence fails.
No parallel cleanup mechanism, census-owned deletion, DNS refresh scheduler, or
new dispatch authority is introduced.

The runtime compares the journaled ACL, bridge and effective NIC configuration
through the existing coherent `EnforcementVerdict`/`verify_bound_enforcement`
boundary. Busy sandbox locks defer observation as pending (they do not interrupt
the managed operation's already-fenced internal readiness). Unavailable evidence
is inconclusive; each candidate has an independent five-second daemon-work
permit. Managed DNS
transitions remain seqlock-protected. Only fresh coherent verification or
lifecycle-completed teardown clears
the shared guest-dispatch refusal used by command and file/helper adapters.
Inconclusive evidence refuses new guest dispatch but NEVER authorizes stopping,
deletion, lease settlement, or repair.

Every guest subprocess goes through `IncusClient::spawn_guest`: ordinary
readiness/filesystem/recovery/signal helpers, supervised/cancellable commands,
and both file transfer runners retain their positively bound sandbox identity
until that boundary. Argument construction and file staging are not admission.
The existing refusal mutex serializes publication against the current refusal
check AND local process spawn; the current RuntimePermit is also admitted
through spawn. Both guards release before pipe IO, daemon responses, execution
or waits. No new marker or long lifecycle lock is involved. Uncertainty returns
typed `EnforcementInconclusive`, never cleanup authority. Existing-command
termination remains subject to ordinary refusal (with no exception).

Live probes hold the same per-sandbox gate through observation, Prepare and
stale-authority recovery. Periodic inspection skips that busy id rather than
starting a second observation halfway through the probe's fresh-arm retry.
Confirmed-loss recovery retains separate cleanup permits; the inspection
batch bound is not a fixed wall-clock deadline for a complete recovery pass.

All readiness producers use that existing gate: fresh/existing create and
warm/cold reconnect fence each daemon poll and re-observe before final guest
identity/repo checks; queries fence verification through guest identity; probes
retain their full observation boundary; inventory fences its policy observation.
The gate is released between boot polls (including sleeps), not held across a
boot timeout. Reconnect releases its mutation section before polling. There is
no instance-only compensating lock. Restrictive stop and lease expiry keep their
independent cleanup permits. Policy uncertainty carries typed runtime evidence
through helper/effect/readiness wrappers and retains its non-cleanup wire code.
It must never become `GuestUnavailable` at the final readiness adapter.

Confirmed running-VM drift crosses the pre-observation captured-authority
Prepare boundary, durably revokes that lease arm, journals recovery and
immediately ownership-fenced force-stops the VM. Failed bookkeeping still stops
restrictively. A changed arm follows the restrictive-stop, fresh-capture,
fresh-ownership, fresh-coherent-verification retry; stale evidence never
prepares a newer arm. The existing immutable worker-intent CAS, successful
durable Prepare before deletion, and verified VM AND network absence before
Complete remain mandatory. Ordinary connected expiry-status convergence
releases server and local live capacity. Runtime-only census cannot delete.

Repair means converging retained **owned** resources through the existing
fenced cleanup/reprovisioning lifecycle, not silently broadening or live-healing
a running sandbox. Every Incus mutation still rebinds positive VM ownership or
checks network/ACL sandbox/project/incarnation ownership. Foreign resources are
never restamped or deleted. A foreign VM refusal is recorded in
`policy-reconciler/state.json`; foreign network cleanup retains the loss and
cleanup obligations. Healthy, absent and inconclusive inverse controls remain
non-destructive.

`policy-reconciler/state.json` uses the existing atomic file-fsync/rename/
directory-fsync writer. It retains the rotating cursor and last observation per
active lease id, pruning retired ids. Status/cursor data is observational, NEVER
mutation authority. Memory preserves rotation if status storage fails. Durable
loss records and lifecycle lease intents, not health, drive restart cleanup.
The fake runtime offers independent ACL/network/NIC, unavailable and foreign
faults, and can reopen its reconciler while the simulated external daemon lives.

Heartbeat `policyReconciler` reports enabled, last-pass time and counts of last
observed verified/drift/inconclusive/foreign/absent/pending active ids. These are
historical polling observations, NOT a continuously verified host-wide claim or
packet evidence. The socket reader uses a local snapshot, never daemon IO.
Telemetry requires explicit **10.1** minor-version selection in `hello.ok`,
matching `capabilities.protocolVersion` and advertised server support.
Daemons send the unchanged strict **10.0** hello envelope and advertise
`supportedProtocolVersions: ["10.1", "10.0"]`. Baseline servers select 10.0;
heartbeats then omit `policyReconciler` entirely (not null). New servers select
10.0 for old daemons and 10.1 only when offered. No extra optional handshake
fields or relaxed unknown-field validation are used. Unsupported/inconsistent
selections are refused before heartbeats, and unnegotiated telemetry is refused.
The server stores the bounded report plus a server `reportedAt` timestamp in
the nullable, display-only `SandboxHost.policyReconcilerHealth` metadata column
under the current authenticated owner/host/epoch fence. A new hello resets that
column to an empty, unreported object so prior-epoch health is not reused.
Owner-scoped host lists and native host DTOs expose only the schema-validated
report, never raw health metadata or unknown host-supplied fields.
It does NOT promote `egressPolicy`, alter dispatch authorization, clear
quarantine or settle any sandbox. Legacy heartbeats retain the latest report.

Hardware evidence remains OUTSTANDING. See the non-executable
[qualification specification](../operations/host-isolation-qualification.md).
ACL compilation, shim execution and fake lifecycles prove control-plane
ordering/refusal only. The existing create/detail DOM tests cover **recorded**
policy and metadata. Refresh/readback coherence is described below.

DNS grant refresh: the production refresh caller is now the
same service-owned expiry loop, as a separate cadence-gated pass (about once a
second, one pass at a time, its own revocable permit joined on shutdown). It
refreshes only lifecycle-active ids whose recorded domain grants are past
half-life, whose VM is running, and that carry neither a reconciler refusal
nor a recorded enforcement loss; a busy sandbox lock defers to the next pass
(probed before resolution, so a held lock costs no lookups).
Issuance reuses the journaled `enforce_and_commit_refresh_plan` boundary, so
refresh stays a managed DNS transition to verification. It never clears a
refusal, settles a lease or repairs drift, and a skipped or failed refresh
leaves the armed expiry lease to fence the grant.

Owed refresh: a refresh mutates the live ACL
(and possibly the bridge's `raw.dnsmasq`) before its durable commit. The DNS
revocation marker now records `refresh_owed` before the first mutation and the
digest of every `raw.dnsmasq` body before it is published; only the commit
clears them (network teardown clears them too). While a refresh is owed, or the
marker holds uncommitted revocations or pending mutations, the readback compares
the live state first. A divergence the owed work explains is refused as
inconclusive, never drift. The classifier runs whenever work is owed, even
when the live ACL equals the old plan. Explained means:

- ingress and every static or base egress rule are exact;
- DNS-tagged rules that are `disabled` or `reject`/`drop` may appear or
  vanish. Any other DNS-tagged rule must be an exact `enabled` canonical
  `allow`; `allow-stateless`, a `logged` allow (Incus's third, active state,
  now modelled rather than refused) or an unknown action is drift;
- planned DNS allows may be absent;
- every DNS allow present is fenced, or is a planned or ledger-armed identity
  with its DNS/DoT companions;
- an identity the refresh DENIED is never explained. If it is live, unfenced
  and its destination is not still granted by another explained allow or a
  static CIDR, it is drift;
- `raw.dnsmasq` is the committed body or a journaled attempt.

Anything else is still drift. "Owed" is a value, not an early return: the
bridge config, the static rules and the instance devices (eth0 bridge and
filtering, extra NICs or devices, NIC ACLs) are verified in every
observation, owed or not, and convict on a mismatch. Only after all of them
pass is the owed refusal surfaced. The old
rule (an uncommitted revocation is drift) let a refresh that withdrew a denied
grant and then failed to publish get its healthy VM halted by the reconciler
and destroyed by the loss drain. A failed DNS expiry recovery no longer
short-circuits the verdict either. It runs the same coherent snapshot in owed
mode, so unexplained drift still convicts and everything else is inconclusive.
An owed refresh is scheduled at the 15-second retry spacing. It runs despite a
reconciler refusal only when that refusal's last cause was the owed refresh
itself (typed `RefreshOwed` evidence, tracked per sandbox). Any other refusal
cause, and a recorded loss, still skip it. A failed, uncancelled refresh
settles its journaled revocations at once through the expiry boundary (fence
first). A create retry over an existing VM with an owed refresh
is refused as inconclusive instead of rolling back the live network.

Liveness: every blocking state has one owner and an exit.
The rule: only the refresh pass commits owed DNS work. It runs whenever a commit
is owed, for a running **or stopped** owned VM; a missing or foreign VM is left
to teardown. The refresh mutates only the host-side bridge and ACL. An uncertain
allow request is a non-blocking obligation unless its rule is live.

| State                                                                | Blocks readiness?                              | Owner and exit                                                                                                                                         | Bound                                                                       |
| -------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `refresh_owed`, journaled publication digests, uncommitted `revoked` | yes (inconclusive)                             | the refresh pass commits them (running or stopped VM); teardown retires them                                                                           | next successful refresh, retried every 15 s; or lease end, which tears down |
| denied destination still open                                        | no: drift                                      | reconciler convicts, then the loss drain tears down                                                                                                    | one observation                                                             |
| `pending` uncertain allow, rule absent                               | no                                             | stays journaled and preventively fenced; retired by lease withdrawal evidence or ACL rebirth                                                           | non-blocking                                                                |
| `pending` uncertain allow, rule live (landed late)                   | yes (inconclusive, `RefreshOwed`)              | the reconciler records the cause; the refresh pass withdraws the rule and retires the entry                                                            | next refresh after landing                                                  |
| `pending` uncertain allow at CREATE (apply readback)                 | yes: the create fails closed                   | rollback; the retry's reborn ACL converts the entry into a standing fence                                                                              | one create retry                                                            |
| `pending` fence release                                              | yes (inconclusive)                             | the refresh pass retries the release boundary                                                                                                          | next successful release; over-denial only                                   |
| standing fence obligation                                            | no                                             | positive withdrawal evidence; survives teardown by design                                                                                              | non-blocking                                                                |
| reconciler refusal                                                   | dispatch only                                  | the next verified observation (2 s); a `RefreshOwed` cause is cleared by the owed refresh, which may run despite it; other causes clear with the cause | cause duration                                                              |
| DNS expiry recovery failure                                          | yes (inconclusive) unless drift is unexplained | the watcher and every observation retry; a denied destination left open convicts                                                                       | daemon recovery                                                             |
| daemon restart                                                       | every id refused until verified                | the reconciler re-verifies; the scheduler re-derives owed work from durable markers                                                                    | 2 s plus one refresh                                                        |

The observation's read budget is a child of the caller's permit: revoked with
it, never longer than what the caller had before DNS expiry recovery ran, and
not granted at all if that budget was already spent.
