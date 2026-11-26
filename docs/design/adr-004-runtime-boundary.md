# ADR-004: Runtime boundary

## Status

Accepted; separate host access is defined by [ADR-006](./adr-006-agent-host-access.md) (2026-11-12).

## Context

API procedures must remain portable and testable while Incus integration stays
on Linux node daemons. There is no TypeScript in-process runtime shim; the
node daemon is the only process that talks to Incus.

## Decision

- Define `SandboxRuntime` in `crates/sandbox-runtime`.
- Ship `FakeRuntime` for unit tests and relay plumbing without VMs.
- Production implementation is `IncusKvmRuntime` on Linux, driven by the host
  daemon (`wssp host run`) through the relay protocol in
  `crates/sandbox-protocol`. Non-Linux hosts use `UnsupportedRuntime`.
- Control-plane TypeScript (`packages/api`, `apps/server`) never imports Incus
  and never executes guest work locally.

## Consequences

- `sandboxes` router procedures enqueue durable operations; the node daemon
  performs create/stop/exec/file work.
- Instance names are `wssp-sbx-<sandboxId>`.
- Unsupported platforms return stable runtime errors from the host
  implementation, not from the API process.

## File IO

Runtime file requests/responses use `FileContent`, an immutable private disk
capture with chunk readers, size and SHA-256. No host filename comes from a guest
path. Incus file IO executes the bundled Python 3 helper as the declared guest
UID/GID. Readiness requires Python 3. The helper rejects symlink path components,
non-regular files and traversal. An upload is a single helper invocation that
stages and fsyncs a temporary guest file, verifies length/hash, and renames only
after the host writes a commit byte while holding the operation's current runtime
permit (the revocation lock). Revocation before that byte makes the helper delete
its staging file (FAILED `cancelled`); revocation after it is UNKNOWN, never
success. The staging name derives from operation/generation/attempt, so
`SandboxRuntime::recover_file_put` can settle an interrupted attempt after a host
crash from guest evidence alone (staging present ⇒ removed, FAILED; exact bytes at
the destination ⇒ SUCCEEDED; otherwise UNKNOWN).

## Terminal PTY

`SandboxRuntime::open_pty` returns a `PtySession`: the single attachment to one
guest shell. It is not `Clone` and every IO method takes `&mut self`, so there
is no second reader, writer or resizer (no multi-attach). Runtimes advertise
support with `pty_capability()` (fail-closed `false`); the trait default and
non-PTY runtimes refuse with `UNSUPPORTED_CAPABILITY`, and `UnsupportedRuntime`
keeps its `HOST_RUNTIME_UNSUPPORTED` shape. No relay, browser auth or UI is part
of this contract; the relay channel is the
[terminal relay contract](./terminal-relay-contract.md) and [browser authentication and UI](./browser-terminal-auth.md).

- **Child.** The host allocates a PTY only for
  `incus --project <p> exec --user <uid> --group <gid> --cwd <home> --env HOME=…
  --env SHELL=… --env TERM=xterm-256color -t wssp-sbx-<id> -- <declared-shell>`.
  argv is built structurally; the shell is one element after `--`. No host shell
  runs in this guest PTY opener. The Incus client gets a scrubbed environment,
  and the guest gets no control-plane credential. Separate host terminals and
  scoped host commands can run host shells under [ADR-006](./adr-006-agent-host-access.md).
- **Identity.** The request has no instance-name field. The name derives from
  the sandbox id and is positively bound against Incus metadata (VM type,
  sandbox tag, template and base image) before spawn. The guest UID/GID/HOME/
  SHELL are the identity recorded for the sandbox, the same contract as command
  execution. The spawn crosses the same admission section as exec (binding
  recheck, runtime permit, policy-refusal fence).
- **Sizes.** Rows are 1–512 and columns 1–1024. Out-of-range sizes are refused
  (`PROTOCOL_ERROR`), not clamped. A resize is `TIOCSWINSZ` on the master; the
  kernel signals `SIGWINCH` to `incus exec`, which forwards the size.
- **Bounds.** Output is pumped through a bounded queue (64 chunks of up to
  16 KiB each), so a slow consumer back-pressures the PTY instead of growing
  memory. Input is one write of at most 64 KiB, into a 16-slot queue. A full
  queue returns `RATE_LIMITED`; it never blocks the caller.
- **Close intent.** A child that exits on its own ends as `ChildExited`, and
  queued output is delivered first, with a grace period of up to 5 s. A runtime
  close ends as `Closed { intent, reaped }`, where the intent is `Client`,
  `Detached`, `Expired`, `SandboxStopped`, `SandboxDestroyed`, `Shutdown` or
  `LifecycleUnconfirmed` (a stop or destroy was attempted but not confirmed, so
  the terminal was closed conservatively while the VM may still run). `reaped`
  is `false` when the reap did not finish within its bound; anything charged to
  the session must then stay charged. The child handle is then retained, and
  `PtySession::reap_confirmed` makes one non-blocking reap attempt per call: a
  reconciliation sweep releases the charge only once a reap is actually
  confirmed. The recorded termination never changes. Close is idempotent: the
  first terminal state wins, and a close after a natural exit reports that
  exit. Session ids are scoped to their sandbox.
- **Reap.** Every exit path reaps the child before the master is released.
  Close sends SIGHUP to the `incus exec` client, waits briefly, then SIGKILLs
  its whole process group. Before the leader is reaped, on a close or a natural
  exit, the group is killed, so a descendant that ignores SIGHUP cannot keep the
  tty, the reader or the master alive. No signal is sent after the reap. The
  group kill is scoped: only a group the child leads (`/proc` pgid equals
  its pid), and never pid 0 or 1, the daemon itself or the daemon's own group;
  closing a terminal never stops the VM or touches another session. If a
  stalled child left the input writer blocked on a full tty queue, that queue
  is drained from a non-controlling, non-blocking slave descriptor (flags from
  `libc`, so the drain runs on every Linux architecture), so no thread or
  descriptor leaks. Each session
  has a lifetime: 4 h by default, at most 12 h. A supervisor expires the session
  without needing a consumer. Every VM `stop --force` and `delete --force`
  effect closes the sandbox's sessions after it runs, never before. The effect
  therefore gets the caller's full runtime-permit budget, however many
  terminals are open. Sessions are closed concurrently, so the close costs about
  one bounded session close. An open reserves its session id before binding, so
  a concurrent stop or destroy either dooms that open or is seen by the
  binding.

## Tracked process and timerless command contract

Non-kill signals open/verify a guest wrapper group pidfd, then
signal the process group, or refuse signal_unsupported_on_guest before effect.
There is no host pidfd across the VM boundary or numeric/leader-only fallback.
SIGKILL remains canonical cancellation. After exhausted cleanup, transport death
does not establish guest death; UNKNOWN has no command retry and sandbox
stop/kill is recovery. Command timeoutMs=0 removes only the command timer;
finite setup, lease and execution authority remain. See the
[filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits) and
[unrun real-guest checklist](../testing.md#fsprocess-real-guest-acceptance-not-yet-run).

## VM allocation and daemon resources

`CreateSandboxRequest` and `ReconnectSandboxRequest` require a validated
`VmSize` (CPU count and guest memory in MiB). The shared policy permits integer
CPU counts 1–32 and memory 512–65536 MiB in 256 MiB steps. Invalid allocation
fails before daemon or network IO. The daemon passes the decoded dispatch
allocation pinned on the accepted sandbox and boot placement. Launches
require both dimensions; unsized fresh launches are refused. Historical
on-disk records alone retain 1 vCPU / 1024 MiB deserialize defaults.

Stopped init explicitly writes `limits.cpu=<decimal>` and
`limits.memory=<decimal>MiB` before the first start. The common
`IncusClient::start(bound, vm_size)` fence compares effective config with those
exact strings and preserves the identity, device and recorded egress fences.
Existing create retries verify allocation before network adoption or saving
provisioning intent, recheck under the sandbox lock before adoption, and check
again at start or running completion. Warm and cold reconnects verify allocation
before config, lease or network mutation, then use the same start boundary. A
missing CPU key means only 1 CPU; a missing memory key means only 1024 MiB. Inherited
profile/image limits must match, and the two literal keys alone join the closed
allowlist. Alternate units, bytes, leading zeros, whitespace, percentages, CPU
pinning/topology and sibling `limits.*` keys are refused. A disagreement returns
`vm_size_mismatch`; it does not resize, relabel or delete an existing VM. No
second allocation metadata record or equivalence normalizer exists. Existing-VM create and reconnect
refusals are possibly effective (`UnknownOutcome`), including identity and
allocation refusals before this attempt mutates anything. An earlier attempt
may already have started the VM; `vm_size_mismatch` alone never authorizes
releasing its live slot. Only a proven first 0→1 refused claim may fail and release.

`SandboxRuntime::sandbox_inventory` returns named local `RuntimeInventoryEntry`
values with sandbox identity, lifecycle state and a `ConfiguredSize` enum:
`Configured(VmSize)`, `Conflict` (invalid or noncanonical config), `NoInstance`
(cleanup-only), or `Unobserved(RuntimeError)` (transient read failure). Incus uses
effective config and narrowly decodes canonical decimal / MiB values; malformed
size evidence stays on that entry rather than failing the whole census.
FakeRuntime retains the accepted size independently of its lifecycle response
record and preserves it across stop/reconnect. Relay inventory and successful
result payloads do not gain size fields. Weighted reservation and
journal fallback consumers use the same allocation rules.

`SandboxRuntime::host_resources` returns positive `u64` daemon-host memory bytes
and CPU threads, enforced by a validating constructor and private fields with
read-only getters. `IncusClient::host_resources` performs only bounded
`query --raw /1.0/resources`, parses `memory.total` and `cpu.total`, and retains
the existing timeout and output limits. A client can inspect resources without
constructing `IncusKvmRuntime`, creating a project or starting a VM. Missing,
malformed, zero and overflowing totals fail; daemon process memory and container
limits are never inputs. FakeRuntime returns fixed synthetic totals of 8 GiB
and 4 threads; its effective admission default is 4096 MiB / 4 CPUs.
UnsupportedRuntime retains its unsupported-platform error; other trait
implementations default to unsupported capability. Detection, reserve formulas,
CLI overrides and capacity advertisement consume these effective limits separately.

Qualification uses FakeRuntime and executable Incus shims with a test clock.
The fixtures check canonical-config readback and daemon totals independently of
the test machine. The live `incus-surface` harness is compiled, never run; its
shim-based `incus_surface_cleanup` integration suite remains part of the
unfiltered all-target test gate. See [testing](../testing.md#vm-allocation-runtime-qualification).

## Shared placement and host PTYs

Sandbox creator and host transport owner remain separate principals through
placement, dispatch, private config, the daemon journal and results on relay protocol 1.0.
Control plane never calls Incus. Host shells use a separate local opener,
fixed shell/identity/environment and typed host target, never a guest-to-host
fallback. Foreign guests may coexist with host PTYs. Local administrator power
is outside API guest isolation. Per-creator subcaps and reserved teardown/host
terminal lanes prevent one creator consuming every shared slot; colluding
creators or capacity one have no guaranteed scheduling entitlement.
