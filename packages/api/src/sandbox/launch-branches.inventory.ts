/**
 * S16 launch-branch inventory, TypeScript.
 *
 * Every production line under `LAUNCH_BRANCH_SWEEP.roots` that contains one of
 * `LAUNCH_BRANCH_SWEEP.patterns` (fixed strings, the V4 rewrite of the S16
 * sweep) is listed here, keyed by file and trimmed line text, with how it
 * treats launch semantics. `launch-branches.inventory.test.ts` fails on an
 * unlisted hit and on a stale entry. This prevents drift only: invariant I18
 * is proven by the behavioural restore cells (§8.7).
 *
 * Classes:
 * - `launch-mode-routed`: decides launch semantics from the operation's
 *   immutable `launchMode` (§8.4), or is the acceptance that stamps it (a
 *   reconnect from STOPPED or READY; an OFFLOADED sandbox never enters it).
 * - `route-pending`: decides new-root versus existing-root semantics from the
 *   operation kind or the sandbox state. A restore (RECONNECT with
 *   `launchMode = NEW_ROOT`, sandbox PROVISIONING) would be misread here, so C6c
 *   must route each one by `launchMode` and flip it to `launch-mode-routed`
 *   (§10 C6c: relay-fence U9, dispatch gates U9.1, exits §8.7).
 * - `create-only`: CREATE-only by design (capacity queue, create intent and
 *   replay authority, image fetch, builds, lease from READY); a restore never
 *   takes it and must not.
 * - `kind-agnostic`: types, kind lists and maps, or a branch that treats every
 *   launch kind alike (or tests a state a restore attempt is never in).
 *
 * Test support (`*.test.ts`, `testing/`, `*-harness.ts`, `*-fixtures.ts`) and
 * this file are outside the sweep.
 */
export type LaunchBranchClass =
  | "launch-mode-routed"
  | "route-pending"
  | "create-only"
  | "kind-agnostic";

export const LAUNCH_BRANCH_SWEEP = {
  roots: [
    "packages/api/src/sandbox",
    "packages/api/src/credentials",
    "apps/server/src/sandbox-relay",
  ],
  patterns: [
    '"CREATE_SANDBOX"',
    '"RECONNECT_SANDBOX"',
    '"sandbox.create"',
    '"sandbox.reconnect"',
    '=== "STOPPED"',
    "kind: { in",
  ],
} as const;

export const LAUNCH_BRANCH_INVENTORY: Readonly<
  Record<string, Readonly<Record<string, LaunchBranchClass>>>
> = {
  "apps/server/src/sandbox-relay/allocation-attestation.ts": {
    'in: ["CREATE_SANDBOX" as const, "RECONNECT_SANDBOX" as const],': "kind-agnostic",
  },
  "apps/server/src/sandbox-relay/disk-dispatch.ts": {
    'const UNBOUND_KINDS = new Set(["sandbox.create", "operation.cancel", "process.stdin"]);':
      "kind-agnostic",
    'if (input.kind !== "sandbox.reconnect" || sandbox.diskOffloadId !== input.restoreOffloadId)':
      "launch-mode-routed",
    'if (input.kind === "sandbox.reconnect" && input.payload.expectDisk !== undefined) {':
      "launch-mode-routed",
    'kind: "RECONNECT_SANDBOX",': "launch-mode-routed",
  },
  "apps/server/src/sandbox-relay/dispatch-gates.ts": {
    'if (input.restore && input.kind !== "sandbox.reconnect") return false;': "launch-mode-routed",
    'const newRoot = input.kind === "sandbox.create" || input.restore;': "launch-mode-routed",
    'if (!(newRoot || (input.kind === "sandbox.reconnect" && input.sandboxState === "STOPPED")))':
      "launch-mode-routed",
    '(input.kind === "sandbox.create" || input.kind === "sandbox.reconnect") &&': "kind-agnostic",
    '(input.kind === "sandbox.create" || input.restore) &&': "launch-mode-routed",
    'if (kind === "sandbox.reconnect" && (upstream || bootstrap)) return false;': "create-only",
    'if (kind === "sandbox.create" && upstream !== (buildVm && bootstrap)) return false;':
      "create-only",
    'if (bootstrap && !(upstream && buildVm && kind === "sandbox.create")) return false;':
      "create-only",
    'return !(buildVm && kind === "sandbox.create");': "create-only",
    'if (kind !== "sandbox.create" || !parsed.success || parsed.data.buildId !== sandbox.buildId)':
      "create-only",
    '} else if (kind === "sandbox.create") return false;': "create-only",
    '(kind !== "sandbox.create" && kind !== "sandbox.reconnect") ||': "kind-agnostic",
  },
  "apps/server/src/sandbox-relay/image-authority.ts": {
    'kind: "CREATE_SANDBOX" | "CAPTURE_TEMPLATE" | "RECONNECT_SANDBOX",': "kind-agnostic",
    'const found = await workload(tx, "CREATE_SANDBOX", target);': "create-only",
    'if ((kind === "RECONNECT_SANDBOX") !== (restoreOffloadId !== undefined)) return null;':
      "launch-mode-routed",
    'const found = await workload(tx, "RECONNECT_SANDBOX", target, target.restoreOffloadId);':
      "launch-mode-routed",
  },
  "apps/server/src/sandbox-relay/image-handlers.ts": {
    'kind: { in: ["CREATE_SANDBOX", "CAPTURE_TEMPLATE"] },': "create-only",
    'op?.kind === "CREATE_SANDBOX" &&': "create-only",
    '} else if (op?.kind === "CREATE_SANDBOX") {': "create-only",
  },
  "apps/server/src/sandbox-relay/inventory-reconcile.ts": {
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },': "kind-agnostic",
    'else if (sandbox.state === "STOPPED" && entry.state === "stopped")': "kind-agnostic",
    '(sandbox.state === "STOPPED" && entry.state === "absent") ||': "kind-agnostic",
    'if (first?.kind === "CREATE_SANDBOX" || restore)': "launch-mode-routed",
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX", "RENEW_SANDBOX_LEASE"] },':
      "kind-agnostic",
    'kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] },': "kind-agnostic",
    'requireRelayFence(next === "STOPPED" || next === "DELETED" || next === "OFFLOADED");':
      "kind-agnostic",
    // The census rule (STOPPED cached copy; PROVISIONING/ERROR with a stored
    // disk, I3): state checks, no launch-kind branch.
    '(sandbox.state === "STOPPED" ||': "kind-agnostic",
    'if (uncertain) return sandbox.state === "STOPPED" ? { converged: false } : null;':
      "kind-agnostic",
    'if (input.next === "STOPPED") await settleCredentialsOnStopped(tx, sandbox.id);':
      "kind-agnostic",
  },
  "apps/server/src/sandbox-relay/operation-handlers.ts": {
    'input.state === "unknown_outcome" || owed.kind === "CREATE_SANDBOX" || isRestoreAttempt(owed);':
      "launch-mode-routed",
    'const launch = operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX";':
      "kind-agnostic",
    '(operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX")':
      "kind-agnostic",
    'if (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") {':
      "kind-agnostic",
    // A restore is routed first (`restoreAttempt` → the §8.7 exit), so these
    // cold-start and create arms never see one.
    'operation.kind === "RECONNECT_SANDBOX" &&': "launch-mode-routed",
    'sandbox.state === "STOPPED"': "launch-mode-routed",
    ': operation.kind === "CREATE_SANDBOX" &&': "launch-mode-routed",
    'operation.kind === "CREATE_SANDBOX" &&': "create-only",
    'if (credentialDowngrade && operation.kind === "RECONNECT_SANDBOX") nextSandbox = "ERROR";':
      "kind-agnostic",
    'sandboxStateBeforeResult === "STOPPED"': "kind-agnostic",
    '(operation.kind === "CREATE_SANDBOX" || isRestoreAttempt(operation)) &&': "launch-mode-routed",
    '(operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") &&':
      "kind-agnostic",
    '(operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX"),':
      "kind-agnostic",
    'const launch = input.kind === "sandbox.create" || input.kind === "sandbox.reconnect";':
      "kind-agnostic",
  },
  "apps/server/src/sandbox-relay/outbox-processor.ts": {
    'if (kind !== "sandbox.create" && kind !== "sandbox.reconnect") return {};': "kind-agnostic",
    '"sandbox.create",': "kind-agnostic",
    '"sandbox.reconnect",': "kind-agnostic",
    '(operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") &&':
      "kind-agnostic",
    '["sandbox.create", "sandbox.reconnect", "command.run"].includes(kind)': "kind-agnostic",
    'if (kind === "sandbox.create" || kind === "sandbox.reconnect") {': "kind-agnostic",
    'advertised && (kind === "sandbox.create" || restore)': "launch-mode-routed",
    // Behind `!exited`: a restore already left through exitRestoreAttempt.
    '...(rejectedState === "FAILED" && operation.kind === "CREATE_SANDBOX"': "launch-mode-routed",
    '...(kind === "sandbox.create" || kind === "sandbox.reconnect"': "kind-agnostic",
    '(kind === "sandbox.create" || kind === "sandbox.reconnect") && sandbox.guestSudo':
      "kind-agnostic",
    '(kind === "sandbox.create" || kind === "sandbox.reconnect") &&': "kind-agnostic",
    'verificationConnectionEpoch: kind === "sandbox.create" ? prepared.epoch : undefined,':
      "create-only",
    '...(kind === "sandbox.create" && payload.image !== undefined': "create-only",
    '...(kind === "sandbox.create" && payload.build !== undefined': "create-only",
    '...(operation.kind === "CREATE_SANDBOX"': "launch-mode-routed",
    'const launch = operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX";':
      "kind-agnostic",
    'operation.kind === "CREATE_SANDBOX" ||': "launch-mode-routed",
    '(operation.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED");':
      "launch-mode-routed",
  },
  "apps/server/src/sandbox-relay/protocol.ts": {
    '"sandbox.create",': "kind-agnostic",
    '"sandbox.reconnect",': "kind-agnostic",
    'const launch = message.kind === "sandbox.create" || message.kind === "sandbox.reconnect";':
      "kind-agnostic",
    'message.kind !== "sandbox.create" &&': "kind-agnostic",
    'message.kind !== "sandbox.reconnect") ||': "kind-agnostic",
    '(message.kind === "sandbox.create" || message.kind === "sandbox.reconnect")': "kind-agnostic",
  },
  "apps/server/src/sandbox-relay/session-manager.ts": {
    'if (input.kind === "sandbox.create" || input.kind === "sandbox.reconnect") {': "kind-agnostic",
    'const launch = message.kind === "sandbox.create" || message.kind === "sandbox.reconnect";':
      "kind-agnostic",
  },
  "packages/api/src/credentials/captures.ts": {
    'vmStops = sandbox?.state === "STOPPED";': "kind-agnostic",
    'let done = sandbox?.state === "STOPPED" || sandbox?.state === "DELETED";': "kind-agnostic",
  },
  "packages/api/src/credentials/live-ops.ts": {
    '"RECONNECT_SANDBOX",': "kind-agnostic",
    "kind: { in: [...BUSY_KINDS] },": "kind-agnostic",
  },
  "packages/api/src/credentials/teardown.ts": {
    'kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] },': "kind-agnostic",
    'if (input.next === "STOPPED" && (lease.state === "ACTIVE" || lease.state === "RELEASING"))':
      "kind-agnostic",
    'else if (input.next === "STOPPED")': "kind-agnostic",
    'case "CREATE_SANDBOX":': "kind-agnostic",
    'case "RECONNECT_SANDBOX":': "kind-agnostic",
  },
  "packages/api/src/sandbox/capacity-queue.ts": {
    'kind: "CREATE_SANDBOX",': "create-only",
    'launchMode: acceptedLaunchMode("CREATE_SANDBOX"),': "launch-mode-routed",
  },
  "packages/api/src/sandbox/contracts.ts": {
    '| "CREATE_SANDBOX"': "kind-agnostic",
    '| "RECONNECT_SANDBOX"': "kind-agnostic",
    'CREATE_SANDBOX: "sandbox.create",': "kind-agnostic",
    'RECONNECT_SANDBOX: "sandbox.reconnect",': "kind-agnostic",
  },
  "packages/api/src/sandbox/disk-offload/detach.ts": {
    'OR: [{ kind: "CREATE_SANDBOX" }, { kind: "RECONNECT_SANDBOX", launchMode: "NEW_ROOT" }],':
      "launch-mode-routed",
  },
  // Display only: a failed offload is shown for a STOPPED disk (the DTO projection).
  "packages/api/src/sandbox/disk-offload/disk-view.ts": {
    'row.state === "STOPPED";': "kind-agnostic",
    // The offload policy's due time: a read projection of a stopped disk.
    'eligibility !== "never" && row.state === "STOPPED" && !current && !live && !failed':
      "kind-agnostic",
  },
  "packages/api/src/sandbox/disk-offload/restore-admit.ts": {
    // The restore acceptance that stamps launchMode NEW_ROOT (§8.4).
    'kind: "RECONNECT_SANDBOX",': "launch-mode-routed",
    '...requestDigestMetadata("RECONNECT_SANDBOX"),': "kind-agnostic",
    // The creating key (§5a): the CREATE row's attribution, never a launch.
    'where: { sandboxId: sandbox.id, userId: sandbox.userId, kind: "CREATE_SANDBOX" },':
      "create-only",
  },
  "packages/api/src/sandbox/disk-offload/destroy.ts": {
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX", "STOP_SANDBOX", "KILL_SANDBOX"] },':
      "kind-agnostic",
  },
  "packages/api/src/sandbox/host-admission.ts": {
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },': "kind-agnostic",
    // Every caller routes a restore through exitRestoreAttempt first; a
    // restore that reached here (not the current attempt) keeps its holds.
    'if (input.kind === "CREATE_SANDBOX") {': "launch-mode-routed",
    'if (input.kind === "RECONNECT_SANDBOX") {': "launch-mode-routed",
    'return input.sandboxStateBeforeResult === "STOPPED";': "launch-mode-routed",
    '(input.kind === "CREATE_SANDBOX" && input.neverIssued === true),': "launch-mode-routed",
  },
  "packages/api/src/sandbox/image-store/captures.ts": {
    'stoppedCapture: sandbox.state === "STOPPED",': "kind-agnostic",
    'stopped: sandbox.state === "STOPPED",': "kind-agnostic",
  },
  "packages/api/src/sandbox/launch-mode.ts": {
    'export function acceptedLaunchMode(kind: "CREATE_SANDBOX"): "NEW_ROOT";': "launch-mode-routed",
    'kind: "RECONNECT_SANDBOX",': "launch-mode-routed",
    'kind: "CREATE_SANDBOX" | "RECONNECT_SANDBOX",': "launch-mode-routed",
    'if (kind === "CREATE_SANDBOX") return "NEW_ROOT";': "launch-mode-routed",
    'if (sandboxState === "STOPPED") return "COLD";': "launch-mode-routed",
    'return op.kind === "RECONNECT_SANDBOX" && op.launchMode === "NEW_ROOT";': "launch-mode-routed",
  },
  "packages/api/src/sandbox/lease-wire.ts": {
    '"sandbox.create",': "kind-agnostic",
    '"sandbox.reconnect",': "kind-agnostic",
  },
  "packages/api/src/sandbox/lease.ts": {
    '(operation.kind !== "CREATE_SANDBOX" && operation.kind !== "RECONNECT_SANDBOX") ||':
      "kind-agnostic",
    '(operation.kind === "CREATE_SANDBOX" || sandbox.state === "STOPPED" || restore) &&':
      "launch-mode-routed",
    '...(!possiblyLiveGuest && operation.kind === "CREATE_SANDBOX" ? { state: "ERROR" } : {}),':
      "launch-mode-routed",
    'operation.kind === "RECONNECT_SANDBOX"': "launch-mode-routed",
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },': "kind-agnostic",
  },
  "packages/api/src/sandbox/operation-transaction.ts": {
    'request.kind === "CREATE_SANDBOX" ? "sandboxes.createIntent" : request.action,': "create-only",
    'prior.kind === "CREATE_SANDBOX" ? "sandboxes.replayCreate" : request.action,': "create-only",
    'const queuedCreate = request.kind === "CREATE_SANDBOX" && request.queuedDigest?.() === true;':
      "create-only",
  },
  "packages/api/src/sandbox/outbox.ts": {
    'return model === "sandbox" && (data.state === "READY" || data.state === "STOPPED");':
      "kind-agnostic",
    '["sandbox.create", "sandbox.reconnect"].includes(String(data.payload.kind)),': "kind-agnostic",
    '...(["sandbox.create", "sandbox.reconnect", "sandbox.stop", "sandbox.kill"].includes(':
      "kind-agnostic",
    '...(["sandbox.create", "sandbox.reconnect"].includes(String(data.payload.kind))':
      "kind-agnostic",
    // A restore boots its stored disk, never the revision image.
    '...(data.payload.kind === "sandbox.create"': "create-only",
    '["sandbox.create", "sandbox.reconnect", "command.run"].includes(String(data.payload.kind))':
      "kind-agnostic",
    'data.payload.kind === "sandbox.create" &&': "create-only",
  },
  "packages/api/src/sandbox/placement-materialize.ts": {
    'launchMode: acceptedLaunchMode("CREATE_SANDBOX"),': "launch-mode-routed",
    'kind: "CREATE_SANDBOX",': "create-only",
  },
  "packages/api/src/sandbox/process-controls.ts": {
    '!(target.kind === "CREATE_SANDBOX" && (await waitingCreate(tx, owner, target.id))) &&':
      "create-only",
    'if (target.kind === "CREATE_SANDBOX")': "create-only",
    // Cancel of a waiting restore: the wait row exists only for a NEW_ROOT
    // restore RECONNECT (§8.3c).
    '!(target.kind === "RECONNECT_SANDBOX" && (await waitingRestore(tx, owner, target.id)))':
      "launch-mode-routed",
    'if (target.kind === "RECONNECT_SANDBOX")': "launch-mode-routed",
  },
  "packages/api/src/sandbox/relay-fence.ts": {
    'if (kind === "RECONNECT_SANDBOX" && op.launchMode === "NEW_ROOT") return ["PROVISIONING"];':
      "launch-mode-routed",
    'case "CREATE_SANDBOX":': "launch-mode-routed",
    'case "RECONNECT_SANDBOX":': "launch-mode-routed",
  },
  "packages/api/src/sandbox/services/sandbox-views.ts": {
    '"CREATE_SANDBOX",': "kind-agnostic",
    '"RECONNECT_SANDBOX",': "kind-agnostic",
    "where: { kind: { in: [...LIFECYCLE_OPERATION_KINDS] } },": "kind-agnostic",
  },
  "packages/api/src/sandbox/services/sandboxes.ts": {
    "kind: { in: kinds },": "kind-agnostic",
    'kind: Exclude<DispatchableOperationKind, "CREATE_SANDBOX" | "KILL_SANDBOX" | "SIGNAL_PROCESS">;':
      "kind-agnostic",
    '...(spec.kind === "RECONNECT_SANDBOX"': "kind-agnostic",
    'const cold = spec.kind === "RECONNECT_SANDBOX" && located.state === "STOPPED";':
      "launch-mode-routed",
    // OFFLOADED → restore acceptance (launchMode NEW_ROOT), never cold.
    'if (spec.kind === "RECONNECT_SANDBOX" && located.state === "OFFLOADED") {':
      "launch-mode-routed",
    'spec.kind === "RECONNECT_SANDBOX" &&': "launch-mode-routed",
    'if (spec.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED") {': "launch-mode-routed",
    // §5 order 4: an offline cached copy detaches (then restores) first.
    'if (spec.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED" && !cachedFallback)':
      "launch-mode-routed",
    'const config = ["RUN_COMMAND", "RECONNECT_SANDBOX"].includes(spec.kind)': "kind-agnostic",
    'sandbox.state === "STOPPED" &&': "launch-mode-routed",
    'spec.kind === "RECONNECT_SANDBOX"': "launch-mode-routed",
    'if (advanceGeneration && spec.kind === "RECONNECT_SANDBOX") {': "launch-mode-routed",
    'kind: "CREATE_SANDBOX",': "create-only",
    'kind: "RECONNECT_SANDBOX",': "kind-agnostic",
    'advanceGeneration: (state) => state === "STOPPED",': "launch-mode-routed",
  },
  "packages/api/src/sandbox/sharing-access.ts": {
    'kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },': "kind-agnostic",
  },
  "packages/api/src/sandbox/state-transitions.ts": {
    '"CREATE_SANDBOX",': "kind-agnostic",
    '"RECONNECT_SANDBOX",': "kind-agnostic",
    // Restore results never reach the mapping (the §8.7 exit runs first).
    'if (kind === "RECONNECT_SANDBOX" && currentState === "STOPPED") return "STOPPED";':
      "launch-mode-routed",
    'kind === "RECONNECT_SANDBOX" &&': "kind-agnostic",
    'case "CREATE_SANDBOX":': "kind-agnostic",
    'case "RECONNECT_SANDBOX":': "kind-agnostic",
  },
};
