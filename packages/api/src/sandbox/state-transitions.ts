import type {
  OperationState,
  SandboxOperationKind,
  SandboxState,
  SandboxTeardownIntent,
} from "@wssp/db";

export const SANDBOX_TRANSITIONS: Readonly<Record<SandboxState, readonly SandboxState[]>> = {
  REQUESTED: ["SCHEDULED", "PROVISIONING", "READY", "STOPPING", "ERROR", "DELETED"],
  SCHEDULED: ["PROVISIONING", "READY", "STOPPING", "ERROR", "DELETED"],
  // → OFFLOADED: a restore attempt or stale copy
  // detached to its stored disk; only through proven safe detachment.
  PROVISIONING: ["READY", "STOPPING", "ERROR", "DELETED", "OFFLOADED"],
  READY: ["STOPPING", "UNREACHABLE", "ERROR", "DELETED"],
  // STOPPING → READY is deliberately absent: only the credential re-arm
  // branch authors it, through canTransitionLifecycleResult below.
  STOPPING: ["STOPPED", "DELETED", "ERROR", "OFFLOADED"],
  STOPPED: ["RECLAIMING", "READY", "STOPPING", "DELETED", "ERROR", "OFFLOADED"],
  RECLAIMING: ["DELETED", "ERROR"],
  DELETED: [],
  UNREACHABLE: ["RECOVERED", "HOST_LOST", "ERROR", "STOPPING"],
  RECOVERED: ["READY", "STOPPING", "ERROR"],
  HOST_LOST: ["RECLAIMING", "DELETED"],
  ERROR: ["RECLAIMING", "DELETED", "READY", "STOPPING", "OFFLOADED"],
  // A pool create waiting for capacity holds nothing: it is placed (REQUESTED)
  // or ends (DELETED: timeout, cancel, access loss, infeasible).
  WAITING_FOR_CAPACITY: ["REQUESTED", "DELETED"],
  // Hostless, disk only in the store: a restore admits it (PROVISIONING,
  // host bound at admission) or an owner destroy ends it (DELETED).
  OFFLOADED: ["PROVISIONING", "DELETED"],
};

export function canTransitionSandboxState(from: SandboxState, to: SandboxState): boolean {
  if (from === to) return true;
  return SANDBOX_TRANSITIONS[from].includes(to);
}

/**
 * Lifecycle results: the ordinary table plus the one extra edge STOPPING →
 * READY, which only a user stop/kill re-armed by a failed login capture may
 * author; the VM kept running.
 */
export function canTransitionLifecycleResult(
  from: SandboxState,
  to: SandboxState,
  credentialRearm: boolean,
): boolean {
  if (credentialRearm && from === "STOPPING" && to === "READY") return true;
  return canTransitionSandboxState(from, to);
}

/** Guest is healthy and may accept exec/file/process work. */
export const HEALTHY_GUEST_STATES: ReadonlySet<SandboxState> = new Set(["READY"]);

/** Stop may interrupt boot, but never replace a destroy intent. */
export const STOPPABLE_SANDBOX_STATES: ReadonlySet<SandboxState> = new Set([
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "RECOVERED",
]);

/** States from which kill is allowed. */
export const KILLABLE_SANDBOX_STATES: ReadonlySet<SandboxState> = new Set([
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPED",
  "UNREACHABLE",
  "RECOVERED",
  "ERROR",
  "OFFLOADED",
]);

/** Operation rows that are still in flight; these are not VM lifecycle. */
export const ACTIVE_OPERATION_STATES: ReadonlySet<OperationState> = new Set([
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
]);

/** Only ordinary guest work may be cancelled. Lifecycle intent must reach its
 * result or be superseded by a new lifecycle action (use kill to abandon create).
 */
export const CANCELLABLE_OPERATION_KINDS: ReadonlySet<SandboxOperationKind> = new Set([
  "RUN_COMMAND",
  "GET_FILE",
  "PUT_FILE",
  "LIST_DIR",
  "STAT_PATH",
  "MKDIR",
  "REMOVE_PATH",
  "MOVE_PATH",
  "LIST_PROCESSES",
  "SIGNAL_PROCESS",
]);

export const LIFECYCLE_OPERATION_KINDS = [
  "CREATE_SANDBOX",
  "KILL_SANDBOX",
  "STOP_SANDBOX",
  "RECONNECT_SANDBOX",
] as const;

export type LifecycleOperationKind = (typeof LIFECYCLE_OPERATION_KINDS)[number];

export function isLifecycleOperationKind(kind: string): kind is LifecycleOperationKind {
  return (LIFECYCLE_OPERATION_KINDS as readonly string[]).includes(kind);
}

/** Credential facts of a failed teardown. */
export type TeardownCredentialFacts = {
  /** The operation owns ≥ 1 RELEASING lease (`teardownOperationId` = op). */
  ownsReleasingLease: boolean;
  /** `SandboxOperation.teardownPriorState`: the state the stop/kill was accepted from. */
  priorState: SandboxState | null;
};

/**
 * VM state authored by a lifecycle operation result. Ordinary exec/file/process
 * results must not call this — they never author sandbox.state.
 */
export function sandboxStateForLifecycleResult(
  kind: LifecycleOperationKind,
  opState: OperationState,
  endState?: unknown,
  currentState?: SandboxState,
  errorCode?: string | null,
  teardown?: TeardownCredentialFacts,
  /** `SandboxOperation.teardownIntent` (S2): server-set, never from a host. */
  teardownIntent?: SandboxTeardownIntent | null,
): SandboxState | undefined {
  if (opState === "CANCELLED" || opState === "UNKNOWN_OUTCOME") return undefined;
  if (opState === "FAILED") {
    // CLI logins (§10.3, P3-3): a user stop/kill that refused to touch the
    // guest because a login capture failed leaves the VM running. It returns
    // to READY when it was accepted from READY or RECOVERED; every other
    // origin (ERROR, UNREACHABLE, pre-ready, STOPPED) stays ERROR. Without an
    // owned RELEASING lease the ordinary FAILED mapping below applies.
    if (
      (kind === "STOP_SANDBOX" || kind === "KILL_SANDBOX") &&
      currentState === "STOPPING" &&
      errorCode === "credential_capture_failed" &&
      teardown?.ownsReleasingLease === true
    )
      return teardown.priorState === "READY" || teardown.priorState === "RECOVERED"
        ? "READY"
        : "ERROR";
    // A cold start retains STOPPED until success. A definite failure proves
    // no live VM, so preserve the disk's state while releasing its live claim.
    if (kind === "RECONNECT_SANDBOX" && currentState === "STOPPED") return "STOPPED";
    // C1: the host refuses a warm re-arm past its freshly lowered lease
    // ceiling before any effect; the running guest and its previous lease are
    // untouched, so the sandbox stays READY (the pull-in sweep then shortens
    // the requested deadline the reconnect re-armed).
    // The same holds for an older daemon's dispatch-time lease refusal
    // (state_conflict, before any effect): ERROR would take the still-running
    // guest out of lease reclaim for good. READY keeps the pull-in and the
    // expiry stop in force; inventory reconciliation remains the authority
    // if the guest is in fact gone.
    // So does a warm re-arm whose result the server could not apply
    // (protocol_error, the WP0 receipt verdict or a per-op refusal): the guest
    // was running before and the lease the server knows stays in force, so
    // READY keeps it under lease reclaim instead of an unreclaimed ERROR.
    if (
      kind === "RECONNECT_SANDBOX" &&
      currentState === "READY" &&
      (errorCode === "lease_exceeds_policy" ||
        errorCode === "state_conflict" ||
        errorCode === "protocol_error")
    )
      return undefined;
    return "ERROR";
  }
  if (opState !== "SUCCEEDED") return undefined;
  switch (kind) {
    case "CREATE_SANDBOX":
    case "RECONNECT_SANDBOX":
      return "READY";
    case "KILL_SANDBOX":
      // I17: a system teardown of an offloaded lineage detaches to its stored
      // disk; only an owner destroy ends the sandbox.
      return teardownIntent === "SYSTEM_DETACH" ? "OFFLOADED" : "DELETED";
    case "STOP_SANDBOX":
      // Positive absence leaves no disk to retain, including interrupted boot.
      return endState === "absent" ? "DELETED" : "STOPPED";
  }
}
