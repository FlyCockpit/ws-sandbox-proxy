import { ORPCError } from "@orpc/server";
import type { OperationState, TemplateBuildState, TemplateCaptureState } from "@wssp/db";
import { CAPTURE_STORING, isBuildAuthorityLost } from "./build-authority";
import { BuildContextPortError } from "./context-port";

/**
 * The orchestrator's pure core: the decision
 * table (what a build does next, given what it observes) and the retry
 * classification of a service call's thrown error. No IO, no clock: the
 * orchestrator feeds rows in and applies the result inside its own
 * transactions, so every row of §3.3 is unit-testable on its own.
 */

/** Orchestrator actions (§3.3 idempotency keys). There is no `cancel` action
 * (r2 N2), and `kill` belongs to the cleanup invariant alone (§3.10). */
export const BUILD_ACTIONS = [
  "create",
  "import",
  "context",
  "run",
  "stop",
  "timeout",
  "capture",
  "kill",
  /** Community verify (community-base T2): the verify VM's create, its smoke
   * command, and its cleanup kill (a key namespace distinct from `kill`). */
  "vcreate",
  "vrun",
  "vkill",
] as const;
export type BuildAction = (typeof BUILD_ACTIONS)[number];
/** Actions the advance loop may claim (every action but the cleanup kills). */
export type AdvanceAction = Exclude<BuildAction, "kill" | "vkill">;

/** `tb:<buildId>:<action>:<n>:<attempt>` (§3.3; the reserved prefix, §3.5). */
export function buildActionKey(
  buildId: string,
  action: BuildAction,
  n: number,
  attempt: number,
): string {
  return `tb:${buildId}:${action}:${n}:${attempt}`;
}

/** The attempt of a key minted by `buildActionKey`, or null. */
export function buildKeyAttempt(key: string | null | undefined): number | null {
  const match = /^tb:[A-Za-z0-9_-]{1,64}:[a-z]+:\d{1,9}:(\d{1,9})$/.exec(key ?? "");
  return match ? Number(match[1]) : null;
}

/** Build error codes (CHECK `template_build_error_code`). */
type BuildErrorCode =
  | "build_step_failed"
  | "build_step_unknown"
  | "build_step_timeout"
  | "build_step_host_disconnected"
  | "build_timeout"
  | "build_context_timeout"
  | "build_context_mismatch"
  | "build_context_expired"
  | "build_context_failed"
  | "build_placement_failed"
  | "build_capture_failed"
  | "build_capture_lease_expired"
  | "build_store_failed"
  | "build_authority_lost"
  | "build_host_lost"
  | "build_internal"
  | "build_verify_failed"
  | "build_upstream_unavailable";

const CONTEXT_ERROR_CODES: ReadonlySet<string> = new Set([
  "build_context_timeout",
  "build_context_expired",
  "build_context_mismatch",
  "build_context_failed",
]);

/** A code-shaped detail (CHECK `^[a-z0-9_.]{1,64}$`), never message text. */
function errorDetailOf(code: unknown): string | null {
  if (typeof code !== "string") return null;
  const detail = code.toLowerCase().slice(0, 64);
  return /^[a-z0-9_.]{1,64}$/.test(detail) ? detail : null;
}

/** Capture rows whose host result is recorded: the result wins over cancel
 * (§3.3, r3 N22). */
const CAPTURE_RESULT_RECORDED: readonly TemplateCaptureState[] = [
  "CAPTURED",
  "STORING",
  "FINALIZED",
];
/**
 * Capture rows after which the build VM is no longer needed (§3.10): only a
 * FINALIZED one. While CAPTURED/STORING the host still uploads the image to
 * the S3 store, and every upload grant re-checks the capture's dispatch
 * authority, which requires the build VM to be usable: killing it at
 * CAPTURED left S3-mode builds stuck in `storing` (each part report answered
 * `stale_transfer`). Peer mode finalizes at CAPTURED at once, so the VM
 * outlives the capture by moments there.
 */
export const CAPTURE_VM_RELEASED: readonly TemplateCaptureState[] = ["FINALIZED"];
const TERMINAL_OPERATION: ReadonlySet<OperationState> = new Set([
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
]);
export const ACTIVE_BUILD_STATES: readonly TemplateBuildState[] = [
  "AWAITING_CONTEXT",
  "QUEUED",
  "PLACING",
  "RUNNING",
  "STOPPING",
  "CAPTURING",
  "CANCELLING",
];
export const TERMINAL_BUILD_STATES: readonly TemplateBuildState[] = [
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
];
/** How long past the step deadline a stop may take to be accepted. */
const STOP_ACCEPT_GRACE_MS = 60 * 60_000;
/** A capture whose operation ended UNKNOWN_OUTCOME is retried at most twice. */
const CAPTURE_UNKNOWN_RETRIES = 2;

type BuildPhase =
  | "awaiting_context"
  | "queued"
  | "placing"
  | "waiting_for_capacity"
  | "context_import"
  | "context_commit"
  | "step"
  | "lease"
  | "stopping"
  | "capturing"
  /** The capture's host has no room for its hold (disk or RAM): retrying. */
  | "capture_waiting_capacity"
  | "storing"
  /** Community verify: the pending revision boots in a fresh verify VM. */
  | "verifying";

/** The build row as the decision table reads it. */
export type BuildView = {
  state: TemplateBuildState;
  phase: string | null;
  /** Exec step index (prelude + planned steps), -1 before the first. */
  stepIndex: number;
  cancelRequestedAt: Date | null;
  deadlineAt: Date | null;
  /** WP7: how long the current step has been held by a quiescing host so
   * far (not yet folded into `deadlineAt`); it extends the step deadline. */
  quiesceHeldMs?: number;
  captureDeadlineAt: Date | null;
  createdAt: Date;
  hasContext: boolean;
  waitForCapacityMs: number | null;
  /** Number of exec steps. */
  execSteps: number;
  /** The current capture attempt (raised by the claim of a retry). */
  captureAttempt: number;
  /** Community verify (D-D); absent/false for user builds. */
  verifyRequired?: boolean;
  verifyDeadlineAt?: Date | null;
};

type OperationView = {
  state: OperationState;
  errorCode: string | null;
  exitCode: number | null;
  idempotencyKey: string;
};

export type Observed = {
  /** The operation of the current phase (create, PUT_FILE, step n, lease, stop). */
  op: OperationView | null;
  sandbox: { state: string; leaseExpiresAt: Date | null } | null;
  capture: {
    state: TemplateCaptureState;
    errorCode: string | null;
    opState: OperationState;
    /** The capture row's immutable `buildAttempt`. */
    attempt: number;
    revisionId: string | null;
  } | null;
  context: { state: string; transferId: string | null; errorCode: string | null } | null;
  /**
   * Community verify facts (D-D, M4), read only for a `verifyRequired` build
   * whose capture is FINALIZED: the verify VM (`Sandbox.verifyBuildId`), its
   * create operation, the smoke operation and whether the pending revision
   * was retired meanwhile (a manual retire wins, D-L).
   */
  verify?: {
    vm: { state: string } | null;
    createOp: { state: OperationState; detail: string | null } | null;
    smokeOp: { state: OperationState; exitCode: number | null } | null;
    revisionRetired: boolean;
  } | null;
};

export type BuildFailure = {
  errorCode: BuildErrorCode;
  errorDetail?: string | null;
  failureStepIndex?: number;
  failureExitCode?: number;
  /** Copy the failing step's output tail (≤ 8 KiB). */
  tail?: boolean;
};

/** Wall-clock bounds the decision table needs (from config and the clock). */
export type DecideLimits = {
  now: Date;
  /** Longest a sealed context may wait (6 h); bounds placing (backstop). */
  contextSealedMaxMs: number;
  /** OPEN idle timeout: a build whose context was never opened fails after it. */
  contextIdleMs: number;
};

export type Decision =
  /** Nothing to do until something changes. */
  | { kind: "wait"; phase?: BuildPhase }
  /** A state change with no service call; the loop decides again after it. */
  | {
      kind: "transition";
      to: TemplateBuildState;
      phase: BuildPhase | null;
      stepIndex?: number;
      /** RUNNING: the create op succeeded and the VM is READY. */
      ready?: true;
      /** CAPTURING: the stop op succeeded and the VM is STOPPED. */
      stopped?: true;
      /** The current phase's operation is done; the next phase has none yet. */
      clearOperation?: true;
      /** SUCCEEDED from a capture the finalizer already published. */
      revisionId?: string;
    }
  /** Claim one service action (frozen at claim time, §3.3). */
  | {
      kind: "claim";
      action: AdvanceAction;
      n: number;
      attempt: number;
      /** State/phase written with the claim. */
      state?: TemplateBuildState;
      phase: BuildPhase;
    }
  | { kind: "fail"; failure: BuildFailure }
  /** CANCELLING with nothing left to wait for: settle and end CANCELLED. */
  | { kind: "cancelled" }
  /** Community verify ended (pass or fail): the orchestrator settles it in
   * its own transaction with the publish lock order (T3, review4 U4). */
  | { kind: "verify_finish"; pass: boolean; failure?: BuildFailure };

const isTerminalOp = (op: OperationView | null) => op !== null && TERMINAL_OPERATION.has(op.state);

/** The placing backstop: upload ceiling + the build's own wait + slack. A
 * capacity wait ends on its own (`capacity_wait_timeout`); this only bounds a
 * stuck create. */
function placingDeadline(build: BuildView, limits: DecideLimits): number {
  return (
    build.createdAt.getTime() +
    limits.contextSealedMaxMs +
    (build.waitForCapacityMs ?? 0) +
    15 * 60_000
  );
}

/**
 * The most hold credit one quiesce gives a build: the daemon's default
 * `quiesce_max` (10 min) with generous slack for its restart. A marker the
 * settlement never cleared (the daemon died mid-quiesce and never came
 * back) stops crediting here, so the build timeout bounds the step again.
 */
export const QUIESCE_HOLD_MAX_MS = 60 * 60_000;

/**
 * WP7 (D9): how long `op` sat held in the outbox by a host quiescing since
 * `quiescingSince`, up to `now`: from the later of the two starts until its
 * dispatch (or now, while still QUEUED), never past `QUIESCE_HOLD_MAX_MS`
 * after the quiesce began. Only `command.run` work is held.
 */
export function quiesceHeldMs(
  quiescingSince: Date | null,
  op: { kind: string; state: OperationState; createdAt: Date; dispatchedAt: Date | null } | null,
  now: Date,
): number {
  if (!quiescingSince || !op || op.kind !== "RUN_COMMAND") return 0;
  const start = Math.max(quiescingSince.getTime(), op.createdAt.getTime());
  const end = Math.min(
    op.dispatchedAt
      ? Math.min(op.dispatchedAt.getTime(), now.getTime())
      : op.state === "QUEUED"
        ? now.getTime()
        : start,
    quiescingSince.getTime() + QUIESCE_HOLD_MAX_MS,
  );
  return Math.max(0, end - start);
}

/**
 * Bounds that end a build even while an action is pending (checked before any
 * claim replay): the step deadline, the capture window before a host result,
 * and the placing backstop.
 */
export function deadlineFailure(
  build: BuildView,
  obs: Observed,
  limits: DecideLimits,
): BuildFailure | null {
  const now = limits.now.getTime();
  // The deadline governs steps only (§3.3): the lease re-anchor after the
  // last step belongs to the stop and capture window.
  if (
    build.state === "RUNNING" &&
    build.phase !== "lease" &&
    build.deadlineAt &&
    build.deadlineAt.getTime() + (build.quiesceHeldMs ?? 0) <= now
  )
    return { errorCode: "build_timeout" };
  // A stop is bounded by the capture window it opened; one never accepted
  // (its call keeps failing) by an hour past the step deadline.
  if (build.state === "STOPPING") {
    const bound =
      build.captureDeadlineAt?.getTime() ??
      (build.deadlineAt ? build.deadlineAt.getTime() + STOP_ACCEPT_GRACE_MS : null);
    if (bound !== null && bound <= now)
      return { errorCode: "build_internal", errorDetail: "stop_timeout" };
  }
  if (
    build.state === "CAPTURING" &&
    build.captureDeadlineAt &&
    build.captureDeadlineAt.getTime() <= now &&
    !(obs.capture && CAPTURE_RESULT_RECORDED.includes(obs.capture.state))
  )
    return { errorCode: "build_capture_failed", errorDetail: "capture_deadline" };
  // The verify window bounds the verify VM, its smoke and any stuck call,
  // unless the smoke result is already recorded (it still settles).
  if (
    build.state === "CAPTURING" &&
    build.verifyRequired &&
    obs.capture?.state === "FINALIZED" &&
    build.verifyDeadlineAt &&
    build.verifyDeadlineAt.getTime() <= now &&
    !(obs.verify?.smokeOp && TERMINAL_OPERATION.has(obs.verify.smokeOp.state))
  )
    return { errorCode: "build_verify_failed", errorDetail: "verify_deadline" };
  if (
    (build.state === "QUEUED" || build.state === "PLACING") &&
    now > placingDeadline(build, limits)
  )
    return { errorCode: "build_placement_failed", errorDetail: "placement_timeout" };
  return null;
}

/**
 * The decision table (§3.2 states, §3.3 outcome table). Called under the
 * build row lock with no pending claim (or after the claim was dropped).
 */
export function decide(build: BuildView, obs: Observed, limits: DecideLimits): Decision {
  const now = limits.now.getTime();
  if (TERMINAL_BUILD_STATES.includes(build.state)) return { kind: "wait" };
  if (build.state === "CANCELLING") {
    // A host capture result recorded before the cancel wins: the finalizer
    // publishes and ends the build SUCCEEDED. An in-flight (PENDING) capture
    // loses: the cancel marked it (`buildCancelledAt`), so a result that
    // still lands is recorded only to be failed and its image released by
    // the finalizer; otherwise the cleanup kill supersedes it, the finalizer
    // fails it once the kill settles, and the relay releases the image its
    // dropped result names (E2-A-01, droppedCaptureImageToRelease).
    if (
      obs.capture &&
      (obs.capture.state === "PENDING" || CAPTURE_STORING.includes(obs.capture.state))
    )
      return { kind: "wait" };
    // A community build's cancel always wins over its verify (U4): the
    // cleanup kills the verify VM (`vkill`), then the pending revision is
    // retired and the build ends CANCELLED. It never publishes.
    if (build.verifyRequired) {
      if (obs.verify?.vm && !TERMINAL_VM_STATES.has(obs.verify.vm.state)) return { kind: "wait" };
      return { kind: "cancelled" };
    }
    if (obs.capture?.state === "FINALIZED" && obs.capture.revisionId)
      return {
        kind: "transition",
        to: "SUCCEEDED",
        phase: null,
        revisionId: obs.capture.revisionId,
      };
    return { kind: "cancelled" };
  }
  const deadline = deadlineFailure(build, obs, limits);
  if (deadline) return { kind: "fail", failure: deadline };

  switch (build.state) {
    case "AWAITING_CONTEXT": {
      const ctx = obs.context;
      if (ctx?.state === "SEALED") return { kind: "transition", to: "QUEUED", phase: "queued" };
      if (ctx && (ctx.state === "ABORTED" || ctx.state === "EXPIRED"))
        return {
          kind: "fail",
          failure: {
            errorCode:
              ctx.errorCode && CONTEXT_ERROR_CODES.has(ctx.errorCode)
                ? (ctx.errorCode as BuildErrorCode)
                : "build_context_failed",
          },
        };
      // Never opened (the accepting route crashed and no client re-opened):
      // the same idle bound as an OPEN context without progress.
      if (!ctx && now > build.createdAt.getTime() + limits.contextIdleMs)
        return { kind: "fail", failure: { errorCode: "build_context_timeout" } };
      return { kind: "wait", phase: "awaiting_context" };
    }
    case "QUEUED":
      return {
        kind: "claim",
        action: "create",
        n: 0,
        attempt: 0,
        state: "PLACING",
        phase: "placing",
      };
    case "PLACING": {
      const op = obs.op;
      if (!op) return { kind: "claim", action: "create", n: 0, attempt: 0, phase: "placing" };
      if (op.state === "SUCCEEDED" && obs.sandbox?.state === "READY")
        return build.hasContext
          ? {
              kind: "transition",
              to: "RUNNING",
              phase: "context_import",
              stepIndex: -1,
              ready: true,
              clearOperation: true,
            }
          : {
              kind: "transition",
              to: "RUNNING",
              phase: "step",
              stepIndex: 0,
              ready: true,
              clearOperation: true,
            };
      if (isTerminalOp(op) && op.state !== "SUCCEEDED")
        return {
          kind: "fail",
          failure: {
            // A community build VM fetches its pin from the index host only:
            // a pin gone upstream (404/410) is its own code (S11).
            errorCode:
              build.verifyRequired && op.errorCode === "image_unavailable"
                ? "build_upstream_unavailable"
                : "build_placement_failed",
            errorDetail: errorDetailOf(op.errorCode),
          },
        };
      return {
        kind: "wait",
        phase: obs.sandbox?.state === "WAITING_FOR_CAPACITY" ? "waiting_for_capacity" : "placing",
      };
    }
    case "RUNNING":
      return decideRunning(build, obs);
    case "STOPPING": {
      const op = obs.op;
      if (!op) return { kind: "claim", action: "stop", n: 0, attempt: 0, phase: "stopping" };
      if (op.state === "SUCCEEDED" && obs.sandbox?.state === "STOPPED")
        return {
          kind: "transition",
          to: "CAPTURING",
          phase: "capturing",
          stopped: true,
          clearOperation: true,
        };
      if (isTerminalOp(op) && op.state !== "SUCCEEDED")
        return {
          kind: "fail",
          failure:
            obs.sandbox?.state === "HOST_LOST"
              ? { errorCode: "build_host_lost" }
              : { errorCode: "build_internal", errorDetail: "stop_failed" },
        };
      return { kind: "wait", phase: "stopping" };
    }
    case "CAPTURING":
      return decideCapturing(build, obs, limits);
    default:
      return { kind: "wait" };
  }
}

function decideRunning(build: BuildView, obs: Observed): Decision {
  const op = obs.op;
  switch (build.phase) {
    case "context_import": {
      const ctx = obs.context;
      if (ctx?.state === "ADOPTED" && ctx.transferId)
        return { kind: "transition", to: "RUNNING", phase: "context_commit", clearOperation: true };
      if (ctx?.state === "SEALED")
        return { kind: "claim", action: "import", n: 0, attempt: 0, phase: "context_import" };
      return {
        kind: "fail",
        failure: {
          errorCode:
            ctx?.errorCode && CONTEXT_ERROR_CODES.has(ctx.errorCode)
              ? (ctx.errorCode as BuildErrorCode)
              : "build_context_failed",
          errorDetail: ctx ? errorDetailOf(ctx.state) : "missing",
        },
      };
    }
    case "context_commit": {
      if (!op)
        return { kind: "claim", action: "context", n: 0, attempt: 0, phase: "context_commit" };
      if (op.state === "SUCCEEDED")
        return {
          kind: "transition",
          to: "RUNNING",
          phase: "step",
          stepIndex: 0,
          clearOperation: true,
        };
      if (isTerminalOp(op))
        return {
          kind: "fail",
          failure: { errorCode: "build_context_failed", errorDetail: errorDetailOf(op.errorCode) },
        };
      return { kind: "wait", phase: "context_commit" };
    }
    case "step": {
      const n = build.stepIndex;
      if (n >= build.execSteps)
        return { kind: "transition", to: "RUNNING", phase: "lease", clearOperation: true };
      if (!op) return { kind: "claim", action: "run", n, attempt: 0, phase: "step" };
      if (op.state === "SUCCEEDED") {
        if (op.exitCode === 0)
          return {
            kind: "transition",
            to: "RUNNING",
            phase: "step",
            stepIndex: n + 1,
            clearOperation: true,
          };
        return {
          kind: "fail",
          failure: {
            errorCode: "build_step_failed",
            failureExitCode: op.exitCode ?? -1,
            tail: true,
          },
        };
      }
      if (op.state === "FAILED" && op.errorCode === "timeout")
        return { kind: "fail", failure: { errorCode: "build_step_timeout", tail: true } };
      // D8: the host stopped the step at its `max_carry` cap after staying
      // disconnected; the stop is proven, so this is not an unknown outcome.
      if (op.state === "FAILED" && op.errorCode === "host_disconnect_expired")
        return { kind: "fail", failure: { errorCode: "build_step_host_disconnected", tail: true } };
      // Commands are never retried: any other end is an unknown outcome.
      if (isTerminalOp(op))
        return {
          kind: "fail",
          failure: {
            errorCode: "build_step_unknown",
            errorDetail: errorDetailOf(op.errorCode),
            tail: true,
          },
        };
      return { kind: "wait", phase: "step" };
    }
    case "lease":
      // The lease re-anchor (setTimeout) commits the new lease in its own
      // transaction; its host acknowledgement is not awaited.
      if (!op) return { kind: "claim", action: "timeout", n: 0, attempt: 0, phase: "lease" };
      return { kind: "transition", to: "STOPPING", phase: "stopping", clearOperation: true };
    default:
      return { kind: "fail", failure: { errorCode: "build_internal", errorDetail: "phase" } };
  }
}

function decideCapturing(build: BuildView, obs: Observed, limits: DecideLimits): Decision {
  const capture = obs.capture;
  if (!capture)
    return {
      kind: "claim",
      action: "capture",
      n: 0,
      attempt: build.captureAttempt,
      phase: "capturing",
    };
  switch (capture.state) {
    case "PENDING":
      return { kind: "wait", phase: "capturing" };
    case "CAPTURED":
    case "STORING":
      return { kind: "wait", phase: "storing" };
    case "FINALIZED":
      if (!capture.revisionId)
        return {
          kind: "fail",
          failure: { errorCode: "build_internal", errorDetail: "capture_revision" },
        };
      if (build.verifyRequired) return decideVerify(obs);
      return { kind: "transition", to: "SUCCEEDED", phase: null, revisionId: capture.revisionId };
    case "FAILED": {
      const attempt = capture.attempt;
      // Retry-with-new-attempt (§3.3): the lookup proves the row terminal
      // with an unknown outcome; the claim raises the build's current
      // attempt and a new key creates a new (buildId, attempt) capture.
      if (capture.opState === "UNKNOWN_OUTCOME" && attempt < CAPTURE_UNKNOWN_RETRIES)
        return { kind: "claim", action: "capture", n: 0, attempt: attempt + 1, phase: "capturing" };
      if (capture.errorCode === "capture_store_failed")
        return { kind: "fail", failure: { errorCode: "build_store_failed" } };
      const lease = obs.sandbox?.leaseExpiresAt;
      if (lease && lease.getTime() <= limits.now.getTime())
        return { kind: "fail", failure: { errorCode: "build_capture_lease_expired" } };
      return {
        kind: "fail",
        failure: {
          errorCode: "build_capture_failed",
          errorDetail: errorDetailOf(capture.errorCode),
        },
      };
    }
    default:
      return {
        kind: "fail",
        failure: { errorCode: "build_internal", errorDetail: "capture_state" },
      };
  }
}

/** Sandbox states a verify VM never leaves (no smoke can still run). */
const TERMINAL_VM_STATES: ReadonlySet<string> = new Set(["DELETED", "ERROR", "HOST_LOST"]);

/**
 * The verify decision table (community-base S9, review4 U9), for a
 * `verifyRequired` build in CAPTURING with its capture FINALIZED. The
 * deadline row is `deadlineFailure`. Before the verify VM row exists a
 * refused create is retried until the deadline; once it exists, any failure
 * is terminal `build_verify_failed`.
 */
function decideVerify(obs: Observed): Decision {
  const verify = obs.verify ?? null;
  const fail = (errorDetail: string | null, tail = false): Decision => ({
    kind: "verify_finish",
    pass: false,
    failure: { errorCode: "build_verify_failed", errorDetail, tail },
  });
  if (verify?.revisionRetired) return fail("revision_retired");
  const smoke = verify?.smokeOp ?? null;
  if (smoke && TERMINAL_OPERATION.has(smoke.state)) {
    if (smoke.state === "SUCCEEDED" && smoke.exitCode === 0)
      return { kind: "verify_finish", pass: true };
    return fail(smoke.state === "SUCCEEDED" ? "smoke_failed" : "smoke_unknown", true);
  }
  if (!verify?.vm)
    return { kind: "claim", action: "vcreate", n: 0, attempt: 0, phase: "verifying" };
  if (TERMINAL_VM_STATES.has(verify.vm.state))
    return fail(errorDetailOf(verify.createOp?.detail) ?? "verify_vm_lost");
  const create = verify.createOp;
  if (create && TERMINAL_OPERATION.has(create.state) && create.state !== "SUCCEEDED")
    return fail(errorDetailOf(create.detail) ?? "verify_create_failed");
  if (verify.vm.state === "READY" && create?.state === "SUCCEEDED" && !smoke)
    return { kind: "claim", action: "vrun", n: 0, attempt: 0, phase: "verifying" };
  return { kind: "wait", phase: "verifying" };
}

/** How a thrown service error is handled (§3.3 retry table). */
export type ErrorClass =
  /** Outcome unknown: replay the same key after backoff. */
  | { kind: "ambiguous" }
  /** Refused before any effect: same key after backoff (bounded by the phase
   * deadline). `phase` names the blocker the build shows while it waits. */
  | { kind: "retryable"; phase?: BuildPhase }
  /** Ends the build. */
  | { kind: "terminal"; failure: BuildFailure };

const TERMINAL_ORPC_CODES: ReadonlySet<string> = new Set([
  "BAD_REQUEST",
  "NOT_FOUND",
  "CONFLICT",
  "PAYLOAD_TOO_LARGE",
  "UNPROCESSABLE_CONTENT",
  "PRECONDITION_FAILED",
]);
const RETRYABLE_CAPTURE_CODES: ReadonlySet<string> = new Set([
  "sandbox.capture_busy",
  "sandbox.host_capacity",
]);

function failureCodeFor(action: AdvanceAction): BuildErrorCode {
  switch (action) {
    case "create":
      return "build_placement_failed";
    case "capture":
      return "build_capture_failed";
    case "import":
    case "context":
      return "build_context_failed";
    case "vrun":
      return "build_verify_failed";
    default:
      return "build_internal";
  }
}

/**
 * Classify a thrown service error. Authority loss is recognised ONLY by the
 * typed `data.code === "build.authority_lost"` (r2 N12): a FORBIDDEN without
 * it ("Authority changed during request") is ambiguous, never terminal.
 */
export function classifyServiceError(action: AdvanceAction, error: unknown): ErrorClass {
  if (isBuildAuthorityLost(error))
    return { kind: "terminal", failure: { errorCode: "build_authority_lost" } };
  if (error instanceof BuildContextPortError) {
    if (error.retryable) return { kind: "retryable" };
    return {
      kind: "terminal",
      failure: {
        errorCode:
          error.contextErrorCode && CONTEXT_ERROR_CODES.has(error.contextErrorCode)
            ? (error.contextErrorCode as BuildErrorCode)
            : "build_context_failed",
        errorDetail: errorDetailOf(error.code),
      },
    };
  }
  if (!(error instanceof ORPCError)) return { kind: "ambiguous" };
  const data = error.data as { code?: unknown } | undefined;
  const code = typeof data?.code === "string" ? data.code : null;
  if (error.code === "SERVICE_UNAVAILABLE" || error.code === "TOO_MANY_REQUESTS")
    return { kind: "retryable" };
  // The build VM's host is reconnecting (a daemon restart): refused inside
  // the operation transaction before any row, so the same key retries,
  // bounded by the phase deadline (live: restart during a prep step).
  if (code === "sandbox.host_unavailable") return { kind: "retryable" };
  if (action === "capture" && code === "sandbox.host_capacity")
    return { kind: "retryable", phase: "capture_waiting_capacity" };
  if (action === "capture" && code && RETRYABLE_CAPTURE_CODES.has(code))
    return { kind: "retryable" };
  if (error.code === "FORBIDDEN") return { kind: "ambiguous" };
  // A verify create refused before its VM row exists retries until the
  // verify deadline (`deadlineFailure`), never ends the build early.
  if (action === "vcreate") return { kind: "retryable", phase: "verifying" };
  if (TERMINAL_ORPC_CODES.has(error.code))
    return {
      kind: "terminal",
      failure: {
        errorCode: failureCodeFor(action),
        errorDetail: errorDetailOf(code ?? error.code),
      },
    };
  return { kind: "ambiguous" };
}

/** Backoff for retryable and ambiguous outcomes: 2 s doubling to 60 s. */
export function retryBackoffMs(failures: number): number {
  return Math.min(60_000, 2_000 * 2 ** Math.max(0, Math.min(failures, 5)));
}

/** Charged minutes (§3.3, r2 N15): READY → end, rounded up, clamped to the
 * reservation (stop/kill lag past the deadline is absorbed, not charged). */
export function chargedMinutes(readyAt: Date | null, endAt: Date, reservedMinutes: number): number {
  if (!readyAt) return 0;
  const ms = Math.max(0, endAt.getTime() - readyAt.getTime());
  return Math.min(Math.ceil(ms / 60_000), reservedMinutes);
}
