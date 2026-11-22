import { randomUUID } from "node:crypto";
import prisma, { type Prisma, type TemplateBuildState } from "@wssp/db";
import { AccountDeletionConflictError, lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { CAPACITY_WAIT_MAX_MS } from "@wssp/sandbox-contracts";
import { noteCapacityChanged } from "../sandbox/capacity-queue-wake";
import type { Principal } from "../sandbox/contracts";
import { SANDBOX_COMMAND_TIMEOUT_MAX_MS } from "../sandbox/contracts";
import { lockOwnerPlacement } from "../sandbox/direct-placement";
import { applyCaptureRetention, captureSandbox } from "../sandbox/image-store/captures";
import { bindOperationChangeBuildWake } from "../sandbox/operation-waiters";
import { readinessReasonOfFailure } from "../sandbox/readiness-detail";
import {
  type BuildCommandExtras,
  createSandbox,
  killSandbox,
  runCommand,
  setSandboxTimeout,
  stopSandbox,
} from "../sandbox/services/sandboxes";
import { buildVmMustDie, type CleanupCursor, cleanupCandidatesSql, rotatingPage } from "./cleanup";
import {
  SMOKE_TIMEOUT_MS,
  UBUNTU_CLOUD_SMOKE_V1,
  VERIFY_WINDOW_MINUTES,
} from "./community/catalog";
import { startCommunityRefreshSchedule } from "./community/refresh-schedule";
import {
  TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS,
  templateBuildLeaseMs,
  templateBuildReserveMinutes,
  templateBuildsConfig,
} from "./config";
import {
  bindBuildContextWake,
  buildContextCommitKey,
  buildContextGuestPath,
  buildContextImportKey,
  buildContextPort,
} from "./context-port";
import {
  type AdvanceAction,
  type BuildFailure,
  type BuildView,
  buildActionKey,
  buildKeyAttempt,
  chargedMinutes,
  classifyServiceError,
  type DecideLimits,
  type Decision,
  deadlineFailure,
  decide,
  type Observed,
  quiesceHeldMs,
  retryBackoffMs,
  TERMINAL_BUILD_STATES,
} from "./decide";
import {
  type BuildStepRecord,
  type ExecPlan,
  type ExecStep,
  loadBuildExecPlan,
  parseStepRecords,
} from "./exec-plan";
import { loadBuildPrincipal } from "./principal";
import {
  bindTemplateBuildWake,
  notifyTemplateBuildProgress,
  notifyTemplateBuildsChanged,
} from "./wake";

/**
 * The template-build orchestrator. A lock-free candidate scan,
 * then one short transaction per build that decides the next action and
 * freezes its complete service input into `pendingAction` (the claim), the
 * service call made with the build principal outside any build-row lock, and
 * a second short transaction that records the result if the claim is still
 * ours. Lock order (§3.4): owner admission → owner placement → build row; no
 * holder of a build row later takes any of them, and no service call runs
 * while the build row is held.
 */

/** A claim's lifetime. Kept above every service call's bound
 * (`TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS`) so a claim never expires under a
 * call that is still running (the unit test pins the order). */
export const TEMPLATE_BUILD_CLAIM_TTL_MS = 120_000;
/**
 * The bound on one orchestrator service call. Every transaction a service
 * reaches is an interactive Prisma transaction, which the shared client runs
 * with Prisma's 5 s transaction timeout (no `transactionOptions` override in
 * `createPrismaClient`); the wrapper bounds the whole call (retries
 * included) at 60 s and reports a late call as ambiguous, so its key is
 * replayed, never re-minted.
 */
export const TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS = 60_000;
/** Builds advanced per tick (§3.3). */
export const TEMPLATE_BUILD_TICK_BATCH = 32;
/** Periodic sweep, next to the capture sweep. */
export const TEMPLATE_BUILD_SWEEP_MS = 15_000;
/** Tail of a failed step's output kept on the build (≤ the CHECK). */
export const BUILD_FAILURE_TAIL_BYTES = 8192;
/** Placeholder argv of a COPY step: the daemon runs its fixed helper and the
 * payload carries no argv or script (B3/B5a). */
export const BUILD_COPY_ARGV = ["wssp-build-copy"];

export class BuildCallTimeout extends Error {
  constructor() {
    super("Build service call exceeded its bound.");
    this.name = "BuildCallTimeout";
  }
}

/** Run one service call under the orchestrator's bound (ambiguous on expiry). */
export async function callWithDeadline<T>(
  work: () => Promise<T>,
  ms = TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new BuildCallTimeout()), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** The claim, stored in `pendingAction` with its frozen input. */
export type PendingAction = {
  kind: AdvanceAction;
  n: number;
  attempt: number;
  key: string;
  input: Record<string, unknown>;
  claimToken: string;
  /** Epoch ms. */
  claimedUntil: number;
  /** Thrown errors so far (backoff only; never raises `attempt`). */
  failures: number;
};

function parsePending(value: Prisma.JsonValue | null): PendingAction | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  return typeof row.kind === "string" &&
    typeof row.key === "string" &&
    typeof row.claimToken === "string" &&
    typeof row.claimedUntil === "number"
    ? (row as unknown as PendingAction)
    : null;
}

const buildSelect = {
  id: true,
  userId: true,
  templateId: true,
  tag: true,
  recipe: true,
  buildArgs: true,
  baseRevisionId: true,
  contextSha256: true,
  poolId: true,
  requestedHostId: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  defaultDiskGiB: true,
  egressRequest: true,
  timeoutMinutes: true,
  waitForCapacityMs: true,
  reservedMinutes: true,
  minutesSettled: true,
  state: true,
  phase: true,
  stepIndex: true,
  steps: true,
  pendingAction: true,
  buildSandboxId: true,
  currentOperationId: true,
  captureOperationId: true,
  captureAttempt: true,
  cancelRequestedAt: true,
  deadlineAt: true,
  captureDeadlineAt: true,
  readyAt: true,
  stoppedAt: true,
  createdAt: true,
  verifyRequired: true,
  verifyDeadlineAt: true,
  verifySandboxId: true,
  triggeredByRevisionId: true,
} satisfies Prisma.SandboxTemplateBuildSelect;
type BuildRow = Prisma.SandboxTemplateBuildGetPayload<{ select: typeof buildSelect }>;

const loadExecPlan = (tx: Prisma.TransactionClient, build: BuildRow) =>
  loadBuildExecPlan(tx, build);

function exitCodeOf(result: Prisma.JsonValue | null): number | null {
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const code = (result as { exitCode?: unknown }).exitCode;
  return typeof code === "number" && Number.isSafeInteger(code) ? code : null;
}

async function observe(tx: Prisma.TransactionClient, build: BuildRow) {
  const op = build.currentOperationId
    ? await tx.sandboxOperation.findFirst({
        where: { id: build.currentOperationId, userId: build.userId },
        select: {
          state: true,
          errorCode: true,
          result: true,
          idempotencyKey: true,
          completedAt: true,
          createdAt: true,
          kind: true,
          dispatchedAt: true,
        },
      })
    : null;
  const sandbox = build.buildSandboxId
    ? await tx.sandbox.findFirst({
        where: { id: build.buildSandboxId, userId: build.userId },
        select: { state: true, leaseExpiresAt: true, sandboxHostId: true, hostOwnerId: true },
      })
    : null;
  // Failure evidence is written to an active capture by relay and server
  // transactions (`recordCaptureEvidence`, `failCapture`) that never lock the
  // build. Under the build row lock the capture row is share-locked before it
  // is read (build → capture, the finalizer's order): a writer committing
  // meanwhile is waited for and seen, so a failure this advance settles
  // (`capture_deadline`, the lease) carries the evidence (I4), never a
  // snapshot older than it.
  if (build.captureOperationId)
    await tx.$queryRaw`SELECT 1 FROM sandbox_template_capture
      WHERE "operationId" = ${build.captureOperationId} AND "userId" = ${build.userId} FOR SHARE`;
  const capture = build.captureOperationId
    ? await tx.sandboxTemplateCapture.findFirst({
        where: { operationId: build.captureOperationId, userId: build.userId },
        select: {
          state: true,
          errorCode: true,
          errorDetail: true,
          capturedAt: true,
          revisionId: true,
          buildAttempt: true,
          Operation: { select: { state: true } },
        },
      })
    : null;
  // Only the current attempt's capture is observed (a link always names it;
  // the claim of a retry drops the replaced attempt's link).
  const current = capture && capture.buildAttempt === build.captureAttempt ? capture : null;
  const context = build.contextSha256
    ? await tx.sandboxBuildContext.findFirst({
        where: { buildId: build.id, userId: build.userId },
        select: { state: true, transferId: true, errorCode: true },
      })
    : null;
  const verify =
    build.verifyRequired && current?.state === "FINALIZED" && current.revisionId
      ? await observeVerify(tx, build, current.revisionId)
      : null;
  const observed: Observed = {
    verify,
    op: op
      ? {
          state: op.state,
          errorCode: op.errorCode,
          exitCode: exitCodeOf(op.result),
          idempotencyKey: op.idempotencyKey,
        }
      : null,
    sandbox: sandbox ? { state: sandbox.state, leaseExpiresAt: sandbox.leaseExpiresAt } : null,
    capture: current
      ? {
          state: current.state,
          errorCode: current.errorCode,
          errorDetail: current.errorDetail,
          capturedAt: current.capturedAt,
          revisionId: current.revisionId,
          opState: current.Operation.state,
          attempt: current.buildAttempt,
        }
      : null,
    context: context
      ? { state: context.state, transferId: context.transferId, errorCode: context.errorCode }
      : null,
  };
  // WP7: a step command held by a quiescing host does not spend the build
  // deadline (quiesce-hold.ts); settled holds are already in `deadlineAt`.
  // Read in every op state, not only QUEUED: a non-quiescing hello lets the
  // held step dispatch before its asynchronous settlement commits, and until
  // then the marker (with `quiesceHeldMs` ending at `dispatchedAt`) is the
  // only record of the hold.
  const quiescingSince =
    build.state === "RUNNING" &&
    op?.kind === "RUN_COMMAND" &&
    sandbox?.sandboxHostId &&
    sandbox.hostOwnerId
      ? ((
          await tx.sandboxHost.findFirst({
            where: { id: sandbox.sandboxHostId, userId: sandbox.hostOwnerId },
            select: { quiescingSince: true },
          })
        )?.quiescingSince ?? null)
      : null;
  return { observed, op, sandbox, quiescingSince };
}

/** The verify facts of a community build (D-D, M4): every lookup is keyed on
 * a durable fact (`Sandbox.verifyBuildId`, the action keys), never on a
 * link an outcome transaction may have lost. */
async function observeVerify(
  tx: Prisma.TransactionClient,
  build: BuildRow,
  revisionId: string,
): Promise<NonNullable<Observed["verify"]>> {
  const vm = await tx.sandbox.findFirst({
    where: { verifyBuildId: build.id, userId: build.userId },
    select: { id: true, state: true },
  });
  const opByKey = (action: "vcreate" | "vrun") =>
    tx.sandboxOperation.findUnique({
      where: {
        userId_idempotencyKey: {
          userId: build.userId,
          idempotencyKey: buildActionKey(build.id, action, 0, 0),
        },
      },
      select: { state: true, errorCode: true, result: true, failure: true },
    });
  const createOp = vm ? await opByKey("vcreate") : null;
  const smokeOp = vm ? await opByKey("vrun") : null;
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: revisionId, userId: build.userId },
    select: { retiredAt: true, pendingVerifyBuildId: true },
  });
  return {
    vm: vm ? { state: vm.state } : null,
    createOp: createOp
      ? {
          state: createOp.state,
          // The u2604 readiness reason when readiness failed (L1), else the code.
          detail: readinessReasonOfFailure(createOp.failure) ?? createOp.errorCode,
        }
      : null,
    smokeOp: smokeOp ? { state: smokeOp.state, exitCode: exitCodeOf(smokeOp.result) } : null,
    revisionRetired: !revision || revision.retiredAt !== null,
  };
}

function viewOf(build: BuildRow, exec: ExecPlan | null): BuildView {
  return {
    state: build.state,
    phase: build.phase,
    stepIndex: build.stepIndex,
    cancelRequestedAt: build.cancelRequestedAt,
    deadlineAt: build.deadlineAt,
    captureDeadlineAt: build.captureDeadlineAt,
    createdAt: build.createdAt,
    hasContext: build.contextSha256 !== null,
    waitForCapacityMs: build.waitForCapacityMs,
    execSteps: exec?.steps.length ?? 0,
    captureAttempt: build.captureAttempt,
    verifyRequired: build.verifyRequired,
    verifyDeadlineAt: build.verifyDeadlineAt,
  };
}

function limitsAt(now: Date): DecideLimits {
  return {
    now,
    contextSealedMaxMs: TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS,
    // An OPEN context's idle bound; a context that was never opened fails after it.
    contextIdleMs: 15 * 60_000,
  };
}

/** A step's timeout: the build's remaining time, at most the command cap. */
export function stepTimeoutMs(deadlineAt: Date | null, now: Date): number {
  const remaining = deadlineAt ? deadlineAt.getTime() - now.getTime() : 0;
  return Math.max(1_000, Math.min(SANDBOX_COMMAND_TIMEOUT_MAX_MS, remaining));
}

/** COPY wire source: the recipe keeps a trailing `/` as a directory hint;
 * the wire form has none (Docker treats `app/` and `app` alike). */
export function wireCopySource(src: string): string {
  return src.length > 1 && src.endsWith("/") ? src.slice(0, -1) : src;
}

/** COPY wire destination: one trailing `/` marks a directory. */
function copyDest(dest: string, isDir: boolean): string {
  if (!isDir || dest === "/") return dest;
  return `${dest}/`;
}

function copyMode(mode: string | null): number | undefined {
  return mode === null ? undefined : Number.parseInt(mode, 8);
}

/** Freeze the complete service input of one action (§3.3 claim step 1). */
export function freezeInput(
  build: Pick<
    BuildRow,
    | "id"
    | "baseRevisionId"
    | "poolId"
    | "requestedHostId"
    | "cpuCount"
    | "memoryMiB"
    | "diskGiB"
    | "defaultDiskGiB"
    | "egressRequest"
    | "timeoutMinutes"
    | "waitForCapacityMs"
    | "buildSandboxId"
    | "contextSha256"
    | "deadlineAt"
    | "templateId"
    | "recipe"
    | "verifySandboxId"
  >,
  exec: ExecPlan | null,
  action: AdvanceAction,
  n: number,
  attempt: number,
  now: Date,
  captureWindowMinutes: number,
  verify: { revisionId: string | null; sandboxId: string | null } = {
    revisionId: null,
    sandboxId: null,
  },
): { key: string; input: Record<string, unknown> } {
  const key =
    action === "import"
      ? buildContextImportKey(build.id, 0)
      : action === "context"
        ? buildContextCommitKey(build.id, attempt)
        : buildActionKey(build.id, action, n, attempt);
  const id = build.buildSandboxId;
  switch (action) {
    case "create": {
      const egress = build.egressRequest as {
        mode?: string;
        domains?: string[];
        cidrs?: string[];
      } | null;
      return {
        key,
        input: {
          template: `revision/${build.baseRevisionId}`,
          ...(build.poolId ? { poolId: build.poolId } : { sandboxHostId: build.requestedHostId }),
          cpuCount: build.cpuCount,
          memoryMiB: build.memoryMiB,
          diskGiB: build.diskGiB,
          idempotencyKey: key,
          timeoutMs: templateBuildLeaseMs(build.timeoutMinutes, captureWindowMinutes),
          lifecycle: { onTimeout: "kill" },
          // DG-6: a build VM never has guestSudo (root steps are D1 only).
          guestSudo: false,
          ...(build.waitForCapacityMs !== null
            ? {
                waitForCapacityMs: Math.min(build.waitForCapacityMs, CAPACITY_WAIT_MAX_MS),
              }
            : {}),
          // The stored REQUEST (§6.3); placement and materialization resolve
          // the effective policy (and any downgrade reason, recorded on this
          // VM's sandbox row) exactly as for a plain create. Absent is the
          // plain create default: open, no fallback grants.
          ...(egress
            ? {
                egress: {
                  mode: egress.mode === "open" ? "open" : "allowlist",
                  domains: egress.domains ?? [],
                  cidrs: egress.cidrs ?? [],
                },
              }
            : {}),
        },
      };
    }
    case "import":
      return { key, input: {} };
    case "context":
      return { key, input: {} };
    case "run": {
      const step = exec?.steps[n];
      if (!step) throw new Error("Build step out of range.");
      return { key, input: runInput(build, step, key, now) };
    }
    case "timeout":
      return {
        key,
        input: {
          id,
          idempotencyKey: key,
          // Re-anchor the lease at the actual stop: capture window + storage
          // window + slack (§3.3), so the VM outlives a recorded capture's
          // upload to the image store.
          timeoutMs: templateBuildReserveMinutes(captureWindowMinutes) * 60_000,
        },
      };
    case "stop":
      return { key, input: { id, idempotencyKey: key } };
    case "vcreate":
      // The verify VM (S9): the pending revision as the guest user, the
      // build's own target and CPU/memory at the revision's DEFAULT disk
      // (above its floor, so the create's root growth check proves the
      // image grows before it is published), deny-all egress, guestSudo
      // pinned off, a lease of the verify window, killed on expiry. Never a
      // capacity wait (T4.1).
      if (!verify.revisionId) throw new Error("Verify revision missing.");
      return {
        key,
        input: {
          template: `revision/${verify.revisionId}`,
          ...(build.poolId ? { poolId: build.poolId } : { sandboxHostId: build.requestedHostId }),
          cpuCount: build.cpuCount,
          memoryMiB: build.memoryMiB,
          diskGiB: build.defaultDiskGiB,
          idempotencyKey: key,
          timeoutMs: VERIFY_WINDOW_MINUTES * 60_000,
          lifecycle: { onTimeout: "kill" },
          guestSudo: false,
          egress: { mode: "allowlist", domains: [], cidrs: [] },
        },
      };
    case "vrun":
      // The smoke as the guest user, no build extras (T8): no root, no COPY.
      if (!verify.sandboxId) throw new Error("Verify VM missing.");
      return {
        key,
        input: {
          id: verify.sandboxId,
          idempotencyKey: key,
          script: UBUNTU_CLOUD_SMOKE_V1,
          timeoutMs: SMOKE_TIMEOUT_MS,
        },
      };
    case "capture": {
      const recipe = build.recipe as { scrubPaths?: string[] } | null;
      return {
        key,
        input: {
          id,
          idempotencyKey: key,
          templateId: build.templateId,
          scrubPaths: recipe?.scrubPaths ?? [],
        },
      };
    }
  }
}

function runInput(
  build: Pick<BuildRow, "buildSandboxId" | "contextSha256" | "deadlineAt" | "id">,
  step: ExecStep,
  key: string,
  now: Date,
): Record<string, unknown> {
  const timeoutMs = stepTimeoutMs(build.deadlineAt, now);
  const base = { id: build.buildSandboxId, idempotencyKey: key, timeoutMs };
  switch (step.kind) {
    case "prelude":
      return { input: { ...base, script: step.script }, extras: { runAs: "root" } };
    case "run":
      return {
        input: {
          ...base,
          script: step.script,
          ...(step.cwd !== null ? { cwd: step.cwd } : {}),
          ...(Object.keys(step.envs).length > 0 ? { envs: step.envs } : {}),
        },
        extras: step.user === "root" ? { runAs: "root" } : {},
      };
    case "copy":
      return {
        input: { ...base, argv: BUILD_COPY_ARGV },
        extras: {
          buildCopy: {
            contextPath: buildContextGuestPath(build.id),
            sha256: build.contextSha256,
            src: step.src.map(wireCopySource),
            dest: copyDest(step.dest, step.destIsDir),
            owner: step.owner,
            ...(step.mode !== null ? { mode: copyMode(step.mode) } : {}),
          },
        },
      };
  }
}

/** Last ≤ 8 KiB of a step's retained output (head/tail segments, §5). */
async function outputTail(
  tx: Prisma.TransactionClient,
  operationId: string,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const segments = await tx.sandboxCommandOutputSegment.findMany({
    where: { outputId: operationId },
    orderBy: { startOffset: "desc" },
    select: { bytes: true },
    take: 2,
  });
  if (segments.length === 0) return null;
  const joined = Buffer.concat(segments.reverse().map((segment) => Buffer.from(segment.bytes)));
  const tail = joined.subarray(Math.max(0, joined.byteLength - BUILD_FAILURE_TAIL_BYTES));
  return new Uint8Array(tail);
}

/** Minutes settle once (§3.3): the caller holds owner placement + the row. */
function settleMinutes(build: BuildRow, endAt: Date, readyAt = build.readyAt) {
  if (build.minutesSettled) return {};
  return {
    minutesSettled: true,
    chargedMinutes: chargedMinutes(readyAt, endAt, build.reservedMinutes),
  };
}

function withStep(
  build: BuildRow,
  n: number,
  patch: Partial<BuildStepRecord>,
): Prisma.InputJsonValue {
  const steps = parseStepRecords(build.steps);
  return steps.map((step) =>
    step.n === n ? { ...step, ...patch } : step,
  ) as Prisma.InputJsonValue;
}

/** End a build FAILED (or CANCELLED when a cancel is recorded). Minutes
 * settle at the failure; the cleanup invariant kills the VM. */
async function applyFailure(
  tx: Prisma.TransactionClient,
  build: BuildRow,
  failure: BuildFailure,
  now: Date,
  exec: ExecPlan | null,
) {
  if (build.cancelRequestedAt) {
    await tx.sandboxTemplateBuild.update({
      where: { id: build.id },
      data: { state: "CANCELLING", pendingAction: PrismaNull(), nextAttemptAt: now },
    });
    return;
  }
  // A failed community build never publishes: its pending revision (if the
  // capture finalized) retires with it, whatever ended the build (verify
  // deadline, a refused step, an internal failure), so retention, prune and
  // GC release its image. Lock order: build (held) → revision.
  if (build.verifyRequired)
    await tx.sandboxTemplateRevision.updateMany({
      where: { pendingVerifyBuildId: build.id, userId: build.userId, retiredAt: null },
      data: { retiredAt: now, retiredReason: "verify_failed" },
    });
  const n = build.stepIndex;
  const stepFailure =
    failure.errorCode === "build_step_failed" ||
    failure.errorCode === "build_step_timeout" ||
    failure.errorCode === "build_step_host_disconnected" ||
    failure.errorCode === "build_step_unknown";
  const step = stepFailure && exec ? exec.steps[n] : undefined;
  const tail =
    failure.tail && build.currentOperationId
      ? await outputTail(tx, build.currentOperationId)
      : null;
  await tx.sandboxTemplateBuild.update({
    where: { id: build.id },
    data: {
      state: "FAILED",
      phase: null,
      errorCode: failure.errorCode,
      errorDetail: failure.errorDetail ?? null,
      ...(step ? { failureStepIndex: step.stepIndex } : {}),
      ...(failure.failureExitCode !== undefined
        ? { failureExitCode: failure.failureExitCode }
        : {}),
      ...(tail ? { failureTail: tail } : {}),
      ...(stepFailure && n >= 0
        ? {
            steps: withStep(build, n, {
              state: "failed",
              exitCode: failure.failureExitCode ?? null,
            }),
          }
        : {}),
      pendingAction: PrismaNull(),
      nextAttemptAt: now,
      completedAt: now,
      ...settleMinutes(build, now),
    },
  });
}

function PrismaNull() {
  return PrismaValue.DbNull;
}

/**
 * A capture accepted for this build's current attempt is the build's
 * capture, whether or not the claim's outcome transaction recorded
 * `captureOperationId`: the capture row carries the immutable
 * (`buildId`, `buildAttempt`) pair from its own acceptance transaction, and
 * the claim that raised `captureAttempt` cleared the previous attempt's link.
 * A cancel that cleared the claim (so tx B discarded the link) therefore
 * cannot hide a recorded capture result (§3.3, r3 N22), and a retried
 * attempt is never confused with the one it replaced. Called under the build
 * row lock; persists the link once found.
 */
async function linkAcceptedCapture(tx: Prisma.TransactionClient, build: BuildRow) {
  if (build.captureOperationId) return build;
  const accepted = await tx.sandboxTemplateCapture.findUnique({
    where: { buildId_buildAttempt: { buildId: build.id, buildAttempt: build.captureAttempt } },
    select: { operationId: true, userId: true },
  });
  if (accepted && accepted.userId !== build.userId) return build;
  if (!accepted) return build;
  return tx.sandboxTemplateBuild.update({
    where: { id: build.id },
    data: { captureOperationId: accepted.operationId },
    select: buildSelect,
  });
}

type Claim = { build: BuildRow; pending: PendingAction };
/** A verify that ended: settled by `finishVerify` in its own transaction. */
type VerifyFinish = {
  verifyFinish: { pass: boolean; failure?: BuildFailure; revisionId: string };
};

/**
 * tx A for one candidate (§3.3 claim step 1). Returns the claim to perform,
 * or null when the row is held by another advancer, has a live claim, or
 * has nothing to do now.
 */
async function claimNext(candidate: { id: string; userId: string }, now: Date) {
  const config = templateBuildsConfig();
  return prisma.$transaction(async (tx): Promise<Claim | VerifyFinish | null> => {
    try {
      await lockOwnerForAdmission(tx, candidate.userId);
    } catch (error) {
      if (error instanceof AccountDeletionConflictError) return null;
      throw error;
    }
    await lockOwnerPlacement(tx, candidate.userId);
    const locked = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM sandbox_template_build
      WHERE id = ${candidate.id} AND "userId" = ${candidate.userId}
      FOR UPDATE SKIP LOCKED`;
    if (!locked[0]) return null;
    let build = await tx.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: candidate.id },
      select: buildSelect,
    });
    build = await linkAcceptedCapture(tx, build);
    const limits = limitsAt(now);
    let exec: ExecPlan | null = null;
    try {
      exec = await loadExecPlan(tx, build);
    } catch {
      if (!TERMINAL_BUILD_STATES.includes(build.state) && build.state !== "CANCELLING") {
        await applyFailure(
          tx,
          build,
          { errorCode: "build_internal", errorDetail: "plan" },
          now,
          null,
        );
        return null;
      }
    }
    const pending = parsePending(build.pendingAction);
    if (pending && pending.claimedUntil > now.getTime()) return null;
    for (let round = 0; round < 8; round++) {
      const { observed, op, sandbox, quiescingSince } = await observe(tx, build);
      const view: BuildView = {
        ...viewOf(build, exec),
        quiesceHeldMs: quiesceHeldMs(quiescingSince, op, now),
      };
      const active = !TERMINAL_BUILD_STATES.includes(build.state) && build.state !== "CANCELLING";
      if (round === 0 && pending && active) {
        // An expired claim replays the SAME key and frozen input under a new
        // token (§3.3), unless a bound has ended the build meanwhile.
        const deadline = deadlineFailure(view, observed, limits);
        if (deadline) {
          await applyFailure(tx, build, deadline, now, exec);
          return null;
        }
        const replay: PendingAction = {
          ...pending,
          claimToken: randomUUID(),
          claimedUntil: now.getTime() + TEMPLATE_BUILD_CLAIM_TTL_MS,
        };
        await tx.sandboxTemplateBuild.update({
          where: { id: build.id },
          data: { pendingAction: replay as unknown as Prisma.InputJsonValue },
        });
        return { build, pending: replay };
      }
      if (round === 0 && pending)
        await tx.sandboxTemplateBuild.update({
          where: { id: build.id },
          data: { pendingAction: PrismaNull() },
        });
      const decision: Decision = decide(view, observed, limits);
      switch (decision.kind) {
        case "wait":
          await tx.sandboxTemplateBuild.update({
            where: { id: build.id },
            data: {
              ...(decision.phase && decision.phase !== build.phase
                ? { phase: decision.phase }
                : {}),
              nextAttemptAt: now,
            },
          });
          return null;
        case "fail":
          await applyFailure(tx, build, decision.failure, now, exec);
          return null;
        case "verify_finish": {
          const revisionId = observed.capture?.revisionId;
          if (!revisionId) {
            await applyFailure(
              tx,
              build,
              { errorCode: "build_internal", errorDetail: "capture_revision" },
              now,
              exec,
            );
            return null;
          }
          return {
            verifyFinish: {
              pass: decision.pass,
              ...(decision.failure ? { failure: decision.failure } : {}),
              revisionId,
            },
          };
        }
        case "cancelled":
          // A cancelled community build never publishes: its pending
          // revision (if the capture finalized) retires with it (S9 Cancel).
          if (build.verifyRequired)
            await tx.sandboxTemplateRevision.updateMany({
              where: {
                pendingVerifyBuildId: build.id,
                userId: build.userId,
                retiredAt: null,
              },
              data: { retiredAt: now, retiredReason: "manual" },
            });
          await tx.sandboxTemplateBuild.update({
            where: { id: build.id },
            data: {
              state: "CANCELLED",
              phase: null,
              pendingAction: PrismaNull(),
              completedAt: now,
              nextAttemptAt: now,
              ...settleMinutes(build, now),
            },
          });
          return null;
        case "transition": {
          const data: Prisma.SandboxTemplateBuildUpdateInput = {
            state: decision.to,
            phase: decision.phase,
            ...(decision.stepIndex !== undefined ? { stepIndex: decision.stepIndex } : {}),
            ...(decision.clearOperation ? { currentOperationId: null } : {}),
          };
          if (decision.ready) {
            const readyAt = op?.completedAt ?? now;
            data.readyAt = readyAt;
            // A community build's timeout also reserves its verify window;
            // its steps get only the recipe's own budget (T8).
            const stepMinutes =
              build.timeoutMinutes - (build.verifyRequired ? VERIFY_WINDOW_MINUTES : 0);
            data.deadlineAt = new Date(readyAt.getTime() + stepMinutes * 60_000);
            if (sandbox?.sandboxHostId && sandbox.hostOwnerId) {
              data.hostId = sandbox.sandboxHostId;
              data.hostOwnerId = sandbox.hostOwnerId;
              data.foreignHost = sandbox.hostOwnerId !== build.userId;
            }
          }
          // A finished step: record it before moving on.
          if (
            build.phase === "step" &&
            decision.phase === "step" &&
            decision.stepIndex === build.stepIndex + 1
          )
            data.steps = withStep(build, build.stepIndex, {
              state: "succeeded",
              exitCode: observed.op?.exitCode ?? 0,
            });
          if (decision.stopped) {
            const stoppedAt = op?.completedAt ?? now;
            data.stoppedAt = stoppedAt;
            Object.assign(data, settleMinutes(build, stoppedAt));
          }
          if (decision.to === "SUCCEEDED") {
            data.revisionId = decision.revisionId ?? null;
            data.completedAt = now;
            data.pendingAction = PrismaNull();
            Object.assign(data, settleMinutes(build, build.stoppedAt ?? now));
          }
          build = await tx.sandboxTemplateBuild.update({
            where: { id: build.id },
            data,
            select: buildSelect,
          });
          continue;
        }
        case "claim": {
          const verifyVm =
            decision.action === "vrun"
              ? await tx.sandbox.findFirst({
                  where: { verifyBuildId: build.id, userId: build.userId },
                  select: { id: true },
                })
              : null;
          const frozen = freezeInput(
            build,
            exec,
            decision.action,
            decision.n,
            decision.attempt,
            now,
            config.captureWindowMinutes,
            { revisionId: observed.capture?.revisionId ?? null, sandboxId: verifyVm?.id ?? null },
          );
          const claim: PendingAction = {
            kind: decision.action,
            n: decision.n,
            attempt: decision.attempt,
            key: frozen.key,
            input: frozen.input,
            claimToken: randomUUID(),
            claimedUntil: now.getTime() + TEMPLATE_BUILD_CLAIM_TTL_MS,
            failures: 0,
          };
          const updated = await tx.sandboxTemplateBuild.update({
            where: { id: build.id },
            data: {
              ...(decision.state ? { state: decision.state } : {}),
              phase: decision.phase,
              pendingAction: claim as unknown as Prisma.InputJsonValue,
              ...(decision.action === "run"
                ? { steps: withStep(build, decision.n, { state: "running" }) }
                : {}),
              // A new capture attempt becomes the current one: the replaced
              // attempt's link is dropped in the same write (§3.3).
              ...(decision.action === "capture" && decision.attempt !== build.captureAttempt
                ? { captureAttempt: decision.attempt, captureOperationId: null }
                : {}),
            },
            select: buildSelect,
          });
          return { build: updated, pending: claim };
        }
      }
    }
    return null;
  });
}

type ActionResult = { kind: "operation"; operationId?: string } | { kind: "imported" };

/** §3.3 claim step 2: the service call, with the build principal and the
 * frozen input only. No build-row lock is held here. */
async function perform(principal: Principal, build: BuildRow, claim: PendingAction) {
  const input = claim.input;
  switch (claim.kind) {
    case "create":
      await createSandbox(principal, input as never, undefined, { buildId: build.id });
      return { kind: "operation" } satisfies ActionResult;
    case "import":
      await buildContextPort().importContext(principal, build.id);
      return { kind: "imported" } satisfies ActionResult;
    case "context": {
      const context = await prisma.sandboxBuildContext.findFirst({
        where: { buildId: build.id, userId: build.userId, state: "ADOPTED" },
        select: { transferId: true },
      });
      if (!context?.transferId) throw new BuildCallTimeout();
      const { operationId } = await buildContextPort().commitContext(
        principal,
        build.id,
        context.transferId,
        claim.key,
      );
      return { kind: "operation", operationId } satisfies ActionResult;
    }
    case "run": {
      const run = input as { input: Record<string, unknown>; extras: BuildCommandExtras };
      await runCommand(principal, run.input as never, run.extras);
      return { kind: "operation" } satisfies ActionResult;
    }
    case "timeout":
      await setSandboxTimeout(principal, input as never);
      return { kind: "operation" } satisfies ActionResult;
    case "stop":
      await stopSandbox(principal, input as never);
      return { kind: "operation" } satisfies ActionResult;
    case "capture":
      await captureSandbox(principal, input as never);
      return { kind: "operation" } satisfies ActionResult;
    case "vcreate":
      // The internal role is asserted against the in-transaction derived one.
      await createSandbox(principal, input as never, undefined, {
        buildId: build.id,
        role: "verify",
      });
      return { kind: "operation" } satisfies ActionResult;
    case "vrun":
      await runCommand(principal, input as never);
      return { kind: "operation" } satisfies ActionResult;
  }
}

/** §3.3 claim step 3 (tx B): record the outcome iff the claim is still ours. */
async function recordOutcome(
  claim: Claim,
  outcome: { ok: true; result: ActionResult } | { ok: false; error: unknown },
  now: Date,
) {
  const config = templateBuildsConfig();
  await prisma.$transaction(async (tx) => {
    try {
      await lockOwnerForAdmission(tx, claim.build.userId);
    } catch (error) {
      if (error instanceof AccountDeletionConflictError) return;
      throw error;
    }
    await lockOwnerPlacement(tx, claim.build.userId);
    await tx.$queryRaw`SELECT id FROM sandbox_template_build WHERE id = ${claim.build.id} AND "userId" = ${claim.build.userId} FOR UPDATE`;
    const build = await tx.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: claim.build.id },
      select: buildSelect,
    });
    const pending = parsePending(build.pendingAction);
    // A later claimer owns the action and replays the same key: discard.
    if (!pending || pending.claimToken !== claim.pending.claimToken) return;
    if (outcome.ok) {
      const data: Prisma.SandboxTemplateBuildUpdateInput = {
        pendingAction: PrismaNull(),
        nextAttemptAt: now,
      };
      if (outcome.result.kind === "operation") {
        const operation = outcome.result.operationId
          ? await tx.sandboxOperation.findFirst({
              where: { id: outcome.result.operationId, userId: build.userId },
              select: { id: true, sandboxId: true, createdAt: true },
            })
          : await tx.sandboxOperation.findUnique({
              where: {
                userId_idempotencyKey: { userId: build.userId, idempotencyKey: pending.key },
              },
              select: { id: true, sandboxId: true, createdAt: true },
            });
        if (!operation) {
          // The call returned but its operation is not visible: ambiguous.
          data.pendingAction = {
            ...pending,
            claimedUntil: now.getTime(),
            failures: pending.failures + 1,
          } as unknown as Prisma.InputJsonValue;
          data.nextAttemptAt = new Date(now.getTime() + retryBackoffMs(pending.failures));
        } else
          switch (pending.kind) {
            case "create":
              data.buildSandboxId = operation.sandboxId;
              data.currentOperationId = operation.id;
              break;
            case "run":
              data.currentOperationId = operation.id;
              data.steps = withStep(build, pending.n, {
                state: "running",
                operationId: operation.id,
              });
              break;
            case "stop":
              data.currentOperationId = operation.id;
              // §3.3: the capture window runs from the accepted stop.
              data.captureDeadlineAt = new Date(
                operation.createdAt.getTime() + config.captureWindowMinutes * 60_000,
              );
              break;
            case "vcreate":
              data.verifySandboxId = operation.sandboxId;
              data.currentOperationId = operation.id;
              break;
            case "capture":
              data.captureOperationId = operation.id;
              // A capacity blocker shown while it retried is over.
              if (build.phase === "capture_waiting_capacity") data.phase = "capturing";
              break;
            default:
              data.currentOperationId = operation.id;
          }
      }
      await tx.sandboxTemplateBuild.update({ where: { id: build.id }, data });
      return;
    }
    const verdict = classifyServiceError(pending.kind, outcome.error);
    if (verdict.kind === "terminal" && build.state !== "CANCELLING") {
      let exec: ExecPlan | null = null;
      try {
        exec = await loadExecPlan(tx, build);
      } catch {
        exec = null;
      }
      await applyFailure(tx, build, verdict.failure, now, exec);
      return;
    }
    if (verdict.kind === "terminal") {
      await tx.sandboxTemplateBuild.update({
        where: { id: build.id },
        data: { pendingAction: PrismaNull(), nextAttemptAt: now },
      });
      return;
    }
    // Ambiguous or retryable: the same key replays after backoff; a thrown
    // error never raises `attempt`. A retryable refusal may name its blocker
    // (E1-A-07: a capture waiting for host disk or RAM), shown as the phase.
    await tx.sandboxTemplateBuild.update({
      where: { id: build.id },
      data: {
        ...(verdict.kind === "retryable" && verdict.phase ? { phase: verdict.phase } : {}),
        pendingAction: {
          ...pending,
          claimedUntil: now.getTime(),
          failures: pending.failures + 1,
        } as unknown as Prisma.InputJsonValue,
        nextAttemptAt: new Date(now.getTime() + retryBackoffMs(pending.failures)),
      },
    });
  });
}

/** Advance one build by at most one service call. */
export async function advanceTemplateBuild(
  candidate: { id: string; userId: string },
  clock: () => Date = () => new Date(),
): Promise<boolean> {
  try {
    return await advanceOnce(candidate, clock);
  } finally {
    notifyTemplateBuildProgress(candidate.id);
  }
}

async function advanceOnce(
  candidate: { id: string; userId: string },
  clock: () => Date,
): Promise<boolean> {
  const claim = await claimNext(candidate, clock());
  if (!claim) return false;
  if ("verifyFinish" in claim) {
    try {
      await finishVerify(candidate, claim.verifyFinish, clock());
    } catch (error) {
      // U4.2: a deadlock or serialization failure (prune and retention lock
      // several revisions in no fixed order) is retried next tick, never a
      // verify failure.
      if (!isRetryableTransactionError(error)) throw error;
      await prisma.sandboxTemplateBuild.updateMany({
        where: { id: candidate.id, userId: candidate.userId },
        data: { nextAttemptAt: new Date(clock().getTime() + retryBackoffMs(1)) },
      });
      return false;
    }
    return true;
  }
  const principal = await loadBuildPrincipal(prisma, claim.build.id, claim.build.userId);
  let outcome: { ok: true; result: ActionResult } | { ok: false; error: unknown };
  if (!principal) outcome = { ok: false, error: new BuildCallTimeout() };
  else
    try {
      outcome = {
        ok: true,
        result: await callWithDeadline(() => perform(principal, claim.build, claim.pending)),
      };
    } catch (error) {
      outcome = { ok: false, error };
    }
  await recordOutcome(claim, outcome, clock());
  return true;
}

/** PostgreSQL 40P01/40001 however Prisma wraps them (P2034); structured codes only. */
export function isRetryableTransactionError(error: unknown): boolean {
  const seen = new Set<unknown>();
  const visit = (value: unknown): boolean => {
    if (!value || typeof value !== "object" || seen.has(value)) return false;
    seen.add(value);
    const record = value as Record<string, unknown>;
    if (
      [record.code, record.sqlState, record.originalCode].some(
        (code) => code === "P2034" || code === "40P01" || code === "40001",
      )
    )
      return true;
    return [record.meta, record.cause, record.driverAdapterError].some(visit);
  };
  return visit(error);
}

/**
 * Settle a community verify (S9 `verify_finish`, T3, review4 U4) in its OWN
 * transaction, never inside a claim's. Lock order: owner admission → owner
 * placement → template → build → revision, the finalizer's and retire's.
 * Under the locks it re-checks everything: the build is still CAPTURING and
 * verifying, no cancel is recorded (cancel wins: the cancel path retires the
 * revision), the revision is live and still pending for this build, and the
 * template is not archived. No key re-check (D-N): a recorded smoke result
 * publishes as a recorded capture result does.
 */
export async function finishVerify(
  candidate: { id: string; userId: string },
  outcome: { pass: boolean; failure?: BuildFailure; revisionId: string },
  now: Date,
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    try {
      await lockOwnerForAdmission(tx, candidate.userId);
    } catch (error) {
      if (error instanceof AccountDeletionConflictError) return;
      throw error;
    }
    await lockOwnerPlacement(tx, candidate.userId);
    const head = await tx.sandboxTemplateBuild.findFirst({
      where: { id: candidate.id, userId: candidate.userId },
      select: { templateId: true },
    });
    if (!head) return;
    const [template] = await tx.$queryRaw<{ archivedAt: Date | null }[]>`
      SELECT "archivedAt" FROM sandbox_logical_template
      WHERE id = ${head.templateId} AND "userId" = ${candidate.userId} FOR UPDATE`;
    await tx.$queryRaw`SELECT id FROM sandbox_template_build WHERE id = ${candidate.id} AND "userId" = ${candidate.userId} FOR UPDATE`;
    await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE id = ${outcome.revisionId} AND "userId" = ${candidate.userId} FOR UPDATE`;
    const build = await tx.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: candidate.id },
      select: { ...buildSelect, cancelRequestedAt: true },
    });
    const revision = await tx.sandboxTemplateRevision.findFirst({
      where: { id: outcome.revisionId, userId: candidate.userId },
      select: { retiredAt: true, pendingVerifyBuildId: true, captureTag: true },
    });
    // Cancel wins over a pass that has not committed (U4.1): leave the build
    // to the cancel path, which retires the revision once the VM is gone.
    if (build.cancelRequestedAt !== null || build.state === "CANCELLING") return;
    if (build.state !== "CAPTURING" || !build.verifyRequired) return;
    const retire = () =>
      tx.sandboxTemplateRevision.updateMany({
        where: {
          id: outcome.revisionId,
          userId: candidate.userId,
          retiredAt: null,
          pendingVerifyBuildId: build.id,
        },
        data: { retiredAt: now, retiredReason: "verify_failed" },
      });
    const live =
      revision !== null &&
      revision.retiredAt === null &&
      revision.pendingVerifyBuildId === build.id &&
      template !== undefined &&
      template.archivedAt === null;
    if (!outcome.pass || !live) {
      await retire();
      const failure = outcome.failure ?? {
        errorCode: "build_verify_failed",
        errorDetail: revision?.retiredAt ? "revision_retired" : "template_archived",
      };
      await applyFailure(tx, build, failure, now, null);
      return;
    }
    // Pass: the revision becomes launchable, `latest` moves, retention runs
    // and the build ends SUCCEEDED, all in this transaction.
    await tx.sandboxTemplateRevision.update({
      where: { id: outcome.revisionId },
      data: { pendingVerifyBuildId: null },
    });
    await tx.$queryRaw`SELECT id FROM sandbox_template_tag WHERE "templateId" = ${build.templateId} AND "userId" = ${build.userId} ORDER BY id FOR UPDATE`;
    await tx.sandboxTemplateTag.upsert({
      where: { templateId_tag: { templateId: build.templateId, tag: build.tag } },
      create: {
        userId: build.userId,
        templateId: build.templateId,
        revisionId: outcome.revisionId,
        tag: build.tag,
      },
      update: { revisionId: outcome.revisionId },
    });
    const keep = await tx.sandboxTemplate.findFirstOrThrow({
      where: { id: build.templateId, userId: build.userId },
      select: { captureKeep: true },
    });
    await applyCaptureRetention(tx, {
      ownerId: build.userId,
      templateId: build.templateId,
      tag: revision?.captureTag ?? build.tag,
      keep: keep.captureKeep,
      now,
    });
    await tx.sandboxTemplateBuild.update({
      where: { id: build.id },
      data: {
        state: "SUCCEEDED",
        phase: null,
        revisionId: outcome.revisionId,
        completedAt: now,
        pendingAction: PrismaNull(),
        nextAttemptAt: now,
        ...settleMinutes(build, build.stoppedAt ?? now),
      },
    });
    // Waiting creates follow a refreshed tag (refresh-on-miss, §3.9).
    if (build.triggeredByRevisionId) noteCapacityChanged(tx);
  });
  notifyTemplateBuildsChanged();
}

const ACTIVE_FOR_SCAN: readonly TemplateBuildState[] = [
  "AWAITING_CONTEXT",
  "QUEUED",
  "PLACING",
  "RUNNING",
  "STOPPING",
  "CAPTURING",
  "CANCELLING",
];

/** The lock-free candidate scan (§3.3, r2 N4): no row lock is taken here. */
export async function scanTemplateBuildCandidates(now: Date, take = TEMPLATE_BUILD_TICK_BATCH) {
  return prisma.$queryRaw<{ id: string; userId: string }[]>`
    SELECT id, "userId" FROM sandbox_template_build
    WHERE state::text IN (${PrismaValue.join(ACTIVE_FOR_SCAN)})
      AND ("nextAttemptAt" IS NULL OR "nextAttemptAt" <= ${now})
    ORDER BY "nextAttemptAt" ASC NULLS FIRST, id
    LIMIT ${take}`;
}

/**
 * The cleanup invariant (§3.10), one pass: kill every live build VM whose
 * build is gone, cancelling, terminal or past its FINALIZED capture; abort
 * the unadopted context of ended builds; mark cleanup DONE when nothing of a
 * terminal build is left. Kills use the build principal's key-free cleanup
 * class with `tb:<buildId>:kill:0:<attempt>`, the attempt raised only when
 * the previous kill ended without effect.
 *
 * Both halves are bounded per pass (`batch`) and rotate with a keyset cursor
 * (`rotatingPage`), so rows that stay blocked cannot monopolize the pass.
 */
export type TemplateBuildCleanupCursors = { vms: CleanupCursor; contexts: CleanupCursor };
const cleanupCursors: TemplateBuildCleanupCursors = {
  vms: { after: null },
  contexts: { after: null },
};

export async function runTemplateBuildCleanup(
  now: Date = new Date(),
  options: { batch?: number; cursors?: TemplateBuildCleanupCursors } = {},
) {
  const batch = options.batch ?? TEMPLATE_BUILD_TICK_BATCH;
  const cursors = options.cursors ?? cleanupCursors;
  const candidates = await rotatingPage(cursors.vms, batch, (bounds) =>
    prisma.$queryRaw<
      {
        id: string;
        userId: string;
        buildId: string;
        state: string;
        liveBuildId: string | null;
        verify: boolean;
      }[]
    >(cleanupCandidatesSql(bounds)),
  );
  let killed = 0;
  for (const vm of candidates) {
    if (vm.liveBuildId === null) {
      // No build row (account deletion in progress, or a bug): account
      // deletion tears the sandbox down and the build lease (kill) bounds it.
      console.warn("[template-builds] A build VM has no build row; its lease will end it.");
      continue;
    }
    const principal = await loadBuildPrincipal(prisma, vm.buildId, vm.userId);
    if (!principal) continue;
    // A verify VM's kills live in their own key namespace (T2).
    const killAction = vm.verify ? "vkill" : "kill";
    const prior = await prisma.sandboxOperation.findFirst({
      where: {
        userId: vm.userId,
        sandboxId: vm.id,
        kind: "KILL_SANDBOX",
        idempotencyKey: { startsWith: `tb:${vm.buildId}:${killAction}:` },
      },
      orderBy: { createdAt: "desc" },
      select: { state: true, idempotencyKey: true },
    });
    if (prior && !["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(prior.state))
      continue;
    const attempt = prior ? (buildKeyAttempt(prior.idempotencyKey) ?? 0) + 1 : 0;
    try {
      await callWithDeadline(() =>
        killSandbox(principal, {
          id: vm.id,
          idempotencyKey: buildActionKey(vm.buildId, killAction, 0, attempt),
        }),
      );
      killed++;
    } catch (error) {
      console.warn(
        "[template-builds] Build VM cleanup kill refused:",
        error instanceof Error ? error.name : "error",
      );
    }
  }
  const ended = await rotatingPage(cursors.contexts, batch, ({ after, upTo, take }) =>
    prisma.sandboxTemplateBuild.findMany({
      where: {
        state: { in: [...TERMINAL_BUILD_STATES] },
        cleanupState: "PENDING",
        ...(after === null && upTo === null
          ? {}
          : {
              id: {
                ...(after === null ? {} : { gt: after }),
                ...(upTo === null ? {} : { lte: upTo }),
              },
            }),
      },
      select: { id: true, userId: true },
      orderBy: { id: "asc" },
      take,
    }),
  );
  let done = 0;
  for (const build of ended) {
    const context = await prisma.sandboxBuildContext.findFirst({
      where: { buildId: build.id, userId: build.userId },
      select: { state: true },
    });
    let contextLive = context?.state === "OPEN" || context?.state === "SEALED";
    if (contextLive) {
      const principal = await loadBuildPrincipal(prisma, build.id, build.userId);
      if (principal)
        try {
          await callWithDeadline(() => buildContextPort().abortContext(principal, build.id));
          contextLive = false;
        } catch {
          // Unbound port (worker) or a busy context: next pass.
        }
    }
    if (contextLive) continue;
    // A build is not DONE while its build VM or its verify VM lives.
    const live = await prisma.sandbox.count({
      where: {
        userId: build.userId,
        OR: [{ buildId: build.id }, { verifyBuildId: build.id }],
        state: { not: "DELETED" },
      },
    });
    if (live > 0) continue;
    const marked = await prisma.sandboxTemplateBuild.updateMany({
      where: { id: build.id, userId: build.userId, cleanupState: "PENDING" },
      data: { cleanupState: "DONE", cleanupDoneAt: now },
    });
    done += marked.count;
  }
  return { killed, done };
}

/** One orchestrator tick: advance up to 32 builds, then the cleanup pass. */
export async function runTemplateBuildTick(
  clock: () => Date = () => new Date(),
  shouldStop: () => boolean = () => false,
) {
  let advanced = 0;
  for (const candidate of await scanTemplateBuildCandidates(clock())) {
    if (shouldStop()) break;
    try {
      // Each build may make several quick transitions; bounded per tick.
      for (let i = 0; i < 4 && (await advanceTemplateBuild(candidate, clock)); i++) advanced++;
    } catch (error) {
      console.warn(
        "[template-builds] Advancing a build failed; it is retried next tick:",
        error instanceof Error ? error.name : "error",
      );
    }
  }
  const cleanup = shouldStop() ? { killed: 0, done: 0 } : await runTemplateBuildCleanup(clock());
  return { advanced, ...cleanup };
}

/** Coalescing scheduler: a wake during a tick runs one more tick after it;
 * wakes closer than `minGapMs` are merged; the sweep runs every 15 s. The tick
 * is told to stop between builds once `stop()` is called, and `stop()` resolves
 * when the in-flight tick (if any) has returned. */
export class TemplateBuildScheduler {
  private running = false;
  private inflight: Promise<void> = Promise.resolve();
  private again = false;
  private stopped = false;
  private timer: ReturnType<typeof setInterval>;
  private last = 0;
  private gap: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly tick: (shouldStop: () => boolean) => Promise<unknown> = (shouldStop) =>
      runTemplateBuildTick(undefined, shouldStop),
    private readonly minGapMs = 1_000,
  ) {
    this.timer = setInterval(() => this.wake(), TEMPLATE_BUILD_SWEEP_MS);
  }

  wake(): void {
    if (this.stopped) return;
    if (this.running) {
      this.again = true;
      return;
    }
    const wait = this.last + this.minGapMs - Date.now();
    if (wait > 0) {
      this.gap ??= setTimeout(() => {
        this.gap = null;
        this.wake();
      }, wait);
      return;
    }
    this.inflight = this.run();
  }

  private async run() {
    this.running = true;
    this.last = Date.now();
    try {
      await this.tick(() => this.stopped);
    } catch (error) {
      console.error(
        "[template-builds] Orchestrator tick failed:",
        error instanceof Error ? error.name : "error",
      );
    } finally {
      this.running = false;
      if (this.again && !this.stopped) {
        this.again = false;
        this.wake();
      }
    }
  }

  /** Idempotent. Resolves once no tick is running; never rejects. */
  stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    if (this.gap) clearTimeout(this.gap);
    this.gap = null;
    return this.running ? this.inflight : Promise.resolve();
  }
}

/** Server start: the tick runs where the context port is bound (§3.6). The
 * startup signal stops scheduling; `stop()` also waits for the in-flight tick,
 * so shutdown can close the context store and the database after it. */
export function startTemplateBuildOrchestrator(signal: AbortSignal): {
  wake: () => void;
  stop: () => Promise<void>;
} {
  const scheduler = new TemplateBuildScheduler();
  const wake = () => scheduler.wake();
  bindTemplateBuildWake(wake);
  bindBuildContextWake(wake);
  bindOperationChangeBuildWake(wake);
  // The daily community refresh accepts builds, so it runs here, on the server.
  const communityRefresh = startCommunityRefreshSchedule();
  const stop = async () => {
    bindTemplateBuildWake(null);
    bindBuildContextWake(null);
    bindOperationChangeBuildWake(null);
    await Promise.all([communityRefresh.stop(), scheduler.stop()]);
  };
  signal.addEventListener("abort", () => void stop(), { once: true });
  scheduler.wake();
  return { wake, stop };
}

export { buildVmMustDie };
