import { isDeepStrictEqual } from "node:util";
import {
  activateLoginLease,
  applyInstalledReceipt,
  credentialAttachReady,
  credentialLaunchReady,
  destroySavedLoginSandbox,
  freeSpecSkips,
  ownsReleasingLease,
  rebindPlacementAfterRearm,
  settleCredentialsOnDeleted,
  settleOperationCredentials,
  teardownOutcomesFromResult,
  withoutCredentialReceipts,
} from "@wssp/api/credentials/relay";
import {
  appendCommandOutput,
  appendCommandOutputBatch,
  isCommandOutputExpired,
  sealCommandOutput,
} from "@wssp/api/sandbox/command-output";
import { relayDispatchKind } from "@wssp/api/sandbox/contracts";
import { consumeOffloadAtReady } from "@wssp/api/sandbox/disk-offload/consume";
import { endOffloadForDestroy } from "@wssp/api/sandbox/disk-offload/destroy";
import { settleSystemDetachKill } from "@wssp/api/sandbox/disk-offload/restore-exit";
import {
  noteHostBlockerReleased,
  releaseLiveResourcesIfHeld,
} from "@wssp/api/sandbox/host-admission";
import { requestDigestKeyCurrent } from "@wssp/api/sandbox/idempotency";
import { recordCaptureResult } from "@wssp/api/sandbox/image-store/capture-result";
import { droppedCaptureImageToRelease } from "@wssp/api/sandbox/image-store/references";
import { isRestoreAttempt, restoreOffloadOf } from "@wssp/api/sandbox/launch-mode";
import {
  finalizeExpiredSandboxLifecycleOperation,
  isLeaseDeadlinePassed,
  isNeverReadyRootOnly,
  type LeaseClock,
  leaseNow,
  leaseTransactionNow,
  queueFailedTeardownRetry,
  queueNeverReadyStopCleanup,
} from "@wssp/api/sandbox/lease";
import {
  fromReadyDeadlineAcceptable,
  LEASE_DISPATCH_KINDS,
  leaseWireSchema,
} from "@wssp/api/sandbox/lease-wire";
import {
  isContentResultKind,
  publishOperationResult,
  storeScalarOperationResult,
} from "@wssp/api/sandbox/operation-results";
import { notifySandboxDispatchPending } from "@wssp/api/sandbox/outbox";
import { outboxOperationSql, outboxOperationWhere } from "@wssp/api/sandbox/outbox-operation";
import {
  casActiveOperation,
  casSandboxGeneration,
  hostDatabaseNow,
  lockHostByEpoch,
  operationActiveFenceWhere,
  RECORDED_CAPTURE_WHERE,
  RelayFencePending,
  relayTransaction,
  requireObserved,
  requireRelayFence,
  requireRelayReceiptWorkload,
  requireRelayWorkload,
  requireResultCompatible,
  sandboxStatesForOperation,
  settleSupersededOperations,
} from "@wssp/api/sandbox/relay-fence";
import { noteTerminalResultRelease } from "@wssp/api/sandbox/result-finalization";
import { safeOperationError } from "@wssp/api/sandbox/sensitive-errors";
import {
  canTransitionLifecycleResult,
  canTransitionSandboxState,
  isLifecycleOperationKind,
  sandboxStateForLifecycleResult,
} from "@wssp/api/sandbox/state-transitions";
import type { OperationState, Prisma, SandboxOperationKind, SandboxState } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  capacityReasonSchema,
  isResultKind,
  OUTPUT_RETENTION_MS,
  operationResultSchema,
  readinessFailureReasonSchema,
} from "@wssp/sandbox-contracts";
import { CaptureRefused, relayCaptures } from "../sandbox-transfers/captures.js";
import { commandOutputChunk } from "./command-output.js";
import { intentReclaimGates } from "./dispatch-gates.js";
import { createResultDeniedGrants, daemonEgressRefusal } from "./egress-refusal.js";
import type { SandboxErrorCode } from "./protocol.js";
import {
  commandResultMetadataSchema,
  hostOperationResultSchema,
  processStartedSchema,
  type StreamBinaryMetadata,
} from "./protocol.js";

const prismaOperationState: Record<string, OperationState> = {
  queued: "QUEUED",
  dispatched: "DISPATCHED",
  accepted: "ACCEPTED",
  running: "RUNNING",
  cancel_requested: "CANCEL_REQUESTED",
  succeeded: "SUCCEEDED",
  failed: "FAILED",
  cancelled: "CANCELLED",
  unknown_outcome: "UNKNOWN_OUTCOME",
};

const TERMINAL_OPERATION_STATES: ReadonlySet<OperationState> = new Set([
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
]);

function isCapacityReason(
  value: string,
): value is import("@wssp/sandbox-contracts").CapacityReason {
  return capacityReasonSchema.safeParse(value).success;
}

const PROGRESS_OPERATION_STATES: ReadonlySet<OperationState> = new Set(["ACCEPTED", "RUNNING"]);

/**
 * `guestGroupSignals` of a ready create/reconnect result: whether the guest
 * delivers TERM/INT/HUP to a process group, as the host's signal helper
 * probed it. Anything but a boolean is unobserved (null).
 */
export function readyResultGroupSignals(
  result: Record<string, unknown> | null | undefined,
): boolean | null {
  const value = result?.guestGroupSignals;
  return typeof value === "boolean" ? value : null;
}

/** Wakes the capture finalizer after a host result commits (bound at startup). */
let captureResultListener: (() => void) | null = null;
export function bindCaptureResultListener(listener: (() => void) | null): void {
  captureResultListener = listener;
}
function notifyCaptureResult() {
  queueMicrotask(() => captureResultListener?.());
}

export type RelaySender = {
  userId: string;
  hostId: string;
  connectionEpoch: number;
  isCurrent?: () => boolean;
};

export type FencedRelayInput = {
  sender: RelaySender;
  sandboxOwnerId?: string;
  workloadOwnerId?: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  attempt: number;
  receipt?: { bodyHash: string; idempotencyKey: string; kind: string };
};

function workloadOwner(input: { sender: RelaySender; workloadOwnerId?: string }): string {
  requireRelayFence(input.workloadOwnerId !== undefined);
  return input.workloadOwnerId;
}
async function bindInboundWorkload(
  tx: Prisma.TransactionClient,
  input: {
    sender: RelaySender;
    sandboxId?: string;
    operationId: string;
    sandboxOwnerId?: string;
    workloadOwnerId?: string;
  },
  fence: (
    tx: Prisma.TransactionClient,
    transport: RelaySender,
    target: { sandboxId?: string; operationId: string; sandboxOwnerId?: string },
  ) => Promise<{ sandboxOwnerId: string }> = requireRelayWorkload,
) {
  const binding = await fence(tx, input.sender, input);
  input.workloadOwnerId = binding.sandboxOwnerId;
  for (const id of [...new Set([binding.sandboxOwnerId, input.sender.userId])].sort())
    await lockOwnerForAdmission(tx, id);
}

function fenceArgs(input: FencedRelayInput) {
  return {
    operationId: input.operationId,
    sandboxId: input.sandboxId,
    userId: workloadOwner(input),
    generation: input.generation,
    attempt: input.attempt,
    hostId: input.sender.hostId,
  };
}

function inboundOperationWhere(
  input: Omit<FencedRelayInput, "sandboxId"> & { sandboxId?: string },
  commandOutput = false,
  identity = false,
) {
  const where = operationActiveFenceWhere({
    operationId: input.operationId,
    sandboxId: input.sandboxId,
    userId: workloadOwner(input),
    hostId: input.sender.hostId,
    generation: input.generation,
    attempt: input.attempt,
  });
  // Only an exact host receipt may resolve a previously uncertain outcome.
  // Output may continue under its exact dispatch binding after an interim UNKNOWN
  // (one without a completion watermark; appendCommandOutput refuses sealed output).
  // This mode cannot resolve outcomes or authorize a different operation kind.
  if (commandOutput) where.kind = "RUN_COMMAND";
  if (input.receipt || commandOutput || identity)
    where.state = {
      in: ["DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED", "UNKNOWN_OUTCOME"],
    };
  if (identity)
    where.state = {
      in: [
        "DISPATCHED",
        "ACCEPTED",
        "RUNNING",
        "CANCEL_REQUESTED",
        "UNKNOWN_OUTCOME",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
      ],
    };
  return where;
}
async function casInboundOperation(
  tx: Prisma.TransactionClient,
  input: FencedRelayInput,
  data: Prisma.SandboxOperationUpdateManyMutationInput,
  commandOutput = false,
) {
  const written = await tx.sandboxOperation.updateMany({
    where: inboundOperationWhere(input, commandOutput),
    data,
  });
  requireRelayFence(written.count === 1);
}

async function acquireInboundFence(
  tx: Prisma.TransactionClient,
  input: Omit<FencedRelayInput, "sandboxId"> & { sandboxId?: string },
  commandOutput = false,
  identity = false,
) {
  await bindInboundWorkload(tx, input);
  await lockHostByEpoch(tx, input.sender.hostId, input.sender.connectionEpoch, input.sender.userId);
  // This read only locates immutable identity. Cancellation does not take H,
  // so operation state must be read again after acquiring S.
  const located = await tx.sandboxOperation.findFirst({
    where: inboundOperationWhere(input, commandOutput, identity),
    select: { sandboxId: true, kind: true, launchMode: true },
  });
  requireRelayFence(located != null);
  await casSandboxGeneration(tx, {
    sandboxId: located.sandboxId,
    userId: workloadOwner(input),
    generation: input.generation,
    hostId: input.sender.hostId,
    states: sandboxStatesForOperation(located),
  });
  await requireRelayWorkload(tx, input.sender, input);
  await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${workloadOwner(input)} FOR UPDATE`;
  const operation = await tx.sandboxOperation.findFirst({
    where: inboundOperationWhere(input, commandOutput, identity),
    select: {
      id: true,
      userId: true,
      dispatchAttempt: true,
      dispatchedHostId: true,
      kind: true,
      state: true,
      sandboxId: true,
      generation: true,
      requestBodyHash: true,
      requestDigestScheme: true,
      requestDigestKeyId: true,
      idempotencyKey: true,
      dispatchedConnectionEpoch: true,
      completedAt: true,
      leaseRevisionAccepted: true,
      leaseExpiresAtAccepted: true,
      leaseExpireActionAccepted: true,
      leaseAcceptedAt: true,
      leaseFromReady: true,
      authorizingKeyId: true,
      resultVersion: true,
      resultExpiresAt: true,
      scalarResult: true,
      processId: true,
      processPid: true,
      processStartedAt: true,
      processBootId: true,
      processStartTicks: true,
      teardownPriorState: true,
      teardownIntent: true,
      launchMode: true,
      restoreOffloadId: true,
    },
  });
  requireRelayFence(operation != null);
  if (input.receipt) {
    requireRelayFence(
      operation.dispatchedConnectionEpoch != null &&
        operation.dispatchedConnectionEpoch <= input.sender.connectionEpoch &&
        requestDigestKeyCurrent(operation) &&
        operation.requestBodyHash === input.receipt.bodyHash &&
        operation.idempotencyKey === input.receipt.idempotencyKey &&
        relayDispatchKind(operation.kind) === input.receipt.kind,
    );
  } else {
    requireRelayFence(operation.dispatchedConnectionEpoch === input.sender.connectionEpoch);
  }
  requireRelayFence(input.sender.isCurrent?.() !== false);
  return { ...operation, dispatchedConnectionEpoch: input.sender.connectionEpoch };
}

/** O is already held. Preclaim before quota/transfer/output children, including
 * failure paths, so retiring a refused capture never seeks an earlier outbox. */
async function prelockOperationOutbox(
  tx: Prisma.TransactionClient,
  userId: string,
  sandboxId: string,
  operationId: string,
): Promise<void> {
  await tx.$queryRaw`SELECT id FROM sandbox_dispatch_outbox
    WHERE "userId" = ${userId} AND "aggregateType" = 'sandbox' AND "aggregateId" = ${sandboxId}
      AND "processedAt" IS NULL AND ${outboxOperationSql(operationId)}
    ORDER BY id FOR UPDATE`;
}

/** Admit bytes while all three rows are fenced; they are visible and ACKed only
 * after commit. Command output is durable (C26); file bytes are captured into
 * the C27 transfer store (persistent metadata, shared reservation and expiry). */
export async function acceptFencedBinaryChunk(input: {
  sender: RelaySender;
  operationId: string;
  generation: number;
  attempt: number;
  sequence: number;
  offset?: number;
  ended: boolean;
  body: Uint8Array;
  output?: StreamBinaryMetadata;
  /** Output chunk ceiling negotiated on the sending connection (D3b). */
  outputChunkBytes?: number;
}): Promise<boolean> {
  const publish = await relayTransaction(async (tx) => {
    const operation = await acquireInboundFence(tx, input, input.output !== undefined);
    requireRelayFence(operation.kind === (input.output ? "RUN_COMMAND" : "GET_FILE"));
    // A long-lived interim UNKNOWN cannot resurrect output past its retention.
    requireRelayFence(!input.output || !isCommandOutputExpired(operation.completedAt, new Date()));
    await casInboundOperation(
      tx,
      { ...input, sandboxId: operation.sandboxId },
      {
        dispatchAttempt: input.attempt,
      },
      input.output !== undefined,
    );
    await prelockOperationOutbox(tx, workloadOwner(input), operation.sandboxId, input.operationId);
    if (input.output) {
      // O is locked above; a sealed watermark (final result, including a final
      // UNKNOWN) is a fence rejection, so committed output never reopens.
      await appendCommandOutput(tx, {
        ...commandOutputChunk(input.output, input.body, input.outputChunkBytes),
        operationId: input.operationId,
        attempt: input.attempt,
      });
      requireRelayFence(input.sender.isCurrent?.() !== false);
      return async () => undefined;
    }
    let staged: (() => Promise<void>) | null;
    try {
      staged = await relayCaptures().admitCapture(
        tx,
        {
          userId: workloadOwner(input),
          keyId: operation.authorizingKeyId,
          sandboxId: operation.sandboxId,
          generation: operation.generation,
          guestPath: input.sequence === 0 ? await operationGuestPath(tx, input, operation) : "",
        },
        {
          operationId: input.operationId,
          attempt: input.attempt,
          sequence: input.sequence,
          offset: input.offset ?? -1,
          body: input.body,
          ended: input.ended,
        },
      );
    } catch (error) {
      if (!(error instanceof CaptureRefused)) throw error;
      noteHostBlockerReleased(tx, input.sender.hostId, input.sender.userId);
      await casInboundOperation(
        tx,
        { ...input, sandboxId: operation.sandboxId },
        {
          state: "FAILED",
          // Retention stays anchored to the first completion, if any (C26).
          completedAt: operation.completedAt ?? new Date(),
          errorCode: error.code,
          errorDetail: safeOperationError(error.code).message,
        },
      );
      await tx.outboxEvent.updateMany({
        where: {
          userId: workloadOwner(input),
          aggregateType: "sandbox",
          aggregateId: operation.sandboxId,
          ...outboxOperationWhere(input.operationId),
          processedAt: null,
        },
        data: { processedAt: new Date() },
      });
      requireRelayFence(input.sender.isCurrent?.() !== false);
      return () => relayCaptures().discardCapture(input.operationId, input.attempt);
    }
    requireRelayFence(input.sender.isCurrent?.() !== false);
    // An identical replay of a committed chunk is re-ACKed without disk IO.
    return staged ?? (async () => undefined);
  }, null);
  if (!publish || input.sender.isCurrent?.() === false) return false;
  try {
    await publish();
  } catch {
    // Not ACKed. The store retired an IO-failed capture (a retried frame then
    // fails the operation) or kept its committed tail (a retry resumes it).
    return false;
  }
  return true;
}

/** One command-output frame of a relay batch (D3b). */
export type FencedOutputFrame = { metadata: StreamBinaryMetadata; body: Uint8Array };

/**
 * D3b: consecutive output chunks of one operation attempt from one connection,
 * admitted in ONE transaction. The fence is exactly `acceptFencedBinaryChunk`'s
 * (owner/H → S → O → outbox), taken once; every chunk then passes the
 * per-chunk checks in order (`appendCommandOutputBatch`). The connection's
 * cached authority ticket (`current`) and its registration must still hold at
 * commit. Returns true when the whole batch committed; the caller ACKs each
 * chunk while the connection is still current. False or a throw means nothing
 * was written: the caller replays
 * the chunks one at a time, which reproduces the per-chunk refusals, protocol
 * errors and partial progress exactly.
 */
export async function acceptFencedOutputBatch(input: {
  sender: RelaySender;
  operationId: string;
  generation: number;
  attempt: number;
  frames: readonly FencedOutputFrame[];
  outputChunkBytes?: number;
  current: () => boolean;
}): Promise<boolean> {
  const { sender, operationId, generation, attempt, frames } = input;
  if (
    frames.length === 0 ||
    frames.some(
      ({ metadata }) =>
        metadata.operationId !== operationId ||
        metadata.generation !== generation ||
        metadata.attempt !== attempt,
    )
  )
    return false;
  // `bindInboundWorkload` records the workload owner on this object.
  const fenced: Omit<FencedRelayInput, "sandboxId"> = {
    sender,
    operationId,
    generation,
    attempt,
  };
  const committed = await relayTransaction(async (tx) => {
    const operation = await acquireInboundFence(tx, fenced, true);
    requireRelayFence(operation.kind === "RUN_COMMAND");
    requireRelayFence(!isCommandOutputExpired(operation.completedAt, new Date()));
    await casInboundOperation(
      tx,
      { ...fenced, sandboxId: operation.sandboxId },
      { dispatchAttempt: attempt },
      true,
    );
    await prelockOperationOutbox(tx, workloadOwner(fenced), operation.sandboxId, operationId);
    await appendCommandOutputBatch(
      tx,
      frames.map(({ metadata, body }) => ({
        ...commandOutputChunk(metadata, body, input.outputChunkBytes),
        operationId,
        attempt,
      })),
    );
    requireRelayFence(sender.isCurrent?.() !== false && input.current());
    return true;
  }, false);
  // Committed means written: never replayed. The caller ACKs only while the
  // connection is still current, as `acceptFencedBinaryChunk` does.
  return committed;
}

/** The guest path recorded with the operation's dispatch (never a host path). */
async function operationGuestPath(
  tx: Prisma.TransactionClient,
  input: { operationId: string; sender: RelaySender; workloadOwnerId?: string },
  operation: { sandboxId: string },
) {
  const event = await tx.outboxEvent.findFirst({
    where: {
      userId: workloadOwner(input),
      aggregateType: "sandbox",
      aggregateId: operation.sandboxId,
      ...outboxOperationWhere(input.operationId),
    },
    select: { payload: true },
  });
  const payload = event?.payload as { path?: unknown } | null | undefined;
  return typeof payload?.path === "string" ? payload.path : "";
}

export async function applyOperationProgress(
  input: FencedRelayInput & {
    state: string;
    progress?: { phase: string; bytesDone?: number; bytesTotal?: number };
  },
): Promise<{ written: boolean }> {
  const opState = prismaOperationState[input.state];
  if (!opState || !PROGRESS_OPERATION_STATES.has(opState)) {
    return { written: false };
  }
  return relayTransaction<{ written: boolean }>(
    async (tx) => {
      const operation = await acquireInboundFence(tx, input);
      requireRelayFence(
        operation.state === "DISPATCHED" ||
          operation.state === "ACCEPTED" ||
          operation.state === "CANCEL_REQUESTED" ||
          (opState === "RUNNING" && operation.state === "RUNNING"),
      );
      const written = await tx.sandboxOperation.updateMany({
        where: {
          ...operationActiveFenceWhere(fenceArgs(input)),
          state: operation.state,
        },
        data: {
          state: operation.state === "CANCEL_REQUESTED" ? "CANCEL_REQUESTED" : opState,
          acceptedAttempt: input.attempt,
          ...(input.progress
            ? {
                progressPhase: input.progress.phase,
                progressBytesDone:
                  input.progress.bytesDone !== undefined ? BigInt(input.progress.bytesDone) : null,
                progressBytesTotal:
                  input.progress.bytesTotal !== undefined
                    ? BigInt(input.progress.bytesTotal)
                    : null,
                progressAt: new Date(),
              }
            : {}),
        },
      });
      requireRelayFence(written.count === 1);
      await tx.outboxEvent.updateMany({
        where: {
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          userId: workloadOwner(input),
          processedAt: null,
          AND: [
            outboxOperationWhere(input.operationId),
            { payload: { path: ["kind"], equals: relayDispatchKind(operation.kind) } },
          ],
        },
        data: { processedAt: new Date() },
      });
      requireRelayFence(input.sender.isCurrent?.() !== false);
      return { written: true };
    },
    { written: false },
  );
}

type InboundOperation = Awaited<ReturnType<typeof acquireInboundFence>>;
type Birth = import("zod").infer<typeof processStartedSchema>;
function decodeTypedResult(
  input: FencedRelayInput & { result?: Record<string, unknown> },
  op: InboundOperation,
  state: OperationState,
) {
  requireResultCompatible(isResultKind(op.kind));
  const parsed = hostOperationResultSchema.safeParse(input.result);
  // Failed-before-issue may have no result at all, but never a fictional success.
  if (!input.result && state !== "SUCCEEDED") return null;
  requireResultCompatible(parsed.success);
  const value = parsed.data;
  const command = value.payload?.type === "command";
  requireResultCompatible(
    !value.resultExpired ||
      (isContentResultKind(op.kind) && value.payload === null && value.continuation === null),
  );
  requireResultCompatible(
    state !== "SUCCEEDED" || value.payload !== null || value.resultExpired === true,
  );
  requireResultCompatible(value.payload === null || state === "SUCCEEDED" || command);
  requireResultCompatible(
    value.continuation === null ||
      value.payload?.type === "file.list" ||
      value.payload?.type === "process.list",
  );
  requireResultCompatible(value.outputBytes === undefined || op.kind === "RUN_COMMAND");
  if (value.payload?.type === "command")
    requireResultCompatible(
      value.birth !== null &&
        isDeepStrictEqual(value.payload.process, {
          sandboxId: value.birth.sandboxId,
          generation: value.birth.generation,
          attempt: value.birth.attempt,
          processId: value.birth.processId,
          pid: value.birth.pid,
        }) &&
        value.payload.startedAt === value.birth.startedAt,
    );
  if (value.birth) requireResultCompatible(op.kind === "RUN_COMMAND");
  if (value.failure)
    requireResultCompatible(
      state !== "SUCCEEDED" &&
        value.failure.resource ===
          (op.kind === "RUN_COMMAND"
            ? "command"
            : op.kind === "SIGNAL_PROCESS" || op.kind === "LIST_PROCESSES"
              ? "process"
              : "filesystem") &&
        (state !== "UNKNOWN_OUTCOME" || value.failure.effect === "unknown"),
    );
  if (value.payload)
    requireResultCompatible(
      operationResultSchema.safeParse({
        operationId: op.id,
        sandboxId: op.sandboxId,
        generation: op.generation,
        kind: op.kind,
        outcome: command ? "pending" : "succeeded",
        observedAt: value.observedAt,
        expiresAt: op.resultExpiresAt?.toISOString() ?? null,
        result: value.payload,
      }).success,
    );
  return value;
}
async function bindProcessBirth(
  tx: Prisma.TransactionClient,
  input: FencedRelayInput,
  op: InboundOperation,
  birth: Birth,
) {
  requireResultCompatible(
    op.kind === "RUN_COMMAND" &&
      op.resultVersion === 1 &&
      op.processId === birth.processId &&
      birth.operationId === input.operationId &&
      birth.sandboxId === input.sandboxId &&
      birth.generation === input.generation &&
      birth.attempt === input.attempt,
  );
  // Terminal evidence may repeat an existing birth, but cannot invent a late
  // incarnation after an authoritative no-birth completion. Shared by live and
  // receipt ingress; UNKNOWN/CANCEL_REQUESTED remain eligible for late birth.
  requireRelayFence(
    !["SUCCEEDED", "FAILED", "CANCELLED"].includes(op.state) || op.processPid !== null,
  );
  // A bound birth is immutable evidence; another incarnation never applies.
  if (op.processPid !== null)
    requireResultCompatible(
      op.processPid === birth.pid &&
        op.processBootId === birth.bootId &&
        op.processStartTicks === birth.startTicks &&
        op.processStartedAt?.getTime() === new Date(birth.startedAt).getTime(),
    );
  const updated = await tx.sandboxOperation.updateMany({
    where: {
      id: op.id,
      userId: workloadOwner(input),
      generation: input.generation,
      dispatchAttempt: input.attempt,
      processId: birth.processId,
      processPid: op.processPid,
    },
    data: {
      processPid: birth.pid,
      processBootId: birth.bootId,
      processStartTicks: birth.startTicks,
      processStartedAt: new Date(birth.startedAt),
    },
  });
  requireRelayFence(updated.count === 1);
}
/** Best-effort identity only. Interim/terminal state is never promoted. */
export async function applyProcessStarted(input: {
  sender: RelaySender;
  birth: unknown;
}): Promise<{ written: boolean }> {
  const parsed = processStartedSchema.safeParse(input.birth);
  if (!parsed.success) return { written: false };
  const birth = parsed.data;
  const fenced = { sender: input.sender, ...birth };
  return relayTransaction<{ written: boolean }>(
    async (tx) => {
      const op = await acquireInboundFence(tx, fenced, false, true);
      await bindProcessBirth(tx, fenced, op, birth);
      await storeScalarOperationResult(tx, {
        ownerId: op.userId,
        operationId: birth.operationId,
        sender: input.sender,
        attempt: birth.attempt,
        observedAt: new Date(birth.observedAt),
        payload: {
          type: "command",
          process: {
            sandboxId: birth.sandboxId,
            generation: birth.generation,
            processId: birth.processId,
            attempt: birth.attempt,
            pid: birth.pid,
          },
          startedAt: birth.startedAt,
          exitCode:
            op.scalarResult &&
            typeof op.scalarResult === "object" &&
            !Array.isArray(op.scalarResult) &&
            "exitCode" in op.scalarResult
              ? op.scalarResult.exitCode
              : null,
        },
      });
      requireRelayFence(input.sender.isCurrent?.() !== false);
      return { written: true };
    },
    { written: false },
  );
}

/** WP6: highest attempt a `file.put` proven not issued may be requeued to
 * (at most 3 requeues per operation, counted on the operation row). */
export const FILE_PUT_REQUEUE_MAX_ATTEMPT = 4;

/** Receipt confirmation of an attempt settled by a requeue (see below). */
type RequeueConfirmation = {
  type: "receipt.confirmed";
  sandboxOwnerId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  attempt: number;
  bodyHash: string;
  idempotencyKey: string;
  kind: string;
};

/** The operation's dispatch intent becomes claimable afresh (attempt + 1); an
 * old sender's finalizer (matching its claim token and send epoch) can no
 * longer retire it. Outbox rows are already held (`prelockOperationOutbox`). */
async function reopenDispatchIntent(
  tx: Prisma.TransactionClient,
  input: { ownerId: string; sandboxId: string; operationId: string; kind: string },
) {
  await tx.outboxEvent.updateMany({
    where: {
      userId: input.ownerId,
      aggregateType: "sandbox",
      aggregateId: input.sandboxId,
      processedAt: null,
      AND: [
        outboxOperationWhere(input.operationId),
        { payload: { path: ["kind"], equals: input.kind } },
      ],
    },
    data: { sentAt: null, claimToken: null, claimedAt: null, sentConnectionEpoch: null },
  });
}

/**
 * WP6 step 1: a `file.put` the host proved it never issued is dispatched again
 * as attempt + 1 instead of settling FAILED, while its source is still
 * retained in the durable transfer spool and the operation is under its own
 * requeue cap. Runs in the result transaction after the inbound fence (owner →
 * H → S → O), then outbox, then the transfer row (the commit's order). Returns
 * the receipt confirmation for the settled attempt, or null to settle as before.
 *
 * The confirmation is built here, in the same transaction, because the host
 * must drop its receipt for this attempt before attempt + 1 reaches it (a
 * retained receipt would be replayed for the new dispatch). The caller sends
 * it before yielding to IO, so it precedes any claim of the reopened intent.
 */
async function requeueUnissuedFilePut(
  tx: Prisma.TransactionClient,
  input: FencedRelayInput,
  operation: {
    id: string;
    kind: SandboxOperationKind;
    state: OperationState;
    requestBodyHash: string;
    idempotencyKey: string;
  },
  now: Date,
): Promise<RequeueConfirmation | null> {
  const ownerId = workloadOwner(input);
  await prelockOperationOutbox(tx, ownerId, input.sandboxId, input.operationId);
  const [source] = await tx.$queryRaw<
    {
      state: string;
      reservationHeld: boolean;
      sha256: string | null;
      idleExpiresAt: Date;
      expiresAt: Date;
      generation: number;
    }[]
  >`SELECT state, "reservationHeld", sha256, "idleExpiresAt", "expiresAt", generation
    FROM sandbox_stream_transfer
    WHERE "operationId" = ${input.operationId} AND "userId" = ${ownerId}
      AND "sandboxId" = ${input.sandboxId} AND direction = 'UPLOAD'
    FOR SHARE`;
  const retained =
    source != null &&
    source.state === "SEALED" &&
    source.reservationHeld &&
    source.sha256 != null &&
    source.generation === input.generation &&
    source.idleExpiresAt > now &&
    source.expiresAt > now;
  if (!retained) return null;
  const kind = relayDispatchKind(operation.kind);
  requireRelayFence(kind === "file.put");
  await casInboundOperation(tx, input, { state: "QUEUED" });
  await reopenDispatchIntent(tx, {
    ownerId,
    sandboxId: input.sandboxId,
    operationId: input.operationId,
    kind,
  });
  requireRelayFence(input.sender.isCurrent?.() !== false);
  return {
    type: "receipt.confirmed",
    sandboxOwnerId: ownerId,
    operationId: input.operationId,
    sandboxId: input.sandboxId,
    generation: input.generation,
    attempt: input.attempt,
    bodyHash: operation.requestBodyHash,
    idempotencyKey: operation.idempotencyKey,
    kind,
  };
}

type ResultInput = FencedRelayInput & {
  state: string;
  error?: {
    code: SandboxErrorCode;
    message: string;
    reason?:
      | import("@wssp/sandbox-contracts").CapacityReason
      | import("@wssp/sandbox-contracts").EgressRefusalReason
      | import("@wssp/sandbox-contracts").ReadinessFailureReason;
  };
  result?: Record<string, unknown>;
  /** Server-internal, never from the wire: this is the server's verdict for
   * an exact receipt it could not apply, not host evidence. */
  verdict?: true;
};
type ResultOutcome = {
  written: boolean;
  allocationUnknown?: boolean;
  /** Send `image.release` (reason `gc`) for this dropped capture's image. */
  releaseImage?: { imageOwnerId: string; fingerprint: string };
  /** WP6: the attempt was requeued; its receipt confirmation, sent first. */
  requeued?: RequeueConfirmation;
};

/**
 * Applies a host result. An EXACT receipt the server refuses is classified
 * here, once, instead of per check (WP0): left refused, it stays unconfirmed
 * and replays into every later session. Retryable refusals are an explicit
 * allowlist; every other refusal of an exact receipt is permanent and takes
 * the server's verdict.
 *
 * Retryable (refused now, replayed by a later session):
 * - Authority, ownership and credentials: `acquireInboundFence` (owner/host
 *   binding, `lockHostByEpoch`, sandbox generation/state CAS, live workload,
 *   request digest key and receipt binding, `sender.isCurrent`), re-run by
 *   `exactReceiptOwed`. A not-this-attempt receipt (another attempt,
 *   generation, host, body hash or key) is retired by that attempt's own
 *   settlement: a terminal server row confirms it (`confirmOperationReceipt`),
 *   an UNKNOWN one by later cleanup proof.
 * - A row already terminal: no write; `confirmOperationReceipt` confirms it.
 * - Database errors (serialization, lock timeout, connection): thrown, never
 *   a fence, so the frame fails and the session retries the receipt.
 * - Races: a refused receipt is applied once more against a fresh snapshot
 *   (a lost CAS does not repeat) before it is classified.
 * - Pending observations (`RelayFencePending`): a process-list item whose
 *   birth the server has not recorded (operation-results.ts
 *   `requireResultMatchesRequest`), a result expiry or READY-lease window the
 *   server clock has not reached yet.
 *
 * Verdict, re-applied without the evidence so every fence above runs again:
 * an UNKNOWN report stays UNKNOWN; a create takes the existing uncertain
 * create path (FAILED unknown_outcome, teardown queued); every other kind is
 * FAILED protocol_error, which never claims success (a lifecycle FAILED maps
 * to its existing failed sandbox state). Live frames are only refused; their
 * receipt follows.
 *
 * A `file.put` proven not issued (WP6) is requeued by the first apply, a
 * write, so it never reaches the verdict; the verdict's `protocol_error` is
 * never `host_effect_not_issued` and so never requeues.
 */
export async function applyOperationResult(
  input: ResultInput,
  clock: LeaseClock = leaseNow,
): Promise<ResultOutcome> {
  const first = await applyResultOnce(input, clock);
  if (first.written || !input.receipt || first.refused !== "fence") return outcomeOf(first);
  const again = await applyResultOnce(input, clock);
  if (again.written || again.refused !== "fence") return outcomeOf(again);
  const owed = await exactReceiptOwed(input);
  if (owed === null) return outcomeOf(again);
  // A new root (a create, or a restore: offload §8.7) the server could not
  // apply may exist: never a definite failure.
  const uncertain =
    input.state === "unknown_outcome" || owed.kind === "CREATE_SANDBOX" || isRestoreAttempt(owed);
  const code = uncertain ? "unknown_outcome" : "protocol_error";
  const settled = await applyResultOnce(
    {
      ...input,
      state: uncertain ? "unknown_outcome" : "failed",
      result: undefined,
      error: { code, message: safeOperationError(code).message },
      verdict: true,
    },
    clock,
  );
  // A successful capture the verdict failed leaves its pinned image unused.
  const releaseImage =
    settled.written && input.state === "succeeded"
      ? await droppedCaptureImageToRelease({
          operationId: input.operationId,
          hostId: input.sender.hostId,
          fingerprint: input.result?.fingerprint,
        })
      : null;
  return { ...outcomeOf(settled), ...(releaseImage ? { releaseImage } : {}) };
}
function outcomeOf(outcome: ResultOutcome & { refused?: unknown }): ResultOutcome {
  const { refused: _refused, ...rest } = outcome;
  return rest;
}
/** The exact receipt is still owed by this host: its authority, binding and
 * epoch fences pass now and its row is not yet settled. Returns its kind. */
async function exactReceiptOwed(input: ResultInput) {
  return relayTransaction(async (tx) => {
    const operation = await acquireInboundFence(tx, input, false, input.result?.version === 1);
    const settled = await tx.sandboxOperation.findFirst({
      where: { id: operation.id, OR: RECEIPT_SETTLED_WHERE },
      select: { id: true },
    });
    return settled ? null : { kind: operation.kind, launchMode: operation.launchMode };
  }, null);
}

async function applyResultOnce(
  input: ResultInput,
  clock: LeaseClock,
): Promise<ResultOutcome & { refused?: "fence" | "pending" }> {
  if (input.error) {
    // Default-open egress §1.5: a daemon egress refusal of a create or a cold
    // reconnect is recorded under its typed reason (`daemonEgressRefusal`).
    const egressRefusal = daemonEgressRefusal(input.error);
    const safe = egressRefusal
      ? safeOperationError(egressRefusal)
      : safeOperationError(input.error.code, input.error.reason);
    // The failed readiness check: a typed constant, kept only with its code.
    const readiness =
      safe.code === "guest_unavailable"
        ? readinessFailureReasonSchema.safeParse(input.error.reason).data
        : undefined;
    const reason = safe.reason ?? readiness;
    input = {
      ...input,
      error: {
        code: safe.code as SandboxErrorCode,
        message: safe.message,
        ...(reason ? { reason } : {}),
      },
    };
  }
  const reportedState = prismaOperationState[input.state];
  if (!reportedState || !TERMINAL_OPERATION_STATES.has(reportedState)) {
    return { written: false };
  }
  // A launch reported ready without its logins installed becomes FAILED below.
  let opState: OperationState = reportedState;
  let credentialFree = false;
  let refused: "fence" | "pending" | undefined;
  const outcome = await relayTransaction(
    async (tx) => {
      const operation = await acquireInboundFence(tx, input, false, input.result?.version === 1);
      requireRelayFence(!["SUCCEEDED", "FAILED", "CANCELLED"].includes(operation.state));
      // A recorded capture is settled too: only its finalizer writes the
      // outcome (a later cancelled/unknown report must not race it).
      if (operation.kind === "CAPTURE_TEMPLATE")
        requireRelayFence(
          (await tx.sandboxOperation.findFirst({
            where: { id: operation.id, ...RECORDED_CAPTURE_WHERE },
            select: { id: true },
          })) === null,
        );
      // CLI logins (§7.1): a launch publishes READY only when every lease it
      // launched is ACTIVE. A host that reports ready without having installed
      // them all is treated as an install failure.
      const launch = operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX";
      let credentialDowngrade = false;
      // A login sandbox's LOGIN lease becomes ACTIVE (binding + residue, no
      // bundle) when the host reports it ready (§11).
      if (launch && opState === "SUCCEEDED")
        await activateLoginLease(tx, {
          sandboxId: input.sandboxId,
          operationId: input.operationId,
        });
      // The READY / attach receipt repeats every `credential.installed`
      // report: a frame lost with its socket (the result replays, the frame
      // does not) must not turn a real install into an install failure.
      if ((launch || operation.kind === "CREDENTIAL_ATTACH") && opState === "SUCCEEDED")
        await applyInstalledReceipt(tx, {
          hostId: input.sender.hostId,
          sandboxId: input.sandboxId,
          result: input.result,
        });
      if (
        launch &&
        opState === "SUCCEEDED" &&
        !(await credentialLaunchReady(tx, input.sandboxId))
      ) {
        credentialDowngrade = true;
        opState = "FAILED";
        const safe = safeOperationError("credential_install_failed");
        input = {
          ...input,
          state: "failed",
          result: undefined,
          error: { code: "credential_install_failed", message: safe.message },
        };
      }
      // CLI logins (§7.1, §10.4): a live attach succeeds only with its lease
      // ACTIVE; a free applies its receipt (capture outcome re-read from the
      // ledger, scrub proof) in this transaction.
      if (
        operation.kind === "CREDENTIAL_ATTACH" &&
        opState === "SUCCEEDED" &&
        !(await credentialAttachReady(tx, input.operationId))
      ) {
        opState = "FAILED";
        const safe = safeOperationError("credential_install_failed");
        input = {
          ...input,
          state: "failed",
          result: undefined,
          error: { code: "credential_install_failed", message: safe.message },
        };
      }
      credentialFree = operation.kind === "CREDENTIAL_FREE";
      // Terminal finalization (one helper for every terminal writer); a
      // stop/kill settles below, after the sandbox state is written.
      if (operation.kind !== "STOP_SANDBOX" && operation.kind !== "KILL_SANDBOX")
        await settleOperationCredentials(tx, {
          sandboxId: input.sandboxId,
          operation: { id: operation.id, kind: operation.kind, dispatchAttempt: input.attempt },
          opState,
          receipt: {
            outcomes: teardownOutcomesFromResult(input.result),
            skip: credentialFree && (await freeSpecSkips(tx, input.operationId)),
          },
        });
      const typed = isResultKind(operation.kind)
        ? decodeTypedResult(input, operation, opState)
        : null;
      requireResultCompatible(typed !== null || input.result?.version === undefined);
      // Live finding B-5: a host replays the exact receipt of an attempt it
      // can only report as uncertain on every reconnect. Against a row that
      // is already UNKNOWN with no new evidence it changes nothing; never
      // re-bind such a dead attempt to the new epoch.
      if (
        input.receipt &&
        opState === "UNKNOWN_OUTCOME" &&
        operation.state === "UNKNOWN_OUTCOME" &&
        input.result === undefined
      ) {
        requireRelayFence(input.sender.isCurrent?.() !== false);
        return { written: false, downloaded: undefined, capture: false };
      }
      const now = await leaseTransactionNow(tx, clock);
      // The server clock may not have reached the expiry the host observed.
      if (typed?.resultExpired)
        requireObserved(operation.resultExpiresAt !== null && operation.resultExpiresAt <= now);
      if (typed?.birth) await bindProcessBirth(tx, input, operation, typed.birth);
      if (operation.state === "UNKNOWN_OUTCOME" && !input.receipt) {
        // A live event may fill exact original birth/exit evidence after an
        // interim UNKNOWN, but only an exact receipt can settle its outcome.
        requireRelayFence(
          operation.kind === "RUN_COMMAND" &&
            typed?.birth !== null &&
            typed?.payload?.type === "command",
        );
        await storeScalarOperationResult(tx, {
          ownerId: workloadOwner(input),
          operationId: input.operationId,
          sender: input.sender,
          attempt: input.attempt,
          payload: typed.payload,
          observedAt: new Date(typed.observedAt),
        });
        requireRelayFence(input.sender.isCurrent?.() !== false);
        return { written: true, downloaded: undefined, capture: false };
      }
      if (input.receipt)
        await casInboundOperation(tx, input, {
          dispatchedConnectionEpoch: input.sender.connectionEpoch,
        });
      // WP6: an upload proven not issued is dispatched again while its source
      // is retained (no credential work is bound to PUT_FILE).
      if (
        operation.kind === "PUT_FILE" &&
        opState === "FAILED" &&
        input.error?.code === "host_effect_not_issued" &&
        (operation.state === "DISPATCHED" ||
          operation.state === "ACCEPTED" ||
          operation.state === "RUNNING") &&
        input.attempt < FILE_PUT_REQUEUE_MAX_ATTEMPT
      ) {
        const requeued = await requeueUnissuedFilePut(tx, input, operation, now);
        if (requeued) return { written: true, downloaded: undefined, capture: false, requeued };
      }
      // A capture's host result is stored on the capture row and the
      // operation stays RUNNING ("finalizing"): the finalizer, in its own
      // transaction, creates the revision and settles the operation.
      if (operation.kind === "CAPTURE_TEMPLATE" && opState === "SUCCEEDED") {
        requireRelayFence(
          await recordCaptureResult(tx, {
            operationId: input.operationId,
            hostId: input.sender.hostId,
            epoch: input.sender.connectionEpoch,
            result: input.result,
          }),
        );
        requireRelayFence(input.sender.isCurrent?.() !== false);
        notifyCaptureResult();
        return { written: true, downloaded: undefined, capture: false };
      }
      if (
        opState === "SUCCEEDED" &&
        (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX")
      )
        requireRelayFence(input.result?.state === "ready");
      if (opState === "SUCCEEDED" && operation.kind === "STOP_SANDBOX") {
        requireRelayFence(input.result?.state === "stopped" || input.result?.state === "absent");
      }
      if (opState === "SUCCEEDED" && operation.kind === "KILL_SANDBOX") {
        requireRelayFence(input.result?.state === "deleted");
      }
      if (operation.kind === "RUN_COMMAND" && input.result && typed === null) {
        requireResultCompatible(commandResultMetadataSchema.safeParse(input.result).success);
      }
      if (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") {
        const sandbox = await tx.sandbox.findFirst({
          where: {
            id: input.sandboxId,
            userId: workloadOwner(input),
            generation: input.generation,
          },
        });
        requireRelayFence(sandbox != null);
        const restoreAttempt = restoreOffloadOf(operation) !== null;
        // B9: the VM booted but its template start/ready commands failed.
        // Its guest is live and unusable: queue cleanup with the typed code
        // (a create is destroyed; a reconnect is only stopped, keeping its disk).
        const startupFailure =
          opState !== "SUCCEEDED" &&
          (input.error?.code === "startup_failed" ||
            input.error?.code === "startup_timeout" ||
            // The guest booted with no IPv4 default route (E1-A-01).
            input.error?.code === "guest_network_unavailable");
        if (
          await finalizeExpiredSandboxLifecycleOperation(
            tx,
            sandbox,
            operation,
            now,
            opState === "SUCCEEDED",
            opState !== "SUCCEEDED" && input.error?.code === "guest_unavailable"
              ? (readinessFailureReasonSchema.safeParse(input.error.reason).data ?? true)
              : false,
            // A failed create has no usable guest to retain. Transfer its
            // uncertain hold to durable generation-fenced teardown immediately;
            // only the host's later absence proof releases the resources.
            startupFailure
              ? input.error!.code
              : // A restore attempt that did not reach
                // READY (fetch, validate, import or init FAILED, or an
                // UNKNOWN outcome) ends through the restore exit: the
                // SYSTEM_DETACH kill, then OFFLOADED with its copy kept.
                restoreAttempt && opState !== "SUCCEEDED"
                ? (input.error?.code ?? "unknown_outcome")
                : // WP0: a cold start's READY evidence the server could not
                  // apply. The VM may be running: settle it like a failed
                  // start (queued stop, hold kept until the stop proves state).
                  input.verdict === true &&
                    operation.kind === "RECONNECT_SANDBOX" &&
                    sandbox.state === "STOPPED"
                  ? "protocol_error"
                  : operation.kind === "CREATE_SANDBOX" &&
                      input.error?.code !== "guest_unavailable" &&
                      (opState === "UNKNOWN_OUTCOME" ||
                        (opState === "FAILED" &&
                          (input.error?.code === "egress_resolution_failed" ||
                            input.error?.code === "timeout" ||
                            // CLI logins: the VM booted but a login could not be
                            // installed; it is destroyed like a readiness failure.
                            input.error?.code === "credential_install_failed")))
                    ? (input.error?.code ?? "unknown_outcome")
                    : undefined,
          )
        ) {
          requireRelayFence(input.sender.isCurrent?.() !== false);
          return { written: true, downloaded: undefined, capture: false };
        }
      }
      if (
        opState === "SUCCEEDED" &&
        LEASE_DISPATCH_KINDS.has(relayDispatchKind(operation.kind) ?? "")
      ) {
        // Immutable enqueue payload binds the ACK to this operation, including
        // delayed receipts after a newer renewal. H → S is already held.
        const event = await tx.outboxEvent.findFirst({
          where: {
            userId: workloadOwner(input),
            aggregateType: "sandbox",
            aggregateId: input.sandboxId,
            ...outboxOperationWhere(input.operationId),
          },
          select: { payload: true },
        });
        const payload = event?.payload;
        const requested = leaseWireSchema.safeParse(
          payload && typeof payload === "object" && !Array.isArray(payload)
            ? payload.lease
            : undefined,
        );
        const acknowledged = leaseWireSchema.safeParse(input.result?.lease);
        requireRelayFence(requested.success && acknowledged.success);
        const fromReadyMs = requested.data.fromReadyMs;
        if (fromReadyMs !== undefined) {
          // Lease from READY (M7): the host set deadline = readyAt + timeout
          // on its own clock. Window-fenced (with skew), never equality.
          requireRelayFence(
            operation.kind === "CREATE_SANDBOX" &&
              operation.leaseFromReady &&
              operation.leaseAcceptedAt != null &&
              acknowledged.data.fromReadyMs === fromReadyMs &&
              requested.data.revision === acknowledged.data.revision &&
              requested.data.action === acknowledged.data.action,
          );
          const window = (nowMs: number) =>
            fromReadyDeadlineAcceptable({
              deadlineMs: acknowledged.data.deadlineUnixMs,
              acceptedAtMs: operation.leaseAcceptedAt!.getTime(),
              timeoutMs: fromReadyMs,
              provisionalMs: requested.data.deadlineUnixMs,
              nowMs,
            });
          // The window's upper edge grows with the server clock up to the
          // provisional deadline: a deadline inside that bound is pending.
          requireRelayFence(window(requested.data.deadlineUnixMs));
          requireObserved(window(now.getTime()));
          const settled = new Date(acknowledged.data.deadlineUnixMs);
          await tx.sandboxOperation.updateMany({
            where: { id: input.operationId, leaseFromReady: true },
            data: { leaseExpiresAtAccepted: settled },
          });
          // Replaces the provisional backstop with the READY-based deadline;
          // a later renewal (revision > 1) already moved the lease on.
          await tx.sandbox.updateMany({
            where: {
              id: input.sandboxId,
              userId: workloadOwner(input),
              generation: input.generation,
              leasePendingReady: true,
              leaseRevision: acknowledged.data.revision,
            },
            data: {
              leaseExpiresAt: settled,
              leaseExpiresAtRequested: settled,
              leasePendingReady: false,
            },
          });
        } else
          requireRelayFence(
            requested.data.revision === acknowledged.data.revision &&
              requested.data.deadlineUnixMs === acknowledged.data.deadlineUnixMs &&
              requested.data.action === acknowledged.data.action,
          );
        if (fromReadyMs === undefined && operation.leaseRevisionAccepted != null)
          requireRelayFence(
            operation.leaseRevisionAccepted === acknowledged.data.revision &&
              operation.leaseExpiresAtAccepted?.getTime() === acknowledged.data.deadlineUnixMs &&
              operation.leaseExpireActionAccepted ===
                (acknowledged.data.action === "destroy" ? "DESTROY" : "STOP"),
          );
        // A delayed ACK is durable evidence for its own intent; it must never
        // replace a newer effective revision (including a shortening).
        await casInboundOperation(tx, input, {
          leaseAcknowledgedAt: now,
          leaseAcknowledgedAttempt: input.attempt,
          leaseAcknowledgedEpoch: input.sender.connectionEpoch,
        });
        await tx.sandbox.updateMany({
          where: {
            id: input.sandboxId,
            userId: workloadOwner(input),
            generation: input.generation,
            OR: [
              { leaseRevisionEffective: null },
              { leaseRevisionEffective: { lt: acknowledged.data.revision } },
            ],
          },
          data: {
            leaseRevisionEffective: acknowledged.data.revision,
            leaseExpiresAtEffective: new Date(acknowledged.data.deadlineUnixMs),
            leaseExpireActionEffective: acknowledged.data.action === "destroy" ? "DESTROY" : "STOP",
          },
        });
      }
      if (
        opState === "SUCCEEDED" &&
        (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX")
      ) {
        await tx.sandboxPlacement.updateMany({
          where: {
            sandboxId: input.sandboxId,
            userId: workloadOwner(input),
            generation: input.generation,
            operationId: input.operationId,
          },
          data: { startedAt: now, readyAt: now },
        });
      }
      // Acquire the operation row before observing its buffered file bytes.
      await casInboundOperation(tx, input, { dispatchAttempt: input.attempt });
      await prelockOperationOutbox(tx, workloadOwner(input), input.sandboxId, input.operationId);
      // Final command results carry the host's byte total: commit the output
      // completion watermark with the terminal state (fence-rejects a total
      // below the bytes already stored). Interim UNKNOWN results carry none.
      if (operation.kind === "RUN_COMMAND" && typeof input.result?.outputBytes === "number")
        await sealCommandOutput(tx, {
          operationId: input.operationId,
          attempt: input.attempt,
          totalBytes: input.result.outputBytes,
        });
      const downloaded =
        operation.kind === "GET_FILE" && opState === "SUCCEEDED"
          ? await relayCaptures().completedCapture(input.operationId, input.attempt, tx)
          : undefined;
      requireRelayFence(
        operation.kind !== "GET_FILE" || opState !== "SUCCEEDED" || downloaded != null,
      );
      requireRelayFence(
        !downloaded ||
          (input.result?.size === downloaded.size && input.result?.sha256 === downloaded.sha256),
      );
      let resultError:
        | {
            code: string;
            message: string;
            reason?: import("@wssp/sandbox-contracts").CapacityReason;
          }
        | undefined = input.error && {
        code: input.error.code,
        message: input.error.message,
        // Sanitized above: only `host_capacity` keeps a (capacity) reason.
        ...(input.error.reason !== undefined && isCapacityReason(input.error.reason)
          ? { reason: input.error.reason }
          : {}),
      };
      // Follow-up 11: a cold start the host refused as sandbox_not_found
      // (no retained disk) gets its fixed diagnostic; the daemon's message
      // text never becomes public detail.
      if (
        resultError?.code === "sandbox_not_found" &&
        operation.kind === "RECONNECT_SANDBOX" &&
        operation.launchMode === "COLD" &&
        opState === "FAILED"
      )
        resultError = safeOperationError(resultError.code, undefined, {
          kind: operation.kind,
          launchMode: operation.launchMode,
          state: opState,
        });
      // A FAILED (not UNKNOWN) exact-image-missing create is the daemon's proof
      // that it refused before any runtime effect (an uncertain allocation is
      // reported UNKNOWN_OUTCOME instead), so no root exists to retain.
      let imageMissingProven = false;
      if (
        opState === "FAILED" &&
        operation.kind === "CREATE_SANDBOX" &&
        input.error?.code === "not_found"
      ) {
        const proof = input.result?.imageMissing;
        if (proof && typeof proof === "object" && !Array.isArray(proof)) {
          const binding = proof as Record<string, unknown>;
          const pinned = await tx.sandboxPlacement.findFirst({
            where: {
              sandboxId: input.sandboxId,
              userId: workloadOwner(input),
              generation: input.generation,
              operationId: input.operationId,
            },
            select: { templateRevisionId: true, artifact: true, architecture: true },
          });
          if (
            pinned &&
            binding.templateRevisionId === pinned.templateRevisionId &&
            binding.artifact === pinned.artifact &&
            binding.architecture === pinned.architecture &&
            binding.connectionEpoch === input.sender.connectionEpoch &&
            operation.dispatchedConnectionEpoch === input.sender.connectionEpoch
          ) {
            resultError = {
              code: "sandbox.template_image_missing",
              message: "The exact template image is missing on this host.",
            };
            imageMissingProven = true;
            await tx.sandboxTemplateAvailability.updateMany({
              where: {
                revisionId: pinned.templateRevisionId,
                hostId: input.sender.hostId,
                userId: workloadOwner(input),
                verifiedConnectionEpoch: input.sender.connectionEpoch,
                localFingerprint: pinned.artifact,
                architecture: pinned.architecture,
              },
              data: { status: "MISSING", observedAt: now },
            });
          }
        }
      }

      // A terminal (or UNKNOWN) result may clear this host's last active-work blocker.
      noteHostBlockerReleased(tx, input.sender.hostId, input.sender.userId);
      await casInboundOperation(tx, input, {
        state: opState,
        // First completion owns the output-retention deadline (C26): replayed
        // UNKNOWN receipts and later exact-bound reconciliation must not extend
        // it, or reconnecting would keep old output readable indefinitely.
        completedAt: operation.completedAt ?? now,
        errorCode: resultError?.code ?? null,
        errorDetail: resultError?.message ?? null,
        ...(typed
          ? {
              failure: typed.failure
                ? {
                    ...typed.failure,
                    ...(resultError?.code === "host_capacity" && resultError.reason
                      ? { reason: resultError.reason }
                      : {}),
                  }
                : PrismaValue.DbNull,
              ...(operation.kind === "RUN_COMMAND"
                ? {
                    processDescriptionExpiresAt: new Date(
                      (operation.completedAt ?? now).getTime() + OUTPUT_RETENTION_MS,
                    ),
                  }
                : {}),
            }
          : resultError?.code === "host_capacity" && resultError.reason
            ? {
                failure: {
                  resource: "sandbox",
                  effect: opState === "UNKNOWN_OUTCOME" ? "unknown" : "none",
                  reason: resultError.reason,
                },
              }
            : {}),
        result: {
          ...(typed
            ? typed.payload?.type === "command"
              ? {
                  exitCode: typed.payload.exitCode,
                  pid: typed.payload.process.pid,
                  outputBytes: typed.outputBytes,
                }
              : {}
            : withoutCredentialReceipts(input.result)),
          ...(downloaded
            ? {
                size: downloaded.size,
                sha256: downloaded.sha256,
                transferId: downloaded.transferId,
              }
            : {}),
        },
      });

      if (isLifecycleOperationKind(operation.kind)) {
        const sandbox = await tx.sandbox.findFirst({
          where: {
            id: input.sandboxId,
            userId: workloadOwner(input),
            generation: input.generation,
          },
          select: {
            id: true,
            state: true,
            generation: true,
            userId: true,
            sandboxHostId: true,
            readyAt: true,
            diskReservationHeld: true,
            startedAt: true,
            diskOffloadId: true,
          },
        });
        requireRelayFence(sandbox != null);
        const sandboxStateBeforeResult = sandbox.state;
        // CLI logins (§10.3, P3-3): a USER stop/kill refused by a failed login
        // capture leaves the VM running; it re-arms only when it owns a
        // RELEASING lease. System teardowns never fail on capture, so a
        // reported capture failure there takes the ordinary FAILED mapping.
        const teardownKind = operation.kind === "STOP_SANDBOX" || operation.kind === "KILL_SANDBOX";
        const rearm =
          teardownKind &&
          opState === "FAILED" &&
          resultError?.code === "credential_capture_failed" &&
          sandboxStateBeforeResult === "STOPPING" &&
          (await ownsReleasingLease(tx, sandbox.id, operation));
        let nextSandbox = sandboxStateForLifecycleResult(
          operation.kind,
          opState,
          input.result?.state,
          sandboxStateBeforeResult,
          resultError?.code,
          { ownsReleasingLease: rearm, priorState: operation.teardownPriorState },
          operation.teardownIntent,
        );
        const neverReadyStopCleanup =
          operation.kind === "STOP_SANDBOX" &&
          opState === "SUCCEEDED" &&
          input.result?.state === "absent" &&
          isNeverReadyRootOnly(sandbox);
        if (
          nextSandbox === "DELETED" &&
          operation.kind === "STOP_SANDBOX" &&
          sandbox.diskReservationHeld
        )
          nextSandbox = neverReadyStopCleanup ? "STOPPING" : "STOPPED";
        // A cold start the host reported ready without installed logins: the
        // VM is running, so it is never recorded STOPPED; ERROR keeps it in
        // reclaim and inventory convergence.
        if (credentialDowngrade && operation.kind === "RECONNECT_SANDBOX") nextSandbox = "ERROR";
        // a cached cold reconnect refused `disk_stale`
        // (the host's retained root is not the stored offload it expected;
        // nothing started) stays STOPPED like any cold-reconnect refusal. The
        // bound host's copy no longer equals `cachedOffloadSeq`, so the next
        // start never boots it: it evicts or discards it and restores
        // (`cachedDiskExpectation`).
        if (
          operation.kind === "RECONNECT_SANDBOX" &&
          opState === "FAILED" &&
          resultError?.code === "disk_stale" &&
          sandboxStateBeforeResult === "STOPPED"
        )
          await tx.sandbox.updateMany({
            where: {
              id: sandbox.id,
              userId: sandbox.userId,
              generation: sandbox.generation,
              diskOffloadId: { not: null },
            },
            data: { cachedOffloadSeq: null },
          });
        // A remnant destroy (inventory-reconcile `obligeRemnantDestroy`) never
        // resurrects a DELETED sandbox: only its success settles anything. A
        // failure keeps the remnant's live charge until a later census.
        if (sandboxStateBeforeResult === "DELETED" && nextSandbox !== "DELETED")
          nextSandbox = undefined;
        // OFFLOADED is decided first. A SUCCEEDED
        // SYSTEM_DETACH kill settles through its detach (root proof → the one
        // OFFLOADED writer) and its own credential arm; none of the generic
        // writers below (state write, live release, teardown retry,
        // image-missing retire, DELETED detach) runs for it.
        const offloaded = nextSandbox === "OFFLOADED";
        if (offloaded) {
          requireRelayFence(
            operation.kind === "KILL_SANDBOX" &&
              opState === "SUCCEEDED" &&
              sandbox.sandboxHostId === input.sender.hostId,
          );
          await settleOperationCredentials(tx, {
            sandboxId: sandbox.id,
            operation: { id: operation.id, kind: operation.kind, dispatchAttempt: input.attempt },
            opState,
            receipt: {
              outcomes: teardownOutcomesFromResult(input.result),
              next: "OFFLOADED",
              rearm: false,
            },
          });
          requireRelayFence(
            await settleSystemDetachKill(tx, {
              sandboxId: sandbox.id,
              userId: sandbox.userId,
              hostId: input.sender.hostId,
              generation: sandbox.generation,
              killOperationId: operation.id,
            }),
          );
        }
        if (nextSandbox && !offloaded) {
          requireRelayFence(canTransitionLifecycleResult(sandbox.state, nextSandbox, rearm));
          // U7/S17: OFFLOADED is written only by `detachToOffloaded`; a
          // SYSTEM_DETACH kill result settles through its detach (census, C6
          // restore exit), never through this generic writer.
          requireRelayFence(nextSandbox !== "OFFLOADED");
          // M19: grants the node's domain blocklist denied, from a successful create.
          const deniedGrants =
            (operation.kind === "CREATE_SANDBOX" || isRestoreAttempt(operation)) &&
            opState === "SUCCEEDED"
              ? createResultDeniedGrants(input.result)
              : undefined;
          // The guest's group-signal support (kernel >= 6.9), observed by the
          // host once this create/reconnect was ready. A result without it
          // leaves the new boot unobserved.
          const groupSignals =
            (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") &&
            opState === "SUCCEEDED" &&
            nextSandbox === "READY"
              ? { guestGroupSignals: readyResultGroupSignals(input.result) }
              : {};
          const lifecycleError =
            opState === "FAILED"
              ? {
                  lastErrorCode: resultError?.code ?? null,
                  lastErrorDetail: resultError?.message ?? null,
                }
              : { lastErrorCode: null, lastErrorDetail: null };
          // a READY with a stored disk (a restore, or a
          // cached cold reconnect) consumes it in this same write.
          const consumed =
            nextSandbox === "READY" && sandbox.diskOffloadId
              ? await consumeOffloadAtReady(tx, {
                  sandboxId: sandbox.id,
                  offloadId: sandbox.diskOffloadId,
                  restoreOperationId: isRestoreAttempt(operation) ? operation.id : null,
                  now,
                })
              : {};
          // an owner destroy ends the stored offload first
          // (the only clearer of `diskOffloadId` for a destroy); any other
          // DELETED with a stored disk aborts on the CHECK.
          if (nextSandbox === "DELETED" && sandbox.diskOffloadId)
            await endOffloadForDestroy(tx, {
              sandboxId: sandbox.id,
              userId: sandbox.userId,
              destroyOperationId: operation.id,
              now,
            });
          const changed = await tx.sandbox.updateMany({
            where: {
              id: sandbox.id,
              state: sandbox.state,
              generation: sandbox.generation,
              userId: sandbox.userId,
            },
            data: {
              state: nextSandbox,
              ...(deniedGrants !== undefined ? { egressDeniedGrants: deniedGrants } : {}),
              ...groupSignals,
              ...(nextSandbox === "READY" && sandbox.readyAt == null ? { readyAt: now } : {}),
              ...(nextSandbox === "READY" && sandbox.startedAt == null ? { startedAt: now } : {}),
              ...lifecycleError,
              ...consumed,
            },
          });
          requireRelayFence(changed.count === 1);
        }
        // CLI logins (§7.5): apply the teardown receipt in the result
        // transaction, before any DELETED detach.
        if (rearm)
          await rebindPlacementAfterRearm(tx, {
            sandboxId: sandbox.id,
            userId: sandbox.userId,
            generation: sandbox.generation,
            operationId: operation.id,
            now,
          });
        if (teardownKind && !offloaded)
          await settleOperationCredentials(tx, {
            sandboxId: sandbox.id,
            operation: { id: operation.id, kind: operation.kind, dispatchAttempt: input.attempt },
            opState,
            receipt: {
              outcomes: teardownOutcomesFromResult(input.result),
              // The never-ready STOP finished with the guest gone: its receipt
              // settles logins as a stop does (scrub outcomes applied) while
              // the row stays STOPPING for the cleanup KILL (as the census
              // path settles it).
              next: neverReadyStopCleanup ? "STOPPED" : nextSandbox,
              rearm,
            },
          });
        else if (nextSandbox === "DELETED") await settleCredentialsOnDeleted(tx, sandbox.id);
        if (!offloaded)
          await releaseLiveResourcesIfHeld(tx, {
            // A cold start the host reported ready is running even though the
            // READY gate failed it: never release its live hold here. Nor for a
            // server verdict: only the host's own definite failure proves the
            // effect unissued; the evidence it could not apply may describe a
            // running VM. Its hold stays until absence is proved (inventory).
            guestRunning: credentialDowngrade || input.verdict === true,
            operationId: input.operationId,
            endState: input.result?.state,
            hostId: sandbox.sandboxHostId,
            ownerId: workloadOwner(input),
            sandboxId: sandbox.id,
            kind: operation.kind,
            opState,
            sandboxStateBeforeResult,
            // E1-A-07: the retained root of a proven-unissued create is released
            // with its live hold; nothing else would ever free it.
            neverIssued: imageMissingProven,
          });
        // STOP/absent releases live capacity but cannot retire the retained
        // root. Advance only after settling that receipt, through the system
        // teardown choke point (including login settlement). STOPPING also
        // excludes this sandbox from on_stop offload candidates.
        if (neverReadyStopCleanup) await queueNeverReadyStopCleanup(tx, sandbox, now);
        // A failed stop/kill (host failure or server verdict) left ERROR with
        // a live hold or never-ready root: nothing else resolves it while the
        // host stays connected. Retry the teardown (bounded); its proof releases the hold.
        // Never past a login capture failure: a system retry would discard
        // the login changes that refusal kept (CLI logins §10.3).
        if (
          teardownKind &&
          opState === "FAILED" &&
          nextSandbox === "ERROR" &&
          !rearm &&
          resultError?.code !== "credential_capture_failed"
        )
          await queueFailedTeardownRetry(
            tx,
            {
              sandboxId: sandbox.id,
              userId: sandbox.userId,
              generation: sandbox.generation,
              failed: {
                kind: operation.kind as "STOP_SANDBOX" | "KILL_SANDBOX",
                idempotencyKey: operation.idempotencyKey,
              },
            },
            now,
          );
        // E2-A-05: a proven-unissued image-missing create holds nothing once
        // its live hold and root are released above, so it ends DELETED (like
        // a capacity wait that ended) instead of lingering as an ERROR row.
        // Anything still held (an unproven attempt) keeps the ERROR row.
        if (imageMissingProven && nextSandbox === "ERROR") {
          const retired = await tx.sandbox.updateMany({
            where: {
              id: sandbox.id,
              userId: sandbox.userId,
              generation: sandbox.generation,
              state: "ERROR",
              liveResourcesHeld: false,
              diskReservationHeld: false,
              sandboxHostId: sandbox.sandboxHostId,
            },
            data: { state: "DELETED", sandboxHostId: null, storagePoolId: null },
          });
          if (retired.count === 1) await settleCredentialsOnDeleted(tx, sandbox.id);
        }
        // Release capacity while the pin is still present, then detach only a
        // proven DELETED placement in this same H → S → O transaction. STOPPED
        // guests retain their disk placement and remain protected by Restrict.
        if (nextSandbox === "DELETED") {
          const detached = await tx.sandbox.updateMany({
            where: {
              id: sandbox.id,
              userId: sandbox.userId,
              generation: sandbox.generation,
              state: "DELETED",
              liveResourcesHeld: false,
              diskReservationHeld: false,
              sandboxHostId: sandbox.sandboxHostId,
            },
            data: { sandboxHostId: null, storagePoolId: null },
          });
          requireRelayFence(detached.count === 1);
        }
        // C21-11: the detach may clear the last blocker; finalization runs as the
        // transaction's last step (see noteHostBlockerReleased).
        noteHostBlockerReleased(tx, sandbox.sandboxHostId, input.sender.userId);
      }

      await settleSupersededOperations(
        tx,
        {
          userId: workloadOwner(input),
          sandboxId: input.sandboxId,
          generation: input.generation,
          kind: operation.kind,
          state: opState,
        },
        now,
      );

      await tx.outboxEvent.updateMany({
        where: {
          userId: workloadOwner(input),
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          processedAt: null,
          ...outboxOperationWhere(input.operationId),
        },
        data: { processedAt: now },
      });

      if (typed?.payload) {
        const args = {
          ownerId: workloadOwner(input),
          operationId: input.operationId,
          sender: { hostId: input.sender.hostId, connectionEpoch: input.sender.connectionEpoch },
          attempt: input.attempt,
          payload: typed.payload,
          observedAt: new Date(typed.observedAt),
        };
        if (isContentResultKind(operation.kind))
          await publishOperationResult(tx, { ...args, continuation: typed.continuation });
        else await storeScalarOperationResult(tx, args);
      }
      noteTerminalResultRelease(tx, workloadOwner(input), { operationId: input.operationId });
      requireRelayFence(input.sender.isCurrent?.() !== false);
      return {
        written: true,
        downloaded,
        capture: operation.kind === "GET_FILE",
        allocationUnknown:
          opState === "UNKNOWN_OUTCOME" &&
          (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX"),
      };
    },
    { written: false, downloaded: undefined, capture: false },
    (error) => {
      refused = error instanceof RelayFencePending ? "pending" : "fence";
    },
  );
  // Only a successful download keeps its capture (until transfer expiry).
  if (outcome.written && outcome.capture && !outcome.downloaded) {
    await relayCaptures().discardCapture(input.operationId, input.attempt);
  }
  // CLI logins (§11 Save): a finished free whose login capture committed lets
  // the login sandbox be destroyed now (no-op for any other free).
  if (outcome.written && credentialFree)
    await destroySavedLoginSandbox({ sandboxId: input.sandboxId });
  // E2-A-01: a successful capture whose result could not be recorded (its
  // authority was superseded, e.g. a cancel's cleanup kill fenced it) leaves
  // a published, pinned image on the host that no revision will ever use.
  const releaseImage =
    !outcome.written && reportedState === "SUCCEEDED"
      ? await droppedCaptureImageToRelease({
          operationId: input.operationId,
          hostId: input.sender.hostId,
          fingerprint: input.result?.fingerprint,
        })
      : null;
  // A wake only: any claim it triggers needs IO, so the caller's
  // confirmation send (no IO in between) always precedes attempt + 1.
  if (outcome.requeued) notifySandboxDispatchPending();
  return {
    written: outcome.written,
    ...(outcome.allocationUnknown ? { allocationUnknown: true } : {}),
    ...(releaseImage ? { releaseImage } : {}),
    ...(outcome.requeued ? { requeued: outcome.requeued } : {}),
    ...(!outcome.written && refused ? { refused } : {}),
  };
}

export function wouldAuthorSandboxState(
  kind: string,
  opState: OperationState,
  current: SandboxState,
  endState?: unknown,
  errorCode?: string | null,
): SandboxState | undefined {
  if (!isLifecycleOperationKind(kind)) return undefined;
  const next = sandboxStateForLifecycleResult(kind, opState, endState, current, errorCode);
  if (!next || !canTransitionSandboxState(current, next)) return undefined;
  return next;
}

/** A missing receipt proves neither success nor safe retry. Preserve uncertainty;
 * expired provisioning transfers cleanup to durable STOP/KILL intent. */
/** D11: the longest a `pendingReceipts` entry holds an operation unsettled,
 * counted from its dispatch. Past it the operation settles as unknown, as it
 * would without the hold; a late receipt still resolves it. */
export const PENDING_RECEIPT_MAX_HOLD_MS = 10 * 60_000;

export async function finishHostReconciliation(
  sender: RelaySender,
  clock: LeaseClock = leaseNow,
  /** D11 (`pendingReceipts`): operations whose receipt the host is still
   * resolving. They are not settled as unknown, and their dispatch intent for
   * that attempt is retired so no replacement attempt is dispatched while the
   * receipt is pending; queued controls (cancel, stdin, signal) stay. A later
   * session settles them as before if the receipt never arrives, and so does
   * this one once an operation has been held past
   * {@link PENDING_RECEIPT_MAX_HOLD_MS} since its dispatch. */
  pendingReceipts: ReadonlySet<string> = new Set(),
): Promise<boolean> {
  let cursor: string | undefined;
  for (;;) {
    // Read a bounded inventory page, then acquire H → S → O separately for each
    // operation. Never acquire a second sandbox after an operation/outbox lock.
    const page = await relayTransaction(async (tx) => {
      await lockOwnerForAdmission(tx, sender.userId);
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      return tx.sandboxOperation.findMany({
        where: {
          Sandbox: { hostOwnerId: sender.userId, sandboxHostId: sender.hostId },
          dispatchedHostId: sender.hostId,
          dispatchedConnectionEpoch: { lt: sender.connectionEpoch },
          state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"] },
          // A recorded settlement (a capture its finalizer completes) has an
          // outcome; it never becomes UNKNOWN (RECEIPT_SETTLED_WHERE).
          NOT: { OR: RECEIPT_SETTLED_WHERE },
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        select: {
          id: true,
          userId: true,
          sandboxId: true,
          generation: true,
          dispatchAttempt: true,
          kind: true,
        },
        orderBy: { id: "asc" },
        take: 64,
      });
    }, null);
    if (page == null || sender.isCurrent?.() === false) return false;
    for (const operation of page) {
      // A pending receipt holds settlement only for a bounded time from its
      // dispatch, measured on the database clock that stamped it: a wedged
      // host worker, or a host naming the same operation on every reconnect,
      // cannot keep it active forever (the session sweep re-runs this).
      const held =
        pendingReceipts.has(operation.id) &&
        (await relayTransaction(async (tx) => {
          // Same H -> S -> O order as the settlement below.
          const binding = await requireRelayWorkload(tx, sender, { operationId: operation.id });
          for (const id of [...new Set([binding.sandboxOwnerId, sender.userId])].sort())
            await lockOwnerForAdmission(tx, id);
          await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
          const sandbox = await tx.sandbox.findFirst({
            where: { id: operation.sandboxId, userId: operation.userId },
            select: { generation: true, state: true },
          });
          requireRelayFence(sandbox != null);
          await casSandboxGeneration(tx, {
            sandboxId: operation.sandboxId,
            userId: operation.userId,
            hostId: sender.hostId,
            generation: sandbox.generation,
            states: [sandbox.state],
          });
          // Fenced on this exact attempt: retire only its dispatch intent.
          const current = await tx.sandboxOperation.findFirst({
            where: operationActiveFenceWhere({
              operationId: operation.id,
              sandboxId: operation.sandboxId,
              userId: operation.userId,
              hostId: sender.hostId,
              generation: operation.generation,
              attempt: operation.dispatchAttempt,
            }),
            select: { kind: true, dispatchedAt: true },
          });
          requireRelayFence(current != null);
          const dbNow = await hostDatabaseNow(tx);
          if (
            current.dispatchedAt == null ||
            dbNow.getTime() - current.dispatchedAt.getTime() >= PENDING_RECEIPT_MAX_HOLD_MS
          )
            return false;
          await tx.outboxEvent.updateMany({
            where: {
              userId: operation.userId,
              aggregateType: "sandbox",
              aggregateId: operation.sandboxId,
              processedAt: null,
              AND: [
                outboxOperationWhere(operation.id),
                { payload: { path: ["kind"], equals: relayDispatchKind(current.kind) } },
              ],
            },
            data: { processedAt: dbNow },
          });
          requireRelayFence(sender.isCurrent?.() !== false);
          return true;
        }, false));
      if (held) continue;
      const written = await relayTransaction(async (tx) => {
        const binding = await requireRelayWorkload(tx, sender, { operationId: operation.id });
        for (const id of [...new Set([binding.sandboxOwnerId, sender.userId])].sort())
          await lockOwnerForAdmission(tx, id);
        await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
        const sandbox = await tx.sandbox.findFirst({
          where: { id: operation.sandboxId, userId: operation.userId },
          select: { generation: true, state: true },
        });
        requireRelayFence(sandbox != null);
        await casSandboxGeneration(tx, {
          sandboxId: operation.sandboxId,
          userId: operation.userId,
          hostId: sender.hostId,
          generation: sandbox.generation,
          states: [sandbox.state],
        });
        const current = await tx.sandboxOperation.findFirst({
          where: {
            ...operationActiveFenceWhere({
              operationId: operation.id,
              sandboxId: operation.sandboxId,
              userId: operation.userId,
              hostId: sender.hostId,
              generation: operation.generation,
              attempt: operation.dispatchAttempt,
            }),
            // Re-checked under the locks: the capture may have been recorded
            // since the page was read.
            NOT: { OR: RECEIPT_SETTLED_WHERE },
          },
          select: {
            id: true,
            userId: true,
            sandboxId: true,
            kind: true,
            state: true,
            generation: true,
            dispatchAttempt: true,
            dispatchedHostId: true,
            dispatchedConnectionEpoch: true,
            errorCode: true,
            completedAt: true,
            launchMode: true,
            restoreOffloadId: true,
          },
        });
        requireRelayFence(current != null);
        const leaseRow = await tx.sandbox.findFirst({
          where: { id: operation.sandboxId, userId: operation.userId },
        });
        requireRelayFence(leaseRow != null);
        const now = clock();
        if (await finalizeExpiredSandboxLifecycleOperation(tx, leaseRow, current, now)) {
          requireRelayFence(sender.isCurrent?.() !== false);
          return true;
        }
        await casActiveOperation(
          tx,
          {
            operationId: operation.id,
            sandboxId: operation.sandboxId,
            userId: operation.userId,
            hostId: sender.hostId,
            generation: operation.generation,
            attempt: operation.dispatchAttempt,
          },
          {
            state: "UNKNOWN_OUTCOME",
            errorCode: current.errorCode === "superseded" ? "superseded" : "unknown_outcome",
            errorDetail: "Host inventory has no confirmed outcome.",
            // A retired row can already carry its first completion (C26):
            // reconciliation must not restart the output-retention deadline.
            completedAt: current.completedAt ?? now,
          },
        );
        await settleSupersededOperations(
          tx,
          {
            userId: operation.userId,
            sandboxId: operation.sandboxId,
            generation: operation.generation,
            kind: current.kind,
            state: "UNKNOWN_OUTCOME",
          },
          now,
        );
        await tx.outboxEvent.updateMany({
          where: {
            userId: operation.userId,
            aggregateType: "sandbox",
            aggregateId: operation.sandboxId,
            processedAt: null,
            ...outboxOperationWhere(operation.id),
          },
          data: { processedAt: now },
        });
        requireRelayFence(sender.isCurrent?.() !== false);
        return true;
      }, false);
      if (written && operation.kind === "GET_FILE")
        await relayCaptures().discardCapture(operation.id, operation.dispatchAttempt);
    }
    if (sender.isCurrent?.() === false) return false;
    if (page.length < 64) return true;
    cursor = page[page.length - 1]!.id;
  }
}

/** The one "already settled or recorded" predicate for an exact receipt, shared
 * by confirmation, the receipt classifier and reconnect reconciliation: a
 * terminal row, or a recorded capture whatever its operation state says (its
 * finalizer completes the revision and owns the terminal write;
 * RECORDED_CAPTURE_WHERE). Such a receipt is confirmed, never given a verdict. */
const RECEIPT_SETTLED_WHERE = [
  { state: { in: ["SUCCEEDED", "FAILED", "CANCELLED"] } },
  RECORDED_CAPTURE_WHERE,
] satisfies Prisma.SandboxOperationWhereInput[];

/** Plan §10: a `command.run` row recorded UNKNOWN on an ordinary (never a
 * template-build) sandbox. Its exact receipt is answered `retireCommand`. */
const RETIRABLE_UNKNOWN_COMMAND_WHERE = {
  kind: "RUN_COMMAND",
  state: "UNKNOWN_OUTCOME",
  Sandbox: { is: { buildId: null } },
} satisfies Prisma.SandboxOperationWhereInput;

/** Confirmation is a separate durable fact, never inferred from receipt ACK.
 * Current H epoch fences earlier prepared sends before this transaction reads O.
 * Terminal operation rows are the permanent idempotency record. No VM-state CAS
 * is needed for already terminal work, including a since-superseded generation.
 */
export async function confirmOperationReceipt(
  input: FencedRelayInput & {
    written: boolean;
    state: string;
    requeued?: RequeueConfirmation;
  },
) {
  // WP6: a requeued attempt was confirmed in its own result transaction; no
  // IO may run between that commit and this frame's send.
  if (input.requeued) return input.requeued;
  // A terminal download can report unknown after losing transient bytes. Its
  // exact-binding terminal row is still confirmation authority. A genuinely
  // unknown server row never matches below. The host requires a local Result
  // or the explicit cleanup-bound settlement below. Live UNKNOWN is not authority.
  if (!input.receipt && (!input.written || input.state === "unknown_outcome")) return null;
  // Plan §10: an exact UNKNOWN `command.run` receipt whose row the server
  // recorded UNKNOWN is answered `retireCommand`: the host retires it on its
  // own proof that the command can no longer run, the row stays UNKNOWN, and
  // no sandbox stop is involved. Never for a template-build sandbox (D1: its
  // VM refuses process control).
  const retirable = input.receipt?.kind === "command.run" && input.state === "unknown_outcome";
  return relayTransaction(async (tx) => {
    // Offload §8.10: terminal work of a now-hostless sandbox is confirmed to
    // the host it was dispatched to, on retained placement evidence.
    await bindInboundWorkload(tx, input, requireRelayReceiptWorkload);
    await lockHostByEpoch(
      tx,
      input.sender.hostId,
      input.sender.connectionEpoch,
      input.sender.userId,
    );
    await requireRelayReceiptWorkload(tx, input.sender, input);
    const operation = await tx.sandboxOperation.findFirst({
      where: {
        id: input.operationId,
        sandboxId: input.sandboxId,
        userId: workloadOwner(input),
        dispatchedHostId: input.sender.hostId,
        generation: input.generation,
        dispatchAttempt: input.attempt,
        OR: [...RECEIPT_SETTLED_WHERE, ...(retirable ? [RETIRABLE_UNKNOWN_COMMAND_WHERE] : [])],
      },
      select: {
        kind: true,
        state: true,
        requestBodyHash: true,
        requestDigestScheme: true,
        requestDigestKeyId: true,
        idempotencyKey: true,
        dispatchedConnectionEpoch: true,
      },
    });
    requireRelayFence(
      operation != null &&
        operation.dispatchedConnectionEpoch != null &&
        operation.dispatchedConnectionEpoch <= input.sender.connectionEpoch,
    );
    const kind = relayDispatchKind(operation.kind);
    requireRelayFence(kind != null);
    if (input.receipt)
      requireRelayFence(
        requestDigestKeyCurrent(operation) &&
          operation.requestBodyHash === input.receipt.bodyHash &&
          operation.idempotencyKey === input.receipt.idempotencyKey &&
          kind === input.receipt.kind,
      );
    else requireRelayFence(operation.dispatchedConnectionEpoch === input.sender.connectionEpoch);
    const retireCommand = operation.state === "UNKNOWN_OUTCOME";
    requireRelayFence(!retireCommand || (retirable && kind === "command.run"));
    // UNKNOWN host receipts are not terminal locally. Permanent server history
    // (including superseded CANCELLED and lease-expired FAILED) plus positive
    // later cleanup on this host authorizes retirement without pretending the
    // original effect succeeded. A still-UNKNOWN server row never reaches here.
    const cleanup =
      input.receipt && input.state === "unknown_outcome" && !retireCommand
        ? await tx.sandboxOperation.findFirst({
            where: {
              userId: workloadOwner(input),
              sandboxId: input.sandboxId,
              dispatchedHostId: input.sender.hostId,
              dispatchedConnectionEpoch: { lte: input.sender.connectionEpoch },
              generation: { gt: input.generation },
              state: "SUCCEEDED",
              OR: [
                { kind: "STOP_SANDBOX", result: { path: ["state"], equals: "stopped" } },
                { kind: "STOP_SANDBOX", result: { path: ["state"], equals: "absent" } },
                { kind: "KILL_SANDBOX", result: { path: ["state"], equals: "deleted" } },
              ],
            },
            select: { generation: true },
            orderBy: { generation: "desc" },
          })
        : null;
    requireRelayFence(input.sender.isCurrent?.() !== false);
    return {
      type: "receipt.confirmed" as const,
      sandboxOwnerId: workloadOwner(input),
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      generation: input.generation,
      attempt: input.attempt,
      bodyHash: operation.requestBodyHash,
      idempotencyKey: operation.idempotencyKey,
      kind,
      ...(cleanup ? { cleanupGeneration: cleanup.generation } : {}),
      ...(retireCommand ? { retireCommand: true as const } : {}),
    };
  }, null);
}

/** Per-adoption stdin redelivery bound: the daemon's reorder buffer limit
 * (`authority.rs` `accept_stdin`: 64 chunks or 1 MiB). */
export const ADOPT_STDIN_MAX_CHUNKS = 64;
export const ADOPT_STDIN_MAX_BYTES = 1024 * 1024;
const ADOPT_CONTROL_SCAN = 512;
/** Rows one adoption may lock: pending controls, the allocation event and
 * the reopenable stdin range, with headroom. */
const ADOPT_LOCK_BOUND = ADOPT_CONTROL_SCAN + ADOPT_STDIN_MAX_CHUNKS + 2;

const ADOPTABLE_STATES: ReadonlySet<OperationState> = new Set([
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
]);

export type AdoptOperationInput = {
  sender: RelaySender;
  sandboxOwnerId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  attempt: number;
  bodyHash: string;
  idempotencyKey: string;
  kind: string;
  phase: "intent" | "effect";
  stdinNextSequence: number | null;
  /** Allocated by the session before this call, for create/reconnect only. */
  allocationSequence?: number;
};

function jsonObject(value: Prisma.JsonValue | null | undefined): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Reconnect adoption: a fresh same-epoch dispatch of the exact attempt
 * `(operationId, generation, attempt)` this host already journaled, sent
 * before `reconcile.complete`. It re-binds the operation, its pending
 * controls and (for launches) its allocation lineage to the sender's epoch.
 * It never creates an attempt, changes the payload, redispatches, or revives
 * a terminal or superseded row. Lock order is the dispatch order
 * K → H → S → O → outbox; no owner admission lock (ADR-003: account deletion
 * is refused while unfinished operations exist). Every refusal is `false`
 * and rolls back every write.
 */
export async function adoptOperation(
  input: AdoptOperationInput,
  clock: LeaseClock = leaseNow,
): Promise<boolean> {
  const { sender } = input;
  const launch = input.kind === "sandbox.create" || input.kind === "sandbox.reconnect";
  if (launch && input.allocationSequence === undefined) return false;
  return relayTransaction(async (tx) => {
    // 1. Immutable identity and the dispatch event (principal, payload), K.
    const located = await tx.sandboxOperation.findFirst({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        dispatchedHostId: sender.hostId,
      },
      select: { kind: true, authorizingKeyId: true, launchMode: true, restoreOffloadId: true },
    });
    requireRelayFence(located != null && relayDispatchKind(located.kind) === input.kind);
    const dispatchEvent = await tx.outboxEvent.findFirst({
      where: {
        userId: input.sandboxOwnerId,
        aggregateType: "sandbox",
        aggregateId: input.sandboxId,
        AND: [
          outboxOperationWhere(input.operationId),
          { payload: { path: ["kind"], equals: input.kind } },
        ],
      },
      orderBy: { id: "asc" },
      select: { id: true, payload: true },
    });
    const payload = jsonObject(dispatchEvent?.payload);
    requireRelayFence(dispatchEvent != null && payload != null);
    if (located.authorizingKeyId)
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${located.authorizingKeyId} FOR SHARE`;
    // 2. H at the sender's epoch, workload binding, S generation/state CAS, O.
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    await requireRelayWorkload(tx, sender, {
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      sandboxOwnerId: input.sandboxOwnerId,
    });
    await casSandboxGeneration(tx, {
      sandboxId: input.sandboxId,
      userId: input.sandboxOwnerId,
      generation: input.generation,
      hostId: sender.hostId,
      states: sandboxStatesForOperation(located),
    });
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.sandboxOwnerId} FOR UPDATE`;
    const op = await tx.sandboxOperation.findFirst({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        generation: input.generation,
        dispatchAttempt: input.attempt,
        dispatchedHostId: sender.hostId,
      },
      select: {
        kind: true,
        state: true,
        errorCode: true,
        dispatchedConnectionEpoch: true,
        requestBodyHash: true,
        requestDigestScheme: true,
        requestDigestKeyId: true,
        idempotencyKey: true,
        authorizingKeyId: true,
        nextStdinSequence: true,
      },
    });
    requireRelayFence(op != null && op.authorizingKeyId === located.authorizingKeyId);
    // 3. Active and not superseded, or a command's interim UNKNOWN (epoch
    // re-bind only; its exact final receipt settles it).
    const interimUnknown =
      op.kind === "RUN_COMMAND" &&
      op.state === "UNKNOWN_OUTCOME" &&
      op.errorCode === "unknown_outcome" &&
      input.phase === "effect";
    requireRelayFence(
      (ADOPTABLE_STATES.has(op.state) && op.errorCode !== "superseded") || interimUnknown,
    );
    requireRelayFence(
      op.dispatchedConnectionEpoch != null &&
        op.dispatchedConnectionEpoch < sender.connectionEpoch &&
        requestDigestKeyCurrent(op) &&
        op.requestBodyHash === input.bodyHash &&
        op.idempotencyKey === input.idempotencyKey,
    );
    const oldEpoch = op.dispatchedConnectionEpoch;
    // 4. Gates that can change while the host is away.
    const now = await leaseTransactionNow(tx, clock);
    const sandbox = await tx.sandbox.findFirst({
      where: { id: input.sandboxId, userId: input.sandboxOwnerId, generation: input.generation },
      select: {
        id: true,
        state: true,
        sandboxHostId: true,
        originHostId: true,
        templateRevisionId: true,
        originPoolId: true,
        leaseExpiresAt: true,
      },
    });
    requireRelayFence(sandbox != null);
    if (launch) requireRelayFence(!isLeaseDeadlinePassed(sandbox.leaseExpiresAt, now));
    if (input.phase === "intent") {
      // Nothing issued yet: a cancellation requested meanwhile wins.
      requireRelayFence(op.state !== "CANCEL_REQUESTED");
      const verdict = await intentReclaimGates(tx, {
        ownerId: input.sandboxOwnerId,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        kind: input.kind,
        payload,
        operationAuthorizingKeyId: op.authorizingKeyId,
        sandbox,
        now,
        // U9.1: from the operation row, never the outbox payload.
        restore: restoreOffloadOf(located) !== null,
      });
      requireRelayFence(verdict === "active");
    }
    // Outbox, in one id-ordered, bounded statement: this operation's pending
    // events, its allocation event, and only the processed stdin events this
    // adoption may reopen (exact attempt, sequences [first, next)). History
    // outside that range is never locked; a backlog past the bound refuses.
    const stdinRange =
      op.kind === "RUN_COMMAND" && input.stdinNextSequence !== null
        ? { first: input.stdinNextSequence, next: op.nextStdinSequence }
        : null;
    if (stdinRange)
      requireRelayFence(
        stdinRange.first <= stdinRange.next &&
          stdinRange.next - stdinRange.first <= ADOPT_STDIN_MAX_CHUNKS,
      );
    const locked = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM sandbox_dispatch_outbox
      WHERE "userId" = ${input.sandboxOwnerId} AND "aggregateType" = 'sandbox'
        AND "aggregateId" = ${input.sandboxId}
        AND ${outboxOperationSql(input.operationId)}
        AND ("processedAt" IS NULL
          OR "eventType" IN ('sandbox.create_requested', 'sandbox.reconnect_requested')
          OR (${stdinRange !== null}
            AND payload->>'kind' = 'process.stdin'
            AND payload->'dispatchAttempt' = to_jsonb(${input.attempt}::int)
            AND jsonb_typeof(payload->'stdinSequence') = 'number'
            AND (payload->>'stdinSequence')::numeric >= ${stdinRange?.first ?? 0}
            AND (payload->>'stdinSequence')::numeric < ${stdinRange?.next ?? 0}))
      ORDER BY id LIMIT ${ADOPT_LOCK_BOUND + 1} FOR UPDATE`;
    requireRelayFence(locked.length <= ADOPT_LOCK_BOUND);
    // 5. Stdin continuity (B1): every chunk the host has not received is
    // re-armed from its own stored event, or the adoption is refused.
    if (op.kind === "RUN_COMMAND" && input.stdinNextSequence !== null) {
      const first = input.stdinNextSequence;
      const next = op.nextStdinSequence;
      if (first < next) {
        const events = await tx.outboxEvent.findMany({
          where: {
            userId: input.sandboxOwnerId,
            aggregateType: "sandbox",
            aggregateId: input.sandboxId,
            AND: [
              outboxOperationWhere(input.operationId),
              { payload: { path: ["kind"], equals: "process.stdin" } },
              { payload: { path: ["dispatchAttempt"], equals: input.attempt } },
              { payload: { path: ["stdinSequence"], gte: first } },
              { payload: { path: ["stdinSequence"], lt: next } },
            ],
          },
          orderBy: { id: "asc" },
          take: 2 * ADOPT_STDIN_MAX_CHUNKS + 2,
          select: { id: true, processedAt: true, payload: true },
        });
        let bytes = 0;
        const reopen: string[] = [];
        for (let sequence = first; sequence < next; sequence++) {
          const matching = events.filter(
            (event) => jsonObject(event.payload)?.stdinSequence === sequence,
          );
          requireRelayFence(matching.length === 1);
          const event = matching[0]!;
          const body = jsonObject(event.payload)!;
          requireRelayFence(body.dispatchRefusal === undefined);
          bytes +=
            typeof body.stdinBase64 === "string"
              ? Buffer.byteLength(body.stdinBase64, "base64")
              : 0;
          requireRelayFence(bytes <= ADOPT_STDIN_MAX_BYTES);
          if (event.processedAt !== null) reopen.push(event.id);
        }
        for (const id of reopen) {
          const reopened = await tx.outboxEvent.updateMany({
            where: { id, userId: input.sandboxOwnerId, aggregateId: input.sandboxId },
            data: {
              processedAt: null,
              sentAt: null,
              claimToken: null,
              claimedAt: null,
              sentConnectionEpoch: null,
            },
          });
          requireRelayFence(reopened.count === 1);
        }
      }
    }
    // 6. Controls (M1): pending cancel/stdin follow the operation's new epoch.
    const controls = await tx.outboxEvent.findMany({
      where: {
        userId: input.sandboxOwnerId,
        aggregateType: "sandbox",
        aggregateId: input.sandboxId,
        processedAt: null,
        ...outboxOperationWhere(input.operationId),
      },
      orderBy: { id: "asc" },
      take: ADOPT_CONTROL_SCAN,
      select: { id: true, payload: true },
    });
    // A backlog beyond the bound cannot be re-bound in full: refuse instead of
    // stranding the remainder on the old epoch.
    requireRelayFence(controls.length < ADOPT_CONTROL_SCAN);
    for (const event of controls) {
      const body = jsonObject(event.payload);
      if (
        !body ||
        (body.kind !== "process.stdin" && body.kind !== "operation.cancel") ||
        body.connectionEpoch !== oldEpoch
      )
        continue;
      const rewritten = await tx.outboxEvent.updateMany({
        where: {
          id: event.id,
          userId: input.sandboxOwnerId,
          aggregateId: input.sandboxId,
          processedAt: null,
        },
        // Invalidate any old-epoch delivery claim too: a delayed old sender's
        // finalizer matches its claim token and send epoch, and must not
        // retire (or mark sent) an event that now belongs to this epoch.
        data: {
          payload: { ...body, connectionEpoch: sender.connectionEpoch } as Prisma.InputJsonObject,
          sentAt: null,
          claimToken: null,
          claimedAt: null,
          sentConnectionEpoch: null,
        },
      });
      requireRelayFence(rewritten.count === 1);
    }
    const adopted = await tx.sandboxOperation.updateMany({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        generation: input.generation,
        dispatchAttempt: input.attempt,
        dispatchedHostId: sender.hostId,
        dispatchedConnectionEpoch: oldEpoch,
        state: op.state,
      },
      data: {
        dispatchedConnectionEpoch: sender.connectionEpoch,
        acceptedAttempt: input.attempt,
        ...(op.state === "DISPATCHED" ? { state: "ACCEPTED" as const } : {}),
      },
    });
    requireRelayFence(adopted.count === 1);
    if (op.state === "DISPATCHED")
      await tx.outboxEvent.updateMany({
        where: {
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          userId: input.sandboxOwnerId,
          processedAt: null,
          AND: [
            outboxOperationWhere(input.operationId),
            { payload: { path: ["kind"], equals: input.kind } },
          ],
        },
        data: { processedAt: now },
      });
    // 7. Allocation lineage (M3): the same durable journal, re-bound to this
    // epoch with a fresh pre-barrier dispatch sequence.
    if (launch) {
      const allocation = await tx.outboxEvent.findFirst({
        where: {
          userId: input.sandboxOwnerId,
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          eventType: { in: ["sandbox.create_requested", "sandbox.reconnect_requested"] },
          ...outboxOperationWhere(input.operationId),
        },
        orderBy: { id: "asc" },
        select: { id: true, payload: true },
      });
      const lineage = jsonObject(allocation?.payload);
      const host = await tx.sandboxHost.findFirst({
        where: {
          id: sender.hostId,
          userId: sender.userId,
          connectionEpoch: sender.connectionEpoch,
        },
        select: { admissionEpoch: true, daemonFeatures: true },
      });
      const journalId = jsonObject(host?.daemonFeatures ?? null)?.journalId;
      requireRelayFence(
        allocation != null &&
          lineage != null &&
          host?.admissionEpoch === sender.connectionEpoch &&
          typeof journalId === "string" &&
          /^[0-9a-f]{32}$/.test(journalId) &&
          lineage.allocationJournalId === journalId &&
          lineage.allocationJournalAttempt === input.attempt &&
          lineage.allocationJournalEpoch === oldEpoch,
      );
      const bound = await tx.outboxEvent.updateMany({
        where: { id: allocation.id, userId: input.sandboxOwnerId, aggregateId: input.sandboxId },
        data: {
          payload: {
            ...lineage,
            allocationJournalEpoch: sender.connectionEpoch,
            allocationDispatchSequence: input.allocationSequence,
          } as Prisma.InputJsonObject,
        },
      });
      requireRelayFence(bound.count === 1);
    }
    // 8. The sender is still the registered current socket.
    requireRelayFence(sender.isCurrent?.() !== false);
    return true;
  }, false);
}

/** Attempt at which a dispatch audit stops requeueing work the host proved
 * undelivered on every earlier attempt too (E4-01): non-lifecycle work settles
 * FAILED, create/reconnect work is left to allocation reconciliation.
 * Stop/kill keeps requeueing until teardown completes. */
export const UNDELIVERED_REDISPATCH_MAX_ATTEMPT = 5;

export type DispatchAuditEntry = {
  sandboxOwnerId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  attempt: number;
  connectionEpoch: number;
  idempotencyKey: string;
  kind: string;
};

/**
 * Reconnect dispatch audit, page source: attempts this host was sent on an
 * older epoch that it never acknowledged (DISPATCHED, or CANCEL_REQUESTED
 * before acceptance), not superseded, ordered by id after `cursor`. Live
 * finding B-1: such a frame can die with the transport; the host's verdict
 * decides between redispatch and the reconciliation's UNKNOWN.
 */
export async function listUnacknowledgedDispatches(
  sender: RelaySender,
  cursor: string | undefined,
  take: number,
): Promise<{ entries: DispatchAuditEntry[]; complete: boolean; cursor?: string }> {
  const rows = await relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    return tx.sandboxOperation.findMany({
      where: {
        Sandbox: { hostOwnerId: sender.userId, sandboxHostId: sender.hostId },
        dispatchedHostId: sender.hostId,
        dispatchedConnectionEpoch: { lt: sender.connectionEpoch },
        state: { in: ["DISPATCHED", "CANCEL_REQUESTED"] },
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      orderBy: { id: "asc" },
      take,
      select: {
        id: true,
        userId: true,
        sandboxId: true,
        generation: true,
        dispatchAttempt: true,
        acceptedAttempt: true,
        dispatchedConnectionEpoch: true,
        idempotencyKey: true,
        kind: true,
        errorCode: true,
      },
    });
  }, null);
  if (rows == null) return { entries: [], complete: true };
  const entries: DispatchAuditEntry[] = [];
  for (const row of rows) {
    const kind = relayDispatchKind(row.kind);
    if (
      kind == null ||
      row.errorCode === "superseded" ||
      row.acceptedAttempt === row.dispatchAttempt ||
      row.dispatchAttempt < 1 ||
      row.dispatchedConnectionEpoch == null
    )
      continue;
    entries.push({
      sandboxOwnerId: row.userId,
      operationId: row.id,
      sandboxId: row.sandboxId,
      generation: row.generation,
      attempt: row.dispatchAttempt,
      connectionEpoch: row.dispatchedConnectionEpoch,
      idempotencyKey: row.idempotencyKey,
      kind,
    });
  }
  return {
    entries,
    complete: rows.length < take,
    ...(rows.length > 0 ? { cursor: rows[rows.length - 1]!.id } : {}),
  };
}

/**
 * The host proved it never received this exact attempt (it attached that
 * epoch in this process and its journal has no record of the operation).
 * Under the dispatch lock order (K → H → S → O → outbox), the attempt is
 * treated as never dispatched: a cancel requested meanwhile settles it
 * CANCELLED; otherwise it is dispatched again on this epoch (back to QUEUED,
 * claimed as attempt + 1 after reconciliation), or, for non-lifecycle work
 * a fresh dispatch would refuse or that reached
 * `UNDELIVERED_REDISPATCH_MAX_ATTEMPT`, settled FAILED `host_effect_not_issued`;
 * create/reconnect at that bound stays DISPATCHED (`false`) for allocation
 * reconciliation; stop/kill keeps requeueing until cleanup completes.
 * Fenced like adoption: exact identity tuple, older epoch,
 * never acknowledged, not superseded, generation/state CAS, workload binding.
 */
type UndeliveredVerdict = "requeued" | "cancelled" | "failed" | false;
export async function settleUndeliveredDispatch(
  input: Omit<DispatchAuditEntry, "connectionEpoch"> & { sender: RelaySender },
  clock: LeaseClock = leaseNow,
): Promise<UndeliveredVerdict> {
  const { sender } = input;
  // WP5 groundwork: what each proven-undelivered strike looked like.
  let strike: { sendToEpochEndMs: number | null } | undefined;
  const verdict = await relayTransaction<UndeliveredVerdict>(async (tx) => {
    const located = await tx.sandboxOperation.findFirst({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        dispatchedHostId: sender.hostId,
      },
      select: { kind: true, authorizingKeyId: true, launchMode: true, restoreOffloadId: true },
    });
    requireRelayFence(located != null && relayDispatchKind(located.kind) === input.kind);
    if (located.authorizingKeyId)
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${located.authorizingKeyId} FOR SHARE`;
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    await requireRelayWorkload(tx, sender, {
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      sandboxOwnerId: input.sandboxOwnerId,
    });
    await casSandboxGeneration(tx, {
      sandboxId: input.sandboxId,
      userId: input.sandboxOwnerId,
      generation: input.generation,
      hostId: sender.hostId,
      states: sandboxStatesForOperation(located),
    });
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.sandboxOwnerId} FOR UPDATE`;
    const op = await tx.sandboxOperation.findFirst({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        generation: input.generation,
        dispatchAttempt: input.attempt,
        dispatchedHostId: sender.hostId,
      },
      select: {
        kind: true,
        state: true,
        errorCode: true,
        acceptedAttempt: true,
        dispatchedConnectionEpoch: true,
        idempotencyKey: true,
        authorizingKeyId: true,
        completedAt: true,
        dispatchedAt: true,
      },
    });
    requireRelayFence(
      op != null &&
        (op.state === "DISPATCHED" || op.state === "CANCEL_REQUESTED") &&
        op.errorCode !== "superseded" &&
        op.acceptedAttempt !== input.attempt &&
        op.idempotencyKey === input.idempotencyKey &&
        op.dispatchedConnectionEpoch != null &&
        op.dispatchedConnectionEpoch < sender.connectionEpoch,
    );
    const now = await leaseTransactionNow(tx, clock);
    // The sending epoch's end is the host's last disconnect only when exactly
    // one revoke (+1) and one hello (+1) separate it from this session.
    const host = await tx.sandboxHost.findFirst({
      where: { id: sender.hostId, connectionEpoch: sender.connectionEpoch },
      select: { lastDisconnectedAt: true },
    });
    strike = {
      sendToEpochEndMs:
        op.dispatchedConnectionEpoch + 2 === sender.connectionEpoch &&
        op.dispatchedAt != null &&
        host?.lastDisconnectedAt != null
          ? host.lastDisconnectedAt.getTime() - op.dispatchedAt.getTime()
          : null,
    };
    await prelockOperationOutbox(tx, input.sandboxOwnerId, input.sandboxId, input.operationId);
    const fence = {
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      userId: input.sandboxOwnerId,
      generation: input.generation,
      attempt: input.attempt,
      hostId: sender.hostId,
    };
    const retire = () =>
      tx.outboxEvent.updateMany({
        where: {
          userId: input.sandboxOwnerId,
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          processedAt: null,
          ...outboxOperationWhere(input.operationId),
        },
        data: { processedAt: now },
      });
    const settle = async (state: "CANCELLED" | "FAILED", code: SandboxErrorCode) => {
      await casActiveOperation(tx, fence, {
        state,
        completedAt: op.completedAt ?? now,
        errorCode: code,
        errorDetail: safeOperationError(code).message,
      });
      // Never delivered: no host result will settle its credential work.
      await settleOperationCredentials(tx, {
        sandboxId: input.sandboxId,
        operation: { id: input.operationId, kind: op.kind, dispatchAttempt: input.attempt },
        opState: state,
      });
      noteHostBlockerReleased(tx, sender.hostId, sender.userId);
      noteTerminalResultRelease(tx, input.sandboxOwnerId, { operationId: input.operationId });
      await retire();
    };
    if (op.state === "CANCEL_REQUESTED") {
      // Cancelled before it ever reached the host: a definite outcome.
      requireRelayFence(!isLifecycleOperationKind(op.kind));
      await settle("CANCELLED", "cancelled");
      requireRelayFence(sender.isCurrent?.() !== false);
      return "cancelled";
    }
    // Bound repeatedly undelivered allocations: reconciliation marks them
    // UNKNOWN, then allocation attestation settles them. Teardown must keep
    // requeueing until it completes; per-operation host refusals cannot loop
    // the session. Non-lifecycle work settles as never issued at the bound.
    if (input.attempt >= UNDELIVERED_REDISPATCH_MAX_ATTEMPT) {
      if (op.kind === "CREATE_SANDBOX" || op.kind === "RECONNECT_SANDBOX") return false;
      if (!isLifecycleOperationKind(op.kind)) {
        await settle("FAILED", "host_effect_not_issued");
        requireRelayFence(sender.isCurrent?.() !== false);
        return "failed";
      }
    }
    if (!isLifecycleOperationKind(op.kind)) {
      const event = await tx.outboxEvent.findFirst({
        where: {
          userId: input.sandboxOwnerId,
          aggregateType: "sandbox",
          aggregateId: input.sandboxId,
          AND: [
            outboxOperationWhere(input.operationId),
            { payload: { path: ["kind"], equals: input.kind } },
          ],
        },
        orderBy: { id: "asc" },
        select: { payload: true },
      });
      const payload = jsonObject(event?.payload);
      const sandbox = await tx.sandbox.findFirst({
        where: { id: input.sandboxId, userId: input.sandboxOwnerId },
        select: {
          id: true,
          state: true,
          sandboxHostId: true,
          originHostId: true,
          templateRevisionId: true,
          originPoolId: true,
        },
      });
      requireRelayFence(payload != null && sandbox != null);
      const verdict = await intentReclaimGates(tx, {
        ownerId: input.sandboxOwnerId,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        kind: input.kind,
        payload,
        operationAuthorizingKeyId: op.authorizingKeyId,
        sandbox,
        now,
        // U9.1: from the operation row, never the outbox payload.
        restore: restoreOffloadOf(located) !== null,
      });
      requireRelayFence(verdict !== "indeterminate");
      if (verdict === "refused") {
        // A fresh dispatch would refuse it: never issued, definitely.
        await settle("FAILED", "host_effect_not_issued");
        requireRelayFence(sender.isCurrent?.() !== false);
        return "failed";
      }
    }
    const requeued = await tx.sandboxOperation.updateMany({
      where: {
        id: input.operationId,
        userId: input.sandboxOwnerId,
        sandboxId: input.sandboxId,
        generation: input.generation,
        dispatchAttempt: input.attempt,
        dispatchedHostId: sender.hostId,
        dispatchedConnectionEpoch: op.dispatchedConnectionEpoch,
        state: "DISPATCHED",
      },
      data: { state: "QUEUED" },
    });
    requireRelayFence(requeued.count === 1);
    await reopenDispatchIntent(tx, {
      ownerId: input.sandboxOwnerId,
      sandboxId: input.sandboxId,
      operationId: input.operationId,
      kind: input.kind,
    });
    requireRelayFence(sender.isCurrent?.() !== false);
    return "requeued";
  }, false);
  // A strike is an undelivered attempt that was requeued or hit the bound
  // (a cancel is not one). WP5 will count only strikes whose sending epoch
  // ended within 5 s of the send; this records the data to size that rule.
  if (strike && (verdict === "requeued" || verdict === "failed"))
    console.info("[sandbox-relay] undelivered dispatch strike:", {
      code: "undelivered_dispatch_strike",
      kind: input.kind,
      attempt: input.attempt,
      verdict,
      sendToEpochEndMs: strike.sendToEpochEndMs,
    });
  return verdict;
}
