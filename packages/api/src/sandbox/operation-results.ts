import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma as PrismaTypes } from "@wssp/db";
import { Prisma } from "@wssp/db/client";
import {
  encodedJsonBytes,
  isResultKind,
  type OperationResult,
  OUTPUT_RETENTION_MS,
  operationOutcome,
  operationResultSchema,
  RESULT_LIMITS,
  resultBodySchema,
  resultContinuationSchema,
  SDK_ERRORS,
} from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceProcedure } from "../lib/sdk-key-access";
import { resultActionForOperationKind } from "../lib/service-scopes";
import type { Principal } from "./contracts";
import { operationNotFound } from "./errors";
import { outboxOperationWhere } from "./outbox-operation";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  requireObserved,
  requireRelayFence,
  requireResultCompatible,
} from "./relay-fence";
import { assertBeforeResultQuota, lockResultQuota, resultOutboxLockQuery } from "./result-locks";

type Tx = PrismaTypes.TransactionClient;
const CONTENT_KINDS = ["STAT_PATH", "LIST_DIR", "MOVE_PATH", "LIST_PROCESSES"] as const;
export function isContentResultKind(kind: string): kind is (typeof CONTENT_KINDS)[number] {
  return (CONTENT_KINDS as readonly string[]).includes(kind);
}
/** B1-C-7: a scalar-result operation (command, mkdir, remove, signal)
 * accepted under 10.5 carries the result version from creation, so an
 * in-flight or failed-before-start row reads as versioned (pending/failed),
 * never as legacy UNSUPPORTED. Content kinds are versioned by their hold. */
export function initialResultFields(kind: string, fsProcess: boolean) {
  return fsProcess && isResultKind(kind) && !isContentResultKind(kind)
    ? { resultVersion: RESULT_LIMITS.resultVersion, resultExpiresAt: null }
    : {};
}
/** Every accepted command is born bound to a fresh opaque process identity;
 * the relay repeats it on dispatch and the host on every process frame. */
export function initialProcessFields(kind: string) {
  return kind === "RUN_COMMAND" ? { processId: randomUUID() } : {};
}
function resultError(
  code:
    | "OPERATION_RESULT_NOT_READY"
    | "OPERATION_RESULT_UNSUPPORTED"
    | "OPERATION_RESULT_EXPIRED"
    | "OPERATION_RESULT_QUOTA"
    | "RESULT_CURSOR_INVALID"
    | "RESULT_CURSOR_STALE",
) {
  return new ORPCError(code, {
    status: SDK_ERRORS[code][0],
    message: SDK_ERRORS[code][1],
    data: { code, ...(code === "OPERATION_RESULT_QUOTA" ? { retryAfterSeconds: 60 } : {}) },
  });
}
/** O rows must already be held. Outbox rows are acquired in one sorted pass,
 * then global transfer quota → one owner result quota → children. */
async function resultSuffix(
  tx: Tx,
  ownerId: string,
  operationIds: readonly string[],
  sandboxIds: readonly string[],
) {
  // B1-C-5 (deferred to slice 6A): at most 100 operations per suffix; a 6A
  // caller with more must split into separate transactions.
  if (operationIds.length === 0 || operationIds.length > 100 || sandboxIds.length === 0)
    throw new Error("Invalid result lock batch.");
  // Reentry may only touch the same set; lockResultQuota rejects expansion.
  // The first call locks outbox before quota, subsequent calls do no prefix IO.
  if (!heldSuffix.has(tx)) {
    await tx.$queryRaw(resultOutboxLockQuery(ownerId, { sandboxIds, operationIds }));
    await lockResultQuota(tx, ownerId, operationIds);
    heldSuffix.add(tx);
  } else await lockResultQuota(tx, ownerId, operationIds);
}
const heldSuffix = new WeakSet<object>();

const REQUEST_EVENT_BY_KIND = {
  STAT_PATH: "sandbox.file_stat_requested",
  LIST_DIR: "sandbox.file_list_requested",
  MOVE_PATH: "sandbox.file_move_requested",
  LIST_PROCESSES: "sandbox.process_list_requested",
} as const satisfies Record<(typeof CONTENT_KINDS)[number], string>;
/** The accepted guest path in the form a host reports it: `//` and `.`
 * collapse; `..` was refused at acceptance and is refused here again. */
function normalizedRequestPath(value: unknown): string {
  requireRelayFence(typeof value === "string" && value.startsWith("/"));
  const parts = value.split("/").filter((part) => part !== "" && part !== ".");
  requireRelayFence(!parts.includes(".."));
  return `/${parts.join("/")}`;
}
/** B1-T-2: content must describe the stored request, read from the
 * operation's own immutable request event before any suffix lock. */
async function requireResultMatchesRequest(
  tx: Tx,
  ownerId: string,
  op: { id: string; sandboxId: string; kind: string },
  payload: OperationResult["result"],
  continuation: { limit: number } | null,
) {
  requireRelayFence(isContentResultKind(op.kind));
  const event = await tx.outboxEvent.findFirst({
    where: {
      userId: ownerId,
      aggregateType: "sandbox",
      aggregateId: op.sandboxId,
      eventType: REQUEST_EVENT_BY_KIND[op.kind],
      ...outboxOperationWhere(op.id),
    },
    select: { payload: true },
    orderBy: { createdAt: "asc" },
  });
  const request = event?.payload;
  requireResultCompatible(
    typeof request === "object" && request !== null && !Array.isArray(request),
  );
  const args = request as Record<string, unknown>;
  // The accepted request is immutable: evidence for another path or shape
  // can never apply. Process-list items below compare with birth bindings
  // the server may still record, so they stay plain fences.
  if (payload?.type === "file.stat")
    requireResultCompatible(payload.entry.path === normalizedRequestPath(args.path));
  else if (payload?.type === "file.rename")
    requireResultCompatible(payload.entry.path === normalizedRequestPath(args.destPath));
  else if (payload?.type === "file.list") {
    const limit = args.limit ?? RESULT_LIMITS.listDefaultLimit;
    requireResultCompatible(
      payload.path === normalizedRequestPath(args.path) &&
        payload.depth === (args.depth ?? 1) &&
        typeof limit === "number" &&
        payload.items.length <= limit &&
        (continuation === null || continuation.limit === limit),
    );
  } else if (payload?.type === "process.list") {
    const commands = await tx.sandboxOperation.findMany({
      where: {
        userId: ownerId,
        sandboxId: op.sandboxId,
        kind: "RUN_COMMAND",
        id: { in: payload.items.map((item) => item.operationId) },
      },
      select: {
        id: true,
        generation: true,
        dispatchAttempt: true,
        processId: true,
        processPid: true,
        processStartedAt: true,
        processDescription: true,
        state: true,
        resultVersion: true,
      },
      take: RESULT_LIMITS.listMaxLimit,
    });
    // Every permanent check runs over the WHOLE page before any item can make
    // it pending, so a later item's wrong identity is never masked by an
    // earlier item still waiting for its birth.
    const limit = args.limit ?? RESULT_LIMITS.listDefaultLimit;
    requireResultCompatible(
      typeof limit === "number" &&
        payload.items.length <= limit &&
        (continuation === null || continuation.limit === limit),
    );
    const listed = payload.items.map((item) => {
      const command = commands.find((row) => row.id === item.operationId);
      // Immutable identity: the command, its generation, attempt and process
      // id never change, so any mismatch there is permanent.
      requireRelayFence(
        command !== undefined &&
          command.generation === item.process.generation &&
          command.dispatchAttempt === item.process.attempt &&
          command.processId === item.process.processId,
      );
      // Older/expired descriptions have no server label to compare; their
      // labels remain host observations, with incarnation ownership still bound.
      const description = command.processDescription;
      if (description !== null) {
        requireRelayFence(typeof description === "object" && !Array.isArray(description));
        const stored = description as Record<string, unknown>;
        // Dispatch and host use the same bounded accepted-intent description.
        // A truncated args array is still an exact comparable prefix (scripts
        // deliberately omit their bodies); omitted suffixes are not attested.
        requireRelayFence(
          item.cmd === stored.cmd &&
            item.cwd === stored.cwd &&
            item.argsTruncated === stored.argsTruncated &&
            JSON.stringify(item.args) === JSON.stringify(stored.args),
        );
      }
      return { item, command };
    });
    // A matching command whose birth the server has not recorded yet is a
    // pending observation only while it can still acquire one: the birth
    // binder (operation-handlers.ts bindProcessBirth) accepts a versioned
    // command that is not terminal. A terminal command without a birth never
    // gets one, so that mismatch is as permanent as any other.
    for (const { command } of listed)
      requireObserved(
        command.processPid !== null ||
          command.resultVersion !== 1 ||
          ["SUCCEEDED", "FAILED", "CANCELLED"].includes(command.state),
      );
    for (const { item, command } of listed)
      requireRelayFence(
        command.processPid === item.process.pid &&
          command.processStartedAt?.toISOString() === new Date(item.startedAt).toISOString(),
      );
  }
}

/** Inactive until feature acceptance calls it. Existing holds never reopen. */
export async function reserveOperationResult(
  tx: Tx,
  input: { ownerId: string; operationId: string; inheritedExpiresAt?: Date },
) {
  const op = await tx.sandboxOperation.findFirst({
    where: { id: input.operationId, userId: input.ownerId },
    select: {
      id: true,
      sandboxId: true,
      kind: true,
      generation: true,
      dispatchAttempt: true,
      state: true,
      resultVersion: true,
    },
  });
  requireRelayFence(op !== null && isContentResultKind(op.kind));
  await resultSuffix(tx, input.ownerId, [op.id], [op.sandboxId]);
  const now = await hostDatabaseNow(tx);
  // Version is the durable tombstone even after physical content deletion.
  if (op.resultVersion !== null || op.state !== "QUEUED" || op.dispatchAttempt !== 0) return false;
  const ownDeadline =
    now.getTime() +
    (op.kind === "MOVE_PATH"
      ? RESULT_LIMITS.mutationContentRetentionMs
      : RESULT_LIMITS.observationRetentionMs);
  const expiresAt = new Date(
    Math.min(ownDeadline, input.inheritedExpiresAt?.getTime() ?? ownDeadline),
  );
  if (expiresAt <= now) throw resultError("OPERATION_RESULT_EXPIRED");
  const used = await tx.sandboxOperationResult.aggregate({
    where: { userId: input.ownerId, expiresAt: { gt: now } },
    _sum: { reservationBytes: true },
  });
  if (
    (used._sum.reservationBytes ?? 0) + RESULT_LIMITS.hostResultMaxBytes >
    RESULT_LIMITS.ownerReservedMaxBytes
  )
    throw resultError("OPERATION_RESULT_QUOTA");
  await tx.sandboxOperation.update({
    where: { id: op.id },
    data: {
      resultVersion: RESULT_LIMITS.resultVersion,
      resultExpiresAt: expiresAt,
      resultObservedAt: now,
    },
  });
  await tx.sandboxOperationResult.create({
    data: {
      operationId: op.id,
      sandboxId: op.sandboxId,
      userId: input.ownerId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      version: RESULT_LIMITS.resultVersion,
      expiresAt,
      reservationBytes: RESULT_LIMITS.hostResultMaxBytes,
    },
  });
  return true;
}

/** The relay-verified sender of a result frame (host plus its live epoch). */
export type ResultSender = { hostId: string; connectionEpoch: number };
/** B1-T-1/B1-C-6: the store re-checks the dispatch binding itself, inside the
 * caller's transaction, so no ingress path can skip the host/epoch fence. */
function requireDispatchedTo(
  op: {
    dispatchedHostId: string | null;
    dispatchedConnectionEpoch: number | null;
    dispatchAttempt: number;
  },
  sender: ResultSender,
  attempt: number,
) {
  requireRelayFence(
    attempt >= 1 &&
      op.dispatchAttempt === attempt &&
      op.dispatchedHostId === sender.hostId &&
      op.dispatchedConnectionEpoch === sender.connectionEpoch,
  );
}
const dispatchSelect = {
  dispatchAttempt: true,
  dispatchedHostId: true,
  dispatchedConnectionEpoch: true,
} satisfies PrismaTypes.SandboxOperationSelect;

/** Caller holds O. The dispatch binding (host, epoch, attempt) is re-checked
 * here. No content is acknowledged by the caller until this transaction commits. */
export async function publishOperationResult(
  tx: Tx,
  input: {
    ownerId: string;
    operationId: string;
    sender: ResultSender;
    attempt: number;
    payload: unknown;
    continuation?: unknown;
    observedAt: Date;
  },
) {
  assertBeforeResultQuota(tx);
  await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.ownerId} FOR UPDATE`;
  const op = await tx.sandboxOperation.findFirst({
    where: { id: input.operationId, userId: input.ownerId },
    select: {
      id: true,
      sandboxId: true,
      kind: true,
      generation: true,
      state: true,
      resultVersion: true,
      resultExpiresAt: true,
      ...dispatchSelect,
    },
  });
  requireRelayFence(op !== null && isContentResultKind(op.kind) && op.resultVersion === 1);
  requireDispatchedTo(op, input.sender, input.attempt);
  const payload = resultBodySchema.parse(input.payload);
  const continuation =
    input.continuation == null ? null : resultContinuationSchema.parse(input.continuation);
  const wireBytes = encodedJsonBytes({ payload, continuation });
  requireResultCompatible(wireBytes <= RESULT_LIMITS.hostResultMaxBytes);
  // The columns store these JSON values separately; SQL NULL continuation has
  // no retained JSON bytes. The wire wrapper still counts toward the host cap.
  const bytes =
    encodedJsonBytes(payload) + (continuation === null ? 0 : encodedJsonBytes(continuation));
  operationResultSchema.parse({
    operationId: op.id,
    sandboxId: op.sandboxId,
    generation: op.generation,
    kind: op.kind,
    outcome: operationOutcome(op.state),
    observedAt: input.observedAt.toISOString(),
    expiresAt: op.resultExpiresAt?.toISOString() ?? null,
    result: payload,
  });
  if (payload.type === "file.list" || payload.type === "process.list") {
    requireResultCompatible((payload.nextCursor !== null) === (continuation !== null));
    if (continuation)
      requireResultCompatible(payload.nextCursor === op.id && payload.items.length > 0);
  } else requireResultCompatible(continuation === null);
  if (continuation)
    requireResultCompatible(
      continuation.kind === op.kind &&
        continuation.generation === op.generation &&
        (payload.type === "file.list" || payload.type === "process.list") &&
        payload.nextCursor === op.id,
    );
  if (continuation && payload.type === "file.list") {
    const last = payload.items[payload.items.length - 1];
    const prefix = payload.path === "/" ? "/" : `${payload.path}/`;
    requireResultCompatible(
      last !== undefined &&
        continuation.root === payload.path &&
        continuation.depth === payload.depth &&
        continuation.limit >= payload.items.length &&
        continuation.lastKey === last.path.slice(prefix.length),
    );
  }
  if (continuation && payload.type === "process.list") {
    const last = payload.items[payload.items.length - 1];
    requireResultCompatible(
      last !== undefined &&
        continuation.limit >= payload.items.length &&
        continuation.lastKey === JSON.stringify([last.startedAt, last.process.processId]),
    );
  }
  await requireResultMatchesRequest(tx, input.ownerId, op, payload, continuation);
  await resultSuffix(tx, input.ownerId, [op.id], [op.sandboxId]);
  const now = await hostDatabaseNow(tx);
  const hold = await tx.sandboxOperationResult.findFirst({
    where: { operationId: op.id, userId: input.ownerId, generation: op.generation },
  });
  if (!hold || hold.reservationState === "RELEASED" || hold.reservationState === "EXPIRED")
    return false;
  if (hold.expiresAt <= now) {
    await tx.sandboxOperationResult.update({
      where: { operationId: op.id },
      data: {
        reservationState: "EXPIRED",
        reservationBytes: 0,
        payload: Prisma.DbNull,
        continuation: Prisma.DbNull,
      },
    });
    return false;
  }
  if (hold.reservationState === "PUBLISHED") {
    requireResultCompatible(
      isDeepStrictEqual(hold.payload, payload) &&
        isDeepStrictEqual(hold.continuation, continuation),
    );
    return true;
  }
  await tx.sandboxOperationResult.update({
    where: { operationId: op.id },
    data: {
      attempt: input.attempt,
      payload,
      continuation: continuation ?? Prisma.DbNull,
      reservationBytes: bytes,
      reservationState: "PUBLISHED",
    },
  });
  await tx.sandboxOperation.update({
    where: { id: op.id },
    data: { resultObservedAt: input.observedAt },
  });
  return true;
}

/** All terminal no-content writers call this after their O/outbox writes.
 * UNKNOWN_OUTCOME retains its hold unless lifecycle evidence finalizes it. */
export async function releaseTerminalOperationResults(
  tx: Tx,
  ownerId: string,
  operationIds: readonly string[],
  authoritativeUnknown = false,
) {
  if (operationIds.length === 0) return 0;
  const candidates = await tx.sandboxOperationResult.findMany({
    where: {
      userId: ownerId,
      operationId: { in: [...operationIds] },
      reservationState: "RESERVED",
      Operation: {
        state: {
          in: authoritativeUnknown
            ? ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"]
            : ["SUCCEEDED", "FAILED", "CANCELLED"],
        },
      },
    },
    select: { operationId: true },
    orderBy: { operationId: "asc" },
    take: 100,
  });
  if (candidates.length === 0) return 0;
  // O rows are held by the caller; their sandbox ids key the outbox index.
  const sandboxIds = await tx.sandboxOperation.findMany({
    where: { userId: ownerId, id: { in: [...operationIds] } },
    select: { sandboxId: true },
    distinct: ["sandboxId"],
    take: 100,
  });
  await resultSuffix(
    tx,
    ownerId,
    operationIds,
    sandboxIds.map((row) => row.sandboxId),
  );
  return (
    await tx.sandboxOperationResult.updateMany({
      where: {
        userId: ownerId,
        operationId: { in: candidates.map((row) => row.operationId) },
        reservationState: "RESERVED",
      },
      data: {
        reservationState: "RELEASED",
        reservationBytes: 0,
        payload: Prisma.DbNull,
        continuation: Prisma.DbNull,
      },
    })
  ).count;
}

/** Small permanent evidence has no paths/description and consumes no hold.
 * Caller holds O; the dispatch binding and process identity are re-checked. */
export async function storeScalarOperationResult(
  tx: Tx,
  input: {
    ownerId: string;
    operationId: string;
    sender: ResultSender;
    attempt: number;
    payload: unknown;
    observedAt: Date;
  },
) {
  assertBeforeResultQuota(tx);
  await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.ownerId} FOR UPDATE`;
  const op = await tx.sandboxOperation.findFirst({
    where: { id: input.operationId, userId: input.ownerId },
    select: {
      id: true,
      sandboxId: true,
      kind: true,
      generation: true,
      state: true,
      scalarResult: true,
      processId: true,
      processPid: true,
      ...dispatchSelect,
    },
  });
  requireRelayFence(op !== null && isResultKind(op.kind) && !isContentResultKind(op.kind));
  requireDispatchedTo(op, input.sender, input.attempt);
  const payload = resultBodySchema.parse(input.payload);
  requireResultCompatible(encodedJsonBytes(payload) <= RESULT_LIMITS.scalarMaxBytes);
  if (payload.type === "command")
    // The incarnation belongs to this dispatch attempt and, once bound by
    // process birth, to the operation's own immutable identity.
    requireResultCompatible(
      payload.process.attempt === input.attempt &&
        (op.processId === null || op.processId === payload.process.processId) &&
        (op.processPid === null || op.processPid === payload.process.pid),
    );
  if (payload.type === "process.signal") {
    // The target is an owned command in the same sandbox: never a foreign
    // process, and never a pid other than the one the request named.
    const target = await tx.sandboxOperation.findFirst({
      where: {
        id: payload.targetOperationId,
        userId: input.ownerId,
        sandboxId: op.sandboxId,
        kind: "RUN_COMMAND",
      },
      select: { processId: true, processPid: true, generation: true, dispatchAttempt: true },
    });
    const request = await tx.outboxEvent.findFirst({
      where: {
        userId: input.ownerId,
        aggregateType: "sandbox",
        aggregateId: op.sandboxId,
        eventType: "sandbox.process_signal_requested",
        ...outboxOperationWhere(op.id),
      },
      select: { payload: true },
      orderBy: { createdAt: "asc" },
    });
    const args =
      typeof request?.payload === "object" && request.payload && !Array.isArray(request.payload)
        ? (request.payload as Record<string, unknown>)
        : null;
    // The request named a target whose identity was bound before acceptance.
    requireResultCompatible(
      target !== null &&
        args !== null &&
        target.processId === payload.process.processId &&
        target.processPid === payload.process.pid &&
        target.generation === payload.process.generation &&
        target.dispatchAttempt === payload.process.attempt &&
        args.signal === payload.signal &&
        isDeepStrictEqual(args.process, payload.process) &&
        args.targetOperationId === payload.targetOperationId &&
        (args.pid === undefined || args.pid === payload.process.pid) &&
        (args.processId === undefined || args.processId === payload.process.processId),
    );
  }
  operationResultSchema.parse({
    operationId: op.id,
    sandboxId: op.sandboxId,
    generation: op.generation,
    kind: op.kind,
    // Command birth/exit evidence remains immutable private history even if
    // the operation later fails, is cancelled, or has an unknown outcome.
    outcome: op.kind === "RUN_COMMAND" ? "pending" : operationOutcome(op.state),
    observedAt: input.observedAt.toISOString(),
    expiresAt: null,
    result: payload,
  });
  if (op.scalarResult !== null) {
    const existing = resultBodySchema.parse(op.scalarResult);
    if (existing.type === "command" && payload.type === "command") {
      requireResultCompatible(
        isDeepStrictEqual(existing.process, payload.process) &&
          existing.startedAt === payload.startedAt &&
          (existing.exitCode === null || existing.exitCode === payload.exitCode),
      );
    } else requireResultCompatible(isDeepStrictEqual(existing, payload));
    if (isDeepStrictEqual(existing, payload)) return;
  }
  await tx.sandboxOperation.update({
    where: { id: op.id },
    data: {
      resultVersion: 1,
      resultExpiresAt: null,
      resultObservedAt: input.observedAt,
      scalarResult: payload,
    },
  });
}

const resultMetadataSelect = {
  id: true,
  sandboxId: true,
  generation: true,
  kind: true,
  state: true,
  resultVersion: true,
  resultExpiresAt: true,
  resultObservedAt: true,
  dispatchAttempt: true,
} satisfies PrismaTypes.SandboxOperationSelect;
/** Scope gates use the stored kind before loading scalar/payload/continuation.
 * serviceProcedure fences success and errors with fresh exit authorization. */
export const getOperationResult = serviceProcedure(
  {
    action: "operations.get",
    intentOnly: true,
  },
  async (owner: Principal, input: { operationId: string }): Promise<OperationResult> => {
    const op = await prisma.sandboxOperation.findFirst({
      where: { id: input.operationId, userId: owner.ownerId, Sandbox: { userId: owner.ownerId } },
      select: resultMetadataSelect,
    });
    if (!op) {
      const receipt = await prisma.sandboxActionReceipt.findFirst({
        where: { id: input.operationId, userId: owner.ownerId },
        select: {
          sandboxId: true,
          hostId: true,
          templateRevisionId: true,
          originPoolId: true,
          logicalTemplateId: true,
          action: true,
        },
      });
      if (!receipt) throw operationNotFound();
      await authorizeServiceAction(
        owner,
        receipt.sandboxId ? "operations.get" : "operations.getReceipt",
        receipt.sandboxId
          ? { sandboxId: receipt.sandboxId }
          : {
              sandboxHostId: receipt.hostId,
              templateRevisionId: receipt.templateRevisionId,
              originPoolId: receipt.originPoolId,
              ...(receipt.action === "templates.append" && receipt.templateRevisionId === null
                ? { logicalTemplateId: receipt.logicalTemplateId ?? "missing" }
                : {}),
            },
      );
      throw resultError("OPERATION_RESULT_UNSUPPORTED");
    }
    await authorizeServiceAction(owner, "operations.get", { operationId: op.id });
    const action = resultActionForOperationKind(op.kind);
    if (!action) throw resultError("OPERATION_RESULT_UNSUPPORTED");
    await authorizeServiceAction(owner, action, { operationId: op.id });
    if (op.resultVersion !== 1) throw resultError("OPERATION_RESULT_UNSUPPORTED");
    return prisma.$transaction(
      async (tx) => {
        // Read status and payload from one snapshot; authorization above only
        // loaded immutable kind/resource metadata.
        const current = await tx.sandboxOperation.findFirst({
          where: { id: op.id, userId: owner.ownerId },
          select: resultMetadataSelect,
        });
        if (!current) throw operationNotFound();
        const snapshot = current;
        const now = await hostDatabaseNow(tx);
        if (snapshot.resultExpiresAt && snapshot.resultExpiresAt <= now)
          throw resultError("OPERATION_RESULT_EXPIRED");
        const outcome = operationOutcome(snapshot.state);
        const showResult = !["failed", "cancelled", "unknown"].includes(outcome);
        // P2-10: only a RESERVED hold on a non-terminal operation may still
        // receive content. Any terminal success without retained content
        // (RELEASED/EXPIRED/missing tombstone) is final, never "poll again".
        const terminal = outcome !== "pending";
        let payload: unknown = null;
        if (showResult && isContentResultKind(snapshot.kind)) {
          const content = await tx.sandboxOperationResult.findFirst({
            where: { operationId: snapshot.id, userId: owner.ownerId },
            select: {
              payload: true,
              reservationState: true,
              generation: true,
              attempt: true,
              version: true,
              expiresAt: true,
            },
          });
          if (content?.reservationState === "PUBLISHED") {
            requireRelayFence(
              content.generation === snapshot.generation &&
                content.attempt === snapshot.dispatchAttempt &&
                content.version === snapshot.resultVersion &&
                content.expiresAt.getTime() === snapshot.resultExpiresAt?.getTime(),
            );
            if (content.expiresAt <= now) throw resultError("OPERATION_RESULT_EXPIRED");
            payload = content.payload;
          } else if (terminal || content?.reservationState !== "RESERVED")
            throw resultError("OPERATION_RESULT_EXPIRED");
        } else if (showResult) {
          const scalar = await tx.sandboxOperation.findFirst({
            where: { id: snapshot.id, userId: owner.ownerId },
            select: { scalarResult: true },
          });
          payload = scalar?.scalarResult ?? null;
          if (payload === null && terminal)
            // Scalar evidence never expires. A versioned success without it is
            // an invariant violation, not a content-retention deadline.
            throw new ORPCError("INTERNAL_SERVER_ERROR", {
              message: SDK_ERRORS.INTERNAL_SERVER_ERROR[1],
              data: { code: "INTERNAL_SERVER_ERROR" },
            });
        }
        if (payload === null && showResult) throw resultError("OPERATION_RESULT_NOT_READY");
        const checked = operationResultSchema.safeParse({
          operationId: snapshot.id,
          sandboxId: snapshot.sandboxId,
          generation: snapshot.generation,
          kind: snapshot.kind,
          outcome,
          observedAt: (snapshot.resultObservedAt ?? now).toISOString(),
          expiresAt: snapshot.resultExpiresAt?.toISOString() ?? null,
          result: payload,
        });
        if (!checked.success) throw new ORPCError("INTERNAL_SERVER_ERROR");
        return checked.data;
      },
      { isolationLevel: "RepeatableRead" },
    );
  },
);

type ResultContinuationInput = {
  cursor: string;
  sandboxId: string;
  generation: number;
  root: string;
  depth: number;
  limit: number;
  kind: "LIST_DIR" | "LIST_PROCESSES";
};

/** Acceptance already holds owner/K/H/S: cursor auth, expiry and content use that tx. */
export async function readResultContinuationInTransaction(
  tx: Tx,
  owner: Principal,
  input: ResultContinuationInput,
) {
  await authorizeServiceAction(owner, "operations.get", { operationId: input.cursor }, tx);
  const op = await tx.sandboxOperation.findFirst({
    where: { id: input.cursor, userId: owner.ownerId },
    select: { ...resultMetadataSelect, Sandbox: { select: { generation: true } } },
  });
  if (!op) throw operationNotFound();
  const action = resultActionForOperationKind(op.kind);
  if (!action) throw resultError("OPERATION_RESULT_UNSUPPORTED");
  // Stored-kind authorization must precede loading the private continuation.
  await authorizeServiceAction(owner, action, { operationId: op.id }, tx);
  if (op.resultVersion !== 1) throw resultError("OPERATION_RESULT_UNSUPPORTED");
  const now = await hostDatabaseNow(tx);
  if (op.sandboxId !== input.sandboxId || op.kind !== input.kind)
    throw resultError("RESULT_CURSOR_INVALID");
  if (op.generation !== input.generation || op.Sandbox.generation !== input.generation)
    throw resultError("RESULT_CURSOR_STALE");
  if (!op.resultExpiresAt || op.resultExpiresAt <= now)
    throw resultError("OPERATION_RESULT_EXPIRED");
  const row = await tx.sandboxOperationResult.findFirst({
    where: { operationId: op.id, userId: owner.ownerId },
    select: {
      continuation: true,
      reservationState: true,
      generation: true,
      attempt: true,
      version: true,
      expiresAt: true,
    },
  });
  if (row?.reservationState !== "PUBLISHED") throw resultError("OPERATION_RESULT_EXPIRED");
  requireRelayFence(
    row.generation === op.generation &&
      row.attempt === op.dispatchAttempt &&
      row.version === op.resultVersion &&
      row.expiresAt.getTime() === op.resultExpiresAt.getTime(),
  );
  const continuation = resultContinuationSchema.safeParse(row.continuation);
  if (
    !continuation.success ||
    continuation.data.root !== input.root ||
    continuation.data.depth !== input.depth ||
    continuation.data.limit !== input.limit ||
    continuation.data.kind !== input.kind ||
    continuation.data.generation !== input.generation
  )
    throw resultError("RESULT_CURSOR_INVALID");
  return { continuation: continuation.data, expiresAt: op.resultExpiresAt };
}

/** Standalone reads retain a single repeatable snapshot; acceptance passes its own tx. */
export const readResultContinuation = serviceProcedure(
  {
    action: "operations.get",
    target: (input: ResultContinuationInput) => ({ operationId: input.cursor }),
  },
  async (owner: Principal, input: ResultContinuationInput) => {
    // Immutable kind pre-read authorizes before entering the standalone snapshot.
    const op = await prisma.sandboxOperation.findFirst({
      where: { id: input.cursor, userId: owner.ownerId },
      select: resultMetadataSelect,
    });
    if (!op) throw operationNotFound();
    const action = resultActionForOperationKind(op.kind);
    if (!action) throw resultError("OPERATION_RESULT_UNSUPPORTED");
    await authorizeServiceAction(owner, action, { operationId: op.id });
    if (op.resultVersion !== 1) throw resultError("OPERATION_RESULT_UNSUPPORTED");
    return prisma.$transaction((tx) => readResultContinuationInTransaction(tx, owner, input), {
      isolationLevel: "RepeatableRead",
    });
  },
);

/** Bounded one-owner expiry transaction, called from the existing retention task.
 * Locate identities first; acquire owner → H (sorted) → S → O → outbox → quota. */
async function lockOwnerForResultCleanup(tx: Tx, ownerId: string) {
  const rows = await tx.$queryRaw<
    { id: string }[]
  >`SELECT id FROM "user" WHERE id = ${ownerId} FOR SHARE`;
  requireRelayFence(rows.length === 1);
}
export async function purgeExpiredOperationResults(ownerId: string, batch = 100) {
  const take = Math.max(1, Math.min(100, batch));
  return prisma.$transaction(async (tx) => {
    assertBeforeResultQuota(tx);
    await lockOwnerForResultCleanup(tx, ownerId);
    const candidateTime = await hostDatabaseNow(tx);
    const candidates = await tx.sandboxOperationResult.findMany({
      where: { userId: ownerId, expiresAt: { lte: candidateTime } },
      select: {
        operationId: true,
        Operation: { select: { sandboxId: true, Sandbox: { select: { sandboxHostId: true } } } },
      },
      orderBy: { operationId: "asc" },
      take,
    });
    if (!candidates.length) return 0;
    const hostIds = [
      ...new Set(
        candidates.flatMap((row) =>
          row.Operation.Sandbox.sandboxHostId ? [row.Operation.Sandbox.sandboxHostId] : [],
        ),
      ),
    ].sort();
    for (const id of hostIds) {
      const host = await tx.sandboxHost.findFirst({
        where: { id, userId: ownerId },
        select: { connectionEpoch: true },
      });
      if (host) await lockHostByEpoch(tx, id, host.connectionEpoch, ownerId);
    }
    const sandboxIds = [...new Set(candidates.map((row) => row.Operation.sandboxId))].sort();
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE "userId" = ${ownerId} AND id IN (${Prisma.join(sandboxIds)}) ORDER BY id FOR UPDATE`;
    const operationIds = candidates.map((row) => row.operationId);
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE "userId" = ${ownerId} AND id IN (${Prisma.join(operationIds)}) ORDER BY id FOR UPDATE`;
    await resultSuffix(tx, ownerId, operationIds, sandboxIds);
    const now = await hostDatabaseNow(tx);
    return (
      await tx.sandboxOperationResult.deleteMany({
        where: { userId: ownerId, operationId: { in: operationIds }, expiresAt: { lte: now } },
      })
    ).count;
  });
}

/** Every completion writer's first completedAt is authoritative, including
 * interim UNKNOWN and lifecycle retirement. Older writers need not know the
 * private description column to enforce the unchanged output deadline. */
function descriptionExpiryWhere(now: Date) {
  return {
    OR: [
      { processDescriptionExpiresAt: { lte: now } },
      { completedAt: { lte: new Date(now.getTime() - OUTPUT_RETENTION_MS) } },
    ],
  };
}

/** At most 10 owners per tick; callers carry this opaque owner key to avoid
 * starving later owners. No transaction holds quota locks for two owners. */
export async function sweepOperationResults(
  afterOwner = "",
  ownerLimit = 10,
  signal?: AbortSignal,
) {
  if (signal?.aborted) return afterOwner;
  const candidateTime = await hostDatabaseNow(prisma);
  const owners = await prisma.sandboxOperationResult.groupBy({
    by: ["userId"],
    where: { userId: { gt: afterOwner }, expiresAt: { lte: candidateTime } },

    orderBy: { userId: "asc" },
    take: Math.max(1, Math.min(10, ownerLimit)),
  });
  const descriptionOwners = await prisma.sandboxOperation.groupBy({
    by: ["userId"],
    where: {
      userId: { gt: afterOwner },
      processDescription: { not: Prisma.DbNull },
      ...descriptionExpiryWhere(candidateTime),
    },

    orderBy: { userId: "asc" },
    take: Math.max(1, Math.min(10, ownerLimit)),
  });
  const ownerIds = [...new Set([...owners, ...descriptionOwners].map((row) => row.userId))]
    .sort()
    .slice(0, Math.max(1, Math.min(10, ownerLimit)));
  let lastOwner = "";
  for (const ownerId of ownerIds) {
    if (signal?.aborted) break;
    await purgeExpiredProcessDescriptions(ownerId);
    if (signal?.aborted) break;
    await purgeExpiredOperationResults(ownerId);
    lastOwner = ownerId;
  }
  return lastOwner;
}

/** Command descriptions share the output deadline, without consuming a result
 * reservation. Active descriptions with no completion deadline remain private. */
export async function purgeExpiredProcessDescriptions(ownerId: string, batch = 100) {
  return prisma.$transaction(async (tx) => {
    await lockOwnerForResultCleanup(tx, ownerId);
    const candidateTime = await hostDatabaseNow(tx);
    const rows = await tx.sandboxOperation.findMany({
      where: {
        userId: ownerId,
        processDescription: { not: Prisma.DbNull },
        ...descriptionExpiryWhere(candidateTime),
      },
      select: { id: true, sandboxId: true, Sandbox: { select: { sandboxHostId: true } } },
      orderBy: { id: "asc" },
      take: Math.max(1, Math.min(100, batch)),
    });
    if (!rows.length) return 0;
    const hosts = [
      ...new Set(
        rows.flatMap((row) => (row.Sandbox.sandboxHostId ? [row.Sandbox.sandboxHostId] : [])),
      ),
    ].sort();
    for (const id of hosts) {
      const host = await tx.sandboxHost.findFirst({
        where: { id, userId: ownerId },
        select: { connectionEpoch: true },
      });
      if (host) await lockHostByEpoch(tx, id, host.connectionEpoch, ownerId);
    }
    const sandboxes = [...new Set(rows.map((row) => row.sandboxId))].sort();
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE "userId" = ${ownerId} AND id IN (${Prisma.join(sandboxes)}) ORDER BY id FOR UPDATE`;
    const ids = rows.map((row) => row.id);
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE "userId" = ${ownerId} AND id IN (${Prisma.join(ids)}) ORDER BY id FOR UPDATE`;
    const now = await hostDatabaseNow(tx);
    return (
      await tx.sandboxOperation.updateMany({
        where: { userId: ownerId, id: { in: ids }, ...descriptionExpiryWhere(now) },
        data: { processDescription: Prisma.DbNull },
      })
    ).count;
  });
}
