import { ORPCError } from "@orpc/server";
import prisma, { type OperationState, type Prisma } from "@wssp/db";
import {
  type ProcessRef,
  processRefSchema,
  resourceIdSchema,
  SDK_ERRORS,
  type SdkErrorCode,
  STDIN_CHUNK_MAX_BYTES,
  stdinBase64Schema,
} from "@wssp/sandbox-contracts";
import {
  authorizeServiceAction,
  authorizeServiceIntent,
  type ServiceAction,
  serviceProcedure,
} from "../lib/sdk-key-access";
import { fsProcessBudgetFamily } from "../lib/service-scopes";
import { consumeSandboxWriteBudget } from "./budgets";
import { cancelCapacityWaitIfWaiting } from "./capacity-queue";
import { idempotencyKey, type Principal } from "./contracts";
import { ACTION_DIGEST_DOMAIN, digestContextSnapshot, parseDigestContext } from "./digest-context";
import { cancelRestoreWaitIfWaiting } from "./disk-offload/restore-admit";
import { idempotencyConflict, operationNotFound, sandboxStateConflict } from "./errors";
import { lockHostForSandboxOperation } from "./host-admission";
import {
  hashRequestBody,
  reconcileIdempotency,
  requestDigestMetadata,
  requestTransportIdentity,
} from "./idempotency";
import { leaseNow, leaseTransactionNow } from "./lease";
import { ownerKeyTransaction, requireReplayPrincipal } from "./operation-transaction";
import { createSandboxOutboxEvent } from "./outbox";
import { attributionOf, budgetSubjectOf, recordedKeyIdOf } from "./principal-kinds";
import { cancelQueuedOperation, operationActiveFenceWhere, requireRelayFence } from "./relay-fence";
import { CANCELLABLE_OPERATION_KINDS } from "./state-transitions";

export type ControlTarget =
  | { operationId: string; process?: never }
  | { process: ProcessRef; operationId?: never };
type ControlInput = ControlTarget & { idempotencyKey: string };
type StdinInput = ControlInput & { contentBase64: string; eof?: boolean };

const controlSelect = {
  id: true,
  sandboxId: true,
  kind: true,
  generation: true,
  state: true,
  dispatchAttempt: true,
  dispatchedHostId: true,
  dispatchedConnectionEpoch: true,
  processId: true,
  processPid: true,
  processBootId: true,
  processStartTicks: true,
  resultVersion: true,
  nextStdinSequence: true,
  stdinClosed: true,
} satisfies Prisma.SandboxOperationSelect;

function processError(code: Extract<SdkErrorCode, `sandbox.process_${string}`>): never {
  throw new ORPCError(code === "sandbox.process_not_found" ? "NOT_FOUND" : "CONFLICT", {
    data: { code },
    message: SDK_ERRORS[code][1],
  });
}

/** Locate only owned immutable metadata. Caller PID is never start evidence. */
export async function locateControlTarget(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: ControlTarget,
) {
  if (input.process !== undefined) {
    if (input.operationId !== undefined) throw new ORPCError("BAD_REQUEST");
    const parsed = processRefSchema.safeParse(input.process);
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    const row = await tx.sandboxOperation.findFirst({
      where: {
        userId: owner.ownerId,
        sandboxId: input.process.sandboxId,
        processId: input.process.processId,
        kind: "RUN_COMMAND",
        Sandbox: { userId: owner.ownerId },
      },
      select: controlSelect,
    });
    if (!row) return processError("sandbox.process_not_found");
    return row;
  }
  if (!resourceIdSchema.safeParse(input.operationId).success) throw new ORPCError("BAD_REQUEST");
  const row = await tx.sandboxOperation.findFirst({
    where: { id: input.operationId, userId: owner.ownerId, Sandbox: { userId: owner.ownerId } },
    select: controlSelect,
  });
  if (!row) throw operationNotFound();
  return row;
}

export function validateControlRef(
  row: {
    generation: number;
    dispatchAttempt: number;
    processPid: number | null;
    processBootId: string | null;
    processStartTicks: string | null;
    resultVersion: number | null;
  },
  ref: ProcessRef,
) {
  if (!processRefSchema.safeParse(ref).success) throw new ORPCError("BAD_REQUEST");
  if (
    row.generation !== ref.generation ||
    (row.dispatchAttempt > 0 && row.dispatchAttempt !== ref.attempt) ||
    (row.processPid !== null && row.processPid !== ref.pid)
  )
    processError("sandbox.process_not_found");
  if (row.resultVersion !== 1)
    throw new ORPCError("BAD_REQUEST", { data: { code: "UNSUPPORTED_CAPABILITY" } });
  if (
    row.processPid === null ||
    row.processBootId === null ||
    row.processStartTicks === null ||
    row.dispatchAttempt === 0
  )
    processError("sandbox.process_not_started");
}

/** owner → idempotency → K (authorization) → H → S → O, then DB time.
 * Locate before locks, but make every mutable decision from the locked reread. */
export async function resolveLockedControl(
  tx: Prisma.TransactionClient,
  owner: Principal,
  action: ServiceAction,
  input: ControlTarget,
) {
  const located = await locateControlTarget(tx, owner, input);
  await authorizeServiceAction(owner, action, { operationId: located.id }, tx);
  if (input.process) validateControlRef(located, input.process);
  const placement = await tx.sandbox.findFirst({
    where: { id: located.sandboxId, userId: owner.ownerId },
    select: { sandboxHostId: true },
  });
  if (!placement) throw operationNotFound();
  if (placement.sandboxHostId)
    await lockHostForSandboxOperation(
      tx,
      placement.sandboxHostId,
      owner.ownerId,
      located.sandboxId,
    );
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id=${located.sandboxId} AND "userId"=${owner.ownerId} FOR NO KEY UPDATE`;
  await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id=${located.id} AND "userId"=${owner.ownerId} FOR UPDATE`;
  const row = await locateControlTarget(tx, owner, input);
  if (input.process) validateControlRef(row, input.process);
  const sandbox = await tx.sandbox.findFirst({
    where: { id: row.sandboxId, userId: owner.ownerId },
    select: {
      id: true,
      generation: true,
      state: true,
      sandboxHostId: true,
      originHostId: true,
      templateRevisionId: true,
      originPoolId: true,
    },
  });
  if (!sandbox || sandbox.sandboxHostId !== placement.sandboxHostId) throw sandboxStateConflict();
  // A never-placed (capacity-waiting) sandbox has no process to control.
  // Offload §8.10 / §5a: the control's transport is the CURRENT host (a
  // restore moves it; `Sandbox.originHostId` stays the first host's).
  const originHostId = sandbox.sandboxHostId ?? sandbox.originHostId;
  if (originHostId === null) throw sandboxStateConflict();
  if (row.generation !== sandbox.generation) {
    if (row.kind === "RUN_COMMAND") processError("sandbox.process_stale");
    throw sandboxStateConflict();
  }
  const now = await leaseTransactionNow(tx, leaseNow);
  return { row, sandbox: { ...sandbox, originHostId }, now };
}

export async function requireLiveControl(
  tx: Prisma.TransactionClient,
  owner: Principal,
  resolved: Awaited<ReturnType<typeof resolveLockedControl>>,
) {
  const { row, sandbox } = resolved;
  if (row.kind !== "RUN_COMMAND") throw sandboxStateConflict();
  if (row.state === "UNKNOWN_OUTCOME") processError("sandbox.process_unknown_outcome");
  if (["SUCCEEDED", "FAILED", "CANCELLED"].includes(row.state))
    processError("sandbox.process_exited");
  if (row.state === "CANCEL_REQUESTED") processError("sandbox.process_cancel_pending");
  const host = row.dispatchedHostId
    ? await tx.sandboxHost.findFirst({ where: { id: row.dispatchedHostId, userId: owner.ownerId } })
    : null;
  if (row.dispatchAttempt > 0 && (!host || host.connectionEpoch !== row.dispatchedConnectionEpoch))
    processError("sandbox.process_unknown_outcome");
  if (
    row.dispatchAttempt === 0 ||
    (row.resultVersion === 1 && (!row.processPid || !row.processBootId || !row.processStartTicks))
  )
    processError("sandbox.process_not_started");
  if (
    host?.status !== "CONNECTED" ||
    sandbox.sandboxHostId !== row.dispatchedHostId ||
    sandbox.state !== "READY"
  )
    processError("sandbox.process_unavailable");
}

function intentHash(
  owner: Principal,
  action: string,
  targetOperationId: string,
  hostId: string,
  hostOwnerId: string,
  input: StdinInput | ControlInput,
) {
  const stdin = action === "commands.writeStdin" ? (input as StdinInput) : null;
  const body = {
    action,
    targetOperationId,
    ...(stdin ? { contentBase64: stdin.contentBase64, eof: stdin.eof === true } : {}),
  };
  const context = {
    ownerId: owner.ownerId,
    hostId,
    hostOwnerId,
    authorizingKeyId: recordedKeyIdOf(owner),
  };
  return hashRequestBody(body, { ...context, domain: ACTION_DIGEST_DOMAIN });
}

type ControlReceipt = { operationId: string; state: OperationState };
function controlReceipt(
  action: "commands.writeStdin",
): (owner: Principal, input: StdinInput) => Promise<ControlReceipt>;
function controlReceipt(
  action: "operations.cancel",
): (owner: Principal, input: ControlInput) => Promise<ControlReceipt>;
function controlReceipt(action: "commands.writeStdin" | "operations.cancel") {
  return serviceProcedure(
    { action, intentOnly: true },
    async (owner: Principal, input: StdinInput | ControlInput) => {
      if (!idempotencyKey.safeParse(input.idempotencyKey).success)
        throw new ORPCError("BAD_REQUEST");
      if (action === "commands.writeStdin") {
        const stdin = input as StdinInput;
        if (
          !stdinBase64Schema.safeParse(stdin.contentBase64).success ||
          Buffer.from(stdin.contentBase64, "base64").byteLength > STDIN_CHUNK_MAX_BYTES ||
          (stdin.contentBase64 === "" && stdin.eof !== true)
        )
          throw new ORPCError("BAD_REQUEST");
      }
      const lookup = async (tx: Prisma.TransactionClient) => {
        await authorizeServiceIntent(owner, action, tx);
        const prior = await tx.sandboxActionReceipt.findUnique({
          where: {
            userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: input.idempotencyKey },
          },
        });
        if (!prior) {
          if (
            await tx.sandboxOperation.findUnique({
              where: {
                userId_idempotencyKey: {
                  userId: owner.ownerId,
                  idempotencyKey: input.idempotencyKey,
                },
              },
              select: { id: true },
            })
          )
            throw idempotencyConflict();
          return null;
        }
        requireReplayPrincipal(prior.authorizingKeyId, owner);
        if (!prior.targetOperationId) throw idempotencyConflict();
        await authorizeServiceAction(owner, action, { operationId: prior.targetOperationId }, tx);
        // Resolve the already-authorized identity, never inspect a different
        // target's qualifiers/state to decide a same-key conflict.
        const target = await locateControlTarget(tx, owner, {
          operationId: prior.targetOperationId,
        });
        if (
          prior.action !== action ||
          (input.process
            ? input.operationId !== undefined ||
              input.process.sandboxId !== target.sandboxId ||
              input.process.processId !== target.processId
            : input.operationId !== target.id)
        )
          throw idempotencyConflict();
        if (input.process) validateControlRef(target, input.process);
        const binding = parseDigestContext(prior.digestContext);
        if (binding.domain !== ACTION_DIGEST_DOMAIN) throw idempotencyConflict();
        reconcileIdempotency(prior, () =>
          intentHash(owner, action, target.id, binding.hostId, binding.hostOwnerId, input),
        );
        return {
          value: { operationId: prior.id, state: prior.state },
        };
      };
      const preflight = async (tx: Prisma.TransactionClient) => {
        if (await lookup(tx)) return null;
        const target = await locateControlTarget(tx, owner, input);
        await authorizeServiceAction(owner, action, { operationId: target.id }, tx);
        if (input.process) validateControlRef(target, input.process);
        if (
          action === "operations.cancel" &&
          !CANCELLABLE_OPERATION_KINDS.has(target.kind) &&
          // A CREATE may be cancelled ONLY while it waits for capacity, and
          // a restore RECONNECT only while it waits.
          !(target.kind === "CREATE_SANDBOX" && (await waitingCreate(tx, owner, target.id))) &&
          !(target.kind === "RECONNECT_SANDBOX" && (await waitingRestore(tx, owner, target.id)))
        )
          throw sandboxStateConflict("lifecycle operations cannot be cancelled; use kill");
        return fsProcessBudgetFamily(action, target.kind);
      };
      const admission = await preflight(prisma);
      const budgetOwner = budgetSubjectOf(owner)?.ownerId;
      if (admission && budgetOwner) await consumeSandboxWriteBudget(budgetOwner, admission);
      return ownerKeyTransaction(owner, input.idempotencyKey, lookup, async (tx) => {
        if (!admission) throw idempotencyConflict();
        if (action === "operations.cancel") {
          const target = await locateControlTarget(tx, owner, input);
          if (target.kind === "CREATE_SANDBOX")
            return cancelWaitingCreate(tx, owner, input as ControlInput, target);
          if (target.kind === "RECONNECT_SANDBOX")
            return cancelWaitingRestore(tx, owner, input as ControlInput, target);
        }
        const resolved = await resolveLockedControl(tx, owner, action, input);
        const { row, sandbox, now } = resolved;
        let state: OperationState = "SUCCEEDED";
        if (action === "commands.writeStdin") {
          const stdin = input as StdinInput;
          await requireLiveControl(tx, owner, resolved);
          if (row.stdinClosed) processError("sandbox.process_stdin_closed");
          // Preserve max as the exhausted next-sequence sentinel.
          if (row.nextStdinSequence >= 2_147_483_647) throw sandboxStateConflict();
          await tx.sandboxOperation.update({
            where: { id: row.id },
            data: { nextStdinSequence: row.nextStdinSequence + 1, stdinClosed: stdin.eof === true },
          });
          await createSandboxOutboxEvent(tx, {
            userId: owner.ownerId,
            aggregateId: row.sandboxId,
            eventType: "sandbox.stdin_requested",
            authorizingPrincipal: attributionOf(owner),
            payload: {
              sandboxId: row.sandboxId,
              sandboxHostId: row.dispatchedHostId,
              operationId: row.id,
              kind: "process.stdin",
              generation: row.generation,
              dispatchAttempt: row.dispatchAttempt,
              connectionEpoch: row.dispatchedConnectionEpoch,
              stdinSequence: row.nextStdinSequence,
              stdinBase64: stdin.contentBase64,
              eof: stdin.eof === true,
            },
          });
        } else {
          if (!CANCELLABLE_OPERATION_KINDS.has(row.kind))
            throw sandboxStateConflict("lifecycle operations cannot be cancelled; use kill");
          state = row.state;
          const fence = {
            operationId: row.id,
            sandboxId: row.sandboxId,
            userId: owner.ownerId,
            generation: row.generation,
            attempt: row.dispatchAttempt,
            hostId: row.dispatchedHostId,
            kind: row.kind,
          };
          if (row.state === "QUEUED") {
            await cancelQueuedOperation(tx, fence, now);
            state = "CANCELLED";
          } else if (["DISPATCHED", "ACCEPTED", "RUNNING"].includes(row.state)) {
            const changed = await tx.sandboxOperation.updateMany({
              where: { ...operationActiveFenceWhere(fence), state: row.state },
              data: { state: "CANCEL_REQUESTED" },
            });
            requireRelayFence(changed.count === 1);
            state = "CANCEL_REQUESTED";
            await createSandboxOutboxEvent(tx, {
              userId: owner.ownerId,
              aggregateId: row.sandboxId,
              eventType: "sandbox.operation_cancel_requested",
              authorizingPrincipal: attributionOf(owner),
              payload: {
                sandboxId: row.sandboxId,
                sandboxHostId: row.dispatchedHostId ?? sandbox.sandboxHostId,
                operationId: row.id,
                kind: "operation.cancel",
                generation: row.generation,
                dispatchAttempt: row.dispatchAttempt,
                connectionEpoch: row.dispatchedConnectionEpoch,
              },
            });
          }
        }
        // Receipt, stream counter/state and outbox share this commit. No public
        // receipt can survive a rollback at ANY of these statements.
        const hostOwnerId = (
          await requestTransportIdentity(tx, owner.ownerId, sandbox.originHostId, sandbox.id)
        ).hostOwnerId;
        const receipt = await tx.sandboxActionReceipt.create({
          data: {
            userId: owner.ownerId,
            idempotencyKey: input.idempotencyKey,
            authorizingKeyId: recordedKeyIdOf(owner),
            requestBodyHash: intentHash(
              owner,
              action,
              row.id,
              sandbox.originHostId,
              hostOwnerId,
              input,
            ),
            digestContext: digestContextSnapshot(
              { domain: ACTION_DIGEST_DOMAIN, hostId: sandbox.originHostId, hostOwnerId },
              { generation: row.generation },
            ),
            ...requestDigestMetadata(),
            action,
            sandboxId: sandbox.id,
            hostId: sandbox.originHostId,
            templateRevisionId: sandbox.templateRevisionId,
            originPoolId: sandbox.originPoolId,
            targetOperationId: row.id,
            generation: row.generation,
            state,
            createdAt: now,
          },
        });
        return { operationId: receipt.id, state: receipt.state };
      });
    },
  );
}

async function waitingCreate(
  client: Prisma.TransactionClient,
  owner: Principal,
  operationId: string,
) {
  return (
    (await client.sandboxCapacityWait.findFirst({
      where: { operationId, userId: owner.ownerId, state: "WAITING" },
      select: { id: true },
    })) != null
  );
}

async function waitingRestore(
  client: Prisma.TransactionClient,
  owner: Principal,
  operationId: string,
) {
  return (
    (await client.sandboxRestoreWait.findFirst({
      where: { operationId, userId: owner.ownerId, state: "WAITING" },
      select: { operationId: true },
    })) != null
  );
}

/** `POST /v1/operations/{id}/cancel` on a restore RECONNECT still waiting
 * for an allowed host (§8.3c): the wait ends CANCELLED and the operation
 * `cancelled`; the sandbox stays OFFLOADED. The receipt binds no host. */
async function cancelWaitingRestore(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: ControlInput,
  target: { id: string; sandboxId: string; generation: number },
) {
  await authorizeServiceAction(owner, "operations.cancel", { operationId: target.id }, tx);
  const cancelled = await cancelRestoreWaitIfWaiting(tx, owner.ownerId, {
    operationId: target.id,
  });
  if (!cancelled) throw sandboxStateConflict("lifecycle operations cannot be cancelled; use kill");
  const sandbox = await tx.sandbox.findFirstOrThrow({
    where: { id: target.sandboxId, userId: owner.ownerId },
    select: { templateRevisionId: true, originPoolId: true },
  });
  const receipt = await tx.sandboxActionReceipt.create({
    data: {
      userId: owner.ownerId,
      idempotencyKey: input.idempotencyKey,
      authorizingKeyId: recordedKeyIdOf(owner),
      requestBodyHash: intentHash(owner, "operations.cancel", target.id, "", "", input),
      digestContext: digestContextSnapshot(
        { domain: ACTION_DIGEST_DOMAIN },
        { generation: target.generation },
      ),
      ...requestDigestMetadata(),
      action: "operations.cancel",
      sandboxId: target.sandboxId,
      hostId: "",
      templateRevisionId: sandbox.templateRevisionId,
      originPoolId: sandbox.originPoolId,
      targetOperationId: target.id,
      generation: target.generation,
      state: "CANCELLED",
      createdAt: await leaseTransactionNow(tx, leaseNow),
    },
  });
  return { operationId: receipt.id, state: receipt.state };
}

/** `POST /v1/operations/{id}/cancel` on a CREATE that is still waiting for
 * capacity (the only cancellable CREATE): it ends CANCELLED, the sandbox
 * DELETED, under User → K → G. The receipt binds no host (none was bound). */
async function cancelWaitingCreate(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: ControlInput,
  target: { id: string; sandboxId: string; generation: number },
) {
  await authorizeServiceAction(owner, "operations.cancel", { operationId: target.id }, tx);
  const cancelled = await cancelCapacityWaitIfWaiting(tx, owner.ownerId, target.sandboxId);
  if (!cancelled) throw sandboxStateConflict("lifecycle operations cannot be cancelled; use kill");
  const sandbox = await tx.sandbox.findFirstOrThrow({
    where: { id: target.sandboxId, userId: owner.ownerId },
    select: { templateRevisionId: true, originPoolId: true },
  });
  const receipt = await tx.sandboxActionReceipt.create({
    data: {
      userId: owner.ownerId,
      idempotencyKey: input.idempotencyKey,
      authorizingKeyId: recordedKeyIdOf(owner),
      requestBodyHash: intentHash(owner, "operations.cancel", target.id, "", "", input),
      digestContext: digestContextSnapshot(
        { domain: ACTION_DIGEST_DOMAIN },
        { generation: target.generation },
      ),
      ...requestDigestMetadata(),
      action: "operations.cancel",
      sandboxId: target.sandboxId,
      hostId: "",
      templateRevisionId: sandbox.templateRevisionId,
      originPoolId: sandbox.originPoolId,
      targetOperationId: target.id,
      generation: target.generation,
      state: "CANCELLED",
      createdAt: await leaseTransactionNow(tx, leaseNow),
    },
  });
  return { operationId: receipt.id, state: receipt.state };
}

export const writeStdinAction = controlReceipt("commands.writeStdin");
export const cancelAction = controlReceipt("operations.cancel");
