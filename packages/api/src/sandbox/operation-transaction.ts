import { ORPCError } from "@orpc/server";
import prisma, { type OperationState, type Prisma, type SandboxOperationKind } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { isPrismaUniqueViolation } from "../lib/prisma-errors";
import {
  authorizeServiceAction,
  authorizeServiceIntent,
  type ServiceAction,
  type ServiceActionContext,
  serviceActionForOperationKind,
} from "../lib/sdk-key-access";
import { fsProcessBudgetFamily } from "../lib/service-scopes";
import { consumeSandboxWriteBudget } from "./budgets";
import type { Principal } from "./contracts";
import {
  bindOperationDigestContext,
  type DigestTransport,
  digestContextSnapshot,
  ENV_FREE_DIGEST_DOMAIN,
  parseDigestContext,
  REQUEST_DIGEST_DOMAIN,
  RESTORE_INTENT_DIGEST_DOMAIN,
} from "./digest-context";
import { idempotencyConflict, sandboxNameTaken } from "./errors";
import { requireFsProcessHost } from "./host-protocol";
import {
  hashOperationRequestBody,
  QUEUED_CREATE_DIGEST_DOMAIN,
  reconcileIdempotency,
  requestDigestMetadata,
  requestTransportIdentity,
  requireHostJournalKeyAck,
  requireRequestDigestMetadata,
} from "./idempotency";
import { sandboxOutboxTransaction } from "./outbox";
import { budgetSubjectOf, recordedKeyIdOf } from "./principal-kinds";
import { assertBeforeResultQuota } from "./result-locks";
import { isSandboxNameViolation } from "./sandbox-names";
import { lockPlacementPrincipals } from "./sharing-authority";

/** The single owner/key serialization and P2002 recovery boundary for both
 * dispatch operations and non-dispatch action receipts. Lock order is owner,
 * key, placement(31), template, build, host, sandbox, operation; the sandbox
 * name is picked under placement(31). No network IO belongs in these callbacks. */
export async function ownerKeyTransaction<T>(
  owner: Principal,
  key: string,
  lookup: (tx: Prisma.TransactionClient) => Promise<{ value: T } | null>,
  work: (tx: Prisma.TransactionClient) => Promise<T>,
  namespace: "operation" | "transfer" = "operation",
  admissionPrincipals?: (tx: Prisma.TransactionClient) => Promise<string[]>,
): Promise<T> {
  try {
    return await sandboxOutboxTransaction(async (tx) => {
      assertBeforeResultQuota(tx);
      if (admissionPrincipals) await lockPlacementPrincipals(tx, await admissionPrincipals(tx));
      else await lockOwnerForAdmission(tx, owner.ownerId);
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify([owner.ownerId, key])}, 0))`;
      const prior = await lookup(tx);
      if (
        namespace !== "transfer" &&
        (await tx.sandboxTransfer.findUnique({
          where: { userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: key } },
          select: { id: true },
        }))
      )
        throw idempotencyConflict();
      return prior ? prior.value : work(tx);
    });
  } catch (error) {
    // Recover AFTER rollback, never query an aborted PostgreSQL transaction.
    if (!isPrismaUniqueViolation(error)) throw error;
    return prisma.$transaction(async (tx) => {
      assertBeforeResultQuota(tx);
      if (admissionPrincipals) await lockPlacementPrincipals(tx, await admissionPrincipals(tx));
      else await lockOwnerForAdmission(tx, owner.ownerId);
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify([owner.ownerId, key])}, 0))`;
      const prior = await lookup(tx);
      // A create that lost a name race to another key (backstop for the
      // pick under placement(31)) is a typed conflict, never a raw P2002.
      if (!prior) throw isSandboxNameViolation(error) ? sandboxNameTaken() : error;
      return prior.value;
    });
  }
}

/** Replay is reauthorized before lifecycle/capacity validation and always uses
 * the original request hash, never the sandbox's newer generation. */
export async function operationTransaction<T>(
  owner: Principal,
  request: {
    key: string;
    intent: unknown;
    kind: SandboxOperationKind;
    action: ServiceAction;
    target: ServiceActionContext;
    resolveTarget?: (tx: Prisma.TransactionClient) => Promise<ServiceActionContext>;
    admissionPrincipals?: (tx: Prisma.TransactionClient) => Promise<string[]>;
    /** Require the command/file capability for this admission. */
    fsProcess?: { commandEnvironment?: boolean };
    /**
     * CREATE only, read after `resolveTarget`: the request entered the
     * capacity queue, so no host is bound. It hashes in the separate queued
     * MAC domain with empty host fields (same scheme string).
     */
    queuedDigest?: () => boolean;
  },
  /** `context` is the in-transaction authorization result itself (never a
   * copy): identity-keyed facts such as `buildRoleOf` read from it. */
  work: (
    tx: Prisma.TransactionClient,
    digest: () => string,
    context: ServiceActionContext,
  ) => Promise<T>,
  replay: (
    tx: Prisma.TransactionClient,
    operation: { id: string; sandboxId: string; state: OperationState },
  ) => Promise<T>,
): Promise<T> {
  if (request.action !== serviceActionForOperationKind(request.kind))
    throw new ORPCError("CONFLICT", { message: "Unsupported operation authority." });
  const family = fsProcessBudgetFamily(request.action);
  let charged = true;
  if (family) {
    // Authorized DB preflight only. No Redis IO is held under acceptance locks.
    // The serialized transaction below repeats principal/grants/digest checks.
    const preflight = async (tx: Prisma.TransactionClient) => {
      await authorizeServiceIntent(owner, request.action, tx);
      const prior = await tx.sandboxOperation.findUnique({
        where: { userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: request.key } },
        select: { id: true, authorizingKeyId: true },
      });
      if (prior) {
        requireReplayPrincipal(prior.authorizingKeyId, owner);
        await authorizeServiceAction(
          owner,
          request.action,
          { operationId: prior.id, retainedReplay: true },
          tx,
        );
        return true;
      }
      const target = request.resolveTarget ? await request.resolveTarget(tx) : request.target;
      await authorizeServiceAction(owner, request.action, target, tx);
      return false;
    };
    const existing = await preflight(prisma);
    charged = !existing;
    // Keep authorized replay/conflict resolution first.
    // A build is exempt (budgetSubjectOf); the budget helper stays kind-free.
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner && charged) await consumeSandboxWriteBudget(budgetOwner, family);
  }
  return ownerKeyTransaction(
    owner,
    request.key,
    async (tx) => {
      await authorizeServiceIntent(
        owner,
        request.kind === "CREATE_SANDBOX" ? "sandboxes.createIntent" : request.action,
        tx,
      );
      const other = await tx.sandboxActionReceipt.findUnique({
        where: { userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: request.key } },
        select: { id: true },
      });
      if (other) throw idempotencyConflict();
      const prior = await tx.sandboxOperation.findFirst({
        where: {
          userId: owner.ownerId,
          idempotencyKey: request.key,
          Sandbox: { userId: owner.ownerId },
        },
        select: {
          id: true,
          sandboxId: true,
          state: true,
          kind: true,
          authorizingKeyId: true,
          requestBodyHash: true,
          requestDigestScheme: true,
          requestDigestKeyId: true,
          generation: true,
          digestContext: true,
        },
      });
      if (!prior) return null;
      requireReplayPrincipal(prior.authorizingKeyId, owner);
      await authorizeServiceAction(
        owner,
        prior.kind === "CREATE_SANDBOX" ? "sandboxes.replayCreate" : request.action,
        { operationId: prior.id, retainedReplay: true },
        tx,
      );
      requireRequestDigestMetadata(prior, requestDigestMetadata(prior.kind));
      if (prior.kind !== request.kind) throw idempotencyConflict();
      const transport = parseDigestContext(prior.digestContext);
      reconcileIdempotency(
        prior,
        () =>
          hashOperationRequestBody(
            digestBody(request.intent, transport),
            request.kind,
            digestFields(owner, transport),
          ),
        requestDigestMetadata(request.kind),
      );
      return { value: await replay(tx, prior) };
    },
    async (tx) => {
      if (!charged) throw idempotencyConflict();
      const target = request.resolveTarget ? await request.resolveTarget(tx) : request.target;
      const context = await authorizeServiceAction(owner, request.action, target, tx);
      const queuedCreate = request.kind === "CREATE_SANDBOX" && request.queuedDigest?.() === true;
      const transport = await acceptanceDigestTransport(
        tx,
        owner,
        request.kind,
        context,
        request.target.sandboxId,
        queuedCreate,
      );
      if (request.fsProcess) {
        const sandboxId = context.sandboxId ?? request.target.sandboxId;
        const sandbox = sandboxId
          ? await tx.sandbox.findFirst({
              where: { id: sandboxId, userId: owner.ownerId },
              select: { id: true, sandboxHostId: true, hostOwnerId: true },
            })
          : null;
        if (!sandbox?.sandboxHostId || !sandbox.hostOwnerId)
          throw new ORPCError("BAD_REQUEST", {
            data: { code: "UNSUPPORTED_CAPABILITY" },
            message: "Capability is unsupported.",
          });
        await requireFsProcessHost(tx, sandbox.hostOwnerId, sandbox.sandboxHostId);
        if (request.kind === "RUN_COMMAND") {
          // Every caller, including direct operation writers, must check the
          // current key. Read the immutable execution snapshot only after S.
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
          const config = await tx.sandboxExecutionConfig.findFirst({
            where: { sandboxId: sandbox.id, userId: owner.ownerId },
            select: { id: true },
          });
          if (config || request.fsProcess.commandEnvironment)
            await requireHostJournalKeyAck(tx, sandbox.sandboxHostId, sandbox.hostOwnerId);
        }
      }
      bindOperationDigestContext(
        tx,
        digestContextSnapshot(transport, { generation: transport.generation }),
      );
      const result = await work(
        tx,
        () =>
          hashOperationRequestBody(
            digestBody(request.intent, transport),
            request.kind,
            digestFields(owner, transport),
          ),
        context,
      );
      await recordDigestContext(tx, owner.ownerId, request.key, transport);
      return result;
    },
    "operation",
    request.admissionPrincipals,
  );
}

/** Scalar binding is checked before ANY request digest work, including P2002. */
export function requireReplayPrincipal(recordedKeyId: string | null, owner: Principal): void {
  if (recordedKeyId !== recordedKeyIdOf(owner)) throw idempotencyConflict();
}

function digestFields(owner: Principal, transport: DigestTransport) {
  return {
    domain: transport.domain,
    ownerId: owner.ownerId,
    hostId: transport.hostId,
    hostOwnerId: transport.hostOwnerId,
    authorizingKeyId: recordedKeyIdOf(owner),
  };
}

/** The transport a digest is computed with; a hostless restore also binds
 * its acceptance generation (§8.3a `restore-intent:v1`). */
type DigestBinding = DigestTransport & { generation?: number | null };

/** `restore-intent:v1` hashes `{intent, acceptance generation}`: a replay
 * after the restore placed (or timed out) recomputes against the stored
 * acceptance generation, never the sandbox's later one. */
function digestBody(intent: unknown, transport: DigestBinding): unknown {
  if (transport.domain !== RESTORE_INTENT_DIGEST_DOMAIN) return intent;
  return { restoreIntent: intent, acceptanceGeneration: transport.generation ?? null };
}

const ENV_FREE_TRANSPORT: DigestTransport = {
  domain: ENV_FREE_DIGEST_DOMAIN,
  hostId: "",
  hostOwnerId: "",
};

function envFreeKind(kind: SandboxOperationKind): boolean {
  return kind === "KILL_SANDBOX" || kind === "STOP_SANDBOX";
}

/** The transport identity a fresh acceptance hashes with (CN3):
 * - env-free KILL/STOP (destroy included) never resolve transport;
 * - a queued CREATE has no host (its own MAC domain);
 * - a sandbox `OFFLOADED` at acceptance is hostless (`restore-intent:v1`);
 * - everything else binds the current transport. */
async function acceptanceDigestTransport(
  tx: Prisma.TransactionClient,
  owner: Principal,
  kind: SandboxOperationKind,
  context: ServiceActionContext,
  targetSandboxId: string | null | undefined,
  queuedCreate: boolean,
): Promise<DigestBinding> {
  if (envFreeKind(kind)) return ENV_FREE_TRANSPORT;
  if (queuedCreate) return { domain: QUEUED_CREATE_DIGEST_DOMAIN, hostId: "", hostOwnerId: "" };
  const sandboxId = targetSandboxId ?? context.sandboxId;
  if (sandboxId) {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: sandboxId, userId: owner.ownerId },
      select: { state: true, generation: true },
    });
    if (sandbox?.state === "OFFLOADED")
      return {
        domain: RESTORE_INTENT_DIGEST_DOMAIN,
        hostId: "",
        hostOwnerId: "",
        generation: sandbox.generation,
      };
  }
  const resolved = await resolvedDigestContext(tx, owner, context, targetSandboxId);
  return {
    domain: REQUEST_DIGEST_DOMAIN,
    hostId: resolved.sandboxHostId ?? "",
    hostOwnerId: resolved.hostOwnerId ?? "",
  };
}

/** Store the acceptance snapshot on the operation the work callback accepted
 * under this key (same transaction, so it is immutable acceptance data). A
 * restore writer already recorded its acceptance generation and is left alone. */
async function recordDigestContext(
  tx: Prisma.TransactionClient,
  ownerId: string,
  key: string,
  transport: DigestTransport,
): Promise<void> {
  const operation = await tx.sandboxOperation.findUnique({
    where: { userId_idempotencyKey: { userId: ownerId, idempotencyKey: key } },
    select: {
      id: true,
      sandboxId: true,
      generation: true,
      digestContext: true,
      Sandbox: {
        select: {
          usagePoolId: true,
          usageMemberId: true,
          CurrentPlacement: { select: { configId: true } },
        },
      },
    },
  });
  if (!operation) return;
  const snapshot = parseDigestContext(operation.digestContext);
  if (snapshot.domain === RESTORE_INTENT_DIGEST_DOMAIN) return;
  await tx.sandboxOperation.update({
    where: { id: operation.id },
    data: {
      digestContext: digestContextSnapshot(transport, {
        generation: operation.generation,
        configId: operation.Sandbox.CurrentPlacement?.configId ?? null,
        usagePoolId: operation.Sandbox.usagePoolId,
        usageMemberId: operation.Sandbox.usageMemberId,
      }),
    },
  });
}

async function resolvedDigestContext(
  tx: Prisma.TransactionClient,
  owner: Principal,
  context: ServiceActionContext,
  sandboxId?: string | null,
) {
  return {
    ...context,
    ...(await requestTransportIdentity(
      tx,
      owner.ownerId,
      context.sandboxHostId,
      sandboxId ?? context.sandboxId,
    )),
  };
}

export { operationDigestContext } from "./digest-context";
