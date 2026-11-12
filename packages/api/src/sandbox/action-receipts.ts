import { ORPCError } from "@orpc/server";
import prisma, { type OperationState, type Prisma } from "@wssp/db";
import { actionReceiptSchema, isSdkErrorCode, operationOutcome } from "@wssp/sandbox-contracts";
import {
  authorizeServiceAction,
  authorizeServiceIntent,
  type ServiceAction,
  type ServiceActionContext,
  serviceProcedure,
} from "../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "./budgets";
import type { Principal } from "./contracts";
import {
  ACTION_DIGEST_DOMAIN,
  type DigestTransport,
  digestContextSnapshot,
  parseDigestContext,
} from "./digest-context";
import { hostDrainingConflict, idempotencyConflict } from "./errors";
import {
  hashRequestBody,
  reconcileIdempotency,
  requestDigestMetadata,
  requestTransportIdentity,
} from "./idempotency";
import { ownerKeyTransaction, requireReplayPrincipal } from "./operation-transaction";
import { notifyOperationsChanged, operationChange } from "./operation-waiters";
import { budgetSubjectOf, grantOf, isBrowserSession, recordedKeyIdOf } from "./principal-kinds";

/** Non-dispatch actions need durable identity too. Persist uncertainty before
 * host IO, never rerun an uncertain effect, and publish success only after the
 * effect commits. No transaction/lock is held across host verification. */
export function actionReceipt<I extends { idempotencyKey: string }>(
  action: ServiceAction,
  target: (input: I) => ServiceActionContext,
  work: (
    owner: Principal,
    input: I,
    receipt: { generation: number | null },
  ) => Promise<{
    resourceId?: string;
    templateRevisionId?: string;
    verificationConnectionEpoch?: number;
    observation?: string;
    state?: OperationState;
  }>,
  resolveTarget?: (
    tx: Prisma.TransactionClient,
    owner: Principal,
    input: I,
  ) => Promise<ServiceActionContext>,
) {
  return serviceProcedure({ action, intentOnly: true }, async (owner: Principal, input: I) => {
    let budgetCharged = true;
    if (["templates.create", "templates.append", "templates.associate"].includes(action)) {
      // This preflight only skips the budget. The serialized lookup below still
      // binds the key, reauthorizes the target and verifies the request digest.
      // Keep Redis IO outside the owner/key transaction. New keys charge before
      // target authorization and before any durable receipt claim, as before.
      const existing = await prisma.sandboxActionReceipt.findUnique({
        where: {
          userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: input.idempotencyKey },
        },
        select: { id: true },
      });
      budgetCharged = existing === null;
      const budgetOwner = budgetSubjectOf(owner)?.ownerId;
      if (budgetCharged && budgetOwner) await consumeSandboxWriteBudget(budgetOwner, "template");
    }
    const requestBodyHash = (transport: DigestTransport) =>
      hashRequestBody(
        { action, input },
        {
          domain: transport.domain,
          ownerId: owner.ownerId,
          hostId: transport.hostId,
          hostOwnerId: transport.hostOwnerId,
          authorizingKeyId: recordedKeyIdOf(owner),
        },
      );
    // The transport half of the digest exactly as it is hashed.
    const transportOf = (binding: {
      sandboxHostId?: string;
      hostOwnerId: string;
    }): DigestTransport => ({
      domain: ACTION_DIGEST_DOMAIN,
      hostId: binding.sandboxHostId ?? "",
      hostOwnerId: binding.hostOwnerId,
    });
    const context = target(input);
    const claim = await ownerKeyTransaction(
      owner,
      input.idempotencyKey,
      async (tx) => {
        await authorizeServiceIntent(owner, action, tx);
        const prior = await tx.sandboxActionReceipt.findUnique({
          where: {
            userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: input.idempotencyKey },
          },
        });
        if (prior) {
          requireReplayPrincipal(prior.authorizingKeyId, owner);
          await authorizeServiceAction(
            owner,
            action,
            prior.targetOperationId
              ? { operationId: prior.targetOperationId, retainedReplay: true }
              : prior.sandboxId
                ? { sandboxId: prior.sandboxId, retainedReplay: true }
                : {
                    sandboxHostId: prior.hostId,
                    ...(action === "templates.append"
                      ? { logicalTemplateId: prior.logicalTemplateId ?? "missing" }
                      : {}),
                    // Registration replay checks its original logical/host
                    // target. The new revision never grants itself; receipt
                    // reads separately require that exact revision grant.
                    templateRevisionId: ["templates.create", "templates.append"].includes(action)
                      ? undefined
                      : prior.templateRevisionId,
                    originPoolId: prior.originPoolId,
                  },
            tx,
          );
          const transport = parseDigestContext(prior.digestContext);
          if (transport.domain !== ACTION_DIGEST_DOMAIN) throw idempotencyConflict();
          reconcileIdempotency(prior, () => requestBodyHash(transport));
          if (prior.action !== action) throw idempotencyConflict();
          return { value: { receipt: prior, claimed: false } };
        }
        if (
          await tx.sandboxOperation.findFirst({
            where: { userId: owner.ownerId, idempotencyKey: input.idempotencyKey },
            select: { id: true },
          })
        )
          throw idempotencyConflict();
        return null;
      },
      async (tx) => {
        // Receipt retention cannot turn a free replay into an unbudgeted write.
        if (!budgetCharged) throw idempotencyConflict();
        let authorized = await authorizeServiceAction(
          owner,
          action,
          resolveTarget ? await resolveTarget(tx, owner, input) : context,
          tx,
        );
        if (isBrowserSession(owner)) {
          const operation = context.operationId
            ? await tx.sandboxOperation.findFirst({
                where: { id: context.operationId, userId: owner.ownerId },
                select: { sandboxId: true },
              })
            : null;
          const sandboxId = context.sandboxId ?? operation?.sandboxId;
          if (context.operationId && !operation) throw new ORPCError("NOT_FOUND");
          if (sandboxId) {
            const sandbox = await tx.sandbox.findFirst({
              where: { id: sandboxId, userId: owner.ownerId },
              select: { originHostId: true, templateRevisionId: true, originPoolId: true },
            });
            if (!sandbox) throw new ORPCError("NOT_FOUND");
            authorized = {
              sandboxId,
              originPoolId: sandbox.originPoolId,
              sandboxHostId: sandbox.originHostId,
              templateRevisionId: sandbox.templateRevisionId,
            };
          }
        }
        const sandboxId = authorized.sandboxId ?? null;
        const sandbox = sandboxId
          ? await tx.sandbox.findFirst({
              where: { id: sandboxId, userId: owner.ownerId },
              select: { generation: true },
            })
          : null;
        const transport = transportOf(
          await requestTransportIdentity(tx, owner.ownerId, authorized.sandboxHostId, sandboxId),
        );
        return {
          claimed: true,
          receipt: await tx.sandboxActionReceipt.create({
            data: {
              userId: owner.ownerId,
              idempotencyKey: input.idempotencyKey,
              authorizingKeyId: recordedKeyIdOf(owner),
              requestBodyHash: requestBodyHash(transport),
              digestContext: digestContextSnapshot(transport, {
                generation: sandbox?.generation ?? null,
              }),
              ...requestDigestMetadata(),
              action,
              sandboxId,
              hostId: authorized.sandboxHostId ?? "",
              logicalTemplateId: context.logicalTemplateId,
              templateRevisionId: authorized.templateRevisionId,
              originPoolId: authorized.originPoolId ?? null,
              targetOperationId: context.operationId,
              generation: sandbox?.generation,
            },
          }),
        };
      },
    );
    if (!claim.claimed) {
      if (claim.receipt.errorCode === "sandbox.host_draining") throw hostDrainingConflict();
      return { operationId: claim.receipt.id, state: claim.receipt.state };
    }
    // UNKNOWN_OUTCOME survives process death, timeout or transport failure. The
    // caller has a pollable receipt and must not issue a new key to guess/retry.
    try {
      const result = await work(owner, input, claim.receipt);
      const state =
        result.state ?? (result.observation === "unreachable" ? "UNKNOWN_OUTCOME" : "SUCCEEDED");
      const receipt = await prisma.sandboxActionReceipt.update({
        where: { id: claim.receipt.id },
        data: {
          state,
          resourceId: result.resourceId,
          templateRevisionId: result.templateRevisionId,
          verificationConnectionEpoch: result.verificationConnectionEpoch,
          probeState: result.observation,
        },
      });
      // Receipts are written outside the observed transaction: wake long-polls here.
      notifyOperationsChanged(operationChange([receipt.id]));
      await authorizeServiceAction(owner, action, context);
      return { operationId: receipt.id, state: receipt.state };
    } catch (error) {
      // Authorization changes still fail closed; never disclose the receipt.
      await authorizeServiceAction(owner, action, context);
      if (
        error instanceof ORPCError &&
        ["BAD_REQUEST", "CONFLICT", "NOT_FOUND", "PRECONDITION_FAILED"].includes(error.code)
      ) {
        const domainCode =
          error.data && typeof error.data === "object" && "code" in error.data
            ? error.data.code
            : undefined;
        const code = isSdkErrorCode(domainCode)
          ? domainCode
          : isSdkErrorCode(error.code)
            ? error.code
            : "CONFLICT";
        await prisma.sandboxActionReceipt.update({
          where: { id: claim.receipt.id },
          data: { state: "FAILED", errorCode: code },
        });
        notifyOperationsChanged(operationChange([claim.receipt.id]));
        if (code === "sandbox.host_draining") throw hostDrainingConflict();
        return { operationId: claim.receipt.id, state: "FAILED" as const };
      }
      return { operationId: claim.receipt.id, state: "UNKNOWN_OUTCOME" as const };
    }
  });
}

const receiptSelect = {
  id: true,
  userId: true,
  action: true,
  authorizingKeyId: true,
  state: true,
  sandboxId: true,
  hostId: true,
  logicalTemplateId: true,
  templateRevisionId: true,
  originPoolId: true,
  targetOperationId: true,
  resourceId: true,
  probeState: true,
  errorCode: true,
  generation: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxActionReceiptSelect;

export const getActionReceipt = serviceProcedure(
  { action: "capabilities.get" },
  async (owner: Principal, input: { id: string }) => {
    const row = await prisma.sandboxActionReceipt.findFirst({
      where: { id: input.id, userId: owner.ownerId },
      select: receiptSelect,
    });
    if (!row) return null;
    if (
      ["templates.create", "templates.append"].includes(row.action) &&
      row.state === "SUCCEEDED" &&
      !row.templateRevisionId
    )
      throw new ORPCError("NOT_FOUND", {
        message: "Template not found.",
        data: { code: "sandbox.template_not_found" },
      });
    await authorizeServiceAction(
      owner,
      row.sandboxId ? "operations.get" : "operations.getReceipt",
      row.sandboxId
        ? { sandboxId: row.sandboxId }
        : {
            sandboxHostId: row.hostId,
            templateRevisionId: row.templateRevisionId,
            originPoolId: row.originPoolId,
            ...(row.action === "templates.append" && row.templateRevisionId === null
              ? { logicalTemplateId: row.logicalTemplateId ?? "missing" }
              : {}),
          },
    );
    // Probe observations require the read capability, independently of status.
    let observation = null;
    if (row.probeState !== null && grantOf(owner).has("sandboxes:read")) {
      await authorizeServiceAction(owner, "sandboxes.get", { sandboxId: row.sandboxId });
      observation = row.probeState;
    }
    let state = row.state;
    if (
      row.targetOperationId &&
      row.action === "operations.cancel" &&
      state !== "UNKNOWN_OUTCOME" &&
      state !== "FAILED"
    ) {
      const operation = await targetOperationState(row.targetOperationId, owner.ownerId);
      if (
        operation &&
        (row.action === "operations.cancel" ||
          ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(operation.state))
      )
        state = operation.state;
    }
    await authorizeServiceAction(
      owner,
      row.sandboxId ? "operations.get" : "operations.getReceipt",
      row.sandboxId
        ? { sandboxId: row.sandboxId }
        : {
            sandboxHostId: row.hostId,
            templateRevisionId: row.templateRevisionId,
            originPoolId: row.originPoolId,
            ...(row.action === "templates.append" && row.templateRevisionId === null
              ? { logicalTemplateId: row.logicalTemplateId ?? "missing" }
              : {}),
          },
    );
    if (observation !== null)
      await authorizeServiceAction(owner, "sandboxes.get", { sandboxId: row.sandboxId });
    return actionReceiptSchema.parse({
      id: row.id,
      kind: row.action,
      state,
      sandboxId: row.sandboxId,
      generation: row.generation,
      targetOperationId: row.targetOperationId,
      resourceId: row.resourceId,
      observation,
      outcome: operationOutcome(state),
      errorCode: row.errorCode,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    });
  },
);

async function targetOperationState(id: string, userId: string) {
  return prisma.sandboxOperation.findFirst({ where: { id, userId }, select: { state: true } });
}
