import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import {
  authorizeServiceAction,
  authorizeServiceIntent,
  type ServiceActionContext,
  serviceActionForOperationKind,
  serviceProcedure,
} from "../lib/sdk-key-access";
import { actionReceipt } from "./action-receipts";
import type { CreateTemplateInput, Principal, SandboxIdInput } from "./contracts";
import { digestKeyChanged } from "./errors";
import { requestDigestKeyCurrent } from "./idempotency";
import { requireReplayPrincipal } from "./operation-transaction";
import { cancelAction, writeStdinAction } from "./process-controls";
import { probeSandbox } from "./services/sandboxes";
import {
  appendTemplateRevision,
  associateTemplateAvailability,
  createTemplate,
} from "./services/templates";
import { resolveTemplateImageTarget } from "./template-resolution";
import { validateVmSizeOverrides } from "./vm-size-input";

export const registerTemplateReceipt = actionReceipt(
  "templates.create",
  (input: CreateTemplateInput & { idempotencyKey: string }) => {
    validateVmSizeOverrides(input);
    return { sandboxHostId: input.hostId };
  },
  async (owner, input) => {
    const created = await createTemplate(owner, input);
    return { resourceId: created.id, templateRevisionId: created.firstRevisionId };
  },
  async (tx, owner, input) => {
    const target = await resolveTemplateImageTarget(tx, owner, input);
    return { sandboxHostId: target.hostId, originPoolId: target.poolId };
  },
);
export const probeSandboxReceipt = actionReceipt(
  "sandboxes.probe",
  (input: SandboxIdInput & { idempotencyKey: string }) => ({ sandboxId: input.id }),
  async (owner, input, receipt) => ({
    observation: (await probeSandbox(owner, input, receipt.generation ?? undefined)).state,
  }),
);
/** Both address forms use the atomic receipt/counter/outbox writer. */
export const writeStdinReceipt = writeStdinAction;
export const cancelOperationReceipt = cancelAction;

/** Create/kill/renew retain their browser DTOs; HTTP resolves only the accepted
 * operation metadata using the same authorized action (no extra read grant). */
const guardedMutationReceipt = serviceProcedure(
  { action: "capabilities.get" },
  async (
    owner: Principal,
    input: {
      key: string;
      action: "sandboxes.create" | "sandboxes.kill" | "sandboxes.setTimeout";
      target: ServiceActionContext;
    },
  ) => {
    await authorizeServiceIntent(
      owner,
      input.action === "sandboxes.create" ? "sandboxes.createIntent" : input.action,
    );
    const row = await prisma.sandboxOperation.findFirst({
      where: { userId: owner.ownerId, idempotencyKey: input.key },
      select: {
        id: true,
        state: true,
        kind: true,
        sandboxId: true,
        authorizingKeyId: true,
        requestDigestScheme: true,
        requestDigestKeyId: true,
      },
    });
    if (!row) throw new ORPCError("INTERNAL_SERVER_ERROR");
    requireReplayPrincipal(row.authorizingKeyId, owner);
    await authorizeServiceAction(
      owner,
      input.action === "sandboxes.create" ? "sandboxes.replayCreate" : input.action,
      { operationId: row.id, retainedReplay: true },
    );
    if (!requestDigestKeyCurrent(row)) throw digestKeyChanged();
    if (serviceActionForOperationKind(row.kind) !== input.action)
      throw new ORPCError("INTERNAL_SERVER_ERROR");
    return { operationId: row.id, state: row.state };
  },
);
export function mutationOperationReceipt(
  owner: Principal,
  key: string,
  action: "sandboxes.create" | "sandboxes.kill" | "sandboxes.setTimeout",
  target: ServiceActionContext = {},
) {
  return guardedMutationReceipt(owner, { key, action, target });
}

export const appendRevisionReceipt = actionReceipt(
  "templates.append",
  (input: import("./template-input").AppendRevisionInput & { idempotencyKey: string }) => {
    validateVmSizeOverrides(input);
    return {
      sandboxHostId: input.hostId,
      logicalTemplateId: input.templateId,
    };
  },
  async (owner, input) => {
    const revision = await appendTemplateRevision(owner, input);
    return { resourceId: revision.id, templateRevisionId: revision.id };
  },
  async (tx, owner, input) => {
    const target = await resolveTemplateImageTarget(tx, owner, input);
    return {
      sandboxHostId: target.hostId,
      originPoolId: target.poolId,
      logicalTemplateId: input.templateId,
    };
  },
);
export const associateAvailabilityReceipt = actionReceipt(
  "templates.associate",
  (
    input: import("zod").z.infer<typeof import("./template-input").associateAvailabilityInput> & {
      idempotencyKey: string;
    },
  ) => ({
    sandboxHostId: input.hostId,
    logicalTemplateId: input.templateId,
    templateRevisionId: input.revisionId,
  }),
  async (owner, input) => {
    const verified = await associateTemplateAvailability(owner, input);
    return {
      resourceId: input.revisionId,
      templateRevisionId: input.revisionId,
      verificationConnectionEpoch: verified.verifiedConnectionEpoch ?? undefined,
    };
  },
  async (tx, owner, input) => {
    const target = await resolveTemplateImageTarget(tx, owner, input);
    return {
      sandboxHostId: target.hostId,
      originPoolId: target.poolId,
      logicalTemplateId: input.templateId,
      templateRevisionId: input.revisionId,
    };
  },
);
