import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { type CredentialSpecV11 } from "@wssp/sandbox-contracts";
import { defaultIncusInstanceName, sandboxStateConflict } from "../sandbox";
import { OPERATION_DISPATCH_KIND, type Principal } from "../sandbox/contracts";
import { operationDigestContext } from "../sandbox/digest-context";
import { lockHostForSandboxOperation } from "../sandbox/host-admission";
import { requestDigestMetadata } from "../sandbox/idempotency";
import { createSandboxOutboxEvent } from "../sandbox/outbox";
import { attributionOf, recordedKeyIdOf } from "../sandbox/principal-kinds";
import { ACTIVE_OPERATION_STATES } from "../sandbox/state-transitions";
import { encodeCredentialSpec, writeOperationSpec } from "./specs";

/**
 * Operation plumbing shared by the live attach/free services (live.ts) and
 * the login flow's finish (login-sessions.ts): the H → S sandbox lock, the
 * busy-operation refusal, the recorded operation row, the spec + outbox
 * dispatch and the generation fence. Every function runs inside the
 * caller's operation transaction.
 */

type Tx = Prisma.TransactionClient;

const BUSY_KINDS = [
  "STOP_SANDBOX",
  "KILL_SANDBOX",
  "RECONNECT_SANDBOX",
  "CAPTURE_TEMPLATE",
  "CREDENTIAL_ATTACH",
  "CREDENTIAL_FREE",
] as const;

const sandboxSelect = {
  id: true,
  state: true,
  generation: true,
  sandboxHostId: true,
  hostOwnerId: true,
} satisfies Prisma.SandboxSelect;

export type LockedSandbox = Prisma.SandboxGetPayload<{ select: typeof sandboxSelect }>;

/** H → S for one owned sandbox, re-read under the row lock. */
export async function lockSandbox(
  tx: Tx,
  owner: Principal,
  sandboxId: string,
): Promise<LockedSandbox> {
  const located = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: owner.ownerId },
    select: sandboxSelect,
  });
  if (!located) throw new ORPCError("NOT_FOUND", { message: "Sandbox not found" });
  await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, sandboxId);
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
  const sandbox = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: owner.ownerId },
    select: sandboxSelect,
  });
  if (!sandbox) throw new ORPCError("NOT_FOUND", { message: "Sandbox not found" });
  return sandbox;
}

/** A stop, kill, reconnect, capture or other attach/free of the sandbox is in flight. */
export async function requireNoBusyOperation(tx: Tx, sandbox: LockedSandbox) {
  const busy = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: sandbox.id,
      kind: { in: [...BUSY_KINDS] },
      state: { in: [...ACTIVE_OPERATION_STATES] },
    },
    select: { id: true },
  });
  if (busy) throw sandboxStateConflict("Another lifecycle or login operation is in flight.");
}

export async function recordedOperation(
  tx: Tx,
  owner: Principal,
  input: {
    id?: string;
    sandbox: LockedSandbox;
    kind: "CREDENTIAL_ATTACH" | "CREDENTIAL_FREE";
    idempotencyKey: string;
    bodyHash: () => string;
    state: "QUEUED" | "SUCCEEDED";
  },
) {
  return tx.sandboxOperation.create({
    data: {
      ...(input.id ? { id: input.id } : {}),
      authorizingKeyId: recordedKeyIdOf(owner),
      userId: owner.ownerId,
      sandboxId: input.sandbox.id,
      kind: input.kind,
      state: input.state,
      generation: input.sandbox.generation,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash: input.bodyHash(),
      digestContext: operationDigestContext(tx),
      ...requestDigestMetadata(input.kind),
      ...(input.state === "SUCCEEDED" ? { completedAt: new Date() } : {}),
    },
    select: { id: true, state: true },
  });
}

export async function dispatchLive(
  tx: Tx,
  owner: Principal,
  input: {
    sandbox: LockedSandbox;
    operationId: string;
    idempotencyKey: string;
    kind: "CREDENTIAL_ATTACH" | "CREDENTIAL_FREE";
    spec: CredentialSpecV11;
  },
) {
  const encoded = encodeCredentialSpec(input.spec);
  const stored = await writeOperationSpec(tx, input.operationId, encoded.bytes);
  await createSandboxOutboxEvent(tx, {
    authorizingPrincipal: attributionOf(owner),
    userId: owner.ownerId,
    aggregateId: input.sandbox.id,
    eventType:
      input.kind === "CREDENTIAL_ATTACH"
        ? "sandbox.credential_attach_requested"
        : "sandbox.credential_free_requested",
    payload: {
      sandboxId: input.sandbox.id,
      sandboxHostId: input.sandbox.sandboxHostId,
      generation: input.sandbox.generation,
      dispatchAttempt: 0,
      operationId: input.operationId,
      idempotencyKey: input.idempotencyKey,
      kind: OPERATION_DISPATCH_KIND[input.kind],
      incusName: defaultIncusInstanceName(input.sandbox.id),
      credentialSpec: { digest: stored.digest, bytes: stored.bytes },
    },
  });
}

/** Keeps the S lock's generation fence explicit, as every enqueue does. */
export async function admitAtGeneration(tx: Tx, owner: Principal, sandbox: LockedSandbox) {
  const admitted = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: owner.ownerId,
      generation: sandbox.generation,
      state: sandbox.state,
    },
    data: { generation: sandbox.generation },
  });
  if (admitted.count !== 1) throw sandboxStateConflict();
}
