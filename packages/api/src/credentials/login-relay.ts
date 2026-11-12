import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import type { SessionPrincipal } from "../sandbox/contracts";
import { credentialLoginFlowPrincipal } from "../sandbox/principal-kinds";
import { ACTIVE_OPERATION_STATES, KILLABLE_SANDBOX_STATES } from "../sandbox/state-transitions";
import {
  definitionResiduePaths,
  markCredentialFilesEver,
  recordCredentialPathHistory,
} from "./specs";
import { loadVerifiedLogin } from "./verified-login";

/**
 * The relay-side half of the login sandbox flow:
 * the LOGIN lease's activation at READY and the destroy after a save. Kept
 * apart from `login-sessions.ts` so the relay does not load the session
 * services at import time (the sandbox services are imported lazily).
 */

type Tx = Prisma.TransactionClient;

/** The principal of wssp's own login flow for one owner (never from a request). */
export function loginFlowPrincipal(ownerId: string): SessionPrincipal {
  return credentialLoginFlowPrincipal(ownerId);
}

/**
 * Destroys a login session's sandbox through the flow principal with
 * `credentialCapture: skip`. Idempotent per (session, purpose) key; a sandbox
 * already tearing down or gone is not an error.
 */
export async function destroyLoginSandbox(
  ownerId: string,
  sandboxId: string,
  key: string,
): Promise<boolean> {
  try {
    const { killSandbox } = await import("../sandbox/services/sandboxes");
    await killSandbox(loginFlowPrincipal(ownerId), {
      id: sandboxId,
      idempotencyKey: key,
      credentialCapture: "skip",
    });
    return true;
  } catch (error) {
    if (error instanceof ORPCError && (error.code === "CONFLICT" || error.code === "NOT_FOUND"))
      return false;
    throw error;
  }
}

/**
 * §11 "only then destroy": after a login capture committed (the session is
 * SAVED) and the free that captured it is no longer in flight, destroy the
 * login sandbox with `credentialCapture: skip`. Called after the commit
 * transaction and after the free's result transaction, whichever comes last;
 * both use one idempotency key. Never throws: the 30-min lease destroys the
 * sandbox anyway.
 */
export async function destroySavedLoginSandbox(
  target: { leaseId: string } | { sandboxId: string },
): Promise<void> {
  try {
    const sandboxId =
      "sandboxId" in target
        ? target.sandboxId
        : (
            await prisma.credentialLease.findUnique({
              where: { id: target.leaseId },
              select: { sandboxId: true, kind: true },
            })
          )?.sandboxId;
    if (!sandboxId) return;
    const session = await prisma.credentialLoginSession.findFirst({
      where: { sandboxId, state: "SAVED" },
      select: { id: true, userId: true },
    });
    if (!session) return;
    const [sandbox, freeInFlight] = await Promise.all([
      prisma.sandbox.findUnique({ where: { id: sandboxId }, select: { state: true } }),
      prisma.sandboxOperation.findFirst({
        where: {
          sandboxId,
          kind: "CREDENTIAL_FREE",
          state: { in: [...ACTIVE_OPERATION_STATES] },
        },
        select: { id: true },
      }),
    ]);
    if (!sandbox || freeInFlight || !KILLABLE_SANDBOX_STATES.has(sandbox.state)) return;
    await destroyLoginSandbox(session.userId, sandboxId, `login-saved-${session.id}`);
  } catch {
    console.error("[credential-login] destroy after save failed; the lease expiry destroys it");
  }
}

/**
 * §11 step 1 / §7.1 LOGIN lease RESERVED → ACTIVE, in the create's result
 * transaction (H → S held) before the READY gate: a LOGIN binding granted to
 * the sandbox's host at its generation, a residue row for the definition's
 * paths, `lease.baseSeq = binding.baseSeq = instance.currentSeq` (possibly
 * null), session READY. No bundle is sent: a login sandbox starts clean.
 */
export async function activateLoginLease(
  tx: Tx,
  input: { sandboxId: string; operationId: string },
): Promise<void> {
  const rows = await tx.$queryRaw<
    { id: string; credentialId: string; instanceId: string; loginSessionId: string | null }[]
  >`SELECT id, "credentialId", "instanceId", "loginSessionId" FROM credential_lease
    WHERE "sandboxId" = ${input.sandboxId} AND "operationId" = ${input.operationId}
      AND kind::text = 'LOGIN' AND state::text = 'RESERVED'
    ORDER BY id`;
  const reserved = rows?.[0];
  if (!reserved) return;
  const sandbox = await tx.sandbox.findUnique({
    where: { id: input.sandboxId },
    select: { userId: true, generation: true, sandboxHostId: true },
  });
  if (!sandbox?.sandboxHostId) return;
  // Bundle-grant order (§7.3): credential FOR SHARE → instance FOR SHARE → lease.
  await tx.$queryRaw`SELECT id FROM credential WHERE id = ${reserved.credentialId} FOR SHARE`;
  const instances = await tx.$queryRaw<{ currentSeq: number | null }[]>`SELECT "currentSeq"
    FROM credential_instance WHERE id = ${reserved.instanceId} FOR SHARE`;
  await tx.$queryRaw`SELECT id FROM credential_lease WHERE id = ${reserved.id} FOR UPDATE`;
  const login = await loadVerifiedLogin(tx, reserved.credentialId);
  if (!login) return;
  const baseSeq = instances[0]?.currentSeq ?? null;
  const binding = await tx.credentialBinding.create({
    data: {
      leaseId: reserved.id,
      instanceId: reserved.instanceId,
      sandboxId: input.sandboxId,
      hostId: sandbox.sandboxHostId,
      grantGeneration: sandbox.generation,
      operationId: input.operationId,
      baseSeq,
      purpose: "LOGIN",
    },
    select: { id: true },
  });
  const paths = definitionResiduePaths(login.definition);
  if (paths.length > 0)
    await tx.credentialResidue.create({
      data: {
        sandboxId: input.sandboxId,
        userId: sandbox.userId,
        credentialId: reserved.credentialId,
        instanceId: reserved.instanceId,
        leaseId: reserved.id,
        bindingId: binding.id,
        grantGeneration: sandbox.generation,
        paths,
        recoverable: true,
      },
      select: { id: true },
    });
  // §7.6: a template capture scrubs every path this sandbox ever held.
  await recordCredentialPathHistory(tx, input.sandboxId, paths);
  // Offload §4: login history → own-host-only resume.
  await markCredentialFilesEver(tx, input.sandboxId);
  await tx.credentialLease.update({
    where: { id: reserved.id },
    data: {
      state: "ACTIVE",
      baseSeq,
      hostId: sandbox.sandboxHostId,
      currentBindingId: binding.id,
    },
    select: { id: true },
  });
  if (reserved.loginSessionId)
    await tx.credentialLoginSession.updateMany({
      where: { id: reserved.loginSessionId, state: "PROVISIONING" },
      data: { state: "READY" },
    });
}
