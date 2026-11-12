import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import type { Principal } from "../sandbox/contracts";
import { credentialError } from "./errors";
import { authorizeCredentialClaims } from "./launch";
import { lockLeaseChain } from "./leases";
import { type ClaimedLease, type CredentialClaimRequest, claimWorkloadLease } from "./selection";
import { markCredentialFilesEver } from "./specs";

/**
 * Lease claims at placement and cold reconnect. Every function runs inside the caller's transaction after S and
 * before the operation row (O); logins are processed in sorted
 * `credentialId` order, one instance row per login (deadlock-free, N3).
 *
 * A create-time account/instance choice is a ONE-SHOT placement hint: it is
 * used by the create's claim and then cleared. Resume uses the attachment's
 * last-used account/instance with fallback; only a pin passed on the resume
 * call itself disables fallback.
 */

type Tx = Prisma.TransactionClient;

const FALLBACK_CODES = new Set([
  "credential.in_use",
  "credential.account_paused",
  "credential.needs_login",
  "credential.instance_not_found",
  "credential.account_not_found",
]);

function fallbackable(error: unknown): boolean {
  if (!(error instanceof ORPCError)) return false;
  const code = (error.data as { code?: unknown } | undefined)?.code;
  return typeof code === "string" && FALLBACK_CODES.has(code);
}

async function activeAttachments(tx: Tx, sandboxId: string) {
  return tx.sandboxCredential.findMany({
    where: { sandboxId, detachedAt: null },
    select: {
      id: true,
      credentialId: true,
      requestedAccountId: true,
      requestedInstanceId: true,
      accountId: true,
      instanceId: true,
    },
    orderBy: { credentialId: "asc" },
    take: 8,
  });
}

async function recordTaken(tx: Tx, attachmentId: string, lease: ClaimedLease) {
  await tx.sandboxCredential.update({
    where: { id: attachmentId },
    data: {
      accountId: lease.accountId,
      instanceId: lease.instanceId,
      requestedAccountId: null,
      requestedInstanceId: null,
    },
    select: { id: true },
  });
}

/**
 * Create / queued-create placement: one lease per active attachment, using
 * the create's one-shot requested account/instance (named rules, no
 * fallback), then clearing it so a later resume never re-applies it. The
 * whole attachment set passes the claim gate against the placed host first.
 */
export async function claimCreateLeases(
  tx: Tx,
  input: {
    principal: Principal;
    ownerId: string;
    sandboxId: string;
    operationId: string;
    hostId: string;
  },
): Promise<ClaimedLease[]> {
  const attachments = await activeAttachments(tx, input.sandboxId);
  await authorizeCredentialClaims(tx, {
    principal: input.principal,
    hostId: input.hostId,
    sandboxId: input.sandboxId,
    claimIds: attachments.map((attachment) => attachment.credentialId),
  });
  const leases: ClaimedLease[] = [];
  for (const attachment of attachments) {
    const lease = await claimWorkloadLease(tx, {
      ...input,
      request: {
        credentialId: attachment.credentialId,
        accountId: attachment.requestedAccountId,
        instanceId: attachment.requestedInstanceId,
      },
    });
    await recordTaken(tx, attachment.id, lease);
    leases.push(lease);
  }
  return leases;
}

export type ResumeClaim =
  | ({ kind: "claimed" } & ClaimedLease)
  | { kind: "recovering"; leaseId: string; credentialId: string; bindingId: string };

/**
 * Cold-reconnect claims (§7.2 resume rules), per attachment:
 *  1. a RECOVERY_REQUIRED lease of this login on this sandbox is reused
 *     (→ RECOVERING with a RECOVER binding naming the old one), regardless
 *     of pause: the disk holds that instance's newest value;
 *  2. recorded account unpaused: the recorded instance, then that account;
 *  3. recorded account paused, or no room: any unpaused account;
 *  4. a pin passed on THIS call uses the named rules with no fallback;
 *  5. before any claim, the claim gate over EVERY attachment the resume
 *     takes (not only the pins): the principal's scope, allowlist and the
 *     feature being writable, then foreign opt-in and host capability
 *     re-read under the credential locks (`host_forbidden`);
 *  6. the attachment records the lease taken.
 * Requires the drain check first (`assertCredentialDrain`).
 */
export async function claimResumeLeases(
  tx: Tx,
  input: {
    principal: Principal;
    ownerId: string;
    sandboxId: string;
    operationId: string;
    hostId: string;
    generation: number;
    pins?: readonly CredentialClaimRequest[];
  },
): Promise<ResumeClaim[]> {
  const attachments = await activeAttachments(tx, input.sandboxId);
  for (const pin of input.pins ?? [])
    if (!attachments.some((attachment) => attachment.credentialId === pin.credentialId))
      throw credentialError("credential.not_attached");
  if (attachments.length === 0) return [];
  await authorizeCredentialClaims(tx, {
    principal: input.principal,
    hostId: input.hostId,
    sandboxId: input.sandboxId,
    claimIds: attachments.map((attachment) => attachment.credentialId),
  });
  const claims: ResumeClaim[] = [];
  for (const attachment of attachments) {
    const live = await tx.credentialLease.findMany({
      where: {
        sandboxId: input.sandboxId,
        credentialId: attachment.credentialId,
        state: {
          in: ["RESERVED", "INSTALLING", "ACTIVE", "RELEASING", "RECOVERY_REQUIRED", "RECOVERING"],
        },
      },
      select: {
        id: true,
        state: true,
        credentialId: true,
        instanceId: true,
        currentBindingId: true,
        baseSeq: true,
      },
      take: 2,
    });
    const recovery = live.find((lease) => lease.state === "RECOVERY_REQUIRED");
    if (live.length > 1 || (live.length === 1 && !recovery))
      throw credentialError("credential.pending_drain");
    if (recovery) {
      claims.push(await reuseForRecovery(tx, input, recovery));
      continue;
    }
    const pin = input.pins?.find((p) => p.credentialId === attachment.credentialId);
    const attempts: CredentialClaimRequest[] = [];
    if (pin) attempts.push(pin);
    else {
      if (attachment.accountId) {
        const account = await tx.credentialAccount.findUnique({
          where: { id: attachment.accountId },
          select: { pausedAt: true },
        });
        // A STOPPED attach may record an account without an instance (§10.1 B1).
        if (account && !account.pausedAt)
          attempts.push(
            ...(attachment.instanceId
              ? [{ credentialId: attachment.credentialId, instanceId: attachment.instanceId }]
              : []),
            { credentialId: attachment.credentialId, accountId: attachment.accountId },
          );
      }
      attempts.push({ credentialId: attachment.credentialId });
    }
    let lease: ClaimedLease | null = null;
    for (const [index, request] of attempts.entries()) {
      try {
        lease = await claimWorkloadLease(tx, { ...input, request });
        break;
      } catch (error) {
        if (index === attempts.length - 1 || !fallbackable(error)) throw error;
      }
    }
    if (!lease) throw credentialError("credential.in_use");
    await recordTaken(tx, attachment.id, lease);
    claims.push({ kind: "claimed", ...lease });
  }
  return claims;
}

/** Rule 1: RECOVERY_REQUIRED → RECOVERING with a RECOVER binding; the old binding closes (residue stays recoverable). */
async function reuseForRecovery(
  tx: Tx,
  input: { sandboxId: string; operationId: string; hostId: string; generation: number },
  lease: {
    id: string;
    credentialId: string;
    instanceId: string;
    currentBindingId: string | null;
    baseSeq: number | null;
  },
): Promise<ResumeClaim> {
  await lockLeaseChain(tx, lease);
  const old = lease.currentBindingId
    ? await tx.credentialBinding.findUnique({
        where: { id: lease.currentBindingId },
        select: { id: true, closedAt: true },
      })
    : null;
  if (old && !old.closedAt)
    await tx.credentialBinding.update({
      where: { id: old.id },
      data: { closedAt: new Date(), closeReason: "superseded_by_recovery" },
      select: { id: true },
    });
  const binding = await tx.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: lease.instanceId,
      sandboxId: input.sandboxId,
      hostId: input.hostId,
      grantGeneration: input.generation,
      operationId: input.operationId,
      baseSeq: lease.baseSeq,
      purpose: "RECOVER",
      recoveryOfBindingId: old?.id ?? null,
    },
    select: { id: true },
  });
  // Offload §4: login history → own-host-only resume.
  await markCredentialFilesEver(tx, input.sandboxId);
  await tx.credentialLease.update({
    where: { id: lease.id },
    data: { state: "RECOVERING", hostId: input.hostId, currentBindingId: binding.id },
    select: { id: true },
  });
  return {
    kind: "recovering",
    leaseId: lease.id,
    credentialId: lease.credentialId,
    bindingId: binding.id,
  };
}

/** Whether drain-before-rebind applies: an active attachment or uncleared residue. */
async function sandboxIsCredentialed(tx: Tx, sandboxId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<{ credentialed: boolean }[]>`SELECT (
      EXISTS (SELECT 1 FROM sandbox_credential WHERE "sandboxId" = ${sandboxId} AND "detachedAt" IS NULL)
      OR EXISTS (SELECT 1 FROM credential_residue WHERE "sandboxId" = ${sandboxId} AND "clearedAt" IS NULL)
    ) AS credentialed`;
  return rows[0]?.credentialed === true;
}

/**
 * Drain before rebind (§7.4.2, scoped by P3-7): a cold reconnect of a
 * credentialed sandbox is accepted only after a complete census on the
 * host's CURRENT connection, with no unresolved envelope of a live lease of
 * the sandbox (a pending capture without a ledger or rejection outcome) and
 * no lease left RELEASING. Quarantined (REJECTED) envelopes never block.
 * An offline host is refused `credential.pending_drain` (retryable).
 * Returns whether the sandbox is credentialed.
 */
export async function assertCredentialDrain(
  tx: Tx,
  input: { sandboxId: string; hostId: string },
): Promise<boolean> {
  if (!(await sandboxIsCredentialed(tx, input.sandboxId))) return false;
  const rows = await tx.$queryRaw<{ drained: boolean }[]>`SELECT (
      EXISTS (SELECT 1 FROM sandbox_host h JOIN credential_host_census c ON c."hostId" = h.id
        WHERE h.id = ${input.hostId} AND h.status::text = 'CONNECTED'
          AND c."connectionEpoch" = h."connectionEpoch")
      AND NOT EXISTS (SELECT 1 FROM credential_pending_capture p
        JOIN credential_lease l ON l.id = p."leaseId"
        WHERE l."sandboxId" = ${input.sandboxId}
          AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
          AND NOT EXISTS (SELECT 1 FROM credential_capture k WHERE k."captureId" = p."captureId")
          AND NOT EXISTS (SELECT 1 FROM credential_capture_rejection r
            WHERE r."hostId" = p."hostId" AND r."captureId" = p."captureId"))
      AND NOT EXISTS (SELECT 1 FROM credential_lease l
        WHERE l."sandboxId" = ${input.sandboxId} AND l.state::text = 'RELEASING')
    ) AS drained`;
  if (rows[0]?.drained !== true) throw credentialError("credential.pending_drain");
  return true;
}

/**
 * Drain before a restore: the hostless
 * form of {@link assertCredentialDrain} for an OFFLOADED sandbox. Its root
 * was detached with proof, so there is no host census to wait for; the
 * restore is accepted only when every lease of the sandbox is settled
 * (RELEASED | FORCE_RELEASED | ABANDONED, the offload gate's
 * `loginStateSettled` lease rule) and no unresolved envelope of a live
 * lease remains (a failed earlier attempt's capture still in flight).
 * A restore never claims over a lease in any other state: in particular
 * a RECOVERY_REQUIRED or RECOVERING lease is never reused for recovery on
 * the restore target (the cold-reconnect rule 1 does not apply to a moved
 * disk). RECOVERY_REQUIRED is refused `credential.recovery_required`
 * (owner action: force-release the login); any other unsettled lease
 * `credential.pending_drain` (retryable). Returns whether the sandbox is
 * credentialed (claims and a launch spec follow).
 */
export async function assertOffloadedCredentialDrain(
  tx: Tx,
  input: { sandboxId: string },
): Promise<boolean> {
  if (!(await sandboxIsCredentialed(tx, input.sandboxId))) return false;
  const rows = await tx.$queryRaw<{ drained: boolean; recovery: boolean }[]>`SELECT (
      NOT EXISTS (SELECT 1 FROM credential_pending_capture p
        JOIN credential_lease l ON l.id = p."leaseId"
        WHERE l."sandboxId" = ${input.sandboxId}
          AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
          AND NOT EXISTS (SELECT 1 FROM credential_capture k WHERE k."captureId" = p."captureId")
          AND NOT EXISTS (SELECT 1 FROM credential_capture_rejection r
            WHERE r."hostId" = p."hostId" AND r."captureId" = p."captureId"))
      AND NOT EXISTS (SELECT 1 FROM credential_lease l
        WHERE l."sandboxId" = ${input.sandboxId}
          AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED'))
    ) AS drained, EXISTS (SELECT 1 FROM credential_lease l
        WHERE l."sandboxId" = ${input.sandboxId} AND l.state::text = 'RECOVERY_REQUIRED'
    ) AS recovery`;
  if (rows[0]?.recovery === true) throw credentialError("credential.recovery_required");
  if (rows[0]?.drained !== true) throw credentialError("credential.pending_drain");
  return true;
}
