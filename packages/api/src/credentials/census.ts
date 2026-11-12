import prisma, { type Prisma } from "@wssp/db";
import type { DaemonCredentialMessage } from "@wssp/sandbox-contracts";
import { lockHostByEpoch, RelayFenceRejected } from "../sandbox/relay-fence";
import {
  groupDiscards,
  heldCaptureClaims,
  lockLeaseSandbox,
  lockSettlementScope,
  type QuarantineDiscard,
} from "./leases";
import { markDrainedReturnKeys } from "./return-keys";
import { settleDrainedTeardowns } from "./teardown";

/**
 * Credential census: the host pages its
 * credential journal after reconciliation; only a COMPLETE census changes
 * server state. It refreshes the host's unresolved envelopes
 * (`CredentialPendingCapture`, never for a capture the server already
 * resolved — ledger or rejection row — so a quarantined envelope never comes
 * back as pending), records the census epoch drain-before-rebind checks,
 * clears verified-scrubbed residue, marks drained return keys and re-sends
 * `credential.quarantine.discard` for quarantined ids already discarded.
 */

type Tx = Prisma.TransactionClient;
type CensusPage = Extract<DaemonCredentialMessage, { type: "credential.census" }>;

export type CensusAccumulator = {
  nextPage: number;
  keyEpoch: number;
  quarantined: Set<string>;
  pending: Map<string, { leaseId: string; bindingId: string; kidR: string; kind: string }>;
  scrubbed: Map<string, string>;
};

export function newCensusAccumulator(): CensusAccumulator {
  return {
    nextPage: 0,
    keyEpoch: 0,
    quarantined: new Set(),
    pending: new Map(),
    scrubbed: new Map(),
  };
}

/** Folds one page in; pages must arrive in order. Returns false on a protocol violation. */
export function accumulateCensusPage(acc: CensusAccumulator, page: CensusPage): boolean {
  if (page.page !== acc.nextPage) return false;
  if (page.page > 0 && page.keyEpoch !== acc.keyEpoch) return false;
  acc.nextPage += 1;
  acc.keyEpoch = page.keyEpoch;
  for (const q of page.quarantined) acc.quarantined.add(q.captureId);
  for (const entry of page.entries) {
    if (entry.scrubbedVerified) acc.scrubbed.set(entry.bindingId, entry.sandboxId);
    for (const p of entry.pending)
      acc.pending.set(p.captureId, {
        leaseId: entry.leaseId,
        bindingId: entry.bindingId,
        kidR: p.kidR,
        kind: p.kind,
      });
  }
  return true;
}

async function applyCensus(
  tx: Tx,
  input: { hostId: string; connectionEpoch: number; census: CensusAccumulator },
): Promise<QuarantineDiscard[]> {
  const { hostId, census } = input;
  await lockHostByEpoch(tx, hostId, input.connectionEpoch);
  const ids = [...census.pending.keys()];
  const resolved = new Set<string>();
  if (ids.length > 0) {
    const rows = await tx.$queryRaw<
      { captureId: string }[]
    >`SELECT "captureId" FROM credential_capture
        WHERE "captureId" = ANY(${ids}::text[])
      UNION SELECT "captureId" FROM credential_capture_rejection
        WHERE "hostId" = ${hostId} AND "captureId" = ANY(${ids}::text[])`;
    for (const row of rows) resolved.add(row.captureId);
  }
  const live = ids.filter((id) => !resolved.has(id) && !census.quarantined.has(id));
  // Custody (`heldCaptureClaims`, shared with the commit fence): an entry
  // naming a lease through a binding this host was never issued is ignored,
  // so it never blocks another lease's drain, delete or re-pin.
  const held = (
    await heldCaptureClaims(
      tx,
      hostId,
      live.flatMap((captureId) => {
        const p = census.pending.get(captureId);
        return p ? [{ captureId, ...p }] : [];
      }),
    )
  ).map((claim) => claim.captureId);
  await tx.$executeRaw`DELETE FROM credential_pending_capture
    WHERE "hostId" = ${hostId} AND NOT ("captureId" = ANY(${held}::text[]))`;
  for (const captureId of held) {
    const p = census.pending.get(captureId);
    if (!p) continue;
    await tx.$executeRaw`INSERT INTO credential_pending_capture
        ("hostId", "captureId", "leaseId", "bindingId", "kidR", kind)
      VALUES (${hostId}, ${captureId}, ${p.leaseId}, ${p.bindingId}, ${p.kidR}, ${p.kind})
      ON CONFLICT ("hostId", "captureId") DO UPDATE
        SET "reportedAt" = (clock_timestamp() AT TIME ZONE 'UTC')`;
  }
  const now = new Date();
  await tx.credentialHostCensus.upsert({
    where: { hostId },
    create: {
      hostId,
      connectionEpoch: BigInt(input.connectionEpoch),
      keyEpoch: BigInt(census.keyEpoch),
      quarantinedCount: census.quarantined.size,
      completedAt: now,
    },
    update: {
      connectionEpoch: BigInt(input.connectionEpoch),
      keyEpoch: BigInt(census.keyEpoch),
      quarantinedCount: census.quarantined.size,
      completedAt: now,
    },
    select: { hostId: true },
  });
  // Verified-absent bindings on sandboxes under this host's authority.
  for (const [bindingId, sandboxId] of census.scrubbed)
    await tx.$executeRaw`UPDATE credential_residue r SET "clearedAt" = ${now}, "clearReason" = 'scrubbed'
      FROM sandbox_instance s
      WHERE r."bindingId" = ${bindingId} AND r."sandboxId" = ${sandboxId} AND r."clearedAt" IS NULL
        AND s.id = r."sandboxId" AND s."sandboxHostId" = ${hostId}`;
  await settleAfterCensus(tx, hostId);
  // Every unresolved envelope the host still holds keeps its key undrained,
  // held or not (a tombstoned lease's envelope is still discarded later).
  const pendingKids = new Set(live.map((id) => census.pending.get(id)?.kidR ?? ""));
  await markDrainedReturnKeys(tx, hostId, census.keyEpoch, pendingKids);
  const quarantined = [...census.quarantined];
  if (quarantined.length === 0) return [];
  const discarded = await tx.$queryRaw<
    { hostId: string; captureId: string }[]
  >`SELECT "hostId", "captureId"
    FROM credential_capture_rejection
    WHERE "hostId" = ${hostId} AND "captureId" = ANY(${quarantined}::text[]) AND "discardedAt" IS NOT NULL`;
  return groupDiscards(discarded);
}

/**
 * Census settlement (§7.1, P3-7): after a complete census, a RELEASING lease
 * of a STOPPED sandbox on this host (or of a DELETED one this host last held)
 * with no unresolved envelope left is settled — RELEASED when its teardown
 * capture already resolved, otherwise RECOVERY_REQUIRED on a stopped disk
 * (residue stays recoverable) or RELEASED{capture_lost} once the disk is
 * gone, so drain never waits on a lease nothing will resolve. Lock order
 * H → S → leases (teardown.ts).
 */
async function settleAfterCensus(tx: Tx, hostId: string) {
  const rows = await tx.$queryRaw<{ sandboxId: string }[]>`SELECT DISTINCT l."sandboxId"
    FROM credential_lease l
    JOIN sandbox_instance s ON s.id = l."sandboxId"
    WHERE l.state::text = 'RELEASING'
      AND ((s.state::text = 'STOPPED' AND s."sandboxHostId" = ${hostId})
        OR (s.state::text = 'DELETED' AND l."hostId" = ${hostId}))
      AND NOT EXISTS (SELECT 1 FROM credential_pending_capture p
        WHERE p."hostId" = ${hostId} AND p."leaseId" = l.id)
    ORDER BY l."sandboxId" LIMIT 256`;
  // Every S in id order, then the COMPLETE settlement scope of all of them
  // in one claim-order pass, and only then settle: interleaving S(n+1) after
  // the instances of sandbox n would wait for an S while holding instances
  // another S-holder's settlement needs (§7.3, `lockSettlementScope`).
  for (const row of rows) await lockLeaseSandbox(tx, row.sandboxId);
  await lockSettlementScope(tx, { sandboxIds: rows.map((row) => row.sandboxId) });
  for (const row of rows) await settleDrainedTeardowns(tx, row.sandboxId);
}

/**
 * Applies a complete census. Returns the quarantine discards to (re)send, or
 * null when the frame arrived on a stale connection epoch.
 */
export async function applyCompleteCensus(input: {
  hostId: string;
  connectionEpoch: number;
  census: CensusAccumulator;
}): Promise<QuarantineDiscard[] | null> {
  try {
    return await prisma.$transaction((tx) => applyCensus(tx, input));
  } catch (error) {
    if (error instanceof RelayFenceRejected) return null;
    throw error;
  }
}
