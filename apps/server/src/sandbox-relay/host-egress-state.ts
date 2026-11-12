/**
 * `host.egress-state` (default-open egress §2.0.5, §2.5, M18): the daemon's
 * live egress report, sent every 5 s and on change. It is a guard-LEASE
 * renewal, not a change notification: a healthy report grants
 * `daemonEgressGuardLeaseUntil = server now() + 15 s`, an unhealthy one clears
 * it, and a daemon that stops reporting loses schedulability when the lease
 * runs out, with no further message. It also carries the node owner's
 * consent to open egress for other users' sandboxes.
 *
 * Fenced like `host.lease-policy` (current registered socket, matching epoch,
 * strictly increasing sequence, in memory and on the row) plus the guard
 * instance/generation fence: an older generation of the stored guard
 * instance is ignored. Written under H, so placement and the create gate
 * observe either the old or the new lease, never a torn one.
 */
import { noteCapacityChanged } from "@wssp/api/sandbox/capacity-queue-wake";
import { EGRESS_GUARD_LEASE_MS } from "@wssp/api/sandbox/egress-guard";
import {
  hostDatabaseNow,
  lockCurrentHostEpoch,
  relayTransaction,
} from "@wssp/api/sandbox/relay-fence";
import type { DaemonControlMessage } from "./protocol.js";

type Report = Extract<DaemonControlMessage, { type: "host.egress-state" }>;
export type EgressStateSession = {
  identity: { hostId: string; userId: string };
  connectionEpoch: number;
  egressSequence: number;
};

/**
 * Returns whether the report was applied. The caller has already proven the
 * socket is the host's current registered link.
 */
export async function recordHostEgressState(
  session: EgressStateSession,
  report: Report,
  isCurrent: () => boolean,
): Promise<boolean> {
  if (report.connectionEpoch !== session.connectionEpoch) return false;
  if (report.sequence <= session.egressSequence) return false;
  session.egressSequence = report.sequence;
  const { hostId, userId } = session.identity;
  return relayTransaction(async (tx) => {
    const host = await lockCurrentHostEpoch(tx, hostId);
    if (host.userId !== userId || host.connectionEpoch !== report.connectionEpoch || !isCurrent())
      return false;
    const current = await tx.sandboxHost.findFirst({
      where: { id: hostId, userId, connectionEpoch: report.connectionEpoch },
      select: {
        daemonEgressStateSequence: true,
        daemonEgressGuardInstanceId: true,
        daemonEgressGuardGeneration: true,
        daemonEgressGuardLeaseUntil: true,
      },
    });
    if (!current) return false;
    if (
      current.daemonEgressStateSequence !== null &&
      BigInt(report.sequence) <= current.daemonEgressStateSequence
    )
      return false;
    const instance =
      report.guardInstanceId !== undefined && report.guardGeneration !== undefined
        ? { id: report.guardInstanceId, generation: BigInt(report.guardGeneration) }
        : null;
    if (
      instance &&
      instance.id === current.daemonEgressGuardInstanceId &&
      current.daemonEgressGuardGeneration !== null &&
      instance.generation < current.daemonEgressGuardGeneration
    )
      return false;
    // The SERVER clock: the daemon's clock never extends a lease.
    const now = await hostDatabaseNow(tx);
    const written = await tx.sandboxHost.updateMany({
      where: { id: hostId, userId, connectionEpoch: report.connectionEpoch },
      data: {
        daemonEgressStateSequence: BigInt(report.sequence),
        daemonOpenEgressForOthers: report.allowOpenForOthers,
        daemonGuestSudoForOthers: report.allowGuestSudoForOthers,
        daemonEgressGuardOk: report.guardOk,
        daemonEgressGuardReason: report.guardReason ?? null,
        daemonEgressGuardEpoch: report.connectionEpoch,
        daemonEgressGuardLeaseUntil: report.guardOk
          ? new Date(now.getTime() + EGRESS_GUARD_LEASE_MS)
          : null,
        ...(instance
          ? {
              daemonEgressGuardInstanceId: instance.id,
              daemonEgressGuardGeneration: instance.generation,
            }
          : {}),
      },
    });
    // A lease that just (re)started may let a waiting create place.
    if (
      written.count === 1 &&
      report.guardOk &&
      !(current.daemonEgressGuardLeaseUntil && current.daemonEgressGuardLeaseUntil > now)
    )
      noteCapacityChanged(tx, { hostIds: [hostId] });
    return written.count === 1;
  }, false);
}
