/**
 * `host.lease-policy`: the daemon's live host lease ceiling, reported on the
 * current link after a local configuration change. Fenced like the terminal
 * policy report (current registered socket, matching epoch, strictly
 * increasing sequence) and, unlike it, persisted on `sandbox_host` under H so
 * placement, renewal, the pull-in sweep and the dashboard read it.
 */
import { lockCurrentHostEpoch, relayTransaction } from "@wssp/api/sandbox/relay-fence";
import { notifySharingAccessChanged } from "@wssp/api/sandbox/sharing-access";
import type { DaemonControlMessage } from "./protocol.js";

type Report = Extract<DaemonControlMessage, { type: "host.lease-policy" }>;
export type LeasePolicySession = {
  identity: { hostId: string; userId: string };
  connectionEpoch: number;
  leaseSequence: number;
};

/**
 * Returns whether the stored ceiling changed. The caller has already proven
 * the socket is the host's current registered link.
 */
export async function recordHostLeasePolicy(
  session: LeasePolicySession,
  report: Report,
  isCurrent: () => boolean,
): Promise<boolean> {
  if (report.connectionEpoch !== session.connectionEpoch) return false;
  if (report.sequence <= session.leaseSequence) return false;
  session.leaseSequence = report.sequence;
  const changed = await relayTransaction(async (tx) => {
    const host = await lockCurrentHostEpoch(tx, session.identity.hostId);
    if (
      host.userId !== session.identity.userId ||
      host.connectionEpoch !== report.connectionEpoch ||
      !isCurrent()
    )
      return false;
    const current = await tx.sandboxHost.findFirst({
      where: { id: session.identity.hostId, userId: session.identity.userId },
      select: { daemonMaxLeaseMs: true },
    });
    // Write only a change (bounded by the daemon's one-second refresh).
    if (!current || current.daemonMaxLeaseMs === report.maxLeaseMs) return false;
    const written = await tx.sandboxHost.updateMany({
      where: {
        id: session.identity.hostId,
        userId: session.identity.userId,
        connectionEpoch: report.connectionEpoch,
      },
      data: { daemonMaxLeaseMs: report.maxLeaseMs },
    });
    return written.count === 1;
  }, false);
  if (changed) notifySharingAccessChanged();
  return changed;
}
