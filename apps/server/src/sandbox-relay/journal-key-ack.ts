import { noteCapacityChanged } from "@wssp/api/sandbox/capacity-queue-wake";
import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
} from "@wssp/api/sandbox/relay-fence";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { RelaySender } from "./operation-handlers.js";
import type { DaemonControlMessage } from "./protocol.js";

/** ACKs have no key material. Owner → H; a stale socket cannot bless its successor. */
export async function acknowledgeJournalKey(
  sender: RelaySender,
  ack: Extract<DaemonControlMessage, { type: "journal.key.ack" }>,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    requireRelayFence(
      sender.isCurrent?.() !== false && ack.connectionEpoch === sender.connectionEpoch,
    );
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(ack.keyId === requestDigestMetadata().requestDigestKeyId);
    const written = await tx.sandboxHost.updateMany({
      where: {
        id: sender.hostId,
        userId: sender.userId,
        connectionEpoch: sender.connectionEpoch,
        journalKeyVersion: ack.keyVersion,
        journalKeyId: ack.keyId,
      },
      data: { journalKeyAcknowledgedEpoch: sender.connectionEpoch },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    // The host is now schedulable on this connection (post-commit wake).
    noteCapacityChanged(tx, { hostIds: [sender.hostId] });
    return true;
  }, false);
}

/** Disconnect and hello use the same owner → H epoch boundary as key ACKs. */
export async function disconnectJournalKey(sender: RelaySender, _now: Date, revoke: boolean) {
  return relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    const host = await tx.sandboxHost.findFirst({
      where: { id: sender.hostId, userId: sender.userId, connectionEpoch: sender.connectionEpoch },
      select: {
        connectionEpoch: true,
        relayProtocolVersion: true,
        relayProtocolEpoch: true,
        admissionRuntime: true,
        admissionEpoch: true,
      },
    });
    requireRelayFence(host !== null);
    const validProtocol =
      host.relayProtocolVersion !== null && host.relayProtocolEpoch === host.connectionEpoch;
    const validRuntime =
      validProtocol &&
      host.admissionEpoch === host.connectionEpoch &&
      (host.admissionRuntime === "FAKE" || host.admissionRuntime === "INCUS_KVM");
    const now = await hostDatabaseNow(tx);
    const written = await tx.sandboxHost.updateMany({
      where: { id: sender.hostId, userId: sender.userId, connectionEpoch: sender.connectionEpoch },
      data: {
        status: "DISCONNECTED",
        lastDisconnectedAt: now,
        journalKeyAcknowledgedEpoch: null,
        // The egress guard lease belongs to the live connection (§2.0.5).
        daemonEgressGuardLeaseUntil: null,
        ...(revoke
          ? {
              connectionEpoch: { increment: 1 },
              relayProtocolVersion: validProtocol ? host.relayProtocolVersion : null,
              relayProtocolEpoch: validProtocol ? host.connectionEpoch + 1 : null,
              admissionRuntime: validRuntime ? host.admissionRuntime : null,
              admissionEpoch: validRuntime ? host.connectionEpoch + 1 : null,
            }
          : {}),
      },
    });
    requireRelayFence(written.count === 1);
    return true;
  }, false);
}
