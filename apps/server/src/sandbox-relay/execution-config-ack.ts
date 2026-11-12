import { loadExecutionConfig } from "@wssp/api/sandbox/execution-config";
import { hostJournalKeyAcknowledged } from "@wssp/api/sandbox/idempotency";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
  requireRelayWorkload,
} from "@wssp/api/sandbox/relay-fence";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { RelaySender } from "./operation-handlers.js";
import type { DaemonControlMessage } from "./protocol.js";

/** Durable exact config ACK. The host's local checksum is never accepted here. */
export async function acknowledgeExecutionConfig(
  sender: RelaySender,
  ack: Extract<DaemonControlMessage, { type: "private.config.ack" }>,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    const binding = await requireRelayWorkload(tx, sender, ack);
    for (const id of [...new Set([binding.sandboxOwnerId, sender.userId])].sort())
      await lockOwnerForAdmission(tx, id);
    requireRelayFence(
      sender.isCurrent?.() !== false && ack.connectionEpoch === sender.connectionEpoch,
    );
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    const host = await tx.sandboxHost.findFirst({
      where: { id: sender.hostId, userId: sender.userId },
      select: {
        connectionEpoch: true,
        journalKeyVersion: true,
        journalKeyId: true,
        journalKeyAcknowledgedEpoch: true,
      },
    });
    requireRelayFence(
      host != null &&
        hostJournalKeyAcknowledged(host) &&
        host.journalKeyId === ack.config.bindingKeyId,
    );
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${ack.sandboxId} AND "userId" = ${binding.sandboxOwnerId} FOR UPDATE`;
    await requireRelayWorkload(tx, sender, ack);
    const config = await loadExecutionConfig(tx, ack.sandboxId, binding.sandboxOwnerId);
    requireRelayFence(config != null && config.hostId === sender.hostId);
    const written = await tx.sandboxExecutionConfig.updateMany({
      where: {
        id: ack.config.configId,
        sandboxId: ack.sandboxId,
        userId: binding.sandboxOwnerId,
        hostId: sender.hostId,
        generation: ack.generation,
        bindingScheme: ack.config.bindingScheme,
        bindingKeyId: ack.config.bindingKeyId,
        bindingMac: ack.config.bindingMac,
        Sandbox: { sandboxHostId: sender.hostId, state: { not: "DELETED" } },
      },
      data: {
        acknowledgedEpoch: sender.connectionEpoch,
        acknowledgedAt: await hostDatabaseNow(tx),
      },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    // An exact durable ACK unlocks install claims immediately. Dispatch claims
    // use plain UUIDs and must never be reopened by a duplicate config ACK.
    await tx.outboxEvent.updateMany({
      where: {
        userId: binding.sandboxOwnerId,
        aggregateId: ack.sandboxId,
        aggregateType: "sandbox",
        processedAt: null,
        sentAt: null,
        sentConnectionEpoch: sender.connectionEpoch,
        claimToken: { startsWith: "config:" },
        payload: { path: ["privateConfig", "configId"], equals: ack.config.configId },
      },
      data: { claimToken: null, claimedAt: null },
    });
    requireRelayFence(sender.isCurrent?.() !== false);
    return true;
  }, false);
}
