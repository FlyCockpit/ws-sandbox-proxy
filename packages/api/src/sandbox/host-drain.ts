import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { authorityTicket } from "@wssp/db/authority";
import {
  authenticateSandboxHostWebsocketSecret,
  readHostIdentityStatus,
} from "../lib/host-token-access";
import { notifyCapacityChanged } from "./capacity-queue-wake";
import type { SetHostDrainingInput } from "./contracts";
import { hostDrainStatus, lockAdmissionHost } from "./host-admission";
import { RelayFenceRejected } from "./relay-fence";

/** Internal transaction primitive. Owner → H → credential (host plane only).
 * H is exactly the admission row; drain neither changes epochs nor emits work.
 */
export async function setHostDrainInTransaction(
  tx: Prisma.TransactionClient,
  ownerId: string,
  input: SetHostDrainingInput,
  authorize: () => Promise<void>,
) {
  const owned = await tx.sandboxHost.findFirst({
    where: { id: input.id, userId: ownerId, deletionRequestedAt: null },
    select: { id: true },
  });
  if (!owned) throw new ORPCError("NOT_FOUND");
  try {
    await lockAdmissionHost(tx, input.id, ownerId);
  } catch (error) {
    // A hello that commits an epoch bump between the epoch read and the CAS is
    // a normal race, not a server fault.
    if (error instanceof RelayFenceRejected)
      throw new ORPCError("CONFLICT", { message: "Host changed during drain." });
    throw error;
  }
  await authorize();
  const row = await tx.sandboxHost.update({
    where: { id: input.id, userId: ownerId },
    // Undrain always clears the offload switch (§10 C7).
    data: { draining: input.draining, drainOffload: input.draining && input.offload === true },
    select: {
      id: true,
      draining: true,
      drainOffload: true,
      liveCount: true,
      memoryReservedMiB: true,
      vcpuReserved: true,
    },
  });
  const {
    liveCount: _reserved,
    memoryReservedMiB: _memory,
    vcpuReserved: _vcpu,
    drainOffload,
    ...status
  } = hostDrainStatus(row);
  return { ...status, offload: drainOffload };
}

export function auditHostDrain(
  ownerId: string,
  actor: string,
  status: { id: string; draining: boolean; offload: boolean },
) {
  // Committed control-plane metadata only: no credentials, guest data or labels.
  console.info(
    JSON.stringify({
      event: "sandbox.host_drain",
      ownerId,
      actor,
      hostId: status.id,
      draining: status.draining,
      offload: status.offload,
    }),
  );
}

/** Host-plane entry: secret verification, immutable host binding, then durable
 * credential/owner revalidation under locks before the mutation. No session/SDK authority.
 */
export async function setHostDrainingWithCredential(secret: string, input: SetHostDrainingInput) {
  const identity = await authenticateSandboxHostWebsocketSecret(secret);
  if (!identity) throw new ORPCError("UNAUTHORIZED");
  if (identity.hostId !== input.id) throw new ORPCError("NOT_FOUND");
  const current = authorityTicket({
    ownerId: identity.userId,
    hostId: identity.hostId,
    credentialId: identity.tokenId,
  });
  const result = await prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, identity.userId);
    return setHostDrainInTransaction(tx, identity.userId, input, async () => {
      if (identity.credentialKind === "hostToken") {
        await tx.$queryRaw`SELECT id FROM host_token WHERE id = ${identity.tokenId} FOR SHARE`;
      } else {
        await tx.$queryRaw`SELECT id FROM host_device_credential WHERE id = ${identity.tokenId} FOR SHARE`;
      }
      if ((await readHostIdentityStatus(identity, new Date(), tx)) !== "active" || !current()) {
        throw new ORPCError("UNAUTHORIZED");
      }
    });
  });
  auditHostDrain(identity.userId, identity.credentialKind, result);
  // Committed: an undrained host may let waiting creates place.
  notifyCapacityChanged({ hostIds: [input.id] });
  return result;
}
