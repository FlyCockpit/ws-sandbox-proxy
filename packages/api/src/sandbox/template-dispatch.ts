import { pinnedAllocationV11Schema } from "@wssp/sandbox-contracts";
import type { GuestIdentity } from "./guest-identity";
import { normalizeIncusFingerprint } from "./incus-image";
import { requireSandboxIntegrity } from "./sensitive-errors";

export type TemplateDispatchSource = {
  incusFingerprint: string;
  architecture: string;
  guestUid: number;
  guestGid: number;
  guestHome: string;
  guestShell: string;
};

export function templateDispatchPayload(template: TemplateDispatchSource) {
  const incusFingerprint = normalizeIncusFingerprint(template.incusFingerprint);
  const guest: GuestIdentity = {
    guestUid: template.guestUid,
    guestGid: template.guestGid,
    guestHome: template.guestHome,
    guestShell: template.guestShell,
  };
  return {
    templateDigest: incusFingerprint,
    incusFingerprint,
    architecture: template.architecture,
    ...guest,
  };
}

/** Launch identity is retained per boot, independent of tags, retirement,
 * availability and subsequent control-operation generation advances. */
export async function pinnedLaunchSource(
  tx: import("@wssp/db").Prisma.TransactionClient,
  sandboxId: string,
  userId: string,
  requireSizeIntegrity: boolean,
) {
  const sandbox = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId },
    select: {
      currentPlacementId: true,
      generation: true,
      cpuCount: true,
      memoryMiB: true,
      diskGiB: true,
      storagePoolName: true,
      storageMarker: true,
    },
  });
  if (!sandbox) return null;
  const row = await tx.sandboxPlacement.findFirst({
    where: {
      sandboxId,
      userId,
      ...(sandbox.currentPlacementId
        ? { id: sandbox.currentPlacementId }
        : { generation: sandbox.generation }),
    },
    select: {
      artifact: true,
      cpuCount: true,
      memoryMiB: true,
      diskGiB: true,
      storagePoolName: true,
      storageMarker: true,
      chargedMemoryMiB: true,
      chargedVcpu: true,
      rootChargeGiB: true,
      architecture: true,
      guestUid: true,
      guestGid: true,
      guestHome: true,
      guestShell: true,
    },
  });
  if (!row) return null;
  // Existing work and cleanup must remain possible on a corrupt allocation.
  // Only a launch depends on size; accounting writers retain their own fences.
  if (requireSizeIntegrity)
    requireSandboxIntegrity(
      row.cpuCount === sandbox.cpuCount &&
        row.memoryMiB === sandbox.memoryMiB &&
        row.diskGiB === sandbox.diskGiB &&
        row.storagePoolName === sandbox.storagePoolName &&
        row.storageMarker === sandbox.storageMarker &&
        row.chargedMemoryMiB !== null &&
        row.chargedVcpu !== null &&
        row.rootChargeGiB !== null,
      "sandbox_allocation_mismatch",
    );
  const { artifact, ...guest } = row;
  return { ...guest, incusFingerprint: artifact };
}

/** Exact boot/root binding for dispatch, including expiry cleanup. */
export function pinnedAllocationPayload(
  template: NonNullable<Awaited<ReturnType<typeof pinnedLaunchSource>>>,
) {
  return {
    allocation: pinnedAllocationV11Schema.parse({
      cpuCount: template.cpuCount,
      memoryMiB: template.memoryMiB,
      diskGiB: template.diskGiB,
      storagePoolName: template.storagePoolName,
      storageMarker: template.storageMarker,
      chargedMemoryMiB: template.chargedMemoryMiB,
      chargedVcpu: template.chargedVcpu,
      rootChargeGiB: template.rootChargeGiB,
    }),
  };
}
