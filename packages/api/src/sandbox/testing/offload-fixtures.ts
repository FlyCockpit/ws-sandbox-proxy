import { randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { dataRootKey } from "../../crypto/data-key";
import {
  completeDiskSession,
  type DiskWrapKeys,
  deriveDiskWrapKeys,
  generateDiskDek,
  newDiskSessionWrap,
} from "../disk-offload/keys";

/**
 * Test-only disk offload rows, built through the real key
 * paths: a session opened with a wrapped DEK, completed by the two-row CAS,
 * then marked STORED. Never used by application IO. Uses a fixed test root
 * unless `keys` is given; the clone's `data_key_epoch` is bootstrapped with
 * that root's kid on first use.
 */
export const OFFLOAD_FIXTURE_KEYS: DiskWrapKeys = deriveDiskWrapKeys({
  current: dataRootKey("5a".repeat(32)),
  previous: null,
});

const FINGERPRINT = `sha256:${"d".repeat(64)}`;

/** An OPEN disk session with its own wrapped DEK, on a fresh offload row. */
export async function seedOpenDiskSession(
  tx: Prisma.TransactionClient,
  input: {
    userId: string;
    sandboxId: string;
    hostId: string;
    seq?: number;
    keys?: DiskWrapKeys;
  },
) {
  const seq = input.seq ?? 1;
  const offload = await tx.sandboxDiskOffload.create({
    data: {
      sandboxId: input.sandboxId,
      userId: input.userId,
      seq,
      sourceGeneration: 1,
      sourceHostId: input.hostId,
      sourceHostOwnerId: input.userId,
      state: "UPLOADING",
      liveSandboxId: input.sandboxId,
    },
    select: { id: true },
  });
  const transfer = await tx.sandboxImageTransfer.create({
    data: {
      userId: input.userId,
      fingerprint: FINGERPRINT,
      purpose: "OFFLOAD_UPLOAD",
      mode: "S3",
      sourceHostId: input.hostId,
      sourceHostOwnerId: input.userId,
      sizeBytes: 1024n,
      partSize: 1024,
      partCount: 1,
      expiresAt: new Date(Date.now() + 3_600_000),
      diskOffloadId: offload.id,
    },
    select: { id: true },
  });
  const sessionId = `ses-${randomUUID()}`;
  const dek = generateDiskDek();
  const wrap = await newDiskSessionWrap(
    tx,
    {
      userId: input.userId,
      sandboxId: input.sandboxId,
      offloadId: offload.id,
      seq,
      sessionId,
    },
    dek,
    input.keys ?? OFFLOAD_FIXTURE_KEYS,
  );
  await tx.sandboxImageUploadSession.create({
    data: {
      id: sessionId,
      transferId: transfer.id,
      diskOffloadId: offload.id,
      liveDiskOffloadId: offload.id,
      userId: input.userId,
      hostId: input.hostId,
      hostEpoch: 1,
      objectKey: `wssp/owners/${input.userId}/sandboxes/${input.sandboxId}/${offload.id}/${sessionId}.wsspenc`,
      sizeBytes: 1024n,
      storedBytes: 1056n,
      partSize: 1056,
      ...wrap,
    },
  });
  return { offloadId: offload.id, sessionId, transferId: transfer.id, dek };
}

/** A STORED offload (completed and verified) for `sandboxId`. */
export async function seedStoredOffload(
  tx: Prisma.TransactionClient,
  input: { userId: string; sandboxId: string; hostId: string; seq?: number; keys?: DiskWrapKeys },
) {
  const open = await seedOpenDiskSession(tx, input);
  if (!(await completeDiskSession(tx, open))) throw new Error("fixture complete failed");
  await tx.sandboxDiskOffload.update({
    where: { id: open.offloadId },
    data: {
      state: "STORED",
      fingerprint: FINGERPRINT,
      sizeBytes: 1024n,
      verifiedAt: new Date(),
      storedAt: new Date(),
    },
  });
  return open;
}

/**
 * Moves an existing sandbox to OFFLOADED with a STORED offload: every host,
 * placement, pool, hold, lease and grace field cleared (the
 * `sandbox_instance_offloaded` CHECK).
 */
export async function offloadSandboxForTest(
  tx: Prisma.TransactionClient,
  input: { userId: string; sandboxId: string; hostId: string; keys?: DiskWrapKeys },
) {
  const stored = await seedStoredOffload(tx, input);
  await tx.sandbox.update({
    where: { id: input.sandboxId },
    data: {
      state: "OFFLOADED",
      diskOffloadId: stored.offloadId,
      offloadSeq: 1,
      sandboxHostId: null,
      hostOwnerId: null,
      currentPlacementId: null,
      usagePoolId: null,
      usageMemberId: null,
      storagePoolId: null,
      storageMarker: null,
      storagePoolName: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
      leaseExpiresAt: null,
      leaseExpiresAtRequested: null,
      leaseExpiresAtEffective: null,
      accessGraceUntil: null,
      accessGraceReason: null,
    },
  });
  return stored;
}

/** Host features of a current offload-capable daemon (image fetch, egress). */
export const OFFLOAD_HOST_FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: true,
    leaseFromReady: false,
    captureStorageMarkers: [],
  },
};

/**
 * A connected, admitted, offload-capable host owned by `userId` (with its
 * storage pool and a fresh egress guard lease), and a STOPPED sandbox on it
 * at `generation`. Built through the shared launch fixtures.
 */
export async function seedStoppedOnHost(
  tx: Prisma.TransactionClient,
  input: {
    userId: string;
    hostOwnerId?: string;
    host?: Partial<Prisma.SandboxHostUncheckedCreateInput>;
    sandbox?: Partial<Prisma.SandboxUncheckedCreateInput>;
  },
) {
  const { seedLaunchHost, seedSandboxInstance, seedTemplateRevision } = await import(
    "./resource-fixtures"
  );
  const hostOwnerId = input.hostOwnerId ?? input.userId;
  const host = await seedLaunchHost(tx, {
    data: {
      userId: hostOwnerId,
      slug: `h-${randomUUID().slice(0, 8)}`,
      label: "Host",
      status: "CONNECTED",
      daemonFeatures: OFFLOAD_HOST_FEATURES,
      daemonDiskOffload: true,
      egressEnforcement: true,
      ...input.host,
    },
  });
  const revision = await seedTemplateRevision(tx, {
    data: {
      userId: input.userId,
      slug: `t-${randomUUID().slice(0, 8)}`,
      label: "T",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(tx, {
    data: {
      userId: input.userId,
      templateId: revision.id,
      sandboxHostId: host.id,
      hostOwnerId,
      originHostId: host.id,
      state: "STOPPED",
      ...input.sandbox,
    },
  });
  return { host, revision, sandbox };
}
