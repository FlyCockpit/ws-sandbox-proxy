import { createHash, randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { vmLiveMemoryChargeMiB, vmRootChargeGiB } from "@wssp/sandbox-contracts";
import {
  digestContextSnapshot,
  ENV_FREE_DIGEST_DOMAIN,
  REQUEST_DIGEST_DOMAIN,
} from "../digest-context";
import {
  privateConfigBinding,
  requestDigestMetadata,
  requestTransportIdentity,
} from "../idempotency";
import { outboxOperationIdOf } from "../outbox-operation";
import { writeRevisionDefaults } from "../revision-config";

/** Explicit revision fixture. IDs returned here name the revision; templateId
 * names its separately created logical template. Never used by application IO. */
export async function seedTemplateRevision(
  tx: Prisma.TransactionClient,
  input: {
    data: {
      id?: string;
      userId: string;
      sandboxHostId?: string | null;
      slug: string;
      label: string;
      imageRef?: string;
      incusFingerprint: string;
      architecture?: string;
      cpuCount?: number;
      memoryMiB?: number;
      /** The revision's default disk (32 when omitted). */
      diskGiB?: number;
      /** The revision's floor (1 when omitted: a registered image of unknown root). */
      minDiskGiB?: number;
      guestUid?: number;
      guestGid?: number;
      guestHome?: string;
      guestShell?: string;
      guestVersion?: string | null;
      retiredAt?: Date | null;
      createdAt?: Date;
      updatedAt?: Date;
    };
  },
) {
  const { data } = input;
  const logical = await tx.sandboxTemplate.create({
    data: { userId: data.userId, slug: data.slug, label: data.label },
  });
  const manifest = {
    incusFingerprint: data.incusFingerprint,
    architecture: data.architecture ?? "x86_64",
    guestUid: data.guestUid ?? 1000,
    guestGid: data.guestGid ?? 1000,
    guestHome: data.guestHome ?? "/home/user",
    guestShell: data.guestShell ?? "/bin/bash",
    guestVersion: data.guestVersion ?? null,
  };
  const revision = await tx.sandboxTemplateRevision.create({
    data: {
      id: data.id,
      userId: data.userId,
      templateId: logical.id,
      revision: 1,
      cpuCount: data.cpuCount ?? 1,
      memoryMiB: data.memoryMiB ?? 1024,
      defaultDiskGiB: data.diskGiB ?? 32,
      minDiskGiB: data.minDiskGiB ?? 1,
      ...manifest,
      manifestDigest: createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
      retiredAt: data.retiredAt,
      createdAt: data.createdAt,
    },
  });
  await writeRevisionDefaults(tx, data.userId, revision.id, {});
  await tx.sandboxTemplateTag.create({
    data: { userId: data.userId, templateId: logical.id, tag: "latest", revisionId: revision.id },
  });
  if (data.sandboxHostId) {
    const host = await tx.sandboxHost.findUniqueOrThrow({ where: { id: data.sandboxHostId } });
    await tx.sandboxTemplateAvailability.create({
      data: {
        userId: data.userId,
        revisionId: revision.id,
        hostId: host.id,
        hostOwnerId: host.userId,
        localFingerprint: revision.incusFingerprint,
        architecture: revision.architecture,
        manifestDigest: revision.manifestDigest,
        status: "AVAILABLE",
        verifiedConnectionEpoch: host.connectionEpoch,
        observedAt: new Date(),
      },
    });
  }
  return {
    ...data,
    ...revision,
    slug: logical.slug,
    label: logical.label,
    sandboxHostId: data.sandboxHostId ?? null,
  };
}

export async function seedSandboxInstance(
  tx: Prisma.TransactionClient,
  input: {
    data: Omit<Prisma.SandboxUncheckedCreateInput, "templateRevisionId" | "originalSelector"> & {
      templateRevisionId?: string;
      originalSelector?: string;
    };
  },
) {
  const { data } = input;
  const revision = await tx.sandboxTemplateRevision.findUniqueOrThrow({
    where: { id: data.templateRevisionId ?? data.templateId },
  });
  const pool = data.sandboxHostId
    ? await tx.sandboxHostStoragePool.findFirst({
        where: { sandboxHostId: data.sandboxHostId, userId: data.hostOwnerId ?? data.userId },
        orderBy: { marker: "asc" },
      })
    : null;
  const sandbox = await tx.sandbox.create({
    data: {
      hostOwnerId: data.userId,
      ...(pool
        ? {
            storagePoolId: pool.id,
            storagePoolName: pool.name,
            storageMarker: pool.marker,
            rootChargeGiB: vmRootChargeGiB(data.diskGiB ?? revision.defaultDiskGiB),
            diskGiB: data.diskGiB ?? revision.defaultDiskGiB,
            diskReservationHeld: data.state !== "DELETED",
          }
        : {}),
      ...data,
      templateId: revision.templateId,
      templateRevisionId: revision.id,
      originalSelector: data.originalSelector ?? `revision/${revision.id}`,
    },
  });
  if (sandbox.sandboxHostId) {
    if (
      !sandbox.hostOwnerId ||
      !sandbox.storagePoolId ||
      !sandbox.storageMarker ||
      !sandbox.storagePoolName ||
      sandbox.rootChargeGiB === null
    )
      throw new Error("Hosted fixture needs complete storage and owner identity.");
    if (sandbox.diskReservationHeld && pool) {
      await tx.sandboxHost.update({
        where: { id: sandbox.sandboxHostId },
        data: { rootCount: { increment: 1 } },
      });
      await tx.sandboxHostStoragePool.update({
        where: { id: pool.id },
        data: { diskReservedGiB: { increment: sandbox.rootChargeGiB! } },
      });
    }
    const configId = randomUUID();
    const binding = privateConfigBinding(
      { configId, sandboxId: sandbox.id, generation: sandbox.generation, env: [] },
      {
        ownerId: sandbox.userId,
        hostOwnerId: sandbox.hostOwnerId!,
        hostId: sandbox.sandboxHostId,
        authorizingKeyId: null,
      },
    );
    await tx.sandboxExecutionConfig.create({
      data: {
        id: configId,
        userId: sandbox.userId,
        sandboxId: sandbox.id,
        hostId: sandbox.sandboxHostId,
        generation: sandbox.generation,
        authorizingKeyId: null,
        templateDefaults: {},
        sandboxOverrides: {},
        mergedDefaults: {},
        bindingScheme: binding.bindingScheme,
        bindingKeyId: binding.bindingKeyId,
        bindingMac: binding.bindingMac,
        acknowledgedEpoch: (
          await tx.sandboxHost.findUniqueOrThrow({ where: { id: sandbox.sandboxHostId } })
        ).connectionEpoch,
        acknowledgedAt: new Date(),
      },
    });
    const operation = await tx.sandboxOperation.create({
      data: {
        userId: sandbox.userId,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "SUCCEEDED",
        generation: sandbox.generation,
        idempotencyKey: `fixture-boot:${sandbox.id}`,
        requestBodyHash: "a".repeat(64),
        digestContext: digestContextSnapshot(
          {
            domain: REQUEST_DIGEST_DOMAIN,
            hostId: sandbox.sandboxHostId,
            hostOwnerId: sandbox.hostOwnerId,
          },
          { generation: sandbox.generation },
        ),
        launchMode: "NEW_ROOT",
        createdAt: new Date(0),
        ...requestDigestMetadata(),
      },
    });
    const placement = await tx.sandboxPlacement.create({
      data: {
        userId: sandbox.userId,
        hostOwnerId: sandbox.hostOwnerId,
        sandboxId: sandbox.id,
        generation: sandbox.generation,
        operationId: operation.id,
        kind: "DIRECT",
        originHostId: sandbox.originHostId ?? "",
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        cpuCount: sandbox.cpuCount,
        memoryMiB: sandbox.memoryMiB,
        diskGiB: sandbox.diskGiB,
        storagePoolId: sandbox.storagePoolId,
        storageMarker: sandbox.storageMarker,
        storagePoolName: sandbox.storagePoolName,
        rootChargeGiB: sandbox.rootChargeGiB,
        chargedMemoryMiB: vmLiveMemoryChargeMiB(sandbox.memoryMiB),
        chargedVcpu: sandbox.cpuCount,
        artifact: revision.incusFingerprint,
        architecture: revision.architecture,
        guestUid: revision.guestUid,
        guestGid: revision.guestGid,
        guestHome: revision.guestHome,
        guestShell: revision.guestShell,
        configId,
        acceptedAt: sandbox.createdAt,
      },
    });
    return tx.sandbox.update({
      where: { id: sandbox.id },
      data: { currentPlacementId: placement.id },
    });
  }
  return sandbox;
}

/** Negotiated, reconciled launch fixture. Explicit overrides retain refusal cases. */
export async function seedLaunchHost(
  tx: Prisma.TransactionClient,
  input: { data: Prisma.SandboxHostUncheckedCreateInput },
) {
  const data = input.data;
  const epoch = data.connectionEpoch ?? 1;
  const host = await tx.sandboxHost.create({
    data: {
      vcpuReserved: data.liveCount ?? 0,
      daemonVcpuBudget: 64,
      memoryReservedMiB: (data.liveCount ?? 0) * vmLiveMemoryChargeMiB(1024),
      daemonMemoryBudgetMiB: 65536,
      daemonMaxCpuCount: 32,
      ...(data.status === "CONNECTED"
        ? {
            connectionEpoch: epoch,
            relayProtocolVersion: "1.0",
            relayProtocolEpoch: epoch,
            lastHeartbeatAt: new Date(),
            admissionEpoch: epoch,
            admissionRuntime: "FAKE" as const,
            inventoryAcknowledgedEpoch: epoch,
            daemonSchedulable: true,
            daemonFeatures: { egressPolicy: true, terminal: true },
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: epoch,
            // A current daemon with a healthy egress guard (default-open
            // egress, M11): an active lease at this epoch. Tests of the lease
            // itself override these fields.
            daemonEgressGuardOk: true,
            daemonEgressGuardEpoch: epoch,
            daemonEgressGuardLeaseUntil: new Date("2999-01-01T00:00:00.000Z"),
          }
        : {}),
      ...data,
    },
  });
  await tx.sandboxHostStoragePool.create({
    data: {
      sandboxHostId: host.id,
      userId: host.userId,
      name: "default",
      marker: `marker_${host.id}`,
      capacityGiB: 8192,
      capacitySource: "explicit",
      newRootsAllowed: true,
      configured: true,
      health: "healthy",
      connectionEpoch: host.connectionEpoch || 1,
      observationSequence: 0,
      reportedAt: new Date(),
    },
  });
  return host;
}

/** A directly seeded accepted operation uses the current digest scheme unless
 * a test explicitly supplies different metadata. No request values are retained. */
export async function seedAcceptedOperation(
  tx: Prisma.TransactionClient,
  input: {
    data: Omit<
      Prisma.SandboxOperationUncheckedCreateInput,
      "requestDigestScheme" | "digestContext"
    > &
      Partial<
        Pick<Prisma.SandboxOperationUncheckedCreateInput, "requestDigestScheme" | "digestContext">
      >;
  },
) {
  const envFree = ["KILL_SANDBOX", "STOP_SANDBOX"].includes(input.data.kind);
  const transport =
    input.data.digestContext === undefined && !envFree
      ? await requestTransportIdentity(tx, input.data.userId, undefined, input.data.sandboxId)
      : null;
  return tx.sandboxOperation.create({
    data: {
      ...requestDigestMetadata(input.data.kind),
      digestContext: digestContextSnapshot(
        {
          domain: envFree ? ENV_FREE_DIGEST_DOMAIN : REQUEST_DIGEST_DOMAIN,
          hostId: transport?.sandboxHostId,
          hostOwnerId: transport?.hostOwnerId,
        },
        { generation: input.data.generation },
      ),
      ...input.data,
    },
  });
}

/** Seed a modern accepted outbox against its already installed private snapshot.
 * Negative binding tests keep any explicitly supplied reference unchanged.
 * Like every production writer, the `operationId` column copies
 * `payload.operationId` unless the test supplies the column itself. */
export async function seedDispatchEvent(
  tx: Prisma.TransactionClient,
  seeded: {
    data: Omit<Prisma.OutboxEventUncheckedCreateInput, "operationId"> & { operationId?: string };
  },
) {
  const payload = seeded.data.payload;
  const input = {
    data: {
      ...seeded.data,
      operationId:
        seeded.data.operationId ?? outboxOperationIdOf(payload as Prisma.InputJsonObject),
    },
  };
  if (
    payload &&
    typeof payload === "object" &&
    !Array.isArray(payload) &&
    "kind" in payload &&
    ["sandbox.create", "sandbox.reconnect", "command.run"].includes(String(payload.kind))
  ) {
    const config = await tx.sandboxExecutionConfig.findFirst({
      where: { sandboxId: input.data.aggregateId, userId: input.data.userId },
    });
    if (config && !Object.hasOwn(payload, "privateConfig"))
      return tx.outboxEvent.create({
        data: {
          ...input.data,
          payload: {
            ...payload,
            privateConfig: {
              configId: config.id,
              bindingScheme: config.bindingScheme,
              bindingKeyId: config.bindingKeyId,
              bindingMac: config.bindingMac,
            },
          },
        },
      });
  }
  return tx.outboxEvent.create(input);
}

/** Older relay fixtures focus on authority/lease behavior after installation.
 * The config handshake itself is exercised by dispatch-config and the live
 * lifecycle host double. Model that completed fixture setup explicitly. */
export async function acknowledgeFixtureExecutionConfigs(tx: Prisma.TransactionClient) {
  let cursor = "";
  for (;;) {
    const rows = await tx.sandboxExecutionConfig.findMany({
      where: { id: { gt: cursor } },
      orderBy: { id: "asc" },
      take: 100,
      select: { id: true, hostId: true, userId: true },
    });
    for (const row of rows) {
      const host = await tx.sandboxHost.findFirst({
        where: { id: row.hostId, userId: row.userId },
        select: { connectionEpoch: true, journalKeyAcknowledgedEpoch: true },
      });
      if (host && host.connectionEpoch === host.journalKeyAcknowledgedEpoch)
        await tx.sandboxExecutionConfig.update({
          where: { id: row.id },
          data: { acknowledgedEpoch: host.connectionEpoch, acknowledgedAt: new Date() },
        });
    }
    if (rows.length < 100) return;
    cursor = rows[rows.length - 1]!.id;
  }
}
