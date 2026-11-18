import { randomUUID } from "node:crypto";
import type { Prisma, SandboxPurpose } from "@wssp/db";
import {
  type NormalizedEgressPolicy,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { writeCreateAttachments, writeLaunchSpec } from "../credentials/launch";
import { claimCreateLeases } from "../credentials/resume";
import type { CredentialClaimRequest } from "../credentials/selection";
import { preflightCredentialSpec } from "../credentials/specs";
import type { BuildRole } from "../template-builds/build-authority";
import { OPERATION_DISPATCH_KIND, type Principal } from "./contracts";
import { operationDigestContext } from "./digest-context";
import type { OffloadPolicyColumns } from "./disk-offload/policy";
import { resolveEffectiveEgress } from "./egress-policy";
import { invalidSandboxTransition, sandboxStateConflict } from "./errors";
import { executionEnvPairs } from "./execution-config";
import { resolveEffectiveGuestSudo, revisionRootTaint } from "./guest-sudo-policy";
import { reserveLiveResources, reserveRootResources } from "./host-admission";
import { privateConfigBinding, requestDigestMetadata } from "./idempotency";
import type { ImageFetchPlan } from "./image-placement";
import { hostImageFeatures, leaseFromReadyEnabled } from "./image-store/config";
import { defaultIncusInstanceName } from "./incus-name";
import { acceptedLaunchMode } from "./launch-mode";
import {
  acceptedLeaseFields,
  initialLeaseFields,
  type LeaseClock,
  leaseTransactionNow,
} from "./lease";
import { provisionMaxMs } from "./lease-policy";
import { createSandboxOutboxEvent } from "./outbox";
import { lockPlacementSuffix, type PlacedResult, poolHostRecheck } from "./pool-placement";
import { attributionOf, buildIdOf, recordedKeyIdOf } from "./principal-kinds";
import { loadRevisionDefaults } from "./revision-config";
import { resolveCreateSandboxName } from "./sandbox-names";
import { templateDispatchPayload } from "./template-dispatch";

/**
 * The normalized create intent that placement needs. For a waiting create it
 * is stored privately on the wait row (`SandboxCapacityWait.intent`) and
 * scrubbed when the wait ends; it is never projected or logged.
 */
export type CreateIntent = {
  originalSelector: string;
  /** Sandbox env overrides (template defaults merge in at placement). */
  overrides: Record<string, string>;
  metadata: Record<string, unknown>;
  /** The normalized egress request; the effective policy is resolved at placement. */
  egress: { request: NormalizedEgressPolicy };
  /** Relative lease; 0 means no lease timer. */
  timeoutMs: number;
  onExpire: "stop" | "destroy";
  /**
   * Requested guestSudo after the WORKLOAD default (false for managed
   * creates). A stored pre-feature intent reads false (`parseIntent`).
   */
  guestSudo: boolean;
  /** Preview tunnels: declared ports, ascending (absent on a pre-feature intent). */
  tunnelPorts?: number[];
};

/**
 * The managed-sandbox facts of a create by `owner`, written at insert : a build principal's create is the build
 * VM (`purpose = TEMPLATE_BUILD`, immutable `buildId`); every other create is
 * an ordinary workload. Never derived from ambient state.
 */
export function buildSandboxFields(
  owner: Principal,
  role: BuildRole | null,
):
  | { purpose: "TEMPLATE_BUILD"; buildId: string }
  | { purpose: "TEMPLATE_VERIFY"; verifyBuildId: string }
  | Record<string, never> {
  const buildId = buildIdOf(owner);
  // The role is required (community-base L1): a build principal's create is
  // its build VM or its community verify VM, never a workload, and nobody
  // else's create is either.
  if ((buildId === null) !== (role === null)) throw sandboxStateConflict();
  if (buildId === null) return {};
  return role === "verify"
    ? { purpose: "TEMPLATE_VERIFY", verifyBuildId: buildId }
    : { purpose: "TEMPLATE_BUILD", buildId };
}

/** The `sandbox.create` image field of a fetch plan (relay 1.0). */
function dispatchImageOf(plan: ImageFetchPlan) {
  if (plan.mode !== "upstream")
    return {
      fingerprint: plan.fingerprint,
      sizeBytes: Number(plan.sizeBytes),
      format: "unified",
      source: "fetch",
    };
  return {
    fingerprint: plan.fingerprint,
    sizeBytes: Number(plan.sizeBytes),
    format: "split",
    source: "upstream",
    upstream: {
      metaPath: plan.upstream.metaPath,
      metaSha256: plan.upstream.metaSha256,
      metaSize: Number(plan.upstream.metaSize),
      diskPath: plan.upstream.diskPath,
      diskSha256: plan.upstream.diskSha256,
      diskSize: Number(plan.upstream.diskSize),
    },
  };
}

/** A server-internal managed create (MS0) other than a build VM: the CLI-login
 * flow's CREDENTIAL_LOGIN sandbox and its post-S rows. */
export type ManagedCreate = {
  purpose: Exclude<SandboxPurpose, "WORKLOAD" | "TEMPLATE_BUILD" | "TEMPLATE_VERIFY">;
  afterSandbox: (
    tx: Prisma.TransactionClient,
    created: { sandboxId: string; operationId: string; generation: number; hostId: string },
  ) => Promise<void>;
};

type Ids = {
  idempotencyKey: string;
  /** A fresh create: the sandbox and its CREATE operation are created here. */
  fresh?: {
    bodyHash: () => string;
    /** The caller's name, or undefined to generate one (never in `CreateIntent`). */
    name?: string;
    /** The requested offload policy (WORKLOAD only); omitted keeps the column default. */
    offloadPolicy?: OffloadPolicyColumns;
    /** A build principal's create: which of its VMs this is (createSandbox
     * asserts it against the in-transaction authorization). */
    buildRole?: BuildRole;
    /** CLI logins named by the create (attachment rows + claims here). */
    credentials?: readonly CredentialClaimRequest[];
    /**
     * A managed sandbox (MS0) created by wssp itself: its purpose, and the
     * flow's own rows written after S and before O (the CLI-login session and
     * its LOGIN claim, §11), given the preassigned CREATE operation id.
     */
    managed?: ManagedCreate;
  };
  /** A waiting create being placed: its rows already exist. */
  queued?: { sandboxId: string; operationId: string; generation: number };
};

/**
 * Pin a resolved placement (H held by `resolvePlacement`) as durable launch
 * intent: sandbox placement fields and lease, execution config, operation
 * lease acceptance, placement row, outbox event, live/root reservations and
 * the locked suffix. The lease starts now (placement), never at queue entry;
 * on a host that negotiated lease-from-READY (M7) the stored deadline is a
 * provisional backstop until the host ACKs readyAt + timeout.
 * Returns the sandbox id.
 */
export async function materializePlacement(
  tx: Prisma.TransactionClient,
  owner: Principal,
  target: PlacedResult,
  intent: CreateIntent,
  ids: Ids,
  clock: LeaseClock,
): Promise<string> {
  const template = target.revision;
  const size = target.size;
  const hostId = target.hostId;
  // A waiting create is always a build VM or a workload (verify never waits).
  const role: BuildRole | null =
    buildIdOf(owner) === null ? null : ids.queued ? "build" : (ids.fresh?.buildRole ?? "build");
  // I12 / review4 U7: bootstrap and the upstream plan come from the WRITTEN
  // row's facts (a TEMPLATE_BUILD sandbox of an UPSTREAM revision), on the
  // fresh and the waiting path alike, never from a caller flag. An UPSTREAM
  // revision boots nowhere else.
  const upstreamRevision = template.sourceKind === "UPSTREAM";
  if (upstreamRevision && role !== "build") throw sandboxStateConflict();
  if (target.imageFetch?.mode === "upstream" && !upstreamRevision) throw sandboxStateConflict();
  // §1.2: the effective egress policy is resolved exactly once per sandbox,
  // here, from host facts read under H; never re-derived afterwards.
  const egress = resolveEffectiveEgress(intent.egress.request, target.egressHost, owner.ownerId);
  const egressFields = {
    egressPolicy: egress.effective.wire as Prisma.InputJsonValue,
    egressPolicyHash: egress.effective.hash,
    egressRequest: intent.egress.request as Prisma.InputJsonValue,
    egressModeReason: egress.reason,
  };
  // OD-2: the effective guestSudo is resolved exactly once, here, beside
  // egress. The revision's root taint is read explicitly in this transaction
  // (S8): revisionPublicSelect is a disclosure projection, not a policy input.
  const guestSudo = resolveEffectiveGuestSudo(
    intent.guestSudo,
    target.guestSudoHost,
    owner.ownerId,
  );
  const rootFacts = await tx.sandboxTemplateRevision.findFirstOrThrow({
    where: { id: template.id, userId: owner.ownerId },
    select: {
      builtWithRoot: true,
      capturedWithGuestRoot: true,
      builtWithWsspRecipe: true,
    } satisfies Prisma.SandboxTemplateRevisionSelect,
  });
  const guestSudoFields = {
    tunnelPorts: intent.tunnelPorts ?? [],
    guestSudoRequested: intent.guestSudo,
    guestSudo: guestSudo.effective,
    guestSudoReason: guestSudo.reason,
    guestRoot: guestSudo.effective || revisionRootTaint(rootFacts),
  };
  const templateDefaults = await loadRevisionDefaults(tx, template.id, owner.ownerId);
  const overrides = executionEnvPairs(intent.overrides);
  const env = executionEnvPairs({
    ...Object.fromEntries(templateDefaults),
    ...Object.fromEntries(overrides),
  });
  const acceptedAt = await leaseTransactionNow(tx, clock);
  // Lease from READY (M7): the clock starts when the sandbox is ready (image
  // download included). Unlimited leases and runtimes without lease-from-ready
  // support keep the lease accepted by the server.
  const fromReadyMs =
    leaseFromReadyEnabled() &&
    intent.timeoutMs > 0 &&
    hostImageFeatures(
      (
        await tx.sandboxHost.findUnique({
          where: { id: hostId },
          select: { daemonFeatures: true },
        })
      )?.daemonFeatures ?? null,
    )?.leaseFromReady
      ? intent.timeoutMs
      : undefined;
  const lease = initialLeaseFields({
    timeoutMs: fromReadyMs === undefined ? intent.timeoutMs : fromReadyMs + provisionMaxMs(),
    onExpire: intent.onExpire,
    now: acceptedAt.getTime(),
  });
  const placementFields = {
    hostOwnerId: target.hostOwnerId,
    storagePoolId: target.storagePool.id,
    storageMarker: target.storagePool.marker,
    storagePoolName: target.storagePool.name,
    rootChargeGiB: vmRootChargeGiB(size.diskGiB),
    usagePoolId: target.poolId,
    usageMemberId: target.memberId,
    sandboxHostId: hostId,
    originHostId: hostId,
    ...lease,
    leasePendingReady: fromReadyMs !== undefined,
  };
  let sandboxId: string;
  let generation: number;
  if (ids.queued) {
    sandboxId = ids.queued.sandboxId;
    generation = ids.queued.generation;
    // S: the only WAITING_FOR_CAPACITY → REQUESTED transition (§4.1).
    const placed = await tx.sandbox.updateMany({
      where: {
        id: sandboxId,
        userId: owner.ownerId,
        state: "WAITING_FOR_CAPACITY",
        generation,
        // A waiting create materializes only under the principal it was
        // stored for: a build VM for its build, a workload for anyone else.
        buildId: buildIdOf(owner),
      },
      data: { ...placementFields, ...egressFields, ...guestSudoFields, state: "REQUESTED" },
    });
    if (placed.count !== 1) throw invalidSandboxTransition("WAITING_FOR_CAPACITY", "REQUESTED");
  } else {
    sandboxId = randomUUID();
    // Under lock 31 (resolvePlacement) and after authorization.
    const name = await resolveCreateSandboxName(tx, owner.ownerId, ids.fresh?.name);
    const created = await tx.sandbox.create({
      data: {
        id: sandboxId,
        userId: owner.ownerId,
        name,
        templateId: template.templateId,
        templateRevisionId: template.id,
        cpuCount: size.cpuCount,
        memoryMiB: size.memoryMiB,
        diskGiB: size.diskGiB,
        originalSelector: intent.originalSelector,
        originPoolId: target.poolId,
        state: "REQUESTED",
        metadata: intent.metadata as Prisma.InputJsonValue,
        ...egressFields,
        ...guestSudoFields,
        ...(ids.fresh?.offloadPolicy ?? {}),
        incusName: defaultIncusInstanceName(sandboxId),
        ...buildSandboxFields(owner, role),
        ...(ids.fresh?.managed ? { purpose: ids.fresh.managed.purpose } : {}),
        ...placementFields,
      },
      select: { generation: true },
    });
    generation = created.generation;
  }

  // CLI logins (§7.2, §6.1), after S and before O: the attachment rows, the
  // worst-case spec preflight (before any claim), then the claims. A queued
  // create's rows and claims were written at entry and by the queue head.
  const freshCredentials = ids.fresh?.credentials ?? [];
  let preassignedOperationId: string | undefined;
  if (!ids.queued && freshCredentials.length > 0) {
    await writeCreateAttachments(tx, {
      ownerId: owner.ownerId,
      principal: owner,
      sandboxId,
      requests: freshCredentials,
    });
    await preflightCredentialSpec(tx, {
      sandboxId,
      credentialIds: freshCredentials.map((request) => request.credentialId),
    });
    preassignedOperationId = `op${randomUUID().replaceAll("-", "")}`;
    await claimCreateLeases(tx, {
      principal: owner,
      ownerId: owner.ownerId,
      sandboxId,
      operationId: preassignedOperationId,
      hostId,
    });
  }
  const managed = ids.queued ? undefined : ids.fresh?.managed;
  if (managed) {
    if (freshCredentials.length > 0) throw sandboxStateConflict();
    preassignedOperationId = `op${randomUUID().replaceAll("-", "")}`;
    await managed.afterSandbox(tx, {
      sandboxId,
      operationId: preassignedOperationId,
      generation,
      hostId,
    });
  }

  const configId = randomUUID();
  const authorizingKeyId = recordedKeyIdOf(owner);
  const binding = privateConfigBinding(
    { configId, sandboxId, generation, env },
    { ownerId: owner.ownerId, hostOwnerId: target.hostOwnerId, hostId, authorizingKeyId },
  );
  await tx.sandboxExecutionConfig.create({
    data: {
      id: configId,
      userId: owner.ownerId,
      sandboxId,
      generation,
      hostId,
      authorizingKeyId,
      templateDefaults: Object.fromEntries(templateDefaults),
      sandboxOverrides: Object.fromEntries(overrides),
      mergedDefaults: Object.fromEntries(env),
      bindingScheme: binding.bindingScheme,
      bindingKeyId: binding.bindingKeyId,
      bindingMac: binding.bindingMac,
    },
  });
  const accepted = {
    ...acceptedLeaseFields({
      now: acceptedAt,
      timeoutMs: intent.timeoutMs,
      revision: lease.leaseRevision,
      expiresAt: lease.leaseExpiresAt,
      action: lease.leaseExpireAction,
    }),
    leaseFromReady: fromReadyMs !== undefined,
    // §8.4: immutable launch semantics, stamped at acceptance (a queued
    // CREATE already carries it from the capacity queue; same value).
    launchMode: acceptedLaunchMode("CREATE_SANDBOX"),
  };
  let operationId: string;
  if (ids.queued) {
    operationId = ids.queued.operationId;
    const updated = await tx.sandboxOperation.updateMany({
      where: {
        id: operationId,
        userId: owner.ownerId,
        sandboxId,
        kind: "CREATE_SANDBOX",
        state: "QUEUED",
      },
      data: accepted,
    });
    if (updated.count !== 1) throw sandboxStateConflict();
  } else {
    if (!ids.fresh) throw sandboxStateConflict();
    const operation = await tx.sandboxOperation.create({
      data: {
        ...(preassignedOperationId ? { id: preassignedOperationId } : {}),
        authorizingKeyId,
        userId: owner.ownerId,
        sandboxId,
        kind: "CREATE_SANDBOX",
        ...accepted,
        state: "QUEUED",
        generation,
        idempotencyKey: ids.idempotencyKey,
        requestBodyHash: ids.fresh.bodyHash(),
        ...requestDigestMetadata(),
        digestContext: operationDigestContext(tx),
      },
    });
    operationId = operation.id;
  }

  const credentialSpec =
    ids.queued || freshCredentials.length > 0
      ? await writeLaunchSpec(tx, { sandboxId, operationId })
      : null;

  const placement = await tx.sandboxPlacement.create({
    data: {
      userId: owner.ownerId,
      hostOwnerId: target.hostOwnerId,
      sandboxId,
      generation,
      operationId,
      kind: target.poolId ? "POOL" : "DIRECT",
      originPoolId: target.poolId,
      originMemberId: target.memberId,
      originShareId: target.originShareId,
      acceptedGraceSeconds: target.acceptedGraceSeconds,
      originHostId: hostId,
      templateId: template.templateId,
      templateRevisionId: template.id,
      cpuCount: size.cpuCount,
      memoryMiB: size.memoryMiB,
      diskGiB: size.diskGiB,
      storagePoolId: target.storagePool.id,
      storageMarker: target.storagePool.marker,
      storagePoolName: target.storagePool.name,
      rootChargeGiB: vmRootChargeGiB(size.diskGiB),
      chargedMemoryMiB: vmLiveMemoryChargeMiB(size.memoryMiB),
      chargedVcpu: size.cpuCount,
      artifact: template.incusFingerprint,
      architecture: template.architecture,
      guestUid: template.guestUid,
      guestGid: template.guestGid,
      guestHome: template.guestHome,
      guestShell: template.guestShell,
      configId,
      acceptedAt,
      imageFetchBytes: target.imageFetch?.sizeBytes ?? null,
    },
  });
  await createSandboxOutboxEvent(tx, {
    authorizingPrincipal: attributionOf(owner),
    userId: owner.ownerId,
    aggregateId: sandboxId,
    eventType: "sandbox.create_requested",
    payload: {
      sandboxId,
      sandboxHostId: hostId,
      templateId: template.id,
      ...templateDispatchPayload(template),
      ...size,
      incusName: defaultIncusInstanceName(sandboxId),
      generation,
      dispatchAttempt: 0,
      operationId,
      idempotencyKey: ids.idempotencyKey,
      kind: OPERATION_DISPATCH_KIND.CREATE_SANDBOX,
      egressPolicy: egress.effective.wire,
      egressPolicyHash: egress.effective.hash,
      ...(credentialSpec ? { credentialSpec } : {}),
      ...(fromReadyMs !== undefined ? { leaseFromReadyMs: fromReadyMs } : {}),
      // Relay 1.0 build binding (`sandbox.create` only), from the principal,
      // on the build VM only (a verify VM gets no build binding and no root).
      ...(role === "build"
        ? { build: { buildId: buildIdOf(owner), ...(upstreamRevision ? { bootstrap: true } : {}) } }
        : {}),
      ...(target.imageFetch ? { image: dispatchImageOf(target.imageFetch) } : {}),
    },
  });

  await tx.sandbox.update({
    where: { id: sandboxId },
    data: { currentPlacementId: placement.id },
  });
  await poolHostRecheck(target.poolId, async () => {
    const claim = { hostId, ownerId: owner.ownerId, sandboxId };
    await reserveLiveResources(tx, claim);
    await reserveRootResources(tx, claim);
  });
  await tx.sandboxHost.update({
    where: { id: hostId },
    data: { lastPlacedAt: acceptedAt },
  });
  await lockPlacementSuffix(tx, owner, target);
  return sandboxId;
}
