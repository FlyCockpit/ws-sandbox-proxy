import { createHash } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma, type TemplateBuildState } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  CAPTURE_SCRUB_PATHS_MAX,
  validScrubPath,
  vmDiskGiBSchema,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { requireNoCredentialWorkInFlight } from "../../credentials/leases";
import { hostCredentialCapable } from "../../credentials/placement";
import {
  buildCaptureScrubSpec,
  encodeCredentialSpec,
  writeOperationSpec,
} from "../../credentials/specs";
import { entityId } from "../../lib/schemas";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { buildAuthorityLost, buildStepAllowed } from "../../template-builds/build-authority";
import { VERIFY_WINDOW_MINUTES } from "../../template-builds/community/catalog";
import { refuseCommunityWrite } from "../../template-builds/community/managed";
import { builtWithWsspRecipe } from "../../template-builds/community/wssp-recipe";
import { chargedMinutes } from "../../template-builds/decide";
import { loadBuildExecPlan } from "../../template-builds/exec-plan";
import {
  notifyTemplateBuildProgress,
  notifyTemplateBuildsChanged,
} from "../../template-builds/wake";
import { consumeSandboxWriteBudget } from "../budgets";
import { noteCapacityChanged } from "../capacity-queue-wake";
import { idempotencyKey, type Principal } from "../contracts";
import { operationDigestContext } from "../digest-context";
import { lockOwnerPlacement } from "../direct-placement";
import {
  captureBusy,
  capturePolicyForbidden,
  captureUnsupported,
  diskBelowImage,
  diskOffloaded,
  hostCapacityConflict,
  imageQuotaExceeded,
  sandboxStateConflict,
  templateNotFound,
  templateStoreUnavailable,
} from "../errors";
import { lockHostForSandboxOperation } from "../host-admission";
import { requestDigestMetadata } from "../idempotency";
import { defaultIncusInstanceName } from "../incus-name";
import { operationTransaction } from "../operation-transaction";
import { createSandboxOutboxEvent, sandboxOutboxTransaction } from "../outbox";
import {
  attributionOf,
  budgetSubjectOf,
  buildIdOf,
  isBrowserSession,
  recordedKeyIdOf,
} from "../principal-kinds";
import { loadRevisionDefaults, writeRevisionDefaults } from "../revision-config";
import {
  accountImageQuotas,
  accountStoredImageBytes,
  effectiveImagePlacement,
  hostImageFeatures,
  imageDistributionMode,
} from "./config";

export { recordCaptureResult } from "./capture-result";

/**
 * Snapshot-to-template (docs/operations/templates.md#capture).
 *
 * Acceptance (owner admission → owner placement → template FOR UPDATE → H →
 * S → O) records a CAPTURE_TEMPLATE operation, a capture row and a transient
 * capture-VM hold (memory, vCPU and the root-sized disk charge on the
 * sandbox's storage pool). The host result is stored on the capture row; a
 * separate finalizer transaction creates the revision, so the relay's H→S→O
 * result path never takes template locks.
 */
export type CaptureSandboxInput = {
  id: string;
  idempotencyKey: string;
  templateId?: string;
  tag?: string;
  scrubPaths?: string[];
  /** The new revision's default disk (at least the sandbox's disk). */
  defaultDiskGiB?: number;
};

const ACTIVE_CAPTURE_STATES = ["PENDING", "CAPTURED", "STORING"] as const;
const CAPTURE_MEMORY_MIB = 1024;
const TAG_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const STORE_TIMEOUT_MS = 2 * 3_600_000;

/** Dashboard input (the /v1 body is `captureBodySchema`). */
export const captureSessionInput = z
  .object({
    id: entityId,
    idempotencyKey,
    templateId: entityId.optional(),
    tag: z.string().regex(TAG_PATTERN).optional(),
    scrubPaths: z.array(z.string().min(1).max(4096).refine(validScrubPath)).max(16).optional(),
    defaultDiskGiB: vmDiskGiBSchema.optional(),
  })
  .strict();

export function captureHold(diskGiB: number) {
  return {
    memoryMiB: vmLiveMemoryChargeMiB(CAPTURE_MEMORY_MIB),
    vcpu: 1,
    // The capture VM's root copy plus the publish output (M2).
    diskGiB: vmRootChargeGiB(diskGiB) + diskGiB,
  };
}

export const captureSandbox = serviceProcedure(
  {
    action: "sandboxes.capture",
    intentOnly: true,
    target: (input: CaptureSandboxInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: CaptureSandboxInput) => {
    // A build's capture (template builds §3.3): the target template and tag
    // were fixed at acceptance (the SDK `latest`-only rule applied there), so
    // they come from the build row, never from the input.
    const buildId = buildIdOf(owner);
    const build =
      buildId === null
        ? null
        : await prisma.sandboxTemplateBuild.findFirst({
            where: { id: buildId, userId: owner.ownerId },
            select: { templateId: true, tag: true },
          });
    if (buildId !== null && !build) throw buildAuthorityLost();
    const tag = build?.tag ?? input.tag ?? "latest";
    // Over the SDK only `latest` may move (I6); other tags need a session.
    if (!build && !isBrowserSession(owner) && tag !== "latest")
      throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.capture_invalid" } });
    if (!TAG_PATTERN.test(tag) || (input.scrubPaths ?? []).some((p) => !validScrubPath(p)))
      throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.capture_invalid" } });
    // Shared by the dashboard and POST /v1/sandboxes/{id}/capture (P2-8).
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeSandboxWriteBudget(budgetOwner, "image");
    const mode = imageDistributionMode();
    if (mode === "off") throw captureUnsupported("runtime");
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        intent: {
          sandboxId: input.id,
          templateId: build?.templateId ?? input.templateId ?? null,
          tag,
          scrubPaths: input.scrubPaths ?? [],
          defaultDiskGiB: input.defaultDiskGiB ?? null,
        },
        kind: "CAPTURE_TEMPLATE",
        action: "sandboxes.capture",
        target: { sandboxId: input.id },
      },
      async (tx, bodyHash) => {
        await lockOwnerPlacement(tx, owner.ownerId);
        const located = await tx.sandbox.findFirst({
          where: { id: input.id, userId: owner.ownerId },
          select: { templateId: true, sandboxHostId: true, state: true },
        });
        if (!located) throw new ORPCError("NOT_FOUND");
        // A create still waiting for capacity has no host and no disk yet.
        if (located.state === "WAITING_FOR_CAPACITY")
          throw sandboxStateConflict("A sandbox waiting for capacity cannot be captured.");
        // C7: an OFFLOADED disk is only in the image store;
        // capture copies a host root, so the sandbox must be started first.
        if (located.state === "OFFLOADED") throw diskOffloaded();
        const templateId = build?.templateId ?? input.templateId ?? located.templateId;
        const [template] = await tx.$queryRaw<
          { id: string; archivedAt: Date | null; captureScrubPaths: string[] }[]
        >`SELECT id, "archivedAt", "captureScrubPaths" FROM sandbox_logical_template
          WHERE id = ${templateId} AND "userId" = ${owner.ownerId} FOR UPDATE`;
        if (!template || template.archivedAt) throw templateNotFound();
        // A community template takes captures only from its own community
        // build (D-G); a user capture into it is refused.
        if (!build) await refuseCommunityWrite(tx, owner.ownerId, template.id);
        // A build's capture is its CURRENT attempt (template → build, the
        // finalizer's order): the claim that raised `captureAttempt` is the
        // only writer, so a share lock reads it stable for this insert. The
        // same lock re-checks the step authority: a cancel (which marks the
        // build's PENDING captures under its update lock) either committed
        // before this read and refuses it, or waits for this insert and then
        // marks it, so no capture escapes a committed cancel (E2-A-01).
        let buildAttempt = 0;
        if (buildId !== null) {
          const [current] = await tx.$queryRaw<
            { captureAttempt: number; state: TemplateBuildState; cancelRequestedAt: Date | null }[]
          >`
            SELECT "captureAttempt", state::text AS state, "cancelRequestedAt" FROM sandbox_template_build
            WHERE id = ${buildId} AND "userId" = ${owner.ownerId} FOR SHARE`;
          if (!current || !buildStepAllowed("sandboxes.capture", current))
            throw buildAuthorityLost();
          buildAttempt = current.captureAttempt;
        }
        await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, input.id);
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.id} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
        const sandbox = await tx.sandbox.findFirst({
          where: { id: input.id, userId: owner.ownerId },
          select: {
            id: true,
            state: true,
            generation: true,
            sandboxHostId: true,
            hostOwnerId: true,
            storagePoolId: true,
            storageMarker: true,
            diskGiB: true,
            incusName: true,
          },
        });
        if (!sandbox?.sandboxHostId || !sandbox.hostOwnerId) throw new ORPCError("NOT_FOUND");
        if (sandbox.state !== "READY" && sandbox.state !== "STOPPED")
          throw captureUnsupported("state");
        // CLI logins (§7.6): never while a login's files are being written,
        // captured or recovered; the residue rows below must be settled.
        await requireNoCredentialWorkInFlight(tx, sandbox.id);
        const host = await tx.sandboxHost.findFirst({
          where: { id: sandbox.sandboxHostId, userId: sandbox.hostOwnerId },
          select: {
            status: true,
            daemonFeatures: true,
            imageCacheEpoch: true,
            connectionEpoch: true,
            memoryReservedMiB: true,
            daemonMemoryBudgetMiB: true,
            vcpuReserved: true,
            daemonVcpuBudget: true,
          },
        });
        const features = hostImageFeatures(host?.daemonFeatures ?? null);
        if (!host || !features?.capture || host.imageCacheEpoch !== host.connectionEpoch)
          throw captureUnsupported("runtime");
        // READY captures freeze and snapshot: copy-on-write storage only.
        // STOPPED captures copy the stopped root directly on any pool (I5, M2).
        if (
          sandbox.state === "READY" &&
          !features.captureStorageMarkers.includes(sandbox.storageMarker ?? "")
        )
          throw captureUnsupported("storage");
        const foreign = sandbox.hostOwnerId !== owner.ownerId;
        if (
          foreign &&
          (await effectiveImagePlacement(tx, owner.ownerId, templateId)) !== "ANY_NODE"
        )
          throw capturePolicyForbidden();
        // v1: a capture on someone else's node must be durable off that node.
        if (foreign && mode !== "s3") throw templateStoreUnavailable();
        const busy = await tx.sandboxTemplateCapture.findFirst({
          where: {
            state: { in: [...ACTIVE_CAPTURE_STATES] },
            OR: [{ sandboxId: sandbox.id }, { hostId: sandbox.sandboxHostId }],
          },
          select: { operationId: true },
        });
        if (busy) throw captureBusy();
        // CLI logins (§6.1, §7.6): every login path this sandbox ever held
        // (cleared residue included) travels in the chunked spec; a host that
        // cannot fetch it cannot scrub it.
        const credentialSpec = await buildCaptureScrubSpec(tx, sandbox.id);
        if (
          credentialSpec &&
          !hostCredentialCapable(host.daemonFeatures, {
            hasCreds: true,
            requiresOwn: false,
            needs: { files: true, env: false, proxy: false },
          })
        )
          throw captureUnsupported("runtime");
        const encodedSpec = credentialSpec ? encodeCredentialSpec(credentialSpec) : null;
        if (mode === "s3") {
          const quotas = await accountImageQuotas(tx, owner.ownerId);
          if (quotas.maxStoredGiB !== null) {
            const stored = await accountStoredImageBytes(tx, owner.ownerId);
            if (stored >= BigInt(quotas.maxStoredGiB) * 1_073_741_824n)
              throw imageQuotaExceeded("stored");
          }
        }
        // The image is the sandbox's whole root: the revision's floor. A
        // default below it could never be created.
        if (input.defaultDiskGiB !== undefined && input.defaultDiskGiB < sandbox.diskGiB)
          throw diskBelowImage();
        const hold = captureHold(sandbox.diskGiB);
        if (
          host.daemonMemoryBudgetMiB === null ||
          host.daemonVcpuBudget === null ||
          host.memoryReservedMiB + hold.memoryMiB > host.daemonMemoryBudgetMiB ||
          host.vcpuReserved + hold.vcpu > host.daemonVcpuBudget
        )
          throw hostCapacityConflict(
            "ram",
            // Unreported budgets can arrive; a hold larger than the budget cannot fit.
            host.daemonMemoryBudgetMiB === null ||
              host.daemonVcpuBudget === null ||
              (hold.memoryMiB <= host.daemonMemoryBudgetMiB && hold.vcpu <= host.daemonVcpuBudget),
          );
        const pool = sandbox.storagePoolId
          ? await tx.sandboxHostStoragePool.findFirst({
              where: { id: sandbox.storagePoolId, sandboxHostId: sandbox.sandboxHostId },
              select: { capacityGiB: true, diskReservedGiB: true },
            })
          : null;
        if (!pool || pool.capacityGiB - pool.diskReservedGiB < hold.diskGiB)
          // The sandbox's own root stays reserved in the pool while it is captured.
          throw hostCapacityConflict(
            "disk",
            pool !== null && hold.diskGiB <= pool.capacityGiB - vmRootChargeGiB(sandbox.diskGiB),
          );
        const admitted = await tx.sandbox.updateMany({
          where: {
            id: sandbox.id,
            userId: owner.ownerId,
            generation: sandbox.generation,
            state: sandbox.state,
          },
          data: { generation: sandbox.generation },
        });
        if (admitted.count !== 1)
          throw new ORPCError("CONFLICT", { data: { code: "sandbox.state_conflict" } });
        const scrubPaths = [
          ...new Set([...template.captureScrubPaths, ...(input.scrubPaths ?? [])]),
        ].slice(0, CAPTURE_SCRUB_PATHS_MAX);
        const operation = await tx.sandboxOperation.create({
          data: {
            authorizingKeyId: recordedKeyIdOf(owner),
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            kind: "CAPTURE_TEMPLATE",
            state: "QUEUED",
            generation: sandbox.generation,
            idempotencyKey: input.idempotencyKey,
            requestBodyHash: bodyHash(),
            digestContext: operationDigestContext(tx),
            ...requestDigestMetadata("CAPTURE_TEMPLATE"),
          },
        });
        const credentialSpecRef = encodedSpec
          ? await writeOperationSpec(tx, operation.id, encodedSpec.bytes)
          : null;
        await tx.sandboxTemplateCapture.create({
          data: {
            operationId: operation.id,
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            templateId,
            tag,
            hostId: sandbox.sandboxHostId,
            hostOwnerId: sandbox.hostOwnerId,
            scrubPaths,
            stoppedCapture: sandbox.state === "STOPPED",
            resourcesHeld: true,
            chargedMemoryMiB: hold.memoryMiB,
            chargedVcpu: hold.vcpu,
            diskChargeGiB: hold.diskGiB,
            storagePoolId: sandbox.storagePoolId,
            // A build's capture takes the build's default at finalize.
            defaultDiskGiB: buildId === null ? (input.defaultDiskGiB ?? null) : null,
            ...(buildId !== null ? { buildId, buildAttempt } : {}),
          },
        });
        await tx.sandboxHost.update({
          where: { id: sandbox.sandboxHostId },
          data: {
            memoryReservedMiB: { increment: hold.memoryMiB },
            vcpuReserved: { increment: hold.vcpu },
          },
        });
        await tx.sandboxHostStoragePool.update({
          where: { id: sandbox.storagePoolId ?? "" },
          data: { diskReservedGiB: { increment: hold.diskGiB } },
        });
        await createSandboxOutboxEvent(tx, {
          authorizingPrincipal: attributionOf(owner),
          userId: owner.ownerId,
          aggregateId: sandbox.id,
          eventType: "sandbox.capture_requested",
          payload: {
            sandboxId: sandbox.id,
            sandboxHostId: sandbox.sandboxHostId,
            operationId: operation.id,
            idempotencyKey: input.idempotencyKey,
            kind: "sandbox.capture",
            generation: sandbox.generation,
            dispatchAttempt: 0,
            incusName: sandbox.incusName ?? defaultIncusInstanceName(sandbox.id),
            capture: {
              scrubPaths,
              stopped: sandbox.state === "STOPPED",
              upload: mode === "s3",
            },
            ...(credentialSpecRef ? { credentialSpec: credentialSpecRef } : {}),
          },
        });
        return { operationId: operation.id, state: operation.state };
      },
      async (_tx, prior) => ({ operationId: prior.id, state: prior.state }),
    );
  },
);

/** Release the transient hold exactly once (resourcesHeld flips under the row). */
async function releaseCaptureHold(tx: Prisma.TransactionClient, operationId: string) {
  const [capture] = await tx.$queryRaw<
    {
      hostId: string;
      resourcesHeld: boolean;
      chargedMemoryMiB: number;
      chargedVcpu: number;
      diskChargeGiB: number;
      storagePoolId: string | null;
    }[]
  >`SELECT "hostId", "resourcesHeld", "chargedMemoryMiB", "chargedVcpu", "diskChargeGiB", "storagePoolId"
    FROM sandbox_template_capture WHERE "operationId" = ${operationId} FOR UPDATE`;
  if (!capture?.resourcesHeld) return;
  await tx.sandboxTemplateCapture.update({
    where: { operationId },
    data: { resourcesHeld: false },
  });
  await tx.$executeRaw`UPDATE sandbox_host SET
    "memoryReservedMiB" = GREATEST(0, "memoryReservedMiB" - ${capture.chargedMemoryMiB}),
    "vcpuReserved" = GREATEST(0, "vcpuReserved" - ${capture.chargedVcpu})
    WHERE id = ${capture.hostId}`;
  if (capture.storagePoolId)
    await tx.$executeRaw`UPDATE sandbox_host_storage_pool SET
      "diskReservedGiB" = GREATEST(0, "diskReservedGiB" - ${capture.diskChargeGiB})
      WHERE id = ${capture.storagePoolId}`;
  // Freed host capacity may let a waiting create place (flushed at commit).
  noteCapacityChanged(tx, { hostIds: [capture.hostId] });
}

async function failCapture(
  tx: Prisma.TransactionClient,
  operationId: string,
  code: "capture_failed" | "capture_store_failed",
) {
  await releaseCaptureHold(tx, operationId);
  await tx.sandboxTemplateCapture.update({
    where: { operationId },
    data: { state: "FAILED", errorCode: code, finalizedAt: new Date() },
  });
  await tx.sandboxOperation.updateMany({
    where: { id: operationId, state: { notIn: ["SUCCEEDED", "FAILED", "CANCELLED"] } },
    data: { state: "FAILED", errorCode: code, completedAt: new Date(), progressPhase: null },
  });
}

/** Retire captures of `tag` beyond the newest `keep`, skipping revisions another tag points to. */
export async function applyCaptureRetention(
  tx: Prisma.TransactionClient,
  input: { ownerId: string; templateId: string; tag: string; keep: number; now: Date },
): Promise<number> {
  return tx.$executeRaw`
    UPDATE sandbox_template_revision r SET "retiredAt" = ${input.now}, "retiredReason" = 'retention'
    WHERE r.id IN (
      SELECT c.id FROM sandbox_template_revision c
      WHERE c."templateId" = ${input.templateId} AND c."userId" = ${input.ownerId}
        AND c."captureTag" = ${input.tag} AND c."retiredAt" IS NULL
        AND c."pendingVerifyBuildId" IS NULL
        AND NOT EXISTS (SELECT 1 FROM sandbox_template_tag g
          WHERE g."revisionId" = c.id AND g.tag <> ${input.tag})
        AND c.id NOT IN (SELECT k.id FROM sandbox_template_revision k
          WHERE k."templateId" = c."templateId" AND k."captureTag" = ${input.tag}
            AND k."retiredAt" IS NULL ORDER BY k.revision DESC LIMIT ${input.keep})
      ORDER BY c.revision ASC LIMIT 100)`;
}

export type FinalizeOutcome =
  | { kind: "finalized"; revisionId: string }
  | { kind: "waiting" }
  | { kind: "failed"; fingerprint: string | null; hostId: string; ownerId: string }
  | { kind: "skipped" };

/**
 * Finalizer (scheduler + 15 s sweep): owner admission → owner placement →
 * template → H → S → O. Creates the revision, availability, artifact, moves
 * the tag, applies retention, releases the hold once and marks SUCCEEDED.
 */
export async function finalizeCapture(
  operationId: string,
  now = new Date(),
): Promise<FinalizeOutcome> {
  const head = await prisma.sandboxTemplateCapture.findUnique({
    where: { operationId },
    select: {
      userId: true,
      templateId: true,
      sandboxId: true,
      hostId: true,
      state: true,
      buildId: true,
    },
  });
  if (!head || !["CAPTURED", "STORING", "PENDING"].includes(head.state)) return { kind: "skipped" };
  // The build id is immutable: read before any lock, so the build row is
  // locked at its place (owner → placement → template → build → H, §3.4).
  const outcome = await sandboxOutboxTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, head.userId);
    await lockOwnerPlacement(tx, head.userId);
    const [template] = await tx.$queryRaw<
      {
        id: string;
        archivedAt: Date | null;
        captureKeep: number;
        communitySource: string | null;
      }[]
    >`SELECT id, "archivedAt", "captureKeep", "communitySource" FROM sandbox_logical_template
      WHERE id = ${head.templateId} AND "userId" = ${head.userId} FOR UPDATE`;
    const build = head.buildId ? await lockFinalizingBuild(tx, head.buildId, head.userId) : null;
    await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${head.hostId} FOR UPDATE`;
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${head.sandboxId} FOR NO KEY UPDATE`;
    const [op] = await tx.$queryRaw<{ state: string; createdAt: Date }[]>`
      SELECT state::text AS state, "createdAt" FROM sandbox_mutation_operation
      WHERE id = ${operationId} FOR UPDATE`;
    const capture = await tx.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } });
    if (!op) return { kind: "skipped" } as const;
    // A host that failed or lost the capture: release the hold, nothing else.
    if (capture.state === "PENDING") {
      if (["FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(op.state)) {
        await releaseCaptureHold(tx, operationId);
        await tx.sandboxTemplateCapture.update({
          where: { operationId },
          data: { state: "FAILED", errorCode: "capture_failed", finalizedAt: now },
        });
        return {
          kind: "failed",
          fingerprint: null,
          hostId: capture.hostId,
          ownerId: capture.userId,
        } as const;
      }
      return { kind: "waiting" } as const;
    }
    const fingerprint = capture.fingerprint;
    if (
      !template ||
      template.archivedAt ||
      !fingerprint ||
      !capture.sizeBytes ||
      !capture.architecture
    ) {
      await failCapture(tx, operationId, "capture_failed");
      return {
        kind: "failed",
        fingerprint,
        hostId: capture.hostId,
        ownerId: capture.userId,
      } as const;
    }
    const mode = imageDistributionMode();
    const foreign = capture.hostOwnerId !== capture.userId;
    if (mode === "s3" || foreign) {
      const artifact = await tx.sandboxImageArtifact.findUnique({
        where: { userId_fingerprint: { userId: capture.userId, fingerprint } },
        select: { state: true },
      });
      if (artifact?.state !== "STORED") {
        const failedStore = artifact && ["CORRUPT", "FAILED", "DELETED"].includes(artifact.state);
        if (failedStore || now.getTime() - op.createdAt.getTime() > STORE_TIMEOUT_MS) {
          await failCapture(tx, operationId, "capture_store_failed");
          return {
            kind: "failed",
            fingerprint,
            hostId: capture.hostId,
            ownerId: capture.userId,
          } as const;
        }
        // A foreign capture must be durable before it becomes a revision (I9).
        if (foreign || mode === "s3") {
          if (capture.state !== "STORING")
            await tx.sandboxTemplateCapture.update({
              where: { operationId },
              data: { state: "STORING" },
            });
          await tx.sandboxOperation.update({
            where: { id: operationId },
            data: { progressPhase: "uploading", progressAt: now },
          });
          return { kind: "waiting" } as const;
        }
      }
    }
    // A build that already ended never gets a revision. CANCELLING does
    // only when the host result was recorded before the cancel committed
    // (§3.3, r3 N22); a cancel that committed first marked this capture
    // (`buildCancelledAt`, serialized with result recording on this row) and
    // wins: no revision, no tag move, and the failed outcome releases the
    // image (E2-A-01 ruling). Likewise a superseded attempt: only the build's
    // current capture attempt may publish its revision.
    // A community build verifies before it publishes (community-base S9):
    // a cancel always wins over a verify that has not passed, so a CANCELLING
    // community build never gets a revision.
    if (
      build &&
      (!["CAPTURING", "CANCELLING"].includes(build.state) ||
        (build.verifyRequired && build.state !== "CAPTURING") ||
        capture.buildCancelledAt !== null ||
        capture.buildAttempt !== build.captureAttempt)
    ) {
      await failCapture(tx, operationId, "capture_failed");
      return {
        kind: "failed",
        fingerprint,
        hostId: capture.hostId,
        ownerId: capture.userId,
      } as const;
    }
    const sandbox = await tx.sandbox.findFirstOrThrow({
      where: { id: capture.sandboxId, userId: capture.userId },
      select: { templateRevisionId: true, diskGiB: true, guestRoot: true },
    });
    const parent = await tx.sandboxTemplateRevision.findFirstOrThrow({
      where: { id: sandbox.templateRevisionId, userId: capture.userId },
    });
    const built = build ? await buildRevisionFields(tx, build) : null;
    const wsspRecipe =
      build && built
        ? await builtWithWsspRecipe({
            build,
            parent,
            template,
            upstreamImageRecorded:
              (await tx.sandboxUpstreamImage.findFirst({
                where: {
                  templateId: parent.templateId,
                  userId: capture.userId,
                  fingerprint: parent.incusFingerprint,
                  revisionId: parent.id,
                },
                select: { id: true },
              })) !== null,
            buildSandboxGuestRoot: sandbox.guestRoot,
            capture: { hostOwnerId: capture.hostOwnerId, userId: capture.userId },
            builtWithRoot: built.builtWithRoot,
          })
        : false;
    const pendingVerify = build?.verifyRequired === true;
    await tx.$queryRaw`SELECT id FROM sandbox_template_tag WHERE "templateId" = ${template.id} AND "userId" = ${capture.userId} ORDER BY id FOR UPDATE`;
    const last = await tx.sandboxTemplateRevision.findFirst({
      where: { templateId: template.id, userId: capture.userId },
      orderBy: { revision: "desc" },
      select: { revision: true },
    });
    const manifest = {
      incusFingerprint: fingerprint,
      architecture: capture.architecture,
      guestUid: parent.guestUid,
      guestGid: parent.guestGid,
      guestHome: parent.guestHome,
      guestShell: parent.guestShell,
      guestVersion: parent.guestVersion,
    };
    const revision = await tx.sandboxTemplateRevision.create({
      data: {
        userId: capture.userId,
        templateId: template.id,
        revision: (last?.revision ?? 0) + 1,
        ...manifest,
        cpuCount: built?.cpuCount ?? parent.cpuCount,
        memoryMiB: built?.memoryMiB ?? parent.memoryMiB,
        // The image is the source VM's whole root: its disk is the smallest a
        // sandbox from it can use (assertDiskFitsImage). The default is the
        // build's, the capture's request, or the parent's, never below it.
        minDiskGiB: sandbox.diskGiB,
        defaultDiskGiB: Math.max(
          built?.defaultDiskGiB ?? capture.defaultDiskGiB ?? parent.defaultDiskGiB,
          sandbox.diskGiB,
        ),
        manifestDigest: createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
        sourceKind: built ? "BUILD" : "CAPTURE",
        parentRevisionId: parent.id,
        capturedFromSandboxId: capture.sandboxId,
        captureTag: capture.tag,
        // OD-1: the source sandbox (a capture's VM, or a build VM on a
        // tainted base) could reach guest root, so its image may carry
        // anything root wrote. Inherited, never re-derived.
        capturedWithGuestRoot: sandbox.guestRoot,
        ...(built
          ? {
              buildId: built.buildId,
              recipeDigest: built.recipeDigest,
              defaultCwd: built.defaultCwd,
              startCmd: built.startCmd,
              readyCmd: built.readyCmd,
              readyTimeoutMs: built.readyTimeoutMs,
              builtWithRoot: built.builtWithRoot,
              builtOnForeignHost: capture.hostOwnerId !== capture.userId,
              // The single write site (DG-12): true only from the seven
              // server facts of community/wssp-recipe.ts.
              builtWithWsspRecipe: wsspRecipe,
            }
          : {}),
        // Not launchable, grantable, taggable or associable until the
        // build's verify VM passes (community-base D-D).
        ...(pendingVerify && build ? { pendingVerifyBuildId: build.id } : {}),
      },
      select: { id: true, manifestDigest: true },
    });
    // Parent's template defaults only, never the sandbox's own overrides; a
    // build adds its final ENV (ARG never persists).
    const defaults = await loadRevisionDefaults(tx, parent.id, capture.userId);
    await writeRevisionDefaults(tx, capture.userId, revision.id, {
      ...Object.fromEntries(defaults),
      ...(built?.env ?? {}),
    });
    await tx.sandboxTemplateAvailability.create({
      data: {
        userId: capture.userId,
        revisionId: revision.id,
        hostId: capture.hostId,
        hostOwnerId: capture.hostOwnerId,
        localFingerprint: fingerprint,
        architecture: capture.architecture,
        manifestDigest: revision.manifestDigest,
        status: "AVAILABLE",
        verifiedConnectionEpoch: capture.resultEpoch,
        observedAt: now,
        sizeBytes: capture.sizeBytes,
        imageFormat: "unified",
      },
    });
    // The capture's own cache evidence (origin pin) on its host: written here
    // from the recorded result, never from an unbound image.cached report.
    if (capture.resultEpoch !== null)
      await tx.sandboxHostImageCache.upsert({
        where: {
          hostId_fingerprint_imageOwnerId: {
            hostId: capture.hostId,
            fingerprint,
            imageOwnerId: capture.userId,
          },
        },
        create: {
          hostId: capture.hostId,
          hostOwnerId: capture.hostOwnerId,
          imageOwnerId: capture.userId,
          fingerprint,
          compressedBytes: capture.sizeBytes,
          unpackedBytes: capture.unpackedBytes,
          origin: "captured",
          pinned: true,
          connectionEpoch: capture.resultEpoch,
          reportedAt: now,
        },
        update: {},
      });
    await tx.sandboxImageArtifact.upsert({
      where: { userId_fingerprint: { userId: capture.userId, fingerprint } },
      create: {
        userId: capture.userId,
        fingerprint,
        architecture: capture.architecture,
        sizeBytes: capture.sizeBytes,
        unpackedBytes: capture.unpackedBytes,
        storeKind: "PEER",
        state: "LOCAL",
        uploadedByHostId: capture.hostId,
      },
      update: {},
    });
    // A pending (community) revision moves no tag and retires nothing: the
    // verify step does both on pass (I1t).
    if (!pendingVerify) {
      await tx.sandboxTemplateTag.upsert({
        where: { templateId_tag: { templateId: template.id, tag: capture.tag } },
        create: {
          userId: capture.userId,
          templateId: template.id,
          revisionId: revision.id,
          tag: capture.tag,
        },
        update: { revisionId: revision.id },
      });
      await applyCaptureRetention(tx, {
        ownerId: capture.userId,
        templateId: template.id,
        tag: capture.tag,
        keep: template.captureKeep,
        now,
      });
    }
    await releaseCaptureHold(tx, operationId);
    await tx.sandboxTemplateCapture.update({
      where: { operationId },
      data: { state: "FINALIZED", revisionId: revision.id, finalizedAt: now },
    });
    await tx.sandboxOperation.update({
      where: { id: operationId },
      data: { state: "SUCCEEDED", completedAt: now, progressPhase: null },
    });
    if (build && pendingVerify) {
      // The build stays CAPTURING while its verify VM runs (D-D).
      await tx.sandboxTemplateBuild.update({
        where: { id: build.id },
        data: {
          phase: "verifying",
          verifyDeadlineAt: new Date(now.getTime() + VERIFY_WINDOW_MINUTES * 60_000),
          nextAttemptAt: now,
        },
      });
    } else if (build) {
      await succeedBuild(tx, build, revision.id, now);
      // Waiting creates follow a rebuilt tag (template-builds §3.9).
      if (build.triggeredByRevisionId) noteCapacityChanged(tx);
    }
    return { kind: "finalized", revisionId: revision.id } as const;
  });
  if (head.buildId) {
    notifyTemplateBuildsChanged();
    notifyTemplateBuildProgress(head.buildId);
  }
  return outcome;
}

/** The finalizer's build branch (§3.3): the build row, locked after the
 * template and before H. Null when the row is gone (account deletion). */
async function lockFinalizingBuild(tx: Prisma.TransactionClient, buildId: string, ownerId: string) {
  const [locked] = await tx.$queryRaw<{ id: string }[]>`
    SELECT id FROM sandbox_template_build WHERE id = ${buildId} AND "userId" = ${ownerId} FOR UPDATE`;
  if (!locked) return null;
  return tx.sandboxTemplateBuild.findUniqueOrThrow({
    where: { id: buildId },
    select: {
      id: true,
      userId: true,
      state: true,
      triggeredByRevisionId: true,
      captureAttempt: true,
      recipe: true,
      recipeDigest: true,
      buildArgs: true,
      baseRevisionId: true,
      cpuCount: true,
      memoryMiB: true,
      diskGiB: true,
      defaultDiskGiB: true,
      readyAt: true,
      stoppedAt: true,
      reservedMinutes: true,
      minutesSettled: true,
      origin: true,
      verifyRequired: true,
      buildDigest: true,
      baseFingerprint: true,
    },
  });
}
type FinalizingBuild = NonNullable<Awaited<ReturnType<typeof lockFinalizingBuild>>>;

/** Revision fields of a build (§3.3 "Finalizer build branch"): resources
 * from the build, final ENV merged over the base defaults, WORKDIR as the
 * default cwd, the recipe's start/ready commands (B9), and whether any step
 * ran as root. */
async function buildRevisionFields(tx: Prisma.TransactionClient, build: FinalizingBuild) {
  const exec = await loadBuildExecPlan(tx, build);
  return {
    buildId: build.id,
    recipeDigest: build.recipeDigest,
    cpuCount: build.cpuCount,
    memoryMiB: build.memoryMiB,
    defaultDiskGiB: build.defaultDiskGiB,
    env: exec.plan.env,
    defaultCwd: exec.plan.workdir,
    startCmd: exec.start?.command ?? null,
    readyCmd: exec.start?.ready ?? null,
    readyTimeoutMs: exec.start?.ready !== undefined ? (exec.start.readyTimeoutMs ?? null) : null,
    builtWithRoot: exec.builtWithRoot,
  };
}

/** The build ends SUCCEEDED with the published revision (a recorded
 * `cancelRequestedAt` is kept: the cancel arrived after the image existed).
 * Minutes settle here only if the stop did not already settle them. */
async function succeedBuild(
  tx: Prisma.TransactionClient,
  build: FinalizingBuild,
  revisionId: string,
  now: Date,
) {
  await tx.sandboxTemplateBuild.update({
    where: { id: build.id },
    data: {
      state: "SUCCEEDED",
      phase: null,
      revisionId,
      completedAt: now,
      pendingAction: PrismaValue.DbNull,
      nextAttemptAt: now,
      ...(build.minutesSettled
        ? {}
        : {
            minutesSettled: true,
            chargedMinutes: chargedMinutes(
              build.readyAt,
              build.stoppedAt ?? now,
              build.reservedMinutes,
            ),
          }),
    },
  });
}

/** Bounded sweep over unsettled captures (server scheduler, every 15 s). */
export async function sweepCaptures(now = new Date()) {
  const pending = await prisma.sandboxTemplateCapture.findMany({
    where: { state: { in: [...ACTIVE_CAPTURE_STATES] } },
    select: { operationId: true },
    orderBy: { updatedAt: "asc" },
    take: 50,
  });
  const outcomes: { operationId: string; outcome: FinalizeOutcome }[] = [];
  for (const capture of pending)
    outcomes.push({
      operationId: capture.operationId,
      outcome: await finalizeCapture(capture.operationId, now).catch(
        () => ({ kind: "skipped" }) as const,
      ),
    });
  return outcomes;
}
