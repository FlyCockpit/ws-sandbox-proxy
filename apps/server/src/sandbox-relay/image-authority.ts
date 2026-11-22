import { checkAcceptedDispatchAuthority } from "@wssp/api/lib/sdk-key-access";
import {
  RESTORE_SANDBOX_FACTS_SELECT,
  restoreHostEligibility,
} from "@wssp/api/sandbox/disk-offload/eligibility";
import { effectiveImagePlacement, hostImageFeatures } from "@wssp/api/sandbox/image-store/config";
import { OFFLOADABLE_SANDBOX_PURPOSES } from "@wssp/api/sandbox/managed-sandbox";
import { requireRelayWorkload } from "@wssp/api/sandbox/relay-fence";
import { storedAttributionOf } from "@wssp/api/sandbox/stored-principal";
import type { Prisma } from "@wssp/db";

/**
 * The one workload fence every image grant passes (security review P1-1):
 * the initial fetch grant, every link renewal, a job resume, an upload
 * begin/continuation/completion and every relay spool request.
 *
 * A grant is only ever as good as the workload it serves: the exact operation
 * (kind, generation, dispatch attempt, still active) dispatched to the exact host connection
 * (host and epoch; a resume is honoured only after the operation was adopted
 * on the new epoch, by reconnect reconciliation, or, for a recorded capture
 * that reconciliation never re-adopts, by the recorded-capture adoption in
 * image-handlers.ts `adoptRecordedCapture`, which moves only the dispatch
 * epoch of that exact dispatch after it passed this fence on its old epoch
 * and requires it again on the new one), the sandbox's host path (requireRelayWorkload), the
 * creator's sharing path, credential policy and authorizing SDK key
 * (checkAcceptedDispatchAuthority), and, on another account's host, the
 * host's accept-foreign setting and the template's image placement policy.
 * Expiry is checked by the callers on the transfer they hold.
 *
 * Every read happens in the caller's transaction (under its host lock where
 * it has one). Any failure, including an unexpected error, is "no".
 */
const ACTIVE = ["DISPATCHED", "ACCEPTED", "RUNNING"] as const;

export type ImageWorkload = {
  operationId: string;
  ownerId: string;
  sandboxId: string;
  templateId: string | null;
  architecture: string | null;
  artifact: string | null;
  /** The operation's current dispatch attempt (round-2 P2-3). */
  dispatchAttempt: number;
};

type Target = {
  operationId: string;
  /** The host the operation was dispatched to, and its connection epoch. */
  hostId: string;
  hostOwnerId: string;
  epoch: number;
  generation?: number;
  sandboxId?: string;
  /** The exact dispatch attempt the request or transfer belongs to. */
  attempt?: number;
};

async function workload(
  tx: Prisma.TransactionClient,
  kind: "CREATE_SANDBOX" | "CAPTURE_TEMPLATE" | "RECONNECT_SANDBOX",
  target: Target,
  /** RECONNECT_SANDBOX only: the restore attempt's offload (U9.1). */
  restoreOffloadId?: string,
): Promise<ImageWorkload | null> {
  try {
    if ((kind === "RECONNECT_SANDBOX") !== (restoreOffloadId !== undefined)) return null;
    const op = await tx.sandboxOperation.findFirst({
      where: {
        id: target.operationId,
        kind,
        ...(restoreOffloadId !== undefined
          ? { launchMode: "NEW_ROOT" as const, restoreOffloadId }
          : {}),
        state: { in: [...ACTIVE] },
        dispatchedHostId: target.hostId,
        dispatchedConnectionEpoch: target.epoch,
        ...(target.generation !== undefined ? { generation: target.generation } : {}),
        ...(target.sandboxId !== undefined ? { sandboxId: target.sandboxId } : {}),
        ...(target.attempt !== undefined ? { dispatchAttempt: target.attempt } : {}),
      },
      select: {
        id: true,
        dispatchAttempt: true,
        userId: true,
        sandboxId: true,
        authorizingKeyId: true,
        Placement: { select: { artifact: true, architecture: true, templateId: true } },
        Sandbox: {
          select: {
            templateRevisionId: true,
            originPoolId: true,
            buildId: true,
            verifyBuildId: true,
          },
        },
      },
    });
    if (!op) return null;
    // Access loss on the account itself: a banned (archived) or deleting
    // creator's workloads get no new grants.
    const creator = await tx.user.findUnique({
      where: { id: op.userId },
      select: { banned: true, banExpires: true, deletionRequestedAt: true },
    });
    const [clock] = await tx.$queryRaw<
      { now: Date }[]
    >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    if (
      !creator ||
      creator.deletionRequestedAt !== null ||
      (creator.banned && (!creator.banExpires || creator.banExpires > clock!.now))
    )
      return null;
    await requireRelayWorkload(
      tx,
      { hostId: target.hostId, userId: target.hostOwnerId },
      { operationId: op.id, sandboxId: op.sandboxId, sandboxOwnerId: op.userId },
    );
    const principal = storedAttributionOf({
      userId: op.userId,
      authorizingKeyId: op.authorizingKeyId,
      sandboxBuildId: op.Sandbox.buildId,
      sandboxVerifyBuildId: op.Sandbox.verifyBuildId,
    });
    const authority = await checkAcceptedDispatchAuthority(
      {
        ownerId: op.userId,
        principal,
        operationKind: kind,
        context: {
          operationId: op.id,
          sandboxId: op.sandboxId,
          sandboxHostId: target.hostId,
          templateRevisionId: op.Sandbox.templateRevisionId,
          originPoolId: op.Sandbox.originPoolId,
        },
      },
      tx,
    );
    if (authority !== "active") return null;
    return {
      operationId: op.id,
      ownerId: op.userId,
      sandboxId: op.sandboxId,
      templateId: op.Placement?.templateId ?? null,
      architecture: op.Placement?.architecture ?? null,
      artifact: op.Placement?.artifact ?? null,
      dispatchAttempt: op.dispatchAttempt,
    };
  } catch {
    return null;
  }
}

/**
 * A create's image fetch: the workload fence, the placement's exact image,
 * and (another account's host) accept-foreign plus ANY_NODE placement.
 */
export async function fetchWorkload(
  tx: Prisma.TransactionClient,
  target: Target & { fingerprint: string },
): Promise<ImageWorkload | null> {
  const found = await workload(tx, "CREATE_SANDBOX", target);
  if (!found?.templateId || found.artifact !== target.fingerprint) return null;
  if (target.hostOwnerId !== found.ownerId) {
    const host = await tx.sandboxHost.findFirst({
      where: { id: target.hostId, userId: target.hostOwnerId },
      select: { daemonFeatures: true },
    });
    if (!hostImageFeatures(host?.daemonFeatures ?? null)?.acceptForeign) return null;
    if ((await effectiveImagePlacement(tx, found.ownerId, found.templateId)) !== "ANY_NODE")
      return null;
  }
  return found;
}

/**
 * A restore's disk fetch: the common
 * workload fence on the exact restore attempt (a RECONNECT accepted with
 * `launchMode = NEW_ROOT` for this offload, dispatched to this connection
 * and attempt), plus `restoreDiskAuthorized`. Returns the offload's object
 * facts for the grant.
 */
export async function restoreFetchWorkload(
  tx: Prisma.TransactionClient,
  target: Target & { fingerprint: string; restoreOffloadId: string },
): Promise<(ImageWorkload & { offloadId: string }) | null> {
  const found = await workload(tx, "RECONNECT_SANDBOX", target, target.restoreOffloadId);
  if (!found) return null;
  const ok = await restoreDiskAuthorized(tx, {
    operationId: found.operationId,
    sandboxId: found.sandboxId,
    ownerId: found.ownerId,
    offloadId: target.restoreOffloadId,
    hostId: target.hostId,
    fingerprint: target.fingerprint,
  });
  return ok ? { ...found, offloadId: target.restoreOffloadId } : null;
}

/**
 * The disk side of every RESTORE_FETCH grant and renewal: the attempt's
 * placement fetched this offload onto this host, the offload is STORED (a
 * CONSUMED copy is refused, §6a), is the sandbox's current disk and has this
 * fingerprint, and the host still passes `restoreHostEligibility` (§5).
 */
async function restoreDiskAuthorized(
  tx: Prisma.TransactionClient,
  input: {
    operationId: string;
    sandboxId: string;
    ownerId: string;
    offloadId: string;
    hostId: string;
    fingerprint: string;
  },
): Promise<boolean> {
  const placement = await tx.sandboxOperation.findFirst({
    where: { id: input.operationId, userId: input.ownerId },
    select: { Placement: { select: { restoreOffloadId: true, originHostId: true } } },
  });
  if (
    placement?.Placement?.restoreOffloadId !== input.offloadId ||
    placement.Placement.originHostId !== input.hostId
  )
    return false;
  const offload = await tx.sandboxDiskOffload.findFirst({
    where: {
      id: input.offloadId,
      sandboxId: input.sandboxId,
      userId: input.ownerId,
      state: "STORED",
      fingerprint: input.fingerprint,
      CurrentFor: { is: { id: input.sandboxId } },
    },
    select: { id: true },
  });
  if (!offload) return false;
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.ownerId },
    select: RESTORE_SANDBOX_FACTS_SELECT,
  });
  if (!sandbox?.templateId) return false;
  const verdict = await restoreHostEligibility(
    tx,
    { ...sandbox, templateId: sandbox.templateId },
    { hostId: input.hostId },
  );
  return verdict.ok && (await ownerActive(tx, input.ownerId));
}

/** A capture's upload: the workload fence plus an unfinished capture row on that host. */
export async function captureWorkload(
  tx: Prisma.TransactionClient,
  target: Target,
): Promise<ImageWorkload | null> {
  const capture = await tx.sandboxTemplateCapture.findFirst({
    where: {
      operationId: target.operationId,
      hostId: target.hostId,
      state: { in: ["PENDING", "CAPTURED", "STORING"] },
    },
    select: { operationId: true },
  });
  if (!capture) return null;
  return workload(tx, "CAPTURE_TEMPLATE", target);
}

type TransferRow = {
  purpose: string;
  userId: string;
  operationId: string | null;
  sourceHostId: string | null;
  sourceHostOwnerId: string | null;
  sourceEpoch: number | null;
  destHostId: string | null;
  destHostOwnerId: string | null;
  destEpoch: number | null;
  dispatchAttempt: number | null;
  fingerprint: string;
  expiresAt: Date;
  /** T8: the disk offload an OFFLOAD_UPLOAD / RESTORE_FETCH transfer moves. */
  diskOffloadId: string | null;
};

/**
 * Whether an OPEN transfer may still be served: not expired, and its
 * workload still authorized. FETCH: the create on the destination's current
 * dispatch epoch. CAPTURE_UPLOAD: the capture on the source's epoch.
 * PUBLISH (owner backfill): the source is still the image owner's own host.
 */
export async function transferAuthorized(
  tx: Prisma.TransactionClient,
  transfer: TransferRow,
  now: Date,
): Promise<boolean> {
  if (transfer.expiresAt <= now) return false;
  switch (transfer.purpose) {
    case "FETCH":
      return (
        transfer.operationId !== null &&
        transfer.destHostId !== null &&
        transfer.destHostOwnerId !== null &&
        transfer.destEpoch !== null &&
        transfer.dispatchAttempt !== null &&
        (await fetchWorkload(tx, {
          operationId: transfer.operationId,
          hostId: transfer.destHostId,
          hostOwnerId: transfer.destHostOwnerId,
          epoch: transfer.destEpoch,
          attempt: transfer.dispatchAttempt,
          fingerprint: transfer.fingerprint,
        })) !== null
      );
    case "CAPTURE_UPLOAD":
      return (
        transfer.operationId !== null &&
        transfer.sourceHostId !== null &&
        transfer.sourceHostOwnerId !== null &&
        transfer.sourceEpoch !== null &&
        transfer.dispatchAttempt !== null &&
        (await captureWorkload(tx, {
          operationId: transfer.operationId,
          hostId: transfer.sourceHostId,
          hostOwnerId: transfer.sourceHostOwnerId,
          epoch: transfer.sourceEpoch,
          attempt: transfer.dispatchAttempt,
        })) !== null
      );
    case "PUBLISH":
      return transfer.sourceHostOwnerId === transfer.userId;
    case "OFFLOAD_UPLOAD":
      return offloadUploadAuthorized(tx, transfer);
    case "RESTORE_FETCH":
      return restoreFetchAuthorized(tx, transfer);
    default:
      return false;
  }
}

/**
 * T8 `OFFLOAD_UPLOAD`: keyed on `diskOffloadId`, never on the fingerprint.
 * The source host and its current epoch match the transfer; the offload is
 * live and still uploadable (PENDING | EXPORTING | UPLOADING) from that
 * source; the sandbox is a WORKLOAD-class sandbox STOPPED at the offload's
 * source generation on that host; its owner is neither banned nor deleting.
 */
async function offloadUploadAuthorized(
  tx: Prisma.TransactionClient,
  transfer: TransferRow,
): Promise<boolean> {
  try {
    if (
      !transfer.diskOffloadId ||
      !transfer.sourceHostId ||
      !transfer.sourceHostOwnerId ||
      transfer.sourceEpoch === null
    )
      return false;
    const offload = await tx.sandboxDiskOffload.findFirst({
      where: {
        id: transfer.diskOffloadId,
        userId: transfer.userId,
        liveSandboxId: { not: null },
        state: { in: ["PENDING", "EXPORTING", "UPLOADING"] },
        sourceHostId: transfer.sourceHostId,
        sourceHostOwnerId: transfer.sourceHostOwnerId,
      },
      select: { sandboxId: true, sourceGeneration: true },
    });
    if (!offload) return false;
    const host = await tx.sandboxHost.findFirst({
      where: {
        id: transfer.sourceHostId,
        userId: transfer.sourceHostOwnerId,
        connectionEpoch: transfer.sourceEpoch,
      },
      select: { id: true },
    });
    if (!host) return false;
    const sandbox = await tx.sandbox.findFirst({
      where: {
        id: offload.sandboxId,
        userId: transfer.userId,
        state: "STOPPED",
        generation: offload.sourceGeneration,
        sandboxHostId: transfer.sourceHostId,
        hostOwnerId: transfer.sourceHostOwnerId,
        purpose: { in: [...OFFLOADABLE_SANDBOX_PURPOSES] },
      },
      select: { id: true },
    });
    return sandbox !== null && (await ownerActive(tx, transfer.userId));
  } catch {
    return false;
  }
}

/**
 * T8 `RESTORE_FETCH` (dispatched by the C6 restore): the exact RECONNECT
 * operation still active on the destination's epoch and attempt, admitted by
 * `admitRestore` for this offload (`restoreOffloadId`), whose placement
 * fetched it; the offload is STORED and is the sandbox's current disk. A
 * CONSUMED copy (§6a) or any other offload is refused.
 */
async function restoreFetchAuthorized(
  tx: Prisma.TransactionClient,
  transfer: TransferRow,
): Promise<boolean> {
  try {
    if (
      !transfer.diskOffloadId ||
      !transfer.operationId ||
      !transfer.destHostId ||
      !transfer.destHostOwnerId ||
      transfer.destEpoch === null ||
      transfer.dispatchAttempt === null
    )
      return false;
    return (
      (await restoreFetchWorkload(tx, {
        operationId: transfer.operationId,
        hostId: transfer.destHostId,
        hostOwnerId: transfer.destHostOwnerId,
        epoch: transfer.destEpoch,
        attempt: transfer.dispatchAttempt,
        fingerprint: transfer.fingerprint,
        restoreOffloadId: transfer.diskOffloadId,
      })) !== null
    );
  } catch {
    return false;
  }
}

/** A banned (archived) or deleting owner's disks get no new grants. */
async function ownerActive(tx: Prisma.TransactionClient, userId: string): Promise<boolean> {
  const owner = await tx.user.findUnique({
    where: { id: userId },
    select: { banned: true, banExpires: true, deletionRequestedAt: true },
  });
  if (!owner || owner.deletionRequestedAt !== null) return false;
  if (!owner.banned) return true;
  const [clock] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  return owner.banExpires !== null && clock !== undefined && owner.banExpires <= clock.now;
}

export const transferAuthoritySelect = {
  purpose: true,
  userId: true,
  operationId: true,
  sourceHostId: true,
  sourceHostOwnerId: true,
  sourceEpoch: true,
  destHostId: true,
  destHostOwnerId: true,
  destEpoch: true,
  dispatchAttempt: true,
  fingerprint: true,
  expiresAt: true,
  diskOffloadId: true,
} satisfies Prisma.SandboxImageTransferSelect;
