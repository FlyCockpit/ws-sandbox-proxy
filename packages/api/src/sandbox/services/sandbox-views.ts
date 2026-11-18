import prisma, { type Prisma, type SandboxOperationKind } from "@wssp/db";
import {
  OPERATION_PROGRESS_PHASES,
  type OperationProgressDto,
  publicOperationErrorCode,
} from "@wssp/sandbox-contracts";
import { findOwnedOrThrow } from "../../lib/ownership";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { capacityWaitViews } from "../capacity-queue";
import type { ListSandboxesInput, Principal, SandboxIdInput } from "../contracts";
import { sandboxDiskDto, sandboxDiskSelect } from "../disk-offload/disk-view";
import { recordedEgressPolicy, recordedEgressRequest } from "../egress-policy";
import { guestSudoReasonDto } from "../guest-sudo-policy";
import { readLockedPathLimit } from "../lease-policy";
import { egressModeReasonDto } from "../public-dto";
import { sandboxListPage, sandboxListReadQuery } from "../sandbox-list";
import { safeOperationError } from "../sensitive-errors";
import { storedMetadata } from "../stored-metadata";

/**
 * The dashboard's owner projection of sandboxes (C47), session only. Besides
 * the sandbox row it carries what the page needs to show a sandbox
 * truthfully: its host's connection summary (an offline host means the stored
 * state may be stale and queued work waits), the template revision it was
 * started from (archived ones included) and its latest lifecycle receipt (so
 * QUEUED and UNKNOWN_OUTCOME stay visible after a reload). The SDK plane keeps
 * `listSandboxes`/`getSandbox` and its own DTO; it never pays for these joins.
 */

/** Lifecycle receipts the projection surfaces (the latest one per sandbox). */
const LIFECYCLE_OPERATION_KINDS = [
  "CREATE_SANDBOX",
  "KILL_SANDBOX",
  "STOP_SANDBOX",
  "RECONNECT_SANDBOX",
  "RENEW_SANDBOX_LEASE",
] as const satisfies readonly SandboxOperationKind[];

const sandboxViewSelect = {
  // Disk location and offload facts (offload plan C8); its template
  // placement read is merged into SandboxTemplateRevision below.
  ...sandboxDiskSelect,
  id: true,
  // Owner content: this view is the owner's own dashboard (session only).
  name: true,
  hostOwnerId: true,
  accessGraceUntil: true,
  CurrentPlacement: { select: { acceptedGraceSeconds: true } },
  state: true,
  generation: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  storagePoolId: true,
  storagePoolName: true,
  templateId: true,
  templateRevisionId: true,
  originPoolId: true,
  sandboxHostId: true,
  leaseExpiresAt: true,
  leaseRevision: true,
  leaseExpireAction: true,
  leaseExpiresAtRequested: true,
  leaseExpireActionRequested: true,
  leaseRevisionEffective: true,
  leaseExpiresAtEffective: true,
  leasePendingReady: true,
  leaseExpireActionEffective: true,
  hostExpiryConfirmedAt: true,
  hostExpiryRevision: true,
  hostExpiryAction: true,
  metadata: true,
  // Recorded immutable egress allowlist (C34), surfaced normalized (C37).
  egressPolicy: true,
  egressPolicyHash: true,
  egressRequest: true,
  egressModeReason: true,
  egressDeniedGrants: true,
  guestSudo: true,
  guestSudoRequested: true,
  guestSudoReason: true,
  tunnelPorts: true,
  guestRoot: true,
  lastErrorCode: true,
  createdAt: true,
  updatedAt: true,
  SandboxHost: {
    select: {
      id: true,
      slug: true,
      label: true,
      status: true,
      lastConnectedAt: true,
      lastHeartbeatAt: true,
      deletionRequestedAt: true,
      draining: true,
      quarantinedAt: true,
    },
  },
  SandboxTemplateRevision: {
    select: {
      id: true,
      revision: true,
      retiredAt: true,
      Template: {
        select: { id: true, slug: true, label: true, archivedAt: true, imagePlacement: true },
      },
    },
  },
  // Receipt metadata only: never the request hash, key, result or error detail.
  Operations: {
    where: { kind: { in: [...LIFECYCLE_OPERATION_KINDS] } },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: 1,
    select: {
      id: true,
      kind: true,
      state: true,
      errorCode: true,
      // Host-reported phase (restore: fetching_disk, importing_disk); a fixed label.
      progressPhase: true,
      createdAt: true,
      completedAt: true,
    },
  },
} satisfies Prisma.SandboxSelect;

type SandboxViewRow = Prisma.SandboxGetPayload<{ select: typeof sandboxViewSelect }>;

/** A stored phase outside the public set (never written, by the DB check) reads as none. */
function progressPhaseOf(phase: string | null): OperationProgressDto["phase"] | null {
  return OPERATION_PROGRESS_PHASES.find((known) => known === phase) ?? null;
}

function toSandboxView(
  {
    hostOwnerId,
    CurrentPlacement,
    SandboxHost,
    SandboxTemplateRevision,
    Operations,
    egressPolicy,
    egressPolicyHash,
    egressRequest,
    egressModeReason,
    guestSudoReason,
    DiskOffloads,
    User,
    purpose,
    diskOffloadId,
    cachedOffloadSeq,
    credentialFilesEver,
    offloadPin,
    offloadMode,
    offloadAfterMs,
    lastStoppedAt,
    ...row
  }: SandboxViewRow,
  creatorId: string,
) {
  const { imagePlacement: _placement, ...template } = SandboxTemplateRevision.Template;
  return {
    ...row,
    // Owner view: the same disk facts as the /v1 DTO, never the raw offload rows.
    disk: sandboxDiskDto({
      state: row.state,
      generation: row.generation,
      purpose,
      diskOffloadId,
      cachedOffloadSeq,
      credentialFilesEver,
      offloadPin,
      offloadMode,
      offloadAfterMs,
      lastStoppedAt,
      DiskOffloads,
      User,
      SandboxTemplateRevision,
    }),
    acceptedGraceSeconds: CurrentPlacement?.acceptedGraceSeconds ?? 0,
    ...(hostOwnerId !== creatorId
      ? { sandboxHostId: null, storagePoolId: null, storagePoolName: null }
      : {}),
    lastErrorCode:
      row.lastErrorCode === "expiry_failed" || row.lastErrorCode === "instance_missing"
        ? row.lastErrorCode
        : publicOperationErrorCode(row.lastErrorCode),
    metadata: storedMetadata(row.id, row.metadata),
    // Effective policy (explicit mode), the request, and why it differs.
    egress: recordedEgressPolicy({ egressPolicy, egressPolicyHash }).policy,
    egressRequest: recordedEgressRequest(egressRequest),
    egressModeReason: egressModeReasonDto(egressModeReason),
    guestSudoReason: guestSudoReasonDto(guestSudoReason),
    // Protected metadata cannot expose raw diagnostics from historical rows.
    expiryFailureReason:
      row.lastErrorCode === "expiry_failed" ? safeOperationError("expiry_failed").message : null,
    host: hostOwnerId === creatorId ? SandboxHost : null,
    template: {
      ...template,
      revisionId: SandboxTemplateRevision.id,
      revision: SandboxTemplateRevision.revision,
      retiredAt: SandboxTemplateRevision.retiredAt,
    },
    lastLifecycleOperation: Operations[0]
      ? {
          ...Operations[0],
          errorCode: publicOperationErrorCode(Operations[0].errorCode),
          progressPhase: progressPhaseOf(Operations[0].progressPhase),
        }
      : null,
  };
}

export const listSandboxViews = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListSandboxesInput) => {
    const query = await sandboxListReadQuery(owner, input);
    const rows = await prisma.sandbox.findMany({
      where: query.where,
      orderBy: query.orderBy,
      take: query.take,
      select: sandboxViewSelect,
    });
    const page = sandboxListPage(rows, query);
    const waits = await capacityWaitViews(
      prisma,
      owner.ownerId,
      page.items.filter((row) => row.state === "WAITING_FOR_CAPACITY").map((row) => row.id),
    );
    return {
      items: page.items.map((row) => ({
        ...toSandboxView(row, owner.ownerId),
        capacityWait: waits.get(row.id) ?? null,
      })),
      nextCursor: page.nextCursor,
    };
  },
);

/**
 * The label of the pool a sandbox was placed through, for its Placement row:
 * only while the viewer owns that pool or still holds a share of it. Anyone
 * else (a revoked share, a deleted pool) gets null and reads "a shared pool".
 */
async function placementPoolLabel(ownerId: string, poolId: string | null) {
  if (!poolId) return null;
  const pool = await prisma.sandboxPool.findFirst({
    where: {
      id: poolId,
      deletedAt: null,
      OR: [{ userId: ownerId }, { Shares: { some: { granteeUserId: ownerId } } }],
    },
    select: { label: true } satisfies Prisma.SandboxPoolSelect,
  });
  return pool?.label ?? null;
}

/** One owned sandbox; another owner's ID is indistinguishable from a missing one (404). */
export const getSandboxView = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: SandboxIdInput) => {
    const row = await findOwnedOrThrow({
      find: (args) => prisma.sandbox.findFirst(args),
      args: { where: { id: input.id }, select: sandboxViewSelect },
      owner: { field: "userId", id: owner.ownerId },
      notFound: "Sandbox not found",
    });
    // Display only, read without locks: the renew form's bound. The server
    // re-checks it under G/H/S when the renewal is accepted.
    const leaseLimit = await prisma.$transaction((tx) => readLockedPathLimit(tx, row));
    const capacityWait =
      row.state === "WAITING_FOR_CAPACITY"
        ? ((await capacityWaitViews(prisma, owner.ownerId, [row.id])).get(row.id) ?? null)
        : null;
    const placementPool = await placementPoolLabel(owner.ownerId, row.originPoolId);
    return {
      ...toSandboxView(row, owner.ownerId),
      leaseLimit,
      capacityWait,
      placementPoolLabel: placementPool,
    };
  },
);
