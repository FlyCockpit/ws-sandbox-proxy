import type {
  OperationState,
  SandboxEgressModeReason,
  SandboxGuestSudoReason,
  SandboxLeaseExpireAction,
  SandboxOperationKind,
  SandboxState,
} from "@wssp/db";
import {
  type CapacityWaitView,
  failureSchema,
  OPERATION_PROGRESS_PHASES,
  type OperationDto,
  operationErrorDetailSchema,
  operationOutcome,
  publicOperationErrorCode,
  readinessFailureReasonSchema,
  type SandboxDto,
} from "@wssp/sandbox-contracts";
import { type SandboxDiskFacts, sandboxDiskDto } from "./disk-offload/disk-view";
import { recordedEgressPolicy, recordedEgressRequest } from "./egress-policy";
import { guestSudoReasonDto } from "./guest-sudo-policy";
import { readinessReasonOfFailure } from "./readiness-detail";
import { storedMetadata } from "./stored-metadata";

/**
 * THE public `/v1` projections of a sandbox and an operation, shared by the SDK
 * read API (`sdk-reads.ts`) and the webhook renderer
 * (`../webhooks/render.ts`). Deliberately free of env, queue and Prisma-client
 * imports: the external worker renders webhook payloads through this module
 * and validates only `@wssp/env/shared`.
 */

const iso = (value: Date) => value.toISOString();
const isoOrNull = (value: Date | null) => (value ? value.toISOString() : null);
const onExpire = (action: SandboxLeaseExpireAction): "stop" | "destroy" =>
  action === "DESTROY" ? "destroy" : "stop";

/**
 * Creator view of a sandbox row: usage attribution is dropped, and the host and
 * storage identity are blanked when the host belongs to someone else (a shared
 * pool), so a creator never learns another owner's host id.
 */
export function redactSandbox<
  T extends {
    hostOwnerId: string | null;
    storagePoolId: string | null;
    storagePoolName: string | null;
    storageMarker: string | null;
    usagePoolId: string | null;
    usageMemberId: string | null;
    CurrentPlacement?: { acceptedGraceSeconds: number } | null;
    acceptedGraceSeconds?: number;
  },
>(row: T, creatorId: string) {
  const {
    hostOwnerId,
    usagePoolId: _pool,
    usageMemberId: _member,
    CurrentPlacement,
    ...view
  } = row;
  return {
    ...view,
    acceptedGraceSeconds: row.acceptedGraceSeconds ?? CurrentPlacement?.acceptedGraceSeconds ?? 0,
    ...(hostOwnerId !== creatorId
      ? { sandboxHostId: null, storagePoolId: null, storagePoolName: null, storageMarker: null }
      : {}),
  };
}

export type SandboxRow = SandboxDiskFacts & {
  acceptedGraceSeconds?: number;
  accessGraceUntil?: Date | null;
  cpuCount: number;
  memoryMiB: number;
  diskGiB: number;
  storagePoolId: string | null;
  storagePoolName: string | null;
  storageMarker: string | null;
  id: string;
  name: string;
  sandboxHostId: string | null;
  templateId: string;
  templateRevisionId: string;
  originPoolId: string | null;
  state: SandboxState;
  generation: number;
  startedAt?: Date | null;
  readyAt?: Date | null;
  leaseRevision: number;
  leaseExpiresAt: Date | null;
  leaseExpireAction: SandboxLeaseExpireAction;
  leaseExpiresAtRequested: Date | null;
  leaseExpireActionRequested: SandboxLeaseExpireAction | null;
  leaseExpiresAtEffective: Date | null;
  leaseExpireActionEffective: SandboxLeaseExpireAction | null;
  /** Lease from READY not yet ACKed: the stored deadline is a backstop only. */
  leasePendingReady?: boolean;
  metadata: unknown;
  egressPolicy: unknown;
  egressPolicyHash: string | null;
  egressRequest: unknown;
  egressModeReason: SandboxEgressModeReason | null;
  egressDeniedGrants: string[];
  guestSudo: boolean;
  guestSudoRequested: boolean;
  guestSudoReason: SandboxGuestSudoReason | null;
  guestRoot: boolean;
  /** Preview tunnels: a tunnel sandbox and its declared ports (absent on
   * old projections). */
  tunnelEnabled?: boolean;
  tunnelPorts?: number[];
  capacityWait?: CapacityWaitView;
  createdAt: Date;
  updatedAt: Date;
};

/** Public spelling of the stored mode reason. */
export function egressModeReasonDto(
  reason: SandboxEgressModeReason | null,
): "node_policy" | "host_unsupported" | null {
  return reason === "NODE_POLICY"
    ? "node_policy"
    : reason === "HOST_UNSUPPORTED"
      ? "host_unsupported"
      : null;
}

function leaseTerm(expiresAt: Date | null, action: SandboxLeaseExpireAction | null) {
  return action === null ? null : { expiresAt: isoOrNull(expiresAt), onExpire: onExpire(action) };
}

export function toSandboxDto(row: SandboxRow): SandboxDto {
  return {
    acceptedGraceSeconds: row.acceptedGraceSeconds ?? 0,
    accessGraceUntil: isoOrNull(row.accessGraceUntil ?? null),
    cpuCount: row.cpuCount,
    memoryMiB: row.memoryMiB,
    diskGiB: row.diskGiB,
    id: row.id,
    name: row.name,
    hostId: row.sandboxHostId,
    storageId: row.storagePoolId,
    storagePoolName: row.storagePoolName,
    storageMarker: row.storageMarker,
    templateId: row.templateId,
    templateRevisionId: row.templateRevisionId,
    originPoolId: row.originPoolId,
    state: row.state,
    generation: row.generation,
    lease: {
      revision: row.leaseRevision,
      // Until the host ACKs a READY-based lease there is no deadline yet.
      expiresAt: row.leasePendingReady ? null : isoOrNull(row.leaseExpiresAt),
      onExpire: onExpire(row.leaseExpireAction),
      requested: row.leasePendingReady
        ? null
        : leaseTerm(row.leaseExpiresAtRequested, row.leaseExpireActionRequested),
      effective: leaseTerm(row.leaseExpiresAtEffective, row.leaseExpireActionEffective),
    },
    endAt: isoOrNull(row.leaseExpiresAtEffective),
    startedAt: isoOrNull(row.startedAt ?? null),
    readyAt: isoOrNull(row.readyAt ?? null),
    lifecycle: {
      onTimeout: row.leaseExpireAction === "DESTROY" ? "kill" : "stop",
      autoResume: false,
    },
    sandboxDomain: null,
    portExposure: null,
    metadata: storedMetadata(row.id, row.metadata),
    egress: recordedEgressPolicy(row).policy,
    egressRequest: recordedEgressRequest(row.egressRequest),
    egressModeReason: egressModeReasonDto(row.egressModeReason),
    egressDeniedGrants: [...row.egressDeniedGrants],
    guestSudo: row.guestSudo,
    guestSudoRequested: row.guestSudoRequested,
    guestSudoReason: guestSudoReasonDto(row.guestSudoReason),
    guestRoot: row.guestRoot,
    // Present on tunnel sandboxes only (possibly empty): a sandbox without
    // tunnels reads as before.
    ...(row.tunnelEnabled ? { tunnelPorts: [...(row.tunnelPorts ?? [])] } : {}),
    disk: sandboxDiskDto(row),
    ...(row.state === "WAITING_FOR_CAPACITY" && row.capacityWait
      ? { capacityWait: row.capacityWait }
      : {}),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export type OperationRow = {
  id: string;
  sandboxId: string;
  kind: SandboxOperationKind;
  state: OperationState;
  generation: number;
  errorCode: string | null;
  /** Already derived from the stored failure record (`getOperation`). */
  readinessReason?: string;
  createdAt: Date;
  updatedAt: Date;
  failure?: unknown;
  leaseAcceptedAt?: Date | null;
  leaseTimeoutMs?: number | null;
  leaseRevisionAccepted?: number | null;
  leaseExpiresAtAccepted?: Date | null;
  leaseExpireActionAccepted?: SandboxLeaseExpireAction | null;
  leaseAcknowledgedAt?: Date | null;
  leaseAcknowledgedAttempt?: number | null;
  leaseAcknowledgedEpoch?: number | null;
  leaseFromReady?: boolean;
  dispatchedAt: Date | null;
  completedAt: Date | null;
  progressPhase?: string | null;
  progressBytesDone?: bigint | null;
  progressBytesTotal?: bigint | null;
  progressAt?: Date | null;
  Capture?: { revisionId: string | null; errorDetail?: string | null } | null;
};

/**
 * The storage cause of a failed template capture (`capture_store_failed`),
 * code-shaped as its CHECK requires (never message text): the same detail a
 * template build shows (post-landing #6). Null for every other operation.
 */
export function captureErrorDetail(row: {
  kind: SandboxOperationKind;
  errorCode: string | null;
  Capture?: { errorDetail?: string | null } | null;
}): string | null {
  if (row.kind !== "CAPTURE_TEMPLATE" || row.errorCode !== "capture_store_failed") return null;
  return operationErrorDetailSchema.safeParse(row.Capture?.errorDetail).data ?? null;
}

const PROGRESS_PHASES: ReadonlySet<string> = new Set(OPERATION_PROGRESS_PHASES);

/** The fixed readiness reason of a `guest_unavailable` operation, if recorded. */
function readinessReasonOf(row: OperationRow): Pick<OperationDto, "readinessReason"> {
  if (row.errorCode !== "guest_unavailable") return {};
  const reason =
    readinessFailureReasonSchema.safeParse(row.readinessReason).data ??
    readinessReasonOfFailure(row.failure);
  return reason ? { readinessReason: reason } : {};
}

export function toOperationDto(row: OperationRow): OperationDto {
  const failure = failureSchema.safeParse(row.failure).data;
  const captureDetail = captureErrorDetail(row);
  return {
    id: row.id,
    sandboxId: row.sandboxId,
    kind: row.kind,
    state: row.state,
    outcome: operationOutcome(row.state),
    generation: row.generation,
    failure: failure
      ? {
          resource: failure.resource,
          effect: failure.effect,
          ...((row.errorCode === "host_capacity" || row.errorCode === "capacity_wait_timeout") &&
          failure.reason
            ? { reason: failure.reason }
            : {}),
        }
      : null,
    leaseIntent:
      // A READY-based lease has no intent to show until the host ACKs it.
      !(row.leaseFromReady && row.leaseAcknowledgedAt == null) &&
      row.leaseAcceptedAt != null &&
      row.leaseTimeoutMs != null &&
      row.leaseRevisionAccepted != null &&
      row.leaseExpiresAtAccepted != null &&
      row.leaseExpireActionAccepted != null
        ? {
            acceptedAt: iso(row.leaseAcceptedAt),
            timeoutMs: row.leaseTimeoutMs,
            revision: row.leaseRevisionAccepted,
            endAt: iso(row.leaseExpiresAtAccepted),
            onTimeout: row.leaseExpireActionAccepted === "DESTROY" ? "kill" : "stop",
            acknowledgedAt: isoOrNull(row.leaseAcknowledgedAt ?? null),
            acknowledgedAttempt: row.leaseAcknowledgedAttempt ?? null,
            acknowledgedEpoch: row.leaseAcknowledgedEpoch ?? null,
          }
        : null,
    // Private-config refusal is an internal diagnostic. Reuse the existing
    // public codes without implying that a possible prior effect was absent.
    errorCode: publicOperationErrorCode(
      row.errorCode === "private_config_refused"
        ? row.state === "FAILED"
          ? "host_effect_not_issued"
          : "unknown_outcome"
        : row.errorCode,
    ),
    ...readinessReasonOf(row),
    ...(captureDetail ? { captureDetail } : {}),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
    dispatchedAt: isoOrNull(row.dispatchedAt),
    completedAt: isoOrNull(row.completedAt),
    ...(row.progressPhase && PROGRESS_PHASES.has(row.progressPhase) && row.progressAt
      ? {
          progress: {
            phase: row.progressPhase as (typeof OPERATION_PROGRESS_PHASES)[number],
            bytesDone: row.progressBytesDone == null ? null : Number(row.progressBytesDone),
            bytesTotal: row.progressBytesTotal == null ? null : Number(row.progressBytesTotal),
            updatedAt: iso(row.progressAt),
          },
        }
      : {}),
    ...(row.Capture?.revisionId ? { capturedRevisionId: row.Capture.revisionId } : {}),
  };
}
