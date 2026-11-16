import { ORPCError } from "@orpc/server";
import type {
  HostConnectionStatus,
  OperationState,
  SandboxOperationKind,
  SandboxState,
} from "@wssp/db";
import type { IMAGE_ARTIFACT_STATES, sandboxListQuerySchema } from "@wssp/sandbox-contracts";
import {
  type HostDto,
  type HostPage,
  type OperationDto,
  PAGE_SIZE_DEFAULT,
  RETIRED_REASONS,
  type SandboxDto,
  type SandboxPage,
  type SandboxStateDto,
  type SdkScope,
  type TemplateDto,
  type TemplatePage,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";
import { decodeCursor } from "../lib/pagination";
import type { ServiceScope } from "../lib/service-scopes";
import { getActionReceipt } from "./action-receipts";
import { poolCapacityLimits } from "./capacity-limits";
import type { Principal, UpdateSandboxInput } from "./contracts";
import { toOperationDto, toSandboxDto } from "./public-dto";
import { getKeyGrant, type KeyGrant } from "./services/capabilities";
import { listHosts } from "./services/hosts";
import { getOperation, getSandbox, listSandboxes, updateSandbox } from "./services/sandboxes";
import {
  getUsablePool as getPool,
  listUsablePoolMembers as listPoolMembers,
  listUsablePools as listPools,
} from "./services/sharing";
import { listTemplates } from "./services/templates";

export { toOperationDto, toSandboxDto } from "./public-dto";

/**
 * Shared public projections for the SDK read API. Each function calls the
 * owner-scoped `serviceProcedure` (the only authorization boundary) and then
 * copies an explicit field list into a public DTO. Nothing is spread from a
 * database row, so a service select that grows (for example with operation
 * output for browser sessions) cannot widen the public response.
 */

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
/** Compile-time parity: public enums and scopes equal the server's, in both directions. */
export const PUBLIC_ENUM_PARITY: [
  Exact<SandboxState, SandboxStateDto>,
  Exact<OperationState, OperationDto["state"]>,
  Exact<SandboxOperationKind, OperationDto["kind"]>,
  Exact<HostConnectionStatus, HostDto["status"]>,
  Exact<ServiceScope, SdkScope>,
] = [true, true, true, true, true];

const iso = (value: Date) => value.toISOString();
const isoOrNull = (value: Date | null) => (value ? value.toISOString() : null);

type HostRow = {
  id: string;
  slug: string;
  label: string;
  status: HostConnectionStatus;
  lastConnectedAt: Date | null;
  lastHeartbeatAt: Date | null;
  capacity: HostDto["capacity"];
  agentAccess?: HostDto["agentAccess"];
  storagePools?: HostDto["storagePools"];
  retainedRootCount: number;
  liveCount: number;
  draining: boolean;
  egressEnforcement: boolean;
  egressOpen: boolean;
  openEgressForOthers: boolean;
  guestSudoForOthers: boolean;
  egressGuard: HostDto["egressGuard"];
  policyReconciler?: HostDto["policyReconciler"];
  deletionRequestedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export function toHostDto(row: HostRow): HostDto {
  return {
    id: row.id,
    slug: row.slug,
    label: row.label,
    status: row.status,
    agentAccess: row.agentAccess ?? { owned: false },
    lastConnectedAt: isoOrNull(row.lastConnectedAt),
    lastHeartbeatAt: isoOrNull(row.lastHeartbeatAt),
    capacity: row.capacity,
    storagePools: row.storagePools ?? [],
    retainedRootCount: row.retainedRootCount,
    draining: row.draining,
    egressEnforcement: row.egressEnforcement,
    egressOpen: row.egressOpen,
    openEgressForOthers: row.openEgressForOthers,
    guestSudoForOthers: row.guestSudoForOthers,
    egressGuard: { ...row.egressGuard },
    ...(row.policyReconciler ? { policyReconciler: row.policyReconciler } : {}),
    liveSandboxCount: row.liveCount,
    drained: row.draining && row.liveCount === 0,
    deletionRequested: row.deletionRequestedAt !== null,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

type TemplateRow = {
  id: string;
  slug: string;
  label: string;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  imagePlacement: "INHERIT" | "ANY_NODE" | "OWNED_NODES_ONLY";
  captureKeep: number;
  pruneAfterDays: number | null;
  communitySource?: string | null;
  communityRefresh?: boolean;
};
export function toTemplateDto(row: TemplateRow): TemplateDto {
  return {
    id: row.id,
    slug: row.slug,
    label: row.label,
    archivedAt: isoOrNull(row.archivedAt),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
    imagePlacement: row.imagePlacement,
    captureKeep: row.captureKeep,
    pruneAfterDays: row.pruneAfterDays,
    ...(row.communitySource === undefined
      ? {}
      : {
          community: row.communitySource
            ? { source: row.communitySource, refresh: row.communityRefresh ?? true }
            : null,
        }),
  };
}
export function toTemplateRevisionDto(
  row: import("@wssp/db").Prisma.SandboxTemplateRevisionGetPayload<{
    select: typeof import("./template-resolution").revisionPublicSelect;
  }> & {
    image?: {
      state: (typeof IMAGE_ARTIFACT_STATES)[number];
      store: "S3" | "PEER";
      sizeBytes: string;
    } | null;
  },
) {
  return {
    id: row.id,
    templateId: row.templateId,
    revision: row.revision,
    cpuCount: row.cpuCount,
    memoryMiB: row.memoryMiB,
    defaultDiskGiB: row.defaultDiskGiB,
    minDiskGiB: row.minDiskGiB,
    incusFingerprint: row.incusFingerprint,
    architecture: row.architecture,
    guest: { uid: row.guestUid, gid: row.guestGid, home: row.guestHome, shell: row.guestShell },
    guestVersion: row.guestVersion,
    manifestDigest: row.manifestDigest,
    retiredAt: isoOrNull(row.retiredAt),
    createdAt: iso(row.createdAt),
    capturedWithGuestRoot: row.capturedWithGuestRoot,
    builtWithWsspRecipe: row.builtWithWsspRecipe,
    source: {
      kind: row.sourceKind,
      parentRevisionId: row.parentRevisionId,
      captureTag: row.captureTag,
    },
    ...(row.image === undefined ? {} : { image: row.image }),
    retiredReason: retiredReasonOf(row.retiredReason),
    pendingVerify: row.pendingVerifyBuildId !== null,
  };
}
function retiredReasonOf(value: string | null): (typeof RETIRED_REASONS)[number] | null {
  return RETIRED_REASONS.find((reason) => reason === value) ?? null;
}

export type SdkPageQuery = { limit?: number; cursor?: string };

/** A syntactically valid but undecodable cursor is rejected, never read as "first page". */
function pageInput(query: SdkPageQuery) {
  if (query.cursor !== undefined && decodeCursor(query.cursor) === null) {
    throw new ORPCError("BAD_REQUEST", { message: "Invalid pagination cursor." });
  }
  return { limit: query.limit ?? PAGE_SIZE_DEFAULT, cursor: query.cursor };
}

export async function sdkListHosts(principal: Principal, query: SdkPageQuery): Promise<HostPage> {
  const page = await listHosts(principal, pageInput(query));
  return { items: page.items.map(toHostDto), nextCursor: page.nextCursor };
}

export async function sdkListTemplates(
  principal: Principal,
  query: SdkPageQuery,
): Promise<TemplatePage> {
  const page = await listTemplates(principal, pageInput(query));
  return { items: page.items.map(toTemplateDto), nextCursor: page.nextCursor };
}

export async function sdkListSandboxes(
  principal: Principal,
  query: z.output<typeof sandboxListQuerySchema>,
): Promise<SandboxPage> {
  const page = await listSandboxes(principal, {
    ...query,
    limit: query.limit ?? PAGE_SIZE_DEFAULT,
  });
  return { items: page.items.map(toSandboxDto), nextCursor: page.nextCursor };
}

export async function sdkGetSandbox(principal: Principal, id: string): Promise<SandboxDto> {
  return toSandboxDto(await getSandbox(principal, { id }));
}

export async function sdkUpdateSandbox(
  principal: Principal,
  id: string,
  body: Pick<UpdateSandboxInput, "name" | "offload">,
): Promise<SandboxDto> {
  return toSandboxDto(
    await updateSandbox(principal, {
      id,
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.offload !== undefined ? { offload: body.offload } : {}),
    }),
  );
}

export async function sdkGetOperation(principal: Principal, id: string) {
  const receipt = await getActionReceipt(principal, { id });
  if (receipt) return receipt;
  return toOperationDto(await getOperation(principal, { operationId: id }));
}

export async function sdkGetKeyGrant(principal: Principal): Promise<KeyGrant> {
  return getKeyGrant(principal, undefined);
}

export async function sdkListTemplateRevisions(
  owner: import("./contracts").Principal,
  input: import("zod").z.infer<typeof import("./template-input").listRevisionsInput>,
) {
  const { listTemplateRevisions } = await import("./services/templates");
  const page = await listTemplateRevisions(owner, input);
  return { items: page.items.map(toTemplateRevisionDto), nextCursor: page.nextCursor };
}
export async function sdkListTemplateAvailability(
  owner: import("./contracts").Principal,
  input: import("zod").z.infer<typeof import("./template-input").listAvailabilityInput>,
) {
  const { listTemplateAvailability } = await import("./services/templates");
  const page = await listTemplateAvailability(owner, input);
  return {
    items: page.items.map((row) => ({
      id: row.id,
      revisionId: row.revisionId,
      hostId: row.hostId,
      status: row.status,
      verifiedConnectionEpoch: row.verifiedConnectionEpoch,
      observedAt: isoOrNull(row.observedAt),
    })),
    nextCursor: page.nextCursor,
  };
}

export async function sdkListPools(owner: Principal, query: { cursor?: string; limit?: number }) {
  const page = await listPools(owner, { ...query, limit: query.limit ?? PAGE_SIZE_DEFAULT });
  return { items: page.items.map(toPoolDto), nextCursor: page.nextCursor };
}
function toPoolDto(row: Awaited<ReturnType<typeof listPools>>["items"][number]) {
  return {
    id: row.id,
    slug: row.slug,
    label: row.label,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
    lease: row.lease,
    preferOwnHosts: row.preferOwnHosts,
    capacityWait: poolCapacityLimits(row),
    ...(row.owner && row.share
      ? { owner: row.owner, share: row.share, disconnectGraceSeconds: row.disconnectGraceSeconds }
      : {}),
  };
}
export async function sdkGetPool(owner: Principal, id: string) {
  const row = await getPool(owner, { id });
  return { ...toPoolDto(row), memberCount: row.memberCount };
}
export async function sdkListPoolMembers(
  owner: Principal,
  poolId: string,
  query: { cursor?: string; limit?: number },
) {
  const page = await listPoolMembers(owner, {
    ...query,
    poolId,
    limit: query.limit ?? PAGE_SIZE_DEFAULT,
  });
  return {
    items: page.items.map((row) =>
      "sandboxHostId" in row
        ? {
            id: row.id,
            poolId: row.poolId,
            hostId: row.sandboxHostId,
            enabled: row.enabled,
            createdAt: iso(row.createdAt),
            updatedAt: iso(row.updatedAt),
            host: {
              id: row.Host.id,
              slug: row.Host.slug,
              label: row.Host.label,
              status: row.Host.status,
              draining: row.Host.draining,
            },
          }
        : { id: row.id, poolId: row.poolId },
    ),
    nextCursor: page.nextCursor,
  };
}
