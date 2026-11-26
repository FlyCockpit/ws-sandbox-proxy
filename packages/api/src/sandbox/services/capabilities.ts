import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  enabledSdkFeatures,
  FS_PROCESS_LIMITS,
  guestApiCapabilities,
  SANDBOX_RELAY_PROTOCOL_VERSION,
  SDK_ROUTE_IDS,
  type SdkFeature,
  type SdkRouteId,
  sandboxCapabilitiesSchema,
} from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceProcedure } from "../../lib/sdk-key-access";
import { SERVICE_SCOPES, type ServiceScope } from "../../lib/service-scopes";
import {
  deploymentQueuePerKey,
  deploymentQueuePerOwner,
  deploymentWaitMaxMs,
} from "../capacity-limits";
import type { Principal } from "../contracts";
import { lockHostForSandboxOperation } from "../host-admission";
import { fsProcessHostRefused, fsProcessHostSupported } from "../host-protocol";
import { deploymentFiniteMaxMs, deploymentLeaseMaxMs } from "../lease-policy";
import { grantOf, viewerOf } from "../principal-kinds";
import { requireCurrentHostUsability } from "../sharing-access";
import { requireOwnedSandboxPlacement } from "../sharing-authority";
import { tunnelConfigured } from "../tunnels/config";

export type KeyGrant = {
  ownSandboxesOnly: boolean;
  scopes: ServiceScope[];
  resourceMode: "allOwned" | "allowlist";
  poolMode: "allUsable" | "selected";
};

/**
 * The calling credential's own grant, revalidated at entry. It discloses no
 * owner resources: allowlisted IDs are deliberately omitted (the scoped list
 * routes show what the key can see). Browser sessions hold every scope.
 */
export const getKeyGrant = serviceProcedure(
  { action: "capabilities.get" },
  async (principal: Principal, _input: undefined): Promise<KeyGrant> => {
    const grant = grantOf(principal);
    const viewer = viewerOf(principal);
    return {
      ownSandboxesOnly: viewer.ownSandboxesOnly,
      scopes: SERVICE_SCOPES.filter((scope) => grant.has(scope)),
      resourceMode: viewer.resourceMode === "ALL_OWNED" ? "allOwned" : "allowlist",
      poolMode: viewer.allowedPoolIds === "allUsable" ? "allUsable" : "selected",
    };
  },
);

export const getSandboxLimits = serviceProcedure(
  { action: "capabilities.get" },
  async (_principal: Principal, _input: undefined) => ({
    sandboxTimeoutMaxMs: deploymentFiniteMaxMs(),
    sandboxTimeoutZero: deploymentLeaseMaxMs() === null,
    capacityWaitMaxMs: deploymentWaitMaxMs(),
    capacityQueuePerKey: deploymentQueuePerKey(),
    capacityQueuePerOwner: deploymentQueuePerOwner(),
    /** A tunnel server is configured: creates may declare preview ports. */
    previewTunnels: await tunnelConfigured(),
  }),
);

/** Global route support and sandbox negotiation use the same feature map. */
export const getSandboxCapabilities = serviceProcedure(
  { action: "sandboxes.capabilities", intentOnly: true },
  async (owner: Principal, input: { id: string; routes?: readonly SdkRouteId[] }) =>
    prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await authorizeServiceAction(owner, "sandboxes.capabilities", { sandboxId: input.id }, tx);
      const located = await tx.sandbox.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { sandboxHostId: true },
      });
      if (!located) throw new ORPCError("NOT_FOUND");
      if (located.sandboxHostId)
        await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, input.id);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id=${input.id} AND "userId"=${owner.ownerId} FOR NO KEY UPDATE`;
      const sandbox = await tx.sandbox.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { generation: true, sandboxHostId: true, guestGroupSignals: true },
      });
      if (!sandbox || sandbox.sandboxHostId !== located.sandboxHostId)
        throw new ORPCError("CONFLICT");
      const placement = sandbox.sandboxHostId
        ? await requireOwnedSandboxPlacement(tx, owner.ownerId, input.id)
        : null;
      const current = placement
        ? await requireCurrentHostUsability(tx, owner.ownerId, input.id)
        : () => true;
      const host = sandbox.sandboxHostId
        ? await tx.sandboxHost.findFirst({
            where: { id: sandbox.sandboxHostId, userId: placement!.hostOwnerId },
            select: {
              status: true,
              connectionEpoch: true,
              relayProtocolVersion: true,
              relayProtocolEpoch: true,
              admissionRuntime: true,
              admissionEpoch: true,
              daemonMemoryBudgetMiB: true,
              daemonMaxCpuCount: true,
              daemonVcpuBudget: true,
            },
          })
        : null;
      const supported = fsProcessHostSupported(host);
      const sizeSupported =
        supported &&
        host != null &&
        host.status === "CONNECTED" &&
        host.relayProtocolVersion === SANDBOX_RELAY_PROTOCOL_VERSION &&
        host.daemonMemoryBudgetMiB !== null &&
        host.daemonMaxCpuCount !== null &&
        host.daemonVcpuBudget !== null;
      // Preview tunnels only while a tunnel server is configured (not while
      // turning off), as in the global capabilities.
      const tunnels = await tunnelConfigured(tx);
      const features = enabledSdkFeatures(input.routes ?? SDK_ROUTE_IDS).filter((feature) =>
        feature === "sandboxes.vmSize"
          ? sizeSupported
          : feature === "sandboxes.tunnel"
            ? tunnels
            : supported || !FS_PROCESS_FEATURES.has(feature),
      );
      if (!current()) throw new ORPCError("FORBIDDEN");
      return sandboxCapabilitiesSchema.parse({
        sandboxId: input.id,
        generation: sandbox.generation,
        features,
        // A connected host whose current-epoch facts are not yet all
        // reported (between hello and admission) is transitional, not
        // unsupported: work is admitted and queued until admission arrives.
        unavailableReason:
          host?.status !== "CONNECTED"
            ? "host_unavailable"
            : supported
              ? null
              : fsProcessHostRefused(host)
                ? "unsupported_runtime"
                : "host_unavailable",
        limits: {
          ...FS_PROCESS_LIMITS,
          commandTimeoutZero:
            FS_PROCESS_LIMITS.commandTimeoutZero &&
            supported &&
            features.includes("commands.execute"),
        },
        // TERM/INT/HUP only where the host has not observed a guest without
        // group signals (kernel < 6.9); unobserved stays checked at call.
        guestApi: guestApiCapabilities(
          supported && features.includes("processes.signal") && sandbox.guestGroupSignals !== false,
        ),
      });
    }),
);
const FS_PROCESS_FEATURES = new Set<SdkFeature>([
  "files.metadata",
  "files.list",
  "commands.background",
  "processes.list",
  "processes.signal",
]);
