import prisma, { type Prisma } from "@wssp/db";
import {
  checkBackupFreshnessQueue,
  notifyDataDeletionsQueue,
  reapExpiredAuthTokensQueue,
  reapWebhookLogQueue,
  webhookDeliveryQueue,
} from "@wssp/queue";
import { z } from "zod";

import { adminOr404Procedure } from "../index";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { destinationHost } from "../webhooks/destination-policy";

// Deliberate field allowlists: no arbitrary JSON, guest paths, request bodies,
// output, errors, inventory digests or credentials may cross this boundary.
// Names join in so a row reads as a thing, not an id (owner decision
// 2026-11-26): the owner's account name and email (admins already see them on
// Users), and the owner-chosen host label, template label and sandbox name.
// Those are admin-only: host and pool owners never see another owner's names.
const ownerSelect = { select: { name: true, email: true } } as const;
const hostSelect = {
  id: true,
  label: true,
  userId: true,
  createdAt: true,
  status: true,
  lastHeartbeatAt: true,
  draining: true,
  daemonMemoryBudgetMiB: true,
  daemonVcpuBudget: true,
  memoryReservedMiB: true,
  vcpuReserved: true,
  rootCount: true,
  liveCount: true,
  daemonMaxCpuCount: true,
  quarantinedAt: true,
  User: ownerSelect,
} satisfies Prisma.SandboxHostSelect;
const sandboxSelect = {
  id: true,
  userId: true,
  createdAt: true,
  sandboxHostId: true,
  templateId: true,
  templateRevisionId: true,
  originPoolId: true,
  state: true,
  generation: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  // Metadata only: whether the guest may run as root (operators of shared hosts).
  guestSudo: true,
  guestSudoReason: true,
  guestRoot: true,
  name: true,
  SandboxHost: { select: { label: true } },
  SandboxTemplateRevision: { select: { Template: { select: { label: true } } } },
  User: ownerSelect,
} satisfies Prisma.SandboxSelect;
const operationSelect = {
  id: true,
  userId: true,
  createdAt: true,
  sandboxId: true,
  kind: true,
  state: true,
  generation: true,
  updatedAt: true,
  Sandbox: { select: { name: true } },
  User: ownerSelect,
} satisfies Prisma.SandboxOperationSelect;
// Webhook endpoints: metadata only. The URL is read solely to derive its HOST;
// path, query, secrets, bodies, excerpts and resolved addresses never cross.
const webhookEndpointSelect = {
  id: true,
  userId: true,
  createdAt: true,
  url: true,
  disabledAt: true,
  disabledReason: true,
  consecutiveFailures: true,
  failingSince: true,
  lastSuccessAt: true,
  User: ownerSelect,
} satisfies Prisma.WebhookEndpointSelect;
const WEBHOOK_DELIVERY_STATE_LIST = [
  "PENDING",
  "IN_FLIGHT",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
] as const;

async function webhookCounters(now: Date) {
  const since = new Date(now.getTime() - 86_400_000);
  const [endpoints, enabled, disabledForFailures, byState, oldestPending, errorClasses] =
    await Promise.all([
      prisma.webhookEndpoint.count(),
      prisma.webhookEndpoint.count({ where: { disabledAt: null } }),
      prisma.webhookEndpoint.count({ where: { disabledReason: "sustained_failures" } }),
      prisma.webhookDelivery.groupBy({
        by: ["state"],
        where: { createdAt: { gte: since } },
        _count: { _all: true },
        orderBy: { state: "asc" },
      }),
      prisma.webhookDelivery.findFirst({
        where: { state: "PENDING" },
        orderBy: { createdAt: "asc" },
        select: { createdAt: true },
      }),
      prisma.webhookDeliveryAttempt.groupBy({
        by: ["errorClass"],
        where: { startedAt: { gte: since }, errorClass: { not: null } },
        _count: { _all: true },
        orderBy: { errorClass: "asc" },
        take: 32,
      }),
    ]);
  return {
    endpoints,
    enabled,
    disabledForFailures,
    deliveries24h: Object.fromEntries(
      WEBHOOK_DELIVERY_STATE_LIST.map((state) => [
        state,
        byState.find((row) => row.state === state)?._count._all ?? 0,
      ]),
    ) as Record<(typeof WEBHOOK_DELIVERY_STATE_LIST)[number], number>,
    oldestPendingAgeSeconds: oldestPending
      ? Math.max(0, Math.floor((now.getTime() - oldestPending.createdAt.getTime()) / 1000))
      : null,
    errorClasses24h: errorClasses.map((row) => ({
      errorClass: row.errorClass ?? "unknown",
      count: row._count._all,
    })),
  };
}

/** The joined owner as `owner: { name, email }` (the relation itself never crosses). */
function withOwner<T extends { User: { name: string; email: string } }>({
  User,
  ...row
}: T): Omit<T, "User"> & { owner: { name: string; email: string } } {
  return { ...row, owner: { name: User.name, email: User.email } };
}

/** A sandbox row with its host and template labels flattened (the relations never cross). */
function sandboxRow<
  T extends {
    User: { name: string; email: string };
    SandboxHost: { label: string } | null;
    SandboxTemplateRevision: { Template: { label: string } };
  },
>({ SandboxHost, SandboxTemplateRevision, ...row }: T) {
  return {
    ...withOwner(row),
    hostLabel: SandboxHost?.label ?? null,
    templateLabel: SandboxTemplateRevision.Template.label,
  };
}

/** An operation row with its sandbox's name flattened (the relation never crosses). */
function operationRow<
  T extends { User: { name: string; email: string }; Sandbox: { name: string } },
>({ Sandbox, ...row }: T) {
  return { ...withOwner(row), sandboxName: Sandbox.name };
}

const filterId = entityId.regex(/^[A-Za-z0-9_-]+$/);
const filters = cursorPageInput.extend({ ownerId: filterId.optional() });

export const adminObservabilityRouter = {
  counters: adminOr404Procedure.handler(async () => {
    const now = new Date();
    const [users, hosts, sandboxes, operations, leases, queues, webhooks] = await Promise.all([
      prisma.user.count(),
      prisma.sandboxHost.count(),
      prisma.sandbox.count(),
      prisma.sandboxOperation.count(),
      Promise.all([
        // Past the server deadline but not yet converged by an expiry.
        prisma.sandbox.count({ where: { state: "READY", leaseExpiresAt: { lte: now } } }),
        prisma.sandboxOperation.count({
          where: {
            kind: "RENEW_SANDBOX_LEASE",
            state: { in: ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"] },
          },
        }),
        prisma.sandbox.count({ where: { hostExpiryConfirmedAt: { not: null } } }),
        prisma.sandboxHost.count({ where: { quarantinedAt: { not: null } } }),
        prisma.outboxEvent.count({ where: { aggregateType: "sandbox", processedAt: null } }),
      ]).then(
        ([
          expiredPending,
          unacknowledgedRenewals,
          hostEnforced,
          quarantinedHosts,
          relayOutbox,
        ]) => ({
          expiredPending,
          unacknowledgedRenewals,
          hostEnforced,
          quarantinedHosts,
          relayOutbox,
        }),
      ),
      Promise.all(
        [
          reapExpiredAuthTokensQueue,
          checkBackupFreshnessQueue,
          webhookDeliveryQueue,
          reapWebhookLogQueue,
          notifyDataDeletionsQueue,
        ].map(async (queue) => {
          const counts = await queue.getJobCounts(
            "wait",
            "active",
            "delayed",
            "failed",
            "completed",
          );
          return {
            queue: queue.name,
            waiting: counts.wait ?? 0,
            active: counts.active ?? 0,
            delayed: counts.delayed ?? 0,
            failed: counts.failed ?? 0,
            completed: counts.completed ?? 0,
          };
        }),
      ),
      webhookCounters(now),
    ]);
    return { users, hosts, sandboxes, operations, leases, queues, webhooks };
  }),
  listWebhookEndpoints: adminOr404Procedure
    .input(
      filters
        .extend({ state: z.enum(["enabled", "disabled", "sustained_failures"]).optional() })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 20;
      const rows = await prisma.webhookEndpoint.findMany({
        where: withCursor(
          {
            userId: input?.ownerId,
            ...(input?.state === "enabled"
              ? { disabledAt: null }
              : input?.state === "disabled"
                ? { disabledAt: { not: null } }
                : input?.state === "sustained_failures"
                  ? { disabledReason: "sustained_failures" }
                  : {}),
          },
          "createdAt",
          input?.cursor,
          "desc",
        ),
        select: webhookEndpointSelect,
        take: pageTake(limit),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      });
      const page = cursorPage(rows, limit, "createdAt");
      return {
        nextCursor: page.nextCursor,
        items: page.items.map((row) => ({
          id: row.id,
          ownerId: row.userId,
          owner: { name: row.User.name, email: row.User.email },
          createdAt: row.createdAt,
          host: destinationHost(row.url),
          state:
            row.disabledAt === null
              ? ("enabled" as const)
              : row.disabledReason === "sustained_failures"
                ? ("sustained_failures" as const)
                : ("disabled" as const),
          consecutiveFailures: row.consecutiveFailures,
          failingSince: row.failingSince,
          lastSuccessAt: row.lastSuccessAt,
        })),
      };
    }),
  listHosts: adminOr404Procedure
    .input(
      filters
        .extend({
          status: z.enum(["DISCONNECTED", "CONNECTED", "STALE", "REVOKED"]).optional(),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 20;
      const rows = await prisma.sandboxHost.findMany({
        where: withCursor(
          { userId: input?.ownerId, status: input?.status },
          "createdAt",
          input?.cursor,
          "desc",
        ),
        select: hostSelect,
        take: pageTake(limit),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      });
      const page = cursorPage(rows, limit, "createdAt");
      return { ...page, items: page.items.map(withOwner) };
    }),
  listSandboxes: adminOr404Procedure
    .input(
      filters
        .extend({
          hostId: filterId.optional(),
          state: z
            .enum([
              "REQUESTED",
              "SCHEDULED",
              "PROVISIONING",
              "READY",
              "STOPPING",
              "STOPPED",
              "RECLAIMING",
              "DELETED",
              "UNREACHABLE",
              "RECOVERED",
              "HOST_LOST",
              "ERROR",
              "WAITING_FOR_CAPACITY",
              "OFFLOADED",
            ])
            .optional(),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 20;
      const rows = await prisma.sandbox.findMany({
        where: withCursor(
          { userId: input?.ownerId, sandboxHostId: input?.hostId, state: input?.state },
          "createdAt",
          input?.cursor,
          "desc",
        ),
        select: sandboxSelect,
        take: pageTake(limit),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      });
      const page = cursorPage(rows, limit, "createdAt");
      return { ...page, items: page.items.map(sandboxRow) };
    }),
  listOperations: adminOr404Procedure
    .input(
      filters
        .extend({
          sandboxId: filterId.optional(),
          state: z
            .enum([
              "QUEUED",
              "DISPATCHED",
              "ACCEPTED",
              "RUNNING",
              "CANCEL_REQUESTED",
              "SUCCEEDED",
              "FAILED",
              "CANCELLED",
              "UNKNOWN_OUTCOME",
            ])
            .optional(),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 20;
      const rows = await prisma.sandboxOperation.findMany({
        where: withCursor(
          { userId: input?.ownerId, sandboxId: input?.sandboxId, state: input?.state },
          "createdAt",
          input?.cursor,
          "desc",
        ),
        select: operationSelect,
        take: pageTake(limit),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      });
      const page = cursorPage(rows, limit, "createdAt");
      return { ...page, items: page.items.map(operationRow) };
    }),
};
