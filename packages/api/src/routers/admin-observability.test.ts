vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import type { MockPrisma } from "../test/mock-prisma";

vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({
  reapExpiredAuthTokensQueue: {
    name: "reap-expired-auth-tokens",
    getJobCounts: vi.fn(async () => ({ wait: 2, active: 1, data: "secret" })),
  },
  imageStoreMaintenanceQueue: {
    add: vi.fn(),
    upsertJobScheduler: vi.fn(),
    removeJobScheduler: vi.fn(),
  },
  checkBackupFreshnessQueue: {
    name: "check-backup-freshness",
    getJobCounts: vi.fn(async () => ({})),
  },
  webhookDeliveryQueue: {
    name: "webhook-delivery",
    getJobCounts: vi.fn(async () => ({ wait: 1, delayed: 4 })),
  },
  notifyDataDeletionsQueue: {
    name: "notify-data-deletions",
    getJobCounts: vi.fn(async () => ({})),
  },
  reapWebhookLogQueue: {
    name: "reap-webhook-log",
    getJobCounts: vi.fn(async () => ({})),
  },
}));
const { default: prisma } = await import("@wssp/db");
const db = prisma as MockPrisma;
const { adminObservabilityRouter } = await import("./admin-observability");
const context = { session: { user: { id: "admin" }, session: { id: "session" } } } as Context;
const client = createRouterClient(adminObservabilityRouter, { context });
beforeEach(() => {
  vi.clearAllMocks();
});

it("bounds every metadata filter before database IO", async () => {
  for (const list of [client.listHosts, client.listSandboxes, client.listOperations]) {
    await expect(list({ limit: 101 })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(list({ limit: 0 })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(list({ ownerId: "a".repeat(65) })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(list({ cursor: "bad cursor" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
  }
  expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
  expect(db.sandbox.findMany).not.toHaveBeenCalled();
  expect(db.sandboxOperation.findMany).not.toHaveBeenCalled();
});

it("uses exhaustive metadata-only selects with bounded keyset queries", async () => {
  db.sandboxHost.findMany.mockResolvedValue([]);
  db.sandbox.findMany.mockResolvedValue([]);
  db.sandboxOperation.findMany.mockResolvedValue([]);
  await expect(
    client.listHosts({ ownerId: "owner", status: "CONNECTED", limit: 2 }),
  ).resolves.toEqual({ items: [], nextCursor: null });
  await client.listSandboxes({ ownerId: "owner", hostId: "host", state: "READY", limit: 2 });
  await client.listOperations({
    root: null,
    ownerId: "owner",
    sandboxId: "sandbox",
    state: "RUNNING",
    limit: 2,
  });
  const allowed = [
    [
      "id",
      "userId",
      "createdAt",
      "status",
      "lastHeartbeatAt",
      "draining",
      "daemonVcpuBudget",
      "vcpuReserved",
      "rootCount",
      "liveCount",
      "memoryReservedMiB",
      "daemonMemoryBudgetMiB",
      "daemonMaxCpuCount",
      "quarantinedAt",
      "label",
      "User",
    ],
    [
      "id",
      "userId",
      "createdAt",
      "sandboxHostId",
      "templateId",
      "templateRevisionId",
      "originPoolId",
      "state",
      "generation",
      "cpuCount",
      "memoryMiB",
      "diskGiB",
      "guestSudo",
      "guestSudoReason",
      "guestRoot",
      "name",
      "SandboxHost",
      "SandboxTemplateRevision",
      "User",
    ],
    [
      "id",
      "userId",
      "createdAt",
      "sandboxId",
      "kind",
      "state",
      "generation",
      "updatedAt",
      "Sandbox",
      "User",
    ],
  ];
  for (const [index, delegate] of [db.sandboxHost, db.sandbox, db.sandboxOperation].entries()) {
    const query = delegate.findMany.mock.calls[0]?.[0];
    expect(Object.keys(query?.select ?? {}).sort()).toEqual(allowed[index]?.sort());
    // The owner joins in by account name and email only.
    expect(query?.select?.User).toEqual({ select: { name: true, email: true } });
    expect(query?.take).toBe(3);
    expect(query?.orderBy).toEqual([{ createdAt: "desc" }, { id: "desc" }]);
    expect(query?.where).toMatchObject({ AND: [{ userId: "owner" }] });
  }
  // The other joins carry one label each, nothing else of the related row.
  const sandboxSelect = db.sandbox.findMany.mock.calls[0]?.[0]?.select;
  expect(sandboxSelect?.SandboxHost).toEqual({ select: { label: true } });
  expect(sandboxSelect?.SandboxTemplateRevision).toEqual({
    select: { Template: { select: { label: true } } },
  });
  expect(db.sandboxOperation.findMany.mock.calls[0]?.[0]?.select?.Sandbox).toEqual({
    select: { name: true },
  });
});

it("returns fixed counters without queue payloads or arbitrary count keys", async () => {
  db.user.count.mockResolvedValue(3);
  db.sandboxHost.count.mockImplementation((async (args?: { where?: unknown }) =>
    args?.where ? 1 : 2) as never);
  db.sandbox.count.mockImplementation((async (args?: { where?: { state?: unknown } }) =>
    args?.where ? (args.where.state === "READY" ? 4 : 5) : 1) as never);
  db.sandboxOperation.count.mockImplementation((async (args?: { where?: unknown }) =>
    args?.where ? 6 : 0) as never);
  db.outboxEvent.count.mockResolvedValue(7);
  db.webhookEndpoint.count.mockImplementation((async (args?: { where?: unknown }) =>
    args?.where ? 1 : 3) as never);
  db.webhookDelivery.groupBy.mockResolvedValue([
    { state: "PENDING", _count: { _all: 2 } },
    { state: "FAILED", _count: { _all: 1 } },
  ] as never);
  db.webhookDelivery.findFirst.mockResolvedValue({
    createdAt: new Date(Date.now() - 90_000),
  } as never);
  db.webhookDeliveryAttempt.groupBy.mockResolvedValue([
    { errorClass: "timeout", _count: { _all: 5 } },
  ] as never);
  expect(await client.counters()).toEqual({
    users: 3,
    hosts: 2,
    sandboxes: 1,
    operations: 0,
    leases: {
      expiredPending: 4,
      unacknowledgedRenewals: 6,
      hostEnforced: 5,
      quarantinedHosts: 1,
      relayOutbox: 7,
    },
    queues: [
      {
        queue: "reap-expired-auth-tokens",
        waiting: 2,
        active: 1,
        delayed: 0,
        failed: 0,
        completed: 0,
      },
      {
        queue: "check-backup-freshness",
        waiting: 0,
        active: 0,
        delayed: 0,
        failed: 0,
        completed: 0,
      },
      { queue: "webhook-delivery", waiting: 1, active: 0, delayed: 4, failed: 0, completed: 0 },
      { queue: "reap-webhook-log", waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 },
      {
        queue: "notify-data-deletions",
        waiting: 0,
        active: 0,
        delayed: 0,
        failed: 0,
        completed: 0,
      },
    ],
    webhooks: {
      endpoints: 3,
      enabled: 1,
      disabledForFailures: 1,
      deliveries24h: { PENDING: 2, IN_FLIGHT: 0, SUCCEEDED: 0, FAILED: 1, CANCELLED: 0 },
      oldestPendingAgeSeconds: expect.any(Number),
      errorClasses24h: [{ errorClass: "timeout", count: 5 }],
    },
  });
});

it("lists webhook endpoints as metadata only: URL host, never path, query or secrets", async () => {
  db.webhookEndpoint.findMany.mockResolvedValue([
    {
      id: "whe-1",
      userId: "owner",
      createdAt: new Date("2026-11-02T00:00:00.000Z"),
      url: "https://hooks.example.com/private/path?token=SECRET",
      disabledAt: null,
      disabledReason: null,
      consecutiveFailures: 2,
      failingSince: null,
      lastSuccessAt: null,
      User: { name: "Ada", email: "ada@example.test" },
    },
  ] as never);
  const page = await client.listWebhookEndpoints({ limit: 5 });
  expect(page.items).toEqual([
    {
      id: "whe-1",
      ownerId: "owner",
      owner: { name: "Ada", email: "ada@example.test" },
      createdAt: new Date("2026-11-02T00:00:00.000Z"),
      host: "hooks.example.com",
      state: "enabled",
      consecutiveFailures: 2,
      failingSince: null,
      lastSuccessAt: null,
    },
  ]);
  expect(JSON.stringify(page)).not.toMatch(/SECRET|private|token/);
  const select = db.webhookEndpoint.findMany.mock.calls[0]?.[0]?.select ?? {};
  expect(Object.keys(select)).not.toEqual(expect.arrayContaining(["secretCiphertext"]));
  for (const forbidden of ["secretCiphertext", "previousSecretCiphertext", "description", "events"])
    expect(select).not.toHaveProperty(forbidden);
});

it("rechecks administrator authority before returning assembled metadata", async () => {
  db.sandboxHost.findMany.mockImplementationOnce(async () => {
    db.user.findUnique.mockResolvedValueOnce(null);
    return [];
  });
  await expect(client.listHosts()).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("returns 404 for a non-admin before reading observability data", async () => {
  db.user.findUnique.mockResolvedValueOnce({ id: "admin", role: "user" } as never);
  await expect(client.listHosts()).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
});

it("returns the owner's name and email beside each id, and never the relation itself", async () => {
  const createdAt = new Date("2026-11-02T00:00:00.000Z");
  const owner = { name: "Ada", email: "ada@example.test" };
  db.sandboxHost.findMany.mockResolvedValue([
    { id: "host-1", userId: "owner", createdAt, status: "CONNECTED", User: owner },
  ] as never);
  db.sandbox.findMany.mockResolvedValue([
    {
      id: "sbx-1",
      userId: "owner",
      createdAt,
      state: "READY",
      name: "quiet-otter",
      SandboxHost: { label: "rack-2" },
      SandboxTemplateRevision: { Template: { label: "Ubuntu 24.04" } },
      User: owner,
    },
  ] as never);
  db.sandboxOperation.findMany.mockResolvedValue([
    {
      id: "op-1",
      userId: "owner",
      createdAt,
      state: "RUNNING",
      Sandbox: { name: "quiet-otter" },
      User: owner,
    },
  ] as never);
  for (const list of [client.listHosts, client.listSandboxes, client.listOperations]) {
    const page = await list({ limit: 5 });
    expect(page.items[0]).toMatchObject({ userId: "owner", owner });
    for (const relation of ["User", "SandboxHost", "SandboxTemplateRevision", "Sandbox"])
      expect(page.items[0]).not.toHaveProperty(relation);
  }
  expect((await client.listSandboxes({ limit: 5 })).items[0]).toMatchObject({
    name: "quiet-otter",
    hostLabel: "rack-2",
    templateLabel: "Ubuntu 24.04",
  });
  expect((await client.listOperations({ limit: 5 })).items[0]).toMatchObject({
    sandboxName: "quiet-otter",
  });
});

it("shows no host label for a sandbox without a host", async () => {
  db.sandbox.findMany.mockResolvedValue([
    {
      id: "sbx-2",
      userId: "owner",
      createdAt: new Date("2026-11-02T00:00:00.000Z"),
      state: "WAITING_FOR_CAPACITY",
      name: "patient-heron",
      SandboxHost: null,
      SandboxTemplateRevision: { Template: { label: "Base" } },
      User: { name: "Ada", email: "ada@example.test" },
    },
  ] as never);
  expect((await client.listSandboxes({ limit: 5 })).items[0]).toMatchObject({
    name: "patient-heron",
    hostLabel: null,
    templateLabel: "Base",
  });
});
