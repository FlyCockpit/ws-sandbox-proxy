import { seedAcceptedOperation } from "../sandbox/testing/resource-fixtures";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import type { Context } from "../context";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({
  reapExpiredAuthTokensQueue: {},
  checkBackupFreshnessQueue: {},
  notifyDataDeletionsQueue: {},
}));
const db = await pgTestDatabase();
const { adminObservabilityRouter } = await import("./admin-observability");
afterAll(() => db.close());

it("pages tied metadata across owners with exact filters and no stored secrets", async () => {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Admin",
      role: "admin",
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: `test-${id}`, expiresAt: new Date(Date.now() + 60_000) },
  });
  const client = createRouterClient(adminObservabilityRouter, {
    context: { session: { user, session } } as Context,
  });
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: { id: ownerId, email: `${ownerId}@example.test`, name: "Owner" },
  });
  const when = new Date("2026-01-01T00:00:00Z");
  const hosts = [];
  for (const [userId, status] of [
    [ownerId, "CONNECTED"],
    [ownerId, "CONNECTED"],
    [ownerId, "DISCONNECTED"],
    [id, "CONNECTED"],
  ] as const) {
    hosts.push(
      await seedLaunchHost(db.inspect, {
        data: {
          userId,
          status,
          slug: randomUUID(),
          label: "private-label",
          inventoryDigest: "private-inventory",
          memoryReservedMiB: 3072,
          daemonMemoryBudgetMiB: 2048,
          daemonMaxCpuCount: 4,
          createdAt: when,
        },
      }),
    );
  }
  const first = await client.listHosts({ ownerId, status: "CONNECTED", limit: 1 });
  expect(first.items).toHaveLength(1);
  expect(first.items[0]).toMatchObject({
    memoryReservedMiB: 3072,
    daemonMemoryBudgetMiB: 2048,
    daemonMaxCpuCount: 4,
  });
  expect(Object.keys(first.items[0]!).sort()).toEqual(
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
    ].sort(),
  );
  expect(first.nextCursor).not.toBeNull();
  await db.inspect.sandboxHost.delete({ where: { id: first.items[0]!.id } });
  const second = await client.listHosts({
    ownerId,
    status: "CONNECTED",
    limit: 1,
    cursor: first.nextCursor!,
  });
  expect(second.items).toHaveLength(1);
  expect(second.nextCursor).toBeNull();
  expect(new Set([...first.items, ...second.items].map((row) => row.id))).toEqual(
    new Set(hosts.slice(0, 2).map((row) => row.id)),
  );
  expect(JSON.stringify([first, second])).not.toContain("private-");
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      slug: "base",
      label: "private-template",
      imageRef: "private-image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
      retiredAt: new Date(),
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      diskGiB: 32,
      userId: ownerId,
      templateId: template.id,
      originHostId: "gone",
      metadata: { secret: "private-metadata" },
      lastErrorDetail: "private-error",
      cpuCount: 2,
      memoryMiB: 2048,
    },
  });
  await seedAcceptedOperation(db.inspect, {
    data: {
      userId: ownerId,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: "private-key",
      requestBodyHash: "private-hash",
      result: { script: "private-command" },
    },
  });
  const sandboxes = await client.listSandboxes({ ownerId });
  expect(sandboxes.items[0]).toMatchObject({ cpuCount: 2, memoryMiB: 2048 });
  expect(Object.keys(sandboxes.items[0]!).sort()).toEqual(
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
    ].sort(),
  );
  expect(JSON.stringify(sandboxes)).not.toContain("private-");
  const operations = await client.listOperations({ ownerId, sandboxId: sandbox.id });
  expect(operations.items).toHaveLength(1);
  expect(JSON.stringify(operations)).not.toContain("private-");
});

it("rejects expired, impersonated and revoked sessions against durable session rows", async () => {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Admin",
      role: "admin",
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: `test-${id}`, expiresAt: new Date(Date.now() + 60_000) },
  });
  const client = createRouterClient(adminObservabilityRouter, {
    context: { session: { user, session } } as Context,
  });
  await expect(client.listOperations()).resolves.toHaveProperty("items");
  await db.inspect.session.update({ where: { id: session.id }, data: { expiresAt: new Date(0) } });
  await expect(client.listOperations()).rejects.toMatchObject({ code: "NOT_FOUND" });
  await db.inspect.session.update({
    where: { id: session.id },
    data: { expiresAt: new Date(Date.now() + 60_000), impersonatedBy: id },
  });
  await expect(client.listOperations()).rejects.toMatchObject({ code: "NOT_FOUND" });
  await db.inspect.session.delete({ where: { id: session.id } });
  await expect(client.listOperations()).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("non-admins receive 404 for every observability endpoint", async () => {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Owner",
      role: "user",
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 60_000) },
  });
  const client = createRouterClient(adminObservabilityRouter, {
    context: { session: { user, session } } as Context,
  });
  for (const read of [
    () => client.counters(),
    () => client.listHosts(),
    () => client.listSandboxes(),
    () => client.listOperations(),
  ]) {
    await expect(read()).rejects.toMatchObject({ code: "NOT_FOUND" });
  }
});
