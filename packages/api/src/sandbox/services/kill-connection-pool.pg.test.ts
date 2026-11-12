import { seedLaunchHost } from "../testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedSandboxInstance, seedTemplateRevision } from "../testing/resource-fixtures";

const db = await pgTestDatabase();
// A pool of one connection: any read escaping killSandbox's transaction would
// wait for the very connection that transaction holds — a deadlock. Completing
// at all proves every read joined the transaction (C24).
const single = vi.hoisted(() => ({
  client: undefined as undefined | { $disconnect(): Promise<void> },
}));
vi.mock("@wssp/db", async () => {
  const { createPrismaClient } = await import("@wssp/db/client");
  const client = createPrismaClient({ connectionString: db.url, max: 1 });
  single.client = client;
  return { default: client };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "kill-pool-pg-test-secret",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { killSandbox } = await import("./sandboxes");

afterAll(async () => {
  await single.client?.$disconnect();
  await db.close();
});

const FP = `sha256:${"a".repeat(64)}`;

it("C24 killSandbox completes on a single-connection pool (no read escapes the transaction)", async () => {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: ownerId, slug: "lab", label: "Lab", status: "CONNECTED", connectionEpoch: 1 },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
    },
  });
  await killSandbox(
    { kind: "session", ownerId },
    { id: sandbox.id, idempotencyKey: `kill-${randomUUID()}` },
  );
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
  });
  expect(operation.state).toBe("QUEUED");
  expect(
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).state,
  ).not.toBe("READY");
}, 30_000);
