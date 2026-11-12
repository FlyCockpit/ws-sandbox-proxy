/**
 * DELETED safety on real PostgreSQL: the `sandbox_instance_deleted_offload` CHECK aborts a
 * DELETED writer that does not end the offload first; the owner destroy of
 * an OFFLOADED sandbox is server-completed through `endOffloadForDestroy`;
 * and the deferred shred runs only after its grace, only for the destroy
 * that ended the sandbox.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "deleted-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createSandbox, killSandbox } from "../services/sandboxes";
import { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } from "../testing/offload-fixtures";
import { poolFixture } from "../testing/pool-fixtures";
import { shredDestroyedOffloads } from "./destroy";

const db = await pgTestDatabase();
afterAll(() => db.close());

const ENV = {
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
  IMAGE_S3_BUCKET: "b",
  IMAGE_S3_ENDPOINT: "http://127.0.0.1:9",
  IMAGE_S3_ACCESS_KEY_ID: "a",
  IMAGE_S3_SECRET_ACCESS_KEY: "s",
};
const saved: Record<string, string | undefined> = {};
beforeAll(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

const HOUR = 3_600_000;

async function offloaded() {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonFeatures: { ...OFFLOAD_HOST_FEATURES }, daemonDiskOffload: true },
  });
  const created = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  const stored = await offloadSandboxForTest(db.inspect, {
    userId: f.id,
    sandboxId: created.id,
    hostId: f.host.id,
  });
  return { f, sandboxId: created.id, offloadId: stored.offloadId };
}

const destroy = (f: Awaited<ReturnType<typeof poolFixture>>, id: string) =>
  killSandbox(f.owner, { id, idempotencyKey: randomUUID() });

describe("DELETED safety (§8.9)", () => {
  it("the CHECK aborts a DELETED write that leaves the stored disk pointer", async () => {
    const { sandboxId, offloadId } = await offloaded();
    await expect(
      db.inspect.sandbox.update({ where: { id: sandboxId }, data: { state: "DELETED" } }),
    ).rejects.toThrow();
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({ state: "OFFLOADED", diskOffloadId: offloadId });
  });

  it("destroy of an OFFLOADED sandbox is server-completed through endOffloadForDestroy", async () => {
    const { f, sandboxId, offloadId } = await offloaded();
    const before = Date.now();
    const result = await destroy(f, sandboxId);
    expect(result).toMatchObject({ state: "DELETED" });
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({ state: "DELETED", diskOffloadId: null });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "KILL_SANDBOX" },
    });
    expect(kill).toMatchObject({ state: "SUCCEEDED", teardownIntent: "OWNER_DESTROY" });
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: offloadId },
    });
    expect(offload).toMatchObject({
      state: "DELETING",
      destroyOperationId: kill.id,
      liveSandboxId: null,
      shreddedAt: null,
    });
    // SANDBOX_OFFLOAD_SHRED_GRACE_HOURS defaults to 24.
    expect(offload.shredAfter!.getTime()).toBeGreaterThanOrEqual(before + 24 * HOUR - 60_000);
    expect(offload.wrappedKey).not.toBeNull();
    // Nothing was sent to any host.
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: sandboxId, eventType: "sandbox.kill_requested" },
      }),
    ).toBe(0);
    // Destroy stays idempotent.
    expect(await destroy(f, sandboxId)).toMatchObject({ state: "DELETED" });
  });

  it("the deferred shred runs only after the grace, for the destroy that ended the sandbox", async () => {
    const { f, sandboxId, offloadId } = await offloaded();
    await destroy(f, sandboxId);
    const now = new Date();
    await shredDestroyedOffloads(null, now);
    expect(
      (await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offloadId } }))
        .shreddedAt,
    ).toBeNull();
    const later = new Date(now.getTime() + 25 * HOUR);
    expect((await shredDestroyedOffloads(null, later)).shredded).toBeGreaterThanOrEqual(1);
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: offloadId },
    });
    expect(offload).toMatchObject({ state: "DELETED", wrappedKey: null });
    expect(offload.shreddedAt).not.toBeNull();
  });

  it("a destroy that is not the sandbox's terminal operation is refused and keeps the key", async () => {
    const { f, sandboxId, offloadId } = await offloaded();
    await destroy(f, sandboxId);
    // Mis-recorded: the offload names another operation as its destroy.
    const other = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "CREATE_SANDBOX" },
    });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: offloadId },
      data: { destroyOperationId: other.id },
    });
    const later = new Date(Date.now() + 25 * HOUR);
    expect((await shredDestroyedOffloads(null, later)).refused).toBeGreaterThanOrEqual(1);
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: offloadId },
    });
    expect(offload).toMatchObject({ state: "DELETING", shreddedAt: null });
    expect(offload.wrappedKey).not.toBeNull();
  });
});
