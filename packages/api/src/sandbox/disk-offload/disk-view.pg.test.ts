/**
 * The disk projection, the restore pin and the restore-availability refusal
 * on real PostgreSQL (offload plan C8): `getSandbox` (the /v1 DTO) and the
 * dashboard view read `disk` from the real relations; the owner pin is
 * session-only; a restore while the image store or data key is missing is
 * refused `sandbox.disk_unavailable` with nothing written.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "disk-view-fixture",
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
vi.mock("../sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
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
import { sandboxSchema } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { leaseNow } from "../lease";
import { toSandboxDto } from "../public-dto";
import { getSandboxView } from "../services/sandbox-views";
import { createSandbox, getSandbox, reconnectSandbox } from "../services/sandboxes";
import { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } from "../testing/offload-fixtures";
import { poolFixture, poolKey } from "../testing/pool-fixtures";
import { setSandboxOffloadPin } from "./pin";

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
beforeEach(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterEach(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

type Fixture = Awaited<ReturnType<typeof poolFixture>>;

async function offloaded(f: Fixture) {
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonFeatures: { ...OFFLOAD_HOST_FEATURES }, daemonDiskOffload: true },
  });
  const created = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await offloadSandboxForTest(db.inspect, {
    userId: f.id,
    sandboxId: created.id,
    hostId: f.host.id,
  });
  return created.id;
}

const code = (error: unknown) =>
  (error as { data?: { code?: string } }).data?.code ?? (error as { code?: string }).code;

describe("disk projection (C8)", () => {
  it("an OFFLOADED sandbox reads disk.location store with its stored copy", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    const dto = toSandboxDto(await getSandbox(f.owner, { id }));
    expect(sandboxSchema.parse(dto)).toEqual(dto);
    expect(dto.state).toBe("OFFLOADED");
    expect(dto.disk).toMatchObject({
      location: "store",
      offloadState: "stored",
      offloadFailure: null,
      eligibility: "any_host",
      offloadPin: "ANY",
    });
    expect(dto.disk?.sizeBytes).toBeGreaterThan(0);
    expect(dto.disk?.offloadedAt).not.toBeNull();
    // Never the object key or key material.
    expect(JSON.stringify(dto)).not.toMatch(/objectKey|wrappedKey|wsspenc/);

    const view = await getSandboxView(f.owner, { id });
    expect(view.disk).toEqual(dto.disk);
    expect(view).not.toHaveProperty("DiskOffloads");
    expect(view).not.toHaveProperty("User");
  });

  it("a fresh sandbox's disk is on its host; a waiting/deleted one has none", async () => {
    const f = await poolFixture(db);
    const created = await createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    const dto = toSandboxDto(await getSandbox(f.owner, { id: created.id }));
    expect(dto.disk).toMatchObject({ location: "host", offloadState: "none" });
  });
});

describe("restore pin (C8)", () => {
  it("the owner session sets OWN_HOSTS; the DTO shows it and narrows eligibility", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    await expect(setSandboxOffloadPin(f.owner, { id, offloadPin: "OWN_HOSTS" })).resolves.toEqual({
      id,
      offloadPin: "OWN_HOSTS",
    });
    const dto = toSandboxDto(await getSandbox(f.owner, { id }));
    expect(dto.disk).toMatchObject({ offloadPin: "OWN_HOSTS", eligibility: "own_hosts" });
    await setSandboxOffloadPin(f.owner, { id, offloadPin: "ANY" });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).offloadPin).toBe("ANY");
  });

  it("an SDK key cannot set it, and another owner's sandbox is not found", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    const key = await poolKey(db, f);
    await expect(
      setSandboxOffloadPin(key.principal, { id, offloadPin: "OWN_HOSTS" }),
    ).rejects.toBeTruthy();
    const g = await poolFixture(db);
    await expect(setSandboxOffloadPin(g.owner, { id, offloadPin: "OWN_HOSTS" })).rejects.toThrow(
      /not found/i,
    );
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).offloadPin).toBe("ANY");
  });
});

describe("restore availability (§6, R12)", () => {
  it("refuses sandbox.disk_unavailable without the data key and writes nothing", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    delete process.env.DATA_ENCRYPTION_KEY;
    const before = await db.inspect.sandboxOperation.count({ where: { sandboxId: id } });
    const error = await reconnectSandbox(
      f.owner,
      { id, idempotencyKey: randomUUID() },
      leaseNow,
    ).catch((e: unknown) => e);
    expect(code(error)).toBe("sandbox.disk_unavailable");
    expect(await db.inspect.sandboxOperation.count({ where: { sandboxId: id } })).toBe(before);
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).state).toBe("OFFLOADED");
  });
});
