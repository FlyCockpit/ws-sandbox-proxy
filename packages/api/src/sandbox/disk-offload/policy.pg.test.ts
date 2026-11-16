import { randomBytes } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: {},
  ensureRunnableJob: vi.fn(),
}));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("../budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

/**
 * The per-sandbox offload policy against real PostgreSQL: the candidate
 * query and the enqueue recheck honour ON_STOP / AFTER / ON_PRESSURE, the
 * host-pressure legs override every policy, the stopped-at trigger stamps
 * the AFTER clock, and the CHECK keeps the columns consistent.
 */
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

const { seedOwner } = await import("../../webhooks/testing/fixtures");
const { seedStoppedOnHost } = await import("../testing/offload-fixtures");
const { enqueueOffload, offloadCandidates } = await import("./enqueue");
const { seedLaunchHost, seedSandboxInstance, seedTemplateRevision } = await import(
  "../testing/resource-fixtures"
);
const { stopSandboxInput, updateSandboxInput } = await import("../contracts");
const { stopSandbox, updateSandbox } = await import("../services/sandboxes");

const HOUR = 3_600_000;

async function world(sandbox: Record<string, unknown> = {}) {
  const owner = await seedOwner(db.inspect);
  const seeded = await seedStoppedOnHost(db.inspect, { userId: owner, sandbox });
  return { owner, ...seeded };
}

const isCandidate = async (sandboxId: string, now = new Date()) =>
  (await offloadCandidates(now)).some((c) => c.sandboxId === sandboxId);

function candidateOf(w: Awaited<ReturnType<typeof world>>) {
  return {
    sandboxId: w.sandbox.id,
    userId: w.owner,
    generation: w.sandbox.generation,
    hostId: w.host.id,
    hostOwnerId: w.owner,
    epoch: w.host.connectionEpoch,
  };
}

describe("offload policy in the candidate query and the enqueue recheck", () => {
  it("ON_STOP (the default) is a candidate at once", async () => {
    const w = await world();
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } })).offloadMode,
    ).toBe("ON_STOP");
    expect(await isCandidate(w.sandbox.id)).toBe(true);
  });

  it("ON_PRESSURE is never a candidate by itself, and enqueue refuses it", async () => {
    const w = await world({ offloadMode: "ON_PRESSURE", lastStoppedAt: new Date(0) });
    expect(await isCandidate(w.sandbox.id, new Date(Date.now() + 30 * 24 * HOUR))).toBe(false);
    expect(await enqueueOffload(candidateOf(w))).toBeNull();
    expect(await db.inspect.sandboxDiskOffload.count({ where: { sandboxId: w.sandbox.id } })).toBe(
      0,
    );
  });

  it("AFTER waits for lastStoppedAt + offloadAfterMs, then enqueues", async () => {
    const stoppedAt = new Date();
    const w = await world({
      offloadMode: "AFTER",
      offloadAfterMs: 2 * HOUR,
      lastStoppedAt: stoppedAt,
    });
    const early = new Date(stoppedAt.getTime() + 2 * HOUR - 1000);
    const due = new Date(stoppedAt.getTime() + 2 * HOUR + 1000);
    expect(await isCandidate(w.sandbox.id, early)).toBe(false);
    expect(await enqueueOffload(candidateOf(w), early)).toBeNull();
    expect(await isCandidate(w.sandbox.id, due)).toBe(true);
    expect(await enqueueOffload(candidateOf(w), due)).toMatchObject({ sandboxId: w.sandbox.id });
  });

  it("the recheck under the sandbox lock sees a policy changed after the candidate read", async () => {
    const w = await world();
    const [candidate] = (await offloadCandidates()).filter((c) => c.sandboxId === w.sandbox.id);
    expect(candidate).toBeDefined();
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { offloadMode: "ON_PRESSURE" },
    });
    expect(await enqueueOffload(candidate!)).toBeNull();
  });

  it("host pressure overrides AFTER and ON_PRESSURE: a storage pool at least 90% full", async () => {
    const w = await world({ offloadMode: "ON_PRESSURE" });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } });
    expect(sandbox.storagePoolId).not.toBeNull();
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: w.host.id } });
    const pool = (used: bigint, epoch = host.connectionEpoch) =>
      db.inspect.sandboxHostStoragePool.update({
        where: { id: sandbox.storagePoolId! },
        data: {
          totalBytes: 1000n,
          usedBytes: used,
          freeBytes: 1000n - used,
          connectionEpoch: epoch,
        },
      });
    await pool(899n);
    expect(await isCandidate(w.sandbox.id)).toBe(false);
    await pool(900n);
    expect(await isCandidate(w.sandbox.id)).toBe(true);
    // A report from an older connection is not current evidence.
    const epoch = host.connectionEpoch + 1;
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: {
        connectionEpoch: epoch,
        admissionEpoch: epoch,
        inventoryAcknowledgedEpoch: epoch,
      },
    });
    expect(await isCandidate(w.sandbox.id)).toBe(false);
    await pool(990n, epoch);
    expect(await enqueueOffload({ ...candidateOf(w), epoch })).toMatchObject({
      sandboxId: w.sandbox.id,
    });
  });

  it("host pressure overrides every policy: a drain with --offload", async () => {
    const w = await world({
      offloadMode: "AFTER",
      offloadAfterMs: 24 * HOUR,
      lastStoppedAt: new Date(),
    });
    expect(await isCandidate(w.sandbox.id)).toBe(false);
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { draining: true } });
    // Draining alone moves nothing.
    expect(await isCandidate(w.sandbox.id)).toBe(false);
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { drainOffload: true } });
    expect(await isCandidate(w.sandbox.id)).toBe(true);
    expect(await enqueueOffload(candidateOf(w))).toMatchObject({ sandboxId: w.sandbox.id });
  });
});

describe("stopped-at trigger and policy CHECK", () => {
  it("every entry into STOPPED stamps lastStoppedAt; staying STOPPED keeps it", async () => {
    const w = await world({ state: "READY", lastStoppedAt: null });
    const read = async () =>
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } })).lastStoppedAt;
    expect(await read()).toBeNull();
    const before = Date.now();
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "STOPPING" } });
    expect(await read()).toBeNull();
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "STOPPED" } });
    const first = await read();
    expect(first).not.toBeNull();
    expect(first!.getTime()).toBeGreaterThanOrEqual(before - 5_000);
    expect(first!.getTime()).toBeLessThanOrEqual(Date.now() + 5_000);
    // An update that leaves the state STOPPED never restarts the clock.
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { state: "STOPPED", offloadMode: "ON_PRESSURE" },
    });
    expect((await read())?.getTime()).toBe(first!.getTime());
  });

  it("the CHECK refuses AFTER without a delay, a delay without AFTER and out-of-range delays", async () => {
    const w = await world();
    const set = (data: { offloadMode: "AFTER" | "ON_STOP"; offloadAfterMs: number | null }) =>
      db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data });
    for (const bad of [
      { offloadMode: "AFTER" as const, offloadAfterMs: null },
      { offloadMode: "ON_STOP" as const, offloadAfterMs: 60_000 },
      { offloadMode: "AFTER" as const, offloadAfterMs: 59_999 },
      { offloadMode: "AFTER" as const, offloadAfterMs: 2_073_600_001 },
    ])
      await expect(set(bad)).rejects.toThrow(/sandbox_instance_offload_policy/);
    await expect(set({ offloadMode: "AFTER", offloadAfterMs: 60_000 })).resolves.toBeDefined();
    await expect(
      set({ offloadMode: "AFTER", offloadAfterMs: 2_073_600_000 }),
    ).resolves.toBeDefined();
  });
});

describe("setting the policy: stop body and update", () => {
  async function ready(purpose: "WORKLOAD" | "TEMPLATE_BUILD" = "WORKLOAD") {
    const ownerId = await seedOwner(db.inspect);
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: ownerId,
        slug: `h-${randomBytes(4).toString("hex")}`,
        label: "Lab",
        status: "CONNECTED",
        connectionEpoch: 1,
        egressEnforcement: true,
      },
    });
    const template = await seedTemplateRevision(db.inspect, {
      data: {
        userId: ownerId,
        sandboxHostId: host.id,
        slug: `t-${randomBytes(4).toString("hex")}`,
        label: "Base",
        imageRef: "images:ubuntu/24.04/cloud",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
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
        ...(purpose === "TEMPLATE_BUILD"
          ? { purpose, buildId: randomBytes(8).toString("hex") }
          : {}),
      },
    });
    return { owner: { kind: "session" as const, ownerId }, sandboxId: sandbox.id };
  }
  const policyOf = async (id: string) =>
    db.inspect.sandbox.findUniqueOrThrow({
      where: { id },
      select: { offloadMode: true, offloadAfterMs: true, state: true },
    });

  it("a stop's offload lands with the accepted stop; a replay never applies it again", async () => {
    const r = await ready();
    const input = stopSandboxInput.parse({
      id: r.sandboxId,
      idempotencyKey: "park-1",
      offload: { mode: "after", afterMs: 2 * HOUR },
    });
    const first = await stopSandbox(r.owner, input);
    expect(await policyOf(r.sandboxId)).toEqual({
      offloadMode: "AFTER",
      offloadAfterMs: 2 * HOUR,
      state: "STOPPING",
    });
    // A later change survives a replay of the same stop.
    await updateSandbox(
      r.owner,
      updateSandboxInput.parse({ id: r.sandboxId, offload: { mode: "on_stop" } }),
    );
    const replay = await stopSandbox(r.owner, input);
    expect(replay).toEqual(first);
    expect(await policyOf(r.sandboxId)).toMatchObject({ offloadMode: "ON_STOP" });
    // The policy is part of the stop's intent: another policy under the key conflicts.
    await expect(
      stopSandbox(
        r.owner,
        stopSandboxInput.parse({
          id: r.sandboxId,
          idempotencyKey: "park-1",
          offload: { mode: "on_pressure" },
        }),
      ),
    ).rejects.toThrow(/Idempotency key was used/);
  });

  it("update sets the policy alone (no name), and keeps the name", async () => {
    const r = await ready();
    const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: r.sandboxId } });
    await updateSandbox(
      r.owner,
      updateSandboxInput.parse({ id: r.sandboxId, offload: { mode: "on_pressure" } }),
    );
    const after = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: r.sandboxId } });
    expect(after).toMatchObject({ offloadMode: "ON_PRESSURE", offloadAfterMs: null });
    expect(after.name).toBe(before.name);
    expect(updateSandboxInput.safeParse({ id: r.sandboxId }).success).toBe(false);
  });

  it("managed sandboxes refuse a policy", async () => {
    const r = await ready("TEMPLATE_BUILD");
    await expect(
      updateSandbox(
        r.owner,
        updateSandboxInput.parse({ id: r.sandboxId, offload: { mode: "on_pressure" } }),
      ),
    ).rejects.toBeDefined();
    await expect(
      stopSandbox(
        r.owner,
        stopSandboxInput.parse({
          id: r.sandboxId,
          idempotencyKey: "build-stop",
          offload: { mode: "on_pressure" },
        }),
      ),
    ).rejects.toBeDefined();
    expect(await policyOf(r.sandboxId)).toMatchObject({ offloadMode: "ON_STOP" });
  });
});
