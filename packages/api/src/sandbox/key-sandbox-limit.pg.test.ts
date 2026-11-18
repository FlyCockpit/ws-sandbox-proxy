vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "key-sandbox-limit-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

/**
 * `SdkKey.maxLiveSandboxes` under real PostgreSQL: the count runs under the
 * owner placement lock (31) that `resolvePlacement` takes on the direct and the
 * pool path, so concurrent creates of one key at its limit serialize and
 * exactly one wins; a replay resolves before the check; waiting creates count;
 * a destroy frees a slot; other keys and sessions are unaffected.
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { countKeyLiveSandboxes } from "./key-sandbox-limit";
import { createSandbox, killSandbox } from "./services/sandboxes";
import { allOwnedPoolKey, poolFixture } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const LOCK_31 = /pg_advisory_xact_lock\(hashtextextended\(\?, 31\)\)/;
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );

async function limitedKey(f: Fixture, maxLiveSandboxes: number) {
  const key = await allOwnedPoolKey(f);
  await db.inspect.sdkKey.update({ where: { id: key.key.id }, data: { maxLiveSandboxes } });
  return key;
}
function limitReached(maxLiveSandboxes: number, liveSandboxes: number) {
  return {
    code: "CONFLICT",
    data: { code: "sandbox.key_limit_reached", maxLiveSandboxes, liveSandboxes },
  };
}
const pooled = (f: Fixture, extra: Record<string, unknown> = {}) => ({
  ...f.input,
  idempotencyKey: randomUUID(),
  ...extra,
});

describe("key live-sandbox limit", () => {
  it("two concurrent pool creates of one key at limit 1: exactly one wins", async () => {
    const f = await poolFixture(db);
    const key = await limitedKey(f, 1);
    const gate = db.pauseAt("first", { after: LOCK_31 });
    const first = settle(db.run("first", () => createSandbox(key.principal, pooled(f))));
    await gate.waitReached();
    const second = settle(db.run("second", () => createSandbox(key.principal, pooled(f))));
    // The second create waits for the first's placement lock before counting.
    await db.waitUntilBlocked("second", { by: "first" });
    gate.release();
    const [a, b] = [await first, await second];
    expect(a.error).toBeUndefined();
    expect(b.error).toMatchObject(limitReached(1, 1));
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
    expect(await countKeyLiveSandboxes(db.inspect, f.id, key.key.id)).toBe(1);
  });

  it("the direct path is limited too, and an idempotent replay at the limit still succeeds", async () => {
    const f = await poolFixture(db);
    const key = await limitedKey(f, 1);
    const input = { template: "base", sandboxHostId: f.host.id, idempotencyKey: randomUUID() };
    const created = await createSandbox(key.principal, input);
    await expect(
      createSandbox(key.principal, { ...input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject(limitReached(1, 1));
    await expect(createSandbox(key.principal, input)).resolves.toMatchObject({ id: created.id });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
  });

  it("a waiting-for-capacity create counts, and destroying it frees the slot", async () => {
    const f = await poolFixture(db);
    const key = await limitedKey(f, 1);
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [f.host.id, f.other.id] } },
      data: { memoryReservedMiB: 65536 },
    });
    const waiting = await createSandbox(key.principal, pooled(f, { waitForCapacityMs: 3_600_000 }));
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } })).state).toBe(
      "WAITING_FOR_CAPACITY",
    );
    await expect(
      createSandbox(key.principal, pooled(f, { waitForCapacityMs: 3_600_000 })),
    ).rejects.toMatchObject(limitReached(1, 1));
    await killSandbox(key.principal, { id: waiting.id, idempotencyKey: randomUUID() });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } })).state).toBe(
      "DELETED",
    );
    expect(await countKeyLiveSandboxes(db.inspect, f.id, key.key.id)).toBe(0);
    await expect(
      createSandbox(key.principal, pooled(f, { waitForCapacityMs: 3_600_000 })),
    ).resolves.toBeDefined();
  });

  it("a sandbox on a lost host (HOST_LOST) frees its slot", async () => {
    const f = await poolFixture(db);
    const key = await limitedKey(f, 1);
    const input = { template: "base", sandboxHostId: f.host.id, idempotencyKey: randomUUID() };
    const created = await createSandbox(key.principal, input);
    await expect(
      createSandbox(key.principal, { ...input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject(limitReached(1, 1));
    // HOST_LOST only ever leads to RECLAIMING or DELETED.
    await db.inspect.sandbox.update({ where: { id: created.id }, data: { state: "HOST_LOST" } });
    expect(await countKeyLiveSandboxes(db.inspect, f.id, key.key.id)).toBe(0);
    await expect(
      createSandbox(key.principal, { ...input, idempotencyKey: randomUUID() }),
    ).resolves.toBeDefined();
  });

  it("other keys and browser sessions of the owner are unaffected by one key's limit", async () => {
    const f = await poolFixture(db);
    const limited = await limitedKey(f, 1);
    const other = await allOwnedPoolKey(f);
    await createSandbox(limited.principal, pooled(f));
    await expect(createSandbox(limited.principal, pooled(f))).rejects.toMatchObject(
      limitReached(1, 1),
    );
    await expect(createSandbox(other.principal, pooled(f))).resolves.toBeDefined();
    await expect(createSandbox(f.owner, pooled(f))).resolves.toBeDefined();
    // Their sandboxes do not count against the limited key.
    expect(await countKeyLiveSandboxes(db.inspect, f.id, limited.key.id)).toBe(1);
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(3);
  });

  it("the column CHECK refuses a limit outside 1..1000", async () => {
    const f = await poolFixture(db);
    const key = await allOwnedPoolKey(f);
    for (const value of [0, 1001])
      await expect(
        db.inspect.sdkKey.update({ where: { id: key.key.id }, data: { maxLiveSandboxes: value } }),
      ).rejects.toBeDefined();
  });
});
