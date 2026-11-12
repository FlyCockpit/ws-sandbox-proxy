import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../testing/resource-fixtures";

// Counts every Prisma delegate call and raw query the production code issues
// while `counter.on` is set; otherwise a transparent pass-through.
const counter = vi.hoisted(() => ({ on: false, calls: [] as string[] }));
vi.mock("@wssp/db", async () => {
  const { prisma } = await (await import("@wssp/db/testing/pg")).pgTestDatabase();
  const record = (name: string) => {
    if (counter.on) counter.calls.push(name);
  };
  const counted = new Proxy(prisma, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver);
      if (typeof property !== "string") return value;
      if (property.startsWith("$query") || property.startsWith("$execute"))
        return (...args: unknown[]) => {
          record(property);
          return (value as (...a: unknown[]) => unknown)(...args);
        };
      if (
        typeof value === "object" &&
        value !== null &&
        typeof (value as { findFirst?: unknown }).findFirst === "function"
      )
        return new Proxy(value, {
          get(delegate, method) {
            const fn: unknown = Reflect.get(delegate, method, delegate);
            if (typeof fn !== "function" || typeof method !== "string") return fn;
            return (...args: unknown[]) => {
              record(`${property}.${method}`);
              return (fn as (...a: unknown[]) => unknown)(...args);
            };
          },
        });
      return value;
    },
  });
  return { default: counted };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "sharing-test-credential-secret-long-enough",
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
  },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("../budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/mailer", () => ({
  renderPoolShare: () => ({ subject: "Invitation", html: "mail" }),
  sendEmail: vi.fn(async () => {}),
}));

import { seedSandboxInstance, seedTemplateRevision } from "../testing/resource-fixtures";
import * as sharing from "./sharing";
import {
  getUsablePool,
  grantPoolShare,
  listSharedPools,
  listUsablePools,
  revokePoolShare,
} from "./sharing";

const db = await pgTestDatabase();
afterAll(() => db.close());
const session = (ownerId: string) => ({ kind: "session" as const, ownerId });

async function user() {
  const id = randomUUID();
  return db.inspect.user.create({
    data: {
      id,
      name: `User ${id.slice(0, 6)}`,
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
      createdAt: new Date(0),
    },
  });
}
const pool = (userId: string, label: string) =>
  db.inspect.sandboxPool.create({ data: { userId, slug: randomUUID(), label } });
async function share(
  ownerId: string,
  poolId: string,
  email: string,
  perms: { canUse: boolean; canContribute: boolean; maxMemoryMiB?: number | null },
) {
  await grantPoolShare(session(ownerId), {
    poolId,
    email,
    canUse: perms.canUse,
    canContribute: perms.canContribute,
    maxMemoryMiB: perms.maxMemoryMiB ?? null,
    maxVcpu: null,
    maxDiskGiB: null,
    signupAllowed: false,
  });
}
/** C sees: two owned pools, two use-shares from A (one with live usage) and one from
 * B, a contribute-only share from A; never A's unshared, a deleted shared or another
 * caller-invisible pool. */
async function mixedFixture() {
  const [a, b, c] = [await user(), await user(), await user()];
  const owned1 = await pool(c.id, "Owned 1");
  const owned2 = await pool(c.id, "Owned 2");
  const sharedA = await pool(a.id, "Shared A");
  const sharedA2 = await pool(a.id, "Shared A2");
  const sharedB = await pool(b.id, "Shared B");
  const contributeOnly = await pool(a.id, "Contribute only");
  const foreign = await pool(a.id, "Foreign");
  const deleted = await pool(a.id, "Deleted");
  await share(a.id, sharedA.id, c.email, {
    canUse: true,
    canContribute: false,
    maxMemoryMiB: 4096,
  });
  await share(a.id, sharedA2.id, c.email, { canUse: true, canContribute: true });
  await share(b.id, sharedB.id, c.email, { canUse: true, canContribute: false });
  await share(a.id, contributeOnly.id, c.email, { canUse: false, canContribute: true });
  await share(a.id, deleted.id, c.email, { canUse: true, canContribute: false });
  await db.inspect.sandboxPool.update({
    where: { id: deleted.id },
    data: { deletedAt: new Date() },
  });
  // A live charge for C in sharedA so usage is non-zero and per-pool.
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: a.id, slug: randomUUID(), label: "Host" },
  });
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: c.id,
      slug: randomUUID(),
      label: "Rev",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: c.id,
      hostOwnerId: a.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: rev.id,
      state: "READY",
      liveResourcesHeld: true,
      originPoolId: sharedA.id,
      usagePoolId: sharedA.id,
    },
  });
  return {
    a,
    b,
    c,
    owned: [owned1, owned2],
    used: [sharedA, sharedA2, sharedB],
    contributeOnly,
    foreign,
    deleted,
    sandbox,
  };
}
const ids = (rows: { id: string }[]) => rows.map((row) => row.id);
async function singles(ownerId: string, poolIds: string[], include: boolean) {
  return Promise.all(
    poolIds.map(async (id) => (await sharing.poolReadViews(session(ownerId), [id], include))[0]),
  );
}

it.each([false, true])(
  "batched pool reads equal N single reads in caller order (includeContribute=%s)",
  async (include) => {
    const f = await mixedFixture();
    const visible = [
      ...ids(f.owned),
      ...ids(f.used),
      ...(include ? [f.contributeOnly.id] : []),
    ].reverse();
    const batch = await sharing.poolReadViews(session(f.c.id), visible, include);
    expect(ids(batch)).toEqual(visible);
    expect(batch).toEqual(await singles(f.c.id, visible, include));
    const usedView = batch.find((view) => view.id === f.used[0]!.id);
    expect(usedView).toMatchObject({
      owner: { id: f.a.id, name: f.a.name },
      share: { canUse: true, canContribute: false, maxMemoryMiB: 4096 },
    });
    expect(usedView?.share?.usage.memoryMiB).not.toBe("0");
    for (const view of batch.filter((v) => v.id !== f.used[0]!.id && "share" in v))
      expect(view.share?.usage).toEqual({ memoryMiB: "0", vcpu: "0", diskGiB: "0" });
    for (const view of batch.filter((v) => ids(f.owned).includes(v.id))) {
      expect(view).not.toHaveProperty("share");
      expect(view).not.toHaveProperty("owner");
    }
    // The single path is the batch of one; the SDK detail agrees with it.
    const { memberCount: _count, ...detail } = await getUsablePool(session(f.c.id), {
      id: f.used[0]!.id,
    });
    expect(detail).toEqual(usedView);
  },
);

it("any unreadable id fails the whole batch like its single read (deleted, foreign, contribute-only, caller-foreign)", async () => {
  const f = await mixedFixture();
  const good = [...ids(f.owned), ...ids(f.used)];
  const hidden: [string, boolean][] = [
    [f.deleted.id, false],
    [f.deleted.id, true],
    [f.foreign.id, false],
    [f.foreign.id, true],
    [f.contributeOnly.id, false],
    [randomUUID(), false],
  ];
  for (const [id, include] of hidden) {
    await expect(sharing.poolReadViews(session(f.c.id), [id], include)).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(
      sharing.poolReadViews(session(f.c.id), [...good, id], include),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  }
  // A's view of C's owned pool: no share, so foreign to A.
  await expect(
    sharing.poolReadViews(session(f.a.id), [f.used[0]!.id, f.owned[0]!.id]),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(ids(await sharing.poolReadViews(session(f.a.id), [f.used[0]!.id]))).toEqual([
    f.used[0]!.id,
  ]);
});

it("incomplete usage evidence in any shared pool is a CONFLICT for the batch and the single read", async () => {
  const f = await mixedFixture();
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { currentPlacementId: null },
  });
  await expect(
    sharing.poolReadViews(session(f.c.id), [...ids(f.owned), ...ids(f.used)]),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(sharing.poolReadViews(session(f.c.id), [f.used[0]!.id])).rejects.toMatchObject({
    code: "CONFLICT",
  });
  // Pools without the incomplete row are unaffected.
  expect(ids(await sharing.poolReadViews(session(f.c.id), ids(f.used).slice(1)))).toEqual(
    ids(f.used).slice(1),
  );
});

it.each(["raw-share-delete", "raw-pool-delete", "hinted-revoke", "unhinted-owner-ban"] as const)(
  "a %s between discover and re-read fails the whole batch closed (real PG barrier)",
  async (kind) => {
    const f = await mixedFixture();
    const target = f.used[1]!;
    const pause = db.pauseAt("read", { after: "sandboxPool.findMany" });
    const read = db.run("read", () =>
      sharing.poolReadViews(session(f.c.id), [...ids(f.owned), ...ids(f.used)]),
    );
    await pause.waitReached();
    try {
      if (kind === "raw-share-delete")
        // Raw write deliberately emits no process-local authority hint.
        await db.inspect.share.delete({
          where: { poolId_granteeUserId: { poolId: target.id, granteeUserId: f.c.id } },
        });
      else if (kind === "raw-pool-delete")
        await db.inspect.sandboxPool.update({
          where: { id: target.id },
          data: { deletedAt: new Date() },
        });
      else if (kind === "hinted-revoke")
        await revokePoolShare(session(f.a.id), { poolId: target.id, granteeUserId: f.c.id });
      else await db.inspect.user.update({ where: { id: f.b.id }, data: { banned: true } });
    } finally {
      pause.release();
    }
    await expect(read).rejects.toMatchObject({ code: "NOT_FOUND" });
  },
);

it("a raw revoke after the dependent reads fails the final check closed (real PG barrier)", async () => {
  const f = await mixedFixture();
  const pause = db.pauseAt("read", { after: "share.findMany" });
  const read = db.run("read", () =>
    sharing.poolReadViews(session(f.c.id), [...ids(f.owned), ...ids(f.used)]),
  );
  await pause.waitReached();
  try {
    await db.inspect.share.delete({
      where: { poolId_granteeUserId: { poolId: f.used[2]!.id, granteeUserId: f.c.id } },
    });
  } finally {
    pause.release();
  }
  await expect(read).rejects.toMatchObject({ code: "NOT_FOUND" });
});

async function counted<T>(work: () => Promise<T>) {
  counter.calls = [];
  counter.on = true;
  try {
    const value = await work();
    return { value, calls: [...counter.calls] };
  } finally {
    counter.on = false;
  }
}
it("pool list pages issue a constant number of queries, independent of page size", async () => {
  const f = await mixedFixture();
  const all = await counted(() => listUsablePools(session(f.c.id), { limit: 50 }));
  expect(all.value.items).toHaveLength(5);
  for (let i = 0; i < 20; i++) {
    const extra = await pool(f.a.id, `Extra ${i}`);
    await share(f.a.id, extra.id, f.c.email, { canUse: true, canContribute: false });
  }
  const many = await counted(() => listUsablePools(session(f.c.id), { limit: 50 }));
  expect(many.value.items).toHaveLength(25);
  // page + discover + re-read + lease + shares + usage + final check.
  expect(many.calls.length).toBeLessThanOrEqual(7);
  expect(many.calls.length).toBe(all.calls.length);
  const shared = await counted(() => listSharedPools(session(f.c.id), { limit: 50 }));
  expect(shared.value.items).toHaveLength(24);
  expect(shared.calls.length).toBe(many.calls.length);
});
