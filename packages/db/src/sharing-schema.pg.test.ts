import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { pgTestDatabase } from "./testing/pg";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function graph() {
  const a = randomUUID(),
    b = randomUUID(),
    c = randomUUID();
  for (const id of [a, b, c])
    await db.inspect.user.create({ data: { id, name: "Owner", email: `${id}@example.test` } });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: a, slug: randomUUID(), label: "Pool" },
  });
  const host = await db.inspect.sandboxHost.create({
    data: { userId: b, slug: randomUUID(), label: "Host" },
  });
  const share = await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: a, granteeUserId: b },
  });
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: b,
      name: "Key",
      scopes: ["pools:read"],
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
    },
  });
  return { a, b, c, pool, host, share, key };
}
type Graph = Awaited<ReturnType<typeof graph>>;
function member(f: Graph) {
  return {
    userId: f.a,
    hostOwnerId: f.b,
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    shareId: f.share.id,
    contributeWitness: true,
    ownHostsOnlyWitness: false,
  };
}
function grant(f: Graph) {
  return {
    userId: f.b,
    poolOwnerId: f.a,
    sdkKeyId: f.key.id,
    poolId: f.pool.id,
    shareId: f.share.id,
    useWitness: true,
  };
}

// Each rejected Prisma statement is its own transaction; failure cannot poison the fixture.
describe("sharing principals, CHECKs and RI permission witnesses (real PostgreSQL)", () => {
  it("preserves owner-local membership and rejects wrong principals, missing and forged foreign sources", async () => {
    const f = await graph();
    const own = await db.inspect.sandboxHost.create({
      data: { userId: f.a, slug: randomUUID(), label: "Own" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.a, hostOwnerId: f.a, poolId: f.pool.id, sandboxHostId: own.id },
    });
    for (const data of [
      { ...member(f), hostOwnerId: f.c },
      { ...member(f), userId: f.c },
      { ...member(f), shareId: null },
      { ...member(f), contributeWitness: false },
      { ...member(f), ownHostsOnlyWitness: null },
    ])
      await expect(db.inspect.sandboxPoolMember.create({ data })).rejects.toBeDefined();
    const row = await db.inspect.sandboxPoolMember.create({ data: member(f) });
    expect(row.hostOwnerId).toBe(f.b);
    await expect(
      db.inspect.sdkKeyPoolAllowlist.create({ data: { ...grant(f), shareId: null } }),
    ).rejects.toBeDefined();
    await db.inspect.sdkKeyPoolAllowlist.create({ data: grant(f) });
  });
  it("enforces self/zero-permission Shares and cap, percent and grace bounds without changing null defaults", async () => {
    const f = await graph();
    expect([f.share.maxMemoryMiB, f.share.maxVcpu, f.share.maxDiskGiB]).toEqual([null, null, null]);
    for (const data of [
      { canUse: false, canContribute: false },
      { maxMemoryMiB: 0 },
      { maxMemoryMiB: 16777217 },
      { maxVcpu: 8193 },
      { maxDiskGiB: 268435457 },
    ])
      await expect(
        db.inspect.share.update({ where: { id: f.share.id }, data }),
      ).rejects.toBeDefined();
    await expect(
      db.inspect.share.create({
        data: { poolId: f.pool.id, ownerUserId: f.a, granteeUserId: f.a },
      }),
    ).rejects.toBeDefined();
    for (const value of [-1, 2592001])
      await expect(
        db.inspect.sandboxPool.update({
          where: { id: f.pool.id },
          data: { disconnectGraceSeconds: value },
        }),
      ).rejects.toBeDefined();
    for (const value of [0, 2592000])
      await db.inspect.sandboxPool.update({
        where: { id: f.pool.id },
        data: { disconnectGraceSeconds: value },
      });
    for (const value of [0, 101])
      await expect(
        db.inspect.sandboxPoolMember.create({ data: { ...member(f), memoryCapPercent: value } }),
      ).rejects.toBeDefined();
  });
  it("raw permission loss soft-removes members, clears grants, never silently reactivates, and explicit re-add needs fresh consent", async () => {
    const f = await graph();
    const m = await db.inspect.sandboxPoolMember.create({ data: member(f) });
    await db.inspect.sdkKeyPoolAllowlist.create({ data: grant(f) });
    await db.inspect.$executeRaw`UPDATE share SET "canContribute" = false WHERE id = ${f.share.id}`;
    expect(await db.inspect.sandboxPoolMember.findUnique({ where: { id: m.id } })).toMatchObject({
      removedAt: expect.any(Date),
      shareId: null,
      contributeWitness: null,
      ownHostsOnlyWitness: null,
    });
    expect(await db.inspect.sdkKeyPoolAllowlist.count({ where: { poolId: f.pool.id } })).toBe(1);
    await expect(
      db.inspect.sandboxPoolMember.update({
        where: { id: m.id },
        data: { ...member(f), removedAt: null },
      }),
    ).rejects.toBeDefined();
    await db.inspect.share.update({ where: { id: f.share.id }, data: { canContribute: true } });
    expect(
      (await db.inspect.sandboxPoolMember.findUniqueOrThrow({ where: { id: m.id } })).removedAt,
    ).not.toBeNull();
    await db.inspect.sandboxPoolMember.update({
      where: { id: m.id },
      data: { ...member(f), removedAt: null },
    });
    await db.inspect.$executeRaw`UPDATE share SET "canUse" = false WHERE id = ${f.share.id}`;
    expect(await db.inspect.sdkKeyPoolAllowlist.count({ where: { poolId: f.pool.id } })).toBe(0);
    await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { ownHostsOnly: true } });
    expect(
      (await db.inspect.sandboxPoolMember.findUniqueOrThrow({ where: { id: m.id } })).removedAt,
    ).not.toBeNull();
  });
  it("cleanup rolls back with permission changes and pool deletion revokes pending invites", async () => {
    const f = await graph();
    const m = await db.inspect.sandboxPoolMember.create({ data: member(f) });
    await expect(
      db.inspect.$transaction(async (tx) => {
        await tx.share.delete({ where: { id: f.share.id } });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(
      (await db.inspect.sandboxPoolMember.findUniqueOrThrow({ where: { id: m.id } })).removedAt,
    ).toBeNull();
    const invite = {
      poolId: f.pool.id,
      ownerUserId: f.a,
      email: "target@example.test",
      pendingKey: `${f.pool.id}:target@example.test`,
      tokenDigest: "a".repeat(64),
      expiresAt: new Date(Date.now() + 3600000),
    };
    await expect(
      db.inspect.shareInvite.create({ data: { ...invite, pendingKey: "forged" } }),
    ).rejects.toBeDefined();
    await expect(
      db.inspect.shareInvite.create({ data: { ...invite, email: " Target@example.test" } }),
    ).rejects.toBeDefined();
    const i = await db.inspect.shareInvite.create({ data: invite });
    await expect(
      db.inspect.shareInvite.update({
        where: { id: i.id },
        data: {
          acceptedAt: new Date(),
          pendingKey: null,
          acceptedByUserId: f.c,
          acceptedShareId: f.share.id,
        },
      }),
    ).rejects.toBeDefined();
    await db.inspect.sandboxPool.update({
      where: { id: f.pool.id },
      data: { deletedAt: new Date() },
    });
    expect(await db.inspect.shareInvite.findUnique({ where: { id: i.id } })).toMatchObject({
      pendingKey: null,
      revokedAt: expect.any(Date),
    });
    await expect(
      db.inspect.shareInvite.update({
        where: { id: i.id },
        data: { revokedAt: null, pendingKey: invite.pendingKey },
      }),
    ).rejects.toBeDefined();
  });
  for (const permission of ["contribute", "use"] as const)
    for (const first of ["grant", "revoke"] as const)
      it(`RI serializes raw ${permission} revoke vs witness insert: ${first} first`, async () => {
        const f = await graph();
        const insert = (tx: import("../prisma/generated/client").Prisma.TransactionClient) =>
          permission === "contribute"
            ? tx.sandboxPoolMember.create({ data: member(f) }).then(() => undefined)
            : tx.sdkKeyPoolAllowlist.create({ data: grant(f) }).then(() => undefined);
        const revoke = (tx: import("../prisma/generated/client").Prisma.TransactionClient) =>
          tx.share.update({
            where: { id: f.share.id },
            data: permission === "contribute" ? { canContribute: false } : { canUse: false },
          });

        const writer: () => Promise<unknown> =
          first === "grant"
            ? () => db.prisma.$transaction((tx) => insert(tx))
            : () => db.prisma.$transaction((tx) => revoke(tx));
        const contender: () => Promise<unknown> =
          first === "grant"
            ? () => db.prisma.$transaction((tx) => revoke(tx))
            : () => db.prisma.$transaction((tx) => insert(tx));
        const pause = db.pauseAt("first", {
          after:
            first === "grant"
              ? permission === "contribute"
                ? "sandboxPoolMember.create"
                : "sdkKeyPoolAllowlist.create"
              : "share.update",
        });
        const a = db.run<unknown>("first", writer);
        await pause.waitReached();
        const b = db.run("second", contender).then(
          () => "ok",
          () => "refused",
        );
        try {
          await db.waitUntilBlocked("second", { by: "first" });
        } finally {
          pause.release();
        }
        await a;
        expect(await b).toBe(first === "grant" ? "ok" : "refused");
        expect(
          permission === "contribute"
            ? await db.inspect.sandboxPoolMember.count({
                where: { poolId: f.pool.id, removedAt: null },
              })
            : await db.inspect.sdkKeyPoolAllowlist.count({ where: { poolId: f.pool.id } }),
        ).toBe(0);
      });
});
