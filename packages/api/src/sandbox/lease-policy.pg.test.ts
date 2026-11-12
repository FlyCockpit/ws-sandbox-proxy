/**
 * T1: the layered lease policy's TS function, its SQL twin and the §3.1 lease
 * path join agree on real PostgreSQL rows, across deployment, host, pool,
 * membership, requester, unlimited-for-shares and own/foreign host.
 */
const leaseEnv = vi.hoisted(() => ({
  SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
  BETTER_AUTH_URL: "http://localhost:3000",
  SANDBOX_MAX_TIMEOUT_MS: 86_400_000 as number | null,
}));
vi.mock("@wssp/env/server", () => ({ env: leaseEnv, ADMIN_EMAILS: new Set() }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { Prisma } from "@wssp/db/client";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import {
  effectiveLeaseLimit,
  type LeaseRequest,
  leaseFitsSql,
  leasePathJoinSql,
  leaseWithinPolicy,
  pathLimitSql,
  pathUnlimitedSql,
  readLockedPathLimit,
} from "./lease-policy";
import { poolFixture } from "./testing/pool-fixtures";
import { seedSandboxInstance, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

const H1 = 3_600_000;
const H6 = 21_600_000;
const H24 = 86_400_000;
const F = 2_073_600_000;

async function matrixFixture() {
  const f = await poolFixture(db);
  const creator = randomUUID();
  await db.inspect.user.create({
    data: { id: creator, name: "Creator", email: `${creator}@example.test` },
  });
  // Pool PB, owned by the creator, with the fixture owner's host contributed.
  const poolB = await db.inspect.sandboxPool.create({
    data: { userId: creator, slug: "b", label: "B" },
  });
  const consent = await db.inspect.share.create({
    data: {
      poolId: poolB.id,
      ownerUserId: creator,
      granteeUserId: f.id,
      canUse: false,
      canContribute: true,
    },
  });
  const memberB = await db.inspect.sandboxPoolMember.create({
    data: {
      userId: creator,
      hostOwnerId: f.id,
      poolId: poolB.id,
      sandboxHostId: f.host.id,
      shareId: consent.id,
      contributeWitness: true,
      ownHostsOnlyWitness: false,
    },
  });
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: creator },
  });
  const memberA = await db.inspect.sandboxPoolMember.findUniqueOrThrow({
    where: { poolId_sandboxHostId: { poolId: f.pool.id, sandboxHostId: f.host.id } },
  });
  const creatorRevision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: creator,
      slug: randomUUID(),
      label: "Creator",
      incusFingerprint: `sha256:${"c".repeat(64)}`,
    },
  });
  const seed = (
    label: string,
    data: {
      userId: string;
      templateId: string;
      originPoolId: string;
      usagePoolId?: string;
      usageMemberId?: string;
    },
  ) =>
    seedSandboxInstance(db.inspect, {
      data: {
        ...data,
        hostOwnerId: f.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "READY",
        liveResourcesHeld: false,
        leaseExpiresAt: new Date("2040-01-01"),
        leaseExpireAction: "STOP",
        metadata: { label },
      },
    });
  const sandboxes = {
    ownOwner: await seed("own+owner", {
      userId: f.id,
      templateId: f.revision.id,
      originPoolId: f.pool.id,
      // Sharing clears the usage path of own-host rows; the origin path stays.
    }),
    ownGrantee: await seed("own+grantee", {
      userId: f.id,
      templateId: f.revision.id,
      originPoolId: poolB.id,
    }),
    foreignGrantee: await seed("foreign+grantee", {
      userId: creator,
      templateId: creatorRevision.id,
      originPoolId: f.pool.id,
      usagePoolId: f.pool.id,
      usageMemberId: memberA.id,
    }),
    foreignOwner: await seed("foreign+owner", {
      userId: creator,
      templateId: creatorRevision.id,
      originPoolId: poolB.id,
      usagePoolId: poolB.id,
      usageMemberId: memberB.id,
    }),
  };
  return { f, creator, poolB, consent, memberA, memberB, sandboxes };
}

/** Independent §3.1 reading through Prisma, never through the SQL under test. */
async function expectedLimit(sandboxId: string) {
  const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  const host = s.sandboxHostId
    ? await db.inspect.sandboxHost.findUnique({ where: { id: s.sandboxHostId } })
    : null;
  const own = s.hostOwnerId === s.userId;
  const poolId = own ? s.originPoolId : s.usagePoolId;
  const pool = poolId ? await db.inspect.sandboxPool.findUnique({ where: { id: poolId } }) : null;
  const member = own
    ? poolId && s.sandboxHostId
      ? await db.inspect.sandboxPoolMember.findUnique({
          where: { poolId_sandboxHostId: { poolId, sandboxHostId: s.sandboxHostId } },
        })
      : null
    : s.usageMemberId
      ? await db.inspect.sandboxPoolMember.findUnique({ where: { id: s.usageMemberId } })
      : null;
  const applies =
    pool != null &&
    member != null &&
    pool.deletedAt == null &&
    member.removedAt == null &&
    member.poolId === pool.id &&
    member.sandboxHostId === s.sandboxHostId;
  return effectiveLeaseLimit({
    deployment: leaseEnv.SANDBOX_MAX_TIMEOUT_MS,
    host: host ? host.daemonMaxLeaseMs : H24,
    pool: applies
      ? {
          maxLeaseMs: pool.maxLeaseMs,
          ownerId: pool.userId,
          unlimitedForShares: pool.unlimitedLeaseForShares,
        }
      : null,
    memberMaxLeaseMs: applies ? member.maxLeaseMs : null,
    requesterId: s.userId,
  });
}

async function sqlLimit(sandboxId: string, deployment: number | null) {
  return db.prisma.$transaction(async (tx) => {
    // Policy SQL never depends on the session time zone.
    await tx.$executeRaw`SET LOCAL TIME ZONE 'Pacific/Chatham'`;
    const rows = await tx.$queryRaw<{ finite: number; unlimited: boolean }[]>`
      SELECT ${pathLimitSql(deployment)} AS finite,
        ${pathUnlimitedSql(deployment, Prisma.sql`s."userId"`)} AS unlimited
      FROM sandbox_instance s
      LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
      ${leasePathJoinSql}
      WHERE s.id = ${sandboxId}`;
    return { finiteMaxMs: Number(rows[0]!.finite), unlimited: rows[0]!.unlimited };
  });
}

async function sqlFits(sandboxId: string, userId: string, request: LeaseRequest) {
  const deployment = leaseEnv.SANDBOX_MAX_TIMEOUT_MS;
  const rows = await db.prisma.$queryRaw<{ fits: boolean }[]>`
    SELECT ${leaseFitsSql(request, userId, deployment)} AS fits
    FROM sandbox_instance s
    LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
    ${leasePathJoinSql}
    WHERE s.id = ${sandboxId}`;
  return rows[0]!.fits;
}

it("T1 parity: effectiveLeaseLimit, pathLimitSql/pathUnlimitedSql, leaseFitsSql and readLockedPathLimit agree", async () => {
  const m = await matrixFixture();
  const pools = [m.f.pool.id, m.poolB.id];
  let checked = 0;
  const seen = new Set<string>();
  for (const deployment of [null, H24]) {
    leaseEnv.SANDBOX_MAX_TIMEOUT_MS = deployment;
    for (const host of [null, H6, H24]) {
      await db.inspect.sandboxHost.update({
        where: { id: m.f.host.id },
        data: { daemonMaxLeaseMs: host },
      });
      for (const pool of [null, H6, "deleted"] as const) {
        for (const member of [null, H1, "removed", "disabled"] as const) {
          for (const unlimitedForShares of [false, true]) {
            await db.inspect.sandboxPool.updateMany({
              where: { id: { in: pools } },
              data: {
                maxLeaseMs: pool === "deleted" ? null : pool,
                deletedAt: pool === "deleted" ? new Date() : null,
                unlimitedLeaseForShares: unlimitedForShares,
              },
            });
            await db.inspect.sandboxPoolMember.update({
              where: { id: m.memberA.id },
              data: {
                maxLeaseMs: typeof member === "number" ? member : null,
                removedAt: member === "removed" ? new Date() : null,
                enabled: member !== "disabled",
              },
            });
            await db.inspect.sandboxPoolMember.update({
              where: { id: m.memberB.id },
              data:
                member === "removed"
                  ? {
                      maxLeaseMs: null,
                      removedAt: new Date(),
                      shareId: null,
                      contributeWitness: null,
                      ownHostsOnlyWitness: null,
                    }
                  : {
                      maxLeaseMs: typeof member === "number" ? member : null,
                      removedAt: null,
                      enabled: member !== "disabled",
                      shareId: m.consent.id,
                      contributeWitness: true,
                      ownHostsOnlyWitness: false,
                    },
            });
            for (const [label, sandbox] of Object.entries(m.sandboxes)) {
              const expected = await expectedLimit(sandbox.id);
              const context = JSON.stringify({
                label,
                deployment,
                host,
                pool,
                member,
                unlimitedForShares,
              });
              expect(await sqlLimit(sandbox.id, deployment), context).toEqual(expected);
              expect(
                await db.prisma.$transaction((tx) => readLockedPathLimit(tx, sandbox)),
                context,
              ).toEqual(expected);
              const requests: LeaseRequest[] = [
                { kind: "none" },
                { kind: "deadline", ms: expected.finiteMaxMs },
                ...(expected.finiteMaxMs < F
                  ? [{ kind: "deadline" as const, ms: expected.finiteMaxMs + 1 }]
                  : []),
              ];
              for (const request of requests)
                expect(await sqlFits(sandbox.id, sandbox.userId, request), context).toBe(
                  leaseWithinPolicy(request, expected),
                );
              seen.add(`${expected.finiteMaxMs}/${expected.unlimited}`);
              checked++;
            }
          }
        }
      }
    }
  }
  expect(checked).toBe(2 * 3 * 3 * 4 * 2 * 4);
  // The matrix reaches every interesting outcome, including unlimited paths.
  for (const outcome of [`${F}/true`, `${F}/false`, `${H6}/false`, `${H1}/false`, `${H24}/false`])
    expect(seen.has(outcome), outcome).toBe(true);
});

it("T1 path specifics: own host keeps its origin path after sharing clears usage; foreign without usage path has host+deployment only", async () => {
  const m = await matrixFixture();
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  await db.inspect.sandboxHost.update({
    where: { id: m.f.host.id },
    data: { daemonMaxLeaseMs: null },
  });
  await db.inspect.sandboxPool.update({ where: { id: m.f.pool.id }, data: { maxLeaseMs: H6 } });
  // Own host: usage cleared (sharing's own-host behaviour), origin path still limits.
  await db.inspect.sandbox.update({
    where: { id: m.sandboxes.ownOwner.id },
    data: { usagePoolId: null, usageMemberId: null },
  });
  expect(
    await db.prisma.$transaction((tx) => readLockedPathLimit(tx, m.sandboxes.ownOwner)),
  ).toEqual({ finiteMaxMs: H6, unlimited: false });
  // Foreign host in access grace with no usage path: host + deployment only.
  await db.inspect.sandbox.update({
    where: { id: m.sandboxes.foreignGrantee.id },
    data: { usagePoolId: null, usageMemberId: null },
  });
  expect(
    await db.prisma.$transaction((tx) => readLockedPathLimit(tx, m.sandboxes.foreignGrantee)),
  ).toEqual({ finiteMaxMs: F, unlimited: true });
  // A usage member that names another pool or host never applies.
  await db.inspect.sandbox.update({
    where: { id: m.sandboxes.foreignGrantee.id },
    data: { usagePoolId: m.poolB.id, usageMemberId: m.memberA.id },
  });
  expect(
    await db.prisma.$transaction((tx) => readLockedPathLimit(tx, m.sandboxes.foreignGrantee)),
  ).toEqual({ finiteMaxMs: F, unlimited: true });
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = H24;
});
