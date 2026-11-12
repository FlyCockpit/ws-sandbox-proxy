vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-access-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedLaunchHost, seedTemplateRevision } from "../testing/resource-fixtures";
import { foreignImageAccessLost } from "./access";

const db = await pgTestDatabase();
afterAll(() => db.close());

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "U", email: `${id}@example.test` } });
  return id;
}
const fpOf = () => `sha256:${(randomUUID() + randomUUID()).replaceAll("-", "").slice(0, 64)}`;

/** A foreign copy that every gate currently admits: the image owner uses a
 * shared pool the host is a member of, the host accepts foreign images, and a
 * live ANY_NODE revision pins the image. */
async function fixture() {
  const hostOwner = await user();
  const imageOwner = await user();
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: hostOwner,
      slug: "h",
      label: "h",
      status: "CONNECTED",
      daemonFeatures: { egressPolicy: true, image: { fetch: true, acceptForeign: true } },
    },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: hostOwner, slug: "p", label: "P" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { userId: hostOwner, hostOwnerId: hostOwner, poolId: pool.id, sandboxHostId: host.id },
  });
  const share = await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: hostOwner, granteeUserId: imageOwner },
  });
  const fingerprint = fpOf();
  const revision = await seedTemplateRevision(db.inspect, {
    data: { userId: imageOwner, slug: "b", label: "B", incusFingerprint: fingerprint },
  });
  await db.inspect.sandboxTemplateAvailability.create({
    data: {
      userId: imageOwner,
      revisionId: revision.id,
      hostId: host.id,
      hostOwnerId: hostOwner,
      localFingerprint: fingerprint,
      architecture: "x86_64",
      manifestDigest: "d".repeat(64),
      status: "AVAILABLE",
      verifiedConnectionEpoch: 1,
    },
  });
  await db.inspect.sandboxHostImageCache.create({
    data: {
      hostId: host.id,
      hostOwnerId: hostOwner,
      imageOwnerId: imageOwner,
      fingerprint,
      compressedBytes: 4096n,
      origin: "fetched",
      connectionEpoch: 1,
      reportedAt: new Date(),
    },
  });
  return { hostOwner, imageOwner, host, pool, share, revision, fingerprint };
}
type F = Awaited<ReturnType<typeof fixture>>;

const lost = async (f: F) =>
  (await foreignImageAccessLost(f.host.id)).filter((row) => row.imageOwnerId === f.imageOwner);
const availability = async (f: F) =>
  (
    await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
      where: { hostId: f.host.id, userId: f.imageOwner },
    })
  ).status;

describe("foreign image access loss (security review P2-5)", () => {
  it("keeps a copy every gate still admits, and never touches the host owner's own images", async () => {
    const f = await fixture();
    await db.inspect.sandboxHostImageCache.create({
      data: {
        hostId: f.host.id,
        hostOwnerId: f.hostOwner,
        imageOwnerId: f.hostOwner,
        fingerprint: fpOf(),
        compressedBytes: 1n,
        origin: "fetched",
        connectionEpoch: 1,
        reportedAt: new Date(),
      },
    });
    expect(await foreignImageAccessLost(f.host.id)).toEqual([]);
    expect(await availability(f)).toBe("AVAILABLE");
  });

  it.each([
    [
      "the share no longer allows use",
      (f: F) =>
        db.inspect.share.update({
          where: { id: f.share.id },
          data: { canUse: false, canContribute: true },
        }),
    ],
    [
      "the host left the pool",
      (f: F) =>
        db.inspect.sandboxPoolMember.updateMany({
          where: { sandboxHostId: f.host.id },
          data: { removedAt: new Date() },
        }),
    ],
    [
      "the account default became owned-nodes-only",
      (f: F) =>
        db.inspect.accountImagePolicy.create({
          data: { userId: f.imageOwner, imagePlacement: "OWNED_NODES_ONLY" },
        }),
    ],
    [
      "the template became owned-nodes-only",
      (f: F) =>
        db.inspect.sandboxTemplate.update({
          where: { id: f.revision.templateId },
          data: { imagePlacement: "OWNED_NODES_ONLY" },
        }),
    ],
    [
      "the image owner was banned",
      (f: F) => db.inspect.user.update({ where: { id: f.imageOwner }, data: { banned: true } }),
    ],
    [
      "the image owner requested deletion",
      (f: F) =>
        db.inspect.user.update({
          where: { id: f.imageOwner },
          data: { deletionRequestedAt: new Date() },
        }),
    ],
    [
      "the host stopped accepting foreign images",
      (f: F) =>
        db.inspect.sandboxHost.update({
          where: { id: f.host.id },
          data: { daemonFeatures: { egressPolicy: true, image: { fetch: true } } },
        }),
    ],
  ])("releases and invalidates the copy when %s", async (_why, change) => {
    const f = await fixture();
    await change(f);
    expect(await lost(f)).toEqual([
      {
        hostId: f.host.id,
        hostOwnerId: f.hostOwner,
        connectionEpoch: f.host.connectionEpoch,
        imageOwnerId: f.imageOwner,
        fingerprint: f.fingerprint,
      },
    ]);
    expect(await availability(f)).toBe("MISSING");
    // The row stays until the host reports the eviction: the next sweep (or
    // the host's next census) releases it again.
    expect((await lost(f)).length).toBe(1);
  });

  it("round-2 P2-4: global scans advance past copies hosts never evict, and releases rotate on a durable schedule", async () => {
    const f = await fixture();
    // 200 more foreign copies sorting before the fixture's own copy.
    const tag = randomUUID().slice(0, 8);
    await db.inspect.sandboxHostImageCache.createMany({
      data: Array.from({ length: 200 }, (_, i) => ({
        id: `0acc${tag}${String(i).padStart(4, "0")}`,
        hostId: f.host.id,
        hostOwnerId: f.hostOwner,
        imageOwnerId: f.imageOwner,
        fingerprint: fpOf(),
        compressedBytes: 1n,
        origin: "fetched",
        connectionEpoch: 1,
        reportedAt: new Date(),
      })),
    });
    await db.inspect.sandboxHostImageCache.updateMany({
      where: { hostId: f.host.id, imageOwnerId: f.imageOwner, fingerprint: f.fingerprint },
      data: { id: `zacc${tag}` },
    });
    await db.inspect.appSetting.deleteMany({ where: { key: "image-store.access.cursor" } });
    // Access lost for all 201; the host never evicts any of them.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { daemonFeatures: { egressPolicy: true, image: { fetch: true } } },
    });
    const first = (await foreignImageAccessLost()).filter((r) => r.hostId === f.host.id);
    expect(first).toHaveLength(200);
    expect(await availability(f)).toBe("AVAILABLE");
    // The second scan continues past the 200 (it used to return them again).
    const second = (await foreignImageAccessLost()).filter((r) => r.hostId === f.host.id);
    expect(await availability(f)).toBe("MISSING");
    expect(
      await db.inspect.sandboxHostImageCache.count({
        where: { hostId: f.host.id, accessLostAt: null, imageOwnerId: f.imageOwner },
      }),
    ).toBe(0);
    // Releases rotate: only the copy not yet attempted is due now.
    expect(second.map((r) => r.fingerprint)).toEqual([f.fingerprint]);
    expect((await foreignImageAccessLost()).filter((r) => r.hostId === f.host.id)).toEqual([]);
    // After the retry window everything is due again, least recently attempted first.
    await db.inspect.$executeRaw`UPDATE sandbox_host_image_cache
      SET "releaseSentAt" = "releaseSentAt" - interval '2 minutes'
      WHERE "hostId" = ${f.host.id}`;
    await db.inspect.$executeRaw`UPDATE sandbox_host_image_cache
      SET "releaseSentAt" = "releaseSentAt" - interval '1 hour'
      WHERE id = ${`zacc${tag}`}`;
    const third = (await foreignImageAccessLost()).filter((r) => r.hostId === f.host.id);
    expect(third).toHaveLength(200);
    expect(third.map((r) => r.fingerprint)).toContain(f.fingerprint);
    // An offline host is not scheduled (it is released by its census on reconnect).
    await db.inspect.$executeRaw`UPDATE sandbox_host_image_cache
      SET "releaseSentAt" = NULL WHERE "hostId" = ${f.host.id}`;
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED" },
    });
    expect((await foreignImageAccessLost()).filter((r) => r.hostId === f.host.id)).toEqual([]);
    expect(await foreignImageAccessLost(f.host.id)).toHaveLength(200);
  });
});
