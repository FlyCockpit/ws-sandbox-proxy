import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../testing/resource-fixtures";

/**
 * C52-R2-3 (real PostgreSQL): the per-owner host cap
 * (`SANDBOX_MAX_HOSTS_PER_OWNER`) at both host INSERT sites, `createHost` and
 * device-login enrollment, including the race two concurrent creators run.
 */
const capEnv = vi.hoisted(() => ({
  BETTER_AUTH_SECRET: "owner-host-cap-pg-test-secret",
  SANDBOX_MAX_HOSTS_PER_OWNER: 2 as number | null,
}));
vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({ env: capEnv, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

const db = await pgTestDatabase();
const { createHostInput } = await import("../contracts");
const { createHost, listHosts } = await import("./hosts");
const { mintHostDeviceCredentialFromApprovedDeviceCode } = await import(
  "../../lib/host-device-credential-access"
);
const { transitionDeviceCode } = await import("../../lib/device-code-transitions");

afterAll(() => db.close());
beforeEach(() => {
  capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = 2;
});

const HOST_LIMIT = { code: "CONFLICT", data: { code: "sandbox.owner_host_limit", limit: 2 } };
/** The owner's host-creation lock (owner-host-cap.ts). */
const CAP_LOCK = /pg_advisory_xact_lock/;

const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );

async function seedOwner(hosts = 0) {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  for (let index = 0; index < hosts; index++) {
    await seedLaunchHost(db.inspect, {
      data: { userId: ownerId, slug: `seed-${index}`, label: `Seed ${index}` },
    });
  }
  return ownerId;
}

const hostCount = (ownerId: string) => db.inspect.sandboxHost.count({ where: { userId: ownerId } });

const create = (ownerId: string, slug: string) =>
  createHost({ kind: "session", ownerId }, createHostInput.parse({ slug, label: slug }));

async function approvedDeviceCode(
  ownerId: string,
  slug: string,
  intent: { kind: "create" } | { kind: "replace"; hostId: string } = { kind: "create" },
) {
  const deviceCode = `device-${randomUUID()}`;
  await db.inspect.deviceCode.create({
    data: {
      deviceCode,
      userCode: `user-${randomUUID()}`,
      userId: ownerId,
      expiresAt: new Date(Date.now() + 600_000),
      status: "approved",
      scope: `host-slug:${slug}`,
      enrollmentIntent: intent.kind,
      replaceHostId: intent.kind === "replace" ? intent.hostId : null,
    },
  });
  return deviceCode;
}

describe("C52-R2-3 per-owner host cap (real PostgreSQL)", () => {
  it("admits hosts up to the cap and refuses the next with a typed CONFLICT", async () => {
    const ownerId = await seedOwner();
    await expect(create(ownerId, "a")).resolves.toMatchObject({ slug: "a" });
    await expect(create(ownerId, "b")).resolves.toMatchObject({ slug: "b" });
    const refused = create(ownerId, "c");
    await expect(refused).rejects.toMatchObject(HOST_LIMIT);
    await expect(refused).rejects.toThrow(/SANDBOX_MAX_HOSTS_PER_OWNER/);
    expect(await hostCount(ownerId)).toBe(2);
  });

  it("counts hosts pending deletion, and the cap is per owner", async () => {
    const ownerId = await seedOwner(2);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: ownerId },
      data: { deletionRequestedAt: new Date() },
    });
    await expect(create(ownerId, "fresh")).rejects.toMatchObject(HOST_LIMIT);
    // Another owner at zero hosts is unaffected.
    const other = await seedOwner();
    await expect(create(other, "fresh")).resolves.toMatchObject({ slug: "fresh" });
  });

  it("`unlimited` lifts the cap, and a raised cap admits more", async () => {
    const ownerId = await seedOwner(2);
    capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = null;
    await expect(create(ownerId, "third")).resolves.toMatchObject({ slug: "third" });
    capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = 4;
    await expect(create(ownerId, "fourth")).resolves.toMatchObject({ slug: "fourth" });
    await expect(create(ownerId, "fifth")).rejects.toMatchObject({
      data: { code: "sandbox.owner_host_limit", limit: 4 },
    });
    expect(await hostCount(ownerId)).toBe(4);
  });

  it("device enrollment for a new slug is refused at the cap without consuming the code", async () => {
    const ownerId = await seedOwner(2);
    const deviceCode = await approvedDeviceCode(ownerId, "edge");
    await expect(
      mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "edge" }),
    ).rejects.toMatchObject(HOST_LIMIT);
    expect(await hostCount(ownerId)).toBe(2);
    expect(await db.inspect.hostDeviceCredential.count({ where: { userId: ownerId } })).toBe(0);
    expect(await db.inspect.deviceCode.count({ where: { deviceCode } })).toBe(1);
  });

  it("inverse: re-enrolling an existing host at the cap creates nothing and succeeds", async () => {
    const ownerId = await seedOwner(2);
    const host = await db.inspect.sandboxHost.findFirstOrThrow({
      where: { userId: ownerId, slug: "seed-0" },
    });
    const deviceCode = await approvedDeviceCode(ownerId, "seed-0", {
      kind: "replace",
      hostId: host.id,
    });
    await expect(
      mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "seed-0" }),
    ).resolves.toMatchObject({ hostId: host.id });
    expect(await hostCount(ownerId)).toBe(2);
  });

  it("device-login approval for a new slug is refused at the cap; a replacement approval is not", async () => {
    const ownerId = await seedOwner(2);
    const pending = async () => {
      const userCode = `UC${randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase()}`;
      await db.inspect.deviceCode.create({
        data: {
          deviceCode: `device-${randomUUID()}`,
          userCode,
          userId: ownerId,
          expiresAt: new Date(Date.now() + 600_000),
          status: "pending",
          scope: "host-slug:edge",
        },
      });
      return userCode;
    };
    const refusedCode = await pending();
    await expect(
      transitionDeviceCode({
        userCode: refusedCode,
        userId: ownerId,
        action: "approve",
        intent: { kind: "create" },
      }),
    ).rejects.toMatchObject(HOST_LIMIT);
    expect(
      await db.inspect.deviceCode.findFirstOrThrow({ where: { userCode: refusedCode } }),
    ).toMatchObject({ status: "pending" });
    const host = await db.inspect.sandboxHost.findFirstOrThrow({ where: { userId: ownerId } });
    await expect(
      transitionDeviceCode({
        userCode: await pending(),
        userId: ownerId,
        action: "approve",
        intent: { kind: "replace", hostId: host.id },
      }),
    ).resolves.toMatchObject({ success: true });
  });

  it.each([
    ["createHost", "createHost"],
    ["createHost", "device enrollment"],
  ] as const)(
    "RACE: %s holding the cap lock blocks a concurrent %s at the last slot; exactly one host is admitted",
    async (_first, second) => {
      const ownerId = await seedOwner(1);
      const deviceCode = await approvedDeviceCode(ownerId, "racer-b");
      // A has counted 1 < 2 under the cap lock and is parked before its INSERT.
      const parked = db.pauseAt("a", { before: "sandboxHost.create" });
      const first = settle(db.run("a", () => create(ownerId, "racer-a")));
      await parked.waitReached();
      const run =
        second === "createHost"
          ? () => create(ownerId, "racer-b")
          : () =>
              mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "racer-b" });
      const other = settle(db.run("b", run));
      let observation: Awaited<ReturnType<typeof db.waitUntilBlocked>> | "finished";
      try {
        // B must wait on A's cap lock, observed in PostgreSQL itself; without
        // the lock B would count 1, insert, and finish while A is parked.
        observation = await Promise.race([
          db.waitUntilBlocked("b", { by: "a" }),
          other.then(() => "finished" as const),
        ]);
      } finally {
        parked.release();
      }
      expect(observation).not.toBe("finished");
      expect(observation).toMatchObject({ waitEventType: "Lock" });
      expect((observation as { query: string }).query).toMatch(CAP_LOCK);
      expect(await first).toMatchObject({ ok: true });
      const lost = await other;
      expect(lost.ok).toBe(false);
      expect((lost as { error: unknown }).error).toMatchObject(HOST_LIMIT);
      expect(await hostCount(ownerId)).toBe(2);
    },
  );
  it("device enrollment holding the cap lock blocks a concurrent createHost", async () => {
    const ownerId = await seedOwner(1);
    const deviceCode = await approvedDeviceCode(ownerId, "racer-a");
    const parked = db.pauseAt("a", { before: "sandboxHost.create" });
    const first = settle(
      db.run("a", () =>
        mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "racer-a" }),
      ),
    );
    await parked.waitReached();
    const other = settle(db.run("b", () => create(ownerId, "racer-b")));
    let observation: Awaited<ReturnType<typeof db.waitUntilBlocked>> | "finished";
    try {
      observation = await Promise.race([
        db.waitUntilBlocked("b", { by: "a" }),
        other.then(() => "finished" as const),
      ]);
    } finally {
      parked.release();
    }
    expect(observation).not.toBe("finished");
    expect((observation as { query: string }).query).toMatch(CAP_LOCK);
    expect(await first).toMatchObject({ ok: true });
    expect(await other).toMatchObject({ ok: false, error: HOST_LIMIT });
    expect(await hostCount(ownerId)).toBe(2);
  });
});

it("3A unlimited enrollment still takes the host-create advisory before INSERT", async () => {
  capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = null;
  const ownerId = await seedOwner();
  const deviceCode = await approvedDeviceCode(ownerId, "device");
  const held = db.pauseAt("session-create", { before: "sandboxHost.create" });
  const creating = db.run("session-create", () => create(ownerId, "session"));
  await held.waitReached();
  const minting = db.run("device-create", () =>
    mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "device" }),
  );
  try {
    expect((await db.waitUntilBlocked("device-create", { by: "session-create" })).query).toContain(
      "pg_advisory_xact_lock",
    );
  } finally {
    held.release();
  }
  await creating;
  await minting;
  expect(await hostCount(ownerId)).toBe(2);
});

it("T2 rolled-back pending host deletion emits no terminal lifecycle hint and releases its authority hold", async () => {
  const ownerId = await seedOwner(1);
  const host = await db.inspect.sandboxHost.findFirstOrThrow({ where: { userId: ownerId } });
  const { deleteHost } = await import("./hosts");
  const { onAuthorityCommitted, authorityTicket } = await import("@wssp/db/authority");
  const seen: unknown[] = [];
  const off = onAuthorityCommitted((scope) => {
    if (scope.kind === "scoped" && scope.hostId === host.id) seen.push(scope);
  });
  const pause = db.pauseAt("delete", { after: "sandboxHost.updateMany" });
  const work = db.run("delete", () => deleteHost({ kind: "session", ownerId }, { id: host.id }));
  const outcome = work.then(
    () => "committed",
    () => "rolled-back",
  );
  try {
    await pause.waitReached();
    expect(authorityTicket({ ownerId, hostId: host.id })()).toBe(false);
    pause.fail(new Error("injected deletion rollback"));
    expect(await outcome).toBe("rolled-back");
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(seen).toEqual([]);
    expect(authorityTicket({ ownerId, hostId: host.id })()).toBe(true);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
        .deletionRequestedAt,
    ).toBeNull();
  } finally {
    pause.release();
    off();
  }
});

it("contribute-only grantees list only their own hosts excluding live membership; use-only, revoked and ownHostsOnly refuse", async () => {
  const ownerId = await seedOwner(1);
  const contributorId = await seedOwner(2);
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: ownerId, slug: "shared", label: "Shared" },
  });
  const share = await db.inspect.share.create({
    data: {
      poolId: pool.id,
      ownerUserId: ownerId,
      granteeUserId: contributorId,
      canUse: false,
      canContribute: true,
    },
  });
  const own = await db.inspect.sandboxHost.findMany({
    where: { userId: contributorId },
    orderBy: { id: "asc" },
  });
  const principal = { kind: "session" as const, ownerId: contributorId };
  const input = { excludePoolId: pool.id, limit: 20 };
  expect((await listHosts(principal, input)).items.map((h) => h.id).sort()).toEqual(
    own.map((h) => h.id).sort(),
  );
  await db.inspect.sandboxPoolMember.create({
    data: {
      poolId: pool.id,
      userId: ownerId,
      hostOwnerId: contributorId,
      sandboxHostId: own[0]!.id,
      shareId: share.id,
      contributeWitness: true,
      ownHostsOnlyWitness: false,
    },
  });
  expect((await listHosts(principal, input)).items.map((h) => h.id)).toEqual([own[1]!.id]);
  await db.inspect.sandboxPool.update({ where: { id: pool.id }, data: { ownHostsOnly: true } });
  await expect(listHosts(principal, input)).rejects.toMatchObject({ code: "NOT_FOUND" });
  await db.inspect.sandboxPool.update({ where: { id: pool.id }, data: { ownHostsOnly: false } });
  await db.inspect.share.update({
    where: { id: share.id },
    data: { canUse: true, canContribute: false },
  });
  await expect(listHosts(principal, input)).rejects.toMatchObject({ code: "NOT_FOUND" });
  await db.inspect.share.delete({ where: { id: share.id } });
  await expect(listHosts(principal, input)).rejects.toMatchObject({ code: "NOT_FOUND" });
});
