import { randomUUID } from "node:crypto";
import { authorityTicket, onAuthorityCommitted } from "@wssp/db/authority";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "password-reset-machine-test", SANDBOX_MAX_HOSTS_PER_OWNER: null },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 10 } }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));

const db = await pgTestDatabase();
afterAll(() => db.close());
const { revokeCredentialsAfterPasswordChange } = await import(
  "../../../auth/src/credential-revocation"
);
const { seedLaunchHost, seedMintSession } = await import("../sandbox/testing/resource-fixtures");
const { createHostToken } = await import("../sandbox/services/hosts");
const { mintHostDeviceCredentialFromApprovedDeviceCode } = await import(
  "./host-device-credential-access"
);
const { transitionDeviceCode } = await import("./device-code-transitions");

async function fixture() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Host owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: userId });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "machine", label: "Machine" },
  });
  const code = await db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      userId,
      scope: "host-slug:machine",
      status: "approved",
      enrollmentIntent: "replace",
      replaceHostId: host.id,
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  return { owner, host, code };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
const kinds = ["host token", "host device credential"] as const;
async function mint(kind: (typeof kinds)[number], f: Fixture): Promise<string> {
  if (kind === "host token")
    return (await createHostToken(f.owner, { hostId: f.host.id, name: "Daemon" })).token.id;
  return (
    await mintHostDeviceCredentialFromApprovedDeviceCode({
      deviceCode: f.code.deviceCode,
      hostSlug: "machine",
    })
  ).credentialId;
}
async function machine(kind: (typeof kinds)[number], id: string) {
  return kind === "host token"
    ? db.inspect.hostToken.findUniqueOrThrow({ where: { id } })
    : db.inspect.hostDeviceCredential.findUniqueOrThrow({ where: { id } });
}
async function resetSweep(f: Fixture) {
  // Both production reset hooks pass revokeSessions:true, pinned by index.test.ts.
  await revokeCredentialsAfterPasswordChange(f.owner.ownerId, { revokeSessions: true });
}
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );

it("a reset sweep revokes both machine types and pending host enrollments, owner-scoped", async () => {
  const f = await fixture();
  const other = await fixture();
  const token = await mint("host token", f);
  const device = await mint("host device credential", f);
  const otherToken = await mint("host token", other);
  const otherDevice = await mint("host device credential", other);
  await db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      userId: f.owner.ownerId,
      scope: "host-slug:new-machine",
      status: "pending",
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  await resetSweep(f);
  expect(await machine("host token", token)).toMatchObject({ revokedAt: expect.any(Date) });
  expect(await machine("host device credential", device)).toMatchObject({
    revokedAt: expect.any(Date),
  });
  expect(await machine("host token", otherToken)).toMatchObject({ revokedAt: null });
  expect(await machine("host device credential", otherDevice)).toMatchObject({ revokedAt: null });
  expect(await db.inspect.deviceCode.count({ where: { userId: f.owner.ownerId } })).toBe(0);
  // Recovery revokes authentication, not the host's durable resources or data.
  expect(await db.inspect.sandboxHost.count({ where: { id: f.host.id } })).toBe(1);
});

it.each(kinds)(
  "%s mint holding the owner lock commits before reset and is revoked",
  async (kind) => {
    const f = await fixture();
    const gate = db.pauseAt("mint", {
      after: kind === "host token" ? "hostToken.create" : "hostDeviceCredential.create",
    });
    const minted = settle(db.run("mint", () => mint(kind, f)));
    await gate.waitReached();
    const reset = settle(db.run("reset", () => resetSweep(f)));
    try {
      await db.waitUntilBlocked("reset", { by: "mint" });
    } finally {
      gate.release();
    }
    const [mintedResult, resetResult] = await Promise.all([minted, reset]);
    expect(mintedResult.error).toBeUndefined();
    expect(resetResult.error).toBeUndefined();
    expect(await machine(kind, mintedResult.value!)).toMatchObject({ revokedAt: expect.any(Date) });
  },
);

it.each(kinds)(
  "%s mint waiting for reset cannot leave a usable machine credential",
  async (kind) => {
    const f = await fixture();
    const gate = db.pauseAt("reset", { after: "sdkKey.updateMany" });
    const reset = settle(db.run("reset", () => resetSweep(f)));
    await gate.waitReached();
    const minted = settle(db.run("mint", () => mint(kind, f)));
    try {
      await db.waitUntilBlocked("mint", { by: "reset" });
    } finally {
      gate.release();
    }
    const [mintedResult, resetResult] = await Promise.all([minted, reset]);
    expect(resetResult.error).toBeUndefined();
    expect(mintedResult.error).toMatchObject({
      code: kind === "host token" ? "UNAUTHORIZED" : "NOT_FOUND",
    });
    expect(
      await db.inspect.hostToken.count({ where: { userId: f.owner.ownerId, revokedAt: null } }),
    ).toBe(0);
    expect(
      await db.inspect.hostDeviceCredential.count({
        where: { userId: f.owner.ownerId, revokedAt: null },
      }),
    ).toBe(0);
  },
);

it.each(["claim", "approve"] as const)(
  "a host %s cannot restore enrollment authority from a cookie cached before reset",
  async (action) => {
    const f = await fixture();
    await db.inspect.deviceCode.update({
      where: { id: f.code.id },
      data: { status: "pending", userId: action === "claim" ? null : f.owner.ownerId },
    });
    await resetSweep(f);
    await expect(
      transitionDeviceCode({
        userCode: f.code.userCode,
        userId: f.owner.ownerId,
        sessionId: f.owner.sessionId,
        action,
        intent: { kind: "replace", hostId: f.host.id },
      }),
    ).rejects.toMatchObject({ code: action === "claim" ? "UNAUTHORIZED" : "CONFLICT" });
    if (action === "claim")
      expect(
        await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: f.code.id } }),
      ).toMatchObject({
        userId: null,
        status: "pending",
      });
  },
);

it("a signed-in password change retains machine credentials and approved host enrollments", async () => {
  const f = await fixture();
  const token = await mint("host token", f);
  const device = await mint("host device credential", f);
  const pending = await db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      userId: f.owner.ownerId,
      scope: "host-slug:next-machine",
      status: "approved",
      enrollmentIntent: "create",
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  const currentSession = await db.inspect.session.findUniqueOrThrow({
    where: { id: f.owner.sessionId },
  });
  await revokeCredentialsAfterPasswordChange(f.owner.ownerId, {
    keepSessionToken: currentSession.token,
  });
  expect(await machine("host token", token)).toMatchObject({ revokedAt: null });
  expect(await machine("host device credential", device)).toMatchObject({ revokedAt: null });
  expect(
    await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: pending.id } }),
  ).toMatchObject({
    status: "approved",
  });
});

it("the final sweep fences gap admissions and publishes machine revocation only after commit", async () => {
  const f = await fixture();
  await resetSweep(f);
  // Model a fresh admission between the pre-sweep and final sweep. Even this
  // connection must receive a final committed change, rather than relying on
  // a notification sent before the gap existed.
  const gapOwner = await seedMintSession(db.inspect, {
    kind: "session" as const,
    ownerId: f.owner.ownerId,
  });
  const token = await mint("host token", { ...f, owner: gapOwner });
  const admitted = authorityTicket({ ownerId: f.owner.ownerId });
  expect(admitted()).toBe(true);
  const observations: Promise<unknown>[] = [];
  const off = onAuthorityCommitted((scope) => {
    if (scope.kind !== "scoped" || scope.ownerId !== f.owner.ownerId) return;
    observations.push(machine("host token", token));
  });
  const gate = db.pauseAt("final-reset", { after: "hostToken.updateMany" });
  const resetting = settle(db.run("final-reset", () => resetSweep(f)));
  try {
    try {
      await gate.waitReached();
      expect(admitted()).toBe(false);
      expect(observations).toHaveLength(0);
      // The row is still uncommitted on a separate connection, while admission
      // is already fenced by the owner's in-flight authority mark.
      expect(await machine("host token", token)).toMatchObject({ revokedAt: null });
    } finally {
      gate.release();
    }
    expect((await resetting).error).toBeUndefined();
    await Promise.resolve();
    expect(observations).toHaveLength(1);
    expect(await observations[0]).toMatchObject({ revokedAt: expect.any(Date) });
    expect(admitted()).toBe(false);
  } finally {
    gate.release();
    await resetting;
    off();
  }
});
