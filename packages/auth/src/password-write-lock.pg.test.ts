import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const database = await (await import("@wssp/db/testing/pg")).pgTestDatabase();
  const { createPrismaClient } = await import("@wssp/db/client");
  // Exercise the minimum supported production pool, not the inspector pool.
  return { default: createPrismaClient({ connectionString: database.url, max: 3 }) };
});
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 3 } }));

const database = await pgTestDatabase();
const { default: prisma } = await import("@wssp/db");
const { passwordWriteLockHeld, withPasswordWriteLock } = await import("./password-write-lock");
const { revokeCredentialsAfterPasswordChange } = await import("./credential-revocation");
afterAll(async () => {
  await prisma.$disconnect();
  await database.close();
});

async function fixture() {
  const userId = randomUUID();
  const token = randomUUID();
  await database.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test`, emailVerified: true },
  });
  const account = await database.inspect.account.create({
    data: { userId, accountId: userId, providerId: "credential", password: "old" },
  });
  const session = await database.inspect.session.create({
    data: { userId, token: randomUUID(), expiresAt: new Date(Date.now() + 3_600_000) },
  });
  await database.inspect.verification.create({
    data: {
      identifier: `reset-password:${token}`,
      value: userId,
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  return { userId, token, account, session };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
function post(path: string, token?: string) {
  return new Request(`https://app.example.test/api/auth${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, newPassword: "replacement-password" }),
  });
}
const noSession = async () => null;
const cachedSession = (f: Fixture) => async () => ({
  user: { id: f.userId },
  session: { id: f.session.id },
});

it("holds the real advisory lock across a change and orders a reset after its password write", async () => {
  const f = await fixture();
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const changed = withPasswordWriteLock(
    "/change-password",
    post("/change-password"),
    async () => {
      expect(passwordWriteLockHeld()).toBe(true);
      entered.resolve();
      await release.promise;
      await prisma.account.update({ where: { id: f.account.id }, data: { password: "changed" } });
      return new Response(null, { status: 200 });
    },
    { getSession: cachedSession(f) },
  );
  await entered.promise;
  const reset = withPasswordWriteLock(
    "/reset-password",
    post("/reset-password", f.token),
    async () => {
      await prisma.account.update({ where: { id: f.account.id }, data: { password: "recovered" } });
      return new Response(null, { status: 200 });
    },
    { getSession: noSession },
  );
  try {
    // A separate PostgreSQL connection proves the handler actually holds the
    // production advisory key, independent of the in-process held flag.
    const [probe] = await database.inspect.$queryRaw<{ locked: boolean }[]>`
      SELECT pg_try_advisory_xact_lock(hashtext(${`password-write:${f.userId}`})) AS locked`;
    expect(probe?.locked).toBe(false);
  } finally {
    release.resolve();
  }
  expect((await changed).status).toBe(200);
  expect((await reset).status).toBe(200);
  expect(
    await database.inspect.account.findUniqueOrThrow({ where: { id: f.account.id } }),
  ).toMatchObject({
    password: "recovered",
  });
});

it("rechecks a queued change's cached session after a real reset releases its lock", async () => {
  const f = await fixture();
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const reset = withPasswordWriteLock(
    "/reset-password",
    post("/reset-password", f.token),
    async () => {
      await revokeCredentialsAfterPasswordChange(f.userId, { revokeSessions: true });
      entered.resolve();
      await release.promise;
      await prisma.account.update({ where: { id: f.account.id }, data: { password: "recovered" } });
      return new Response(null, { status: 200 });
    },
    { getSession: noSession },
  );
  await entered.promise;
  const handler = vi.fn(async () => {
    await prisma.account.update({ where: { id: f.account.id }, data: { password: "attacker" } });
    return new Response(null, { status: 200 });
  });
  const change = withPasswordWriteLock("/change-password", post("/change-password"), handler, {
    getSession: cachedSession(f),
  });
  release.resolve();
  expect((await reset).status).toBe(200);
  expect((await change).status).toBe(401);
  expect(handler).not.toHaveBeenCalled();
  expect(
    await database.inspect.account.findUniqueOrThrow({ where: { id: f.account.id } }),
  ).toMatchObject({
    password: "recovered",
  });
});

it("two password writers and nested credential sweeps finish with a real three-connection pool", async () => {
  const fixtures = await Promise.all([fixture(), fixture()]);
  const responses = await Promise.all(
    fixtures.map((f) =>
      withPasswordWriteLock(
        "/reset-password",
        post("/reset-password", f.token),
        async () => {
          await prisma.account.update({
            where: { id: f.account.id },
            data: { password: "recovered" },
          });
          await revokeCredentialsAfterPasswordChange(f.userId, { revokeSessions: true });
          return new Response(null, { status: 200 });
        },
        { getSession: noSession },
      ),
    ),
  );
  expect(responses.map((response) => response.status)).toEqual([200, 200]);
  for (const f of fixtures) {
    expect(await database.inspect.session.count({ where: { userId: f.userId } })).toBe(0);
    expect(
      await database.inspect.account.findUniqueOrThrow({ where: { id: f.account.id } }),
    ).toMatchObject({
      password: "recovered",
    });
  }
});
