import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

/**
 * The SETUP_KEY first-admin claim against real PostgreSQL: the unique email
 * settles a sign-up racing the claim, and the admin governance lock
 * serializes two claims of one link. Barriers are statement pauses and lock
 * waits observed through pg_stat_activity, never sleeps.
 */
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://wssp.example" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/auth", () => ({
  auth: {
    $context: Promise.resolve({
      password: {
        hash: async (password: string) => `hashed:${password}`,
        config: { minPasswordLength: 12, maxPasswordLength: 128 },
      },
    }),
  },
}));

const db = await pgTestDatabase();
const { bootstrapFirstAdmin, claimFirstAdmin, SETUP_TOKEN_PREFIX } = await import(
  "./admin-bootstrap"
);
const { hasActiveAdministrator } = await import("@wssp/db/admin-governance");
afterAll(() => db.close());

const PASSWORD = "a-long-new-password";

async function issue(email: string): Promise<string> {
  const result = await bootstrapFirstAdmin(email, { ttlSeconds: 3600 });
  if (result.kind !== "ready") throw new Error(`expected a link, got ${result.kind}`);
  return new URL(result.url).searchParams.get("token") ?? "";
}

const setupLinks = () =>
  db.inspect.verification.count({ where: { identifier: { startsWith: SETUP_TOKEN_PREFIX } } });

it("a sign-up that takes the address mid-claim wins the unique email; the claim never promotes it", async () => {
  const token = await issue("raced@example.test");
  // Park the claim after its "address still free" check, inside the locked tx.
  const gate = db.pauseAt("claim", { after: "user.findUnique" });
  const claim = db.run("claim", () => claimFirstAdmin({ token, newPassword: PASSWORD }));
  await gate.waitReached();
  // A Better-Auth sign-up (which takes no governance lock) commits meanwhile.
  const signedUp = await db.inspect.user.create({
    data: { email: "raced@example.test", name: "Someone", emailVerified: false },
    select: { id: true },
  });
  gate.release();

  expect(await claim).toEqual({ kind: "invalid_token" });
  // Rolled back as a whole: the account is untouched and has no password.
  expect(
    await db.inspect.user.findMany({
      where: { email: "raced@example.test" },
      select: { id: true, role: true },
    }),
  ).toEqual([{ id: signedUp.id, role: "user" }]);
  expect(await db.inspect.account.count({ where: { userId: signedUp.id } })).toBe(0);
  expect(await hasActiveAdministrator(db.inspect)).toBe(false);
});

it("two claims of one link serialize on the governance lock: exactly one admin", async () => {
  const token = await issue("owner@example.test");
  const gate = db.pauseAt("first", { after: /pg_advisory_xact_lock/ });
  const first = db.run("first", () => claimFirstAdmin({ token, newPassword: PASSWORD }));
  await gate.waitReached();
  const second = db.run("second", () => claimFirstAdmin({ token, newPassword: PASSWORD }));
  await db.waitUntilBlocked("second", { by: "first" });
  gate.release();

  const outcomes = [await first, await second];
  expect(outcomes[0]).toMatchObject({ kind: "claimed" });
  expect(outcomes[1]).toEqual({ kind: "invalid_token" });

  const admins = await db.inspect.user.findMany({
    where: { email: "owner@example.test" },
    select: { id: true, role: true, emailVerified: true },
  });
  expect(admins).toEqual([
    {
      id: (outcomes[0] as { userId: string }).userId,
      role: "admin",
      emailVerified: true,
    },
  ]);
  expect(
    await db.inspect.account.findMany({
      where: { userId: admins[0]?.id },
      select: { providerId: true, accountId: true, password: true },
    }),
  ).toEqual([
    { providerId: "credential", accountId: admins[0]?.id, password: `hashed:${PASSWORD}` },
  ]);
  expect(await setupLinks()).toBe(0);
  expect(await hasActiveAdministrator(db.inspect)).toBe(true);
});

it("once the administrator exists the key issues nothing more", async () => {
  expect(await bootstrapFirstAdmin("late@example.test", { ttlSeconds: 3600 })).toEqual({
    kind: "admin_exists",
  });
  expect(await setupLinks()).toBe(0);
});
