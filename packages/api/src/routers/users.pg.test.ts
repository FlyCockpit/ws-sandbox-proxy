import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import type { Context } from "../context";
import { seedLaunchHost } from "../sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/auth", () => ({
  auth: { api: {}, $context: Promise.resolve({ password: { hash: async () => "hashed" } }) },
}));
const sendEmail = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@wssp/mailer", () => ({
  renderInviteUser: () => ({ subject: "invite", html: "invite" }),
  sendEmail,
  isEmailConfigured: () => true,
}));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => undefined }));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "users-pg-test-secret-long-enough-for-hs256",
  },
  SIGNUP_ENABLED: false,
  ADMIN_EMAILS: new Set<string>(),
}));
const db = await pgTestDatabase();
const { usersRouter } = await import("./users");
const { settingsRouter } = await import("./settings");
const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
const { LastAdminError } = await import("@wssp/db/admin-governance");
const { authorityTicket } = await import("@wssp/db/authority");
afterAll(() => db.close());

async function seed(role = "admin") {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Admin",
      role,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: `test-${id}`, expiresAt: new Date(Date.now() + 60_000) },
  });
  const context = { session: { user, session } } as Context;
  return {
    id,
    client: createRouterClient(usersRouter, { context }),
    settings: createRouterClient(settingsRouter, { context }),
  };
}

it("serializes competing demotions and reauthorizes the losing admin before any effect", async () => {
  const a = await seed();
  const b = await seed();
  const gate = db.pauseAt("a", { before: "user.update" });
  const first = db.run("a", () => a.client.setRole({ userId: b.id, role: "user" }));
  await gate.waitReached();
  const second = db.run("b", () => b.client.setRole({ userId: a.id, role: "user" }));
  const outcome = expect(second).rejects.toMatchObject({ code: "NOT_FOUND" });
  const blocked = await db.waitUntilBlocked("b", { by: "a" });
  expect(blocked.query).toContain("pg_advisory_xact_lock");
  gate.release();
  await expect(first).resolves.toEqual({ success: true });
  await outcome;
  expect((await db.inspect.user.findUniqueOrThrow({ where: { id: a.id } })).role).toBe("admin");
  await db.inspect.user.update({ where: { id: a.id }, data: { role: "user" } });
});

it("preserves the final administrator across concurrent account deletions", async () => {
  const a = await seed();
  const b = await seed("editor,\u00a0ADMIN\ufeff, billing");
  const gate = db.pauseAt("a", { before: "user.deleteMany" });
  const first = db.run("a", () => requestAccountDeletion(a.id));
  await gate.waitReached();
  const second = db.run("b", () => requestAccountDeletion(b.id));
  const outcome = expect(second).rejects.toBeInstanceOf(LastAdminError);
  await db.waitUntilBlocked("b", { by: "a" });
  gate.release();
  await expect(first).resolves.toBe(true);
  await outcome;
  expect(await db.inspect.user.count({ where: { id: b.id } })).toBe(1);
  await db.inspect.user.update({ where: { id: b.id }, data: { role: "user" } });
});

it("refuses offline owner deletion without revocation, then bans with durable C21 cleanup", async () => {
  const admin = await seed();
  const owner = await seed("user");
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: owner.id, slug: "offline", label: "Offline", status: "DISCONNECTED" },
  });
  await expect(admin.client.remove({ userId: owner.id })).rejects.toMatchObject({
    code: "CONFLICT",
    data: { blockers: ["hosts"] },
  });
  expect(await db.inspect.session.count({ where: { userId: owner.id } })).toBe(1);
  expect((await db.inspect.user.findUniqueOrThrow({ where: { id: owner.id } })).banned).not.toBe(
    true,
  );
  const ticket = authorityTicket({ ownerId: owner.id });
  const unrelated = authorityTicket({ ownerId: admin.id });
  await expect(admin.client.archive({ userId: owner.id })).resolves.toEqual({ success: true });
  expect(ticket()).toBe(false);
  expect(unrelated()).toBe(true);
  expect(await db.inspect.session.count({ where: { userId: owner.id } })).toBe(0);
  expect((await db.inspect.user.findUniqueOrThrow({ where: { id: owner.id } })).banned).toBe(true);
  expect(await db.inspect.sandboxHost.count({ where: { id: host.id } })).toBe(1);
  await admin.client.unarchive({ userId: owner.id });
  expect((await db.inspect.user.findUniqueOrThrow({ where: { id: owner.id } })).banned).toBe(false);
  expect(await db.inspect.session.count({ where: { userId: owner.id } })).toBe(0);
  await db.inspect.sandboxHost.delete({ where: { id: host.id } });
  await expect(admin.client.remove({ userId: owner.id })).resolves.toEqual({ success: true });
  await db.inspect.user.update({ where: { id: admin.id }, data: { role: "user" } });
});

it("denies a settings write whose admin was demoted after the entry gate", async () => {
  const a = await seed();
  const b = await seed();
  const gate = db.pauseAt("settings", { before: /pg_advisory_xact_lock/ });
  const pending = db.run("settings", () =>
    b.settings.update({ key: "signupEnabled", value: "true" }),
  );
  const outcome = expect(pending).rejects.toMatchObject({ code: "NOT_FOUND" });
  await gate.waitReached();
  await a.client.setRole({ userId: b.id, role: "user" });
  gate.release();
  await outcome;
  expect(await db.inspect.appSetting.findUnique({ where: { key: "signupEnabled" } })).toBeNull();
  await db.inspect.user.update({ where: { id: a.id }, data: { role: "user" } });
});

it("rolls back a finalization FK failure and names fresh blockers through the admin router", async () => {
  const admin = await seed();
  const owner = await seed("user");
  const finalDelete = db.pauseAt("remove", { before: "user.deleteMany" });
  const pending = db.run("remove", () => admin.client.remove({ userId: owner.id }));
  const refusal = expect(pending).rejects.toMatchObject({
    code: "CONFLICT",
    data: { blockers: ["hosts"] },
  });
  await finalDelete.waitReached();
  const recheck = db.pauseAt("remove", { before: /FROM "user".*FOR UPDATE/ });
  finalDelete.fail(Object.assign(new Error("test FK failure"), { code: "P2003" }));
  await recheck.waitReached();
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: owner.id, slug: "raced", label: "Raced" },
  });
  recheck.release();
  await refusal;
  expect(await db.inspect.session.count({ where: { userId: owner.id } })).toBe(1);
  expect(
    (await db.inspect.user.findUniqueOrThrow({ where: { id: owner.id } })).deletionRequestedAt,
  ).toBeNull();
  await db.inspect.sandboxHost.delete({ where: { id: host.id } });
  await db.inspect.user.update({ where: { id: admin.id }, data: { role: "user" } });
});

it("denies an invitation whose admin was demoted after the entry gate, without mailing", async () => {
  const a = await seed();
  const b = await seed();
  const email = `${randomUUID()}@example.test`;
  sendEmail.mockClear();
  const gate = db.pauseAt("invite", { before: /pg_advisory_xact_lock/ });
  const pending = db.run("invite", () =>
    b.client.invite({ email, name: "Invitee", role: "admin" }),
  );
  const outcome = expect(pending).rejects.toMatchObject({ code: "NOT_FOUND" });
  await gate.waitReached();
  await a.client.setRole({ userId: b.id, role: "user" });
  gate.release();
  await outcome;
  expect(await db.inspect.user.count({ where: { email } })).toBe(0);
  expect(sendEmail).not.toHaveBeenCalled();
  await db.inspect.user.update({ where: { id: a.id }, data: { role: "user" } });
});

it("serializes a demotion behind an in-flight invitation and mails only after commit", async () => {
  const a = await seed();
  const b = await seed();
  const email = `${randomUUID()}@example.test`;
  sendEmail.mockClear();
  const gate = db.pauseAt("invite", { before: "user.create" });
  const pending = db.run("invite", () =>
    b.client.invite({ email, name: "Invitee", role: "admin" }),
  );
  await gate.waitReached();
  // Holding only governance, the demotion waits until the invitation's final
  // response gate has passed, so the success response is deterministic.
  const demoteGate = db.pauseAt("demote", { after: /pg_advisory_xact_lock/ });
  const demotion = db.run("demote", () => a.client.setRole({ userId: b.id, role: "user" }));
  const blocked = await db.waitUntilBlocked("demote", { by: "invite" });
  expect(blocked.query).toContain("pg_advisory_xact_lock");
  expect(sendEmail).not.toHaveBeenCalled();
  gate.release();
  const invited = await pending;
  expect(invited.emailSent).toBe(true);
  expect(sendEmail).toHaveBeenCalledOnce();
  await demoteGate.waitReached();
  demoteGate.release();
  await expect(demotion).resolves.toEqual({ success: true });
  const created = await db.inspect.user.findUniqueOrThrow({
    where: { email },
    include: { accounts: true },
  });
  expect(created.role).toBe("admin");
  expect(created.accounts).toMatchObject([
    { providerId: "credential", accountId: created.id, password: "hashed" },
  ]);
  await db.inspect.user.update({ where: { id: created.id }, data: { role: "user" } });
  await db.inspect.user.update({ where: { id: a.id }, data: { role: "user" } });
});

it("refuses the response when a demotion lands between the invitation commit and the final gate", async () => {
  const a = await seed();
  const b = await seed();
  const email = `${randomUUID()}@example.test`;
  sendEmail.mockClear();
  const write = db.pauseAt("invite", { before: "user.create" });
  const pending = db.run("invite", () =>
    b.client.invite({ email, name: "Invitee", role: "admin" }),
  );
  const outcome = expect(pending).rejects.toMatchObject({ code: "NOT_FOUND" });
  await write.waitReached();
  // The next actor-row lock after the write is the final response gate's.
  const finalGate = db.pauseAt("invite", {
    before: /^sql:SELECT id FROM "user" WHERE id = \? FOR SHARE$/,
  });
  write.release();
  await finalGate.waitReached();
  await expect(a.client.setRole({ userId: b.id, role: "user" })).resolves.toEqual({
    success: true,
  });
  finalGate.release();
  await outcome;
  // The committed account and its post-commit mail stand regardless of the refusal.
  const created = await db.inspect.user.findUniqueOrThrow({
    where: { email },
    include: { accounts: true },
  });
  expect(created.accounts).toMatchObject([{ providerId: "credential", accountId: created.id }]);
  expect(sendEmail).toHaveBeenCalledOnce();
  await db.inspect.user.update({ where: { id: created.id }, data: { role: "user" } });
  await db.inspect.user.update({ where: { id: a.id }, data: { role: "user" } });
});

it("leaves unrelated authority tickets valid across committed and rolled-back invitations", async () => {
  const admin = await seed();
  const owner = await seed("user");
  const ticket = authorityTicket({ ownerId: owner.id });
  const email = `${randomUUID()}@example.test`;
  await expect(
    admin.client.invite({ email, name: "Invitee", role: "user" }),
  ).resolves.toMatchObject({ emailSent: true });
  expect(ticket()).toBe(true);
  // The invitee must replace the admin-known password; only the mailed accept
  // link (Better Auth's verify-email) verifies the address.
  expect(
    await db.inspect.user.findUniqueOrThrow({
      where: { email },
      select: { mustChangePassword: true, emailVerified: true },
    }),
  ).toEqual({ mustChangePassword: true, emailVerified: false });
  const rollback = db.pauseAt("invite", { after: "account.create" });
  const failed = db.run("invite", () =>
    admin.client.invite({ email: `${randomUUID()}@example.test`, name: "Other", role: "user" }),
  );
  await rollback.waitReached();
  // Sampled while the invitation is in flight, then checked after it rolls back.
  const inFlight = authorityTicket({ ownerId: owner.id });
  expect(ticket()).toBe(true);
  rollback.fail(new Error("injected invitation failure"));
  await expect(failed).rejects.toThrow();
  expect(ticket()).toBe(true);
  expect(inFlight()).toBe(true);
  expect(await db.inspect.user.count({ where: { email } })).toBe(1);
  await db.inspect.user.update({ where: { id: admin.id }, data: { role: "user" } });
});

it("serializes a session revocation with the final admin gate instead of accepting it", async () => {
  const admin = await seed();
  const rows = await db.inspect.session.findMany({
    where: { userId: admin.id },
    select: { id: true },
  });
  // The handler's read, then the final gate's user read (the second gate read).
  const handler = db.pauseAt("list", { after: "user.findMany" });
  const pending = db.run("list", () => admin.client.list({ limit: 1 }));
  await handler.waitReached();
  const finalGate = db.pauseAt("list", { before: "user.findUnique" });
  handler.release();
  await finalGate.waitReached();
  const revoke = db.run("revoke", () =>
    db.prisma.$transaction((tx) => tx.session.deleteMany({ where: { userId: admin.id } })),
  );
  await db.waitUntilBlocked("revoke", { by: "list" });
  finalGate.release();
  await expect(pending).resolves.toMatchObject({ users: expect.any(Array) });
  await expect(revoke).resolves.toEqual({ count: rows.length });
  await expect(admin.client.list({ limit: 1 })).rejects.toMatchObject({ code: "NOT_FOUND" });
  await db.inspect.user.update({ where: { id: admin.id }, data: { role: "user" } });
});
