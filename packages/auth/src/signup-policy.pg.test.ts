import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

const mail = vi.hoisted(() => ({ urls: [] as string[] }));
const base = "http://localhost:3000";
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-invite-auth-test-secret-long-enough",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set<string>(),
  SIGNUP_ENABLED: false,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => true,
  renderResetPassword: () => ({ subject: "reset", html: "mail" }),
  renderTwoFactorOtp: () => ({ subject: "otp", html: "mail" }),
  renderVerifyEmail: ({ url }: { url: string }) => {
    mail.urls.push(url);
    return { subject: "verify", html: "mail" };
  },
  sendEmail: async () => {},
}));
const db = await pgTestDatabase();
const { auth } = await import("./index");
const { poolInviteSignup } = await import("./signup-policy");
afterAll(() => db.close());
const password = "correct-horse-battery-pool";
async function invite() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: { id, name: "Inviter", email: `${id}@example.test`, emailVerified: true },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: id, slug: randomUUID(), label: "Pool" },
  });
  const email = `${randomUUID()}@example.test`,
    token = `wssp_inv_${randomBytes(32).toString("base64url")}`;
  const row = await db.inspect.shareInvite.create({
    data: {
      poolId: pool.id,
      ownerUserId: id,
      email,
      signupAllowed: true,
      pendingKey: `${pool.id}:${email}`,
      tokenDigest: createHash("sha256").update(token).digest("hex"),
      expiresAt: new Date(Date.now() + 7 * 86400000),
    },
  });
  return { email, token, row, ownerId: id };
}
async function post(body: unknown, path = "/sign-up/email") {
  return auth.handler(
    new Request(`${base}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: base },
      body: JSON.stringify(body),
    }),
  );
}
it.each(["http", "direct"] as const)(
  "%s closed signup binds token+target; real mailbox proof is required and provenance stays private",
  async (transport) => {
    const f = await invite();
    const body = { name: "Invitee", email: f.email, password, poolInviteToken: f.token };
    const response =
      transport === "http"
        ? await post(body)
        : await auth.api.signUpEmail({ body, asResponse: true });
    expect(response.status).toBe(200);
    const json = await response.json();
    expect(JSON.stringify(json)).not.toContain("createdViaPoolInvite");
    let user = await db.inspect.user.findUniqueOrThrow({ where: { email: f.email } });
    expect(user).toMatchObject({
      emailVerified: false,
      createdViaPoolInviteBy: f.ownerId,
      createdViaPoolInviteId: f.row.id,
    });
    expect(await db.inspect.share.count({ where: { poolId: f.row.poolId } })).toBe(0);
    expect((await post({ email: f.email, password }, "/sign-in/email")).status).toBe(403);
    const verification = mail.urls.at(-1)!;
    const token = new URL(verification).searchParams.get("token")!;
    if (transport === "http") await auth.handler(new Request(verification));
    else await auth.api.verifyEmail({ query: { token } });
    user = await db.inspect.user.findUniqueOrThrow({ where: { email: f.email } });
    expect(user.emailVerified).toBe(true);
    expect(await db.inspect.share.count({ where: { poolId: f.row.poolId } })).toBe(0);
    expect(
      (await db.inspect.shareInvite.findUniqueOrThrow({ where: { id: f.row.id } })).pendingKey,
    ).not.toBeNull();
  },
);
it("bad token, mismatched email and missing invite share Better Auth status/body and all pay the hash cost", async () => {
  const f = await invite();
  const context = await auth.$context;
  const hash = vi.spyOn(context.password, "hash");
  const shapes = [];
  for (const fields of [
    { email: `${randomUUID()}@example.test` },
    { email: f.email, poolInviteToken: "invalid" },
    { email: `${randomUUID()}@example.test`, poolInviteToken: f.token },
  ]) {
    const before = hash.mock.calls.length;
    const response = await post({ name: "New", password, ...fields });
    expect(hash.mock.calls.length).toBe(before + 1);
    shapes.push({ status: response.status, body: await response.json() });
  }
  expect(shapes[0]).toEqual(shapes[1]);
  expect(shapes[1]).toEqual(shapes[2]);
  expect(shapes[0]?.status).toBe(422);
  hash.mockRestore();
  expect((await post({ email: f.email, password: 42, poolInviteToken: f.token })).status).toBe(400);
});
it.each(["revoke", "rotate", "expire"] as const)(
  "mailbox proof after %s cannot restore signup eligibility or activate a share",
  async (action) => {
    const f = await invite();
    expect(
      (await post({ email: f.email, name: "Pending", password, poolInviteToken: f.token })).status,
    ).toBe(200);
    const verification = mail.urls.at(-1)!;
    if (action === "revoke")
      await db.inspect.shareInvite.update({
        where: { id: f.row.id },
        data: { revokedAt: new Date(), pendingKey: null },
      });
    else if (action === "rotate")
      await db.inspect.shareInvite.update({
        where: { id: f.row.id },
        data: { tokenDigest: "c".repeat(64) },
      });
    else
      await db.inspect.shareInvite.update({
        where: { id: f.row.id },
        data: { createdAt: new Date(0), expiresAt: new Date(1) },
      });
    await auth.handler(new Request(verification));
    expect(
      (await db.inspect.user.findUniqueOrThrow({ where: { email: f.email } })).emailVerified,
    ).toBe(true);
    expect(await poolInviteSignup({ email: f.email, poolInviteToken: f.token })).toBeNull();
    expect(await db.inspect.share.count({ where: { poolId: f.row.poolId } })).toBe(0);
  },
);
it("concurrent scoped signup creates at most one unverified target account without consuming invitation", async () => {
  const f = await invite();
  const results = await Promise.all([
    post({ email: f.email, name: "Pending", password, poolInviteToken: f.token }),
    post({ email: f.email, name: "Pending", password, poolInviteToken: f.token }),
  ]);
  expect(results.some((r) => r.status === 200)).toBe(true);
  expect(await db.inspect.user.count({ where: { email: f.email, emailVerified: false } })).toBe(1);
  expect(
    (await db.inspect.shareInvite.findUniqueOrThrow({ where: { id: f.row.id } })).pendingKey,
  ).not.toBeNull();
});
