import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const db = await (await import("@wssp/db/testing/pg")).pgTestDatabase();
  const { createPrismaClient } = await import("@wssp/db/client");
  return { default: createPrismaClient({ connectionString: db.url, max: 3 }) };
});
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 3 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "password-race-pg-test-secret-at-least-32-chars",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => true,
  renderResetPassword: () => ({ subject: "Reset", html: "" }),
  renderVerifyEmail: () => ({ subject: "Verify", html: "" }),
  renderTwoFactorOtp: () => ({ subject: "OTP", html: "" }),
  sendEmail: async () => {},
}));
vi.mock("./mcp-plugins", () => ({ resolveMcpPlugins: () => [] }));
vi.mock("../../api/src/sandbox/terminal-budgets", () => ({
  consumeTerminalMintBudget: async () => {},
  consumeHostProofBudget: async () => {},
}));
vi.mock("../../api/src/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));

const db = await pgTestDatabase();
const { default: prisma } = await import("@wssp/db");
const { auth } = await import("./index");
const { handlePasswordAuthRequest } = await import("./password-auth-handler");
const context = await auth.$context;
const oldPassword = "disposable-old-proof-password-13579";
const newPassword = "disposable-new-proof-password-24680";
const base = "http://localhost:3000";
afterAll(async () => {
  await prisma.$disconnect();
  await db.close();
});

function send(path: string, body: object, cookie = "") {
  return handlePasswordAuthRequest(
    auth,
    new Request(`${base}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: base, cookie },
      body: JSON.stringify(body),
    }),
  );
}

it.each(["change-keep", "change-revoke", "reset"] as const)(
  "%s refuses old password proofs paused before and after the session fence",
  async (writer) => {
    for (const point of ["verified", "before-insert"] as const) {
      const id = randomUUID();
      const email = `${id}@example.test`;
      const oldHash = await context.password.hash(oldPassword);
      await db.inspect.user.create({ data: { id, email, name: "Owner", emailVerified: true } });
      await db.inspect.account.create({
        data: { userId: id, accountId: id, providerId: "credential", password: oldHash },
      });
      const initial = await send("/sign-in/email", { email, password: oldPassword });
      expect(initial.status).toBe(200);
      const cookie = initial.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      expect(cookie).toContain("session_token=");
      await db.inspect.session.create({
        data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 60_000) },
      });
      const host = await db.inspect.hostToken.create({
        data: { userId: id, name: "host", lookupPrefix: randomUUID(), secretDigest: randomUUID() },
      });
      const sdk = await db.inspect.sdkKey.create({
        data: {
          userId: id,
          name: "sdk",
          scopes: [],
          lookupPrefix: randomUUID(),
          secretDigest: randomUUID(),
        },
      });
      const code = await db.inspect.deviceCode.create({
        data: {
          userId: id,
          deviceCode: randomUUID(),
          userCode: randomUUID(),
          scope: "host",
          status: "approved",
          expiresAt: new Date(Date.now() + 60_000),
        },
      });
      const reached = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const hooks = context.options.databaseHooks!.session!.create!;
      const verify = context.password.verify;
      const before = hooks.before!;
      let armed = true;
      if (point === "verified") {
        vi.spyOn(context.password, "verify").mockImplementation(async (input) => {
          const valid = await verify(input);
          if (armed && valid && input.hash === oldHash && input.password === oldPassword) {
            armed = false;
            reached.resolve();
            await release.promise;
          }
          return valid;
        });
      } else {
        vi.spyOn(hooks, "before").mockImplementation(async (session, endpoint) => {
          const result = await before(session, endpoint);
          if (armed && session.userId === id && endpoint?.path === "/sign-in/email") {
            armed = false;
            reached.resolve();
            await release.promise;
          }
          return result;
        });
      }
      const signingIn = send("/sign-in/email", { email, password: oldPassword });
      try {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            reached.promise,
            signingIn.then(() => {
              throw new Error("Sign-in finished before barrier");
            }),
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new Error("Sign-in barrier was not reached")), 5_000);
            }),
          ]);
        } finally {
          clearTimeout(timer);
        }
        let changed: Response;
        if (writer === "reset") {
          const token = randomUUID();
          await db.inspect.verification.create({
            data: {
              identifier: `reset-password:${token}`,
              value: id,
              expiresAt: new Date(Date.now() + 60_000),
            },
          });
          changed = await send("/reset-password", { token, newPassword });
        } else {
          changed = await send(
            "/change-password",
            {
              currentPassword: oldPassword,
              newPassword,
              revokeOtherSessions: writer === "change-revoke",
            },
            cookie,
          );
        }
        expect(changed.status, await changed.clone().text()).toBe(200);
        const account = await db.inspect.account.findFirstOrThrow({
          where: { userId: id, providerId: "credential" },
        });
        expect(account.password).not.toBe(oldHash);
        expect(await verify({ hash: account.password!, password: newPassword })).toBe(true);
        const sessions = writer === "reset" ? 0 : writer === "change-revoke" ? 1 : 2;
        expect(await db.inspect.session.count({ where: { userId: id } })).toBe(sessions);
        expect(
          (await db.inspect.hostToken.findUniqueOrThrow({ where: { id: host.id } })).revokedAt ===
            null,
        ).toBe(writer !== "reset");
        expect(
          (await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: sdk.id } })).revokedAt === null,
        ).toBe(writer === "change-keep");
        expect(await db.inspect.deviceCode.count({ where: { id: code.id } })).toBe(
          writer === "reset" ? 0 : 1,
        );
        release.resolve();
        const raced = await signingIn;
        expect(raced.status).toBe(401);
        expect(await raced.json()).toMatchObject({ code: "INVALID_EMAIL_OR_PASSWORD" });
        expect(raced.headers.getSetCookie()).toEqual([]);
        expect(await db.inspect.session.count({ where: { userId: id } })).toBe(sessions);
      } finally {
        release.resolve();
        await signingIn.catch(() => {});
        vi.restoreAllMocks();
      }
    }
  },
  30_000,
);
