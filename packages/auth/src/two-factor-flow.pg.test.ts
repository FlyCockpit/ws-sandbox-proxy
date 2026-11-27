import { createHmac, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";

/**
 * M7-S12: the REAL Better Auth instance (every plugin wssp configures) against
 * the disposable PostgreSQL schema. Enrollment returned 500 in the smoke run
 * because the two-factor plugin writes columns `TwoFactor` lacked; mocked unit
 * tests could not see it. This walks enable → verify TOTP → sign in with TOTP,
 * including the plugin's failed-attempt counter and lockout columns.
 */

const BASE_URL = "http://localhost:3000";

vi.mock("../../api/src/sandbox/terminal-budgets", () => ({
  consumeTerminalMintBudget: async () => {},
  consumeHostProofBudget: async () => {},
}));
vi.mock("../../api/src/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 10 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: BASE_URL,
    SANDBOX_REQUEST_HMAC_SECRET: "0".repeat(64),
    BETTER_AUTH_SECRET: "two-factor-flow-pg-test-secret-at-least-32-chars",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set<string>(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  renderResetPassword: () => ({ subject: "", html: "" }),
  renderTwoFactorOtp: () => ({ subject: "", html: "" }),
  renderVerifyEmail: () => ({ subject: "", html: "" }),
  sendEmail: vi.fn(async () => undefined),
}));

const db = await pgTestDatabase();
const { auth } = await import("./index");
const { handlePasswordAuthRequest } = await import("./password-auth-handler");
afterAll(() => db.close());

const PASSWORD = "correct-horse-battery-staple";

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), the plugin's defaults. */
function totp(base32Secret: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32Secret.replace(/=+$/, "").toUpperCase())
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes = Buffer.from((bits.match(/.{8}/g) ?? []).map((byte) => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const digest = createHmac("sha1", bytes).update(counter).digest();
  const offset = (digest.at(-1) as number) & 0xf;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

/** A six-digit code guaranteed to differ from `code`. */
function wrongCode(code: string): string {
  return code === "000000" ? "111111" : "000000";
}

/** Cookie header carrying every cookie a response set. */
function cookiesFrom(response: Response, previous = ""): string {
  const jar = new Map(
    previous
      .split("; ")
      .filter(Boolean)
      .map((pair) => pair.split("=", 2) as [string, string]),
  );
  for (const header of response.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const index = (pair ?? "").indexOf("=");
    const name = (pair ?? "").slice(0, index);
    const value = (pair ?? "").slice(index + 1);
    if (value === "") jar.delete(name);
    else jar.set(name, value);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function post(path: string, body: unknown, cookie = ""): Promise<Response> {
  return handlePasswordAuthRequest(
    auth,
    new Request(`${BASE_URL}/api/auth${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: BASE_URL,
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

async function signedInUser(): Promise<{ email: string; userId: string; cookie: string }> {
  const email = `${randomUUID()}@example.test`;
  const signUp = await post("/sign-up/email", { email, password: PASSWORD, name: "Ada" });
  expect(signUp.status, await signUp.clone().text()).toBe(200);
  const user = await db.inspect.user.update({ where: { email }, data: { emailVerified: true } });
  const signIn = await post("/sign-in/email", { email, password: PASSWORD });
  expect(signIn.status, await signIn.clone().text()).toBe(200);
  return { email, userId: user.id, cookie: cookiesFrom(signIn) };
}

async function enrolledUser() {
  const user = await signedInUser();
  const enable = await post("/two-factor/enable", { password: PASSWORD }, user.cookie);
  expect(enable.status, await enable.clone().text()).toBe(200);
  const { totpURI, backupCodes } = (await enable.json()) as {
    totpURI: string;
    backupCodes: string[];
  };
  expect(backupCodes.length).toBeGreaterThan(0);
  const secret = new URL(totpURI).searchParams.get("secret") as string;
  expect(secret).toMatch(/^[A-Z2-7]+=*$/);
  const pending = await db.inspect.twoFactor.findUniqueOrThrow({
    where: { userId: user.userId },
  });
  expect(pending).toMatchObject({ verified: false, failedVerificationCount: 0, lockedUntil: null });

  const verify = await post("/two-factor/verify-totp", { code: totp(secret) }, user.cookie);
  expect(verify.status, await verify.clone().text()).toBe(200);
  expect(
    (await db.inspect.user.findUniqueOrThrow({ where: { id: user.userId } })).twoFactorEnabled,
  ).toBe(true);
  expect(
    (await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } })).verified,
  ).toBe(true);
  return { ...user, secret };
}

async function twoFactorChallenge(email: string): Promise<string> {
  const signIn = await post("/sign-in/email", { email, password: PASSWORD });
  expect(signIn.status, await signIn.clone().text()).toBe(200);
  expect(await signIn.clone().json()).toMatchObject({ twoFactorRedirect: true });
  const cookie = cookiesFrom(signIn);
  expect(cookie).toContain("two_factor");
  return cookie;
}

describe("Better Auth two-factor against the real schema", () => {
  it("enables TOTP, verifies it, and signs in with a TOTP second factor", async () => {
    const user = await enrolledUser();
    const challenge = await twoFactorChallenge(user.email);

    const wrong = await post(
      "/two-factor/verify-totp",
      { code: wrongCode(totp(user.secret)) },
      challenge,
    );
    expect(wrong.status).toBe(401);
    expect(
      (await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } }))
        .failedVerificationCount,
    ).toBe(1);

    const right = await post("/two-factor/verify-totp", { code: totp(user.secret) }, challenge);
    expect(right.status, await right.clone().text()).toBe(200);
    const sessionCookie = cookiesFrom(right, challenge);
    expect(sessionCookie).toContain("session_token");
    expect(
      (await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } }))
        .failedVerificationCount,
    ).toBe(0);

    const session = await auth.handler(
      new Request(`${BASE_URL}/api/auth/get-session`, { headers: { cookie: sessionCookie } }),
    );
    expect(((await session.json()) as { user: { id: string } }).user.id).toBe(user.userId);
  });

  it("locks the second factor after the failure budget is spent", async () => {
    const user = await enrolledUser();
    await db.inspect.twoFactor.update({
      where: { userId: user.userId },
      data: { failedVerificationCount: 9 },
    });
    const challenge = await twoFactorChallenge(user.email);
    const code = totp(user.secret);
    const wrong = await post("/two-factor/verify-totp", { code: wrongCode(code) }, challenge);
    expect(wrong.status).toBe(401);
    const locked = await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } });
    expect(locked.failedVerificationCount).toBe(10);
    expect(locked.lockedUntil?.getTime()).toBeGreaterThan(Date.now());

    const blocked = await post("/two-factor/verify-totp", { code }, challenge);
    expect(blocked.status).toBe(429);
  });
});

it.each(["http", "direct"] as const)(
  "%s refuses cached revoked cookies on BOTH oracle routes before factor comparison",
  async (transport) => {
    const user = await signedInUser();
    await post("/two-factor/enable", { password: PASSWORD }, user.cookie);
    const cached = await auth.api.getSession({ headers: new Headers({ cookie: user.cookie }) });
    expect(cached?.user.id).toBe(user.userId);
    await db.inspect.session.deleteMany({ where: { userId: user.userId } });
    for (const uri of [false, true]) {
      if (transport === "direct") {
        const attempt = uri
          ? auth.api.getTOTPURI({
              body: { password: PASSWORD },
              headers: new Headers({ cookie: user.cookie }),
            })
          : auth.api.verifyTOTP({
              body: { code: "000000" },
              headers: new Headers({ cookie: user.cookie }),
            });
        await expect(attempt).rejects.toMatchObject({ status: "UNAUTHORIZED" });
      } else {
        const response = await post(
          uri ? "/two-factor/get-totp-uri" : "/two-factor/verify-totp",
          uri ? { password: PASSWORD } : { code: "000000" },
          user.cookie,
        );
        expect(response.status).toBe(401);
        expect(await response.text()).not.toContain("otpauth:");
      }
      expect(
        (await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } }))
          .failedVerificationCount,
      ).toBe(0);
    }
  },
);
it.each([
  "__Secure-better-auth.session_token=",
  "better-auth.session_data.0=invalid",
  "__Host-better-auth.session_token=bad",
  "better-auth.session_data=",
])("unresolved session cookie %s cannot enter challenge verification", async (cookie) => {
  const user = await enrolledUser();
  const challenge = await twoFactorChallenge(user.email);
  const response = await post(
    "/two-factor/verify-totp",
    { code: totp(user.secret) },
    `${challenge}; ${cookie}`,
  );
  expect(response.status).toBe(401);
});
it("verified factors cannot redisclose URI or use signed-in verification", async () => {
  const user = await enrolledUser();
  const challenge = await twoFactorChallenge(user.email);
  const login = await post("/two-factor/verify-totp", { code: totp(user.secret) }, challenge);
  expect(login.status).toBe(200);
  const cookie = cookiesFrom(login);
  expect((await post("/two-factor/get-totp-uri", { password: PASSWORD }, cookie)).status).toBe(401);
  expect((await post("/two-factor/verify-totp", { code: totp(user.secret) }, cookie)).status).toBe(
    401,
  );
});
it("enrollment and repeated real challenge success advance the shared maximum watermark without clearing host locks", async () => {
  const user = await enrolledUser();
  const row = await db.inspect.user.findUniqueOrThrow({ where: { id: user.userId } });
  expect(row.hostTerminalLastTotpStep).not.toBeNull();
  const lockedUntil = new Date(Date.now() + 900000);
  await db.inspect.user.update({
    where: { id: user.userId },
    data: { hostTerminalLockedUntil: lockedUntil, hostTerminalFailedAttempts: 9 },
  });
  const challenge = await twoFactorChallenge(user.email);
  expect(
    (await post("/two-factor/verify-totp", { code: totp(user.secret) }, challenge)).status,
  ).toBe(200);
  const next = await db.inspect.user.findUniqueOrThrow({ where: { id: user.userId } });
  expect(next.hostTerminalLastTotpStep).toBeGreaterThanOrEqual(row.hostTerminalLastTotpStep!);
  expect(next.hostTerminalLockedUntil).toEqual(lockedUntil);
  expect(next.hostTerminalFailedAttempts).toBe(9);
});
it.each(["http", "direct"] as const)(
  "%s failed after-hook suppresses every success cookie/token and deletes newly created session",
  async (transport) => {
    const user = await enrolledUser();
    const challenge = await twoFactorChallenge(user.email);
    const pause = db.pauseAt("login", { before: /sql:SELECT id FROM "user".*FOR NO KEY UPDATE/ });
    const action = db.run("login", () =>
      transport === "http"
        ? post("/two-factor/verify-totp", { code: totp(user.secret), trustDevice: true }, challenge)
        : auth.api.verifyTOTP({
            body: { code: totp(user.secret), trustDevice: true },
            headers: new Headers({ cookie: challenge }),
            asResponse: true,
          }),
    );
    try {
      await pause.waitReached();
      await db.inspect.twoFactor.update({
        where: { userId: user.userId },
        data: { secret: "replaced-after-comparison" },
      });
    } finally {
      pause.release();
    }
    const response = await action;
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await response.json()).not.toHaveProperty("token");
    // Only enrollment's prior session remains; challenge's newly minted row is gone.
    expect(await db.inspect.session.count({ where: { userId: user.userId } })).toBe(1);
  },
);

it("real auth challenge→host replay and after-hook→host mint race share the User watermark", async () => {
  const user = await enrolledUser();
  const challenge = await twoFactorChallenge(user.email);
  // One code for the login and every replay below: a second `totp()` call
  // that crossed a 30 s step boundary would be a fresh, legitimately
  // accepted code, not a replay.
  const code = totp(user.secret);
  const response = await post("/two-factor/verify-totp", { code }, challenge);
  const login = await auth.api.getSession({
    headers: new Headers({ cookie: cookiesFrom(response) }),
  });
  if (!login) throw new Error("missing successful login");
  const { seedLaunchHost } = await import("../../api/src/sandbox/testing/resource-fixtures");
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: user.userId,
      slug: randomUUID(),
      label: "Proof host",
      status: "CONNECTED",
      connectionEpoch: 1,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
    },
  });
  const { bindHostTerminalPolicy } = await import("../../api/src/sandbox/host-terminal-policy");
  const { mintHostTerminalTicket } = await import("../../api/src/sandbox/host-terminal-tickets");
  const { factorFingerprint } = await import("@wssp/db/terminal-proof");
  const factor = await db.inspect.twoFactor.findUniqueOrThrow({ where: { userId: user.userId } });
  await db.inspect.user.update({
    where: { id: user.userId },
    data: {
      hostTerminalFactorFingerprint: factorFingerprint(factor),
      hostTerminalFactorObservedAt: new Date(Date.now() - 660000),
    },
  });
  // Proof integration only: relay transport itself is covered in server PG.
  bindHostTerminalPolicy({
    read: () => ({
      hostTerminal: true,
      requireHostTerminalTotp: true,
      policyRevision: 1,
      epoch: 1,
    }),
    raise: async () => false,
    authorize: async () => true,
  });
  const owner = { userId: user.userId, sessionId: login.session.id };
  const input = { hostId: host.id, rows: 24, cols: 80, code };
  try {
    await expect(mintHostTerminalTicket(owner, input)).rejects.toMatchObject({ code: "FORBIDDEN" });
    const nextChallenge = await twoFactorChallenge(user.email);
    const pause = db.pauseAt("auth", { after: /sql:SELECT id FROM "user".*FOR NO KEY UPDATE/ });
    const authWork = db.run("auth", () =>
      post("/two-factor/verify-totp", { code: input.code }, nextChallenge),
    );
    await pause.waitReached();
    const hostWork = db.run("host", () => mintHostTerminalTicket(owner, input));
    const hostResult = hostWork.then(
      () => "accepted",
      () => "refused",
    );
    try {
      await db.waitUntilBlocked("host", { by: "auth" });
    } finally {
      pause.release();
    }
    expect((await authWork).status).toBe(200); // Preserve plugin login reuse semantics.
    expect(await hostResult).toBe("refused");
    expect(await db.inspect.hostTerminalTicket.count({ where: { userId: user.userId } })).toBe(0);
  } finally {
    bindHostTerminalPolicy(null);
  }
});
