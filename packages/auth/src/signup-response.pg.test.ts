import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const base = "http://localhost:3000";
const admins = vi.hoisted(() => new Set<string>());
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 10 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "neutral-signup-auth-test-secret-long-enough",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: admins,
  SIGNUP_ENABLED: false,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => true,
  renderResetPassword: () => ({ subject: "reset", html: "mail" }),
  renderTwoFactorOtp: () => ({ subject: "otp", html: "mail" }),
  renderVerifyEmail: () => ({ subject: "verify", html: "mail" }),
  sendEmail: async () => {},
}));
const db = await pgTestDatabase();
const { auth } = await import("./index");
const { handlePasswordAuthRequest } = await import("./password-auth-handler");
const { runWithAllowedUserCreation } = await import("./user-creation-policy");
const { SIGNUP_SETTING_KEY } = await import("./signup-policy");
afterAll(() => db.close());

const password = "correct-horse-battery-neutral";
const NEUTRAL = '{"token":null,"user":null}';
const PRISMA_METHODS = [
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
  "findMany",
  "count",
  "create",
  "update",
  "updateMany",
  "upsert",
  "delete",
  "deleteMany",
];
const address = () => `${randomUUID()}@example.test`;

function signUp(fields: Record<string, unknown>) {
  return handlePasswordAuthRequest(
    auth,
    new Request(`${base}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: base },
      body: JSON.stringify({ name: "Probe", password, ...fields }),
    }),
  );
}

// Everything an anonymous caller sees, except the clock.
async function observed(response: Response) {
  const headers = [...response.headers].filter(([name]) => name !== "date");
  return { status: response.status, headers, body: await response.text() };
}

async function setSignup(open: boolean) {
  await db.inspect.appSetting.upsert({
    where: { key: SIGNUP_SETTING_KEY },
    create: { key: SIGNUP_SETTING_KEY, value: String(open) },
    update: { value: String(open) },
  });
}

async function registered(verified: boolean) {
  const email = address();
  await setSignup(true);
  expect((await signUp({ email })).status).toBe(200);
  if (verified) await db.inspect.user.update({ where: { email }, data: { emailVerified: true } });
  return email;
}

async function invitation(email: string) {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: { id: ownerId, name: "Inviter", email: `${ownerId}@example.test`, emailVerified: true },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: ownerId, slug: randomUUID(), label: "Pool" },
  });
  const token = `wssp_inv_${randomBytes(32).toString("base64url")}`;
  await db.inspect.shareInvite.create({
    data: {
      poolId: pool.id,
      ownerUserId: ownerId,
      email,
      signupAllowed: true,
      pendingKey: `${pool.id}:${email}`,
      tokenDigest: createHash("sha256").update(token).digest("hex"),
      expiresAt: new Date(Date.now() + 7 * 86400000),
    },
  });
  return token;
}

afterEach(() => admins.clear());

describe("sign-up answers the same for a free and a registered address", () => {
  it("open sign-up: one neutral 200 for free, registered-verified and registered-unverified", async () => {
    const verified = await registered(true);
    const unverified = await registered(false);
    await setSignup(true);
    const free = address();
    const [a, b, c] = [
      await observed(await signUp({ email: free })),
      await observed(await signUp({ email: verified })),
      await observed(await signUp({ email: unverified })),
    ];
    expect(a).toMatchObject({ status: 200, body: NEUTRAL });
    expect(a.headers.some(([name]) => name === "set-cookie")).toBe(false);
    expect(b).toEqual(a);
    expect(c).toEqual(a);
    // The free address really got its account; the others kept theirs.
    expect(
      await db.inspect.user.count({ where: { email: { in: [free, verified, unverified] } } }),
    ).toBe(3);
  });

  it("closed sign-up: the same 422 for free, registered-verified and registered-unverified, with the same work", async () => {
    const verified = await registered(true);
    const unverified = await registered(false);
    await setSignup(false);
    // Record every adapter call (Better Auth's own reads and writes) and the
    // sign-up setting read: a duplicate must not pay for anything a free
    // address does not, or the other way round.
    const adapter = (await auth.$context).adapter as unknown as Record<
      string,
      (...args: unknown[]) => unknown
    >;
    const operations: string[] = [];
    for (const name of ["findOne", "findMany", "count", "create", "update", "updateMany"]) {
      const original = adapter[name]!.bind(adapter);
      vi.spyOn(adapter, name).mockImplementation((...args: unknown[]) => {
        operations.push(`${name}:${(args[0] as { model?: string } | undefined)?.model}`);
        return original(...args);
      });
    }
    // Plus every direct Prisma call the hooks make (setting, invitation, user
    // reads) and raw SQL.
    const prisma = (await import("@wssp/db")).default as unknown as Record<
      string,
      Record<string, (...args: unknown[]) => unknown>
    >;
    for (const model of [
      "user",
      "account",
      "session",
      "verification",
      "appSetting",
      "shareInvite",
    ]) {
      const delegate = prisma[model]!;
      for (const method of PRISMA_METHODS) {
        if (typeof delegate[method] !== "function") continue;
        const original = delegate[method].bind(delegate);
        vi.spyOn(delegate, method).mockImplementation((...args: unknown[]) => {
          operations.push(`${model}.${method}`);
          return original(...args);
        });
      }
    }
    for (const method of ["$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe"]) {
      const raw = prisma as unknown as Record<string, (...args: unknown[]) => unknown>;
      const original = raw[method]!.bind(raw);
      vi.spyOn(raw, method).mockImplementation((...args: unknown[]) => {
        operations.push(method);
        return original(...args);
      });
    }
    // Each invitation shape a caller can send without holding a valid
    // invitation for the address: the free address must not pay the
    // invitation preflight that a registered one skips.
    const elsewhere = await invitation(address());
    const variants: Record<string, (email: string) => Promise<Record<string, unknown>>> = {
      none: async () => ({}),
      "well-formed unknown token": async () => ({
        poolInviteToken: `wssp_inv_${randomBytes(32).toString("base64url")}`,
      }),
      "another address's token": async () => ({ poolInviteToken: elsewhere }),
      "revoked invitation of this address": async (email) => {
        const token = await invitation(email);
        await db.inspect.shareInvite.updateMany({
          where: { email },
          data: { revokedAt: new Date(), pendingKey: null },
        });
        return { poolInviteToken: token };
      },
    };
    const outcomes = [];
    for (const [variant, fields] of Object.entries(variants)) {
      const work = [];
      for (const email of [address(), verified, unverified]) {
        const extra = await fields(email);
        operations.length = 0;
        outcomes.push(await observed(await signUp({ email, ...extra })));
        work.push([...operations]);
      }
      expect(work[0], variant).toContain("appSetting.findUnique");
      expect(
        work[0]?.some((op) => op.startsWith("findOne:user")),
        variant,
      ).toBe(true);
      if (variant !== "none") expect(work[0], variant).toContain("shareInvite.findFirst");
      expect(work[1], variant).toEqual(work[0]);
      expect(work[2], variant).toEqual(work[0]);
    }
    vi.restoreAllMocks();
    expect(outcomes[0]).toMatchObject({ status: 422 });
    expect(JSON.parse(outcomes[0]!.body)).toMatchObject({ code: "FAILED_TO_CREATE_USER" });
    for (const outcome of outcomes) expect(outcome).toEqual(outcomes[0]);
  });

  it("closed sign-up: a real pool-invite or ADMIN_EMAILS creation answers 200; the same address again answers the registered 422", async () => {
    await setSignup(false);
    const invitee = address();
    const token = await invitation(invitee);
    const created = await observed(await signUp({ email: invitee, poolInviteToken: token }));
    expect(created).toMatchObject({ status: 200, body: NEUTRAL });
    expect(await db.inspect.user.count({ where: { email: invitee } })).toBe(1);

    const admin = address();
    admins.add(admin);
    const bootstrap = await observed(
      await runWithAllowedUserCreation("admin-bootstrap", () => signUp({ email: admin })),
    );
    expect(bootstrap).toEqual(created);
    expect((await db.inspect.user.findUniqueOrThrow({ where: { email: admin } })).role).toBe(
      "admin",
    );

    const free = await observed(await signUp({ email: address() }));
    expect(free.status).toBe(422);
    for (const again of [
      await signUp({ email: invitee, poolInviteToken: token }),
      await runWithAllowedUserCreation("admin-bootstrap", () => signUp({ email: admin })),
      await signUp({ email: invitee }),
    ])
      expect(await observed(again)).toEqual(free);
  });
});
