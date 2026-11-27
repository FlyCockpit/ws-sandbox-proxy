import { randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const base = "http://localhost:3000";
const fixture = vi.hoisted(() => ({
  events: [] as { pid: number; txid: string; point: string; key?: unknown }[],
  active: 0,
  peak: 0,
  after: undefined as
    | ((point: string, args: unknown[], tx: Prisma.TransactionClient) => Promise<void>)
    | undefined,
  beforeCommit: undefined as
    | ((password: boolean, verified: boolean, tx: Prisma.TransactionClient) => Promise<void>)
    | undefined,
}));
vi.mock("@wssp/db", async () => {
  const db = await (await import("@wssp/db/testing/pg")).pgTestDatabase();
  const { createPrismaClient } = await import("@wssp/db/client");
  const raw = createPrismaClient({ connectionString: db.url, max: 3 });
  // Owned fixture wrapper preserves every production query extension. It only
  // observes/pauses statements and injects errors before the real COMMIT.
  const wrap = (client: typeof raw): typeof raw =>
    new Proxy(client, {
      get(target, property, receiver) {
        const value: unknown = Reflect.get(target, property, receiver);
        if (property === "$extends" && typeof value === "function")
          return (...args: unknown[]) => wrap(Reflect.apply(value, target, args));
        if (property !== "$transaction" || typeof value !== "function") return value;
        return (work: unknown, options?: unknown) => {
          if (typeof work !== "function") return Reflect.apply(value, target, [work, options]);
          return Reflect.apply(value, target, [
            async (tx: Prisma.TransactionClient) => {
              fixture.active++;
              fixture.peak = Math.max(fixture.peak, fixture.active);
              const [backend] = await tx.$queryRaw<
                { pid: number; txid: string }[]
              >`SELECT pg_backend_pid() AS pid, txid_current()::text AS txid`;
              const { pid, txid } = backend!;
              let password = false;
              let verified = false;
              const invoke = async (owner: object, fn: unknown, point: string, args: unknown[]) => {
                const data = (args[0] as { data?: Record<string, unknown> } | undefined)?.data;
                if (point.startsWith("account.") && data?.password !== undefined) password = true;
                if (point.startsWith("user.") && data?.emailVerified === true) verified = true;
                const key = point.startsWith("sql:") ? args[1] : undefined;
                fixture.events.push({ pid, txid, point, key });
                if (typeof fn !== "function")
                  throw new Error("Fixture expected a callable Prisma method");
                const result = await Reflect.apply(fn, owner, args);
                await fixture.after?.(point, args, tx);
                return result;
              };
              const observed = new Proxy(tx, {
                get(owner, key, innerReceiver) {
                  const member: unknown = Reflect.get(owner, key, innerReceiver);
                  if (typeof key !== "string") return member;
                  if (["$queryRaw", "$executeRaw"].includes(key) && typeof member === "function")
                    return (...args: unknown[]) => {
                      const sql = (args[0] as readonly string[])
                        .join("?")
                        .replace(/\s+/g, " ")
                        .trim();
                      return invoke(owner, member, `sql:${sql}`, args);
                    };
                  if (member && typeof member === "object")
                    return new Proxy(member, {
                      get(delegate, method, delegateReceiver) {
                        const fn: unknown = Reflect.get(delegate, method, delegateReceiver);
                        if (typeof fn !== "function" || typeof method !== "string") return fn;
                        return (...args: unknown[]) =>
                          invoke(delegate, fn, `${key}.${method}`, args);
                      },
                    });
                  return member;
                },
              });
              try {
                const result = await work(observed);
                await fixture.beforeCommit?.(password, verified, tx);
                return result;
              } finally {
                fixture.active--;
              }
            },
            options,
          ]);
        };
      },
    });
  return { default: wrap(raw) };
});
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 3 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "mailed-reset-pg-test-secret-at-least-32-chars",
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
const { createEmailVerificationToken } = await import("better-auth/api");
const { onAuthSessionsRevoked } = await import("@wssp/db/session-revocation");
const { authorityTicket, onAuthorityCommitted } = await import("@wssp/db/authority");
const { revokeCredentialsAfterPasswordChange } = await import("./credential-revocation");
const context = await auth.$context;
const chosen = "only-the-invitee-knows-this-password";
afterAll(async () => {
  await prisma.$disconnect();
  await db.close();
});
afterEach(() => {
  fixture.after = undefined;
  fixture.beforeCommit = undefined;
  fixture.events.length = 0;
  fixture.peak = 0;
  vi.restoreAllMocks();
});

async function invitee() {
  const id = randomUUID();
  const email = `${id}@example.test`;
  await db.inspect.user.create({ data: { id, email, name: "Invitee", mustChangePassword: true } });
  const oldHash = await context.password.hash("administrator-known-temporary-password");
  await db.inspect.account.create({
    data: { userId: id, accountId: id, providerId: "credential", password: oldHash },
  });
  return { id, email, oldHash };
}
type Invitee = Awaited<ReturnType<typeof invitee>>;
async function mailed(user: Invitee) {
  const token = randomUUID();
  await db.inspect.verification.create({
    data: {
      identifier: `reset-password:${token}`,
      value: user.id,
      expiresAt: new Date(Date.now() + 600_000),
    },
  });
  return token;
}
const reset = (token: string, newPassword = chosen) =>
  handlePasswordAuthRequest(
    auth,
    new Request(`${base}/api/auth/reset-password`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: base },
      body: JSON.stringify({ token, newPassword }),
    }),
  );
async function verify(user: Invitee) {
  const token = await createEmailVerificationToken(context.secret, user.email);
  return handlePasswordAuthRequest(
    auth,
    new Request(`${base}/api/auth/verify-email?token=${token}`),
  );
}
const flags = (id: string) =>
  db.inspect.user.findUniqueOrThrow({
    where: { id },
    select: { emailVerified: true, mustChangePassword: true },
  });
const password = async (id: string) =>
  (await db.inspect.account.findFirstOrThrow({ where: { userId: id, providerId: "credential" } }))
    .password;
const links = (id: string) =>
  db.inspect.verification.count({
    where: { value: id, identifier: { startsWith: "reset-password:" } },
  });
const gate = () => Promise.withResolvers<void>();

/** Missing lock/barrier is a failure; no elapsed-time pass. */
async function reached<T>(signal: Promise<T>, operation: Promise<Response>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      signal,
      operation.then(async (r) => {
        expect(r.status, `Endpoint failed before barrier: ${await r.clone().text()}`).toBe(200);
        throw new Error(`Endpoint returned ${r.status} before barrier: ${await r.text()}`);
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Required PG barrier was not reached")), 5_000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

describe("real mailed reset / verify-email activation transactions (pool3)", () => {
  it.each(["write", "commit", "temporary-cleanup"] as const)(
    "rolls back token/password/temporary-state on actual %s failure and retries same token",
    async (failure) => {
      const user = await invitee();
      const token = await mailed(user);
      await mailed(user);
      let injected = false;
      fixture.after = async (point, args) => {
        const data = (args[0] as { data?: Record<string, unknown> } | undefined)?.data;
        if (
          !injected &&
          ((failure === "write" && point === "account.updateMany" && data?.password) ||
            (failure === "temporary-cleanup" &&
              point === "user.updateMany" &&
              data?.mustChangePassword === false))
        ) {
          injected = true;
          throw new Error(`owned fixture ${failure} failure after real statement`);
        }
      };
      fixture.beforeCommit = async (written) => {
        if (failure === "commit" && written && !injected) {
          injected = true;
          throw new Error("owned fixture failure before real commit");
        }
      };
      const after = vi.spyOn(context.options.databaseHooks!.account!.update!, "after");
      expect((await reset(token)).status).toBe(500);
      expect(injected).toBe(true);
      expect(after).not.toHaveBeenCalled();
      expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: true });
      expect(await password(user.id)).toBe(user.oldHash);
      expect(await links(user.id)).toBe(2);
      expect((await reset(token)).status).toBe(200);
      expect(after).toHaveBeenCalledOnce();
      expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: false });
      expect(
        await context.password.verify({ hash: (await password(user.id))!, password: chosen }),
      ).toBe(true);
      expect(await links(user.id)).toBe(0);
    },
  );

  it("password, token cleanup and temporary cleanup share the owner-locked transaction; afterhooks see commit", async () => {
    const user = await invitee();
    const token = await mailed(user);
    const entered = gate();
    const release = gate();
    fixture.beforeCommit = async (written) => {
      if (!written) return;
      entered.resolve();
      await release.promise;
    };
    const hooks = context.options.databaseHooks!.account!.update!;
    const original = hooks.after!;
    const after = vi.spyOn(hooks, "after").mockImplementation(async (...args) => {
      expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: false });
      expect(await links(user.id)).toBe(0);
      await original(...args);
    });
    const spending = reset(token);
    try {
      await reached(entered.promise, spending);
      expect(after).not.toHaveBeenCalled();
      expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: true });
      expect(await password(user.id)).toBe(user.oldHash);
      expect(await links(user.id)).toBe(1);
      const update = fixture.events.findLast((e) => e.point === "account.updateMany")!;
      const owner = fixture.events.findLast((e) => e.point.includes("FOR NO KEY UPDATE"))!;
      // Pooled connections can reuse a backend PID for separate transactions.
      expect(owner.txid).toBe(update.txid);
      expect(owner.pid).toBe(update.pid);
      expect(fixture.events.filter((e) => e.txid === update.txid).map((e) => e.point)).toEqual(
        expect.arrayContaining([
          "verification.delete",
          "verification.deleteMany",
          "user.updateMany",
        ]),
      );
      const other = db.inspect.$transaction(async (tx) => {
        const [row] = await tx.$queryRaw<{ locked: boolean }[]>`
          SELECT pg_try_advisory_xact_lock(hashtext(${`password-write:${user.id}`})) AS locked`;
        expect(row?.locked).toBe(false);
      });
      await other;
      release.resolve();
      expect((await spending).status).toBe(200);
      expect(after).toHaveBeenCalledOnce();
      expect(fixture.peak).toBeLessThanOrEqual(2);
    } finally {
      release.resolve();
      await spending;
    }
  });

  it.each(["first", "second"])(
    "two mailed tokens: %s wins and the prechecked competitor loses",
    async (first) => {
      const user = await invitee();
      const tokens = { first: await mailed(user), second: await mailed(user) };
      const entered = gate();
      const release = gate();
      const original = context.password.hash;
      vi.spyOn(context.password, "hash").mockImplementationOnce(async (value) => {
        entered.resolve();
        await release.promise;
        return original(value);
      });
      const winning = reset(tokens[first as keyof typeof tokens], `${first}-password-only-invitee`);
      await reached(entered.promise, winning);
      const other = first === "first" ? "second" : "first";
      const queued = gate();
      const read = prisma.verification.findFirst.bind(prisma.verification);
      const lookup = vi.spyOn(prisma.verification, "findFirst").mockImplementation((args) => {
        if (args?.where?.identifier === `reset-password:${tokens[other]}`) queued.resolve();
        return read(args);
      });
      const losing = reset(tokens[other], "losing-password-never-installed");
      try {
        await reached(queued.promise, losing);
        release.resolve();
        expect((await winning).status).toBe(200);
        expect((await losing).status).toBe(400);
        expect(
          await context.password.verify({
            hash: (await password(user.id))!,
            password: `${first}-password-only-invitee`,
          }),
        ).toBe(true);
        expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: false });
        expect(await links(user.id)).toBe(0);
      } finally {
        release.resolve();
        lookup.mockRestore();
        await Promise.allSettled([winning, losing]);
      }
    },
  );

  it.each(["reset", "verify"])(
    "real %s first serializes the other mailed-proof writer",
    async (first) => {
      const user = await invitee();
      const token = await mailed(user);
      const entered = gate();
      const release = gate();
      let paused = false;
      if (first === "reset") {
        const original = context.password.hash;
        vi.spyOn(context.password, "hash").mockImplementationOnce(async (value) => {
          entered.resolve();
          await release.promise;
          return original(value);
        });
      } else {
        fixture.after = async (point, args) => {
          if (!paused && point.includes("FOR NO KEY UPDATE") && args[1] === user.id) {
            paused = true;
            entered.resolve();
            await release.promise;
          }
        };
      }
      const winning = first === "reset" ? reset(token) : verify(user);
      await reached(entered.promise, winning);
      const queued = gate();
      const lookup = prisma.verification.findFirst.bind(prisma.verification);
      vi.spyOn(prisma.verification, "findFirst").mockImplementation((args) => {
        if (args?.where?.identifier === `reset-password:${token}`) queued.resolve();
        return lookup(args);
      });
      const losing = first === "reset" ? verify(user) : reset(token);
      try {
        if (first === "verify") await reached(queued.promise, losing);
        release.resolve();
        expect((await winning).status).toBe(200);
        expect((await losing).status).toBe(first === "reset" ? 200 : 400);
        expect(await flags(user.id)).toEqual({
          emailVerified: true,
          mustChangePassword: first !== "reset",
        });
        expect(
          first === "reset"
            ? await context.password.verify({ hash: (await password(user.id))!, password: chosen })
            : (await password(user.id)) === user.oldHash,
        ).toBe(true);
        expect(await links(user.id)).toBe(0);
      } finally {
        release.resolve();
        await Promise.allSettled([winning, losing]);
      }
    },
  );

  it("verification proof and reset invalidation roll back together under PW then owner on one backend", async () => {
    const user = await invitee();
    await mailed(user);
    let injected = false;
    fixture.beforeCommit = async (_password, verified) => {
      if (verified && !injected) {
        injected = true;
        throw new Error("owned fixture verify commit failure");
      }
    };
    expect((await verify(user)).status).toBe(500);
    expect(injected).toBe(true);
    expect(await flags(user.id)).toEqual({ emailVerified: false, mustChangePassword: true });
    expect(await links(user.id)).toBe(1);
    const writer = fixture.events.findLast((e) => e.point === "user.update")!;
    const statements = fixture.events.filter((e) => e.txid === writer.txid);
    const pw = statements.findIndex((e) => e.key === `password-write:${user.id}`);
    const owner = statements.findIndex((e) => e.point.includes("FOR NO KEY UPDATE"));
    expect(pw).toBeGreaterThanOrEqual(0);
    expect(owner).toBeGreaterThan(pw);
    expect(statements.some((e) => e.point === "verification.deleteMany")).toBe(true);
    expect((await verify(user)).status).toBe(200);
    expect(await flags(user.id)).toEqual({ emailVerified: true, mustChangePassword: true });
    expect(await password(user.id)).toBe(user.oldHash);
    expect(await links(user.id)).toBe(0);
  });

  it("in-transaction revocation reuses the reset client and publishes authority/session signals only on commit", async () => {
    const user = await invitee();
    const token = await mailed(user);
    const seen = vi.fn();
    const notified = vi.fn();
    const off = onAuthorityCommitted(seen);
    const offSessions = onAuthSessionsRevoked(notified);
    const original = context.adapter.transaction.bind(context.adapter);
    const entered = gate();
    const release = gate();
    vi.spyOn(context.adapter, "transaction").mockImplementation((callback) =>
      original(async (adapter) => {
        const result = await callback(adapter);
        // The fixture invokes an existing service inside the real adapter's ALS.
        seen.mockClear();
        notified.mockClear();
        const ticket = authorityTicket({ ownerId: user.id });
        await revokeCredentialsAfterPasswordChange(user.id, { revokeSessions: true });
        expect(ticket()).toBe(false);
        expect(seen).not.toHaveBeenCalled();
        expect(notified).not.toHaveBeenCalled();
        entered.resolve();
        await release.promise;
        return result;
      }),
    );
    const spending = reset(token);
    try {
      await reached(entered.promise, spending);
      expect(fixture.peak).toBeLessThanOrEqual(2);
      const writer = fixture.events.findLast((e) => e.point === "account.updateMany")!;
      expect(fixture.events.findLast((e) => e.point === "hostToken.updateMany")?.txid).toBe(
        writer.txid,
      );
      expect(fixture.events.findLast((e) => e.point === "hostToken.updateMany")?.pid).toBe(
        writer.pid,
      );
      // Spare connection still answers ordinary BA reads while both are held.
      expect((await context.internalAdapter.findUserById(user.id))?.id).toBe(user.id);
      release.resolve();
      expect((await spending).status).toBe(200);
      await Promise.resolve();
      expect(seen).toHaveBeenCalledWith({ kind: "scoped", ownerId: user.id });
      expect(notified).toHaveBeenCalledWith({ userId: user.id });
    } finally {
      release.resolve();
      await spending;
      off();
      offSessions();
    }
  });
  it.each(["reset", "verify"] as const)(
    "%s waits for the real owner row while already holding PW, with ordinary pool3 progress",
    async (operation) => {
      const user = await invitee();
      const token = await mailed(user);
      const hashed = gate();
      const continueHash = gate();
      if (operation === "reset") {
        const original = context.password.hash;
        vi.spyOn(context.password, "hash").mockImplementationOnce(async (value) => {
          hashed.resolve();
          await continueHash.promise;
          return original(value);
        });
      }
      let writing: Promise<Response> | undefined;
      if (operation === "reset") {
        writing = reset(token);
        await reached(hashed.promise, writing);
      }
      const held = gate();
      const releaseOwner = gate();
      const blocker = db.inspect.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${user.id} FOR NO KEY UPDATE`;
        held.resolve();
        await releaseOwner.promise;
      });
      await held.promise;
      if (operation === "verify") writing = verify(user);
      const request = writing!;
      continueHash.resolve();
      try {
        const deadline = performance.now() + 5_000;
        let blocked: { pid: number }[] = [];
        while (performance.now() < deadline) {
          blocked = await db.inspect.$queryRaw<{ pid: number }[]>`
          SELECT pid FROM pg_stat_activity WHERE datname = current_database()
          AND wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0
          AND query LIKE '%FOR NO KEY UPDATE%'`;
          if (blocked.length > 0) break;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        expect(blocked).toHaveLength(1);
        const ownerAttempt = fixture.events.findLast((e) => e.point.includes("FOR NO KEY UPDATE"))!;
        expect(ownerAttempt.pid).toBe(blocked[0]!.pid);
        const [pw] = await db.inspect.$queryRaw<{ locked: boolean }[]>`
        SELECT pg_try_advisory_xact_lock(hashtext(${`password-write:${user.id}`})) AS locked`;
        expect(pw?.locked).toBe(false);
        expect((await context.internalAdapter.findUserById(user.id))?.id).toBe(user.id);
        expect(fixture.peak).toBeLessThanOrEqual(2);
        releaseOwner.resolve();
        expect((await request).status).toBe(200);
      } finally {
        continueHash.resolve();
        releaseOwner.resolve();
        await Promise.allSettled([request, blocker]);
      }
    },
  );

  it("real verify-email invalidates a token whose request already selected its owner before locking", async () => {
    const user = await invitee();
    const token = await mailed(user);
    const entered = gate();
    const release = gate();
    let paused = false;
    const original = prisma.verification.findFirst.bind(prisma.verification);
    vi.spyOn(prisma.verification, "findFirst").mockImplementation((args) => {
      const read = original(args);
      if (args?.where?.identifier !== `reset-password:${token}` || paused) return read;
      paused = true;
      return (async () => {
        const row = await read;
        expect(row?.value).toBe(user.id);
        entered.resolve();
        await release.promise;
        return row;
      })() as ReturnType<typeof prisma.verification.findFirst>;
    });
    const spending = reset(token);
    try {
      await reached(entered.promise, spending);
      expect((await verify(user)).status).toBe(200);
      expect(await links(user.id)).toBe(0);
      release.resolve();
      expect((await spending).status).toBe(400);
      expect(await password(user.id)).toBe(user.oldHash);
      expect(await flags(user.id)).toEqual({ emailVerified: true, mustChangePassword: true });
    } finally {
      release.resolve();
      await spending;
    }
  });
  it.each([true, false])(
    "extended Prisma session notifications publish only after reset commit=%s",
    async (commit) => {
      const user = await invitee();
      const token = await mailed(user);
      const notified = vi.fn();
      const off = onAuthSessionsRevoked(notified);
      let resetStarted = false;
      fixture.after = async (point) => {
        if (point === "verification.delete" && !resetStarted) {
          resetStarted = true;
          // Independent pre-sweep already committed and may notify.
          notified.mockClear();
        }
      };
      fixture.beforeCommit = async (written) => {
        if (!written) return;
        expect(resetStarted).toBe(true);
        expect(notified).not.toHaveBeenCalled();
        if (!commit) throw new Error("owned fixture reset notification rollback");
      };
      try {
        expect((await reset(token)).status).toBe(commit ? 200 : 500);
        await Promise.resolve();
        if (commit) expect(notified).toHaveBeenCalledWith({ userId: user.id });
        else expect(notified).not.toHaveBeenCalled();
      } finally {
        off();
      }
    },
  );
});
