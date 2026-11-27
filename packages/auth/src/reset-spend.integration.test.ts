import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Real pinned BA handler, transaction machinery, production adapter and hooks.
// Only database delegates/delivery are fake. PG proves actual lock semantics.
const fixture = vi.hoisted(() => {
  type Row = Record<string, unknown>;
  type Tables = Record<string, Row[]>;
  const tables: Tables = {};
  const events: string[] = [];
  const locks = new Map<string, Promise<void>>();
  const controls = { commitError: false, writeError: false, cleanupError: false };
  let connections = 0;
  let peak = 0;
  let readBarrier: ((where: Row) => void) | undefined;
  let lockBarrier: ((key: string) => Promise<void>) | undefined;
  const match = (row: Row, where: Row = {}): boolean =>
    Object.entries(where).every(([key, value]) => {
      if (value === undefined) return true;
      if (key === "AND") return (value as Row[]).every((part) => match(row, part));
      if (key === "OR") return (value as Row[]).some((part) => match(row, part));
      if (key === "user")
        return tables.user!.some((u) => u.id === row.userId && match(u, value as Row));
      const have = row[key];
      if (value && typeof value === "object" && !(value instanceof Date)) {
        const condition = value as Row;
        return (
          (!("equals" in condition) || have === condition.equals) &&
          (!("lt" in condition) ||
            (have instanceof Date && condition.lt instanceof Date && have < condition.lt)) &&
          (!("lte" in condition) ||
            (have instanceof Date && condition.lte instanceof Date && have <= condition.lte)) &&
          (!("startsWith" in condition) || String(have).startsWith(String(condition.startsWith))) &&
          (!("not" in condition) || have !== condition.not) &&
          (!("in" in condition) || (condition.in as unknown[]).includes(have)) &&
          (!("gt" in condition) ||
            (have instanceof Date && condition.gt instanceof Date && have > condition.gt))
        );
      }
      return have === value;
    });
  const make = (state: () => Tables, writing: () => void) => {
    const delegate = (name: string) => {
      const find = ({ where }: { where?: Row }) => {
        readBarrier?.(where ?? {});
        return state()[name]?.find((row) => match(row, where)) ?? null;
      };
      return {
        findFirst: async (args: { where?: Row }) => find(args),
        findUnique: async (args: { where?: Row }) => {
          const row = find(args);
          return row && name === "user"
            ? {
                ...row,
                accounts:
                  state()
                    .account?.filter((a) => a.userId === row.id)
                    .slice(0, 2) ?? [],
                sessions:
                  state()
                    .session?.filter((a) => a.userId === row.id)
                    .slice(0, 1) ?? [],
              }
            : row;
        },
        findMany: async ({ where, take = 100 }: { where?: Row; take?: number }) =>
          (state()[name] ?? []).filter((row) => match(row, where)).slice(0, take),
        count: async ({ where }: { where?: Row }) =>
          (state()[name] ?? []).filter((r) => match(r, where)).length,
        create: async ({ data }: { data: Row }) => {
          writing();
          const row = { id: randomUUID(), ...data };
          state()[name] ??= [];
          state()[name]!.push(row);
          return { ...row };
        },
        update: async ({ where, data }: { where: Row; data: Row }) => {
          if (name === "account" && controls.writeError) {
            controls.writeError = false;
            throw new Error("fixture password write failure");
          }
          writing();
          const row = find({ where });
          if (!row) throw Object.assign(new Error("not found"), { code: "P2025" });
          Object.assign(row, data);
          return { ...row };
        },
        updateMany: async ({ where, data }: { where: Row; data: Row }) => {
          if (name === "account" && controls.writeError) {
            controls.writeError = false;
            throw new Error("fixture password write failure");
          }
          if (name === "user" && data.mustChangePassword === false && controls.cleanupError) {
            controls.cleanupError = false;
            throw new Error("fixture temporary cleanup failure");
          }
          writing();
          const found = state()[name]?.filter((r) => match(r, where)) ?? [];
          for (const row of found) Object.assign(row, data);
          return { count: found.length };
        },
        delete: async ({ where }: { where: Row }) => {
          writing();
          const row = find({ where });
          if (!row) throw Object.assign(new Error("not found"), { code: "P2025" });
          state()[name] = state()[name]!.filter((r) => r !== row);
          return row;
        },
        deleteMany: async ({ where }: { where: Row }) => {
          writing();
          const prior = state()[name] ?? [];
          state()[name] = prior.filter((row) => !match(row, where));
          return { count: prior.length - state()[name]!.length };
        },
      };
    };
    return Object.fromEntries(
      [
        "user",
        "account",
        "session",
        "verification",
        "sdkKey",
        "mcpGrant",
        "hostToken",
        "hostDeviceCredential",
        "deviceCode",
        "oauthAccessToken",
        "oauthRefreshToken",
        "oauthConsent",
        "appSetting",
        "shareInvite",
      ].map((name) => [name, delegate(name)]),
    );
  };
  const root = make(
    () => tables,
    () => {},
  );
  const client = {
    ...root,
    $extends: vi.fn(),
    $queryRaw: async () => [{ locked: true }],
    $transaction: vi.fn(),
  };
  client.$extends.mockReturnValue(client);
  client.$transaction.mockImplementation(async (work: (tx: object) => Promise<unknown>) => {
    connections++;
    peak = Math.max(peak, connections);
    let local: Tables | undefined;
    let dirty = false;
    const releases: (() => void)[] = [];
    const keys = new Set<string>();
    const acquire = async (key: string) => {
      if (keys.has(key)) return;
      keys.add(key);
      const prior = locks.get(key) ?? Promise.resolve();
      let release!: () => void;
      locks.set(
        key,
        new Promise<void>((done) => {
          release = done;
        }),
      );
      releases.push(release);
      await prior;
      events.push(key);
      await lockBarrier?.(key);
    };
    const state = () => (local ??= structuredClone(tables));
    const tx = {
      ...make(state, () => {
        dirty = true;
      }),
      $executeRaw: async (_sql: TemplateStringsArray, key: string) => {
        await acquire(key);
        return 1;
      },
      $queryRaw: async (sql: TemplateStringsArray, key: string) => {
        if (sql.join("").includes("FOR NO KEY UPDATE")) {
          await acquire(`owner:${key}`);
          return state()
            .user!.filter((row) => row.id === key)
            .map(({ id }) => ({ id }));
        }
        await acquire(key);
        return [{ locked: true }];
      },
    };
    try {
      const result = await work(tx);
      const passwordChanged = local?.account?.some(
        (a) => a.password !== tables.account?.find((old) => old.id === a.id)?.password,
      );
      if (passwordChanged && controls.commitError) {
        controls.commitError = false;
        throw new Error("fixture commit failure");
      }
      if (dirty && local) {
        for (const key of Object.keys(tables)) delete tables[key];
        Object.assign(tables, local);
      }
      events.push(passwordChanged ? "password-commit" : "commit");
      return result;
    } finally {
      for (const release of releases) release();
      connections--;
    }
  });
  return {
    tables,
    client,
    controls,
    events,
    connections: () => connections,
    peak: () => peak,
    setReadBarrier: (fn?: typeof readBarrier) => {
      readBarrier = fn;
    },
    setLockBarrier: (fn?: typeof lockBarrier) => {
      lockBarrier = fn;
    },
    resetPeak: () => {
      peak = 0;
    },
  };
});
vi.mock("@wssp/db", () => ({ default: fixture.client }));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 3 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    NODE_ENV: "test",
    BETTER_AUTH_URL: "https://app.example.test",
    BETTER_AUTH_SECRET: "disposable-activation-fixture-secret-123456789",
  },
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  renderResetPassword: () => ({ subject: "Reset", html: "" }),
  renderVerifyEmail: () => ({ subject: "Verify", html: "" }),
  renderTwoFactorOtp: () => ({ subject: "OTP", html: "" }),
  sendEmail: async () => {
    expect(fixture.connections()).toBe(0);
  },
}));
vi.mock("./mcp-plugins", () => ({ resolveMcpPlugins: () => [] }));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  AgentTokenPolicyBlockedError: class extends Error {},
  authenticateAgentTokenSecret: vi.fn(),
  principalForMcpGrant: vi.fn(),
}));
vi.mock("../../../apps/server/src/mcp-rate-limit.js", () => ({
  consumeMcpCredentialQuota: vi.fn(),
}));
const { auth } = await import("./index");
const { handlePasswordAuthRequest } = await import("./password-auth-handler");
const { createEmailVerificationToken } = await import("better-auth/api");
const context = await auth.$context;
const hash = vi.spyOn(context.password, "hash").mockImplementation(async (p) => `hash:${p}`);
vi.spyOn(context.password, "verify").mockImplementation(
  async ({ hash, password }) => hash === `hash:${password}`,
);
const userId = "invitee";
const email = "invitee@example.test";
const user = () => fixture.tables.user![0]!;
const credential = () => fixture.tables.account![0]!;
const deferred = () => {
  const { promise, resolve } = Promise.withResolvers<void>();
  return { promise, resolve };
};
const reset = (token: string) =>
  handlePasswordAuthRequest(
    auth,
    new Request("https://app.example.test/api/auth/reset-password", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://app.example.test" },
      body: JSON.stringify({ token, newPassword: `${token}-password-12345` }),
    }),
  );
async function link(token: string) {
  fixture.tables.verification!.push({
    id: randomUUID(),
    identifier: `reset-password:${token}`,
    value: userId,
    expiresAt: new Date(Date.now() + 60_000),
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}
async function verifyEmail() {
  const token = await createEmailVerificationToken(context.secret, email);
  return handlePasswordAuthRequest(
    auth,
    new Request(`https://app.example.test/api/auth/verify-email?token=${token}`),
  );
}
beforeEach(() => {
  fixture.setReadBarrier();
  fixture.setLockBarrier();
  fixture.resetPeak();
  fixture.events.length = 0;
  Object.assign(fixture.controls, { commitError: false, writeError: false, cleanupError: false });
  for (const key of Object.keys(fixture.tables)) delete fixture.tables[key];
  const now = new Date();
  Object.assign(fixture.tables, {
    user: [
      {
        id: userId,
        name: "Invitee",
        email,
        emailVerified: false,
        mustChangePassword: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    account: [
      {
        id: "credential",
        userId,
        accountId: userId,
        providerId: "credential",
        password: "hash:prior-password",
        createdAt: now,
        updatedAt: now,
      },
    ],
    verification: [],
    session: [],
  });
  hash.mockImplementation(async (password) => `hash:${password}`);
});
afterEach(() => {
  fixture.setReadBarrier();
  fixture.setLockBarrier();
});

describe("mailed reset atomicity through actual BA and production Prisma adapter", () => {
  it.each(["writeError", "commitError", "cleanupError"] as const)(
    "rolls back token/password/temp flag on %s; same token retries",
    async (failure) => {
      await link("mailed");
      await link("competitor");
      const hooks = context.options.databaseHooks!.account!.update!;
      const after = vi.spyOn(hooks, "after");
      fixture.controls[failure] = true;
      try {
        const failed = await reset("mailed");
        expect(failed.status, await failed.clone().text()).toBe(500);
        expect(after).not.toHaveBeenCalled();
        expect(credential().password).toBe("hash:prior-password");
        expect(user()).toMatchObject({ emailVerified: false, mustChangePassword: true });
        expect(fixture.tables.verification).toHaveLength(2);
        const success = await reset("mailed");
        expect(success.status, await success.clone().text()).toBe(200);
        expect(after).toHaveBeenCalledOnce();
        expect(credential().password).toBe("hash:mailed-password-12345");
        expect(user()).toMatchObject({ emailVerified: false, mustChangePassword: false });
        expect(fixture.tables.verification).toEqual([]);
      } finally {
        after.mockRestore();
      }
    },
  );
  it("account afterhooks run exactly after the successful real commit", async () => {
    await link("mailed");
    const hooks = context.options.databaseHooks!.account!.update!;
    const original = hooks.after!;
    const after = vi.spyOn(hooks, "after").mockImplementation(async (...args) => {
      expect(fixture.events).toContain("password-commit");
      expect(fixture.connections()).toBe(1); // outer password holder only
      expect(user().mustChangePassword).toBe(false);
      await original(...args);
    });
    try {
      const success = await reset("mailed");
      expect(success.status, await success.clone().text()).toBe(200);
      expect(after).toHaveBeenCalledOnce();
    } finally {
      after.mockRestore();
    }
  });
  it.each(["first", "second"])(
    "two mailed links: %s spends first and invalidates its competitor",
    async (first) => {
      await link("first");
      await link("second");
      const hashing = deferred();
      const release = deferred();
      const queued = deferred();
      hash.mockImplementationOnce(async (p) => {
        hashing.resolve();
        await release.promise;
        return `hash:${p}`;
      });
      const winning = reset(first);
      await hashing.promise;
      const other = first === "first" ? "second" : "first";
      fixture.setReadBarrier((where) => {
        if (where.identifier === `reset-password:${other}`) queued.resolve();
      });
      const losing = reset(other);
      try {
        await queued.promise;
        release.resolve();
        expect((await winning).status).toBe(200);
        expect((await losing).status).toBe(400);
        expect(credential().password).toBe(`hash:${first}-password-12345`);
        expect(user().emailVerified).toBe(false);
        expect(fixture.tables.verification).toEqual([]);
        expect(fixture.peak()).toBeLessThanOrEqual(2);
      } finally {
        release.resolve();
        await Promise.allSettled([winning, losing]);
      }
    },
  );
  it.each(["reset", "verify"])("serializes %s first against real verify-email", async (first) => {
    await link("mailed");
    const entered = deferred();
    const release = deferred();
    const queued = deferred();
    if (first === "reset")
      hash.mockImplementationOnce(async (p) => {
        entered.resolve();
        await release.promise;
        return `hash:${p}`;
      });
    else
      fixture.setLockBarrier(async (key) => {
        if (key === `owner:${userId}`) {
          entered.resolve();
          await release.promise;
        }
      });
    const winning = first === "reset" ? reset("mailed") : verifyEmail();
    await entered.promise;
    fixture.setReadBarrier((where) => {
      if (where.identifier === "reset-password:mailed") queued.resolve();
    });
    const losing = first === "reset" ? verifyEmail() : reset("mailed");
    try {
      if (first === "verify") await queued.promise;
      release.resolve();
      expect((await winning).status).toBe(200);
      expect((await losing).status).toBe(first === "reset" ? 200 : 400);
      expect(user()).toMatchObject({ emailVerified: true, mustChangePassword: first !== "reset" });
      expect(credential().password).toBe(
        first === "reset" ? "hash:mailed-password-12345" : "hash:prior-password",
      );
      expect(fixture.tables.verification).toEqual([]);
    } finally {
      release.resolve();
      await Promise.allSettled([winning, losing]);
    }
  });
  it("verification rollback preserves proof, temporary state and prior reset links", async () => {
    await link("mailed");
    const deletion = vi.spyOn(fixture.client, "$transaction");
    const original = deletion.getMockImplementation()!;
    deletion.mockImplementationOnce(async (work) =>
      original(async (tx: object) => {
        await work(tx);
        throw new Error("fixture verification commit failure");
      }),
    );
    try {
      expect((await verifyEmail()).status).toBe(500);
      expect(user()).toMatchObject({ emailVerified: false, mustChangePassword: true });
      expect(fixture.tables.verification).toHaveLength(1);
    } finally {
      deletion.mockImplementation(original);
    }
  });
  it("standalone signup stays nontransactional, including locale and SMTP callbacks", async () => {
    const before = fixture.client.$transaction.mock.calls.length;
    const response = await handlePasswordAuthRequest(
      auth,
      new Request("https://app.example.test/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://app.example.test" },
        body: JSON.stringify({
          email: "new@example.test",
          name: "New",
          password: "new-password-12345",
        }),
      }),
    );
    expect(response.status).toBe(200);
    expect(fixture.tables.user!.some((u) => u.email === "new@example.test")).toBe(true);
    expect(fixture.client.$transaction.mock.calls.length).toBe(before);
  });
  it("standalone committed signup writes still run queued afterhooks when later work fails", async () => {
    const after = vi.spyOn(context.options.databaseHooks!.user!.create!, "after");
    const create = vi
      .spyOn(context.internalAdapter, "linkAccount")
      .mockRejectedValueOnce(new Error("fixture signup account failure"));
    try {
      const response = await handlePasswordAuthRequest(
        auth,
        new Request("https://app.example.test/api/auth/sign-up/email", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://app.example.test" },
          body: JSON.stringify({
            name: "New",
            email: "retained@example.test",
            password: "new-password-12345",
          }),
        }),
      );
      expect(create).toHaveBeenCalledOnce();
      expect(response.status).toBe(500);
      expect(fixture.tables.user!.some((row) => row.email === "retained@example.test")).toBe(true);
      expect(after).toHaveBeenCalledOnce();
    } finally {
      create.mockRestore();
      after.mockRestore();
    }
  });

  it("pool3 reserved activation siblings progress before the real reset transaction", async () => {
    await link("mailed");
    fixture.tables.user!.push({ id: "other", email: "other@example.test", emailVerified: false });
    const entered = deferred();
    const release = deferred();
    const queued = deferred();
    const order: string[] = [];
    const activate = () =>
      context.adapter.update({
        model: "user",
        where: [{ field: "id", value: "other" }],
        update: { emailVerified: true },
      });
    let first!: Promise<unknown>;
    let second!: Promise<unknown>;
    let paused = false;
    fixture.setLockBarrier(async (key) => {
      if (key !== "password-write:other" || paused) return;
      paused = true;
      entered.resolve();
      await release.promise;
    });
    hash.mockImplementationOnce(async (password) => {
      first = activate().then(() => {
        order.push("first");
      });
      await entered.promise;
      second = activate().then(() => {
        order.push("second");
      });
      return `hash:${password}`;
    });
    const original = context.adapter.transaction.bind(context.adapter);
    const transaction = vi.spyOn(context.adapter, "transaction").mockImplementation((callback) => {
      const result = original(callback);
      queued.resolve();
      return result;
    });
    const spending = reset("mailed");
    try {
      await queued.promise;
      expect(fixture.connections()).toBe(2);
      release.resolve();
      expect((await spending).status).toBe(200);
      await Promise.all([first, second]);
      expect(order).toEqual(["first", "second"]);
      expect(fixture.peak()).toBeLessThanOrEqual(2);
      expect(credential().password).toBe("hash:mailed-password-12345");
      expect(user()).toMatchObject({ emailVerified: false, mustChangePassword: false });
    } finally {
      release.resolve();
      transaction.mockRestore();
      await Promise.allSettled([spending, first, second]);
    }
  });
});
