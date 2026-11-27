import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { memory, revokeCredentials, adapterOptions } = vi.hoisted(() => ({
  memory: {} as Record<string, Record<string, unknown>[]>,
  revokeCredentials: vi.fn(),
  adapterOptions: [] as unknown[],
}));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("../../api/src/test/mock-prisma");
  const db = await createMockPrisma();
  db.$extends.mockReturnValue(db as never);
  return { default: db };
});
vi.mock("better-auth/adapters/prisma", async () => {
  const { memoryAdapter } = await import("better-auth/adapters/memory");
  return {
    prismaAdapter: (_client: unknown, options: unknown) => {
      adapterOptions.push(options);
      return memoryAdapter(memory);
    },
  };
});
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 10 } }));
vi.mock("@wssp/env/server", () => ({
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: false,
  env: {
    BETTER_AUTH_SECRET: "password-reset-unit-test-secret-at-least-32-chars",
    BETTER_AUTH_URL: "http://localhost:3000",
    NODE_ENV: "test",
    MCP_ENABLED: false,
  },
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  sendEmail: vi.fn(),
  renderResetPassword: vi.fn(),
  renderVerifyEmail: vi.fn(() => ({ subject: "Verify email", html: "Test verification mail" })),
  renderTwoFactorOtp: vi.fn(),
}));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  AgentTokenPolicyBlockedError: class AgentTokenPolicyBlockedError extends Error {},
  authenticateAgentTokenSecret: vi.fn(),
  principalForMcpGrant: vi.fn(),
}));
vi.mock("../../../apps/server/src/mcp-rate-limit.js", () => ({
  consumeMcpCredentialQuota: vi.fn(),
}));
vi.mock("./mcp-plugins", () => ({ resolveMcpPlugins: () => [] }));
vi.mock("./credential-revocation.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./credential-revocation.js")>()),
  revokeCredentialsAfterPasswordChange: revokeCredentials,
}));

const { auth: rawAuth, passwordPepper } = await import("./index");
const { withPasswordWriteLock } = await import("./password-write-lock");
const { withPasswordSignInFence } = await import("./password-sign-in-fence");
// Preserve direct-API error assertions while applying the same HTTP security
// boundaries. The production server mount has its own integration regressions.
async function securedCall<T>(
  path: string,
  input: { body?: unknown; headers?: ConstructorParameters<typeof Headers>[0] },
  run: () => Promise<T>,
): Promise<T> {
  const request = new Request(`http://localhost:3000/api/auth${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...Object.fromEntries(new Headers(input.headers)),
    },
    body: JSON.stringify(input.body),
  });
  let result!: T;
  const handler = async () => {
    result = await run();
    return new Response(null);
  };
  if (path === "/sign-in/email") await withPasswordSignInFence(request, handler);
  else
    await withPasswordWriteLock(path, request, handler, {
      getSession: (headers) => rawAuth.api.getSession({ headers }),
    });
  return result;
}
const auth = {
  ...rawAuth,
  api: {
    ...rawAuth.api,
    resetPassword: (input: NonNullable<Parameters<typeof rawAuth.api.resetPassword>[0]>) =>
      securedCall("/reset-password", input, () => rawAuth.api.resetPassword(input)),
    changePassword: (input: NonNullable<Parameters<typeof rawAuth.api.changePassword>[0]>) =>
      securedCall("/change-password", input, () => rawAuth.api.changePassword(input)),
    signInEmail: (input: Parameters<typeof rawAuth.api.signInEmail>[0] & { asResponse: true }) =>
      securedCall("/sign-in/email", input, () => rawAuth.api.signInEmail(input)),
  },
};
const { default: prisma } = await import("@wssp/db");
it("keeps standalone Prisma operations nontransactional", async () => {
  expect(adapterOptions).toContainEqual(
    expect.objectContaining({ provider: "postgresql", transaction: false }),
  );
  expect((await rawAuth.$context).adapter.options?.adapterConfig.transaction).toBe(false);
});
const userId = "reset-owner";
const password = "original-password-test-only";
const newPassword = "replacement-password-test-only";
const resetToken = "reset-token-test-only";

beforeEach(async () => {
  vi.clearAllMocks();
  vi.mocked(prisma.session.findMany).mockResolvedValue([]);
  revokeCredentials.mockReset().mockResolvedValue(undefined);
  const now = new Date();
  for (const key of Object.keys(memory)) delete memory[key];
  Object.assign(memory, {
    user: [
      {
        id: userId,
        email: "owner@example.test",
        name: "Owner",
        emailVerified: true,
        role: "user",
        createdAt: now,
        updatedAt: now,
      },
    ],
    account: [
      {
        id: "password-account",
        accountId: userId,
        userId,
        providerId: "credential",
        password: await passwordPepper.hash(password),
        createdAt: now,
        updatedAt: now,
      },
    ],
    verification: [
      {
        id: "recovery",
        identifier: `reset-password:${resetToken}`,
        value: userId,
        expiresAt: new Date(Date.now() + 60_000),
        createdAt: now,
        updatedAt: now,
      },
    ],
    session: [userId, userId, "another-owner"].map((id, index) => ({
      id: `session-${index}`,
      userId: id,
      token: `session-token-${index}`,
      expiresAt: new Date(Date.now() + 60_000),
      createdAt: now,
      updatedAt: now,
    })),
    twoFactor: [],
  });
  vi.mocked(prisma.user.findUnique).mockResolvedValue(null);
  vi.mocked(prisma.$queryRaw).mockImplementation(
    (sql, id) =>
      Promise.resolve(
        Array.isArray(sql) && sql.join("").includes("FOR NO KEY UPDATE")
          ? [{ id }]
          : [{ locked: true }],
      ) as ReturnType<typeof prisma.$queryRaw>,
  );
  vi.mocked(prisma.session.findFirst).mockImplementation(
    (args) =>
      Promise.resolve(
        memory.session!.find((row) => matchesWhere(row, args?.where)) ?? null,
      ) as ReturnType<typeof prisma.session.findFirst>,
  );
  vi.mocked(prisma.account.findFirst).mockImplementation(
    (args) =>
      Promise.resolve(
        memory.account!.find((row) => {
          const where = args?.where;
          if (where?.user)
            return (
              row.providerId === "credential" &&
              memory.user!.some(
                (user) => user.id === row.userId && user.email === "owner@example.test",
              )
            );
          return matchesWhere(row, where);
        }) ?? null,
      ) as ReturnType<typeof prisma.account.findFirst>,
  );
  vi.mocked(prisma.verification.findFirst).mockImplementation(
    (args) =>
      Promise.resolve(
        memory.verification!.find((row) => matchesWhere(row, args?.where)) ?? null,
      ) as ReturnType<typeof prisma.verification.findFirst>,
  );
  vi.mocked(prisma.user.updateMany).mockImplementation((args) => {
    const rows = memory.user!.filter((row) => matchesWhere(row, args?.where));
    for (const row of rows) Object.assign(row, args.data);
    return Object.defineProperty(Promise.resolve({ count: rows.length }), Symbol.toStringTag, {
      value: "PrismaPromise",
    }) as ReturnType<typeof prisma.user.updateMany>;
  });
  vi.mocked(prisma.verification.create).mockImplementation((args) => {
    const row = { id: `fence-${memory.verification!.length}`, ...args.data };
    memory.verification!.push(row);
    return Promise.resolve(row) as ReturnType<typeof prisma.verification.create>;
  });

  vi.mocked(prisma.verification.findMany).mockImplementation((args) => {
    const rows = memory.verification!.filter((row) => matchesWhere(row, args?.where));
    return Promise.resolve(rows.slice(0, args?.take ?? rows.length)) as ReturnType<
      typeof prisma.verification.findMany
    >;
  });
  vi.mocked(prisma.verification.deleteMany).mockImplementation((args) => {
    const before = memory.verification!.length;
    memory.verification = memory.verification!.filter((row) => !matchesWhere(row, args?.where));
    return Promise.resolve({ count: before - memory.verification.length }) as ReturnType<
      typeof prisma.verification.deleteMany
    >;
  });
  vi.mocked(prisma.session.deleteMany).mockImplementation((args) => {
    const before = memory.session?.length ?? 0;
    memory.session = memory.session?.filter((row) => !matchesWhere(row, args?.where)) ?? [];
    return Object.defineProperty(
      Promise.resolve({ count: before - memory.session.length }),
      Symbol.toStringTag,
      { value: "PrismaPromise" },
    ) as ReturnType<typeof prisma.session.deleteMany>;
  });
});

/** The fixture's Prisma writes must apply the actual predicates, including OR. */
function matchesWhere(row: Record<string, unknown>, where: unknown): boolean {
  if (!where || typeof where !== "object") throw new Error("Expected a scoped predicate");
  return Object.entries(where).every(([field, filter]) => {
    if (field === "OR" && Array.isArray(filter))
      return filter.some((part) => matchesWhere(row, part));
    if (filter && typeof filter === "object") {
      if ("startsWith" in filter) return String(row[field]).startsWith(String(filter.startsWith));
      if ("in" in filter && Array.isArray(filter.in)) return filter.in.includes(row[field]);
      if ("equals" in filter) return row[field] === filter.equals;
      if ("not" in filter) return row[field] !== filter.not;
      if ("gt" in filter && filter.gt instanceof Date)
        return row[field] instanceof Date && row[field] > filter.gt;
      throw new Error(`Unsupported fixture filter: ${field}`);
    }
    return row[field] === filter;
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function reset() {
  return auth.api.resetPassword({ body: { token: resetToken, newPassword } });
}

describe("password recovery", () => {
  it("maps a pre-sweep verification lookup failure to 503 without changing password or token", async () => {
    const context = await auth.$context;
    const lookup = vi
      .spyOn(context.internalAdapter, "findVerificationValue")
      .mockRejectedValueOnce(new Error("lookup unavailable"));
    const originalHash = memory.account?.[0]?.password;
    const originalToken = { ...memory.verification?.[0] };
    await expect(reset()).rejects.toMatchObject({
      status: "SERVICE_UNAVAILABLE",
      message:
        "We couldn't finish securing your account. Nothing was changed — try the link again.",
    });
    expect(lookup).toHaveBeenCalledExactlyOnceWith(`reset-password:${resetToken}`);
    expect(revokeCredentials).not.toHaveBeenCalled();
    expect(memory.account?.[0]?.password).toBe(originalHash);
    expect(memory.verification).toEqual([originalToken]);
    expect(memory.session).toHaveLength(3);
    await expect(reset()).resolves.toEqual({ status: true });
  });

  it("enables session revocation and awaits revocation for the reset token's owner", async () => {
    expect(auth.options.emailAndPassword?.revokeSessionsOnPasswordReset).toBe(true);
    await expect(reset()).resolves.toEqual({ status: true });
    expect(revokeCredentials.mock.calls).toEqual([
      [userId, { revokeSessions: true }],
      [userId, { revokeSessions: true }],
    ]);
    expect(memory.session?.map((row) => row.userId)).toEqual(["another-owner"]);
  });

  it("clears an invite's temporary-password restriction but verifies only through its mailed link", async () => {
    memory.user![0]!.emailVerified = false;
    memory.user![0]!.mustChangePassword = true;
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ mustChangePassword: true } as never);
    await expect(reset()).resolves.toEqual({ status: true });
    expect(revokeCredentials.mock.calls).toEqual([
      [userId, { revokeSessions: true }],
      [userId, { revokeSessions: true }],
    ]);
    expect(prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: userId, mustChangePassword: true },
      data: { mustChangePassword: false },
    });
    expect(memory.user![0]).toMatchObject({ emailVerified: false, mustChangePassword: false });
    const signInChosen = () => {
      const input = { body: { email: "owner@example.test", password: newPassword } };
      return securedCall("/sign-in/email", input, () => rawAuth.api.signInEmail(input));
    };
    await expect(signInChosen()).rejects.toMatchObject({ body: { code: "EMAIL_NOT_VERIFIED" } });
    const { adminInviteAcceptUrl } = await import("./admin-invite-verification");
    const accept = await adminInviteAcceptUrl({
      secret: "password-reset-unit-test-secret-at-least-32-chars",
      authBaseUrl: "http://localhost:3000",
      userId,
      email: "owner@example.test",
      locale: "en-US",
    });
    const verified = await auth.handler(new Request(accept));
    expect(verified.status).toBe(302);
    expect(verified.headers.get("location")).toBe("/en-US/verify-email?ok=1");
    expect(memory.user![0]).toMatchObject({ emailVerified: true, mustChangePassword: false });
    await expect(signInChosen()).resolves.toMatchObject({ user: { id: userId } });
  });

  it("refuses before changing the password or consuming the link, then accepts the same link", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ mustChangePassword: true } as never);
    revokeCredentials.mockRejectedValueOnce(new Error("revocation unavailable"));
    const originalHash = memory.account?.[0]?.password;
    await expect(reset()).rejects.toMatchObject({
      status: "SERVICE_UNAVAILABLE",
      message:
        "We couldn't finish securing your account. Nothing was changed — try the link again.",
    });
    expect(revokeCredentials).toHaveBeenCalledExactlyOnceWith(userId, { revokeSessions: true });
    expect(memory.account?.[0]?.password).toBe(originalHash);
    expect(memory.verification).toHaveLength(1);
    expect(memory.session).toHaveLength(3);
    expect(prisma.user.updateMany).not.toHaveBeenCalled();
    await expect(reset()).resolves.toEqual({ status: true });
    expect(memory.verification).toHaveLength(0);
    expect(
      await passwordPepper.verify({
        hash: String(memory.account?.[0]?.password),
        password: newPassword,
      }),
    ).toBe(true);
  });

  it("refuses the endpoint after all three real revocation transaction retries fail", async () => {
    const { revokeCredentialsAfterPasswordChange: realRevoke } =
      await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
    const error = new Error("private database details");
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    let failures = 3;
    vi.mocked(prisma.$queryRaw).mockImplementation((strings, id) => {
      if (
        Array.isArray(strings) &&
        strings.join("").includes("FOR NO KEY UPDATE") &&
        failures-- > 0
      )
        return Object.defineProperty(Promise.reject(error), Symbol.toStringTag, {
          value: "PrismaPromise",
        }) as ReturnType<typeof prisma.$queryRaw>;
      return Promise.resolve(
        Array.isArray(strings) && strings.join("").includes("FOR NO KEY UPDATE")
          ? [{ id }]
          : [{ locked: true }],
      ) as ReturnType<typeof prisma.$queryRaw>;
    });
    revokeCredentials.mockImplementationOnce(realRevoke);
    const hash = memory.account?.[0]?.password;
    await expect(reset()).rejects.toMatchObject({ status: "SERVICE_UNAVAILABLE" });
    expect(prisma.$transaction).toHaveBeenCalledTimes(4);
    expect(memory.account?.[0]?.password).toBe(hash);
    expect(memory.verification).toHaveLength(1);
    expect(memory.session).toHaveLength(3);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("SECURITY"), {
      userId,
      errorClass: "Error",
    });
    expect(JSON.stringify(log.mock.calls)).not.toContain(error.message);
    log.mockRestore();
    await expect(reset()).resolves.toEqual({ status: true });
  });

  it("signs out everywhere if password hashing fails after the pre-sweep, leaving password and token intact", async () => {
    const headers = await signIn();
    const { revokeCredentialsAfterPasswordChange: realRevoke } =
      await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
    revokeCredentials.mockImplementationOnce(realRevoke);
    const originalHash = memory.account?.[0]?.password;
    const context = await auth.$context;
    vi.spyOn(context.password, "hash").mockImplementationOnce(async () => {
      expect(memory.session?.map((row) => row.userId)).toEqual(["another-owner"]);
      expect(
        await auth.api.getSession({ headers, query: { disableCookieCache: true } }),
      ).toBeNull();
      throw new Error("hash unavailable");
    });
    await expect(reset()).rejects.toThrow("hash unavailable");
    expect(revokeCredentials).toHaveBeenCalledExactlyOnceWith(userId, { revokeSessions: true });
    expect(memory.account?.[0]?.password).toBe(originalHash);
    expect(memory.verification).toHaveLength(1);
    expect(memory.session?.map((row) => row.userId)).toEqual(["another-owner"]);
  });

  it.each([true, false])(
    "finishes reset with emailVerified=%s and kills the other link after all post-sweep retries fail, then reports the error",
    async (emailVerified) => {
      const { revokeCredentialsAfterPasswordChange: realRevoke } =
        await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
      const error = new Error("after-sweep unavailable");
      const log = vi.spyOn(console, "error").mockImplementation(() => {});
      memory.user![0]!.emailVerified = emailVerified;
      memory.user![0]!.mustChangePassword = true;
      vi.mocked(prisma.user.findUnique).mockResolvedValue({ mustChangePassword: true } as never);
      memory.verification!.push({
        ...memory.verification![0],
        id: "other-link",
        identifier: "reset-password:other-link",
      });
      const unrelatedLink = {
        ...memory.verification![0],
        id: "another-owner-link",
        identifier: "reset-password:another-owner-link",
        value: "another-owner",
      };
      memory.verification!.push(unrelatedLink);
      let failures = 3;
      vi.mocked(prisma.$queryRaw).mockImplementation((strings, id) => {
        if (
          Array.isArray(strings) &&
          strings.join("").includes("FOR NO KEY UPDATE") &&
          revokeCredentials.mock.calls.length === 2 &&
          failures-- > 0
        )
          return Object.defineProperty(Promise.reject(error), Symbol.toStringTag, {
            value: "PrismaPromise",
          }) as ReturnType<typeof prisma.$queryRaw>;
        return Promise.resolve(
          Array.isArray(strings) && strings.join("").includes("FOR NO KEY UPDATE")
            ? [{ id }]
            : [{ locked: true }],
        ) as ReturnType<typeof prisma.$queryRaw>;
      });
      revokeCredentials.mockResolvedValueOnce(undefined).mockImplementationOnce(realRevoke);
      await expect(reset()).rejects.toBe(error);
      expect(prisma.$transaction).toHaveBeenCalledTimes(5);
      expect(revokeCredentials.mock.calls).toEqual([
        [userId, { revokeSessions: true }],
        [userId, { revokeSessions: true }],
      ]);
      expect(memory.verification).toEqual([unrelatedLink]);
      expect(prisma.verification.deleteMany).toHaveBeenCalledWith({
        where: { value: userId, identifier: { startsWith: "reset-password:" } },
      });
      expect(prisma.user.updateMany).toHaveBeenCalledWith({
        where: { id: userId, mustChangePassword: true },
        data: { mustChangePassword: false },
      });
      expect(memory.user![0]).toMatchObject({ emailVerified, mustChangePassword: false });
      expect(vi.mocked(prisma.user.updateMany).mock.invocationCallOrder[0]).toBeLessThan(
        revokeCredentials.mock.invocationCallOrder[1]!,
      );
      expect(vi.mocked(prisma.verification.deleteMany).mock.invocationCallOrder[0]).toBeLessThan(
        vi.mocked(prisma.user.updateMany).mock.invocationCallOrder[0]!,
      );
      expect(
        await passwordPepper.verify({
          hash: String(memory.account?.[0]?.password),
          password: newPassword,
        }),
      ).toBe(true);
      await expect(
        auth.api.resetPassword({ body: { token: "other-link", newPassword: password } }),
      ).rejects.toMatchObject({ body: { code: "INVALID_TOKEN" } });
      expect(log).toHaveBeenCalledWith(expect.stringContaining("SECURITY"), {
        userId,
        errorClass: "Error",
      });
    },
  );

  it("removes the reset owner's impersonations in both sweeps", async () => {
    const { revokeCredentialsAfterPasswordChange: realRevoke } =
      await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
    revokeCredentials.mockImplementation(realRevoke);
    memory.session!.push({ id: "impersonation-before", userId: "target", impersonatedBy: userId });
    const context = await auth.$context;
    const hash = context.password.hash;
    vi.spyOn(context.password, "hash").mockImplementationOnce(async (value) => {
      expect(memory.session!.some((row) => row.id === "impersonation-before")).toBe(false);
      // An in-flight impersonation that lands after the first sweep.
      memory.session!.push({
        id: "impersonation-between",
        userId: "target",
        impersonatedBy: userId,
      });
      return hash(value);
    });
    await expect(reset()).resolves.toEqual({ status: true });
    expect(memory.session!.map((row) => row.userId)).toEqual(["another-owner"]);
  });

  it.each(["before", "between"])(
    "invalidates a real pending 2FA sign-in created %s the reset sweeps",
    async (timing) => {
      const headers = await signIn();
      const enrollment = await auth.api.enableTwoFactor({ headers, body: { password } });
      if (enrollment.method !== "totp") throw new Error("Expected TOTP enrollment");
      const { backupCodes } = enrollment;
      // Enrolled fixture; sign-in and backup-code completion use the real plugin.
      memory.user![0]!.twoFactorEnabled = true;
      memory.twoFactor![0]!.verified = true;
      const challenge = async () => {
        const response = await auth.api.signInEmail({
          body: { email: "owner@example.test", password },
          asResponse: true,
        });
        expect(await response.clone().json()).toMatchObject({ twoFactorRedirect: true });
        return new Headers({
          cookie: response.headers
            .getSetCookie()
            .map((value) => value.split(";")[0])
            .join("; "),
        });
      };
      await auth.api.verifyBackupCode({
        headers: await challenge(),
        body: { code: backupCodes[0]!, trustDevice: true },
      });
      const trust = memory.verification!.find((row) =>
        String(row.identifier).startsWith("trust-device-"),
      );
      expect(trust).toMatchObject({ value: userId });
      const unrelated = [
        { id: "other-challenge", identifier: "2fa-other", value: "another-owner" },
        { id: "other-otp", identifier: "2fa-otp-2fa-other", value: "hashed-code:0" },
        { id: "other-attempts", identifier: "2fa-attempts-2fa-other", value: "0" },
        { id: "other-trust", identifier: "trust-device-other", value: "another-owner" },
        { id: "other-session-otp", identifier: `2fa-otp-${userId}x!session`, value: "hash:0" },
        { id: "unrelated", identifier: "unrelated-purpose", value: userId },
      ];
      memory.verification!.push(...unrelated);
      let pendingHeaders: Headers;
      let identifiers: string[] = [];
      const pending = async () => {
        pendingHeaders = await challenge();
        const parent = memory.verification!.find(
          (row) => row.value === userId && String(row.identifier).startsWith("2fa-"),
        )!;
        const otp = `2fa-otp-${parent.identifier}`;
        // SMTP is disabled in this fixture. These are the pinned plugin's exact
        // OTP identifiers/values for pending and authenticated-session flows.
        memory.verification!.push(
          { id: "pending-otp", identifier: otp, value: "hashed-code:0" },
          { id: "session-otp", identifier: `2fa-otp-${userId}!session`, value: "hash:0" },
          { id: "pending-trust", identifier: "trust-device-pending", value: userId },
        );
        // More than one batch: no pending sign-in may escape the bounded read.
        for (let index = 0; index < 101; index++) {
          const identifier = `2fa-${String(index).padStart(20, "0")}`;
          memory.verification!.push(
            { id: identifier, identifier, value: userId },
            { id: `attempts-${index}`, identifier: `2fa-attempts-${identifier}`, value: "0" },
            { id: `otp-${index}`, identifier: `2fa-otp-${identifier}`, value: "hash:0" },
          );
        }
        identifiers = [String(parent.identifier), `2fa-attempts-${parent.identifier}`, otp];
        for (const identifier of identifiers)
          expect(memory.verification!.some((row) => row.identifier === identifier)).toBe(true);
      };
      if (timing === "before") await pending();
      const { revokeCredentialsAfterPasswordChange: realRevoke } =
        await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
      revokeCredentials.mockImplementation(realRevoke);
      const context = await auth.$context;
      const hash = context.password.hash;
      vi.spyOn(context.password, "hash").mockImplementationOnce(async (value) => {
        if (timing === "before")
          expect(
            memory.verification!.some((row) => identifiers.includes(String(row.identifier))),
          ).toBe(false);
        else await pending();
        return hash(value);
      });
      await expect(reset()).resolves.toEqual({ status: true });
      const sessions = [...memory.session!];
      await expect(
        auth.api.verifyBackupCode({ headers: pendingHeaders!, body: { code: backupCodes[1]! } }),
      ).rejects.toMatchObject({
        status: "UNAUTHORIZED",
        body: { code: "INVALID_TWO_FACTOR_COOKIE" },
      });
      expect(memory.session).toEqual(sessions);
      expect(memory.verification).toEqual(unrelated);
      expect(memory.twoFactor).toHaveLength(1);
    },
  );

  it("leaves expired reset tokens to the endpoint without revoking credentials", async () => {
    memory.verification![0]!.expiresAt = new Date(Date.now() - 1);
    await expect(reset()).rejects.toMatchObject({ status: "BAD_REQUEST" });
    expect(revokeCredentials).not.toHaveBeenCalled();
  });

  it("does not revoke credentials for a rejected reset", async () => {
    await expect(
      auth.api.resetPassword({ body: { token: "invalid", newPassword } }),
    ).rejects.toMatchObject({ status: "BAD_REQUEST" });
    expect(revokeCredentials).not.toHaveBeenCalled();
  });
});

async function signIn() {
  const response = await auth.api.signInEmail({
    body: { email: "owner@example.test", password },
    asResponse: true,
  });
  expect(response.status).toBe(200);
  const cookies = response.headers.getSetCookie().map((value) => value.split(";")[0]);
  return new Headers({ cookie: cookies.join("; ") });
}

describe("password changes and session cache", () => {
  it.each(["password verification", "session insert"] as const)(
    "an admin's temporary-password sign-in paused at %s cannot outlive the invitee replacing it",
    async (stage) => {
      const headers = await signIn();
      memory.user![0]!.mustChangePassword = true;
      vi.mocked(prisma.user.findUnique).mockImplementation(
        (args) =>
          Promise.resolve(
            memory.user!.find((row) => matchesWhere(row, args?.where)) ?? null,
          ) as ReturnType<typeof prisma.user.findUnique>,
      );
      const context = await rawAuth.$context;
      const reached = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      if (stage === "password verification") {
        const verify = context.password.verify;
        vi.spyOn(context.password, "verify").mockImplementationOnce(async (input) => {
          const valid = await verify(input);
          reached.resolve();
          await release.promise;
          return valid;
        });
      } else {
        let pause = true;
        const create = context.adapter.create;
        vi.spyOn(context.adapter, "create").mockImplementation(
          new Proxy(create, {
            apply: async (create, owner, args) => {
              if (pause && args[0]?.model === "session") {
                pause = false;
                reached.resolve();
                await release.promise;
              }
              return Reflect.apply(create, owner, args);
            },
          }),
        );
      }
      const { handlePasswordAuthRequest } = await import("./password-auth-handler");
      const signInRequest = () =>
        new Request("http://localhost:3000/api/auth/sign-in/email", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "http://localhost:3000" },
          body: JSON.stringify({ email: "owner@example.test", password }),
        });
      const attacker = handlePasswordAuthRequest(rawAuth, signInRequest());
      await reached.promise;
      const { revokeCredentialsAfterPasswordChange: realRevoke } =
        await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
      revokeCredentials.mockImplementation(realRevoke);
      try {
        // The temporary-password guard forces sign-out even when the client
        // asks to keep other sessions; clearing the flag must not admit an
        // earlier sign-in that already verified the admin-known password.
        await auth.api.changePassword({
          headers,
          body: {
            currentPassword: password,
            newPassword,
            revokeOtherSessions: false,
          },
        });
        expect(memory.user![0]!.mustChangePassword).toBe(false);
      } finally {
        release.resolve();
      }
      const refused = await attacker;
      expect(refused.status).toBe(401);
      expect(
        refused.headers
          .getSetCookie()
          .filter((cookie) => cookie.includes("session_token="))
          .every((cookie) => cookie.includes("session_token=;")),
      ).toBe(true);
      expect(memory.session!.filter((row) => row.userId === userId)).toHaveLength(1);
      expect(
        await passwordPepper.verify({
          hash: String(memory.account![0]!.password),
          password: newPassword,
        }),
      ).toBe(true);
    },
  );

  it("rejects an update when the document owner differs from the cookie owner", async () => {
    const headers = await signIn();
    headers.set("X-Expected-User", "another-owner");
    headers.set("content-type", "application/json");
    headers.set("origin", "http://localhost:3000");
    const response = await auth.handler(
      new Request("http://localhost:3000/api/auth/update-user", {
        method: "POST",
        headers,
        body: JSON.stringify({ name: "Wrong owner" }),
      }),
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ code: "IDENTITY_CHANGED" });
    expect(memory.user![0]!.name).toBe("Owner");
    expect(await auth.api.signOut({ headers })).toEqual({ success: true });
  });

  it.each([true, false])(
    "shares revocation only when sign-out is %s",
    async (revokeOtherSessions) => {
      const headers = await signIn();
      await auth.api.changePassword({
        headers,
        body: { currentPassword: password, newPassword, revokeOtherSessions },
      });
      if (revokeOtherSessions)
        expect(revokeCredentials).toHaveBeenCalledExactlyOnceWith(userId, {
          keepSessionToken: expect.any(String),
        });
      else expect(revokeCredentials).not.toHaveBeenCalled();
    },
  );

  it("ends the password-changing administrator's impersonations on sign-out", async () => {
    const { revokeCredentialsAfterPasswordChange: realRevoke } =
      await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
    const headers = await signIn();
    memory.session!.push({ id: "impersonation", userId: "target", impersonatedBy: userId });
    revokeCredentials.mockImplementation(realRevoke);
    await auth.api.changePassword({
      headers,
      body: { currentPassword: password, newPassword, revokeOtherSessions: true },
    });
    expect(memory.session!.some((row) => row.impersonatedBy === userId)).toBe(false);
    expect(memory.session!.filter((row) => row.userId === userId)).toHaveLength(1);
    expect(memory.session!.some((row) => row.userId === "another-owner")).toBe(true);
  });

  it("also revokes credentials when the temporary-password guard forces sign-out", async () => {
    const headers = await signIn();
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ mustChangePassword: true } as never);
    await auth.api.changePassword({
      headers,
      body: { currentPassword: password, newPassword, revokeOtherSessions: false },
    });
    expect(revokeCredentials).toHaveBeenCalledExactlyOnceWith(userId, {
      keepSessionToken: expect.any(String),
    });
    expect(prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: userId, mustChangePassword: true },
      data: { mustChangePassword: false },
    });
  });

  it("does not revoke credentials after a rejected password change", async () => {
    const headers = await signIn();
    await expect(
      auth.api.changePassword({
        headers,
        body: { currentPassword: "wrong-password", newPassword, revokeOtherSessions: true },
      }),
    ).rejects.toMatchObject({ status: "BAD_REQUEST" });
    expect(revokeCredentials).not.toHaveBeenCalled();
  });

  it("logs SECURITY and rethrows a failed sweep after the changed password commits", async () => {
    const headers = await signIn();
    const { revokeCredentialsAfterPasswordChange: realRevoke } =
      await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
    const error = new Error("revocation unavailable");
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    let failures = 3;
    vi.mocked(prisma.$queryRaw).mockImplementation((strings, id) => {
      if (
        Array.isArray(strings) &&
        strings.join("").includes("FOR NO KEY UPDATE") &&
        failures-- > 0
      )
        return Object.defineProperty(Promise.reject(error), Symbol.toStringTag, {
          value: "PrismaPromise",
        }) as ReturnType<typeof prisma.$queryRaw>;
      return Promise.resolve(
        Array.isArray(strings) && strings.join("").includes("FOR NO KEY UPDATE")
          ? [{ id }]
          : [{ locked: true }],
      ) as ReturnType<typeof prisma.$queryRaw>;
    });
    revokeCredentials.mockImplementation(realRevoke);
    await expect(
      auth.api.changePassword({
        headers,
        body: { currentPassword: password, newPassword, revokeOtherSessions: true },
      }),
    ).rejects.toBe(error);
    expect(
      await passwordPepper.verify({
        hash: String(memory.account![0]!.password),
        password: newPassword,
      }),
    ).toBe(true);
    expect(prisma.$transaction).toHaveBeenCalledTimes(4);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("SECURITY"), {
      userId,
      errorClass: "Error",
    });
  });

  it.each(["revoked", "expired"])(
    "stops a %s session's cookie-cache renewal chain",
    async (state) => {
      const headers = await signIn();
      const cached = await auth.api.getSession({ headers });
      expect(cached?.user.id).toBe(userId);
      if (state === "revoked")
        memory.session = memory.session!.filter((row) => row.token !== cached!.session.token);
      else
        memory.session!.find((row) => row.token === cached!.session.token)!.expiresAt = new Date(
          Date.now() - 1,
        );
      // The signed cache is still valid for reads, just as on origin.
      expect((await auth.api.getSession({ headers }))?.user.id).toBe(userId);
      for (let attempt = 0; attempt < 2; attempt++) {
        const response = await auth.handler(
          new Request("http://localhost:3000/api/auth/update-user", {
            method: "POST",
            headers: new Headers({
              ...Object.fromEntries(headers),
              "content-type": "application/json",
              origin: "http://localhost:3000",
            }),
            body: JSON.stringify({ name: "Stolen session" }),
          }),
        );
        expect(response.status).toBe(401);
        const cookies = response.headers.getSetCookie();
        for (const name of ["better-auth.session_token", "better-auth.session_data"]) {
          expect(
            cookies.some((cookie) => cookie.startsWith(`${name}=`) && cookie.includes("Max-Age=0")),
          ).toBe(true);
        }
        expect(
          cookies.filter(
            (cookie) =>
              cookie.startsWith("better-auth.session_data=") && !cookie.includes("Max-Age=0"),
          ),
        ).toEqual([]);
        expect(memory.user![0]!.name).toBe("Owner");
      }
      // Direct API dispatch must enforce the same check, even without a Request/method.
      await expect(
        auth.api.updateUser({ headers, body: { name: "Stolen again" } }),
      ).rejects.toMatchObject({ status: "UNAUTHORIZED" });
    },
  );

  it.each(["/two-factor/generate-backup-codes", "/two-factor/send-otp"])(
    "rejects revoked cookie authority on plugin write %s",
    async (path) => {
      const headers = await signIn();
      memory.session = [];
      const response = await auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method: "POST",
          headers: new Headers({
            ...Object.fromEntries(headers),
            "content-type": "application/json",
            origin: "http://localhost:3000",
          }),
          body: JSON.stringify({ userCode: "code" }),
        }),
      );
      expect(response.status).toBe(401);
      expect(
        response.headers
          .getSetCookie()
          .some(
            (cookie) =>
              cookie.startsWith("better-auth.session_data=") && cookie.includes("Max-Age=0"),
          ),
      ).toBe(true);
    },
  );

  it("allows a live session to update and renew its cache", async () => {
    const headers = await signIn();
    const response = await auth.api.updateUser({
      headers,
      body: { name: "New name" },
      asResponse: true,
    });
    expect(response.status).toBe(200);
    expect(
      response.headers
        .getSetCookie()
        .some(
          (cookie) =>
            cookie.startsWith("better-auth.session_data=") && !cookie.includes("Max-Age=0"),
        ),
    ).toBe(true);
  });

  it("allows password recovery and sign-out with a revoked session cookie", async () => {
    const headers = await signIn();
    memory.session = [];
    await expect(
      auth.api.resetPassword({ headers, body: { token: resetToken, newPassword } }),
    ).resolves.toEqual({ status: true });
    await expect(auth.api.signOut({ headers })).resolves.toEqual({ success: true });
  });

  it("keeps the 60 s signed cookie cache (a revoked session ends within it; minting re-checks the live row)", () => {
    expect(auth.options.session?.cookieCache).toEqual({ enabled: true, maxAge: 60 });
  });
});

it("password revocation aborts an already-open MCP request through the ban announcement path", async () => {
  vi.useRealTimers();
  const { createMcpAuthenticator } = await import("../../../apps/server/src/mcp/auth");
  const reached = Promise.withResolvers<void>();
  let activeSignal: AbortSignal | undefined;
  const authenticate = createMcpAuthenticator({
    authInstance: {} as Parameters<typeof createMcpAuthenticator>[0]["authInstance"],
    authenticateAgent: async () => ({
      kind: "sdkKey",
      credentialKind: "AGENT_TOKEN",
      keyId: "stolen",
      ownerId: "reset-owner",
      expiresAt: null,
      resourceMode: "ALL_OWNED",
      ownSandboxesOnly: true,
      scopes: new Set(["sandboxes:read"]),
      allowedHostIds: "allOwned",
      allowedRevisionIds: "allOwned",
      allowedPoolIds: "allUsable",
    }),
    quota: async () => {},
    transport: {
      fetch: async (request) => {
        activeSignal = request.signal;
        reached.resolve();
        await new Promise<void>((resolve) =>
          request.signal.addEventListener("abort", () => resolve(), { once: true }),
        );
        return new Response(null, { status: 204 });
      },
    },
  });
  const pending = authenticate(
    new Request("http://localhost:3000/mcp", {
      method: "POST",
      headers: { host: "localhost:3000", authorization: "Bearer wssp_agent_test" },
      body: "{}",
    }),
  );
  await reached.promise;
  expect(activeSignal?.aborted).toBe(false);
  const { revokeCredentialsAfterPasswordChange: realRevoke } =
    await vi.importActual<typeof import("./credential-revocation")>("./credential-revocation");
  revokeCredentials.mockImplementation(realRevoke);
  await reset();
  expect(activeSignal?.aborted).toBe(true);
  // Upstream's stateless transport reports an aborted bodyless response as 499.
  expect((await pending).status).toBe(499);
});

// Adapter writes commit independently; a spent reset link never returns on failure.
describe("password reset without adapter transactions", { timeout: 20_000 }, () => {
  it.each([400, 500])(
    "fails closed when the password write fails after the token was spent (%i)",
    async (status) => {
      const { APIError } = await import("better-auth/api");
      const { betterAuth: realBetterAuth } =
        await vi.importActual<typeof import("better-auth")>("better-auth");
      const { memoryAdapter } = await import("better-auth/adapters/memory");
      const now = new Date();
      const db: Record<string, Record<string, unknown>[]> = {
        user: [
          {
            id: "u1",
            email: "reset@example.test",
            name: "Reset",
            emailVerified: true,
            createdAt: now,
            updatedAt: now,
          },
        ],
        account: [],
        session: [
          {
            id: "s1",
            userId: "u1",
            token: "session-token",
            expiresAt: new Date(now.getTime() + 3_600_000),
            createdAt: now,
            updatedAt: now,
          },
        ],
        verification: [
          {
            id: "v1",
            identifier: "reset-password:the-token",
            value: "u1",
            expiresAt: new Date(now.getTime() + 3_600_000),
            createdAt: now,
            updatedAt: now,
          },
        ],
      };
      const memory = memoryAdapter(db);
      // Like chess's Prisma adapter: `transaction` just runs the work, so every
      // write commits as it happens. The account (password) write fails.
      const nonTransactional = ((adapterOptions: Parameters<typeof memory>[0]) => {
        const inner = memory(adapterOptions);
        const adapter: typeof inner = new Proxy(inner, {
          get(target, key, receiver) {
            if (key === "transaction")
              return (work: (trx: typeof inner) => unknown) => work(adapter);
            const value = Reflect.get(target, key, receiver);
            if ((key === "update" || key === "updateMany") && typeof value === "function") {
              return (args: { model: string }) => {
                if (args.model === "account") {
                  if (status === 400)
                    throw new APIError("BAD_REQUEST", { message: "password write failed" });
                  throw new Error("password write failed");
                }
                return Reflect.apply(value, target, [args]);
              };
            }
            return value;
          },
        });
        return adapter;
      }) as typeof memory;
      revokeCredentials.mockClear();
      const instance = realBetterAuth({
        baseURL: "https://app.example.test",
        secret: "disposable-unit-test-secret-with-no-external-use",
        database: nonTransactional,
        rateLimit: { enabled: false },
        user: rawAuth.options.user,
        emailAndPassword: { ...rawAuth.options.emailAndPassword, enabled: true },
        logger: { disabled: true },
      } as Parameters<typeof realBetterAuth>[0]);
      const ctx = await instance.$context;
      const oldHash = await ctx.password.hash("old-password-12345");
      db.account?.push({
        id: "a1",
        userId: "u1",
        accountId: "u1",
        providerId: "credential",
        password: oldHash,
        createdAt: now,
        updatedAt: now,
      });

      const res = await instance.handler(
        new Request("https://app.example.test/api/auth/reset-password", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://app.example.test" },
          body: JSON.stringify({ token: "the-token", newPassword: "new-password-12345" }),
        }),
      );

      expect(res.status).toBe(status);
      expect(db.verification).toHaveLength(0); // the link is spent
      expect(db.session).toHaveLength(0); // existing sessions were deleted
      expect(db.account?.[0]?.password).toBe(oldHash); // the old password stays
      expect(revokeCredentials).not.toHaveBeenCalled();
    },
  );
});

it("refuses server-only setPassword for an existing passwordless user outside a write lock", async () => {
  const headers = await signIn();
  memory.account = [];
  await expect(rawAuth.api.setPassword({ headers, body: { newPassword } })).rejects.toThrow(
    /password-write lock/,
  );
  expect(memory.account).toEqual([]);
});

it("production session hook refuses a raw unfenced password sign-in", async () => {
  const response = await rawAuth.handler(
    new Request("http://localhost:3000/api/auth/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "owner@example.test", password }),
    }),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(memory.session).toHaveLength(3);
});
