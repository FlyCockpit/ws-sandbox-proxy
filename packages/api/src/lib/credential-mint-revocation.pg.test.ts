import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "credential-reset-race-test",
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: true,
    WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: 90,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));

const db = await pgTestDatabase();
afterAll(() => db.close());
const { revokeCredentialsAfterPasswordChange } = await import(
  "../../../auth/src/credential-revocation"
);
const { mintCredentialKey } = await import("../sandbox/services/sdk-keys");
const { recordMcpConsent } = await import("../sandbox/services/mcp-consent");
const { seedMintSession } = await import("../sandbox/testing/resource-fixtures");
const { mintUserLoginFromApprovedDeviceCode } = await import("./user-login-credential-access");
const { transitionDeviceCode } = await import("./device-code-transitions");

const grant = {
  access: "read",
  poolMode: "ALL_USABLE",
  poolIds: [],
  ownSandboxesOnly: false,
  maxLiveSandboxes: 3,
  expiresInDays: 30,
  name: "CLI login",
};
async function fixture() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: id });
  const code = await db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      userId: id,
      scope: "user-login",
      status: "approved",
      loginGrant: grant,
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  return { owner, code };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
const kinds = ["API", "AGENT_TOKEN", "OAUTH_GRANT", "CLI_LOGIN"] as const;
async function mint(kind: (typeof kinds)[number], f: Fixture): Promise<string> {
  if (kind === "CLI_LOGIN")
    return (await mintUserLoginFromApprovedDeviceCode({ deviceCode: f.code.deviceCode })).keyId;
  if (kind === "OAUTH_GRANT") {
    await recordMcpConsent({
      userId: f.owner.ownerId,
      sessionId: f.owner.sessionId,
      clientId: "client",
      referenceId: "reference",
      requestedScopes: ["sandboxes:read"],
      choices: { scopes: ["sandboxes:read"], resourceMode: "ALL_OWNED" },
    });
    return (await db.inspect.mcpGrant.findFirstOrThrow({ where: { userId: f.owner.ownerId } }))
      .sdkKeyId;
  }
  return (
    await mintCredentialKey(
      f.owner,
      {
        name: "browser key",
        scopes: ["sandboxes:read"],
        resourceMode: "ALL_OWNED",
        hostIds: [],
        templateRevisionIds: [],
        expiresAt: new Date(Date.now() + 86_400_000),
      },
      kind,
    )
  ).key.id;
}
// The pinned endpoint's two sweeps. Endpoint/password/token
// behaviour is separately exercised against Better Auth in auth/src/index.test.ts.
async function resetAccess(f: Fixture) {
  await revokeCredentialsAfterPasswordChange(f.owner.ownerId, { revokeSessions: true });
  await revokeCredentialsAfterPasswordChange(f.owner.ownerId);
}
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );
it.each(["API", "AGENT_TOKEN", "OAUTH_GRANT"] as const)(
  "%s gap mint is refused after the pre-sweep even if the post-sweep never succeeds",
  async (kind) => {
    const f = await fixture();
    const other = await fixture();
    await db.inspect.session.create({
      data: {
        id: randomUUID(),
        userId: f.owner.ownerId,
        token: randomUUID(),
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    await revokeCredentialsAfterPasswordChange(f.owner.ownerId, { revokeSessions: true });
    // Stop before Better Auth's session deletion and omit the post-sweep: a
    // committed reset with a failed post-sweep must leave no gap credential.
    await expect(mint(kind, f)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(await db.inspect.session.count({ where: { userId: f.owner.ownerId } })).toBe(0);
    expect(await db.inspect.session.count({ where: { userId: other.owner.ownerId } })).toBe(1);
    expect(await db.inspect.sdkKey.count({ where: { userId: f.owner.ownerId } })).toBe(0);
  },
);

it.each(kinds)(
  "%s mint holding the owner lock finishes before reset and is revoked",
  async (kind) => {
    const f = await fixture();
    const gate = db.pauseAt("mint", { after: "sdkKey.create" });
    const minted = settle(db.run("mint", () => mint(kind, f)));
    await gate.waitReached();
    const reset = settle(db.run("reset", () => resetAccess(f)));
    try {
      await db.waitUntilBlocked("reset", { by: "mint" });
    } finally {
      gate.release();
    }
    const [result, resetResult] = await Promise.all([minted, reset]);
    expect(result.error).toBeUndefined();
    expect(resetResult.error).toBeUndefined();
    expect(
      await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: result.value! } }),
    ).toMatchObject({ revokedAt: expect.any(Date) });
    expect(
      await db.inspect.deviceCode.count({
        where: { userId: f.owner.ownerId, scope: "user-login" },
      }),
    ).toBe(0);
  },
);
it.each(kinds)("%s mint waiting for reset cannot leave a standing credential", async (kind) => {
  const f = await fixture();
  const gate = db.pauseAt("reset", { after: "sdkKey.updateMany" });
  const reset = settle(db.run("reset", () => resetAccess(f)));
  await gate.waitReached();
  const minted = settle(db.run("mint", () => mint(kind, f)));
  try {
    await db.waitUntilBlocked("mint", { by: "reset" });
  } finally {
    gate.release();
  }
  const [result, resetResult] = await Promise.all([minted, reset]);
  expect(resetResult.error).toBeUndefined();
  if (result.error)
    expect(result.error).toMatchObject({
      code: kind === "CLI_LOGIN" ? "NOT_FOUND" : "UNAUTHORIZED",
    });
  else
    expect(
      await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: result.value! } }),
    ).toMatchObject({ revokedAt: expect.any(Date) });
  expect(
    await db.inspect.sdkKey.count({ where: { userId: f.owner.ownerId, revokedAt: null } }),
  ).toBe(0);
  if (kind !== "CLI_LOGIN")
    await expect(mint(kind, f)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});
it("an unclaimed code cannot be approved by a cached session after reset", async () => {
  const f = await fixture();
  await db.inspect.deviceCode.update({
    where: { id: f.code.id },
    data: { userId: null, status: "pending" },
  });
  await resetAccess(f);
  await expect(
    transitionDeviceCode({
      userCode: f.code.userCode,
      userId: f.owner.ownerId,
      sessionId: f.owner.sessionId,
      action: "claim",
    }),
  ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  expect(await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: f.code.id } })).toMatchObject(
    { userId: null, status: "pending" },
  );
});

it.each(["missing", "expired", "foreign"] as const)(
  "refuses %s authorizing session rows",
  async (state) => {
    const f = await fixture();
    if (state === "missing")
      await db.inspect.session.deleteMany({ where: { id: f.owner.sessionId } });
    if (state === "expired")
      await db.inspect.session.update({
        where: { id: f.owner.sessionId },
        data: { expiresAt: new Date(0) },
      });
    if (state === "foreign") f.owner.sessionId = (await fixture()).owner.sessionId;
    await expect(mint("API", f)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(await db.inspect.sdkKey.count({ where: { userId: f.owner.ownerId } })).toBe(0);
  },
);
