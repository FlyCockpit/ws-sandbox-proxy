import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedMintSession } from "../sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "agent-pg-fixture",
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: true,
    WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: 90,
    SANDBOX_REQUEST_HMAC_SECRET: "test".repeat(16),
    BETTER_AUTH_URL: "https://example.test",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
const db = await pgTestDatabase();
afterAll(() => db.close());
const { createAgentToken } = await import("../sandbox/services/agent-tokens");
const { createSdkKey } = await import("../sandbox/services/sdk-keys");
const { authenticateSdkKeySecret, authenticateAgentTokenSecret, serviceResourceFilter } =
  await import("../lib/sdk-key-access");
const { listSandboxes } = await import("../sandbox/services/sandboxes");
const { seedSandboxInstance, seedTemplateRevision, seedAcceptedOperation } = await import(
  "../sandbox/testing/resource-fixtures"
);
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
  return seedMintSession(db.inspect, { kind: "session" as const, ownerId: id });
}
const mintInput = () => ({
  name: "Agent",
  scopes: ["sandboxes:read" as const],
  resourceMode: "ALL_OWNED" as const,
  expiresAt: new Date(Date.now() + 86_400_000),
});
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );
it("serializes the tenth and eleventh token mint under the owner advisory lock", async () => {
  const owner = await fixture();
  for (let i = 0; i < 9; i++) await createAgentToken(owner, mintInput());
  const gate = db.pauseAt("first", { after: "sdkKey.count" });
  const first = settle(db.run("first", () => createAgentToken(owner, mintInput())));
  await gate.waitReached();
  const second = settle(db.run("second", () => createAgentToken(owner, mintInput())));
  try {
    await db.waitUntilBlocked("second", { by: "first" });
  } finally {
    gate.release();
  }
  const [a, b] = await Promise.all([first, second]);
  expect(a.error).toBeUndefined();
  expect(b.error).toMatchObject({ code: "CONFLICT", data: { code: "agent_token.limit" } });
  expect(
    await db.inspect.sdkKey.count({
      where: {
        userId: owner.ownerId,
        kind: "AGENT_TOKEN",
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    }),
  ).toBe(10);
});
it("expired and revoked tokens do not consume the active token cap", async () => {
  const owner = await fixture();
  for (let i = 0; i < 10; i++) await createAgentToken(owner, mintInput());
  const keys = await db.inspect.sdkKey.findMany({
    where: { userId: owner.ownerId },
    take: 10,
    select: { id: true },
  });
  await db.inspect.sdkKey.update({ where: { id: keys[0]!.id }, data: { revokedAt: new Date() } });
  await db.inspect.sdkKey.update({ where: { id: keys[1]!.id }, data: { expiresAt: new Date(0) } });
  await expect(createAgentToken(owner, mintInput())).resolves.toBeDefined();
  await expect(createAgentToken(owner, mintInput())).resolves.toBeDefined();
});
it("all-owned own-only filters creator identity in SQL before pagination", async () => {
  const owner = await fixture();
  const agent = await createAgentToken(owner, mintInput());
  const sibling = await createAgentToken(owner, mintInput());
  const broad = await createSdkKey(owner, {
    name: "Broad",
    scopes: ["sandboxes:read"],
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
  });
  const principal = await authenticateAgentTokenSecret(agent.secret);
  const broadPrincipal = await authenticateSdkKeySecret(broad.secret);
  if (!principal || !broadPrincipal) throw new Error("fixture inactive");
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: owner.ownerId,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const created: string[] = [];
  for (const keyId of [sibling.key.id, agent.key.id, null, sibling.key.id, agent.key.id]) {
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: owner.ownerId,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        state: "READY",
      },
    });
    await seedAcceptedOperation(db.inspect, {
      data: {
        userId: owner.ownerId,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "SUCCEEDED",
        idempotencyKey: randomUUID(),
        authorizingKeyId: keyId,
        generation: 1,
        requestBodyHash: "a".repeat(64),
      },
    });
    if (keyId === agent.key.id) created.push(sandbox.id);
  }
  const first = await listSandboxes(principal, { limit: 1 });
  expect(first.items).toHaveLength(1);
  expect(first.nextCursor).not.toBeNull();
  const second = await listSandboxes(principal, { limit: 1, cursor: first.nextCursor! });
  expect(second.items).toHaveLength(1);
  expect(second.nextCursor).toBeNull();
  expect([...first.items, ...second.items].map((row) => row.id).sort()).toEqual(created.sort());
  expect(
    await db.inspect.sandbox.count({ where: serviceResourceFilter(broadPrincipal, "sandbox") }),
  ).toBe(5);
});

it("inserts and authenticates an AGENT_TOKEN with NULL expiry, and includes it in the cap", async () => {
  const owner = await fixture();
  const agent = await createAgentToken(owner, { ...mintInput(), expiresAt: null });
  expect(
    await db.inspect.sdkKey.findUnique({
      where: { id: agent.key.id },
      select: { kind: true, expiresAt: true },
    }),
  ).toEqual({ kind: "AGENT_TOKEN", expiresAt: null });
  expect(await authenticateAgentTokenSecret(agent.secret)).toMatchObject({ expiresAt: null });
  for (let i = 0; i < 9; i++) await createAgentToken(owner, { ...mintInput(), expiresAt: null });
  await expect(createAgentToken(owner, mintInput())).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "agent_token.limit" },
  });
});

it("the schema permits inserting a never-expiring agent token while retaining its secret invariant", async () => {
  const owner = await fixture();
  const { generateProductCredentialSecret, credentialLookupPrefix, hmacDigestForProductPurpose } =
    await import("@wssp/db/credential-security");
  const secret = generateProductCredentialSecret("agentToken");
  const data = {
    userId: owner.ownerId,
    name: "No expiry",
    kind: "AGENT_TOKEN" as const,
    scopes: ["sandboxes:read"],
    resourceMode: "ALL_OWNED" as const,
    lookupPrefix: credentialLookupPrefix(secret),
    secretDigest: hmacDigestForProductPurpose({ purpose: "agentToken", value: secret.raw }),
    expiresAt: null,
  };
  const row = await db.inspect.sdkKey.create({ data });
  expect(row.expiresAt).toBeNull();
  expect(await authenticateAgentTokenSecret(secret.raw)).toMatchObject({
    keyId: row.id,
    credentialKind: "AGENT_TOKEN",
    expiresAt: null,
  });
  await expect(
    db.inspect.sdkKey.create({
      data: { ...data, lookupPrefix: "wssp_agent_invalid", secretDigest: null },
    }),
  ).rejects.toThrow(/sdk_key_kind_secret/);
});
