import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "agent-token-policy-pg-fixture",
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: true,
    WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: 90,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const access = await import("./sdk-key-access");
const crypto = await import("@wssp/db/credential-security");
const { listAgentTokens } = await import("../sandbox/services/agent-tokens");
const { sessionPrincipal } = await import("../sandbox/contracts");
const { env } = (await import("@wssp/env/server")) as unknown as {
  env: { WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: boolean };
};
afterAll(() => db.close());
afterEach(() => {
  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = true;
});

async function owner() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  return userId;
}

async function agentToken(userId: string, expiresAt: Date | null) {
  const credential = crypto.generateProductCredentialSecret("agentToken");
  const row = await db.inspect.sdkKey.create({
    data: {
      userId,
      kind: "AGENT_TOKEN",
      name: `agent-${randomUUID()}`,
      ownSandboxesOnly: true,
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      scopes: ["sandboxes:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: crypto.hmacDigestForProductPurpose({
        purpose: "agentToken",
        value: credential.raw,
      }),
      expiresAt,
    },
    select: { id: true },
  });
  return { id: row.id, raw: credential.raw };
}

async function listed(userId: string) {
  const page = await listAgentTokens(sessionPrincipal(userId), { includeRevoked: true });
  return new Map(page.items.map((item) => [item.id, item]));
}

it("blocks an existing no-expiry agent token while the switch is off and restores it once on", async () => {
  const userId = await owner();
  const never = await agentToken(userId, null);
  const dated = await agentToken(userId, new Date(Date.now() + 7 * 86_400_000));

  await expect(access.authenticateAgentTokenSecret(never.raw)).resolves.toMatchObject({
    keyId: never.id,
  });
  expect((await listed(userId)).get(never.id)?.blockedByPolicy).toBe(false);

  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
  await expect(access.authenticateAgentTokenSecret(never.raw)).rejects.toMatchObject({
    code: "agent_token.no_expiry_blocked",
  });
  await expect(access.revalidateSdkKey(never.id, userId)).resolves.toBeNull();
  // Dated tokens are unaffected.
  await expect(access.authenticateAgentTokenSecret(dated.raw)).resolves.toMatchObject({
    keyId: dated.id,
  });
  const whileOff = await listed(userId);
  expect(whileOff.get(never.id)).toMatchObject({ blockedByPolicy: true, revokedAt: null });
  expect(whileOff.get(dated.id)?.blockedByPolicy).toBe(false);
  // Kept, not revoked or deleted.
  const stored = await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: never.id } });
  expect(stored).toMatchObject({ revokedAt: null, expiresAt: null });

  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = true;
  await expect(access.authenticateAgentTokenSecret(never.raw)).resolves.toMatchObject({
    keyId: never.id,
    credentialKind: "AGENT_TOKEN",
  });
  expect((await listed(userId)).get(never.id)?.blockedByPolicy).toBe(false);
});

it("a revoked no-expiry token is reported revoked, never as blocked", async () => {
  const userId = await owner();
  const never = await agentToken(userId, null);
  await db.inspect.sdkKey.update({ where: { id: never.id }, data: { revokedAt: new Date() } });
  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
  await expect(access.authenticateAgentTokenSecret(never.raw)).resolves.toBeNull();
  expect((await listed(userId)).get(never.id)?.blockedByPolicy).toBe(false);
});

it("decides the policy at the final durable read, after the lookup and the lastUsedAt write", async () => {
  const userId = await owner();
  const never = await agentToken(userId, null);
  // Pause after the lastUsedAt write: the policy turns off before the final read.
  const pause = db.pauseAt("auth", { after: "sdkKey.updateMany" });
  const authenticating = db.run("auth", () => access.authenticateAgentTokenSecret(never.raw));
  await pause.waitReached();
  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
  pause.release();
  await expect(authenticating).rejects.toMatchObject({ code: "agent_token.no_expiry_blocked" });
});
