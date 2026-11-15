import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "mcp-consent-pg-fixture", BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const db = await pgTestDatabase();
const { recordMcpConsent } = await import("./mcp-consent");
afterAll(() => db.close());
async function fixture() {
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
  const session = await db.inspect.session.create({
    data: { userId, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  return {
    userId,
    sessionId: session.id,
    clientId: "client",
    referenceId: randomUUID(),
    requestedScopes: ["sandboxes:read", "hosts:read"],
    choices: { scopes: ["sandboxes:read"], resourceMode: "ALL_OWNED" },
  };
}
it.each(["revoked", "expired", "foreign", "impersonated"] as const)(
  "refuses a %s durable session before changing the existing key",
  async (kind) => {
    const f = await fixture();
    await recordMcpConsent(f);
    const grant = await db.inspect.mcpGrant.findFirstOrThrow({ where: { userId: f.userId } });
    if (kind === "revoked") await db.inspect.session.delete({ where: { id: f.sessionId } });
    if (kind === "expired")
      await db.inspect.session.update({
        where: { id: f.sessionId },
        data: { expiresAt: new Date(0) },
      });
    if (kind === "impersonated")
      await db.inspect.session.update({
        where: { id: f.sessionId },
        data: { impersonatedBy: "admin" },
      });
    if (kind === "foreign") f.sessionId = (await fixture()).sessionId;
    await expect(
      recordMcpConsent({
        ...f,
        choices: { ...f.choices, scopes: ["sandboxes:read", "hosts:read"] },
      }),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(
      (await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: grant.sdkKeyId } })).scopes,
    ).toEqual(["sandboxes:read"]);
  },
);
it("session revocation waits for the consent transaction's share lock", async () => {
  const f = await fixture();
  const pause = db.pauseAt("consent", { after: /sql:SELECT id FROM session.*FOR SHARE/ });
  const recording = db.run("consent", () => recordMcpConsent(f));
  await pause.waitReached();
  const revocation = db.run("revoke", () =>
    db.prisma.$transaction((tx) => tx.session.delete({ where: { id: f.sessionId } })),
  );
  try {
    await db.waitUntilBlocked("revoke", { by: "consent" });
  } finally {
    pause.release();
  }
  await recording;
  await revocation;
  await expect(recordMcpConsent(f)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});
it("consent waits for a winning session revocation and then refuses without inserting a grant", async () => {
  const f = await fixture();
  const pause = db.pauseAt("revoke", { after: "session.delete" });
  const revocation = db.run("revoke", () =>
    db.prisma.$transaction((tx) => tx.session.delete({ where: { id: f.sessionId } })),
  );
  await pause.waitReached();
  const recording = db.run("consent", () => recordMcpConsent(f));
  const outcome = recording.then(
    () => "accepted",
    () => "refused",
  );
  try {
    await db.waitUntilBlocked("consent", { by: "revoke" });
  } finally {
    pause.release();
  }
  await revocation;
  expect(await outcome).toBe("refused");
  expect(await db.inspect.mcpGrant.count({ where: { userId: f.userId } })).toBe(0);
});
it("serializes concurrent widening attempts against an existing grant", async () => {
  const f = await fixture();
  await recordMcpConsent(f);
  const attempts = await Promise.allSettled([
    recordMcpConsent(f),
    recordMcpConsent({ ...f, choices: { ...f.choices, scopes: ["sandboxes:read", "hosts:read"] } }),
  ]);
  expect(attempts.map((result) => result.status)).toEqual(["fulfilled", "rejected"]);
  expect(
    (await db.inspect.sdkKey.findFirstOrThrow({ where: { userId: f.userId } })).scopes,
  ).toEqual(["sandboxes:read"]);
});
