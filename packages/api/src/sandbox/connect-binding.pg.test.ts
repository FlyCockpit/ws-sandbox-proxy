/**
 * The retained `sandboxes.connect` authorization against a real database
 * (wssp-ssh 1b): scope, kind, owner scoping, the synchronous `current()` after
 * a committed revoke, and the live re-read's verdicts.
 */
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "./testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "connect-binding-pg-fixture",
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: true,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const access = await import("../lib/sdk-key-access");
const { checkSandboxConnect } = await import("./connect-binding");
const { revokeSdkKey } = await import("./services/sdk-keys");
const { sessionPrincipal } = await import("./contracts");
afterAll(() => db.close());

async function fixture() {
  const ownerId = `connect-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, email: `${ownerId}@example.test`, name: "Owner", twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 4,
      egressEnforcement: true,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      templateId: revision.id,
      originPoolId: null,
      originHostId: host.id,
      sandboxHostId: host.id,
      state: "READY",
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  const mint = async (scopes: string[], kind: "API" | "AGENT_TOKEN" = "API") => {
    const row = await db.inspect.sdkKey.create({
      data: {
        userId: ownerId,
        kind,
        name: `key-${randomUUID()}`,
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        scopes,
        resourceMode: "ALL_OWNED",
        ...(kind === "AGENT_TOKEN" ? { expiresAt: new Date(Date.now() + 86_400_000) } : {}),
      },
    });
    const principal = await access.revalidateSdkKey(row.id, ownerId);
    if (!principal) throw new Error("Fixture key was refused.");
    return principal;
  };
  return { ownerId, host, sandbox, mint };
}

it("authorizes a READY sandbox for a kind API key holding sandboxes:connect", async () => {
  const f = await fixture();
  const key = await f.mint(["sandboxes:connect"]);
  const checked = await checkSandboxConnect(key, f.sandbox.id);
  expect(checked).toMatchObject({
    ok: true,
    binding: {
      ownerId: f.ownerId,
      keyId: key.keyId,
      sandboxId: f.sandbox.id,
      hostId: f.host.id,
      hostOwnerId: f.ownerId,
      epoch: 4,
    },
  });
  if (!checked.ok) throw new Error("unreachable");
  expect(checked.retained.current()).toBe(true);
});

it("refuses a key without the scope (403), an agent token (403) and another owner's sandbox (404)", async () => {
  const f = await fixture();
  await expect(
    checkSandboxConnect(await f.mint(["commands:execute", "sandboxes:read"]), f.sandbox.id),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await expect(
    checkSandboxConnect(await f.mint(["sandboxes:read"], "AGENT_TOKEN"), f.sandbox.id),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  const other = await fixture();
  await expect(
    checkSandboxConnect(await other.mint(["sandboxes:connect"]), f.sandbox.id),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("a committed revoke makes the retained authorization stale at once and the re-read refuses", async () => {
  const f = await fixture();
  const key = await f.mint(["sandboxes:connect"]);
  const checked = await checkSandboxConnect(key, f.sandbox.id);
  if (!checked.ok) throw new Error("fixture not connectable");
  await revokeSdkKey(sessionPrincipal(f.ownerId), { id: key.keyId });
  expect(checked.retained.current()).toBe(false);
  await expect(checkSandboxConnect(key, f.sandbox.id, checked.binding)).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
});

it("the live re-read reports a stopped sandbox, a new generation and a new host connection", async () => {
  const f = await fixture();
  const key = await f.mint(["sandboxes:connect"]);
  const checked = await checkSandboxConnect(key, f.sandbox.id);
  if (!checked.ok) throw new Error("fixture not connectable");
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { connectionEpoch: 5 } });
  expect(await checkSandboxConnect(key, f.sandbox.id, checked.binding)).toEqual({
    ok: false,
    intent: "host_disconnected",
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { generation: { increment: 1 } },
  });
  expect(await checkSandboxConnect(key, f.sandbox.id, checked.binding)).toEqual({
    ok: false,
    intent: "superseded",
  });
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "STOPPED" } });
  expect(await checkSandboxConnect(key, f.sandbox.id, checked.binding)).toEqual({
    ok: false,
    intent: "sandbox_stopped",
  });
});
