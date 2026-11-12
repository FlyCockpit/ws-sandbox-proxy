import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * C45: the host-credentials page's list/revoke procedures against real
 * PostgreSQL — owner scoping, cursor paging, digest-free projections, and a
 * revoked device credential that can no longer authenticate the host relay.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c45-pg-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { sandboxHostsRouter } = await import("../../../../packages/api/src/routers/sandbox-hosts");
const { authenticateSandboxHostWebsocketSecret } = await import(
  "../../../../packages/api/src/lib/host-token-access"
);
const { onAuthorityCommitted } = await import("@wssp/db/authority");
const { credentialLookupPrefix, generateProductCredentialSecret, hmacDigestForProductPurpose } =
  await import("@wssp/db/credential-security");
afterAll(() => db.close());

async function owner() {
  const id = `cred-${randomUUID()}`;
  const user = await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "lab", label: "Lab", status: "CONNECTED", connectionEpoch: 1 },
  });
  const device = generateProductCredentialSecret("deviceCredential");
  const deviceRow = await db.inspect.hostDeviceCredential.create({
    data: {
      userId: id,
      sandboxHostId: host.id,
      lookupPrefix: credentialLookupPrefix(device),
      secretDigest: hmacDigestForProductPurpose({ purpose: "deviceCredential", value: device.raw }),
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session,
    },
  } as Context;
  return {
    id,
    host,
    device,
    deviceRow,
    client: createRouterClient(sandboxHostsRouter, { context }),
  };
}

it("two owners list disjoint device credentials and host tokens, with no digest", async () => {
  const a = await owner();
  const b = await owner();
  const minted = await a.client.createHostToken({ hostId: a.host.id, name: "daemon" });
  const devicesA = await a.client.listDeviceCredentials({ limit: 50 });
  const devicesB = await b.client.listDeviceCredentials({ limit: 50 });
  expect(devicesA.items.map((row) => row.id)).toEqual([a.deviceRow.id]);
  expect(devicesB.items.map((row) => row.id)).toEqual([b.deviceRow.id]);
  expect(devicesA.items[0]).toMatchObject({
    lookupPrefix: a.deviceRow.lookupPrefix,
    host: { id: a.host.id, slug: "lab", label: "Lab", status: "CONNECTED" },
  });
  const tokensA = await a.client.listHostTokens({ limit: 50 });
  const tokensB = await b.client.listHostTokens({ limit: 50 });
  expect(tokensA.items.map((row) => row.id)).toEqual([minted.token.id]);
  expect(tokensB.items).toEqual([]);
  const serialized = JSON.stringify([devicesA, tokensA, minted.token]);
  expect(serialized).not.toContain("secretDigest");
  expect(serialized).not.toContain(a.deviceRow.secretDigest);
  expect(serialized).not.toContain(a.device.raw);
  expect(serialized).not.toContain(minted.secret);
});

it("a foreign owner's device-credential revoke is NOT_FOUND and changes nothing", async () => {
  const a = await owner();
  const b = await owner();
  await expect(b.client.revokeDeviceCredential({ id: a.deviceRow.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  const row = await db.inspect.hostDeviceCredential.findUniqueOrThrow({
    where: { id: a.deviceRow.id },
  });
  expect(row.revokedAt).toBeNull();
  expect(await authenticateSandboxHostWebsocketSecret(a.device.raw)).toMatchObject({
    tokenId: a.deviceRow.id,
    credentialKind: "deviceCredential",
  });
});

it("a revoked device credential stops authenticating and notifies the relay", async () => {
  const a = await owner();
  expect(await authenticateSandboxHostWebsocketSecret(a.device.raw)).not.toBeNull();
  const committed: unknown[] = [];
  const stop = onAuthorityCommitted((scope) => committed.push(scope));
  try {
    const revoked = await a.client.revokeDeviceCredential({ id: a.deviceRow.id });
    expect(revoked.revokedAt).toBeInstanceOf(Date);
    expect(JSON.stringify(revoked)).not.toContain("secretDigest");
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    stop();
  }
  // The session manager closes live sockets matching this scope (tokenId).
  expect(committed).toContainEqual({
    kind: "scoped",
    ownerId: a.id,
    credentialId: a.deviceRow.id,
  });
  expect(await authenticateSandboxHostWebsocketSecret(a.device.raw)).toBeNull();
  expect((await a.client.listDeviceCredentials({ limit: 50 })).items).toEqual([]);
  const withRevoked = await a.client.listDeviceCredentials({ limit: 50, includeRevoked: true });
  expect(withRevoked.items.map((row) => row.id)).toEqual([a.deviceRow.id]);
  // A second revoke is NOT_FOUND: nothing active to revoke.
  await expect(a.client.revokeDeviceCredential({ id: a.deviceRow.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
});

it("host tokens page by cursor, newest first, with every token reachable", async () => {
  const a = await owner();
  const ids: string[] = [];
  for (const name of ["one", "two", "three"]) {
    ids.push((await a.client.createHostToken({ hostId: a.host.id, name })).token.id);
  }
  const first = await a.client.listHostTokens({ limit: 2 });
  expect(first.items).toHaveLength(2);
  expect(first.nextCursor).not.toBeNull();
  const second = await a.client.listHostTokens({ limit: 2, cursor: first.nextCursor ?? undefined });
  expect(second.nextCursor).toBeNull();
  const seen = [...first.items, ...second.items].map((row) => row.id);
  expect(seen.sort()).toEqual([...ids].sort());
  expect(first.items[0]?.host).toMatchObject({ id: a.host.id, slug: "lab" });
});

it("explicit refusal verdicts come only with the full verified secret: revoked → credential_revoked, banned/deleting owner → owner_unavailable; wrong or unknown secrets stay ambiguous", async () => {
  const { authenticateSandboxHostWebsocket } = await import(
    "../../../../packages/api/src/lib/host-token-access"
  );
  const a = await owner();
  expect(await authenticateSandboxHostWebsocket(a.device.raw)).toMatchObject({
    identity: { tokenId: a.deviceRow.id },
  });
  // A wrong secret under a real lookup prefix, and an unknown credential.
  const wrong = generateProductCredentialSecret("deviceCredential");
  const forged = a.device.raw.slice(0, -4) + (a.device.raw.endsWith("AAAA") ? "BBBB" : "AAAA");
  await db.inspect.hostDeviceCredential.update({
    where: { id: a.deviceRow.id },
    data: { revokedAt: new Date() },
  });
  for (const secret of [wrong.raw, forged, "wssp_device_not-a-credential"])
    expect(await authenticateSandboxHostWebsocket(secret)).toBeNull();
  expect(await authenticateSandboxHostWebsocket(a.device.raw)).toEqual({
    refusal: "credential_revoked",
  });
  // Banned owner (credential itself not revoked), then a deleting owner.
  const b = await owner();
  await db.inspect.user.update({ where: { id: b.id }, data: { banned: true } });
  expect(await authenticateSandboxHostWebsocket(b.device.raw)).toEqual({
    refusal: "owner_unavailable",
  });
  expect(await authenticateSandboxHostWebsocket(forged)).toBeNull();
  const c = await owner();
  await db.inspect.user.update({ where: { id: c.id }, data: { deletionRequestedAt: new Date() } });
  expect(await authenticateSandboxHostWebsocket(c.device.raw)).toEqual({
    refusal: "owner_unavailable",
  });
  // The legacy identity-or-null API is unchanged for every refusal.
  expect(await authenticateSandboxHostWebsocketSecret(c.device.raw)).toBeNull();
});
