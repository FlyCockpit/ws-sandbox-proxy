import { createHash } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import type { MockPrisma } from "../test/mock-prisma";

vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/queue", () => ({ redisConnection: { tag: "redis" } }));

const CREDENTIAL = `tnsvc_${"s".repeat(43)}`;
const t = vi.hoisted(() => ({
  keys: vi.fn(),
  check: vi.fn(),
  fence: vi.fn(),
}));
vi.mock("../sandbox/tunnels/config", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sandbox/tunnels/config")>()),
  tunnelKeys: t.keys,
  sealCredential: () => ({ ciphertext: Buffer.alloc(8), nonce: Buffer.alloc(12), keyId: "k1" }),
}));
vi.mock("../sandbox/tunnels/tun-client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sandbox/tunnels/tun-client")>()),
  checkCredential: t.check,
}));
vi.mock("../crypto/data-key-epoch", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../crypto/data-key-epoch")>()),
  fenceWriteKey: t.fence,
}));

const { default: prisma } = await import("@wssp/db");
const db = prisma as MockPrisma;
const { adminTunnelRouter } = await import("./admin-tunnel");
const { TUNNEL_OWED } = await import("../sandbox/tunnels/rows");
const context = { session: { user: { id: "admin" }, session: { id: "session" } } } as Context;
const client = createRouterClient(adminTunnelRouter, { context });

const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const OLD = { apiUrl: "https://tunnel.example.com" };

beforeEach(() => {
  vi.clearAllMocks();
  t.keys.mockReturnValue({ current: { rootKeyId: "k1" }, all: [] });
  t.fence.mockResolvedValue({ rootKeyId: "k1" });
  t.check.mockResolvedValue(undefined);
  db.$queryRaw.mockResolvedValue([
    { disabledAt: null, apiUrl: OLD.apiUrl, credentialSha256: sha(CREDENTIAL) },
  ] as never);
  db.sandboxTunnel.count.mockResolvedValue(0);
});

it("is hidden (404) for non-admins and never calls the tunnel server", async () => {
  for (const call of [
    () => client.get(),
    () => client.set({ apiUrl: "https://other.example.com", credential: CREDENTIAL }),
    () => client.clear({}),
  ]) {
    db.user.findUnique.mockResolvedValueOnce({ id: "admin", role: "user" } as never);
    await expect(call()).rejects.toMatchObject({ code: "NOT_FOUND" });
  }
  expect(t.check).not.toHaveBeenCalled();
});

it("get reports the setting without the credential", async () => {
  db.tunnelServerConfig.findUnique.mockResolvedValue({
    apiUrl: OLD.apiUrl,
    maxTunnelsPerOwner: 10,
    updatedAt: new Date(1000),
    disabledAt: null,
  } as never);
  db.sandboxTunnel.count.mockResolvedValueOnce(2).mockResolvedValueOnce(1);
  const read = await client.get();
  expect(read).toMatchObject({
    configured: true,
    turningOff: false,
    apiUrl: OLD.apiUrl,
    tunnels: { total: 2, connected: 1 },
  });
  expect(JSON.stringify(read)).not.toContain("tnsvc_");
});

it("a configuration never changes its server or credential: turn tunnels off first", async () => {
  const other = `tnsvc_${"o".repeat(43)}`;
  for (const input of [
    { apiUrl: "https://other.example.com", credential: CREDENTIAL },
    { apiUrl: OLD.apiUrl, credential: other },
  ])
    await expect(client.set(input)).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "admin.tunnel_config_refused", reason: "turn_off_first" },
    });
  // While turning off nothing changes, not even with the same credential
  // (no re-entry: a lost key is what remove-now is for).
  const locked = { apiUrl: OLD.apiUrl, credentialSha256: sha(CREDENTIAL) };
  db.$queryRaw.mockResolvedValue([{ ...locked, disabledAt: new Date() }] as never);
  await expect(client.set({ apiUrl: OLD.apiUrl, credential: CREDENTIAL })).rejects.toMatchObject({
    data: { reason: "turning_off" },
  });
  db.$queryRaw.mockResolvedValue([{ ...locked, disabledAt: null }] as never);
  expect(t.check).not.toHaveBeenCalled();
  expect(db.tunnelServerConfig.create).not.toHaveBeenCalled();
  expect(db.tunnelServerConfig.update).not.toHaveBeenCalled();
  // The same server (credential omitted or re-sent): only the limit changes.
  await expect(
    client.set({ apiUrl: OLD.apiUrl, credential: CREDENTIAL, maxTunnelsPerOwner: 20 }),
  ).resolves.toEqual({ configured: true, apiUrl: OLD.apiUrl, changed: false });
  expect(db.tunnelServerConfig.update).toHaveBeenCalledWith({
    where: { id: "default" },
    data: { maxTunnelsPerOwner: 20, updatedById: "admin" },
  });
  expect(t.check).not.toHaveBeenCalled();
});

it("a first configure checks the credential and mints a new identity each time", async () => {
  db.$queryRaw.mockResolvedValue([] as never);
  await expect(client.set({ apiUrl: OLD.apiUrl })).rejects.toMatchObject({
    data: { reason: "credential_required" },
  });
  await client.set({ apiUrl: OLD.apiUrl, credential: CREDENTIAL });
  await client.set({ apiUrl: OLD.apiUrl, credential: CREDENTIAL });
  expect(t.check).toHaveBeenCalledWith({ apiUrl: OLD.apiUrl, credential: CREDENTIAL });
  const keys = db.tunnelServerConfig.create.mock.calls.map(([args]) => {
    const data = (args as { data: { serverKey: string; credentialSha256: string } }).data;
    expect(data.credentialSha256).toBe(sha(CREDENTIAL));
    expect(data.serverKey).toMatch(/^[0-9a-f]{64}$/);
    return data.serverKey;
  });
  expect(new Set(keys).size).toBe(2);
  expect(db.tunnelServerConfig.upsert).not.toHaveBeenCalled();
});

it("refuses a host name the relay frame cannot carry", async () => {
  await expect(
    client.set({ apiUrl: "https://my_tunnel.example.com", credential: CREDENTIAL }),
  ).rejects.toMatchObject({ data: { reason: "url_invalid" } });
});

it("turning off only marks the setting; rows stay for the controller", async () => {
  db.tunnelServerConfig.updateMany.mockResolvedValue({ count: 1 });
  db.sandboxTunnel.count.mockResolvedValue(3);
  await expect(client.clear({})).resolves.toEqual({ turningOff: true, tunnelsLeft: 3 });
  expect(db.tunnelServerConfig.updateMany).toHaveBeenCalledWith(
    expect.objectContaining({ where: { id: "default", disabledAt: null } }),
  );
  expect(db.sandboxTunnel.count).toHaveBeenCalledWith({ where: TUNNEL_OWED });
  expect(db.sandboxTunnel.deleteMany).not.toHaveBeenCalled();
  expect(db.sandboxTunnel.updateMany).not.toHaveBeenCalled();
});

it("remove now closes every owed row (generation kept rising) instead of deleting it", async () => {
  db.$queryRaw.mockResolvedValue([{ serverKey: "key-1" }]);
  db.tunnelServerConfig.deleteMany.mockResolvedValue({ count: 1 });
  db.sandboxTunnel.count.mockResolvedValue(2);
  await expect(client.clear({ removeNow: true })).resolves.toEqual({
    turningOff: true,
    tunnelsLeft: 0,
  });
  expect(db.sandboxTunnel.deleteMany).not.toHaveBeenCalled();
  // Rows whose remote state is forgotten unconfirmed never report their
  // clean-up done, and are marked before their key goes.
  expect(db.sandboxTunnel.updateMany).toHaveBeenNthCalledWith(1, {
    where: { serverKey: { not: null } },
    data: { cleanupForgottenAt: expect.any(Date) },
  });
  expect(db.sandboxTunnel.updateMany).toHaveBeenNthCalledWith(2, {
    where: TUNNEL_OWED,
    data: expect.objectContaining({
      closedAt: expect.any(Date),
      tunTunnelId: null,
      sweepLabel: false,
      creatingUntil: null,
      serverKey: null,
      generation: { increment: 1 },
    }),
  });
  // Under the configuration's lock: no write gives a row its key meanwhile.
  const locks = db.$queryRaw.mock.calls.map(([query]) => (query as string[]).join("?"));
  expect(locks.some((query) => /tunnel_server_config[\s\S]*FOR UPDATE/.test(query))).toBe(true);
  expect(db.tunnelServerConfig.deleteMany).toHaveBeenCalledWith({ where: { id: "default" } });
  // Its links may outlive it on the tunnel server: no revocation confirms
  // them gone by a later configuration's 404 any more.
  expect(db.sandboxTunnelLink.updateMany).toHaveBeenCalledWith({
    where: { serverKey: "key-1", revokedAt: null, forgottenAt: null },
    data: { forgottenAt: expect.any(Date) },
  });
});
