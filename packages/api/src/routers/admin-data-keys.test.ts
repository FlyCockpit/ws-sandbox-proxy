import { createRouterClient } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import type { MockPrisma } from "../test/mock-prisma";

vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/queue", () => ({ redisConnection: { tag: "redis" } }));

const keys = vi.hoisted(() => ({
  rotate: vi.fn(),
  destroy: vi.fn(),
  declareLost: vi.fn(),
  list: vi.fn(),
  blockers: vi.fn(),
  promote: vi.fn(),
  status: vi.fn(),
  ring: vi.fn(),
}));
vi.mock("../credentials/return-keys", () => ({
  rotateReturnKey: keys.rotate,
  destroyReturnKey: keys.destroy,
  declareHostReturnKeyLost: keys.declareLost,
  listReturnKeys: keys.list,
  listReturnKeyBlockers: keys.blockers,
}));
vi.mock("../crypto/data-key-status", () => ({ readDataKeyStatus: keys.status }));
vi.mock("../crypto/data-key", () => ({ readDataKeyring: keys.ring }));
vi.mock("../crypto/data-key-epoch", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../crypto/data-key-epoch")>()),
  promoteDataKey: keys.promote,
}));

const { default: prisma } = await import("@wssp/db");
const db = prisma as MockPrisma;
const { DataKeyStaleWriter } = await import("../crypto/data-key-epoch");
const { adminDataKeysRouter } = await import("./admin-data-keys");
const context = { session: { user: { id: "admin" }, session: { id: "session" } } } as Context;
const client = createRouterClient(adminDataKeysRouter, { context });

const KID = "0123456789abcdef";
const RING = { current: { id: KID, key: Buffer.alloc(32, 9) }, previous: null };

beforeEach(() => {
  vi.clearAllMocks();
  keys.ring.mockReturnValue(RING);
});

it("returns 404 for a non-admin before any key IO", async () => {
  for (const call of [
    () => client.status(),
    () => client.listReturnKeys(),
    () => client.promote({ kid: KID }),
    () => client.rotateReturnKey(),
    () => client.destroyReturnKey({ kidR: KID, confirmKidR: KID, destroyQuarantined: false }),
    () => client.declareHostLost({ kidR: KID, hostId: "host-1" }),
  ]) {
    db.user.findUnique.mockResolvedValueOnce({ id: "admin", role: "user" } as never);
    await expect(call()).rejects.toMatchObject({ code: "NOT_FOUND" });
  }
  for (const fn of Object.values(keys)) if (fn !== keys.ring) expect(fn).not.toHaveBeenCalled();
});

it("status carries kids, counts and epochs only, never key material", async () => {
  keys.status.mockResolvedValue({
    epoch: { currentKid: KID, previousKid: null, epoch: "1", switchedAt: "2026-11-03T00:00:00Z" },
    counts: [{ source: "credential_secret_version.rootKid", kid: KID, rows: 3 }],
    kids: [{ kid: KID, rows: 3, current: true, safeToRemove: false }],
    held: [KID],
    heartbeats: null,
  });
  db.credentialReturnKeyState.findUnique.mockResolvedValue({
    currentKidR: "fedcba9876543210",
    currentEpoch: 2n,
  } as never);
  const status = await client.status();
  expect(status).toMatchObject({
    configured: true,
    returnKey: { currentKidR: "fedcba9876543210", currentEpoch: "2" },
  });
  expect(keys.status).toHaveBeenCalledWith({ ring: RING, redis: { tag: "redis" } });
  expect(JSON.stringify(status)).not.toContain(RING.current.key.toString("hex"));
});

it("an invalid or missing key reads as not configured and refuses promote", async () => {
  keys.ring.mockImplementation(() => {
    throw new Error("DATA_ENCRYPTION_KEY is invalid.");
  });
  keys.status.mockResolvedValue({ epoch: null, counts: [], kids: [], held: [], heartbeats: null });
  db.credentialReturnKeyState.findUnique.mockResolvedValue(null);
  await expect(client.status()).resolves.toMatchObject({ configured: false, returnKey: null });
  await expect(client.promote({ kid: KID })).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "admin.data_key_refused", reason: "not_configured" },
  });
  expect(keys.promote).not.toHaveBeenCalled();
});

it("promote runs in the admin write transaction and audits only a real switch, after commit", async () => {
  const info = vi.spyOn(console, "info").mockImplementation(() => {});
  keys.promote.mockResolvedValueOnce({
    ok: true,
    changed: true,
    currentKid: KID,
    previousKid: "1111111111111111",
    epoch: 3n,
  });
  await expect(client.promote({ kid: KID })).resolves.toEqual({
    changed: true,
    currentKid: KID,
    previousKid: "1111111111111111",
    epoch: "3",
  });
  expect(keys.promote).toHaveBeenCalledWith(RING, KID, db);
  expect(info).toHaveBeenCalledTimes(1);
  expect(JSON.parse(String(info.mock.calls[0]?.[0]))).toEqual({
    event: "data_key.promoted",
    actor: "admin",
    currentKid: KID,
    previousKid: "1111111111111111",
    epoch: "3",
  });
  keys.promote.mockResolvedValueOnce({ ok: false, reason: "key_not_held" });
  await expect(client.promote({ kid: KID })).rejects.toMatchObject({
    data: { code: "admin.data_key_refused", reason: "key_not_held" },
  });
  expect(info).toHaveBeenCalledTimes(1);
  info.mockRestore();
});

it("return-key rotation maps a stale writer to a retryable 503 and a missing state to not_initialized", async () => {
  keys.rotate.mockRejectedValueOnce(new DataKeyStaleWriter());
  await expect(client.rotateReturnKey()).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
  keys.rotate.mockResolvedValueOnce(null);
  await expect(client.rotateReturnKey()).rejects.toMatchObject({
    data: { reason: "not_initialized" },
  });
  keys.rotate.mockResolvedValueOnce({ kidR: KID, epoch: 5n });
  const info = vi.spyOn(console, "info").mockImplementation(() => {});
  await expect(client.rotateReturnKey()).resolves.toEqual({ kidR: KID, epoch: "5" });
  expect(keys.rotate).toHaveBeenLastCalledWith(db);
  expect(String(info.mock.calls[0]?.[0])).toContain("credential.return_key_rotated");
  info.mockRestore();
});

it("destruction needs the typed kid, passes the quarantine flag, and audits the count", async () => {
  await expect(
    client.destroyReturnKey({ kidR: KID, confirmKidR: "0123", destroyQuarantined: false }),
  ).rejects.toMatchObject({ data: { reason: "confirmation_mismatch" } });
  expect(keys.destroy).not.toHaveBeenCalled();
  keys.destroy.mockResolvedValueOnce({ ok: false, reason: "host_not_drained" });
  await expect(
    client.destroyReturnKey({ kidR: KID, confirmKidR: KID, destroyQuarantined: false }),
  ).rejects.toMatchObject({ data: { reason: "host_not_drained" } });
  const info = vi.spyOn(console, "info").mockImplementation(() => {});
  keys.destroy.mockResolvedValueOnce({ ok: true, quarantined: 2 });
  await expect(
    client.destroyReturnKey({ kidR: KID, confirmKidR: KID, destroyQuarantined: true }),
  ).resolves.toEqual({ kidR: KID, destroyed: true });
  expect(keys.destroy).toHaveBeenLastCalledWith({ kidR: KID, destroyQuarantined: true }, db);
  expect(JSON.parse(String(info.mock.calls[0]?.[0]))).toEqual({
    event: "credential.return_key_destroyed",
    actor: "admin",
    kidR: KID,
    destroyQuarantined: true,
    quarantined: 2,
  });
  info.mockRestore();
});

it("declare-lost is audited and refusals are typed", async () => {
  keys.declareLost.mockResolvedValueOnce({ ok: false, reason: "already_declared" });
  await expect(client.declareHostLost({ kidR: KID, hostId: "host-1" })).rejects.toMatchObject({
    data: { reason: "already_declared" },
  });
  const info = vi.spyOn(console, "info").mockImplementation(() => {});
  keys.declareLost.mockResolvedValueOnce({ ok: true });
  await expect(client.declareHostLost({ kidR: KID, hostId: "host-1" })).resolves.toEqual({
    kidR: KID,
    hostId: "host-1",
    declaredLost: true,
  });
  expect(String(info.mock.calls[0]?.[0])).toContain("credential.return_key_host_declared_lost");
  info.mockRestore();
});

it("bounds every list before IO", async () => {
  await expect(client.listReturnKeys({ limit: 51 })).rejects.toMatchObject({
    code: "BAD_REQUEST",
  });
  await expect(client.listReturnKeys({ cursor: "-1", limit: 5 })).rejects.toMatchObject({
    code: "BAD_REQUEST",
  });
  await expect(client.listReturnKeyBlockers({ kidR: "not-a-kid", limit: 5 })).rejects.toMatchObject(
    { code: "BAD_REQUEST" },
  );
  expect(keys.list).not.toHaveBeenCalled();
  keys.list.mockResolvedValue({ items: [], nextCursor: null });
  await client.listReturnKeys({ cursor: "7", limit: 5 });
  expect(keys.list).toHaveBeenCalledWith({ afterEpoch: 7n, limit: 5 });
});
