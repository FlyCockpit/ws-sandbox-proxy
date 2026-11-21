import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "connect-sessions-unit",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  // Writes go to the audit's isolated client, reads to the shared one.
  const audit = await createMockPrisma();
  return { default: await createMockPrisma(), connectAuditPrisma: () => audit };
});
const { default: prisma, connectAuditPrisma } = await import("@wssp/db");
type MockPrisma = import("../test/mock-prisma").MockPrisma;
const shared = prisma as unknown as MockPrisma;
const audit = connectAuditPrisma() as unknown as MockPrisma;
const { sessionPrincipal } = await import("./contracts");
const {
  CONNECT_AUDIT_MAX_WAIT_MS,
  CONNECT_AUDIT_TRANSACTION_TIMEOUT_MS,
  CONNECT_SESSION_STALE_MS,
  lastConnectByKey,
  listSandboxConnectSessions,
  recordConnectSessionClose,
  recordConnectSessionOpen,
} = await import("./connect-sessions");

beforeEach(() => vi.clearAllMocks());

describe("recordConnectSessionOpen / Close", () => {
  it("writes the key's own origin, owner-scoped, and nothing for a missing key", async () => {
    audit.sdkKey.findFirst.mockResolvedValueOnce({ origin: "CLI_LOGIN" } as never);
    audit.sandboxConnectSession.create.mockResolvedValueOnce({ id: "c1" } as never);
    const openedAt = new Date("2026-11-20T10:00:00Z");
    const open = { id: "c1", ownerId: "u1", sandboxId: "s1", hostId: "h1", keyId: "k1", openedAt };
    await expect(recordConnectSessionOpen(open)).resolves.toBe(true);
    expect(audit.sdkKey.findFirst).toHaveBeenCalledWith({
      where: { id: "k1", userId: "u1" },
      select: { origin: true },
    });
    expect(audit.sandboxConnectSession.create).toHaveBeenCalledWith({
      data: {
        id: "c1",
        userId: "u1",
        sandboxId: "s1",
        hostId: "h1",
        keyId: "k1",
        origin: "CLI_LOGIN",
        openedAt,
      },
      select: { id: true },
    });
    audit.sdkKey.findFirst.mockResolvedValueOnce(null);
    await expect(recordConnectSessionOpen(open)).resolves.toBe(false);
    expect(audit.sandboxConnectSession.create).toHaveBeenCalledTimes(1);
  });

  it("completes only an open row of the same owner, with sane counters", async () => {
    const closedAt = new Date("2026-11-20T10:05:00Z");
    audit.sandboxConnectSession.updateMany.mockResolvedValueOnce({ count: 1 });
    await expect(
      recordConnectSessionClose({
        id: "c1",
        ownerId: "u1",
        closedAt,
        closeIntent: "revoked",
        ptyChannels: 2,
        execChannels: -1,
        bytesIn: 5,
        bytesOut: Number.NaN,
      }),
    ).resolves.toBe(true);
    const call = audit.sandboxConnectSession.updateMany.mock.calls[0]?.[0];
    expect(call?.where).toEqual({ id: "c1", userId: "u1", closedAt: null });
    expect(call?.data).toEqual({
      closedAt,
      closeIntent: "revoked",
      ptyChannels: 2,
      execChannels: 0,
      bytesIn: 5n,
      bytesOut: 0n,
    });
  });

  it("an open that ended before it was written inserts the complete row once", async () => {
    audit.sdkKey.findFirst.mockResolvedValueOnce({ origin: "DASHBOARD" } as never);
    audit.sandboxConnectSession.create.mockResolvedValueOnce({ id: "c2" } as never);
    const openedAt = new Date("2026-11-20T10:00:00Z");
    const closedAt = new Date("2026-11-20T10:00:01Z");
    await expect(
      recordConnectSessionOpen({
        id: "c2",
        ownerId: "u1",
        sandboxId: "s1",
        hostId: "h1",
        keyId: "k1",
        openedAt,
        end: {
          closedAt,
          closeIntent: "client",
          ptyChannels: 1,
          execChannels: 0,
          bytesIn: 3,
          bytesOut: 4,
        },
      }),
    ).resolves.toBe(true);
    expect(audit.sandboxConnectSession.create.mock.calls[0]?.[0]?.data).toMatchObject({
      openedAt,
      closedAt,
      closeIntent: "client",
      ptyChannels: 1,
      bytesIn: 3n,
      bytesOut: 4n,
    });
    expect(audit.sandboxConnectSession.updateMany).not.toHaveBeenCalled();
  });

  it("every write runs in one bounded transaction on the audit client, never the shared one", async () => {
    audit.sandboxConnectSession.updateMany.mockResolvedValueOnce({ count: 0 });
    await recordConnectSessionClose({
      id: "c1",
      ownerId: "u1",
      closedAt: new Date(),
      closeIntent: "client",
      ptyChannels: 0,
      execChannels: 0,
      bytesIn: 0,
      bytesOut: 0,
    });
    audit.sdkKey.findFirst.mockResolvedValueOnce({ origin: "DASHBOARD" } as never);
    audit.sandboxConnectSession.create.mockResolvedValueOnce({ id: "c3" } as never);
    await recordConnectSessionOpen({
      id: "c3",
      ownerId: "u1",
      sandboxId: "s1",
      hostId: "h1",
      keyId: "k1",
      openedAt: new Date(),
    });
    expect(audit.$transaction).toHaveBeenCalledTimes(2);
    for (const call of audit.$transaction.mock.calls) {
      expect(call).toEqual([
        expect.any(Function),
        { maxWait: CONNECT_AUDIT_MAX_WAIT_MS, timeout: CONNECT_AUDIT_TRANSACTION_TIMEOUT_MS },
      ]);
    }
    expect(shared.$transaction).not.toHaveBeenCalled();
    expect(shared.sdkKey.findFirst).not.toHaveBeenCalled();
    expect(shared.sandboxConnectSession.create).not.toHaveBeenCalled();
    expect(shared.sandboxConnectSession.updateMany).not.toHaveBeenCalled();
  });
});

describe("listSandboxConnectSessions", () => {
  const owner = sessionPrincipal("u1");

  it("is owner-scoped: a sandbox the caller does not own is not found", async () => {
    shared.sandbox.findFirst.mockResolvedValueOnce(null);
    await expect(listSandboxConnectSessions(owner, { id: "s1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(shared.sandbox.findFirst).toHaveBeenCalledWith({
      where: { id: "s1", userId: "u1" },
      select: { id: true },
    });
    expect(shared.sandboxConnectSession.findMany).not.toHaveBeenCalled();
  });

  it("reads one bounded page newest first and projects metadata only", async () => {
    shared.sandbox.findFirst.mockResolvedValueOnce({ id: "s1" } as never);
    const now = Date.now();
    shared.sandboxConnectSession.findMany.mockResolvedValueOnce([
      {
        id: "c2",
        keyId: "k1",
        hostId: "h1",
        origin: "DASHBOARD",
        openedAt: new Date(now - 1000),
        closedAt: null,
        closeIntent: null,
        ptyChannels: 0,
        execChannels: 0,
        bytesIn: 0n,
        bytesOut: 0n,
      },
      {
        id: "c1",
        keyId: "gone",
        hostId: "h1",
        origin: "CLI_LOGIN",
        openedAt: new Date(now - CONNECT_SESSION_STALE_MS - 1000),
        closedAt: null,
        closeIntent: null,
        ptyChannels: 1,
        execChannels: 0,
        bytesIn: 12n,
        bytesOut: 9_007_199_254_740_993n,
      },
    ] as never);
    shared.sdkKey.findMany.mockResolvedValueOnce([{ id: "k1", name: "ci" }] as never);
    const page = await listSandboxConnectSessions(owner, { id: "s1", limit: 5 });
    const query = shared.sandboxConnectSession.findMany.mock.calls[0]?.[0];
    expect(query?.take).toBe(6);
    expect(query?.orderBy).toEqual([{ openedAt: "desc" }, { id: "desc" }]);
    expect(query?.where).toEqual({ AND: [{ userId: "u1", sandboxId: "s1" }] });
    expect(Object.keys(query?.select ?? {}).sort()).toEqual(
      [
        "bytesIn",
        "bytesOut",
        "closeIntent",
        "closedAt",
        "execChannels",
        "hostId",
        "id",
        "keyId",
        "openedAt",
        "origin",
        "ptyChannels",
      ].sort(),
    );
    expect(shared.sdkKey.findMany).toHaveBeenCalledWith({
      where: { userId: "u1", id: { in: ["k1", "gone"] } },
      take: 2,
      select: { id: true, name: true },
    });
    expect(page.nextCursor).toBeNull();
    expect(page.items.map((row) => [row.id, row.keyName, row.status])).toEqual([
      ["c2", "ci", "open"],
      ["c1", null, "unknown"],
    ]);
    expect(page.items[1]?.bytesOut).toBe("9007199254740993");
  });
});

describe("lastConnectByKey", () => {
  it("one owner-scoped aggregate bounded by the page's key ids", async () => {
    await expect(lastConnectByKey("u1", [])).resolves.toEqual(new Map());
    expect(shared.sandboxConnectSession.groupBy).not.toHaveBeenCalled();
    const at = new Date("2030-01-01T00:00:00Z");
    shared.sandboxConnectSession.groupBy.mockResolvedValueOnce([
      { keyId: "k1", _max: { openedAt: at } },
    ] as never);
    const last = await lastConnectByKey("u1", ["k1", "k2"]);
    expect(last).toEqual(new Map([["k1", at]]));
    expect(shared.sandboxConnectSession.groupBy).toHaveBeenCalledWith({
      by: ["keyId"],
      where: { userId: "u1", keyId: { in: ["k1", "k2"] } },
      _max: { openedAt: true },
      orderBy: { keyId: "asc" },
      take: 2,
    });
  });
});
