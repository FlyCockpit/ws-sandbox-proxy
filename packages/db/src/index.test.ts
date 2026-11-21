import { beforeEach, describe, expect, it, vi } from "vitest";

const created = vi.hoisted(() => ({
  shared: [] as unknown[],
  audit: [] as { url: string; $disconnect: ReturnType<typeof vi.fn> }[],
}));

vi.mock("@wssp/env/shared", () => ({
  env: { DATABASE_URL: "postgresql://u:p@db.test/app", DATABASE_POOL_MAX: 10 },
}));
vi.mock("./client", () => ({
  createPrismaClient: (options: unknown) => {
    created.shared.push(options);
    return { kind: "shared" };
  },
  createConnectAuditPrismaClient: (url: string) => {
    const client = { url, $disconnect: vi.fn(async () => {}) };
    created.audit.push(client);
    return client;
  },
}));

beforeEach(() => {
  vi.resetModules();
  created.shared.length = 0;
  created.audit.length = 0;
});

describe("connectAuditPrisma", () => {
  it("is created lazily, once, and disconnecting a never-created client is a no-op", async () => {
    const db = await import("./index");
    expect(created.shared).toHaveLength(1);
    expect(created.audit).toHaveLength(0);
    await expect(db.disconnectConnectAuditPrisma()).resolves.toBeUndefined();
    expect(created.audit).toHaveLength(0);
    const client = db.connectAuditPrisma();
    expect(db.connectAuditPrisma()).toBe(client);
    expect(created.audit).toEqual([client]);
    expect(created.audit[0]?.url).toBe("postgresql://u:p@db.test/app");
    await db.disconnectConnectAuditPrisma();
    expect(created.audit[0]?.$disconnect).toHaveBeenCalledOnce();
  });

  it("the disconnect is bounded and never rejects", async () => {
    const db = await import("./index");
    const client = db.connectAuditPrisma() as unknown as (typeof created.audit)[number];
    vi.useFakeTimers();
    try {
      client.$disconnect.mockImplementationOnce(() => new Promise(() => {}));
      let settled = false;
      const done = db.disconnectConnectAuditPrisma().then(() => {
        settled = true;
      });
      await vi.advanceTimersByTimeAsync(db.CONNECT_AUDIT_DISCONNECT_MS - 1);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await done;
      client.$disconnect.mockRejectedValueOnce(new Error("socket closed"));
      await expect(db.disconnectConnectAuditPrisma()).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
