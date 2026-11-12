import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { bindSandboxTerminalLifecycle, sandboxTerminalWrite } = await import("./terminal-lifecycle");
const { sandboxOutboxTransaction } = await import("./outbox");

describe("sandboxTerminalWrite (which sandbox writes can end a terminal)", () => {
  it.each([
    ["updateMany", { where: { id: "s1" }, data: { state: "STOPPING" } }, ["s1"]],
    ["update", { where: { id: "s1" }, data: { generation: 4 } }, ["s1"]],
    ["updateMany", { where: { id: "s1" }, data: { sandboxHostId: null } }, ["s1"]],
    ["delete", { where: { id: "s1" } }, ["s1"]],
    ["updateMany", { where: { sandboxHostId: "h" }, data: { state: "UNREACHABLE" } }, "all"],
    ["deleteMany", { where: { userId: "u" } }, "all"],
    ["updateMany", undefined, "all"],
  ] as const)("%s %j → %j", (method, args, expected) => {
    const change = sandboxTerminalWrite(method, args);
    expect(change === "all" ? "all" : [...(change?.sandboxIds ?? [])]).toEqual(expected);
  });

  it.each([
    ["updateMany", { where: { id: "s1" }, data: { leaseExpiresAtEffective: new Date() } }],
    ["updateMany", { where: { id: "s1" }, data: { liveResourcesHeld: false } }],
    ["create", { data: { state: "READY" } }],
    ["findFirst", { where: { id: "s1" } }],
  ] as const)("%s %j is not terminal-relevant", (method, args) => {
    expect(sandboxTerminalWrite(method, args)).toBeNull();
  });
});

describe("sandboxOutboxTransaction announces terminal lifecycle only after commit", () => {
  const seen: unknown[] = [];
  beforeEach(() => {
    vi.clearAllMocks();
    seen.length = 0;
    bindSandboxTerminalLifecycle((change) => {
      seen.push(change === "all" ? "all" : [...change.sandboxIds]);
    });
    db.$transaction.mockImplementation((async (work: (tx: typeof db) => Promise<unknown>) =>
      work(db)) as never);
    db.sandboxHost.findMany.mockResolvedValue([]);
  });

  it("a committed stop announces the sandbox once, after the transaction resolved", async () => {
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandbox.updateMany({ where: { id: "s1" }, data: { state: "STOPPING" } });
      expect(seen).toEqual([]); // not before commit
      await tx.sandbox.updateMany({ where: { id: "s2" }, data: { generation: 2 } });
    });
    expect(seen).toEqual([["s1", "s2"]]);
  });

  it("a write that matched no row, a rollback, and an unrelated write announce nothing", async () => {
    db.sandbox.updateMany.mockResolvedValueOnce({ count: 0 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandbox.updateMany({ where: { id: "s1" }, data: { state: "STOPPED" } });
    });
    db.sandbox.updateMany.mockResolvedValueOnce({ count: 1 });
    await expect(
      sandboxOutboxTransaction(async (tx) => {
        await tx.sandbox.updateMany({ where: { id: "s1" }, data: { state: "STOPPED" } });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    db.sandbox.updateMany.mockResolvedValueOnce({ count: 1 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandbox.updateMany({ where: { id: "s1" }, data: { liveResourcesHeld: true } });
    });
    expect(seen).toEqual([]);
  });

  it("a listener failure never fails the committed write", async () => {
    bindSandboxTerminalLifecycle(() => {
      throw new Error("listener broke");
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
    await expect(
      sandboxOutboxTransaction(async (tx) =>
        tx.sandbox.updateMany({ where: { id: "s1" }, data: { state: "DELETED" } }),
      ),
    ).resolves.toEqual({ count: 1 });
  });
});
