import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { notifySandboxTerminalLifecycle, subscribeSandboxTerminalLifecycle, sandboxTerminalWrite } =
  await import("./terminal-lifecycle");
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

describe("lifecycle subscriptions are additive", () => {
  it("every subscriber hears a change, and disposing one keeps the others", () => {
    const first: unknown[] = [];
    const second: unknown[] = [];
    const offFirst = subscribeSandboxTerminalLifecycle((change) => first.push(change));
    const offSecond = subscribeSandboxTerminalLifecycle((change) => second.push(change));
    notifySandboxTerminalLifecycle("all");
    expect(first).toEqual(["all"]);
    expect(second).toEqual(["all"]);
    offFirst();
    offFirst(); // idempotent: never removes another subscription
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["s1"]) });
    expect(first).toHaveLength(1);
    expect(second).toHaveLength(2);
    offSecond();
    notifySandboxTerminalLifecycle("all");
    expect(second).toHaveLength(2);
  });

  it("a throwing subscriber never keeps the next one from hearing the change", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const heard: unknown[] = [];
    const offBroken = subscribeSandboxTerminalLifecycle(() => {
      throw new Error("listener broke");
    });
    const offOk = subscribeSandboxTerminalLifecycle((change) => heard.push(change));
    notifySandboxTerminalLifecycle("all");
    expect(heard).toEqual(["all"]);
    offBroken();
    offOk();
  });
});

describe("sandboxOutboxTransaction announces terminal lifecycle only after commit", () => {
  const seen: unknown[] = [];
  let unsubscribe: (() => void) | undefined;
  beforeEach(() => {
    vi.clearAllMocks();
    seen.length = 0;
    unsubscribe?.();
    unsubscribe = subscribeSandboxTerminalLifecycle((change) => {
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
    const offBroken = subscribeSandboxTerminalLifecycle(() => {
      throw new Error("listener broke");
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
    await expect(
      sandboxOutboxTransaction(async (tx) =>
        tx.sandbox.updateMany({ where: { id: "s1" }, data: { state: "DELETED" } }),
      ),
    ).resolves.toEqual({ count: 1 });
    offBroken();
  });
});
