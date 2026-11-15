import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("../budgets", () => ({ consumeSandboxWriteBudget: vi.fn() }));
const { default: db } = await import("@wssp/db");
const { bindHostAccess } = await import("../host-access");
const { liftAgentHostCommandsVeto, liftHostTerminalVeto } = await import("./host-policy");
const owner = { kind: "session" as const, ownerId: "owner" };
const offWitness = vi.fn();
const liftCache = vi.fn();
beforeEach(() => {
  vi.clearAllMocks();
  db.sandboxHost.findFirst.mockResolvedValue({ connectionEpoch: 3 } as never);
  db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
  bindHostAccess({
    read: () => null,
    offWitness,
    lift: liftCache,
    lower: vi.fn(),
    start: vi.fn(),
    poll: vi.fn(),
    stdin: vi.fn(),
    cancel: vi.fn(),
    file: vi.fn(),
  });
});
afterEach(() => bindHostAccess(null));
it.each([liftAgentHostCommandsVeto, liftHostTerminalVeto])(
  "requires a live current-epoch raw-off witness",
  async (lift) => {
    for (const witness of [
      null,
      { epoch: 2, isOff: () => true },
      { epoch: 3, isOff: () => false },
    ]) {
      offWitness.mockReturnValue(witness);
      await expect(lift(owner, { id: "host" })).rejects.toMatchObject({
        code: "CONFLICT",
        data: { code: "host.node_not_off" },
      });
      expect(db.sandboxHost.updateMany).not.toHaveBeenCalled();
      expect(db.hostAuditEvent.create).not.toHaveBeenCalled();
      expect(liftCache).not.toHaveBeenCalled();
    }
    offWitness.mockReturnValue({ epoch: 3, isOff: () => true });
    await expect(lift(owner, { id: "host" })).resolves.toEqual({ ok: true });
    expect(db.hostAuditEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ actor: "PERSON", kind: "POLICY_VETO_LIFT" }),
      }),
    );
    expect(liftCache).toHaveBeenCalledOnce();
  },
);
it("rechecks the live off witness after database IO before committing", async () => {
  const isOff = vi.fn().mockReturnValueOnce(true).mockReturnValue(false);
  offWitness.mockReturnValue({ epoch: 3, isOff });
  await expect(liftAgentHostCommandsVeto(owner, { id: "host" })).rejects.toMatchObject({
    data: { code: "host.node_not_off" },
  });
  expect(liftCache).not.toHaveBeenCalled();
});
it("keeps missing and foreign hosts undisclosed even when offline", async () => {
  db.sandboxHost.findFirst.mockResolvedValue(null);
  offWitness.mockReturnValue(null);
  await expect(liftHostTerminalVeto(owner, { id: "foreign" })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
});
