import { beforeEach, describe, expect, it, vi } from "vitest";

// Keep the pinned Prisma adapter; only the database checkout/delegates are fake.
const db = vi.hoisted(() => ({
  user: { findFirst: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
  verification: { findFirst: vi.fn(), findMany: vi.fn(), delete: vi.fn(), deleteMany: vi.fn() },
  $executeRaw: vi.fn(),
  $queryRaw: vi.fn(),
  $transaction: vi.fn(),
}));
vi.mock("@wssp/db", () => ({ default: db }));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 3 } }));
const { createPasswordResetAdapter } = await import("./password-reset-adapter");
const { releaseSlots, tryAcquireSlots } = await import("./lock-slots");
const adapter = createPasswordResetAdapter()({});
type Selector = Parameters<typeof adapter.update>[0]["where"][number];
const user = { id: "InviteA", email: "InviteA@example.test", emailVerified: true };

beforeEach(() => {
  vi.clearAllMocks();
  db.user.findFirst.mockResolvedValue(user);
  db.user.update.mockResolvedValue(user);
  db.user.updateMany.mockResolvedValue({ count: 1 });
  db.verification.findMany.mockResolvedValue([]);
  db.verification.deleteMany.mockResolvedValue({ count: 0 });
  db.$executeRaw.mockResolvedValue(1);
  db.$queryRaw.mockImplementation(async (sql: TemplateStringsArray, id: string) =>
    sql.join("").includes("FOR NO KEY UPDATE") ? [{ id }] : [{ locked: true }],
  );
  db.$transaction.mockImplementation(async (run: (tx: typeof db) => Promise<unknown>) => run(db));
});

describe.each(["update", "updateMany"] as const)("activation %s selectors", (method) => {
  const write = (where: Selector[]) =>
    adapter[method]({ model: "user", where, update: { emailVerified: true } });

  it.each(["id", "email"])(
    "rejects case-insensitive %s before lookup, checkout or writes",
    async (field) => {
      await expect(
        write([{ field, value: user[field as "id" | "email"], mode: "insensitive" }]),
      ).rejects.toThrow("Activation requires an exact user selector");
      expect(db.user.findFirst).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(db.$executeRaw).not.toHaveBeenCalled();
      expect(db.user.update).not.toHaveBeenCalled();
      expect(db.user.updateMany).not.toHaveBeenCalled();
      expect(db.verification.deleteMany).not.toHaveBeenCalled();
      expect(tryAcquireSlots(2)).toBe(true);
      releaseSlots(2);
    },
  );

  it.each<{ value: Selector["value"] }>([
    { value: ["InviteA", "invitea"] },
    { value: [1, 2] },
    { value: null },
    { value: 12 },
    { value: true },
    { value: new Date(0) },
  ])("rejects non-string selector $value before lookup, checkout or writes", async ({ value }) => {
    await expect(write([{ field: "id", value, operator: "eq" }])).rejects.toThrow(
      "Activation requires an exact user selector",
    );
    expect(db.user.findFirst).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(db.$executeRaw).not.toHaveBeenCalled();
    expect(db.user.update).not.toHaveBeenCalled();
    expect(db.user.updateMany).not.toHaveBeenCalled();
    expect(db.verification.deleteMany).not.toHaveBeenCalled();
  });

  it.each<Selector[][]>([
    [],
    [
      { field: "id", value: "InviteA" },
      { field: "email", value: "other@example.test" },
    ],
    [{ field: "email", value: "InviteA", operator: "contains" }],
    [{ field: "name", value: "InviteA" }],
  ])("rejects non-exact/multi-target selector %j", async (...where) => {
    await expect(write(where)).rejects.toThrow("Activation requires an exact user selector");
    expect(db.user.findFirst).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(db.user.update).not.toHaveBeenCalled();
    expect(db.user.updateMany).not.toHaveBeenCalled();
  });

  it.each(["id", "email"] as const)(
    "accepts exact %s and invokes this method under the locks",
    async (field) => {
      await write([{ field, value: user[field], operator: "eq", mode: "sensitive" }]);
      expect(db.$transaction).toHaveBeenCalledOnce();
      expect(db.$executeRaw.mock.calls.map((args) => args[1])).toEqual(["password-write:InviteA"]);
      expect(db.$queryRaw).toHaveBeenCalledExactlyOnceWith(expect.anything(), user.id);
      expect(db.$executeRaw.mock.invocationCallOrder[0]).toBeLessThan(
        db.$queryRaw.mock.invocationCallOrder[0]!,
      );
      expect(db.$queryRaw.mock.invocationCallOrder[0]).toBeLessThan(
        db.user[method].mock.invocationCallOrder[0]!,
      );
      expect(db.user[method]).toHaveBeenCalledOnce();
      expect(db.user[method === "update" ? "updateMany" : "update"]).not.toHaveBeenCalled();
      expect(db.verification.deleteMany).toHaveBeenCalled();
    },
  );
});

const resetRow = () => ({
  id: "token-row",
  identifier: "reset-password:mailed",
  value: user.id,
  expiresAt: new Date(Date.now() + 60_000),
});
const consumeArgs = { model: "verification", where: [{ field: "id", value: "token-row" }] };
async function holdingReset(run: () => Promise<void>) {
  const { withPasswordWriteLock } = await import("./password-write-lock");
  await withPasswordWriteLock(
    "/reset-password",
    new Request("https://app.example.test/api/auth/reset-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "mailed" }),
    }),
    async () => {
      await run();
      return new Response();
    },
    { getSession: async () => null },
  );
}
describe("reset consumption guards on the actual Prisma adapter", () => {
  it("refuses reset consumption outside the held request transaction", async () => {
    db.verification.findFirst.mockResolvedValue(resetRow());
    await expect(adapter.consumeOne(consumeArgs)).rejects.toThrow(
      "Reset consumption requires its password transaction",
    );
    expect(db.verification.delete).not.toHaveBeenCalled();
  });
  it.each(["missing", "owner", "identifier", "expired"] as const)(
    "rechecks %s after taking the owner fence",
    async (changed) => {
      const original = resetRow();
      const live =
        changed === "missing"
          ? null
          : {
              ...original,
              ...(changed === "owner" ? { value: "other-owner" } : {}),
              ...(changed === "identifier" ? { identifier: "reset-password:other" } : {}),
              ...(changed === "expired" ? { expiresAt: new Date(0) } : {}),
            };
      db.verification.findFirst
        .mockReset()
        .mockResolvedValueOnce(original)
        .mockResolvedValueOnce(original)
        .mockResolvedValueOnce(live);
      await holdingReset(async () => {
        await expect(
          adapter.transaction(async (tx) => tx.consumeOne(consumeArgs)),
        ).rejects.toMatchObject({ body: { code: "INVALID_TOKEN" } });
      });
      expect(db.verification.delete).not.toHaveBeenCalled();
      expect(db.user.updateMany).not.toHaveBeenCalled();
    },
  );
  it("refuses a missing owner before token consumption", async () => {
    db.verification.findFirst.mockResolvedValue(resetRow());
    db.$queryRaw.mockImplementation(async (sql: TemplateStringsArray) =>
      sql.join("").includes("FOR NO KEY UPDATE") ? [] : [{ locked: true }],
    );
    await holdingReset(async () => {
      await expect(
        adapter.transaction(async (tx) => tx.consumeOne(consumeArgs)),
      ).rejects.toMatchObject({ body: { code: "INVALID_TOKEN" } });
    });
    expect(db.verification.delete).not.toHaveBeenCalled();
  });
  it("refuses a reset token belonging to another lock owner", async () => {
    const row = resetRow();
    db.verification.findFirst
      .mockReset()
      .mockResolvedValueOnce(row)
      .mockResolvedValue({ ...row, value: "other-owner" });
    await holdingReset(async () => {
      await expect(adapter.transaction(async (tx) => tx.consumeOne(consumeArgs))).rejects.toThrow(
        /password-write lock/,
      );
    });
    expect(db.verification.delete).not.toHaveBeenCalled();
  });
  it("refuses consume after lapse but advertises the real transaction through failure", async () => {
    db.verification.findFirst.mockResolvedValue(resetRow());
    await holdingReset(async () => {
      const clock = vi.spyOn(performance, "now").mockReturnValue(performance.now() + 26_000);
      try {
        expect(adapter.options?.adapterConfig.transaction).not.toBe(false);
        await expect(adapter.transaction(async (tx) => tx.consumeOne(consumeArgs))).rejects.toThrow(
          /password-write lock/,
        );
        expect(adapter.options?.adapterConfig.transaction).not.toBe(false);
      } finally {
        clock.mockRestore();
      }
    });
    expect(
      db.$queryRaw.mock.calls.filter(([sql]) =>
        (sql as TemplateStringsArray).join("").includes("FOR NO KEY UPDATE"),
      ),
    ).toHaveLength(0);
    expect(db.verification.delete).not.toHaveBeenCalled();
    expect(adapter.options?.adapterConfig.transaction).toBe(false);
  });
  it("checks the live lock again after waiting for the owner row", async () => {
    db.verification.findFirst.mockResolvedValue(resetRow());
    let restoreClock: (() => void) | undefined;
    db.$queryRaw.mockImplementation(async (sql: TemplateStringsArray, id: string) => {
      if (sql.join("").includes("FOR NO KEY UPDATE")) {
        const clock = vi.spyOn(performance, "now").mockReturnValue(performance.now() + 26_000);
        restoreClock = () => clock.mockRestore();
        return [{ id }];
      }
      return [{ locked: true }];
    });
    try {
      await holdingReset(async () => {
        await expect(adapter.transaction(async (tx) => tx.consumeOne(consumeArgs))).rejects.toThrow(
          /password-write lock/,
        );
      });
    } finally {
      restoreClock?.();
    }
    expect(db.verification.delete).not.toHaveBeenCalled();
  });
});

it("ordinary user updates keep the nontransactional adapter behavior", async () => {
  await adapter.update({
    model: "user",
    where: [{ field: "id", value: user.id }],
    update: { name: "Renamed" },
  });
  expect(db.user.update).toHaveBeenCalledOnce();
  expect(db.$transaction).not.toHaveBeenCalled();
  expect(db.$executeRaw).not.toHaveBeenCalled();
  expect(db.$queryRaw).not.toHaveBeenCalled();
  expect(db.verification.deleteMany).not.toHaveBeenCalled();
});

it("non-reset verification consumption remains outside the reset gates", async () => {
  const row = { ...resetRow(), identifier: "2fa-challenge" };
  db.verification.findFirst.mockResolvedValue(row);
  db.verification.delete.mockResolvedValue(row);
  expect(await adapter.consumeOne(consumeArgs)).toMatchObject({ identifier: "2fa-challenge" });
  expect(db.verification.delete).toHaveBeenCalledOnce();
  expect(db.$transaction).not.toHaveBeenCalled();
  expect(db.$queryRaw).not.toHaveBeenCalled();
});
