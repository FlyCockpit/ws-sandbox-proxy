vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: vi.fn(async () => {}) }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

import { createRouterClient } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import { isServiceProcedure } from "../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../sandbox/budgets";
import { POOL_PROCEDURE_INVENTORY } from "../sandbox/services";
import { addPoolMember, createPool } from "../sandbox/services/pools";
import { sandboxPoolsRouter } from "./sandbox-pools";

const { default: db } = await import("@wssp/db");
beforeEach(() => {
  vi.clearAllMocks();
});
it("registers exactly the inventoried centrally guarded pool services", () => {
  expect(Object.keys(sandboxPoolsRouter).sort()).toEqual(
    Object.keys(POOL_PROCEDURE_INVENTORY).sort(),
  );
  expect(Object.values(POOL_PROCEDURE_INVENTORY).every(isServiceProcedure)).toBe(true);
});
it.each(Object.keys(sandboxPoolsRouter) as (keyof typeof sandboxPoolsRouter)[])(
  "%s requires a browser session",
  async (procedure) => {
    const client = createRouterClient(sandboxPoolsRouter, {
      context: { session: null } satisfies Context,
    });
    const call = client[procedure] as (input: never) => Promise<unknown>;
    await expect(
      call({
        id: "pool",
        poolId: "pool",
        sandboxHostId: "host",
        slug: "pool",
        label: "Pool",
      } as never),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  },
);
it("pool writes charge the owner procedure bucket before entering the transaction", async () => {
  vi.mocked(consumeSandboxWriteBudget).mockRejectedValueOnce(new Error("Budget refused"));
  await expect(
    createPool({ kind: "session", ownerId: "owner" }, { slug: "pool", label: "Pool" }),
  ).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
  expect(consumeSandboxWriteBudget).toHaveBeenCalledWith("owner", "pool");
  expect(db.$transaction).not.toHaveBeenCalled();
});
it("member writes reject a foreign/absent host before taking H", async () => {
  db.sandboxPool.findFirst.mockResolvedValue({ id: "pool" } as never);
  db.sandboxHost.findFirst.mockResolvedValue(null);
  await expect(
    addPoolMember(
      { kind: "session", ownerId: "owner" },
      { poolId: "pool", sandboxHostId: "foreign", enabled: true },
    ),
  ).rejects.toMatchObject({ code: "NOT_FOUND", data: { code: "sandbox.host_not_found" } });
  const sql = db.$queryRaw.mock.calls.map((args) => String(args[0]));
  expect(sql.some((query) => query.includes("sandbox_host"))).toBe(false);
  expect(db.sandboxPoolMember.upsert).not.toHaveBeenCalled();
});

it("SDK discovery scopes never authorize pool or member management", async () => {
  const services = await import("../sandbox/services/pools");
  const principal = {
    kind: "sdkKey" as const,
    ownerId: "owner",
    keyId: "sdk",
    expiresAt: null,
    resourceMode: "ALL_OWNED" as const,
    scopes: new Set(["pools:read"] as const),
    allowedPoolIds: "allUsable" as const,
    allowedHostIds: "allOwned" as const,
    allowedRevisionIds: "allOwned" as const,
  };
  for (const service of [
    services.createPool,
    services.updatePool,
    services.deletePool,
    services.addPoolMember,
    services.updatePoolMember,
    services.removePoolMember,
  ]) {
    const call = service as (owner: typeof principal, input: never) => Promise<unknown>;
    await expect(
      call({ ...principal }, {
        id: "pool",
        poolId: "pool",
        sandboxHostId: "host",
        slug: "pool",
        label: "Pool",
        enabled: true,
      } as never),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  }
  expect(db.$transaction).not.toHaveBeenCalled();
});

it.each(["update", "delete", "addMember", "updateMember", "removeMember"] as const)(
  "%s refuses an impersonated or durably revoked cookie before any write",
  async (procedure) => {
    const session = {
      user: { id: "owner", emailVerified: true, twoFactorEnabled: true },
      session: {
        id: "cookie",
        userId: "owner",
        expiresAt: new Date(Date.now() + 3600000),
        impersonatedBy: "admin",
      },
    } as NonNullable<Context["session"]>;
    const input =
      procedure === "update"
        ? { id: "pool", slug: "pool", label: "Pool" }
        : procedure === "delete"
          ? { id: "pool" }
          : procedure === "removeMember"
            ? { poolId: "pool", sandboxHostId: "host" }
            : { poolId: "pool", sandboxHostId: "host", enabled: true };
    // Real durable query uses impersonatedBy:null; this fixture represents a mismatch.
    db.session.findUnique.mockResolvedValue(null);
    const run = () =>
      (
        createRouterClient(sandboxPoolsRouter, { context: { session } })[procedure] as (
          input: never,
        ) => Promise<unknown>
      )(input as never);
    await expect(run()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(db.sandboxPool.update).not.toHaveBeenCalled();
    expect(db.sandboxPoolMember.upsert).not.toHaveBeenCalled();
    session.session.impersonatedBy = null;
    db.session.findUnique.mockResolvedValue(null);
    await expect(run()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(db.sandboxPool.update).not.toHaveBeenCalled();
    expect(db.sandboxPoolMember.upsert).not.toHaveBeenCalled();
  },
);
