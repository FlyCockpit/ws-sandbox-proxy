import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "grant-fixture" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
const { default: db } = await import("@wssp/db");
const { mcpGrantsRouter } = await import("./mcp-grants");
const { bindMcpGrantTokenRevocation } = await import("../sandbox/services/mcp-grants");
const session = {
  user: {
    id: "owner",
    role: "user",
    twoFactorEnabled: true,
    banned: false,
    createdAt: new Date(0),
  },
  session: { id: "session" },
} as Session;
const client = () => createRouterClient(mcpGrantsRouter, { context: { session } });
beforeEach(() => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (fn) => fn(db));
  bindMcpGrantTokenRevocation(async () => {});
});
it("requires a person session", async () => {
  const anonymous = createRouterClient(mcpGrantsRouter, { context: { session: null } });
  await expect(anonymous.list({ limit: 2 })).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  await expect(anonymous.revoke({ id: "grant" })).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});
it("returns only bounded owner-scoped metadata, never reference IDs or digests", async () => {
  db.mcpGrant.findMany.mockResolvedValue([]);
  await expect(client().list({ limit: 3 })).resolves.toEqual({ items: [], nextCursor: null });
  expect(db.mcpGrant.findMany).toHaveBeenCalledWith(
    expect.objectContaining({ take: 4, where: { AND: [{ userId: "owner", revokedAt: null }] } }),
  );
  const select = db.mcpGrant.findMany.mock.calls[0]![0]!.select!;
  expect(select).not.toHaveProperty("referenceId");
  expect(select.SdkKey).not.toHaveProperty("select.secretDigest");
});
it("foreign and absent grants are indistinguishable", async () => {
  db.mcpGrant.findFirst.mockResolvedValue(null);
  await expect(client().revoke({ id: "foreign" })).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(db.mcpGrant.findFirst).toHaveBeenCalledWith({
    where: { id: "foreign", userId: "owner" },
    select: { sdkKeyId: true, clientId: true },
  });
  expect(db.sdkKey.updateMany).not.toHaveBeenCalled();
});
it("revokes both grant and OAuth backing key before notifying the refresh-token hook", async () => {
  db.mcpGrant.findFirst.mockResolvedValue({ sdkKeyId: "key", clientId: "client" } as never);
  const hook = vi.fn(async () => {
    expect(db.mcpGrant.updateMany).toHaveBeenCalledWith({
      where: { id: "grant", userId: "owner", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
    expect(db.sdkKey.updateMany).toHaveBeenCalledWith({
      where: { id: "key", userId: "owner", kind: "OAUTH_GRANT", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });
  bindMcpGrantTokenRevocation(hook);
  await expect(client().revoke({ id: "grant" })).resolves.toEqual({ ok: true });
  expect(hook).toHaveBeenCalledWith("owner", "client");
});
