import { createRouterClient, ORPCError } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "test-better-auth-secret" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});
const budget = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => budget }));
const mint = vi.hoisted(() => vi.fn());
vi.mock("../lib/user-login-credential-access", () => ({
  mintUserLoginFromApprovedDeviceCode: mint,
}));
const { userLoginsRouter } = await import("./user-logins");

const minted = {
  keyId: "key-1",
  secret: "wssp_sdk_secret",
  name: "wssp login",
  userId: "user-1",
  email: "owner@example.test",
  scopes: ["sandboxes:read"],
  poolMode: "ALL_USABLE" as const,
  poolIds: [],
  ownSandboxesOnly: false,
  expiresAt: new Date("2026-12-18T00:00:00.000Z"),
  maxLiveSandboxes: null,
};
const client = () =>
  createRouterClient(userLoginsRouter, { context: { session: null, clientIp: "192.0.2.9" } });

beforeEach(() => {
  vi.clearAllMocks();
  budget.mockResolvedValue(undefined);
  mint.mockResolvedValue(minted);
});

it("is public, charges the shared per-IP exchange budget and returns the minted login", async () => {
  await expect(client().exchangeDeviceCode({ deviceCode: " code " })).resolves.toEqual(minted);
  expect(budget).toHaveBeenCalledWith("ip:192.0.2.9");
  expect(mint).toHaveBeenCalledWith({ deviceCode: "code" });
});

it("a budget refusal prevents any exchange work", async () => {
  budget.mockRejectedValueOnce(new ORPCError("TOO_MANY_REQUESTS"));
  await expect(client().exchangeDeviceCode({ deviceCode: "code" })).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  expect(mint).not.toHaveBeenCalled();
});

it("an unavailable budget store reads as authorization_pending", async () => {
  budget.mockRejectedValueOnce(new ORPCError("SERVICE_UNAVAILABLE"));
  await expect(client().exchangeDeviceCode({ deviceCode: "code" })).rejects.toMatchObject({
    code: "SERVICE_UNAVAILABLE",
    data: { deviceFlowError: "authorization_pending" },
  });
  expect(mint).not.toHaveBeenCalled();
});

it("refuses an empty or oversized device code before the budget", async () => {
  await expect(client().exchangeDeviceCode({ deviceCode: " " })).rejects.toMatchObject({
    code: "BAD_REQUEST",
  });
  await expect(client().exchangeDeviceCode({ deviceCode: "x".repeat(513) })).rejects.toMatchObject({
    code: "BAD_REQUEST",
  });
  expect(budget).not.toHaveBeenCalled();
});

it("a write login holds sandboxes:connect (CLI shells); a read login never does", async () => {
  const { USER_LOGIN_READ_SCOPES, USER_LOGIN_WRITE_SCOPES } = await import(
    "@wssp/config/user-device-login"
  );
  expect(USER_LOGIN_WRITE_SCOPES).toContain("sandboxes:connect");
  expect(USER_LOGIN_READ_SCOPES).not.toContain("sandboxes:connect");
});
