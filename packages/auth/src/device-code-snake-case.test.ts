import { describe, expect, it, vi } from "vitest";

const BASE_URL = "http://localhost:3000";
const db = vi.hoisted(
  (): Record<string, Record<string, unknown>[]> => ({
    user: [],
    session: [],
    account: [],
    verification: [],
    deviceCode: [],
  }),
);
vi.mock("@wssp/db", () => ({ default: { $extends: () => ({}) } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: BASE_URL,
    CORS_ORIGIN: "https://web.example.test",
    BETTER_AUTH_SECRET: "device-shape-test-secret-at-least-32-characters",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  renderResetPassword: vi.fn(),
  renderTwoFactorOtp: vi.fn(),
  renderVerifyEmail: vi.fn(),
  sendEmail: vi.fn(),
}));
vi.mock("better-auth/adapters/prisma", async () => ({ prismaAdapter: () => memoryAdapter(db) }));
vi.mock("@wssp/db/account-deletion", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wssp/db/account-deletion")>()),
  requestAccountDeletion: vi.fn(),
}));
const { memoryAdapter } = await import("better-auth/adapters/memory");
const { auth } = await import("./index");

describe("Better Auth device code response shape", () => {
  it("returns snake_case fields from /api/auth/device/code", async () => {
    const response = await auth.handler(
      new Request(`${BASE_URL}/api/auth/device/code`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: "wssp", scope: "host-slug:desk-01" }),
      }),
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      device_code: expect.any(String),
      user_code: expect.any(String),
      verification_uri: "https://web.example.test/device",
      verification_uri_complete: expect.stringMatching(
        /^https:\/\/web\.example\.test\/device\?user_code=/,
      ),
      interval: 5,
      expires_in: expect.any(Number),
    });
    expect(body.deviceCode).toBeUndefined();
    expect(db.deviceCode?.[0]?.pollingInterval).toBe(5000);
    for (const invalid of [
      { user_id: "owner" },
      { user_id: "" },
      { client_id: "x".repeat(65) },
      { client_id: "unknown" },
    ]) {
      const rejected = await auth.handler(
        new Request(`${BASE_URL}/api/auth/device/code`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ client_id: "wssp", scope: "host-slug:desk-01", ...invalid }),
        }),
      );
      expect(rejected.status).toBe(400);
      expect(db.deviceCode).toHaveLength(1);
    }
  });
});

describe("C21-ACCTDEL Better Auth user deletion chokepoint", () => {
  it.each([
    ["POST", "/delete-user"],
    ["GET", "/delete-user/callback?token=t"],
    ["POST", "/admin/remove-user"],
  ])("%s %s is not mounted (404)", async (method, path) => {
    const response = await auth.handler(
      new Request(`${BASE_URL}/api/auth${path}`, {
        method,
        headers: { "content-type": "application/json" },
        ...(method === "POST" ? { body: JSON.stringify({ userId: "owner" }) } : {}),
      }),
    );
    expect(response.status).toBe(404);
  });

  it("the defense-in-depth delete hook refuses with a Better Auth APIError CONFLICT naming blockers", async () => {
    const { AccountDeletionConflictError, requestAccountDeletion } = await import(
      "@wssp/db/account-deletion"
    );
    const { APIError } = await import("better-auth/api");
    vi.mocked(requestAccountDeletion).mockRejectedValueOnce(
      new AccountDeletionConflictError(["hosts", "sandboxes"]),
    );
    const before = auth.options.databaseHooks?.user?.delete?.before;
    if (!before) throw new Error("delete hook missing");
    const refusal = await Promise.resolve(before({ id: "owner" } as never, null as never)).catch(
      (error: unknown) => error,
    );
    expect(refusal).toBeInstanceOf(APIError);
    expect(refusal).toMatchObject({
      status: "CONFLICT",
      body: { blockers: ["hosts", "sandboxes"] },
    });
  });

  it("the delete hook finalizes through requestAccountDeletion and suppresses Better Auth's own delete", async () => {
    const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
    vi.mocked(requestAccountDeletion).mockResolvedValueOnce(true);
    const before = auth.options.databaseHooks?.user?.delete?.before;
    if (!before) throw new Error("delete hook missing");
    await expect(Promise.resolve(before({ id: "owner" } as never, null as never))).resolves.toBe(
      false,
    );
    expect(requestAccountDeletion).toHaveBeenCalledWith("owner");
  });
});
