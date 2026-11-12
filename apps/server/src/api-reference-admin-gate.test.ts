import { type Context, Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock @wssp/auth at the module boundary so the gate reads session
// resolution from a stub instead of touching the real Better-Auth instance
// (which would otherwise try to connect to Postgres on import).
const getSession = vi.fn();

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/auth", () => ({
  auth: {
    api: {
      get getSession() {
        return getSession;
      },
    },
  },
}));

const { default: prisma } = await import("@wssp/db");
const { invalidateForceTwoFactorSettingsCache } = await import("@wssp/api/lib/two-factor-policy");
const { apiReferenceAdminGate } = await import("./api-reference-admin-gate");

const db = prisma as unknown as {
  appSetting: { findMany: ReturnType<typeof vi.fn> };
  user: { findUnique: ReturnType<typeof vi.fn> };
};

function wireAuthoritativeGateUser(user: {
  role?: string | null;
  emailVerified?: boolean;
  twoFactorEnabled?: boolean | null;
  createdAt?: Date;
}) {
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: user.twoFactorEnabled ?? false,
    role: user.role ?? "user",
    emailVerified: user.emailVerified ?? false,
    banned: false,
    banExpires: null,
    createdAt: user.createdAt ?? new Date("2025-01-01"),
  } as never);
}

function mockSession(session: Awaited<ReturnType<typeof getSession>>) {
  getSession.mockResolvedValue(session ? { ...session, session: { id: "test-session-id" } } : null);
  if (session?.user) {
    wireAuthoritativeGateUser(session.user);
  }
}

describe("apiReferenceAdminGate", () => {
  let app: Hono;
  // Sentinel — if the gate calls next() the downstream handler runs and we
  // return 200 with a payload the test can assert on. This stands in for the
  // OpenAPI reference page served by the oRPC handler in app.ts.
  const downstream = vi.fn((c: Context) => c.json({ ok: true }));

  beforeEach(() => {
    getSession.mockReset();
    db.appSetting.findMany.mockResolvedValue([]);
    // Force-2FA settings are TTL-cached in-process; reset between tests.
    invalidateForceTwoFactorSettingsCache();
    downstream.mockClear();
    app = new Hono();
    app.use("/api-reference/*", apiReferenceAdminGate);
    app.all("/api-reference/*", downstream);
  });

  it("404s unauthenticated callers (not 401) so the page isn't enumerable", async () => {
    mockSession(null);
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Not found" });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("404s signed-in non-admin callers (not 403)", async () => {
    mockSession({ user: { id: "u1", role: "user", emailVerified: true } });
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(downstream).not.toHaveBeenCalled();
  });

  it("404s unverified admins", async () => {
    mockSession({ user: { id: "admin-1", role: "admin", emailVerified: false } });
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(downstream).not.toHaveBeenCalled();
  });

  it("404s a getSession failure (treated as unauthenticated)", async () => {
    getSession.mockRejectedValue(new Error("db down"));
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(downstream).not.toHaveBeenCalled();
  });

  it("admits a verified admin and lets the reference page render", async () => {
    mockSession({
      user: { id: "admin-1", role: "admin", emailVerified: true, twoFactorEnabled: true },
    });
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it("404s an admin without required 2FA", async () => {
    mockSession({
      user: { id: "admin-1", role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(downstream).not.toHaveBeenCalled();
  });

  it("404s an admin without 2FA once the enrollment grace window has closed", async () => {
    mockSession({
      user: {
        id: "admin-1",
        role: "admin",
        emailVerified: true,
        twoFactorEnabled: false,
        createdAt: new Date("2025-01-01"),
      },
    });
    db.appSetting.findMany.mockResolvedValue([]);
    const res = await app.request("/api-reference/");
    expect(res.status).toBe(404);
    expect(downstream).not.toHaveBeenCalled();
  });
});
