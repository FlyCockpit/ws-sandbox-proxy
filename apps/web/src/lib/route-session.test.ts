import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const server = vi.hoisted(() => ({
  getRouteSession: vi.fn(),
  getProtectedRouteSession: vi.fn(),
  getRouteAdminAccess: vi.fn(),
}));
vi.mock("@/server/auth-session", () => ({
  getRouteSession: server.getRouteSession,
  getProtectedRouteSession: server.getProtectedRouteSession,
}));
vi.mock("@/server/admin-route-access", () => ({ getRouteAdminAccess: server.getRouteAdminAccess }));

import { resetDocumentIdentityForTests } from "./document-identity";
import {
  resolveProtectedRouteSession,
  resolveRouteAdminAccess,
  resolveRouteSession,
} from "./route-session";

const reload = vi.fn();
const root = { style: { visibility: "" } };
const user = (id: string) => ({
  user: {
    id,
    name: id,
    email: `${id}@example.test`,
    emailVerified: true,
    role: "user",
    twoFactorEnabled: false,
    createdAt: 0,
  },
});

/** Whether a promise settled within a few macrotasks. */
async function settles(promise: Promise<unknown>): Promise<boolean> {
  let settled = false;
  void promise.then(
    () => (settled = true),
    () => (settled = true),
  );
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  return settled;
}

beforeEach(() => {
  resetDocumentIdentityForTests(() => undefined);
  reload.mockReset();
  root.style.visibility = "";
  vi.stubGlobal("window", { location: { reload } });
  vi.stubGlobal("document", { documentElement: root });
});
afterEach(() => vi.unstubAllGlobals());

describe("route session guards check the document identity", () => {
  it("each probe returns the server answer for the document's own identity", async () => {
    const own = { status: "resolved", session: user("a") } as const;
    server.getRouteSession.mockResolvedValue(own);
    server.getProtectedRouteSession.mockResolvedValue({
      ...own,
      forcedTwoFactorSettings: {},
      passwordChangeRequired: false,
    });
    server.getRouteAdminAccess.mockResolvedValue({ ...own, authorized: true });
    await expect(resolveRouteSession()).resolves.toEqual(own);
    await expect(resolveProtectedRouteSession()).resolves.toMatchObject(own);
    await expect(resolveRouteAdminAccess()).resolves.toMatchObject({ authorized: true });
    // A failed probe decides nothing.
    server.getRouteSession.mockResolvedValue({ status: "error" });
    await expect(resolveRouteSession()).resolves.toEqual({ status: "error" });
    expect(reload).not.toHaveBeenCalled();
  });

  it.each([
    ["the _auth layout", () => resolveProtectedRouteSession(), "protected"],
    ["the /admin guard", () => resolveRouteAdminAccess(), "admin"],
    ["the device page", () => resolveRouteSession(), "plain"],
  ] as const)(
    "%s replaces the document for another account and never settles",
    async (_, probe, kind) => {
      server.getRouteSession.mockResolvedValueOnce({ status: "resolved", session: user("a") });
      await resolveRouteSession();
      const other = { status: "resolved", session: user("b") } as const;
      if (kind === "protected")
        server.getProtectedRouteSession.mockResolvedValueOnce({
          ...other,
          forcedTwoFactorSettings: {},
          passwordChangeRequired: false,
        });
      else if (kind === "admin")
        server.getRouteAdminAccess.mockResolvedValueOnce({ ...other, authorized: false });
      else server.getRouteSession.mockResolvedValueOnce(other);
      expect(await settles(probe())).toBe(false);
      expect(root.style.visibility).toBe("hidden");
      expect(reload).toHaveBeenCalledOnce();
    },
  );

  it("a sign-out elsewhere is caught on the next anonymous-only page (login)", async () => {
    server.getRouteSession.mockResolvedValueOnce({ status: "resolved", session: user("a") });
    await resolveRouteSession();
    server.getRouteSession.mockResolvedValueOnce({ status: "resolved", session: null });
    expect(await settles(resolveRouteSession())).toBe(false);
    expect(reload).toHaveBeenCalledOnce();
  });
});
