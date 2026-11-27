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

import {
  holdDocumentIdentityUnverified,
  isDocumentIdentityUnverified,
  resetDocumentIdentityForTests,
} from "./document-identity";
import {
  resolveProtectedRouteSession,
  resolveRouteAdminAccess,
  resolveRouteSession,
} from "./route-session";

const reload = vi.fn();
/** The root element's inline style, as `hidePage` writes it. */
const root = {
  style: {
    display: "",
    priority: "",
    setProperty(name: string, value: string, priority: string) {
      if (name === "display") Object.assign(this, { display: value, priority });
    },
  },
};
const hidden = () => root.style.display === "none" && root.style.priority === "important";
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
  Object.assign(root.style, { display: "", priority: "" });
  vi.stubGlobal("window", { location: { reload } });
  // No server-rendered app shell in this document: guards do not wait
  // (lib/app-shell-hydration.test.ts covers the wait).
  vi.stubGlobal("document", { documentElement: root, querySelector: () => null });
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
      expect(hidden()).toBe(true);
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

  it.each([
    ["session", resolveRouteSession, server.getRouteSession, {}],
    [
      "protected",
      resolveProtectedRouteSession,
      server.getProtectedRouteSession,
      { forcedTwoFactorSettings: {}, passwordChangeRequired: false },
    ],
    ["admin", resolveRouteAdminAccess, server.getRouteAdminAccess, { authorized: true }],
  ] as const)(
    "a %s guard's answer confirms an unverified identity, unless it predates a newer invalidation",
    async (_kind, probe, serverProbe, extra) => {
      server.getRouteSession.mockResolvedValueOnce({ status: "resolved", session: user("a") });
      await resolveRouteSession();
      // A 401 with no watcher connected: unverified.
      holdDocumentIdentityUnverified();
      expect(isDocumentIdentityUnverified()).toBe(true);
      // The guard's probe is under way when another invalidation arrives.
      let answer: (value: unknown) => void = () => {};
      serverProbe.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            answer = resolve;
          }),
      );
      serverProbe.mockResolvedValueOnce({ status: "resolved", session: user("a"), ...extra });
      const pending = probe();
      holdDocumentIdentityUnverified();
      answer({ status: "resolved", session: user("stale"), ...extra });
      await expect(pending).resolves.toMatchObject({ session: user("a") });
      expect(isDocumentIdentityUnverified()).toBe(false);
      expect(reload).not.toHaveBeenCalled();
    },
  );
});
