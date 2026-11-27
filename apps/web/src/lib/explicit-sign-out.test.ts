import { beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({
  signOut: vi.fn(),
  undo: vi.fn(),
  mark: vi.fn(),
  leave: vi.fn(),
}));
vi.mock("@/lib/auth-client", () => ({ authClient: { signOut: auth.signOut } }));
vi.mock("@/lib/document-identity", () => ({
  markExplicitSignOut: () => {
    auth.mark();
    return auth.undo;
  },
  leaveDocument: auth.leave,
}));

const { signOutAndLeave, signOutFailureKey } = await import("./explicit-sign-out");

beforeEach(() => {
  for (const fn of Object.values(auth)) fn.mockReset();
});

describe("signOutAndLeave", () => {
  it("marks the sign-out, then leaves for the sign-in page only after success", async () => {
    let finish!: (result: { error: null }) => void;
    auth.signOut.mockImplementation(() => {
      expect(auth.mark).toHaveBeenCalledTimes(1);
      return new Promise((resolve) => {
        finish = resolve;
      });
    });
    const pending = signOutAndLeave("/en-US/login");
    await vi.waitFor(() => expect(auth.signOut).toHaveBeenCalledOnce());
    expect(auth.leave).not.toHaveBeenCalled();
    finish({ error: null });
    expect(await pending).toEqual({ ok: true });
    expect(auth.signOut).toHaveBeenCalledWith(undefined);
    expect(auth.leave).toHaveBeenCalledExactlyOnceWith("/en-US/login");
    expect(auth.undo).not.toHaveBeenCalled();
  });

  it("passes disableRedirect through (MCP re-authentication)", async () => {
    auth.signOut.mockResolvedValue({ data: { success: true }, error: null });
    await signOutAndLeave("/en-US/login?redirectTo=x", { disableRedirect: true });
    expect(auth.signOut).toHaveBeenCalledWith({ disableRedirect: true });
    expect(auth.leave).toHaveBeenCalledWith("/en-US/login?redirectTo=x");
  });

  it("undoes the mark when the server refuses", async () => {
    const error = { status: 500 };
    auth.signOut.mockResolvedValue({ data: null, error });
    expect(await signOutAndLeave("/en-US/login")).toEqual({ ok: false, error });
    expect(auth.undo).toHaveBeenCalledTimes(1);
    expect(auth.leave).not.toHaveBeenCalled();
  });

  it("undoes the mark when the request throws (offline, transport failure)", async () => {
    const error = new Error("offline");
    auth.signOut.mockRejectedValue(error);
    expect(await signOutAndLeave("/en-US/login")).toEqual({ ok: false, error });
    expect(auth.undo).toHaveBeenCalledTimes(1);
    expect(auth.leave).not.toHaveBeenCalled();
  });
});

it("uses offline copy for network failures and generic copy for server refusals", () => {
  expect(signOutFailureKey(new TypeError("Failed to fetch"))).toBe("userMenu.signOutOffline");
  expect(signOutFailureKey({ status: 500 })).toBe("userMenu.signOutFailed");
});
