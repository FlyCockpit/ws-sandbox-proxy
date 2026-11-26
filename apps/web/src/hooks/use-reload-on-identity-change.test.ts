import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const boundary = vi.hoisted(() => ({
  /** Last deps of each layout effect, by call order within one render. */
  deps: [] as (unknown[] | undefined)[],
  cleanups: [] as ((() => void) | undefined)[],
  call: 0,
  state: { status: "pending" } as
    | { status: "pending" }
    | { status: "error" }
    | { status: "anonymous" }
    | { status: "authenticated"; session: { user: { id: string } } },
  meta: { isOffline: false, isDegraded: false, isRefetching: false },
  refetch: vi.fn(),
  reload: vi.fn(),
}));

// Run the hook without a DOM: layout effects that fire, in order, whenever
// their deps change (cleaning up the previous run first), as React does.
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  useLayoutEffect: (effect: () => (() => void) | undefined, deps: unknown[]) => {
    const i = boundary.call++;
    const last = boundary.deps[i];
    if (last !== undefined && deps.every((dep, j) => dep === last[j])) return;
    boundary.deps[i] = deps;
    boundary.cleanups[i]?.();
    boundary.cleanups[i] = effect() ?? undefined;
  },
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: boundary.state,
    meta: boundary.meta,
    actions: { refetch: boundary.refetch },
  }),
}));

import { markExplicitSignOut, resetDocumentIdentityForTests } from "@/lib/document-identity";

import { sessionIdentity, useReloadOnIdentityChange } from "./use-reload-on-identity-change";

const user = (id: string) => ({ status: "authenticated", session: { user: { id } } }) as const;

function useRenderWith(state: typeof boundary.state) {
  boundary.state = state;
  boundary.call = 0;
  useReloadOnIdentityChange();
}

/** The identity boundary unmounts (a fresh root render, a test teardown). */
function unmount() {
  for (const cleanup of boundary.cleanups) cleanup?.();
  boundary.deps = [];
  boundary.cleanups = [];
}

class FakeChannel {
  static open: FakeChannel[] = [];
  posted = 0;
  onmessage: ((event: MessageEvent) => void) | null = null;
  constructor() {
    FakeChannel.open.push(this);
  }
  postMessage() {
    this.posted++;
  }
}

beforeEach(() => {
  resetDocumentIdentityForTests();
  boundary.deps = [];
  boundary.cleanups = [];
  boundary.meta = { isOffline: false, isDegraded: false, isRefetching: false };
  boundary.reload.mockReset();
  boundary.refetch.mockReset();
  FakeChannel.open = [];
  vi.stubGlobal("window", { location: { reload: boundary.reload } });
  vi.stubGlobal("BroadcastChannel", FakeChannel);
});
afterEach(() => {
  unmount();
  vi.unstubAllGlobals();
});

describe("sessionIdentity", () => {
  it("maps session states to identities", () => {
    expect(sessionIdentity(user("u1"))).toBe("u1");
    expect(sessionIdentity({ status: "anonymous" })).toBeNull();
    expect(sessionIdentity({ status: "pending" })).toBeUndefined();
    expect(sessionIdentity({ status: "error" })).toBeUndefined();
  });
});

describe("useReloadOnIdentityChange", () => {
  it("does not reload on the first known identity or on sign-in", () => {
    useRenderWith({ status: "pending" });
    useRenderWith({ status: "anonymous" });
    useRenderWith(user("u1"));
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("does not reload when a pending or error blip resolves to the same user", () => {
    useRenderWith(user("u1"));
    useRenderWith({ status: "error" });
    useRenderWith({ status: "pending" });
    useRenderWith(user("u1"));
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it.each(["isOffline", "isDegraded", "isRefetching"] as const)(
    "does not accept %s as proof of a changed identity",
    (flag) => {
      useRenderWith(user("u1"));
      boundary.meta[flag] = true;
      useRenderWith({ status: "anonymous" });
      expect(boundary.reload).not.toHaveBeenCalled();
      boundary.meta[flag] = false;
      useRenderWith(user("u1"));
      expect(boundary.reload).not.toHaveBeenCalled();
      useRenderWith({ status: "anonymous" });
      expect(boundary.reload).toHaveBeenCalledOnce();
    },
  );

  it("A → sign-out elsewhere → B: replaces the document at the sign-out", () => {
    useRenderWith(user("a"));
    useRenderWith({ status: "anonymous" });
    expect(boundary.reload).toHaveBeenCalledTimes(1);
    useRenderWith(user("b"));
    expect(boundary.reload).toHaveBeenCalledTimes(2);
  });

  it("A → B directly: replaces the document", () => {
    useRenderWith(user("a"));
    useRenderWith({ status: "pending" });
    useRenderWith(user("b"));
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("remembers whose data is cached across a watcher unmount", () => {
    useRenderWith(user("a"));
    unmount();
    // Another account signed in while no watcher was mounted.
    useRenderWith(user("b"));
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("leaves an explicit sign-out's own page load alone, until it is undone", () => {
    useRenderWith(user("u1"));
    const undo = markExplicitSignOut();
    useRenderWith({ status: "error" });
    useRenderWith(user("u1"));
    expect(boundary.reload).not.toHaveBeenCalled();
    undo();
    useRenderWith({ status: "anonymous" });
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("tells the other tabs about a sign-in, and checks the session on theirs", () => {
    useRenderWith({ status: "anonymous" });
    const [channel] = FakeChannel.open;
    expect(channel?.posted).toBe(1);
    useRenderWith(user("a"));
    expect(channel?.posted).toBe(2);
    useRenderWith(user("a"));
    expect(channel?.posted).toBe(2);
    channel?.onmessage?.({} as MessageEvent);
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    // The channel is the document's, not the watcher's: it stays open.
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    expect(FakeChannel.open).toHaveLength(1);
  });
});
