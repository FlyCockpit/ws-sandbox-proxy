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
  /** What the atom holds right after a refetch (`readSessionIdentity`). */
  checked: undefined as string | null | undefined,
  inFlight: false,
  /** An account-aware page is showing (the boundary's `showsAccount`). */
  showsAccount: true,
  /** The hook's refs, by call order, kept across renders of one mount. */
  refs: [] as { current: unknown }[],
  refCall: 0,
}));

// Run the hook without a DOM: layout effects that fire, in order, whenever
// their deps change (cleaning up the previous run first), as React does.
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  // Outside a component: read the store's client snapshot directly.
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) => getSnapshot(),
  useRef: (initial: unknown) => {
    const i = boundary.refCall++;
    boundary.refs[i] ??= { current: initial };
    return boundary.refs[i];
  },
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
  useAuthSession: (options?: { unmasked?: boolean }) => ({
    // The watcher must read the raw session: a masked read here would see
    // only `pending`, and every identity test below would fail.
    state: options?.unmasked === true ? boundary.state : { status: "pending" },
    meta: boundary.meta,
    actions: { refetch: boundary.refetch },
  }),
  readSessionIdentity: () => boundary.checked,
  isSessionFetchInFlight: () => boundary.inFlight,
}));

import {
  admitRouteIdentity,
  documentIdentityBaseline,
  isDocumentIdentityUnverified,
  markExplicitSignOut,
  resetDocumentIdentityForTests,
} from "@/lib/document-identity";

import { sessionIdentity, useReloadOnIdentityChange } from "./use-reload-on-identity-change";

const user = (id: string) => ({ status: "authenticated", session: { user: { id } } }) as const;

function useRenderWith(state: typeof boundary.state) {
  boundary.state = state;
  boundary.call = 0;
  boundary.refCall = 0;
  useReloadOnIdentityChange({ showsAccount: boundary.showsAccount });
}

/** The identity boundary unmounts (a fresh root render, a test teardown). */
function unmount() {
  for (const cleanup of boundary.cleanups) cleanup?.();
  boundary.deps = [];
  boundary.cleanups = [];
  boundary.refs = [];
}

/** window/document listeners by event type. */
const events = new Map<string, Set<() => void>>();
function listen(type: string, fn: () => void) {
  if (!events.has(type)) events.set(type, new Set());
  events.get(type)?.add(fn);
}
function fire(type: string) {
  for (const fn of events.get(type) ?? []) fn();
}
const settle = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};

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
  boundary.checked = undefined;
  boundary.inFlight = false;
  boundary.showsAccount = true;
  boundary.refs = [];
  FakeChannel.open = [];
  events.clear();
  vi.stubGlobal("window", {
    location: { reload: boundary.reload },
    addEventListener: (type: string, fn: () => void) => listen(type, fn),
    removeEventListener: (type: string, fn: () => void) => events.get(type)?.delete(fn),
  });
  vi.stubGlobal("document", {
    visibilityState: "visible",
    documentElement: { style: { setProperty: () => {} } },
    addEventListener: (type: string, fn: () => void) => listen(type, fn),
    removeEventListener: (type: string, fn: () => void) => events.get(type)?.delete(fn),
  });
  vi.stubGlobal("BroadcastChannel", FakeChannel);
});
afterEach(() => {
  unmount();
  vi.useRealTimers();
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
    // Still on its way out when B is confirmed: one reload is enough.
    useRenderWith(user("b"));
    expect(boundary.reload).toHaveBeenCalledTimes(1);
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

  it("after a peer's announcement with no watcher mounted, re-checks on mount and stays neutral until then", async () => {
    // A on an app page; the root boundary goes away (a fresh root render).
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    // Another tab announces; nobody here can check it yet.
    channel?.onmessage?.({} as MessageEvent);
    expect(isDocumentIdentityUnverified()).toBe(true);
    // The boundary mounts again (no guard confirmed anyone). The mount check
    // refetches; the atom says B.
    boundary.checked = "b";
    useRenderWith({ status: "pending" });
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("a 401 with no watcher mounted is checked when the boundary mounts", async () => {
    const { reportSessionRejected } = await import("@/lib/document-identity");
    useRenderWith(user("a"));
    unmount();
    reportSessionRejected();
    expect(isDocumentIdentityUnverified()).toBe(true);
    boundary.checked = null;
    useRenderWith(user("a"));
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("a fresh check that confirms the same account lifts the neutral chrome", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    boundary.checked = "a";
    useRenderWith({ status: "pending" });
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("a failed check keeps it neutral; a guard's confirmation lifts it", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    boundary.checked = undefined;
    useRenderWith({ status: "pending" });
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    await admitRouteIdentity({ status: "resolved", session: { user: { id: "a" } } });
    expect(isDocumentIdentityUnverified()).toBe(false);
  });

  it("a failed mount check is retried on focus, visibility or reconnect, never left neutral", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    // Back in the shell: the mount check gets no fresh answer (offline, 503).
    boundary.checked = undefined;
    useRenderWith(user("a"));
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    // Back online: a new check of its own, still nothing.
    fire("online");
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(2);
    expect(isDocumentIdentityUnverified()).toBe(true);
    // The tab regains focus; this check's answer is A: the chrome comes back.
    boundary.checked = "a";
    fire("focus");
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(boundary.reload).not.toHaveBeenCalled();
    // Settled: further focus events check nothing more.
    fire("visibilitychange");
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(3);
  });

  it("a retried check that answers another account replaces the document", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    useRenderWith(user("a"));
    await settle();
    boundary.checked = "b";
    fire("visibilitychange");
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("an unmounted watcher's listeners and checks are gone", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    fire("focus");
    fire("online");
    await settle();
    expect(boundary.refetch).not.toHaveBeenCalled();
    expect(events.get("focus")?.size ?? 0).toBe(0);
    expect(events.get("visibilitychange")?.size ?? 0).toBe(0);
  });

  it("a fetch in flight across an unmount and a newer invalidation can't settle it, even after a remount", async () => {
    const answers: (() => void)[] = [];
    boundary.refetch.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          answers.push(resolve);
        }),
    );
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    // The boundary mounts: check 1 starts; it unmounts before it answers;
    // another tab announces a newer change.
    useRenderWith({ status: "pending" });
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    // It remounts while check 1 is still in flight: check 2 starts.
    useRenderWith({ status: "pending" });
    expect(answers).toHaveLength(2);
    // Check 1 answers A: it belongs to an unmounted watcher and predates the
    // newer change, so it settles nothing.
    boundary.checked = "a";
    answers[0]?.();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    // Check 2, asked after the change, answers A: now it is settled.
    answers[1]?.();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
  });

  it("a check superseded by an automatic refresh checks again once that settles", async () => {
    vi.useFakeTimers();
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    // The mount check is cancelled by Better Auth's own cross-tab refresh,
    // which is still running when the check's promise resolves.
    boundary.checked = undefined;
    boundary.inFlight = true;
    useRenderWith(user("a"));
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    // That refresh settles with the same account; the follow-up check
    // (a new one of the watcher's own) confirms it with no other event.
    boundary.inFlight = false;
    boundary.checked = "a";
    await vi.advanceTimersByTimeAsync(250);
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(2);
    expect(isDocumentIdentityUnverified()).toBe(false);
  });

  it("follow-ups stop after three supersessions", async () => {
    vi.useFakeTimers();
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    unmount();
    channel?.onmessage?.({} as MessageEvent);
    boundary.checked = undefined;
    boundary.inFlight = true;
    useRenderWith(user("a"));
    await settle();
    for (let i = 0; i < 5; i++) {
      await vi.advanceTimersByTimeAsync(250);
      await settle();
    }
    expect(boundary.refetch).toHaveBeenCalledTimes(4);
    expect(isDocumentIdentityUnverified()).toBe(true);
  });

  it("with the boundary kept mounted, a peer's check that gets no answer leaves the identity unverified", async () => {
    // A on an app page, then a public page: wssp's boundary stays mounted, so
    // no remount would check again later.
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    // Another tab switches accounts; this tab's check fails (503, A retained).
    boundary.checked = undefined;
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    expect(isDocumentIdentityUnverified()).toBe(true);
    // Back into an unguarded page: still neutral. Focus checks again: B.
    boundary.checked = "b";
    fire("focus");
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("a 401's check that gets no answer leaves it unverified; one that confirms A changes nothing", async () => {
    const { reportSessionRejected } = await import("@/lib/document-identity");
    useRenderWith(user("a"));
    boundary.checked = "a";
    reportSessionRejected();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(boundary.reload).not.toHaveBeenCalled();
    boundary.checked = undefined;
    reportSessionRejected();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
  });

  it("a peer's check that settles on another account replaces the document, whatever the render saw", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    // The render still shows A refetching (gated); the settled atom says B.
    boundary.meta.isRefetching = true;
    useRenderWith(user("a"));
    boundary.checked = "b";
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("overlapping superseded checks leave no timer behind after unmount", async () => {
    vi.useFakeTimers();
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    boundary.checked = undefined;
    boundary.inFlight = true;
    channel?.onmessage?.({} as MessageEvent);
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(2);
    unmount();
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(boundary.refetch).toHaveBeenCalledTimes(2);
  });

  it("on a public page, a peer's announcement holds the chrome neutral while its check runs", async () => {
    let answer: () => void = () => {};
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    // A leaves for a public page; the boundary stays mounted.
    boundary.showsAccount = false;
    useRenderWith(user("a"));
    boundary.refetch.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          answer = resolve;
        }),
    );
    channel?.onmessage?.({} as MessageEvent);
    // SPA Back into an unguarded app page while the check is still running:
    // no account shown.
    expect(isDocumentIdentityUnverified()).toBe(true);
    boundary.showsAccount = true;
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(true);
    boundary.checked = "b";
    answer();
    await settle();
    expect(boundary.reload).toHaveBeenCalledTimes(1);
  });

  it("on an account page, a peer's check that confirms A never masks the chrome", async () => {
    const seen: boolean[] = [];
    const { subscribeIdentityVerification } = await import("@/lib/document-identity");
    subscribeIdentityVerification(() => seen.push(isDocumentIdentityUnverified()));
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    boundary.checked = "a";
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    expect(seen.length).toBeGreaterThan(0); // the admitted identity was announced
    expect(seen.every((unverified) => !unverified)).toBe(true);
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("an older guard's answer can't lift a hold that a newer announcement's failed check set", async () => {
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    // A failed check: unverified.
    boundary.checked = undefined;
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    // A guard's probe starts (generation taken now) ...
    const { identityVerificationGeneration } = await import("@/lib/document-identity");
    const since = identityVerificationGeneration();
    // ... another tab announces again; this tab's check fails again.
    channel?.onmessage?.({} as MessageEvent);
    await settle();
    // The guard's answer (A) predates that announcement: still unverified.
    await admitRouteIdentity({ status: "resolved", session: { user: { id: "a" } } }, since);
    expect(isDocumentIdentityUnverified()).toBe(true);
  });

  it("leaving the account pages while a peer's check runs holds the chrome neutral until it answers", async () => {
    let answer: () => void = () => {};
    useRenderWith(user("a"));
    const [channel] = FakeChannel.open;
    boundary.refetch.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          answer = resolve;
        }),
    );
    // On an account page: the check starts unmasked (no flicker).
    channel?.onmessage?.({} as MessageEvent);
    expect(isDocumentIdentityUnverified()).toBe(false);
    // A public page while it runs, then SPA Back into an unguarded app page.
    boundary.showsAccount = false;
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(true);
    boundary.showsAccount = true;
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(true);
    // The answer confirms A: the chrome comes back, no reload.
    boundary.checked = "a";
    answer();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("leaving the account pages with no check running masks nothing", () => {
    useRenderWith(user("a"));
    boundary.showsAccount = false;
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(false);
  });

  it("an account the atom inherited from before the watcher, unlike the admitted one, is checked, not adopted", async () => {
    // A public page read A into the atom; A's session expired; the login
    // guard admitted nobody. The boundary mounts with the stale A snapshot.
    await admitRouteIdentity({ status: "resolved", session: null });
    boundary.checked = null;
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(true);
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    // The reactive observer did not adopt the inherited A meanwhile.
    expect(documentIdentityBaseline()).toBeNull();
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(documentIdentityBaseline()).toBeNull();
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("an inherited account whose check fails stays unadopted and unverified, and is retried", async () => {
    await admitRouteIdentity({ status: "resolved", session: null });
    boundary.checked = undefined; // 503, A retained
    boundary.meta.isDegraded = true;
    useRenderWith(user("a"));
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(true);
    expect(documentIdentityBaseline()).toBeNull();
    // The server recovers; focus checks again: nobody signed in.
    boundary.meta.isDegraded = false;
    useRenderWith(user("a"));
    expect(documentIdentityBaseline()).toBeNull();
    boundary.checked = null;
    fire("focus");
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("an atom that agrees with the admitted account is not re-checked on mount", async () => {
    await admitRouteIdentity({ status: "resolved", session: { user: { id: "a" } } });
    useRenderWith(user("a"));
    expect(boundary.refetch).not.toHaveBeenCalled();
    expect(isDocumentIdentityUnverified()).toBe(false);
  });

  it("a retained account that a later admission disagrees with is checked while mounted", async () => {
    // verify-email with the boundary mounted; the atom retains A through
    // failed refreshes (degraded), the document was never admitted.
    boundary.meta.isDegraded = true;
    useRenderWith(user("a"));
    expect(boundary.refetch).not.toHaveBeenCalled();
    // SPA navigation to login: its guard admits nobody.
    await admitRouteIdentity({ status: "resolved", session: null });
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(true);
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    boundary.checked = null;
    // (the check above answered undefined; focus checks again: nobody)
    fire("focus");
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(documentIdentityBaseline()).toBeNull();
  });

  it("a fresh other account while mounted still replaces the document at once", () => {
    useRenderWith(user("a"));
    useRenderWith(user("b"));
    expect(boundary.reload).toHaveBeenCalledTimes(1);
    expect(boundary.refetch).not.toHaveBeenCalled();
  });

  it("a sign-in over an anonymous admission while mounted is adopted, not held", async () => {
    await admitRouteIdentity({ status: "resolved", session: null });
    useRenderWith({ status: "anonymous" });
    useRenderWith(user("a"));
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(documentIdentityBaseline()).toBe("a");
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("a session fetch that predates an anonymous admission is superseded, not adopted", async () => {
    // verify-email: the atom's first fetch (asked while A was signed in) is
    // still running; A's session is revoked; the login guard admits nobody.
    boundary.inFlight = true;
    useRenderWith({ status: "pending" });
    expect(boundary.refetch).not.toHaveBeenCalled();
    await admitRouteIdentity({ status: "resolved", session: null });
    useRenderWith({ status: "pending" });
    // The watcher's own check supersedes it, and holds until it answers.
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    expect(isDocumentIdentityUnverified()).toBe(true);
    boundary.inFlight = false;
    boundary.checked = null;
    await settle();
    expect(isDocumentIdentityUnverified()).toBe(false);
    expect(documentIdentityBaseline()).toBeNull();
    // A later, real sign-in is adopted as usual.
    useRenderWith({ status: "anonymous" });
    useRenderWith(user("a"));
    expect(documentIdentityBaseline()).toBe("a");
    expect(boundary.reload).not.toHaveBeenCalled();
  });

  it("a fetch that predates a repeated anonymous admission is superseded too", async () => {
    // On login (admitted nobody); another tab's sign-in starts a check here
    // whose request is still running when A is revoked and signup's guard
    // admits nobody again.
    await admitRouteIdentity({ status: "resolved", session: null });
    useRenderWith({ status: "anonymous" });
    boundary.inFlight = true;
    useRenderWith({ status: "pending" });
    expect(boundary.refetch).not.toHaveBeenCalled();
    await admitRouteIdentity({ status: "resolved", session: null });
    useRenderWith({ status: "pending" });
    expect(boundary.refetch).toHaveBeenCalledTimes(1);
    expect(isDocumentIdentityUnverified()).toBe(true);
  });
});
