import { beforeEach, describe, expect, it, vi } from "vitest";

const fx = vi.hoisted(() => ({
  calls: [] as ({ unmasked?: boolean } | undefined)[],
  /** What the atom holds (unmasked). */
  state: { status: "pending" } as
    | { status: "pending" }
    | { status: "anonymous" }
    | { status: "authenticated"; session: { user: { id: string } } },
}));

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  useEffect: (effect: () => void) => effect(),
  // Outside a component: read the store's client snapshot directly.
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) => getSnapshot(),
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: (options?: { unmasked?: boolean }) => {
    fx.calls.push(options);
    // Masked readers see `pending` while the identity is unverified.
    return { state: options?.unmasked === true ? fx.state : { status: "pending" } };
  },
}));

const identity = await import("@/lib/document-identity");
const { useOrphanOwnerSync } = await import("./use-orphan-owner-sync");
const { useOrphanCredentials } = await import("@/stores/orphan-credentials");

const user = (id: string) => ({ status: "authenticated", session: { user: { id } } }) as const;

beforeEach(() => {
  identity.resetDocumentIdentityForTests(() => undefined);
  fx.calls = [];
  vi.stubGlobal("window", {});
  return () => vi.unstubAllGlobals();
});

describe("useOrphanOwnerSync", () => {
  it("keeps the admitted owner while the chrome is masked (bookkeeping reads unmasked)", () => {
    fx.state = user("a");
    expect(useOrphanOwnerSync()).toBe("a");
    expect(fx.calls).toEqual([{ unmasked: true }]);
    expect(useOrphanCredentials.getState().ownerId).toBe("a");
  });

  it("records mints under the admitted account, not one the atom retained", async () => {
    // A read into the atom before any guard; a guard then admitted B.
    fx.state = user("a");
    await identity.admitRouteIdentity({ status: "resolved", session: { user: { id: "b" } } });
    expect(useOrphanOwnerSync()).toBe("b");
    expect(useOrphanCredentials.getState().ownerId).toBe("b");
    // A confirmed sign-out still clears it.
    fx.state = { status: "anonymous" };
    expect(useOrphanOwnerSync()).toBeNull();
  });
});
