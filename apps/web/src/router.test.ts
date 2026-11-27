// @vitest-environment jsdom
import { MutationObserver, onlineManager, type QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The QueryClient wiring in getRouter: offline writes fail fast with an
 * explanation instead of pausing silently, and an offline query error does
 * not toast (the OfflineBanner and the page's boundary already say it).
 */
const toast = vi.hoisted(() => ({ error: vi.fn(), info: vi.fn(), success: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  createRouter: (options: { context: { queryClient: QueryClient } }) => options,
}));
vi.mock("@tanstack/react-router-ssr-query", () => ({ setupRouterSsrQueryIntegration: () => {} }));
vi.mock("@tanstack/react-start", () => {
  const chain = { server: () => chain, client: () => () => undefined };
  return { createIsomorphicFn: () => chain };
});
vi.mock("@wssp/config/locales", () => ({ isSafeAssetScriptPath: () => false }));
vi.mock("./components/error-state", () => ({ default: () => null }));
vi.mock("./components/route-content-skeleton", () => ({ RouteContentSkeleton: () => null }));
vi.mock("./i18n", () => ({
  default: { t: (key: string) => key },
  createRequestI18n: () => undefined,
}));
vi.mock("./lib/pool-invite", () => ({ capturePoolInviteFragment: () => {} }));
vi.mock("@/server/auth-session", () => ({ getSessionCookieHint: vi.fn(async () => false) }));
vi.mock("./routeTree.gen", () => ({ routeTree: {} }));
vi.mock("./stores/orphan-credentials", () => ({
  useOrphanCredentials: { getState: () => ({ clear: () => {} }) },
}));
vi.mock("./utils/orpc", () => ({ orpc: {} }));

const { getRouter } = await import("./router");

let online = true;
let queryClient: QueryClient;
const offlineFetch = () => Promise.reject(new TypeError("Failed to fetch"));

beforeEach(() => {
  online = true;
  vi.spyOn(window.navigator, "onLine", "get").mockImplementation(() => online);
  queryClient = (getRouter() as unknown as { context: { queryClient: QueryClient } }).context
    .queryClient;
  queryClient.mount();
});

afterEach(() => {
  onlineManager.setOnline(true);
  queryClient.unmount();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function goOffline() {
  online = false;
  onlineManager.setOnline(false);
}

describe("router QueryClient offline policy", () => {
  it("an offline write runs, fails at once and is explained, never paused silently", async () => {
    goOffline();
    const mutationFn = vi.fn(offlineFetch);
    const observer = new MutationObserver(queryClient, { mutationFn });
    await expect(observer.mutate(undefined)).rejects.toThrow("Failed to fetch");
    expect(mutationFn).toHaveBeenCalledOnce();
    expect(observer.getCurrentResult().isPaused).toBe(false);
    expect(toast.error).toHaveBeenCalledExactlyOnceWith("errors:offline");
  });

  it("a write that opts into the queue waits offline with a notice and is announced when sent", async () => {
    goOffline();
    const mutationFn = vi.fn(async () => "saved");
    const observer = new MutationObserver(queryClient, { mutationFn, meta: { offline: "queue" } });
    const done = observer.mutate(undefined);
    await vi.waitFor(() => expect(observer.getCurrentResult().isPaused).toBe(true));
    expect(toast.info).toHaveBeenCalledExactlyOnceWith("common:offline.queued");
    online = true;
    onlineManager.setOnline(true);
    await expect(done).resolves.toBe("saved");
    expect(toast.success).toHaveBeenCalledExactlyOnceWith("common:offline.queuedSent");
  });

  it("an offline query error does not toast", async () => {
    goOffline();
    await expect(
      queryClient.fetchQuery({ queryKey: ["hosts"], queryFn: offlineFetch, networkMode: "always" }),
    ).rejects.toThrow();
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("an online query error still toasts, saying the server could not be reached", async () => {
    await expect(
      queryClient.fetchQuery({ queryKey: ["hosts"], queryFn: offlineFetch }),
    ).rejects.toThrow();
    expect(toast.error).toHaveBeenCalledOnce();
    expect(toast.error.mock.calls[0]?.[0]).toBe("errors:unreachable");
  });
});
