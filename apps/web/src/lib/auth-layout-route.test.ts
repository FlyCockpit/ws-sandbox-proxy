import { QueryClient } from "@tanstack/react-query";
import { isRedirect } from "@tanstack/react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

const server = vi.hoisted(() => ({ getProtectedRouteSession: vi.fn() }));
vi.mock("@/server/auth-session", () => server);
vi.mock("@/lib/auth-client", () => ({ authClient: {} }));

import { Route } from "@/routes/$lang/_app/_auth";
import { orpc } from "@/utils/orpc";

import type { ProtectedRouteSessionResolution, RouteSession } from "./route-session-access";

const session: RouteSession = {
  user: {
    id: "user-1",
    name: "User",
    email: "user@example.test",
    emailVerified: true,
    role: "admin",
    twoFactorEnabled: false,
    createdAt: 0,
  },
};

type BeforeLoad = (options: {
  context: { queryClient: QueryClient; orpc: typeof orpc };
  location: { href: string; pathname: string; searchStr: string; hash: string };
  params: { lang: string };
}) => Promise<unknown>;

// The `_auth` guard as the router calls it. Typed narrowly: the full
// TanStack option type needs a live router match this test does not build.
const beforeLoad = Route.options.beforeLoad as unknown as BeforeLoad;

let queryClient: QueryClient;
const fetchSpy = vi.fn();

async function guard(resolution: ProtectedRouteSessionResolution) {
  server.getProtectedRouteSession.mockResolvedValueOnce(resolution);
  return beforeLoad({
    context: { queryClient, orpc },
    location: { href: "/en-US/dashboard", pathname: "/en-US/dashboard", searchStr: "", hash: "" },
    params: { lang: "en-US" },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5 * 60_000 } } });
  vi.stubGlobal("fetch", fetchSpy);
});

describe("_auth layout guard (cold dashboard load)", () => {
  // Cold load before: getRouteSession → settings.getAll (layout skeleton) →
  // page queries = 3 sequential round trips. After: one guard round trip
  // carries session + force-2FA settings, then page queries = 2.
  it("resolves session and force-2FA settings in ONE server round trip, no oRPC request", async () => {
    const forcedTwoFactorSettings = { force2faInternalUsers: "true" };

    await expect(guard({ status: "resolved", session, forcedTwoFactorSettings })).resolves.toEqual({
      session,
      forcedTwoFactorSettings,
    });

    expect(server.getProtectedRouteSession).toHaveBeenCalledOnce();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("seeds settings.getAll under its exact query key so shell consumers do not refetch", async () => {
    await guard({
      status: "resolved",
      session,
      forcedTwoFactorSettings: { force2faPublicUsers: "true", force2faInternalUsers: undefined },
    });

    const query = queryClient
      .getQueryCache()
      .find({ queryKey: orpc.settings.getAll.queryKey(), exact: true });
    expect(query?.state.data).toEqual({ force2faPublicUsers: "true" });
    expect(query?.isStale()).toBe(false);
  });

  it("redirects an anonymous visitor to login without seeding any settings", async () => {
    const thrown = await guard({ status: "resolved", session: null }).catch((error) => error);

    expect(isRedirect(thrown)).toBe(true);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });

  it("turns a failed lookup into a route error, never a page render", async () => {
    await expect(guard({ status: "error" })).rejects.toThrow("Route session unavailable");
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  });
});
