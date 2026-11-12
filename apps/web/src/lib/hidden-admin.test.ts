import { createMemoryHistory, createRouter, isNotFound } from "@tanstack/react-router";
import { describe, expect, it, vi } from "vitest";

import { NotFoundPage } from "@/components/not-found-page";
import type { RouterAppContext } from "@/routes/__root";
import { Route as LangRoute } from "@/routes/$lang";
import { routeTree } from "@/routeTree.gen";

import { HIDDEN_ROUTE_NOT_FOUND_ID, hideAdminRoute, isAdminRouteMatch } from "./hidden-admin";
import type { AdminRouteResolution, RouteSession } from "./route-session-access";

const session: RouteSession = {
  user: {
    id: "user-1",
    name: "User",
    email: "user@example.test",
    emailVerified: true,
    role: "user",
    twoFactorEnabled: true,
    createdAt: 0,
  },
};

// The application's real route tree, matched the way the SSR render matches it.
// Matching only reads paths; no loader or beforeLoad runs, so no context is used.
const router = createRouter({
  routeTree,
  history: createMemoryHistory(),
  context: {} as RouterAppContext,
});
const matchesFor = (pathname: string) => router.matchRoutes(pathname, {});

async function outcome(pathname: string, resolution: AdminRouteResolution) {
  const resolve = vi.fn(async () => resolution);
  try {
    await hideAdminRoute(matchesFor(pathname), resolve);
    return { thrown: null, calls: resolve.mock.calls.length };
  } catch (error) {
    return { thrown: error, calls: resolve.mock.calls.length };
  }
}

describe("hidden admin pages (M7-S13)", () => {
  it("hides exactly what the router renders as the admin tree, including case variants", () => {
    for (const path of [
      "/en-US/admin",
      "/en-US/admin/",
      "/es-MX/admin/users",
      "/en-US/ADMIN/users",
      "/en-US/Admin",
      "/es-MX/aDmIn/settings/",
    ])
      expect(isAdminRouteMatch(matchesFor(path)), path).toBe(true);
    for (const path of ["/en-US", "/en-US/administrator", "/en-US/dashboard/admin", "/admin"])
      expect(isAdminRouteMatch(matchesFor(path)), path).toBe(false);
  });

  it.each([
    ["signed out", { status: "resolved", session: null, authorized: false }],
    ["signed-in non-admin", { status: "resolved", session, authorized: false }],
  ] as const)(
    "throws the unknown-route notFound at $lang for a %s visitor",
    async (_, resolution) => {
      for (const path of ["/en-US/admin/users", "/en-US/ADMIN/users"]) {
        const { thrown } = await outcome(path, resolution);
        expect(isNotFound(thrown), path).toBe(true);
        expect(thrown).toMatchObject({ routeId: HIDDEN_ROUTE_NOT_FOUND_ID });
      }
    },
  );

  it("lets an authorized admin through and leaves lookup failures to the admin route", async () => {
    expect(
      await outcome("/en-US/admin", { status: "resolved", session, authorized: true }),
    ).toEqual({ thrown: null, calls: 1 });
    expect(await outcome("/en-US/admin", { status: "error" })).toEqual({ thrown: null, calls: 1 });
  });

  it("never resolves the session for non-admin paths", async () => {
    expect(
      await outcome("/en-US/dashboard", { status: "resolved", session: null, authorized: false }),
    ).toEqual({ thrown: null, calls: 0 });
  });

  it("gives $lang (the boundary unknown URLs reach) a not-found page", async () => {
    // The route plugin code-splits the component into a lazy wrapper; load it.
    const component = LangRoute.options.notFoundComponent as unknown as {
      preload?: () => Promise<unknown>;
    };
    expect(component).toBeDefined();
    await component.preload?.();
    expect(NotFoundPage).toBeTypeOf("function");
  });
});
