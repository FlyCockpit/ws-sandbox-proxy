import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_SHELL_ATTRIBUTE,
  APP_SHELL_HYDRATION_TIMEOUT_MS,
  appShellHydrated,
  markAppShellHydrated,
  resetAppShellHydrationForTests,
} from "./app-shell-hydration";

/**
 * Route guards decide only after the server-rendered `_app` shell hydrated
 * (React #418 on a cold load that redirects): the wait, its cap, the three
 * guard resolvers, and the shell frame that reports.
 */
const mountEffects = vi.hoisted(() => [] as unknown[]);
vi.mock("@/hooks/use-mount-effect", () => ({
  useMountEffect: (fn: unknown) => {
    mountEffects.push(fn);
  },
}));
vi.mock("@tanstack/react-router", () => ({
  useLocation: () => ({ pathname: "/en-US/dashboard" }),
  useParams: () => ({ lang: "en-US" }),
  useMatch: () => "/$lang/_app",
  useRouterState: () => [],
}));
vi.mock("@/components/bottom-nav", () => ({
  BottomNavFirstFrame: () => null,
  BottomNavSkeleton: () => null,
}));
vi.mock("@/components/header", () => ({ default: () => null }));
vi.mock("@/components/route-content-skeleton", () => ({ ContentSkeleton: () => null }));
vi.mock("@/components/skip-to-content", () => ({ SkipToContent: () => null }));

/** A document whose server HTML does (or does not) hold the app shell. */
function stubDocument(hasAppShell: boolean) {
  vi.stubGlobal("document", {
    documentElement: { style: { visibility: "" } },
    querySelector: (selector: string) =>
      hasAppShell && selector === `[${APP_SHELL_ATTRIBUTE}]` ? {} : null,
  });
}

/** Whether the promise has settled after the queued microtasks ran. */
async function settled(promise: Promise<unknown>): Promise<boolean> {
  let done = false;
  void promise.then(
    () => {
      done = true;
    },
    () => {
      done = true;
    },
  );
  for (let i = 0; i < 5; i++) await Promise.resolve();
  return done;
}

beforeEach(() => {
  resetAppShellHydrationForTests();
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("appShellHydrated", () => {
  it("holds a guard while the server-rendered shell has not hydrated", async () => {
    stubDocument(true);
    const wait = appShellHydrated();
    expect(await settled(wait)).toBe(false);
    markAppShellHydrated();
    expect(await settled(wait)).toBe(true);
  });

  it("resolves at once after the shell hydrated (every later navigation)", async () => {
    stubDocument(true);
    markAppShellHydrated();
    expect(await settled(appShellHydrated())).toBe(true);
  });

  it("resolves at once when the document holds no app shell (from a public page)", async () => {
    stubDocument(false);
    expect(await settled(appShellHydrated())).toBe(true);
  });

  it("resolves at once on the server", async () => {
    expect(typeof document).toBe("undefined");
    expect(await settled(appShellHydrated())).toBe(true);
  });

  it("never holds a guard forever if the shell stops reporting", async () => {
    stubDocument(true);
    const wait = appShellHydrated();
    vi.advanceTimersByTime(APP_SHELL_HYDRATION_TIMEOUT_MS - 1);
    expect(await settled(wait)).toBe(false);
    vi.advanceTimersByTime(1);
    expect(await settled(wait)).toBe(true);
  });

  it("clears a waiter's timer once the shell reports", async () => {
    stubDocument(true);
    const wait = appShellHydrated();
    expect(vi.getTimerCount()).toBe(1);
    markAppShellHydrated();
    expect(await settled(wait)).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("the route guard resolvers", () => {
  const resolved = { status: "resolved" as const, session: null };
  const resolvers = [
    ["resolveRouteSession", "getRouteSession", resolved],
    [
      "resolveProtectedRouteSession",
      "getProtectedRouteSession",
      { ...resolved, forcedTwoFactorSettings: {}, passwordChangeRequired: false },
    ],
    ["resolveRouteAdminAccess", "getRouteAdminAccess", { ...resolved, authorized: false }],
  ] as const;

  async function load(probeName: string, probe: () => Promise<unknown>) {
    vi.resetModules();
    const admit = vi.fn(async () => undefined);
    const probes = {
      getRouteSession: vi.fn(),
      getProtectedRouteSession: vi.fn(),
      getRouteAdminAccess: vi.fn(),
      [probeName]: vi.fn(probe),
    };
    vi.doMock("@/server/auth-session", () => probes);
    vi.doMock("@/server/admin-route-access", () => probes);
    vi.doMock("@/lib/document-identity", () => ({
      admitRouteIdentity: admit,
      identityVerificationGeneration: () => 0,
    }));
    const hydration = await import("./app-shell-hydration");
    const routeSession = (await import("./route-session")) as unknown as Record<
      string,
      () => Promise<unknown>
    >;
    return { admit, probe: probes[probeName], hydration, routeSession };
  }
  afterEach(() => {
    vi.doUnmock("@/server/auth-session");
    vi.doUnmock("@/server/admin-route-access");
    vi.doUnmock("@/lib/document-identity");
  });

  it.each(resolvers)(
    "%s runs the probe at once but decides only after the shell hydrated",
    async (resolverName, probeName, answer) => {
      const { admit, probe, hydration, routeSession } = await load(probeName, async () => answer);
      stubDocument(true);

      const resolution = routeSession[resolverName]?.();
      if (!resolution) throw new Error(`${resolverName} is not exported`);
      expect(probe).toHaveBeenCalledOnce();
      expect(await settled(resolution)).toBe(false);
      expect(admit).not.toHaveBeenCalled();

      hydration.markAppShellHydrated();
      await expect(resolution).resolves.toEqual(answer);
      expect(admit).toHaveBeenCalledOnce();
    },
  );

  it.each(resolvers)(
    "%s delivers a failed probe only after the shell hydrated",
    async (resolverName, probeName) => {
      const failure = new Error("network down");
      const { admit, hydration, routeSession } = await load(probeName, async () => {
        throw failure;
      });
      stubDocument(true);

      let rejected: unknown;
      const resolution = (routeSession[resolverName]?.() ?? Promise.resolve()).then(
        () => undefined,
        (error: unknown) => {
          rejected = error;
        },
      );
      expect(await settled(resolution)).toBe(false);
      expect(rejected).toBeUndefined();

      hydration.markAppShellHydrated();
      await resolution;
      expect(rejected).toBe(failure);
      expect(admit).not.toHaveBeenCalled();
    },
  );
});

describe("the _app shell frame", () => {
  it("marks itself in the server HTML and reports hydration from its first effect", async () => {
    vi.resetModules();
    const { AppShellFrame, AppShellPending } = await import("@/components/app-shell");
    const hydration = await import("./app-shell-hydration");
    const frames = [
      () => <AppShellPending />,
      () => (
        <AppShellFrame header={null} bottomNav={null}>
          {null}
        </AppShellFrame>
      ),
    ];
    for (const frame of frames) {
      mountEffects.length = 0;
      const html = renderToStaticMarkup(frame());
      expect(html.match(new RegExp(`${hydration.APP_SHELL_ATTRIBUTE}=""`, "g"))).toHaveLength(1);
      expect(mountEffects).toContain(hydration.markAppShellHydrated);
    }
  });
});
