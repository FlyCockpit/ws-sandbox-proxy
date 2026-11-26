// @vitest-environment jsdom
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const routeState = vi.hoisted(() => ({
  routeId: "/$lang/_app" as string,
  matches: [] as { routeId: string; staticData?: Record<string, string> }[],
}));

vi.mock("@tanstack/react-router", () => ({
  useParams: () => ({ lang: "en-US" }),
  useMatch: ({ select }: { select: (match: { routeId: string }) => string }) =>
    select({ routeId: routeState.routeId }),
  useRouterState: ({ select }: { select: (state: { matches: unknown }) => unknown }) =>
    select({ matches: routeState.matches }),
}));

// The frame's content column, as `FrameContent` draws it: it owns the
// container and the padding.
const FRAME_CONTENT = "container mx-auto max-w-6xl px-4 py-4 md:py-6";
vi.mock("@/components/dashboard-frame", () => ({
  DashboardFramePending: ({ children }: { children: ReactNode }) => (
    <div data-frame-content="" className={FRAME_CONTENT}>
      {children}
    </div>
  ),
}));
vi.mock("@/components/auth/auth-config-gate", () => ({ AuthScreenSkeleton: () => null }));
vi.mock("@/components/auth/auth-screen", () => ({
  AuthScreen: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/skeleton-list", () => ({ SkeletonList: () => <div data-list="" /> }));

import { MountedFrameContext } from "@/lib/pending-layout";

import { ContentSkeleton, RouteContentSkeleton } from "./route-content-skeleton";

const APP = { routeId: "/$lang/_app" };
const AUTH = { routeId: "/$lang/_app/_auth", staticData: { pendingFrame: "dashboard" } };
const DASHBOARD = { routeId: "/$lang/_app/_auth/dashboard", staticData: {} };
const SANDBOX = {
  routeId: "/$lang/_app/_auth/dashboard/sandboxes/$sandboxId",
  staticData: { pendingShape: "detail" },
};
const NEW_SANDBOX = {
  routeId: "/$lang/_app/_auth/dashboard/sandboxes/new",
  staticData: { pendingShape: "form" },
};
const ADMIN = { routeId: "/$lang/_app/admin", staticData: { pendingShape: "list" } };
const ADMIN_USERS = { routeId: "/$lang/_app/admin/users", staticData: { pendingShape: "list" } };

function render(node: ReactNode): HTMLElement {
  const host = document.createElement("div");
  host.innerHTML = renderToStaticMarkup(node);
  return host;
}

/**
 * The element whose children are the shape's skeleton (its first child is the
 * header). It is the marked one, framed or not, so it always has a box.
 */
function bodyWrapper(host: HTMLElement): HTMLElement {
  const skeleton = host.querySelector<HTMLElement>("[data-route-skeleton]");
  if (!skeleton) throw new Error("no skeleton");
  return skeleton;
}

/** Container/padding classes from the skeleton down (the frame's own are excluded). */
function paddingInside(host: HTMLElement): string[] {
  const skeleton = host.querySelector<HTMLElement>("[data-route-skeleton]");
  const elements = [skeleton, ...(skeleton?.querySelectorAll<HTMLElement>("*") ?? [])];
  return elements
    .filter((element) => element && !element.hasAttribute("data-frame-content"))
    .flatMap((element) => element?.className.toString().split(/\s+/) ?? [])
    .filter((name) => /^(container|px-4|py-4|md:py-6|max-w-6xl)$/.test(name));
}

beforeEach(() => {
  routeState.routeId = APP.routeId;
  routeState.matches = [APP, AUTH, DASHBOARD, SANDBOX];
});

describe("RouteContentSkeleton inside the dashboard frame", () => {
  it("the bare pending frame draws the frame and the body, padded once by the frame", () => {
    const bare = render(<RouteContentSkeleton />);
    expect(bare.querySelector("[data-frame-content]")).not.toBeNull();
    // The marker sits on the body inside the frame (a real box), not on a
    // display:contents wrapper around the frame.
    expect(bare.querySelector("[data-frame-content] > [data-route-skeleton]")).not.toBeNull();
    expect(bodyWrapper(bare).className).toBe("min-w-0 space-y-6");
    expect(paddingInside(bare)).toEqual([]);
  });

  it("_auth's pending component (inside the live frame) draws only the same body", () => {
    routeState.routeId = AUTH.routeId;
    const inside = render(<RouteContentSkeleton skipFrames />);
    expect(inside.querySelector("[data-frame-content]")).toBeNull();
    const skeleton = inside.querySelector<HTMLElement>("[data-route-skeleton]");
    expect(skeleton?.getAttribute("data-route-skeleton")).toBe("detail");
    expect(skeleton?.className).toBe("min-w-0 space-y-6");
    expect(paddingInside(inside)).toEqual([]);
    // Same body markup as the bare frame's: nothing shifts when it swaps.
    expect(skeleton?.innerHTML).toBe(bodyWrapper(render(<RouteContentSkeleton />)).innerHTML);
  });

  it("a nested pending boundary below the frame draws only the body too", () => {
    routeState.routeId = DASHBOARD.routeId;
    const nested = render(<RouteContentSkeleton />);
    expect(nested.querySelector("[data-frame-content]")).toBeNull();
    expect(nested.querySelector("[data-route-skeleton]")?.className).toBe("min-w-0 space-y-6");
    expect(paddingInside(nested)).toEqual([]);
  });

  it("an unframed page still gets its own padded container", () => {
    const unframed = render(
      <ContentSkeleton
        layout={{ shape: "form", width: "narrow", frames: [], insideFrame: false }}
      />,
    );
    expect(unframed.querySelector("[data-route-skeleton]")?.className).toBe(
      "container mx-auto space-y-6 px-4 py-4 md:py-6 max-w-4xl",
    );
  });
});

describe("RouteContentSkeleton width and the mounted frame", () => {
  it("a form inside the frame takes FormPage's width, without padding", () => {
    routeState.matches = [APP, AUTH, DASHBOARD, NEW_SANDBOX];
    const bare = render(<RouteContentSkeleton />);
    expect(bodyWrapper(bare).className).toBe("min-w-0 space-y-6 mx-auto w-full max-w-5xl");
    expect(paddingInside(bare)).toEqual([]);
    routeState.routeId = DASHBOARD.routeId;
    const nested = render(<RouteContentSkeleton />);
    expect(bodyWrapper(nested).className).toBe("min-w-0 space-y-6 mx-auto w-full max-w-5xl");
    expect(paddingInside(nested)).toEqual([]);
  });

  it("an admin child's pending boundary inside the mounted frame draws only the body", () => {
    routeState.routeId = ADMIN.routeId;
    routeState.matches = [APP, ADMIN, ADMIN_USERS];
    const inside = render(
      <MountedFrameContext value={true}>
        <RouteContentSkeleton />
      </MountedFrameContext>,
    );
    expect(inside.querySelector("[data-frame-content]")).toBeNull();
    expect(inside.querySelector("[data-route-skeleton]")?.className).toBe("min-w-0 space-y-6");
    // The same markup as a declared frame's nested list boundary (the list's
    // own card padding aside, no container or page padding).
    expect(inside.innerHTML).toBe(
      render(
        <ContentSkeleton
          layout={{ shape: "list", width: "default", frames: [], insideFrame: true }}
        />,
      ).innerHTML,
    );
    expect(inside.innerHTML).not.toMatch(/[" ]container /);
  });

  it("/admin's pre-authorization pending frame is still identical to an unknown URL's", () => {
    routeState.routeId = APP.routeId;
    routeState.matches = [APP, ADMIN, ADMIN_USERS];
    const admin = render(<RouteContentSkeleton />).innerHTML;
    routeState.matches = [APP];
    const unknown = render(<RouteContentSkeleton />).innerHTML;
    expect(admin).toBe(unknown);
    expect(admin).toContain("container mx-auto space-y-6 px-4 py-4 md:py-6 max-w-6xl");
  });
});
