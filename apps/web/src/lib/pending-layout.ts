/**
 * What a route looks like while it loads, declared on the route itself
 * (`staticData`) so the skeleton the user sees first has the page's shape:
 * a list, a detail view, a form or a dashboard, at the page's width, inside
 * the layout chrome (the dashboard frame's sidebar) that the page sits in.
 * See docs/design/shell-rules.md § Route pending states
 *
 *   export const Route = createFileRoute("/$lang/_app/_auth/dashboard/sandboxes/")({
 *     staticData: { pendingShape: "list" },
 *     component: SandboxesPage,
 *   });
 *
 * A layout route that draws its own chrome around its children sets
 * `pendingFrame`; leaf routes set `pendingShape` (default "list") and
 * `pendingWidth` (default "default", the unframed page widths).
 *
 * wssp's shapes add the Settings hub's card grid (`hub`) and the sign-in
 * card (`auth`); its one frame is `_auth`'s dashboard frame (sidebar).
 * Admin routes declare only the defaults: their first frame must be the same
 * as any other unframed URL's, so it never reveals that /admin exists.
 */
import { createContext } from "react";

export type PendingShape = "list" | "detail" | "form" | "dashboard" | "hub" | "auth";
export type PendingFrame = "dashboard";
export type PendingWidth = "narrow" | "default" | "wide";

declare module "@tanstack/react-router" {
  interface StaticDataRouteOption {
    pendingShape?: PendingShape;
    pendingWidth?: PendingWidth;
    pendingFrame?: PendingFrame;
  }
}

export type PendingLayout = {
  shape: PendingShape;
  width: PendingWidth;
  frames: PendingFrame[];
  /**
   * A frame above the boundary is already on screen (the skeleton renders
   * inside its content column, which owns the container and padding), so
   * only the skeleton body is drawn, never a second page container.
   */
  insideFrame: boolean;
};

/**
 * True below a mounted `DashboardFrame` (its content column already owns the
 * container and padding). Route metadata cannot say so for /admin: its layout
 * renders the frame without declaring `pendingFrame`, so that its own
 * pre-authorization pending frame stays identical to an unknown URL's. A
 * pending boundary below it reads this instead.
 */
export const MountedFrameContext = createContext(false);

type MatchLike = {
  routeId: string;
  staticData?: {
    pendingShape?: PendingShape;
    pendingWidth?: PendingWidth;
    pendingFrame?: PendingFrame;
  };
};

/**
 * The skeleton for the matches from `fromRouteId` (the route whose pending
 * boundary is showing) down to the leaf. Frames above that route are already
 * on screen (their layout rendered), so only the ones at or below it are
 * drawn; the leaf decides the shape and width.
 */
export function resolvePendingLayout(
  matches: readonly MatchLike[],
  fromRouteId: string | undefined,
): PendingLayout {
  const start = fromRouteId ? matches.findIndex((match) => match.routeId === fromRouteId) : 0;
  const below = matches.slice(Math.max(start, 0));
  const insideFrame = matches
    .slice(0, Math.max(start, 0))
    .some((match) => match.staticData?.pendingFrame !== undefined);
  const frames: PendingFrame[] = [];
  for (const match of below) {
    const frame = match.staticData?.pendingFrame;
    if (frame) frames.push(frame);
  }
  const leaf = [...below].reverse().find((match) => match.staticData?.pendingShape);
  const widthMatch = [...below].reverse().find((match) => match.staticData?.pendingWidth);
  return {
    shape: leaf?.staticData?.pendingShape ?? "list",
    width: widthMatch?.staticData?.pendingWidth ?? "default",
    frames,
    insideFrame,
  };
}
