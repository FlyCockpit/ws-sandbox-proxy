import { useMatch, useParams, useRouterState } from "@tanstack/react-router";
import { Card, CardContent, CardHeader } from "@wssp/ui/components/card";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { type ReactNode, use } from "react";

import { AuthScreenSkeleton } from "@/components/auth/auth-config-gate";
import { AuthScreen } from "@/components/auth/auth-screen";
import { DashboardFramePending } from "@/components/dashboard-frame";
import { SkeletonList } from "@/components/skeleton-list";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { settingsHubGroups } from "@/lib/nav-items";
import {
  MountedFrameContext,
  type PendingFrame,
  type PendingLayout,
  type PendingShape,
  type PendingWidth,
  resolvePendingLayout,
} from "@/lib/pending-layout";

// Unframed pages (device, consent, admin): the default is the dashboard
// frame's content width, so the skeleton's columns line up with the page.
const WIDTH_CLASS: Record<PendingWidth, string> = {
  narrow: "max-w-4xl",
  default: "max-w-6xl",
  wide: "max-w-7xl",
};

/** The page body inside the dashboard frame's content column. */
const FRAME_BODY_CLASS = "min-w-0 space-y-6";

/** `FormPage`'s default width (packages/ui form-page.tsx), centred in the column. */
const FORM_PAGE_WIDTH_CLASS = "mx-auto w-full max-w-5xl";

function frameBodyClass(shape: PendingShape): string {
  return cn(FRAME_BODY_CLASS, shape === "form" && FORM_PAGE_WIDTH_CLASS);
}

/**
 * The content-area skeleton for the route that is loading, shaped by its
 * `staticData` (lib/pending-layout.ts). It never draws app chrome: the app
 * shell renders around it (`_app`'s pending component, and every pending
 * boundary below it, sit inside the shell's `<main>`), so the header, the nav
 * and the bottom nav are the real ones from the first frame.
 *
 * It is the router's `defaultPendingComponent`, `_app`'s pending content
 * (inside `AppShellPending`) and `_auth`'s (inside the live dashboard frame,
 * `skipFrames`). Inside a frame already on screen (`_auth`'s, or a pending
 * boundary below it) only the body is drawn: the frame owns the padding.
 */
export function RouteContentSkeleton({ skipFrames = false }: { skipFrames?: boolean }) {
  const routeId = useMatch({ strict: false, select: (match) => match.routeId });
  // The matches of the location being loaded (a pending route is already in
  // `matches`, with status "pending"), leaf last.
  const matches = useRouterState({ select: (state) => state.matches });
  const layout = resolvePendingLayout(matches, routeId);
  // A mounted `DashboardFrame` above this boundary (/admin's, which declares
  // no `pendingFrame`) already pads the column, like a declared one would.
  const inMountedFrame = use(MountedFrameContext);
  // `skipFrames`: rendered by `_auth`'s own pending component, inside its
  // live frame, so the frame is on screen even though it starts at this route.
  return (
    <ContentSkeleton
      layout={
        skipFrames
          ? { ...layout, frames: [], insideFrame: true }
          : inMountedFrame
            ? { ...layout, insideFrame: true }
            : layout
      }
    />
  );
}

/** The skeleton markup for a resolved layout. */
export function ContentSkeleton({ layout }: { layout: PendingLayout }) {
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  if (layout.shape === "auth" && layout.frames.length === 0)
    // The sign-in card brings its own centred layout.
    return (
      <div data-route-skeleton="auth" aria-busy="true" className="contents">
        <AuthScreen>
          <AuthScreenSkeleton />
        </AuthScreen>
      </div>
    );
  const framed = layout.frames.length > 0;
  // The marked element always has a box (the shell check looks for a visible
  // one): framed, it is the body inside the innermost frame, which owns the
  // padding; the frames themselves wrap it unmarked.
  let body: ReactNode = (
    <div
      data-route-skeleton={layout.shape}
      aria-busy="true"
      className={cn(
        framed || layout.insideFrame
          ? // The frame's content column already owns the container and padding.
            frameBodyClass(layout.shape)
          : ["container mx-auto space-y-6 px-4 py-4 md:py-6", WIDTH_CLASS[layout.width]],
      )}
    >
      <ShapeSkeleton shape={layout.shape} />
    </div>
  );
  // Innermost frame first.
  for (const frame of [...layout.frames].reverse()) {
    body = (
      <FrameSkeleton frame={frame} lang={lang}>
        {body}
      </FrameSkeleton>
    );
  }
  return body;
}

function FrameSkeleton({
  frame,
  lang,
  children,
}: {
  frame: PendingFrame;
  lang: string;
  children: ReactNode;
}) {
  switch (frame) {
    case "dashboard":
      // `_auth`'s frame: the sidebar (static items, the current section lit)
      // and the content column; the page body is the shape inside it.
      return <DashboardFramePending lang={lang}>{children}</DashboardFramePending>;
  }
}

function HeaderSkeleton({ action }: { action?: boolean }) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-5 w-64 max-w-full" />
      </div>
      {action ? <Skeleton className="h-11 w-32" /> : null}
    </div>
  );
}

function ShapeSkeleton({ shape }: { shape: PendingShape }) {
  switch (shape) {
    case "list":
      return (
        <>
          <HeaderSkeleton action />
          <Card>
            <CardHeader className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-24" />
            </CardHeader>
            <CardContent className="p-0">
              <SkeletonList count={4} />
            </CardContent>
          </Card>
        </>
      );
    case "detail":
      return (
        <>
          <HeaderSkeleton action />
          <Skeleton className="h-48 w-full rounded-lg" />
          <div className="space-y-3">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-5/6" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        </>
      );
    case "form":
      return (
        <>
          <HeaderSkeleton />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {Array.from({ length: 4 }, (_, index) => (
              <div key={index} className="space-y-2">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-11 w-full md:h-8" />
              </div>
            ))}
          </div>
          <Skeleton className="h-11 w-32" />
        </>
      );
    case "dashboard":
      return (
        <>
          <HeaderSkeleton />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Skeleton className="h-32 w-full rounded-lg" />
            <Skeleton className="h-32 w-full rounded-lg" />
          </div>
        </>
      );
    case "hub":
      // The Settings hub: each group's heading over a two-column grid of
      // cards (counts from the static hub), so nothing jumps when it loads.
      return (
        <>
          <HeaderSkeleton />
          {settingsHubGroups.map((group) => (
            <div key={group.id} className="flex min-w-0 flex-col gap-2">
              <Skeleton className="h-4 w-28" />
              <div className="grid min-w-0 gap-2 sm:grid-cols-2">
                {group.items.map((item) => (
                  <Skeleton key={item.id} className="h-[5.5rem] rounded-xl" />
                ))}
              </div>
            </div>
          ))}
        </>
      );
    case "auth":
      // Inside a frame (never in practice): the card alone.
      return <AuthScreenSkeleton />;
  }
}
