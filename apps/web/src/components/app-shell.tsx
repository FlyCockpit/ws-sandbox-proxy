import { useLocation, useMatch, useParams, useRouterState } from "@tanstack/react-router";
import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";

import { BottomNavFirstFrame, BottomNavSkeleton } from "@/components/bottom-nav";
import Header from "@/components/header";
import { OfflineBanner } from "@/components/offline-banner";
import { ContentSkeleton } from "@/components/route-content-skeleton";
import { SkipToContent } from "@/components/skip-to-content";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { markAppShellHydrated } from "@/lib/app-shell-hydration";
import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";
import { resolvePendingLayout } from "@/lib/pending-layout";

/**
 * The `_app` shell's one grid: header row, the main page scroller, and the
 * phone bottom nav. Shared by the live layout and its server-rendered pending
 * frame so the two have the same geometry.
 */
export function AppShellFrame({
  header,
  bottomNav,
  mobileKeyboardOpen = false,
  children,
}: {
  header: ReactNode;
  bottomNav: ReactNode;
  mobileKeyboardOpen?: boolean;
  children: ReactNode;
}) {
  // The first effect of a hydrated (or client-rendered) frame: from here on a
  // route guard may change the URL (lib/app-shell-hydration.ts).
  useMountEffect(markAppShellHydrated);
  return (
    <>
      <SkipToContent />
      <div
        className={cn(
          "grid h-svh min-w-0 grid-rows-[auto_1fr_auto] md:grid-rows-[auto_1fr] md:pb-[var(--safe-area-bottom)]",
          !mobileKeyboardOpen && "pb-[calc(3.5rem_+_var(--safe-area-bottom))]",
        )}
        style={{
          paddingTop: "var(--safe-area-top)",
          paddingLeft: "var(--safe-area-left)",
          paddingRight: "var(--safe-area-right)",
        }}
        // APP_SHELL_ATTRIBUTE: what a guard looks for to know a server-rendered
        // shell may still be hydrating.
        data-app-shell=""
      >
        <div>{header}</div>
        {/* No `scrollbar-gutter: stable`: the 2FA banner and the admin
            section nav inside the scroller are full-bleed. This shell has no
            footer: phones get the BottomNav. See docs/design/shell-rules.md */}
        <main
          id="main-content"
          tabIndex={-1}
          data-scroll-restoration-id={MAIN_SCROLLER_ID}
          className="relative [container-type:size] min-h-0 min-w-0 overflow-y-auto overflow-x-clip overscroll-contain"
        >
          {children}
        </main>
        {bottomNav}
      </div>
    </>
  );
}

/**
 * The `_app` branch's pending frame. The branch is client-rendered
 * (`ssr: false`), so this is what the server sends for every signed-in URL
 * and what a hard refresh paints first: the real header row (account control
 * as a skeleton), the bottom nav, and the route's content skeleton
 * (`RouteContentSkeleton`, shaped by the routes' `staticData`), which draws
 * the dashboard frame's sidebar for pages inside it. The live layout then
 * replaces it with the same geometry.
 */
export function AppShellPending() {
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const pathname = useLocation().pathname;
  const routeId = useMatch({ strict: false, select: (match) => match.routeId });
  const matches = useRouterState({ select: (state) => state.matches });
  const layout = resolvePendingLayout(matches, routeId);
  return (
    <AppShellFrame
      header={
        // The offline notice too, so an offline hard refresh does not move
        // the page down when the layout replaces this frame.
        <>
          <Header placeholder />
          <OfflineBanner />
        </>
      }
      bottomNav={
        // Pages in the dashboard frame are signed-in pages: their tabs are
        // static, so they are drawn for real (the sidebar's are too).
        layout.frames.includes("dashboard") ? (
          <BottomNavFirstFrame lang={lang} pathname={pathname} />
        ) : (
          <BottomNavSkeleton />
        )
      }
    >
      <ContentSkeleton layout={layout} />
    </AppShellFrame>
  );
}
