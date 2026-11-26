import { useLocation, useParams } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";

import { AuthScreenSkeleton } from "@/components/auth/auth-config-gate";
import { AuthScreen } from "@/components/auth/auth-screen";
import { BottomNavFirstFrame, BottomNavSkeleton } from "@/components/bottom-nav";
import { DashboardFramePending } from "@/components/dashboard-frame";
import Header from "@/components/header";
import { SkeletonList } from "@/components/skeleton-list";
import { SkipToContent } from "@/components/skip-to-content";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";
import { settingsHubGroups, stripLangPrefix } from "@/lib/nav-items";

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

/** A page's loading body: a title line over a list, the shape most pages have. */
export function PageSkeleton() {
  return (
    <div data-page-skeleton className="min-w-0 space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-full max-w-md" />
      </div>
      <SkeletonList />
    </div>
  );
}

/**
 * The Settings hub's loading body: its shape (title, then each group's
 * heading over a two-column grid of cards), not a list, so nothing jumps
 * when the cards arrive. Group and card counts come from the static hub.
 */
function SettingsHubSkeleton() {
  return (
    <div data-settings-hub-skeleton="" className="flex min-w-0 flex-col gap-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-4 w-full max-w-md" />
      </div>
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
    </div>
  );
}

const AUTH_PAGES = new Set([
  "/login",
  "/signup",
  "/forgot-password",
  "/reset-password",
  "/verify-email",
]);

/** Which loading body a pathname under `_app` gets before its route loads. */
export function shellPendingKind(pathname: string): "dashboard" | "auth" | "page" {
  const path = stripLangPrefix(pathname).replace(/\/+$/, "") || "/";
  // Not /admin: its pending frame must match an unknown URL's, so a hard
  // refresh can't tell anyone the hidden admin tree exists.
  if (/^\/(dashboard|settings)(\/|$)/.test(path)) return "dashboard";
  if (AUTH_PAGES.has(path)) return "auth";
  return "page";
}

/** The Settings hub itself (not a page under it). */
function isSettingsHub(pathname: string): boolean {
  return (stripLangPrefix(pathname).replace(/\/+$/, "") || "/") === "/settings";
}

/**
 * The `_app` branch's pending frame. The branch is client-rendered
 * (`ssr: false`), so this is what the server sends for every signed-in URL
 * and what a hard refresh paints first: the real header row (account control
 * as a skeleton), the sidebar for dashboard and settings pages (its width
 * from the head bootstrap's `data-sidebar`), the bottom nav, and only the
 * page body as a skeleton. The live layout then replaces it with the same
 * geometry.
 */
export function AppShellPending() {
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const pathname = useLocation().pathname;
  const kind = shellPendingKind(pathname);
  return (
    <AppShellFrame
      header={<Header placeholder />}
      bottomNav={
        // Dashboard and settings URLs are signed-in pages: their tabs are
        // static, so they are drawn for real (the sidebar's are too).
        kind === "dashboard" ? (
          <BottomNavFirstFrame lang={lang} pathname={pathname} />
        ) : (
          <BottomNavSkeleton />
        )
      }
    >
      <div aria-busy="true" className="contents">
        {kind === "dashboard" ? (
          <DashboardFramePending lang={lang}>
            {isSettingsHub(pathname) ? <SettingsHubSkeleton /> : <PageSkeleton />}
          </DashboardFramePending>
        ) : kind === "auth" ? (
          <AuthScreen>
            <AuthScreenSkeleton />
          </AuthScreen>
        ) : (
          <div className="container mx-auto max-w-6xl px-4 py-4 md:py-6">
            <PageSkeleton />
          </div>
        )}
      </div>
    </AppShellFrame>
  );
}
