import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { PanelLeft } from "lucide-react";
import { type ReactNode, useCallback } from "react";
import { useTranslation } from "react-i18next";

import { PAGE_COLUMN_CLASS } from "@/components/page-shell";
import PullToRefresh from "@/components/pull-to-refresh";
import { useShowsAdminNavigation } from "@/hooks/use-admin-navigation";
import {
  type AppNavId,
  type AppNavItem,
  getNavItems,
  primaryNavItems,
  primarySectionFor,
  toLangRoute,
} from "@/lib/nav-items";
import { MountedFrameContext } from "@/lib/pending-layout";
import { useUiPreferences } from "@/stores/ui-preferences";

/**
 * Signed-in app chrome (mounted by `_auth`): a collapsible sidebar at `md` and
 * up with the daily sections on top and Settings (and Admin, for admins)
 * pinned to the bottom. Below `md` the bottom tab bar and its More sheet carry
 * the same items, so each breakpoint has exactly one nav surface. The active
 * item comes from `primarySectionFor`, so every page under a section keeps
 * that section lit.
 *
 * `children` replaces the routed page: the route's pending and error states
 * render inside this same frame, so a hard refresh or a failed page never
 * drops the sidebar.
 */
export function DashboardFrame({
  lang,
  banner,
  children,
}: {
  lang: string;
  banner?: ReactNode;
  children?: ReactNode;
}) {
  const queryClient = useQueryClient();
  // Pull-to-refresh (PWA, touch only) refetches the active section's lists.
  const handleRefresh = useCallback(
    () => queryClient.invalidateQueries({ type: "active" }),
    [queryClient],
  );

  return (
    <FrameLayout sidebar={<LiveSidebar lang={lang} />}>
      {banner}
      <PullToRefresh onRefresh={handleRefresh}>
        <MountedFrameContext value={true}>
          <FrameContent>{children ?? <Outlet />}</FrameContent>
        </MountedFrameContext>
      </PullToRefresh>
    </FrameLayout>
  );
}

/**
 * The frame's first paint, before the session is known (the `_app` pending
 * frame, server-rendered). The same sidebar without the toggle's state or the
 * admin-only item (pinned at the bottom, so it appearing later moves nothing).
 */
export function DashboardFramePending({ lang, children }: { lang: string; children: ReactNode }) {
  const pathname = useLocation().pathname;
  return (
    <FrameLayout
      sidebar={
        <SidebarNav
          lang={lang}
          items={primaryNavItems}
          active={primarySectionFor(pathname)}
          toggle={null}
        />
      }
    >
      <FrameContent>{children}</FrameContent>
    </FrameLayout>
  );
}

function FrameLayout({ sidebar, children }: { sidebar: ReactNode; children: ReactNode }) {
  return (
    // Main owns page scrolling at every breakpoint. Its size container bounds
    // the sticky desktop sidebar; only the sidebar's navigation scrolls locally.
    <div className="flex min-h-full min-w-0 flex-col md:flex-row">
      {sidebar}
      <div data-dashboard-content className="flex min-h-0 min-w-0 max-w-full flex-1 flex-col">
        {children}
      </div>
    </div>
  );
}

function FrameContent({ children }: { children: ReactNode }) {
  return (
    // The widest page tier, so every signed-in page, the admin section nav and
    // the banners share one column that grows with the viewport scale.
    <div className={cn(PAGE_COLUMN_CLASS, "flex min-h-0 min-w-0 flex-1 flex-col py-4 md:py-6")}>
      <div className="flex min-h-0 min-w-0 max-w-full flex-1 flex-col">{children}</div>
    </div>
  );
}

function LiveSidebar({ lang }: { lang: string }) {
  const sidebarCollapsed = useUiPreferences((state) => state.sidebarCollapsed);
  const toggleSidebar = useUiPreferences((state) => state.toggleSidebar);
  const showsAdmin = useShowsAdminNavigation();
  const active = primarySectionFor(useLocation().pathname);
  const items = getNavItems({ placement: "sidebar", isAuthenticated: true, showsAdmin });
  return (
    <SidebarNav
      lang={lang}
      items={items}
      active={active}
      toggle={{ collapsed: sidebarCollapsed, onToggle: toggleSidebar }}
    />
  );
}

/*
 * Collapsed or expanded is drawn from `<html data-sidebar="collapsed">`
 * (the `in-data-[sidebar=collapsed]:` classes), which the head bootstrap sets
 * before the first paint and the preferences store keeps in sync, so the
 * server-rendered loading frame and the live sidebar are the same width.
 */
const COLLAPSED_CENTER = "in-data-[sidebar=collapsed]:justify-center";

function SidebarNav({
  lang,
  items,
  active,
  toggle,
}: {
  lang: string;
  items: readonly AppNavItem[];
  active: AppNavId | null;
  /** `null` while the shell loads: the toggle shows but is not yet usable. */
  toggle: { collapsed: boolean; onToggle: () => void } | null;
}) {
  const { t } = useTranslation(["dashboard", "nav"]);
  const sidebarLabel = toggle?.collapsed
    ? t("dashboard:nav.expandSidebar")
    : t("dashboard:nav.collapseSidebar");
  const groups = (["main", "footer"] as const).map((id) => ({
    id,
    items: items.filter((item) => item.group === id),
  }));

  return (
    <aside
      aria-label={t("dashboard:nav.ariaLabel")}
      data-dashboard-nav="sidebar"
      data-collapsed={toggle ? String(toggle.collapsed) : undefined}
      className="hidden w-60 overflow-x-hidden overflow-y-auto overscroll-contain border-sidebar-border bg-sidebar in-data-[sidebar=collapsed]:w-16 md:sticky md:top-0 md:flex md:h-[100cqh] md:max-h-[100cqh] md:shrink-0 md:flex-col md:self-start md:border-e"
    >
      <div className={cn("flex justify-end p-2", COLLAPSED_CENTER)}>
        <Button
          type="button"
          variant="ghost"
          size="icon-touch"
          aria-pressed={toggle ? toggle.collapsed : undefined}
          aria-label={sidebarLabel}
          title={sidebarLabel}
          disabled={!toggle}
          onClick={toggle?.onToggle}
        >
          <PanelLeft aria-hidden="true" />
        </Button>
      </div>
      <nav
        className="flex flex-1 flex-col gap-1 px-2 pb-4"
        aria-label={t("dashboard:nav.ariaLabel")}
      >
        {groups.map((group) =>
          group.items.length === 0 ? null : (
            <div
              key={group.id}
              data-nav-group={group.id}
              className={cn(
                "flex flex-col gap-1 in-data-[sidebar=collapsed]:items-center",
                group.id === "footer" && "mt-auto border-t pt-2",
              )}
            >
              {group.items.map((item) => (
                <SidebarLink key={item.id} item={item} lang={lang} active={item.id === active} />
              ))}
            </div>
          ),
        )}
      </nav>
    </aside>
  );
}

function SidebarLink({ item, lang, active }: { item: AppNavItem; lang: string; active: boolean }) {
  const { t } = useTranslation(["nav"]);
  const label = t(item.labelKey);
  return (
    <Link
      to={toLangRoute(item.path)}
      params={{ lang }}
      activeOptions={{ exact: item.exact }}
      title={label}
      data-nav-id={item.id}
      data-active={active ? "true" : undefined}
      className={cn(
        buttonVariants({ variant: "ghost", size: "touch" }),
        "justify-start gap-2 in-data-[sidebar=collapsed]:w-11 in-data-[sidebar=collapsed]:px-0",
        COLLAPSED_CENTER,
        active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-muted-foreground",
      )}
    >
      <item.icon aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0 truncate in-data-[sidebar=collapsed]:sr-only">{label}</span>
    </Link>
  );
}
