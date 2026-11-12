import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { PanelLeft } from "lucide-react";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import PullToRefresh from "@/components/pull-to-refresh";
import {
  type PrimaryNavItem,
  primaryNavItems,
  primarySectionFor,
  toLangRoute,
} from "@/lib/nav-items";
import { useUiPreferences } from "@/stores/ui-preferences";

/**
 * Signed-in app chrome (mounted by `_auth`): a collapsible sidebar of the
 * primary sections at `md` and up. Below `md` the bottom tab bar carries the
 * same `primaryNavItems`, so each breakpoint has exactly one nav surface. The
 * active item comes from `primarySectionFor`, so every `/settings/...` page
 * keeps Settings lit.
 */
export function DashboardFrame({ lang }: { lang: string }) {
  const { t } = useTranslation(["dashboard"]);
  const sidebarCollapsed = useUiPreferences((state) => state.sidebarCollapsed);
  const toggleSidebar = useUiPreferences((state) => state.toggleSidebar);
  const sidebarLabel = sidebarCollapsed
    ? t("dashboard:nav.expandSidebar")
    : t("dashboard:nav.collapseSidebar");
  const active = primarySectionFor(useLocation().pathname);
  const queryClient = useQueryClient();
  // Pull-to-refresh (PWA, touch only) refetches the active section's lists.
  const handleRefresh = useCallback(
    () => queryClient.invalidateQueries({ type: "active" }),
    [queryClient],
  );

  return (
    // Main owns page scrolling at every breakpoint. Its size container bounds
    // the sticky desktop sidebar; only the sidebar's navigation scrolls locally.
    <div className="flex min-h-full min-w-0 flex-col md:flex-row">
      <aside
        aria-label={t("dashboard:nav.ariaLabel")}
        data-dashboard-nav="sidebar"
        data-collapsed={sidebarCollapsed ? "true" : "false"}
        className={cn(
          "hidden overflow-x-hidden overflow-y-auto overscroll-contain border-sidebar-border bg-sidebar md:flex md:sticky md:top-0 md:h-[100cqh] md:max-h-[100cqh] md:self-start md:shrink-0 md:flex-col md:border-e",
          sidebarCollapsed ? "w-16" : "w-60",
        )}
      >
        <div className={cn("flex p-2", sidebarCollapsed ? "justify-center" : "justify-end")}>
          <Button
            type="button"
            variant="ghost"
            size="icon-touch"
            aria-pressed={sidebarCollapsed}
            aria-label={sidebarLabel}
            title={sidebarLabel}
            onClick={toggleSidebar}
          >
            <PanelLeft aria-hidden="true" />
          </Button>
        </div>
        <nav className="flex flex-col gap-1 px-2 pb-4" aria-label={t("dashboard:nav.ariaLabel")}>
          {primaryNavItems.map((item) => (
            <SidebarLink
              key={item.id}
              item={item}
              lang={lang}
              collapsed={sidebarCollapsed}
              active={item.id === active}
            />
          ))}
        </nav>
      </aside>

      <div data-dashboard-content className="flex min-h-0 min-w-0 max-w-full flex-1 flex-col">
        <PullToRefresh onRefresh={handleRefresh}>
          <div className="container mx-auto flex min-h-0 min-w-0 max-w-6xl flex-1 flex-col px-4 py-4 md:py-6">
            <div className="flex min-h-0 min-w-0 max-w-full flex-1 flex-col">
              <Outlet />
            </div>
          </div>
        </PullToRefresh>
      </div>
    </div>
  );
}

function SidebarLink({
  item,
  lang,
  collapsed,
  active,
}: {
  item: PrimaryNavItem;
  lang: string;
  collapsed: boolean;
  active: boolean;
}) {
  const { t } = useTranslation(["dashboard"]);
  const label = t(item.labelKey);
  return (
    <Link
      to={toLangRoute(item.path)}
      params={{ lang }}
      activeOptions={{ exact: item.exact }}
      title={collapsed ? label : undefined}
      data-nav-id={item.id}
      data-active={active ? "true" : undefined}
      className={cn(
        buttonVariants({ variant: "ghost", size: collapsed ? "icon-touch" : "touch" }),
        collapsed ? "justify-center" : "justify-start gap-2",
        active ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-muted-foreground",
      )}
    >
      <item.icon aria-hidden="true" className="size-4" />
      {collapsed ? (
        <span className="sr-only">{label}</span>
      ) : (
        <span className="min-w-0 truncate">{label}</span>
      )}
    </Link>
  );
}
