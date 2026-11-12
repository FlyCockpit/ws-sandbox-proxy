import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { type RouteNavItem, toLangRoute } from "@/lib/nav-items";

/**
 * A compact in-page tab row of sibling pages (Account, Hosts). Real links, so
 * the active one gets `aria-current="page"`. It is page content, not a nav
 * landmark: the sidebar or bottom tabs stay the only navigation.
 */
export function RouteTabs({
  items,
  lang,
  label,
}: {
  items: readonly RouteNavItem[];
  lang: string;
  label: string;
}) {
  const { t } = useTranslation(["settings", "hosts"]);
  return (
    <div
      role="group"
      aria-label={label}
      data-route-tabs
      className="-mx-4 min-w-0 overflow-x-auto overflow-y-hidden overscroll-x-contain px-4 no-scrollbar"
    >
      <div className="flex w-max items-center gap-1 border-b">
        {items.map((item) => (
          <Link
            key={item.path}
            to={toLangRoute(item.path)}
            params={{ lang }}
            activeOptions={{ exact: item.exact }}
            className="-mb-px inline-flex min-h-11 shrink-0 items-center gap-2 border-b-2 px-3 text-sm font-medium transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            activeProps={{ className: "border-primary text-foreground" }}
            inactiveProps={{ className: "border-transparent text-muted-foreground" }}
          >
            <item.icon aria-hidden="true" className="size-4" />
            {t(item.labelKey)}
          </Link>
        ))}
      </div>
    </div>
  );
}
