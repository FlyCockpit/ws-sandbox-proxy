import { Link, useLocation, useParams } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { useAuthSession } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { getNavItems, primaryNavItems, primarySectionFor, toLangRoute } from "@/lib/nav-items";

const TAB_CLASS =
  "flex min-h-[44px] min-w-[64px] flex-col items-center justify-center gap-0.5 px-3 py-1.5 transition-colors";

/**
 * Phone navigation. Signed in: the four primary sections (the same items and
 * active logic as the desktop sidebar), the only nav surface below `md`.
 * Signed out: the anonymous items.
 */
export default function BottomNav({ hidden }: { hidden?: boolean }) {
  // `strict: false` keeps this safe to render under any matched route (the
  // top-level `/` redirect leaves no `lang` param). Fall back to the default
  // locale rather than crashing.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const pathname = useLocation().pathname;
  const authSession = useAuthSession();
  const { t } = useTranslation(["nav", "dashboard"]);

  if (hidden) return null;

  const shell = (children: ReactNode) => (
    <nav
      aria-label={t("nav:mainNav.ariaLabel")}
      data-bottom-nav
      className="fixed bottom-0 left-0 right-0 z-50 border-t bg-background/80 backdrop-blur-lg md:hidden"
      style={{
        paddingBottom: "var(--safe-area-bottom)",
        paddingLeft: "var(--safe-area-left)",
        paddingRight: "var(--safe-area-right)",
      }}
    >
      <div className="flex h-14 items-center justify-around">{children}</div>
    </nav>
  );

  if (authSession.state.status === "pending" || authSession.state.status === "error") {
    return shell(
      primaryNavItems.map((item) => <Skeleton key={item.id} className="h-10 w-16 rounded-md" />),
    );
  }

  if (authSession.state.status === "authenticated") {
    const active = primarySectionFor(pathname);
    return shell(
      primaryNavItems.map((item) => (
        <Link
          key={item.id}
          to={toLangRoute(item.path)}
          params={{ lang }}
          activeOptions={{ exact: item.exact }}
          data-nav-id={item.id}
          data-active={item.id === active ? "true" : undefined}
          className={cn(TAB_CLASS, item.id === active ? "text-primary" : "text-muted-foreground")}
        >
          <item.icon aria-hidden="true" className="size-5" />
          <span className="text-[10px] font-medium leading-tight">{t(item.labelKey)}</span>
        </Link>
      )),
    );
  }

  const items = getNavItems({ placement: "mobile", isAuthenticated: false });
  return shell(
    items.map((item) => (
      <Link
        key={item.id}
        to={toLangRoute(item.path)}
        params={{ lang }}
        activeOptions={{ exact: item.exact }}
        className={TAB_CLASS}
        activeProps={{ className: "text-primary" }}
        inactiveProps={{ className: "text-muted-foreground" }}
      >
        <item.icon aria-hidden="true" className="size-5" />
        <span className="text-[10px] font-medium leading-tight">{t(`nav:${item.labelKey}`)}</span>
      </Link>
    )),
  );
}
