import { Link, useLocation, useParams } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { Ellipsis } from "lucide-react";
import { lazy, type ReactNode, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";

import { useShowsAdminNavigation } from "@/hooks/use-admin-navigation";
import { useAuthSession } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { getNavItems, primarySectionFor, toLangRoute } from "@/lib/nav-items";

// Lazy so the Base UI overlay chunk (Sheet) stays off the eager shell bundle;
// it loads on the first press of More.
const BottomNavMore = lazy(() => import("./bottom-nav-more"));

const TAB_CLASS =
  "flex min-h-[44px] min-w-[44px] shrink flex-col items-center justify-center gap-0.5 px-1 py-1.5 transition-colors";
/**
 * Labels are at least 12px. Tabs size to their label and shrink together down
 * to the 44px touch floor (px, so a large browser font size doesn't raise it
 * past the screen: 5 × 44px fits 320px); a label that still doesn't fit
 * truncates instead of pushing the bar past the screen edge (the link's
 * accessible name stays whole). See docs/design/shell-rules.md § Viewport scale
 */
const TAB_LABEL_CLASS = "max-w-full truncate text-xs font-medium leading-tight";

/** Signed-in tabs: every `tabs` item; the rest of the sidebar sits behind More. */
const SIGNED_IN_TABS = getNavItems({ placement: "tabs", isAuthenticated: true });

function BottomNavShell({ children }: { children: ReactNode }) {
  const { t } = useTranslation("nav");
  return (
    <nav
      aria-label={t("mainNav.ariaLabel")}
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
}

/** The bar while the session resolves (and the server-rendered first frame). */
export function BottomNavSkeleton() {
  return (
    <BottomNavShell>
      {[...SIGNED_IN_TABS.map((item) => item.id), "more"].map((id) => (
        <Skeleton key={id} className="h-10 w-16 rounded-md" />
      ))}
    </BottomNavShell>
  );
}

/**
 * The signed-in bar in the server-rendered first frame of a dashboard or
 * settings URL: the tabs are static, so they are drawn as the real links
 * (icons, labels, the current one lit) instead of blank blocks, like the
 * desktop sidebar's first frame. More is drawn but inert until the live bar
 * replaces this one; it reads no session.
 */
export function BottomNavFirstFrame({ lang, pathname }: { lang: string; pathname: string }) {
  const { t } = useTranslation("nav");
  const active = primarySectionFor(pathname);
  return (
    <BottomNavShell>
      {SIGNED_IN_TABS.map((item) => (
        <Link
          key={item.id}
          to={toLangRoute(item.path)}
          params={{ lang }}
          data-tab-id={item.id}
          data-active={item.id === active ? "true" : undefined}
          className={cn(TAB_CLASS, item.id === active ? "text-primary" : "text-muted-foreground")}
        >
          <item.icon aria-hidden="true" className="size-5" />
          <span className={TAB_LABEL_CLASS}>{t(item.labelKey)}</span>
        </Link>
      ))}
      <span data-tab-id="more" className={cn(TAB_CLASS, "text-muted-foreground")}>
        <Ellipsis aria-hidden="true" className="size-5" />
        <span className={TAB_LABEL_CLASS}>{t("items.more")}</span>
      </span>
    </BottomNavShell>
  );
}

/**
 * Phone navigation. Signed in: Sandboxes · Templates · Activity · Settings ·
 * More (Hosts, Admin for admins), the same items and active logic as the
 * desktop sidebar and the only nav surface below `md`. Signed out: the
 * anonymous items.
 */
export default function BottomNav({ hidden }: { hidden?: boolean }) {
  const authSession = useAuthSession();
  if (hidden) return null;
  if (authSession.state.status === "pending" || authSession.state.status === "error") {
    return <BottomNavSkeleton />;
  }
  if (authSession.state.status === "authenticated") return <SignedInBottomNav />;
  return <AnonymousBottomNav />;
}

function useLang() {
  // `strict: false` keeps this safe to render under any matched route (the
  // top-level `/` redirect leaves no `lang` param). Fall back to the default
  // locale rather than crashing.
  const params = useParams({ strict: false });
  return isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
}

function SignedInBottomNav() {
  const lang = useLang();
  const pathname = useLocation().pathname;
  const showsAdmin = useShowsAdminNavigation();
  const { t } = useTranslation("nav");
  const [moreOpen, setMoreOpen] = useState(false);
  const [moreMounted, setMoreMounted] = useState(false);
  const active = primarySectionFor(pathname);
  const tabIds = new Set(SIGNED_IN_TABS.map((item) => item.id));
  const rest = getNavItems({ placement: "sidebar", isAuthenticated: true, showsAdmin }).filter(
    (item) => !tabIds.has(item.id),
  );
  const moreActive = rest.some((item) => item.id === active);

  return (
    <BottomNavShell>
      {SIGNED_IN_TABS.map((item) => (
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
          <span className={TAB_LABEL_CLASS}>{t(item.labelKey)}</span>
        </Link>
      ))}
      {rest.length > 0 ? (
        <button
          type="button"
          aria-haspopup="dialog"
          aria-expanded={moreOpen}
          data-nav-id="more"
          data-active={moreActive ? "true" : undefined}
          className={cn(TAB_CLASS, moreActive ? "text-primary" : "text-muted-foreground")}
          onPointerEnter={() => void import("./bottom-nav-more")}
          onClick={() => {
            setMoreMounted(true);
            setMoreOpen(true);
          }}
        >
          <Ellipsis aria-hidden="true" className="size-5" />
          <span className={TAB_LABEL_CLASS}>{t("items.more")}</span>
        </button>
      ) : null}
      {moreMounted ? (
        <Suspense fallback={null}>
          <BottomNavMore
            open={moreOpen}
            onOpenChange={setMoreOpen}
            items={rest}
            lang={lang}
            active={active}
          />
        </Suspense>
      ) : null}
    </BottomNavShell>
  );
}

function AnonymousBottomNav() {
  const lang = useLang();
  const { t } = useTranslation("nav");
  const items = getNavItems({ placement: "mobile", isAuthenticated: false });
  return (
    <BottomNavShell>
      {items.map((item) => (
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
          <span className={TAB_LABEL_CLASS}>{t(item.labelKey)}</span>
        </Link>
      ))}
    </BottomNavShell>
  );
}
