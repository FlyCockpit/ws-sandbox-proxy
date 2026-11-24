import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { useTranslation } from "react-i18next";
import { AppNameLink } from "@/components/app-name-link";
import { LanguageSwitcher } from "@/components/language-switcher";
import { ModeToggle } from "@/components/mode-toggle";
import { SkipToContent } from "@/components/skip-to-content";

import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";
import { getNavItems, toLangRoute } from "@/lib/nav-items";

export const Route = createFileRoute("/$lang/_public")({
  component: PublicLayout,
});

function PublicLayout() {
  return (
    <div
      className="grid h-svh min-w-0 grid-rows-[auto_1fr]"
      style={{
        paddingBottom: "var(--safe-area-bottom)",
        paddingTop: "var(--safe-area-top)",
        paddingLeft: "var(--safe-area-left)",
        paddingRight: "var(--safe-area-right)",
      }}
    >
      <SkipToContent />
      <PublicHeader />
      <main
        id="main-content"
        tabIndex={-1}
        data-scroll-restoration-id={MAIN_SCROLLER_ID}
        className="relative [container-type:size] min-h-0 min-w-0 overflow-x-clip overflow-y-auto overscroll-contain [scrollbar-gutter:stable]"
      >
        <Outlet />
      </main>
    </div>
  );
}

function PublicHeader() {
  const { lang } = Route.useParams();
  const { t } = useTranslation("nav");
  // Deliberately always the logged-out nav: public pages stay fully static —
  // no session fetch, no better-auth chunk, SSR HTML identical for everyone.
  // The Sign In link below is the static auth entry point that comes with
  // that choice. Known tradeoff: a signed-in user's server-side locale
  // preference can't redirect these pages (that would need a session fetch);
  // it applies once they enter the `_app` branch (`useUserLocaleSync`). To
  // make this header session-aware instead, see
  // SSR-safe public chrome: optional client leaves stay out of the server tree.
  const items = getNavItems({ placement: "desktop", isAuthenticated: false });

  return (
    <header>
      <div className="flex min-w-0 flex-row flex-wrap items-center gap-4 px-4 py-2">
        {/* Gives way first, like the app header's (see AppNameLink). */}
        <AppNameLink lang={lang} />
        {/* The public branch has no BottomNav, so from `sm:` up this
            scrollable row is its navigation. Below `sm:` there is no room for
            it next to the controls (it pushed them to a second row), and the
            app name already links home; hidden, it costs no gap either. */}
        <nav
          aria-label={t("mainNav.ariaLabel")}
          className="hidden min-w-0 flex-1 overflow-x-auto overflow-y-hidden overscroll-x-contain no-scrollbar sm:block"
        >
          <div className="flex w-max items-center gap-1">
            {items.map((item) => (
              <Link
                key={item.id}
                to={toLangRoute(item.path)}
                params={{ lang }}
                activeOptions={{ exact: item.exact }}
                className="inline-flex min-h-11 shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                activeProps={{
                  className: "bg-muted text-foreground",
                }}
              >
                <item.icon aria-hidden="true" className="size-4" />
                <span>{t(item.labelKey)}</span>
              </Link>
            ))}
          </div>
        </nav>
        <div className="ml-auto flex min-w-0 max-w-full flex-wrap items-center gap-2">
          <LanguageSwitcher />
          <ModeToggle />
          <Link
            to="/$lang/login"
            params={{ lang }}
            search={{ redirectTo: undefined }}
            // The app header's Sign In metrics (`touch`, 44px tall), filled:
            // it is this page's entry point.
            className={buttonVariants({ size: "touch" })}
          >
            {t("userMenu.signIn")}
          </Link>
        </div>
      </div>
      <hr />
    </header>
  );
}
