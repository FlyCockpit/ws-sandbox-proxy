import { Link, useParams } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { AppNameLink } from "@/components/app-name-link";
import { LanguageSwitcher } from "@/components/language-switcher";
import { ModeToggle } from "@/components/mode-toggle";
import { NotFoundPage } from "@/components/not-found-page";
import { SkipToContent } from "@/components/skip-to-content";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";
import { getNavItems, toLangRoute } from "@/lib/nav-items";

/**
 * The public shell: header and the one page scroller. The `_public` layout
 * renders its routes through it, and so does the 404 (`$lang`'s
 * `notFoundComponent`), so an unknown URL keeps the header's language and
 * theme controls and the scroller. wssp has no public footer (the landing is
 * the only public page); one would go last in the content column below.
 * See docs/design/shell-rules.md
 */
export function PublicShell({ children }: { children: ReactNode }) {
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
      {/* No `scrollbar-gutter: stable`: a reserved gutter stops every
          full-bleed rule inside the scroller short of the viewport edge with
          classic scrollbars. */}
      <main
        id="main-content"
        tabIndex={-1}
        data-scroll-restoration-id={MAIN_SCROLLER_ID}
        className="relative [container-type:size] min-h-0 min-w-0 overflow-x-clip overflow-y-auto overscroll-contain"
      >
        {/* At least as tall as the scroller: the page grows into the space
            (the 404 centres in it), and a footer added later would end at the
            scroller's bottom on a short page. */}
        <div className="flex min-h-full min-w-0 flex-col">
          <div className="flex min-w-0 flex-1 flex-col">{children}</div>
        </div>
      </main>
    </div>
  );
}

function PublicHeader() {
  // `strict: false`: the 404 renders this header under `$lang` as well as the
  // `_public` routes. An unsupported value never gets this far (`$lang`
  // redirects it), but fall back rather than build a broken link.
  const langParam = useParams({ strict: false, select: (p) => p.lang });
  const lang = isSupportedLocale(langParam) ? langParam : DEFAULT_LOCALE;
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

/**
 * The 404 for an unknown URL, which matches no layout: `$lang`'s
 * `notFoundComponent`, so it renders in `$lang`'s outlet with nothing around
 * it. Wrapped in the public shell, it keeps the header (language, theme, Sign
 * In) and the scroller like every other page. Hidden admin pages throw the
 * same not-found and land here too, so they stay indistinguishable.
 */
export function PublicNotFoundPage() {
  return (
    <PublicShell>
      <NotFoundPage />
    </PublicShell>
  );
}
