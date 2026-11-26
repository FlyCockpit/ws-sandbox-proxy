import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { LayoutGrid, LogIn } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { AppNameLink } from "@/components/app-name-link";
import { LanguageSwitcher } from "@/components/language-switcher";
import { ModeToggle } from "@/components/mode-toggle";
import { NotFoundPage } from "@/components/not-found-page";
import { OfflineBanner } from "@/components/offline-banner";
import { SkipToContent } from "@/components/skip-to-content";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { APP_HOME } from "@/lib/app-home";
import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";
import { getNavItems, toLangRoute } from "@/lib/nav-items";
import { sessionHintQueryOptions } from "@/lib/session-hint";

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
      {/* One grid row: the offline notice sits under the header, in the flow
          (it never covers the page), like the app shell's. */}
      <div className="min-w-0">
        <PublicHeader />
        <OfflineBanner />
      </div>
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
  // The nav row is always the logged-out one: public pages stay static, with
  // no session lookup and no better-auth chunk. Only the action at the end
  // follows the session-cookie hint (lib/session-hint.ts, presence only, never
  // an access check): "Open app" to the signed-in home when a cookie is
  // there, Sign In otherwise. The `_public` layout seeds the hint during SSR,
  // so a public page renders the right action from the first byte; the 404
  // (no `_public` route around it) asks on the client. An anonymous request
  // gets the anonymous header, identical for everyone, and ssr-cache.ts never
  // caches a request carrying a session cookie. A signed-in user's
  // server-side locale preference still applies only once they enter the
  // `_app` branch (`useUserLocaleSync`). docs/design/shell-rules.md § Public
  // header.
  const items = getNavItems({ placement: "desktop", isAuthenticated: false });
  const { data: signedIn = false } = useQuery(sessionHintQueryOptions());
  const signInLabel = t("userMenu.signIn");
  const openAppLabel = t("userMenu.openApp");

  return (
    <header>
      <div className="flex min-w-0 flex-row flex-wrap items-center gap-4 px-4 py-2">
        {/* Gives way first, like the app header's (see AppNameLink). */}
        <AppNameLink to={signedIn ? APP_HOME : "/$lang"} lang={lang} />
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
          {/* Filled: it is this page's entry point. The app header's metrics
              (`touch`, UserMenu): below `sm:` a 44px icon named by
              `aria-label`, so the row fits at 320px; from `sm:` the text.
              Both labels sit in one grid cell, the other one invisible, so
              the button is as wide as the longer of the two in either state
              and the swap moves nothing. */}
          {signedIn ? (
            <Link
              to={APP_HOME}
              params={{ lang }}
              aria-label={openAppLabel}
              data-session-action="open-app"
              className={cn(buttonVariants({ size: "touch" }), SESSION_ACTION_CLASS)}
            >
              <LayoutGrid aria-hidden="true" className="size-4 sm:hidden" />
              <SwapLabel shown={openAppLabel} reserved={signInLabel} />
            </Link>
          ) : (
            <Link
              to="/$lang/login"
              params={{ lang }}
              search={{ redirectTo: undefined }}
              aria-label={signInLabel}
              data-session-action="sign-in"
              className={cn(buttonVariants({ size: "touch" }), SESSION_ACTION_CLASS)}
            >
              <LogIn aria-hidden="true" className="size-4 sm:hidden" />
              <SwapLabel shown={signInLabel} reserved={openAppLabel} />
            </Link>
          )}
        </div>
      </div>
      <hr />
    </header>
  );
}

const SESSION_ACTION_CLASS = "w-11 px-0 sm:w-auto sm:px-3.5";

/**
 * `shown`, in a box as wide as the wider of `shown` and `reserved`: both share
 * one grid cell and `reserved` is invisible (and so not announced).
 */
function SwapLabel({ shown, reserved }: { shown: string; reserved: string }) {
  return (
    <span className="hidden text-center sm:grid">
      <span aria-hidden="true" className="invisible col-start-1 row-start-1">
        {reserved}
      </span>
      <span className="col-start-1 row-start-1">{shown}</span>
    </span>
  );
}

/**
 * The 404 for an unknown URL, which matches no layout: `$lang`'s
 * `notFoundComponent`, so it renders in `$lang`'s outlet with nothing around
 * it. Wrapped in the public shell, it keeps the header (language, theme, Sign
 * In or Open app) and the scroller like every other page. Hidden admin pages throw the
 * same not-found and land here too, so they stay indistinguishable.
 */
export function PublicNotFoundPage() {
  return (
    <PublicShell>
      <NotFoundPage />
    </PublicShell>
  );
}
