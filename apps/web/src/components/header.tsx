import { useParams } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";

import { useAuthSession } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { APP_HOME } from "@/lib/app-home";

import { AppNameLink } from "./app-name-link";
import { LanguageSwitcher } from "./language-switcher";
import { MainNav } from "./main-nav";
import { ModeToggle } from "./mode-toggle";
import UserMenu from "./user-menu";

/**
 * The app header row. `placeholder` is the server-rendered first frame of the
 * client-only app shell (see `app-shell.tsx`): the same row with the account
 * control as the skeleton UserMenu itself shows while the session resolves,
 * so the swap to the live header moves nothing.
 */
export default function Header({ placeholder = false }: { placeholder?: boolean }) {
  // `strict: false` lets this component render under any route (including the
  // top-level `/` redirect) without throwing when the `lang` param is absent.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;

  return (
    // `data-app-header`: what `pnpm check:shell-loading` measures, frame by
    // frame, from the first paint of a hard refresh to the loaded page.
    <div data-app-header="">
      <div className="flex min-w-0 flex-row flex-wrap items-center gap-4 px-4 py-2">
        {/* The app name gives way first at every width (see AppNameLink): it
            truncates down to 44px before the row wraps, so the header stays
            one row; it wraps only when the controls themselves (e.g. a long
            account name) cannot fit next to that 44px. */}
        {placeholder ? <AppNameLink to="/$lang" lang={lang} /> : <LiveAppNameLink lang={lang} />}
        {placeholder ? null : <MainNav />}
        <div className="ml-auto flex min-w-0 max-w-full flex-wrap items-center gap-2">
          <LanguageSwitcher />
          <ModeToggle />
          {placeholder ? <Skeleton className="h-11 w-11 md:w-24" /> : <UserMenu />}
        </div>
      </div>
      <hr />
    </div>
  );
}

/**
 * Signed in, the app name goes to the signed-in home, never to the public
 * landing page (which would only forward there). Anonymous visitors on the
 * auth pages go to the landing page. The server-rendered first frame
 * (`placeholder`) has no session yet and links to the landing page, which
 * forwards a signed-in visitor by the cookie hint; the box is the same.
 */
function LiveAppNameLink({ lang }: { lang: string }) {
  const isAuthenticated = useAuthSession().state.status === "authenticated";
  return <AppNameLink to={isAuthenticated ? APP_HOME : "/$lang"} lang={lang} />;
}
