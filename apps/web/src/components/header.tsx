import { useParams } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";

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
    <div>
      <div className="flex min-w-0 flex-row flex-wrap items-center gap-4 px-4 py-2">
        {/* The app name gives way first at every width (see AppNameLink): it
            truncates down to 44px before the row wraps, so the header stays
            one row; it wraps only when the controls themselves (e.g. a long
            account name) cannot fit next to that 44px. */}
        <AppNameLink lang={lang} />
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
