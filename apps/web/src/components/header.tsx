import { Link, useParams } from "@tanstack/react-router";
import { env } from "@wssp/env/web";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";

import { LanguageSwitcher } from "./language-switcher";
import { MainNav } from "./main-nav";
import { ModeToggle } from "./mode-toggle";
import UserMenu from "./user-menu";

export default function Header() {
  const appName = env.VITE_APP_NAME;
  // `strict: false` lets this component render under any route (including the
  // top-level `/` redirect) without throwing when the `lang` param is absent.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;

  return (
    <div>
      <div className="flex min-w-0 flex-row flex-wrap items-center gap-4 px-4 py-2">
        {/* basis-0 on phones: the brand truncates before the row wraps, so the
            signed-in header stays one row; it wraps only when the controls
            themselves (e.g. a long account name) cannot fit. */}
        <Link
          to="/$lang"
          params={{ lang }}
          className="inline-flex min-h-11 min-w-24 max-w-40 grow basis-0 items-center font-semibold text-lg sm:max-w-56 md:grow-0 md:basis-auto lg:max-w-none"
        >
          <span className="truncate">{appName}</span>
        </Link>
        <MainNav />
        <div className="ml-auto flex min-w-0 max-w-full flex-wrap items-center gap-2">
          <LanguageSwitcher />
          <ModeToggle />
          <UserMenu />
        </div>
      </div>
      <hr />
    </div>
  );
}
