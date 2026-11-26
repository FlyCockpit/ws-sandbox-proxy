import { useQuery } from "@tanstack/react-query";
import { Link, useLocation, useParams } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { User } from "lucide-react";
import { lazy, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";

import { useAuthSession } from "@/hooks/use-auth-session";
import { useOrphanOwnerSync } from "@/hooks/use-orphan-owner-sync";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { orpc } from "@/utils/orpc";

// Lazy so the shared Base UI overlay chunk (Menu/Dialog/focus-guards) leaves the
// eager first-paint bundle. Only the signed-in branch touches Base UI; the
// pending Skeleton and signed-out Buttons/Links stay fully eager. The shell
// below reproduces the trigger Button exactly, so the swap is zero-CLS.
const UserMenuContent = lazy(() => import("./user-menu-content"));

// Warm the chunk on hover/focus. The module cache dedupes repeat calls, so the
// click handler that follows resolves instantly from cache.
function prefetchMenu() {
  void import("./user-menu-content");
}

export default function UserMenu() {
  // `strict: false` so the menu renders under both prefixed and (briefly) the
  // top-level `/` redirect route without throwing.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const authSession = useAuthSession();
  // The header is always mounted: sign-out and owner changes reach the
  // orphaned-credential queue even with no credential page open.
  useOrphanOwnerSync();
  const { data: configData, isPending: configPending } = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation("nav");
  // The user the real menu was opened for. Keyed by user id (not a plain
  // boolean) so a different account in the same tab gets the closed shell
  // again instead of the lazy menu, which mounts `defaultOpen`.
  const [mountedForUser, setMountedForUser] = useState<string | null>(null);
  const pathname = useLocation().pathname.replace(/\/+$/, "");

  if (authSession.state.status === "pending" || authSession.state.status === "error") {
    return <Skeleton className="h-11 w-11 md:w-24" />;
  }

  if (authSession.state.status === "anonymous") {
    // Default to NOT showing Sign Up until the flag is known, so it never
    // flashes when signup is disabled.
    const showSignUp = !configPending && configData?.signupEnabled === true;
    // Below `sm:` both buttons do not fit one row next to Language and Theme
    // (es-MX labels are long), so only the button for the *other* page shows:
    // Sign Up on /login, Sign In everywhere else. The login and signup cards
    // already link to each other.
    const onLogin = pathname === `/${lang}/login`;
    const fromSm = "hidden sm:inline-flex";
    return (
      <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
        {showSignUp && (
          <Link
            to="/$lang/signup"
            params={{ lang }}
            search={{ redirectTo: undefined }}
            className={cn(buttonVariants({ size: "touch" }), !onLogin && fromSm)}
          >
            {t("userMenu.signUp")}
          </Link>
        )}
        <Link
          to="/$lang/login"
          params={{ lang }}
          search={{ redirectTo: undefined }}
          className={cn(
            buttonVariants({ size: "touch", variant: "outline" }),
            showSignUp && onLogin && fromSm,
          )}
        >
          {t("userMenu.signIn")}
        </Link>
      </div>
    );
  }

  const session = authSession.state.session;

  // The eager placeholder: visually identical to UserMenuContent's trigger so
  // there is no layout shift when the real control loads. `inert` while the
  // lazy chunk is in flight (Suspense fallback) so it can't take a second,
  // ignored click.
  const shell = (inert: boolean) => (
    <Button
      variant="outline"
      size="touch"
      // Same as UserMenuContent's trigger: a 44px icon below md:; from md: the
      // name, at most 192px, shrinking (to 44px) before the header controls
      // run past the trailing line. The full name is in the title.
      className="w-11 px-0! md:w-auto md:min-w-11 md:max-w-48 md:shrink md:px-3.5!"
      title={session.user.name}
      aria-label={t("userMenu.open", { name: session.user.name })}
      aria-haspopup="menu"
      inert={inert}
      onPointerEnter={prefetchMenu}
      onFocus={prefetchMenu}
      onClick={() => {
        prefetchMenu();
        setMountedForUser(session.user.id);
      }}
    >
      <User className="size-4 md:hidden" aria-hidden="true" />
      <span className="hidden truncate md:block">{session.user.name}</span>
    </Button>
  );

  if (mountedForUser !== session.user.id) return shell(false);

  return (
    <Suspense fallback={shell(true)}>
      <UserMenuContent key={session.user.id} />
    </Suspense>
  );
}
