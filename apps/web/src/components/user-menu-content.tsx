import { useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "@tanstack/react-router";
import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@wssp/ui/components/dropdown-menu";
import { toast } from "@wssp/ui/components/sileo";
import { BookOpen, User } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useShowsAdminNavigation } from "@/hooks/use-admin-navigation";
import { useAuthSession } from "@/hooks/use-auth-session";
import { markExplicitSignOut } from "@/hooks/use-reload-on-identity-change";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { docsUrl } from "@/lib/docs-links";
import { getNavItems, toLangRoute } from "@/lib/nav-items";
import { useOrphanCredentials } from "@/stores/orphan-credentials";
import { friendly } from "@/utils/friendly-error";

/**
 * The real Base UI account menu. Lazy-loaded by `user-menu.tsx` on first
 * interaction so the shared Base UI overlay chunk stays off the eager bundle
 * (UserMenu mounts in the root on every page). It mounts `defaultOpen` so the
 * click that triggered the load opens the menu immediately — no effect, no
 * second click. Only rendered when a session is present.
 */
export default function UserMenuContent() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  // `strict: false` so the menu renders under both prefixed and (briefly) the
  // top-level `/` redirect route without throwing.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const authSession = useAuthSession();
  const showsAdmin = useShowsAdminNavigation();
  const { t } = useTranslation(["nav", "common"]);

  // The shell only renders this once a session exists; guard defensively so a
  // session-expiry race can't dereference a null user.
  if (authSession.state.status !== "authenticated") return null;
  const session = authSession.state.session;

  const userMenuItems = getNavItems({
    placement: "userMenu",
    isAuthenticated: true,
    showsAdmin,
  });
  // The product guide, when the deployment publishes the docs (VITE_DOCS_URL).
  const helpHref = docsUrl(env.VITE_DOCS_URL, "guide");

  return (
    <DropdownMenu defaultOpen>
      {/* A 44px icon below md:. From md: it shows the name, at most 192px wide,
          and shrinks (to 44px) before the header controls run past the
          trailing line; the name truncates and the full name is in the title
          (same as UserMenu's eager trigger). */}
      <DropdownMenuTrigger
        render={
          <Button
            variant="outline"
            size="touch"
            className="w-11 px-0! md:w-auto md:min-w-11 md:max-w-48 md:shrink md:px-3.5!"
            title={session.user.name}
            aria-label={t("userMenu.open", { name: session.user.name })}
          />
        }
      >
        <User className="size-4 md:hidden" aria-hidden="true" />
        <span className="hidden truncate md:block">{session.user.name}</span>
      </DropdownMenuTrigger>
      {/* At least 224px so the email fits; `end` keeps the menu's trailing
          edge on the trigger's, the header's trailing line. */}
      <DropdownMenuContent align="end" className="min-w-56 bg-card">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="space-y-0.5">
            <span className="block text-muted-foreground">{t("userMenu.myAccount")}</span>
            <span className="block truncate text-foreground" title={session.user.name}>
              {session.user.name}
            </span>
            <span className="block truncate font-normal" title={session.user.email}>
              {session.user.email}
            </span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {userMenuItems.map((item) => (
            <DropdownMenuItem
              key={item.id}
              onClick={() => navigate({ to: toLangRoute(item.path), params: { lang } })}
            >
              <item.icon className="size-4" aria-hidden="true" />
              {t(item.labelKey)}
            </DropdownMenuItem>
          ))}
          {helpHref ? (
            <DropdownMenuItem
              // A real link: opens the docs in a new tab with the browser's
              // own link behaviour (middle-click, copy link address).
              render={<a href={helpHref} target="_blank" rel="noopener noreferrer" />}
            >
              <BookOpen className="size-4" aria-hidden="true" />
              {t("userMenu.helpDocs")}
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            variant="destructive"
            inset
            onClick={async () => {
              // Dynamic import keeps the sign-out path out of the menu chunk's
              // critical path; the auth client is already warm once the menu
              // is reachable for a signed-in user.
              const { authClient } = await import("@/lib/auth-client");
              const cancelSignOut = markExplicitSignOut();
              try {
                const result = await authClient.signOut();
                if (result.error) throw result.error;
                queryClient.clear();
                useOrphanCredentials.getState().clear();
                window.location.assign(`/${lang}/login`);
              } catch (error) {
                cancelSignOut();
                toast.error(friendly(error));
              }
            }}
          >
            {t("userMenu.signOut")}
          </DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
