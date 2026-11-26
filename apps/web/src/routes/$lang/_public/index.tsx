import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";

import { PageShell } from "@/components/page-shell";
import { APP_HOME } from "@/lib/app-home";
import { poolInviteToken } from "@/lib/pool-invite";
import { ensureSessionHint } from "@/lib/session-hint";
import { signupMode } from "@/lib/signup-mode";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_public/")({
  // A signed-in visitor (including the installed PWA, which opens at `/`)
  // goes straight to the signed-in home, Sandboxes, instead of a page that
  // offers "Sign in". The check looks only at whether the session cookie
  // exists, so anonymous renders stay static and cacheable; the home route's
  // `_auth` gate does the real check (a stale cookie ends on the login page).
  beforeLoad: async ({ params, context }) => {
    // The `_public` layout's beforeLoad already put the hint in the query
    // cache, so this is a cache read, not a second server call. A failed hint
    // reads as signed out (lib/session-hint.ts): the landing page shows rather
    // than an error screen, and the home route's own guard is unaffected.
    const signedIn = await ensureSessionHint(context.queryClient);
    if (signedIn) {
      throw redirect({ to: APP_HOME, params: { lang: params.lang }, replace: true });
    }
  },
  component: HomePage,
});

function HomePage() {
  const { t } = useTranslation("common");
  const { lang } = Route.useParams();
  return (
    <PageShell width="narrow" className="py-16 text-center">
      <h1 className="text-4xl font-semibold tracking-tight">{t("home.title")}</h1>
      <p className="mx-auto mt-4 max-w-md text-balance text-muted-foreground">
        {t("home.description")}
      </p>
      <LandingActions lang={lang} />
    </PageShell>
  );
}

/**
 * The way in, following the server's sign-up mode (lib/signup-mode.ts):
 *
 * - `open`, or `invite` (this tab holds a pool invitation, which opens sign-up
 *   for the invited address): Create account (primary) + Sign in.
 * - `bootstrap`: no administrator exists yet (`appConfig` turns the flag off
 *   once one does), so the visitor is almost certainly the operator: "Set up
 *   this server" is the primary button and Sign in the secondary one.
 * - `closed`: Sign in (primary) + the invite-only line, so a visitor without
 *   an account knows to ask for an invitation.
 *
 * The mode comes from a client query, not the SSR render: `useQuery` does not
 * fetch on the server, so every anonymous render (and the cached HTML) has the
 * neutral Sign in, and the mode-specific buttons appear once `appConfig`
 * answers. The row keeps one button height in every state, so the swap does
 * not move the page.
 */
function LandingActions({ lang }: { lang: string }) {
  const { t } = useTranslation("common");
  const { data: config } = useQuery(orpc.appConfig.queryOptions());
  const mode = config ? signupMode(config, poolInviteToken() !== undefined) : null;
  const canCreate = mode === "open" || mode === "invite";

  const signIn = (primary: boolean) => (
    <Link
      to="/$lang/login"
      params={{ lang }}
      search={{ redirectTo: undefined }}
      data-landing-action="sign-in"
      className={cn(buttonVariants({ variant: primary ? "default" : "outline" }), "min-h-11")}
    >
      {t("home.signIn")}
    </Link>
  );
  const signUp = (label: string, action: "create-account" | "set-up") => (
    <Link
      to="/$lang/signup"
      params={{ lang }}
      search={{ redirectTo: undefined }}
      data-landing-action={action}
      className={cn(buttonVariants({ variant: "default" }), "min-h-11 whitespace-normal")}
    >
      {label}
    </Link>
  );

  return (
    <div className="mt-8 space-y-3">
      <div className="flex flex-wrap items-center justify-center gap-3">
        {canCreate && signUp(t("home.createAccount"), "create-account")}
        {mode === "bootstrap" && signUp(t("home.setUp"), "set-up")}
        {signIn(!canCreate && mode !== "bootstrap")}
      </div>
      {mode === "closed" && <p className="text-sm text-muted-foreground">{t("home.inviteOnly")}</p>}
    </div>
  );
}
