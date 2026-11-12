import { createFileRoute, redirect } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { PageShell } from "@/components/page-shell";
import { decideRootLanding } from "@/lib/route-session-access";
import { getRootLandingSession } from "@/server/auth-session";

export const Route = createFileRoute("/$lang/_public/")({
  // A signed-in visitor's root is Sandboxes. Anonymous visitors (no auth
  // cookie) resolve without a session lookup, so this page stays static.
  beforeLoad: async ({ params }) => {
    if (decideRootLanding(await getRootLandingSession()).kind === "dashboard") {
      throw redirect({ to: "/$lang/dashboard/sandboxes", params: { lang: params.lang } });
    }
  },
  component: HomePage,
});

function HomePage() {
  const { t } = useTranslation("common");
  return (
    <PageShell width="narrow" className="py-16 text-center">
      <h1 className="text-4xl font-semibold tracking-tight">{t("home.title")}</h1>
      <p className="mx-auto mt-4 max-w-md text-balance text-muted-foreground">
        {t("home.description")}
      </p>
    </PageShell>
  );
}
