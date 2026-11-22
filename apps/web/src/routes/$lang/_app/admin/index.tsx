import { createFileRoute, Link } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { cn } from "@wssp/ui/lib/utils";
import { Activity, Settings, Users } from "lucide-react";
import { useTranslation } from "react-i18next";

import { AdminPolicySummary } from "@/components/admin/admin-policy-summary";
import { DeploymentSetupCard } from "@/components/admin/deployment-setup-card";
import { PageHeader, PageShell } from "@/components/page-shell";

export const Route = createFileRoute("/$lang/_app/admin/")({
  component: AdminOverview,
});

const ADMIN_LINKS = [
  {
    to: "/$lang/admin/users",
    labelKey: "admin:nav.users",
    descriptionKey: "admin:users.description",
    icon: Users,
  },
  {
    to: "/$lang/admin/observability",
    labelKey: "admin:nav.observability",
    descriptionKey: "admin:observability.description",
    icon: Activity,
  },
  {
    to: "/$lang/admin/settings",
    labelKey: "admin:nav.settings",
    descriptionKey: "admin:settings.description",
    icon: Settings,
  },
] as const;

function AdminOverview() {
  const { lang } = Route.useParams();
  const { t } = useTranslation(["admin", "common"]);

  return (
    <PageShell width="wide">
      <PageHeader title={t("admin:overview.title")} description={t("admin:overview.description")} />
      <AdminPolicySummary lang={lang} />
      <DeploymentSetupCard lang={lang} />
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {ADMIN_LINKS.map((item) => (
          <Card key={item.to}>
            <CardHeader className="space-y-2">
              <div className="flex items-center gap-2">
                <item.icon aria-hidden className="size-4 text-muted-foreground" />
                <CardTitle className="text-base">{t(item.labelKey)}</CardTitle>
              </div>
              <CardDescription>{t(item.descriptionKey)}</CardDescription>
            </CardHeader>
            <CardContent>
              <Link
                to={item.to}
                params={{ lang }}
                className={cn(buttonVariants({ variant: "outline", size: "sm" }), "min-h-[44px]")}
              >
                {t("common:actions.manage")}
              </Link>
            </CardContent>
          </Card>
        ))}
      </section>
    </PageShell>
  );
}
