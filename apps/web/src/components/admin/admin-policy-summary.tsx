import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { useTranslation } from "react-i18next";

import { orpc } from "@/utils/orpc";

/**
 * One read-only line on the Admin overview: whether sign-up is open and who
 * must use 2FA, as the server reports it. Changes stay on Admin › Settings,
 * behind their confirmations.
 */
export function AdminPolicySummary({ lang }: { lang: string }) {
  const { t } = useTranslation("admin");
  const settings = useQuery({
    ...orpc.settings.adminGet.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  if (settings.isPending) return <Skeleton className="h-5 w-full max-w-xl" />;
  if (settings.isError) return null;
  const { signupEnabled, force2faInternalUsers, force2faPublicUsers } = settings.data;
  return (
    <p data-admin-policy="" className="text-sm text-muted-foreground">
      {t("overview.policy", {
        signup: t(signupEnabled ? "overview.signupOpen" : "overview.signupClosed"),
        admins: t(force2faInternalUsers ? "overview.required" : "overview.notRequired"),
        others: t(force2faPublicUsers ? "overview.required" : "overview.notRequired"),
      })}{" "}
      <Link
        to="/$lang/admin/settings"
        params={{ lang }}
        className="inline-flex min-h-11 items-center font-medium text-foreground underline underline-offset-4"
      >
        {t("overview.policyLink")}
      </Link>
    </p>
  );
}
