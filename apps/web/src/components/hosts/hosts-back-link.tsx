import { Link } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useTranslation } from "react-i18next";

/** "‹ Hosts": the way back to the Hosts list from a host page. 44px tall, at the top. */
export function HostsBackLink({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  return (
    <Link
      to="/$lang/settings/hosts"
      params={{ lang }}
      data-hosts-back=""
      className="-ms-2 inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <ChevronLeft aria-hidden="true" className="size-4" />
      {t("title")}
    </Link>
  );
}
