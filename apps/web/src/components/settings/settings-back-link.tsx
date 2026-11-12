import { Link } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useTranslation } from "react-i18next";

/** "‹ Settings": the way back to the hub from every page it links. 44px tall. */
export function SettingsBackLink({ lang }: { lang: string }) {
  const { t } = useTranslation("settings");
  return (
    <Link
      to="/$lang/settings"
      params={{ lang }}
      activeOptions={{ exact: true }}
      data-settings-back
      className="-ms-2 inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <ChevronLeft aria-hidden="true" className="size-4" />
      {t("hub.back")}
    </Link>
  );
}
