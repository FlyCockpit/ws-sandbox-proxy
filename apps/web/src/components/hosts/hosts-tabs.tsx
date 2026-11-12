import { useTranslation } from "react-i18next";

import { RouteTabs } from "@/components/route-tabs";
import { hostsTabItems } from "@/lib/nav-items";

/** Hosts | Host credentials, shown on both pages. */
export function HostsTabs({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  return <RouteTabs items={hostsTabItems} lang={lang} label={t("tabs.label")} />;
}
