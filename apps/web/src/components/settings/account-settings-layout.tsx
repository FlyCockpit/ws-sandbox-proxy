import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-shell";
import { RouteTabs } from "@/components/route-tabs";
import { accountTabItems } from "@/lib/nav-items";

import { SettingsBackLink } from "./settings-back-link";

/** Account pages (Profile · Security · Images & builds): back link, title, tab row. */
export function AccountSettingsLayout({ lang, children }: { lang: string; children: ReactNode }) {
  const { t } = useTranslation("settings");
  return (
    <div className="flex w-full min-w-0 max-w-4xl flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("account.title")}
        description={t("account.description")}
      />
      <RouteTabs items={accountTabItems} lang={lang} label={t("account.tabsLabel")} />
      {children}
    </div>
  );
}
