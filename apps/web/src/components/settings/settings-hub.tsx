import { Link } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-shell";
import { settingsHubGroups, toLangRoute } from "@/lib/nav-items";

/**
 * The Settings hub: everything set up once, in grouped cards. Each card is a
 * single 44px+ link to its page; those pages link back with "‹ Settings".
 */
export function SettingsHub({ lang }: { lang: string }) {
  const { t } = useTranslation("settings");
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader title={t("hub.title")} description={t("hub.description")} />
      {settingsHubGroups.map((group) => (
        <section
          key={group.id}
          aria-labelledby={`settings-hub-${group.id}`}
          className="flex min-w-0 flex-col gap-2"
        >
          <h2 id={`settings-hub-${group.id}`} className="text-sm font-medium text-muted-foreground">
            {t(group.labelKey)}
          </h2>
          <ul className="grid min-w-0 gap-2 sm:grid-cols-2">
            {group.items.map((item) => (
              <li key={item.id} className="min-w-0">
                <Link
                  to={toLangRoute(item.path)}
                  params={{ lang }}
                  data-hub-item={item.id}
                  className="flex min-h-11 min-w-0 items-center gap-3 rounded-xl border bg-card p-4 text-card-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <item.icon aria-hidden="true" className="size-5 shrink-0 text-muted-foreground" />
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="font-medium">{t(item.labelKey)}</span>
                    <span className="text-sm text-muted-foreground">{t(item.descriptionKey)}</span>
                  </span>
                  <ChevronRight
                    aria-hidden="true"
                    className="size-4 shrink-0 text-muted-foreground"
                  />
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
