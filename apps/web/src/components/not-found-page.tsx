import { Link, useParams } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { useTranslation } from "react-i18next";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";

/**
 * The one not-found page. `$lang` renders it for unknown URLs and for admin
 * pages hidden from the viewer (see lib/hidden-admin.ts), so the two are
 * indistinguishable.
 */
export function NotFoundPage() {
  const { t } = useTranslation("errors");
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-3 px-6 py-8 text-center">
      <h1 className="text-base font-medium">{t("pageNotFound.title")}</h1>
      <p className="text-sm text-muted-foreground">{t("pageNotFound.description")}</p>
      <Link to="/$lang" params={{ lang }} className={buttonVariants({ className: "min-h-[44px]" })}>
        {t("pageNotFound.home")}
      </Link>
    </main>
  );
}
