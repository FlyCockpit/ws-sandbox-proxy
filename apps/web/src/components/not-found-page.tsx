import { Link, useParams } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { useTranslation } from "react-i18next";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";

/**
 * The one not-found page body. `$lang` renders it inside the public shell
 * (`PublicNotFoundPage`) for unknown URLs and for admin pages hidden from the
 * viewer (see lib/hidden-admin.ts), so the two are indistinguishable. A div,
 * not a `<main>`: the shell owns the page scroller. `flex-1` fills the shell's
 * content column, so the message centres in the space below the header.
 */
export function NotFoundPage() {
  const { t } = useTranslation("errors");
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 px-6 py-8 text-center">
      <h1 className="text-base font-medium">{t("pageNotFound.title")}</h1>
      <p className="text-sm text-muted-foreground">{t("pageNotFound.description")}</p>
      <Link to="/$lang" params={{ lang }} className={buttonVariants({ className: "min-h-[44px]" })}>
        {t("pageNotFound.home")}
      </Link>
    </div>
  );
}
