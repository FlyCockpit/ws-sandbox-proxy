import { Link } from "@tanstack/react-router";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { Globe, Hammer, HardDrive, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

/**
 * The Templates page's one "New template" action: three ways to get an
 * image, quickest first. The community option opens its short dialog; the
 * recipe build and the register form are pages of their own.
 */

const OPTION_CLASS =
  "flex min-h-11 w-full min-w-0 items-start gap-3 rounded-lg border p-3 text-left hover:bg-muted/50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring";

function OptionBody({
  icon: Icon,
  title,
  detail,
  badge,
}: {
  icon: LucideIcon;
  title: string;
  detail: string;
  badge?: ReactNode;
}) {
  return (
    <>
      <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="flex min-w-0 flex-wrap items-center gap-2 text-sm font-medium">
          {title}
          {badge}
        </span>
        <span className="text-sm text-muted-foreground text-pretty">{detail}</span>
      </span>
    </>
  );
}

export function NewTemplateChooser({
  lang,
  onCommunity,
  onClose,
}: {
  lang: string;
  /** Opens the community dialog (the chooser closes itself first). */
  onCommunity: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "common"]);
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("templates:chooser.title")}</DialogTitle>
          <DialogDescription>{t("templates:chooser.description")}</DialogDescription>
        </DialogHeader>
        <ul aria-label={t("templates:chooser.title")} className="flex min-w-0 flex-col gap-2">
          <li>
            <button
              type="button"
              data-new-template="community"
              className={OPTION_CLASS}
              onClick={onCommunity}
            >
              <OptionBody
                icon={Globe}
                title={t("templates:chooser.community")}
                detail={t("templates:chooser.communityDetail")}
                badge={
                  <span className="rounded-sm border border-emerald-600/40 bg-emerald-600/10 px-1.5 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                    {t("templates:chooser.recommended")}
                  </span>
                }
              />
            </button>
          </li>
          <li>
            <Link
              to="/$lang/dashboard/templates/new/build"
              params={{ lang }}
              data-new-template="build"
              className={OPTION_CLASS}
              onClick={onClose}
            >
              <OptionBody
                icon={Hammer}
                title={t("templates:chooser.build")}
                detail={t("templates:chooser.buildDetail")}
              />
            </Link>
          </li>
          <li>
            <Link
              to="/$lang/dashboard/templates/new/register"
              params={{ lang }}
              data-new-template="register"
              className={OPTION_CLASS}
              onClick={onClose}
            >
              <OptionBody
                icon={HardDrive}
                title={t("templates:chooser.register")}
                detail={t("templates:chooser.registerDetail")}
              />
            </Link>
          </li>
        </ul>
      </DialogContent>
    </Dialog>
  );
}
