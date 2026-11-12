import { Toaster } from "@wssp/ui/components/sileo";
import { useTranslation } from "react-i18next";

/** The app's toast viewport, with translated pill titles for long messages. */
export function AppToaster() {
  const { t } = useTranslation("common");
  return (
    <Toaster
      titles={{
        message: t("toastTitle.message"),
        success: t("toastTitle.success"),
        error: t("toastTitle.error"),
        info: t("toastTitle.info"),
        warning: t("toastTitle.warning"),
      }}
    />
  );
}
