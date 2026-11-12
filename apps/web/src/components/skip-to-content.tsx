import { useTranslation } from "react-i18next";

/** First tab stop in both mutually exclusive hosted shells. */
export function SkipToContent() {
  const { t } = useTranslation("nav");
  return (
    <a
      href="#main-content"
      className="sr-only z-[100] focus:not-sr-only focus:fixed focus:min-h-11 focus:px-4 focus:py-3 focus:bg-background focus:text-foreground focus:outline-2 focus:outline-ring"
      style={{ top: "var(--safe-area-top)", left: "var(--safe-area-left)" }}
    >
      {t("skipToContent")}
    </a>
  );
}
