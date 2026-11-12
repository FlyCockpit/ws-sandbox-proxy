import { Trans, useTranslation } from "react-i18next";

/**
 * A resource's human label stays prominent; its immutable slug is supporting
 * text, shown only when it says something the label does not.
 */
export function ResourceIdentity({ label, slug }: { label: string; slug: string }) {
  const { t } = useTranslation("common");
  if (label === slug)
    return <span className="min-w-0 max-w-full break-words text-left font-medium">{label}</span>;
  return (
    <span className="min-w-0 max-w-full break-words text-left">
      <Trans
        t={t}
        i18nKey="resourceOption"
        components={{
          label: <span className="min-w-0 break-words font-medium">{label}</span>,
          slug: (
            <span className="min-w-0 break-all font-mono text-xs text-muted-foreground">
              {slug}
            </span>
          ),
        }}
      />
    </span>
  );
}
