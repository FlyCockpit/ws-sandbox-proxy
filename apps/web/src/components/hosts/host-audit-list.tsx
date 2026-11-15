import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";

// Explicit metadata projection: command text, paths and output are never rendered.
const auditEntries = z
  .array(
    z.object({
      id: z.string(),
      createdAt: z.union([z.string(), z.date()]),
      actor: z.enum(["AGENT", "PERSON"]),
      kind: z.enum([
        "COMMAND",
        "COMMAND_QUEUED",
        "QUEUED_RUN",
        "QUEUED_DISMISSED",
        "FILE_READ",
        "FILE_LIST",
        "FILE_WRITE",
        "FILE_EDIT",
        "POLICY_LOWER",
        "POLICY_VETO_LIFT",
      ]),
      program: z.string().nullable().optional(),
      state: z.string().nullable().optional(),
    }),
  )
  .max(50);
export function HostAuditList({
  entries,
  lang,
  onRetry,
}: {
  entries: unknown;
  lang: string;
  onRetry: () => void;
}) {
  const { t } = useTranslation("agents");
  const parsed = auditEntries.safeParse(entries);
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <h2 className="font-semibold">{t("audit.title")}</h2>
      {!parsed.success ? (
        <InlineRetry message={t("audit.unavailable")} onRetry={onRetry} />
      ) : parsed.data.length === 0 ? (
        <p>{t("audit.empty")}</p>
      ) : (
        <ul className="flex min-w-0 flex-col gap-2">
          {parsed.data.map((entry) => (
            <li key={entry.id} className="break-words rounded border p-3 text-sm">
              {[
                entry.program ?? null,
                entry.state
                  ? t(`audit.states.${entry.state}`, { defaultValue: t("audit.unknownState") })
                  : null,
              ]
                .filter((part): part is string => part !== null)
                .reduce(
                  (entryText, detail) => t("audit.detail", { entry: entryText, detail }),
                  t("audit.entry", {
                    date: new Date(entry.createdAt).toLocaleString(lang),
                    actor: t(`audit.actor.${entry.actor}`),
                    kind: t(`audit.kinds.${entry.kind}`),
                  }),
                )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
