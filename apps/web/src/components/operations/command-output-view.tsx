import { OUTPUT_HEAD_BYTES, OUTPUT_TAIL_BYTES } from "@wssp/api/sandbox/contracts";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";

import {
  type FetchOutputPage,
  type OutputTiming,
  useCommandOutput,
} from "@/hooks/use-command-output";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { formatDateTime } from "@/lib/format-date-time";
import { formatBytes } from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";

/**
 * A command's output (C48), read incrementally while it runs. Everything is
 * rendered as React text nodes in one preformatted log block — never as HTML, never as
 * terminal escape sequences (those arrive already replaced by visible
 * stand-ins). Ranges the server did not keep are explicit markers, the head
 * and tail split is explained, and expired output says so instead of looking
 * empty. The operation's status is shown by the page from its own query; this
 * view never derives state from output.
 */

const fetchOutputPage: FetchOutputPage = (input, { signal }) =>
  orpc.sandboxes.getCommandOutput.call(input, { signal });

type CommandOutputProps = {
  operationId: string;
  /** Reader of the output pages (default: the owner's command output). */
  fetchPage?: FetchOutputPage;
  settled: boolean;
  receipt?: string;
  locale: string;
  timing?: OutputTiming;
};

export function CommandOutputView(props: CommandOutputProps) {
  const unavailable = useSensitiveAccessUnavailable();
  const { t } = useTranslation(["operations"]);
  if (unavailable)
    return (
      <p role="status" data-sensitive-unavailable="" className="text-sm text-muted-foreground">
        {t("operations:sensitiveAccessUnavailable")}
      </p>
    );
  return <AuthorizedCommandOutputView {...props} />;
}

function AuthorizedCommandOutputView({
  operationId,
  fetchPage = fetchOutputPage,
  settled,
  receipt,
  locale,
  timing,
}: CommandOutputProps) {
  const { t } = useTranslation(["operations"]);
  const { snapshot, status, connection } = useCommandOutput({
    operationId,
    enabled: true,
    settled,
    receipt,
    fetchPage,
    timing,
  });
  const pieces = snapshot?.pieces ?? [];
  const hasText = pieces.some((piece) => piece.type === "text" && piece.text.length > 0);
  const hasStderr = pieces.some((piece) => piece.type === "text" && piece.stream !== "stdout");

  let statusLine: string;
  if (status === "signedOut") statusLine = t("operations:output.signedOut");
  else if (status === "expired") statusLine = t("operations:output.expired");
  else if (status === "notFound") statusLine = t("operations:output.notFound");
  else if (status === "loading") statusLine = t("operations:output.loading");
  else if (status === "complete")
    statusLine = t("operations:output.complete", {
      total: formatBytes(snapshot?.totalBytes ?? snapshot?.receivedBytes ?? 0, locale),
    });
  else if (status === "unsealed") statusLine = t("operations:output.unsealed");
  else statusLine = settled ? t("operations:output.waitingFinal") : t("operations:output.live");

  return (
    <section
      aria-labelledby="operation-output"
      data-output-status={status}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="operation-output" className="font-heading text-sm font-semibold">
        {t("operations:output.title")}
      </h2>
      <p role="status" data-output-line="" className="text-sm text-muted-foreground">
        {statusLine}
      </p>
      {connection !== "ok" ? (
        <p
          role="alert"
          data-output-connection={connection}
          className="rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
        >
          {t(`operations:output.${connection}`)}
        </p>
      ) : null}
      {snapshot?.restarted ? (
        <p data-output-restarted="" className="text-sm text-muted-foreground">
          {t("operations:output.restarted")}
        </p>
      ) : null}
      {snapshot?.truncated ? (
        <p data-output-truncated="" className="text-sm text-muted-foreground">
          {t("operations:output.truncated", {
            head: formatBytes(OUTPUT_HEAD_BYTES, locale),
            tail: formatBytes(OUTPUT_TAIL_BYTES, locale),
          })}
        </p>
      ) : null}
      {status !== "expired" &&
      status !== "notFound" &&
      status !== "loading" &&
      status !== "signedOut" ? (
        hasText || pieces.length > 0 ? (
          // A log region, not a copy field: it is read, not copied as one
          // value. `aria-live="off"`: appended output is not announced.
          <div
            role="log"
            aria-live="off"
            aria-label={t("operations:output.region")}
            data-output=""
            className="max-h-[60svh] min-w-0 overflow-x-auto overflow-y-auto overscroll-contain whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-3 font-mono text-xs leading-relaxed"
          >
            {pieces.map((piece) =>
              piece.type === "gap" ? (
                <span
                  key={`gap-${piece.start}`}
                  data-output-gap={`${piece.start}-${piece.end}`}
                  className="my-1 block rounded border border-dashed px-2 py-1 text-muted-foreground"
                >
                  {t("operations:output.gap", {
                    size: formatBytes(piece.end - piece.start, locale),
                    start: piece.start,
                    end: piece.end,
                  })}
                </span>
              ) : (
                <span
                  key={`text-${piece.start}`}
                  data-output-stream={piece.stream}
                  className={cn(piece.stream === "stderr" && "text-destructive")}
                >
                  {piece.text}
                </span>
              ),
            )}
          </div>
        ) : (
          <p data-output-empty="" className="text-sm text-muted-foreground">
            {status === "complete"
              ? t("operations:output.emptyComplete")
              : t("operations:output.empty")}
          </p>
        )
      ) : null}
      {hasStderr && status !== "expired" ? (
        <p className="text-xs text-muted-foreground">{t("operations:output.stderrLegend")}</p>
      ) : null}
      {snapshot?.expiresAt && status === "complete" ? (
        <p className="text-xs text-muted-foreground">
          {t("operations:output.expiresAt", {
            when: formatDateTime(snapshot.expiresAt, locale, { seconds: true }),
          })}
        </p>
      ) : null}
    </section>
  );
}
