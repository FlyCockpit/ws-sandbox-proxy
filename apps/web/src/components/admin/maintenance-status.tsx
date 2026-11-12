import { useQuery } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { CheckCircle2, RefreshCcw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { WideContent } from "@/components/wide-content";
import { orpc } from "@/utils/orpc";

import { BackupStatusCard } from "./backup-status-card";
import { DataKeyCard } from "./data-key-card";

/** Most recent failed maintenance jobs shown (server maximum is 100). */
const FAILED_JOB_LIMIT = 50;

/**
 * Maintenance status inside admin observability: backup freshness, the
 * data-key rotation card, the maintenance queues' job counts, and recent
 * failed jobs. Job metadata only —
 * the queue views carry no payloads, results or error text, by contract.
 */
export function MaintenanceStatus() {
  return (
    <div className="space-y-6">
      <BackupStatusCard />
      <DataKeyCard />
      <QueueCounts />
      <FailedJobs />
    </div>
  );
}

function QueueName({ name }: { name: string }) {
  const { t } = useTranslation("admin");
  // Unknown queue names (a newer worker) render verbatim rather than blank.
  return <>{t(`observability.maintenance.queueNames.${name}`, { defaultValue: name })}</>;
}

function QueueCounts() {
  const { t, i18n } = useTranslation("admin");
  const counters = useQuery({
    ...orpc.adminObservability.counters.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const number = new Intl.NumberFormat(i18n.language);
  const columns = ["waiting", "active", "delayed", "failed", "completed"] as const;
  return (
    <section className="min-w-0 rounded-md border">
      <div className="border-b px-4 py-3">
        <h2 className="text-base font-semibold">{t("observability.maintenance.queuesTitle")}</h2>
        <p className="text-xs text-muted-foreground">
          {t("observability.maintenance.queuesDescription")}
        </p>
      </div>
      {counters.isPending ? (
        <div className="space-y-2 p-4">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </div>
      ) : counters.isError ? (
        <InlineRetry
          className="py-12"
          message={t("observability.loadFailed")}
          onRetry={() => void counters.refetch()}
        />
      ) : (
        <WideContent>
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead className="border-b text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">
                  {t("observability.maintenance.columns.queue")}
                </th>
                {columns.map((column) => (
                  <th key={column} className="px-4 py-2 text-right font-medium">
                    {t(`observability.maintenance.columns.${column}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y">
              {counters.data.queues.map((queue) => (
                <tr key={queue.queue} data-queue={queue.queue}>
                  <td className="px-4 py-2">
                    <QueueName name={queue.queue} />
                  </td>
                  {columns.map((column) => (
                    <td key={column} className="px-4 py-2 text-right tabular-nums">
                      {number.format(queue[column])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </WideContent>
      )}
    </section>
  );
}

function FailedJobs() {
  const { t, i18n } = useTranslation(["admin", "common"]);
  const dates = new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" });
  const failed = useQuery({
    ...orpc.queue.listFailed.queryOptions({ input: { limit: FAILED_JOB_LIMIT } }),
    // Polls with its own inline state; a toast per failed poll would spam.
    refetchInterval: 30_000,
    meta: { skipGlobalErrorToast: true },
  });
  const description = failed.isPending
    ? t("admin:observability.loading")
    : failed.isError
      ? t("admin:observability.loadFailedShort")
      : failed.data.items.length >= FAILED_JOB_LIMIT
        ? t("admin:observability.maintenance.failedCountCapped", {
            count: failed.data.items.length,
          })
        : t("admin:observability.maintenance.failedCount", { count: failed.data.items.length });
  return (
    <section className="min-w-0 rounded-md border">
      <div className="flex flex-col gap-2 border-b px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">
            {t("admin:observability.maintenance.failedTitle")}
          </h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="min-h-[44px]"
          disabled={failed.isFetching}
          onClick={() => void failed.refetch()}
        >
          <RefreshCcw aria-hidden className="size-4" />
          {t("common:actions.refresh")}
        </Button>
      </div>
      {failed.isPending ? (
        <div className="space-y-2 p-4">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : failed.isError ? (
        <InlineRetry
          className="py-12"
          message={t("admin:observability.maintenance.failedLoadFailed")}
          onRetry={() => void failed.refetch()}
        />
      ) : failed.data.items.length === 0 ? (
        <div className="flex flex-col items-center gap-2 px-4 py-12 text-center">
          <CheckCircle2 aria-hidden className="size-8 text-muted-foreground" />
          <p className="text-sm font-medium">{t("admin:observability.maintenance.noneFailed")}</p>
          <p className="max-w-md text-sm text-muted-foreground">
            {t("admin:observability.maintenance.noneFailedDescription")}
          </p>
        </div>
      ) : (
        <ul className="divide-y">
          {failed.data.items.map((job) => {
            const at = new Date(job.finishedOn ?? job.timestamp);
            return (
              <li
                key={`${job.queue}:${job.id ?? job.timestamp}`}
                className="grid min-w-0 gap-2 px-4 py-3 md:grid-cols-[minmax(0,1fr)_auto]"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">
                    <QueueName name={job.queue} />
                  </p>
                  <p className="truncate font-mono text-xs text-muted-foreground">
                    {job.id ?? t("admin:observability.maintenance.noJobId")}
                  </p>
                </div>
                <div className="text-left text-xs text-muted-foreground md:text-right">
                  <p>
                    {t("admin:observability.maintenance.attempts", { count: job.attemptsMade })}
                  </p>
                  <time dateTime={at.toISOString()}>{dates.format(at)}</time>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
