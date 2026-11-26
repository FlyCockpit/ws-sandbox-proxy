import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { OnboardingChecklist } from "@/components/sandboxes/onboarding-checklist";
import {
  CapacityWaitLine,
  DiskLocationBadge,
  HostText,
  ReceiptLine,
  type SandboxListItem,
  StatePill,
  TemplateText,
} from "@/components/sandboxes/sandbox-parts";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useStatusClock } from "@/hooks/use-status-clock";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { dateTimeTitle } from "@/lib/format-date-time";
import { hostConnectionState, nextHostStateChangeAt } from "@/lib/host-status";
import {
  isOperationActive,
  isTransitional,
  isUnlimitedLeaseEnd,
  type SandboxStatusFilter,
  sandboxHostView,
  sandboxLabels,
  sandboxPhase,
  sandboxTitle,
} from "@/lib/sandbox-rules";
import { sandboxDisplayOverride } from "@/lib/sandbox-status";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Sandboxes list (C47). Rows are exactly what the server last reported:
 * state, host (with its live connection state), template revision, labels,
 * lifetime and the latest lifecycle receipt. Nothing here moves a sandbox
 * forward on its own; the list polls quickly only while some sandbox or
 * receipt is still in flight.
 */

/** Poll cadence while something is in flight, and otherwise. */
export const SANDBOX_BUSY_REFETCH_MS = 3_000;
export const SANDBOX_IDLE_REFETCH_MS = 15_000;

export function isSandboxBusy(sandbox: {
  state: SandboxListItem["state"];
  lastLifecycleOperation: SandboxListItem["lastLifecycleOperation"];
}): boolean {
  return (
    isTransitional(sandbox.state) ||
    (sandbox.lastLifecycleOperation != null &&
      isOperationActive(sandbox.lastLifecycleOperation.state))
  );
}

export function SandboxesPage({
  lang,
  userId,
  status = "active",
  onStatusChange,
}: {
  lang: string;
  /** The signed-in user: whose getting-started checklist this is. */
  userId: string;
  /** From `?status=` (the route owns it, so Back restores the filter). */
  status?: SandboxStatusFilter;
  onStatusChange: (status: SandboxStatusFilter) => void;
}) {
  const { t, i18n } = useTranslation(["sandboxes", "dashboard", "common"]);
  const query = useInfiniteQuery({
    ...orpc.sandboxes.list.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor, status }),
    }),
    refetchInterval: (current) =>
      current.state.data?.pages.some((page) => page.items.some(isSandboxBusy))
        ? SANDBOX_BUSY_REFETCH_MS
        : SANDBOX_IDLE_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const sandboxes = query.data?.pages.flatMap((page) => page.items);
  const now = useStatusClock(query.dataUpdatedAt);
  useRerenderAt(
    nextHostStateChangeAt(
      (sandboxes ?? []).flatMap((sandbox) => (sandbox.host ? [sandbox.host] : [])),
      now,
    ),
  );

  return (
    <section className="flex min-w-0 max-w-full flex-col gap-6">
      <PageHeader
        title={t("sandboxes:title")}
        description={t("sandboxes:description")}
        actions={
          <Link
            to="/$lang/dashboard/sandboxes/new"
            params={{ lang }}
            className={buttonVariants({ size: "touch" })}
          >
            <Plus aria-hidden="true" className="size-4" />
            {t("sandboxes:create.action")}
          </Link>
        }
      />
      {/* The signed-in home's getting-started checklist: above the filter,
          whatever it shows, until its steps are done or it is hidden. */}
      <OnboardingChecklist
        lang={lang}
        scope={userId}
        hasSandboxRows={sandboxes ? sandboxes.length > 0 : undefined}
      />
      <SegmentedControl
        value={status}
        onChange={onStatusChange}
        ariaLabel={t("sandboxes:filter.label")}
        items={[
          { value: "active", label: t("sandboxes:filter.active") },
          { value: "deleted", label: t("sandboxes:filter.deleted") },
          { value: "all", label: t("sandboxes:filter.all") },
        ]}
      />
      <QueryBoundary
        query={{
          data: sandboxes,
          isPending: query.isPending,
          isError: query.isError,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t(
              status === "deleted"
                ? "sandboxes:empty.deletedTitle"
                : status === "active"
                  ? "sandboxes:empty.activeTitle"
                  : "sandboxes:empty.title",
            )}
            description={t(
              status === "deleted"
                ? "sandboxes:empty.deletedDescription"
                : status === "active"
                  ? "sandboxes:empty.activeDescription"
                  : "sandboxes:empty.description",
            )}
          />
        }
      >
        {(rows) => (
          <>
            <ul aria-label={t("sandboxes:listRegion")} className="flex min-w-0 flex-col gap-3">
              {rows.map((sandbox) => (
                <SandboxRow
                  key={sandbox.id}
                  sandbox={sandbox}
                  lang={lang}
                  locale={i18n.language}
                  now={now}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
    </section>
  );
}

function SandboxRow({
  sandbox,
  lang,
  locale,
  now,
}: {
  sandbox: SandboxListItem;
  lang: string;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["sandboxes", "hosts"]);
  const labels = sandboxLabels(sandbox.metadata);
  const deadline = sandbox.leaseExpiresAt ? new Date(sandbox.leaseExpiresAt).getTime() : null;
  const stopped = sandboxPhase(sandbox.state) === "stopped";
  const offline = sandbox.state !== "DELETED" && sandboxHostView(sandbox.host, now) === "offline";
  return (
    <li
      data-sandbox-id={sandbox.id}
      data-sandbox-state={sandbox.state}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
            <h3 data-sandbox-name="" className="min-w-0 truncate font-mono text-sm font-medium">
              {sandboxTitle(sandbox)}
            </h3>
            <StatePill state={sandbox.state} display={sandboxDisplayOverride(sandbox)} />
            {/* Only a stored disk is worth a badge in the list (disk offload). */}
            {sandbox.disk && sandbox.disk.location !== "host" ? (
              <DiskLocationBadge disk={sandbox.disk} />
            ) : null}
          </div>
          {sandbox.capacityWait ? (
            <CapacityWaitLine wait={sandbox.capacityWait} lang={lang} />
          ) : null}
          <dl className="mt-3 grid min-w-0 gap-x-5 gap-y-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-4">
            <div className="min-w-0">
              <dt>{t("sandboxes:fields.host")}</dt>
              <dd data-sandbox-host="" className="break-words font-medium text-foreground">
                <HostText
                  host={sandbox.host}
                  now={now}
                  waiting={sandbox.state === "WAITING_FOR_CAPACITY"}
                />
              </dd>
            </div>
            <div className="min-w-0">
              <dt>{t("sandboxes:fields.template")}</dt>
              <dd data-sandbox-template="" className="break-words font-medium text-foreground">
                <TemplateText template={sandbox.template} />
              </dd>
            </div>
            <div className="min-w-0">
              <dt>{t("sandboxes:fields.allocation")}</dt>
              <dd data-sandbox-allocation="" className="font-medium text-foreground tabular-nums">
                {t("sandboxes:allocation", {
                  cpuCount: sandbox.cpuCount,
                  memoryMiB: sandbox.memoryMiB,
                  diskGiB: sandbox.diskGiB,
                })}
              </dd>
            </div>
            <div className="min-w-0">
              <dt>{t("sandboxes:fields.expires")}</dt>
              <dd
                data-sandbox-lifetime=""
                className="font-medium text-foreground"
                title={
                  stopped ||
                  sandbox.state === "DELETED" ||
                  deadline == null ||
                  sandbox.leasePendingReady ||
                  isUnlimitedLeaseEnd(deadline)
                    ? undefined
                    : dateTimeTitle(deadline, locale)
                }
              >
                {/* A stopped VM has no running lifetime (as on its detail page):
                    its next Start arms a new one. */}
                {stopped
                  ? t("sandboxes:lifetime.stopped")
                  : sandbox.state === "DELETED" || deadline == null
                    ? "—"
                    : sandbox.leasePendingReady
                      ? t("sandboxes:lifetime.startsAtReady")
                      : isUnlimitedLeaseEnd(deadline)
                        ? t("sandboxes:expiry.unlimited")
                        : t("sandboxes:expiry.at", {
                            when: formatRelativeTime(deadline, locale, now),
                            action: t(
                              `sandboxes:expiry.action.${sandbox.leaseExpireAction === "DESTROY" ? "destroy" : "stop"}`,
                            ),
                          })}
              </dd>
            </div>
            <div className="min-w-0">
              <dt>{t("sandboxes:fields.created")}</dt>
              <dd
                className="font-medium text-foreground"
                title={dateTimeTitle(sandbox.createdAt, locale)}
              >
                {formatRelativeTime(new Date(sandbox.createdAt).getTime(), locale, now)}
              </dd>
            </div>
          </dl>
          {labels.length > 0 ? (
            <ul aria-label={t("sandboxes:fields.labels")} className="mt-3 flex flex-wrap gap-1">
              {labels.map(([key, value]) => (
                <li
                  key={key}
                  className="max-w-full truncate rounded border bg-muted/50 px-1.5 py-0.5 font-mono text-xs"
                >
                  {key}={value}
                </li>
              ))}
            </ul>
          ) : null}
          <div className="mt-3">
            <ReceiptLine
              receipt={sandbox.lastLifecycleOperation}
              locale={locale}
              now={now}
              compact
            />
          </div>
          {offline && sandbox.host ? (
            <p data-host-offline="" className="mt-2 text-xs text-amber-700 dark:text-amber-400">
              {translateText(t, "sandboxes:hostOffline", {
                host: sandbox.host.label,
                state: t(`hosts:status.${hostConnectionState(sandbox.host, now)}`),
              })}
            </p>
          ) : null}
        </div>
        <Link
          to="/$lang/dashboard/sandboxes/$sandboxId"
          params={{ lang, sandboxId: sandbox.id }}
          aria-label={t("sandboxes:openLabel", { id: sandbox.id })}
          className={buttonVariants({ variant: "outline", size: "touch" })}
        >
          {t("sandboxes:open")}
        </Link>
      </div>
    </li>
  );
}
