import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Input } from "@wssp/ui/components/input";
import { useDebounce } from "@wssp/ui/hooks/use-async-search";
import { Plus } from "lucide-react";
import { useState } from "react";
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
import { SandboxQuickAction } from "@/components/sandboxes/sandbox-quick-action";
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
  sandboxNameFilter,
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

/** How long typing pauses before the name filter asks the server. */
const NAME_FILTER_DEBOUNCE_MS = 300;

export function SandboxesPage({
  lang,
  userId,
  status = "active",
  name,
  onSearchChange,
}: {
  lang: string;
  /** The signed-in user: whose getting-started checklist this is. */
  userId: string;
  /** From `?status=` (the route owns it, so Back restores the filter). */
  status?: SandboxStatusFilter;
  /** From `?name=`: a part of the sandbox name, already in the name alphabet. */
  name?: string;
  onSearchChange: (search: { status: SandboxStatusFilter; name?: string }) => void;
}) {
  const { t, i18n } = useTranslation(["sandboxes", "dashboard", "common"]);
  // What is typed shows at once; the server is asked once typing pauses.
  const [nameText, setNameText] = useState(name ?? "");
  // Back/Forward (or a link) can change `?name=` under a mounted page: follow
  // it, unless it is just what this input last wrote there.
  const [nameFromUrl, setNameFromUrl] = useState(name);
  const [nameWritten, setNameWritten] = useState(name);
  if (name !== nameFromUrl) {
    setNameFromUrl(name);
    if (name !== nameWritten) {
      setNameText(name ?? "");
      setNameWritten(name);
    }
  }
  const filter = sandboxNameFilter(nameText);
  const nameContains =
    useDebounce(filter.invalid ? "" : filter.value, NAME_FILTER_DEBOUNCE_MS) || undefined;
  const setName = (text: string) => {
    setNameText(text);
    const next = sandboxNameFilter(text);
    const written = next.invalid ? undefined : next.value || undefined;
    setNameWritten(written);
    onSearchChange({ status, name: written });
  };
  const query = useInfiniteQuery({
    ...orpc.sandboxes.list.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) => ({
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
        status,
        ...(nameContains ? { nameContains } : {}),
      }),
    }),
    // A name nobody can have matches nothing: no request.
    enabled: !filter.invalid,
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
      <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SegmentedControl
          value={status}
          onChange={(next) =>
            onSearchChange({
              status: next,
              name: filter.invalid ? undefined : filter.value || undefined,
            })
          }
          ariaLabel={t("sandboxes:filter.label")}
          items={[
            { value: "active", label: t("sandboxes:filter.active") },
            { value: "deleted", label: t("sandboxes:filter.deleted") },
            { value: "all", label: t("sandboxes:filter.all") },
          ]}
        />
        <div className="flex min-w-0 flex-col gap-1 sm:w-72">
          <Input
            type="search"
            inputMode="search"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            data-sandbox-name-filter=""
            aria-label={t("sandboxes:filter.name")}
            aria-invalid={filter.invalid || undefined}
            aria-describedby={filter.invalid ? "sandbox-name-filter-hint" : undefined}
            placeholder={t("sandboxes:filter.name")}
            maxLength={63}
            value={nameText}
            onChange={(event) => setName(event.target.value)}
            className="min-h-11"
          />
          {filter.invalid ? (
            <p id="sandbox-name-filter-hint" className="text-xs text-destructive">
              {t("sandboxes:filter.nameHint")}
            </p>
          ) : null}
        </div>
      </div>
      {filter.invalid ? (
        <NoNameMatch name={filter.value} onClear={() => setName("")} />
      ) : (
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
            nameContains ? (
              <NoNameMatch name={nameContains} onClear={() => setName("")} />
            ) : (
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
            )
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
      )}
    </section>
  );
}

/** No sandbox name contains the filter: say so and offer the way back. */
function NoNameMatch({ name, onClear }: { name: string; onClear: () => void }) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <div role="status" data-sandbox-no-match="">
      <EmptyState
        className="rounded-xl border px-4"
        title={translateText(t, "sandboxes:empty.noMatchTitle", { name })}
        description={t("sandboxes:empty.noMatchDescription")}
        action={
          <Button type="button" variant="outline" size="touch" className="mt-2" onClick={onClear}>
            {t("sandboxes:empty.clearFilter")}
          </Button>
        }
      />
    </div>
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
      className="flex min-w-0 flex-col rounded-xl border bg-card px-4 py-3 text-card-foreground"
    >
      {/* Dense by design (design review #13): one row of facts at desktop
          widths, two columns on a phone, the actions beside the name. */}
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
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
          <dl className="mt-2 grid min-w-0 grid-cols-2 gap-x-5 gap-y-1.5 text-xs text-muted-foreground lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1.3fr)_minmax(0,0.8fr)]">
            <div className="col-span-2 min-w-0 lg:col-span-1">
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
            <ul aria-label={t("sandboxes:fields.labels")} className="mt-2 flex flex-wrap gap-1">
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
          {/* Nothing for a finished request: the state already says it. */}
          <div className="mt-2 empty:hidden">
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
        <div className="flex min-w-0 shrink-0 flex-wrap items-start gap-2 sm:flex-nowrap">
          {sandbox.state === "DELETED" ? null : (
            <SandboxQuickAction sandbox={sandbox} lang={lang} />
          )}
          <Link
            to="/$lang/dashboard/sandboxes/$sandboxId"
            params={{ lang, sandboxId: sandbox.id }}
            aria-label={t("sandboxes:openLabel", { id: sandbox.id })}
            className={buttonVariants({ variant: "outline", size: "touch" })}
          >
            {t("sandboxes:open")}
          </Link>
        </div>
      </div>
    </li>
  );
}
