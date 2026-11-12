import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { X } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import {
  type OperationListItem,
  OperationResultText,
  OperationStatePill,
} from "@/components/operations/operation-parts";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { WideContent } from "@/components/wide-content";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  durationMs,
  formatDuration,
  isOperationPending,
  OPERATION_KINDS,
  OPERATION_STATES,
  type OperationKind,
  type OperationStateFilter,
  type OperationsSearch,
  operationsListInput,
} from "@/lib/operation-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Operations list (C48): the owner's operations, newest first, filtered by
 * sandbox, status and type (kept in the URL, so Back returns to the same
 * view). A row is status metadata only — type, state, sandbox, exit code or
 * typed error, timing — never the command, its environment, file paths or
 * output; those are only on an operation's own page. The list polls quickly
 * only while a shown operation is still in flight, and it renders at most
 * {@link OPERATIONS_MAX_ROWS} rows: past that it asks for a narrower filter
 * instead of growing without bound (every loaded page is refetched on poll).
 */

const OPERATIONS_BUSY_REFETCH_MS = 3_000;
const OPERATIONS_IDLE_REFETCH_MS = 15_000;
/** Loaded pages × page size never exceeds this. */
const OPERATIONS_MAX_PAGES = 5;
export const OPERATIONS_MAX_ROWS = OPERATIONS_MAX_PAGES * DASHBOARD_PAGE_LIMIT;

const STATE_GROUPS = ["active", "settled"] as const;

export function OperationsPage({
  lang,
  search,
  onSearchChange,
}: {
  lang: string;
  search: OperationsSearch;
  onSearchChange: (next: OperationsSearch) => void;
}) {
  const { t, i18n } = useTranslation(["operations", "dashboard", "common"]);
  const stateId = useId();
  const kindId = useId();
  const query = useInfiniteQuery({
    ...orpc.sandboxes.listOperations.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) =>
        operationsListInput(search, DASHBOARD_PAGE_LIMIT, cursor),
    }),
    refetchInterval: (current) =>
      current.state.data?.pages.some((page) =>
        page.items.some((item) => isOperationPending(item.state)),
      )
        ? OPERATIONS_BUSY_REFETCH_MS
        : OPERATIONS_IDLE_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const rows = query.data?.pages.flatMap((page) => page.items);
  const atCap = (query.data?.pages.length ?? 0) >= OPERATIONS_MAX_PAGES;
  const filtered =
    search.sandboxId !== undefined || search.state !== undefined || search.kind !== undefined;
  const now = Date.now();

  return (
    <section className="flex min-w-0 max-w-full flex-col gap-6">
      <PageHeader title={t("operations:title")} description={t("operations:description")} />
      <div
        role="group"
        aria-label={t("operations:filter.label")}
        className="flex min-w-0 flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end"
      >
        <div className="flex min-w-0 flex-col gap-1 sm:w-56">
          <Label htmlFor={stateId}>{t("operations:filter.state")}</Label>
          <FormSelect
            id={stateId}
            value={search.state ?? ""}
            onValueChange={(value) =>
              onSearchChange({
                ...search,
                state: (value || undefined) as OperationStateFilter | undefined,
              })
            }
          >
            <SelectItem value="">{t("operations:filter.allStates")}</SelectItem>
            {STATE_GROUPS.map((group) => (
              <SelectItem key={group} value={group}>
                {t(`operations:filter.${group}`)}
              </SelectItem>
            ))}
            {OPERATION_STATES.map((state) => (
              <SelectItem key={state} value={state}>
                {t(`operations:state.${state}`)}
              </SelectItem>
            ))}
          </FormSelect>
        </div>
        <div className="flex min-w-0 flex-col gap-1 sm:w-56">
          <Label htmlFor={kindId}>{t("operations:filter.kind")}</Label>
          <FormSelect
            id={kindId}
            value={search.kind ?? ""}
            onValueChange={(value) =>
              onSearchChange({
                ...search,
                kind: (value || undefined) as OperationKind | undefined,
              })
            }
          >
            <SelectItem value="">{t("operations:filter.allKinds")}</SelectItem>
            {OPERATION_KINDS.map((kind) => (
              <SelectItem key={kind} value={kind}>
                {t(`operations:kind.${kind}`)}
              </SelectItem>
            ))}
          </FormSelect>
        </div>
        {search.sandboxId !== undefined ? (
          <div className="flex min-w-0 items-center gap-2">
            <span
              data-sandbox-filter={search.sandboxId}
              className="min-w-0 truncate rounded border bg-muted/50 px-2 py-1 font-mono text-xs"
            >
              {t("operations:filter.sandbox", { id: search.sandboxId })}
            </span>
            <Button
              type="button"
              variant="outline"
              size="touch"
              onClick={() => onSearchChange({ ...search, sandboxId: undefined })}
            >
              <X aria-hidden="true" className="size-4" />
              {t("operations:filter.clearSandbox")}
            </Button>
          </div>
        ) : null}
      </div>
      <QueryBoundary
        query={{
          data: rows,
          isPending: query.isPending,
          isError: query.isError,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t(filtered ? "operations:empty.filteredTitle" : "operations:empty.title")}
            description={t(
              filtered ? "operations:empty.filteredDescription" : "operations:empty.description",
            )}
            action={
              filtered ? undefined : (
                <Link
                  to="/$lang/dashboard/sandboxes"
                  params={{ lang }}
                  className={buttonVariants({ variant: "outline", size: "touch" })}
                >
                  {t("operations:empty.action")}
                </Link>
              )
            }
          />
        }
      >
        {(items) => (
          <>
            <WideContent className="rounded-xl border">
              <table
                aria-label={t("operations:listRegion")}
                className="w-full min-w-[760px] text-left text-xs"
              >
                <thead className="border-b text-muted-foreground">
                  <tr>
                    <th className="p-3 font-medium">{t("operations:columns.created")}</th>
                    <th className="p-3 font-medium">{t("operations:columns.kind")}</th>
                    <th className="p-3 font-medium">{t("operations:columns.state")}</th>
                    <th className="p-3 font-medium">{t("operations:columns.sandbox")}</th>
                    <th className="p-3 font-medium">{t("operations:columns.result")}</th>
                    <th className="p-3 font-medium">{t("operations:columns.duration")}</th>
                    <th className="p-3 text-right font-medium">
                      <span className="sr-only">{t("operations:columns.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {items.map((item) => (
                    <OperationRow
                      key={item.id}
                      item={item}
                      lang={lang}
                      locale={i18n.language}
                      now={now}
                    />
                  ))}
                </tbody>
              </table>
            </WideContent>
            {atCap && query.hasNextPage ? (
              <p data-row-cap="" role="status" className="text-sm text-muted-foreground">
                {t("operations:rowCap", { count: OPERATIONS_MAX_ROWS })}
              </p>
            ) : (
              <LoadMore
                hasNextPage={query.hasNextPage}
                isFetchingNextPage={query.isFetchingNextPage}
                onLoadMore={() => void query.fetchNextPage()}
              />
            )}
          </>
        )}
      </QueryBoundary>
    </section>
  );
}

function OperationRow({
  item,
  lang,
  locale,
  now,
}: {
  item: OperationListItem;
  lang: string;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["operations"]);
  const created = new Date(item.createdAt).getTime();
  const took = durationMs(item.dispatchedAt ?? item.createdAt, item.completedAt);
  return (
    // Every cell is vertically centred: the sandbox and Open links are 44 px
    // touch targets, so top-aligned text cells sat higher than them (M7-S7).
    <tr data-operation-id={item.id} data-operation-state={item.state}>
      <td className="p-3 align-middle tabular-nums" title={new Date(item.createdAt).toISOString()}>
        {formatRelativeTime(created, locale, now)}
      </td>
      <td className="p-3 align-middle font-medium">{t(`operations:kind.${item.kind}`)}</td>
      <td className="p-3 align-middle">
        <OperationStatePill state={item.state} />
      </td>
      <td className="p-3 align-middle">
        <Link
          to="/$lang/dashboard/sandboxes/$sandboxId"
          params={{ lang, sandboxId: item.sandboxId }}
          className="inline-flex min-h-11 items-center font-mono underline-offset-4 hover:underline"
        >
          {item.sandboxName}
        </Link>
        {item.sandboxState === "DELETED" ? (
          <span data-sandbox-deleted="" className="block text-muted-foreground">
            {t("operations:sandboxDeleted")}
          </span>
        ) : null}
      </td>
      <td className="p-3 align-middle">
        <OperationResultText exitCode={item.exitCode} errorCode={item.errorCode} />
      </td>
      <td className="p-3 align-middle tabular-nums">
        {took === null ? "—" : formatDuration(took, locale)}
      </td>
      <td className="p-3 text-right align-middle">
        <Link
          to="/$lang/dashboard/operations/$operationId"
          params={{ lang, operationId: item.id }}
          aria-label={t("operations:openLabel", { id: item.id })}
          className={buttonVariants({ variant: "outline", size: "touch" })}
        >
          {t("operations:open")}
        </Link>
      </td>
    </tr>
  );
}
