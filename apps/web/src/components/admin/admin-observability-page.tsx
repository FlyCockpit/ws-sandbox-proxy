import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { Button } from "@wssp/ui/components/button";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@wssp/ui/components/select";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { useDebounce } from "@wssp/ui/hooks/use-async-search";
import { cn } from "@wssp/ui/lib/utils";
import { Boxes, ListChecks, Server, Timer, Users, Webhook } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader, PageShell } from "@/components/page-shell";
import { SegmentedControl } from "@/components/segmented-control";
import { WideContent } from "@/components/wide-content";
import {
  HOST_STATUSES,
  hostListInput,
  invalidObservabilityFilters,
  type ObservabilityIdFilter,
  type ObservabilitySearch,
  type ObservabilityTab,
  OPERATION_STATES,
  observabilityFilterKey,
  operationListInput,
  parseFilterSelect,
  SANDBOX_STATES,
  sandboxListInput,
  switchObservabilityTab,
} from "@/lib/admin-observability-search";
import { formatDateTime } from "@/lib/format-date-time";
import { orpc } from "@/utils/orpc";

import { MaintenanceStatus } from "./maintenance-status";

type HostPage = Awaited<ReturnType<AppRouterClient["adminObservability"]["listHosts"]>>;
type SandboxPage = Awaited<ReturnType<AppRouterClient["adminObservability"]["listSandboxes"]>>;
type OperationPage = Awaited<ReturnType<AppRouterClient["adminObservability"]["listOperations"]>>;

export type ObservabilitySearchPatch = Partial<ObservabilitySearch>;

/**
 * Cross-owner metadata observability: counters, hosts, sandboxes and
 * operations (ids, states, timestamps, capacity), plus maintenance status.
 * Metadata only by contract (`adminObservability`): no commands, output,
 * files, credentials or payloads ever reach this page. Filters live in the URL;
 * pages are keyset cursors kept in component state.
 */
export function AdminObservabilityPage({
  search,
  onSearch,
}: {
  search: ObservabilitySearch;
  /** Filter edits replace history; they always reset paging. */
  onSearch: (patch: ObservabilitySearchPatch) => void;
}) {
  const { t } = useTranslation(["admin", "common"]);
  // An id typed into a filter updates the URL on every keystroke but reaches
  // the server only after a pause. Everything else — tabs, selects, clicking
  // an id in a row, clearing — applies at once, so a click never fires an
  // unfiltered request first.
  const [typing, setTyping] = useState<ObservabilityIdFilter | null>(null);
  const debounced = {
    owner: useDebounce(search.owner, 300),
    host: useDebounce(search.host, 300),
    sandbox: useDebounce(search.sandbox, 300),
  };
  const effective: ObservabilitySearch = typing
    ? { ...search, [typing]: debounced[typing] }
    : search;
  const invalid = invalidObservabilityFilters(search);
  const settling = typing !== null && debounced[typing] !== search[typing];
  const apply = (patch: ObservabilitySearchPatch) => {
    setTyping(null);
    onSearch(patch);
  };
  const type = (name: ObservabilityIdFilter, value: string) => {
    setTyping(name);
    onSearch({ [name]: value });
  };

  return (
    <PageShell width="wide" className="min-w-0">
      <PageHeader
        title={t("admin:observability.title")}
        description={t("admin:observability.description")}
      />
      <Counters />
      <WebhookEndpoints />

      <SegmentedControl
        value={search.tab}
        onChange={(tab: ObservabilityTab) => apply(switchObservabilityTab(tab))}
        ariaLabel={t("admin:observability.tabsAriaLabel")}
        items={[
          { value: "hosts", label: t("admin:observability.tabs.hosts") },
          { value: "sandboxes", label: t("admin:observability.tabs.sandboxes") },
          { value: "operations", label: t("admin:observability.tabs.operations") },
          { value: "maintenance", label: t("admin:observability.tabs.maintenance") },
        ]}
      />

      {search.tab === "maintenance" ? (
        <MaintenanceStatus />
      ) : (
        <>
          <Filters search={search} invalid={invalid} onSearch={apply} onType={type} />
          {/* Keyed by the filter set: any filter change remounts the list and
              drops its cursor stack, so paging never mixes filter sets. */}
          <ObservabilityList
            key={observabilityFilterKey(effective)}
            search={effective}
            blocked={invalid.length > 0 || invalidObservabilityFilters(effective).length > 0}
            settling={settling}
            onSearch={apply}
          />
        </>
      )}
    </PageShell>
  );
}

function Counters() {
  const { t } = useTranslation("admin");
  const counters = useQuery({
    ...orpc.adminObservability.counters.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  if (counters.isError) {
    return (
      <InlineRetry
        variant="destructive"
        message={t("observability.summaryLoadFailed")}
        onRetry={() => void counters.refetch()}
      />
    );
  }
  const tiles = [
    { key: "users", icon: Users, value: counters.data?.users },
    { key: "hosts", icon: Server, value: counters.data?.hosts },
    { key: "sandboxes", icon: Boxes, value: counters.data?.sandboxes },
    { key: "operations", icon: ListChecks, value: counters.data?.operations },
  ] as const;
  const leases = counters.data?.leases;
  const leaseTiles = [
    { key: "expiredPending", value: leases?.expiredPending },
    { key: "unacknowledgedRenewals", value: leases?.unacknowledgedRenewals },
    { key: "hostEnforced", value: leases?.hostEnforced },
    { key: "quarantinedHosts", value: leases?.quarantinedHosts },
    { key: "relayOutbox", value: leases?.relayOutbox },
  ] as const;
  return (
    <>
      <section
        aria-label={t("observability.summary.ariaLabel")}
        className="grid grid-cols-2 gap-3 md:grid-cols-4"
      >
        <CounterTiles tiles={tiles} />
      </section>
      <section
        aria-label={t("observability.leases.ariaLabel")}
        className="grid grid-cols-2 gap-3 md:grid-cols-5"
      >
        <CounterTiles
          tiles={leaseTiles.map((tile) => ({ ...tile, icon: Timer }))}
          prefix="leases"
        />
      </section>
      <section
        aria-label={t("observability.webhooks.ariaLabel")}
        className="grid grid-cols-2 gap-3 md:grid-cols-6"
      >
        <CounterTiles
          tiles={[
            { key: "endpoints", value: counters.data?.webhooks.endpoints },
            { key: "enabled", value: counters.data?.webhooks.enabled },
            { key: "disabledForFailures", value: counters.data?.webhooks.disabledForFailures },
            { key: "pending24h", value: counters.data?.webhooks.deliveries24h.PENDING },
            { key: "failed24h", value: counters.data?.webhooks.deliveries24h.FAILED },
            {
              key: "oldestPendingSeconds",
              value:
                counters.data === undefined
                  ? undefined
                  : (counters.data.webhooks.oldestPendingAgeSeconds ?? 0),
            },
          ].map((tile) => ({ ...tile, icon: Webhook }))}
          prefix="webhooks"
        />
      </section>
    </>
  );
}

/**
 * Webhook endpoints across owners: metadata only (id, owner, destination HOST,
 * state, failure health). No path, query, secret, body, excerpt or address.
 * Admins get no test, redeliver or edit actions.
 */
function WebhookEndpoints() {
  const { t, i18n } = useTranslation("admin");
  const endpoints = useInfiniteQuery({
    ...orpc.adminObservability.listWebhookEndpoints.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: 20, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const rows = endpoints.data?.pages.flatMap((page) => page.items) ?? [];
  if (endpoints.isError)
    return (
      <InlineRetry
        variant="destructive"
        message={t("observability.webhooks.loadFailed")}
        onRetry={() => void endpoints.refetch()}
      />
    );
  return (
    <section aria-label={t("observability.webhooks.listLabel")} className="min-w-0 space-y-2">
      <h2 className="text-sm font-medium">{t("observability.webhooks.listLabel")}</h2>
      {endpoints.isPending ? (
        <Skeleton className="h-10 w-full" />
      ) : rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("observability.webhooks.empty")}</p>
      ) : (
        <ul className="min-w-0 divide-y rounded-md border text-sm">
          {rows.map((row) => (
            <li
              key={row.id}
              data-webhook-endpoint={row.id}
              className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 p-3"
            >
              <span className="break-all font-medium">{row.host}</span>
              <span className="font-mono text-xs text-muted-foreground">{row.ownerId}</span>
              <span>{t(`observability.webhooks.state.${row.state}`)}</span>
              <span className="text-muted-foreground">
                {t("observability.webhooks.failures", {
                  count: row.consecutiveFailures,
                  formatted: new Intl.NumberFormat(i18n.language).format(row.consecutiveFailures),
                })}
              </span>
            </li>
          ))}
        </ul>
      )}
      <LoadMore
        hasNextPage={endpoints.hasNextPage}
        isFetchingNextPage={endpoints.isFetchingNextPage}
        onLoadMore={() => void endpoints.fetchNextPage()}
      />
    </section>
  );
}

function CounterTiles({
  tiles,
  prefix = "summary",
}: {
  tiles: readonly { key: string; icon: typeof Users; value: number | undefined }[];
  prefix?: "summary" | "leases" | "webhooks";
}) {
  const { t, i18n } = useTranslation("admin");
  const number = new Intl.NumberFormat(i18n.language);
  return (
    <>
      {tiles.map((tile) => (
        <div key={tile.key} className="min-w-0 rounded-md border p-4">
          <div className="flex items-center gap-2 text-muted-foreground">
            <tile.icon aria-hidden className="size-4 shrink-0" />
            <p className="truncate text-xs font-medium">
              {t(`observability.${prefix}.${tile.key}`)}
            </p>
          </div>
          {tile.value === undefined ? (
            <Skeleton className="mt-2 h-8 w-16" />
          ) : (
            <p className="mt-2 text-2xl font-semibold tabular-nums" data-counter={tile.key}>
              {number.format(tile.value)}
            </p>
          )}
        </div>
      ))}
    </>
  );
}

function IdFilter({
  id,
  name,
  value,
  invalid,
  onChange,
}: {
  id: string;
  name: ObservabilityIdFilter;
  value: string;
  invalid: boolean;
  onChange: (value: string) => void;
}) {
  const { t } = useTranslation("admin");
  const hintId = `${id}-hint`;
  return (
    <div className="min-w-0 space-y-1">
      <Label htmlFor={id} className="text-xs">
        {t(`observability.filters.${name}`)}
      </Label>
      <Input
        id={id}
        type="search"
        inputMode="text"
        autoComplete="off"
        spellCheck={false}
        maxLength={64}
        value={value}
        aria-invalid={invalid || undefined}
        aria-describedby={invalid ? hintId : undefined}
        placeholder={t(`observability.filters.${name}Placeholder`)}
        onChange={(event) => onChange(event.target.value)}
        className="min-h-[44px] font-mono"
      />
      {invalid ? (
        <p id={hintId} className="text-xs text-destructive">
          {t("observability.filters.invalidId")}
        </p>
      ) : null}
    </div>
  );
}

function SelectFilter({
  id,
  label,
  value,
  onChange,
  options,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Every value with its translated label; the trigger shows the label (M7-S15). */
  options: readonly { value: string; label: string }[];
}) {
  return (
    <div className="min-w-0 space-y-1">
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <Select
        value={value}
        items={options}
        onValueChange={(next) => {
          if (typeof next === "string") onChange(next);
        }}
      >
        <SelectTrigger id={id} className="min-h-[44px] w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function Filters({
  search,
  invalid,
  onSearch,
  onType,
}: {
  search: ObservabilitySearch;
  invalid: ObservabilityIdFilter[];
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onType: (name: ObservabilityIdFilter, value: string) => void;
}) {
  const { t } = useTranslation(["admin", "operations", "sandboxes"]);
  const hasFilters =
    search.owner !== "" ||
    (search.tab === "hosts" && search.hostStatus !== "all") ||
    (search.tab === "sandboxes" && (search.host !== "" || search.sandboxState !== "all")) ||
    (search.tab === "operations" && (search.sandbox !== "" || search.operationState !== "all"));
  return (
    <div className="rounded-md border p-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[repeat(3,minmax(0,1fr))_auto] lg:items-start">
        <IdFilter
          id="observability-owner"
          name="owner"
          value={search.owner}
          invalid={invalid.includes("owner")}
          onChange={(value) => onType("owner", value)}
        />
        {search.tab === "hosts" ? (
          <SelectFilter
            id="observability-host-status"
            label={t("admin:observability.filters.hostStatus")}
            value={search.hostStatus}
            onChange={(value) => onSearch({ hostStatus: parseFilterSelect(value, HOST_STATUSES) })}
            options={[
              { value: "all", label: t("admin:observability.filters.allStatuses") },
              ...HOST_STATUSES.map((status) => ({
                value: status,
                label: t(`admin:observability.hostStatus.${status}`),
              })),
            ]}
          />
        ) : null}
        {search.tab === "sandboxes" ? (
          <>
            <IdFilter
              id="observability-host"
              name="host"
              value={search.host}
              invalid={invalid.includes("host")}
              onChange={(value) => onType("host", value)}
            />
            <SelectFilter
              id="observability-sandbox-state"
              label={t("admin:observability.filters.sandboxState")}
              value={search.sandboxState}
              onChange={(value) =>
                onSearch({ sandboxState: parseFilterSelect(value, SANDBOX_STATES) })
              }
              options={[
                { value: "all", label: t("admin:observability.filters.allStates") },
                ...SANDBOX_STATES.map((state) => ({
                  value: state,
                  label: t(`sandboxes:state.${state}`),
                })),
              ]}
            />
          </>
        ) : null}
        {search.tab === "operations" ? (
          <>
            <IdFilter
              id="observability-sandbox"
              name="sandbox"
              value={search.sandbox}
              invalid={invalid.includes("sandbox")}
              onChange={(value) => onType("sandbox", value)}
            />
            <SelectFilter
              id="observability-operation-state"
              label={t("admin:observability.filters.operationState")}
              value={search.operationState}
              onChange={(value) =>
                onSearch({ operationState: parseFilterSelect(value, OPERATION_STATES) })
              }
              options={[
                { value: "all", label: t("admin:observability.filters.allStates") },
                ...OPERATION_STATES.map((state) => ({
                  value: state,
                  label: t(`operations:state.${state}`),
                })),
              ]}
            />
          </>
        ) : null}
        {hasFilters ? (
          <Button
            type="button"
            variant="ghost"
            className="min-h-[44px] self-end"
            onClick={() =>
              onSearch({
                owner: "",
                hostStatus: "all",
                host: "",
                sandboxState: "all",
                sandbox: "",
                operationState: "all",
              })
            }
          >
            {t("admin:observability.filters.clear")}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

type ListQuery<T> = {
  data: T | undefined;
  isPending: boolean;
  isError: boolean;
  isFetching: boolean;
  refetch: () => unknown;
};

function ObservabilityList({
  search,
  blocked,
  settling,
  onSearch,
}: {
  search: ObservabilitySearch;
  blocked: boolean;
  settling: boolean;
  onSearch: (patch: ObservabilitySearchPatch) => void;
}) {
  // Cursor stack for keyset paging: [] is page 1; each Next pushes the page's
  // nextCursor, Previous pops. The parent remounts this list on filter change.
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const meta = { skipGlobalErrorToast: true };
  const hosts = useQuery({
    ...orpc.adminObservability.listHosts.queryOptions({ input: hostListInput(search, cursor) }),
    meta,
    enabled: !blocked && search.tab === "hosts",
  });
  const sandboxes = useQuery({
    ...orpc.adminObservability.listSandboxes.queryOptions({
      input: sandboxListInput(search, cursor),
    }),
    meta,
    enabled: !blocked && search.tab === "sandboxes",
  });
  const operations = useQuery({
    ...orpc.adminObservability.listOperations.queryOptions({
      input: operationListInput(search, cursor),
    }),
    meta,
    enabled: !blocked && search.tab === "operations",
  });
  const paging = {
    page: cursors.length + 1,
    onPrevious: () => setCursors((stack) => stack.slice(0, -1)),
    onNext: (next: string) => setCursors((stack) => [...stack, next]),
  };

  if (blocked) return settling ? null : <InvalidFilterNotice />;
  if (search.tab === "hosts")
    return <HostTable query={hosts} paging={paging} onSearch={onSearch} />;
  if (search.tab === "sandboxes")
    return <SandboxTable query={sandboxes} paging={paging} onSearch={onSearch} />;
  return <OperationTable query={operations} paging={paging} onSearch={onSearch} />;
}

function InvalidFilterNotice() {
  const { t } = useTranslation("admin");
  return (
    <p className="rounded-md border px-4 py-12 text-center text-sm text-muted-foreground">
      {t("observability.filters.fixToSearch")}
    </p>
  );
}

type Paging = { page: number; onPrevious: () => void; onNext: (cursor: string) => void };

function DataShell<T extends { items: unknown[]; nextCursor: string | null }>({
  title,
  query,
  paging,
  columns,
  children,
}: {
  title: string;
  query: ListQuery<T>;
  paging: Paging;
  columns: number;
  children: (data: T) => ReactNode;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const data = query.data;
  const nextCursor = data?.nextCursor ?? null;
  return (
    <section className="min-w-0 rounded-md border" aria-busy={query.isFetching || undefined}>
      <div className="flex flex-col gap-2 border-b px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground">
            {query.isPending
              ? t("admin:observability.loading")
              : query.isError
                ? t("admin:observability.loadFailedShort")
                : t("admin:observability.rowsOnPage", { count: data?.items.length ?? 0 })}
          </p>
        </div>
        <nav
          aria-label={t("admin:observability.paginationAriaLabel")}
          className="flex items-center gap-2"
        >
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="min-h-[44px]"
            disabled={query.isFetching || paging.page <= 1}
            onClick={paging.onPrevious}
          >
            {t("admin:observability.previous")}
          </Button>
          <span className="min-w-16 text-center text-xs tabular-nums text-muted-foreground">
            {t("admin:observability.pageLabel", { page: paging.page })}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="min-h-[44px]"
            disabled={query.isFetching || nextCursor === null}
            onClick={() => {
              if (nextCursor) paging.onNext(nextCursor);
            }}
          >
            {t("admin:observability.next")}
          </Button>
        </nav>
      </div>
      {query.isPending ? (
        <TableSkeleton columns={columns} />
      ) : query.isError || !data ? (
        <InlineRetry
          className="py-12"
          message={t("admin:observability.loadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : data.items.length === 0 ? (
        <p className="px-4 py-12 text-center text-sm text-muted-foreground">
          {t("admin:observability.empty")}
        </p>
      ) : (
        <WideContent>{children(data)}</WideContent>
      )}
    </section>
  );
}

function TableSkeleton({ columns }: { columns: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: 6 }).map((_, row) => (
        <div
          key={row}
          className="grid gap-3"
          style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: columns }).map((__, column) => (
            <Skeleton key={column} className="h-8 w-full rounded-sm" />
          ))}
        </div>
      ))}
    </div>
  );
}

function useDateFormatter() {
  const { i18n, t } = useTranslation("admin");
  return (value: Date | string | null | undefined) =>
    value ? formatDateTime(value, i18n.language) : t("observability.notAvailable");
}

function Pill({ tone, children }: { tone: "ok" | "warn" | "muted" | "bad"; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex min-h-6 items-center rounded-sm border px-2 text-xs font-medium",
        tone === "ok" && "border-primary/20 bg-primary/10 text-primary",
        tone === "warn" && "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
        tone === "bad" && "border-destructive/30 bg-destructive/10 text-destructive",
        tone === "muted" && "bg-muted text-muted-foreground",
      )}
    >
      {children}
    </span>
  );
}

/** An id that narrows the view to it: owner → this tab, host → sandboxes, sandbox → operations. */
function IdLink({ label, id, onClick }: { label: string; id: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="inline-flex min-h-[44px] max-w-full items-center truncate rounded-sm font-mono text-xs underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {id}
    </button>
  );
}

const TH = "px-4 py-2 font-medium";
const TD = "px-4 py-2 align-top";

function hostTone(status: string): "ok" | "warn" | "muted" | "bad" {
  if (status === "CONNECTED") return "ok";
  if (status === "REVOKED") return "bad";
  return "warn";
}

function HostTable({
  query,
  paging,
  onSearch,
}: {
  query: ListQuery<HostPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
}) {
  const { t } = useTranslation("admin");
  const formatDate = useDateFormatter();
  return (
    <DataShell title={t("observability.tables.hosts")} query={query} paging={paging} columns={6}>
      {(data) => (
        <table className="w-full min-w-[920px] text-left text-xs">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th className={TH}>{t("observability.columns.host")}</th>
              <th className={TH}>{t("observability.columns.owner")}</th>
              <th className={TH}>{t("observability.columns.status")}</th>
              <th className={TH}>{t("observability.columns.heartbeat")}</th>
              <th className={TH}>{t("observability.columns.capacity")}</th>
              <th className={TH}>{t("observability.columns.created")}</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {data.items.map((row) => (
              <tr key={row.id} data-row-id={row.id}>
                <td className={TD}>
                  <IdLink
                    id={row.id}
                    label={t("observability.showHostSandboxes", { id: row.id })}
                    onClick={() => onSearch(switchObservabilityTab("sandboxes", { host: row.id }))}
                  />
                </td>
                <td className={TD}>
                  <IdLink
                    id={row.userId}
                    label={t("observability.filterByOwner", { id: row.userId })}
                    onClick={() => onSearch({ owner: row.userId })}
                  />
                </td>
                <td className={TD}>
                  <div className="flex flex-wrap gap-1">
                    <Pill tone={hostTone(row.status)}>
                      {t(`observability.hostStatus.${row.status}`)}
                    </Pill>
                    {row.draining ? <Pill tone="warn">{t("observability.draining")}</Pill> : null}
                    {row.quarantinedAt ? (
                      <Pill tone="bad">{t("observability.quarantined")}</Pill>
                    ) : null}
                  </div>
                </td>
                <td className={`${TD} tabular-nums`}>{formatDate(row.lastHeartbeatAt)}</td>
                <td className={`${TD} tabular-nums`}>
                  {t("observability.capacity", {
                    live: row.liveCount,
                    roots: row.rootCount,
                  })}
                  <p data-admin-host-memory="">
                    {t("observability.memoryReserved", { value: row.memoryReservedMiB })}
                  </p>
                  <p>
                    {row.daemonMemoryBudgetMiB === null
                      ? t("observability.budgetNotReported")
                      : t("observability.memoryBudget", { value: row.daemonMemoryBudgetMiB })}
                  </p>
                  <p data-admin-host-vcpu="">
                    {row.daemonVcpuBudget === null
                      ? t("observability.vcpuNotReported")
                      : t("observability.vcpuBudget", {
                          reserved: row.vcpuReserved,
                          budget: row.daemonVcpuBudget,
                        })}
                  </p>
                  <p>
                    {row.daemonMaxCpuCount === null
                      ? t("observability.cpuNotReported")
                      : t("observability.cpuCap", { value: row.daemonMaxCpuCount })}
                  </p>
                </td>
                <td className={`${TD} tabular-nums`}>{formatDate(row.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DataShell>
  );
}

function sandboxTone(state: string): "ok" | "warn" | "muted" | "bad" {
  if (state === "READY") return "ok";
  if (state === "DELETED" || state === "STOPPED") return "muted";
  if (state === "ERROR" || state === "HOST_LOST") return "bad";
  return "warn";
}

function SandboxTable({
  query,
  paging,
  onSearch,
}: {
  query: ListQuery<SandboxPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
}) {
  const { t } = useTranslation(["admin", "sandboxes"]);
  const formatDate = useDateFormatter();
  return (
    <DataShell
      title={t("admin:observability.tables.sandboxes")}
      query={query}
      paging={paging}
      columns={8}
    >
      {(data) => (
        <table className="w-full min-w-[980px] text-left text-xs">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th className={TH}>{t("admin:observability.columns.sandbox")}</th>
              <th className={TH}>{t("admin:observability.columns.owner")}</th>
              <th className={TH}>{t("admin:observability.columns.state")}</th>
              <th className={TH}>{t("admin:observability.columns.host")}</th>
              <th className={TH}>{t("admin:observability.columns.template")}</th>
              <th className={TH}>{t("admin:observability.columns.templateRevision")}</th>
              <th className={TH}>{t("admin:observability.columns.allocation")}</th>
              <th className={TH}>{t("admin:observability.columns.created")}</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {data.items.map((row) => (
              <tr key={row.id} data-row-id={row.id}>
                <td className={TD}>
                  <IdLink
                    id={row.id}
                    label={t("admin:observability.showSandboxOperations", { id: row.id })}
                    onClick={() =>
                      onSearch(switchObservabilityTab("operations", { sandbox: row.id }))
                    }
                  />
                  <p className="text-muted-foreground tabular-nums">
                    {t("admin:observability.generation", { generation: row.generation })}
                  </p>
                </td>
                <td className={TD}>
                  <IdLink
                    id={row.userId}
                    label={t("admin:observability.filterByOwner", { id: row.userId })}
                    onClick={() => onSearch({ owner: row.userId })}
                  />
                </td>
                <td className={TD}>
                  <Pill tone={sandboxTone(row.state)}>{t(`sandboxes:state.${row.state}`)}</Pill>
                </td>
                <td className={TD}>
                  {row.sandboxHostId ? (
                    <IdLink
                      id={row.sandboxHostId}
                      label={t("admin:observability.filterByHost", { id: row.sandboxHostId })}
                      onClick={() => onSearch({ host: row.sandboxHostId ?? "" })}
                    />
                  ) : (
                    t("admin:observability.notAvailable")
                  )}
                </td>
                <td className={`${TD} font-mono`}>{row.templateId}</td>
                <td className={`${TD} font-mono`}>{row.templateRevisionId}</td>
                <td data-admin-allocation="" className={`${TD} tabular-nums`}>
                  {t("admin:observability.allocation", {
                    cpuCount: row.cpuCount,
                    memoryMiB: row.memoryMiB,
                    diskGiB: row.diskGiB,
                  })}
                </td>
                <td className={`${TD} tabular-nums`}>{formatDate(row.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DataShell>
  );
}

function operationTone(state: string): "ok" | "warn" | "muted" | "bad" {
  if (state === "SUCCEEDED") return "ok";
  if (state === "FAILED" || state === "UNKNOWN_OUTCOME") return "bad";
  if (state === "CANCELLED") return "muted";
  return "warn";
}

function OperationTable({
  query,
  paging,
  onSearch,
}: {
  query: ListQuery<OperationPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
}) {
  const { t } = useTranslation(["admin", "operations"]);
  const formatDate = useDateFormatter();
  return (
    <DataShell
      title={t("admin:observability.tables.operations")}
      query={query}
      paging={paging}
      columns={6}
    >
      {(data) => (
        <table className="w-full min-w-[980px] text-left text-xs">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th className={TH}>{t("admin:observability.columns.operation")}</th>
              <th className={TH}>{t("admin:observability.columns.owner")}</th>
              <th className={TH}>{t("admin:observability.columns.kind")}</th>
              <th className={TH}>{t("admin:observability.columns.state")}</th>
              <th className={TH}>{t("admin:observability.columns.sandbox")}</th>
              <th className={TH}>{t("admin:observability.columns.updated")}</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {data.items.map((row) => (
              <tr key={row.id} data-row-id={row.id}>
                <td className={`${TD} font-mono`}>
                  {row.id}
                  <p className="font-sans text-muted-foreground tabular-nums">
                    {t("admin:observability.generation", { generation: row.generation })}
                  </p>
                </td>
                <td className={TD}>
                  <IdLink
                    id={row.userId}
                    label={t("admin:observability.filterByOwner", { id: row.userId })}
                    onClick={() => onSearch({ owner: row.userId })}
                  />
                </td>
                <td className={TD}>{t(`operations:kind.${row.kind}`)}</td>
                <td className={TD}>
                  <Pill tone={operationTone(row.state)}>{t(`operations:state.${row.state}`)}</Pill>
                </td>
                <td className={TD}>
                  {row.sandboxId ? (
                    <IdLink
                      id={row.sandboxId}
                      label={t("admin:observability.filterBySandbox", { id: row.sandboxId })}
                      onClick={() => onSearch({ sandbox: row.sandboxId ?? "" })}
                    />
                  ) : (
                    t("admin:observability.notAvailable")
                  )}
                </td>
                <td className={`${TD} tabular-nums`}>{formatDate(row.updatedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DataShell>
  );
}
