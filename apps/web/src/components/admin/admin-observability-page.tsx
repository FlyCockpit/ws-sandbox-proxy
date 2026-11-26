import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { AsyncCombobox } from "@wssp/ui/components/async-combobox";
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
import { Boxes, ListChecks, Server, Timer, Users, Webhook, X } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { CopyableId } from "@/components/copyable-id";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader, PageShell } from "@/components/page-shell";
import { SegmentedControl } from "@/components/segmented-control";
import { WideContent } from "@/components/wide-content";
import {
  formatAgeSeconds,
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
  // Display names of owners seen in rows or picked in the filter, so the
  // owner filter shows a person, not an id.
  const [ownerNames, setOwnerNames] = useState<Record<string, Owner>>({});
  const filterByOwner = (id: string, owner?: Owner) => {
    if (owner) setOwnerNames((known) => ({ ...known, [id]: owner }));
    apply({ owner: id });
  };

  return (
    <PageShell inFrame width="wide" className="min-w-0">
      <PageHeader
        title={t("admin:observability.title")}
        description={t("admin:observability.description")}
      />
      <Counters />
      <WebhookEndpoints onOwner={filterByOwner} />

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
          <Filters
            search={search}
            invalid={invalid}
            onSearch={apply}
            onType={type}
            owner={ownerNames[search.owner]}
            onOwner={filterByOwner}
          />
          {/* Keyed by the filter set: any filter change remounts the list and
              drops its cursor stack, so paging never mixes filter sets. */}
          <ObservabilityList
            key={observabilityFilterKey(effective)}
            search={effective}
            blocked={invalid.length > 0 || invalidObservabilityFilters(effective).length > 0}
            settling={settling}
            onSearch={apply}
            onOwner={filterByOwner}
          />
        </>
      )}
    </PageShell>
  );
}

/**
 * Counter tiles flow into as many columns as fit at 10rem or more each (two on
 * a phone, up to the section's tile count on a wide screen), so a label wraps
 * between words instead of being squeezed into a sixth of a narrow column.
 */
const COUNTER_GRID_CLASS = "grid grid-cols-[repeat(auto-fit,minmax(min(100%,10rem),1fr))] gap-3";

function Counters() {
  const { t, i18n } = useTranslation("admin");
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
      <section aria-label={t("observability.summary.ariaLabel")} className={COUNTER_GRID_CLASS}>
        <CounterTiles tiles={tiles} />
      </section>
      <section aria-label={t("observability.leases.ariaLabel")} className={COUNTER_GRID_CLASS}>
        <CounterTiles
          tiles={leaseTiles.map((tile) => ({ ...tile, icon: Timer }))}
          prefix="leases"
        />
      </section>
      <section aria-label={t("observability.webhooks.ariaLabel")} className={COUNTER_GRID_CLASS}>
        <CounterTiles
          tiles={[
            { key: "endpoints", value: counters.data?.webhooks.endpoints },
            { key: "enabled", value: counters.data?.webhooks.enabled },
            { key: "disabledForFailures", value: counters.data?.webhooks.disabledForFailures },
            { key: "pending24h", value: counters.data?.webhooks.deliveries24h.PENDING },
            { key: "failed24h", value: counters.data?.webhooks.deliveries24h.FAILED },
            {
              key: "oldestPending",
              value: counters.data === undefined ? undefined : 0,
              display:
                counters.data === undefined
                  ? undefined
                  : counters.data.webhooks.oldestPendingAgeSeconds === null
                    ? t("observability.webhooks.oldestPendingNone")
                    : formatAgeSeconds(
                        counters.data.webhooks.oldestPendingAgeSeconds,
                        i18n.language,
                      ),
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
function WebhookEndpoints({ onOwner }: { onOwner: (id: string, owner: Owner) => void }) {
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
              <OwnerCell ownerId={row.ownerId} owner={row.owner} onFilter={onOwner} />
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
  /** `display` replaces the formatted number (a duration, "None"). */
  tiles: readonly {
    key: string;
    icon: typeof Users;
    value: number | undefined;
    display?: string;
  }[];
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
            <p className="min-w-0 text-xs font-medium text-pretty [overflow-wrap:anywhere]">
              {t(`observability.${prefix}.${tile.key}`)}
            </p>
          </div>
          {tile.value === undefined ? (
            <Skeleton className="mt-2 h-8 w-16" />
          ) : (
            <p className="mt-2 text-2xl font-semibold tabular-nums" data-counter={tile.key}>
              {tile.display ?? number.format(tile.value)}
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
  name: Exclude<ObservabilityIdFilter, "owner">;
  value: string;
  invalid: boolean;
  onChange: (value: string) => void;
}) {
  const { t } = useTranslation("admin");
  const hintId = `${id}-hint`;
  const helpId = `${id}-help`;
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
        aria-describedby={invalid ? `${hintId} ${helpId}` : helpId}
        placeholder={t(`observability.filters.${name}Placeholder`)}
        onChange={(event) => onChange(event.target.value)}
        className="min-h-[44px] font-mono"
      />
      {invalid ? (
        <p id={hintId} className="text-xs text-destructive">
          {t("observability.filters.invalidId")}
        </p>
      ) : null}
      <p id={helpId} className="text-xs text-muted-foreground">
        {t("observability.filters.idHint")}
      </p>
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

type Owner = { name: string; email: string };
type UserChoice = Owner & { id: string };

/**
 * The owner filter: search users by name or email (the admin user list) and
 * pick one. The URL keeps the id; a known owner is shown by name.
 */
function OwnerFilter({
  ownerId,
  owner,
  invalid,
  onChange,
}: {
  ownerId: string;
  owner: Owner | undefined;
  invalid: boolean;
  onChange: (id: string, owner?: Owner) => void;
}) {
  const { t } = useTranslation("admin");
  const hintId = "observability-owner-hint";
  return (
    <div className="min-w-0 space-y-1">
      <p id="observability-owner-label" className="text-xs font-medium">
        {t("observability.filters.owner")}
      </p>
      {ownerId ? (
        <div
          data-owner-filter={ownerId}
          className="flex min-h-[44px] min-w-0 items-center gap-2 rounded-md border px-3"
        >
          <span
            className="min-w-0 flex-1 truncate text-sm"
            aria-invalid={invalid || undefined}
            aria-describedby={invalid ? hintId : undefined}
          >
            {owner
              ? `${owner.name} (${owner.email})`
              : t("observability.filters.ownerId", { id: ownerId })}
          </span>
          <Button
            type="button"
            variant="ghost"
            size="icon-touch"
            aria-label={t("observability.filters.ownerClear")}
            onClick={() => onChange("")}
          >
            <X aria-hidden="true" />
          </Button>
        </div>
      ) : (
        <AsyncCombobox<UserChoice>
          aria-labelledby="observability-owner-label"
          className="min-h-[44px]"
          placeholder={t("observability.filters.ownerPlaceholder")}
          searchPlaceholder={t("observability.filters.ownerSearch")}
          emptyText={t("observability.filters.ownerEmpty")}
          onSearch={async (query, signal) => {
            const page = await orpc.users.list.call(
              { limit: 8, search: query.trim() || undefined },
              { signal },
            );
            return page.users.map((user) => ({ id: user.id, name: user.name, email: user.email }));
          }}
          onSelect={(user) => onChange(user.id, { name: user.name, email: user.email })}
          getKey={(user) => user.id}
          getLabel={(user) => user.name || user.email}
          renderItem={(user) => (
            <span className="min-w-0">
              <span className="block truncate">{user.name}</span>
              <span className="block truncate text-xs text-muted-foreground">{user.email}</span>
            </span>
          )}
        />
      )}
      {invalid ? (
        <p id={hintId} className="text-xs text-destructive">
          {t("observability.filters.invalidId")}
        </p>
      ) : null}
    </div>
  );
}

/** Owner name (filters to them) and email, with the id in a copy chip. */
function OwnerCell({
  ownerId,
  owner,
  onFilter,
}: {
  ownerId: string;
  owner: Owner;
  onFilter: (id: string, owner: Owner) => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <div className="flex min-w-0 flex-col items-start">
      <button
        type="button"
        onClick={() => onFilter(ownerId, owner)}
        aria-label={t("observability.filterByOwner", { id: ownerId })}
        title={t("observability.filterByOwner", { id: ownerId })}
        className="inline-flex min-h-[44px] max-w-full items-center truncate rounded-sm text-left font-medium underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {owner.name || owner.email}
      </button>
      <span className="max-w-full truncate text-muted-foreground">{owner.email}</span>
      <CopyableId value={ownerId} label={t("observability.ids.owner")} />
    </div>
  );
}

/**
 * An opaque id in a copy chip, under its owner-chosen name when it has one,
 * plus an action that narrows the view to it.
 */
function IdCell({
  id,
  idLabel,
  name,
  action,
}: {
  id: string;
  idLabel: string;
  name?: string | null;
  action?: { text: string; label: string; onClick: () => void };
}) {
  return (
    <div className="flex min-w-0 flex-col items-start">
      {name ? (
        <span data-admin-name="" className="max-w-full truncate font-medium" title={name}>
          {name}
        </span>
      ) : null}
      <CopyableId value={id} label={idLabel} />
      {action ? (
        <button
          type="button"
          onClick={action.onClick}
          aria-label={action.label}
          title={action.label}
          className="inline-flex min-h-[44px] items-center rounded-sm text-xs font-medium underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {action.text}
        </button>
      ) : null}
    </div>
  );
}

function Filters({
  search,
  invalid,
  onSearch,
  onType,
  owner,
  onOwner,
}: {
  search: ObservabilitySearch;
  invalid: ObservabilityIdFilter[];
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onType: (name: ObservabilityIdFilter, value: string) => void;
  owner: Owner | undefined;
  onOwner: (id: string, owner?: Owner) => void;
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
        <OwnerFilter
          ownerId={search.owner}
          owner={owner}
          invalid={invalid.includes("owner")}
          onChange={onOwner}
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
  onOwner,
}: {
  search: ObservabilitySearch;
  blocked: boolean;
  settling: boolean;
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onOwner: (id: string, owner: Owner) => void;
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
    return <HostTable query={hosts} paging={paging} onSearch={onSearch} onOwner={onOwner} />;
  if (search.tab === "sandboxes")
    return <SandboxTable query={sandboxes} paging={paging} onSearch={onSearch} onOwner={onOwner} />;
  return (
    <OperationTable query={operations} paging={paging} onSearch={onSearch} onOwner={onOwner} />
  );
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
        // The same green as a ready host on the Hosts page.
        tone === "ok" &&
          "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
        tone === "warn" && "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
        tone === "bad" && "border-destructive/30 bg-destructive/10 text-destructive",
        tone === "muted" && "bg-muted text-muted-foreground",
      )}
    >
      {children}
    </span>
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
  onOwner,
}: {
  query: ListQuery<HostPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onOwner: (id: string, owner: Owner) => void;
}) {
  const { t } = useTranslation("admin");
  const formatDate = useDateFormatter();
  return (
    <DataShell title={t("observability.tables.hosts")} query={query} paging={paging} columns={6}>
      {(data) => (
        <table className="w-full min-w-[880px] text-left text-xs">
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
                  <IdCell
                    id={row.id}
                    idLabel={t("observability.ids.host")}
                    name={row.label}
                    action={{
                      text: t("observability.rowActions.sandboxes"),
                      label: t("observability.showHostSandboxes", { id: row.id }),
                      onClick: () =>
                        onSearch(switchObservabilityTab("sandboxes", { host: row.id })),
                    }}
                  />
                </td>
                <td className={TD}>
                  <OwnerCell ownerId={row.userId} owner={row.owner} onFilter={onOwner} />
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
                  {t("observability.capacityLive", { count: row.liveCount })} ·{" "}
                  {t("observability.capacityStopped", { count: row.rootCount })}
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
  onOwner,
}: {
  query: ListQuery<SandboxPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onOwner: (id: string, owner: Owner) => void;
}) {
  const { t } = useTranslation(["admin", "sandboxes"]);
  const formatDate = useDateFormatter();
  return (
    <DataShell
      title={t("admin:observability.tables.sandboxes")}
      query={query}
      paging={paging}
      columns={7}
    >
      {(data) => (
        <table className="w-full min-w-[880px] text-left text-xs">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th className={TH}>{t("admin:observability.columns.sandbox")}</th>
              <th className={TH}>{t("admin:observability.columns.owner")}</th>
              <th className={TH}>{t("admin:observability.columns.state")}</th>
              <th className={TH}>{t("admin:observability.columns.host")}</th>
              <th className={TH}>{t("admin:observability.columns.template")}</th>
              <th className={TH}>{t("admin:observability.columns.allocation")}</th>
              <th className={TH}>{t("admin:observability.columns.created")}</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {data.items.map((row) => (
              <tr key={row.id} data-row-id={row.id}>
                <td className={TD}>
                  <IdCell
                    id={row.id}
                    idLabel={t("admin:observability.ids.sandbox")}
                    name={row.name}
                    action={{
                      text: t("admin:observability.rowActions.operations"),
                      label: t("admin:observability.showSandboxOperations", { id: row.id }),
                      onClick: () =>
                        onSearch(switchObservabilityTab("operations", { sandbox: row.id })),
                    }}
                  />
                  <p className="text-muted-foreground tabular-nums">
                    {t("admin:observability.generation", { generation: row.generation })}
                  </p>
                </td>
                <td className={TD}>
                  <OwnerCell ownerId={row.userId} owner={row.owner} onFilter={onOwner} />
                </td>
                <td className={TD}>
                  <Pill tone={sandboxTone(row.state)}>{t(`sandboxes:state.${row.state}`)}</Pill>
                </td>
                <td className={TD}>
                  {row.sandboxHostId ? (
                    <IdCell
                      id={row.sandboxHostId}
                      idLabel={t("admin:observability.ids.host")}
                      name={row.hostLabel}
                      action={{
                        text: t("admin:observability.rowActions.filter"),
                        label: t("admin:observability.filterByHost", { id: row.sandboxHostId }),
                        onClick: () => onSearch({ host: row.sandboxHostId ?? "" }),
                      }}
                    />
                  ) : (
                    t("admin:observability.notAvailable")
                  )}
                </td>
                <td className={TD}>
                  <IdCell
                    id={row.templateId}
                    idLabel={t("admin:observability.ids.template")}
                    name={row.templateLabel}
                  />
                  <p className="text-muted-foreground">{t("admin:observability.revisionOf")}</p>
                  <IdCell
                    id={row.templateRevisionId}
                    idLabel={t("admin:observability.ids.revision")}
                  />
                </td>
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
  onOwner,
}: {
  query: ListQuery<OperationPage>;
  paging: Paging;
  onSearch: (patch: ObservabilitySearchPatch) => void;
  onOwner: (id: string, owner: Owner) => void;
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
        <table className="w-full min-w-[880px] text-left text-xs">
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
                <td className={TD}>
                  <IdCell id={row.id} idLabel={t("admin:observability.ids.operation")} />
                  <p className="text-muted-foreground tabular-nums">
                    {t("admin:observability.generation", { generation: row.generation })}
                  </p>
                </td>
                <td className={TD}>
                  <OwnerCell ownerId={row.userId} owner={row.owner} onFilter={onOwner} />
                </td>
                <td className={TD}>{t(`operations:kind.${row.kind}`)}</td>
                <td className={TD}>
                  <Pill tone={operationTone(row.state)}>{t(`operations:state.${row.state}`)}</Pill>
                </td>
                <td className={TD}>
                  {row.sandboxId ? (
                    <IdCell
                      id={row.sandboxId}
                      idLabel={t("admin:observability.ids.sandbox")}
                      name={row.sandboxName}
                      action={{
                        text: t("admin:observability.rowActions.filter"),
                        label: t("admin:observability.filterBySandbox", { id: row.sandboxId }),
                        onClick: () => onSearch({ sandbox: row.sandboxId ?? "" }),
                      }}
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
