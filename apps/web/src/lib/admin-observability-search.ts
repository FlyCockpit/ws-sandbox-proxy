/**
 * Search-param contract for `/$lang/admin/observability`. Lives outside the
 * route file so it can be unit tested (route files must not export anything).
 *
 * Every filter is an exact metadata match the server validates too
 * (`adminObservability.*`). Id filters keep what the admin typed (trimmed,
 * bounded) so the field stays editable; an id the server would reject is
 * reported by {@link invalidObservabilityFilters} and the list is not queried,
 * rather than silently showing unfiltered rows. Unknown enum values fall back
 * to "all". The cursor is NOT part of the URL: pages are keyset cursors held
 * in component state and reset whenever the filter set changes.
 */

const OBSERVABILITY_TABS = ["hosts", "sandboxes", "operations", "maintenance"] as const;
export type ObservabilityTab = (typeof OBSERVABILITY_TABS)[number];

export const HOST_STATUSES = ["CONNECTED", "STALE", "DISCONNECTED", "REVOKED"] as const;
type HostStatusFilter = (typeof HOST_STATUSES)[number];

export const SANDBOX_STATES = [
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPING",
  "STOPPED",
  "RECLAIMING",
  "DELETED",
  "UNREACHABLE",
  "RECOVERED",
  "HOST_LOST",
  "ERROR",
  "WAITING_FOR_CAPACITY",
  "OFFLOADED",
] as const;
type SandboxStateFilter = (typeof SANDBOX_STATES)[number];

export const OPERATION_STATES = [
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
] as const;
type OperationStateFilter = (typeof OPERATION_STATES)[number];

/** Rows per page; the server caps pages at 100. */
const OBSERVABILITY_PAGE_SIZE = 25;

export type ObservabilitySearch = {
  tab: ObservabilityTab;
  /** Exact owner (user) id. */
  owner: string;
  hostStatus: "all" | HostStatusFilter;
  /** Exact host id (sandboxes tab). */
  host: string;
  sandboxState: "all" | SandboxStateFilter;
  /** Exact sandbox id (operations tab). */
  sandbox: string;
  operationState: "all" | OperationStateFilter;
};

export const DEFAULT_OBSERVABILITY_SEARCH: ObservabilitySearch = {
  tab: "hosts",
  owner: "",
  hostStatus: "all",
  host: "",
  sandboxState: "all",
  sandbox: "",
  operationState: "all",
};

/** Mirrors the server's `filterId` (entity id + URL-safe alphabet). */
const FILTER_ID = /^[A-Za-z0-9_-]{1,64}$/;

function isFilterId(value: string): boolean {
  return FILTER_ID.test(value);
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value);
}

/** Longest id text kept from the URL (the server's id bound). */
const MAX_ID_TEXT = 64;

function parseId(value: unknown): string {
  // TanStack Router JSON-parses search values, so a numeric-looking id can
  // arrive as a number.
  const text = typeof value === "number" ? String(value) : value;
  return typeof text === "string" ? text.trim().slice(0, MAX_ID_TEXT) : "";
}

export function parseObservabilitySearch(search: Record<string, unknown>): ObservabilitySearch {
  return {
    tab: isOneOf(search.tab, OBSERVABILITY_TABS) ? search.tab : DEFAULT_OBSERVABILITY_SEARCH.tab,
    owner: parseId(search.owner),
    hostStatus: isOneOf(search.hostStatus, HOST_STATUSES) ? search.hostStatus : "all",
    host: parseId(search.host),
    sandboxState: isOneOf(search.sandboxState, SANDBOX_STATES) ? search.sandboxState : "all",
    sandbox: parseId(search.sandbox),
    operationState: isOneOf(search.operationState, OPERATION_STATES)
      ? search.operationState
      : "all",
  };
}

/** Coerce a Select value into a known filter enum, falling back to `"all"`. */
export function parseFilterSelect<T extends string>(
  value: string,
  allowed: readonly T[],
): "all" | T {
  return isOneOf(value, allowed) ? value : "all";
}

export type ObservabilityIdFilter = "owner" | "host" | "sandbox";

/** Id filters of the active tab that are set but could never match a real id. */
export function invalidObservabilityFilters(search: ObservabilitySearch): ObservabilityIdFilter[] {
  const active: ObservabilityIdFilter[] =
    search.tab === "sandboxes"
      ? ["owner", "host"]
      : search.tab === "operations"
        ? ["owner", "sandbox"]
        : search.tab === "hosts"
          ? ["owner"]
          : [];
  return active.filter((key) => search[key] !== "" && !isFilterId(search[key]));
}

/**
 * Query inputs per list. Only filters that belong to the list are sent and
 * empty ids are omitted; callers must not query while
 * {@link invalidObservabilityFilters} reports anything (no partial matches).
 */
function baseInput(search: ObservabilitySearch, cursor: string | undefined) {
  return { limit: OBSERVABILITY_PAGE_SIZE, cursor, ownerId: search.owner || undefined };
}

export function hostListInput(search: ObservabilitySearch, cursor: string | undefined) {
  return {
    ...baseInput(search, cursor),
    status: search.hostStatus === "all" ? undefined : search.hostStatus,
  };
}

export function sandboxListInput(search: ObservabilitySearch, cursor: string | undefined) {
  return {
    ...baseInput(search, cursor),
    hostId: search.host || undefined,
    state: search.sandboxState === "all" ? undefined : search.sandboxState,
  };
}

export function operationListInput(search: ObservabilitySearch, cursor: string | undefined) {
  return {
    ...baseInput(search, cursor),
    sandboxId: search.sandbox || undefined,
    state: search.operationState === "all" ? undefined : search.operationState,
  };
}

/** A key that changes whenever the active tab's filter set changes (resets paging). */
export function observabilityFilterKey(search: ObservabilitySearch): string {
  const input =
    search.tab === "hosts"
      ? hostListInput(search, undefined)
      : search.tab === "sandboxes"
        ? sandboxListInput(search, undefined)
        : search.tab === "operations"
          ? operationListInput(search, undefined)
          : {};
  return JSON.stringify([search.tab, input]);
}

/**
 * Patch that switches to `tab` and resets every tab-specific filter to its
 * default (M7-S15), so e.g. `hostStatus=STALE` does not linger in the URL on
 * the Sandboxes tab. The owner filter is shared by all lists and is kept;
 * `extra` sets the new tab's own filters (clicking a host id opens Sandboxes
 * filtered to that host).
 */
export function switchObservabilityTab(
  tab: ObservabilityTab,
  extra: Partial<Omit<ObservabilitySearch, "tab" | "owner">> = {},
): Partial<ObservabilitySearch> {
  return {
    tab,
    hostStatus: DEFAULT_OBSERVABILITY_SEARCH.hostStatus,
    host: DEFAULT_OBSERVABILITY_SEARCH.host,
    sandboxState: DEFAULT_OBSERVABILITY_SEARCH.sandboxState,
    sandbox: DEFAULT_OBSERVABILITY_SEARCH.sandbox,
    operationState: DEFAULT_OBSERVABILITY_SEARCH.operationState,
    ...extra,
  };
}

/**
 * An age in seconds as one or two coarse units in the UI locale
 * ("45 sec", "12 min", "3 hr 5 min", "2 days 4 hr"), for "oldest pending".
 */
export function formatAgeSeconds(seconds: number, locale: string): string {
  const unit = (value: number, name: "second" | "minute" | "hour" | "day") =>
    new Intl.NumberFormat(locale, { style: "unit", unit: name, unitDisplay: "short" }).format(
      value,
    );
  const whole = Math.max(0, Math.floor(seconds));
  if (whole < 60) return unit(whole, "second");
  if (whole < 3_600) return unit(Math.floor(whole / 60), "minute");
  if (whole < 86_400) {
    const hours = Math.floor(whole / 3_600);
    const minutes = Math.floor((whole % 3_600) / 60);
    return minutes ? `${unit(hours, "hour")} ${unit(minutes, "minute")}` : unit(hours, "hour");
  }
  const days = Math.floor(whole / 86_400);
  const hours = Math.floor((whole % 86_400) / 3_600);
  return hours ? `${unit(days, "day")} ${unit(hours, "hour")}` : unit(days, "day");
}
