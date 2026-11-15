import {
  OPERATION_ERROR_CODES,
  OPERATION_KINDS,
  OPERATION_LIST_STATE_GROUPS,
  OPERATION_STATES,
} from "@wssp/api/sandbox/contracts";
import { CANCELLABLE_OPERATION_KINDS } from "@wssp/api/sandbox/state-transitions";

import type { OperationState } from "@/lib/sandbox-rules";

/**
 * Pure rules for the Operations dashboard (C48). The page shows what the
 * server reported: a cancel request never flips an operation to CANCELLED in
 * the browser (only the host's acknowledgement does, through the next read),
 * and which operations may be cancelled follows the server's own kind set
 * (imported, not copied). The server still decides every request.
 */

export type OperationKind = (typeof OPERATION_KINDS)[number];
export type { OperationState };
export { OPERATION_ERROR_CODES, OPERATION_KINDS, OPERATION_STATES };

/** How the page groups operation states (every state keeps its own label). */
export type OperationTone =
  | "pending"
  | "cancelling"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "unknown";

const TONE: Record<OperationState, OperationTone> = {
  QUEUED: "pending",
  DISPATCHED: "pending",
  ACCEPTED: "pending",
  RUNNING: "pending",
  CANCEL_REQUESTED: "cancelling",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
  CANCELLED: "cancelled",
  UNKNOWN_OUTCOME: "unknown",
};

export function operationTone(state: OperationState): OperationTone {
  return TONE[state];
}

/** Still in flight: the status is polled. CANCEL_REQUESTED waits for the host's acknowledgement. */
export function isOperationPending(state: OperationState): boolean {
  const tone = TONE[state];
  return tone === "pending" || tone === "cancelling";
}

/**
 * Offer Cancel only where the server would accept a new cancellation: an
 * ordinary guest operation (never a lifecycle action — those are superseded
 * by stop/destroy) that is still queued or running. Once CANCEL_REQUESTED,
 * the request is already on its way; a second click adds nothing.
 */
export function canCancelOperation(kind: OperationKind, state: OperationState): boolean {
  return (
    CANCELLABLE_OPERATION_KINDS.has(kind) &&
    (state === "QUEUED" || state === "DISPATCHED" || state === "ACCEPTED" || state === "RUNNING")
  );
}

/** What the server answered a cancel request with, as the page explains it. */
export type CancelAnswer = "pending" | "cancelled" | "finishedFirst" | "unknown";

export function cancelAnswer(state: OperationState): CancelAnswer {
  switch (state) {
    case "CANCELLED":
      return "cancelled";
    case "SUCCEEDED":
    case "FAILED":
      return "finishedFirst";
    case "UNKNOWN_OUTCOME":
      return "unknown";
    default:
      return "pending";
  }
}

// ── list filters (URL search params) ──

export type OperationStateFilter = (typeof OPERATION_LIST_STATE_GROUPS)[number] | OperationState;

export type OperationsSearch = {
  sandboxId?: string;
  state?: OperationStateFilter;
  kind?: OperationKind;
};

const STATE_FILTERS: ReadonlySet<string> = new Set([
  ...OPERATION_LIST_STATE_GROUPS,
  ...OPERATION_STATES,
]);
const KINDS: ReadonlySet<string> = new Set(OPERATION_KINDS);
/** Same bounds as the server's entity IDs (1–64 URL-safe characters). */
const SANDBOX_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The route's search contract. Anything unrecognized is dropped rather than
 * sent, so a hand-edited URL shows the unfiltered list instead of an error.
 */
export function parseOperationsSearch(search: Record<string, unknown>): OperationsSearch {
  const out: OperationsSearch = {};
  if (typeof search.sandboxId === "string" && SANDBOX_ID.test(search.sandboxId))
    out.sandboxId = search.sandboxId;
  if (typeof search.state === "string" && STATE_FILTERS.has(search.state))
    out.state = search.state as OperationStateFilter;
  if (typeof search.kind === "string" && KINDS.has(search.kind))
    out.kind = search.kind as OperationKind;
  return out;
}

/** The list input for a filter (unset filters are omitted, never sent empty). */
export function operationsListInput(search: OperationsSearch, limit: number, cursor?: string) {
  return {
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(search.sandboxId === undefined ? {} : { sandboxId: search.sandboxId }),
    ...(search.state === undefined ? {} : { state: search.state }),
    ...(search.kind === undefined ? {} : { kind: search.kind }),
  };
}

/** Whole seconds between two timestamps, or null when either is missing. */
export function durationMs(
  from: Date | string | null | undefined,
  to: Date | string | null | undefined,
): number | null {
  if (from == null || to == null) return null;
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  return Number.isFinite(start) && Number.isFinite(end) && end >= start ? end - start : null;
}

export function formatDuration(ms: number, locale: string): string {
  const seconds = ms / 1000;
  if (seconds < 60)
    return new Intl.NumberFormat(locale, {
      style: "unit",
      unit: "second",
      unitDisplay: "short",
      maximumFractionDigits: seconds < 10 ? 1 : 0,
    }).format(seconds);
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds - minutes * 60);
  const fmt = (value: number, unit: "minute" | "second") =>
    new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "short" }).format(value);
  return rest === 0 ? fmt(minutes, "minute") : `${fmt(minutes, "minute")} ${fmt(rest, "second")}`;
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

/** The server's typed `OUTPUT_EXPIRED` (410): content is gone, status stays readable. */
export function isOutputExpired(error: unknown): boolean {
  const shape = shapeOf(error);
  const data = shape.data;
  const code =
    data && typeof data === "object" && "code" in data ? (data as { code?: unknown }).code : null;
  return code === "OUTPUT_EXPIRED" || shape.status === 410 || shape.code === "GONE";
}

export type CancelProblem = "notFound" | "notCancellable" | "forbidden" | "generic";

export function cancelProblem(error: unknown): CancelProblem {
  const shape = shapeOf(error);
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "CONFLICT" || shape.status === 409) return "notCancellable";
  if (shape.code === "FORBIDDEN" || shape.status === 403) return "forbidden";
  return "generic";
}
