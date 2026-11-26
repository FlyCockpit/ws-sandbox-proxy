import {
  isOperationActive,
  isUnlimitedLeaseEnd,
  lifetimeOptions,
  type OperationState,
  type SandboxState,
} from "@/lib/sandbox-rules";

/**
 * Display rules for the sandbox detail header (design review #2, #7, #11):
 * what the page calls the sandbox's state while a lifecycle request is in
 * flight, the create's step progress, the lifetime summary and the renew
 * default. Pure: everything comes from the server's read; nothing is assumed.
 */

type LatestOperation = {
  kind: string;
  state: OperationState;
  createdAt: Date | string;
  completedAt?: Date | string | null;
  progressPhase?: string | null;
} | null;

/**
 * A state the page shows instead of the stored one while a request is moving
 * the sandbox: a start (cold reconnect) of a stopped sandbox is "Starting"
 * (an offloaded one "Restoring"), and a destroy in flight is "Destroying",
 * never the "Stopping" the server stores while it tears the VM down.
 */
export type SandboxDisplayOverride = "STARTING" | "RESTORING" | "DESTROYING";

export function sandboxDisplayOverride(sandbox: {
  state: SandboxState;
  lastLifecycleOperation: LatestOperation;
}): SandboxDisplayOverride | null {
  const latest = sandbox.lastLifecycleOperation;
  if (!latest || !isOperationActive(latest.state) || sandbox.state === "DELETED") return null;
  if (latest.kind === "KILL_SANDBOX") return "DESTROYING";
  if (latest.kind === "RECONNECT_SANDBOX") {
    if (sandbox.state === "STOPPED") return "STARTING";
    if (sandbox.state === "OFFLOADED") return "RESTORING";
  }
  return null;
}

export type ProvisionStep = "placed" | "creating" | "booting" | "ready";
export type StepStatus = "done" | "current" | "todo";

const STEPS: readonly ProvisionStep[] = ["placed", "creating", "booting", "ready"];

/**
 * Step progress of a create or start (Placed → Creating → Booting → Ready),
 * read from the sandbox state and its latest lifecycle request: QUEUED is
 * not placed yet, DISPATCHED/ACCEPTED (or an image phase) is creating, and
 * RUNNING or PROVISIONING is booting. Null when nothing is starting.
 */
export function provisionProgress(sandbox: {
  state: SandboxState;
  lastLifecycleOperation: LatestOperation;
}): { steps: { step: ProvisionStep; status: StepStatus }[]; sinceMs: number } | null {
  const latest = sandbox.lastLifecycleOperation;
  const starting =
    ["REQUESTED", "SCHEDULED", "PROVISIONING"].includes(sandbox.state) ||
    sandboxDisplayOverride(sandbox) === "STARTING" ||
    sandboxDisplayOverride(sandbox) === "RESTORING";
  if (!starting) return null;
  const startKind = latest?.kind === "CREATE_SANDBOX" || latest?.kind === "RECONNECT_SANDBOX";
  const opState = startKind && latest ? latest.state : null;
  const imagePhase =
    latest?.progressPhase != null && /image|disk/.test(latest.progressPhase) && opState !== null;
  let current: ProvisionStep;
  if (opState === "QUEUED" || (opState === null && sandbox.state === "REQUESTED"))
    current = "placed";
  else if (imagePhase || opState === "DISPATCHED" || opState === "ACCEPTED") current = "creating";
  else current = "booting";
  // A PROVISIONING sandbox has been placed and created, whatever the receipt says.
  if (sandbox.state === "PROVISIONING" && current !== "booting" && !imagePhase) current = "booting";
  const index = STEPS.indexOf(current);
  const since = latest && startKind ? new Date(latest.createdAt).getTime() : Number.NaN;
  return {
    steps: STEPS.map((step, i) => ({
      step,
      status: i < index ? "done" : i === index ? "current" : "todo",
    })),
    sinceMs: since,
  };
}

/**
 * When the running VM last became ready, if the latest lifecycle request says
 * so (a create or start that succeeded). Null otherwise: a renewal after the
 * start hides that moment from this read, and the page then shows no time.
 */
export function runningSinceMs(sandbox: {
  state: SandboxState;
  lastLifecycleOperation: LatestOperation;
}): number | null {
  const latest = sandbox.lastLifecycleOperation;
  if (sandbox.state !== "READY" || !latest || latest.state !== "SUCCEEDED") return null;
  if (latest.kind !== "CREATE_SANDBOX" && latest.kind !== "RECONNECT_SANDBOX") return null;
  if (latest.completedAt == null) return null;
  const at = new Date(latest.completedAt).getTime();
  return Number.isFinite(at) ? at : null;
}

/**
 * "3 hr 59 min", "2 days 4 hr", "45 sec": the largest unit and the one right
 * after it (omitted when zero), short and localized. Seconds only under a
 * minute, unless `seconds` asks for them (a ticking elapsed time).
 */
export function formatSpan(ms: number, locale: string, { seconds = false } = {}): string {
  const units = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
    ["second", 1000],
  ] as const;
  const total = Math.max(0, Math.floor(ms / 1000) * 1000);
  const allowed = units.filter(([unit]) => unit !== "second" || seconds || total < 60_000);
  const values = allowed.map(([unit, size], i) => {
    const above = i === 0 ? Number.POSITIVE_INFINITY : allowed[i - 1]![1];
    return [unit, Math.floor((total % above) / size)] as const;
  });
  const first = values.findIndex(([, value]) => value > 0);
  const start = first === -1 ? values.length - 1 : first;
  const shown = values.slice(start, start + 2).filter(([, value], i) => i === 0 || value > 0);
  return shown
    .map(([unit, value]) =>
      new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "short" }).format(value),
    )
    .join(" ");
}

/** "03:50" today, "Nov 26, 03:50" another day: the absolute moment a lifetime ends. */
export function formatClock(ms: number, locale: string, now: number, timeZone?: string): string {
  const at = new Date(ms);
  const sameDay =
    new Intl.DateTimeFormat("en-CA", { dateStyle: "short", timeZone }).format(at) ===
    new Intl.DateTimeFormat("en-CA", { dateStyle: "short", timeZone }).format(new Date(now));
  return new Intl.DateTimeFormat(locale, {
    ...(sameDay ? {} : { month: "short", day: "numeric" }),
    hour: "2-digit",
    minute: "2-digit",
    timeZone,
  }).format(at);
}

/** The finite deadline of the lease, or null for none / no time limit. */
export function finiteDeadline(expiresAt: Date | string | null | undefined): number | null {
  if (expiresAt == null) return null;
  const ms = new Date(expiresAt).getTime();
  if (!Number.isFinite(ms) || isUnlimitedLeaseEnd(ms)) return null;
  return ms;
}

/**
 * The Renew dialog's starting choice: never shorter than what is left, and
 * at least the lifetime the sandbox runs with (its remembered lease): the
 * smallest allowed preset at or above both, else the largest allowed one.
 * A sandbox with no time limit keeps "no time limit" where it is allowed.
 */
export function renewDefaultMinutes(input: {
  maxTimeoutMs: number;
  allowUnlimited: boolean;
  remainingMs: number | null;
  rememberedMs: number | null;
}): string {
  const options = lifetimeOptions(input.maxTimeoutMs, input.allowUnlimited);
  const finite = options.filter((minutes) => minutes > 0);
  if (input.remainingMs === null && input.allowUnlimited) return "0";
  const floor = Math.max(input.remainingMs ?? 0, input.rememberedMs ?? 0);
  const pick = finite.find((minutes) => minutes * 60_000 >= floor) ?? finite.at(-1);
  return String(pick ?? options[0] ?? 5);
}

/**
 * The renewal's new deadline if accepted now, and whether it shortens the
 * current one. `minutes` "0" is no time limit (never shorter).
 */
export function renewPreview(
  minutes: string,
  currentDeadline: number | null,
  now: number,
): { newDeadline: number | null; shortens: boolean } | null {
  if (minutes === "0") return { newDeadline: null, shortens: false };
  const value = Number(minutes);
  if (!Number.isInteger(value) || value < 1) return null;
  const newDeadline = now + value * 60_000;
  return {
    newDeadline,
    // No finite deadline today means no time limit: any finite one shortens it.
    shortens: currentDeadline === null ? true : newDeadline < currentDeadline,
  };
}
