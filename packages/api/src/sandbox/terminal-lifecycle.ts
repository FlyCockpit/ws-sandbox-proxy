/**
 * Post-commit notification that a sandbox's terminal-relevant record changed
 * (state, generation, host placement or owner) — C53.
 *
 * Every control-plane sandbox write runs inside `sandboxOutboxTransaction`
 * (service and relay transactions alike), which observes the `sandbox`
 * delegate and calls `notifySandboxTerminalLifecycle` only after its commit.
 * Subscribers are additive: the browser terminal service and the CLI connect
 * manager each subscribe while they hold live attachments, re-read each
 * affected binding and close what stopped, was destroyed, expired or was
 * superseded. The signal carries no authority, and a missed one only delays
 * closure to the periodic re-read.
 */

/** Sandbox ids the commit touched, or "all" when a write was not keyed by id. */
export type SandboxTerminalLifecycleChange = { sandboxIds: ReadonlySet<string> } | "all";

type Listener = (change: SandboxTerminalLifecycleChange) => void;

const listeners = new Set<Listener>();

/**
 * Add one in-process listener; the returned function removes exactly that
 * subscription (idempotent) and leaves every other subscriber in place.
 */
export function subscribeSandboxTerminalLifecycle(listener: Listener): () => void {
  // A wrapper per call: subscribing the same function twice is two subscriptions.
  const entry: Listener = (change) => listener(change);
  listeners.add(entry);
  return () => {
    listeners.delete(entry);
  };
}

export function notifySandboxTerminalLifecycle(change: SandboxTerminalLifecycleChange): void {
  for (const listener of [...listeners]) {
    try {
      listener(change);
    } catch {
      // The write has committed; the periodic re-read still closes. One
      // failing subscriber never keeps the others from hearing the change.
      console.error("[sandbox-terminal] lifecycle notification failed; periodic re-read pending");
    }
  }
}

const TERMINAL_FIELDS = [
  "state",
  "generation",
  "sandboxHostId",
  "userId",
  "usagePoolId",
  "usageMemberId",
  "accessGraceUntil",
] as const;

/**
 * Whether a `sandbox` delegate write can end a terminal's authority, and which
 * ids it names. Unknown shapes are conservative ("all").
 */
export function sandboxTerminalWrite(
  method: string,
  args: unknown,
): SandboxTerminalLifecycleChange | null {
  if (method === "delete" || method === "deleteMany") return keyedIds(args);
  if (method !== "update" && method !== "updateMany" && method !== "upsert") return null;
  if (!isRecord(args)) return "all";
  const data = method === "upsert" ? args.update : args.data;
  if (!isRecord(data)) return "all";
  if (!TERMINAL_FIELDS.some((field) => field in data)) return null;
  return keyedIds(args);
}

function keyedIds(args: unknown): SandboxTerminalLifecycleChange {
  if (!isRecord(args) || !isRecord(args.where)) return "all";
  const id = args.where.id;
  if (typeof id === "string") return { sandboxIds: new Set([id]) };
  return "all";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}
