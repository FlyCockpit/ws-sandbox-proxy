/**
 * Post-commit notification that a sandbox's terminal-relevant record changed
 * (state, generation, host placement or owner) — C53.
 *
 * Every control-plane sandbox write runs inside `sandboxOutboxTransaction`
 * (service and relay transactions alike), which observes the `sandbox`
 * delegate and calls `notifySandboxTerminalLifecycle` only after its commit.
 * The server binds the browser terminal service here; it re-reads each
 * affected binding (`checkTerminalBinding`) and closes terminals of a sandbox
 * that stopped, was destroyed, expired or was superseded. The signal carries
 * no authority, and a missed one only delays closure to the periodic re-read.
 */

/** Sandbox ids the commit touched, or "all" when a write was not keyed by id. */
export type SandboxTerminalLifecycleChange = { sandboxIds: ReadonlySet<string> } | "all";

type Listener = (change: SandboxTerminalLifecycleChange) => void;

let listener: Listener | null = null;

/** Server runtime binds the in-process terminal service (no-op until bound). */
export function bindSandboxTerminalLifecycle(next: Listener | null): void {
  listener = next;
}

export function notifySandboxTerminalLifecycle(change: SandboxTerminalLifecycleChange): void {
  try {
    listener?.(change);
  } catch {
    // The write has committed; the periodic terminal re-read still closes.
    console.error("[sandbox-terminal] lifecycle notification failed; periodic re-read pending");
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
