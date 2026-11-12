import type { Prisma, SandboxLaunchMode, SandboxState } from "@wssp/db";

import { sandboxStateConflict } from "./errors";
import { ACTIVE_OPERATION_STATES } from "./state-transitions";

/**
 * Launch semantics live on the operation, never on the placement. `SandboxOperation.launchMode` is written once, at
 * acceptance, and never rewritten:
 *
 * - CREATE → `NEW_ROOT` (placement-materialize and the capacity queue);
 * - restore → `NEW_ROOT` with `restoreOffloadId` (C6b `acceptRestore`);
 * - a reconnect from `STOPPED` → `COLD`;
 * - a reconnect from `READY` → `WARM`.
 *
 * `SandboxPlacement.restoreOffloadId` is provenance only; nothing reads it
 * to classify an operation.
 */
export type LaunchModeOperation = {
  kind: string;
  launchMode: SandboxLaunchMode | null;
};

/** The mode a launch is accepted with. Restore admission stamps `NEW_ROOT`
 * itself (with `restoreOffloadId`); every other launch acceptance calls this.
 * Restore admission (`acceptRestore`) writes `launchMode: "NEW_ROOT"` and
 * `restoreOffloadId` on the RECONNECT it creates (CHECK
 * `sandbox_operation_launch_mode`) inside `operationTransaction`, which then
 * stores the hostless `restore-intent:v1` digest snapshot (digest-context.ts).
 * A reconnect from any other state is never accepted as a launch: an
 * `OFFLOADED` sandbox resumes only through restore admission. */
export function acceptedLaunchMode(kind: "CREATE_SANDBOX"): "NEW_ROOT";
export function acceptedLaunchMode(
  kind: "RECONNECT_SANDBOX",
  sandboxState: SandboxState,
): "COLD" | "WARM";
export function acceptedLaunchMode(
  kind: "CREATE_SANDBOX" | "RECONNECT_SANDBOX",
  sandboxState?: SandboxState,
): SandboxLaunchMode {
  if (kind === "CREATE_SANDBOX") return "NEW_ROOT";
  if (sandboxState === "STOPPED") return "COLD";
  if (sandboxState === "READY") return "WARM";
  throw sandboxStateConflict("Sandbox cannot be reconnected from this state.");
}

/** The immutable accepted mode, or null for a non-launch operation. */
export function launchModeOf(op: LaunchModeOperation): SandboxLaunchMode | null {
  return op.launchMode;
}

/** A restore attempt: a reconnect accepted with a new root. Only restore
 * admission writes that pair (CHECK `sandbox_operation_launch_mode`). */
export function isRestoreAttempt(op: LaunchModeOperation): boolean {
  return op.kind === "RECONNECT_SANDBOX" && op.launchMode === "NEW_ROOT";
}

export type RestoringSandbox = {
  id: string;
  userId: string;
  generation: number;
  diskOffloadId: string | null;
};

/** Pure form of `currentlyRestoring`: the offload pointer plus an active
 * restore attempt of the current generation. */
export function isCurrentlyRestoring(
  sandbox: Pick<RestoringSandbox, "generation" | "diskOffloadId">,
  operations: readonly (LaunchModeOperation & { generation: number; state: string })[],
): boolean {
  if (sandbox.diskOffloadId === null) return false;
  return operations.some(
    (op) =>
      isRestoreAttempt(op) &&
      op.generation === sandbox.generation &&
      (ACTIVE_OPERATION_STATES as ReadonlySet<string>).has(op.state),
  );
}

/**
 * The sandbox is restoring: it still points at its offload **and** an active
 * (non-terminal) `RECONNECT_SANDBOX` with `launchMode = NEW_ROOT` exists for
 * the current generation (§8.4). A restored sandbox that reached READY is
 * never "restoring" again, and its later warm or cold reconnects are WARM or
 * COLD. The owner-stop refusal `409 sandbox.restoring` (C6b) reads this.
 */
export async function currentlyRestoring(
  tx: Prisma.TransactionClient,
  sandbox: RestoringSandbox,
): Promise<boolean> {
  if (sandbox.diskOffloadId === null) return false;
  const attempt = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      kind: "RECONNECT_SANDBOX",
      launchMode: "NEW_ROOT",
      generation: sandbox.generation,
      state: { in: [...ACTIVE_OPERATION_STATES] },
    },
    select: { id: true },
  });
  return attempt !== null;
}

/**
 * The stored offload a launch boots from (offload plan U9.1), read only from
 * the operation row: a restore attempt with its immutable `restoreOffloadId`.
 * Dispatch gates and the frame derive "is a restore" from this, never from
 * the outbox payload. Null for every other operation.
 */
export function restoreOffloadOf(
  op: LaunchModeOperation & { restoreOffloadId: string | null },
): string | null {
  return isRestoreAttempt(op) ? op.restoreOffloadId : null;
}
