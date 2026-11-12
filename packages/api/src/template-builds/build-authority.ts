/**
 * What a build principal may do.
 * A leaf module: no imports beyond types and the error class, so the managed-
 * sandbox guard and the auth core can share one table without an import cycle.
 *
 * - step: spend-bearing work. The build must be active and in a state that
 *   allows the action; the owner's credential policy, guest access / host
 *   usability and (for a keyed build) the accepting key with `templates:build`
 *   and its allowlists are re-checked every time.
 * - cleanup: stop and kill of the build's own VM. Key-free, so it still works
 *   after revocation, a ban or account-deletion blocking. There is no
 *   `operations.cancel` in any class: builds end steps by killing the VM.
 * - read: metadata and step outputs of the build's own VM.
 * Anything else is refused.
 */
import { ORPCError } from "@orpc/server";
import type { TemplateBuildState } from "@wssp/db";
import type { ServiceAction, ServiceScope } from "../lib/service-scopes";

/** The single SDK scope that authorizes every build step (checked at
 * acceptance and again per step on the accepting key). */
export const TEMPLATE_BUILD_SCOPE: ServiceScope = "templates:build";

export type BuildActionClass = "step" | "cleanup" | "read";

/** Build states in which a step may run, per action. Never CANCELLING or
 * terminal; a recorded `cancelRequestedAt` refuses every step as well. */
const STEP_STATES: Readonly<Partial<Record<ServiceAction, readonly TemplateBuildState[]>>> = {
  "sandboxes.createIntent": ["QUEUED", "PLACING"],
  "sandboxes.create": ["QUEUED", "PLACING"],
  "commands.run": ["RUNNING"],
  "files.write": ["RUNNING"],
  "sandboxes.setTimeout": ["PLACING", "RUNNING", "STOPPING", "CAPTURING"],
  "sandboxes.capture": ["STOPPING", "CAPTURING"],
};

/**
 * A community build's verify VM (community-base I4b): only its create and the
 * smoke command, only while the build is CAPTURING with its capture
 * FINALIZED for the current attempt and `verifyRequired`. Never files, a
 * capture, a lease change, a reconnect, signals or a terminal.
 */
const VERIFY_STEP_STATES: Readonly<Partial<Record<ServiceAction, readonly TemplateBuildState[]>>> =
  {
    "sandboxes.createIntent": ["CAPTURING"],
    "sandboxes.create": ["CAPTURING"],
    "commands.run": ["CAPTURING"],
  };

/** Which VM of its build a build principal acts on (derived, never asserted). */
export type BuildRole = "build" | "verify";

const CLEANUP_ACTIONS: ReadonlySet<ServiceAction> = new Set(["sandboxes.stop", "sandboxes.kill"]);

const READ_ACTIONS: ReadonlySet<ServiceAction> = new Set([
  "sandboxes.get",
  "sandboxes.replayCreate",
  "operations.get",
  "operations.getReceipt",
  "operations.getCommandResult",
  "operations.getCommandOutput",
  "operations.getFileMutationResult",
]);

/** Build states with live authority (dispatch-time step check). */
export const BUILD_ACTIVE_STATES: ReadonlySet<TemplateBuildState> = new Set([
  "AWAITING_CONTEXT",
  "QUEUED",
  "PLACING",
  "RUNNING",
  "STOPPING",
  "CAPTURING",
]);

/** The class of `action` for a build principal; null refuses it. A receipt
 * replay (`retainedReplay`) never starts new work, so it is a read. */
export function buildActionClass(
  action: ServiceAction,
  retainedReplay = false,
): BuildActionClass | null {
  if (CLEANUP_ACTIONS.has(action)) return "cleanup";
  if (READ_ACTIONS.has(action)) return "read";
  if (STEP_STATES[action] || VERIFY_STEP_STATES[action]) return retainedReplay ? "read" : "step";
  return null;
}

/** Every action some class admits (the managed-sandbox guard's build set). */
export const BUILD_ACTIONS: ReadonlySet<ServiceAction> = new Set([
  ...(Object.keys(STEP_STATES) as ServiceAction[]),
  ...CLEANUP_ACTIONS,
  ...READ_ACTIONS,
]);

/** The verify VM's managed-policy set (review4 U3): its steps plus the
 * key-free cleanup (`vkill`) and the reads (create replay, outputs). */
export const VERIFY_ACTIONS: ReadonlySet<ServiceAction> = new Set([
  ...(Object.keys(VERIFY_STEP_STATES) as ServiceAction[]),
  ...CLEANUP_ACTIONS,
  ...READ_ACTIONS,
]);

export type BuildStepFacts = {
  state: TemplateBuildState;
  cancelRequestedAt: Date | null;
  /** Community verify facts (both false for every user build). */
  verifyRequired?: boolean;
  captureFinalized?: boolean;
};

/** May a step of `role` run now? The two roles' state sets are disjoint. */
export function buildStepAllowed(
  action: ServiceAction,
  build: BuildStepFacts,
  role: BuildRole = "build",
): boolean {
  if (build.cancelRequestedAt !== null || !BUILD_ACTIVE_STATES.has(build.state)) return false;
  if (role === "build") return (STEP_STATES[action] ?? []).includes(build.state);
  return (
    build.verifyRequired === true &&
    build.captureFinalized === true &&
    (VERIFY_STEP_STATES[action] ?? []).includes(build.state)
  );
}

/** The role of a build principal's untargeted create (T1 rule b, review4
 * U1): verify iff the build is CAPTURING, else build. */
export function untargetedCreateRole(state: TemplateBuildState): BuildRole {
  return state === "CAPTURING" ? "verify" : "build";
}

/** The build principal's typed refusal. Orchestrator retry classification
 * keys on `data.code`, never on the message. */
export function buildAuthorityLost(): ORPCError<"FORBIDDEN", { code: "build.authority_lost" }> {
  return new ORPCError("FORBIDDEN", {
    message: "Build authority is no longer active.",
    data: { code: "build.authority_lost" },
  });
}

export function isBuildAuthorityLost(error: unknown): boolean {
  return (
    error instanceof ORPCError &&
    error.code === "FORBIDDEN" &&
    (error.data as { code?: unknown } | undefined)?.code === "build.authority_lost"
  );
}
