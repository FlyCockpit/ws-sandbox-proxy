import type { Principal } from "../sandbox/contracts";

/**
 * The orchestrator's way into the server-only build-context store and transfer
 * store. The server
 * binds it at start, after both stores recovered; a process that never binds
 * it (the standalone worker) refuses every call as retryable, so the action is
 * replayed where the port is bound.
 *
 * Each call takes the principal the orchestrator already holds (the build
 * principal), so `apps/server` never mints one. Every call is idempotent:
 * - `importContext` adopts the sealed staged context into an ordinary SEALED
 *   upload transfer bound to the build's sandbox (`TransferStore.importSealed`,
 *   keyed `tb:<buildId>:import:<n>:0`) and returns that transfer.
 * - `commitContext` issues the existing transfer commit (PUT_FILE) with the
 *   caller's `tb:<buildId>:context:0:<a>` key and returns the operation id.
 * - `abortContext` (cleanup class) aborts an unadopted context and unlinks its
 *   file; an adopted, already ended or absent context is a no-op.
 */
export type BuildContextPort = {
  importContext(principal: Principal, buildId: string): Promise<{ transferId: string }>;
  commitContext(
    principal: Principal,
    buildId: string,
    transferId: string,
    idempotencyKey: string,
  ): Promise<{ operationId: string }>;
  abortContext(principal: Principal, buildId: string): Promise<void>;
};

/**
 * Typed port refusals. `retryable` ones replay the same key after backoff
 * (bounded by the build's `deadlineAt`); the others end the build as
 * `build_context_failed{code}` (or the context's own `errorCode` when it has
 * one: `build_context_timeout`, `build_context_expired`, `build_context_mismatch`).
 */
export type BuildContextPortCode =
  /** No port in this process (worker). */
  | "unbound"
  /** Transfer slot or disk refusal (`TRANSFER_QUOTA`), or a transient spool state. */
  | "busy"
  /** The staged file is gone. */
  | "missing"
  /** The staged file failed validation (symlink, links, owner, mode, size). */
  | "invalid"
  /** The context is not in a state this call accepts (not sealed, ended, not found). */
  | "state";

export class BuildContextPortError extends Error {
  constructor(
    readonly code: BuildContextPortCode,
    readonly retryable: boolean,
    /** The context's own terminal errorCode, when it ended with one. */
    readonly contextErrorCode: string | null = null,
  ) {
    super(`Build context port refused: ${code}`);
    this.name = "BuildContextPortError";
  }
}

let bound: BuildContextPort | null = null;

export function bindBuildContextPort(port: BuildContextPort | null): void {
  bound = port;
}

/** The bound port, or a retryable `unbound` refusal. */
export function buildContextPort(): BuildContextPort {
  if (!bound) throw new BuildContextPortError("unbound", true);
  return bound;
}

type BuildContextWake = (buildId: string) => void;
let wake: BuildContextWake | null = null;

/** The orchestrator binds its wake; the context store calls it after a seal or
 * an expiry commits (no-op until bound). */
export function bindBuildContextWake(listener: BuildContextWake | null): void {
  wake = listener;
}

export function notifyBuildContextChanged(buildId: string): void {
  try {
    wake?.(buildId);
  } catch {
    // The state change is durable; the orchestrator's scan picks it up.
  }
}

const BUILD_ID = "[A-Za-z0-9_-]{1,64}";
/** Internal transfer idempotency keys (the reserved `tb:` namespace, §3.3, §3.5). */
export const BUILD_CONTEXT_IMPORT_KEY = new RegExp(`^tb:${BUILD_ID}:import:\\d{1,9}:0$`);
export const BUILD_CONTEXT_COMMIT_KEY = new RegExp(`^tb:${BUILD_ID}:context:0:\\d{1,9}$`);

export function buildContextImportKey(buildId: string, importAttempt: number): string {
  return `tb:${buildId}:import:${importAttempt}:0`;
}

export function buildContextCommitKey(buildId: string, attempt: number): string {
  return `tb:${buildId}:context:0:${attempt}`;
}

/** Guest path of an adopted context archive (scrubbed by capture, §6.2). */
export function buildContextGuestPath(buildId: string): string {
  return `/var/tmp/wssp-build/${buildId}/context.tar`;
}
