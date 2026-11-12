import { z } from "zod";

/**
 * Relay 1.0 additive template start/ready dispatch field (template builds
 * B9). Mirrors `crates/sandbox-protocol/src/startup.rs`; the shared fixture is
 * `crates/sandbox-protocol/fixtures/control_startup.json`.
 *
 * `startup` rides only on `sandbox.create` and `sandbox.reconnect` (never with
 * `build`) and only to daemons advertising `templateStartup`. The daemon runs
 * the start command as the guest user, never root.
 */
export const STARTUP_COMMAND_MAX_BYTES = 4096;
export const STARTUP_CWD_MAX_BYTES = 4096;
export const STARTUP_READY_TIMEOUT_MIN_MS = 1_000;
export const STARTUP_READY_TIMEOUT_MAX_MS = 600_000;
export const STARTUP_READY_TIMEOUT_DEFAULT_MS = 60_000;

// biome-ignore lint/suspicious/noControlCharactersInRegex: refuses control characters
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const bytes = (value: string) => new TextEncoder().encode(value).byteLength;

const commandSchema = z
  .string()
  .refine(
    (value) =>
      value.length > 0 && bytes(value) <= STARTUP_COMMAND_MAX_BYTES && !value.includes("\0"),
    "invalid startup command",
  );

export const dispatchStartupV11Schema = z
  .strictObject({
    command: commandSchema,
    ready: commandSchema.optional(),
    readyTimeoutMs: z
      .number()
      .int()
      .min(STARTUP_READY_TIMEOUT_MIN_MS)
      .max(STARTUP_READY_TIMEOUT_MAX_MS)
      .optional(),
    cwd: z
      .string()
      .refine(
        (value) =>
          value.startsWith("/") &&
          bytes(value) <= STARTUP_CWD_MAX_BYTES &&
          !CONTROL.test(value) &&
          !value.split("/").includes(".."),
        "invalid startup cwd",
      )
      .optional(),
  })
  .refine((startup) => startup.readyTimeoutMs === undefined || startup.ready !== undefined, {
    message: "readyTimeoutMs requires ready",
  });
export type DispatchStartupV11 = z.infer<typeof dispatchStartupV11Schema>;

/** Strict placement of `startup` on one dispatch (see the Rust module docs). */
export function validDispatchStartup(dispatch: {
  kind: string;
  startup?: unknown;
  build?: unknown;
}): boolean {
  if (dispatch.startup === undefined) return true;
  return (
    (dispatch.kind === "sandbox.create" || dispatch.kind === "sandbox.reconnect") &&
    dispatch.build === undefined &&
    dispatchStartupV11Schema.safeParse(dispatch.startup).success
  );
}

/** The dispatch `startup` of a revision's stored start/ready columns, or
 * undefined when the revision has no start command. */
export function revisionStartup(revision: {
  startCmd: string | null;
  readyCmd: string | null;
  readyTimeoutMs: number | null;
  defaultCwd: string | null;
}): DispatchStartupV11 | undefined {
  if (revision.startCmd === null) return undefined;
  return dispatchStartupV11Schema.parse({
    command: revision.startCmd,
    ...(revision.readyCmd !== null ? { ready: revision.readyCmd } : {}),
    ...(revision.readyCmd !== null && revision.readyTimeoutMs !== null
      ? { readyTimeoutMs: revision.readyTimeoutMs }
      : {}),
    ...(revision.defaultCwd !== null ? { cwd: revision.defaultCwd } : {}),
  });
}
