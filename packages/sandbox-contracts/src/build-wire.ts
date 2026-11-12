import { z } from "zod";

/**
 * Relay 1.0 additive template-build dispatch fields. Mirrors
 * `crates/sandbox-protocol/src/build.rs`; the shared fixture is
 * `crates/sandbox-protocol/fixtures/control_build.json`.
 *
 * D1: guest root runs only inside build VMs. `build` rides only on
 * `sandbox.create`; `runAs` and `buildCopy` only on `command.run`, and the
 * daemon refuses them unless its journaled sandbox record carries a build id.
 */
export const BUILD_COPY_SRC_MAX = 64;
export const BUILD_COPY_SRC_MAX_BYTES = 1024;
export const BUILD_COPY_DEST_MAX_BYTES = 4096;
export const BUILD_COPY_MODE_MAX = 0o777;
export const BUILD_CONTEXT_DIR = "/var/tmp/wssp-build";
export const BUILD_CONTEXT_FILE = "context.tar";

const BUILD_ID = /^[A-Za-z0-9_-]{1,128}$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: refuses control characters
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

export function validBuildId(value: string): boolean {
  return BUILD_ID.test(value);
}

/** The only guest path a build context is put to and copied from. */
export function buildContextPath(buildId: string): string | null {
  return validBuildId(buildId) ? `${BUILD_CONTEXT_DIR}/${buildId}/${BUILD_CONTEXT_FILE}` : null;
}

/** The build id a context path names, when it has the exact fixed shape. */
export function buildIdOfContextPath(path: string): string | null {
  const prefix = `${BUILD_CONTEXT_DIR}/`;
  const suffix = `/${BUILD_CONTEXT_FILE}`;
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) return null;
  const id = path.slice(prefix.length, path.length - suffix.length);
  return validBuildId(id) ? id : null;
}

/** `.` alone, or relative non-empty segments (no `.`/`..`), `*` only last. */
export function validBuildCopySrc(src: string): boolean {
  if (src === ".") return true;
  if (
    src.length === 0 ||
    new TextEncoder().encode(src).byteLength > BUILD_COPY_SRC_MAX_BYTES ||
    src.startsWith("/") ||
    CONTROL.test(src)
  )
    return false;
  const segments = src.split("/");
  return segments.every(
    (segment, index) =>
      segment.length > 0 &&
      segment !== "." &&
      segment !== ".." &&
      (index === segments.length - 1 || !segment.includes("*")),
  );
}

/** Absolute guest path, no `.`/`..`/empty segments; one trailing `/` = directory. */
export function validBuildCopyDest(dest: string): boolean {
  if (
    !dest.startsWith("/") ||
    new TextEncoder().encode(dest).byteLength > BUILD_COPY_DEST_MAX_BYTES ||
    CONTROL.test(dest) ||
    dest.includes("*")
  )
    return false;
  if (dest === "/") return true;
  const body = dest.endsWith("/") ? dest.slice(1, -1) : dest.slice(1);
  return (
    body.length > 0 &&
    body.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}

export const dispatchBuildV11Schema = z.strictObject({
  buildId: z.string().refine(validBuildId, "invalid build id"),
  /**
   * The community prep build VM of a raw upstream base (bootstrap readiness).
   * Rust omits it while false, so the wire carries `true` or nothing.
   */
  bootstrap: z.literal(true).optional(),
});
export type DispatchBuildV11 = z.infer<typeof dispatchBuildV11Schema>;

export const runAsV11Schema = z.literal("root");
export type RunAsV11 = z.infer<typeof runAsV11Schema>;

export const buildCopyV11Schema = z.strictObject({
  contextPath: z.string().refine((p) => buildIdOfContextPath(p) !== null, "invalid context path"),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  src: z
    .array(z.string().refine(validBuildCopySrc, "invalid copy source"))
    .min(1)
    .max(BUILD_COPY_SRC_MAX),
  dest: z.string().refine(validBuildCopyDest, "invalid copy destination"),
  owner: z.enum(["root", "user"]),
  mode: z.number().int().min(0).max(BUILD_COPY_MODE_MAX).optional(),
});
export type BuildCopyV11 = z.infer<typeof buildCopyV11Schema>;

/** Strict placement of the build fields on one dispatch (see the Rust module docs). */
export function validDispatchBuildFields(dispatch: {
  kind: string;
  build?: unknown;
  runAs?: unknown;
  buildCopy?: unknown;
  argv?: unknown;
  script?: unknown;
  env?: unknown[];
}): boolean {
  const create = dispatch.kind === "sandbox.create";
  const command = dispatch.kind === "command.run";
  if (
    dispatch.build !== undefined &&
    (!create || !dispatchBuildV11Schema.safeParse(dispatch.build).success)
  )
    return false;
  if (
    dispatch.runAs !== undefined &&
    (!command || !runAsV11Schema.safeParse(dispatch.runAs).success)
  )
    return false;
  if (dispatch.buildCopy !== undefined)
    return (
      command &&
      buildCopyV11Schema.safeParse(dispatch.buildCopy).success &&
      dispatch.runAs === undefined &&
      dispatch.argv === undefined &&
      dispatch.script === undefined &&
      (dispatch.env === undefined || dispatch.env.length === 0)
    );
  return true;
}
