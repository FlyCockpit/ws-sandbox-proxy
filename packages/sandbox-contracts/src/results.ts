import { z } from "zod";
import limits from "../../config/src/sandbox-result-limits.json";
import { isoDateTimeSchema, OPERATION_OUTCOMES, resourceIdSchema } from "./dto";
import {
  observedGuestPathSchema,
  processInfoSchema,
  processRefSchema,
  processSignalSchema,
  utf8String,
} from "./processes";

export const RESULT_LIMITS = limits;
export function encodedJsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}
function utf8Compare(a: string, b: string): number {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i]! - right[i]!;
  }
  return left.length - right.length;
}
export function modePermissions(mode: number): string {
  return [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001]
    .map((bit, i) => {
      const set = (mode & bit) !== 0;
      if (i === 2 && mode & 0o4000) return set ? "s" : "S";
      if (i === 5 && mode & 0o2000) return set ? "s" : "S";
      if (i === 8 && mode & 0o1000) return set ? "t" : "T";
      return set ? "rwx"[i % 3] : "-";
    })
    .join("");
}
const nameSchema = utf8String(255).refine(
  (value) =>
    value === "/" || (value.length > 0 && !/[/\0]/.test(value) && value !== "." && value !== ".."),
);
export const entryInfoSchema = z
  .object({
    name: nameSchema,
    path: observedGuestPathSchema,
    type: z.enum(["file", "dir", "symlink", "other"]),
    size: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    mode: z.number().int().min(0).max(0o7777),
    permissions: z.string().length(9),
    uid: z.number().int().min(0).max(4_294_967_295),
    gid: z.number().int().min(0).max(4_294_967_295),
    // Same NUL rule as name/path: jsonb cannot store U+0000.
    owner: utf8String(128)
      .refine((value) => !value.includes("\0"))
      .nullable(),
    group: utf8String(128)
      .refine((value) => !value.includes("\0"))
      .nullable(),
    modifiedTime: isoDateTimeSchema.nullable(),
    symlinkTarget: utf8String(4096)
      .refine((value) => !value.includes("\0"))
      .nullable(),
  })
  .strict()
  .refine(
    (entry) =>
      entry.name ===
        (entry.path === "/" ? "/" : entry.path.slice(entry.path.lastIndexOf("/") + 1)) &&
      entry.permissions === modePermissions(entry.mode) &&
      (entry.type === "symlink" ? entry.symlinkTarget !== null : entry.symlinkTarget === null),
  );
export type EntryInfo = z.infer<typeof entryInfoSchema>;
export { failureSchema, type OperationFailure } from "./dto";

const livePage = { nextCursor: resourceIdSchema.nullable(), consistency: z.literal("live") };
export const resultBodySchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("file.stat"), entry: entryInfoSchema }).strict(),
  z
    .object({
      type: z.literal("file.list"),
      path: observedGuestPathSchema,
      depth: z.number().int().min(1).max(limits.directoryDepthMax),
      items: z.array(entryInfoSchema).max(limits.listMaxLimit),
      ...livePage,
    })
    .strict(),
  z.object({ type: z.literal("file.mkdir"), created: z.boolean() }).strict(),
  z.object({ type: z.literal("file.remove"), removed: z.literal(true) }).strict(),
  z.object({ type: z.literal("file.rename"), entry: entryInfoSchema }).strict(),
  z
    .object({
      type: z.literal("process.list"),
      items: z.array(processInfoSchema).max(limits.listMaxLimit),
      ...livePage,
    })
    .strict(),
  z
    .object({
      type: z.literal("process.signal"),
      process: processRefSchema,
      targetOperationId: resourceIdSchema,
      signal: processSignalSchema,
      accepted: z.literal(true),
      delivery: z.literal("process_group"),
    })
    .strict(),
  z
    .object({
      type: z.literal("command"),
      process: processRefSchema,
      startedAt: isoDateTimeSchema,
      exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).nullable(),
    })
    .strict(),
]);
export const RESULT_TYPE_BY_KIND = {
  STAT_PATH: "file.stat",
  LIST_DIR: "file.list",
  MKDIR: "file.mkdir",
  REMOVE_PATH: "file.remove",
  MOVE_PATH: "file.rename",
  LIST_PROCESSES: "process.list",
  SIGNAL_PROCESS: "process.signal",
  RUN_COMMAND: "command",
} as const;
export type ResultKind = keyof typeof RESULT_TYPE_BY_KIND;
export function isResultKind(kind: string): kind is ResultKind {
  return Object.hasOwn(RESULT_TYPE_BY_KIND, kind);
}
export const operationResultSchema = z
  .object({
    operationId: resourceIdSchema,
    sandboxId: resourceIdSchema,
    generation: z.number().int().positive().max(2_147_483_647),
    kind: z.enum([
      "STAT_PATH",
      "LIST_DIR",
      "MKDIR",
      "REMOVE_PATH",
      "MOVE_PATH",
      "LIST_PROCESSES",
      "SIGNAL_PROCESS",
      "RUN_COMMAND",
    ]),
    outcome: z.enum(OPERATION_OUTCOMES),
    observedAt: isoDateTimeSchema,
    expiresAt: isoDateTimeSchema.nullable(),
    result: resultBodySchema.nullable(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const issue = () => ctx.addIssue({ code: "custom", message: "Invalid operation result." });
    if (encodedJsonBytes(value) > limits.responseMaxBytes) issue();
    const expiring = ["STAT_PATH", "LIST_DIR", "MOVE_PATH", "LIST_PROCESSES"].includes(value.kind);
    if (expiring !== (value.expiresAt !== null)) issue();
    if (value.result === null) {
      if (value.outcome === "succeeded") issue();
      return;
    }
    if (RESULT_TYPE_BY_KIND[value.kind] !== value.result.type) issue();
    if (
      value.outcome !== "succeeded" &&
      !(value.kind === "RUN_COMMAND" && value.outcome === "pending")
    )
      issue();
    if (value.result.type === "file.list") {
      const page = value.result;
      const prefix = page.path === "/" ? "/" : `${page.path}/`;
      if (
        page.items.some((entry, i) => {
          if (!entry.path.startsWith(prefix)) return true;
          const relative = entry.path.slice(prefix.length).split("/");
          return (
            relative.length > page.depth ||
            relative.some((part) => part === "" || part === "." || part === "..") ||
            (i > 0 && utf8Compare(page.items[i - 1]!.path, entry.path) >= 0)
          );
        })
      )
        issue();
    }
    if (
      value.result.type === "process.list" &&
      value.result.items.some(
        (entry, i, items) =>
          i > 0 &&
          (Date.parse(items[i - 1]!.startedAt) > Date.parse(entry.startedAt) ||
            (Date.parse(items[i - 1]!.startedAt) === Date.parse(entry.startedAt) &&
              utf8Compare(items[i - 1]!.process.processId, entry.process.processId) >= 0)),
      )
    )
      issue();
    const refs =
      value.result.type === "process.list"
        ? value.result.items.map((item) => item.process)
        : "process" in value.result
          ? [value.result.process]
          : [];
    if (
      refs.some((ref) => ref.sandboxId !== value.sandboxId || ref.generation !== value.generation)
    )
      issue();
  });
export type OperationResult = z.infer<typeof operationResultSchema>;
/** Private continuation. Public cursors contain only the originating operation ID. */
export const resultContinuationSchema = z
  .object({
    lastKey: utf8String(4096),
    root: observedGuestPathSchema,
    depth: z.number().int().min(1).max(limits.directoryDepthMax),
    limit: z.number().int().min(1).max(limits.listMaxLimit),
    generation: z.number().int().positive().max(2_147_483_647),
    kind: z.enum(["LIST_DIR", "LIST_PROCESSES"]),
  })
  .strict();

/** Staged request codecs. No route is mounted by importing these definitions. */
export const resultListOptionsSchema = z
  .object({
    limit: z.number().int().min(1).max(limits.listMaxLimit).default(limits.listDefaultLimit),
    cursor: resourceIdSchema.optional(),
  })
  .strict();
