import { z } from "zod";
import { resourceIdSchema } from "./dto";

export const HOST_COMMAND_MAX_MS = 86_400_000;
export const HOST_COMMAND_WAIT_MAX_MS = 60_000;
export const HOST_COMMAND_OUTPUT_MAX_BYTES = 65_536;
export const HOST_FILE_CONTENT_MAX_BYTES = 262_144;
const bytes = (value: string) => new TextEncoder().encode(value).byteLength;
const noNul = (value: string) => !value.includes("\0");
const text = (max: number) =>
  z
    .string()
    .max(max)
    .refine(noNul, "NUL is forbidden.")
    .refine((value) => bytes(value) <= max, `At most ${max} UTF-8 bytes.`);
const offset = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const path = text(4096).min(1);
export const hostIdParamsSchema = z.strictObject({ hostId: resourceIdSchema });
export const hostCommandIdSchema = z.string().regex(/^[A-Za-z0-9_-]{22}$/);
export const hostCommandParamsSchema = hostIdParamsSchema
  .extend({ commandId: hostCommandIdSchema })
  .strict();
export const hostQueuedCommandParamsSchema = hostIdParamsSchema
  .extend({ id: resourceIdSchema })
  .strict();

/** Exactly one execution form; limits count encoded UTF-8 bytes, not JS characters. */
export const hostCommandBodySchema = z
  .strictObject({
    argv: z.array(text(4096)).min(1).max(256).optional(),
    script: text(16_384).min(1).optional(),
    cwd: path.optional(),
    timeoutMs: z.number().int().min(1).max(HOST_COMMAND_MAX_MS).optional(),
    stdin: z.boolean().optional(),
    waitMs: z.number().int().min(0).max(HOST_COMMAND_WAIT_MAX_MS).optional(),
  })
  .superRefine((value, ctx) => {
    if ((value.argv === undefined) === (value.script === undefined))
      ctx.addIssue({ code: "custom", message: "Exactly one of argv or script is required." });
    if (
      value.argv &&
      (value.argv[0] === "" || value.argv.reduce((sum, arg) => sum + bytes(arg), 0) > 16_384)
    )
      ctx.addIssue({
        code: "custom",
        path: ["argv"],
        message: "Invalid program or argv exceeds 16384 UTF-8 bytes.",
      });
  });
const queryNumber = (max: number, min = 0) =>
  z
    .string()
    .regex(/^(0|[1-9][0-9]*)$/)
    .max(16)
    .transform(Number)
    .pipe(z.number().int().min(min).max(max));
export const hostCommandQuerySchema = z.strictObject({
  stdoutOffset: queryNumber(Number.MAX_SAFE_INTEGER).optional(),
  stderrOffset: queryNumber(Number.MAX_SAFE_INTEGER).optional(),
  maxBytes: queryNumber(HOST_COMMAND_OUTPUT_MAX_BYTES, 1).optional(),
  waitMs: queryNumber(HOST_COMMAND_WAIT_MAX_MS).optional(),
});
/** Canonical padded RFC 4648 base64, at most 64 KiB decoded. */
export const hostStdinDataSchema = z
  .string()
  .max(87_384)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/)
  .refine((value) => {
    const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
    if ((value.length / 4) * 3 - padding > 65_536) return false;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const last = alphabet.indexOf(value[value.length - padding - 1] ?? "A");
    return padding === 2 ? last % 16 === 0 : padding === 1 ? last % 4 === 0 : true;
  });
export const hostCommandStdinBodySchema = z.strictObject({
  data: hostStdinDataSchema,
  eof: z.boolean(),
});
export const HOST_COMMAND_STATES = [
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "timed_out",
  "interrupted",
  "unknown",
] as const;
const hostOutputSchema = z.strictObject({
  offset,
  data: hostStdinDataSchema,
  dropped: z.boolean(),
});
export const hostCommandStatusSchema = z.strictObject({
  commandId: hostCommandIdSchema,
  state: z.enum(HOST_COMMAND_STATES),
  exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).optional(),
  signal: z.number().int().min(1).max(127).optional(),
  startedAt: offset.optional(),
  endsBy: offset.optional(),
  finishedAt: offset.optional(),
  stdout: hostOutputSchema,
  stderr: hostOutputSchema,
  stdoutBytes: offset,
  stderrBytes: offset,
});
export const hostCommandStdinResultSchema = z.strictObject({
  commandId: hostCommandIdSchema,
  accepted: z.boolean(),
  reason: z.string().max(64).optional(),
});
export const queueHostCommandBodySchema = z.strictObject({
  command: text(16_384).min(1),
  reason: text(1000).min(1),
  expiresInHours: z.number().int().min(1).max(168).optional(),
});
export const HOST_QUEUED_COMMAND_STATES = [
  "QUEUED",
  "RUN",
  "DISMISSED",
  "EXPIRED",
  "REFUSED",
] as const;
export const hostQueuedCommandSchema = z.strictObject({
  id: resourceIdSchema,
  state: z.enum(HOST_QUEUED_COMMAND_STATES),
  expiresAt: z.iso.datetime(),
});

export const hostFileEtagSchema = z.string().regex(/^h:[A-Za-z0-9_-]{22}$/);
const unredacted = (value: string) => !value.includes("⟦redacted");
const fileText = () =>
  text(HOST_FILE_CONTENT_MAX_BYTES).refine(unredacted, "Redacted spans cannot be written.");
export const hostFileReadBodySchema = z.strictObject({
  path,
  offset: offset.optional(),
  maxBytes: z.number().int().min(1).max(HOST_FILE_CONTENT_MAX_BYTES).optional(),
});
export const hostFileListBodySchema = z.strictObject({ path });
export const hostFileWriteBodySchema = z.strictObject({
  path,
  content: fileText(),
  expectedEtag: hostFileEtagSchema.optional(),
  createOnly: z.boolean().optional(),
});
export const hostFileEditBodySchema = z.strictObject({
  path,
  edits: z
    .array(
      z.strictObject({
        oldText: fileText().refine((value) => value.length > 0),
        newText: fileText(),
      }),
    )
    .min(1)
    .max(20),
  expectedEtag: hostFileEtagSchema.optional(),
});
export const hostFileReadSchema = z.strictObject({
  content: z
    .string()
    .max(HOST_FILE_CONTENT_MAX_BYTES)
    .refine((value) => bytes(value) <= HOST_FILE_CONTENT_MAX_BYTES),
  offset,
  size: offset,
  etag: hostFileEtagSchema,
  truncated: z.boolean(),
});
export const hostFileListSchema = z.strictObject({
  entries: z
    .array(
      z.strictObject({
        name: text(4096).min(1),
        kind: z.enum(["file", "dir", "symlink", "other"]),
        size: offset.optional(),
      }),
    )
    .max(1000),
  truncated: z.boolean(),
});
export const hostFileWriteSchema = z.strictObject({
  etag: hostFileEtagSchema,
  size: offset,
  created: z.boolean(),
});
export const hostFileEditSchema = z.strictObject({
  etag: hostFileEtagSchema,
  size: offset,
  replacements: z.number().int().min(1).max(20),
});
export type HostCommandInput = z.input<typeof hostCommandBodySchema>;
export type HostCommandStatus = z.output<typeof hostCommandStatusSchema>;
export type HostQueuedCommand = z.output<typeof hostQueuedCommandSchema>;
export type HostFileRead = z.output<typeof hostFileReadSchema>;
export type HostFileList = z.output<typeof hostFileListSchema>;
export type HostFileWrite = z.output<typeof hostFileWriteSchema>;
export type HostFileEdit = z.output<typeof hostFileEditSchema>;
