import { z } from "zod";
import {
  cursorSchema,
  isoDateTimeSchema,
  OPERATION_STATES,
  operationWaitMsQuerySchema,
  resourceIdSchema,
} from "./dto";

/**
 * Incremental command output (`GET /v1/operations/{id}/output`). The server
 * retains at most the first 256 KiB plus a rolling final 768 KiB of one
 * command's aggregate stdout/stderr byte stream. Offsets count every byte the
 * command produced across both streams, so dropped ranges are explicit gaps.
 */
export const OUTPUT_HEAD_BYTES = 256 * 1024;
export const OUTPUT_TAIL_BYTES = 768 * 1024;
/** Most chunk bytes one page returns. */
export const OUTPUT_PAGE_MAX_BYTES = 64 * 1024;
/** Most chunks (and gaps) one page returns, even when streams alternate per byte. */
export const OUTPUT_PAGE_MAX_CHUNKS = 1024;
/** Output content is kept this long after its operation completes. */
export const OUTPUT_RETENTION_MS = 24 * 60 * 60 * 1000;

/** Decimal byte budget string, 1–65536. Query values are strings on the wire. */
export const outputMaxBytesQuerySchema = z
  .string()
  .regex(/^[1-9][0-9]{0,4}$/)
  .transform(Number)
  .pipe(z.number().int().min(1).max(OUTPUT_PAGE_MAX_BYTES));

export const outputQuerySchema = z
  .object({
    cursor: cursorSchema.optional(),
    maxBytes: outputMaxBytesQuerySchema.optional(),
    /** Long-poll: hold an empty, still-open page up to this many ms (max 25000). */
    waitMs: operationWaitMsQuerySchema.optional(),
  })
  .strict();

/** Decoded length of canonical padded base64, without decoding it. */
export function base64ByteLength(data: string): number {
  const padding = data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0;
  return (data.length / 4) * 3 - padding;
}

const offsetSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** One run of consecutive bytes from a single stream, standard base64. */
export const outputChunkSchema = z
  .object({
    stream: z.enum(["stdout", "stderr"]),
    offset: offsetSchema,
    data: z.base64().min(1),
  })
  .strict();
export type OutputChunkDto = z.infer<typeof outputChunkSchema>;

/** Half-open aggregate byte range `[start, end)` that is not retained. */
export const outputGapSchema = z
  .object({ start: offsetSchema, end: offsetSchema })
  .strict()
  .refine((gap) => gap.start < gap.end, { message: "gap must be non-empty" });

export const commandOutputPageSchema = z
  .object({
    operationId: resourceIdSchema,
    state: z.enum(OPERATION_STATES),
    /** Exit status once the host reported one; null while running or unknown. */
    exitCode: z.number().int().nullable(),
    /** Dispatch attempt whose bytes these are. Cursors are bound to it. */
    attempt: z.number().int().min(0),
    /** True when the supplied cursor belonged to an earlier attempt: restart decoding at 0. */
    reset: z.boolean(),
    /** Aggregate offset this page starts at. */
    offset: offsetSchema,
    chunks: z.array(outputChunkSchema).max(OUTPUT_PAGE_MAX_CHUNKS),
    gaps: z.array(outputGapSchema).max(OUTPUT_PAGE_MAX_CHUNKS + 1),
    /** Pass back to continue. It never re-reads a range this page returned. */
    nextCursor: cursorSchema,
    /** More chunks or gaps are available at `nextCursor` right now. */
    hasMore: z.boolean(),
    /** Bytes the server has received from the host so far (aggregate offset). */
    receivedBytes: offsetSchema,
    /** Bytes the command produced, once the completion watermark committed. */
    totalBytes: offsetSchema.nullable(),
    retainedBytes: offsetSchema,
    /** Some produced bytes are not retained (see `gaps`). */
    truncated: z.boolean(),
    /**
     * Completion watermark: no further bytes will ever be stored. A terminal
     * operation state alone does not imply this.
     */
    complete: z.boolean(),
    expiresAt: isoDateTimeSchema.nullable(),
  })
  .strict()
  .refine(
    (page) =>
      page.chunks.reduce((sum, chunk) => sum + base64ByteLength(chunk.data), 0) <=
      OUTPUT_PAGE_MAX_BYTES,
    { message: "page exceeds its byte budget", path: ["chunks"] },
  );
export type CommandOutputPageDto = z.infer<typeof commandOutputPageSchema>;
