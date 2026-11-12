import { Buffer } from "node:buffer";
import { base64ByteLength, type CommandOutputPageDto } from "@wssp/sandbox-contracts";
import { WsspError } from "./errors";
import type { PollContext } from "./polling";

export type CommandStream = "stdout" | "stderr";

/**
 * One output observation in aggregate-offset order: decoded text from one
 * stream, or a half-open byte range `[start, end)` the server did not retain.
 */
export type OutputEvent =
  | { kind: "data"; stream: CommandStream; offset: number; text: string }
  | { kind: "gap"; start: number; end: number }
  | { kind: "reset"; attempt: number; offset: number };

export function decodeBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, "base64"));
}

/** Canonical padded base64, as the stdin route requires. */
export function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Incremental UTF-8 decoding, one decoder per stream: a code point may be
 * split across chunks and pages. `reset` starts both decoders over — a new
 * dispatch attempt or a gap means later bytes no longer join earlier partial
 * sequences (continuing would risk incorrectly decoding the boundary).
 */
export class StreamDecoders {
  #stdout = new TextDecoder("utf-8");
  #stderr = new TextDecoder("utf-8");

  reset(): void {
    this.#stdout = new TextDecoder("utf-8");
    this.#stderr = new TextDecoder("utf-8");
  }

  decode(stream: CommandStream, bytes: Uint8Array): string {
    return (stream === "stdout" ? this.#stdout : this.#stderr).decode(bytes, { stream: true });
  }

  /**
   * End-of-stream decode of one stream: a trailing partial sequence surfaces
   * as U+FFFD instead of vanishing inside the decoder.
   */
  flush(stream: CommandStream): string {
    return (stream === "stdout" ? this.#stdout : this.#stderr).decode();
  }
}

/**
 * Bounded tail-keeping text buffer: retains the last `maxChars` UTF-16 units
 * and counts the dropped prefix, so accumulation stays bounded no matter how
 * much output a command produces. Never splits a surrogate pair at the cut.
 */
export class TrimBuffer {
  #parts: string[] = [];
  #length = 0;
  #dropped = 0;
  readonly #maxChars: number;

  constructor(maxChars: number) {
    this.#maxChars = maxChars;
  }

  /** Characters of older output discarded by trimming. */
  get dropped(): number {
    return this.#dropped;
  }

  push(text: string): void {
    if (text === "") return;
    this.#parts.push(text);
    this.#length += text.length;
    // Trim eagerly at 2x so a flood of small chunks stays bounded too.
    if (this.#length > this.#maxChars * 2) this.trim();
  }

  clear(): void {
    this.#parts = [];
    this.#length = 0;
    this.#dropped = 0;
  }

  trim(): void {
    let excess = this.#length - this.#maxChars;
    while (excess > 0) {
      const first = this.#parts[0];
      if (first === undefined) return;
      if (first.length <= excess) {
        this.#parts.shift();
        this.#length -= first.length;
        this.#dropped += first.length;
        excess -= first.length;
        continue;
      }
      let cut = excess;
      // Never start the retained text with a lone low surrogate.
      if (cut < first.length) {
        const code = first.charCodeAt(cut);
        if (code >= 0xdc00 && code <= 0xdfff) cut += 1;
      }
      this.#parts[0] = first.slice(cut);
      this.#length -= cut;
      this.#dropped += cut;
      return;
    }
  }

  value(): string {
    this.trim();
    return this.#parts.join("");
  }
}

type RawEvent =
  | { kind: "data"; stream: CommandStream; offset: number; bytes: Uint8Array }
  | { kind: "gap"; start: number; end: number };

const CURSOR_PATTERN = /^(\d{1,10})_(\d{1,16})$/;

/** Offset half of an `attempt_offset` output cursor, or null when malformed. */
/** `{ attempt, offset }` of a server output cursor, or null when malformed. */
function parseOutputCursor(cursor: string): { attempt: number; offset: number } | null {
  const match = CURSOR_PATTERN.exec(cursor);
  if (!match) return null;
  const attempt = Number(match[1]);
  const offset = Number(match[2]);
  return Number.isSafeInteger(attempt) && Number.isSafeInteger(offset) ? { attempt, offset } : null;
}

/**
 * True when `next` moves the read position forward from `previous`: a later
 * dispatch attempt, or a larger offset within the same attempt. A first read
 * (no cursor) advances only when it delivered bytes.
 */
export function outputCursorAdvanced(previous: string | undefined, next: string): boolean {
  const to = parseOutputCursor(next);
  if (!to) return false;
  if (previous === undefined) return to.offset > 0;
  const from = parseOutputCursor(previous);
  if (!from) return false;
  return to.attempt > from.attempt || (to.attempt === from.attempt && to.offset > from.offset);
}

export function outputCursorOffset(cursor: string): number | null {
  const match = CURSOR_PATTERN.exec(cursor);
  if (!match) return null;
  const offset = Number(match[2]);
  return Number.isSafeInteger(offset) ? offset : null;
}

export function protocolError(context: PollContext, detail: string): WsspError {
  return new WsspError({
    kind: "protocol",
    message: `${context.label}: ${detail}`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * Order and validate one page's ranges. The contract tiles `[offset,
 * nextCursor)` exactly with ascending, non-overlapping chunks and gaps; any
 * deviation is a protocol error, never a silently dropped or repeated range.
 */
export function pageEvents(page: CommandOutputPageDto, context: PollContext): RawEvent[] {
  const ranges: { start: number; end: number; chunk?: CommandOutputPageDto["chunks"][number] }[] =
    [];
  for (const chunk of page.chunks) {
    ranges.push({
      start: chunk.offset,
      end: chunk.offset + base64ByteLength(chunk.data),
      chunk,
    });
  }
  for (const gap of page.gaps) ranges.push({ start: gap.start, end: gap.end });
  ranges.sort((a, b) => a.start - b.start);
  const events: RawEvent[] = [];
  let position = page.offset;
  for (const range of ranges) {
    if (range.start !== position) {
      throw protocolError(context, "the output page ranges do not tile [offset, nextCursor).");
    }
    events.push(
      range.chunk
        ? {
            kind: "data",
            stream: range.chunk.stream,
            offset: range.chunk.offset,
            bytes: decodeBase64(range.chunk.data),
          }
        : { kind: "gap", start: range.start, end: range.end },
    );
    position = range.end;
  }
  const end = outputCursorOffset(page.nextCursor);
  if (end === null || end !== position) {
    throw protocolError(context, "the output page cursor does not match its ranges.");
  }
  return events;
}
