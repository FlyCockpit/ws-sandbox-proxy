import { OUTPUT_HEAD_BYTES, OUTPUT_TAIL_BYTES } from "@wssp/api/sandbox/contracts";

/**
 * Browser-side accumulation of a command's durable output (C48), fed one
 * `getCommandOutput` page at a time.
 *
 * - **Text only.** Bytes are decoded as UTF-8 (one streaming decoder per
 *   stream, so a character split across chunks decodes once) and rendered by
 *   React as text nodes. Control characters, including the ESC that starts
 *   ANSI/OSC sequences, and bidirectional-override characters are replaced
 *   by visible stand-ins, so output can neither run markup nor restyle or
 *   reorder what the page shows.
 * - **Cursor-exact.** Pieces are keyed by aggregate byte offsets. A byte the
 *   buffer already holds is never appended twice (a repeated or overlapping
 *   page is trimmed to what is new), a range the server says is gone is a
 *   gap marker, and a jump the server did not explain is also shown as a gap.
 *   A page whose cursor belonged to an earlier dispatch attempt (`reset`)
 *   starts over.
 * - **Bounded.** Like the server, it keeps at most the first 256 KiB and the
 *   last 768 KiB of what it read (a live reader sees more than the server
 *   retains); a dropped middle becomes a gap. Adjacent text merges into
 *   pieces of at most {@link PIECE_MAX_BYTES}, and once there are
 *   {@link PIECE_SOFT_CAP} pieces the streams merge too, so the rendered node
 *   count stays bounded however the streams interleave. Gaps stop merging,
 *   so {@link PIECE_MAX_COUNT} caps pieces independently of bytes.
 */

export type OutputStream = "stdout" | "stderr";

export type OutputPiece =
  | {
      type: "text";
      /** `mixed` once the piece bound forced two streams into one piece. */
      stream: OutputStream | "mixed";
      start: number;
      end: number;
      text: string;
    }
  | { type: "gap"; start: number; end: number };

export type OutputPage = {
  attempt: number;
  reset: boolean;
  chunks: { stream: OutputStream; offset: number; data: string }[];
  gaps: { start: number; end: number }[];
  nextCursor: string;
  hasMore: boolean;
  receivedBytes: number;
  totalBytes: number | null;
  retainedBytes: number;
  truncated: boolean;
  complete: boolean;
  expiresAt: string | Date | null;
};

export type OutputSnapshot = {
  pieces: readonly OutputPiece[];
  /** Pass back for the next page; null before the first page. */
  cursor: string | null;
  attempt: number | null;
  /** The host retried the command and its output started over at least once. */
  restarted: boolean;
  receivedBytes: number;
  totalBytes: number | null;
  retainedBytes: number;
  /** The server or this page dropped part of the output (see the gap pieces). */
  truncated: boolean;
  /** Completion watermark: no further byte will ever be stored. */
  complete: boolean;
  expiresAt: string | null;
};

export const PIECE_MAX_BYTES = 16 * 1024;
export const PIECE_SOFT_CAP = 256;
/** Hard bound on pieces (text and gaps), whatever the byte count. */
export const PIECE_MAX_COUNT = 2 * PIECE_SOFT_CAP;
/** Bytes of text the buffer keeps: the server's own head + tail budget. */
export const BUFFER_MAX_BYTES = OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES;

/** Every C0/C1 control and DEL (C1 includes the one-byte CSI, U+009B). */
const CONTROL = /\p{Cc}/gu;
// Cf includes bidi controls, zero-width formatting and supplementary tags.
const INVISIBLE = /[\p{Cf}\u2028\u2029]/gu;

function codeTag(char: string): string {
  return `⟨U+${char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

/**
 * Make decoded output safe to show as plain text. Newlines and tabs stay;
 * CRLF becomes LF; every other C0 control and DEL becomes its Unicode
 * "control picture" (ESC → ␛, lone CR → ␍); C1 controls and bidi
 * controls, Unicode formatting characters and line/paragraph separators become a visible `⟨U+202E⟩` tag.
 */
export function displayText(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    .replace(CONTROL, (char) => {
      if (char === "\n" || char === "\t") return char;
      const code = char.charCodeAt(0);
      if (code < 0x20) return String.fromCharCode(0x2400 + code);
      if (code === 0x7f) return "\u2421";
      return codeTag(char);
    })
    .replace(INVISIBLE, codeTag);
}

/** Labels occupy one visual line; preserve newlines/tabs as visible escapes. */
export function displayInlineText(text: string): string {
  return displayText(text).replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll("\t", "\\t");
}

function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

type Item =
  | { type: "chunk"; start: number; stream: OutputStream; data: string }
  | { type: "gap"; start: number; end: number };

export class CommandOutputBuffer {
  private pieces: OutputPiece[] = [];
  /** Aggregate offset just past everything this buffer has accounted for. */
  private end = 0;
  private textBytes = 0;
  private clientTrimmed = false;
  private decoders = CommandOutputBuffer.newDecoders();
  private state: Omit<OutputSnapshot, "pieces" | "truncated"> & { serverTruncated: boolean } = {
    cursor: null,
    attempt: null,
    restarted: false,
    receivedBytes: 0,
    totalBytes: null,
    retainedBytes: 0,
    serverTruncated: false,
    complete: false,
    expiresAt: null,
  };

  private static newDecoders(): Record<OutputStream, TextDecoder> {
    return { stdout: new TextDecoder("utf-8"), stderr: new TextDecoder("utf-8") };
  }

  apply(page: OutputPage): OutputSnapshot {
    const restarted =
      page.reset || (this.state.attempt !== null && page.attempt !== this.state.attempt);
    if (restarted) {
      this.pieces = [];
      this.end = 0;
      this.textBytes = 0;
      this.clientTrimmed = false;
      this.decoders = CommandOutputBuffer.newDecoders();
    }
    const items: Item[] = [
      ...page.chunks.map((chunk) => ({
        type: "chunk" as const,
        start: chunk.offset,
        stream: chunk.stream,
        data: chunk.data,
      })),
      ...page.gaps.map((gap) => ({ type: "gap" as const, start: gap.start, end: gap.end })),
    ].sort((a, b) => a.start - b.start);
    for (const item of items) {
      if (item.type === "gap") this.addGap(item.start, item.end);
      else this.addChunk(item.stream, item.start, decodeBase64(item.data));
    }
    this.trim();
    this.state = {
      cursor: page.nextCursor,
      attempt: page.attempt,
      restarted: this.state.restarted || (restarted && this.state.attempt !== null),
      receivedBytes: page.receivedBytes,
      totalBytes: page.totalBytes,
      retainedBytes: page.retainedBytes,
      serverTruncated: page.truncated,
      complete: page.complete,
      expiresAt: page.expiresAt == null ? null : new Date(page.expiresAt).toISOString(),
    };
    return this.snapshot();
  }

  snapshot(): OutputSnapshot {
    const { serverTruncated, ...state } = this.state;
    return {
      ...state,
      pieces: this.pieces.map((piece) => ({ ...piece })),
      truncated: serverTruncated || this.clientTrimmed || this.pieces.some((p) => p.type === "gap"),
    };
  }

  private addGap(start: number, end: number) {
    if (end <= this.end) return;
    const from = Math.max(start, this.end);
    // Bytes on either side of a gap never belong to the same character.
    this.decoders = CommandOutputBuffer.newDecoders();
    const last = this.pieces.at(-1);
    if (last?.type === "gap" && last.end >= from) last.end = end;
    else this.pieces.push({ type: "gap", start: from, end });
    this.end = end;
  }

  private addChunk(stream: OutputStream, offset: number, bytes: Uint8Array) {
    const chunkEnd = offset + bytes.length;
    if (chunkEnd <= this.end) return; // already held: a repeated page
    // A hole the server did not report is still not retained here.
    if (offset > this.end) this.addGap(this.end, offset);
    const fresh = offset < this.end ? bytes.subarray(this.end - offset) : bytes;
    const start = Math.max(offset, this.end);
    const text = displayText(this.decoders[stream].decode(fresh, { stream: true }));
    this.end = chunkEnd;
    this.textBytes += fresh.length;
    const last = this.pieces.at(-1);
    if (
      last?.type === "text" &&
      last.end === start &&
      last.end - last.start + fresh.length <= PIECE_MAX_BYTES &&
      (last.stream === stream || this.pieces.length >= PIECE_SOFT_CAP)
    ) {
      last.text += text;
      last.end = chunkEnd;
      if (last.stream !== stream) last.stream = "mixed";
      return;
    }
    this.pieces.push({ type: "text", stream, start, end: chunkEnd, text });
  }

  /**
   * Keep the head and the newest tail; the dropped middle becomes one gap.
   * The piece count is bounded on its own: sparse output (tiny chunks between
   * gaps) cannot merge, so past {@link PIECE_MAX_COUNT} the oldest text after
   * the head collapses into the surrounding gaps even below the byte budget.
   */
  private trim() {
    while (this.textBytes > BUFFER_MAX_BYTES) {
      const index = this.pieces.findIndex(
        (piece) => piece.type === "text" && piece.start >= OUTPUT_HEAD_BYTES,
      );
      if (index < 0) break;
      this.dropText(index);
    }
    while (this.pieces.length > PIECE_MAX_COUNT) {
      let index = this.pieces.findIndex(
        (piece) => piece.type === "text" && piece.start >= OUTPUT_HEAD_BYTES,
      );
      if (index < 0) index = this.pieces.findIndex((piece, i) => i > 0 && piece.type === "text");
      if (index < 0) return;
      this.dropText(index);
    }
  }

  private dropText(index: number) {
    const piece = this.pieces[index]!;
    this.textBytes -= piece.end - piece.start;
    this.clientTrimmed = true;
    const gap: OutputPiece = { type: "gap", start: piece.start, end: piece.end };
    const before = this.pieces[index - 1];
    const after = this.pieces[index + 1];
    if (before?.type === "gap" && before.end >= gap.start) {
      before.end = gap.end;
      this.pieces.splice(index, 1);
      if (after?.type === "gap" && after.start <= before.end) {
        before.end = Math.max(before.end, after.end);
        this.pieces.splice(index, 1);
      }
    } else if (after?.type === "gap" && after.start <= gap.end) {
      after.start = gap.start;
      this.pieces.splice(index, 1);
    } else {
      this.pieces[index] = gap;
    }
  }
}
