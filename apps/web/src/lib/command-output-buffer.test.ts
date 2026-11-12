import { OUTPUT_HEAD_BYTES } from "@wssp/api/sandbox/contracts";
import { describe, expect, it } from "vitest";

import {
  BUFFER_MAX_BYTES,
  CommandOutputBuffer,
  displayInlineText,
  displayText,
  type OutputPage,
  type OutputPiece,
  PIECE_MAX_BYTES,
  PIECE_MAX_COUNT,
  PIECE_SOFT_CAP,
} from "./command-output-buffer";

/**
 * C48 browser output buffer: cursor-exact accumulation of server pages,
 * explicit gaps, attempt resets, UTF-8 split across chunks, text-only
 * sanitizing, and the node/byte bounds that keep a noisy command from
 * growing the page without limit.
 */

const b64 = (text: string | Uint8Array) =>
  Buffer.from(typeof text === "string" ? new TextEncoder().encode(text) : text).toString("base64");

function page(overrides: Partial<OutputPage> = {}): OutputPage {
  return {
    attempt: 1,
    reset: false,
    chunks: [],
    gaps: [],
    nextCursor: "1_0",
    hasMore: false,
    receivedBytes: 0,
    totalBytes: null,
    retainedBytes: 0,
    truncated: false,
    complete: false,
    expiresAt: null,
    ...overrides,
  };
}

const text = (pieces: readonly OutputPiece[]) =>
  pieces
    .map((piece) => (piece.type === "text" ? piece.text : `[gap ${piece.start}-${piece.end}]`))
    .join("");

describe("CommandOutputBuffer", () => {
  it("appends pages in cursor order and keeps the server's next cursor", () => {
    const buffer = new CommandOutputBuffer();
    buffer.apply(
      page({ chunks: [{ stream: "stdout", offset: 0, data: b64("hello ") }], nextCursor: "1_6" }),
    );
    const snap = buffer.apply(
      page({
        chunks: [
          { stream: "stderr", offset: 6, data: b64("warn ") },
          { stream: "stdout", offset: 11, data: b64("world") },
        ],
        nextCursor: "1_16",
      }),
    );
    expect(text(snap.pieces)).toBe("hello warn world");
    expect(snap.pieces.map((piece) => piece.type === "text" && piece.stream)).toEqual([
      "stdout",
      "stderr",
      "stdout",
    ]);
    expect(snap.cursor).toBe("1_16");
  });

  it("a repeated or overlapping page adds nothing twice", () => {
    const buffer = new CommandOutputBuffer();
    const first = page({ chunks: [{ stream: "stdout", offset: 0, data: b64("abcdef") }] });
    buffer.apply(first);
    buffer.apply(first);
    const snap = buffer.apply(
      page({ chunks: [{ stream: "stdout", offset: 3, data: b64("defghi") }] }),
    );
    expect(text(snap.pieces)).toBe("abcdefghi");
  });

  it("shows server gaps and unexplained holes as explicit gap markers", () => {
    const buffer = new CommandOutputBuffer();
    const snap = buffer.apply(
      page({
        chunks: [
          { stream: "stdout", offset: 0, data: b64("head") },
          { stream: "stdout", offset: 100, data: b64("tail") },
          { stream: "stdout", offset: 110, data: b64("!") },
        ],
        gaps: [{ start: 4, end: 100 }],
        truncated: true,
      }),
    );
    expect(text(snap.pieces)).toBe("head[gap 4-100]tail[gap 104-110]!");
    expect(snap.truncated).toBe(true);
  });

  it("a page for a newer dispatch attempt starts over", () => {
    const buffer = new CommandOutputBuffer();
    buffer.apply(page({ chunks: [{ stream: "stdout", offset: 0, data: b64("first try") }] }));
    const snap = buffer.apply(
      page({
        attempt: 2,
        reset: true,
        chunks: [{ stream: "stdout", offset: 0, data: b64("second") }],
      }),
    );
    expect(text(snap.pieces)).toBe("second");
    expect(snap.restarted).toBe(true);
    expect(snap.attempt).toBe(2);
  });

  it("decodes a UTF-8 character split across chunks once", () => {
    const bytes = new TextEncoder().encode("é✓");
    const buffer = new CommandOutputBuffer();
    buffer.apply(
      page({ chunks: [{ stream: "stdout", offset: 0, data: b64(bytes.subarray(0, 1)) }] }),
    );
    buffer.apply(
      page({ chunks: [{ stream: "stdout", offset: 1, data: b64(bytes.subarray(1, 3)) }] }),
    );
    const snap = buffer.apply(
      page({ chunks: [{ stream: "stdout", offset: 3, data: b64(bytes.subarray(3)) }] }),
    );
    expect(text(snap.pieces)).toBe("é✓");
  });

  it("keeps the rendered piece count bounded when streams alternate every byte", () => {
    const buffer = new CommandOutputBuffer();
    let offset = 0;
    let snap = buffer.snapshot();
    for (let round = 0; round < 20; round++) {
      const chunks: OutputPage["chunks"] = [];
      for (let i = 0; i < 1000; i++) {
        chunks.push({ stream: i % 2 === 0 ? "stdout" : "stderr", offset, data: b64("x") });
        offset += 1;
      }
      snap = buffer.apply(page({ chunks }));
    }
    expect(text(snap.pieces)).toBe("x".repeat(20_000));
    expect(snap.pieces.length).toBeLessThanOrEqual(PIECE_SOFT_CAP + 2);
    for (const piece of snap.pieces)
      expect(piece.end - piece.start).toBeLessThanOrEqual(PIECE_MAX_BYTES);
  });

  it("keeps the head and the newest tail of a live stream larger than the server keeps", () => {
    const buffer = new CommandOutputBuffer();
    const block = "y".repeat(8 * 1024);
    let offset = 0;
    let snap = buffer.snapshot();
    // 2 MiB streamed live, 8 KiB at a time.
    for (let i = 0; i < 256; i++) {
      snap = buffer.apply(page({ chunks: [{ stream: "stdout", offset, data: b64(block) }] }));
      offset += block.length;
    }
    const kept = snap.pieces
      .filter((piece) => piece.type === "text")
      .reduce((sum, piece) => sum + (piece.end - piece.start), 0);
    expect(kept).toBeLessThanOrEqual(BUFFER_MAX_BYTES);
    expect(kept).toBeGreaterThan(BUFFER_MAX_BYTES - PIECE_MAX_BYTES);
    const first = snap.pieces[0]!;
    const last = snap.pieces.at(-1)!;
    expect(first).toMatchObject({ type: "text", start: 0 });
    expect(last).toMatchObject({ type: "text", end: offset });
    const gaps = snap.pieces.filter((piece) => piece.type === "gap");
    expect(gaps).toHaveLength(1);
    expect(snap.truncated).toBe(true);
  });

  it.each([
    ["past the head", OUTPUT_HEAD_BYTES],
    ["inside the head", 0],
  ])("keeps the piece count bounded for sparse, gap-heavy output %s", (_label, base) => {
    const buffer = new CommandOutputBuffer();
    let offset = base;
    let snap = buffer.snapshot();
    // Ten pages of a thousand one-byte chunks, each after a dropped range.
    for (let round = 0; round < 10; round++) {
      const chunks: OutputPage["chunks"] = [];
      const gaps: OutputPage["gaps"] = [];
      for (let i = 0; i < 1000; i++) {
        gaps.push({ start: offset, end: offset + 1 });
        chunks.push({ stream: i % 2 ? "stderr" : "stdout", offset: offset + 1, data: b64("s") });
        offset += 2;
      }
      snap = buffer.apply(page({ chunks, gaps, truncated: true }));
      expect(snap.pieces.length).toBeLessThanOrEqual(PIECE_MAX_COUNT);
    }
    // Far below the byte budget, yet bounded; the newest output survives.
    expect(snap.pieces.length).toBeLessThanOrEqual(PIECE_MAX_COUNT);
    expect(snap.pieces.at(-1)).toMatchObject({ type: "text", end: offset, text: "s" });
    // Pieces stay ordered and contiguous: every byte is text or inside a gap.
    for (let i = 1; i < snap.pieces.length; i++)
      expect(snap.pieces[i]!.start).toBe(snap.pieces[i - 1]!.end);
    expect(snap.truncated).toBe(true);
  });
});

describe("displayText", () => {
  it("replaces ESC, other C0 controls, DEL and lone CR with visible pictures", () => {
    expect(displayText("\u001b[31mred\u001b[0m")).toBe("␛[31mred␛[0m");
    expect(displayText("a\u0007b\u0000c\u007f")).toBe("a␇b␀c␡");
    expect(displayText("line\r\nnext\rover")).toBe("line\nnext␍over");
    expect(displayText("tab\tnewline\n")).toBe("tab\tnewline\n");
    // The one-byte C1 CSI (U+009B) is a terminal escape too.
    expect(displayText("\u009b31mX")).toBe("⟨U+009B⟩31mX");
  });

  it("makes bidi overrides visible instead of reordering the text", () => {
    expect(displayText("abc\u202Edcb")).toBe("abc⟨U+202E⟩dcb");
    expect(displayText("\u2066x\u2069")).toBe("⟨U+2066⟩x⟨U+2069⟩");
  });

  it("leaves markup as literal text (React renders it as a text node)", () => {
    expect(displayText("<script>alert(1)</script>")).toBe("<script>alert(1)</script>");
  });
});

it("inline labels distinguish literal backslashes from escaped line and tab breaks", () => {
  expect(displayInlineText("a\\nb")).toBe("a\\\\nb");
  expect(displayInlineText("a\nb")).toBe("a\\nb");
  expect(displayInlineText("a\\tb")).toBe("a\\\\tb");
  expect(displayInlineText("a\tb")).toBe("a\\tb");
});

it("neutralizes Unicode separators and the Cf class, including supplementary formatting", () => {
  const hostile = "\u2028\u2029\u200B\u200C\u200D\u2060\uFEFF\u00AD\u{E0001}";
  const safe = "⟨U+2028⟩⟨U+2029⟩⟨U+200B⟩⟨U+200C⟩⟨U+200D⟩⟨U+2060⟩⟨U+FEFF⟩⟨U+00AD⟩⟨U+E0001⟩";
  expect(displayText(hostile)).toBe(safe);
  expect(displayInlineText(hostile)).toBe(safe);
});
