import {
  appendCommandOutput,
  buildCommandOutputPage,
  OUTPUT_MAX_HEAD_SEGMENTS,
  OUTPUT_MAX_TAIL_SEGMENTS,
  OUTPUT_PAGE_MAX_SEGMENTS,
  type OutputPageOperation,
  sealCommandOutput,
} from "@wssp/api/sandbox/command-output";
import { RelayFenceRejected } from "@wssp/api/sandbox/relay-fence";
import {
  base64ByteLength,
  type CommandOutputPageDto,
  commandOutputPageSchema,
  OUTPUT_HEAD_BYTES,
  OUTPUT_PAGE_MAX_BYTES,
  OUTPUT_PAGE_MAX_CHUNKS,
  OUTPUT_TAIL_BYTES,
} from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../../../crates/sandbox-protocol/fixtures/command_output.json";
import { commandOutputChunk } from "./command-output.js";
import {
  type FenceStore,
  installFenceTransaction,
  relayStore,
  storedCommandOutput,
} from "./fenced-prisma-harness.js";
import { encodeBinaryFrame, parseBinaryFrame, type StreamBinaryMetadata } from "./protocol.js";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);

let store: FenceStore;
beforeEach(() => {
  vi.clearAllMocks();
  store = relayStore("RUN_COMMAND", "RUNNING");
  installFenceTransaction(db, store);
});

const meta = (
  sequence: number,
  offset: number,
  stream: "stdout" | "stderr" = "stdout",
  extra: Partial<StreamBinaryMetadata> = {},
): StreamBinaryMetadata => ({
  type: "stream.chunk",
  streamId: "op-1",
  operationId: "op-1",
  generation: 1,
  attempt: 1,
  sequence,
  offset,
  flags: { [stream]: true },
  ...extra,
});
const append = (m: StreamBinaryMetadata, body: Uint8Array) =>
  prisma.$transaction((tx) =>
    appendCommandOutput(tx, { ...commandOutputChunk(m, body), operationId: "op-1" }),
  );
const seal = (totalBytes: number, attempt = 1) =>
  prisma.$transaction((tx) => sealCommandOutput(tx, { operationId: "op-1", attempt, totalBytes }));
const byteAt = (offset: number) => (offset * 31 + 7) & 0xff;

const operation = (state: OutputPageOperation["state"] = "RUNNING"): OutputPageOperation => ({
  id: "op-1",
  kind: "RUN_COMMAND",
  state,
  completedAt: state === "RUNNING" ? null : new Date("2026-09-26T00:00:00Z"),
  result: state === "RUNNING" ? null : { exitCode: 3, outputBytes: 0 },
});

/** One page exactly as the service reads it: header plus ≤ 65 segments ending after the cursor. */
function page(
  state: OutputPageOperation["state"],
  cursor?: string,
  maxBytes?: number,
  now = new Date("2026-09-26T01:00:00Z"),
): CommandOutputPageDto {
  const header = store.outputs.get("op-1") as never;
  const attempt = header ? Number((header as { attempt: number }).attempt) : 0;
  const [cursorAttempt, cursorOffset] = (cursor ?? "0_0").split("_").map(Number);
  const from = cursorAttempt === attempt ? cursorOffset! : 0;
  const segments = [...store.outputSegments.values()]
    .filter((row) => Number(row.endOffset) > from)
    .sort((a, b) => Number(a.startOffset) - Number(b.startOffset))
    .slice(0, OUTPUT_PAGE_MAX_SEGMENTS + 1) as never[];
  const built = buildCommandOutputPage({
    operation: operation(state),
    header,
    segments,
    cursor,
    maxBytes,
    now,
  });
  // Every page satisfies the public contract, including its byte budget.
  expect(commandOutputPageSchema.parse(built)).toEqual(built);
  return built;
}

/** Polls until no more is available; asserts cursors never revisit a range. */
function drain(state: OutputPageOperation["state"], maxBytes?: number) {
  const chunks: { offset: number; stream: string; data: Buffer }[] = [];
  const gaps: { start: number; end: number }[] = [];
  let cursor: string | undefined;
  let pages = 0;
  let position = 0;
  for (;;) {
    const next = page(state, cursor, maxBytes);
    pages++;
    expect(next.offset).toBe(position);
    let used = 0;
    const ranges = [
      ...next.chunks.map((chunk) => {
        const data = Buffer.from(chunk.data, "base64");
        used += data.length;
        chunks.push({ offset: chunk.offset, stream: chunk.stream, data });
        return { start: chunk.offset, end: chunk.offset + data.length };
      }),
      ...next.gaps,
    ].sort((a, b) => a.start - b.start);
    for (const range of ranges) {
      expect(range.start).toBe(position);
      position = range.end;
    }
    gaps.push(...next.gaps);
    expect(used).toBeLessThanOrEqual(maxBytes ?? OUTPUT_PAGE_MAX_BYTES);
    expect(next.chunks.length + next.gaps.length).toBeLessThanOrEqual(OUTPUT_PAGE_MAX_CHUNKS);
    expect(next.nextCursor).toBe(`1_${position}`);
    cursor = next.nextCursor;
    if (!next.hasMore) {
      const size = chunks.reduce((sum, chunk) => sum + chunk.data.length, 0);
      return { chunks, size, gaps, last: next, pages };
    }
  }
}

describe("durable command output store", () => {
  it("matches Rust binary fixtures without decoding split UTF-8", async () => {
    const body = Buffer.from(fixture.bodyHex, "hex");
    const encoded = encodeBinaryFrame(fixture.metadata as StreamBinaryMetadata, body);
    expect(Buffer.from(encoded).toString("hex")).toBe(fixture.frameHex);
    const parsed = parseBinaryFrame(encoded);
    expect([...parsed.body]).toEqual([0xe2, 0x82]);
    expect(parsed.metadata.offset).toBe(9);
    const chunk = commandOutputChunk(parsed.metadata, parsed.body);
    expect(chunk).toMatchObject({
      offset: 9,
      gapStart: fixture.metadata.gapStart,
      stderr: false,
    });
    expect([...chunk.body]).toEqual([0xe2, 0x82]);
  });

  it("retains the exact first 256 KiB and final 768 KiB of a >1 MiB interleaved run with a host gap", async () => {
    // 1.5 MiB in 8 KiB frames alternating stdout/stderr; the host dropped
    // [512 KiB, 640 KiB) and declared it with gapStart.
    const frame = 8192;
    const produced = 1.5 * 1024 * 1024;
    const hostGap = { start: 512 * 1024, end: 640 * 1024 };
    const received: [number, number][] = [];
    const streamOf = new Map<number, string>();
    let sequence = 0;
    let previousEnd = 0;
    for (let offset = 0; offset < produced; offset += frame) {
      if (offset >= hostGap.start && offset < hostGap.end) continue;
      const body = Uint8Array.from({ length: frame }, (_, i) => byteAt(offset + i));
      const stream = sequence % 2 ? "stderr" : "stdout";
      streamOf.set(offset, stream);
      await append(
        meta(sequence++, offset, stream, offset > previousEnd ? { gapStart: previousEnd } : {}),
        body,
      );
      received.push([offset, offset + frame]);
      previousEnd = offset + frame;
    }
    await seal(produced);
    // Expected: every received byte below 256 KiB, then the last 768 KiB received.
    const expected: number[] = [];
    for (const [start, end] of received) for (let o = start; o < end; o++) expected.push(o);
    const head = expected.filter((offset) => offset < OUTPUT_HEAD_BYTES);
    const tail = expected.filter((offset) => offset >= OUTPUT_HEAD_BYTES).slice(-OUTPUT_TAIL_BYTES);
    const stored = storedCommandOutput(store, "op-1")!;
    expect(stored.retained).toBe(OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES);
    expect(stored.retained).toBeLessThanOrEqual(1024 * 1024);
    // Bounded rows: 32 head + 96 tail segments of 8 KiB, never more.
    expect(stored.segments).toBe(128);
    expect(stored).toMatchObject({ receivedEnd: produced, totalBytes: produced });

    const { chunks, size, gaps, last } = drain("SUCCEEDED");
    expect(size).toBe(head.length + tail.length);
    const actual = Buffer.concat(chunks.map((chunk) => chunk.data));
    const wanted = Buffer.from([...head, ...tail].map(byteAt));
    expect(actual.equals(wanted)).toBe(true);
    expect(chunks[0]!.offset).toBe(0);
    expect(chunks.find((chunk) => chunk.offset >= OUTPUT_HEAD_BYTES)?.offset).toBe(tail[0]);
    for (const chunk of chunks) {
      // Stream identity is exact per frame; a chunk never spans two frames' streams.
      const frameStart = chunk.offset - (chunk.offset % frame);
      expect(chunk.offset + chunk.data.length).toBeLessThanOrEqual(frameStart + frame);
      expect(chunk.stream).toBe(streamOf.get(frameStart));
    }
    // Every dropped range is reported once: the head/tail cut already covers the host gap.
    expect(gaps).toEqual([{ start: OUTPUT_HEAD_BYTES, end: tail[0] }]);
    expect(last).toMatchObject({
      complete: true,
      truncated: true,
      exitCode: 3,
      totalBytes: produced,
      receivedBytes: produced,
      retainedBytes: OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES,
      hasMore: false,
    });
  });

  it("reports a host gap inside the retained tail and a trailing gap once the watermark commits", async () => {
    await append(meta(0, 0), new Uint8Array([1, 2, 3]));
    await append(meta(1, 10, "stderr", { gapStart: 3 }), new Uint8Array([4]));
    let result = drain("RUNNING");
    expect(result.gaps).toEqual([{ start: 3, end: 10 }]);
    expect(result.last).toMatchObject({ complete: false, receivedBytes: 11, totalBytes: null });
    await seal(20);
    result = drain("SUCCEEDED");
    expect(result.gaps).toEqual([
      { start: 3, end: 10 },
      { start: 11, end: 20 },
    ]);
    expect(result.last).toMatchObject({ complete: true, truncated: true, retainedBytes: 4 });
  });

  it("deduplicates exact retries, refuses conflicting replays, undeclared gaps and sealed output", async () => {
    const body = new Uint8Array([0xe2, 0x82]);
    await append(meta(0, 0), body);
    await append(meta(0, 0), body);
    expect(storedCommandOutput(store, "op-1")?.retained).toBe(2);
    await expect(append(meta(0, 0), new Uint8Array([9, 9]))).rejects.toThrow(
      "Conflicting output replay",
    );
    await expect(append(meta(1, 5), new Uint8Array([1]))).rejects.toThrow("Invalid output cursor");
    await expect(append(meta(2, 2), new Uint8Array([1]))).rejects.toThrow("Invalid output cursor");
    await expect(append(meta(1, 1), new Uint8Array([1]))).rejects.toThrow("Invalid output cursor");
    expect(() => commandOutputChunk(meta(1, 2), new Uint8Array(65537))).toThrow("metadata");
    expect(() =>
      commandOutputChunk({ ...meta(1, 2), flags: { stdout: true, stderr: true } }, body),
    ).toThrow("metadata");
    await seal(2);
    await expect(append(meta(1, 2), new Uint8Array([1]))).rejects.toBeInstanceOf(
      RelayFenceRejected,
    );
    // Even an exact replay cannot reopen committed output.
    await expect(append(meta(0, 0), body)).rejects.toBeInstanceOf(RelayFenceRejected);
    await seal(2);
    await expect(seal(3)).rejects.toBeInstanceOf(RelayFenceRejected);
    expect(storedCommandOutput(store, "op-1")).toMatchObject({ retained: 2, totalBytes: 2 });
  });

  it("a total below the stored bytes cannot commit, and a newer attempt discards older bytes", async () => {
    await append(meta(0, 0), new Uint8Array([1, 2, 3]));
    await expect(seal(2)).rejects.toBeInstanceOf(RelayFenceRejected);
    await append({ ...meta(0, 0), attempt: 2 }, new Uint8Array([7]));
    expect(storedCommandOutput(store, "op-1")).toMatchObject({ retained: 1, receivedEnd: 1 });
    await expect(append(meta(1, 3), new Uint8Array([1]))).rejects.toBeInstanceOf(
      RelayFenceRejected,
    );
    await expect(seal(1, 1)).rejects.toBeInstanceOf(RelayFenceRejected);
    // A cursor from attempt 1 restarts at 0 with reset=true instead of skipping attempt 2 bytes.
    const next = page("RUNNING", "1_3");
    expect(next).toMatchObject({ attempt: 2, reset: true, offset: 0, nextCursor: "2_1" });
    expect(next.chunks).toEqual([{ stream: "stdout", offset: 0, data: "Bw==" }]);
  });

  it("bounds rows when a host fragments output with a gap before every byte", async () => {
    let offset = 0;
    let sequence = 0;
    for (let n = 0; n < 400; n++) {
      const start = n === 0 ? 0 : offset + 1;
      await append(
        meta(sequence++, start, "stdout", n === 0 ? {} : { gapStart: offset }),
        new Uint8Array([n & 0xff]),
      );
      offset = start + 1;
    }
    // Head rows stop at their cap (later head bytes become gaps).
    const heads = [...store.outputSegments.values()].filter((row) => !row.tail).length;
    expect(heads).toBe(OUTPUT_MAX_HEAD_SEGMENTS);
    for (let n = 0; n < 400; n++) {
      const start = OUTPUT_HEAD_BYTES + n * 2;
      await append(meta(sequence++, start, "stderr", { gapStart: offset }), new Uint8Array([1]));
      offset = start + 1;
    }
    const tails = [...store.outputSegments.values()].filter((row) => row.tail).length;
    expect(tails).toBe(OUTPUT_MAX_TAIL_SEGMENTS);
    const { size, last } = drain("RUNNING");
    expect(size).toBe(OUTPUT_MAX_HEAD_SEGMENTS + OUTPUT_MAX_TAIL_SEGMENTS);
    expect(last.receivedBytes).toBe(offset);
  });

  it("repeat cursors return identical pages and never duplicate retained ranges", async () => {
    for (let n = 0; n < 12; n++)
      await append(meta(n, n * 8192, n % 3 ? "stdout" : "stderr"), new Uint8Array(8192).fill(n));
    const first = page("RUNNING");
    expect(first.chunks.reduce((sum, c) => sum + base64ByteLength(c.data), 0)).toBe(
      OUTPUT_PAGE_MAX_BYTES,
    );
    expect(first).toMatchObject({ hasMore: true, nextCursor: "1_65536", complete: false });
    expect(page("RUNNING", first.nextCursor)).toEqual(page("RUNNING", first.nextCursor));
    const second = page("RUNNING", first.nextCursor);
    expect(second.chunks[0]!.offset).toBe(65536);
    expect(second).toMatchObject({ hasMore: false, nextCursor: "1_98304" });
    // Caught up: the same cursor is an empty page, not a replay.
    expect(page("RUNNING", second.nextCursor)).toMatchObject({ chunks: [], gaps: [] });
    expect(() => page("RUNNING", "1_98305")).toThrow("Invalid output cursor");
    expect(() => page("RUNNING", "not-a-cursor")).toThrow("Invalid output cursor");
  });

  it("split UTF-8 decodes exactly per stream across chunk and page boundaries", async () => {
    const text = "héllo €uro 🙂 ok";
    const stdout = Buffer.from(text);
    const stderr = Buffer.from("⚠ warn");
    // Interleave: every byte of stdout alternates with a stderr byte, in 1-byte frames.
    let sequence = 0;
    let offset = 0;
    for (let i = 0; i < Math.max(stdout.length, stderr.length); i++) {
      if (i < stdout.length) await append(meta(sequence++, offset++), stdout.subarray(i, i + 1));
      if (i < stderr.length)
        await append(meta(sequence++, offset++, "stderr"), stderr.subarray(i, i + 1));
    }
    await seal(offset);
    const decoders = { stdout: new TextDecoder(), stderr: new TextDecoder() };
    const out = { stdout: "", stderr: "" };
    let cursor: string | undefined;
    for (;;) {
      const next = page("SUCCEEDED", cursor, 3);
      for (const chunk of next.chunks)
        out[chunk.stream] += decoders[chunk.stream].decode(Buffer.from(chunk.data, "base64"), {
          stream: true,
        });
      cursor = next.nextCursor;
      if (!next.hasMore) break;
    }
    out.stdout += decoders.stdout.decode();
    out.stderr += decoders.stderr.decode();
    expect(out).toEqual({ stdout: text, stderr: "⚠ warn" });
  });

  it("expires exactly 24 hours after completion with the status still intact (fake clock)", async () => {
    await append(meta(0, 0), new Uint8Array([1]));
    await seal(1);
    const completed = operation("SUCCEEDED").completedAt!.getTime();
    const before = page("SUCCEEDED", undefined, undefined, new Date(completed + 86_400_000 - 1));
    expect(before).toMatchObject({
      exitCode: 3,
      expiresAt: new Date(completed + 86_400_000).toISOString(),
    });
    let error: unknown;
    try {
      page("SUCCEEDED", undefined, undefined, new Date(completed + 86_400_000));
    } catch (thrown) {
      error = thrown;
    }
    expect(error).toMatchObject({ status: 410, data: { code: "OUTPUT_EXPIRED" } });
  });

  it("an operation with no output yet reads as an empty, incomplete page", () => {
    expect(page("RUNNING")).toMatchObject({
      attempt: 0,
      chunks: [],
      gaps: [],
      nextCursor: "0_0",
      complete: false,
      hasMore: false,
      receivedBytes: 0,
    });
    // A server-authored terminal state admits no further output: complete, nothing retained.
    expect(page("CANCELLED")).toMatchObject({ complete: true, truncated: false, totalBytes: null });
  });
});

describe("retention scheduling", () => {
  // The outbox passes have their own pg coverage (outbox-retention.pg.test.ts).
  beforeEach(async () => {
    const retention = await import("@wssp/api/sandbox/outbox-retention");
    vi.spyOn(retention, "pruneDeletedSandboxOutbox").mockResolvedValue({ deleted: 0, cursor: "" });
  });
  it("prunes the outbox after the result sweep, carrying the prune cursor", async () => {
    vi.useFakeTimers();
    vi.spyOn(
      await import("@wssp/api/sandbox/command-output"),
      "purgeExpiredCommandOutput",
    ).mockResolvedValue(0);
    const order: string[] = [];
    vi.spyOn(
      await import("@wssp/api/sandbox/operation-results"),
      "sweepOperationResults",
    ).mockImplementation(async () => {
      order.push("results");
      return "";
    });
    const retention = await import("@wssp/api/sandbox/outbox-retention");
    const prune = vi
      .spyOn(retention, "pruneDeletedSandboxOutbox")
      .mockImplementation(async (options) => {
        order.push("prune");
        return { deleted: 1, cursor: `${options?.cursor ?? ""}>next` };
      });
    const controller = new AbortController();
    const { startCommandOutputRetention } = await import("./command-output");
    const stop = startCommandOutputRetention(controller.signal, 100);
    try {
      await vi.advanceTimersByTimeAsync(1);
      expect(order).toEqual(["results", "prune"]);
      await vi.advanceTimersByTimeAsync(100);
      expect(prune.mock.calls.map(([options]) => options?.cursor)).toEqual(["", ">next"]);
    } finally {
      controller.abort();
      await stop();
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  });
  it("skips overlapping ticks and drains the in-flight sweep on abort", async () => {
    vi.useFakeTimers();
    const output = await import("@wssp/api/sandbox/command-output");
    const results = await import("@wssp/api/sandbox/operation-results");
    let release!: (value: number) => void;
    const blocked = new Promise<number>((resolve) => {
      release = resolve;
    });
    const purge = vi.spyOn(output, "purgeExpiredCommandOutput").mockReturnValue(blocked);
    const sweep = vi.spyOn(results, "sweepOperationResults").mockResolvedValue("");
    const controller = new AbortController();
    const { startCommandOutputRetention } = await import("./command-output");
    const stop = startCommandOutputRetention(controller.signal, 100);
    try {
      await vi.advanceTimersByTimeAsync(1000);
      expect(purge).toHaveBeenCalledTimes(1);
      controller.abort();
      let drained = false;
      const stopping = stop().then(() => {
        drained = true;
      });
      await Promise.resolve();
      expect(drained).toBe(false);
      release(0);
      await stopping;
      expect(sweep).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1000);
      expect(purge).toHaveBeenCalledTimes(1);
    } finally {
      release(0);
      await stop();
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  });
  it("drains expired output fully in bounded batches, then sweeps result owners", async () => {
    vi.useFakeTimers();
    const purge = vi.spyOn(
      await import("@wssp/api/sandbox/command-output"),
      "purgeExpiredCommandOutput",
    );
    // 25 full batches (more than the former 10-batch cap) and a short tail.
    for (let i = 0; i < 25; i++) purge.mockResolvedValueOnce(100);
    purge.mockResolvedValueOnce(40);
    const sweep = vi
      .spyOn(await import("@wssp/api/sandbox/operation-results"), "sweepOperationResults")
      .mockResolvedValue("last-owner");
    const controller = new AbortController();
    const { startCommandOutputRetention } = await import("./command-output");
    const stop = startCommandOutputRetention(controller.signal, 100);
    try {
      await vi.advanceTimersByTimeAsync(1);
      expect(purge).toHaveBeenCalledTimes(26);
      expect(purge.mock.calls.every(([, batch]) => batch === 100)).toBe(true);
      expect(sweep).toHaveBeenCalledTimes(1);
    } finally {
      controller.abort();
      await stop();
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  });
  it("stops a tick at its time budget and resumes the backlog on the next tick", async () => {
    vi.useFakeTimers();
    const purge = vi
      .spyOn(await import("@wssp/api/sandbox/command-output"), "purgeExpiredCommandOutput")
      .mockResolvedValue(100);
    const sweep = vi
      .spyOn(await import("@wssp/api/sandbox/operation-results"), "sweepOperationResults")
      .mockResolvedValue("");
    const controller = new AbortController();
    const { startCommandOutputRetention } = await import("./command-output");
    // A zero budget allows exactly one batch per tick.
    const stop = startCommandOutputRetention(controller.signal, 100, () => new Date(), 0);
    try {
      await vi.advanceTimersByTimeAsync(1);
      expect(purge).toHaveBeenCalledTimes(1);
      expect(sweep).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(100);
      expect(purge).toHaveBeenCalledTimes(2);
    } finally {
      controller.abort();
      await stop();
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  });
});

it("retention logs retain no supplied error name or message", async () => {
  vi.useFakeTimers();
  const sentinel = "private-retention-data";
  const output = await import("@wssp/api/sandbox/command-output");
  vi.spyOn(output, "purgeExpiredCommandOutput").mockRejectedValue(
    Object.assign(new Error(sentinel), { name: sentinel }),
  );
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const controller = new AbortController();
  const { startCommandOutputRetention } = await import("./command-output");
  const stop = startCommandOutputRetention(controller.signal, 100);
  try {
    await vi.advanceTimersByTimeAsync(1);
    expect(log).toHaveBeenCalled();
    expect(JSON.stringify(log.mock.calls)).not.toContain(sentinel);
  } finally {
    controller.abort();
    await stop();
    vi.restoreAllMocks();
    vi.useRealTimers();
  }
});
