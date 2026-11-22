import { createHash, randomBytes, randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { TRANSFER_MAX_BYTES as CAP, TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { sdkErrorResponse } from "../sandbox-api/errors.js";
import {
  type DownloadSource,
  downloadBody,
  registerDownloadRoutes,
  selectRange,
} from "./download-routes.js";
import { transferSlotsInUse } from "./http-admission.js";

const state = vi.hoisted(() => ({ store: { downloadSource: vi.fn() } }));
vi.mock("./runtime.js", () => ({ transferStore: () => state.store }));
vi.mock("@wssp/env/server", () => ({
  env: { TRANSFER_GLOBAL_ACTIVE: 16, TRANSFER_OWNER_ACTIVE: 4 },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
const principal: Principal = { kind: "session", ownerId: "owner" };
const operationId = randomUUID();
let app: Hono<SandboxApiEnv>;
beforeEach(() => {
  vi.clearAllMocks();
  app = new Hono<SandboxApiEnv>();
  app.onError((error, c) => sdkErrorResponse(c, error));
  app.use("*", async (c, next) => {
    c.set("requestId", randomUUID());
    await next();
  });
  registerDownloadRoutes(app, async () => principal);
});
afterEach(() => {
  vi.useRealTimers();
  expect(transferSlotsInUse()).toBe(0);
});

/** Arbitrary bytes of any size without materializing them: chunk k is a
 * random 1 MiB block with every byte XORed with `k & 255`, so a byte taken from
 * another chunk less than 256 chunks away always differs. Built a 32-bit word
 * at a time; the bytes are the same as a per-byte XOR. */
const block = randomBytes(CHUNK);
function chunkAt(index: number) {
  const chunk = Buffer.allocUnsafeSlow(CHUNK);
  block.copy(chunk);
  const salt = (index & 255) * 0x01010101;
  if (salt !== 0) {
    const words = new Uint32Array(chunk.buffer, chunk.byteOffset, CHUNK / 4);
    for (let i = 0; i < words.length; i++) words[i]! ^= salt;
  }
  return chunk;
}
function generated(size: number) {
  const reads: [number, number][] = [];
  const bytesAt = (offset: number, length: number) => {
    const out = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; ) {
      const at = offset + i;
      const inChunk = at % CHUNK;
      const n = Math.min(length - i, CHUNK - inChunk);
      chunkAt(Math.floor(at / CHUNK)).copy(out, i, inChunk, inChunk + n);
      i += n;
    }
    return out;
  };
  const whole = createHash("sha256");
  for (let offset = 0; offset < size; offset += CHUNK)
    whole.update(bytesAt(offset, Math.min(CHUNK, size - offset)));
  const source: DownloadSource = {
    size,
    sha256: whole.digest("hex"),
    guestPath: "/home/user/big.bin",
    read: async (offset, length) => {
      if (offset < 0 || length > CHUNK || offset + length > size) throw new Error("bad read");
      reads.push([offset, length]);
      return bytesAt(offset, length);
    },
    delivered: vi.fn<(offset: number, length: number) => void>(),
    close: vi.fn<() => void>(),
  };
  return { source, reads };
}
/** Counting sink: hashes the stream without keeping it; `stopAt` models a disconnect. */
async function drain(
  response: Response,
  stopAt = Number.POSITIVE_INFINITY,
  hash = createHash("sha256"),
) {
  const reader = response.body!.getReader();
  let size = 0;
  let largest = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    hash.update(value);
    size += value.byteLength;
    largest = Math.max(largest, value.byteLength);
    if (size >= stopAt) {
      await reader.cancel();
      break;
    }
  }
  return { size, largest, hash };
}
const get = (headers: Record<string, string> = {}, method = "GET") =>
  app.request(`/operations/${operationId}/content`, { method, headers });

it("generated chunks differ at every byte from any chunk under 256 away", () => {
  // A byte served from the wrong chunk (the 32 MiB + 1 case's last byte from
  // chunk 31, say) changes the stream and so its hash.
  for (const [a, b] of [
    [31, 32],
    [0, 1],
    [0, 255],
    [255, 256],
    [700, 701],
  ] as const) {
    const left = chunkAt(a);
    const right = chunkAt(b);
    for (let i = 0; i < CHUNK; i++)
      if (left[i] === right[i]) expect.fail(`chunks ${a}/${b} at ${i}`);
  }
});

it.each([5 * 1024 * 1024, 7.5 * 1024 * 1024, 32 * 1024 * 1024 + 1, CAP])(
  "streams %i arbitrary bytes whole and resumed by range with one SHA-256",
  async (size) => {
    const { source, reads } = generated(size);
    state.store.downloadSource.mockResolvedValue(source);
    const whole = await get();
    expect(whole.status).toBe(200);
    expect(whole.headers.get("content-length")).toBe(String(size));
    expect(whole.headers.get("etag")).toBe(`"${source.sha256}"`);
    const full = await drain(whole);
    expect(full.size).toBe(size);
    expect(full.largest).toBeLessThanOrEqual(CHUNK);
    expect(full.hash.digest("hex")).toBe(source.sha256);
    // Pull-based: exactly one read per durable chunk, never ahead of the consumer.
    expect(reads).toHaveLength(Math.ceil(size / CHUNK));
    expect(transferSlotsInUse()).toBe(0);

    // Interrupted mid-way, then resumed from the received offset against the same ETag.
    reads.length = 0;
    const cut = Math.floor(size / 2) + 17;
    const joined = createHash("sha256");
    const first = await drain(await get(), cut, joined);
    expect(transferSlotsInUse()).toBe(0);
    expect(reads.length).toBeLessThanOrEqual(Math.ceil(cut / CHUNK) + 1);
    const resumed = await get({ range: `bytes=${first.size}-`, "if-range": `"${source.sha256}"` });
    expect(resumed.status).toBe(206);
    expect(resumed.headers.get("content-range")).toBe(`bytes ${first.size}-${size - 1}/${size}`);
    // The interrupted prefix and the resumed suffix hash to the whole capture.
    const rest = await drain(resumed, Number.POSITIVE_INFINITY, joined);
    expect(first.size + rest.size).toBe(size);
    expect(joined.digest("hex")).toBe(source.sha256);
    expect(state.store.downloadSource).toHaveBeenCalledTimes(3);
  },
  300_000,
);

it("selects one satisfiable range and rejects every other form with 416", () => {
  const etag = `"${"a".repeat(64)}"`;
  expect(selectRange(undefined, undefined, 10, etag)).toBeNull();
  expect(selectRange("bytes=0-", undefined, 10, etag)).toEqual({ start: 0, end: 9 });
  expect(selectRange("bytes=2-4", etag, 10, etag)).toEqual({ start: 2, end: 4 });
  expect(selectRange("bytes=8-100", undefined, 10, etag)).toEqual({ start: 8, end: 9 });
  expect(selectRange("bytes=-3", undefined, 10, etag)).toEqual({ start: 7, end: 9 });
  expect(selectRange("bytes=-30", undefined, 10, etag)).toEqual({ start: 0, end: 9 });
  // If-Range is a strong comparison: anything else sends the whole content.
  for (const validator of [`W/${etag}`, `"${"b".repeat(64)}"`, "Sat, 26 Sep 2026 00:00:00 GMT"])
    expect(selectRange("bytes=2-4", validator, 10, etag)).toBeNull();
  for (const range of [
    "bytes=10-",
    "bytes=5-4",
    "bytes=-0",
    "bytes=0-1,3-4",
    "bytes=0-1, 3-4",
    "bytes= 0-1",
    "bytes=",
    "bytes=-",
    "items=0-1",
    "bytes=1234567890123456-",
    "bytes=0x1-2",
  ])
    expect(() => selectRange(range, undefined, 10, etag), range).toThrow(
      expect.objectContaining({ status: 416 }),
    );
  expect(() => selectRange("bytes=0-", undefined, 0, etag)).toThrow(
    expect.objectContaining({ status: 416 }),
  );
});

it("answers HEAD and refused ranges without reading content or keeping a slot", async () => {
  const { source, reads } = generated(3 * CHUNK);
  state.store.downloadSource.mockResolvedValue(source);
  const head = await get({}, "HEAD");
  expect(head.status).toBe(200);
  expect(head.headers.get("content-length")).toBe(String(3 * CHUNK));
  const ranged = await get({ range: "bytes=-5" }, "HEAD");
  expect(ranged.status).toBe(206);
  expect(ranged.headers.get("content-length")).toBe("5");
  const refused = await get({ range: "bytes=0-1,5-6" });
  expect(refused.status).toBe(416);
  expect(refused.headers.get("content-range")).toBe(`bytes */${3 * CHUNK}`);
  expect(((await refused.json()) as { error: { code: string } }).error.code).toBe(
    "RANGE_NOT_SATISFIABLE",
  );
  expect(reads).toHaveLength(0);
});

it("admits four streams per owner and releases each on completion or cancel", async () => {
  const { source } = generated(3 * CHUNK);
  state.store.downloadSource.mockResolvedValue(source);
  const open = await Promise.all([get(), get(), get(), get()]);
  expect(open.map((r) => r.status)).toEqual([200, 200, 200, 200]);
  expect(transferSlotsInUse()).toBe(4);
  const refused = await get();
  expect(refused.status).toBe(429);
  expect(state.store.downloadSource).toHaveBeenCalledTimes(4);
  await open[0]!.body!.cancel();
  await drain(open[1]!);
  expect(transferSlotsInUse()).toBe(2);
  const reopened = await get();
  expect(reopened.status).toBe(200);
  expect(transferSlotsInUse()).toBe(3);
  for (const response of [...open.slice(2), reopened]) await response.body?.cancel();
  expect(transferSlotsInUse()).toBe(0);
  // A refused lookup (not ready, expired, forbidden) returns its slot at once.
  state.store.downloadSource.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
  expect((await get()).status).toBe(500);
});

it("ends a stalled consumer's stream at the idle deadline and releases once", async () => {
  vi.useFakeTimers();
  const { source, reads } = generated(3 * CHUNK);
  const release = vi.fn();
  const stream = downloadBody(source, 0, source.size, release, 1000);
  const reader = stream.getReader();
  expect((await reader.read()).value?.byteLength).toBe(CHUNK);
  // The consumer stops pulling; nothing more is read while it stalls.
  await vi.advanceTimersByTimeAsync(999);
  expect(release).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  expect(release).toHaveBeenCalledTimes(1);
  await expect(reader.read()).rejects.toMatchObject({ status: 410 });
  expect(reads).toHaveLength(1);
  await reader.cancel().catch(() => {});
  expect(release).toHaveBeenCalledTimes(1);
});

it("fails the stream on a short or failed read and releases exactly once", async () => {
  for (const read of [
    async () => new Uint8Array(1),
    async () => {
      throw Object.assign(new Error("gone"), { status: 410 });
    },
  ]) {
    const release = vi.fn();
    const delivered = vi.fn();
    const source: DownloadSource = {
      size: 10,
      sha256: "a".repeat(64),
      guestPath: "/f",
      read,
      delivered,
      close: vi.fn(),
    };
    const reader = downloadBody(source, 0, 10, release).getReader();
    await expect(reader.read()).rejects.toBeTruthy();
    expect(release).toHaveBeenCalledTimes(1);
    expect(delivered).not.toHaveBeenCalled();
  }
});

it("E-17 credits a chunk only once the consumer pulls past it, and the end only on the final pull", async () => {
  const { source } = generated(2 * CHUNK + 5);
  const delivered = vi.mocked(source.delivered);
  const release = vi.fn();
  const reader = downloadBody(source, 0, source.size, release).getReader();
  expect((await reader.read()).value?.byteLength).toBe(CHUNK);
  expect(delivered).not.toHaveBeenCalled();
  expect((await reader.read()).value?.byteLength).toBe(CHUNK);
  expect(delivered.mock.calls).toEqual([[0, CHUNK]]);
  expect((await reader.read()).value?.byteLength).toBe(5);
  expect(delivered.mock.calls).toEqual([
    [0, CHUNK],
    [CHUNK, CHUNK],
  ]);
  // The last chunk is handed over but not yet credited; the response is open.
  expect(release).not.toHaveBeenCalled();
  expect((await reader.read()).done).toBe(true);
  expect(delivered.mock.calls).toEqual([
    [0, CHUNK],
    [CHUNK, CHUNK],
    [2 * CHUNK, 5],
    [2 * CHUNK + 5, 0],
  ]);
  expect(release).toHaveBeenCalledTimes(1);
});

it("E-17 a cancelled stream never credits the chunk still in flight", async () => {
  const { source } = generated(3 * CHUNK);
  const delivered = vi.mocked(source.delivered);
  const release = vi.fn();
  const reader = downloadBody(source, CHUNK, source.size, release).getReader();
  expect((await reader.read()).value?.byteLength).toBe(CHUNK);
  await reader.cancel();
  expect(delivered).not.toHaveBeenCalled();
  expect(release).toHaveBeenCalledTimes(1);
});

it("E-17 an empty body is delivered only when the consumer reads it", async () => {
  const delivered = vi.fn();
  const release = vi.fn();
  const source: DownloadSource = {
    size: 0,
    sha256: "a".repeat(64),
    guestPath: "/f",
    read: async () => new Uint8Array(),
    delivered,
    close: vi.fn(),
  };
  const reader = downloadBody(source, 0, 0, release).getReader();
  expect(delivered).not.toHaveBeenCalled();
  expect(release).not.toHaveBeenCalled();
  expect((await reader.read()).done).toBe(true);
  expect(delivered.mock.calls).toEqual([[0, 0]]);
  expect(release).toHaveBeenCalledTimes(1);
});

it("E-17 closes the capture stream exactly once per response, including HEAD and 416", async () => {
  const { source } = generated(3 * CHUNK);
  state.store.downloadSource.mockResolvedValue(source);
  const close = vi.mocked(source.close);
  await get({}, "HEAD");
  expect(close).toHaveBeenCalledTimes(1);
  await get({ range: "bytes=0-1,5-6" });
  expect(close).toHaveBeenCalledTimes(2);
  await drain(await get());
  expect(close).toHaveBeenCalledTimes(3);
  await (await get()).body!.cancel();
  expect(close).toHaveBeenCalledTimes(4);
});

it("S0 cancel during a blocked read never enqueues late bytes or releases twice", async () => {
  const { source } = generated(1);
  let entered!: () => void;
  let resume!: () => void;
  const reached = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    resume = resolve;
  });
  source.read = async () => {
    entered();
    await held;
    return new Uint8Array([1]);
  };
  const release = vi.fn();
  const reader = downloadBody(source, 0, 1, release).getReader();
  const pending = reader.read();
  await reached;
  await reader.cancel();
  resume();
  expect(await pending).toEqual({ done: true, value: undefined });
  // Drain the blocked pull's continuations, including its post-read gate.
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(release).toHaveBeenCalledTimes(1);
  expect(source.delivered).not.toHaveBeenCalled();
});

it.each(["before", "after"])(
  "revocation %s the last chunk preserves delivery boundaries and releases once",
  async (when) => {
    const { source, reads } = generated(CHUNK + 1);
    const release = vi.fn();
    let revoked = false;
    const authorize = vi.fn(async () => {
      if (revoked) throw new ORPCError("UNAUTHORIZED");
    });
    const reader = downloadBody(source, 0, source.size, release, 60000, authorize).getReader();
    expect((await reader.read()).value?.byteLength).toBe(CHUNK);
    if (when === "after") expect((await reader.read()).value?.byteLength).toBe(1);
    revoked = true;
    if (when === "after") {
      expect(await reader.read()).toEqual({ done: true, value: undefined });
      expect(reads).toHaveLength(2);
      expect(authorize).toHaveBeenCalledTimes(4); // two checks per data pull, none for close
      expect(vi.mocked(source.delivered).mock.calls).toEqual([
        [0, CHUNK],
        [CHUNK, 1],
        [CHUNK + 1, 0],
      ]);
    } else {
      await expect(reader.read()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
      expect(reads).toHaveLength(1);
      expect(source.delivered).not.toHaveBeenCalled();
    }
    expect(release).toHaveBeenCalledTimes(1);
  },
);
