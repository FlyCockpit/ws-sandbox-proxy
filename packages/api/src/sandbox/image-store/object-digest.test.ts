import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import {
  IMAGE_ENCRYPTION_RECORD_BYTES as RECORD,
  IMAGE_ENCRYPTION_TAG_BYTES as TAG,
} from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { digestImageObject } from "./object-digest";
import { decryptImageStream, encryptRecord } from "./s3";
import {
  ImageIntegrityError,
  isTerminalImageVerificationError,
  VerifyCancelledError,
} from "./verification-errors";

const key = Buffer.alloc(32, 9);

function seal(plain: Buffer): Buffer {
  const records = Math.max(1, Math.ceil(plain.length / RECORD));
  const out: Buffer[] = [];
  for (let i = 0; i < records; i++)
    out.push(
      encryptRecord(key, i, i === records - 1, plain.subarray(i * RECORD, (i + 1) * RECORD)),
    );
  return Buffer.concat(out);
}

/** The stored bytes as an object-store body: chunks of `size` bytes. */
async function* chunked(bytes: Buffer, size = 64 * 1024): AsyncGenerator<Uint8Array> {
  for (let at = 0; at < bytes.length; at += size) yield bytes.subarray(at, at + size);
}

const fingerprint = (plain: Buffer) => `sha256:${createHash("sha256").update(plain).digest("hex")}`;

describe("digestImageObject", () => {
  it.each([0, 5, RECORD, RECORD + 1, 3 * RECORD - 7])(
    "matches encryptRecord and the reference decryptImageStream for %i plaintext bytes",
    async (length) => {
      const plain = Buffer.alloc(length);
      for (let i = 0; i < length; i++) plain[i] = (i * 31) & 0xff;
      const sealed = seal(plain);
      const digest = await digestImageObject(chunked(sealed, 7_001), {
        key,
        plainSize: length,
      });
      expect(digest).toEqual({ size: BigInt(length), fingerprint: fingerprint(plain) });
      const reference: Buffer[] = [];
      for await (const chunk of decryptImageStream(key, length, chunked(sealed, 7_001)))
        reference.push(chunk);
      expect(Buffer.concat(reference).equals(plain)).toBe(true);
    },
  );

  it("hashes an unencrypted object as is", async () => {
    const plain = Buffer.from("template image bytes");
    expect(await digestImageObject(chunked(plain, 3), { key: null, plainSize: 0 })).toEqual({
      size: BigInt(plain.length),
      fingerprint: fingerprint(plain),
    });
  });

  it.each(["tamper", "truncate", "trailing", "wrong key", "reordered"])(
    "%s is a terminal integrity failure",
    async (mode) => {
      const plain = Buffer.alloc(2 * RECORD + 3, 1);
      let sealed = seal(plain);
      if (mode === "tamper") sealed[RECORD + 5] = (sealed[RECORD + 5] ?? 0) ^ 1;
      if (mode === "truncate") sealed = sealed.subarray(0, sealed.length - 1);
      if (mode === "trailing") sealed = Buffer.concat([sealed, Buffer.alloc(1)]);
      if (mode === "reordered")
        sealed = Buffer.concat([
          sealed.subarray(RECORD + TAG, 2 * (RECORD + TAG)),
          sealed.subarray(0, RECORD + TAG),
          sealed.subarray(2 * (RECORD + TAG)),
        ]);
      const failure = await digestImageObject(chunked(sealed), {
        key: mode === "wrong key" ? Buffer.alloc(32, 1) : key,
        plainSize: plain.length,
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ImageIntegrityError);
      expect(isTerminalImageVerificationError(failure)).toBe(true);
    },
  );

  it("rethrows a store or network failure as is (retryable, never a verdict)", async () => {
    const failure = new Error("socket hang up");
    const body = (async function* () {
      yield Buffer.alloc(10);
      throw failure;
    })();
    await expect(digestImageObject(body, { key, plainSize: 10 })).rejects.toBe(failure);
    expect(isTerminalImageVerificationError(failure)).toBe(false);
  });

  it("stops on cancel with VerifyCancelledError", async () => {
    const plain = Buffer.alloc(40 * RECORD, 2);
    const sealed = seal(plain);
    const shutdown = new AbortController();
    const body = (async function* () {
      let sent = 0;
      for await (const chunk of chunked(sealed, RECORD)) {
        if (++sent === 4) shutdown.abort("worker shutdown");
        yield chunk;
      }
    })();
    await expect(
      digestImageObject(body, { key, plainSize: plain.length, signal: shutdown.signal }),
    ).rejects.toBeInstanceOf(VerifyCancelledError);
  });

  /** A body that sends `first`, then stalls until closed (a hung object-store read). */
  function stalling(first: Buffer) {
    let closed = false;
    const body: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        let sent = false;
        return {
          next: () => {
            if (!sent) {
              sent = true;
              return Promise.resolve({ value: first, done: false });
            }
            return new Promise<IteratorResult<Uint8Array>>(() => {});
          },
          return: () => {
            closed = true;
            return Promise.resolve({ value: undefined, done: true });
          },
        };
      },
    };
    return { body, closed: () => closed };
  }

  it("a worker failure ends the digest while the source read is stalled, and closes the source", async () => {
    const plain = Buffer.alloc(3 * RECORD, 4);
    const sealed = seal(plain);
    sealed[3] = (sealed[3] ?? 0) ^ 1;
    const source = stalling(sealed.subarray(0, RECORD + TAG));
    await expect(
      digestImageObject(source.body, { key, plainSize: plain.length }),
    ).rejects.toBeInstanceOf(ImageIntegrityError);
    expect(source.closed()).toBe(true);
  });

  it("an S3-style Node stream is destroyed when the digest fails while its next read stalls", async () => {
    const plain = Buffer.alloc(3 * RECORD, 4);
    const sealed = seal(plain);
    sealed[3] = (sealed[3] ?? 0) ^ 1;
    // Pushes one record, then never more data (a hung response).
    const stream = new Readable({ read() {} });
    stream.push(sealed.subarray(0, RECORD + TAG));
    await expect(
      digestImageObject(stream, { key, plainSize: plain.length }),
    ).rejects.toBeInstanceOf(ImageIntegrityError);
    expect(stream.destroyed).toBe(true);
  });

  it("bytes past the last record are refused while reading, not at the end", async () => {
    const plain = Buffer.from("short");
    // The whole object plus trailing junk, then a stall: no EOF ever comes.
    const source = stalling(Buffer.concat([seal(plain), Buffer.alloc(64)]));
    await expect(
      digestImageObject(source.body, { key, plainSize: plain.length }),
    ).rejects.toBeInstanceOf(ImageIntegrityError);
    expect(source.closed()).toBe(true);
  });

  it("a cancel ends the digest while the source read is stalled", async () => {
    const source = stalling(Buffer.alloc(10));
    const shutdown = new AbortController();
    const pending = digestImageObject(source.body, {
      key,
      plainSize: 3 * RECORD,
      signal: shutdown.signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    shutdown.abort("worker shutdown");
    await expect(pending).rejects.toBeInstanceOf(VerifyCancelledError);
    expect(source.closed()).toBe(true);
  });

  it("a cancel after the last byte is still never a verdict", async () => {
    const plain = Buffer.from("last");
    const shutdown = new AbortController();
    const body = (async function* () {
      yield seal(plain);
      // The source is done; the worker may already hold the digest.
      shutdown.abort("worker shutdown");
    })();
    await expect(
      digestImageObject(body, { key, plainSize: plain.length, signal: shutdown.signal }),
    ).rejects.toBeInstanceOf(VerifyCancelledError);
  });

  it("does not wipe the caller's key (the caller owns it)", async () => {
    const own = Buffer.alloc(32, 9);
    await digestImageObject(chunked(seal(Buffer.from("x"))), { key: own, plainSize: 1 });
    expect(own.equals(key)).toBe(true);
  });

  // The regression behind `POST /v1/sandboxes` → 500 during a disk-offload
  // verify: the inline decrypt/hash of an in-memory or fast local stream never
  // gave the event loop a turn, so request handling (and interactive
  // transactions) starved. Counted in event-loop turns, not wall time.
  it("gives the event loop a turn at least every few megabytes", async () => {
    const plain = Buffer.alloc(48 * RECORD, 3);
    const sealed = seal(plain);
    let turns = 0;
    let running = true;
    const tick = () => {
      if (!running) return;
      turns++;
      setImmediate(tick);
    };
    setImmediate(tick);
    const digest = await digestImageObject(chunked(sealed), { key, plainSize: plain.length });
    running = false;
    expect(digest.fingerprint).toBe(fingerprint(plain));
    // 48 MiB through an 8 MiB in-flight window: at least five waits for the worker.
    expect(turns).toBeGreaterThanOrEqual(5);

    // The reference inline decrypt over the same in-memory body: no turn at all.
    let inlineTurns = 0;
    running = true;
    const inlineTick = () => {
      if (!running) return;
      inlineTurns++;
      setImmediate(inlineTick);
    };
    setImmediate(inlineTick);
    const hash = createHash("sha256");
    for await (const chunk of decryptImageStream(key, plain.length, chunked(sealed)))
      hash.update(chunk);
    running = false;
    expect(inlineTurns).toBe(0);
  });
});
