import { Worker } from "node:worker_threads";
import { IMAGE_ENCRYPTION_RECORD_BYTES, IMAGE_ENCRYPTION_TAG_BYTES } from "@wssp/sandbox-contracts";
import { ImageIntegrityError, VerifyCancelledError } from "./verification-errors";

/**
 * Ciphertext handed to the worker but not yet consumed by it. Above this the
 * reader waits for the worker, so memory stays bounded and the server's event
 * loop gets a turn at least every few megabytes.
 */
const IN_FLIGHT_MAX_BYTES = 8 * 1024 * 1024;
const SETTLED = Symbol("settled");

function isDestroyable(body: unknown): body is { destroy(): void } {
  return (
    typeof body === "object" &&
    body !== null &&
    "destroy" in body &&
    typeof (body as { destroy: unknown }).destroy === "function"
  );
}

/**
 * The worker body (plain CommonJS, evaluated by `new Worker(…, { eval: true })`
 * so the bundled server needs no separate worker file). It mirrors
 * `decryptImageStream`/`recordNonce`/`recordAad` in `./s3`; the tests check
 * the two against `encryptRecord`. Integrity failures (authentication,
 * truncation, trailing bytes) are reported as `integrity: true`; anything
 * else is an ordinary failure the job retries.
 */
const WORKER_SOURCE = `
"use strict";
const { parentPort, workerData } = require("node:worker_threads");
const { createDecipheriv, createHash } = require("node:crypto");
const { plainSize, recordBytes, tagBytes } = workerData;
const key = workerData.key ? Buffer.from(workerData.key) : null;
if (workerData.key) workerData.key.fill(0);
const sealedBytes = recordBytes + tagBytes;
const records = Math.max(1, Math.ceil(plainSize / recordBytes));
const hash = createHash("sha256");
let parts = [];
let held = 0;
let index = 0;
let size = 0;
class Integrity extends Error {}
function take(bytes) {
  const all = parts.length === 1 ? parts[0] : Buffer.concat(parts, held);
  parts = all.length > bytes ? [all.subarray(bytes)] : [];
  held -= bytes;
  return all.subarray(0, bytes);
}
function open(final, sealed) {
  if (sealed.length < tagBytes) throw new Integrity("truncated image record");
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(index), 4);
  const aad = Buffer.alloc(20);
  aad.write("wssp-img-r1", 0, "ascii");
  aad.writeBigUInt64BE(BigInt(index), 11);
  aad[19] = final ? 1 : 0;
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(sealed.length - tagBytes));
  let plain;
  try {
    plain = Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - tagBytes)), decipher.final()]);
  } catch (error) {
    throw new Integrity(String(error && error.message));
  }
  hash.update(plain);
  size += plain.length;
}
function onChunk(chunk) {
  if (!key) {
    hash.update(chunk);
    size += chunk.length;
    return;
  }
  parts.push(chunk);
  held += chunk.length;
  while (held >= sealedBytes && index < records - 1) {
    open(false, take(sealedBytes));
    index++;
  }
  // Past the last record nothing more may arrive: refuse it now, not at EOF.
  if (index === records - 1 && held > plainSize - index * recordBytes + tagBytes)
    throw new Integrity("encrypted image length mismatch");
}
function onEnd() {
  if (key) {
    if (index !== records - 1) throw new Integrity("truncated encrypted image");
    const last = plainSize - index * recordBytes;
    if (held !== last + tagBytes) throw new Integrity("encrypted image length mismatch");
    open(true, take(held));
    key.fill(0);
  }
  return { size, sha256: hash.digest("hex") };
}
parentPort.on("message", (message) => {
  try {
    if (message.chunk) {
      const chunk = Buffer.from(message.chunk);
      onChunk(chunk);
      parentPort.postMessage({ consumed: chunk.length });
    } else {
      parentPort.postMessage({ done: onEnd() });
    }
  } catch (error) {
    if (key) key.fill(0);
    parentPort.postMessage({
      failed: { integrity: error instanceof Integrity, message: String(error && error.message) },
    });
  }
});
`;

type WorkerReply =
  | { consumed: number }
  | { done: { size: number; sha256: string } }
  | { failed: { integrity: boolean; message: string } };

/**
 * The size and `sha256:` fingerprint of an image-store object's plaintext:
 * `key` set → an `aes256gcm-r1` object of `plainSize` plaintext bytes, which
 * is decrypted and authenticated record by record; `key` null → the raw bytes.
 *
 * The decrypt and hash run on a worker thread, never on the caller's event
 * loop: with the default embedded worker a verify shares the API server's
 * process, and an inline multi-gigabyte decrypt/hash starved request handling
 * until interactive transactions expired (`POST /v1/sandboxes` → 500).
 *
 * Throws {@link ImageIntegrityError} on tamper, truncation or trailing bytes;
 * a source (store or network) error is rethrown as is; `signal` stops the read
 * with {@link VerifyCancelledError}. The worker is always terminated.
 */
export async function digestImageObject(
  body: AsyncIterable<Uint8Array>,
  options: { plainSize: number; key: Buffer | null; signal?: AbortSignal },
): Promise<{ size: bigint; fingerprint: string }> {
  const { signal } = options;
  if (signal?.aborted) throw new VerifyCancelledError();
  // The worker gets its own copy of the key and wipes it (and this transfer copy).
  const keyCopy = options.key ? new Uint8Array(options.key) : null;
  const worker = new Worker(WORKER_SOURCE, {
    eval: true,
    workerData: {
      key: keyCopy,
      plainSize: options.plainSize,
      recordBytes: IMAGE_ENCRYPTION_RECORD_BYTES,
      tagBytes: IMAGE_ENCRYPTION_TAG_BYTES,
    },
  });
  keyCopy?.fill(0);
  let inFlight = 0;
  let failure: unknown;
  let digest: { size: number; sha256: string } | undefined;
  let wake: (() => void) | undefined;
  // Set once the worker finished, failed or was cancelled. Each wait below
  // registers its own one-shot waiter (cleared when it returns), so nothing
  // retains a settled read and its chunk: memory stays within the window.
  let isSettled = false;
  let onSettle: (() => void) | undefined;
  const settle = () => {
    isSettled = true;
    onSettle?.();
  };
  /** `work`'s value, or SETTLED as soon as the digest settles (whichever is first). */
  const untilSettled = <T>(work: Promise<T>) =>
    new Promise<T | typeof SETTLED>((resolve, reject) => {
      if (isSettled) return resolve(SETTLED);
      onSettle = () => resolve(SETTLED);
      work.then(resolve, reject);
    }).finally(() => {
      onSettle = undefined;
    });
  const fail = (error: unknown) => {
    if (digest === undefined) failure ??= error;
    settle();
    wake?.();
  };
  const onAbort = () => fail(new VerifyCancelledError());
  worker.on("message", (reply: WorkerReply) => {
    if ("consumed" in reply) {
      inFlight -= reply.consumed;
      wake?.();
    } else if ("done" in reply) {
      if (failure === undefined) digest = reply.done;
      settle();
    } else
      fail(
        reply.failed.integrity
          ? new ImageIntegrityError(reply.failed.message)
          : new Error(`image digest failed: ${reply.failed.message}`),
      );
  });
  worker.on("error", fail);
  worker.on("exit", (code) => fail(new Error(`image digest worker exited (${code})`)));
  signal?.addEventListener("abort", onAbort, { once: true });
  const source = body[Symbol.asyncIterator]();
  let exhausted = false;
  try {
    for (;;) {
      const read = source.next();
      // A read abandoned below may still settle later: never unhandled.
      read.catch(() => {});
      const next = await untilSettled(read);
      if (next === SETTLED) break;
      if (next.done) {
        exhausted = true;
        break;
      }
      // A private copy whose buffer moves to the worker (the stream may reuse its own).
      const copy = new Uint8Array(next.value);
      inFlight += copy.byteLength;
      worker.postMessage({ chunk: copy.buffer }, [copy.buffer]);
      while (inFlight > IN_FLIGHT_MAX_BYTES && failure === undefined)
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
      if (failure !== undefined) break;
    }
    if (failure === undefined && exhausted) {
      worker.postMessage({ end: true });
      await untilSettled(new Promise<never>(() => {}));
    }
  } finally {
    wake = undefined;
    signal?.removeEventListener("abort", onAbort);
    // Close an unfinished source without waiting on it. A Node stream (the S3
    // body) is destroyed directly: its iterator's return() would queue behind
    // a stalled read and keep the store connection open.
    if (!exhausted) {
      if (isDestroyable(body)) body.destroy();
      void Promise.resolve(source.return?.()).catch(() => {});
    }
    await worker.terminate();
  }
  // A cancel at any point, even while the worker was being stopped, is never a verdict.
  if (signal?.aborted) throw new VerifyCancelledError();
  if (failure !== undefined) throw failure;
  if (digest === undefined) throw new Error("image digest ended without a result");
  return { size: BigInt(digest.size), fingerprint: `sha256:${digest.sha256}` };
}
