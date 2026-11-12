import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import {
  type EntryInfo,
  type OperationResult,
  RESULT_TYPE_BY_KIND,
  type ResultKind,
  TRANSFER_CHUNK_BYTES,
  TRANSFER_MAX_BYTES,
} from "@wssp/sandbox-contracts";
import type { CancelResult, CommandsApi } from "./commands";
import { attachErrorContext, isWsspError, WsspError } from "./errors";
import { ensureSucceeded, type OperationRead, waitOperation } from "./operations";
import {
  Deadline,
  type PollContext,
  type PollingOptions,
  readWithRetry,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
  waitTimeoutError,
  withWaitTimeout,
} from "./polling";
import { generateKey, type MutationOptions, submitMutation } from "./sandboxes";
import { createTransfersApi, derivedTransferKey, type TransfersApi } from "./transfers";
import {
  type DownloadContent,
  type DownloadRange,
  MAX_TIMEOUT_MS,
  type WsspTransport,
} from "./transport";

/** Default budget of the cancellation-acknowledgement wait after an abort. */
const DEFAULT_CANCEL_ACK_TIMEOUT_MS = 30_000;
const MAX_CANCEL_ACK_TIMEOUT_MS = 10 * 60_000;

/**
 * Default memory cap of the byte-array conveniences (`readBytes`/`writeBytes`
 * and `FileDownload.bytes`): 32 MiB. Streaming is the primary API; this bound
 * is CLIENT memory only, independent of the server's per-transfer cap.
 */
export const DEFAULT_FILE_MEMORY_BYTES = 32 * 1024 * 1024;
/**
 * Upload payload: bytes, a one-shot async iterable (a Node `Readable` works),
 * or a factory returning a FRESH iterable. Only bytes and factories support
 * resuming an interrupted upload; a consumed one-shot stream cannot rewind.
 * Every chunk must be a Uint8Array.
 */
export type UploadSource =
  | Uint8Array
  | AsyncIterable<Uint8Array>
  | (() => AsyncIterable<Uint8Array>);

export type UploadOptions = MutationOptions & {
  /**
   * Declared total length, required for stream sources: the server reserves
   * the full length before any byte moves. For Uint8Array sources it must
   * equal the buffer length when given.
   */
  totalBytes?: number;
  /** Budget of the cancellation-acknowledgement wait after an abort. Default 30 s. */
  cancelAckTimeoutMs?: number;
};

export type UploadResult = {
  transferId: string;
  /** The PUT_FILE operation; succeeded once `upload` resolves. */
  operationId: string;
  sha256: string;
  totalBytes: number;
};

/**
 * A rich no-follow metadata result with its recovery operation ID.
 * Only a versioned, unexpired confirmed missing path resolves null.
 */
export type FileStat = EntryInfo & { operationId: string };
export type Page<T> = { items: T[]; nextCursor: string | null; consistency: "live" };
export type FileListOptions = MutationOptions & { depth?: number; limit?: number; cursor?: string };
export type FileRemoveOptions = MutationOptions & { recursive?: boolean };

/** Identity of a capture a previous download opened, enough to resume it. */
export type ResumeTarget = {
  operationId: string;
  /** The capture ETag from the interrupted download. */
  etag: string;
};

/** The server's advertised transfer bounds, read before capture/upload. */
export type TransferLimitsInfo = {
  /** Configured per-transfer cap (at most TRANSFER_MAX_BYTES). */
  transferMaxBytes: number;
  /** The fixed upload chunk size (1 MiB). */
  chunkBytes: number;
  /** Default memory cap of the byte-array conveniences (32 MiB). */
  memoryBytesDefault: number;
};

/**
 * One opened download. `stream` is validated as it flows: a short or long
 * body and a whole-content hash mismatch error the stream (a mid-stream
 * revocation or expiry surfaces the same way, and the capture can be
 * re-opened with `resumeDownload` at the received offset).
 */
export type FileDownload = {
  readonly operationId: string;
  /** Total capture size. */
  readonly size: number;
  /** Whole-capture SHA-256 hex. */
  readonly sha256: string;
  readonly etag: string;
  /** Offset of the first byte of this response (0, or the resumed offset). */
  readonly start: number;
  /** Bytes this response carries (`size - start` for a whole/resumed read). */
  readonly length: number;
  /** The validated byte stream; consumable exactly once. */
  readonly stream: ReadableStream<Uint8Array>;
  /** The stream as a Node Readable; consumable exactly once. */
  nodeStream(): Readable;
  /**
   * Collect the stream into one bounded buffer. A capture larger than
   * `maxBytes` (default and at most 32 MiB — the client cap) is rejected
   * BEFORE the body is read, using the declared Content-Length.
   */
  bytes(options?: { maxBytes?: number; signal?: AbortSignal }): Promise<Uint8Array>;
};

/** readBytes submits a capture mutation, so it takes an idempotency key. */
export type ReadBytesOptions = MutationOptions & { maxBytes?: number };
export type WriteBytesOptions = MutationOptions & { maxBytes?: number };

export type FilesApi = {
  list(sandboxId: string, path: string, options?: FileListOptions): Promise<Page<EntryInfo>>;
  getInfo(sandboxId: string, path: string, options?: MutationOptions): Promise<EntryInfo>;
  makeDir(sandboxId: string, path: string, options?: MutationOptions): Promise<boolean>;
  remove(sandboxId: string, path: string, options?: FileRemoveOptions): Promise<void>;
  rename(
    sandboxId: string,
    from: string,
    to: string,
    options?: MutationOptions,
  ): Promise<EntryInfo>;
  /** The server's transfer bounds, discoverable before any capture/upload. */
  limits(options?: WaitOptions): Promise<TransferLimitsInfo>;
  /**
   * Upload a file and resolve once the guest replacement operation succeeded.
   * Resumable: re-call with the SAME idempotencyKey after an interruption and
   * the create replay returns the durable cursor, so already-acknowledged
   * chunks are hashed but never re-sent. A caller abort leaves the transfer
   * OPEN for that resume and throws `aborted` (or `unknown` when a chunk was
   * in flight); an abort racing the guest replacement requests cancellation
   * and never reports a stop while the outcome is unconfirmed. Call
   * `transfers.abortUpload` (or let idle expiry) to clean up an abandoned
   * upload.
   */
  upload(
    sandboxId: string,
    guestPath: string,
    source: UploadSource,
    options?: UploadOptions,
  ): Promise<UploadResult>;
  /**
   * Capture one guest file (one GET_FILE operation) and open its immutable
   * bytes as a validated stream. A missing path fails the operation with a
   * typed `not_found`; a missing sandbox fails the submission (404
   * `sandbox.not_found`) — the two are never conflated.
   */
  download(sandboxId: string, path: string, options?: MutationOptions): Promise<FileDownload>;
  /**
   * Resume a capture at `offset` guarded by its ETag: the bytes continue only
   * if the capture is unchanged. A replaced capture (validator mismatch) is a
   * conflict, not a silent restart; expired or generation-changed content is
   * `gone` (410).
   */
  resumeDownload(
    target: ResumeTarget,
    offset: number,
    options?: WaitOptions,
  ): Promise<FileDownload>;
  /** Read one byte range of a capture; length-validated (the hash covers the whole). */
  downloadRange(
    operationId: string,
    range: DownloadRange,
    options?: WaitOptions,
  ): Promise<FileDownload>;
  /** Bounded whole-file read (default cap 32 MiB of client memory). */
  readBytes(sandboxId: string, path: string, options?: ReadBytesOptions): Promise<Uint8Array>;
  /** Bounded whole-buffer write (default cap 32 MiB of client memory). */
  writeBytes(
    sandboxId: string,
    path: string,
    data: Uint8Array,
    options?: WriteBytesOptions,
  ): Promise<UploadResult>;
  /** The file, or null only for a confirmed missing path. Never null for a missing sandbox. */
  stat(sandboxId: string, path: string, options?: MutationOptions): Promise<FileStat | null>;
  /** True exactly when the path is confirmed to exist. */
  exists(sandboxId: string, path: string, options?: MutationOptions): Promise<boolean>;
};

function invalidRequest(context: PollContext, detail: string): WsspError {
  return new WsspError({
    kind: "invalid_request",
    message: `${context.label}: ${detail}`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

function boundedOption(
  context: PollContext,
  name: string,
  value: number,
  min: number,
  max: number,
): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw invalidRequest(context, `${name} must be an integer from ${min} to ${max}.`);
  }
  return value;
}

/** The caller's own signal aborted this phase (a mid-flight send may have landed). */
function isCallerAbort(signal: AbortSignal | undefined, error: unknown): boolean {
  return (
    signal?.aborted === true &&
    (isWsspError(error, "aborted") || (isWsspError(error, "unknown") && error.reason === "aborted"))
  );
}

/** Yield chunk-sized slices so the pump copies at most one chunk per step. */
async function* oneShot(data: Uint8Array): AsyncIterable<Uint8Array> {
  for (let at = 0; at < data.byteLength; at += TRANSFER_CHUNK_BYTES) {
    yield data.subarray(at, at + TRANSFER_CHUNK_BYTES);
  }
}

/** Re-throw a transport error with the caller's key attached, when missing. */
function withIdempotencyKey(error: unknown, key: string): unknown {
  return attachErrorContext(error, { idempotencyKey: key });
}

/**
 * A commit-phase failure recovers through the RESERVATION key: retrying
 * `files.upload` with `error.idempotencyKey` replays create AND the derived
 * commit, so the convenience surface always reports the caller's key. The
 * derived commit key rides along separately for support correlation.
 */
function withUploadKey(error: unknown, key: string, commitKey: string): unknown {
  if (!isWsspError(error)) return error;
  Object.defineProperty(error, "idempotencyKey", {
    value: key,
    enumerable: true,
    configurable: true,
  });
  return attachErrorContext(error, { commitKey });
}

/**
 * Attach every recovery identity to a post-commit failure: the reservation
 * key, the derived commit key and the committed operation ID. Existing
 * values win; only the missing ones are filled in.
 */
function withRecoveryIdentity(
  error: unknown,
  key: string,
  commitKey: string | null,
  operationId: string,
): unknown {
  return attachErrorContext(error, { idempotencyKey: key, commitKey, operationId });
}

/**
 * One pending read raced against caller cancellation and an optional
 * deadline: a stalled source or body can no longer park an upload (or a
 * bounded read) past its abort or timeout. The losing read's late rejection
 * is swallowed; its late resolution is discarded by the caller's cleanup.
 */
function racedRead<T>(
  pending: Promise<T>,
  signal: AbortSignal | undefined,
  timeoutMs: number | undefined,
  makeInterrupt: (timedOut: boolean) => WsspError,
): Promise<T> {
  if (signal !== undefined || timeoutMs !== undefined) {
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        if (timer !== undefined) clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      const interrupt = (timedOut: boolean) => {
        if (settled) return;
        settled = true;
        cleanup();
        // The abandoned read must not surface as an unhandled rejection.
        pending.catch(() => {});
        reject(makeInterrupt(timedOut));
      };
      const onAbort = () => interrupt(false);
      const timer =
        timeoutMs === undefined ? undefined : setTimeout(() => interrupt(true), timeoutMs);
      if (signal?.aborted) {
        interrupt(false);
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      pending.then(
        (value) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(value);
        },
        (error: unknown) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      );
    });
  }
  return pending;
}

/** Bounded wait for a source's cleanup; a stalled source must not block settlement. */
const SOURCE_CLOSE_TIMEOUT_MS = 10_000;

async function closeSource(iterator: AsyncIterator<Uint8Array>): Promise<void> {
  let returned: Promise<unknown> | undefined;
  try {
    returned = iterator.return?.();
  } catch {
    // A cleanup that throws synchronously is already settled: never let a
    // source's cleanup error mask the upload's own outcome.
    return;
  }
  if (!returned) return;
  returned.catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      returned,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, SOURCE_CLOSE_TIMEOUT_MS);
      }),
    ]);
  } catch {
    // The source's own cleanup failure must not mask the upload outcome.
  } finally {
    // Always release the losing timeout: a fast return() must not pin the
    // process (or the test loop) for the full bound.
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function createFilesApi(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
  transfers: TransfersApi = createTransfersApi(transport, defaults),
  cancelOperation?: CommandsApi["cancelAndWait"],
): FilesApi {
  async function limits(options: WaitOptions = {}): Promise<TransferLimitsInfo> {
    const capabilities = await transport.request("getCapabilities", {
      signal: options.signal,
      timeoutMs: waitTimeout(options),
    });
    return {
      transferMaxBytes: capabilities.limits.transferMaxBytes,
      chunkBytes: TRANSFER_CHUNK_BYTES,
      memoryBytesDefault: DEFAULT_FILE_MEMORY_BYTES,
    };
  }

  /**
   * ANY exception crossing a SOURCE boundary (factory call, asyncIterator
   * acquisition, next() — sync or async) is a source failure, regardless of
   * class: a source may legitimately call another SDK operation and throw ITS
   * WsspError, whose key, message, and cause belong to that operation. Trust
   * none of it: re-key to THIS upload's reservation, use a fixed message,
   * attach only a redacted cause. Upload-validation and chunk-transport
   * errors are generated by pump itself, never through this boundary.
   */
  const sourceFailureOf = (context: PollContext, error: unknown): WsspError =>
    new WsspError({
      kind: "unknown",
      code: "TRANSFER_IO",
      message: `${context.label}: the upload source failed; accepted bytes are held under the reservation — resume with the same idempotency key.`,
      idempotencyKey: context.idempotencyKey ?? null,
      cause: transport.redactCause(error),
    });

  /**
   * Push the source through the chunk pipeline: hash EVERY byte (the commit
   * covers the whole content, including a resumed prefix), but send only
   * chunks at or after `startAt` (the server's durable cursor, always
   * chunk-aligned). Throws before sending a chunk that would overflow the
   * declared total, and after the pass when the source length mismatches it.
   */
  async function pump(
    source: AsyncIterable<Uint8Array>,
    total: number,
    startAt: number,
    hash: ReturnType<typeof createHash>,
    send: (offset: number, chunk: Uint8Array) => Promise<void>,
    signal: AbortSignal | undefined,
    deadline: Deadline,
    context: PollContext,
  ): Promise<void> {
    const abortedRead = () =>
      new WsspError({
        kind: "aborted",
        reason: "aborted",
        message: `${context.label}: the upload was aborted; resume it with the same idempotency key.`,
        idempotencyKey: context.idempotencyKey ?? null,
      });
    let position = 0;
    // One fixed SDK-owned chunk buffer filled slice by slice: a piece is
    // copied immediately (sources may reuse/refill their buffers), an
    // oversized piece is NEVER copied whole, and tiny pieces copy once each
    // instead of re-copying a growing prefix per yield.
    const pending = new Uint8Array(TRANSFER_CHUNK_BYTES);
    let pendingLen = 0;
    const emit = async (chunk: Uint8Array): Promise<void> => {
      if (position + chunk.byteLength > total) {
        throw invalidRequest(context, `the source produced more than the declared ${total} bytes.`);
      }
      hash.update(chunk);
      const at = position;
      position += chunk.byteLength;
      if (at < startAt) return;
      // Chunk-aligned cursors make every chunk either fully below the resume
      // offset (hashed, skipped) or fully at/after it (sent): never a splice.
      await send(at, chunk);
    };
    const flush = async (final: boolean): Promise<void> => {
      if (pendingLen === TRANSFER_CHUNK_BYTES || (final && pendingLen > 0)) {
        if (signal?.aborted) throw abortedRead();
        await emit(pending.subarray(0, pendingLen));
        pendingLen = 0;
      }
    };
    let iterator: AsyncIterator<Uint8Array>;
    try {
      iterator = source[Symbol.asyncIterator]();
    } catch (error) {
      throw sourceFailureOf(context, error);
    }
    try {
      for (;;) {
        // A source read is raced against the caller's signal and the upload
        // deadline: a paused Node stream can no longer park the upload past
        // either one (deadline.remaining also throws once it is exhausted).
        // The budget is computed BEFORE next(): if next() does synchronous
        // work that exhausts it and returns a REJECTED promise, racedRead is
        // already the next call — the rejection always gets a handler.
        const remaining = deadline.remaining(context);
        let reading: Promise<IteratorResult<Uint8Array>>;
        try {
          reading = iterator.next();
        } catch (error) {
          throw sourceFailureOf(context, error);
        }
        const next = await racedRead(
          reading.catch((error: unknown) => {
            throw sourceFailureOf(context, error);
          }),
          signal,
          remaining,
          (timedOut) => (timedOut ? waitTimeoutError(context) : abortedRead()),
        );
        if (next.done) break;
        const piece = next.value;
        if (!(piece instanceof Uint8Array)) {
          throw invalidRequest(context, "an upload source must yield Uint8Array chunks.");
        }
        let at = 0;
        while (at < piece.byteLength) {
          const n = Math.min(TRANSFER_CHUNK_BYTES - pendingLen, piece.byteLength - at);
          pending.set(piece.subarray(at, at + n), pendingLen);
          pendingLen += n;
          at += n;
          if (pendingLen === TRANSFER_CHUNK_BYTES) await flush(false);
        }
      }
      await flush(true);
      if (position !== total) {
        throw invalidRequest(
          context,
          `the source produced ${position} bytes; the reservation declared ${total}.`,
        );
      }
    } finally {
      // Bounded cleanup: a stalled source may never answer return().
      await closeSource(iterator);
    }
  }

  async function upload(
    sandboxId: string,
    guestPath: string,
    source: UploadSource,
    options: UploadOptions = {},
  ): Promise<UploadResult> {
    const context: PollContext = { label: `upload ${sandboxId}` };
    const key = options.idempotencyKey ?? generateKey();
    context.idempotencyKey = key;
    const bytes = source instanceof Uint8Array ? source : null;
    const total = bytes ? bytes.byteLength : options.totalBytes;
    if (total === undefined) {
      throw invalidRequest(context, "a stream source requires totalBytes.");
    }
    // All validation precedes the reservation: invalid input never allocates.
    if (!Number.isSafeInteger(total) || total < 0 || total > TRANSFER_MAX_BYTES) {
      throw invalidRequest(
        context,
        `totalBytes must be an integer from 0 to ${TRANSFER_MAX_BYTES}.`,
      );
    }
    if (bytes && options.totalBytes !== undefined && options.totalBytes !== bytes.byteLength) {
      throw invalidRequest(context, "totalBytes does not match the buffer length.");
    }
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    const receipt = await transfers.createUpload(
      { sandboxId, guestPath, totalBytes: total },
      { ...withWaitTimeout(options, deadline.remaining(context)), idempotencyKey: key },
    );
    context.label = `upload ${sandboxId} transfer ${receipt.id}`;
    const startAt = receipt.receivedBytes;
    // A durable cursor is chunk-aligned — except the exact total: an upload
    // interrupted after its final (unaligned) chunk landed holds
    // receivedBytes === totalBytes and legitimately awaits commit recovery.
    const aligned = startAt % TRANSFER_CHUNK_BYTES === 0 || startAt === total;
    if (receipt.totalBytes !== total || !aligned || startAt > total) {
      throw new WsspError({
        kind: "protocol",
        reason: "invalid_response",
        message: `${context.label}: the replayed receipt does not match the reservation.`,
        idempotencyKey: key,
      });
    }
    // A receipt retired EXPIRED at the full cursor may hold a LANDED commit
    // whose response was lost — and so can a FAILED one (server startup
    // recovery retires a SEALED upload FAILED when its spool is missing or
    // corrupt, WITHOUT removing the committed operation). The server keeps
    // the operation and replays the commit under its derived key even after
    // retirement. Recover it below BEFORE recommending a new key — a fresh
    // reservation could repeat an already-completed guest replacement.
    const recoverable =
      receipt.state === "OPEN" ||
      (startAt === total &&
        (receipt.state === "SEALED" || receipt.state === "EXPIRED" || receipt.state === "FAILED"));
    if (!recoverable) {
      throw new WsspError({
        kind: "conflict",
        message: `${context.label}: the transfer replayed by this key is ${receipt.state}; use a new idempotency key.`,
        idempotencyKey: key,
      });
    }
    // A one-shot stream cannot RESEND a partially-uploaded prefix; at the
    // full cursor nothing is sent (recovery only rehashes and replays the
    // commit), so any source shape is acceptable there.
    if (startAt > 0 && startAt < total && bytes === null && typeof source !== "function") {
      throw invalidRequest(
        context,
        "this upload is partially sent; resume needs bytes or a stream factory, not a one-shot stream.",
      );
    }
    const hash = createHash("sha256");
    const sourceFailure = (error: unknown): WsspError => sourceFailureOf(context, error);
    // The commit key derives from the caller's key: a retried upload replays
    // the SAME commit, and the server returns the original operation.
    const commitKey = derivedTransferKey(key, "commit");
    // ANY full-cursor replay — including OPEN — is potentially committed: a
    // previous commit request can still be in server-side hashing after its
    // client request failed (hashing holds no DB transaction, and the
    // reservation replays OPEN with receivedBytes === totalBytes until it
    // lands). Until the commit replay RECOVERS the operation (or a confirmed
    // abort resolves it), no interruption is definitive: the original guest
    // replacement can still run.
    const recoveringCommit = startAt === total;
    // An interrupted RECOVERY (rehash, source cleanup, commit argument
    // evaluation, pre-send) leaves a possibly-committed operation
    // unobserved: plain `aborted`/`timeout` would be definitive while the
    // guest replacement may still run. Report `unknown` carrying BOTH keys;
    // a same-key retry replays the commit and recovers the operation, after
    // which the existing cancellation settlement applies.
    const recoveryInterruption = (error: unknown): WsspError | null => {
      if (!recoveringCommit) return null;
      const aborted = isCallerAbort(options.signal, error);
      // A commit replay refused for capacity until its deadline (E-18) is no
      // more definitive than a timeout: the original commit may have landed.
      if (!aborted && !isWsspError(error, "timeout") && !isWsspError(error, "capacity"))
        return null;
      return new WsspError({
        kind: "unknown",
        reason: aborted ? "aborted" : "timeout",
        message: `${context.label}: interrupted while recovering a possibly-committed transfer; the guest replacement may still run — retry with the same idempotency key to learn the outcome before assuming the file's content.`,
        idempotencyKey: key,
        commitKey,
        cause: transport.redactCause(error),
      });
    };
    let iterable: AsyncIterable<Uint8Array>;
    try {
      iterable =
        source instanceof Uint8Array
          ? oneShot(source)
          : typeof source === "function"
            ? source()
            : source;
    } catch (error) {
      throw sourceFailure(error);
    }
    try {
      await pump(
        iterable,
        total,
        startAt,
        hash,
        async (offset, chunk) => {
          await transfers.putChunk(receipt.id, offset, chunk, total, {
            signal: options.signal,
            waitTimeoutMs: deadline.remaining(context),
          });
        },
        options.signal,
        deadline,
        context,
      );
    } catch (error) {
      // During committed recovery a length mismatch is NOT a fresh caller
      // bug: the original commit may already have landed. Never run
      // reservation-abort cleanup against the retired receipt (its 409 is
      // suppressed anyway) and never report a definitive invalid_request —
      // the guest replacement stays unobserved and may still run. Report
      // `unknown` with BOTH keys; a same-key retry with the ORIGINAL
      // content recovers the operation.
      if (recoveringCommit && isWsspError(error, "invalid_request")) {
        throw new WsspError({
          kind: "unknown",
          code: "TRANSFER_IO",
          message: `${context.label}: the recovery source disagreed with the reserved length while a committed replacement may still be pending; retry with the same idempotency key and the original content to learn the outcome.`,
          idempotencyKey: key,
          commitKey,
          cause: transport.redactCause(error),
        });
      }
      // A length-mismatched source can never commit: release the reservation
      // (best-effort; idle expiry is the backstop) instead of leaking it.
      if (isWsspError(error, "invalid_request")) {
        await transfers.abortUpload(receipt.id, { waitTimeoutMs: 10_000 }).catch(() => {});
      }
      const interruption = recoveryInterruption(error);
      if (interruption) throw interruption;
      // The API may already hold accepted bytes: the failure must carry the
      // caller's key so the upload can be resumed, never a bare abort. A raw
      // (non-WSSP) source error becomes a keyed TRANSFER_IO first; source
      // errors are already normalized (and re-keyed) at the source boundary.
      throw isWsspError(error) ? withIdempotencyKey(error, key) : sourceFailure(error);
    }
    const sha256 = hash.digest("hex");
    // A commit failure must still carry the RESERVATION key (the derived
    // commit key rides `commitKey`): recovery is a `files.upload` retry under
    // the original key, which replays both phases. Argument evaluation
    // (deadline.remaining can throw a bare timeout) and a pre-send abort sit
    // INSIDE the try so recovery uncertainty covers them too.
    let commit: { operationId: string };
    try {
      commit = await transfers.commitUpload(receipt.id, sha256, {
        ...withWaitTimeout(options, deadline.remaining(context)),
        idempotencyKey: commitKey,
      });
    } catch (error: unknown) {
      const interruption = recoveryInterruption(error);
      if (interruption) throw interruption;
      // A 409 during commit recovery means the ORIGINAL commit still holds
      // the transfer's exclusive permit (store.ts:197) and can land after
      // this retry gave up. The conflict does NOT resolve the uncertainty:
      // report `unknown` with both keys, preserving the 409 metadata.
      if (recoveringCommit && isWsspError(error, "conflict")) {
        throw new WsspError({
          kind: "unknown",
          code: error.code,
          status: error.status,
          requestId: error.requestId,
          message: `${context.label}: the commit replay conflicts with a commit already in progress; the original replacement may still land — retry with the same idempotency key to learn the outcome.`,
          idempotencyKey: key,
          commitKey,
          cause: transport.redactCause(error),
        });
      }
      // A commit replayed onto a retired (EXPIRED/FAILED) receipt can still
      // fail 410: the reservation died before the commit was ever
      // confirmed. Nothing is recoverable under this key; only NOW
      // recommend a fresh one.
      if (
        (receipt.state === "EXPIRED" || receipt.state === "FAILED") &&
        isWsspError(error, "gone")
      ) {
        throw withUploadKey(
          new WsspError({
            kind: "gone",
            code: error.code,
            status: error.status,
            requestId: error.requestId,
            message: `${context.label}: the reservation expired before its commit was confirmed; retry with a NEW idempotency key.`,
          }),
          key,
          commitKey,
        );
      }
      throw withUploadKey(error, key, commitKey);
    }
    context.operationId = commit.operationId;
    try {
      const operation = await waitOperation(
        transport,
        defaults,
        commit.operationId,
        { ...withWaitTimeout(options, deadline.remaining(context)) },
        context,
      );
      ensureSucceeded(operation, context);
    } catch (error) {
      if (isCallerAbort(options.signal, error)) {
        throw await settleAbortedUpload(commit.operationId, commitKey, options, context);
      }
      // Post-commit failures carry ALL recovery identities: the reservation
      // key (a `files.upload` retry replays the commit), the derived commit
      // key and the committed operation ID — even when the key was generated
      // internally and the wait itself was unauthorized or timed out.
      throw withRecoveryIdentity(error, key, commitKey, commit.operationId);
    }
    return { transferId: receipt.id, operationId: commit.operationId, sha256, totalBytes: total };
  }

  /**
   * An abort after commit: request cancellation of the PUT_FILE under a
   * derived key and confirm the TARGET operation's terminal state. A
   * confirmed cancellation reports `aborted`; anything else — a completed
   * replacement, an unconfirmed request — reports `unknown` carrying the
   * operation ID. Never a bare wait error while the commit may still land.
   */
  async function settleAbortedUpload(
    operationId: string,
    commitKey: string,
    options: UploadOptions,
    context: PollContext,
  ): Promise<WsspError> {
    const ackContext: PollContext = { ...context, label: `${context.label} cancellation` };
    if (!cancelOperation) {
      return new WsspError({
        kind: "unknown",
        reason: "aborted",
        message: `${ackContext.label}: the upload committed and the abort left the guest replacement unobserved; poll the operation.`,
        operationId,
        idempotencyKey: context.idempotencyKey ?? null,
        commitKey,
      });
    }
    let cancel: CancelResult;
    try {
      cancel = await cancelOperation(operationId, {
        idempotencyKey: derivedTransferKey(commitKey, "cancel"),
        waitTimeoutMs: boundedOption(
          ackContext,
          "cancelAckTimeoutMs",
          options.cancelAckTimeoutMs ?? DEFAULT_CANCEL_ACK_TIMEOUT_MS,
          1,
          MAX_CANCEL_ACK_TIMEOUT_MS,
        ),
      });
    } catch (error) {
      if (isWsspError(error)) {
        return new WsspError({
          kind: "unknown",
          reason: "aborted",
          message: `${ackContext.label}: cancellation was requested but not confirmed (${error.message}); poll the operation.`,
          operationId,
          idempotencyKey: context.idempotencyKey ?? null,
          commitKey,
        });
      }
      throw error;
    }
    if (cancel.outcome === "cancelled") {
      return new WsspError({
        kind: "aborted",
        reason: "aborted",
        message: `${ackContext.label}: the guest replacement was cancelled after the abort.`,
        operationId,
        idempotencyKey: context.idempotencyKey ?? null,
        commitKey,
      });
    }
    return new WsspError({
      kind: "unknown",
      reason: "aborted",
      message: `${ackContext.label}: the abort raced the guest replacement (outcome: ${cancel.outcome}); poll the operation before assuming the file's content.`,
      operationId,
      idempotencyKey: context.idempotencyKey ?? null,
      commitKey,
    });
  }

  /** Wrap one answered download in the validating stream and its accessors. */
  function wrapDownload(
    content: DownloadContent & { operationId: string },
    context: PollContext,
  ): FileDownload {
    // The hash covers the whole capture: only a response spanning it verifies.
    const whole = content.start === 0 && content.length === content.size;
    let claimed = false;
    const open = (): ReadableStream<Uint8Array> => {
      if (claimed) {
        throw invalidRequest(context, "the download stream was already consumed.");
      }
      claimed = true;
      return validated;
    };
    const hash = createHash("sha256");
    let seen = 0;
    const body = content.body;
    const reader = body?.getReader();
    // Every body-stage failure carries the capture's recovery identity: with
    // an SDK-generated key this is the only handle for replaying (rather than
    // duplicating) an already-accepted capture after a truncation, a hash
    // mismatch, or a cancellation.
    const recoveryKey = context.idempotencyKey ?? null;
    const integrity = (detail: string, cause?: unknown) =>
      new WsspError({
        kind: "unavailable",
        code: "TRANSFER_IO",
        message: `${context.label}: ${detail}`,
        operationId: content.operationId,
        idempotencyKey: recoveryKey,
        cause,
      });
    const validated = new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          if (!reader) {
            c.close();
            return;
          }
          let result: Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>["read"]>>;
          try {
            result = await reader.read();
          } catch (error) {
            // A typed abort from the transport body (caller signal fired
            // mid-read) stays an abort — never a length failure or a
            // TRANSFER_IO misreport — but the transport error carries no
            // capture identity: attach the operation ID and the reservation
            // key so an SDK-generated-key download stays recoverable.
            if (isWsspError(error, "aborted")) {
              throw new WsspError({
                kind: "aborted",
                reason: "aborted",
                message: `${context.label}: the download was aborted.`,
                operationId: content.operationId,
                idempotencyKey: recoveryKey,
              });
            }
            // A body failure's raw message can carry credentials (an injected
            // adapter's diagnostics): fixed public text plus a REDACTED cause.
            throw integrity(
              `the stream broke after ${seen} of ${content.length} bytes.`,
              transport.redactCause(error),
            );
          }
          if (result.done) {
            if (seen !== content.length) {
              throw integrity(`the body ended at ${seen} of ${content.length} bytes.`);
            }
            if (whole && hash.digest("hex") !== content.sha256) {
              throw integrity("the received bytes do not match the capture SHA-256.");
            }
            c.close();
            return;
          }
          seen += result.value.byteLength;
          if (seen > content.length) {
            // Request cancellation without AWAITING it: a body whose cancel()
            // never settles must not hold the error path open.
            void reader.cancel().catch(() => {});
            throw integrity(`the body overran the declared ${content.length} bytes.`);
          }
          hash.update(result.value);
          c.enqueue(result.value);
        },
        cancel(reason) {
          // Requested, never awaited: a body whose cancel() never settles
          // must not hang a consumer's `download.stream.cancel()`.
          void reader?.cancel(reason).catch(() => {});
        },
      },
      // Demand-driven: no byte is pulled before a consumer asks, so the
      // bytes() memory-cap gate rejects an over-cap body with zero reads.
      { highWaterMark: 0 },
    );
    const download: FileDownload = {
      operationId: content.operationId,
      size: content.size,
      sha256: content.sha256,
      etag: content.etag,
      start: content.start,
      length: content.length,
      get stream() {
        return open();
      },
      nodeStream() {
        return Readable.fromWeb(
          open() as unknown as import("node:stream/web").ReadableStream<Uint8Array>,
        );
      },
      async bytes(bytesOptions = {}) {
        const maxBytes = boundedOption(
          context,
          "maxBytes",
          bytesOptions.maxBytes ?? DEFAULT_FILE_MEMORY_BYTES,
          0,
          DEFAULT_FILE_MEMORY_BYTES,
        );
        // The declared length gates BEFORE any body byte is read into memory.
        if (content.length > maxBytes) {
          // Fire-and-forget: awaiting a stalled cancel() would resurrect the
          // very hang this pre-read gate exists to prevent.
          void reader?.cancel().catch(() => {});
          throw invalidRequest(
            context,
            `the capture is ${content.length} bytes, over the ${maxBytes}-byte memory cap; use the streaming API.`,
          );
        }
        const streamReader = open().getReader();
        // One destination sized to the DECLARED length, filled in place: peak
        // payload memory is the cap plus at most one in-flight body chunk —
        // never a second full copy alongside a retained chunk list.
        const out = new Uint8Array(content.length);
        let at = 0;
        const abortedRead = () =>
          new WsspError({
            kind: "aborted",
            reason: "aborted",
            message: `${context.label}: the read was aborted.`,
            operationId: content.operationId,
            idempotencyKey: recoveryKey,
          });
        try {
          for (;;) {
            // Raced against the caller's signal even when it differs from the
            // download's own: a stalled body cannot park the read.
            const next = await racedRead(streamReader.read(), bytesOptions.signal, undefined, () =>
              abortedRead(),
            );
            if (next.done) break;
            const value = next.value;
            // Belt for a forged Content-Length (the stream fences it first).
            if (at + value.byteLength > out.byteLength) {
              throw invalidRequest(
                context,
                `the body overran the declared ${content.length} bytes.`,
              );
            }
            out.set(value, at);
            at += value.byteLength;
          }
        } catch (error) {
          // Cancellation is REQUESTED, never awaited: when the abort won
          // racedRead, a body whose async cancel() never settles must not
          // leave bytes() pending forever.
          void streamReader.cancel().catch(() => {});
          throw error;
        }
        return out;
      },
    };
    return download;
  }

  async function openDownload(
    operationId: string,
    range: DownloadRange | undefined,
    ifRange: string | undefined,
    expectStart: number | undefined,
    signal: AbortSignal | undefined,
    timeoutMs: number | undefined,
    context: PollContext,
  ): Promise<FileDownload> {
    const content = await transport.downloadContent({
      params: { id: operationId },
      range,
      ifRange,
      signal,
      timeoutMs,
    });
    const tagged = { ...content, operationId };
    if (range !== undefined && content.status !== 206) {
      // A range request answered 200: the If-Range validator mismatched (or
      // the range was dropped) — the capture changed under the resume.
      void content.body?.cancel().catch(() => {});
      throw new WsspError({
        kind: "conflict",
        message: `${context.label}: the capture no longer matches the resumed download; restart it from byte 0.`,
        operationId,
      });
    }
    if (ifRange !== undefined && content.etag !== ifRange) {
      // A correctly-ranged 206 from a DIFFERENT capture: whole-content
      // hashing is skipped at nonzero offsets, so without this check the
      // caller would splice a foreign tail onto the resumed prefix.
      void content.body?.cancel().catch(() => {});
      throw new WsspError({
        kind: "conflict",
        message: `${context.label}: the capture ETag changed under the resumed download; restart it from byte 0.`,
        operationId,
      });
    }
    if (expectStart !== undefined && content.start !== expectStart) {
      void content.body?.cancel().catch(() => {});
      throw new WsspError({
        kind: "protocol",
        reason: "invalid_response",
        message: `${context.label}: the range starts at ${content.start}, not the requested ${expectStart}.`,
        operationId,
      });
    }
    return wrapDownload(tagged, context);
  }

  async function download(
    sandboxId: string,
    path: string,
    options: MutationOptions = {},
  ): Promise<FileDownload> {
    const context: PollContext = { label: `download ${sandboxId}` };
    const key = options.idempotencyKey ?? generateKey();
    context.idempotencyKey = key;
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    const receipt = await submitMutation(
      (attempt) =>
        transport.request("requestDownload", {
          params: { id: sandboxId },
          body: { path },
          idempotencyKey: key,
          signal: attempt,
        }),
      resolvePolling(defaults, { ...withWaitTimeout(options, deadline.remaining(context)) }),
      options.signal,
      context,
    );
    context.operationId = receipt.operationId;
    // Every failure after the capture was ACCEPTED carries its identity: the
    // reservation key and the operation ID. With an SDK-generated key this is
    // the only way the caller can recover (or audit) the capture instead of
    // blindly requesting another one.
    try {
      const operation = await waitOperation(
        transport,
        defaults,
        receipt.operationId,
        { ...withWaitTimeout(options, deadline.remaining(context)) },
        context,
      );
      ensureSucceeded(operation, context);
    } catch (error) {
      throw withRecoveryIdentity(error, key, null, receipt.operationId);
    }
    try {
      // Header acquisition shares the call's remaining budget (the capture
      // submission and polling already consumed part of it), clamped to the
      // transport's per-request cap — a valid multi-minute budget must not be
      // rejected outright. Only the BODY may stream beyond it, as documented.
      return await openDownload(
        receipt.operationId,
        undefined,
        undefined,
        undefined,
        options.signal,
        Math.min(deadline.remaining(context), MAX_TIMEOUT_MS),
        context,
      );
    } catch (error) {
      throw withRecoveryIdentity(error, key, null, receipt.operationId);
    }
  }

  async function resumeDownload(
    target: ResumeTarget,
    offset: number,
    options: WaitOptions = {},
  ): Promise<FileDownload> {
    const context: PollContext = {
      label: `resumeDownload ${target.operationId}`,
      operationId: target.operationId,
    };
    boundedOption(context, "offset", offset, 0, Number.MAX_SAFE_INTEGER);
    return openDownload(
      target.operationId,
      { start: offset },
      target.etag,
      offset,
      options.signal,
      waitTimeout(options),
      context,
    );
  }

  async function downloadRange(
    operationId: string,
    range: DownloadRange,
    options: WaitOptions = {},
  ): Promise<FileDownload> {
    const context: PollContext = { label: `downloadRange ${operationId}`, operationId };
    return openDownload(
      operationId,
      range,
      undefined,
      "suffix" in range ? undefined : range.start,
      options.signal,
      waitTimeout(options),
      context,
    );
  }

  async function readBytes(
    sandboxId: string,
    path: string,
    options: ReadBytesOptions = {},
  ): Promise<Uint8Array> {
    // maxBytes is validated before the capture is requested: an out-of-range
    // cap never starts an operation.
    const context: PollContext = { label: `readBytes ${sandboxId}` };
    boundedOption(
      context,
      "maxBytes",
      options.maxBytes ?? DEFAULT_FILE_MEMORY_BYTES,
      0,
      DEFAULT_FILE_MEMORY_BYTES,
    );
    const opened = await download(sandboxId, path, options);
    return opened.bytes({ maxBytes: options.maxBytes, signal: options.signal });
  }

  async function writeBytes(
    sandboxId: string,
    path: string,
    data: Uint8Array,
    options: WriteBytesOptions = {},
  ): Promise<UploadResult> {
    const context: PollContext = { label: `writeBytes ${sandboxId}` };
    const maxBytes = boundedOption(
      context,
      "maxBytes",
      options.maxBytes ?? DEFAULT_FILE_MEMORY_BYTES,
      0,
      DEFAULT_FILE_MEMORY_BYTES,
    );
    if (data.byteLength > maxBytes) {
      throw invalidRequest(
        context,
        `the buffer is ${data.byteLength} bytes, over the ${maxBytes}-byte memory cap; use the streaming upload.`,
      );
    }
    return upload(sandboxId, path, data, options);
  }

  async function observe(
    kind: ResultKind,
    sandboxId: string,
    options: MutationOptions,
    send: (
      key: string,
      signal: AbortSignal,
    ) => Promise<{
      operationId: string;
      state: import("@wssp/sandbox-contracts").OperationStateDto;
      location: string;
    }>,
  ): Promise<{ operation: OperationRead; envelope: OperationResult; context: PollContext }> {
    const key = options.idempotencyKey ?? generateKey();
    const context: PollContext = {
      label: `filesystem ${sandboxId}`,
      idempotencyKey: key,
      phase: "submit",
    };
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    try {
      const receipt = await submitMutation(
        (signal) => send(key, signal),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      context.operationId = receipt.operationId;
      context.phase = "follow";
      const operation = await waitOperation(
        transport,
        defaults,
        receipt.operationId,
        withWaitTimeout(options, deadline.remaining(context)),
        context,
      );
      if (operation.kind !== kind || operation.sandboxId !== sandboxId)
        throw new WsspError({
          kind: "protocol",
          reason: "invalid_response",
          message: "Filesystem status does not match its accepted operation.",
        });
      // Uncertainty/cancellation remains the primary outcome. FAILED stat still
      // reads its authorized version/expiry before any missing-path conversion.
      if (operation.outcome === "unknown" || operation.outcome === "cancelled")
        ensureSucceeded(operation, context);
      context.phase = "result";
      const envelope = await readWithRetry(
        (signal) =>
          transport.request("getOperationResult", { params: { id: receipt.operationId }, signal }),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      if (
        envelope.operationId !== receipt.operationId ||
        envelope.sandboxId !== sandboxId ||
        envelope.kind !== kind ||
        envelope.generation !== operation.generation ||
        envelope.outcome !== operation.outcome ||
        (envelope.result !== null && envelope.result.type !== RESULT_TYPE_BY_KIND[kind])
      )
        throw new WsspError({
          kind: "protocol",
          reason: "invalid_response",
          message: "Filesystem result does not match its accepted operation.",
        });
      return { operation, envelope, context };
    } catch (error) {
      throw attachErrorContext(error, {
        operationId: context.operationId,
        idempotencyKey: key,
        phase: context.phase,
      });
    }
  }
  function requireBody(snapshot: Awaited<ReturnType<typeof observe>>) {
    ensureSucceeded(snapshot.operation, snapshot.context);
    if (snapshot.envelope.result === null)
      throw new WsspError({
        kind: "protocol",
        reason: "invalid_response",
        message: "Filesystem result is unavailable.",
        operationId: snapshot.operation.id,
      });
    return snapshot.envelope.result;
  }
  async function stat(
    sandboxId: string,
    path: string,
    options: MutationOptions = {},
  ): Promise<FileStat | null> {
    const snapshot = await observe("STAT_PATH", sandboxId, options, (key, signal) =>
      transport.request("statPath", {
        params: { id: sandboxId },
        body: { path },
        idempotencyKey: key,
        signal,
      }),
    );
    if (snapshot.operation.outcome === "failed" && snapshot.operation.errorCode === "fs_not_found")
      return null;
    const body = requireBody(snapshot);
    if (body.type !== "file.stat")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
    return { ...body.entry, operationId: snapshot.operation.id };
  }
  async function getInfo(
    sandboxId: string,
    path: string,
    options: MutationOptions = {},
  ): Promise<EntryInfo> {
    const snapshot = await observe("STAT_PATH", sandboxId, options, (key, signal) =>
      transport.request("statPath", {
        params: { id: sandboxId },
        body: { path },
        idempotencyKey: key,
        signal,
      }),
    );
    const body = requireBody(snapshot);
    if (body.type !== "file.stat")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
    return body.entry;
  }
  async function list(
    sandboxId: string,
    path: string,
    options: FileListOptions = {},
  ): Promise<Page<EntryInfo>> {
    const snapshot = await observe("LIST_DIR", sandboxId, options, (key, signal) =>
      transport.request("listDir", {
        params: { id: sandboxId },
        body: {
          path,
          depth: options.depth ?? 1,
          limit: options.limit ?? 100,
          cursor: options.cursor,
        },
        idempotencyKey: key,
        signal,
      }),
    );
    const body = requireBody(snapshot);
    if (body.type !== "file.list")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
    return { items: body.items, nextCursor: body.nextCursor, consistency: body.consistency };
  }
  async function makeDir(
    sandboxId: string,
    path: string,
    options: MutationOptions = {},
  ): Promise<boolean> {
    const snapshot = await observe("MKDIR", sandboxId, options, (key, signal) =>
      transport.request("mkdir", {
        params: { id: sandboxId },
        body: { path },
        idempotencyKey: key,
        signal,
      }),
    );
    const body = requireBody(snapshot);
    if (body.type !== "file.mkdir")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
    return body.created;
  }
  async function remove(
    sandboxId: string,
    path: string,
    options: FileRemoveOptions = {},
  ): Promise<void> {
    const snapshot = await observe("REMOVE_PATH", sandboxId, options, (key, signal) =>
      transport.request("removePath", {
        params: { id: sandboxId },
        body: { path, recursive: options.recursive ?? false },
        idempotencyKey: key,
        signal,
      }),
    );
    if (requireBody(snapshot).type !== "file.remove")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
  }
  async function rename(
    sandboxId: string,
    from: string,
    to: string,
    options: MutationOptions = {},
  ): Promise<EntryInfo> {
    const snapshot = await observe("MOVE_PATH", sandboxId, options, (key, signal) =>
      transport.request("movePath", {
        params: { id: sandboxId },
        body: { path: from, destPath: to },
        idempotencyKey: key,
        signal,
      }),
    );
    const body = requireBody(snapshot);
    if (body.type !== "file.rename")
      throw new WsspError({ kind: "protocol", message: "Unexpected filesystem result." });
    return body.entry;
  }

  return {
    list,
    getInfo,
    makeDir,
    remove,
    rename,
    limits,
    upload,
    download,
    resumeDownload,
    downloadRange,
    readBytes,
    writeBytes,
    stat,
    exists: async (sandboxId, path, options = {}) =>
      (await stat(sandboxId, path, options)) !== null,
  };
}
