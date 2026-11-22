import { createHash, randomUUID } from "node:crypto";
import {
  FS_PROCESS_LIMITS,
  guestApiCapabilities,
  SDK_ERRORS,
  type SdkErrorCode,
  TRANSFER_CHUNK_BYTES,
  VM_SIZE_PUBLIC_LIMITS,
} from "@wssp/sandbox-contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { isWsspError, WsspError } from "./errors";
import { DEFAULT_FILE_MEMORY_BYTES } from "./files";
import { derivedTransferKey } from "./transfers";
import type { FetchLike } from "./transport";

const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test/root";
const CHUNK = TRANSFER_CHUNK_BYTES;
const NOW = "2026-01-01T00:00:00.000Z";
const LATER = "2026-01-01T01:00:00.000Z";

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** Deterministic binary content: every byte value, position-dependent. */
function makeBytes(length: number, seed = 7): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 31 + seed + (i >> 8)) & 0xff;
  return out;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function envelope(code: SdkErrorCode): Response {
  const [status, message] = SDK_ERRORS[code];
  return json(status, { error: { code, message, requestId: randomUUID() } });
}

type StoredTransfer = {
  id: string;
  sandboxId: string;
  guestPath: string;
  total: number;
  state: "OPEN" | "SEALED" | "ABORTED" | "EXPIRED" | "FAILED";
  chunks: Map<number, Uint8Array>;
  received: number;
  key: string;
  operationId: string | null;
  commitKey: string | null;
  commitSha: string | null;
  /** Sandbox generation at reservation; a change fences writes/commits (410). */
  generation: number;
};

type OperationRecord = {
  id: string;
  sandboxId: string;
  kind: string;
  state: "QUEUED" | "SUCCEEDED" | "FAILED" | "CANCELLED";
  errorCode: string | null;
  path?: string;
  /** Polls before the terminal state. */
  pendingPolls: number;
};

type Capture = {
  operationId: string;
  bytes: Uint8Array;
  expired: boolean;
  /** Sandbox generation at capture time; a change expires the content (410). */
  generation: number;
};

type ServerFault = {
  /** Accept the next chunk write but drop its response. */
  dropNextChunkResponse?: boolean;
  /** Land the commit (sealing the transfer) but drop every response to it. */
  dropCommitResponses?: boolean;
  /** Answer every request with 401 (a revoked key). */
  revoked?: boolean;
  /** Revoke the key after this many chunk writes (mid-upload revocation). */
  revokeAfterPuts?: number;
  /** Truncate a download body after this many bytes (mid-stream break). */
  truncateBodyAt?: number;
  /** Corrupt one byte of the sealed content before the commit read. */
  corruptSealed?: boolean;
  /** The content body never delivers a byte (a stalled transfer). */
  hangContent?: boolean;
  /** The content request never answers at all (stalled HEADERS). */
  hangContentHeaders?: boolean;
  /** Retire a transfer EXPIRED right after its commit lands (sweeper race). */
  expireAfterCommit?: boolean;
  /** Retire a transfer FAILED right after its commit lands (startup recovery
   * found the spool gone but kept the committed operation). */
  failAfterCommit?: boolean;
  /** Answer every operation read with 403 (a key without operations:read). */
  forbidOperationReads?: boolean;
  /** The operation never leaves QUEUED (wait deadlines always expire). */
  operationNeverTerminates?: boolean;
  /** Close the body cleanly after this many bytes (a clean short body). */
  shortBodyCloseAt?: number;
  /** Declare this Content-Length while serving the full capture (forged). */
  forgeContentLength?: number;
  /** Land every commit durably but answer 403 (post-commit fencing). */
  fenceCommitResponses?: boolean;
  /** Hold a fresh commit in server-side hashing until releaseCommit(). */
  holdCommit?: boolean;
  /** Refuse every fresh commit with 429 TRANSFER_QUOTA (E-18). */
  quotaCommits?: boolean;
  /** Answer downloads with a DIFFERENT strong ETag than the capture's. */
  forgeEtag?: string;
};

function receiptOf(t: StoredTransfer) {
  return {
    id: t.id,
    sandboxId: t.sandboxId,
    generation: t.generation,
    direction: "UPLOAD",
    state: t.state,
    totalBytes: t.total,
    receivedBytes: t.received,
    chunkBytes: CHUNK,
    idleExpiresAt: LATER,
    expiresAt: LATER,
  };
}

function operationJson(op: OperationRecord) {
  const terminal = op.state !== "QUEUED";
  return {
    id: op.id,
    sandboxId: op.sandboxId,
    kind: op.kind,
    leaseIntent: null,
    failure: null,
    state: op.state,
    outcome:
      op.state === "SUCCEEDED"
        ? "succeeded"
        : op.state === "FAILED"
          ? "failed"
          : op.state === "CANCELLED"
            ? "cancelled"
            : "pending",
    generation: 1,
    errorCode: op.errorCode,
    createdAt: NOW,
    updatedAt: NOW,
    dispatchedAt: NOW,
    completedAt: terminal ? LATER : null,
  };
}

/**
 * An in-memory server implementing the documented transfer wire semantics:
 * sequential chunk writes with digest-checked replays, whole-content commit
 * verification, immutable ranged captures with ETag/If-Range, and operation
 * polling. Fault flags script the failure modes under test.
 */
function fakeServer(config: {
  transferMaxBytes?: number;
  statOutcome?: "exists" | "missing" | "sandbox_gone";
  sandboxMissing?: boolean;
  capturePolls?: number;
  /** Polls before a committed PUT_FILE operation reaches SUCCEEDED. */
  commitPolls?: number;
}) {
  const state = {
    transfers: new Map<string, StoredTransfer>(),
    byKey: new Map<string, StoredTransfer>(),
    operations: new Map<string, OperationRecord>(),
    captures: new Map<string, Capture>(),
    fault: {} as ServerFault,
    /** Live sandbox generation; captures fence on it. */
    generation: 1,
    writes: [] as { id: string; offset: number; bytes: Uint8Array }[],
    bodyBytesServed: 0,
    /** Underlying body pull invocations (eager-consumption detector). */
    bodyPulls: 0,
    cancelledBodies: 0,
    cancelRequests: [] as string[],
    puts: 0,
    /** Operation submissions by idempotency key (production replays them). */
    opByKey: new Map<string, OperationRecord>(),
    /** Transfers with an in-flight commit (the exclusive permit). */
    commitsInFlight: new Set<string>(),
  };
  const maxBytes = config.transferMaxBytes ?? 64 * CHUNK;

  function newOperation(
    sandboxId: string,
    kind: string,
    pendingPolls = 0,
    errorCode: string | null = null,
  ): OperationRecord {
    const op: OperationRecord = {
      id: `op_${randomUUID().slice(0, 8)}`,
      sandboxId,
      kind,
      state: pendingPolls > 0 ? "QUEUED" : errorCode ? "FAILED" : "SUCCEEDED",
      errorCode,
      pendingPolls,
    };
    state.operations.set(op.id, op);
    return op;
  }

  async function readJson(call: { init: RequestInit }): Promise<Record<string, unknown>> {
    const body = call.init.body;
    if (typeof body !== "string") return {};
    return JSON.parse(body) as Record<string, unknown>;
  }

  async function handle(url: string, init: RequestInit): Promise<Response> {
    if (state.fault.revoked) return envelope("UNAUTHORIZED");
    const path = new URL(url).pathname;
    const headers = init.headers as Record<string, string>;
    const key = headers["idempotency-key"];

    if (path.endsWith("/v1/capabilities")) {
      return json(200, {
        apiVersion: "v1",
        guestApi: guestApiCapabilities(false),
        features: ["files.upload", "files.download"],
        limits: {
          ...FS_PROCESS_LIMITS,
          ...VM_SIZE_PUBLIC_LIMITS,
          sandboxTimeoutMinMs: 1,
          sandboxTimeoutDefaultMs: 300000,
          sandboxTimeoutMaxMs: 86400000,
          sandboxTimeoutZero: false,
          pageSizeDefault: 20,
          pageSizeMax: 100,
          jsonBodyMaxBytes: 1_048_576,
          transferMaxBytes: maxBytes,
          capacityWaitMaxMs: 3_600_000,
          capacityQueuePerKey: 16,
          capacityQueuePerOwner: 64,
        },
        ports: { ingress: false, proxy: false, tunnel: false },
        network: { egressModes: ["open", "allowlist"], defaultEgressMode: "open" },
        key: {
          ownSandboxesOnly: false,
          scopes: [],
          resourceMode: "allOwned",
          poolMode: "allUsable",
        },
      });
    }

    if (path.endsWith("/v1/transfers") && init.method === "POST") {
      const body = await readJson({ init });
      const prior = key !== undefined ? state.byKey.get(`${body.sandboxId}:${key}`) : undefined;
      if (prior) {
        if (prior.total !== body.totalBytes || prior.guestPath !== body.guestPath) {
          return envelope("CONFLICT");
        }
        return json(201, receiptOf(prior));
      }
      if (typeof body.totalBytes !== "number" || body.totalBytes > maxBytes) {
        return envelope("PAYLOAD_TOO_LARGE");
      }
      const transfer: StoredTransfer = {
        id: randomUUID(),
        sandboxId: String(body.sandboxId),
        guestPath: String(body.guestPath),
        total: Number(body.totalBytes),
        state: "OPEN",
        chunks: new Map(),
        received: 0,
        key: String(key),
        operationId: null,
        commitKey: null,
        commitSha: null,
        generation: state.generation,
      };
      state.transfers.set(transfer.id, transfer);
      state.byKey.set(`${transfer.sandboxId}:${transfer.key}`, transfer);
      return json(201, receiptOf(transfer), { location: `/v1/transfers/${transfer.id}` });
    }

    const transferMatch = /\/v1\/transfers\/([0-9a-f-]+)(\/commit)?$/.exec(path);
    if (transferMatch) {
      const transfer = state.transfers.get(transferMatch[1]!);
      if (!transfer) return envelope("NOT_FOUND");
      const isCommit = transferMatch[2] === "/commit";
      // Mirror the real store: a LANDED commit stays replayable under its key
      // even after retirement EXPIRED (sweeper) or FAILED (startup recovery
      // found the spool missing/corrupt but kept the operation) — status
      // reads still return the receipt; new writes/commits 410.
      if (transfer.state === "EXPIRED" || transfer.state === "FAILED") {
        if (init.method === "GET") return json(200, receiptOf(transfer));
        if (
          isCommit &&
          transfer.operationId !== null &&
          transfer.commitKey !== null &&
          transfer.commitKey === key
        ) {
          if (state.fault.dropCommitResponses) throw new TypeError("response lost");
          return json(202, {
            operationId: transfer.operationId,
            state: "QUEUED" as const,
            location: `/v1/operations/${transfer.operationId}`,
          });
        }
        return envelope("TRANSFER_EXPIRED");
      }
      if (init.method === "GET") return json(200, receiptOf(transfer));
      if (init.method === "DELETE") {
        // Mirror upload-routes.ts: a nonempty DELETE body must declare JSON.
        const hasBody = init.body !== undefined && init.body !== null;
        if (hasBody && headers["content-type"] !== "application/json") {
          return envelope("UNSUPPORTED_MEDIA_TYPE");
        }
        if (transfer.state === "SEALED") return envelope("CONFLICT");
        transfer.state = "ABORTED";
        return json(200, receiptOf(transfer));
      }
      if (init.method === "PUT") {
        if (
          state.fault.revokeAfterPuts !== undefined &&
          state.puts >= state.fault.revokeAfterPuts
        ) {
          return envelope("UNAUTHORIZED");
        }
        // Generation fencing matches TransferStore.current(): a sandbox
        // generation change on a LIVE reservation is 409 CONFLICT (410 is
        // reserved for terminal/expired reservations).
        if (transfer.generation !== state.generation) return envelope("CONFLICT");
        const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(headers["content-range"] ?? "");
        if (!match) return envelope("BAD_REQUEST");
        const [start, end, total] = match.slice(1).map(Number);
        const bytes = new Uint8Array(init.body as Uint8Array);
        if (
          total !== transfer.total ||
          start! % CHUNK !== 0 ||
          bytes.byteLength !== end! - start! + 1 ||
          bytes.byteLength !== Math.min(CHUNK, total! - start!)
        ) {
          return envelope("BAD_REQUEST");
        }
        const existing = transfer.chunks.get(start!);
        if (existing) {
          if (sha256(existing) !== sha256(bytes)) return envelope("CONFLICT");
          return json(200, receiptOf(transfer));
        }
        if (transfer.state !== "OPEN" || start !== transfer.received) {
          return envelope("CONFLICT");
        }
        transfer.chunks.set(start!, bytes);
        transfer.received = start! + bytes.byteLength;
        state.writes.push({ id: transfer.id, offset: start!, bytes });
        state.puts += 1;
        if (state.fault.dropNextChunkResponse) {
          state.fault.dropNextChunkResponse = false;
          throw new TypeError("response lost");
        }
        return json(200, receiptOf(transfer));
      }
      // commit
      const receipt202 = {
        operationId: transfer.operationId,
        state: "QUEUED" as const,
        location: `/v1/operations/${transfer.operationId}`,
      };
      if (transfer.operationId && transfer.commitKey === key) {
        if (state.fault.dropCommitResponses) throw new TypeError("response lost");
        if (state.fault.fenceCommitResponses) return envelope("FORBIDDEN");
        return json(202, receipt202);
      }
      // Commit hashing holds no DB transaction (store.ts:545-578): while a
      // fresh commit is held here the reservation still replays OPEN with
      // receivedBytes === totalBytes. Releasing lets the ORIGINAL commit land.
      // The exclusive transfer permit (store.ts:197, upload-routes.pg.test.ts:
      // 247-266): a second commit while one is active is rejected 409.
      if (state.fault.quotaCommits) return envelope("TRANSFER_QUOTA");
      if (state.commitsInFlight.has(transfer.id)) return envelope("CONFLICT");
      if (state.fault.holdCommit) {
        state.commitsInFlight.add(transfer.id);
        await commitGate;
        state.commitsInFlight.delete(transfer.id);
      }
      if (transfer.generation !== state.generation) return envelope("CONFLICT");
      if (transfer.state !== "OPEN" || transfer.received !== transfer.total) {
        return envelope("CONFLICT");
      }
      const whole = new Uint8Array(transfer.total);
      for (let offset = 0; offset < transfer.total; offset += CHUNK) {
        whole.set(transfer.chunks.get(offset)!, offset);
      }
      if (state.fault.corruptSealed && whole.byteLength > 0) whole[0]! ^= 0xff;
      const body = await readJson({ init });
      if (sha256(whole) !== body.sha256) return envelope("BAD_REQUEST");
      transfer.state = "SEALED";
      transfer.commitKey = String(key);
      transfer.commitSha = String(body.sha256);
      const op = newOperation(transfer.sandboxId, "PUT_FILE", config.commitPolls ?? 0);
      transfer.operationId = op.id;
      receipt202.operationId = op.id;
      receipt202.location = `/v1/operations/${op.id}`;
      // The commit LANDS; only the response is lost. expireAfterCommit
      // scripts the sweeper retiring the transfer before the client recovers.
      if (state.fault.expireAfterCommit) transfer.state = "EXPIRED";
      if (state.fault.failAfterCommit) transfer.state = "FAILED";
      if (state.fault.dropCommitResponses) throw new TypeError("response lost");
      // Post-commit fencing: the commit is durable, the response is 403.
      if (state.fault.fenceCommitResponses) return envelope("FORBIDDEN");
      return json(202, receipt202);
    }

    const statMatch = /\/v1\/sandboxes\/([^/]+)\/files\/(stat|download)$/.exec(path);
    if (statMatch && init.method === "POST") {
      if (config.sandboxMissing) return envelope("sandbox.not_found");
      const [, sandboxId, action] = statMatch;
      // Operation submissions are idempotency-keyed: a replayed key returns
      // the ORIGINAL operation instead of starting another capture/stat.
      const opKey = typeof key === "string" ? key : undefined;
      if (opKey) {
        const seen = state.opByKey.get(`${action}:${opKey}`);
        if (seen) {
          return json(202, {
            operationId: seen.id,
            state: seen.state,
            location: `/v1/operations/${seen.id}`,
          });
        }
      }
      if (action === "stat") {
        const errorCode =
          config.statOutcome === "missing"
            ? "fs_not_found"
            : config.statOutcome === "sandbox_gone"
              ? "sandbox_not_found"
              : null;
        const op = newOperation(sandboxId!, "STAT_PATH", 0, errorCode);
        op.path = String((await readJson({ init })).path);
        if (opKey) state.opByKey.set(`stat:${opKey}`, op);
        return json(202, {
          operationId: op.id,
          state: op.state,
          location: `/v1/operations/${op.id}`,
        });
      }
      const body = await readJson({ init });
      const op = newOperation(sandboxId!, "GET_FILE", config.capturePolls ?? 0);
      if (opKey) state.opByKey.set(`download:${opKey}`, op);
      const captureBytes = makeBytes(Number(body.sizeHint ?? 0) || 0);
      state.captures.set(op.id, {
        operationId: op.id,
        bytes: captureBytes,
        expired: false,
        generation: state.generation,
      });
      return json(202, {
        operationId: op.id,
        state: op.state,
        location: `/v1/operations/${op.id}`,
      });
    }

    const opMatch = /\/v1\/operations\/([^/]+)(\/content|\/cancel|\/result)?$/.exec(path);
    if (opMatch) {
      const op = state.operations.get(opMatch[1]!);
      if (!op) return envelope("sandbox.operation_not_found");
      if (opMatch[2] === "/result") {
        if (state.fault.forbidOperationReads) return envelope("FORBIDDEN");
        const path = op.path ?? "/app/blob";
        return json(200, {
          operationId: op.id,
          sandboxId: op.sandboxId,
          generation: 1,
          kind: op.kind,
          outcome: op.state === "SUCCEEDED" ? "succeeded" : "failed",
          observedAt: NOW,
          expiresAt: LATER,
          result:
            op.state === "SUCCEEDED"
              ? {
                  type: "file.stat",
                  entry: {
                    name: path.slice(path.lastIndexOf("/") + 1),
                    path,
                    type: "file",
                    size: 1,
                    mode: 420,
                    permissions: "rw-r--r--",
                    uid: 1000,
                    gid: 1000,
                    owner: null,
                    group: null,
                    modifiedTime: NOW,
                    symlinkTarget: null,
                  },
                }
              : null,
        });
      }
      if (opMatch[2] === "/cancel") {
        state.cancelRequests.push(op.id);
        // Production (services/sandboxes.ts:1087-1093) preserves terminal
        // outcomes: cancellation only lands on an operation still QUEUED.
        if (op.state === "QUEUED") op.state = "CANCELLED";
        return json(202, {
          operationId: `act_${op.id}`,
          state: "ACCEPTED",
          location: `/v1/operations/act_${op.id}`,
        });
      }
      if (opMatch[2] === "/content") {
        if (state.fault.hangContentHeaders) {
          // The headers themselves never arrive (a stalled content fetch);
          // like a real adapter, the request still honors caller aborts.
          await new Promise<never>((_resolve, reject) => {
            (init.signal as AbortSignal | null)?.addEventListener("abort", () =>
              reject(new DOMException("The operation was aborted.", "AbortError")),
            );
          });
        }
        const capture = state.captures.get(op.id);
        if (!capture) return envelope("sandbox.operation_not_found");
        if (op.state === "QUEUED") return envelope("TRANSFER_NOT_READY");
        if (op.state !== "SUCCEEDED") return envelope("CONFLICT");
        // Generation fencing: a sandbox change expires the capture (410).
        if (capture.expired || capture.generation !== state.generation) {
          return envelope("TRANSFER_EXPIRED");
        }
        const bytes = capture.bytes;
        // The If-Range validator matches the REAL capture; forgeEtag models
        // the response carrying a different strong ETag anyway.
        const realEtag = `"${sha256(bytes)}"`;
        const etag = state.fault.forgeEtag ?? realEtag;
        const size = bytes.byteLength;
        const rangeHeader = headers.range;
        const ifRange = headers["if-range"];
        let start = 0;
        let end = size - 1;
        let partial = false;
        if (rangeHeader !== undefined) {
          if (ifRange !== undefined && ifRange !== realEtag) {
            // Validator mismatch: the whole content restarts (200).
          } else {
            const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
            if (!match || (match[1] === "" && match[2] === "") || size === 0) {
              return json(416, {}, { "content-range": `bytes */${size}` });
            }
            if (match[1] === "") {
              const suffix = Number(match[2]);
              if (suffix < 1) return json(416, {}, { "content-range": `bytes */${size}` });
              start = Math.max(0, size - suffix);
            } else {
              start = Number(match[1]);
              if (match[2] !== "") end = Math.min(Number(match[2]), size - 1);
              if (start >= size || end < start) {
                return json(416, {}, { "content-range": `bytes */${size}` });
              }
            }
            partial = true;
          }
        }
        const slice = bytes.subarray(start, end + 1);
        const truncate = state.fault.truncateBodyAt;
        const shortClose = state.fault.shortBodyCloseAt;
        let remaining = slice;
        if (truncate !== undefined && truncate < slice.byteLength) {
          remaining = slice.subarray(0, truncate);
        } else if (shortClose !== undefined && shortClose < slice.byteLength) {
          remaining = slice.subarray(0, shortClose);
        }
        const truncated = truncate !== undefined && remaining.byteLength !== slice.byteLength;
        const responseHeaders: Record<string, string> = {
          etag,
          "content-length": String(state.fault.forgeContentLength ?? slice.byteLength),
          "accept-ranges": "bytes",
        };
        if (partial) responseHeaders["content-range"] = `bytes ${start}-${end}/${size}`;
        // Stream in 64 KiB frames so multi-read flows are exercised; a
        // truncated body ends early, as a mid-stream revocation does. With
        // hangContent the body never delivers a byte (a stalled transfer).
        const stream = new ReadableStream<Uint8Array>(
          {
            async pull(c) {
              state.bodyPulls += 1;
              if (state.fault.hangContent) {
                await new Promise(() => {});
                return;
              }
              const next = remaining.subarray(0, 64 * 1024);
              remaining = remaining.subarray(next.byteLength);
              state.bodyBytesServed += next.byteLength;
              if (next.byteLength === 0) {
                if (truncated) c.error(new Error("connection aborted mid-stream"));
                else c.close(); // shortClosed: a CLEAN end, fewer bytes than declared
                return;
              }
              c.enqueue(next);
            },
            cancel() {
              state.cancelledBodies += 1;
            },
          },
          // Demand-driven: a pull here means the SDK actually read the body.
          { highWaterMark: 0 },
        );
        return new Response(stream, { status: partial ? 206 : 200, headers: responseHeaders });
      }
      if (state.fault.forbidOperationReads) return envelope("FORBIDDEN");
      if (state.fault.operationNeverTerminates) {
        return json(200, operationJson({ ...op, state: "QUEUED" }));
      }
      if (op.pendingPolls > 0) {
        op.pendingPolls -= 1;
        return json(200, operationJson({ ...op, state: "QUEUED" }));
      }
      return json(200, operationJson(op));
    }

    throw new Error(`unhandled ${init.method} ${path}`);
  }

  const calls: { url: string; init: RequestInit }[] = [];
  let releaseCommit!: () => void;
  const commitGate = new Promise<void>((resolve) => {
    releaseCommit = resolve;
  });
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    calls.push({ url, init });
    return handle(url, init);
  });
  const client = createWsspClient({
    baseUrl: BASE,
    apiKey: KEY,
    fetch,
    polling: { intervalMs: 1, maxIntervalMs: 2, waitTimeoutMs: 30_000 },
  });
  return { client, state, calls, fetch, releaseCommit };
}

async function failure(promise: Promise<unknown>): Promise<WsspError> {
  const error = await promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(WsspError);
  return error as WsspError;
}

/** files.ts SOURCE_CLOSE_TIMEOUT_MS: how long an upload waits for a stalled source's return(). */
const SOURCE_CLOSE_BOUND_MS = 10_000;

/**
 * An upload on a fake clock (setTimeout, clearTimeout and Date; setImmediate
 * stays real), so the test crosses each bounded wait itself, one millisecond
 * short first, only after `reach` has seen the upload enter that wait.
 */
function onFakeClock(promise: () => Promise<unknown>) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  let settled = false;
  const outcome = failure(promise()).finally(() => {
    settled = true;
  });
  // Lets the fake server and the upload run (microtasks and real immediates)
  // without moving the clock, until `reached` holds.
  const reach = async (reached: () => boolean, what: string) => {
    for (let turn = 0; turn < 10_000 && !reached(); turn++) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(reached(), `the upload never reached ${what}`).toBe(true);
  };
  // Crosses a bound of `ms` that starts at the current fake time: still
  // pending 1 ms before it, then the outcome once it elapses.
  const cross = async (ms: number) => {
    await vi.advanceTimersByTimeAsync(ms - 1);
    expect(settled, `settled before the ${ms} ms bound`).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
  };
  const result = async () => {
    await reach(() => settled, "settlement");
    vi.useRealTimers();
    return outcome;
  };
  return { reach, cross, result, settled: () => settled };
}

// A failed onFakeClock() case must not leave its fake clock to the next case.
afterEach(() => {
  vi.useRealTimers();
});

/** `source`, counting next() and return() calls. */
function observed(source: AsyncIterable<Uint8Array>) {
  const calls = { next: 0, return: 0 };
  const iterable: AsyncIterable<Uint8Array> = {
    [Symbol.asyncIterator]() {
      const inner = source[Symbol.asyncIterator]();
      return {
        next() {
          calls.next += 1;
          return inner.next();
        },
        return() {
          calls.return += 1;
          return inner.return?.() ?? Promise.resolve({ done: true, value: undefined });
        },
      };
    },
  };
  return { iterable, calls };
}

/** Register a completed capture for `op` content reads after an upload flow. */
function plantCapture(
  server: ReturnType<typeof fakeServer>,
  operationId: string,
  bytes: Uint8Array,
) {
  server.state.captures.set(operationId, {
    operationId,
    bytes,
    expired: false,
    generation: server.state.generation,
  });
}

describe("files.upload roundtrips at boundary sizes", () => {
  it.each([0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 123])(
    "roundtrips %d bytes with the whole-content hash",
    async (size) => {
      const server = fakeServer({});
      const data = makeBytes(size);
      const result = await server.client.files.upload("sbx_1", "/app/blob", data, {
        idempotencyKey: `up-${size}`,
      });
      expect(result.totalBytes).toBe(size);
      expect(result.sha256).toBe(sha256(data));
      const transfer = [...server.state.transfers.values()][0]!;
      expect(transfer.state).toBe("SEALED");
      expect(transfer.received).toBe(size);
      // Every write was sequential and within the reservation.
      let offset = 0;
      for (const write of server.state.writes) {
        expect(write.offset).toBe(offset);
        offset += write.bytes.byteLength;
      }
      expect(offset).toBe(size);
    },
  );

  it("chunks a stream source of uneven pieces", async () => {
    const server = fakeServer({});
    const size = 2 * CHUNK + 999;
    const data = makeBytes(size, 41);
    const pieces = async function* () {
      for (let at = 0; at < size; at += 100_003) {
        yield data.subarray(at, Math.min(size, at + 100_003));
      }
    };
    const result = await server.client.files.upload("sbx_1", "/s", pieces(), {
      idempotencyKey: "stream-1",
      totalBytes: size,
    });
    expect(result.sha256).toBe(sha256(data));
    expect(server.state.writes.map((w) => w.bytes.byteLength)).toEqual([CHUNK, CHUNK, 999]);
  });
});

describe("interrupted upload resumes at the durable offset", () => {
  it("a lost chunk response retries the identical chunk, never duplicates", async () => {
    const server = fakeServer({});
    server.state.fault.dropNextChunkResponse = true;
    const size = CHUNK + 5;
    const data = makeBytes(size);
    const result = await server.client.files.upload("sbx_1", "/app/x", data, {
      idempotencyKey: "resume-drop",
    });
    expect(result.sha256).toBe(sha256(data));
    // Chunk 0 was written once logically: the replay was a digest replay (no
    // second entry in the write journal).
    expect(server.state.writes).toHaveLength(2);
    expect(server.state.writes[0]!.offset).toBe(0);
    expect(server.state.writes[1]!.offset).toBe(CHUNK);
  });

  it("an aborted upload stays OPEN and resumes under the same key without duplicate writes", async () => {
    const server = fakeServer({});
    const size = 3 * CHUNK;
    const data = makeBytes(size);
    const controller = new AbortController();
    // Abort exactly when the first chunk write is in flight.
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (init.method === "PUT") controller.abort();
      return baseFetch(url, init);
    });
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "resume-abort",
        signal: controller.signal,
      }),
    );
    // The in-flight chunk may have landed: unknown (reason aborted), never a
    // plain wait error. The transfer stays resumable.
    expect(isWsspError(first, "unknown") || isWsspError(first, "aborted")).toBe(true);
    expect(first.idempotencyKey).toBe("resume-abort");
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("OPEN");
    expect(transfer.received).toBeGreaterThanOrEqual(0);

    server.fetch.mockImplementation(baseFetch);
    const result = await server.client.files.upload("sbx_1", "/app/x", data, {
      idempotencyKey: "resume-abort",
    });
    expect(result.sha256).toBe(sha256(data));
    // No offset was ever written twice, and the acknowledged prefix was not
    // re-sent: one PUT in the aborted attempt plus the two remaining chunks.
    const offsets = server.state.writes.map((w) => w.offset);
    expect(new Set(offsets).size).toBe(offsets.length);
    expect(offsets).toEqual([0, CHUNK, 2 * CHUNK].filter((o) => o < size));
    expect(server.calls.filter((c) => c.init.method === "PUT")).toHaveLength(3);
  });

  it("a one-shot stream cannot resume a partially-sent upload", async () => {
    const server = fakeServer({});
    const size = 2 * CHUNK;
    const data = makeBytes(size);
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (init.method === "PUT") controller.abort();
      return baseFetch(url, init);
    });
    const stream = async function* () {
      yield data;
    };
    await failure(
      server.client.files.upload("sbx_1", "/app/x", stream(), {
        idempotencyKey: "one-shot",
        totalBytes: size,
        signal: controller.signal,
      }),
    );
    server.fetch.mockImplementation(baseFetch);
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.received).toBe(CHUNK);
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", stream(), {
        idempotencyKey: "one-shot",
        totalBytes: size,
      }),
    );
    expect(error.kind).toBe("invalid_request");
  });

  it("an abort racing a COMPLETED guest replacement reports unknown with recovery identities", async () => {
    const server = fakeServer({});
    const data = makeBytes(10);
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    let abortArmed = false;
    server.fetch.mockImplementation(async (url, init) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/commit")) abortArmed = true;
      // Abort once the commit has landed and the replacement wait begins.
      if (abortArmed && init.method === "GET" && /\/v1\/operations\/[^/]+$/.test(path)) {
        controller.abort();
      }
      return baseFetch(url, init);
    });
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "cancel-race",
        signal: controller.signal,
      }),
    );
    // The commit's PUT_FILE completed synchronously: production preserves
    // terminal outcomes, so the cancellation request cannot overwrite it —
    // completion WON the race and the caller must learn the outcome.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe("cancel-race");
    expect(error.commitKey).toBe(derivedTransferKey("cancel-race", "commit"));
    expect(error.operationId).not.toBeNull();
    expect(server.state.cancelRequests).toHaveLength(1);
    const op = [...server.state.operations.values()].find((o) => o.kind === "PUT_FILE")!;
    expect(op.state).toBe("SUCCEEDED");
  });
});

describe("source validation", () => {
  it("a short source fails locally and releases the reservation", async () => {
    const server = fakeServer({});
    const short = async function* () {
      yield new Uint8Array(10);
    };
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", short(), {
        idempotencyKey: "short-src",
        totalBytes: CHUNK,
      }),
    );
    expect(error.kind).toBe("invalid_request");
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("ABORTED");
  });

  it("a buffer disagreeing with the declared total fails before any IO", async () => {
    const server = fakeServer({});
    const data = makeBytes(CHUNK + 10);
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "over-src",
        totalBytes: CHUNK,
      }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(server.calls).toHaveLength(0);
  });

  it("a stream exceeding the declared total never sends the overflowing chunk", async () => {
    const server = fakeServer({});
    const data = makeBytes(CHUNK + 10);
    const stream = async function* () {
      yield data;
    };
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", stream(), {
        idempotencyKey: "over-stream",
        totalBytes: CHUNK,
      }),
    );
    expect(error.kind).toBe("invalid_request");
    // Only the one in-bounds chunk was sent; the overflow failed locally.
    expect(server.state.writes).toHaveLength(1);
    expect(server.state.writes[0]!.offset).toBe(0);
  });

  it("a stream yielding non-bytes fails before that chunk is sent", async () => {
    const server = fakeServer({});
    const bad = async function* () {
      yield "text" as unknown as Uint8Array;
    };
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", bad(), {
        idempotencyKey: "bad-chunk",
        totalBytes: 4,
      }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(server.state.writes).toHaveLength(0);
  });

  it("commit rejects a wrong whole-content hash (server-side verification)", async () => {
    const server = fakeServer({});
    server.state.fault.corruptSealed = true;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", makeBytes(100), {
        idempotencyKey: "hash-mismatch",
      }),
    );
    expect(error.kind).toBe("invalid_request");
  });
});

describe("files.download and readBytes", () => {
  it("captures and streams a file with hash validation", async () => {
    const server = fakeServer({});
    const data = makeBytes(CHUNK + 17);
    // Plant the capture the download request will create.
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(url).pathname.endsWith("/files/download")) {
        const response = await baseFetch(url, init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(url, init);
    });
    const download = await server.client.files.download("sbx_1", "/app/blob", {
      idempotencyKey: "dl-1",
    });
    expect(download.size).toBe(data.byteLength);
    expect(download.sha256).toBe(sha256(data));
    const collected: Uint8Array[] = [];
    const reader = download.stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      collected.push(value);
    }
    expect(Buffer.concat(collected.map((c) => Buffer.from(c)))).toEqual(Buffer.from(data));
  });

  it("readBytes returns the exact bytes", async () => {
    const server = fakeServer({});
    const data = makeBytes(65_537, 99);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(url).pathname.endsWith("/files/download")) {
        const response = await baseFetch(url, init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(url, init);
    });
    const bytes = await server.client.files.readBytes("sbx_1", "/app/blob");
    expect(bytes).toEqual(data);
  });

  it("readBytes rejects an over-cap capture BEFORE reading the body", async () => {
    const server = fakeServer({});
    const data = makeBytes(2 * 1024 * 1024);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(url).pathname.endsWith("/files/download")) {
        const response = await baseFetch(url, init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(url, init);
    });
    // The declared length alone decides: the body hangs forever, so any
    // implementation that reads before enforcing the cap never resolves.
    server.state.fault.hangContent = true;
    const error = await failure(
      server.client.files.readBytes("sbx_1", "/app/blob", { maxBytes: 1024 }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(server.state.bodyBytesServed).toBe(0);
    // Demand-driven wrappers: the over-cap rejection never invoked a single
    // underlying body read.
    expect(server.state.bodyPulls).toBe(0);
    expect(server.state.cancelledBodies).toBe(1);
  });

  it("writeBytes rejects an over-cap buffer before any IO", async () => {
    const server = fakeServer({});
    const error = await failure(
      server.client.files.writeBytes(
        "sbx_1",
        "/app/x",
        new Uint8Array(DEFAULT_FILE_MEMORY_BYTES + 1),
      ),
    );
    expect(error.kind).toBe("invalid_request");
    expect(server.calls).toHaveLength(0);
  });

  it("bytes failing the advertised hash fail the stream with TRANSFER_IO at the end", async () => {
    // Serve a body whose bytes do not match the ETag-advertised hash (a
    // corrupted capture): the validating stream must error, not yield.
    const data = makeBytes(1000);
    const wrongDigest = "0".repeat(64);
    const fetch = vi.fn<FetchLike>(async (_url, init) => {
      const range = (init.headers as Record<string, string>).range;
      const ranged = range !== undefined;
      const stream = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(data);
          c.close();
        },
      });
      return new Response(stream, {
        status: ranged ? 206 : 200,
        headers: {
          etag: `"${wrongDigest}"`,
          "content-length": String(data.byteLength),
          "accept-ranges": "bytes",
          ...(ranged
            ? { "content-range": `bytes 0-${data.byteLength - 1}/${data.byteLength}` }
            : {}),
        },
      });
    });
    const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
    const download = await client.files.downloadRange("op_x", { start: 0 });
    const error = await failure(
      (async () => {
        const reader = download.stream.getReader();
        for (;;) {
          if ((await reader.read()).done) return;
        }
      })(),
    );
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
  });

  it("a mid-stream break errors the stream as TRANSFER_IO", async () => {
    const server = fakeServer({});
    const data = makeBytes(300_000);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(url).pathname.endsWith("/files/download")) {
        const response = await baseFetch(url, init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(url, init);
    });
    server.state.fault.truncateBodyAt = 100_000;
    const download = await server.client.files.download("sbx_1", "/app/blob");
    const error = await failure(
      (async () => {
        const reader = download.stream.getReader();
        for (;;) {
          if ((await reader.read()).done) return;
        }
      })(),
    );
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
  });

  it("an expired capture is gone (410), a pending one a conflict (409)", async () => {
    const server = fakeServer({});
    const op = { id: "op_exp" };
    plantCapture(server, op.id, makeBytes(10));
    server.state.captures.get(op.id)!.expired = true;
    server.state.operations.set(op.id, {
      id: op.id,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "SUCCEEDED",
      errorCode: null,
      pendingPolls: 0,
    });
    const gone = await failure(server.client.files.downloadRange(op.id, { start: 0 }));
    expect(gone.kind).toBe("gone");

    const pending = { id: "op_pending" };
    plantCapture(server, pending.id, makeBytes(10));
    server.state.operations.set(pending.id, {
      id: pending.id,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "QUEUED",
      errorCode: null,
      pendingPolls: 0,
    });
    const conflict = await failure(server.client.files.downloadRange(pending.id, { start: 0 }));
    expect(conflict.kind).toBe("conflict");
    expect(conflict.code).toBe("TRANSFER_NOT_READY");
  });
});

async function withCapture(size: number, seed = 7) {
  const server = fakeServer({});
  const data = makeBytes(size, seed);
  const opId = "op_cap";
  plantCapture(server, opId, data);
  server.state.operations.set(opId, {
    id: opId,
    sandboxId: "sbx_1",
    kind: "GET_FILE",
    state: "SUCCEEDED",
    errorCode: null,
    pendingPolls: 0,
  });
  return { server, data, opId };
}

describe("ranges and resume", () => {
  it("downloadRange reads one inclusive range with the exact bytes", async () => {
    const { server, data, opId } = await withCapture(1000);
    const range = await server.client.files.downloadRange(opId, { start: 100, end: 199 });
    expect(range.start).toBe(100);
    expect(range.length).toBe(100);
    expect(range.size).toBe(1000);
    expect(await range.bytes()).toEqual(data.subarray(100, 200));
  });

  it("an unsatisfiable range is invalid_request (416)", async () => {
    const { server, opId } = await withCapture(1000);
    const error = await failure(server.client.files.downloadRange(opId, { start: 5000 }));
    expect(error.kind).toBe("invalid_request");
    expect(error.code).toBe("RANGE_NOT_SATISFIABLE");
  });

  it("an interrupted download resumes at the offset with If-Range", async () => {
    const { server, data, opId } = await withCapture(300_000);
    const first = await server.client.files.downloadRange(opId, { start: 0, end: 99_999 });
    const head = await first.bytes();
    const resumed = await server.client.files.resumeDownload(
      { operationId: opId, etag: first.etag },
      100_000,
    );
    expect(resumed.start).toBe(100_000);
    const tail = await resumed.bytes({ maxBytes: 300_000 });
    const whole = new Uint8Array(300_000);
    whole.set(head, 0);
    whole.set(tail, 100_000);
    expect(whole).toEqual(data);
  });

  it("a stale ETag on resume conflicts instead of silently restarting", async () => {
    const { server, opId } = await withCapture(1000);
    const wrongEtag = `"${"0".repeat(64)}"`;
    const error = await failure(
      server.client.files.resumeDownload({ operationId: opId, etag: wrongEtag }, 100),
    );
    expect(error.kind).toBe("conflict");
  });

  it("a changed generation expires the content (410 gone)", async () => {
    const { server, data, opId } = await withCapture(1000);
    // Actually move the sandbox generation; the capture's fence expires it.
    server.state.generation += 1;
    const error = await failure(
      server.client.files.resumeDownload({ operationId: opId, etag: `"${sha256(data)}"` }, 50),
    );
    expect(error.kind).toBe("gone");
    expect(error.code).toBe("TRANSFER_EXPIRED");
  });
});

describe("stat and missing-file versus missing-VM", () => {
  it("an existing path stats", async () => {
    const server = fakeServer({ statOutcome: "exists" });
    const stat = await server.client.files.stat("sbx_1", "/app/blob");
    expect(stat).not.toBeNull();
    expect(stat!.path).toBe("/app/blob");
    expect(await server.client.files.exists("sbx_1", "/app/blob")).toBe(true);
  });

  it("a missing file resolves null", async () => {
    const server = fakeServer({ statOutcome: "missing" });
    expect(await server.client.files.stat("sbx_1", "/nope")).toBeNull();
    expect(await server.client.files.exists("sbx_1", "/nope")).toBe(false);
  });

  it("a missing sandbox throws not_found, never null", async () => {
    const server = fakeServer({ sandboxMissing: true });
    const error = await failure(server.client.files.stat("sbx_gone", "/app/blob"));
    expect(error.kind).toBe("not_found");
    expect(error.code).toBe("sandbox.not_found");
  });
});

describe("limits and revocation", () => {
  it("the server transfer cap is discoverable before capture/upload", async () => {
    const server = fakeServer({ transferMaxBytes: 3 * CHUNK });
    const limits = await server.client.files.limits();
    expect(limits.transferMaxBytes).toBe(3 * CHUNK);
    expect(limits.chunkBytes).toBe(CHUNK);
    expect(limits.memoryBytesDefault).toBe(DEFAULT_FILE_MEMORY_BYTES);
  });

  it("a revoked key fails the upload with authorization, mid-stream or first chunk", async () => {
    const server = fakeServer({});
    server.state.fault.revoked = true;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", makeBytes(10), {
        idempotencyKey: "revoked-1",
      }),
    );
    expect(error.kind).toBe("authorization");
    expect(error.code).toBe("UNAUTHORIZED");
  });

  it("an expired transfer stops the upload as gone", async () => {
    const server = fakeServer({});
    const controller = new AbortController();
    void controller;
    // Expire the transfer once it exists.
    const baseFetch = server.fetch.getMockImplementation()!;
    let expired = false;
    server.fetch.mockImplementation(async (url, init) => {
      if (!expired && init.method === "PUT") {
        expired = true;
        for (const transfer of server.state.transfers.values()) transfer.state = "EXPIRED";
      }
      return baseFetch(url, init);
    });
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", makeBytes(CHUNK + 1), {
        idempotencyKey: "expired-1",
      }),
    );
    expect(error.kind).toBe("gone");
    expect(error.code).toBe("TRANSFER_EXPIRED");
  });
});

describe("node stream adapters", () => {
  it("uploads from a Node Readable and downloads to one", async () => {
    const { Readable } = await import("node:stream");
    const server = fakeServer({});
    const data = makeBytes(CHUNK + 3, 21);
    const upload = await server.client.files.upload(
      "sbx_1",
      "/app/node",
      Readable.toWeb(Readable.from([data])) as AsyncIterable<Uint8Array>,
      { idempotencyKey: "node-up", totalBytes: data.byteLength },
    );
    expect(upload.sha256).toBe(sha256(data));

    const opId = "op_node";
    plantCapture(server, opId, data);
    server.state.operations.set(opId, {
      id: opId,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "SUCCEEDED",
      errorCode: null,
      pendingPolls: 0,
    });
    const download = await server.client.files.downloadRange(opId, { start: 0 });
    const nodeStream = download.nodeStream();
    const chunks: Buffer[] = [];
    for await (const chunk of nodeStream) chunks.push(Buffer.from(chunk));
    expect(Buffer.concat(chunks)).toEqual(Buffer.from(data));
  });

  it("the download stream is consumable exactly once", async () => {
    const server = fakeServer({});
    const opId = "op_once";
    plantCapture(server, opId, makeBytes(10));
    server.state.operations.set(opId, {
      id: opId,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "SUCCEEDED",
      errorCode: null,
      pendingPolls: 0,
    });
    const download = await server.client.files.downloadRange(opId, { start: 0 });
    await download.bytes();
    const error = await failure(download.bytes());
    expect(error.kind).toBe("invalid_request");
  });
});

describe("round-1 review: recovery, cancellation, memory and disclosure", () => {
  it("an interruption after the final (unaligned) chunk resumes straight to commit", async () => {
    const server = fakeServer({});
    const size = CHUNK + 5;
    const data = makeBytes(size);
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    // Abort once the whole content has landed but before the commit is sent.
    server.fetch.mockImplementation(async (url, init) => {
      const response = await baseFetch(url, init);
      const transfer = [...server.state.transfers.values()][0];
      if (transfer && transfer.received === size && transfer.state === "OPEN") {
        controller.abort();
      }
      return response;
    });
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "final-chunk",
        signal: controller.signal,
      }),
    );
    expect(isWsspError(first, "aborted") || isWsspError(first, "unknown")).toBe(true);
    expect(first.idempotencyKey).toBe("final-chunk");
    const transfer = [...server.state.transfers.values()][0]!;
    // The durable cursor is the unaligned exact total: a legitimate state.
    expect(transfer.received).toBe(size);
    expect(size % CHUNK).not.toBe(0);

    server.fetch.mockImplementation(baseFetch);
    const result = await server.client.files.upload("sbx_1", "/app/x", data, {
      idempotencyKey: "final-chunk",
    });
    expect(result.sha256).toBe(sha256(data));
    // No byte was re-sent: two PUTs total, both from the first attempt.
    expect(server.calls.filter((c) => c.init.method === "PUT")).toHaveLength(2);
    expect(result.totalBytes).toBe(size);
  });

  it("a lost commit response replays the SAME commit (one operation, in-call)", async () => {
    const server = fakeServer({});
    const size = CHUNK + 5;
    const data = makeBytes(size);
    // Land the commit, drop the first response; the retry replays it.
    let dropped = false;
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (!dropped && new URL(url).pathname.endsWith("/commit")) {
        dropped = true;
        server.state.fault.dropCommitResponses = true;
        try {
          return await baseFetch(url, init);
        } finally {
          server.state.fault.dropCommitResponses = false;
        }
      }
      return baseFetch(url, init);
    });
    const result = await server.client.files.upload("sbx_1", "/app/x", data, {
      idempotencyKey: "commit-replay",
    });
    expect(result.sha256).toBe(sha256(data));
    const putFileOps = [...server.state.operations.values()].filter((op) => op.kind === "PUT_FILE");
    expect(putFileOps).toHaveLength(1);
    expect(result.operationId).toBe(putFileOps[0]!.id);
  });

  it("an uncertain commit failure carries the reservation key plus commit identity, and recovers cross-call", async () => {
    const server = fakeServer({});
    const size = CHUNK + 5;
    const data = makeBytes(size);
    // Every commit response is lost, though the commit lands.
    server.state.fault.dropCommitResponses = true;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "uncertain-commit",
        waitTimeoutMs: 800,
      }),
    );
    expect(error.kind).toBe("unknown");
    // The RESERVATION key, not the derived commit key — a retry with it must work.
    expect(error.idempotencyKey).toBe("uncertain-commit");
    expect(error.commitKey).toBe(derivedTransferKey("uncertain-commit", "commit"));
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("SEALED");

    server.state.fault.dropCommitResponses = false;
    const recovered = await server.client.files.upload("sbx_1", "/app/x", data, {
      idempotencyKey: error.idempotencyKey!,
    });
    expect(recovered.sha256).toBe(sha256(data));
    // The replayed commit returned the ORIGINAL operation.
    expect(recovered.operationId).toBe(transfer.operationId);
    const putFileOps = [...server.state.operations.values()].filter((op) => op.kind === "PUT_FILE");
    expect(putFileOps).toHaveLength(1);
    // No byte was re-transmitted across the recovery.
    expect(server.calls.filter((c) => c.init.method === "PUT")).toHaveLength(2);
  });

  it("a stalled source aborts promptly and the source is closed", async () => {
    const server = fakeServer({});
    let returned = false;
    const stalled: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        let sent = false;
        return {
          next(): Promise<IteratorResult<Uint8Array>> {
            if (!sent) {
              sent = true;
              return Promise.resolve({ done: false, value: makeBytes(10) });
            }
            return new Promise(() => {});
          },
          return(): Promise<IteratorResult<Uint8Array>> {
            returned = true;
            return Promise.resolve({ done: true, value: undefined });
          },
        };
      },
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 50);
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", stalled, {
        idempotencyKey: "stalled-abort",
        totalBytes: 100,
        signal: controller.signal,
      }),
    );
    clearTimeout(timer);
    expect(error.kind).toBe("aborted");
    expect(error.idempotencyKey).toBe("stalled-abort");
    expect(returned).toBe(true);
  });

  it("a stalled source loses to the upload deadline", async () => {
    const server = fakeServer({});
    const stalled: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        return { next: () => new Promise<IteratorResult<Uint8Array>>(() => {}) };
      },
    };
    const started = Date.now();
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", stalled, {
        idempotencyKey: "stalled-deadline",
        totalBytes: 100,
        waitTimeoutMs: 700,
      }),
    );
    expect(error.kind).toBe("timeout");
    expect(error.idempotencyKey).toBe("stalled-deadline");
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("a stalled body loses to the bytes() signal even when the download has none", async () => {
    const server = fakeServer({});
    server.state.fault.hangContent = true;
    const opId = "op_stall";
    plantCapture(server, opId, makeBytes(100));
    server.state.operations.set(opId, {
      id: opId,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "SUCCEEDED",
      errorCode: null,
      pendingPolls: 0,
    });
    const download = await server.client.files.downloadRange(opId, { start: 0 });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 50);
    const error = await failure(download.bytes({ signal: controller.signal }));
    clearTimeout(timer);
    expect(error.kind).toBe("aborted");
  });

  it("a failing body never discloses credentials through the stream error", async () => {
    const canary = KEY;
    const fetch = vi.fn<FetchLike>(async () => {
      const stream = new ReadableStream<Uint8Array>({
        pull(c) {
          c.error(new Error(`proxy failure, sent Authorization: Bearer ${canary}`));
        },
      });
      return new Response(stream, {
        status: 206,
        headers: {
          etag: `"${"0".repeat(64)}"`,
          "content-length": "10",
          "accept-ranges": "bytes",
          "content-range": "bytes 0-9/10",
        },
      });
    });
    const client = createWsspClient({ baseUrl: BASE, apiKey: canary, fetch });
    const download = await client.files.downloadRange("op_x", { start: 0 });
    const error = await failure(download.bytes());
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.message).not.toContain(canary);
    expect(JSON.stringify(error)).not.toContain(canary);
    expect(JSON.stringify(error.cause ?? {})).not.toContain(canary);
  });

  it("bytes() allocates exactly one declared-length buffer (peak = cap + one chunk)", async () => {
    const size = 2 * 1024 * 1024 + 7;
    const data = makeBytes(size);
    const digest = sha256(data);
    // Pre-built 64 KiB frames; allocation counting starts only around bytes().
    const frames: Uint8Array[] = [];
    for (let at = 0; at < size; at += 64 * 1024) frames.push(data.subarray(at, at + 64 * 1024));
    const fetch = vi.fn<FetchLike>(async (_url, init) => {
      const ranged = (init.headers as Record<string, string>).range !== undefined;
      let i = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(c) {
          if (i >= frames.length) {
            c.close();
            return;
          }
          c.enqueue(frames[i++]!);
        },
      });
      return new Response(stream, {
        status: ranged ? 206 : 200,
        headers: {
          etag: `"${digest}"`,
          "content-length": String(size),
          "accept-ranges": "bytes",
          ...(ranged ? { "content-range": `bytes 0-${size - 1}/${size}` } : {}),
        },
      });
    });
    const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
    const download = await client.files.downloadRange("op_y", { start: 0 });
    const bigAllocations: number[] = [];
    const RealUint8Array = globalThis.Uint8Array;
    vi.stubGlobal(
      "Uint8Array",
      new Proxy(RealUint8Array, {
        construct(target, args: unknown[]) {
          if (typeof args[0] === "number" && args[0] >= 1024 * 1024) {
            bigAllocations.push(args[0]);
          }
          return Reflect.construct(target, args) as Uint8Array;
        },
      }),
    );
    let out: Uint8Array;
    try {
      out = await download.bytes();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(out).toEqual(data);
    // One destination buffer of the declared length — never a second copy.
    expect(bigAllocations).toEqual([size]);
  });

  it("a key revoked mid-upload fails with authorization carrying the upload key", async () => {
    const server = fakeServer({});
    server.state.fault.revokeAfterPuts = 1;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", makeBytes(3 * CHUNK), {
        idempotencyKey: "revoked-mid",
      }),
    );
    expect(error.kind).toBe("authorization");
    expect(error.code).toBe("UNAUTHORIZED");
    expect(error.idempotencyKey).toBe("revoked-mid");
    expect(server.state.writes).toHaveLength(1);
  });

  it("a host-reported missing sandbox is a typed not_found, never null", async () => {
    const server = fakeServer({ statOutcome: "sandbox_gone" });
    const error = await failure(server.client.files.stat("sbx_1", "/app/x"));
    expect(error.kind).toBe("not_found");
    expect(error.operationErrorCode).toBe("sandbox_not_found");
    await expect(server.client.files.exists("sbx_1", "/app/x")).rejects.toThrow();
  });

  it("uploads a Node Readable directly, without web conversion", async () => {
    const { Readable } = await import("node:stream");
    const server = fakeServer({});
    const data = makeBytes(CHUNK + 3, 33);
    const node = Readable.from([data.subarray(0, 100), data.subarray(100)]);
    const result = await server.client.files.upload("sbx_1", "/app/node-direct", node, {
      idempotencyKey: "node-direct",
      totalBytes: data.byteLength,
    });
    expect(result.sha256).toBe(sha256(data));
    expect(server.state.writes.map((w) => w.bytes.byteLength)).toEqual([CHUNK, 3]);
  });
});

describe("files.upload and download — round-2 review", () => {
  /** Route this server's files/download requests at a planted capture. */
  function serveCapture(server: ReturnType<typeof fakeServer>, data: Uint8Array) {
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(String(url)).pathname.endsWith("/files/download")) {
        const response = await baseFetch(String(url), init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(String(url), init);
    });
  }

  it("uploads the ORIGINAL bytes when a source reuses and refills its buffer", async () => {
    const server = fakeServer({});
    const half = 512 * 1024;
    const first = makeBytes(half, 3);
    const second = makeBytes(half, 99);
    // One reused buffer: refilled between yields, as pooled stream readers do.
    const reused = new Uint8Array(half);
    reused.set(first);
    const source = (async function* () {
      yield reused;
      reused.set(second);
      yield reused;
    })();
    const expected = new Uint8Array(half * 2);
    expected.set(first, 0);
    expected.set(second, half);
    const result = await server.client.files.upload("sbx_1", "/app/reuse", source, {
      idempotencyKey: "reused-buffer",
      totalBytes: half * 2,
    });
    expect(result.sha256).toBe(sha256(expected));
    // The wire content too: the FIRST fill, then the second — no re-read of
    // the refilled buffer.
    expect(server.state.writes).toHaveLength(1);
    expect(server.state.writes[0]!.bytes).toEqual(expected);
  });

  it("recovers the original commit from an EXPIRED receipt after a lost response", async () => {
    const server = fakeServer({});
    server.state.fault.dropCommitResponses = true;
    server.state.fault.expireAfterCommit = true;
    const key = "upload-expired-commit";
    const data = makeBytes(100);
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    // The reservation was retired EXPIRED; only the operation survives.
    expect([...server.state.transfers.values()][0]!.state).toBe("EXPIRED");
    server.state.fault.dropCommitResponses = false;
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    // The ORIGINAL operation was recovered; nothing was re-sent or re-created.
    expect(recovered.operationId).toBe([...server.state.operations.values()][0]!.id);
    expect(server.state.writes).toHaveLength(1);
    expect([...server.state.operations.values()].filter((o) => o.kind === "PUT_FILE")).toHaveLength(
      1,
    );
  });

  it("an expired reservation whose commit NEVER landed advises a new key", async () => {
    const server = fakeServer({});
    const key = "upload-expired-uncommitted";
    const data = makeBytes(10);
    // Retire the transfer (with its full content staged) right after create.
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementationOnce(async (url, init) => {
      const response = await baseFetch(String(url), init);
      const transfer = [...server.state.transfers.values()][0]!;
      transfer.received = transfer.total;
      transfer.chunks.set(0, data);
      transfer.state = "EXPIRED";
      return response;
    });
    await failure(server.client.files.upload("sbx_1", "/app/e.bin", data, { idempotencyKey: key }));
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/e.bin", data, { idempotencyKey: key }),
    );
    expect(error.kind).toBe("gone");
    expect(error.message).toContain("NEW idempotency key");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
  });

  it("a post-commit operation read rejection carries all recovery identities", async () => {
    const server = fakeServer({});
    server.state.fault.forbidOperationReads = true;
    const key = "upload-op-403";
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", makeBytes(20), { idempotencyKey: key }),
    );
    expect(error.kind).toBe("authorization");
    expect(error.idempotencyKey).toBe(key);
    expect(error.operationId).toBe([...server.state.operations.values()][0]!.id);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
  });

  it("a post-commit wait timeout carries all recovery identities", async () => {
    const server = fakeServer({});
    server.state.fault.operationNeverTerminates = true;
    const key = "upload-op-timeout";
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", makeBytes(20), {
        idempotencyKey: key,
        waitTimeoutMs: 800,
        intervalMs: 1,
      }),
    );
    expect(error.kind).toBe("timeout");
    expect(error.idempotencyKey).toBe(key);
    expect(error.operationId).toBe([...server.state.operations.values()][0]!.id);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
  });

  it("stalled content HEADERS lose to the shared download deadline, with recovery identity", async () => {
    const server = fakeServer({});
    serveCapture(server, makeBytes(50));
    server.state.fault.hangContentHeaders = true;
    const started = Date.now();
    const error = await failure(
      server.client.files.download("sbx_1", "/app/d.bin", {
        idempotencyKey: "dl-stalled",
        waitTimeoutMs: 800,
        intervalMs: 1,
      }),
    );
    expect(error.kind).toBe("timeout");
    expect(Date.now() - started).toBeLessThan(5000);
    // The accepted capture's identity survives the header failure.
    expect(error.idempotencyKey).toBe("dl-stalled");
    expect(error.operationId).toBe([...server.state.captures.keys()][0]!);
  });

  it("a rejected capture operation READ carries the capture identity", async () => {
    const server = fakeServer({});
    serveCapture(server, makeBytes(50));
    server.state.fault.forbidOperationReads = true;
    const error = await failure(
      server.client.files.download("sbx_1", "/app/d.bin", { idempotencyKey: "dl-403" }),
    );
    expect(error.kind).toBe("authorization");
    expect(error.idempotencyKey).toBe("dl-403");
    expect(error.operationId).toBe([...server.state.captures.keys()][0]!);
  });

  it("a download budget beyond the per-request cap still fetches content", async () => {
    const server = fakeServer({});
    const data = makeBytes(120);
    serveCapture(server, data);
    // 30 minutes overall: valid for polling (60 min cap) but beyond the
    // transport's 15-minute single-request timeout. The content fetch must be
    // clamped, not rejected.
    const download = await server.client.files.download("sbx_1", "/app/d.bin", {
      idempotencyKey: "dl-long",
      waitTimeoutMs: 1_800_000,
      intervalMs: 1,
    });
    const bytes = await download.bytes();
    expect(bytes).toEqual(data);
  });

  it("a successful upload leaves no timers behind", async () => {
    vi.useFakeTimers();
    try {
      const server = fakeServer({});
      await server.client.files.upload("sbx_1", "/app/t.bin", makeBytes(10), {
        idempotencyKey: "timer-clean",
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a cleanly-closed short body fails as TRANSFER_IO", async () => {
    const server = fakeServer({});
    serveCapture(server, makeBytes(40));
    server.state.fault.shortBodyCloseAt = 30; // closes CLEANLY 10 bytes early
    const download = await server.client.files.download("sbx_1", "/app/d.bin", {});
    const error = await failure(
      (async () => {
        const reader = download.stream.getReader();
        for (;;) {
          if ((await reader.read()).done) return;
        }
      })(),
    );
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.message).toContain("ended at 30 of 40");
  });

  it("a body overrunning a forged Content-Length fails as TRANSFER_IO", async () => {
    const server = fakeServer({});
    serveCapture(server, makeBytes(40));
    server.state.fault.forgeContentLength = 35; // declares 35, serves 40
    const download = await server.client.files.download("sbx_1", "/app/d.bin", {});
    const error = await failure(
      (async () => {
        const reader = download.stream.getReader();
        for (;;) {
          if ((await reader.read()).done) return;
        }
      })(),
    );
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.message).toContain("overran");
  });

  it("the read memory cap admits exactly maxBytes and rejects maxBytes-1", async () => {
    const server = fakeServer({});
    const opId = "op_cap_edge";
    server.state.operations.set(opId, {
      id: opId,
      sandboxId: "sbx_1",
      kind: "GET_FILE",
      state: "SUCCEEDED",
      errorCode: null,
      pendingPolls: 0,
    });
    const exact = makeBytes(1000);
    plantCapture(server, opId, exact);
    const exactDownload = await server.client.files.downloadRange(opId, { start: 0 });
    const read = await exactDownload.bytes({ maxBytes: 1000 });
    expect(read.byteLength).toBe(1000);
    expect(read).toEqual(exact);
    const overDownload = await server.client.files.downloadRange(opId, { start: 0 });
    const error = await failure(overDownload.bytes({ maxBytes: 999 }));
    expect(error.kind).toBe("invalid_request");
  });

  it("a sandbox generation change mid-upload conflicts (production semantics: 409)", async () => {
    const server = fakeServer({});
    const data = makeBytes(CHUNK * 2);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      const response = await baseFetch(String(url), init);
      if (init?.method === "PUT") server.state.generation = 2; // after chunk 1
      return response;
    });
    // TransferStore.current() answers 409 CONFLICT for a generation change on
    // a live reservation (the pg tests pin this), not 410.
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, { idempotencyKey: "gen-change" }),
    );
    expect(error.kind).toBe("conflict");
    expect(error.code).toBe("CONFLICT");
    expect(error.idempotencyKey).toBe("gen-change");
    // No subsequent chunk or commit succeeds against the fenced reservation.
    const retry = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, { idempotencyKey: "gen-change" }),
    );
    expect(retry.kind).toBe("conflict");
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("OPEN");
    expect(transfer.operationId).toBeNull();
    expect(server.state.writes).toHaveLength(1);
  });
});

describe("files.upload and download — round-3 review", () => {
  it("a mid-upload source error carries the reservation key and recovers", async () => {
    const server = fakeServer({});
    const { Readable } = await import("node:stream");
    const data = makeBytes(CHUNK + 10);
    const canary = `secret-path-${KEY}`;
    // A Node stream failing after the first chunk: the raw error message
    // carries a credential canary that must never leak into the SDK error.
    const failing = Readable.from(
      (async function* () {
        yield data.subarray(0, CHUNK);
        throw new Error(`read failed for /home/u/${canary}`);
      })(),
    );
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", failing, {
        idempotencyKey: "src-fail",
        totalBytes: data.byteLength,
      }),
    );
    expect(first).toBeInstanceOf(WsspError);
    expect(first.kind).toBe("unknown");
    expect(first.code).toBe("TRANSFER_IO");
    expect(first.idempotencyKey).toBe("src-fail");
    expect(first.message).not.toContain(canary);
    expect(JSON.stringify(first)).not.toContain(canary);
    // The reservation held the first chunk: a same-key retry resumes and
    // completes, sending only the remainder.
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: "src-fail",
    });
    expect(recovered.sha256).toBe(sha256(data));
    expect(server.state.writes).toHaveLength(2);
    expect(server.state.writes[1]!.offset).toBe(CHUNK);
    expect(server.state.writes[1]!.bytes.byteLength).toBe(10);
  });

  it("a throwing source factory fails keyed, with a redacted cause", async () => {
    const server = fakeServer({});
    const canary = `factory-${KEY}`;
    const error = await failure(
      server.client.files.upload(
        "sbx_1",
        "/app/d.bin",
        () => {
          throw new Error(`cannot open ${canary}`);
        },
        { idempotencyKey: "factory-fail", totalBytes: 10 },
      ),
    );
    expect(error).toBeInstanceOf(WsspError);
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.idempotencyKey).toBe("factory-fail");
    expect(error.message).not.toContain(canary);
    expect(JSON.stringify(error.cause ?? {})).not.toContain(canary);
  });

  it("an SDK-generated key still reaches the caller on a source failure", async () => {
    const server = fakeServer({});
    const source = (async function* () {
      yield makeBytes(10);
      throw new Error("boom");
    })();
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", source, { totalBytes: 20 }),
    );
    expect(error).toBeInstanceOf(WsspError);
    // The generated reservation key is attached, so the OPEN transfer is
    // identifiable/recoverable even without a caller-provided key.
    expect(typeof error.idempotencyKey).toBe("string");
    expect(error.idempotencyKey!.length).toBeGreaterThan(0);
    // And that generated key actually recovers the reservation.
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", makeBytes(20), {
      idempotencyKey: error.idempotencyKey!,
    });
    expect(recovered.totalBytes).toBe(20);
  });

  it("an oversized single piece is never copied whole (chunk-bounded memory)", async () => {
    const server = fakeServer({});
    const size = 3 * 1024 * 1024; // 3 MiB, one yielded piece
    const piece = makeBytes(size);
    const source = (async function* () {
      yield piece;
    })();
    const bigAllocations: number[] = [];
    // The fake SERVER legitimately assembles the whole content at commit;
    // only SDK-side (pre-commit) allocations are evidence here.
    let committing = false;
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(String(url)).pathname.endsWith("/commit")) committing = true;
      return baseFetch(String(url), init);
    });
    const RealUint8Array = globalThis.Uint8Array;
    vi.stubGlobal(
      "Uint8Array",
      new Proxy(RealUint8Array, {
        construct(target, args: unknown[]) {
          if (!committing && typeof args[0] === "number" && args[0] >= 2 * 1024 * 1024) {
            bigAllocations.push(args[0]);
          }
          return Reflect.construct(target, args) as Uint8Array;
        },
      }),
    );
    try {
      const result = await server.client.files.upload("sbx_1", "/app/big.bin", source, {
        idempotencyKey: "big-piece",
        totalBytes: size,
      });
      expect(result.sha256).toBe(sha256(piece));
    } finally {
      vi.unstubAllGlobals();
    }
    // The pump's fixed chunk buffer is 1 MiB: nothing piece-sized is allocated.
    expect(bigAllocations).toEqual([]);
  });

  it("tiny pieces do not re-copy a growing prefix per yield", async () => {
    const server = fakeServer({});
    const pieces = 2048;
    const pieceLen = 512;
    const parts = Array.from({ length: pieces }, (_, i) => makeBytes(pieceLen, i % 251));
    const source = (async function* () {
      for (const part of parts) yield part;
    })();
    const allocations: number[] = [];
    const RealUint8Array = globalThis.Uint8Array;
    vi.stubGlobal(
      "Uint8Array",
      new Proxy(RealUint8Array, {
        construct(target, args: unknown[]) {
          if (typeof args[0] === "number" && args[0] > 0) allocations.push(args[0]);
          return Reflect.construct(target, args) as Uint8Array;
        },
      }),
    );
    try {
      const total = pieces * pieceLen;
      await server.client.files.upload("sbx_1", "/app/tiny.bin", source, {
        idempotencyKey: "tiny-pieces",
        totalBytes: total,
      });
    } finally {
      vi.unstubAllGlobals();
    }
    // The fixed chunk buffer plus a handful of small helpers — not one
    // allocation per yielded piece (the old concat accumulated 2048).
    expect(allocations.length).toBeLessThan(50);
  });

  it("a landed commit whose response is fenced 403 reports unknown, then recovers", async () => {
    const server = fakeServer({});
    server.state.fault.fenceCommitResponses = true;
    const key = "commit-fenced";
    const data = makeBytes(CHUNK + 5);
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
        intervalMs: 1,
      }),
    );
    // Ambiguous, never a definitive rejection: the commit may have landed.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("maybe_after_commit");
    expect(error.status).toBe(403);
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    // It DID land: a same-key retry replays the commit and returns the
    // original operation without re-transmitting a byte.
    server.state.fault.fenceCommitResponses = false;
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    const transfer = [...server.state.transfers.values()][0]!;
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.calls.filter((c) => c.init.method === "PUT")).toHaveLength(2);
  });
});

describe("files.upload and download — round-4 review", () => {
  it("recovers the original commit from a FAILED receipt (startup recovery kept the operation)", async () => {
    const server = fakeServer({});
    server.state.fault.dropCommitResponses = true;
    server.state.fault.failAfterCommit = true;
    const key = "upload-failed-commit";
    const data = makeBytes(100);
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    // Startup recovery retired the sealed spool FAILED; the operation stays.
    expect([...server.state.transfers.values()][0]!.state).toBe("FAILED");
    server.state.fault.dropCommitResponses = false;
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe([...server.state.operations.values()][0]!.id);
    expect(server.state.writes).toHaveLength(1);
    expect([...server.state.operations.values()].filter((o) => o.kind === "PUT_FILE")).toHaveLength(
      1,
    );
  });

  it("a FAILED reservation whose commit NEVER landed advises a new key", async () => {
    const server = fakeServer({});
    const key = "upload-failed-uncommitted";
    const data = makeBytes(10);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementationOnce(async (url, init) => {
      const response = await baseFetch(String(url), init);
      const transfer = [...server.state.transfers.values()][0]!;
      transfer.received = transfer.total;
      transfer.chunks.set(0, data);
      transfer.state = "FAILED";
      return response;
    });
    await failure(server.client.files.upload("sbx_1", "/app/e.bin", data, { idempotencyKey: key }));
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/e.bin", data, { idempotencyKey: key }),
    );
    expect(error.kind).toBe("gone");
    expect(error.message).toContain("NEW idempotency key");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
  });

  it("bytes() abort wins even when the body's cancel() never settles", async () => {
    const digest = sha256(makeBytes(10));
    const fetch = vi.fn<FetchLike>(async () => {
      const stream = new ReadableStream<Uint8Array>({
        // A valid but fully stalled body: reads AND cancellation never settle.
        pull() {
          return new Promise(() => {});
        },
        cancel() {
          return new Promise(() => {});
        },
      });
      return new Response(stream, {
        status: 206,
        headers: {
          etag: `"${digest}"`,
          "content-length": "10",
          "accept-ranges": "bytes",
          "content-range": "bytes 0-9/10",
        },
      });
    });
    const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
    const download = await client.files.downloadRange("op_stall", { start: 0 });
    const controller = new AbortController();
    const started = Date.now();
    const pending = failure(download.bytes({ signal: controller.signal }));
    controller.abort();
    const error = await pending;
    expect(error.kind).toBe("aborted");
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("a next() that exhausts the deadline and rejects never escapes unhandled", async () => {
    vi.useFakeTimers();
    try {
      const server = fakeServer({});
      const source: AsyncIterable<Uint8Array> = {
        [Symbol.asyncIterator]() {
          let calls = 0;
          return {
            next(): Promise<IteratorResult<Uint8Array>> {
              calls += 1;
              if (calls === 1) {
                return Promise.resolve({ done: false, value: makeBytes(10) });
              }
              // Synchronously blow past the deadline, THEN return a rejected
              // promise: the budget must have been computed before this call,
              // or this rejection never gets a handler.
              vi.setSystemTime(Date.now() + 5_000);
              return Promise.reject(new Error("disk vanished"));
            },
            return(): Promise<IteratorResult<Uint8Array>> {
              return Promise.resolve({ done: true, value: undefined });
            },
          };
        },
      };
      const error = await failure(
        server.client.files.upload("sbx_1", "/app/d.bin", source, {
          idempotencyKey: "clock-jump",
          totalBytes: 20,
          waitTimeoutMs: 1_000,
        }),
      );
      // The SOURCE failure surfaces (wrapped, keyed) — not a bare timeout
      // with an abandoned rejection behind it.
      expect(error.kind).toBe("unknown");
      expect(error.code).toBe("TRANSFER_IO");
      expect(error.idempotencyKey).toBe("clock-jump");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("files.upload and download — round-5 review", () => {
  it("a source-thrown WsspError is re-keyed to the reservation and redacted", async () => {
    const canary = `leaked-${KEY}`;
    const server = fakeServer({});
    // The source calls ANOTHER SDK operation, which fails with its own
    // identity and a credential-bearing diagnostic.
    const upstream = new WsspError({
      kind: "not_found",
      message: `sandboxes.get failed: GET https://internal/${canary} → 404`,
      idempotencyKey: "upstream-operation-key",
    });
    async function* source(): AsyncGenerator<Uint8Array> {
      yield makeBytes(10);
      throw upstream;
    }
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x.bin", source(), {
        idempotencyKey: "upload-reservation-key",
        totalBytes: 11,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("TRANSFER_IO");
    // The reservation key replaces the upstream operation's identity.
    expect(error.idempotencyKey).toBe("upload-reservation-key");
    // The upstream message/cause never surface unredacted.
    expect(error.message).not.toContain(canary);
    expect(error.cause ? JSON.stringify(error.cause) : "").not.toContain(canary);
    // The reservation stays OPEN and resumable under the same key.
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("OPEN");
    const recovered = await server.client.files.upload("sbx_1", "/app/x.bin", makeBytes(11), {
      idempotencyKey: "upload-reservation-key",
    });
    expect(recovered.operationId).toBe(transfer.operationId);
  });

  it("a source-thrown invalid_request does NOT abort the reservation", async () => {
    const server = fakeServer({});
    async function* source(): AsyncGenerator<Uint8Array> {
      yield makeBytes(10);
      throw new WsspError({
        kind: "invalid_request",
        message: "an unrelated validation error from another SDK call",
      });
    }
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x.bin", source(), { totalBytes: 11 }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("TRANSFER_IO");
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("OPEN");
    expect(transfer.operationId).toBeNull();
  });

  const sealedWithLostCommit = async (key: string, data: Uint8Array) => {
    const server = fakeServer({});
    server.state.fault.dropCommitResponses = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    server.state.fault.dropCommitResponses = false;
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("SEALED");
    expect(transfer.operationId).not.toBeNull();
    return { server, transfer };
  };

  it("aborting mid-recovery of a committed receipt reports unknown with both keys", async () => {
    const key = "r5-commit-abort";
    const data = makeBytes(1000);
    const { server, transfer } = await sealedWithLostCommit(key, data);
    const controller = new AbortController();
    // The rehash source yields once, aborts, then stalls forever.
    const stalling = observed(
      (async function* () {
        yield data.subarray(0, 10);
        controller.abort();
        await new Promise(() => {});
      })(),
    );
    const clock = onFakeClock(() =>
      server.client.files.upload("sbx_1", "/app/d.bin", stalling.iterable, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
        signal: controller.signal,
      }),
    );
    // The abort reached the upload and it is waiting out the stalled source's cleanup.
    await clock.reach(() => stalling.calls.return === 1, "source cleanup");
    expect(controller.signal.aborted).toBe(true);
    await clock.cross(SOURCE_CLOSE_BOUND_MS);
    const error = await clock.result();
    // NOT a definitive abort: the committed operation may still run.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    // A same-key retry replays the commit and recovers the original op.
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });

  it("a deadline hit during sealed recovery also reports unknown with both keys", async () => {
    const key = "r5-commit-timeout";
    const data = makeBytes(1000);
    const { server, transfer } = await sealedWithLostCommit(key, data);
    const stalling = observed(
      (async function* () {
        yield data.subarray(0, 10);
        await new Promise(() => {});
      })(),
    );
    const clock = onFakeClock(() =>
      server.client.files.upload("sbx_1", "/app/d.bin", stalling.iterable, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
        waitTimeoutMs: 800,
      }),
    );
    // Parked in the rehash read that never answers: only the deadline ends it.
    await clock.reach(() => stalling.calls.next === 2, "the stalled rehash read");
    await clock.cross(800);
    await clock.reach(() => stalling.calls.return === 1, "source cleanup");
    await clock.cross(SOURCE_CLOSE_BOUND_MS);
    const error = await clock.result();
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
  });
});

describe("files.upload and download — round-6 review", () => {
  const sealedWithLostCommit = async (key: string, data: Uint8Array) => {
    const server = fakeServer({});
    server.state.fault.dropCommitResponses = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    server.state.fault.dropCommitResponses = false;
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("SEALED");
    expect(transfer.operationId).not.toBeNull();
    return { server, transfer };
  };

  /** Yields the full content, then its cleanup NEVER settles. */
  const hangingCleanupSource = (
    data: Uint8Array,
    onReturn?: () => void,
  ): AsyncIterable<Uint8Array> => ({
    [Symbol.asyncIterator]() {
      let sent = false;
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (sent) return Promise.resolve({ done: true, value: undefined });
          sent = true;
          return Promise.resolve({ done: false, value: data });
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          onReturn?.();
          return new Promise(() => {});
        },
      };
    },
  });

  it("abort during source cleanup after a successful rehash reports unknown with both keys", async () => {
    const key = "r6-cleanup-abort";
    const data = makeBytes(1000);
    const { server, transfer } = await sealedWithLostCommit(key, data);
    const controller = new AbortController();
    const source = observed(hangingCleanupSource(data, () => controller.abort()));
    const clock = onFakeClock(() =>
      server.client.files.upload("sbx_1", "/app/d.bin", source.iterable, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
        signal: controller.signal,
      }),
    );
    // The whole rehash was read, then the abort came from inside the hanging cleanup.
    await clock.reach(() => source.calls.return === 1, "source cleanup");
    expect(source.calls.next).toBe(2);
    expect(controller.signal.aborted).toBe(true);
    await clock.cross(SOURCE_CLOSE_BOUND_MS);
    const error = await clock.result();
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });

  it("a deadline exhausted during source cleanup reports unknown with both keys", async () => {
    const key = "r6-cleanup-deadline";
    const data = makeBytes(1000);
    const { server, transfer } = await sealedWithLostCommit(key, data);
    const source = observed(hangingCleanupSource(data));
    const clock = onFakeClock(() =>
      server.client.files.upload("sbx_1", "/app/d.bin", source.iterable, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
        waitTimeoutMs: 800,
      }),
    );
    // The whole rehash was read inside the deadline; the hanging cleanup outlives it.
    await clock.reach(() => source.calls.return === 1, "source cleanup");
    expect(source.calls.next).toBe(2);
    await clock.cross(SOURCE_CLOSE_BOUND_MS);
    const error = await clock.result();
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
  });

  it("a download aborted via its own signal mid-body reports aborted, never TRANSFER_IO", async () => {
    const server = fakeServer({});
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(url).pathname.endsWith("/content")) {
        // Headers arrive; the body stalls forever (its cancel() resolves the
        // pending read with done:true, like a WHATWG adapter).
        return new Response(new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) }), {
          status: 200,
          headers: {
            etag: `"${"a".repeat(64)}"`,
            "content-length": "10",
            "accept-ranges": "bytes",
          },
        });
      }
      return baseFetch(url, init);
    });
    const download = await server.client.files.download("sbx_1", "/app/f", {
      signal: controller.signal,
    });
    const pending = failure(download.bytes());
    controller.abort();
    const error = await pending;
    expect(error.kind).toBe("aborted");
    expect(error.reason).toBe("aborted");
    // The transport-originated abort carries the capture's identity: the
    // generated reservation key and the accepted operation ID.
    expect(error.idempotencyKey).not.toBeNull();
    expect(error.operationId).not.toBeNull();
  });

  it("stat and exists report the generated key and accepted operation when polling is forbidden", async () => {
    const server = fakeServer({});
    server.state.fault.forbidOperationReads = true;
    const statError = await failure(server.client.files.stat("sbx_1", "/app/x"));
    expect(statError.kind).toBe("authorization");
    // The generated reservation key and the accepted STAT_PATH operation
    // survive the post-submission 403 — a retry can reuse both.
    expect(statError.idempotencyKey).not.toBeNull();
    const statOps = [...server.state.operations.values()].filter((o) => o.kind === "STAT_PATH");
    expect(statError.operationId).toBe(statOps[0]!.id);
    const existsError = await failure(server.client.files.exists("sbx_1", "/app/x"));
    expect(existsError.idempotencyKey).not.toBeNull();
    const allStatOps = [...server.state.operations.values()].filter((o) => o.kind === "STAT_PATH");
    expect(existsError.operationId).toBe(allStatOps[1]!.id);
  });

  it("a queued cancellation still lands and reports aborted", async () => {
    const server = fakeServer({ commitPolls: 1 });
    const data = makeBytes(10);
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    let abortArmed = false;
    server.fetch.mockImplementation(async (url, init) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/commit")) abortArmed = true;
      if (abortArmed && init.method === "GET" && /\/v1\/operations\/[^/]+$/.test(path)) {
        controller.abort();
      }
      return baseFetch(url, init);
    });
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "cancel-queued",
        signal: controller.signal,
      }),
    );
    // The PUT_FILE was still QUEUED: the cancellation request lands and the
    // confirmed outcome is a typed abort.
    expect(error.kind).toBe("aborted");
    expect(server.state.cancelRequests).toHaveLength(1);
    const op = [...server.state.operations.values()].find((o) => o.kind === "PUT_FILE")!;
    expect(op.state).toBe("CANCELLED");
  });

  it("an unconfirmed cancellation reports unknown with recovery identities", async () => {
    const server = fakeServer({});
    const data = makeBytes(10);
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    let abortArmed = false;
    server.fetch.mockImplementation(async (url, init) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/commit")) abortArmed = true;
      if (abortArmed && init.method === "GET" && /\/v1\/operations\/[^/]+$/.test(path)) {
        controller.abort();
      }
      // The cancellation request LANDS, but its confirmation poll is refused.
      if (path.endsWith("/cancel")) server.state.fault.forbidOperationReads = true;
      return baseFetch(url, init);
    });
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/x", data, {
        idempotencyKey: "cancel-unconfirmed",
        signal: controller.signal,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe("cancel-unconfirmed");
    expect(error.commitKey).toBe(derivedTransferKey("cancel-unconfirmed", "commit"));
    expect(error.operationId).not.toBeNull();
    expect(server.state.cancelRequests).toHaveLength(1);
  });
});

describe("files.upload and download — round-7 review", () => {
  it("a short source during committed recovery reports unknown with both keys and never aborts", async () => {
    const key = "r7-short-recovery";
    const data = makeBytes(1000);
    const server = fakeServer({});
    server.state.fault.dropCommitResponses = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    server.state.fault.dropCommitResponses = false;
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("SEALED");
    expect(transfer.operationId).not.toBeNull();
    // The retry's source is EXHAUSTED early: 10 bytes against the reserved
    // 1000. The original replacement may still run — no definitive
    // invalid_request, no reservation-abort cleanup.
    const short = (async function* () {
      yield makeBytes(10);
    })();
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", short, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    expect(transfer.state).toBe("SEALED");
    // A same-key retry with the ORIGINAL content still recovers the op.
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });

  it("a truncated readBytes body carries the generated capture key, and the same key replays the capture", async () => {
    const server = fakeServer({});
    const data = makeBytes(40);
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(String(url)).pathname.endsWith("/files/download")) {
        const response = await baseFetch(String(url), init);
        const body = (await response.json()) as { operationId: string };
        plantCapture(server, body.operationId, data);
        return json(202, body);
      }
      return baseFetch(String(url), init);
    });
    server.state.fault.shortBodyCloseAt = 30; // closes cleanly 10 bytes early
    const error = await failure(server.client.files.readBytes("sbx_1", "/app/f"));
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.operationId).not.toBeNull();
    // The generated capture key survives the body-stage failure.
    expect(error.idempotencyKey).not.toBeNull();
    const key = error.idempotencyKey as string;
    // Retrying under that key REPLAYS the accepted capture instead of
    // submitting another one.
    server.state.fault.shortBodyCloseAt = undefined;
    const bytes = await server.client.files.readBytes("sbx_1", "/app/f", {
      idempotencyKey: key,
    });
    expect(bytes).toEqual(data);
    const captures = [...server.state.operations.values()].filter((o) => o.kind === "GET_FILE");
    expect(captures).toHaveLength(1);
    expect(captures[0]!.id).toBe(error.operationId);
  });

  it("a bytes() cancellation carries the capture key too", async () => {
    const server = fakeServer({});
    const controller = new AbortController();
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(String(url)).pathname.endsWith("/content")) {
        return new Response(new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) }), {
          status: 200,
          headers: {
            etag: `"${"a".repeat(64)}"`,
            "content-length": "10",
            "accept-ranges": "bytes",
          },
        });
      }
      return baseFetch(String(url), init);
    });
    const download = await server.client.files.download("sbx_1", "/app/f");
    const pending = failure(download.bytes({ signal: controller.signal }));
    controller.abort();
    const abortError = await pending;
    expect(abortError.kind).toBe("aborted");
    expect(abortError.idempotencyKey).not.toBeNull();
    expect(abortError.operationId).not.toBeNull();
  });

  it("maxBytes above the 32 MiB client cap is rejected BEFORE any capture or reservation", async () => {
    const server = fakeServer({});
    const over = DEFAULT_FILE_MEMORY_BYTES + 1;
    const readError = await failure(
      server.client.files.readBytes("sbx_1", "/app/f", { maxBytes: over }),
    );
    expect(readError.kind).toBe("invalid_request");
    expect(readError.message).toContain("maxBytes");
    expect(server.state.operations.size).toBe(0);
    const writeError = await failure(
      server.client.files.writeBytes("sbx_1", "/app/f", new Uint8Array(8), { maxBytes: over }),
    );
    expect(writeError.kind).toBe("invalid_request");
    expect(server.state.transfers.size).toBe(0);
    // Streaming above the cap still works: download() itself is uncapped.
    const download = await server.client.files.download("sbx_1", "/app/f");
    expect(download.operationId).toBeTruthy();
    expect(download.size).toBe(0);
  });
});

describe("files.upload and download — round-8 review", () => {
  /** /content answers headers, then the body stalls AND its cancel never settles. */
  const stalledUncancellableBody = (server: ReturnType<typeof fakeServer>) => {
    const baseFetch = server.fetch.getMockImplementation()!;
    server.fetch.mockImplementation(async (url, init) => {
      if (new URL(String(url)).pathname.endsWith("/content")) {
        return new Response(
          new ReadableStream<Uint8Array>({
            pull: () => new Promise(() => {}),
            cancel: () => new Promise(() => {}),
          }),
          {
            status: 200,
            headers: {
              etag: `"${"a".repeat(64)}"`,
              "content-length": "10",
              "accept-ranges": "bytes",
            },
          },
        );
      }
      return baseFetch(String(url), init);
    });
  };

  it("download.stream.cancel() resolves even when the body cancel never settles", async () => {
    const server = fakeServer({});
    stalledUncancellableBody(server);
    const download = await server.client.files.download("sbx_1", "/app/f");
    const started = Date.now();
    await download.stream.cancel();
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("nodeStream().destroy() settles even when the body cancel never settles", async () => {
    const server = fakeServer({});
    stalledUncancellableBody(server);
    const download = await server.client.files.download("sbx_1", "/app/f");
    const node = download.nodeStream();
    node.resume(); // start consuming: a pull is in flight against the stalled body
    await new Promise<void>((resolve, reject) => {
      const watchdog = setTimeout(() => reject(new Error("destroy hung")), 5000);
      node.once("close", () => {
        clearTimeout(watchdog);
        resolve();
      });
      node.destroy();
    });
  });
});

describe("files.upload and download — round-9 review", () => {
  /** Commit held in hashing; the reservation replays OPEN at the full cursor. */
  const commitHeldAtFullCursor = async (key: string, data: Uint8Array) => {
    const server = fakeServer({});
    server.state.fault.holdCommit = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    const transfer = [...server.state.transfers.values()][0]!;
    // The original commit has NOT landed: the replay is OPEN, full cursor.
    expect(transfer.state).toBe("OPEN");
    expect(transfer.received).toBe(data.byteLength);
    return { server, transfer };
  };

  it("aborting an OPEN full-cursor replay keeps uncertainty until the original commit lands", async () => {
    const key = "r9-open-abort";
    const data = makeBytes(1000);
    const { server, transfer } = await commitHeldAtFullCursor(key, data);
    const controller = new AbortController();
    const stalling = observed(
      (async function* () {
        yield data.subarray(0, 10);
        controller.abort();
        await new Promise(() => {});
      })(),
    );
    const clock = onFakeClock(() =>
      server.client.files.upload("sbx_1", "/app/d.bin", stalling.iterable, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
        signal: controller.signal,
      }),
    );
    await clock.reach(() => stalling.calls.return === 1, "source cleanup");
    expect(controller.signal.aborted).toBe(true);
    await clock.cross(SOURCE_CLOSE_BOUND_MS);
    const error = await clock.result();
    // Not a definitive abort: the held commit can still replace the file.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    // The ORIGINAL commit lands after the retry already gave up.
    server.state.fault.holdCommit = false;
    server.releaseCommit();
    await vi.waitFor(() => expect(transfer.state).toBe("SEALED"));
    expect(transfer.operationId).not.toBeNull();
    // Recovery replays the commit and returns THAT operation.
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });

  it("a short recovery source against an OPEN full-cursor receipt skips abort cleanup and keeps both keys", {
    timeout: 30_000,
  }, async () => {
    const key = "r9-open-short";
    const data = makeBytes(1000);
    const { server, transfer } = await commitHeldAtFullCursor(key, data);
    const short = (async function* () {
      yield makeBytes(10);
    })();
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", short, {
        idempotencyKey: key,
        totalBytes: data.byteLength,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    // No reservation-abort cleanup ran against the live reservation.
    expect(transfer.state).toBe("OPEN");
    server.state.fault.holdCommit = false;
    server.releaseCommit();
    await vi.waitFor(() => expect(transfer.state).toBe("SEALED"));
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });
});

describe("files.upload and download — round-10 review", () => {
  it("a 409 commit replay while the original commit holds the permit keeps uncertainty with both keys", async () => {
    const key = "r10-permit";
    const data = makeBytes(1000);
    // Hold the original commit in hashing; the client times out.
    const server = fakeServer({});
    server.state.fault.holdCommit = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    const transfer = [...server.state.transfers.values()][0]!;
    expect(transfer.state).toBe("OPEN");
    expect(transfer.received).toBe(data.byteLength);
    // Retry with the COMPLETE source: the rehash passes and the commit replay
    // is rejected 409 — the original still holds the permit. The conflict must
    // NOT resolve the earlier uncertainty.
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, { idempotencyKey: key }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.status).toBe(409);
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    // The original commit lands; a same-key retry recovers THAT operation.
    server.state.fault.holdCommit = false;
    server.releaseCommit();
    await vi.waitFor(() => expect(transfer.state).toBe("SEALED"));
    expect(transfer.operationId).not.toBeNull();
    const recovered = await server.client.files.upload("sbx_1", "/app/d.bin", data, {
      idempotencyKey: key,
    });
    expect(recovered.operationId).toBe(transfer.operationId);
    expect(server.state.writes).toHaveLength(1);
  });

  it("E-18 a commit replay refused for capacity until its deadline stays unknown with both keys", async () => {
    const key = "e18-recovery";
    const data = makeBytes(1000);
    const server = fakeServer({});
    server.state.fault.holdCommit = true;
    const first = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 800,
      }),
    );
    expect(first.kind).toBe("unknown");
    // The original commit may still land; a full store answering the replay
    // until the deadline must not read as a definitive capacity refusal.
    server.state.fault.quotaCommits = true;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", data, {
        idempotencyKey: key,
        waitTimeoutMs: 300,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.idempotencyKey).toBe(key);
    expect(error.commitKey).toBe(derivedTransferKey(key, "commit"));
    server.state.fault.holdCommit = false;
    server.releaseCommit();
  });

  it("E-18 a fresh commit refused for capacity until its deadline is a typed capacity error", async () => {
    const server = fakeServer({});
    server.state.fault.quotaCommits = true;
    const error = await failure(
      server.client.files.upload("sbx_1", "/app/d.bin", makeBytes(10), {
        idempotencyKey: "e18-fresh",
        waitTimeoutMs: 300,
      }),
    );
    expect(error).toMatchObject({
      kind: "capacity",
      code: "TRANSFER_QUOTA",
      idempotencyKey: "e18-fresh",
    });
  });
});

describe("files.upload and download — round-12 review", () => {
  it("a resumed 206 with a different ETag conflicts instead of splicing a foreign tail", async () => {
    const { server, data, opId } = await withCapture(1000);
    // Correct range headers, but the response carries ANOTHER capture's ETag.
    server.state.fault.forgeEtag = `"${"f".repeat(64)}"`;
    const error = await failure(
      server.client.files.resumeDownload({ operationId: opId, etag: `"${sha256(data)}"` }, 100),
    );
    expect(error.kind).toBe("conflict");
    expect(error.operationId).toBe(opId);
  });
});
