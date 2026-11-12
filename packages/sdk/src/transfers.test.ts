import { createHash } from "node:crypto";
import {
  isRetryableRefusalCode,
  SDK_ERRORS,
  type SdkErrorCode,
  TRANSFER_CHUNK_BYTES,
  TRANSFER_MAX_BYTES,
} from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";
import { WsspError } from "./errors";
import { createTransfersApi, derivedTransferKey } from "./transfers";
import { createWsspTransport, type FetchLike } from "./transport";

const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test/prefix";
const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const CHUNK = TRANSFER_CHUNK_BYTES;
const NOW = "2026-01-01T00:00:00.000Z";
const TRANSFER_ID = "0f1c2f3a-1b2c-4d5e-8f90-123456789abc";

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": REQUEST_ID, ...headers },
  });
}

function envelope(code: SdkErrorCode, extra: Record<string, unknown> = {}): Response {
  const [status, message] = SDK_ERRORS[code];
  return json(status, {
    error: {
      ...(isRetryableRefusalCode(code) ? { retryable: true } : {}),
      ...(code === "sandbox.host_capacity" || code === "sandbox.pool_full"
        ? { reason: "ram" }
        : {}),
      code,
      message,
      requestId: REQUEST_ID,
      ...extra,
    },
  });
}

function receipt(over: Record<string, unknown> = {}) {
  return {
    id: TRANSFER_ID,
    sandboxId: "sbx_1",
    generation: 1,
    direction: "UPLOAD",
    state: "OPEN",
    totalBytes: CHUNK,
    receivedBytes: 0,
    chunkBytes: CHUNK,
    idleExpiresAt: NOW,
    expiresAt: NOW,
    ...over,
  };
}

type Call = { url: string; init: RequestInit };
type Step = Response | ((call: Call) => Response | Promise<Response>);

function harness(...steps: Step[]) {
  const calls: Call[] = [];
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    const call = { url, init };
    calls.push(call);
    const step = steps.shift();
    if (!step) throw new Error(`unexpected call: ${init.method} ${url}`);
    return typeof step === "function" ? step(call) : step;
  });
  const transport = createWsspTransport({
    baseUrl: BASE,
    apiKey: KEY,
    fetch,
    timeoutMs: 5_000,
  });
  const transfers = createTransfersApi(transport, {
    intervalMs: 1,
    maxIntervalMs: 2,
    waitTimeoutMs: 10_000,
  });
  return { transport, transfers, calls, leftovers: () => steps.length };
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

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

async function bodyBytes(call: Call): Promise<Uint8Array> {
  const body = call.init.body;
  if (body instanceof Uint8Array) return body;
  if (typeof body === "string") return new TextEncoder().encode(body);
  throw new Error("unexpected body type");
}

describe("derivedTransferKey", () => {
  it("is domain-separated, deterministic and within the key bound", () => {
    const a = derivedTransferKey("owner-key", "commit");
    const b = derivedTransferKey("owner-key", "cancel");
    expect(a).toMatch(/^sdk:commit:[a-f0-9]{64}$/);
    expect(b).toMatch(/^sdk:cancel:[a-f0-9]{64}$/);
    expect(a).not.toBe(b);
    expect(a.length).toBeLessThanOrEqual(128);
    expect(derivedTransferKey("owner-key", "commit")).toBe(a);
    // No prefix collision: keys sharing a long prefix derive differently.
    const long = "k".repeat(120);
    expect(derivedTransferKey(long, "commit")).not.toBe(derivedTransferKey(`${long}x`, "commit"));
  });
});

describe("createUpload", () => {
  it("reserves an upload and parses the 201 receipt", async () => {
    const { transfers, calls } = harness(
      json(201, receipt(), { location: `/v1/transfers/${TRANSFER_ID}` }),
    );
    const created = await transfers.createUpload(
      { sandboxId: "sbx_1", guestPath: "/app/data.bin", totalBytes: CHUNK },
      { idempotencyKey: "up-1" },
    );
    expect(created.id).toBe(TRANSFER_ID);
    expect(created.receivedBytes).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.url).toBe(`${BASE}/v1/transfers`);
    expect((calls[0]!.init.headers as Record<string, string>)["idempotency-key"]).toBe("up-1");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({
      sandboxId: "sbx_1",
      guestPath: "/app/data.bin",
      totalBytes: CHUNK,
    });
  });

  it("retries a lost response under the SAME key and resolves the replay", async () => {
    const { transfers, calls } = harness(
      () => {
        throw new TypeError("socket hangup");
      },
      json(201, receipt()),
    );
    const created = await transfers.createUpload(
      { sandboxId: "sbx_1", guestPath: "/f", totalBytes: 1 },
      { idempotencyKey: "up-retry" },
    );
    expect(created.id).toBe(TRANSFER_ID);
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect((call.init.headers as Record<string, string>)["idempotency-key"]).toBe("up-retry");
    }
  });

  it("rejects a total above the hard ceiling before any IO", async () => {
    const { transfers, calls } = harness();
    const error = await failure(
      transfers.createUpload(
        { sandboxId: "sbx_1", guestPath: "/f", totalBytes: TRANSFER_MAX_BYTES + 1 },
        { idempotencyKey: "up-big" },
      ),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });

  it("maps a refused reservation to invalid_request (413), never retried", async () => {
    const { transfers, calls } = harness(envelope("PAYLOAD_TOO_LARGE"));
    const error = await failure(
      transfers.createUpload(
        { sandboxId: "sbx_1", guestPath: "/f", totalBytes: 1 },
        { idempotencyKey: "up-cap" },
      ),
    );
    expect(error.kind).toBe("invalid_request");
    expect(error.code).toBe("PAYLOAD_TOO_LARGE");
    expect(calls).toHaveLength(1);
  });

  it("E-18 a catalog capacity refusal waits out Retry-After under the same key", async () => {
    vi.useFakeTimers();
    try {
      const quota = () =>
        new Response(
          JSON.stringify({
            error: {
              code: "TRANSFER_QUOTA",
              message: "Transfer capacity is full.",
              requestId: REQUEST_ID,
              retryAfterSeconds: 5,
            },
          }),
          { status: 429, headers: { "content-type": "application/json", "retry-after": "5" } },
        );
      const { transfers, calls } = harness(...Array.from({ length: 10 }, () => quota));
      const pending = failure(
        transfers.createUpload(
          { sandboxId: "sbx_1", guestPath: "/f", totalBytes: 1 },
          { idempotencyKey: "up-full", waitTimeoutMs: 12_000 },
        ),
      );
      await vi.advanceTimersByTimeAsync(13_000);
      const error = await pending;
      expect(error).toMatchObject({
        kind: "capacity",
        code: "TRANSFER_QUOTA",
        status: 429,
        retryAfterSeconds: 5,
        idempotencyKey: "up-full",
      });
      expect(calls).toHaveLength(3);
      expect(calls.map((call) => new Headers(call.init.headers).get("idempotency-key"))).toEqual([
        "up-full",
        "up-full",
        "up-full",
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("E-18 a capacity refusal after an unknown attempt stays unknown at the deadline", async () => {
    vi.useFakeTimers();
    try {
      const { transfers, calls } = harness(
        () => {
          throw new TypeError("socket hangup");
        },
        ...Array.from(
          { length: 10 },
          () => () => envelope("TRANSFER_QUOTA", { retryAfterSeconds: 1 }),
        ),
      );
      const pending = failure(
        transfers.createUpload(
          { sandboxId: "sbx_1", guestPath: "/f", totalBytes: 1 },
          { idempotencyKey: "up-uncertain", waitTimeoutMs: 2_500 },
        ),
      );
      await vi.advanceTimersByTimeAsync(3_000);
      const error = await pending;
      // The deadline ended between attempts on a capacity refusal, but the
      // lost first response may have reserved: the outcome stays unknown.
      expect(error.kind).toBe("unknown");
      expect(error.idempotencyKey).toBe("up-uncertain");
      expect(calls).toHaveLength(4);
      expect(
        calls.every(
          (call) => new Headers(call.init.headers).get("idempotency-key") === "up-uncertain",
        ),
      ).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("E-27 refuses a relative or `..` guest path before any IO", async () => {
    const { transfers, calls } = harness();
    for (const guestPath of [
      "/home/user/../user/ui/trav.txt",
      "/a/..",
      "trav.txt",
      // E-28: the guest's own file rules.
      "/home/user/./dot.txt",
      "/",
      "/a\ud800b",
      // G4R1-1: refused, never trimmed.
      "/data/report ",
      "\t/data/report",
      "\n/data/report",
    ]) {
      const error = await failure(
        transfers.createUpload(
          { sandboxId: "sbx_1", guestPath, totalBytes: 1 },
          { idempotencyKey: "up-path" },
        ),
      );
      expect(error.kind, guestPath).toBe("invalid_request");
    }
    expect(calls).toHaveLength(0);
  });
});

describe("getUpload / findUpload", () => {
  it("reads the durable receipt", async () => {
    const { transfers } = harness(json(200, receipt({ receivedBytes: CHUNK })));
    const status = await transfers.getUpload(TRANSFER_ID);
    expect(status.receivedBytes).toBe(CHUNK);
  });

  it("findUpload resolves null only on a confirmed 404", async () => {
    const { transfers } = harness(envelope("NOT_FOUND"));
    expect(await transfers.findUpload(TRANSFER_ID)).toBeNull();
    const { transfers: failing } = harness(envelope("TRANSFER_EXPIRED"));
    const error = await failure(failing.findUpload(TRANSFER_ID));
    expect(error.kind).toBe("gone");
  });
});

describe("putChunk", () => {
  const chunk = new Uint8Array(CHUNK).fill(7);

  it("sends Content-Range with the reserved total and exact bytes", async () => {
    const { transfers, calls } = harness(json(200, receipt({ receivedBytes: CHUNK })));
    const result = await transfers.putChunk(TRANSFER_ID, 0, chunk, CHUNK);
    expect(result.receivedBytes).toBe(CHUNK);
    const [call] = calls;
    expect(call!.init.method).toBe("PUT");
    expect(call!.url).toBe(`${BASE}/v1/transfers/${TRANSFER_ID}`);
    const headers = call!.init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/octet-stream");
    expect(headers["content-range"]).toBe(`bytes 0-${CHUNK - 1}/${CHUNK}`);
    expect(await bodyBytes(call!)).toEqual(chunk);
  });

  it.each([
    ["unaligned offset", 1, CHUNK, CHUNK * 2],
    ["offset at the total", CHUNK, 1, CHUNK],
    ["wrong chunk length", 0, CHUNK - 1, CHUNK * 2],
    ["final chunk longer than the remainder", 0, CHUNK, CHUNK - 1],
  ])("rejects %s before any IO", async (_label, offset, length, total) => {
    const { transfers, calls } = harness();
    const error = await failure(
      transfers.putChunk(TRANSFER_ID, offset, new Uint8Array(length), total),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });

  it("resends the IDENTICAL chunk after a lost response (digest replay)", async () => {
    let stored = false;
    const { transfers, calls } = harness(
      () => {
        // The write landed; the response was lost.
        stored = true;
        throw new TypeError("connection reset");
      },
      (call) => {
        // The replay carries the identical bytes.
        expect(stored).toBe(true);
        void call;
        return json(200, receipt({ receivedBytes: CHUNK }));
      },
    );
    const result = await transfers.putChunk(TRANSFER_ID, 0, chunk, CHUNK);
    expect(result.receivedBytes).toBe(CHUNK);
    expect(calls).toHaveLength(2);
    expect(await bodyBytes(calls[0]!)).toEqual(await bodyBytes(calls[1]!));
  });

  it("a digest conflict at an accepted offset is definitive (409, no retry)", async () => {
    const { transfers, calls } = harness(envelope("CONFLICT"));
    const error = await failure(transfers.putChunk(TRANSFER_ID, 0, chunk, CHUNK));
    expect(error.kind).toBe("conflict");
    expect(calls).toHaveLength(1);
  });

  it("an expired transfer reports gone (410)", async () => {
    const { transfers } = harness(envelope("TRANSFER_EXPIRED"));
    const error = await failure(transfers.putChunk(TRANSFER_ID, 0, chunk, CHUNK));
    expect(error.kind).toBe("gone");
    expect(error.code).toBe("TRANSFER_EXPIRED");
  });

  it("a revoked key fails with authorization, not a retry loop", async () => {
    const { transfers, calls } = harness(envelope("UNAUTHORIZED"));
    const error = await failure(transfers.putChunk(TRANSFER_ID, 0, chunk, CHUNK));
    expect(error.kind).toBe("authorization");
    expect(calls).toHaveLength(1);
  });
});

describe("commitUpload", () => {
  const digest = sha256(new Uint8Array(0));

  it("rejects a malformed hash before any IO", async () => {
    const { transfers, calls } = harness();
    const error = await failure(
      transfers.commitUpload(TRANSFER_ID, "ABCDEF", { idempotencyKey: "c-1" }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });

  it("commits with a separate key and parses the 202 receipt", async () => {
    const { transfers, calls } = harness(
      json(202, { operationId: "op_9", state: "QUEUED", location: "/v1/operations/op_9" }),
    );
    const receiptResult = await transfers.commitUpload(TRANSFER_ID, digest, {
      idempotencyKey: "commit-1",
    });
    expect(receiptResult.operationId).toBe("op_9");
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.url).toBe(`${BASE}/v1/transfers/${TRANSFER_ID}/commit`);
    expect((calls[0]!.init.headers as Record<string, string>)["idempotency-key"]).toBe("commit-1");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ sha256: digest });
  });

  it("retries a lost 202 under the same key and replays the original operation", async () => {
    const { transfers, calls } = harness(
      () => {
        throw new TypeError("lost");
      },
      json(202, { operationId: "op_9", state: "ACCEPTED", location: "/v1/operations/op_9" }),
    );
    const receiptResult = await transfers.commitUpload(TRANSFER_ID, digest, {
      idempotencyKey: "commit-1",
    });
    expect(receiptResult.operationId).toBe("op_9");
    expect(calls).toHaveLength(2);
  });

  it("a whole-content hash mismatch is a definitive invalid_request (400)", async () => {
    const { transfers, calls } = harness(envelope("BAD_REQUEST"));
    const error = await failure(
      transfers.commitUpload(TRANSFER_ID, digest, { idempotencyKey: "commit-1" }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(1);
  });

  it.each(["FORBIDDEN", "NOT_FOUND"] as const)(
    "a fenced commit response (%s) is ambiguous: unknown + maybe_after_commit, key retained",
    async (code) => {
      const { transfers, calls } = harness(envelope(code));
      const error = await failure(
        transfers.commitUpload(TRANSFER_ID, digest, { idempotencyKey: "commit-1" }),
      );
      // The server may have durably committed before fencing the response:
      // never report this as a definitive rejection.
      expect(error.kind).toBe("unknown");
      expect(error.reason).toBe("maybe_after_commit");
      expect(error.code).toBe(code);
      expect(error.idempotencyKey).toBe("commit-1");
      expect(calls).toHaveLength(1); // no retry: the fence is not transient
    },
  );
});

describe("abortUpload", () => {
  it("sends no idempotency key but a labeled JSON body (the server 415s unlabeled bodies)", async () => {
    const { transfers, calls } = harness(json(200, receipt({ state: "ABORTED" })));
    const aborted = await transfers.abortUpload(TRANSFER_ID);
    expect(aborted.state).toBe("ABORTED");
    expect(calls[0]!.init.method).toBe("DELETE");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["idempotency-key"]).toBeUndefined();
    // upload-routes.ts rejects a nonempty non-JSON body with 415: the
    // serialized `{}` must carry its media type despite the keyless route.
    expect(headers["content-type"]).toBe("application/json");
    expect(calls[0]!.init.body).toBe("{}");
  });

  it("repeats the abort after a lost response (replay-safe)", async () => {
    const { transfers, calls } = harness(
      () => {
        throw new TypeError("lost");
      },
      json(200, receipt({ state: "ABORTED" })),
    );
    const aborted = await transfers.abortUpload(TRANSFER_ID);
    expect(aborted.state).toBe("ABORTED");
    expect(calls).toHaveLength(2);
  });

  it("aborting a committed upload is a conflict", async () => {
    const { transfers } = harness(envelope("CONFLICT"));
    const error = await failure(transfers.abortUpload(TRANSFER_ID));
    expect(error.kind).toBe("conflict");
  });
});

describe("transport downloadContent", () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const digest = sha256(bytes);
  const headers = {
    etag: `"${digest}"`,
    "content-length": String(bytes.byteLength),
    "accept-ranges": "bytes",
  };

  function downloadResponse(
    status: number,
    body: Uint8Array | null,
    extra: Record<string, string> = {},
  ): Response {
    return new Response(body, { status, headers: { ...headers, ...extra } });
  }

  it("streams the whole capture with validated headers", async () => {
    const { transport } = harness(downloadResponse(200, bytes));
    const content = await transport.downloadContent({ params: { id: "op_1" } });
    expect(content.status).toBe(200);
    expect(content.sha256).toBe(digest);
    expect(content.size).toBe(bytes.byteLength);
    expect(content.start).toBe(0);
    expect(content.length).toBe(bytes.byteLength);
    const reader = content.body!.getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    expect(Buffer.concat(chunks.map((c) => Buffer.from(c)))).toEqual(Buffer.from(bytes));
  });

  it("sends Range and If-Range and validates the 206 Content-Range", async () => {
    const { transport, calls } = harness(
      downloadResponse(206, bytes.subarray(2), {
        "content-length": String(bytes.byteLength - 2),
        "content-range": `bytes 2-${bytes.byteLength - 1}/${bytes.byteLength}`,
      }),
    );
    const content = await transport.downloadContent({
      params: { id: "op_1" },
      range: { start: 2 },
      ifRange: `"${digest}"`,
    });
    expect(content.status).toBe(206);
    expect(content.start).toBe(2);
    expect(content.size).toBe(bytes.byteLength);
    const sentHeaders = calls[0]!.init.headers as Record<string, string>;
    expect(sentHeaders.range).toBe("bytes=2-");
    expect(sentHeaders["if-range"]).toBe(`"${digest}"`);
  });

  it("rejects a 206 whose Content-Range disagrees with Content-Length", async () => {
    const { transport } = harness(
      downloadResponse(206, bytes.subarray(2), {
        "content-length": String(bytes.byteLength - 2),
        "content-range": `bytes 0-${bytes.byteLength - 1}/${bytes.byteLength}`,
      }),
    );
    const error = await failure(
      transport.downloadContent({ params: { id: "op_1" }, range: { start: 2 } }),
    );
    expect(error.kind).toBe("protocol");
  });

  it("rejects a response without a strong ETag", async () => {
    const { transport } = harness(
      new Response(bytes, { status: 200, headers: { "content-length": "5" } }),
    );
    const error = await failure(transport.downloadContent({ params: { id: "op_1" } }));
    expect(error.kind).toBe("protocol");
  });

  it("supports a HEAD read without opening a stream", async () => {
    const { transport, calls } = harness(downloadResponse(200, null));
    const content = await transport.downloadContent({ params: { id: "op_1" }, head: true });
    expect(content.body).toBeNull();
    expect(content.size).toBe(bytes.byteLength);
    expect(calls[0]!.init.method).toBe("HEAD");
  });

  it("maps 416 to invalid_request, 409 not-ready to conflict and 410 to gone", async () => {
    for (const [code, kind] of [
      ["RANGE_NOT_SATISFIABLE", "invalid_request"],
      ["TRANSFER_NOT_READY", "conflict"],
      ["TRANSFER_EXPIRED", "gone"],
    ] as const) {
      const { transport } = harness(envelope(code));
      const error = await failure(transport.downloadContent({ params: { id: "op_1" } }));
      expect(error.kind).toBe(kind);
      expect(error.code).toBe(code);
    }
  });

  it("cancelling the stream releases the caller-signal wiring", async () => {
    const controller = new AbortController();
    const { transport } = harness(downloadResponse(200, bytes));
    const content = await transport.downloadContent({
      params: { id: "op_1" },
      signal: controller.signal,
    });
    await content.body!.cancel();
    controller.abort(); // must not throw or re-enter after release
    expect(controller.signal.aborted).toBe(true);
  });

  it("rejects a malformed range before any IO", async () => {
    const { transport, calls } = harness();
    const error = await failure(
      transport.downloadContent({ params: { id: "op_1" }, range: { start: 5, end: 2 } }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });
});
