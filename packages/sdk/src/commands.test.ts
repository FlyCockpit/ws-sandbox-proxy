import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import {
  isRetryableRefusalCode,
  OPERATION_WAIT_PROGRESS_HOLD_MS,
  type OperationStateDto,
  SDK_ERRORS,
  type SdkErrorCode,
} from "@wssp/sandbox-contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { createCommandsApi, type OutputEvent, type RunResult } from "./commands";
import { WsspError } from "./errors";
import { OUTPUT_READ_BURST } from "./polling";
import { createWsspTransport, type FetchLike, type WsspTransport } from "./transport";

// These bounds fixtures explicitly exercise the disabled admission state.
vi.mock("../../sandbox-contracts/src/command-timeout-policy", () => ({
  commandTimeoutZeroEnabled: false,
}));

const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test/prefix";
const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const NOW = "2026-01-01T00:00:00.000Z";

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

/** Abort the caller, then reject the in-flight request as the abort would. */
function aborting(controller: AbortController) {
  return () => {
    controller.abort();
    return new Promise<Response>((_, reject) => {
      setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
    });
  };
}

const b64 = (text: string | number[]): string =>
  Buffer.from(typeof text === "string" ? text : new Uint8Array(text)).toString("base64");

function chunk(stream: "stdout" | "stderr", offset: number, text: string | number[]) {
  return { stream, offset, data: b64(text) };
}

function page(over: Record<string, unknown> = {}) {
  return {
    operationId: "op_1",
    state: "RUNNING",
    exitCode: null,
    attempt: 0,
    reset: false,
    offset: 0,
    chunks: [],
    gaps: [],
    nextCursor: "0_0",
    hasMore: false,
    receivedBytes: 0,
    totalBytes: null,
    retainedBytes: 0,
    truncated: false,
    complete: false,
    expiresAt: null,
    ...over,
  };
}

function completePage(over: Record<string, unknown> = {}) {
  return page({ state: "SUCCEEDED", exitCode: 0, complete: true, totalBytes: 0, ...over });
}

function operation(state: OperationStateDto, over: Record<string, unknown> = {}) {
  return {
    id: "op_1",
    sandboxId: "sbx_1",
    kind: "RUN_COMMAND",
    leaseIntent: null,
    failure: null,
    state,
    outcome:
      state === "SUCCEEDED"
        ? "succeeded"
        : state === "FAILED"
          ? "failed"
          : state === "CANCELLED"
            ? "cancelled"
            : state === "UNKNOWN_OUTCOME"
              ? "unknown"
              : "pending",
    generation: 1,
    errorCode: null,
    createdAt: NOW,
    updatedAt: NOW,
    dispatchedAt: NOW,
    completedAt: null,
    ...over,
  };
}

function commandResult() {
  return {
    operationId: "op_1",
    sandboxId: "sbx_1",
    generation: 1,
    kind: "RUN_COMMAND",
    outcome: "pending",
    observedAt: NOW,
    expiresAt: null,
    result: {
      type: "command",
      process: { sandboxId: "sbx_1", generation: 1, processId: "proc_1", attempt: 1, pid: 42 },
      startedAt: NOW,
      exitCode: null,
    },
  };
}

function cancelReceipt(state: OperationStateDto, over: Record<string, unknown> = {}) {
  return {
    id: "rcpt_1",
    kind: "operations.cancel",
    state,
    outcome:
      state === "SUCCEEDED"
        ? "succeeded"
        : state === "FAILED"
          ? "failed"
          : state === "CANCELLED"
            ? "cancelled"
            : state === "UNKNOWN_OUTCOME"
              ? "unknown"
              : "pending",
    sandboxId: "sbx_1",
    generation: 1,
    errorCode: null,
    targetOperationId: "op_1",
    resourceId: null,
    observation: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

const receipt = (operationId = "op_1", state: OperationStateDto = "QUEUED") => ({
  operationId,
  state,
  location: `/v1/operations/${operationId}`,
});

type Call = { url: string; init: RequestInit; at: number };
type Step = Response | ((call: Call) => Response | Promise<Response>);

function harness(...steps: Step[]) {
  const calls: Call[] = [];
  const leftovers = () => steps.length;
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    const call: Call = { url, init, at: Date.now() };
    calls.push(call);
    const step = steps.shift();
    if (!step) throw new Error(`unexpected call: ${init.method} ${url}`);
    return typeof step === "function" ? step(call) : step;
  });
  const client = createWsspClient({
    baseUrl: BASE,
    apiKey: KEY,
    fetch,
    polling: { intervalMs: 100, maxIntervalMs: 400, waitTimeoutMs: 60_000 },
  });
  return { client, calls, leftovers };
}

type Settled<T> = { value?: T; error?: unknown };

async function drive<T>(promise: Promise<T>, maxMs = 120_000): Promise<Settled<T>> {
  let done = false;
  let value: T | undefined;
  let error: unknown;
  void promise.then(
    (v) => {
      done = true;
      value = v;
    },
    (e: unknown) => {
      done = true;
      error = e;
    },
  );
  for (let elapsed = 0; !done && elapsed < maxMs; elapsed += 25) {
    await vi.advanceTimersByTimeAsync(25);
  }
  if (!done) throw new Error("the promise never settled");
  return { value, error };
}

async function ok<T>(promise: Promise<T>): Promise<T> {
  const settled = await drive(promise);
  if (settled.error !== undefined) throw settled.error;
  return settled.value as T;
}

async function fails(promise: Promise<unknown>): Promise<WsspError> {
  const settled = await drive(promise);
  if (settled.error === undefined) throw new Error("expected a rejection");
  expect(settled.error).toBeInstanceOf(WsspError);
  return settled.error as WsspError;
}

/** A response that settles only when the request's signal aborts. */
function hangs(): Step {
  return (call) =>
    new Promise<Response>((_, reject) => {
      call.init.signal?.addEventListener("abort", () =>
        reject(new DOMException("This operation was aborted", "AbortError")),
      );
    });
}

function bodyOf(call: Call): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("separate guest and wait budgets", () => {
  for (const helper of ["script", "argv"] as const) {
    const invoke = (
      client: ReturnType<typeof createWsspClient>,
      options: import("./commands").CommandOptions,
    ) =>
      helper === "script"
        ? client.commands.script("sbx_1", "sleep 1", options)
        : client.commands.argv("sbx_1", ["sleep", "1"], options);

    it(`${helper} maps the guest budget to the command wire field only`, async () => {
      const { client, calls } = harness(
        json(202, receipt()),
        json(200, completePage()),
        json(200, operation("SUCCEEDED")),
      );
      await ok(invoke(client, { timeoutMs: 123_456, waitTimeoutMs: 240_000 }));
      expect(bodyOf(calls[0] as Call)).toEqual({
        [helper]: helper === "script" ? "sleep 1" : ["sleep", "1"],
        timeoutMs: 123_456,
      });
    });

    it(`${helper} keeps waitTimeoutMs local and stops at the observer deadline`, async () => {
      const { client, calls } = harness(json(202, receipt()), hangs());
      const startedAt = Date.now();
      const error = await fails(invoke(client, { waitTimeoutMs: 1000 }));
      expect(error.kind).toBe("timeout");
      expect(Date.now() - startedAt).toBe(1000);
      expect(bodyOf(calls[0] as Call)).not.toHaveProperty("waitTimeoutMs");
      expect(calls).toHaveLength(2);
    });

    it(`${helper} uses the same guest budget bounds as run and start`, async () => {
      for (const timeoutMs of [0, -1, 1.5, 1_800_001, Number.NaN]) {
        const { client, calls } = harness();
        const error = await fails(invoke(client, { timeoutMs }));
        expect(error.kind).toBe("invalid_request");
        expect(calls).toHaveLength(0);
      }
    });
  }

  it("applies waitTimeoutMs to process.wait and rejects the removed wait alias", async () => {
    const { client, calls } = harness(json(202, receipt()), json(200, commandResult()), hangs());
    const process = await ok(
      client.commands.start("sbx_1", { script: "true" }, { timeoutMs: 10_000 }),
    );
    const startedAt = Date.now();
    const error = await fails(process.wait({ waitTimeoutMs: 1000 }));
    expect(error.kind).toBe("timeout");
    expect(Date.now() - startedAt).toBe(1000);
    expect(calls).toHaveLength(3);
    // @ts-expect-error the wait-only timeout alias was removed
    expect(await fails(process.wait({ timeoutMs: 1000 }))).toMatchObject({
      kind: "invalid_request",
    });
    expect(calls).toHaveLength(3);
  });
});

describe("run output", () => {
  it("decodes UTF-8 per stream across chunk and page splits, interleaved, without repeating ranges", async () => {
    const events: OutputEvent[] = [];
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      // "hé" split across pages: [h, 0xC3] then [0xA9], stderr interleaved.
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, [0x68, 0xc3]), chunk("stderr", 2, "E1")],
          nextCursor: "0_4",
          hasMore: true,
          receivedBytes: 4,
        }),
      ),
      json(
        200,
        completePage({
          offset: 4,
          chunks: [chunk("stdout", 4, [0xa9]), chunk("stderr", 5, "E2")],
          nextCursor: "0_7",
          receivedBytes: 7,
          totalBytes: 7,
          retainedBytes: 7,
        }),
      ),
      // The SUCCEEDED complete page ends run(): no status read.
    );
    const result = await ok(
      client.commands.script("sbx_1", "printf hi", {
        idempotencyKey: "run-1",
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("hé");
    expect(result.stderr).toBe("E1E2");
    expect(result.truncated).toBe(false);
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "h" },
      { kind: "data", stream: "stderr", offset: 2, text: "E1" },
      { kind: "data", stream: "stdout", offset: 4, text: "é" },
      { kind: "data", stream: "stderr", offset: 5, text: "E2" },
    ]);
    const offsets = events
      .filter((e) => e.kind === "data")
      .map((e) => (e.kind === "data" ? e.offset : -1));
    expect(new Set(offsets).size).toBe(offsets.length);
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/sandboxes/sbx_1/commands`,
      `GET ${BASE}/v1/operations/op_1/output?waitMs=20000`,
      `GET ${BASE}/v1/operations/op_1/output?cursor=0_4&waitMs=20000`,
    ]);
    expect(leftovers()).toBe(0);
  });

  it("reports gaps as events and marks the result truncated", async () => {
    const events: OutputEvent[] = [];
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "ab")],
          gaps: [{ start: 2, end: 9 }],
          nextCursor: "0_9",
          receivedBytes: 9,
          totalBytes: 9,
          retainedBytes: 2,
          truncated: true,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.argv("sbx_1", ["true"], {
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    expect(result.stdout).toBe("ab");
    expect(result.truncated).toBe(true);
    expect(result.retainedBytes).toBe(2);
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "ab" },
      { kind: "gap", start: 2, end: 9 },
    ]);
  });

  it("restarts decoding on a reset page (a newer attempt replaces older bytes)", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, [0x68, 0xc3])], // partial "hé"
          nextCursor: "0_2",
          hasMore: true,
          receivedBytes: 2,
        }),
      ),
      json(
        200,
        completePage({
          attempt: 1,
          reset: true,
          chunks: [chunk("stdout", 0, "xy")],
          nextCursor: "1_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(client.commands.script("sbx_1", "true"));
    expect(result.stdout).toBe("xy");
    expect(result.truncated).toBe(false);
  });

  it("returns a nonzero RunResult with explicit check:false", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          state: "SUCCEEDED",
          exitCode: 3,
          chunks: [chunk("stderr", 0, "boom")],
          nextCursor: "0_4",
          receivedBytes: 4,
          totalBytes: 4,
          retainedBytes: 4,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(client.commands.argv("sbx_1", ["false-ish"], { check: false }));
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toBe("boom");
  });

  it("surfaces a guest-side command timeout as a typed timeout error", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, completePage({ state: "FAILED" })),
      json(200, operation("FAILED", { errorCode: "timeout", completedAt: NOW })),
    );
    const error = await fails(client.commands.script("sbx_1", "sleep 9999"));
    expect(error.kind).toBe("timeout");
    expect(error.operationErrorCode).toBe("timeout");
    expect(error.reason).toBeNull();
    expect(error.operationId).toBe("op_1");
  });

  it("rejects a page whose ranges do not tile [offset, nextCursor)", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "ab"), chunk("stdout", 1, "cd")], // overlap
          nextCursor: "0_3",
          hasMore: false,
        }),
      ),
    );
    const error = await fails(client.commands.script("sbx_1", "true"));
    expect(error.kind).toBe("protocol");
    expect(error.message).toContain("tile");
  });

  it("rejects a page that claims more output without progress", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          hasMore: true,
          receivedBytes: 1,
        }),
      ),
      json(200, page({ offset: 1, nextCursor: "0_1", hasMore: true, receivedBytes: 1 })),
    );
    const error = await fails(client.commands.script("sbx_1", "true"));
    expect(error.kind).toBe("protocol");
    expect(error.message).toContain("no progress");
  });

  it("fails the follow when the onOutput callback throws", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
    );
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onOutput: () => {
          throw new Error("renderer exploded");
        },
      }),
    );
    // The command may still be running: an unknown follow outcome, never a stop.
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.message).toContain("onOutput");
    expect(error.cause).toBeUndefined();
  });

  it("redacts credential-bearing callback errors (cause chain included)", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
    );
    const thrown = new Error(`renderer failed with ${KEY}`, {
      cause: new Error(`nested authorization: Bearer ${KEY}`),
    });
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onOutput: () => {
          throw thrown;
        },
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain(KEY);
  });

  it("redaction survives a Proxy-backed callback error whose accessors throw", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
    );
    // Every property read (message, name, cause, code, instanceof chain) throws.
    const hostile = new Proxy(new Error(`raw ${KEY}`), {
      get() {
        throw new Error(`accessor leaked ${KEY}`);
      },
    });
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onOutput: () => {
          throw hostile;
        },
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1"); // operation context is not lost
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain(KEY);
  });

  it("redaction keeps the outer message when a nested cause accessor throws", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
    );
    const thrown = new Error("plain failure");
    Object.defineProperty(thrown, "cause", {
      get() {
        throw new Error(`nested accessor ${KEY}`);
      },
    });
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onOutput: () => {
          throw thrown;
        },
      }),
    );
    expect(error.cause).toBeUndefined();
  });

  it("redaction never invokes methods on an object-valued message", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
    );
    // An object-valued message whose string-like methods would CAPTURE the
    // arguments they receive (the closure-held API key passed to split()).
    const invoked: string[] = [];
    const hostileMessage = {
      slice: (..._args: unknown[]) => {
        invoked.push("slice");
        return "sliced";
      },
      split: (...args: unknown[]) => {
        invoked.push(`split:${String(args[0])}`);
        return [];
      },
      toString: () => "hostile message",
    };
    const thrown = new Error("placeholder");
    Object.defineProperty(thrown, "message", { value: hostileMessage });
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onOutput: () => {
          throw thrown;
        },
      }),
    );
    expect(error.kind).toBe("unknown");
    // No method of the hostile object ran; the placeholder carries nothing.
    expect(invoked).toEqual([]);
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain(KEY);
  });

  it("flushes a trailing incomplete UTF-8 sequence at the completion watermark", async () => {
    const events: OutputEvent[] = [];
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, [0x68, 0xc3])], // "h" + a lone lead byte
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "printf h", {
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    // The partial sequence is delivered as U+FFFD, not silently lost.
    expect(result.stdout).toBe("h\ufffd");
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "h" },
      { kind: "data", stream: "stdout", offset: 2, text: "\ufffd" },
    ]);
  });

  it("bounds run-result accumulation and reports discarded output", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "0123456789"), chunk("stderr", 10, "abcdef")],
          nextCursor: "0_16",
          receivedBytes: 16,
          totalBytes: 16,
          retainedBytes: 16,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(client.commands.script("sbx_1", "noisy", { maxOutputChars: 4 }));
    expect(result.stdout).toBe("6789");
    expect(result.stderr).toBe("cdef");
    expect(result.discarded).toEqual({ stdout: 6, stderr: 2 });
    expect(result.truncated).toBe(true);
  });

  it("never repeats a range when abort interrupts a blocked output callback", async () => {
    const events: OutputEvent[] = [];
    let releaseCallback!: () => void;
    let callbackCalls = 0;
    const controller = new AbortController();
    const firstPage = page({
      chunks: [chunk("stdout", 0, "x")],
      nextCursor: "0_1",
      hasMore: true,
      receivedBytes: 1,
    });
    const { client } = harness(
      json(202, receipt()),
      json(200, firstPage),
      json(202, receipt("rcpt_1", "SUCCEEDED")), // completion raced the abort
      json(200, firstPage), // the interrupted page is re-read from its cursor
      json(200, completePage({ offset: 1, nextCursor: "0_1", receivedBytes: 1, totalBytes: 1 })),
      json(200, operation("SUCCEEDED")),
    );
    const promise = client.commands.script("sbx_1", "true", {
      idempotencyKey: "race",
      onAbort: "cancel",
      signal: controller.signal,
      onOutput: (event) => {
        events.push(event);
        callbackCalls += 1;
        return new Promise<void>((resolve) => {
          releaseCallback = resolve;
        });
      },
    });
    for (let i = 0; i < 100 && callbackCalls === 0; i++) await vi.advanceTimersByTimeAsync(10);
    expect(callbackCalls).toBe(1);
    controller.abort(); // abort while the callback is still blocked
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    releaseCallback(); // the interrupted pass commits its range, then stops
    const result = await ok(promise);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("x");
    // The range was delivered exactly once, across the abort and the re-read.
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "x" }]);
  });

  it("never repeats a range when abort interrupts a callback on a reset page", async () => {
    const events: OutputEvent[] = [];
    let releaseCallback!: () => void;
    let callbackCalls = 0;
    const controller = new AbortController();
    const resetPage = page({
      attempt: 1,
      reset: true, // a newer dispatch attempt replaced the older bytes
      chunks: [chunk("stdout", 0, "x")],
      nextCursor: "1_1",
      hasMore: true,
      receivedBytes: 1,
    });
    const { client } = harness(
      json(202, receipt()),
      json(200, resetPage),
      json(202, receipt("rcpt_1", "SUCCEEDED")), // completion raced the abort
      json(200, resetPage), // the interrupted reset page is re-read as-is
      json(
        200,
        completePage({ attempt: 1, offset: 1, nextCursor: "1_1", receivedBytes: 1, totalBytes: 1 }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const promise = client.commands.script("sbx_1", "true", {
      idempotencyKey: "race-reset",
      onAbort: "cancel",
      signal: controller.signal,
      onOutput: (event) => {
        events.push(event);
        callbackCalls += 1;
        return new Promise<void>((resolve) => {
          releaseCallback = resolve;
        });
      },
    });
    for (let i = 0; i < 100 && callbackCalls === 0; i++) await vi.advanceTimersByTimeAsync(10);
    expect(callbackCalls).toBe(1);
    controller.abort();
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    releaseCallback();
    const result = await ok(promise);
    expect(result.stdout).toBe("x");
    // The reset page was applied once per ATTEMPT: the replay did not clear
    // committed progress, so the range was delivered exactly once.
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "x" }]);
  });

  it("rejects unknown — without replaying — when a blocked callback fails after the abort", async () => {
    const events: OutputEvent[] = [];
    let failCallback!: (error: Error) => void;
    let callbackCalls = 0;
    const controller = new AbortController();
    const firstPage = page({
      chunks: [chunk("stdout", 0, "x")],
      nextCursor: "0_1",
      hasMore: true,
      receivedBytes: 1,
    });
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, firstPage),
      json(202, receipt("rcpt_1", "SUCCEEDED")), // completion raced the abort
      // Steps 4-5 exist only for the REGRESSION path (no commit/sticky): the
      // settlement would re-read the page — now carrying a second range — and
      // resolve with duplicated output instead of rejecting.
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "x"), chunk("stdout", 1, "y")],
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const promise = client.commands.script("sbx_1", "true", {
      idempotencyKey: "race-fail",
      onAbort: "cancel",
      signal: controller.signal,
      onOutput: (event) => {
        events.push(event);
        callbackCalls += 1;
        // Only the first (interrupted) call blocks; a replay would resolve.
        if (callbackCalls === 1) {
          return new Promise<void>((_resolve, reject) => {
            failCallback = reject;
          });
        }
      },
    });
    for (let i = 0; i < 100 && callbackCalls === 0; i++) await vi.advanceTimersByTimeAsync(10);
    controller.abort();
    for (let i = 0; i < 200 && calls.length < 3; i++) await vi.advanceTimersByTimeAsync(10);
    expect(calls).toHaveLength(3); // the cancellation was submitted
    failCallback(new Error("renderer exploded")); // the abort won the race first
    const error = await fails(promise);
    // The callback failure is sticky and reconciled during settlement: the
    // run rejects unknown instead of replaying the range and resolving over
    // output the callback never saw.
    expect(error.kind).toBe("unknown");
    expect(error.message).toContain("onOutput");
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "x" }]);
  });

  it("fences the page task when the run deadline expires inside a callback", async () => {
    const events: OutputEvent[] = [];
    let releaseCallback!: () => void;
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "x"), chunk("stdout", 1, "y")],
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
    );
    const promise = client.commands.script("sbx_1", "true", {
      // A one-second wait deadline expiring while the first callback blocks.
      timeoutMs: 1_000,
      onOutput: (event) => {
        events.push(event);
        if (events.length === 1) {
          return new Promise<void>((resolve) => {
            releaseCallback = resolve;
          });
        }
      },
    });
    const error = await fails(promise);
    expect(error.kind).toBe("timeout");
    // An SDK wait deadline, not a guest-side timeout: no operation error code.
    expect(error.operationErrorCode).toBeNull();
    releaseCallback(); // the abandoned page task commits its range, then stops
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    // The second range was never delivered after run() rejected.
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "x" }]);
  });

  it("delivers only the uncommitted suffix of a server-merged replay page", async () => {
    const events: OutputEvent[] = [];
    const controller = new AbortController();
    const { client, leftovers } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          hasMore: true,
          receivedBytes: 1,
        }),
      ),
      () => {
        controller.abort(); // abort during the continuation fetch
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")), // completion raced the abort
      // Settlement re-reads from cursor 0_1; the server merged "y" into the
      // segment it already returned, so the page reaches back over [0,1).
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "xy")],
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "true", {
        onAbort: "cancel",
        signal: controller.signal,
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    expect(result.stdout).toBe("xy");
    // The committed prefix [0,1) was trimmed; only [1,2) was delivered.
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "x" },
      { kind: "data", stream: "stdout", offset: 1, text: "y" },
    ]);
    expect(leftovers()).toBe(0);
  });

  it("never re-delivers committed ranges when a replay starts earlier after multiple pages", async () => {
    const events: OutputEvent[] = [];
    const controller = new AbortController();
    const { client, leftovers } = harness(
      json(202, receipt()),
      // Two pages at DIFFERENT starting offsets: [0,1) then [1,2).
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "a")],
          nextCursor: "0_1",
          hasMore: true,
          receivedBytes: 1,
        }),
      ),
      json(
        200,
        page({
          offset: 1,
          chunks: [chunk("stdout", 1, "b")],
          nextCursor: "0_2",
          hasMore: true,
          receivedBytes: 2,
        }),
      ),
      () => {
        controller.abort();
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")),
      // Merged replay starting at 0 covers the committed [0,2) plus new "c".
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "abc")],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "true", {
        onAbort: "cancel",
        signal: controller.signal,
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    // The delivery offset is monotonic within the attempt: the replay's
    // earlier start trimmed to its uncommitted suffix, never reset it.
    expect(result.stdout).toBe("abc");
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "a" },
      { kind: "data", stream: "stdout", offset: 1, text: "b" },
      { kind: "data", stream: "stdout", offset: 2, text: "c" },
    ]);
    expect(leftovers()).toBe(0);
  });

  it("decodes a multibyte code point straddling the merged-replay trim boundary", async () => {
    const events: OutputEvent[] = [];
    const controller = new AbortController();
    const { client, leftovers } = harness(
      json(202, receipt()),
      // "h" + the held lead byte of "é" (0xC3): decoder state spans pages.
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, [0x68, 0xc3])],
          nextCursor: "0_2",
          hasMore: true,
          receivedBytes: 2,
        }),
      ),
      () => {
        controller.abort();
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")),
      // Merged segment [0,3): the "é" continuation byte straddles the trim.
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, [0x68, 0xc3, 0xa9])],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "true", {
        onAbort: "cancel",
        signal: controller.signal,
        onOutput: (event) => {
          events.push(event);
        },
      }),
    );
    // The trim dropped exactly the consumed prefix: the held lead byte joins
    // the replayed continuation byte into "é" — no U+FFFD, no duplication.
    expect(result.stdout).toBe("hé");
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "h" },
      { kind: "data", stream: "stdout", offset: 2, text: "é" },
    ]);
    expect(leftovers()).toBe(0);
  });

  it("fences a settlement callback when the acknowledgement deadline expires", async () => {
    const events: OutputEvent[] = [];
    let releaseCallback!: () => void;
    const controller = new AbortController();
    const { client, leftovers } = harness(
      json(202, receipt()),
      () => {
        controller.abort();
        return json(200, page({})); // abort during the first output fetch
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")), // completion raced the abort
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "x"), chunk("stdout", 1, "y")],
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
    );
    const promise = client.commands.script("sbx_1", "true", {
      onAbort: "cancel",
      signal: controller.signal,
      cancelAckTimeoutMs: 1_000, // expires while the settlement callback blocks
      onOutput: (event) => {
        events.push(event);
        if (events.length === 1) {
          return new Promise<void>((resolve) => {
            releaseCallback = resolve;
          });
        }
      },
    });
    const error = await fails(promise);
    expect(error.kind).toBe("timeout");
    releaseCallback(); // the abandoned settlement task commits, then stops
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    // The second range was never delivered after run() rejected.
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "x" }]);
    expect(leftovers()).toBe(0);
  });

  it("fences decoder-flush callbacks per stream when the deadline expires", async () => {
    const events: OutputEvent[] = [];
    let releaseCallback!: () => void;
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          // A trailing incomplete UTF-8 sequence in BOTH streams: each flush
          // produces a callback at the completion watermark.
          chunks: [chunk("stdout", 0, [0x68, 0xc3]), chunk("stderr", 2, [0x65, 0xc3])],
          nextCursor: "0_4",
          receivedBytes: 4,
          totalBytes: 4,
          retainedBytes: 4,
        }),
      ),
    );
    const promise = client.commands.script("sbx_1", "true", {
      timeoutMs: 1_000,
      onOutput: (event) => {
        events.push(event);
        if (events.length === 3) {
          // Block on the STDOUT flush event; the deadline expires meanwhile.
          return new Promise<void>((resolve) => {
            releaseCallback = resolve;
          });
        }
      },
    });
    const error = await fails(promise);
    expect(error.kind).toBe("timeout");
    releaseCallback();
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    // The stderr flush callback never fired after run() rejected.
    expect(events).toEqual([
      { kind: "data", stream: "stdout", offset: 0, text: "h" },
      { kind: "data", stream: "stderr", offset: 2, text: "e" },
      { kind: "data", stream: "stdout", offset: 4, text: "\ufffd" },
    ]);
  });

  it("runs output callbacks before resolving completion", async () => {
    const order: string[] = [];
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          receivedBytes: 1,
          totalBytes: 1,
          retainedBytes: 1,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "true", {
        onOutput: async () => {
          await new Promise((resolve) => setTimeout(resolve, 50));
          order.push("callback");
        },
      }),
    );
    order.push("resolved");
    expect(result.exitCode).toBe(0);
    expect(order).toEqual(["callback", "resolved"]);
  });
});

describe("run submission and budget", () => {
  // The server bounds the SERIALIZED {argv, script, cwd, env} payload at
  // 32768 UTF-8 bytes, wrapper included: L + 45 for a plain ASCII script
  // (plus one byte per escaped newline in the script).
  const serializedBytes = (script: string) =>
    new TextEncoder().encode(JSON.stringify({ argv: null, script, cwd: null, env: [] })).byteLength;

  it("sends a script at the exact serialized payload boundary, byte-exact", async () => {
    const script = `#!/bin/sh\ntrue #${".".repeat(32722 - 16)}`;
    expect(script.length).toBe(32722);
    expect(serializedBytes(script)).toBe(32768);
    const { client, calls, leftovers } = harness(json(202, receipt()), json(200, completePage()));
    await ok(client.commands.script("sbx_1", script));
    expect(bodyOf(calls[0] as Call).script).toBe(script);
    expect(leftovers()).toBe(0);
  });

  it("rejects a script one byte beyond the serialized payload budget locally", async () => {
    const script = "x".repeat(32724);
    expect(serializedBytes(script)).toBe(32769);
    const { client, calls } = harness();
    const error = await fails(client.commands.script("sbx_1", script));
    expect(error.kind).toBe("invalid_request");
    expect(error.message).toContain("32769");
    expect(calls).toHaveLength(0);
  });

  it("maximal_contract_env_passes_frame_encoder", async () => {
    const fixtures: Array<{
      name: string;
      valid: boolean;
      pairs: Array<{ key: string; unit: string; repeat: number; tail: string }>;
    }> = JSON.parse(
      readFileSync(
        new URL("../../../crates/sandbox-protocol/fixtures/env_cases.json", import.meta.url),
        "utf8",
      ),
    );
    for (const fixture of fixtures.filter((c) => c.name.startsWith("maximal-"))) {
      const envs = Object.fromEntries(
        fixture.pairs.map((p) => [p.key, p.unit.repeat(p.repeat) + p.tail]),
      );
      const { client, calls } = harness(json(202, receipt()), json(200, commandResult()));
      await ok(client.commands.start("sbx_1", { argv: ["true"], envs }));
      expect(bodyOf(calls[0] as Call).envs).toEqual(envs);
    }
  });

  it("start waits out a host reconnect (503 sandbox.host_reconnecting) under one key", async () => {
    const reconnecting = () => envelope("sandbox.host_reconnecting", { retryAfterSeconds: 1 });
    const { client, calls } = harness(
      reconnecting(),
      reconnecting(),
      json(202, receipt()),
      json(200, commandResult()),
    );
    await ok(client.commands.start("sbx_1", { argv: ["true"], envs: { PRIVATE: "value" } }));
    const posts = calls.slice(0, 3);
    const keys = posts.map((c) => (c.init.headers as Record<string, string>)["idempotency-key"]);
    expect(new Set(keys).size).toBe(1);
    expect(posts.every((c) => c.init.method === "POST")).toBe(true);
    expect((calls[1] as Call).at - (calls[0] as Call).at).toBe(1_000);
    expect(calls).toHaveLength(4);
  });

  it("rejects an empty command name before network IO for start and run", async () => {
    const { client, calls } = harness();
    for (const action of [client.commands.start, client.commands.run]) {
      const error = await fails(action("sbx_1", { argv: [""] }));
      expect(error.kind).toBe("invalid_request");
    }
    expect(calls).toHaveLength(0);
  });

  it("rejects invalid envs and legacy env before network IO", async () => {
    for (const fields of [
      { env: [["A", "private-canary"]] },
      { envs: [["A", "private-canary"]] },
      { envs: { A: "界".repeat(1366) } },
      { envs: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`K${i}`, "x"])) },
      {
        envs: {
          A: "x".repeat(4096),
          B: "x".repeat(4096),
          C: "x".repeat(4096),
          D: "x".repeat(4096),
        },
      },
    ]) {
      const { client, calls } = harness();
      const error = await fails(
        client.commands.start("sbx_1", { argv: ["true"], ...fields } as never),
      );
      expect(error.kind).toBe("invalid_request");
      expect(error.message).not.toContain("private-canary");
      expect(calls).toHaveLength(0);
    }
  });

  it("rejects an over-long script locally, before any network IO", async () => {
    const { client, calls } = harness();
    const error = await fails(client.commands.script("sbx_1", "x".repeat(32769)));
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });

  it("accepts a 30-minute command timeout and waits it out within the lease", async () => {
    // Poll sleeps are exactly 60 seconds (min == max == the polling cap, no
    // jitter), so thirty pending pages push completion to the 30-minute mark:
    // a wait budget shortened to the 1 s default — or anything under
    // 30 minutes — would die at an early sleep. The run must complete within
    // the configured lease (the 1_800_000 ms command budget plus the 60 s
    // wait floor).
    const steps: Step[] = [
      json(202, receipt()),
      // Empty pending pages (no bytes yet, cursor unmoved, hasMore false —
      // each drain returns "not complete" before the no-progress check).
      ...Array.from({ length: 30 }, () => json(200, page({}))),
      json(200, completePage()),
      json(200, operation("SUCCEEDED")),
    ];
    const calls: Call[] = [];
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      const call: Call = { url, init, at: Date.now() };
      calls.push(call);
      const step = steps.shift();
      if (!step) throw new Error(`unexpected call: ${init.method} ${url}`);
      return typeof step === "function" ? step(call) : step;
    });
    const client = createWsspClient({
      baseUrl: BASE,
      apiKey: KEY,
      fetch,
      polling: { intervalMs: 60_000, maxIntervalMs: 60_000, waitTimeoutMs: 1_860_000 },
    });
    const startedAt = Date.now();
    const settled = await drive(
      client.commands.run("sbx_1", { script: "make bootstrap", timeoutMs: 1_800_000 }),
      2_400_000,
    );
    if (settled.error !== undefined) throw settled.error;
    const result = settled.value as RunResult;
    expect(result.exitCode).toBe(0);
    // The fake clock genuinely crossed the 30-minute boundary.
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(1_800_000);
    expect(bodyOf(calls[0] as Call).timeoutMs).toBe(1_800_000);
  });

  it("waits for dispatch before sending initial stdin (queued-to-running)", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()), // QUEUED
      json(200, operation("QUEUED", { dispatchedAt: null })),
      json(200, operation("DISPATCHED")),
      json(202, receipt("rcpt_stdin", "ACCEPTED")),
      json(200, completePage()),
    );
    await ok(client.commands.argv("sbx_1", ["cat"], { stdin: "hello stdin" }));
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/sandboxes/sbx_1/commands`,
      `GET ${BASE}/v1/operations/op_1`, // dispatch wait: still queued
      `GET ${BASE}/v1/operations/op_1`, // dispatched
      `POST ${BASE}/v1/operations/op_1/stdin`,
      // The dispatch wait above stays plain polling; the follow long-polls.
      `GET ${BASE}/v1/operations/op_1/output?waitMs=20000`,
    ]);
    expect(bodyOf(calls[3] as Call)).toEqual({
      contentBase64: Buffer.from("hello stdin").toString("base64"),
      eof: true,
    });
    // The stdin key is domain-separated and derived from the full run key.
    expect((calls[3] as Call).init.headers).toMatchObject({
      "idempotency-key": expect.stringMatching(/^sdk:stdin:[0-9a-f]{64}$/),
    });
    expect(leftovers()).toBe(0);
  });

  it("rejects an over-size initial stdin before ANY network IO", async () => {
    const { client, calls } = harness();
    const error = await fails(
      client.commands.argv("sbx_1", ["cat"], { stdin: new Uint8Array(32 * 1024 + 1) }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0); // the command is never started
  });

  it("rejects an invalid maxOutputChars before ANY network IO", async () => {
    for (const maxOutputChars of [0, -1, 1.5, 64 * 1024 * 1024 + 1]) {
      const { client, calls } = harness();
      const error = await fails(client.commands.script("sbx_1", "true", { maxOutputChars }));
      expect(error.kind).toBe("invalid_request");
      expect(error.message).toContain("maxOutputChars");
      expect(error.idempotencyKey).not.toBeNull(); // the generated key is carried
      expect(calls).toHaveLength(0); // no command was ever started
    }
  });

  it("rejects an invalid cancelAckTimeoutMs before ANY network IO", async () => {
    for (const cancelAckTimeoutMs of [0, -5, 10 * 60_000 + 1]) {
      const { client, calls } = harness();
      const error = await fails(
        client.commands.run("sbx_1", { argv: ["true"] }, { cancelAckTimeoutMs }),
      );
      expect(error.kind).toBe("invalid_request");
      expect(error.message).toContain("cancelAckTimeoutMs");
      expect(calls).toHaveLength(0);
    }
  });
});

describe("writeStdin", () => {
  it.each(["ACCEPTED", "SUCCEEDED"] as const)(
    "resolves at %s acceptance without polling the target command",
    async (state) => {
      const { client, calls, leftovers } = harness(json(202, receipt("rcpt_stdin", state)));
      await ok(client.commands.writeStdin("op_1", "abc", { idempotencyKey: "stdin-1" }));
      expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
        `POST ${BASE}/v1/operations/op_1/stdin`,
      ]);
      expect(bodyOf(calls[0] as Call)).toEqual({ contentBase64: b64("abc") });
      expect(leftovers()).toBe(0);
    },
  );

  it("surfaces a rejected write as the receipt's typed error", async () => {
    const { client } = harness(
      json(202, receipt("rcpt_stdin", "FAILED")),
      json(200, {
        ...cancelReceipt("FAILED", { errorCode: "CONFLICT" }),
        id: "rcpt_stdin",
        kind: "commands.writeStdin",
      }),
    );
    const error = await fails(client.commands.writeStdin("op_1", "abc"));
    expect(error.kind).toBe("conflict");
    expect(error.operationErrorCode).toBe("CONFLICT");
  });

  it("bounds the rejected-receipt read against cancellation-insensitive IO", async () => {
    const { client, calls } = harness(
      json(202, receipt()), // run start accepted
      json(200, operation("DISPATCHED")),
      json(202, receipt("rcpt_stdin", "FAILED")),
      hangs(), // the receipt read never answers
    );
    const error = await fails(
      client.commands.argv("sbx_1", ["cat"], { stdin: "x", waitTimeoutMs: 1_000 }),
    );
    // The shared run deadline reaches the read: a typed timeout carrying the
    // COMMAND's operation context, not a hang.
    expect(error.kind).toBe("timeout");
    expect(error.operationId).toBe("op_1");
    expect(error.message).toContain("stdin");
    expect(calls).toHaveLength(4);
  });

  it("keeps command context for a rejected stdin on a 30-minute command", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("DISPATCHED")),
      json(202, receipt("rcpt_stdin", "FAILED")),
      json(200, {
        ...cancelReceipt("FAILED", { errorCode: "CONFLICT" }),
        id: "rcpt_stdin",
        kind: "commands.writeStdin",
      }),
    );
    const error = await fails(
      client.commands.run(
        "sbx_1",
        // The 30-minute guest budget floors the wait deadline at 31 minutes —
        // far beyond the transport's per-request maximum. The receipt read
        // must not inherit that budget as a raw request timeout.
        { script: "long", timeoutMs: 1_800_000 },
        { stdin: "x" },
      ),
    );
    expect(error.kind).toBe("conflict");
    expect(error.operationErrorCode).toBe("CONFLICT");
    // The failed ACTION receipt is named; the command's context (label,
    // idempotency key) is retained alongside it.
    expect(error.operationId).toBe("rcpt_stdin");
    expect(error.message).toContain("stdin");
    expect(calls).toHaveLength(4);
  });

  it("requires eof for an empty write", async () => {
    const { client, calls } = harness();
    const error = await fails(client.commands.writeStdin("op_1", ""));
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
  });
});

describe("abort and cancellation", () => {
  it("abort requests cancellation and reports aborted only once CANCELLED is confirmed", async () => {
    const controller = new AbortController();
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      () => {
        controller.abort();
        return json(200, page({}));
      },
      json(202, receipt("rcpt_1", "CANCELLED")),
    );
    const error = await fails(
      client.commands.script("sbx_1", "sleep 60", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
      }),
    );
    expect(error.kind).toBe("aborted");
    expect(error.operationId).toBe("op_1");
    const cancel = calls[2] as Call;
    expect(cancel.init.method).toBe("POST");
    expect(cancel.url).toBe(`${BASE}/v1/operations/op_1/cancel`);
    expect((cancel.init.headers as Record<string, string>)["idempotency-key"]).toMatch(
      /^sdk:cancel:[0-9a-f]{64}$/,
    );
    expect(leftovers()).toBe(0);
  });

  it("reports an unknown outcome when the cancellation acknowledgement is lost", async () => {
    const controller = new AbortController();
    const { client } = harness(
      json(202, receipt()),
      () => {
        controller.abort();
        return json(200, page({}));
      },
      hangs(), // the cancel request never answers
    );
    const error = await fails(
      client.commands.script("sbx_1", "sleep 60", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
        cancelAckTimeoutMs: 1_000,
      }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toMatch(/^sdk:cancel:[0-9a-f]{64}$/);
  });

  it("fences a cancellation-insensitive output read that resolves after run() settled", async () => {
    const events: OutputEvent[] = [];
    const controller = new AbortController();
    let resolveLateRead!: (response: Response) => void;
    const calls: string[] = [];
    const steps: (Response | (() => Promise<Response>))[] = [
      json(202, receipt()),
      // The read NEVER observes the attempt signal (cancellation-insensitive
      // transport.request): it stays pending across the caller's abort and
      // the whole settlement, resolving only afterwards.
      () =>
        new Promise<Response>((resolve) => {
          resolveLateRead = resolve;
        }),
      json(202, receipt("rcpt_1", "SUCCEEDED")), // cancellation
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "ab")],
          nextCursor: "0_2",
          receivedBytes: 2,
          totalBytes: 2,
          retainedBytes: 2,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    ];
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      calls.push(`${init.method} ${url}`);
      const step = steps.shift();
      if (!step) throw new Error(`unexpected call: ${init.method} ${url}`);
      return typeof step === "function" ? step() : step;
    });
    // Model a cancellation-insensitive transport.request: the signal is
    // dropped, so a pending read resolves whenever the underlying IO does.
    const baseTransport = createWsspTransport({ baseUrl: BASE, apiKey: KEY, fetch });
    const rawRequest = baseTransport.request;
    const transport: WsspTransport = {
      ...baseTransport,
      request: ((route: string, input: unknown) =>
        rawRequest(
          route as never,
          { ...(input as object), signal: undefined } as never,
        )) as WsspTransport["request"],
    };
    const commands = createCommandsApi(transport, {
      intervalMs: 100,
      maxIntervalMs: 400,
      waitTimeoutMs: 60_000,
    });
    const promise = commands.script("sbx_1", "true", {
      onAbort: "cancel",
      signal: controller.signal,
      onOutput: (event) => {
        events.push(event);
      },
    });
    let settled: { result?: RunResult; error?: WsspError } = {};
    void promise.then(
      (result) => {
        settled.result = result;
      },
      (error: unknown) => {
        settled.error = error as WsspError;
      },
    );
    // Let the output read get in flight, then abort and drive settlement.
    for (let i = 0; i < 20; i++) await vi.advanceTimersByTimeAsync(10);
    controller.abort();
    for (let i = 0; i < 10_000 && settled.result === undefined && settled.error === undefined; i++)
      await vi.advanceTimersByTimeAsync(1_000);
    expect(settled.error).toBeUndefined();
    expect(settled.result?.stdout).toBe("ab");
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "ab" }]);
    // The stale read resolves AFTER run() settled: its page must be fenced —
    // no callback may fire post-settlement.
    resolveLateRead(
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "late")],
          nextCursor: "0_4",
          hasMore: true,
          receivedBytes: 4,
        }),
      ),
    );
    for (let i = 0; i < 100; i++) await vi.advanceTimersByTimeAsync(10);
    expect(events).toEqual([{ kind: "data", stream: "stdout", offset: 0, text: "ab" }]);
  });

  it("rejects unknown when a callback aborts the caller and then throws, even with CANCELLED confirmed", async () => {
    const controller = new AbortController();
    const events: OutputEvent[] = [];
    const { client } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          hasMore: true,
          receivedBytes: 1,
        }),
      ),
      json(202, receipt("rcpt_1", "CANCELLED")),
    );
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        onAbort: "cancel",
        signal: controller.signal,
        onOutput: (event) => {
          events.push(event);
          controller.abort(); // the abort wins the polling race...
          throw new Error("renderer exploded"); // ...then the callback fails
        },
      }),
    );
    // The sticky callback failure is reconciled during settlement: it wins
    // over the confirmed cancellation — the caller never saw that output.
    expect(error.kind).toBe("unknown");
    expect(error.message).toContain("onOutput");
    expect(events).toHaveLength(1);
    // The reconcile race left no referenced timer behind.
    expect(vi.getTimerCount()).toBe(0);
  });

  it("applies the cancellation policy to an abort during the stdin submission", async () => {
    const controller = new AbortController();
    const { client, calls, leftovers } = harness(
      json(202, receipt()), // QUEUED
      json(200, operation("DISPATCHED")),
      () => {
        // The stdin submission is in flight when the caller aborts; its send
        // becomes uncertain, but the accepted command still needs settling.
        controller.abort();
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "CANCELLED")),
    );
    const error = await fails(
      client.commands.argv("sbx_1", ["cat"], {
        idempotencyKey: "runkey",
        stdin: "hello",
        onAbort: "cancel",
        signal: controller.signal,
      }),
    );
    expect(error.kind).toBe("aborted");
    expect(error.message).toContain("cancelled");
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/sandboxes/sbx_1/commands`,
      `GET ${BASE}/v1/operations/op_1`,
      `POST ${BASE}/v1/operations/op_1/stdin`,
      `POST ${BASE}/v1/operations/op_1/cancel`,
    ]);
    expect(leftovers()).toBe(0);
  });

  it("reports unknown when the cancel scope is forbidden while settling an aborted run", async () => {
    const controller = new AbortController();
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      aborting(controller), // output read interrupted by the caller's abort
      envelope("FORBIDDEN"), // the key lacks the cancel scope
    );
    const error = await fails(
      client.commands.script("sbx_1", "sleep 60", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
      }),
    );
    // The cancellation was never confirmed: NOT a plain authorization error
    // with operationId null — an unknown outcome naming the command.
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toMatch(/^sdk:cancel:/);
    expect(error.message).toContain("could not be submitted");
    // Safe failure details survive as a bounded redacted cause.
    expect((error.cause as Error).message).toContain("FORBIDDEN");
    expect(JSON.stringify(error)).not.toContain(KEY);
    expect(calls).toHaveLength(3);
    expect(leftovers()).toBe(0);
  });

  it("reports unknown when the cancellation submission is throttled past its budget", async () => {
    const controller = new AbortController();
    const { client, calls } = harness(
      json(202, receipt()),
      aborting(controller),
      // 429s until the acknowledgement budget runs out (fresh Response per
      // attempt: a body can be read only once).
      ...Array.from({ length: 12 }, () => envelope("TOO_MANY_REQUESTS", { retryAfterSeconds: 0 })),
    );
    const error = await fails(
      client.commands.script("sbx_1", "sleep 60", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
        cancelAckTimeoutMs: 250,
      }),
    );
    // The throttle budget was exhausted: NOT a plain timeout — an unknown
    // outcome naming the command that may still be running (the submission's
    // own uncertainty report passes settlement through unchanged).
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toMatch(/^sdk:cancel:/);
    expect(error.message).toContain("same idempotency key");
    expect(calls.length).toBeGreaterThan(2);
  });

  it("reports unknown when the cancel scope is forbidden while settling an aborted opt-in run", async () => {
    const controller = new AbortController();
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      aborting(controller), // dispatch wait interrupted by the caller's abort
      envelope("FORBIDDEN"), // the key lacks the cancel scope
    );
    const error = await fails(
      client.commands.run(
        "sbx_1",
        { argv: ["sleep", "60"] },
        { stdin: "x", onAbort: "cancel", signal: controller.signal },
      ),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toMatch(/^sdk:cancel:/);
    expect(error.message).toContain("could not be submitted");
    expect((error.cause as Error).message).toContain("FORBIDDEN");
    expect(calls).toHaveLength(3);
    expect(leftovers()).toBe(0);
  });

  it("reports unknown when a opt-in run cancellation submission is throttled past its budget", async () => {
    const controller = new AbortController();
    const { client, calls } = harness(
      json(202, receipt()),
      aborting(controller),
      ...Array.from({ length: 12 }, () => envelope("TOO_MANY_REQUESTS", { retryAfterSeconds: 0 })),
    );
    const error = await fails(
      client.commands.run(
        "sbx_1",
        { argv: ["sleep", "60"] },
        { stdin: "x", onAbort: "cancel", signal: controller.signal },
      ),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toMatch(/^sdk:cancel:/);
    expect(error.message).toContain("same idempotency key");
    expect(calls.length).toBeGreaterThan(2);
  });

  it("cancels the accepted command when opt-in run aborts during the dispatch wait", async () => {
    const controller = new AbortController();
    const { client, calls, leftovers } = harness(
      json(202, receipt()), // accepted, still QUEUED
      () => {
        controller.abort(); // abort while waiting for dispatch
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "CANCELLED")),
    );
    const error = await fails(
      client.commands.run(
        "sbx_1",
        { argv: ["cat"] },
        { stdin: "x", onAbort: "cancel", signal: controller.signal },
      ),
    );
    expect(error.kind).toBe("aborted");
    expect(error.message).toContain("cancelled");
    expect(error.operationId).toBe("op_1");
    // The accepted command was not left to run unattended.
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/sandboxes/sbx_1/commands`,
      `GET ${BASE}/v1/operations/op_1`,
      `POST ${BASE}/v1/operations/op_1/cancel`,
    ]);
    expect(leftovers()).toBe(0);
  });

  it("returns natural completion when opt-in abort races a finished command", async () => {
    const controller = new AbortController();
    const { client } = harness(
      json(202, receipt()),
      () => {
        controller.abort();
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")), // the command finished first
      json(200, completePage()),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.run(
        "sbx_1",
        { argv: ["cat"] },
        { stdin: "x", onAbort: "cancel", signal: controller.signal },
      ),
    );
    expect(result.exitCode).toBe(0);
  });

  it("applies the cancellation policy to an abort during the terminal read", async () => {
    const controller = new AbortController();
    const { client, calls } = harness(
      json(202, receipt()),
      // Only a non-SUCCEEDED final page needs the terminal status read.
      json(200, completePage({ state: "FAILED", exitCode: null })),
      () => {
        // The output follow completed; the caller aborts while the final
        // operation read is in flight.
        controller.abort();
        return new Promise<Response>((_, reject) => {
          setTimeout(() => reject(new DOMException("aborted", "AbortError")), 10);
        });
      },
      json(202, receipt("rcpt_1", "CANCELLED")),
    );
    const error = await fails(
      client.commands.script("sbx_1", "true", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
      }),
    );
    expect(error.kind).toBe("aborted");
    expect(error.message).toContain("cancelled");
    expect((calls[3] as Call).url).toBe(`${BASE}/v1/operations/op_1/cancel`);
  });

  it("derives distinct cancel keys for distinct max-length keys with a common prefix", async () => {
    const prefix = "k".repeat(120);
    const cancelKeys: string[] = [];
    for (const suffix of ["AAAAAAA1", "AAAAAAA2"]) {
      const controller = new AbortController();
      const { client, calls } = harness(
        json(202, receipt()),
        () => {
          controller.abort();
          return json(200, page({}));
        },
        json(202, receipt("rcpt_1", "CANCELLED")),
      );
      await fails(
        client.commands.script("sbx_1", "sleep 60", {
          idempotencyKey: `${prefix}${suffix}`,
          onAbort: "cancel",
          signal: controller.signal,
        }),
      );
      const cancel = calls[2] as Call;
      cancelKeys.push((cancel.init.headers as Record<string, string>)["idempotency-key"] ?? "");
    }
    // A prefix-truncating derivation would collide here (idempotency conflict).
    expect(cancelKeys[0]).toMatch(/^sdk:cancel:[0-9a-f]{64}$/);
    expect(cancelKeys[0]).not.toBe(cancelKeys[1]);
  });

  it("resolves normally when completion races the abort", async () => {
    const controller = new AbortController();
    const { client } = harness(
      json(202, receipt()),
      () => {
        controller.abort();
        return json(200, page({}));
      },
      json(202, receipt("rcpt_1", "SUCCEEDED")), // the command had already finished
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "done")],
          nextCursor: "0_4",
          receivedBytes: 4,
          totalBytes: 4,
          retainedBytes: 4,
        }),
      ),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(
      client.commands.script("sbx_1", "true", {
        idempotencyKey: "runkey",
        onAbort: "cancel",
        signal: controller.signal,
      }),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("done");
  });
});

describe("cancelAndWait", () => {
  it("resolves once the target confirms CANCELLED", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt("rcpt_1", "CANCEL_REQUESTED")),
      json(200, operation("CANCEL_REQUESTED")),
      json(200, operation("CANCELLED", { completedAt: NOW })),
    );
    const result = await ok(client.commands.cancelAndWait("op_1", { idempotencyKey: "cx-1" }));
    expect(result).toEqual({ operationId: "op_1", state: "CANCELLED", outcome: "cancelled" });
    // Confirmation is read from the TARGET operation, not the action receipt.
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/operations/op_1/cancel`,
      `GET ${BASE}/v1/operations/op_1?waitMs=20000`,
      `GET ${BASE}/v1/operations/op_1?waitMs=20000`,
    ]);
    expect(leftovers()).toBe(0);
  });

  it("resolves with succeeded when the command completed first (normal completion race)", async () => {
    const { client } = harness(json(202, receipt("rcpt_1", "SUCCEEDED")));
    const result = await ok(client.commands.cancelAndWait("op_1"));
    expect(result.outcome).toBe("succeeded");
    expect(result.state).toBe("SUCCEEDED");
  });

  it("reads the target after a FAILED cancel action: it may still have been cancelled", async () => {
    // The cancellation ACTION was rejected (e.g. the generation moved on); the
    // receipt reports FAILED, which says nothing about the command itself.
    const { client } = harness(
      json(202, receipt("rcpt_1", "FAILED")),
      json(200, operation("CANCELLED", { completedAt: NOW })),
    );
    const result = await ok(client.commands.cancelAndWait("op_1"));
    expect(result).toEqual({ operationId: "op_1", state: "CANCELLED", outcome: "cancelled" });
  });

  it("reads the target after a FAILED cancel action: a genuine command failure", async () => {
    const { client } = harness(
      json(202, receipt("rcpt_1", "FAILED")),
      json(200, operation("FAILED", { errorCode: "guest_operation_failed", completedAt: NOW })),
    );
    const result = await ok(client.commands.cancelAndWait("op_1"));
    expect(result).toEqual({ operationId: "op_1", state: "FAILED", outcome: "failed" });
  });

  it("stays unknown when the target never confirms after a FAILED cancel action", async () => {
    const { client } = harness(json(202, receipt("rcpt_1", "FAILED")), hangs());
    const error = await fails(
      client.commands.cancelAndWait("op_1", { idempotencyKey: "cx-3", waitTimeoutMs: 1_000 }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
  });

  it("returns the operation ID with an unknown outcome when the ACK never resolves", async () => {
    const { client } = harness(json(202, receipt("rcpt_1", "CANCEL_REQUESTED")), hangs());
    const error = await fails(
      client.commands.cancelAndWait("op_1", { idempotencyKey: "cx-2", waitTimeoutMs: 1_000 }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toBe("cx-2");
  });
});

describe("detached broker flow", () => {
  it("starts detached, then stat/tail/cancel work from the operation ID alone", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(200, commandResult()), // start
      json(200, page({ receivedBytes: 2 })), // stat: still running
      json(
        200,
        page({
          chunks: [chunk("stdout", 0, "ab")],
          nextCursor: "0_2",
          hasMore: false,
          receivedBytes: 2,
        }),
      ),
      json(
        200,
        completePage({
          offset: 2,
          chunks: [chunk("stdout", 2, "cd")],
          nextCursor: "0_4",
          receivedBytes: 4,
          totalBytes: 4,
          retainedBytes: 4,
        }),
      ),
      json(202, receipt("rcpt_1", "SUCCEEDED")), // cancel after completion
    );
    const process = await ok(
      client.commands.start("sbx_1", { script: "printf abcd" }, { idempotencyKey: "broker-1" }),
    );
    expect(process.operationId).toBe("op_1");
    const stat = await ok(process.stat());
    expect(stat.state).toBe("RUNNING");
    expect(stat.complete).toBe(false);
    const tail = await ok(process.tail());
    expect(tail.stdout).toBe("abcd");
    expect(tail.exitCode).toBe(0);
    expect(tail.state).toBe("SUCCEEDED");
    const cancel = await ok(process.cancelAndWait());
    expect(cancel.outcome).toBe("succeeded");
    expect(calls[2]?.url).toBe(`${BASE}/v1/operations/op_1/output?maxBytes=1`);
    expect(leftovers()).toBe(0);
  });

  it("tail keeps only the last maxChars of each stream", async () => {
    const { client } = harness(
      json(
        200,
        completePage({
          chunks: [chunk("stdout", 0, "0123456789"), chunk("stderr", 10, "err!")],
          nextCursor: "0_14",
          receivedBytes: 14,
          totalBytes: 14,
          retainedBytes: 14,
        }),
      ),
    );
    const tail = await ok(client.commands.tail("op_1", { maxChars: 4 }));
    expect(tail.stdout).toBe("6789");
    expect(tail.stderr).toBe("err!");
    expect(tail.truncated).toBe(false);
  });
});

describe("C58-2 an UNKNOWN_OUTCOME command is reported unknown, promptly", () => {
  it("run rejects `unknown` with the operation as soon as the caught-up page reads UNKNOWN_OUTCOME", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          chunks: [chunk("stdout", 0, "partial")],
          nextCursor: "0_7",
          receivedBytes: 7,
        }),
      ),
      json(200, operation("UNKNOWN_OUTCOME", { errorCode: "unknown_outcome" })),
    );
    const started = Date.now();
    const error = await fails(
      client.commands.run(
        "sbx_1",
        { script: "make", timeoutMs: 1_800_000 },
        { idempotencyKey: "k" },
      ),
    );
    expect(error).toMatchObject({
      kind: "unknown",
      operationId: "op_1",
      idempotencyKey: "k",
      operationErrorCode: "unknown_outcome",
    });
    // Not the 31-minute deadline: one page and one operation read. `Date` is
    // the fake clock (beforeEach `vi.useFakeTimers()`), advanced only by
    // `drive()` in 25 ms steps, so this bound is simulated time, not wall time.
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual([
      "/prefix/v1/sandboxes/sbx_1/commands",
      "/prefix/v1/operations/op_1/output",
      "/prefix/v1/operations/op_1",
    ]);
    expect(leftovers()).toBe(0);
  });

  it("inverse: a still-running command keeps following, without reading the operation, to its full output", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(200, page({ chunks: [chunk("stdout", 0, "a")], nextCursor: "0_1", receivedBytes: 1 })),
      json(200, page({ offset: 1, nextCursor: "0_1", receivedBytes: 1 })),
      json(
        200,
        completePage({
          offset: 1,
          chunks: [chunk("stdout", 1, "bc")],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
    );
    const result = await ok(client.commands.script("sbx_1", "slow", { idempotencyKey: "k" }));
    expect(result).toMatchObject({ exitCode: 0, stdout: "abc", truncated: false });
    expect(
      calls.filter((c) => new URL(c.url).pathname === "/prefix/v1/operations/op_1"),
    ).toHaveLength(0);
    expect(leftovers()).toBe(0);
  });

  it("inverse: an interim UNKNOWN that a late receipt resolved keeps following to the watermark", async () => {
    const { client, leftovers } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          receivedBytes: 1,
        }),
      ),
      // The receipt landed between the page and the operation read.
      json(200, operation("SUCCEEDED")),
      json(
        200,
        completePage({
          offset: 1,
          chunks: [chunk("stdout", 1, "yz")],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
    );
    const result = await ok(client.commands.script("sbx_1", "x", { idempotencyKey: "k" }));
    expect(result).toMatchObject({ exitCode: 0, stdout: "xyz" });
    expect(leftovers()).toBe(0);
  });

  it("tail of an UNKNOWN_OUTCOME command rejects `unknown` instead of waiting out its budget", async () => {
    const { client, leftovers } = harness(
      json(200, page({ state: "UNKNOWN_OUTCOME", nextCursor: "0_0" })),
      json(200, operation("UNKNOWN_OUTCOME", { errorCode: "unknown_outcome" })),
    );
    const error = await fails(client.commands.tail("op_1"));
    expect(error).toMatchObject({ kind: "unknown", operationId: "op_1" });
    expect(leftovers()).toBe(0);
  });
});

describe("REVIEWER PROBE fix-sdk-r1", () => {
  it("tail: interim UNKNOWN resolved late to FAILED keeps following and returns the tail", async () => {
    const { client, leftovers } = harness(
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          receivedBytes: 1,
        }),
      ),
      json(200, operation("FAILED", { errorCode: "not_found" })),
      json(
        200,
        completePage({
          state: "FAILED",
          exitCode: 3,
          offset: 1,
          chunks: [chunk("stdout", 1, "yz")],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
    );
    const tail = await ok(client.commands.tail("op_1"));
    expect(tail).toMatchObject({ state: "FAILED", exitCode: 3, stdout: "xyz" });
    expect(leftovers()).toBe(0);
  });

  it("run: interim UNKNOWN then op read pending (CANCEL_REQUESTED) keeps following, never unknown", async () => {
    const { client, leftovers } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "0_1",
          receivedBytes: 1,
        }),
      ),
      json(200, operation("CANCEL_REQUESTED")),
      json(
        200,
        completePage({
          offset: 1,
          chunks: [chunk("stdout", 1, "yz")],
          nextCursor: "0_3",
          receivedBytes: 3,
          totalBytes: 3,
          retainedBytes: 3,
        }),
      ),
    );
    const result = await ok(client.commands.script("sbx_1", "x", { idempotencyKey: "k" }));
    expect(result).toMatchObject({ exitCode: 0, stdout: "xyz" });
    expect(leftovers()).toBe(0);
  });

  it("run: UNKNOWN page with hasMore reads the next page first, operation only when caught up", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          chunks: [chunk("stdout", 0, "ab")],
          nextCursor: "0_2",
          receivedBytes: 4,
          hasMore: true,
        }),
      ),
      json(
        200,
        page({
          state: "UNKNOWN_OUTCOME",
          offset: 2,
          chunks: [chunk("stdout", 2, "cd")],
          nextCursor: "0_4",
          receivedBytes: 4,
        }),
      ),
      json(200, operation("UNKNOWN_OUTCOME", { errorCode: "unknown_outcome" })),
    );
    const seen: string[] = [];
    const error = await fails(
      client.commands.run(
        "sbx_1",
        { script: "x" },
        {
          idempotencyKey: "k",
          onOutput: (e) => {
            if (e.kind === "data") seen.push(e.text);
          },
        },
      ),
    );
    expect(error).toMatchObject({ kind: "unknown", operationId: "op_1" });
    expect(seen.join("")).toBe("abcd");
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual([
      "/prefix/v1/sandboxes/sbx_1/commands",
      "/prefix/v1/operations/op_1/output",
      "/prefix/v1/operations/op_1/output",
      "/prefix/v1/operations/op_1",
    ]);
    expect(leftovers()).toBe(0);
  });
});

describe("definitive control catalog refusals", () => {
  it.each([
    ["sandbox.process_unknown_outcome", "unknown"],
    ["sandbox.process_exited", "conflict"],
    ["sandbox.process_stale", "conflict"],
    ["sandbox.process_stdin_closed", "conflict"],
    ["sandbox.process_cancel_pending", "conflict"],
    ["sandbox.process_unavailable", "unavailable"],
    ["sandbox.process_not_started", "conflict"],
    ["sandbox.process_permission_denied", "conflict"],
  ] as const)("%s is final for every shared mutation consumer", async (code, kind) => {
    for (const helper of ["stdin", "cancel", "run", "files"] as const) {
      const { client, calls } = harness(envelope(code));
      const options = { idempotencyKey: "final-refusal", waitTimeoutMs: 1_000 };
      const pending =
        helper === "stdin"
          ? client.commands.writeStdin("op_1", "x", options)
          : helper === "cancel"
            ? client.commands.cancelAndWait("op_1", options)
            : helper === "run"
              ? client.commands.run("sbx_1", { argv: ["true"] }, options)
              : client.files.stat("sbx_1", "/", options);
      const error = await fails(pending);
      expect(error).toMatchObject({ kind, code, status: 409, idempotencyKey: "final-refusal" });
      expect(error.message).not.toContain("may have reached");
      expect(calls).toHaveLength(1);
      expect(calls[0]?.init.method).toBe("POST");
    }
  });
});

it("a mutation throttled through its deadline retains capacity, code and Retry-After", async () => {
  const { client, calls } = harness(
    json(
      429,
      {
        error: {
          code: "TOO_MANY_REQUESTS",
          message: SDK_ERRORS.TOO_MANY_REQUESTS[1],
          requestId: REQUEST_ID,
        },
      },
      { "retry-after": "5" },
    ),
  );
  const error = await fails(
    client.commands.writeStdin("op_1", "x", { idempotencyKey: "throttled", waitTimeoutMs: 1_000 }),
  );
  expect(error).toMatchObject({
    kind: "capacity",
    code: "TOO_MANY_REQUESTS",
    status: 429,
    retryAfterSeconds: 5,
    idempotencyKey: "throttled",
  });
  expect(error.message).not.toContain("may have reached");
  expect(calls).toHaveLength(1);
});

it("earlier transport uncertainty survives a later capacity refusal at the deadline", async () => {
  const { client, calls } = harness(
    () => {
      throw new TypeError("network unavailable");
    },
    json(
      429,
      {
        error: {
          code: "TOO_MANY_REQUESTS",
          message: SDK_ERRORS.TOO_MANY_REQUESTS[1],
          requestId: REQUEST_ID,
        },
      },
      { "retry-after": "5" },
    ),
  );
  const error = await fails(
    client.commands.writeStdin("op_1", "x", {
      idempotencyKey: "uncertain-throttled",
      waitTimeoutMs: 1_000,
    }),
  );
  expect(error).toMatchObject({
    kind: "unknown",
    reason: "timeout",
    idempotencyKey: "uncertain-throttled",
  });
  expect(error.message).toContain("may have reached");
  expect(calls).toHaveLength(2);
});

describe("long-poll operation reads", () => {
  /** A server hold: answers `body` after `ms`, or rejects when the request aborts. */
  function held(ms: number, body: () => Response): Step {
    return (call) =>
      new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => resolve(body()), ms);
        call.init.signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(new DOMException("This operation was aborted", "AbortError"));
        });
      });
  }
  const waitMsOf = (call: Call) => new URL(call.url).searchParams.get("waitMs");

  it("run() of a quick command is the submit plus one held output read", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      // The command finishes 300 ms into the hold; the server answers at once.
      held(300, () =>
        json(
          200,
          completePage({
            chunks: [chunk("stdout", 0, "hi\n")],
            nextCursor: "0_3",
            receivedBytes: 3,
            totalBytes: 3,
            retainedBytes: 3,
          }),
        ),
      ),
    );
    const startedAt = Date.now();
    const result = await ok(client.commands.script("sbx_1", "echo hi"));
    expect(result.stdout).toBe("hi\n");
    // The SUCCEEDED complete page carries everything: no status read.
    expect(calls).toHaveLength(2);
    expect(waitMsOf(calls[1] as Call)).toBe("20000");
    // No poll interval was slept: the answer is seen as soon as it commits.
    expect(Date.now() - startedAt).toBeLessThan(400);
    expect(leftovers()).toBe(0);
  });

  it("regression (prod trace): server-paced progress is followed at once, never after a backoff", async () => {
    // Production trace at 22d2de1: the SDK slept ~500 ms after an answer that
    // carried the bytes. A server-paced answer (held its progress hold) that
    // moved the cursor must be re-issued immediately.
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      // Attempt-0 cursor, then the dispatched attempt resets it with bytes.
      held(OPERATION_WAIT_PROGRESS_HOLD_MS, () =>
        json(
          200,
          page({
            attempt: 1,
            reset: true,
            chunks: [chunk("stdout", 0, "hi\n")],
            nextCursor: "1_3",
            receivedBytes: 3,
            retainedBytes: 3,
          }),
        ),
      ),
      // The completion watermark commits 120 ms into the next hold.
      held(120, () =>
        json(
          200,
          completePage({
            attempt: 1,
            offset: 3,
            nextCursor: "1_3",
            receivedBytes: 3,
            totalBytes: 3,
            retainedBytes: 3,
          }),
        ),
      ),
    );
    const result = await ok(client.commands.script("sbx_1", "echo hi"));
    expect(result).toMatchObject({ exitCode: 0, stdout: "hi\n" });
    expect(calls).toHaveLength(3);
    // Zero SDK-side gap: the next read went out the instant the answer arrived.
    expect((calls[2] as Call).at - (calls[1] as Call).at).toBe(OPERATION_WAIT_PROGRESS_HOLD_MS);
    expect(leftovers()).toBe(0);
  });

  it("early or replayed progress backs off instead of looping (old, capped or hostile server)", async () => {
    // Every answer comes back at once with the same bytes and cursor (a replay).
    const replay = () =>
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 }));
    const { client, calls } = harness(
      json(202, receipt()),
      ...Array.from({ length: 30 }, () => replay),
    );
    const settled = await drive(client.commands.script("sbx_1", "x", { waitTimeoutMs: 4_000 }));
    expect(settled.error).toMatchObject({ kind: "timeout" });
    const reads = calls.filter((c) => new URL(c.url).pathname.endsWith("/output"));
    // Interval backoff 100 → 400 ms (harness polling), never back to back.
    for (let i = 1; i < reads.length; i++)
      expect((reads[i] as Call).at - (reads[i - 1] as Call).at).toBeGreaterThanOrEqual(100);
    expect(reads.length).toBeLessThanOrEqual(12);
  });

  it("early progress that does advance still backs off (not paced by the server)", async () => {
    let offset = 0;
    const early: Step = () => {
      offset += 1;
      return json(
        200,
        page({
          offset: offset - 1,
          chunks: [chunk("stdout", offset - 1, "x")],
          nextCursor: `0_${offset}`,
          receivedBytes: offset,
          retainedBytes: offset,
        }),
      );
    };
    const { client, calls } = harness(
      json(202, receipt()),
      ...Array.from({ length: 30 }, () => early),
    );
    await drive(client.commands.script("sbx_1", "x", { waitTimeoutMs: 4_000 }));
    const reads = calls.filter((c) => new URL(c.url).pathname.endsWith("/output"));
    for (let i = 1; i < reads.length; i++)
      expect((reads[i] as Call).at - (reads[i - 1] as Call).at).toBeGreaterThanOrEqual(100);
  });

  it("sustained multi-page output stays within the per-key budget", async () => {
    // A command printing 128 KiB/s: every read finds a full 64 KiB page with
    // more waiting (hasMore). After the retained-output burst the follow paces
    // itself to one read per 2 s.
    let offset = 0;
    const startedAt = Date.now();
    const full: Step = () => {
      const start = offset;
      offset += 1;
      return json(
        200,
        page({
          offset: start,
          chunks: [chunk("stdout", start, "y")],
          nextCursor: `0_${offset}`,
          receivedBytes: offset + 1,
          retainedBytes: offset,
          hasMore: true,
        }),
      );
    };
    const { client, calls } = harness(
      json(202, receipt()),
      ...Array.from({ length: 200 }, () => full),
    );
    await drive(client.commands.script("sbx_1", "x", { waitTimeoutMs: 120_000 }), 130_000);
    const reads = calls.filter((c) => new URL(c.url).pathname.endsWith("/output"));
    const inFirstMinute = reads.filter((c) => c.at - startedAt < 60_000).length;
    const inSecondMinute = reads.filter(
      (c) => c.at - startedAt >= 60_000 && c.at - startedAt < 120_000,
    ).length;
    expect(inFirstMinute).toBeLessThanOrEqual(OUTPUT_READ_BURST + 30);
    expect(inSecondMinute).toBeLessThanOrEqual(30);
    expect(inSecondMinute).toBeGreaterThanOrEqual(25); // paced, not stalled
    expect(inFirstMinute + inSecondMinute).toBeLessThan(100);
  });

  it("rejects an output page that belongs to another operation (no success shortcut)", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, completePage({ operationId: "op_other", chunks: [chunk("stdout", 0, "x")] })),
    );
    const error = await fails(client.commands.script("sbx_1", "true"));
    expect(error).toMatchObject({ kind: "protocol", operationId: "op_1" });
    expect(error.message).toContain("different operation");
    expect(calls).toHaveLength(2);
  });

  it("a chatty 60 s command costs at most ~30 output requests a minute", async () => {
    // Mock server with the contract's streamed-output pacing: every read of a
    // running command that has new bytes is held OPERATION_WAIT_PROGRESS_HOLD_MS
    // and answered with them; at 60 s the command completes. Zero RTT is the
    // worst case for the rate.
    const startedAt = Date.now();
    let offset = 0;
    const serve: Step = () =>
      new Promise<Response>((resolve) => {
        setTimeout(() => {
          const done = Date.now() - startedAt >= 60_000;
          const start = offset;
          offset += 1;
          resolve(
            json(
              200,
              (done ? completePage : page)({
                offset: start,
                chunks: [chunk("stdout", start, "x")],
                nextCursor: `0_${offset}`,
                receivedBytes: offset,
                retainedBytes: offset,
                ...(done ? { totalBytes: offset } : {}),
              }),
            ),
          );
        }, OPERATION_WAIT_PROGRESS_HOLD_MS);
      });
    const { client, calls } = harness(
      json(202, receipt()),
      ...Array.from({ length: 40 }, () => serve),
    );
    const result = await ok(
      client.commands.script("sbx_1", "yes | pv -qL 20", { waitTimeoutMs: 120_000 }),
    );
    expect(result.exitCode).toBe(0);
    const outputReads = calls.filter((c) => new URL(c.url).pathname.endsWith("/output"));
    expect(outputReads.length).toBeLessThanOrEqual(31);
    expect(result.stdout).toBe("x".repeat(outputReads.length));
    // Each read went out as soon as the previous answered: pacing is the
    // server hold alone, not an SDK backoff on top of it.
    for (let i = 1; i < outputReads.length; i++)
      expect((outputReads[i] as Call).at - (outputReads[i - 1] as Call).at).toBe(
        OPERATION_WAIT_PROGRESS_HOLD_MS,
      );
  });

  it("a 30 s command costs at most three output reads, re-sent without sleeping", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      held(20_000, () => json(200, page())), // full hold, nothing new
      held(10_000, () => json(200, completePage())), // completes 10 s into the next hold
    );
    await ok(client.commands.script("sbx_1", "sleep 30"));
    expect(calls).toHaveLength(3);
    // The second hold went out immediately after the first came back.
    expect((calls[2] as Call).at - (calls[1] as Call).at).toBe(20_000);
    expect(leftovers()).toBe(0);
  });

  it("an early answer WITHOUT news (server waiter cap) backs off instead of looping", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, page()), // answered at once although a hold was asked for
      json(200, page()),
      json(200, completePage()),
    );
    await ok(client.commands.script("sbx_1", "true"));
    expect((calls[2] as Call).at - (calls[1] as Call).at).toBe(100); // intervalMs
    expect((calls[3] as Call).at - (calls[2] as Call).at).toBe(200); // doubled
  });

  it("a FAILED final page still reads the operation for its typed error", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(200, completePage({ state: "FAILED", exitCode: null })),
      json(200, operation("FAILED", { errorCode: "timeout", completedAt: NOW })),
    );
    const error = await fails(client.commands.script("sbx_1", "sleep 99"));
    expect(error).toMatchObject({ kind: "timeout", operationId: "op_1" });
    expect(calls).toHaveLength(3);
    expect(leftovers()).toBe(0);
  });

  it("falls back to plain polling after an old server's 400 and remembers it", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      envelope("BAD_REQUEST"), // an old server rejects the unknown waitMs
      json(200, page({ chunks: [chunk("stdout", 0, "x")], nextCursor: "0_1", receivedBytes: 1 })),
      json(200, completePage({ offset: 1, nextCursor: "0_1", receivedBytes: 1, totalBytes: 1 })),
    );
    await ok(client.commands.script("sbx_1", "true"));
    expect(calls.map((c) => waitMsOf(c))).toEqual([null, "20000", null, null]);
    // Without server holds, progress does not skip the interval (no tight loop).
    expect((calls[3] as Call).at - (calls[2] as Call).at).toBe(100);
    expect(leftovers()).toBe(0);
  });

  it("a 400 without waitMs is a real error, not a fallback", async () => {
    const { client, calls } = harness(json(202, receipt()), envelope("BAD_REQUEST"));
    const error = await fails(client.commands.script("sbx_1", "true", { longPollMs: 0 }));
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(2);
  });

  it("clamps the hold to the remaining wait deadline", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      held(4_000, () => json(200, page())),
      hangs(),
    );
    const error = await fails(client.commands.script("sbx_1", "true", { waitTimeoutMs: 5_000 }));
    expect(error.kind).toBe("timeout");
    // 5 s budget minus the 1 s answer margin; the remainder is too short to hold.
    expect(waitMsOf(calls[1] as Call)).toBe("4000");
    expect(waitMsOf(calls[2] as Call)).toBeNull();
  });

  it("an abort during a held read goes through cancellation settlement", async () => {
    const controller = new AbortController();
    const { client, calls } = harness(
      json(202, receipt()),
      held(20_000, () => json(200, page())),
      json(202, receipt("rcpt_1", "CANCEL_REQUESTED")),
      json(200, operation("CANCELLED", { completedAt: NOW })),
    );
    const promise = client.commands.script("sbx_1", "sleep 60", {
      onAbort: "cancel",
      signal: controller.signal,
    });
    for (let i = 0; i < 20 && calls.length < 2; i++) await vi.advanceTimersByTimeAsync(10);
    controller.abort();
    const error = await fails(promise);
    expect(error.kind).toBe("aborted");
    expect(error.message).toContain("cancelled after the abort");
    expect(calls.map((c) => `${c.init.method} ${new URL(c.url).pathname}`)).toEqual([
      "POST /prefix/v1/sandboxes/sbx_1/commands",
      "GET /prefix/v1/operations/op_1/output",
      "POST /prefix/v1/operations/op_1/cancel",
      "GET /prefix/v1/operations/op_1",
    ]);
  });

  it("start() holds the result read until the process started", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      held(20_000, () => envelope("OPERATION_RESULT_NOT_READY")), // full hold, not ready
      held(500, () => json(200, commandResult())),
    );
    const process = await ok(client.commands.start("sbx_1", { script: "sleep 5" }));
    expect(process.process.pid).toBe(42);
    expect(calls.map((c) => `${new URL(c.url).pathname}?waitMs=${waitMsOf(c)}`)).toEqual([
      "/prefix/v1/sandboxes/sbx_1/commands?waitMs=null",
      "/prefix/v1/operations/op_1/result?waitMs=20000",
      "/prefix/v1/operations/op_1/result?waitMs=20000",
    ]);
    expect((calls[2] as Call).at - (calls[1] as Call).at).toBe(20_000);
    expect(leftovers()).toBe(0);
  });

  it("rejects an out-of-range longPollMs before any request", async () => {
    const { client, calls } = harness();
    for (const longPollMs of [-1, 25_001, 1.5]) {
      await expect(client.commands.script("sbx_1", "true", { longPollMs })).rejects.toThrow(
        /longPollMs/,
      );
    }
    expect(calls).toHaveLength(0);
  });
});
