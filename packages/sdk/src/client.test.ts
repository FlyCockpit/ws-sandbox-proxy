import {
  isRetryableRefusalCode,
  type OperationStateDto,
  operationOutcome,
  type SandboxDto,
  type SandboxStateDto,
  SDK_ERRORS,
  type SdkErrorCode,
} from "@wssp/sandbox-contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { isCapacityWaitTimeout, isWsspError, WsspError } from "./errors";
import { poll, resolvePolling } from "./polling";
import type { FetchLike } from "./transport";

const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test/prefix";
const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const NOW = "2026-01-01T00:00:00.000Z";
const T1 = "2026-01-01T01:00:00.000Z";

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
      ...(code === "sandbox.share_quota" || code === "sandbox.member_quota"
        ? { resource: "memory" }
        : {}),
      code,
      message,
      requestId: REQUEST_ID,
      ...extra,
    },
  });
}

function sandbox(
  state: SandboxStateDto,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    diskGiB: 32,
    id: "sbx_1",
    name: "quiet-otter",
    hostId: "host_1",
    storageId: "storage_1",
    storagePoolName: "default",
    storageMarker: "marker_1",
    templateId: "tpl_1",
    templateRevisionId: "tpl_1",
    originPoolId: null,
    cpuCount: 1,
    memoryMiB: 1024,
    state,
    generation: 1,
    endAt: null,
    startedAt: null,
    readyAt: null,
    lifecycle: { onTimeout: "kill", autoResume: false },
    sandboxDomain: null,
    portExposure: null,
    lease: { revision: 0, expiresAt: null, onExpire: "stop", requested: null, effective: null },
    egress: { mode: "allowlist", domains: [], cidrs: [] },
    egressRequest: null,
    egressModeReason: null,
    egressDeniedGrants: [],
    guestSudo: true,
    guestSudoRequested: true,
    guestSudoReason: null,
    guestRoot: true,
    disk: {
      location: "host",
      offloadState: "none",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: null,
      eligibility: "any_host",
      offloadPin: "ANY",
      offloadPolicy: { mode: "on_stop" },
      offloadDueAt: null,
    },
    metadata: {},
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

function operation(state: OperationStateDto, over: Record<string, unknown> = {}) {
  return {
    id: "op_1",
    sandboxId: "sbx_1",
    kind: "CREATE_SANDBOX",
    state,
    outcome: operationOutcome(state),
    generation: 1,
    failure: null,
    leaseIntent: {
      acceptedAt: NOW,
      timeoutMs: 300000,
      revision: 1,
      endAt: T1,
      onTimeout: "kill",
      acknowledgedAt: NOW,
      acknowledgedAttempt: 1,
      acknowledgedEpoch: 1,
    },
    errorCode: null,
    createdAt: NOW,
    updatedAt: NOW,
    dispatchedAt: NOW,
    completedAt: null,
    ...over,
  };
}

function probe(
  observation: "guest_ready" | "stopped" | "confirmed_absent" | "unreachable" | null,
  over: Record<string, unknown> = {},
) {
  return {
    id: "op_p1",
    kind: "sandboxes.probe",
    state: "SUCCEEDED",
    outcome: "succeeded",
    sandboxId: "sbx_1",
    generation: 1,
    errorCode: null,
    targetOperationId: null,
    resourceId: "sbx_1",
    observation,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

const receipt = (operationId = "op_1") => ({
  operationId,
  state: "QUEUED",
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

/** Flush microtasks and any zero-delay timers. */
async function flush(times = 10): Promise<void> {
  for (let i = 0; i < times; i++) await vi.advanceTimersByTimeAsync(0);
}

const idempotencyKeys = (calls: Call[]) =>
  calls.map((call) => (call.init.headers as Record<string, string>)["idempotency-key"]);

function callAt(calls: Call[], index: number): Call {
  const call = calls[index];
  if (!call) throw new Error(`no call at index ${index}`);
  return call;
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("create with waitForCapacityMs", () => {
  afterEach(() => vi.useRealTimers());

  it("polls a waiting create slowly (5–15 s, plain reads), then long-polls once it is placed", async () => {
    vi.useFakeTimers();
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(200, operation("QUEUED")),
      json(200, sandbox("WAITING_FOR_CAPACITY", { hostId: null, storageId: null })),
      json(200, sandbox("WAITING_FOR_CAPACITY", { hostId: null, storageId: null })),
      json(200, sandbox("REQUESTED")),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
    );
    const pending = client.sandboxes.create(
      { template: "base", poolId: "pool_1", waitForCapacityMs: 3_600_000 },
      { idempotencyKey: "queued-1" },
    );
    await vi.advanceTimersByTimeAsync(5_000);
    await vi.advanceTimersByTimeAsync(15_000);
    const result = await pending;
    expect(result.state).toBe("READY");
    const urls = calls.map((c) => c.url);
    expect(urls.slice(1, 5)).toEqual([
      `${BASE}/v1/operations/op_1`,
      `${BASE}/v1/sandboxes/sbx_1`,
      `${BASE}/v1/sandboxes/sbx_1`,
      `${BASE}/v1/sandboxes/sbx_1`,
    ]);
    expect(calls[2]!.at - calls[1]!.at).toBeLessThan(1_000);
    expect(calls[3]!.at - calls[2]!.at).toBeGreaterThanOrEqual(5_000);
    expect(calls[4]!.at - calls[3]!.at).toBeGreaterThanOrEqual(10_000);
    expect(calls[4]!.at - calls[3]!.at).toBeLessThanOrEqual(15_000);
    expect(urls[5]).toBe(`${BASE}/v1/operations/op_1?waitMs=20000`);
    expect(leftovers()).toBe(0);
  });

  it("a local deadline never cancels the server entry: the error carries sandboxId, operationId and key", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("QUEUED")),
      json(200, sandbox("WAITING_FOR_CAPACITY", { hostId: null, storageId: null })),
    );
    const error = await fails(
      client.sandboxes.create(
        { template: "base", poolId: "pool_1", waitForCapacityMs: 60_000 },
        { idempotencyKey: "queued-2", waitTimeoutMs: 50 },
      ),
    );
    expect(error).toMatchObject({
      kind: "timeout",
      sandboxId: "sbx_1",
      operationId: "op_1",
      idempotencyKey: "queued-2",
    });
    expect(calls.some((c) => c.init.method === "DELETE")).toBe(false);
  });

  it.each(["operation", "sandbox"] as const)(
    "retries a post-receipt 503 from the %s read without resubmitting",
    async (read) => {
      const { client, calls, leftovers } = harness(
        json(202, receipt()),
        ...(read === "operation" ? [envelope("SERVICE_UNAVAILABLE")] : []),
        json(200, operation("QUEUED")),
        ...(read === "sandbox" ? [envelope("SERVICE_UNAVAILABLE")] : []),
        json(200, sandbox("REQUESTED")),
        json(200, operation("SUCCEEDED")),
        json(200, sandbox("READY")),
      );
      const result = await ok(
        client.sandboxes.create(
          { template: "base", poolId: "pool_1", waitForCapacityMs: 60_000 },
          { idempotencyKey: "queued-retry" },
        ),
      );
      expect(result.state).toBe("READY");
      expect(calls.filter((call) => call.init.method === "POST")).toHaveLength(1);
      expect(calls[read === "operation" ? 2 : 3]!.at - calls[1]!.at).toBeGreaterThanOrEqual(5_000);
      expect(leftovers()).toBe(0);
    },
  );

  it.each(["operation", "sandbox"] as const)(
    "preserves receipt context when aborted during the %s read",
    async (read) => {
      const controller = new AbortController();
      const { client, calls } = harness(
        json(202, receipt()),
        ...(read === "sandbox" ? [json(200, operation("QUEUED"))] : []),
        hangs(),
      );
      const pending = client.sandboxes.create(
        { template: "base", poolId: "pool_1", waitForCapacityMs: 60_000 },
        { idempotencyKey: "queued-abort", signal: controller.signal },
      );
      await flush();
      const failed = fails(pending);
      controller.abort();
      expect(await failed).toMatchObject({
        kind: "aborted",
        operationId: "op_1",
        idempotencyKey: "queued-abort",
        sandboxId: read === "sandbox" ? "sbx_1" : null,
      });
      expect(calls).toHaveLength(read === "sandbox" ? 3 : 2);
    },
  );

  it.each(["operation", "sandbox"] as const)(
    "bounds a stalled %s read by the caller's short wait deadline",
    async (read) => {
      const { client, calls } = harness(
        json(202, receipt()),
        ...(read === "sandbox" ? [json(200, operation("QUEUED"))] : []),
        hangs(),
      );
      const started = Date.now();
      const error = await fails(
        client.sandboxes.create(
          { template: "base", poolId: "pool_1", waitForCapacityMs: 60_000 },
          { idempotencyKey: "queued-stalled", waitTimeoutMs: 50 },
        ),
      );
      expect(error).toMatchObject({
        kind: "timeout",
        operationId: "op_1",
        idempotencyKey: "queued-stalled",
        sandboxId: read === "sandbox" ? "sbx_1" : null,
      });
      expect(Date.now() - started).toBeLessThanOrEqual(75);
      expect(calls).toHaveLength(read === "sandbox" ? 3 : 2);
    },
  );

  it("preserves receipt context and a definitive read error's kind and code", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("QUEUED")),
      envelope("FORBIDDEN"),
    );
    expect(
      await fails(
        client.sandboxes.create(
          { template: "base", poolId: "pool_1", waitForCapacityMs: 60_000 },
          { idempotencyKey: "queued-forbidden" },
        ),
      ),
    ).toMatchObject({
      kind: "authorization",
      code: "FORBIDDEN",
      operationId: "op_1",
      sandboxId: "sbx_1",
      idempotencyKey: "queued-forbidden",
    });
  });

  it("isCapacityWaitTimeout identifies a server-side capacity timeout", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("QUEUED")),
      json(200, sandbox("DELETED", { hostId: null, storageId: null })),
      json(
        200,
        operation("FAILED", {
          errorCode: "capacity_wait_timeout",
          failure: { resource: "sandbox", effect: "none", reason: "disk" },
          leaseIntent: null,
        }),
      ),
    );
    const error = await fails(
      client.sandboxes.create(
        { template: "base", poolId: "pool_1", waitForCapacityMs: 1_000 },
        { idempotencyKey: "queued-3" },
      ),
    );
    expect(isCapacityWaitTimeout(error)).toBe(true);
    expect(error.reason).toBe("disk");
    expect(isCapacityWaitTimeout(new Error("x"))).toBe(false);
  });
});

describe("create", () => {
  it("resolves only once the operation succeeded AND the sandbox reads READY", async () => {
    const { client, calls, leftovers } = harness(
      json(202, receipt()),
      json(200, operation("QUEUED")),
      json(200, operation("RUNNING")),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("PROVISIONING")),
      json(200, sandbox("READY")),
    );
    const result = await ok(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-1" },
      ),
    );
    expect(result.state).toBe("READY");
    expect(result.id).toBe("sbx_1");
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      `POST ${BASE}/v1/sandboxes`,
      // Operation reads are long-polls (default 20 s hold); sandbox reads are not.
      `GET ${BASE}/v1/operations/op_1?waitMs=20000`,
      `GET ${BASE}/v1/operations/op_1?waitMs=20000`,
      `GET ${BASE}/v1/operations/op_1?waitMs=20000`,
      `GET ${BASE}/v1/sandboxes/sbx_1`,
      `GET ${BASE}/v1/sandboxes/sbx_1`,
    ]);
    expect(leftovers()).toBe(0);
  });

  it("recovers a lost create response under the same idempotency key", async () => {
    const { client, calls } = harness(
      () => Promise.reject(new TypeError("socket hang up")),
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
    );
    const input = { template: "revision/" + "tpl_1", sandboxHostId: "host_1" };
    const result = await ok(client.sandboxes.create(input, { idempotencyKey: "create-lost" }));
    expect(result.state).toBe("READY");
    const posts = calls.filter((c) => c.init.method === "POST");
    expect(posts).toHaveLength(2);
    expect(idempotencyKeys(posts)).toEqual(["create-lost", "create-lost"]);
    expect(callAt(posts, 0).init.body).toBe(callAt(posts, 1).init.body);
  });

  it("recovers 429 and 503 submissions, honoring Retry-After", async () => {
    const { client, calls } = harness(
      envelope("TOO_MANY_REQUESTS", { retryAfterSeconds: 5 }),
      envelope("SERVICE_UNAVAILABLE"),
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
    );
    const result = await ok(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-rl" },
      ),
    );
    expect(result.state).toBe("READY");
    const t0 = callAt(calls, 0).at;
    expect(callAt(calls, 1).at - t0).toBe(5_000); // Retry-After beats the 100 ms interval
    expect(callAt(calls, 2).at - t0).toBe(5_200); // plain backoff: interval doubled to 200 ms
    expect(idempotencyKeys(calls.slice(0, 3))).toEqual(["create-rl", "create-rl", "create-rl"]);
  });

  it("waits out a host reconnect (503 sandbox.host_reconnecting) under the same key", async () => {
    const reconnecting = () => envelope("sandbox.host_reconnecting", { retryAfterSeconds: 1 });
    const { client, calls } = harness(
      reconnecting(),
      reconnecting(),
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
    );
    const result = await ok(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-reconnect" },
      ),
    );
    expect(result.state).toBe("READY");
    const t0 = callAt(calls, 0).at;
    expect(callAt(calls, 1).at - t0).toBe(1_000); // Retry-After beats the 100 ms interval
    expect(callAt(calls, 2).at - t0).toBe(2_000);
    expect(idempotencyKeys(calls.slice(0, 3))).toEqual([
      "create-reconnect",
      "create-reconnect",
      "create-reconnect",
    ]);
  });

  it("reports a reconnect that outlasts the wait as the definitive refusal, not unknown", async () => {
    const reconnecting = () => envelope("sandbox.host_reconnecting", { retryAfterSeconds: 1 });
    const { client, calls } = harness(...Array.from({ length: 20 }, reconnecting));
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-reconnect-deadline", waitTimeoutMs: 3_500 },
      ),
    );
    expect(error).toMatchObject({
      kind: "unavailable",
      code: "sandbox.host_reconnecting",
      status: 503,
    });
    expect(calls.length).toBeGreaterThan(1);
    expect(calls.length).toBeLessThan(6);
  });

  it.each(["sandbox.host_capacity", "sandbox.pool_full"] as const)(
    "create_capacity_refusal_is_not_retried: %s",
    async (code) => {
      const { client, calls } = harness(envelope(code));
      const error = await fails(
        client.sandboxes.create(
          {
            template: "revision/tpl_1",
            ...(code === "sandbox.pool_full" ? { poolId: "pool_1" } : { sandboxHostId: "host_1" }),
          },
          { idempotencyKey: "capacity-refusal" },
        ),
      );
      expect(error).toMatchObject({ kind: "capacity", code, status: 409 });
      expect(calls).toHaveLength(1);
    },
  );

  it("create_pool_unavailable_is_not_retried", async () => {
    const { client, calls } = harness(envelope("sandbox.pool_unavailable"));
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/tpl_1", poolId: "pool_1" },
        { idempotencyKey: "unavailable-refusal" },
      ),
    );
    expect(error).toMatchObject({
      kind: "unavailable",
      code: "sandbox.pool_unavailable",
      status: 409,
    });
    expect(calls).toHaveLength(1);
  });

  it.each([
    ["sandbox.vm_size_invalid", 400, "invalid_request"],
    ["sandbox.vm_size_unsupported", 409, "unsupported"],
    ["sandbox.vm_size_mismatch", 409, "conflict"],
    ["sandbox.share_quota", 409, "conflict"],
    ["sandbox.member_quota", 409, "conflict"],
    ["sandbox.pool_policy_changed", 409, "conflict"],
  ] as const)("never retries a definitive %s create refusal", async (code, status, kind) => {
    const retryOwner = vi.spyOn(await import("./polling"), "poll");
    try {
      // Keep returning fresh refusals so an accidental retry cannot hide
      // behind fixture exhaustion. This still exercises the real polling loop.
      const refusal = () => envelope(code, { message: "private-remote-sentinel" });
      const { client, calls } = harness(...Array.from({ length: 100 }, () => refusal));
      const error = await fails(
        client.sandboxes.create(
          { template: "revision/tpl_1", sandboxHostId: "host_1" },
          { idempotencyKey: "size-error", waitTimeoutMs: 1000 },
        ),
      );
      expect(calls).toHaveLength(1);
      expect(error).toMatchObject({ code, status, kind });
      expect(JSON.stringify(error)).not.toContain("private-remote-sentinel");
      expect(error.message).not.toContain("private-remote-sentinel");
      expect(retryOwner).toHaveBeenCalledTimes(1);
      const submission = retryOwner.mock.calls[0];
      expect(submission?.[5]).toMatchObject({ submission: true });
      // poll's separate definitive-4xx fence currently short-circuits retryOn.
      // Also assert the actual consumer's policy, so widening submitMutation
      // alone fails even while that independent fence still protects fetches.
      expect(submission?.[4]?.(error)).toBe(false);
    } finally {
      retryOwner.mockRestore();
    }
  });

  it("never retries an UNKNOWN_OUTCOME, and exposes the operation and key", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("UNKNOWN_OUTCOME", { errorCode: "unknown_outcome" })),
    );
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-unknown" },
      ),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toBe("create-unknown");
    expect(error.operationErrorCode).toBe("unknown_outcome");
    expect(calls).toHaveLength(2);
  });

  it("names the node daemon restart when a create FAILED with unknown_outcome (E3B-02)", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("FAILED", { errorCode: "unknown_outcome" })),
    );
    const error = await fails(
      client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" }),
    );
    expect(error.kind).toBe("unknown");
    expect(error.operationErrorCode).toBe("unknown_outcome");
    expect(error.message).toMatch(
      /failed \(unknown_outcome\): the node daemon could not confirm a result \(it restarted or lost its connection mid-operation\)/,
    );
  });

  it.each([
    ["host_capacity", "capacity"],
    ["sandbox.template_image_missing", "conflict"],
    ["host_effect_not_issued", "unavailable"],
    ["host_disconnect_expired", "unavailable"],
    ["vm_size_mismatch", "conflict"],
    ["egress_resolution_failed", "invalid_request"],
  ] as const)("maps a FAILED %s operation to %s without retrying", async (code, kind) => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("FAILED", { errorCode: code })),
    );
    const error = await fails(
      client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" }),
    );
    expect(error.kind).toBe(kind);
    expect(error.operationErrorCode).toBe(code);
    expect(error.code).toBe(code);
    expect(error.toJSON().code).toBe(code);
    expect(error.operationId).toBe("op_1");
    expect(calls).toHaveLength(2);
  });
});

it("a FAILED host_disconnect_expired says the node stopped the work at its carry limit", async () => {
  const { client } = harness(
    json(202, receipt()),
    json(200, operation("FAILED", { errorCode: "host_disconnect_expired" })),
  );
  const error = await fails(
    client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" }),
  );
  expect(error.kind).toBe("unavailable");
  expect(error.message).toContain("past its carry limit");
});

it("a FAILED guest_unavailable names the failed readiness check", async () => {
  const { client } = harness(
    json(202, receipt()),
    json(
      200,
      operation("FAILED", { errorCode: "guest_unavailable", readinessReason: "guest_user" }),
    ),
  );
  const error = await fails(
    client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" }),
  );
  expect(error.kind).toBe("unavailable");
  expect(error.message).toContain("readiness check guest_user failed");
});

it("unknown future operation codes produce a generic typed failure without retrying", async () => {
  const { client, calls } = harness(
    json(202, receipt()),
    json(200, operation("FAILED", { errorCode: "sandbox.future_private_diagnostic" })),
  );
  const error = await fails(
    client.sandboxes.create({ template: "revision/tpl_1", sandboxHostId: "host_1" }),
  );
  expect(error.kind).toBe("unavailable");
  expect(error.operationErrorCode).toBe("internal");
  expect(error.operationId).toBe("op_1");
  expect(error.message).not.toContain("future_private_diagnostic");
  expect(calls).toHaveLength(2);
});
it("unknown future receipt codes produce a generic typed failure without retrying", async () => {
  const { client, calls } = harness(
    json(202, receipt("op_p1")),
    json(
      200,
      probe(null, {
        state: "FAILED",
        outcome: "failed",
        errorCode: "sandbox.future_private_diagnostic",
        observation: null,
      }),
    ),
  );
  const error = await fails(client.sandboxes.isAlive("sbx_1"));
  expect(error.kind).toBe("unavailable");
  expect(error.operationErrorCode).toBe("INTERNAL_SERVER_ERROR");
  expect(calls).toHaveLength(2);
});
it("forward-compatible error codes do not relax the rest of an operation", async () => {
  const { client } = harness(
    json(200, operation("FAILED", { errorCode: "future_code", extra: "unexpected" })),
  );
  const error = await fails(client.operations.wait("op_1"));
  expect(error.kind).toBe("protocol");
});

describe("operation waits", () => {
  it("operations.wait resolves the terminal record even when failed", async () => {
    const { client } = harness(json(200, operation("FAILED", { errorCode: "timeout" })));
    const result = await ok(client.operations.wait("op_1"));
    expect(result.outcome).toBe("failed");
  });

  it("honors Retry-After while polling an operation", async () => {
    const { client, calls } = harness(
      envelope("TOO_MANY_REQUESTS", { retryAfterSeconds: 3 }),
      json(200, operation("SUCCEEDED")),
    );
    const result = await ok(client.operations.wait("op_1"));
    expect(result.state).toBe("SUCCEEDED");
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(3_000);
  });

  it.each(["TOO_MANY_REQUESTS", "TRANSFER_QUOTA", "OPERATION_RESULT_QUOTA"] as const)(
    "%s waits out same-request 429s and preserves capacity at the deadline",
    async (code) => {
      const { client, calls } = harness(
        ...Array.from({ length: 4 }, () => () => envelope(code, { retryAfterSeconds: 1 })),
      );
      // longPollMs 0: every retry is the identical plain read.
      const error = await fails(
        client.operations.wait("op_1", { waitTimeoutMs: 2500, longPollMs: 0 }),
      );
      expect(error).toMatchObject({
        kind: "capacity",
        code,
        status: 429,
        retryAfterSeconds: 1,
        operationId: "op_1",
      });
      expect(calls).toHaveLength(3);
      expect(calls.map((c) => c.url)).toEqual([
        callAt(calls, 0).url,
        callAt(calls, 0).url,
        callAt(calls, 0).url,
      ]);
      expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(1000);
    },
  );

  it("honors a header-only Retry-After on a proxy 503", async () => {
    const { client, calls } = harness(
      new Response("<html>Service Unavailable</html>", {
        status: 503,
        headers: { "content-type": "text/html", "retry-after": "3" },
      }),
      json(200, operation("SUCCEEDED")),
    );
    await ok(client.operations.wait("op_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(3_000);
  });

  it("honors the HTTP-date Retry-After form", async () => {
    const at = new Date(Date.now() + 4_000).toUTCString();
    const { client, calls } = harness(
      new Response("<html>Service Unavailable</html>", {
        status: 503,
        headers: { "content-type": "text/html", "retry-after": at },
      }),
      json(200, operation("SUCCEEDED")),
    );
    await ok(client.operations.wait("op_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(4_000);
  });

  it("honors a header-only 429 while polling an operation", async () => {
    const { client, calls } = harness(
      new Response("<html>Too Many Requests</html>", {
        status: 429,
        headers: { "content-type": "text/html", "retry-after": "3" },
      }),
      json(200, operation("SUCCEEDED")),
    );
    await ok(client.operations.wait("op_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(3_000);
  });

  it("honors a header-only 429 while polling readiness", async () => {
    const { client, calls } = harness(
      new Response("<html>Too Many Requests</html>", {
        status: 429,
        headers: { "content-type": "text/html", "retry-after": "2" },
      }),
      json(200, sandbox("READY")),
    );
    await ok(client.sandboxes.waitReady("sbx_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(2_000);
  });

  it("ignores an out-of-range Retry-After header", async () => {
    const { client, calls } = harness(
      new Response("<html>Service Unavailable</html>", {
        status: 503,
        headers: { "content-type": "text/html", "retry-after": "99999999" },
      }),
      json(200, operation("SUCCEEDED")),
    );
    await ok(client.operations.wait("op_1"));
    // Falls back to the 100 ms poll interval, not a 3-year sleep.
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(100);
  });

  it("polls with a bounded exponential interval", async () => {
    const { client, calls } = harness(
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("SUCCEEDED")),
    );
    await ok(client.operations.wait("op_1", { intervalMs: 100, maxIntervalMs: 250 }));
    const deltas = calls.slice(1).map((c, i) => c.at - callAt(calls, i).at);
    expect(deltas).toEqual([100, 200, 250, 250]);
  });

  it("aborts a wait and exposes the operation ID", async () => {
    const { client, calls } = harness(
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
    );
    const controller = new AbortController();
    const promise = client.operations.wait("op_1", { signal: controller.signal });
    await vi.advanceTimersByTimeAsync(0);
    controller.abort();
    const settled = await drive(promise);
    expect(settled.error).toBeInstanceOf(WsspError);
    const error = settled.error as WsspError;
    expect(error.kind).toBe("aborted");
    expect(error.operationId).toBe("op_1");
    expect(calls).toHaveLength(1);
  });

  it("times out a wait and exposes the operation ID", async () => {
    const { client } = harness(
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
      json(200, operation("QUEUED")),
    );
    const error = await fails(client.operations.wait("op_1", { waitTimeoutMs: 1_000 }));
    expect(error.kind).toBe("timeout");
    expect(error.operationId).toBe("op_1");
  });
});

describe("stop and destroy", () => {
  it("stop waits until the recorded state is STOPPED", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "STOP_SANDBOX" })),
      json(200, sandbox("STOPPING")),
      json(200, sandbox("STOPPED")),
    );
    const result = await ok(client.sandboxes.stop("sbx_1"));
    expect(result.state).toBe("STOPPED");
  });

  it("stop sends the offload policy in its body only when given", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "STOP_SANDBOX" })),
      json(200, sandbox("STOPPED")),
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "STOP_SANDBOX" })),
      json(200, sandbox("STOPPED")),
    );
    await ok(client.sandboxes.stop("sbx_1", { offload: { mode: "on_pressure" } }));
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({
      offload: { mode: "on_pressure" },
    });
    await ok(client.sandboxes.stop("sbx_1"));
    expect(JSON.parse(String(callAt(calls, 3).init.body))).toEqual({});
  });

  it("stop during boot with no instance succeeds with DELETED", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "STOP_SANDBOX" })),
      json(200, sandbox("DELETED")),
    );
    const result = await ok(client.sandboxes.stop("sbx_1", { idempotencyKey: "boot-stop" }));
    expect(result.state).toBe("DELETED");
    expect(calls).toHaveLength(3);
  });

  it("stop accepts a confirmed deletion as a terminal stop", async () => {
    // The host can report a stop result of `absent`; the server records the
    // sandbox DELETED whether or not it ever started.
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "STOP_SANDBOX" })),
      json(200, sandbox("DELETED")),
    );
    const result = await ok(client.sandboxes.stop("sbx_1"));
    expect(result.state).toBe("DELETED");
  });

  it("destroy resolves only on the confirmed DELETED state", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "KILL_SANDBOX" })),
      json(200, sandbox("RECLAIMING")),
      json(200, sandbox("DELETED")),
    );
    await ok(client.sandboxes.destroy("sbx_1"));
    expect(callAt(calls, 0).init.method).toBe("DELETE");
    // It must NOT have resolved at the RECLAIMING read.
    expect(calls).toHaveLength(4);
  });

  it("destroy also accepts a confirmed not-found as deletion", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "KILL_SANDBOX" })),
      envelope("sandbox.not_found"),
    );
    await ok(client.sandboxes.destroy("sbx_1"));
  });

  it("fails the wait when the sandbox reaches a dead state", async () => {
    const { client } = harness(json(200, sandbox("PROVISIONING")), json(200, sandbox("ERROR")));
    const error = await fails(client.sandboxes.waitReady("sbx_1"));
    expect(error.kind).toBe("unavailable");
    expect(error.message).toContain("ERROR");
  });
});

describe("connect", () => {
  it("reports a cold reconnect and waits for READY", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX", generation: 2 })),
      json(200, sandbox("STOPPED", { generation: 2 })),
      json(200, sandbox("READY", { generation: 2 })),
    );
    const result = await ok(client.sandboxes.connect("sbx_1", { mode: "cold" }));
    expect(typeof result.connect).toBe("function");
    expect(result.state).toBe("READY");
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({ mode: "cold" });
  });

  it("defaults to a warm reconnect", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX" })),
      json(200, sandbox("READY")),
    );
    const result = await ok(client.sandboxes.connect("sbx_1"));
    expect(typeof result.connect).toBe("function");
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({});
  });
});

describe("setTimeout (accepted lease intent)", () => {
  it("exact-intent waiter completes despite a later shortening", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RENEW_SANDBOX_LEASE" })),
      json(
        200,
        sandbox("READY", {
          lease: {
            revision: 2,
            expiresAt: NOW,
            onExpire: "stop",
            requested: { expiresAt: NOW, onExpire: "stop" },
            effective: { expiresAt: NOW, onExpire: "stop" },
          },
        }),
      ),
    );
    const result = await ok(client.sandboxes.setTimeout("sbx_1", { timeoutMs: 300000 }));
    expect(result.effective).toEqual({ expiresAt: T1, onExpire: "destroy" });
    expect(result.sandbox.lease.revision).toBe(2);
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({ timeoutMs: 300000 });
    expect(calls).toHaveLength(3);
  });

  it.each([
    null,
    {
      acceptedAt: NOW,
      timeoutMs: 300000,
      revision: 1,
      endAt: T1,
      onTimeout: "kill",
      acknowledgedAt: null,
      acknowledgedAttempt: null,
      acknowledgedEpoch: null,
    },
  ])("requires durable exact intent ACK rather than just success", async (leaseIntent) => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RENEW_SANDBOX_LEASE", leaseIntent })),
    );
    const error = await fails(client.sandboxes.setTimeout("sbx_1", { timeoutMs: 300000 }));
    expect(error.kind).toBe("protocol");
  });

  it.each(["STOPPING", "STOPPED", "RECLAIMING", "DELETED", "ERROR", "HOST_LOST"] as const)(
    "succeeds from the ACK when expiry has already advanced to %s",
    async (state) => {
      const { client, calls } = harness(
        json(202, receipt()),
        json(200, operation("SUCCEEDED", { kind: "RENEW_SANDBOX_LEASE" })),
        json(200, sandbox(state, { generation: 2 })),
      );
      const result = await ok(client.sandboxes.setTimeout("sbx_1", { timeoutMs: 1 }));
      expect(result.effective).toEqual({ expiresAt: T1, onExpire: "destroy" });
      expect(result.sandbox).toMatchObject({ state, generation: 2 });
      expect(calls).toHaveLength(3);
    },
  );

  it("still checks the sandbox snapshot identity after the lease ACK", async () => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RENEW_SANDBOX_LEASE" })),
      json(200, sandbox("READY", { id: "other-sandbox" })),
    );
    const error = await fails(client.sandboxes.setTimeout("sbx_1", { timeoutMs: 1 }));
    expect(error.kind).toBe("protocol");
  });
});

describe("isAlive", () => {
  it("returns true when the host probe observes guest_ready", async () => {
    const { client } = harness(json(202, receipt("op_p1")), json(200, probe("guest_ready")));
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(true);
  });

  it("returns false for a confirmed stopped observation", async () => {
    const { client } = harness(json(202, receipt("op_p1")), json(200, probe("stopped")));
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
  });

  it("returns false for a confirmed absent observation", async () => {
    const { client } = harness(json(202, receipt("op_p1")), json(200, probe("confirmed_absent")));
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
  });

  it("throws a typed unavailable error when the host is unreachable", async () => {
    // The server records an unreachable probe as UNKNOWN_OUTCOME; the sandbox
    // record still shows a live placement, so this is NOT absence.
    const { client } = harness(
      json(202, receipt("op_p1")),
      json(200, probe("unreachable", { state: "UNKNOWN_OUTCOME", outcome: "unknown" })),
      json(200, sandbox("READY")),
    );
    const error = await fails(client.sandboxes.isAlive("sbx_1"));
    expect(error.kind).toBe("unavailable");
    expect(error.operationId).toBe("op_p1");
    expect(error.message).toContain("unreachable");
  });

  it("returns false when an unreachable probe matches a DELETED tombstone", async () => {
    const { client } = harness(
      json(202, receipt("op_p1")),
      json(200, probe("unreachable", { state: "UNKNOWN_OUTCOME", outcome: "unknown" })),
      json(200, sandbox("DELETED")),
    );
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
  });

  it("bounds a stalled tombstone lookup by the wait deadline", async () => {
    const { client } = harness(
      json(202, receipt("op_p1")),
      json(200, probe("unreachable", { state: "UNKNOWN_OUTCOME", outcome: "unknown" })),
      hangs(),
    );
    const start = Date.now();
    const error = await fails(
      client.sandboxes.isAlive("sbx_1", { idempotencyKey: "probe-dl", waitTimeoutMs: 1_000 }),
    );
    expect(error.kind).toBe("timeout");
    expect(error.operationId).toBe("op_p1");
    expect(error.idempotencyKey).toBe("probe-dl");
    // The stalled lookup is cut at the deadline, not at the 30 s transport timeout.
    expect(Date.now() - start).toBe(1_000);
  });

  it("aborts a stalled tombstone lookup with the probe's operation ID", async () => {
    const { client, calls } = harness(
      json(202, receipt("op_p1")),
      json(200, probe("unreachable", { state: "UNKNOWN_OUTCOME", outcome: "unknown" })),
      hangs(),
    );
    const controller = new AbortController();
    const promise = client.sandboxes.isAlive("sbx_1", { signal: controller.signal });
    await flush();
    expect(calls).toHaveLength(3);
    const abortedAt = Date.now();
    controller.abort();
    const settled = await drive(promise);
    const error = settled.error as WsspError;
    expect(error.kind).toBe("aborted");
    expect(error.operationId).toBe("op_p1");
    expect(Date.now() - abortedAt).toBeLessThanOrEqual(25);
  });

  it("returns false for isAlive after destroy (tombstone probes unreachable)", async () => {
    const { client } = harness(
      json(202, receipt("op_d1")),
      json(200, operation("SUCCEEDED", { id: "op_d1", kind: "KILL_SANDBOX" })),
      json(200, sandbox("DELETED")),
      json(202, receipt("op_p1")),
      json(200, probe("unreachable", { state: "UNKNOWN_OUTCOME", outcome: "unknown" })),
      json(200, sandbox("DELETED")),
    );
    await ok(client.sandboxes.destroy("sbx_1"));
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
  });

  it("returns false when the probe admission confirms the sandbox is gone", async () => {
    const { client, calls } = harness(envelope("sandbox.not_found"));
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
    expect(calls).toHaveLength(1);
  });

  it("returns false when the probe receipt fails as confirmed gone", async () => {
    const { client } = harness(
      json(202, receipt("op_p1")),
      json(
        200,
        probe(null, {
          state: "FAILED",
          outcome: "failed",
          errorCode: "sandbox.not_found",
          observation: null,
        }),
      ),
    );
    await expect(ok(client.sandboxes.isAlive("sbx_1"))).resolves.toBe(false);
  });
});

describe("the deadline bounds every attempt", () => {
  it("cancels a slow in-flight request at the wait deadline", async () => {
    const { client, calls } = harness(hangs());
    const start = Date.now();
    const error = await fails(client.operations.wait("op_1", { waitTimeoutMs: 1_000 }));
    expect(error.kind).toBe("timeout");
    expect(error.operationId).toBe("op_1");
    // 30 s of transport patience is cut at the 1 s wait deadline.
    expect(Date.now() - start).toBe(1_000);
    expect(calls).toHaveLength(1);
  });

  it("does not fire another mutation after sleeping to the deadline", async () => {
    const { client, calls } = harness(
      () => Promise.reject(new TypeError("socket hang up")),
      () => Promise.reject(new TypeError("socket hang up")),
      // A third POST would fail the harness as an unexpected call.
    );
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-dl", waitTimeoutMs: 150 },
      ),
    );
    // The deadline expired mid-backoff AFTER an uncertain attempt: the lost
    // submission may have reached the server, so this is `unknown`, not a
    // plain `timeout` a caller could mistake for safely retryable.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    expect(error.idempotencyKey).toBe("create-dl");
    expect(calls.filter((c) => c.init.method === "POST")).toHaveLength(2);
  });

  it("keeps the outcome unknown when recovery fails with a definitive error", async () => {
    const { client, calls } = harness(
      // Attempt 1: the response is lost; the create may have been accepted.
      () => Promise.reject(new TypeError("socket hang up")),
      // Attempt 2 (same key): the SDK key has expired — a definitive 401.
      envelope("UNAUTHORIZED"),
    );
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-401" },
      ),
    );
    // The original allocation is still unresolved: unknown, not authorization.
    expect(error.kind).toBe("unknown");
    expect(error.code).toBe("UNAUTHORIZED");
    expect(error.idempotencyKey).toBe("create-401");
    // Authorization failures are not auto-retried: exactly two attempts.
    expect(calls.filter((c) => c.init.method === "POST")).toHaveLength(2);
    expect(idempotencyKeys(calls.filter((c) => c.init.method === "POST"))).toEqual([
      "create-401",
      "create-401",
    ]);
  });

  it("preserves submission uncertainty when aborted during retry backoff", async () => {
    const { client, calls } = harness(
      // Attempt 1: the response is lost; the request may have reached the server.
      () => Promise.reject(new TypeError("socket hang up")),
      hangs(),
    );
    const controller = new AbortController();
    const promise = client.sandboxes.create(
      { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
      { idempotencyKey: "create-backoff", signal: controller.signal },
    );
    await flush();
    expect(calls).toHaveLength(1);
    // Abort during the 100 ms backoff sleep, before any retry is sent.
    controller.abort();
    const settled = await drive(promise);
    const error = settled.error as WsspError;
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe("create-backoff");
    expect(calls).toHaveLength(1);
  });

  it("rejects a terminal answer that arrives past the deadline", async () => {
    // fn ignores the attempt signal and answers at 1.5 s; the 1 s wait must
    // still fail rather than accept the late success.
    const late = () =>
      new Promise<{ done: true; value: number }>((resolve) =>
        setTimeout(() => resolve({ done: true, value: 1 }), 1_500),
      );
    const start = Date.now();
    const error = await fails(
      poll(late, resolvePolling(undefined, { waitTimeoutMs: 1_000 }), undefined, { label: "unit" }),
    );
    expect(error.kind).toBe("timeout");
    // The wait settles AT the deadline, not when the callback finishes.
    expect(Date.now() - start).toBe(1_000);
  });

  it("settles at the deadline even when the callback never settles", async () => {
    const start = Date.now();
    const error = await fails(
      poll(
        // Ignores the attempt signal and never resolves or rejects.
        () => new Promise<{ done: true; value: number }>(() => {}),
        resolvePolling(undefined, { waitTimeoutMs: 1_000 }),
        undefined,
        { label: "unit" },
      ),
    );
    expect(error.kind).toBe("timeout");
    expect(Date.now() - start).toBe(1_000);
  });

  it("settles a never-settling submission at the deadline as unknown", async () => {
    const start = Date.now();
    const error = await fails(
      poll(
        () => new Promise<{ done: true; value: number }>(() => {}),
        resolvePolling(undefined, { waitTimeoutMs: 1_000 }),
        undefined,
        { label: "unit submission", idempotencyKey: "sub-1" },
        undefined,
        { submission: true },
      ),
    );
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    expect(error.idempotencyKey).toBe("sub-1");
    expect(Date.now() - start).toBe(1_000);
  });

  it("settles a never-settling callback promptly when aborted", async () => {
    const controller = new AbortController();
    const promise = poll(
      () => new Promise<{ done: true; value: number }>(() => {}),
      resolvePolling(undefined, { waitTimeoutMs: 60_000 }),
      controller.signal,
      { label: "unit" },
    );
    await flush();
    const abortedAt = Date.now();
    controller.abort();
    const settled = await drive(promise);
    expect((settled.error as WsspError).kind).toBe("aborted");
    expect(Date.now() - abortedAt).toBeLessThanOrEqual(25);
  });

  it("a timed-out accepted create recovers under its returned key", async () => {
    const input = { template: "revision/" + "tpl_1", sandboxHostId: "host_1" };
    const first = harness(hangs());
    const error = await fails(first.client.sandboxes.create(input, { waitTimeoutMs: 1_000 }));
    // The submission may have reached the server: unknown, not plain timeout.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    if (error.idempotencyKey === null) throw new Error("the timeout must carry the key");
    const key = error.idempotencyKey;
    const second = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
    );
    const result = await ok(second.client.sandboxes.create(input, { idempotencyKey: key }));
    expect(result.state).toBe("READY");
    // One key, replayed: the server returns the original receipt, so the
    // accepted create never allocates a second VM.
    expect(idempotencyKeys(second.calls.filter((c) => c.init.method === "POST"))).toEqual([key]);
  });
});

describe("read timeouts", () => {
  it("bounds a stalled get by waitTimeoutMs", async () => {
    const { client } = harness(hangs());
    const start = Date.now();
    const error = await fails(client.sandboxes.get("sbx_1", { waitTimeoutMs: 100 }));
    expect(error.kind).toBe("timeout");
    expect(Date.now() - start).toBe(100);
  });

  it("bounds a stalled find by timeoutMs", async () => {
    const { client } = harness(hangs());
    const start = Date.now();
    const error = await fails(client.sandboxes.find("sbx_1", { waitTimeoutMs: 100 }));
    expect(error.kind).toBe("timeout");
    expect(Date.now() - start).toBe(100);
  });

  it("bounds a stalled list by timeoutMs", async () => {
    const { client } = harness(hangs());
    const start = Date.now();
    const error = await fails(client.sandboxes.list({}, { waitTimeoutMs: 100 }));
    expect(error.kind).toBe("timeout");
    expect(Date.now() - start).toBe(100);
  });

  it("bounds a stalled operations.get by waitTimeoutMs", async () => {
    const { client } = harness(hangs());
    const start = Date.now();
    const error = await fails(client.operations.get("op_1", { waitTimeoutMs: 100 }));
    expect(error.kind).toBe("timeout");
    expect(Date.now() - start).toBe(100);
  });
});

describe("cancellation during network IO", () => {
  it("aborts an in-flight create submission", async () => {
    const { client, calls } = harness(hangs());
    const controller = new AbortController();
    const promise = client.sandboxes.create(
      { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
      { idempotencyKey: "create-abort", signal: controller.signal },
    );
    await flush();
    expect(calls).toHaveLength(1);
    const abortedAt = Date.now();
    controller.abort();
    const settled = await drive(promise);
    const error = settled.error as WsspError;
    expect(error).toBeInstanceOf(WsspError);
    // The submission may have reached the server: kind `unknown` with the
    // abort as the reason, so nobody retries under a fresh key by mistake.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("aborted");
    expect(error.idempotencyKey).toBe("create-abort");
    expect(error.operationId).toBeNull();
    expect(calls).toHaveLength(1);
    // The in-flight request is cancelled, not ridden out to a transport timeout.
    expect(Date.now() - abortedAt).toBeLessThanOrEqual(25);
  });

  it("a create submission cut at the deadline reports an unknown outcome", async () => {
    const { client, calls } = harness(hangs());
    const start = Date.now();
    const error = await fails(
      client.sandboxes.create(
        { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
        { idempotencyKey: "create-dl", waitTimeoutMs: 1_000 },
      ),
    );
    // The request may have reached the server: unknown, carrying the key.
    expect(error.kind).toBe("unknown");
    expect(error.reason).toBe("timeout");
    expect(error.idempotencyKey).toBe("create-dl");
    expect(error.operationId).toBeNull();
    expect(Date.now() - start).toBe(1_000);
    expect(calls).toHaveLength(1);
  });

  it("aborts an in-flight operation poll with the operation ID", async () => {
    const { client } = harness(hangs());
    const controller = new AbortController();
    const promise = client.operations.wait("op_1", { signal: controller.signal });
    await flush();
    const abortedAt = Date.now();
    controller.abort();
    const settled = await drive(promise);
    const error = settled.error as WsspError;
    expect(error.kind).toBe("aborted");
    expect(error.operationId).toBe("op_1");
    expect(Date.now() - abortedAt).toBeLessThanOrEqual(25);
  });

  it("aborts an in-flight readiness read after create was accepted", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      hangs(),
    );
    const controller = new AbortController();
    const promise = client.sandboxes.create(
      { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
      { idempotencyKey: "create-abort-ready", signal: controller.signal },
    );
    await flush();
    expect(calls).toHaveLength(3);
    const abortedAt = Date.now();
    controller.abort();
    const settled = await drive(promise);
    const error = settled.error as WsspError;
    expect(error.kind).toBe("aborted");
    expect(error.operationId).toBe("op_1");
    expect(error.idempotencyKey).toBe("create-abort-ready");
    expect(Date.now() - abortedAt).toBeLessThanOrEqual(25);
  });
});

describe("connect option separation", () => {
  it("waitTimeoutMs stays the wait budget and never enters the body", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX" })),
      json(200, sandbox("READY")),
    );
    await ok(client.sandboxes.connect("sbx_1", { mode: "cold", waitTimeoutMs: 5_000 }));
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({ mode: "cold" });
  });

  it("rejects both wait names on lifecycle helpers before submission", async () => {
    const { client, calls } = harness();
    const options = { waitTimeoutMs: 1000, timeoutMs: 1000 };
    for (const call of [
      () => client.sandboxes.connect("sbx_1", options),
      () =>
        client.sandboxes.create({ template: "revision/tpl_1", sandboxHostId: "host_1" }, options),
      () => client.sandboxes.setTimeout("sbx_1", { timeoutMs: 1000 }, options),
    ]) {
      expect((await fails(call())).kind).toBe("invalid_request");
    }
    expect(calls).toHaveLength(0);
  });

  it("leaseTimeoutMs arms the guest lease, beyond the wait budget's maximum", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX" })),
      json(200, sandbox("READY")),
    );
    const result = await ok(client.sandboxes.connect("sbx_1", { leaseTimeoutMs: 7_200_000 }));
    expect(typeof result.connect).toBe("function");
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({
      timeoutMs: 7_200_000,
    });
  });
});

describe("client polling defaults survive into state waits", () => {
  // The harness client's defaults are 100 ms → 400 ms; the SDK fallback is
  // 250 ms → 2 s. A regression shows the fallback deltas instead.
  it("waitReady polls at the client default interval", async () => {
    const { client, calls } = harness(
      json(200, sandbox("PROVISIONING")),
      json(200, sandbox("READY")),
    );
    await ok(client.sandboxes.waitReady("sbx_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(100);
  });

  it("waitDeleted polls at the client default interval", async () => {
    const { client, calls } = harness(
      json(200, sandbox("RECLAIMING")),
      json(200, sandbox("DELETED")),
    );
    await ok(client.sandboxes.waitDeleted("sbx_1"));
    expect(callAt(calls, 1).at - callAt(calls, 0).at).toBe(100);
  });

  it("the renewal receipt wait polls at the client default interval", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("DISPATCHED", { kind: "RENEW_SANDBOX_LEASE" })),
      json(200, operation("SUCCEEDED", { kind: "RENEW_SANDBOX_LEASE" })),
      json(200, sandbox("STOPPING", { generation: 2 })),
    );
    await ok(client.sandboxes.setTimeout("sbx_1", { timeoutMs: 300000 }));
    expect(callAt(calls, 2).at - callAt(calls, 1).at).toBe(100);
  });

  it("a maxIntervalMs-only override inherits the client interval", async () => {
    const { client, calls } = harness(
      json(200, sandbox("PROVISIONING")),
      json(200, sandbox("PROVISIONING")),
      json(200, sandbox("READY")),
    );
    await ok(client.sandboxes.waitReady("sbx_1", { maxIntervalMs: 200 }));
    const deltas = calls.slice(1).map((c, i) => c.at - callAt(calls, i).at);
    expect(deltas).toEqual([100, 200]);
  });
});

describe("reads", () => {
  it("get, find and list pass through the transport", async () => {
    const page = { items: [sandbox("READY")], nextCursor: null };
    const { client } = harness(
      json(200, sandbox("READY")),
      envelope("sandbox.not_found"),
      json(200, page),
    );
    const got = await ok(client.sandboxes.get("sbx_1"));
    expect(got.state).toBe("READY");
    const missing = await ok(client.sandboxes.find("sbx_2"));
    expect(missing).toBeNull();
    const listed = await ok(client.sandboxes.list({ limit: 20 }));
    expect(listed.items).toHaveLength(1);
    expect(isWsspError(new WsspError({ kind: "unknown", message: "x" }), "unknown")).toBe(true);
  });

  it("a DELETED sandbox stays distinct from not-found", async () => {
    const { client } = harness(json(200, sandbox("DELETED")));
    const found = await ok(client.sandboxes.find("sbx_1"));
    expect((found as SandboxDto).state).toBe("DELETED");
  });
});

describe("3C1 bound handles and environment absence", () => {
  const sentinel = "s3c1-workload-value-never-retained";

  it("returns ID-bound create/connect handles without retaining the input; siblings keep their option names", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY")),
      json(200, sandbox("READY")),
      json(202, receipt("reconnect")),
      json(200, operation("SUCCEEDED", { id: "reconnect", kind: "RECONNECT_SANDBOX" })),
      json(200, sandbox("READY")),
    );
    const input = {
      template: "revision/" + "tpl_1",
      sandboxHostId: "host_1",
      envs: { TOKEN: sentinel },
    };
    const handle = await ok(client.sandboxes.create(input));
    // No request object is stored in the handle, including after the caller
    // reuses its object for a later environment-bearing request.
    Object.assign(input, { envs: { TOKEN: sentinel } });
    expect(Object.isFrozen(handle)).toBe(true);
    expect(JSON.stringify(handle)).not.toContain(sentinel);
    expect(handle).not.toHaveProperty("envs");
    expect(handle).not.toHaveProperty("input");
    expect(typeof handle.commands.run).toBe("function");
    expect(typeof handle.files.upload).toBe("function");
    for (const refusal of [
      handle.pause(),
      handle.snapshot(),
      handle.restore("snapshot-id"),
      handle.fork(),
    ]) {
      await expect(refusal).rejects.toMatchObject({
        kind: "unsupported",
        code: "UNSUPPORTED_CAPABILITY",
      });
    }
    expect(() => handle.getHost(8080)).toThrow(WsspError);
    expect(calls).toHaveLength(3);
    expect((await ok(handle.get())).id).toBe(handle.id);
    const connected = await ok(handle.connect({ leaseTimeoutMs: 1000, waitTimeoutMs: 5000 }));
    expect(connected.id).toBe(handle.id);
    expect(typeof connected.setTimeout).toBe("function");
    expect(JSON.parse(String(callAt(calls, 4).init.body))).toEqual({ timeoutMs: 1000 });
    expect(calls.slice(3).every((call) => !String(call.init.body).includes(sentinel))).toBe(true);
  });

  it.each(["network", "timeout"] as const)(
    "request %s errors drop environment-bearing fetch diagnostics and request objects",
    async (failure) => {
      const { client } = harness((call) => {
        if (failure === "network")
          throw new Error(String(call.init.body), { cause: { envs: { TOKEN: sentinel } } });
        return new Promise<Response>((_, reject) => {
          call.init.signal?.addEventListener("abort", () =>
            reject(new Error(String(call.init.body), { cause: { envs: { TOKEN: sentinel } } })),
          );
        });
      });
      const error = await fails(
        client.transport.request("startCommand", {
          params: { id: "sbx_1" },
          body: { argv: ["true"], envs: { TOKEN: sentinel } },
          idempotencyKey: "secret-error",
          timeoutMs: 10,
        }),
      );
      expect(error.kind).toBe("unknown");
      expect(error.reason).toBe(failure);
      expect(error.idempotencyKey).toBe("secret-error");
      expect(error.cause).toBeUndefined();
      const { inspect } = await import("node:util");
      for (const secret of [sentinel, Buffer.from(sentinel).toString("base64")]) {
        expect(JSON.stringify(error)).not.toContain(secret);
        expect(inspect(error, { showHidden: true, depth: 8 })).not.toContain(secret);
      }
    },
  );

  it("refuses invalid create envs before IO without retaining their values in the error", async () => {
    const { client, calls } = harness();
    const input = {
      template: "revision/" + "tpl_1",
      sandboxHostId: "host_1",
      envs: { HOME: sentinel },
    };
    const error = await fails(client.sandboxes.create(input));
    expect(error.kind).toBe("invalid_request");
    expect(calls).toHaveLength(0);
    const { inspect } = await import("node:util");
    expect(inspect(error, { showHidden: true, depth: 8 })).not.toContain(sentinel);
  });

  it.each(["create", "connect"] as const)(
    "%s requires an exact intent ACK even if mutable sandbox state is already READY",
    async (action) => {
      const { client, calls } = harness(
        json(202, receipt()),
        json(200, operation("SUCCEEDED", { leaseIntent: null })),
      );
      const error = await fails(
        action === "create"
          ? client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" })
          : client.sandboxes.connect("sbx_1"),
      );
      expect(error.kind).toBe("protocol");
      expect(calls).toHaveLength(2);
    },
  );
});

it.each([{ id: "another-operation" }, { kind: "RUN_COMMAND" }, { sandboxId: "another-sandbox" }])(
  "3C1 connect refuses ACK evidence for another operation/kind/sandbox: %j",
  async (over) => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX", ...over })),
    );
    const error = await fails(client.sandboxes.connect("sbx_1"));
    expect(error.kind).toBe("protocol");
    expect(error.operationId).toBe("op_1");
    expect(calls).toHaveLength(2);
  },
);

it.each([{ id: "another-sandbox" }, { generation: 2 }])(
  "3C1 bound waiter refuses READY from another identity/generation: %j",
  async (over) => {
    const { client } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED")),
      json(200, sandbox("READY", over)),
    );
    const error = await fails(
      client.sandboxes.create({ template: "revision/" + "tpl_1", sandboxHostId: "host_1" }),
    );
    expect(error.kind).toBe(over.id ? "protocol" : "conflict");
  },
);

it("sandbox list encodes numeric limits and exact AND filters as bounded wire values", async () => {
  const calls: string[] = [];
  const client = createWsspClient({
    baseUrl: BASE,
    apiKey: KEY,
    fetch: async (url) => {
      calls.push(url);
      return json(200, {
        items: [sandbox("STOPPED", { metadata: { team: "雪😀", empty: "" } })],
        nextCursor: "a".repeat(200),
      });
    },
  });
  const query = {
    limit: 7,
    cursor: "a".repeat(200),
    metadata: { team: "雪😀", empty: "" },
    states: ["READY", "STOPPED"] as ("READY" | "STOPPED")[],
    templateId: "tpl_1",
    startedAfter: NOW,
    order: "asc" as const,
  };
  const result = await client.sandboxes.list(query);
  const url = new URL(calls[0]!);
  expect(Object.fromEntries(url.searchParams)).toEqual({
    limit: "7",
    cursor: query.cursor,
    metadata: JSON.stringify(query.metadata),
    states: "READY,STOPPED",
    templateId: "tpl_1",
    startedAfter: NOW,
    order: "asc",
  });
  expect(result.items[0]?.metadata).toEqual(query.metadata);
  expect(result.nextCursor).toBe(query.cursor);
});

it.each([
  { limit: "2" },
  { limit: 0 },
  { limit: 101 },
  { limit: 1.5 },
  { limit: NaN },
  { metadata: { count: 1 } },
  { metadata: { value: undefined } },
  { metadata: { value: "\ud800" } },
  { metadata: { constructor: "x" } },
  { metadata: JSON.parse('{"__proto__":"x"}') },
  { states: [] },
  { states: ["unknown"] },
  { templateId: "!" },
  { startedAfter: "yesterday" },
  { order: "sideways" },
  { poolId: 123 },
])("sandbox list rejects malformed options before IO: %j", async (query) => {
  const fetch = vi.fn<FetchLike>();
  const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
  await expect(client.sandboxes.list(query as never)).rejects.toMatchObject({
    kind: "invalid_request",
  });
  expect(fetch).not.toHaveBeenCalled();
});

it.each([
  ["sandbox.vm_size_invalid", "invalid_request"],
  ["sandbox.vm_size_unsupported", "unsupported"],
  ["sandbox.vm_size_mismatch", "conflict"],
] as const)("B5 remote %s is definitive and never submission-retried", async (code, kind) => {
  const { client, calls } = harness(envelope(code));
  const error = await fails(
    client.sandboxes.create(
      { diskGiB: 32, template: "base", sandboxHostId: "host_1", cpuCount: 2, memoryMiB: 2048 },
      { idempotencyKey: "size-remote" },
    ),
  );
  expect(error).toMatchObject({ code, kind, idempotencyKey: "size-remote" });
  expect(calls).toHaveLength(1);
  expect(JSON.parse(String(calls[0]!.init.body))).toMatchObject({
    diskGiB: 32,
    cpuCount: 2,
    memoryMiB: 2048,
  });
});

it("B5 sized lost create keeps original key and exact sized body", async () => {
  const { client, calls } = harness(
    () => Promise.reject(new TypeError("socket hang up")),
    envelope("SERVICE_UNAVAILABLE"),
    json(202, receipt()),
    json(200, operation("SUCCEEDED")),
    json(200, sandbox("READY")),
  );
  const input = { template: "base", sandboxHostId: "host_1", memoryMiB: 2048 };
  await ok(client.sandboxes.create(input, { idempotencyKey: "probe-sized" }));
  const posts = calls.filter((c) => c.init.method === "POST");
  expect(posts).toHaveLength(3);
  expect(idempotencyKeys(posts)).toEqual(["probe-sized", "probe-sized", "probe-sized"]);
  for (const post of posts)
    expect(JSON.parse(String(post.init.body))).toEqual({
      template: "base",
      sandboxHostId: "host_1",
      memoryMiB: 2048,
    });
});
it("B5 local step-invalid memory makes no request", async () => {
  const { client, calls } = harness();
  const error = await fails(
    client.sandboxes.create(
      { template: "base", sandboxHostId: "host_1", memoryMiB: 1000 },
      { idempotencyKey: "k" },
    ),
  );
  expect(error).toMatchObject({ kind: "invalid_request", code: null });
  expect(calls).toHaveLength(0);
});

it("B5 sandbox field remains the fixed snapshot after get returns a fresh read", async () => {
  const { client } = harness(
    json(202, receipt()),
    json(200, operation("SUCCEEDED")),
    json(200, sandbox("READY", { diskGiB: 32, cpuCount: 2, memoryMiB: 2048 })),
    json(200, sandbox("STOPPED", { diskGiB: 32, cpuCount: 2, memoryMiB: 2048 })),
  );
  const handle = await ok(client.sandboxes.create({ template: "base", sandboxHostId: "host_1" }));
  expect(await handle.get()).toMatchObject({
    diskGiB: 32,
    state: "STOPPED",
    cpuCount: 2,
    memoryMiB: 2048,
  });
  expect(handle.sandbox).toMatchObject({
    diskGiB: 32,
    state: "READY",
    cpuCount: 2,
    memoryMiB: 2048,
  });
  expect(Object.isFrozen(handle)).toBe(true);
});

it.each(["ram", "vcpu", "disk", "storage", "ceiling"] as const)(
  "returns definitive capacity reason %s with one fetch for each capacity code",
  async (reason) => {
    for (const code of ["sandbox.host_capacity", "sandbox.pool_full"] as const) {
      const fetch = vi.fn<FetchLike>(async () => envelope(code, { reason }));
      const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
      await expect(
        client.sandboxes.create({ template: "base", sandboxHostId: "host_1" }),
      ).rejects.toMatchObject({ kind: "capacity", code, reason, status: 409 });
      expect(fetch).toHaveBeenCalledTimes(1);
    }
  },
);
it.each([null, 0, 2049, 1.5, "32"])("invalid local disk %s makes no request", async (diskGiB) => {
  const fetch = vi.fn<FetchLike>();
  const client = createWsspClient({ baseUrl: BASE, apiKey: KEY, fetch });
  await expect(
    client.transport.request("createSandbox", {
      body: {
        template: "base",
        sandboxHostId: "host_1",
        // @ts-expect-error Deliberately validate invalid disk input at the runtime boundary.
        diskGiB,
      },
      idempotencyKey: "invalid-disk",
    }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  expect(fetch).not.toHaveBeenCalled();
});

it("keeps the bounded capacity reason of a failed accepted operation without resubmission", async () => {
  const { client, calls } = harness(
    json(202, receipt()),
    json(
      200,
      operation("FAILED", {
        errorCode: "host_capacity",
        failure: { resource: "sandbox", effect: "none", reason: "disk" },
      }),
    ),
  );
  const error = await fails(
    client.sandboxes.create({ template: "revision/tpl_1", sandboxHostId: "host_1" }),
  );
  expect(error).toMatchObject({
    kind: "capacity",
    reason: "disk",
    operationErrorCode: "host_capacity",
    operationId: "op_1",
  });
  expect(calls).toHaveLength(2);
});

describe("sandboxes.update (rename)", () => {
  it("PUTs the name without an idempotency key and returns the fresh sandbox", async () => {
    const { client, calls } = harness(json(200, sandbox("READY", { name: "nightly-build" })));
    const renamed = await ok(client.sandboxes.update("sbx_1", { name: "nightly-build" }));
    expect(renamed.name).toBe("nightly-build");
    const call = callAt(calls, 0);
    expect(call.init.method).toBe("PUT");
    expect(call.url).toBe(`${BASE}/v1/sandboxes/sbx_1`);
    expect(JSON.parse(String(call.init.body))).toEqual({ name: "nightly-build" });
    expect(new Headers(call.init.headers).has("idempotency-key")).toBe(false);
  });

  it("update sets the offload policy alone", async () => {
    const { client, calls } = harness(json(200, sandbox("STOPPED")));
    await ok(client.sandboxes.update("sbx_1", { offload: { mode: "after", afterMs: 7_200_000 } }));
    expect(callAt(calls, 0).init.method).toBe("PUT");
    expect(JSON.parse(String(callAt(calls, 0).init.body))).toEqual({
      offload: { mode: "after", afterMs: 7_200_000 },
    });
  });

  it("a bound handle renames itself and keeps its own snapshot", async () => {
    const { client, calls } = harness(
      json(202, receipt()),
      json(200, operation("SUCCEEDED", { kind: "RECONNECT_SANDBOX" })),
      json(200, sandbox("READY")),
      json(200, sandbox("READY", { name: "nightly-build" })),
    );
    const handle = await ok(client.sandboxes.connect("sbx_1"));
    const renamed = await ok(handle.update({ name: "nightly-build" }));
    expect(renamed.name).toBe("nightly-build");
    expect(handle.name).toBe("quiet-otter");
    expect(callAt(calls, 3).url).toBe(`${BASE}/v1/sandboxes/sbx_1`);
  });

  it.each([
    ["sandbox.name_taken", "conflict"],
    ["sandbox.name_invalid", "invalid_request"],
  ] as const)("%s surfaces as kind %s", async (code, kind) => {
    const { client } = harness(envelope(code));
    const error = await fails(client.sandboxes.update("sbx_1", { name: "quiet-otter" }));
    expect(isWsspError(error, kind)).toBe(true);
    expect(error.code).toBe(code);
  });
});

it("a capture forwards its defaultDiskGiB for the new revision", async () => {
  const { client, calls } = harness(envelope("sandbox.disk_below_image"));
  await expect(
    client.sandboxes.captureTemplate(
      "sbx_1",
      { templateId: "tpl_1", defaultDiskGiB: 64 },
      { idempotencyKey: "capture-disk" },
    ),
  ).rejects.toMatchObject({ code: "sandbox.disk_below_image" });
  expect(JSON.parse(String(calls[0]!.init.body))).toEqual({
    templateId: "tpl_1",
    defaultDiskGiB: 64,
  });
});
