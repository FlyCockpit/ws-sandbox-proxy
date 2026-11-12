import type { TemplateBuildDto } from "@wssp/sandbox-contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { WsspError } from "./errors";
import { Template } from "./template-builder";
import type { FetchLike } from "./transport";

const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const NOW = "2026-01-01T00:00:00.000Z";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": REQUEST_ID },
  });
}

function build(state: TemplateBuildDto["state"]): TemplateBuildDto {
  const done = state === "SUCCEEDED";
  return {
    id: "build_1",
    templateId: "tpl_1",
    tag: "latest",
    acceptedBy: "sdkKey",
    state,
    phase: done ? null : "placing",
    stepIndex: -1,
    steps: [],
    recipeDigest: "a".repeat(64),
    buildDigest: "b".repeat(64),
    contextSha256: null,
    contextBytes: null,
    timeoutMinutes: 30,
    reservedMinutes: 30,
    chargedMinutes: done ? 1 : null,
    revisionId: done ? "rev_1" : null,
    cacheHitRevisionId: null,
    errorCode: null,
    errorDetail: null,
    failureStepIndex: null,
    failureExitCode: null,
    cancelRequestedAt: null,
    cleanupState: done ? "DONE" : "PENDING",
    egressModeReason: null,
    createdAt: NOW,
    updatedAt: NOW,
    completedAt: done ? NOW : null,
  };
}

type Step = () => Response | Promise<Response>;
const networkDown: Step = () => Promise.reject(new TypeError("fetch failed"));

function harness(...steps: Step[]) {
  const calls: string[] = [];
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    calls.push(`${init.method} ${new URL(url).pathname}`);
    const step = steps.shift();
    if (!step) throw new Error(`unexpected call: ${init.method} ${url}`);
    return step();
  });
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_test_canary",
    fetch,
  });
  return { client, calls };
}

async function settle<T>(promise: Promise<T>): Promise<{ value?: T; error?: unknown }> {
  let result: { value?: T; error?: unknown } | undefined;
  void promise.then(
    (value) => {
      result = { value };
    },
    (error: unknown) => {
      result = { error };
    },
  );
  for (let elapsed = 0; !result && elapsed < 120_000; elapsed += 100)
    await vi.advanceTimersByTimeAsync(100);
  if (!result) throw new Error("the build wait never settled");
  return result;
}

const created = () =>
  json(201, { build: build("QUEUED"), joined: false, cacheHit: false, contextUpload: null });
const start = (client: ReturnType<typeof harness>["client"]) =>
  client.templates.build(Template().fromTemplate("base").runCmd("true"), {
    name: "retry-follow",
    hostId: "host_1",
  });

describe("templates.build follow (E1-A-09)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("retries transient read failures with backoff and reaches the end", async () => {
    const { client, calls } = harness(
      created,
      networkDown,
      () =>
        json(503, { error: { code: "SERVICE_UNAVAILABLE", message: "x", requestId: REQUEST_ID } }),
      () => json(200, build("SUCCEEDED")),
    );
    const { value, error } = await settle(start(client));
    expect(error).toBeUndefined();
    expect(value?.state).toBe("SUCCEEDED");
    expect(calls).toEqual([
      "POST /v1/template-builds",
      "GET /v1/template-builds/build_1",
      "GET /v1/template-builds/build_1",
      "GET /v1/template-builds/build_1",
    ]);
  });

  it("gives up after a bounded number of consecutive failures", async () => {
    const { client, calls } = harness(created, ...Array.from({ length: 6 }, () => networkDown));
    const { error } = await settle(start(client));
    expect(error).toBeInstanceOf(WsspError);
    expect((error as WsspError).kind).toBe("unavailable");
    expect(calls).toHaveLength(7);
  });

  it("a definitive answer is never retried", async () => {
    const { client, calls } = harness(created, () =>
      json(404, { error: { code: "NOT_FOUND", message: "x", requestId: REQUEST_ID } }),
    );
    const { error } = await settle(start(client));
    expect((error as WsspError).kind).toBe("not_found");
    expect(calls).toHaveLength(2);
  });
});

describe("templates.build log follow (E2-A-03)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const step = (state: "running" | "succeeded") => ({
    n: 0,
    stepIndex: 0,
    kind: "run" as const,
    state,
    operationId: "op_0",
    exitCode: state === "succeeded" ? 0 : null,
  });
  const withSteps = (state: TemplateBuildDto["state"], stepState: "running" | "succeeded") => ({
    ...build(state),
    phase: state === "RUNNING" ? "step" : null,
    stepIndex: 0,
    steps: [step(stepState)],
  });
  const hint = (name: string) => ({
    type: "blocked_name" as const,
    step: 0,
    name,
    source: "own_node" as const,
    preset: null,
    message: `blocked: \`${name}\` — add it to egress`,
    at: NOW,
  });
  const logs = (names: string[], data: string | null) =>
    json(200, {
      buildId: "build_1",
      step: step("succeeded"),
      output: {
        operationId: "op_0",
        state: "SUCCEEDED",
        exitCode: 0,
        attempt: 1,
        reset: false,
        offset: 0,
        chunks: data ? [{ stream: "stdout", offset: 0, data: btoa(data) }] : [],
        gaps: [],
        nextCursor: "c1",
        hasMore: false,
        receivedBytes: 2,
        totalBytes: 2,
        retainedBytes: 2,
        truncated: false,
        complete: true,
        expiresAt: null,
      },
      hints: names.map(hint),
    });

  it("a hint recorded after the step's output completed is still streamed", async () => {
    const { client, calls } = harness(
      created,
      () => json(200, withSteps("RUNNING", "running")),
      // The step's output completes with one hint; the second lands later.
      () => logs(["a.example.org"], "ok"),
      () => json(200, withSteps("RUNNING", "succeeded")),
      () => json(200, withSteps("SUCCEEDED", "succeeded")),
      () => logs(["a.example.org", "b.example.org"], null),
    );
    const hints: string[] = [];
    const { value, error } = await settle(
      client.templates.build(Template().fromTemplate("base").runCmd("true"), {
        name: "late-hint",
        hostId: "host_1",
        onBuildLogs: (entry) => {
          if (entry.type === "hint") hints.push(entry.hint.name);
        },
      }),
    );
    expect(error).toBeUndefined();
    expect(value?.state).toBe("SUCCEEDED");
    expect(hints).toEqual(["a.example.org", "b.example.org"]);
    expect(calls).toEqual([
      "POST /v1/template-builds",
      "GET /v1/template-builds/build_1",
      "GET /v1/template-builds/build_1/logs",
      "GET /v1/template-builds/build_1",
      "GET /v1/template-builds/build_1",
      "GET /v1/template-builds/build_1/logs",
    ]);
  });
});
