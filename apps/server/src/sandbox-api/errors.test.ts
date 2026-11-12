import { readFileSync } from "node:fs";
import { ORPCError } from "@orpc/server";
import { isRetryableRefusalCode, RETRYABLE_REFUSAL_CODES } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterEach, expect, it, vi } from "vitest";

// A non-default value proves the header comes from the deployment setting.
const mockEnv = { CAPACITY_RETRY_AFTER_SECONDS: 17 };
vi.mock("@wssp/env/server", () => ({ env: mockEnv }));

const { SDK_ERRORS, sdkErrorResponse } = await import("./errors.js");

afterEach(() => vi.restoreAllMocks());
/** Required typed fields of the `template.build_*` refusals. */
const BUILD_FIELDS: Record<string, Record<string, unknown>> = {
  "template.build_disabled": { reason: "off" },
  "template.build_recipe_invalid": { recipeCode: "recipe_invalid", line: 2, column: 1 },
  "template.build_no_builder": { skipped: { builder: true, capture_policy: false, lease: false } },
  "template.build_concurrency": { maxConcurrent: 2 },
  "template.build_minutes_exhausted": { minutesPerMonth: 10 },
  "template.build_context_too_large": { maxBytes: 1024 },
  "template.build_context_busy": { scope: "account" },
  "template.build_not_cancellable": { state: "SUCCEEDED" },
  "template.community_unavailable": { reason: "index_unreachable" },
};
it("returns only catalog fields for every supported error and redacts unknown and prototype codes", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  let error: unknown;
  const app = new Hono<{ Variables: { requestId: string } }>();
  app.use("*", async (c, next) => {
    c.set("requestId", "generated-id");
    await next();
  });
  app.onError((e, c) => sdkErrorResponse(c, e));
  app.get("/", () => {
    throw error;
  });
  for (const [code, [status, message]] of Object.entries(SDK_ERRORS)) {
    for (const domain of [false, true]) {
      error = new ORPCError(domain ? "BAD_REQUEST" : code, {
        message: "sensitive detail",
        data: {
          ...(domain ? { code } : {}),
          // Both forms of every capacity refusal: permanent without a domain code.
          ...(isRetryableRefusalCode(code) ? { retryable: domain } : {}),
          ...(code === "sandbox.share_quota" || code === "sandbox.member_quota"
            ? { resource: "memory" }
            : {}),
          ...(code === "sandbox.host_capacity" || code === "sandbox.pool_full"
            ? { reason: "ram" }
            : {}),
          ...(code === "lease_exceeds_policy" ? { maxTimeoutMs: 21_600_000 } : {}),
          ...(code === "sandbox.capture_unsupported" ? { reason: "storage" } : {}),
          ...(code === "sandbox.image_quota_exceeded" ? { scope: "stored" } : {}),
          ...(code === "capacity_wait_exceeds_policy" ? { maxWaitMs: 3_600_000 } : {}),
          ...(code === "sandbox.capacity_queue_full" ? { scope: "key" } : {}),
          ...(BUILD_FIELDS[code] ?? {}),
          ...(code === "sandbox.template_image_unavailable"
            ? { reason: "rebuilding", hint: "rebuild_required" }
            : {}),
          secret: "sensitive detail",
        },
        cause: new Error("sensitive detail"),
      });
      const response = await app.request("/");
      expect(response.status).toBe(status);
      const retryAfter =
        code === "SERVICE_UNAVAILABLE"
          ? 5
          : code === "TRANSFER_QUOTA"
            ? 5
            : code === "sandbox.host_reconnecting"
              ? 1
              : isRetryableRefusalCode(code) && domain
                ? 17
                : undefined;
      expect(response.headers.get("retry-after")).toBe(
        retryAfter === undefined ? null : String(retryAfter),
      );
      expect(await response.json()).toEqual({
        error: {
          code,
          message,
          requestId: "generated-id",
          ...(code === "sandbox.share_quota" || code === "sandbox.member_quota"
            ? { resource: "memory" }
            : {}),
          ...(code === "sandbox.host_capacity" || code === "sandbox.pool_full"
            ? { reason: "ram" }
            : {}),
          ...(code === "lease_exceeds_policy" ? { maxTimeoutMs: 21_600_000 } : {}),
          ...(code === "sandbox.capture_unsupported" ? { reason: "storage" } : {}),
          ...(code === "sandbox.image_quota_exceeded" ? { scope: "stored" } : {}),
          ...(code === "capacity_wait_exceeds_policy" ? { maxWaitMs: 3_600_000 } : {}),
          ...(code === "sandbox.capacity_queue_full" ? { scope: "key" } : {}),
          ...(BUILD_FIELDS[code] ?? {}),
          ...(code === "sandbox.template_image_unavailable"
            ? { reason: "rebuilding", hint: "rebuild_required" }
            : {}),
          ...(isRetryableRefusalCode(code) ? { retryable: domain } : {}),
          ...(retryAfter === undefined ? {} : { retryAfterSeconds: retryAfter }),
        },
      });
    }
  }
  // A build refusal without its documented fields never goes out as such.
  error = new ORPCError("CONFLICT", { data: { code: "template.build_concurrency" } });
  expect((await app.request("/")).status).toBe(500);
  for (const code of ["__proto__", "constructor", "toString", "unexpected"]) {
    error = new ORPCError(code, { data: { code } });
    const response = await app.request("/");
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({ error: { code: "INTERNAL_SERVER_ERROR" } });
  }
});
it("includes every existing sandbox domain code in the public catalog", () => {
  const source = readFileSync(
    new URL("../../../../packages/api/src/sandbox/errors.ts", import.meta.url),
    "utf8",
  );
  const block = source.slice(
    source.indexOf("const SandboxErrorCode = {"),
    source.indexOf("} as const;"),
  );
  const codes = [...block.matchAll(/:\s*"([^"]+)"/g)].map((m) => m[1]);
  expect(codes.length).toBeGreaterThanOrEqual(12);
  for (const code of codes) expect(Object.hasOwn(SDK_ERRORS, code!)).toBe(true);
});

it.each(["ram", "vcpu", "disk", "storage", "ceiling"])(
  "preserves bounded capacity reason %s only on the two capacity codes",
  async (reason) => {
    for (const code of ["sandbox.host_capacity", "sandbox.pool_full", "sandbox.host_unavailable"]) {
      const app = new Hono<{ Variables: { requestId: string } }>();
      app.use("*", async (c, next) => {
        c.set("requestId", "request");
        await next();
      });
      app.onError((error, c) => sdkErrorResponse(c, error));
      app.get("/", () => {
        throw new ORPCError("CONFLICT", { data: { code, reason, retryable: true } });
      });
      const response = await app.request("/");
      const body = await response.json();
      if (code === "sandbox.host_unavailable") expect(body).not.toHaveProperty("error.reason");
      else expect(body).toMatchObject({ error: { code, reason } });
    }
  },
);

it("carries a bounded lease maximum only on lease_exceeds_policy and fails closed without it", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const respond = async (data: Record<string, unknown>) => {
    const app = new Hono<{ Variables: { requestId: string } }>();
    app.use("*", async (c, next) => {
      c.set("requestId", "request");
      await next();
    });
    app.onError((error, c) => sdkErrorResponse(c, error));
    app.get("/", () => {
      throw new ORPCError("BAD_REQUEST", { data });
    });
    const response = await app.request("/");
    return { status: response.status, body: await response.json() };
  };
  expect(await respond({ code: "lease_exceeds_policy", maxTimeoutMs: 21_600_000 })).toMatchObject({
    status: 400,
    body: { error: { code: "lease_exceeds_policy", maxTimeoutMs: 21_600_000 } },
  });
  for (const maxTimeoutMs of [undefined, "21600000", 1, 2_073_600_001])
    expect(await respond({ code: "lease_exceeds_policy", maxTimeoutMs })).toMatchObject({
      status: 500,
      body: { error: { code: "INTERNAL_SERVER_ERROR" } },
    });
  const other = await respond({ code: "BAD_REQUEST", maxTimeoutMs: 21_600_000 });
  expect(other.body).not.toHaveProperty("error.maxTimeoutMs");
});

it("E1-B-09 names the refused entry and path on credential.value_invalid, never other data", async () => {
  const app = new Hono<{ Variables: { requestId: string } }>();
  app.use("*", async (c, next) => {
    c.set("requestId", "rid");
    await next();
  });
  let error: unknown;
  app.onError((e, c) => sdkErrorResponse(c, e));
  app.get("/", () => {
    throw error;
  });
  error = new ORPCError("BAD_REQUEST", {
    data: {
      code: "credential.value_invalid",
      entry: "bundle.undeclared_path",
      path: ".fakecli",
      secret: "value bytes",
    },
  });
  const body = (await (await app.request("/")).json()) as { error: Record<string, unknown> };
  expect(body.error).toMatchObject({
    code: "credential.value_invalid",
    entry: "bundle.undeclared_path",
    path: ".fakecli",
  });
  expect(JSON.stringify(body)).not.toContain("value bytes");
  // A malformed field is dropped, not echoed.
  error = new ORPCError("BAD_REQUEST", {
    data: { code: "credential.value_invalid", entry: "x\ny", path: 7 },
  });
  const bad = (await (await app.request("/")).json()) as { error: Record<string, unknown> };
  expect(bad.error).not.toHaveProperty("entry");
  expect(bad.error).not.toHaveProperty("path");
  // Another code never carries them.
  error = new ORPCError("BAD_REQUEST", {
    data: { code: "credential.busy", entry: "e", path: "p" },
  });
  const other = (await (await app.request("/")).json()) as { error: Record<string, unknown> };
  expect(other.error).not.toHaveProperty("entry");
});

/**
 * E2-B-01 parity: whatever data a domain error carries, the envelope this
 * builder emits must parse under the public contract (`sdkErrorEnvelopeSchema`,
 * strict). The SDK parses that schema strictly, so a field the builder adds
 * without declaring it in the contract turns a typed refusal into an
 * untyped `invalid_response` on every client.
 *
 * Every code is probed with every family of field the builder knows how to
 * forward (each probe valid for its own family). A new forwarded field must
 * be added to PROBES and to the contract, or this test fails.
 */
const PROBES: Record<string, Record<string, unknown>> = {
  capacity: { reason: "ram", retryable: true },
  poolReserved: { reason: "reserved", skipped: ["vm_size"], retryable: true },
  quota: { resource: "disk", skipped: ["lease_policy"], retryable: false },
  memberQuota: { resource: "vcpu", skipped: ["vm_size"], retryable: true },
  lease: { maxTimeoutMs: 21_600_000 },
  capture: { reason: "storage" },
  imageQuota: { scope: "stored" },
  wait: { maxWaitMs: 3_600_000 },
  queue: { scope: "key", retryable: true },
  image: { reason: "rebuilding", hint: "rebuild_required" },
  egress: { reason: "open_egress_not_permitted" },
  valueInvalid: { entry: "bundle.undeclared_path", path: ".fakecli" },
  retry: { retryAfterSeconds: 7 },
  ...Object.fromEntries(Object.entries(BUILD_FIELDS).map(([code, fields]) => [code, fields])),
};
it("E2-B-01 every emitted error envelope parses under the strict public contract", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const { sdkErrorEnvelopeSchema } = await import("@wssp/sandbox-contracts");
  let error: unknown;
  const app = new Hono<{ Variables: { requestId: string } }>();
  app.use("*", async (c, next) => {
    c.set("requestId", "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19");
    await next();
  });
  app.onError((e, c) => sdkErrorResponse(c, e));
  app.get("/", () => {
    throw error;
  });
  const failures: string[] = [];
  const preserved = new Set<string>();
  for (const code of Object.keys(SDK_ERRORS))
    for (const [probe, fields] of Object.entries(PROBES)) {
      error = new ORPCError("BAD_REQUEST", { data: { ...fields, code } });
      const body = (await (await app.request("/")).json()) as { error: { code: string } };
      const parsed = sdkErrorEnvelopeSchema.safeParse(body);
      if (!parsed.success) failures.push(`${code} + ${probe}: ${JSON.stringify(body.error)}`);
      if (body.error.code === code) preserved.add(code);
    }
  expect(failures).toEqual([]);
  // Every code survives with at least one probe (none is always degraded).
  expect(Object.keys(SDK_ERRORS).filter((code) => !preserved.has(code))).toEqual([]);
});

it("classifies every capacity refusal: Retry-After only on retryable, fails closed without the flag", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  let error: unknown;
  const app = new Hono<{ Variables: { requestId: string } }>();
  app.use("*", async (c, next) => {
    c.set("requestId", "rid");
    await next();
  });
  app.onError((e, c) => sdkErrorResponse(c, e));
  app.get("/", () => {
    throw error;
  });
  const fields: Record<string, Record<string, unknown>> = {
    "sandbox.host_capacity": { reason: "vcpu" },
    "sandbox.pool_full": { reason: "disk", skipped: ["vm_size"] },
    "sandbox.pool_unavailable": { skipped: ["template_startup"] },
    "sandbox.share_quota": { resource: "disk" },
    "sandbox.member_quota": { resource: "memory" },
    "sandbox.capacity_queue_full": { scope: "pool" },
  };
  const respond = async (data: Record<string, unknown>) => {
    error = new ORPCError("CONFLICT", { data });
    const response = await app.request("/");
    return {
      status: response.status,
      header: response.headers.get("retry-after"),
      body: (await response.json()) as { error: Record<string, unknown> },
    };
  };
  for (const code of RETRYABLE_REFUSAL_CODES) {
    const base = { code, ...fields[code] };
    const temporary = await respond({ ...base, retryable: true });
    expect(temporary, code).toMatchObject({
      status: 409,
      header: "17",
      body: { error: { ...base, retryable: true, retryAfterSeconds: 17 } },
    });
    // A hint smuggled into the data of a permanent refusal is never sent.
    const permanent = await respond({ ...base, retryable: false, retryAfterSeconds: 9 });
    expect(permanent, code).toMatchObject({
      status: 409,
      header: null,
      body: { error: { ...base, retryable: false } },
    });
    expect(permanent.body.error).not.toHaveProperty("retryAfterSeconds");
    // Unclassified or malformed: never a typed refusal a harness could misread.
    for (const retryable of [undefined, "true", 1, null]) {
      const bad = await respond({ ...base, retryable });
      expect(bad, `${code} ${String(retryable)}`).toMatchObject({
        status: 500,
        header: null,
        body: { error: { code: "INTERNAL_SERVER_ERROR" } },
      });
      expect(bad.body.error).not.toHaveProperty("retryable");
    }
  }
  // Another 409 never carries the flag or the capacity backoff.
  const other = await respond({ code: "sandbox.host_unavailable", retryable: true });
  expect(other).toMatchObject({ status: 409, header: null });
  expect(other.body.error).not.toHaveProperty("retryable");
  expect(other.body.error).not.toHaveProperty("retryAfterSeconds");
});
