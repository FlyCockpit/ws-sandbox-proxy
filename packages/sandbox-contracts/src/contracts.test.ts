import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";
import pathWhitespace from "../../config/src/sandbox-path-whitespace.json";
import {
  capabilitiesSchema,
  downloadBodySchema,
  enabledSdkFeatures,
  guestEntryPathSchema,
  guestFilePathSchema,
  guestPathSchema,
  isRetryableRefusalCode,
  type MutationParams,
  mkdirBodySchema,
  moveBodySchema,
  OPERATION_ERROR_CODES,
  OPERATION_STATES,
  operationOutcome,
  operationSchema,
  pageLimitQuerySchema,
  pageQuerySchema,
  publicOperationErrorCode,
  removeBodySchema,
  resourceIdParamsSchema,
  SDK_ERRORS,
  SDK_FEATURES,
  SDK_ROUTE_IDS,
  SDK_ROUTES,
  type SdkRoute,
  sandboxSchema,
  sdkErrorEnvelopeSchema,
  statBodySchema,
  transferCreateSchema,
} from "./index";
import { buildSdkOpenApiDocument } from "./openapi";

const srcDir = new URL("./", import.meta.url);

describe("mutation route params typing", () => {
  it("types params only for an {id} segment, matching the runtime check", () => {
    expectTypeOf<MutationParams<"/v1/sandboxes/{id}/stop">>().toEqualTypeOf<
      typeof resourceIdParamsSchema
    >();
    expectTypeOf<MutationParams<"/v1/sandboxes">>().toEqualTypeOf<null>();
    // A differently-named placeholder must not type as `{id}` params.
    expectTypeOf<MutationParams<"/v1/operations/{operationId}/cancel">>().toEqualTypeOf<null>();
  });
});

describe("package boundary", () => {
  it("imports only zod and relative modules from source files", () => {
    const sources = readdirSync(srcDir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
    expect(sources.length).toBeGreaterThanOrEqual(4);
    for (const file of sources) {
      const text = readFileSync(new URL(file, srcDir), "utf8");
      const specifiers = [...text.matchAll(/(?:from|import)\s*\(?\s*"([^"]+)"/g)].map((m) => m[1]);
      for (const specifier of specifiers) {
        expect(`${file}:${specifier}`).toMatch(
          /:(?:zod|\.\/[a-z-]+|\.\/(?:env|vm-size|lease)-limits\.json|\.\.\/\.\.\/config\/src\/(?:sandbox-result|credential-protocol)-limits\.json)$/,
        );
      }
    }
    const manifest = JSON.parse(readFileSync(new URL("../package.json", srcDir), "utf8"));
    expect(Object.keys(manifest.dependencies)).toEqual(["zod"]);
  });
});

describe("static OpenAPI document", () => {
  const doc = buildSdkOpenApiDocument() as {
    paths: Record<string, Record<string, { operationId: string; security?: unknown[] }>>;
    components: { schemas: Record<string, unknown> };
  };

  it("matches the committed snapshot byte-for-byte after JSON parsing", () => {
    const committed = JSON.parse(readFileSync(new URL("../openapi.json", srcDir), "utf8"));
    expect(doc).toEqual(committed);
  });

  it("documents exactly the SDK registry routes and nothing internal", () => {
    const operations = Object.entries(doc.paths).flatMap(([path, methods]) =>
      Object.entries(methods).map(([method, op]) => `${method} ${path} ${op.operationId}`),
    );
    expect(operations.sort()).toEqual(
      [
        "get /v1/openapi.json getOpenApiDocument",
        ...SDK_ROUTE_IDS.map((id) => `${SDK_ROUTES[id].method} ${SDK_ROUTES[id].path} ${id}`),
      ].sort(),
    );
    const text = JSON.stringify(doc);
    for (const internal of [
      "/rpc",
      "/api-reference",
      "/admin",
      "/ws/",
      "/api/auth",
      "wssp_host_",
    ]) {
      expect(text).not.toContain(internal);
    }
    // Only the document itself is anonymous.
    for (const [path, methods] of Object.entries(doc.paths)) {
      for (const op of Object.values(methods)) {
        expect(op.security === undefined).toBe(path !== "/v1/openapi.json");
      }
    }
  });

  it("registers every route response schema as a named component", () => {
    for (const id of SDK_ROUTE_IDS) {
      const route: SdkRoute = SDK_ROUTES[id];
      if (route.binaryResponse) continue;
      expect(Object.keys(doc.components.schemas)).toContain(route.response.name);
    }
    expect(Object.keys(doc.components.schemas)).toContain("ErrorEnvelope");
  });

  it("documents the ranged binary download with validators and 416", () => {
    const op = doc.paths["/v1/operations/{id}/content"]?.get as unknown as {
      parameters: { name: string; in: string }[];
      responses: Record<
        string,
        { headers?: Record<string, unknown>; content?: Record<string, unknown> }
      >;
      "x-wssp-scopes": string[];
    };
    expect(op["x-wssp-scopes"]).toEqual(["operations:read", "files:read"]);
    expect(op.parameters.filter((p) => p.in === "header").map((p) => p.name)).toEqual([
      "Range",
      "If-Range",
    ]);
    for (const status of ["200", "206"]) {
      expect(Object.keys(op.responses[status]?.content ?? {})).toEqual([
        "application/octet-stream",
      ]);
      expect(op.responses[status]?.headers).toHaveProperty("ETag");
      expect(op.responses[status]?.headers).toHaveProperty("Repr-Digest");
    }
    expect(op.responses["206"]?.headers).toHaveProperty("Content-Range");
    expect(op.responses["416"]?.headers).toHaveProperty("Content-Range");
    for (const status of ["404", "409", "410", "416"]) expect(op.responses).toHaveProperty(status);
    // Capture is requested by an ordinary idempotent mutation.
    expect(doc.paths["/v1/sandboxes/{id}/files/download"]?.post).toBeDefined();
  });

  it("keeps guest file bytes on binary transports and host text files explicitly bounded", () => {
    for (const id of SDK_ROUTE_IDS) {
      const route: SdkRoute = SDK_ROUTES[id];
      const body = route.body ? JSON.stringify(z.toJSONSchema(route.body)) : "";
      // Stdin is the only guest-bound base64 field, bounded to one 32 KiB chunk.
      // A CLI-login value upload carries credential files as base64 into the
      // vault (never to a guest path), bounded by the definition and the JSON
      // body cap.
      if (route.path.startsWith("/v1/hosts/")) continue;
      if (id !== "writeStdin" && id !== "sendProcessStdin" && id !== "writeCredentialValue")
        expect(body, id).not.toMatch(/base64|content/i);
      // File bytes move only through the binary transfer transports.
      if (route.binary || route.binaryResponse)
        expect(["upload", "download"], id).toContain(route.transport);
    }
    expect(JSON.stringify(doc)).not.toMatch(/getFileContent|writeFile|payloadBytes/);
  });
});

describe("DTO semantics", () => {
  const operation = {
    id: "op1",
    sandboxId: "sb1",
    kind: "RUN_COMMAND",
    leaseIntent: null,
    failure: null,
    state: "UNKNOWN_OUTCOME",
    outcome: "unknown",
    generation: 1,
    errorCode: "unknown_outcome",
    createdAt: "2026-09-26T00:00:00.000Z",
    updatedAt: "2026-09-26T00:00:00.000Z",
    dispatchedAt: null,
    completedAt: null,
  };

  it("keeps unknown outcome distinct from failure and every other state", () => {
    expect(operationOutcome("UNKNOWN_OUTCOME")).toBe("unknown");
    for (const state of OPERATION_STATES) {
      if (state !== "UNKNOWN_OUTCOME") expect(operationOutcome(state)).not.toBe("unknown");
    }
    expect(operationOutcome("FAILED")).toBe("failed");
    expect(operationSchema.safeParse(operation).success).toBe(true);
    expect(operationSchema.safeParse({ ...operation, outcome: "failed" }).success).toBe(false);
  });

  it("rejects output, results and idempotency keys on operation metadata", () => {
    for (const extra of ["result", "errorDetail", "payloadBytes", "idempotencyKey", "output"]) {
      expect(operationSchema.safeParse({ ...operation, [extra]: "x" }).success).toBe(false);
    }
  });

  it("requires ISO UTC dates on DTOs", () => {
    expect(operationSchema.safeParse({ ...operation, createdAt: "Sat Sep 26 2026" }).success).toBe(
      false,
    );
    expect(sandboxSchema.safeParse({}).success).toBe(false);
  });

  it("reports unknown stored operation error codes as internal", () => {
    expect(publicOperationErrorCode(null)).toBeNull();
    expect(publicOperationErrorCode("timeout")).toBe("timeout");
    expect(publicOperationErrorCode("secret detail from somewhere")).toBe("internal");
    const hostCatalog: string[] = JSON.parse(
      readFileSync(new URL("../../config/src/sandbox-error-codes.json", srcDir), "utf8"),
    );
    for (const code of hostCatalog) expect(OPERATION_ERROR_CODES).toContain(code);
  });

  it("parses page limits strictly", () => {
    for (const bad of ["0", "101", "1e1", " 5", "-1", "05", "", "0x10", "1.5"]) {
      expect(pageLimitQuerySchema.safeParse(bad).success, bad).toBe(false);
    }
    expect(pageLimitQuerySchema.parse("1")).toBe(1);
    expect(pageLimitQuerySchema.parse("100")).toBe(100);
    expect(pageQuerySchema.safeParse({ offset: "1" }).success).toBe(false);
  });

  it("derives capability features only from registered routes", () => {
    expect(enabledSdkFeatures([])).toEqual([]);
    expect(enabledSdkFeatures(["getCapabilities"])).toEqual([]);
    expect(enabledSdkFeatures(["listSandboxes", "getSandbox"])).toEqual(["sandboxes.read"]);
    expect(enabledSdkFeatures().sort()).toEqual([...SDK_FEATURES].sort());
    expect(
      capabilitiesSchema.safeParse({
        apiVersion: "v1",
        features: ["commands.run"],
        limits: { pageSizeDefault: 20, pageSizeMax: 100, jsonBodyMaxBytes: 1, transferMaxBytes: 1 },
        key: {
          ownSandboxesOnly: false,
          scopes: [],
          resourceMode: "allOwned",
          poolMode: "allUsable",
        },
      }).success,
    ).toBe(false);
  });

  it("describes every catalog code in the error envelope", () => {
    const BUILD_EXTRAS_FIXTURE: Record<string, Record<string, unknown>> = {
      "template.build_disabled": { reason: "lease_ceiling" },
      "template.build_recipe_invalid": { recipeCode: "dockerfile_syntax", line: 3, column: 1 },
      "template.build_no_builder": {
        skipped: { builder: true, capture_policy: false, lease: false },
      },
      "template.build_concurrency": { maxConcurrent: 2 },
      "template.build_minutes_exhausted": { minutesPerMonth: 1000 },
      "template.build_context_too_large": { maxBytes: 1024 },
      "template.build_context_busy": { scope: "account" },
      "template.build_not_cancellable": { state: "SUCCEEDED" },
      "template.community_unavailable": { reason: "no_tested_version" },
    };
    for (const code of Object.keys(BUILD_EXTRAS_FIXTURE))
      expect(
        sdkErrorEnvelopeSchema.safeParse({
          error: { code, message: "m", requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19" },
        }).success,
        `${code} without its fields`,
      ).toBe(false);
    for (const code of Object.keys(SDK_ERRORS)) {
      expect(
        sdkErrorEnvelopeSchema.safeParse({
          error: {
            ...(isRetryableRefusalCode(code) ? { retryable: false } : {}),
            ...(code === "host.agent_access_off" ? { retryable: false } : {}),
            ...(code === "host.node_offline" ? { retryable: true, retryAfterSeconds: 5 } : {}),
            ...(code === "host.file_error" ? { data: { reason: "path_denied" } } : {}),
            ...(code === "sandbox.key_limit_reached"
              ? { data: { maxLiveSandboxes: 2, liveSandboxes: 2 } }
              : {}),
            ...(code === "sandbox.host_capacity" || code === "sandbox.pool_full"
              ? { reason: "ram" }
              : {}),
            ...(code === "sandbox.share_quota" || code === "sandbox.member_quota"
              ? { resource: "memory" }
              : {}),
            ...(code === "lease_exceeds_policy" ? { maxTimeoutMs: 21_600_000 } : {}),
            ...(code === "sandbox.capture_unsupported" ? { reason: "storage" } : {}),
            ...(code === "sandbox.image_quota_exceeded" ? { scope: "stored" } : {}),
            ...(code === "capacity_wait_exceeds_policy" ? { maxWaitMs: 3_600_000 } : {}),
            ...(code === "sandbox.capacity_queue_full" ? { scope: "key" } : {}),
            ...(BUILD_EXTRAS_FIXTURE[code] ?? {}),
            code,
            message: "m",
            requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19",
          },
        }).success,
        code,
      ).toBe(true);
    }
  });
});

describe("lease limits (shared with crates/sandbox-protocol)", () => {
  it("exports the shared JSON values", async () => {
    const limits = JSON.parse(readFileSync(new URL("lease-limits.json", srcDir), "utf8"));
    const mod = await import("./lease-limits");
    expect(limits).toEqual({
      limitMinMs: 300_000,
      finiteMaxMs: 2_073_600_000,
      unlimitedDeadlineMs: 253_402_300_799_999,
    });
    expect(mod.LEASE_LIMIT_MIN_MS).toBe(limits.limitMinMs);
    expect(mod.LEASE_FINITE_MAX_MS).toBe(limits.finiteMaxMs);
    expect(mod.LEASE_UNLIMITED_DEADLINE_MS).toBe(limits.unlimitedDeadlineMs);
    expect(new Date(mod.LEASE_UNLIMITED_DEADLINE_MS).toISOString()).toBe(
      "9999-12-31T23:59:59.999Z",
    );
    // The finite maximum fits the Int4 leaseTimeoutMs column.
    expect(mod.LEASE_FINITE_MAX_MS).toBeLessThanOrEqual(2_147_483_647);
  });
  it("recognizes the far-future end in every representation", async () => {
    const { isUnlimitedLeaseEnd, LEASE_UNLIMITED_DEADLINE_MS } = await import("./lease-limits");
    expect(isUnlimitedLeaseEnd("9999-12-31T23:59:59.999Z")).toBe(true);
    expect(isUnlimitedLeaseEnd(new Date(LEASE_UNLIMITED_DEADLINE_MS))).toBe(true);
    expect(isUnlimitedLeaseEnd(LEASE_UNLIMITED_DEADLINE_MS)).toBe(true);
    expect(isUnlimitedLeaseEnd(LEASE_UNLIMITED_DEADLINE_MS - 1)).toBe(false);
    expect(isUnlimitedLeaseEnd("2026-01-01T00:00:00.000Z")).toBe(false);
    expect(isUnlimitedLeaseEnd(null)).toBe(false);
    expect(isUnlimitedLeaseEnd(undefined)).toBe(false);
    expect(isUnlimitedLeaseEnd("not a date")).toBe(false);
  });
  it("carries a bounded maximum on lease_exceeds_policy", () => {
    const base = {
      code: "lease_exceeds_policy",
      message: "m",
      requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19",
    };
    expect(sdkErrorEnvelopeSchema.safeParse({ error: base }).success).toBe(false);
    for (const maxTimeoutMs of [299_999, 2_073_600_001, 1.5])
      expect(sdkErrorEnvelopeSchema.safeParse({ error: { ...base, maxTimeoutMs } }).success).toBe(
        false,
      );
    expect(
      sdkErrorEnvelopeSchema.safeParse({ error: { ...base, maxTimeoutMs: 300_000 } }).success,
    ).toBe(true);
  });
  it("E2-B-01 declares the entry and path of credential.value_invalid", () => {
    const base = {
      code: "credential.value_invalid",
      message: "m",
      requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19",
    };
    const parse = (extra: Record<string, unknown>) =>
      sdkErrorEnvelopeSchema.safeParse({ error: { ...base, ...extra } }).success;
    expect(parse({})).toBe(true);
    expect(parse({ entry: "bundle.undeclared_path", path: ".fakecli" })).toBe(true);
    expect(parse({ entry: "env.TOOL_API_KEY" })).toBe(true);
    // Typed and bounded; still strict about anything undeclared.
    expect(parse({ entry: "a\nb" })).toBe(false);
    expect(parse({ path: 7 })).toBe(false);
    expect(parse({ entry: "x".repeat(513) })).toBe(false);
    expect(parse({ entry: "env.X", value: "secret" })).toBe(false);
    // Another code never carries them.
    expect(
      sdkErrorEnvelopeSchema.safeParse({ error: { ...base, code: "credential.busy", entry: "e" } })
        .success,
    ).toBe(false);
  });
});

describe("guest paths (TQ-N2, E-28)", () => {
  // Every rejected form, against the host's validate_guest_path and the guest
  // file helper (crates/sandbox-runtime/src/incus/{client.rs,file-helper.py}).
  const anyOperation = [
    "",
    "   ",
    "relative",
    "../etc",
    "/a/../b",
    "/a/..",
    "/a\0b",
    "/a\ud800b",
    // G4R1-1: refused, never trimmed.
    " /tmp/x",
    "/tmp/x ",
    "\t/tmp/x",
    "\n/tmp/x",
    "/tmp/x\n",
  ];
  const fileOnly = ["/a/./b", "/a/.", "/.", "/", "//", "/a\nb", "/a\u007fb"];
  const tooLong = [`/${"a".repeat(4096)}`, `/${"é".repeat(2048)}`];
  it("refuses exactly the shared leading/trailing whitespace set (B2-K-5)", () => {
    for (const point of pathWhitespace.whitespace) {
      const char = String.fromCodePoint(point);
      expect(guestPathSchema.safeParse(`/tmp/x${char}`).success, String(point)).toBe(false);
      expect(guestPathSchema.safeParse(`${char}/tmp/x`).success, String(point)).toBe(false);
    }
    for (const point of pathWhitespace.notWhitespace)
      expect(guestPathSchema.safeParse(`/tmp/x${String.fromCodePoint(point)}`).success).toBe(true);
  });
  it("refuses each form with one rule for every file operation and a stricter one for file bytes", () => {
    for (const path of [...anyOperation, ...tooLong])
      expect(guestPathSchema.safeParse(path).success, JSON.stringify(path)).toBe(false);
    for (const path of fileOnly)
      expect(guestPathSchema.safeParse(path).success, JSON.stringify(path)).toBe(true);
    for (const path of [...anyOperation, ...fileOnly, ...tooLong]) {
      expect(guestFilePathSchema.safeParse(path).success, JSON.stringify(path)).toBe(false);
      expect(downloadBodySchema.safeParse({ path }).success, JSON.stringify(path)).toBe(false);
      expect(
        transferCreateSchema.safeParse({
          sandboxId: "s",
          direction: "UPLOAD",
          guestPath: path,
          totalBytes: 1,
          idempotencyKey: "k",
        }).success,
        JSON.stringify(path),
      ).toBe(false);
    }
  });
  it("keeps internal spaces and dotted names exactly as sent", () => {
    for (const schema of [guestPathSchema, guestEntryPathSchema, guestFilePathSchema]) {
      expect(schema.parse("/tmp/my report.txt")).toBe("/tmp/my report.txt");
      expect(schema.parse("/tmp/a..b/..c/.hidden")).toBe("/tmp/a..b/..c/.hidden");
      expect(schema.parse(`/${"a".repeat(4095)}`)).toHaveLength(4096);
    }
  });
  it("refuses `/` as an entry (G4R1-2) and in the SDK bodies of mkdir, move and remove", () => {
    expect(guestPathSchema.safeParse("/").success).toBe(true);
    expect(guestEntryPathSchema.safeParse("/").success).toBe(false);
    expect(mkdirBodySchema.safeParse({ path: "/" }).success).toBe(false);
    expect(removeBodySchema.safeParse({ path: "/" }).success).toBe(false);
    expect(moveBodySchema.safeParse({ path: "/a", destPath: "/" }).success).toBe(false);
    for (const path of [" /a", "/a "]) {
      expect(statBodySchema.safeParse({ path }).success).toBe(false);
      expect(moveBodySchema.safeParse({ path: "/a", destPath: path }).success).toBe(false);
    }
  });
});

it("3C1 relative lifetime contracts reject absolute leases and invalid durations", async () => {
  const { createSandboxBodySchema, reconnectBodySchema, renewBodySchema } = await import(
    "./mutations"
  );
  for (const timeoutMs of [-1, 0.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 1e300]) {
    expect(
      createSandboxBodySchema.safeParse({
        template: "revision/" + "t",
        sandboxHostId: "h",
        timeoutMs,
      }).success,
    ).toBe(false);
    expect(reconnectBodySchema.safeParse({ timeoutMs }).success).toBe(false);
    expect(renewBodySchema.safeParse({ timeoutMs }).success).toBe(false);
  }
  expect(
    createSandboxBodySchema.safeParse({
      template: "revision/" + "t",
      sandboxHostId: "h",
      leaseExpiresAt: "2026-01-01T01:00:00Z",
    }).success,
  ).toBe(false);
  expect(renewBodySchema.safeParse({ leaseExpiresAt: "2026-01-01T01:00:00Z" }).success).toBe(false);
  // 0 (no lease timer) and finite values past 24h are policy decisions, not
  // shape errors: the server answers lease_exceeds_policy with the maximum.
  // That includes well-formed integers above the 24-day finite ceiling.
  for (const timeoutMs of [0, 86_400_001, 2_073_600_000, 2_073_600_001, 2 ** 40]) {
    expect(renewBodySchema.safeParse({ timeoutMs }).success).toBe(true);
    expect(reconnectBodySchema.safeParse({ timeoutMs }).success).toBe(true);
  }
  const { leaseTimeoutBeyondFiniteMax } = await import("./mutations");
  expect(leaseTimeoutBeyondFiniteMax(2_073_600_001)).toBe(true);
  for (const value of [2_073_600_000, 0, 1.5, -1, Number.MAX_SAFE_INTEGER + 1, "3000000000"])
    expect(leaseTimeoutBeyondFiniteMax(value)).toBe(false);
  expect(reconnectBodySchema.safeParse({}).success).toBe(true);
  expect(reconnectBodySchema.safeParse({ onExpire: "stop" }).success).toBe(false);
  expect(
    createSandboxBodySchema.safeParse({ template: "revision/" + "t", sandboxHostId: "h" }).success,
  ).toBe(true);
  expect(renewBodySchema.safeParse({ timeoutMs: 1 }).success).toBe(true);
});

it("guestSudo is an optional boolean with no schema default (the service resolves it)", async () => {
  const { createSandboxBodySchema } = await import("./mutations");
  const base = { template: "revision/" + "template", sandboxHostId: "host" };
  expect("guestSudo" in createSandboxBodySchema.parse(base)).toBe(false);
  expect(createSandboxBodySchema.parse({ ...base, guestSudo: false }).guestSudo).toBe(false);
  expect(createSandboxBodySchema.parse({ ...base, guestSudo: true }).guestSudo).toBe(true);
  expect(createSandboxBodySchema.safeParse({ ...base, guestSudo: "yes" }).success).toBe(false);
});

it("3D create envs are bounded unique private defaults with reserved guest identity", async () => {
  const { createSandboxBodySchema } = await import("./mutations");
  const base = { template: "revision/" + "template", sandboxHostId: "host" };
  expect(createSandboxBodySchema.parse({ ...base, envs: { APP: " a\nb " } }).envs).toEqual({
    APP: " a\nb ",
  });
  for (const envs of [
    { HOME: "x" },
    { SHELL: "x" },
    { TERM: "x" },
    { APP: "x".repeat(4097) },
    Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`K${i}`, "v"])),
    [["APP", "x"]],
    JSON.parse('{"__proto__":"x"}'),
  ])
    expect(createSandboxBodySchema.safeParse({ ...base, envs }).success).toBe(false);
});

it("pool/direct create is XOR in strict validation and generated OpenAPI", async () => {
  const { createSandboxBodySchema } = await import("./mutations");
  const base = { template: "base" };
  expect(createSandboxBodySchema.safeParse({ ...base, poolId: "pool" }).success).toBe(true);
  expect(createSandboxBodySchema.safeParse({ ...base, sandboxHostId: "host" }).success).toBe(true);
  expect(createSandboxBodySchema.safeParse(base).success).toBe(false);
  expect(
    createSandboxBodySchema.safeParse({ ...base, poolId: "pool", sandboxHostId: "host" }).success,
  ).toBe(false);
  // A direct create with a wait parses: the service refuses it with a typed
  // capacity_wait_exceeds_policy (maxWaitMs 0), not a generic invalid request.
  expect(
    createSandboxBodySchema.safeParse({ ...base, sandboxHostId: "host", waitForCapacityMs: 60_000 })
      .success,
  ).toBe(true);
  const doc = buildSdkOpenApiDocument();
  expect(doc).toMatchObject({
    paths: {
      "/v1/sandboxes": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  oneOf: [
                    { required: ["poolId"], not: { required: ["sandboxHostId"] } },
                    { required: ["sandboxHostId"], not: { required: ["poolId"] } },
                  ],
                },
              },
            },
          },
        },
      },
    },
  });
});

it("activates strict disk create/DTO fields", async () => {
  const { createSandboxBodySchema } = await import("./mutations");
  const { hostSchema, sandboxSchema, templateRevisionSchema, hostCapacitySchema } = await import(
    "./dto"
  );
  const base = { template: "base:latest", sandboxHostId: "host" };
  expect(createSandboxBodySchema.parse(base)).toEqual(base);
  expect(createSandboxBodySchema.parse({ ...base, diskGiB: 32 })).toEqual({
    ...base,
    diskGiB: 32,
  });
  expect(createSandboxBodySchema.safeParse({ ...base, diskGiB: 32 }).success).toBe(true);
  for (const diskGiB of [null, 0, 2049, 1.5]) {
    expect(createSandboxBodySchema.safeParse({ ...base, diskGiB }).success).toBe(false);
  }
  expect(createSandboxBodySchema.safeParse({ ...base, poolId: "pool", diskGiB: 32 }).success).toBe(
    false,
  );
  expect(templateRevisionSchema.shape.defaultDiskGiB.safeParse(32).success).toBe(true);
  expect(templateRevisionSchema.shape.minDiskGiB.safeParse(8).success).toBe(true);
  expect(templateRevisionSchema.shape).not.toHaveProperty("diskGiB");
  expect(sandboxSchema.shape.storageMarker.safeParse(null).success).toBe(true);
  expect(sandboxSchema.shape.storageMarker.safeParse("/host/path").success).toBe(false);
  expect(hostSchema.shape).not.toHaveProperty("maxLiveSandboxes");
  expect(hostSchema.shape).not.toHaveProperty("liveCount");
  expect(hostCapacitySchema.shape).not.toHaveProperty("liveSandboxLimit");
  expect(
    hostSchema.shape.storagePools.safeParse(Array.from({ length: 17 }, () => ({}))).success,
  ).toBe(false);
});

it("stages independent revision disk inputs without inheriting a previous revision", async () => {
  const { templateBodySchema, appendTemplateRevisionBodySchema } = await import("./mutations");
  const { vmRevisionSizeSchema } = await import("./vm-size");
  const input = { hostId: "host", slug: "base", label: "Base", imageRef: "images:base" };
  expect(templateBodySchema.parse(input)).not.toHaveProperty("defaultDiskGiB");
  expect(templateBodySchema.safeParse({ ...input, diskGiB: 64 }).success).toBe(false);
  expect(templateBodySchema.parse({ ...input, defaultDiskGiB: 64 }).defaultDiskGiB).toBe(64);
  const { slug: _slug, label: _label, ...append } = input;
  expect(
    appendTemplateRevisionBodySchema.parse({ ...append, defaultDiskGiB: 32, minDiskGiB: 8 }),
  ).toMatchObject({ defaultDiskGiB: 32, minDiskGiB: 8 });
  expect(appendTemplateRevisionBodySchema.safeParse({ ...append, defaultDiskGiB: 0 }).success).toBe(
    false,
  );
  // The floor defaults to the default and never exceeds it.
  expect(vmRevisionSizeSchema.parse({})).toEqual({
    cpuCount: 1,
    memoryMiB: 1024,
    defaultDiskGiB: 32,
    minDiskGiB: 32,
  });
  expect(vmRevisionSizeSchema.parse({ defaultDiskGiB: 16, minDiskGiB: 8 })).toMatchObject({
    defaultDiskGiB: 16,
    minDiskGiB: 8,
  });
  expect(vmRevisionSizeSchema.safeParse({ defaultDiskGiB: 8, minDiskGiB: 16 }).success).toBe(false);
});
