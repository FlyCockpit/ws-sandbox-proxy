import {
  isRetryableRefusalCode,
  RETRYABLE_REFUSAL_CODES,
  SDK_ERROR_CODES,
  SDK_ERRORS,
  type SdkErrorCode,
} from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";
import { isWsspError, WSSP_ERROR_KINDS, WsspError, type WsspErrorKind } from "./errors";
import {
  createWsspTransport,
  type FetchLike,
  MAX_REDIRECTS,
  RESPONSE_MAX_BYTES,
} from "./transport";

const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test/prefix";
const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const NOW = "2026-01-01T00:00:00.000Z";

const sandbox = {
  acceptedGraceSeconds: 0,
  accessGraceUntil: null,
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
  state: "READY",
  generation: 1,
  endAt: null,
  startedAt: null,
  readyAt: null,
  lifecycle: { onTimeout: "kill", autoResume: false },
  sandboxDomain: null,
  portExposure: null,
  lease: {
    revision: 0,
    expiresAt: null,
    onExpire: "stop",
    requested: null,
    effective: null,
  },
  metadata: {},
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
  createdAt: NOW,
  updatedAt: NOW,
};

const receipt = { operationId: "op_1", state: "QUEUED", location: "/v1/operations/op_1" };

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": REQUEST_ID, ...headers },
  });
}

/** The required typed fields of the `template.build_*` refusals. */
const BUILD_FIELDS: Partial<Record<SdkErrorCode, Record<string, unknown>>> = {
  "template.build_disabled": { reason: "lease_ceiling" },
  "template.build_recipe_invalid": { recipeCode: "dockerfile_syntax", line: 3, column: 7 },
  "template.build_no_builder": { skipped: { builder: true, capture_policy: false, lease: true } },
  "template.build_concurrency": { maxConcurrent: 2 },
  "template.build_minutes_exhausted": { minutesPerMonth: 1000 },
  "template.build_context_too_large": { maxBytes: 1024 },
  "template.build_context_busy": { scope: "global" },
  "template.build_not_cancellable": { state: "FAILED" },
  "template.community_unavailable": { reason: "index_unreachable" },
};

function envelope(code: SdkErrorCode, extra: Record<string, unknown> = {}): Response {
  const [status, message] = SDK_ERRORS[code];
  return json(status, {
    error: {
      ...(isRetryableRefusalCode(code) ? { retryable: true } : {}),
      ...(code === "host.agent_access_off" ? { retryable: false } : {}),
      ...(code === "host.node_offline" ? { retryable: true, retryAfterSeconds: 5 } : {}),
      ...(code === "host.file_error" ? { data: { reason: "path_denied" } } : {}),
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
      ...(BUILD_FIELDS[code] ?? {}),
      code,
      message,
      requestId: REQUEST_ID,
      ...extra,
    },
  });
}

function expectedReason(code: SdkErrorCode): string | null {
  if (code === "host.file_error") return "path_denied";
  if (code === "sandbox.host_capacity" || code === "sandbox.pool_full") return "ram";
  if (code === "sandbox.capture_unsupported") return "storage";
  if (code === "sandbox.image_quota_exceeded") return "stored";
  return null;
}

function redirect(status: number, location: string | null): Response {
  return new Response(null, { status, headers: location ? { location } : {} });
}

type Call = { url: string; init: RequestInit };

function transportWith(...responses: Array<Response | ((call: Call) => Promise<Response>)>) {
  const calls: Call[] = [];
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    const call = { url, init };
    calls.push(call);
    const next = responses.shift();
    if (!next) throw new Error("no response queued");
    return typeof next === "function" ? next(call) : next;
  });
  return { transport: createWsspTransport({ baseUrl: BASE, apiKey: KEY, fetch }), calls, fetch };
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

/** A response whose fetch settles only when its signal aborts. */
function hangs(call: Call): Promise<Response> {
  return new Promise((_, reject) => {
    call.init.signal?.addEventListener("abort", () =>
      reject(new DOMException("This operation was aborted", "AbortError")),
    );
  });
}

const stop = (transport: ReturnType<typeof transportWith>["transport"]) =>
  transport.request("stopSandbox", { params: { id: "sbx_1" }, idempotencyKey: "stop-1" });
const read = (transport: ReturnType<typeof transportWith>["transport"]) =>
  transport.request("getSandbox", { params: { id: "sbx_1" } });

describe("configuration", () => {
  it.each([
    ["http://api.example.test", /https/],
    ["https://user:pass@api.example.test", /credentials/],
    ["https://api.example.test/?token=x", /query/],
    ["https://api.example.test/#x", /fragment/],
    ["not a url", /absolute URL/],
  ])("rejects base URL %s without echoing it", (baseUrl, message) => {
    const error = (() => {
      try {
        createWsspTransport({ baseUrl, apiKey: KEY });
      } catch (e) {
        return e as Error;
      }
      throw new Error("expected a throw");
    })();
    expect(error).toBeInstanceOf(TypeError);
    expect(error.message).toMatch(message);
    expect(error.message).not.toContain(baseUrl);
  });

  it.each(["http://localhost:3000", "http://127.0.0.1", "http://[::1]:8080/", BASE])(
    "accepts %s",
    (baseUrl) => {
      expect(() => createWsspTransport({ baseUrl, apiKey: KEY })).not.toThrow();
    },
  );

  it.each(["wssp_host_abc", "Bearer wssp_sdk_abc", "wssp_sdk_", "wssp_sdk_a b"])(
    "rejects key %s without echoing it",
    (apiKey) => {
      expect(() => createWsspTransport({ baseUrl: BASE, apiKey })).toThrow(
        /^apiKey must be a wssp_sdk_ key\.$/,
      );
    },
  );

  it("rejects out-of-range timeouts", () => {
    expect(() => createWsspTransport({ baseUrl: BASE, apiKey: KEY, timeoutMs: 0 })).toThrow(
      TypeError,
    );
  });
});

describe("requests", () => {
  it("sends a bearer read with manual redirects and no cookies", async () => {
    const { transport, calls } = transportWith(json(200, sandbox));
    await expect(read(transport)).resolves.toEqual(sandbox);
    expect(calls).toHaveLength(1);
    const [call] = calls;
    expect(call?.url).toBe("https://api.example.test/prefix/v1/sandboxes/sbx_1");
    expect(call?.init).toMatchObject({
      method: "GET",
      redirect: "manual",
      credentials: "omit",
      body: undefined,
    });
    expect(call?.init.headers).toEqual({
      accept: "application/json",
      authorization: `Bearer ${KEY}`,
    });
  });

  it("encodes the page query as wire strings", async () => {
    const { transport, calls } = transportWith(json(200, { items: [], nextCursor: null }));
    await transport.request("listSandboxes", { query: { limit: "5", cursor: "abc" } });
    expect(calls[0]?.url).toBe("https://api.example.test/prefix/v1/sandboxes?limit=5&cursor=abc");
  });

  it("sends a mutation with its idempotency key and JSON body, returning the receipt", async () => {
    const { transport, calls } = transportWith(json(202, receipt, { location: receipt.location }));
    const body = {
      template: "revision/" + "tpl_1",
      sandboxHostId: "host_1",
      metadata: { a: "1" },
      envs: { APP: "synthetic-create-env" },
    };
    await expect(
      transport.request("createSandbox", { body, idempotencyKey: "create-1" }),
    ).resolves.toEqual(receipt);
    expect(calls[0]?.url).toBe("https://api.example.test/prefix/v1/sandboxes");
    expect(calls[0]?.init.method).toBe("POST");
    expect(calls[0]?.init.body).toBe(JSON.stringify(body));
    expect(calls[0]?.init.headers).toMatchObject({
      "content-type": "application/json",
      "idempotency-key": "create-1",
    });
  });

  it.each([
    ["a path-traversal ID", () => ({ params: { id: "../hosts" } })],
    ["an undeclared query parameter", () => ({ params: { id: "sbx_1" }, query: { token: "x" } })],
  ])("refuses %s locally", async (_label, input) => {
    const { transport, fetch } = transportWith();
    const error = await failure(
      transport.request("getSandbox", input() as { params: { id: string } }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses a mutation without a valid idempotency key or body locally", async () => {
    const { transport, fetch } = transportWith();
    const noKey = await failure(
      transport.request("stopSandbox", { params: { id: "sbx_1" }, idempotencyKey: "" }),
    );
    const badBody = await failure(
      transport.request("createSandbox", {
        body: { template: "revision/" + "tpl_1", sandboxHostId: "host_1", extra: true } as never,
        idempotencyKey: "k",
      }),
    );
    expect([noKey.kind, badBody.kind]).toEqual(["invalid_request", "invalid_request"]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses a well-formed lease above the 24-day ceiling locally as lease_exceeds_policy", async () => {
    const { transport, fetch } = transportWith();
    const over = 2_073_600_001;
    const errors = [
      await failure(
        transport.request("createSandbox", {
          body: { template: "revision/" + "tpl_1", sandboxHostId: "host_1", timeoutMs: over },
          idempotencyKey: "k",
        }),
      ),
      await failure(
        transport.request("renewSandboxLease", {
          params: { id: "sbx_1" },
          body: { timeoutMs: over },
          idempotencyKey: "k",
        }),
      ),
      await failure(
        transport.request("reconnectSandbox", {
          params: { id: "sbx_1" },
          body: { timeoutMs: over },
          idempotencyKey: "k",
        }),
      ),
    ];
    for (const error of errors)
      expect(error).toMatchObject({
        kind: "invalid_request",
        code: "lease_exceeds_policy",
        maxTimeoutMs: 2_073_600_000,
      });
    // Malformed values remain shape errors with no catalog code.
    for (const timeoutMs of [1.5, -1]) {
      const malformed = await failure(
        transport.request("renewSandboxLease", {
          params: { id: "sbx_1" },
          body: { timeoutMs },
          idempotencyKey: "k",
        }),
      );
      expect(malformed).toMatchObject({ kind: "invalid_request", code: null });
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("names the failing body field without echoing its value (E-23)", async () => {
    const { transport, fetch } = transportWith();
    const error = await failure(
      transport.request("startCommand", {
        params: { id: "sbx_1" },
        body: { argv: ["env"], envs: { FOO: ["secret-canary"] } } as never,
        idempotencyKey: "cmd-1",
      }),
    );
    expect(error.kind).toBe("invalid_request");
    expect(error.message).toMatch(/route schema \(.*\benvs: custom\b.*\)\.$/);
    expect(error.message).not.toContain("secret-canary");
    expect(error.message).not.toContain("FOO");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([0, 1.5, -10, Number.MAX_SAFE_INTEGER])(
    "rejects a per-request timeoutMs of %s as a typed invalid_request error",
    async (timeoutMs) => {
      const { transport, fetch } = transportWith();
      const error = await failure(
        transport.request("getSandbox", { params: { id: "sbx_1" }, timeoutMs }),
      );
      expect(isWsspError(error, "invalid_request")).toBe(true);
      expect(error.message).toContain("timeoutMs");
      const mutationError = await failure(
        transport.request("stopSandbox", {
          params: { id: "sbx_1" },
          idempotencyKey: "stop-1",
          timeoutMs,
        }),
      );
      expect(isWsspError(mutationError, "invalid_request")).toBe(true);
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});

/** Expected read kind; mutations turn ambiguous 5xx errors into `unknown`. */
const READ_KIND: Record<SdkErrorCode, WsspErrorKind> = {
  "host.not_owned": "authorization",
  "host.agent_access_off": "conflict",
  "host.node_offline": "unavailable",
  "host.command_not_found": "not_found",
  "host_queue.limit": "capacity",
  "host.file_error": "invalid_request",
  "host.file_outcome_unknown": "unknown",
  OPERATION_RESULT_EXPIRED: "gone",
  OPERATION_RESULT_NOT_READY: "conflict",
  OPERATION_RESULT_QUOTA: "capacity",
  OPERATION_RESULT_UNSUPPORTED: "unsupported",
  RESULT_CURSOR_INVALID: "invalid_request",
  RESULT_CURSOR_STALE: "conflict",
  "sandbox.process_not_found": "not_found",
  "sandbox.process_exited": "conflict",
  "sandbox.process_stale": "conflict",
  "sandbox.process_not_started": "conflict",
  "sandbox.process_stdin_closed": "conflict",
  "sandbox.process_cancel_pending": "conflict",
  "sandbox.process_permission_denied": "conflict",
  "sandbox.process_unknown_outcome": "unknown",
  "sandbox.process_unavailable": "unavailable",

  "sandbox.vm_size_invalid": "invalid_request",
  "sandbox.vm_size_unsupported": "unsupported",
  "sandbox.vm_size_mismatch": "conflict",
  "sandbox.disk_below_image": "invalid_request",
  "sandbox.metadata_invalid": "invalid_request",
  "sandbox.egress_policy_invalid": "invalid_request",
  lease_exceeds_policy: "invalid_request",
  digest_key_changed: "conflict",
  digest_key_unavailable: "conflict",
  "sandbox.host_reconnecting": "unavailable",
  receipt_digest_pruned: "conflict",
  BAD_REQUEST: "invalid_request",
  UNAUTHORIZED: "authorization",
  FORBIDDEN: "authorization",
  NOT_FOUND: "not_found",
  METHOD_NOT_SUPPORTED: "unsupported",
  CONFLICT: "conflict",
  PAYLOAD_TOO_LARGE: "invalid_request",
  UNSUPPORTED_MEDIA_TYPE: "invalid_request",
  TOO_MANY_REQUESTS: "capacity",
  INTERNAL_SERVER_ERROR: "unavailable",
  SERVICE_UNAVAILABLE: "unavailable",
  GATEWAY_TIMEOUT: "timeout",
  "sandbox.idempotency_conflict": "conflict",
  "sandbox.state_conflict": "conflict",
  "sandbox.managed": "conflict",
  "sandbox.template_not_found": "not_found",
  "sandbox.template_in_use": "conflict",
  "sandbox.template_image_missing": "conflict",
  "sandbox.template_unavailable": "conflict",
  capacity_wait_exceeds_policy: "invalid_request",
  "sandbox.capacity_queue_full": "capacity",
  "sandbox.template_image_rejected": "invalid_request",
  "sandbox.template_revision_exists": "conflict",
  "sandbox.template_image_unavailable": "unavailable",
  "sandbox.template_store_unavailable": "unavailable",
  "sandbox.capture_unsupported": "unsupported",
  "sandbox.capture_policy_forbidden": "conflict",
  "sandbox.capture_busy": "conflict",
  "sandbox.disk_evicting": "conflict",
  "sandbox.restoring": "conflict",
  restore_no_allowed_host: "conflict",
  "sandbox.disk_offloaded": "conflict",
  "sandbox.disk_unavailable": "unavailable",
  "sandbox.host_forget_unsafe": "conflict",
  "sandbox.capture_invalid": "invalid_request",
  "sandbox.image_quota_exceeded": "capacity",
  "sandbox.host_not_found": "not_found",
  "sandbox.pool_not_found": "not_found",
  "sandbox.pool_no_compatible_host": "conflict",
  "sandbox.pool_unavailable": "unavailable",
  "sandbox.share_quota": "conflict",
  "sandbox.member_quota": "conflict",
  "sandbox.pool_policy_changed": "conflict",
  "sandbox.pool_full": "capacity",
  "sandbox.host_capacity": "capacity",
  "sandbox.host_draining": "conflict",
  "sandbox.host_delete_conflict": "conflict",
  "sandbox.host_unavailable": "unavailable",
  host_runtime_unsupported: "unsupported",
  "sandbox.not_found": "not_found",
  "sandbox.operation_not_found": "not_found",
  "sandbox.invalid_transition": "conflict",
  UNSUPPORTED_CAPABILITY: "unsupported",
  TRANSFER_EXPIRED: "gone",
  TRANSFER_QUOTA: "capacity",
  TRANSFER_IO: "unavailable",
  TRANSFER_NOT_READY: "conflict",
  RANGE_NOT_SATISFIABLE: "invalid_request",
  OUTPUT_EXPIRED: "gone",
  "webhook.endpoint_not_found": "not_found",
  "webhook.delivery_not_found": "not_found",
  "webhook.destination_invalid": "invalid_request",
  "webhook.destination_blocked": "invalid_request",
  "webhook.endpoint_limit": "capacity",
  "webhook.endpoint_disabled": "conflict",
  "webhook.event_expired": "gone",
  "template.build_disabled": "unsupported",
  "template.build_recipe_invalid": "invalid_request",
  "template.build_no_builder": "capacity",
  "template.build_concurrency": "capacity",
  "template.build_minutes_exhausted": "capacity",
  "template.build_context_required": "invalid_request",
  "template.build_context_too_large": "invalid_request",
  "template.build_context_busy": "capacity",
  "template.build_context_mismatch": "invalid_request",
  "template.build_not_cancellable": "conflict",
  "template.build_egress_mode_unavailable": "unsupported",
  "template.community_key_scope": "authorization",
  "template.community_unavailable": "unavailable",
  "template.community_managed": "conflict",
  "credential.not_found": "not_found",
  "credential.account_not_found": "not_found",
  "credential.instance_not_found": "not_found",
  "credential.lease_not_found": "not_found",
  "credential.definition_not_found": "not_found",
  "credential.in_use": "conflict",
  "credential.account_paused": "conflict",
  "credential.needs_login": "conflict",
  "credential.limit_reached": "capacity",
  "credential.unavailable": "unsupported",
  "credential.repin_blocked": "conflict",
  "credential.repin_confirm_erase": "invalid_request",
  "credential.value_invalid": "invalid_request",
  "credential.definition_corrupt": "conflict",
  "credential.name_taken": "conflict",
  "sandbox.name_invalid": "invalid_request",
  "sandbox.name_taken": "conflict",
  "credential.busy": "conflict",
  "credential.spec_too_large": "invalid_request",
  "credential.pending_drain": "conflict",
  "credential.recovery_required": "conflict",
  "credential.host_forbidden": "conflict",
  "credential.env_conflict": "conflict",
  "credential.path_conflict": "conflict",
  "credential.proxy_not_enabled": "conflict",
  "credential.not_attached": "not_found",
  "credential.already_attached": "conflict",
  "credential.capture_in_progress": "conflict",
  "credential.login_needs_consent": "conflict",
  "credential.login_requires_upload": "conflict",
  "credential.login_session_not_found": "not_found",
  "credential.login_state": "conflict",
  "definition.invalid": "invalid_request",
  "definition.spec_too_large": "invalid_request",
  "definition.schema_version_unsupported": "invalid_request",
};

describe("HTTP status and error matrix", () => {
  it.each(SDK_ERROR_CODES)("classifies %s on a read and a mutation", async (code) => {
    const status = SDK_ERRORS[code][0];
    // A pre-commit 5xx refusal proves the mutation did not happen.
    const preCommit = code === "sandbox.host_reconnecting";
    const r = transportWith(envelope(code), envelope(code));
    const readError = await failure(read(r.transport));
    expect(readError).toMatchObject({
      kind: READ_KIND[code],
      code,
      status,
      requestId: REQUEST_ID,
      route: "getSandbox",
      reason: expectedReason(code),
      idempotencyKey: null,
    });
    const mutationError = await failure(stop(r.transport));
    expect(mutationError).toMatchObject({
      kind: status >= 500 && !preCommit ? "unknown" : READ_KIND[code],
      code,
      status,
      route: "stopSandbox",
      idempotencyKey: "stop-1",
      reason: status >= 500 && !preCommit ? "server_error" : expectedReason(code),
    });
    expect(WSSP_ERROR_KINDS).toContain(readError.kind);
    // Build refusals carry their typed fields on `build`, nowhere else.
    expect(readError.build).toEqual(BUILD_FIELDS[code] ?? null);
    expect(readError.retryable).toBe(
      code === "host.agent_access_off"
        ? false
        : code === "host.node_offline" || isRetryableRefusalCode(code)
          ? true
          : null,
    );
  });

  it("keeps expired content, missing resources and unknown outcomes distinct", async () => {
    const { transport } = transportWith(
      envelope("OUTPUT_EXPIRED"),
      envelope("sandbox.operation_not_found"),
      envelope("INTERNAL_SERVER_ERROR"),
    );
    const output = (id: string) => transport.request("getCommandOutput", { params: { id } });
    const kinds = [
      (await failure(output("op_1"))).kind,
      (await failure(output("op_2"))).kind,
      (await failure(stop(transport))).kind,
    ];
    expect(kinds).toEqual(["gone", "not_found", "unknown"]);
  });

  it("carries the lease policy maximum", async () => {
    const { transport } = transportWith(envelope("lease_exceeds_policy"));
    const error = await failure(stop(transport));
    expect(error).toMatchObject({
      kind: "invalid_request",
      code: "lease_exceeds_policy",
      status: 400,
      maxTimeoutMs: 21_600_000,
    });
    expect(error.toJSON()).toMatchObject({ maxTimeoutMs: 21_600_000 });
  });

  it("refuses a lease policy envelope without its maximum", async () => {
    const { transport } = transportWith(
      json(400, {
        error: {
          code: "lease_exceeds_policy",
          message: SDK_ERRORS.lease_exceeds_policy[1],
          requestId: REQUEST_ID,
        },
      }),
    );
    const error = await failure(read(transport));
    expect(error.code).toBeNull();
  });

  it("carries the throttling delay", async () => {
    const { transport } = transportWith(envelope("TOO_MANY_REQUESTS", { retryAfterSeconds: 7 }));
    expect(await failure(read(transport))).toMatchObject({
      kind: "capacity",
      retryAfterSeconds: 7,
    });
  });

  it("uses the catalog message, never the server-supplied text", async () => {
    const { transport } = transportWith(
      json(404, {
        error: { code: "sandbox.not_found", message: "leaked internals", requestId: REQUEST_ID },
      }),
    );
    const error = await failure(stop(transport));
    expect(error.message).toBe("stopSandbox: Sandbox not found. (sandbox.not_found, HTTP 404)");
  });

  it.each([
    ["an envelope whose status disagrees with the catalog", () => json(500, envelope404Body())],
    ["a non-JSON proxy page", () => new Response("<html>bad gateway</html>", { status: 502 })],
    ["an unexpected 2xx", () => json(201, {})],
  ])("treats %s as non-definitive", async (_label, response) => {
    const r = transportWith(response(), response());
    const readError = await failure(read(r.transport));
    expect(readError.code).toBeNull();
    expect(["protocol", "unavailable"]).toContain(readError.kind);
    const mutationError = await failure(stop(r.transport));
    expect(mutationError).toMatchObject({ kind: "unknown", code: null, idempotencyKey: "stop-1" });
  });

  it("maps uncataloged gateway statuses on reads", async () => {
    const { transport } = transportWith(
      new Response("timeout", { status: 504 }),
      new Response("down", { status: 503 }),
      new Response("teapot", { status: 418 }),
    );
    const kinds = [
      (await failure(read(transport))).kind,
      (await failure(read(transport))).kind,
      (await failure(read(transport))).kind,
    ];
    expect(kinds).toEqual(["timeout", "unavailable", "protocol"]);
  });
});

function envelope404Body() {
  return { error: { code: "sandbox.not_found", message: "x", requestId: REQUEST_ID } };
}

describe("missing sandbox", () => {
  it("maps only a confirmed sandbox.not_found to null", async () => {
    const { transport } = transportWith(envelope("sandbox.not_found"));
    await expect(transport.findSandbox("sbx_1")).resolves.toBeNull();
  });

  it("returns a deleted sandbox rather than null", async () => {
    const deleted = { ...sandbox, state: "DELETED" };
    const { transport } = transportWith(json(200, deleted));
    await expect(transport.findSandbox("sbx_1")).resolves.toEqual(deleted);
  });

  it.each([
    ["a generic route miss", () => envelope("NOT_FOUND"), "not_found"],
    ["a malformed 404 page", () => new Response("not found", { status: 404 }), "protocol"],
    ["an authorization failure", () => envelope("FORBIDDEN"), "authorization"],
    ["an unavailable server", () => envelope("SERVICE_UNAVAILABLE"), "unavailable"],
  ])("throws on %s", async (_label, response, kind) => {
    const { transport } = transportWith(response());
    expect((await failure(transport.findSandbox("sbx_1"))).kind).toBe(kind);
  });
});

describe("response schema validation", () => {
  it.each([
    ["an extra field", () => json(200, { ...sandbox, ownerId: "user_1" })],
    ["a wrong type", () => json(200, { ...sandbox, generation: "1" })],
    ["invalid JSON", () => new Response("{", { status: 200 })],
    ["invalid UTF-8", () => new Response(new Uint8Array([0xff, 0xfe]), { status: 200 })],
    ["an empty body", () => new Response(null, { status: 200 })],
  ])("rejects a read with %s as a typed protocol error", async (_label, response) => {
    const { transport } = transportWith(response());
    expect(await failure(read(transport))).toMatchObject({
      kind: "protocol",
      reason: "invalid_response",
      status: 200,
    });
  });

  it("rejects an oversized body without buffering past the cap", async () => {
    const { transport } = transportWith(
      new Response(new Uint8Array(RESPONSE_MAX_BYTES + 1), { status: 200 }),
    );
    expect(await failure(read(transport))).toMatchObject({ kind: "protocol" });
  });

  it("reports a mismatched 202 receipt as an unknown outcome", async () => {
    const { transport } = transportWith(json(202, { ...receipt, location: "https://evil/x" }));
    expect(await failure(stop(transport))).toMatchObject({
      kind: "unknown",
      reason: "invalid_response",
      idempotencyKey: "stop-1",
    });
  });
});

describe("timeouts and aborts", () => {
  const timed = () => {
    const calls: Call[] = [];
    const transport = createWsspTransport({
      baseUrl: BASE,
      apiKey: KEY,
      timeoutMs: 20,
      fetch: (url, init) => {
        calls.push({ url, init });
        return hangs({ url, init });
      },
    });
    return { transport, calls };
  };

  it("times out a read", async () => {
    const { transport } = timed();
    expect(await failure(read(transport))).toMatchObject({ kind: "timeout", reason: "timeout" });
  });

  it("reports a timed-out mutation as unknown with its key", async () => {
    const { transport } = timed();
    expect(await failure(stop(transport))).toMatchObject({
      kind: "unknown",
      reason: "timeout",
      idempotencyKey: "stop-1",
    });
  });

  it("times out a stalled response body", async () => {
    const stalled = new Response(new ReadableStream({ pull: () => new Promise(() => {}) }), {
      status: 200,
    });
    const transport = createWsspTransport({
      baseUrl: BASE,
      apiKey: KEY,
      timeoutMs: 20,
      fetch: async () => stalled,
    });
    expect(await failure(read(transport))).toMatchObject({ kind: "timeout" });
  });

  it("honours a per-request timeout", async () => {
    const { transport } = transportWith(hangs);
    const error = await failure(
      transport.request("getSandbox", { params: { id: "sbx_1" }, timeoutMs: 10 }),
    );
    expect(error.kind).toBe("timeout");
  });

  it("aborts a read and a mutation in flight", async () => {
    const { transport } = transportWith(hangs, hangs);
    const readAbort = new AbortController();
    const readPromise = transport.request("getSandbox", {
      params: { id: "sbx_1" },
      signal: readAbort.signal,
    });
    readAbort.abort();
    expect(await failure(readPromise)).toMatchObject({ kind: "aborted", reason: "aborted" });
    const mutationAbort = new AbortController();
    const mutationPromise = transport.request("stopSandbox", {
      params: { id: "sbx_1" },
      idempotencyKey: "stop-1",
      signal: mutationAbort.signal,
    });
    mutationAbort.abort();
    expect(await failure(mutationPromise)).toMatchObject({ kind: "unknown", reason: "aborted" });
  });

  it("does not send when the signal is already aborted", async () => {
    const { transport, fetch } = transportWith();
    const error = await failure(
      transport.request("stopSandbox", {
        params: { id: "sbx_1" },
        idempotencyKey: "stop-1",
        signal: AbortSignal.abort(),
      }),
    );
    expect(error.kind).toBe("aborted");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("maps a network failure", async () => {
    const refused = async () => {
      throw new TypeError("fetch failed");
    };
    const { transport } = transportWith(refused, refused);
    expect((await failure(read(transport))).kind).toBe("unavailable");
    expect(await failure(stop(transport))).toMatchObject({ kind: "unknown", reason: "network" });
  });
});

describe("redirects", () => {
  it("follows a same-origin 307 for a mutation, keeping method, body and key", async () => {
    const { transport, calls } = transportWith(
      redirect(307, "/prefix/v1/sandboxes/sbx_1/stop?moved=1"),
      json(202, receipt),
    );
    await expect(stop(transport)).resolves.toEqual(receipt);
    expect(calls.map((c) => [c.url, c.init.method, c.init.body])).toEqual([
      ["https://api.example.test/prefix/v1/sandboxes/sbx_1/stop", "POST", "{}"],
      ["https://api.example.test/prefix/v1/sandboxes/sbx_1/stop?moved=1", "POST", "{}"],
    ]);
    expect(calls[1]?.init.headers).toMatchObject({ authorization: `Bearer ${KEY}` });
  });

  it("follows a same-origin 302 for a read", async () => {
    const { transport, calls } = transportWith(
      redirect(302, "https://api.example.test/other"),
      json(200, sandbox),
    );
    await expect(read(transport)).resolves.toEqual(sandbox);
    expect(calls[1]?.url).toBe("https://api.example.test/other");
  });

  it.each([
    ["another host", 307, "https://attacker.example/v1/sandboxes/sbx_1"],
    ["a scheme downgrade", 302, "http://api.example.test/prefix/v1/sandboxes/sbx_1"],
    ["another port", 308, "https://api.example.test:8443/v1/sandboxes/sbx_1"],
    ["a missing Location", 302, null],
  ])("refuses a redirect to %s without sending the key there", async (_label, status, location) => {
    const r = transportWith(redirect(status, location), redirect(status, location));
    expect(await failure(read(r.transport))).toMatchObject({
      kind: "protocol",
      reason: "redirect_refused",
      status,
    });
    expect(await failure(stop(r.transport))).toMatchObject({
      kind: "unknown",
      reason: "redirect_refused",
    });
    expect(r.calls.map((c) => c.url)).toEqual([
      "https://api.example.test/prefix/v1/sandboxes/sbx_1",
      "https://api.example.test/prefix/v1/sandboxes/sbx_1/stop",
    ]);
  });

  it("refuses a same-origin 303 that would drop a mutation body", async () => {
    const { transport, calls } = transportWith(redirect(303, "/prefix/v1/operations/op_1"));
    expect((await failure(stop(transport))).reason).toBe("redirect_refused");
    expect(calls).toHaveLength(1);
  });

  it("refuses an opaque redirect it cannot inspect", async () => {
    const opaque = { type: "opaqueredirect", status: 0, headers: new Headers(), body: null };
    const { transport } = transportWith(opaque as unknown as Response);
    expect((await failure(read(transport))).reason).toBe("redirect_refused");
  });

  it(`stops after ${MAX_REDIRECTS} same-origin hops`, async () => {
    const hops = Array.from({ length: MAX_REDIRECTS + 1 }, (_, i) => redirect(307, `/hop${i}`));
    const { transport, calls } = transportWith(...hops);
    expect((await failure(read(transport))).reason).toBe("redirect_refused");
    expect(calls).toHaveLength(MAX_REDIRECTS + 1);
  });
});

describe("capacity refusal retryable flag", () => {
  it.each(RETRYABLE_REFUSAL_CODES)(
    "%s: retryable true carries the backoff, false carries none",
    async (code) => {
      const r = transportWith(
        json(
          409,
          (await envelope(code, { retryable: true, retryAfterSeconds: 30 }).json()) as unknown,
          { "retry-after": "30" },
        ),
        envelope(code, { retryable: false }),
      );
      const temporary = await failure(stop(r.transport));
      expect(temporary).toMatchObject({
        code,
        status: 409,
        retryable: true,
        retryAfterSeconds: 30,
      });
      expect(temporary.toJSON()).toMatchObject({ retryable: true });
      const permanent = await failure(stop(r.transport));
      expect(permanent).toMatchObject({ code, status: 409, retryable: false });
      expect(permanent.retryAfterSeconds).toBeNull();
      expect(permanent.toJSON()).toMatchObject({ retryable: false });
      // A Retry-After added by a proxy never turns a permanent refusal into a backoff.
      const proxied = transportWith(
        json(409, (await envelope(code, { retryable: false }).json()) as unknown, {
          "retry-after": "30",
        }),
      );
      expect((await failure(stop(proxied.transport))).retryAfterSeconds).toBeNull();
      // Both are definitive refusals, never an unknown outcome.
      expect(permanent.kind).not.toBe("unknown");
    },
  );

  it.each(RETRYABLE_REFUSAL_CODES)(
    "%s without retryable is outside the contract, not a typed refusal",
    async (code) => {
      const body = (await envelope(code).json()) as { error: Record<string, unknown> };
      delete body.error.retryable;
      const nonBoolean = (await envelope(code).json()) as { error: Record<string, unknown> };
      nonBoolean.error.retryable = "yes";
      for (const malformed of [body, nonBoolean]) {
        const { transport } = transportWith(json(409, malformed), json(409, malformed));
        const readError = await failure(read(transport));
        expect(readError.code).toBeNull();
        expect(readError.retryable).toBeNull();
        expect(readError.reason).toBe("invalid_response");
        const mutationError = await failure(stop(transport));
        expect(mutationError.kind).toBe("unknown");
        expect(mutationError.code).toBeNull();
      }
    },
  );

  it("never reports retryable for any other code", async () => {
    const { transport } = transportWith(envelope("sandbox.host_unavailable", { retryable: true }));
    const error = await failure(read(transport));
    expect(error.code).toBe("sandbox.host_unavailable");
    expect(error.retryable).toBeNull();
    expect(error.toJSON()).not.toHaveProperty("retryable");
  });
});

describe("Retry-After header", () => {
  const html = (headers: Record<string, string>) =>
    new Response("<html>Service Unavailable</html>", {
      status: 503,
      headers: { "content-type": "text/html", ...headers },
    });

  it("propagates the header on a non-envelope error response", async () => {
    const { transport } = transportWith(html({ "retry-after": "30" }));
    const error = await failure(read(transport));
    expect(error.kind).toBe("unavailable");
    expect(error.retryAfterSeconds).toBe(30);
  });

  it("accepts the HTTP-date form", async () => {
    const at = new Date(Date.now() + 45_000).toUTCString();
    const { transport } = transportWith(html({ "retry-after": at }));
    const error = await failure(read(transport));
    expect(error.retryAfterSeconds).toBeGreaterThanOrEqual(44);
    expect(error.retryAfterSeconds).toBeLessThanOrEqual(45);
  });

  it("prefers a valid envelope field over the header", async () => {
    const { transport } = transportWith(
      new Response(
        JSON.stringify({
          error: {
            code: "TOO_MANY_REQUESTS",
            message: "x",
            requestId: REQUEST_ID,
            retryAfterSeconds: 7,
          },
        }),
        { status: 429, headers: { "content-type": "application/json", "retry-after": "30" } },
      ),
    );
    const error = await failure(read(transport));
    expect(error.retryAfterSeconds).toBe(7);
  });

  it.each(["0", "86401", "99999999", "not-a-date", "-5"])(
    "ignores the out-of-range or invalid value %s",
    async (value) => {
      const { transport } = transportWith(html({ "retry-after": value }));
      const error = await failure(read(transport));
      expect(error.retryAfterSeconds).toBeNull();
    },
  );
});

describe("transport downloadContent body errors", () => {
  it("a body failure never leaks adapter diagnostics: fixed message, redacted cause", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(
          new Error(`fetch adapter: sent Authorization: Bearer ${KEY} to api.example.test`),
        );
      },
    });
    const fetch = vi.fn<FetchLike>(
      async () =>
        new Response(body, {
          status: 200,
          headers: {
            etag: `"${"a".repeat(64)}"`,
            "content-length": "5",
            "accept-ranges": "bytes",
            "content-range": "bytes 0-4/5",
          },
        }),
    );
    const transport = createWsspTransport({ baseUrl: BASE, apiKey: KEY, fetch, timeoutMs: 5000 });
    const content = await transport.downloadContent({ params: { id: "op_leaky" } });
    expect(content.body).not.toBeNull();
    const read = content.body?.getReader().read();
    const error = await failure(read ?? Promise.reject(new Error("no body")));
    expect(error.kind).toBe("unavailable");
    expect(error.code).toBe("TRANSFER_IO");
    expect(error.message).toBe("downloadFile: the response body failed mid-stream.");
    expect(JSON.stringify(error)).not.toContain(KEY);
    expect(error.cause ? JSON.stringify(error.cause) : "").not.toContain(KEY);
  });
});

describe("transport downloadContent body cancellation", () => {
  it("caller-signal cancellation DURING a pending read errors the stream — never a clean EOF", async () => {
    // A WHATWG body's cancel() resolves a pending read with done: true; the
    // wrapper must still error the stream so no caller accepts a truncated
    // download as complete.
    const body = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) });
    const fetch = vi.fn<FetchLike>(
      async () =>
        new Response(body, {
          status: 200,
          headers: {
            etag: `"${"a".repeat(64)}"`,
            "content-length": "5",
            "accept-ranges": "bytes",
            "content-range": "bytes 0-4/5",
          },
        }),
    );
    const controller = new AbortController();
    const transport = createWsspTransport({ baseUrl: BASE, apiKey: KEY, fetch, timeoutMs: 30_000 });
    const content = await transport.downloadContent({
      params: { id: "op_stall" },
      signal: controller.signal,
    });
    expect(content.body).not.toBeNull();
    const reader = content.body!.getReader();
    const pending = failure(reader.read());
    controller.abort();
    const error = await pending;
    expect(error.kind).toBe("aborted");
    expect(error.reason).toBe("aborted");
  });
});

describe("transport downloadContent stream cancellation", () => {
  it("body.cancel() resolves even when the adapter's cancel never settles", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull: () => new Promise(() => {}),
      cancel: () => new Promise(() => {}), // never settles
    });
    const fetch = vi.fn<FetchLike>(
      async () =>
        new Response(body, {
          status: 200,
          headers: {
            etag: `"${"a".repeat(64)}"`,
            "content-length": "5",
            "accept-ranges": "bytes",
            "content-range": "bytes 0-4/5",
          },
        }),
    );
    const transport = createWsspTransport({ baseUrl: BASE, apiKey: KEY, fetch, timeoutMs: 30_000 });
    const content = await transport.downloadContent({ params: { id: "op_nc" } });
    expect(content.body).not.toBeNull();
    const started = Date.now();
    await content.body!.cancel();
    expect(Date.now() - started).toBeLessThan(5000);
  });
});

describe("downloadContent — round-11 review", () => {
  const ETAG = `"${"e".repeat(64)}"`;
  /** A download response with self-consistent headers for the given span. */
  function spanResponse(length: number, size: number, start?: number): Response {
    const body = new Uint8Array(length).fill(7);
    if (start === undefined) {
      return new Response(body, {
        status: 200,
        headers: { etag: ETAG, "content-length": String(length), "accept-ranges": "bytes" },
      });
    }
    return new Response(body, {
      status: 206,
      headers: {
        etag: ETAG,
        "content-length": String(length),
        "accept-ranges": "bytes",
        "content-range": `bytes ${start}-${start + length - 1}/${size}`,
      },
    });
  }
  const id = { id: "op_dl" };

  it("rejects an unsolicited 206 partial span for a whole download", async () => {
    const { transport } = transportWith(spanResponse(100, 1000, 0));
    const error = await failure(transport.downloadContent({ params: id }));
    expect(error.kind).toBe("protocol");
    expect(error.reason).toBe("invalid_response");
  });

  it("rejects a short 206 for an open-ended range (correct start, wrong end)", async () => {
    const { transport } = transportWith(spanResponse(100, 1000, 100));
    const error = await failure(transport.downloadContent({ params: id, range: { start: 100 } }));
    expect(error.kind).toBe("protocol");
    expect(error.reason).toBe("invalid_response");
  });

  it("rejects a 206 whose end boundary is short of an explicit range", async () => {
    const { transport } = transportWith(spanResponse(25, 100, 10));
    const error = await failure(
      transport.downloadContent({ params: id, range: { start: 10, end: 29 } }),
    );
    expect(error.kind).toBe("protocol");
    expect(error.reason).toBe("invalid_response");
  });

  it("rejects a 206 that over-serves a suffix range", async () => {
    const { transport } = transportWith(spanResponse(10, 100, 90));
    const error = await failure(transport.downloadContent({ params: id, range: { suffix: 5 } }));
    expect(error.kind).toBe("protocol");
    expect(error.reason).toBe("invalid_response");
  });

  it.each([301, 302, 303])("a %d redirect preserves HEAD across every hop", async (status) => {
    const target = `${BASE}/v1/operations/op_dl/content?hop=1`;
    const { transport, calls } = transportWith(
      redirect(status, target),
      new Response(null, {
        status: 200,
        headers: { etag: ETAG, "content-length": "5", "accept-ranges": "bytes" },
      }),
    );
    const content = await transport.downloadContent({ params: id, head: true });
    expect(content.size).toBe(5);
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(call.init.method ?? "GET").toBe("HEAD");
    }
  });
});

describe("downloadContent — round-12 review", () => {
  it("a rejected wrong-span 206 cancels the underlying body without leaking the abort listener", async () => {
    let cancels = 0;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(25).fill(7));
      },
      cancel() {
        cancels += 1;
      },
    });
    const response = new Response(body, {
      status: 206,
      headers: {
        etag: `"${"e".repeat(64)}"`,
        "content-length": "25",
        "accept-ranges": "bytes",
        "content-range": "bytes 10-34/100",
      },
    });
    const caller = new AbortController();
    const { transport } = transportWith(response);
    const error = await failure(
      transport.downloadContent({
        params: { id: "op_dl" },
        range: { start: 10, end: 29 },
        signal: caller.signal,
      }),
    );
    expect(error.kind).toBe("protocol");
    expect(error.reason).toBe("invalid_response");
    // The span was rejected BEFORE watchBody locked the body: the underlying
    // stream is cancelled and no abort listener was ever attached.
    await vi.waitFor(() => expect(cancels).toBe(1));
    caller.abort();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(cancels).toBe(1);
  });
});

describe("C58-1 base URL joining (every request target)", () => {
  // Origin-only and trailing-slash bases once produced `//v1/...`, which no
  // server routes. Each form must reach exactly `<prefix>/v1/...`.
  const forms = [
    { base: "https://api.example.test", prefix: "" },
    { base: "https://api.example.test/", prefix: "" },
    { base: "https://api.example.test//", prefix: "" },
    { base: "https://api.example.test/api", prefix: "/api" },
    { base: "https://api.example.test/api/", prefix: "/api" },
    { base: "https://api.example.test/a/b/", prefix: "/a/b" },
    // FSDK-R1-2: an empty query or fragment marker must not reach route URLs.
    { base: "https://api.example.test/api?", prefix: "/api" },
    { base: "https://api.example.test/api#", prefix: "/api" },
    { base: "https://api.example.test?#", prefix: "" },
  ];
  const TRANSFER = "6f1c2f3a-1b2c-4d5e-8f90-123456789abd";
  function at(base: string, response: () => Response) {
    const urls: string[] = [];
    const fetch = vi.fn<FetchLike>(async (url) => {
      urls.push(url);
      return response();
    });
    return { transport: createWsspTransport({ baseUrl: base, apiKey: KEY, fetch }), urls };
  }

  it.each(forms)("JSON routes from $base", async ({ base, prefix }) => {
    const { transport, urls } = at(base, () => json(200, sandbox));
    await transport.findSandbox("sbx_1");
    expect(urls).toEqual([`https://api.example.test${prefix}/v1/sandboxes/sbx_1`]);
    expect(transport.baseUrl).toBe(`https://api.example.test${prefix}`);
  });

  it.each(forms)("upload chunks and downloads from $base", async ({ base, prefix }) => {
    const { transport, urls } = at(base, () => json(500, {}));
    await transport
      .putUploadChunk({ params: { id: TRANSFER }, offset: 0, total: 1, bytes: new Uint8Array(1) })
      .catch(() => undefined);
    await transport.downloadContent({ params: { id: "op_1" } }).catch(() => undefined);
    expect(urls.map((url) => new URL(url).pathname)).toEqual([
      `${prefix}/v1/transfers/${TRANSFER}`,
      `${prefix}/v1/operations/op_1/content`,
    ]);
    for (const url of urls) expect(url).not.toContain("//v1");
  });
});

it.each([1, true, null, {}, [], "\ud800", "\0", "x".repeat(1025)])(
  "strict transport refuses invalid metadata responses: %j",
  async (value) => {
    const { transport } = transportWith(
      json(200, { items: [{ ...sandbox, metadata: { label: value } }], nextCursor: null }),
    );
    await expect(transport.request("listSandboxes", {})).rejects.toMatchObject({
      kind: "protocol",
      reason: "invalid_response",
    });
  },
);

it("strict transport validates the raw metadata JSON query and preserves one value", async () => {
  const { transport, calls } = transportWith(json(200, { items: [], nextCursor: null }));
  const metadata = JSON.stringify({ team: "雪😀", empty: "" });
  await transport.request("listSandboxes", {
    query: { metadata, states: "READY,STOPPED", limit: "2" },
  });
  expect(new URL(calls[0]!.url).searchParams.getAll("metadata")).toEqual([metadata]);
  for (const bad of ['{"count":1}', '{"a":"x","a":"y"}', "{", "[]", '{"prototype":"x"}']) {
    await expect(
      transport.request("listSandboxes", { query: { metadata: bad } }),
    ).rejects.toMatchObject({ kind: "invalid_request" });
  }
  expect(calls).toHaveLength(1);
});

it.each([
  { cpuCount: 0 },
  { memoryMiB: 513 },
  { cpuCount: "private-size-sentinel" },
  { memoryMiB: null },
])("B5 malformed size %j is local, safe, code-null and makes no request", async (size) => {
  const { transport, fetch } = transportWith();
  const caught = await failure(
    transport.request("createSandbox", {
      body: {
        template: "base",
        sandboxHostId: "host",
        envs: { PRIVATE: "private-size-sentinel" },
        ...size,
      } as never,
      idempotencyKey: "size-local",
    }),
  );
  expect(caught).toMatchObject({ kind: "invalid_request", code: null });
  expect(JSON.stringify(caught)).not.toContain("private-size-sentinel");
  expect(fetch).not.toHaveBeenCalled();
});

describe("E2-B-01 credential.value_invalid", () => {
  const write = (transport: ReturnType<typeof transportWith>["transport"]) =>
    transport.request("writeCredentialValue", {
      params: { id: "cred_1", instanceId: "inst_1" },
      body: { env: { X: "v" } },
    });
  it("keeps the code and exposes entry and path", async () => {
    const { transport } = transportWith(
      envelope("credential.value_invalid", { entry: "bundle.undeclared_path", path: ".fakecli" }),
    );
    const error = await failure(write(transport));
    expect(error).toMatchObject({
      kind: "invalid_request",
      code: "credential.value_invalid",
      status: 400,
      valueInvalid: { entry: "bundle.undeclared_path", path: ".fakecli" },
    });
    expect(error.toJSON()).toMatchObject({ valueInvalid: { entry: "bundle.undeclared_path" } });
  });
  it("an unknown extra field is ignored: the code and declared fields survive", async () => {
    const { transport } = transportWith(
      envelope("credential.value_invalid", { entry: "env.X", futureField: 1 }),
    );
    const error = await failure(write(transport));
    expect(error).toMatchObject({
      kind: "invalid_request",
      code: "credential.value_invalid",
      status: 400,
      valueInvalid: { entry: "env.X", path: null },
    });
    // A declared field is still strict: a malformed one is not ignored.
    const { transport: bad } = transportWith(
      envelope("credential.value_invalid", { entry: "a\nb", futureField: 1 }),
    );
    expect(await failure(write(bad))).toMatchObject({ code: null, reason: "invalid_response" });
  });
  it("an unknown code or a status mismatch still fails as invalid_response", async () => {
    const requestId = "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19";
    for (const response of [
      json(400, { error: { code: "credential.future", message: "m", requestId, x: 1 } }),
      json(409, { error: { code: "credential.value_invalid", message: "m", requestId, x: 1 } }),
    ]) {
      const { transport } = transportWith(response);
      const error = await failure(write(transport));
      expect(error).toMatchObject({ code: null, reason: "invalid_response" });
    }
  });
});
