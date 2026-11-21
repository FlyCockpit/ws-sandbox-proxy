import { ORPCError } from "@orpc/server";
import { env } from "@wssp/env/server";
import {
  CAPACITY_QUEUE_SCOPES,
  CAPTURE_UNSUPPORTED_REASONS,
  type CapacityReason,
  type ConnectRefusalReason,
  capacityReasonSchema,
  capacityWaitMaxSchema,
  connectRefusalReasonSchema,
  credentialValueInvalidTextSchema,
  type EgressRefusalReason,
  egressRefusalReasonSchema,
  HOST_FILE_ERROR_REASONS,
  IMAGE_QUOTA_SCOPES,
  isRetryableRefusalCode,
  isSdkErrorCode,
  isTemplateBuildErrorExtrasCode,
  type KeyLimitReachedData,
  keyLimitReachedDataSchema,
  leaseMaxTimeoutMsSchema,
  type PoolFullReason,
  poolFullReasonSchema,
  SDK_ERRORS,
  type SdkErrorCode,
  type SkippedHostReason,
  sdkErrorEnvelopeSchema,
  skippedHostReasonsSchema,
  TEMPLATE_BUILD_ERROR_EXTRAS,
  TEMPLATE_IMAGE_UNAVAILABLE_REASONS,
  type TunnelRefusalReason,
  tunnelRefusalReasonSchema,
} from "@wssp/sandbox-contracts";
import type { Context } from "hono";
import { z } from "zod";

/** Public HTTP catalog, owned by @wssp/sandbox-contracts (OpenAPI and SDK consume it too). */
export { SDK_ERRORS } from "@wssp/sandbox-contracts";

type SandboxApiError = {
  error: {
    code: SdkErrorCode;
    message: string;
    requestId: string;
    retryAfterSeconds?: number;
    resource?: "memory" | "vcpu" | "disk";
    reason?:
      | PoolFullReason
      | CapacityReason
      | (typeof CAPTURE_UNSUPPORTED_REASONS)[number]
      | EgressRefusalReason
      | TunnelRefusalReason
      | ConnectRefusalReason;
    maxTimeoutMs?: number;
    skipped?: SkippedHostReason[];
    maxWaitMs?: number;
    scope?: (typeof CAPACITY_QUEUE_SCOPES)[number] | (typeof IMAGE_QUOTA_SCOPES)[number];
    retryable?: boolean;
  } & Record<string, unknown>;
};

const isCode = isSdkErrorCode;
/** Retry-After of `429 TRANSFER_QUOTA`. */
const TRANSFER_QUOTA_RETRY_AFTER_SECONDS = 5;
/** Retry-After of `503 sandbox.host_reconnecting`. */
const HOST_RECONNECTING_RETRY_AFTER_SECONDS = 1;

export function sdkErrorResponse(c: Context, error: unknown): Response {
  let code: SdkErrorCode = "INTERNAL_SERVER_ERROR";
  let retryAfterSeconds: number | undefined;
  let resource: SandboxApiError["error"]["resource"];
  let reason: SandboxApiError["error"]["reason"];
  let maxTimeoutMs: number | undefined;
  let skipped: SkippedHostReason[] | undefined;
  let maxWaitMs: number | undefined;
  let scope: SandboxApiError["error"]["scope"];
  /** `sandbox.template_image_unavailable`: rebuild-on-miss reason and hint. */
  let image: Record<string, string> | undefined;
  /** `credential.value_invalid`: the refused entry and file path (non-secret, E1-B-09). */
  let valueInvalid: { entry?: string; path?: string } | undefined;
  /** The documented fields of a `template.build_*` refusal (validated). */
  let buildExtras: Record<string, unknown> | undefined;
  /** Capacity/quota/pool refusals (`RETRYABLE_REFUSAL_CODES`): required. */
  let retryable: boolean | undefined;
  let hostFileData: { reason: (typeof HOST_FILE_ERROR_REASONS)[number] } | undefined;
  /** `sandbox.key_limit_reached`: the key's limit and its live creates. */
  let keyLimitData: KeyLimitReachedData | undefined;
  if (error instanceof ORPCError) {
    const data = error.data;
    const domain = data && typeof data === "object" && "code" in data ? data.code : undefined;
    code = isCode(domain) ? domain : isCode(error.code) ? error.code : code;
    if (
      isRetryableRefusalCode(code) &&
      data &&
      typeof data === "object" &&
      "retryable" in data &&
      typeof data.retryable === "boolean"
    )
      retryable = data.retryable;
    if (
      (code === "sandbox.host_capacity" || code === "sandbox.pool_full") &&
      data &&
      typeof data === "object" &&
      "reason" in data
    ) {
      // `reserved` is a pool-only reason; host capacity keeps the shared set.
      const parsed = (
        code === "sandbox.pool_full" ? poolFullReasonSchema : capacityReasonSchema
      ).safeParse(data.reason);
      if (parsed.success) reason = parsed.data;
    }
    if (
      code === "sandbox.capture_unsupported" &&
      data &&
      typeof data === "object" &&
      "reason" in data
    ) {
      const parsed = z.enum(CAPTURE_UNSUPPORTED_REASONS).safeParse(data.reason);
      if (parsed.success) reason = parsed.data;
    }
    if (code === "UNSUPPORTED_CAPABILITY" && data && typeof data === "object" && "reason" in data) {
      const parsed = egressRefusalReasonSchema
        .or(tunnelRefusalReasonSchema)
        .or(connectRefusalReasonSchema)
        .safeParse(data.reason);
      if (parsed.success) reason = parsed.data;
    }
    if (
      code === "sandbox.image_quota_exceeded" &&
      data &&
      typeof data === "object" &&
      "scope" in data
    ) {
      const parsed = z.enum(IMAGE_QUOTA_SCOPES).safeParse(data.scope);
      if (parsed.success) scope = parsed.data;
    }
    if (
      (code === "sandbox.pool_full" ||
        code === "sandbox.pool_unavailable" ||
        code === "sandbox.share_quota" ||
        code === "sandbox.member_quota") &&
      data &&
      typeof data === "object" &&
      "skipped" in data
    ) {
      const parsed = skippedHostReasonsSchema.safeParse(data.skipped);
      if (parsed.success) skipped = parsed.data;
    }
    if (
      (code === "sandbox.share_quota" || code === "sandbox.member_quota") &&
      data &&
      typeof data === "object" &&
      "resource" in data
    ) {
      if (
        data.resource === "memory" ||
        data.resource === "vcpu" ||
        (code === "sandbox.share_quota" && data.resource === "disk")
      )
        resource = data.resource;
    }
    if (
      code === "lease_exceeds_policy" &&
      data &&
      typeof data === "object" &&
      "maxTimeoutMs" in data
    ) {
      const parsed = leaseMaxTimeoutMsSchema.safeParse(data.maxTimeoutMs);
      if (parsed.success) maxTimeoutMs = parsed.data;
    }
    if (
      code === "capacity_wait_exceeds_policy" &&
      data &&
      typeof data === "object" &&
      "maxWaitMs" in data
    ) {
      const parsed = capacityWaitMaxSchema.safeParse(data.maxWaitMs);
      if (parsed.success) maxWaitMs = parsed.data;
    }
    if (
      code === "sandbox.capacity_queue_full" &&
      data &&
      typeof data === "object" &&
      "scope" in data
    )
      scope = CAPACITY_QUEUE_SCOPES.find((value) => value === data.scope);
    if (code === "sandbox.template_image_unavailable" && data && typeof data === "object") {
      const imageReason =
        "reason" in data
          ? TEMPLATE_IMAGE_UNAVAILABLE_REASONS.find((value) => value === data.reason)
          : undefined;
      image = {
        ...(imageReason ? { reason: imageReason } : {}),
        ...("hint" in data && data.hint === "rebuild_required" ? { hint: "rebuild_required" } : {}),
      };
    }
    if (code === "credential.value_invalid" && data && typeof data === "object") {
      const text = credentialValueInvalidTextSchema;
      const entry = "entry" in data ? text.safeParse(data.entry) : undefined;
      const path = "path" in data ? text.safeParse(data.path) : undefined;
      valueInvalid = {
        ...(entry?.success ? { entry: entry.data } : {}),
        ...(path?.success ? { path: path.data } : {}),
      };
    }
    if (code === "sandbox.key_limit_reached" && data && typeof data === "object") {
      const parsed = keyLimitReachedDataSchema.safeParse({
        maxLiveSandboxes: "maxLiveSandboxes" in data ? data.maxLiveSandboxes : undefined,
        liveSandboxes: "liveSandboxes" in data ? data.liveSandboxes : undefined,
      });
      if (parsed.success) keyLimitData = parsed.data;
    }
    if (code === "host.agent_access_off") retryable = false;
    if (code === "host.node_offline") {
      retryable = true;
      retryAfterSeconds = 1;
    }
    if (code === "host.file_error" && data && typeof data === "object" && "reason" in data) {
      const parsed = z.enum(HOST_FILE_ERROR_REASONS).safeParse(data.reason);
      if (parsed.success) hostFileData = { reason: parsed.data };
    }
    if (isTemplateBuildErrorExtrasCode(code) && data && typeof data === "object") {
      const { code: _code, ...fields } = data as Record<string, unknown>;
      // Only the documented fields: anything else in the data is dropped.
      const parsed = z.object(TEMPLATE_BUILD_ERROR_EXTRAS[code].shape).safeParse(fields);
      if (parsed.success) buildExtras = parsed.data;
    }
    if (
      code === "TOO_MANY_REQUESTS" &&
      data &&
      typeof data === "object" &&
      "retryAfterSeconds" in data
    ) {
      const seconds = data.retryAfterSeconds;
      if (
        typeof seconds === "number" &&
        Number.isSafeInteger(seconds) &&
        seconds > 0 &&
        seconds <= 86400
      ) {
        retryAfterSeconds = seconds;
      }
    }
  }
  const requested = code;
  if (code === "host.file_error" && !hostFileData) code = "INTERNAL_SERVER_ERROR";
  if (code === "sandbox.key_limit_reached" && !keyLimitData) code = "INTERNAL_SERVER_ERROR";
  if ((code === "sandbox.host_capacity" || code === "sandbox.pool_full") && reason === undefined)
    code = "INTERNAL_SERVER_ERROR";
  if ((code === "sandbox.share_quota" || code === "sandbox.member_quota") && !resource)
    code = "INTERNAL_SERVER_ERROR";
  if (code === "lease_exceeds_policy" && maxTimeoutMs === undefined) code = "INTERNAL_SERVER_ERROR";
  if (code === "sandbox.capture_unsupported" && reason === undefined)
    code = "INTERNAL_SERVER_ERROR";
  if (code === "sandbox.image_quota_exceeded" && scope === undefined)
    code = "INTERNAL_SERVER_ERROR";
  if (code === "capacity_wait_exceeds_policy" && maxWaitMs === undefined)
    code = "INTERNAL_SERVER_ERROR";
  if (code === "sandbox.capacity_queue_full" && !scope) code = "INTERNAL_SERVER_ERROR";
  // A capacity refusal never goes out unclassified (the harness falls back on
  // `retryable: false` and backs off on `true`).
  if (isRetryableRefusalCode(code) && retryable === undefined) code = "INTERNAL_SERVER_ERROR";
  // A build refusal never goes out without its documented fields.
  if (isTemplateBuildErrorExtrasCode(code) && !buildExtras) code = "INTERNAL_SERVER_ERROR";
  if (code !== requested) {
    // A degraded refusal carries none of the fields gathered for the code it
    // was (e.g. `skipped` of a share_quota without its resource).
    reason = resource = scope = maxTimeoutMs = maxWaitMs = undefined;
    skipped = image = valueInvalid = buildExtras = retryAfterSeconds = retryable = undefined;
    keyLimitData = undefined;
  }
  // Backoff advice only for a refusal current usage or state can clear; a
  // permanent (`retryable: false`) refusal never carries Retry-After.
  if (isRetryableRefusalCode(code))
    retryAfterSeconds = retryable === true ? env.CAPACITY_RETRY_AFTER_SECONDS : undefined;
  if (code === "SERVICE_UNAVAILABLE") retryAfterSeconds = 5;
  // A full transfer store frees a slot as soon as a transfer settles (E-17/E-18):
  // tell clients to back off briefly rather than re-POST at their poll interval.
  if (code === "TRANSFER_QUOTA") retryAfterSeconds = TRANSFER_QUOTA_RETRY_AFTER_SECONDS;
  // The journal key ACK follows a hello within one round trip.
  if (code === "sandbox.host_reconnecting")
    retryAfterSeconds = HOST_RECONNECTING_RETRY_AFTER_SECONDS;
  const [status, message] = SDK_ERRORS[code];
  const requestId: string = c.get("requestId");
  if (status >= 500) {
    // Class and machine code only (e.g. PrismaClientKnownRequestError P2028):
    // never the message, which can carry request data.
    const kind =
      error instanceof Error
        ? `${error.constructor.name}${"code" in error && typeof error.code === "string" ? ` ${error.code}` : ""}`
        : typeof error;
    console.error(`[sandbox-api] [${requestId}] ${code} (${kind.slice(0, 80)})`);
  }
  const body = contractEnvelope(
    {
      error: {
        code,
        message,
        requestId,
        ...(code === "host.file_error" && hostFileData ? { data: hostFileData } : {}),
        ...(code === "sandbox.key_limit_reached" && keyLimitData ? { data: keyLimitData } : {}),
        ...(buildExtras && isTemplateBuildErrorExtrasCode(code) ? buildExtras : {}),
        ...(image && code === "sandbox.template_image_unavailable" ? image : {}),
        ...(valueInvalid && code === "credential.value_invalid" ? valueInvalid : {}),
        ...(reason ? { reason } : {}),
        ...(resource ? { resource } : {}),
        ...(scope ? { scope } : {}),
        ...(maxTimeoutMs === undefined ? {} : { maxTimeoutMs }),
        ...(skipped ? { skipped } : {}),
        ...(maxWaitMs === undefined ? {} : { maxWaitMs }),
        ...(retryable === undefined ? {} : { retryable }),
        ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
      },
    } satisfies SandboxApiError,
    requestId,
  );
  const sent = body.error.code;
  const [sentStatus] = SDK_ERRORS[sent];
  if (sentStatus === 401) c.header("WWW-Authenticate", 'Bearer realm="wssp"');
  const sentRetry = body.error.retryAfterSeconds;
  if (sentRetry !== undefined) c.header("Retry-After", String(sentRetry));
  // A refused WebSocket upgrade (`/v1/sandboxes/{id}/connect`) loses its body:
  // @hono/node-server answers it with `Content-Length: 0` and the headers only.
  // The code and reason (catalog constants, never request data) ride headers
  // too, so the CLI can tell a stopped sandbox from a lost host.
  if (c.req.header("upgrade")?.toLowerCase() === "websocket") {
    c.header("X-Wssp-Error-Code", sent);
    if (body.error.reason) c.header("X-Wssp-Error-Reason", body.error.reason);
  }
  return c.json(body, sentStatus);
}

/** Stands in for the request id when checking an envelope's fields. */
const CONTRACT_PROBE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
/**
 * The public contract is strict and every SDK parses it strictly: an
 * undeclared or malformed field would turn a typed refusal into an untyped
 * `invalid_response` on every client (E2-B-01). The envelope goes out only
 * when it parses; otherwise its extras are dropped and the code kept when
 * the bare envelope is valid, else a bare 500. The parity test in
 * errors.test.ts keeps this fallback unreachable.
 */
function contractEnvelope(body: SandboxApiError, requestId: string): SandboxApiError {
  const valid = (candidate: SandboxApiError) =>
    sdkErrorEnvelopeSchema.safeParse({
      error: { ...candidate.error, requestId: CONTRACT_PROBE_REQUEST_ID },
    }).success;
  if (valid(body)) return body;
  const { code, message, retryAfterSeconds, retryable } = body.error;
  console.error(
    `[sandbox-api] [${requestId}] ${code}: envelope fields outside the contract dropped`,
  );
  const bare: SandboxApiError = {
    error: {
      code,
      message,
      requestId,
      ...(retryable === undefined ? {} : { retryable }),
      ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
    },
  };
  if (valid(bare)) return bare;
  const [, internalMessage] = SDK_ERRORS.INTERNAL_SERVER_ERROR;
  return { error: { code: "INTERNAL_SERVER_ERROR", message: internalMessage, requestId } };
}
