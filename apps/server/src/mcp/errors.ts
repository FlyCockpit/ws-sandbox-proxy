import { ORPCError } from "@orpc/server";
import { AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE } from "@wssp/config/agent-token-limits";
import { env } from "@wssp/env/server";
import {
  CAPTURE_UNSUPPORTED_REASONS,
  capacityReasonSchema,
  egressRefusalReasonSchema,
  hostFileErrorReasonSchema,
  isRetryableRefusalCode,
  isSdkErrorCode,
  poolFullReasonSchema,
  SDK_ERRORS,
} from "@wssp/sandbox-contracts";

export function mcpError(error: unknown, idempotencyKey?: string) {
  let code = "INTERNAL_SERVER_ERROR",
    message = "Internal server error";
  const extras: Record<string, unknown> = {};
  if (error instanceof ORPCError) {
    const data =
      error.data && typeof error.data === "object" ? (error.data as Record<string, unknown>) : {};
    code = isSdkErrorCode(data.code) ? data.code : isSdkErrorCode(error.code) ? error.code : code;
    message = isSdkErrorCode(code) ? SDK_ERRORS[code][1] : message;
    const reasonSchema =
      code === "host.file_error"
        ? hostFileErrorReasonSchema
        : code === "sandbox.host_capacity"
          ? capacityReasonSchema
          : code === "sandbox.pool_full"
            ? poolFullReasonSchema
            : code === "UNSUPPORTED_CAPABILITY"
              ? egressRefusalReasonSchema
              : null;
    const nestedReason =
      data.data && typeof data.data === "object" && "reason" in data.data
        ? data.data.reason
        : undefined;
    const parsedReason = reasonSchema?.safeParse(
      code === "host.file_error" ? (nestedReason ?? data.reason) : data.reason,
    );
    if (parsedReason?.success) extras.reason = parsedReason.data;
    if (
      code === "sandbox.capture_unsupported" &&
      CAPTURE_UNSUPPORTED_REASONS.some((reason) => reason === data.reason)
    )
      extras.reason = data.reason;
    if (typeof data.retryable === "boolean") extras.retryable = data.retryable;
    if (isRetryableRefusalCode(code) && extras.retryable === true)
      extras.retryAfterSeconds = env.CAPACITY_RETRY_AFTER_SECONDS;
    if (code === "host.agent_access_off") extras.retryable = false;
    if (code === "host.node_offline" || code === "TOO_MANY_REQUESTS") {
      extras.retryable = true;
      extras.retryAfterSeconds =
        typeof data.retryAfterSeconds === "number" &&
        Number.isFinite(data.retryAfterSeconds) &&
        data.retryAfterSeconds > 0
          ? Math.ceil(data.retryAfterSeconds)
          : 1;
    }
  }
  if (extras.retryable === false) delete extras.retryAfterSeconds;
  const result = { code, message, ...extras, ...(idempotencyKey ? { idempotencyKey } : {}) };
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: result }) }],
    structuredContent: { error: result },
    isError: true,
  };
}
export function mcpUnauthorized(resource: string) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "Unauthorized" } }),
    {
      status: 401,
      headers: {
        "content-type": "application/json",
        "WWW-Authenticate": `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource/mcp", resource)}"`,
      },
    },
  );
}

/** An existing no-expiry agent token while the deployment disallows them: 401
 * with a stable machine code, so an agent can tell "re-mint with an expiry"
 * apart from a wrong or revoked token. The token itself is not revoked. */
export function mcpAgentTokenPolicyBlocked(resource: string) {
  const message =
    "This agent token has no expiry, and this deployment no longer allows no-expiry tokens. Mint a token with an expiry, or ask the operator to allow no-expiry tokens.";
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32000,
        message: "Unauthorized",
        data: { code: AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE, message, retryable: false },
      },
    }),
    {
      status: 401,
      headers: {
        "content-type": "application/json",
        "WWW-Authenticate": `Bearer error="invalid_token", error_description="${AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE}", resource_metadata="${new URL("/.well-known/oauth-protected-resource/mcp", resource)}"`,
      },
    },
  );
}

/** Preserve machine retry details and HTTP Retry-After at pre-transport budget boundaries. */
export function mcpQuotaResponse(error: unknown): Response {
  const details = mcpError(error).structuredContent.error;
  return Response.json(
    { jsonrpc: "2.0", id: null, error: { code: -32000, message: details.message, data: details } },
    {
      status: details.code === "TOO_MANY_REQUESTS" ? 429 : 503,
      headers: {
        "Retry-After": String("retryAfterSeconds" in details ? details.retryAfterSeconds : 5),
      },
    },
  );
}
