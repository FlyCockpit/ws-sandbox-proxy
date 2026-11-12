/**
 * Canonical C20 `hostCredentials.exchangeDeviceCode` error matrix.
 * `docs/design/device-flow-contract.md` must stay in sync (see contract test).
 */
export type ExchangeDeviceCodeErrorRow = {
  http: number;
  orpcCode: string;
  /** `null` means `data.deviceFlowError` is absent. */
  deviceFlowError: string | null;
  retry: boolean;
  /** Stable row id for doc ↔ code parity tests. */
  id: string;
};

/** Error-table rows only (HTTP 200 success is documented separately). */
export const EXCHANGE_DEVICE_CODE_ERROR_ROWS: readonly ExchangeDeviceCodeErrorRow[] = [
  {
    id: "pending",
    http: 400,
    orpcCode: "BAD_REQUEST",
    deviceFlowError: "authorization_pending",
    retry: true,
  },
  {
    id: "slow_down",
    http: 400,
    orpcCode: "BAD_REQUEST",
    deviceFlowError: "slow_down",
    retry: true,
  },
  {
    id: "expired_token",
    http: 400,
    orpcCode: "BAD_REQUEST",
    deviceFlowError: "expired_token",
    retry: false,
  },
  {
    id: "validation",
    http: 400,
    orpcCode: "BAD_REQUEST",
    deviceFlowError: null,
    retry: false,
  },
  {
    id: "access_denied",
    http: 403,
    orpcCode: "FORBIDDEN",
    deviceFlowError: "access_denied",
    retry: false,
  },
  {
    id: "owner_policy",
    http: 403,
    orpcCode: "FORBIDDEN",
    deviceFlowError: null,
    retry: false,
  },
  {
    id: "not_found",
    http: 404,
    orpcCode: "NOT_FOUND",
    deviceFlowError: null,
    retry: false,
  },
  {
    id: "conflict",
    http: 409,
    orpcCode: "CONFLICT",
    deviceFlowError: null,
    retry: false,
  },
  {
    id: "rate_limit",
    http: 429,
    orpcCode: "TOO_MANY_REQUESTS",
    deviceFlowError: null,
    retry: true,
  },
  {
    id: "transient_unavailable",
    http: 503,
    orpcCode: "SERVICE_UNAVAILABLE",
    deviceFlowError: "authorization_pending",
    retry: true,
  },
];

/**
 * Known throw sites reachable from `exchangeDeviceCode` (handler + mint + budget + CSRF plugin),
 * each mapped to a documented row. This list is maintained by hand; completeness is not
 * inferred from it. Anything unlisted falls under the contract's terminal catch-all rule
 * (docs/design/device-flow-contract.md, retry rule 5), so an unmapped failure can never be
 * mistaken for a retryable outcome.
 */
export const EXCHANGE_DEVICE_CODE_THROW_SITE_IDS = [
  "input_validation", // zod hostSlug / deviceCode
  "budget_rate_limit", // procedure-budget RateLimiterRes
  "budget_unavailable", // procedure-budget fail-closed Redis error → tagged 503
  "mint_invalid_slug", // mintHostDeviceCredentialFromApprovedDeviceCode (defense in depth)
  "mint_not_found",
  "mint_scope_missing",
  "mint_slug_mismatch",
  "mint_pending_poll", // authorization_pending | slow_down | access_denied | expired_token | not_found
  "mint_approved_conflict",
  "mint_approved_not_found",
  "mint_owner_policy",
  "mint_host_slug_conflict",
  "mint_owner_host_limit", // C52-R2-3 SANDBOX_MAX_HOSTS_PER_OWNER
  "mint_transaction_retry", // rethrowDeviceTransactionError → 503 authorization_pending
  "csrf_mismatch", // SimpleCsrfProtectionHandlerPlugin (all browser origins)
] as const;

export type ExchangeDeviceCodeThrowSiteId = (typeof EXCHANGE_DEVICE_CODE_THROW_SITE_IDS)[number];

/** Maps each throw site to one or more contract row ids. */
export const EXCHANGE_DEVICE_CODE_THROW_SITE_ROWS: Record<
  ExchangeDeviceCodeThrowSiteId,
  readonly string[]
> = {
  input_validation: ["validation"],
  budget_rate_limit: ["rate_limit"],
  budget_unavailable: ["transient_unavailable"],
  mint_invalid_slug: ["validation"],
  mint_not_found: ["not_found"],
  mint_scope_missing: ["validation"],
  mint_slug_mismatch: ["validation"],
  mint_pending_poll: ["pending", "slow_down", "access_denied", "expired_token", "not_found"],
  mint_approved_conflict: ["conflict", "not_found"],
  mint_approved_not_found: ["not_found"],
  mint_owner_policy: ["owner_policy"],
  mint_host_slug_conflict: ["conflict"],
  mint_owner_host_limit: ["conflict"],
  mint_transaction_retry: ["transient_unavailable"],
  csrf_mismatch: [], // documented under Transport headers, not error table
};
