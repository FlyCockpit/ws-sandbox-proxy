import {
  actionReceiptSchema,
  BUILD_CONTEXT_ROUTES,
  DOWNLOAD_ROUTES,
  idempotencyKeySchema,
  isSdkErrorCode,
  isTemplateBuildErrorExtrasCode,
  JSON_ROUTES,
  LEASE_FINITE_MAX_MS,
  leaseTimeoutBeyondFiniteMax,
  operationSchema,
  publicOperationErrorCode,
  type SandboxDto,
  SDK_ERRORS,
  type SdkRoute,
  sdkErrorEnvelopeSchema,
  TEMPLATE_BUILD_ERROR_EXTRAS,
  type TemplateBuildContextDto,
  type TemplateBuildErrorExtrasCode,
  TRANSFER_CHUNK_BYTES,
  TRANSFER_MAX_BYTES,
  templateBuildContextSchema,
  transferReceiptSchema,
  UPLOAD_ROUTES,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import {
  classifyCatalogError,
  redactCause,
  WsspError,
  type WsspErrorInit,
  type WsspErrorKind,
  type WsspErrorReason,
} from "./errors";

/** Routes whose body `timeoutMs` is a sandbox lease (create, connect, renew). */
const LEASE_TIMEOUT_ROUTES: ReadonlySet<string> = new Set([
  "createSandbox",
  "reconnectSandbox",
  "renewSandboxLease",
]);

// Forward-compatible client decoding only: the server retains its closed,
// strict code catalog. Unknown strings become values-free generic failures;
// every other operation/receipt field still passes the strict DTO schema.
function genericOperationCode(value: unknown, receipt: boolean): unknown {
  if (
    !value ||
    typeof value !== "object" ||
    !("errorCode" in value) ||
    (value.errorCode !== null && typeof value.errorCode !== "string")
  )
    return value;
  const code = value.errorCode;
  return {
    ...value,
    errorCode: receipt
      ? code === null || isSdkErrorCode(code)
        ? code
        : "INTERNAL_SERVER_ERROR"
      : publicOperationErrorCode(code),
  };
}
const operationReadSchema = z.union([
  z.preprocess((value) => genericOperationCode(value, false), operationSchema),
  z.preprocess((value) => genericOperationCode(value, true), actionReceiptSchema),
]);

type ErrorBody = z.output<typeof sdkErrorEnvelopeSchema>["error"];
/**
 * The strict envelope after dropping fields the code's variant does not
 * declare (a newer server added one this SDK does not know, E2-B-01). Every
 * declared field is still validated strictly and a required one must be
 * present; an unknown code still fails. Null when that does not parse.
 */
function envelopeIgnoringUnknownFields(json: unknown): ErrorBody | null {
  if (!json || typeof json !== "object" || !("error" in json)) return null;
  const error = json.error;
  if (!error || typeof error !== "object" || !("code" in error)) return null;
  const variant = sdkErrorEnvelopeSchema.shape.error.options.find(
    (option) => option.shape.code.safeParse(error.code).success,
  );
  if (!variant) return null;
  const known = Object.fromEntries(
    Object.entries(error).filter(([key]) => Object.hasOwn(variant.shape, key)),
  );
  const parsed = sdkErrorEnvelopeSchema.safeParse({ error: known });
  return parsed.success ? parsed.data.error : null;
}
/** A `template.build_*` refusal with typed fields (narrows the envelope union). */
function isBuildRefusal(
  error: ErrorBody,
): error is Extract<ErrorBody, { code: TemplateBuildErrorExtrasCode }> {
  return isTemplateBuildErrorExtrasCode(error.code);
}

/** The subset of WHATWG `fetch` the transport uses. Inject one for tests or custom agents. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export type WsspTransportOptions = {
  /** API origin, optionally with a path prefix. HTTPS, or HTTP only for loopback hosts. */
  baseUrl: string | URL;
  /** A `wssp_sdk_` key. Never read from the environment by this package. */
  apiKey: string;
  fetch?: FetchLike;
  /** Per-request deadline covering redirects and the response body. Default 30 s. */
  timeoutMs?: number;
};

export type RequestOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
};

/** The upload registry routes carried by JSON bodies (the chunk PUT is binary). */
const TRANSFER_JSON_ROUTES = {
  createUpload: UPLOAD_ROUTES.createUpload,
  getUpload: UPLOAD_ROUTES.getUpload,
  commitUpload: UPLOAD_ROUTES.commitUpload,
  abortUpload: UPLOAD_ROUTES.abortUpload,
} as const;
/** The build-context routes carried by JSON bodies (the chunk PUT is binary). */
const BUILD_CONTEXT_JSON_ROUTES = {
  openBuildContext: BUILD_CONTEXT_ROUTES.openBuildContext,
  sealBuildContext: BUILD_CONTEXT_ROUTES.sealBuildContext,
} as const;
const REQUEST_ROUTES = { ...JSON_ROUTES, ...TRANSFER_JSON_ROUTES, ...BUILD_CONTEXT_JSON_ROUTES };
type Routes = typeof REQUEST_ROUTES;
/** Every route `request` serves: the JSON registry plus the JSON transfer routes. */
export type RequestRouteId = keyof Routes;
type ParamsInput<K extends RequestRouteId> = null extends Routes[K]["params"]
  ? { params?: undefined }
  : { params: z.input<Extract<Routes[K]["params"], z.ZodType>> };
type BodyInput<K extends RequestRouteId> = Routes[K] extends { body: infer B extends z.ZodType }
  ? (Record<string, never> extends z.input<B> ? { body?: z.input<B> } : { body: z.input<B> }) &
      (Routes[K] extends { idempotency: false }
        ? { idempotencyKey?: undefined }
        : {
            /** Required on every mutation; reuse it to retry an `unknown` outcome. */
            idempotencyKey: string;
          })
  : { body?: undefined; idempotencyKey?: undefined };

/** Input of one `/v1` JSON route; query values are wire strings (e.g. `limit: "20"`). */
export type RouteRequest<K extends RequestRouteId> = ParamsInput<K> &
  BodyInput<K> & { query?: z.input<Routes[K]["query"]> } & RequestOptions;

/** Validated success body of one route (200 read, 201 receipt or 202 mutation receipt). */
export type RouteResponse<K extends RequestRouteId> = z.output<Routes[K]["response"]["schema"]>;

/** One transfer receipt, as returned by the upload routes. */
export type TransferReceiptDto = z.output<typeof transferReceiptSchema>;

/** One fixed binary chunk write of an upload reservation. */
export type UploadChunkRequest = {
  params: { id: string };
  /** Chunk start: a multiple of TRANSFER_CHUNK_BYTES, below `total`. */
  offset: number;
  /** The reserved total; sent as the Content-Range denominator. */
  total: number;
  /** Exactly `min(TRANSFER_CHUNK_BYTES, total - offset)` bytes. */
  bytes: Uint8Array;
} & RequestOptions;

/** One fixed binary chunk of a template build's staged context. */
export type BuildContextChunkRequest = {
  /** The build id. */
  params: { id: string };
  /** Chunk start: a multiple of TRANSFER_CHUNK_BYTES, below `total`. */
  offset: number;
  /** The context's declared total (`contextBytes`). */
  total: number;
  /** Exactly `min(TRANSFER_CHUNK_BYTES, total - offset)` bytes. */
  bytes: Uint8Array;
} & RequestOptions;

/** One byte range of a download: `start`-`end` inclusive (open-ended without `end`). */
export type DownloadRange = { start: number; end?: number } | { suffix: number };

export type DownloadRequest = {
  params: { id: string };
  range?: DownloadRange;
  /** Strong ETag of a previous read of this capture; a mismatch restarts at 200. */
  ifRange?: string;
  /** Read the headers only (no body stream). */
  head?: boolean;
} & RequestOptions;

/** One answered download: validated headers plus the byte stream (null for HEAD). */
export type DownloadContent = {
  status: 200 | 206;
  /** Whole-capture SHA-256 hex (the ETag payload). */
  sha256: string;
  etag: string;
  /** Total capture size in bytes. */
  size: number;
  /** Offset of the first byte of this response. */
  start: number;
  /** Bytes carried by this response. */
  length: number;
  body: ReadableStream<Uint8Array> | null;
};

export type WsspTransport = {
  readonly baseUrl: string;
  request<K extends RequestRouteId>(route: K, input: RouteRequest<K>): Promise<RouteResponse<K>>;
  /**
   * Write one fixed upload chunk (PUT /v1/transfers/{id}). A lost response is
   * kind `unknown`; re-sending the IDENTICAL chunk is always safe (the server
   * digest-checks replays and conflicts changed bytes at an accepted offset).
   */
  putUploadChunk(input: UploadChunkRequest): Promise<TransferReceiptDto>;
  /**
   * Write one fixed chunk of a build's staged context
   * (PUT /v1/template-builds/{id}/context/chunks/{offset}). Re-sending the
   * identical chunk is safe; a lost response is kind `unknown`.
   */
  putBuildContextChunk(input: BuildContextChunkRequest): Promise<TemplateBuildContextDto>;
  /**
   * Open one capture download (GET /v1/operations/{id}/content), whole or one
   * range. The deadline covers the headers; the returned stream is bounded by
   * the server's idle deadline and the caller's signal, which cancels it.
   */
  downloadContent(input: DownloadRequest): Promise<DownloadContent>;
  /** The sandbox, or null only when the server confirms `sandbox.not_found`. */
  findSandbox(id: string, options?: RequestOptions): Promise<SandboxDto | null>;
  /**
   * A bounded, redacted copy of an arbitrary thrown value (caller callbacks,
   * injected fetch errors), safe to attach as a WsspError cause: the API key
   * and credential-shaped text are stripped, the original object is dropped.
   */
  redactCause(cause: unknown): Error | undefined;
};

type LooseRequest = {
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  body?: unknown;
  idempotencyKey?: unknown;
} & RequestOptions;

export const DEFAULT_TIMEOUT_MS = 30_000;
/** Largest timeout for ONE request; multi-phase budgets may exceed it. */
export const MAX_TIMEOUT_MS = 15 * 60_000;
export const MAX_REDIRECTS = 3;
/** Largest JSON response read into memory; documented pages are far smaller. */
export const RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const API_KEY_PATTERN = /^wssp_sdk_[A-Za-z0-9_-]{1,512}$/;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

const MAX_DESCRIBED_ISSUES = 5;

/**
 * Where a local body check failed (E-23): each issue's field path and zod
 * issue code, e.g. `envs: custom`. Never the input value or the zod
 * message, which can quote it (an env value may be a secret). Request bodies
 * are strict objects, so string path segments are schema-declared keys; any
 * segment that is not identifier-shaped is still masked.
 */
function describeIssues(issues: readonly { path: readonly PropertyKey[]; code: string }[]): string {
  const described = issues.slice(0, MAX_DESCRIBED_ISSUES).map((issue) => {
    const path = issue.path
      .map((segment) =>
        typeof segment === "number"
          ? `[${segment}]`
          : typeof segment === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(segment)
            ? `.${segment}`
            : ".*",
      )
      .join("")
      .replace(/^\./, "");
    return `${path || "body"}: ${issue.code}`;
  });
  if (issues.length > MAX_DESCRIBED_ISSUES)
    described.push(`${issues.length - MAX_DESCRIBED_ISSUES} more`);
  return described.join("; ");
}

// Messages never echo the input: a malformed URL may itself contain a credential.
function parseBaseUrl(input: string | URL): URL {
  let url: URL;
  try {
    url = new URL(String(input));
  } catch {
    throw new TypeError("baseUrl must be an absolute URL.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("baseUrl must not contain credentials, a query or a fragment.");
  }
  if (!(url.protocol === "https:" || (url.protocol === "http:" && isLoopback(url.hostname)))) {
    throw new TypeError("baseUrl must use https; http is accepted only for loopback hosts.");
  }
  // An empty `?` or `#` passes the checks above (search and hash read "") but
  // stays in `href`; clear both so no route URL carries it (FSDK-R1-2).
  url.search = "";
  url.hash = "";
  url.pathname = basePath(url);
  return url;
}

/**
 * The base's path prefix without trailing slashes: "" for an origin-only base.
 * WHATWG gives a special-scheme URL a pathname of at least "/", so this must
 * never be read back from `URL.pathname` (C58-1: "https://host" joined "//v1").
 */
function basePath(base: URL): string {
  return base.pathname.replace(/\/+$/, "");
}

/** THE route URL join: every request target is the base origin + prefix + route path. */
function routeUrl(base: URL, path: string): URL {
  const url = new URL(base.href);
  url.pathname = `${basePath(base)}${path}`;
  return url;
}

function parseTimeout(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS) {
    throw new TypeError(`timeoutMs must be an integer from 1 to ${MAX_TIMEOUT_MS}.`);
  }
  return value;
}

function isRedirect(response: Response): boolean {
  return (
    response.type === "opaqueredirect" ||
    (response.status >= 300 && response.status < 400 && response.status !== 304)
  );
}

function discard(response: Response): void {
  response.body?.cancel().catch(() => {});
}

/**
 * Body text, or null when it exceeds the cap or is not UTF-8. Stream and abort
 * errors propagate. An injected fetch may not tie its body to `signal`, so the
 * deadline is enforced here as well: a cancelled read ends early and throws.
 */
async function readBody(response: Response, signal: AbortSignal): Promise<string | null> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const cancel = () => {
    reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      total += value.byteLength;
      if (total > RESPONSE_MAX_BYTES) {
        cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function parseJson(text: string | null): unknown {
  if (text === null || text === "") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Non-catalog failure status on a read: a proxy page, an unexpected 2xx, etc. */
function fallbackKind(status: number): WsspErrorKind {
  // A proxy 429/504 without the wssp envelope is still capacity/timeout:
  // polling must honor its Retry-After header instead of terminating.
  if (status === 429) return "capacity";
  if (status === 504) return "timeout";
  if (status >= 500) return "unavailable";
  return "protocol";
}

/** Same bound as the error envelope's `retryAfterSeconds` (1 s … 24 h). */
const RETRY_AFTER_MAX_SECONDS = 86_400;

/**
 * The `Retry-After` header in seconds, or null when absent/unparseable/out of
 * range. Both HTTP forms are accepted (delta-seconds and HTTP-date); a proxy
 * error page carries the header without a JSON envelope.
 */
function parseRetryAfter(value: string | null): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  let seconds: number;
  if (/^\d{1,7}$/.test(trimmed)) {
    seconds = Number(trimmed);
  } else {
    const at = Date.parse(trimmed);
    if (Number.isNaN(at)) return null;
    seconds = Math.ceil((at - Date.now()) / 1000);
  }
  return seconds >= 1 && seconds <= RETRY_AFTER_MAX_SECONDS ? seconds : null;
}

export function createWsspTransport(options: WsspTransportOptions): WsspTransport {
  const base = parseBaseUrl(options.baseUrl);
  if (typeof options.apiKey !== "string" || !API_KEY_PATTERN.test(options.apiKey)) {
    throw new TypeError("apiKey must be a wssp_sdk_ key.");
  }
  // Held only in this closure: never a property, so inspection/serialization of
  // the transport cannot reveal it.
  const apiKey = options.apiKey;
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const defaultTimeout = parseTimeout(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const baseUrl = base.href.replace(/\/$/, "");

  function buildUrl(route: SdkRoute, input: LooseRequest): URL | null {
    let path: string = route.path;
    if (route.params) {
      const parsed = route.params.safeParse(input.params ?? {});
      if (!parsed.success) return null;
      for (const [name, value] of Object.entries(parsed.data as Record<string, string>)) {
        path = path.replace(`{${name}}`, encodeURIComponent(value));
      }
    } else if (input.params !== undefined) {
      return null;
    }
    const query = input.query ?? {};
    if (!route.query.safeParse(query).success) return null;
    const url = routeUrl(base, path);
    for (const [name, value] of Object.entries(query)) {
      if (value !== undefined) url.searchParams.set(name, String(value));
    }
    return url;
  }

  type Fail = (kind: WsspErrorKind, detail: string, extra?: Partial<WsspErrorInit>) => WsspError;

  /** One settled request: the response plus the deadline/abort machinery. */
  type Exchange = {
    response: Response;
    fail: Fail;
    interrupted(error: unknown): WsspError;
    /** End the deadline; the response (or its body) no longer races the timer. */
    disarmTimer(): void;
    /** Fully release: timer plus the caller-abort wiring. Terminal exactly once. */
    release(): void;
    controller: AbortController;
    callerSignal: AbortSignal | undefined;
  };

  type ExchangeArgs = {
    sensitiveBody?: boolean;
    routeId: string;
    mutation: boolean;
    idempotencyKey: string | null;
    url: URL;
    method: string;
    headers: Record<string, string>;
    body: string | Uint8Array | undefined;
    timeoutMs: number;
    signal: AbortSignal | undefined;
  };

  /**
   * Send one request (same-origin redirects only, bearer key retained) and
   * settle at the response headers. The deadline and caller abort stay wired
   * until `release`; a streaming caller disarms the timer at the headers and
   * releases when the body ends.
   */
  async function openExchange(args: ExchangeArgs): Promise<Exchange> {
    const fail: Fail = (kind, detail, extra = {}) =>
      new WsspError({
        kind,
        message: `${args.routeId}: ${detail}`,
        route: args.routeId,
        idempotencyKey: args.idempotencyKey,
        ...extra,
      });
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, args.timeoutMs);
    const onAbort = () => controller.abort();
    args.signal?.addEventListener("abort", onAbort, { once: true });
    let timerArmed = true;
    const disarmTimer = () => {
      if (!timerArmed) return;
      timerArmed = false;
      clearTimeout(timer);
    };
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      disarmTimer();
      args.signal?.removeEventListener("abort", onAbort);
    };
    const transportFailure = (reason: WsspErrorReason, cause?: unknown, status?: number) => {
      const kind: WsspErrorKind = args.mutation
        ? "unknown"
        : reason === "timeout"
          ? "timeout"
          : reason === "aborted"
            ? "aborted"
            : reason === "redirect_refused"
              ? "protocol"
              : "unavailable";
      const detail = args.mutation ? "the outcome is unknown" : "the request failed";
      return fail(kind, `${detail} (${reason}).`, {
        reason,
        status: status ?? null,
        // An injected fetch error can quote the request body. Secret-bearing
        // mutations drop its diagnostic chain before constructing SDK errors.
        cause: args.sensitiveBody ? undefined : redactCause(cause, apiKey),
      });
    };
    const interrupted = (error: unknown) =>
      transportFailure(timedOut ? "timeout" : args.signal?.aborted ? "aborted" : "network", error);
    try {
      let target = args.url;
      let method = args.method;
      let response: Response;
      for (let hop = 0; ; hop++) {
        try {
          response = await fetchImpl(target.href, {
            method,
            headers: args.headers,
            body:
              method === "GET" || method === "HEAD"
                ? undefined
                : (args.body as RequestInit["body"]),
            redirect: "manual",
            credentials: "omit",
            signal: controller.signal,
          });
        } catch (error) {
          throw interrupted(error);
        }
        if (!isRedirect(response)) break;
        discard(response);
        const preservesMethod = response.status === 307 || response.status === 308;
        let next: URL | null = null;
        try {
          const location = response.headers.get("location");
          next = location ? new URL(location, target) : null;
        } catch {
          next = null;
        }
        // Only same-origin hops keep the bearer key on the wire, and only hops
        // that keep the method and body (or a plain GET/HEAD) are followed.
        if (
          !next ||
          next.origin !== base.origin ||
          hop >= MAX_REDIRECTS ||
          (!preservesMethod && method !== "GET" && method !== "HEAD")
        ) {
          throw transportFailure("redirect_refused", undefined, response.status);
        }
        target = next;
        // 301/302/303 rewrite POST-like requests to GET, but HEAD carries no
        // body: a header-only download stays HEAD across every hop.
        method = preservesMethod || method === "HEAD" ? method : "GET";
      }
      return {
        response,
        fail,
        interrupted,
        disarmTimer,
        release,
        controller,
        callerSignal: args.signal,
      };
    } catch (error) {
      release();
      throw error;
    }
  }

  type ResponseInfo = {
    json: unknown;
    requestId: string | null;
    retryAfter: number | null;
  };

  /** Bounded read of a (small) JSON body plus the metadata headers. */
  async function readInfo(exchange: Exchange): Promise<ResponseInfo> {
    const { response } = exchange;
    const headerRequestId = response.headers.get("x-request-id");
    const requestId =
      headerRequestId && REQUEST_ID_PATTERN.test(headerRequestId) ? headerRequestId : null;
    let text: string | null;
    try {
      text = await readBody(response, exchange.controller.signal);
    } catch (error) {
      throw exchange.interrupted(error);
    }
    return {
      json: parseJson(text),
      requestId,
      // A proxy error page carries Retry-After without a JSON envelope.
      retryAfter: parseRetryAfter(response.headers.get("retry-after")),
    };
  }

  /** The WsspError for a non-success status: the catalog envelope when it matches. */
  function statusError(
    exchange: Exchange,
    mutation: boolean,
    status: number,
    info: ResponseInfo,
  ): WsspError {
    const strict = sdkErrorEnvelopeSchema.safeParse(info.json);
    const parsed = strict.success ? strict.data.error : envelopeIgnoringUnknownFields(info.json);
    if (parsed) {
      const { code, requestId: bodyRequestId, retryAfterSeconds } = parsed;
      const [catalogStatus, catalogMessage] = SDK_ERRORS[code];
      if (catalogStatus === status) {
        const kind = classifyCatalogError(code, mutation);
        const error = parsed;
        if (isBuildRefusal(error)) {
          // Build refusals carry their own typed fields (`WsspError.build`).
          const { code: _c, message: _m, requestId: _r, retryAfterSeconds: _a, ...fields } = error;
          const build = TEMPLATE_BUILD_ERROR_EXTRAS[error.code].safeParse(fields);
          return exchange.fail(kind, `${catalogMessage} (${code}, HTTP ${status})`, {
            code,
            status,
            requestId: bodyRequestId,
            retryAfterSeconds: retryAfterSeconds ?? info.retryAfter,
            build: build.success ? build.data : null,
          });
        }
        return exchange.fail(kind, `${catalogMessage} (${code}, HTTP ${status})`, {
          code,
          status,
          requestId: bodyRequestId,
          // A permanent refusal carries no backoff, even if a proxy adds a header.
          retryAfterSeconds:
            "retryable" in error && error.retryable === false
              ? null
              : (retryAfterSeconds ?? info.retryAfter),
          resource: "resource" in error ? error.resource : null,
          maxTimeoutMs: "maxTimeoutMs" in error ? error.maxTimeoutMs : null,
          skipped: "skipped" in error ? (error.skipped ?? null) : null,
          maxWaitMs: "maxWaitMs" in error ? error.maxWaitMs : null,
          scope: "scope" in error ? error.scope : null,
          retryable: "retryable" in error ? error.retryable : null,
          hint: "hint" in error ? (error.hint ?? null) : null,
          keyLimit: error.code === "sandbox.key_limit_reached" ? error.data : null,
          valueInvalid:
            error.code === "credential.value_invalid"
              ? { entry: error.entry ?? null, path: error.path ?? null }
              : null,
          reason:
            ("reason" in error ? error.reason : undefined) ??
            (error.code === "host.file_error" ? error.data.reason : undefined) ??
            // Image quota scope doubles as the reason (stored | downloads).
            (error.code === "sandbox.image_quota_exceeded" ? error.scope : undefined) ??
            (kind === "unknown" && status >= 500 ? "server_error" : null),
        });
      }
    }
    return exchange.fail(
      mutation ? "unknown" : fallbackKind(status),
      `unexpected HTTP ${status} response.`,
      {
        reason: status >= 500 ? "server_error" : "invalid_response",
        status,
        requestId: info.requestId,
        retryAfterSeconds: info.retryAfter,
      },
    );
  }

  /** Request-time validation reports typed invalid_request errors, unlike the
   * constructor's TypeError for a malformed default. */
  function requestTimeout(fail: Fail, value: number | undefined): number {
    if (value !== undefined && (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS)) {
      throw fail("invalid_request", `timeoutMs must be an integer from 1 to ${MAX_TIMEOUT_MS}.`);
    }
    return value ?? defaultTimeout;
  }

  async function request<K extends RequestRouteId>(
    id: K,
    rawInput: RouteRequest<K>,
  ): Promise<RouteResponse<K>> {
    const input = rawInput as unknown as LooseRequest;
    const route: SdkRoute = REQUEST_ROUTES[id];
    const mutation = route.body !== undefined;
    const keyed = mutation && route.idempotency !== false;
    const idempotencyKey =
      keyed && typeof input.idempotencyKey === "string" ? input.idempotencyKey : null;
    const fail: Fail = (kind, detail, extra = {}) =>
      new WsspError({ kind, message: `${id}: ${detail}`, route: id, idempotencyKey, ...extra });

    const timeoutMs = requestTimeout(fail, input.timeoutMs);
    const url = buildUrl(route, input);
    if (!url) throw fail("invalid_request", "invalid path parameters or query.");
    let body: string | undefined;
    if (route.body) {
      if (keyed && !idempotencyKeySchema.safeParse(input.idempotencyKey).success) {
        throw fail("invalid_request", "a valid idempotencyKey is required.");
      }
      if (!keyed && input.idempotencyKey !== undefined) {
        throw fail("invalid_request", "this route takes no idempotency key.");
      }
      const payload = input.body ?? {};
      const parsed = route.body.safeParse(payload);
      if (!parsed.success) {
        throw fail(
          "invalid_request",
          `the request body does not match the route schema (${describeIssues(parsed.error.issues)}).`,
        );
      }
      // A well-formed lease above the finite ceiling can never be admitted:
      // answer as the server does (`lease_exceeds_policy` with the ceiling).
      // Only lease routes: a command's `timeoutMs` is a different field.
      if (
        LEASE_TIMEOUT_ROUTES.has(id) &&
        leaseTimeoutBeyondFiniteMax((payload as { timeoutMs?: unknown }).timeoutMs)
      ) {
        throw fail("invalid_request", "timeoutMs exceeds the lease policy maximum.", {
          code: "lease_exceeds_policy",
          maxTimeoutMs: LEASE_FINITE_MAX_MS,
        });
      }
      body = JSON.stringify(payload);
    } else if (input.body !== undefined || input.idempotencyKey !== undefined) {
      throw fail("invalid_request", "this route takes no body or idempotency key.");
    }
    if (input.signal?.aborted) throw fail("aborted", "aborted before the request was sent.");

    const headers: Record<string, string> = {
      accept: "application/json",
      authorization: `Bearer ${apiKey}`,
    };
    // A serialized JSON body always carries its media type — independently of
    // the idempotency key (a keyless JSON route like abortUpload otherwise
    // sends an unlabeled body the server's media-type check rejects, 415).
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    if (idempotencyKey !== null) {
      headers["idempotency-key"] = idempotencyKey;
    }

    const exchange = await openExchange({
      routeId: id,
      sensitiveBody: [
        "createSandbox",
        "startCommand",
        "writeStdin",
        "sendProcessStdin",
        "statPath",
        "listDir",
        "mkdir",
        "movePath",
        "removePath",
        "requestDownload",
        "createUpload",
        "createTemplateBuild",
      ].includes(id),
      mutation,
      idempotencyKey,
      url,
      method: route.method.toUpperCase(),
      headers,
      body,
      timeoutMs,
      signal: input.signal,
    });
    try {
      const status = exchange.response.status;
      const info = await readInfo(exchange);
      const successStatus = route.successStatus ?? (mutation ? 202 : 200);
      if (status === successStatus) {
        const schema = id === "getOperation" ? operationReadSchema : route.response.schema;
        const parsed = schema.safeParse(info.json);
        if (parsed.success) return parsed.data as RouteResponse<K>;
        throw exchange.fail(
          mutation ? "unknown" : "protocol",
          `the ${status} response does not match the ${route.response.name} schema.`,
          { reason: "invalid_response", status, requestId: info.requestId },
        );
      }
      throw statusError(exchange, mutation, status, info);
    } finally {
      exchange.release();
    }
  }

  async function putUploadChunk(input: UploadChunkRequest): Promise<TransferReceiptDto> {
    const route: SdkRoute = UPLOAD_ROUTES.putUploadChunk;
    const fail: Fail = (kind, detail, extra = {}) =>
      new WsspError({
        kind,
        message: `putUploadChunk: ${detail}`,
        route: "putUploadChunk",
        ...extra,
      });
    const { offset, total, bytes } = input;
    // Mirror the server's chunk rules BEFORE any IO, so a malformed chunk
    // never consumes a request: aligned offset, exact fixed-chunk length.
    if (!Number.isSafeInteger(total) || total < 1 || total > TRANSFER_MAX_BYTES) {
      throw fail("invalid_request", `total must be an integer from 1 to ${TRANSFER_MAX_BYTES}.`);
    }
    if (
      !Number.isSafeInteger(offset) ||
      offset % TRANSFER_CHUNK_BYTES !== 0 ||
      offset < 0 ||
      offset >= total
    ) {
      throw fail("invalid_request", "offset must be a chunk multiple below the reserved total.");
    }
    const expected = Math.min(TRANSFER_CHUNK_BYTES, total - offset);
    if (bytes.byteLength !== expected) {
      throw fail(
        "invalid_request",
        `the chunk at offset ${offset} must be exactly ${expected} bytes.`,
      );
    }
    const timeoutMs = requestTimeout(fail, input.timeoutMs);
    const url = buildUrl(route, { params: input.params, query: {} });
    if (!url) throw fail("invalid_request", "invalid transfer id.");
    if (input.signal?.aborted) throw fail("aborted", "aborted before the request was sent.");
    const exchange = await openExchange({
      routeId: "putUploadChunk",
      // A chunk write whose response is lost is uncertain: kind `unknown`. The
      // identical-chunk replay makes the retry safe without an idempotency key.
      mutation: true,
      idempotencyKey: null,
      url,
      method: "PUT",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/octet-stream",
        "content-range": `bytes ${offset}-${offset + bytes.byteLength - 1}/${total}`,
      },
      body: bytes,
      timeoutMs,
      signal: input.signal,
    });
    try {
      const status = exchange.response.status;
      const info = await readInfo(exchange);
      if (status === 200) {
        const parsed = transferReceiptSchema.safeParse(info.json);
        if (parsed.success) return parsed.data;
        throw exchange.fail(
          "unknown",
          "the 200 response does not match the TransferReceipt schema.",
          { reason: "invalid_response", status, requestId: info.requestId },
        );
      }
      throw statusError(exchange, true, status, info);
    } finally {
      exchange.release();
    }
  }

  async function putBuildContextChunk(
    input: BuildContextChunkRequest,
  ): Promise<TemplateBuildContextDto> {
    const route: SdkRoute = BUILD_CONTEXT_ROUTES.putBuildContextChunk;
    const fail: Fail = (kind, detail, extra = {}) =>
      new WsspError({
        kind,
        message: `putBuildContextChunk: ${detail}`,
        route: "putBuildContextChunk",
        ...extra,
      });
    const { offset, total, bytes } = input;
    if (!Number.isSafeInteger(total) || total < 1 || total > TRANSFER_MAX_BYTES) {
      throw fail("invalid_request", `total must be an integer from 1 to ${TRANSFER_MAX_BYTES}.`);
    }
    if (
      !Number.isSafeInteger(offset) ||
      offset % TRANSFER_CHUNK_BYTES !== 0 ||
      offset < 0 ||
      offset >= total
    ) {
      throw fail("invalid_request", "offset must be a chunk multiple below the context size.");
    }
    const expected = Math.min(TRANSFER_CHUNK_BYTES, total - offset);
    if (bytes.byteLength !== expected) {
      throw fail(
        "invalid_request",
        `the chunk at offset ${offset} must be exactly ${expected} bytes.`,
      );
    }
    const timeoutMs = requestTimeout(fail, input.timeoutMs);
    const url = buildUrl(route, {
      params: { id: input.params.id, offset: String(offset) },
      query: {},
    });
    if (!url) throw fail("invalid_request", "invalid build id.");
    if (input.signal?.aborted) throw fail("aborted", "aborted before the request was sent.");
    const exchange = await openExchange({
      routeId: "putBuildContextChunk",
      mutation: true,
      idempotencyKey: null,
      url,
      method: "PUT",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/octet-stream",
      },
      body: bytes,
      timeoutMs,
      signal: input.signal,
    });
    try {
      const status = exchange.response.status;
      const info = await readInfo(exchange);
      if (status === 200) {
        const parsed = templateBuildContextSchema.safeParse(info.json);
        if (parsed.success) return parsed.data;
        throw exchange.fail(
          "unknown",
          "the 200 response does not match the TemplateBuildContext schema.",
          { reason: "invalid_response", status, requestId: info.requestId },
        );
      }
      throw statusError(exchange, true, status, info);
    } finally {
      exchange.release();
    }
  }

  const ETAG_PATTERN = /^"([a-f0-9]{64})"$/;
  const CONTENT_RANGE_PATTERN = /^bytes (\d+)-(\d+)\/(\d+)$/;

  /**
   * Hand the response body to the caller as a stream: the per-request deadline
   * ends at the headers (a large capture streams far longer than 30 s); the
   * caller's signal cancels the stream, and the machinery releases exactly
   * once on completion, error or cancel.
   */
  function watchBody(exchange: Exchange): ReadableStream<Uint8Array> {
    const body = exchange.response.body;
    exchange.disarmTimer();
    if (!body) {
      exchange.release();
      return new ReadableStream({ start: (c) => c.close() });
    }
    const reader = body.getReader();
    const caller = exchange.callerSignal;
    let abortedByCaller = false;
    const abortError = () =>
      new WsspError({
        kind: "aborted",
        reason: "aborted",
        message: "downloadFile: the response body read was aborted.",
        route: "downloadFile",
      });
    const onAbort = () => {
      // reader.cancel() RESOLVES a pending WHATWG read with done: true — it
      // need not reject. Flag the abort so the next pull ERRORS the stream
      // instead of closing it like a successful (truncated) EOF.
      abortedByCaller = true;
      reader.cancel().catch(() => {});
    };
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      caller?.removeEventListener("abort", onAbort);
      exchange.release();
    };
    if (caller?.aborted) {
      abortedByCaller = true;
      finish();
      reader.cancel().catch(() => {});
    } else {
      caller?.addEventListener("abort", onAbort, { once: true });
    }
    return new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          try {
            const result = await reader.read();
            if (abortedByCaller) {
              finish();
              throw abortError();
            }
            if (result.done) {
              finish();
              c.close();
              return;
            }
            c.enqueue(result.value);
          } catch (error) {
            finish();
            // A body failure comes from the injected fetch adapter and may
            // carry its diagnostics — including the Authorization header it
            // was given. Direct transport callers have no files-layer
            // redaction, so normalize HERE: fixed message, redacted cause.
            if (abortedByCaller) {
              throw abortError();
            }
            throw new WsspError({
              kind: "unavailable",
              code: "TRANSFER_IO",
              message: "downloadFile: the response body failed mid-stream.",
              route: "downloadFile",
              cause: redactCause(error, apiKey),
            });
          }
        },
        cancel(reason) {
          finish();
          // Cancellation is REQUESTED, never awaited: an adapter body whose
          // cancel() never settles must not hang `stream.cancel()` — the
          // caller's own deadline/abort already guards byte delivery.
          void reader.cancel(reason).catch(() => {});
        },
      },
      // Demand-driven: a zero high-water mark means the underlying body is
      // read only when a consumer asks, so a pre-read gate (the memory cap)
      // can reject before a single byte moves.
      { highWaterMark: 0 },
    );
  }

  /** Validate the documented download headers; a missing piece is protocol. */
  function materializeDownload(
    exchange: Exchange,
    head: boolean,
    spanOk?: (status: 200 | 206, start: number, size: number, length: number) => boolean,
  ): DownloadContent {
    const { response } = exchange;
    const status = response.status as 200 | 206;
    const bad = (detail: string): WsspError =>
      exchange.fail("protocol", detail, { reason: "invalid_response", status });
    const etagHeader = response.headers.get("etag");
    const etag = etagHeader ? ETAG_PATTERN.exec(etagHeader) : null;
    const sha256 = etag?.[1];
    if (!etagHeader || !sha256) throw bad("the response is missing a strong capture ETag.");
    const lengthHeader = response.headers.get("content-length");
    if (!lengthHeader || !/^\d{1,15}$/.test(lengthHeader)) {
      throw bad("the response is missing a valid Content-Length.");
    }
    const length = Number(lengthHeader);
    let start = 0;
    let size = length;
    if (status === 206) {
      const match = CONTENT_RANGE_PATTERN.exec(response.headers.get("content-range") ?? "");
      const first = match?.[1] !== undefined ? Number(match[1]) : Number.NaN;
      const last = match?.[2] !== undefined ? Number(match[2]) : Number.NaN;
      const total = match?.[3] !== undefined ? Number(match[3]) : Number.NaN;
      if (
        ![first, last, total].every(Number.isSafeInteger) ||
        total < 1 ||
        last < first ||
        last >= total ||
        last - first + 1 !== length
      ) {
        throw bad("the Content-Range does not match the Content-Length.");
      }
      start = first;
      size = total;
    }
    // Span validation runs BEFORE watchBody() acquires the reader: rejecting
    // here leaves the body unlocked so discard() can cancel it and no abort
    // listener is ever attached.
    if (spanOk && !spanOk(status, start, size, length)) {
      throw bad("the response does not cover the requested span.");
    }
    if (head) {
      exchange.release();
      discard(response);
      return { status, sha256, etag: etagHeader, size, start, length, body: null };
    }
    if (exchange.callerSignal?.aborted) {
      exchange.release();
      discard(response);
      throw exchange.fail("aborted", "aborted before the response body was read.", { status });
    }
    return { status, sha256, etag: etagHeader, size, start, length, body: watchBody(exchange) };
  }

  async function downloadContent(input: DownloadRequest): Promise<DownloadContent> {
    const route: SdkRoute = DOWNLOAD_ROUTES.downloadFile;
    const fail: Fail = (kind, detail, extra = {}) =>
      new WsspError({ kind, message: `downloadFile: ${detail}`, route: "downloadFile", ...extra });
    let rangeHeader: string | undefined;
    if (input.range !== undefined) {
      if ("suffix" in input.range) {
        const { suffix } = input.range;
        if (!Number.isSafeInteger(suffix) || suffix < 1) {
          throw fail("invalid_request", "a suffix range must be a positive integer.");
        }
        rangeHeader = `bytes=-${suffix}`;
      } else {
        const { start, end } = input.range;
        if (!Number.isSafeInteger(start) || start < 0) {
          throw fail("invalid_request", "a range start must be a nonnegative integer.");
        }
        if (end !== undefined && (!Number.isSafeInteger(end) || end < start)) {
          throw fail("invalid_request", "a range end must be an integer at or after its start.");
        }
        rangeHeader = `bytes=${start}-${end ?? ""}`;
      }
    }
    if (input.ifRange !== undefined && !ETAG_PATTERN.test(input.ifRange)) {
      throw fail("invalid_request", "ifRange must be the strong capture ETag.");
    }
    const timeoutMs = requestTimeout(fail, input.timeoutMs);
    const url = buildUrl(route, { params: input.params, query: {} });
    if (!url) throw fail("invalid_request", "invalid operation id.");
    if (input.signal?.aborted) throw fail("aborted", "aborted before the request was sent.");
    const exchange = await openExchange({
      routeId: "downloadFile",
      mutation: false,
      idempotencyKey: null,
      url,
      method: input.head === true ? "HEAD" : "GET",
      headers: {
        authorization: `Bearer ${apiKey}`,
        ...(rangeHeader !== undefined ? { range: rangeHeader } : {}),
        ...(input.ifRange !== undefined ? { "if-range": input.ifRange } : {}),
      },
      body: undefined,
      timeoutMs,
      signal: input.signal,
    });
    const status = exchange.response.status;
    if (status === 200 || status === 206) {
      try {
        // The response must answer the COMPLETE requested span, not merely
        // start at the requested offset: an explicit range needs both
        // boundaries, an open-ended range runs to the end of the capture, a
        // suffix range ends at the last byte, and a whole download is 200.
        // Validated inside materializeDownload, before the body is locked.
        const spanOk = (
          status: 200 | 206,
          start: number,
          size: number,
          length: number,
        ): boolean => {
          const range = input.range;
          if (range === undefined) {
            // A whole download is answered 200; an unsolicited 206 partial
            // span silently truncates the capture.
            return status === 200;
          }
          // A range request answered 200 is the If-Range validator restart;
          // the files layer decides whether to accept or conflict on it.
          if (status === 200) return true;
          if ("suffix" in range) {
            return start === Math.max(0, size - range.suffix) && start + length === size;
          }
          const expectLast = range.end === undefined ? size - 1 : Math.min(range.end, size - 1);
          return start === range.start && start + length - 1 === expectLast;
        };
        return materializeDownload(exchange, input.head === true, spanOk);
      } catch (error) {
        exchange.release();
        discard(exchange.response);
        throw error;
      }
    }
    try {
      const info = await readInfo(exchange);
      // A bare 416 (no catalog envelope) still means the range cannot be
      // satisfied: the Content-Range header carries the size, not a body.
      if (status === 416 && !sdkErrorEnvelopeSchema.safeParse(info.json).success) {
        throw fail("invalid_request", "the range is not satisfiable (416).", {
          code: "RANGE_NOT_SATISFIABLE",
          status,
          requestId: info.requestId,
        });
      }
      throw statusError(exchange, false, status, info);
    } finally {
      exchange.release();
    }
  }

  async function findSandbox(id: string, options: RequestOptions = {}) {
    try {
      return await request("getSandbox", { params: { id }, ...options });
    } catch (error) {
      if (error instanceof WsspError && error.code === "sandbox.not_found" && error.status === 404)
        return null;
      throw error;
    }
  }

  return Object.freeze({
    baseUrl,
    request,
    putUploadChunk,
    putBuildContextChunk,
    downloadContent,
    findSandbox,
    redactCause: (cause: unknown) => redactCause(cause, apiKey),
    toJSON: () => ({ baseUrl }),
  });
}
