import {
  OPERATION_WAIT_MAX_MS,
  OPERATION_WAIT_PROGRESS_HOLD_MS,
  OUTPUT_HEAD_BYTES,
  OUTPUT_PAGE_MAX_BYTES,
  OUTPUT_TAIL_BYTES,
  type ProcessRef,
} from "@wssp/sandbox-contracts";
import { isTransientRefusal, WsspError, type WsspErrorKind, type WsspErrorPhase } from "./errors";
import type { WsspTransport } from "./transport";

/** First delay between polls; doubles each round up to `maxIntervalMs`. */
export const DEFAULT_POLL_INTERVAL_MS = 250;
/** Longest delay between polls unless a `Retry-After` asks for more. */
export const DEFAULT_POLL_MAX_INTERVAL_MS = 2_000;
/** Default overall budget of one lifecycle wait. */
export const DEFAULT_WAIT_TIMEOUT_MS = 10 * 60_000;
const MAX_WAIT_TIMEOUT_MS = 60 * 60_000;
/** Default server-side hold of one operation read (long-poll). */
export const DEFAULT_LONG_POLL_MS = 20_000;
/** Largest hold a server accepts (`waitMs`). */
export const MAX_LONG_POLL_MS = OPERATION_WAIT_MAX_MS;
/** A hold shorter than this is not worth asking for; read plainly. */
const LONG_POLL_MIN_MS = 1_000;
/** The held answer must arrive this long before the wait deadline. */
const LONG_POLL_DEADLINE_SLACK_MS = 1_000;
/** Transport timeout of a held read: its hold plus this margin. */
const LONG_POLL_REQUEST_MARGIN_MS = 10_000;
/** An answer this close to the full hold counts as "the server waited". */
const LONG_POLL_EARLY_TOLERANCE_MS = 250;

export type PollingOptions = {
  /** First poll interval. Default 250 ms. */
  intervalMs?: number;
  /** Poll interval cap. Default 2 s. */
  maxIntervalMs?: number;
  /** Overall SDK wait deadline. Default 10 min; never a guest execution budget. */
  waitTimeoutMs?: number;
  /**
   * How long the server may hold one operation status/output/result read
   * open until something changes (long-poll), 0–25000 ms. Default 20 s; 0
   * turns long-polling off (plain interval polling).
   */
  longPollMs?: number;
};

export type ResolvedPolling = {
  intervalMs: number;
  maxIntervalMs: number;
  timeoutMs: number;
  longPollMs: number;
};

/** Per-call wait options: polling bounds plus caller cancellation. */
export type WaitOptions = PollingOptions & { signal?: AbortSignal };

/** Identity attached to errors a wait fabricates itself (deadline, abort). */
export type PollContext = {
  process?: ProcessRef | null;
  phase?: WsspErrorPhase;
  label: string;
  operationId?: string | null;
  idempotencyKey?: string | null;
};

/**
 * `waited`: the attempt was a long-poll the server held for its full hold, so
 * the next attempt goes out at once (the server does the waiting) and the
 * backoff restarts. Never set it for an answer that came back early.
 */
export type PollResult<T> = { done: true; value: T } | { done: false; waited?: boolean };

/** What one attempt may know about the wait it runs in. */
export type PollAttempt = {
  /** Milliseconds left before the wait deadline when the attempt started. */
  remainingMs: number;
};

function boundedInt(name: string, value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer from ${min} to ${max}.`);
  }
  return value;
}

/** Resolve the public wait-budget names before any request can be sent. */
export function waitTimeout(options: PollingOptions | undefined): number | undefined {
  if (options && Reflect.get(options, "timeoutMs") !== undefined)
    throw new WsspError({
      kind: "invalid_request",
      message: "Use waitTimeoutMs for observation waits; timeoutMs is the command budget.",
    });
  return options?.waitTimeoutMs;
}

/** Internal phase deadlines replace the caller's observer budget. */
export function withWaitTimeout<T extends PollingOptions>(options: T, timeoutMs: number) {
  waitTimeout(options);
  return { ...options, waitTimeoutMs: timeoutMs };
}

export function resolvePolling(
  defaults: PollingOptions | undefined,
  options: PollingOptions | undefined,
): ResolvedPolling {
  const defaultTimeout = waitTimeout(defaults);
  const timeout = waitTimeout(options) ?? defaultTimeout;
  const merged = { ...defaults, ...options };
  const intervalMs = boundedInt(
    "polling.intervalMs",
    merged.intervalMs ?? DEFAULT_POLL_INTERVAL_MS,
    1,
    60_000,
  );
  const maxIntervalMs = boundedInt(
    "polling.maxIntervalMs",
    merged.maxIntervalMs ?? DEFAULT_POLL_MAX_INTERVAL_MS,
    1,
    300_000,
  );
  if (intervalMs > maxIntervalMs) {
    throw new TypeError("polling.intervalMs must not exceed polling.maxIntervalMs.");
  }
  const timeoutMs = boundedInt(
    "polling.waitTimeoutMs",
    timeout ?? DEFAULT_WAIT_TIMEOUT_MS,
    1,
    MAX_WAIT_TIMEOUT_MS,
  );
  const longPollMs = boundedInt(
    "polling.longPollMs",
    merged.longPollMs ?? DEFAULT_LONG_POLL_MS,
    0,
    MAX_LONG_POLL_MS,
  );
  return { intervalMs, maxIntervalMs, timeoutMs, longPollMs };
}

/** Only the polling-shape options, for internal phases that set their own deadline. */
export function pollingShape(options: PollingOptions): PollingOptions {
  return {
    ...(options.intervalMs !== undefined ? { intervalMs: options.intervalMs } : {}),
    ...(options.maxIntervalMs !== undefined ? { maxIntervalMs: options.maxIntervalMs } : {}),
    ...(options.longPollMs !== undefined ? { longPollMs: options.longPollMs } : {}),
  };
}

/**
 * The hold to request for one read: the configured long-poll, but never past
 * `remainingMs` minus a margin so the answer lands inside the wait deadline;
 * 0 (plain read) when that leaves less than a second.
 */
export function longPollWaitMs(polling: ResolvedPolling, remainingMs: number): number {
  const ms = Math.floor(Math.min(polling.longPollMs, remainingMs - LONG_POLL_DEADLINE_SLACK_MS));
  return ms >= LONG_POLL_MIN_MS ? ms : 0;
}

/**
 * Whether a held answer that carried progress was paced by the server: it
 * took (nearly) the server's progress hold. A shorter answer (an older server,
 * a capped one, or a misbehaving one) is not trusted to pace the next read.
 */
export function pacedProgress(elapsedMs: number): boolean {
  return elapsedMs >= OPERATION_WAIT_PROGRESS_HOLD_MS - LONG_POLL_EARLY_TOLERANCE_MS;
}

/**
 * Output reads one follow may send back to back: a command's whole retained
 * output (256 KiB head + 768 KiB tail in 64 KiB pages = 16 full pages) plus
 * half again for short pages (the 1,024-chunk page cap on interleaved streams,
 * gap-only pages), so reading a finished command never waits. Only sustained
 * output beyond that (a command printing faster than 32 KiB/s for a long time)
 * is paced; bytes a paced reader falls behind on become explicit gaps, never
 * silent loss.
 */
export const OUTPUT_READ_BURST =
  ((OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES) / OUTPUT_PAGE_MAX_BYTES) * 1.5;

/** Steady-state spacing of one follow's output reads: ≤ 30 a minute. */
export const OUTPUT_READ_INTERVAL_MS = OPERATION_WAIT_PROGRESS_HOLD_MS;

/**
 * Token bucket for one follow's output reads: up to `burst` back to back,
 * then one per `intervalMs`. Long-polls the server paces never wait here;
 * it bounds pagination (`hasMore` pages) and any server that answers early.
 */
export class RequestPacer {
  #tokens: number;
  #last: number;
  constructor(
    readonly burst = OUTPUT_READ_BURST,
    readonly intervalMs = OUTPUT_READ_INTERVAL_MS,
  ) {
    this.#tokens = burst;
    this.#last = Date.now();
  }

  /** Wait for one token; resolves early (without a token) when `signal` aborts. */
  async take(signal: AbortSignal | undefined): Promise<void> {
    for (;;) {
      const now = Date.now();
      this.#tokens = Math.min(this.burst, this.#tokens + (now - this.#last) / this.intervalMs);
      this.#last = now;
      if (this.#tokens >= 1) {
        this.#tokens -= 1;
        return;
      }
      if (signal?.aborted) return;
      await sleep(Math.ceil((1 - this.#tokens) * this.intervalMs), signal);
    }
  }
}

/** Servers that answered `waitMs` with 400 (they predate long-poll), per client transport. */
const longPollUnsupported = new WeakSet<WsspTransport>();

/**
 * One operation read, held server-side for `waitMs` when the server supports
 * it. `read(query, timeoutMs)` receives the `waitMs` query (or nothing) and the
 * transport timeout to use (hold + margin, or the transport default). A server
 * that predates long-poll rejects the unknown `waitMs` with 400 BAD_REQUEST:
 * the first such answer is remembered for this client and the read is repeated
 * plainly. `held` is true when the server accepted a hold for this read.
 * `waited` is true only when it also took (nearly) the whole hold, so a server
 * that answers early without news, e.g. at its waiter cap, is polled with
 * normal backoff instead of in a tight loop. Callers that can tell the answer
 * carried progress may re-issue a `held` read at once (the server holds the
 * next one until there is more).
 */
export async function longPollRead<T>(
  transport: WsspTransport,
  waitMs: number,
  read: (query: { waitMs?: string }, timeoutMs: number | undefined) => Promise<T>,
): Promise<{ value: T; waited: boolean; held: boolean; elapsedMs: number }> {
  if (waitMs <= 0 || longPollUnsupported.has(transport))
    return { value: await read({}, undefined), waited: false, held: false, elapsedMs: 0 };
  const started = Date.now();
  let value: T;
  try {
    value = await read({ waitMs: String(waitMs) }, waitMs + LONG_POLL_REQUEST_MARGIN_MS);
  } catch (error) {
    if (!(error instanceof WsspError && error.status === 400 && error.code === "BAD_REQUEST"))
      throw error;
    longPollUnsupported.add(transport);
    return { value: await read({}, undefined), waited: false, held: false, elapsedMs: 0 };
  }
  const elapsedMs = Date.now() - started;
  return {
    value,
    waited: elapsedMs >= waitMs - LONG_POLL_EARLY_TOLERANCE_MS,
    held: true,
    elapsedMs,
  };
}

/** A timeout that also ends early when `signal` aborts; the loop reports it. */
export function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

export function waitTimeoutError(context: PollContext): WsspError {
  return new WsspError({
    kind: "timeout",
    reason: "timeout",
    message: `${context.label}: timed out waiting for a terminal state.`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

function waitAbortedError(context: PollContext): WsspError {
  return new WsspError({
    kind: "aborted",
    reason: "aborted",
    message: `${context.label}: the wait was aborted.`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * A submission aborted or cut off mid-flight. The request may have reached
 * the server, so the outcome is `unknown` (with the abort/timeout as the
 * reason), never a plain wait error: callers must not mistake an uncertain
 * allocation for safely retryable under a fresh key.
 */
function submissionOutcomeError(reason: "aborted" | "timeout", context: PollContext): WsspError {
  return new WsspError({
    kind: "unknown",
    reason,
    message: `${context.label}: the submission ${reason === "aborted" ? "was aborted" : "timed out"} and may have reached the server; retry only under the same idempotency key.`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * A recovery attempt failed with a DEFINITIVE error (e.g. the key expired and
 * the retry answered 401) while an earlier submission attempt is unresolved.
 * The earlier attempt may have reached the server, so the outcome stays
 * `unknown` with the original key; the recovery failure rides along as
 * code/status/cause. Definitive errors are never auto-retried, so this throw
 * is the end of the wait.
 */
function unresolvedSubmissionError(context: PollContext, error: unknown): WsspError {
  const detail = error instanceof WsspError ? error.message : "an unexpected error";
  return new WsspError({
    kind: "unknown",
    reason: null,
    code: error instanceof WsspError ? error.code : null,
    status: error instanceof WsspError ? error.status : null,
    message: `${context.label}: an earlier submission attempt may have reached the server and recovery failed (${detail}); retry only under the same idempotency key.`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

const RETRYABLE_KINDS: ReadonlySet<WsspErrorKind> = new Set(["timeout", "unavailable", "capacity"]);

/**
 * Bounded exponential polling: 250 ms doubling to 2 s by default, one shared
 * deadline, `Retry-After` honored when it exceeds the interval. Retryable read
 * failures (`timeout`, `unavailable`, `capacity` — 429/503 included) are
 * waited out; anything else propagates. `retryOn` may widen the retryable set
 * (the mutation submit loop adds `unknown`, retried under the same key).
 */
export async function poll<T>(
  fn: (attempt: AbortSignal, info: PollAttempt) => Promise<PollResult<T>>,
  polling: ResolvedPolling,
  signal: AbortSignal | undefined,
  context: PollContext,
  retryOn?: (error: WsspError) => boolean,
  options?: { submission?: boolean; capacityAtDeadline?: boolean },
): Promise<T> {
  // A cancelled/expired SUBMISSION may have reached the server: report an
  // unknown outcome, not a plain wait error. The uncertainty also persists
  // across retries: once any attempt ended `unknown`, every later exit —
  // abort or deadline, mid-attempt or mid-backoff — stays `unknown` until a
  // receipt resolves it. Reads and pre-send exits stay `aborted`/`timeout`.
  let uncertain = false;
  const submission = options?.submission === true;
  const cancelled = (inFlight: boolean) =>
    submission && (inFlight || uncertain)
      ? submissionOutcomeError("aborted", context)
      : waitAbortedError(context);
  const expiredError = (inFlight: boolean) =>
    submission && (inFlight || uncertain)
      ? submissionOutcomeError("timeout", context)
      : waitTimeoutError(context);
  const deadline = Date.now() + polling.timeoutMs;
  let interval = polling.intervalMs;
  // Catalog 429s and `capacityAtDeadline` transfer submissions (E-18): when the deadline ends
  // while capacity is still full, throw the server's own refusal — a
  // definitive `capacity` error with its code and Retry-After — instead of a
  // bare wait timeout. Only a refusal answered by the latest attempt, and
  // never while an earlier submission is unresolved. Other failures keep the
  // timeout: their callers classify a deadline as an uncertain outcome.
  let refused: WsspError | null = null;
  // A transient pre-commit refusal answered by the latest attempt is itself
  // the deadline's answer (nothing was accepted), unless an earlier
  // submission is unresolved.
  let transient: WsspError | null = null;
  const exhausted = () =>
    refused && !uncertain && (options?.capacityAtDeadline || refused.status === 429)
      ? capacityExhaustedError(refused, context)
      : transient && !uncertain
        ? transient
        : expiredError(false);
  for (;;) {
    if (signal?.aborted) throw cancelled(false);
    // The deadline bounds every attempt: checked before the attempt starts...
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw exhausted();
    refused = null;
    transient = null;
    // ...enforced while it runs (the attempt signal aborts at expiry, so an
    // in-flight request is cancelled instead of riding out its own timeout)...
    const attempt = new AbortController();
    let expired = false;
    let interrupt!: (error: WsspError) => void;
    const interrupted = new Promise<never>((_, reject) => {
      interrupt = reject;
    });
    // The race below subscribes to the rejection; this handler marks it as
    // handled for the case where the callback wins the race and the
    // interruption promise rejects later.
    interrupted.catch(() => {});
    const timer = setTimeout(() => {
      expired = true;
      attempt.abort();
      interrupt(expiredError(true));
    }, remaining);
    const onAbort = () => {
      attempt.abort();
      interrupt(cancelled(true));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    let result: PollResult<T>;
    let retryAfterMs: number | null = null;
    try {
      // The attempt RACES its own interruption: the wait settles at the
      // deadline (or abort) even if the callback ignores cancellation and
      // never settles.
      result = await Promise.race([fn(attempt.signal, { remainingMs: remaining }), interrupted]);
    } catch (error) {
      // A caller abort or an expired deadline surfaces as a wait error with the
      // context (operation ID, idempotency key), never as a bare transport error.
      if (signal?.aborted) throw cancelled(true);
      if (expired) throw expiredError(true);
      if (
        error instanceof WsspError &&
        !(
          error.code !== null &&
          error.status !== null &&
          error.status >= 400 &&
          error.status < 500 &&
          error.status !== 429
        ) &&
        (retryOn ? retryOn(error) : RETRYABLE_KINDS.has(error.kind))
      ) {
        // A lost submission response (kind `unknown`) is never resolved by
        // retrying: the uncertainty outlives this attempt.
        if (error.kind === "unknown") uncertain = true;
        refused = error.kind === "capacity" ? error : null;
        transient = isTransientRefusal(error) ? error : null;
        result = { done: false };
        retryAfterMs = error.retryAfterSeconds !== null ? error.retryAfterSeconds * 1000 : null;
      } else {
        // A definitive failure while an earlier submission is unresolved does
        // not resolve it: keep `unknown` and the original key.
        if (uncertain) throw unresolvedSubmissionError(context, error);
        throw error;
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
    // ...and checked before a success is accepted: a terminal answer that
    // arrived past the deadline is not this wait's success.
    if (Date.now() > deadline) throw expiredError(true);
    if (result.done) return result.value;
    if (result.waited) {
      // The server already waited for us: ask again at once, fresh backoff.
      interval = polling.intervalMs;
      continue;
    }
    // Retry-After wins over the interval cap; the remaining deadline bounds both.
    const wait = Math.min(Math.max(interval, retryAfterMs ?? 0), deadline - Date.now());
    if (wait <= 0) throw exhausted();
    await sleep(wait, signal);
    interval = Math.min(interval * 2, polling.maxIntervalMs);
  }
}

/**
 * The wait deadline ended while the server kept refusing for capacity: the
 * last refusal, typed and keyed (`TRANSFER_QUOTA`, `TOO_MANY_REQUESTS`, …).
 */
function capacityExhaustedError(refusal: WsspError, context: PollContext): WsspError {
  return new WsspError({
    kind: "capacity",
    code: refusal.code,
    status: refusal.status,
    requestId: refusal.requestId,
    retryAfterSeconds: refusal.retryAfterSeconds,
    route: refusal.route,
    message: `${context.label}: capacity stayed full until the wait deadline (${refusal.message})`,
    operationId: context.operationId ?? refusal.operationId,
    idempotencyKey: context.idempotencyKey ?? refusal.idempotencyKey,
    operationErrorCode: refusal.operationErrorCode,
  });
}

/** One deadline shared by every phase of a multi-step wait. */
export class Deadline {
  readonly #timeoutMs: number;
  readonly #start: number;

  constructor(timeoutMs: number) {
    this.#timeoutMs = timeoutMs;
    this.#start = Date.now();
  }

  /** Milliseconds left; throws the wait timeout error once it is exhausted. */
  remaining(context: PollContext): number {
    const left = this.#timeoutMs - (Date.now() - this.#start);
    if (left <= 0) throw waitTimeoutError(context);
    return left;
  }
}

/** Retry one authorized read under the shared transport/5xx/429 policy. */
export function readWithRetry<T>(
  read: (signal: AbortSignal) => Promise<T>,
  polling: ResolvedPolling,
  signal: AbortSignal | undefined,
  context: PollContext,
): Promise<T> {
  return poll(
    async (attempt) => ({ done: true, value: await read(attempt) }),
    polling,
    signal,
    context,
  );
}
