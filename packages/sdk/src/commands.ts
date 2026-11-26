import { createHash } from "node:crypto";
import {
  COMMAND_PAYLOAD_MAX_BYTES,
  type CommandOutputPageDto,
  classifyKillOutcome,
  type commandBodySchema,
  commandPayloadBytes,
  commandTimeoutSchema,
  envSchema,
  type OperationResult,
  type OperationStateDto,
  OUTPUT_TAIL_BYTES,
  type ProcessInfo,
  type ProcessRef,
  processRefSchema,
  processSignalSchema,
  STDIN_CHUNK_MAX_BYTES,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";
import {
  attachErrorContext,
  CommandExitError,
  isWsspError,
  ProcessError,
  WsspError,
} from "./errors";
import type { Page } from "./files";
import { ensureSucceeded, type OperationRead, waitOperation } from "./operations";
import {
  encodeBase64,
  type OutputEvent,
  outputCursorAdvanced,
  outputCursorOffset,
  pageEvents,
  protocolError,
  StreamDecoders,
  TrimBuffer,
} from "./output";
import {
  Deadline,
  longPollRead,
  longPollWaitMs,
  type PollAttempt,
  type PollContext,
  type PollingOptions,
  pacedProgress,
  poll,
  pollingShape,
  RequestPacer,
  type ResolvedPolling,
  readWithRetry,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
  withWaitTimeout,
} from "./polling";
import { generateKey, type MutationOptions, submitMutation } from "./sandboxes";
import { MAX_TIMEOUT_MS as MAX_REQUEST_TIMEOUT_MS, type WsspTransport } from "./transport";

/** Body of `POST /v1/sandboxes/{id}/commands`: exactly one of argv or script. */
export type CommandInput = z.input<typeof commandBodySchema>;

/** Guest-side command budget the server accepts (30 minutes). */
export const COMMAND_TIMEOUT_MAX_MS = 1_800_000;
/**
 * Wait headroom added on top of the guest-side command budget, so a 30-minute
 * command is waited out within the lease instead of hitting the SDK deadline.
 */
export const COMMAND_WAIT_MARGIN_MS = 60_000;
/** Default budget of the separate cancellation-acknowledgement wait. */
export const DEFAULT_CANCEL_ACK_TIMEOUT_MS = 30_000;
const MAX_CANCEL_ACK_TIMEOUT_MS = 10 * 60_000;

/** Default per-stream character budget of a `tail` retrieval. */
export const DEFAULT_TAIL_CHARS = 64 * 1024;
/** A tail never holds more than the server's rolling tail (768 KiB of bytes). */
export const MAX_TAIL_CHARS = OUTPUT_TAIL_BYTES;

/**
 * Per-stream decoded characters a `run` result retains; older output is
 * dropped and counted under `discarded` (which also sets `truncated`).
 */
export const DEFAULT_RUN_OUTPUT_CHARS = 4 * 1024 * 1024;
/** Hard cap of `maxOutputChars`, so a result stays a bounded in-memory value. */
export const MAX_RUN_OUTPUT_CHARS = 64 * 1024 * 1024;

export type { OutputEvent } from "./output";
export type OutputCallback = (event: OutputEvent) => void | Promise<void>;

export type RunOptions = MutationOptions & {
  /** Guest execution budget; waitTimeoutMs only bounds this observer. */
  timeoutMs?: number;
  check?: boolean;
  onAbort?: "detach" | "cancel";
  onStdout?: (text: string) => void | Promise<void>;
  onStderr?: (text: string) => void | Promise<void>;
  /** Decoded output events in aggregate-offset order; gaps included. */
  onOutput?: OutputCallback;
  /**
   * Optional initial stdin (at most 32 KiB), written with `eof: true` once the
   * command is dispatched (a queued operation rejects stdin server-side). The
   * command may not read it before it runs.
   */
  stdin?: string | Uint8Array;
  /**
   * Budget of the bounded acknowledgement wait an abort triggers for the
   * cancellation request. Default 30 s. Independent of `waitTimeoutMs`.
   */
  cancelAckTimeoutMs?: number;
  /**
   * Per-stream decoded characters retained for the result. Default 4 Mi,
   * max 64 Mi. Older output beyond the budget is dropped and counted in
   * `discarded`.
   */
  maxOutputChars?: number;
};

/** Convenience command options; execution and SDK wait budgets are separate. */
export type CommandOptions = RunOptions & {
  /** Guest execution budget, mapped to CommandInput.timeoutMs (max 30 min). */
  timeoutMs?: CommandInput["timeoutMs"];
};

/** Dropped-prefix counters of one bounded output buffer, in UTF-16 units. */
export type DiscardedOutput = { stdout: number; stderr: number };

export type RunResult = {
  process: ProcessRef | null;
  startOffset: number;
  operationId: string;
  /** The guest exit status; check:false returns nonzero natural completion. */
  exitCode: number;
  /** Decoded retained stdout (the final `maxOutputChars` at most). */
  stdout: string;
  stderr: string;
  /** Some produced bytes are missing: server gaps, or output dropped by the
   * `maxOutputChars` budget (see `discarded`). */
  truncated: boolean;
  /** Characters dropped from the front of each stream by the output budget. */
  discarded: DiscardedOutput;
  /** Bytes the command produced once the completion watermark committed. */
  totalBytes: number | null;
  receivedBytes: number;
  retainedBytes: number;
};

/** One status read of a command operation, from its output metadata. */
export type CommandStat = {
  process: ProcessRef | null;
  operationId: string;
  state: OperationStateDto;
  exitCode: number | null;
  complete: boolean;
  truncated: boolean;
  receivedBytes: number;
  totalBytes: number | null;
  retainedBytes: number;
  expiresAt: string | null;
};

export type TailOptions = WaitOptions & {
  /** Per-stream decoded character budget kept from the end. Default 64 Ki chars. */
  maxChars?: number;
};

export type CommandTail = {
  process: ProcessRef | null;
  startOffset: number;
  operationId: string;
  state: OperationStateDto;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  /** Characters dropped from the front of each stream beyond `maxChars`. */
  discarded: DiscardedOutput;
  totalBytes: number | null;
  receivedBytes: number;
  retainedBytes: number;
};

/** Terminal result of an acknowledged cancellation request. */
export type CancelResult = {
  /** The target (command) operation. */
  operationId: string;
  state: OperationStateDto;
  /** `succeeded` means the command completed normally before the cancel landed. */
  outcome: "cancelled" | "succeeded" | "failed";
};

export type WriteStdinOptions = MutationOptions & {
  /** Close the command's stdin after this chunk. Required for an empty chunk. */
  eof?: boolean;
};

export type CommandWaitOptions = Omit<RunOptions, "timeoutMs" | "stdin">;
export type StartOptions = MutationOptions & { timeoutMs?: number; stdin?: string | Uint8Array };
export type ProcessConnectOptions = WaitOptions & {
  fromCursor?: string;
  replay?: "live" | "retained";
};
export type ProcessListOptions = MutationOptions & { limit?: number; cursor?: string };
export type KillResult = "killed" | "alreadyExited";
export type SignalResult =
  | Extract<NonNullable<OperationResult["result"]>, { type: "process.signal" }>
  | KillResult;
export type CommandHandle = {
  readonly operationId: string;
  readonly process: ProcessRef;
  wait(options?: CommandWaitOptions): Promise<RunResult>;
  disconnect(): void;
  kill(options?: MutationOptions): Promise<KillResult>;
  stat(options?: WaitOptions): Promise<CommandStat>;
  tail(options?: TailOptions): Promise<CommandTail>;
  writeStdin(chunk: string | Uint8Array, options?: WriteStdinOptions): Promise<void>;
  closeStdin(options?: MutationOptions): Promise<void>;
  cancelAndWait(options?: MutationOptions): Promise<CancelResult>;
};

export type CommandsApi = {
  /** Start a command, follow its output and resolve with its exit status. */
  run(sandboxId: string, input: CommandInput | string, options?: RunOptions): Promise<RunResult>;
  /** `run` convenience for a shell script (bytes preserved exactly). */
  script(sandboxId: string, script: string, options?: CommandOptions): Promise<RunResult>;
  /** `run` convenience for an argv vector (no shell). */
  argv(sandboxId: string, argv: string[], options?: CommandOptions): Promise<RunResult>;
  /**
   * Start a command and await guest-attested identity before returning its
   * detached handle. Initial stdin is accepted after that evidence; output
   * and completion are observed only through an explicit wait().
   */
  start(
    sandboxId: string,
    input: CommandInput | string,
    options?: StartOptions,
  ): Promise<CommandHandle>;
  list(sandboxId: string, options?: ProcessListOptions): Promise<Page<ProcessInfo>>;
  connect(process: ProcessRef, options?: ProcessConnectOptions): Promise<CommandHandle>;
  signal(
    process: ProcessRef,
    signal: "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGKILL",
    options?: MutationOptions,
  ): Promise<SignalResult>;
  kill(process: ProcessRef, options?: MutationOptions): Promise<KillResult>;
  closeStdin(process: ProcessRef, options?: MutationOptions): Promise<void>;
  /** One status/metadata read of a command operation. */
  stat(operationId: string, options?: WaitOptions): Promise<CommandStat>;
  /**
   * Read output from the beginning and keep the final `maxChars` of each
   * stream; buffers are trimmed incrementally, so a noisy command cannot grow
   * the SDK process. Resolves once the completion watermark commits.
   */
  tail(operationId: string, options?: TailOptions): Promise<CommandTail>;
  /**
   * Write one stdin chunk (at most 32 KiB decoded) and resolve once the write
   * is ACCEPTED — the server accepts into the durable outbox while the command
   * keeps running; acceptance never asserts the guest consumed the bytes.
   */
  writeStdin(
    target: string | ProcessRef,
    chunk: string | Uint8Array,
    options?: WriteStdinOptions,
  ): Promise<void>;
  /**
   * Request cancellation and wait (bounded) for the TARGET operation's
   * terminal state — a failed cancellation action is never mistaken for a
   * failed command. An acknowledgement that never resolves throws kind
   * `unknown` carrying the operation ID: cancellation was requested, its
   * effect is not confirmed.
   */
  cancelAndWait(operationId: string, options?: MutationOptions): Promise<CancelResult>;
};

type Pump = {
  /** Paces this follow's output reads (pagination bursts, early answers). */
  pacer: RequestPacer;
  startOffset: number;
  cursor: string | undefined;
  decoders: StreamDecoders;
  stdout: TrimBuffer;
  stderr: TrimBuffer;
  truncated: boolean;
  lastPage: CommandOutputPageDto | null;
  /** Follow session; bumping it fences an abandoned in-flight page task. */
  session: number;
  /** Serializes page application (and with it callback delivery) per pump. */
  chain: Promise<void>;
  /**
   * First undelivered offset, MONOTONIC within a dispatch attempt: an
   * earlier-starting replay page (a merged segment) must never reset it, or
   * committed ranges would be delivered twice. Reset only on attempt change.
   */
  delivered: number;
  /** Dispatch attempt whose bytes the pump currently holds (cursors are bound to it). */
  attempt: number | null;
  /**
   * Sticky callback failure: a callback that rejects after its follow lost a
   * race is recorded here so settlement rejects `unknown` instead of
   * replaying the range and resolving with duplicated output.
   */
  callbackError: WsspError | null;
};

function newPump(stdoutChars: number, stderrChars: number): Pump {
  return {
    pacer: new RequestPacer(),
    startOffset: 0,
    cursor: undefined,
    decoders: new StreamDecoders(),
    stdout: new TrimBuffer(stdoutChars),
    stderr: new TrimBuffer(stderrChars),
    truncated: false,
    lastPage: null,
    session: 0,
    chain: Promise.resolve(),
    delivered: 0,
    attempt: null,
    callbackError: null,
  };
}

/** Bounded integer as a typed invalid_request carrying the operation context. */
function boundedOption(
  context: PollContext,
  name: string,
  value: number,
  min: number,
  max: number,
): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw invalidRequest(context, `${name} must be an integer from ${min} to ${max}.`);
  }
  return value;
}

/**
 * Run options are validated BEFORE the command is submitted: an invalid value
 * must never start a command, which would orphan its operation ID and key.
 */
function validateRunOptions(options: RunOptions, context: PollContext): void {
  if (options.maxOutputChars !== undefined) {
    boundedOption(context, "maxOutputChars", options.maxOutputChars, 1, MAX_RUN_OUTPUT_CHARS);
  }
  if (options.cancelAckTimeoutMs !== undefined) {
    boundedOption(
      context,
      "cancelAckTimeoutMs",
      options.cancelAckTimeoutMs,
      1,
      MAX_CANCEL_ACK_TIMEOUT_MS,
    );
  }
}

/** Defaults cover the command budget; an explicit observer budget remains independent. */
function resolveRunTimeout(
  defaults: PollingOptions | undefined,
  options: WaitOptions,
  commandTimeoutMs: number | undefined,
): number {
  const resolved = resolvePolling(defaults, options).timeoutMs;
  if (commandTimeoutMs === undefined) return resolved;
  const budget = boundedOption(
    { label: "command" },
    "timeoutMs",
    commandTimeoutMs,
    0,
    COMMAND_TIMEOUT_MAX_MS,
  );
  return budget === 0 ||
    options.waitTimeoutMs !== undefined ||
    defaults?.waitTimeoutMs !== undefined
    ? resolved
    : Math.max(resolved, budget + COMMAND_WAIT_MARGIN_MS);
}

function invalidRequest(context: PollContext, detail: string): WsspError {
  return new WsspError({
    kind: "invalid_request",
    message: `${context.label}: ${detail}`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * The caller's own signal aborted this phase — including a mutation
 * SUBMISSION whose send became uncertain (kind `unknown`, reason `aborted`).
 * Anything accepted before that point still needs the cancellation policy.
 */
function isCallerAbort(signal: AbortSignal | undefined, error: unknown): boolean {
  return (
    signal?.aborted === true &&
    (isWsspError(error, "aborted") || (isWsspError(error, "unknown") && error.reason === "aborted"))
  );
}

/** Cancellation was requested but never confirmed: the outcome stays unknown. */
function uncertainCancellation(
  context: PollContext,
  operationId: string,
  reason: "aborted" | "timeout" = "aborted",
): WsspError {
  return new WsspError({
    kind: "unknown",
    reason,
    message: `${context.label}: cancellation was requested but not acknowledged; the command may still be running. Poll the operation before assuming it stopped.`,
    operationId,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

const TERMINAL_STATES: ReadonlySet<OperationStateDto> = new Set([
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
]);

const textEncoder = new TextEncoder();

/**
 * Domain-separated derived key bound to the COMPLETE original key via SHA-256:
 * two distinct owner keys can never derive the same cancel/stdin key, however
 * long their common prefix. 75 chars, within the 128-char key bound.
 */
function derivedKey(key: string, domain: "cancel" | "stdin"): string {
  const digest = createHash("sha256").update(`${domain}:${key}`).digest("hex");
  return `sdk:${domain}:${digest}`;
}

export function createCommandsApi(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
): CommandsApi {
  /**
   * Deliver one page through the pump's serialization chain: only one page is
   * applied (and only one callback runs) at a time, and a fenced session
   * stops delivering without losing the progress it already committed.
   * Returns false when the session was fenced before the page completed.
   */
  async function applyPage(
    pump: Pump,
    page: CommandOutputPageDto,
    finalize: boolean,
    session: number,
    context: PollContext,
    onOutput: OutputCallback | undefined,
  ): Promise<boolean> {
    const prior = pump.chain;
    let release!: () => void;
    pump.chain = prior.then(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await prior;
    try {
      return await applyPageInner(pump, page, finalize, session, context, onOutput);
    } finally {
      release();
    }
  }

  async function applyPageInner(
    pump: Pump,
    page: CommandOutputPageDto,
    finalize: boolean,
    session: number,
    context: PollContext,
    onOutput: OutputCallback | undefined,
  ): Promise<boolean> {
    if (session !== pump.session) return false; // fenced before starting
    // A callback failure is sticky: nothing further is delivered, and any
    // later drain (abort settlement) re-throws it instead of resolving.
    if (pump.callbackError) throw pump.callbackError;
    if (page.attempt !== pump.attempt) {
      const reset = pump.attempt !== null;
      pump.startOffset = 0;
      // The first page of a dispatch attempt (the initial attempt, or a newer
      // one whose reset restarts decoding at 0) replaces older bytes. Reset
      // ONCE per attempt: a re-fetched reset page (an earlier pass was
      // interrupted inside a callback) must not clear the delivery progress
      // that pass already committed.
      pump.attempt = page.attempt;
      pump.decoders.reset();
      pump.stdout.clear();
      pump.stderr.clear();
      pump.truncated = false;
      pump.cursor = undefined;
      pump.delivered = 0;
      if (reset && onOutput) {
        try {
          await emit(onOutput, { kind: "reset", attempt: page.attempt, offset: 0 }, context);
        } catch (error) {
          if (error instanceof WsspError) pump.callbackError ??= error;
          throw error;
        }
        if (session !== pump.session) return false;
      }
      if (page.offset !== 0) {
        throw protocolError(context, "a reset output page does not start at offset 0.");
      }
    } else if (pump.cursor === undefined) {
      if (page.offset !== 0) {
        throw protocolError(context, "the output page does not continue from its cursor.");
      }
    } else {
      const expected = outputCursorOffset(pump.cursor);
      // A page may legitimately START EARLIER than the cursor when the server
      // merged new bytes into a segment it already returned: its committed
      // prefixes are trimmed per range below. Starting LATER would skip bytes
      // the follow never saw — a real protocol break.
      if (expected === null || page.offset > expected) {
        throw protocolError(context, "the output page does not continue from its cursor.");
      }
    }
    if (page.truncated) pump.truncated = true;
    const events = pageEvents(page, context);
    for (const event of events) {
      const start = event.kind === "gap" ? event.start : event.offset;
      const end = event.kind === "gap" ? event.end : event.offset + event.bytes.byteLength;
      // A range this page already committed (an earlier pass was interrupted
      // inside a callback) is never delivered twice; a range REACHING BACK
      // over committed bytes (a server-merged segment) is trimmed to its
      // uncommitted suffix — the streaming decoder has consumed exactly the
      // committed prefix, so decoding continues seamlessly.
      if (end <= pump.delivered) continue;
      const from = Math.max(start, pump.delivered);
      try {
        if (event.kind === "gap") {
          pump.truncated = true;
          pump.decoders.reset();
          if (onOutput) await emit(onOutput, { kind: "gap", start: from, end }, context);
        } else {
          const text = pump.decoders.decode(event.stream, event.bytes.subarray(from - start));
          if (text !== "") {
            (event.stream === "stdout" ? pump.stdout : pump.stderr).push(text);
            if (onOutput) {
              await emit(
                onOutput,
                { kind: "data", stream: event.stream, offset: from, text },
                context,
              );
            }
          }
        }
      } catch (error) {
        // The range is decoded and buffered; only its callback failed. Commit
        // it and keep the failure sticky, so a settlement replay never
        // delivers the range twice and never resolves over the failure.
        pump.delivered = end;
        if (error instanceof WsspError) pump.callbackError ??= error;
        throw error;
      }
      // The range is fully delivered (buffered and the callback awaited):
      // commit it even when the session was fenced underneath us.
      pump.delivered = end;
      if (session !== pump.session) return false; // fenced mid-page; progress kept
    }
    pump.cursor = page.nextCursor;
    pump.lastPage = page;
    if (finalize) {
      // Completion watermark: flush both decoders so a trailing partial UTF-8
      // sequence is delivered (as U+FFFD) instead of vanishing. The events
      // carry the page's end offset.
      const end = outputCursorOffset(page.nextCursor) ?? page.offset;
      for (const stream of ["stdout", "stderr"] as const) {
        // The fence applies to flush callbacks exactly as to chunk callbacks:
        // check before each flush and after each awaited callback, so a
        // blocked stdout flush resuming after a deadline never lets the
        // stderr flush fire post-rejection.
        if (session !== pump.session) return false;
        const text = pump.decoders.flush(stream);
        if (text === "") continue;
        (stream === "stdout" ? pump.stdout : pump.stderr).push(text);
        if (onOutput) {
          try {
            await emit(onOutput, { kind: "data", stream, offset: end, text }, context);
          } catch (error) {
            if (error instanceof WsspError) pump.callbackError ??= error;
            throw error;
          }
          if (session !== pump.session) return false;
        }
      }
    }
    return session === pump.session;
  }

  async function emit(cb: OutputCallback, event: OutputEvent, context: PollContext): Promise<void> {
    try {
      await cb(event);
    } catch {
      // The command is unaffected and may still be running: report an UNKNOWN
      // follow outcome, never a stop. The operation ID lets the caller resume.
      // Callback errors may contain output or private request descriptions;
      // retain no caller-owned cause.
      throw new WsspError({
        kind: "unknown",
        message: `${context.label}: the onOutput callback threw; the command may still be running.`,
        operationId: context.operationId ?? null,
        idempotencyKey: context.idempotencyKey ?? null,
      });
    }
  }

  /**
   * Read and apply pages until caught up. `complete` only when the completion
   * watermark (or a final state) committed AND no page is pending: a terminal
   * operation state alone never ends the follow. Every page read asks the
   * server to hold an empty page until output or completion arrives
   * (long-poll); `waited` reports that the last read was held for its whole
   * hold, so the caller re-reads at once instead of sleeping.
   */
  async function drain(
    operationId: string,
    pump: Pump,
    attempt: AbortSignal,
    context: PollContext,
    onOutput: OutputCallback | undefined,
    polling: ResolvedPolling,
    info: PollAttempt,
  ): Promise<{ complete: boolean; waited: boolean }> {
    const deadlineAt = Date.now() + info.remainingMs;
    for (;;) {
      attempt.throwIfAborted();
      // Capture the session BEFORE requesting the page: a
      // cancellation-insensitive read that is still pending while run()
      // times out or finishes abort settlement must never apply its page —
      // it would otherwise resolve later, observe the newly bumped session,
      // and invoke callbacks after run() already rejected.
      const session = pump.session;
      // At most a short burst of reads back to back, then ≤ 30 a minute: bounds
      // pagination and servers that answer early (server-held reads never wait).
      await pump.pacer.take(attempt);
      attempt.throwIfAborted();
      const cursor = pump.cursor;
      const {
        value: page,
        waited,
        held,
        elapsedMs,
      } = await longPollRead(longPollWaitMs(polling, deadlineAt - Date.now()), (hold, timeoutMs) =>
        transport.request("getCommandOutput", {
          params: { id: operationId },
          query: cursor === undefined ? hold : { cursor, ...hold },
          signal: attempt,
          ...(timeoutMs !== undefined ? { timeoutMs } : {}),
        }),
      );
      // The request may have ignored the abort: recheck the attempt signal,
      // then refuse to apply a page whose follow session is stale.
      attempt.throwIfAborted();
      // Never apply (or trust the completion of) another operation's output.
      if (page.operationId !== operationId)
        throw protocolError(context, "the output page belongs to a different operation.");
      const previous = pump.cursor;
      const applied = await applyPage(
        pump,
        page,
        page.complete && !page.hasMore,
        session,
        context,
        onOutput,
      );
      // A callback failed in an earlier (raced-out) pass: propagate it rather
      // than resolving over output the caller never saw.
      if (pump.callbackError) throw pump.callbackError;
      if (!applied || session !== pump.session) {
        // A newer follow session owns the pump now (abort settlement); this
        // rejection is swallowed by the poll race that already interrupted us.
        throw new WsspError({
          kind: "aborted",
          reason: "aborted",
          message: `${context.label}: the follow was superseded.`,
          operationId: context.operationId ?? null,
          idempotencyKey: context.idempotencyKey ?? null,
        });
      }
      if (!page.hasMore) {
        if (!page.complete && page.state === "UNKNOWN_OUTCOME")
          await throwIfUnknown(operationId, attempt, context);
        // A server-paced answer that really moved the cursor (a later attempt
        // or offset, not a replay) is followed at once: the server holds the
        // next read until there is more. Early answers, replays and answers
        // without news fall back to the interval backoff.
        const progressed =
          held && pacedProgress(elapsedMs) && outputCursorAdvanced(previous, page.nextCursor);
        return { complete: page.complete, waited: waited || progressed };
      }
      if (page.nextCursor === previous) {
        throw protocolError(context, "the output page made no progress.");
      }
    }
  }

  /**
   * C58-2: an interim UNKNOWN_OUTCOME keeps its output open to its exact
   * dispatch (native-http-contract.md, Command output), so its watermark may
   * never commit and the follow would wait out the whole deadline. The caught-up
   * follow instead reads the operation and reports the documented `unknown`
   * (resume with the same key or operation ID), unless a late receipt already
   * resolved it, in which case following continues to the watermark.
   */
  async function throwIfUnknown(
    operationId: string,
    attempt: AbortSignal,
    context: PollContext,
  ): Promise<void> {
    const operation = await transport.request("getOperation", {
      params: { id: operationId },
      signal: attempt,
    });
    attempt.throwIfAborted();
    if (operation.id !== operationId)
      throw protocolError(context, "the operation status belongs to a different operation.");
    if (operation.outcome === "unknown") ensureSucceeded(operation, context);
  }

  function buildResult(
    receipt: { operationId: string },
    pump: Pump,
    context: PollContext,
  ): RunResult {
    const page = pump.lastPage;
    if (!page?.complete) {
      throw protocolError(context, "the follow ended without a complete output page.");
    }
    if (page.exitCode === null) {
      throw protocolError(context, "the command succeeded without an exit code.");
    }
    // value() applies the final trim before the dropped counters are read.
    const stdout = pump.stdout.value();
    const stderr = pump.stderr.value();
    const discarded = { stdout: pump.stdout.dropped, stderr: pump.stderr.dropped };
    return {
      operationId: receipt.operationId,
      process: context.process ?? null,
      startOffset: pump.startOffset,
      exitCode: page.exitCode,
      stdout,
      stderr,
      truncated: pump.truncated || page.truncated || discarded.stdout > 0 || discarded.stderr > 0,
      discarded,
      totalBytes: page.totalBytes,
      receivedBytes: page.receivedBytes,
      retainedBytes: page.retainedBytes,
    };
  }

  /**
   * Submit a cancellation and wait (bounded) for the TARGET operation's
   * terminal state. The 202 receipt's own state is trusted only for the two
   * unambiguous cases: a FAILED action receipt may mean the cancellation
   * itself was rejected (for example the generation moved on), never that the
   * command failed. Anything unconfirmed throws kind `unknown` with the
   * operation ID.
   */
  async function requestCancellation(
    operationId: string,
    key: string,
    signal: AbortSignal | undefined,
    timeoutMs: number,
    label: string,
  ): Promise<CancelResult> {
    const context: PollContext = { label, operationId, idempotencyKey: key };
    const deadline = new Deadline(timeoutMs);
    const polling = resolvePolling(defaults, { waitTimeoutMs: timeoutMs });
    const receipt = await submitMutation(
      (attempt) =>
        transport.request("cancelOperation", {
          params: { id: operationId },
          body: {},
          idempotencyKey: key,
          signal: attempt,
        }),
      polling,
      signal,
      context,
    );
    if (receipt.state === "CANCELLED") {
      return { operationId, state: "CANCELLED", outcome: "cancelled" };
    }
    if (receipt.state === "SUCCEEDED") {
      return { operationId, state: "SUCCEEDED", outcome: "succeeded" };
    }
    const terminal = await waitForCancellation(operationId, { signal }, deadline, context);
    if (
      terminal.outcome === "cancelled" ||
      terminal.outcome === "succeeded" ||
      terminal.outcome === "failed"
    ) {
      return { operationId, state: terminal.state, outcome: terminal.outcome };
    }
    throw uncertainCancellation(context, operationId);
  }

  // Every accepted cancellation uses the same deadline/abort finalizer.
  async function waitForCancellation(
    operationId: string,
    options: WaitOptions,
    deadline: Deadline,
    context: PollContext,
  ): Promise<OperationRead> {
    try {
      return await waitOperation(
        transport,
        defaults,
        operationId,
        withWaitTimeout(options, deadline.remaining(context)),
        context,
      );
    } catch (error) {
      if (isWsspError(error, "aborted") || isWsspError(error, "timeout"))
        throw uncertainCancellation(context, operationId, error.kind);
      throw error;
    }
  }

  /**
   * A cancellation whose SUBMISSION failed (a key without the cancel scope, an
   * exhausted throttle budget, a network error) never got a server receipt:
   * the cancellation is UNCONFIRMED and the command may still be running.
   * Settlement reports kind `unknown` carrying the target operation ID, the
   * derived cancellation key, and a redacted copy of the failure — never the
   * bare submission failure (an `authorization`/`timeout` with
   * `operationId: null` while the command keeps running). Uncertainty already
   * typed by the target read passes through unchanged.
   */
  function uncertainSubmission(
    error: unknown,
    context: PollContext,
    operationId: string,
    key: string,
  ): WsspError {
    if (
      error instanceof WsspError &&
      error.kind === "unknown" &&
      error.operationId === operationId
    ) {
      return error;
    }
    return new WsspError({
      kind: "unknown",
      reason: "server_error",
      message: `${context.label}: the cancellation could not be submitted (${error instanceof WsspError ? error.kind : "failure"}); the command may still be running. Poll the operation before assuming it stopped.`,
      operationId,
      idempotencyKey: key,
      cause: transport.redactCause(error),
    });
  }

  /**
   * The caller aborted anywhere after the start was accepted: fence any
   * in-flight page task, request cancellation under a separate bounded
   * acknowledgement wait, then either report the confirmed cancellation
   * (`aborted`), surface the command's own terminal failure, or — when
   * completion raced the abort — finish the run normally. Cancellation that
   * cannot be confirmed is kind `unknown`, never a reported stop.
   */
  async function settleAborted(
    receipt: { operationId: string },
    key: string,
    options: RunOptions,
    pump: Pump,
    context: PollContext,
  ): Promise<RunResult> {
    // Fence the interrupted follow: its page task commits the range it is
    // inside, then stops; the settlement drain resumes from that progress.
    pump.session += 1;
    const ackTimeout = boundedOption(
      context,
      "cancelAckTimeoutMs",
      options.cancelAckTimeoutMs ?? DEFAULT_CANCEL_ACK_TIMEOUT_MS,
      1,
      MAX_CANCEL_ACK_TIMEOUT_MS,
    );
    const ackDeadline = new Deadline(ackTimeout);
    const ackContext: PollContext = { ...context, label: `${context.label} cancellation` };
    // A derived key ties the cancel to this run: re-following after an
    // `unknown` start replays the same cancellation instead of issuing another.
    const cancelKey = derivedKey(key, "cancel");
    let cancel: CancelResult;
    try {
      cancel = await requestCancellation(
        receipt.operationId,
        cancelKey,
        undefined,
        ackDeadline.remaining(ackContext),
        ackContext.label,
      );
    } catch (error) {
      // A submission failure must not bypass outcome settlement: the
      // cancellation is unconfirmed and the accepted command may still run.
      throw uncertainSubmission(error, ackContext, receipt.operationId, cancelKey);
    }
    // Reconcile the interrupted page task within the acknowledgement budget:
    // a callback that was still blocked when the abort won may have FAILED,
    // and a sticky callback failure rejects unknown — even over a confirmed
    // CANCELLED, the caller never saw that output.
    let reconcileTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        pump.chain,
        new Promise<void>((resolve) => {
          reconcileTimer = setTimeout(resolve, Math.max(ackDeadline.remaining(ackContext), 0));
        }),
      ]);
    } finally {
      // The chain usually wins the race: never leave the timer referenced
      // (it would keep the process alive for the remaining ack budget).
      if (reconcileTimer !== undefined) clearTimeout(reconcileTimer);
    }
    if (pump.callbackError) throw pump.callbackError;
    if (cancel.outcome === "cancelled") {
      throw new WsspError({
        kind: "aborted",
        reason: "aborted",
        message: `${context.label}: the command was cancelled after the abort.`,
        operationId: receipt.operationId,
        idempotencyKey: context.idempotencyKey ?? null,
      });
    }
    // Completion raced the abort (or the command failed on its own): drain the
    // remaining output under the acknowledgement deadline and finish normally.
    const ackPolling = resolvePolling(defaults, {
      waitTimeoutMs: ackDeadline.remaining(ackContext),
    });
    await poll<void>(
      async (attempt, info) => {
        const { complete, waited } = await drain(
          receipt.operationId,
          pump,
          attempt,
          context,
          options.onOutput,
          ackPolling,
          info,
        );
        return complete ? { done: true, value: undefined } : { done: false, waited };
      },
      ackPolling,
      undefined,
      context,
    );
    const terminal = await waitOperation(
      transport,
      defaults,
      receipt.operationId,
      { waitTimeoutMs: ackDeadline.remaining(ackContext) },
      context,
    );
    ensureSucceeded(terminal, context);
    return buildResult(receipt, pump, context);
  }

  /**
   * Initial stdin needs a DISPATCHED command: the server rejects stdin for an
   * operation with dispatchAttempt 0. Wait for dispatch under the shared
   * deadline. False when the operation went terminal first — stdin is then
   * skipped so the follow surfaces the command's own outcome.
   */
  async function waitForDispatch(
    operationId: string,
    options: WaitOptions,
    deadline: Deadline,
    context: PollContext,
  ): Promise<boolean> {
    return poll<boolean>(
      async (attempt) => {
        const operation = await transport.request("getOperation", {
          params: { id: operationId },
          signal: attempt,
        });
        const dispatchedAt = "dispatchedAt" in operation ? operation.dispatchedAt : null;
        return dispatchedAt !== null || TERMINAL_STATES.has(operation.state)
          ? { done: true, value: dispatchedAt !== null && !TERMINAL_STATES.has(operation.state) }
          : { done: false };
      },
      resolvePolling(defaults, {
        ...(options.intervalMs !== undefined ? { intervalMs: options.intervalMs } : {}),
        ...(options.maxIntervalMs !== undefined ? { maxIntervalMs: options.maxIntervalMs } : {}),
        waitTimeoutMs: deadline.remaining(context),
      }),
      options.signal,
      context,
    );
  }

  async function follow(
    receipt: { operationId: string },
    key: string,
    options: RunOptions,
    deadline: Deadline,
    context: PollContext,
    stdinBase64: string | undefined,
    attachment?: { cursor: string; attempt: number; offset: number },
    detachSignal?: AbortSignal,
  ): Promise<RunResult> {
    // Each wait has independent observer options; validate them here,
    // before any output is fetched.
    validateRunOptions(options, context);
    const maxOutputChars = boundedOption(
      context,
      "maxOutputChars",
      options.maxOutputChars ?? DEFAULT_RUN_OUTPUT_CHARS,
      1,
      MAX_RUN_OUTPUT_CHARS,
    );
    const pump = newPump(maxOutputChars, maxOutputChars);
    if (attachment) {
      pump.cursor = attachment.cursor;
      pump.attempt = attachment.attempt;
      pump.delivered = attachment.offset;
      pump.startOffset = attachment.offset;
    }
    const onOutput: OutputCallback | undefined =
      options.onOutput || options.onStdout || options.onStderr
        ? async (event) => {
            await options.onOutput?.(event);
            if (event.kind === "data" && !options.signal?.aborted)
              await (event.stream === "stdout" ? options.onStdout : options.onStderr)?.(event.text);
          }
        : undefined;
    // Every post-start phase (stdin, output, the terminal read) is inside this
    // try: an abort anywhere after acceptance goes through the
    // cancellation/completion-race settlement, never a bare wait error.
    try {
      if (stdinBase64 !== undefined) {
        const dispatched = await waitForDispatch(receipt.operationId, options, deadline, {
          ...context,
          label: `${context.label} dispatch`,
        });
        if (dispatched) {
          await writeStdinInner(
            receipt.operationId,
            stdinBase64,
            derivedKey(key, "stdin"),
            { ...options, eof: true },
            deadline,
            { ...context, label: `${context.label} stdin` },
          );
        }
      }
      const followPolling = resolvePolling(defaults, {
        ...pollingShape(options),
        waitTimeoutMs: deadline.remaining(context),
      });
      await poll<void>(
        async (attempt, info) => {
          const { complete, waited } = await drain(
            receipt.operationId,
            pump,
            attempt,
            context,
            onOutput,
            followPolling,
            info,
          );
          return complete ? { done: true, value: undefined } : { done: false, waited };
        },
        followPolling,
        options.signal,
        context,
      );
      // The completing output page already says SUCCEEDED (the output route
      // serves only commands): no status read is needed. Any other final state
      // reads the operation for its typed error.
      if (pump.lastPage?.state !== "SUCCEEDED") {
        const operation = await waitOperation(
          transport,
          defaults,
          receipt.operationId,
          { ...withWaitTimeout(options, deadline.remaining(context)) },
          context,
        );
        if (operation.kind !== "RUN_COMMAND")
          throw protocolError(context, "command follow returned a different operation kind.");
        // A guest-side command timeout lands here as a FAILED operation with the
        // stable `timeout` code: a typed `timeout` WsspError with the operation ID.
        ensureSucceeded(operation, context);
      }
      return await finalizeExit(buildResult(receipt, pump, context), options, deadline, context);
    } catch (error) {
      // An abort anywhere after acceptance — the dispatch wait, the stdin
      // submission (whose send may be uncertain), the output follow or the
      // terminal read — goes through the cancellation/completion-race
      // settlement, never a bare wait error.
      if (
        isCallerAbort(options.signal, error) &&
        options.onAbort === "cancel" &&
        !detachSignal?.aborted
      ) {
        // AWAIT the settlement: the finally fence below must run only after
        // it, so a callback still blocked when the acknowledgement deadline
        // expires is fenced at that exit too.
        return await finalizeExit(
          await settleAborted(receipt, key, { ...options, onOutput }, pump, context),
          options,
          deadline,
          context,
        );
      }
      if (isWsspError(error) && error.code === "OUTPUT_EXPIRED" && options.check !== false) {
        try {
          const operation = await transport.request("getOperation", {
            params: { id: receipt.operationId },
            timeoutMs: Math.min(deadline.remaining(context), MAX_REQUEST_TIMEOUT_MS),
          });
          if (operation.id !== receipt.operationId || operation.kind !== "RUN_COMMAND")
            throw protocolError(context, "expired output has a different command identity.");
          ensureSucceeded(operation, context);
          const result = await transport.request("getOperationResult", {
            params: { id: receipt.operationId },
            timeoutMs: Math.min(deadline.remaining(context), MAX_REQUEST_TIMEOUT_MS),
          });
          if (
            result.kind !== "RUN_COMMAND" ||
            result.operationId !== receipt.operationId ||
            result.sandboxId !== operation.sandboxId ||
            result.generation !== operation.generation ||
            result.outcome !== "succeeded" ||
            result.result?.type !== "command"
          )
            throw protocolError(
              context,
              "expired output exit evidence does not match its command.",
            );
          if (result.result.exitCode !== null && result.result.exitCode !== 0)
            return await finalizeExit(
              {
                operationId: receipt.operationId,
                process: result.result.process,
                exitCode: result.result.exitCode,
                stdout: "",
                stderr: "",
                startOffset: pump.startOffset,
                totalBytes: null,
                receivedBytes: 0,
                retainedBytes: 0,
                truncated: true,
                discarded: { stdout: 0, stderr: 0 },
              },
              options,
              deadline,
              context,
              "expired",
            );
        } catch (failure) {
          throw attachProcessError(failure, context.process ?? null, context, "result");
        }
      }
      throw attachProcessError(error, context.process ?? null, context, "follow");
    } finally {
      // Fence an abandoned in-flight page task on EVERY exit (deadline,
      // callback failure, abort): it commits the range it is inside, then
      // stops instead of delivering callbacks after run() settled.
      pump.session += 1;
    }
  }

  /** Validate locally, before any network IO, and encode canonical base64. */
  function encodeStdin(chunk: string | Uint8Array, context: PollContext): string {
    const bytes = typeof chunk === "string" ? textEncoder.encode(chunk) : chunk;
    if (bytes.byteLength > STDIN_CHUNK_MAX_BYTES) {
      throw invalidRequest(
        context,
        `stdin chunk is ${bytes.byteLength} bytes; the maximum is ${STDIN_CHUNK_MAX_BYTES}.`,
      );
    }
    if (bytes.byteLength === 0) {
      // The server requires eof on an empty write; initial stdin always sets it.
      return "";
    }
    return encodeBase64(bytes);
  }

  async function writeStdinInner(
    operationId: string,
    contentBase64: string,
    key: string,
    options: MutationOptions & { eof?: boolean },
    deadline: Deadline,
    context: PollContext,
  ): Promise<void> {
    if (contentBase64 === "" && options.eof !== true) {
      throw invalidRequest(context, "an empty stdin write requires eof: true.");
    }
    const receipt = await submitMutation(
      (attempt) =>
        transport.request("writeStdin", {
          params: { id: operationId },
          body: { contentBase64, ...(options.eof === true ? { eof: true } : {}) },
          idempotencyKey: key,
          signal: attempt,
        }),
      resolvePolling(defaults, {
        ...(options.intervalMs !== undefined ? { intervalMs: options.intervalMs } : {}),
        ...(options.maxIntervalMs !== undefined ? { maxIntervalMs: options.maxIntervalMs } : {}),
        waitTimeoutMs: deadline.remaining(context),
      }),
      options.signal,
      context,
    );
    // SUCCEEDED acknowledges atomic receipt/sequence/outbox acceptance, not
    // guest consumption. It stays successful when the target later exits.
    // ACCEPTED remains readable during the coordinated server cutover.
    if (receipt.state === "ACCEPTED" || receipt.state === "SUCCEEDED") return;
    // A rejected write (e.g. not dispatched, generation moved) is a FAILED
    // receipt: one read carries the stable error code. It goes through
    // deadline-bounded polling with the ATTEMPT signal: a raw request with
    // the whole remaining budget as its timeout could hang forever on
    // cancellation-insensitive IO, exceed the transport's per-request maximum
    // (a 30-minute command's deadline is longer), and lose the command's
    // operation context on failure.
    const read = await poll(
      async (attempt) => {
        const value = await transport.request("getOperation", {
          params: { id: receipt.operationId },
          signal: attempt,
        });
        return { done: true as const, value };
      },
      resolvePolling(defaults, { waitTimeoutMs: deadline.remaining(context) }),
      options.signal,
      context,
    );
    if ("state" in read && (read.state === "ACCEPTED" || read.state === "SUCCEEDED")) return;
    ensureSucceeded(read, context);
  }

  async function writeOperationStdin(
    operationId: string,
    chunk: string | Uint8Array,
    options: WriteStdinOptions = {},
  ): Promise<void> {
    const context: PollContext = { label: `writeStdin ${operationId}`, operationId };
    const contentBase64 = encodeStdin(chunk, context);
    if (contentBase64 === "" && options.eof !== true) {
      throw invalidRequest(context, "an empty stdin write requires eof: true.");
    }
    const key = options.idempotencyKey ?? generateKey();
    context.idempotencyKey = key;
    const polling = resolvePolling(defaults, options);
    const deadline = new Deadline(polling.timeoutMs);
    await writeStdinInner(
      operationId,
      contentBase64,
      key,
      { ...options, eof: options.eof === true },
      deadline,
      context,
    );
  }

  /** Reject an oversize serialized command payload before any network IO. */
  function assertPayloadWithinLimit(input: CommandInput, context: PollContext): void {
    if (input.argv?.[0] === "") {
      throw invalidRequest(context, "invalid command name.");
    }
    if (input.envs !== undefined && !envSchema.safeParse(input.envs).success) {
      throw invalidRequest(context, "invalid command environment.");
    }
    const bytes = commandPayloadBytes(input);
    if (bytes > COMMAND_PAYLOAD_MAX_BYTES) {
      throw invalidRequest(
        context,
        `the serialized command payload is ${bytes} bytes; the maximum is ${COMMAND_PAYLOAD_MAX_BYTES}.`,
      );
    }
  }

  function commandOptions(
    input: CommandInput | string,
    options: RunOptions | StartOptions,
    context: PollContext,
  ) {
    if (Reflect.get(options, "guestTimeoutMs") !== undefined)
      throw invalidRequest(
        context,
        "Use timeoutMs for the command budget; guestTimeoutMs was removed.",
      );
    if (Reflect.has(options, "background"))
      throw invalidRequest(context, "Use commands.start for background commands.");
    const body: CommandInput = typeof input === "string" ? { script: input } : { ...input };
    if (body.timeoutMs !== undefined && options.timeoutMs !== undefined)
      throw invalidRequest(
        context,
        "Specify the command timeout in the input or options, never both.",
      );
    const { timeoutMs, ...waitOptions } = options;
    if (timeoutMs !== undefined) body.timeoutMs = timeoutMs;
    if (body.timeoutMs !== undefined && !commandTimeoutSchema.safeParse(body.timeoutMs).success)
      throw invalidRequest(context, "Invalid command timeoutMs.");
    assertPayloadWithinLimit(body, context);
    return { body, waitOptions };
  }
  function parseCursor(cursor: string) {
    const match = /^(\d{1,10})_(\d{1,16})$/.exec(cursor);
    const offset = outputCursorOffset(cursor);
    const attempt = match ? Number(match[1]) : NaN;
    if (offset === null || !Number.isSafeInteger(attempt) || attempt > 2_147_483_647)
      throw new WsspError({ kind: "invalid_request", message: "Invalid output cursor." });
    return { cursor, attempt, offset };
  }
  function checkedRef(process: ProcessRef): ProcessRef {
    const checked = processRefSchema.safeParse(process);
    if (!checked.success)
      throw new WsspError({
        kind: "invalid_request",
        message: "A full qualified process reference is required.",
      });
    return Object.freeze(checked.data);
  }
  function attachProcessError(
    error: unknown,
    process: ProcessRef | null,
    context: PollContext,
    phase: "submit" | "start" | "follow" | "result",
  ) {
    if (
      isWsspError(error) &&
      error.code?.startsWith("sandbox.process_") &&
      !(error instanceof ProcessError)
    )
      error = new ProcessError({ ...error.toJSON(), cause: undefined });
    return attachErrorContext(error, {
      process,
      operationId: context.operationId,
      idempotencyKey: context.idempotencyKey,
      phase,
    });
  }
  async function finalizeExit(
    result: RunResult,
    options: RunOptions,
    deadline: Deadline,
    context: PollContext,
    initialAvailability: "available" | "expired" = "available",
  ): Promise<RunResult> {
    if (options.check === false || result.exitCode === 0) return result;
    let stdout = result.stdout,
      stderr = result.stderr;
    let availability: "available" | "expired" = initialAvailability;
    let truncated = result.truncated;
    let startOffset = result.startOffset;
    if (
      initialAvailability === "available" &&
      (result.startOffset > 0 ||
        (options.maxOutputChars !== undefined && options.maxOutputChars < 65536))
    ) {
      try {
        const retained = await tail(result.operationId, {
          waitTimeoutMs: deadline.remaining(context),
          maxChars: 65536,
        });
        startOffset = retained.startOffset;
        stdout = retained.stdout;
        stderr = retained.stderr;
        truncated ||= retained.truncated;
      } catch (error) {
        if (!isWsspError(error) || error.code !== "OUTPUT_EXPIRED")
          throw attachProcessError(error, result.process, context, "result");
        availability = "expired";
        stdout = "";
        stderr = "";
        truncated = true;
      }
    }
    throw new CommandExitError({
      ...result,
      startOffset,
      stdout,
      stderr,
      truncated,
      outputAvailability: availability,
      idempotencyKey: context.idempotencyKey,
    });
  }
  function handleFor(
    operationId: string,
    process: ProcessRef,
    submissionKey: string | null,
    attachment: { cursor: string; attempt: number; offset: number },
  ): CommandHandle {
    const ref = checkedRef(process);
    // A connected observer does not know the command submission key. Its
    // local control root is used only for explicit cancellation, never replay metadata.
    const controlRoot = submissionKey ?? generateKey();
    const detached = new AbortController();
    const stdin = (data: string | Uint8Array, opts?: WriteStdinOptions) =>
      sendProcessStdin(ref, data, opts);
    const close = (opts?: MutationOptions) =>
      sendProcessStdin(ref, new Uint8Array(), { ...opts, eof: true });
    return {
      operationId,
      process: ref,
      disconnect: () => detached.abort(),
      wait: async (options: CommandWaitOptions = {}) => {
        waitTimeout(options);
        const signal = options.signal
          ? AbortSignal.any([options.signal, detached.signal])
          : detached.signal;
        const observer = { ...options, signal };
        const context: PollContext = {
          label: `command ${operationId}`,
          operationId,
          idempotencyKey: submissionKey,
          process: ref,
          phase: "follow",
        };
        return follow(
          { operationId },
          controlRoot,
          observer,
          new Deadline(resolvePolling(defaults, observer).timeoutMs),
          context,
          undefined,
          attachment,
          detached.signal,
        );
      },
      stat: async (options) => ({ ...(await stat(operationId, options)), process: ref }),
      tail: async (options) => ({ ...(await tail(operationId, options)), process: ref }),
      kill: (options) => killProcess(ref, options),
      writeStdin: stdin,
      closeStdin: close,
      cancelAndWait: (options) => cancelAndWait(operationId, options),
    };
  }
  async function start(
    sandboxId: string,
    input: CommandInput | string,
    options: StartOptions = {},
  ): Promise<CommandHandle> {
    const context: PollContext = {
      label: `startCommand ${sandboxId}`,
      idempotencyKey: options.idempotencyKey ?? generateKey(),
      phase: "submit",
    };
    const { body, waitOptions } = commandOptions(input, options, context);
    const key = context.idempotencyKey!;
    const deadline = new Deadline(resolvePolling(defaults, waitOptions).timeoutMs);
    const stdin = options.stdin === undefined ? undefined : encodeStdin(options.stdin, context);
    try {
      const receipt = await submitMutation(
        (signal) =>
          transport.request("startCommand", {
            params: { id: sandboxId },
            body: { ...body, startEvidence: "required" },
            idempotencyKey: key,
            signal,
          }),
        resolvePolling(defaults, withWaitTimeout(waitOptions, deadline.remaining(context))),
        options.signal,
        context,
      );
      context.operationId = receipt.operationId;
      context.phase = "start";
      const startPolling = resolvePolling(
        defaults,
        withWaitTimeout(waitOptions, deadline.remaining(context)),
      );
      const ref = await poll<ProcessRef>(
        async (signal, { remainingMs }) => {
          // The server holds a not-ready read until the start evidence lands.
          const { value: read, waited } = await longPollRead(
            longPollWaitMs(startPolling, remainingMs),
            async (query, timeoutMs) => {
              try {
                return {
                  result: await transport.request("getOperationResult", {
                    params: { id: receipt.operationId },
                    query,
                    signal,
                    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
                  }),
                };
              } catch (error) {
                if (isWsspError(error) && error.code === "OPERATION_RESULT_NOT_READY")
                  return { result: null };
                throw error;
              }
            },
          );
          if (read.result === null) return { done: false, waited };
          const result: OperationResult = read.result;
          if (
            result.operationId !== receipt.operationId ||
            result.sandboxId !== sandboxId ||
            result.kind !== "RUN_COMMAND"
          )
            throw protocolError(context, "start result does not match the accepted command.");
          if (result.result?.type === "command")
            return { done: true, value: result.result.process };
          const status = await transport.request("getOperation", {
            params: { id: receipt.operationId },
            signal,
          });
          ensureSucceeded(status, context);
          throw protocolError(context, "command start identity is unavailable.");
        },
        startPolling,
        options.signal,
        context,
      );
      if (stdin !== undefined)
        await writeStdinInner(
          receipt.operationId,
          stdin,
          derivedKey(key, "stdin"),
          { ...waitOptions, eof: true },
          deadline,
          context,
        );
      return handleFor(receipt.operationId, ref, key, {
        cursor: `${ref.attempt}_0`,
        attempt: ref.attempt,
        offset: 0,
      });
    } catch (error) {
      if (
        context.operationId &&
        isWsspError(error) &&
        (error.kind === "aborted" || error.kind === "timeout") &&
        error.operationErrorCode === null
      )
        throw new WsspError({
          kind: "unknown",
          reason: error.kind,
          message:
            "Command start observation ended; execution may continue. Recover with the original key or operation.",
          operationId: context.operationId,
          idempotencyKey: key,
          phase: "start",
        });
      throw attachErrorContext(error, {
        operationId: context.operationId,
        idempotencyKey: key,
        phase: context.phase,
      });
    }
  }
  async function run(
    sandboxId: string,
    input: CommandInput | string,
    options: RunOptions = {},
  ): Promise<RunResult> {
    const context: PollContext = {
      label: `runCommand ${sandboxId}`,
      idempotencyKey: options.idempotencyKey ?? generateKey(),
      phase: "submit",
    };
    const { body, waitOptions } = commandOptions(input, options, context);
    validateRunOptions(waitOptions, context);
    const key = context.idempotencyKey!;
    const deadline = new Deadline(resolveRunTimeout(defaults, waitOptions, body.timeoutMs));
    if (body.startEvidence === "required") {
      const handle = await start(sandboxId, body, {
        ...withWaitTimeout(waitOptions, deadline.remaining(context)),
        idempotencyKey: key,
      });
      return handle.wait(withWaitTimeout(waitOptions, deadline.remaining(context)));
    }
    const stdin = options.stdin === undefined ? undefined : encodeStdin(options.stdin, context);
    try {
      const receipt = await submitMutation(
        (signal) =>
          transport.request("startCommand", {
            params: { id: sandboxId },
            body,
            idempotencyKey: key,
            signal,
          }),
        resolvePolling(defaults, withWaitTimeout(waitOptions, deadline.remaining(context))),
        options.signal,
        context,
      );
      context.operationId = receipt.operationId;
      context.phase = "follow";
      return await follow(receipt, key, waitOptions, deadline, context, stdin);
    } catch (error) {
      throw attachErrorContext(error, {
        operationId: context.operationId,
        idempotencyKey: key,
        phase: context.phase,
      });
    }
  }
  async function connect(
    process: ProcessRef,
    options: ProcessConnectOptions = {},
  ): Promise<CommandHandle> {
    const ref = checkedRef(process);
    const polling = resolvePolling(defaults, options);
    if (options.fromCursor !== undefined && options.replay !== undefined)
      throw new WsspError({
        kind: "invalid_request",
        message: "Specify fromCursor or replay, never both.",
      });
    const requested =
      options.fromCursor === undefined ? undefined : parseCursor(options.fromCursor);
    try {
      const snapshot = await readWithRetry(
        (signal) =>
          transport.request("connectProcess", {
            params: { id: ref.sandboxId, pid: String(ref.pid) },
            query: {
              generation: String(ref.generation),
              processId: ref.processId,
              attempt: String(ref.attempt),
            },
            signal,
          }),
        polling,
        options.signal,
        { label: "connect process", process: ref },
      );
      if (JSON.stringify(snapshot.info.process) !== JSON.stringify(ref)) {
        const actual = snapshot.info.process;
        if (
          actual.sandboxId !== ref.sandboxId ||
          actual.processId !== ref.processId ||
          actual.generation !== ref.generation ||
          actual.attempt !== ref.attempt ||
          actual.pid !== ref.pid
        )
          throw new WsspError({
            kind: "protocol",
            reason: "invalid_response",
            message: "Connected process does not match its qualified reference.",
          });
      }
      if (parseCursor(snapshot.attachmentCursor).attempt !== snapshot.attempt)
        throw new WsspError({
          kind: "protocol",
          reason: "invalid_response",
          message: "Connected output cursor has a different attempt.",
        });
      if (requested && requested.attempt !== snapshot.attempt)
        throw new WsspError({
          kind: "invalid_request",
          message: "Output cursor has a different process attempt.",
        });
      if (snapshot.outputOperationId !== snapshot.info.operationId)
        throw protocolError(
          { label: "connect process" },
          "Output does not belong to the connected command.",
        );
      const attachment =
        requested ??
        (options.replay === "retained"
          ? { cursor: `${snapshot.attempt}_0`, attempt: snapshot.attempt, offset: 0 }
          : parseCursor(snapshot.attachmentCursor));
      return handleFor(snapshot.outputOperationId, ref, null, attachment);
    } catch (error) {
      throw attachProcessError(error, ref, { label: "connect process" }, "follow");
    }
  }
  async function list(
    sandboxId: string,
    options: ProcessListOptions = {},
  ): Promise<Page<ProcessInfo>> {
    const key = options.idempotencyKey ?? generateKey();
    const context: PollContext = { label: `process list ${sandboxId}`, idempotencyKey: key };
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    try {
      const receipt = await submitMutation(
        (signal) =>
          transport.request("listProcesses", {
            params: { id: sandboxId },
            body: { limit: options.limit ?? 100, cursor: options.cursor },
            idempotencyKey: key,
            signal,
          }),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      context.operationId = receipt.operationId;
      const status = await waitOperation(
        transport,
        defaults,
        receipt.operationId,
        withWaitTimeout(options, deadline.remaining(context)),
        context,
      );
      if (status.kind !== "LIST_PROCESSES" || status.sandboxId !== sandboxId)
        throw protocolError(context, "process list status does not match its observation.");
      ensureSucceeded(status, context);
      const result = await readWithRetry(
        (signal) =>
          transport.request("getOperationResult", { params: { id: receipt.operationId }, signal }),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      if (
        result.operationId !== receipt.operationId ||
        result.sandboxId !== sandboxId ||
        result.kind !== "LIST_PROCESSES" ||
        result.generation !== status.generation ||
        result.outcome !== status.outcome ||
        result.result?.type !== "process.list"
      )
        throw protocolError(context, "process list result does not match its observation.");
      return {
        items: result.result.items,
        nextCursor: result.result.nextCursor,
        consistency: result.result.consistency,
      };
    } catch (error) {
      throw attachErrorContext(error, {
        operationId: context.operationId,
        idempotencyKey: key,
        phase: "result",
      });
    }
  }
  async function processMutation(
    ref: ProcessRef,
    options: MutationOptions,
    send: (
      key: string,
      signal: AbortSignal,
    ) => Promise<{ operationId: string; state: OperationStateDto; location: string }>,
  ) {
    const key = options.idempotencyKey ?? generateKey();
    const context: PollContext = { label: "process control", idempotencyKey: key, process: ref };
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    try {
      const receipt = await submitMutation(
        (signal) => send(key, signal),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      context.operationId = receipt.operationId;
      return { receipt, key, context, deadline };
    } catch (error) {
      throw attachProcessError(error, ref, context, "submit");
    }
  }
  const qualifiers = (ref: ProcessRef) => ({
    generation: ref.generation,
    processId: ref.processId,
    attempt: ref.attempt,
  });
  async function killProcess(
    process: ProcessRef,
    options: MutationOptions = {},
  ): Promise<KillResult> {
    const ref = checkedRef(process);
    const { receipt, context, deadline } = await processMutation(ref, options, (key, signal) =>
      transport.request("killProcess", {
        params: { id: ref.sandboxId, pid: String(ref.pid) },
        body: qualifiers(ref),
        idempotencyKey: key,
        signal,
      }),
    );
    try {
      const action = await readWithRetry(
        (signal) =>
          transport.request("getOperation", { params: { id: receipt.operationId }, signal }),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      if (action.id !== receipt.operationId)
        throw protocolError(context, "kill receipt identity does not match its acceptance.");
      if (
        action.kind !== "operations.cancel" ||
        !action.targetOperationId ||
        action.sandboxId !== ref.sandboxId ||
        action.generation !== ref.generation
      )
        throw protocolError(context, "kill did not return the canonical cancel receipt.");
      context.operationId = action.targetOperationId;
      const target = await waitForCancellation(
        action.targetOperationId,
        options,
        deadline,
        context,
      );
      if (
        target.kind !== "RUN_COMMAND" ||
        target.sandboxId !== ref.sandboxId ||
        target.generation !== ref.generation
      )
        throw protocolError(context, "kill target does not match its command.");
      const outcome = classifyKillOutcome(target);
      if (outcome !== "unknown") return outcome;
      if (target.outcome === "failed") {
        throw new WsspError({
          kind: "unknown",
          message: "Target termination is unconfirmed.",
          operationId: target.id,
          idempotencyKey: context.idempotencyKey,
          operationErrorCode: target.errorCode,
          process: ref,
          failure: "failure" in target ? target.failure : null,
        });
      }
      ensureSucceeded(target, context);
      throw protocolError(context, "kill ended without authoritative completion.");
    } catch (error) {
      throw attachProcessError(error, ref, context, "follow");
    }
  }
  async function signalProcess(
    process: ProcessRef,
    signalName: "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGKILL",
    options: MutationOptions = {},
  ): Promise<SignalResult> {
    const ref = checkedRef(process);
    if (!processSignalSchema.safeParse(signalName).success)
      throw new WsspError({ kind: "invalid_request", message: "Unsupported signal name." });
    if (signalName === "SIGKILL") return killProcess(ref, options);
    const { receipt, context, deadline } = await processMutation(ref, options, (key, signal) =>
      transport.request("signalProcess", {
        params: { id: ref.sandboxId, pid: String(ref.pid) },
        body: { ...qualifiers(ref), signal: signalName },
        idempotencyKey: key,
        signal,
      }),
    );
    try {
      const status = await waitOperation(
        transport,
        defaults,
        receipt.operationId,
        withWaitTimeout(options, deadline.remaining(context)),
        context,
      );
      if (
        status.kind !== "SIGNAL_PROCESS" ||
        status.sandboxId !== ref.sandboxId ||
        status.generation !== ref.generation
      )
        throw protocolError(context, "signal status does not match its control.");
      ensureSucceeded(status, context);
      const result = await readWithRetry(
        (signal) =>
          transport.request("getOperationResult", { params: { id: receipt.operationId }, signal }),
        resolvePolling(defaults, withWaitTimeout(options, deadline.remaining(context))),
        options.signal,
        context,
      );
      if (
        result.operationId !== receipt.operationId ||
        result.kind !== "SIGNAL_PROCESS" ||
        result.sandboxId !== ref.sandboxId ||
        result.generation !== ref.generation ||
        result.outcome !== status.outcome ||
        result.result?.type !== "process.signal" ||
        result.result.signal !== signalName
      )
        throw protocolError(context, "signal result does not match its control.");
      const actual = result.result.process;
      if (
        actual.sandboxId !== ref.sandboxId ||
        actual.generation !== ref.generation ||
        actual.processId !== ref.processId ||
        actual.attempt !== ref.attempt ||
        actual.pid !== ref.pid
      )
        throw protocolError(context, "signal result targets a different incarnation.");
      return result.result;
    } catch (error) {
      throw attachProcessError(error, ref, context, "result");
    }
  }
  async function sendProcessStdin(
    process: ProcessRef,
    chunk: string | Uint8Array,
    options: WriteStdinOptions = {},
  ): Promise<void> {
    const ref = checkedRef(process);
    const content = encodeStdin(chunk, { label: "process stdin" });
    if (content === "" && options.eof !== true)
      throw new WsspError({ kind: "invalid_request", message: "Empty stdin requires EOF." });
    const { receipt, context, deadline } = await processMutation(ref, options, (key, signal) =>
      transport.request("sendProcessStdin", {
        params: { id: ref.sandboxId, pid: String(ref.pid) },
        body: { ...qualifiers(ref), contentBase64: content, eof: options.eof === true },
        idempotencyKey: key,
        signal,
      }),
    );
    try {
      if (receipt.state === "ACCEPTED" || receipt.state === "SUCCEEDED") return;
      const status = await waitOperation(
        transport,
        defaults,
        receipt.operationId,
        withWaitTimeout(options, deadline.remaining(context)),
        context,
      );
      if (
        status.kind !== "commands.writeStdin" ||
        status.sandboxId !== ref.sandboxId ||
        status.generation !== ref.generation
      )
        throw protocolError(context, "stdin did not return its acceptance receipt.");
      ensureSucceeded(status, context);
    } catch (error) {
      throw attachProcessError(error, ref, context, "follow");
    }
  }
  async function stat(operationId: string, options: WaitOptions = {}): Promise<CommandStat> {
    const page = await transport.request("getCommandOutput", {
      params: { id: operationId },
      query: { maxBytes: "1" },
      signal: options.signal,
      timeoutMs: waitTimeout(options),
    });
    return {
      operationId: page.operationId,
      process: null,
      state: page.state,
      exitCode: page.exitCode,
      complete: page.complete,
      truncated: page.truncated,
      receivedBytes: page.receivedBytes,
      totalBytes: page.totalBytes,
      retainedBytes: page.retainedBytes,
      expiresAt: page.expiresAt,
    };
  }

  async function tail(operationId: string, options: TailOptions = {}): Promise<CommandTail> {
    const context: PollContext = {
      label: `command output tail ${operationId}`,
      operationId,
    };
    const maxChars = boundedOption(
      context,
      "tail maxChars",
      options.maxChars ?? DEFAULT_TAIL_CHARS,
      1,
      MAX_TAIL_CHARS,
    );
    const polling = resolvePolling(defaults, options);
    const deadline = new Deadline(polling.timeoutMs);
    const pump = newPump(maxChars, maxChars);
    const tailPolling = resolvePolling(defaults, {
      ...pollingShape(options),
      waitTimeoutMs: deadline.remaining(context),
    });
    await poll<void>(
      async (attempt, info) => {
        const { complete, waited } = await drain(
          operationId,
          pump,
          attempt,
          context,
          undefined,
          tailPolling,
          info,
        );
        return complete ? { done: true, value: undefined } : { done: false, waited };
      },
      tailPolling,
      options.signal,
      context,
    );
    const page = pump.lastPage;
    if (!page?.complete) {
      throw protocolError(context, "the tail ended without a complete output page.");
    }
    return {
      operationId,
      process: null,
      startOffset: pump.startOffset,
      state: page.state,
      exitCode: page.exitCode,
      stdout: pump.stdout.value(),
      stderr: pump.stderr.value(),
      truncated: pump.truncated || page.truncated,
      discarded: { stdout: pump.stdout.dropped, stderr: pump.stderr.dropped },
      totalBytes: page.totalBytes,
      receivedBytes: page.receivedBytes,
      retainedBytes: page.retainedBytes,
    };
  }

  async function cancelAndWait(
    operationId: string,
    options: MutationOptions = {},
  ): Promise<CancelResult> {
    const key = options.idempotencyKey ?? generateKey();
    const polling = resolvePolling(defaults, options);
    return requestCancellation(
      operationId,
      key,
      options.signal,
      polling.timeoutMs,
      `cancelOperation ${operationId}`,
    );
  }

  return {
    run,
    script: (sandboxId, script, options) => run(sandboxId, { script }, options),
    argv: (sandboxId, argv, options) => run(sandboxId, { argv }, options),
    start,
    list,
    connect,
    signal: signalProcess,
    kill: killProcess,
    closeStdin: (ref, options) =>
      sendProcessStdin(ref, new Uint8Array(), { ...options, eof: true }),
    stat,
    tail,
    writeStdin: (target, chunk, options) =>
      typeof target === "string"
        ? writeOperationStdin(target, chunk, options)
        : sendProcessStdin(target, chunk, options),
    cancelAndWait,
  };
}
