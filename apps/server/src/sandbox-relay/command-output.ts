import {
  type CommandOutputChunk,
  OUTPUT_CHUNK_MAX_BYTES,
  purgeExpiredCommandOutput,
} from "@wssp/api/sandbox/command-output";
import { sweepOperationResults } from "@wssp/api/sandbox/operation-results";
import { pruneDeletedSandboxOutbox } from "@wssp/api/sandbox/outbox-retention";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import type { StreamBinaryMetadata } from "./protocol.js";

/**
 * The output chunk ceiling a hello negotiates (D3b): a daemon offering
 * `maxOutputChunkBytes` gets `min(offer, OUTPUT_CHUNK_MAX_BYTES)`; one that
 * offers nothing keeps the historical 8 KiB and is never told a ceiling.
 */
export function negotiatedOutputChunkBytes(offer: number): number {
  return Math.min(offer, OUTPUT_CHUNK_MAX_BYTES);
}

/**
 * Relay metadata → durable output chunk. The bytes themselves are stored by
 * `appendCommandOutput` inside the fenced relay transaction, so they become
 * visible (and acknowledged) only after that transaction commits. `maxBytes`
 * is the ceiling negotiated on the sending connection.
 */
export function commandOutputChunk(
  m: StreamBinaryMetadata,
  body: Uint8Array,
  maxBytes: number = OUTPUT_CHUNK_MAX_BYTES,
): CommandOutputChunk {
  const { offset, flags } = m;
  if (
    m.streamId !== m.operationId ||
    offset === undefined ||
    body.length === 0 ||
    body.length > Math.min(maxBytes, OUTPUT_CHUNK_MAX_BYTES) ||
    !Number.isSafeInteger(offset + body.length) ||
    m.type !== "stream.chunk" ||
    m.final ||
    Boolean(flags?.stdout) === Boolean(flags?.stderr) ||
    flags?.fileDownload ||
    flags?.fileUpload ||
    flags?.stdin
  ) {
    throw new Error("Invalid command output metadata.");
  }
  return {
    operationId: m.operationId,
    attempt: m.attempt,
    sequence: m.sequence,
    offset,
    ...(m.gapStart === undefined ? {} : { gapStart: m.gapStart }),
    stderr: flags?.stderr === true,
    body,
  };
}

const OUTPUT_RETENTION_SWEEP_MS = 5 * 60_000;
/** Each tick may drain for at most this long, well inside its interval. */
const OUTPUT_SWEEP_BUDGET_MS = 60_000;
const SWEEP_BATCH = 100;

/** Drains every expired output row as of `now`, in bounded batches, until a
 * short batch, abort, or the tick's time budget (B1-C-8: full drain restored). */
async function sweepExpiredCommandOutput(
  now: Date,
  signal: AbortSignal,
  budgetMs: number,
): Promise<number> {
  const started = performance.now();
  let total = 0;
  while (!signal.aborted) {
    const deleted = await purgeExpiredCommandOutput(now, SWEEP_BATCH);
    total += deleted;
    if (deleted < SWEEP_BATCH || performance.now() - started >= budgetMs) break;
  }
  return total;
}

/**
 * Retention task: deletes output content 24 hours after its operation
 * completes, expires operation results, and maintains the dispatch outbox
 * (processed rows of long-deleted sandboxes). Reads already report `OUTPUT_EXPIRED` from the operation's
 * completion time, so a late sweep never makes expired output readable.
 */
export function startCommandOutputRetention(
  signal: AbortSignal,
  intervalMs = OUTPUT_RETENTION_SWEEP_MS,
  clock: () => Date = () => new Date(),
  budgetMs = OUTPUT_SWEEP_BUDGET_MS,
): () => Promise<void> {
  let running: Promise<unknown> = Promise.resolve();
  let active = false;
  let resultOwnerCursor = "";
  let outboxPruneCursor = "";
  const sweep = () => {
    if (active || signal.aborted) return;
    active = true;
    running = (async () => {
      await sweepExpiredCommandOutput(clock(), signal, budgetMs);
      if (!signal.aborted)
        resultOwnerCursor = await sweepOperationResults(resultOwnerCursor, 10, signal);
      if (!signal.aborted)
        outboxPruneCursor = (await pruneDeletedSandboxOutbox({ cursor: outboxPruneCursor, signal }))
          .cursor;
    })()
      .catch((error: unknown) => {
        console.error(
          "[sandbox-relay] output retention sweep failed:",
          safeErrorLog(error, "retention_failed"),
        );
      })
      .finally(() => {
        active = false;
      });
  };
  const timer = setInterval(sweep, intervalMs);
  timer.unref();
  const stop = async () => {
    clearInterval(timer);
    signal.removeEventListener("abort", onAbort);
    await running;
  };
  const onAbort = () => void stop();
  if (signal.aborted) void stop();
  else {
    signal.addEventListener("abort", onAbort, { once: true });
    sweep();
  }
  return stop;
}
