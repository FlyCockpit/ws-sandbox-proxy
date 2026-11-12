import { createHash } from "node:crypto";
import { TRANSFER_MAX_BYTES, type uploadCreateBodySchema } from "@wssp/sandbox-contracts";
import type { z } from "zod";
import { isWsspError, WsspError } from "./errors";
import {
  Deadline,
  type PollContext,
  type PollingOptions,
  poll,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
  withWaitTimeout,
} from "./polling";
import { generateKey, type MutationOptions, type MutationReceipt } from "./sandboxes";
import type { TransferReceiptDto, WsspTransport } from "./transport";

/** Body of `POST /v1/transfers`: sandbox, guest path and the declared total. */
export type UploadReservation = z.input<typeof uploadCreateBodySchema>;
export type TransferReceipt = TransferReceiptDto;

/**
 * Domain-separated key derived from the caller's upload key via SHA-256, the
 * same construction the commands module uses for cancel/stdin: two distinct
 * owner keys can never derive the same commit/cancel key, however long their
 * common prefix. 75 chars, within the 128-char key bound.
 */
export function derivedTransferKey(key: string, domain: "commit" | "cancel"): string {
  const digest = createHash("sha256").update(`${domain}:${key}`).digest("hex");
  return `sdk:${domain}:${digest}`;
}

export type TransfersApi = {
  /**
   * Reserve an upload (or replay the reservation of the SAME idempotency key:
   * an identical create returns the original transfer with its durable
   * `receivedBytes` cursor, so a retried upload resumes instead of
   * reallocating). The cap is discoverable beforehand via `files.limits()`.
   */
  createUpload(input: UploadReservation, options?: MutationOptions): Promise<TransferReceipt>;
  /** One receipt read of an upload. */
  getUpload(id: string, options?: WaitOptions): Promise<TransferReceipt>;
  /** The upload receipt, or null only when the server confirms it is unknown. */
  findUpload(id: string, options?: WaitOptions): Promise<TransferReceipt | null>;
  /**
   * Write one fixed chunk at its aligned offset, retrying a lost response by
   * re-sending the IDENTICAL bytes (the server digest-checks replays; changed
   * bytes at an accepted offset are a definitive conflict).
   */
  putChunk(
    id: string,
    offset: number,
    bytes: Uint8Array,
    total: number,
    options?: WaitOptions,
  ): Promise<TransferReceipt>;
  /**
   * Seal the spool and bind it to one PUT_FILE operation (202 = accepted, not
   * guest-replaced). The whole-file SHA-256 is verified by the server; a
   * mismatch is a definitive 400. Replays under the same key return the
   * original operation even after expiry.
   */
  commitUpload(id: string, sha256: string, options?: MutationOptions): Promise<MutationReceipt>;
  /**
   * Abort an uncommitted upload and release its spool. Repeating abort is
   * safe; a committed upload conflicts (cancel its operation instead).
   */
  abortUpload(id: string, options?: WaitOptions): Promise<TransferReceipt>;
};

function invalidRequest(context: PollContext, detail: string): WsspError {
  return new WsspError({
    kind: "invalid_request",
    message: `${context.label}: ${detail}`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * Submit a transfer request and wait out `unknown` (lost response, 5xx) and
 * `capacity` (429) by re-sending the identical request: create/commit replay
 * under the same idempotency key, chunk writes digest-check identical bytes,
 * and abort is replay-safe. Any other error is definitive and propagates.
 * Mirrors `submitMutation`, generalized beyond mutation receipts.
 */
async function submitIdempotent<T>(
  send: (attempt: AbortSignal) => Promise<T>,
  polling: ReturnType<typeof resolvePolling>,
  signal: AbortSignal | undefined,
  context: PollContext,
): Promise<T> {
  return poll<T>(
    async (attempt) => ({ done: true, value: await send(attempt) }),
    polling,
    signal,
    context,
    (error) => error.kind === "unknown" || error.kind === "capacity",
    // A store still full at the deadline surfaces as its typed 429 (E-18).
    { submission: true, capacityAtDeadline: true },
  );
}

export function createTransfersApi(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
): TransfersApi {
  async function createUpload(
    input: UploadReservation,
    options: MutationOptions = {},
  ): Promise<TransferReceipt> {
    const context: PollContext = { label: `createUpload ${input.sandboxId}` };
    const key = options.idempotencyKey ?? generateKey();
    context.idempotencyKey = key;
    // The hard ceiling is checked before any IO; a lower configured cap is
    // discoverable via files.limits() and enforced server-side as 413.
    if (
      !Number.isSafeInteger(input.totalBytes) ||
      input.totalBytes < 0 ||
      input.totalBytes > TRANSFER_MAX_BYTES
    ) {
      throw invalidRequest(
        context,
        `totalBytes must be an integer from 0 to ${TRANSFER_MAX_BYTES}.`,
      );
    }
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    return submitIdempotent(
      (attempt) =>
        transport.request("createUpload", {
          params: undefined,
          body: input,
          idempotencyKey: key,
          signal: attempt,
        }),
      resolvePolling(defaults, { ...withWaitTimeout(options, deadline.remaining(context)) }),
      options.signal,
      context,
    );
  }

  async function getUpload(id: string, options: WaitOptions = {}): Promise<TransferReceipt> {
    return transport.request("getUpload", {
      params: { id },
      signal: options.signal,
      timeoutMs: waitTimeout(options),
    });
  }

  async function findUpload(
    id: string,
    options: WaitOptions = {},
  ): Promise<TransferReceipt | null> {
    try {
      return await getUpload(id, options);
    } catch (error) {
      if (isWsspError(error, "not_found") && error.code === "NOT_FOUND" && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  async function putChunk(
    id: string,
    offset: number,
    bytes: Uint8Array,
    total: number,
    options: WaitOptions = {},
  ): Promise<TransferReceipt> {
    const context: PollContext = { label: `putUploadChunk ${id} at ${offset}` };
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    return submitIdempotent(
      (attempt) =>
        transport.putUploadChunk({ params: { id }, offset, total, bytes, signal: attempt }),
      resolvePolling(defaults, { ...withWaitTimeout(options, deadline.remaining(context)) }),
      options.signal,
      context,
    );
  }

  async function commitUpload(
    id: string,
    sha256: string,
    options: MutationOptions = {},
  ): Promise<MutationReceipt> {
    const context: PollContext = { label: `commitUpload ${id}` };
    const key = options.idempotencyKey ?? generateKey();
    context.idempotencyKey = key;
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw invalidRequest(context, "sha256 must be 64 lowercase hex characters.");
    }
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    try {
      return await submitIdempotent(
        (attempt) =>
          transport.request("commitUpload", {
            params: { id },
            body: { sha256 },
            idempotencyKey: key,
            signal: attempt,
          }),
        resolvePolling(defaults, { ...withWaitTimeout(options, deadline.remaining(context)) }),
        options.signal,
        context,
      );
    } catch (error) {
      // The server authorizes BEFORE the commit transaction commits, but a
      // fence landing just after that check can still follow a DURABLE commit
      // (store.ts documents this maybe-after-commit window): a 403/404 here
      // is ambiguous, never a definitive rejection. Report `unknown` and keep
      // the commit key so the caller replays the commit to recover the truth.
      if (isWsspError(error) && (error.kind === "authorization" || error.kind === "not_found")) {
        throw new WsspError({
          kind: "unknown",
          reason: "maybe_after_commit",
          message: `${context.label}: the commit response was fenced (${error.code ?? error.status}); the commit may have landed — replay the same idempotency key to recover the outcome.`,
          code: error.code,
          status: error.status,
          requestId: error.requestId,
          idempotencyKey: key,
          cause: error,
        });
      }
      throw error;
    }
  }

  async function abortUpload(id: string, options: WaitOptions = {}): Promise<TransferReceipt> {
    const context: PollContext = { label: `abortUpload ${id}` };
    const deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    return submitIdempotent(
      (attempt) => transport.request("abortUpload", { params: { id }, signal: attempt }),
      resolvePolling(defaults, { ...withWaitTimeout(options, deadline.remaining(context)) }),
      options.signal,
      context,
    );
  }

  return { createUpload, getUpload, findUpload, putChunk, commitUpload, abortUpload };
}
