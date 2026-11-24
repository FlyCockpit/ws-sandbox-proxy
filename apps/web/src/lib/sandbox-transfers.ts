import { TRANSFER_CHUNK_BYTES, TRANSFER_MAX_BYTES } from "@wssp/api/sandbox/contracts";

import { newIntentKey, sandboxProblem } from "@/lib/sandbox-rules";
import { Sha256 } from "@/lib/sha256";

/**
 * Browser file transfer adapter (C47) for the dashboard's binary plane,
 * `/api/dashboard/…` (C29/C30). It authenticates with the session cookie
 * only (`credentials: "include"`); the server additionally requires the
 * browser's own same-origin `Origin`/`Sec-Fetch-Site` headers (its CSRF
 * boundary), which a page cannot forge. No SDK key, bearer token or other
 * credential is ever read, stored or sent from here.
 *
 * Uploads never hold more than one 1 MiB chunk in memory: each chunk is read
 * from the File, hashed incrementally, sent with an exact `Content-Range`,
 * and the whole-file SHA-256 is committed at the end. Downloads are served
 * by the browser straight to disk from the content URL.
 */

export { TRANSFER_CHUNK_BYTES, TRANSFER_MAX_BYTES };

export type TransferProblem =
  | "tooLarge"
  | "quota"
  | "busy"
  | "expired"
  | "forbidden"
  | "signedOut"
  | "notFound"
  | "notReady"
  | "conflict"
  | "storage"
  | "invalid"
  | "network"
  | "cancelled"
  | "uncertain"
  | "generic";

export class TransferError extends Error {
  constructor(
    readonly problem: TransferProblem,
    readonly status?: number,
  ) {
    super(`transfer ${problem}${status ? ` (${status})` : ""}`);
    this.name = "TransferError";
  }
}

const CODE_PROBLEM: Record<string, TransferProblem> = {
  PAYLOAD_TOO_LARGE: "tooLarge",
  TRANSFER_QUOTA: "quota",
  TOO_MANY_REQUESTS: "busy",
  TRANSFER_EXPIRED: "expired",
  FORBIDDEN: "forbidden",
  UNAUTHORIZED: "signedOut",
  NOT_FOUND: "notFound",
  "sandbox.not_found": "notFound",
  "sandbox.operation_not_found": "notFound",
  TRANSFER_NOT_READY: "notReady",
  CONFLICT: "conflict",
  "sandbox.state_conflict": "conflict",
  "sandbox.idempotency_conflict": "conflict",
  TRANSFER_IO: "storage",
  SERVICE_UNAVAILABLE: "storage",
  BAD_REQUEST: "invalid",
};

const STATUS_PROBLEM: Record<number, TransferProblem> = {
  400: "invalid",
  401: "signedOut",
  403: "forbidden",
  404: "notFound",
  409: "conflict",
  410: "expired",
  413: "tooLarge",
  // Only a `TRANSFER_QUOTA` code means the transfer quota; the request limiter
  // answers 429 with a bare message, which is throttling, not quota.
  429: "busy",
  503: "storage",
};

/** The problem a failed response describes: its stable error code, else its status. */
async function responseProblem(response: Response): Promise<TransferProblem> {
  let code: unknown;
  try {
    code = ((await response.json()) as { error?: { code?: unknown } })?.error?.code;
  } catch {
    code = undefined;
  }
  const known = typeof code === "string" ? CODE_PROBLEM[code] : undefined;
  if (known) return known;
  return STATUS_PROBLEM[response.status] ?? "generic";
}

/** The transfer problem any failure (a transfer or an oRPC call) stands for. */
export function toTransferProblem(error: unknown): TransferProblem {
  if (error instanceof TransferError) return error.problem;
  const shape = (error && typeof error === "object" ? error : {}) as {
    code?: unknown;
    status?: unknown;
  };
  if (shape.code === "UNAUTHORIZED" || shape.status === 401) return "signedOut";
  const problem = sandboxProblem(error);
  if (problem === "notFound") return "notFound";
  if (problem === "stateChanged") return "conflict";
  if (problem === "forbidden") return "forbidden";
  if (problem === "invalid") return "invalid";
  return "generic";
}

export type TransferDeps = {
  /** API origin (`env.VITE_SERVER_URL`). */
  serverUrl: string;
  fetch?: typeof fetch;
  /** Idempotency-key randomness (tests pin it). */
  random?: () => string;
  /** Throttle back-off (tests observe it instead of sleeping). */
  wait?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

/** Waits honoured per request after a throttled (429, not quota) answer. */
export const THROTTLE_MAX_WAITS = 6;
/** Upper bound on one `Retry-After` wait; the request limiter's window is 60 s. */
export const THROTTLE_MAX_WAIT_MS = 60_000;
const THROTTLE_DEFAULT_WAIT_MS = 1_000;

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new TransferError("cancelled"));
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new TransferError("cancelled"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function retryAfterMs(response: Response): number {
  const header = response.headers.get("retry-after");
  const seconds = header == null ? Number.NaN : Number(header);
  if (Number.isFinite(seconds) && seconds >= 0)
    return Math.min(Math.ceil(seconds * 1000), THROTTLE_MAX_WAIT_MS);
  const date = header == null ? Number.NaN : Date.parse(header);
  if (Number.isFinite(date)) return Math.min(Math.max(date - Date.now(), 0), THROTTLE_MAX_WAIT_MS);
  return THROTTLE_DEFAULT_WAIT_MS;
}

/**
 * `send`, waiting out request throttling: a 429 that is not the transfer
 * quota was refused before the handler ran, so resending is safe. Waits are
 * bounded and abortable; the last throttled answer is returned as-is.
 */
async function sendThrottled(
  deps: TransferDeps,
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<Response> {
  const wait = deps.wait ?? sleep;
  for (let waits = 0; ; waits++) {
    const response = await send(deps, path, init, signal);
    if (response.status !== 429 || waits >= THROTTLE_MAX_WAITS) return response;
    if ((await responseProblem(response.clone())) === "quota") return response;
    await wait(retryAfterMs(response), signal);
    if (signal?.aborted) throw new TransferError("cancelled");
  }
}

function base(deps: TransferDeps) {
  return `${deps.serverUrl.replace(/\/+$/, "")}/api/dashboard`;
}

async function send(
  deps: TransferDeps,
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<Response> {
  const doFetch = deps.fetch ?? fetch;
  let response: Response;
  try {
    response = await doFetch(`${base(deps)}${path}`, {
      ...init,
      credentials: "include",
      cache: "no-store",
      signal,
    });
  } catch {
    if (signal?.aborted) throw new TransferError("cancelled");
    throw new TransferError("network", undefined);
  }
  return response;
}

async function expectOk(response: Response, statuses: readonly number[]) {
  if (statuses.includes(response.status)) return;
  throw new TransferError(await responseProblem(response), response.status);
}

export type UploadReceipt = { transferId: string; operationId: string; sha256: string };

/**
 * Upload `file` to `guestPath` in the sandbox. Refuses a file over the
 * product cap before any request; the server's configured cap (which may be
 * lower) refuses the reservation before any byte is sent. A chunk whose
 * response is lost is resent identically (idempotent on the server) up to
 * twice. Cancelling, or any failure before commit, aborts the reservation so
 * the spool is released at once instead of at idle expiry. Once the commit has
 * been sent, a cancel or lost answer is only reported as "nothing written" if
 * the abort succeeds; otherwise the commit key is replayed for its receipt, or
 * the outcome is reported as `uncertain`. Request throttling (a 429 without
 * the transfer-quota code) is waited out per `Retry-After`, bounded.
 */
/** Commit statuses the server can return after the operation was created. */
const MAYBE_AFTER_COMMIT = new Set([403, 404, 409]);

export async function uploadToSandbox(
  deps: TransferDeps,
  input: {
    sandboxId: string;
    guestPath: string;
    file: Blob;
    signal?: AbortSignal;
    onProgress?: (sentBytes: number, totalBytes: number) => void;
  },
): Promise<UploadReceipt> {
  const { file, signal } = input;
  if (file.size > TRANSFER_MAX_BYTES) throw new TransferError("tooLarge");
  const random = deps.random ?? (() => crypto.randomUUID());
  const createKey = newIntentKey("upload", random);
  // A lost create response is replayed with the same key: the same reservation.
  const created = await withNetworkRetry(() =>
    sendThrottled(
      deps,
      "/transfers",
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": createKey },
        body: JSON.stringify({
          sandboxId: input.sandboxId,
          guestPath: input.guestPath,
          totalBytes: file.size,
        }),
      },
      signal,
    ),
  );
  await expectOk(created, [200, 201]);
  const transferId = ((await created.json()) as { id: string }).id;
  const path = `/transfers/${encodeURIComponent(transferId)}`;
  let committed = false;
  let commitKey: string | null = null;
  let commitMayHaveLanded = false;
  const commitRequest = (sha256: string): RequestInit => ({
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": commitKey ?? "" },
    body: JSON.stringify({ sha256 }),
  });
  let sha256 = "";
  try {
    const hash = new Sha256();
    input.onProgress?.(0, file.size);
    for (let offset = 0; offset < file.size; offset += TRANSFER_CHUNK_BYTES) {
      if (signal?.aborted) throw new TransferError("cancelled");
      const end = Math.min(offset + TRANSFER_CHUNK_BYTES, file.size);
      const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      hash.update(chunk);
      await putChunk(deps, path, chunk, offset, file.size, signal);
      input.onProgress?.(end, file.size);
    }
    sha256 = hash.hex();
    if (signal?.aborted) throw new TransferError("cancelled");
    commitKey = newIntentKey("upload-commit", random);
    // A lost commit response is replayed with the same key (same operation).
    const receipt = await withNetworkRetry(async () => {
      try {
        return await sendThrottled(deps, `${path}/commit`, commitRequest(sha256), signal);
      } catch (error) {
        commitMayHaveLanded = true;
        throw error;
      }
    });
    await expectOk(receipt, [200, 202]);
    // An accepted commit whose body is lost is as uncertain as a lost answer.
    const operationId = await readOperationId(receipt);
    if (operationId === null) {
      commitMayHaveLanded = true;
      throw new TransferError("network");
    }
    committed = true;
    return { transferId, operationId, sha256 };
  } catch (error) {
    // A refusal only settles the outcome if no earlier attempt may have been
    // accepted: a later 401 or 429 cannot disprove a lost answer. Some
    // statuses can conceal an accepted commit even on the first attempt: the
    // store answers 409 while a commit owns the transfer, and it re-checks
    // authority and ownership after the operation is durable, so 403 and 404
    // can follow a commit that landed.
    const refused =
      !commitMayHaveLanded &&
      error instanceof TransferError &&
      error.status != null &&
      error.status < 500 &&
      !MAYBE_AFTER_COMMIT.has(error.status);
    if (commitKey == null || refused) throw error;
    // The commit was sent, so the server may own the transfer already. Only a
    // successful abort proves nothing was written; otherwise replay the commit
    // key for its receipt, or admit the outcome is unknown.
    const released = await sendThrottled(deps, path, { method: "DELETE" }).catch(() => null);
    if (released?.status === 200) {
      committed = true;
      throw error;
    }
    const replay = await sendThrottled(deps, `${path}/commit`, commitRequest(sha256)).catch(
      () => null,
    );
    committed = true;
    const operationId =
      replay && (replay.status === 200 || replay.status === 202)
        ? await readOperationId(replay)
        : null;
    if (operationId !== null) return { transferId, operationId, sha256 };
    throw new TransferError("uncertain");
  } finally {
    if (!committed) {
      // Release the reservation now; a failed abort is harmless (idle expiry).
      await releaseReservation(deps, path);
    }
  }
}

/**
 * Abort an uncommitted reservation. A throttled abort is waited out in the
 * background (bounded) so the page reports the failure at once.
 */
async function releaseReservation(deps: TransferDeps, path: string) {
  const first = await send(deps, path, { method: "DELETE" }).catch(() => null);
  if (first?.status === 429)
    void sendThrottled(deps, path, { method: "DELETE" }).catch(() => undefined);
}

/** The commit receipt's operation ID, or null when its body is lost or malformed. */
async function readOperationId(response: Response): Promise<string | null> {
  try {
    const { operationId } = (await response.json()) as { operationId?: unknown };
    return typeof operationId === "string" && operationId.length > 0 ? operationId : null;
  } catch {
    return null;
  }
}

/** One resend after a network failure (never after a server answer). */
async function withNetworkRetry(request: () => Promise<Response>): Promise<Response> {
  try {
    return await request();
  } catch (error) {
    if (error instanceof TransferError && error.problem === "network") return request();
    throw error;
  }
}

async function putChunk(
  deps: TransferDeps,
  path: string,
  chunk: Uint8Array,
  offset: number,
  total: number,
  signal?: AbortSignal,
) {
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await sendThrottled(
        deps,
        path,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Range": `bytes ${offset}-${offset + chunk.length - 1}/${total}`,
          },
          body: chunk as BodyInit,
        },
        signal,
      );
      await expectOk(response, [200]);
      return;
    } catch (error) {
      // Throttling ("busy") was already waited out by `sendThrottled`.
      const retryable =
        error instanceof TransferError &&
        (error.problem === "network" || error.problem === "conflict");
      if (!retryable || attempt >= 2) throw error;
    }
  }
}

/** Where the browser saves a completed capture from (cookie session, same origin). */
export function downloadUrl(deps: Pick<TransferDeps, "serverUrl">, operationId: string): string {
  return `${base(deps as TransferDeps)}/operations/${encodeURIComponent(operationId)}/content`;
}

/**
 * Check a completed capture is still readable before offering it: the same
 * route answers `HEAD` with its length and no body, so an expired capture or
 * a revoked session is explained on the page rather than as a browser error.
 */
export async function probeDownload(
  deps: TransferDeps,
  operationId: string,
  signal?: AbortSignal,
): Promise<{ sizeBytes: number | null }> {
  const response = await send(
    deps,
    `/operations/${encodeURIComponent(operationId)}/content`,
    { method: "HEAD" },
    signal,
  );
  if (response.status !== 200)
    throw new TransferError(STATUS_PROBLEM[response.status] ?? "generic", response.status);
  const length = Number(response.headers.get("content-length"));
  return { sizeBytes: Number.isSafeInteger(length) && length >= 0 ? length : null };
}

/**
 * SHA-256 and size of a build context (template builds §3.6): the create
 * request carries both, so the file is hashed before acceptance, one 1 MiB
 * slice at a time.
 */
export async function hashBuildContext(
  file: Blob,
  options: { signal?: AbortSignal; onProgress?: (hashed: number, total: number) => void } = {},
): Promise<{ sha256: string; bytes: number }> {
  if (file.size > TRANSFER_MAX_BYTES) throw new TransferError("tooLarge");
  const hash = new Sha256();
  for (let offset = 0; offset < file.size; offset += TRANSFER_CHUNK_BYTES) {
    if (options.signal?.aborted) throw new TransferError("cancelled");
    const end = Math.min(offset + TRANSFER_CHUNK_BYTES, file.size);
    hash.update(new Uint8Array(await file.slice(offset, end).arrayBuffer()));
    options.onProgress?.(end, file.size);
  }
  return { sha256: hash.hex(), bytes: file.size };
}

/**
 * Upload the staged context of a COPY build the session accepted
 * (`/api/dashboard/template-builds/:id/context…`, same-origin and the live
 * session only): open (idempotent), every chunk on the fixed 1 MiB grid at
 * its offset in the path, then seal, where the server checks the SHA-256
 * sent at acceptance. A chunk is replayable, so a lost answer is resent.
 */
export async function uploadBuildContext(
  deps: TransferDeps,
  input: {
    buildId: string;
    file: Blob;
    signal?: AbortSignal;
    onProgress?: (sentBytes: number, totalBytes: number) => void;
  },
): Promise<void> {
  const { file, signal } = input;
  const path = `/template-builds/${encodeURIComponent(input.buildId)}/context`;
  const post = (suffix: string) =>
    withNetworkRetry(() =>
      sendThrottled(
        deps,
        `${path}${suffix}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
        signal,
      ),
    );
  const opened = await post("");
  await expectOk(opened, [200]);
  const { receivedBytes } = (await opened.json()) as { receivedBytes?: unknown };
  // Re-opening resumes after the chunks the server already holds.
  const resumeAt =
    typeof receivedBytes === "number" && receivedBytes > 0
      ? Math.floor(Math.min(receivedBytes, file.size) / TRANSFER_CHUNK_BYTES) * TRANSFER_CHUNK_BYTES
      : 0;
  input.onProgress?.(resumeAt, file.size);
  for (let offset = resumeAt; offset < file.size; offset += TRANSFER_CHUNK_BYTES) {
    if (signal?.aborted) throw new TransferError("cancelled");
    const end = Math.min(offset + TRANSFER_CHUNK_BYTES, file.size);
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    for (let attempt = 0; ; attempt++) {
      try {
        const response = await sendThrottled(
          deps,
          `${path}/chunks/${offset}`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/octet-stream" },
            body: chunk as BodyInit,
          },
          signal,
        );
        await expectOk(response, [200]);
        break;
      } catch (error) {
        const retryable =
          error instanceof TransferError &&
          (error.problem === "network" || error.problem === "conflict");
        if (!retryable || attempt >= 2) throw error;
      }
    }
    input.onProgress?.(end, file.size);
  }
  const sealed = await post("/seal");
  await expectOk(sealed, [200]);
}
