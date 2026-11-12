import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { isBrowserSession } from "@wssp/api/sandbox/principal-kinds";
import { DOWNLOAD_ROUTES, type SdkRoute, TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";
import type { Context, Hono } from "hono";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { acquireTransferSlot } from "./http-admission.js";
import { transferError } from "./limits.js";
import { transferStore } from "./runtime.js";

/** A sealed, immutable capture: exact size, whole-content SHA-256, positional reads. */
export type DownloadSource = {
  size: number;
  sha256: string;
  guestPath: string;
  read(offset: number, length: number): Promise<Uint8Array>;
  /** The consumer pulled past these bytes (E-17 delivery coverage). */
  delivered(offset: number, length: number): void;
  /** This response is over (completed, failed or cancelled); idempotent. */
  close(): void;
};

/** A stalled consumer (no pull for this long) loses its stream and its slot. */
const DOWNLOAD_IDLE_MS = 60_000;

const etagOf = (sha256: string) => `"${sha256}"`;

/**
 * Selects the bytes to send: `null` for the whole content, else one inclusive
 * range. `If-Range` is a strong ETag comparison; a mismatch (including a weak
 * validator or a date) sends the whole content. Multiple ranges, other units,
 * malformed and unsatisfiable ranges are rejected with 416 (C30 decision).
 */
export function selectRange(
  range: string | undefined,
  ifRange: string | undefined,
  size: number,
  etag: string,
): { start: number; end: number } | null {
  if (range === undefined) return null;
  if (ifRange !== undefined && ifRange !== etag) return null;
  const match = /^bytes=(\d{0,15})-(\d{0,15})$/.exec(range);
  if (!match || size === 0) throw transferError("RANGE_NOT_SATISFIABLE");
  const [first, last] = [match[1]!, match[2]!];
  if (first === "") {
    // Suffix range: the final `last` bytes.
    const suffix = Number(last);
    if (last === "" || suffix === 0) throw transferError("RANGE_NOT_SATISFIABLE");
    return { start: Math.max(0, size - suffix), end: size - 1 };
  }
  const start = Number(first);
  const end = last === "" ? size - 1 : Math.min(Number(last), size - 1);
  if (start >= size || (last !== "" && Number(last) < start))
    throw transferError("RANGE_NOT_SATISFIABLE");
  return { start, end };
}

/**
 * Pull-based body: at most one chunk read is in flight and nothing is read
 * before the consumer asks (highWaterMark 0), so a slow client holds no more
 * than one chunk. `release` runs exactly once on completion, error, consumer
 * cancel or the idle deadline.
 *
 * Delivery (E-17): a chunk counts as delivered only when the consumer asks
 * for more after it — with highWaterMark 0 that next pull means the previous
 * chunk left this stream — and the final close happens on the pull after the
 * last chunk. A cancel or error credits nothing still queued. "Left this
 * stream" means Node handed it to the kernel, not that the client has it, so
 * the store keeps a delivered capture for a short grace (TQ-F1).
 */
export function downloadBody(
  source: DownloadSource,
  start: number,
  endExclusive: number,
  release: () => void,
  idleMs = DOWNLOAD_IDLE_MS,
  authorize: () => Promise<void> = async () => {},
): ReadableStream<Uint8Array> {
  let finished = false;
  let offset = start;
  let pending: { at: number; length: number } | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      finish();
      controller.error(transferError("TRANSFER_EXPIRED"));
    }, idleMs);
    timer.unref?.();
  };
  const finish = () => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    release();
  };
  return new ReadableStream<Uint8Array>(
    {
      start(c) {
        controller = c;
        arm();
      },
      async pull(c) {
        clearTimeout(timer);
        try {
          if (finished) return;
          if (offset >= endExclusive) {
            // No IO or disclosure remains: credit the final delivered bytes
            // and close normally even if authority changed after enqueue.
            if (pending) source.delivered(pending.at, pending.length);
            pending = null;
            source.delivered(offset, 0);
            finish();
            c.close();
            return;
          }
          await authorize();
          if (finished) return;
          if (pending) source.delivered(pending.at, pending.length);
          pending = null;
          // Chunk-aligned reads: each read stays within one durable 1 MiB chunk.
          const length = Math.min(
            TRANSFER_CHUNK_BYTES - (offset % TRANSFER_CHUNK_BYTES),
            endExclusive - offset,
          );
          let bytes: Uint8Array;
          try {
            bytes = await source.read(offset, length);
          } finally {
            // A revocation during IO hides bytes AND the source's error.
            await authorize();
          }
          if (finished) return;
          if (bytes.byteLength !== length) throw transferError("TRANSFER_IO");
          pending = { at: offset, length };
          offset += length;
          c.enqueue(bytes);
          arm();
        } catch (error) {
          finish();
          throw error;
        }
      },
      cancel() {
        finish();
      },
    },
    { highWaterMark: 0 },
  );
}

/** Serves one source for one request. Exposed for the streaming fixtures. */
function serveDownload(
  c: Context,
  source: DownloadSource,
  release: () => void,
  authorize: () => Promise<void>,
): Response {
  const etag = etagOf(source.sha256);
  let selected: { start: number; end: number } | null;
  try {
    selected = selectRange(c.req.header("range"), c.req.header("if-range"), source.size, etag);
  } catch (error) {
    release();
    c.header("Content-Range", `bytes */${source.size}`);
    throw error;
  }
  const start = selected?.start ?? 0;
  const endExclusive = selected ? selected.end + 1 : source.size;
  const name = source.guestPath.split("/").filter(Boolean).at(-1) ?? "download";
  const headers = new Headers(c.res.headers);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Accept-Ranges", "bytes");
  headers.set("ETag", etag);
  headers.set("Repr-Digest", `sha-256=:${Buffer.from(source.sha256, "hex").toString("base64")}:`);
  headers.set("Content-Length", String(endExclusive - start));
  if (selected) headers.set("Content-Range", `bytes ${start}-${selected.end}/${source.size}`);
  const status = selected ? 206 : 200;
  // Hono answers HEAD from the GET handler; never open a stream it would discard.
  if (c.req.raw.method === "HEAD") {
    release();
    return new Response(null, { status, headers });
  }
  return new Response(
    downloadBody(source, start, endExclusive, release, DOWNLOAD_IDLE_MS, authorize),
    { status, headers },
  );
}

async function handle(
  c: Context,
  route: SdkRoute,
  authorize: () => Promise<Principal>,
  checkNow: () => Promise<void>,
): Promise<Response> {
  const owner = await authorize();
  if (new URL(c.req.url).search) throw new ORPCError("BAD_REQUEST");
  const params = route.params?.safeParse(c.req.param());
  if (!params?.success) throw new ORPCError("BAD_REQUEST");
  const operationId = (params.data as { id: string }).id;
  const release = acquireTransferSlot(owner);
  const recheck = async () => {
    if (isBrowserSession(owner)) await checkNow();
  };
  let source: DownloadSource | undefined;
  let released = false;
  const finish = () => {
    if (released) return;
    released = true;
    release();
    source?.close();
  };
  try {
    // Live authorization per request: scopes, grants, originating credential,
    // operation outcome, capture expiry and sandbox generation. Each chunk read
    // repeats the transfer's own authorization and expiry checks.
    try {
      source = await transferStore().downloadSource(owner, operationId);
    } finally {
      await recheck();
    }
    return serveDownload(c, source, finish, recheck);
  } catch (error) {
    finish();
    if (error instanceof ORPCError && error.code === "NOT_FOUND")
      throw new ORPCError("NOT_FOUND", { data: { code: route.notFound } });
    throw error;
  }
}

/** One registration inventory and handler for both credential planes. */
export function registerDownloadRoutes<E extends SandboxApiEnv>(
  app: Hono<E>,
  authorize: (c: Context) => Promise<Principal>,
  checkNow: (c: Context) => Promise<void> = async (c) => {
    await authorize(c);
  },
) {
  for (const route of Object.values(DOWNLOAD_ROUTES) as SdkRoute[]) {
    const path = route.path.replace("/v1", "").replace("{id}", ":id");
    app.on(route.method.toUpperCase(), path, (c) =>
      handle(
        c,
        route,
        () => authorize(c),
        () => checkNow(c),
      ),
    );
    app.all(path, () => {
      throw new ORPCError("METHOD_NOT_SUPPORTED");
    });
  }
}
