import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { idempotencyKey } from "@wssp/api/sandbox/contracts";
import { isBrowserSession } from "@wssp/api/sandbox/principal-kinds";
import {
  JSON_BODY_MAX_BYTES,
  type SdkRoute,
  TRANSFER_CHUNK_BYTES,
  UPLOAD_ROUTES,
} from "@wssp/sandbox-contracts";
import { type Context, Hono } from "hono";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { admitted } from "./http-admission.js";
import { checkChunk } from "./limits.js";
import { transferStore } from "./runtime.js";

export async function readBody(
  c: Context,
  binary: boolean,
  authorize: () => Promise<void>,
): Promise<Uint8Array> {
  const limit = binary ? TRANSFER_CHUNK_BYTES : JSON_BODY_MAX_BYTES;
  const encoding = c.req.header("content-encoding");
  if (encoding && encoding.toLowerCase() !== "identity")
    throw new ORPCError("UNSUPPORTED_MEDIA_TYPE");
  const declared = c.req.header("content-length");
  if (declared && (!/^\d+$/.test(declared) || !Number.isSafeInteger(Number(declared))))
    throw new ORPCError("BAD_REQUEST");
  if (declared && Number(declared) > limit) throw new ORPCError("PAYLOAD_TOO_LARGE");
  if (c.req.raw.signal.aborted) throw new ORPCError("BAD_REQUEST");
  const reader = c.req.raw.body?.getReader();
  if (!reader) return new Uint8Array();
  const buffer = new Uint8Array(limit);
  let size = 0;
  let cancelled = false;
  const cancel = () => {
    cancelled = true;
    void reader.cancel().catch(() => {});
  };
  const timer = setTimeout(cancel, 60_000);
  timer.unref();
  c.req.raw.signal.addEventListener("abort", cancel, { once: true });
  try {
    await authorize();
    let checkedAt = Date.now();
    let checkedBytes = 0;
    for (;;) {
      const { done, value } = await reader.read().catch((error: unknown) => {
        // Transport/body failures are bad requests; authority infrastructure
        // failures outside this read must retain their server-error status.
        throw error instanceof ORPCError ? error : new ORPCError("BAD_REQUEST");
      });
      if (!done) size += value.byteLength;
      // Tiny network pieces must not amplify DB work. Check at the first byte
      // or read boundary after one second / one MiB, and always at EOF.
      if (done || Date.now() - checkedAt >= 1000 || size - checkedBytes >= TRANSFER_CHUNK_BYTES) {
        await authorize();
        checkedAt = Date.now();
        checkedBytes = size;
      }
      if (cancelled || c.req.raw.signal.aborted) throw new ORPCError("BAD_REQUEST");
      if (done) break;
      if (size > limit) throw new ORPCError("PAYLOAD_TOO_LARGE");
      buffer.set(value, size - value.byteLength);
    }
    if (declared && Number(declared) !== size) throw new ORPCError("BAD_REQUEST");
    const type = c.req.header("content-type") ?? "";
    if (
      (size || binary) &&
      !(
        binary ? /^application\/octet-stream$/i : /^application\/json(?:\s*;\s*charset=utf-8)?$/i
      ).test(type)
    )
      throw new ORPCError("UNSUPPORTED_MEDIA_TYPE");
    return buffer.subarray(0, size);
  } catch (error) {
    cancel();
    throw error;
  } finally {
    clearTimeout(timer);
    c.req.raw.signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}

async function handle(
  c: Context,
  id: keyof typeof UPLOAD_ROUTES,
  authorize: () => Promise<Principal>,
  checkNow: () => Promise<void>,
) {
  const owner = await authorize();
  const recheck = async () => {
    if (isBrowserSession(owner)) await checkNow();
  };
  return admitted(owner, async () => {
    const route: SdkRoute = UPLOAD_ROUTES[id];
    let result: unknown;
    try {
      if (new URL(c.req.url).search) throw new ORPCError("BAD_REQUEST");
      const params = route.params?.safeParse(c.req.param());
      if (params && !params.success) throw new ORPCError("BAD_REQUEST");
      const transferId = c.req.param("id") ?? "";
      const store = transferStore();
      // Authorize the resource before consuming bytes; the store rechecks after IO.
      const prior = id === "createUpload" ? undefined : await store.status(owner, transferId);
      if (prior && prior.direction !== "UPLOAD") throw new ORPCError("NOT_FOUND");
      let offset = 0;
      let length = 0;
      if (route.binary) {
        const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(c.req.header("content-range") ?? "");
        if (!match) throw new ORPCError("BAD_REQUEST");
        const [start, end, total] = match.slice(1).map(Number);
        if (
          ![start, end, total].every(Number.isSafeInteger) ||
          total !== prior?.totalBytes ||
          end! < start! ||
          end! >= total!
        )
          throw new ORPCError("BAD_REQUEST");
        offset = start!;
        length = end! - start! + 1;
        checkChunk(total!, offset, length);
      }
      const bytes = await readBody(c, route.binary === true, recheck);
      let body: unknown;
      if (route.body) {
        try {
          body = bytes.length
            ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
            : {};
        } catch {
          throw new ORPCError("BAD_REQUEST");
        }
        const parsed = route.body.safeParse(body);
        if (!parsed.success) throw new ORPCError("BAD_REQUEST");
        body = parsed.data;
      } else if (!route.binary && bytes.length) throw new ORPCError("BAD_REQUEST");
      let key = "";
      if (route.body && route.idempotency !== false) {
        const parsed = idempotencyKey.safeParse(c.req.header("Idempotency-Key"));
        if (!parsed.success) throw new ORPCError("BAD_REQUEST");
        key = parsed.data;
      }
      // In particular, browser 2FA/ban policy cannot be cached across a slow body.
      await authorize();
      switch (id) {
        case "createUpload":
          result = await store.create(owner, {
            ...UPLOAD_ROUTES.createUpload.body.parse(body),
            direction: "UPLOAD",
            idempotencyKey: key,
          });
          break;
        case "getUpload":
          result = await store.status(owner, transferId);
          break;
        case "putUploadChunk":
          if (bytes.length !== length) throw new ORPCError("BAD_REQUEST");
          // The store hashes its own defensive copy once.
          result = await store.write(owner, transferId, offset, bytes);
          break;
        case "commitUpload": {
          const receipt = await store.commit(
            owner,
            transferId,
            key,
            UPLOAD_ROUTES.commitUpload.body.parse(body).sha256,
          );
          result = { ...receipt, location: `/v1/operations/${receipt.operationId}` };
          break;
        }
        case "abortUpload":
          result = await store.abort(owner, transferId);
          break;
      }
    } finally {
      // Disclosure-only after acceptance: committed work is not rolled back.
      // This also replaces sensitive store/body errors after session revocation.
      await recheck();
    }
    // Do not prepare success headers (including receipt Location) before the
    // exit fence: Hono carries prepared headers onto an error response too.
    const response = route.response.schema.parse(result);
    if (id === "createUpload")
      c.header("Location", `${c.req.path}/${(response as { id: string }).id}`);
    if (id === "commitUpload") c.header("Location", (response as { location: string }).location);
    return c.json(response, route.successStatus ?? 200);
  });
}

/** One registration inventory and handler for both credential planes. */
export function registerUploadRoutes<E extends SandboxApiEnv>(
  app: Hono<E>,
  authorize: (c: Context) => Promise<Principal>,
  checkNow: (c: Context) => Promise<void> = async (c) => {
    await authorize(c);
  },
) {
  for (const [id, route] of Object.entries(UPLOAD_ROUTES)) {
    const path = route.path.replace("/v1", "").replace("{id}", ":id");
    app.on(route.method.toUpperCase(), path, (c) =>
      handle(
        c,
        id as keyof typeof UPLOAD_ROUTES,
        () => authorize(c),
        () => checkNow(c),
      ),
    );
  }
  app.all("/transfers", () => {
    throw new ORPCError("METHOD_NOT_SUPPORTED");
  });
  app.all("/transfers/*", () => {
    throw new ORPCError("NOT_FOUND");
  });
}
