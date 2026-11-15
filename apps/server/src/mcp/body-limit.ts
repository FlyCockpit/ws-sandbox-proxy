import type { MiddlewareHandler } from "hono";
import { resolveClientIp } from "../client-ip.js";

/** Bound actual bytes, time and concurrent buffering, independently of Content-Length. */
export function mcpJsonBodyLimit({
  maxBytes = 1_048_576,
  deadlineMs = 60_000,
  maxReaders = 64,
  maxIpReaders = 8,
} = {}): MiddlewareHandler {
  let readers = 0;
  const byIp = new Map<string, number>();
  return async (c, next) => {
    const signal = c.req.raw.signal;
    const length = c.req.header("content-length");
    if (length && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length))))
      return c.newResponse(null, 400);
    if (length && Number(length) > maxBytes) return c.newResponse(null, 413);
    const encoding = c.req.header("content-encoding");
    if (encoding && encoding.toLowerCase() !== "identity") return c.newResponse(null, 415);
    const ip = resolveClientIp(c),
      prior = byIp.get(ip) ?? 0;
    if (readers >= maxReaders || prior >= maxIpReaders)
      return c.newResponse(null, 429, { "Retry-After": "1" });
    readers++;
    byIp.set(ip, prior + 1);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const reader = c.req.raw.body?.getReader();
    let timedOut = false;
    const cancel = () => {
      void reader?.cancel().catch(() => {});
    };
    try {
      if (signal.aborted) return new Response(null, { status: 499 });
      const bytes = new Uint8Array(maxBytes);
      let count = 0;
      timer = setTimeout(() => {
        timedOut = true;
        cancel();
      }, deadlineMs);
      timer.unref();
      signal.addEventListener("abort", cancel, { once: true });
      for (;;) {
        const chunk = await reader?.read();
        if (timedOut) return c.newResponse(null, 408);
        if (signal.aborted) return new Response(null, { status: 499 });
        if (!chunk || chunk.done) break;
        count += chunk.value.byteLength;
        if (count > maxBytes) {
          cancel();
          return c.newResponse(null, 413);
        }
        bytes.set(chunk.value, count - chunk.value.byteLength);
      }
      if (length && Number(length) !== count) return c.newResponse(null, 400);
      // Finish releasing the original stream before replacing the buffered request.
      reader?.releaseLock();
      c.req.raw = new Request(c.req.raw, { body: bytes.slice(0, count) });
      return next();
    } catch {
      return c.newResponse(null, 400);
    } finally {
      if (timer) clearTimeout(timer);
      signal.removeEventListener("abort", cancel);
      try {
        reader?.releaseLock();
      } catch {
        /* Already released. */
      }
      readers--;
      const remaining = (byIp.get(ip) ?? 1) - 1;
      if (remaining) byIp.set(ip, remaining);
      else byIp.delete(ip);
    }
  };
}
