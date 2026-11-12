import { ORPCError } from "@orpc/server";
import { setHostDrainingInput } from "@wssp/api/sandbox/contracts";
import { setHostDrainingWithCredential } from "@wssp/api/sandbox/host-drain";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { authLimiter, createRateLimiterMiddleware } from "../rate-limit.js";

/** Host credential plane, mounted before browser auth/CORS. Deliberately outside /v1. */
export function createHostControlApi() {
  const app = new Hono();
  app.onError((error, c) => {
    const status = error instanceof ORPCError ? error.status : 500;
    const code = error instanceof ORPCError ? error.code : "INTERNAL_SERVER_ERROR";
    return c.json({ error: { code } }, status as 400 | 401 | 403 | 404 | 409 | 500);
  });
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    await next();
  });
  app.use("*", createRateLimiterMiddleware(authLimiter, { failClosed: true }));
  app.use(
    "*",
    bodyLimit({
      maxSize: 1024,
      onError: (c) => c.json({ error: { code: "PAYLOAD_TOO_LARGE" } }, 413),
    }),
  );
  app.post("/drain", async (c) => {
    const secret = /^Bearer (\S+)$/i.exec(c.req.header("authorization") ?? "")?.[1];
    if (!secret) throw new ORPCError("UNAUTHORIZED");
    if (
      new URL(c.req.url).search ||
      c.req.header("content-encoding") ||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")
    ) {
      throw new ORPCError("BAD_REQUEST");
    }
    const input = setHostDrainingInput.safeParse(await c.req.json().catch(() => null));
    if (!input.success) throw new ORPCError("BAD_REQUEST");
    return c.json(await setHostDrainingWithCredential(secret, input.data));
  });
  app.all("*", (c) => c.json({ error: { code: "NOT_FOUND" } }, 404));
  return app;
}
