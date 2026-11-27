import type { Session } from "@wssp/auth";
import type { Context, Next } from "hono";
import { sessionMiddleware } from "./session-middleware.js";

/** Consistency check only: authentication and authorization remain downstream. */
export async function expectedIdentity(c: Context, next: Next) {
  const expected = c.req.header("X-Expected-User");
  if (!expected) return next();
  if (c.get("session") === undefined) await sessionMiddleware(c, async () => {});
  if (c.get("sessionLookupFailed")) return c.json({ code: "SESSION_UNAVAILABLE" }, 503);
  const session = c.get("session") as Session | null;
  const owner = c.get("sessionCookieOwner") ?? session?.user?.id;
  if (owner && owner !== expected) {
    c.header("X-Identity-Changed", "1");
    return c.json({ code: "IDENTITY_CHANGED" }, 409);
  }
  return next();
}
