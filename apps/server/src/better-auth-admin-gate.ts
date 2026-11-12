import type { Context } from "hono";

/** Admin HTTP plugin endpoints bypass app projections/last-admin rules and
 * include impersonation and password takeover. Only oRPC administers users.
 * The auth config also disables every plugin endpoint before library effects.
 */
export async function betterAuthAdminGate(c: Context) {
  return c.json({ error: "not_found", error_description: "Not found" }, 404);
}
