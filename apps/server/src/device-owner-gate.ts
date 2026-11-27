import { call, ORPCError } from "@orpc/server";
import { ownerDeviceProcedure } from "@wssp/api";
import { transitionDeviceCode } from "@wssp/api/lib/device-code-transitions";
import { evaluateOwnerDeviceSession } from "@wssp/api/lib/owner-device-session-gate";
import { auth, type Session } from "@wssp/auth";
import { userLoginGrantSchema } from "@wssp/config/user-device-login";
import type { Context, Next } from "hono";
import { z } from "zod";
import { validateSameSiteJsonRequest } from "./request-origin.js";

async function requireVerifiedOwnerDeviceSession(headers: Headers) {
  const cookieOnly = new Headers(headers);
  cookieOnly.delete("authorization");
  // Lookup failures propagate as 5xx; absence alone means unauthenticated.
  const session = (await auth.api.getSession({ headers: cookieOnly })) as Session | null;
  const expected = headers.get("X-Expected-User");
  if (expected && session?.user?.id && session.user.id !== expected) {
    return { ok: false as const, body: { code: "IDENTITY_CHANGED" }, status: 409 as const };
  }
  return evaluateOwnerDeviceSession(session);
}

function reject(
  c: Context,
  result: Extract<Awaited<ReturnType<typeof requireVerifiedOwnerDeviceSession>>, { ok: false }>,
) {
  return c.json(result.body, result.status);
}

/** Exact allowlist prevents alternate router spellings from bypassing the owner gate. */
export async function deviceOwnerGate(c: Context, next: Next) {
  let path: string;
  try {
    path = decodeURIComponent(c.req.path).replace(/\/+/g, "/");
  } catch {
    return c.json({ error: "invalid_request" }, 400);
  }
  if (!path.startsWith("/api/auth/device")) return next();
  if (c.req.path === "/api/auth/device/code" && c.req.method === "POST") return next();
  const paths = ["/api/auth/device", "/api/auth/device/approve", "/api/auth/device/deny"];
  if (!paths.includes(c.req.path)) return c.json({ error: "not_found" }, 404);
  if (c.req.method !== "POST") return c.json({ error: "method_not_allowed" }, 405);
  const originError = validateSameSiteJsonRequest(c, { allowTrustedCrossSite: true });
  if (originError) return originError;
  let result: Awaited<ReturnType<typeof requireVerifiedOwnerDeviceSession>>;
  try {
    result = await requireVerifiedOwnerDeviceSession(c.req.raw.headers);
  } catch (error) {
    if (c.req.header("X-Expected-User")) return c.json({ code: "SESSION_UNAVAILABLE" }, 503);
    throw error;
  }
  if (!result.ok) return reject(c, result);
  c.set("deviceOwnerId", result.session.user.id);
  c.set("deviceOwnerSession", result.session);
  await next();
}

const deviceDecisionInput = z.object({
  userCode: z.string().trim().min(1).max(191),
  intent: z
    .discriminatedUnion("kind", [
      z.object({ kind: z.literal("create") }),
      z.object({ kind: z.literal("replace"), hostId: z.string().min(1).max(191) }),
    ])
    .optional(),
  /** A `user-login` approval's chosen grant; the transition refuses it on a host row. */
  grant: userLoginGrantSchema.optional(),
});

// Parse the body before entering the registered gate: a slow body cannot carry
// cached browser authority into a credential enrollment/rotation decision.
const deviceDecision = ownerDeviceProcedure
  .input(deviceDecisionInput.extend({ action: z.enum(["claim", "approve", "deny"]) }))
  .handler(({ input, context }) =>
    transitionDeviceCode({
      ...input,
      userId: context.session.user.id,
      sessionId: context.session.session.id,
    }),
  );

export async function deviceDecisionHandler(c: Context) {
  const body = deviceDecisionInput.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);
  const action = c.req.path.endsWith("/approve")
    ? "approve"
    : c.req.path.endsWith("/deny")
      ? "deny"
      : "claim";
  try {
    return c.json(
      await call(
        deviceDecision,
        { ...body.data, action },
        {
          context: { session: c.get("deviceOwnerSession") as Session, clientIp: undefined },
        },
      ),
    );
  } catch (error) {
    if (!(error instanceof ORPCError)) throw error;
    return c.json(
      {
        error: error.code,
        error_description: error.message,
        ...(error.data ? { data: error.data } : {}),
      },
      error.code === "SERVICE_UNAVAILABLE"
        ? 503
        : error.code === "CONFLICT"
          ? 409
          : error.code === "UNAUTHORIZED"
            ? 401
            : error.code === "FORBIDDEN"
              ? 403
              : error.code === "NOT_FOUND"
                ? 404
                : 400,
    );
  }
}
