import { env } from "@wssp/env/server";
import type { Context } from "hono";

const allowedOrigins = new Set(
  [env.BETTER_AUTH_URL, env.CORS_ORIGIN]
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .map((value) => new URL(value).origin),
);

/** Exact-match browser Origin allowlist (the configured public app origins). */
export function isAllowedBrowserOrigin(origin: string | undefined): boolean {
  return !!origin && allowedOrigins.has(origin);
}

export function validateSameSiteJsonRequest(
  c: Context,
  { allowTrustedCrossSite = false }: { allowTrustedCrossSite?: boolean } = {},
): Response | null {
  const contentType = c.req.header("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return c.json({ error: "Request must be JSON." }, 415);
  }

  const origin = c.req.header("origin");
  const trustedOrigin = !!origin && allowedOrigins.has(origin);
  const secFetchSite = c.req.header("sec-fetch-site")?.toLowerCase();
  if (
    secFetchSite &&
    !["same-origin", "same-site", "none"].includes(secFetchSite) &&
    !(secFetchSite === "cross-site" && allowTrustedCrossSite && trustedOrigin)
  ) {
    return c.json({ error: "Cross-site requests are not allowed." }, 403);
  }

  if (origin && !allowedOrigins.has(origin)) {
    return c.json({ error: "Cross-site requests are not allowed." }, 403);
  }

  return null;
}
