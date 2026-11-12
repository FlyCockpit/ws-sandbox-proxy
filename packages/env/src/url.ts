import { z } from "zod";

/**
 * Like `originUrl`, but tolerates a path — for values that name a *service
 * endpoint* rather than a browser origin.
 *
 * `BACKUP_S3_ENDPOINT` is the case: a reverse-proxied MinIO or Ceph gateway
 * can legitimately live at `https://s3.example.com/minio`, which the AWS SDK
 * supports and `originUrl` would reject outright. What still has to be enforced
 * is a real http(s) scheme — a bare `z.url()` accepts `minio:9000`, which the
 * SDK cannot reach.
 *
 * No `.transform()` here: the path is meaningful to the SDK, so the value is
 * passed through exactly as configured.
 */
export function httpUrl(label: string) {
  return z
    .url()
    .refine(
      (value) => {
        const parsed = new URL(value);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
      },
      { message: `${label} must use http or https.` },
    )
    .refine(
      (value) => {
        const parsed = new URL(value);
        return !parsed.username && !parsed.password;
      },
      { message: `${label} must not include credentials.` },
    );
}

export function originUrl(label: string) {
  return z
    .url()
    .refine(
      (value) => {
        const parsed = new URL(value);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
      },
      { message: `${label} must use http or https.` },
    )
    .refine(
      (value) => {
        const parsed = new URL(value);
        return !parsed.username && !parsed.password;
      },
      { message: `${label} must not include credentials.` },
    )
    .refine(
      (value) => {
        const parsed = new URL(value);
        return parsed.pathname === "/" && !parsed.search && !parsed.hash;
      },
      { message: `${label} must be an origin only, with no path, query, or hash.` },
    )
    .transform((value) => new URL(value).origin);
}

/** Loopback hosts, where cleartext HTTP is acceptable for local development. */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

/**
 * `httpUrl` for endpoints that carry bearer material (presigned URLs, image
 * bytes): HTTPS, or HTTP only on an explicit loopback host (local dev and the
 * disposable `pnpm test:s3` harness).
 */
export function secureServiceUrl(label: string) {
  return httpUrl(label).refine(
    (value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" || isLoopbackHost(parsed.hostname);
    },
    { message: `${label} must use https (http only on a loopback host).` },
  );
}
