import type { MiddlewareHandler } from "hono";

/** Decode only for detection; preserve ordinary escaped paths in logs. */
function decodedSegment(segment: string): string {
  let decoded = segment;
  for (let layer = 0; layer < 3; layer++) {
    const next = decoded.replace(/%([0-9a-f]{2})/gi, (_match, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
    if (next === decoded) break;
    decoded = next;
  }
  return decoded;
}

const RESET_PASSWORD_PREFIX = /^\/api\/auth\/reset-password\//i;
const RESET_PASSWORD_PREFIX_LENGTH = "/api/auth/reset-password/".length;
const PRODUCT_CREDENTIAL = /wssp_(?:sdk|host|device)_/i;

/** Shared by access and error logs. Better Auth reset callbacks carry a path
 * token; verify-email, magic-link, invitation, OTP and device flows carry
 * secrets in query/body instead. Strip queries even when called with a URL path.
 */
export function requestLogPath(path: string): string {
  const segments = (path.split(/[?#]/, 1)[0] ?? "").split("/");
  const decoded = segments.map(decodedSegment);
  // The slash-collapsed decoded prefix only ever grows, so the reset-token
  // verdict is settled once it matches, or once it is as long as the pattern
  // without matching. Settling early keeps this linear in the path length.
  let prefix = "";
  let resetToken: boolean | undefined;
  return segments
    .map((segment, index) => {
      const part = decoded[index] ?? "";
      if (resetToken === undefined) {
        prefix = (index === 0 ? part : `${prefix}/${part}`).replace(/\/+/g, "/");
        if (RESET_PASSWORD_PREFIX.test(prefix)) resetToken = true;
        else if (prefix.length >= RESET_PASSWORD_PREFIX_LENGTH) resetToken = false;
      }
      return resetToken || PRODUCT_CREDENTIAL.test(part) ? "[redacted]" : segment;
    })
    .join("/");
}

export function requestLogMethod(method: string): string {
  return ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)
    ? method
    : "OTHER";
}

/** Log path only — never query strings or product credential path segments. */
export function createPathOnlyRequestLogger(
  log: (message: string, ...rest: string[]) => void,
): MiddlewareHandler {
  return async (c, next) => {
    const start = Date.now();
    const method = requestLogMethod(c.req.method);
    const path = requestLogPath(c.req.path);
    log(`<-- ${method} ${path}`);
    await next();
    log(`--> ${method} ${path} ${c.res.status} ${Date.now() - start}ms`);
  };
}
