import type { HttpBindings } from "@hono/node-server";
import { ORPCError } from "@orpc/server";
import { authenticateSdkKeySecret, type ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import type { MiddlewareHandler } from "hono";

export type SandboxApiEnv = {
  Bindings: Partial<HttpBindings>;
  Variables: { requestId: string; principal: ServicePrincipal };
};

// Normalize separators/casing for parameter names only. Query values never become credentials.
const credentialNames = new Set([
  "token",
  "key",
  "apikey",
  "accesstoken",
  "authorization",
  "auth",
  "bearer",
  "secret",
  "credential",
  "credentials",
  "sdkkey",
  "sdktoken",
  "hosttoken",
  "devicetoken",
  "clientsecret",
  "password",
  "refreshtoken",
  "idtoken",
]);

export const sdkAuthentication: MiddlewareHandler<SandboxApiEnv> = async (c, next) => {
  const query = new URL(c.req.url).searchParams;
  for (const [name, value] of query) {
    if (
      credentialNames.has(name.toLowerCase().replace(/[-_\s]/g, "")) ||
      /wssp_(?:sdk|host|device)_|^Bearer /i.test(value)
    ) {
      throw new ORPCError("BAD_REQUEST");
    }
  }
  // Fetch Headers merges duplicates, but Node may expose a single Authorization
  // value. Inspect the original header list as well as the merged syntax.
  const rawHeaders = c.env?.incoming?.rawHeaders;
  if (rawHeaders) {
    let count = 0;
    for (let i = 0; i < rawHeaders.length; i += 2) {
      if (rawHeaders[i]?.toLowerCase() === "authorization") count++;
    }
    if (count > 1) throw new ORPCError("UNAUTHORIZED");
  }
  const header = c.req.header("authorization");
  const match = header?.match(/^Bearer (wssp_sdk_[A-Za-z0-9_-]+)$/i);
  if (!match) throw new ORPCError("UNAUTHORIZED");
  const principal = await authenticateSdkKeySecret(match[1]!);
  if (!principal) throw new ORPCError("UNAUTHORIZED");
  c.set("principal", principal);
  await next();
};
