import { Hono } from "hono";
import type { SandboxApiEnv } from "./auth.js";
import { registerSdkReadRoutes } from "./reads.js";

// Every /v1 resource route comes from the @wssp/sandbox-contracts registry.
// Handlers call serviceProcedure-built services with c.var.principal; never
// fabricate a cookie session or call a browser router.
export function createSandboxApiRoutes() {
  const routes = new Hono<SandboxApiEnv>();
  registerSdkReadRoutes(routes);
  return routes;
}
