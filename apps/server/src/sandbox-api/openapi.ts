import { buildSdkOpenApiDocument } from "@wssp/sandbox-contracts";
import type { Handler } from "hono";
import type { SandboxApiEnv } from "./auth.js";

/**
 * Public static SDK spec. Built once from the same registry and schemas that
 * validate every `/v1` response; it never includes browser, admin or internal
 * oRPC procedures (those stay behind the admin-gated `/api-reference`).
 */
const document = buildSdkOpenApiDocument();

export const serveSdkOpenApiDocument: Handler<SandboxApiEnv> = (c) => c.json(document);
