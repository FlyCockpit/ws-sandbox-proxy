import { randomUUID } from "node:crypto";
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { type McpToolName, visibleMcpTools } from "@wssp/api/mcp/tool-contracts";
import { idempotencyKey as keySchema } from "@wssp/api/sandbox/contracts";
import { consumeMcpCreateQuota, consumeMcpHostCommandQuota } from "../mcp-rate-limit.js";
import { mcpError } from "./errors.js";
import { dispatchMcpTool } from "./tool-dispatch.js";

export async function callMcpTool(
  principal: ServicePrincipal,
  name: string,
  raw: unknown,
  options: {
    signal?: AbortSignal;
    dispatch?: typeof dispatchMcpTool;
    createQuota?: (key: string) => Promise<void>;
    hostCommandQuota?: (key: string) => Promise<void>;
  } = {},
) {
  const tool = visibleMcpTools(principal.scopes).find((tool) => tool.name === name);
  // Hidden and nonexistent tools deliberately share exactly the same result.
  if (!tool)
    return { content: [{ type: "text" as const, text: `Tool ${name} not found` }], isError: true };
  let idempotencyKey: string | undefined;
  try {
    let input = raw;
    if (tool.mutating) {
      const body =
        typeof raw === "object" && raw !== null && !Array.isArray(raw)
          ? (raw as Record<string, unknown>)
          : {};
      const checkedKey = keySchema.safeParse(body.idempotencyKey ?? randomUUID());
      if (!checkedKey.success) throw new ORPCError("BAD_REQUEST");
      idempotencyKey = checkedKey.data;
      input = { ...body, idempotencyKey };
    }
    const parsed = tool.input.safeParse(input);
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    if (name === "sandbox_create")
      await (options.createQuota ?? consumeMcpCreateQuota)(principal.keyId);
    if (name === "host_command_run")
      await (options.hostCommandQuota ?? consumeMcpHostCommandQuota)(principal.keyId);
    const result = await (options.dispatch ?? dispatchMcpTool)(
      principal,
      tool.name as McpToolName,
      parsed.data,
      options.signal,
    );
    const structuredContent = { result, ...(idempotencyKey ? { idempotencyKey } : {}) };
    return {
      content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }],
      structuredContent,
    };
  } catch (error) {
    return mcpError(error, idempotencyKey);
  }
}
export function registerMcpTools(
  server: McpServer,
  principal: ServicePrincipal,
  signal?: AbortSignal,
) {
  for (const tool of visibleMcpTools(principal.scopes)) {
    server.registerTool<StandardSchemaWithJSON, StandardSchemaWithJSON>(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.input,
        annotations: {
          readOnlyHint: !tool.mutating,
          destructiveHint:
            tool.mutating &&
            ![
              "sandbox_create",
              "file_read",
              "file_list",
              "host_command_queue",
              "host_file_read",
              "host_file_list",
            ].includes(tool.name),
          // With no caller-supplied key, repeating identical arguments creates a new key.
          idempotentHint: !tool.mutating,
        },
      },
      async (input) => callMcpTool(principal, tool.name, input, { signal }),
    );
  }
}
