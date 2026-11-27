import {
  createMcpHandler,
  type McpHandlerRequestOptions,
  type McpHttpHandler,
  McpServer,
} from "@modelcontextprotocol/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { registerMcpTools } from "./tools.js";

export const MCP_TRANSPORT_OPTIONS = {
  legacy: "stateless",
  responseMode: "json",
  maxSubscriptions: 0,
  maxRequestBodySize: 1_048_576,
  keepAliveMs: 15_000,
} as const;

const JSON_BATCH_ERROR = {
  jsonrpc: "2.0",
  id: null,
  error: { code: -32600, message: "Invalid Request: JSON-RPC batching is not supported" },
} as const;

function isJsonContentType(value: string | null): boolean {
  return (value ?? "").toLowerCase().split(";")[0]?.trim() === "application/json";
}

async function readBoundedBody(
  request: Request,
  maxBytes: number,
): Promise<
  { kind: "ok"; bytes: Uint8Array<ArrayBuffer> } | { kind: "too-large" } | { kind: "aborted" }
> {
  if (request.signal.aborted) return { kind: "aborted" };
  if (request.body === null) return { kind: "ok", bytes: new Uint8Array(0) };
  const reader = request.body.getReader();
  const onAbort = () => {
    void reader.cancel().catch(() => {});
  };
  request.signal.addEventListener("abort", onAbort, { once: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      if (request.signal.aborted) {
        void reader.cancel().catch(() => {});
        return { kind: "aborted" };
      }
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.byteLength;
      if (total > maxBytes) {
        void reader.cancel().catch(() => {});
        return { kind: "too-large" };
      }
      chunks.push(chunk.value);
    }
  } finally {
    request.signal.removeEventListener("abort", onAbort);
    try {
      reader.releaseLock();
    } catch {
      // Already released.
    }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { kind: "ok", bytes };
}

export function createMcpTransport(options?: { keepAliveMs?: number }): McpHttpHandler {
  const handler = createMcpHandler(
    (ctx) => {
      const principal = ctx.authInfo?.extra?.principal as ServicePrincipal | undefined;
      if (!principal || principal.credentialKind === "API" || ctx.requestInfo?.signal?.aborted)
        throw new Error("MCP principal unavailable");
      const server = new McpServer(
        { name: "wssp", version: "1.0.0" },
        { capabilities: { tools: { listChanged: false } } },
      );
      registerMcpTools(server, principal, ctx.requestInfo?.signal);
      return server;
    },
    {
      ...MCP_TRANSPORT_OPTIONS,
      ...(options?.keepAliveMs !== undefined ? { keepAliveMs: options.keepAliveMs } : {}),
      onerror: () => console.error("[mcp] transport failed"),
    },
  );

  const fetch = async (
    request: Request,
    requestOptions?: McpHandlerRequestOptions,
  ): Promise<Response> => {
    if (request.method.toUpperCase() !== "POST") return handler.fetch(request, requestOptions);
    if (requestOptions?.parsedBody !== undefined) {
      if (Array.isArray(requestOptions.parsedBody))
        return Response.json(JSON_BATCH_ERROR, { status: 400 });
      return handler.fetch(request, requestOptions);
    }
    if (!isJsonContentType(request.headers.get("content-type")))
      return handler.fetch(request, requestOptions);
    let bodyRead: Awaited<ReturnType<typeof readBoundedBody>>;
    try {
      bodyRead = await readBoundedBody(request, MCP_TRANSPORT_OPTIONS.maxRequestBodySize);
    } catch {
      return request.signal.aborted
        ? new Response(null, { status: 499 })
        : Response.json(
            { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
            { status: 400 },
          );
    }
    if (bodyRead.kind === "aborted") return new Response(null, { status: 499 });
    if (bodyRead.kind === "too-large")
      return Response.json(
        {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32000, message: "Request body too large" },
        },
        { status: 413 },
      );
    if (bodyRead.bytes.byteLength > 0) {
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bodyRead.bytes);
      } catch {
        return Response.json(
          {
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: "Parse error: Invalid UTF-8" },
          },
          { status: 400 },
        );
      }
      try {
        const parsed: unknown = JSON.parse(text);
        if (Array.isArray(parsed)) return Response.json(JSON_BATCH_ERROR, { status: 400 });
        return handler.fetch(request, { ...requestOptions, parsedBody: parsed });
      } catch {
        // Fall through with valid UTF-8 so the SDK answers invalid JSON consistently.
      }
    }
    const rebuilt = new Request(request.url, {
      method: request.method,
      headers: request.headers,
      signal: request.signal,
      body: bodyRead.bytes,
    });
    return handler.fetch(rebuilt, requestOptions);
  };

  return { ...handler, fetch };
}
