import {
  guestFilePathSchema,
  hostCommandBodySchema,
  hostCommandIdSchema,
  hostFileEditBodySchema,
  hostFileListBodySchema,
  hostFileReadBodySchema,
  hostFileWriteBodySchema,
  queueHostCommandBodySchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import type { ServiceAction, ServiceScope } from "../lib/service-scopes";
import {
  commandOutputInput,
  createSandboxInput,
  idempotencyKey,
  killSandboxInput,
  listDirInput,
  listSandboxesInput,
  readFileInput,
  runCommandInput,
  stopSandboxInput,
  writeStdinInput,
} from "../sandbox/contracts";

const id = z.string().min(1).max(128);
const key = { idempotencyKey: idempotencyKey.optional() };
/** Keep native refinements while allowing the MCP adapter to supply the retry key. */
function retryableInput<S extends z.ZodRawShape>(base: z.ZodObject<S>) {
  const { idempotencyKey: _key, ...shape } = base.shape;
  return z.object({ ...shape, ...key }).superRefine((value, ctx) => {
    const source = value as Record<string, unknown>;
    const native = Object.fromEntries(Object.keys(base.shape).map((key) => [key, source[key]]));
    const parsed = base.safeParse({
      ...native,
      idempotencyKey: native.idempotencyKey ?? "mcp-validation",
    });
    if (!parsed.success)
      for (const issue of parsed.error.issues)
        ctx.addIssue({ code: "custom", path: issue.path, message: issue.message });
  });
}
const host = { hostId: id };
const wait = z.number().int().min(0).max(60_000).default(60_000);
const poll = z.object({
  ...host,
  commandId: hostCommandIdSchema,
  stdoutOffset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).default(0),
  stderrOffset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).default(0),
  maxBytes: z.number().int().min(1).max(65_536).default(65_536),
  waitMs: wait,
});
function tool<N extends string, I extends z.ZodObject>(
  name: N,
  scopes: readonly ServiceScope[],
  actions: readonly ServiceAction[],
  input: I,
  mutating = false,
  description = name as string,
) {
  return { name, scopes, actions, input, mutating, description };
}
/** Closed inventory: credentials only; no router or session procedure dispatch. */
export const MCP_TOOLS = [
  tool("sandbox_list", ["sandboxes:read"], ["sandboxes.list"], listSandboxesInput),
  tool("sandbox_get", ["sandboxes:read"], ["sandboxes.get"], z.object({ id })),
  tool("sandbox_wait_ready", ["sandboxes:read"], ["sandboxes.get"], z.object({ id, waitMs: wait })),
  tool(
    "sandbox_create",
    ["sandboxes:create"],
    ["sandboxes.createIntent", "sandboxes.create", "sandboxes.replayCreate"],
    retryableInput(createSandboxInput),
    true,
  ),
  tool(
    "sandbox_stop",
    ["sandboxes:manage"],
    ["sandboxes.stop"],
    retryableInput(stopSandboxInput),
    true,
  ),
  tool(
    "sandbox_destroy",
    ["sandboxes:destroy"],
    ["sandboxes.kill"],
    retryableInput(killSandboxInput),
    true,
  ),
  tool(
    "command_run",
    ["commands:execute", "commands:read", "operations:read"],
    [
      "commands.run",
      "operations.get",
      "operations.getCommandOutput",
      "operations.getCommandResult",
    ],
    retryableInput(runCommandInput).safeExtend({ waitMs: wait }),
    true,
  ),
  tool(
    "command_start",
    ["commands:execute"],
    ["commands.run"],
    retryableInput(runCommandInput),
    true,
  ),
  tool(
    "command_output",
    ["commands:read", "operations:read"],
    ["operations.getCommandOutput"],
    commandOutputInput.extend({ waitMs: wait }),
  ),
  tool(
    "command_stdin",
    ["commands:execute"],
    ["commands.writeStdin"],
    retryableInput(writeStdinInput),
    true,
  ),
  tool(
    "command_cancel",
    ["operations:cancel", "commands:execute"],
    ["operations.cancel"],
    z.object({ operationId: id, ...key }),
    true,
  ),
  tool(
    "file_read",
    ["files:read"],
    ["files.read", "operations.get", "operations.downloadFile"],
    retryableInput(readFileInput).safeExtend({
      operationId: id.optional(),
      waitMs: wait,
      offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).default(0),
      maxBytes: z.number().int().min(1).max(262_144).default(65_536),
    }),
    true,
    "Capture a guest file; returns an operation receipt. Content retrieval needs operations:read.",
  ),
  tool(
    "file_list",
    ["files:read"],
    ["files.listDir", "operations.get", "operations.getFileResult"],
    retryableInput(listDirInput).safeExtend({ operationId: id.optional(), waitMs: wait }),
    true,
    "List a guest directory; returns an operation receipt.",
  ),
  tool(
    "file_write",
    ["files:write"],
    ["files.write"],
    z.object({
      id,
      path: guestFilePathSchema,
      content: z
        .string()
        .max(262_144)
        .refine((value) => new TextEncoder().encode(value).length <= 262_144),
      ...key,
    }),
    true,
  ),
  tool(
    "host_list",
    ["hosts:read"],
    ["hosts.list"],
    z.object({
      cursor: z.string().max(1024).optional(),
      limit: z.number().int().min(1).max(100).default(50),
    }),
    false,
    "List owned hosts only. Host commands run as an Incus admin and can reach other users' sandboxes; ownSandboxesOnly does not limit host access.",
  ),
  tool("host_get", ["hosts:read"], ["hosts.get"], z.object(host)),
  tool(
    "host_command_run",
    ["hosts:execute"],
    ["hostCommands.run"],
    hostCommandBodySchema.safeExtend({ ...host, ...key }),
    true,
  ),
  tool("host_command_get", ["hosts:execute"], ["hostCommands.get"], poll),
  tool(
    "host_command_cancel",
    ["hosts:execute"],
    ["hostCommands.cancel"],
    z.object({ ...host, commandId: hostCommandIdSchema, ...key }),
    true,
  ),
  tool(
    "host_command_queue",
    ["hosts:execute"],
    ["hostCommands.queue"],
    queueHostCommandBodySchema.extend({ ...host, ...key }),
    true,
    "Ask a person to run a command. This tool never runs or dismisses a queued command.",
  ),
  tool(
    "host_file_read",
    ["hosts:files"],
    ["hostFiles.read"],
    hostFileReadBodySchema.extend({ ...host, ...key }),
    true,
  ),
  tool(
    "host_file_list",
    ["hosts:files"],
    ["hostFiles.list"],
    hostFileListBodySchema.extend({ ...host, ...key }),
    true,
  ),
  tool(
    "host_file_write",
    ["hosts:files"],
    ["hostFiles.write"],
    hostFileWriteBodySchema.extend({ ...host, ...key }),
    true,
  ),
  tool(
    "host_file_edit",
    ["hosts:files"],
    ["hostFiles.edit"],
    hostFileEditBodySchema.extend({ ...host, ...key }),
    true,
  ),
] as const;
export type McpToolName = (typeof MCP_TOOLS)[number]["name"];
export function visibleMcpTools(scopes: ReadonlySet<string>) {
  return MCP_TOOLS.filter((tool) => tool.scopes.every((scope) => scopes.has(scope)));
}
