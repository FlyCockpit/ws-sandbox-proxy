import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { MCP_TOOLS, type McpToolName } from "@wssp/api/mcp/tool-contracts";
import {
  createSandboxInput,
  killSandboxInput,
  listDirInput,
  readFileInput,
  runCommandInput,
  stopSandboxInput,
  writeStdinInput,
} from "@wssp/api/sandbox/contracts";
import { getOperationResult } from "@wssp/api/sandbox/operation-results";
import { withOperationWait } from "@wssp/api/sandbox/operation-waiters";
import {
  cancelOperationReceipt,
  mutationOperationReceipt,
  writeStdinReceipt,
} from "@wssp/api/sandbox/sdk-mutations";
import {
  sdkGetOperation,
  sdkGetSandbox,
  sdkListHosts,
  sdkListSandboxes,
  toHostDto,
} from "@wssp/api/sandbox/sdk-reads";
import {
  cancelHostCommand,
  getHostCommand,
  runHostCommand,
} from "@wssp/api/sandbox/services/host-commands";
import {
  editHostFile,
  listHostDir,
  readHostFile,
  writeHostFile,
} from "@wssp/api/sandbox/services/host-files";
import { queueHostCommand } from "@wssp/api/sandbox/services/host-queued";
import { getHost } from "@wssp/api/sandbox/services/hosts";
import {
  createSandbox,
  getCommandOutput,
  killSandbox,
  listDir,
  readFile,
  runCommand,
  stopSandbox,
} from "@wssp/api/sandbox/services/sandboxes";
import { operationOutcome } from "@wssp/sandbox-contracts";
import type { z } from "zod";
import { admitted } from "../sandbox-transfers/http-admission.js";
import { transferStore } from "../sandbox-transfers/runtime.js";

type Input<N extends McpToolName> = z.output<
  Extract<(typeof MCP_TOOLS)[number], { name: N }>["input"]
>;
function parse<N extends McpToolName>(name: N, raw: unknown): Input<N> {
  const tool = MCP_TOOLS.find((tool) => tool.name === name)!;
  const result = tool.input.safeParse(raw);
  if (!result.success) throw new ORPCError("BAD_REQUEST");
  return result.data as Input<N>;
}
async function pause(signal?: AbortSignal) {
  await delay(250, undefined, { signal });
}
async function output(
  p: ServicePrincipal,
  input: { operationId: string; cursor?: string; maxBytes?: number; waitMs: number },
  signal?: AbortSignal,
) {
  return withOperationWait({
    ownerId: p.ownerId,
    operationId: input.operationId,
    waitMs: input.waitMs,
    signal,
    read: () => getCommandOutput(p, input),
    ready: (page) =>
      page.complete || page.hasMore || operationOutcome(page.state) !== "pending"
        ? true
        : page.chunks.length || page.gaps.length || page.reset
          ? "progress"
          : false,
  });
}
async function waitOperation(
  p: ServicePrincipal,
  operationId: string,
  waitMs: number,
  signal?: AbortSignal,
) {
  return withOperationWait({
    ownerId: p.ownerId,
    operationId,
    waitMs,
    signal,
    read: () => sdkGetOperation(p, operationId),
    ready: (operation) => operationOutcome(operation.state) !== "pending",
  });
}
/** All branches call the same credential services as native HTTP; never a session router. */
export async function dispatchMcpTool(
  p: ServicePrincipal,
  name: McpToolName,
  raw: unknown,
  signal?: AbortSignal,
): Promise<unknown> {
  if (signal?.aborted) throw new ORPCError("BAD_REQUEST");
  switch (name) {
    case "sandbox_list": {
      const i = parse(name, raw);
      return sdkListSandboxes(p, i);
    }
    case "sandbox_get":
      return sdkGetSandbox(p, parse(name, raw).id);
    case "sandbox_wait_ready": {
      const i = parse(name, raw),
        end = Date.now() + i.waitMs;
      for (;;) {
        const sandbox = await sdkGetSandbox(p, i.id);
        if (
          !["REQUESTED", "SCHEDULED", "PROVISIONING", "WAITING_FOR_CAPACITY"].includes(
            sandbox.state,
          ) ||
          Date.now() >= end ||
          signal?.aborted
        )
          return sandbox;
        await pause(signal);
      }
    }
    case "sandbox_create": {
      const i = parse(name, raw);
      await createSandbox(p, createSandboxInput.parse(i));
      return mutationOperationReceipt(p, i.idempotencyKey!, "sandboxes.create");
    }
    case "sandbox_stop":
      return stopSandbox(p, stopSandboxInput.parse(parse(name, raw)));
    case "sandbox_destroy": {
      const i = parse(name, raw);
      await killSandbox(p, killSandboxInput.parse(i));
      return mutationOperationReceipt(p, i.idempotencyKey!, "sandboxes.kill", { sandboxId: i.id });
    }
    case "command_start":
      return runCommand(p, runCommandInput.parse(parse(name, raw)));
    case "command_run": {
      const { waitMs, ...i } = parse(name, raw);
      const receipt = await runCommand(p, runCommandInput.parse(i));
      const end = Date.now() + waitMs;
      const pages: unknown[] = [];
      let cursor: string | undefined;
      let bytes = 0;
      for (;;) {
        const page = await output(
          p,
          {
            operationId: receipt.operationId,
            cursor,
            maxBytes: 65_536,
            waitMs: Math.max(0, end - Date.now()),
          },
          signal,
        );
        pages.push(page);
        bytes += Buffer.byteLength(JSON.stringify(page));
        cursor = page.nextCursor ?? undefined;
        if (page.complete) {
          const result = await getOperationResult(p, { operationId: receipt.operationId });
          return { ...receipt, output: pages, result, complete: true };
        }
        if (Date.now() >= end || bytes >= 1_048_576 || signal?.aborted)
          return {
            ...receipt,
            output: pages,
            cursor,
            complete: false,
            truncated: bytes >= 1_048_576,
          };
        if (!page.hasMore) await pause(signal);
      }
    }
    case "command_output":
      return output(p, parse(name, raw), signal);
    case "command_stdin": {
      const { idempotencyKey, ...i } = parse(name, raw);
      return writeStdinReceipt(p, { ...writeStdinInput.parse(i), idempotencyKey: idempotencyKey! });
    }
    case "command_cancel": {
      const i = parse(name, raw);
      return cancelOperationReceipt(p, { ...i, idempotencyKey: i.idempotencyKey! });
    }
    case "file_read": {
      const { operationId, waitMs, offset, maxBytes, ...i } = parse(name, raw);
      const receipt = operationId ? { operationId } : await readFile(p, readFileInput.parse(i));
      if (!p.scopes.has("operations:read")) return receipt;
      const operation = await waitOperation(p, receipt.operationId, waitMs, signal);
      if (operation.state !== "SUCCEEDED") return { ...receipt, operation };
      return admitted(p, async () => {
        const source = await transferStore().downloadSource(p, receipt.operationId);
        try {
          const bytes = await source.read(
            offset,
            Math.max(0, Math.min(maxBytes, source.size - offset)),
          );
          source.delivered(offset, bytes.length);
          return {
            ...receipt,
            contentBase64: Buffer.from(bytes).toString("base64"),
            offset,
            size: source.size,
            truncated: offset + bytes.length < source.size,
          };
        } finally {
          source.close();
        }
      });
    }
    case "file_list": {
      const { operationId, waitMs, ...i } = parse(name, raw);
      const receipt = operationId ? { operationId } : await listDir(p, listDirInput.parse(i));
      if (!p.scopes.has("operations:read")) return receipt;
      const operation = await waitOperation(p, receipt.operationId, waitMs, signal);
      return operation.state === "SUCCEEDED"
        ? getOperationResult(p, { operationId: receipt.operationId })
        : { ...receipt, operation };
    }
    case "file_write": {
      const i = parse(name, raw),
        bytes = Buffer.from(i.content, "utf8");
      return admitted(p, async () => {
        const store = transferStore();
        const transfer = await store.create(p, {
          sandboxId: i.id,
          direction: "UPLOAD",
          guestPath: i.path,
          totalBytes: bytes.length,
          idempotencyKey: i.idempotencyKey!,
        });
        if (bytes.length && transfer.receivedBytes < bytes.length)
          await store.write(p, transfer.id, 0, bytes);
        return store.commit(
          p,
          transfer.id,
          `mcp:${createHash("sha256").update(`mcp-file-write-commit\0${i.idempotencyKey}`).digest("hex")}`,
          createHash("sha256").update(bytes).digest("hex"),
        );
      });
    }
    case "host_list": {
      const page = await sdkListHosts(p, parse(name, raw));
      return { ...page, items: page.items.filter((host) => host.agentAccess.owned) };
    }
    case "host_get":
      return toHostDto(await getHost(p, { id: parse(name, raw).hostId }));
    case "host_command_run":
      return runHostCommand(p, parse(name, raw));
    case "host_command_get":
      return getHostCommand(p, parse(name, raw));
    case "host_command_cancel":
      return cancelHostCommand(p, parse(name, raw));
    case "host_command_queue":
      return queueHostCommand(p, parse(name, raw));
    case "host_file_read":
      return readHostFile(p, parse(name, raw));
    case "host_file_list":
      return listHostDir(p, parse(name, raw));
    case "host_file_write":
      return writeHostFile(p, parse(name, raw));
    case "host_file_edit":
      return editHostFile(p, parse(name, raw));
  }
}
