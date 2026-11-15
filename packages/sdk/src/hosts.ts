import {
  type HostCommandInput,
  type HostCommandStatus,
  type hostCommandQuerySchema,
  type hostCommandStdinBodySchema,
  type hostFileEditBodySchema,
  type hostFileListBodySchema,
  type hostFileReadBodySchema,
  type hostFileWriteBodySchema,
  type queueHostCommandBodySchema,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";
import { WsspError } from "./errors";
import {
  type PollingOptions,
  poll,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
} from "./polling";
import { generateKey, type MutationOptions } from "./sandboxes";
import type { RouteResponse, WsspTransport } from "./transport";

export type HostCommandQuery = z.output<typeof hostCommandQuerySchema>;
export type HostCommandStdinInput = z.input<typeof hostCommandStdinBodySchema>;
export type QueueHostCommandInput = z.input<typeof queueHostCommandBodySchema>;
export type HostFileReadInput = z.input<typeof hostFileReadBodySchema>;
export type HostFileListInput = z.input<typeof hostFileListBodySchema>;
export type HostFileWriteInput = z.input<typeof hostFileWriteBodySchema>;
export type HostFileEditInput = z.input<typeof hostFileEditBodySchema>;
export type HostCommandRunResult = HostCommandStatus & {
  /** Masked UTF-8 output, retaining the last 1 MiB per stream. */
  stdoutText: string;
  stderrText: string;
  /** True when the daemon or this helper discarded any output. */
  truncated: boolean;
};
export type HostCommandsApi = {
  start(
    hostId: string,
    input: HostCommandInput,
    options?: MutationOptions,
  ): Promise<HostCommandStatus>;
  get(
    hostId: string,
    commandId: string,
    query?: HostCommandQuery,
    options?: WaitOptions,
  ): Promise<HostCommandStatus>;
  writeStdin(
    hostId: string,
    commandId: string,
    input: HostCommandStdinInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"writeHostCommandStdin">>;
  cancel(hostId: string, commandId: string, options?: MutationOptions): Promise<HostCommandStatus>;
  /** Start once, then poll until terminal and drain the remaining output. Timeout/abort detaches. */
  run(
    hostId: string,
    input: HostCommandInput,
    options?: MutationOptions,
  ): Promise<HostCommandRunResult>;
};
export type HostFilesApi = {
  read(
    hostId: string,
    input: HostFileReadInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"readHostFile">>;
  list(
    hostId: string,
    input: HostFileListInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"listHostFiles">>;
  write(
    hostId: string,
    input: HostFileWriteInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"writeHostFile">>;
  edit(
    hostId: string,
    input: HostFileEditInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"editHostFile">>;
};
export type HostsApi = {
  list(
    query?: { limit?: number; cursor?: string },
    options?: WaitOptions,
  ): Promise<RouteResponse<"listHosts">>;
  get(hostId: string, options?: WaitOptions): Promise<RouteResponse<"getHost">>;
  readonly commands: HostCommandsApi;
  queueCommand(
    hostId: string,
    input: QueueHostCommandInput,
    options?: MutationOptions,
  ): Promise<RouteResponse<"queueHostCommand">>;
  getQueuedCommand(
    hostId: string,
    id: string,
    options?: WaitOptions,
  ): Promise<RouteResponse<"getQueuedHostCommand">>;
  readonly files: HostFilesApi;
};
function requestOptions(options?: WaitOptions, holdMs = 0) {
  const timeout = waitTimeout(options);
  return {
    signal: options?.signal,
    timeoutMs: timeout ?? (holdMs > 0 ? holdMs + 10_000 : undefined),
  };
}
function mutationOptions(options?: MutationOptions, holdMs = 0) {
  return {
    ...requestOptions(options, holdMs),
    idempotencyKey: options?.idempotencyKey ?? generateKey(),
  };
}
function queryWire(input: HostCommandQuery = {}) {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue;
    if (typeof value !== "number" || !Number.isSafeInteger(value))
      throw new WsspError({ kind: "invalid_request", message: "Invalid host command query." });
    out[key] = String(value);
  }
  return out;
}

/** Command/file methods require an owned, granted host; direct execution also needs node opt-in. */
export function createHostsApi(transport: WsspTransport, defaults?: PollingOptions): HostsApi {
  const commands: HostCommandsApi = {
    start: (hostId, body, options) =>
      transport.request("startHostCommand", {
        params: { hostId },
        body,
        ...mutationOptions(options, body.waitMs),
      }),
    get: (hostId, commandId, query, options) =>
      transport.request("getHostCommand", {
        params: { hostId, commandId },
        query: queryWire(query),
        ...requestOptions(options, query?.waitMs),
      }),
    writeStdin: (hostId, commandId, body, options) =>
      transport.request("writeHostCommandStdin", {
        params: { hostId, commandId },
        body,
        ...mutationOptions(options),
      }),
    cancel: (hostId, commandId, options) =>
      transport.request("cancelHostCommand", {
        params: { hostId, commandId },
        body: {},
        ...mutationOptions(options),
      }),
    async run(hostId, input, options) {
      const polling = resolvePolling(defaults, options);
      const key = options?.idempotencyKey ?? generateKey();
      const started = Date.now();
      let status = await commands.start(hostId, input, {
        ...options,
        idempotencyKey: key,
        waitTimeoutMs: polling.timeoutMs,
      });
      const commandId = status.commandId;
      const output = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      const offsets = { stdout: 0, stderr: 0 };
      let truncated = false;
      const consume = () => {
        if (status.commandId !== commandId)
          throw new WsspError({
            kind: "protocol",
            reason: "invalid_response",
            message: "Host command identity changed.",
            idempotencyKey: key,
          });
        let progress = false;
        for (const stream of ["stdout", "stderr"] as const) {
          const chunk = status[stream];
          const data = Buffer.from(chunk.data, "base64");
          if (
            chunk.offset < offsets[stream] ||
            (chunk.offset > offsets[stream] && !chunk.dropped) ||
            chunk.offset + data.length > status[`${stream}Bytes`]
          )
            throw new WsspError({
              kind: "protocol",
              reason: "invalid_response",
              message: "Invalid host output offsets.",
              idempotencyKey: key,
            });
          progress ||= data.length > 0 || chunk.offset > offsets[stream];
          truncated ||= chunk.dropped;
          offsets[stream] = chunk.offset + data.length;
          const combined = Buffer.concat([output[stream], data]);
          truncated ||= combined.length > 1_048_576;
          output[stream] = combined.subarray(Math.max(0, combined.length - 1_048_576));
        }
        const complete =
          status.state !== "running" &&
          offsets.stdout >= status.stdoutBytes &&
          offsets.stderr >= status.stderrBytes;
        return { complete, progress };
      };
      const first = consume();
      if (!first.complete) {
        const remaining = polling.timeoutMs - (Date.now() - started);
        if (remaining <= 0)
          throw new WsspError({
            kind: "timeout",
            reason: "timeout",
            message: "Host command wait expired.",
            idempotencyKey: key,
          });
        await poll(
          async (signal, attempt) => {
            const waitMs = Math.max(
              0,
              Math.min(polling.longPollMs, 60_000, attempt.remainingMs - 1_000),
            );
            status = await commands.get(
              hostId,
              commandId,
              {
                stdoutOffset: offsets.stdout,
                stderrOffset: offsets.stderr,
                maxBytes: 65_536,
                waitMs,
              },
              { signal, waitTimeoutMs: Math.min(attempt.remainingMs, waitMs + 10_000) },
            );
            const next = consume();
            if (next.complete) return { done: true, value: undefined };
            if (status.state !== "running" && !next.progress)
              throw new WsspError({
                kind: "protocol",
                reason: "invalid_response",
                message: "Terminal host output did not advance.",
                idempotencyKey: key,
              });
            return { done: false };
          },
          { ...polling, timeoutMs: remaining },
          options?.signal,
          { label: "host command", idempotencyKey: key },
        );
      }
      return {
        ...status,
        stdoutText: output.stdout.toString("utf8"),
        stderrText: output.stderr.toString("utf8"),
        truncated,
      };
    },
  };
  return {
    list: (query, options) => {
      if (
        query?.limit !== undefined &&
        (!Number.isSafeInteger(query.limit) || query.limit < 1 || query.limit > 100)
      )
        throw new WsspError({ kind: "invalid_request", message: "Invalid host page limit." });
      return transport.request("listHosts", {
        query: { ...query, limit: query?.limit?.toString() },
        ...requestOptions(options),
      });
    },
    get: (hostId, options) =>
      transport.request("getHost", { params: { hostId }, ...requestOptions(options) }),
    commands,
    queueCommand: (hostId, body, options) =>
      transport.request("queueHostCommand", {
        params: { hostId },
        body,
        ...mutationOptions(options),
      }),
    getQueuedCommand: (hostId, id, options) =>
      transport.request("getQueuedHostCommand", {
        params: { hostId, id },
        ...requestOptions(options),
      }),
    files: {
      read: (hostId, body, options) =>
        transport.request("readHostFile", {
          params: { hostId },
          body,
          ...mutationOptions(options),
        }),
      list: (hostId, body, options) =>
        transport.request("listHostFiles", {
          params: { hostId },
          body,
          ...mutationOptions(options),
        }),
      write: (hostId, body, options) =>
        transport.request("writeHostFile", {
          params: { hostId },
          body,
          ...mutationOptions(options),
        }),
      edit: (hostId, body, options) =>
        transport.request("editHostFile", {
          params: { hostId },
          body,
          ...mutationOptions(options),
        }),
    },
  };
}
