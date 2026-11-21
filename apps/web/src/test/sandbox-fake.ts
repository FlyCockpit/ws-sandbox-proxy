import { skipToken } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import {
  createSandboxInput,
  FS_PROCESS_LIMITS,
  OPERATION_KINDS,
  OPERATION_STATES,
  type ProcessRef,
  VM_SIZE_LIMITS,
} from "@wssp/api/sandbox/contracts";
import {
  commandOutputPageSchema,
  enabledSdkFeatures,
  guestApiCapabilities,
  type OperationErrorCode,
  type OperationFailure,
  OUTPUT_PAGE_MAX_BYTES,
  operationResultSchema,
  processConnectionSchema,
  processSignalSchema,
  sandboxCapabilitiesSchema,
  vmSizeOverridesSchema,
} from "../../../../packages/sandbox-contracts/src/index";

type ProcedureOutput<K extends keyof AppRouterClient["sandboxes"]> = Awaited<
  ReturnType<AppRouterClient["sandboxes"][K]>
>;

/**
 * A scripted in-memory stand-in for the oRPC procedures the Sandboxes pages
 * use (C47 DOM tests). It records every call, replays a mutation retried
 * with the same idempotency key and body (and refuses a changed body, as the
 * server does), and lets a test move sandboxes between states the way the
 * host would, then refetch. Nothing here decides what the page shows.
 */

type Row = Record<string, unknown>;

export type FakeSandboxServer = {
  sandboxes: Row[];
  hosts: Row[];
  pools?: Row[];
  templates: Row[];
  observationResults?: Row[];
  connections?: Row[];
  /** `sandboxes.listConnectSessions` rows (wssp-ssh §10), each with its `sandboxId`. */
  connectSessions?: Row[];
  supportedSignals?: ("SIGKILL" | "SIGTERM" | "SIGINT" | "SIGHUP")[];
  capabilitiesUnavailable?: boolean;
  pickerPageSize?: number;
  maxTimeoutMs?: number;
  operations: Row[];
  calls: { procedure: string; input: unknown }[];
  /** Errors thrown (once each, in order) by the next calls of a procedure. */
  errors: Record<string, unknown[]>;
  /** The next N calls of a procedure are applied, then their response is lost. */
  lostResponses: Record<string, number>;
  /** When set, the procedure waits for this promise before answering. */
  gates: Record<string, Promise<void> | undefined>;
  receipts: Map<string, { body: string; result: unknown }>;
  seq: number;
  /** Stored command output per operation ID (C48), paged like the server. */
  outputs: Map<string, FakeOutput>;
  /** Output reads aborted by the caller (navigation or stall timeout). */
  aborted: number;
};

/**
 * One command's stored output as the server would page it: chunks and gaps
 * at aggregate byte offsets for one dispatch attempt. `pageLimit` caps the
 * items one page returns (the server's 64 KiB / 1024-item page bound).
 */
export type FakeOutput = {
  attempt: number;
  chunks: { stream: "stdout" | "stderr"; offset: number; bytes: Uint8Array }[];
  gaps: { start: number; end: number }[];
  complete: boolean;
  truncated?: boolean;
  totalBytes?: number | null;
  expired?: boolean;
  pageLimit?: number;
  expiresAt?: Date | null;
};

export function textBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Append a chunk at the current end of the stored output. */
export function appendOutput(
  output: FakeOutput,
  stream: "stdout" | "stderr",
  data: string | Uint8Array,
) {
  const bytes = typeof data === "string" ? textBytes(data) : data;
  const end = Math.max(
    0,
    ...output.chunks.map((chunk) => chunk.offset + chunk.bytes.length),
    ...output.gaps.map((gap) => gap.end),
  );
  output.chunks.push({ stream, offset: end, bytes });
}

export const OUTPUT_EXPIRED = () =>
  Object.assign(new Error("Command output has expired"), {
    code: "GONE",
    status: 410,
    data: { code: "OUTPUT_EXPIRED" },
  });

function outputPage(
  operationId: string,
  operation: Row,
  output: FakeOutput,
  cursor: string | undefined,
  maxBytes = OUTPUT_PAGE_MAX_BYTES,
) {
  const parsed = cursor ? /^(\d+)_(\d+)$/.exec(cursor) : null;
  const reset = parsed != null && Number(parsed[1]) !== output.attempt;
  const from = parsed && !reset ? Number(parsed[2]) : 0;
  const items = [
    ...output.chunks
      .filter((chunk) => chunk.offset + chunk.bytes.length > from)
      .map((chunk) => ({ at: chunk.offset, chunk })),
    ...output.gaps.filter((gap) => gap.end > from).map((gap) => ({ at: gap.start, gap })),
  ].sort((a, b) => a.at - b.at);
  const limit = output.pageLimit ?? 1024;
  const taken = items.slice(0, limit);
  let remaining = Math.min(maxBytes, OUTPUT_PAGE_MAX_BYTES);
  let position = from;
  const chunks: { stream: string; offset: number; data: string }[] = [];
  const gaps: { start: number; end: number }[] = [];
  for (const item of taken) {
    if ("chunk" in item && item.chunk) {
      const start = Math.max(item.chunk.offset, from);
      const bytes = item.chunk.bytes.subarray(
        start - item.chunk.offset,
        start - item.chunk.offset + remaining,
      );
      if (bytes.length === 0) break;
      remaining -= bytes.length;
      chunks.push({
        stream: item.chunk.stream,
        offset: start,
        data: Buffer.from(bytes).toString("base64"),
      });
      position = start + bytes.length;
      if (position < item.chunk.offset + item.chunk.bytes.length) break;
    } else if ("gap" in item && item.gap) {
      gaps.push({ start: Math.max(item.gap.start, from), end: item.gap.end });
      position = item.gap.end;
    }
  }
  const received = Math.max(
    0,
    ...output.chunks.map((chunk) => chunk.offset + chunk.bytes.length),
    ...output.gaps.map((gap) => gap.end),
  );
  return commandOutputPageSchema.parse({
    operationId,
    state: String(operation.state),
    exitCode: operation.exitCode ?? null,
    attempt: output.attempt,
    reset,
    offset: from,
    chunks,
    gaps,
    nextCursor: `${output.attempt}_${position}`,
    hasMore: position < received,
    receivedBytes: received,
    totalBytes: output.complete ? (output.totalBytes ?? received) : null,
    retainedBytes: output.chunks.reduce((sum, chunk) => sum + chunk.bytes.length, 0),
    truncated: output.truncated ?? output.gaps.length > 0,
    complete: output.complete,
    expiresAt: output.expiresAt?.toISOString() ?? null,
  });
}

export function newFakeSandboxServer(): FakeSandboxServer {
  return {
    sandboxes: [],
    hosts: [],
    templates: [],
    operations: [],
    calls: [],
    errors: {},
    lostResponses: {},
    gates: {},
    receipts: new Map(),
    seq: 0,
    outputs: new Map(),
    aborted: 0,
  };
}

export function coded(code: string, orpcCode = "CONFLICT") {
  const statuses: Record<string, number> = {
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    GONE: 410,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
  };
  return Object.assign(new Error(code), {
    code: orpcCode,
    status: statuses[orpcCode] ?? 500,
    data: { code },
  });
}

export const NOT_FOUND = () =>
  Object.assign(new Error("not found"), { code: "NOT_FOUND", status: 404 });

function clone<T>(value: T): T {
  return structuredClone(value);
}

type InfiniteOptions = {
  input: (cursor: string | undefined) => Record<string, unknown>;
  initialPageParam: unknown;
  getNextPageParam: (page: { nextCursor: string | null }) => unknown;
};

export function fakeSandboxOrpc(server: FakeSandboxServer) {
  const record = (procedure: string, input: unknown) =>
    server.calls.push({ procedure, input: clone(input) });
  const failNext = (procedure: string) => {
    const error = server.errors[procedure]?.shift();
    if (error) throw error;
  };
  const call =
    <I, O>(procedure: string, handler: (input: I) => O) =>
    async (input: I): Promise<O> => {
      record(procedure, input);
      const gate = server.gates[procedure];
      if (gate) await gate;
      failNext(procedure);
      const result = clone(handler(input));
      const lost = server.lostResponses[procedure] ?? 0;
      if (lost > 0) {
        server.lostResponses[procedure] = lost - 1;
        throw new Error("network");
      }
      return result;
    };
  /** Server-side idempotency: same key and body replays, a changed body conflicts. */
  const idempotent = <I extends { idempotencyKey: string }, O>(
    procedure: string,
    handler: (input: I) => O,
  ) =>
    call(procedure, (input: I) => {
      const canonicalKill =
        procedure === "signalProcess" && "signal" in input && input.signal === "SIGKILL";
      const canonicalInput = canonicalKill
        ? Object.fromEntries(Object.entries(input).filter(([key]) => key !== "signal"))
        : input;
      const body = JSON.stringify({
        procedure: canonicalKill ? "killProcess" : procedure,
        ...canonicalInput,
        idempotencyKey: undefined,
      });
      const prior = server.receipts.get(input.idempotencyKey);
      if (prior) {
        if (prior.body !== body) throw coded("sandbox.idempotency_conflict");
        return prior.result as O;
      }
      const result = handler(input);
      server.receipts.set(input.idempotencyKey, { body, result: clone(result) });
      return result;
    });
  /** Bounded pages use an opaque fixture cursor rather than database ordering. */
  const pagedInfinite =
    (key: string[], procedure: string, rows: (input: Record<string, unknown>) => Row[]) =>
    (options: InfiniteOptions) => ({
      queryKey: [...key, "infinite", options.input(undefined)],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
        const input = options.input(pageParam);
        record(procedure, input);
        failNext(procedure);
        const all = rows(input);
        const start = pageParam === undefined ? 0 : Number(pageParam);
        const limit = Math.min(Number(input.limit ?? 20), server.pickerPageSize ?? 100);
        const items = all.slice(start, start + limit);
        const next = start + limit < all.length ? String(start + limit) : null;
        return { items: clone(items), nextCursor: next };
      },
    });
  // A single bounded page as a plain query (the Sandboxes onboarding checks).
  // Recorded as `<procedure>:first` so it never consumes an injected error.
  const pagedQuery =
    (key: string[], procedure: string, rows: (input: Record<string, unknown>) => Row[]) =>
    ({ input }: { input: Record<string, unknown> }) => ({
      queryKey: [...key, "first", input],
      queryFn: async () => {
        record(`${procedure}:first`, input);
        return { items: clone(rows(input).slice(0, Number(input.limit ?? 20))), nextCursor: null };
      },
    });
  const query =
    (key: string[], procedure: string, handler: (input: never) => unknown) =>
    ({ input }: { input?: unknown } = {}) => ({
      queryKey: [...key, input === skipToken ? "skip" : input],
      queryFn:
        input === skipToken
          ? skipToken
          : async () => {
              record(procedure, input);
              failNext(procedure);
              return clone(handler(input as never));
            },
    });
  const sandbox = (id: string) => {
    const row = server.sandboxes.find((candidate) => candidate.id === id);
    if (!row) throw NOT_FOUND();
    return row;
  };
  const operation = (kind: (typeof OPERATION_KINDS)[number], sandboxId: string) => {
    server.seq += 1;
    const op = operationRow({
      id: `op-${server.seq}`,
      sandboxId,
      kind,
      state: "QUEUED",
      errorCode: null,
      failure: null,
      createdAt: new Date(),
      completedAt: null,
    });
    server.operations.push(op);
    return op;
  };
  const lifecycle = (row: Row, kind: (typeof OPERATION_KINDS)[number], state?: string) => {
    const op = operation(kind, String(row.id));
    row.lastLifecycleOperation = op;
    if (state) row.state = state;
    return op;
  };
  const mutation = <I, O>(fn: (input: I) => Promise<O>) => ({
    mutationOptions: () => ({ mutationFn: fn }),
  });
  const findOperation = (id: string) => {
    const row = server.operations.find((candidate) => candidate.id === id);
    if (!row) throw NOT_FOUND();
    return row;
  };

  const cancelProcess = (input: {
    process: ProcessRef;
    idempotencyKey: string;
  }): ProcedureOutput<"killProcess"> => {
    const target = server.operations.find(
      (row) =>
        row.kind === "RUN_COMMAND" &&
        row.sandboxId === input.process.sandboxId &&
        row.processId === input.process.processId,
    );
    if (!target) throw coded("sandbox.process_not_found", "NOT_FOUND");
    if (
      input.process.generation !== target.generation ||
      input.process.attempt !== (target.dispatchAttempt ?? 1) ||
      input.process.pid !== (target.processPid ?? 42)
    )
      throw coded("sandbox.process_not_found", "NOT_FOUND");
    const current = server.sandboxes.find((row) => row.id === input.process.sandboxId);
    if (current && current.generation !== target.generation) throw coded("sandbox.process_stale");
    if (["DISPATCHED", "ACCEPTED", "RUNNING"].includes(String(target.state)))
      target.state = "CANCEL_REQUESTED";
    if (target.state === "QUEUED") completeFakeCommand(target, "cancelled");
    server.seq += 1;
    // This durable action receipt is deliberately absent from operations.
    return {
      operationId: `receipt-${server.seq}`,
      state: OPERATION_STATES.find((state) => state === target.state) ?? "UNKNOWN_OUTCOME",
    };
  };
  return {
    settings: {
      getAll: { key: () => ["settings", "getAll"] },
      imagePolicy: {
        key: () => ["settings", "imagePolicy"],
        queryOptions: () => ({
          queryKey: ["settings", "imagePolicy"],
          queryFn: async () => ({
            mode: "off" as const,
            imagePlacement: "ANY_NODE" as const,
            quotas: { maxStoredGiB: null, downloadsPerHour: null },
            usage: { storedBytes: "0", downloadsLastHour: 0 },
          }),
        }),
      },
    },
    sandboxPools: {
      listUsable: {
        key: () => ["sandboxPools", "list"],
        queryOptions: pagedQuery(["sandboxPools", "list"], "listPools", () => server.pools ?? []),
        infiniteOptions: pagedInfinite(
          ["sandboxPools", "list"],
          "listPools",
          // Pools carry their caller-specific lease view (best path).
          () =>
            (server.pools ?? []).map((pool) => ({
              lease: { maxTimeoutMs: server.maxTimeoutMs ?? 86_400_000, timeoutZero: false },
              ...pool,
            })),
        ),
      },
    },
    sandboxHosts: {
      listHosts: {
        key: () => ["sandboxHosts", "listHosts"],
        queryOptions: pagedQuery(["sandboxHosts", "listHosts"], "listHosts", () => server.hosts),
        infiniteOptions: pagedInfinite(
          ["sandboxHosts", "listHosts"],
          "listHosts",
          () => server.hosts,
        ),
      },
    },
    sandboxTemplates: {
      listRevisionChoices: {
        key: () => ["sandboxTemplates", "listRevisionChoices"],
        infiniteOptions: pagedInfinite(
          ["sandboxTemplates", "listRevisionChoices"],
          "listRevisionChoices",
          (input) =>
            server.templates.filter(
              (row) =>
                row.retiredAt == null &&
                row.archivedAt == null &&
                (row.availability as { hostId: string; status: string }[]).some(
                  (entry) =>
                    (entry.status === "AVAILABLE" ||
                      (input.includePending && entry.status === "PENDING")) &&
                    (input.poolId ? true : (input.hostIds as string[]).includes(entry.hostId)),
                ),
            ),
        ),
      },
      getTemplateRevision: {
        queryOptions: query(
          ["sandboxTemplates", "getTemplateRevision"],
          "getTemplateRevision",
          (input: { id: string }) => {
            const row = server.templates.find((row) => row.id === input.id);
            if (!row) throw NOT_FOUND();
            return row;
          },
        ),
      },

      listTemplates: {
        key: () => ["sandboxTemplates", "listTemplates"],
        queryOptions: pagedQuery(["sandboxTemplates", "listTemplates"], "listTemplates", (input) =>
          server.templates.filter((row) => input.status !== "active" || row.archivedAt == null),
        ),
        infiniteOptions: pagedInfinite(
          ["sandboxTemplates", "listTemplates"],
          "listTemplates",
          (input) => [
            ...new Map(
              server.templates
                .filter((row) => input.status !== "active" || row.archivedAt == null)
                .map((row) => [
                  row.templateId,
                  { ...row, id: row.templateId, archivedAt: row.archivedAt ?? null },
                ]),
            ).values(),
          ],
        ),
      },
      listRevisions: {
        key: () => ["sandboxTemplates", "listRevisions"],
        infiniteOptions: pagedInfinite(
          ["sandboxTemplates", "listRevisions"],
          "listRevisions",
          (input) => server.templates.filter((row) => row.templateId === input.templateId),
        ),
      },
      getTemplate: {
        queryOptions: query(
          ["sandboxTemplates", "getTemplate"],
          "getTemplate",
          (input: { id: string }) => {
            const row = server.templates.find((candidate) => candidate.templateId === input.id);
            if (!row) throw NOT_FOUND();
            return { ...row, id: row.templateId };
          },
        ),
      },
    },
    sandboxes: {
      getSandboxCapabilities: {
        queryOptions: query(
          ["sandboxes", "getSandboxCapabilities"],
          "getSandboxCapabilities",
          (input: { id: string }): ProcedureOutput<"getSandboxCapabilities"> => {
            const signals = server.supportedSignals ?? ["SIGKILL"];
            return sandboxCapabilitiesSchema.parse({
              sandboxId: input.id,
              generation: 1,
              unavailableReason: server.capabilitiesUnavailable ? "host_unavailable" : null,
              features: enabledSdkFeatures().filter(
                (feature) =>
                  feature !== "processes.signal" || signals.some((name) => name !== "SIGKILL"),
              ),
              limits: FS_PROCESS_LIMITS,
              guestApi: {
                ...guestApiCapabilities(signals.some((name) => name !== "SIGKILL")),
                supportedSignals: signals,
              },
            });
          },
        ),
      },
      listDir: mutation(
        idempotent("listDir", (input: { id: string; idempotencyKey: string }) => ({
          operationId: operation("LIST_DIR", input.id).id,
          state: "QUEUED",
        })),
      ),
      listProcesses: mutation(
        idempotent("listProcesses", (input: { id: string; idempotencyKey: string }) => ({
          operationId: operation("LIST_PROCESSES", input.id).id,
          state: "QUEUED",
        })),
      ),
      getOperationResult: {
        queryOptions: query(
          ["sandboxes", "getOperationResult"],
          "getOperationResult",
          (input: { operationId: string }) => {
            const op = findOperation(input.operationId);
            // Scripted pages are indexed by observation, not unrelated commands/controls.
            const index = server.operations
              .filter((row) => ["LIST_DIR", "LIST_PROCESSES"].includes(String(row.kind)))
              .findIndex((row) => row.id === op.id);
            const page = server.observationResults?.[index] ?? { outcome: "pending", result: null };
            return operationResultSchema.parse({
              operationId: op.id,
              sandboxId: op.sandboxId,
              generation: op.generation,
              kind: op.kind,
              observedAt: new Date().toISOString(),
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              ...page,
            });
          },
        ),
      },
      connectProcess: {
        queryOptions: query(
          ["sandboxes", "connectProcess"],
          "connectProcess",
          (input: { process: { processId: string } }) => {
            const connection = server.connections?.find(
              (row) =>
                (row.info as { process: { processId: string } }).process.processId ===
                input.process.processId,
            );
            if (!connection) throw NOT_FOUND();
            return processConnectionSchema.parse(connection);
          },
        ),
      },
      killProcess: mutation(idempotent("killProcess", cancelProcess)),
      signalProcess: mutation(
        idempotent(
          "signalProcess",
          (input: {
            process: {
              sandboxId: string;
              processId: string;
              generation: number;
              attempt: number;
              pid: number;
            };
            signal: string;
            idempotencyKey: string;
          }) => {
            if (!processSignalSchema.safeParse(input.signal).success)
              throw coded("BAD_REQUEST", "BAD_REQUEST");
            if (input.signal === "SIGKILL") return cancelProcess(input);
            if (
              !(server.supportedSignals ?? ["SIGKILL"]).includes(
                processSignalSchema.parse(input.signal),
              )
            )
              throw coded("UNSUPPORTED_CAPABILITY", "BAD_REQUEST");
            return {
              operationId: String(operation("SIGNAL_PROCESS", input.process.sandboxId).id),
              state: "QUEUED",
            } satisfies ProcedureOutput<"signalProcess">;
          },
        ),
      ),
      getLimits: {
        queryOptions: query(["sandboxes", "limits"], "getLimits", () => ({
          sandboxTimeoutMaxMs: server.maxTimeoutMs ?? 86_400_000,
          sandboxTimeoutZero: false,
        })),
      },
      key: () => ["sandboxes"],
      list: {
        infiniteOptions: pagedInfinite(["sandboxes", "list"], "list", (input) =>
          server.sandboxes.filter((row) =>
            input.status === undefined || input.status === "active"
              ? row.state !== "DELETED"
              : input.status === "deleted"
                ? row.state === "DELETED"
                : input.status === "all" || row.state === "READY",
          ),
        ),
      },
      getSandbox: {
        queryOptions: query(["sandboxes", "getSandbox"], "getSandbox", (input: { id: string }) => ({
          // The detail view's own lease-path limit (display only).
          leaseLimit: { finiteMaxMs: server.maxTimeoutMs ?? 86_400_000, unlimited: false },
          ...sandbox(input.id),
        })),
      },
      getOperation: {
        queryOptions: query(
          ["sandboxes", "getOperation"],
          "getOperation",
          (input: { operationId: string }) => {
            const row = server.operations.find((candidate) => candidate.id === input.operationId);
            if (!row) throw NOT_FOUND();
            return row;
          },
        ),
      },
      listConnectSessions: {
        infiniteOptions: pagedInfinite(
          ["sandboxes", "listConnectSessions"],
          "listConnectSessions",
          (input) => (server.connectSessions ?? []).filter((row) => row.sandboxId === input.id),
        ),
      },
      listOperations: {
        infiniteOptions: pagedInfinite(["sandboxes", "listOperations"], "listOperations", (input) =>
          server.operations.filter(
            (row) =>
              (input.sandboxId === undefined || row.sandboxId === input.sandboxId) &&
              (input.kind === undefined || row.kind === input.kind) &&
              (input.state === undefined ||
                row.state === input.state ||
                (input.state === "active" &&
                  ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"].includes(
                    String(row.state),
                  )) ||
                (input.state === "settled" &&
                  ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(
                    String(row.state),
                  ))),
          ),
        ),
      },
      getOperationView: {
        queryOptions: query(
          ["sandboxes", "getOperationView"],
          "getOperationView",
          (input: { operationId: string }) => findOperation(input.operationId),
        ),
      },
      getCommandOutput: {
        /** `orpc.sandboxes.getCommandOutput.call`, abortable like a real request. */
        call: async (
          input: { operationId: string; cursor?: string; maxBytes?: number },
          options?: { signal?: AbortSignal },
        ) => {
          record("getCommandOutput", input);
          const gate = server.gates.getCommandOutput;
          if (gate) {
            await new Promise<void>((resolve, reject) => {
              const abort = () => {
                server.aborted += 1;
                reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
              };
              if (options?.signal?.aborted) return abort();
              options?.signal?.addEventListener("abort", abort, { once: true });
              void gate.then(resolve);
            });
          }
          failNext("getCommandOutput");
          findOperation(input.operationId);
          const output = server.outputs.get(input.operationId);
          if (!output) throw NOT_FOUND();
          if (output.expired) throw OUTPUT_EXPIRED();
          return clone(
            outputPage(
              input.operationId,
              findOperation(input.operationId),
              output,
              input.cursor,
              input.maxBytes,
            ),
          );
        },
      },
      cancelOperation: mutation(
        call("cancelOperation", (input: { operationId: string }) => {
          const row = findOperation(input.operationId);
          const state = String(row.state);
          if (state === "QUEUED") completeFakeCommand(row, "cancelled");
          else if (["DISPATCHED", "ACCEPTED", "RUNNING"].includes(state))
            row.state = "CANCEL_REQUESTED";
          return { operationId: row.id, state: row.state };
        }),
      ),
      createSandbox: mutation(
        idempotent(
          "createSandbox",
          (input: {
            template: string;
            name?: string;
            cpuCount?: number;
            memoryMiB?: number;
            diskGiB?: number;
            sandboxHostId?: string;
            poolId?: string;
            idempotencyKey: string;
            metadata?: Record<string, string>;
            envs?: Record<string, string>;
            egress?: { mode?: "open" | "allowlist"; domains?: string[]; cidrs?: string[] };
            timeoutMs?: number;
            lifecycle?: { onTimeout?: "kill" | "stop" };
          }) => {
            const size = vmSizeOverridesSchema.safeParse({
              cpuCount: input.cpuCount,
              memoryMiB: input.memoryMiB,
              diskGiB: input.diskGiB,
            });
            if (!size.success) throw coded("sandbox.vm_size_invalid", "BAD_REQUEST");
            server.seq += 1;
            const host =
              server.hosts.find((row) => row.id === input.sandboxHostId) ??
              (input.poolId ? server.hosts[0] : null);
            const template = server.templates.find((row) =>
              input.template.startsWith("template/")
                ? row.templateId === input.template.slice(9)
                : row.id === input.template.replace(/^revision\//, ""),
            );
            const row: Row = {
              ...sandboxRow({
                id: `sbx-new-${server.seq}`,
                ...(typeof input.name === "string" ? { name: input.name } : {}),
                state: "REQUESTED",
                sandboxHostId: host?.id ?? null,
                templateId: template?.templateId ?? "logical-1",
                templateRevisionId: template?.id ?? "tpl-1",
                originPoolId: input.poolId ?? null,
                cpuCount:
                  size.data.cpuCount ?? template?.cpuCount ?? VM_SIZE_LIMITS.cpuCountDefault,
                memoryMiB:
                  size.data.memoryMiB ?? template?.memoryMiB ?? VM_SIZE_LIMITS.memoryMiBDefault,
                diskGiB:
                  size.data.diskGiB ?? template?.defaultDiskGiB ?? VM_SIZE_LIMITS.diskGiBDefault,
                metadata: createSandboxInput.shape.metadata.parse(input.metadata ?? {}),
                // Mirrors the server on the creator's own node: the request's
                // mode (inferred like `inferEgressMode`) is effective, and
                // open drops the fallback grants.
                ...fakeEgress(input.egress),
                leaseExpiresAt: new Date(Date.now() + (input.timeoutMs ?? 300000)),
                leaseExpiresAtRequested: new Date(Date.now() + (input.timeoutMs ?? 300000)),
                leaseExpireAction: input.lifecycle?.onTimeout === "stop" ? "STOP" : "DESTROY",
                leaseExpireActionRequested:
                  input.lifecycle?.onTimeout === "stop" ? "STOP" : "DESTROY",
              }),
              host,
              template: template
                ? {
                    id: template.templateId,
                    revisionId: template.id,
                    revision: 1,
                    slug: template.slug,
                    label: template.label,
                    retiredAt: null,
                  }
                : null,
            };
            lifecycle(row, "CREATE_SANDBOX");
            server.sandboxes.unshift(row);
            return row;
          },
        ),
      ),
      // Rename: not an operation (no idempotency key); names are unique among live rows.
      updateSandbox: mutation(
        call("updateSandbox", (input: { id: string; name?: string; offload?: Row }) => {
          const row = sandbox(input.id);
          if (
            input.name !== undefined &&
            server.sandboxes.some(
              (other) =>
                other.id !== row.id && other.state !== "DELETED" && other.name === input.name,
            )
          )
            throw coded("sandbox.name_taken");
          if (input.name !== undefined) row.name = input.name;
          const disk = row.disk as Row | null;
          if (input.offload !== undefined && disk)
            row.disk = { ...disk, offloadPolicy: input.offload };
          return row;
        }),
      ),
      // Restore pin (disk offload): not an operation; owner session only.
      setOffloadPin: mutation(
        call("setOffloadPin", (input: { id: string; offloadPin: "ANY" | "OWN_HOSTS" }) => {
          const row = sandbox(input.id);
          const disk = row.disk as Row | null;
          if (disk) row.disk = { ...disk, offloadPin: input.offloadPin };
          return { id: row.id, offloadPin: input.offloadPin };
        }),
      ),
      // Retry cleanup: session only, no idempotency key.
      retryCleanup: mutation(
        call("retryCleanup", (input: { id: string }) => {
          const row = sandbox(input.id);
          if (row.state !== "ERROR" || row.lastErrorCode !== "restore_cleanup_pending")
            throw coded("sandbox.state_conflict");
          row.state = "STOPPING";
          return row;
        }),
      ),
      stopSandbox: mutation(
        idempotent("stopSandbox", (input: { id: string; idempotencyKey: string }) => {
          const op = lifecycle(sandbox(input.id), "STOP_SANDBOX", "STOPPING");
          return { operationId: op.id, state: "QUEUED" };
        }),
      ),
      reconnectSandbox: mutation(
        idempotent(
          "reconnectSandbox",
          (input: {
            id: string;
            idempotencyKey: string;
            mode?: "warm" | "cold";
            timeoutMs?: number;
            overrideCreatorAllowlist?: boolean;
          }) => {
            const row = sandbox(input.id);
            const cold = row.state === "STOPPED" || row.state === "OFFLOADED";
            const deadline = new Date(
              cold
                ? Date.now() + (input.timeoutMs ?? 300000)
                : Math.max(
                    Date.now() + (input.timeoutMs ?? 300000),
                    new Date(row.leaseExpiresAt as Date).getTime(),
                    row.leaseExpiresAtEffective
                      ? new Date(row.leaseExpiresAtEffective as Date).getTime()
                      : 0,
                  ),
            );
            Object.assign(row, {
              leaseRevision: Number(row.leaseRevision) + 1,
              leaseExpiresAt: deadline,
              leaseExpiresAtRequested: deadline,
              leaseExpireActionRequested: row.leaseExpireAction,
              ...(cold
                ? {
                    leaseExpiresAtEffective: null,
                    leaseExpireActionEffective: null,
                    startedAt: null,
                    readyAt: null,
                  }
                : {}),
            });
            const op = lifecycle(row, "RECONNECT_SANDBOX");
            return { operationId: op.id, state: "QUEUED" };
          },
        ),
      ),
      killSandbox: mutation(
        idempotent("killSandbox", (input: { id: string; idempotencyKey: string }) => {
          const row = sandbox(input.id);
          lifecycle(row, "KILL_SANDBOX", "STOPPING");
          return row;
        }),
      ),
      setSandboxTimeout: mutation(
        idempotent(
          "setSandboxTimeout",
          (input: { id: string; idempotencyKey: string; timeoutMs: number }) => {
            const row = sandbox(input.id);
            const action = row.leaseExpireAction;
            const deadline = new Date(Date.now() + input.timeoutMs);
            Object.assign(row, {
              leaseRevision: Number(row.leaseRevision) + 1,
              leaseExpiresAt: deadline,
              leaseExpireAction: action,
              leaseExpiresAtRequested: deadline,
              leaseExpireActionRequested: action,
            });
            const op = lifecycle(row, "RENEW_SANDBOX_LEASE");
            Object.assign(op, {
              state: "SUCCEEDED",
              errorCode: null,
              failure: null,
              completedAt: new Date(),
            });
            return row;
          },
        ),
      ),
      readFile: mutation(
        idempotent("readFile", (input: { id: string; path: string; idempotencyKey: string }) => {
          sandbox(input.id);
          const op = operation("GET_FILE", input.id);
          return { operationId: op.id, state: "QUEUED" };
        }),
      ),
    },
  };
}

/** Script a host terminal command result, including its public diagnostics.
 * Codes: sandbox-protocol/error.rs; storage: operation-handlers.ts.
 * Like finish_dispatch, failures without explicit effect evidence remain unknown.
 * Exit codes are payload evidence, never synthesized from a diagnostic code.
 */
export function completeFakeCommand(
  row: Row,
  outcome: "succeeded" | "cancelled" | "timeout" | "unknown",
  evidence: { exitCode?: number | null; failure?: OperationFailure | null } = {},
) {
  const terminal = {
    succeeded: { state: "SUCCEEDED", errorCode: null },
    cancelled: { state: "CANCELLED", errorCode: "cancelled" },
    timeout: { state: "FAILED", errorCode: "timeout" },
    unknown: { state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" },
  } satisfies Record<string, { state: string; errorCode: OperationErrorCode | null }>;
  Object.assign(row, terminal[outcome], {
    exitCode: evidence.exitCode ?? null,
    failure:
      evidence.failure === undefined
        ? outcome === "timeout" || outcome === "unknown"
          ? { resource: "command", effect: "unknown" }
          : null
        : evidence.failure,
    completedAt: new Date(),
    updatedAt: new Date(),
  });
}

/** An operation as `listOperations`/`getOperationView` return it (C48). */
export function operationRow(overrides: Row = {}): Row {
  const now = Date.now();
  const row = {
    id: "op-1",
    sandboxId: "sbx-1",
    kind: "RUN_COMMAND",
    state: "RUNNING",
    generation: 1,
    // Host completion/outbox cancellation uses the protocol's `cancelled`.
    // Other failures must supply the actual code/effect; FAILED alone proves neither.
    errorCode: overrides.state === "CANCELLED" ? "cancelled" : null,
    failure: null,
    errorMessage: null,
    exitCode: null,
    createdAt: new Date(now - 30_000),
    updatedAt: new Date(now - 30_000),
    dispatchedAt: new Date(now - 29_000),
    completedAt: ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(
      String(overrides.state),
    )
      ? new Date(now)
      : null,
    sandboxState: "READY",
    sandboxName: "quiet-otter",
    sandbox: { id: "sbx-1", name: "quiet-otter", state: "READY", generation: 1, host: fakeHost() },
    outputExpiresAt: null,
    ...overrides,
  };
  if (
    !OPERATION_KINDS.includes(row.kind as (typeof OPERATION_KINDS)[number]) ||
    !OPERATION_STATES.includes(row.state as (typeof OPERATION_STATES)[number])
  )
    throw new Error("Invalid fake operation kind/state");
  return row;
}

/** A sandbox view as `getSandbox`/`list` return it (host and template summaries included). */
/** Effective egress and normalized request for a create on the creator's own node. */
function fakeEgress(
  input: { mode?: "open" | "allowlist"; domains?: string[]; cidrs?: string[] } = {},
) {
  const mode =
    input.mode ?? (input.domains === undefined && input.cidrs === undefined ? "open" : "allowlist");
  const request = { mode, domains: [...(input.domains ?? [])], cidrs: [...(input.cidrs ?? [])] };
  return {
    egress: mode === "open" ? { mode, domains: [], cidrs: [] } : request,
    egressRequest: request,
  };
}

export function sandboxRow(overrides: Row = {}): Row {
  const now = Date.now();
  return {
    id: "sbx-1",
    // sbx-1 is "quiet-otter"; any other fixture id doubles as its (valid) name.
    name:
      overrides.id === undefined || overrides.id === "sbx-1" ? "quiet-otter" : String(overrides.id),
    state: "READY",
    generation: 1,
    templateId: "tpl-1",
    templateRevisionId: "tpl-1",
    originPoolId: null,
    cpuCount: VM_SIZE_LIMITS.cpuCountDefault,
    memoryMiB: VM_SIZE_LIMITS.memoryMiBDefault,
    diskGiB: VM_SIZE_LIMITS.diskGiBDefault,
    storagePoolId: "storage-1",
    storagePoolName: "default",
    sandboxHostId: "host-1",
    leaseRevision: 1,
    leaseRevisionEffective: null,
    leaseExpiresAt: new Date(now + 3_600_000),
    leaseExpireAction: "STOP",
    leaseExpiresAtRequested: new Date(now + 3_600_000),
    leaseExpireActionRequested: "STOP",
    leaseExpiresAtEffective: null,
    leaseExpireActionEffective: null,
    hostExpiryConfirmedAt: null,
    hostExpiryRevision: null,
    hostExpiryAction: null,
    metadata: {},
    egress: { mode: "allowlist", domains: [], cidrs: [] },
    egressRequest: null,
    egressModeReason: null,
    egressDeniedGrants: [],
    guestSudo: true,
    guestSudoRequested: true,
    guestSudoReason: null,
    guestRoot: true,
    // Disk offload projection (disk-view.ts): on its host, never stored.
    disk: {
      location: "host",
      offloadState: "none",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: null,
      eligibility: "any_host",
      offloadPin: "ANY",
      offloadPolicy: { mode: "on_stop" },
      offloadDueAt: null,
    },
    lastErrorCode: null,
    expiryFailureReason: null,
    createdAt: new Date(now - 60_000),
    updatedAt: new Date(now - 60_000),
    host: fakeHost(),
    template: {
      id: "logical-1",
      revisionId: "tpl-1",
      revision: 1,
      slug: "ubuntu",
      label: "Ubuntu",
      retiredAt: null,
      archivedAt: null,
    },
    lastLifecycleOperation: null,
    ...overrides,
  };
}

export function fakeStoragePool(overrides: Row = {}): Row {
  return {
    id: "storage-1",
    name: "default",
    marker: "marker-1",
    capacityGiB: 96,
    totalBasedCapacityGiB: null,
    capacitySource: "explicit",
    derivationTotalBytes: null,
    derivationFreeBytes: null,
    derivationCommittedBytes: null,
    derivationActualBytes: null,
    derivationHeadroomBytes: null,
    implicitCeilingGiB: null,
    draining: false,
    health: "healthy",
    reason: null,
    totalBytes: 200 * 2 ** 30,
    usedBytes: 50 * 2 ** 30,
    freeBytes: 150 * 2 ** 30,
    diskReservedGiB: 0,
    reportedAt: new Date().toISOString(),
    ...overrides,
  };
}

export function fakeHost(overrides: Row = {}): Row {
  return {
    id: "host-1",
    slug: "alpha",
    label: "Alpha",
    status: "CONNECTED",
    lastConnectedAt: new Date(Date.now() - 60_000),
    lastHeartbeatAt: new Date(),
    deletionRequestedAt: null,
    draining: false,
    quarantinedAt: null,
    quarantineReason: null,
    liveSandboxCount: 0,
    egressEnforcement: true,
    egressOpen: true,
    openEgressForOthers: false,
    guestSudoForOthers: true,
    egressGuard: { ok: true, reason: null, leaseActive: true },
    storagePools: [fakeStoragePool()],
    retainedRootCount: 0,
    capacity: {
      memoryBudgetMiB: 4096,
      maxCpuCount: 4,
      maxMemoryMiB: 4096,
      memoryReservedMiB: 0,
      memoryAvailableMiB: 4096,
      memoryOvercommittedMiB: 0,
      vcpuBudget: 64,
      vcpuReserved: 0,
      vcpuAvailable: 64,
      vcpuOvercommitted: 0,

      retainedRootCount: 0,
      current: true,
      reportedAt: new Date().toISOString(),
    },
    ...overrides,
  };
}

export function fakeTemplate(overrides: Row = {}): Row {
  return {
    id: "tpl-1",
    templateId: "logical-1",
    revision: 1,
    cpuCount: VM_SIZE_LIMITS.cpuCountDefault,
    memoryMiB: VM_SIZE_LIMITS.memoryMiBDefault,
    defaultDiskGiB: VM_SIZE_LIMITS.diskGiBDefault,
    minDiskGiB: VM_SIZE_LIMITS.diskGiBDefault,
    availability: [{ hostId: overrides.sandboxHostId ?? "host-1", status: "AVAILABLE" }],
    sandboxHostId: "host-1",
    retiredAt: null,
    slug: "ubuntu",
    label: "Ubuntu",
    imageRef: "local:ubuntu",
    incusFingerprint: `sha256:${"ab".repeat(32)}`,
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
    guestVersion: null,
    createdAt: new Date(Date.now() - 86_400_000),
    updatedAt: new Date(Date.now() - 86_400_000),
    host: fakeHost(),
    sandboxCount: 1,
    ...overrides,
  };
}
