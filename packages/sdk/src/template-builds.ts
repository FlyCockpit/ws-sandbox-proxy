import { randomUUID } from "node:crypto";
import { open } from "node:fs/promises";
import {
  TEMPLATE_BUILD_TERMINAL_STATES,
  type TemplateBuildContextDto,
  type TemplateBuildCreatedDto,
  type TemplateBuildDto,
  type TemplateBuildHintDto,
  type TemplateBuildStateDto,
  type TemplateBuildStepDto,
  TRANSFER_CHUNK_BYTES,
} from "@wssp/sandbox-contracts";
import { parseRecipe, type Recipe } from "@wssp/template-recipe";
import { type PackContextOptions, packContext } from "./build-context";
import { WsspError } from "./errors";
import { type CommandStream, decodeBase64, StreamDecoders } from "./output";
import { DEFAULT_LONG_POLL_MS, RequestPacer, sleep } from "./polling";
import type { TemplateBuilder } from "./template-builder";
import type { RouteResponse, WsspTransport } from "./transport";

/** Follow reads retry transient failures: 6 tries, 500 ms doubling to 8 s
 * (a Retry-After up to 30 s wins), about 15 s of outage in all. */
const FOLLOW_RETRY_KINDS: ReadonlySet<string> = new Set(["unavailable", "timeout", "capacity"]);
const FOLLOW_RETRY_ATTEMPTS = 6;
const FOLLOW_RETRY_BASE_MS = 500;
const FOLLOW_RETRY_MAX_MS = 8_000;
const FOLLOW_RETRY_AFTER_MAX_MS = 30_000;

/**
 * One line of `onBuildLogs`: a progress line, step output, a dropped range,
 * or a synthetic hint. A `hint` names a host the build VM's allowlist
 * resolver refused; when `hint.source` is `"foreign_node"` the name was
 * reported by another user's node (unverified) and carries no grant advice.
 */
export type BuildLogEntry =
  | { type: "phase"; message: string; build: TemplateBuildDto }
  | { type: "output"; step: number; stream: CommandStream; data: Uint8Array; text: string }
  | { type: "gap"; step: number; start: number; end: number }
  | { type: "hint"; step: number; message: string; hint: TemplateBuildHintDto };

export type TemplateBuildOptions = {
  /** Target template: a slug (created when missing; the key needs `templates:write`). */
  name?: string;
  /** Target template by id (instead of `name`). */
  templateId?: string;
  /** SDK keys move `latest` only. */
  tag?: "latest";
  /** Exactly one placement target: a pool or one of your hosts. */
  poolId?: string;
  hostId?: string;
  cpuCount?: number;
  memoryMiB?: number;
  diskGiB?: number;
  /** The new revision's `defaultDiskGiB` (default: the base's, at least the build disk). */
  defaultDiskGiB?: number;
  /** Values of the recipe's ARG steps. */
  buildArgs?: Record<string, string>;
  /** Directory packed (ustar) and uploaded as the COPY context. Required with COPY. */
  contextDir?: string;
  /** Packing options (filter, size cap, temp directory). */
  context?: PackContextOptions;
  /** Pool targets only: wait this long for capacity (clamped for COPY builds). */
  waitForCapacityMs?: number | "unlimited";
  /** Step time budget in minutes (default: the server's, at most 30). */
  timeoutMinutes?: number;
  /** Reuse it to retry an `unknown` acceptance; generated when absent. */
  idempotencyKey?: string;
  /** Wait for the build to end (default true); false returns once accepted and uploaded. */
  wait?: boolean;
  /** Progress lines interleaved with step output; requires waiting. */
  onBuildLogs?: (entry: BuildLogEntry) => void;
  signal?: AbortSignal;
};

export type TemplateBuildListOptions = {
  limit?: number;
  cursor?: string;
  templateId?: string;
  state?: TemplateBuildStateDto;
};

export type TemplateBuildsApi = {
  /**
   * Build a template revision from `template`: pack the context (COPY only),
   * accept the build, upload and seal the context, then (by default) wait
   * for the build to end, streaming its logs to `onBuildLogs`. Resolves with
   * the build's final state; check it with `isBuildFailed`.
   */
  build(template: TemplateBuilder, options: TemplateBuildOptions): Promise<TemplateBuildDto>;
  getBuild(
    id: string,
    options?: { waitMs?: number; signal?: AbortSignal },
  ): Promise<TemplateBuildDto>;
  listBuilds(
    query?: TemplateBuildListOptions,
    options?: { signal?: AbortSignal },
  ): Promise<RouteResponse<"listTemplateBuilds">>;
  /** Request cancellation; idempotent while cancelling. The build VM is killed by cleanup. */
  cancelBuild(id: string, options?: { signal?: AbortSignal }): Promise<TemplateBuildDto>;
  /** One page of one executed step's output (`step` = `steps[n].n`). */
  buildLogs(
    id: string,
    query: { step: number; cursor?: string; maxBytes?: number; waitMs?: number },
    options?: { signal?: AbortSignal },
  ): Promise<RouteResponse<"getTemplateBuildLogs">>;
};

const TERMINAL: ReadonlySet<TemplateBuildStateDto> = new Set(TEMPLATE_BUILD_TERMINAL_STATES);

/** True once the build will not change state again. */
export function isBuildDone(build: Pick<TemplateBuildDto, "state">): boolean {
  return TERMINAL.has(build.state);
}

/** True when the build ended without a revision (failed or cancelled). */
export function isBuildFailed(build: Pick<TemplateBuildDto, "state">): boolean {
  return build.state === "FAILED" || build.state === "CANCELLED";
}

function invalid(message: string): WsspError {
  return new WsspError({ kind: "invalid_request", message });
}

/** The display line of one executed step, from the local recipe. */
function stepLine(recipe: Recipe, step: TemplateBuildStepDto, count: number): string {
  const source = recipe.steps[step.stepIndex];
  let what: string;
  if (step.kind === "prelude") what = "WORKDIR (prepare)";
  else if (source?.type === "run") what = `RUN ${source.script.split("\n", 1)[0]}`;
  else if (source?.type === "copy") what = `COPY ${source.src.join(" ")} ${source.dest}`;
  else what = step.kind.toUpperCase();
  return `Step ${step.n + 1}/${count}: ${what}`;
}

function phaseLine(recipe: Recipe, build: TemplateBuildDto): string {
  if (build.phase === "step" && build.stepIndex >= 0) {
    const step = build.steps[build.stepIndex];
    if (step) return stepLine(recipe, step, build.steps.length);
  }
  if (isBuildDone(build))
    return build.errorCode
      ? `${build.state}: ${build.errorCode}${build.errorDetail ? ` (${build.errorDetail})` : ""}`
      : build.state;
  return build.phase ?? build.state.toLowerCase();
}

export function createTemplateBuildsApi(transport: WsspTransport): TemplateBuildsApi {
  const getBuild: TemplateBuildsApi["getBuild"] = (id, options) =>
    transport.request("getTemplateBuild", {
      params: { id },
      query: options?.waitMs ? { waitMs: String(options.waitMs) } : {},
      signal: options?.signal,
      // A held read answers within waitMs; leave headroom for the response.
      timeoutMs: (options?.waitMs ?? 0) + 30_000,
    });

  const buildLogs: TemplateBuildsApi["buildLogs"] = (id, query, options) =>
    transport.request("getTemplateBuildLogs", {
      params: { id },
      query: {
        step: String(query.step),
        ...(query.cursor ? { cursor: query.cursor } : {}),
        ...(query.maxBytes ? { maxBytes: String(query.maxBytes) } : {}),
        ...(query.waitMs ? { waitMs: String(query.waitMs) } : {}),
      },
      signal: options?.signal,
      timeoutMs: (query.waitMs ?? 0) + 30_000,
    });

  /** Upload the packed tar from the server's received offset, then seal. */
  async function upload(
    buildId: string,
    path: string,
    handle: TemplateBuildContextDto,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    let current = handle;
    if (current.state === "OPEN") {
      const file = await open(path, "r");
      try {
        const buffer = new Uint8Array(TRANSFER_CHUNK_BYTES);
        for (let offset = current.receivedBytes; offset < current.totalBytes; ) {
          const length = Math.min(TRANSFER_CHUNK_BYTES, current.totalBytes - offset);
          let read = 0;
          while (read < length) {
            const { bytesRead } = await file.read(buffer, read, length - read, offset + read);
            if (bytesRead === 0) throw invalid("The packed context changed during upload.");
            read += bytesRead;
          }
          current = await transport.putBuildContextChunk({
            params: { id: buildId },
            offset,
            total: current.totalBytes,
            bytes: buffer.subarray(0, length),
            signal,
          });
          offset = current.receivedBytes;
        }
      } finally {
        await file.close();
      }
    }
    if (current.state === "OPEN")
      current = await transport.request("sealBuildContext", { params: { id: buildId }, signal });
    if (current.state !== "SEALED" && current.state !== "ADOPTED")
      throw new WsspError({
        kind: "conflict",
        message: `The build context ended ${current.state}${current.errorCode ? ` (${current.errorCode})` : ""}.`,
      });
  }

  /**
   * One follow read, retried on a transient failure (network, timeout, 5xx,
   * 429) with bounded backoff: the build keeps running server-side, so a blip
   * must not end the wait. Definitive answers (4xx) and aborts are thrown.
   */
  async function followRead<T>(read: () => Promise<T>, signal: AbortSignal | undefined) {
    for (let failures = 0; ; failures++) {
      try {
        return await read();
      } catch (error) {
        if (
          signal?.aborted ||
          !(error instanceof WsspError) ||
          !FOLLOW_RETRY_KINDS.has(error.kind) ||
          failures + 1 >= FOLLOW_RETRY_ATTEMPTS
        )
          throw error;
        const backoff = Math.min(FOLLOW_RETRY_BASE_MS * 2 ** failures, FOLLOW_RETRY_MAX_MS);
        const after = (error.retryAfterSeconds ?? 0) * 1000;
        await sleep(Math.min(Math.max(backoff, after), FOLLOW_RETRY_AFTER_MAX_MS), signal);
        if (signal?.aborted)
          throw new WsspError({ kind: "aborted", message: "Build wait aborted." });
      }
    }
  }

  /** Follow a build to its end, emitting phase lines and step output. */
  async function follow(
    recipe: Recipe,
    first: TemplateBuildDto,
    onLogs: ((entry: BuildLogEntry) => void) | undefined,
    signal: AbortSignal | undefined,
  ): Promise<TemplateBuildDto> {
    let build = first;
    let lastLine = "";
    const cursors = new Map<number, string>();
    const complete = new Set<number>();
    const decoders = new Map<number, StreamDecoders>();
    const hintsSeen = new Set<string>();
    const emit = (entry: BuildLogEntry) => {
      try {
        onLogs?.(entry);
      } catch {
        // A throwing observer must not end the build wait.
      }
    };
    // Steps whose hints can no longer change (see `hintsFinal`) and whose
    // output was read to the end: never read again.
    const settled = new Set<number>();
    // Log reads share the command follow's budget shape: a burst, then at
    // most one per 2 s (a step printing continuously costs ≤ 30 reads a minute).
    const pacer = new RequestPacer();
    /**
     * E2-A-03: a blocked-name hint is attributed to the build's latest
     * started step and recorded asynchronously, so it can land on a step
     * after that step's output already completed. Once a later step has
     * started, or the build left RUNNING (only a RUNNING build takes hints),
     * no further hint can reach `step`: a read that begins after the build
     * read showing that sees all of its hints.
     */
    const hintsFinal = (step: TemplateBuildStepDto) =>
      build.state !== "RUNNING" ||
      build.steps.some((later) => later.n > step.n && later.state !== "pending");
    /** Reads `step` to its current end; true when the last page carried news. */
    const readStep = async (step: TemplateBuildStepDto, waitMs?: number) => {
      const final = hintsFinal(step);
      for (;;) {
        await pacer.take(signal);
        const page = await followRead(
          () =>
            buildLogs(build.id, { step: step.n, cursor: cursors.get(step.n), waitMs }, { signal }),
          signal,
        );
        let news = false;
        for (const hint of page.hints) {
          const key = `${hint.step}\u0000${hint.name}`;
          if (hintsSeen.has(key)) continue;
          hintsSeen.add(key);
          news = true;
          emit({ type: "hint", step: hint.step, message: hint.message, hint });
        }
        const output = page.output;
        if (!output) return news;
        const decoder = decoders.get(step.n) ?? new StreamDecoders();
        decoders.set(step.n, decoder);
        if (output.reset) decoder.reset();
        for (const gap of output.gaps) {
          decoder.reset();
          emit({ type: "gap", step: step.n, start: gap.start, end: gap.end });
        }
        for (const chunk of output.chunks) {
          const data = decodeBase64(chunk.data);
          emit({
            type: "output",
            step: step.n,
            stream: chunk.stream,
            data,
            text: decoder.decode(chunk.stream, data),
          });
        }
        news ||= output.chunks.length > 0 || output.gaps.length > 0;
        cursors.set(step.n, output.nextCursor);
        if (output.complete) complete.add(step.n);
        if (output.complete && !output.hasMore && final) settled.add(step.n);
        if (!output.hasMore) return news;
        waitMs = undefined;
      }
    };
    for (;;) {
      if (signal?.aborted) throw new WsspError({ kind: "aborted", message: "Build wait aborted." });
      const line = phaseLine(recipe, build);
      if (line !== lastLine) {
        lastLine = line;
        emit({ type: "phase", message: line, build });
      }
      // A finished step is read until its output ends, then once more when
      // its hints become final (never repeatedly while they are not).
      if (onLogs)
        for (const step of build.steps)
          if (
            step.operationId &&
            step.state !== "pending" &&
            step.state !== "running" &&
            !settled.has(step.n) &&
            (!complete.has(step.n) || hintsFinal(step))
          )
            await readStep(step);
      if (isBuildDone(build)) return build;
      const running = onLogs
        ? build.steps.find((step) => step.state === "running" && step.operationId)
        : undefined;
      if (running && !complete.has(running.n)) {
        // A held read that brought output is followed by the next held read
        // (the server paces it); the build is re-read only when the step's
        // output ended or the hold passed without news.
        const news = await readStep(running, DEFAULT_LONG_POLL_MS);
        if (news && !complete.has(running.n)) continue;
        build = await followRead(() => getBuild(build.id, { signal }), signal);
      } else
        build = await followRead(
          () => getBuild(build.id, { waitMs: DEFAULT_LONG_POLL_MS, signal }),
          signal,
        );
    }
  }

  return {
    getBuild,
    buildLogs,
    listBuilds: (query = {}, options) =>
      transport.request("listTemplateBuilds", {
        query: {
          ...(query.limit ? { limit: String(query.limit) } : {}),
          ...(query.cursor ? { cursor: query.cursor } : {}),
          ...(query.templateId ? { templateId: query.templateId } : {}),
          ...(query.state ? { state: query.state } : {}),
        },
        signal: options?.signal,
      }),
    cancelBuild: (id, options) =>
      transport.request("cancelTemplateBuild", { params: { id }, signal: options?.signal }),
    async build(template, options) {
      if ((options.name === undefined) === (options.templateId === undefined))
        throw invalid("Pass exactly one of name and templateId.");
      if ((options.poolId === undefined) === (options.hostId === undefined))
        throw invalid("Pass exactly one of poolId and hostId.");
      if (options.onBuildLogs && options.wait === false)
        throw invalid("onBuildLogs needs wait (the default).");
      const recipe = template.toRecipe({ buildArgs: options.buildArgs });
      const hasCopy = parseRecipe(recipe, { buildArgs: options.buildArgs }).plan.hasCopy;
      if (hasCopy && options.contextDir === undefined)
        throw invalid("The recipe has COPY steps: pass contextDir.");
      if (!hasCopy && options.contextDir !== undefined)
        throw invalid("contextDir is only used by recipes with COPY steps.");
      const key = options.idempotencyKey ?? randomUUID();
      // Pack first: the context's digest and size are part of the build request.
      const packed = hasCopy
        ? await packContext(options.contextDir as string, options.context)
        : undefined;
      let created: TemplateBuildCreatedDto;
      try {
        created = await transport.request("createTemplateBuild", {
          idempotencyKey: key,
          body: {
            template:
              options.templateId !== undefined
                ? { id: options.templateId }
                : { slug: options.name as string },
            ...(options.tag ? { tag: options.tag } : {}),
            recipe: recipe as unknown as Record<string, unknown>,
            ...(options.buildArgs ? { buildArgs: options.buildArgs } : {}),
            ...(options.poolId !== undefined
              ? { poolId: options.poolId }
              : { sandboxHostId: options.hostId }),
            ...(options.cpuCount !== undefined ? { cpuCount: options.cpuCount } : {}),
            ...(options.memoryMiB !== undefined ? { memoryMiB: options.memoryMiB } : {}),
            ...(options.diskGiB !== undefined ? { diskGiB: options.diskGiB } : {}),
            ...(options.defaultDiskGiB !== undefined
              ? { defaultDiskGiB: options.defaultDiskGiB }
              : {}),
            ...(options.timeoutMinutes !== undefined
              ? { timeoutMinutes: options.timeoutMinutes }
              : {}),
            ...(options.waitForCapacityMs !== undefined
              ? { waitForCapacityMs: options.waitForCapacityMs }
              : {}),
            ...(packed ? { contextSha256: packed.sha256, contextBytes: packed.bytes } : {}),
            ...(template.noCache ? { noCache: true } : {}),
          },
          signal: options.signal,
        });
        if (packed && created.contextUpload)
          await upload(created.build.id, packed.path, created.contextUpload, options.signal);
      } finally {
        await packed?.dispose();
      }
      if (options.wait === false) return created.build;
      return follow(recipe, created.build, options.onBuildLogs, options.signal);
    },
  };
}
