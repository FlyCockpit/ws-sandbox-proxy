import type {
  attachCredentialBodySchema,
  CreateTunnelLinkBody,
  createSandboxBodySchema,
  ExposeTunnelBody,
  mutationReceiptSchema,
  ProcessRef,
  reconnectBodySchema,
  renewBodySchema,
  SandboxCapabilities,
  SandboxDto,
  SandboxOffloadPolicy,
  SandboxPage,
  SandboxStateDto,
  SandboxTunnelDto,
  SandboxTunnelPortsDto,
  TunnelLinkDto,
  UpdateTunnelPortsBody,
  updateSandboxBodySchema,
} from "@wssp/sandbox-contracts";
import { sandboxListFiltersSchema } from "@wssp/sandbox-contracts";
import type { z } from "zod";
import type { WriteStdinOptions } from "./commands";
import { type CommandsApi, createCommandsApi } from "./commands";
import { isTransientRefusal, WsspError } from "./errors";
import { createFilesApi, type FilesApi } from "./files";
import { ensureSucceeded, waitOperation } from "./operations";
import {
  DEFAULT_WAIT_TIMEOUT_MS,
  Deadline,
  type PollContext,
  type PollingOptions,
  poll,
  pollingShape,
  type ResolvedPolling,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
  withWaitTimeout,
} from "./polling";
import { DEFAULT_TIMEOUT_MS, type WsspTransport } from "./transport";

type CreateSandboxBody = z.input<typeof createSandboxBodySchema>;
/**
 * Create input: the `/v1` create body plus the SDK-only `allowInternetAccess`
 * switch (E2B's name). Sandboxes default to open internet.
 *
 * - `allowInternetAccess` omitted: `egress` is sent as given. Omitting both
 *   requests open internet. An `egress` with `domains` or `cidrs` and no
 *   `mode` is an allowlist (the server's fail-safe inference).
 * - `true`: open internet; any `egress.domains`/`cidrs` are fallback grants,
 *   used only if the sandbox lands on another user's node that allows only
 *   listed destinations (`sandbox.egressModeReason` says when that happened).
 * - `false`: allowlist mode; only `egress.domains`/`cidrs` are reachable (none
 *   listed blocks all outbound traffic).
 *
 * A `mode` in `egress` that contradicts `allowInternetAccess` is refused
 * locally with kind `invalid_request`, before any network IO.
 */
export type CreateSandboxRequest = CreateSandboxBody & { allowInternetAccess?: boolean };
export type MutationReceipt = z.output<typeof mutationReceiptSchema>;

export type ReconnectInput = z.input<typeof reconnectBodySchema>;
/** Update input (`PUT /v1/sandboxes/{id}`): `name` and/or the offload policy `offload`. */
export type UpdateSandboxInput = z.input<typeof updateSandboxBodySchema>;
export type RenewLeaseInput = z.input<typeof renewBodySchema>;
export type ListSandboxesQuery = z.input<typeof sandboxListFiltersSchema> & {
  limit?: number;
  cursor?: string;
};

/** Options of a mutation call; one key covers submission retries and the wait. */
export type MutationOptions = WaitOptions & {
  /** Reuse this key to recover a previous call whose outcome was `unknown`. */
  idempotencyKey?: string;
};

export type ConnectOptions = MutationOptions & {
  /** Omitted adapts to READY/STOPPED; explicit warm/cold constrain the state. */
  mode?: ReconnectInput["mode"];
  /**
   * Guest-side reconnect budget sent in the request body (server maximum
   * 24 h). Independent of `waitTimeoutMs`, the SDK wait budget.
   */
  leaseTimeoutMs?: ReconnectInput["timeoutMs"];
  /**
   * CLI logins: resume pins for a cold start. A named account or instance
   * applies to this start only and never falls back (`credential.in_use`,
   * `credential.account_paused`); other logins resume by their recorded
   * account and instance with fallback. Needs `credentials:use`.
   */
  credentials?: ReconnectInput["credentials"];
  /**
   * Restore of an offloaded sandbox only: restore onto this host or through
   * this pool (at most one), and wait up to `waitForCapacityMs` for a host it
   * may use to have room (else `restore_no_allowed_host`).
   */
  sandboxHostId?: ReconnectInput["sandboxHostId"];
  poolId?: ReconnectInput["poolId"];
  waitForCapacityMs?: ReconnectInput["waitForCapacityMs"];
};

/** Stop and destroy: `credentialCapture: "skip"` skips copying login files back. */
export type TeardownOptions = MutationOptions & { credentialCapture?: "skip" };

/**
 * Stop: the teardown options plus `offload`, the sandbox's offload policy set
 * with the accepted stop (sent in the body, so it is part of the request
 * hash). `{ mode: "on_pressure" }` parks the disk on its host until the host
 * needs the space; `{ mode: "after", afterMs }` exports it after a delay.
 */
export type StopOptions = TeardownOptions & { offload?: SandboxOffloadPolicy };

/** One login to attach; a named account or instance applies to this attach only. */
export type AttachCredentialInput = z.input<typeof attachCredentialBodySchema>;

/** Live login attach/free on one sandbox (scope `credentials:use` + `sandboxes:manage`). */
export type SandboxCredentials = {
  /**
   * Attach a login and resolve once it is installed (READY: new commands and
   * terminals see its env) or recorded (STOPPED: claimed at the next start).
   */
  attach(input: AttachCredentialInput, options?: MutationOptions): Promise<{ operationId: string }>;
  /**
   * Free a login and resolve once it is done: its env left at once, terminals
   * opened with it closed, its files copied back (unless `skip`) and scrubbed.
   */
  free(credentialId: string, options?: TeardownOptions): Promise<{ operationId: string }>;
};

type BoundToSandbox<T> = T extends (id: string, ...args: infer P) => infer R
  ? (...args: P) => R
  : never;
export type SandboxCommands = {
  [K in "run" | "script" | "argv" | "start" | "list"]: BoundToSandbox<CommandsApi[K]>;
} & Pick<CommandsApi, "connect" | "signal" | "kill" | "closeStdin"> & {
    writeStdin(
      process: ProcessRef,
      chunk: string | Uint8Array,
      options?: WriteStdinOptions,
    ): Promise<void>;
  };
export type SandboxFiles = {
  [K in
    | "upload"
    | "download"
    | "readBytes"
    | "writeBytes"
    | "stat"
    | "exists"
    | "list"
    | "getInfo"
    | "makeDir"
    | "remove"
    | "rename"]: BoundToSandbox<FilesApi[K]>;
};

/** A snapshot with methods bound only to this ID and the client, never create input. */
export type Sandbox = SandboxDto & {
  /** Fixed creation/connect snapshot; call get() for a fresh read. */
  readonly sandbox: SandboxDto;
  readonly commands: SandboxCommands;
  readonly files: SandboxFiles;
  capabilities(options?: WaitOptions): Promise<SandboxCapabilities>;
  get(options?: WaitOptions): Promise<SandboxDto>;
  /** Rename and/or set the offload policy; returns a fresh read. This handle's own fields stay the snapshot. */
  update(input: UpdateSandboxInput, options?: WaitOptions): Promise<SandboxDto>;
  connect(options?: ConnectOptions): Promise<Sandbox>;
  setTimeout(input: RenewLeaseInput, options?: MutationOptions): Promise<RenewResult>;
  stop(options?: StopOptions): Promise<SandboxDto>;
  /** Save this sandbox as a new template revision (moves `latest`). */
  captureTemplate(input?: CaptureTemplateInput, options?: MutationOptions): Promise<CaptureResult>;
  destroy(options?: TeardownOptions): Promise<void>;
  readonly credentials: SandboxCredentials;
  /** Preview tunnels (optional on a deployment): expose declared ports, mint links. */
  readonly tunnel: SandboxTunnelApi;
  isAlive(options?: MutationOptions): Promise<boolean>;
  pause(): Promise<never>;
  snapshot(): Promise<never>;
  restore(snapshotId: string): Promise<never>;
  fork(): Promise<never>;
  getHost(port: number): never;
};
export type ConnectResult = Sandbox;

/**
 * Preview tunnels for a tunnel sandbox's declared ports (created with
 * `network.tunnelPorts`, possibly `[]`; change them with `updatePorts`). The
 * node runs the tunnel client outside the VM; you never hold a tunnel
 * credential. Refused with kind `unsupported` (`reason: "tunnel_off"`) on a
 * deployment without a tunnel server.
 */
export type SandboxTunnelApi = {
  /** Expose `ports` (default: every declared port). Idempotent. */
  expose(input?: ExposeTunnelBody, options?: WaitOptions): Promise<SandboxTunnelDto>;
  get(options?: WaitOptions): Promise<SandboxTunnelDto>;
  /** Delete the tunnel; every link to it stops working. */
  close(options?: WaitOptions): Promise<SandboxTunnelDto>;
  /** A short-lived (single-use by default) access URL for one exposed port. Treat it as a secret. */
  link(input: CreateTunnelLinkBody, options?: WaitOptions): Promise<TunnelLinkDto>;
  /**
   * Add or remove declared ports at runtime. `state` is `pending` until the
   * sandbox's host recorded the change (expose an added port after that, or
   * at once: the tunnel connects once it is applied). Removing an exposed
   * port replaces the tunnel: every link to it stops working.
   */
  updatePorts(input: UpdateTunnelPortsBody, options?: WaitOptions): Promise<SandboxTunnelPortsDto>;
};

/** The exact host-acknowledged renewal intent and the latest sandbox snapshot.
 * The snapshot may already reflect expiry or a later lease revision. */
export type RenewResult = {
  sandbox: SandboxDto;
  effective: NonNullable<SandboxDto["lease"]["effective"]>;
};

/** Only a defined `skip` is sent, so existing keys keep their request hash. */
function teardownBody(options: TeardownOptions): { credentialCapture?: "skip" } {
  return options.credentialCapture === "skip" ? { credentialCapture: "skip" } : {};
}

/** The stop body: the teardown body plus a defined `offload` only. */
function stopBody(options: StopOptions): {
  credentialCapture?: "skip";
  offload?: SandboxOffloadPolicy;
} {
  return {
    ...teardownBody(options),
    ...(options.offload !== undefined ? { offload: options.offload } : {}),
  };
}

/** The `/v1` create body for an SDK create input (`allowInternetAccess` mapped onto `egress.mode`). */
export function createSandboxBody(input: CreateSandboxRequest): CreateSandboxBody {
  const { allowInternetAccess, ...body } = input;
  if (allowInternetAccess === undefined) return body;
  const mode = allowInternetAccess ? "open" : "allowlist";
  if (body.egress?.mode !== undefined && body.egress.mode !== mode) {
    throw new WsspError({
      kind: "invalid_request",
      message: `createSandbox: allowInternetAccess: ${allowInternetAccess} contradicts egress.mode "${body.egress.mode}".`,
    });
  }
  return { ...body, egress: { ...body.egress, mode } };
}

export function generateKey(): string {
  return crypto.randomUUID();
}

/** Sandbox states from which a wait for another state can never succeed. */
const DEAD_STATES: ReadonlySet<SandboxStateDto> = new Set(["ERROR", "DELETED", "HOST_LOST"]);

function deadStateError(label: string, sandbox: SandboxDto, context: PollContext): WsspError {
  return new WsspError({
    kind: "unavailable",
    message: `${label}: the sandbox reached ${sandbox.state} while waiting.`,
    operationId: context.operationId ?? null,
    idempotencyKey: context.idempotencyKey ?? null,
  });
}

/**
 * Submit a mutation and wait out `unknown` (lost response, 5xx), `capacity`
 * (429) and transient host-reconnect (503 `sandbox.host_reconnecting`) answers by re-sending the request under the SAME idempotency key: the
 * server replays the original receipt, so a lost accepted response never
 * allocates twice. Definitive host/pool capacity and availability refusals
 * propagate immediately so the caller can choose another provider.
 */
export async function submitMutation(
  send: (attempt: AbortSignal) => Promise<MutationReceipt>,
  polling: ResolvedPolling,
  signal: AbortSignal | undefined,
  context: PollContext,
): Promise<MutationReceipt> {
  return poll<MutationReceipt>(
    async (attempt) => ({ done: true, value: await send(attempt) }),
    polling,
    signal,
    context,
    (error) =>
      (error.kind === "unknown" &&
        (error.code === null || (error.status !== null && error.status >= 500))) ||
      (error.kind === "capacity" && error.status === 429) ||
      // 503 `sandbox.host_reconnecting`: the host's journal key ACK is still
      // arriving after a relay reconnect. Refused before any durable write.
      isTransientRefusal(error) ||
      // 409 `sandbox.disk_evicting`: a start of a cached disk waits for its
      // eviction, then restores elsewhere. Refused before any durable write.
      error.code === "sandbox.disk_evicting",
    // A cancelled submission may have reached the server: poll reports it as
    // kind `unknown` (with the abort/timeout reason), never a plain wait error.
    { submission: true, capacityAtDeadline: true },
  );
}

export type SandboxesApi = {
  capabilities(id: string, options?: WaitOptions): Promise<SandboxCapabilities>;
  /** One read of the recorded lifecycle state (not a liveness probe). */
  get(id: string, options?: WaitOptions): Promise<SandboxDto>;
  /** The sandbox, or null only for a confirmed `sandbox.not_found`. */
  find(id: string, options?: WaitOptions): Promise<SandboxDto | null>;
  list(query?: ListSandboxesQuery, options?: WaitOptions): Promise<SandboxPage>;
  /**
   * Rename a sandbox (`name` unique among the owner's live sandboxes:
   * `sandbox.name_taken`, kind `conflict`) and/or set its offload policy
   * (`offload`, see `StopOptions`). Returns the fresh sandbox.
   */
  update(id: string, input: UpdateSandboxInput, options?: WaitOptions): Promise<SandboxDto>;
  /**
   * Create and resolve only once the operation succeeded AND the sandbox reads
   * READY. A lost response is recovered under the same idempotency key; an
   * UNKNOWN_OUTCOME is thrown as kind `unknown` and never retried.
   */
  create(input: CreateSandboxRequest, options?: MutationOptions): Promise<Sandbox>;
  /** Reconnect and return a bound sandbox after its exact ACK and READY. */
  connect(id: string, options?: ConnectOptions): Promise<ConnectResult>;
  /**
   * Stop, including during boot. A retained disk ends STOPPED; if boot never
   * created an instance, Stop succeeds and the sandbox reads DELETED.
   * `offload` sets the sandbox's offload policy with the stop.
   */
  stop(id: string, options?: StopOptions): Promise<SandboxDto>;
  /**
   * Snapshot-to-template: capture a READY (copy-on-write storage) or STOPPED
   * sandbox, scrub it and publish a new revision; resolves once finalized.
   */
  captureTemplate(
    id: string,
    input?: CaptureTemplateInput,
    options?: MutationOptions,
  ): Promise<CaptureResult>;
  /** Destroy and resolve only once deletion is confirmed (DELETED or absent). */
  destroy(id: string, options?: TeardownOptions): Promise<void>;
  /** Attach a login to a sandbox (see {@link SandboxCredentials.attach}). */
  attachCredential(
    id: string,
    input: AttachCredentialInput,
    options?: MutationOptions,
  ): Promise<{ operationId: string }>;
  /** Free a login from a sandbox (see {@link SandboxCredentials.free}). */
  freeCredential(
    id: string,
    credentialId: string,
    options?: TeardownOptions,
  ): Promise<{ operationId: string }>;
  /**
   * Set a relative lifetime (may shorten), resolving from this operation's
   * exact durable lease ACK, even after a later lease supersedes it.
   */
  setTimeout(id: string, input: RenewLeaseInput, options?: MutationOptions): Promise<RenewResult>;
  /**
   * Await the host probe: true for `guest_ready`, false for confirmed
   * `stopped`/`confirmed_absent` (or a confirmed not-found), a typed
   * `unavailable` error when the host is unreachable.
   */
  isAlive(id: string, options?: MutationOptions): Promise<boolean>;
  /** Poll until the sandbox reads READY. */
  waitReady(id: string, options?: MutationOptions): Promise<SandboxDto>;
  /** Poll until deletion is confirmed. */
  waitDeleted(id: string, options?: MutationOptions): Promise<void>;
};

export function createSandboxesApi(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
  resources?: { commands: CommandsApi; files: FilesApi },
): SandboxesApi {
  const commands = resources?.commands ?? createCommandsApi(transport, defaults);
  const files =
    resources?.files ??
    createFilesApi(transport, defaults, undefined, (id, options) =>
      commands.cancelAndWait(id, options),
    );
  // Only DEFINED per-call overrides merge: an undefined spread member would
  // erase the client defaults in resolvePolling.
  const pollingOf = (options: WaitOptions, deadline: Deadline, context: PollContext) => ({
    ...pollingShape(options),
    waitTimeoutMs: deadline.remaining(context),
  });

  async function waitForState(
    id: string,
    label: string,
    done: (sandbox: SandboxDto) => boolean,
    options: WaitOptions,
    deadline: Deadline,
    context: PollContext,
  ): Promise<SandboxDto> {
    // A dead state resolves the poll and is thrown AFTER it: thrown inside, the
    // `unavailable` kind would be misread as a retryable transport failure.
    const sandbox = await poll<SandboxDto>(
      async (attempt) => {
        const current = await transport.request("getSandbox", {
          params: { id },
          signal: attempt,
        });
        return done(current) || DEAD_STATES.has(current.state)
          ? { done: true, value: current }
          : { done: false };
      },
      resolvePolling(defaults, pollingOf(options, deadline, context)),
      options.signal,
      context,
    );
    if (!done(sandbox)) throw deadStateError(label, sandbox, context);
    return sandbox;
  }

  async function waitReady(
    id: string,
    options: MutationOptions = {},
    deadline: Deadline = new Deadline(resolvePolling(defaults, options).timeoutMs),
    context: PollContext = { label: `sandbox ${id} readiness` },
  ): Promise<SandboxDto> {
    return waitForState(
      id,
      context.label,
      (sandbox) => sandbox.state === "READY",
      options,
      deadline,
      context,
    );
  }

  async function waitIntentReady(
    id: string,
    generation: number,
    options: MutationOptions,
    deadline: Deadline,
    context: PollContext,
  ): Promise<SandboxDto> {
    const current = await waitForState(
      id,
      context.label,
      (sandbox) =>
        sandbox.id !== id || sandbox.generation !== generation || sandbox.state === "READY",
      options,
      deadline,
      context,
    );
    if (current.id !== id)
      throw new WsspError({
        kind: "protocol",
        message: `${context.label}: sandbox identity differs from the accepted intent.`,
        operationId: context.operationId,
        idempotencyKey: context.idempotencyKey,
      });
    if (current.generation !== generation)
      throw new WsspError({
        kind: "conflict",
        message: `${context.label}: the accepted boot generation was superseded.`,
        operationId: context.operationId,
        idempotencyKey: context.idempotencyKey,
      });
    return current;
  }

  async function waitDeleted(
    id: string,
    options: MutationOptions = {},
    deadline: Deadline = new Deadline(resolvePolling(defaults, options).timeoutMs),
    context: PollContext = { label: `sandbox ${id} deletion` },
  ): Promise<void> {
    await poll<void>(
      async (attempt) => {
        const sandbox = await transport.findSandbox(id, { signal: attempt });
        // A confirmed 404 is also confirmed deletion; the record is retained
        // as DELETED on this server, so both are terminal truths.
        return sandbox === null || sandbox.state === "DELETED"
          ? { done: true, value: undefined }
          : { done: false };
      },
      resolvePolling(defaults, pollingOf(options, deadline, context)),
      options.signal,
      context,
    );
  }

  async function runMutation(
    label: string,
    key: string,
    options: MutationOptions,
    send: (key: string, attempt: AbortSignal) => Promise<MutationReceipt>,
  ): Promise<{ receipt: MutationReceipt; deadline: Deadline; context: PollContext }> {
    const polling = resolvePolling(defaults, options);
    const deadline = new Deadline(polling.timeoutMs);
    const context: PollContext = { label, idempotencyKey: key };
    const receipt = await submitMutation(
      (attempt) => send(key, attempt),
      polling,
      options.signal,
      context,
    );
    context.operationId = receipt.operationId;
    return { receipt, deadline, context };
  }

  async function awaitOperation(
    label: string,
    receipt: MutationReceipt,
    deadline: Deadline,
    context: PollContext,
    options: MutationOptions,
  ) {
    const operation = await waitOperation(
      transport,
      defaults,
      receipt.operationId,
      { ...withWaitTimeout(options, deadline.remaining(context)) },
      context,
    );
    if (operation.id !== receipt.operationId)
      throw new WsspError({
        kind: "protocol",
        message: `${label}: operation identity differs from its receipt.`,
        operationId: receipt.operationId,
        idempotencyKey: context.idempotencyKey,
      });
    ensureSucceeded(operation, { ...context, label });
    return operation;
  }

  /**
   * A queued create may wait hours: poll it slowly with jitter (5–15 s, one
   * request per round) while its sandbox is WAITING_FOR_CAPACITY, then hand
   * over to the normal long-poll. A local deadline or abort never cancels the
   * server entry: the error carries sandboxId, operationId and the key.
   */
  async function waitForCapacity(
    receipt: MutationReceipt,
    wait: NonNullable<CreateSandboxRequest["waitForCapacityMs"]>,
    options: MutationOptions,
    context: PollContext,
    callerDeadline: Deadline | null,
  ): Promise<void> {
    const until =
      callerDeadline !== null
        ? null
        : wait === "unlimited"
          ? Number.POSITIVE_INFINITY
          : Date.now() + wait + DEFAULT_WAIT_TIMEOUT_MS;
    let sandboxId: string | null = null;
    const stopped = (kind: "timeout" | "aborted") =>
      new WsspError({
        kind,
        ...(kind === "aborted" ? { reason: "aborted" as const } : {}),
        message: `createSandbox: ${kind === "aborted" ? "aborted" : "the local wait ended"} while waiting for capacity; the queued create remains on the server (destroy the sandbox to cancel it).`,
        operationId: receipt.operationId,
        idempotencyKey: context.idempotencyKey,
        sandboxId,
      });
    const remaining = () => {
      if (callerDeadline === null) return (until ?? Number.POSITIVE_INFINITY) - Date.now();
      try {
        return callerDeadline.remaining(context);
      } catch {
        return 0;
      }
    };
    for (let round = 0; ; round++) {
      if (options.signal?.aborted) throw stopped("aborted");
      if (remaining() <= 0) throw stopped("timeout");
      try {
        if (sandboxId === null) {
          const operation = await transport.request("getOperation", {
            params: { id: receipt.operationId },
            signal: options.signal,
            timeoutMs: Math.min(remaining(), DEFAULT_TIMEOUT_MS),
          });
          if (operation.outcome !== "pending") return;
          sandboxId = operation.sandboxId;
        }
        if (options.signal?.aborted) throw stopped("aborted");
        if (remaining() <= 0) throw stopped("timeout");
        const sandbox = sandboxId
          ? await transport.findSandbox(sandboxId, {
              signal: options.signal,
              timeoutMs: Math.min(remaining(), DEFAULT_TIMEOUT_MS),
            })
          : null;
        if (sandbox?.state !== "WAITING_FOR_CAPACITY") return;
      } catch (error) {
        if (options.signal?.aborted || (error instanceof WsspError && error.kind === "aborted"))
          throw stopped("aborted");
        if (
          !(error instanceof WsspError) ||
          !["timeout", "unavailable", "capacity"].includes(error.kind)
        )
          throw new WsspError({
            ...(error instanceof WsspError ? error : { kind: "protocol" as const }),
            message:
              error instanceof WsspError
                ? error.message
                : "createSandbox: an unexpected capacity read failure occurred.",
            operationId: receipt.operationId,
            idempotencyKey: context.idempotencyKey,
            sandboxId,
          });
        if (remaining() <= 0) throw stopped("timeout");
      }
      const delay = round === 0 ? 5_000 : 10_000 + Math.floor(Math.random() * 5_000);
      const left = remaining();
      if (left <= 0) throw stopped("timeout");
      await new Promise<void>((resolve) => {
        // `setTimeout` in this scope is the sandbox lease method.
        const timer = globalThis.setTimeout(wake, Math.min(delay, left));
        function wake() {
          globalThis.clearTimeout(timer);
          options.signal?.removeEventListener("abort", wake);
          resolve();
        }
        options.signal?.addEventListener("abort", wake, { once: true });
      });
    }
  }

  async function create(input: CreateSandboxRequest, options: MutationOptions = {}) {
    const body = createSandboxBody(input);
    const key = options.idempotencyKey ?? generateKey();
    const run = await runMutation("createSandbox", key, options, (k, s) =>
      transport.request("createSandbox", { body, idempotencyKey: k, signal: s }),
    );
    const { receipt, context } = run;
    let deadline = run.deadline;
    if (input.waitForCapacityMs !== undefined) {
      const callerBudget =
        waitTimeout(options) !== undefined || waitTimeout(defaults) !== undefined;
      await waitForCapacity(
        receipt,
        input.waitForCapacityMs,
        options,
        context,
        callerBudget ? deadline : null,
      );
      // Without a caller budget, placement and readiness get a fresh default
      // budget once the create left the queue (the lease starts at placement).
      if (!callerBudget) deadline = new Deadline(resolvePolling(defaults, options).timeoutMs);
    }
    const operation = await awaitOperation("createSandbox", receipt, deadline, context, options);
    if (operation.sandboxId === null) {
      throw new WsspError({
        kind: "protocol",
        message: "createSandbox: the succeeded operation carries no sandbox ID.",
        operationId: receipt.operationId,
        idempotencyKey: key,
      });
    }
    requireLeaseAck(operation, context, "CREATE_SANDBOX");
    return bindSandbox(
      await waitIntentReady(operation.sandboxId, operation.generation ?? 0, options, deadline, {
        ...context,
        label: "createSandbox readiness",
      }),
    );
  }

  async function connect(id: string, options: ConnectOptions = {}): Promise<ConnectResult> {
    const key = options.idempotencyKey ?? generateKey();
    const body: ReconnectInput = {
      ...(options.mode !== undefined ? { mode: options.mode } : {}),
      ...(options.leaseTimeoutMs !== undefined ? { timeoutMs: options.leaseTimeoutMs } : {}),
      ...(options.credentials !== undefined ? { credentials: options.credentials } : {}),
      ...(options.sandboxHostId !== undefined ? { sandboxHostId: options.sandboxHostId } : {}),
      ...(options.poolId !== undefined ? { poolId: options.poolId } : {}),
      ...(options.waitForCapacityMs !== undefined
        ? { waitForCapacityMs: options.waitForCapacityMs }
        : {}),
    };
    const { receipt, deadline, context } = await runMutation(
      `reconnectSandbox ${id}`,
      key,
      options,
      (k, s) =>
        transport.request("reconnectSandbox", {
          params: { id },
          body,
          idempotencyKey: k,
          signal: s,
        }),
    );
    const operation = await awaitOperation(
      `reconnectSandbox ${id}`,
      receipt,
      deadline,
      context,
      options,
    );
    requireLeaseAck(operation, context, "RECONNECT_SANDBOX", id);
    const sandbox = await waitIntentReady(id, operation.generation ?? 0, options, deadline, {
      ...context,
      label: `reconnectSandbox ${id} readiness`,
    });
    return bindSandbox(sandbox);
  }

  async function captureTemplate(
    id: string,
    input: CaptureTemplateInput = {},
    options: MutationOptions = {},
  ): Promise<CaptureResult> {
    const key = options.idempotencyKey ?? generateKey();
    const { receipt, deadline, context } = await runMutation(
      `captureSandbox ${id}`,
      key,
      options,
      (k, s) =>
        transport.request("captureSandbox", {
          params: { id },
          body: {
            ...(input.templateId ? { templateId: input.templateId } : {}),
            ...(input.scrubPaths ? { scrubPaths: input.scrubPaths } : {}),
            ...(input.defaultDiskGiB !== undefined ? { defaultDiskGiB: input.defaultDiskGiB } : {}),
          },
          idempotencyKey: k,
          signal: s,
        }),
    );
    const operation = await awaitOperation(
      `captureSandbox ${id}`,
      receipt,
      deadline,
      context,
      options,
    );
    const revisionId = "capturedRevisionId" in operation ? operation.capturedRevisionId : undefined;
    if (!revisionId)
      throw new WsspError({
        kind: "protocol",
        message: `captureSandbox ${id}: the operation reported no revision.`,
        operationId: operation.id,
        idempotencyKey: context.idempotencyKey,
      });
    return { operationId: operation.id, revisionId };
  }

  async function stop(id: string, options: StopOptions = {}) {
    const key = options.idempotencyKey ?? generateKey();
    const { receipt, deadline, context } = await runMutation(
      `stopSandbox ${id}`,
      key,
      options,
      (k, s) =>
        transport.request("stopSandbox", {
          params: { id },
          body: stopBody(options),
          idempotencyKey: k,
          signal: s,
        }),
    );
    await awaitOperation(`stopSandbox ${id}`, receipt, deadline, context, options);
    // The host may report a successful stop as `absent` (the guest was already
    // gone or boot was interrupted before init). Proven absence ends DELETED;
    // a retained disk ends STOPPED and can be cold started; a disk moved to
    // storage while stopped reads OFFLOADED (a start restores it).
    return waitForState(
      id,
      context.label,
      (sandbox) =>
        sandbox.state === "STOPPED" || sandbox.state === "DELETED" || sandbox.state === "OFFLOADED",
      options,
      deadline,
      context,
    );
  }

  async function destroy(id: string, options: TeardownOptions = {}): Promise<void> {
    const key = options.idempotencyKey ?? generateKey();
    const { receipt, deadline, context } = await runMutation(
      `destroySandbox ${id}`,
      key,
      options,
      (k, s) =>
        transport.request("destroySandbox", {
          params: { id },
          body: teardownBody(options),
          idempotencyKey: k,
          signal: s,
        }),
    );
    await awaitOperation(`destroySandbox ${id}`, receipt, deadline, context, options);
    await waitDeleted(id, options, deadline, context);
  }

  async function attachCredential(
    id: string,
    input: AttachCredentialInput,
    options: MutationOptions = {},
  ): Promise<{ operationId: string }> {
    const key = options.idempotencyKey ?? generateKey();
    const label = `attachSandboxCredential ${id}`;
    const { receipt, deadline, context } = await runMutation(label, key, options, (k, s) =>
      transport.request("attachSandboxCredential", {
        params: { id },
        body: input,
        idempotencyKey: k,
        signal: s,
      }),
    );
    await awaitOperation(label, receipt, deadline, context, options);
    return { operationId: receipt.operationId };
  }

  async function freeCredential(
    id: string,
    credentialId: string,
    options: TeardownOptions = {},
  ): Promise<{ operationId: string }> {
    const key = options.idempotencyKey ?? generateKey();
    const label = `freeSandboxCredential ${id}`;
    const { receipt, deadline, context } = await runMutation(label, key, options, (k, s) =>
      transport.request("freeSandboxCredential", {
        params: { id, credentialId },
        body: teardownBody(options),
        idempotencyKey: k,
        signal: s,
      }),
    );
    await awaitOperation(label, receipt, deadline, context, options);
    return { operationId: receipt.operationId };
  }

  async function setTimeout(
    id: string,
    input: RenewLeaseInput,
    options: MutationOptions = {},
  ): Promise<RenewResult> {
    const key = options.idempotencyKey ?? generateKey();
    const { receipt, deadline, context } = await runMutation(
      `renewSandboxLease ${id}`,
      key,
      options,
      (k, s) =>
        transport.request("renewSandboxLease", {
          params: { id },
          body: input,
          idempotencyKey: k,
          signal: s,
        }),
    );
    const operation = await awaitOperation(
      `renewSandboxLease ${id}`,
      receipt,
      deadline,
      context,
      options,
    );
    const intent = requireLeaseAck(operation, context, "RENEW_SANDBOX_LEASE", id);
    // The exact durable ACK completes renewal. Expiry may already have moved
    // the sandbox to a later generation/state; return its current snapshot.
    const sandbox = await waitForState(id, context.label, () => true, options, deadline, context);
    if (sandbox.id !== id)
      throw new WsspError({
        kind: "protocol",
        message: `${context.label}: sandbox identity differs from the accepted intent.`,
        operationId: operation.id,
        idempotencyKey: context.idempotencyKey,
      });
    return {
      sandbox,
      effective: {
        expiresAt: intent.endAt,
        onExpire: intent.onTimeout === "kill" ? "destroy" : "stop",
      },
    };
  }

  function requireLeaseAck(
    operation: Awaited<ReturnType<typeof awaitOperation>>,
    context: PollContext,
    kind: "CREATE_SANDBOX" | "RECONNECT_SANDBOX" | "RENEW_SANDBOX_LEASE",
    sandboxId?: string,
  ) {
    if (
      operation.kind !== kind ||
      (sandboxId !== undefined && operation.sandboxId !== sandboxId) ||
      !("leaseIntent" in operation) ||
      operation.leaseIntent === null ||
      operation.leaseIntent.acknowledgedAt === null ||
      operation.leaseIntent.acknowledgedAttempt === null ||
      operation.leaseIntent.acknowledgedEpoch === null
    )
      throw new WsspError({
        kind: "protocol",
        message: `${context.label}: missing accepted lease acknowledgement.`,
        operationId: operation.id,
        idempotencyKey: context.idempotencyKey,
      });
    return operation.leaseIntent;
  }

  function refuseCapability(capability: string): never {
    throw new WsspError({
      kind: "unsupported",
      code: "UNSUPPORTED_CAPABILITY",
      message: `Unsupported capability: ${capability}.`,
    });
  }

  function update(id: string, input: UpdateSandboxInput, options: WaitOptions = {}) {
    return transport.request("updateSandbox", {
      params: { id },
      body: input,
      signal: options.signal,
      timeoutMs: waitTimeout(options),
    });
  }

  // Constructed in the client scope: this closure retains only the ID, never
  // the create request, environment, mutation options or response internals.
  function bindSandbox(snapshot: SandboxDto): Sandbox {
    const id = snapshot.id;
    const boundRef = (ref: ProcessRef) => {
      if (ref.sandboxId !== id)
        throw new WsspError({
          kind: "invalid_request",
          message: "Process reference belongs to a different sandbox.",
        });
      return ref;
    };
    const handle: Sandbox = {
      ...snapshot,
      sandbox: snapshot,
      capabilities: (options = {}) =>
        transport.request("getSandboxCapabilities", {
          params: { id },
          signal: options.signal,
          timeoutMs: waitTimeout(options),
        }),
      commands: Object.freeze({
        list: (options) => commands.list(id, options),
        connect: (ref, options) => commands.connect(boundRef(ref), options),
        signal: (ref, signal, options) => commands.signal(boundRef(ref), signal, options),
        kill: (ref, options) => commands.kill(boundRef(ref), options),
        writeStdin: (ref, data, options) => commands.writeStdin(boundRef(ref), data, options),
        closeStdin: (ref, options) => commands.closeStdin(boundRef(ref), options),
        run: (input, options) => commands.run(id, input, options),
        script: (script, options) => commands.script(id, script, options),
        argv: (argv, options) => commands.argv(id, argv, options),
        start: (input, options) => commands.start(id, input, options),
      }),
      files: Object.freeze({
        list: (path, options) => files.list(id, path, options),
        getInfo: (path, options) => files.getInfo(id, path, options),
        makeDir: (path, options) => files.makeDir(id, path, options),
        remove: (path, options) => files.remove(id, path, options),
        rename: (from, to, options) => files.rename(id, from, to, options),
        upload: (path, source, options) => files.upload(id, path, source, options),
        download: (path, options) => files.download(id, path, options),
        readBytes: (path, options) => files.readBytes(id, path, options),
        writeBytes: (path, data, options) => files.writeBytes(id, path, data, options),
        stat: (path, options) => files.stat(id, path, options),
        exists: (path, options) => files.exists(id, path, options),
      }),
      get: (options: WaitOptions = {}) =>
        transport.request("getSandbox", {
          params: { id },
          signal: options.signal,
          timeoutMs: waitTimeout(options),
        }),
      update: (input: UpdateSandboxInput, options?: WaitOptions) => update(id, input, options),
      connect: (options?: ConnectOptions) => connect(id, options),
      setTimeout: (input: RenewLeaseInput, options?: MutationOptions) =>
        setTimeout(id, input, options),
      stop: (options?: StopOptions) => stop(id, options),
      captureTemplate: (input?: CaptureTemplateInput, options?: MutationOptions) =>
        captureTemplate(id, input, options),
      destroy: (options?: TeardownOptions) => destroy(id, options),
      credentials: Object.freeze({
        attach: (input: AttachCredentialInput, options?: MutationOptions) =>
          attachCredential(id, input, options),
        free: (credentialId: string, options?: TeardownOptions) =>
          freeCredential(id, credentialId, options),
      }),
      tunnel: Object.freeze({
        expose: (input: ExposeTunnelBody = {}, options: WaitOptions = {}) =>
          transport.request("exposeSandboxTunnel", {
            params: { id },
            body: input,
            signal: options.signal,
            timeoutMs: waitTimeout(options),
          }),
        get: (options: WaitOptions = {}) =>
          transport.request("getSandboxTunnel", {
            params: { id },
            signal: options.signal,
            timeoutMs: waitTimeout(options),
          }),
        close: (options: WaitOptions = {}) =>
          transport.request("closeSandboxTunnel", {
            params: { id },
            signal: options.signal,
            timeoutMs: waitTimeout(options),
          }),
        link: (input: CreateTunnelLinkBody, options: WaitOptions = {}) =>
          transport.request("createSandboxTunnelLink", {
            params: { id },
            body: input,
            signal: options.signal,
            timeoutMs: waitTimeout(options),
          }),
        updatePorts: (input: UpdateTunnelPortsBody, options: WaitOptions = {}) =>
          transport.request("updateSandboxTunnelPorts", {
            params: { id },
            body: input,
            signal: options.signal,
            timeoutMs: waitTimeout(options),
          }),
      }),
      isAlive: (options?: MutationOptions) => isAlive(id, options),
      pause: async () => refuseCapability("pause"),
      snapshot: async () => refuseCapability("snapshot"),
      restore: async () => refuseCapability("restore"),
      fork: async () => refuseCapability("fork"),
      getHost: () => refuseCapability("ports"),
    };
    return Object.freeze(handle);
  }

  async function isAlive(id: string, options: MutationOptions = {}): Promise<boolean> {
    const key = options.idempotencyKey ?? generateKey();
    let submitted: Awaited<ReturnType<typeof runMutation>>;
    try {
      submitted = await runMutation(`probeSandbox ${id}`, key, options, (k, s) =>
        transport.request("probeSandbox", {
          params: { id },
          body: {},
          idempotencyKey: k,
          signal: s,
        }),
      );
    } catch (error) {
      if (error instanceof WsspError && error.code === "sandbox.not_found") return false;
      throw error;
    }
    const { receipt, deadline, context } = submitted;
    const operation = await waitOperation(
      transport,
      defaults,
      receipt.operationId,
      { ...withWaitTimeout(options, deadline.remaining(context)) },
      context,
    );
    // A probe may surface the confirmed-gone truth as a failure, from either
    // the operation code catalog or the SDK code catalog on a receipt.
    if (
      operation.outcome === "failed" &&
      (operation.errorCode === "sandbox_not_found" || operation.errorCode === "sandbox.not_found")
    ) {
      return false;
    }
    const observation = "observation" in operation ? operation.observation : null;
    if (operation.outcome === "succeeded") {
      if (observation === "guest_ready") return true;
      if (observation === "stopped" || observation === "confirmed_absent") return false;
    }
    if (observation === "unreachable") {
      // The server records an unreachable probe as UNKNOWN_OUTCOME. A retained
      // DELETED tombstone (or a confirmed 404) probes exactly this way, and
      // that IS a confirmed absence; anything else is genuinely unknown
      // liveness and must not read as false. The lookup runs through the
      // polling helper so the shared deadline, abort normalization and the
      // probe's operation ID / key apply to it as well.
      const tombstone = await poll<SandboxDto | null>(
        async (attempt) => ({
          done: true,
          value: await transport.findSandbox(id, { signal: attempt }),
        }),
        resolvePolling(defaults, pollingOf(options, deadline, context)),
        options.signal,
        context,
      );
      if (tombstone === null || tombstone.state === "DELETED") return false;
      throw new WsspError({
        kind: "unavailable",
        message: `probeSandbox ${id}: the host is unreachable.`,
        operationId: receipt.operationId,
        idempotencyKey: key,
      });
    }
    ensureSucceeded(operation, { ...context, label: `probeSandbox ${id}` });
    throw new WsspError({
      kind: "unavailable",
      message: `probeSandbox ${id}: the host returned no confirmed observation.`,
      operationId: receipt.operationId,
      idempotencyKey: key,
    });
  }

  return {
    capabilities: (id, options = {}) =>
      transport.request("getSandboxCapabilities", {
        params: { id },
        signal: options.signal,
        timeoutMs: waitTimeout(options),
      }),
    get: (id, options = {}) =>
      transport.request("getSandbox", {
        params: { id },
        signal: options.signal,
        timeoutMs: waitTimeout(options),
      }),
    find: (id, options = {}) =>
      transport.findSandbox(id, { signal: options.signal, timeoutMs: waitTimeout(options) }),
    list: async (query = {}, options = {}) => {
      const { limit, cursor, ...filters } = query;
      const parsed = sandboxListFiltersSchema.strict().safeParse(filters);
      if (
        !parsed.success ||
        (limit !== undefined && (!Number.isInteger(limit) || limit < 1 || limit > 100))
      ) {
        throw new WsspError({
          kind: "invalid_request",
          route: "listSandboxes",
          message: "Invalid sandbox list filters.",
        });
      }
      return transport.request("listSandboxes", {
        query: {
          ...parsed.data,
          cursor,
          limit: limit === undefined ? undefined : String(limit),
          metadata:
            parsed.data.metadata === undefined ? undefined : JSON.stringify(parsed.data.metadata),
          states: parsed.data.states === undefined ? undefined : parsed.data.states.join(","),
        },
        signal: options.signal,
        timeoutMs: waitTimeout(options),
      });
    },
    update,
    create,
    connect,
    stop,
    captureTemplate,
    destroy,
    attachCredential,
    freeCredential,
    setTimeout,
    isAlive,
    waitReady: (id, options) => waitReady(id, options),
    waitDeleted: (id, options) => waitDeleted(id, options),
  };
}

/** `sandbox.captureTemplate` input: defaults to the sandbox's own template. */
export type CaptureTemplateInput = {
  templateId?: string;
  scrubPaths?: string[];
  /** The new revision's `defaultDiskGiB` (>= this sandbox's disk, its minimum). */
  defaultDiskGiB?: number;
};
export type CaptureResult = { operationId: string; revisionId: string };

/** True for a create that failed because no host could provide the image. */
export function isImageUnavailable(error: unknown): boolean {
  return (
    error instanceof WsspError &&
    (error.code === "image_unavailable" || error.code === "sandbox.template_image_unavailable")
  );
}
