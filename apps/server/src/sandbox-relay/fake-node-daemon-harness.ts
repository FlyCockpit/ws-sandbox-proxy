/**
 * C57 wire-level host double for the lifecycle conformance suite
 * (`lifecycle-conformance.pg.test.ts`). It speaks the relay protocol to the
 * REAL `SandboxRelaySessionManager` (hello, receipt replay, census, dispatch,
 * output/file streams, cancel, probes and terminal frames) over an in-memory
 * socket, and models only what the Rust daemon and `FakeRuntime` do:
 *
 * - runtime: `crates/sandbox-runtime/src/fake/mod.rs` (VMs keyed by create
 *   idempotency key, stdout `exec:script:<script>\n`, exit 1 iff the script
 *   contains `exit 1` or `false`);
 * - journal: intent → effect → result phases that survive a host crash, and
 *   the restart receipt rules of `apps/cli/src/sandbox_relay/reconcile.rs`
 *   (`resolve_receipt` / `reconcile_effect`).
 *
 * The fault points are the rows of the shared cross-language fixture
 * `crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json`; the Rust
 * suite asserts the real daemon against the same rows. This file is a test
 * double: it never runs in production and owns no production state.
 */
import { createHash } from "node:crypto";
import type { HostLease } from "@wssp/api/sandbox/lease-wire";
import type { HostCommandStatus } from "@wssp/sandbox-contracts";
import {
  SANDBOX_RELAY_PROTOCOL_VERSION,
  TRANSFER_CHUNK_BYTES,
  type VmSize,
  vmSizeSchema,
} from "@wssp/sandbox-contracts";
import helloFixture from "../../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json";
import {
  encodeBinaryFrame,
  encodeTerminalDataFrame,
  parseBinaryFrame,
  type StreamBinaryMetadata,
  type TerminalFence,
} from "./protocol.js";
import { type SandboxRelaySocket, sandboxRelaySessionManager } from "./session-manager.js";

type Manager = typeof sandboxRelaySessionManager;
type Json = Record<string, unknown>;
export type HostIdentity = Parameters<Manager["acceptAuthenticatedSocket"]>[0]["identity"];

/** A host-side loss point: one row of the shared fault matrix. */
export type HostFault = {
  kind: "sandbox.create" | "command.run";
  /** Durable phase reached before the crash; `delivered`: result applied, confirmation lost. */
  journal: null | "intent" | "effect" | "result" | "delivered";
  /** Whether the runtime effect happened before the crash. */
  effect: boolean;
};

type Phase = "intent" | "effect" | "result";
type JournalEntry = {
  sandboxOwnerId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  attempt: number;
  bodyHash: string;
  idempotencyKey: string;
  kind: string;
  phase: Phase;
  lease?: HostLease;
  state?: "succeeded" | "failed" | "cancelled" | "unknown_outcome";
  result?: Json | null;
  error?: { code: string; message: string } | null;
};
type Vm = { createKey: string; state: "ready" | "stopped"; size: VmSize };
type LeaseRow = {
  generation: number;
  lease: HostLease;
  expired: boolean;
  expiryComplete: boolean;
  timerExpired: boolean;
};
/** A scripted guest program; unregistered scripts behave like FakeRuntime. */
export type FakeProgram = {
  stdout?: Uint8Array;
  stderr?: Uint8Array;
  exitCode?: number;
  /** Simulated guest time the program takes; advanced on the fake clock. */
  durationMs?: number;
  /** Holds completion until released (a long-running script). */
  gate?: Promise<void>;
};

export type FakeClock = { now(): Date; advance(ms: number): void; offsetMs(): number };
/** Real wall time plus a test-controlled offset: leases created at real "now" expire under it. */
export function fakeClock(): FakeClock {
  let offset = 0;
  return {
    now: () => new Date(Date.now() + offset),
    advance: (ms) => {
      offset += ms;
    },
    offsetMs: () => offset,
  };
}

class DaemonSocket implements SandboxRelaySocket {
  readyState = 1;
  bufferedAmount = 0;
  closes: { code?: number; reason?: string }[] = [];
  constructor(private readonly daemon: FakeNodeDaemon) {}
  send(data: string | ArrayBuffer | Uint8Array) {
    if (this.readyState !== 1) return;
    this.daemon.receive(this, data);
  }
  close(code?: number, reason?: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const OUTPUT_CHUNK = 8 * 1024;
const encoder = new TextEncoder();

function fakeExitCode(script: string): number {
  return script.includes("exit 1") || script.includes("false") ? 1 : 0;
}

export class FakeNodeDaemon {
  /** Host access test-double state: no real host command or filesystem effects. */
  agentPolicy = {
    hostCommands: false,
    hostFiles: false,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 0,
  };
  private agentSequence = 0;
  readonly hostCommands = new Map<string, HostCommandStatus>();
  async reportAgentPolicy() {
    const hello = this.received.findLast((f) => f.type === "hello.ok");
    if (!hello) throw new Error("not connected");
    await this.text({
      type: "host.agent-policy",
      connectionEpoch: hello.connectionEpoch,
      sequence: ++this.agentSequence,
      hostCommands: this.agentPolicy.hostCommands,
      hostFiles: this.agentPolicy.hostFiles,
      agentPolicyRevision: this.agentPolicy.agentPolicyRevision,
      ...(this.agentPolicy.hostCommands
        ? { hostCommandMaxMs: this.agentPolicy.hostCommandMaxMs }
        : {}),
    });
  }
  async finishHostCommand(commandId: string) {
    const status = this.hostCommands.get(commandId);
    if (!status) throw new Error("unknown host command");
    Object.assign(status, { state: "succeeded", exitCode: 0, finishedAt: Date.now() });
    await this.text({ type: "host.exec.status", ...status });
  }

  /** Durable across crashes (the host's disk). */
  readonly journal = new Map<string, JournalEntry>();
  readonly leases = new Map<string, LeaseRow>();
  readonly vms = new Map<string, Vm>();
  /** Changed only between connections, as a real daemon capacity override would be. */
  vmCapacity = { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 };
  private readonly workloadOwners = new Map<string, string>();
  readonly allocations = new Map<
    string,
    import("zod").z.infer<typeof import("@wssp/sandbox-contracts").pinnedAllocationV11Schema>
  >();
  private observationSequence = 0;
  private readonly journalId = "1234567890abcdef1234567890abcdef";
  private get storagePools() {
    return [
      {
        ...helloFixture.storagePools[0]!,
        capacitySource: "explicit" as const,
        health: "healthy" as const,
        reason: null,
        marker: `marker_${this.identity.hostId}`,
        capacityGiB: 8192,
        totalBasedCapacityGiB: null,
        derivationTotalBytes: null,
        derivationFreeBytes: null,
        derivationCommittedBytes: null,
        derivationActualBytes: null,
        derivationHeadroomBytes: null,
        implicitCeilingGiB: null,
      },
    ];
  }
  readonly files = new Map<string, Uint8Array>();
  /** Private retained host journal; separate from public VM metadata. */
  readonly privateConfigs = new Map<string, { reference: unknown; env: Array<[string, string]> }>();
  /** Modeled guest target environments, never command receipts or output. */
  readonly commandEnvs = new Map<string, Record<string, string>>();
  /** Runtime effect counters: what an uncertain retry must never raise. */
  readonly effects = { creates: 0, commands: new Map<string, number>(), puts: 0 };
  readonly programs = new Map<string, FakeProgram>();
  /** Every frame the server sent, in order (text frames parsed). */
  readonly received: Json[] = [];
  readonly receipts: Json[] = [];
  readonly dispatches: Json[] = [];
  socket: DaemonSocket | undefined;
  /** Incremented by every host process death; in-flight work of an older life stops. */
  private lives = 0;
  /** One-shot: the next download dies after its first chunk (a mid-capture host loss). */
  crashDuringDownload = false;
  /**
   * One-shot: the next download stops after its first chunk yet reports the
   * whole file's size and hash (a faulty host). The server must not trust it.
   */
  lieAboutDownload = false;
  private fault: HostFault | undefined;
  private emitChain: Promise<void> = Promise.resolve();
  private tasks = new Set<Promise<void>>();
  private cancelled = new Set<string>();
  private carryExpired = new Set<string>();
  private cancelWaiters = new Map<string, () => void>();
  private cancelHold: Promise<void> | undefined;
  /** Unexpected task failures; a conformance test asserts this stays empty. */
  readonly failures: unknown[] = [];
  private uploads = new Map<
    string,
    { parts: Uint8Array[]; done: (bytes: Uint8Array) => void; fail: (error: Error) => void }
  >();
  private terminals = new Map<string, { fence: TerminalFence; sent: number; acked: number }>();
  private pendingReceiptAcks = new Map<string, () => void>();

  constructor(
    private readonly manager: Manager,
    private readonly identity: HostIdentity,
    private readonly clock: FakeClock,
    private readonly options: {
      terminal?: boolean;
      admission?: boolean;
      afterAdmission?: () => Promise<void>;
      /** Host lease ceiling in the hello; null = unlimited (default 24h). */
      maxLeaseMs?: number | null;
      /** Default-open egress: static open capability (default true). */
      egressOpen?: boolean;
      /** Guard health reported after admission (default healthy). */
      guardOk?: boolean;
      /** Node-owner consent for other users' open sandboxes (default false). */
      openEgressForOthers?: boolean;
      /** WP7: advertise the `quiesce` capability (default false). */
      quiesce?: boolean;
    } = {},
  ) {}

  /** WP7: survives reconnects; every hello carries `quiescing: true` while set. */
  quiescing = false;
  private quiesceSequence = 0;
  /** WP7: send `host.quiesce` on the current link and stay quiescing. */
  async quiesce() {
    const hello = this.received.findLast((f) => f.type === "hello.ok");
    if (!this.socket || !hello) throw new Error("not connected");
    this.quiescing = true;
    await this.text({
      type: "host.quiesce",
      connectionEpoch: hello.connectionEpoch,
      sequence: ++this.quiesceSequence,
    });
  }

  private egressSequence = 0;
  /** Send `host.egress-state` on the current link (a lease renewal). */
  async reportEgressState(
    connectionEpoch: number,
    report: { guardOk?: boolean; openEgressForOthers?: boolean } = {},
  ) {
    const guardOk = report.guardOk ?? this.options.guardOk ?? true;
    this.egressSequence += 1;
    await this.text({
      type: "host.egress-state",
      connectionEpoch,
      sequence: this.egressSequence,
      allowOpenForOthers: report.openEgressForOthers ?? this.options.openEgressForOthers ?? false,
      allowGuestSudoForOthers: false,
      guardOk,
      ...(guardOk ? {} : { guardReason: "guard_not_running" }),
      ...(guardOk ? { guardInstanceId: "fake-guard", guardGeneration: 1 } : {}),
    });
  }

  /** One-shot: the next dispatch of `fault.kind` crashes the host at that boundary. */
  arm(fault: HostFault) {
    this.fault = fault;
  }
  /** Hold every operation.cancel until released (capture-safety probes). */
  holdCancels(hold: Promise<void> | undefined) {
    this.cancelHold = hold;
  }
  /**
   * The host's `max_carry` cap (WP3, D2): stop a running command, as the real
   * daemon does once its proven stop lands, and settle it FAILED
   * `host_disconnect_expired`. Works while the server is away (C13).
   */
  expireCarry(operationId: string) {
    this.carryExpired.add(operationId);
    this.cancelWaiters.get(operationId)?.();
  }
  commandEffects(operationId: string) {
    return this.effects.commands.get(operationId) ?? 0;
  }

  /** Connect (or reconnect after a crash): hello, receipt replay, census, reconcile. */
  async connect(): Promise<void> {
    this.agentSequence = 0;
    const socket = new DaemonSocket(this);
    this.socket = socket;
    const seen = this.received.length;
    this.manager.acceptAuthenticatedSocket({ socket, identity: this.identity });
    const versions = this.options.admission
      ? [SANDBOX_RELAY_PROTOCOL_VERSION]
      : this.options.terminal
        ? [SANDBOX_RELAY_PROTOCOL_VERSION]
        : [SANDBOX_RELAY_PROTOCOL_VERSION];
    await this.text({
      type: "hello",
      id: `hello-${Date.now()}`,
      protocolVersion: SANDBOX_RELAY_PROTOCOL_VERSION,
      supportedProtocolVersions: versions,
      daemon: {
        hostId: this.identity.hostId,
        label: "c57-fake-daemon",
        capabilities: {
          protocolVersion: SANDBOX_RELAY_PROTOCOL_VERSION,
          binaryFrames: true,
          cancellation: true,
          operationWal: true,
          hostInventory: true,
          maxBinaryChunkBytes: 1024 * 1024,
          streamWindowChunks: 4,
          runtimeKind: "fake",
          egressPolicy: true,
          terminal: this.options.terminal ?? false,
          hostManagedSandboxCeiling: 250,
          hostTerminal: false,
          ...(this.agentPolicy.hostCommands
            ? {
                hostCommands: true,
                hostFiles: this.agentPolicy.hostFiles,
                hostCommandMaxMs: this.agentPolicy.hostCommandMaxMs,
              }
            : {}),
          ...(this.agentPolicy.agentPolicyRevision
            ? { agentPolicyRevision: this.agentPolicy.agentPolicyRevision }
            : {}),
          requireHostTerminalTotp: true,
          policyRevision: 0,
          maxOutputChunkBytes: 8192,
          censusEntryResults: true,
          pendingReceipts: true,
          expiryStatusResults: true,
          observationFence: true,
          commandRetire: true,
          maxLeaseMs: this.options.maxLeaseMs === undefined ? 86_400_000 : this.options.maxLeaseMs,
          egress: {
            open: this.options.egressOpen ?? true,
            guard: this.options.guardOk ?? true,
          },
          ...(this.options.quiesce ? { quiesce: true } : {}),
        },
      },
      ...(this.quiescing ? { quiescing: true } : {}),
      inventory: {
        hostId: this.identity.hostId,
        schedulable: true,
        sandboxCount: this.vms.size,
      },
      vmCapacity: this.vmCapacity,
      storagePools: this.storagePools,
    });
    if (this.socket !== socket || !this.received.slice(seen).some((f) => f.type === "hello.ok"))
      throw new Error(`hello refused: ${JSON.stringify(this.received.slice(seen))}`);
    {
      const hello = this.received.slice(seen).find((frame) => frame.type === "hello.ok")!;
      await this.text({
        type: "host.admission",
        connectionEpoch: hello.connectionEpoch,
        runtimeKind: "fake",
        schedulable: true,
        egressPolicy: true,
        terminal: this.options.terminal ?? false,
        vmCapacity: this.vmCapacity,
        storagePools: this.storagePools,
        journalId: this.journalId,
        egressOpen: this.options.egressOpen ?? true,
      });
      // A current daemon renews its egress guard lease right after admission
      // (and every 5 s; `reportEgressState` models a later report).
      this.egressSequence = 0;
      await this.reportEgressState(hello.connectionEpoch as number);
      await this.options.afterAdmission?.();
    }
    // reconcile.rs: later generations first, one outstanding receipt at a time.
    const pending = [...this.journal.values()].sort((a, b) => b.generation - a.generation);
    for (const entry of pending) {
      const resolved = this.resolveReceipt(entry);
      const acked = new Promise<void>((resolve) =>
        this.pendingReceiptAcks.set(entry.operationId, resolve),
      );
      const receipt = {
        type: "operation.receipt",
        sandboxOwnerId: resolved.sandboxOwnerId,
        operationId: resolved.operationId,
        sandboxId: resolved.sandboxId,
        generation: resolved.generation,
        attempt: resolved.attempt,
        bodyHash: resolved.bodyHash,
        idempotencyKey: resolved.idempotencyKey,
        kind: resolved.kind,
        state: resolved.state!,
        result: resolved.result ?? null,
        error: resolved.error ?? null,
      };
      this.receipts.push(receipt);
      await this.text(receipt);
      await acked;
    }
    const census = this.census();
    for (let page = 0; page === 0 || page * 64 < census.length; page++) {
      const entries = census.slice(page * 64, page * 64 + 64);
      await this.text({
        type: "sandbox.inventory",
        page,
        complete: (page + 1) * 64 >= census.length,
        entries,
      });
    }
    await this.text({ type: "reconcile.complete" });
  }

  /** Host process death: the socket drops, in-flight tasks stop, the journal stays. */
  crash() {
    this.lives += 1;
    // In-flight effects of this life end with the process.
    for (const upload of this.uploads.values()) upload.fail(new HostCrashed());
    this.uploads.clear();
    for (const wake of this.cancelWaiters.values()) wake();
    // Its PTYs die with it: nothing is adopted by the next process (C52).
    this.terminals.clear();
    const socket = this.socket;
    if (!socket) return;
    this.socket = undefined;
    socket.readyState = 3;
    this.manager.removeSession(socket);
  }

  async reportStorage() {
    const hello = this.received.findLast((f) => f.type === "hello.ok");
    if (!this.socket || !hello) return;
    await this.text({
      type: "inventory.update",
      id: `health-${++this.observationSequence}`,
      connectionEpoch: hello.connectionEpoch,
      observationSequence: this.observationSequence,
      inventory: { hostId: this.identity.hostId, schedulable: true, sandboxCount: this.vms.size },
      storagePools: this.storagePools.map(
        ({ name, marker, health, reason, totalBytes, usedBytes, freeBytes }) => ({
          name,
          marker,
          health,
          reason,
          totalBytes,
          usedBytes,
          freeBytes,
        }),
      ),
    });
  }

  /** Server-side loss of this host's socket (server restart): the host keeps its work. */
  serverDrop() {
    const socket = this.socket;
    if (!socket) return;
    this.manager.removeSession(socket);
    this.socket = undefined;
  }

  async idle() {
    while (this.tasks.size > 0) await Promise.allSettled([...this.tasks]);
    await this.emitChain;
  }

  // ── server → host ──────────────────────────────────────────────────

  receive(socket: DaemonSocket, data: string | ArrayBuffer | Uint8Array) {
    if (socket !== this.socket) return;
    if (typeof data !== "string") {
      const buffer =
        data instanceof Uint8Array
          ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
          : data;
      this.binary(socket, buffer as ArrayBuffer);
      return;
    }
    const message = JSON.parse(data) as Json;
    this.received.push(message);
    switch (message.type) {
      case "host.policy.lower":
        if (message.target === "hostCommands") {
          this.agentPolicy.hostCommands = false;
          this.agentPolicy.hostFiles = false;
          this.agentPolicy.agentPolicyRevision++;
          for (const status of this.hostCommands.values())
            if (status.state === "running")
              Object.assign(status, { state: "cancelled", finishedAt: Date.now() });
          this.track(
            this.reportAgentPolicy().then(() =>
              this.text(
                { type: "host.policy.lower.result", requestId: message.requestId, ok: true },
                socket,
              ),
            ),
          );
        } else
          this.track(
            this.text(
              { type: "host.policy.lower.result", requestId: message.requestId, ok: true },
              socket,
            ),
          );
        return;
      case "host.exec.start": {
        const commandId = message.commandId as string;
        const reason =
          message.ownerId !== this.identity.userId
            ? "owner_mismatch"
            : !this.agentPolicy.hostCommands
              ? "host_commands_off"
              : message.agentPolicyRevision !== this.agentPolicy.agentPolicyRevision
                ? "policy_changed"
                : undefined;
        if (reason) {
          this.track(
            this.text(
              { type: "host.exec.rejected", requestId: message.requestId, commandId, reason },
              socket,
            ),
          );
          return;
        }
        const startedAt = Date.now();
        const endsBy = startedAt + (message.timeoutMs as number);
        this.hostCommands.set(commandId, {
          commandId,
          state: "running",
          startedAt,
          endsBy,
          stdout: { offset: 0, data: "", dropped: false },
          stderr: { offset: 0, data: "", dropped: false },
          stdoutBytes: 0,
          stderrBytes: 0,
        });
        this.track(
          this.text(
            {
              type: "host.exec.started",
              requestId: message.requestId,
              commandId,
              startedAt,
              endsBy,
            },
            socket,
          ),
        );
        return;
      }
      case "host.exec.poll":
      case "host.exec.cancel": {
        const status = this.hostCommands.get(message.commandId as string);
        if (!status) return;
        if (message.type === "host.exec.cancel")
          Object.assign(status, { state: "cancelled", finishedAt: Date.now() });
        this.track(
          this.text({ type: "host.exec.status", requestId: message.requestId, ...status }, socket),
        );
        return;
      }
      case "host.exec.stdin":
        this.track(
          this.text(
            {
              type: "host.exec.stdin.result",
              requestId: message.requestId,
              commandId: message.commandId,
              accepted: true,
            },
            socket,
          ),
        );
        return;
      case "host.file.request":
        this.track(
          this.text(
            {
              type: "host.file.result",
              requestId: message.requestId,
              ok: false,
              error: "not_found",
            },
            socket,
          ),
        );
        return;

      case "allocation.attest.request":
        this.track(
          this.text(
            {
              type: "allocation.attest.result",
              connectionEpoch: message.connectionEpoch,
              barrier: message.barrier,
              journalId: this.journalId,
              entries: (message.sandboxIds as string[]).map((sandboxId) => ({
                sandboxId,
                sandboxOwnerId: (
                  message.allocations as { sandboxId: string; sandboxOwnerId: string }[]
                ).find((p) => p.sandboxId === sandboxId)?.sandboxOwnerId,
                settledNeverIssued:
                  !this.vms.has(sandboxId) &&
                  ![...this.journal.values()].some((e) => e.sandboxId === sandboxId),
              })),
            },
            socket,
          ),
        );
        return;
      case "journal.key.install":
        this.track(
          this.text(
            {
              type: "journal.key.ack",
              connectionEpoch: message.connectionEpoch,
              keyVersion: message.keyVersion,
              keyId: message.keyId,
            },
            socket,
          ),
        );
        return;
      case "private.config.install": {
        const frame = message as Extract<
          import("./protocol.js").ServerControlMessage,
          { type: "private.config.install" }
        >;
        if (frame.hostOwnerId !== this.identity.userId || frame.hostId !== this.identity.hostId)
          return;
        this.privateConfigs.set(frame.sandboxId, {
          reference: frame.config,
          env: structuredClone(frame.env),
        });
        this.track(
          this.text(
            {
              type: "private.config.ack",
              sandboxOwnerId: frame.sandboxOwnerId,
              connectionEpoch: frame.connectionEpoch,
              sandboxId: frame.sandboxId,
              generation: frame.generation,
              config: frame.config,
            },
            socket,
          ),
        );
        return;
      }
      case "availability.request":
        this.track(
          this.text(
            {
              type: "availability.result",
              requestId: message.requestId,
              connectionEpoch: message.connectionEpoch,
              page: message.page,
              entries: (message.bindings as import("./protocol.js").AvailabilityBinding[]).map(
                (binding) => ({ binding, status: "present" }),
              ),
            },
            socket,
          ),
        );
        return;
      case "operation.dispatch":
        this.dispatches.push(message);
        this.track(this.dispatch(socket, message));
        return;
      case "receipt.confirmed": {
        const receipt = this.journal.get(String(message.operationId));
        if (
          receipt &&
          receipt.sandboxOwnerId === message.sandboxOwnerId &&
          receipt.sandboxId === message.sandboxId &&
          receipt.generation === message.generation &&
          receipt.attempt === message.attempt &&
          receipt.bodyHash === message.bodyHash &&
          receipt.idempotencyKey === message.idempotencyKey &&
          receipt.kind === message.kind
        )
          this.journal.delete(String(message.operationId));
        return;
      }
      case "receipt.ack":
        this.pendingReceiptAcks.get(String(message.operationId))?.();
        this.pendingReceiptAcks.delete(String(message.operationId));
        return;
      case "operation.cancel":
        this.track(this.cancel(message));
        return;
      case "sandbox.probe.request": {
        const vm = this.vms.get(String(message.sandboxId));
        this.track(
          this.text({
            type: "sandbox.probe.result",
            requestId: message.requestId,
            state: vm?.state === "ready" ? "guest_ready" : vm ? "stopped" : "confirmed_absent",
          }),
        );
        return;
      }
      case "terminal.open":
        this.track(this.terminalOpen(message));
        return;
      case "terminal.ack": {
        const fence = message.fence as TerminalFence;
        const session = this.terminals.get(fence.sessionId);
        if (session) session.acked = Math.max(session.acked, Number(message.sequence) + 1);
        return;
      }
      case "terminal.close": {
        const fence = message.fence as TerminalFence;
        this.terminals.delete(fence.sessionId);
        this.track(
          this.text({
            type: "terminal.exit",
            requestId: message.requestId,
            fence,
            intent: message.intent,
            reaped: true,
          }),
        );
        return;
      }
      default:
        return;
    }
  }

  private binary(socket: DaemonSocket, frame: ArrayBuffer) {
    const { metadata, body } = parseBinaryFrame(frame);
    if (!metadata.flags?.fileUpload) return;
    const upload = this.uploads.get(metadata.operationId);
    if (!upload) return;
    upload.parts.push(Uint8Array.from(body));
    const offset = (metadata.offset ?? 0) + body.byteLength;
    this.track(
      this.text(
        {
          type: "file.chunk.ack",
          operationId: metadata.operationId,
          generation: metadata.generation,
          attempt: metadata.attempt,
          sequence: metadata.sequence,
          offset,
        },
        socket,
      ),
    );
    if (metadata.final || metadata.type === "stream.end")
      upload.done(new Uint8Array(Buffer.concat(upload.parts)));
  }

  // ── dispatch execution (journal phases mirror supervisor.rs) ─────────

  private async dispatch(socket: DaemonSocket, d: Json) {
    const operationId = String(d.operationId);
    const kind = String(d.kind);
    const existing = this.journal.get(operationId);
    if (existing) {
      // journal.rs Decision::Replay / Unknown: a redelivered dispatch never
      // repeats the effect; it reports what the journal knows.
      const resolved = existing.phase === "result" ? existing : this.resolveReceipt(existing);
      await this.result(socket, resolved);
      return;
    }
    const fault = this.fault?.kind === kind ? this.fault : undefined;
    if (fault) this.fault = undefined;
    if (fault && fault.journal === null) return this.crash();
    const sandboxOwnerId = String(d.sandboxOwnerId);
    if (
      this.workloadOwners.has(String(d.sandboxId)) &&
      this.workloadOwners.get(String(d.sandboxId)) !== sandboxOwnerId
    )
      throw new Error("workload identity changed");
    this.workloadOwners.set(String(d.sandboxId), sandboxOwnerId);
    const entry: JournalEntry = {
      sandboxOwnerId,
      operationId,
      sandboxId: String(d.sandboxId),
      generation: Number(d.generation),
      attempt: Number(d.attempt),
      bodyHash: String(d.bodyHash),
      idempotencyKey: String(d.idempotencyKey),
      kind,
      phase: "intent",
      ...(d.lease ? { lease: d.lease as HostLease } : {}),
    };
    this.journal.set(operationId, entry);
    if (entry.lease && entry.kind !== "sandbox.stop" && entry.kind !== "sandbox.kill") {
      const current = this.leases.get(entry.sandboxId);
      const now = this.clock.now().getTime();
      const sameGeneration = current?.generation === entry.generation;
      const stale = current && sameGeneration && entry.lease.revision < current.lease.revision;
      const observation = stale && entry.kind === "sandbox.reconnect";
      const lapsed = current && (current.expired || now >= current.lease.deadlineUnixMs);
      const refused =
        (current && entry.generation < current.generation) ||
        (sameGeneration && lapsed) ||
        (stale && !observation) ||
        (sameGeneration &&
          !observation &&
          entry.kind === "sandbox.reconnect" &&
          current &&
          entry.lease.deadlineUnixMs < current.lease.deadlineUnixMs) ||
        (!observation && entry.lease.deadlineUnixMs <= now) ||
        (current &&
          !sameGeneration &&
          lapsed &&
          (!current.expiryComplete || current.lease.action === "destroy"));
      if (refused) {
        Object.assign(entry, {
          phase: "result",
          state: "failed",
          result: null,
          error: { code: "state_conflict", message: "lease was not durably accepted" },
        });
        await this.result(socket, entry);
        return;
      }
      if (!observation)
        this.leases.set(entry.sandboxId, {
          generation: entry.generation,
          lease: entry.lease,
          expired: false,
          expiryComplete: false,
          timerExpired: false,
        });
    }
    if (fault?.journal === "intent") return this.crash();
    const life = this.lives;
    // connect.rs: a fresh intent is acknowledged `accepted` before any effect.
    await this.text(
      {
        type: "operation.progress",
        id: `accepted-${operationId}`,
        operationId,
        sandboxId: entry.sandboxId,
        generation: entry.generation,
        attempt: entry.attempt,
        state: "accepted",
      },
      socket,
    );
    if (life !== this.lives) return;
    entry.phase = "effect";
    if (fault?.journal === "effect" && !fault.effect) return this.crash();
    let outcome: Pick<JournalEntry, "state" | "result" | "error">;
    try {
      outcome = await this.effect(socket, entry, d);
    } catch (error) {
      if (error instanceof HostCrashed) return;
      throw error;
    }
    // A host that died during the effect records nothing more (no Result).
    if (life !== this.lives) return;
    if (fault?.journal === "effect") return this.crash();
    Object.assign(entry, outcome, { phase: "result" });
    if (fault?.journal === "result") return this.crash();
    await this.result(socket, entry);
    if (fault?.journal === "delivered") {
      // The result was applied; the confirmation is lost with the process.
      this.journal.set(operationId, entry);
      this.crash();
    }
  }

  private async effect(
    socket: DaemonSocket,
    entry: JournalEntry,
    d: Json,
  ): Promise<Pick<JournalEntry, "state" | "result" | "error">> {
    const vm = this.vms.get(entry.sandboxId);
    const ok = (result: Json) => ({ state: "succeeded" as const, result, error: null });
    const failed = (code: string, message: string) => ({
      state: "failed" as const,
      result: null,
      error: { code, message },
    });
    switch (entry.kind) {
      case "sandbox.create": {
        // FakeState::create_sandbox: the create key binds the VM; a retry is a no-op.
        if (!vm) {
          const a = (
            d as Extract<
              import("./protocol.js").ServerControlMessage,
              { type: "operation.dispatch" }
            >
          ).allocation;
          const size = vmSizeSchema.parse({
            cpuCount: d.cpuCount,
            memoryMiB: d.memoryMiB,
            diskGiB: a?.diskGiB,
          });
          if (!a) return failed("protocol_error", "missing allocation");
          this.allocations.set(entry.sandboxId, a);
          this.vms.set(entry.sandboxId, { createKey: entry.idempotencyKey, state: "ready", size });
          this.effects.creates += 1;
        }
        return ok({ state: "ready", lease: entry.lease });
      }
      case "sandbox.reconnect":
        if (!vm) return failed("sandbox_not_found", "no instance");
        if (
          vm.size.cpuCount !== d.cpuCount ||
          vm.size.memoryMiB !== d.memoryMiB ||
          vm.size.diskGiB !== (d.allocation as { diskGiB?: number } | undefined)?.diskGiB
        )
          return failed("vm_size_mismatch", "VM allocation mismatch.");
        vm.state = "ready";
        return ok({ state: "ready", lease: entry.lease });
      case "sandbox.lease.renew":
        return ok({ lease: entry.lease });
      case "sandbox.stop":
        if (vm) vm.state = "stopped";
        this.latchLease(entry.sandboxId);
        return ok({ state: vm ? "stopped" : "absent" });
      case "sandbox.kill":
        this.vms.delete(entry.sandboxId);
        this.latchLease(entry.sandboxId, true);
        return ok({ state: "deleted" });
      case "command.run":
        return this.run(socket, entry, d);
      case "file.put": {
        const upload = new Promise<Uint8Array>((done, fail) =>
          this.uploads.set(entry.operationId, { parts: [], done, fail }),
        );
        const bytes = await upload;
        this.uploads.delete(entry.operationId);
        const path = String(d.destPath ?? d.path);
        this.files.set(`${entry.sandboxId}:${path}`, bytes);
        this.effects.puts += 1;
        return ok({ path, size: bytes.byteLength });
      }
      case "file.get": {
        const bytes = this.files.get(`${entry.sandboxId}:${String(d.path)}`);
        if (!bytes) return failed("not_found", "no such file");
        for (let sequence = 0, offset = 0; ; sequence++) {
          const body = bytes.subarray(offset, offset + TRANSFER_CHUNK_BYTES);
          const final = offset + body.byteLength >= bytes.byteLength;
          await this.binaryOut(socket, {
            type: final ? "stream.end" : "stream.chunk",
            streamId: `download-${entry.operationId}`,
            operationId: entry.operationId,
            generation: entry.generation,
            attempt: entry.attempt,
            sequence,
            offset,
            flags: { fileDownload: true },
            final,
            body,
          });
          offset += body.byteLength;
          if (this.lieAboutDownload && !final) {
            this.lieAboutDownload = false;
            break;
          }
          if (this.crashDuringDownload && !final) {
            this.crashDuringDownload = false;
            this.crash();
            throw new HostCrashed();
          }
          if (final) break;
        }
        return ok({ size: bytes.byteLength, sha256: sha256(bytes) });
      }
      case "file.stat": {
        const present = this.files.has(`${entry.sandboxId}:${String(d.path)}`);
        if (present) {
          const path = String(d.path);
          return ok({
            version: 1,
            observedAt: this.clock.now().toISOString(),
            payload: {
              type: "file.stat",
              entry: {
                path,
                name: path === "/" ? "/" : path.slice(path.lastIndexOf("/") + 1),
                type: "file",
                size: this.files.get(`${entry.sandboxId}:${path}`)!.byteLength,
                mode: 0o644,
                permissions: "rw-r--r--",
                uid: 1000,
                gid: 1000,
                owner: null,
                group: null,
                modifiedTime: null,
                symlinkTarget: null,
              },
            },
            continuation: null,
            birth: null,
            failure: null,
          });
        }
        return failed("not_found", "no such file");
      }
      default:
        return failed("unsupported_capability", `fake daemon does not run ${entry.kind}`);
    }
  }

  private latchLease(sandboxId: string, destroyed = false) {
    const row = this.leases.get(sandboxId);
    if (row && (destroyed || row.lease.action === "stop"))
      Object.assign(row, { expired: true, expiryComplete: true });
  }

  private async run(socket: DaemonSocket, entry: JournalEntry, d: Json) {
    const defaults = this.privateConfigs.get(entry.sandboxId)?.env ?? [];
    const overrides = (d.env ?? []) as Array<[string, string]>;
    this.commandEnvs.set(entry.operationId, Object.fromEntries([...defaults, ...overrides]));
    const script = typeof d.script === "string" ? d.script : ((d.argv as string[]) ?? []).join(" ");
    const program = this.programs.get(script);
    this.effects.commands.set(entry.operationId, this.commandEffects(entry.operationId) + 1);
    const startedAt = this.clock.now().toISOString();
    const process = {
      sandboxId: entry.sandboxId,
      generation: entry.generation,
      attempt: entry.attempt,
      processId: String(d.processId),
      pid: 42,
    };
    const birth = {
      type: "process.started",
      ...process,
      operationId: entry.operationId,
      bootId: "00000000-0000-0000-0000-000000000001",
      startTicks: "1",
      startedAt,
      observedAt: startedAt,
    };
    await this.text(birth, socket);
    const commandResult = (exitCode: number | null, outputBytes: number) => ({
      version: 1,
      observedAt: this.clock.now().toISOString(),
      payload: { type: "command", process, startedAt, exitCode },
      birth,
      continuation: null,
      failure: null,
      outputBytes,
    });
    const stdout = program?.stdout ?? encoder.encode(`exec:script:${script}\n`);
    const stderr = program?.stderr ?? new Uint8Array();
    let offset = 0;
    let sequence = 0;
    const stream = async (bytes: Uint8Array, flag: "stdout" | "stderr") => {
      for (let at = 0; at < bytes.byteLength; at += OUTPUT_CHUNK) {
        if (this.cancelled.has(entry.operationId) || this.carryExpired.has(entry.operationId))
          return;
        const body = bytes.subarray(at, at + OUTPUT_CHUNK);
        await this.binaryOut(socket, {
          type: "stream.chunk",
          streamId: entry.operationId,
          operationId: entry.operationId,
          generation: entry.generation,
          attempt: entry.attempt,
          sequence: sequence++,
          offset,
          flags: { [flag]: true },
          body,
        });
        offset += body.byteLength;
      }
    };
    await stream(stdout, "stdout");
    if (program?.durationMs) this.clock.advance(program.durationMs);
    if (
      program?.gate &&
      !this.cancelled.has(entry.operationId) &&
      !this.carryExpired.has(entry.operationId)
    )
      await Promise.race([
        program.gate,
        new Promise<void>((resolve) => this.cancelWaiters.set(entry.operationId, resolve)),
      ]);
    this.cancelWaiters.delete(entry.operationId);
    await stream(stderr, "stderr");
    if (this.carryExpired.has(entry.operationId))
      return {
        state: "failed" as const,
        result: commandResult(null, offset),
        error: { code: "host_disconnect_expired", message: "carry window expired" },
      };
    if (this.cancelled.has(entry.operationId))
      return {
        state: "cancelled" as const,
        result: commandResult(null, offset),
        error: { code: "cancelled", message: "command cancelled" },
      };
    return {
      state: "succeeded" as const,
      result: commandResult(program?.exitCode ?? fakeExitCode(script), offset),
      error: null,
    };
  }

  /** The cancel ACK is the target's terminal `cancelled` result, sent by `run`. */
  private async cancel(message: Json) {
    if (this.cancelHold) await this.cancelHold;
    const operationId = String(message.operationId);
    this.cancelled.add(operationId);
    this.cancelWaiters.get(operationId)?.();
  }

  /**
   * reconcile.rs restart rules for a receipt whose Result was not recorded.
   * The resolved row is journaled exactly as `record_reconciled_result` does.
   */
  private resolveReceipt(entry: JournalEntry): JournalEntry {
    if (entry.phase === "result") {
      // reconcile.rs: download bytes do not survive a restart, so a recorded
      // successful file.get is reported unknown (the durable row is unchanged).
      if (entry.kind === "file.get" && entry.state === "succeeded")
        return {
          ...entry,
          state: "unknown_outcome",
          result: null,
          error: { code: "unknown_outcome", message: "download bytes no longer retained" },
        };
      return entry;
    }
    const settle = (
      state: NonNullable<JournalEntry["state"]>,
      result: Json | null,
      error: JournalEntry["error"],
    ) => Object.assign(entry, { phase: "result" as const, state, result, error });
    const allocation = entry.kind === "sandbox.create" || entry.kind === "sandbox.reconnect";
    if (allocation && entry.phase === "intent")
      return settle("failed", null, {
        code: "host_effect_not_issued",
        message: "allocation interrupted before issue",
      });
    if (allocation && !entry.lease)
      return settle("unknown_outcome", null, {
        code: "unknown_outcome",
        message: "missing durable lease decision",
      });
    const vm = this.vms.get(entry.sandboxId);
    const end =
      allocation && vm?.state === "ready" && vm.createKey === entry.idempotencyKey
        ? "ready"
        : entry.kind === "sandbox.stop" && vm?.state === "stopped"
          ? "stopped"
          : entry.kind === "sandbox.stop" && !vm
            ? "absent"
            : entry.kind === "sandbox.kill" && !vm
              ? "deleted"
              : null;
    if (end)
      return settle(
        "succeeded",
        { state: end, ...(entry.lease ? { lease: entry.lease } : {}) },
        null,
      );
    return settle("unknown_outcome", null, {
      code: "unknown_outcome",
      message: "host query does not prove the expected end state",
    });
  }

  private census() {
    const ids = new Set([...this.vms.keys(), ...this.leases.keys()]);
    return [...ids].sort().map((sandboxId) => {
      const vm = this.vms.get(sandboxId);
      const lease = this.leases.get(sandboxId);
      return {
        sandboxId,
        sandboxOwnerId: this.workloadOwners.get(sandboxId) ?? null,
        state: vm?.state ?? "absent",
        root: this.allocations.has(sandboxId)
          ? {
              storagePoolName: this.allocations.get(sandboxId)!.storagePoolName,
              storageMarker: this.allocations.get(sandboxId)!.storageMarker,
              diskGiB: this.allocations.get(sandboxId)!.diskGiB,
              state: vm ? "present" : "absent",
              networkCleanupComplete: !vm,
              observationSequence: ++this.observationSequence,
            }
          : null,
        ...(lease
          ? {
              lease: {
                generation: lease.generation,
                lease: lease.lease,
                expired: lease.expired,
                expiryComplete: lease.expiryComplete,
                timerExpired: lease.timerExpired,
              },
            }
          : {}),
      };
    });
  }

  // ── terminal (C52) ──────────────────────────────────────────────────

  private async terminalOpen(message: Json) {
    const fence = message.fence as TerminalFence;
    this.terminals.set(fence.sessionId, { fence, sent: 0, acked: 0 });
    await this.text({
      type: "terminal.ready",
      requestId: message.requestId,
      fence,
      rows: message.rows,
      cols: message.cols,
    });
  }
  /** Fence of the host's live PTY for `sessionId`, if any. */
  terminalFence(sessionId: string) {
    return this.terminals.get(sessionId)?.fence;
  }
  liveTerminals() {
    return this.terminals.size;
  }
  /**
   * Floods one PTY within its output credit window (8 unacknowledged frames)
   * until the server closes the session or `frames` are sent.
   */
  async floodTerminal(sessionId: string, frames: number) {
    const body = new Uint8Array(16 * 1024).fill(0x41);
    for (let i = 0, stalls = 0; i < frames; ) {
      const session = this.terminals.get(sessionId);
      const socket = this.socket;
      if (!session || !socket) return i;
      if (session.sent - session.acked >= 8) {
        // No credit: back-pressure, exactly as the host stops reading the PTY.
        if (++stalls > 10_000) return i;
        await new Promise((resolve) => setImmediate(resolve));
        continue;
      }
      i += 1;
      this.manager.handleBinaryFrame(
        socket,
        encodeTerminalDataFrame(
          { type: "terminal.data", fence: session.fence, sequence: session.sent },
          body,
        ),
      );
      session.sent += 1;
      await new Promise((resolve) => setImmediate(resolve));
    }
    return frames;
  }

  // ── host → server ──────────────────────────────────────────────────

  private async result(socket: DaemonSocket, entry: JournalEntry) {
    await this.text(
      {
        type: "operation.result",
        id: `result-${entry.operationId}-${entry.attempt}`,
        operationId: entry.operationId,
        sandboxId: entry.sandboxId,
        generation: entry.generation,
        attempt: entry.attempt,
        state: entry.state,
        ...(entry.error ? { error: entry.error } : {}),
        ...(entry.result ? { result: entry.result } : {}),
      },
      socket,
    );
  }

  private text(message: Json, socket = this.socket): Promise<void> {
    return this.emit(socket, (live) => this.manager.handleTextFrame(live, JSON.stringify(message)));
  }

  /**
   * A stream frame. After a host death the effect stops (HostCrashed); after a
   * server-side drop the process lives on and frames to the dead socket are
   * lost, exactly as a write to a closed transport.
   */
  private binaryOut(socket: DaemonSocket, frame: StreamBinaryMetadata & { body: Uint8Array }) {
    const life = this.lives;
    const { body, ...metadata } = frame;
    return this.emit(socket, (live) =>
      this.manager.handleBinaryFrame(live, encodeBinaryFrame(metadata, body)),
    ).then(() => {
      if (life !== this.lives) throw new HostCrashed();
    });
  }

  /** Host frames are ordered per socket and each is fully processed before the next. */
  private emit(socket: DaemonSocket | undefined, send: (socket: DaemonSocket) => void) {
    const run = this.emitChain.then(async () => {
      if (!socket || socket !== this.socket || socket.readyState !== 1) return;
      send(socket);
      await this.manager.drain(socket);
    });
    this.emitChain = run.catch(() => undefined);
    return run;
  }

  private track(task: Promise<unknown>) {
    const tracked = task.then(
      () => undefined,
      (error: unknown) => {
        if (!(error instanceof HostCrashed)) this.failures.push(error);
      },
    );
    this.tasks.add(tracked);
    void tracked.finally(() => this.tasks.delete(tracked)).catch(() => undefined);
  }
}

/** The host died mid-effect; the task stops without sending anything further. */
class HostCrashed extends Error {}
