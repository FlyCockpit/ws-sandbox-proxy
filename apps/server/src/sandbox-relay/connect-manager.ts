/**
 * Server half of CLI channels (wssp-ssh 1b): one `wssp.connect.v1` client
 * WebSocket (`GET /v1/sandboxes/{id}/connect`, a kind `API` key with
 * `sandboxes:connect`) multiplexes channels that the node runs as guest
 * processes over the host relay's `channel.*` family
 * (`docs/design/connect-channel-contract.md`).
 *
 * Identity: a connection is bound to `{ownerId, keyId, sandboxId, generation,
 * hostId, hostOwnerId, epoch}` from the server's own records (the upgrade's
 * `checkSandboxConnect`). The server mints the host `connectionId` and every
 * host `channelId`; nothing but a channel's kind parameters comes from the
 * client. Guest identity never travels: the node takes it from its lease.
 *
 * Authority: the connection keeps the retained `sandboxes.connect`
 * authorization (`authorizeRetainedServiceAction`). Its synchronous
 * `current()` gates every delivery in both directions; while it is stale,
 * client frames and host output are held in order (bounded) and a re-read
 * runs. The same re-read runs every 15 s, on every authority commit naming
 * the credential, owner, host, host owner or global policy (and on any commit
 * that made the retained guard stale, which covers the pool owner), on every
 * sandbox lifecycle notification and at the key's or lease's expiry. It is
 * coalesced (one in flight), bounded by a 5 s deadline and fails closed.
 * Host→server frames are additionally gated by the host link's cached ticket
 * in the session manager before they reach this class; server→host frames
 * wait here for `link.authorized()` (`resumeHost` flushes them).
 *
 * One end path: `end(intent)` is idempotent. It sends `channel.close{intent}`
 * for every live channel, `end{intent}` and close 4401 to the client, and
 * from then on nothing is forwarded in either direction. A channel's host
 * capacity stays charged until the node's settled `channel.exit`
 * (`reaped: true`) or the host socket's end, even after its connection ended.
 *
 * Kinds: `pty` and `exec` run a guest process; `tcp` and `unix` relay one
 * connection to a guest loopback port or guest Unix socket (stdin and
 * stdout only, eof both ways, no signals, no terminal). A kind is opened
 * only when the node's hello offered it. The client names a port or a
 * path, never a host: the target is always the guest's own loopback.
 *
 * Flow control (end to end): output windows are the host's (8 pty / 32
 * frames for every bulk kind per channel, both output streams together). A host frame is handed
 * to the client only while the client's own window for the channel has room,
 * the connection's unacknowledged output stays under 4 MiB and the client
 * socket's `bufferedAmount` is under its high water; the host is acked when
 * the frame is handed over. So the server holds at most two windows per
 * channel (one queued, one unacknowledged by the client), and a slow client
 * stops host credit. stdin is forwarded within the host window and acked to
 * the client as the node acks it. Every channel stream is one FIFO (data,
 * eof, exit); a natural `exit` leaves only after every frame before it.
 */
import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import {
  checkSandboxConnect,
  type SandboxConnectBinding,
  type SandboxConnectCheck,
} from "@wssp/api/sandbox/connect-binding";
import { CONNECT_AUDIT_FORWARDED_PORTS_MAX } from "@wssp/api/sandbox/connect-sessions";
import { subscribeSandboxTerminalLifecycle } from "@wssp/api/sandbox/terminal-lifecycle";
import { authorityTicket, onAuthorityCommitted } from "@wssp/db/authority";
import {
  CONNECT_CLOSE_CODE,
  CONNECT_CLOSE_INTENTS,
  CONNECT_CONTROL_MAX_BYTES,
  CONNECT_LIMITS,
  type ConnectClientControl,
  type ConnectCloseIntent,
  type ConnectError,
  type ConnectServerControl,
  connectClientControlSchema,
  encodeConnectDataFrame,
  parseConnectDataFrame,
} from "@wssp/sandbox-contracts";
import type { ConnectAuditClose, ConnectAuditOpen } from "./connect-audit.js";
import {
  CHANNEL_LIMITS,
  type ChannelDataMetadata,
  type ChannelFence,
  type DaemonControlMessage,
  encodeChannelDataFrame,
  encodeServerControlMessage,
  type SandboxErrorCode,
} from "./protocol.js";

const WS_OPEN = 1;
/** Connections per sandbox / per key / per owner (plan §9). */
export const CONNECT_CONNECTION_CAPS = { perSandbox: 8, perKey: 16, perOwner: 32 } as const;
/** Re-read cadence, deadline and the raced reads tolerated before failing closed. */
const CONNECT_REVALIDATE_MS = 15_000;
const CONNECT_CHECK_TIMEOUT_MS = 5_000;
/**
 * Consecutive re-reads an authority change overlapped before failing closed
 * (`lifecycle_unconfirmed`). A raced read decides nothing: deliveries stay
 * held, and the change's own commit (or a short retry) re-reads.
 */
const CONNECT_RACED_READS = 5;
const RACED_RETRY_MS = 250;
/** An upgrade's reserved slot is released if the socket never opens. */
const RESERVATION_TTL_MS = 10_000;
/**
 * Unacknowledged output per connection (bytes, both streams of every channel).
 * A channel holding none may still send one frame (its reserve, see `pump`),
 * so this is exceeded by at most one frame per channel (`maxChannels` × 32 KiB).
 */
const CONNECT_UNACKED_BYTES_PER_CONNECTION = 4 * 1024 * 1024;
/** No frame is handed to a client socket holding more than this (bytes). */
const CLIENT_BUFFER_HIGH_BYTES = 4 * 1024 * 1024;
/** Poll cadence while output waits only for the client socket to drain. */
const CLIENT_DRAIN_POLL_MS = 25;
/** Client frames held while the retained authorization is re-read. */
const CONNECT_CLIENT_HOLD_MAX_FRAMES = 4096;
const CONNECT_CLIENT_HOLD_MAX_BYTES = 8 * 1024 * 1024;
/**
 * A client socket buffering more than this (control frames included, which
 * no credit bounds) is not reading: the connection ends `backpressure`.
 */
const CLIENT_BUFFER_HARD_BYTES = 16 * 1024 * 1024;
/** No client input or credit is handed to a host socket buffering more than this (bytes). */
const HOST_BUFFER_HIGH_BYTES = 4 * 1024 * 1024;
/**
 * Control frames and credit acks to the node (small, bounded per channel) may
 * use the buffer up to this mark, so one tenant's bulk stdin at the high mark
 * never stalls another tenant's credit or controls on a shared node; opens
 * are refused above it.
 */
const HOST_BUFFER_CONTROL_BYTES = 12 * 1024 * 1024;
/** A host socket buffering this much is not reading: it is closed. */
const HOST_BUFFER_HARD_BYTES = 32 * 1024 * 1024;

function hostBuffered(socket: { readonly bufferedAmount?: number }): number {
  try {
    const amount = Number(socket.bufferedAmount ?? 0);
    return Number.isFinite(amount) && amount >= 0 ? amount : HOST_BUFFER_HIGH_BYTES;
  } catch {
    return HOST_BUFFER_HIGH_BYTES;
  }
}

/** Frames one channel may move per scheduling turn (fairness across channels). */
const PUMP_TURN_FRAMES = 4;
/** Non-data client frames (eof, resize, signal, close) waiting per channel. */
const CONNECT_CONTROL_QUEUE_MAX = 32;
/** Non-fatal notices (`error`) per channel, from the server or the node. */
const CONNECT_NOTICES_PER_CHANNEL = 64;
/** Input-rate cost of one forwarded control frame (bytes). */
const CONTROL_FRAME_COST_BYTES = 512;
/** Connection-end log lines per minute (process-wide). */
const AUDIT_LOGS_PER_MINUTE = 60;
/** Foreign (unknown) channel frames tolerated per host socket. */
const CONNECT_FOREIGN_FRAME_LIMIT = 256;
const AUDIT_LOGS_PER_SOCKET = 16;
const OPEN_WINDOW_MS = 60_000;
/**
 * A connection never outlives 12 h (the node's per-channel `PTY_MAX_SESSION`);
 * activity never extends it. Key and lease expiry end it earlier.
 */
const CONNECT_MAX_LIFETIME_MS = 12 * 60 * 60 * 1000;
/**
 * Default per-connection byte rate in each direction (owner decision 4: a
 * speed cap per connection protects the node owner's link on shared nodes).
 */
const CONNECT_DEFAULT_MAX_BYTES_PER_SECOND = 8 * 1024 * 1024;

/**
 * A token bucket over data bytes: up to one second of rate as burst. A frame
 * may go while the balance is positive and then spends its full size (the
 * balance may go negative), so a frame larger than the burst is never stuck.
 */
export class ByteRate {
  private tokens: number;
  private at: number;

  constructor(
    private readonly rate: number,
    now: number,
  ) {
    this.tokens = rate;
    this.at = now;
  }

  private refill(now: number) {
    const elapsed = Math.max(0, now - this.at);
    this.at = Math.max(this.at, now);
    this.tokens = Math.min(this.rate, this.tokens + (elapsed * this.rate) / 1000);
  }

  ready(now: number): boolean {
    this.refill(now);
    return this.tokens > 0;
  }

  spend(bytes: number, now: number) {
    this.refill(now);
    this.tokens -= bytes;
  }

  /** Milliseconds until a frame may go again (at least 1). */
  waitMs(now: number): number {
    this.refill(now);
    return this.tokens > 0 ? 1 : Math.max(1, Math.ceil(((1 - this.tokens) * 1000) / this.rate));
  }
}

/** setTimeout's largest delay; a farther expiry is re-armed by the re-read. */
const MAX_TIMER_MS = 2_147_483_647;

type HostSocket = {
  readonly readyState: number;
  readonly bufferedAmount?: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
};

/** The registered host connection a sandbox's channels ride (session manager). */
export type ConnectHostLink = {
  socket: HostSocket;
  hostId: string;
  /** The host's owner (the authenticated relay credential's user). */
  ownerId: string;
  epoch: number;
  protocolVersion: string;
  /** The host link's cached authority (no IO): false holds server→host frames. */
  authorized(): boolean;
  /** The channel kinds the node's hello offered (the negotiated set). */
  kinds: readonly string[];
};

export type ConnectHosts = {
  /** The channels-capable, reconciled, non-quiescing link of `hostId`. */
  connectHost(
    hostId: string,
  ): { link: ConnectHostLink } | { error: { code: SandboxErrorCode; message: string } };
  /** The host socket abused the channel family; close it with a protocol error. */
  closeHostSocket(socket: HostSocket, message: string): void;
};

/** The client side: the upgraded `wssp.connect.v1` WebSocket. */
export type ConnectClientSocket = {
  readonly readyState: number;
  readonly bufferedAmount: number;
  send(data: string | Uint8Array): void;
  close(code: number, reason: string): void;
  ping?(): void;
};

export type HostChannelControl = Extract<
  DaemonControlMessage,
  { type: "channel.ready" | "channel.ack" | "channel.eof" | "channel.error" | "channel.exit" }
>;

type ConnectCheck = (
  principal: ServicePrincipal,
  sandboxId: string,
  expected?: Pick<SandboxConnectBinding, "hostId" | "hostOwnerId" | "generation" | "epoch">,
) => Promise<SandboxConnectCheck>;

type Retained = Extract<SandboxConnectCheck, { ok: true }>["retained"];

export type ConnectManagerOptions = {
  check?: ConnectCheck;
  revalidateMs?: number;
  checkTimeoutMs?: number;
  pingMs?: number;
  idleMs?: number;
  openTimeoutMs?: number;
  maxLifetimeMs?: number;
  /** Data bytes per second per connection, each direction. */
  maxBytesPerSecond?: number;
  /** The §10 audit (row + log line per live connection); never throws. */
  audit?: ConnectAudit;
  now?: () => number;
};

/** Told when a connection goes live (after `hello`) and when that one ends. */
export type ConnectAudit = {
  opened(open: ConnectAuditOpen): void;
  closed(close: ConnectAuditClose): void;
};

type OutputStream = "stdout" | "stderr";
const streamIndex = (stream: OutputStream) => (stream === "stdout" ? 0 : 1);

type OutItem =
  | { kind: "ready"; pty?: { rows: number; cols: number } }
  | { kind: "data"; stream: OutputStream; seq: number; body: Uint8Array }
  | { kind: "eof"; stream: OutputStream; frames: number }
  | { kind: "error"; code: "unsupported_signal" | "state_conflict" }
  | {
      kind: "exit";
      exitCode?: number;
      signal?: number;
      intent?: ConnectCloseIntent;
      error?: ConnectError;
      reaped: boolean;
    };

type InItem =
  | { kind: "data"; seq: number; body: Uint8Array }
  | { kind: "eof"; frames: number }
  | { kind: "resize"; rows: number; cols: number }
  | { kind: "signal"; signal: "TERM" | "INT" | "HUP" | "KILL" }
  | { kind: "close" };

/**
 * `opening` (open sent) → `open` (ready) → `closing` (a close was decided;
 * the client already heard its end) → `unreaped` (exited, the node has not
 * settled the end) → `ended` (capacity released).
 */
type ChannelState = "opening" | "open" | "closing" | "unreaped" | "ended";

type ChannelKind = Extract<ConnectClientControl, { type: "open" }>["kind"];

/** A relay channel: one byte stream to a guest socket (stdin and stdout only). */
function isRelay(kind: ChannelKind): boolean {
  return kind === "tcp" || kind === "unix";
}

type Chan = {
  clientId: number;
  kind: ChannelKind;
  fence: ChannelFence;
  link: ConnectHostLink;
  creatorId: string;
  connection: ConnectConnection | null;
  state: ChannelState;
  /** The client heard this channel's last frame (`exit`, or the connection's `end`). */
  clientDone: boolean;
  /** A `channel.close` was sent to the node; `killSent`: a kill-class one. */
  closeSent: boolean;
  killSent: boolean;
  /** The node's first `channel.exit` arrived. */
  exited: boolean;
  openTimer?: ReturnType<typeof setTimeout>;
  out: OutItem[];
  /** Data frames queued in `out`. */
  outQueued: number;
  /** Next expected host output seq, per stream. */
  hostNext: [number, number];
  /** Frames handed to the client / acked by it, per stream; sizes of the unacked ones. */
  clientSent: [number, number];
  clientAcked: [number, number];
  inflight: [number[], number[]];
  /** Sizes of stdin frames not yet acknowledged to the client, oldest first. */
  inSizes: number[];
  inUnackedBytes: number;
  /** stdin frames acknowledged to the client. */
  inClientAcked: number;
  /** The highest output seq to acknowledge to the node, per stream (coalesced). */
  hostAckDue: [number | null, number | null];
  /** Hand-over times of the client-unacknowledged frames, oldest first. */
  sentAt: [number[], number[]];
  /** stdin: next client seq expected, frames sent to the node, frames it acked. */
  inNext: number;
  inSent: number;
  inAcked: number;
  /** The highest node stdin ack not yet told to the client (held while stale). */
  ackDue: number | null;
  stdinEof: boolean;
  in: InItem[];
  /** Non-data items in `in`. */
  inControl: number;
  /** The node's `channel.eof` arrived, per stream (data after it is a violation). */
  hostEof: [boolean, boolean];
  /** Notices the server answered to the client's requests / the node sent. */
  notices: number;
  nodeNotices: number;
  violations: number;
};

type HostState = {
  channels: Set<Chan>;
  opens: { at: number; creatorId: string }[];
  tombstones: string[];
  foreign: number;
  audits: number;
};

export type ConnectReservation = {
  readonly binding: SandboxConnectBinding;
  /** [`ConnectManager.lifecycleMark`] sampled before the pre-upgrade read. */
  readonly lifecycleMark: number | undefined;
  release(): void;
};

export type ConnectManagerResources = {
  connections: number;
  reservations: number;
  /** Channels still charged against a host (including those of ended connections). */
  channels: number;
  unreaped: number;
  timers: number;
  hostSockets: number;
  subscribed: number;
};

function mintId(prefix: string): string {
  return `${prefix}${randomUUID().replaceAll("-", "")}`;
}

function hostKey(fence: Pick<ChannelFence, "connectionId" | "channelId">): string {
  return `${fence.connectionId}/${fence.channelId}`;
}

function sameFence(a: ChannelFence, b: ChannelFence): boolean {
  return (
    a.channelId === b.channelId &&
    a.connectionId === b.connectionId &&
    a.hostId === b.hostId &&
    a.epoch === b.epoch &&
    a.target.kind === b.target.kind &&
    a.target.sandboxId === b.target.sandboxId &&
    a.target.generation === b.target.generation
  );
}

function frameMax(kind: ChannelKind): number {
  return kind === "pty" ? CHANNEL_LIMITS.ptyDataMaxBytes : CHANNEL_LIMITS.bulkDataMaxBytes;
}

function windowOf(kind: ChannelKind): number {
  return kind === "pty" ? CHANNEL_LIMITS.ptyWindowFrames : CHANNEL_LIMITS.bulkWindowFrames;
}

/** Errors on the client wire: a stable code and a short message, nothing else. */
function clientError(
  error: { code: string; message: string } | undefined,
): ConnectError | undefined {
  if (!error) return undefined;
  const code = /^[a-z][a-z0-9_]{0,63}$/.test(error.code) ? error.code : "internal";
  const message = error.message.length <= 256 ? error.message : `${error.message.slice(0, 253)}...`;
  return { code, message };
}

/** A re-read's refusal: an authorization error class, else unconfirmed. */
/** A node close intent as the client wire names it (unknown ones fail closed). */
function clientIntent(intent: string): ConnectCloseIntent {
  if (intent === "replaced") return "superseded";
  return (CONNECT_CLOSE_INTENTS as readonly string[]).includes(intent)
    ? (intent as ConnectCloseIntent)
    : "lifecycle_unconfirmed";
}

function revocationIntent(error: unknown): ConnectCloseIntent {
  const code = error instanceof ORPCError ? error.code : "";
  if (code === "FORBIDDEN" || code === "CONFLICT" || code === "UNAUTHORIZED") return "revoked";
  if (code === "NOT_FOUND") return "sandbox_destroyed";
  return "lifecycle_unconfirmed";
}

/**
 * One upgraded client socket. Its methods never throw into the WebSocket
 * handlers or the host relay: a failing client transport ends `detached`.
 */
export class ConnectConnection {
  readonly connectionId = mintId("c");
  private state: "verifying" | "live" | "ended" = "verifying";
  private socket: ConnectClientSocket | undefined;
  private readonly channels = new Map<number, Chan>();
  private lastChannelId = -1;
  private ptyLive = 0;
  private opens: number[] = [];
  private hold: { frames: (string | Uint8Array)[]; bytes: number } = { frames: [], bytes: 0 };
  private unackedBytes = 0;
  private checking = false;
  private dirty = false;
  private racedReads = 0;
  private revalidateTimer: ReturnType<typeof setTimeout> | undefined;
  private heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
  private expiryTimer: ReturnType<typeof setTimeout> | undefined;
  private drainTimer: ReturnType<typeof setTimeout> | undefined;
  private lifetimeTimer: ReturnType<typeof setTimeout> | undefined;
  /** Per direction: the byte-rate wait (output to the client, input to the node). */
  private outRateTimer: ReturnType<typeof setTimeout> | undefined;
  private inRateTimer: ReturnType<typeof setTimeout> | undefined;
  private lastActivity: number;
  /** Output (host → client) and input (client → host) data byte rates. */
  private readonly outRate: ByteRate;
  private readonly inRate: ByteRate;
  /** §10 audit counters (metadata only): set once the connection went live. */
  private audited = false;
  /** When the connection went live (the audit's `openedAt`, epoch ms). */
  private liveAt = 0;
  private ptyOpened = 0;
  private execOpened = 0;
  private relayOpened = 0;
  /** The audit's distinct guest tcp ports (first seen, bounded); never a Unix path. */
  private readonly forwardedPorts = new Set<number>();
  private bytesIn = 0;
  private bytesOut = 0;

  constructor(
    private binding: SandboxConnectBinding,
    readonly principal: ServicePrincipal,
    private retained: Retained,
    private readonly manager: ConnectManager,
    private readonly lifecycleMark?: number,
  ) {
    this.lastActivity = manager.now();
    this.outRate = new ByteRate(manager.maxBytesPerSecond, manager.now());
    this.inRate = new ByteRate(manager.maxBytesPerSecond, manager.now());
  }

  get ownerId() {
    return this.binding.ownerId;
  }
  get keyId() {
    return this.binding.keyId;
  }
  get sandboxId() {
    return this.binding.sandboxId;
  }
  get hostId() {
    return this.binding.hostId;
  }
  get hostOwnerId() {
    return this.binding.hostOwnerId;
  }
  /** The server-side binding (never client-supplied). */
  get bound(): SandboxConnectBinding {
    return this.binding;
  }
  get ended() {
    return this.state === "ended";
  }
  get timers(): number {
    return [
      this.revalidateTimer,
      this.heartbeatTimer,
      this.expiryTimer,
      this.drainTimer,
      this.lifetimeTimer,
      this.outRateTimer,
      this.inRateTimer,
    ].filter((timer) => timer !== undefined).length;
  }
  /** Channels of this connection the client still knows (metadata; tests). */
  get channelCount(): number {
    return this.channels.size;
  }

  /** The retained authorization still holds (no IO). */
  current(): boolean {
    return this.state !== "ended" && this.retained.current() && !this.leaseExpired();
  }

  /** The sandbox lease the connection was bound to has ended (no IO). */
  private leaseExpired(): boolean {
    const lease = this.binding.leaseExpiresAt;
    return lease !== null && lease !== undefined && this.manager.now() >= lease.getTime();
  }

  // -- socket events -------------------------------------------------------

  opened(socket: ConnectClientSocket) {
    this.socket = socket;
    if (this.state === "ended") {
      this.closeSocket();
      return;
    }
    this.activity();
    this.armHeartbeat();
    this.lifetimeTimer = setTimeout(() => {
      this.lifetimeTimer = undefined;
      this.end("expired", { code: "timeout", message: "connection lifetime reached" });
    }, this.manager.maxLifetimeMs);
    this.lifetimeTimer.unref?.();
    // A lifecycle change between the pre-upgrade read and now has no event
    // left to see: then re-read once before hello.
    if (this.current() && !this.manager.lifecycleChangedSince(this.lifecycleMark)) this.goLive();
    else void this.revalidate();
  }

  activity() {
    this.lastActivity = this.manager.now();
  }

  message(data: unknown) {
    if (this.state === "ended") return;
    this.activity();
    let frame: string | Uint8Array;
    if (typeof data === "string") frame = data;
    else if (data instanceof ArrayBuffer) frame = new Uint8Array(data);
    else if (data instanceof Uint8Array) frame = data;
    else return;
    if (this.state === "live" && this.hold.frames.length === 0 && this.current()) {
      this.process(frame);
      return;
    }
    const bytes = typeof frame === "string" ? frame.length : frame.byteLength;
    if (
      this.hold.frames.length >= CONNECT_CLIENT_HOLD_MAX_FRAMES ||
      this.hold.bytes + bytes > CONNECT_CLIENT_HOLD_MAX_BYTES
    ) {
      this.end("backpressure", {
        code: "rate_limited",
        message: "client frames exceeded the hold",
      });
      return;
    }
    this.hold.frames.push(frame);
    this.hold.bytes += bytes;
    if (this.state !== "live") return;
    if (this.current()) this.resume();
    else void this.revalidate();
  }

  /** The client socket closed or errored: every channel ends `detached`. */
  gone() {
    if (this.state === "ended") return;
    this.socket = undefined;
    this.end("detached");
  }

  // -- the one end path -----------------------------------------------------

  /**
   * Idempotent. Nothing is forwarded in either direction after this: every
   * live channel gets `channel.close{intent}`, the client gets `end` + 4401.
   */
  end(intent: ConnectCloseIntent, error?: ConnectError) {
    if (this.state === "ended") return;
    this.state = "ended";
    this.stopTimers();
    this.hold = { frames: [], bytes: 0 };
    for (const chan of this.channels.values()) {
      chan.out = [];
      chan.outQueued = 0;
      chan.in = [];
      chan.inControl = 0;
      chan.ackDue = null;
      chan.clientDone = true;
      chan.connection = null;
      this.manager.closeChannelOnHost(chan, intent);
    }
    this.channels.clear();
    this.sendControl({ type: "end", intent, ...(error ? { error } : {}) }, true);
    this.closeSocket();
    this.manager.forget(this);
    if (this.audited)
      this.manager.auditClosed({
        ...this.auditIds(),
        closedAt: this.manager.now(),
        intent,
        ptyChannels: this.ptyOpened,
        execChannels: this.execOpened,
        relayChannels: this.relayOpened,
        forwardedPorts: [...this.forwardedPorts],
        bytesIn: this.bytesIn,
        bytesOut: this.bytesOut,
      });
  }

  private auditIds(): ConnectAuditOpen {
    return {
      connectionId: this.connectionId,
      ownerId: this.binding.ownerId,
      keyId: this.binding.keyId,
      sandboxId: this.binding.sandboxId,
      hostId: this.binding.hostId,
      openedAt: this.liveAt,
    };
  }

  // -- authority ------------------------------------------------------------

  /** Coalesced re-read (one in flight); a hint arriving meanwhile re-runs it once. */
  async revalidate(): Promise<void> {
    if (this.state === "ended") return;
    if (this.checking) {
      this.dirty = true;
      return;
    }
    this.checking = true;
    this.dirty = false;
    clearTimeout(this.revalidateTimer);
    this.revalidateTimer = undefined;
    try {
      const outcome = await this.verify();
      // `end` may have run while the read was in flight.
      if (this.ended) return;
      if (outcome === "raced") {
        this.racedReads += 1;
        if (this.racedReads >= CONNECT_RACED_READS) {
          this.end("lifecycle_unconfirmed");
          return;
        }
        // Held deliveries wait; the change's commit or this retry re-reads.
        this.arm(RACED_RETRY_MS);
        return;
      }
      if (outcome !== "ok") {
        this.end(outcome);
        return;
      }
      this.racedReads = 0;
      if (this.state === "verifying") this.goLive();
      else this.resume();
      this.arm();
    } finally {
      this.checking = false;
      // A hint that arrived during the read (every early return included)
      // re-runs it at once instead of waiting for the next timer.
      if (this.dirty && !this.ended) {
        this.dirty = false;
        void this.revalidate();
      }
    }
  }

  /**
   * One re-read. The credential, owner, host and host-owner tickets are
   * sampled BEFORE it: a refusal while one of them changed is a raced read
   * (the authorization itself refuses a read an authority change overlapped)
   * and decides nothing; a refusal on unchanged tickets is the verdict.
   */
  private async verify(): Promise<"ok" | "raced" | ConnectCloseIntent> {
    const binding = this.binding;
    const fresh = authorityTicket({
      ownerId: binding.ownerId,
      credentialId: binding.keyId,
      hostId: binding.hostId,
    });
    const transportFresh = authorityTicket({ ownerId: binding.hostOwnerId });
    const hostPolicyFresh = authorityTicket({
      ownerId: binding.hostOwnerId,
      hostId: binding.hostId,
    });
    const unchanged = () => fresh() && transportFresh() && hostPolicyFresh();
    let checked: SandboxConnectCheck;
    try {
      checked = await this.checkWithDeadline();
    } catch (error) {
      const intent = revocationIntent(error);
      if (intent !== "lifecycle_unconfirmed" && !unchanged()) return "raced";
      return intent;
    }
    if (this.ended) return "lifecycle_unconfirmed";
    if (!checked.ok) {
      if (checked.intent === "stale") return "raced";
      if (checked.intent === "unsupported") return "revoked";
      return checked.intent;
    }
    if (!checked.retained.current()) return "raced";
    this.retained = checked.retained;
    this.binding = checked.binding;
    return "ok";
  }

  /** The re-read, bounded: a hung query never suspends revocation. */
  private checkWithDeadline(): Promise<SandboxConnectCheck> {
    let read: Promise<SandboxConnectCheck>;
    try {
      read = this.manager.check(this.principal, this.binding.sandboxId, this.binding);
    } catch (error) {
      return Promise.reject(error);
    }
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      deadline = setTimeout(
        () => reject(new Error("connect re-read timed out")),
        this.manager.checkTimeoutMs,
      );
      deadline.unref?.();
    });
    return Promise.race([read, timeout]).finally(() => clearTimeout(deadline));
  }

  private goLive() {
    if (this.state !== "verifying") return;
    const host = this.manager.hostLink(this.binding);
    if (!host) {
      this.end("host_disconnected", { code: "disconnected", message: "host is not connected" });
      return;
    }
    this.state = "live";
    this.sendControl({
      type: "hello",
      connectionId: this.connectionId,
      sandboxId: this.binding.sandboxId,
      limits: CONNECT_LIMITS,
    });
    this.audited = true;
    this.liveAt = this.manager.now();
    this.manager.auditOpened(this.auditIds());
    this.arm();
    this.resume();
  }

  /** A fresh authorization: process held client frames, then pump held output. */
  private resume() {
    while (this.state === "live" && this.hold.frames.length > 0 && this.current()) {
      const frame = this.hold.frames.shift()!;
      this.hold.bytes -= typeof frame === "string" ? frame.length : frame.byteLength;
      this.process(frame);
    }
    if (this.state !== "live") return;
    this.flushAllInput();
    this.pumpAll();
  }

  private arm(delay = this.manager.revalidateMs) {
    if (this.state === "ended") return;
    clearTimeout(this.revalidateTimer);
    this.revalidateTimer = setTimeout(() => void this.revalidate(), delay);
    this.revalidateTimer.unref?.();
    this.armExpiry();
  }

  /** Expiry fires no event: re-read at the key's or the lease's end. */
  private armExpiry() {
    clearTimeout(this.expiryTimer);
    this.expiryTimer = undefined;
    const ends = [this.binding.keyExpiresAt, this.binding.leaseExpiresAt]
      .filter((at): at is Date => at !== null)
      .map((at) => at.getTime());
    if (ends.length === 0 || this.state === "ended") return;
    const delay = Math.max(0, Math.min(...ends) - Date.now());
    if (delay > MAX_TIMER_MS) return;
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = undefined;
      void this.revalidate();
    }, delay + 1);
    this.expiryTimer.unref?.();
  }

  private armHeartbeat() {
    if (this.state === "ended") return;
    clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = setTimeout(() => this.heartbeat(), this.manager.pingMs);
    this.heartbeatTimer.unref?.();
  }

  private heartbeat() {
    this.heartbeatTimer = undefined;
    if (this.state === "ended") return;
    if (this.manager.now() - this.lastActivity >= this.manager.idleMs) {
      this.end("detached", { code: "timeout", message: "client silent" });
      return;
    }
    // The node's stall rule, applied to the client: the server acks the node
    // as frames leave, so only it can see a client that never acks.
    const now = this.manager.now();
    for (const chan of [...this.channels.values()]) {
      if (chan.clientDone) continue;
      if (
        !chan.sentAt.some(
          (times) => times.length > 0 && now - times[0]! >= CONNECT_LIMITS.ackStallMs,
        )
      )
        continue;
      const error = { code: "timeout" as const, message: "output not acknowledged" };
      if (chan.state === "opening" || chan.state === "open")
        this.manager.closeChannel(chan, "backpressure", error);
      else {
        // The node already exited (its output drains here): end delivery,
        // and upgrade an unsettled end to a kill.
        this.closeChannelForClient(chan, "backpressure", error);
        this.manager.closeChannelOnHost(chan, "backpressure");
      }
    }
    try {
      this.socket?.ping?.();
    } catch {
      this.detachSoon();
      return;
    }
    this.armHeartbeat();
  }

  private stopTimers() {
    for (const timer of [
      this.revalidateTimer,
      this.heartbeatTimer,
      this.expiryTimer,
      this.drainTimer,
      this.lifetimeTimer,
      this.outRateTimer,
      this.inRateTimer,
    ])
      clearTimeout(timer);
    this.outRateTimer = undefined;
    this.inRateTimer = undefined;
    this.lifetimeTimer = undefined;
    this.revalidateTimer = undefined;
    this.heartbeatTimer = undefined;
    this.expiryTimer = undefined;
    this.drainTimer = undefined;
  }

  // -- client frames (authorized, in order) --------------------------------

  private process(frame: string | Uint8Array) {
    if (typeof frame !== "string") {
      this.clientData(frame);
      return;
    }
    if (frame.length > CONNECT_CONTROL_MAX_BYTES) {
      this.violation("control frame too large");
      return;
    }
    let message: ConnectClientControl;
    try {
      const parsed = connectClientControlSchema.safeParse(JSON.parse(frame));
      if (!parsed.success) throw new Error("invalid");
      message = parsed.data;
    } catch {
      this.violation("invalid control frame");
      return;
    }
    if (message.type === "open") {
      this.open(message);
      return;
    }
    const chan =
      message.type === "ack"
        ? this.channelForAck(message.channel)
        : this.channelFor(message.channel);
    if (!chan) return;
    // After the client's own close only acks still mean something.
    if (chan.closeSent && message.type !== "ack") return;
    switch (message.type) {
      case "ack": {
        const index = streamIndex(message.stream);
        if (message.seq >= chan.clientSent[index]) {
          this.violation("ack beyond the frames sent");
          return;
        }
        while (chan.clientAcked[index] <= message.seq) {
          chan.clientAcked[index] += 1;
          this.unackedBytes -= chan.inflight[index].shift() ?? 0;
          chan.sentAt[index].shift();
        }
        this.pumpAll();
        return;
      }
      case "eof":
        if (chan.stdinEof || message.frames !== chan.inNext) {
          this.violation("invalid stdin eof");
          return;
        }
        chan.stdinEof = true;
        this.queueInput(chan, { kind: "eof", frames: message.frames });
        return;
      case "resize":
        if (chan.kind !== "pty") {
          this.notice(chan, "state_conflict");
          return;
        }
        this.queueInput(chan, { kind: "resize", rows: message.rows, cols: message.cols });
        return;
      case "signal":
        if (chan.kind !== "exec") {
          this.notice(chan, "unsupported_signal");
          return;
        }
        this.queueInput(chan, { kind: "signal", signal: message.signal });
        return;
      case "close":
        this.queueInput(chan, { kind: "close" });
        return;
    }
  }

  /**
   * The live channel a client frame names. An id the client used before
   * (ended, or already told its exit) is ignored silently: acks and input
   * race the exit. An id never opened is a protocol violation.
   */
  private channelFor(clientId: number): Chan | undefined {
    const chan = this.channels.get(clientId);
    if (chan && !chan.clientDone && (chan.state === "opening" || chan.state === "open"))
      return chan;
    if (!chan && clientId > this.lastChannelId) this.violation("frame for an unopened channel");
    return undefined;
  }

  /**
   * Output acks count until the client heard the channel's exit, whatever
   * the node's state: a natural exit's output may still be draining.
   */
  private channelForAck(clientId: number): Chan | undefined {
    const chan = this.channels.get(clientId);
    if (chan && !chan.clientDone) return chan;
    if (!chan && clientId > this.lastChannelId) this.violation("frame for an unopened channel");
    return undefined;
  }

  private clientData(frame: Uint8Array) {
    const parsed = parseConnectDataFrame(frame);
    if (parsed?.metadata.stream !== "stdin") {
      this.violation("invalid data frame");
      return;
    }
    const { metadata, body } = parsed;
    const chan = this.channelFor(metadata.channel);
    if (!chan) return;
    // After the client's own close its stdin means nothing.
    if (chan.closeSent) return;
    if (chan.state !== "open") {
      this.violation("input before ready");
      return;
    }
    if (chan.stdinEof || body.byteLength > frameMax(chan.kind) || metadata.seq !== chan.inNext) {
      this.violation("invalid stdin frame");
      return;
    }
    if (chan.inNext - chan.inAcked >= windowOf(chan.kind)) {
      this.violation("stdin beyond its window");
      return;
    }
    if (this.unackedInputBytes() + body.byteLength > CONNECT_LIMITS.unackedInputBytes) {
      this.violation("stdin beyond the connection's budget");
      return;
    }
    chan.inNext += 1;
    chan.inSizes.push(body.byteLength);
    chan.inUnackedBytes += body.byteLength;
    this.queueInput(chan, { kind: "data", seq: metadata.seq, body: body.slice() });
  }

  /** stdin bytes the client sent and the server has not acknowledged (all live channels). */
  private unackedInputBytes(): number {
    let bytes = 0;
    for (const chan of this.channels.values()) if (!chan.clientDone) bytes += chan.inUnackedBytes;
    return bytes;
  }

  private queueInput(chan: Chan, item: InItem) {
    if (item.kind === "resize") {
      // Only the latest size matters: coalesce with a resize still waiting.
      if (chan.in.at(-1)?.kind === "resize") {
        chan.in[chan.in.length - 1] = item;
        this.manager.flushInput(chan);
        return;
      }
    }
    if (item.kind !== "data") {
      if (chan.inControl >= CONNECT_CONTROL_QUEUE_MAX) {
        this.violation("too many queued control frames");
        return;
      }
      chan.inControl += 1;
    }
    chan.in.push(item);
    this.manager.flushInput(chan);
  }

  /** A non-fatal notice for the client; a flood of them is a violation. */
  private notice(chan: Chan, code: "state_conflict" | "unsupported_signal") {
    chan.notices += 1;
    if (chan.notices > CONNECT_NOTICES_PER_CHANNEL) {
      this.violation("too many refused channel requests");
      return;
    }
    this.sendControl({ type: "error", channel: chan.clientId, code });
  }

  private open(message: Extract<ConnectClientControl, { type: "open" }>) {
    if (message.channel <= this.lastChannelId) {
      this.violation("channel ids must increase");
      return;
    }
    this.lastChannelId = message.channel;
    const refuse = (code: SandboxErrorCode, text: string) =>
      this.sendControl({
        type: "exit",
        channel: message.channel,
        error: { code, message: text },
        frames: { stdout: 0, stderr: 0 },
      });
    const now = this.manager.now();
    this.opens = this.opens.filter((at) => now - at < OPEN_WINDOW_MS);
    if (this.opens.length >= CONNECT_LIMITS.opensPerMinute) {
      refuse("rate_limited", "channel open rate exceeded for this connection");
      return;
    }
    // Every attempt counts, refused ones too (each refusal is a reply).
    this.opens.push(now);
    if (
      this.channels.size >= CONNECT_LIMITS.maxChannels ||
      (message.kind === "pty" && this.ptyLive >= CONNECT_LIMITS.maxPtyChannels)
    ) {
      refuse("host_capacity", "channel capacity reached for this connection");
      return;
    }
    const host = this.manager.hostLink(this.binding);
    if (!host) {
      this.end("host_disconnected", { code: "disconnected", message: "host is not connected" });
      return;
    }
    // A node that did not offer this kind (an older daemon) never sees it.
    if (!host.kinds.includes(message.kind)) {
      refuse(
        "unsupported_capability",
        `the sandbox's node cannot open ${message.kind} channels; update its daemon`,
      );
      return;
    }
    if (hostBuffered(host.socket) >= HOST_BUFFER_CONTROL_BYTES) {
      refuse("rate_limited", "host is congested");
      return;
    }
    const refusal = this.manager.admitOpen(host, this.binding.ownerId, message.kind);
    if (refusal) {
      refuse(refusal.code, refusal.message);
      return;
    }
    // Like a terminal open: never under a stale host ticket (retryable).
    const chan = host.authorized()
      ? this.manager.openChannel(this, host, this.binding, message)
      : null;
    if (!chan) {
      refuse("disconnected", "host is not connected");
      return;
    }
    this.channels.set(message.channel, chan);
    if (chan.kind === "pty") this.ptyLive += 1;
    if (chan.kind === "pty") this.ptyOpened += 1;
    else if (chan.kind === "exec") this.execOpened += 1;
    else this.relayOpened += 1;
    if (
      chan.kind === "tcp" &&
      message.port !== undefined &&
      this.forwardedPorts.size < CONNECT_AUDIT_FORWARDED_PORTS_MAX
    )
      this.forwardedPorts.add(message.port);
  }

  // -- host → client ----------------------------------------------------------

  /** Called by the manager when a channel's capacity is released. */
  released(chan: Chan) {
    if (this.channels.get(chan.clientId) === chan && chan.clientDone) {
      this.channels.delete(chan.clientId);
      if (chan.kind === "pty") this.ptyLive -= 1;
    }
  }

  /** The client heard the channel's exit. */
  private clientFinished(chan: Chan) {
    chan.clientDone = true;
    // Its acks are ignored from now on: what it still holds unacked leaves
    // the connection's budget now, and output waiting on it may move.
    for (const sizes of chan.inflight) {
      for (const size of sizes) this.unackedBytes -= size;
      sizes.length = 0;
    }
    for (const times of chan.sentAt) times.length = 0;
    this.armDrain();
    if (chan.state === "ended") {
      this.channels.delete(chan.clientId);
      if (chan.kind === "pty") this.ptyLive -= 1;
    }
  }

  /** A node stdin ack: told to the client at once (control priority) when authorized. */
  stdinAcked(chan: Chan, seq: number) {
    chan.ackDue = seq;
    this.flushAck(chan);
  }

  private flushAck(chan: Chan) {
    if (chan.ackDue === null || chan.clientDone || this.state !== "live") return;
    if (!this.current()) {
      void this.revalidate();
      return;
    }
    const seq = chan.ackDue;
    chan.ackDue = null;
    while (chan.inClientAcked <= seq) {
      chan.inUnackedBytes -= chan.inSizes.shift() ?? 0;
      chan.inClientAcked += 1;
    }
    this.sendControl({ type: "ack", channel: chan.clientId, stream: "stdin", seq });
  }

  /**
   * A server-side close of one channel (open deadline, a host violation): the
   * client hears its exit now; nothing more of it is delivered.
   */
  closeChannelForClient(chan: Chan, intent: ConnectCloseIntent, error?: ConnectError) {
    if (chan.clientDone) return;
    chan.in = [];
    chan.inControl = 0;
    chan.ackDue = null;
    // Delivered like every frame: only while the authorization holds.
    chan.out = [{ kind: "exit", intent, ...(error ? { error } : {}), reaped: true }];
    chan.outQueued = 0;
    this.pump(chan);
  }

  /**
   * Output round robin: every channel in turn from the output cursor, at most
   * `PUMP_TURN_FRAMES` frames each per turn, until no channel moves. The
   * cursor moves past a channel only when it was served, so a backlogged
   * channel never keeps a shared budget (the byte rate, the connection's
   * unacked bytes) from the others, however often passes run.
   */
  pumpAll() {
    const order = this.fromCursor(this.outCursor);
    for (const chan of order) this.flushAck(chan);
    let moved = true;
    while (moved && this.state === "live") {
      moved = false;
      for (const chan of order) {
        const before = chan.clientSent[0] + chan.clientSent[1];
        if (this.pump(chan, PUMP_TURN_FRAMES) > 0) moved = true;
        // Only a data share counts as being served (notices, eofs do not).
        if (chan.clientSent[0] + chan.clientSent[1] > before) this.outCursor = chan.clientId + 1;
      }
    }
  }

  /** Input round robin, with its own cursor (see `pumpAll`). */
  flushAllInput() {
    const order = this.fromCursor(this.inCursor);
    let moved = true;
    while (moved && this.state !== "ended") {
      moved = false;
      for (const chan of order) {
        const before = chan.inSent;
        if (this.manager.flushInput(chan, PUMP_TURN_FRAMES) > 0) moved = true;
        if (chan.inSent > before) this.inCursor = chan.clientId + 1;
      }
    }
  }

  /** The next channel to serve, per direction (a client channel id). */
  private outCursor = 0;
  private inCursor = 0;

  /** The channels in id order, starting at the first id at or after `cursor`. */
  private fromCursor(cursor: number): Chan[] {
    const chans = [...this.channels.values()].sort((a, b) => a.clientId - b.clientId);
    const start = chans.findIndex((chan) => chan.clientId >= cursor);
    return start <= 0 ? chans : [...chans.slice(start), ...chans.slice(0, start)];
  }

  /** Hand queued output to the client, in order, within every credit bound. */
  pump(chan: Chan, budget = Number.POSITIVE_INFINITY): number {
    this.flushAck(chan);
    let blockedOnSocket = false;
    let sent = 0;
    while (chan.out.length > 0 && sent < budget) {
      if (this.state !== "live" || chan.clientDone) return sent;
      if (!this.current()) {
        void this.revalidate();
        return sent;
      }
      const item = chan.out[0]!;
      if (item.kind === "data") {
        const index = streamIndex(item.stream);
        const unacked =
          chan.clientSent[0] - chan.clientAcked[0] + chan.clientSent[1] - chan.clientAcked[1];
        if (unacked >= windowOf(chan.kind)) break;
        // A channel holding nothing unacked may always send one frame (its
        // reserve): channels whose local readers stopped can fill the
        // shared budget but never freeze the connection's other channels.
        if (
          unacked > 0 &&
          this.unackedBytes + item.body.byteLength > CONNECT_UNACKED_BYTES_PER_CONNECTION
        )
          break;
        if (this.bufferedAmount() >= CLIENT_BUFFER_HIGH_BYTES) {
          blockedOnSocket = true;
          break;
        }
        // While the output rate timer waits, only its round-robin pass sends.
        if (this.outRateTimer || !this.outRate.ready(this.manager.now())) {
          this.armOutRate();
          break;
        }
        chan.out.shift();
        chan.outQueued -= 1;
        if (
          !this.sendData(
            encodeConnectDataFrame(
              { type: "data", channel: chan.clientId, stream: item.stream, seq: item.seq },
              item.body,
            ),
          )
        )
          return sent;
        sent += 1;
        this.bytesOut += item.body.byteLength;
        this.outRate.spend(item.body.byteLength, this.manager.now());
        chan.clientSent[index] += 1;
        chan.inflight[index].push(item.body.byteLength);
        chan.sentAt[index].push(this.manager.now());
        this.unackedBytes += item.body.byteLength;
        // Host credit returns only as the frame leaves for the client.
        this.manager.ackHost(chan, item.stream, item.seq);
        continue;
      }
      chan.out.shift();
      sent += 1;
      switch (item.kind) {
        case "ready":
          this.sendControl({
            type: "ready",
            channel: chan.clientId,
            ...(item.pty ? { pty: item.pty } : {}),
          });
          break;
        case "eof":
          this.sendControl({
            type: "eof",
            channel: chan.clientId,
            stream: item.stream,
            frames: item.frames,
          });
          break;
        case "error":
          this.sendControl({ type: "error", channel: chan.clientId, code: item.code });
          break;
        case "exit":
          this.sendControl({
            type: "exit",
            channel: chan.clientId,
            ...(item.exitCode !== undefined ? { exitCode: item.exitCode } : {}),
            ...(item.signal !== undefined ? { signal: item.signal } : {}),
            ...(item.intent ? { intent: item.intent } : {}),
            ...(item.error ? { error: item.error } : {}),
            frames: { stdout: chan.clientSent[0], stderr: chan.clientSent[1] },
          });
          this.clientFinished(chan);
          return sent;
      }
    }
    if (blockedOnSocket) this.armDrain();
    return sent;
  }

  /** Stdin may go to the host now (the input byte rate). */
  inputReady(): boolean {
    if (!this.inRateTimer && this.inRate.ready(this.manager.now())) return true;
    this.armInRate();
    return false;
  }

  spendInput(bytes: number) {
    this.inRate.spend(bytes, this.manager.now());
  }

  /** stdin data bytes handed to the node (the §10 `bytesIn`). */
  countInput(bytes: number) {
    this.bytesIn += bytes;
  }

  /** Resume output once its byte rate allows a frame again (independent of input). */
  private armOutRate() {
    if (this.outRateTimer || this.state === "ended") return;
    this.outRateTimer = setTimeout(() => {
      this.outRateTimer = undefined;
      if (this.state !== "ended") this.pumpAll();
    }, this.outRate.waitMs(this.manager.now()));
    this.outRateTimer.unref?.();
  }

  /** Resume input once its byte rate allows a frame again (independent of output). */
  private armInRate() {
    if (this.inRateTimer || this.state === "ended") return;
    this.inRateTimer = setTimeout(() => {
      this.inRateTimer = undefined;
      if (this.state !== "ended") this.flushAllInput();
    }, this.inRate.waitMs(this.manager.now()));
    this.inRateTimer.unref?.();
  }

  /** Re-try both directions shortly (a socket buffer or a budget was full). */
  armDrain() {
    if (this.drainTimer || this.state === "ended") return;
    this.drainTimer = setTimeout(() => {
      this.drainTimer = undefined;
      if (this.state === "ended") return;
      this.flushAllInput();
      this.pumpAll();
    }, CLIENT_DRAIN_POLL_MS);
    this.drainTimer.unref?.();
  }

  private bufferedAmount(): number {
    try {
      const amount = Number(this.socket?.bufferedAmount ?? 0);
      return Number.isFinite(amount) && amount >= 0 ? amount : CLIENT_BUFFER_HIGH_BYTES;
    } catch {
      return CLIENT_BUFFER_HIGH_BYTES;
    }
  }

  // -- client transport --------------------------------------------------------

  private violation(reason: string) {
    this.manager.audit(`client ${reason}`);
    this.end("protocol_violation", { code: "protocol_error", message: reason });
  }

  private sendControl(frame: ConnectServerControl, final = false) {
    if (!this.socket || this.socket.readyState !== WS_OPEN) return;
    if (!final && this.state !== "live") return;
    if (!final && this.bufferedAmount() >= CLIENT_BUFFER_HARD_BYTES) {
      this.end("backpressure", { code: "timeout", message: "client is not reading" });
      return;
    }
    try {
      this.socket.send(JSON.stringify(frame));
    } catch {
      this.detachSoon();
    }
  }

  private sendData(frame: Uint8Array): boolean {
    if (!this.socket || this.socket.readyState !== WS_OPEN) {
      this.detachSoon();
      return false;
    }
    try {
      this.socket.send(frame);
      return true;
    } catch {
      this.detachSoon();
      return false;
    }
  }

  private closeSocket() {
    try {
      this.socket?.close(CONNECT_CLOSE_CODE, "end");
    } catch {
      /* Transport already gone. */
    }
  }

  private detachSoon() {
    queueMicrotask(() => {
      if (this.state === "ended") return;
      this.socket = undefined;
      this.end("detached");
    });
  }
}

/** Owns every CLI connection and every channel of this process. */
export class ConnectManager {
  private readonly connections = new Set<ConnectConnection>();
  private readonly reservations = new Set<{ binding: SandboxConnectBinding }>();
  private readonly channelsByKey = new Map<string, Chan>();
  private readonly hosts = new Map<HostSocket, HostState>();
  private unsubscribe: (() => void) | undefined;
  private disposed = false;
  private auditWindow = { start: 0, count: 0 };
  private lifecycleSeq = 0;
  private offLifecycleMark: (() => void) | undefined;

  readonly check: ConnectCheck;
  readonly revalidateMs: number;
  readonly checkTimeoutMs: number;
  readonly pingMs: number;
  readonly idleMs: number;
  readonly openTimeoutMs: number;
  readonly maxLifetimeMs: number;
  readonly maxBytesPerSecond: number;
  readonly now: () => number;
  private readonly connectAudit: ConnectAudit | undefined;

  constructor(
    private readonly links: ConnectHosts,
    options: ConnectManagerOptions = {},
  ) {
    this.check = options.check ?? checkSandboxConnect;
    this.revalidateMs = options.revalidateMs ?? CONNECT_REVALIDATE_MS;
    this.checkTimeoutMs = options.checkTimeoutMs ?? CONNECT_CHECK_TIMEOUT_MS;
    this.pingMs = options.pingMs ?? CONNECT_LIMITS.pingIntervalMs;
    this.idleMs = options.idleMs ?? CONNECT_LIMITS.idleTimeoutMs;
    this.openTimeoutMs = options.openTimeoutMs ?? CONNECT_LIMITS.openTimeoutMs;
    this.maxLifetimeMs = options.maxLifetimeMs ?? CONNECT_MAX_LIFETIME_MS;
    this.maxBytesPerSecond = options.maxBytesPerSecond ?? CONNECT_DEFAULT_MAX_BYTES_PER_SECOND;
    this.now = options.now ?? Date.now;
    this.connectAudit = options.audit;
  }

  /** §10 audit hooks: never throw into the relay. */
  auditOpened(open: ConnectAuditOpen) {
    try {
      this.connectAudit?.opened(open);
    } catch {
      /* The audit never breaks the relay. */
    }
  }

  auditClosed(close: ConnectAuditClose) {
    try {
      this.connectAudit?.closed(close);
    } catch {
      /* The audit never breaks the relay. */
    }
  }

  get shuttingDown(): boolean {
    return this.disposed;
  }

  resources(): ConnectManagerResources {
    const channels = [...this.hosts.values()].flatMap((state) => [...state.channels]);
    let timers = 0;
    for (const connection of this.connections) timers += connection.timers;
    timers += channels.filter((chan) => chan.openTimer !== undefined).length;
    return {
      connections: this.connections.size,
      reservations: this.reservations.size,
      channels: channels.length,
      unreaped: channels.filter((chan) => chan.state === "unreaped").length,
      timers,
      hostSockets: this.hosts.size,
      subscribed: this.unsubscribe ? 1 : 0,
    };
  }

  /** Live connections (metadata only; tests). */
  list(): readonly ConnectConnection[] {
    return [...this.connections];
  }

  /** The host channel fences of live channels (metadata only; tests). */
  channelFences(): ChannelFence[] {
    return [...this.channelsByKey.values()].map((chan) => ({ ...chan.fence }));
  }

  // -- admission ------------------------------------------------------------------

  /**
   * Reserve a connection slot before the upgrade (caps are 429 refusals).
   * The slot becomes the connection at `attach`, or is released.
   */
  reserve(
    binding: SandboxConnectBinding,
    lifecycleMark?: number,
  ):
    | { ok: true; reservation: ConnectReservation }
    | { ok: false; reason: "shutdown" | "capacity" } {
    if (this.disposed) return { ok: false, reason: "shutdown" };
    const all = [...this.connections, ...this.reservations].map((entry) =>
      entry instanceof ConnectConnection
        ? { ownerId: entry.ownerId, keyId: entry.keyId, sandboxId: entry.sandboxId }
        : entry.binding,
    );
    if (
      all.filter((entry) => entry.sandboxId === binding.sandboxId).length >=
        CONNECT_CONNECTION_CAPS.perSandbox ||
      all.filter((entry) => entry.keyId === binding.keyId).length >=
        CONNECT_CONNECTION_CAPS.perKey ||
      all.filter((entry) => entry.ownerId === binding.ownerId).length >=
        CONNECT_CONNECTION_CAPS.perOwner
    )
      return { ok: false, reason: "capacity" };
    const entry = { binding };
    this.reservations.add(entry);
    const timer = setTimeout(() => this.reservations.delete(entry), RESERVATION_TTL_MS);
    timer.unref?.();
    return {
      ok: true,
      reservation: {
        binding,
        lifecycleMark,
        release: () => {
          clearTimeout(timer);
          this.reservations.delete(entry);
        },
      },
    };
  }

  /** The upgrade completed: the reservation becomes a connection. */
  attach(
    reservation: ConnectReservation,
    principal: ServicePrincipal,
    retained: Retained,
  ): ConnectConnection {
    reservation.release();
    const connection = new ConnectConnection(
      reservation.binding,
      principal,
      retained,
      this,
      reservation.lifecycleMark,
    );
    if (this.disposed) {
      connection.end("shutdown");
      return connection;
    }
    this.start();
    this.connections.add(connection);
    return connection;
  }

  forget(connection: ConnectConnection) {
    this.connections.delete(connection);
    if (this.connections.size === 0) this.stopListening();
  }

  /**
   * A counter of sandbox lifecycle changes (any sandbox), subscribed from the
   * first call until dispose. The route samples it before its authorization
   * read; a connection whose mark moved re-reads before its hello, so a stop
   * or a new generation between that read and the socket's open is not
   * missed until the next 15 s re-read.
   */
  lifecycleMark(): number {
    if (!this.offLifecycleMark && !this.disposed)
      this.offLifecycleMark = subscribeSandboxTerminalLifecycle(() => {
        this.lifecycleSeq += 1;
      });
    return this.lifecycleSeq;
  }

  lifecycleChangedSince(mark: number | undefined): boolean {
    return (
      mark !== undefined && (this.offLifecycleMark === undefined || mark !== this.lifecycleSeq)
    );
  }

  /** Graceful shutdown: every connection ends `shutdown`; no new connection opens. */
  dispose() {
    this.disposed = true;
    this.offLifecycleMark?.();
    this.offLifecycleMark = undefined;
    for (const connection of [...this.connections]) connection.end("shutdown");
    this.stopListening();
  }

  private start() {
    if (this.unsubscribe) return;
    const offAuthority = onAuthorityCommitted((scope) => {
      for (const connection of [...this.connections]) {
        const binding = connection;
        if (
          scope.kind === "global" ||
          (scope.credentialId !== undefined && scope.credentialId === binding.keyId) ||
          (scope.ownerId !== undefined &&
            (scope.ownerId === binding.ownerId || scope.ownerId === binding.hostOwnerId)) ||
          (scope.hostId !== undefined && scope.hostId === binding.hostId) ||
          // Any other participant of the retained guard (a pool owner):
          // the commit made it stale.
          !connection.current()
        )
          void connection.revalidate();
      }
    });
    const offLifecycle = subscribeSandboxTerminalLifecycle((change) => {
      for (const connection of [...this.connections])
        if (change === "all" || change.sandboxIds.has(connection.sandboxId))
          void connection.revalidate();
    });
    this.unsubscribe = () => {
      offAuthority();
      offLifecycle();
    };
  }

  private stopListening() {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  // -- host links -------------------------------------------------------------------

  /** Whether the binding's host can carry channels now (the upgrade's refusal class). */
  hostAvailability(binding: SandboxConnectBinding): "ok" | "outdated" | "unavailable" {
    const host = this.links.connectHost(binding.hostId);
    if ("error" in host)
      return host.error.code === "unsupported_capability" ? "outdated" : "unavailable";
    return this.hostLink(binding) ? "ok" : "unavailable";
  }

  /** The binding's host link, only while it is the same host connection. */
  hostLink(binding: SandboxConnectBinding): ConnectHostLink | null {
    const host = this.links.connectHost(binding.hostId);
    if ("error" in host) return null;
    const { link } = host;
    if (
      link.hostId !== binding.hostId ||
      link.ownerId !== binding.hostOwnerId ||
      link.epoch !== binding.epoch ||
      link.socket.readyState !== WS_OPEN
    )
      return null;
    return link;
  }

  /** Per-host caps (the node enforces the same), counted until settled. */
  admitOpen(
    link: ConnectHostLink,
    creatorId: string,
    kind: ChannelKind,
  ): { code: SandboxErrorCode; message: string } | null {
    const state = this.hostState(link.socket);
    const now = this.now();
    state.opens = state.opens.filter(({ at }) => now - at < OPEN_WINDOW_MS);
    if (
      state.opens.length >= CHANNEL_LIMITS.opensPerMinutePerHost ||
      state.opens.filter((open) => open.creatorId === creatorId).length >=
        CHANNEL_LIMITS.opensPerMinutePerGuestCreator
    )
      return { code: "rate_limited", message: "channel open rate exceeded for this host" };
    const counted = [...state.channels];
    if (
      counted.length >= CHANNEL_LIMITS.maxChannelsPerHost ||
      (kind === "pty" &&
        counted.filter((chan) => chan.kind === "pty").length >=
          CHANNEL_LIMITS.maxPtyChannelsPerHost) ||
      counted.filter((chan) => chan.creatorId === creatorId).length >=
        CHANNEL_LIMITS.maxChannelsPerGuestCreator
    )
      return { code: "host_capacity", message: "host channel capacity reached" };
    return null;
  }

  openChannel(
    connection: ConnectConnection,
    link: ConnectHostLink,
    binding: SandboxConnectBinding,
    open: Extract<ConnectClientControl, { type: "open" }>,
  ): Chan | null {
    const fence: ChannelFence = {
      // Minted, never derived from the client's number.
      channelId: mintId("h"),
      connectionId: connection.connectionId,
      hostId: link.hostId,
      epoch: link.epoch,
      target: { kind: "sandbox", sandboxId: binding.sandboxId, generation: binding.generation },
    };
    const chan: Chan = {
      clientId: open.channel,
      kind: open.kind,
      fence,
      link,
      creatorId: binding.ownerId,
      connection,
      state: "opening",
      clientDone: false,
      closeSent: false,
      killSent: false,
      exited: false,
      out: [],
      outQueued: 0,
      hostNext: [0, 0],
      inControl: 0,
      hostEof: [false, false],
      notices: 0,
      nodeNotices: 0,
      clientSent: [0, 0],
      clientAcked: [0, 0],
      inflight: [[], []],
      sentAt: [[], []],
      hostAckDue: [null, null],
      inSizes: [],
      inUnackedBytes: 0,
      inClientAcked: 0,
      inNext: 0,
      inSent: 0,
      inAcked: 0,
      ackDue: null,
      stdinEof: false,
      in: [],
      violations: 0,
    };
    if (
      !this.sendToHost(chan, {
        type: "channel.open",
        fence,
        kind: open.kind,
        ...(open.argv ? { argv: open.argv } : {}),
        login: open.login ?? false,
        ...(open.cwd ? { cwd: open.cwd } : {}),
        ...(open.env ? { env: open.env } : {}),
        ...(open.pty ? { pty: open.pty } : {}),
        // The relay target: a guest port or socket path, never a host.
        ...(open.port !== undefined ? { port: open.port } : {}),
        ...(open.path !== undefined ? { path: open.path } : {}),
      })
    )
      return null;
    const state = this.hostState(link.socket);
    state.opens.push({ at: this.now(), creatorId: binding.ownerId });
    state.channels.add(chan);
    this.channelsByKey.set(hostKey(fence), chan);
    chan.openTimer = setTimeout(() => {
      chan.openTimer = undefined;
      if (chan.state === "opening")
        this.closeChannel(chan, "expired", {
          code: "timeout",
          message: "channel open was not answered in time",
        });
    }, this.openTimeoutMs);
    chan.openTimer.unref?.();
    return chan;
  }

  /** The single server→node input gate: in order, authorized, within the window. */
  flushInput(chan: Chan, budget = Number.POSITIVE_INFINITY): number {
    this.flushHostAcks(chan);
    const connection = chan.connection;
    if (!connection || connection.ended || chan.closeSent) return 0;
    let moved = 0;
    while (chan.in.length > 0 && moved < budget) {
      if (!connection.current()) {
        void connection.revalidate();
        return moved;
      }
      // A stale host ticket: the host's refresh resumes this (resumeHost).
      if (!chan.link.authorized()) return moved;
      const item = chan.in[0]!;
      // A node that stops reading holds client input here (bounded by the
      // window and the control queue), never in the server's socket buffer:
      // bulk stdin up to the high mark, controls up to the control mark.
      if (
        hostBuffered(chan.link.socket) >=
        (item.kind === "data" ? HOST_BUFFER_HIGH_BYTES : HOST_BUFFER_CONTROL_BYTES)
      ) {
        connection.armDrain();
        return moved;
      }
      if (item.kind === "data") {
        if (chan.inSent - chan.inAcked >= windowOf(chan.kind)) return moved;
        if (!connection.inputReady()) return moved;
        chan.in.shift();
        try {
          chan.link.socket.send(
            encodeChannelDataFrame(
              {
                type: "channel.data",
                fence: chan.fence,
                stream: "stdin",
                seq: item.seq,
              } satisfies ChannelDataMetadata,
              item.body,
            ),
          );
        } catch {
          this.closeChannel(chan, "host_disconnected");
          return moved;
        }
        connection.spendInput(item.body.byteLength);
        connection.countInput(item.body.byteLength);
        chan.inSent += 1;
        moved += 1;
        continue;
      }
      if (!connection.inputReady()) return moved;
      chan.in.shift();
      chan.inControl -= 1;
      connection.spendInput(CONTROL_FRAME_COST_BYTES);
      moved += 1;
      let sentOk = true;
      switch (item.kind) {
        case "eof":
          sentOk = this.sendToHost(chan, {
            type: "channel.eof",
            fence: chan.fence,
            stream: "stdin",
            frames: item.frames,
          });
          break;
        case "resize":
          sentOk = this.sendToHost(chan, {
            type: "channel.resize",
            fence: chan.fence,
            rows: item.rows,
            cols: item.cols,
          });
          break;
        case "signal":
          sentOk = this.sendToHost(chan, {
            type: "channel.signal",
            fence: chan.fence,
            signal: item.signal,
          });
          break;
        case "close":
          // A normal close: the node hangs the session up; its exit follows.
          chan.closeSent = true;
          chan.in = [];
          chan.inControl = 0;
          if (
            !this.sendToHost(chan, { type: "channel.close", fence: chan.fence, intent: "client" })
          )
            this.closeChannel(chan, "host_disconnected");
          return moved;
      }
      if (!sentOk) {
        this.closeChannel(chan, "host_disconnected");
        return moved;
      }
    }
    return moved;
  }

  ackHost(chan: Chan, stream: OutputStream, seq: number) {
    // After the node's exit the channel is gone there: no credit to return.
    if (chan.exited) return;
    chan.hostAckDue[streamIndex(stream)] = seq;
    this.flushHostAcks(chan);
  }

  /**
   * Credit back to the node, cumulative and coalesced per stream: a node
   * that stops reading gets at most one pending ack per stream (the state
   * here is bounded), never a growing socket buffer.
   */
  flushHostAcks(chan: Chan) {
    if (chan.exited || chan.state !== "open" || !chan.connection || chan.connection.ended) {
      chan.hostAckDue = [null, null];
      return;
    }
    if (chan.hostAckDue[0] === null && chan.hostAckDue[1] === null) return;
    // Credit moves only while the connection's authority and the host's
    // ticket hold, like every other frame; it waits, coalesced, meanwhile.
    if (!chan.connection.current() || !chan.link.authorized()) return;
    if (hostBuffered(chan.link.socket) >= HOST_BUFFER_CONTROL_BYTES) {
      chan.connection?.armDrain();
      return;
    }
    for (const stream of ["stdout", "stderr"] as const) {
      const seq = chan.hostAckDue[streamIndex(stream)];
      if (seq === null) continue;
      chan.hostAckDue[streamIndex(stream)] = null;
      this.sendToHost(chan, { type: "channel.ack", fence: chan.fence, stream, seq });
    }
  }

  /** The host ticket was refreshed: send the input it held back. */
  resumeHost(socket: HostSocket) {
    const state = this.hosts.get(socket);
    if (!state) return;
    for (const chan of [...state.channels]) this.flushInput(chan);
  }

  /**
   * A server decision for one channel (open deadline, a node violation, a
   * lost transport): the client hears its exit, the node gets one close.
   */
  closeChannel(chan: Chan, intent: ConnectCloseIntent, error?: ConnectError) {
    if (chan.state !== "opening" && chan.state !== "open") return;
    clearTimeout(chan.openTimer);
    chan.openTimer = undefined;
    chan.state = "closing";
    chan.connection?.closeChannelForClient(chan, intent, error);
    this.closeChannelOnHost(chan, intent);
  }

  /**
   * One `channel.close` per decision: a normal close is asked once, and a
   * later kill-class decision (revocation, lifecycle) upgrades it once more,
   * as the node expects. An unsendable close releases at once.
   */
  closeChannelOnHost(chan: Chan, intent: ConnectCloseIntent) {
    clearTimeout(chan.openTimer);
    chan.openTimer = undefined;
    // A server-made exit still waiting for the authority gate stays queued
    // (the client must hear it, and only then is the channel forgotten).
    chan.out = chan.out.filter((item) => item.kind === "exit");
    chan.outQueued = 0;
    chan.in = [];
    chan.inControl = 0;
    if (chan.state === "opening" || chan.state === "open") chan.state = "closing";
    if (chan.state === "ended") return;
    if (chan.exited) {
      // Unreaped: the node may still be settling a normal end, which a
      // kill-class decision (a revocation) upgrades to a scope kill.
      if (!chan.killSent && intent !== "client") {
        chan.killSent = true;
        chan.closeSent = true;
        this.sendToHost(chan, { type: "channel.close", fence: chan.fence, intent });
      }
      return;
    }
    if (chan.closeSent) {
      if (!chan.killSent && intent !== "client") {
        chan.killSent = true;
        this.sendToHost(chan, { type: "channel.close", fence: chan.fence, intent });
      }
      return;
    }
    chan.closeSent = true;
    if (intent !== "client") chan.killSent = true;
    if (!this.sendToHost(chan, { type: "channel.close", fence: chan.fence, intent }))
      this.release(chan);
  }

  // -- node frames (already gated by the host ticket) -------------------------------

  handleHostControl(socket: HostSocket, message: HostChannelControl) {
    const chan = this.lookup(socket, message.fence);
    if (!chan) return;
    const connection = chan.connection;
    switch (message.type) {
      case "channel.ready":
        if (chan.state === "closing" || chan.state === "ended") return;
        if (chan.state !== "opening" || (chan.kind === "pty") !== (message.pty !== undefined)) {
          this.violation(chan, "unexpected channel.ready");
          return;
        }
        clearTimeout(chan.openTimer);
        chan.openTimer = undefined;
        chan.state = "open";
        this.enqueue(chan, { kind: "ready", ...(message.pty ? { pty: message.pty } : {}) });
        return;
      case "channel.ack":
        if (chan.state !== "open" && chan.state !== "opening") return;
        if (message.seq < chan.inAcked || message.seq >= chan.inSent) {
          this.violation(chan, "channel stdin ack out of range");
          return;
        }
        chan.inAcked = message.seq + 1;
        connection?.stdinAcked(chan, message.seq);
        this.flushInput(chan);
        return;
      case "channel.eof": {
        if (chan.state !== "open") return;
        if (isRelay(chan.kind) && message.stream !== "stdout") {
          this.violation(chan, "relay eof on a stream it does not have");
          return;
        }
        const index = streamIndex(message.stream);
        if (chan.hostEof[index] || message.frames !== chan.hostNext[index]) {
          this.violation(chan, "invalid channel eof");
          return;
        }
        chan.hostEof[index] = true;
        this.enqueue(chan, { kind: "eof", stream: message.stream, frames: message.frames });
        return;
      }
      case "channel.error":
        if (chan.state !== "open" && chan.state !== "opening") return;
        chan.nodeNotices += 1;
        if (chan.nodeNotices > CONNECT_NOTICES_PER_CHANNEL) {
          this.violation(chan, "too many channel notices");
          return;
        }
        this.enqueue(chan, { kind: "error", code: message.code });
        return;
      case "channel.exit": {
        if (chan.exited) {
          // The node's settle of an uncertain end: only a confirmed reap releases.
          if (message.reaped) this.release(chan);
          else this.violation(chan, "repeated unsettled channel exit");
          return;
        }
        // The node counts every frame it sent; the relay is ordered, so a
        // different count means frames were lost or invented.
        if (
          message.frames.stdout !== chan.hostNext[0] ||
          message.frames.stderr !== chan.hostNext[1]
        ) {
          chan.exited = true;
          clearTimeout(chan.openTimer);
          chan.openTimer = undefined;
          if (chan.state === "opening" || chan.state === "open") chan.state = "closing";
          chan.connection?.closeChannelForClient(chan, "protocol_violation", {
            code: "protocol_error",
            message: "channel exit frame counts mismatch",
          });
          if (message.reaped) this.release(chan);
          else {
            chan.state = "unreaped";
            // Unsettled: the node may still be ending it; make that a kill.
            this.closeChannelOnHost(chan, "protocol_violation");
          }
          return;
        }
        chan.exited = true;
        clearTimeout(chan.openTimer);
        chan.openTimer = undefined;
        const decided = chan.state === "closing" || chan.clientDone;
        chan.state = message.reaped ? "ended" : "unreaped";
        if (!decided) {
          const exit: OutItem = {
            kind: "exit",
            ...(message.exitCode !== undefined ? { exitCode: message.exitCode } : {}),
            ...(message.signal !== undefined ? { signal: message.signal } : {}),
            ...(message.intent ? { intent: clientIntent(message.intent) } : {}),
            ...(message.error ? { error: clientError(message.error) } : {}),
            reaped: message.reaped,
          };
          // A close decision on the node (an intent) already dropped what was
          // unread; output still queued here is dropped too, so the exit is
          // never stuck behind credit the client will not return. A natural
          // exit waits for every frame before it.
          if (message.intent) {
            // EOFs counting dropped frames could never complete: they go too.
            const dropped = chan.outQueued > 0;
            chan.out = chan.out.filter(
              (item) => item.kind !== "data" && !(dropped && item.kind === "eof"),
            );
            chan.outQueued = 0;
          }
          this.enqueue(chan, exit);
        }
        chan.in = [];
        chan.inControl = 0;
        if (message.reaped) this.release(chan);
        return;
      }
    }
  }

  handleHostData(socket: HostSocket, metadata: ChannelDataMetadata, body: Uint8Array) {
    const chan = this.lookup(socket, metadata.fence);
    if (!chan) return;
    // Output racing a close decision is dropped: the node ends it anyway.
    if (chan.state === "closing" || chan.clientDone) return;
    if (chan.state !== "open") {
      this.violation(chan, "channel output outside an open channel");
      return;
    }
    if (
      metadata.stream === "stdin" ||
      (isRelay(chan.kind) && metadata.stream !== "stdout") ||
      body.byteLength > frameMax(chan.kind)
    ) {
      this.violation(chan, "invalid channel output frame");
      return;
    }
    const index = streamIndex(metadata.stream);
    if (chan.hostEof[index]) {
      this.violation(chan, "channel output after its eof");
      return;
    }
    if (metadata.seq < chan.hostNext[index]) {
      this.violation(chan, "duplicate channel output sequence");
      return;
    }
    if (metadata.seq > chan.hostNext[index]) {
      this.closeChannel(chan, "protocol_violation", {
        code: "protocol_error",
        message: "channel output sequence gap",
      });
      return;
    }
    if (chan.outQueued >= windowOf(chan.kind)) {
      this.closeChannel(chan, "protocol_violation", {
        code: "protocol_error",
        message: "channel output beyond its window",
      });
      return;
    }
    chan.hostNext[index] += 1;
    this.enqueue(chan, {
      kind: "data",
      stream: metadata.stream,
      seq: metadata.seq,
      body: body.slice(),
    });
  }

  /**
   * The host socket ended (or was replaced): every connection bound to that
   * host connection ends `host_disconnected`, and every channel on it is
   * settled (the node kills the channels of a lost relay itself).
   */
  removeHostSocket(socket: HostSocket, hostId: string) {
    const state = this.hosts.get(socket);
    for (const connection of [...this.connections]) {
      if (connection.hostId !== hostId) continue;
      const link = this.hostLink(connection.bound);
      if (link === null || link.socket === socket)
        connection.end("host_disconnected", {
          code: "disconnected",
          message: "host connection ended",
        });
    }
    if (!state) return;
    for (const chan of [...state.channels]) {
      chan.closeSent = true;
      this.release(chan);
    }
    this.hosts.delete(socket);
  }

  // -- internals ---------------------------------------------------------------------

  private enqueue(chan: Chan, item: OutItem) {
    if (chan.clientDone || !chan.connection) return;
    chan.out.push(item);
    if (item.kind === "data") chan.outQueued += 1;
    chan.connection.pump(chan);
  }

  /** The ONE release of a channel's host capacity (idempotent). */
  private release(chan: Chan) {
    clearTimeout(chan.openTimer);
    chan.openTimer = undefined;
    chan.state = "ended";
    chan.in = [];
    chan.inControl = 0;
    const key = hostKey(chan.fence);
    if (this.channelsByKey.get(key) === chan) this.channelsByKey.delete(key);
    const state = this.hosts.get(chan.link.socket);
    if (state?.channels.delete(chan)) {
      state.tombstones.push(key);
      if (state.tombstones.length > CONNECT_FOREIGN_FRAME_LIMIT) state.tombstones.shift();
      if (state.channels.size === 0 && state.opens.length === 0 && state.foreign === 0)
        this.hosts.delete(chan.link.socket);
    }
    chan.connection?.released(chan);
  }

  private lookup(socket: HostSocket, fence: ChannelFence): Chan | undefined {
    const chan = this.channelsByKey.get(hostKey(fence));
    if (!chan || chan.link.socket !== socket) {
      const state = this.hostState(socket);
      state.foreign += 1;
      if (!state.tombstones.includes(hostKey(fence)))
        this.hostAudit(state, "foreign channel frame");
      if (state.foreign > CONNECT_FOREIGN_FRAME_LIMIT)
        this.links.closeHostSocket(socket, "Too many foreign channel frames.");
      return undefined;
    }
    if (!sameFence(chan.fence, fence)) {
      this.violation(chan, "channel fence mismatch");
      return undefined;
    }
    return chan;
  }

  private violation(chan: Chan, reason: string) {
    chan.violations += 1;
    const state = this.hosts.get(chan.link.socket);
    if (state) this.hostAudit(state, reason);
    if (chan.violations >= CHANNEL_LIMITS.fenceViolationLimit)
      this.closeChannel(chan, "protocol_violation", {
        code: "protocol_error",
        message: "repeated channel protocol violations",
      });
  }

  private hostAudit(state: HostState, reason: string) {
    if (state.audits >= AUDIT_LOGS_PER_SOCKET) return;
    state.audits += 1;
    console.warn(`[sandbox-connect] channel frame dropped (${reason})`);
  }

  /** Client protocol refusals (rate-capped; never request data). */
  audit(reason: string) {
    const now = this.now();
    if (now - this.auditWindow.start >= 60_000) this.auditWindow = { start: now, count: 0 };
    if (this.auditWindow.count >= AUDIT_LOGS_PER_MINUTE) return;
    this.auditWindow.count += 1;
    console.warn(`[sandbox-connect] connection ended (${reason})`);
  }

  private sendToHost(
    chan: Chan,
    message: Parameters<typeof encodeServerControlMessage>[0],
  ): boolean {
    if (chan.link.socket.readyState !== WS_OPEN) return false;
    if (hostBuffered(chan.link.socket) >= HOST_BUFFER_HARD_BYTES) {
      // The node stopped reading for good: what must reach it (closes) cannot.
      this.links.closeHostSocket(chan.link.socket, "Host is not reading channel frames.");
      return false;
    }
    try {
      chan.link.socket.send(encodeServerControlMessage(message, chan.link.protocolVersion));
      return true;
    } catch {
      return false;
    }
  }

  private hostState(socket: HostSocket): HostState {
    let state = this.hosts.get(socket);
    if (!state) {
      state = { channels: new Set(), opens: [], tombstones: [], foreign: 0, audits: 0 };
      this.hosts.set(socket, state);
    }
    return state;
  }
}
