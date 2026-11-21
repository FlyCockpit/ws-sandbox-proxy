import { ORPCError } from "@orpc/server";
import { readCredentialsAvailability } from "@wssp/api/credentials/availability";
import { registerCredentialFrameSink } from "@wssp/api/credentials/relay";
import { revalidateSandboxHostIdentity } from "@wssp/api/lib/host-token-access";
import { checkAcceptedDispatchAuthority } from "@wssp/api/lib/sdk-key-access";
import {
  type AuthorizingPrincipal,
  KEY_FREE_CLEANUP_KINDS,
  relayDispatchKind,
} from "@wssp/api/sandbox/contracts";
import {
  buildCommandRunOperationDispatchMessage,
  commandRunDispatchBuildInputFromOutboxPayload,
} from "@wssp/api/sandbox/dispatch-control-envelope";
import {
  HostImageMissing,
  HostImageRejected,
  type HostSandboxProbeInput,
  type LiveProbeState,
} from "@wssp/api/sandbox/host-image-verifier";
import { fsProcessHostSupported } from "@wssp/api/sandbox/host-protocol";
import { hostJournalKey, hostJournalKeyAcknowledged } from "@wssp/api/sandbox/idempotency";
import type { HostLease } from "@wssp/api/sandbox/lease-wire";
import { notifySandboxDispatchPending, systemDispatchAllowed } from "@wssp/api/sandbox/outbox";
import { outboxOperationWhere } from "@wssp/api/sandbox/outbox-operation";
import {
  controlAllowed,
  dispatchClassOf,
  recordedKeyIdOf,
} from "@wssp/api/sandbox/principal-kinds";
import {
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
  requireRelayWorkload,
} from "@wssp/api/sandbox/relay-fence";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import { markHostQuiescing, settleHostQuiesce } from "@wssp/api/template-builds/quiesce-hold";
import prisma, { type Prisma } from "@wssp/db";
import {
  authorityTicket,
  type CommittedAuthorityScope,
  onAuthorityCommitted,
} from "@wssp/db/authority";
import { env } from "@wssp/env/server";
import {
  dispatchHasDiskFields,
  FS_PROCESS_LIMITS,
  pinnedAllocationV11Schema,
  TRANSFER_MAX_BYTES,
  vmSizeSchema,
} from "@wssp/sandbox-contracts";
import {
  type TunnelHostLink,
  wakeTunnelController,
} from "../../../../packages/api/src/sandbox/tunnels/bridge.js";
import { tunnelController } from "../../../../packages/api/src/sandbox/tunnels/controller.js";
import { AllocationAttestation } from "./allocation-attestation.js";
import type { SandboxHostWebsocketIdentity } from "./auth.js";
import { AvailabilityCensus } from "./availability-census.js";
import { negotiatedOutputChunkBytes } from "./command-output.js";
import { ConnectAuditRecorder } from "./connect-audit.js";
import { ConnectManager, type HostChannelControl } from "./connect-manager.js";
import { CredentialSessionRelay, offerReturnKey } from "./credential-handlers.js";
import { deploymentEgressBlocklist, egressBlocklistFrame } from "./egress-blocklist.js";
import { EgressHintThrottle, handleEgressRefused } from "./egress-hints.js";
import { acknowledgeExecutionConfig } from "./execution-config-ack.js";
import { type HostAccessLink, HostAccessRelay } from "./host-access.js";
import { HOST_CONTROL_MAX_BYTES } from "./host-access-protocol.js";
import { recordHostEgressState } from "./host-egress-state.js";
import { commitHostHello } from "./host-hello.js";
import { recordHostLeasePolicy } from "./host-lease-policy.js";
import { HostTerminalPolicies } from "./host-terminal-policy.js";
import {
  InventoryCensus,
  judgeExpiryStatus,
  recordHostAdmission,
  recordHostHeartbeat,
  recordHostInventory,
} from "./inventory-reconcile.js";
import { acknowledgeJournalKey, disconnectJournalKey } from "./journal-key-ack.js";
import { ObservationFence } from "./observation-fence.js";
import {
  acceptFencedBinaryChunk,
  acceptFencedOutputBatch,
  adoptOperation,
  applyOperationProgress,
  applyOperationResult,
  applyProcessStarted,
  confirmOperationReceipt,
  finishHostReconciliation,
  listUnacknowledgedDispatches,
  PENDING_RECEIPT_MAX_HOLD_MS,
  type RelaySender,
  settleUndeliveredDispatch,
} from "./operation-handlers.js";
import {
  CHANNEL_LIMITS,
  type ChannelDataMetadata,
  classifyRelayDispatchKind,
  type DaemonControlMessage,
  DISPATCH_AUDIT_PAGE_MAX,
  encodeBinaryFrame,
  encodeServerControlMessage,
  negotiatedCapabilities,
  parseBinaryFrame,
  parseChannelDataFrame,
  parseDaemonControlFrame,
  parseParsedDaemonControlFrame,
  parseTerminalDataFrame,
  SANDBOX_BINARY_CHUNK_MAX_BYTES,
  SANDBOX_FRAME_MAX_BYTES,
  SANDBOX_RELAY_PROTOCOL_VERSION,
  type SandboxErrorCode,
  SandboxRelayDispatchValidationError,
  SandboxRelayVmSizeMismatchError,
  type StreamBinaryMetadata,
  TERMINAL_LIMITS,
  type TerminalCloseIntent,
  type TerminalDataMetadata,
} from "./protocol.js";
import {
  HOST_CREDENTIAL_INACTIVE_ERROR,
  type HostTerminalControl,
  SandboxTerminalManager,
  TERMINAL_MAX_PENDING_RESIZES,
} from "./terminal-manager.js";

/**
 * Receive backpressure (P0-2). Counts include the in-flight frame; queue
 * storage is dropped immediately on removal, and removal releases the pause
 * (a paused transport cannot finish its close handshake). At the high-water
 * mark the server stops reading the host socket (TCP flow control then blocks
 * the daemon's writes) and resumes at the low-water mark. Nothing is closed:
 * pausing only delays frames, in order.
 *
 * Liveness bound: a pause lasts as long as processing the frames between the
 * marks takes. The daemon's 30 s write timeout and 30 s silence deadline
 * only fire if the server makes no progress for 30 s, which ends the session
 * as a transport loss (carried work is adopted on reconnect), exactly as a
 * stalled server would without pausing.
 */
export const SANDBOX_RECEIVE_MAX_FRAMES = 256;
export const SANDBOX_RECEIVE_MAX_BYTES = 8 * 1024 * 1024;
export const SANDBOX_RECEIVE_RESUME_FRAMES = SANDBOX_RECEIVE_MAX_FRAMES / 2;
export const SANDBOX_RECEIVE_RESUME_BYTES = SANDBOX_RECEIVE_MAX_BYTES / 2;
/** Memory ceiling for frames that still arrive while paused (what the
 * websocket library had already buffered). A paused, honest peer cannot reach
 * it; reaching it is a protocol violation. */
export const SANDBOX_RECEIVE_HARD_MAX_FRAMES = SANDBOX_RECEIVE_MAX_FRAMES * 16;
export const SANDBOX_RECEIVE_HARD_MAX_BYTES = SANDBOX_RECEIVE_MAX_BYTES * 4;
/**
 * Half-open detection (WP4). The server pings every host socket on this
 * cadence; a socket with no pong and no frame for the timeout is removed
 * (epoch revoked, host DISCONNECTED). The liveness clock stops while receive
 * backpressure has paused the reader: a paused socket delivers neither frames
 * nor pongs, so its silence is the server's own doing. Pongs never enter the
 * receive queue (`ws` answers them at the transport).
 */
/**
 * The protocol error returned when a daemon control frame fails strict parsing.
 */
export const UNPARSED_CONTROL_FRAME_MESSAGE = "Invalid sandbox relay control frame.";
export const SANDBOX_RELAY_PING_INTERVAL_MS = 15_000;
export const SANDBOX_RELAY_LIVENESS_TIMEOUT_MS = 45_000;
/** A liveness check that fires this late means the event loop stalled: frames
 * and pongs may be waiting behind it, so it defers instead of deciding. */
const LIVENESS_LATE_CHECK_MS = 1_000;
/** A parsed command-output chunk waiting in a receive queue (D3b). */
type QueuedOutput = { metadata: StreamBinaryMetadata; body: Uint8Array };
type ReceiveWork = { run: () => Promise<void>; bytes: number; output?: QueuedOutput };
type OutputWork = ReceiveWork & { output: QueuedOutput };
/**
 * D3b: consecutive queued output chunks of one operation attempt are admitted
 * together, in one fenced transaction after one authority revalidation,
 * bounded by chunk count and body bytes.
 */
export const OUTPUT_BATCH_MAX_CHUNKS = 16;
export const OUTPUT_BATCH_MAX_BYTES = 1024 * 1024;
type ReceiveQueue = {
  work: ReceiveWork[];
  frames: number;
  bytes: number;
  draining: boolean;
  /** Socket reads are paused until the queue drains to the low-water mark. */
  paused: boolean;
};
const WS_READY_STATE_OPEN = 1;
const SANDBOX_RELAY_UNREGISTERED_STALE_AFTER_MS = 10_000;
/** Concurrent upload streams; each holds at most one pending file ACK, so this
 * also keeps `fileAcks` under its bound without failing mid-stream. */
const FILE_STREAM_MAX_ACTIVE = 16;
/** A transient store read-admission refusal (CONFLICT / TRANSFER_QUOTA) gets a
 * few short retries before the sender gives up (C29). */
const FILE_READ_ADMISSION_RETRIES = 5;
const FILE_READ_ADMISSION_RETRY_MS = 100;
const HOST_IMAGE_VERIFY_TIMEOUT_MS = 30_000;
/** Sessions revalidated at once after a global/owner authority change. */
const AUTHORITY_REVALIDATION_CONCURRENCY = 8;
/**
 * Host terminal frames held while the socket's cached authority ticket is
 * revalidated (C52-CO-1). A host that honours its credit windows has, per
 * counted session, at most the output window of data, the input window of
 * acks, the pending resize readies, the open ready and the exit in flight;
 * the bound is twice that over the per-host cap, so overflow means the host
 * ignored its windows (protocol error). Bytes are raw frame sizes.
 */
export const TERMINAL_HOLD_MAX_FRAMES =
  2 *
  TERMINAL_LIMITS.maxSessionsPerHost *
  (TERMINAL_LIMITS.outputWindowFrames +
    TERMINAL_LIMITS.inputWindowFrames +
    TERMINAL_MAX_PENDING_RESIZES +
    2);
export const TERMINAL_HOLD_MAX_BYTES = 4 * 1024 * 1024;

type HeldTerminalFrame =
  | { kind: "control"; message: HostTerminalControl; bytes: number }
  | { kind: "data"; metadata: TerminalDataMetadata; body: Uint8Array; bytes: number };

/**
 * Host channel frames held while the socket's cached authority ticket is
 * revalidated (wssp-ssh 1b, like the terminal hold). A node that honours its
 * windows has, per counted channel, at most a window of output, a window of
 * stdin acks, its eofs, ready, error notices and exit in flight; the bound is
 * twice that over the per-host cap, so overflow means the node ignored its
 * windows (protocol error). Bytes: twice the node's bulk cap (128 frames of
 * 32 KiB) plus every pty window (32 channels of 8 frames of 16 KiB).
 */
export const CHANNEL_HOLD_MAX_FRAMES =
  2 * CHANNEL_LIMITS.maxChannelsPerHost * (2 * CHANNEL_LIMITS.bulkWindowFrames + 6);
export const CHANNEL_HOLD_MAX_BYTES =
  2 *
  (128 * CHANNEL_LIMITS.bulkDataMaxBytes +
    CHANNEL_LIMITS.maxPtyChannelsPerHost *
      CHANNEL_LIMITS.ptyWindowFrames *
      CHANNEL_LIMITS.ptyDataMaxBytes);

type HeldChannelFrame =
  | { kind: "control"; message: HostChannelControl; bytes: number }
  | { kind: "data"; metadata: ChannelDataMetadata; body: Uint8Array; bytes: number };

type PendingImageVerify = {
  socket: SandboxRelaySocket;
  epoch: number;
  expectedArchitecture: string;
  resolve: (value: {
    incusFingerprint: string;
    architecture: string;
    sizeBytes?: number;
    format?: "unified" | "split";
  }) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

export type SandboxRelaySocket = {
  readonly readyState: number;
  readonly bufferedAmount?: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  /** Stop / restart reading from the transport (receive backpressure). */
  pause?(): void;
  resume?(): void;
  /** Transport-level ping; the peer's pong is reported via `notePeerAlive`. */
  ping?(): void;
};

/** Reconnect adoption frames a session may send before reconciliation. */
export const SANDBOX_RELAY_MAX_ADOPT_FRAMES = 512;

/** D11: how often an open session re-checks its `pendingReceipts` holds. */
const PENDING_RECEIPT_SWEEP_MS = 60_000;

type SessionState = {
  socket: SandboxRelaySocket;
  identity: SandboxHostWebsocketIdentity;
  connectedAt: Date;
  lastHeartbeatAt: Date;
  registered: boolean;
  /** Hello image capability; null for daemons without the image cache. */
  imageFeatures?: import("@wssp/sandbox-contracts").ImageCapabilitiesV11 | null;
  /** Hello `templateStartup` (B9): the daemon runs start/ready commands. */
  templateStartup?: boolean;
  /** Hello `guestSudo`: the daemon accepts `guestSudo`/`guestRoot`. */
  guestSudo?: boolean;
  /** Hello `diskOffload`: the daemon speaks the `disk.*`
   * frames and accepts the reconnect disk fields. */
  diskOffload?: boolean;
  /** Hello `tunnel`: the daemon runs a verified preview-tunnel client. */
  tunnelCapable?: boolean;
  /** Hello `tunnelPorts`: the daemon accepts a launch's `tunnelPorts`. */
  tunnelPorts?: boolean;
  /** When reconciliation completed (ms): tunnel applies wait briefly after it. */
  reconciledAt?: number;
  /** `disk.offload.inventory` pages this session sent (bounded). */
  diskInventoryPages?: number;
  /** Census keys seen on this connection until the complete page. */
  imageCensus?: import("./image-handlers.js").ImageCensusRun;
  /** Hello `egressRefusedHints` (B12); false/absent refuses `egress.refused`. */
  egressRefusedHints?: boolean;
  egressHintThrottle?: EgressHintThrottle;
  /** Hello credential capability; null for daemons without CLI logins. */
  credentialFeatures?: import("@wssp/sandbox-contracts").CredentialCapabilitiesV11 | null;
  /** Credential census pages and capture assemblies of this connection. */
  credentialRelay?: import("./credential-handlers.js").CredentialSessionRelay;
  admissionState: import("./inventory-reconcile.js").HostAdmissionState;
  reconciled: boolean;
  census?: InventoryCensus;
  availabilityCensus?: AvailabilityCensus;
  allocationAttestation?: AllocationAttestation;
  allocationSequence?: number;
  /** `operation.adopt` frames received before reconciliation (at most 512). */
  adoptFrames?: number;
  /** Reconnect dispatch audit: the next expected page, its keyset cursor and
   * the entries offered on the outstanding page (verdicts must match). */
  audit?: {
    nextPage: number;
    cursor?: string;
    offered?: {
      page: number;
      entries: Map<string, import("./operation-handlers.js").DispatchAuditEntry>;
    };
    done: boolean;
  };
  connectionEpoch: number;
  /** Last accepted `host.lease-policy` sequence on this link. */
  leaseSequence: number;
  /** Last accepted `host.egress-state` sequence on this link. */
  egressSequence: number;
  /** Hello `quiesce` capability (WP7); false/absent refuses `host.quiesce`. */
  quiesceCapable?: boolean;
  /**
   * WP7 (D9): the daemon is quiescing for a restart. Set at registration from
   * `hello.quiescing` (atomically with publication) or by `host.quiesce`; a
   * new connection's hello without it clears it. While set, new
   * `command.run` work is held in the outbox before its claim and new
   * terminal opens are refused.
   */
  quiescing?: boolean;
  /** Last accepted `host.quiesce` sequence on this link. */
  quiesceSequence?: number;
  protocolVersion: ReturnType<typeof negotiatedCapabilities>["protocolVersion"];
  /** The hello advertised a PTY-capable runtime (C52). */
  terminalCapable: boolean;
  /** WP8 hello `terminalResume.graceMs`; absent: the node never detaches a PTY. */
  terminalResumeGraceMs?: number;
  /** Output chunk ceiling sent in `hello.ok`; set when hello is accepted. */
  outputChunkBytes?: number;
  /** Orders expiry observations against lifecycle results after hello. */
  observationFence?: ObservationFence;
  /** Last accepted `sandbox.expiry_status` batch (strictly increasing). */
  expiryStatusBatch?: number;
  /** D11: re-runs settlement of `pendingReceipts` holds while the session
   * stays open, so a hold expires without a reconnect. */
  pendingReceiptSweep?: ReturnType<typeof setInterval>;
  /** Ordered host terminal frames awaiting a fresh authority ticket (bounded). */
  terminalHold: { frames: HeldTerminalFrame[]; bytes: number; refreshing: boolean };
  /** Hello `channels` (wssp-ssh): the negotiated kinds; absent: no channel frames. */
  channelKinds?: readonly string[];
  /** Ordered host channel frames awaiting a fresh authority ticket (bounded). */
  channelHold: { frames: HeldChannelFrame[]; bytes: number };
  unauthenticatedTimer: ReturnType<typeof setTimeout>;
  expiryTimer?: ReturnType<typeof setTimeout>;
  /** Half-open detection (WP4): last frame or pong, the ping cadence and the
   * lazily re-armed silence deadline. */
  liveness: {
    lastSeenMs: number;
    pingTimer?: ReturnType<typeof setInterval>;
    deadlineTimer?: ReturnType<typeof setTimeout>;
    deadlineAtMs: number;
  };
  authorized: () => boolean;
};

export type DispatchOperationInput = {
  allocation?: import("zod").z.infer<typeof pinnedAllocationV11Schema>;
  /** Internal staged contract fence; never serialized into an old dispatch. */
  requiresFsProcess?: boolean;
  resultVersion?: 1;
  processId?: string;
  process?: import("@wssp/sandbox-contracts").ProcessRef;
  targetOperationId?: string;
  limit?: number;
  continuation?: import("zod").infer<
    typeof import("@wssp/sandbox-contracts").resultContinuationSchema
  >;
  /** Internal evidence: called before frame IO or when an earlier send may exist. */
  onPossibleDispatchFrame?: () => void;
  authorizingPrincipal: AuthorizingPrincipal;
  connectionEpoch: number;
  operationId: string;
  sandboxId: string;
  idempotencyKey: string;
  kind: string;
  generation: number;
  attempt: number;
  bodyHash?: string;
  digestScheme?: string;
  digestKeyId?: string | null;
  lease?: HostLease;
  privateConfig?: import("@wssp/api/sandbox/execution-config").PrivateConfigReference;
  /** Inactive negotiated launch fields; no public producer until B5. */
  cpuCount?: number;
  memoryMiB?: number;
  templateDigest?: string;
  templateRevisionId?: string;
  verificationConnectionEpoch?: number;
  incusFingerprint?: string;
  architecture?: string;
  guestUid?: number;
  guestGid?: number;
  guestHome?: string;
  guestShell?: string;
  incusName?: string;
  argv?: string[];
  script?: string;
  cwd?: string;
  timeoutMs?: number;
  stdinSequence?: number;
  path?: string;
  destPath?: string;
  recursive?: boolean;
  maxDepth?: number;
  env?: Array<[string, string]>;
  /** Recorded immutable egress policy (M5, C34), carried on VM launches. */
  egressPolicy?: import("@wssp/sandbox-contracts").EgressPolicyWire;
  egressPolicyHash?: string;
  /** Planned image fetch (creates on `image.fetch` hosts only). */
  image?: import("@wssp/sandbox-contracts").DispatchImageV11;
  /** `sandbox.capture` body. */
  capture?: import("@wssp/sandbox-contracts").DispatchCaptureV11;
  /** Template build binding (`sandbox.create` of a build VM only). */
  build?: import("@wssp/sandbox-contracts").DispatchBuildV11;
  /** Build step fields (`command.run` on a build VM only; D1). */
  runAs?: import("@wssp/sandbox-contracts").RunAsV11;
  buildCopy?: import("@wssp/sandbox-contracts").BuildCopyV11;
  /** Template start/ready commands (launches on `templateStartup` daemons; B9). */
  startup?: import("@wssp/sandbox-contracts").DispatchStartupV11;
  /** Guest privilege from the sandbox row (launches on `guestSudo` daemons). */
  guestSudo?: true;
  guestRoot?: true;
  /** Preview tunnels: a tunnel sandbox's declared ports and their revision
   * (launches only). */
  tunnelPorts?: number[];
  tunnelPortsRevision?: number;
  /** §8.6 disk fields (launches on `diskOffload` daemons). */
  restore?: import("@wssp/sandbox-contracts").DispatchRestoreV11;
  launchMode?: import("@wssp/sandbox-contracts").LaunchMode;
  expectDisk?: import("@wssp/sandbox-contracts").DispatchExpectDiskV11;
  diskBaseFingerprint?: string;
  /** CLI logins: reference to the stored spec, never inline. */
  credentialSpec?: import("@wssp/sandbox-contracts").CredentialSpecRefV11;
  signal?: "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGKILL";
  stdinBytes?: Uint8Array;
  fileUpload?: {
    size: number;
    sha256: string;
    read: (offset: number, length: number) => Promise<Uint8Array>;
  };
  /** Capacity reserved by the caller before any durable dispatch claim. */
  fileStreamSlot?: FileStreamSlot;
  stdinEof?: boolean;
};

/** A pre-claim file.put capacity reservation; release() is idempotent. */
export type FileStreamSlot = { release(): void };

/**
 * D3b: `first` plus the output chunks queued directly behind it for the same
 * operation, generation and attempt, up to the batch bounds. The run stops at
 * the first frame that differs (another operation, another attempt, or any
 * control frame), so frames are never reordered: a batch commits exactly the
 * chunks the per-chunk path would have committed before its next frame, and
 * nothing received after another operation's fatal frame is ever admitted.
 */
function takeOutputBatch(first: OutputWork, work: ReceiveWork[]): OutputWork[] {
  const batch = [first];
  const key = attemptKey(first.output.metadata);
  let bytes = first.output.body.length;
  while (batch.length < OUTPUT_BATCH_MAX_CHUNKS) {
    const next = work[0];
    if (!isOutputWork(next) || bytes + next.output.body.length > OUTPUT_BATCH_MAX_BYTES) break;
    if (attemptKey(next.output.metadata) !== key) break;
    work.shift();
    batch.push(next);
    bytes += next.output.body.length;
  }
  return batch;
}

/** The `channel.*` control frames a node sends (all routed to the connect manager). */
function isHostChannelControl(message: DaemonControlMessage): message is HostChannelControl {
  return (
    message.type === "channel.ready" ||
    message.type === "channel.ack" ||
    message.type === "channel.eof" ||
    message.type === "channel.error" ||
    message.type === "channel.exit"
  );
}

function isOutputWork(work: ReceiveWork | undefined): work is OutputWork {
  return work?.output !== undefined;
}

function attemptKey(metadata: StreamBinaryMetadata): string {
  return JSON.stringify([metadata.operationId, metadata.generation, metadata.attempt]);
}

async function sendBinaryChunks(
  socket: SandboxRelaySocket,
  authorize: () => Promise<boolean>,
  current: () => boolean,
  streamId: string,
  operationId: string,
  generation: number,
  attempt: number,
  bytes: Uint8Array,
  flags: { fileUpload?: boolean; stdin?: boolean },
  eof = true,
  sequence = 0,
) {
  if (bytes.byteLength === 0 && !eof) return 0;
  const chunks = Array.from(
    { length: Math.max(1, Math.ceil(bytes.length / SANDBOX_BINARY_CHUNK_MAX_BYTES)) },
    (_, i) =>
      bytes.subarray(i * SANDBOX_BINARY_CHUNK_MAX_BYTES, (i + 1) * SANDBOX_BINARY_CHUNK_MAX_BYTES),
  );
  for (const [index, chunk] of chunks.entries()) {
    if (!(await authorize()) || !current()) return index;
    const last = eof && index === chunks.length - 1;
    socket.send(
      encodeBinaryFrame(
        {
          type: last ? "stream.end" : "stream.chunk",
          streamId,
          operationId,
          generation,
          attempt,
          sequence: sequence + index,
          flags,
          final: last,
        },
        chunk,
      ),
    );
  }
  return chunks.length;
}

/** Typed admission refusal (`rate_limited`) before any session state exists.
 * The daemon logs the message and reconnects with backoff. 1013: try again later. */
function refuseHostSocket(socket: SandboxRelaySocket, message: string) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN) {
      socket.send(
        encodeServerControlMessage(
          { type: "protocol.error", failure: "rate_limited", message },
          SANDBOX_RELAY_PROTOCOL_VERSION,
        ),
      );
    }
  } catch {
    // A failed refusal reply must not keep the socket open.
  }
  try {
    socket.close(1013, "host_socket_limit");
  } catch {
    /* Transport already failed. */
  }
}

function closeWithProtocolError(
  socket: SandboxRelaySocket,
  message: string,
  protocolVersion: string,
) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN) {
      socket.send(
        encodeServerControlMessage(
          { type: "protocol.error", failure: "protocol_error", message },
          protocolVersion,
        ),
      );
    }
  } catch {
    // A failed error reply must not prevent closing/revoking the socket.
  }
  try {
    socket.close(1002, "protocol_error");
  } catch {
    /* Transport already failed. */
  }
}

/** `SANDBOX_MAX_SOCKETS_PER_HOST` default (packages/env/src/vars/server.ts). */
export const DEFAULT_MAX_SOCKETS_PER_HOST = 2;

/** Every valid relay session carries the current typed command/file/process fields. */
/** Wire `pid` of a dispatch: only `process.signal` carries one, and only as
 * a copy of its qualified target's pid. Nothing else may supply it. */
export function signalDispatchPid(input: Pick<DispatchOperationInput, "kind" | "process">) {
  return input.kind === "process.signal" ? input.process?.pid : undefined;
}

export function fsProcessDispatchFields(
  version: string | undefined,
  input: DispatchOperationInput,
) {
  if (version !== "1.0")
    throw new SandboxRelayDispatchValidationError("Unsupported relay version.");
  return input.kind === "command.run"
    ? { resultVersion: input.resultVersion, processId: input.processId }
    : {
        resultVersion: input.resultVersion,
        limit: input.limit,
        continuation: input.continuation,
        process: input.process,
        targetOperationId: input.targetOperationId,
      };
}

export class SandboxRelaySessionManager {
  /** C52-R2-3: concurrent node-daemon sockets per host on this process. */
  private readonly maxSocketsPerHost: number;
  /** Half-open detection bounds (WP4); shorter only in tests. */
  pingIntervalMs: number;
  livenessTimeoutMs: number;

  constructor(
    options: {
      maxSocketsPerHost?: number;
      pingIntervalMs?: number;
      livenessTimeoutMs?: number;
    } = {},
  ) {
    this.maxSocketsPerHost = options.maxSocketsPerHost ?? DEFAULT_MAX_SOCKETS_PER_HOST;
    this.pingIntervalMs = options.pingIntervalMs ?? SANDBOX_RELAY_PING_INTERVAL_MS;
    this.livenessTimeoutMs = options.livenessTimeoutMs ?? SANDBOX_RELAY_LIVENESS_TIMEOUT_MS;
  }

  private fileAcks = new Map<
    string,
    {
      socket: SandboxRelaySocket;
      sequence: number;
      offset: number;
      resolve: () => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  /** Upload streaming tasks, keyed `operationId:generation:attempt`. */
  private fileStreams = new Map<string, Promise<void>>();
  /** Pre-claim reservations taken by the outbox processor BEFORE it commits a
   * dispatch claim; each converts to a keyed `fileStreams` entry at dispatch. */
  private streamReservations = 0;
  private epochRevocations = new Set<Promise<void>>();
  private helloRegistrations = new Set<Promise<void>>();
  private closeWithProtocolError(socket: SandboxRelaySocket, message: string) {
    // Before hello, use the current safe protocol-error envelope. Registered
    // sessions carry the exact supported version.
    const version =
      this.sessionsBySocket.get(socket)?.protocolVersion ?? SANDBOX_RELAY_PROTOCOL_VERSION;
    closeWithProtocolError(socket, message, version);
  }

  private sessionsBySocket = new Map<SandboxRelaySocket, SessionState>();
  private socketByHostId = new Map<string, SandboxRelaySocket>();
  /** Every admitted socket (registered or awaiting hello) per host; mutated
   * only beside `sessionsBySocket` (accept and removeSession). */
  private socketsByHostId = new Map<string, Set<SandboxRelaySocket>>();
  private queues = new WeakMap<SandboxRelaySocket, ReceiveQueue>();
  private frameTail = new WeakMap<SandboxRelaySocket, Promise<void>>();
  private pendingProbes = new Map<
    string,
    {
      socket: SandboxRelaySocket;
      epoch: number;
      resolve: (state: LiveProbeState) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private pendingImageVerifies = new Map<string, PendingImageVerify>();
  private imageVerifySeq = 0;
  private unsubscribe = onAuthorityCommitted((scope) => {
    void this.revalidateAuthorityScope(scope);
  });

  readonly hostAccess = new HostAccessRelay(
    async (hostId, ownerId) => {
      const socket = this.socketByHostId.get(hostId);
      const session = socket && this.sessionsBySocket.get(socket);
      if (
        !socket ||
        socket.readyState !== WS_READY_STATE_OPEN ||
        !session?.registered ||
        !session.reconciled ||
        session.identity.userId !== ownerId ||
        !this.isCurrentRegistered(session, socket)
      )
        return null;
      if (!(await this.authorizeSession(session)) || !session.authorized()) return null;
      return this.hostAccessLink(session);
    },
    (hostId, ownerId) => this.hostTerminalPolicies.lower(hostId, ownerId),
    (hostId, ownerId) => this.hostTerminalPolicies.lift(hostId, ownerId),
    (hostId, ownerId) => this.hostTerminalPolicies.offWitness(hostId, ownerId),
  );

  /** A node report can never clear the durable emergency stop. */
  private async resendHostPolicyVeto(
    session: SessionState,
    target: "hostCommands" | "hostTerminal",
    on: boolean,
  ): Promise<void> {
    if (!on) return;
    const host = await prisma.sandboxHost.findFirst({
      where: {
        id: session.identity.hostId,
        userId: session.identity.userId,
        connectionEpoch: session.connectionEpoch,
      },
      select: { agentHostCommandsVetoedAt: true, hostTerminalVetoedAt: true },
    });
    if (!session.authorized() || !this.isCurrentRegistered(session, session.socket)) return;
    const vetoed =
      target === "hostCommands" ? host?.agentHostCommandsVetoedAt : host?.hostTerminalVetoedAt;
    if (vetoed)
      await this.hostAccess.lower(session.identity.hostId, session.identity.userId, target);
  }

  private hostAccessLink(session: SessionState): HostAccessLink {
    return {
      hostId: session.identity.hostId,
      ownerId: session.identity.userId,
      epoch: session.connectionEpoch,
      socket: session.socket,
      protocolVersion: session.protocolVersion,
      authorized: () => session.authorized() && this.isCurrentRegistered(session, session.socket),
      connected: () =>
        session.socket.readyState === WS_READY_STATE_OPEN &&
        session.reconciled &&
        this.isCurrentRegistered(session, session.socket),
    };
  }

  readonly hostTerminalPolicies = new HostTerminalPolicies((hostId, reason) =>
    this.terminals.closeHostTarget(hostId, reason),
  );

  /**
   * In-memory only: this process holds the host's current registered
   * connection for exactly this owner and epoch. False when the connection
   * ended or moved on (a reconnect, another process's boot sweep): a host
   * disconnect, not a revocation (WP8).
   */
  terminalTransportConnected(hostId: string, ownerId: string, epoch: number): boolean {
    const socket = this.socketByHostId.get(hostId);
    const session = socket && this.sessionsBySocket.get(socket);
    return (
      !!session &&
      session.identity.userId === ownerId &&
      session.connectionEpoch === epoch &&
      this.isCurrentRegistered(session, session.socket)
    );
  }

  /** DB-only fresh transport authorization. Safe under terminal mint's H; no socket IO. */
  async authorizeTerminalTransport(
    hostId: string,
    ownerId: string,
    epoch: number,
    client: Prisma.TransactionClient,
  ): Promise<boolean> {
    const socket = this.socketByHostId.get(hostId);
    const session = socket && this.sessionsBySocket.get(socket);
    if (!session || !this.terminalTransportConnected(hostId, ownerId, epoch)) return false;
    const host = await client.sandboxHost.findFirst({
      where: {
        id: hostId,
        userId: ownerId,
        connectionEpoch: epoch,
        hostTerminalVetoedAt: null,
        deletionRequestedAt: null,
      },
      select: { id: true },
    });
    if (!host) return false;
    const checked = await revalidateSandboxHostIdentity(session.identity, new Date(), client);
    return (
      checked.status === "active" &&
      session.authorized() &&
      this.isCurrentRegistered(session, session.socket)
    );
  }

  /** C52 terminal channel; C53 opens sessions through it. */
  readonly terminals = new SandboxTerminalManager({
    terminalHost: (hostId, kind = "sandbox", purpose = "open") => {
      const socket = this.socketByHostId.get(hostId);
      const session = socket && this.sessionsBySocket.get(socket);
      if (
        !socket ||
        !session ||
        socket.readyState !== WS_READY_STATE_OPEN ||
        !session.registered ||
        (kind === "sandbox" && !session.reconciled) ||
        // WP7: a quiescing daemon is about to restart; refuse new opens like
        // an absent host (the daemon refuses them locally too). A resume
        // (WP8) reattaches a PTY the daemon still holds, and it serves it
        // while quiescing: refusing it would let a long drain exhaust the
        // terminal's grace and lose the PTY.
        (session.quiescing === true && purpose !== "resume")
      )
        return { error: { code: "disconnected", message: "host is not connected" } };
      if (
        kind === "sandbox"
          ? !session.terminalCapable
          : !this.hostTerminalPolicies.read(hostId, session.identity.userId)?.hostTerminal
      )
        return {
          error: { code: "unsupported_capability", message: "Unsupported capability: terminal" },
        };
      return {
        link: {
          socket,
          hostPolicy: this.hostTerminalPolicies.read(hostId, session.identity.userId),
          hostId: session.identity.hostId,
          ownerId: session.identity.userId,
          epoch: session.connectionEpoch,
          protocolVersion: session.protocolVersion,
          ...(session.terminalResumeGraceMs === undefined
            ? {}
            : { resumeGraceMs: session.terminalResumeGraceMs }),
          authorized: () => session.authorized() && this.isCurrentRegistered(session, socket),
        },
      };
    },
    closeHostSocket: (socket, message) => {
      const relay = socket as SandboxRelaySocket;
      if (!this.sessionsBySocket.has(relay)) return;
      this.closeWithProtocolError(relay, message);
      this.removeSession(relay);
    },
  });

  /** The process's one connect audit writer (drained by server shutdown). */
  readonly connectAudit = new ConnectAuditRecorder();

  /**
   * CLI channels (wssp-ssh 1b): `/v1/sandboxes/{id}/connect` connections ride
   * a registered, reconciled, non-quiescing host that negotiated `channels`.
   */
  readonly connects = new ConnectManager(
    {
      connectHost: (hostId) => {
        const socket = this.socketByHostId.get(hostId);
        const session = socket && this.sessionsBySocket.get(socket);
        if (
          !socket ||
          !session ||
          socket.readyState !== WS_READY_STATE_OPEN ||
          !session.registered ||
          !session.reconciled ||
          session.quiescing === true
        )
          return { error: { code: "disconnected", message: "host is not connected" } };
        if (!session.channelKinds)
          return {
            error: { code: "unsupported_capability", message: "Unsupported capability: channels" },
          };
        return {
          link: {
            socket,
            hostId: session.identity.hostId,
            ownerId: session.identity.userId,
            epoch: session.connectionEpoch,
            protocolVersion: session.protocolVersion,
            authorized: () => session.authorized() && this.isCurrentRegistered(session, socket),
            kinds: session.channelKinds,
          },
        };
      },
      closeHostSocket: (socket, message) => {
        const relay = socket as SandboxRelaySocket;
        if (!this.sessionsBySocket.has(relay)) return;
        this.closeWithProtocolError(relay, message);
        this.removeSession(relay);
      },
    },
    {
      maxBytesPerSecond: env.SANDBOX_CONNECT_MAX_BYTES_PER_SECOND,
      audit: this.connectAudit,
    },
  );

  private async revalidateAuthorityScope(scope: CommittedAuthorityScope) {
    const sessions = [...this.sessionsBySocket.values()].filter(
      (session) =>
        scope.kind !== "scoped" ||
        ((scope.ownerId === undefined || session.identity.userId === scope.ownerId) &&
          (scope.hostId === undefined || session.identity.hostId === scope.hostId) &&
          (scope.credentialId === undefined || session.identity.tokenId === scope.credentialId)),
    );
    // The same fresh revalidation as the queued path. Only definitive
    // inactivity closes 4003; infrastructure failure closes 1011. `stale`
    // means a newer change overlapped: its own committed delivery
    // revalidates. `active` also refreshes the cached ticket, so terminal
    // traffic held on the stale ticket resumes (C52-CO-1).
    // Each session is independent: a global/owner change revalidates them in
    // bounded batches instead of one DB round trip at a time.
    let failure: { reason: unknown } | undefined;
    for (let start = 0; start < sessions.length; start += AUTHORITY_REVALIDATION_CONCURRENCY) {
      const settled = await Promise.allSettled(
        sessions
          .slice(start, start + AUTHORITY_REVALIDATION_CONCURRENCY)
          .map((session) => this.authorizeSession(session)),
      );
      for (const result of settled)
        if (result.status === "rejected" && !failure) failure = { reason: result.reason };
    }
    // An unexpected throw still surfaces, after every other session was revalidated.
    if (failure) throw failure.reason;
  }

  /** 4003 always means "authority revoked" (relay-drop: revoke, not detach).
   * The reason names an explicit verdict (`credential_revoked`,
   * `owner_unavailable`) only when this enrolled credential was revoked or its
   * owner is banned/deleting; the daemon stops its VMs only on those. */
  private closeAuthority(
    session: SessionState,
    reason:
      | "credential_revoked"
      | "owner_unavailable"
      | "credential_inactive" = "credential_inactive",
  ) {
    if (this.sessionsBySocket.get(session.socket) !== session) return;
    try {
      session.socket.close(4003, reason);
    } catch {
      /* Already closed. */
    }
    // The HOST lost its authority, not the browser's owner (C52-R2-1).
    this.removeSession(
      session.socket,
      new Date(),
      "host_disconnected",
      HOST_CREDENTIAL_INACTIVE_ERROR,
    );
  }

  private closeAuthorityError(session: SessionState) {
    if (this.sessionsBySocket.get(session.socket) !== session) return;
    try {
      session.socket.close(1011, "internal_error");
    } catch {
      /* Already closed. */
    }
    this.removeSession(session.socket);
  }

  private async authorizeSession(session: SessionState): Promise<boolean> {
    const current = authorityTicket({
      ownerId: session.identity.userId,
      hostId: session.identity.hostId,
      credentialId: session.identity.tokenId,
    });
    const result = await revalidateSandboxHostIdentity(session.identity);
    if (result.status === "error") {
      this.closeAuthorityError(session);
      return false;
    }
    if (result.status === "inactive") {
      this.closeAuthority(session, result.reason);
      return false;
    }
    // Cleanup keeps its relay credential during a host tombstone, but its host
    // shell loses authority. Close it BEFORE refreshing/resuming terminal traffic.
    // The tombstone comes from the same credential read that proved the host
    // row exists under this owner.
    if (result.hostDeletionRequested) this.terminals.closeHostTarget(session.identity.hostId);
    // A stale ticket is not evidence of inactivity (C21-7): fail only this action.
    // The overlapping change's committed delivery revalidates the socket itself.
    if (
      result.status === "stale" ||
      !current() ||
      this.sessionsBySocket.get(session.socket) !== session
    )
      return false;
    session.authorized = () =>
      current() &&
      this.sessionsBySocket.get(session.socket) === session &&
      (!session.identity.expiresAt || session.identity.expiresAt.getTime() > Date.now());
    // The only place a ticket is refreshed: resume terminal traffic held or
    // deferred (both directions) on the previous, stale ticket.
    this.resumeTerminals(session);
    return session.authorized();
  }

  private async authorizeOperation(
    session: SessionState,
    operationId: string,
    principal: AuthorizingPrincipal,
    control: "dispatch" | "stdin" | "cancel" = "dispatch",
  ): Promise<(() => boolean) | null> {
    if (!controlAllowed(principal) && control !== "dispatch") return null;
    if (!(await this.authorizeSession(session))) return null;
    const hostCurrent = session.authorized;
    let keyCurrent = () => false;
    let pathCurrent = () => true;
    let expiresAt: Date | null = null;
    const principalKeyId = recordedKeyIdOf(principal);
    const active = await relayTransaction(async (tx) => {
      if (principalKeyId !== null)
        await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${principalKeyId} FOR SHARE`;
      await lockHostByEpoch(
        tx,
        session.identity.hostId,
        session.connectionEpoch,
        session.identity.userId,
      );
      const binding = await requireRelayWorkload(tx, session.identity, { operationId });
      keyCurrent = authorityTicket({
        ownerId: binding.sandboxOwnerId,
        hostId: session.identity.hostId,
        ...(principalKeyId !== null ? { credentialId: principalKeyId } : {}),
      });
      const located = { sandboxId: binding.sandboxId };
      if (!located) return false;
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${located.sandboxId} FOR SHARE`;
      const operation = await tx.sandboxOperation.findFirst({
        where: {
          id: operationId,
          userId: binding.sandboxOwnerId,
          Sandbox: { userId: binding.sandboxOwnerId, sandboxHostId: session.identity.hostId },
        },
        select: {
          kind: true,
          authorizingKeyId: true,
          Sandbox: {
            select: { id: true, originHostId: true, templateRevisionId: true, originPoolId: true },
          },
        },
      });
      if (!operation || (control === "dispatch" && operation.authorizingKeyId !== principalKeyId))
        return false;
      return (
        (await checkAcceptedDispatchAuthority(
          {
            ownerId: binding.sandboxOwnerId,
            principal,
            cleanup:
              control === "cancel" ||
              KEY_FREE_CLEANUP_KINDS.has(operation.kind) ||
              ["STOP_SANDBOX", "KILL_SANDBOX"].includes(operation.kind),
            operationKind: operation.kind,
            context: {
              sandboxId: operation.Sandbox.id,
              sandboxHostId: operation.Sandbox.originHostId,
              templateRevisionId: operation.Sandbox.templateRevisionId,
              originPoolId: operation.Sandbox.originPoolId,
            },
            onActiveAuthority: (current) => {
              pathCurrent = current;
            },
            onActive: (deadline) => {
              expiresAt = deadline;
            },
          },
          tx,
        )) === "active"
      );
    }, false).catch(() => false);
    if (!active) return null;
    return () =>
      hostCurrent() &&
      keyCurrent() &&
      pathCurrent() &&
      (!expiresAt || expiresAt.getTime() > Date.now());
  }

  private armExpiry(session: SessionState) {
    const deadline = session.identity.expiresAt;
    if (!deadline) return;
    const remaining = deadline.getTime() - Date.now();
    if (remaining <= 0) {
      this.closeAuthority(session);
      return;
    }
    session.expiryTimer = setTimeout(
      () => this.armExpiry(session),
      Math.min(remaining, 2_147_483_647),
    );
    session.expiryTimer.unref?.();
  }

  acceptAuthenticatedSocket({
    socket,
    identity,
    now = new Date(),
  }: {
    socket: SandboxRelaySocket;
    identity: SandboxHostWebsocketIdentity;
    now?: Date;
  }): boolean {
    // C52-R2-3: admission is a synchronous check-and-insert, so concurrent
    // upgrades for one host cannot both pass on this process. A refused
    // socket never gets a session or receive queue; frames on it are dropped.
    const hostSockets = this.socketsByHostId.get(identity.hostId) ?? new Set();
    if (hostSockets.size >= this.maxSocketsPerHost) {
      refuseHostSocket(
        socket,
        `Host connection limit reached: at most ${this.maxSocketsPerHost} concurrent daemon connections per host (SANDBOX_MAX_SOCKETS_PER_HOST). Stop any other daemon running with this host's credential; this daemon retries.`,
      );
      return false;
    }
    hostSockets.add(socket);
    this.socketsByHostId.set(identity.hostId, hostSockets);
    const unauthenticatedTimer = setTimeout(() => {
      const session = this.sessionsBySocket.get(socket);
      if (!session?.registered) {
        this.closeWithProtocolError(socket, "Host hello was not received in time.");
        this.removeSession(socket, now);
      }
    }, SANDBOX_RELAY_UNREGISTERED_STALE_AFTER_MS);

    this.queues.set(socket, { work: [], frames: 0, bytes: 0, draining: false, paused: false });
    const session: SessionState = {
      socket,
      identity,
      connectedAt: now,
      lastHeartbeatAt: now,
      registered: false,
      admissionState: {},
      reconciled: false,
      connectionEpoch: 0,
      leaseSequence: 0,
      egressSequence: 0,
      protocolVersion: SANDBOX_RELAY_PROTOCOL_VERSION,
      terminalCapable: false,
      terminalHold: { frames: [], bytes: 0, refreshing: false },
      channelHold: { frames: [], bytes: 0 },
      unauthenticatedTimer,
      liveness: { lastSeenMs: Date.now(), deadlineAtMs: 0 },
      authorized: () => false,
    };
    this.sessionsBySocket.set(socket, session);
    this.armExpiry(session);
    this.armLiveness(session);
    return true;
  }

  /** A frame or pong from the host: it is still there (WP4). */
  notePeerAlive(socket: SandboxRelaySocket) {
    const session = this.sessionsBySocket.get(socket);
    if (session) session.liveness.lastSeenMs = Date.now();
  }

  private armLiveness(session: SessionState) {
    const { socket } = session;
    const pingTimer = setInterval(() => {
      // No ping while reads are paused: its pong could not be read anyway.
      if (this.sessionsBySocket.get(socket) !== session || this.queues.get(socket)?.paused) return;
      try {
        socket.ping?.();
      } catch {
        /* A failed ping is silence; the deadline decides. */
      }
    }, this.pingIntervalMs);
    pingTimer.unref?.();
    session.liveness.pingTimer = pingTimer;
    this.armLivenessDeadline(session, this.livenessTimeoutMs);
  }

  /** One timer per session, re-armed only when it fires (no per-frame churn). */
  private armLivenessDeadline(session: SessionState, delayMs: number) {
    session.liveness.deadlineAtMs = Date.now() + delayMs;
    const timer = setTimeout(() => this.checkLiveness(session), delayMs);
    timer.unref?.();
    session.liveness.deadlineTimer = timer;
  }

  private checkLiveness(session: SessionState) {
    const { socket, liveness } = session;
    if (this.sessionsBySocket.get(socket) !== session) return;
    const now = Date.now();
    if (now - liveness.deadlineAtMs > LIVENESS_LATE_CHECK_MS) {
      // The event loop stalled past the deadline: timers run before pending
      // socket reads, so let those reads land first.
      this.armLivenessDeadline(session, LIVENESS_LATE_CHECK_MS);
      return;
    }
    if (this.queues.get(socket)?.paused) {
      // The clock is stopped while the reader is paused.
      liveness.lastSeenMs = now;
      this.armLivenessDeadline(session, this.livenessTimeoutMs);
      return;
    }
    const remaining = liveness.lastSeenMs + this.livenessTimeoutMs - now;
    if (remaining > 0) {
      this.armLivenessDeadline(session, remaining);
      return;
    }
    console.warn("[sandbox-relay] host socket silent; removing session:", {
      code: "host_liveness_timeout",
      registered: session.registered,
      silentMs: now - liveness.lastSeenMs,
      sessionAgeMs: now - session.connectedAt.getTime(),
    });
    this.removeSession(socket);
  }

  /**
   * WP7: persist the quiesce hold for template-build deadlines
   * (quiesce-hold.ts). Best effort, after the in-memory hold is in place: a
   * lost write only means a held build step is not given its time back.
   */
  private recordQuiesceHold(session: SessionState, quiescing: boolean): void {
    const host = {
      hostId: session.identity.hostId,
      ownerId: session.identity.userId,
      // Fenced in the database: a write from an older connection is a no-op
      // once a newer hello has committed.
      connectionEpoch: session.connectionEpoch,
    };
    // Serialized per host, in the order the transitions happened here.
    const previous = this.quiesceHoldWrites.get(host.hostId) ?? Promise.resolve();
    const next = previous
      .then(async () => {
        if (quiescing) await markHostQuiescing(host, new Date());
        else await settleHostQuiesce(host, new Date());
      })
      .then(
        () => undefined,
        (error: unknown) => {
          console.error("[sandbox-relay] quiesce hold record failed:", safeErrorLog(error));
        },
      );
    this.quiesceHoldWrites.set(host.hostId, next);
    void next.finally(() => {
      if (this.quiesceHoldWrites.get(host.hostId) === next)
        this.quiesceHoldWrites.delete(host.hostId);
    });
  }

  /** WP7: the tail of each host's serialized quiesce-hold writes. */
  private readonly quiesceHoldWrites = new Map<string, Promise<void>>();

  /** WP7: the host's current session is quiescing (see `SessionState.quiescing`). */
  isHostQuiescing(hostId: string): boolean {
    const socket = this.socketByHostId.get(hostId);
    return socket ? this.sessionsBySocket.get(socket)?.quiescing === true : false;
  }

  isHostConnected(hostId: string, connectionEpoch?: number): boolean {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    const session = this.sessionsBySocket.get(socket);
    return Boolean(
      session?.registered &&
        session.reconciled &&
        (connectionEpoch == null || session.connectionEpoch === connectionEpoch),
    );
  }

  async verifyHostImage(input: {
    ownerId: string;
    hostId: string;
    imageRef: string;
    expectedArchitecture: string;
  }): Promise<{
    incusFingerprint: string;
    architecture: string;
    sizeBytes?: number;
    format?: "unified" | "split";
  }> {
    const socket = this.socketByHostId.get(input.hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) {
      throw new Error("host is not connected");
    }
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      session.identity.userId !== input.ownerId ||
      session.identity.hostId !== input.hostId
    ) {
      throw new Error("host is not connected");
    }
    if (!(await this.authorizeSession(session)) || !session.authorized())
      throw new Error("host credential inactive");
    if (this.pendingImageVerifies.size >= 64) throw new Error("image verifier busy");
    const requestId = `img-${input.hostId}-${++this.imageVerifySeq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingImageVerifies.delete(requestId);
        reject(new Error("host image verification timed out"));
      }, HOST_IMAGE_VERIFY_TIMEOUT_MS);
      this.pendingImageVerifies.set(requestId, {
        resolve,
        reject,
        timer,
        socket,
        epoch: session.connectionEpoch,
        expectedArchitecture: input.expectedArchitecture,
      });
      try {
        socket.send(
          encodeServerControlMessage(
            {
              type: "image.verify.request",
              requestId,
              imageRef: input.imageRef,
              expectedArchitecture: input.expectedArchitecture,
            },
            session.protocolVersion,
          ),
        );
      } catch (error) {
        clearTimeout(timer);
        this.pendingImageVerifies.delete(requestId);
        reject(error instanceof Error ? error : new Error("host image verification send failed"));
      }
    });
  }

  async probeSandbox(input: HostSandboxProbeInput): Promise<LiveProbeState> {
    const socket = this.socketByHostId.get(input.hostId);
    const session = socket && this.sessionsBySocket.get(socket);
    if (
      !socket ||
      socket.readyState !== WS_READY_STATE_OPEN ||
      !session?.registered ||
      !session.reconciled ||
      session.identity.hostId !== input.hostId
    )
      return "unreachable";
    const workload = await relayTransaction(async (tx) => {
      await lockHostByEpoch(tx, input.hostId, session.connectionEpoch, session.identity.userId);
      return requireRelayWorkload(tx, session.identity, {
        sandboxId: input.sandboxId,
        sandboxOwnerId: input.ownerId,
      });
    }, null);
    if (!workload) return "unreachable";
    if (!(await this.authorizeSession(session)) || !session.authorized()) return "unreachable";
    if (this.pendingProbes.size >= 64) return "unreachable";
    const requestId = `probe-${++this.imageVerifySeq}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingProbes.delete(requestId);
        resolve("unreachable");
      }, HOST_IMAGE_VERIFY_TIMEOUT_MS);
      this.pendingProbes.set(requestId, { socket, epoch: session.connectionEpoch, resolve, timer });
      try {
        socket.send(
          encodeServerControlMessage(
            {
              ...(({ ownerId: _owner, ...rest }) => rest)(input),
              hostOwnerId: workload.hostOwnerId,
              sandboxOwnerId: workload.sandboxOwnerId,
              type: "sandbox.probe.request",
              requestId,
            },
            session.protocolVersion,
          ),
        );
      } catch {
        clearTimeout(timer);
        this.pendingProbes.delete(requestId);
        resolve("unreachable");
      }
    });
  }

  /**
   * Synchronous pre-claim capacity for one file.put stream. The outbox
   * processor reserves BEFORE committing a dispatch claim (DISPATCHED +
   * attempt + epoch): a saturated pool then leaves the outbox event pending
   * for a later scan instead of stranding a committed dispatch that no
   * same-epoch retry can reach.
   */
  reserveFileStreamSlot(): FileStreamSlot | null {
    if (this.fileStreams.size + this.streamReservations >= FILE_STREAM_MAX_ACTIVE) return null;
    this.streamReservations += 1;
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this.streamReservations -= 1;
      },
    };
  }

  /** Capture the credential of the exact socket before a claim. A durable
   * inactive verdict remains available even if revocation closes that socket.
   * Ticket movement/DB failure alone is indeterminate and keeps work pending. */
  captureHostDispatchCredential(
    hostId: string,
  ):
    | ((
        epoch: number,
        client?: Prisma.TransactionClient,
      ) => Promise<"active" | "inactive" | "indeterminate">)
    | undefined {
    const socket = this.socketByHostId.get(hostId);
    const session = socket ? this.sessionsBySocket.get(socket) : undefined;
    if (!session?.registered || !session.reconciled) return undefined;
    const epoch = session.connectionEpoch;
    const identity = session.identity;
    return async (expectedEpoch, client) => {
      if (expectedEpoch !== epoch) return "indeterminate";
      const result = await revalidateSandboxHostIdentity(identity, new Date(), client);
      return result.status === "active" || result.status === "inactive"
        ? result.status
        : "indeterminate";
    };
  }

  /** Config payload is sent only over the current authenticated 10.3+ socket.
   * No operation send/claim is implied; only a persisted exact ACK unlocks it. */
  async installExecutionConfig(
    hostId: string,
    operationId: string,
    principal: AuthorizingPrincipal,
    frame: Extract<
      import("./protocol.js").ServerControlMessage,
      { type: "private.config.install" }
    >,
  ): Promise<boolean | "invalid_config" | "not_sent"> {
    const socket = this.socketByHostId.get(hostId);
    const session = socket && this.sessionsBySocket.get(socket);
    if (
      !socket ||
      socket.readyState !== WS_READY_STATE_OPEN ||
      !session?.registered ||
      !session.reconciled ||
      session.connectionEpoch !== frame.connectionEpoch ||
      session.identity.hostId !== frame.hostId ||
      session.identity.userId !== frame.hostOwnerId
    )
      return "not_sent";
    const workload = await relayTransaction(async (tx) => {
      await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
      return requireRelayWorkload(tx, session.identity, {
        operationId,
        sandboxId: frame.sandboxId,
        sandboxOwnerId: frame.sandboxOwnerId,
      });
    }, null);
    if (!workload) return "not_sent";
    const current = await this.authorizeOperation(session, operationId, principal);
    if (!current?.()) return "not_sent";
    let frameMayHaveBeenSent = false;
    try {
      const evidence = await prisma.sandboxHost.findFirst({
        where: {
          id: hostId,
          userId: session.identity.userId,
          connectionEpoch: frame.connectionEpoch,
        },
        select: {
          connectionEpoch: true,
          journalKeyVersion: true,
          journalKeyId: true,
          journalKeyAcknowledgedEpoch: true,
        },
      });
      if (
        !evidence ||
        !hostJournalKeyAcknowledged(evidence) ||
        evidence.journalKeyId !== frame.config.bindingKeyId ||
        !current() ||
        this.socketByHostId.get(hostId) !== socket ||
        session.connectionEpoch !== frame.connectionEpoch
      )
        return "not_sent";
      let encoded: string;
      try {
        encoded = encodeServerControlMessage(frame, session.protocolVersion);
      } catch {
        // Encoding finished before socket IO: a constant typed pre-effect refusal.
        return "invalid_config";
      }
      frameMayHaveBeenSent = true;
      socket.send(encoded);
      return true;
    } catch {
      // No operation claim was made. Recovery retries this idempotent install;
      // encoding/transport diagnostics must never retain private frame values.
      return frameMayHaveBeenSent ? false : "not_sent";
    }
  }

  async dispatchOperation(
    hostId: string,
    input: DispatchOperationInput,
  ): Promise<"sent" | "refused_before_frame" | "sent_then_lost_authority"> {
    const dispatchKeyId = recordedKeyIdOf(input.authorizingPrincipal);
    if (
      dispatchClassOf(input.authorizingPrincipal, input.kind) === "system" &&
      !systemDispatchAllowed(input.kind, input as unknown as Record<string, unknown>, true)
    )
      return "refused_before_frame";
    if (classifyRelayDispatchKind(input.kind) !== "allowed") return "refused_before_frame";
    // Image plans and captures require the corresponding runtime feature.
    // Build fields likewise go only to daemons advertising `image.build` (the
    // daemon that journals build ids and accepts guest-root build steps).
    const buildFields =
      input.build !== undefined || input.runAs !== undefined || input.buildCopy !== undefined;
    if (input.image || input.capture || buildFields) {
      const socket = this.socketByHostId.get(hostId);
      const features = socket ? this.sessionsBySocket.get(socket)?.imageFeatures : null;
      if (
        (input.image && !features?.fetch) ||
        (input.capture && !features?.capture) ||
        (buildFields && features?.build !== true)
      )
        return "refused_before_frame";
    }
    // Template startup requires runtime support for start and ready commands.
    if (input.startup !== undefined) {
      const socket = this.socketByHostId.get(hostId);
      if (!socket || this.sessionsBySocket.get(socket)?.templateStartup !== true)
        return "refused_before_frame";
    }
    // Guest privilege fields require runtime support for guest sudo.
    if (input.guestSudo !== undefined || input.guestRoot !== undefined) {
      const socket = this.socketByHostId.get(hostId);
      if (!socket || this.sessionsBySocket.get(socket)?.guestSudo !== true)
        return "refused_before_frame";
    }
    // Declared tunnel ports require runtime support for the tunnel plan
    // (an older daemon's strict dispatch parser would drop the relay).
    if (input.tunnelPorts !== undefined) {
      const socket = this.socketByHostId.get(hostId);
      if (!socket || this.sessionsBySocket.get(socket)?.tunnelPorts !== true)
        return "refused_before_frame";
    }
    // Disk offload requires runtime support for stopped-disk transfer.
    if (dispatchHasDiskFields(input)) {
      const socket = this.socketByHostId.get(hostId);
      if (!socket || this.sessionsBySocket.get(socket)?.diskOffload !== true)
        return "refused_before_frame";
    }
    // A credential spec goes only to a session that negotiated spec transfer.
    if (input.credentialSpec) {
      const socket = this.socketByHostId.get(hostId);
      const features = socket ? this.sessionsBySocket.get(socket)?.credentialFeatures : null;
      if (!features?.specTransfer) return "refused_before_frame";
    }
    if (typeof input.bodyHash !== "string" || !/^[0-9a-f]{64}$/.test(input.bodyHash))
      throw new SandboxRelayDispatchValidationError(
        "bodyHash must be a canonical lowercase SHA-256 hash",
      );
    if (input.kind === "process.signal" && (!input.process || !input.targetOperationId))
      return "refused_before_frame";
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return "refused_before_frame";
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      session.connectionEpoch !== input.connectionEpoch
    )
      return "refused_before_frame";
    const workload = await relayTransaction(async (tx) => {
      await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
      return requireRelayWorkload(tx, session.identity, {
        operationId: input.operationId,
        sandboxId: input.sandboxId,
      });
    }, null);
    if (!workload) return "refused_before_frame";
    let current = () => false;
    const authorize = async () => {
      current =
        (await this.authorizeOperation(session, input.operationId, input.authorizingPrincipal)) ??
        (() => false);
      if (!current()) return false;
      if (
        (input.kind === "command.run" && input.timeoutMs === 0) ||
        input.requiresFsProcess ||
        input.resultVersion !== undefined ||
        input.processId !== undefined ||
        input.process !== undefined ||
        input.limit !== undefined ||
        input.continuation !== undefined ||
        input.targetOperationId !== undefined
      ) {
        if (
          input.kind === "command.run" &&
          input.timeoutMs === 0 &&
          !FS_PROCESS_LIMITS.commandTimeoutZero
        )
          return false;
        const supported = await relayTransaction(async (tx) => {
          if (dispatchKeyId !== null)
            await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${dispatchKeyId} FOR SHARE`;
          await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
          const host = await tx.sandboxHost.findFirst({
            where: { id: hostId, userId: session.identity.userId },
            select: {
              connectionEpoch: true,
              relayProtocolVersion: true,
              relayProtocolEpoch: true,
              admissionRuntime: true,
              admissionEpoch: true,
            },
          });
          return fsProcessHostSupported(host);
        }, false);
        if (!supported || !current()) return false;
      }
      if (input.kind === "sandbox.create" || input.kind === "sandbox.reconnect") {
        const matches = await relayTransaction(async (tx) => {
          // No owner lock in dispatch authority: preserve K → H → S order.
          if (dispatchKeyId !== null)
            await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${dispatchKeyId} FOR SHARE`;
          await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.sandboxId} AND "userId" = ${workload.sandboxOwnerId} FOR SHARE`;
          const sandbox = await tx.sandbox.findFirst({
            where: {
              id: input.sandboxId,
              userId: workload.sandboxOwnerId,
              sandboxHostId: hostId,
              generation: input.generation,
            },
            select: {
              cpuCount: true,
              memoryMiB: true,
              diskGiB: true,
              storagePoolName: true,
              storageMarker: true,
              currentPlacementId: true,
            },
          });
          // Missing or superseded S is stale dispatch, not allocation evidence.
          if (!sandbox) return null;
          const placement = sandbox.currentPlacementId
            ? await tx.sandboxPlacement.findFirst({
                where: {
                  id: sandbox.currentPlacementId,
                  sandboxId: input.sandboxId,
                  userId: workload.sandboxOwnerId,
                },
                select: {
                  cpuCount: true,
                  memoryMiB: true,
                  diskGiB: true,
                  storagePoolName: true,
                  storageMarker: true,
                  chargedMemoryMiB: true,
                  chargedVcpu: true,
                  rootChargeGiB: true,
                },
              })
            : null;
          return (
            vmSizeSchema.safeParse({
              cpuCount: input.cpuCount,
              memoryMiB: input.memoryMiB,
              diskGiB: input.allocation?.diskGiB,
            }).success &&
            pinnedAllocationV11Schema.safeParse(input.allocation).success &&
            placement != null &&
            sandbox.diskGiB === placement.diskGiB &&
            sandbox.storagePoolName === placement.storagePoolName &&
            sandbox.storageMarker === placement.storageMarker &&
            input.allocation != null &&
            Object.keys(pinnedAllocationV11Schema.shape).every(
              (key) => Reflect.get(input.allocation ?? {}, key) === Reflect.get(placement, key),
            ) &&
            sandbox.cpuCount === placement.cpuCount &&
            sandbox.memoryMiB === placement.memoryMiB &&
            input.cpuCount === placement.cpuCount &&
            input.memoryMiB === placement.memoryMiB
          );
        }, null);
        if (matches === null) return false;
        if (!matches) throw new SandboxRelayVmSizeMismatchError("VM allocation mismatch.");
        if (!current()) return false;
      }
      const envBearing = (input.env?.length ?? 0) > 0 || input.privateConfig != null;
      const keyed = input.digestScheme === "hmac-sha256-v1";
      if (!KEY_FREE_CLEANUP_KINDS.has(input.kind) && (envBearing || keyed)) {
        const ready = await relayTransaction(async (tx) => {
          await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
          const evidence = await tx.sandboxHost.findFirst({
            where: { id: hostId, userId: session.identity.userId },
            select: {
              connectionEpoch: true,
              journalKeyVersion: true,
              journalKeyId: true,
              journalKeyAcknowledgedEpoch: true,
            },
          });
          return (
            evidence != null &&
            hostJournalKeyAcknowledged(evidence) &&
            keyed &&
            input.digestKeyId === evidence.journalKeyId
          );
        }, false);
        if (!ready) return false;
      }
      return current();
    };
    if (!(await authorize()) || !current()) return "refused_before_frame";
    if (
      input.kind === "file.put" &&
      (!input.fileUpload ||
        !Number.isSafeInteger(input.fileUpload.size) ||
        input.fileUpload.size < 0 ||
        input.fileUpload.size > TRANSFER_MAX_BYTES ||
        !/^[a-f0-9]{64}$/.test(input.fileUpload.sha256))
    )
      throw new Error("Invalid file source manifest");
    let streamKey: string | undefined;
    if (input.kind === "file.put") {
      // Admit the stream BEFORE the dispatch send. The outbox processor already
      // reserved this capacity BEFORE committing the dispatch claim, so a
      // saturated pool strands no committed dispatch: refusal happens while the
      // outbox event is still pending and retryable. The keyed placeholder is
      // synchronous so two concurrent dispatches of one attempt cannot both
      // stream; the real task replaces it after the send.
      const key = `${input.operationId}:${input.generation}:${input.attempt}`;
      if (this.fileStreams.has(key)) {
        input.onPossibleDispatchFrame?.();
        input.fileStreamSlot?.release();
        return "sent_then_lost_authority";
      }
      if (
        !input.fileStreamSlot &&
        this.fileStreams.size + this.streamReservations >= FILE_STREAM_MAX_ACTIVE
      )
        return "refused_before_frame";
      this.fileStreams.set(key, Promise.resolve());
      // The keyed placeholder replaces the reservation in the accounting.
      input.fileStreamSlot?.release();
      streamKey = key;
    }
    let frameToSend: string | undefined;
    const sendFrame = (frame: string) => {
      frameToSend = frame;
    };
    try {
      if (input.kind === "command.run") {
        const dispatch = buildCommandRunOperationDispatchMessage(
          commandRunDispatchBuildInputFromOutboxPayload(input, input.sandboxId, {
            sandboxOwnerId: workload.sandboxOwnerId,
            attempt: input.attempt,
            bodyHash: input.bodyHash ?? "",
            stdinSequence: input.stdinSequence ?? 0,
          }),
        );
        sendFrame(
          encodeServerControlMessage(
            {
              ...dispatch,
              sandboxOwnerId: workload.sandboxOwnerId,
              ...fsProcessDispatchFields(session.protocolVersion, input),
              digestScheme: input.digestScheme,
              digestKeyId: input.digestKeyId,
            },
            session.protocolVersion,
          ),
        );
      } else {
        sendFrame(
          encodeServerControlMessage(
            {
              type: "operation.dispatch",
              sandboxOwnerId: workload.sandboxOwnerId,
              operationId: input.operationId,
              sandboxId: input.sandboxId,
              idempotencyKey: input.idempotencyKey,
              kind: input.kind,
              generation: input.generation,
              attempt: input.attempt,
              cpuCount: input.cpuCount,
              memoryMiB: input.memoryMiB,
              allocation: input.allocation,
              templateDigest: input.templateDigest,
              templateRevisionId: input.templateRevisionId,
              verificationConnectionEpoch: input.verificationConnectionEpoch,
              incusFingerprint: input.incusFingerprint,
              architecture: input.architecture,
              guestUid: input.guestUid,
              guestGid: input.guestGid,
              guestHome: input.guestHome,
              guestShell: input.guestShell,
              incusName: input.incusName,
              argv: input.argv,
              script: input.script,
              cwd: input.cwd,
              stdinSequence: input.stdinSequence,
              timeoutMs: input.timeoutMs,
              path: input.path,
              destPath: input.destPath,
              recursive: input.recursive,
              maxDepth: input.maxDepth,
              ...fsProcessDispatchFields(session.protocolVersion, input),
              env: input.env,
              privateConfig: input.privateConfig,
              egressPolicy: input.egressPolicy,
              egressPolicyHash: input.egressPolicyHash,
              ...(input.image ? { image: input.image } : {}),
              ...(input.capture ? { capture: input.capture } : {}),
              ...(input.build ? { build: input.build } : {}),
              ...(input.startup ? { startup: input.startup } : {}),
              ...(input.guestSudo ? { guestSudo: true as const } : {}),
              ...(input.guestRoot ? { guestRoot: true as const } : {}),
              ...(input.tunnelPorts
                ? {
                    tunnelPorts: input.tunnelPorts,
                    tunnelPortsRevision: input.tunnelPortsRevision ?? 0,
                  }
                : {}),
              // Omitted (never null) when absent: a dispatch without them is
              // byte-identical to one from before disk offload.
              ...(input.restore ? { restore: input.restore } : {}),
              ...(input.launchMode ? { launchMode: input.launchMode } : {}),
              ...(input.expectDisk ? { expectDisk: input.expectDisk } : {}),
              ...(input.diskBaseFingerprint
                ? { diskBaseFingerprint: input.diskBaseFingerprint }
                : {}),
              ...(input.credentialSpec ? { credentialSpec: input.credentialSpec } : {}),
              // The qualified target is the single source of the signal pid
              // The daemon requires `pid == process.pid`.
              pid: signalDispatchPid(input),
              signal: input.signal,
              bodyHash: input.bodyHash,
              digestScheme: input.digestScheme,
              digestKeyId: input.digestKeyId,
              lease: input.lease,
              ...(input.kind === "file.put"
                ? {
                    fileSize: input.fileUpload?.size,
                    fileSha256: input.fileUpload?.sha256,
                  }
                : {}),
            },
            session.protocolVersion,
          ),
        );
      }
    } catch (error) {
      if (streamKey) this.fileStreams.delete(streamKey);
      throw error;
    }
    const encoded = frameToSend;
    if (encoded === undefined) throw new Error("Missing dispatch frame");
    if (input.kind === "sandbox.create" || input.kind === "sandbox.reconnect") {
      const sent = await relayTransaction(async (tx) => {
        // Match the dispatcher's K -> H order; keep H until socket enqueue.
        if (dispatchKeyId !== null)
          await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${dispatchKeyId} FOR SHARE`;
        await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
        if (!current() || !this.isCurrentRegistered(session, socket)) return false;
        const operation = await tx.sandboxOperation.findFirst({
          where: {
            id: input.operationId,
            userId: workload.sandboxOwnerId,
            generation: input.generation,
            dispatchAttempt: input.attempt,
            dispatchedHostId: hostId,
            dispatchedConnectionEpoch: session.connectionEpoch,
            state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING"] },
            Sandbox: { generation: input.generation, sandboxHostId: hostId },
          },
          select: { id: true },
        });
        if (!operation) return false;
        const event = await tx.outboxEvent.findFirst({
          where: {
            userId: workload.sandboxOwnerId,
            aggregateType: "sandbox",
            aggregateId: input.sandboxId,
            eventType: { in: ["sandbox.create_requested", "sandbox.reconnect_requested"] },
            ...outboxOperationWhere(input.operationId),
          },
          orderBy: { id: "asc" },
          select: { id: true, payload: true },
        });
        const payload = event?.payload;
        if (
          !event ||
          !payload ||
          typeof payload !== "object" ||
          Array.isArray(payload) ||
          payload.allocationJournalEpoch !== session.connectionEpoch ||
          payload.allocationJournalAttempt !== input.attempt
        )
          return "invalid_binding" as const;
        const sequence = this.nextAllocationSequence(session);
        await tx.outboxEvent.updateMany({
          where: { id: event.id, userId: workload.sandboxOwnerId },
          data: { payload: { ...payload, allocationDispatchSequence: sequence } },
        });
        // No await between the last authority fence and enqueue. A failed
        // commit after IO loses evidence and holds, rather than releases.
        if (!current() || !this.isCurrentRegistered(session, socket)) return false;
        input.onPossibleDispatchFrame?.();
        socket.send(encoded);
        return true;
      }, false);
      // Return through the transaction boundary before throwing: relayTransaction
      // sanitizes unexpected exceptions and would erase the validation class.
      if (sent === "invalid_binding")
        throw new SandboxRelayDispatchValidationError("Missing allocation journal binding.");
      if (!sent) return "refused_before_frame";
    } else if (
      (input.kind === "command.run" && input.timeoutMs === 0) ||
      input.requiresFsProcess ||
      input.resultVersion !== undefined ||
      input.processId !== undefined ||
      input.process !== undefined ||
      input.limit !== undefined ||
      input.continuation !== undefined ||
      input.targetOperationId !== undefined
    ) {
      // Keep H through the synchronous socket enqueue. A hello downgrade
      // cannot commit between the durable check and a possible new-shape send.
      const sent = await relayTransaction(async (tx) => {
        if (dispatchKeyId !== null)
          await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${dispatchKeyId} FOR SHARE`;
        await lockHostByEpoch(tx, hostId, session.connectionEpoch, session.identity.userId);
        const host = await tx.sandboxHost.findFirst({
          where: { id: hostId, userId: session.identity.userId },
          select: {
            connectionEpoch: true,
            relayProtocolVersion: true,
            relayProtocolEpoch: true,
            admissionRuntime: true,
            admissionEpoch: true,
          },
        });
        if (
          !fsProcessHostSupported(host) ||
          (input.kind === "command.run" &&
            input.timeoutMs === 0 &&
            !FS_PROCESS_LIMITS.commandTimeoutZero) ||
          !current() ||
          !this.isCurrentRegistered(session, socket)
        )
          return false;
        input.onPossibleDispatchFrame?.();
        socket.send(encoded);
        return true;
      }, false);
      if (!sent) {
        if (streamKey) this.fileStreams.delete(streamKey);
        return "refused_before_frame";
      }
    } else {
      input.onPossibleDispatchFrame?.();
      socket.send(encoded);
    }
    if (input.kind === "file.put") {
      const source = input.fileUpload;
      if (!source || !Number.isSafeInteger(source.size) || source.size < 0)
        throw new Error("Missing file source");
      // Upload streaming runs as its own bounded task (C29): the dispatch loop
      // awaits only the control send, so one slow or ACK-stalled upload never
      // blocks dispatch, cancellation or lease recovery for other owners. A
      // failed stream converges with a silent host: the operation stays
      // DISPATCHED until the guest's idle timeout or the next epoch settles it.
      const key = `${input.operationId}:${input.generation}:${input.attempt}`;
      const task = this.streamFilePut(socket, authorize, current, key, input, source)
        .catch((error: unknown) => {
          console.error(
            `[sandbox-relay] file.put stream ${input.operationId} failed:`,
            safeErrorLog(error),
          );
        })
        .finally(() => {
          this.fileStreams.delete(key);
        });
      this.fileStreams.set(key, task);
    }
    if (input.kind === "command.run" && (input.stdinBytes != null || input.stdinEof === true)) {
      await sendBinaryChunks(
        socket,
        authorize,
        () => current(),
        `stdin-${input.operationId}`,
        input.operationId,
        input.generation,
        input.attempt,
        input.stdinBytes ?? new Uint8Array(),
        { stdin: true },
        input.stdinEof !== false,
      );
    }
    return current() ? "sent" : "sent_then_lost_authority";
  }

  /**
   * One upload's chunk stream, running as a tracked task outside the dispatch
   * loop. Same attempt/epoch fencing as before: every chunk re-authorizes, and
   * every send waits for its exact fenced ACK before the next read.
   */
  private async streamFilePut(
    socket: SandboxRelaySocket,
    authorize: () => Promise<boolean>,
    current: () => boolean,
    key: string,
    input: DispatchOperationInput,
    source: NonNullable<DispatchOperationInput["fileUpload"]>,
  ): Promise<void> {
    for (let offset = 0, sequence = 0; offset < source.size || sequence === 0; sequence++) {
      if (!(await authorize()) || !current()) return;
      const bytes = await this.readUploadChunk(
        source,
        offset,
        Math.min(64 * 1024, source.size - offset),
      );
      if (bytes.length !== Math.min(64 * 1024, source.size - offset))
        throw new Error("Short file source");
      if (!(await authorize()) || !current()) return;
      const ended = offset + bytes.length === source.size;
      if (this.fileAcks.has(key) || this.fileAcks.size >= 16)
        throw new Error("File sender capacity");
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.fileAcks.delete(key);
          reject(new Error("File ACK timeout"));
        }, 30_000);
        timer.unref();
        this.fileAcks.set(key, {
          socket,
          sequence,
          offset: offset + bytes.length,
          resolve,
          reject,
          timer,
        });
        try {
          socket.send(
            encodeBinaryFrame(
              {
                type: ended ? "stream.end" : "stream.chunk",
                streamId: `file-${input.operationId}`,
                operationId: input.operationId,
                generation: input.generation,
                attempt: input.attempt,
                sequence,
                offset,
                flags: { fileUpload: true },
                final: ended,
              },
              bytes,
            ),
          );
        } catch (error) {
          clearTimeout(timer);
          this.fileAcks.delete(key);
          reject(error);
        }
      }).catch((error: unknown) => {
        if (current()) throw error;
      });
      if (!current()) return;
      offset += bytes.length;
      if (ended) break;
    }
  }

  /** Bounded retries for transient store read-admission refusals only; any
   * other failure (expiry, revoked grant, IO) abandons the stream at once. */
  private async readUploadChunk(
    source: NonNullable<DispatchOperationInput["fileUpload"]>,
    offset: number,
    length: number,
  ): Promise<Uint8Array> {
    for (let retry = 0; ; retry++) {
      try {
        return await source.read(offset, length);
      } catch (error) {
        const code = error instanceof ORPCError ? error.code : undefined;
        if (
          (code === "CONFLICT" || code === "TRANSFER_QUOTA") &&
          retry < FILE_READ_ADMISSION_RETRIES
        ) {
          await new Promise((resolve) => setTimeout(resolve, FILE_READ_ADMISSION_RETRY_MS));
          continue;
        }
        throw error;
      }
    }
  }

  /** Last stored-incarnation check for BOTH browser and SDK controls. No
   * target creator credential participates. Order: control K → H → S → O. */
  private async authorizeControlIncarnation(
    session: SessionState,
    operationId: string,
    generation: number,
    attempt: number,
    principal: AuthorizingPrincipal,
    control: "stdin" | "cancel",
  ): Promise<boolean> {
    if (!controlAllowed(principal)) return false;
    const principalKeyId = recordedKeyIdOf(principal);
    return relayTransaction(async (tx) => {
      if (principalKeyId !== null)
        await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${principalKeyId} FOR SHARE`;
      await lockHostByEpoch(
        tx,
        session.identity.hostId,
        session.connectionEpoch,
        session.identity.userId,
      );
      const binding = await requireRelayWorkload(tx, session.identity, { operationId });
      const located = { sandboxId: binding.sandboxId };
      if (!located) return false;
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id=${located.sandboxId} FOR SHARE`;
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id=${operationId} FOR SHARE`;
      const operation = await tx.sandboxOperation.findFirst({
        where: {
          id: operationId,
          userId: binding.sandboxOwnerId,
          generation,
          dispatchAttempt: attempt,
          dispatchedHostId: session.identity.hostId,
          dispatchedConnectionEpoch: session.connectionEpoch,
          state: {
            in:
              control === "cancel"
                ? ["ACCEPTED", "RUNNING", "CANCEL_REQUESTED"]
                : ["ACCEPTED", "RUNNING"],
          },
          ...(control === "stdin" ? { kind: "RUN_COMMAND" as const } : {}),
          Sandbox: { userId: binding.sandboxOwnerId, generation },
        },
        select: { id: true },
      });
      return operation !== null;
    }, false).catch(() => false);
  }

  async sendStdin(
    hostId: string,
    operationId: string,
    generation: number,
    attempt: number,
    bytes: Uint8Array,
    eof: boolean,
    connectionEpoch: number,
    sequence: number,
    principal: AuthorizingPrincipal,
  ): Promise<boolean> {
    // Acceptance reserves this exact range. Reject a zero-frame write before
    // IO, and never confirm a send which failed to emit every reserved slot.
    if (bytes.byteLength === 0 && !eof)
      throw new SandboxRelayDispatchValidationError("Empty stdin requires EOF.");
    const reserved = Math.max(1, Math.ceil(bytes.byteLength / SANDBOX_BINARY_CHUNK_MAX_BYTES));
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    if (!this.isHostConnected(hostId, connectionEpoch)) return false;
    const session = this.sessionsBySocket.get(socket);
    if (!session) return false;
    let current = () => false;
    const authorize = async () => {
      current =
        (await this.authorizeOperation(session, operationId, principal, "stdin")) ?? (() => false);
      return (
        current() &&
        (await this.authorizeControlIncarnation(
          session,
          operationId,
          generation,
          attempt,
          principal,
          "stdin",
        )) &&
        current()
      );
    };
    if (!(await authorize()) || !current()) return false;
    const emitted = await sendBinaryChunks(
      socket,
      authorize,
      () => current(),
      `stdin-${operationId}`,
      operationId,
      generation,
      attempt,
      bytes,
      { stdin: true },
      eof,
      sequence,
    );
    if (emitted !== reserved)
      throw new Error("Stdin frame count does not match reserved sequences.");
    return true;
  }

  async cancelOperation(
    hostId: string,
    operationId: string,
    generation: number,
    attempt: number,
    connectionEpoch: number,
    principal: AuthorizingPrincipal,
  ): Promise<boolean> {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    if (!this.isHostConnected(hostId, connectionEpoch)) return false;
    const session = this.sessionsBySocket.get(socket);
    if (!session) return false;
    const current =
      (await this.authorizeOperation(session, operationId, principal, "cancel")) ?? (() => false);
    if (
      !current() ||
      !(await this.authorizeControlIncarnation(
        session,
        operationId,
        generation,
        attempt,
        principal,
        "cancel",
      )) ||
      !current()
    )
      return false;
    socket.send(
      encodeServerControlMessage(
        {
          type: "operation.cancel",
          operationId,
          generation,
          attempt,
          reason: "cancelled",
        },
        session.protocolVersion,
      ),
    );
    return true;
  }

  /**
   * Terminal frames take an independent lane (C52): validated and routed
   * synchronously instead of queueing behind the serialized control work, so
   * a PTY flood cannot delay heartbeats, cancellation or expiry. Authority is
   * the session's cached ticket (no per-frame IO), enforced by
   * `admitTerminalFrame`. This only checks the session's structure.
   */
  private terminalLane(socket: SandboxRelaySocket, now: Date): SessionState | null {
    const session = this.sessionsBySocket.get(socket);
    if (!session) return null;
    if (!session.registered || this.socketByHostId.get(session.identity.hostId) !== socket) {
      this.closeWithProtocolError(socket, "Terminal frame outside a negotiated terminal session.");
      this.removeSession(socket, now);
      return null;
    }
    return session;
  }

  /**
   * The single host→server terminal authority gate (C52-CO-1). A frame is
   * delivered only under a current ticket. On a stale ticket it is HELD, in
   * order and bounded, while the same fresh revalidation the queued path uses
   * runs: `active` refreshes the ticket and drains the hold; a revoked
   * credential closes 4003 and the hold is discarded (zero bytes delivered).
   */
  private admitTerminalFrame(session: SessionState, frame: HeldTerminalFrame) {
    const hold = session.terminalHold;
    if (hold.frames.length === 0 && session.authorized()) {
      this.deliverTerminalFrame(session.socket, frame);
      return;
    }
    if (
      hold.frames.length >= TERMINAL_HOLD_MAX_FRAMES ||
      hold.bytes + frame.bytes > TERMINAL_HOLD_MAX_BYTES
    ) {
      this.closeWithProtocolError(session.socket, "Terminal frames exceeded their credit windows.");
      this.removeSession(session.socket);
      return;
    }
    hold.frames.push(frame);
    hold.bytes += frame.bytes;
    this.drainTerminalFrames(session);
  }

  private deliverTerminalFrame(socket: SandboxRelaySocket, frame: HeldTerminalFrame) {
    if (frame.kind === "control") this.terminals.handleHostControl(socket, frame.message);
    else this.terminals.handleHostData(socket, frame.metadata, frame.body);
  }

  private drainTerminalFrames(session: SessionState) {
    const hold = session.terminalHold;
    while (hold.frames.length > 0) {
      if (this.sessionsBySocket.get(session.socket) !== session) return;
      if (!session.authorized()) {
        this.refreshTerminalAuthority(session);
        return;
      }
      const frame = hold.frames.shift()!;
      hold.bytes -= frame.bytes;
      this.deliverTerminalFrame(session.socket, frame);
    }
  }

  /** At most one revalidation in flight per socket for held terminal frames. */
  private refreshTerminalAuthority(session: SessionState) {
    if (session.terminalHold.refreshing) return;
    session.terminalHold.refreshing = true;
    void this.authorizeSession(session).finally(() => {
      session.terminalHold.refreshing = false;
    });
  }

  /** A fresh ticket: deliver held host frames, then send deferred browser input/resizes. */
  private resumeTerminals(session: SessionState) {
    this.drainTerminalFrames(session);
    if (session.authorized() && session.terminalHold.frames.length === 0)
      this.terminals.resumeHost(session.socket);
    this.drainChannelFrames(session);
    if (session.authorized() && session.channelHold.frames.length === 0)
      this.connects.resumeHost(session.socket);
  }

  /**
   * Channel frames take the terminal lane's path (wssp-ssh 1b): validated and
   * routed synchronously, bypassing the serialized queue. A host that did not
   * negotiate `channels` never receives one, so any frame from it is a
   * protocol error.
   */
  private channelLane(socket: SandboxRelaySocket, now: Date): SessionState | null {
    const session = this.sessionsBySocket.get(socket);
    if (!session) return null;
    if (
      !session.registered ||
      !session.channelKinds ||
      this.socketByHostId.get(session.identity.hostId) !== socket
    ) {
      this.closeWithProtocolError(socket, "Channel frame outside an open channel.");
      this.removeSession(socket, now);
      return null;
    }
    return session;
  }

  /** The host→server channel authority gate: held in order (bounded) while stale. */
  private admitChannelFrame(session: SessionState, frame: HeldChannelFrame) {
    const hold = session.channelHold;
    if (hold.frames.length === 0 && session.authorized()) {
      this.deliverChannelFrame(session.socket, frame);
      return;
    }
    if (
      hold.frames.length >= CHANNEL_HOLD_MAX_FRAMES ||
      hold.bytes + frame.bytes > CHANNEL_HOLD_MAX_BYTES
    ) {
      this.closeWithProtocolError(session.socket, "Channel frames exceeded their credit windows.");
      this.removeSession(session.socket);
      return;
    }
    hold.frames.push(frame);
    hold.bytes += frame.bytes;
    this.drainChannelFrames(session);
  }

  private deliverChannelFrame(socket: SandboxRelaySocket, frame: HeldChannelFrame) {
    if (frame.kind === "control") this.connects.handleHostControl(socket, frame.message);
    else this.connects.handleHostData(socket, frame.metadata, frame.body);
  }

  private drainChannelFrames(session: SessionState) {
    const hold = session.channelHold;
    while (hold.frames.length > 0) {
      if (this.sessionsBySocket.get(session.socket) !== session) return;
      if (!session.authorized()) {
        this.refreshTerminalAuthority(session);
        return;
      }
      const frame = hold.frames.shift()!;
      hold.bytes -= frame.bytes;
      this.deliverChannelFrame(session.socket, frame);
    }
  }

  handleTextFrame(socket: SandboxRelaySocket, frame: string, now = new Date()) {
    this.notePeerAlive(socket);
    const size = Buffer.byteLength(frame, "utf8");
    if (!this.admitFrameSize(socket, size, HOST_CONTROL_MAX_BYTES)) return;
    let peeked: unknown;
    try {
      peeked = JSON.parse(frame);
    } catch {
      peeked = undefined;
    }
    const type = (peeked as { type?: unknown } | undefined)?.type;
    if (typeof type === "string" && type.startsWith("channel.")) {
      const session = this.channelLane(socket, now);
      if (!session) return;
      let message: DaemonControlMessage;
      try {
        message = parseParsedDaemonControlFrame(peeked, size, session.protocolVersion);
      } catch {
        this.closeWithProtocolError(socket, "Invalid sandbox relay channel frame.");
        this.removeSession(socket, now);
        return;
      }
      if (isHostChannelControl(message))
        this.admitChannelFrame(session, { kind: "control", message, bytes: size });
      return;
    }
    if (typeof type === "string" && type.startsWith("terminal.")) {
      const session = this.terminalLane(socket, now);
      if (!session) return;
      let message: DaemonControlMessage;
      try {
        // Already parsed and sized above; the queued lane re-parses the string.
        message = parseParsedDaemonControlFrame(peeked, size, session.protocolVersion);
      } catch {
        this.closeWithProtocolError(socket, "Invalid sandbox relay terminal frame.");
        this.removeSession(socket, now);
        return;
      }
      if (
        message.type === "terminal.ready" ||
        message.type === "terminal.ack" ||
        message.type === "terminal.exit"
      )
        if (message.fence.target.kind === "host" || session.reconciled)
          this.admitTerminalFrame(session, {
            kind: "control",
            message: message satisfies HostTerminalControl,
            bytes: size,
          });
      return;
    }
    this.enqueueSocketWork(socket, size, async () => {
      const session = this.sessionsBySocket.get(socket);
      if (!session || !(await this.authorizeSession(session)) || !session.authorized()) return;
      let message: DaemonControlMessage;
      try {
        message = parseDaemonControlFrame(frame, session.protocolVersion);
      } catch {
        this.closeWithProtocolError(socket, UNPARSED_CONTROL_FRAME_MESSAGE);
        this.removeSession(socket, now);
        return;
      }
      if (message.type === "hello") {
        await this.handleHello(session, message, now);
        return;
      }
      if (!this.requireCurrentHello(session, socket, now)) return;
      const sender = this.senderOf(session);
      switch (message.type) {
        case "process.started": {
          // Birth is best-effort and may race reconciliation. It only binds
          // identity, never promotes state, and ingress requires the exact
          // dispatched epoch/attempt. Previous-epoch births cannot be adopted;
          // only terminal receipt reconciliation can adopt an older dispatch.
          await applyProcessStarted({ sender, birth: message });
          return;
        }
        case "operation.receipt.pruned": {
          this.noteLifecycleResult(session, message.sandboxId);
          // A pruned report can retire only its exact creator/placement tuple.
          // No digest is fabricated and this never settles an unknown effect.
          const bound = await relayTransaction(async (tx) => {
            await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
            const binding = await requireRelayWorkload(tx, sender, message);
            await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${message.sandboxId} AND "userId" = ${binding.sandboxOwnerId} FOR SHARE`;
            await requireRelayWorkload(tx, sender, message);
            const operation = await tx.sandboxOperation.findFirst({
              where: {
                id: message.operationId,
                userId: binding.sandboxOwnerId,
                sandboxId: message.sandboxId,
                generation: message.generation,
                dispatchAttempt: message.attempt,
                dispatchedHostId: sender.hostId,
                dispatchedConnectionEpoch: { lte: sender.connectionEpoch },
                idempotencyKey: message.idempotencyKey,
              },
              select: { kind: true },
            });
            requireRelayFence(
              operation != null && relayDispatchKind(operation.kind) === message.kind,
            );
            return true;
          }, false);
          if (!bound) return;
          await applyOperationResult({
            sender,
            sandboxOwnerId: message.sandboxOwnerId,
            operationId: message.operationId,
            sandboxId: message.sandboxId,
            generation: message.generation,
            attempt: message.attempt,
            state: "unknown_outcome",
            error: { code: "receipt_digest_pruned", message: "Receipt digest pruned." },
          });
          if (this.isCurrentRegistered(session, socket)) {
            // Retire only the host's exact tombstone; UNKNOWN and the live slot
            // remain held on the server. No result digest is invented.
            socket.send(
              encodeServerControlMessage(
                {
                  ...message,
                  type: "receipt.pruned.ack",
                  connectionEpoch: session.connectionEpoch,
                },
                session.protocolVersion,
              ),
            );
            socket.send(
              encodeServerControlMessage(
                { type: "receipt.ack", operationId: message.operationId },
                session.protocolVersion,
              ),
            );
          }
          return;
        }
        case "dispatch.audit.request": {
          // Only before reconciliation, one outstanding page at a time.
          if (session.reconciled) throw new Error("dispatch audit after reconciliation");
          session.audit ??= { nextPage: 0, done: false };
          const audit = session.audit;
          if (audit.done || audit.offered || message.page !== audit.nextPage)
            throw new Error("out-of-order dispatch audit");
          const page = await listUnacknowledgedDispatches(
            sender,
            audit.cursor,
            DISPATCH_AUDIT_PAGE_MAX,
          );
          audit.cursor = page.cursor ?? audit.cursor;
          audit.offered = {
            page: message.page,
            entries: new Map(page.entries.map((entry) => [entry.operationId, entry])),
          };
          audit.done = page.complete;
          if (this.isCurrentRegistered(session, socket))
            socket.send(
              encodeServerControlMessage(
                {
                  type: "dispatch.audit.page",
                  page: message.page,
                  complete: page.complete,
                  entries: page.entries,
                },
                session.protocolVersion,
              ),
            );
          return;
        }
        case "dispatch.audit.result": {
          if (session.reconciled) throw new Error("dispatch audit after reconciliation");
          const offered = session.audit?.offered;
          if (!offered || offered.page !== message.page)
            throw new Error("dispatch audit result without its page");
          session.audit!.offered = undefined;
          session.audit!.nextPage = message.page + 1;
          for (const verdict of message.entries) {
            const entry = offered.entries.get(verdict.operationId);
            if (
              !entry ||
              entry.generation !== verdict.generation ||
              entry.attempt !== verdict.attempt
            )
              throw new Error("dispatch audit verdict for an unoffered attempt");
            // A positive never-received proof: dispatch it again on this epoch
            // (or settle it definitely) instead of reconciling it UNKNOWN.
            if (!verdict.received) await settleUndeliveredDispatch({ sender, ...entry });
          }
          return;
        }
        case "operation.adopt": {
          // Reconnect adoption of an attempt this host journaled under an
          // older epoch: only before reconciliation, bounded per session.
          if (session.reconciled) throw new Error("adoption after reconciliation");
          session.adoptFrames = (session.adoptFrames ?? 0) + 1;
          if (session.adoptFrames > SANDBOX_RELAY_MAX_ADOPT_FRAMES)
            throw new Error("too many adoption frames");
          const launch = message.kind === "sandbox.create" || message.kind === "sandbox.reconnect";
          const adopted = await adoptOperation({
            sender,
            ...message,
            ...(launch ? { allocationSequence: this.nextAllocationSequence(session) } : {}),
          });
          if (this.isCurrentRegistered(session, socket))
            socket.send(
              encodeServerControlMessage(
                {
                  type: "operation.adopt.result",
                  operationId: message.operationId,
                  generation: message.generation,
                  attempt: message.attempt,
                  adopted,
                },
                session.protocolVersion,
              ),
            );
          return;
        }
        case "operation.receipt": {
          this.noteLifecycleResult(session, message.sandboxId);
          // Exact-bound receipts also resolve a live UNKNOWN after its cleanup
          // owner obtains evidence. The same owner/host/epoch/attempt/hash fences
          // apply before and after initial inventory reconciliation.
          const receiptInput = {
            sender,
            ...message,
            error: message.error ?? undefined,
            result: message.result ?? undefined,
            receipt: {
              bodyHash: message.bodyHash,
              idempotencyKey: message.idempotencyKey,
              kind: message.kind,
            },
          };
          const receiptOutcome = await applyOperationResult(receiptInput);
          const confirmed = await confirmOperationReceipt({
            ...receiptInput,
            ...receiptOutcome,
          });
          if (confirmed && this.isCurrentRegistered(session, socket))
            socket.send(encodeServerControlMessage(confirmed, session.protocolVersion));
          this.releaseDroppedCapture(sender, receiptOutcome.releaseImage);
          if (this.isCurrentRegistered(session, socket))
            socket.send(
              encodeServerControlMessage(
                { type: "receipt.ack", operationId: message.operationId },
                session.protocolVersion,
              ),
            );
          return;
        }
        case "sandbox.inventory": {
          if (session.reconciled) throw new Error("inventory after reconciliation");
          session.census ??= new InventoryCensus(sender);
          // A sandbox whose entry contradicts the server is contained to that
          // sandbox (E3-A-01): the census, and the node, go on.
          const outcome = await session.census.acceptPage(message);
          if (!this.isCurrentRegistered(session, socket)) return;
          // With `censusEntryResults` the ACK says which entries converged
          // and which were refused for stale storage (the host retries those).
          if ("ok" in outcome)
            socket.send(
              encodeServerControlMessage(
                {
                  type: "inventory.ack",
                  page: message.page,
                  entryResults: session.census.pageResults,
                },
                session.protocolVersion,
              ),
            );
          return;
        }
        case "allocation.attest.result":
          await session.allocationAttestation?.accept(message);
          return;
        case "sandbox.expiry_status": {
          // Every connected expiry report is judged as one ordered batch.
          if (message.batch === undefined) throw new Error("expiry status batch missing");
          if (message.batch !== undefined) {
            if (message.batch <= (session.expiryStatusBatch ?? 0))
              throw new Error("expiry status batch out of order");
            // Every batch names its observation, which never goes back.
            if (
              message.observation === undefined ||
              !session.observationFence?.accept(message.observation)
            )
              throw new Error("expiry status observation missing or out of order");
            session.expiryStatusBatch = message.batch;
          }
          // Before reconciliation the census is the only evidence channel.
          if (!session.reconciled) return;
          // Evidence is re-offered by the host until it is judged here.
          // Non-expired evidence from an observation that may predate a
          // lifecycle result this session received is not judged.
          const fence = session.observationFence;
          const observation = message.observation!;
          const judged = await judgeExpiryStatus(sender, message.entries, undefined, (sandboxId) =>
            fence ? fence.predates(sandboxId, observation) : true,
          );
          if ("results" in judged && this.isCurrentRegistered(session, socket))
            socket.send(
              encodeServerControlMessage(
                {
                  type: "sandbox.expiry_status.ack",
                  batch: message.batch,
                  entryResults: judged.results,
                },
                session.protocolVersion,
              ),
            );
          return;
        }
        case "reconcile.complete":
          if (session.reconciled) throw new Error("duplicate reconciliation");
          // Absence is concluded only from a complete census, never inferred here.
          if (!session.census?.complete) throw new Error("reconciliation before census");
          // D11: receipts the host is still resolving are left unsettled (no
          // interim unknown outcome) until they arrive or this session ends.
          session.reconciled = await finishHostReconciliation(
            sender,
            undefined,
            new Set(message.pendingReceipts ?? []),
          );
          if (session.reconciled && message.pendingReceipts?.length)
            this.sweepPendingReceipts(session, socket, sender, new Set(message.pendingReceipts));
          if (session.reconciled) await session.availabilityCensus?.next();
          if (session.reconciled) {
            session.allocationAttestation = new AllocationAttestation(
              {
                ...sender,
                isCurrent: () => session.authorized() && this.isCurrentRegistered(session, socket),
              },
              () => this.nextAllocationSequence(session),
              (request) =>
                socket.send(encodeServerControlMessage(request, session.protocolVersion)),
            );
            await session.allocationAttestation.request();
          }
          if (session.reconciled && this.isCurrentRegistered(session, socket)) {
            session.reconciledAt = Date.now();
            notifySandboxDispatchPending();
            wakeTunnelController();
          }
          return;
        case "terminal.ready":
        case "terminal.ack":
        case "terminal.exit":
          // Routed by the terminal lane before queueing; never reached.
          return;
        case "heartbeat": {
          const written = await recordHostHeartbeat(sender, message.policyReconciler, now);
          if (!written || !this.isCurrentRegistered(session, socket)) return;
          session.lastHeartbeatAt = now;
          socket.send(
            encodeServerControlMessage(
              {
                type: "heartbeat.pong",
                id: message.id,
                receivedAt: now.toISOString(),
              },
              session.protocolVersion,
            ),
          );
          return;
        }
        case "private.config.refused":
          await (await import("./outbox-processor.js")).refuseExecutionConfig(sender, message);
          return;
        case "private.config.ack":
          if (await acknowledgeExecutionConfig(sender, message)) notifySandboxDispatchPending();
          return;
        case "journal.key.ack":
          if (await acknowledgeJournalKey(sender, message)) notifySandboxDispatchPending();
          return;
        case "host.agent-policy":
          if (this.hostAccess.policies.report(session.identity.hostId, session.socket, message))
            await this.resendHostPolicyVeto(session, "hostCommands", message.hostCommands);
          return;
        case "host.policy.lower.result":
        case "host.exec.started":
        case "host.exec.rejected":
        case "host.exec.status":
        case "host.exec.stdin.result":
        case "host.file.result":
          await this.hostAccess.receive(this.hostAccessLink(session), message);
          return;
        case "host.terminal-policy":
          if (this.hostTerminalPolicies.report(session.identity.hostId, session.socket, message))
            await this.resendHostPolicyVeto(session, "hostTerminal", message.hostTerminal);
          return;
        case "host.quiesce": {
          // WP7 (D9): negotiated. From here on new `command.run` work for this
          // host stays QUEUED in the outbox (held before its claim) until a
          // later connection's hello arrives without `quiescing`.
          if (!session.quiesceCapable) throw new Error("unnegotiated quiesce");
          if (!this.isCurrentRegistered(session, socket)) return;
          if (message.connectionEpoch !== session.connectionEpoch) return;
          if (message.sequence <= (session.quiesceSequence ?? 0)) return;
          session.quiesceSequence = message.sequence;
          session.quiescing = true;
          socket.send(
            encodeServerControlMessage(
              { type: "host.quiesce.ack", sequence: message.sequence },
              session.protocolVersion,
            ),
          );
          this.recordQuiesceHold(session, true);
          return;
        }
        case "tunnel.portsStatus":
          if (session.tunnelPorts && session.registered)
            await tunnelController().onPortsStatus(
              session.identity.hostId,
              session.connectionEpoch,
              message,
            );
          return;
        case "tunnel.status":
          // Accepted from registration on: a reconnecting daemon reports its
          // running clients before reconciliation, so they are not re-applied.
          if (session.tunnelCapable && session.registered)
            await tunnelController().onStatus(
              session.identity.hostId,
              session.connectionEpoch,
              message,
            );
          return;
        case "host.lease-policy":
          if (!this.isCurrentRegistered(session, socket)) return;
          await recordHostLeasePolicy(session, message, () =>
            this.isCurrentRegistered(session, socket),
          );
          return;
        case "host.egress-state":
          if (!this.isCurrentRegistered(session, socket)) return;
          await recordHostEgressState(session, message, () =>
            this.isCurrentRegistered(session, socket),
          );
          return;
        case "host.admission":
          await recordHostAdmission(sender, message, now, session.admissionState);
          return;
        case "availability.result":
          await session.availabilityCensus?.accept(message);
          return;
        case "inventory.update":
          if (message.inventory.hostId !== sender.hostId)
            throw new Error("inventory host mismatch");

          await recordHostInventory(sender, message.inventory.schedulable, message);

          return;
        case "file.chunk.ack": {
          const key = `${message.operationId}:${message.generation}:${message.attempt}`;
          const pending = this.fileAcks.get(key);
          if (
            pending &&
            pending.socket === socket &&
            session.reconciled &&
            sender.isCurrent?.() &&
            pending.sequence === message.sequence &&
            pending.offset === message.offset
          ) {
            clearTimeout(pending.timer);
            this.fileAcks.delete(key);
            pending.resolve();
          }
          return;
        }
        case "sandbox.probe.result": {
          const pending = this.pendingProbes.get(message.requestId);
          if (
            !pending ||
            pending.socket !== socket ||
            pending.epoch !== session.connectionEpoch ||
            !session.reconciled ||
            !sender.isCurrent?.()
          )
            return;
          this.pendingProbes.delete(message.requestId);
          clearTimeout(pending.timer);
          pending.resolve(message.state);
          return;
        }
        case "image.verify.result": {
          const pending = this.pendingImageVerifies.get(message.requestId);
          if (!pending || pending.socket !== socket || pending.epoch !== session.connectionEpoch)
            return;
          this.pendingImageVerifies.delete(message.requestId);
          clearTimeout(pending.timer);
          if (message.error) {
            // Only an actual image verdict rejects the template: a missing
            // alias, a non-VM image or an architecture mismatch. Everything
            // else (host_capacity queue-full, transient runtime failures) means
            // the host could not answer — a retryable host_unavailable (C46).
            if (message.error.code === "not_found") {
              pending.reject(new HostImageMissing("host image was not found"));
            } else if (message.error.code === "protocol_error") {
              pending.reject(new HostImageRejected(message.error.message));
            } else {
              pending.reject(new Error(message.error.message));
            }
            return;
          }
          if (!message.incusFingerprint || message.architecture !== pending.expectedArchitecture) {
            pending.reject(new HostImageRejected("host returned incomplete image verification"));
            return;
          }
          pending.resolve({
            incusFingerprint: message.incusFingerprint,
            architecture: message.architecture,
            ...(message.sizeBytes ? { sizeBytes: message.sizeBytes } : {}),
            ...(message.format ? { format: message.format } : {}),
          });
          return;
        }
        case "image.fetch.request":
        case "image.cached":
        case "image.evicted":
        case "image.fetch.failed":
        case "image.cache.census":
        case "image.links.request":
        case "image.part.ack":
        case "image.upload.begin":
        case "image.upload.parts":
        case "image.upload.complete":
        case "image.job.resume":
        case "image.job.failed": {
          // Image requests and replies require image-cache runtime support.
          if (!session.imageFeatures) throw new Error("unnegotiated image frame");
          if (!session.reconciled) throw new Error("image frame before reconciliation");
          // Image frames are advisory to the relay: a failed handler is logged
          // (class only) and answered where a reply is owed, never a dropped session.
          await this.handleImageMessage(session, socket, sender, message).catch((error) => {
            console.error(
              `[sandbox-relay] image frame ${message.type} failed (${error instanceof Error ? error.constructor.name : typeof error})`,
            );
            if (message.type === "image.fetch.request" && this.isCurrentRegistered(session, socket))
              socket.send(
                encodeServerControlMessage(
                  { type: "image.fetch.refused", requestId: message.requestId, code: "internal" },
                  session.protocolVersion,
                ),
              );
          });
          return;
        }
        case "disk.upload.begin":
        case "disk.upload.parts":
        case "disk.upload.complete":
        case "disk.offload.failed":
        case "disk.evict.request":
        case "disk.evicted":
        case "disk.discarded":
        case "disk.offload.released":
        case "disk.offload.inventory": {
          // Only a session that advertised `diskOffload` may speak them.
          if (!session.diskOffload) throw new Error("unnegotiated disk offload frame");
          if (!session.reconciled) throw new Error("disk offload frame before reconciliation");
          // Advisory like image frames: a failed handler is logged (class
          // only), never a dropped session.
          await this.handleDiskMessage(session, socket, sender, message).catch((error) => {
            console.error(
              `[sandbox-relay] disk frame ${message.type} failed (${error instanceof Error ? error.constructor.name : typeof error})`,
            );
          });
          return;
        }
        case "egress.refused":
          if (!session.egressRefusedHints) throw new Error("unnegotiated egress hint");
          if (!session.reconciled || !this.isCurrentRegistered(session, socket)) return;
          session.egressHintThrottle ??= new EgressHintThrottle();
          await handleEgressRefused({
            hostId: sender.hostId,
            sandboxId: message.sandboxId,
            names: message.names,
            throttle: session.egressHintThrottle,
            nowMs: Date.now(),
          });
          return;
        case "credential.spec.request":
        case "credential.bundle.request":
        case "credential.capture.begin":
        case "credential.capture.chunk":
        case "credential.installed":
        case "credential.scrubbed":
        case "credential.return.key.ack":
        case "credential.census":
        case "credential.quarantine.discarded": {
          // Only a session that negotiated CLI logins may speak them, and only
          // a return-key ack may precede reconciliation (the key is sent at hello).
          if (!session.credentialFeatures) throw new Error("unnegotiated credential frame");
          if (!session.reconciled && message.type !== "credential.return.key.ack")
            throw new Error("credential frame before reconciliation");
          const relay = this.credentialRelayOf(session, socket, sender);
          await relay.handle(message).catch((error) => {
            console.error(
              `[sandbox-relay] credential frame ${message.type} failed (${error instanceof Error ? error.constructor.name : typeof error})`,
            );
            if (
              message.type === "credential.bundle.request" &&
              this.isCurrentRegistered(session, socket)
            )
              socket.send(
                encodeServerControlMessage(
                  {
                    type: "credential.bundle.refused",
                    requestId: message.requestId,
                    code: "internal",
                  },
                  session.protocolVersion,
                ),
              );
          });
          return;
        }
        case "operation.progress":
          if (!session.reconciled) throw new Error("progress before reconciliation");
          await applyOperationProgress({
            sender,
            operationId: message.operationId,
            sandboxId: message.sandboxId,
            generation: message.generation,
            attempt: message.attempt,
            state: message.state,
            ...(message.progress ? { progress: message.progress } : {}),
          });
          return;
        case "operation.result": {
          if (!session.reconciled) throw new Error("result before reconciliation");
          this.noteLifecycleResult(session, message.sandboxId);
          const resultInput = {
            sender,
            operationId: message.operationId,
            sandboxId: message.sandboxId,
            generation: message.generation,
            attempt: message.attempt,
            state: message.state,
            error: message.error,
            result: message.result,
          };
          const resultOutcome = await applyOperationResult(resultInput);
          const confirmed = await confirmOperationReceipt({ ...resultInput, ...resultOutcome });
          if (confirmed && this.isCurrentRegistered(session, socket))
            socket.send(encodeServerControlMessage(confirmed, session.protocolVersion));
          this.releaseDroppedCapture(sender, resultOutcome.releaseImage);
          if (resultOutcome.written && resultOutcome.allocationUnknown)
            await session.allocationAttestation?.request(message.operationId);
        }
      }
    });
  }

  handleBinaryFrame(socket: SandboxRelaySocket, frame: ArrayBuffer, now = new Date()) {
    this.notePeerAlive(socket);
    if (!this.admitFrameSize(socket, frame.byteLength, SANDBOX_FRAME_MAX_BYTES)) return;
    let terminal: ReturnType<typeof parseTerminalDataFrame>;
    try {
      terminal = parseTerminalDataFrame(frame);
    } catch {
      this.closeWithProtocolError(socket, "Invalid sandbox relay terminal frame.");
      this.removeSession(socket, now);
      return;
    }
    if (terminal) {
      const session = this.terminalLane(socket, now);
      if (session && (terminal.metadata.fence.target.kind === "host" || session.reconciled))
        this.admitTerminalFrame(session, {
          kind: "data",
          metadata: terminal.metadata,
          body: terminal.body,
          bytes: frame.byteLength,
        });
      return;
    }
    let channel: ReturnType<typeof parseChannelDataFrame>;
    try {
      channel = parseChannelDataFrame(frame);
    } catch {
      // A channel frame that does not parse: never queued, never delivered.
      if (this.sessionsBySocket.has(socket)) {
        this.closeWithProtocolError(socket, "Invalid sandbox relay channel frame.");
        this.removeSession(socket, now);
      }
      return;
    }
    if (channel) {
      const session = this.channelLane(socket, now);
      if (session)
        this.admitChannelFrame(session, {
          kind: "data",
          metadata: channel.metadata,
          body: channel.body,
          bytes: frame.byteLength,
        });
      return;
    }
    // Parsed up front only to recognise batchable output; a frame that does
    // not parse is reported by its own queued work, in order, as before.
    let parsed: ReturnType<typeof parseBinaryFrame> | undefined;
    try {
      parsed = parseBinaryFrame(frame);
    } catch {
      parsed = undefined;
    }
    const output =
      parsed &&
      parsed.metadata.type === "stream.chunk" &&
      Boolean(parsed.metadata.flags?.stdout) !== Boolean(parsed.metadata.flags?.stderr)
        ? parsed
        : undefined;
    this.enqueueSocketWork(
      socket,
      frame.byteLength,
      () => this.acceptBinaryFrame(socket, now, parsed ?? frame),
      output,
    );
  }

  /** One fenced binary frame: the per-chunk path (and every batch fallback). */
  private async acceptBinaryFrame(
    socket: SandboxRelaySocket,
    now: Date,
    frame: ArrayBuffer | ReturnType<typeof parseBinaryFrame>,
  ): Promise<void> {
    const session = this.sessionsBySocket.get(socket);
    if (
      !session ||
      !(await this.authorizeSession(session)) ||
      !session.authorized() ||
      !this.requireCurrentHello(session, socket, now)
    )
      return;
    if (!session.reconciled) throw new Error("binary before reconciliation");
    const parsed = frame instanceof ArrayBuffer ? parseBinaryFrame(frame) : frame;
    const output =
      parsed.metadata.flags?.stdout || parsed.metadata.flags?.stderr ? parsed.metadata : undefined;
    if (!output && parsed.metadata.flags?.fileDownload !== true) return;
    const accepted = await acceptFencedBinaryChunk({
      output,
      outputChunkBytes: session.outputChunkBytes,
      sender: this.senderOf(session),
      ...parsed.metadata,
      body: parsed.body,
      ended: parsed.metadata.type === "stream.end" || parsed.metadata.final === true,
    });
    if (accepted) this.ackBinaryChunk(session, socket, parsed.metadata, parsed.body.length);
  }

  private ackBinaryChunk(
    session: SessionState,
    socket: SandboxRelaySocket,
    metadata: StreamBinaryMetadata,
    length: number,
  ) {
    if (!session.authorized() || !this.isCurrentRegistered(session, socket)) return;
    const output = metadata.flags?.stdout || metadata.flags?.stderr;
    socket.send(
      encodeServerControlMessage(
        {
          type: output ? "command.output.ack" : "file.chunk.ack",
          operationId: metadata.operationId,
          generation: metadata.generation,
          attempt: metadata.attempt,
          sequence: metadata.sequence,
          offset: (metadata.offset ?? 0) + length,
        },
        session.protocolVersion,
      ),
    );
  }

  /**
   * D3b: consecutive queued output chunks of one operation attempt. The
   * session is revalidated once; the chunks commit in one fenced transaction and
   * are then ACKed one by one, exactly as single chunks are. Whenever the batch
   * cannot commit whole (authority, fence, protocol or storage refusal), its
   * chunks run one at a time instead, reproducing the per-chunk outcome.
   */
  private async acceptOutputBatch(
    socket: SandboxRelaySocket,
    items: readonly OutputWork[],
  ): Promise<void> {
    const [first, ...rest] = items;
    if (!first) return;
    const session = this.sessionsBySocket.get(socket);
    if (
      !session ||
      !(await this.authorizeSession(session)) ||
      !session.authorized() ||
      !this.requireCurrentHello(session, socket, new Date())
    ) {
      // The first chunk was refused as the per-chunk path refuses it; every
      // other chunk revalidates on its own.
      for (const item of rest) await item.run();
      return;
    }
    if (!session.reconciled) throw new Error("binary before reconciliation");
    // `takeOutputBatch` yields one operation attempt only.
    const { operationId, generation, attempt } = first.output.metadata;
    let committed = false;
    try {
      committed = await acceptFencedOutputBatch({
        sender: this.senderOf(session),
        operationId,
        generation,
        attempt,
        frames: items.map((item) => item.output),
        outputChunkBytes: session.outputChunkBytes,
        current: () => session.authorized(),
      });
    } catch {
      committed = false;
    }
    if (!committed) {
      for (const item of items) await item.run();
      return;
    }
    for (const { output } of items)
      this.ackBinaryChunk(session, socket, output.metadata, output.body.length);
  }

  /** Deterministic drain for shutdown/tests; every received frame shares this tail. */
  async drain(socket: SandboxRelaySocket): Promise<void> {
    await this.frameTail.get(socket);
  }

  removeSession(
    socket: SandboxRelaySocket,
    now = new Date(),
    terminalIntent: TerminalCloseIntent = "host_disconnected",
    terminalError?: { code: SandboxErrorCode; message: string },
  ) {
    const session = this.sessionsBySocket.get(socket);
    if (!session) return;
    // Held terminal and channel frames are never delivered once the session is gone.
    session.terminalHold.frames.length = 0;
    session.terminalHold.bytes = 0;
    session.channelHold.frames.length = 0;
    session.channelHold.bytes = 0;
    for (const [key, ack] of this.fileAcks)
      if (ack.socket === socket) {
        clearTimeout(ack.timer);
        this.fileAcks.delete(key);
        ack.reject(new Error("Host disconnected"));
      }
    const queue = this.queues.get(socket);
    this.queues.delete(socket);
    if (queue) {
      queue.work.length = 0;
      // The queue owns the transport pause; dropping it releases the pause.
      // A paused `ws` never reads the peer's close reply, so the close
      // handshake (ours below, or the caller's) would otherwise wait out the
      // 30 s close timeout after the per-host slot was already freed.
      if (queue.paused) {
        queue.paused = false;
        try {
          socket.resume?.();
        } catch {
          /* Transport already failed. */
        }
      }
    }
    session.availabilityCensus?.stop();
    session.credentialRelay?.dispose();
    clearTimeout(session.unauthenticatedTimer);
    clearTimeout(session.expiryTimer);
    clearInterval(session.pendingReceiptSweep);
    clearInterval(session.liveness.pingTimer);
    clearTimeout(session.liveness.deadlineTimer);
    session.allocationAttestation?.close();
    for (const [id, pending] of this.pendingProbes) {
      if (pending.socket === socket) {
        clearTimeout(pending.timer);
        pending.resolve("unreachable");
        this.pendingProbes.delete(id);
      }
    }
    for (const [id, pending] of this.pendingImageVerifies) {
      if (pending.socket === socket) {
        clearTimeout(pending.timer);
        pending.reject(new Error("host disconnected"));
        this.pendingImageVerifies.delete(id);
      }
    }
    this.hostTerminalPolicies.remove(session.identity.hostId, socket);
    const hostAccessCleanup = session.registered
      ? this.hostAccess
          .disconnect(session.identity.hostId, session.identity.userId, socket)
          .catch(() => console.error("[host-access] disconnect audit failed"))
      : Promise.resolve();
    this.sessionsBySocket.delete(socket);
    const hostSockets = this.socketsByHostId.get(session.identity.hostId);
    hostSockets?.delete(socket);
    if (hostSockets?.size === 0) this.socketsByHostId.delete(session.identity.hostId);
    // No terminal session survives its host socket (no adoption on reconnect);
    // a resumable one (WP8) tells its v2 browser it may reattach.
    this.terminals.removeHostSocket(socket, terminalIntent, false, terminalError);
    // CLI connections bound to this host connection end; its channels settle.
    this.connects.removeHostSocket(socket, session.identity.hostId);
    if (socket.readyState === WS_READY_STATE_OPEN) {
      try {
        socket.close(1001, "session_removed");
      } catch {
        /* Still revoke authority below. */
      }
    }
    if (this.socketByHostId.get(session.identity.hostId) === socket) {
      this.socketByHostId.delete(session.identity.hostId);
    }
    if (session.registered) {
      const revocation = Promise.all([this.revokeEpoch(session, now), hostAccessCleanup]).then(
        () => undefined,
      );
      this.epochRevocations.add(revocation);
      void revocation.then(() => this.epochRevocations.delete(revocation));
      return revocation;
    }
  }

  private async markHostDisconnected(session: SessionState, now: Date) {
    try {
      await disconnectJournalKey(
        {
          hostId: session.identity.hostId,
          userId: session.identity.userId,
          connectionEpoch: session.connectionEpoch,
        },
        now,
        false,
      );
    } catch (error) {
      console.error("[sandbox-relay] host disconnect mark failed:", safeErrorLog(error));
    }
  }

  private async revokeEpoch(session: SessionState, now: Date) {
    try {
      // disconnectJournalKey returns false on an epoch CAS loss: a newer hello
      // already owns authority. That expected outcome needs no error log.
      await disconnectJournalKey(
        {
          hostId: session.identity.hostId,
          userId: session.identity.userId,
          connectionEpoch: session.connectionEpoch,
        },
        now,
        true,
      );
    } catch (error) {
      console.error("[sandbox-relay] epoch revocation failed:", safeErrorLog(error));
    }
  }

  /** Resolves when every currently tracked upload stream has ended (tests and
   * shutdown drains; streams also end on their own when their session leaves). */
  async settledFileStreams(): Promise<void> {
    await Promise.allSettled([...this.fileStreams.values()]);
  }

  dispose() {
    this.unsubscribe();
    // CLI connections end `shutdown` (their channels are asked to close)
    // before the host sockets go.
    this.connects.dispose();
    this.terminals.closeAll("shutdown");
    for (const pending of this.pendingImageVerifies.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("sandbox relay shutting down"));
    }
    this.pendingImageVerifies.clear();
    for (const pending of this.pendingProbes.values()) {
      clearTimeout(pending.timer);
      pending.resolve("unreachable");
    }
    this.pendingProbes.clear();
    for (const socket of this.sessionsBySocket.keys()) this.removeSession(socket);
    return Promise.allSettled([...this.helloRegistrations]).then(async () => {
      // A hello removed above may commit during the drain and register its
      // epoch revocation only then. Read the set after those hellos settle.
      while (this.epochRevocations.size) await Promise.allSettled([...this.epochRevocations]);
    });
  }

  private nextAllocationSequence(session: SessionState): number {
    const sequence = (session.allocationSequence ?? 0) + 1;
    if (!Number.isSafeInteger(sequence)) throw new Error("Allocation sequence exhausted");
    session.allocationSequence = sequence;
    return sequence;
  }

  private credentialRelayOf(
    session: SessionState,
    socket: SandboxRelaySocket,
    sender: RelaySender,
  ): import("./credential-handlers.js").CredentialSessionRelay {
    session.credentialRelay ??= new CredentialSessionRelay(sender, (frame) => {
      if (this.isCurrentRegistered(session, socket))
        socket.send(encodeServerControlMessage(frame, session.protocolVersion));
    });
    return session.credentialRelay;
  }

  /**
   * Send a server-initiated credential frame (`credential.revoke`,
   * `credential.quarantine.discard`) to a host's current, credential-capable
   * session; false when there is none (delivery is best-effort, §7.4.2).
   */
  sendCredentialFrame(
    hostId: string,
    frame: import("@wssp/sandbox-contracts").ServerCredentialMessage,
  ): boolean {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      !session.credentialFeatures ||
      !session.authorized()
    )
      return false;
    try {
      socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      return true;
    } catch {
      return false;
    }
  }

  /** Send an image frame to a host's current, image-capable session. */
  /** E2-A-01: unpin and evict a capture image no revision will ever use. A
   * frame lost here is recovered by the census and the origin-pin GC. */
  private releaseDroppedCapture(
    sender: { hostId: string; connectionEpoch: number },
    release: { imageOwnerId: string; fingerprint: string } | undefined,
  ) {
    if (!release) return;
    this.sendImageFrame(sender.hostId, sender.connectionEpoch, {
      type: "image.release",
      fingerprint: release.fingerprint,
      imageOwnerId: release.imageOwnerId,
      reason: "gc",
    });
  }

  sendImageFrame(
    hostId: string,
    connectionEpoch: number,
    frame: import("@wssp/sandbox-contracts").ServerImageMessage,
  ): boolean {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      !session.imageFeatures ||
      session.connectionEpoch !== connectionEpoch ||
      !session.authorized()
    )
      return false;
    try {
      socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      return true;
    } catch {
      return false;
    }
  }

  /** a disk frame goes only to the current, reconciled
   * session of that epoch that advertised `diskOffload`. */
  /** Preview tunnels: the registered, reconciled session of `hostId` here. */
  tunnelLink(hostId: string): TunnelHostLink | null {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return null;
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      session.reconciledAt === undefined ||
      !session.authorized() ||
      !this.isCurrentRegistered(session, socket)
    )
      return null;
    return {
      hostId,
      ownerId: session.identity.userId,
      epoch: session.connectionEpoch,
      reconciledAt: session.reconciledAt,
      capable: session.tunnelCapable === true,
      plan: session.tunnelPorts === true,
      send: (frame) => {
        if (
          socket.readyState !== WS_READY_STATE_OPEN ||
          !session.authorized() ||
          !this.isCurrentRegistered(session, socket)
        )
          return false;
        try {
          socket.send(encodeServerControlMessage(frame, session.protocolVersion));
          return true;
        } catch {
          return false;
        }
      },
    };
  }

  sendDiskFrame(
    hostId: string,
    connectionEpoch: number,
    frame: import("@wssp/sandbox-contracts").ServerDiskMessage,
  ): boolean {
    const socket = this.socketByHostId.get(hostId);
    if (!socket || socket.readyState !== WS_READY_STATE_OPEN) return false;
    const session = this.sessionsBySocket.get(socket);
    if (
      !session?.registered ||
      !session.reconciled ||
      session.diskOffload !== true ||
      session.connectionEpoch !== connectionEpoch ||
      !session.authorized()
    )
      return false;
    try {
      socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      return true;
    } catch {
      return false;
    }
  }

  private async handleImageMessage(
    session: SessionState,
    socket: SandboxRelaySocket,
    sender: RelaySender,
    message: import("@wssp/sandbox-contracts").DaemonImageMessage,
  ): Promise<void> {
    const images = await import("./image-handlers.js");
    const { imageRelaySpool } = await import("../sandbox-image-relay/index.js");
    const ctx: import("./image-handlers.js").ImageFrameContext = {
      sender,
      spool: imageRelaySpool(),
      reply: (frame) => {
        if (this.isCurrentRegistered(session, socket))
          socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      },
      sendTo: (hostId, epoch, frame) => this.sendImageFrame(hostId, epoch, frame),
      isHostCurrent: (hostId, epoch) => {
        const other = this.socketByHostId.get(hostId);
        const state = other ? this.sessionsBySocket.get(other) : undefined;
        return Boolean(
          state?.registered &&
            state.reconciled &&
            state.imageFeatures?.serve &&
            state.connectionEpoch === epoch,
        );
      },
    };
    switch (message.type) {
      case "image.fetch.request":
        return images.handleImageFetchRequest(ctx, message);
      case "image.cached":
        return images.handleImageCached(ctx, message);
      case "image.evicted":
        return images.handleImageEvicted(ctx, message);
      case "image.fetch.failed":
      case "image.job.failed":
        return images.handleImageFailure(ctx, message);
      case "image.cache.census":
        // A page 0 starts a new run (the daemon also sends a periodic census).
        if (message.page === 0 || !session.imageCensus)
          session.imageCensus = { seen: new Set(), startedAt: null };
        await images.handleImageCensus(ctx, message, session.imageCensus);
        if (message.complete) {
          session.imageCensus = undefined;
          // Census reconciliation retries releases of copies whose access was
          // lost while this host was away (P2-5).
          const { releaseLostForeignImages } = await import("../sandbox-image-relay/scheduler.js");
          await releaseLostForeignImages(ctx.sendTo, sender.hostId).catch(() => 0);
        }
        return;
      case "image.links.request":
        return images.handleImageLinksRequest(ctx, message);
      case "image.part.ack":
        return images.handleImagePartAck(ctx, message);
      case "image.upload.begin":
        return images.handleImageUploadBegin(ctx, message);
      case "image.upload.parts":
        return images.handleImageUploadParts(ctx, message);
      case "image.upload.complete": {
        const { enqueueImageVerify } = await import("@wssp/api/sandbox/image-store/jobs");
        return images.handleImageUploadComplete(ctx, message, enqueueImageVerify);
      }
      case "image.job.resume": {
        await images.handleImageJobResume(ctx, message);
        // A resumed disk upload needs its grant again (§7 Mid-upload).
        if (!session.diskOffload || message.role !== "SOURCE") return;
        const disks = await import("./disk-handlers.js");
        return disks.handleDiskUploadResume(
          {
            sender,
            reply: (frame) => {
              if (this.isCurrentRegistered(session, socket))
                socket.send(encodeServerControlMessage(frame, session.protocolVersion));
            },
          },
          message.transferId,
        );
      }
    }
  }

  /** §7: the disk upload frames, eviction (request,
   * evicted) and discard answers. */
  private async handleDiskMessage(
    session: SessionState,
    socket: SandboxRelaySocket,
    sender: RelaySender,
    message: import("@wssp/sandbox-contracts").DaemonDiskMessage,
  ): Promise<void> {
    const disks = await import("./disk-handlers.js");
    const ctx: import("./disk-handlers.js").DiskFrameContext = {
      sender,
      reply: (frame) => {
        if (this.isCurrentRegistered(session, socket))
          socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      },
    };
    switch (message.type) {
      case "disk.upload.begin":
        return disks.handleDiskUploadBegin(ctx, message);
      case "disk.upload.parts":
        return disks.handleDiskUploadParts(ctx, message);
      case "disk.upload.complete": {
        const { enqueueDiskVerify } = await import("@wssp/api/sandbox/disk-offload/store");
        return disks.handleDiskUploadComplete(ctx, message, enqueueDiskVerify);
      }
      case "disk.offload.failed":
        return disks.handleDiskOffloadFailed(ctx, message);
      case "disk.evict.request":
        return disks.handleDiskEvictRequest(ctx, message);
      case "disk.evicted":
        return disks.handleDiskEvicted(ctx, message);
      case "disk.discarded":
        return disks.handleDiskDiscarded(ctx, message);
      case "disk.offload.released":
        return disks.handleDiskOffloadReleased(ctx, message);
      case "disk.offload.inventory":
        // Bounded per session; the daemon sends at most that many pages.
        session.diskInventoryPages = (session.diskInventoryPages ?? 0) + 1;
        if (session.diskInventoryPages > disks.DISK_INVENTORY_PAGES_PER_SESSION) return;
        return disks.handleDiskOffloadInventory(ctx, message);
    }
  }

  private senderOf(session: SessionState): RelaySender {
    const current = session.authorized;
    return {
      userId: session.identity.userId,
      hostId: session.identity.hostId,
      connectionEpoch: session.connectionEpoch,
      isCurrent: () => current() && this.isCurrentRegistered(session, session.socket),
    };
  }

  private admitFrameSize(socket: SandboxRelaySocket, bytes: number, max: number): boolean {
    if (!this.sessionsBySocket.has(socket)) return false;
    if (bytes <= max) return true;
    // A single oversized frame is a misbehaving peer: a typed verdict.
    this.closeWithProtocolError(socket, "Relay frame exceeds the size limit.");
    this.removeSession(socket);
    return false;
  }

  /** WP2 follow-up: a result or receipt for `sandboxId` fences connected
   * evidence from any observation that may predate it. Only after
   * `reconcile.complete`: the daemon observes only after sending it. Every
   * kind counts (conservative: a command result fences one observation). */
  private noteLifecycleResult(session: SessionState, sandboxId: string) {
    if (session.reconciled) session.observationFence?.noteResult(sandboxId);
  }

  private enqueueSocketWork(
    socket: SandboxRelaySocket,
    bytes: number,
    run: () => Promise<void>,
    output?: QueuedOutput,
  ): void {
    const queue = this.queues.get(socket);
    if (!queue) return;
    if (
      queue.frames + 1 > SANDBOX_RECEIVE_HARD_MAX_FRAMES ||
      queue.bytes + bytes > SANDBOX_RECEIVE_HARD_MAX_BYTES
    ) {
      this.closeWithProtocolError(socket, "Relay frames kept arriving while reads were paused.");
      this.removeSession(socket);
      return;
    }
    queue.frames += 1;
    queue.bytes += bytes;
    queue.work.push(output ? { run, bytes, output } : { run, bytes });
    if (
      !queue.paused &&
      (queue.frames >= SANDBOX_RECEIVE_MAX_FRAMES || queue.bytes >= SANDBOX_RECEIVE_MAX_BYTES)
    ) {
      queue.paused = true;
      socket.pause?.();
    }
    if (queue.draining) return;
    queue.draining = true;
    const drain = async () => {
      try {
        while (this.queues.get(socket) === queue) {
          const item = queue.work.shift();
          if (!item) break;
          const batch = isOutputWork(item) ? takeOutputBatch(item, queue.work) : [item];
          if (batch.length > 1) await this.acceptOutputBatch(socket, batch.filter(isOutputWork));
          else await item.run();
          queue.frames -= batch.length;
          for (const taken of batch) queue.bytes -= taken.bytes;
          if (
            queue.paused &&
            queue.frames <= SANDBOX_RECEIVE_RESUME_FRAMES &&
            queue.bytes <= SANDBOX_RECEIVE_RESUME_BYTES
          ) {
            queue.paused = false;
            if (this.queues.get(socket) === queue) {
              // The liveness clock restarts with the reader (WP4).
              this.notePeerAlive(socket);
              socket.resume?.();
            }
          }
        }
      } catch {
        // Integrity failures are already logged with a stable code. Closing is
        // intentional: replay fails again on reconnect until an operator repairs
        // the corrupt ledger row. Only this host's socket is affected.
        this.closeWithProtocolError(socket, "Relay frame processing failed.");
        this.removeSession(socket);
      } finally {
        queue.draining = false;
      }
    };
    this.frameTail.set(socket, drain());
  }

  /** D11: a held operation must not outlive its bound while the host keeps the
   * session open. Each sweep re-runs settlement with the same names; an
   * operation past the hold (database clock) settles as unknown. Ends once
   * every hold is past its bound, or with the session. */
  private sweepPendingReceipts(
    session: SessionState,
    socket: SandboxRelaySocket,
    sender: RelaySender,
    pending: ReadonlySet<string>,
  ) {
    const until = Date.now() + PENDING_RECEIPT_MAX_HOLD_MS + PENDING_RECEIPT_SWEEP_MS * 2;
    session.pendingReceiptSweep = setInterval(() => {
      if (!this.isCurrentRegistered(session, socket) || Date.now() > until) {
        clearInterval(session.pendingReceiptSweep);
        return;
      }
      void finishHostReconciliation(
        { ...sender, isCurrent: () => this.isCurrentRegistered(session, socket) },
        undefined,
        pending,
      ).catch(() => {
        // Transient: the next sweep, or the next session, settles it.
      });
    }, PENDING_RECEIPT_SWEEP_MS);
    session.pendingReceiptSweep.unref?.();
  }

  private isCurrentRegistered(session: SessionState, socket: SandboxRelaySocket): boolean {
    return (
      this.sessionsBySocket.get(socket) === session &&
      session.registered &&
      this.socketByHostId.get(session.identity.hostId) === socket
    );
  }

  private requireCurrentHello(
    session: SessionState,
    socket: SandboxRelaySocket,
    now: Date,
  ): boolean {
    if (!session.registered || this.socketByHostId.get(session.identity.hostId) !== socket) {
      this.closeWithProtocolError(socket, "Host hello is required before relay traffic.");
      this.removeSession(socket, now);
      return false;
    }
    return true;
  }

  private handleHello(
    session: SessionState,
    message: Extract<DaemonControlMessage, { type: "hello" }>,
    now: Date,
  ) {
    const registration = this.registerHello(session, message, now);
    this.helloRegistrations.add(registration);
    const forget = () => this.helloRegistrations.delete(registration);
    void registration.then(forget, forget);
    return registration;
  }

  private async registerHello(
    session: SessionState,
    message: Extract<DaemonControlMessage, { type: "hello" }>,
    now: Date,
  ) {
    if (session.registered) {
      this.closeWithProtocolError(session.socket, "Host hello is already registered.");
      this.removeSession(session.socket, now);
      return;
    }
    if (message.protocolVersion !== SANDBOX_RELAY_PROTOCOL_VERSION) {
      this.closeWithProtocolError(session.socket, "Unsupported sandbox relay protocol version.");
      this.removeSession(session.socket, now);
      return;
    }

    if (message.daemon.hostId !== session.identity.hostId) {
      this.closeWithProtocolError(
        session.socket,
        "Host identity does not match the websocket credential.",
      );
      this.removeSession(session.socket, now);
      return;
    }

    if (this.sessionsBySocket.get(session.socket) !== session) return;

    let connectionEpoch: number;
    try {
      connectionEpoch = await commitHostHello({
        identity: session.identity,
        message,
        now,
      });
    } catch {
      this.closeWithProtocolError(session.socket, "Host hello registration failed.");
      this.removeSession(session.socket, now);
      return;
    }

    if (this.sessionsBySocket.get(session.socket) !== session) {
      // Removal raced the hello transaction: revoke the epoch it committed.
      // The epoch CAS leaves a newer hello's authority untouched.
      session.connectionEpoch = connectionEpoch;
      const revocation = this.revokeEpoch(session, now);
      this.epochRevocations.add(revocation);
      void revocation.then(() => this.epochRevocations.delete(revocation));
      await revocation;
      return;
    }

    if (!(await this.authorizeSession(session)) || !session.authorized()) {
      session.connectionEpoch = connectionEpoch;
      await this.markHostDisconnected(session, now);
      return;
    }
    const previous = this.socketByHostId.get(session.identity.hostId);
    if (
      previous &&
      (this.sessionsBySocket.get(previous)?.connectionEpoch ?? 0) >= connectionEpoch
    ) {
      this.removeSession(session.socket, now);
      return;
    }
    session.connectionEpoch = connectionEpoch;
    session.protocolVersion = SANDBOX_RELAY_PROTOCOL_VERSION;
    session.terminalCapable = message.daemon.capabilities.terminal === true;
    session.terminalResumeGraceMs = message.daemon.capabilities.terminalResume?.graceMs;
    session.channelKinds = message.daemon.capabilities.channels?.kinds;
    session.imageFeatures = message.daemon.capabilities.image ?? null;
    session.egressRefusedHints = message.daemon.capabilities.egressRefusedHints === true;
    session.templateStartup = message.daemon.capabilities.templateStartup === true;
    session.guestSudo = message.daemon.capabilities.guestSudo === true;
    session.diskOffload = message.daemon.capabilities.diskOffload === true;
    session.tunnelCapable = message.daemon.capabilities.tunnel !== undefined;
    session.tunnelPorts = message.daemon.capabilities.tunnelPorts === true;
    session.credentialFeatures = message.daemon.capabilities.credentials ?? null;
    const outputChunkBytes = negotiatedOutputChunkBytes(
      message.daemon.capabilities.maxOutputChunkBytes,
    );
    session.outputChunkBytes = outputChunkBytes;
    session.quiesceCapable = message.daemon.capabilities.quiesce === true;
    // WP7: set with registration (no await between), so neither a server
    // restart nor a reconnect during a quiesce can dispatch a new command.
    session.quiescing = message.quiescing === true;
    session.observationFence = new ObservationFence();
    session.registered = true;
    clearTimeout(session.unauthenticatedTimer);
    session.lastHeartbeatAt = now;
    this.socketByHostId.set(session.identity.hostId, session.socket);
    if (previous && previous !== session.socket) {
      this.closeWithProtocolError(previous, "Host connection replaced.");
      this.removeSession(previous, now);
    }
    // WP7: a quiescing hello keeps (or starts) the persisted hold; any other
    // hello ends it and gives held template-build steps their time back.
    this.recordQuiesceHold(session, session.quiescing === true);

    this.hostTerminalPolicies.register(
      {
        hostId: session.identity.hostId,
        ownerId: session.identity.userId,
        epoch: session.connectionEpoch,
        socket: session.socket,
        authorized: () => session.authorized() && this.isCurrentRegistered(session, session.socket),
        connected: () =>
          session.socket.readyState === WS_READY_STATE_OPEN &&
          session.reconciled &&
          this.isCurrentRegistered(session, session.socket),
      },
      {
        hostTerminal: message.daemon.capabilities.hostTerminal,
        requireHostTerminalTotp: message.daemon.capabilities.requireHostTerminalTotp,
        policyRevision: message.daemon.capabilities.policyRevision,
      },
    );

    const lowerRequests = await prisma.sandboxHost.findFirst({
      where: {
        id: session.identity.hostId,
        userId: session.identity.userId,
        connectionEpoch: session.connectionEpoch,
      },
      select: { agentHostCommandsVetoedAt: true, hostTerminalVetoedAt: true },
    });
    if (!session.authorized() || !this.isCurrentRegistered(session, session.socket)) return;
    const agent = message.daemon.capabilities;
    this.hostAccess.policies.register(this.hostAccessLink(session), {
      hostCommands: agent.hostCommands === true,
      hostFiles: agent.hostFiles === true,
      ...(agent.hostCommandMaxMs === undefined ? {} : { hostCommandMaxMs: agent.hostCommandMaxMs }),
      agentPolicyRevision: agent.agentPolicyRevision ?? 0,
      lowerPending: !!lowerRequests?.agentHostCommandsVetoedAt,
    });
    if (lowerRequests?.hostTerminalVetoedAt)
      this.hostTerminalPolicies.lower(session.identity.hostId, session.identity.userId);
    session.socket.send(
      encodeServerControlMessage(
        {
          type: "hello.ok",
          id: message.id,
          protocolVersion: session.protocolVersion,
          capabilities: {
            // Optional offers (`channels`) are echoed only when offered.
            ...negotiatedCapabilities(session.protocolVersion, message.daemon.capabilities),
            outputChunkBytes,
            // WP7: echoed only to daemons that offered it (strict parsers).
            ...(session.quiesceCapable ? { quiesce: true as const } : {}),
            // Terminal reattachment is enabled only for a runtime that offers it.
            ...(session.terminalResumeGraceMs === undefined ? {} : { terminalResume: true }),
          },
          supportedProtocolVersions: [SANDBOX_RELAY_PROTOCOL_VERSION],
          hostOwnerId: session.identity.userId,
          connectionEpoch: session.connectionEpoch,
        },
        session.protocolVersion,
      ),
    );

    session.socket.send(
      encodeServerControlMessage(
        {
          type: "journal.key.install",
          connectionEpoch: session.connectionEpoch,
          ...hostJournalKey(session.identity.userId, session.identity.hostId),
        },
        session.protocolVersion,
      ),
    );
    for (const target of ["hostCommands", "hostTerminal"] as const) {
      const pending =
        target === "hostCommands"
          ? lowerRequests?.agentHostCommandsVetoedAt
          : lowerRequests?.hostTerminalVetoedAt;
      const on = target === "hostCommands" ? agent.hostCommands : agent.hostTerminal;
      if (pending && on)
        session.socket.send(
          encodeServerControlMessage(
            {
              type: "host.policy.lower",
              connectionEpoch: session.connectionEpoch,
              requestId: crypto.randomUUID(),
              target,
            },
            session.protocolVersion,
          ),
        );
    }
    const sender: RelaySender = {
      hostId: session.identity.hostId,
      userId: session.identity.userId,
      connectionEpoch: session.connectionEpoch,
      isCurrent: () => this.isCurrentRegistered(session, session.socket),
    };
    // Send the deployment blocklist on every connection.
    session.socket.send(
      encodeServerControlMessage(
        egressBlocklistFrame(deploymentEgressBlocklist()),
        session.protocolVersion,
      ),
    );
    session.availabilityCensus = new AvailabilityCensus(sender, (message) => {
      if (sender.isCurrent?.())
        session.socket.send(encodeServerControlMessage(message, session.protocolVersion));
    });
    const credentials = session.credentialFeatures;
    if (credentials?.sealedReturn && readCredentialsAvailability().keyPresent)
      await offerReturnKey(sender, credentials.returnKeyEpoch, (frame) => {
        if (sender.isCurrent?.())
          session.socket.send(encodeServerControlMessage(frame, session.protocolVersion));
      });
  }
}

export const sandboxRelaySessionManager = new SandboxRelaySessionManager({
  maxSocketsPerHost: env.SANDBOX_MAX_SOCKETS_PER_HOST,
});
registerCredentialFrameSink((hostId, frame) =>
  sandboxRelaySessionManager.sendCredentialFrame(hostId, frame),
);
