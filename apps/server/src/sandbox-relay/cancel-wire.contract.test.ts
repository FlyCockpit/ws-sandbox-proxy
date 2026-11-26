import { bindHostTerminalPolicy } from "@wssp/api/sandbox/host-terminal-policy";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { hostJournalKey, requestDigestMetadata } from "@wssp/api/sandbox/idempotency";

vi.mock("@wssp/api/lib/host-token-access", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wssp/api/lib/host-token-access")>()),
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));

import { type ChildProcess, execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { constants } from "node:fs";
import {
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { serve } from "@hono/node-server";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
} from "@wssp/db/credential-security";
import { canonicalEgressPolicyJson, pinnedAllocationV11Schema } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterEach, expect, it, vi } from "vitest";
import { type WebSocket, WebSocketServer } from "ws";
import { reserveOperationResult } from "../../../../packages/api/src/sandbox/operation-results";
import { cancelOperation } from "../../../../packages/api/src/sandbox/services/sandboxes";
import { mintTerminalTicket } from "../../../../packages/api/src/sandbox/terminal-tickets";
import type { SandboxHostWebsocketIdentity } from "./auth.js";
import { killBrowserClients, upgradeBrowserTerminal } from "./browser-terminal-client-harness.js";
import {
  BROWSER_TERMINAL_ROUTE,
  browserTerminalUpgradeHandler,
  createBrowserTerminalUpgradeMiddleware,
  selectWebSocketSubprotocol,
} from "./browser-terminal-upgrade.js";
import {
  bootstrapHostLease,
  cancelWriterFixture,
  crashWireHost,
  type FakeGuard,
  installWireDelegates,
  journalLockHeld,
  readListedFile,
  releaseWireFixture,
  removeWireDir,
  spawnWireHost,
  startFakeGuard,
  stopEveryWireHost,
  stopWireHost,
  WIRE_EXPIRY_OBSERVATION_MS,
  WIRE_GUEST_TERMINATE_MS,
  WIRE_STORAGE_POLL_MS,
  watchWireHost,
  wireJournalLock,
  pinnedSize as wirePinnedSize,
  wireStore,
  writeBootstrapVm,
  writeWireShim,
} from "./cancel-wire-fixtures.js";
import {
  installFenceTransaction,
  prismaPromise,
  relayStore,
  storedCommandOutput,
} from "./fenced-prisma-harness.js";
import { processSandboxOutboxBatch } from "./outbox-processor.js";
import { encodeServerControlMessage, encodeTerminalDataFrame } from "./protocol.js";
import {
  sandboxRelaySessionManager as manager,
  UNPARSED_CONTROL_FRAME_MESSAGE,
} from "./session-manager.js";
import { createSandboxRelayWebsocketMiddleware } from "./websocket.js";

// The real daemon binds its key to this ephemeral test relay URL. Browser
// Origin assertions continue to use the fixed public app URL below.
vi.mock("@wssp/api/sandbox/idempotency", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@wssp/api/sandbox/idempotency")>();
  return {
    ...actual,
    hostJournalKey: (owner: string, host: string) => {
      if (!testKeyServerBinding) throw new Error("test relay not listening");
      return actual.hostJournalKey(owner, host, testKeyServerBinding);
    },
  };
});

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_SECRET: "service-principal-test",
    // C53: the browser terminal plane's exact Origin allowlist.
    BETTER_AUTH_URL: "https://app.example.test",
    get IMAGE_RELAY_SPOOL_DIR() {
      return join(dir, "image-spool");
    },
    IMAGE_RELAY_SPOOL_BYTES: 1024 * 1024,
  },
}));
vi.mock("../rate-limit.js", () => ({
  hostRelayLimiter: {},
  terminalUpgradeLimiter: {},
  createRateLimiterMiddleware: () => async (_context: unknown, next: () => Promise<void>) => {
    await next();
  },
}));
// C53: Better Auth's cookie lookup (the browser plane's only IO besides Prisma).
const browserAuth = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession: browserAuth.getSession } } }));

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("@wssp/queue", () => ({
  ensureRunnableJob: vi.fn(),
  imageStoreMaintenanceQueue: {},
}));
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
let store = relayStore();
let dir = "";
let host: ChildProcess | undefined;
// The node's egress guard double (debug daemons only: `WSSP_TEST_GUARD_ROOT`).
let guard: FakeGuard | undefined;
let server: WebSocketServer | undefined;
let testKeyServerBinding: string | undefined;
let peer: WebSocket | undefined;
const frames: Record<string, unknown>[] = [];
const receivedFrames = new EventEmitter();
// IncusClient's existing readiness bound is 120 s (client.rs). Setup must let
// that finish under CPU contention, plus 5 s for relay delivery. Command and
// cancellation assertions retain until()'s independent 12 s failure bound.
const BOOTSTRAP_TIMEOUT_MS = 125_000;
// A daemon session (first connect, reconnect after a drop, or restart) re-runs
// the whole host observation (census, capacity, storage pools) before
// `reconcile.complete`; a reconnect adds adoption, the dispatch audit and an
// inventory census. That is about 190 Incus-double invocations, each a fresh
// Python interpreter (~60 ms of CPU each, several times that in wall time
// under CPU contention). Measured on an 8-thread machine at load ~20: up to
// 27 s for a first session and 42 s for a reconnect (18 s after the double
// stopped recompiling itself per call), so until()'s 12 s step bound is not
// a session bound. The relay-chaos suite bounds the same reconnect at 60 s.
const SESSION_TIMEOUT_MS = 60_000;
// The config's testTimeout (scripts/vitest-cancel-wire.config.ts): setup's
// first session and bootstrap create, plus a body of 12 s steps. A case
// that waits for more sessions or VM lifecycle results adds their bounds, so
// until()'s labelled failure always fires before the case budget does.
const CASE_TIMEOUT_MS = 240_000;
// The dispatched command's own budget (`timeoutMs`).
const COMMAND_TIMEOUT_MS = 15_000;
// A command carried across a relay drop must still be inside its budget when
// the daemon adopts or revokes it and when the case releases or cancels it:
// one session bound plus the steps around it. Otherwise its own timeout
// cleanup races the scenario under test (a slow reconnect outlasts 15 s).
const CARRIED_COMMAND_TIMEOUT_MS = 2 * SESSION_TIMEOUT_MS;
// Cases whose double holds the guest terminate helper on a release barrier
// wait for that helper's exec deadline (the fixtures' widened
// WIRE_GUEST_TERMINATE_MS) to end a held attempt: one step past it. Their
// command outlives two held attempts and the steps around them, so its own
// timeout cleanup never races the held cleanup.
const HELD_HELPER_BOUND_MS = WIRE_GUEST_TERMINATE_MS + 12_000;
// C37/C38 after storage heals. While storage was failed, every expiry action
// attempt failed and backed off (apps/cli expiry.rs: 1 s doubling, at most
// 30 s), more of them the slower the machine: one attempt may still be in
// flight and fail, then the backoff runs, then the destroying attempt.
const LOSS_DESTROY_BOUND_MS = 30_000 + 2 * 12_000;
// Then the settlement and the network cleanup report. Expiry evidence whose
// root census failed (its calls time out under load), or whose absent root
// still owes network cleanup, is re-offered once per newer storage
// observation, at most ROOTLESS_RETRIES (8, apps/cli evidence.rs) times
// between them: each round is one storage poll plus one expiry observation
// (the fixtures' widened values).
const SETTLEMENT_BOUND_MS = (8 + 1) * (WIRE_STORAGE_POLL_MS + WIRE_EXPIRY_OBSERVATION_MS);
const HELD_HELPER_COMMAND_TIMEOUT_MS = 2 * HELD_HELPER_BOUND_MS + 30_000;
function caseTimeout({ sessions = 0, lifecycles = 0 }) {
  return CASE_TIMEOUT_MS + sessions * SESSION_TIMEOUT_MS + lifecycles * BOOTSTRAP_TIMEOUT_MS;
}
const CASE_BUDGET = {
  oneSession: caseTimeout({ sessions: 1 }),
  twoSessions: caseTimeout({ sessions: 2 }),
  threeSessions: caseTimeout({ sessions: 3 }),
  fourSessions: caseTimeout({ sessions: 4 }),
  sessionAndCreate: caseTimeout({ sessions: 1, lifecycles: 1 }),
  sessionAndTwoLifecycles: caseTimeout({ sessions: 1, lifecycles: 2 }),
};
function bootstrapResult(operationId: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      receivedFrames.off("frame", onFrame);
    };
    const onFrame = (frame: Record<string, unknown>) => {
      if (frame.type !== "operation.result" || frame.operationId !== operationId) return;
      cleanup();
      resolve(frame);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("bootstrap lease result exceeded Incus readiness and relay deadline"));
    }, BOOTSTRAP_TIMEOUT_MS);
    receivedFrames.on("frame", onFrame);
  });
}
const failures: string[] = [];
const pinnedSize = () => wirePinnedSize(store);
let dropConfirmation = true;
// Relay-drop cases: refuse new daemon connections (a server outage), or answer
// `operation.adopt` like a pre-adoption server (strict parse -> protocol.error).
let refuseConnections = false;
let rejectAdoption = false;
// Live finding B-1: a dispatch frame dies in transit (written, never read).
let loseDispatches = false;
// Report redelivery: the next daemon frame `loseDaemonFrame` matches is read
// but never handled, and its connection dies (the server's queue discards
// it on close); likewise the next server frame `loseServerFrame` matches is
// never written. Each is one-shot. `serverFrames` records what the server
// wrote; `hostEnv` adds daemon environment (debug timing knobs).
let loseDaemonFrame: ((frame: Record<string, unknown>) => boolean) | undefined;
let loseServerFrame: ((frame: Record<string, unknown>) => boolean) | undefined;
const serverFrames: Record<string, unknown>[] = [];
let hostEnv: Record<string, string> = {};

// A case that hit its vitest timeout keeps running in the background; its
// polls must not act on the next case's daemon, store or directory. The
// generation is checked before every predicate call (a predicate may send
// through `peer` synchronously or start a nested `until`, which then captures
// the same generation) and after it, so a stale poll neither acts nor
// reports success.
let caseGeneration = 0;
async function until(check: () => boolean | Promise<boolean>, label: string, boundMs = 12000) {
  const generation = caseGeneration;
  const live = () => {
    if (generation !== caseGeneration) throw new Error(`${label}: the case already ended`);
  };
  const deadline = Date.now() + boundMs;
  for (;;) {
    live();
    const done = await check();
    live();
    if (done) return;
    if (Date.now() > deadline)
      throw new Error(`${label}: ${failures.join("\n")}; frames=${JSON.stringify(frames)}`);
    await delay(5);
  }
}
async function exists(name: string) {
  return readFile(join(dir, name)).then(
    () => true,
    () => false,
  );
}
async function receipt() {
  const paths = await readdir(join(dir, "data"), { recursive: true });
  const path = paths.find((p) => p.endsWith("receipts/op-1.json"));
  if (!path) return undefined;
  // Retired between the listing and the read: no receipt (readListedFile).
  const text = await readListedFile(join(dir, "data", path));
  return text === undefined ? undefined : JSON.parse(text).receipt;
}
async function startHost() {
  const address = server!.address();
  if (typeof address !== "object" || !address) throw new Error("missing listener");
  guard ??= await startFakeGuard(join(dir, "guard-root"), join(dir, "networks"));
  host = await spawnWireHost({
    dir,
    serverUrl: `ws://127.0.0.1:${address.port}`,
    args: (await exists("one-slot")) ? ["--sandbox-vcpu-budget", "1"] : [],
    // Debug-build-only hold (apps/cli supervisor.rs): a create waits in
    // Effect, before any runtime call, until this file exists.
    env: {
      ...hostEnv,
      ...((await exists("hold-create-effect"))
        ? { WSSP_TEST_BARRIER_CREATE_EFFECT: join(dir, "release-create-effect") }
        : {}),
    },
  });
  host.stderr!.on("data", (chunk) => failures.push(String(chunk)));
  host.on("error", (error) => failures.push(String(error)));
}
async function stopHost() {
  const child = host;
  host = undefined;
  await stopWireHost(child);
}
async function crashHost() {
  if (await crashWireHost(host, dir)) host = undefined;
}
const execFileAsync = promisify(execFile);
async function armHostLease(
  egress?: {
    policy: { domains: string[]; cidrs: string[] };
    hash: string;
  },
  guestRoot = false,
) {
  await bootstrapHostLease(
    { dir, store, send: (frame) => peer!.send(frame), result: bootstrapResult, until },
    egress,
    guestRoot,
  );
  // Keep setup-only frames out of the command's existing wire assertions.
  frames.splice(0, frames.length, ...frames.filter((f) => f.operationId !== "lease-bootstrap"));
}
async function setup(
  mode: string,
  holdWrapper = false,
  commandEnv?: Array<[string, string]>,
  beforeStart?: () => Promise<void>,
  commandTimeoutMs = COMMAND_TIMEOUT_MS,
) {
  vi.clearAllMocks();
  refuseConnections = false;
  rejectAdoption = false;
  loseDispatches = false;
  loseDaemonFrame = undefined;
  loseServerFrame = undefined;
  serverFrames.length = 0;
  hostEnv = {};
  frames.length = 0;
  failures.length = 0;
  dropConfirmation = true;
  // Each case's operation is seeded as acceptance writes it for its kind
  // (result version and process identity included), never as a legacy row.
  const create =
    mode === "readiness-create" ||
    mode === "readiness-adopt-create" ||
    mode === "readiness-create-root" ||
    mode === "readiness-create-disk";
  store = wireStore(
    mode === "stat-missing"
      ? "STAT_PATH"
      : mode.startsWith("readiness-")
        ? create
          ? "CREATE_SANDBOX"
          : "RECONNECT_SANDBOX"
        : "RUN_COMMAND",
  );
  dir = await mkdtemp(join(tmpdir(), "wssp-c10-wire-"));
  if (mode === "enforcement-loss") await writeFile(join(dir, "one-slot"), "");
  if (mode === "readiness-adopt-create") await writeFile(join(dir, "hold-create-effect"), "");
  await writeWireShim(dir, mode);
  await writeFile(
    join(dir, "writer.py"),
    (commandEnv ? 'import os\nprint(os.environ.get("KEYED_ENV", "missing"), flush=True)\n' : "") +
      cancelWriterFixture,
  );
  if (holdWrapper) await writeFile(join(dir, "hold-wrapper"), "");
  if (!mode.startsWith("readiness-")) await writeBootstrapVm(dir);
  Object.assign(store.outbox.get("evt-1")!.payload, {
    dispatchAttempt: 0,
    idempotencyKey: "key-1",
    argv: ["python3", join(dir, "writer.py"), dir],
    timeoutMs: commandTimeoutMs,
    incusFingerprint: "sha256:" + "abcdef0123456789".repeat(4),
    ...(commandEnv ? { env: commandEnv } : {}),
  });
  if (mode === "stat-missing") {
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "file.stat",
      path: join(dir, "missing"),
    });
  }
  if (mode.startsWith("readiness-")) {
    const kind = create ? "sandbox.create" : "sandbox.reconnect";
    store.outbox.get("evt-1")!.eventType = create
      ? "sandbox.create_requested"
      : "sandbox.reconnect_requested";
    const fp = "sha256:" + "abcdef0123456789".repeat(4);
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: create ? "PROVISIONING" : "STOPPED",
      liveResourcesHeld: true,
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = vmLiveMemoryChargeMiB(1024);
    store.hosts.get("host-1")!.vcpuReserved = 1;
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind,
      ...pinnedSize(),
      templateDigest: fp,
      incusFingerprint: fp,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      egressPolicy: { domains: [], cidrs: [] },
      // The host (C35) verifies the recorded hash against the canonical
      // normalized policy text before any host mutation.
      egressPolicyHash: createHash("sha256")
        .update(canonicalEgressPolicyJson({ domains: [], cidrs: [] }), "utf8")
        .digest("hex"),
    });
  }
  installWireDelegates(prisma, store);
  let imageCensusAcknowledged = false;
  // A content kind is versioned by its result hold, reserved at acceptance.
  if (mode === "stat-missing")
    await prisma.$transaction((tx) =>
      reserveOperationResult(tx, { ownerId: "user-1", operationId: "op-1" }),
    );
  server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  server.on("connection", (socket) => {
    if (refuseConnections) {
      socket.terminate();
      return;
    }
    peer = socket;
    // One case injects a deferred expiry batch before the daemon observes a
    // loss. Reserve its sequence number and translate later batches and acks
    // together, so both peers retain their current protocol ordering.
    let injectedExpiryBatch: number | undefined;
    const adapter = {
      get readyState() {
        return socket.readyState;
      },
      get bufferedAmount() {
        return socket.bufferedAmount;
      },
      send(data: string | ArrayBuffer | Uint8Array) {
        if (typeof data === "string" && JSON.parse(data).type === "image.cache.census.ack")
          imageCensusAcknowledged = true;
        if (typeof data === "string" && injectedExpiryBatch !== undefined) {
          const frame = JSON.parse(data);
          if (frame.type === "sandbox.expiry_status.ack") {
            if (frame.batch === injectedExpiryBatch) return;
            data = JSON.stringify({ ...frame, batch: frame.batch - 1 });
          }
        }
        if (
          typeof data === "string" &&
          dropConfirmation &&
          JSON.parse(data).type === "receipt.confirmed"
        )
          return;
        if (
          typeof data === "string" &&
          loseDispatches &&
          JSON.parse(data).type === "operation.dispatch"
        )
          return;
        if (typeof data === "string") {
          const frame = JSON.parse(data);
          if (loseServerFrame?.(frame)) {
            loseServerFrame = undefined;
            socket.terminate();
            return;
          }
          serverFrames.push(frame);
        }
        socket.send(data);
      },
      close(code?: number, reason?: string) {
        socket.close(code, reason);
      },
    };
    manager.acceptAuthenticatedSocket({
      socket: adapter,
      identity: {
        hostId: "host-1",
        userId: "user-1",
        tokenId: "token-1",
        credentialKind: "hostToken" as const,
        expiresAt: null,
      },
    });
    socket.on("message", (data, binary, injectedExpiry = false) => {
      if (binary) {
        const bytes = Array.isArray(data)
          ? Buffer.concat(data)
          : data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : data;
        manager.handleBinaryFrame(adapter, Uint8Array.from(bytes).buffer);
        return;
      }
      const text = data.toString();
      const frame = JSON.parse(text);
      if (frame.type === "sandbox.expiry_status") {
        if (injectedExpiry) injectedExpiryBatch = frame.batch;
        else if (injectedExpiryBatch !== undefined) frame.batch += 1;
      }
      frames.push(frame);
      receivedFrames.emit("frame", frame);
      if (loseDaemonFrame?.(frame)) {
        loseDaemonFrame = undefined;
        socket.terminate();
        return;
      }
      if (rejectAdoption && frame.type === "operation.adopt") {
        socket.send(
          JSON.stringify({
            type: "protocol.error",
            failure: "protocol_error",
            message: UNPARSED_CONTROL_FRAME_MESSAGE,
          }),
        );
        socket.close(1008, "protocol_error");
        return;
      }
      // This setup-only operation is owned and confirmed by armHostLease.
      if (
        frame.operationId === "lease-bootstrap" ||
        String(frame.operationId).startsWith("capacity-")
      )
        return;
      manager.handleTextFrame(adapter, JSON.stringify(frame));
    });
    socket.on("close", () => manager.removeSession(adapter));
  });
  await once(server, "listening");
  const keyAddress = server.address();
  if (!keyAddress || typeof keyAddress === "string") throw new Error("test relay not listening");
  testKeyServerBinding = `ws://127.0.0.1:${keyAddress.port}/ws/sandbox-host`;
  // The fresh host holds no instance yet; a placed READY/STOPPED row would be
  // converged to `instance_missing` by its first complete census.
  const seeded = store.sandboxes.get("sbx-1")!;
  const seededState = seeded.state;
  seeded.state = "PROVISIONING";
  await beforeStart?.();
  await startHost();
  await until(
    () => frames.some((f) => f.type === "reconcile.complete"),
    "initial reconciliation",
    SESSION_TIMEOUT_MS,
  );
  await until(() => manager.isHostConnected("host-1"), "host registered");
  await until(
    () => [...store.credentialCensuses.values()].some((row) => row.hostId === "host-1"),
    "credential census committed",
  );
  await until(() => imageCensusAcknowledged, "image cache census committed");
  // A fresh guard's deployment source is unknown until the daemon relays the
  // server's `egress.blocklist` on its next monitor tick; until then the
  // daemon refuses creates and reports guardOk:false, so the server's create
  // gate (`createEgressAdmissible`) waits for the healthy `host.egress-state`.
  await until(() => (guard?.pushes() ?? 0) > 0, "deployment blocklist pushed to the guard");
  await until(
    () => store.hosts.get("host-1")?.daemonEgressGuardOk === true,
    "healthy egress guard lease reported",
  );
  // No server placement is performed: these cases use the seeded boot placement.
  // Hello has committed the shim's bounded capacity before launch dispatch.
  expect(store.hosts.get("host-1")).toMatchObject({
    daemonMemoryBudgetMiB: expect.any(Number),
    daemonMaxCpuCount: expect.any(Number),
  });
  store.sandboxes.get("sbx-1")!.state = seededState;
  if (mode.startsWith("readiness-")) {
    // These tests exercise runtime readiness, not egress. The current CLI
    // advertises egressPolicy:false (C34), and the launch dispatch gate
    // refuses a downgraded capability, so the harness simulates a capable
    // (C35+) daemon after its hello committed.
    store.hosts.get("host-1")!.egressEnforcement = true;
    if (mode === "readiness-adopt-create") {
      // The create readies normally; the relay drop is the scenario.
    } else if (mode === "readiness-create") {
      // The very first start's identity readiness fails.
      await writeFile(join(dir, "fail-readiness"), "");
    } else if (mode === "readiness-create-disk") {
      // Identity readiness passes; the guest root never grew to the disk.
      await writeFile(join(dir, "root-verdict"), "ungrown");
    } else if (mode === "readiness-create-root") {
      // Identity readiness passes; the create-time hygiene audit finds a
      // static root grant (guestSudo off, guestRoot false).
      await writeFile(join(dir, "sudo-verdict-revoke-audit"), "root_granted sudo_ws group_docker");
    } else {
      // C37 R1: reconnect verifies the recorded enforcement but never
      // re-applies it, so the scenario first provisions enforcement with a
      // successful create bootstrap (the readiness marker is not yet armed),
      // then arms the readiness failure and stops the VM out of band: the
      // reconnect under test is a cold resume of a STOPPED sandbox whose
      // readiness fails.
      const policy = { domains: [], cidrs: [] };
      await armHostLease({
        policy,
        hash: createHash("sha256").update(canonicalEgressPolicyJson(policy), "utf8").digest("hex"),
      });
      await writeFile(join(dir, "fail-readiness"), "");
      await execFileAsync(join(dir, "incus"), ["stop", "wssp-sbx-sbx-1"]);
    }
  } else await armHostLease(undefined, mode === "guest-root");
  if (mode === "enforcement-loss" || mode.startsWith("terminal-")) return;
  await processSandboxOutboxBatch();
  await until(() => store.operations.get("op-1")!.acceptedAttempt === 1, "host accepted");
}

/** Strip the wrapper's private PID banner and its fixed-position start record (slice 4a). */
function afterWrapperHead(stderr: string): string {
  const rest = stderr.slice(stderr.indexOf("\n") + 1);
  return rest.startsWith("WSSP_READY ") ? rest.slice(rest.indexOf("\n") + 1) : rest;
}

/** The versioned (1.0) host result of op-1's command: its exit code under
 * the process identity acceptance bound, plus the journaled byte count. */
function commandResult(exitCode: number | null) {
  const process = expect.objectContaining({
    processId: store.operations.get("op-1")!.processId,
    sandboxId: "sbx-1",
  });
  return {
    version: 1,
    outputBytes: expect.any(Number),
    birth: expect.objectContaining({ type: "process.started", operationId: "op-1" }),
    payload: { type: "command", exitCode, process },
  };
}

/** op-1 settled its command's exit under the bound process identity: the
 * versioned scalar evidence and the row's result summary agree. */
function expectStoredCommandExit(exitCode: number) {
  const op = store.operations.get("op-1")!;
  expect(op.scalarResult).toMatchObject(commandResult(exitCode).payload);
  expect(op.result).toMatchObject({ exitCode, outputBytes: expect.any(Number) });
}

/** op-1's versioned host and stored results after an uncertain natural
 * entry: a started command keeps its bound identity and null exit; a wrapper
 * setup failure never started one, so it carries only the uncertainty. */
function uncertainEntryResults(kind: string) {
  return kind === "exit"
    ? {
        host: commandResult(null),
        stored: { exitCode: null, pid: expect.any(Number), outputBytes: expect.any(Number) },
      }
    : {
        host: {
          version: 1,
          outputBytes: expect.any(Number),
          birth: null,
          payload: null,
          failure: { resource: "command", effect: "unknown" },
        },
        stored: {},
      };
}

function receivedOutput() {
  const output = storedCommandOutput(store, "op-1");
  return {
    stdout: output?.stdout.toString("utf8") ?? "",
    stderr: output?.stderr.toString("utf8") ?? "",
  };
}

afterEach(async () => {
  caseGeneration += 1;
  try {
    if (dir) await releaseWireFixture(dir);
  } finally {
    try {
      await stopHost();
    } finally {
      // Any daemon the case spawned and did not stop (watchdog backstop).
      await stopEveryWireHost();
      await manager.dispose();
      server?.close();
      guard?.server.close();
      guard = undefined;
      if (dir) await removeWireDir(dir);
      dir = "";
    }
  }
});

/** Abruptly drop the daemon's relay socket (no close handshake) and wait for
 * the real daemon to reconnect, adopt and finish reconciliation. */
async function dropAndReconnect() {
  const epoch = store.hosts.get("host-1")!.connectionEpoch;
  const reconciled = frames.filter((f) => f.type === "reconcile.complete").length;
  peer?.terminate();
  await until(
    () =>
      frames.filter((f) => f.type === "reconcile.complete").length > reconciled &&
      manager.isHostConnected("host-1") &&
      store.hosts.get("host-1")!.connectionEpoch > epoch,
    "daemon reconnected and reconciled",
    SESSION_TIMEOUT_MS,
  );
}

it("relay drop: a running command is adopted on reconnect and finishes SUCCEEDED", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("normal", false, undefined, undefined, CARRIED_COMMAND_TIMEOUT_MS);
  await until(() => exists("armed"), "writer armed");
  const before = store.operations.get("op-1")!.dispatchedConnectionEpoch;
  await dropAndReconnect();
  // Carried with its stdin stream open (B1): the host reports its next sequence.
  expect(
    frames.find((f) => f.type === "operation.adopt" && f.operationId === "op-1"),
  ).toMatchObject({ phase: "effect", stdinNextSequence: expect.any(Number) });
  const adopted = store.operations.get("op-1")!;
  expect(adopted.state).not.toBe("UNKNOWN_OUTCOME");
  expect(adopted.dispatchedConnectionEpoch).toBeGreaterThan(before!);
  await writeFile(join(dir, "release-natural"), "");
  await until(() => store.operations.get("op-1")!.state === "SUCCEEDED", "adopted result");
  expectStoredCommandExit(0);
  expect(
    [...store.operations.values()].some((op) => op.kind === "KILL_SANDBOX"),
    "no teardown is enqueued",
  ).toBe(false);
  expect(await exists("term-observed")).toBe(false);
});

it("relay drop: a create held in Effect is adopted on reconnect and finishes ready", {
  timeout: CASE_BUDGET.sessionAndCreate,
}, async () => {
  await setup("readiness-adopt-create");
  // The create journaled Effect and waits at the barrier, before any runtime call.
  await until(
    async () => (await receipt())?.phase === "effect",
    "create reached Effect and is held",
  );
  await dropAndReconnect();
  expect(
    frames.find((f) => f.type === "operation.adopt" && f.operationId === "op-1"),
  ).toMatchObject({ kind: "sandbox.create", phase: "effect", stdinNextSequence: null });
  expect(store.operations.get("op-1")!.state).not.toBe("UNKNOWN_OUTCOME");
  await writeFile(join(dir, "release-create-effect"), "");
  await until(
    () => store.operations.get("op-1")!.state === "SUCCEEDED",
    "adopted create result",
    BOOTSTRAP_TIMEOUT_MS,
  );
  expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
  expect(
    [...store.operations.values()].some((op) => op.kind === "KILL_SANDBOX"),
    "no teardown is enqueued",
  ).toBe(false);
});

it("relay drop: a dispatch lost in transit is proved never received and runs, never UNKNOWN", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  // "terminal-" modes stop setup before the command dispatch.
  await setup("terminal-lost-dispatch");
  const states: string[] = [];
  const watch = setInterval(() => states.push(store.operations.get("op-1")!.state), 2);
  try {
    loseDispatches = true;
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")).toMatchObject({
      state: "DISPATCHED",
      dispatchAttempt: 1,
    });
    loseDispatches = false;
    await dropAndReconnect();
    expect(
      frames.find((f) => f.type === "dispatch.audit.result"),
      "the host proved it never received attempt 1",
    ).toMatchObject({
      entries: [{ operationId: "op-1", attempt: 1, received: false }],
    });
    expect(store.operations.get("op-1")!.state).toBe("QUEUED");
    await processSandboxOutboxBatch();
    await until(() => store.operations.get("op-1")!.acceptedAttempt === 2, "attempt 2 accepted");
    await until(() => exists("armed"), "the command really runs");
    await writeFile(join(dir, "release-natural"), "");
    await until(() => store.operations.get("op-1")!.state === "SUCCEEDED", "result");
  } finally {
    clearInterval(watch);
  }
  expect(states).not.toContain("UNKNOWN_OUTCOME");
});

it("relay drop: a cancel requested while the host is away is delivered after adoption", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("normal", false, undefined, undefined, CARRIED_COMMAND_TIMEOUT_MS);
  await until(() => exists("armed"), "writer armed");
  const epoch = store.hosts.get("host-1")!.connectionEpoch;
  const reconciled = frames.filter((f) => f.type === "reconcile.complete").length;
  // The server stays unreachable until the cancellation is durable.
  refuseConnections = true;
  peer?.terminate();
  await until(
    () => store.hosts.get("host-1")!.connectionEpoch > epoch,
    "disconnect revoked the old epoch",
  );
  await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
  expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
  const cancel = () =>
    [...store.outbox.values()].find(
      (e) => e.payload.kind === "operation.cancel" && e.payload.operationId === "op-1",
    )!;
  const staleEpoch = cancel().payload.connectionEpoch;
  refuseConnections = false;
  await until(
    () =>
      frames.filter((f) => f.type === "reconcile.complete").length > reconciled &&
      manager.isHostConnected("host-1"),
    "daemon reconnected and reconciled",
    SESSION_TIMEOUT_MS,
  );
  expect(frames.some((f) => f.type === "operation.adopt" && f.operationId === "op-1")).toBe(true);
  const adopted = store.operations.get("op-1")!;
  expect(adopted.state).toBe("CANCEL_REQUESTED");
  expect(cancel().payload.connectionEpoch).toBe(adopted.dispatchedConnectionEpoch);
  expect(cancel().payload.connectionEpoch).not.toBe(staleEpoch);
  await processSandboxOutboxBatch();
  await until(() => exists("cleanup-entered"), "cancel reached the adopted command");
  await until(
    () => store.operations.get("op-1")!.state === "CANCELLED",
    "cancel applied after adoption",
  );
  expect(await exists("term-observed")).toBe(true);
});

it("relay drop: a server that rejects operation.adopt degrades to today's revoke", {
  timeout: CASE_BUDGET.twoSessions,
}, async () => {
  await setup("normal", false, undefined, undefined, CARRIED_COMMAND_TIMEOUT_MS);
  await until(() => exists("armed"), "writer armed");
  rejectAdoption = true;
  const reconciled = frames.filter((f) => f.type === "reconcile.complete").length;
  peer?.terminate();
  // The strict server answers protocol.error: a verdict, so the daemon revokes
  // its carried work and reconnects once more with nothing to adopt.
  await until(
    () =>
      frames.filter((f) => f.type === "reconcile.complete").length > reconciled &&
      manager.isHostConnected("host-1"),
    "daemon reconnected after the refusal",
    // Two reconnects, each re-running the shim's startup census.
    2 * SESSION_TIMEOUT_MS,
  );
  expect(frames.filter((f) => f.type === "operation.adopt")).toHaveLength(1);
  await until(
    () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
    "revoked work is uncertain, exactly as before adoption existed",
  );
  // The host revoked its local execution: the attempt ends uncertain there too.
  await until(
    async () => (await receipt())?.state === "unknown_outcome",
    "the revoked attempt's journal records an uncertain outcome",
  );
  expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
});

async function retireExecs(): Promise<string[]> {
  return readFile(join(dir, "retire-execs"), "utf8").then(
    (text) => text.trim().split("\n"),
    () => [],
  );
}

it.each(["killed", "not-due", "unscoped"])(
  "Plan §10 wire %s: an UNKNOWN command whose guest group outlived its revoked owner meets the root retire helper",
  async (verdict) => {
    await setup("normal", false, undefined, undefined, CARRIED_COMMAND_TIMEOUT_MS);
    await until(() => exists("armed"), "writer armed");
    // A strict server refuses adoption: the daemon revokes its carried
    // work, the attempt ends UNKNOWN, and the guest group keeps running.
    rejectAdoption = true;
    const reconciled = frames.filter((f) => f.type === "reconcile.complete").length;
    peer?.terminate();
    await until(
      () =>
        frames.filter((f) => f.type === "reconcile.complete").length > reconciled &&
        manager.isHostConnected("host-1"),
      "daemon reconnected after the refusal",
      // Two reconnects, as above.
      2 * SESSION_TIMEOUT_MS,
    );
    await until(
      () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
      "revoked work is uncertain",
    );
    await until(async () => (await receipt())?.state === "unknown_outcome", "journal UNKNOWN");
    // Decision 2: the start was journaled when it bound.
    expect((await receipt()).ext?.commandStart).toMatchObject({
      uid: 1000,
      budgetMs: CARRIED_COMMAND_TIMEOUT_MS,
    });
    const pgid = Number(await readFile(join(dir, "guest-pgid"), "utf8"));
    expect(() => process.kill(-pgid, 0)).not.toThrow();
    expect(await retireExecs()).toEqual([]);
    if (verdict === "not-due") await writeFile(join(dir, "retire-not-due"), "");
    if (verdict === "unscoped") await writeFile(join(dir, "retire-unscoped"), "");
    // The next replay is answered `retireCommand` (the row is UNKNOWN).
    rejectAdoption = false;
    dropConfirmation = false;
    await dropAndReconnect();
    await until(async () => (await retireExecs()).length > 0, "root retire helper ran", 20_000);
    expect((await retireExecs())[0]).toBe(
      `kill-deadline wssp-cmd-op-1-1-1.scope ${CARRIED_COMMAND_TIMEOUT_MS}`,
    );
    if (verdict !== "killed") {
      // Kept: the group lives and the receipt stays.
      await delay(1500);
      expect(await receipt()).toBeDefined();
      expect(() => process.kill(-pgid, 0)).not.toThrow();
      expect(await exists("retire-killed")).toBe(false);
    }
    if (verdict === "unscoped") {
      // Today's reboot arm (same boot): unproven and final for the session.
      expect(await retireExecs()).toHaveLength(1);
    } else {
      if (verdict === "not-due") {
        await rm(join(dir, "retire-not-due"));
      }
      // A not-due command is re-proved inside the session (no reconnect).
      const epoch = store.hosts.get("host-1")!.connectionEpoch;
      await until(async () => !(await receipt()), "the receipt retired after the kill", 30_000);
      expect(store.hosts.get("host-1")!.connectionEpoch).toBe(epoch);
      expect(await readFile(join(dir, "retire-killed"), "utf8")).toBe("kill-deadline");
      await until(() => {
        try {
          process.kill(-pgid, 0);
          return false;
        } catch {
          return true;
        }
      }, "the whole guest group is dead");
      if (verdict === "not-due") expect((await retireExecs()).length).toBeGreaterThan(1);
    }
    // The server row stays UNKNOWN and no sandbox stop was queued.
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(
      [...store.outbox.values()].some((e) => String(e.payload.kind).startsWith("sandbox.stop")),
    ).toBe(false);
  },
  CASE_BUDGET.threeSessions,
);

it("harness tears down a daemon that is reconnecting without a WebSocket peer", async () => {
  await setup("normal");
  const child = host!;
  peer?.terminate();
  peer = undefined;
  await stopHost();
  expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
  expect(host).toBeUndefined();
});

it.each([
  { staleInverse: false, failedStorage: false, midProbeRenewal: false, freshHealthy: false },
  { staleInverse: true, failedStorage: false, midProbeRenewal: false, freshHealthy: false },
  { staleInverse: false, failedStorage: true, midProbeRenewal: false, freshHealthy: false },
  { staleInverse: true, failedStorage: true, midProbeRenewal: false, freshHealthy: false },
  { staleInverse: false, failedStorage: true, midProbeRenewal: true, freshHealthy: false },
  { staleInverse: false, failedStorage: true, midProbeRenewal: true, freshHealthy: true },
  {
    staleInverse: false,
    failedStorage: true,
    midProbeRenewal: false,
    freshHealthy: false,
    periodic: true,
  },
  {
    staleInverse: false,
    failedStorage: true,
    midProbeRenewal: true,
    freshHealthy: false,
    periodic: true,
  },
  {
    staleInverse: false,
    failedStorage: true,
    midProbeRenewal: true,
    freshHealthy: true,
    periodic: true,
  },
])(
  "C37/C38 connected loss settles server and one-slot daemon capacity $staleInverse / failed storage $failedStorage / mid-probe renewal $midProbeRenewal / fresh healthy $freshHealthy / periodic $periodic",
  async ({ staleInverse, failedStorage, midProbeRenewal, freshHealthy, periodic }) => {
    await setup("enforcement-loss");
    const fp = `sha256:${"abcdef0123456789".repeat(4)}`;
    const lease = store.outbox.get("evt-1")!.payload.lease as {
      revision: number;
      deadlineUnixMs: number;
      action: "stop";
      expiryPolicy: "retry-force-60s";
    };
    const row = store.sandboxes.get("sbx-1")!;
    Object.assign(row, {
      state: "READY",
      liveResourcesHeld: true,
      leaseRevisionEffective: 1,
      leaseExpiresAtEffective: new Date(lease.deadlineUnixMs),
      leaseExpireActionEffective: "STOP",
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = vmLiveMemoryChargeMiB(1024);
    store.hosts.get("host-1")!.vcpuReserved = 1;
    store.operations.get("op-1")!.state = "SUCCEEDED";
    const epoch = store.hosts.get("host-1")!.connectionEpoch;
    async function allocation(id: string, sandboxId: string, generation = 1, revision = 1) {
      peer!.send(
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.dispatch",
          digestScheme: requestDigestMetadata().requestDigestScheme,
          digestKeyId: requestDigestMetadata().requestDigestKeyId,
          operationId: id,
          sandboxId,
          kind: sandboxId === "sbx-1" ? "sandbox.reconnect" : "sandbox.create",
          ...pinnedSize(),
          generation,
          attempt: 1,
          idempotencyKey: id,
          bodyHash: "c".repeat(64),
          lease: { ...lease, revision },
          incusFingerprint: fp,
          templateDigest: fp,
          egressPolicy: { domains: [], cidrs: [] },
          egressPolicyHash: createHash("sha256")
            .update(canonicalEgressPolicyJson({ domains: [], cidrs: [] }))
            .digest("hex"),
          architecture: "x86_64",
        }),
      );
      await until(
        () => frames.some((f) => f.type === "operation.result" && f.operationId === id),
        `allocation ${id}`,
        // A create/reconnect result (a refusal answers at once): bounded like
        // the bootstrap create.
        BOOTSTRAP_TIMEOUT_MS,
      );
      return frames.find((f) => f.type === "operation.result" && f.operationId === id)!;
    }
    const probe = () =>
      manager.probeSandbox({
        ownerId: "user-1",
        hostId: "host-1",
        sandboxId: "sbx-1",
        generation: Number(store.sandboxes.get("sbx-1")!.generation),
        incusFingerprint: fp,
        architecture: "x86_64",
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/user",
        guestShell: "/bin/bash",
      });
    expect((await allocation("capacity-before", "sbx-new")).error).toMatchObject({
      code: "host_capacity",
      reason: "vcpu",
    });
    expect(await probe()).toBe("guest_ready");
    if (staleInverse) {
      expect(await allocation("capacity-warm", "sbx-1", 2, 2)).toMatchObject({
        state: "succeeded",
      });
      Object.assign(store.sandboxes.get("sbx-1")!, {
        generation: 2,
        leaseRevision: 2,
        leaseRevisionEffective: 2,
      });
      store.operations.set("warm-proof", {
        ...store.operations.get("op-1")!,
        id: "warm-proof",
        kind: "RECONNECT_SANDBOX",
        generation: 2,
        state: "SUCCEEDED",
        dispatchedHostId: "host-1",
        dispatchedConnectionEpoch: epoch,
      });
      // Deferred generation-1 completion arriving over the same authenticated
      // socket cannot settle the current server row. The transaction barrier
      // proves it was processed before asserting the inverse.
      let processed = false;
      store.barriers.afterCommit = async () => {
        processed = true;
      };
      expect(frames.filter((f) => f.type === "sandbox.expiry_status")).toHaveLength(0);
      peer!.emit(
        "message",
        Buffer.from(
          JSON.stringify({
            type: "sandbox.expiry_status",
            batch: 1,
            observation: 1,
            entries: [
              {
                sandboxOwnerId: "user-1",
                root: null,
                sandboxId: "sbx-1",
                state: "absent",
                lease: {
                  generation: 1,
                  lease,
                  expired: true,
                  expiryComplete: true,
                  timerExpired: false,
                },
              },
            ],
          }),
        ),
        false,
        true,
      );
      await until(() => processed, "stale lifecycle completion processed");
      store.barriers.afterCommit = undefined;
      expect(store.sandboxes.get("sbx-1")).toMatchObject({
        state: "READY",
        generation: 2,
        liveResourcesHeld: true,
      });
      expect(store.hosts.get("host-1")!.liveCount).toBe(1);
      expect((await allocation("capacity-stale-control", "sbx-new")).error).toMatchObject({
        code: "host_capacity",
      });
      expect(await exists("deleted")).toBe(false);
    }
    const probesBeforeDrift = frames.filter((f) => f.type === "sandbox.probe.result").length;
    // C37 observes through a live probe. C38's additional case issues NO
    // post-drift probe: the service-owned periodic reconciler must detect it.
    const acl = (await readdir(join(dir, "acls"))).find((p) => p.endsWith(".json"))!;
    const aclPath = join(dir, "acls", acl);
    const healthyAcl = await readFile(aclPath, "utf8");
    const installAcl = async (body: string) => {
      await writeFile(`${aclPath}.next`, body);
      await rename(`${aclPath}.next`, aclPath);
    };
    const config = JSON.parse(await readFile(aclPath, "utf8"));
    config.egress.push({ action: "allow", state: "enabled", destination: "0.0.0.0/0" });
    const runtimeDir = join(
      dir,
      "data",
      "relay",
      createHash("sha256").update("host-1").digest("hex"),
      "runtime",
    );
    if (!periodic) {
      // Live-probe cases are about the probe's own detection. Hold the
      // independent periodic inspector out of the drift window: the sweep's
      // acknowledgement proves no inspection is in flight (sweeps are
      // serialized) and none starts until the probe has returned. The
      // enforcement-loss drain keeps running throughout. Engage it BEFORE any
      // storage fault or fixture barrier: an in-flight inspection could
      // otherwise consume the probe's ACL-read barrier.
      await writeFile(join(dir, "hold-policy-reconciler"), "");
      await until(() => exists("hold-policy-reconciler.held"), "periodic inspection held");
    }
    const journals = ["enforcement-losses", "network-cleanups"];
    if (failedStorage) {
      // Fail BOTH loss recording and teardown bookkeeping. The restrictive
      // halt must still happen now, but deletion/completion must wait.
      for (const name of journals) {
        const path = join(runtimeDir, name);
        await mkdir(path, { recursive: true });
        await rename(path, `${path}-held`);
        await writeFile(path, "storage unavailable");
      }
    }
    if (midProbeRenewal) await writeFile(join(dir, "barrier-acl-read"), "");
    if (!freshHealthy) await writeFile(join(dir, "release-stop"), "");
    // Install the storage fault and observation barrier BEFORE drift becomes
    // visible to the autonomous poller (not just before a manual probe).
    await installAcl(JSON.stringify(config));
    const observing = periodic
      ? until(async () => {
          if (!(await exists("stopped"))) return false;
          try {
            const state = JSON.parse(
              await readFile(join(runtimeDir, "policy-reconciler", "state.json"), "utf8"),
            );
            // A stale Prepare can stop BEFORE it captures/rechecks the new
            // arm. Match the completed observation, not that intermediate halt.
            // Failed teardown bookkeeping leaves the restrictive halt proven,
            // but the complete enforcement observation remains inconclusive.
            // Once healed, the next serialized pass may already have
            // replaced the transient inconclusive result with verified.
            const allowed = freshHealthy
              ? ["inconclusive", "verified"]
              : [failedStorage ? "inconclusive" : "drift"];
            return allowed.includes(state.observations["sbx-1"]);
          } catch {
            return false;
          }
        }, "periodic reconciler completed current-arm verification").then(() => "unreachable")
      : probe();
    if (midProbeRenewal) {
      await until(() => exists("acl-read-entered"), "probe ACL read barrier entered");
      // The exact captured revision becomes stale DURING observation, on the
      // actual socket. Renewal itself does no runtime verification.
      peer!.send(
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.dispatch",
          digestScheme: requestDigestMetadata().requestDigestScheme,
          digestKeyId: requestDigestMetadata().requestDigestKeyId,
          operationId: "renew-during-probe",
          sandboxId: "sbx-1",
          kind: "sandbox.lease.renew",
          generation: 1,
          attempt: 1,
          idempotencyKey: "renew-during-probe",
          bodyHash: "d".repeat(64),
          lease: { ...lease, revision: 2 },
        }),
      );
      await until(
        () =>
          frames.some(
            (f) => f.type === "operation.result" && f.operationId === "renew-during-probe",
          ),
        "mid-probe renewal acknowledged",
      );
      expect(
        frames.find((f) => f.type === "operation.result" && f.operationId === "renew-during-probe"),
      ).toMatchObject({ state: "succeeded" });
      Object.assign(row, { leaseRevision: 2, leaseRevisionEffective: 2 });
      await writeFile(join(dir, "release-acl-read"), "");
      if (freshHealthy) {
        // Initial observation has confirmed drift and stale Prepare reached
        // its restrictive halt. Heal BEFORE fresh current-arm verification.
        await until(() => exists("stop-entered"), "stale Prepare restrictively stopped");
        await installAcl(healthyAcl);
        await writeFile(join(dir, "release-stop"), "");
      }
    }
    const observed = await observing;
    // Resume periodic inspection for the rest of the scenario, exactly as in
    // an unheld run once the probe has released the lifecycle gate.
    if (!periodic) await rm(join(dir, "hold-policy-reconciler"));
    if (observed === "confirmed_absent") {
      expect(failedStorage || freshHealthy).toBe(false);
      expect(await exists("deleted")).toBe(true);
    } else if (observed === "stopped") {
      expect(await exists("stopped")).toBe(true);
    } else expect(observed).toBe("unreachable");
    const leasePath = join(
      runtimeDir,
      "..",
      "leases",
      `${createHash("sha256").update("sbx-1").digest("hex")}.json`,
    );
    if (freshHealthy) {
      const refused = JSON.parse(await readFile(leasePath, "utf8")).record;
      expect(refused.enforcementLoss ?? false).toBe(false);
      expect(refused).toMatchObject({ expired: false, expiryComplete: false });
      expect(refused.lease.revision).toBe(2);
      for (const name of journals) {
        const path = join(runtimeDir, name);
        await rm(path);
        await rename(`${path}-held`, path);
      }
      expect(
        (await readdir(join(runtimeDir, "enforcement-losses"))).filter((p) => p.endsWith(".json")),
      ).toEqual([]);
      expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(true);
      expect(store.hosts.get("host-1")!.liveCount).toBe(1);
      expect((await allocation("capacity-healthy-inverse", "sbx-new")).error).toMatchObject({
        code: "host_capacity",
      });
      expect(await exists("stopped")).toBe(true);
      expect(await exists("deleted")).toBe(false);
      expect(frames.filter((f) => f.type === "hello")).toHaveLength(1);
      expect(lease.deadlineUnixMs).toBeGreaterThan(Date.now() + 60_000);
      return;
    }
    if (failedStorage) {
      expect(await exists("stopped")).toBe(true);
      expect(await exists("deleted")).toBe(false);
      // One sweep pass records the observation (state.json) BEFORE its loss
      // drain persists the Prepare latch on the lease: two sequential durable
      // writes, so a reader can land between them.
      let pending: Record<string, unknown> & { lease?: unknown } = {};
      await until(async () => {
        pending = JSON.parse(await readFile(leasePath, "utf8")).record;
        return pending.enforcementLoss === true && pending.expired === true;
      }, "loss drain latched Prepare on the lease");
      expect(pending).toMatchObject({
        enforcementLoss: true,
        expired: true,
        expiryComplete: false,
      });
      expect(pending.lease).toEqual({
        ...lease,
        revision: staleInverse || midProbeRenewal ? 2 : 1,
      });
      expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(true);
      expect(store.hosts.get("host-1")!.liveCount).toBe(1);
      expect((await allocation("capacity-storage-blocked", "sbx-new")).error).toMatchObject({
        code: "host_capacity",
      });
      // Heal storage ONLY. No reconnect, manual verify/redetection, second
      // probe, operation cleanup request, or clock advance drives recovery.
      for (const name of journals) {
        const path = join(runtimeDir, name);
        await rm(path);
        await rename(`${path}-held`, path);
      }
    }
    await expect(
      until(() => exists("deleted"), "loss drain destroyed the VM", LOSS_DESTROY_BOUND_MS),
    ).resolves.toBeUndefined();
    // E-15: the slot can be released one step early. A host expiry status
    // that proves the halted VM STOPPED frees the slot from STOPPED
    // (recordSettledHostExpiry); only the later census of the destroyed VM
    // converges it to ERROR/instance_missing. Wait for that final state; the
    // exact match below still pins every field.
    await expect(
      until(
        () => {
          const row = store.sandboxes.get("sbx-1")!;
          return !row.liveResourcesHeld && row.state === "ERROR";
          // Healed storage first retries teardown bookkeeping on the 2 s drain
          // cadence, then a census converges the row: allow several passes.
        },
        "connected lifecycle settlement released server slot",
        SETTLEMENT_BOUND_MS,
      ),
    ).resolves.toBeUndefined();
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "ERROR",
      lastErrorCode: "instance_missing",
      liveResourcesHeld: false,
    });
    expect(store.hosts.get("host-1")!.liveCount).toBe(0);
    // The census that converged the row and the expiry status that reports
    // network cleanup complete are independent frames: wait for the latter.
    // An absent root still owing network cleanup is re-proven under newer
    // storage observations on the same budget as missing root evidence.
    const lastStatus = () => frames.filter((f) => f.type === "sandbox.expiry_status").at(-1);
    await until(
      () => {
        const entry = (
          lastStatus()?.entries as
            | Array<{
                root?: { networkCleanupComplete?: boolean };
                lease?: { expiryComplete?: boolean };
              }>
            | undefined
        )?.[0];
        return (
          entry?.root?.networkCleanupComplete === true && entry?.lease?.expiryComplete === true
        );
      },
      "expiry status reports network cleanup complete",
      SETTLEMENT_BOUND_MS,
    );
    const completed = lastStatus();
    expect(completed).toMatchObject({
      entries: [
        expect.objectContaining({
          sandboxOwnerId: "user-1",
          root: expect.objectContaining({
            state: "absent",
            storagePoolName: "default",
            storageMarker: "a".repeat(32),
            diskGiB: 32,
            networkCleanupComplete: true,
            observationSequence: expect.any(Number),
          }),
          sandboxId: "sbx-1",
          state: "absent",
          lease: expect.objectContaining({
            generation: staleInverse ? 2 : 1,
            expired: true,
            expiryComplete: true,
          }),
        }),
      ],
    });
    // A new sandbox now passes the actual daemon's one-slot admission. This
    // fixture deliberately has no replacement VM, so the later binding error
    // is expected; accepted progress proves local capacity was released.
    const replacement = await allocation("capacity-after", "sbx-new");
    expect(replacement.error).not.toMatchObject({ code: "host_capacity" });
    expect(frames).toContainEqual(
      expect.objectContaining({
        type: "operation.progress",
        operationId: "capacity-after",
        state: "accepted",
      }),
    );
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(epoch);
    expect(frames.filter((f) => f.type === "hello")).toHaveLength(1);
    expect(lease.deadlineUnixMs).toBeGreaterThan(Date.now() + 60_000);
    if (periodic) {
      expect(frames.filter((f) => f.type === "sandbox.probe.result")).toHaveLength(
        probesBeforeDrift,
      );
      await until(
        () =>
          frames.some(
            (f) =>
              f.type === "heartbeat" &&
              (f.policyReconciler as { enabled?: boolean } | undefined)?.enabled,
          ),
        "connected reconciler health report",
      );
      expect(store.hosts.get("host-1")!.policyReconcilerHealth).toMatchObject({
        enabled: true,
        reportedAt: expect.any(String),
      });
    }
  },
  CASE_TIMEOUT_MS + LOSS_DESTROY_BOUND_MS + 2 * SETTLEMENT_BOUND_MS,
);

it.each(["normal", "blocked", "failed"])(
  "C10 wire %s: service → outbox → relay → host evidence → result/receipt",
  async (mode) => {
    await setup(
      mode,
      false,
      undefined,
      undefined,
      mode === "blocked" ? HELD_HELPER_COMMAND_TIMEOUT_MS : COMMAND_TIMEOUT_MS,
    );
    await until(() => exists("armed"), "controlled writer armed");
    await writeFile(join(dir, "write-before"), "");
    await until(() => exists("write-before-done"), "writer produced initial byte");
    const request = await cancelOperation(
      { kind: "session" as const, ownerId: "user-1" },
      { operationId: "op-1" },
    );
    expect(
      await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      ),
    ).toEqual(request);
    expect(
      [...store.outbox.values()].filter((e) => e.payload.kind === "operation.cancel"),
    ).toHaveLength(1);
    await processSandboxOutboxBatch();
    // Duplicate on the actual wire is harmless and cannot abandon the owner.
    await processSandboxOutboxBatch(() => new Date(Date.now() + 31001));
    await until(() => exists("cleanup-entered"), "cleanup owner entered after durable intent");
    if (mode !== "normal") {
      await until(
        () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
        "failed/blocked cleanup exposed uncertainty",
        HELD_HELPER_BOUND_MS,
      );
      expect((await receipt()).phase).toBe("effect");
      expect((await receipt()).cancelRequested).toBe(true);
      expect(frames.some((f) => f.state === "cancelled")).toBe(false);
      await writeFile(join(dir, "release-cleanup"), "");
    }
    await until(
      () => store.operations.get("op-1")!.state === "CANCELLED",
      "same owner upgraded cancellation",
    );
    expect((await receipt()).phase).toBe("result");
    expect(await exists("term-observed")).toBe(true);
    const termAt = BigInt(await readFile(join(dir, "term-observed"), "utf8"));
    const killedAt = BigInt(await readFile(join(dir, "kill-observed"), "utf8"));
    expect(killedAt - termAt).toBeGreaterThanOrEqual(200_000_000n);
    const pgid = Number(await readFile(join(dir, "guest-pgid"), "utf8"));
    await writeFile(join(dir, "write-after"), "");
    expect(() => process.kill(-pgid, 0)).toThrow();
    expect(await readFile(join(dir, "bytes"), "utf8")).toBe("X");
    expect(await exists("write-after-done")).toBe(false);
    expect([...store.outbox.values()].every((e) => e.processedAt !== null)).toBe(true);
    // Confirmation loss/restart replays the actual journal, never a fabricated receipt.
    await crashHost();
    frames.length = 0;
    dropConfirmation = false;
    await startHost();
    await until(
      () => frames.some((f) => f.type === "reconcile.complete"),
      "reconnect receipt replay",
      SESSION_TIMEOUT_MS,
    );
    expect(frames.some((f) => f.type === "operation.receipt" && f.state === "cancelled")).toBe(
      true,
    );
    await until(async () => !(await receipt()), "exact receipt confirmation compacts journal");
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
  },
  CASE_BUDGET.oneSession + HELD_HELPER_BOUND_MS,
);

// A daemon double that hardens itself as the daemon does (non-dumpable) and
// takes the journal lock the daemon's way (flock on an O_CLOEXEC descriptor).
// "unexeced": a fork child leads its own process group and never reaches exec
// (the window between spawn and exec, held open). "leaked": the descriptor is
// made inheritable and that child execs another image, as a daemon
// descriptor leak would. "vfork": a thread spawns through glibc posix_spawn
// (vfork, as the daemon's std::process::Command does) with no process group
// of its own; the child waits in an open of the `release` FIFO before exec,
// so it is in the daemon's group and the spawning thread cannot stop.
const LOCK_HOLDER_DOUBLE = `
import ctypes, fcntl, os, sys, threading, time
lock, ready, mode = sys.argv[1], sys.argv[2], sys.argv[3]
assert ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE
fd = os.open(lock, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
def publish(pid):
    with open(ready + ".tmp", "w") as f:
        f.write(str(pid))
    os.rename(ready + ".tmp", ready)
if mode == "vfork":
    release = os.path.join(os.path.dirname(ready), "release")
    os.mkfifo(release)
    open_release = [(os.POSIX_SPAWN_OPEN, 3, release, os.O_RDONLY, 0)]
    spawn = lambda: os.posix_spawn("/bin/sleep", ["sleep", "600"], os.environ, file_actions=open_release)
    publish(os.getpid())  # first: the vfork wait keeps the GIL
    threading.Thread(target=spawn, daemon=True).start()
elif os.fork() == 0:
    os.setpgid(0, 0)
    publish(os.getpid())
    if mode == "leaked":
        os.set_inheritable(fd, True)
        os.execv("/bin/sh", ["sh", "-c", "sleep 600; :", lock])
    time.sleep(600)
    os._exit(0)
time.sleep(600)
`;
async function lockHolderDouble(mode: "unexeced" | "leaked" | "vfork") {
  dir = await mkdtemp(join(tmpdir(), "wssp-c10-wire-"));
  await mkdir(dirname(wireJournalLock(dir)), { recursive: true });
  host = spawn(
    "python3",
    ["-c", LOCK_HOLDER_DOUBLE, wireJournalLock(dir), join(dir, "holder-pid"), mode],
    { detached: true, stdio: "ignore" },
  );
  // A worker that dies mid-case still takes the double and its children.
  watchWireHost(host, dir);
  await until(() => exists("holder-pid"), "double published its holder");
  const pid = Number(await readFile(join(dir, "holder-pid"), "utf8"));
  // The leaked child must have finished its exec before the crash reads it.
  if (mode === "leaked")
    await until(
      async () => (await readFile(`/proc/${pid}/cmdline`, "utf8")).startsWith("sh"),
      "leaked holder exec'd",
    );
  if (mode === "vfork")
    await until(async () => (await childOf(pid)) !== undefined, "vfork child waits before exec");
  expect(await journalLockHeld(dir)).toBe(true);
  return pid;
}

/** `/proc/<pid>/stat` fields after the command name (state first). */
async function procFields(pid: number | string) {
  const stat = await readFile(`/proc/${pid}/stat`, "utf8").catch(() => "");
  return stat ? stat.slice(stat.lastIndexOf(")") + 2).split(" ") : undefined;
}
async function procAlive(pid: number) {
  const state = (await procFields(pid))?.[0];
  return state !== undefined && state !== "Z" && state !== "X";
}
/** Live worker-death watchdogs (`watchWireHost`) guarding `daemon`. */
async function watchdogsOf(daemon: number) {
  const found: number[] = [];
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    const argv = (await readFile(`/proc/${entry}/cmdline`, "utf8").catch(() => "")).split("\0");
    if (
      argv[1] === "-e" &&
      argv[2]?.includes("WSSP_WIRE_WATCHDOG_ROOT") &&
      argv[3] === String(daemon)
    )
      found.push(Number(entry));
  }
  return found;
}
async function childOf(parent: number) {
  for (const entry of await readdir("/proc"))
    if (/^\d+$/.test(entry) && Number((await procFields(entry))?.[1]) === parent)
      return Number(entry);
  return undefined;
}
/**
 * Once the double is stopped, open the release FIFO's write end so its vfork
 * child goes on to exec. While nothing waits to read (a stopped child left its
 * open), the non-blocking open fails with ENXIO and is retried.
 */
async function releaseOnceStopped(pid: number, settled: () => boolean) {
  while (!settled()) {
    if ((await procFields(pid))?.[0] === "T") {
      const writer = await open(
        join(dir, "release"),
        constants.O_WRONLY | constants.O_NONBLOCK,
      ).catch(() => undefined);
      if (writer) {
        await writer.close();
        return true;
      }
    }
    await delay(5);
  }
  return false;
}

it("crash fixture: a process-group kill leaves a spawn child before exec holding the journal lock", async () => {
  await lockHolderDouble("unexeced");
  const child = host!;
  host = undefined;
  const exited = once(child, "exit");
  process.kill(-child.pid!, "SIGKILL");
  await exited;
  expect(await journalLockHeld(dir)).toBe(true);
});

it("crash fixture: a crash also ends a non-dumpable spawn child before exec, so the restart finds the journal lock free", async () => {
  const pid = await lockHolderDouble("unexeced");
  const daemon = host!.pid!;
  await expect(readlink(`/proc/${pid}/exe`)).rejects.toMatchObject({ code: "EACCES" });
  expect(await watchdogsOf(daemon)).toHaveLength(1);
  expect(await crashWireHost(host, dir)).toBe(true);
  host = undefined;
  expect(await journalLockHeld(dir)).toBe(false);
  await until(async () => (await watchdogsOf(daemon)).length === 0, "watchdog retired");
});

it("crash fixture: a crash stops only the daemon, so a vfork child before its setpgid still execs and the crash completes", async () => {
  const pid = await lockHolderDouble("vfork");
  let settled = false;
  const crash = crashWireHost(host, dir).finally(() => {
    settled = true;
  });
  const released = releaseOnceStopped(pid, () => settled);
  expect(await crash).toBe(true);
  host = undefined;
  expect(await released).toBe(true);
  expect(await journalLockHeld(dir)).toBe(false);
});

it("crash fixture: an exec'd process keeping the journal lock fails the crash and is never killed", async () => {
  const pid = await lockHolderDouble("leaked");
  const daemon = host!.pid!;
  try {
    await expect(crashWireHost(host, dir)).rejects.toThrow(
      "journal lock still held after the crash: a descriptor leak survived exec",
    );
    host = undefined;
    expect(await procAlive(pid)).toBe(true);
    expect(await journalLockHeld(dir)).toBe(true);
    // A worker dying now must still take the surviving holder with it.
    expect(await watchdogsOf(daemon)).toHaveLength(1);
  } finally {
    process.kill(-pid, "SIGKILL");
  }
});

it("1.0 wire: a precise missing-path stat keeps the session open", async () => {
  await setup("stat-missing");
  expect(frames.findLast((f) => f.type === "hello")).toMatchObject({
    supportedProtocolVersions: ["1.0"],
    daemon: {
      capabilities: { hostTerminal: false, requireHostTerminalTotp: true, policyRevision: 0 },
    },
  });
  await until(() => store.operations.get("op-1")!.state === "FAILED", "stat failure published");
  expect(
    frames.find((f) => f.type === "operation.result" && f.operationId === "op-1"),
  ).toMatchObject({ state: "failed", error: { code: "fs_not_found" } });
  expect(store.operations.get("op-1")!.errorCode).toBe("fs_not_found");
  expect(manager.isHostConnected("host-1")).toBe(true);
});

it("offload wire: the real host advertises diskOffload and serves offload frames, the restore and the cached cold reconnect", async () => {
  await setup("stat-missing");
  await until(() => store.operations.get("op-1")!.state === "FAILED", "stat failure published");
  // I10: the daemon serves disk offload (C4), so its hello advertises the
  // capability and the server records it for this epoch.
  const hello = frames.findLast((f) => f.type === "hello") as
    | { daemon: { capabilities: Record<string, unknown> } }
    | undefined;
  expect(hello?.daemon.capabilities).toHaveProperty("diskOffload", true);
  expect(store.hosts.get("host-1")!.daemonDiskOffload).toBe(true);
  const fp = `sha256:${"abcdef0123456789".repeat(4)}`;
  const disk = `sha256:${"d".repeat(64)}`;
  const reconnect = {
    type: "operation.dispatch" as const,
    digestScheme: requestDigestMetadata().requestDigestScheme,
    digestKeyId: requestDigestMetadata().requestDigestKeyId,
    sandboxOwnerId: "user-1",
    sandboxId: "sbx-1",
    kind: "sandbox.reconnect",
    ...(() => {
      const size = wirePinnedSize(store);
      return { ...size, allocation: pinnedAllocationV11Schema.parse(size.allocation) };
    })(),
    generation: 5,
    attempt: 1,
    bodyHash: "c".repeat(64),
    incusFingerprint: fp,
    templateDigest: fp,
    egressPolicy: { domains: [], cidrs: [] },
    egressPolicyHash: createHash("sha256")
      .update(canonicalEgressPolicyJson({ domains: [], cidrs: [] }))
      .digest("hex"),
    architecture: "x86_64",
  };
  const answered = async (operationId: string, fields: Record<string, unknown>) => {
    // Encoded by the server's own validator, parsed by the real binary.
    peer!.send(
      encodeServerControlMessage(
        { ...reconnect, operationId, idempotencyKey: operationId, ...fields },
        "1.0",
      ),
    );
    await until(
      () => frames.some((f) => f.type === "operation.result" && f.operationId === operationId),
      `${operationId} answered`,
    );
    return frames.find((f) => f.type === "operation.result" && f.operationId === operationId);
  };
  const hellos = frames.filter((f) => f.type === "hello").length;
  // Offload plan C6c: a restore reconnect (with guest privilege from the
  // sandbox row) is served: it passes ingress and the Intent-phase restore
  // fetch and is decided as that one operation at its lease (this frame
  // carries none), never refused as an unsupported field.
  const restore = await answered("capacity-restore", {
    image: { fingerprint: disk, sizeBytes: 4096, format: "unified", source: "fetch" },
    restore: { offloadId: "off-1", seq: 1, fingerprint: disk, cloudInitInstanceId: "iid-1" },
    launchMode: "new_root",
    diskBaseFingerprint: disk,
    guestSudo: true,
    guestRoot: true,
  });
  expect(restore).toMatchObject({ error: { code: "state_conflict" } });
  // A cached cold reconnect on a host with no stored copy of that offload:
  // the `disk_stale` refusal, before any lease or start (§8.1), in the shared
  // catalog's own code (the server keeps the sandbox STOPPED and the next
  // start evicts or discards the cached copy, then restores). Its certainty
  // is today's cold-reconnect refusal classification (this harness's VM
  // runs, so it is not provably unstarted).
  expect(
    await answered("capacity-cached", {
      launchMode: "cold",
      expectDisk: { seq: 1, fingerprint: disk },
    }),
  ).toMatchObject({ error: { code: "disk_stale" } });
  // Each refusal was that one operation: the session stayed up.
  expect(frames.filter((f) => f.type === "hello")).toHaveLength(hellos);
  expect(manager.isHostConnected("host-1")).toBe(true);
  // Server disk frames parse on the real host. An eviction frame is not
  // served before C5 and is ignored; the session stays up.
  peer!.send(
    encodeServerControlMessage(
      { type: "disk.evict.suggest", sandboxId: "sbx-1", offloadId: "off-1", seq: 1 },
      "1.0",
    ),
  );
  // An offload request for a sandbox this host never ran is answered with
  // `disk.offload.failed`, not a session end.
  peer!.send(
    encodeServerControlMessage(
      {
        type: "disk.offload.request",
        sandboxId: "sbx-ghost",
        generation: 1,
        offloadId: "off-2",
        seq: 1,
      },
      "1.0",
    ),
  );
  await until(
    () => frames.some((f) => f.type === "disk.offload.failed"),
    "offload request answered",
  );
  expect(frames.find((f) => f.type === "disk.offload.failed")).toMatchObject({
    sandboxId: "sbx-ghost",
    offloadId: "off-2",
    seq: 1,
    code: "instance_missing",
  });
  expect(failures.some((line) => line.includes("disk offload frame"))).toBe(false);
  expect(frames.filter((f) => f.type === "hello")).toHaveLength(hellos);
  expect(manager.isHostConnected("host-1")).toBe(true);
});

it("offload wire: after reconciliation the real host reports its unfinished offload and a release drops it", async () => {
  // An `uploaded` entry whose stored ack was missed, journaled
  // before this daemon started (its state dir: data/relay/sha256(host id)).
  const journal = () =>
    join(
      dir,
      "data",
      "relay",
      createHash("sha256").update("host-1").digest("hex"),
      "images",
      "disk-offload.json",
    );
  await setup("stat-missing", false, undefined, async () => {
    await mkdir(dirname(journal()), { recursive: true });
    const tag = createHash("sha256").update("host-1").digest("hex").slice(0, 12);
    await writeFile(
      journal(),
      JSON.stringify({
        version: 1,
        entries: {
          "sbx-1": {
            offloadId: "off-9",
            seq: 1,
            generation: 3,
            phase: "uploaded",
            alias: `wssp-off-${tag}-off-9`,
            stagedSha256: "d".repeat(64),
          },
        },
      }),
      { mode: 0o600 },
    );
    // No row of this host names it (e.g. CONSUMED elsewhere, or unknown).
    db.sandboxDiskOffload.findMany.mockResolvedValue([] as never);
  });
  await until(
    () => frames.some((f) => f.type === "disk.offload.inventory"),
    "offload inventory reported",
  );
  expect(frames.find((f) => f.type === "disk.offload.inventory")).toEqual({
    type: "disk.offload.inventory",
    entries: [{ sandboxId: "sbx-1", offloadId: "off-9", seq: 1 }],
  });
  // Sent only after reconciliation, and answered from this host's rows.
  expect(frames.findIndex((f) => f.type === "reconcile.complete")).toBeLessThan(
    frames.findIndex((f) => f.type === "disk.offload.inventory"),
  );
  await until(() => db.sandboxDiskOffload.findMany.mock.calls.length > 0, "inventory answered");
  expect(db.sandboxDiskOffload.findMany.mock.calls[0]![0]).toMatchObject({
    where: { id: { in: ["off-9"] }, sourceHostId: "host-1", sourceHostOwnerId: "user-1" },
  });
  // The `released` answer drops the entry (with its alias and staging).
  let entries: Record<string, unknown> = { "sbx-1": {} };
  await until(async () => {
    entries = JSON.parse(await readFile(journal(), "utf8")).entries;
    return Object.keys(entries).length === 0;
  }, "released entry dropped");
  expect(failures.some((line) => line.includes("disk offload frame"))).toBe(false);
  expect(manager.isHostConnected("host-1")).toBe(true);
});

it("offload wire: a stored ack is answered disk.offload.released once the host dropped the export", async () => {
  // The server frees the host's export slot only on this frame.
  const journal = () =>
    join(
      dir,
      "data",
      "relay",
      createHash("sha256").update("host-1").digest("hex"),
      "images",
      "disk-offload.json",
    );
  const fingerprint = `sha256:${"d".repeat(64)}`;
  await setup("stat-missing", false, undefined, async () => {
    await mkdir(dirname(journal()), { recursive: true });
    const tag = createHash("sha256").update("host-1").digest("hex").slice(0, 12);
    await writeFile(
      journal(),
      JSON.stringify({
        version: 1,
        entries: {
          "sbx-1": {
            offloadId: "off-9",
            seq: 1,
            generation: 3,
            phase: "uploaded",
            alias: `wssp-off-${tag}-off-9`,
            stagedSha256: "d".repeat(64),
          },
        },
      }),
      { mode: 0o600 },
    );
    // This host's row: STORED (verified while the ack was missed).
    db.sandboxDiskOffload.findMany.mockResolvedValue([
      {
        id: "off-9",
        sandboxId: "sbx-1",
        seq: 1,
        state: "STORED",
        fingerprint,
        sourceGeneration: 3,
      },
    ] as never);
    db.sandboxDiskOffload.updateMany.mockResolvedValue({ count: 1 } as never);
  });
  await until(() => frames.some((f) => f.type === "disk.offload.released"), "release confirmed");
  expect(frames.find((f) => f.type === "disk.offload.released")).toEqual({
    type: "disk.offload.released",
    sandboxId: "sbx-1",
    offloadId: "off-9",
    seq: 1,
    reportId: expect.stringMatching(/^[0-9a-f]{32}$/),
  });
  const entries = JSON.parse(await readFile(journal(), "utf8")).entries;
  expect(entries["sbx-1"]).toMatchObject({ offloadId: "off-9", phase: "stored" });
  await until(() => db.sandboxDiskOffload.updateMany.mock.calls.length > 0, "release recorded");
  expect(db.sandboxDiskOffload.updateMany.mock.calls.at(-1)![0]).toMatchObject({
    where: {
      id: "off-9",
      sandboxId: "sbx-1",
      seq: 1,
      sourceHostId: "host-1",
      sourceHostOwnerId: "user-1",
      sourceReleasedAt: null,
    },
    data: { sourceReleasedAt: expect.any(Date) },
  });
  expect(failures.some((line) => line.includes("disk offload frame"))).toBe(false);
  expect(manager.isHostConnected("host-1")).toBe(true);
});

/** The ghost offload request of the offload wire cases: the real host
 * answers it `disk.offload.failed` (`instance_missing`). */
function requestGhostOffload() {
  peer!.send(
    encodeServerControlMessage(
      {
        type: "disk.offload.request",
        sandboxId: "sbx-ghost",
        generation: 1,
        offloadId: "off-2",
        seq: 1,
      },
      "1.0",
    ),
  );
}
const ghostFailure = (f: Record<string, unknown>) =>
  f.type === "disk.offload.failed" && f.offloadId === "off-2";
const reconciles = () => frames.filter((f) => f.type === "reconcile.complete").length;
async function reconnected(before: number) {
  await until(
    () => reconciles() > before && manager.isHostConnected("host-1"),
    "daemon reconnected and reconciled",
    SESSION_TIMEOUT_MS,
  );
}
/** The image outbox of the newest connection has drained past its re-sent
 * reports: they are queued at `hello.ok`, ahead of its census. */
async function censusAfter(index: number) {
  await until(
    () => frames.slice(index).some((f) => f.type === "image.cache.census" && f.complete === true),
    "image census of the new connection",
    SESSION_TIMEOUT_MS,
  );
}

it("offload wire: a failure report lost with its connection is sent again on the next one and acked once", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("stat-missing");
  await until(() => store.operations.get("op-1")!.state === "FAILED", "stat failure published");
  const before = reconciles();
  // Read off the socket but never handled: the connection dies with it.
  loseDaemonFrame = ghostFailure;
  requestGhostOffload();
  await until(() => frames.some(ghostFailure), "offload request answered");
  const reportId = frames.find(ghostFailure)!.reportId;
  expect(reportId).toMatch(/^[0-9a-f]{32}$/);
  await reconnected(before);
  await until(() => frames.filter(ghostFailure).length === 2, "the lost report sent again");
  expect(frames.filter(ghostFailure).map((f) => f.reportId)).toEqual([reportId, reportId]);
  const acked = (f: Record<string, unknown>) => f.type === "report.ack" && f.reportId === reportId;
  await until(() => serverFrames.some(acked), "the repeat acknowledged by the real manager");
  // Acknowledged: the next connection carries it no more.
  const settled = reconciles();
  const mark = frames.length;
  peer!.terminate();
  await reconnected(settled);
  await censusAfter(mark);
  expect(frames.filter(ghostFailure)).toHaveLength(2);
  expect(serverFrames.filter(acked)).toHaveLength(1);
  expect(failures.some((line) => line.includes("disk offload frame"))).toBe(false);
});

it("offload wire: a failure report whose ack was lost is sent once more and acked as a repeat", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("stat-missing");
  await until(() => store.operations.get("op-1")!.state === "FAILED", "stat failure published");
  const before = reconciles();
  // Handled, but its acknowledgement never written: the connection dies.
  loseServerFrame = (f) => f.type === "report.ack";
  requestGhostOffload();
  await reconnected(before);
  await until(() => frames.filter(ghostFailure).length === 2, "the unacked report sent again");
  const [first, second] = frames.filter(ghostFailure);
  expect(second!.reportId).toBe(first!.reportId);
  const acked = (f: Record<string, unknown>) =>
    f.type === "report.ack" && f.reportId === first!.reportId;
  await until(() => serverFrames.some(acked), "the repeat acknowledged");
  expect(serverFrames.filter(acked)).toHaveLength(1);
  expect(failures.some((line) => line.includes("disk offload frame"))).toBe(false);
});

it("offload wire: on one live connection the disk tick runs the inventory pass again", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  // r5 minor #2: the connect loop's periodic disk tick, end to end (its
  // interval and the pass's cadence shortened by the debug knob).
  const journal = () =>
    join(
      dir,
      "data",
      "relay",
      createHash("sha256").update("host-1").digest("hex"),
      "images",
      "disk-offload.json",
    );
  await setup("stat-missing", false, undefined, async () => {
    hostEnv = { WSSP_TEST_DISK_TIMING: "200,1000" };
    await mkdir(dirname(journal()), { recursive: true });
    const tag = createHash("sha256").update("host-1").digest("hex").slice(0, 12);
    await writeFile(
      journal(),
      JSON.stringify({
        version: 1,
        entries: {
          "sbx-1": {
            offloadId: "off-9",
            seq: 1,
            generation: 3,
            phase: "uploaded",
            alias: `wssp-off-${tag}-off-9`,
            stagedSha256: "d".repeat(64),
          },
        },
      }),
      { mode: 0o600 },
    );
    // Still in flight on the server: no answer, so the entry stays.
    db.sandboxDiskOffload.findMany.mockResolvedValue([
      {
        id: "off-9",
        sandboxId: "sbx-1",
        seq: 1,
        state: "UPLOADING",
        fingerprint: `sha256:${"d".repeat(64)}`,
        sourceGeneration: 3,
      },
    ] as never);
  });
  const hellos = frames.filter((f) => f.type === "hello").length;
  const inventories = () => frames.filter((f) => f.type === "disk.offload.inventory").length;
  await until(() => inventories() >= 1, "first inventory pass");
  await until(() => inventories() >= 2, "periodic inventory pass", SESSION_TIMEOUT_MS);
  expect(frames.filter((f) => f.type === "hello")).toHaveLength(hellos);
  expect(manager.isHostConnected("host-1")).toBe(true);
  const entries = JSON.parse(await readFile(journal(), "utf8")).entries;
  expect(entries["sbx-1"]).toMatchObject({ offloadId: "off-9", phase: "uploaded" });
});

it("keyed 1.0 command env reaches the guest and retains separate private receipt MACs", async () => {
  const value = "keyed-env-wire-private-sentinel";
  await setup("normal", false, [["KEYED_ENV", value]]);
  await until(() => exists("armed"), "env-bearing guest armed");
  await writeFile(join(dir, "release-natural"), "");
  await until(() => store.operations.get("op-1")!.state === "SUCCEEDED", "keyed env result");
  expect(receivedOutput().stdout).toContain(value);
  expect(frames.some((frame) => frame.type === "journal.key.ack")).toBe(true);
  const stored = await receipt();
  expect(stored).toMatchObject({
    digestScheme: "hmac-sha256-v1",
    digestKeyId: requestDigestMetadata().requestDigestKeyId,
    serverRequestHash: store.operations.get("op-1")!.requestBodyHash,
  });
  expect(stored.requestHash).not.toBe(stored.serverRequestHash);
  expect(stored.bodyHash).not.toBe(stored.requestHash);
  const key = hostJournalKey("user-1", "host-1");
  expect(JSON.stringify(stored).includes(key.keyHex)).toBe(false);
  expect(JSON.stringify(stored).includes(value)).toBe(false);
  expect(failures.join("\n").includes(key.keyHex)).toBe(false);
  expect(failures.join("\n").includes(value)).toBe(false);
});

it("C10 wire: complete natural EXIT before cancel retains exit 0", async () => {
  await setup("natural");
  await until(() => exists("natural-exit"), "nonce-bound natural EXIT emitted");
  await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
  await processSandboxOutboxBatch();
  await writeFile(join(dir, "release-natural"), "");
  await until(() => store.operations.get("op-1")!.state === "SUCCEEDED", "natural result");
  expectStoredCommandExit(0);
  expect(await exists("cleanup-entered")).toBe(false);
});

it("C10 wire: a command that ran without its start record is uncertain, never an unappliable success", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  // The real wrapper never runs argv without its start record; this shim
  // head (PID banner, natural EXIT, no READY) models evidence lost anyway.
  // 1.0 has no command payload without a bound birth, so the host reports
  // the attempt uncertain instead of a success the server could never apply.
  await setup("natural-no-ready");
  await until(() => exists("natural-exit"), "natural EXIT without a start record");
  await writeFile(join(dir, "release-natural"), "");
  await until(() => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME", "uncertain result");
  expect(store.operations.get("op-1")).toMatchObject({
    errorCode: "unknown_outcome",
    scalarResult: null,
  });
  const uncertain = {
    state: "unknown_outcome",
    result: {
      version: 1,
      payload: null,
      birth: null,
      failure: { resource: "command", effect: "unknown" },
    },
  };
  expect(
    frames.find((f) => f.type === "operation.result" && f.operationId === "op-1"),
  ).toMatchObject(uncertain);
  expect(frames.some((f) => f.operationId === "op-1" && f.state === "succeeded")).toBe(false);
  // The nonterminal receipt stays until cleanup proves the attempt dead; its
  // replay in a later session applies cleanly and changes nothing.
  expect(await receipt()).toMatchObject({ phase: "effect", ...uncertain });
  const sent = frames.length;
  await dropAndReconnect();
  await until(
    () =>
      frames.slice(sent).some((f) => f.type === "operation.receipt" && f.operationId === "op-1"),
    "uncertain receipt replayed",
  );
  expect(frames.slice(sent).filter((f) => f.type === "hello")).toHaveLength(1);
  expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
  expect(manager.isHostConnected("host-1")).toBe(true);
});

it.each(["natural-during-cleanup", "natural-after-retry", "natural-cleanup-release"])(
  "C10 wire: %s retains EXIT(0) while cleanup is blocked before signal",
  async (mode) => {
    await setup(mode, false, undefined, undefined, HELD_HELPER_COMMAND_TIMEOUT_MS);
    await until(() => exists("armed"), "writer armed");
    await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
    await processSandboxOutboxBatch();
    await until(() => exists("cleanup-entered"), "helper blocked before any signal");
    if (mode === "natural-after-retry") {
      await until(
        () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
        "first failed helper published uncertainty; same owner continues",
        HELD_HELPER_BOUND_MS,
      );
      expect((await receipt()).phase).toBe("effect");
    }
    await writeFile(join(dir, "release-natural"), "");
    await until(() => exists("natural-finished"), "real wrapper emitted EXIT(0) and was reaped");
    if (mode === "natural-cleanup-release") await writeFile(join(dir, "release-cleanup"), "");
    // Cover both group_gone after release and helper timeout while still blocked.
    // Either continuation must classify the drained natural completion.
    await until(
      () => store.operations.get("op-1")!.state === "SUCCEEDED",
      "natural result",
      HELD_HELPER_BOUND_MS,
    );
    expectStoredCommandExit(0);
    expect(await exists("term-observed")).toBe(false);
    expect(frames.some((f) => f.state === "cancelled")).toBe(false);
    expect((await receipt()).phase).toBe("result");
    await writeFile(join(dir, "release-cleanup"), "");
    await processSandboxOutboxBatch(() => new Date(Date.now() + 31001));
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
    expect([...store.outbox.values()].every((e) => e.processedAt !== null)).toBe(true);
  },
  CASE_TIMEOUT_MS + 2 * HELD_HELPER_BOUND_MS,
);

it.each(["natural-late-output", "natural-late-reframed"])(
  "C10 wire: %s classifies the complete stream after parent reap",
  async (mode) => {
    await setup(mode, false, undefined, undefined, HELD_HELPER_COMMAND_TIMEOUT_MS);
    await until(() => exists("armed"), "writer armed");
    await until(() => exists("holder-pid"), "independent descriptor holder started");
    await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
    await processSandboxOutboxBatch();
    await until(() => exists("cleanup-entered"), "helper blocked before signal");
    await writeFile(join(dir, "release-natural"), "");
    await until(() => exists("natural-finished"), "real wrapper emitted first EXIT");
    await until(
      () => exists("late-done"),
      "holder wrote tails after transport reap",
      HELD_HELPER_BOUND_MS,
    );
    await until(
      () => frames.some((f) => f.type === "operation.result"),
      "final output journaled and published",
      HELD_HELPER_BOUND_MS,
    );
    const reframed = mode === "natural-late-reframed";
    const state = reframed ? "succeeded" : "unknown_outcome";
    if (reframed)
      await until(() => frames.some((f) => f.type === "operation.receipt"), "terminal receipt");
    for (const type of reframed
      ? ["operation.result", "operation.receipt"]
      : ["operation.result"]) {
      expect(frames.find((f) => f.type === type)).toMatchObject({
        state,
        result: commandResult(reframed ? 7 : null),
      });
    }
    await until(
      () => store.operations.get("op-1")!.state === (reframed ? "SUCCEEDED" : "UNKNOWN_OUTCOME"),
      "server persisted final classification",
    );
    const result = store.operations.get("op-1")!.result;
    expect(result).toMatchObject({
      exitCode: reframed ? 7 : null,
      outputBytes: expect.any(Number),
    });
    expect(await receipt()).toMatchObject({
      phase: reframed ? "result" : "effect",
      state,
      result: commandResult(reframed ? 7 : null),
    });
    expect(result).not.toHaveProperty("stdout");
    expect(receivedOutput()).toEqual({
      stdout: "late-stdout",
      stderr: expect.stringMatching(/^\nWSSP_EXIT [a-f0-9]+ 0\nlate-stderr$/),
    });
    expect(await exists("term-observed")).toBe(false);
    expect(frames.some((f) => f.state === "cancelled")).toBe(false);
  },
  CASE_TIMEOUT_MS + HELD_HELPER_BOUND_MS,
);

it.each(["exit", "setup"])(
  "C10 wire: natural %s before cleanup cannot become cancelled after late output",
  async (kind) => {
    await setup(`natural-entry-${kind}`);
    await until(() => exists("holder-pid"), "independent descriptor holder started");
    if (kind === "exit") {
      await until(() => exists("armed"), "writer armed");
      await writeFile(join(dir, "release-natural"), "");
    }
    await until(() => exists("natural-finished"), "real wrapper completed before cancellation");
    const initialStderr = await readFile(join(dir, "initial-stderr"), "utf8");
    const nonce = /^WSSP_PID ([a-f0-9]+) \d+\n/.exec(initialStderr)?.[1];
    expect(nonce).toBeDefined();
    expect(
      initialStderr.endsWith(
        `\nWSSP_${kind === "exit" ? "EXIT" : "SETUP_FAILED"} ${nonce} ${kind === "exit" ? 0 : 1}\n`,
      ),
    ).toBe(true);
    // This fixture publishes the entire initial stderr in one atomic pipe
    // write, so any evidence the wait owner parsed from it proves it consumed
    // the whole snapshot; its next drain cannot precede recording the natural
    // suffix from the same bytes. A started command is listed by the
    // versioned process page once its birth (the start record) is bound. A
    // wrapper setup failure never starts one: its forwarded diagnostic, which
    // precedes the withheld suffix in the same bytes, is the evidence.
    let inventory = 0;
    await until(async () => {
      if (kind === "setup") {
        const forwarded = receivedOutput().stderr;
        return forwarded.length > 0 && afterWrapperHead(initialStderr).startsWith(forwarded);
      }
      const operationId = `observe-${++inventory}`;
      peer!.send(
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.dispatch",
          digestScheme: requestDigestMetadata().requestDigestScheme,
          digestKeyId: requestDigestMetadata().requestDigestKeyId,
          operationId,
          sandboxId: "sbx-1",
          idempotencyKey: operationId,
          kind: "process.list",
          resultVersion: 1,
          generation: 1,
          attempt: 1,
          bodyHash: "a".repeat(64),
        }),
      );
      await until(
        () => frames.some((f) => f.type === "operation.result" && f.operationId === operationId),
        "process inventory result",
      );
      const frame = frames.find(
        (f) => f.type === "operation.result" && f.operationId === operationId,
      )!;
      const result = frame.result as { payload: { items: { operationId: string }[] } };
      return result.payload.items.some((process) => process.operationId === "op-1");
    }, "wait owner observed the initial completion snapshot");
    await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
    await processSandboxOutboxBatch();
    await until(
      async () => (await receipt())?.cancelRequested === true,
      "durable host cancel intent",
    );
    expect(await exists("cleanup-entered")).toBe(false);
    await writeFile(join(dir, "release-pipe"), "");
    await until(() => exists("late-done"), "late bytes invalidated the original suffix");
    await until(
      () => frames.some((f) => f.type === "operation.result" && f.operationId === "op-1"),
      "final host result",
    );
    expect(receivedOutput()).toEqual({
      stdout: "late-stdout",
      stderr: `${afterWrapperHead(initialStderr)}late-stderr`,
    });
    const result = uncertainEntryResults(kind);
    expect(
      frames.find((f) => f.type === "operation.result" && f.operationId === "op-1"),
    ).toMatchObject({
      state: "unknown_outcome",
      result: result.host,
    });
    await until(() => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME", "server outcome");
    expect(store.operations.get("op-1")!.result).toEqual(result.stored);
    expect(await receipt()).toMatchObject({
      phase: "effect",
      state: "unknown_outcome",
      result: result.host,
    });
    expect(frames.some((f) => f.state === "cancelled")).toBe(false);
    expect(await exists("cleanup-entered")).toBe(false);
    expect(await exists("term-observed")).toBe(false);
  },
);

it.each(["exit", "setup"])(
  "C10 wire: buffered natural %s before cancellation cannot become cancelled",
  async (kind) => {
    await setup(`natural-entry-${kind}`, true);
    const testHost = host!;
    try {
      await until(() => exists("before-wrapper"), "wrapper launch barrier");
      expect(testHost.kill("SIGSTOP")).toBe(true);
      await until(
        async () => /^State:\s+T/m.test(await readFile(`/proc/${testHost.pid}/status`, "utf8")),
        "host stopped before completion frames exist",
      );
      await writeFile(join(dir, "release-natural"), "");
      await writeFile(join(dir, "release-wrapper"), "");
      await until(() => exists("natural-finished"), "real wrapper completed before server cancel");
      const initialStderr = await readFile(join(dir, "initial-stderr"), "utf8");
      const nonce = /^WSSP_PID ([a-f0-9]+) \d+\n/.exec(initialStderr)?.[1];
      expect(nonce).toBeDefined();
      expect(
        initialStderr.endsWith(
          `\nWSSP_${kind === "exit" ? "EXIT" : "SETUP_FAILED"} ${nonce} ${kind === "exit" ? 0 : 1}\n`,
        ),
      ).toBe(true);
      await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      );
      await processSandboxOutboxBatch();
      await writeFile(join(dir, "release-pipe"), "");
      await until(() => exists("late-done"), "completion and tail buffered before host resumes");
      expect(testHost.kill("SIGCONT")).toBe(true);
      await until(
        () => frames.some((f) => f.type === "operation.result" && f.operationId === "op-1"),
        "final host result",
      );
      expect(receivedOutput()).toEqual({
        stdout: "late-stdout",
        stderr: `${afterWrapperHead(initialStderr)}late-stderr`,
      });
      const result = uncertainEntryResults(kind);
      expect(
        frames.find((f) => f.type === "operation.result" && f.operationId === "op-1"),
      ).toMatchObject({ state: "unknown_outcome", result: result.host });
      await until(
        () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
        "server persisted final classification",
      );
      expect(store.operations.get("op-1")!.result).toEqual(result.stored);
      expect(await receipt()).toMatchObject({
        phase: "effect",
        state: "unknown_outcome",
        result: result.host,
      });
      expect(frames.some((f) => f.state === "cancelled")).toBe(false);
    } finally {
      // A failed assertion must never leave the host stopped during teardown.
      testHost.kill("SIGCONT");
      await writeFile(join(dir, "release-wrapper"), "");
    }
  },
);

it("C10 wire: held pipe has bounded drain and never supplies cancellation evidence", async () => {
  await setup("held-pipe");
  await until(() => exists("armed"), "writer armed");
  await until(() => exists("holder-pid"), "independent pipe holder acquired descriptor");
  await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
  await processSandboxOutboxBatch();
  await until(
    () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
    "bounded drain deadline while pipe remains held",
  );
  expect(await exists("release-pipe")).toBe(false);
  expect(frames.some((f) => f.state === "cancelled")).toBe(false);
  expect((await receipt()).phase).toBe("effect");
});

it("C10 wire: expiry fences the old writer but CANCELLED waits for the host stop observation", async () => {
  await setup("normal");
  await until(() => exists("armed"), "writer armed");
  store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(Date.now() - 1);
  db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
  await processSandboxOutboxBatch();
  expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
  expect(await exists("stop-entered")).toBe(false);
  db.$queryRaw.mockResolvedValue([]);
  await processSandboxOutboxBatch();
  await until(() => exists("stop-entered"), "stop effect reached host barrier");
  expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
  await writeFile(join(dir, "write-before"), "");
  await until(() => exists("write-before-done"), "writer still runs while stop blocked");
  await writeFile(join(dir, "release-stop"), "");
  await until(
    () => store.sandboxes.get("sbx-1")!.state === "STOPPED",
    "positive lifecycle observation",
  );
  expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
});

it.each(["readiness-create", "readiness-reconnect"])(
  "C14 %s: runtime → relay → durable journal/restart → server cleanup",
  async (mode) => {
    await setup(mode);
    await until(
      () => store.operations.get("op-1")!.state === "FAILED",
      "readiness cleanup committed",
      // The create's own result: bounded like the bootstrap create.
      BOOTSTRAP_TIMEOUT_MS,
    );
    expect(
      frames.find((frame) => frame.type === "operation.result" && frame.operationId === "op-1"),
    ).toMatchObject({
      state: "unknown_outcome",
      error: { code: "guest_unavailable", reason: "guest_user" },
    });
    expect(await receipt()).toMatchObject({
      phase: "effect",
      state: "unknown_outcome",
      errorCode: "guest_unavailable",
      readinessReason: "guest_user",
    });
    // The failed check reaches the operator-visible detail (fixed text).
    const detail =
      "Sandbox guest readiness failed (guest_user: the template's guest user, uid or gid does not match); cleanup queued.";
    expect(store.operations.get("op-1")).toMatchObject({ errorDetail: detail });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({ lastErrorDetail: detail });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "STOPPING",
      generation: 2,
      liveResourcesHeld: true,
    });
    expect(store.hosts.get("host-1")!.liveCount).toBe(1);
    const cleanup = [...store.operations.values()].filter((op) => op.kind === "KILL_SANDBOX");
    expect(cleanup).toHaveLength(1);
    expect(
      [...store.outbox.values()].some((event) => event.payload.operationId === cleanup[0]!.id),
    ).toBe(true);
    // Lose the connection before cleanup: the same diagnostic survives journal
    // reopening, runtime reconciliation and the actual operation.receipt frame.
    await crashHost();
    // Even disappearance during downtime cannot erase the durable diagnostic.
    if (mode === "readiness-reconnect") await writeFile(join(dir, "deleted"), "");
    frames.length = 0;
    await startHost();
    await until(
      () => frames.some((frame) => frame.type === "operation.receipt"),
      "readiness receipt replay",
      SESSION_TIMEOUT_MS,
    );
    expect(frames.find((frame) => frame.type === "operation.receipt")).toMatchObject({
      state: "unknown_outcome",
      error: { code: "guest_unavailable", reason: "guest_user" },
    });
    await until(() => manager.isHostConnected("host-1"), "reconciled host");
    await processSandboxOutboxBatch();
    await until(
      () => store.sandboxes.get("sbx-1")!.state === "DELETED",
      "confirmed readiness cleanup",
      // The cleanup kill's own lifecycle result (stop and delete).
      BOOTSTRAP_TIMEOUT_MS,
    );
    expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(false);
    expect(store.hosts.get("host-1")!.liveCount).toBe(0);
    expect([...store.operations.values()].filter((op) => op.kind === "KILL_SANDBOX")).toHaveLength(
      1,
    );
  },
  CASE_BUDGET.sessionAndTwoLifecycles,
);

it("root growth wire: a create whose root did not grow fails root_disk_not_grown and is destroyed", async () => {
  await setup("readiness-create-disk");
  await until(
    () => store.operations.get("op-1")!.state === "FAILED",
    "readiness cleanup committed",
    // The create's own result: bounded like the bootstrap create.
    BOOTSTRAP_TIMEOUT_MS,
  );
  expect(
    frames.find((frame) => frame.type === "operation.result" && frame.operationId === "op-1"),
  ).toMatchObject({
    state: "unknown_outcome",
    error: { code: "guest_unavailable", reason: "root_disk_not_grown" },
  });
  // The helper measured against the create's own root disk.
  const disks = (await readFile(join(dir, "root-execs"), "utf8")).trim().split("\n");
  expect(disks.length).toBeGreaterThan(0);
  expect(store.operations.get("op-1")).toMatchObject({ errorCode: "root_disk_not_grown" });
  expect(store.sandboxes.get("sbx-1")).toMatchObject({ state: "STOPPING", generation: 2 });
  expect([...store.operations.values()].filter((op) => op.kind === "KILL_SANDBOX")).toHaveLength(1);
});

it("guestSudo wire: a create whose image grants root statically fails guest_root_granted and is destroyed", async () => {
  await setup("readiness-create-root");
  await until(
    () => store.operations.get("op-1")!.state === "FAILED",
    "readiness cleanup committed",
    // The create's own result: bounded like the bootstrap create.
    BOOTSTRAP_TIMEOUT_MS,
  );
  expect(
    frames.find((frame) => frame.type === "operation.result" && frame.operationId === "op-1"),
  ).toMatchObject({
    state: "unknown_outcome",
    error: { code: "guest_unavailable", reason: "guest_root_granted" },
  });
  // The audit ran (guestSudo off, no guest root): never a grant.
  expect((await readFile(join(dir, "sudo-execs"), "utf8")).trim().split("\n")).toContain(
    "revoke-audit",
  );
  expect(store.operations.get("op-1")).toMatchObject({ errorCode: "guest_root_granted" });
  // Cleanup is unchanged: a create is destroyed.
  expect(store.sandboxes.get("sbx-1")).toMatchObject({ state: "STOPPING", generation: 2 });
  expect([...store.operations.values()].filter((op) => op.kind === "KILL_SANDBOX")).toHaveLength(1);
});

it("guestSudo wire: a guestRoot sandbox's UNKNOWN command is killed once, parked while the VM runs, and retires only after the VM stops", {
  timeout: CASE_BUDGET.fourSessions,
}, async () => {
  await setup("guest-root", false, undefined, undefined, CARRIED_COMMAND_TIMEOUT_MS);
  await until(() => exists("armed"), "writer armed");
  rejectAdoption = true;
  const reconciled = frames.filter((f) => f.type === "reconcile.complete").length;
  peer?.terminate();
  await until(
    () =>
      frames.filter((f) => f.type === "reconcile.complete").length > reconciled &&
      manager.isHostConnected("host-1"),
    "daemon reconnected after the refusal",
    // Two reconnects, as above.
    2 * SESSION_TIMEOUT_MS,
  );
  await until(
    () => store.operations.get("op-1")!.state === "UNKNOWN_OUTCOME",
    "revoked work is uncertain",
  );
  await until(async () => (await receipt())?.state === "unknown_outcome", "journal UNKNOWN");
  const pgid = Number(await readFile(join(dir, "guest-pgid"), "utf8"));
  rejectAdoption = false;
  dropConfirmation = false;
  await dropAndReconnect();
  await until(async () => (await retireExecs()).length > 0, "root retire helper ran", 20_000);
  // The due kill ran for its effect (the group is dead) ...
  expect((await retireExecs())[0]).toBe(
    `kill-deadline wssp-cmd-op-1-1-1.scope ${CARRIED_COMMAND_TIMEOUT_MS}`,
  );
  await until(() => {
    try {
      process.kill(-pgid, 0);
      return false;
    } catch {
      return true;
    }
  }, "the guest group is dead");
  // ... but its guest verdict proves nothing: the receipt is parked and
  // never timer-retried while the same VM runs.
  await delay(3000);
  expect(await receipt()).toBeDefined();
  expect(await retireExecs()).toHaveLength(1);
  // The VM stops (out of band): the next replay retires it on host proof
  // alone, with no further guest exec.
  await writeFile(join(dir, "release-stop"), "");
  await execFileAsync(join(dir, "incus"), ["stop", "wssp-sbx-sbx-1"]);
  await dropAndReconnect();
  await until(async () => !(await receipt()), "retired after the stop", 30_000);
  // Retired on host proof alone: no further guest exec. (The observed stop
  // then settles the server row like any stopped sandbox.)
  expect(await retireExecs()).toHaveLength(1);
});

it.each([false, true])(
  "C20 saved device login → real relay middleware (host mismatch: %s)",
  async (mismatch) => {
    vi.clearAllMocks();
    store = relayStore();
    store.hosts.get("host-1")!.connectionEpoch = 0;
    store.hosts.set("other-host", { ...store.hosts.get("host-1")!, id: "other-host" });
    installFenceTransaction(db, store);
    db.$queryRaw.mockResolvedValue([]);
    db.appSetting.findMany.mockResolvedValue([]);
    const credential = generateProductCredentialSecret("deviceCredential");
    db.hostDeviceCredential.findUnique.mockResolvedValue({
      id: "device-1",
      userId: "user-1",
      sandboxHostId: mismatch ? "other-host" : "host-1",
      SandboxHost: { userId: "user-1", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: hmacDigestForProductPurpose({
        purpose: "deviceCredential",
        value: credential.raw,
      }),
      revokedAt: null,
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: true,
        createdAt: new Date("2020-01-01"),
        role: "user",
      },
    } as never);
    db.hostDeviceCredential.update.mockResolvedValue({ id: "device-1" } as never);
    const app = new Hono<{ Variables: { sandboxRelayIdentity: SandboxHostWebsocketIdentity } }>();
    app.use("/ws/sandbox-host", createSandboxRelayWebsocketMiddleware());
    app.get("/ws/sandbox-host", (c) => c.json(c.get("sandboxRelayIdentity")));
    const identities = new WeakMap<object, SandboxHostWebsocketIdentity>();
    const seen: Record<string, unknown>[] = [];
    const output: string[] = [];
    const http = createServer(async (request, response) => {
      const body: Buffer[] = [];
      for await (const chunk of request) body.push(Buffer.from(chunk));
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/api/auth/device/code") {
        expect(JSON.parse(Buffer.concat(body).toString()).scope).toBe("host-slug:desk-01");
        response.end(
          JSON.stringify({
            device_code: "fixture-code",
            user_code: "TEST-CODE",
            verification_uri: "https://web.example.test/device",
            expires_in: 30,
            interval: 1,
          }),
        );
      } else {
        expect(request.url).toBe("/rpc/hostCredentials/exchangeDeviceCode");
        expect(request.headers["x-csrf-token"]).toBe("orpc");
        expect(JSON.parse(Buffer.concat(body).toString())).toEqual({
          json: { deviceCode: "fixture-code", hostSlug: "desk-01" },
        });
        response.end(
          JSON.stringify({
            json: {
              credentialId: "device-1",
              userId: "user-1",
              hostId: "host-1",
              secret: credential.raw,
            },
          }),
        );
      }
    });
    const ws = new WebSocketServer({
      server: http,
      verifyClient: (info, done) => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(info.req.headers))
          if (typeof value === "string") headers.set(key, value);
        void Promise.resolve(app.request("/ws/sandbox-host", { headers }))
          .then(async (response) => {
            if (response.status !== 200) {
              done(false, response.status);
              return;
            }
            identities.set(info.req, (await response.json()) as SandboxHostWebsocketIdentity);
            done(true);
          })
          .catch(() => done(false, 500));
      },
    });
    let devicePeer: WebSocket | undefined;
    ws.on("connection", (socket, request) => {
      devicePeer = socket;
      const identity = identities.get(request);
      if (!identity) throw new Error("middleware identity missing");
      const adapter = {
        get readyState() {
          return socket.readyState;
        },
        get bufferedAmount() {
          return socket.bufferedAmount;
        },
        send(data: string | ArrayBuffer | Uint8Array) {
          if (typeof data === "string") seen.push(JSON.parse(data));
          socket.send(data);
        },
        close(code?: number, reason?: string) {
          socket.close(code, reason);
        },
      };
      manager.acceptAuthenticatedSocket({ socket: adapter, identity });
      socket.on("message", (data) => manager.handleTextFrame(adapter, data.toString()));
      socket.on("close", () => manager.removeSession(adapter));
    });
    http.listen(0, "127.0.0.1");
    await once(http, "listening");
    const address = http.address();
    if (!address || typeof address === "string") throw new Error("listener missing");
    testKeyServerBinding = `ws://127.0.0.1:${address.port}/ws/sandbox-host`;
    const root = await mkdtemp(join(tmpdir(), "wssp-c20-device-"));
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      WSSP_CONFIG_DIR: join(root, "config"),
      WSSP_DATA_DIR: join(root, "data"),
    };
    for (const key of [
      "ALL_PROXY",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "all_proxy",
      "http_proxy",
      "https_proxy",
      "NO_PROXY",
      "no_proxy",
    ]) {
      delete env[key];
    }
    let deviceHost: ChildProcess | undefined;
    let login: ChildProcess | undefined;
    try {
      login = spawn(
        resolve("target/debug/wssp"),
        [
          "-vv",
          "host",
          "enroll",
          "--slug",
          "desk-01",
          "--server",
          `http://127.0.0.1:${address.port}`,
        ],
        { env, stdio: ["ignore", "pipe", "pipe"] },
      );
      login.stdout!.on("data", (chunk) => output.push(String(chunk)));
      login.stderr!.on("data", (chunk) => output.push(String(chunk)));
      const loginExit = once(login, "exit");
      const loginDeadline = setTimeout(() => login?.kill("SIGKILL"), 15_000);
      expect((await loginExit)[0]).toBe(0);
      clearTimeout(loginDeadline);
      deviceHost = spawn(
        resolve("target/debug/wssp"),
        ["-vv", "host", "run", "--runtime", "fake"],
        {
          env,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      deviceHost.stdout!.on("data", (chunk) => output.push(String(chunk)));
      deviceHost.stderr!.on("data", (chunk) => output.push(String(chunk)));
      if (mismatch) {
        await until(
          () => seen.some((frame) => frame.type === "protocol.error"),
          "host mismatch rejected",
        );
        expect(seen.find((frame) => frame.type === "protocol.error")).toMatchObject({
          message: "Host identity does not match the websocket credential.",
        });
        expect(manager.isHostConnected("host-1")).toBe(false);
        expect(manager.isHostConnected("other-host")).toBe(false);
      } else {
        await until(
          () => manager.isHostConnected("host-1"),
          "saved assigned device host connected",
        );
        expect(seen.some((frame) => frame.type === "hello.ok")).toBe(true);
      }
      expect(db.hostDeviceCredential.update).toHaveBeenCalledOnce();
      expect(db.hostToken.findUnique).not.toHaveBeenCalled();
      expect(output.join("")).not.toContain(credential.raw);
      expect(await readFile(join(root, "config/config.toml"), "utf8")).not.toContain(
        credential.raw,
      );
    } finally {
      devicePeer?.terminate();
      if (login && login.exitCode === null) {
        const stopped = once(login, "exit");
        login.kill("SIGKILL");
        await stopped;
      }
      if (deviceHost && deviceHost.exitCode === null) {
        const stopped = once(deviceHost, "exit");
        deviceHost.kill("SIGKILL");
        await stopped;
      }
      manager.dispose();
      ws.close();
      http.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);

class TerminalSink {
  bufferedAmount = 0;
  bytes = 0;
  text = "";
  readies: { rows: number; cols: number }[] = [];
  closes: Record<string, unknown>[] = [];
  /** When set, every delivered byte stays "buffered" (a browser that never reads). */
  stalled = false;
  sendOutput(bytes: Uint8Array) {
    this.bytes += bytes.byteLength;
    if (this.stalled) this.bufferedAmount += bytes.byteLength;
    if (this.text.length < 4096) this.text += Buffer.from(bytes).toString("latin1");
  }
  ready(size: { rows: number; cols: number }) {
    this.readies.push(size);
  }
  close(notice: Record<string, unknown>) {
    this.closes.push(notice);
  }
}

function openTerminal(sink: TerminalSink) {
  const opened = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    rows: 24,
    cols: 80,
    attachment: sink,
  });
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  return opened.session;
}

it("C52 wire: the real host opens a fenced PTY from its journal and refuses forged input", async () => {
  await setup("terminal-echo");
  const sink = new TerminalSink();
  const session = openTerminal(sink);
  await until(() => sink.readies.length === 1, "terminal ready");
  expect(session.input(new TextEncoder().encode("hello\n")).ok).toBe(true);
  await until(() => sink.text.includes("got:hello"), "echo through the real PTY");
  // The PTY child is "incus exec -t" for the journal-bound sandbox and guest.
  // Read after the echo: "terminal ready" only means the daemon spawned the
  // child; the shim records its argv before it reads input, so the echo
  // proves the record is complete.
  const argv: string[] = JSON.parse(await readFile(join(dir, "pty-argv"), "utf8"));
  expect(argv).toContain("-t");
  expect(argv.slice(argv.indexOf("--") + 1)).toEqual(["/bin/bash"]);
  expect(argv[argv.indexOf("--user") + 1]).toBe("1000");
  expect(argv).toContain("wssp-sbx-sbx-1");
  // Forged input frames straight onto the host socket: wrong generation,
  // epoch and operation. The host writes ZERO bytes and, on the third
  // violation, closes the session with an explicit protocol_violation.
  const open = frames.length; // frames only holds host->server text
  const fence = manager.terminals.sessionFence(session.sessionId)!;
  const forged = (change: Record<string, unknown>, text: string) =>
    peer!.send(
      Buffer.from(
        encodeTerminalDataFrame(
          { type: "terminal.data", fence: { ...fence, ...change }, sequence: 1 },
          new TextEncoder().encode(text),
        ),
      ),
    );
  forged({ target: { kind: "sandbox", sandboxId: "sbx-1", generation: 2 } }, "forged-a\n");
  forged({ epoch: Number(fence.epoch) + 1 }, "forged-b\n");
  await delay(300);
  expect(sink.text).not.toContain("forged");
  expect(sink.closes).toEqual([]);
  forged({ operationId: "topforged" }, "forged-c\n");
  await until(() => sink.closes.length === 1, "violation close");
  expect(sink.closes[0]).toMatchObject({ code: 4401, intent: "protocol_violation" });
  expect(sink.text).not.toContain("forged");
  const exit = frames.slice(open).find((f) => f.type === "terminal.exit");
  expect(exit).toMatchObject({ intent: "protocol_violation", reaped: true });
  expect(manager.terminals.sessionCount()).toBe(0);
});

it("C52 wire: a PTY flood keeps heartbeats and control moving, then a stalled browser is detached with 4401", {
  timeout: CASE_TIMEOUT_MS,
}, async () => {
  await setup("terminal-flood");
  const sink = new TerminalSink();
  openTerminal(sink);
  await until(() => sink.readies.length === 1, "terminal ready");
  await until(() => sink.bytes > 1024 * 1024, "flood flowing");
  const heartbeatsBefore = frames.filter((f) => f.type === "heartbeat").length;
  // Server->host control during the flood: a live probe round trip.
  const probeStarted = Date.now();
  const probe = await manager.probeSandbox({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    incusFingerprint: "sha256:" + "abcdef0123456789".repeat(4),
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
  });
  expect(Date.now() - probeStarted).toBeLessThan(10_000);
  expect(frames.some((f) => f.type === "sandbox.probe.result")).toBe(true);
  expect(probe).not.toBe("unreachable");
  await until(
    () => frames.filter((f) => f.type === "heartbeat").length > heartbeatsBefore,
    "host heartbeat during the flood",
  );
  expect(sink.closes).toEqual([]);
  // The browser stops reading: its buffer passes the bound and it is
  // detached with the explicit backpressure error, never left half-open.
  sink.stalled = true;
  await until(() => sink.closes.length === 1, "backpressure detach");
  expect(sink.closes[0]).toMatchObject({
    code: 4401,
    intent: "backpressure",
    error: { code: "rate_limited" },
  });
  expect(sink.bufferedAmount).toBeLessThanOrEqual(1024 * 1024);
  await until(() => frames.some((f) => f.type === "terminal.exit"), "host closed the PTY");
  expect(frames.find((f) => f.type === "terminal.exit")).toMatchObject({
    intent: "backpressure",
    reaped: true,
  });
  expect(manager.terminals.sessionCount()).toBe(0);
});

class ResumableSink extends TerminalSink {
  readonly resumable = true;
  frames = 0;
  resumes: { terminalId: string; outputSeq: number }[] = [];
  override sendOutput(bytes: Uint8Array) {
    this.frames += 1;
    super.sendOutput(bytes);
  }
  override ready(
    size: { rows: number; cols: number },
    resume?: { terminalId: string; outputSeq: number },
  ) {
    super.ready(size);
    if (resume) this.resumes.push(resume);
  }
}

it("WP8 wire: a sandbox PTY survives a relay drop and the real host resumes it once", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("terminal-echo");
  const hello = frames.find((f) => f.type === "hello") as
    | { daemon: { capabilities: Record<string, unknown> } }
    | undefined;
  expect(hello?.daemon.capabilities.terminalResume).toEqual({ graceMs: 120_000 });
  const first = new ResumableSink();
  const opened = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    rows: 24,
    cols: 80,
    attachment: first,
  });
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  await until(() => first.resumes.length === 1, "resumable terminal ready");
  const terminalId = first.resumes[0]!.terminalId;
  expect(opened.session.input(new TextEncoder().encode("hello\n")).ok).toBe(true);
  await until(() => first.text.includes("got:hello"), "echo before the drop");
  // The PTY child exists once; a resume must never start another.
  await rm(join(dir, "pty-argv"));

  await dropAndReconnect();
  await until(() => first.closes.length === 1, "reconnect notice");
  expect(first.closes[0]).toMatchObject({ reconnect: { terminalId, graceMs: 120_000 } });
  // The daemon closed nothing: no exit for the terminal on the new connection.
  const resumedAt = frames.length;

  const second = new ResumableSink();
  const resumed = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    rows: 30,
    cols: 100,
    resume: { terminalId, nextOutputSeq: first.frames },
    attachment: second,
  });
  if (!resumed.ok) throw new Error(JSON.stringify(resumed.error));
  await until(() => second.resumes.length === 1, "resume answered");
  expect(second.resumes[0]).toEqual({ terminalId, outputSeq: first.frames });
  expect(second.readies[0]).toEqual({ rows: 30, cols: 100 });
  expect(frames.slice(resumedAt).find((f) => f.type === "terminal.ready")).toMatchObject({
    outputSeq: first.frames,
  });
  // Input restarts at 0 on the new fence; nothing typed before is replayed.
  expect(resumed.session.input(new TextEncoder().encode("again\n")).ok).toBe(true);
  await until(() => second.text.includes("got:again"), "echo through the resumed PTY");
  await delay(200);
  expect(second.text).not.toContain("hello");
  expect(second.text.split("got:again").length).toBe(2);
  expect(frames.slice(resumedAt).some((f) => f.type === "terminal.exit")).toBe(false);
  expect(await exists("pty-argv")).toBe(false);
  expect(failures.join("")).not.toMatch(/panicked/);
});

it("WP8 wire (live P1): another server process revoking the epoch under a live relay leaves the PTY to the real host, which resumes it after the drop", {
  timeout: CASE_BUDGET.oneSession,
}, async () => {
  await setup("terminal-echo");
  const first = new ResumableSink();
  const opened = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    rows: 24,
    cols: 80,
    attachment: first,
  });
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  await until(() => first.resumes.length === 1, "resumable terminal ready");
  const terminalId = first.resumes[0]!.terminalId;
  expect(opened.session.input(new TextEncoder().encode("hello\n")).ok).toBe(true);
  await until(() => first.text.includes("got:hello"), "echo before the sweep");
  await rm(join(dir, "pty-argv"));
  // A start-first deploy: the new process's boot sweep revokes the epoch of
  // the connection this (old) process still holds.
  const { disconnectJournalKey } = await import("./journal-key-ack.js");
  const swept = store.hosts.get("host-1")!.connectionEpoch;
  await disconnectJournalKey(
    { hostId: "host-1", userId: "user-1", connectionEpoch: swept },
    new Date(),
    true,
  );
  expect(store.hosts.get("host-1")!.connectionEpoch).toBe(swept + 1);
  const sweptAt = frames.length;
  // The old process's re-read verdict for the binding (BrowserTerminal.end).
  opened.session.close("host_disconnected");
  expect(first.closes).toEqual([
    expect.objectContaining({
      intent: "host_disconnected",
      reconnect: { terminalId, graceMs: 120_000 },
    }),
  ]);
  await delay(300);
  // No terminal.close reached the node: it ended nothing.
  expect(frames.slice(sweptAt).some((f) => f.type === "terminal.exit")).toBe(false);

  // The old process drains; the node reconnects (to the new one) and detaches.
  await dropAndReconnect();
  const resumedAt = frames.length;
  const second = new ResumableSink();
  const resumed = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    sandboxId: "sbx-1",
    generation: 1,
    rows: 24,
    cols: 80,
    resume: { terminalId, nextOutputSeq: first.frames },
    attachment: second,
  });
  if (!resumed.ok) throw new Error(JSON.stringify(resumed.error));
  await until(() => second.resumes.length === 1, "resume answered");
  expect(second.resumes[0]).toEqual({ terminalId, outputSeq: first.frames });
  expect(resumed.session.input(new TextEncoder().encode("again\n")).ok).toBe(true);
  await until(() => second.text.includes("got:again"), "echo through the same PTY");
  expect(frames.slice(resumedAt).some((f) => f.type === "terminal.exit")).toBe(false);
  // The same shell: no second PTY child was ever started.
  expect(await exists("pty-argv")).toBe(false);
  expect(failures.join("")).not.toMatch(/panicked/);
});

/**
 * C53 wire: the browser plane end to end against the REAL node daemon. A
 * cookie session + one-use ticket upgrade opens a PTY on the real `wssp host
 * run` (its fake incus records the `exec -t` argv); a replayed ticket and
 * a host credential on the browser endpoint allocate no PTY at the host.
 */
it("C53 wire: cookie-session upgrade drives the real host PTY; replay and wrong plane allocate none", async () => {
  await setup("terminal-echo");
  const sandbox = {
    state: "READY",
    generation: 1,
    sandboxHostId: "host-1",
    leaseExpiresAt: null,
    hostOwnerId: "user-1",
    SandboxHost: {
      userId: "user-1",
      connectionEpoch: store.hosts.get("host-1")!.connectionEpoch,
      deletionRequestedAt: null,
    },
    SandboxTemplateRevision: { defaultCwd: null },
  };
  bindHostTerminalPolicy({
    read: () => undefined,
    raise: async () => false,
    authorize: (hostId, ownerId, epoch, tx) =>
      manager.authorizeTerminalTransport(hostId, ownerId, epoch, tx),
  });
  const tickets = new Map<string, Record<string, unknown>>();
  browserAuth.getSession.mockImplementation(async ({ headers }: { headers: Headers }) =>
    headers.get("cookie") === "sid=auth-1"
      ? { user: { id: "user-1" }, session: { id: "auth-1", userId: "user-1" } }
      : null,
  );
  db.session.findUnique.mockResolvedValue({ id: "auth-1" } as never);
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: true,
    role: "user",
    emailVerified: true,
    banned: false,
    banExpires: null,
    createdAt: new Date("2020-01-01"),
    deletionRequestedAt: null,
  } as never);
  db.appSetting.findMany.mockResolvedValue([]);
  db.sandbox.findFirst.mockImplementation(((args: { where: Record<string, unknown> }) => {
    const where = Array.isArray(args.where.AND)
      ? Object.assign({}, ...(args.where.AND as Record<string, unknown>[]))
      : args.where;
    return prismaPromise(
      Promise.resolve(
        (where.id === "sbx-1" && where.userId === "user-1"
          ? { id: "sbx-1", purpose: "WORKLOAD", buildId: null, ...sandbox }
          : null) as never,
      ),
    );
  }) as never);
  db.sandboxTerminalTicket.deleteMany.mockResolvedValue({ count: 0 } as never);
  db.sandboxTerminalTicket.create.mockImplementation(((args: { data: Record<string, unknown> }) => {
    tickets.set(String(args.data.tokenDigest), { ...args.data });
    return prismaPromise(Promise.resolve({ id: "ticket" } as never));
  }) as never);
  db.$queryRaw.mockImplementation(((strings: TemplateStringsArray, ...values: unknown[]) => {
    if (!/"sandbox_browser_terminal_ticket"[\s\S]*RETURNING/.test(strings.join("?")))
      return prismaPromise(Promise.resolve([] as never));
    const row = tickets.get(String(values[0]));
    tickets.delete(String(values[0]));
    return prismaPromise(Promise.resolve((row ? [row] : []) as never));
  }) as never);
  const app = new Hono();
  app.use(BROWSER_TERMINAL_ROUTE, createBrowserTerminalUpgradeMiddleware());
  app.get(BROWSER_TERMINAL_ROUTE, browserTerminalUpgradeHandler());
  const browserServer = serve({
    fetch: app.fetch,
    port: 0,
    hostname: "127.0.0.1",
    websocket: {
      server: new WebSocketServer({
        noServer: true,
        handleProtocols: (protocols, request) => selectWebSocketSubprotocol(protocols, request.url),
      }),
    },
  });
  try {
    await once(browserServer, "listening");
    const address = browserServer.address();
    if (typeof address !== "object" || !address) throw new Error("missing listener");
    const base = `127.0.0.1:${address.port}`;
    const mint = async () => {
      const { ticket } = await mintTerminalTicket(
        { userId: "user-1", sessionId: "auth-1" },
        { sandboxId: "sbx-1", rows: 24, cols: 80 },
      );
      return ["wssp.terminal.v1", `wssp.terminal.ticket.${ticket}`];
    };
    const attempt = (protocols: string[], authorization?: string) =>
      upgradeBrowserTerminal({
        base,
        path: "/api/dashboard/sandboxes/sbx-1/terminal/ws",
        protocols,
        cookie: "sid=auth-1",
        origin: "https://app.example.test",
        ...(authorization ? { authorization } : {}),
      });
    const terminalFrames = () => frames.filter((f) => String(f.type).startsWith("terminal."));

    // Happy path: the real host opens a PTY for the journal-bound sandbox.
    const protocols = await mint();
    const browser = await attempt(protocols);
    if (browser.kind !== "open") throw new Error(`refused: ${JSON.stringify(browser)}`);
    expect(browser.protocol).toBe("wssp.terminal.v1");
    await until(() => browser.text.some((f) => f.type === "ready"), "browser ready");
    // Ready proves spawn; the shim still has to run before its argv file exists.
    await until(() => exists("pty-argv"), "PTY shim recorded its argv");
    browser.sendBinary(Buffer.from("hello\n"));
    await until(() => browser.binary.join("").includes("got:hello"), "echo through the real PTY");
    browser.sendText(JSON.stringify({ type: "close", requestId: "bye" }));
    expect(await browser.closed).toEqual({ code: 4401, reason: "client" });
    await until(
      () => frames.some((f) => f.type === "terminal.exit" && f.intent === "client"),
      "host reaped the PTY",
    );
    expect(frames.find((f) => f.type === "terminal.exit")).toMatchObject({ reaped: true });
    await until(() => manager.terminals.sessionCount() === 0, "session released");

    // Refused legs: no new terminal frame from the host and no new PTY exec.
    await rm(join(dir, "pty-argv"), { force: true });
    const before = terminalFrames().length;
    const replay = await attempt(protocols);
    expect(replay).toMatchObject({ kind: "refused", status: 401, refusal: "TICKET_INVALID" });
    const wrongPlane = await attempt(await mint(), `Bearer wssp_host_${"B".repeat(43)}`);
    expect(wrongPlane).toMatchObject({ kind: "refused", status: 401, refusal: "CREDENTIAL_PLANE" });
    // A veto installed after mint still refuses binding before any daemon PTY
    // allocation. Exercise the fresh durable read, rather than mocking it on.
    const vetoedProtocols = await mint();
    store.hosts.get("host-1")!.hostTerminalVetoedAt = new Date();
    const vetoed = await attempt(vetoedProtocols);
    if (vetoed.kind !== "open") throw new Error(`refused: ${JSON.stringify(vetoed)}`);
    expect(await vetoed.closed).toEqual({ code: 4401, reason: "revoked" });
    expect(vetoed.text.some((f) => f.type === "ready")).toBe(false);
    await delay(500);
    expect(terminalFrames()).toHaveLength(before);
    expect(await exists("pty-argv")).toBe(false);
    expect(manager.terminals.sessionCount()).toBe(0);
  } finally {
    killBrowserClients();
    db.sandbox.findFirst.mockReset();
    db.$queryRaw.mockReset();
    await new Promise<void>((resolve) => browserServer.close(() => resolve()));
  }
});
