/**
 * WP1 reconnect chaos cells (reconnect plan rev 4, WP1; matrix in
 * `relay-chaos-matrix.ts`). Each cell runs the REAL debug `wssp` daemon
 * against the incus shim of `cancel-wire-fixtures.ts`, through the loopback
 * fault proxy (`relay-fault-proxy-harness.ts`), to the real relay session
 * manager over the fenced Prisma store. No Incus, no live VM.
 *
 * Server faults:
 * - SrvR: `dispose()` (sessions removed, disconnects written), then a new
 *   `SandboxRelaySessionManager` on the same store, after the boot sweep.
 * - SrvX: no dispose and no disconnect write; the proxy resets both sides,
 *   the old manager is abandoned, and the new one boots with the sweep.
 * - DmnR: the daemon exits (SIGKILL, or a finished quiesce) and is respawned
 *   on the same data dir.
 * - Slow DB: the fenced store's commit barrier.
 *
 * Every cell asserts (`expectCell`): the final state is in the cell's allowed
 * set; at most one effect per (op, attempt) (each command logs its start);
 * no UNKNOWN_OUTCOME ever committed in a `safe` cell; the daemon is still
 * alive; after quiescence no unconfirmed journal receipt, no unprocessed
 * outbox row, and output byte-exact (or an explicit gap where allowed).
 *
 * Ordering is by proxy holds, frame waits, file barriers and the debug
 * timing knob (`WSSP_TEST_RELAY_TIMING`), never by sleeps. The only waits on
 * the clock are a fault's own duration (an outage, a slow DB) and the
 * daemon's deadlines the knob shortens.
 */
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/api/lib/host-token-access", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wssp/api/lib/host-token-access")>()),
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));
// The real daemon binds its journal key to the relay URL it dials: here the
// fault proxy's.
vi.mock("@wssp/api/sandbox/idempotency", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@wssp/api/sandbox/idempotency")>();
  return {
    ...actual,
    hostJournalKey: (owner: string, host: string) => {
      if (!chaos.keyBinding) throw new Error("test relay not listening");
      return actual.hostJournalKey(owner, host, chaos.keyBinding);
    },
  };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_SECRET: "service-principal-test",
    BETTER_AUTH_URL: "https://app.example.test",
  },
}));
vi.mock("../rate-limit.js", () => ({
  authLimiter: {},
  terminalUpgradeLimiter: {},
  createRateLimiterMiddleware: () => async (_context: unknown, next: () => Promise<void>) => {
    await next();
  },
}));
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession: vi.fn() } } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
/**
 * SrvR/SrvX need a NEW session manager on the same store. Every importer of
 * the process singleton (outbox processor, terminals) gets this handle, which
 * forwards to whichever manager is current.
 */
const chaos = vi.hoisted(() => ({
  keyBinding: undefined as string | undefined,
  current: undefined as object | undefined,
}));
vi.mock("./session-manager.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./session-manager.js")>();
  chaos.current = actual.sandboxRelaySessionManager;
  const handle = new Proxy(
    {},
    {
      get(_target, key) {
        const current = chaos.current as Record<PropertyKey, unknown>;
        const value = Reflect.get(current, key, current);
        return typeof value === "function" ? value.bind(current) : value;
      },
    },
  ) as typeof actual.sandboxRelaySessionManager;
  return { ...actual, sandboxRelaySessionManager: handle };
});

import { type ChildProcess, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import prisma from "@wssp/db";
import { afterEach, expect, it, vi } from "vitest";
import { type WebSocket, WebSocketServer } from "ws";
import faultMatrix from "../../../../crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json";
import { cancelOperation } from "../../../../packages/api/src/sandbox/services/sandboxes";
import {
  bootstrapHostLease,
  type FakeGuard,
  installWireDelegates,
  readListedFile,
  releaseWireFixture,
  removeWireDir,
  spawnWireHost,
  startFakeGuard,
  stopWireHost,
  WIRE_FINGERPRINT,
  wireStore,
  writeBootstrapVm,
  writeWireShim,
} from "./cancel-wire-fixtures.js";
import {
  type FenceStore,
  matches,
  type OperationRow,
  type OutboxRow,
  prismaPromise,
  storedCommandOutput,
} from "./fenced-prisma-harness.js";
import { sweepConnectedHosts } from "./host-liveness.js";
import { processSandboxOutboxBatch } from "./outbox-processor.js";
import {
  RELAY_CHAOS_MATRIX,
  type RelayChaosCell,
  type RelayChaosSubset,
  relayChaosCells,
} from "./relay-chaos-matrix.js";
import { RelayFaultProxy, type RelayFrameMatch } from "./relay-fault-proxy-harness.js";
import { SandboxRelaySessionManager, type SandboxRelaySocket } from "./session-manager.js";

const db = vi.mocked(prisma, true);

/** The shared cross-language `carry` rows the outage cells (C12, C13) prove end to end. */
function carryRow(id: string) {
  const row = faultMatrix.carry.find((candidate) => candidate.id === id);
  if (!row) throw new Error(`lifecycle_fault_matrix.json has no carry row ${id}`);
  return {
    state: row.expect.operation.toUpperCase(),
    errorCode: row.expect.operationErrorCode ?? undefined,
  };
}

// ---- per-case state ---------------------------------------------------------

let store: FenceStore;
let dir = "";
let host: ChildProcess | undefined;
let guard: FakeGuard | undefined;
let server: WebSocketServer | undefined;
let proxy: RelayFaultProxy | undefined;
/** The server's side of the daemon's latest relay socket. */
let peer: WebSocket | undefined;
/** Managers that "died" (SrvX): their sockets get no further handling. */
const dead = new Set<SandboxRelaySessionManager>();
const managers: SandboxRelaySessionManager[] = [];
const failures: string[] = [];
const receivedFrames = new EventEmitter();
/** Every committed state of every operation, in commit order. */
const history = new Map<string, string[]>();
/** Server-side receive pauses (P0-2 backpressure) and close codes. */
const serverSockets = { pauses: 0, closes: [] as number[] };
/** Snapshots taken at setup, before op-1 is dispatched (C15's op-2). */
let seed: { operation: OperationRow; event: OutboxRow } | undefined;

function manager(): SandboxRelaySessionManager {
  return chaos.current as SandboxRelaySessionManager;
}

function newManager(options: ManagerOptions = {}) {
  const created = new SandboxRelaySessionManager({ maxSocketsPerHost: 2, ...options });
  managers.push(created);
  chaos.current = created;
  return created;
}

type ManagerOptions = { pingIntervalMs?: number; livenessTimeoutMs?: number };

async function until(check: () => boolean | Promise<boolean>, label: string, boundMs = 20_000) {
  const deadline = Date.now() + boundMs;
  while (!(await check())) {
    if (Date.now() > deadline) {
      const tail = (proxy?.frames ?? [])
        .slice(-40)
        .map((f) => `${f.linkId}:${f.dir}:${f.type}:${f.operationId ?? ""}:${f.disposition}`);
      throw new Error(
        `${label}: ops=${JSON.stringify([...history])}; frames=${tail.join(" ")}; daemon=${failures.join("").slice(-4000)}`,
      );
    }
    await delay(5);
  }
}

const flags = (operationId: string) => join(dir, "flags", operationId);
async function exists(path: string) {
  return readFile(path).then(
    () => true,
    () => false,
  );
}
/** Times the guest command started (`chaosCommand` logs every start). */
async function effects(operationId: string): Promise<number> {
  const log = await readFile(join(flags(operationId), "effects"), "utf8").catch(() => "");
  return log.split("\n").filter(Boolean).length;
}
async function release(operationId: string) {
  await writeFile(join(flags(operationId), "release"), "");
}
async function armed(operationId: string) {
  await until(() => exists(join(flags(operationId), "armed")), `${operationId} command armed`);
}
/** The daemon's journaled receipts (unconfirmed by the server). */
async function journalReceipts(): Promise<Record<string, Record<string, unknown>>> {
  const paths = await readdir(join(dir, "data"), { recursive: true }).catch(() => [] as string[]);
  const found: Record<string, Record<string, unknown>> = {};
  for (const path of paths) {
    const match = /receipts\/([^/]+)\.json$/.exec(path);
    if (!match) continue;
    // Retired between the listing and the read: absent (readListedFile).
    const text = await readListedFile(join(dir, "data", path));
    if (text !== undefined) found[match[1]!] = JSON.parse(text).receipt;
  }
  return found;
}
function daemonAlive() {
  return !!host && host.exitCode === null && host.signalCode === null;
}
function op(id: string) {
  return store.operations.get(id)!;
}
function framesOf(match: RelayFrameMatch, fromSeq = 0) {
  return (proxy?.frames ?? []).filter(
    (frame) =>
      frame.seq >= fromSeq &&
      (typeof match === "function"
        ? match(frame)
        : (match.dir === undefined || frame.dir === match.dir) &&
          (match.type === undefined || frame.type === match.type) &&
          (match.operationId === undefined || frame.operationId === match.operationId)),
  );
}

/** Deterministic output a command writes: `size` bytes, keyed by `seed`. */
function pattern(size: number, salt: number): Buffer {
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 7 + salt) % 251;
  return bytes;
}

/**
 * The guest command of every cell: logs its start, writes its pattern to
 * stdout, marks `armed`, then waits for `release` and exits 0. SIGTERM (a
 * cancel or carry stop) is recorded and exits 143.
 */
const chaosCommand = String.raw`import os, signal, sys, time
from pathlib import Path
flags = Path(sys.argv[1])
size, salt = int(sys.argv[2]), int(sys.argv[3])
with open(flags / "effects", "a") as log:
    log.write(str(os.getpid()) + "\n")
def term(_signal, _frame):
    (flags / "term-observed").touch()
    sys.exit(143)
signal.signal(signal.SIGTERM, term)
data = bytes((i * 7 + salt) % 251 for i in range(size))
for start in range(0, size, 65536):
    sys.stdout.buffer.write(data[start:start + 65536])
    sys.stdout.buffer.flush()
(flags / "armed").touch()
while not (flags / "release").exists():
    time.sleep(0.005)
sys.exit(0)
`;

const DEFAULT_OUTPUT = 4096;

type CellSetup = {
  /** Bytes op-1 writes to stdout before it is armed. */
  outputBytes?: number;
  /** op-1's command timeout. */
  timeoutMs?: number;
  /** `WSSP_TEST_RELAY_TIMING` for the daemon. */
  timing?: string;
  manager?: ManagerOptions;
  /** Dispatch op-1 and wait until the host accepted it (default true). */
  dispatch?: boolean;
};

function commandPayload(operationId: string, size: number, salt: number) {
  return ["python3", join(dir, "command.py"), flags(operationId), String(size), String(salt)];
}

async function setup(options: CellSetup = {}) {
  vi.clearAllMocks();
  failures.length = 0;
  history.clear();
  serverSockets.pauses = 0;
  serverSockets.closes.length = 0;
  store = wireStore("RUN_COMMAND");
  dir = await mkdtemp(join(tmpdir(), "wssp-chaos-"));
  await writeWireShim(dir, "normal");
  await writeBootstrapVm(dir);
  await writeFile(join(dir, "command.py"), chaosCommand);
  for (const id of ["op-1", "op-2"]) await mkdir(flags(id), { recursive: true });
  Object.assign(store.outbox.get("evt-1")!.payload, {
    dispatchAttempt: 0,
    idempotencyKey: "key-1",
    argv: commandPayload("op-1", options.outputBytes ?? DEFAULT_OUTPUT, 1),
    timeoutMs: options.timeoutMs ?? 120_000,
    incusFingerprint: WIRE_FINGERPRINT,
  });
  seed = {
    operation: { ...op("op-1") },
    event: structuredClone(store.outbox.get("evt-1")!),
  };
  installWireDelegates(
    prisma,
    store,
    (where) => [...store.operations.values()].find((row) => matches(row, where)) ?? null,
  );
  // The boot sweep (WP4) pages hosts outside a write transaction.
  db.sandboxHost.findMany.mockImplementation((args) =>
    prismaPromise(prisma.$transaction((tx) => tx.sandboxHost.findMany(args))),
  );
  // Every committed operation state, for the no-UNKNOWN assertion.
  store.barriers.afterCommit = async () => {
    for (const row of store.operations.values()) {
      const states = history.get(row.id) ?? [];
      if (states.at(-1) !== row.state) states.push(String(row.state));
      history.set(row.id, states);
    }
  };
  newManager(options.manager);
  server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  server.on("connection", acceptRelaySocket);
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test relay not listening");
  proxy = await RelayFaultProxy.start({ upstream: `ws://127.0.0.1:${address.port}` });
  chaos.keyBinding = `${proxy.url}/ws/sandbox-host`;
  // The fresh host holds no instance yet; a placed READY row would be
  // converged to `instance_missing` by its first complete census.
  const seeded = store.sandboxes.get("sbx-1")!;
  const seededState = seeded.state;
  seeded.state = "PROVISIONING";
  await startHost(options.timing);
  await until(() => manager().isHostConnected("host-1"), "host registered and reconciled", 125_000);
  await until(() => (guard?.pushes() ?? 0) > 0, "deployment blocklist pushed to the guard");
  await until(
    () => store.hosts.get("host-1")?.daemonEgressGuardOk === true,
    "healthy egress guard lease reported",
  );
  seeded.state = seededState;
  await bootstrapHostLease({
    dir,
    store,
    send: (frame) => peer!.send(frame),
    result: bootstrapResult,
    until: (check, label) => until(check, label, 125_000),
  });
  if (options.dispatch === false) return;
  await processSandboxOutboxBatch();
  await until(() => op("op-1").acceptedAttempt === 1, "host accepted op-1");
}

function bootstrapResult(operationId: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      receivedFrames.off("frame", onFrame);
      reject(new Error("bootstrap lease result exceeded the readiness and relay deadline"));
    }, 125_000);
    const onFrame = (frame: Record<string, unknown>) => {
      if (frame.type !== "operation.result" || frame.operationId !== operationId) return;
      clearTimeout(timer);
      receivedFrames.off("frame", onFrame);
      resolve(frame);
    };
    receivedFrames.on("frame", onFrame);
  });
}

/** The relay endpoint: each socket belongs to the manager current at accept. */
function acceptRelaySocket(socket: WebSocket) {
  const owner = manager();
  peer = socket;
  const adapter: SandboxRelaySocket = {
    get readyState() {
      return socket.readyState;
    },
    get bufferedAmount() {
      return socket.bufferedAmount;
    },
    send(data) {
      socket.send(data);
    },
    close(code, reason) {
      socket.close(code, reason);
    },
    // P0-2: receive backpressure stops reading the TCP socket.
    pause() {
      serverSockets.pauses += 1;
      socket.pause();
    },
    resume() {
      socket.resume();
    },
    ping() {
      // An abandoned (SrvX) manager's timer may still fire on a closed socket.
      if (socket.readyState === socket.OPEN) socket.ping();
    },
  };
  socket.on("pong", () => {
    if (!dead.has(owner)) owner.notePeerAlive(adapter);
  });
  owner.acceptAuthenticatedSocket({
    socket: adapter,
    identity: {
      hostId: "host-1",
      userId: "user-1",
      tokenId: "token-1",
      credentialKind: "hostToken" as const,
      expiresAt: null,
    },
  });
  socket.on("message", (data, binary) => {
    if (dead.has(owner)) return;
    const bytes = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
    if (binary) {
      owner.handleBinaryFrame(adapter, Uint8Array.from(bytes).buffer);
      return;
    }
    const text = bytes.toString("utf8");
    const frame = JSON.parse(text) as Record<string, unknown>;
    receivedFrames.emit("frame", frame);
    // The setup-only lease bootstrap is owned and confirmed by the harness.
    if (frame.operationId === "lease-bootstrap") return;
    owner.handleTextFrame(adapter, text);
  });
  socket.on("close", (code) => {
    serverSockets.closes.push(code);
    if (!dead.has(owner)) owner.removeSession(adapter);
  });
}

async function startHost(timing?: string) {
  guard ??= await startFakeGuard(join(dir, "guard-root"), join(dir, "networks"));
  host = await spawnWireHost({
    dir,
    serverUrl: proxy!.url,
    env: timing ? { WSSP_TEST_RELAY_TIMING: timing } : {},
  });
  host.stderr!.on("data", (chunk) => failures.push(String(chunk)));
  host.on("error", (error) => failures.push(String(error)));
}

/** The daemon's next session after `epoch` is registered and reconciled. */
async function reconnectedAfter(epoch: number, label = "daemon reconnected and reconciled") {
  await until(
    () =>
      store.hosts.get("host-1")!.connectionEpoch > epoch &&
      manager().isHostConnected("host-1", Number(store.hosts.get("host-1")!.connectionEpoch)),
    label,
    60_000,
  );
}
const epoch = () => Number(store.hosts.get("host-1")!.connectionEpoch);

/**
 * Restart the relay server. `graceful` (SrvR): dispose the manager, which
 * removes every session and writes its disconnect. `crash` (SrvX): no
 * dispose and no disconnect write; the proxy resets both sides and the old
 * manager is abandoned. Either way the new process runs the boot sweep (WP4)
 * before it accepts a socket; the proxy refuses links until then.
 */
async function restartServer(kind: "graceful" | "crash", options?: ManagerOptions) {
  proxy!.outage();
  const old = manager();
  if (kind === "graceful") await old.dispose();
  else {
    dead.add(old);
    proxy!.reset();
  }
  newManager(options);
  const swept = await sweepConnectedHosts();
  proxy!.restore();
  return swept;
}

/** Seed op-2 (a second command) from the setup snapshot, with its outbox event. */
function seedSecondCommand() {
  const { operation, event } = seed!;
  store.operations.set("op-2", {
    ...operation,
    id: "op-2",
    idempotencyKey: "key-2",
    processId: randomUUID(),
  });
  store.outbox.set("evt-2", {
    ...structuredClone(event),
    id: "evt-2",
    operationId: "op-2",
    processedAt: null,
    payload: {
      ...structuredClone(event.payload),
      operationId: "op-2",
      idempotencyKey: "key-2",
      argv: commandPayload("op-2", DEFAULT_OUTPUT, 2),
    },
  });
}

type OpExpectation = {
  id: string;
  allowed: readonly string[];
  /** Guest starts expected in total (each attempt at most once). */
  effects: number;
  errorCode?: string;
  output?: { bytes: number; salt: number; gap?: "allowed" };
};

/** The per-cell assertions (plan WP1), after quiescence. */
async function expectCell(cell: RelayChaosCell, ops: readonly OpExpectation[]) {
  await until(async () => {
    await processSandboxOutboxBatch();
    const receipts = Object.keys(await journalReceipts());
    return (
      receipts.length === 0 && [...store.outbox.values()].every((row) => row.processedAt !== null)
    );
  }, `${cell.id} quiescent: every receipt confirmed, every outbox row processed`);
  for (const expected of ops) {
    const row = op(expected.id);
    expect(expected.allowed, `${cell.id} ${expected.id} final state`).toContain(row.state);
    if (expected.errorCode) expect(row.errorCode).toBe(expected.errorCode);
    if (cell.safe)
      expect(history.get(expected.id) ?? [], `${cell.id} ${expected.id} history`).not.toContain(
        "UNKNOWN_OUTCOME",
      );
    const started = await effects(expected.id);
    expect(started, `${cell.id} ${expected.id} effects`).toBe(expected.effects);
    expect(started).toBeLessThanOrEqual(Number(row.dispatchAttempt));
    if (expected.output) {
      const want = pattern(expected.output.bytes, expected.output.salt);
      const stored = storedCommandOutput(store, expected.id);
      expect(stored, `${cell.id} ${expected.id} output`).toBeDefined();
      expect(stored!.stderr.length).toBe(0);
      if (stored!.retained === want.length) {
        expect(stored!.stdout.equals(want), `${cell.id} ${expected.id} byte-exact`).toBe(true);
      } else {
        expect(expected.output.gap, `${cell.id} ${expected.id} gap`).toBe("allowed");
        // An explicit gap: every retained segment is the exact bytes at its offset.
        for (const segment of store.outputSegments.values()) {
          if (segment.outputId !== expected.id) continue;
          const start = Number(segment.startOffset);
          const bytes = Buffer.from(segment.bytes as Uint8Array);
          expect(bytes.equals(want.subarray(start, start + bytes.length))).toBe(true);
        }
      }
    }
  }
  expect(daemonAlive(), `${cell.id} daemon alive`).toBe(true);
}

afterEach(async () => {
  try {
    if (dir) await releaseWireFixture(dir);
    if (dir) for (const id of ["op-1", "op-2"]) await release(id).catch(() => undefined);
  } finally {
    try {
      await stopWireHost(host);
      host = undefined;
    } finally {
      for (const created of managers.splice(0)) await created.dispose();
      dead.clear();
      await proxy?.close();
      proxy = undefined;
      server?.close();
      server = undefined;
      guard?.server.close();
      guard = undefined;
      chaos.keyBinding = undefined;
      if (dir) await removeWireDir(dir);
      dir = "";
    }
  }
});

// ---- cell registry ------------------------------------------------------------

const subset = (process.env.RELAY_CHAOS_SUBSET ?? "pr") as RelayChaosSubset;
const selected = new Set(relayChaosCells(subset).map((cell) => cell.id));
const registered = new Set<string>();
const CELL_TIMEOUT_MS = 180_000;

function cell(
  id: (typeof RELAY_CHAOS_MATRIX)[number]["id"],
  body: (cell: RelayChaosCell) => Promise<void>,
  variant = "",
) {
  const entry: RelayChaosCell = RELAY_CHAOS_MATRIX.find((candidate) => candidate.id === id)!;
  registered.add(id);
  const run = entry.status === "enabled" && selected.has(id) ? it : it.skip;
  run(
    `${id}${variant ? ` (${variant})` : ""}: ${entry.scenario} → ${entry.expect}`,
    () => body(entry),
    CELL_TIMEOUT_MS,
  );
}

// ---- cells --------------------------------------------------------------------

cell("C1", async (c) => {
  await setup();
  await armed("op-1");
  const before = epoch();
  // RST on both sockets while the command is in its Effect.
  expect(proxy!.reset()).toBe(1);
  await reconnectedAfter(before);
  expect(
    framesOf({ dir: "n2s", type: "operation.adopt", operationId: "op-1" }).at(-1)?.json,
  ).toMatchObject({ phase: "effect" });
  expect(op("op-1").dispatchedConnectionEpoch).toBe(epoch());
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "adopted command finished");
  expect(await exists(join(flags("op-1"), "term-observed"))).toBe(false);
  await expectCell(c, [
    {
      id: "op-1",
      allowed: ["SUCCEEDED"],
      effects: 1,
      output: { bytes: DEFAULT_OUTPUT, salt: 1 },
    },
  ]);
});

cell("C2", async (c) => {
  // Four 64 KiB frames fill the stream window; this is six windows' worth.
  const bytes = 384 * 1024;
  await setup({ outputBytes: bytes, dispatch: false });
  // Hold the server's output ACKs: the window fills and the rest of the
  // output stays retained on the host while the server restarts.
  const acks = proxy!.holdUntil({ dir: "s2n", type: "command.output.ack", operationId: "op-1" });
  await processSandboxOutboxBatch();
  await until(() => op("op-1").acceptedAttempt === 1, "host accepted op-1");
  await armed("op-1");
  await acks.matched;
  const before = epoch();
  await restartServer("graceful");
  await reconnectedAfter(before);
  await until(
    () => (storedCommandOutput(store, "op-1")?.retained ?? 0) === bytes,
    "the new server received all output",
  );
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after SrvR");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes, salt: 1 } },
  ]);
});

cell("C3", async (c) => {
  await setup();
  await armed("op-1");
  const before = epoch();
  const links = proxy!.accepted;
  expect(proxy!.closeWith(1000, "normal closure")).toBe(1);
  await reconnectedAfter(before);
  expect(proxy!.accepted).toBe(links + 1);
  expect(daemonAlive()).toBe(true);
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after close 1000");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C4", async (c) => {
  await setup();
  await armed("op-1");
  const before = epoch();
  const links = proxy!.accepted;
  const closedAt = Date.now();
  expect(proxy!.closeWith(1013, "try again later")).toBe(1);
  await proxy!.waitForLinks(links + 1, 30_000);
  // Close 1013 raises the wait to the jittered 5 s busy floor ([2.5, 5] s),
  // above the 1 s carry floor a plain transport loss gets.
  expect(Date.now() - closedAt).toBeGreaterThanOrEqual(2_400);
  await reconnectedAfter(before);
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after close 1013");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C5", async (c) => {
  // A short liveness bound: a false removal would happen well inside the
  // slow-DB window if the clock ran while reads are paused.
  const liveness = { pingIntervalMs: 250, livenessTimeoutMs: 1_000 };
  await setup({ manager: liveness });
  await armed("op-1");
  const before = epoch();
  const links = proxy!.accepted;
  // The real daemon adopts one frame at a time (reconcile.rs adopt_carried
  // awaits each operation.adopt.result), so the 300-frame burst rides
  // behind its adoption: the proxy holds the adopt, the DB stalls, and 300
  // heartbeats follow the adopt on the same link at once.
  const adopt = proxy!.holdUntil({ dir: "n2s", type: "operation.adopt", operationId: "op-1" });
  proxy!.reset();
  const held = await adopt.matched;
  let slow: (() => void) | undefined;
  const stalled = new Promise<void>((resolve) => {
    slow = resolve;
  });
  store.barriers.beforeCommit = () => stalled;
  adopt.release();
  for (let index = 0; index < 300; index++)
    proxy!.inject(held.linkId, "n2s", JSON.stringify({ type: "heartbeat", id: `burst-${index}` }));
  await until(() => serverSockets.pauses > 0, "receive backpressure paused the reader");
  // The DB stays stalled for three liveness bounds while reads are paused.
  await delay(liveness.livenessTimeoutMs * 3);
  expect(proxy!.liveLinks().map((link) => link.id)).toEqual([held.linkId]);
  store.barriers.beforeCommit = undefined;
  slow!();
  await reconnectedAfter(before);
  await until(
    () =>
      framesOf({ dir: "s2n", type: "heartbeat.pong" }).filter((frame) =>
        String(frame.json?.id).startsWith("burst-"),
      ).length === 300,
    "every burst frame was processed and answered",
  );
  // No 1008 and no removal: the same link carries the session throughout.
  expect(serverSockets.closes).not.toContain(1008);
  expect(proxy!.accepted).toBe(links + 1);
  expect(proxy!.liveLinks().map((link) => link.id)).toEqual([held.linkId]);
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after the burst");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C6", async (c) => {
  await setup({ dispatch: false });
  const lost = proxy!.dropNext({ dir: "s2n", type: "operation.dispatch", operationId: "op-1" });
  await processSandboxOutboxBatch();
  await lost;
  expect(op("op-1")).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
  const before = epoch();
  const cursor = proxy!.cursor;
  proxy!.reset();
  await reconnectedAfter(before);
  expect(
    framesOf({ dir: "n2s", type: "dispatch.audit.result" }, cursor).at(-1)?.json,
    "the host proved it never received attempt 1",
  ).toMatchObject({ entries: [{ operationId: "op-1", attempt: 1, received: false }] });
  expect(op("op-1").state).toBe("QUEUED");
  await processSandboxOutboxBatch();
  await until(() => op("op-1").acceptedAttempt === 2, "attempt 2 accepted");
  await armed("op-1");
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "redispatched command finished");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C7", async (c) => {
  await setup();
  await armed("op-1");
  const lost = proxy!.holdThenReset({ dir: "n2s", type: "operation.result", operationId: "op-1" });
  const before = epoch();
  await release("op-1");
  const result = await lost;
  expect(result.disposition).toBe("discarded");
  await reconnectedAfter(before);
  await until(() => op("op-1").state === "SUCCEEDED", "replayed receipt applied");
  await until(async () => !(await journalReceipts())["op-1"], "the replayed receipt was confirmed");
  // The result came back as a journal receipt replay: at least once, and at
  // most once per session (a session that ends before the confirmation
  // replays it again on the next one; it never loops within a session).
  expectReplaysOncePerSession("op-1", result.seq, 1);
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

/**
 * Journal receipt replays of `operationId` since `fromSeq`: at least `least`,
 * and at most one per session. A session that ends before its confirmation
 * replays the receipt again on the next one; it never loops within one.
 */
function expectReplaysOncePerSession(operationId: string, fromSeq: number, least: number) {
  const replays = framesOf({ dir: "n2s", type: "operation.receipt", operationId }, fromSeq);
  expect(replays.length).toBeGreaterThanOrEqual(least);
  expect(new Set(replays.map((frame) => frame.linkId)).size).toBe(replays.length);
}

const confirmationOf =
  (operationId: string) =>
  (frame: { dir: string; type: string | null; json: Record<string, unknown> | null }) =>
    frame.dir === "s2n" &&
    frame.type === "receipt.confirmed" &&
    frame.json?.operationId === operationId;

cell("C8", async (c) => {
  await setup();
  await armed("op-1");
  const lost = proxy!.dropReplyThenReset(
    { dir: "n2s", type: "operation.result", operationId: "op-1" },
    confirmationOf("op-1"),
  );
  const before = epoch();
  await release("op-1");
  const { dropped } = await lost;
  // The server applied the live result before its confirmation was lost.
  await until(() => op("op-1").state === "SUCCEEDED", "live result applied");
  const completedAt = op("op-1").completedAt;
  await reconnectedAfter(before);
  await until(async () => !(await journalReceipts())["op-1"], "the replayed receipt was confirmed");
  expectReplaysOncePerSession("op-1", dropped.seq, 1);
  expect(
    framesOf(confirmationOf("op-1"), dropped.seq).filter((f) => f.disposition === "forwarded"),
  ).toHaveLength(1);
  // The replay re-applied nothing.
  expect(op("op-1").completedAt).toEqual(completedAt);
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C9", async (c) => {
  await setup();
  await armed("op-1");
  const before = epoch();
  // The server stays unreachable until the cancellation is durable.
  proxy!.outage();
  proxy!.reset();
  await until(() => epoch() > before, "the disconnect revoked the old epoch");
  await cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" });
  expect(op("op-1").state).toBe("CANCEL_REQUESTED");
  const away = epoch();
  proxy!.restore();
  await reconnectedAfter(away);
  expect(op("op-1").state).toBe("CANCEL_REQUESTED");
  await processSandboxOutboxBatch();
  await until(() => op("op-1").state === "CANCELLED", "cancel reached the adopted command");
  expect(await exists(join(flags("op-1"), "term-observed"))).toBe(true);
  await expectCell(c, [
    { id: "op-1", allowed: ["CANCELLED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C10", async (c) => {
  await setup();
  expect(op("op-1").resultVersion).toBe(1);
  await armed("op-1");
  // (1) The live result is lost: the attempt is settled by its receipt.
  const lostResult = proxy!.holdThenReset({
    dir: "n2s",
    type: "operation.result",
    operationId: "op-1",
  });
  // (2) The replayed receipt's confirmation is lost too.
  const lostConfirmation = proxy!.dropReplyThenReset(
    { dir: "n2s", type: "operation.receipt", operationId: "op-1" },
    confirmationOf("op-1"),
  );
  let before = epoch();
  await release("op-1");
  const { seq } = await lostResult;
  await lostConfirmation;
  await reconnectedAfter(before);
  await until(() => op("op-1").state === "SUCCEEDED", "versioned receipt applied");
  // (3) The second replay is confirmed and the journal compacts...
  await until(async () => !(await journalReceipts())["op-1"], "receipt confirmed");
  // (4) ...so a later session replays nothing: the receipt never loops.
  before = epoch();
  const cursor = proxy!.cursor;
  proxy!.reset();
  await reconnectedAfter(before);
  expect(framesOf({ dir: "n2s", type: "operation.receipt", operationId: "op-1" }, cursor)).toEqual(
    [],
  );
  expectReplaysOncePerSession("op-1", seq, 2);
  expect(
    framesOf(confirmationOf("op-1"), seq).filter((f) => f.disposition === "forwarded"),
  ).toHaveLength(1);
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C11", async (c) => {
  // A 3 s server-silence deadline (the knob also shortens the heartbeat).
  await setup({ timing: "3s,,,," });
  await armed("op-1");
  const links = proxy!.accepted;
  // Blackhole the reconnect's census: from its first inventory page on,
  // nothing reaches either side and neither side sees a close.
  const census = proxy!.holdUntil({ dir: "n2s", type: "sandbox.inventory" });
  proxy!.reset();
  const page = await census.matched;
  expect(page.linkId).toBe(links + 1);
  proxy!.blackhole();
  census.release();
  // The daemon's silence deadline detaches (never revokes) and redials.
  await until(() => proxy!.accepted >= links + 2, "the daemon redialled after silence", 30_000);
  await until(
    () =>
      manager().isHostConnected("host-1", epoch()) &&
      op("op-1").dispatchedConnectionEpoch === epoch(),
    "adopted on the link after the blackhole",
    60_000,
  );
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after the blackhole");
  expect(await exists(join(flags("op-1"), "term-observed"))).toBe(false);
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C12", async (c) => {
  // Intent window 1 s, max_carry 30 s: the knob's stand-in for an outage
  // longer than the old fixed 60 s grace but inside the carry window.
  await setup({ timing: ",1s,30s,," });
  await armed("op-1");
  const before = epoch();
  proxy!.outage();
  proxy!.reset();
  await until(() => proxy!.refused >= 2, "the daemon redialled into the outage");
  // The outage itself: three intent windows.
  await delay(3_000);
  // The command finishes while the server is away; its receipt is journaled.
  await release("op-1");
  await until(
    async () => (await journalReceipts())["op-1"]?.state === "succeeded",
    "the carried command finished during the outage",
  );
  expect(await exists(join(flags("op-1"), "term-observed"))).toBe(false);
  proxy!.restore();
  await reconnectedAfter(before);
  const row = carryRow("carry-command-outlives-the-window");
  await until(() => op("op-1").state === row.state, "receipt applied after the outage");
  await expectCell(c, [
    { id: "op-1", allowed: [row.state], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

for (const variant of ["max_carry", "timeout"] as const) {
  cell(
    "C13",
    async (c) => {
      const row = carryRow(
        variant === "max_carry" ? "carry-command-max-carry" : "carry-command-own-timer",
      );
      const code = row.errorCode!;
      await setup(
        variant === "max_carry" ? { timing: ",,2s,," } : { timeoutMs: 3_000, timing: ",,30s,," },
      );
      // The timeout's stop proof runs the shim's terminate helper without a
      // cancel intent.
      if (variant === "timeout") await writeFile(join(dir, "terminate-on-timeout"), "");
      await armed("op-1");
      const before = epoch();
      proxy!.outage();
      proxy!.reset();
      // The host ends the carried command on its own while the server is away.
      await until(async () => {
        const stored = (await journalReceipts())["op-1"];
        return stored?.state === "failed";
      }, `the host ended the command (${code}) during the outage`);
      expect(JSON.stringify((await journalReceipts())["op-1"])).toContain(code);
      proxy!.restore();
      await reconnectedAfter(before);
      await until(() => op("op-1").state === row.state, `${code} applied after the outage`);
      await expectCell(c, [
        {
          id: "op-1",
          allowed: [row.state],
          errorCode: code,
          effects: 1,
          output: { bytes: DEFAULT_OUTPUT, salt: 1 },
        },
      ]);
    },
    variant,
  );
}

cell("C14", async (c) => {
  await setup();
  await armed("op-1");
  const before = epoch();
  expect(store.hosts.get("host-1")!.status).toBe("CONNECTED");
  const swept = await (async () => {
    // SrvX: the process dies; nothing writes the disconnect...
    proxy!.outage();
    dead.add(manager());
    proxy!.reset();
    expect(store.hosts.get("host-1")).toMatchObject({
      status: "CONNECTED",
      connectionEpoch: before,
    });
    // ...until the next process's boot sweep, before it listens.
    newManager();
    const result = await sweepConnectedHosts();
    expect(store.hosts.get("host-1")!.status).toBe("DISCONNECTED");
    proxy!.restore();
    return result;
  })();
  expect(swept).toEqual({ disconnected: 1 });
  await reconnectedAfter(before);
  expect(op("op-1").dispatchedConnectionEpoch).toBe(epoch());
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "command finished after SrvX");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
  ]);
});

cell("C15", async (c) => {
  await setup();
  await armed("op-1");
  const daemon = host!;
  // `wssp host daemon quiesce` as `ExecReload` runs it: the control file names
  // this daemon, so it is sent SIGUSR1 (graceful quiesce).
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    WSSP_DATA_DIR: join(dir, "data"),
    WSSP_CONFIG_DIR: join(dir, "config"),
  };
  delete env.MAINPID;
  const quiesce = spawn(
    resolve("target/debug/wssp"),
    ["host", "daemon", "quiesce", "--pid", String(daemon.pid)],
    { env, stdio: ["ignore", "pipe", "pipe"] },
  );
  quiesce.stderr!.on("data", (chunk) => failures.push(String(chunk)));
  const [quiesceExit] = await once(quiesce, "exit");
  expect(quiesceExit).toBe(0);
  await until(() => manager().isHostQuiescing("host-1"), "the server holds the host quiescing");
  // A new command is held in the server queue, before any claim.
  seedSecondCommand();
  await processSandboxOutboxBatch();
  expect(op("op-2")).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  expect(store.outbox.get("evt-2")!.processedAt).toBeNull();
  // The running command finishes; then the daemon leaves on its own (exit 0).
  const exited = once(daemon, "exit");
  await release("op-1");
  await until(() => op("op-1").state === "SUCCEEDED", "running command finished while quiescing");
  const [code] = await exited;
  expect(code).toBe(0);
  expect(op("op-2")).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  // DmnR: the service manager starts the new binary on the same data dir.
  const before = epoch();
  await startHost();
  await reconnectedAfter(before);
  expect(manager().isHostQuiescing("host-1")).toBe(false);
  await processSandboxOutboxBatch();
  await until(() => op("op-2").acceptedAttempt === 1, "held command dispatched to the new daemon");
  await armed("op-2");
  await release("op-2");
  await until(() => op("op-2").state === "SUCCEEDED", "held command finished");
  await expectCell(c, [
    { id: "op-1", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 1 } },
    { id: "op-2", allowed: ["SUCCEEDED"], effects: 1, output: { bytes: DEFAULT_OUTPUT, salt: 2 } },
  ]);
});

it("every matrix cell has a case here", () => {
  expect([...registered].sort()).toEqual(RELAY_CHAOS_MATRIX.map((entry) => entry.id).sort());
});
