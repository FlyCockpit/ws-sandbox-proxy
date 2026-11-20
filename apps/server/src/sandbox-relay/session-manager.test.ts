import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { duplexPair } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { ORPCError } from "@orpc/server";
import { revalidateSandboxHostIdentity } from "@wssp/api/lib/host-token-access";
import * as sdkAccess from "@wssp/api/lib/sdk-key-access";
import { markHostQuiescing, settleHostQuiesce } from "@wssp/api/template-builds/quiesce-hold";
import { withAuthorityChange } from "@wssp/db/authority";

async function flushCommittedAuthorityListeners() {
  await new Promise<void>((resolve) => queueMicrotask(resolve));
}

// WP7: the persisted quiesce hold (template-build deadlines), recorded best
// effort after the in-memory hold.
vi.mock("@wssp/api/template-builds/quiesce-hold", () => ({
  markHostQuiescing: vi.fn().mockResolvedValue(undefined),
  settleHostQuiesce: vi.fn().mockResolvedValue(0),
}));

vi.mock("@wssp/api/lib/host-token-access", () => ({
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));

import {
  buildCommandRunOperationDispatchMessage,
  commandRunDispatchBuildInputFromOutboxPayload,
} from "@wssp/api/sandbox/dispatch-control-envelope";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket, WebSocketServer } from "ws";
import expiryStop from "../../../../crates/sandbox-protocol/fixtures/control_expiry_stop_dispatch.json";
import downloadRecovery from "../../../../crates/sandbox-protocol/fixtures/download_recovery.json";
import { blocklistDigest } from "./egress-blocklist.js";
import {
  gate,
  installFenceTransaction,
  matches,
  prismaPromise,
  relayStore,
  runningCensusFrames,
  storedCommandOutput,
} from "./fenced-prisma-harness.js";
import {
  encodeBinaryFrame,
  encodeChannelDataFrame,
  parseBinaryFrame,
  parseDaemonControlFrame,
  SandboxRelayDispatchValidationError,
} from "./protocol.js";
import { bindMemoryCaptures } from "./relay-captures-harness.js";
import {
  SANDBOX_RECEIVE_HARD_MAX_FRAMES,
  SANDBOX_RECEIVE_MAX_BYTES,
  SANDBOX_RECEIVE_MAX_FRAMES,
  SANDBOX_RELAY_LIVENESS_TIMEOUT_MS,
  SANDBOX_RELAY_PING_INTERVAL_MS,
  SandboxRelaySessionManager,
  type SandboxRelaySocket,
  sandboxRelaySessionManager,
  UNPARSED_CONTROL_FRAME_MESSAGE,
} from "./session-manager.js";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "service-principal-test",
  },
}));

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
const WS_READY_STATE_OPEN = 1;

class FakeSocket {
  readyState = WS_READY_STATE_OPEN;
  bufferedAmount = 0;
  sends: string[] = [];
  binarySends: ArrayBuffer[] = [];
  closes: { code?: number; reason?: string }[] = [];
  /** Receive backpressure: a real socket stops delivering frames while paused. */
  paused = false;
  pauses = 0;
  resumes = 0;

  pause() {
    this.paused = true;
    this.pauses += 1;
  }

  resume() {
    this.paused = false;
    this.resumes += 1;
    // Reading again consumes the peer's close reply (as `ws` does).
    if (this.readyState === 2) this.readyState = 3;
  }

  /** WP4: transport pings; `onPing` plays the peer (e.g. answers a pong). */
  pings = 0;
  onPing?: () => void;
  ping() {
    this.pings += 1;
    this.onPing?.();
  }

  send(data: string | ArrayBuffer | Uint8Array) {
    if (typeof data === "string") {
      this.sends.push(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      this.binarySends.push(data);
      return;
    }
    this.binarySends.push(data.slice().buffer);
  }

  close(code?: number, reason?: string) {
    if (this.readyState === 3) return;
    this.closes.push({ code, reason });
    // A paused `ws` sends its close frame but never reads the peer's reply,
    // so it stays CLOSING until reads resume (or the 30 s close timeout).
    this.readyState = this.paused ? 2 : 3;
  }
}

const testIdentity = {
  hostId: "host-1",
  userId: "user-1",
  tokenId: "token-1",
  credentialKind: "hostToken" as const,
  expiresAt: null,
};

function helloFrame(
  hostId: string,
  protocolVersion = "1.0",
  egressPolicy = false,
  _telemetry = false,
  capabilities: Record<string, unknown> = {},
) {
  const hello = helloFixture(hostId, false);
  return JSON.stringify({
    ...hello,
    protocolVersion,
    supportedProtocolVersions: [protocolVersion],
    daemon: {
      ...hello.daemon,
      capabilities: {
        ...hello.daemon.capabilities,
        protocolVersion,
        egressPolicy,
        ...capabilities,
      },
    },
  });
}

let store = relayStore("GET_FILE");
let manager: SandboxRelaySessionManager;
function socket() {
  const result = new FakeSocket();
  manager.acceptAuthenticatedSocket({ socket: result, identity: testIdentity });
  return result;
}
async function registered(
  telemetry = false,
  egressPolicy = true,
  capabilities: Record<string, unknown> = {},
  complete: Record<string, unknown> = {},
) {
  const result = socket();
  manager.handleTextFrame(
    result,
    helloFrame("host-1", "1.0", egressPolicy, telemetry, capabilities),
  );
  await manager.drain(result);
  expect(result.closes, "hello").toEqual([]);
  const key = result.sends
    .map((text) => JSON.parse(text))
    .find((frame) => frame.type === "journal.key.install");
  manager.handleTextFrame(
    result,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: key.connectionEpoch,
      keyVersion: key.keyVersion,
      keyId: key.keyId,
    }),
  );

  for (const page of runningCensusFrames(store)) manager.handleTextFrame(result, page);
  manager.handleTextFrame(result, JSON.stringify({ type: "reconcile.complete", ...complete }));
  await manager.drain(result);
  expect(
    result.closes,
    JSON.stringify(
      result.sends.map((f) => JSON.parse(f)).filter((f) => f.type === "protocol.error"),
    ),
  ).toEqual([]);
  for (const config of store.configs.values())
    config.acknowledgedEpoch = store.hosts.get("host-1")!.connectionEpoch;
  for (const event of store.outbox.values()) {
    const operation = store.operations.get(String(event.payload.operationId));
    if (operation?.kind === "RUN_COMMAND") {
      operation.resultVersion ??= 1;
      operation.processId ??= `proc-${operation.id}`;
      Object.assign(event.payload, {
        resultVersion: operation.resultVersion,
        processId: operation.processId,
      });
    }
    Object.assign(event.payload, {
      allocationJournalEpoch: store.hosts.get("host-1")!.connectionEpoch,
      allocationJournalAttempt: 1,
    });
    event.eventType ??= "sandbox.create_requested";
  }
  return result;
}
const resultFrame = JSON.stringify({
  type: "operation.result",
  id: "result-1",
  result: {
    size: 2,
    sha256: createHash("sha256")
      .update(new Uint8Array([65, 66]))
      .digest("hex"),
  },
  operationId: "op-1",
  sandboxId: "sbx-1",
  generation: 1,
  attempt: 1,
  state: "succeeded",
});
const captures = bindMemoryCaptures();
const chunkFrame = () =>
  encodeBinaryFrame(
    {
      type: "stream.end",
      streamId: "file-1",
      operationId: "op-1",
      generation: 1,
      attempt: 1,
      sequence: 0,
      offset: 0,
      flags: { fileDownload: true },
      final: true,
    },
    new Uint8Array([65, 66]),
  );
beforeEach(async () => {
  vi.clearAllMocks();
  vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({
    status: "active",
    hostDeletionRequested: false,
  });
  store = relayStore("GET_FILE");
  store.hosts.get("host-1")!.connectionEpoch = 0;
  installFenceTransaction(db, store);
  manager = new SandboxRelaySessionManager();
  await captures.discardCapture("op-1", 1);
  db.sandboxHost.updateMany.mockImplementation((args) =>
    prismaPromise(prisma.$transaction((tx) => tx.sandboxHost.updateMany(args))),
  );
});
afterEach(() => manager.dispose());
describe("ordered socket authority", () => {
  it("serializes admission frames, accepts an identical repeat and closes a conflicting repeat", async () => {
    const host = await registered();
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { protocolVersion: string }
    >;
    sessions.get(host)!.protocolVersion = "1.0";
    const report = {
      vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
      storagePools: capacityFixture("host-1").storagePools,
      journalId: "1234567890abcdef1234567890abcdef",
      type: "host.admission",
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: true,
      terminal: false,
    };
    manager.handleTextFrame(host, JSON.stringify(report));
    manager.handleTextFrame(host, JSON.stringify(report));
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    expect(store.hosts.get("host-1")).toMatchObject({
      admissionEpoch: 1,
      admissionRuntime: "FAKE",
      daemonFeatures: { egressPolicy: true, terminal: false },
    });
    manager.handleTextFrame(host, JSON.stringify({ ...report, egressPolicy: false }));
    await manager.drain(host);
    expect(host.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
    expect(manager.isHostConnected("host-1")).toBe(false);
    expect(store.hosts.get("host-1")!.daemonFeatures).toEqual({
      egressPolicy: true,
      egressOpen: false,
      terminal: false,
      journalId: "1234567890abcdef1234567890abcdef",
    });
  });

  it("C8: corrupt inventory closes only that host and repeats on reconnect until repair", async () => {
    store.hosts.set("host-2", {
      ...structuredClone(store.hosts.get("host-1")!),
      id: "host-2",
      userId: "user-2",
    });
    const other = new FakeSocket();
    manager.acceptAuthenticatedSocket({
      socket: other,
      identity: { ...testIdentity, hostId: "host-2", userId: "user-2" },
    });
    manager.handleTextFrame(other, helloFrame("host-2"));
    await manager.drain(other);
    for (const page of runningCensusFrames(store, "host-2")) manager.handleTextFrame(other, page);
    manager.handleTextFrame(other, JSON.stringify({ type: "reconcile.complete" }));
    await manager.drain(other);
    Object.assign(store.sandboxes.get("sbx-1")!, {
      liveResourcesHeld: true,
      diskReservationHeld: false,
    });
    Object.assign(store.hosts.get("host-1")!, { liveCount: 1, memoryReservedMiB: 512 });
    const absent = JSON.stringify({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries: [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" }],
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        if (attempt === 2)
          Object.assign(store.hosts.get("host-1")!, { memoryReservedMiB: 1344, vcpuReserved: 1 });
        const host = socket();
        manager.handleTextFrame(host, helloFrame("host-1"));
        await manager.drain(host);
        Object.assign(store.storagePools.get("storage:host-1")!, {
          connectionEpoch: store.hosts.get("host-1")!.connectionEpoch,
          reportedAt: new Date(),
        });
        manager.handleTextFrame(host, absent);
        manager.handleTextFrame(host, JSON.stringify({ type: "reconcile.complete" }));
        await manager.drain(host);
        expect(host.closes).toEqual(attempt < 2 ? [{ code: 1002, reason: "protocol_error" }] : []);
        expect(manager.isHostConnected("host-1")).toBe(attempt === 2);
        expect(other.closes).toEqual([]);
        expect(manager.isHostConnected("host-2")).toBe(true);
        expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(attempt < 2);
      }
      expect(log).toHaveBeenCalledTimes(2);
      expect(log).toHaveBeenCalledWith("[sandbox] integrity failure:", {
        code: "sandbox_reservation_underflow",
        errorClass: "Error",
      });
    } finally {
      log.mockRestore();
    }
  });

  it("echoes a channels offer and refuses every unsolicited channel frame", async () => {
    const fence = {
      channelId: "chan-1",
      connectionId: "conn-1",
      hostId: "host-1",
      epoch: 1,
      target: { kind: "sandbox" as const, sandboxId: "sbx-1", generation: 1 },
    };
    const plain = await registered();
    const plainAck = JSON.parse(plain.sends.find((s) => JSON.parse(s).type === "hello.ok")!);
    expect(plainAck.capabilities).not.toHaveProperty("channels");
    manager.handleTextFrame(
      plain,
      JSON.stringify({ type: "channel.ready", fence, pty: { rows: 24, cols: 80 } }),
    );
    expect(plain.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);

    const offered = await registered(false, true, { channels: { kinds: ["pty", "exec"] } });
    const ack = JSON.parse(offered.sends.find((s) => JSON.parse(s).type === "hello.ok")!);
    expect(ack.capabilities.channels).toEqual({ kinds: ["pty", "exec"] });
    manager.handleBinaryFrame(
      offered,
      encodeChannelDataFrame(
        { type: "channel.data", fence, stream: "stdout", seq: 0 },
        new Uint8Array([1]),
      ),
    );
    expect(offered.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
  });

  it.each([false, true])(
    "negotiates telemetry=%s without changing strict legacy hello fields",
    async (telemetry) => {
      const host = await registered(telemetry);
      const ack = JSON.parse(host.sends.find((s) => JSON.parse(s).type === "hello.ok")!);
      expect(ack.protocolVersion).toBe(telemetry ? "1.0" : "1.0");
      expect(ack.capabilities.protocolVersion).toBe(ack.protocolVersion);
      expect(Object.keys(ack).sort()).toEqual(
        [
          "type",
          "id",
          "protocolVersion",
          "capabilities",
          "supportedProtocolVersions",
          "hostOwnerId",
          "connectionEpoch",
        ].sort(),
      );
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "legacy-compatible" }));
      await manager.drain(host);
      expect(host.closes).toEqual([]);
      expect(host.sends.some((s) => JSON.parse(s).id === "legacy-compatible")).toBe(true);
    },
  );

  it("reflects reconciler health as capability metadata without widening authority", async () => {
    const host = await registered(true);
    const health = {
      enabled: true,
      lastPassUnixMs: 123,
      verified: 2,
      drift: 1,
      inconclusive: 3,
      foreign: 1,
      absent: 0,
      pending: 5,
    };
    const prior = { ...store.hosts.get("host-1")! };
    const sandbox = { ...store.sandboxes.get("sbx-1")! };
    manager.handleTextFrame(
      host,
      JSON.stringify({ type: "heartbeat", id: "health", policyReconciler: health }),
    );
    await manager.drain(host);
    expect(store.hosts.get("host-1")!.policyReconcilerHealth).toMatchObject({
      ...health,
      reportedAt: expect.any(String),
    });
    expect(store.hosts.get("host-1")!.egressEnforcement).toBe(prior.egressEnforcement);
    expect(store.hosts.get("host-1")!.quarantinedAt).toBe(prior.quarantinedAt);
    expect(store.hosts.get("host-1")!.liveCount).toBe(prior.liveCount);
    expect(store.sandboxes.get("sbx-1")).toEqual(sandbox);
    expect(host.sends.some((s) => JSON.parse(s).type === "heartbeat.pong")).toBe(true);
    // An ordinary legacy heartbeat must not erase the last known report.
    manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "legacy" }));
    await manager.drain(host);
    expect(store.hosts.get("host-1")!.policyReconcilerHealth).toMatchObject(health);
  });

  it("does not let a superseded socket replace reconciler health", async () => {
    const old = await registered(true);
    const current = await registered(true);
    const health = {
      enabled: true,
      lastPassUnixMs: 1,
      verified: 0,
      drift: 1,
      inconclusive: 0,
      foreign: 0,
      absent: 0,
      pending: 0,
    };
    manager.handleTextFrame(
      current,
      JSON.stringify({ type: "heartbeat", id: "new-health", policyReconciler: health }),
    );
    await manager.drain(current);
    const capabilities = store.hosts.get("host-1")!.policyReconcilerHealth;
    manager.handleTextFrame(
      old,
      JSON.stringify({
        type: "heartbeat",
        id: "stale-health",
        policyReconciler: { ...health, drift: 0, verified: 99 },
      }),
    );
    await manager.drain(old);
    expect(store.hosts.get("host-1")!.policyReconcilerHealth).toEqual(capabilities);
  });

  it.each(["epoch", "owner"])(
    "refuses heartbeat health when the database %s fence changed",
    async (changed) => {
      const host = await registered(true);
      const row = store.hosts.get("host-1")!;
      const prior = row.policyReconcilerHealth;
      if (changed === "epoch") row.connectionEpoch = Number(row.connectionEpoch) + 1;
      else row.userId = "another-owner";
      manager.handleTextFrame(
        host,
        JSON.stringify({
          type: "heartbeat",
          id: "stale-cas",
          policyReconciler: {
            enabled: true,
            lastPassUnixMs: 1,
            verified: 1,
            drift: 0,
            inconclusive: 0,
            foreign: 0,
            absent: 0,
            pending: 0,
          },
        }),
      );
      await manager.drain(host);
      expect(store.hosts.get("host-1")!.policyReconcilerHealth).toEqual(prior);
      expect(host.sends.filter((s) => JSON.parse(s).id === "stale-cas")).toEqual([]);
    },
  );

  it("ACKs committed binary output and exact retransmits but never stale attempts", async () => {
    store.operations.get("op-1")!.kind = "RUN_COMMAND";
    const host = await registered();
    host.sends = [];
    const meta = {
      type: "stream.chunk" as const,
      streamId: "op-1",
      operationId: "op-1",
      generation: 1,
      attempt: 1,
      sequence: 0,
      offset: 0,
      flags: { stdout: true },
    };
    const frame = encodeBinaryFrame(meta, new Uint8Array([1, 2]));
    for (let n = 0; n < 2; n++) {
      manager.handleBinaryFrame(host, frame);
      await manager.drain(host);
    }
    expect(host.sends.map((text) => JSON.parse(text))).toEqual(
      Array(2).fill({
        type: "command.output.ack",
        operationId: "op-1",
        generation: 1,
        attempt: 1,
        sequence: 0,
        offset: 2,
      }),
    );
    expect(storedCommandOutput(store, "op-1")?.retained).toBe(2);
    manager.handleBinaryFrame(
      host,
      encodeBinaryFrame({ ...meta, attempt: 2 }, new Uint8Array([1, 2])),
    );
    await manager.drain(host);
    expect(host.sends).toHaveLength(2);
  });
  it("a hello delayed by revalidation cannot replace a newer connection", async () => {
    const entered = gate(),
      resume = gate();
    vi.mocked(revalidateSandboxHostIdentity)
      .mockResolvedValueOnce({ status: "active", hostDeletionRequested: false })
      .mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return { status: "active", hostDeletionRequested: false };
      });
    const older = socket();
    manager.handleTextFrame(older, helloFrame("host-1"));
    await entered.promise;
    try {
      const newer = await registered();
      expect(manager.isHostConnected("host-1", 2)).toBe(true);
      resume.resolve();
      await manager.drain(older);
      expect(manager.isHostConnected("host-1", 2)).toBe(true);
      expect(newer.readyState).toBe(WS_READY_STATE_OPEN);
      expect(older.readyState).toBe(3);
      expect(older.sends).toEqual([]);
    } finally {
      resume.resolve();
      await manager.drain(older);
    }
  });

  it("registers only after hello commit, and queues following heartbeat", async () => {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeCommit = async () => {
      store.barriers.beforeCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    const host = socket();
    manager.handleTextFrame(host, helloFrame("host-1"));
    manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "hb" }));
    await entered.promise;
    expect(manager.isHostConnected("host-1")).toBe(false);
    expect(host.sends).toEqual([]);
    resume.resolve();
    await manager.drain(host);
    expect(host.sends.map((s) => JSON.parse(s).type)).toEqual([
      "hello.ok",
      "journal.key.install",
      "egress.blocklist",
      "heartbeat.pong",
    ]);
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(1);
  });
  it.each(["11.0", "2.0", "3.0"])("rejects hello %s before registration", async (version) => {
    const host = socket();
    manager.handleTextFrame(host, helloFrame("host-1", version));
    await manager.drain(host);
    expect(host.closes.length).toBeGreaterThan(0);
    expect(host.sends.some((s) => JSON.parse(s).type === "hello.ok")).toBe(false);
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(0);
  });
  it.each([
    [
      "an unknown capability",
      helloFrame("host-1", "1.0", false, false, { futureCapability: true }),
    ],
    [
      "a malformed hello",
      JSON.stringify({ ...JSON.parse(helloFrame("host-1")), daemon: { hostId: "host-1" } }),
    ],
  ])(
    "refuses a hello with %s with the exact unparsed-frame error the daemon keys on",
    async (_name, frame) => {
      // Malformed hello frames receive a terminal protocol refusal.
      expect(UNPARSED_CONTROL_FRAME_MESSAGE).toBe("Invalid sandbox relay control frame.");
      const host = socket();
      manager.handleTextFrame(host, frame);
      await manager.drain(host);
      expect(host.sends.map((s) => JSON.parse(s))).toEqual([
        {
          type: "protocol.error",
          failure: "protocol_error",
          message: UNPARSED_CONTROL_FRAME_MESSAGE,
        },
      ]);
      expect(host.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
      expect(manager.isHostConnected("host-1")).toBe(false);
      expect(store.hosts.get("host-1")!.connectionEpoch).toBe(0);
    },
  );
  it("rejects foreign hello and repeated hello", async () => {
    const foreign = socket();
    manager.handleTextFrame(foreign, helloFrame("other"));
    await manager.drain(foreign);
    expect(foreign.readyState).toBe(3);
    const host = await registered();
    manager.handleTextFrame(host, helloFrame("host-1"));
    await manager.drain(host);
    expect(host.readyState).toBe(3);
    expect(host.sends.filter((s) => JSON.parse(s).type === "hello.ok")).toHaveLength(1);
  });
  it("rejects all pre-hello traffic", async () => {
    for (const frame of [resultFrame, JSON.stringify({ type: "heartbeat", id: "hb" })]) {
      const host = socket();
      manager.handleTextFrame(host, frame);
      await manager.drain(host);
      expect(host.readyState).toBe(3);
    }
    const host = socket();
    manager.handleBinaryFrame(host, chunkFrame());
    await manager.drain(host);
    expect(host.readyState).toBe(3);
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
  });
  it("Q3: a removed session drops its queued frames", async () => {
    const host = await registered();
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    const before = store.writes.length;
    for (let i = 0; i < 10; i++)
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "hb" }));
    manager.removeSession(host);
    expect(host.readyState).toBe(3);
    resume.resolve();
    await manager.drain(host);
    // The entered transaction may make rollback-only S writes while disconnect
    // waits on owner/H. No operation mutation or queued heartbeat commits.
    expect(store.writes.slice(before)).not.toContain("operations");
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    expect(host.sends.filter((s) => JSON.parse(s).type === "heartbeat.pong")).toHaveLength(0);
    expect(captures.peek("op-1", 1)).toBeUndefined();
  });
  it("P0-2: a flood behind a blocked frame pauses reads, then resumes and processes every frame in order", async () => {
    const host = await registered();
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    const total = SANDBOX_RECEIVE_MAX_FRAMES * 4;
    let sent = 0;
    // A paused transport delivers nothing more, exactly like `ws` + TCP.
    const pump = () => {
      while (!host.paused && sent < total) {
        manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: `hb-${sent}` }));
        sent += 1;
      }
    };
    pump();
    // The blocked frame plus queued heartbeats reach the high-water mark.
    expect(host.paused).toBe(true);
    expect(sent).toBe(SANDBOX_RECEIVE_MAX_FRAMES - 1);
    expect(host.pauses).toBe(1);
    expect(host.closes).toEqual([]);
    expect(host.readyState).toBe(WS_READY_STATE_OPEN);
    release.resolve();
    // Each resume lets the transport deliver more until the flood is in.
    for (let round = 0; sent < total; round++) {
      expect(round, "reads never resumed").toBeLessThan(100);
      await vi.waitFor(() => expect(host.paused).toBe(false));
      expect(host.resumes).toBeGreaterThanOrEqual(1);
      pump();
    }
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    expect(host.paused).toBe(false);
    expect(host.pauses).toBeGreaterThanOrEqual(2);
    expect(host.resumes).toBe(host.pauses);
    const pongs = host.sends
      .map((s) => JSON.parse(s) as { type: string; id?: string })
      .filter((m) => m.type === "heartbeat.pong")
      .map((m) => m.id);
    expect(pongs).toEqual(Array.from({ length: total }, (_, i) => `hb-${i}`));
  });
  it("P0-2: the byte high-water mark pauses reads without closing", async () => {
    const host = await registered();
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    let sent = 0;
    while (!host.paused) {
      manager.handleBinaryFrame(host, new ArrayBuffer(1024 * 1024));
      sent += 1;
    }
    expect(sent).toBe(SANDBOX_RECEIVE_MAX_BYTES / (1024 * 1024));
    expect(host.closes).toEqual([]);
    expect(host.readyState).toBe(WS_READY_STATE_OPEN);
    manager.removeSession(host);
    release.resolve();
    await manager.drain(host);
  });
  it("P0-2: frames that keep arriving while paused hit the hard ceiling as a protocol error", async () => {
    const host = await registered();
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    // A transport that ignores pause (never the case for `ws`).
    for (let i = 0; i < SANDBOX_RECEIVE_HARD_MAX_FRAMES; i++)
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "hb" }));
    expect(host.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
    expect(host.sends.map((s) => JSON.parse(s).type)).toContain("protocol.error");
    release.resolve();
    await manager.drain(host);
  });
  /** A registered socket whose reads are paused behind a blocked frame. */
  async function pausedHost(host: SandboxRelaySocket) {
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    for (let i = 1; i < SANDBOX_RECEIVE_MAX_FRAMES; i++)
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: `hb-${i}` }));
    return release;
  }
  const pausedTeardowns: [string, (host: FakeSocket) => Promise<unknown>][] = [
    ["remove", async (host) => manager.removeSession(host)],
    [
      "revoke",
      async () => {
        vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({ status: "inactive" });
        await withAuthorityChange({ credentialId: "token-1" }, async () => undefined);
        await flushCommittedAuthorityListeners();
      },
    ],
    ["replace", async () => registered()],
    ["shutdown", async () => manager.dispose()],
    [
      "protocol error",
      async (host) => {
        for (let i = 0; i < SANDBOX_RECEIVE_HARD_MAX_FRAMES; i++)
          manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "hb" }));
      },
    ],
  ];
  it.each(pausedTeardowns)(
    "P0-2: %s of a paused session releases the pause so the close handshake completes",
    async (_kind, teardown) => {
      const host = await registered();
      const release = await pausedHost(host);
      expect(host.paused).toBe(true);
      await teardown(host);
      await vi.waitFor(() => expect(host.closes).toHaveLength(1));
      // CLOSING forever (until the 30 s close timeout) if the pause stayed.
      expect(host.paused).toBe(false);
      expect(host.readyState).toBe(3);
      expect(manager.isHostConnected("host-1", 1)).toBe(false);
      release.resolve();
      await manager.drain(host);
      expect(host.resumes).toBe(host.pauses);
    },
  );
  it("P0-2: a real paused `ws` finishes its close handshake when the session is removed", async () => {
    const [serverEnd, peerEnd] = duplexPair();
    const http = createServer();
    const wss = new WebSocketServer({ noServer: true });
    const accepted = new Promise<WebSocket>((resolve) =>
      http.on("upgrade", (req, transport, head) =>
        wss.handleUpgrade(req, transport, head, resolve),
      ),
    );
    http.emit("connection", serverEnd);
    const peer = new WebSocket("ws://relay.test/", { createConnection: () => peerEnd });
    const ws = await accepted;
    try {
      if (peer.readyState !== WebSocket.OPEN) await once(peer, "open");
      // The production adapter's shape (websocket.ts) over the raw `ws`.
      const host: SandboxRelaySocket = {
        get readyState() {
          return ws.readyState;
        },
        send: (data) => ws.send(data),
        close: (code, reason) => ws.close(code, reason),
        pause: () => ws.pause(),
        resume: () => ws.resume(),
      };
      manager.acceptAuthenticatedSocket({ socket: host, identity: testIdentity });
      manager.handleTextFrame(host, helloFrame("host-1", "1.0", true));
      await manager.drain(host);
      for (const page of runningCensusFrames(store)) manager.handleTextFrame(host, page);
      manager.handleTextFrame(host, JSON.stringify({ type: "reconcile.complete" }));
      await manager.drain(host);
      expect(manager.isHostConnected("host-1", 1)).toBe(true);
      const release = await pausedHost(host);
      expect(ws.isPaused).toBe(true);
      const closed = once(ws, "close");
      manager.removeSession(host);
      // The peer's close reply is read at once, not after the 30 s timeout.
      const [code] = await Promise.race([
        closed,
        delay(2000).then(() => {
          throw new Error(`still ${ws.readyState} (CLOSING) after 2 s`);
        }),
      ]);
      expect(code).toBe(1001);
      release.resolve();
      await manager.drain(host);
    } finally {
      ws.terminate();
      peer.terminate();
      http.close();
    }
  });
  it.each([false, true])("Q7: completed download replay conflict=%s", async (conflict) => {
    const host = await registered();
    const full = new Uint8Array(1024 * 1024).fill(65);
    const chunk = (sequence: number, body: Uint8Array, final: boolean) =>
      encodeBinaryFrame(
        {
          type: final ? "stream.end" : "stream.chunk",
          streamId: "file",
          operationId: "op-1",
          generation: 1,
          attempt: 1,
          sequence,
          offset: sequence * full.length,
          final,
          flags: { fileDownload: true },
        },
        body,
      );
    manager.handleBinaryFrame(host, chunk(0, full, false));
    manager.handleBinaryFrame(host, chunk(1, new Uint8Array([66]), true));
    manager.handleBinaryFrame(host, chunk(1, new Uint8Array([conflict ? 67 : 66]), true));
    const content = Buffer.concat([full, new Uint8Array([66])]);
    manager.handleTextFrame(
      host,
      JSON.stringify({
        ...JSON.parse(resultFrame),
        result: {
          size: content.length,
          sha256: createHash("sha256").update(content).digest("hex"),
        },
      }),
    );
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe(conflict ? "FAILED" : "SUCCEEDED");
    if (!conflict) expect(Buffer.compare(Buffer.from(captures.bytes("op-1", 1)!), content)).toBe(0);
  });
  it.each(["stdin", "cancel", "terminal"])(
    "c4: %s waits across a committed but unsent dispatch and host acceptance",
    async (control) => {
      const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
      const { writeStdin, cancelOperation } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      Object.assign(store.operations.get("op-1")!, {
        kind: "RUN_COMMAND",
        state: "QUEUED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
        dispatchedConnectionEpoch: null,
      });
      store.outbox.get("evt-1")!.payload.dispatchAttempt = 0;
      const host = await registered();
      host.sends = [];
      const spies = [
        vi
          .spyOn(sandboxRelaySessionManager, "isHostConnected")
          .mockImplementation(manager.isHostConnected.bind(manager)),
        vi
          .spyOn(sandboxRelaySessionManager, "dispatchOperation")
          .mockImplementation(manager.dispatchOperation.bind(manager)),
        vi
          .spyOn(sandboxRelaySessionManager, "sendStdin")
          .mockImplementation(manager.sendStdin.bind(manager)),
        vi
          .spyOn(sandboxRelaySessionManager, "cancelOperation")
          .mockImplementation(manager.cancelOperation.bind(manager)),
      ];
      db.outboxEvent.findMany.mockImplementation((args) =>
        prismaPromise(
          Promise.resolve(
            [...store.outbox.values()]
              .filter((row) => matches(row, args?.where as Record<string, unknown>))
              .sort((a, b) => a.id.localeCompare(b.id))
              .slice(0, args?.take ?? 32) as never,
          ),
        ),
      );
      db.outboxEvent.updateMany.mockImplementation((args) =>
        prismaPromise(db.$transaction((tx) => tx.outboxEvent.updateMany(args))),
      );
      db.$queryRaw.mockResolvedValue([]);
      db.sandboxOperation.findFirst.mockImplementation((args) =>
        Object.assign(
          prismaPromise(
            Promise.resolve(
              [...store.operations.values()].find((row) =>
                matches(
                  { ...row, Sandbox: store.sandboxes.get(row.sandboxId) },
                  args?.where as Record<string, unknown>,
                ),
              ) as never,
            ),
          ),
          {
            User: vi.fn(),
            Sandbox: vi.fn(),
            TypedResult: vi.fn(),
            CommandOutput: vi.fn(),
            Placement: vi.fn(),
            Capture: vi.fn(),
            CapacityWait: vi.fn(),
            CredentialSpec: vi.fn(),
            RestoreWait: vi.fn(),
          },
        ),
      );
      const entered = gate(),
        resume = gate();
      store.barriers.afterCommit = async () => {
        store.barriers.afterCommit = undefined;
        entered.resolve();
        await resume.promise;
      };
      const first = processSandboxOutboxBatch();
      try {
        await entered.promise;
        expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
        if (control === "stdin") {
          for (const contentBase64 of ["QQ==", "Qg=="])
            await expect(
              writeStdin(
                { kind: "session" as const, ownerId: "user-1" },
                { operationId: "op-1", contentBase64 },
              ),
            ).rejects.toMatchObject({ data: { code: "sandbox.process_not_started" } });
        } else
          await cancelOperation(
            { kind: "session" as const, ownerId: "user-1" },
            { operationId: "op-1" },
          );
        await processSandboxOutboxBatch();
        expect(host.sends).toEqual([]);
        expect(host.binarySends).toEqual([]);
        for (const event of [...store.outbox.values()].slice(1)) {
          expect(event.processedAt).toBeNull();
          expect(event.claimToken).toBeNull();
        }
        resume.resolve();
        await first;
        expect(host.sends.map((frame) => JSON.parse(frame).type)).toEqual(["operation.dispatch"]);
        await processSandboxOutboxBatch(); // Sent is still not ACCEPTED.
        expect(host.binarySends).toEqual([]);
        expect(host.sends).toHaveLength(1);
        if (control === "terminal")
          manager.handleTextFrame(
            host,
            JSON.stringify({
              ...JSON.parse(resultFrame),
              state: "cancelled",
              result: undefined,
              error: { code: "cancelled", message: "command was cancelled" },
            }),
          );
        else
          manager.handleTextFrame(
            host,
            JSON.stringify({
              type: "operation.progress",
              id: "accepted-op-1",
              operationId: "op-1",
              sandboxId: "sbx-1",
              generation: 1,
              attempt: 1,
              state: "accepted",
            }),
          );
        await manager.drain(host);
        expect(host.closes).toEqual([]);
        await processSandboxOutboxBatch();
        expect([...store.outbox.values()].every((event) => event.processedAt !== null)).toBe(
          control !== "cancel",
        );
        if (control === "stdin") {
          expect(host.binarySends).toEqual([]);
        } else if (control === "cancel") {
          expect(host.sends.map((frame) => JSON.parse(frame).type)).toEqual([
            "operation.dispatch",
            "operation.cancel",
          ]);
          expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
          manager.handleTextFrame(
            host,
            JSON.stringify({
              type: "operation.result",
              id: "cancelled-op-1",
              operationId: "op-1",
              sandboxId: "sbx-1",
              generation: 1,
              attempt: 1,
              state: "cancelled",
              error: { code: "cancelled", message: "command was cancelled" },
            }),
          );
          await manager.drain(host);
          expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
        } else {
          expect(host.sends).toHaveLength(2);
          expect(JSON.parse(host.sends[1]!)).toMatchObject({ type: "receipt.confirmed" });
          expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
        }
      } finally {
        resume.resolve();
        await first;
        for (const spy of spies) spy.mockRestore();
      }
    },
  );
  it("R8: each reserved stdin sequence emits one actual frame, including empty EOF", async () => {
    const host = await registered();
    store.operations.get("op-1")!.kind = "RUN_COMMAND";
    await expect(
      manager.sendStdin("host-1", "op-1", 1, 1, new Uint8Array(), false, 1, 0, { kind: "session" }),
    ).rejects.toThrow("Empty stdin requires EOF");
    await expect(
      manager.sendStdin("host-1", "op-1", 1, 1, new Uint8Array(), false, 1, 0, { kind: "session" }),
    ).rejects.toThrow(SandboxRelayDispatchValidationError);
    expect(host.binarySends).toHaveLength(0);
    let next = 0;
    for (const [length, eof] of [
      [1, false],
      [1024 * 1024, false],
      [1024 * 1024 + 1, false],
      [0, true],
    ] as const) {
      const count = Math.max(1, Math.ceil(length / (1024 * 1024)));
      const before = host.binarySends.length;
      expect(
        await manager.sendStdin("host-1", "op-1", 1, 1, new Uint8Array(length), eof, 1, next, {
          kind: "session",
        }),
      ).toBe(true);
      const frames = host.binarySends.slice(before).map(parseBinaryFrame);
      expect(frames).toHaveLength(count);
      expect(frames.map((frame) => frame.metadata.sequence)).toEqual(
        Array.from({ length: count }, (_, i) => next + i),
      );
      expect(frames.reduce((sum, frame) => sum + frame.body.byteLength, 0)).toBe(length);
      expect(frames.at(-1)!.metadata.final).toBe(eof);
      next += count;
    }
  });
  it("Q2-extension: hello during delayed send confirmation leaves absent receipt unknown without retry", async () => {
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    Object.assign(store.operations.get("op-1")!, {
      kind: "RUN_COMMAND",
      state: "QUEUED",
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    });
    store.outbox.get("evt-1")!.payload.dispatchAttempt = 0;
    await registered();
    const connected = vi
      .spyOn(sandboxRelaySessionManager, "isHostConnected")
      .mockImplementation(manager.isHostConnected.bind(manager));
    const send = vi
      .spyOn(sandboxRelaySessionManager, "dispatchOperation")
      .mockImplementation(manager.dispatchOperation.bind(manager));
    db.outboxEvent.findMany.mockImplementation((args) =>
      prismaPromise(
        Promise.resolve(
          [...store.outbox.values()].filter((row) =>
            matches(row, args?.where as Record<string, unknown>),
          ) as never,
        ),
      ),
    );
    db.$queryRaw.mockResolvedValue([]);
    const entered = gate(),
      resume = gate();
    let delayed = false;
    db.outboxEvent.updateMany.mockImplementation((args) =>
      prismaPromise(
        (async () => {
          if (!delayed) {
            delayed = true;
            entered.resolve();
            await resume.promise;
          }
          return db.$transaction((tx) => tx.outboxEvent.updateMany(args));
        })(),
      ),
    );
    try {
      const first = processSandboxOutboxBatch();
      await entered.promise;
      expect(store.outbox.get("evt-1")!.sentConnectionEpoch).toBe(1);
      expect(store.outbox.get("evt-1")!.sentAt).toBeNull();
      await registered(); // actual production hello advances epoch and clears old claim
      expect(store.hosts.get("host-1")!.connectionEpoch).toBe(2);
      expect(store.outbox.get("evt-1")!.claimToken).toBeNull();
      resume.resolve();
      await first;
      expect(store.outbox.get("evt-1")!.sentAt).toBeNull();
      await processSandboxOutboxBatch();
      expect(send).toHaveBeenCalledTimes(1);
      expect(store.operations.get("op-1")!.dispatchAttempt).toBe(1);
      expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
      expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    } finally {
      connected.mockRestore();
      send.mockRestore();
      resume.resolve();
    }
  });
  it("nullable comparisons follow SQL, not JavaScript numeric coercion", () => {
    expect(matches({ id: "null", epoch: null }, { epoch: { lt: 2 } })).toBe(false);
    expect(matches({ id: "null", epoch: null }, { epoch: { gt: -1 } })).toBe(false);
  });
  it("hello reopens only unacknowledged sent intent from an older epoch", async () => {
    const event = store.outbox.get("evt-1")!;
    Object.assign(event, { sentAt: new Date(), sentConnectionEpoch: 0 });
    store.outbox.set("acknowledged", { ...event, id: "acknowledged", processedAt: new Date() });
    await registered();
    expect(store.outbox.get("evt-1")!.sentAt).toBeNull();
    expect(store.outbox.get("acknowledged")!.sentAt).not.toBeNull();
  });
  it("P15: blocked final chunk cannot be overtaken by its result", async () => {
    const host = await registered();
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    manager.handleTextFrame(host, resultFrame);
    await entered.promise;
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    resume.resolve();
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array([65, 66]));
    expect(captures.peek("op-1", 1)?.size).toBe(2);
    manager.handleTextFrame(host, resultFrame);
    await manager.drain(host);
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array([65, 66]));
  });
  it.each(["binary", "result"])("replacement revokes already-entered %s", async (kind) => {
    const host = await registered();
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    if (kind === "binary") manager.handleBinaryFrame(host, chunkFrame());
    else manager.handleTextFrame(host, resultFrame);
    await entered.promise;
    const replacement = await registered();
    expect(host.readyState).toBe(3);
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(2);
    resume.resolve();
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(captures.peek("op-1", 1)).toBeUndefined();
    manager.handleTextFrame(host, helloFrame("host-1"));
    await manager.drain(host);
    expect(replacement.readyState).toBe(1);
    expect(manager.isHostConnected("host-1")).toBe(true);
  });
  it("removal during registration cannot resurrect the socket", async () => {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeCommit = async () => {
      store.barriers.beforeCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    const host = socket();
    manager.handleTextFrame(host, helloFrame("host-1"));
    await entered.promise;
    manager.removeSession(host);
    resume.resolve();
    await manager.drain(host);
    expect(host.readyState).toBe(3);
    expect(manager.isHostConnected("host-1")).toBe(false);
    expect(host.sends.some((s) => JSON.parse(s).type === "hello.ok")).toBe(false);
    expect(store.hosts.get("host-1")).toMatchObject({
      connectionEpoch: 2,
      status: "DISCONNECTED",
      journalKeyAcknowledgedEpoch: null,
    });
  });

  it("a hello removed during commit cannot revoke a newer hello's epoch", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const entered = gate(),
      resume = gate();
    store.barriers.afterCommit = async () => {
      store.barriers.afterCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    const abandoned = socket();
    manager.handleTextFrame(abandoned, helloFrame("host-1"));
    await entered.promise;
    manager.removeSession(abandoned);
    const replacement = await registered();
    const epoch = store.hosts.get("host-1")!.connectionEpoch;
    resume.resolve();
    await manager.drain(abandoned);
    expect(store.hosts.get("host-1")).toMatchObject({
      connectionEpoch: epoch,
      status: "CONNECTED",
    });
    expect(manager.isHostConnected("host-1", epoch)).toBe(true);
    expect(replacement.readyState).toBe(1);
    expect(errors).not.toHaveBeenCalledWith(
      "[sandbox-relay] epoch revocation failed:",
      expect.anything(),
    );
    errors.mockRestore();
  });

  it("dispose waits for a removed hello to commit and revoke its epoch", async () => {
    const entered = gate(),
      resume = gate(),
      revoking = gate(),
      finishRevocation = gate();
    store.barriers.afterCommit = async () => {
      store.barriers.afterCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    const host = socket();
    manager.handleTextFrame(host, helloFrame("host-1"));
    await entered.promise;
    // The transport may have gone before shutdown; its hello still owns work.
    manager.removeSession(host);
    let disposed = false;
    const disposal = manager.dispose().then(() => {
      disposed = true;
    });
    await Promise.resolve();
    expect(disposed).toBe(false);
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      revoking.resolve();
      await finishRevocation.promise;
    };
    resume.resolve();
    await revoking.promise;
    expect(disposed).toBe(false);
    finishRevocation.resolve();
    await disposal;
    expect(store.hosts.get("host-1")).toMatchObject({ connectionEpoch: 2, status: "DISCONNECTED" });
  });

  it("does not double-increment epoch when registration is abandoned after commit", async () => {
    const predecessor = await registered();
    const before = store.hosts.get("host-1")!.connectionEpoch;
    const entered = gate(),
      resume = gate();
    vi.mocked(revalidateSandboxHostIdentity)
      .mockResolvedValueOnce({ status: "active", hostDeletionRequested: false })
      .mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return { status: "active", hostDeletionRequested: false };
      });
    const candidate = socket();
    manager.acceptAuthenticatedSocket({ socket: candidate, identity: testIdentity });
    manager.handleTextFrame(candidate, helloFrame("host-1"));
    await entered.promise;
    manager.removeSession(candidate);
    resume.resolve();
    await manager.drain(candidate);
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(before + 1);
    expect(manager.isHostConnected("host-1", before)).toBe(true);
    expect(predecessor.closes).toHaveLength(0);
  });

  it("hello keeps the owner-set label and records the daemon runtime and version", async () => {
    store.hosts.get("host-1")!.label = "Owner label";
    const host = socket();
    const hello = JSON.parse(helloFrame("host-1"));
    hello.daemon.version = "0.9.1";
    hello.daemon.capabilities.runtimeKind = "incus_kvm";
    hello.daemon.capabilities.egressPolicy = true;
    manager.handleTextFrame(host, JSON.stringify(hello));
    await manager.drain(host);
    const row = store.hosts.get("host-1")!;
    expect(row.status).toBe("CONNECTED");
    expect(row.label).toBe("Owner label");
    expect(row.daemonRuntime).toBe("INCUS_KVM");
    expect(row.daemonVersion).toBe("0.9.1");
    expect(row.egressEnforcement).toBe(true);
  });

  it("sends the deployment egress blocklist after every hello", async () => {
    const capable = socket();
    const hello = JSON.parse(helloFrame("host-1"));
    hello.daemon.capabilities.egress = { open: false, guard: true };
    manager.handleTextFrame(capable, JSON.stringify(hello));
    await manager.drain(capable);
    const frames = capable.sends.map((s) => JSON.parse(s));
    expect(frames.map((f) => f.type).slice(0, 3)).toEqual([
      "hello.ok",
      "journal.key.install",
      "egress.blocklist",
    ]);
    // Unset in tests: an explicit clear, never an absent list.
    expect(frames[2]).toEqual({
      type: "egress.blocklist",
      configured: false,
      entries: [],
      digest: blocklistDigest([]),
    });

    const older = socket();
    manager.handleTextFrame(older, helloFrame("host-1"));
    await manager.drain(older);
    expect(older.sends.map((s) => JSON.parse(s).type)).toContain("egress.blocklist");
  });

  it("hello without the egress capability records enforcement as off", async () => {
    const host = await registered(false, false);
    expect(host.readyState).not.toBe(3);
    expect(store.hosts.get("host-1")!.egressEnforcement).toBe(false);
  });

  it.each(["remove", "dispose"])("%s aborts an already-entered frame", async (action) => {
    const host = await registered();
    store.operations.get("op-1")!.state = "DISPATCHED";
    const entered = gate(),
      resume = gate();
    store.barriers.beforeOperationWrite = async () => {
      store.barriers.beforeOperationWrite = undefined;
      entered.resolve();
      await resume.promise;
    };
    manager.handleTextFrame(
      host,
      JSON.stringify({
        type: "operation.progress",
        id: "p",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "running",
      }),
    );
    await entered.promise;
    if (action === "remove") manager.removeSession(host);
    else manager.dispose();
    resume.resolve();
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
    expect(host.readyState).toBe(3);
  });

  it("times out an unregistered socket without advancing authority", async () => {
    vi.useFakeTimers();
    try {
      const host = socket();
      await vi.advanceTimersByTimeAsync(10001);
      expect(host.readyState).toBe(3);
      expect(store.hosts.get("host-1")!.connectionEpoch).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a failed hello reply still closes and revokes the registered socket", async () => {
    const host = socket();
    host.send = () => {
      throw new Error("transport failed");
    };
    manager.handleTextFrame(host, helloFrame("host-1"));
    await manager.drain(host);
    expect(host.readyState).toBe(3);
    expect(manager.isHostConnected("host-1")).toBe(false);
  });

  it("binds outbound controls and dispatch to the committed epoch", async () => {
    const host = await registered();
    expect(manager.isHostConnected("host-1", 1)).toBe(true);
    expect(manager.isHostConnected("host-1", 2)).toBe(false);
    const beforeFrameWrite = vi.fn(() => host.sends.length);
    const beforeSendCount = host.sends.length;
    const base = {
      authorizingPrincipal: { kind: "session" as const },
      sandboxOwnerId: "user-1",
      onPossibleDispatchFrame: beforeFrameWrite,
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "key",
      bodyHash: "a".repeat(64),
      kind: "command.run",
      generation: 1,
      attempt: 1,
    };
    expect(await manager.dispatchOperation("host-1", base)).toBe("sent");
    expect(JSON.parse(host.sends.at(-1)!).timeoutMs).toBe(120000);
    expect(beforeFrameWrite).toHaveReturnedWith(beforeSendCount);
    expect(await manager.dispatchOperation("host-1", { ...base, kind: "snapshot.create" })).toBe(
      "refused_before_frame",
    );
    const replacement = await registered();
    expect(await manager.dispatchOperation("host-1", base)).toBe("refused_before_frame");
    expect(beforeFrameWrite).toHaveBeenCalledTimes(1);
    expect(
      await manager.sendStdin("host-1", "op-1", 1, 1, new Uint8Array(), true, 1, 32, {
        kind: "session",
      }),
    ).toBe(false);
    expect(await manager.cancelOperation("host-1", "op-1", 1, 1, 1, { kind: "session" })).toBe(
      false,
    );
    // Only hello.ok and the census ack.
    expect(replacement.sends.map((frame) => JSON.parse(frame).type)).toEqual([
      "hello.ok",
      "journal.key.install",
      "egress.blocklist",
      "inventory.ack",
    ]);
  });

  it("sends startup only to a session that advertised templateStartup (B9)", async () => {
    const host = await registered();
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { templateStartup?: boolean }
    >;
    Object.assign(store.sandboxes.get("sbx-1")!, { diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    Object.assign(store.placements.get("placement:sbx-1")!, {
      diskGiB: 32,
      cpuCount: 2,
      memoryMiB: 2048,
      chargedMemoryMiB: 2304,
      chargedVcpu: 2,
    });
    const create = {
      authorizingPrincipal: { kind: "session" as const },
      allocation: allocationFixture(),
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "startup-dispatch",
      kind: "sandbox.create",
      generation: 1,
      attempt: 1,
      bodyHash: "a".repeat(64),
      egressPolicy: { domains: [], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
      cpuCount: 2,
      memoryMiB: 2048,
      startup: { command: "npm start", ready: "curl -sf localhost:3000" },
    };
    const dispatches = () =>
      host.sends
        .map((frame) => JSON.parse(frame))
        .filter((frame) => frame.type === "operation.dispatch");
    sessions.get(host)!.templateStartup = false;
    expect(await manager.dispatchOperation("host-1", create)).toBe("refused_before_frame");
    expect(dispatches()).toHaveLength(0);
    sessions.get(host)!.templateStartup = true;
    expect(await manager.dispatchOperation("host-1", create)).toBe("sent");
    expect(dispatches()[0].startup).toEqual(create.startup);
  });

  it("sends disk offload fields only to a session that advertised diskOffload (I10)", async () => {
    const host = await registered();
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { diskOffload?: boolean }
    >;
    Object.assign(store.sandboxes.get("sbx-1")!, { diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    Object.assign(store.placements.get("placement:sbx-1")!, {
      diskGiB: 32,
      cpuCount: 2,
      memoryMiB: 2048,
      chargedMemoryMiB: 2304,
      chargedVcpu: 2,
    });
    const fingerprint = `sha256:${"d".repeat(64)}`;
    const reconnect = {
      authorizingPrincipal: { kind: "session" as const },
      allocation: allocationFixture(),
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "cold-dispatch",
      kind: "sandbox.reconnect",
      generation: 1,
      attempt: 1,
      bodyHash: "a".repeat(64),
      egressPolicy: { domains: [], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
      cpuCount: 2,
      memoryMiB: 2048,
    };
    const dispatches = () =>
      host.sends
        .map((frame) => JSON.parse(frame))
        .filter((frame) => frame.type === "operation.dispatch");
    const cached = {
      ...reconnect,
      launchMode: "cold" as const,
      expectDisk: { seq: 1, fingerprint },
      diskBaseFingerprint: fingerprint,
    };
    expect(sessions.get(host)!.diskOffload).toBe(false);
    expect(await manager.dispatchOperation("host-1", cached)).toBe("refused_before_frame");
    expect(dispatches()).toHaveLength(0);
    sessions.get(host)!.diskOffload = true;
    expect(await manager.dispatchOperation("host-1", cached)).toBe("sent");
    expect(dispatches()[0]).toMatchObject({
      launchMode: "cold",
      expectDisk: { seq: 1, fingerprint },
      diskBaseFingerprint: fingerprint,
    });
    // Disk frames go only to a diskOffload session of the current epoch.
    const frame = {
      type: "disk.evict.suggest" as const,
      sandboxId: "sbx-1",
      offloadId: "o",
      seq: 1,
    };
    expect(manager.sendDiskFrame("host-1", 2, frame)).toBe(false);
    expect(manager.sendDiskFrame("host-1", 1, frame)).toBe(true);
    sessions.get(host)!.diskOffload = false;
    expect(manager.sendDiskFrame("host-1", 1, frame)).toBe(false);
    expect(
      host.sends.filter((sent) => JSON.parse(sent).type === "disk.evict.suggest"),
    ).toHaveLength(1);
  });

  it("closes a session that sends a disk frame without advertising diskOffload", async () => {
    const host = await registered();
    manager.handleTextFrame(
      host,
      JSON.stringify({ type: "disk.evict.request", sandboxId: "sbx-1", offloadId: "o", seq: 1 }),
    );
    await manager.drain(host);
    expect(host.closes.length).toBeGreaterThan(0);
  });

  it.each(["1.0"])("dispatch uses the injected %s session size projection", async (version) => {
    const host = await registered();
    // Keep activation lists unchanged: inject only this already-registered
    // session to exercise the actual authorization + dispatch send path.
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { protocolVersion: string }
    >;
    const session = sessions.get(host)!;
    session.protocolVersion = version;
    Object.assign(store.sandboxes.get("sbx-1")!, { diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    Object.assign(store.placements.get("placement:sbx-1")!, {
      diskGiB: 32,
      cpuCount: 2,
      memoryMiB: 2048,
      chargedMemoryMiB: 2304,
      chargedVcpu: 2,
    });
    expect(
      await manager.dispatchOperation("host-1", {
        authorizingPrincipal: { kind: "session" },
        allocation: allocationFixture(),
        connectionEpoch: 1,
        operationId: "op-1",
        sandboxId: "sbx-1",
        idempotencyKey: "size-dispatch",
        kind: "sandbox.create",
        generation: 1,
        attempt: 1,
        bodyHash: "a".repeat(64),
        egressPolicy: { domains: [], cidrs: [] },
        egressPolicyHash: "b".repeat(64),
        cpuCount: 2,
        memoryMiB: 2048,
      }),
    ).toBe(version === "1.0" ? "sent" : "refused_before_frame");
    const dispatches = host.sends
      .map((frame) => JSON.parse(frame))
      .filter((frame) => frame.type === "operation.dispatch");
    expect(dispatches).toHaveLength(version === "1.0" ? 1 : 0);
    if (version !== "1.0") return;
    const dispatch = dispatches[0];
    if (version === "1.0")
      expect(dispatch).toMatchObject({
        allocation: { diskGiB: 32 },
        cpuCount: 2,
        memoryMiB: 2048,
      });
    else {
      expect(dispatch).not.toHaveProperty("cpuCount");
      expect(dispatch).not.toHaveProperty("memoryMiB");
    }
  });

  it("preserves absent command identity and Incus name for host defaults", async () => {
    const host = await registered();
    expect(
      await manager.dispatchOperation("host-1", {
        authorizingPrincipal: { kind: "session" },
        connectionEpoch: 1,
        operationId: "op-1",
        sandboxId: "sbx-1",
        idempotencyKey: "key",
        bodyHash: "a".repeat(64),
        kind: "command.run",
        generation: 1,
        attempt: 1,
        script: "true",
      }),
    ).toBe("sent");
    const sent = JSON.parse(host.sends.at(-1)!);
    for (const field of ["incusName", "guestUid", "guestGid", "guestHome", "guestShell"]) {
      expect(sent).not.toHaveProperty(field);
    }
  });

  it.each([0, 120_000, 300_000, 1_800_000])(
    "command.run preserves timeout %i through the wire builder",
    async (timeoutMs) => {
      const host = await registered();
      const bodyHash = "a".repeat(64);
      const input = {
        authorizingPrincipal: { kind: "session" as const },
        sandboxOwnerId: "user-1",
        connectionEpoch: 1,
        operationId: "op-1",
        sandboxId: "sbx-1",
        idempotencyKey: "key",
        bodyHash,
        kind: "command.run",
        generation: 1,
        attempt: 1,
        script: "true",
        stdinSequence: 0,
        recursive: false,
        architecture: "x86_64",
        templateDigest: `sha256:${"b".repeat(64)}`,
        incusFingerprint: `sha256:${"b".repeat(64)}`,
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/u",
        guestShell: "/bin/bash",
        incusName: "wssp-sbx-test",
        timeoutMs,
      };
      expect(await manager.dispatchOperation("host-1", input)).toBe("sent");
      const sent = JSON.parse(host.sends.at(-1)!);
      expect(sent.timeoutMs).toBe(timeoutMs);
      expect(sent).toEqual({
        ...buildCommandRunOperationDispatchMessage(
          commandRunDispatchBuildInputFromOutboxPayload({ ...input }, input.sandboxId, {
            sandboxOwnerId: "user-1",
            attempt: input.attempt,
            bodyHash,
            stdinSequence: 0,
          }),
        ),
      });
    },
  );
});

describe("wire receipt confirmation", () => {
  it.each(["SUCCEEDED", "RUNNING", "UNKNOWN_OUTCOME", "REJECTED"])(
    "reconciles %s without treating ACK as deletion authority",
    async (state) => {
      Object.assign(store.operations.get("op-1")!, {
        kind: "RUN_COMMAND",
        state: state === "REJECTED" ? "SUCCEEDED" : state,
        requestBodyHash: "a".repeat(64),
        idempotencyKey: "key",
        dispatchedConnectionEpoch: 1,
      });
      const host = socket();
      manager.handleTextFrame(host, helloFrame("host-1"));
      await manager.drain(host);
      manager.handleTextFrame(
        host,
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.receipt",
          operationId: "op-1",
          sandboxId: "sbx-1",
          generation: 1,
          attempt: 1,
          bodyHash: (state === "REJECTED" ? "b" : "a").repeat(64),
          idempotencyKey: "key",
          kind: "command.run",
          state: state === "UNKNOWN_OUTCOME" ? "unknown_outcome" : "succeeded",
          result: null,
          error: null,
        }),
      );
      await manager.drain(host);
      const messages = host.sends.map((value) => JSON.parse(value) as { type: string });
      expect(messages.filter((message) => message.type === "receipt.ack")).toHaveLength(1);
      expect(messages.filter((message) => message.type === "receipt.confirmed")).toHaveLength(
        state === "REJECTED" ? 0 : 1,
      );
    },
  );
});

describe("canonical dispatch producer parity", () => {
  it("carries the actual expiry producer through dispatch encoding and the shared receipt bound", async () => {
    manager.dispose();
    manager = sandboxRelaySessionManager;
    const host = await registered();
    store.operations.clear();
    store.outbox.clear();
    // Cleanup retains the exact immutable root binding.
    // Advance the injected clock to the fixture's existing lease deadline.
    const now = new Date(store.sandboxes.get("sbx-1")!.leaseExpiresAt!);
    db.$queryRaw.mockImplementation((_query, ...values) =>
      db.sandbox.findMany({
        where: {
          leaseExpiresAt: { lte: values[0] as Date },
          state: { in: ["READY", "REQUESTED", "SCHEDULED", "PROVISIONING", "STOPPED"] },
          ...(typeof values[1] === "string" ? { id: { gt: values[1] } } : {}),
        },
        orderBy: { id: "asc" },
        take: Number(values[4]),
      }),
    );
    db.sandbox.findMany.mockImplementation((args) =>
      prismaPromise(
        Promise.resolve(
          [...store.sandboxes.values()]
            .filter((row) => matches(row, args?.where as Record<string, unknown>))
            .slice(0, args?.take ?? 32) as never,
        ),
      ),
    );
    db.sandboxOperation.findUnique.mockResolvedValue(null);
    db.outboxEvent.findMany.mockImplementation((args) =>
      prismaPromise(
        Promise.resolve(
          [...store.outbox.values()]
            .filter((row) => matches(row, args?.where as Record<string, unknown>))
            .slice(0, args?.take ?? 32) as never,
        ),
      ),
    );
    db.outboxEvent.updateMany.mockImplementation((args) =>
      prismaPromise(prisma.$transaction((tx) => tx.outboxEvent.updateMany(args))),
    );
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    expect(await processSandboxOutboxBatch(() => now)).toBe(1); // durable expiry enqueue
    expect(await processSandboxOutboxBatch(() => now)).toBe(1); // real session-manager send
    const sent = JSON.parse(host.sends.at(-1)!);
    expect(sent).toEqual({ ...expiryStop, sandboxOwnerId: "user-1" }); // Rust admits this exact fixture, without replacing the hash.
    expect(
      parseDaemonControlFrame(
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.receipt",
          operationId: sent.operationId,
          sandboxId: sent.sandboxId,
          generation: sent.generation,
          attempt: sent.attempt,
          bodyHash: sent.bodyHash,
          idempotencyKey: sent.idempotencyKey,
          kind: sent.kind,
          state: "succeeded",
          result: null,
          error: null,
        }),
      ),
    ).toMatchObject({ bodyHash: expiryStop.bodyHash });
  });
  it.each([undefined, "lease-expire:sbx-1:1", "A".repeat(64), "a".repeat(63), "a".repeat(65)])(
    "rejects a noncanonical dispatch hash %s before any socket effect",
    async (bodyHash) => {
      const host = await registered();
      const before = [...host.sends];
      await expect(
        manager.dispatchOperation("host-1", {
          authorizingPrincipal: { kind: "session" },
          ...expiryStop,
          connectionEpoch: 1,
          bodyHash,
        }),
      ).rejects.toThrow("bodyHash must be a canonical lowercase SHA-256 hash");
      expect(host.sends).toEqual(before);
    },
  );
});

describe("C10 cancel acknowledgement on the wire", () => {
  it("recovers a committed cancel after confirmation is lost on reconnect", async () => {
    Object.assign(store.operations.get("op-1")!, {
      kind: "RUN_COMMAND",
      state: "CANCEL_REQUESTED",
      requestBodyHash: "a".repeat(64),
      idempotencyKey: "key",
      dispatchedConnectionEpoch: 1,
    });
    const old = await registered();
    const send = old.send.bind(old);
    old.send = (data) => {
      if (typeof data === "string" && JSON.parse(data).type === "receipt.confirmed")
        throw new Error("confirmation lost");
      send(data);
    };
    manager.handleTextFrame(
      old,
      JSON.stringify({
        type: "operation.result",
        id: "cancel-result",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "cancelled",
        error: { code: "cancelled", message: "command was cancelled" },
      }),
    );
    await manager.drain(old);
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
    expect(old.sends.some((s) => JSON.parse(s).type === "receipt.confirmed")).toBe(false);
    const replacement = socket();
    manager.handleTextFrame(replacement, helloFrame("host-1"));
    await manager.drain(replacement);
    manager.handleTextFrame(
      replacement,
      JSON.stringify({
        sandboxOwnerId: "user-1",
        type: "operation.receipt",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        bodyHash: "a".repeat(64),
        idempotencyKey: "key",
        kind: "command.run",
        state: "cancelled",
        error: { code: "cancelled", message: "command was cancelled" },
        result: null,
      }),
    );
    await manager.drain(replacement);
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
    expect(
      replacement.sends.filter((s) => JSON.parse(s).type === "receipt.confirmed"),
    ).toHaveLength(1);
    expect(
      replacement.sends.filter((s) => JSON.parse(s).type === "receipt.confirmed").length,
    ).toBeGreaterThan(0);
  });
});

describe("download confirmation recovery", () => {
  it("recovers a committed download after its confirmation is lost on reconnect", async () => {
    Object.assign(store.operations.get("op-1")!, {
      requestBodyHash: "a".repeat(64),
      idempotencyKey: "key",
    });
    const old = await registered();
    manager.handleBinaryFrame(old, chunkFrame());
    await manager.drain(old);
    // Simulate transport loss on the confirmation, AFTER production result commit.
    const send = old.send.bind(old);
    old.send = (data) => {
      if (typeof data === "string" && JSON.parse(data).type === "receipt.confirmed")
        throw new Error("confirmation lost");
      send(data);
    };
    manager.handleTextFrame(old, resultFrame);
    await manager.drain(old);
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array([65, 66]));
    expect(old.sends.some((s) => JSON.parse(s).type === "receipt.confirmed")).toBe(false);
    const replacement = socket();
    manager.handleTextFrame(replacement, helloFrame("host-1"));
    await manager.drain(replacement);
    manager.handleTextFrame(replacement, JSON.stringify(downloadRecovery.receipt));
    await manager.drain(replacement);
    expect(replacement.sends.map((s) => JSON.parse(s).type)).toEqual([
      "hello.ok",
      "journal.key.install",
      "egress.blocklist",
      "receipt.confirmed",
      "receipt.ack",
    ]);
    expect(JSON.parse(replacement.sends[3]!)).toEqual(downloadRecovery.confirmation);
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
  });
  // WP0: a success the server can never apply (its bytes are gone with the
  // old session) is not left open to replay: the server's verdict settles it
  // FAILED protocol_error, which confirms the receipt.
  it.each([
    ["unknown_outcome", "SUCCEEDED", true, "SUCCEEDED"],
    ["unknown_outcome", "FAILED", true, "FAILED"],
    ["unknown_outcome", "CANCELLED", true, "CANCELLED"],
    ["unknown_outcome", "UNKNOWN_OUTCOME", false, "UNKNOWN_OUTCOME"],
    ["succeeded", "UNKNOWN_OUTCOME", true, "FAILED"],
    ["succeeded", "SUCCEEDED", true, "SUCCEEDED"],
  ] as const)(
    "download report %s × durable server %s",
    async (state, durable, confirms, settled) => {
      Object.assign(store.operations.get("op-1")!, {
        state: durable,
        requestBodyHash: "a".repeat(64),
        idempotencyKey: "key",
      });
      const host = socket();
      manager.handleTextFrame(host, helloFrame("host-1"));
      await manager.drain(host);
      manager.handleTextFrame(
        host,
        JSON.stringify({
          sandboxOwnerId: "user-1",
          type: "operation.receipt",
          operationId: "op-1",
          sandboxId: "sbx-1",
          generation: 1,
          attempt: 1,
          bodyHash: "a".repeat(64),
          idempotencyKey: "key",
          kind: "file.get",
          state,
          result: null,
          error: null,
        }),
      );
      await manager.drain(host);
      expect(host.sends.filter((s) => JSON.parse(s).type === "receipt.confirmed")).toHaveLength(
        confirms ? 1 : 0,
      );
      expect(host.sends.filter((s) => JSON.parse(s).type === "receipt.ack")).toHaveLength(1);
      expect(store.operations.get("op-1")!.state).toBe(settled);
    },
  );
});

const probeInput = {
  incusFingerprint: "sha256:" + "a".repeat(64),
  ownerId: "user-1",
  hostId: "host-1",
  sandboxId: "sbx-1",
  generation: 1,
  architecture: "x86_64",
  guestUid: 1000,
  guestGid: 1000,
  guestHome: "/home/user",
  guestShell: "/bin/bash",
};
it("C14 disconnected and unreconciled hosts cannot yield live probe success", async () => {
  await expect(manager.probeSandbox(probeInput)).resolves.toBe("unreachable");
  const sock = socket();
  await expect(manager.probeSandbox(probeInput)).resolves.toBe("unreachable");
  expect(sock.sends.some((frame) => frame.includes("probe.request"))).toBe(false);
});
it.each(["guest_ready", "stopped", "confirmed_absent", "unreachable"])(
  "C14 live probe relays fresh %s evidence",
  async (state) => {
    const sock = await registered();
    const probe = manager.probeSandbox(probeInput);
    await vi.waitFor(() =>
      expect(JSON.parse(sock.sends.at(-1)!).type).toBe("sandbox.probe.request"),
    );
    const request = JSON.parse(sock.sends.at(-1)!);
    expect(request.type).toBe("sandbox.probe.request");
    manager.handleTextFrame(
      sock,
      JSON.stringify({ type: "sandbox.probe.result", requestId: request.requestId, state }),
    );
    await manager.drain(sock);
    await expect(probe).resolves.toBe(state);
  },
);
it.each(["disconnect", "shutdown"])("C14 pending probe becomes unreachable on %s", async (path) => {
  const sock = await registered();
  const probe = manager.probeSandbox(probeInput);
  if (path === "disconnect") manager.removeSession(sock);
  else manager.dispose();
  await expect(probe).resolves.toBe("unreachable");
});
it("C14 a probe timeout cannot be confused with stored lifecycle or late evidence", async () => {
  const sock = await registered();
  vi.useFakeTimers();
  try {
    const probe = manager.probeSandbox(probeInput);
    await vi.waitFor(() =>
      expect(JSON.parse(sock.sends.at(-1)!).type).toBe("sandbox.probe.request"),
    );
    const request = JSON.parse(sock.sends.at(-1)!);
    await vi.advanceTimersByTimeAsync(30_000);
    await expect(probe).resolves.toBe("unreachable");
    manager.handleTextFrame(
      sock,
      JSON.stringify({
        type: "sandbox.probe.result",
        requestId: request.requestId,
        state: "guest_ready",
      }),
    );
    await manager.drain(sock);
    await expect(probe).resolves.toBe("unreachable");
  } finally {
    vi.useRealTimers();
  }
});
it("C14 image verification stays bound to its requesting host session", async () => {
  const sock = await registered();
  const request = manager.verifyHostImage({
    ownerId: "user-1",
    hostId: "host-1",
    imageRef: "local:base",
    expectedArchitecture: "x86_64",
  });
  await vi.waitFor(() => expect(JSON.parse(sock.sends.at(-1)!).type).toBe("image.verify.request"));
  const observed = expect(request).rejects.toThrow("host disconnected");
  manager.removeSession(sock);
  await observed;
});

it("C46 a host's image refusal is HostImageRejected; losing the host is not", async () => {
  const { HostImageRejected } = await import("@wssp/api/sandbox/host-image-verifier");
  const sock = await registered();
  const refused = manager.verifyHostImage({
    ownerId: "user-1",
    hostId: "host-1",
    imageRef: "local:missing",
    expectedArchitecture: "x86_64",
  });
  await vi.waitFor(() => expect(JSON.parse(sock.sends.at(-1)!).type).toBe("image.verify.request"));
  const { requestId } = JSON.parse(sock.sends.at(-1)!);
  manager.handleTextFrame(
    sock,
    JSON.stringify({
      type: "image.verify.result",
      requestId,
      error: { code: "protocol_error", message: "alias `local:missing` not found" },
    }),
  );
  await manager.drain(sock);
  await expect(refused).rejects.toBeInstanceOf(HostImageRejected);
  await expect(refused).rejects.toThrow("alias `local:missing` not found");

  const lost = manager.verifyHostImage({
    ownerId: "user-1",
    hostId: "host-1",
    imageRef: "local:base",
    expectedArchitecture: "x86_64",
  });
  await vi.waitFor(() => expect(JSON.parse(sock.sends.at(-1)!).type).toBe("image.verify.request"));
  const observed = expect(lost).rejects.not.toBeInstanceOf(HostImageRejected);
  manager.removeSession(sock);
  await observed;
});

it("C14 replaced sockets cannot satisfy a new live probe", async () => {
  const old = await registered();
  const current = await registered();
  let resolved = false;
  const probe = manager.probeSandbox(probeInput).then((state) => {
    resolved = true;
    return state;
  });
  await vi.waitFor(() =>
    expect(JSON.parse(current.sends.at(-1)!).type).toBe("sandbox.probe.request"),
  );
  const request = JSON.parse(current.sends.at(-1)!);
  const response = JSON.stringify({
    type: "sandbox.probe.result",
    requestId: request.requestId,
    state: "guest_ready",
  });
  manager.handleTextFrame(old, response);
  await manager.drain(old);
  expect(resolved).toBe(false);
  manager.handleTextFrame(current, response);
  await manager.drain(current);
  await expect(probe).resolves.toBe("guest_ready");
});

describe("active credential boundaries", () => {
  it.each(["hello", "heartbeat", "chunk", "dispatch"])(
    "denies an inactive credential at %s",
    async (boundary) => {
      const host = boundary === "hello" ? socket() : await registered();
      const before = [...host.sends];
      vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({ status: "inactive" });
      if (boundary === "hello") manager.handleTextFrame(host, helloFrame("host-1"));
      if (boundary === "heartbeat")
        manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "hb" }));
      if (boundary === "chunk") manager.handleBinaryFrame(host, chunkFrame());
      if (boundary === "dispatch")
        expect(
          await manager.dispatchOperation("host-1", {
            authorizingPrincipal: { kind: "session" },
            connectionEpoch: 1,
            operationId: "op-1",
            sandboxId: "sbx-1",
            idempotencyKey: "key",
            kind: "command.run",
            generation: 1,
            attempt: 1,
            bodyHash: "a".repeat(64),
          }),
        ).toBe("refused_before_frame");
      await manager.drain(host);
      expect(host.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
      expect(manager.isHostConnected("host-1")).toBe(false);
      expect(host.sends).toEqual(before);
      expect(captures.peek("op-1", 1)).toBeUndefined();
      // Losing authority is not proof of guest termination.
      expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
    },
  );

  it("revocation closes after commit when revalidation fails", async () => {
    const host = await registered();
    vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({ status: "inactive" });
    await withAuthorityChange(
      { ownerId: "user-1", credentialId: "token-1" },
      async () => undefined,
    );
    await flushCommittedAuthorityListeners();
    expect(host.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
    expect(manager.isHostConnected("host-1")).toBe(false);
  });

  it("expires an idle registered connection and clears the timer on shutdown", async () => {
    vi.useFakeTimers();
    try {
      const host = new FakeSocket();
      manager.acceptAuthenticatedSocket({
        socket: host,
        identity: { ...testIdentity, expiresAt: new Date(Date.now() + 1000) },
      });
      manager.handleTextFrame(host, helloFrame("host-1"));
      await manager.drain(host);
      await vi.advanceTimersByTimeAsync(1000);
      expect(host.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
      manager.dispose();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("revocation between outbound chunks stops the remaining stream", async () => {
    const host = await registered();
    const send = host.send.bind(host);
    host.send = (data) => {
      send(data);
      if (data instanceof ArrayBuffer) {
        // The revoke commits durably: later revalidation reads the revoked row.
        vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({ status: "inactive" });
        void withAuthorityChange({ credentialId: "token-1" }, async () => undefined);
      }
    };
    // Dispatch itself is accepted; the revocation stops the backgrounded
    // stream task before it reads or sends another chunk (C29).
    expect(
      await manager.dispatchOperation("host-1", {
        authorizingPrincipal: { kind: "session" },
        connectionEpoch: 1,
        operationId: "op-1",
        sandboxId: "sbx-1",
        idempotencyKey: "key",
        kind: "file.put",
        bodyHash: "a".repeat(64),
        generation: 1,
        attempt: 1,
        fileUpload: {
          size: 2 * 1024 * 1024,
          sha256: "a".repeat(64),
          read: async (_offset, length) => new Uint8Array(length),
        },
      }),
    ).toBe("sent");
    // The stream task sends chunk 0 (which commits the revocation), then parks
    // on the chunk ACK until the authority close rejects it.
    await vi.waitFor(() => expect(host.binarySends).toHaveLength(1));
    await flushCommittedAuthorityListeners();
    expect(host.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
    await manager.settledFileStreams();
    expect(host.binarySends).toHaveLength(1);
  });
});

it.each(["revocation", "expiry"])(
  "retains the SDK %s fence until the actual socket send",
  async (change) => {
    const host = await registered();
    const before = [...host.sends];
    const start = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(start);
    store.operations.get("op-1")!.authorizingKeyId = "sdk-1";
    const authenticate = vi
      .spyOn(sdkAccess, "checkAcceptedDispatchAuthority")
      .mockImplementation(async (input) => {
        input.onActive?.(new Date(start + 1));
        if (change === "revocation")
          await withAuthorityChange(
            { ownerId: "user-1", credentialId: "sdk-1" },
            async () => undefined,
          );
        else clock.mockReturnValue(start + 1);
        return "active";
      });
    try {
      expect(
        await manager.dispatchOperation("host-1", {
          authorizingPrincipal: { kind: "sdkKey", keyId: "sdk-1" },
          connectionEpoch: 1,
          operationId: "op-1",
          sandboxId: "sbx-1",
          idempotencyKey: "key",
          kind: "command.run",
          generation: 1,
          attempt: 1,
          bodyHash: "a".repeat(64),
        }),
      ).toBe("refused_before_frame");
      expect(host.sends).toEqual(before);
      expect(host.closes).toEqual([]);
    } finally {
      clock.mockRestore();
      authenticate.mockRestore();
    }
  },
);

describe("C21-CANCELKEY cancel control key fence", () => {
  it("uses the control principal and the narrow accepted-authority check without rerunning scopes", async () => {
    const host = await registered();
    const before = [...host.sends];
    const narrow = vi
      .spyOn(sdkAccess, "checkAcceptedDispatchAuthority")
      .mockResolvedValue("active");
    const full = vi.spyOn(sdkAccess, "authorizeServiceAction");
    try {
      expect(
        await manager.cancelOperation("host-1", "op-1", 1, 1, 1, {
          kind: "sdkKey",
          keyId: "sdk-1",
        }),
      ).toBe(true);
      expect(narrow).toHaveBeenCalledWith(
        expect.objectContaining({
          ownerId: "user-1",
          principal: { kind: "sdkKey", keyId: "sdk-1" },
        }),
        expect.any(Object),
      );
      expect(full).not.toHaveBeenCalled();
      expect(host.sends.length).toBe(before.length + 1);
    } finally {
      narrow.mockRestore();
      full.mockRestore();
    }
  });
  it.each([
    ["keyed", "sdk-1"],
    ["keyless", null],
  ] as const)(
    "refuses relay control (cancel, stdin) for %s build attribution even when authority is active",
    async (_name, keyId) => {
      const host = await registered();
      const before = [...host.sends];
      const narrow = vi
        .spyOn(sdkAccess, "checkAcceptedDispatchAuthority")
        .mockResolvedValue("active");
      const build = { kind: "build" as const, buildId: "build-1", keyId };
      try {
        expect(await manager.cancelOperation("host-1", "op-1", 1, 1, 1, build)).toBe(false);
        expect(
          await manager.sendStdin("host-1", "op-1", 1, 1, new Uint8Array(), true, 1, 0, build),
        ).toBe(false);
        // Refused before any authority lookup or frame: builds end steps by kill.
        expect(narrow).not.toHaveBeenCalled();
        expect(host.sends).toEqual(before);
      } finally {
        narrow.mockRestore();
      }
    },
  );
  it("does not send a cancel whose own key is inactive", async () => {
    const host = await registered();
    const before = [...host.sends];
    const narrow = vi
      .spyOn(sdkAccess, "checkAcceptedDispatchAuthority")
      .mockResolvedValue("inactive");
    try {
      expect(
        await manager.cancelOperation("host-1", "op-1", 1, 1, 1, {
          kind: "sdkKey",
          keyId: "sdk-1",
        }),
      ).toBe(false);
      expect(host.sends).toEqual(before);
      expect(host.closes).toEqual([]);
    } finally {
      narrow.mockRestore();
    }
  });
});

it("file sender waits for the exact fenced ACK before reading another chunk", async () => {
  const host = await registered();
  const first = gate();
  const send = host.send.bind(host);
  host.send = (data) => {
    send(data);
    if (!(data instanceof ArrayBuffer)) return;
    const { metadata, body } = parseBinaryFrame(data);
    if (metadata.sequence === 0) first.resolve();
    else
      manager.handleTextFrame(
        host,
        JSON.stringify({
          type: "file.chunk.ack",
          operationId: "op-1",
          generation: 1,
          attempt: 1,
          sequence: metadata.sequence,
          offset: metadata.offset! + body.length,
        }),
      );
  };
  const read = vi.fn(async (_offset: number, length: number) => new Uint8Array(length));
  const dispatch = manager.dispatchOperation("host-1", {
    authorizingPrincipal: { kind: "session" },
    connectionEpoch: 1,
    operationId: "op-1",
    sandboxId: "sbx-1",
    idempotencyKey: "file",
    bodyHash: "a".repeat(64),
    kind: "file.put",
    generation: 1,
    attempt: 1,
    fileUpload: { size: 2 * 65536 + 3, sha256: "a".repeat(64), read },
  });
  await first.promise;
  for (const identity of [
    { generation: 2, sequence: 0, offset: 65536 },
    { generation: 1, sequence: 2, offset: 65536 },
    { generation: 1, sequence: 0, offset: 1 },
  ])
    manager.handleTextFrame(
      host,
      JSON.stringify({ type: "file.chunk.ack", operationId: "op-1", attempt: 1, ...identity }),
    );
  await manager.drain(host);
  expect(read).toHaveBeenCalledTimes(1);
  manager.handleTextFrame(
    host,
    JSON.stringify({
      type: "file.chunk.ack",
      operationId: "op-1",
      attempt: 1,
      generation: 1,
      sequence: 0,
      offset: 65536,
    }),
  );
  // The dispatch promise resolves with the control send (C29); the stream task
  // owns the remaining chunks, still gated on each exact fenced ACK.
  expect(await dispatch).toBe("sent");
  await manager.settledFileStreams();
  expect(read.mock.calls).toEqual([
    [0, 65536],
    [65536, 65536],
    [131072, 3],
  ]);
});

it("C29 a stalled upload stream never blocks dispatch or cancellation of other work", async () => {
  const host = await registered();
  store.operations.set("op-put", {
    ...store.operations.get("op-1")!,
    id: "op-put",
    kind: "PUT_FILE",
    state: "RUNNING",
  });
  // The first chunk's ACK never arrives: the stream parks on it.
  expect(
    await manager.dispatchOperation("host-1", {
      authorizingPrincipal: { kind: "session" },
      connectionEpoch: 1,
      operationId: "op-put",
      sandboxId: "sbx-1",
      idempotencyKey: "put",
      kind: "file.put",
      bodyHash: "a".repeat(64),
      generation: 1,
      attempt: 1,
      fileUpload: {
        size: 3 * 65536,
        sha256: "a".repeat(64),
        read: async (_offset, length) => new Uint8Array(length),
      },
    }),
  ).toBe("sent");
  await vi.waitFor(() => expect(host.binarySends).toHaveLength(1));
  store.operations.set("op-2", {
    ...store.operations.get("op-put")!,
    id: "op-2",
    kind: "STOP_SANDBOX",
  });
  // Unrelated dispatch and cancellation proceed while the upload is stalled.
  expect(
    await manager.dispatchOperation("host-1", {
      authorizingPrincipal: { kind: "session" },
      allocation: allocationFixture(),
      connectionEpoch: 1,
      operationId: "op-2",
      sandboxId: "sbx-1",
      idempotencyKey: "stop",
      kind: "sandbox.stop",
      bodyHash: "a".repeat(64),
      generation: 1,
      attempt: 1,
    }),
  ).toBe("sent");
  expect(await manager.cancelOperation("host-1", "op-put", 1, 1, 1, { kind: "session" })).toBe(
    true,
  );
  manager.removeSession(host);
  await manager.settledFileStreams();
});

it("C29 file.put capacity is reservable before the dispatch claim and refusal stays countable", async () => {
  const host = await registered();
  const put = (operationId: string, extra: Record<string, unknown> = {}) => {
    if (!store.operations.has(operationId))
      store.operations.set(operationId, {
        ...store.operations.get("op-1")!,
        id: operationId,
        kind: "PUT_FILE",
      });
    return {
      authorizingPrincipal: { kind: "session" as const },
      connectionEpoch: 1,
      operationId,
      sandboxId: "sbx-1",
      idempotencyKey: operationId,
      kind: "file.put",
      bodyHash: "a".repeat(64),
      generation: 1,
      attempt: 1,
      fileUpload: {
        size: 65536,
        sha256: "a".repeat(64),
        // The stream parks on its first ACK, holding its slot.
        read: async (_offset: number, length: number) => new Uint8Array(length),
      },
      ...extra,
    };
  };
  // Every slot reserved before any claim: no capacity remains for newcomers.
  const slots = Array.from({ length: 16 }, () => manager.reserveFileStreamSlot());
  expect(slots.every((slot) => slot !== null)).toBe(true);
  expect(manager.reserveFileStreamSlot()).toBeNull();
  // An unreserved dispatch observes the reservations and is refused.
  expect(await manager.dispatchOperation("host-1", put("op-unreserved"))).toBe(
    "refused_before_frame",
  );
  // A reserved dispatch proceeds even at full count; its keyed stream replaces
  // the reservation in the accounting.
  const adopted = slots.pop()!;
  expect(
    await manager.dispatchOperation("host-1", put("op-reserved", { fileStreamSlot: adopted })),
  ).toBe("sent");
  expect(manager.reserveFileStreamSlot()).toBeNull();
  const beforeDuplicate = host.sends.length;
  const possibleFrame = vi.fn();
  expect(
    await manager.dispatchOperation(
      "host-1",
      put("op-reserved", { onPossibleDispatchFrame: possibleFrame }),
    ),
  ).toBe("sent_then_lost_authority");
  expect(possibleFrame).toHaveBeenCalledOnce();
  expect(host.sends).toHaveLength(beforeDuplicate);
  // Releasing is idempotent and frees exactly one slot.
  slots[0]!.release();
  slots[0]!.release();
  const spare = manager.reserveFileStreamSlot();
  expect(spare).not.toBeNull();
  spare!.release();
  for (const slot of slots) slot?.release();
  manager.removeSession(host);
  await manager.settledFileStreams();
});

it("C29 a transient store read-admission refusal is retried, not fatal to the sender", async () => {
  const host = await registered();
  const send = host.send.bind(host);
  host.send = (data) => {
    send(data);
    if (!(data instanceof ArrayBuffer)) return;
    const { metadata, body } = parseBinaryFrame(data);
    manager.handleTextFrame(
      host,
      JSON.stringify({
        type: "file.chunk.ack",
        operationId: "op-1",
        generation: 1,
        attempt: 1,
        sequence: metadata.sequence,
        offset: metadata.offset! + body.length,
      }),
    );
  };
  let failures = 0;
  const read = vi.fn(async (_offset: number, length: number) => {
    if (failures++ < 2) throw new ORPCError("CONFLICT");
    return new Uint8Array(length);
  });
  expect(
    await manager.dispatchOperation("host-1", {
      authorizingPrincipal: { kind: "session" },
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "file",
      bodyHash: "a".repeat(64),
      kind: "file.put",
      generation: 1,
      attempt: 1,
      fileUpload: { size: 65536 + 5, sha256: "a".repeat(64), read },
    }),
  ).toBe("sent");
  await manager.settledFileStreams();
  // Chunk 0 is retried past two transient refusals, chunk 1 reads clean: both
  // chunks are still sent after the refusals.
  expect(read).toHaveBeenCalledTimes(4);
  expect(host.binarySends).toHaveLength(2);
});

it("C46 a host_capacity image answer is retryable host-unavailable, never image rejection", async () => {
  const { HostImageRejected } = await import("@wssp/api/sandbox/host-image-verifier");
  const sock = await registered();
  const busy = manager.verifyHostImage({
    ownerId: "user-1",
    hostId: "host-1",
    imageRef: "local:base",
    expectedArchitecture: "x86_64",
  });
  await vi.waitFor(() => expect(JSON.parse(sock.sends.at(-1)!).type).toBe("image.verify.request"));
  const { requestId } = JSON.parse(sock.sends.at(-1)!);
  manager.handleTextFrame(
    sock,
    JSON.stringify({
      type: "image.verify.result",
      requestId,
      error: { code: "host_capacity", message: "host image observation queue full" },
    }),
  );
  await manager.drain(sock);
  await expect(busy).rejects.toThrow("host image observation queue full");
  await expect(busy).rejects.not.toBeInstanceOf(HostImageRejected);
});

describe("connected expiry status", () => {
  const status = JSON.stringify({
    type: "sandbox.expiry_status",
    batch: 1,
    observation: 1,
    entries: [
      {
        sandboxOwnerId: "user-1",
        root: null,
        sandboxId: "sbx-1",
        state: "ready",
        lease: {
          generation: 1,
          lease: {
            revision: 1,
            deadlineUnixMs: 1_000,
            action: "stop",
            expiryPolicy: "retry-force-60s",
          },
          expired: true,
          expiryComplete: false,
          timerExpired: true,
          expiryFailure: { reason: "stop failed", attempts: 1, sinceUnixMs: 1_000 },
        },
      },
    ],
  });
  it("applies a host expiry failure only after reconciliation", async () => {
    Object.assign(store.sandboxes.get("sbx-1")!, {
      leaseRevisionEffective: 1,
      leaseExpiresAtEffective: new Date(1_000),
      leaseExpireActionEffective: "STOP",
    });
    const early = socket();
    manager.handleTextFrame(early, helloFrame("host-1"));
    manager.handleTextFrame(early, status);
    await manager.drain(early);
    expect(store.sandboxes.get("sbx-1")).toMatchObject({ state: "READY" });
    manager.dispose();
    manager = new SandboxRelaySessionManager();

    const host = await registered();
    manager.handleTextFrame(host, status);
    await manager.drain(host);
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "ERROR",
      lastErrorCode: "expiry_failed",
      lastErrorDetail: "Host could not enforce sandbox expiry.",
    });
    expect(host.closes).toEqual([]);
  });
});

describe("C52-R2-3 per-host socket cap", () => {
  const refusal = (candidate: FakeSocket) => ({
    sends: candidate.sends.map((frame) => JSON.parse(frame)),
    closes: candidate.closes,
  });
  const otherHost = { ...testIdentity, hostId: "host-2" };

  it("admits up to the default cap of 2 and refuses the next socket with a typed, daemon-visible error", () => {
    const first = socket();
    const second = socket();
    const third = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: third, identity: testIdentity })).toBe(
      false,
    );
    expect(first.closes).toEqual([]);
    expect(second.closes).toEqual([]);
    expect(refusal(third)).toEqual({
      sends: [
        {
          type: "protocol.error",
          failure: "rate_limited",
          message: expect.stringContaining("SANDBOX_MAX_SOCKETS_PER_HOST"),
        },
      ],
      closes: [{ code: 1013, reason: "host_socket_limit" }],
    });
    // A refused socket has no session: its frames are dropped, nothing is queued.
    manager.handleTextFrame(third, helloFrame("host-1"));
    expect(third.sends).toHaveLength(1);
    // Inverse: the cap is per host.
    const elsewhere = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: elsewhere, identity: otherHost })).toBe(
      true,
    );
    expect(elsewhere.closes).toEqual([]);
  });

  it("a closed socket frees its slot", () => {
    const first = socket();
    socket();
    manager.removeSession(first);
    const next = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: next, identity: testIdentity })).toBe(true);
    expect(next.closes).toEqual([]);
  });

  it("a reconnect overlapping a live session is admitted, and the replacement frees the old slot", async () => {
    const old = await registered();
    const replacement = await registered();
    expect(old.closes.length).toBeGreaterThan(0);
    expect(replacement.closes).toEqual([]);
    const overlap = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: overlap, identity: testIdentity })).toBe(
      true,
    );
    const extra = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: extra, identity: testIdentity })).toBe(
      false,
    );
  });

  it("honours a configured cap", () => {
    manager.dispose();
    manager = new SandboxRelaySessionManager({ maxSocketsPerHost: 1 });
    socket();
    const second = new FakeSocket();
    expect(manager.acceptAuthenticatedSocket({ socket: second, identity: testIdentity })).toBe(
      false,
    );
    expect(refusal(second).sends[0].message).toContain("at most 1 concurrent");
  });
});

describe("socket slot release on abnormal paths", () => {
  const admits = () => {
    const s = new FakeSocket();
    return manager.acceptAuthenticatedSocket({ socket: s, identity: testIdentity });
  };
  it("a hello whose commit fails frees its slot", async () => {
    const a = socket();
    socket();
    db.$transaction.mockRejectedValueOnce(new Error("db down"));
    manager.handleTextFrame(a, helloFrame("host-1"));
    await manager.drain(a);
    await new Promise((r) => setTimeout(r, 20));
    console.log(
      "probeA closes",
      JSON.stringify(a.closes),
      a.sends.map((x) => JSON.parse(x).type),
    );
    expect(a.closes.length).toBeGreaterThan(0);
    expect(admits()).toBe(true);
    expect(admits()).toBe(false);
  });
  it("a hello naming another host frees its slot", async () => {
    const a = socket();
    socket();
    manager.handleTextFrame(a, helloFrame("host-OTHER"));
    await manager.drain(a);
    console.log("probeB closes", JSON.stringify(a.closes));
    expect(admits()).toBe(true);
  });
  it("the unregistered timeout frees both slots", async () => {
    manager.dispose();
    vi.useFakeTimers();
    try {
      manager = new SandboxRelaySessionManager();
      socket();
      socket();
      expect(admits()).toBe(false);
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      expect(admits()).toBe(true);
      expect(admits()).toBe(true);
      expect(admits()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
  it("dispose clears the per-host sets; a garbage frame frees its slot", async () => {
    const a = socket();
    socket();
    manager.handleTextFrame(a, "{not json");
    await manager.drain(a).catch(() => {});
    console.log("probeD closes", JSON.stringify(a.closes));
    expect(admits()).toBe(true);
    manager.dispose();
    expect(admits()).toBe(true);
    expect(admits()).toBe(true);
    expect(admits()).toBe(false);
  });
  it("an oversized frame on an unregistered socket frees its slot", async () => {
    const a = socket();
    socket();
    manager.handleTextFrame(a, "x".repeat(9 * 1024 * 1024));
    await manager.drain(a).catch(() => {});
    console.log("probeE closes", JSON.stringify(a.closes));
    expect(admits()).toBe(true);
  });
});

describe("3D private config socket carrier", () => {
  it.each(["1.0"])(
    "%s sends values only to the exact owner/host/epoch with current key ACK",
    async (version) => {
      db.sandboxTemplateAvailability.findMany.mockResolvedValue([]);
      const host = socket();
      const hello = JSON.parse(helloFrame("host-1"));
      hello.supportedProtocolVersions = [version];
      manager.handleTextFrame(host, JSON.stringify(hello));
      await manager.drain(host);
      for (const page of runningCensusFrames(store)) manager.handleTextFrame(host, page);
      manager.handleTextFrame(host, JSON.stringify({ type: "reconcile.complete" }));
      await manager.drain(host);
      expect(host.closes).toEqual([]);
      expect(manager.isHostConnected("host-1")).toBe(true);
      const epoch = Number(
        host.sends.map((value) => JSON.parse(value)).find((frame) => frame.type === "hello.ok")
          .connectionEpoch,
      );
      expect(epoch).toBeGreaterThan(0);
      const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
      const keyId = requestDigestMetadata().requestDigestKeyId;
      const frame: Extract<
        import("./protocol.js").ServerControlMessage,
        { type: "private.config.install" }
      > = {
        sandboxOwnerId: "user-1",
        type: "private.config.install",
        refusalToken: "install-token",
        connectionEpoch: epoch,
        server: "wss://server/ws/sandbox-host",
        hostOwnerId: "user-1",
        hostId: "host-1",
        sandboxId: "sbx-1",
        generation: 1,
        config: {
          configId: "config",
          bindingScheme: "hmac-sha256-v1",
          bindingKeyId: keyId,
          bindingMac: "c".repeat(64),
        },
        env: [["APP", "synthetic-private-carrier"]],
      };
      db.sandboxHost.findFirst.mockResolvedValue({
        connectionEpoch: epoch,
        journalKeyVersion: 1,
        journalKeyId: keyId,
        journalKeyAcknowledgedEpoch: null,
      } as never);
      expect(
        await manager.installExecutionConfig("host-1", "op-1", { kind: "session" }, frame),
      ).toBe("not_sent");
      Object.assign(store.hosts.get("host-1")!, {
        journalKeyVersion: 1,
        journalKeyId: keyId,
        journalKeyAcknowledgedEpoch: epoch,
      });
      db.sandboxHost.findFirst.mockResolvedValue({
        connectionEpoch: epoch,
        journalKeyVersion: 1,
        journalKeyId: keyId,
        journalKeyAcknowledgedEpoch: epoch,
      } as never);
      for (const patch of [
        { hostOwnerId: "other-owner" },
        { sandboxOwnerId: "other-creator" },
        { hostId: "other-host" },
        { connectionEpoch: epoch + 1 },
      ])
        expect(
          await manager.installExecutionConfig(
            "host-1",
            "op-1",
            { kind: "session" },
            { ...frame, ...patch },
          ),
        ).toBe("not_sent");
      expect(
        host.sends
          .map((value) => JSON.parse(value))
          .filter((value) => value.type === "private.config.install"),
      ).toEqual([]);
      expect(
        await manager.installExecutionConfig(
          "host-1",
          "op-1",
          { kind: "session" },
          {
            ...frame,
            env: [["HOME", "synthetic-private-carrier"]],
          },
        ),
      ).toBe("invalid_config");
      expect(
        host.sends
          .map((value) => JSON.parse(value))
          .filter((value) => value.type === "private.config.install"),
      ).toEqual([]);
      expect(
        await manager.installExecutionConfig("host-1", "op-1", { kind: "session" }, frame),
      ).toBe(true);
      expect(
        host.sends
          .map((value) => JSON.parse(value))
          .filter((value) => value.type === "private.config.install"),
      ).toEqual([
        version === "1.0"
          ? frame
          : Object.fromEntries(Object.entries(frame).filter(([key]) => key !== "refusalToken")),
      ]);
    },
  );
});

describe("pruned receipt wire ingestion", () => {
  it("queues teardown for a pruned create receipt and keeps capacity held without fabricating a receipt hash or confirmation", async () => {
    const host = socket();
    const hello = JSON.parse(helloFrame("host-1"));
    hello.supportedProtocolVersions = ["1.0"];
    manager.handleTextFrame(host, JSON.stringify(hello));
    await manager.drain(host);
    expect(
      host.sends.map((value) => JSON.parse(value)).find((m) => m.type === "hello.ok")
        ?.protocolVersion,
    ).toBe("1.0");
    Object.assign(store.operations.get("op-1")!, {
      kind: "CREATE_SANDBOX",
      idempotencyKey: "key",
      state: "DISPATCHED",
      dispatchedConnectionEpoch: 1,
    });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = 1024;
    for (const spoof of [
      { sandboxOwnerId: "other-creator" },
      { idempotencyKey: "other-key" },
      { kind: "sandbox.kill" },
      { generation: 2 },
    ]) {
      const before = host.sends.length;
      manager.handleTextFrame(
        host,
        JSON.stringify({
          type: "operation.receipt.pruned",
          sandboxOwnerId: "user-1",
          operationId: "op-1",
          sandboxId: "sbx-1",
          generation: 1,
          attempt: 1,
          idempotencyKey: "key",
          kind: "sandbox.create",
          ...spoof,
        }),
      );
      await manager.drain(host);
      expect(host.sends).toHaveLength(before);
      expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
    }
    manager.handleTextFrame(
      host,
      JSON.stringify({
        sandboxOwnerId: "user-1",
        type: "operation.receipt.pruned",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        idempotencyKey: "key",
        kind: "sandbox.create",
      }),
    );
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "receipt_digest_pruned",
      errorDetail: "Sandbox provisioning outcome unconfirmed; cleanup queued.",
    });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "STOPPING",
      liveResourcesHeld: true,
    });
    expect(store.hosts.get("host-1")!.liveCount).toBe(1);
    const messages = host.sends.map((value) => JSON.parse(value));
    expect(messages.filter((m) => m.type === "receipt.ack")).toEqual([
      { type: "receipt.ack", operationId: "op-1" },
    ]);
    expect(messages.filter((m) => m.type === "receipt.pruned.ack")).toEqual([
      {
        sandboxOwnerId: "user-1",
        type: "receipt.pruned.ack",
        connectionEpoch: 1,
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        idempotencyKey: "key",
        kind: "sandbox.create",
      },
    ]);
    expect(messages.filter((m) => m.type === "receipt.confirmed")).toEqual([]);
  });
});

it("3A captured host credential stays epoch-bound after socket revocation", async () => {
  await registered();
  const captured = manager.captureHostDispatchCredential("host-1")!;
  expect(await captured(2)).toBe("indeterminate");
  expect(await captured(1)).toBe("active");
  vi.mocked(revalidateSandboxHostIdentity).mockResolvedValueOnce({
    status: "stale",
    hostDeletionRequested: false,
  });
  expect(await captured(1)).toBe("indeterminate");
  vi.mocked(revalidateSandboxHostIdentity).mockResolvedValueOnce({ status: "inactive" });
  expect(await captured(1)).toBe("inactive");
});

it("exact image absence stays distinct from verification rejection and host failure", async () => {
  const { HostImageMissing } = await import("@wssp/api/sandbox/host-image-verifier");
  const sock = await registered();
  const missing = manager.verifyHostImage({
    ownerId: "user-1",
    hostId: "host-1",
    imageRef: `sha256:${"a".repeat(64)}`,
    expectedArchitecture: "x86_64",
  });
  const observed = expect(missing).rejects.toBeInstanceOf(HostImageMissing);
  await vi.waitFor(() => expect(JSON.parse(sock.sends.at(-1)!).type).toBe("image.verify.request"));
  const { requestId } = JSON.parse(sock.sends.at(-1)!);
  manager.handleTextFrame(
    sock,
    JSON.stringify({
      type: "image.verify.result",
      requestId,
      error: { code: "not_found", message: "Image missing" },
    }),
  );
  await manager.drain(sock);
  await observed;
});

it.each([
  ["1.0", "CREATE_SANDBOX", true],
  ["1.0", "RECONNECT_SANDBOX", true],
  ["1.0", "CREATE_SANDBOX", false],
  ["1.0", "GET_FILE", false],
  ["1.0", "RUN_COMMAND", false],
] as const)(
  "%s %s UNKNOWN keeps its session and terminals: %s",
  async (version, kind, _eligible) => {
    const host = await registered();
    const terminals = Reflect.get(
      manager,
      "terminals",
    ) as import("./terminal-manager.js").SandboxTerminalManager;
    const terminalClose = vi.spyOn(terminals, "removeHostSocket");
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { protocolVersion: string }
    >;
    sessions.get(host)!.protocolVersion = version;
    Object.assign(store.operations.get("op-1")!, { kind, state: "DISPATCHED" });
    store.sandboxes.get("sbx-1")!.liveResourcesHeld = true;
    if (kind === "CREATE_SANDBOX") store.sandboxes.get("sbx-1")!.state = "PROVISIONING";
    manager.handleTextFrame(
      host,
      JSON.stringify({
        type: "operation.result",
        id: "unknown",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "unknown_outcome",
        error: { code: "host_capacity", message: "admission refused" },
      }),
    );
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe(
      kind === "CREATE_SANDBOX" ? "FAILED" : "UNKNOWN_OUTCOME",
    );
    expect(host.closes).toEqual([]);
    expect(terminalClose).not.toHaveBeenCalled();
    expect(host.sends.some((frame) => JSON.parse(frame).type === "terminal.close")).toBe(false);
    expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(true);
  },
);

it.each([true, false])(
  "an in-flight allocation enqueue racing the request stays held (answer first: %s)",
  async (answerFirst) => {
    const { AllocationAttestation } = await import("./allocation-attestation.js");
    const host = await registered();
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      {
        protocolVersion: string;
        allocationSequence: number;
        allocationAttestation?: InstanceType<typeof AllocationAttestation>;
      }
    >;
    const session = sessions.get(host)!;
    session.protocolVersion = "1.0";
    session.allocationSequence = 1;
    Object.assign(store.hosts.get("host-1")!, {
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionEpoch: 1,
      daemonFeatures: { journalId: "a".repeat(32) },
      liveCount: 1,
    });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    const operation = store.operations.get("op-1")!;
    Object.assign(operation, { kind: "CREATE_SANDBOX", state: "DISPATCHED" });
    store.operations.set("older", { ...operation, id: "older", state: "UNKNOWN_OUTCOME" });
    Object.assign(store.outbox.get("evt-1")!, {
      eventType: "sandbox.create_requested",
      payload: {
        operationId: "op-1",
        generation: 1,
        allocationJournalId: "a".repeat(32),
        allocationJournalEpoch: 1,
        allocationJournalAttempt: 1,
        allocationDispatchSequence: null,
      },
    });
    store.outbox.set("older-event", {
      ...store.outbox.get("evt-1")!,
      id: "older-event",
      payload: {
        operationId: "older",
        generation: 1,
        allocationJournalId: "a".repeat(32),
        allocationJournalEpoch: 1,
        allocationJournalAttempt: 1,
        allocationDispatchSequence: 1,
      },
    });
    const requests: Extract<
      import("./protocol.js").ServerControlMessage,
      { type: "allocation.attest.request" }
    >[] = [];
    session.allocationAttestation = new AllocationAttestation(
      { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
      () => ++session.allocationSequence,
      (request) => {
        requests.push(request);
        host.send(JSON.stringify(request));
      },
    );
    const entered = gate(),
      resume = gate();
    vi.mocked(revalidateSandboxHostIdentity).mockImplementationOnce(async () => {
      entered.resolve();
      await resume.promise;
      return { status: "active", hostDeletionRequested: false };
    });
    const send = manager.dispatchOperation("host-1", {
      authorizingPrincipal: { kind: "session" },
      allocation: allocationFixture(),
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "key",
      kind: "sandbox.create",
      generation: 1,
      attempt: 1,
      bodyHash: "a".repeat(64),
      cpuCount: 1,
      memoryMiB: 1024,
      egressPolicy: { domains: [], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    await entered.promise;
    await session.allocationAttestation.request();
    expect(requests[0]!.barrier).toBe(2);
    const answer = {
      type: "allocation.attest.result" as const,
      connectionEpoch: 1,
      barrier: 2,
      journalId: "a".repeat(32),
      entries: [{ sandboxOwnerId: "user-1", sandboxId: "sbx-1", settledNeverIssued: true }],
    };
    if (answerFirst) await session.allocationAttestation.accept(answer);
    resume.resolve();
    expect(await send).toBe("sent");
    expect(store.outbox.get("evt-1")!.payload.allocationDispatchSequence).toBe(3);
    if (!answerFirst) await session.allocationAttestation.accept(answer);
    expect(store.sandboxes.get("sbx-1")!.liveResourcesHeld).toBe(true);
    expect(host.closes).toEqual([]);
    const frames = host.sends.map((raw) => JSON.parse(raw) as { type: string });
    expect(frames.findIndex((frame) => frame.type === "allocation.attest.request")).toBeLessThan(
      frames.findIndex((frame) => frame.type === "operation.dispatch"),
    );
    session.allocationAttestation.close();
  },
);

it("attests historical UNKNOWN; new create uncertainty queues cleanup without another attestation", async () => {
  db.sandboxTemplateAvailability.findMany.mockResolvedValue([]);
  const host = socket();
  const hello = JSON.parse(helloFrame("host-1")) as Record<string, unknown>;
  hello.supportedProtocolVersions = ["1.0"];
  Object.assign(store.operations.get("op-1")!, {
    kind: "CREATE_SANDBOX",
    state: "UNKNOWN_OUTCOME",
  });
  Object.assign(store.sandboxes.get("sbx-1")!, { state: "PROVISIONING", liveResourcesHeld: true });
  const terminals = Reflect.get(
    manager,
    "terminals",
  ) as import("./terminal-manager.js").SandboxTerminalManager;
  const terminalClose = vi.spyOn(terminals, "removeHostSocket");
  manager.handleTextFrame(host, JSON.stringify(hello));
  await manager.drain(host);
  manager.handleTextFrame(
    host,
    JSON.stringify({
      storagePools: capacityFixture("host-1").storagePools,
      type: "host.admission",
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: false,
      terminal: false,
      vmCapacity: { vcpuBudget: 64, memoryBudgetMiB: 65536, maxCpuCount: 32 },
      journalId: "a".repeat(32),
    }),
  );
  manager.handleTextFrame(
    host,
    JSON.stringify({ type: "sandbox.inventory", page: 0, complete: true, entries: [] }),
  );
  await manager.drain(host);
  expect(host.closes).toEqual([]);
  const requests = () =>
    host.sends
      .map((raw) => JSON.parse(raw) as { type: string; barrier: number })
      .filter((frame) => frame.type === "allocation.attest.request");
  expect(requests()).toHaveLength(0);
  manager.handleTextFrame(host, JSON.stringify({ type: "reconcile.complete" }));
  await manager.drain(host);
  expect(host.closes).toEqual([]);
  expect(requests()).toHaveLength(1);
  const decline = async () => {
    manager.handleTextFrame(
      host,
      JSON.stringify({
        type: "allocation.attest.result",
        connectionEpoch: 1,
        barrier: requests().at(-1)!.barrier,
        journalId: "a".repeat(32),
        entries: [{ sandboxOwnerId: "user-1", sandboxId: "sbx-1", settledNeverIssued: false }],
      }),
    );
    await manager.drain(host);
  };
  await decline();
  store.operations.get("op-1")!.state = "DISPATCHED";
  const unknown = JSON.stringify({
    type: "operation.result",
    id: "unknown",
    operationId: "op-1",
    sandboxId: "sbx-1",
    generation: 1,
    attempt: 1,
    state: "unknown_outcome",
    error: { code: "host_capacity", message: "admission refused" },
  });
  manager.handleTextFrame(host, unknown);
  await manager.drain(host);
  expect(requests()).toHaveLength(1);
  manager.handleTextFrame(host, unknown);
  await manager.drain(host);
  expect(requests()).toHaveLength(1);
  expect(host.closes).toEqual([]);
  expect(terminalClose).not.toHaveBeenCalled();
  const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
    typeof host,
    { allocationAttestation: import("./allocation-attestation.js").AllocationAttestation }
  >;
  const request = vi.spyOn(sessions.get(host)!.allocationAttestation, "request");
  for (const kind of ["RUN_COMMAND", "WRITE_FILE"]) {
    Object.assign(store.operations.get("op-1")!, { state: "DISPATCHED", kind, generation: 2 });
    store.sandboxes.get("sbx-1")!.state = "READY";
    manager.handleTextFrame(host, JSON.stringify({ ...JSON.parse(unknown), generation: 2 }));
    await manager.drain(host);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(request).not.toHaveBeenCalled();
  }
});

it("10.7 allocation without journal binding fails validation before any frame", async () => {
  const host = await registered();
  const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
    FakeSocket,
    { protocolVersion: string }
  >;
  sessions.get(host)!.protocolVersion = "1.0";
  Object.assign(store.operations.get("op-1")!, { kind: "CREATE_SANDBOX", state: "DISPATCHED" });
  Object.assign(store.sandboxes.get("sbx-1")!, { state: "PROVISIONING", liveResourcesHeld: true });
  store.outbox.get("evt-1")!.eventType = "sandbox.create_requested";
  delete store.outbox.get("evt-1")!.payload.allocationJournalEpoch;
  const possible = vi.fn();
  const before = host.sends.length;
  await expect(
    manager.dispatchOperation("host-1", {
      authorizingPrincipal: { kind: "session" },
      allocation: allocationFixture(),
      connectionEpoch: 1,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "key",
      kind: "sandbox.create",
      generation: 1,
      attempt: 1,
      bodyHash: "a".repeat(64),
      cpuCount: 1,
      memoryMiB: 1024,
      egressPolicy: { domains: [], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
      onPossibleDispatchFrame: possible,
    }),
  ).rejects.toThrow("Missing allocation journal binding");
  expect(possible).not.toHaveBeenCalled();
  expect(host.sends).toHaveLength(before);
});

function allocationFixture() {
  const p = store.placements.get("placement:sbx-1")!;
  return {
    cpuCount: Number(p.cpuCount),
    memoryMiB: Number(p.memoryMiB),
    diskGiB: Number(p.diskGiB),
    storagePoolName: String(p.storagePoolName),
    storageMarker: String(p.storageMarker),
    chargedMemoryMiB: Number(p.chargedMemoryMiB),
    chargedVcpu: Number(p.chargedVcpu),
    rootChargeGiB: Number(p.rootChargeGiB),
  };
}

it("T2 host repair PTY frames do not depend on guest census reconciliation", async () => {
  const host = socket();
  const hello = JSON.parse(helloFrame("host-1"));
  hello.daemon.capabilities.hostTerminal = true;
  hello.daemon.capabilities.requireHostTerminalTotp = false;
  manager.handleTextFrame(host, JSON.stringify(hello));
  await manager.drain(host);
  expect(host.closes).toEqual([]);
  const ready = vi.fn(),
    output = vi.fn(),
    closed = vi.fn();
  const opened = manager.terminals.open({
    ownerId: "user-1",
    hostId: "host-1",
    target: { kind: "host" },
    epoch: 1,
    hostPolicy: { policyRevision: hello.daemon.capabilities.policyRevision, proofRequired: false },
    rows: 24,
    cols: 80,
    attachment: { bufferedAmount: 0, ready, sendOutput: output, close: closed },
  });
  expect(opened.ok).toBe(true);
  const request = host.sends.map((s) => JSON.parse(s)).find((f) => f.type === "terminal.open");
  manager.handleTextFrame(
    host,
    JSON.stringify({
      type: "terminal.ready",
      requestId: request.requestId,
      fence: request.fence,
      rows: 24,
      cols: 80,
    }),
  );
  expect(ready).toHaveBeenCalledOnce();
  const { encodeTerminalDataFrame } = await import("./protocol.js");
  manager.handleBinaryFrame(
    host,
    encodeTerminalDataFrame(
      { type: "terminal.data", fence: request.fence, sequence: 0 },
      new Uint8Array([65]),
    ),
  );
  expect(output).toHaveBeenCalledWith(new Uint8Array([65]));
  vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({
    status: "active",
    hostDeletionRequested: true,
  });
  await withAuthorityChange({ ownerId: "user-1", hostId: "host-1" }, async () => {
    store.hosts.get("host-1")!.deletionRequestedAt = new Date();
  });
  await flushCommittedAuthorityListeners();
  await manager.drain(host);
  await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce());
  manager.handleBinaryFrame(
    host,
    encodeTerminalDataFrame(
      { type: "terminal.data", fence: request.fence, sequence: 1 },
      new Uint8Array([66]),
    ),
  );
  expect(output).toHaveBeenCalledTimes(1);
  expect(host.closes).toEqual([]); // Relay cleanup remains available.
});

describe("D3b command-output throughput", () => {
  const output = (sequence: number, offset: number, body: Uint8Array, operationId = "op-1") =>
    encodeBinaryFrame(
      {
        type: "stream.chunk",
        streamId: operationId,
        operationId,
        generation: 1,
        attempt: 1,
        sequence,
        offset,
        flags: { stdout: true },
      },
      body,
    );
  const acks = (host: FakeSocket) =>
    host.sends
      .map((text) => JSON.parse(text))
      .filter((frame) => frame.type === "command.output.ack")
      .map((frame) => [frame.sequence, frame.offset]);
  const opAcks = (host: FakeSocket) =>
    host.sends
      .map((text) => JSON.parse(text))
      .filter((frame) => frame.type === "command.output.ack")
      .map((frame) => [frame.operationId, frame.sequence]);
  /** A second running command on the same host, a clone of op-1. */
  const addSecondCommand = () =>
    store.operations.set("op-2", { ...store.operations.get("op-1")!, id: "op-2" });
  /** Parks the first fenced transaction at H so the following frames queue. */
  function holdFirstTransaction() {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    return { entered: entered.promise, resume: () => resume.resolve() };
  }
  beforeEach(() => {
    store.operations.get("op-1")!.kind = "RUN_COMMAND";
  });

  it("admits queued chunks in one fenced transaction after one revalidation and ACKs each", async () => {
    const host = await registered();
    host.sends = [];
    const held = holdFirstTransaction();
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
    await held.entered;
    vi.mocked(revalidateSandboxHostIdentity).mockClear();
    db.$transaction.mockClear();
    for (let n = 1; n <= 5; n++) manager.handleBinaryFrame(host, output(n, n, new Uint8Array([n])));
    held.resume();
    await manager.drain(host);
    // Five queued chunks: one revalidation and one transaction, not five each.
    expect(vi.mocked(revalidateSandboxHostIdentity)).toHaveBeenCalledTimes(1);
    expect(db.$transaction).toHaveBeenCalledTimes(1);
    expect(acks(host)).toEqual([0, 1, 2, 3, 4, 5].map((n) => [n, n + 1]));
    expect(storedCommandOutput(store, "op-1")).toMatchObject({
      receivedEnd: 6,
      stdout: Buffer.from([0, 1, 2, 3, 4, 5]),
    });
  });

  it("bounds a batch by chunk count", async () => {
    const host = await registered();
    host.sends = [];
    const held = holdFirstTransaction();
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
    await held.entered;
    db.$transaction.mockClear();
    for (let n = 1; n <= 20; n++)
      manager.handleBinaryFrame(host, output(n, n, new Uint8Array([n])));
    held.resume();
    await manager.drain(host);
    // 20 queued chunks: a batch of 16, then one of 4.
    expect(db.$transaction).toHaveBeenCalledTimes(2);
    expect(acks(host)).toHaveLength(21);
  });

  it.each(["stale", "inactive"] as const)(
    "an authority change during a batch refuses it; its chunks then run one by one (%s)",
    async (status) => {
      const host = await registered();
      host.sends = [];
      const held = holdFirstTransaction();
      manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
      await held.entered;
      for (let n = 1; n <= 3; n++)
        manager.handleBinaryFrame(host, output(n, n, new Uint8Array([n])));
      // The batch's own transaction (the next one after the first commits):
      // authority changes after the batch's revalidation, before its commit.
      let changedInBatch = false;
      store.barriers.afterCommit = async () => {
        store.barriers.afterCommit = undefined;
        store.barriers.beforeHostLock = async () => {
          store.barriers.beforeHostLock = undefined;
          changedInBatch = true;
          vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue(
            status === "stale" ? { status, hostDeletionRequested: false } : { status },
          );
          await withAuthorityChange(
            { ownerId: "user-1", credentialId: "token-1" },
            async () => undefined,
          );
          await flushCommittedAuthorityListeners();
        };
      };
      vi.mocked(revalidateSandboxHostIdentity).mockClear();
      held.resume();
      await manager.drain(host);
      expect(changedInBatch).toBe(true);
      // One batch revalidation, then (stale only) one per refused chunk.
      expect(vi.mocked(revalidateSandboxHostIdentity).mock.calls.length).toBeGreaterThanOrEqual(
        status === "stale" ? 4 : 1,
      );
      // Nothing of the batch committed or was ACKed; each chunk was refused alone.
      expect(acks(host)).toEqual([[0, 1]]);
      expect(storedCommandOutput(store, "op-1")).toMatchObject({ receivedEnd: 1 });
      if (status === "inactive") {
        expect(host.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
        return;
      }
      expect(host.closes).toEqual([]);
      // A retransmit under restored authority is accepted.
      vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({
        status: "active",
        hostDeletionRequested: false,
      });
      for (let n = 1; n <= 3; n++)
        manager.handleBinaryFrame(host, output(n, n, new Uint8Array([n])));
      await manager.drain(host);
      expect(acks(host)).toEqual([0, 1, 2, 3].map((n) => [n, n + 1]));
    },
  );

  it("a protocol error inside a batch keeps the per-chunk prefix and closes", async () => {
    const host = await registered();
    host.sends = [];
    const held = holdFirstTransaction();
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
    await held.entered;
    manager.handleBinaryFrame(host, output(1, 1, new Uint8Array([1])));
    // Sequence 3 skips 2: an invalid cursor, a protocol error.
    manager.handleBinaryFrame(host, output(3, 2, new Uint8Array([2])));
    held.resume();
    await manager.drain(host);
    expect(acks(host)).toEqual([
      [0, 1],
      [1, 2],
    ]);
    expect(storedCommandOutput(store, "op-1")).toMatchObject({ receivedEnd: 2 });
    expect(host.readyState).toBe(3);
  });

  it("never regroups interleaved operations: a later invalid chunk cannot strand an earlier valid one", async () => {
    addSecondCommand();
    const host = await registered();
    host.sends = [];
    const held = holdFirstTransaction();
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
    await held.entered;
    // A1, B0, A3 (A3 skips sequence 2: a protocol error).
    manager.handleBinaryFrame(host, output(1, 1, new Uint8Array([1])));
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([9]), "op-2"));
    manager.handleBinaryFrame(host, output(3, 2, new Uint8Array([2])));
    held.resume();
    await manager.drain(host);
    // Exactly the single-accept outcome: B0 committed before A3 closes.
    expect(opAcks(host)).toEqual([
      ["op-1", 0],
      ["op-1", 1],
      ["op-2", 0],
    ]);
    expect(storedCommandOutput(store, "op-1")).toMatchObject({ receivedEnd: 2 });
    expect(storedCommandOutput(store, "op-2")).toMatchObject({
      receivedEnd: 1,
      stdout: Buffer.from([9]),
    });
    expect(host.readyState).toBe(3);
  });

  it("commits no chunk received after another operation's fatal frame", async () => {
    addSecondCommand();
    const host = await registered();
    host.sends = [];
    const held = holdFirstTransaction();
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([0])));
    await held.entered;
    db.$transaction.mockClear();
    // B0, B1, then A2 skipping sequence 1 (fatal), then B2, B3.
    manager.handleBinaryFrame(host, output(0, 0, new Uint8Array([10]), "op-2"));
    manager.handleBinaryFrame(host, output(1, 1, new Uint8Array([11]), "op-2"));
    manager.handleBinaryFrame(host, output(2, 1, new Uint8Array([1])));
    manager.handleBinaryFrame(host, output(2, 2, new Uint8Array([12]), "op-2"));
    manager.handleBinaryFrame(host, output(3, 3, new Uint8Array([13]), "op-2"));
    held.resume();
    await manager.drain(host);
    expect(opAcks(host)).toEqual([
      ["op-1", 0],
      ["op-2", 0],
      ["op-2", 1],
    ]);
    expect(storedCommandOutput(store, "op-2")).toMatchObject({
      receivedEnd: 2,
      stdout: Buffer.from([10, 11]),
    });
    expect(storedCommandOutput(store, "op-1")).toMatchObject({ receivedEnd: 1 });
    expect(host.readyState).toBe(3);
  });

  it("answers the required receipt and census capabilities and judges every inventory page", async () => {
    const host = await registered();
    const frames = host.sends.map((text) => JSON.parse(text));
    const helloOk = frames.find((frame) => frame.type === "hello.ok");
    for (const name of [
      "censusEntryResults",
      "pendingReceipts",
      "commandRetire",
      "expiryStatusResults",
      "observationFence",
    ])
      expect(helloOk.capabilities[name]).toBe(true);
    const acks = frames.filter((frame) => frame.type === "inventory.ack");
    expect(acks.length).toBeGreaterThan(0);
    for (const ack of acks) expect(ack.entryResults).toBeDefined();
  });

  it.each([
    "maxLeaseMs",
    "egress",
    "maxOutputChunkBytes",
    "censusEntryResults",
    "pendingReceipts",
    "commandRetire",
    "expiryStatusResults",
    "observationFence",
  ])("refuses a hello missing %s", async (name) => {
    const host = socket();
    manager.handleTextFrame(host, helloFrame("host-1", "1.0", true, false, { [name]: undefined }));
    await manager.drain(host);
    expect(host.closes).toHaveLength(1);
    expect(host.sends.map((text) => JSON.parse(text).type)).not.toContain("hello.ok");
  });

  it("D11: a pending receipt is not settled unknown until a later session without it", async () => {
    const op = () => store.operations.get("op-1")!;
    await registered(false, true, { pendingReceipts: true });
    Object.assign(op(), {
      state: "DISPATCHED",
      dispatchedConnectionEpoch: 1,
      dispatchedAt: new Date(),
    });
    const intent = store.outbox.get("evt-1")!;
    Object.assign(intent, {
      processedAt: null,
      payload: { ...intent.payload, kind: "command.run" },
    });
    // A cancel queued during the disconnect is a control, not the intent.
    store.outbox.set("evt-cancel", {
      ...intent,
      id: "evt-cancel",
      eventType: "sandbox.operation_cancel_requested",
      payload: { ...intent.payload, kind: "operation.cancel" },
    });
    // The host names op-1 as still resolving: no interim unknown, and no
    // replacement attempt can be claimed while its receipt is pending.
    await registered(false, true, { pendingReceipts: true }, { pendingReceipts: ["op-1"] });
    expect(store.hosts.get("host-1")!.connectionEpoch).toBe(2);
    expect(op().state).toBe("DISPATCHED");
    expect(op().errorCode ?? null).toBeNull();
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(store.outbox.get("evt-cancel")!.processedAt, "the cancel is still delivered").toBeNull();
    // That session ended without the receipt: today's settlement applies.
    await registered(false, true, { pendingReceipts: true });
    expect(op().state).toBe("UNKNOWN_OUTCOME");
  });
  it("D11: a pending receipt holds an operation only for a bounded time", async () => {
    const { PENDING_RECEIPT_MAX_HOLD_MS } = await import("./operation-handlers.js");
    await registered(false, true, { pendingReceipts: true });
    Object.assign(store.operations.get("op-1")!, {
      state: "DISPATCHED",
      dispatchedConnectionEpoch: 1,
      dispatchedAt: new Date(Date.now() - PENDING_RECEIPT_MAX_HOLD_MS - 1),
    });
    await registered(false, true, { pendingReceipts: true }, { pendingReceipts: ["op-1"] });
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
  });
  it("D11: a held operation expires while its session stays open (no reconnect)", async () => {
    const { PENDING_RECEIPT_MAX_HOLD_MS } = await import("./operation-handlers.js");
    await registered(false, true, { pendingReceipts: true });
    Object.assign(store.operations.get("op-1")!, {
      state: "DISPATCHED",
      dispatchedConnectionEpoch: 1,
      dispatchedAt: new Date(),
    });
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const host = await registered(
        false,
        true,
        { pendingReceipts: true },
        { pendingReceipts: ["op-1"] },
      );
      expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
      // A sweep inside the bound keeps holding it.
      await vi.advanceTimersByTimeAsync(60_000);
      expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
      // The bound passes (database clock) while the host keeps heartbeating.
      store.operations.get("op-1")!.dispatchedAt = new Date(
        Date.now() - PENDING_RECEIPT_MAX_HOLD_MS - 1,
      );
      await vi.advanceTimersByTimeAsync(60_000);
      await vi.waitFor(() => expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME"));
      expect(host.closes).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
  const judged = { expiryStatusResults: true, observationFence: true };
  it("expiryStatusResults: each batch is answered by one ack judging every entry, in order", async () => {
    const host = await registered(false, true, judged);
    host.sends = [];
    const entry = {
      sandboxOwnerId: "user-1",
      sandboxId: "sbx-1",
      state: "ready",
      root: null,
    };
    manager.handleTextFrame(
      host,
      JSON.stringify({ type: "sandbox.expiry_status", batch: 1, observation: 1, entries: [entry] }),
    );
    await manager.drain(host);
    const acks = host.sends
      .map((text) => JSON.parse(text))
      .filter((f) => f.type === "sandbox.expiry_status.ack");
    expect(acks).toEqual([
      {
        type: "sandbox.expiry_status.ack",
        batch: 1,
        entryResults: [{ sandboxId: "sbx-1", outcome: expect.any(String) }],
      },
    ]);
    expect(host.closes).toEqual([]);
    // A replayed batch is a protocol violation.
    manager.handleTextFrame(
      host,
      JSON.stringify({ type: "sandbox.expiry_status", batch: 1, observation: 1, entries: [entry] }),
    );
    await manager.drain(host);
    expect(host.closes.length).toBe(1);
  });
  it.each([
    ["without its observation", [{ batch: 1 }]],
    [
      "with an observation going back",
      [
        { batch: 1, observation: 1 },
        { batch: 2, observation: 2 },
        { batch: 3, observation: 1 },
      ],
    ],
    ["whose first observation is not 1", [{ batch: 1, observation: 2 }]],
    ["jumping to MAX_SAFE_INTEGER", [{ batch: 1, observation: Number.MAX_SAFE_INTEGER }]],
    [
      "skipping an observation",
      [
        { batch: 1, observation: 1 },
        { batch: 2, observation: 3 },
      ],
    ],
  ])("observationFence: a batch %s fails the session", async (_, frames) => {
    const host = await registered(false, true, judged);
    const entry = { sandboxOwnerId: "user-1", sandboxId: "sbx-1", state: "ready", root: null };
    for (const frame of frames)
      manager.handleTextFrame(
        host,
        JSON.stringify({ type: "sandbox.expiry_status", ...frame, entries: [entry] }),
      );
    await manager.drain(host);
    expect(host.closes.length).toBe(1);
  });
  /** Codex rc-fu-b r1 #1: after a result fences observation 1, a first
   * batch that jumps to 2 (or MAX_SAFE_INTEGER) is refused before anything
   * is judged: the session fails, the row is untouched. */
  it.each([2, Number.MAX_SAFE_INTEGER])(
    "observationFence: a jump to %s past a fenced observation is never judged",
    async (jump) => {
      const host = await registered(false, true, judged);
      manager.handleTextFrame(host, resultFrame);
      await manager.drain(host);
      const before = structuredClone(store.sandboxes.get("sbx-1"));
      let locks = 0;
      store.barriers.beforeHostLock = async () => {
        locks += 1;
      };
      manager.handleTextFrame(
        host,
        JSON.stringify({
          type: "sandbox.expiry_status",
          batch: 1,
          observation: jump,
          entries: [{ sandboxOwnerId: "user-1", sandboxId: "sbx-1", state: "stopped", root: null }],
        }),
      );
      await manager.drain(host);
      store.barriers.beforeHostLock = undefined;
      expect(host.closes.length).toBe(1);
      expect(locks).toBe(0);
      expect(store.sandboxes.get("sbx-1")).toEqual(before);
    },
  );
  /** Codex WP2 r3 P1 at the session: a lifecycle result for sbx-1 arrives
   * while observation 1 may be in flight; observation 1's stopped entry
   * (non-expired, the current arm) is answered superseded without being
   * judged, and the row is untouched. Observation 2 began after the server
   * answered 1, so it is judged by the census rules (the converging outcome
   * itself is covered against the store in inventory-reconcile tests). */
  it("observationFence: evidence observed before a received result is not judged", async () => {
    const host = await registered(false, true, judged);
    manager.handleTextFrame(host, resultFrame);
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    const before = structuredClone(store.sandboxes.get("sbx-1"));
    const stopped = {
      sandboxOwnerId: "user-1",
      sandboxId: "sbx-1",
      state: "stopped",
      root: null,
      lease: {
        generation: before!.generation,
        lease: {
          revision: 1,
          deadlineUnixMs: Date.now() + 3_600_000,
          action: "stop",
          expiryPolicy: "retry-force-60s",
        },
        expired: false,
        expiryComplete: false,
        timerExpired: false,
      },
    };
    host.sends = [];
    const offer = (batch: number, observation: number) =>
      manager.handleTextFrame(
        host,
        JSON.stringify({ type: "sandbox.expiry_status", batch, observation, entries: [stopped] }),
      );
    let fencedLocks = 0;
    store.barriers.beforeHostLock = async () => {
      fencedLocks += 1;
    };
    offer(1, 1);
    await manager.drain(host);
    store.barriers.beforeHostLock = undefined;
    expect(fencedLocks, "the fenced entry is not judged").toBe(0);
    const ack = (batch: number) =>
      host.sends
        .map((text) => JSON.parse(text))
        .find((f) => f.type === "sandbox.expiry_status.ack" && f.batch === batch);
    expect(ack(1).entryResults).toEqual([{ sandboxId: "sbx-1", outcome: "superseded" }]);
    expect(store.sandboxes.get("sbx-1")).toEqual(before);
    // Judging an entry locks the host; the fenced one was never judged.
    let judgedEntries = 0;
    store.barriers.beforeHostLock = async () => {
      judgedEntries += 1;
    };
    offer(2, 2);
    await manager.drain(host);
    store.barriers.beforeHostLock = undefined;
    expect(ack(2).entryResults).toEqual([{ sandboxId: "sbx-1", outcome: expect.any(String) }]);
    expect(judgedEntries).toBeGreaterThan(0);
    expect(host.closes).toEqual([]);
  });
  it("expiry status carries no batch without expiryStatusResults", async () => {
    const host = await registered(false, true);
    manager.handleTextFrame(
      host,
      JSON.stringify({
        type: "sandbox.expiry_status",
        batch: 1,
        entries: [{ sandboxOwnerId: "user-1", sandboxId: "sbx-1", state: "ready", root: null }],
      }),
    );
    await manager.drain(host);
    expect(host.closes.length).toBe(1);
  });
  it.each([
    [65536, 65536, 65536],
    [16384, 16384, 16384],
    [1048576, 65536, 65536],
  ])("hello offering %s negotiates %s (chunk ceiling %s)", async (offer, told, ceiling) => {
    const host = await registered(
      false,
      true,
      offer === undefined ? {} : { maxOutputChunkBytes: offer },
    );
    const helloOk = host.sends.map((text) => JSON.parse(text)).find((f) => f.type === "hello.ok");
    if (told === undefined) expect(helloOk.capabilities).not.toHaveProperty("outputChunkBytes");
    else expect(helloOk.capabilities.outputChunkBytes).toBe(told);
    host.sends = [];
    const body = new Uint8Array(ceiling).map((_, i) => i % 251);
    manager.handleBinaryFrame(host, output(0, 0, body));
    await manager.drain(host);
    expect(acks(host)).toEqual([[0, ceiling]]);
    // Stored as 8 KiB segments whatever the chunk size.
    expect(storedCommandOutput(store, "op-1")).toMatchObject({
      segments: ceiling / 8192,
      stdout: Buffer.from(body),
    });
    manager.handleBinaryFrame(host, output(1, ceiling, new Uint8Array(ceiling + 1)));
    await manager.drain(host);
    expect(host.readyState).toBe(3);
    expect(acks(host)).toHaveLength(1);
  });

  it("refuses an out-of-range offer at hello", async () => {
    for (const offer of [0, 4096, 8191, 1048577, "65536", 1.5]) {
      const host = socket();
      manager.handleTextFrame(
        host,
        helloFrame("host-1", "1.0", true, false, { maxOutputChunkBytes: offer }),
      );
      await manager.drain(host);
      expect(host.readyState, String(offer)).toBe(3);
    }
  });
});

describe("WP4: half-open detection", () => {
  beforeEach(() => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
    });
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.useRealTimers();
  });
  const removed = (host: FakeSocket) =>
    host.closes.some((close) => close.code === 1001 && close.reason === "session_removed");

  it("pings every 15 s; a host that answers pongs stays well past the silence bound", async () => {
    const host = await registered();
    host.onPing = () => manager.notePeerAlive(host);
    const before = host.pings;
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_PING_INTERVAL_MS);
    expect(host.pings).toBe(before + 1);
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS * 4);
    expect(host.pings).toBe(before + 1 + 4 * (SANDBOX_RELAY_LIVENESS_TIMEOUT_MS / 15_000));
    expect(removed(host)).toBe(false);
    expect(manager.isHostConnected("host-1")).toBe(true);
  });

  it("frames count as liveness without pongs", async () => {
    const host = await registered();
    for (let i = 0; i < 8; i++) {
      await vi.advanceTimersByTimeAsync(10_000);
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: `hb-${i}` }));
      await manager.drain(host);
    }
    expect(removed(host)).toBe(false);
    expect(manager.isHostConnected("host-1")).toBe(true);
  });

  it("no pong and no frame for 45 s removes the session and revokes its epoch", async () => {
    const host = await registered();
    const epoch = store.hosts.get("host-1")!.connectionEpoch;
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS - 1);
    expect(removed(host)).toBe(false);
    expect(host.pings).toBe(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(removed(host)).toBe(true);
    expect(manager.isHostConnected("host-1")).toBe(false);
    await vi.waitFor(() =>
      expect(store.hosts.get("host-1")).toMatchObject({
        status: "DISCONNECTED",
        connectionEpoch: epoch + 1,
      }),
    );
    expect(console.warn).toHaveBeenCalledWith(
      "[sandbox-relay] host socket silent; removing session:",
      expect.objectContaining({ code: "host_liveness_timeout", registered: true }),
    );
    // Its timers are gone with it: no further pings.
    const pings = host.pings;
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS);
    expect(host.pings).toBe(pings);
  });

  it("the clock is frozen while reads are paused: a slow DB plus a burst never removes the host", async () => {
    const host = await registered();
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    // A frame stuck behind a slow transaction, then a burst up to the mark.
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    let sent = 0;
    while (!host.paused) {
      manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: `hb-${sent}` }));
      sent += 1;
    }
    const pings = host.pings;
    // Paused: no frames and no pongs can be read, for far longer than 45 s.
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS * 5);
    expect(removed(host)).toBe(false);
    expect(host.closes).toEqual([]);
    // And no pings are sent into a paused reader.
    expect(host.pings).toBe(pings);
    release.resolve();
    await vi.waitFor(() => expect(host.paused).toBe(false));
    await manager.drain(host);
    expect(manager.isHostConnected("host-1")).toBe(true);
    // The clock restarts at resume: a full 45 s window, not the stale one.
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS - 1_000);
    expect(removed(host)).toBe(false);
    expect(host.pings).toBeGreaterThan(pings);
    // Then a host that stays silent is removed.
    await vi.advanceTimersByTimeAsync(2_000);
    expect(removed(host)).toBe(true);
  });

  it("a slow DB without a pause keeps an answering host (pongs bypass the queue)", async () => {
    const host = await registered();
    host.onPing = () => manager.notePeerAlive(host);
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    manager.handleBinaryFrame(host, chunkFrame());
    await entered.promise;
    expect(host.paused).toBe(false);
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS * 3);
    expect(removed(host)).toBe(false);
    release.resolve();
    await manager.drain(host);
    expect(manager.isHostConnected("host-1")).toBe(true);
  });

  it("a deadline check that fires late (stalled event loop) defers to pending reads", async () => {
    const host = await registered();
    // The loop stalls past the deadline; the frame that arrived meanwhile is
    // read only after the late timer callback.
    vi.setSystemTime(Date.now() + SANDBOX_RELAY_LIVENESS_TIMEOUT_MS + 5_000);
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS);
    expect(removed(host)).toBe(false);
    manager.handleTextFrame(host, JSON.stringify({ type: "heartbeat", id: "late" }));
    await manager.drain(host);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(removed(host)).toBe(false);
    expect(manager.isHostConnected("host-1")).toBe(true);
  });

  it("an unregistered socket's liveness timers end with its session", async () => {
    const host = socket();
    await vi.advanceTimersByTimeAsync(10_001);
    expect(host.readyState).toBe(3);
    const pings = host.pings;
    await vi.advanceTimersByTimeAsync(SANDBOX_RELAY_LIVENESS_TIMEOUT_MS * 2);
    expect(host.pings).toBe(pings);
  });
});

describe("WP7 graceful quiesce (D9)", () => {
  const frames = (host: FakeSocket) => host.sends.map((value) => JSON.parse(value));
  const epoch = () => store.hosts.get("host-1")!.connectionEpoch;
  const quiesce = (sequence: number, connectionEpoch = epoch()) =>
    JSON.stringify({ type: "host.quiesce", connectionEpoch, sequence });
  const terminalHost = (kind: "host" | "sandbox") =>
    (
      Reflect.get(manager.terminals, "hosts") as import("./terminal-manager.js").TerminalHosts
    ).terminalHost("host-1", kind);
  const helloWith = (quiescing: boolean, capability: boolean) => {
    const hello = JSON.parse(
      helloFrame("host-1", "1.0", true, false, capability ? { quiesce: true } : {}),
    );
    return JSON.stringify({ ...hello, ...(quiescing ? { quiescing: true } : {}) });
  };

  it("echoes the capability only when offered", async () => {
    const plain = await registered();
    expect(frames(plain).find((f) => f.type === "hello.ok").capabilities).not.toHaveProperty(
      "quiesce",
    );
    const capable = await registered(false, true, { quiesce: true });
    expect(frames(capable).find((f) => f.type === "hello.ok").capabilities.quiesce).toBe(true);
    expect(manager.isHostQuiescing("host-1")).toBe(false);
  });

  it("host.quiesce sets the state, acks its sequence, holds command.run and refuses terminal opens", async () => {
    const host = await registered(false, true, { quiesce: true, terminal: true });
    expect("link" in terminalHost("sandbox")).toBe(true);
    manager.handleTextFrame(host, quiesce(1));
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    expect(frames(host).filter((f) => f.type === "host.quiesce.ack")).toEqual([
      { type: "host.quiesce.ack", sequence: 1 },
    ]);
    expect(manager.isHostQuiescing("host-1")).toBe(true);
    // Still connected: controls, results and other kinds keep flowing.
    expect(manager.isHostConnected("host-1")).toBe(true);
    for (const kind of ["sandbox", "host"] as const)
      expect(terminalHost(kind)).toEqual({
        error: { code: "disconnected", message: "host is not connected" },
      });
    // A replayed sequence or another epoch's report is ignored (no second ACK).
    manager.handleTextFrame(host, quiesce(1));
    manager.handleTextFrame(host, quiesce(2, epoch() + 1));
    await manager.drain(host);
    expect(host.closes).toEqual([]);
    expect(frames(host).filter((f) => f.type === "host.quiesce.ack")).toHaveLength(1);
  });

  it("an unnegotiated host.quiesce is a protocol error", async () => {
    const host = await registered();
    manager.handleTextFrame(host, quiesce(1));
    await manager.drain(host);
    expect(host.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
    expect(manager.isHostQuiescing("host-1")).toBe(false);
  });

  it("a reconnect hello sets quiescing at registration; a hello without it clears it", async () => {
    const first = socket();
    manager.handleTextFrame(first, helloWith(true, true));
    await manager.drain(first);
    expect(first.closes).toEqual([]);
    // Set with registration, before reconciliation could make it dispatchable.
    expect(manager.isHostQuiescing("host-1")).toBe(true);
    const second = socket();
    manager.handleTextFrame(second, helloWith(false, true));
    await manager.drain(second);
    expect(second.closes).toEqual([]);
    expect(manager.isHostQuiescing("host-1")).toBe(false);
  });

  it("persists the hold for template-build deadlines: started by host.quiesce or a quiescing hello, settled by any other hello", async () => {
    const host = await registered(false, true, { quiesce: true });
    // An ordinary hello settles any hold a previous daemon left.
    await vi.waitFor(() =>
      expect(settleHostQuiesce).toHaveBeenLastCalledWith(
        expect.objectContaining({ hostId: "host-1", connectionEpoch: epoch() }),
        expect.any(Date),
      ),
    );
    expect(markHostQuiescing).not.toHaveBeenCalled();
    manager.handleTextFrame(host, quiesce(1));
    await manager.drain(host);
    await vi.waitFor(() => expect(markHostQuiescing).toHaveBeenCalled());
    expect(markHostQuiescing).toHaveBeenCalledWith(
      expect.objectContaining({ hostId: "host-1", connectionEpoch: epoch() }),
      expect.any(Date),
    );
    vi.mocked(markHostQuiescing).mockClear();
    vi.mocked(settleHostQuiesce).mockClear();
    const reconnect = socket();
    manager.handleTextFrame(reconnect, helloWith(true, true));
    await manager.drain(reconnect);
    await vi.waitFor(() => expect(markHostQuiescing).toHaveBeenCalled());
    expect(markHostQuiescing).toHaveBeenCalledWith(
      expect.objectContaining({ hostId: "host-1", connectionEpoch: epoch() }),
      expect.any(Date),
    );
    expect(settleHostQuiesce).not.toHaveBeenCalled();
    // A failed write never touches the in-memory hold or the connection.
    vi.mocked(settleHostQuiesce).mockRejectedValueOnce(new Error("db down"));
    const restarted = socket();
    manager.handleTextFrame(restarted, helloWith(false, true));
    await manager.drain(restarted);
    await vi.waitFor(() => expect(settleHostQuiesce).toHaveBeenCalledTimes(1));
    expect(restarted.closes).toEqual([]);
    expect(manager.isHostQuiescing("host-1")).toBe(false);
  });

  it("serializes hold writes per host: a slow mark finishes before the next settle starts", async () => {
    const host = await registered(false, true, { quiesce: true });
    await vi.waitFor(() => expect(settleHostQuiesce).toHaveBeenCalled());
    vi.mocked(settleHostQuiesce).mockClear();
    let finishMark!: () => void;
    vi.mocked(markHostQuiescing).mockImplementationOnce(
      () => new Promise<void>((resolve) => (finishMark = resolve)),
    );
    manager.handleTextFrame(host, quiesce(1));
    await manager.drain(host);
    await vi.waitFor(() => expect(markHostQuiescing).toHaveBeenCalled());
    const restarted = socket();
    manager.handleTextFrame(restarted, helloWith(false, true));
    await manager.drain(restarted);
    await delay(20);
    expect(settleHostQuiesce).not.toHaveBeenCalled();
    finishMark();
    await vi.waitFor(() => expect(settleHostQuiesce).toHaveBeenCalledTimes(1));
    expect(vi.mocked(settleHostQuiesce).mock.calls[0]![0].connectionEpoch).toBeGreaterThan(
      vi.mocked(markHostQuiescing).mock.calls[0]![0].connectionEpoch,
    );
  });

  it("refuses a quiescing hello without the capability", async () => {
    const host = socket();
    manager.handleTextFrame(host, helloWith(true, false));
    await manager.drain(host);
    expect(host.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
    expect(frames(host).some((f) => f.type === "hello.ok")).toBe(false);
    expect(manager.isHostQuiescing("host-1")).toBe(false);
  });
});
