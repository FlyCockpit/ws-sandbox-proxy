vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

const droppedCapture = vi.hoisted(() => ({ release: vi.fn() }));
vi.mock("@wssp/api/sandbox/image-store/references", () => ({
  droppedCaptureImageToRelease: droppedCapture.release,
}));

import { initialProcessFields, initialResultFields } from "@wssp/api/sandbox/operation-results";
import {
  commandResultFixture,
  gate,
  installFenceTransaction,
  relayStore,
} from "./fenced-prisma-harness.js";
import { bindMemoryCaptures } from "./relay-captures-harness.js";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
const {
  confirmOperationReceipt,
  applyOperationProgress,
  applyOperationResult,
  acceptFencedBinaryChunk,
  readyResultGroupSignals,
  wouldAuthorSandboxState,
} = await import("./operation-handlers.js");
const captures = bindMemoryCaptures();
const sender = { userId: "user-1", hostId: "host-1", connectionEpoch: 1 };
const fence = { sender, operationId: "op-1", sandboxId: "sbx-1", generation: 1, attempt: 1 };
const fileResult = () => {
  if (store.operations.get("op-1")?.kind === "RUN_COMMAND") return commandResultFixture(store);
  const content = captures.peek("op-1", 1);
  return content ? { size: content.size, sha256: content.sha256 } : undefined;
};
const binary = () =>
  acceptFencedBinaryChunk({
    ...fence,
    sequence: 0,
    offset: 0,
    ended: true,
    body: new Uint8Array([65, 66]),
  });
let store = relayStore();
beforeEach(async () => {
  vi.clearAllMocks();
  store = relayStore();
  installFenceTransaction(db, store);
  await captures.discardCapture("op-1", 1);
});

describe("unit (fenced harness; no real-DB test yet) — one inbound fence", () => {
  it("accepts current progress under the shared lock order", async () => {
    store.operations.get("op-1")!.state = "DISPATCHED";
    expect(await applyOperationProgress({ ...fence, state: "accepted" })).toEqual({
      written: true,
    });
    expect(await applyOperationProgress({ ...fence, state: "running" })).toEqual({ written: true });
    expect(store.writes.filter((row, i, all) => i === 0 || row !== all[i - 1]).slice(0, 3)).toEqual(
      ["hosts", "sandboxes", "operations"],
    );
  });
  it("progress replay cannot make acknowledged work redispatchable", async () => {
    for (const state of ["queued", "dispatched", "accepted"]) {
      expect(await applyOperationProgress({ ...fence, state })).toEqual({ written: false });
      expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    }
  });
  it("records ordinary success/failure without authoring VM state", async () => {
    for (const kind of [
      "RUN_COMMAND",
      "GET_FILE",
      "PUT_FILE",
      "STAT_PATH",
      "LIST_DIR",
      "SIGNAL_PROCESS",
    ]) {
      store.operations.get("op-1")!.kind = kind;
      store.operations.get("op-1")!.state = "RUNNING";
      expect(
        await applyOperationResult({
          ...fence,
          state: "failed",
          error: { code: "not_found", message: "missing" },
        }),
      ).toEqual({ written: true });
      expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
    }
  });
  it.each([
    ["CREATE_SANDBOX", "REQUESTED", "succeeded", "READY"],
    ["STOP_SANDBOX", "STOPPING", "succeeded", "STOPPED"],
    ["KILL_SANDBOX", "STOPPING", "succeeded", "DELETED"],
    ["RECONNECT_SANDBOX", "STOPPED", "succeeded", "READY"],
    ["STOP_SANDBOX", "STOPPING", "failed", "ERROR"],
  ])("lifecycle %s %s %s authors %s", async (kind, state, result, next) => {
    store.operations.get("op-1")!.kind = kind;
    store.sandboxes.get("sbx-1")!.state = state;
    expect(
      await applyOperationResult({
        ...fence,
        state: result,
        result: { state: next.toLowerCase(), lease: store.outbox.get("evt-1")!.payload.lease },
      }),
    ).toEqual({ written: true });
    expect(store.sandboxes.get("sbx-1")!.state).toBe(next);
    expect(store.writes.filter((row, i, all) => i === 0 || row !== all[i - 1]).slice(0, 3)).toEqual(
      ["hosts", "sandboxes", "operations"],
    );
  });
  it.each([
    ["STOP_SANDBOX", "STOPPING", "succeeded", "CANCELLED"],
    ["KILL_SANDBOX", "STOPPING", "succeeded", "CANCELLED"],
    ["STOP_SANDBOX", "STOPPING", "cancelled", "UNKNOWN_OUTCOME"],
    ["CREATE_SANDBOX", "PROVISIONING", "succeeded", "UNKNOWN_OUTCOME"],
    ["RECONNECT_SANDBOX", "STOPPED", "succeeded", "UNKNOWN_OUTCOME"],
  ])("C10-CX6: %s %s %s settles only its predecessors to %s", async (kind, state, result, next) => {
    store.operations.get("op-1")!.kind = kind;
    store.operations.get("op-1")!.generation = 2;
    Object.assign(store.sandboxes.get("sbx-1")!, { state, generation: 2 });
    const older = {
      ...store.operations.get("op-1")!,
      id: "older",
      kind: "RUN_COMMAND",
      generation: 1,
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
      state: "CANCEL_REQUESTED",
      errorCode: "superseded",
    };
    store.operations.set(older.id, older);
    const excluded = [
      { ...older, id: "foreign-owner", userId: "foreign" },
      { ...older, id: "foreign-sandbox", sandboxId: "foreign" },
      { ...older, id: "same-generation", generation: 2 },
      { ...older, id: "newer-generation", generation: 3 },
      { ...older, id: "ordinary-cancel", errorCode: null },
      { ...older, id: "already-succeeded", state: "SUCCEEDED" },
      { ...older, id: "already-cancelled", state: "CANCELLED" },
    ];
    for (const row of excluded) store.operations.set(row.id, structuredClone(row));
    expect(
      await applyOperationResult({
        ...fence,
        generation: 2,
        state: result,
        result: {
          state:
            kind === "KILL_SANDBOX" ? "deleted" : kind === "STOP_SANDBOX" ? "stopped" : "ready",
          lease: store.outbox.get("evt-1")!.payload.lease,
        },
      }),
    ).toEqual({
      written: true,
    });
    expect(store.operations.get(older.id)!.state).toBe(next);
    for (const row of excluded) expect(store.operations.get(row.id)).toEqual(row);
  });
  for (const change of [
    "owner",
    "host",
    "generation",
    "attempt",
    "sandbox",
    "epoch",
    "deleted",
    "terminal",
  ] as const) {
    it(`${change}: rejects progress/result/binary without mutation`, async () => {
      store.operations.get("op-1")!.kind = "GET_FILE";
      const op = store.operations.get("op-1")!;
      if (change === "owner") op.userId = "foreign";
      if (change === "host") op.dispatchedHostId = "foreign";
      if (change === "generation") store.sandboxes.get("sbx-1")!.generation = 2;
      if (change === "attempt") op.dispatchAttempt = 2;
      if (change === "sandbox") op.sandboxId = "foreign";
      if (change === "epoch") store.hosts.get("host-1")!.connectionEpoch = 2;
      if (change === "deleted") store.sandboxes.get("sbx-1")!.state = "DELETED";
      if (change === "terminal") op.state = "SUCCEEDED";
      const before = structuredClone([
        store.hosts,
        store.sandboxes,
        store.operations,
        store.outbox,
      ]);
      expect(await applyOperationProgress({ ...fence, state: "running" })).toEqual({
        written: false,
      });
      expect(await applyOperationResult({ ...fence, state: "failed" })).toEqual({ written: false });
      expect(await binary()).toBe(false);
      expect([store.hosts, store.sandboxes, store.operations, store.outbox]).toEqual(before);
      expect(captures.peek("op-1", 1)).toBeUndefined();
    });
  }
  it("duplicate terminal and terminal progress cannot overwrite a result", async () => {
    await applyOperationResult({
      ...fence,
      state: "succeeded",
      result: commandResultFixture(store, "op-1", 1),
    });
    expect(await applyOperationResult({ ...fence, state: "failed" })).toEqual({ written: false });
    expect(await applyOperationProgress({ ...fence, state: "running" })).toEqual({
      written: false,
    });
    expect(await applyOperationProgress({ ...fence, state: "succeeded" })).toEqual({
      written: false,
    });
    expect(store.operations.get("op-1")!.result).toMatchObject({ exitCode: 1 });
  });
  it("destroy wins while a result waits for admission", async () => {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    const result = applyOperationResult({ ...fence, state: "succeeded", result: fileResult() });
    await entered.promise;
    await prisma.$transaction(async (tx) => {
      await tx.sandboxHost.updateMany({
        where: { id: "host-1", connectionEpoch: 1 },
        data: { connectionEpoch: 1 },
      });
      await tx.sandbox.updateMany({
        where: { id: "sbx-1", generation: 1 },
        data: { generation: 2, state: "DELETED" },
      });
    });
    resume.resolve();
    expect(await result).toEqual({ written: false });
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
  });
  it("result holding admission commits before concurrent destroy (actual lock contention)", async () => {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeOperationWrite = async () => {
      store.barriers.beforeOperationWrite = undefined;
      entered.resolve();
      await resume.promise;
    };
    const result = applyOperationResult({ ...fence, state: "succeeded", result: fileResult() });
    await entered.promise;
    let destroyed = false;
    const destroy = prisma.$transaction(async (tx) => {
      await tx.sandboxHost.updateMany({ where: { id: "host-1" }, data: { connectionEpoch: 1 } });
      await tx.sandbox.updateMany({
        where: { id: "sbx-1" },
        data: { state: "DELETED", generation: 2 },
      });
      destroyed = true;
    });
    await Promise.resolve();
    expect(destroyed).toBe(false);
    resume.resolve();
    expect(await result).toEqual({ written: true });
    await destroy;
    expect(store.sandboxes.get("sbx-1")!.state).toBe("DELETED");
  });
  it("commit failure retains file bytes and rolls back all writes", async () => {
    store.operations.get("op-1")!.kind = "GET_FILE";
    await captures.append("op-1", 1, 0, new Uint8Array([88]), true);
    store.barriers.beforeCommit = async () => {
      throw new Error("commit failed");
    };
    await expect(
      applyOperationResult({ ...fence, state: "succeeded", result: fileResult() }),
    ).rejects.toThrow("An internal error occurred.");
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array([88]));
    store.barriers.beforeCommit = undefined;
    expect(
      await applyOperationResult({ ...fence, state: "succeeded", result: fileResult() }),
    ).toEqual({ written: true });
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array([88]));
    expect(captures.peek("op-1", 1)?.size).toBe(1);
  });

  it("file completion requires the captured length and SHA-256", async () => {
    store.operations.get("op-1")!.kind = "GET_FILE";
    await binary();
    const capture = captures.peek("op-1", 1)!;
    for (const result of [
      { size: 3, sha256: capture.sha256 },
      { size: 2, sha256: "0".repeat(64) },
    ]) {
      expect(await applyOperationResult({ ...fence, state: "succeeded", result })).toEqual({
        written: false,
      });
      expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    }
    expect(
      await applyOperationResult({
        ...fence,
        state: "succeeded",
        result: { size: capture.size, sha256: capture.sha256 },
      }),
    ).toEqual({ written: true });
  });
  it("binary commit failure publishes no bytes", async () => {
    store.operations.get("op-1")!.kind = "GET_FILE";
    store.barriers.beforeCommit = async () => {
      throw new Error("commit failed");
    };
    await expect(binary()).rejects.toThrow("An internal error occurred.");
    expect(captures.peek("op-1", 1)).toBeUndefined();
  });
  it("empty download is persisted, missing download does not falsely succeed", async () => {
    store.operations.get("op-1")!.kind = "GET_FILE";
    expect(
      await applyOperationResult({ ...fence, state: "succeeded", result: fileResult() }),
    ).toEqual({
      written: false,
    });
    await acceptFencedBinaryChunk({
      ...fence,
      sequence: 0,
      offset: 0,
      ended: true,
      body: new Uint8Array(),
    });
    expect(
      await applyOperationResult({ ...fence, state: "succeeded", result: fileResult() }),
    ).toEqual({ written: true });
    expect(await captures.bytes("op-1", 1)).toEqual(new Uint8Array());
  });
  it("outbox lookups stay on the sandbox aggregate index prefix", async () => {
    store.operations.get("op-1")!.kind = "GET_FILE";
    await binary();
    const outboxSql = store.trace.filter(
      (entry) => entry.startsWith("sql:") && entry.includes("FROM sandbox_dispatch_outbox"),
    );
    expect(outboxSql.length).toBeGreaterThan(0);
    for (const sql of outboxSql) expect(sql).toContain(`"aggregateType" = 'sandbox'`);
  });
  it("ordinary results never author lifecycle state", () => {
    expect(wouldAuthorSandboxState("RUN_COMMAND", "FAILED", "READY")).toBeUndefined();
    expect(wouldAuthorSandboxState("CREATE_SANDBOX", "SUCCEEDED", "DELETED")).toBeUndefined();
  });
});

describe("reconnect acknowledgement lease fence", () => {
  it("accepts the immutable queued lease and rejects the observed renewal", async () => {
    store.operations.get("op-1")!.kind = "RECONNECT_SANDBOX";
    store.sandboxes.get("sbx-1")!.state = "STOPPED";
    const queued = store.outbox.get("evt-1")!.payload.lease as Record<string, unknown>;
    // A renewal (revision 2) landed after the reconnect was queued with
    // revision 1. The host runs the runtime work with the renewal but its ACK
    // must echo the queued lease exactly — anything else is fenced out.
    const observed = { ...queued, revision: 2 };
    expect(
      await applyOperationResult({
        ...fence,
        state: "succeeded",
        result: { state: "ready", lease: observed },
      }),
    ).toEqual({ written: false });
    expect(store.operations.get("op-1")!.state).not.toBe("SUCCEEDED");
    expect(store.sandboxes.get("sbx-1")!.state).toBe("STOPPED");
    expect(
      await applyOperationResult({
        ...fence,
        state: "succeeded",
        result: { state: "ready", lease: queued },
      }),
    ).toEqual({ written: true });
    expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
  });
});
describe("guest group-signal support", () => {
  const reconnect = async (result: Record<string, unknown>) => {
    store.operations.get("op-1")!.kind = "RECONNECT_SANDBOX";
    store.sandboxes.get("sbx-1")!.state = "STOPPED";
    const lease = store.outbox.get("evt-1")!.payload.lease;
    return applyOperationResult({
      ...fence,
      state: "succeeded",
      result: { state: "ready", lease, ...result },
    });
  };
  it("records the host's observation from a ready reconnect", async () => {
    expect(await reconnect({ guestGroupSignals: false })).toEqual({ written: true });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "READY",
      guestGroupSignals: false,
    });
  });
  it("missing ready evidence leaves the new boot unobserved", async () => {
    store.sandboxes.get("sbx-1")!.guestGroupSignals = false;
    expect(await reconnect({})).toEqual({ written: true });
    expect(store.sandboxes.get("sbx-1")!.guestGroupSignals).toBeNull();
  });
  it("accepts only a boolean", () => {
    expect(readyResultGroupSignals({ guestGroupSignals: true })).toBe(true);
    expect(readyResultGroupSignals({ guestGroupSignals: false })).toBe(false);
    for (const result of [undefined, null, {}, { guestGroupSignals: "false" }])
      expect(readyResultGroupSignals(result)).toBeNull();
  });
});
describe("receipt reconciliation", () => {
  const receipt = { bodyHash: "hash", idempotencyKey: "key", kind: "command.run" };
  const replacement = { ...sender, connectionEpoch: 2 };
  beforeEach(async () => {
    store.hosts.get("host-1")!.connectionEpoch = 2;
    Object.assign(store.operations.get("op-1")!, {
      requestBodyHash: "hash",
      idempotencyKey: "key",
    });
  });
  it("replacement progress, result and binary cannot adopt old work", async () => {
    expect(
      await applyOperationProgress({ ...fence, sender: replacement, state: "running" }),
    ).toEqual({ written: false });
    expect(
      await applyOperationResult({ ...fence, sender: replacement, state: "succeeded" }),
    ).toEqual({ written: false });
    expect(
      await acceptFencedBinaryChunk({
        ...fence,
        sender: replacement,
        sequence: 0,
        ended: true,
        body: new Uint8Array([1]),
      }),
    ).toBe(false);
    expect(store.operations.get("op-1")!.dispatchedConnectionEpoch).toBe(1);
  });
  it("E2-A-01: a successful capture result the fence drops hands its image back for release", async () => {
    const fingerprint = `sha256:${"e".repeat(64)}`;
    droppedCapture.release.mockResolvedValueOnce({ imageOwnerId: "user-1", fingerprint });
    expect(
      await applyOperationResult({
        ...fence,
        sender: replacement,
        state: "succeeded",
        result: { fingerprint, sizeBytes: 1, architecture: "x86_64" },
      }),
    ).toEqual({ written: false, releaseImage: { imageOwnerId: "user-1", fingerprint } });
    expect(droppedCapture.release).toHaveBeenCalledWith({
      operationId: "op-1",
      hostId: "host-1",
      fingerprint,
    });
    // A failed result published nothing to release.
    droppedCapture.release.mockClear();
    await applyOperationResult({
      ...fence,
      sender: replacement,
      state: "failed",
      error: { code: "capture_failed", message: "x" },
    });
    expect(droppedCapture.release).not.toHaveBeenCalled();
  });
  it.each(["bodyHash", "idempotencyKey", "kind"] as const)(
    "rejects mismatched receipt %s",
    async (field) => {
      expect(
        await applyOperationResult({
          ...fence,
          sender: replacement,
          receipt: { ...receipt, [field]: "foreign" },
          state: "succeeded",
        }),
      ).toEqual({ written: false });
      expect(store.operations.get("op-1")!.state).toBe("RUNNING");
      expect(store.operations.get("op-1")!.dispatchedConnectionEpoch).toBe(1);
    },
  );
  it.each(["DISPATCHED", "ACCEPTED", "RUNNING"])(
    "recovers a confirmed receipt from %s exactly once",
    async (state) => {
      store.operations.get("op-1")!.state = state;
      expect(
        await applyOperationResult({
          ...fence,
          sender: replacement,
          receipt,
          state: "succeeded",
          result: commandResultFixture(store),
        }),
      ).toEqual({ written: true });
      expect(store.operations.get("op-1")!.dispatchedConnectionEpoch).toBe(2);
      expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
      expect(
        await applyOperationResult({ ...fence, sender: replacement, receipt, state: "succeeded" }),
      ).toEqual({ written: false });
    },
  );
  it("missing inventory stays unknown across bounded pages and preserves placement", async () => {
    const { finishHostReconciliation } = await import("./operation-handlers.js");
    await captures.append("op-1", 1, 0, new Uint8Array([65]), true);
    // An unknown download keeps no capture; other kinds never touch captures.
    store.operations.get("op-1")!.kind = "GET_FILE";
    const template = store.operations.get("op-1")!;
    for (let i = 0; i < 70; i++)
      store.operations.set(`op-${i + 2}`, { ...template, id: `op-${i + 2}` });
    store.operations.set("fresh", {
      ...template,
      id: "fresh",
      state: "QUEUED",
      dispatchedConnectionEpoch: null,
    });
    expect(await finishHostReconciliation(replacement)).toBe(true);
    expect(
      [...store.operations.values()].filter((op) => op.state === "UNKNOWN_OUTCOME"),
    ).toHaveLength(71);
    expect(store.operations.get("fresh")!.state).toBe("QUEUED");
    expect(captures.peek("op-1", 1)).toBeUndefined();
    expect(store.sandboxes.get("sbx-1")!.sandboxHostId).toBe("host-1");
    expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
  });
});

describe("unit (fenced harness; no real-DB test yet) — durable receipt confirmation and uncertain lifecycle", () => {
  const receipt = { bodyHash: "a".repeat(64), idempotencyKey: "key", kind: "command.run" };
  beforeEach(() =>
    Object.assign(store.operations.get("op-1")!, {
      requestBodyHash: receipt.bodyHash,
      idempotencyKey: receipt.idempotencyKey,
    }),
  );
  it("confirms terminal work and requests host proof for an exact unknown command", async () => {
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", written: false }),
    ).toBeNull();
    const written = await applyOperationResult({
      ...fence,
      state: "succeeded",
      result: fileResult(),
    });
    expect(written.written).toBe(true);
    expect(
      await confirmOperationReceipt({ ...fence, state: "succeeded", ...written }),
    ).toMatchObject({ type: "receipt.confirmed", ...receipt });
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", written: false }),
    ).toMatchObject({ type: "receipt.confirmed" });
    for (const state of ["succeeded", "unknown_outcome"]) {
      expect(
        await confirmOperationReceipt({ ...fence, receipt, state, written: false }),
      ).toMatchObject({ type: "receipt.confirmed" });
      for (const field of ["bodyHash", "idempotencyKey", "kind"] as const) {
        expect(
          await confirmOperationReceipt({
            ...fence,
            receipt: { ...receipt, [field]: "foreign" },
            state,
            written: false,
          }),
        ).toBeNull();
      }
    }
    expect(
      await confirmOperationReceipt({ ...fence, state: "unknown_outcome", written: true }),
    ).toBeNull();
    store.operations.get("op-1")!.state = "UNKNOWN_OUTCOME";
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "unknown_outcome", written: true }),
    ).toMatchObject({ type: "receipt.confirmed", retireCommand: true });
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", written: false }),
    ).toBeNull();
  });
  it("WP0/C10: an unappliable versioned receipt gets a terminal verdict, never an open replay", async () => {
    Object.assign(store.operations.get("op-1")!, {
      resultVersion: null,
      processId: null,
      ...initialResultFields("RUN_COMMAND", true),
      ...initialProcessFields("RUN_COMMAND"),
    });
    // A natural success without its bound birth (the wrapper's start record
    // is best-effort): 1.0 has no command payload for it.
    const result = {
      version: 1,
      observedAt: new Date().toISOString(),
      payload: null,
      continuation: null,
      birth: null,
      failure: null,
      outputBytes: 0,
    };
    // The live frame is still refused without a write; its receipt follows.
    expect(await applyOperationResult({ ...fence, state: "succeeded", result })).toEqual({
      written: false,
    });
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    const written = await applyOperationResult({ ...fence, receipt, state: "succeeded", result });
    expect(written.written).toBe(true);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "protocol_error",
      scalarResult: null,
    });
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", ...written }),
    ).toMatchObject({ type: "receipt.confirmed", operationId: "op-1" });
    // A replay in a later session changes nothing and is confirmed again by
    // the terminal row, so the host retires it.
    expect(
      await applyOperationResult({ ...fence, receipt, state: "succeeded", result }),
    ).toMatchObject({ written: false });
    expect(store.operations.get("op-1")!.state).toBe("FAILED");
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", written: false }),
    ).toMatchObject({ type: "receipt.confirmed" });
  });
  it("WP0/C10: a versioned success with no result at all is settled, not left open", async () => {
    Object.assign(store.operations.get("op-1")!, {
      resultVersion: null,
      processId: null,
      ...initialResultFields("RUN_COMMAND", true),
      ...initialProcessFields("RUN_COMMAND"),
    });
    expect(await applyOperationResult({ ...fence, state: "succeeded" })).toEqual({
      written: false,
    });
    const written = await applyOperationResult({ ...fence, receipt, state: "succeeded" });
    expect(written.written).toBe(true);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "protocol_error",
    });
    expect(
      await confirmOperationReceipt({ ...fence, receipt, state: "succeeded", ...written }),
    ).toMatchObject({ type: "receipt.confirmed" });
  });
  it("a malformed unknown command receipt stays uncertain and requires host proof", async () => {
    Object.assign(store.operations.get("op-1")!, {
      resultVersion: null,
      processId: null,
      ...initialResultFields("RUN_COMMAND", true),
      ...initialProcessFields("RUN_COMMAND"),
    });
    // UNKNOWN evidence for a command must name the command resource.
    const result = {
      version: 1,
      observedAt: new Date().toISOString(),
      payload: null,
      continuation: null,
      birth: null,
      failure: { resource: "filesystem", effect: "unknown" },
    };
    const input = { ...fence, receipt, state: "unknown_outcome", result };
    expect(await applyOperationResult(input)).toMatchObject({ written: true });
    // The row remains uncertain; only host proof may retire its receipt.
    expect(store.operations.get("op-1")).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      errorCode: "unknown_outcome",
      scalarResult: null,
    });
    expect(
      await confirmOperationReceipt({ ...input, state: "unknown_outcome", written: true }),
    ).toMatchObject({ type: "receipt.confirmed", retireCommand: true });
    // Each later session's replay changes nothing.
    expect(await applyOperationResult(input)).toEqual({ written: false });
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    // The existing path: a later stop supersedes the attempt, and its
    // positive cleanup is the proof the host needs to delete the receipt.
    store.operations.get("op-1")!.state = "CANCELLED";
    store.operations.set("stop-2", {
      ...store.operations.get("op-1")!,
      id: "stop-2",
      kind: "STOP_SANDBOX",
      state: "SUCCEEDED",
      generation: 2,
      result: { state: "stopped" },
    });
    expect(
      await confirmOperationReceipt({ ...input, state: "unknown_outcome", written: false }),
    ).toMatchObject({ type: "receipt.confirmed", cleanupGeneration: 2 });
  });
  it("WP0: an exact receipt refused by a database error stays retryable, never settled", async () => {
    Object.assign(store.operations.get("op-1")!, {
      resultVersion: null,
      processId: null,
      ...initialResultFields("RUN_COMMAND", true),
      ...initialProcessFields("RUN_COMMAND"),
    });
    const transient = Object.assign(new Error("could not serialize access"), { code: "P2034" });
    db.$transaction.mockImplementationOnce(() => Promise.reject(transient));
    // Unappliable evidence, so only the error class decides: it is thrown
    // (the frame fails and the session retries), never classified.
    const input = { ...fence, receipt, state: "succeeded" };
    await expect(applyOperationResult(input)).rejects.toBeDefined();
    expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    expect(store.operations.get("op-1")!.errorCode ?? null).toBeNull();
  });
  it("replacement epoch fences confirmation while it waits for the host lock", async () => {
    await applyOperationResult({ ...fence, state: "succeeded", result: fileResult() });
    const entered = gate(),
      release = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await release.promise;
    };
    const pending = confirmOperationReceipt({
      ...fence,
      receipt,
      state: "succeeded",
      written: false,
    });
    await entered.promise;
    await prisma.$transaction(async (tx) => {
      await tx.sandboxHost.updateMany({
        where: { id: "host-1", connectionEpoch: 1 },
        data: { connectionEpoch: 2 },
      });
    });
    release.resolve();
    expect(await pending).toBeNull();
    expect(
      await confirmOperationReceipt({
        ...fence,
        sender: { ...sender, connectionEpoch: 2 },
        receipt,
        state: "succeeded",
        written: false,
      }),
    ).toMatchObject({ type: "receipt.confirmed" });
  });
  it.each(["succeeded", "failed"])(
    "uncertain create queues teardown and a late %s receipt cannot resurrect it",
    async (state) => {
      store.operations.get("op-1")!.kind = "CREATE_SANDBOX";
      store.sandboxes.get("sbx-1")!.state = "PROVISIONING";
      expect(
        await applyOperationResult({
          ...fence,
          state: "unknown_outcome",
          error: { code: "unknown_outcome", message: "launch timed out" },
        }),
      ).toEqual({ written: true });
      expect(store.sandboxes.get("sbx-1")!.state).toBe("STOPPING");
      expect(store.sandboxes.get("sbx-1")!.sandboxHostId).toBe("host-1");
      // E3B-02: the failure names the node daemon restart (the code is unchanged).
      expect(store.operations.get("op-1")).toMatchObject({
        state: "FAILED",
        errorCode: "unknown_outcome",
        errorDetail: expect.stringMatching(
          /^The node daemon could not confirm .*it restarted or lost its connection/,
        ),
      });
      expect(
        await applyOperationResult({
          ...fence,
          receipt: { ...receipt, kind: "sandbox.create" },
          state,
          result: { state: "ready", lease: store.outbox.get("evt-1")!.payload.lease },
        }),
      ).toEqual({ written: false });
      expect(store.sandboxes.get("sbx-1")!.state).toBe("STOPPING");
      expect(
        [...store.operations.values()].filter((op) => op.kind === "KILL_SANDBOX"),
      ).toHaveLength(1);
    },
  );
});

describe("C10 cancellation acknowledgement", () => {
  const receipt = { bodyHash: "a".repeat(64), idempotencyKey: "key", kind: "command.run" };
  const replacement = { ...sender, connectionEpoch: 2 };

  beforeEach(async () => {
    Object.assign(store.operations.get("op-1")!, {
      kind: "RUN_COMMAND",
      requestBodyHash: receipt.bodyHash,
      idempotencyKey: receipt.idempotencyKey,
      dispatchedConnectionEpoch: 1,
    });
  });

  it("natural completion wins while cancel is requested", async () => {
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    expect(
      await applyOperationResult({ ...fence, state: "succeeded", result: fileResult() }),
    ).toEqual({ written: true });
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
  });

  it("duplicate cancelled terminal commits exactly once", async () => {
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    const cancelled = {
      state: "cancelled" as const,
      error: { code: "cancelled" as const, message: "command was cancelled" },
    };
    expect(await applyOperationResult({ ...fence, ...cancelled })).toEqual({ written: true });
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
    expect(await applyOperationResult({ ...fence, ...cancelled })).toEqual({ written: false });
  });

  it("lost cancel acknowledgement reconnects to cancelled never success", async () => {
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    expect(
      await applyOperationResult({
        ...fence,
        sender: replacement,
        receipt,
        state: "cancelled",
        error: { code: "cancelled", message: "command was cancelled" },
      }),
    ).toEqual({ written: true });
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
    expect(store.operations.get("op-1")!.state).not.toBe("SUCCEEDED");
  });

  it("broken transport during cancel reconciles unknown not cancelled", async () => {
    const { finishHostReconciliation } = await import("./operation-handlers.js");
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    expect(await finishHostReconciliation(replacement)).toBe(true);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(store.operations.get("op-1")!.errorCode).toBe("unknown_outcome");
  });
});
