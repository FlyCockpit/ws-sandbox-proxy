vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

import prisma from "@wssp/db";
import { bindCapacityQueueWake, noteCapacityChanged } from "./capacity-queue-wake";
import { KEY_FREE_CLEANUP_KINDS } from "./contracts";
import {
  bindSandboxDispatchWake,
  createSandboxOutboxEvent,
  decodeOutboxPrincipal,
  notifySandboxDispatchPending,
  sandboxOutboxTransaction,
  systemDispatchAllowed,
} from "./outbox.js";
import { outboxOperationIdOf } from "./outbox-operation";

describe("sandbox outbox helper", () => {
  beforeEach(() => {
    bindSandboxDispatchWake(null);
    vi.resetAllMocks();
    vi.mocked(prisma.sandbox.findFirst).mockResolvedValue({
      leaseRevision: 1,
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
      leaseExpireAction: "STOP",
      template: "revision/" + "template-1",
      sandboxHostId: "host-1",
    } as never);
    vi.mocked(prisma.sandboxPlacement.findFirst).mockResolvedValue({
      artifact: "sha256:" + "a".repeat(64),
      architecture: "x86_64",
      guestUid: 1234,
      guestGid: 2345,
      guestHome: "/home/declared",
      guestShell: "/bin/bash",
    } as never);
    vi.mocked(prisma.$transaction).mockImplementation(async (fn) =>
      (fn as (tx: typeof prisma) => Promise<unknown>)(prisma),
    );
  });
  afterEach(() => bindSandboxDispatchWake(null));

  it("wakes only after a committed sandbox service transaction", async () => {
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    await sandboxOutboxTransaction(async (tx) => {
      await createSandboxOutboxEvent(tx, {
        authorizingPrincipal: { kind: "session" },
        userId: "user-1",
        aggregateId: "sandbox-1",
        eventType: "sandbox.create_requested",
        payload: { operationId: "op-1", kind: "sandbox.create" },
      });
      return true;
    });
    expect(wake).toHaveBeenCalledTimes(1);
  });

  it("does not wake when the service transaction rolls back", async () => {
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    vi.mocked(prisma.$transaction).mockRejectedValue(new Error("rollback"));
    await expect(
      sandboxOutboxTransaction(async () => {
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(wake).not.toHaveBeenCalled();
  });

  it("delivers capacity-queue hints only after commit, merged, and never on rollback (unit; real wakes: capacity-queue.pg.test.ts)", async () => {
    const wake = vi.fn();
    bindCapacityQueueWake(wake);
    try {
      await sandboxOutboxTransaction(async (tx) => {
        noteCapacityChanged(tx, { hostIds: ["host-1"] });
        noteCapacityChanged(tx, { poolIds: ["pool-1"] });
        expect(wake).not.toHaveBeenCalled();
        return true;
      });
      expect(wake).toHaveBeenCalledTimes(1);
      const hint = wake.mock.calls[0]![0] as { poolIds: string[]; hostIds: string[] };
      expect([...hint.hostIds]).toEqual(["host-1"]);
      expect([...hint.poolIds]).toEqual(["pool-1"]);
      wake.mockClear();
      vi.mocked(prisma.$transaction).mockImplementation(async (fn) => {
        await (fn as (tx: typeof prisma) => Promise<unknown>)(prisma);
        throw new Error("rollback");
      });
      await expect(
        sandboxOutboxTransaction(async (tx) => {
          noteCapacityChanged(tx, "all");
          return true;
        }),
      ).rejects.toThrow("rollback");
      expect(wake).not.toHaveBeenCalled();
    } finally {
      bindCapacityQueueWake(null);
    }
  });

  it("rejects an oversized encoded command envelope before outbox insertion or wake", async () => {
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    vi.mocked(prisma.sandboxPlacement.findFirst).mockResolvedValue({
      artifact: "sha256:" + "a".repeat(64),
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/" + "x".repeat(65536),
      guestShell: "/bin/bash",
    } as never);
    await expect(
      sandboxOutboxTransaction((tx) =>
        createSandboxOutboxEvent(tx, {
          authorizingPrincipal: { kind: "session" },
          userId: "user-1",
          aggregateId: "sandbox-1",
          eventType: "sandbox.command_requested",
          payload: { operationId: "op-1", kind: "command.run", script: "true" },
        }),
      ),
    ).rejects.toThrow("Encoded command dispatch exceeds 64 KiB");
    expect(prisma.outboxEvent.create).not.toHaveBeenCalled();
    expect(wake).not.toHaveBeenCalled();
  });

  it("notifySandboxDispatchPending is a no-op without a bound wake", () => {
    expect(() => notifySandboxDispatchPending()).not.toThrow();
  });

  it("does not self-wake on locks, dispatch claims or cancellation retry claims", async () => {
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    vi.mocked(prisma.sandboxOperation.updateMany).mockResolvedValue({ count: 1 });
    vi.mocked(prisma.outboxEvent.updateMany).mockResolvedValue({ count: 1 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandbox.updateMany({ where: { id: "sandbox-1" }, data: { generation: 1 } });
      await tx.sandboxOperation.updateMany({
        where: { id: "op-1" },
        data: { state: "DISPATCHED", acceptedAttempt: null },
      });
      await tx.sandboxOperation.updateMany({
        where: { id: "op-1" },
        data: { state: "CANCEL_REQUESTED" },
      });
      await tx.sandboxOperation.updateMany({
        where: { id: "op-1" },
        data: {
          state: "QUEUED",
          dispatchAttempt: 0,
          dispatchedAt: null,
          dispatchedHostId: null,
          dispatchedConnectionEpoch: null,
        },
      });
      await tx.outboxEvent.updateMany({
        where: { id: "event-1" },
        data: { claimToken: "claim", claimedAt: new Date() },
      });
    });
    expect(wake).not.toHaveBeenCalled();
  });

  it("zero-row eligibility writes do not wake", async () => {
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    vi.mocked(prisma.sandboxOperation.updateMany).mockResolvedValue({ count: 0 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandboxOperation.updateMany({
        where: { id: "missing" },
        data: { state: "ACCEPTED", acceptedAttempt: 1 },
      });
    });
    expect(wake).not.toHaveBeenCalled();
  });
});

it.each([
  "sandbox.create",
  "sandbox.reconnect",
  "sandbox.stop",
  "sandbox.kill",
  "command.run",
  "file.get",
  "file.put",
  "file.list",
  "file.stat",
  "file.mkdir",
  "file.remove",
  "file.move",
  "process.signal",
])("C14 %s persists the host-bound template identity for dispatch and replay", async (kind) => {
  const db = vi.mocked(prisma, true);
  db.sandbox.findFirst.mockResolvedValue({
    leaseRevision: 1,
    leaseExpiresAt: new Date(Date.now() + 3_600_000),
    leaseExpireAction: "STOP",
    template: "revision/" + "template-1",
    sandboxHostId: "host-1",
  } as never);
  db.sandboxPlacement.findFirst.mockResolvedValue({
    artifact: "sha256:" + "a".repeat(64),
    architecture: "aarch64",
    guestUid: 1234,
    guestGid: 2345,
    guestHome: "/home/declared",
    guestShell: "/bin/bash",
  } as never);
  await createSandboxOutboxEvent(db, {
    authorizingPrincipal: { kind: "session" },
    userId: "owner",
    aggregateId: "sbx",
    eventType: "test",
    payload: {
      operationId: "op-1",
      kind,
      guestUid: 0,
      imageRef: "moved-alias",
      ...(kind === "command.run" ? { argv: ["true"], timeoutMs: 120000 } : {}),
    },
  });
  expect(db.sandboxPlacement.findFirst).toHaveBeenLastCalledWith(
    expect.objectContaining({
      where: expect.objectContaining({ sandboxId: "sbx", userId: "owner" }),
    }),
  );
  expect(db.outboxEvent.create).toHaveBeenLastCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({
        payload: expect.objectContaining({
          incusFingerprint: "sha256:" + "a".repeat(64),
          templateDigest: "sha256:" + "a".repeat(64),
          architecture: "aarch64",
          guestUid: 1234,
          guestGid: 2345,
          guestHome: "/home/declared",
        }),
      }),
    }),
  );
});

it.each([
  [{}, null],
  [{ authorizingKeyId: "k1" }, null],
  [{ kind: "sandbox.stop" }, null],
  [{ authorizingPrincipal: { kind: "system" } }, { kind: "system" }],
  [{ authorizingPrincipal: { kind: "session" }, authorizingKeyId: "shadow" }, { kind: "session" }],
  [{ authorizingPrincipal: { kind: "sdkKey", keyId: "k1" } }, { kind: "sdkKey", keyId: "k1" }],
  [{ authorizingPrincipal: null, authorizingKeyId: "k1" }, null],
  [{ authorizingPrincipal: { kind: "session", keyId: "shadow" } }, null],
  [{ authorizingKeyId: null }, null],
] as const)("explicit attribution decoding %j", (payload, expected) => {
  expect(decodeOutboxPrincipal(payload)).toEqual(expected);
});

describe("build attribution (template-builds §3.1)", () => {
  const build = { kind: "build", buildId: "build-1", keyId: "k1" };
  it.each([
    [{ authorizingPrincipal: build }, build],
    [
      { authorizingPrincipal: { kind: "build", buildId: "build-1", keyId: null } },
      { kind: "build", buildId: "build-1", keyId: null },
    ],
    // Strict: exactly {kind, buildId, keyId}.
    [{ authorizingPrincipal: { kind: "build", buildId: "build-1" } }, null],
    [{ authorizingPrincipal: { ...build, extra: true } }, null],
    [{ authorizingPrincipal: { ...build, keyId: "" } }, null],
    [{ authorizingPrincipal: { ...build, keyId: 7 } }, null],
    [{ authorizingPrincipal: { ...build, buildId: "" } }, null],
    [{ authorizingPrincipal: { ...build, buildId: "../x" } }, null],
  ] as const)("decodes strictly %j", (payload, expected) => {
    expect(decodeOutboxPrincipal(payload)).toEqual(expected);
  });

  it("a build kill passes the closed system payload; an extra field is refused", () => {
    const kill = { kind: "sandbox.kill", sandboxId: "s", authorizingPrincipal: build };
    expect(systemDispatchAllowed("sandbox.kill", kill)).toBe(true);
    expect(systemDispatchAllowed("sandbox.stop", { ...kill, kind: "sandbox.stop" })).toBe(true);
    expect(systemDispatchAllowed("sandbox.kill", { ...kill, runAs: "root" })).toBe(false);
    expect(systemDispatchAllowed("sandbox.kill", { ...kill, extra: "x" })).toBe(false);
  });

  it("C9 live: a prepared system kill of a restored lineage carries its disk base", () => {
    const kill = {
      kind: "sandbox.kill",
      sandboxId: "s",
      authorizingPrincipal: { kind: "system" },
      diskBaseFingerprint: `sha256:${"a".repeat(64)}`,
    };
    expect(systemDispatchAllowed("sandbox.kill", kill, true)).toBe(true);
    expect(systemDispatchAllowed("sandbox.stop", { ...kill, kind: "sandbox.stop" }, true)).toBe(
      true,
    );
    // Only on the prepared frame, and only a well-formed fingerprint.
    expect(systemDispatchAllowed("sandbox.kill", kill)).toBe(false);
    expect(
      systemDispatchAllowed("sandbox.kill", { ...kill, diskBaseFingerprint: "sha256:x" }, true),
    ).toBe(false);
    expect(
      systemDispatchAllowed("sandbox.kill", { ...kill, restore: { offloadId: "o" } }, true),
    ).toBe(false);
  });
});

it("principal-shadowing writes the server principal after every payload spread", async () => {
  await createSandboxOutboxEvent(vi.mocked(prisma, true), {
    userId: "owner",
    aggregateId: "sandbox",
    eventType: "sandbox.stdin_requested",
    authorizingPrincipal: { kind: "session" },
    payload: {
      operationId: "op-1",
      kind: "process.stdin",
      authorizingPrincipal: { kind: "sdkKey", keyId: "shadow" },
      authorizingKeyId: "shadow",
    },
  });
  expect(prisma.outboxEvent.create).toHaveBeenLastCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({
        payload: expect.objectContaining({ authorizingPrincipal: { kind: "session" } }),
      }),
    }),
  );
});

it.each([
  "sandbox.kill",
  "sandbox.stop",
  "command.run",
  "file.put",
  "sandbox.lease.renew",
  "operation.cancel",
  "process.stdin",
  "process.signal",
  "process.list",
  "sandbox.delete",
])("system_dispatch_kind_allowlist %s", (kind) => {
  expect(
    systemDispatchAllowed(kind, { kind, sandboxId: "s", authorizingPrincipal: { kind: "system" } }),
  ).toBe(kind === "sandbox.kill" || kind === "sandbox.stop");
});
it.each([
  "env",
  "envs",
  "stdinBase64",
  "stdinBytes",
  "stdinEof",
  "configId",
  "config",
  "privateConfig",
  "bindingMac",
  "extra",
])("system_dispatch_kind_allowlist rejects cleanup field %s including nested payloads", (field) => {
  expect(
    systemDispatchAllowed("sandbox.stop", {
      kind: "sandbox.stop",
      [field]: { nested: { envs: { TOKEN: "sentinel" } } },
    }),
  ).toBe(false);
});

describe("T11 (M4): the lease-policy system renewal gains exactly one validated field", () => {
  // Unit (pure predicate). Each call site runs it: outbox-processor claim and
  // accepted-authority checks and session-manager's prepared dispatch; the
  // real dispatch path is covered by lease-pull-in.pg.test.ts.
  const lease = {
    revision: 3,
    deadlineUnixMs: Date.parse("2030-01-01T06:00:00Z"),
    action: "destroy",
    expiryPolicy: "retry-force-60s",
    shortenOnly: true,
  };
  const stored = {
    kind: "sandbox.lease.renew",
    sandboxId: "s",
    sandboxHostId: "h",
    operationId: "o",
    generation: 1,
    dispatchAttempt: 0,
    idempotencyKey: "lease-policy:s:1:2",
    templateId: "t",
    templateDigest: `sha256:${"a".repeat(64)}`,
    incusFingerprint: `sha256:${"a".repeat(64)}`,
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/u",
    guestShell: "/bin/bash",
    authorizingPrincipal: { kind: "system" },
    lease,
  };
  it("accepts the stored payload and the prepared dispatch input", () => {
    expect(systemDispatchAllowed("sandbox.lease.renew", stored)).toBe(true);
    expect(
      systemDispatchAllowed(
        "sandbox.lease.renew",
        {
          ...stored,
          connectionEpoch: 2,
          attempt: 1,
          bodyHash: "b".repeat(64),
          digestScheme: "hmac-sha256-v1",
          digestKeyId: "k",
          onPossibleDispatchFrame: () => {},
          allocation: undefined,
        },
        true,
      ),
    ).toBe(true);
  });
  it.each([
    ["a malformed lease", { lease: { ...lease, revision: 0 } }],
    ["a lease past the far-future bound", { lease: { ...lease, deadlineUnixMs: 253402300800000 } }],
    ["an extra lease field", { lease: { ...lease, extra: true } }],
    [
      "a lease that is not shorten-only (round 2 #1)",
      { lease: { ...lease, shortenOnly: undefined } },
    ],
    ["an extra payload field", { envs: { A: "b" } }],
    ["a user idempotency key", { idempotencyKey: "user-renewal" }],
    ["another reserved namespace", { idempotencyKey: "lease-expire:s:1:2:STOP" }],
  ])("refuses %s", (_label, patch) => {
    expect(systemDispatchAllowed("sandbox.lease.renew", { ...stored, ...patch })).toBe(false);
  });
  it("never allows `lease` on another kind, and renew stays outside key-free cleanup", () => {
    for (const kind of ["sandbox.stop", "sandbox.kill", "sandbox.reconnect", "sandbox.create"])
      expect(systemDispatchAllowed(kind, { ...stored, kind })).toBe(false);
    expect(KEY_FREE_CLEANUP_KINDS.has("sandbox.lease.renew")).toBe(false);
  });
});

describe("sandboxOutboxTransaction wakes operation long-polls only after commit", () => {
  // Unit (mocked Prisma). Real-DB commit→notify ordering and the fence-rejected
  // rollback: apps/server/src/sandbox-relay/operation-wait.pg.test.ts.
  type Rendered = string[] | "all";
  const render = (change: import("./operation-waiters.js").OperationChange | null): Rendered =>
    change === null
      ? []
      : change === "all"
        ? "all"
        : [
            ...[...change.operationIds].map((id) => `op:${id}`),
            ...[...change.ownerIds].map((id) => `owner:${id}`),
          ].sort();
  let seen: Rendered[];
  let watching: Array<() => void>;
  beforeEach(async () => {
    vi.resetAllMocks();
    vi.mocked(prisma.$transaction).mockImplementation(async (fn) =>
      (fn as (tx: typeof prisma) => Promise<unknown>)(prisma),
    );
    vi.mocked(prisma.sandboxHost.findMany).mockResolvedValue([]);
    const waiters = await import("./operation-waiters.js");
    seen = [];
    waiters.bindOperationChangeFanout((change) => {
      seen.push(render(change));
    });
    watching = [];
  });
  afterEach(async () => {
    for (const dispose of watching) dispose();
    (await import("./operation-waiters.js")).bindOperationChangeFanout(null);
  });

  it.each([
    [
      "sandboxOperation",
      "update",
      { where: { id: "op_1" }, data: { state: "RUNNING" } },
      ["op:op_1"],
    ],
    [
      "sandboxOperation",
      "updateMany",
      { where: { id: { in: ["op_2", "op_1"] }, userId: "u" }, data: {} },
      ["op:op_1", "op:op_2"],
    ],
    // No id: only that owner's waiters re-read.
    [
      "sandboxOperation",
      "updateMany",
      { where: { sandboxId: "s1", userId: "u" }, data: {} },
      ["owner:u"],
    ],
    ["sandboxOperation", "deleteMany", { where: { userId: "u" } }, ["owner:u"]],
    ["sandboxOperation", "upsert", { where: { id: "op_3" } }, ["op:op_3"]],
    [
      "sandboxOperationResult",
      "update",
      { where: { operationId: "op_4" }, data: { reservationState: "PUBLISHED" } },
      ["op:op_4"],
    ],
    ["sandboxOperationResult", "create", { data: { operationId: "op_5" } }, ["op:op_5"]],
    // zeroReservedResultHolds: AND [caller filter, owner filter].
    [
      "sandboxOperationResult",
      "updateMany",
      {
        where: {
          AND: [{ operationId: { in: ["op_6"] } }, { userId: "u", reservationState: "RESERVED" }],
        },
        data: {},
      },
      ["op:op_6"],
    ],
    [
      "sandboxOperationResult",
      "updateMany",
      { where: { AND: [{ sandboxId: { in: ["s1"] } }, { userId: "u" }] }, data: {} },
      ["owner:u"],
    ],
    // Neither an id nor an owner: the only remaining "all".
    ["sandboxOperation", "updateMany", { where: { sandboxId: "s1" }, data: {} }, "all"],
  ] as const)("%s.%s %j wakes %j", async (model, method, args, expected) => {
    const { operationWrite } = await import("./outbox.js");
    expect(render(operationWrite(model, method, args))).toEqual(expected);
  });

  it.each([
    ["sandboxOperation", "create", { data: { id: "op_1" } }],
    ["sandboxOperation", "findFirst", { where: { id: "op_1" } }],
    ["sandbox", "update", { where: { id: "s1" }, data: {} }],
  ] as const)("%s.%s is not an operation change", async (model, method, args) => {
    const { operationWrite } = await import("./outbox.js");
    expect(operationWrite(model, method, args)).toBeNull();
  });

  it("announces after the transaction resolved, merged, once", async () => {
    vi.mocked(prisma.sandboxOperation.updateMany).mockResolvedValue({ count: 1 });
    vi.mocked(prisma.sandboxOperationResult.update).mockResolvedValue({} as never);
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandboxOperation.updateMany({ where: { id: "op_1" }, data: { state: "SUCCEEDED" } });
      expect(seen).toEqual([]); // not before commit
      await tx.sandboxOperationResult.update({
        where: { operationId: "op_2" },
        data: { reservationState: "PUBLISHED" },
      });
      await tx.sandboxOperation.updateMany({ where: { userId: "u" }, data: {} });
    });
    expect(seen).toEqual([["op:op_1", "op:op_2", "owner:u"]]);
  });

  it("a held long-poll wakes on the commit", async () => {
    const { watchOperation } = await import("./operation-waiters.js");
    const watch = watchOperation("op_1", "u");
    watching.push(watch.dispose);
    vi.mocked(prisma.sandboxOperation.update).mockResolvedValue({} as never);
    await sandboxOutboxTransaction((tx) =>
      tx.sandboxOperation.update({ where: { id: "op_1" }, data: { state: "RUNNING" } }),
    );
    await expect(watch.wait(1_000)).resolves.toBe("changed");
  });

  it("a zero-row write and a rolled-back transaction announce nothing", async () => {
    vi.mocked(prisma.sandboxOperation.updateMany).mockResolvedValue({ count: 0 });
    await sandboxOutboxTransaction(async (tx) => {
      await tx.sandboxOperation.updateMany({ where: { id: "op_1" }, data: { state: "RUNNING" } });
    });
    vi.mocked(prisma.sandboxOperation.updateMany).mockResolvedValue({ count: 1 });
    await expect(
      sandboxOutboxTransaction(async (tx) => {
        await tx.sandboxOperation.updateMany({ where: { id: "op_1" }, data: { state: "RUNNING" } });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(seen).toEqual([]);
  });
});

it("outbox events require an explicit operation identity", () => {
  expect(outboxOperationIdOf({ operationId: "operation-1" })).toBe("operation-1");
  expect(() => outboxOperationIdOf({})).toThrow("Missing outbox operation identity.");
  expect(() => outboxOperationIdOf({ operationId: 1 })).toThrow(
    "Missing outbox operation identity.",
  );
});
