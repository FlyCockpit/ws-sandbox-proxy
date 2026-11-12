import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedDispatchEvent,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import type { CaptureChunk } from "./captures.js";
import type { TransferLimits } from "./limits.js";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
/** Spool-file fault/hold points: one-shot, reset after each test. */
const fault = vi.hoisted(() => ({
  enospc: false,
  holdSync: undefined as (() => Promise<void>) | undefined,
  holdRead: undefined as (() => Promise<void>) | undefined,
}));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof fs>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof fs.open>) => {
      const file = await actual.open(...args);
      if (!String(args[0]).endsWith(".spool")) return file;
      return new Proxy(file, {
        get(target, key) {
          const value = Reflect.get(target, key);
          if (key === "write" && fault.enospc)
            return async (bytes: Uint8Array, offset: number, _length: number, position: number) => {
              fault.enospc = false;
              // A partial write lands before the device reports it is full.
              await target.write(bytes, offset, 1, position);
              throw Object.assign(new Error("injected disk full"), { code: "ENOSPC" });
            };
          if (key === "sync" && fault.holdSync)
            return async () => {
              const hold = fault.holdSync;
              fault.holdSync = undefined;
              await target.sync();
              await hold?.();
            };
          if (key === "read" && fault.holdRead)
            return async (...read: Parameters<typeof target.read>) => {
              const hold = fault.holdRead;
              fault.holdRead = undefined;
              const result = await target.read(...read);
              await hold?.();
              return result;
            };
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
});
const db = await pgTestDatabase();
const { TransferStore } = await import("./store.js");
const { CaptureRefused } = await import("./captures.js");
const limits: TransferLimits = {
  maxBytes: CHUNK * 3,
  diskBytes: CHUNK * 12,
  ownerActive: 4,
  globalActive: 16,
  idleMs: 900_000,
  absoluteMs: 3_600_000,
};
const stores: InstanceType<typeof TransferStore>[] = [];
const roots: string[] = [];
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const gate = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
async function start(config = limits, root?: string) {
  root ??= await fs.mkdtemp(join(tmpdir(), "wssp-c28-"));
  if (!roots.includes(root)) roots.push(root);
  const store = new TransferStore(root, config);
  stores.push(store);
  await store.start();
  return { store, root };
}
async function seed() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "host", label: "host" },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "image",
      label: "image",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
    },
  });
  const principal: Principal = { kind: "session", ownerId: id };
  const owner = {
    userId: id,
    keyId: null,
    sandboxId: sandbox.id,
    generation: sandbox.generation,
    guestPath: "/home/user/out.bin",
  };
  return { principal, owner, sandbox };
}
type Store = InstanceType<typeof TransferStore>;
/** Admission in its own transaction (the relay's fenced one), then publish. */
async function capture(
  store: Store,
  owner: Awaited<ReturnType<typeof seed>>["owner"],
  chunk: CaptureChunk,
) {
  const publish = await db.prisma.$transaction((tx) => store.admitCapture(tx, owner, chunk));
  await publish?.();
  return publish;
}
const chunk = (operationId: string, sequence: number, body: Uint8Array, ended: boolean) => ({
  operationId,
  attempt: 1,
  sequence,
  offset: sequence * CHUNK,
  body,
  ended,
});
afterEach(async () => {
  fault.enospc = false;
  fault.holdSync = undefined;
  fault.holdRead = undefined;
  for (const store of stores.splice(0)) await store.close();
  await db.inspect.sandboxTransfer.updateMany({
    where: { reservationHeld: true },
    data: { state: "EXPIRED", reservationHeld: false },
  });
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});
afterAll(() => db.close());

it("rejects capture admission without a transport host before inserting a transfer", async () => {
  const s = await seed(),
    f = await start();
  await db.inspect.sandbox.update({
    where: { id: s.sandbox.id },
    data: { sandboxHostId: null, diskReservationHeld: false },
  });
  await expect(
    capture(f.store, s.owner, chunk("unbound", 0, new Uint8Array(), true)),
  ).rejects.toMatchObject({ code: "protocol_error" });
  expect(await db.inspect.sandboxTransfer.count({ where: { sandboxId: s.sandbox.id } })).toBe(0);
});

it("captures binary, empty and partial final relay chunks as sealed store transfers", async () => {
  const s = await seed(),
    f = await start();
  const first = Uint8Array.from({ length: CHUNK }, (_, i) => (i * 7) % 256);
  const tail = new Uint8Array([0, 255, 0, 13, 10]);
  await capture(f.store, s.owner, chunk("op-bin", 0, first, false));
  expect(await f.store.completedCapture("op-bin", 1)).toBeUndefined();
  await capture(f.store, s.owner, chunk("op-bin", 1, tail, true));
  const whole = Buffer.concat([first, tail]);
  const done = await f.store.completedCapture("op-bin", 1);
  expect(done).toEqual({ transferId: expect.any(String), size: whole.length, sha256: sha(whole) });
  const row = await db.inspect.sandboxTransfer.findUniqueOrThrow({
    where: { id: done!.transferId },
  });
  // Persistent metadata; the conservative reservation shrank to the real size.
  expect(row).toMatchObject({
    direction: "DOWNLOAD",
    state: "SEALED",
    acceptedHostId: s.sandbox.sandboxHostId,
    totalBytes: BigInt(whole.length),
    receivedBytes: BigInt(whole.length),
    reservationHeld: true,
    guestPath: "/home/user/out.bin",
    operationId: "op-bin",
    operationAttempt: 1,
    sha256: sha(whole),
  });
  expect(row.idempotencyKey).toMatch(/^relay:/);
  expect(await db.inspect.sandboxTransferChunk.count({ where: { transferId: row.id } })).toBe(2);
  // Immutable ranged bytes through the ordinary owner-authorized reader.
  expect(await f.store.read(s.principal, row.id, CHUNK - 2, 5)).toEqual(
    Buffer.from(whole.subarray(CHUNK - 2, CHUNK + 3)),
  );
  await capture(f.store, s.owner, chunk("op-empty", 0, new Uint8Array(), true));
  expect(await f.store.completedCapture("op-empty", 1)).toMatchObject({
    size: 0,
    sha256: sha(new Uint8Array()),
  });
  // No host path: the spool name is the generated transfer id.
  expect((await fs.readdir(f.root)).sort()).toEqual(
    [
      `${row.id}.spool`,
      `${(await f.store.completedCapture("op-empty", 1))!.transferId}.spool`,
    ].sort(),
  );
});

it("replays identical chunks, refuses conflicts gaps and sizes, and shares the store quota", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 2 });
  const full = new Uint8Array(CHUNK).fill(1);
  await capture(f.store, s.owner, chunk("op-a", 0, full, false));
  // Identical replay of a committed chunk: no disk step, re-ACKed.
  expect(await capture(f.store, s.owner, chunk("op-a", 0, full, false))).toBeNull();
  for (const [bad, code] of [
    [chunk("op-a", 0, new Uint8Array(CHUNK).fill(2), false), "protocol_error"],
    [chunk("op-a", 2, new Uint8Array([1]), true), "protocol_error"],
    [chunk("op-a", 1, new Uint8Array(7), false), "protocol_error"],
    [{ ...chunk("op-a", 1, new Uint8Array([1]), true), offset: 5 }, "protocol_error"],
    [chunk("op-new", 1, new Uint8Array([1]), true), "protocol_error"],
    [chunk("op-a", 3, new Uint8Array([1]), true), "request_too_large"],
  ] as const)
    await expect(capture(f.store, s.owner, bad)).rejects.toSatisfy(
      (error) => error instanceof CaptureRefused && error.code === code,
    );
  // A user transfer session and a capture draw on the same owner quota.
  await f.store.create(s.principal, {
    sandboxId: s.sandbox.id,
    direction: "UPLOAD",
    guestPath: "/tmp/in",
    totalBytes: 1,
    idempotencyKey: randomUUID(),
  });
  await expect(
    capture(f.store, s.owner, chunk("op-b", 0, new Uint8Array([1]), true)),
  ).rejects.toMatchObject({ code: "transfer_quota" });
  expect(await db.inspect.sandboxTransfer.count({ where: { operationId: "op-b" } })).toBe(0);
  // Discard releases the capture's reservation exactly once.
  await f.store.discardCapture("op-a", 1);
  await f.store.discardCapture("op-a", 1);
  expect(
    await db.inspect.sandboxTransfer.findFirstOrThrow({ where: { operationId: "op-a" } }),
  ).toMatchObject({ state: "FAILED", reservationHeld: false });
  await capture(f.store, s.owner, chunk("op-b", 0, new Uint8Array([1]), true));
  expect(await f.store.completedCapture("op-b", 1)).toMatchObject({ size: 1 });
});

it("disk-full partial write fails the capture and releases its reservation", async () => {
  const s = await seed(),
    f = await start();
  fault.enospc = true;
  await expect(
    capture(f.store, s.owner, chunk("op-full", 0, new Uint8Array([1, 2, 3]), true)),
  ).rejects.toMatchObject({ code: "ENOSPC" });
  const row = await db.inspect.sandboxTransfer.findFirstOrThrow({
    where: { operationId: "op-full" },
  });
  expect(row).toMatchObject({ state: "FAILED", reservationHeld: false, receivedBytes: 0n });
  expect(await fs.readdir(f.root)).toEqual([]);
  // A host retry of the same frame is refused, so the operation fails.
  await expect(
    capture(f.store, s.owner, chunk("op-full", 0, new Uint8Array([1, 2, 3]), true)),
  ).rejects.toMatchObject({ code: "transfer_expired" });
});

it("expiry never serves a concurrent range reader past its deadline and cleans up after it", async () => {
  const s = await seed(),
    f = await start();
  await capture(f.store, s.owner, chunk("op-exp", 0, new Uint8Array([9, 8, 7]), true));
  const { transferId } = (await f.store.completedCapture("op-exp", 1))!;
  const reading = gate(),
    release = gate();
  fault.holdRead = async () => {
    reading.resolve();
    await release.promise;
  };
  const read = f.store.read(s.principal, transferId, 0, 3);
  const refused = expect(read).rejects.toMatchObject({ status: 410 });
  await reading.promise;
  await db.inspect.sandboxTransfer.update({
    where: { id: transferId },
    data: { idleExpiresAt: new Date(0) },
  });
  // The sweep does not unlink under an active reader...
  await f.store.sweep();
  expect(await fs.readdir(f.root)).toEqual([`${transferId}.spool`]);
  release.resolve();
  // ...and the reader rechecks the deadline before returning bytes.
  await refused;
  await f.store.sweep();
  expect(await fs.readdir(f.root)).toEqual([]);
  expect(await f.store.completedCapture("op-exp", 1)).toBeUndefined();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: transferId } }),
  ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
});

it("shutdown drains in-flight capture IO, refuses new captures and restart recovers sealed content", async () => {
  const s = await seed(),
    f = await start();
  const syncing = gate(),
    release = gate();
  fault.holdSync = async () => {
    syncing.resolve();
    await release.promise;
  };
  const writing = capture(f.store, s.owner, chunk("op-drain", 0, new Uint8Array([4, 5]), true));
  await syncing.promise;
  let closed = false;
  const closing = f.store.close().then(() => {
    closed = true;
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(closed).toBe(false);
  release.resolve();
  await writing;
  await closing;
  await expect(
    capture(f.store, s.owner, chunk("op-late", 0, new Uint8Array([1]), true)),
  ).rejects.toMatchObject({ status: 503 });
  const reopened = await start(limits, f.root);
  const done = await reopened.store.completedCapture("op-drain", 1);
  expect(done).toMatchObject({ size: 2, sha256: sha(new Uint8Array([4, 5])) });
  expect(await reopened.store.read(s.principal, done!.transferId, 0, 2)).toEqual(
    Buffer.from([4, 5]),
  );
});

it("restart settles an unsealed capture immediately and keeps sealed content", async () => {
  const s = await seed(),
    f = await start();
  await capture(f.store, s.owner, chunk("op-open", 0, new Uint8Array(CHUNK).fill(3), false));
  await capture(f.store, s.owner, chunk("op-sealed", 0, new Uint8Array([9, 8]), true));
  const open = await db.inspect.sandboxTransfer.findUniqueOrThrow({
    where: { operationId_operationAttempt: { operationId: "op-open", operationAttempt: 1 } },
  });
  expect(open).toMatchObject({ state: "OPEN", reservationHeld: true });
  await f.store.close();
  // The idle deadline is far away: only restart recovery can settle it now.
  const reopened = await start(limits, f.root);
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: open.id } }),
  ).toMatchObject({ state: "FAILED", reservationHeld: false });
  await expect(fs.access(join(f.root, `${open.id}.spool`))).rejects.toMatchObject({
    code: "ENOENT",
  });
  const sealed = await reopened.store.completedCapture("op-sealed", 1);
  expect(sealed).toMatchObject({ size: 2, sha256: sha(new Uint8Array([9, 8])) });
  expect(await reopened.store.read(s.principal, sealed!.transferId, 0, 2)).toEqual(
    Buffer.from([9, 8]),
  );
});

it("sweep releases transfers whose sandbox generation ended or was deleted", async () => {
  const s = await seed(),
    f = await start();
  await capture(f.store, s.owner, chunk("op-gen", 0, new Uint8Array([1]), true));
  await capture(f.store, s.owner, chunk("op-keep", 0, new Uint8Array([2]), true));
  const kept = await f.store.completedCapture("op-keep", 1);
  await f.store.sweep();
  // Same generation, READY: nothing is released.
  expect(
    await db.inspect.sandboxTransfer.count({
      where: { sandboxId: s.sandbox.id, reservationHeld: true },
    }),
  ).toBe(2);
  await db.inspect.sandbox.update({
    where: { id: s.sandbox.id },
    data: { generation: s.sandbox.generation + 1, state: "DELETED" },
  });
  await f.store.sweep();
  const rows = await db.inspect.sandboxTransfer.findMany({ where: { sandboxId: s.sandbox.id } });
  expect(rows.map((row) => [row.state, row.reservationHeld])).toEqual([
    ["EXPIRED", false],
    ["EXPIRED", false],
  ]);
  await expect(f.store.read(s.principal, kept!.transferId, 0, 1)).rejects.toMatchObject({
    status: 410,
  });
});

it("serves parallel reads of one sealed capture while exclusive tasks still conflict", async () => {
  const s = await seed(),
    f = await start();
  const body = Uint8Array.from({ length: CHUNK }, (_, i) => i % 251);
  await capture(f.store, s.owner, chunk("op-par", 0, body, true));
  const done = await f.store.completedCapture("op-par", 1);
  const reading = gate(),
    release = gate();
  fault.holdRead = async () => {
    reading.resolve();
    await release.promise;
  };
  const first = f.store.read(s.principal, done!.transferId, 0, 16);
  await reading.promise;
  // A second reader of the same immutable bytes proceeds while the first is held.
  expect(await f.store.read(s.principal, done!.transferId, 16, 16)).toEqual(
    Buffer.from(body.subarray(16, 32)),
  );
  // Status polling is permitless (C29): it answers while a reader holds its
  // shared permit. Exclusive work (abort, cleanup) still never overlaps one.
  expect((await f.store.status(s.principal, done!.transferId)).state).toBe("SEALED");
  await expect(f.store.abort(s.principal, done!.transferId)).rejects.toMatchObject({
    status: 409,
  });
  release.resolve();
  expect(await first).toEqual(Buffer.from(body.subarray(0, 16)));
  expect((await f.store.status(s.principal, done!.transferId)).state).toBe("SEALED");
});

it("3A refused capture preclaims outbox before transfer", async () => {
  const s = await seed(),
    f = await start();
  const { bindRelayCaptures } = await import("./captures.js");
  bindRelayCaptures(f.store);
  const { acceptFencedBinaryChunk } = await import("../sandbox-relay/operation-handlers.js");
  await db.inspect.sandboxHost.update({
    where: { id: s.sandbox.sandboxHostId! },
    data: { connectionEpoch: 1 },
  });
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: s.owner.userId,
      sandboxId: s.sandbox.id,
      generation: 1,
      kind: "GET_FILE",
      state: "RUNNING",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      dispatchAttempt: 1,
      dispatchedHostId: s.sandbox.sandboxHostId,
      dispatchedConnectionEpoch: 1,
    },
  });
  const event = await seedDispatchEvent(db.inspect, {
    data: {
      userId: s.owner.userId,
      aggregateId: s.sandbox.id,
      aggregateType: "sandbox",
      eventType: "sandbox.file_get_requested",
      payload: { operationId: op.id, path: "/tmp/out" },
    },
  });
  const input = {
    sender: { userId: s.owner.userId, hostId: s.sandbox.sandboxHostId!, connectionEpoch: 1 },
    operationId: op.id,
    generation: 1,
    attempt: 1,
    sequence: 0,
    offset: 0,
    ended: false,
    body: new Uint8Array(CHUNK).fill(1),
  };
  expect(await acceptFencedBinaryChunk(input)).toBe(true);
  const transfer = await db.inspect.sandboxTransfer.findFirstOrThrow({
    where: { operationId: op.id },
  });
  const held = db.pauseAt("outbox-holder", { before: "$transaction.commit" });
  const holder = db.run("outbox-holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_dispatch_outbox WHERE id = ${event.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const refusing = db.run("capture", () =>
    acceptFencedBinaryChunk({ ...input, body: new Uint8Array(CHUNK).fill(2) }),
  );
  try {
    expect((await db.waitUntilBlocked("capture", { by: "outbox-holder" })).query).toMatch(
      /FROM sandbox_dispatch_outbox.*ORDER BY id FOR UPDATE/s,
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${transfer.id} FOR UPDATE NOWAIT`;
    });
  } finally {
    held.release();
  }
  await holder;
  expect(await refusing).toBe(true);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } })).state,
  ).toBe("FAILED");
  expect(
    (await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } })).processedAt,
  ).not.toBeNull();
});
