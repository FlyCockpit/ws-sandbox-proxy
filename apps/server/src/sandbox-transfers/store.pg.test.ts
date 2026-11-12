import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import type { TransferLimits } from "./limits.js";

vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
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
const fault = vi.hoisted(() => ({
  operation: "",
  partial: false,
  directory: false,
  short: false,
  hold: undefined as (() => Promise<void>) | undefined,
  holdRead: undefined as (() => Promise<void>) | undefined,
}));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof fs>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof fs.open>) => {
      const file = await actual.open(...args);
      if (!String(args[0]).endsWith(".spool") && !fault.directory) return file;
      return new Proxy(file, {
        get(target, key) {
          const value = Reflect.get(target, key);
          if (key === "sync" && fault.hold)
            return async () => {
              const hold = fault.hold;
              fault.hold = undefined;
              await target.sync();
              await hold?.();
            };
          if (key === "read" && fault.holdRead)
            return async (bytes: Uint8Array, offset: number, length: number, position: number) => {
              const hold = fault.holdRead;
              fault.holdRead = undefined;
              await hold?.();
              return target.read(bytes, offset, length, position);
            };
          if (key === "write" && fault.short)
            return async (bytes: Uint8Array, offset: number, _length: number, position: number) => {
              fault.short = false;
              return target.write(bytes, offset, 1, position);
            };
          if (key === fault.operation)
            return async () => {
              fault.operation = "";
              if (fault.partial && key === "write") await target.write(Buffer.from([99]), 0, 1, 0);
              throw Object.assign(new Error("injected storage failure"), { code: "ENOSPC" });
            };
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
});
const db = await pgTestDatabase();
const { withAuthorityChange } = await import("@wssp/db/authority");
const { TransferStore } = await import("./store.js");
const { assertHostDeletable } = await import("@wssp/api/sandbox/host-admission");
const { ownerKeyTransaction } = await import("@wssp/api/sandbox/operation-transaction");
const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
const limits: TransferLimits = {
  maxBytes: CHUNK * 2,
  diskBytes: CHUNK * 4,
  ownerActive: 4,
  globalActive: 16,
  idleMs: 900_000,
  absoluteMs: 3_600_000,
  // Short delivery grace so retirement is observable; TQ-F1 tests set their own.
  deliveredGraceMs: 50,
};
const stores: InstanceType<typeof TransferStore>[] = [];
const roots: string[] = [];
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
async function start(config = limits, root?: string) {
  root ??= await fs.mkdtemp(join(tmpdir(), "wssp-c27-"));
  if (!roots.includes(root)) roots.push(root);
  const store = new TransferStore(root, config);
  stores.push(store);
  await store.start();
  return { store, root, path: (id: string) => join(root, `${id}.spool`) };
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
  const input = (totalBytes = 1, idempotencyKey = randomUUID()) => ({
    sandboxId: sandbox.id,
    direction: "UPLOAD" as const,
    guestPath: "/tmp/upload",
    totalBytes,
    idempotencyKey,
  });
  const sdk = async (scopes = ["files:read", "files:write"]): Promise<Principal> => {
    const key = await db.inspect.sdkKey.create({
      data: {
        userId: id,
        name: "key",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        resourceMode: "ALL_OWNED",
        scopes,
      },
    });
    return {
      kind: "sdkKey",
      keyId: key.id,
      ownerId: id,
      expiresAt: null,
      resourceMode: "ALL_OWNED",
      scopes: new Set(["files:read", "files:write"]),
      allowedHostIds: "allOwned",
      allowedRevisionIds: "allOwned",
      allowedPoolIds: "allUsable",
    };
  };
  return { principal, sandbox, host, input, sdk };
}
afterEach(async () => {
  fault.operation = "";
  fault.partial = false;
  fault.directory = false;
  fault.short = false;
  fault.hold = undefined;
  fault.holdRead = undefined;
  for (const store of stores.splice(0)) await store.close();
  // This test file owns its disposable database and filesystem roots.
  await db.inspect.sandboxTransfer.updateMany({
    where: { reservationHeld: true },
    data: { state: "EXPIRED", reservationHeld: false },
  });
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});
afterAll(() => db.close());

it("rejects upload admission without a transport host before inserting a transfer", async () => {
  const s = await seed(),
    f = await start();
  await db.inspect.sandbox.update({
    where: { id: s.sandbox.id },
    data: { sandboxHostId: null, diskReservationHeld: false },
  });
  await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(
    f.store.importSealed(s.principal, {
      sandboxId: s.sandbox.id,
      generation: s.sandbox.generation,
      idempotencyKey: "tb:b1:import:0:0",
      guestPath: "/var/tmp/wssp-build/b1/context.tar",
      sha256: hash(Buffer.from([1])),
      totalBytes: 1,
      chunks: [{ offset: 0, length: 1, digest: hash(Buffer.from([1])) }],
      source: { root: f.root, name: "absent.context" },
      onSealed: async () => {},
    }),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  expect(await db.inspect.sandboxTransfer.count({ where: { sandboxId: s.sandbox.id } })).toBe(0);
});

it("serializes transfer admission with account deletion without losing its reservation", async () => {
  const s = await seed(),
    f = await start(),
    input = s.input();
  const gate = db.pauseAt("admit", { after: "sandboxTransfer.create" });
  const creating = db.run("admit", () => f.store.create(s.principal, input));
  // Beginning account deletion fences outstanding responses even if blockers
  // ultimately refuse deletion; the durable receipt must still be recoverable.
  const fenced = expect(creating).rejects.toMatchObject({ status: 403 });
  await gate.waitReached();
  const deleting = db.run("delete", () => requestAccountDeletion(s.principal.ownerId));
  const refused = expect(deleting).rejects.toMatchObject({
    kinds: expect.arrayContaining(["transfers"]),
  });
  try {
    expect((await db.waitUntilBlocked("delete", { by: "admit" })).query).toContain("FOR UPDATE");
  } finally {
    gate.release();
  }
  await refused;
  await fenced;
  const replay = await f.store.create(s.principal, input);
  expect(replay.state).toBe("OPEN");
  expect(await fs.readdir(f.root)).toEqual([`${replay.id}.spool`]);
  expect(
    await db.inspect.sandboxTransfer.count({
      where: { userId: s.principal.ownerId, reservationHeld: true },
    }),
  ).toBe(1);
});

it("reauthorizes after reading spool bytes before returning them", async () => {
  const s = await seed(),
    actor = await s.sdk(["files:read"]),
    f = await start();
  const row = await f.store.create(actor, { ...s.input(), direction: "DOWNLOAD" });
  const bytes = Buffer.from([7]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  expect(await f.store.read(actor, row.id, 0, 1)).toEqual(bytes);
  const gate = db.pauseAt("read", { before: 'sql:SELECT id FROM "user" WHERE id = ? FOR SHARE' });
  const reading = db.run("read", () => f.store.read(actor, row.id, 0, 1));
  const denied = expect(reading).rejects.toMatchObject({ status: 403 });
  await gate.waitReached();
  try {
    if (actor.kind !== "sdkKey") throw new Error("fixture");
    await db.inspect.sdkKey.update({ where: { id: actor.keyId }, data: { revokedAt: new Date() } });
  } finally {
    gate.release();
  }
  await denied;
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).state,
  ).toBe("SEALED");
});

it("rejects caps and unknown lengths before allocating and serializes exact disk reservations", async () => {
  const s = await seed(),
    other = await seed(),
    f = await start({ ...limits, diskBytes: 3 });
  await expect(f.store.create(s.principal, s.input(limits.maxBytes + 1))).rejects.toMatchObject({
    status: 413,
  });
  await expect(
    f.store.create(s.principal, { ...s.input(), totalBytes: undefined } as never),
  ).rejects.toThrow();
  expect(await fs.readdir(f.root)).toEqual([]);
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: s.principal.ownerId } })).toBe(
    0,
  );
  const gate = db.pauseAt("first", { after: "sandboxTransfer.aggregate" });
  const first = db.run("first", () => f.store.create(s.principal, s.input(2)));
  await gate.waitReached();
  const second = db.run("second", () => f.store.create(other.principal, other.input(2)));
  const rejected = expect(second).rejects.toMatchObject({ status: 429 });
  expect((await db.waitUntilBlocked("second", { by: "first" })).query).toContain(
    "pg_advisory_xact_lock",
  );
  gate.release();
  const row = await first;
  await rejected;
  expect(await fs.readdir(f.root)).toEqual([`${row.id}.spool`]);
  await f.store.create(other.principal, other.input(1));
  expect(
    (
      await db.inspect.sandboxTransfer.aggregate({
        where: { reservationHeld: true },
        _sum: { totalBytes: true },
      })
    )._sum.totalBytes,
  ).toBe(3n);
});

it("enforces owner and global session counts including zero-byte sessions and releases once", async () => {
  const s = await seed(),
    other = await seed(),
    f = await start({ ...limits, ownerActive: 1, globalActive: 2 });
  const one = await f.store.create(s.principal, s.input(0));
  await expect(f.store.create(s.principal, s.input(0))).rejects.toMatchObject({ status: 429 });
  const two = await f.store.create(other.principal, other.input(0));
  const third = await seed();
  await expect(f.store.create(third.principal, third.input(0))).rejects.toMatchObject({
    status: 429,
  });
  await f.store.seal(s.principal, one.id);
  expect(await f.store.read(s.principal, one.id, 0, 0)).toEqual(Buffer.alloc(0));
  await f.store.abort(s.principal, one.id);
  await f.store.abort(s.principal, one.id);
  expect(await db.inspect.sandboxTransfer.count({ where: { reservationHeld: true } })).toBe(1);
  await f.store.create(third.principal, third.input(0));
  expect((await f.store.status(other.principal, two.id)).state).toBe("OPEN");
});

it("accepts fixed chunks and identical retries but rejects changed bytes gaps and digest mismatches", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input(CHUNK + 3));
  const body = Buffer.alloc(CHUNK, 71),
    tail = Buffer.from([0, 255, 4]);
  await expect(f.store.write(s.principal, row.id, CHUNK, tail, hash(tail))).rejects.toMatchObject({
    status: 409,
  });
  await expect(f.store.write(s.principal, row.id, 0, body, "wrong")).rejects.toMatchObject({
    status: 400,
  });
  await expect(f.store.write(s.principal, row.id, 1, body, hash(body))).rejects.toMatchObject({
    status: 400,
  });
  await f.store.write(s.principal, row.id, 0, body, hash(body));
  await f.store.write(s.principal, row.id, 0, body, hash(body));
  const changed = Buffer.alloc(CHUNK, 72);
  await expect(f.store.write(s.principal, row.id, 0, changed, hash(changed))).rejects.toMatchObject(
    { status: 409 },
  );
  await expect(f.store.seal(s.principal, row.id)).rejects.toMatchObject({ status: 409 });
  // The HTTP route passes no digest: the store hashes its own copy.
  await f.store.write(s.principal, row.id, CHUNK, tail);
  await f.store.seal(s.principal, row.id);
  await f.store.write(s.principal, row.id, CHUNK, tail, hash(tail));
  expect(await f.store.read(s.principal, row.id, CHUNK - 1, 4)).toEqual(
    Buffer.from([71, 0, 255, 4]),
  );
  expect((await fs.stat(f.path(row.id))).size).toBe(CHUNK + 3);
  expect(await db.inspect.sandboxTransferChunk.count({ where: { transferId: row.id } })).toBe(2);
});

it("binds every entry to owner key sandbox generation and current scopes including replay", async () => {
  const s = await seed(),
    other = await seed(),
    f = await start();
  const actor = await s.sdk(),
    sibling = await s.sdk(),
    input = s.input();
  const row = await f.store.create(actor, input);
  expect((await f.store.create(actor, input)).id).toBe(row.id);
  // This type inventory must grow whenever the store gains another caller-facing
  // entry point; every such entry executes the same cross-owner denial matrix.
  // Relay capture entries take no Principal: their authority is the fenced relay
  // transaction (H -> S -> O), covered by relay-captures.pg.test.ts.
  const foreignCalls: Record<
    Exclude<
      keyof InstanceType<typeof TransferStore>,
      | "start"
      | "close"
      | "sweep"
      | "admitCapture"
      | "completedCapture"
      | "discardCapture"
      | "uploadSource"
    >,
    () => Promise<unknown>
  > = {
    create: () => f.store.create(other.principal, input),
    status: () => f.store.status(other.principal, row.id),
    abort: () => f.store.abort(other.principal, row.id),
    write: () =>
      f.store.write(other.principal, row.id, 0, Buffer.from([1]), hash(Buffer.from([1]))),
    read: () => f.store.read(other.principal, row.id, 0, 1),
    seal: () => f.store.seal(other.principal, row.id),
    commit: () => f.store.commit(other.principal, row.id, "commit", hash(Buffer.from([1]))),
    // Operation-addressed; its capture matrix is in download-routes.pg.test.ts.
    downloadSource: () => f.store.downloadSource(other.principal, row.id),
    // Build-context adoption (template-builds §3.7): authorized before any IO.
    importSealed: () =>
      f.store.importSealed(other.principal, {
        sandboxId: input.sandboxId,
        generation: 1,
        idempotencyKey: "tb:b1:import:0:0",
        guestPath: "/var/tmp/wssp-build/b1/context.tar",
        sha256: hash(Buffer.from([1])),
        totalBytes: 1,
        chunks: [{ offset: 0, length: 1, digest: hash(Buffer.from([1])) }],
        source: { root: f.root, name: "absent.context" },
        onSealed: async () => {},
      }),
  };
  for (const call of Object.values(foreignCalls))
    await expect(call()).rejects.toMatchObject({ status: 404 });
  for (const wrong of [s.principal, sibling]) {
    await expect(f.store.status(wrong, row.id)).rejects.toMatchObject({ status: 404 });
    await expect(f.store.abort(wrong, row.id)).rejects.toMatchObject({ status: 404 });
    await expect(
      f.store.write(wrong, row.id, 0, Buffer.from([1]), hash(Buffer.from([1]))),
    ).rejects.toMatchObject({ status: 404 });
    await expect(f.store.read(wrong, row.id, 0, 1)).rejects.toMatchObject({ status: 404 });
    await expect(f.store.seal(wrong, row.id)).rejects.toMatchObject({ status: 404 });
  }
  await expect(f.store.create(await s.sdk(["files:read"]), s.input())).rejects.toMatchObject({
    status: 403,
  });
  await expect(f.store.create(actor, { ...input, guestPath: "/changed" })).rejects.toMatchObject({
    status: 409,
  });
  await expect(
    ownerKeyTransaction(
      actor,
      input.idempotencyKey,
      async () => null,
      async () => "bypass",
    ),
  ).rejects.toMatchObject({ status: 409 });
  await db.inspect.sandbox.update({ where: { id: s.sandbox.id }, data: { generation: 2 } });
  await expect(
    f.store.write(actor, row.id, 0, Buffer.from([1]), hash(Buffer.from([1]))),
  ).rejects.toMatchObject({ status: 409 });
  expect((await f.store.create(actor, input)).generation).toBe(1);
  if (actor.kind !== "sdkKey") throw new Error("fixture");
  await db.inspect.sdkKey.update({ where: { id: actor.keyId }, data: { revokedAt: new Date() } });
  await expect(f.store.create(actor, input)).rejects.toMatchObject({ status: 403 });
  await expect(f.store.status(actor, row.id)).rejects.toMatchObject({ status: 403 });
});

it("rechecks authority after disk IO before committing chunk metadata", async () => {
  const s = await seed(),
    actor = await s.sdk(),
    f = await start();
  const row = await f.store.create(actor, s.input());
  const gate = db.pauseAt("write", { before: 'sql:SELECT id FROM "user" WHERE id = ? FOR SHARE' });
  const writing = db.run("write", () =>
    f.store.write(actor, row.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  );
  const denied = expect(writing).rejects.toMatchObject({ status: 403 });
  await gate.waitReached();
  if (actor.kind !== "sdkKey") throw new Error("fixture");
  await db.inspect.sdkKey.update({ where: { id: actor.keyId }, data: { revokedAt: new Date() } });
  gate.release();
  await denied;
  expect(await db.inspect.sandboxTransferChunk.count({ where: { transferId: row.id } })).toBe(0);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
  ).toBe(0n);
});

it.each(["write", "sync"])(
  "retires poisoned files after %s failure with no acknowledged bytes",
  async (operation) => {
    const s = await seed(),
      f = await start();
    const row = await f.store.create(s.principal, s.input(2));
    fault.operation = operation;
    fault.partial = true;
    await expect(
      f.store.write(s.principal, row.id, 0, Buffer.from([1, 2]), hash(Buffer.from([1, 2]))),
    ).rejects.toMatchObject({ status: 503 });
    expect(await fs.readdir(f.root)).toEqual([]);
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ receivedBytes: 0n, state: "FAILED", reservationHeld: false });
  },
);

it("preserves acknowledged spool content when recovery metadata is temporarily unavailable", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input());
  const bytes = Buffer.from([23]);
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  await f.store.close();
  const interrupted = new TransferStore(f.root, limits);
  stores.push(interrupted);
  const gate = db.pauseAt("recover", { before: "sandboxTransferChunk.findUnique" });
  const recovering = db.run("recover", () => interrupted.start());
  const unavailable = expect(recovering).rejects.toMatchObject({ status: 503 });
  await gate.waitReached();
  gate.fail(Object.assign(new Error("injected database unavailability"), { code: "P2024" }));
  await unavailable;
  expect(await fs.readFile(f.path(row.id))).toEqual(bytes);
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({
    state: "SEALED",
    reservationHeld: true,
    receivedBytes: 1n,
  });
  const recovered = await start(limits, f.root);
  expect(await recovered.store.read(s.principal, row.id, 0, 1)).toEqual(bytes);
});

it("recovers uncommitted tails and reservations and detects missing or corrupted acknowledged bytes", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input(CHUNK + 1));
  const bytes = Buffer.alloc(CHUNK, 21);
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.close();
  await fs.appendFile(f.path(row.id), Buffer.from([99]));
  const restarted = await start(limits, f.root);
  expect((await fs.stat(f.path(row.id))).size).toBe(CHUNK);
  expect((await restarted.store.status(s.principal, row.id)).receivedBytes).toBe(CHUNK);
  expect(
    (
      await db.inspect.sandboxTransfer.aggregate({
        where: { reservationHeld: true },
        _sum: { totalBytes: true },
      })
    )._sum.totalBytes,
  ).toBe(BigInt(CHUNK + 1));
  await restarted.store.write(s.principal, row.id, CHUNK, Buffer.from([7]), hash(Buffer.from([7])));
  await restarted.store.seal(s.principal, row.id);
  await restarted.store.close();
  await fs.writeFile(f.path(row.id), Buffer.alloc(CHUNK + 1, 4));
  const recovered = await start(limits, f.root);
  expect((await recovered.store.status(s.principal, row.id)).state).toBe("FAILED");
  expect(await fs.readdir(f.root)).toEqual([]);
  const missing = await recovered.store.create(s.principal, s.input());
  await recovered.store.close();
  await fs.unlink(f.path(missing.id));
  const again = await start(limits, f.root);
  expect((await again.store.status(s.principal, missing.id)).state).toBe("FAILED");
});

it("recovers durable allocation and cleanup intents and removes only canonical orphan names", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input()),
    cleanup = await f.store.create(s.principal, s.input());
  await f.store.close();
  await db.inspect.sandboxTransfer.update({ where: { id: row.id }, data: { state: "ALLOCATING" } });
  await db.inspect.sandboxTransfer.update({
    where: { id: cleanup.id },
    data: { state: "ABORTED" },
  });
  const orphan = randomUUID();
  await fs.writeFile(f.path(orphan), "orphan", { mode: 0o600 });
  const recovered = await start(limits, f.root);
  expect(await fs.readdir(f.root)).toEqual([]);
  expect((await recovered.store.status(s.principal, row.id)).state).toBe("EXPIRED");
  expect((await recovered.store.status(s.principal, cleanup.id)).state).toBe("ABORTED");
  expect(await db.inspect.sandboxTransfer.count({ where: { reservationHeld: true } })).toBe(0);
});

it("never follows request paths symlinks or hardlinks into server files", async () => {
  const s = await seed(),
    f = await start();
  for (const id of ["../../outside", "/etc/passwd", "x\0y"])
    await expect(f.store.status(s.principal, id)).rejects.toThrow();
  const outside = await fs.mkdtemp(join(tmpdir(), "wssp-c27-outside-"));
  roots.push(outside);
  const victim = join(outside, "victim");
  await fs.writeFile(victim, "untouched", { mode: 0o600 });
  const row = await f.store.create(s.principal, { ...s.input(), guestPath: victim });
  expect(await fs.readFile(victim, "utf8")).toBe("untouched");
  await fs.unlink(f.path(row.id));
  await fs.symlink(victim, f.path(row.id));
  await expect(
    f.store.write(s.principal, row.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  ).rejects.toMatchObject({ status: 503 });
  expect(await fs.readFile(victim, "utf8")).toBe("untouched");
  const hard = await f.store.create(s.principal, s.input());
  await fs.unlink(f.path(hard.id));
  await fs.link(victim, f.path(hard.id));
  await expect(
    f.store.write(s.principal, hard.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  ).rejects.toMatchObject({ status: 503 });
  expect(await fs.readFile(victim, "utf8")).toBe("untouched");
  const link = join(outside, "root");
  await fs.symlink(f.root, link);
  await expect(new TransferStore(link, limits).start()).rejects.toMatchObject({ status: 503 });
});

it("expires content at idle or absolute deadline but preserves receipts and active work", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input()),
    healthy = await f.store.create(s.principal, s.input());
  await db.inspect.sandboxTransfer.update({
    where: { id: row.id },
    data: { idleExpiresAt: new Date(0) },
  });
  await expect(
    f.store.write(s.principal, row.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  ).rejects.toMatchObject({ status: 410 });
  await f.store.sweep();
  await f.store.sweep();
  expect((await f.store.status(s.principal, row.id)).state).toBe("EXPIRED");
  expect((await f.store.status(s.principal, healthy.id)).state).toBe("OPEN");
  const gate = db.pauseAt("busy", { before: 'sql:SELECT id FROM "user" WHERE id = ? FOR SHARE' });
  const writing = db.run("busy", () =>
    f.store.write(s.principal, healthy.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  );
  const expired = expect(writing).rejects.toMatchObject({ status: 410 });
  await gate.waitReached();
  await db.inspect.sandboxTransfer.update({
    where: { id: healthy.id },
    data: { expiresAt: new Date(0) },
  });
  await f.store.sweep();
  expect(await fs.readdir(f.root)).toEqual([`${healthy.id}.spool`]);
  await expect(
    f.store.write(s.principal, healthy.id, 0, Buffer.from([3]), hash(Buffer.from([3]))),
  ).rejects.toMatchObject({ status: 409 });
  gate.release();
  await expired;
  await f.store.sweep();
  expect(await fs.readdir(f.root)).toEqual([]);
});

it("held transfers block host and account deletion until durable cleanup completes", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input());
  await db.inspect.sandbox.update({
    where: { id: s.sandbox.id },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
    },
  });
  // This fixture models completed VM/root cleanup; only the transfer remains.
  await db.inspect.sandboxHost.update({
    where: { id: s.host.id },
    data: { liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: s.host.id },
    data: { diskReservedGiB: 0 },
  });
  await expect(
    db.prisma.$transaction((tx) => assertHostDeletable(tx, s.host.id, s.principal.ownerId)),
  ).rejects.toMatchObject({ status: 409 });
  await expect(requestAccountDeletion(s.principal.ownerId)).rejects.toMatchObject({
    kinds: expect.arrayContaining(["transfers"]),
  });
  await db.inspect.sandboxHost.update({
    where: { id: s.host.id },
    data: { deletionRequestedAt: new Date() },
  });
  await f.store.abort(s.principal, row.id);
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: s.host.id } })).toBeNull();
  await expect(
    db.prisma.$transaction((tx) => assertHostDeletable(tx, s.host.id, s.principal.ownerId)),
  ).resolves.toBeUndefined();
});

it("bounds coalesced retries and drains their final authorization before shutdown", async () => {
  const s = await seed(),
    f = await start({ ...limits, globalActive: 2 }),
    input = s.input();
  const allocation = db.pauseAt("allocate", { after: "sandboxTransfer.create" });
  const retryReturn = db.pauseAt("retry", { before: "sandboxTransfer.findFirst" });
  const creating = db.run("allocate", () => f.store.create(s.principal, input));
  await allocation.waitReached();
  const retrying = db.run("retry", () => f.store.create(s.principal, input));
  let drained = false;
  let closing: Promise<void> | undefined;
  try {
    await expect(f.store.create(s.principal, { ...input, totalBytes: 2 })).rejects.toMatchObject({
      status: 429,
    });
    allocation.release();
    await creating;
    await retryReturn.waitReached();
    closing = f.store.close().then(() => {
      drained = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(drained).toBe(false);
  } finally {
    allocation.release();
    retryReturn.release();
    await Promise.allSettled([creating, retrying, closing]);
  }
  expect(drained).toBe(true);
  expect((await retrying).id).toBe((await creating).id);
});

it("coalesces concurrent identical creates and drains pending IO before shutdown", async () => {
  const s = await seed(),
    f = await start(),
    input = s.input();
  const gate = db.pauseAt("create", { after: "sandboxTransfer.create" });
  const creating = db.run("create", () => f.store.create(s.principal, input));
  await gate.waitReached();
  const duplicate = f.store.create(s.principal, input);
  await expect(f.store.create(s.principal, { ...input, totalBytes: 2 })).rejects.toMatchObject({
    status: 409,
  });
  gate.release();
  const [first, second] = await Promise.all([creating, duplicate]);
  expect(second.id).toBe(first.id);
  expect(await fs.readdir(f.root)).toEqual([`${first.id}.spool`]);
  const blocked = db.pauseAt("write", { after: "sandboxTransferChunk.create" });
  const writing = db.run("write", () =>
    f.store.write(s.principal, first.id, 0, Buffer.from([7]), hash(Buffer.from([7]))),
  );
  await blocked.waitReached();
  let drained = false;
  const draining = f.store.close().then(() => {
    drained = true;
  });
  try {
    await expect(f.store.status(s.principal, first.id)).rejects.toMatchObject({ status: 503 });
    expect(drained).toBe(false);
  } finally {
    blocked.release();
    await writing;
    await draining;
  }
  expect(drained).toBe(true);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: first.id } })).receivedBytes,
  ).toBe(1n);
});

it("handles short writes and keeps reservations through directory-sync cleanup failures", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input(3));
  fault.short = true;
  const body = Buffer.from([1, 2, 3]);
  await f.store.write(s.principal, row.id, 0, body, hash(body));
  expect(await fs.readFile(f.path(row.id))).toEqual(body);
  fault.directory = true;
  fault.operation = "sync";
  await expect(f.store.abort(s.principal, row.id)).rejects.toMatchObject({ status: 503 });
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "ABORTED", reservationHeld: true });
  await f.store.sweep();
  await f.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "ABORTED", reservationHeld: false });
});

it("sweeps beyond a full page even when the first cleanup fails", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 40, globalActive: 40 });
  const rows = [];
  for (let i = 0; i < 34; i++) rows.push(await f.store.create(s.principal, s.input(0)));
  const sorted = await db.inspect.sandboxTransfer.findMany({
    where: { userId: s.principal.ownerId },
    orderBy: { id: "asc" },
    take: 40,
  });
  const first = sorted[0]!;
  await fs.unlink(f.path(first.id));
  await fs.mkdir(f.path(first.id), { mode: 0o700 });
  await db.inspect.sandboxTransfer.updateMany({
    where: { userId: s.principal.ownerId },
    data: { expiresAt: new Date(0) },
  });
  await expect(f.store.sweep()).rejects.toMatchObject({ status: 503 });
  expect(await db.inspect.sandboxTransfer.count({ where: { reservationHeld: true } })).toBe(1);
  expect(await fs.readdir(f.root)).toEqual([`${first.id}.spool`]);
  await fs.rmdir(f.path(first.id));
  await f.store.sweep();
  expect(await db.inspect.sandboxTransfer.count({ where: { reservationHeld: true } })).toBe(0);
});

it("refuses non-private or unwritable spool directories before admission", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "wssp-c27-permissions-"));
  roots.push(root);
  for (const mode of [0o750, 0o500]) {
    await fs.chmod(root, mode);
    await expect(new TransferStore(root, limits).start()).rejects.toMatchObject({ status: 503 });
  }
  await fs.chmod(root, 0o700);
  const f = await start(limits, root),
    s = await seed();
  expect((await f.store.create(s.principal, s.input(0))).state).toBe("OPEN");
});

it("survives SIGKILL after payload fsync before metadata commit and resumes the same session", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input(CHUNK + 1));
  const first = Buffer.alloc(CHUNK, 43);
  await f.store.write(s.principal, row.id, 0, first, hash(first));
  await f.store.close();
  const source = `
    import { open } from "node:fs/promises";
    import { TransferStore } from ${JSON.stringify(new URL("./store.ts", import.meta.url).href)};
    const probe = await open(${JSON.stringify(f.path(row.id))}, "r+");
    const prototype = Object.getPrototypeOf(probe), sync = prototype.sync;
    await probe.close();
    prototype.sync = async function () {
      await sync.call(this);
      const stat = await this.stat();
      if (stat.isFile() && stat.size === ${CHUNK + 1}) {
        process.send("payload-durable");
        await new Promise(() => {});
      }
    };
    const store = new TransferStore(${JSON.stringify(f.root)}, ${JSON.stringify(limits)});
    await store.start();
    await store.write(${JSON.stringify(s.principal)}, ${JSON.stringify(row.id)}, ${CHUNK}, Buffer.from([9]), ${JSON.stringify(hash(Buffer.from([9])))});
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source], {
    stdio: ["ignore", "ignore", "pipe", "ipc"],
    env: {
      PATH: process.env.PATH,
      NODE_ENV: "test",
      DATABASE_URL: db.url,
      REDIS_URL: "redis://127.0.0.1:1",
      BETTER_AUTH_URL: "http://localhost:3000",
      BETTER_AUTH_SECRET: randomUUID() + randomUUID(),
      SANDBOX_REQUEST_HMAC_SECRET: randomBytes(32).toString("hex"),
      SIGNUP_ENABLED: "false",
    },
  });
  let errors = "";
  child.stderr?.on("data", (bytes: Buffer) => {
    errors = (errors + bytes.toString()).slice(-8192);
  });
  const exited = once(child, "exit");
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`child did not reach fsync: ${errors}`)),
        20_000,
      );
      child.once("message", () => {
        clearTimeout(timer);
        resolve();
      });
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("exit", () => {
        clearTimeout(timer);
        reject(new Error(`child exited before fsync: ${errors}`));
      });
    });
    expect(
      (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
    ).toBe(BigInt(CHUNK));
  } finally {
    child.kill("SIGKILL");
    await exited;
  }
  const recovered = await start(limits, f.root);
  expect((await fs.stat(f.path(row.id))).size).toBe(CHUNK);
  await recovered.store.write(s.principal, row.id, CHUNK, Buffer.from([9]), hash(Buffer.from([9])));
  await recovered.store.seal(s.principal, row.id);
  expect(await recovered.store.read(s.principal, row.id, CHUNK - 1, 2)).toEqual(
    Buffer.from([43, 9]),
  );
});

it("reauthorizes coalesced create retries before reporting an input conflict", async () => {
  const s = await seed(),
    actor = await s.sdk(),
    f = await start(),
    input = s.input();
  let reached!: () => void, release!: () => void;
  const entered = new Promise<void>((resolve) => {
    reached = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  fault.hold = async () => {
    reached();
    await held;
  };
  const creating = f.store.create(actor, input);
  const denied = expect(creating).rejects.toMatchObject({ status: 403 });
  try {
    await entered;
    if (actor.kind !== "sdkKey") throw new Error("fixture");
    await db.inspect.sdkKey.update({ where: { id: actor.keyId }, data: { revokedAt: new Date() } });
    await expect(f.store.create(actor, { ...input, totalBytes: 2 })).rejects.toMatchObject({
      status: 403,
    });
  } finally {
    release();
    await denied;
  }
  expect(await fs.readdir(f.root)).toEqual([]);
});

it("C29 status polling proceeds while a sealed-content read holds its shared permit", async () => {
  const s = await seed(),
    actor = await s.sdk(["files:read"]),
    f = await start();
  const row = await f.store.create(actor, { ...s.input(), direction: "DOWNLOAD" });
  const bytes = Buffer.from([7]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  const gate = db.pauseAt("read", { after: "sandboxTransfer.findFirst" });
  const reading = db.run("read", () => f.store.read(actor, row.id, 0, 1));
  await gate.waitReached();
  try {
    // Pre-C29 status() took an exclusive permit, which could never be granted
    // while this read held its shared permit; it now answers concurrently.
    await expect(f.store.status(actor, row.id)).resolves.toMatchObject({ state: "SEALED" });
  } finally {
    gate.release();
  }
  expect(await reading).toEqual(bytes);
});

it("an authority change committed during an upload commit rolls the operation back", async () => {
  const s = await seed(),
    actor = await s.sdk(["files:write"]),
    f = await start();
  const row = await f.store.create(actor, s.input(1));
  const bytes = Buffer.from([7]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  const key = randomUUID();
  const gate = db.pauseAt("commit", { after: "sandboxOperation.create" });
  const committing = db.run("commit", () => f.store.commit(actor, row.id, key, hash(bytes)));
  const denied = expect(committing).rejects.toMatchObject({ status: 403 });
  await gate.waitReached();
  // The owner's authority changes after the operation insert but before the
  // commit transaction ends: nothing may persist behind a 403.
  await withAuthorityChange({ ownerId: s.principal.ownerId }, async () => {});
  gate.release();
  await denied;
  expect(
    await db.inspect.sandboxOperation.count({
      where: {
        NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
        userId: s.principal.ownerId,
      },
    }),
  ).toBe(0);
  const after = await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } });
  expect(after).toMatchObject({ state: "SEALED", operationId: null });
  // The durable receipt stays recoverable: replaying the idempotency key commits.
  const replay = await f.store.commit(actor, row.id, key, hash(bytes));
  expect(replay.operationId).toBeTruthy();
  expect(
    await db.inspect.sandboxOperation.count({
      where: {
        NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
        userId: s.principal.ownerId,
      },
    }),
  ).toBe(1);
});

async function seedDownloadCapture(bytes: Buffer) {
  const s = await seed();
  const f = await start();
  const row = await f.store.create(s.principal, {
    ...s.input(bytes.length),
    direction: "DOWNLOAD",
  });
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: s.principal.ownerId,
      sandboxId: s.sandbox.id,
      kind: "GET_FILE",
      state: "SUCCEEDED",
      generation: 1,
      idempotencyKey: "dl",
      requestBodyHash: "a".repeat(64),
      completedAt: new Date(),
      result: { transferId: row.id },
    },
  });
  await db.inspect.sandboxTransfer.update({
    where: { id: row.id },
    data: { operationId: operation.id, sha256: hash(bytes) },
  });
  return { s, f, row, operation };
}

it("C30 a ban committed between chunks ends a session download stream", async () => {
  const { s, f, operation } = await seedDownloadCapture(Buffer.from([7, 9]));
  const source = await f.store.downloadSource(s.principal, operation.id);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([7]));
  await withAuthorityChange({ ownerId: s.principal.ownerId }, async () => {
    await db.inspect.user.update({
      where: { id: s.principal.ownerId },
      data: { banned: true },
    });
  });
  await expect(source.read(1, 1)).rejects.toMatchObject({ status: 403 });
});

it("C30 an in-process authority change alone ends the stream between chunks", async () => {
  const { s, f, operation } = await seedDownloadCapture(Buffer.from([7, 9]));
  const source = await f.store.downloadSource(s.principal, operation.id);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([7]));
  // No durable row changes: only the ticket sampled when the source opened can
  // catch this (2FA rollout, host/key rotation and other in-process revocations).
  await withAuthorityChange({ ownerId: s.principal.ownerId }, async () => {});
  await expect(source.read(1, 1)).rejects.toMatchObject({ status: 403 });
});

it("C30 a ban written by another control plane ends the stream (durable re-read)", async () => {
  const { s, f, operation } = await seedDownloadCapture(Buffer.from([7, 9]));
  const source = await f.store.downloadSource(s.principal, operation.id);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([7]));
  // No in-process authority bump: only the per-chunk durable policy re-read
  // catches a ban committed by a different process.
  await db.inspect.user.update({
    where: { id: s.principal.ownerId },
    data: { banned: true },
  });
  await expect(source.read(1, 1)).rejects.toMatchObject({ status: 403 });
});

it("C30 an authority change committed during a chunk read voids that chunk", async () => {
  const { s, f, operation } = await seedDownloadCapture(Buffer.from([7, 9]));
  const source = await f.store.downloadSource(s.principal, operation.id);
  const gate = db.pauseAt("read", { after: "sandboxTransfer.findFirst" });
  const reading = db.run("read", () => source.read(0, 1));
  const denied = expect(reading).rejects.toMatchObject({ status: 403 });
  await gate.waitReached();
  // Committed while the read's IO was in flight: the post-read ticket check
  // must void the bytes rather than return them under a stale grant.
  await withAuthorityChange({ ownerId: s.principal.ownerId }, async () => {});
  gate.release();
  await denied;
});

it("C27 a deletion request committed between chunks ends a session upload stream", async () => {
  const s = await seed(),
    f = await start();
  const row = await f.store.create(s.principal, s.input(2));
  const bytes = Buffer.from([7, 9]);
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  const committed = await f.store.commit(s.principal, row.id, randomUUID(), hash(bytes));
  const source = await f.store.uploadSource(row.id, committed.operationId);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([7]));
  await withAuthorityChange({ ownerId: s.principal.ownerId }, async () => {
    await db.inspect.user.update({
      where: { id: s.principal.ownerId },
      data: { deletionRequestedAt: new Date() },
    });
  });
  await expect(source.read(1, 1)).rejects.toMatchObject({ status: 403 });
});

it("C27 a key expiring between revalidation and completion voids the read", async () => {
  const s = await seed(),
    f = await start();
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: s.principal.ownerId,
      name: "expiring",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALL_OWNED",
      scopes: ["files:read", "files:write"],
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  const actor: Principal = {
    kind: "sdkKey",
    keyId: key.id,
    ownerId: s.principal.ownerId,
    expiresAt: key.expiresAt,
    resourceMode: "ALL_OWNED",
    scopes: new Set(["files:read", "files:write"]),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
  const row = await f.store.create(actor, { ...s.input(), direction: "DOWNLOAD" });
  const bytes = Buffer.from([7]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  // Revalidation reads new Date(), not Date.now() or DB now(). Keep the
  // initial deadline well ahead of setup, then expire the DB key while IO is
  // parked. The closing transaction must revalidate and void the bytes. Do
  // not change authority revisions or the actor's expiry: either would let
  // authorized() mask a missing closing-transaction revalidation.
  let entered!: () => void, release!: () => void;
  const reading_io = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  fault.holdRead = async () => {
    entered();
    await held;
  };
  const reading = f.store.read(actor, row.id, 0, 1);
  const denied = expect(reading).rejects.toMatchObject({ status: 403 });
  await reading_io;
  try {
    await db.inspect.sdkKey.update({
      where: { id: key.id },
      data: { expiresAt: new Date(0) },
    });
    release();
    await denied;
  } finally {
    release();
  }
});

it("C27 a key expiring after the read's in-transaction checks is caught only by the closing fence", async () => {
  const s = await seed(),
    f = await start();
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: s.principal.ownerId,
      name: "expiring",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALL_OWNED",
      scopes: ["files:read", "files:write"],
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  const actor: Principal = {
    kind: "sdkKey",
    keyId: key.id,
    ownerId: s.principal.ownerId,
    expiresAt: key.expiresAt,
    resourceMode: "ALL_OWNED",
    scopes: new Set(["files:read", "files:write"]),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
  const row = await f.store.create(actor, { ...s.input(), direction: "DOWNLOAD" });
  const bytes = Buffer.from([7]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  // Park INSIDE the read's closing transaction, after its reauthorization
  // (current()) and row update already ran: the key then expires, so only
  // authorized()'s return-time fence can void the already-read bytes. (The
  // disk-IO variant above passes even without that fence because the closing
  // transaction reauthorizes.)
  const parked = db.pauseAt("reader", { after: "sandboxTransfer.update" });
  const reading = db.run("reader", () => f.store.read(actor, row.id, 0, 1));
  const denied = expect(reading).rejects.toMatchObject({ status: 403 });
  await parked.waitReached();
  // Only the return-time fence reads Date.now(). Cross that clock after all
  // DB revalidation has finished; keep real IO and timers running normally.
  const now = vi.spyOn(Date, "now").mockReturnValue(key.expiresAt!.getTime() + 1);
  try {
    parked.release();
    await denied;
  } finally {
    now.mockRestore();
    parked.release();
  }
});

it("C27 an SDK key expiring mid-stream ends the upload at the boundary", async () => {
  const s = await seed(),
    f = await start();
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: s.principal.ownerId,
      name: "expiring",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALL_OWNED",
      scopes: ["files:read", "files:write"],
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  const actor: Principal = {
    kind: "sdkKey",
    keyId: key.id,
    ownerId: s.principal.ownerId,
    expiresAt: key.expiresAt,
    resourceMode: "ALL_OWNED",
    scopes: new Set(["files:read", "files:write"]),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
  const row = await f.store.create(actor, s.input(2));
  const bytes = Buffer.from([7, 9]);
  await f.store.write(actor, row.id, 0, bytes, hash(bytes));
  await f.store.seal(actor, row.id);
  const committed = await f.store.commit(actor, row.id, randomUUID(), hash(bytes));
  const source = await f.store.uploadSource(row.id, committed.operationId);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([7]));
  // Cross the real key's deadline only after the stream exists. A 250ms
  // setup budget expired before admission on busy hosts and proved nothing
  // about the intended between-chunk fence. Keep IO and timers real.
  const now = vi.spyOn(Date, "now").mockReturnValue(key.expiresAt!.getTime() + 1);
  try {
    await expect(source.read(1, 1)).rejects.toMatchObject({ status: 403 });
  } finally {
    now.mockRestore();
  }
});

/** One committed one-byte upload of `owner` with its PUT_FILE operation. */
async function committedUpload(
  s: Awaited<ReturnType<typeof seed>>,
  f: Awaited<ReturnType<typeof start>>,
) {
  const row = await f.store.create(s.principal, s.input(1));
  const bytes = Buffer.from([5]);
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  const { operationId } = await f.store.commit(s.principal, row.id, randomUUID(), hash(bytes));
  return { row, operationId };
}
const settleOperation = (id: string, state: "SUCCEEDED" | "FAILED" | "CANCELLED") =>
  db.inspect.sandboxOperation.update({ where: { id }, data: { state, completedAt: new Date() } });

it("E-17 an upload holds its slot until its PUT_FILE durably settles; uncertain outcomes keep it", async () => {
  const f = await start({ ...limits, ownerActive: 1 });
  for (const state of [
    "QUEUED",
    "DISPATCHED",
    "ACCEPTED",
    "RUNNING",
    "CANCEL_REQUESTED",
    "UNKNOWN_OUTCOME",
  ] as const) {
    const s = await seed();
    const { operationId } = await committedUpload(s, f);
    await db.inspect.sandboxOperation.update({ where: { id: operationId }, data: { state } });
    await expect(f.store.create(s.principal, s.input()), state).rejects.toMatchObject({
      status: 429,
    });
  }
  for (const state of ["SUCCEEDED", "FAILED", "CANCELLED"] as const) {
    const s = await seed();
    const { row, operationId } = await committedUpload(s, f);
    await settleOperation(operationId, state);
    const next = await f.store.create(s.principal, s.input());
    expect(next.state, state).toBe("OPEN");
    // Admission also returned the settled upload's disk.
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
    await expect(fs.access(f.path(row.id))).rejects.toMatchObject({ code: "ENOENT" });
  }
});

it("E-17 a settled upload's in-flight read keeps its slot and no read starts after it", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1 });
  const { row, operationId } = await committedUpload(s, f);
  const source = await f.store.uploadSource(row.id, operationId);
  const gate = db.pauseAt("relay", { after: "sandboxOperation.count" });
  const reading = db.run("relay", () => source.read(0, 1));
  await gate.waitReached();
  try {
    // The host reports success while the server still has this chunk in flight.
    await settleOperation(operationId, "SUCCEEDED");
    await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  } finally {
    gate.release();
  }
  expect(Buffer.from(await reading)).toEqual(Buffer.from([5]));
  await expect(source.read(0, 1)).rejects.toMatchObject({ status: 410 });
  await f.store.create(s.principal, s.input());
});

it("E-17 a settlement frees the slot only once it commits", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1 });
  const { operationId } = await committedUpload(s, f);
  let commit!: () => void;
  const held = new Promise<void>((resolve) => {
    commit = resolve;
  });
  let written!: () => void;
  const updated = new Promise<void>((resolve) => {
    written = resolve;
  });
  const settling = db.inspect.$transaction(
    async (tx) => {
      await tx.sandboxOperation.update({
        where: { id: operationId },
        data: { state: "SUCCEEDED" },
      });
      written();
      await held;
    },
    { timeout: 30_000 },
  );
  await updated;
  try {
    await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  } finally {
    commit();
    await settling;
  }
  await f.store.create(s.principal, s.input());
});

it("E-17 two admissions racing for one freed slot: exactly one wins and cleanup runs once", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1 });
  const { row, operationId } = await committedUpload(s, f);
  await settleOperation(operationId, "SUCCEEDED");
  const results = await Promise.allSettled([
    f.store.create(s.principal, s.input()),
    f.store.create(s.principal, s.input()),
    f.store.sweep(),
  ]);
  expect(results.slice(0, 2).filter((r) => r.status === "fulfilled")).toHaveLength(1);
  expect(results.slice(0, 2).find((r) => r.status === "rejected")).toMatchObject({
    reason: { status: 429 },
  });
  await f.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
  expect(
    await db.inspect.sandboxTransfer.count({
      where: { userId: s.principal.ownerId, reservationHeld: true },
    }),
  ).toBe(1);
  expect(await fs.readdir(f.root)).toHaveLength(1);
});

it("E-17 sweep and restart retire settled uploads without a new admission", async () => {
  const s = await seed(),
    f = await start();
  const swept = await committedUpload(s, f);
  await settleOperation(swept.operationId, "FAILED");
  await f.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: swept.row.id } }),
  ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
  const restarted = await committedUpload(s, f);
  await settleOperation(restarted.operationId, "SUCCEEDED");
  await f.store.close();
  await start(limits, f.root);
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: restarted.row.id } }),
  ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
  expect(await fs.readdir(f.root)).toEqual([]);
});

it("WP6 a requeued upload keeps its verified spool across a restart and stays readable", async () => {
  const s = await seed(),
    f = await start();
  const { row, operationId } = await committedUpload(s, f);
  // The host proved attempt 1 never issued; the relay requeued it (QUEUED,
  // attempt 1 recorded) for attempt 2.
  await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: { state: "QUEUED", dispatchAttempt: 1 },
  });
  await f.store.close();
  const restarted = await start(limits, f.root);
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true, operationId });
  await restarted.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });
  const source = await restarted.store.uploadSource(row.id, operationId);
  expect(Buffer.from(await source.read(0, 1))).toEqual(Buffer.from([5]));
});

it("E-17 a capture frees its slot once every byte was delivered and its last stream closed", async () => {
  const s = await seed(),
    other = await seed(),
    f = await start({ ...limits, ownerActive: 1, globalActive: 2 });
  const bytes = Buffer.from([7, 9]);
  const row = await f.store.create(s.principal, { ...s.input(2), direction: "DOWNLOAD" });
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: s.principal.ownerId,
      sandboxId: s.sandbox.id,
      kind: "GET_FILE",
      state: "SUCCEEDED",
      generation: 1,
      idempotencyKey: "dl-slot",
      requestBodyHash: "a".repeat(64),
      completedAt: new Date(),
      result: { transferId: row.id },
    },
  });
  await db.inspect.sandboxTransfer.update({
    where: { id: row.id },
    data: { operationId: operation.id, sha256: hash(bytes) },
  });
  const full = () =>
    expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  // Two parallel range streams; the first delivers byte 0 only and closes.
  const first = await f.store.downloadSource(s.principal, operation.id);
  const second = await f.store.downloadSource(s.principal, operation.id);
  await first.read(0, 1);
  first.delivered(0, 1);
  first.close();
  first.close();
  await full();
  // The second completes the coverage but is still open: bytes may still move.
  await second.read(1, 1);
  second.delivered(1, 1);
  await full();
  // A third stream opening and closing meanwhile must not retire it under the second.
  const third = await f.store.downloadSource(s.principal, operation.id);
  third.close();
  await f.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });
  // The other owner's global count includes this in-flight capture too.
  await f.store.create(other.principal, other.input());
  await expect(f.store.create(other.principal, other.input())).rejects.toMatchObject({
    status: 429,
  });
  second.close();
  await vi.waitFor(async () =>
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  await f.store.create(s.principal, s.input());
  await expect(f.store.downloadSource(s.principal, operation.id)).rejects.toMatchObject({
    status: 410,
  });
});

it("E-17 an undelivered or cancelled capture stream credits nothing and keeps the slot", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1 });
  const { operation, row } = await (async () => {
    const bytes = Buffer.from([1, 2, 3]);
    const created = await f.store.create(s.principal, { ...s.input(3), direction: "DOWNLOAD" });
    await f.store.write(s.principal, created.id, 0, bytes, hash(bytes));
    await f.store.seal(s.principal, created.id);
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: s.principal.ownerId,
        sandboxId: s.sandbox.id,
        kind: "GET_FILE",
        state: "SUCCEEDED",
        generation: 1,
        idempotencyKey: "dl-cancel",
        requestBodyHash: "a".repeat(64),
        completedAt: new Date(),
        result: { transferId: created.id },
      },
    });
    await db.inspect.sandboxTransfer.update({
      where: { id: created.id },
      data: { operationId: op.id, sha256: hash(bytes) },
    });
    return { operation: op, row: created };
  })();
  for (let n = 0; n < 3; n++) {
    const source = await f.store.downloadSource(s.principal, operation.id);
    await source.read(0, 3);
    source.close();
  }
  // Delivery reported after close is ignored.
  const late = await f.store.downloadSource(s.principal, operation.id);
  late.close();
  late.delivered(0, 3);
  await f.store.sweep();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });
  await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
});

it("E-17 a relay capture is admitted beside a settled upload no admission has reaped yet", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1 });
  const { row, operationId } = await committedUpload(s, f);
  await settleOperation(operationId, "SUCCEEDED");
  // Capture admission runs inside the relay's fenced transaction and never
  // reaps; only the slot predicate can see that the upload is finished.
  const publish = await db.prisma.$transaction((tx) =>
    f.store.admitCapture(
      tx,
      {
        userId: s.principal.ownerId,
        keyId: null,
        sandboxId: s.sandbox.id,
        generation: 1,
        guestPath: "/tmp/out",
      },
      {
        operationId: randomUUID(),
        attempt: 1,
        sequence: 0,
        offset: 0,
        body: Buffer.from([1]),
        ended: true,
      },
    ),
  );
  await publish?.();
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });
  expect(
    await db.inspect.sandboxTransfer.count({
      where: { userId: s.principal.ownerId, direction: "DOWNLOAD", state: "SEALED" },
    }),
  ).toBe(1);
});

it("E-17 a terminal transfer whose cleanup is pending frees its slot but keeps charging disk", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1, diskBytes: 4 });
  const row = await f.store.create(s.principal, s.input(3));
  fault.directory = true;
  fault.operation = "sync";
  await expect(f.store.abort(s.principal, row.id)).rejects.toMatchObject({ status: 503 });
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "ABORTED", reservationHeld: true });
  // The slot is free; the 3 bytes still on disk are not.
  await expect(f.store.create(s.principal, s.input(2))).rejects.toMatchObject({ status: 429 });
  await f.store.create(s.principal, s.input(1));
});

it("parallel admissions never exceed the owner budget beside settled and uncertain uploads", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 4, globalActive: 16 });
  // two settled uploads (slot free), one UNKNOWN_OUTCOME upload (slot held)
  for (const state of ["SUCCEEDED", "CANCELLED", "UNKNOWN_OUTCOME"] as const) {
    const row = await f.store.create(s.principal, s.input(1));
    const bytes = Buffer.from([5]);
    await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
    const { operationId } = await f.store.commit(s.principal, row.id, randomUUID(), hash(bytes));
    await db.inspect.sandboxOperation.update({ where: { id: operationId }, data: { state } });
  }
  const results = await Promise.allSettled(
    Array.from({ length: 8 }, () => f.store.create(s.principal, s.input(1))),
  );
  const ok = results.filter((r) => r.status === "fulfilled");
  const refused = results.filter((r) => r.status === "rejected");
  expect(ok).toHaveLength(3);
  for (const r of refused) expect(r).toMatchObject({ reason: { status: 429 } });
  // committed-state bound: held, live slots for the owner never above 4
  const live = await db.inspect.sandboxTransfer.count({
    where: { userId: s.principal.ownerId, reservationHeld: true, state: "OPEN" },
  });
  expect(live).toBe(3);
});

// ---- C58 G4: delivered captures, their grace and racing streams (TQ-F1/F2/F3/N1) ----
async function deliveredCapture(
  s: Awaited<ReturnType<typeof seed>>,
  f: Awaited<ReturnType<typeof start>>,
  bytes: Buffer,
) {
  const row = await f.store.create(s.principal, {
    ...s.input(bytes.length),
    direction: "DOWNLOAD",
  });
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: s.principal.ownerId,
      sandboxId: s.sandbox.id,
      kind: "GET_FILE",
      state: "SUCCEEDED",
      generation: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      completedAt: new Date(),
      result: { transferId: row.id },
    },
  });
  await db.inspect.sandboxTransfer.update({
    where: { id: row.id },
    data: { operationId: operation.id, sha256: hash(bytes) },
  });
  // One stream takes every byte and closes: the capture is delivered.
  const full = async () => {
    const source = await f.store.downloadSource(s.principal, operation.id);
    expect(Buffer.from(await source.read(0, bytes.length)).equals(bytes)).toBe(true);
    source.delivered(0, bytes.length);
    source.close();
  };
  return { row, operation, full };
}
const internals = (store: InstanceType<typeof TransferStore>) =>
  store as unknown as {
    coverage: Map<string, unknown>;
    streams: Map<string, number>;
    slotted: Map<string, number>;
    delivered: Set<string>;
    graces: Map<string, unknown>;
    settling: Set<Promise<void>>;
  };
const rowOf = (id: string) => db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id } });

// Adopted from reviews/transfer-quota-r1-probe.patch; the expectations after
// the settlement follow decision D-3 (b): the content is kept for the grace.
it("a re-stream opened while a delivered capture settles is served whole and leaks no coverage", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1, deliveredGraceMs: 400 });
  const { row, operation } = await deliveredCapture(s, f, Buffer.from([7, 9]));
  const a = await f.store.downloadSource(s.principal, operation.id);
  await a.read(0, 2);
  a.delivered(0, 2);
  // Hold the row lock so the settlement's EXPIRED write waits.
  let unlock!: () => void;
  const hold = new Promise<void>((r) => {
    unlock = r;
  });
  let locked!: () => void;
  const isLocked = new Promise<void>((r) => {
    locked = r;
  });
  const lock = db.inspect.$transaction(
    async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${row.id} FOR UPDATE`;
      locked();
      await hold;
    },
    { timeout: 30_000 },
  );
  await isLocked;
  a.close(); // settlement starts, blocked on the row lock
  const b = await f.store.downloadSource(s.principal, operation.id); // re-stream racing it
  // Row is still SEALED and held: the owner budget is full.
  await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  unlock();
  await lock;
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: true }),
  );
  // TQ-N1: the capture's own slot is free, but B's admitted stream still counts.
  await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  // TQ-F2: the racing stream is not retired under it; it reads the content.
  expect([...(await b.read(0, 2))]).toEqual([7, 9]);
  // The racing stream reports a partial delivery, then closes.
  b.delivered(0, 1);
  // TQ-F3: a kept capture records no coverage.
  expect(internals(f.store).coverage.has(row.id)).toBe(false);
  b.close();
  await f.store.create(s.principal, s.input());
  // The grace ends and the capture is retired; nothing is left in memory.
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  const mem = internals(f.store);
  expect(mem.streams.has(row.id)).toBe(false);
  expect(mem.slotted.has(row.id)).toBe(false);
  expect(mem.delivered.has(row.id)).toBe(false);
  expect(mem.graces.has(row.id)).toBe(false);
  expect(mem.coverage.has(row.id)).toBe(false);
  await expect(f.store.downloadSource(s.principal, operation.id)).rejects.toMatchObject({
    status: 410,
  });
});

it("TQ-F1 a delivered capture frees its slot at once and stays resumable for the grace", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1, deliveredGraceMs: 60_000 });
  const bytes = Buffer.from([1, 2, 3]);
  const { row, operation, full } = await deliveredCapture(s, f, bytes);
  await full();
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: true }),
  );
  // The sweep keeps kept content.
  await f.store.sweep();
  expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: true });
  expect(await fs.readdir(f.root)).toContain(`${row.id}.spool`);
  // The tail resumes (twice, and in parallel) with the same bytes.
  const [tail, again] = await Promise.all([
    f.store.downloadSource(s.principal, operation.id),
    f.store.downloadSource(s.principal, operation.id),
  ]);
  expect([...(await tail.read(1, 2))]).toEqual([2, 3]);
  expect([...(await again.read(2, 1))]).toEqual([3]);
  tail.close();
  again.close();
  // No stream open: the kept capture holds no slot.
  const next = await f.store.create(s.principal, s.input());
  // TQ-N1 + budget: with the owner's one slot taken, a resume is refused...
  await expect(f.store.downloadSource(s.principal, operation.id)).rejects.toMatchObject({
    status: 429,
  });
  expect(internals(f.store).streams.has(row.id)).toBe(false);
  // ...and admitted again once that slot is free; while it is open it counts.
  await f.store.abort(s.principal, next.id);
  const resumed = await f.store.downloadSource(s.principal, operation.id);
  await expect(f.store.create(s.principal, s.input())).rejects.toMatchObject({ status: 429 });
  expect([...(await resumed.read(0, 3))]).toEqual([1, 2, 3]);
  resumed.close();
  await f.store.create(s.principal, s.input());
});

it("TQ-F1 the grace keeps charging disk, ends with a 410, and waits for a stream still open", async () => {
  const s = await seed(),
    f = await start({ ...limits, diskBytes: 4, deliveredGraceMs: 300 });
  const { row, operation, full } = await deliveredCapture(s, f, Buffer.from([1, 2, 3]));
  await full();
  await vi.waitFor(async () => expect((await rowOf(row.id)).state).toBe("EXPIRED"));
  // The kept 3 bytes are still on the disk budget.
  await expect(f.store.create(s.principal, s.input(2))).rejects.toMatchObject({ status: 429 });
  // A stream opened inside the grace outlives it, and the capture waits for it.
  const late = await f.store.downloadSource(s.principal, operation.id);
  await new Promise((r) => setTimeout(r, 600));
  await f.store.sweep();
  expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: true });
  expect([...(await late.read(0, 3))]).toEqual([1, 2, 3]);
  // After the grace no new stream opens.
  await expect(f.store.downloadSource(s.principal, operation.id)).rejects.toMatchObject({
    status: 410,
  });
  late.close();
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  expect(await fs.readdir(f.root)).toEqual([]);
  expect(internals(f.store).graces.size).toBe(0);
  await f.store.create(s.principal, s.input(2));
});

it("TQ-F1 a restart drops the grace: kept content is retired by recovery", async () => {
  const s = await seed(),
    f = await start({ ...limits, deliveredGraceMs: 60_000 });
  const { row, operation, full } = await deliveredCapture(s, f, Buffer.from([4]));
  await full();
  await vi.waitFor(async () => expect((await rowOf(row.id)).state).toBe("EXPIRED"));
  await f.store.close();
  const restarted = await start({ ...limits, deliveredGraceMs: 60_000 }, f.root);
  expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: false });
  await expect(restarted.store.downloadSource(s.principal, operation.id)).rejects.toMatchObject({
    status: 410,
  });
});

it("TQ-F3 a stream that credits an aborted capture leaves no coverage behind", async () => {
  const s = await seed(),
    f = await start(limits);
  const { row, operation } = await deliveredCapture(s, f, Buffer.from([1, 2, 3]));
  const open = await f.store.downloadSource(s.principal, operation.id);
  await open.read(0, 1);
  await f.store.abort(s.principal, row.id);
  // Credit after the retirement recreates bookkeeping for a dead capture...
  open.delivered(0, 1);
  open.close();
  // ...which its last close drops.
  await vi.waitFor(() => expect(internals(f.store).coverage.has(row.id)).toBe(false));
  // A partial capture that is still live keeps its coverage for a resume.
  const live = await deliveredCapture(s, f, Buffer.from([5, 6]));
  const part = await f.store.downloadSource(s.principal, live.operation.id);
  await part.read(0, 1);
  part.delivered(0, 1);
  part.close();
  // The close's stale-coverage check is a tracked task: wait for it to finish.
  const pending = internals(f.store).settling;
  expect(pending.size).toBeGreaterThan(0);
  await Promise.allSettled([...pending]);
  expect(internals(f.store).coverage.has(live.row.id)).toBe(true);
});

// ---- C58 G4 r1 reviewer probes (grace admission, stale-row race, abort in grace) ----
it("a grace resume racing a create never lets the owner exceed ownerActive", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1, deliveredGraceMs: 60_000 });
  const { row, operation, full } = await deliveredCapture(s, f, Buffer.from([1, 2, 3]));
  await full();
  await vi.waitFor(async () => expect((await rowOf(row.id)).state).toBe("EXPIRED"));
  // Stagger the resume so both lock orders occur (create first at higher rounds).
  const orders = new Set<string>();
  for (let round = 0; round < 12; round++) {
    const [resume, created] = await Promise.allSettled([
      new Promise((r) => setTimeout(r, round * 3)).then(() =>
        f.store.downloadSource(s.principal, operation.id),
      ),
      f.store.create(s.principal, s.input()),
    ]);
    orders.add(resume.status);
    const won = [resume, created].filter((r) => r.status === "fulfilled");
    expect(won).toHaveLength(1);
    if (resume.status === "fulfilled") resume.value.close();
    if (created.status === "fulfilled") await f.store.abort(s.principal, created.value.id);
    expect(internals(f.store).slotted.has(row.id)).toBe(false);
  }
  // Discriminating only if both winners were observed.
  expect(orders).toEqual(new Set(["fulfilled", "rejected"]));
});

it("a GET that read the row before the grace ended and retired gets 410 and leaks nothing", async () => {
  const s = await seed(),
    f = await start({ ...limits, deliveredGraceMs: 50 });
  const { row, operation } = await deliveredCapture(s, f, Buffer.from([1, 2]));
  const store = f.store as unknown as {
    owned: (...args: unknown[]) => Promise<{ state: string }>;
  };
  const original = store.owned.bind(f.store);
  let gate!: () => void;
  const held = new Promise<void>((r) => {
    gate = r;
  });
  let seen!: () => void;
  const sawSealed = new Promise<void>((r) => {
    seen = r;
  });
  let armed = false;
  store.owned = async (...args: unknown[]) => {
    const result = await original(...args);
    if (armed && args[1] === row.id && result.state === "SEALED") {
      armed = false;
      seen();
      await held;
    }
    return result;
  };
  // The last full read is in flight; arm the stale read for the next GET.
  const a = await f.store.downloadSource(s.principal, operation.id);
  await a.read(0, 2);
  a.delivered(0, 2);
  armed = true;
  const late = f.store.downloadSource(s.principal, operation.id);
  await sawSealed; // `late` holds a SEALED row snapshot
  a.close(); // grace starts and (50 ms) ends; the capture retires
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  gate();
  await expect(late).rejects.toMatchObject({ status: 410 });
  const mem = internals(f.store);
  expect(mem.streams.has(row.id)).toBe(false);
  expect(mem.slotted.has(row.id)).toBe(false);
  expect(mem.graces.has(row.id)).toBe(false);
  expect(mem.coverage.has(row.id)).toBe(false);
  expect(await fs.readdir(f.root)).toEqual([]);
});

it("abort during a grace stream stops its bytes and releases everything", async () => {
  const s = await seed(),
    f = await start({ ...limits, ownerActive: 1, deliveredGraceMs: 60_000 });
  const { row, operation, full } = await deliveredCapture(s, f, Buffer.from([1, 2, 3]));
  await full();
  await vi.waitFor(async () => expect((await rowOf(row.id)).state).toBe("EXPIRED"));
  const resume = await f.store.downloadSource(s.principal, operation.id);
  expect([...(await resume.read(0, 1))]).toEqual([1]);
  await f.store.abort(s.principal, row.id);
  await expect(resume.read(1, 2)).rejects.toMatchObject({ status: 410 });
  resume.delivered(1, 2);
  resume.close();
  await vi.waitFor(async () =>
    expect(await rowOf(row.id)).toMatchObject({ reservationHeld: false }),
  );
  const mem = internals(f.store);
  await vi.waitFor(() => expect(mem.coverage.has(row.id)).toBe(false));
  expect(mem.streams.has(row.id)).toBe(false);
  expect(mem.slotted.has(row.id)).toBe(false);
  expect(mem.graces.has(row.id)).toBe(false);
  expect(mem.delivered.has(row.id)).toBe(false);
  // The owner's one slot is free again.
  await f.store.create(s.principal, s.input());
});

it("3A upload holds O and outbox before acquiring transfer", async () => {
  const s = await seed(),
    f = await start();
  const bytes = Buffer.from([7]);
  const row = await f.store.create(s.principal, s.input());
  await f.store.write(s.principal, row.id, 0, bytes, hash(bytes));
  await f.store.seal(s.principal, row.id);
  const gate = db.pauseAt("commit", {
    before: /^sql:SELECT id FROM sandbox_stream_transfer.*FOR UPDATE$/,
  });
  const committing = db.run("commit", () =>
    f.store.commit(s.principal, row.id, randomUUID(), hash(bytes)),
  );
  await gate.waitReached();
  try {
    // Both fresh rows exist in this transaction before the transfer rank.
    // PostgreSQL exposes their RowExclusive relation locks even before commit.
    const held = await db.inspect.$queryRaw<
      { name: string }[]
    >`SELECT relation::regclass::text AS name FROM pg_locks WHERE pid = ${db.backendPid("commit")} AND mode = 'RowExclusiveLock'`;
    expect(held.map((r) => r.name)).toEqual(
      expect.arrayContaining(["sandbox_mutation_operation", "sandbox_dispatch_outbox"]),
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${row.id} FOR UPDATE NOWAIT`;
    });
  } finally {
    gate.release();
  }
  expect(await committing).toMatchObject({ state: "QUEUED" });
});

it("B5 upload allocation/chunks/status are uncharged; commit charges ordinary once and replay is free", async () => {
  const s = await seed();
  const f = await start();
  const budgets = await import("@wssp/api/sandbox/budgets");
  const charged = vi.spyOn(budgets, "consumeSandboxWriteBudget");
  try {
    const bytes = Buffer.alloc(CHUNK + 1, 7);
    const row = await f.store.create(s.principal, s.input(bytes.length));
    const first = bytes.subarray(0, CHUNK);
    const last = bytes.subarray(CHUNK);
    await f.store.write(s.principal, row.id, 0, first, hash(first));
    await f.store.write(s.principal, row.id, 0, first, hash(first));
    await f.store.write(s.principal, row.id, CHUNK, last, hash(last));
    await f.store.seal(s.principal, row.id);
    await f.store.status(s.principal, row.id);
    expect(charged).not.toHaveBeenCalled();
    const key = randomUUID();
    const accepted = await f.store.commit(s.principal, row.id, key, hash(bytes));
    expect(await f.store.commit(s.principal, row.id, key, hash(bytes))).toEqual(accepted);
    expect(charged.mock.calls).toEqual([[s.principal.ownerId, "ordinary"]]);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: s.principal.ownerId, kind: "PUT_FILE" },
      }),
    ).toBe(1);
    expect(
      await db.inspect.outboxEvent.count({
        where: {
          userId: s.principal.ownerId,
          payload: { path: ["operationId"], equals: accepted.operationId },
        },
      }),
    ).toBe(1);
  } finally {
    charged.mockRestore();
  }
});
