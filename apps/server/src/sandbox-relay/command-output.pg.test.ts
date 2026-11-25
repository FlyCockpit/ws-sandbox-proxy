import {
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { commandResultFixture } from "./command-result-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

const transactions = vi.hoisted(() => ({ count: 0 }));
vi.mock("@wssp/db", async () => {
  const prisma = (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma;
  // The instrumented client, counting top-level transactions (D3b batching).
  return {
    default: new Proxy(prisma, {
      get(target, key, receiver) {
        const value: unknown = Reflect.get(target, key, receiver);
        if (key !== "$transaction" || typeof value !== "function") return value;
        return (...args: unknown[]) => {
          transactions.count += 1;
          return Reflect.apply(value, target, args);
        };
      },
    }),
  };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const db = await pgTestDatabase();
const { acceptFencedBinaryChunk, acceptFencedOutputBatch, applyOperationResult } = await import(
  "./operation-handlers.js"
);
const { purgeExpiredCommandOutput, readCommandOutputPage } = await import(
  "@wssp/api/sandbox/command-output"
);
afterAll(() => db.close());

const HOUR = 3_600_000;
const receipt = { bodyHash: "a".repeat(64), idempotencyKey: "cmd", kind: "command.run" };

async function seed(state = "RUNNING" as const) {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "Owner", email: `${id}@example.test` } });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "host", label: "host", status: "CONNECTED", connectionEpoch: 1 },
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
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: id,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      resultVersion: 1,
      processId: randomUUID(),
      generation: 1,
      idempotencyKey: "cmd",
      requestBodyHash: "a".repeat(64),
      state,
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  const sender = { userId: id, hostId: host.id, connectionEpoch: 1 };
  const chunk = (sequence: number, offset: number, body: number[], extra = {}) => ({
    sender,
    operationId: operation.id,
    generation: 1,
    attempt: 1,
    sequence,
    ended: false,
    body: new Uint8Array(body),
    output: {
      type: "stream.chunk" as const,
      streamId: operation.id,
      operationId: operation.id,
      generation: 1,
      attempt: 1,
      sequence,
      offset,
      flags: { stdout: true },
      ...extra,
    },
  });
  const result = (
    state: string,
    extra: { receipt?: typeof receipt; result?: Record<string, unknown> } = {},
  ) => ({
    sender,
    operationId: operation.id,
    sandboxId: sandbox.id,
    generation: 1,
    attempt: 1,
    state,
    ...extra,
    ...(extra.result &&
    (typeof extra.result.exitCode === "number" || extra.result.exitCode === null)
      ? {
          result: commandResultFixture(operation, {
            exitCode: extra.result.exitCode,
            ...(typeof extra.result.outputBytes === "number"
              ? { outputBytes: extra.result.outputBytes }
              : {}),
          }),
        }
      : {}),
  });
  const page = (cursor?: string, now = new Date()) =>
    readCommandOutputPage({ ownerId: id, operationId: operation.id, cursor, now });
  const rows = async () => ({
    header: await db.inspect.sandboxCommandOutput.findUnique({ where: { id: operation.id } }),
    segments: await db.inspect.sandboxCommandOutputSegment.count({
      where: { outputId: operation.id },
    }),
  });
  return { id, host, sandbox, operation, sender, chunk, result, page, rows };
}

it("fences output by owner host epoch generation attempt and commits it only with the transaction", async () => {
  const s = await seed();
  const input = s.chunk(0, 0, [1, 2]);
  for (const bad of [
    { ...input, sender: { ...input.sender, userId: "foreign" } },
    { ...input, sender: { ...input.sender, hostId: "foreign" } },
    { ...input, sender: { ...input.sender, connectionEpoch: 2 } },
    { ...input, generation: 2 },
    { ...input, attempt: 2 },
  ])
    expect(await acceptFencedBinaryChunk(bad)).toBe(false);
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  const gate = db.pauseAt("output", { after: "sandboxCommandOutput.create" });
  const pending = db.run("output", () => acceptFencedBinaryChunk(input));
  await gate.waitReached();
  // Uncommitted: another connection (and so every reader) sees nothing yet.
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  gate.release();
  expect(await pending).toBe(true);
  expect((await s.rows()).segments).toBe(1);
  // An exact retransmit is acknowledged again without storing twice.
  expect(await acceptFencedBinaryChunk(input)).toBe(true);
  expect((await s.page()).receivedBytes).toBe(2);

  // Interim UNKNOWN (no byte total) keeps the exact dispatch writable.
  expect(
    await applyOperationResult(s.result("unknown_outcome", { result: { exitCode: null } })),
  ).toEqual({ written: true });
  expect(await acceptFencedBinaryChunk({ ...s.chunk(1, 2, [3]), attempt: 2 })).toBe(false);
  expect(await acceptFencedBinaryChunk(s.chunk(1, 2, [3]))).toBe(true);
  expect(await s.page()).toMatchObject({ receivedBytes: 3, complete: false });

  // Final UNKNOWN commits the watermark; nothing reopens it, not even a replay.
  expect(
    await applyOperationResult(
      s.result("unknown_outcome", { receipt, result: { exitCode: null, outputBytes: 3 } }),
    ),
  ).toEqual({ written: true });
  expect(await acceptFencedBinaryChunk(s.chunk(2, 3, [4]))).toBe(false);
  expect(await acceptFencedBinaryChunk(input)).toBe(false);
  expect(await s.page()).toMatchObject({ complete: true, totalBytes: 3, state: "UNKNOWN_OUTCOME" });

  // A later exact receipt with the same total resolves the outcome.
  expect(
    await applyOperationResult(s.result("succeeded", { result: { stdout: "forbidden" } })),
  ).toEqual({ written: false });
  expect(
    await applyOperationResult(
      s.result("succeeded", { receipt, result: { exitCode: 0, outputBytes: 3 } }),
    ),
  ).toEqual({ written: true });
  const final = await s.page();
  expect(final).toMatchObject({ state: "SUCCEEDED", exitCode: 0, complete: true, gaps: [] });
  expect(Buffer.concat(final.chunks.map((c) => Buffer.from(c.data, "base64")))).toEqual(
    Buffer.from([1, 2, 3]),
  );
});

it("final result before the last chunk seals a trailing gap and refuses the late chunk", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [0xe2, 0x82]))).toBe(true);
  // The host reports 3 bytes; the third (0xac, completing "€") has not arrived.
  expect(
    await applyOperationResult(s.result("succeeded", { result: { exitCode: 7, outputBytes: 3 } })),
  ).toEqual({ written: true });
  // A total below the stored bytes can never commit.
  const rejected = await seed();
  expect(await acceptFencedBinaryChunk(rejected.chunk(0, 0, [1, 2]))).toBe(true);
  expect(
    await applyOperationResult(
      rejected.result("succeeded", { result: { exitCode: 0, outputBytes: 1 } }),
    ),
  ).toEqual({ written: false });

  expect(await acceptFencedBinaryChunk(s.chunk(1, 2, [0xac]))).toBe(false);
  const page = await s.page();
  expect(page).toMatchObject({
    state: "SUCCEEDED",
    exitCode: 7,
    complete: true,
    truncated: true,
    receivedBytes: 2,
    totalBytes: 3,
    gaps: [{ start: 2, end: 3 }],
    hasMore: false,
    nextCursor: "1_3",
  });
  expect(page.chunks).toEqual([{ stream: "stdout", offset: 0, data: "4oI=" }]);
  // Repeating the final cursor returns an empty page, never the bytes again.
  expect(await s.page(page.nextCursor)).toMatchObject({ chunks: [], gaps: [], offset: 3 });
});

it("stale-generation output is fenced and writes no rows", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1]))).toBe(true);
  await db.inspect.sandbox.update({ where: { id: s.sandbox.id }, data: { generation: 2 } });
  expect(await acceptFencedBinaryChunk(s.chunk(1, 1, [2]))).toBe(false);
  const header = (await s.rows()).header;
  expect(header).toMatchObject({ receivedEnd: 1n, nextSequence: 1 });
  expect((await s.rows()).segments).toBe(1);
});

it("retains the exact head and tail of a >1 MiB run in real PostgreSQL within bounded rows", async () => {
  const s = await seed();
  const frame = 8192;
  const produced = 1.25 * 1024 * 1024;
  let sequence = 0;
  for (let offset = 0; offset < produced; offset += frame) {
    const body = Array.from({ length: frame }, (_, i) => (offset + i) % 251);
    const input = s.chunk(sequence, offset, body, {
      flags: sequence % 2 ? { stderr: true } : { stdout: true },
    });
    sequence++;
    expect(await acceptFencedBinaryChunk(input)).toBe(true);
  }
  expect(
    await applyOperationResult(
      s.result("succeeded", { result: { exitCode: 0, outputBytes: produced } }),
    ),
  ).toEqual({ written: true });
  const { header, segments } = await s.rows();
  expect(header).toMatchObject({ headBytes: 256 * 1024, tailBytes: 768 * 1024 });
  expect(segments).toBe(128);
  const bytes: Buffer[] = [];
  const gaps: { start: number; end: number }[] = [];
  let cursor: string | undefined;
  for (let pages = 0; ; pages++) {
    expect(pages).toBeLessThan(40);
    const next = await s.page(cursor);
    for (const chunk of next.chunks) {
      expect(chunk.stream).toBe(Math.floor(chunk.offset / frame) % 2 ? "stderr" : "stdout");
      bytes.push(Buffer.from(chunk.data, "base64"));
    }
    gaps.push(...next.gaps);
    cursor = next.nextCursor;
    if (!next.hasMore) break;
  }
  const tailStart = produced - 768 * 1024;
  expect(gaps).toEqual([{ start: 256 * 1024, end: tailStart }]);
  const expected = Buffer.from(
    [
      ...Array.from({ length: 256 * 1024 }, (_, i) => i),
      ...Array.from({ length: 768 * 1024 }, (_, i) => tailStart + i),
    ].map((offset) => offset % 251),
  );
  expect(Buffer.concat(bytes).equals(expected)).toBe(true);
});

it("expires output 24 hours after completion with status intact; retention purges only expired rows (fake clock)", async () => {
  const s = await seed();
  const other = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1]))).toBe(true);
  expect(await acceptFencedBinaryChunk(other.chunk(0, 0, [2]))).toBe(true);
  expect(
    await applyOperationResult(s.result("failed", { result: { exitCode: 2, outputBytes: 1 } })),
  ).toEqual({ written: true });
  const completedAt = (
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: s.operation.id } })
  ).completedAt!;
  const expiry = new Date(completedAt.getTime() + 24 * HOUR);
  expect(await s.page(undefined, new Date(expiry.getTime() - 1))).toMatchObject({
    expiresAt: expiry.toISOString(),
    exitCode: 2,
  });
  await expect(s.page(undefined, expiry)).rejects.toMatchObject({
    status: 410,
    data: { code: "OUTPUT_EXPIRED" },
  });
  // Before expiry this output survives a sweep; at expiry it goes, while the
  // still-running operation's output stays. (Earlier tests in this file own
  // older completed rows, so counts are not asserted here.)
  await purgeExpiredCommandOutput(new Date(expiry.getTime() - 1));
  expect((await s.rows()).segments).toBe(1);
  expect(await purgeExpiredCommandOutput(expiry)).toBeGreaterThanOrEqual(1);
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  expect((await other.rows()).segments).toBe(1);
  // Status and exit code outlive the content; reads stay typed expiry, never empty success.
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: s.operation.id } }),
  ).toMatchObject({ state: "FAILED", result: { exitCode: 2, pid: 42, outputBytes: 1 } });
  await expect(s.page(undefined, expiry)).rejects.toMatchObject({ status: 410 });
});

it("a long-lived interim UNKNOWN cannot accept output past its retention", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1]))).toBe(true);
  expect(
    await applyOperationResult(s.result("unknown_outcome", { result: { exitCode: null } })),
  ).toEqual({ written: true });
  await db.inspect.sandboxOperation.update({
    where: { id: s.operation.id },
    data: { completedAt: new Date(Date.now() - 25 * HOUR) },
  });
  expect(await acceptFencedBinaryChunk(s.chunk(1, 1, [2]))).toBe(false);
  expect((await s.rows()).header).toMatchObject({ receivedEnd: 1n });
});

it("C26 a later exact receipt never extends the first completion's retention deadline", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1, 2]))).toBe(true);
  // The reconnect's interim UNKNOWN at T0 owns the retention deadline.
  expect(
    await applyOperationResult(
      s.result("unknown_outcome", { receipt, result: { exitCode: null, outputBytes: 2 } }),
    ),
  ).toEqual({ written: true });
  const interim = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: s.operation.id },
  });
  expect(interim.completedAt).not.toBeNull();
  await new Promise((resolve) => setTimeout(resolve, 5));
  // The host's exact receipt reconciles the outcome later; retention stays at T0.
  expect(
    await applyOperationResult(
      s.result("succeeded", { receipt, result: { exitCode: 0, outputBytes: 2 } }),
    ),
  ).toEqual({ written: true });
  const reconciled = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: s.operation.id },
  });
  expect(reconciled.state).toBe("SUCCEEDED");
  expect(reconciled.completedAt?.getTime()).toBe(interim.completedAt?.getTime());
  // Output expires from the first completion, not from the replay.
  const expiry = new Date(interim.completedAt!.getTime() + 24 * HOUR);
  expect(await s.page(undefined, new Date(expiry.getTime() - 1))).toMatchObject({
    receivedBytes: 2,
  });
  await expect(s.page(undefined, expiry)).rejects.toMatchObject({ status: 410 });
});

it("C26 output of a permanently superseded command reports completion", async () => {
  const s = await seed(); // still RUNNING
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1, 2]))).toBe(true);
  // A failed stop/kill retired this sandbox generation: no byte of this
  // dispatch can ever commit again, so the truncated output is complete.
  await db.inspect.sandbox.update({ where: { id: s.sandbox.id }, data: { generation: 2 } });
  expect(await acceptFencedBinaryChunk(s.chunk(1, 2, [3]))).toBe(false);
  expect(await s.page()).toMatchObject({ receivedBytes: 2, complete: true, totalBytes: null });
});
it("C26 real lifecycle supersession and reconciliation never restart retention, even already expired", async () => {
  const { killSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
  const { finishHostReconciliation } = await import("./operation-handlers.js");

  // A command completes UNKNOWN_OUTCOME at T0; that first completion owns the
  // output-retention deadline no matter how often later lifecycles supersede it.
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1, 2]))).toBe(true);
  const t0 = new Date();
  expect(
    await applyOperationResult(
      s.result("unknown_outcome", { receipt, result: { exitCode: null, outputBytes: 2 } }),
      () => t0,
    ),
  ).toEqual({ written: true });
  const owner = { kind: "session" as const, ownerId: s.id };
  // T1: a real lifecycle intent (kill) advances the generation and retires the
  // UNKNOWN command.
  await killSandbox(owner, { id: s.sandbox.id, idempotencyKey: `kill-a-${randomUUID()}` });
  const retired = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: s.operation.id },
  });
  expect(retired).toMatchObject({ state: "CANCEL_REQUESTED", errorCode: "superseded" });
  expect(retired.completedAt?.getTime()).toBe(t0.getTime());
  // T2: a repeated lifecycle (a retried kill) retires the retired row again —
  // the deadline still must not move.
  const { retireSupersededOperations } = await import("@wssp/api/sandbox/relay-fence");
  await db.inspect.$transaction(async (tx) => {
    await retireSupersededOperations(tx, s.id, s.sandbox.id, 99, new Date());
  });
  const retiredAgain = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: s.operation.id },
  });
  expect(retiredAgain).toMatchObject({ state: "CANCEL_REQUESTED", errorCode: "superseded" });
  expect(retiredAgain.completedAt?.getTime()).toBe(t0.getTime());

  // Host-inventory reconciliation of the retired, never-reported command must
  // not move the deadline either.
  await db.inspect.sandboxHost.update({
    where: { id: s.host.id },
    data: { connectionEpoch: 2 },
  });
  expect(
    await finishHostReconciliation({ userId: s.id, hostId: s.host.id, connectionEpoch: 2 }),
  ).toBe(true);
  const reconciled = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: s.operation.id },
  });
  expect(reconciled.state).toBe("UNKNOWN_OUTCOME");
  expect(reconciled.completedAt?.getTime()).toBe(t0.getTime());
  // Reads still answer against the T0 deadline.
  expect(await s.page(undefined, new Date(t0.getTime() + 24 * HOUR - 1))).toMatchObject({
    receivedBytes: 2,
  });
  await expect(s.page(undefined, new Date(t0.getTime() + 24 * HOUR))).rejects.toMatchObject({
    status: 410,
  });

  // Already expired at supersession time: retirement must not resurrect it.
  const old = await seed();
  expect(await acceptFencedBinaryChunk(old.chunk(0, 0, [9]))).toBe(true);
  const t0Expired = new Date(Date.now() - 25 * HOUR);
  expect(
    await applyOperationResult(
      old.result("unknown_outcome", { receipt, result: { exitCode: null, outputBytes: 1 } }),
      () => t0Expired,
    ),
  ).toEqual({ written: true });
  await killSandbox(
    { kind: "session", ownerId: old.id },
    { id: old.sandbox.id, idempotencyKey: `kill-c-${randomUUID()}` },
  );
  const retiredOld = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: old.operation.id },
  });
  expect(retiredOld).toMatchObject({ state: "CANCEL_REQUESTED", errorCode: "superseded" });
  expect(retiredOld.completedAt?.getTime()).toBe(t0Expired.getTime());
  await expect(old.page()).rejects.toMatchObject({
    status: 410,
    data: { code: "OUTPUT_EXPIRED" },
  });
  await purgeExpiredCommandOutput(new Date());
  expect(await old.rows()).toEqual({ header: null, segments: 0 });
});

// ── D3b: batched admission and negotiated chunk sizes ──

type Seeded = Awaited<ReturnType<typeof seed>>;
type ChunkInput = ReturnType<Seeded["chunk"]>;

function acceptBatch(
  s: Seeded,
  inputs: readonly ChunkInput[],
  options: { outputChunkBytes?: number; current?: () => boolean } = {},
) {
  return acceptFencedOutputBatch({
    sender: s.sender,
    operationId: s.operation.id,
    generation: inputs[0]?.generation ?? 1,
    attempt: inputs[0]?.attempt ?? 1,
    frames: inputs.map((input) => ({ metadata: input.output, body: input.body })),
    outputChunkBytes: options.outputChunkBytes,
    current: options.current ?? (() => true),
  });
}

/** Every stored row of one output, ids and owner keys left out. */
async function storedRows(operationId: string) {
  const header = await db.inspect.sandboxCommandOutput.findUniqueOrThrow({
    where: { id: operationId },
    select: {
      attempt: true,
      nextSequence: true,
      receivedEnd: true,
      totalBytes: true,
      headBytes: true,
      tailBytes: true,
      headSegments: true,
      tailSegments: true,
      recent: true,
    },
  });
  const segments = await db.inspect.sandboxCommandOutputSegment.findMany({
    where: { outputId: operationId },
    orderBy: { startOffset: "asc" },
    select: { tail: true, startOffset: true, endOffset: true, bytes: true, stderrMask: true },
  });
  return {
    header,
    segments: segments.map((row) => ({
      ...row,
      bytes: Buffer.from(row.bytes).toString("hex"),
      stderrMask: Buffer.from(row.stderrMask).toString("hex"),
    })),
  };
}

/** A varied stream: sizes up to `max`, both streams, a declared gap, crossing
 * the 256 KiB head boundary; `replayAt` repeats one chunk verbatim. */
function workload(s: Seeded, total: number, max: number) {
  const inputs: ChunkInput[] = [];
  let offset = 0;
  for (let sequence = 0; offset < total; sequence++) {
    const length = sequence % 5 === 3 ? 100 + sequence : max;
    const gap = sequence === 7 ? 1000 : 0;
    const body = Array.from({ length }, (_, i) => (offset + gap + i) % 251);
    inputs.push(
      s.chunk(sequence, offset + gap, body, {
        flags: sequence % 3 ? { stdout: true } : { stderr: true },
        ...(gap ? { gapStart: offset } : {}),
      }),
    );
    // The stored chunk keeps its stream bit too.
    offset += gap + length;
  }
  return inputs;
}

it("D3b a batch of queued chunks costs one transaction and stores byte-identical rows", async () => {
  const single = await seed();
  const batched = await seed();
  const singles = workload(single, 300 * 1024, 8192);
  const batches = workload(batched, 300 * 1024, 8192);
  // An exact retransmit inside a batch is acknowledged without storing twice.
  batches.splice(5, 0, batches[4]!);
  transactions.count = 0;
  for (const input of singles) expect(await acceptFencedBinaryChunk(input)).toBe(true);
  expect(transactions.count).toBe(singles.length);
  transactions.count = 0;
  for (let at = 0; at < batches.length; at += 16)
    expect(await acceptBatch(batched, batches.slice(at, at + 16))).toBe(true);
  expect(transactions.count).toBe(Math.ceil(batches.length / 16));
  expect(await storedRows(batched.operation.id)).toEqual(await storedRows(single.operation.id));
  const [a, b] = [await single.page(), await batched.page()];
  expect({ ...b, operationId: a.operationId }).toEqual(a);
});

it("D3b 64 KiB chunks are stored as the same 8 KiB segments as 8 KiB chunks, tail eviction included", async () => {
  const small = await seed();
  const large = await seed();
  const produced = 1.25 * 1024 * 1024;
  const block = 64 * 1024;
  const flags = (offset: number) =>
    Math.floor(offset / block) % 2 ? { stderr: true } : { stdout: true };
  const bytes = (offset: number, length: number) =>
    Array.from({ length }, (_, i) => (offset + i) % 253);
  for (let offset = 0, sequence = 0; offset < produced; offset += 8192, sequence++)
    expect(
      await acceptFencedBinaryChunk(
        small.chunk(sequence, offset, bytes(offset, 8192), { flags: flags(offset) }),
      ),
    ).toBe(true);
  const largeInputs: ChunkInput[] = [];
  for (let offset = 0, sequence = 0; offset < produced; offset += block, sequence++)
    largeInputs.push(large.chunk(sequence, offset, bytes(offset, block), { flags: flags(offset) }));
  // Half one at a time, half in one bounded batch.
  for (const input of largeInputs.slice(0, 10))
    expect(await acceptFencedBinaryChunk({ ...input, outputChunkBytes: block })).toBe(true);
  expect(await acceptBatch(large, largeInputs.slice(10), { outputChunkBytes: block })).toBe(true);
  const [a, b] = [await storedRows(small.operation.id), await storedRows(large.operation.id)];
  expect(b.segments).toEqual(a.segments);
  expect(b.segments).toHaveLength(128);
  const counters = ({ header }: typeof a) => ({
    ...header,
    nextSequence: undefined,
    recent: undefined,
  });
  expect(counters(b)).toEqual(counters(a));
  // An explicitly negotiated 8 KiB ceiling refuses a larger chunk.
  const bounded = await seed();
  await expect(
    acceptFencedBinaryChunk({
      ...bounded.chunk(0, 0, bytes(0, 8193), { flags: { stdout: true } }),
      outputChunkBytes: 8192,
    }),
  ).rejects.toThrow();
  expect(await bounded.rows()).toEqual({ header: null, segments: 0 });
});

it("D3b a batch commits whole or not at all: authority, fence and protocol refusals write nothing", async () => {
  const s = await seed();
  const inputs = [0, 1, 2, 3].map((n) => s.chunk(n, n, [n]));
  // The connection's authority ticket went stale before commit.
  let checks = 0;
  expect(
    await acceptBatch(s, inputs, {
      current: () => {
        checks += 1;
        return false;
      },
    }),
  ).toBe(false);
  expect(checks).toBe(1);
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  // A frame of another attempt never joins the batch.
  expect(
    await acceptBatch(s, [
      inputs[0]!,
      { ...inputs[1]!, output: { ...inputs[1]!.output, attempt: 2 } },
    ]),
  ).toBe(false);
  // A wrong sender epoch fails the shared fence.
  expect(await acceptBatch({ ...s, sender: { ...s.sender, connectionEpoch: 2 } }, inputs)).toBe(
    false,
  );
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  // An invalid cursor in the middle rolls back the chunks before it…
  await expect(acceptBatch(s, [inputs[0]!, inputs[1]!, inputs[3]!])).rejects.toThrow();
  expect(await s.rows()).toEqual({ header: null, segments: 0 });
  // …and the per-chunk replay the caller then runs keeps exactly the prefix.
  expect(await acceptFencedBinaryChunk(inputs[0]!)).toBe(true);
  expect(await acceptFencedBinaryChunk(inputs[1]!)).toBe(true);
  await expect(acceptFencedBinaryChunk(inputs[3]!)).rejects.toThrow();
  expect((await s.rows()).header).toMatchObject({ receivedEnd: 2n, nextSequence: 2 });
  // A sealed watermark refuses a batch exactly as it refuses one chunk.
  expect(
    await applyOperationResult(s.result("succeeded", { result: { exitCode: 0, outputBytes: 2 } })),
  ).toEqual({ written: true });
  expect(await acceptBatch(s, [inputs[2]!, inputs[3]!])).toBe(false);
  expect((await s.rows()).header).toMatchObject({ receivedEnd: 2n, totalBytes: 2n });
});

it("D3b micro-benchmark: fenced output admission, per chunk vs batched vs 64 KiB", async () => {
  const total = 1024 * 1024;
  const run = async (label: string, size: number, batch: number) => {
    const s = await seed();
    const inputs: ChunkInput[] = [];
    for (let offset = 0, sequence = 0; offset < total; offset += size, sequence++)
      inputs.push(
        s.chunk(
          sequence,
          offset,
          Array.from({ length: size }, (_, i) => i % 251),
        ),
      );
    const started = performance.now();
    for (let at = 0; at < inputs.length; at += batch)
      if (batch === 1)
        expect(await acceptFencedBinaryChunk({ ...inputs[at]!, outputChunkBytes: size })).toBe(
          true,
        );
      else
        expect(await acceptBatch(s, inputs.slice(at, at + batch), { outputChunkBytes: size })).toBe(
          true,
        );
    const seconds = (performance.now() - started) / 1000;
    const result = {
      label,
      chunksPerSecond: Math.round(inputs.length / seconds),
      kibPerSecond: Math.round(total / 1024 / seconds),
    };
    console.info("[D3b bench]", JSON.stringify(result));
    return result;
  };
  const perChunk = await run("8 KiB, one transaction per chunk", 8192, 1);
  const batched = await run("8 KiB, batches of 4 (one window)", 8192, 4);
  await run("8 KiB, batches of 16", 8192, 16);
  await run("64 KiB, one transaction per chunk", 65536, 1);
  const large = await run("64 KiB, batches of 4 (one window)", 65536, 4);
  // Throughput direction only; absolute numbers depend on the machine.
  expect(batched.kibPerSecond).toBeGreaterThan(perChunk.kibPerSecond);
  expect(large.kibPerSecond).toBeGreaterThan(perChunk.kibPerSecond);
});
