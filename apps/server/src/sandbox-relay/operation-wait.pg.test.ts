// Real-PostgreSQL proofs for operation long-poll wakeups (sdk-longpoll):
// the post-commit notification sees committed state from another connection,
// a rolled-back (fence-rejected) relay transaction never notifies, an output
// chunk wakes its waiter, and a held read answers right after the commit.
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { commandResultFixture } from "./command-result-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";

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
const db = await pgTestDatabase();
const { acceptFencedBinaryChunk, applyOperationResult } = await import("./operation-handlers.js");
const { readCommandOutputPage } = await import("@wssp/api/sandbox/command-output");
const waiters = await import("@wssp/api/sandbox/operation-waiters");
afterAll(() => db.close());
afterEach(() => {
  waiters.bindOperationChangeFanout(null);
  expect(waiters.operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
});

const receipt = { bodyHash: "a".repeat(64), idempotencyKey: "cmd", kind: "command.run" };

async function seed() {
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
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  const sender = { userId: id, hostId: host.id, connectionEpoch: 1 };
  const chunk = (sequence: number, offset: number, body: number[]) => ({
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
  const page = (cursor?: string) =>
    readCommandOutputPage({ ownerId: id, operationId: operation.id, cursor, now: new Date() });
  return { id, operation, chunk, result, page };
}

/** Record each post-commit notification for `operationId`, plus what another
 * connection reads at that instant. */
function recordNotifications(operationId: string) {
  const seen: Array<Promise<{ state: string | undefined; complete: boolean }>> = [];
  waiters.bindOperationChangeFanout((change) => {
    if (change !== "all" && !change.operationIds.has(operationId)) return;
    seen.push(
      (async () => {
        const [operation, output] = await Promise.all([
          db.inspect.sandboxOperation.findUnique({
            where: { id: operationId },
            select: { state: true },
          }),
          db.inspect.sandboxCommandOutput.findUnique({
            where: { id: operationId },
            select: { totalBytes: true },
          }),
        ]);
        return { state: operation?.state, complete: output?.totalBytes != null };
      })(),
    );
  });
  return seen;
}

it("notifies only after commit: another connection already sees the sealed terminal state", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [104, 105]))).toBe(true);
  const seen = recordNotifications(s.operation.id);
  // Parked inside the transaction right after its operation write.
  const gate = db.pauseAt("finish", { after: "sandboxOperation.updateMany" });
  const pending = db.run("finish", () =>
    applyOperationResult(s.result("succeeded", { result: { exitCode: 0, outputBytes: 2 } })),
  );
  await gate.waitReached();
  // Mid-transaction: nothing announced yet.
  expect(seen).toHaveLength(0);
  gate.release();
  expect(await pending).toEqual({ written: true });
  expect(seen.length).toBeGreaterThanOrEqual(1);
  // Every notification observed committed, sealed, terminal state.
  for (const observed of await Promise.all(seen))
    expect(observed).toEqual({ state: "SUCCEEDED", complete: true });
});

it("a fence-rejected relay transaction rolls back its operation write and notifies nothing", async () => {
  const s = await seed();
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1, 2]))).toBe(true);
  // A final UNKNOWN seals the watermark; a late chunk still passes the fence
  // lookup and CAS-writes the operation, then is refused at the sealed output.
  expect(
    await applyOperationResult(
      s.result("unknown_outcome", { receipt, result: { exitCode: null, outputBytes: 2 } }),
    ),
  ).toEqual({ written: true });
  const seen = recordNotifications(s.operation.id);
  const wrote = db.pauseAt("late", { after: "sandboxOperation.updateMany" });
  const late = db.run("late", () => acceptFencedBinaryChunk(s.chunk(1, 2, [3])));
  await wrote.waitReached(); // the operation row WAS written inside the transaction
  wrote.release();
  expect(await late).toBe(false);
  expect(seen).toHaveLength(0);
});

it("a committed output chunk wakes the operation's waiter", async () => {
  const s = await seed();
  const watch = waiters.watchOperation(s.operation.id, s.id);
  try {
    const woke = watch.wait(10_000);
    expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [1]))).toBe(true);
    expect(await woke).toBe("changed");
  } finally {
    watch.dispose();
  }
});

it("a held output read answers right after the commit, with the committed page", async () => {
  const s = await seed();
  const started = Date.now();
  const held = waiters.withOperationWait({
    ownerId: s.id,
    operationId: s.operation.id,
    waitMs: 20_000,
    read: () => s.page(),
    ready: (page) => page.complete || page.chunks.length > 0,
  });
  await new Promise((resolve) => setTimeout(resolve, 200));
  expect(await acceptFencedBinaryChunk(s.chunk(0, 0, [111, 107]))).toBe(true);
  const committedAt = Date.now();
  expect(
    await applyOperationResult(s.result("succeeded", { result: { exitCode: 0, outputBytes: 2 } })),
  ).toEqual({ written: true });
  const page = await held;
  const answeredAt = Date.now();
  expect(page.chunks.length + (page.complete ? 1 : 0)).toBeGreaterThan(0);
  expect(answeredAt - started).toBeGreaterThanOrEqual(200);
  // Woken by the commit, not by the 5 s recheck or the 20 s hold.
  expect(answeredAt - committedAt).toBeLessThan(2_000);
});
