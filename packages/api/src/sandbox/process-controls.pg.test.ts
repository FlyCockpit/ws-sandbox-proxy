import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import type { ProcessRef } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "./digest-context";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "./testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "ab".repeat(32), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const { charged } = vi.hoisted(() => ({
  charged: vi.fn(async (_owner: string, _family: string) => {}),
}));
vi.mock("./budgets", () => ({
  consumeCreateConnectBudget: vi.fn(),
  consumeSandboxWriteBudget: charged,
}));
const db = await pgTestDatabase();
const { writeStdinAction, cancelAction } = await import("./process-controls");
const { signalProcessAction } = await import("./process-signals");
const { getActionReceipt } = await import("./action-receipts");
const access = await import("../lib/sdk-key-access");
const digest = await import("./idempotency");
afterAll(() => db.close());
afterEach(() => {
  vi.restoreAllMocks();
  charged.mockReset();
});

async function seed() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, email: `${userId}@example.test`, name: "Owner", twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
    },
  });
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: {
      journalKeyVersion: 1,
      journalKeyId: digest.requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "READY",
      liveResourcesHeld: true,
    },
  });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "RUN_COMMAND",
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      processId: randomUUID(),
      processPid: 42,
      processBootId: randomUUID(),
      processStartTicks: "123",
      processStartedAt: new Date(),
      resultVersion: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      ...digest.requestDigestMetadata(),
    },
  });
  const owner = { kind: "session" as const, ownerId: userId };
  const ref: ProcessRef = {
    sandboxId: sandbox.id,
    generation: 1,
    processId: operation.processId!,
    pid: 42,
    attempt: 1,
  };
  const write = (idempotencyKey = randomUUID(), eof = false) => ({
    operationId: operation.id,
    idempotencyKey,
    contentBase64: Buffer.from("input").toString("base64"),
    eof,
  });
  const key = async () => {
    const row = await db.inspect.sdkKey.create({
      data: {
        userId,
        name: "control",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        resourceMode: "ALL_OWNED",
        scopes: ["commands:execute", "operations:cancel", "operations:read"],
      },
    });
    const principal = await access.revalidateSdkKey(row.id, userId);
    if (!principal) throw new Error("Fixture refused");
    return principal;
  };
  return { owner, host, sandbox, operation, ref, write, key };
}
async function counts(f: Awaited<ReturnType<typeof seed>>) {
  return {
    receipts: await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } }),
    effects: await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.stdin_requested" },
    }),
    sequence: (
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })
    ).nextStdinSequence,
  };
}

it.each([
  "sandboxOperation.update",
  "outboxEvent.create",
  "sandboxActionReceipt.create",
  "$transaction.commit",
])("stdin rollback after %s leaves no receipt, sequence or effect", async (stage) => {
  const f = await seed();
  const gate = db.pauseAt(
    "write",
    stage === "$transaction.commit" ? { before: stage } : { after: stage },
  );
  const pending = db.run("write", () => writeStdinAction(f.owner, f.write()));
  const assertion = expect(pending).rejects.toBeDefined();
  await gate.waitReached();
  gate.fail(new Error("injected rollback"));
  await assertion;
  expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
});

it("racing identical stdin accepts have exactly one receipt and effect; bidirectional aliases replay", async () => {
  const f = await seed();
  const input = f.write();
  const held = db.pauseAt("first", { before: "$transaction.commit" });
  const first = db.run("first", () => writeStdinAction(f.owner, input));
  await held.waitReached();
  const second = db.run("second", () =>
    writeStdinAction(f.owner, { ...input, operationId: undefined, process: f.ref }),
  );
  expect((await db.waitUntilBlocked("second", { by: "first" })).query).toMatch(
    /pg_advisory_xact_lock/,
  );
  held.release();
  const receipt = await first;
  expect(await second).toEqual(receipt);
  expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
  const pidFirst = { ...f.write(), operationId: undefined, process: f.ref };
  const pidReceipt = await writeStdinAction(f.owner, pidFirst);
  expect(
    await writeStdinAction(f.owner, {
      ...pidFirst,
      process: undefined,
      operationId: f.operation.id,
    }),
  ).toEqual(pidReceipt);
});

it("EOF is sequenced once, replays freely, rejects later EOF/data; last counter cannot wrap", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { nextStdinSequence: 2_147_483_646 },
  });
  const input = { ...f.write(undefined, true), contentBase64: "" };
  const receipt = await writeStdinAction(f.owner, input);
  expect(receipt.state).toBe("SUCCEEDED");
  expect(await writeStdinAction(f.owner, input)).toEqual(receipt);
  for (const eof of [true, false])
    await expect(writeStdinAction(f.owner, f.write(undefined, eof))).rejects.toMatchObject({
      data: { code: "sandbox.process_stdin_closed" },
    });
  expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 2_147_483_647 });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { stdinClosed: false },
  });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({ code: "CONFLICT" });
});

it.each(["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"] as const)(
  "stdin acceptance remains SUCCEEDED after target %s",
  async (state) => {
    const f = await seed();
    const input = f.write();
    const receipt = await writeStdinAction(f.owner, input);
    await db.inspect.sandboxOperation.update({ where: { id: f.operation.id }, data: { state } });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED", connectionEpoch: 2 },
    });
    expect(
      await writeStdinAction(f.owner, { ...input, operationId: undefined, process: f.ref }),
    ).toEqual(receipt);
    expect(await getActionReceipt(f.owner, { id: receipt.operationId })).toMatchObject({
      state: "SUCCEEDED",
      outcome: "succeeded",
    });
    await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
      data: {
        code:
          state === "UNKNOWN_OUTCOME"
            ? "sandbox.process_unknown_outcome"
            : "sandbox.process_exited",
      },
    });
    expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
  },
);

it.each([
  "disconnect",
  "epoch",
  "CANCEL_REQUESTED",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
  "generation",
] as const)(
  "kill/cancel replay in BOTH directions after %s never reissues effect",
  async (change) => {
    for (const pidFirst of [true, false]) {
      const f = await seed();
      const idempotencyKey = randomUUID();
      const pid = { process: f.ref, idempotencyKey };
      const op = { operationId: f.operation.id, idempotencyKey };
      const receipt = await (pidFirst
        ? signalProcessAction(f.owner, { ...pid, signal: "SIGKILL" })
        : cancelAction(f.owner, op));
      if (change === "disconnect" || change === "epoch")
        await db.inspect.sandboxHost.update({
          where: { id: f.host.id },
          data: { status: "DISCONNECTED", connectionEpoch: change === "epoch" ? 2 : 1 },
        });
      else if (change === "generation")
        await db.inspect.sandbox.update({
          where: { id: f.sandbox.id },
          data: { generation: 2, state: "STOPPED" },
        });
      else
        await db.inspect.sandboxOperation.update({
          where: { id: f.operation.id },
          data: { state: change },
        });
      expect(
        await (pidFirst
          ? cancelAction(f.owner, op)
          : signalProcessAction(f.owner, { ...pid, signal: "SIGKILL" })),
      ).toEqual(receipt);
      expect(
        await db.inspect.outboxEvent.count({
          where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
        }),
      ).toBe(1);
    }
  },
);

it.each([
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
] as const)(
  "resolved kill accepts offline/replaced epoch target %s without inventing completion",
  async (state) => {
    const f = await seed();
    await db.inspect.sandboxOperation.update({ where: { id: f.operation.id }, data: { state } });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED", connectionEpoch: 2 },
    });
    const receipt = await cancelAction(f.owner, { process: f.ref, idempotencyKey: randomUUID() });
    expect(receipt.state).toBe(
      ["DISPATCHED", "ACCEPTED", "RUNNING"].includes(state) ? "CANCEL_REQUESTED" : state,
    );
    expect(
      await db.inspect.outboxEvent.count({
        where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
      }),
    ).toBe(["DISPATCHED", "ACCEPTED", "RUNNING"].includes(state) ? 1 : 0);
  },
);

it("unstarted PID cannot invent identity; operation-ID cancellation/replay recovers queued work", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: {
      state: "QUEUED",
      dispatchAttempt: 0,
      acceptedAttempt: null,
      processPid: null,
      processBootId: null,
      processStartTicks: null,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    },
  });
  const key = randomUUID();
  await expect(
    cancelAction(f.owner, { process: f.ref, idempotencyKey: key }),
  ).rejects.toMatchObject({ data: { code: "sandbox.process_not_started" } });
  const op = { operationId: f.operation.id, idempotencyKey: key };
  expect(await cancelAction(f.owner, op)).toMatchObject({ state: "CANCELLED" });
  expect(await cancelAction(f.owner, op)).toMatchObject({ state: "CANCELLED" });
  await expect(
    cancelAction(f.owner, { process: f.ref, idempotencyKey: key }),
  ).rejects.toMatchObject({ data: { code: "sandbox.process_not_started" } });
});

it.each(["pid", "attempt", "generation", "processId", "sandboxId"] as const)(
  "exact reference rejects mismatched %s on fresh and replay",
  async (field) => {
    const f = await seed();
    const input = f.write();
    await writeStdinAction(f.owner, input);
    const ref = {
      ...f.ref,
      [field]: typeof f.ref[field] === "number" ? Number(f.ref[field]) + 1 : randomUUID(),
    };
    for (const key of [input.idempotencyKey, randomUUID()])
      await expect(
        writeStdinAction(f.owner, {
          process: ref,
          idempotencyKey: key,
          contentBase64: input.contentBase64,
        }),
      ).rejects.toMatchObject({
        data: {
          code:
            key === input.idempotencyKey && (field === "processId" || field === "sandboxId")
              ? "sandbox.idempotency_conflict"
              : "sandbox.process_not_found",
        },
      });
    expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
  },
);

it("new stale, epoch-replaced, pending, and disconnected stdin refuse without receipt or bytes", async () => {
  const f = await seed();
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { generation: 2 } });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
    data: { code: "sandbox.process_stale" },
  });
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { generation: 1 } });
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { connectionEpoch: 2 } });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
    data: { code: "sandbox.process_unknown_outcome" },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: 1, status: "DISCONNECTED" },
  });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
    data: { code: "sandbox.process_unavailable" },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { state: "CANCEL_REQUESTED" },
  });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
    data: { code: "sandbox.process_cancel_pending" },
  });
  expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
});

it("other control principal is refused BEFORE digest; revocation fences replay", async () => {
  const f = await seed();
  const first = await f.key();
  const other = await f.key();
  const input = f.write();
  await writeStdinAction(first, input);
  const hashed = vi.spyOn(digest, "hashRequestBody");
  await expect(writeStdinAction(other, input)).rejects.toMatchObject({
    data: { code: "sandbox.idempotency_conflict" },
  });
  expect(hashed).not.toHaveBeenCalled();
  await db.inspect.sdkKey.update({ where: { id: first.keyId }, data: { revokedAt: new Date() } });
  await expect(writeStdinAction(first, input)).rejects.toMatchObject({ code: "FORBIDDEN" });
});

it.each(["same", "other"] as const)(
  "P2002 control recovery rolls back sequence/outbox and binds the %s winning principal in a NEW transaction",
  async (winner) => {
    const f = await seed();
    const principal = await f.key();
    const other = await f.key();
    const input = f.write();
    const gate = db.pauseAt("loser", { before: "sandboxActionReceipt.create" });
    const pending = db
      .run("loser", () => writeStdinAction(principal, input))
      .then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
    await gate.waitReached();
    const accepted = await db.inspect.sandboxActionReceipt.create({
      data: {
        digestContext: digestContextSnapshot(
          { domain: "wssp-action-v1", hostId: f.host.id, hostOwnerId: f.owner.ownerId },
          { generation: 1 },
        ),

        userId: f.owner.ownerId,
        idempotencyKey: input.idempotencyKey,
        authorizingKeyId: winner === "same" ? principal.keyId : other.keyId,
        action: "commands.writeStdin",
        targetOperationId: f.operation.id,
        sandboxId: f.sandbox.id,
        hostId: f.host.id,
        templateRevisionId: f.sandbox.templateRevisionId,
        generation: 1,
        requestBodyHash: digest.hashRequestBody(
          {
            action: "commands.writeStdin",
            targetOperationId: f.operation.id,
            contentBase64: input.contentBase64,
            eof: false,
          },
          {
            domain: "wssp-action-v1",
            ownerId: f.owner.ownerId,
            hostOwnerId: f.owner.ownerId,
            hostId: f.host.id,
            authorizingKeyId: principal.keyId,
          },
        ),
        ...digest.requestDigestMetadata(),
        state: "SUCCEEDED",
      },
    });
    const hashed = vi.spyOn(digest, "hashRequestBody");
    gate.release();
    const result = await pending;
    if (winner === "same")
      expect(result).toEqual({ value: { operationId: accepted.id, state: "SUCCEEDED" } });
    else {
      expect(result).toMatchObject({ error: { data: { code: "sandbox.idempotency_conflict" } } });
      expect(hashed).not.toHaveBeenCalled();
    }
    expect(await counts(f)).toEqual({ receipts: 1, effects: 0, sequence: 0 });
  },
);

it("sequential replays are free across aliases; racing misses may charge twice but have ONE receipt/effect", async () => {
  const f = await seed();
  const input = f.write();
  let arrivals = 0;
  let release: () => void = () => {};
  const bothCharged = new Promise<void>((resolve) => {
    release = resolve;
  });
  charged.mockImplementation(async () => {
    if (++arrivals === 2) release();
    await bothCharged;
  });
  const [a, b] = await Promise.all([
    writeStdinAction(f.owner, input),
    writeStdinAction(f.owner, { ...input, operationId: undefined, process: f.ref }),
  ]);
  expect(a).toEqual(b);
  expect(charged).toHaveBeenCalledTimes(2);
  expect(charged.mock.calls.map((call) => call[1])).toEqual(["stdin", "stdin"]);
  expect(await writeStdinAction(f.owner, input)).toEqual(a);
  expect(charged).toHaveBeenCalledTimes(2);
  expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
});

it("saturated stdin, ordinary and content quotas still admit command termination; non-command cancel is ordinary", async () => {
  const f = await seed();
  const observation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.owner.ownerId,
      sandboxId: f.sandbox.id,
      kind: "STAT_PATH",
      generation: 1,
      state: "QUEUED",
      idempotencyKey: randomUUID(),
      requestBodyHash: "b".repeat(64),
    },
  });
  await db.inspect.sandboxOperationResult.create({
    data: {
      operationId: observation.id,
      sandboxId: f.sandbox.id,
      userId: f.owner.ownerId,
      generation: 1,
      attempt: 0,
      version: 1,
      expiresAt: new Date(Date.now() + 60_000),
      reservationBytes: 33_554_432,
    },
  });
  charged.mockImplementation(async (_owner, family) => {
    if (family !== "termination") throw new ORPCError("TOO_MANY_REQUESTS");
  });
  await expect(writeStdinAction(f.owner, f.write())).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  const { runCommand, statPath } = await import("./services/sandboxes");
  for (const call of [
    () => runCommand(f.owner, { id: f.sandbox.id, idempotencyKey: randomUUID(), argv: ["true"] }),
    () => statPath(f.owner, { id: f.sandbox.id, path: "/", idempotencyKey: randomUUID() }),
  ])
    await expect(call()).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  await expect(
    cancelAction(f.owner, { operationId: observation.id, idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  const input = { process: f.ref, idempotencyKey: randomUUID() };
  const receipt = await cancelAction(f.owner, input);
  expect(receipt.state).toBe("CANCEL_REQUESTED");
  expect(charged.mock.calls.map((call) => call[1])).toEqual([
    "stdin",
    "ordinary",
    "ordinary",
    "ordinary",
    "termination",
  ]);
  expect(
    await cancelAction(f.owner, {
      operationId: f.operation.id,
      idempotencyKey: input.idempotencyKey,
    }),
  ).toEqual(receipt);
  expect(charged).toHaveBeenCalledTimes(5);
});

it("each procedure in an RPC batch charges independently; command and file durable replays are free", async () => {
  const f = await seed();
  const { runCommand, statPath } = await import("./services/sandboxes");
  const input = { id: f.sandbox.id, idempotencyKey: randomUUID(), argv: ["true"] };
  const first = await runCommand(f.owner, input);
  expect(await runCommand(f.owner, input)).toEqual(first);
  const file = { id: f.sandbox.id, path: "/", idempotencyKey: randomUUID() };
  const accepted = await statPath(f.owner, file);
  expect(await statPath(f.owner, file)).toEqual(accepted);
  const inputs = [f.write(), f.write(), f.write()];
  await Promise.all(inputs.map((body) => writeStdinAction(f.owner, body)));
  expect(charged.mock.calls.map((call) => call[1])).toEqual([
    "ordinary",
    "ordinary",
    "stdin",
    "stdin",
    "stdin",
  ]);
  expect(await counts(f)).toEqual({ receipts: 3, effects: 3, sequence: 3 });
});

it("acceptance takes owner → key advisory → control K → H → S → O before DB time", async () => {
  const f = await seed();
  const principal = await f.key();
  const held = db.pauseAt("holder", { before: "$transaction.commit" });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id=${principal.keyId} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const accepting = db.run("accept", () => writeStdinAction(principal, f.write()));
  expect((await db.waitUntilBlocked("accept", { by: "holder" })).query).toMatch(
    /sdk_key.*FOR SHARE/,
  );
  await db.inspect.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id=${f.host.id} FOR UPDATE NOWAIT`;
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id=${f.sandbox.id} FOR UPDATE NOWAIT`;
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id=${f.operation.id} FOR UPDATE NOWAIT`;
  });
  const clock = db.pauseAt("accept", { before: /clock_timestamp/ });
  held.release();
  await holder;
  await clock.waitReached();
  for (const [table, id] of [
    ["sandbox_host", f.host.id],
    ["sandbox_instance", f.sandbox.id],
    ["sandbox_mutation_operation", f.operation.id],
  ] as const) {
    await expect(
      db.inspect.$queryRawUnsafe(`SELECT id FROM ${table} WHERE id=$1 FOR UPDATE NOWAIT`, id),
    ).rejects.toBeDefined();
  }
  clock.release();
  await accepting;
});

it("target completion and stdin acceptance serialize at O; completion wins without a receipt", async () => {
  const f = await seed();
  const held = db.pauseAt("exit", { before: "$transaction.commit" });
  const exit = db.run("exit", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id=${f.sandbox.id} FOR NO KEY UPDATE`;
      await tx.sandboxOperation.update({
        where: { id: f.operation.id },
        data: { state: "SUCCEEDED" },
      });
    }),
  );
  await held.waitReached();
  const writing = db.run("write", () => writeStdinAction(f.owner, f.write()));
  const rejected = expect(writing).rejects.toMatchObject({
    data: { code: "sandbox.process_exited" },
  });
  expect((await db.waitUntilBlocked("write", { by: "exit" })).query).toMatch(/sandbox_instance/);
  held.release();
  await exit;
  await rejected;
  expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
});

it("account deletion serializes acceptance; deletion-first rejects, acceptance-first leaves atomic descendants", async () => {
  for (const deletionFirst of [true, false]) {
    const f = await seed();
    if (deletionFirst) {
      const held = db.pauseAt("delete", { before: "$transaction.commit" });
      const deletion = db.run("delete", () =>
        db.prisma.$transaction(async (tx) => {
          await tx.user.update({
            where: { id: f.owner.ownerId },
            data: { deletionRequestedAt: new Date() },
          });
        }),
      );
      await held.waitReached();
      const writing = db.run("write", () => writeStdinAction(f.owner, f.write()));
      const rejection = expect(writing).rejects.toMatchObject({ code: "CONFLICT" });
      expect((await db.waitUntilBlocked("write", { by: "delete" })).query).toMatch(
        /user.*FOR SHARE/,
      );
      held.release();
      await deletion;
      await rejection;
      expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
    } else {
      const held = db.pauseAt("write", { before: "$transaction.commit" });
      const writing = db.run("write", () => writeStdinAction(f.owner, f.write()));
      await held.waitReached();
      const deletion = db.run("delete", () =>
        db.prisma.$transaction(async (tx) => {
          await tx.user.update({
            where: { id: f.owner.ownerId },
            data: { deletionRequestedAt: new Date() },
          });
        }),
      );
      expect((await db.waitUntilBlocked("delete", { by: "write" })).query).toMatch(/UPDATE.*user/);
      held.release();
      await writing;
      await deletion;
      expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
    }
  }
});

it("canceling a signal or observation operation cannot cancel the referenced command", async () => {
  const f = await seed();
  for (const kind of ["LIST_PROCESSES", "SIGNAL_PROCESS"] as const) {
    const control = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.owner.ownerId,
        sandboxId: f.sandbox.id,
        generation: 1,
        kind,
        state: "QUEUED",
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
        result: { targetOperationId: f.operation.id },
      },
    });
    expect(
      await cancelAction(f.owner, { operationId: control.id, idempotencyKey: randomUUID() }),
    ).toMatchObject({ state: "CANCELLED" });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }))
        .state,
    ).toBe("RUNNING");
  }
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(0);
});

it("enabled internal signal conformance creates a distinct SIGNAL_PROCESS with its OWN principal; cancel never targets the command", async () => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionRuntime: "FAKE",
      admissionEpoch: 1,
    },
  });
  const creator = await f.key();
  const controller = await f.key();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { authorizingKeyId: creator.keyId },
  });
  await db.inspect.sdkKey.update({ where: { id: creator.keyId }, data: { revokedAt: new Date() } });
  const input = { process: f.ref, signal: "SIGTERM" as const, idempotencyKey: randomUUID() };
  const result = await signalProcessAction(controller, input);
  expect(result.operationId).not.toBe(f.operation.id);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: result.operationId } }),
  ).toMatchObject({ kind: "SIGNAL_PROCESS", authorizingKeyId: controller.keyId });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.owner.ownerId, eventType: "sandbox.process_signal_requested" },
  });
  expect(event.payload).toMatchObject({
    operationId: result.operationId,
    targetOperationId: f.operation.id,
    process: f.ref,
    authorizingPrincipal: { kind: "sdkKey", keyId: controller.keyId },
  });
  expect(
    await cancelAction(f.owner, { operationId: result.operationId, idempotencyKey: randomUUID() }),
  ).toMatchObject({ state: "CANCELLED" });
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })).state,
  ).toBe("RUNNING");
  expect(charged.mock.calls.map((call) => call[1])).toEqual(["termination", "ordinary"]);
  expect(await signalProcessAction(controller, input)).toEqual({
    operationId: result.operationId,
    state: "CANCELLED",
  });
  expect(charged).toHaveBeenCalledTimes(2);
});

it("malformed selectors cannot turn an undefined operation ID into an owned first-row control", async () => {
  const f = await seed();
  for (const target of [
    {},
    { operationId: "" },
    { operationId: f.operation.id, process: f.ref },
    { process: null },
  ]) {
    await expect(
      cancelAction(f.owner, { ...target, idempotencyKey: randomUUID() } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  }
  expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })).state,
  ).toBe("RUNNING");
});

it("unknown signal names refuse before control acceptance even in enabled conformance", async () => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionRuntime: "FAKE",
      admissionEpoch: 1,
    },
  });
  await expect(
    signalProcessAction(f.owner, {
      process: f.ref,
      idempotencyKey: randomUUID(),
      signal: "SIGUSR1" as never,
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
  expect(charged).not.toHaveBeenCalled();
});

it("EOF-only aliases share a receipt and reject new EOF/data at ordinary sequence counters", async () => {
  const f = await seed();
  const idempotencyKey = randomUUID();
  const input = { process: f.ref, idempotencyKey, contentBase64: "", eof: true };
  const receipt = await writeStdinAction(f.owner, input);
  await expect(
    writeStdinAction(f.owner, {
      operationId: f.operation.id,
      idempotencyKey,
      contentBase64: "",
      eof: true,
    }),
  ).resolves.toEqual(receipt);
  for (const next of [
    { contentBase64: "", eof: true },
    { contentBase64: Buffer.from("late input").toString("base64"), eof: false },
  ])
    await expect(
      writeStdinAction(f.owner, {
        ...next,
        operationId: f.operation.id,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ data: { code: "sandbox.process_stdin_closed" } });
  expect(await counts(f)).toEqual({ receipts: 1, effects: 1, sequence: 1 });
});

it("accepted kill alias replay precedes fresh state/epoch admission", async () => {
  const f = await seed();
  const idempotencyKey = randomUUID();
  const receipt = await cancelAction(f.owner, { process: f.ref, idempotencyKey });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { state: "UNKNOWN_OUTCOME" },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: 2, status: "DISCONNECTED" },
  });
  await expect(
    cancelAction(f.owner, { operationId: f.operation.id, idempotencyKey }),
  ).resolves.toEqual(receipt);
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
});

it("a fresh resolved kill accepts a disconnected host without a connectivity refusal", async () => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { status: "DISCONNECTED" },
  });
  await expect(
    cancelAction(f.owner, { process: f.ref, idempotencyKey: randomUUID() }),
  ).resolves.toMatchObject({ state: "CANCEL_REQUESTED" });
});

it("SIGKILL/PID kill and operation cancel charge ONE termination family with free cross-alias replay", async () => {
  const f = await seed();
  const idempotencyKey = randomUUID();
  const receipt = await signalProcessAction(f.owner, {
    process: f.ref,
    idempotencyKey,
    signal: "SIGKILL",
  });
  await expect(
    cancelAction(f.owner, { operationId: f.operation.id, idempotencyKey }),
  ).resolves.toEqual(receipt);
  await expect(
    signalProcessAction(f.owner, { process: f.ref, idempotencyKey, signal: "SIGKILL" }),
  ).resolves.toEqual(receipt);
  expect(charged.mock.calls).toEqual([[f.owner.ownerId, "termination"]]);
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } })).toBe(
    1,
  );
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
});

it.each(["stdin", "cancel", "signal"] as const)(
  "ungranted %s refuses identically before PID, generation, start or version disclosure",
  async (action) => {
    const f = await seed();
    const principal = await f.key();
    await db.inspect.sdkKey.update({
      where: { id: principal.keyId },
      data: { resourceMode: "ALLOWLIST" },
    });
    const call = (process: ProcessRef) => {
      const input = { process, idempotencyKey: randomUUID() };
      return action === "stdin"
        ? writeStdinAction(principal, { ...input, contentBase64: f.write().contentBase64 })
        : action === "cancel"
          ? cancelAction(principal, input)
          : signalProcessAction(principal, { ...input, signal: "SIGTERM" });
    };
    let refusal: unknown;
    for (const variant of ["exact", "pid", "generation", "unstarted", "legacy"]) {
      await db.inspect.sandboxOperation.update({
        where: { id: f.operation.id },
        data: {
          processPid: variant === "unstarted" ? null : 42,
          processBootId: variant === "unstarted" ? null : f.operation.processBootId,
          processStartTicks: variant === "unstarted" ? null : "123",
          resultVersion: variant === "legacy" ? null : 1,
        },
      });
      const ref = {
        ...f.ref,
        ...(variant === "pid" ? { pid: 43 } : {}),
        ...(variant === "generation" ? { generation: 2 } : {}),
      };
      const error: unknown = await call(ref).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ORPCError);
      if (!(error instanceof ORPCError)) throw new Error("Expected refusal");
      const response = {
        code: error.code,
        status: error.status,
        message: error.message,
        data: error.data,
      };
      expect(response).toMatchObject({ code: "FORBIDDEN" });
      if (refusal === undefined) refusal = response;
      expect(response).toEqual(refusal);
    }
    expect(charged).not.toHaveBeenCalled();
    expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
  },
);

it.each(["stdin", "cancel"] as const)(
  "same-key %s different-target replay conflicts before target validation",
  async (action) => {
    const f = await seed();
    const idempotencyKey = randomUUID();
    const first = { operationId: f.operation.id, idempotencyKey };
    if (action === "stdin")
      await writeStdinAction(f.owner, { ...first, contentBase64: f.write().contentBase64 });
    else await cancelAction(f.owner, first);
    const other = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.owner.ownerId,
        sandboxId: f.sandbox.id,
        generation: 1,
        kind: "RUN_COMMAND",
        processId: randomUUID(),
        resultVersion: null,
        idempotencyKey: randomUUID(),
        requestBodyHash: "b".repeat(64),
      },
    });
    for (const target of [
      { process: { ...f.ref, processId: other.processId!, pid: 999, generation: 2 } },
      { process: { ...f.ref, processId: randomUUID() } },
      { operationId: other.id },
      { operationId: randomUUID() },
    ]) {
      const input = { ...target, idempotencyKey };
      await expect(
        action === "stdin"
          ? writeStdinAction(f.owner, { ...input, contentBase64: f.write().contentBase64 })
          : cancelAction(f.owner, input),
      ).rejects.toMatchObject({ data: { code: "sandbox.idempotency_conflict" } });
    }
    expect(charged).toHaveBeenCalledTimes(1);
  },
);

it.each(["", Buffer.from("initial input").toString("base64")])(
  "initial stdin persists EOF; subsequent data and EOF refuse without receipts (%#)",
  async (stdinBase64) => {
    const f = await seed();
    const { runCommand } = await import("./services/sandboxes");
    const accepted = await runCommand(f.owner, {
      id: f.sandbox.id,
      argv: ["cat"],
      stdinBase64,
      idempotencyKey: randomUUID(),
    });
    // Simulate the accepted command's proven dispatch, without guest IO.
    await db.inspect.sandboxOperation.update({
      where: { id: accepted.operationId },
      data: {
        state: "RUNNING",
        dispatchAttempt: 1,
        acceptedAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 1,
        processPid: 43,
        processBootId: randomUUID(),
        processStartTicks: "456",
        processStartedAt: new Date(),
      },
    });
    const row = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: accepted.operationId },
    });
    expect(row).toMatchObject({ stdinClosed: true, nextStdinSequence: 1 });
    for (const eof of [false, true]) {
      await expect(
        writeStdinAction(f.owner, {
          operationId: accepted.operationId,
          idempotencyKey: randomUUID(),
          contentBase64: eof ? "" : f.write().contentBase64,
          eof,
        }),
      ).rejects.toMatchObject({ data: { code: "sandbox.process_stdin_closed" } });
    }
    expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }))
        .nextStdinSequence,
    ).toBe(1);
  },
);

it.each(["STAT_PATH", "LIST_PROCESSES", "SIGNAL_PROCESS"] as const)(
  "cancel of stale non-command %s returns a state conflict",
  async (kind) => {
    const f = await seed();
    const target = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.owner.ownerId,
        sandboxId: f.sandbox.id,
        generation: 1,
        kind,
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "b".repeat(64),
      },
    });
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { generation: 2 } });
    await expect(
      cancelAction(f.owner, { operationId: target.id, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "sandbox.state_conflict" },
    });
    expect(await counts(f)).toEqual({ receipts: 0, effects: 0, sequence: 0 });
  },
);

it.each(
  ["cancel", "kill"].flatMap((alias) =>
    [
      "sandboxOperation.updateMany",
      "outboxEvent.create",
      "sandboxActionReceipt.create",
      "$transaction.commit",
    ].map((stage) => ({ alias, stage })),
  ),
)(
  "$alias rollback after $stage leaves no receipt, cancel transition or effect",
  async ({ alias, stage }) => {
    const f = await seed();
    const before = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    });
    const gate = db.pauseAt(
      "cancel",
      stage === "$transaction.commit" ? { before: stage } : { after: stage },
    );
    const pending = db.run("cancel", () =>
      alias === "kill"
        ? signalProcessAction(f.owner, {
            process: f.ref,
            signal: "SIGKILL",
            idempotencyKey: randomUUID(),
          })
        : cancelAction(f.owner, { operationId: f.operation.id, idempotencyKey: randomUUID() }),
    );
    const assertion = expect(pending).rejects.toBeDefined();
    await gate.waitReached();
    gate.fail(new Error("injected cancel rollback"));
    await assertion;
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toEqual(before);
    expect(
      await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } }),
    ).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.owner.ownerId } })).toBe(0);
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } }))
        .liveResourcesHeld,
    ).toBe(true);
  },
);

it("cancel of an already-dispatched SIGNAL_PROCESS targets only the control; its PID alias conflicts", async () => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionRuntime: "FAKE",
      admissionEpoch: 1,
    },
  });
  const signal = await signalProcessAction(f.owner, {
    process: f.ref,
    signal: "SIGTERM",
    idempotencyKey: randomUUID(),
  });
  await db.inspect.sandboxOperation.update({
    where: { id: signal.operationId },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  const idempotencyKey = randomUUID();
  expect(
    await cancelAction(f.owner, { operationId: signal.operationId, idempotencyKey }),
  ).toMatchObject({ state: "CANCEL_REQUESTED" });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
  });
  expect(event.payload).toMatchObject({
    operationId: signal.operationId,
    kind: "operation.cancel",
  });
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })).state,
  ).toBe("RUNNING");
  await expect(cancelAction(f.owner, { process: f.ref, idempotencyKey })).rejects.toMatchObject({
    data: { code: "sandbox.idempotency_conflict" },
  });
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } })).toBe(
    1,
  );
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
});

it("racing first kill aliases charge twice but commit one receipt and one cancel effect", async () => {
  const f = await seed();
  let arrivals = 0;
  let release: () => void = () => {};
  const bothCharged = new Promise<void>((resolve) => {
    release = resolve;
  });
  charged.mockImplementation(async () => {
    if (++arrivals === 2) release();
    await bothCharged;
  });
  const idempotencyKey = randomUUID();
  const [a, b] = await Promise.all([
    cancelAction(f.owner, { operationId: f.operation.id, idempotencyKey }),
    signalProcessAction(f.owner, { process: f.ref, signal: "SIGKILL", idempotencyKey }),
  ]);
  expect(a).toEqual(b);
  expect(a.state).toBe("CANCEL_REQUESTED");
  expect(charged.mock.calls).toEqual([
    [f.owner.ownerId, "termination"],
    [f.owner.ownerId, "termination"],
  ]);
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } })).toBe(
    1,
  );
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
  expect(await cancelAction(f.owner, { operationId: f.operation.id, idempotencyKey })).toEqual(a);
  expect(charged).toHaveBeenCalledTimes(2);
});

it.each(["cancel", "signal"] as const)(
  "%s locks owner → advisory → K → H → S → O, then reads DB time",
  async (action) => {
    const f = await seed();
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 1,
        admissionRuntime: "FAKE",
        admissionEpoch: 1,
      },
    });
    const principal = await f.key();
    const idempotencyKey = randomUUID();
    const beforeAdvisory = db.pauseAt("accept", { before: /pg_advisory_xact_lock/ });
    const gates = [
      db.pauseAt("accept", { before: /sandbox_host.*FOR UPDATE/ }),
      db.pauseAt("accept", { before: /sandbox_instance.*FOR NO KEY UPDATE/ }),
      db.pauseAt("accept", { before: /sandbox_mutation_operation.*FOR UPDATE/ }),
      db.pauseAt("accept", { before: /clock_timestamp/ }),
    ];
    const accepting = db.run("accept", () =>
      action === "cancel"
        ? cancelAction(principal, { operationId: f.operation.id, idempotencyKey })
        : signalProcessAction(principal, { process: f.ref, signal: "SIGTERM", idempotencyKey }),
    );
    const locks = [
      ['"user"', f.owner.ownerId],
      ["sdk_key", principal.keyId],
      ["sandbox_host", f.host.id],
      ["sandbox_instance", f.sandbox.id],
      ["sandbox_mutation_operation", f.operation.id],
    ] as const;
    async function assertLocks(heldRows: number, advisoryHeld: boolean) {
      const advisory = await db.inspect.$transaction(
        (tx) =>
          tx.$queryRaw<
            { locked: boolean }[]
          >`SELECT pg_try_advisory_xact_lock(hashtextextended(${JSON.stringify([f.owner.ownerId, idempotencyKey])}, 0)) AS locked`,
      );
      expect(advisory).toEqual([{ locked: !advisoryHeld }]);
      for (const [index, [table, id]] of locks.entries()) {
        const attempt = db.inspect.$queryRawUnsafe(
          `SELECT id FROM ${table} WHERE id=$1 FOR UPDATE NOWAIT`,
          id,
        );
        if (index < heldRows) await expect(attempt).rejects.toBeDefined();
        else await expect(attempt).resolves.toHaveLength(1);
      }
    }
    await beforeAdvisory.waitReached();
    await assertLocks(1, false);
    // Install this barrier only after the free SDK-key preflight has ended;
    // it must observe the acceptance transaction's K acquisition.
    const beforeKey = db.pauseAt("accept", { before: /sdk_key.*FOR SHARE/ });
    beforeAdvisory.release();
    await beforeKey.waitReached();
    await assertLocks(1, true);
    beforeKey.release();
    for (const [stage, gate] of gates.entries()) {
      await gate.waitReached();
      // Each gate proves earlier locks held and all later rows still free.
      await assertLocks(stage + 2, true);
      gate.release();
    }
    await accepting;
  },
);

it("browser kill returns an action receipt and the owner can observe only the target operation", async () => {
  const f = await seed();
  const receipt = await cancelAction(f.owner, { process: f.ref, idempotencyKey: randomUUID() });
  const { getOperation } = await import("./services/sandboxes");
  expect(receipt.state).toBe("CANCEL_REQUESTED");
  await expect(getOperation(f.owner, { operationId: receipt.operationId })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(getOperation(f.owner, { operationId: f.operation.id })).resolves.toMatchObject({
    id: f.operation.id,
    kind: "RUN_COMMAND",
    state: "CANCEL_REQUESTED",
  });
});

it("E1-A-06 a command without a cwd runs in the revision's default cwd", async () => {
  const f = await seed();
  const { runCommand } = await import("./services/sandboxes");
  const dispatchedCwd = async (operationId: string) => {
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { payload: { path: ["operationId"], equals: operationId } },
      select: { payload: true, operationId: true },
    });
    // D5: createSandboxOutboxEvent stores the indexed operationId column.
    expect(event.operationId).toBe(operationId);
    return (event.payload as { cwd?: string }).cwd;
  };
  const plain = await runCommand(f.owner, {
    id: f.sandbox.id,
    idempotencyKey: randomUUID(),
    argv: ["pwd"],
  });
  expect(await dispatchedCwd(plain.operationId)).toBeUndefined();
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.sandbox.templateRevisionId },
    data: { defaultCwd: "/srv/app" },
  });
  const defaulted = await runCommand(f.owner, {
    id: f.sandbox.id,
    idempotencyKey: randomUUID(),
    argv: ["pwd"],
  });
  expect(await dispatchedCwd(defaulted.operationId)).toBe("/srv/app");
  const explicit = await runCommand(f.owner, {
    id: f.sandbox.id,
    idempotencyKey: randomUUID(),
    argv: ["pwd"],
    cwd: "/tmp",
  });
  expect(await dispatchedCwd(explicit.operationId)).toBe("/tmp");
});
