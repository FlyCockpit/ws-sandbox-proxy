import {
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { OPERATION_KINDS } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * C48: the operations page's owner projection against real PostgreSQL —
 * newest-first keyset pages that neither repeat nor skip rows, the
 * sandbox/state/kind filters, rows that carry status metadata and the exit
 * code but never a stored result (file digests, transfer IDs, PIDs), another
 * owner's operations absent from the list and NOT_FOUND on detail, and a
 * cancellation that stays CANCEL_REQUESTED (still "active") until the host
 * acknowledges it.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c48-pg-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
afterAll(() => db.close());

const FP = `sha256:${"d".repeat(64)}`;

async function owner() {
  const id = `ops-${randomUUID()}`;
  const user = await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      lastHeartbeatAt: new Date(),
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "ubuntu",
      label: "Ubuntu",
      imageRef: "local:ubuntu",
      incusFingerprint: FP,
    },
  });
  const sandbox = (state: "READY" | "DELETED" = "READY") =>
    seedSandboxInstance(db.inspect, {
      data: {
        userId: id,
        sandboxHostId: state === "DELETED" ? null : host.id,
        originHostId: host.id,
        templateId: template.id,
        originPoolId: null,
        state,
      },
    });
  let minute = 0;
  const operation = (
    sandboxId: string,
    data: {
      kind: import("@wssp/db").SandboxOperationKind;
      state: "RUNNING" | "SUCCEEDED" | "FAILED" | "QUEUED" | "UNKNOWN_OUTCOME";
      result?: object;
      errorCode?: string;
      errorDetail?: string;
    },
  ) => {
    minute += 1;
    return seedAcceptedOperation(db.inspect, {
      data: {
        userId: id,
        sandboxId,
        generation: 1,
        dispatchAttempt: data.state === "QUEUED" ? 0 : 1,
        dispatchedHostId: data.state === "QUEUED" ? null : host.id,
        idempotencyKey: `k-${randomUUID()}`,
        requestBodyHash: "h",
        createdAt: new Date(Date.UTC(2026, 8, 26, 10, minute)),
        completedAt: data.state === "SUCCEEDED" || data.state === "FAILED" ? new Date() : undefined,
        ...data,
      },
    });
  };
  const durableSession = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session: durableSession,
    },
  } as Context;
  return {
    id,
    host,
    sandbox,
    operation,
    api: createRouterClient(sandboxesRouter, { context }),
  };
}

it("pages newest first without repeats; filters by sandbox, kind and state; rows carry no result", async () => {
  const a = await owner();
  const one = await a.sandbox();
  const two = await a.sandbox("DELETED");
  const cmd = await a.operation(one.id, {
    kind: "RUN_COMMAND",
    state: "SUCCEEDED",
    result: { exitCode: 2, pid: 4242, outputBytes: 17 },
  });
  const file = await a.operation(one.id, {
    kind: "GET_FILE",
    state: "SUCCEEDED",
    result: { size: 5, sha256: "e".repeat(64), transferId: "transfer-secretish" },
  });
  const running = await a.operation(two.id, { kind: "RUN_COMMAND", state: "RUNNING" });
  const failed = await a.operation(two.id, {
    kind: "LIST_DIR",
    state: "FAILED",
    errorCode: "path_refused",
    errorDetail: "cannot list /root/private",
  });
  const queued = await a.operation(one.id, { kind: "CREATE_SANDBOX", state: "QUEUED" });

  // Two-row pages walk the whole owner list exactly once, newest first.
  const seen: string[] = [];
  let cursor: string | undefined;
  for (let pages = 0; pages < 5; pages++) {
    const page = await a.api.listOperations({ limit: 2, cursor });
    seen.push(...page.items.map((item) => item.id));
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  const boots = await db.inspect.sandboxOperation.findMany({
    where: { userId: a.id, idempotencyKey: { startsWith: "fixture-boot:" } },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: 10,
  });
  expect(seen).toEqual([
    queued.id,
    failed.id,
    running.id,
    file.id,
    cmd.id,
    ...boots.map((row) => row.id),
  ]);

  const all = await a.api.listOperations({ limit: 50 });
  const byId = new Map(all.items.map((item) => [item.id, item]));
  expect(byId.get(cmd.id)).toMatchObject({
    exitCode: 2,
    state: "SUCCEEDED",
    sandboxState: "READY",
  });
  expect(byId.get(file.id)).toMatchObject({ exitCode: null, kind: "GET_FILE" });
  expect(byId.get(failed.id)).toMatchObject({ errorCode: "path_refused", sandboxState: "DELETED" });
  const wire = JSON.stringify(all);
  expect(wire).not.toContain("transfer-secretish");
  expect(wire).not.toContain("e".repeat(64));
  expect(wire).not.toContain("4242");
  expect(wire).not.toContain("/root/private");
  expect(wire).not.toMatch(/idempotencyKey|requestBodyHash|"result"|errorDetail/);

  const ids = async (input: Parameters<typeof a.api.listOperations>[0]) =>
    (await a.api.listOperations(input)).items.map((item) => item.id);
  expect(await ids({ limit: 50, sandboxId: two.id })).toEqual([failed.id, running.id]);
  expect(await ids({ limit: 50, kind: "RUN_COMMAND" })).toEqual([running.id, cmd.id]);
  expect(await ids({ limit: 50, state: "active" })).toEqual([queued.id, running.id]);
  expect(await ids({ limit: 50, state: "settled" })).toEqual([
    failed.id,
    file.id,
    cmd.id,
    ...boots.map((row) => row.id),
  ]);
  expect(await ids({ limit: 50, state: "FAILED", sandboxId: two.id })).toEqual([failed.id]);

  const view = await a.api.getOperationView({ operationId: failed.id });
  expect(view).toMatchObject({
    errorCode: "path_refused",
    errorMessage: "Guest path refused.",
    sandboxState: "DELETED",
    sandbox: { id: two.id, state: "DELETED", host: null },
    exitCode: null,
  });
});

it("another owner's operations are absent from the list and NOT_FOUND on detail", async () => {
  const a = await owner();
  const b = await owner();
  const sandbox = await a.sandbox();
  const op = await a.operation(sandbox.id, { kind: "RUN_COMMAND", state: "RUNNING" });
  expect((await b.api.listOperations({ limit: 50 })).items).toEqual([]);
  expect((await b.api.listOperations({ limit: 50, sandboxId: sandbox.id })).items).toEqual([]);
  await expect(b.api.getOperationView({ operationId: op.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(b.api.cancelOperation({ operationId: op.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect((await a.api.getOperationView({ operationId: op.id })).state).toBe("RUNNING");
});

it("a cancelled running command stays CANCEL_REQUESTED (and active) until the host acknowledges", async () => {
  const a = await owner();
  const sandbox = await a.sandbox();
  const op = await a.operation(sandbox.id, { kind: "RUN_COMMAND", state: "RUNNING" });
  expect(await a.api.cancelOperation({ operationId: op.id })).toEqual({
    operationId: op.id,
    state: "CANCEL_REQUESTED",
  });
  // A repeated click is the same request: still pending, one outbox event.
  expect(await a.api.cancelOperation({ operationId: op.id })).toEqual({
    operationId: op.id,
    state: "CANCEL_REQUESTED",
  });
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: a.id, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
  const view = await a.api.getOperationView({ operationId: op.id });
  expect(view.state).toBe("CANCEL_REQUESTED");
  expect(view.completedAt).toBeNull();
  const active = await a.api.listOperations({ limit: 50, state: "active" });
  expect(active.items.map((item) => [item.id, item.state])).toEqual([[op.id, "CANCEL_REQUESTED"]]);
});

it.each(OPERATION_KINDS)(
  "catalog-only historical %s errors across owner list/detail/status",
  async (kind) => {
    const a = await owner();
    const sandbox = await a.sandbox();
    for (const errorCode of ["guest_operation_failed", "private-legacy-code-SENTINEL", undefined]) {
      const op = await a.operation(sandbox.id, {
        kind,
        state: "FAILED",
        errorCode,
        errorDetail: "PRIVATE-LEGACY-PATH-ARGV-STDERR",
      });
      const detail = await a.api.getOperationView({ operationId: op.id });
      const status = await a.api.getOperation({ operationId: op.id });
      const list = await a.api.listOperations({ limit: 100 });
      const wire = JSON.stringify({ detail, status, list });
      expect(wire).not.toMatch(/PRIVATE-LEGACY|private-legacy-code|errorDetail|"result"/);
      expect(detail.errorMessage).toBe(
        errorCode === "guest_operation_failed" ? "Guest operation failed." : "Operation failed.",
      );
      expect(status).not.toHaveProperty("result");
    }
  },
);
