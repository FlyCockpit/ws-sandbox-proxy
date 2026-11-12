import { expect, it } from "vitest";
import {
  completeFakeCommand,
  fakeSandboxOrpc,
  fakeTemplate,
  newFakeSandboxServer,
  operationRow,
  sandboxRow,
} from "./sandbox-fake";

it("kill and SIGKILL return replayable action receipts that browser getOperation cannot read", async () => {
  const server = newFakeSandboxServer();
  const target = operationRow({ id: "command", sandboxId: "sbx", processId: "process" });
  server.operations.push(target);
  const orpc = fakeSandboxOrpc(server).sandboxes;
  const process = { sandboxId: "sbx", generation: 1, attempt: 1, pid: 42, processId: "process" };
  const input = { process, idempotencyKey: "kill" };
  const receipt = await orpc.killProcess.mutationOptions().mutationFn(input);
  expect(receipt).toMatchObject({ state: "CANCEL_REQUESTED" });
  expect(receipt.operationId).not.toBe(target.id);
  expect(server.operations).toHaveLength(1);
  expect(await orpc.killProcess.mutationOptions().mutationFn(input)).toEqual(receipt);
  const readReceipt = orpc.getOperation.queryOptions({
    input: { operationId: receipt.operationId },
  });
  if (typeof readReceipt.queryFn !== "function") throw new Error("Expected enabled query");
  await expect(readReceipt.queryFn()).rejects.toMatchObject({ code: "NOT_FOUND", status: 404 });
  const signal = await orpc.signalProcess
    .mutationOptions()
    .mutationFn({ ...input, idempotencyKey: "kill", signal: "SIGKILL" });
  expect(signal).toEqual(receipt);
  expect(server.operations).toHaveLength(1);
});

it("missing result IDs refuse, and invalid result/connection schemas cannot masquerade as server responses", async () => {
  const server = newFakeSandboxServer();
  const orpc = fakeSandboxOrpc(server).sandboxes;
  const read = orpc.getOperationResult.queryOptions({ input: { operationId: "absent" } });
  if (typeof read.queryFn !== "function") throw new Error("Expected enabled query");
  await expect(read.queryFn()).rejects.toMatchObject({ code: "NOT_FOUND" });
  await orpc.listProcesses.mutationOptions().mutationFn({ id: "sbx", idempotencyKey: "list" });
  server.observationResults = [
    { outcome: "succeeded", result: { type: "process.list", items: [] } },
  ];
  const invalid = orpc.getOperationResult.queryOptions({
    input: { operationId: server.operations[0]?.id },
  });
  if (typeof invalid.queryFn !== "function") throw new Error("Expected enabled query");
  await expect(invalid.queryFn()).rejects.toThrow();
  expect(() => operationRow({ kind: "CANCEL" })).toThrow("Invalid fake operation kind/state");
});

it("output responses use the operation state, ISO expiry and real page byte bound", async () => {
  const server = newFakeSandboxServer();
  server.operations.push(operationRow({ id: "command", state: "SUCCEEDED", exitCode: 7 }));
  server.outputs.set("command", {
    attempt: 1,
    complete: true,
    expiresAt: new Date(),
    gaps: [],
    chunks: [{ stream: "stdout", offset: 0, bytes: new Uint8Array(70_000) }],
  });
  const read = fakeSandboxOrpc(server).sandboxes.getCommandOutput.call;
  const first = await read({ operationId: "command" });
  expect(first).toMatchObject({ state: "SUCCEEDED", exitCode: 7, hasMore: true });
  expect(typeof first.expiresAt).toBe("string");
  expect(Buffer.from(first.chunks[0]!.data, "base64")).toHaveLength(65_536);
  const rest = await read({ operationId: "command", cursor: first.nextCursor });
  expect(rest.hasMore).toBe(false);
  expect(Buffer.from(rest.chunks[0]!.data, "base64")).toHaveLength(4_464);
});

it("catalog reads use logical template IDs and bounded pages, capabilities use only real features", async () => {
  const server = newFakeSandboxServer();
  server.templates = [fakeTemplate()];
  const orpc = fakeSandboxOrpc(server);
  const logical = orpc.sandboxTemplates.getTemplate.queryOptions({ input: { id: "logical-1" } });
  if (typeof logical.queryFn !== "function") throw new Error("Expected enabled query");
  expect(await logical.queryFn()).toMatchObject({ id: "logical-1" });
  const capabilities = orpc.sandboxes.getSandboxCapabilities.queryOptions({ input: { id: "sbx" } });
  if (typeof capabilities.queryFn !== "function") throw new Error("Expected enabled query");
  expect(await capabilities.queryFn()).toMatchObject({
    sandboxId: "sbx",
    generation: 1,
    guestApi: { supportedSignals: ["SIGKILL"] },
  });
  const page = orpc.sandboxTemplates.listRevisionChoices.infiniteOptions({
    input: (cursor) => ({ hostIds: ["host-1"], cursor, limit: 1 }),
    initialPageParam: undefined,
    getNextPageParam: (page) => page.nextCursor,
  });
  server.templates.push(fakeTemplate({ id: "tpl-2" }));
  const first = await page.queryFn({ pageParam: undefined });
  expect(first.items).toHaveLength(1);
  expect(first.nextCursor).toBeTruthy();
  expect((await page.queryFn({ pageParam: first.nextCursor ?? undefined })).items).toHaveLength(1);
});

it.each(["missing", "qualifier-mismatch", "sandbox-stale"] as const)(
  "cancel fixture preserves the real %s refusal code/status before a receipt",
  async (scenario) => {
    const server = newFakeSandboxServer();
    const process = { sandboxId: "sbx", generation: 1, attempt: 1, pid: 42, processId: "process" };
    if (scenario !== "missing")
      server.operations.push(
        operationRow({ id: "command", sandboxId: "sbx", processId: "process" }),
      );
    if (scenario === "qualifier-mismatch") process.pid = 43;
    if (scenario === "sandbox-stale")
      server.sandboxes.push(sandboxRow({ id: "sbx", generation: 2 }));
    await expect(
      fakeSandboxOrpc(server)
        .sandboxes.killProcess.mutationOptions()
        .mutationFn({ process, idempotencyKey: "refused" }),
    ).rejects.toMatchObject({
      code: scenario === "sandbox-stale" ? "CONFLICT" : "NOT_FOUND",
      status: scenario === "sandbox-stale" ? 409 : 404,
      data: {
        code: scenario === "sandbox-stale" ? "sandbox.process_stale" : "sandbox.process_not_found",
      },
    });
    expect(server.receipts.size).toBe(0);
  },
);

it.each(["killProcess", "cancelOperation"] as const)(
  "%s queued cancellation retains terminal diagnostics",
  async (procedure) => {
    const server = newFakeSandboxServer();
    const target = operationRow({
      id: "command",
      sandboxId: "sbx",
      processId: "process",
      state: "QUEUED",
    });
    server.operations.push(target);
    const orpc = fakeSandboxOrpc(server).sandboxes;
    if (procedure === "killProcess")
      await orpc.killProcess.mutationOptions().mutationFn({
        process: { sandboxId: "sbx", generation: 1, attempt: 1, pid: 42, processId: "process" },
        idempotencyKey: "kill",
      });
    else await orpc.cancelOperation.mutationOptions().mutationFn({ operationId: "command" });
    expect(target).toMatchObject({
      state: "CANCELLED",
      errorCode: "cancelled",
      exitCode: null,
      failure: null,
      completedAt: expect.any(Date),
    });
  },
);

it.each([
  ["succeeded", "SUCCEEDED", null, null],
  ["cancelled", "CANCELLED", "cancelled", null],
  ["timeout", "FAILED", "timeout", { resource: "command", effect: "unknown" }],
  ["unknown", "UNKNOWN_OUTCOME", "unknown_outcome", { resource: "command", effect: "unknown" }],
] as const)(
  "host %s completion preserves the server's code and effect fields",
  (outcome, state, errorCode, failure) => {
    const row = operationRow();
    completeFakeCommand(row, outcome);
    expect(row).toMatchObject({
      state,
      errorCode,
      exitCode: null,
      failure,
      completedAt: expect.any(Date),
    });
  },
);

it("terminal exit and effect evidence is copied without guessing from timeout", () => {
  const row = operationRow();
  completeFakeCommand(row, "timeout", {
    exitCode: 137,
    failure: { resource: "command", effect: "partial" },
  });
  expect(row).toMatchObject({
    state: "FAILED",
    errorCode: "timeout",
    exitCode: 137,
    failure: { resource: "command", effect: "partial" },
  });
  completeFakeCommand(row, "succeeded", { exitCode: 0 });
  expect(row).toMatchObject({ state: "SUCCEEDED", errorCode: null, exitCode: 0, failure: null });
  expect(operationRow({ state: "CANCELLED" }).errorCode).toBe("cancelled");
});

it.each([
  { cpuCount: 0 },
  { cpuCount: 33 },
  { memoryMiB: 513 },
  { memoryMiB: 1000 },
  { diskGiB: 0 },
  { diskGiB: 2049 },
])("B5 fake rejects invalid VM size %j before accepting anything", async (size) => {
  const server = newFakeSandboxServer();
  await expect(
    fakeSandboxOrpc(server)
      .sandboxes.createSandbox.mutationOptions()
      .mutationFn({
        template: "base",
        sandboxHostId: "host-1",
        idempotencyKey: "invalid-size",
        ...size,
      }),
  ).rejects.toMatchObject({
    code: "BAD_REQUEST",
    status: 400,
    data: { code: "sandbox.vm_size_invalid" },
  });
  expect(server.sandboxes).toEqual([]);
  expect(server.operations).toEqual([]);
  expect(server.receipts.size).toBe(0);
  expect(server.seq).toBe(0);
});

it("B5 fake resolves omitted dimensions from the revision and keeps explicit overrides", async () => {
  const server = newFakeSandboxServer();
  server.templates = [fakeTemplate({ cpuCount: 3, memoryMiB: 3072 })];
  const create = fakeSandboxOrpc(server).sandboxes.createSandbox.mutationOptions().mutationFn;
  expect(await create({ template: "revision/tpl-1", idempotencyKey: "defaults" })).toMatchObject({
    cpuCount: 3,
    memoryMiB: 3072,
  });
  expect(
    await create({ template: "revision/tpl-1", memoryMiB: 2048, idempotencyKey: "partial" }),
  ).toMatchObject({
    cpuCount: 3,
    memoryMiB: 2048,
  });
});
