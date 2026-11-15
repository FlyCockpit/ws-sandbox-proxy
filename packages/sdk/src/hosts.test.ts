import { expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { WsspError } from "./errors";
import type { HostCommandStatus } from "./index";
import type { FetchLike } from "./transport";

const commandId = "a".repeat(22);
const etag = `h:${"b".repeat(22)}`;
const requestId = "11111111-1111-4111-8111-111111111111";
function status(extra: Partial<HostCommandStatus> = {}): HostCommandStatus {
  return {
    commandId,
    state: "running",
    stdout: { offset: 0, data: "", dropped: false },
    stderr: { offset: 0, data: "", dropped: false },
    stdoutBytes: 0,
    stderrBytes: 0,
    ...extra,
  };
}
function clientWith(...responses: { status: number; body: unknown }[]) {
  const fetch = vi.fn<FetchLike>(async () => {
    const next = responses.shift();
    if (!next) throw new Error("No mock response.");
    return Response.json(next.body, { status: next.status });
  });
  return {
    fetch,
    client: createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: "wssp_sdk_fixture",
      fetch,
      polling: { intervalMs: 1, maxIntervalMs: 1, longPollMs: 0 },
    }),
  };
}

it("routes host commands, queue requests and files with strict bodies and idempotency keys", async () => {
  const queued = { id: "queue1", state: "QUEUED", expiresAt: "2026-11-13T00:00:00.000Z" };
  const read = { content: "hello", offset: 0, size: 5, etag, truncated: false };
  const listing = { entries: [{ name: "a", kind: "file", size: 5 }], truncated: false };
  const write = { etag, size: 5, created: true };
  const edit = { etag, size: 5, replacements: 1 };
  const { client, fetch } = clientWith(
    { status: 202, body: status() },
    { status: 200, body: status() },
    { status: 200, body: { commandId, accepted: true } },
    { status: 200, body: status({ state: "cancelled" }) },
    { status: 202, body: queued },
    { status: 200, body: queued },
    { status: 200, body: read },
    { status: 200, body: listing },
    { status: 200, body: write },
    { status: 200, body: edit },
  );
  expect(
    await client.hosts.commands.start(
      "host1",
      { argv: ["id"], stdin: true },
      { idempotencyKey: "host-start" },
    ),
  ).toEqual(status());
  await client.hosts.commands.get("host1", commandId, {
    stdoutOffset: 5,
    stderrOffset: 8,
    maxBytes: 64,
    waitMs: 60_000,
  });
  expect(
    await client.hosts.commands.writeStdin(
      "host1",
      commandId,
      { data: "eA==", eof: true },
      { idempotencyKey: "host-stdin" },
    ),
  ).toEqual({ commandId, accepted: true });
  expect((await client.hosts.commands.cancel("host1", commandId)).state).toBe("cancelled");
  expect(
    await client.hosts.queueCommand("host1", {
      command: "id",
      reason: "inspect identity",
      expiresInHours: 24,
    }),
  ).toEqual(queued);
  expect(await client.hosts.getQueuedCommand("host1", "queue1")).toEqual(queued);
  expect(await client.hosts.files.read("host1", { path: "/work/a", maxBytes: 256 })).toEqual(read);
  expect(await client.hosts.files.list("host1", { path: "/work" })).toEqual(listing);
  expect(
    await client.hosts.files.write("host1", {
      path: "/work/a",
      content: "hello",
      createOnly: true,
    }),
  ).toEqual(write);
  expect(
    await client.hosts.files.edit("host1", {
      path: "/work/a",
      expectedEtag: etag,
      edits: [{ oldText: "hello", newText: "world" }],
    }),
  ).toEqual(edit);
  const calls = fetch.mock.calls;
  expect(calls.map(([url]) => new URL(url).pathname)).toEqual([
    "/v1/hosts/host1/commands",
    `/v1/hosts/host1/commands/${commandId}`,
    `/v1/hosts/host1/commands/${commandId}/stdin`,
    `/v1/hosts/host1/commands/${commandId}/cancel`,
    "/v1/hosts/host1/queued-commands",
    "/v1/hosts/host1/queued-commands/queue1",
    ...["read", "list", "write", "edit"].map((op) => `/v1/hosts/host1/files/${op}`),
  ]);
  expect(new URL(calls[1]?.[0] ?? "").searchParams.get("waitMs")).toBe("60000");
  for (const [, init] of calls) {
    const headers = new Headers(init.headers);
    if (init.method === "POST") expect(headers.get("Idempotency-Key")).toBeTruthy();
    else expect(headers.has("Idempotency-Key")).toBe(false);
  }
  expect(new Headers(calls[0]?.[1].headers).get("Idempotency-Key")).toBe("host-start");
  expect(new Headers(calls[2]?.[1].headers).get("Idempotency-Key")).toBe("host-stdin");
  expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ data: "eA==", eof: true });
});

it("validates host identity DTOs and foreign ownership without disclosing policy", async () => {
  // Build a complete host from the schema-independent wire shape used by the server.
  const now = "2026-11-12T00:00:00.000Z";
  const host = {
    id: "host1",
    slug: "node",
    label: "Node",
    status: "CONNECTED",
    agentAccess: { owned: false },
    lastConnectedAt: now,
    lastHeartbeatAt: now,
    retainedRootCount: 0,
    capacity: {
      memoryBudgetMiB: null,
      maxCpuCount: null,
      maxMemoryMiB: null,
      memoryReservedMiB: 0,
      memoryAvailableMiB: null,
      memoryOvercommittedMiB: null,
      vcpuBudget: null,
      vcpuReserved: 0,
      vcpuAvailable: null,
      vcpuOvercommitted: null,
      retainedRootCount: 0,
      current: false,
      reportedAt: null,
    },
    storagePools: [],
    draining: false,
    egressEnforcement: true,
    egressOpen: true,
    openEgressForOthers: false,
    guestSudoForOthers: false,
    egressGuard: { ok: true, reason: null, leaseActive: true },
    liveSandboxCount: 0,
    drained: false,
    deletionRequested: false,
    createdAt: now,
    updatedAt: now,
  };
  const { client, fetch } = clientWith(
    { status: 200, body: host },
    { status: 200, body: { items: [host], nextCursor: null } },
    { status: 200, body: { ...host, agentAccess: { owned: false, hostCommands: false } } },
    {
      status: 200,
      body: { ...host, agentAccess: { owned: true, hostCommands: true, hostFiles: false } },
    },
  );
  expect(await client.hosts.get("host1")).toEqual(host);
  expect((await client.hosts.list({ limit: 2 })).items).toEqual([host]);
  expect(new URL(fetch.mock.calls[1]?.[0] ?? "").searchParams.get("limit")).toBe("2");
  await expect(client.hosts.get("host1")).rejects.toMatchObject({ kind: "protocol" });
  expect((await client.hosts.get("host1")).agentAccess).toEqual({
    owned: true,
    hostCommands: true,
    hostFiles: false,
  });
});

it("rejects invalid host inputs locally before sending a request", async () => {
  const { client, fetch } = clientWith();
  await expect(
    client.hosts.commands.start("host1", { argv: ["id"], script: "id" }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  await expect(client.hosts.commands.get("host1", "short")).rejects.toMatchObject({
    kind: "invalid_request",
  });
  await expect(
    client.hosts.commands.get("host1", commandId, { maxBytes: 65_537 }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  expect(() => client.hosts.commands.get("host1", commandId, { stdoutOffset: Number.NaN })).toThrow(
    WsspError,
  );
  await expect(
    client.hosts.commands.writeStdin("host1", commandId, { data: "Zh==", eof: true }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  await expect(
    client.hosts.files.write("host1", { path: "/work/a", content: "é".repeat(131_073) }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  await expect(
    client.hosts.files.edit("host1", { path: "/work/a", edits: [] }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  await expect(
    client.hosts.queueCommand("host1", { command: "id", reason: "check", expiresInHours: 169 }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  expect(fetch).not.toHaveBeenCalled();
});

it("starts once, follows absolute masked offsets and drains terminal output", async () => {
  const stream = (offset: number, value: string, dropped = false) => ({
    offset,
    data: Buffer.from(value).toString("base64"),
    dropped,
  });
  const { client, fetch } = clientWith(
    { status: 202, body: status({ stdout: stream(0, "a"), stdoutBytes: 1 }) },
    {
      status: 200,
      body: status({
        state: "succeeded",
        exitCode: 0,
        stdout: stream(1, "b"),
        stdoutBytes: 3,
        stderr: stream(0, "err"),
        stderrBytes: 3,
      }),
    },
    {
      status: 200,
      body: status({
        state: "succeeded",
        exitCode: 0,
        stdout: stream(2, "c"),
        stdoutBytes: 3,
        stderr: stream(3, ""),
        stderrBytes: 3,
      }),
    },
  );
  const result = await client.hosts.commands.run(
    "host1",
    { script: "printf abc" },
    { idempotencyKey: "stable-host-key" },
  );
  expect(result).toMatchObject({
    state: "succeeded",
    exitCode: 0,
    stdoutText: "abc",
    stderrText: "err",
    truncated: false,
  });
  expect(fetch.mock.calls.filter(([, init]) => init.method === "POST")).toHaveLength(1);
  expect(new URL(fetch.mock.calls[1]?.[0] ?? "").searchParams.get("stdoutOffset")).toBe("1");
  expect(new URL(fetch.mock.calls[2]?.[0] ?? "").searchParams.get("stdoutOffset")).toBe("2");
  expect(new URL(fetch.mock.calls[2]?.[0] ?? "").searchParams.get("stderrOffset")).toBe("3");
});

it("reports gaps and decodes UTF-8 across output chunk boundaries", async () => {
  const { client } = clientWith(
    {
      status: 202,
      body: status({
        stdout: { offset: 7, data: Buffer.from([0xc3]).toString("base64"), dropped: true },
        stdoutBytes: 8,
      }),
    },
    {
      status: 200,
      body: status({
        state: "succeeded",
        exitCode: 0,
        stdout: { offset: 8, data: Buffer.from([0xa9]).toString("base64"), dropped: false },
        stdoutBytes: 9,
      }),
    },
  );
  expect(await client.hosts.commands.run("host1", { argv: ["id"] })).toMatchObject({
    stdoutText: "é",
    truncated: true,
  });
});

it("retains a bounded output tail when following a large host command", async () => {
  const page = Buffer.alloc(65_536, "x").toString("base64");
  const { client } = clientWith(
    { status: 202, body: status() },
    ...Array.from({ length: 17 }, (_, i) => ({
      status: 200,
      body: status({
        state: i === 16 ? "succeeded" : "running",
        stdout: { offset: i * 65_536, data: page, dropped: false },
        stdoutBytes: (i + 1) * 65_536,
      }),
    })),
  );
  const result = await client.hosts.commands.run("host1", { argv: ["id"] });
  expect(result.stdoutText.length).toBe(1_048_576);
  expect(result.truncated).toBe(true);
});

it("fails malformed responses and lost start responses without starting again", async () => {
  const malformed = clientWith({ status: 202, body: { ...status(), private: "no" } });
  await expect(
    malformed.client.hosts.commands.start(
      "host1",
      { argv: ["id"] },
      { idempotencyKey: "same-key" },
    ),
  ).rejects.toMatchObject({ kind: "unknown", idempotencyKey: "same-key" });
  expect(malformed.fetch).toHaveBeenCalledTimes(1);
  const fetch = vi.fn<FetchLike>(async () => {
    throw new TypeError("lost response");
  });
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch,
  });
  await expect(
    client.hosts.commands.run("host1", { script: "id" }, { idempotencyKey: "same-key" }),
  ).rejects.toMatchObject({ kind: "unknown", idempotencyKey: "same-key" });
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("detaches on a wait deadline and preserves the command submission key", async () => {
  const fetch = vi.fn<FetchLike>(async (_url, init) => {
    if (init.method === "POST") return Response.json(status(), { status: 202 });
    return new Promise((_resolve, reject) =>
      init.signal?.addEventListener(
        "abort",
        () => reject(new DOMException("Aborted", "AbortError")),
        { once: true },
      ),
    );
  });
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch,
    polling: { intervalMs: 1, maxIntervalMs: 1 },
  });
  await expect(
    client.hosts.commands.run(
      "host1",
      { script: "id" },
      { idempotencyKey: "same-key", waitTimeoutMs: 30 },
    ),
  ).rejects.toMatchObject({ kind: "timeout", idempotencyKey: "same-key" });
  expect(fetch.mock.calls.filter(([, init]) => init.method === "POST")).toHaveLength(1);
});

it("exposes typed file reasons and host policy retry semantics", async () => {
  const error = (code: string, fields: object) => ({
    error: { code, requestId, message: "safe", ...fields },
  });
  const { client } = clientWith(
    { status: 422, body: error("host.file_error", { data: { reason: "redacted_span" } }) },
    { status: 409, body: error("host.agent_access_off", { retryable: false }) },
    { status: 409, body: error("host.node_offline", { retryable: true, retryAfterSeconds: 5 }) },
    { status: 404, body: error("host.command_not_found", {}) },
  );
  await expect(client.hosts.files.read("host1", { path: "/work/a" })).rejects.toMatchObject({
    code: "host.file_error",
    reason: "redacted_span",
    kind: "invalid_request",
  });
  await expect(client.hosts.commands.start("host1", { argv: ["id"] })).rejects.toMatchObject({
    code: "host.agent_access_off",
    retryable: false,
    retryAfterSeconds: null,
  });
  await expect(client.hosts.commands.get("host1", commandId)).rejects.toMatchObject({
    code: "host.node_offline",
    retryable: true,
    retryAfterSeconds: 5,
  });
  await expect(client.hosts.commands.get("host1", commandId)).rejects.toMatchObject({
    code: "host.command_not_found",
    kind: "not_found",
  });
});
