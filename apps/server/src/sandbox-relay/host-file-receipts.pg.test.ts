import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "host-file-receipts-pg-fixture",
    SANDBOX_REQUEST_HMAC_SECRET: "test".repeat(16),
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_MAX_HOSTS_PER_OWNER: null,
    CAPACITY_RETRY_AFTER_SECONDS: 5,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, imageStoreMaintenanceQueue: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/api/lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("../mcp-rate-limit", () => ({
  consumeMcpCreateQuota: async () => {},
  consumeMcpHostCommandQuota: async () => {},
}));
const db = await pgTestDatabase();
const { sandboxRelaySessionManager: manager } = await import("./session-manager");
const { FakeNodeDaemon, fakeClock } = await import("./fake-node-daemon-harness");
const { createHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { authenticateSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { bindHostAccess } = await import("../../../../packages/api/src/sandbox/host-access");
const files = await import("../../../../packages/api/src/sandbox/services/host-files");
const { hostFileRequestHmac } = await import(
  "../../../../packages/api/src/sandbox/host-file-receipts"
);
const { sweepHostAccessRetention } = await import(
  "../../../../packages/api/src/sandbox/host-retention"
);
const { callMcpTool } = await import("../mcp/tools");

type Json = Record<string, unknown>;
const daemons: InstanceType<typeof FakeNodeDaemon>[] = [];
afterEach(async () => {
  for (const daemon of daemons.splice(0)) await daemon.crash();
  bindHostAccess(null);
});
afterAll(async () => {
  await manager.dispose();
  await db.close();
});
async function credential(ownerId: string) {
  const key = await createSdkKey(
    { kind: "session", ownerId },
    {
      name: "full",
      scopes: [...SERVICE_SCOPES],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    },
  );
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("inactive fixture");
  return principal;
}
const etag = (n: number) => `h:${String(n).padStart(22, "0")}`;
/** A node whose file requests succeed, counting every applied effect. */
async function fixture() {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const owner = { kind: "session" as const, ownerId };
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: ownerId, slug: "node", label: "Node" },
  });
  const token = await createHostToken(owner, { hostId: host.id, name: "daemon" });
  const daemon = new FakeNodeDaemon(
    manager,
    {
      hostId: host.id,
      userId: ownerId,
      tokenId: token.token.id,
      credentialKind: "hostToken",
      expiresAt: null,
    },
    fakeClock(),
    { admission: true },
  );
  daemon.agentPolicy = {
    hostCommands: true,
    hostFiles: true,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 1,
  };
  const applied: Json[] = [];
  daemon.hostFileReply = (request) => {
    applied.push(request);
    return request.op === "write"
      ? { ok: true, result: { etag: etag(applied.length), size: 2, created: true } }
      : { ok: true, result: { etag: etag(applied.length), size: 5, replacements: 1 } };
  };
  daemons.push(daemon);
  bindHostAccess(manager.hostAccess);
  await daemon.connect();
  await daemon.idle();
  return { ownerId, host, daemon, applied, principal: await credential(ownerId) };
}
const write = (hostId: string, idempotencyKey: string, content = "hi") => ({
  hostId,
  path: "/srv/a",
  content,
  createOnly: true,
  idempotencyKey,
});
const edit = (hostId: string, idempotencyKey: string, newText = "hello") => ({
  hostId,
  path: "/srv/a",
  edits: [{ oldText: "hi", newText }],
  idempotencyKey,
});
const conflict = { code: "CONFLICT", data: { code: "sandbox.idempotency_conflict" } };
const unknown = { code: "CONFLICT", data: { code: "host.file_outcome_unknown" } };

it("replays a write and an edit under the same key without applying them again", async () => {
  const f = await fixture();
  const first = await files.writeHostFile(f.principal, write(f.host.id, "w1"));
  expect(first).toEqual({ etag: etag(1), size: 2, created: true });
  expect(await files.writeHostFile(f.principal, write(f.host.id, "w1"))).toEqual(first);
  const edited = await files.editHostFile(f.principal, edit(f.host.id, "e1"));
  expect(edited).toEqual({ etag: etag(2), size: 5, replacements: 1 });
  expect(await files.editHostFile(f.principal, edit(f.host.id, "e1"))).toEqual(edited);
  expect(f.applied.map((r) => r.op)).toEqual(["write", "edit"]);
  // A replay is neither re-audited nor re-dispatched; receipts hold no content.
  expect(
    await db.inspect.hostAuditEvent.count({
      where: { userId: f.ownerId, kind: { in: ["FILE_WRITE", "FILE_EDIT"] } },
    }),
  ).toBe(2);
  const receipts = await db.inspect.hostFileReceipt.findMany({ where: { userId: f.ownerId } });
  expect(receipts.map((r) => r.state)).toEqual(["SUCCEEDED", "SUCCEEDED"]);
  // A receipt lives 7 days, like a decided queued host command (createdAt and
  // expiresAt are stamped separately, so allow a little slack).
  for (const r of receipts) {
    const lifetime = r.expiresAt.getTime() - r.createdAt.getTime();
    expect(Math.abs(lifetime - 7 * 86_400_000)).toBeLessThan(60_000);
  }
  expect(JSON.stringify(receipts)).not.toContain("/srv/a");
  expect(JSON.stringify(receipts)).not.toContain("hello");
});

it("refuses a different request under a used key as an idempotency conflict", async () => {
  const f = await fixture();
  await files.writeHostFile(f.principal, write(f.host.id, "k"));
  await expect(
    files.writeHostFile(f.principal, write(f.host.id, "k", "other")),
  ).rejects.toMatchObject(conflict);
  await expect(files.editHostFile(f.principal, edit(f.host.id, "k"))).rejects.toMatchObject(
    conflict,
  );
  await files.editHostFile(f.principal, edit(f.host.id, "e"));
  await expect(
    files.editHostFile(f.principal, edit(f.host.id, "e", "changed")),
  ).rejects.toMatchObject(conflict);
  expect(f.applied).toHaveLength(2);
});

it("scopes keys per credential: another credential of the same owner applies independently", async () => {
  const f = await fixture();
  const other = await credential(f.ownerId);
  const a = await files.writeHostFile(f.principal, write(f.host.id, "shared"));
  const b = await files.writeHostFile(other, write(f.host.id, "shared", "different"));
  expect(a.etag).not.toBe(b.etag);
  expect(f.applied).toHaveLength(2);
  expect(await files.writeHostFile(other, write(f.host.id, "shared", "different"))).toEqual(b);
  expect(f.applied).toHaveLength(2);
});

it("applies concurrent duplicates once; the duplicate waits and replays the first result", async () => {
  const f = await fixture();
  const held: Json[] = [];
  f.daemon.hostFileReply = (request) => {
    held.push(request);
    return null;
  };
  const input = write(f.host.id, "race");
  const first = files.writeHostFile(f.principal, input);
  await expect.poll(() => held.length).toBe(1);
  const second = files.writeHostFile(f.principal, input);
  // The duplicate observes the PENDING reservation and must not dispatch.
  await new Promise((resolve) => setTimeout(resolve, 600));
  expect(held).toHaveLength(1);
  const socket = f.daemon.socket;
  if (!socket) throw new Error("fixture disconnected");
  manager.handleTextFrame(
    socket,
    JSON.stringify({
      type: "host.file.result",
      requestId: held[0]?.requestId,
      ok: true,
      result: { etag: etag(7), size: 2, created: true },
    }),
  );
  await manager.drain(socket);
  const [a, b] = await Promise.all([first, second]);
  expect(a).toEqual({ etag: etag(7), size: 2, created: true });
  expect(b).toEqual(a);
  expect(held).toHaveLength(1);
});

it("keeps an uncertain outcome: a node lost mid-request is never dispatched again under the key", async () => {
  const f = await fixture();
  const held: Json[] = [];
  f.daemon.hostFileReply = (request) => {
    held.push(request);
    return null;
  };
  const pending = files.editHostFile(f.principal, edit(f.host.id, "lost"));
  await expect.poll(() => held.length).toBe(1);
  f.daemon.crash();
  await expect(pending).rejects.toMatchObject(unknown);
  await f.daemon.connect();
  await f.daemon.idle();
  await expect(files.editHostFile(f.principal, edit(f.host.id, "lost"))).rejects.toMatchObject(
    unknown,
  );
  expect(held).toHaveLength(1);
  expect(
    await db.inspect.hostFileReceipt.findFirst({ where: { userId: f.ownerId } }),
  ).toMatchObject({ state: "UNKNOWN", result: null });
});

it("treats a reservation stuck PENDING past the settle window as an unknown outcome", async () => {
  const f = await fixture();
  await db.inspect.hostFileReceipt.create({
    data: {
      userId: f.ownerId,
      sandboxHostId: f.host.id,
      sdkKeyId: f.principal.keyId,
      idempotencyKey: "crashed",
      requestHmac: hostFileRequestHmac(f.host.id, ["write", "/srv/a", "hi", null, true]),
      createdAt: new Date(Date.now() - 60_000),
      expiresAt: new Date(Date.now() + 86_400_000),
    },
  });
  await expect(files.writeHostFile(f.principal, write(f.host.id, "crashed"))).rejects.toMatchObject(
    unknown,
  );
  expect(f.applied).toHaveLength(0);
});

it("keeps the key UNKNOWN when the node may have applied the change (policy_changed, io_error)", async () => {
  // The daemon rewrites a successful result to policy_changed when the host
  // policy changed before delivery, and reports io_error after a rename whose
  // directory fsync failed: neither proves the file is unchanged.
  for (const reason of ["policy_changed", "io_error"]) {
    const f = await fixture();
    let dispatched = 0;
    f.daemon.hostFileReply = () => {
      dispatched += 1;
      return { ok: false, error: reason };
    };
    await expect(
      files.editHostFile(f.principal, edit(f.host.id, `maybe-${reason}`)),
    ).rejects.toMatchObject(unknown);
    // A retry under the key is answered from the receipt, never re-dispatched.
    await expect(
      files.editHostFile(f.principal, edit(f.host.id, `maybe-${reason}`)),
    ).rejects.toMatchObject(unknown);
    expect(dispatched, reason).toBe(1);
    expect(
      await db.inspect.hostFileReceipt.findFirst({ where: { userId: f.ownerId } }),
    ).toMatchObject({ state: "UNKNOWN" });
  }
});

it("releases the key after a definitive node refusal so the same request may run again", async () => {
  const f = await fixture();
  f.daemon.hostFileReply = () => ({ ok: false, error: "exists" });
  await expect(files.writeHostFile(f.principal, write(f.host.id, "refused"))).rejects.toMatchObject(
    { data: { code: "host.file_error", reason: "exists" } },
  );
  expect(await db.inspect.hostFileReceipt.count({ where: { userId: f.ownerId } })).toBe(0);
  let count = 0;
  f.daemon.hostFileReply = () => ({
    ok: true,
    result: { etag: etag(++count), size: 2, created: true },
  });
  expect(await files.writeHostFile(f.principal, write(f.host.id, "refused"))).toMatchObject({
    etag: etag(1),
  });
});

it("sweeps expired receipts in keyset batches and lets an expired key be reused", async () => {
  const f = await fixture();
  for (const key of ["old-1", "old-2", "old-3", "fresh"])
    await files.writeHostFile(f.principal, write(f.host.id, key));
  const past = new Date(Date.now() - 1000);
  await db.inspect.hostFileReceipt.updateMany({
    where: { userId: f.ownerId, idempotencyKey: { in: ["old-1", "old-2", "old-3"] } },
    data: { expiresAt: past },
  });
  // Before any sweep, an expired key is already reusable for another request.
  expect(await files.writeHostFile(f.principal, write(f.host.id, "old-1", "new"))).toMatchObject({
    etag: etag(5),
  });
  await db.inspect.hostFileReceipt.updateMany({
    where: { userId: f.ownerId, idempotencyKey: "old-1" },
    data: { expiresAt: past },
  });
  const swept = await sweepHostAccessRetention(new Date(), 2);
  expect(swept.fileReceipts).toBeGreaterThanOrEqual(3);
  expect(
    (await db.inspect.hostFileReceipt.findMany({ where: { userId: f.ownerId } })).map(
      (r) => r.idempotencyKey,
    ),
  ).toEqual(["fresh"]);
  expect(await files.writeHostFile(f.principal, write(f.host.id, "old-2", "again"))).toMatchObject({
    etag: etag(6),
  });
  expect(await files.writeHostFile(f.principal, write(f.host.id, "fresh"))).toMatchObject({
    etag: etag(4),
  });
  expect(f.applied).toHaveLength(6);
});

it("replays MCP host_file_write and host_file_edit by idempotencyKey and reports conflicts", async () => {
  const f = await fixture();
  const call = (name: string, input: Json) => callMcpTool(f.principal, name, input);
  const body = { hostId: f.host.id, path: "/srv/a", content: "hi", idempotencyKey: "mcp-w" };
  const first = await call("host_file_write", body);
  expect(first).toMatchObject({
    structuredContent: { result: { etag: etag(1) }, idempotencyKey: "mcp-w" },
  });
  expect(await call("host_file_write", body)).toEqual(first);
  const editBody = {
    hostId: f.host.id,
    path: "/srv/a",
    edits: [{ oldText: "hi", newText: "hello" }],
    idempotencyKey: "mcp-e",
  };
  const edited = await call("host_file_edit", editBody);
  expect(await call("host_file_edit", editBody)).toEqual(edited);
  expect(await call("host_file_write", { ...body, content: "changed" })).toMatchObject({
    isError: true,
    structuredContent: { error: { code: "sandbox.idempotency_conflict" } },
  });
  expect(f.applied.map((r) => r.op)).toEqual(["write", "edit"]);
});
