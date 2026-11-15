import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  authorizeServiceAction: vi.fn(async () => ({})),
}));

import { type HostAccessLink, HostAccessRelay } from "./host-access";

const { default: prisma } = await import("@wssp/db");
const db = prisma as unknown as import("@wssp/api/test/mock-prisma").MockPrisma;
beforeEach(() => {
  vi.clearAllMocks();
  db.sandboxHost.findFirst.mockResolvedValue({
    userId: "a",
    connectionEpoch: 2,
    agentHostCommandsVetoedAt: null,
  } as never);
  db.hostAuditEvent.updateMany.mockResolvedValue({ count: 1 });
});
afterEach(() => vi.useRealTimers());
function rig(ownerId = "a") {
  const frames: Record<string, unknown>[] = [];
  let authorized = true;
  const link: HostAccessLink = {
    hostId: "host",
    ownerId,
    epoch: 2,
    protocolVersion: "1.0",
    socket: {
      send: (frame) => {
        frames.push(JSON.parse(frame));
      },
    },
    authorized: () => authorized,
  };
  const relay = new HostAccessRelay(async () => link, vi.fn());
  relay.policies.register(link, {
    hostCommands: true,
    hostFiles: true,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 4,
    lowerPending: false,
  });
  return {
    relay,
    link,
    frames,
    revoke: () => {
      authorized = false;
    },
  };
}
const principal = { kind: "session", ownerId: "a" } as const;
const commandId = "abcdefghijklmnopqrstuv";
async function tick() {
  for (let i = 0; i < 12; i++) await Promise.resolve();
}
it("refuses a link whose authenticated owner mismatches the principal and durable host", async () => {
  const r = rig("b");
  await expect(
    r.relay.start(principal, "host", { argv: ["true"], commandId }),
  ).rejects.toMatchObject({ data: { code: "host.not_owned" } });
  expect(r.frames).toHaveLength(0);
});
it("checks durable pending lowering before start, stdin and every file dispatch", async () => {
  const r = rig();
  db.sandboxHost.findFirst.mockResolvedValue({
    userId: "a",
    connectionEpoch: 2,
    agentHostCommandsVetoedAt: new Date(),
  } as never);
  for (const work of [
    () => r.relay.start(principal, "host", { argv: ["true"], commandId }),
    () => r.relay.stdin(principal, "host", { commandId, data: "", eof: true }),
    () => r.relay.file(principal, "host", { op: "read", path: "/srv/test" }),
    () =>
      r.relay.poll(principal, "host", {
        commandId,
        stdoutOffset: 0,
        stderrOffset: 0,
        maxBytes: 100,
      }),
    () => r.relay.cancel(principal, "host", commandId),
  ])
    await expect(work()).rejects.toMatchObject({ data: { code: "host.agent_access_off" } });
  expect(r.frames).toHaveLength(0);
});
it("correlates exact socket, epoch and command id, then disconnect settles pending calls", async () => {
  const r = rig();
  const pending = r.relay.start(principal, "host", { argv: ["true"], commandId });
  await tick();
  const frame = r.frames[0]!;
  expect(frame).toMatchObject({
    ownerId: "a",
    agentPolicyRevision: 4,
    connectionEpoch: 2,
  });
  const reply = {
    type: "host.exec.started",
    requestId: frame.requestId as string,
    commandId,
    startedAt: 1,
    endsBy: 2,
  } as const;
  await r.relay.receive({ ...r.link, epoch: 1 }, reply);
  await r.relay.receive({ ...r.link, socket: { send() {} } }, reply);
  await r.relay.receive(r.link, { ...reply, commandId: "AAAAAAAAAAAAAAAAAAAAAA" });
  let done = false;
  void pending.then(() => {
    done = true;
  });
  await tick();
  expect(done).toBe(false);
  await r.relay.receive(r.link, reply);
  expect((await pending).state).toBe("running");
  const poll = r.relay.poll(principal, "host", {
    commandId,
    stdoutOffset: 0,
    stderrOffset: 0,
    maxBytes: 65536,
  });
  const refusal = expect(poll).rejects.toMatchObject({ data: { code: "host.node_offline" } });
  await tick();
  await r.relay.disconnect("host", "a", r.link.socket);
  await refusal;
  expect(db.hostAuditEvent.updateMany).toHaveBeenCalledWith(
    expect.objectContaining({ data: expect.objectContaining({ state: "interrupted" }) }),
  );
});
it("bounds pending work per host at 64 and times requests out", async () => {
  vi.useFakeTimers();
  const r = rig();
  const requests = Array.from({ length: 64 }, () =>
    r.relay
      .poll(principal, "host", { commandId, stdoutOffset: 0, stderrOffset: 0, maxBytes: 1 })
      .catch((error: unknown) => error),
  );
  await tick();
  expect(r.frames).toHaveLength(64);
  await expect(
    r.relay.poll(principal, "host", { commandId, stdoutOffset: 0, stderrOffset: 0, maxBytes: 1 }),
  ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  await vi.advanceTimersByTimeAsync(5000);
  expect(await Promise.all(requests)).toEqual(
    Array.from({ length: 64 }, () =>
      expect.objectContaining({
        data: { code: "host.node_offline", retryable: true, retryAfterSeconds: 1 },
      }),
    ),
  );
});
