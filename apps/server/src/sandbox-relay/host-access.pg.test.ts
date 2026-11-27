import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedMintSession,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "host-access-pg-fixture",
    SANDBOX_REQUEST_HMAC_SECRET: "test".repeat(16),
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_MAX_HOSTS_PER_OWNER: null,
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
const db = await pgTestDatabase();
const { sandboxRelaySessionManager: manager } = await import("./session-manager");
const { FakeNodeDaemon, fakeClock } = await import("./fake-node-daemon-harness");
const { createHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { authenticateSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { bindHostAccess } = await import("../../../../packages/api/src/sandbox/host-access");
const commands = await import("../../../../packages/api/src/sandbox/services/host-commands");
const files = await import("../../../../packages/api/src/sandbox/services/host-files");
const queued = await import("../../../../packages/api/src/sandbox/services/host-queued");
const {
  lowerAgentHostCommands,
  liftAgentHostCommandsVeto,
  liftHostTerminalVeto,
  lowerHostTerminal,
} = await import("../../../../packages/api/src/sandbox/services/host-policy");
const daemons: InstanceType<typeof FakeNodeDaemon>[] = [];
afterEach(async () => {
  for (const daemon of daemons.splice(0)) await daemon.crash();
  bindHostAccess(null);
});
afterAll(async () => {
  await manager.dispose();
  await db.close();
});
async function person() {
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
  return seedMintSession(db.inspect, { kind: "session" as const, ownerId });
}
async function credential(
  owner: Awaited<ReturnType<typeof person>>,
  hostId: string,
  mode: "ALL_OWNED" | "ALLOWLIST" = "ALL_OWNED",
) {
  const key = await createSdkKey(owner, {
    name: "full",
    scopes: [...SERVICE_SCOPES],
    resourceMode: mode,
    hostIds: mode === "ALLOWLIST" ? [hostId] : [],
    templateRevisionIds: [],
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("inactive fixture");
  return principal;
}
async function fixture(on = true) {
  const owner = await person();
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: owner.ownerId, slug: "node", label: "Node" },
  });
  const token = await createHostToken(owner, { hostId: host.id, name: "daemon" });
  const daemon = new FakeNodeDaemon(
    manager,
    {
      hostId: host.id,
      userId: owner.ownerId,
      tokenId: token.token.id,
      credentialKind: "hostToken",
      expiresAt: null,
    },
    fakeClock(),
    { admission: true },
  );
  daemon.agentPolicy = {
    hostCommands: on,
    hostFiles: on,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 1,
  };
  daemons.push(daemon);
  bindHostAccess(manager.hostAccess);
  await daemon.connect();
  await daemon.idle();
  return { owner, host, daemon, principal: await credential(owner, host.id) };
}
it("refuses B's full all-owned and allowlisted credentials on A's shared node for commands, files and queue, but accepts A", async () => {
  const f = await fixture();
  const b = await person();
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: b.ownerId, slug: "shared", label: "Shared" },
  });
  // A's node contributes to B's pool. Physical custody remains A's.
  const share = await db.inspect.share.create({
    data: {
      poolId: pool.id,
      ownerUserId: b.ownerId,
      granteeUserId: f.owner.ownerId,
      canUse: true,
      canContribute: true,
    },
  });
  await db.inspect.sandboxPoolMember.create({
    data: {
      userId: b.ownerId,
      poolId: pool.id,
      sandboxHostId: f.host.id,
      hostOwnerId: f.owner.ownerId,
      shareId: share.id,
      contributeWitness: true,
      ownHostsOnlyWitness: false,
      enabled: true,
    },
  });
  for (const mode of ["ALL_OWNED", "ALLOWLIST"] as const) {
    let principal = await credential(b, f.host.id);
    if (mode === "ALLOWLIST") {
      await db.inspect.sdkKey.update({
        where: { id: principal.keyId },
        data: { resourceMode: "ALLOWLIST" },
      });
      await db.inspect.sdkKeyHostAllowlist.create({
        data: { sdkKeyId: principal.keyId, sandboxHostId: f.host.id },
      });
      principal = { ...principal, resourceMode: "ALLOWLIST", allowedHostIds: new Set([f.host.id]) };
    }
    for (const work of [
      () => commands.runHostCommand(principal, { hostId: f.host.id, argv: ["true"] }),
      () => files.readHostFile(principal, { hostId: f.host.id, path: "/srv/project" }),
      () =>
        queued.queueHostCommand(principal, {
          hostId: f.host.id,
          command: "true",
          reason: "review",
        }),
    ])
      await expect(work()).rejects.toMatchObject({ code: "FORBIDDEN" });
  }
  const started = await commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] });
  expect(started.state).toBe("running");
  await expect(
    files.readHostFile(f.principal, { hostId: f.host.id, path: "/srv/project" }),
  ).rejects.toMatchObject({ data: { code: "host.file_error", reason: "not_found" } });
  expect(
    (
      await queued.queueHostCommand(f.principal, {
        hostId: f.host.id,
        command: "true",
        reason: "review",
      })
    ).state,
  ).toBe("QUEUED");
});
it("off refuses, on dispatches with revision and owner, credential reads stay isolated, end statuses update the audit", async () => {
  const f = await fixture(false);
  await expect(
    commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] }),
  ).rejects.toMatchObject({ data: { code: "host.agent_access_off", retryable: false } });
  f.daemon.agentPolicy = {
    ...f.daemon.agentPolicy,
    hostCommands: true,
    hostFiles: true,
    agentPolicyRevision: 2,
  };
  await f.daemon.reportAgentPolicy();
  await f.daemon.idle();
  const started = await commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] });
  expect(f.daemon.received.findLast((frame) => frame.type === "host.exec.start")).toMatchObject({
    ownerId: f.owner.ownerId,
    agentPolicyRevision: 2,
  });
  const other = await credential(f.owner, f.host.id);
  await expect(
    commands.getHostCommand(other, { hostId: f.host.id, commandId: started.commandId }),
  ).rejects.toMatchObject({ data: { code: "host.command_not_found" } });
  await f.daemon.finishHostCommand(started.commandId);
  await f.daemon.idle();
  expect(
    await db.inspect.hostAuditEvent.findUnique({ where: { commandId: started.commandId } }),
  ).toMatchObject({ state: "succeeded", exitCode: 0 });
});
it("pending lowering vetoes a still-on live report; lowering cancels audit rows and sends the lower-only frame", async () => {
  const f = await fixture();
  const command = await commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] });
  const queue = await queued.queueHostCommand(f.principal, {
    hostId: f.host.id,
    command: "true",
    reason: "review",
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { agentHostCommandsVetoedAt: new Date() },
  });
  expect(manager.hostAccess.read(f.host.id, f.owner.ownerId)?.hostCommands).toBe(true);
  await expect(
    commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] }),
  ).rejects.toMatchObject({ data: { code: "host.agent_access_off" } });
  await lowerAgentHostCommands(f.owner, { id: f.host.id });
  await f.daemon.idle();
  expect(f.daemon.received).toContainEqual(
    expect.objectContaining({ type: "host.policy.lower", target: "hostCommands" }),
  );
  expect(
    await db.inspect.hostAuditEvent.findUnique({ where: { commandId: command.commandId } }),
  ).toMatchObject({ state: "cancelled", reason: "policy_lowered" });
  await f.daemon.finishHostCommand(command.commandId);
  await f.daemon.idle();
  expect(
    await db.inspect.hostAuditEvent.findUnique({ where: { commandId: command.commandId } }),
  ).toMatchObject({ state: "cancelled", reason: "policy_lowered" });
  expect(await db.inspect.hostQueuedCommand.findUnique({ where: { id: queue.id } })).toMatchObject({
    state: "QUEUED",
  });
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
    agentHostCommandsVetoedAt: expect.any(Date),
  });
});
it("serializes queued-command admission at 50 under the owner lock", async () => {
  const f = await fixture();
  await db.inspect.hostQueuedCommand.createMany({
    data: Array.from({ length: 49 }, () => ({
      userId: f.owner.ownerId,
      sandboxHostId: f.host.id,
      sdkKeyId: f.principal.keyId,
      command: "true",
      reason: "review",
      expiresAt: new Date(Date.now() + 86400000),
    })),
  });
  const gate = db.pauseAt("first", { after: "hostQueuedCommand.count" });
  const settle = <T>(work: Promise<T>) =>
    work.then(
      (value) => ({ value, error: undefined }),
      (error: unknown) => ({ value: undefined, error }),
    );
  const first = settle(
    db.run("first", () =>
      queued.queueHostCommand(f.principal, { hostId: f.host.id, command: "true", reason: "50" }),
    ),
  );
  await gate.waitReached();
  const second = settle(
    db.run("second", () =>
      queued.queueHostCommand(f.principal, { hostId: f.host.id, command: "true", reason: "51" }),
    ),
  );
  try {
    await db.waitUntilBlocked("second", { by: "first" });
  } finally {
    gate.release();
  }
  const [a, b] = await Promise.all([first, second]);
  expect(a.error).toBeUndefined();
  expect(b.error).toMatchObject({ data: { code: "host_queue.limit" } });
  expect(
    await db.inspect.hostQueuedCommand.count({
      where: { userId: f.owner.ownerId, state: "QUEUED" },
    }),
  ).toBe(50);
});
it("queued status is credential-scoped; person decisions race through one guarded state change", async () => {
  const f = await fixture(false);
  const other = await credential(f.owner, f.host.id);
  const row = await queued.queueHostCommand(f.principal, {
    hostId: f.host.id,
    command: "printf 'quoted'",
    reason: "review",
    idempotencyKey: "queue-replay",
  });
  expect(
    await queued.queueHostCommand(f.principal, {
      hostId: f.host.id,
      command: "printf 'quoted'",
      reason: "review",
      idempotencyKey: "queue-replay",
    }),
  ).toEqual(row);
  await expect(
    queued.getQueuedHostCommand(other, { hostId: f.host.id, id: row.id }),
  ).rejects.toMatchObject({ data: { code: "host.command_not_found" } });
  expect(
    (await queued.listQueuedHostCommands(f.owner, { hostId: f.host.id, limit: 1 })).items,
  ).toEqual([
    expect.objectContaining({ id: row.id, credentialName: "full", command: "printf 'quoted'" }),
  ]);
  const decisions = await Promise.allSettled([
    queued.runQueuedHostCommand(f.owner, { id: row.id }),
    queued.dismissQueuedHostCommand(f.owner, { id: row.id }),
  ]);
  for (const result of decisions)
    if (result.status === "rejected") expect(result.reason).toMatchObject({ code: "CONFLICT" });
  expect(decisions.filter((d) => d.status === "fulfilled")).toHaveLength(1);
  const run = decisions[0];
  if (run?.status === "fulfilled")
    expect(run.value).toMatchObject({
      state: "RUN",
      hostTerminalAvailable: false,
      typedCommand: expect.stringContaining("env -u SUDO_ASKPASS"),
    });
  expect(
    await db.inspect.hostAuditEvent.count({
      where: { userId: f.owner.ownerId, kind: { in: ["QUEUED_RUN", "QUEUED_DISMISSED"] } },
    }),
  ).toBe(1);
});
it("idempotent command starts dispatch once and disconnect interrupts the audit without storing command text", async () => {
  const f = await fixture();
  const input = {
    hostId: f.host.id,
    script: "VAR=private /usr/bin/printf secret-argument",
    idempotencyKey: "same-command",
  };
  const [a, b] = await Promise.all([
    commands.runHostCommand(f.principal, input),
    commands.runHostCommand(f.principal, input),
  ]);
  expect(a.commandId).toBe(b.commandId);
  expect(f.daemon.received.filter((frame) => frame.type === "host.exec.start")).toHaveLength(1);
  const audit = await db.inspect.hostAuditEvent.findUniqueOrThrow({
    where: { commandId: a.commandId },
  });
  expect(audit.program).toBe("printf");
  expect(audit.subjectHmac).toMatch(/^hmac-sha256:[a-f0-9]{64}$/);
  expect(JSON.stringify(audit)).not.toContain("secret-argument");
  f.daemon.crash();
  await expect
    .poll(
      async () =>
        (await db.inspect.hostAuditEvent.findUnique({ where: { commandId: a.commandId } }))?.state,
    )
    .toBe("interrupted");
});
it("keeps the dashboard veto across off reports, malicious on reports and reconnects until a person lifts it", async () => {
  const f = await fixture();
  f.daemon.crash();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { agentHostCommandsVetoedAt: new Date() },
  });
  await f.daemon.connect();
  await f.daemon.idle();
  expect(f.daemon.received).toContainEqual(
    expect.objectContaining({ type: "host.policy.lower", target: "hostCommands" }),
  );
  expect(manager.hostAccess.read(f.host.id, f.owner.ownerId)?.hostCommands).toBe(false);
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
    agentHostCommandsVetoedAt: expect.any(Date),
  });
  const count = f.daemon.received.filter((frame) => frame.type === "host.policy.lower").length;
  f.daemon.agentPolicy.hostCommands = true;
  f.daemon.agentPolicy.hostFiles = true;
  f.daemon.agentPolicy.agentPolicyRevision++;
  await f.daemon.reportAgentPolicy();
  await f.daemon.idle();
  expect(
    f.daemon.received.filter((frame) => frame.type === "host.policy.lower").length,
  ).toBeGreaterThan(count);
  await expect(
    files.readHostFile(f.principal, { hostId: f.host.id, path: "/srv/test" }),
  ).rejects.toMatchObject({ data: { code: "host.agent_access_off" } });
  f.daemon.crash();
  await f.daemon.connect();
  await f.daemon.idle();
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
    agentHostCommandsVetoedAt: expect.any(Date),
  });
});

it("lifting a veto is owner-only, audited, and cannot turn on an off node", async () => {
  const f = await fixture();
  await lowerAgentHostCommands(f.owner, { id: f.host.id });
  await f.daemon.idle(); // Observe the first off report before changing another policy generation.
  await lowerHostTerminal(f.owner, { id: f.host.id });
  await f.daemon.idle();
  const foreign = await person();
  for (const [target, lift] of [
    ["hostCommands", liftAgentHostCommandsVeto],
    ["hostTerminal", liftHostTerminalVeto],
  ] as const) {
    await expect(lift(foreign, { id: f.host.id })).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(lift(f.principal, { id: f.host.id })).rejects.toMatchObject({ code: "FORBIDDEN" });
    // Each lift fences cached authority; daemon.idle() does not await the
    // relay's asynchronous revalidation before the next off witness is sampled.
    await expect
      .poll(() => manager.hostAccess.offWitness(f.host.id, f.owner.ownerId, target)?.isOff())
      .toBe(true);
    await lift(f.owner, { id: f.host.id });
  }
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
    agentHostCommandsVetoedAt: null,
    hostTerminalVetoedAt: null,
  });
  await expect
    .poll(() => manager.hostAccess.read(f.host.id, f.owner.ownerId)?.hostCommands)
    .toBe(false);
  expect(f.daemon.agentPolicy.hostCommands).toBe(false);
  await expect(
    commands.runHostCommand(f.principal, { hostId: f.host.id, argv: ["true"] }),
  ).rejects.toMatchObject({ data: { code: "host.agent_access_off" } });
  expect(
    await db.inspect.hostAuditEvent.count({
      where: { sandboxHostId: f.host.id, actor: "PERSON", kind: "POLICY_VETO_LIFT" },
    }),
  ).toBe(2);
});

it("Allow again refuses offline lowering and raw-on reports despite an effective veto", async () => {
  const f = await fixture();
  await f.daemon.crash();
  await lowerAgentHostCommands(f.owner, { id: f.host.id });
  await lowerHostTerminal(f.owner, { id: f.host.id });
  const refusal = { code: "CONFLICT", data: { code: "host.node_not_off" } };
  for (const lift of [liftAgentHostCommandsVeto, liftHostTerminalVeto])
    await expect(lift(f.owner, { id: f.host.id })).rejects.toMatchObject(refusal);
  // A malicious/stale node can report on while the effective policies are off.
  // Ignore lower frames to model a failed save, retaining its raw-on report.
  await f.daemon.connect();
  await f.daemon.idle();
  const receive = f.daemon.receive.bind(f.daemon);
  const receiveSpy = vi.spyOn(f.daemon, "receive").mockImplementation((socket, data) => {
    if (typeof data === "string" && JSON.parse(data).type === "host.policy.lower") {
      f.daemon.received.push(JSON.parse(data));
      return;
    }
    receive(socket, data);
  });
  try {
    f.daemon.agentPolicy = {
      ...f.daemon.agentPolicy,
      hostCommands: true,
      hostFiles: true,
      agentPolicyRevision: f.daemon.agentPolicy.agentPolicyRevision + 1,
    };
    await f.daemon.reportAgentPolicy();
    const hello = f.daemon.received.findLast((frame) => frame.type === "hello.ok");
    const socket = f.daemon.socket;
    if (!socket) throw new Error("fixture disconnected");
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "host.terminal-policy",
        connectionEpoch: hello?.connectionEpoch,
        sequence: 1,
        hostTerminal: true,
        requireHostTerminalTotp: true,
        policyRevision: 1,
      }),
    );
    await manager.drain(socket);
    await f.daemon.idle();
    expect(manager.hostAccess.read(f.host.id, f.owner.ownerId)).toMatchObject({
      hostCommands: false,
      nodeHostCommands: true,
    });
    for (const lift of [liftAgentHostCommandsVeto, liftHostTerminalVeto])
      await expect(lift(f.owner, { id: f.host.id })).rejects.toMatchObject(refusal);
  } finally {
    receiveSpy.mockRestore();
  }
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
    agentHostCommandsVetoedAt: expect.any(Date),
    hostTerminalVetoedAt: expect.any(Date),
  });
  expect(
    await db.inspect.hostAuditEvent.count({
      where: { sandboxHostId: f.host.id, kind: "POLICY_VETO_LIFT" },
    }),
  ).toBe(0);
});

it.each([
  ["hostCommands", lowerAgentHostCommands, liftAgentHostCommandsVeto, "agentHostCommandsVetoedAt"],
  ["hostTerminal", lowerHostTerminal, liftHostTerminalVeto, "hostTerminalVetoedAt"],
] as const)(
  "rolls back the %s lift if the live node disconnects before commit",
  async (target, lower, lift, field) => {
    const f = await fixture(false);
    await lower(f.owner, { id: f.host.id });
    await f.daemon.idle();
    await expect
      .poll(() => manager.hostAccess.offWitness(f.host.id, f.owner.ownerId, target)?.isOff())
      .toBe(true);
    const gate = db.pauseAt("lift", { after: "hostAuditEvent.create" });
    const result = db
      .run("lift", () => lift(f.owner, { id: f.host.id }))
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    await gate.waitReached();
    try {
      f.daemon.crash();
    } finally {
      gate.release();
    }
    expect(await result).toMatchObject({ code: "CONFLICT", data: { code: "host.node_not_off" } });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
      [field]: expect.any(Date),
    });
    expect(
      await db.inspect.hostAuditEvent.count({
        where: { sandboxHostId: f.host.id, kind: "POLICY_VETO_LIFT" },
      }),
    ).toBe(0);
  },
);
