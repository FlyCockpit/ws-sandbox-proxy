import { digestContextSnapshot } from "./digest-context";
import { seedAcceptedOperation, seedLaunchHost } from "./testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedSandboxInstance, seedTemplateRevision } from "./testing/resource-fixtures";

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
const access = await import("../lib/sdk-key-access");
const digests = await import("./idempotency");
const services = await import("./services/sandboxes");
const { createSandboxInput, runCommandInput } = await import("./contracts");
const { mutationOperationReceipt, probeSandboxReceipt } = await import("./sdk-mutations");
const { bindHostSandboxProbe } = await import("./host-image-verifier");
const { deleteHost } = await import("./services/hosts");
const { withAuthorityChange } = await import("@wssp/db/authority");
const { SERVICE_SCOPES } = await import("../lib/service-scopes");
afterAll(() => db.close());
afterEach(() => vi.restoreAllMocks());

async function fixture() {
  const ownerId = `s3b-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, email: `${ownerId}@example.test`, name: "Owner", twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      templateId: revision.id,
      originPoolId: null,
      originHostId: host.id,
      sandboxHostId: host.id,
      state: "READY",
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  const mint = async (mode: "ALLOWLIST" | "ALL_OWNED" = "ALLOWLIST") => {
    const row = await db.inspect.sdkKey.create({
      data: {
        userId: ownerId,
        name: "key",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        scopes: [...SERVICE_SCOPES],
        resourceMode: mode,
        ...(mode === "ALLOWLIST"
          ? {
              HostAllowlist: { create: { sandboxHostId: host.id } },
              RevisionAllowlist: { create: { templateRevisionId: revision.id } },
            }
          : {}),
      },
    });
    const principal = await access.revalidateSdkKey(row.id, ownerId);
    if (!principal) throw new Error("Fixture key was refused.");
    return principal;
  };
  const k1 = await mint();
  const k2 = await mint();
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    data: { authorizingKeyId: k1.keyId },
  });
  const command = (key = randomUUID(), value = "secret-a") =>
    runCommandInput.parse({
      id: sandbox.id,
      idempotencyKey: key,
      argv: ["true"],
      envs: { TOKEN: value },
    });
  // New env-bearing work must have the negotiated current-epoch journal ACK.
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: {
      journalKeyVersion: 1,
      journalKeyId: digests.requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    },
  });
  return { ownerId, host, revision, sandbox, k1, k2, mint, command };
}

it.each(["secret-a", "guess"])(
  "3B K2 correct/guessed env %s has identical conflict and no digest call",
  async (value) => {
    const f = await fixture();
    const input = f.command();
    await services.runCommand(f.k1, input);
    const digest = vi.spyOn(digests, "hashOperationRequestBody");
    await expect(
      services.runCommand(f.k2, { ...input, envs: { TOKEN: value } }),
    ).rejects.toMatchObject({ code: "CONFLICT", data: { code: "sandbox.idempotency_conflict" } });
    expect(digest).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.ownerId, idempotencyKey: { not: `fixture-boot:${f.sandbox.id}` } },
      }),
    ).toBe(1);
  },
);

it("3B same-key canonical intent replays; unknown scheme and digest_key_changed refuse before digest", async () => {
  const f = await fixture();
  const input = f.command();
  const first = await services.runCommand(f.k1, input);
  expect(await services.runCommand(f.k1, input)).toEqual(first);
  for (const metadata of [
    { requestDigestScheme: "unknown-scheme", requestDigestKeyId: null },
    { requestDigestScheme: "hmac-sha256-v1", requestDigestKeyId: "other-key-id" },
  ]) {
    await db.inspect.sandboxOperation.update({ where: { id: first.operationId }, data: metadata });
    const digest = vi.spyOn(digests, "hashOperationRequestBody");
    await expect(services.runCommand(f.k1, input)).rejects.toMatchObject({
      data: { code: "digest_key_changed" },
    });
    expect(digest).not.toHaveBeenCalled();
    digest.mockRestore();
  }
});

it.each(["same", "other"])(
  "3B real P2002 rollback reacquires owner/idempotency/K and binds %s key before digest",
  async (winnerKey) => {
    const f = await fixture();
    const input = f.command();
    const parked = db.pauseAt("loser", { before: "sandboxOperation.create" });
    const request = db.run("loser", () => services.runCommand(f.k1, input));
    const outcome = request.then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    await parked.waitReached();
    const winnerPrincipal = winnerKey === "same" ? f.k1 : f.k2;
    const winner = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.ownerId,
        sandboxId: f.sandbox.id,
        authorizingKeyId: winnerPrincipal.keyId,
        idempotencyKey: input.idempotencyKey,
        kind: "RUN_COMMAND",
        generation: 1,
        state: "QUEUED",
        ...digests.requestDigestMetadata(),
        requestBodyHash: digests.hashOperationRequestBody(input, "RUN_COMMAND", {
          ownerId: f.ownerId,
          hostId: f.host.id,
          hostOwnerId: f.ownerId,
          authorizingKeyId: winnerPrincipal.keyId,
        }),
      },
    });
    const digest = vi.spyOn(digests, "hashOperationRequestBody");
    const recovery = db.pauseAt("loser", { before: /^sql:SELECT id FROM "user".*FOR SHARE$/ });
    parked.release();
    await recovery.waitReached();
    // The losing INSERT has rolled back: no private outbox or second operation leaked.
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.ownerId } })).toBe(0);
    recovery.release();
    const result = await outcome;
    if (winnerKey === "same")
      expect(result).toEqual({ value: { operationId: winner.id, state: "QUEUED" } });
    else {
      expect(result).toMatchObject({ error: { data: { code: "sandbox.idempotency_conflict" } } });
      expect(digest).not.toHaveBeenCalled();
    }
  },
);

it("3B action receipt key binding precedes HMAC on replay and records immutable scalar", async () => {
  const f = await fixture();
  bindHostSandboxProbe(async () => "guest_ready");
  const input = { id: f.sandbox.id, idempotencyKey: randomUUID() };
  const first = await probeSandboxReceipt(f.k1, input);
  expect(await probeSandboxReceipt(f.k1, input)).toEqual(first);
  expect(
    await db.inspect.sandboxActionReceipt.findUniqueOrThrow({ where: { id: first.operationId } }),
  ).toMatchObject({ authorizingKeyId: f.k1.keyId });
  const digest = vi.spyOn(digests, "hashRequestBody");
  await expect(probeSandboxReceipt(f.k2, input)).rejects.toMatchObject({
    data: { code: "sandbox.idempotency_conflict" },
  });
  expect(digest).not.toHaveBeenCalled();
});

it("3B createIntent cannot allocate; full create kind mapping and mutation receipt use stored allocation", async () => {
  const f = await fixture();
  const input = createSandboxInput.parse({
    sandboxHostId: f.host.id,
    template: "revision/" + f.revision.id,
    idempotencyKey: randomUUID(),
  });
  expect(access.serviceActionForOperationKind("CREATE_SANDBOX")).toBe("sandboxes.create");
  await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.k1.keyId } });
  await expect(access.authorizeServiceAction(f.k1, "sandboxes.createIntent")).resolves.toEqual({});
  await expect(services.createSandbox(f.k1, input)).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: f.ownerId, idempotencyKey: { not: `fixture-boot:${f.sandbox.id}` } },
    }),
  ).toBe(0);
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: { userId: f.ownerId, sdkKeyId: f.k1.keyId, templateRevisionId: f.revision.id },
  });
  const sandbox = await services.createSandbox(f.k1, input);
  const receipt = await mutationOperationReceipt(f.k1, input.idempotencyKey, "sandboxes.create");
  expect(receipt.state).toBe("QUEUED");
  await expect(
    mutationOperationReceipt(f.k2, input.idempotencyKey, "sandboxes.create"),
  ).rejects.toMatchObject({ data: { code: "sandbox.idempotency_conflict" } });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  expect((await services.createSandbox(f.k1, input)).id).toBe(sandbox.id);
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: receipt.operationId },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: op.id },
    data: { requestDigestKeyId: "replacement" },
  });
  await expect(
    mutationOperationReceipt(f.k1, input.idempotencyKey, "sandboxes.create"),
  ).rejects.toMatchObject({ data: { code: "digest_key_changed" } });
});

it.each(["success", "error"])(
  "3B resolved create receipt result guard fences %s after recorded-context authorization",
  async (exit) => {
    const f = await fixture();
    const input = createSandboxInput.parse({
      sandboxHostId: f.host.id,
      template: "revision/" + f.revision.id,
      idempotencyKey: randomUUID(),
    });
    await services.createSandbox(f.k1, input);
    const gate = db.pauseAt("receipt", { after: "sandboxOperation.findFirst" });
    const reading = db.run("receipt", () =>
      mutationOperationReceipt(f.k1, input.idempotencyKey, "sandboxes.create"),
    );
    const outcome = reading.catch((error) => error);
    await gate.waitReached();
    await withAuthorityChange({ ownerId: f.ownerId, credentialId: f.k1.keyId }, async () => {
      await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.k1.keyId } });
      if (exit === "error")
        await db.inspect.sandboxOperation.updateMany({
          where: { userId: f.ownerId },
          data: { requestDigestKeyId: "replacement" },
        });
    });
    gate.release();
    expect(await outcome).toMatchObject({ code: "FORBIDDEN" });
  },
);

it("session_reads_retained_history_after_host_deletion", async () => {
  const f = await fixture();
  const owner = { kind: "session" as const, ownerId: f.ownerId };
  await db.prisma.$transaction(async (tx) => {
    const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
    const { lockCurrentHostEpoch } = await import("./relay-fence");
    const { releaseLiveResourcesOnInventoryProof, releaseRootResources } = await import(
      "./host-admission"
    );
    await lockOwnerForAdmission(tx, f.ownerId);
    await lockCurrentHostEpoch(tx, f.host.id);
    const claim = { hostId: f.host.id, ownerId: f.ownerId, sandboxId: f.sandbox.id };
    await releaseLiveResourcesOnInventoryProof(tx, claim);
    await releaseRootResources(tx, claim);
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      diskReservationHeld: false,
    },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.ownerId,
      sandboxId: f.sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: "history",
      requestBodyHash: "opaque",
      state: "SUCCEEDED",
      completedAt: new Date(),
    },
  });
  await db.inspect.sandboxCommandOutput.create({
    data: { id: op.id, attempt: 1, receivedEnd: 0, totalBytes: 0 },
  });
  await deleteHost(owner, { id: f.host.id });
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toBeNull();
  expect((await services.getSandbox(owner, { id: f.sandbox.id })).id).toBe(f.sandbox.id);
  expect((await services.getOperation(owner, { operationId: op.id })).id).toBe(op.id);
  expect(
    await services.getCommandOutput(owner, { operationId: op.id, maxBytes: 1024 }),
  ).toMatchObject({ complete: true });
  await expect(
    services.getSandbox({ kind: "session", ownerId: f.k2.keyId }, { id: f.sandbox.id }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect((await services.getSandbox(f.k1, { id: f.sandbox.id })).id).toBe(f.sandbox.id);
  await expect(services.getSandbox(f.k2, { id: f.sandbox.id })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
  const allOwned = await f.mint("ALL_OWNED");
  expect((await services.getSandbox(allOwned, { id: f.sandbox.id })).id).toBe(f.sandbox.id);
});

it.each(["success", "error"] as const)(
  "3B resolved receipt guard prevents %s disclosure after a host-only fence moves",
  async (exit) => {
    const f = await fixture();
    const input = createSandboxInput.parse({
      sandboxHostId: f.host.id,
      template: "revision/" + f.revision.id,
      idempotencyKey: randomUUID(),
    });
    await services.createSandbox(f.k1, input);
    const { holdAuthorityChange } = await import("@wssp/db/authority");
    let hold: ReturnType<typeof holdAuthorityChange> | undefined;
    const original = digests.requestDigestKeyCurrent;
    const moved = vi.spyOn(digests, "requestDigestKeyCurrent").mockImplementationOnce((row) => {
      hold = holdAuthorityChange({ ownerId: f.ownerId, hostId: f.host.id });
      return exit === "success" ? original(row) : false;
    });
    try {
      await expect(
        mutationOperationReceipt(f.k1, input.idempotencyKey, "sandboxes.create"),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(moved).toHaveBeenCalledOnce();
    } finally {
      hold?.settle();
    }
  },
);

it("3B createIntent is never an operation-kind accept authorization", async () => {
  const f = await fixture();
  const { operationTransaction } = await import("./operation-transaction");
  const work = vi.fn(async () => "allocated");
  await expect(
    operationTransaction(
      f.k1,
      {
        key: randomUUID(),
        kind: "CREATE_SANDBOX",
        action: "sandboxes.createIntent",
        target: {},
        intent: { envs: { TOKEN: "value" } },
      },
      work,
      async () => "replayed",
    ),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  expect(work).not.toHaveBeenCalled();
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: f.ownerId, idempotencyKey: { not: `fixture-boot:${f.sandbox.id}` } },
    }),
  ).toBe(0);
});

it.each(["same", "other"] as const)(
  "3B action receipt P2002 recovery binds %s key before invoking HMAC",
  async (winnerKey) => {
    const f = await fixture();
    const input = { id: f.sandbox.id, idempotencyKey: randomUUID() };
    const probe = vi.fn(async () => "guest_ready" as const);
    bindHostSandboxProbe(probe);
    const gate = db.pauseAt("action-loser", { before: "sandboxActionReceipt.create" });
    const losing = db.run("action-loser", () => probeSandboxReceipt(f.k1, input));
    const outcome = losing.then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    await gate.waitReached();
    const principal = winnerKey === "same" ? f.k1 : f.k2;
    const winner = await db.inspect.sandboxActionReceipt.create({
      data: {
        digestContext: digestContextSnapshot(
          { domain: "wssp-action-v2", hostId: f.host.id, hostOwnerId: f.ownerId },
          { generation: 1 },
        ),

        userId: f.ownerId,
        authorizingKeyId: principal.keyId,
        hostId: f.host.id,
        sandboxId: f.sandbox.id,
        templateRevisionId: f.revision.id,
        originPoolId: null,
        action: "sandboxes.probe",
        state: "SUCCEEDED",
        idempotencyKey: input.idempotencyKey,
        ...digests.requestDigestMetadata(),
        requestBodyHash: digests.hashRequestBody(
          { action: "sandboxes.probe", input },
          {
            domain: "wssp-action-v2",
            ownerId: f.ownerId,
            hostId: f.host.id,
            hostOwnerId: f.ownerId,
            authorizingKeyId: principal.keyId,
          },
        ),
      },
    });
    const digest = vi.spyOn(digests, "hashRequestBody");
    gate.release();
    const result = await outcome;
    if (winnerKey === "same")
      expect(result).toEqual({ value: { operationId: winner.id, state: "SUCCEEDED" } });
    else {
      expect(result).toMatchObject({ error: { data: { code: "sandbox.idempotency_conflict" } } });
      expect(digest).not.toHaveBeenCalled();
    }
    expect(probe).not.toHaveBeenCalled();
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.ownerId } })).toBe(1);
  },
);

it("3B operation and action writers bind request HMAC to owner, original host and immutable key", async () => {
  const f = await fixture();
  const input = f.command();
  const accepted = await services.runCommand(f.k1, input);
  const row = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: accepted.operationId },
  });
  expect(row.requestBodyHash).toBe(
    digests.hashRequestBody(input, {
      ownerId: f.ownerId,
      hostId: f.host.id,
      hostOwnerId: f.ownerId,
      authorizingKeyId: f.k1.keyId,
    }),
  );
  bindHostSandboxProbe(async () => "guest_ready");
  const probe = { id: f.sandbox.id, idempotencyKey: randomUUID() };
  const receipt = await probeSandboxReceipt(f.k1, probe);
  const action = await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
    where: { id: receipt.operationId },
  });
  expect(action.requestBodyHash).toBe(
    digests.hashRequestBody(
      { action: "sandboxes.probe", input: probe },
      {
        domain: "wssp-action-v2",
        ownerId: f.ownerId,
        hostId: f.host.id,
        hostOwnerId: f.ownerId,
        authorizingKeyId: f.k1.keyId,
      },
    ),
  );
});

it("3B same-key replayCreate retains its original allocation after host finalization for ALL_OWNED", async () => {
  const f = await fixture();
  const all = await f.mint("ALL_OWNED");
  const allInput = createSandboxInput.parse({
    sandboxHostId: f.host.id,
    template: "revision/" + f.revision.id,
    idempotencyKey: randomUUID(),
  });
  const allowedInput = { ...allInput, idempotencyKey: randomUUID() };
  const accepted = await services.createSandbox(all, allInput);
  await services.createSandbox(f.k1, allowedInput);
  // Retained history fixture: no runtime was launched. The real host finalizer
  // must keep S/O while cascading the original ALLOWLIST host grant.
  await db.inspect.sandboxOperation.updateMany({
    where: { userId: f.ownerId },
    data: { state: "SUCCEEDED", completedAt: new Date() },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { userId: f.ownerId },
    data: { processedAt: new Date() },
  });
  const { releaseLiveResourcesOnInventoryProof, releaseRootResources } = await import(
    "./host-admission"
  );
  const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
  const held = await db.inspect.sandbox.findMany({
    where: { userId: f.ownerId, OR: [{ liveResourcesHeld: true }, { diskReservationHeld: true }] },
    take: 10,
    select: { id: true },
  });
  for (const row of held)
    await db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.ownerId);
      await releaseLiveResourcesOnInventoryProof(tx, {
        hostId: f.host.id,
        ownerId: f.ownerId,
        sandboxId: row.id,
      });
      await releaseRootResources(tx, { hostId: f.host.id, ownerId: f.ownerId, sandboxId: row.id });
    });
  await db.inspect.sandbox.updateMany({
    where: { userId: f.ownerId },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      diskReservationHeld: false,
    },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  await deleteHost({ kind: "session", ownerId: f.ownerId }, { id: f.host.id });
  expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toBeNull();
  expect((await services.createSandbox(all, allInput)).id).toBe(accepted.id);
  expect(
    await mutationOperationReceipt(all, allInput.idempotencyKey, "sandboxes.create"),
  ).toMatchObject({ state: "SUCCEEDED" });
  await expect(services.createSandbox(f.k1, allowedInput)).resolves.toMatchObject({
    state: "DELETED",
  });
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: f.ownerId, idempotencyKey: { not: `fixture-boot:${f.sandbox.id}` } },
    }),
  ).toBe(2);
});
