import {
  acknowledgeFixtureExecutionConfigs,
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

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

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
  },
}));
const db = await pgTestDatabase();
const { acknowledgeJournalKey, disconnectJournalKey } = await import("./journal-key-ack.js");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
afterAll(() => db.close());

async function fixture() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test` },
  });
  const keyId = requestDigestMetadata().requestDigestKeyId;
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug: "host",
      label: "Host",
      connectionEpoch: 1,
      status: "CONNECTED",
      journalKeyVersion: 1,
      journalKeyId: keyId,
      journalKeyAcknowledgedEpoch: null,
    },
  });
  return {
    host,
    sender: { userId, hostId: host.id, connectionEpoch: 1 },
    ack: { type: "journal.key.ack" as const, connectionEpoch: 1, keyVersion: 1 as const, keyId },
  };
}

it("journal_key_ack_requires_current_epoch_exact_key_and_owner", async () => {
  const { host, sender, ack } = await fixture();
  for (const attempt of [
    { ...ack, keyId: "0".repeat(32) },
    { ...ack, connectionEpoch: 2 },
  ])
    expect(await acknowledgeJournalKey(sender, attempt)).toBe(false);
  const foreign = randomUUID();
  await db.inspect.user.create({
    data: { id: foreign, name: "Other", email: `${foreign}@example.test` },
  });
  expect(await acknowledgeJournalKey({ ...sender, userId: foreign }, ack)).toBe(false);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
      .journalKeyAcknowledgedEpoch,
  ).toBeNull();
  expect(await acknowledgeJournalKey(sender, ack)).toBe(true);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
      .journalKeyAcknowledgedEpoch,
  ).toBe(1);
});

it("journal_key_ack_epoch_fence_survives_a_reconnect_race", async () => {
  const { host, sender, ack } = await fixture();
  const gate = db.pauseAt("ack", { before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const pending = db.run("ack", () => acknowledgeJournalKey(sender, ack));
  await gate.waitReached();
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { connectionEpoch: 2, journalKeyAcknowledgedEpoch: null },
  });
  gate.release();
  expect(await pending).toBe(false);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
      .journalKeyAcknowledgedEpoch,
  ).toBeNull();
});

it("journal_key_disconnect_clears_only_its_epoch", async () => {
  const { host, sender, ack } = await fixture();
  expect(await acknowledgeJournalKey(sender, ack)).toBe(true);
  expect(await disconnectJournalKey(sender, new Date(), true)).toBe(true);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
      .journalKeyAcknowledgedEpoch,
  ).toBeNull();
  const next = { ...sender, connectionEpoch: 2 };
  expect(await acknowledgeJournalKey(next, { ...ack, connectionEpoch: 2 })).toBe(true);
  expect(await disconnectJournalKey(sender, new Date(), true)).toBe(false);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
      .journalKeyAcknowledgedEpoch,
  ).toBe(2);
});

it("env_bearing_work_refuses_before_enqueue_and_send_without_current_key_ack", async () => {
  const { host, sender, ack } = await fixture();
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: sender.userId,
      sandboxHostId: host.id,
      slug: "template",
      label: "Template",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: sender.userId,
      templateId: template.id,
      originPoolId: null,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "READY",
    },
  });
  const { runCommand } = await import("@wssp/api/sandbox/services/sandboxes");
  const owner = { kind: "session" as const, ownerId: sender.userId };
  const input = {
    id: sandbox.id,
    idempotencyKey: "env-work",
    argv: ["true"],
    timeoutMs: 120000,
    envs: { PRIVATE: "test-private-value" },
  };
  for (const epoch of [null, 0, 2]) {
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: { journalKeyAcknowledgedEpoch: epoch },
    });
    await expect(runCommand(owner, input)).rejects.toMatchObject({
      data: { code: "digest_key_unavailable" },
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, sandboxId: sandbox.id },
      }),
    ).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where: { aggregateId: sandbox.id } })).toBe(0);
  }
  // A disconnected host has neither a live session nor its key ACK. The
  // availability refusal must take precedence and leave no accepted work.
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { status: "DISCONNECTED", journalKeyAcknowledgedEpoch: null },
  });
  await expect(runCommand(owner, input)).rejects.toMatchObject({
    data: { code: "sandbox.host_unavailable" },
  });
  expect(await db.inspect.outboxEvent.count({ where: { aggregateId: sandbox.id } })).toBe(0);
  await db.inspect.sandboxHost.update({ where: { id: host.id }, data: { status: "CONNECTED" } });
  expect(await acknowledgeJournalKey(sender, ack)).toBe(true);
  await runCommand(owner, input);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, sandboxId: sandbox.id },
  });
  expect(operation).toMatchObject(requestDigestMetadata());
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { journalKeyAcknowledgedEpoch: null },
  });
  const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
    "./outbox-processor.js"
  );
  async function processSandboxOutboxBatch(
    ...args: Parameters<typeof processOutboxWithInstalledConfig>
  ) {
    await acknowledgeFixtureExecutionConfigs(db.inspect);
    return processOutboxWithInstalledConfig(...args);
  }

  const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
  vi.mocked(manager.dispatchOperation).mockClear();
  expect(await processSandboxOutboxBatch()).toBe(0);
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } })).state,
  ).toBe("QUEUED");
  expect(
    (await db.inspect.outboxEvent.findFirstOrThrow({ where: { aggregateId: sandbox.id } })).sentAt,
  ).toBeNull();
  expect(await acknowledgeJournalKey(sender, ack)).toBe(true);
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(manager.dispatchOperation).toHaveBeenCalledWith(
    host.id,
    expect.objectContaining({
      digestScheme: "hmac-sha256-v1",
      digestKeyId: ack.keyId,
    }),
  );
});

it("env_bearing_work_in_the_post_hello_key_ack_window_is_a_transient_refusal", async () => {
  const { host, sender, ack } = await fixture();
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: sender.userId,
      sandboxHostId: host.id,
      slug: "template",
      label: "Template",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: sender.userId,
      templateId: template.id,
      originPoolId: null,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "READY",
    },
  });
  const { runCommand } = await import("@wssp/api/sandbox/services/sandboxes");
  const owner = { kind: "session" as const, ownerId: sender.userId };
  const input = {
    id: sandbox.id,
    idempotencyKey: "env-window",
    argv: ["true"],
    timeoutMs: 120000,
    envs: { PRIVATE: "test-private-value" },
  };
  const accepted = async () => [
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, sandboxId: sandbox.id },
    }),
    await db.inspect.outboxEvent.count({ where: { aggregateId: sandbox.id } }),
  ];
  // The hello just committed (database clock); the key ACK is still in flight.
  await db.inspect
    .$executeRaw`UPDATE sandbox_host SET "lastConnectedAt" = clock_timestamp() AT TIME ZONE 'UTC' WHERE id = ${host.id}`;
  await expect(runCommand(owner, input)).rejects.toMatchObject({
    code: "SERVICE_UNAVAILABLE",
    data: { code: "sandbox.host_reconnecting" },
  });
  // Sealing is unchanged: the transient refusal still precedes every write.
  expect(await accepted()).toEqual([0, 0]);
  // Past the grace, a missing ACK (e.g. a non-canonical origin) is permanent.
  await db.inspect
    .$executeRaw`UPDATE sandbox_host SET "lastConnectedAt" = clock_timestamp() AT TIME ZONE 'UTC' - interval '31 seconds' WHERE id = ${host.id}`;
  await expect(runCommand(owner, input)).rejects.toMatchObject({
    data: { code: "digest_key_unavailable" },
  });
  expect(await accepted()).toEqual([0, 0]);
  // The ACK arrives: the same key is now accepted.
  expect(await acknowledgeJournalKey(sender, ack)).toBe(true);
  await runCommand(owner, input);
  expect(await accepted()).toEqual([1, 1]);
});

it("digest_refusal_after_receipt_keeps_slot through server ingestion", async () => {
  const { applyOperationResult } = await import("./operation-handlers.js");
  for (const phase of ["Intent", "Effect", "Result"]) {
    for (const code of [
      "digest_key_unavailable",
      "digest_key_changed",
      "receipt_digest_pruned",
      "idempotency_conflict",
      "unknown_outcome",
    ] as const) {
      // The paired production-daemon wire test proves all three receipt phases
      // emit UNKNOWN; ingestion must retain capacity for every refusal code.
      const { host, sender } = await fixture();
      await db.inspect.sandboxHost.update({ where: { id: host.id }, data: { liveCount: 1 } });
      const template = await seedTemplateRevision(db.inspect, {
        data: {
          userId: sender.userId,
          sandboxHostId: host.id,
          slug: "template",
          label: "Template",
          imageRef: "image",
          incusFingerprint: `sha256:${"a".repeat(64)}`,
        },
      });
      const sandbox = await seedSandboxInstance(db.inspect, {
        data: {
          userId: sender.userId,
          templateId: template.id,
          originPoolId: null,
          sandboxHostId: host.id,
          originHostId: host.id,
          state: "PROVISIONING",
          liveResourcesHeld: true,
        },
      });
      const operation = await seedAcceptedOperation(db.inspect, {
        data: {
          userId: sender.userId,
          sandboxId: sandbox.id,
          kind: "CREATE_SANDBOX",
          generation: 1,
          state: "DISPATCHED",
          dispatchAttempt: 1,
          dispatchedHostId: host.id,
          dispatchedConnectionEpoch: 1,
          idempotencyKey: `${phase}-${code}`,
          requestBodyHash: "a".repeat(64),
          ...requestDigestMetadata(),
        },
      });
      expect(
        await applyOperationResult({
          sender,
          operationId: operation.id,
          sandboxId: sandbox.id,
          generation: 1,
          attempt: 1,
          state: "unknown_outcome",
          error: { code, message: "Host dispatch digest refused." },
        }),
      ).toMatchObject({ written: true });
      expect(
        await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } }),
      ).toMatchObject({
        state: "STOPPING",
        liveResourcesHeld: true,
        lastErrorCode: code,
        lastErrorDetail:
          code === "unknown_outcome"
            ? "The node daemon could not confirm the create's outcome (it restarted or lost its connection mid-create); cleanup queued."
            : "Sandbox provisioning outcome unconfirmed; cleanup queued.",
      });
      expect(
        (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } })).liveCount,
      ).toBe(1);
      expect(
        (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } }))
          .state,
      ).toBe("FAILED");
    }
  }
});

it("receipt_key_id_replacement_is_checked_before_reading_the_digest", async () => {
  const { applyOperationResult } = await import("./operation-handlers.js");
  const { host, sender } = await fixture();
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: sender.userId,
      sandboxHostId: host.id,
      slug: "template",
      label: "Template",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: sender.userId,
      templateId: template.id,
      originPoolId: null,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "PROVISIONING",
      liveResourcesHeld: true,
    },
  });
  await db.inspect.sandboxHost.update({ where: { id: host.id }, data: { liveCount: 1 } });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: sender.userId,
      sandboxId: sandbox.id,
      kind: "CREATE_SANDBOX",
      generation: 1,
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      idempotencyKey: "old-key",
      requestBodyHash: "a".repeat(64),
      requestDigestScheme: "hmac-sha256-v1",
      requestDigestKeyId: "0".repeat(32),
    },
  });
  const digest = vi.fn(() => "a".repeat(64));
  const receipt = {
    get bodyHash() {
      return digest();
    },
    idempotencyKey: operation.idempotencyKey,
    kind: "sandbox.create",
  };
  const outcome = await applyOperationResult({
    sender,
    operationId: operation.id,
    sandboxId: sandbox.id,
    generation: 1,
    attempt: 1,
    state: "unknown_outcome",
    receipt,
  });
  expect(digest).not.toHaveBeenCalled();
  expect(outcome).toEqual({ written: false });
  expect(
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).liveResourcesHeld,
  ).toBe(true);
});

it("new_digest_errors_are_constant_at_the_ingestion_boundary", async () => {
  const { applyOperationResult } = await import("./operation-handlers.js");
  const { SDK_ERRORS } = await import("@wssp/sandbox-contracts");
  const { host, sender } = await fixture();
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: sender.userId,
      sandboxHostId: host.id,
      slug: "template",
      label: "Template",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: sender.userId,
      templateId: template.id,
      originPoolId: null,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "READY",
    },
  });
  for (const code of [
    "digest_key_changed",
    "digest_key_unavailable",
    "receipt_digest_pruned",
  ] as const) {
    const operation = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: sender.userId,
        sandboxId: sandbox.id,
        kind: "RUN_COMMAND",
        generation: 1,
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: host.id,
        dispatchedConnectionEpoch: 1,
        idempotencyKey: code,
        requestBodyHash: "a".repeat(64),
        ...requestDigestMetadata(),
      },
    });
    expect(
      await applyOperationResult({
        sender,
        operationId: operation.id,
        sandboxId: sandbox.id,
        generation: 1,
        attempt: 1,
        state: "failed",
        error: { code, message: "key-error-private-sentinel" },
      }),
    ).toEqual({ written: true });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } }),
    ).toMatchObject({
      errorCode: code,
      errorDetail: SDK_ERRORS[code][1],
    });
  }
});
