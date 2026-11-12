import { describe, expect, it, vi } from "vitest";
import {
  renderTestEvent,
  renderWebhookEvent,
  serializeWebhookPayload,
  webhookCredentialEventRenderSelect,
} from "./render";

const T = new Date("2026-11-02T00:00:00.000Z");
const sandboxRow = {
  id: "sb1",
  name: "quiet-otter",
  userId: "owner",
  cpuCount: 1,
  memoryMiB: 1024,
  diskGiB: 32,
  storagePoolId: "sp1",
  storagePoolName: "default",
  storageMarker: "m",
  sandboxHostId: "host-of-someone-else",
  hostOwnerId: "pool-owner",
  usagePoolId: "pool1",
  usageMemberId: "m1",
  accessGraceUntil: null,
  templateId: "t1",
  templateRevisionId: "r1",
  originPoolId: "pool1",
  state: "DELETED",
  generation: 3,
  startedAt: T,
  readyAt: null,
  leaseRevision: 1,
  leaseExpiresAt: null,
  leaseExpireAction: "DESTROY",
  leaseExpiresAtRequested: null,
  leaseExpireActionRequested: null,
  leaseExpiresAtEffective: null,
  leaseExpireActionEffective: null,
  metadata: { team: "a" },
  egressPolicy: null,
  egressPolicyHash: null,
  egressRequest: null,
  egressModeReason: null,
  egressDeniedGrants: [],
  createdAt: T,
  updatedAt: T,
  lastErrorDetail: "SECRET host diagnostic",
};
const operationRow = {
  id: "op1",
  userId: "owner",
  sandboxId: "sb1",
  kind: "RUN_COMMAND",
  state: "SUCCEEDED",
  generation: 1,
  errorCode: null,
  failure: { resource: "command", effect: "none", reason: "ram" },
  createdAt: T,
  updatedAt: T,
  dispatchedAt: T,
  completedAt: T,
  result: { stdout: "SECRET output" },
  errorDetail: "SECRET detail",
};

// Columns a credential_event row has beyond the payload projection; the
// mock returns them all, so the renderer must pick, not spread.
const credentialEventRow = {
  id: "cev1",
  userId: "owner",
  type: "capture_lost",
  credentialId: "cred1",
  accountId: "acc1",
  instanceId: "inst1",
  leaseId: "lease1",
  sandboxId: "sb1",
  reason: "capture_lost",
  hostId: "host-of-someone-else",
  storageSeq: 7,
  sizeBytes: 4096,
  at: T,
  value: "SECRET credential value",
};

function client(credentialRow: Record<string, unknown> | null = credentialEventRow) {
  return {
    sandbox: { findFirst: vi.fn(async () => sandboxRow) },
    sandboxOperation: { findFirst: vi.fn(async () => operationRow) },
    credentialEvent: { findFirst: vi.fn(async () => credentialRow) },
  } as never;
}
const event = (type: string, facts: unknown) => ({
  id: `evt_${"0".repeat(32)}`,
  userId: "owner",
  type,
  sandboxId: "sb1",
  operationId: "op1",
  occurredAt: T,
  facts,
});

describe("webhook renderer (public /v1 projection only)", () => {
  it("renders create_failed from facts with the PUBLIC error code and a redacted foreign host", async () => {
    const body = await renderWebhookEvent(
      client(),
      event("sandbox.create_failed", {
        from: "PROVISIONING",
        to: "DELETED",
        generation: 3,
        errorCode: "some_internal_code",
      }),
    );
    const parsed = JSON.parse(body ?? "null");
    expect(parsed).toEqual({
      id: `evt_${"0".repeat(32)}`,
      schemaVersion: 1,
      occurredAt: T.toISOString(),
      type: "sandbox.create_failed",
      data: {
        sandbox: {
          id: "sb1",
          name: "quiet-otter",
          state: "DELETED",
          previousState: "PROVISIONING",
          generation: 3,
          hostId: null,
          templateId: "t1",
          templateRevisionId: "r1",
          originPoolId: "pool1",
          metadata: { team: "a" },
        },
        error: { code: "internal" },
      },
    });
    expect(body).not.toContain("SECRET");
    expect(body).not.toContain("host-of-someone-else");
  });

  it("takes operation state and error code from facts, never result, output or detail", async () => {
    const body = await renderWebhookEvent(
      client(),
      event("operation.completed", {
        from: "RUNNING",
        to: "UNKNOWN_OUTCOME",
        kind: "RUN_COMMAND",
        generation: 1,
        errorCode: "private_config_refused",
      }),
    );
    const parsed = JSON.parse(body ?? "null");
    expect(parsed.data.operation).toEqual({
      id: "op1",
      sandboxId: "sb1",
      kind: "RUN_COMMAND",
      state: "UNKNOWN_OUTCOME",
      outcome: "unknown",
      errorCode: "unknown_outcome",
      // failure.reason is dropped unless the error is host_capacity (as /v1).
      failure: { resource: "command", effect: "none" },
      completedAt: T.toISOString(),
    });
    expect(body).not.toContain("SECRET");
  });

  it("renders credential.* from the owner's event row: ids and a reason code only", async () => {
    const c = client() as unknown as {
      credentialEvent: { findFirst: ReturnType<typeof vi.fn> };
    };
    const body = await renderWebhookEvent(
      c as never,
      event("credential.capture_lost", { credentialEventId: "cev1" }),
    );
    expect(JSON.parse(body ?? "null")).toEqual({
      id: `evt_${"0".repeat(32)}`,
      schemaVersion: 1,
      occurredAt: T.toISOString(),
      type: "credential.capture_lost",
      data: {
        credential: { id: "cred1", accountId: "acc1", instanceId: "inst1" },
        leaseId: "lease1",
        sandboxId: "sb1",
        reason: "capture_lost",
      },
    });
    expect(body).not.toContain("SECRET");
    expect(body).not.toContain("host-of-someone-else");
    expect(body).not.toContain("4096");
    // The query itself is the disclosure boundary: owner-scoped, fixed projection.
    expect(c.credentialEvent.findFirst).toHaveBeenCalledWith({
      where: { id: "cev1", userId: "owner" },
      select: webhookCredentialEventRenderSelect,
    });
    expect(Object.keys(webhookCredentialEventRenderSelect).sort()).toEqual(
      [
        "accountId",
        "credentialId",
        "id",
        "instanceId",
        "leaseId",
        "reason",
        "sandboxId",
        "type",
        "userId",
      ].sort(),
    );
  });

  it("renders every credential event type and drops a reason that is not a fixed token", async () => {
    for (const type of ["capture_failed", "recovery_required", "needs_login"]) {
      const body = await renderWebhookEvent(
        client({ ...credentialEventRow, type, reason: "Free text: SECRET" }),
        event(`credential.${type}`, { credentialEventId: "cev1" }),
      );
      const parsed = JSON.parse(body ?? "null");
      expect(parsed.type).toBe(`credential.${type}`);
      expect(parsed.data.reason).toBeNull();
      expect(body).not.toContain("SECRET");
    }
  });

  it("returns null for a credential event of another type, a missing row or bad facts", async () => {
    expect(
      await renderWebhookEvent(
        client({ ...credentialEventRow, type: "value_written" }),
        event("credential.capture_lost", { credentialEventId: "cev1" }),
      ),
    ).toBeNull();
    expect(
      await renderWebhookEvent(
        client(null),
        event("credential.recovery_required", { credentialEventId: "cev1" }),
      ),
    ).toBeNull();
    expect(
      await renderWebhookEvent(client(), event("credential.needs_login", { other: 1 })),
    ).toBeNull();
  });

  it("returns null for malformed facts or a missing row", async () => {
    expect(await renderWebhookEvent(client(), event("sandbox.ready", { to: "NOPE" }))).toBeNull();
    const empty = {
      sandbox: { findFirst: vi.fn(async () => null) },
      sandboxOperation: { findFirst: vi.fn(async () => null) },
    } as never;
    expect(
      await renderWebhookEvent(
        empty,
        event("sandbox.ready", { from: null, to: "READY", generation: 1, errorCode: null }),
      ),
    ).toBeNull();
  });

  it("enforces the strict schema and the 64 KiB cap", () => {
    const base = {
      id: `evt_${"1".repeat(32)}`,
      type: "webhook.test",
      schemaVersion: 1,
      occurredAt: T.toISOString(),
    };
    expect(
      serializeWebhookPayload("webhook.test", { ...base, data: { endpointId: "e1" } }),
    ).not.toBeNull();
    expect(
      serializeWebhookPayload("webhook.test", { ...base, data: { endpointId: "e1", extra: 1 } }),
    ).toBeNull();
    expect(
      serializeWebhookPayload("operation.completed", {
        ...base,
        type: "operation.completed",
        data: { operation: { id: "x".repeat(70_000) } },
      }),
    ).toBeNull();
    expect(renderTestEvent({ eventId: base.id, endpointId: "e1", occurredAt: T })).toContain(
      '"type":"webhook.test"',
    );
  });
});
