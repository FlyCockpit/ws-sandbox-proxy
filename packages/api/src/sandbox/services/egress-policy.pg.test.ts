import { seedLaunchHost } from "../testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { DENY_ALL_EGRESS_POLICY, toEgressPolicyWire } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../testing/resource-fixtures";

/**
 * C34 (M5 deny-default egress): against real PostgreSQL — an invalid policy is
 * rejected with the typed error before any row exists; a policy-bearing create
 * against a host without the egress capability is UNSUPPORTED_CAPABILITY with
 * zero sandbox, operation and outbox rows; a capable host persists the
 * normalized policy and hash and carries them into the create outbox payload;
 * no policy records deny-all; an idempotent retry returns the same sandbox with
 * the same recorded policy; a cold reconnect re-dispatches the recorded policy;
 * metadata cannot widen egress; and the recorded policy is owner-scoped.
 */

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "egress-policy-pg-test-secret",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { createSandboxInput } = await import("../contracts");
const { sdkGetSandbox } = await import("../sdk-reads");
const { createSandbox, reconnectSandbox } = await import("./sandboxes");

afterAll(() => db.close());

const FP = `sha256:${"d".repeat(64)}`;
const session = (ownerId: string) => ({ kind: "session" as const, ownerId });

async function seedOwner(egressEnforcement: boolean) {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      lastHeartbeatAt: new Date(),
      egressEnforcement,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  return { ownerId, hostId: host.id, templateId: template.id };
}

const counts = async (ownerId: string) => ({
  sandboxes: await db.inspect.sandbox.count({ where: { userId: ownerId } }),
  operations: await db.inspect.sandboxOperation.count({ where: { userId: ownerId } }),
  outbox: await db.inspect.outboxEvent.count({ where: { userId: ownerId } }),
});

const liveCount = async (hostId: string) =>
  (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } })).liveCount;

it("rejects an invalid policy with the typed error before any row or dispatch exists", async () => {
  const seeded = await seedOwner(true);
  const before = await counts(seeded.ownerId);
  await expect(
    createSandbox(
      session(seeded.ownerId),
      createSandboxInput.parse({
        template: "revision/" + seeded.templateId,
        sandboxHostId: seeded.hostId,
        idempotencyKey: `egress-${randomUUID()}`,
        egress: { domains: ["*.example.com"] },
      }),
    ),
  ).rejects.toMatchObject({
    code: "BAD_REQUEST",
    data: { code: "sandbox.egress_policy_invalid" },
  });
  expect(await counts(seeded.ownerId)).toEqual(before);
});

it.each([
  ["EC2 IPv6 metadata exact", "fd00:ec2::254/128"],
  ["IPv6 unique-local supernet", "fc00::/7"],
  ["Alibaba metadata exact", "100.100.100.200/32"],
])(
  "rejects a non-link-local metadata CIDR (%s) with the typed error and zero allocation",
  async (_label, cidr) => {
    const seeded = await seedOwner(true);
    const before = await counts(seeded.ownerId);
    await expect(
      createSandbox(
        session(seeded.ownerId),
        createSandboxInput.parse({
          template: "revision/" + seeded.templateId,
          sandboxHostId: seeded.hostId,
          idempotencyKey: `egress-${randomUUID()}`,
          egress: { cidrs: [cidr] },
        }),
      ),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      data: { code: "sandbox.egress_policy_invalid" },
    });
    expect(await counts(seeded.ownerId)).toEqual(before);
    expect(await liveCount(seeded.hostId)).toBe(0);
  },
);

it("rejects a policy-bearing create on a host without the egress capability, before any VM allocation", async () => {
  const seeded = await seedOwner(false);
  const before = await counts(seeded.ownerId);
  await expect(
    createSandbox(
      session(seeded.ownerId),
      createSandboxInput.parse({
        template: "revision/" + seeded.templateId,
        sandboxHostId: seeded.hostId,
        idempotencyKey: `egress-${randomUUID()}`,
        egress: { domains: ["example.com"] },
      }),
    ),
  ).rejects.toMatchObject({
    code: "BAD_REQUEST",
    data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress" },
  });
  expect(await counts(seeded.ownerId)).toEqual(before);
  expect(await liveCount(seeded.hostId)).toBe(0);
});

it("rejects an omitted-policy (deny-all) create on a host without the egress capability, before any VM allocation", async () => {
  const seeded = await seedOwner(false);
  const before = await counts(seeded.ownerId);
  await expect(
    createSandbox(
      session(seeded.ownerId),
      createSandboxInput.parse({
        template: "revision/" + seeded.templateId,
        sandboxHostId: seeded.hostId,
        idempotencyKey: `egress-${randomUUID()}`,
      }),
    ),
  ).rejects.toMatchObject({
    code: "BAD_REQUEST",
    data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress" },
  });
  expect(await counts(seeded.ownerId)).toEqual(before);
  expect(await liveCount(seeded.hostId)).toBe(0);
});

it("rejects a cold reconnect on a host that no longer enforces egress, before any launch intent", async () => {
  const seeded = await seedOwner(true);
  const created = await createSandbox(
    session(seeded.ownerId),
    createSandboxInput.parse({
      template: "revision/" + seeded.templateId,
      sandboxHostId: seeded.hostId,
      idempotencyKey: `egress-${randomUUID()}`,
    }),
  );
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  // The replacement hello dropped the capability after the create committed.
  await db.inspect.sandboxHost.update({
    where: { id: seeded.hostId },
    data: { egressEnforcement: false },
  });
  const operations = await db.inspect.sandboxOperation.count({
    where: { userId: seeded.ownerId, kind: "RECONNECT_SANDBOX" },
  });
  await expect(
    reconnectSandbox(session(seeded.ownerId), {
      id: created.id,
      idempotencyKey: `reconnect-${randomUUID()}`,
      mode: "cold",
      timeoutMs: 3_600_000,
      onExpire: "stop",
    }),
  ).rejects.toMatchObject({
    code: "BAD_REQUEST",
    data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress" },
  });
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: seeded.ownerId, kind: "RECONNECT_SANDBOX" },
    }),
  ).toBe(operations);
  expect(
    await db.inspect.outboxEvent.count({
      where: { aggregateId: created.id, eventType: "sandbox.reconnect_requested" },
    }),
  ).toBe(0);
  expect(await liveCount(seeded.hostId)).toBe(1);
});

it("persists the normalized policy and hash and carries them in the create outbox payload", async () => {
  const seeded = await seedOwner(true);
  const created = await createSandbox(
    session(seeded.ownerId),
    createSandboxInput.parse({
      template: "revision/" + seeded.templateId,
      sandboxHostId: seeded.hostId,
      idempotencyKey: `egress-${randomUUID()}`,
      egress: { domains: ["Example.COM."], cidrs: ["128.66.1.2/24"] },
      metadata: { egress: "0.0.0.0/0" },
    }),
  );
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect(row.egressPolicy).toEqual({ domains: ["example.com"], cidrs: ["128.66.1.0/24"] });
  expect(row.egressPolicyHash).toMatch(/^[0-9a-f]{64}$/);
  // The metadata key never widens egress.
  expect(row.metadata).toEqual({ egress: "0.0.0.0/0" });
  const outbox = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: created.id, eventType: "sandbox.create_requested" },
  });
  expect(outbox.payload).toMatchObject({
    egressPolicy: { domains: ["example.com"], cidrs: ["128.66.1.0/24"] },
    egressPolicyHash: row.egressPolicyHash,
  });
});

it("records deny-all when no policy is given, and an idempotent retry keeps the recorded policy", async () => {
  const seeded = await seedOwner(true);
  const input = createSandboxInput.parse({
    template: "revision/" + seeded.templateId,
    sandboxHostId: seeded.hostId,
    idempotencyKey: `egress-${randomUUID()}`,
  });
  const created = await createSandbox(session(seeded.ownerId), input);
  const replay = await createSandbox(session(seeded.ownerId), input);
  expect(replay.id).toBe(created.id);
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  // Stored in the wire form: allowlist rows carry no `mode` key.
  expect(row.egressPolicy).toEqual(toEgressPolicyWire(DENY_ALL_EGRESS_POLICY));
  expect(row.egressPolicyHash).toMatch(/^[0-9a-f]{64}$/);
  expect(await db.inspect.sandbox.count({ where: { userId: seeded.ownerId } })).toBe(1);
});

it("a cold reconnect re-dispatches the recorded policy and hash verbatim", async () => {
  const seeded = await seedOwner(true);
  const created = await createSandbox(
    session(seeded.ownerId),
    createSandboxInput.parse({
      template: "revision/" + seeded.templateId,
      sandboxHostId: seeded.hostId,
      idempotencyKey: `egress-${randomUUID()}`,
      egress: { domains: ["example.com"] },
    }),
  );
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  await reconnectSandbox(session(seeded.ownerId), {
    id: created.id,
    idempotencyKey: `reconnect-${randomUUID()}`,
    mode: "cold",
    timeoutMs: 3_600_000,
    onExpire: "stop",
  });
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: created.id, eventType: "sandbox.reconnect_requested" },
  });
  expect(event.payload).toMatchObject({
    egressPolicy: { domains: ["example.com"], cidrs: [] },
    egressPolicyHash: row.egressPolicyHash,
  });
});

it("discloses the recorded policy to the owner only and never widens with host capability changes", async () => {
  const a = await seedOwner(true);
  const b = await seedOwner(true);
  const created = await createSandbox(
    session(a.ownerId),
    createSandboxInput.parse({
      template: "revision/" + a.templateId,
      sandboxHostId: a.hostId,
      idempotencyKey: `egress-${randomUUID()}`,
      egress: { domains: ["example.com"] },
    }),
  );
  // Host capability loss after create does not change the recorded policy.
  await db.inspect.sandboxHost.update({
    where: { id: a.hostId },
    data: { egressEnforcement: false },
  });
  const view = await sdkGetSandbox(session(a.ownerId), created.id);
  expect(view.egress).toEqual({ mode: "allowlist", domains: ["example.com"], cidrs: [] });
  await expect(sdkGetSandbox(session(b.ownerId), created.id)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
});
