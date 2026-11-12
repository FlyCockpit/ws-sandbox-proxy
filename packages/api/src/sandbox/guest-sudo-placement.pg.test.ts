/**
 * guestSudo on real PostgreSQL: the effective value and `guestRoot` are
 * resolved once at materialization (own capable host → on; no capability →
 * HOST_UNSUPPORTED; foreign without consent → NODE_POLICY; consent never
 * filters), the revision's root taint is read in the same transaction, a
 * queued create keeps its requested value until placement, and the CHECKs
 * refuse managed sandboxes with guestSudo.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "guest-sudo-placement-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("./sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { runCapacityQueuePass } from "./capacity-queue";
import { leaseNow } from "./lease";
import { createSandbox } from "./services/sandboxes";
import { poolFixture } from "./testing/pool-fixtures";
import { seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

type Fixture = Awaited<ReturnType<typeof poolFixture>>;

/** A use grantee with its own exact revision on both fixture hosts. */
async function grantee(f: Fixture) {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Grantee",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: id },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: f.host.id,
      slug: `g-${id.slice(0, 8)}`,
      label: "Grantee",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
    where: { revisionId: revision.id, hostId: f.host.id },
  });
  const { id: _id, ...copy } = availability;
  await db.inspect.sandboxTemplateAvailability.create({ data: { ...copy, hostId: f.other.id } });
  return {
    owner: { kind: "session" as const, ownerId: id },
    input: (extra: Record<string, unknown> = {}) => ({
      poolId: f.pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
      ...extra,
    }),
  };
}

/** The static capability (hello) and live consent (egress-state report). */
async function setGuestSudo(hostId: string, capable: boolean, consent: boolean) {
  await db.inspect.sandboxHost.update({
    where: { id: hostId },
    data: {
      daemonFeatures: { egressPolicy: true, terminal: true, guestSudo: capable },
      daemonGuestSudoForOthers: consent,
    },
  });
}
const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
const direct = (f: Fixture, extra: Record<string, unknown> = {}) => ({
  template: "base",
  sandboxHostId: f.host.id,
  idempotencyKey: randomUUID(),
  ...extra,
});
const fields = (sandbox: Awaited<ReturnType<typeof row>>) => ({
  guestSudoRequested: sandbox.guestSudoRequested,
  guestSudo: sandbox.guestSudo,
  guestSudoReason: sandbox.guestSudoReason,
  guestRoot: sandbox.guestRoot,
});

describe("resolveEffectiveGuestSudo at materialization", () => {
  it("own capable host: omitted → on (guestRoot), explicit false → off", async () => {
    const f = await poolFixture(db);
    await setGuestSudo(f.host.id, true, false);
    const on = await createSandbox(f.owner, direct(f));
    expect(fields(await row(on.id))).toEqual({
      guestSudoRequested: true,
      guestSudo: true,
      guestSudoReason: null,
      guestRoot: true,
    });
    expect(on).toMatchObject({ guestSudo: true, guestRoot: true });
    const off = await createSandbox(f.owner, direct(f, { guestSudo: false }));
    expect(fields(await row(off.id))).toEqual({
      guestSudoRequested: false,
      guestSudo: false,
      guestSudoReason: null,
      guestRoot: false,
    });
  });

  it("a host without the capability degrades with HOST_UNSUPPORTED", async () => {
    const f = await poolFixture(db);
    await setGuestSudo(f.host.id, false, true);
    const created = await createSandbox(f.owner, direct(f));
    expect(fields(await row(created.id))).toEqual({
      guestSudoRequested: true,
      guestSudo: false,
      guestSudoReason: "HOST_UNSUPPORTED",
      guestRoot: false,
    });
  });

  it("foreign node: NODE_POLICY without consent, on with consent; consent never filters", async () => {
    const f = await poolFixture(db);
    const g = await grantee(f);
    for (const host of f.hosts) await setGuestSudo(host.id, true, false);
    const denied = await createSandbox(g.owner, g.input());
    expect(fields(await row(denied.id))).toEqual({
      guestSudoRequested: true,
      guestSudo: false,
      guestSudoReason: "NODE_POLICY",
      guestRoot: false,
    });
    for (const host of f.hosts) await setGuestSudo(host.id, true, true);
    const allowed = await createSandbox(g.owner, g.input());
    expect(fields(await row(allowed.id))).toMatchObject({ guestSudo: true, guestRoot: true });
  });

  it("the revision's root taint sets guestRoot with guestSudo off; the wssp recipe waives builtWithRoot", async () => {
    const f = await poolFixture(db);
    await setGuestSudo(f.host.id, true, false);
    const build = {
      sourceKind: "BUILD" as const,
      buildId: randomUUID(),
      recipeDigest: "a".repeat(64),
      builtWithRoot: true,
    };
    await db.inspect.sandboxTemplateRevision.update({ where: { id: f.revision.id }, data: build });
    const tainted = await createSandbox(f.owner, direct(f, { guestSudo: false }));
    expect(fields(await row(tainted.id))).toEqual({
      guestSudoRequested: false,
      guestSudo: false,
      guestSudoReason: null,
      guestRoot: true,
    });
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: f.revision.id },
      data: { builtWithWsspRecipe: true },
    });
    const exempt = await createSandbox(f.owner, direct(f, { guestSudo: false }));
    expect((await row(exempt.id)).guestRoot).toBe(false);
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: f.revision.id },
      data: { builtWithWsspRecipe: false, builtWithRoot: false, capturedWithGuestRoot: true },
    });
    const captured = await createSandbox(f.owner, direct(f, { guestSudo: false }));
    expect((await row(captured.id)).guestRoot).toBe(true);
  });

  it("a queued create keeps its requested value and resolves it when placed", async () => {
    const f = await poolFixture(db);
    const g = await grantee(f);
    for (const host of f.hosts) await setGuestSudo(host.id, true, false);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { memoryReservedMiB: 65536 },
    });
    const waiting = await createSandbox(g.owner, g.input({ waitForCapacityMs: 3_600_000 }));
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
    expect(fields(await row(waiting.id))).toMatchObject({ guestSudo: false, guestRoot: false });
    const wait = await db.inspect.sandboxCapacityWait.findUniqueOrThrow({
      where: { sandboxId: waiting.id },
    });
    expect(wait.intent).toMatchObject({ guestSudo: true });
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { memoryReservedMiB: 0 },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await row(waiting.id)).toMatchObject({
      state: "REQUESTED",
      guestSudoRequested: true,
      guestSudo: false,
      guestSudoReason: "NODE_POLICY",
    });
  });
});

describe("CHECKs", () => {
  it("refuse guestSudo on a managed sandbox, without guestRoot, and a reason with guestSudo on", async () => {
    const f = await poolFixture(db);
    await setGuestSudo(f.host.id, true, false);
    const created = await createSandbox(f.owner, direct(f));
    const refused = (data: Record<string, unknown>) =>
      expect(db.inspect.sandbox.update({ where: { id: created.id }, data })).rejects.toThrow(
        /sandbox_instance_guest_sudo/,
      );
    await refused({ purpose: "CREDENTIAL_LOGIN" });
    await refused({ guestRoot: false });
    await refused({ guestSudoReason: "NODE_POLICY" });
  });
});
