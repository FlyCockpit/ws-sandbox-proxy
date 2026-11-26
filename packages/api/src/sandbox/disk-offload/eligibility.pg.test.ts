import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * Offload eligibility against real PostgreSQL: `loginStateSettled` per predicate, the receipt gate, and the
 * `restoreHostEligibility` matrix (one cell per requirement, each flipping
 * exactly one fact of an otherwise eligible host).
 */
const db = await pgTestDatabase();
afterAll(() => db.close());
const { seedOwner, seedSandbox } = await import("../../webhooks/testing/fixtures");
const service = await import("../../credentials/service");
const { markCredentialFilesEver } = await import("../../credentials/specs");
const { seedStoppedOnHost } = await import("../testing/offload-fixtures");
const { hostDatabaseNow } = await import("../relay-fence");
const {
  loginStateSettled,
  offloadReceiptsSettled,
  RESTORE_SANDBOX_FACTS_SELECT,
  restoreHostEligibility,
} = await import("./eligibility");

const savedKey = process.env.DATA_ENCRYPTION_KEY;
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
});

const DOCUMENT = {
  schemaVersion: 1,
  id: "fakecli",
  displayName: "Fake CLI",
  login: { command: "fakecli login", method: "device-code" },
  credentials: { files: { required: [".fakecli/token"], optional: [], exclude: [] } },
};

async function loginWorld() {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const definition = await service.createDefinition(actor, { document: DOCUMENT });
  const login = await service.createLogin(actor, { name: "fakecli", definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id, name: "a" });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  const sandbox = await seedSandbox(db.inspect, owner, "STOPPED");
  const lease = async (state: "ACTIVE" | "RELEASED" | "RECOVERY_REQUIRED" | "ABANDONED") =>
    db.inspect.credentialLease.create({
      data: {
        userId: owner,
        credentialId: login.id,
        accountId: account.id,
        instanceId: instance.id,
        sandboxId: sandbox.id,
        operationId: `op-${randomUUID()}`,
        kind: "WORKLOAD",
        exclusive: false,
        state,
        ...(state === "RELEASED" || state === "ABANDONED" ? { releasedAt: new Date() } : {}),
      },
      select: { id: true },
    });
  const settled = () => db.prisma.$transaction((tx) => loginStateSettled(tx, sandbox.id));
  return { owner, login, instance, sandbox, lease, settled };
}

describe("loginStateSettled (§4 safeguard 1)", () => {
  it("a sandbox with no login state is settled", async () => {
    const w = await loginWorld();
    expect(await w.settled()).toBe(true);
  });

  it.each([
    ["RELEASED", true],
    ["ABANDONED", true],
    ["ACTIVE", false],
    ["RECOVERY_REQUIRED", false],
  ] as const)("a lease in %s → settled=%s", async (state, expected) => {
    const w = await loginWorld();
    await w.lease(state);
    expect(await w.settled()).toBe(expected);
  });

  it("recoverable uncleared residue is unsettled; cleared or unrecoverable residue is not", async () => {
    const w = await loginWorld();
    const lease = await w.lease("RELEASED");
    const binding = await db.inspect.credentialBinding.create({
      data: {
        leaseId: lease.id,
        instanceId: w.instance.id,
        sandboxId: w.sandbox.id,
        hostId: "host",
        grantGeneration: 1,
        purpose: "INSTALL",
      },
      select: { id: true },
    });
    const residue = await db.inspect.credentialResidue.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        credentialId: w.login.id,
        instanceId: w.instance.id,
        leaseId: lease.id,
        bindingId: binding.id,
        grantGeneration: 1,
        paths: [".fakecli/token"],
        recoverable: true,
      },
      select: { id: true },
    });
    expect(await w.settled()).toBe(false);
    await db.inspect.credentialResidue.update({
      where: { id: residue.id },
      data: { recoverable: false },
    });
    expect(await w.settled()).toBe(true);
    await db.inspect.credentialResidue.update({
      where: { id: residue.id },
      data: { recoverable: true, clearedAt: new Date(), clearReason: "scrubbed" },
    });
    expect(await w.settled()).toBe(true);
  });

  it("a pending capture of any of the sandbox's leases is unsettled", async () => {
    const w = await loginWorld();
    const lease = await w.lease("RELEASED");
    const host = await db.inspect.sandboxHost.create({
      data: { userId: w.owner, slug: `h-${randomUUID().slice(0, 8)}`, label: "H" },
      select: { id: true },
    });
    await db.inspect.credentialPendingCapture.create({
      data: {
        hostId: host.id,
        captureId: `c-${randomUUID()}`,
        leaseId: lease.id,
        bindingId: "b",
        kidR: "k",
        kind: "free",
      },
    });
    expect(await w.settled()).toBe(false);
  });
});

describe("offloadReceiptsSettled (§4a N4)", () => {
  async function opWorld() {
    const owner = await seedOwner(db.inspect);
    const sandbox = await seedSandbox(db.inspect, owner, "STOPPED", { generation: 3 });
    const op = (data: {
      kind: "RUN_COMMAND" | "STOP_SANDBOX";
      state: "UNKNOWN_OUTCOME" | "SUCCEEDED" | "RUNNING";
      generation: number;
      createdAt: Date;
      result?: object;
    }) =>
      db.inspect.sandboxOperation.create({
        data: {
          digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
          ...requestDigestMetadata(),

          userId: owner,
          sandboxId: sandbox.id,
          idempotencyKey: randomUUID(),
          requestBodyHash: "h",
          ...data,
        },
      });
    const gate = () => db.prisma.$transaction((tx) => offloadReceiptsSettled(tx, sandbox.id, 3));
    return { op, gate };
  }
  const t = (minutes: number) => new Date(Date.UTC(2026, 0, 1, 0, minutes));

  it("an UNKNOWN command of the stopped generation is retired only by a later host-observed stop", async () => {
    const w = await opWorld();
    await w.op({ kind: "RUN_COMMAND", state: "UNKNOWN_OUTCOME", generation: 3, createdAt: t(1) });
    expect(await w.gate()).toBe(false);
    // A stop created before the command does not retire it.
    await w.op({
      kind: "STOP_SANDBOX",
      state: "SUCCEEDED",
      generation: 3,
      createdAt: t(0),
      result: { state: "stopped" },
    });
    expect(await w.gate()).toBe(false);
    await w.op({
      kind: "STOP_SANDBOX",
      state: "SUCCEEDED",
      generation: 3,
      createdAt: t(2),
      result: { state: "stopped" },
    });
    expect(await w.gate()).toBe(true);
  });

  it("an UNKNOWN command of an older generation does not block; work in flight does", async () => {
    const w = await opWorld();
    await w.op({ kind: "RUN_COMMAND", state: "UNKNOWN_OUTCOME", generation: 2, createdAt: t(1) });
    expect(await w.gate()).toBe(true);
    await w.op({ kind: "RUN_COMMAND", state: "RUNNING", generation: 3, createdAt: t(3) });
    expect(await w.gate()).toBe(false);
  });
});

describe("restoreHostEligibility (§5 matrix)", () => {
  async function eligibleWorld() {
    const owner = await seedOwner(db.inspect);
    const { host, sandbox } = await seedStoppedOnHost(db.inspect, { userId: owner });
    const facts = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: sandbox.id },
      select: RESTORE_SANDBOX_FACTS_SELECT,
    });
    const verdict = (
      over: Partial<typeof facts> = {},
      restriction: Parameters<typeof restoreHostEligibility>[3] = null,
      poolId: string | null = null,
    ) =>
      db.prisma.$transaction((tx) =>
        restoreHostEligibility(tx, { ...facts, ...over }, { hostId: host.id, poolId }, restriction),
      );
    return { owner, host, sandbox, facts, verdict };
  }
  const reason = (v: { ok: boolean; reason?: string }) => (v.ok ? "ok" : v.reason);

  it("an own, connected, capable host is eligible", async () => {
    const w = await eligibleWorld();
    expect(reason(await w.verdict())).toBe("ok");
  });

  it.each([
    ["host_unavailable", { status: "DISCONNECTED" as const }],
    ["host_unavailable", { lastHeartbeatAt: new Date(Date.now() - 120_000) }],
    ["host_unavailable", { daemonSchedulable: false }],
    ["host_draining", { draining: true }],
    ["host_quarantined", { quarantinedAt: new Date() }],
    ["egress_guard_unavailable", { daemonEgressGuardOk: false }],
    ["egress_unsupported", { egressEnforcement: false }],
    ["disk_offload_unsupported", { daemonDiskOffload: false }],
    [
      "image_fetch_unsupported",
      { daemonFeatures: { egressPolicy: true, image: { fetch: false } } },
    ],
  ])("host fact → %s", async (expected, hostData) => {
    const w = await eligibleWorld();
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: hostData });
    expect(reason(await w.verdict())).toBe(expected);
  });

  it("a heartbeat committed after the caller sampled its clock is fresh; one dated in the future is not", async () => {
    const w = await eligibleWorld();
    const at = async (sql: "now" | "future") =>
      (
        await db.inspect.$queryRaw<{ at: Date }[]>`UPDATE sandbox_host
          SET "lastHeartbeatAt" = (clock_timestamp() AT TIME ZONE 'UTC')
            + CASE WHEN ${sql} = 'future' THEN interval '60 seconds' ELSE interval '0' END
          WHERE id = ${w.host.id} RETURNING "lastHeartbeatAt" AS at`
      )[0]!.at;
    const verdictAfter = (sql: "now" | "future") =>
      db.prisma.$transaction(async (tx) => {
        // Restore selection samples its clock, then reads candidates: the
        // heartbeat lands in between, strictly after the sample.
        const now = await hostDatabaseNow(tx);
        await db.inspect.$executeRaw`SELECT pg_sleep(0.005)`;
        const stamped = await at(sql);
        expect(stamped.getTime()).toBeGreaterThan(now.getTime());
        return restoreHostEligibility(tx, w.facts, { hostId: w.host.id, poolId: null }, null, now);
      });
    expect(reason(await verdictAfter("now"))).toBe("ok");
    expect(reason(await verdictAfter("future"))).toBe("host_unavailable");
  });

  it("no storage pool on the current epoch that holds the root → no_room", async () => {
    const w = await eligibleWorld();
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: w.host.id },
      data: { capacityGiB: 1 },
    });
    expect(reason(await w.verdict())).toBe("no_room");
  });

  it("a managed purpose is never restored", async () => {
    const w = await eligibleWorld();
    expect(reason(await w.verdict({ purpose: "TEMPLATE_BUILD" }))).toBe("purpose_managed");
  });

  it("guestSudo needs the host capability", async () => {
    const w = await eligibleWorld();
    expect(reason(await w.verdict({ guestSudo: true }))).toBe("guest_sudo_unsupported");
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: {
        daemonFeatures: {
          egressPolicy: true,
          guestSudo: true,
          image: { fetch: true, acceptForeign: true },
        },
      },
    });
    expect(reason(await w.verdict({ guestSudo: true }))).toBe("ok");
  });

  it("a recorded open policy needs egressOpen; never re-derived or narrowed", async () => {
    const w = await eligibleWorld();
    const open = { mode: "open", domains: [], cidrs: [] };
    expect(reason(await w.verdict({ egressPolicy: open }))).toBe("open_egress_not_permitted");
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: {
        daemonFeatures: { egressPolicy: true, egressOpen: true, image: { fetch: true } },
      },
    });
    expect(reason(await w.verdict({ egressPolicy: open }))).toBe("ok");
  });

  it("a stale copy of this sandbox on the host excludes it (R9)", async () => {
    const w = await eligibleWorld();
    const pool = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
      where: { sandboxHostId: w.host.id },
    });
    await db.inspect.sandboxDiskCopy.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        hostId: w.host.id,
        hostOwnerId: w.owner,
        storagePoolId: pool.id,
        storageMarker: pool.marker,
        storagePoolName: pool.name,
        rootChargeGiB: 33,
        offloadSeq: 1,
        createKey: "k",
        baseFingerprint: `sha256:${"c".repeat(64)}`,
      },
    });
    expect(reason(await w.verdict())).toBe("stale_copy_on_host");
  });

  it("SDK-key restrictions (F10, §5a): host and pool legs", async () => {
    const w = await eligibleWorld();
    expect(reason(await w.verdict({}, { hostIds: new Set(["other"]), poolIds: null }))).toBe(
      "key_host_not_allowed",
    );
    expect(reason(await w.verdict({}, { hostIds: new Set([w.host.id]), poolIds: null }))).toBe(
      "ok",
    );
    expect(reason(await w.verdict({}, { hostIds: null, poolIds: new Set(["p"]) }))).toBe(
      "key_pool_not_allowed",
    );
    expect(reason(await w.verdict({}, { hostIds: null, poolIds: new Set(["p"]) }, "p"))).toBe("ok");
  });

  describe("a foreign host", () => {
    async function foreignWorld() {
      const owner = await seedOwner(db.inspect);
      const other = await seedOwner(db.inspect);
      const own = await seedStoppedOnHost(db.inspect, { userId: owner });
      const foreign = await seedStoppedOnHost(db.inspect, { userId: other });
      const facts = await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: own.sandbox.id },
        select: RESTORE_SANDBOX_FACTS_SELECT,
      });
      const verdict = (over: Partial<typeof facts> = {}) =>
        db.prisma.$transaction((tx) =>
          restoreHostEligibility(tx, { ...facts, ...over }, { hostId: foreign.host.id }),
        );
      return { owner, own, foreign, facts, verdict };
    }

    it("accepting foreign images is eligible; refusing them is not", async () => {
      const w = await foreignWorld();
      expect(reason(await w.verdict())).toBe("ok");
      await db.inspect.sandboxHost.update({
        where: { id: w.foreign.host.id },
        data: { daemonFeatures: { egressPolicy: true, image: { fetch: true } } },
      });
      expect(reason(await w.verdict())).toBe("foreign_images_refused");
    });

    it("pin, login history and OWNED_NODES_ONLY each exclude it", async () => {
      const w = await foreignWorld();
      expect(reason(await w.verdict({ offloadPin: "OWN_HOSTS" }))).toBe("pinned_to_own_hosts");
      await db.prisma.$transaction((tx) => markCredentialFilesEver(tx, w.own.sandbox.id));
      const flagged = await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: w.own.sandbox.id },
        select: { credentialFilesEver: true },
      });
      expect(flagged.credentialFilesEver).toBe(true);
      expect(reason(await w.verdict({ credentialFilesEver: true }))).toBe(
        "login_history_own_hosts_only",
      );
      await db.inspect.sandboxTemplate.update({
        where: { id: w.facts.templateId },
        data: { imagePlacement: "OWNED_NODES_ONLY" },
      });
      expect(reason(await w.verdict())).toBe("image_placement_owned_only");
    });

    it("guestSudo there also needs its owner's consent; open egress needs consent", async () => {
      const w = await foreignWorld();
      await db.inspect.sandboxHost.update({
        where: { id: w.foreign.host.id },
        data: {
          daemonFeatures: {
            egressPolicy: true,
            egressOpen: true,
            guestSudo: true,
            image: { fetch: true, acceptForeign: true },
          },
          daemonGuestSudoForOthers: false,
        },
      });
      expect(reason(await w.verdict({ guestSudo: true }))).toBe("guest_sudo_unsupported");
      const open = { mode: "open", domains: [], cidrs: [] };
      expect(reason(await w.verdict({ egressPolicy: open }))).toBe("open_egress_not_permitted");
      await db.inspect.sandboxHost.update({
        where: { id: w.foreign.host.id },
        data: { daemonGuestSudoForOthers: true, daemonOpenEgressForOthers: true },
      });
      expect(reason(await w.verdict({ guestSudo: true, egressPolicy: open }))).toBe("ok");
    });
  });
});
