import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { encodeBundle, fromHex, parseLoginDefinition } from "@wssp/login-definition";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../sandbox/digest-context";
import { requestDigestMetadata } from "../sandbox/idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64) },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * C7b claims at cold reconnect against real PostgreSQL . Barriers are row locks observed through pg_stat_activity.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const service = await import("./service");
const { assertCredentialDrain, claimCreateLeases, claimResumeLeases } = await import("./resume");
const { buildSandboxCredentialSpec, preflightCredentialSpec } = await import("./specs");
const {
  authorizeCredentialClaims,
  credentialLaunchReady,
  requireCreateCredentialsAllowed,
  settleCredentialLaunch,
} = await import("./launch");
const { forceReleaseLease } = await import("./leases");
const {
  settleCredentialFreeResult,
  settleCredentialsOnDeleted,
  settleCredentialsOnStopped,
  settleCredentialTeardown,
} = await import("./teardown");
const { grantInstallBundle, recordInstalled, recordScrubbed } = await import("./grants");
const { commitCapture } = await import("./captures");
const { issueCurrentReturnKey } = await import("./return-keys");
const { applyCompleteCensus, newCensusAccumulator, accumulateCensusPage } = await import(
  "./census"
);
const { sealToReturnKey } = await import("./vault/sealed-box");
const { buildEnvelope } = await import("./vault/envelope");
afterAll(() => db.close());

const ORIGIN = "https://wssp.example.test";
const savedKey = process.env.DATA_ENCRYPTION_KEY;
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
});

const DOCUMENT = (
  id: string,
  sharing: "exclusive" | "shareable",
  path: string | null = `.config/${id}`,
  env: string[] = [],
) => ({
  schemaVersion: 1,
  id,
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: {
    files: {
      required: path === null ? [] : [path],
      optional: [] as string[],
      exclude: [] as string[],
    },
    ...(env.length > 0 ? { env: env.map((name) => ({ name, required: false })) } : {}),
    sharing,
  },
});
const CAPABLE = {
  credentials: {
    files: true,
    env: true,
    proxy: false,
    sealedReturn: true,
    checkpoint: true,
    specTransfer: true,
    maxBundleBytes: 4_823_129,
    returnKeyEpoch: 0,
  },
};
const CLAIM_UPDATE = /^sql:UPDATE credential_instance SET "activeLeases" = "activeLeases" \+ 1/;

type Owner = { owner: string; actor: { kind: "session"; ownerId: string }; host: { id: string } };

async function ownerWithHost(): Promise<Owner> {
  const owner = await seedOwner(db.inspect);
  const host = await db.inspect.sandboxHost.create({
    data: {
      userId: owner,
      slug: randomUUID(),
      label: "Own host",
      connectionEpoch: 1,
      status: "CONNECTED",
      daemonFeatures: CAPABLE,
    },
    select: { id: true },
  });
  return { owner, actor: { kind: "session", ownerId: owner }, host };
}

/** A login with accounts × instances (each READY with a real uploaded value). */
/**
 * Each login declares its own path (`.config/<slug>`) unless `opts.path`
 * names one: the logins of one sandbox must be disjoint (the claim gate).
 */
async function login(
  o: Owner,
  accounts: number,
  perAccount: number,
  capacity = 1,
  /** `path: null` is an env-only login (its value is `env` alone). */
  opts: { path?: string | null; env?: string[] } = {},
) {
  const slug = `tool-${randomUUID().slice(0, 8)}`;
  const path = opts.path === undefined ? `.config/${slug}` : opts.path;
  const document = DOCUMENT(slug, capacity === 1 ? "exclusive" : "shareable", path, opts.env);
  const definition = await service.createDefinition(o.actor, { document });
  const created = await service.createLogin(o.actor, { name: slug, definitionId: definition.id });
  const out: { accountId: string; instances: string[] }[] = [];
  for (let a = 0; a < accounts; a++) {
    const account = await service.createAccount(o.actor, { credentialId: created.id });
    const instances: string[] = [];
    for (let i = 0; i < perAccount; i++) {
      const instance = await service.createInstance(o.actor, {
        credentialId: created.id,
        accountId: account.id,
        ...(capacity !== 1 ? { maxConcurrent: capacity } : {}),
      });
      await service.writeValue(o.actor, {
        credentialId: created.id,
        instanceId: instance.id,
        ...(path === null
          ? { env: Object.fromEntries((opts.env ?? []).map((name) => [name, `v-${i}`])) }
          : {
              files: [
                { path, kind: "dir" as const },
                { path: `${path}/token`, contentBase64: Buffer.from(`v-${i}`).toString("base64") },
              ],
            }),
      });
      instances.push(instance.id);
    }
    out.push({ accountId: account.id, instances });
  }
  const digest = (
    await db.inspect.credential.findUniqueOrThrow({
      where: { id: created.id },
      select: { definitionDigest: true },
    })
  ).definitionDigest;
  return { credentialId: created.id, accounts: out, digest, document, path, slug };
}
type Login = Awaited<ReturnType<typeof login>>;

async function stoppedSandbox(o: Owner) {
  return seedSandbox(db.inspect, o.owner, "STOPPED", {
    sandboxHostId: o.host.id,
    hostOwnerId: o.owner,
    originHostId: o.host.id,
  });
}

async function attach(
  o: Owner,
  sandboxId: string,
  l: Login,
  recorded: { accountId?: string; instanceId?: string; requestedInstanceId?: string } = {},
) {
  return db.inspect.sandboxCredential.create({
    data: {
      sandboxId,
      userId: o.owner,
      credentialId: l.credentialId,
      accountId: recorded.accountId ?? null,
      instanceId: recorded.instanceId ?? null,
      requestedInstanceId: recorded.requestedInstanceId ?? null,
    },
  });
}

function resume(
  o: Owner,
  sandboxId: string,
  pins?: { credentialId: string; accountId?: string; instanceId?: string }[],
  actor = "resume",
) {
  return db.run(actor, () =>
    db.prisma.$transaction((tx) =>
      claimResumeLeases(tx, {
        principal: o.actor,
        ownerId: o.owner,
        sandboxId,
        operationId: `op-${randomUUID().slice(0, 8)}`,
        hostId: o.host.id,
        generation: 2,
        ...(pins ? { pins } : {}),
      }),
    ),
  );
}

const codeOf = (error: unknown) => (error as { data?: { code?: string } }).data?.code;

async function census(o: Owner, extra: Partial<Parameters<typeof accumulateCensusPage>[1]> = {}) {
  const acc = newCensusAccumulator();
  accumulateCensusPage(acc, {
    type: "credential.census",
    page: 0,
    complete: true,
    keyEpoch: 1,
    quarantined: [],
    entries: [],
    ...extra,
  });
  return applyCompleteCensus({ hostId: o.host.id, connectionEpoch: 1, census: acc });
}

/** A RECOVERY_REQUIRED lease of `instanceId` on `sandboxId` with an open binding and recoverable residue. */
async function recoveryLease(o: Owner, l: Login, sandboxId: string, instanceId: string) {
  const accountId = l.accounts.find((a) => a.instances.includes(instanceId))!.accountId;
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId: o.owner,
      credentialId: l.credentialId,
      accountId,
      instanceId,
      sandboxId,
      operationId: "op-old",
      kind: "WORKLOAD",
      exclusive: true,
      state: "RECOVERY_REQUIRED",
      hostId: o.host.id,
      baseSeq: 1,
    },
  });
  await db.inspect.credentialInstance.update({
    where: { id: instanceId },
    data: { activeLeases: { increment: 1 } },
  });
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId,
      sandboxId,
      hostId: o.host.id,
      grantGeneration: 1,
      baseSeq: 1,
      purpose: "INSTALL",
    },
  });
  await db.inspect.credentialResidue.create({
    data: {
      sandboxId,
      userId: o.owner,
      credentialId: l.credentialId,
      instanceId,
      leaseId: lease.id,
      bindingId: binding.id,
      grantGeneration: 1,
      paths: [l.path],
      recoverable: true,
    },
  });
  await db.inspect.credentialLease.update({
    where: { id: lease.id },
    data: { currentBindingId: binding.id },
  });
  return { leaseId: lease.id, bindingId: binding.id };
}

async function sealedCapture(
  o: Owner,
  l: Login,
  input: {
    sandboxId: string;
    leaseId: string;
    bindingId: string;
    instanceId: string;
    kind: "stop" | "recovery";
    residueId?: string;
  },
) {
  const frame = await issueCurrentReturnKey({
    hostId: o.host.id,
    hostSlotEpoch: 0,
    serverOrigin: ORIGIN,
  });
  const publicKey = Buffer.from(frame!.publicKey, "base64url");
  const parsed = parseLoginDefinition(l.document);
  if (!parsed.success) throw new Error("bad fixture");
  const plaintext = encodeBundle(
    {
      definitionDigest: fromHex(l.digest),
      files: [
        { kind: "dir", path: l.path, mode: 0o700 },
        { kind: "file", path: `${l.path}/token`, mode: 0o600, data: Buffer.from("late") },
      ],
      env: [],
    },
    parsed.definition,
  );
  const captureId = `cap-${randomUUID().slice(0, 12)}`;
  const aad = {
    serverOrigin: ORIGIN,
    hostOwnerId: o.owner,
    hostId: o.host.id,
    sandboxOwnerId: o.owner,
    sandboxId: input.sandboxId,
    leaseId: input.leaseId,
    bindingId: input.bindingId,
    instanceId: input.instanceId,
    credentialId: l.credentialId,
    captureSeq: "1",
    captureId,
    kind: input.kind,
    residueId: input.residueId ?? "",
  };
  const seal = sealToReturnKey(plaintext, publicKey, aad);
  const envelope = buildEnvelope(
    {
      kidR: frame!.kidR,
      recipientPubSha256: createHash("sha256").update(publicKey).digest("hex"),
      aad,
      sealedLen: seal.byteLength,
      sealedSha256: createHash("sha256").update(seal).digest("hex"),
      createdAt: 1,
    },
    seal,
  );
  return {
    hostId: o.host.id,
    connectionEpoch: 1,
    serverOrigin: ORIGIN,
    captureId,
    leaseId: input.leaseId,
    bindingId: input.bindingId,
    kidR: frame!.kidR,
    kind: input.kind,
    envelopeDigest: createHash("sha256").update(envelope).digest("hex"),
    envelope,
  };
}

describe("C7b resume rules (pg)", () => {
  it("5: recorded instance; same account; paused → other account; full → other account; resume pins refuse; a create-time choice is not applied at resume", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 2, 2);
    const [a1, a2] = l.accounts as [Login["accounts"][number], Login["accounts"][number]];
    const recorded = { accountId: a1.accountId, instanceId: a1.instances[0]! };

    // Recorded instance.
    const s1 = await stoppedSandbox(o);
    await attach(o, s1.id, l, recorded);
    expect(await resume(o, s1.id)).toMatchObject([
      { kind: "claimed", instanceId: a1.instances[0] },
    ]);

    // Recorded instance held (s1 holds it now) → same account.
    const s2 = await stoppedSandbox(o);
    await attach(o, s2.id, l, recorded);
    expect(await resume(o, s2.id)).toMatchObject([
      { kind: "claimed", instanceId: a1.instances[1] },
    ]);
    // The attachment records the lease taken.
    expect(
      await db.inspect.sandboxCredential.findFirstOrThrow({
        where: { sandboxId: s2.id },
        select: { instanceId: true },
      }),
    ).toEqual({ instanceId: a1.instances[1] });

    // Account full → another account.
    const s3 = await stoppedSandbox(o);
    await attach(o, s3.id, l, recorded);
    expect(await resume(o, s3.id)).toMatchObject([{ kind: "claimed", accountId: a2.accountId }]);

    // Resume-call pins: named rules, no fallback.
    const s4 = await stoppedSandbox(o);
    await attach(o, s4.id, l, recorded);
    await expect(
      resume(o, s4.id, [{ credentialId: l.credentialId, instanceId: a1.instances[0]! }]),
    ).rejects.toSatisfy((e) => codeOf(e) === "credential.in_use");
    await service.updateAccount(o.actor, {
      credentialId: l.credentialId,
      accountId: a1.accountId,
      paused: true,
    });
    await expect(
      resume(o, s4.id, [{ credentialId: l.credentialId, accountId: a1.accountId }]),
    ).rejects.toSatisfy((e) => codeOf(e) === "credential.account_paused");
    // Recorded account paused → any unpaused account.
    expect(await resume(o, s4.id)).toMatchObject([{ kind: "claimed", accountId: a2.accountId }]);

    // A create-time choice is used once by the create and then cleared.
    const o2 = await ownerWithHost();
    const l2 = await login(o2, 2, 1);
    const s5 = await stoppedSandbox(o2);
    const target = l2.accounts[1]!.instances[0]!;
    await attach(o2, s5.id, l2, { requestedInstanceId: target });
    const created = await db.prisma.$transaction((tx) =>
      claimCreateLeases(tx, {
        principal: o2.actor,
        ownerId: o2.owner,
        sandboxId: s5.id,
        operationId: "op-c",
        hostId: o2.host.id,
      }),
    );
    expect(created).toMatchObject([{ instanceId: target }]);
    const s6 = await stoppedSandbox(o2);
    await attach(o2, s6.id, l2, { requestedInstanceId: l2.accounts[1]!.instances[0]! });
    // Resume ignores the requested (create-time) id: auto-pick takes account 1.
    expect(await resume(o2, s6.id)).toMatchObject([
      { kind: "claimed", instanceId: l2.accounts[0]!.instances[0] },
    ]);
  });

  it("6: two stopped sandboxes cold-starting for one instance — one claims it, the other is refused in_use", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const recorded = {
      accountId: l.accounts[0]!.accountId,
      instanceId: l.accounts[0]!.instances[0]!,
    };
    const s1 = await stoppedSandbox(o);
    const s2 = await stoppedSandbox(o);
    await attach(o, s1.id, l, recorded);
    await attach(o, s2.id, l, recorded);
    const gate = db.pauseAt("first", { after: CLAIM_UPDATE });
    const first = resume(o, s1.id, undefined, "first");
    await gate.waitReached();
    const second = resume(o, s2.id, undefined, "second");
    await db.waitUntilBlocked("second", { by: "first" });
    gate.release();
    const results = await Promise.allSettled([first, second]);
    expect(results[0]).toMatchObject({ status: "fulfilled" });
    expect(results[1].status === "rejected" && codeOf(results[1].reason)).toBe("credential.in_use");
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: recorded.instanceId },
        select: { activeLeases: true },
      }),
    ).toEqual({ activeLeases: 1 });
  });

  it("20 (resume half): multi-login resumes with opposite pin orders on shared instances do not deadlock", async () => {
    const o = await ownerWithHost();
    const l1 = await login(o, 1, 1, 2);
    const l2 = await login(o, 1, 1, 2);
    const s1 = await stoppedSandbox(o);
    const s2 = await stoppedSandbox(o);
    for (const s of [s1, s2]) {
      await attach(o, s.id, l1);
      await attach(o, s.id, l2);
    }
    const pin1 = { credentialId: l1.credentialId, instanceId: l1.accounts[0]!.instances[0]! };
    const pin2 = { credentialId: l2.credentialId, instanceId: l2.accounts[0]!.instances[0]! };
    const gate = db.pauseAt("a", { after: CLAIM_UPDATE });
    const a = resume(o, s1.id, [pin1, pin2], "a");
    await gate.waitReached();
    const b = resume(o, s2.id, [pin2, pin1], "b");
    await db.waitUntilBlocked("b", { by: "a" });
    gate.release();
    const [ra, rb] = await Promise.all([a, b]);
    expect(ra).toHaveLength(2);
    expect(rb).toHaveLength(2);
    for (const id of [pin1.instanceId, pin2.instanceId])
      expect(
        (
          await db.inspect.credentialInstance.findUniqueOrThrow({
            where: { id },
            select: { activeLeases: true },
          })
        ).activeLeases,
      ).toBe(2);
  });
});

describe("claim gate: the complete attachment set, policy under the locks (pg)", () => {
  /** An SDK key principal (no allowlist rows: an ALLOWLIST key sees no login). */
  const sdkKey = (o: Owner, scopes: string[], resourceMode: "ALL_OWNED" | "ALLOWLIST") =>
    ({
      kind: "sdkKey",
      ownerId: o.owner,
      keyId: `key-${randomUUID().slice(0, 8)}`,
      expiresAt: null,
      resourceMode,
      scopes: new Set(scopes),
      allowedHostIds: "allOwned",
      allowedRevisionIds: "allOwned",
      allowedPoolIds: "allUsable",
    }) as never;
  const coldResume = (
    o: Owner,
    sandboxId: string,
    principal: unknown,
    options: { hostId?: string; actor?: string } = {},
  ) =>
    db.run(options.actor ?? "resume", () =>
      db.prisma.$transaction((tx) =>
        claimResumeLeases(tx, {
          principal: principal as never,
          ownerId: o.owner,
          sandboxId,
          operationId: `op-${randomUUID().slice(0, 8)}`,
          hostId: options.hostId ?? o.host.id,
          generation: 2,
        }),
      ),
    );
  const leaseCount = (sandboxId: string) =>
    db.inspect.credentialLease.count({ where: { sandboxId } });

  it("a cold resume with no pins authorizes every login it claims: scope, allowlist, drain mode", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l);
    // No `credentials:use`: refused before any claim.
    await expect(
      coldResume(o, s.id, sdkKey(o, ["sandboxes:write"], "ALL_OWNED")),
    ).rejects.toMatchObject({ code: "FORBIDDEN", status: 403 });
    // E2-B-03: the create path refuses the same way (not UNSUPPORTED_CAPABILITY).
    expect(() =>
      requireCreateCredentialsAllowed(sdkKey(o, ["sandboxes:write"], "ALL_OWNED"), [
        { credentialId: l.credentialId },
      ]),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN", status: 403 }));
    // The scope, but the login is not on the key's allowlist.
    const hidden = await coldResume(
      o,
      s.id,
      sdkKey(o, ["sandboxes:write", "credentials:use"], "ALLOWLIST"),
    ).catch((error: unknown) => error);
    expect(codeOf(hidden)).toBe("credential.not_found");
    // Drain mode (explicitly off, key present): no new claim, even for a session.
    process.env.CREDENTIALS_ENABLED = "false";
    try {
      const drained = await coldResume(o, s.id, o.actor).catch((error: unknown) => error);
      expect(codeOf(drained)).toBe("credential.unavailable");
    } finally {
      process.env.CREDENTIALS_ENABLED = "true";
    }
    expect(await leaseCount(s.id)).toBe(0);
    expect(await coldResume(o, s.id, o.actor)).toHaveLength(1);
  });

  for (const path of ["resume", "create"] as const)
    it(`foreign-host consent revoked while the ${path} claim waits on the login lock: host_forbidden, no lease`, async () => {
      const o = await ownerWithHost();
      const foreign = await ownerWithHost();
      const l = await login(o, 1, 1);
      await service.updateLoginPolicy(o.actor, { id: l.credentialId, foreignAllowed: true });
      const s = await seedSandbox(db.inspect, o.owner, "STOPPED", {
        sandboxHostId: foreign.host.id,
        hostOwnerId: foreign.owner,
        originHostId: foreign.host.id,
      });
      await attach(o, s.id, l);
      // The revocation holds the login FOR UPDATE (uncommitted) while the claim starts.
      const gate = db.pauseAt("revoke", { after: "credential.update" });
      const revoke = db.run("revoke", () =>
        service.updateLoginPolicy(o.actor, { id: l.credentialId, foreignAllowed: false }),
      );
      await gate.waitReached();
      const claim =
        path === "resume"
          ? coldResume(o, s.id, o.actor, { hostId: foreign.host.id, actor: "claim" })
          : db.run("claim", () =>
              db.prisma.$transaction((tx) =>
                claimCreateLeases(tx, {
                  principal: o.actor,
                  ownerId: o.owner,
                  sandboxId: s.id,
                  operationId: `op-${randomUUID().slice(0, 8)}`,
                  hostId: foreign.host.id,
                }),
              ),
            );
      await db.waitUntilBlocked("claim", { by: "revoke" });
      gate.release();
      await revoke;
      const refused = await claim.catch((error: unknown) => error);
      expect(codeOf(refused)).toBe("credential.host_forbidden");
      expect(await leaseCount(s.id)).toBe(0);
    });
});

describe("claim gate: the effective attachment set is disjoint (pg)", () => {
  const leases = (sandboxId: string) => db.inspect.credentialLease.count({ where: { sandboxId } });
  const createClaim = (o: Owner, sandboxId: string) =>
    db.prisma.$transaction((tx) =>
      claimCreateLeases(tx, {
        principal: o.actor,
        ownerId: o.owner,
        sandboxId,
        operationId: `op-${randomUUID().slice(0, 8)}`,
        hostId: o.host.id,
      }),
    );

  it("final-1: create and resume refuse overlapping paths and shared env names before any claim", async () => {
    const o = await ownerWithHost();
    const outer = await login(o, 1, 1, 1, { path: ".config/shared" });
    const inner = await login(o, 1, 1, 1, { path: ".config/shared/inner" });
    const envA = await login(o, 1, 1, 1, { env: ["TOOL_TOKEN"] });
    const envB = await login(o, 1, 1, 1, { env: ["TOOL_TOKEN"] });
    for (const [a, b, code] of [
      [outer, inner, "credential.path_conflict"],
      [envA, envB, "credential.env_conflict"],
    ] as const) {
      const created = await stoppedSandbox(o);
      await attach(o, created.id, a);
      await attach(o, created.id, b);
      expect(codeOf(await createClaim(o, created.id).catch((e: unknown) => e))).toBe(code);
      expect(await leases(created.id)).toBe(0);
      const stopped = await stoppedSandbox(o);
      await attach(o, stopped.id, a);
      await attach(o, stopped.id, b);
      expect(codeOf(await resume(o, stopped.id).catch((e: unknown) => e))).toBe(code);
      expect(await leases(stopped.id)).toBe(0);
    }
    // A disjoint set is claimed.
    const fine = await stoppedSandbox(o);
    await attach(o, fine.id, outer);
    await attach(o, fine.id, envA);
    expect(await resume(o, fine.id)).toHaveLength(2);
  });

  it("final-1: a re-pin that would overlap another attached login is refused and leaves the pin unchanged", async () => {
    const o = await ownerWithHost();
    const other = await login(o, 1, 1, 1, { path: ".config/other" });
    const moving = await login(o, 1, 1);
    const s = await stoppedSandbox(o);
    await attach(o, s.id, other);
    const attachment = await attach(o, s.id, moving);
    // v2 of `moving` keeps its path and adds one inside `other`'s.
    const document = DOCUMENT(moving.slug, "exclusive", moving.path);
    document.credentials.files.optional = [".config/other/nested"];
    const v2 = await service.createDefinition(o.actor, { document });
    const refused = await service
      .repinLogin(o.actor, { id: moving.credentialId, definitionId: v2.id })
      .catch((e: unknown) => e);
    expect(codeOf(refused)).toBe("credential.path_conflict");
    expect(
      await db.inspect.credential.findUniqueOrThrow({
        where: { id: moving.credentialId },
        select: { definitionDigest: true },
      }),
    ).toEqual({ definitionDigest: moving.digest });
    // Detached from `other`'s sandbox, the same re-pin is accepted.
    await db.inspect.sandboxCredential.update({
      where: { id: attachment.id },
      data: { detachedAt: new Date() },
    });
    await expect(
      service.repinLogin(o.actor, { id: moving.credentialId, definitionId: v2.id }),
    ).resolves.toMatchObject({ id: moving.credentialId });
  });
});

describe("env-only guest logins settle without a capture (pg)", () => {
  it("final-2: a RELEASING exclusive copy-back lease of an env-only login is released at stop and at free; a file login still waits", async () => {
    const o = await ownerWithHost();
    const envOnly = await login(o, 1, 1, 1, { path: null, env: ["TOOL_TOKEN"] });
    const files = await login(o, 1, 1);
    const releasing = async (l: Login, sandboxId: string, teardownOperationId: string | null) => {
      const instanceId = l.accounts[0]!.instances[0]!;
      await attach(o, sandboxId, l, { instanceId });
      const lease = await db.inspect.credentialLease.create({
        data: {
          userId: o.owner,
          credentialId: l.credentialId,
          accountId: l.accounts[0]!.accountId,
          instanceId,
          sandboxId,
          operationId: `op-${randomUUID().slice(0, 8)}`,
          kind: "WORKLOAD",
          exclusive: true,
          state: "RELEASING",
          hostId: o.host.id,
          teardownOperationId,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instanceId },
        data: { activeLeases: 1 },
      });
      return lease.id;
    };
    const stateOf = (id: string) =>
      db.inspect.credentialLease.findUniqueOrThrow({
        where: { id },
        select: { state: true, endReason: true },
      });
    // Stop: no capture outcome at all (the daemon produced none).
    const stopped = await stoppedSandbox(o);
    const envLease = await releasing(envOnly, stopped.id, null);
    const fileLease = await releasing(files, stopped.id, null);
    await db.prisma.$transaction((tx) => settleCredentialsOnStopped(tx, stopped.id, null));
    expect(await stateOf(envLease)).toEqual({ state: "RELEASED", endReason: "stopped" });
    expect(await stateOf(fileLease)).toMatchObject({ state: "RELEASING" });
    // Free: the env-only lease is released and detached without a capture.
    const freed = await stoppedSandbox(o);
    const freeOp = `op-free-${randomUUID().slice(0, 8)}`;
    const freeLease = await releasing(envOnly, freed.id, freeOp);
    await db.prisma.$transaction((tx) =>
      settleCredentialFreeResult(tx, {
        sandboxId: freed.id,
        operation: { id: freeOp, dispatchAttempt: 1 },
        opState: "SUCCEEDED",
        skip: false,
        outcomes: [],
      }),
    );
    expect(await stateOf(freeLease)).toEqual({ state: "RELEASED", endReason: "freed" });
  });
});

describe("claim gate: the login flow's LOGIN claim (pg)", () => {
  it("the session's consent alone decides a foreign host; the login's workload opt-in does not", async () => {
    const o = await ownerWithHost();
    const foreign = await ownerWithHost();
    const optedIn = await login(o, 1, 1);
    await service.updateLoginPolicy(o.actor, { id: optedIn.credentialId, foreignAllowed: true });
    const notOptedIn = await login(o, 1, 1);
    const gate = (credentialId: string, hostId: string, foreignConsent: boolean) =>
      db.prisma
        .$transaction((tx) =>
          authorizeCredentialClaims(tx, {
            principal: o.actor,
            hostId,
            sandboxId: null,
            claimIds: [credentialId],
            foreignConsent,
          }),
        )
        .then(
          () => "allowed",
          (error: unknown) => codeOf(error),
        );
    expect(await gate(optedIn.credentialId, foreign.host.id, false)).toBe(
      "credential.host_forbidden",
    );
    expect(await gate(notOptedIn.credentialId, foreign.host.id, true)).toBe("allowed");
    expect(await gate(notOptedIn.credentialId, o.host.id, false)).toBe("allowed");
  });
});

describe("teardown lock order (pg)", () => {
  const DECREMENT = /^sql:UPDATE credential_instance SET "activeLeases" = "activeLeases" - 1/;

  it("two sandboxes sharing two instances settle concurrently with opposite lease orders: no deadlock", async () => {
    const o = await ownerWithHost();
    const l1 = await login(o, 1, 1, 2);
    const l2 = await login(o, 1, 1, 2);
    const i1 = {
      credentialId: l1.credentialId,
      accountId: l1.accounts[0]!.accountId,
      instanceId: l1.accounts[0]!.instances[0]!,
    };
    const i2 = {
      credentialId: l2.credentialId,
      accountId: l2.accounts[0]!.accountId,
      instanceId: l2.accounts[0]!.instances[0]!,
    };
    const a = await stoppedSandbox(o);
    const b = await stoppedSandbox(o);
    // Lease ids sort i2-first on A and i1-first on B: lease order is opposite.
    const tag = randomUUID().slice(0, 8);
    for (const [id, sandboxId, instance] of [
      [`${tag}-a1`, a.id, i2],
      [`${tag}-a2`, a.id, i1],
      [`${tag}-b1`, b.id, i1],
      [`${tag}-b2`, b.id, i2],
    ] as const) {
      await db.inspect.credentialLease.create({
        data: {
          id,
          userId: o.owner,
          ...instance,
          sandboxId,
          operationId: `op-${id}`,
          kind: "WORKLOAD",
          exclusive: false,
          state: "RESERVED",
          hostId: o.host.id,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instance.instanceId },
        data: { activeLeases: { increment: 1 } },
      });
    }
    const settle = (actor: string, sandboxId: string) =>
      db.run(actor, () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
          await settleCredentialsOnDeleted(tx, sandboxId);
        }),
      );
    const gate = db.pauseAt("a", { after: DECREMENT });
    const first = settle("a", a.id);
    await gate.waitReached();
    const second = settle("b", b.id);
    await db.waitUntilBlocked("b", { by: "a" });
    gate.release();
    const results = await Promise.allSettled([first, second]);
    expect(results.map((result) => result.status)).toEqual(["fulfilled", "fulfilled"]);
    for (const instance of [i1, i2])
      expect(
        await db.inspect.credentialInstance.findUniqueOrThrow({
          where: { id: instance.instanceId },
          select: { activeLeases: true },
        }),
      ).toEqual({ activeLeases: 0 });
  });
});

describe("settlement scope: the complete instance set before any phase (pg)", () => {
  type Slot = { credentialId: string; accountId: string; instanceId: string };
  /** Two shareable logins with one instance each, `a` before `b` in the claim order. */
  async function orderedPair(o: Owner): Promise<{ a: Slot; b: Slot }> {
    const slots: Slot[] = [];
    for (let n = 0; n < 2; n++) {
      const l = await login(o, 1, 1, 2);
      slots.push({
        credentialId: l.credentialId,
        accountId: l.accounts[0]!.accountId,
        instanceId: l.accounts[0]!.instances[0]!,
      });
    }
    slots.sort((x, y) => (x.credentialId < y.credentialId ? -1 : 1));
    return { a: slots[0]!, b: slots[1]! };
  }
  async function seedLease(
    o: Owner,
    sandboxId: string,
    slot: Slot,
    state: "RESERVED" | "ACTIVE" | "RELEASING",
    operationId = `op-${randomUUID().slice(0, 8)}`,
  ) {
    const lease = await db.inspect.credentialLease.create({
      data: {
        userId: o.owner,
        ...slot,
        sandboxId,
        operationId,
        kind: "WORKLOAD",
        exclusive: false,
        state,
        hostId: o.host.id,
      },
    });
    await db.inspect.credentialInstance.update({
      where: { id: slot.instanceId },
      data: { activeLeases: { increment: 1 } },
    });
    return lease;
  }
  const lockS = (tx: { $queryRaw: typeof db.prisma.$queryRaw }, sandboxId: string) =>
    tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
  function latch() {
    let open!: () => void;
    const opened = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { open, opened };
  }
  /** Another host's stop of a sandbox holding A and B: S, then A, then B. */
  const teardown = (actor: string, sandboxId: string) =>
    db.run(actor, () =>
      db.prisma.$transaction(async (tx) => {
        await lockS(tx, sandboxId);
        await settleCredentialTeardown(tx, {
          sandboxId,
          priorState: "READY",
          generation: 2,
          teardownOperationId: `op-td-${actor}`,
        });
      }),
    );
  const statuses = (results: PromiseSettledResult<unknown>[]) =>
    results.map((result) =>
      result.status === "fulfilled" ? "fulfilled" : String((result.reason as Error).message),
    );

  it("a failed launch then the expiry teardown in one transaction: the launch's B and the teardown's A do not cycle with another teardown", async () => {
    const o = await ownerWithHost();
    const { a, b } = await orderedPair(o);
    const x = await stoppedSandbox(o);
    const y = await stoppedSandbox(o);
    const launch = `op-launch-${randomUUID().slice(0, 8)}`;
    // X: the launch's lease on B (pending), an older ACTIVE lease on A.
    const pending = await seedLease(o, x.id, b, "RESERVED", launch);
    await seedLease(o, x.id, a, "ACTIVE");
    await seedLease(o, y.id, a, "ACTIVE");
    await seedLease(o, y.id, b, "ACTIVE");
    const between = latch();
    const settledLaunch = latch();
    // The expiry/readiness path (lease.ts): settleOperationCredentials (the
    // failed launch) and then commitLockedSandboxLeaseExpiry's teardown.
    const first = db.run("x", () =>
      db.prisma.$transaction(async (tx) => {
        await lockS(tx, x.id);
        await settleCredentialLaunch(tx, {
          sandboxId: x.id,
          operationId: launch,
          succeeded: false,
        });
        settledLaunch.open();
        await between.opened;
        await settleCredentialTeardown(tx, {
          sandboxId: x.id,
          priorState: "READY",
          generation: 2,
          teardownOperationId: "op-td-x",
        });
      }),
    );
    await settledLaunch.opened;
    const second = teardown("y", y.id);
    await db.waitUntilBlocked("y", { by: "x" });
    between.open();
    expect(statuses(await Promise.allSettled([first, second]))).toEqual(["fulfilled", "fulfilled"]);
    expect(
      await db.inspect.credentialLease.findUniqueOrThrow({
        where: { id: pending.id },
        select: { state: true },
      }),
    ).toEqual({ state: "ABANDONED" });
    expect(
      await db.inspect.credentialLease.count({ where: { sandboxId: x.id, state: "RELEASING" } }),
    ).toBe(1);
    expect(
      await db.inspect.credentialLease.count({ where: { sandboxId: y.id, state: "RELEASING" } }),
    ).toBe(2);
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: b.instanceId },
        select: { activeLeases: true },
      }),
    ).toEqual({ activeLeases: 1 });
  });

  it("a REJECTED capture on a DELETED sandbox settles its drained teardowns without reaching back for an earlier instance", async () => {
    const o = await ownerWithHost();
    const { a, b } = await orderedPair(o);
    const x = await seedSandbox(db.inspect, o.owner, "DELETED", {
      sandboxHostId: o.host.id,
      hostOwnerId: o.owner,
      originHostId: o.host.id,
    });
    const y = await stoppedSandbox(o);
    const drained = await seedLease(o, x.id, a, "RELEASING");
    const captured = await seedLease(o, x.id, b, "ACTIVE");
    const binding = await db.inspect.credentialBinding.create({
      data: {
        leaseId: captured.id,
        instanceId: b.instanceId,
        sandboxId: x.id,
        hostId: o.host.id,
        grantGeneration: 1,
        purpose: "INSTALL",
      },
    });
    await seedLease(o, y.id, a, "ACTIVE");
    await seedLease(o, y.id, b, "ACTIVE");
    // A malformed envelope with custody: REJECTED{context_mismatch}, whose
    // lease rule on a DELETED sandbox runs settleDrainedTeardowns.
    const envelope = randomBytes(64);
    const gate = db.pauseAt("x", { after: "credentialLease.findUniqueOrThrow" });
    const first = db.run("x", () =>
      commitCapture({
        hostId: o.host.id,
        connectionEpoch: 1,
        serverOrigin: ORIGIN,
        captureId: `cap-${randomUUID().slice(0, 12)}`,
        leaseId: captured.id,
        bindingId: binding.id,
        kidR: "kid-none",
        kind: "stop",
        envelopeDigest: createHash("sha256").update(envelope).digest("hex"),
        envelope,
      }),
    );
    await gate.waitReached();
    const second = teardown("y", y.id);
    await db.waitUntilBlocked("y", { by: "x" });
    gate.release();
    const results = await Promise.allSettled([first, second]);
    expect(statuses(results)).toEqual(["fulfilled", "fulfilled"]);
    expect((results[0] as PromiseFulfilledResult<unknown>).value).toEqual({
      outcome: "rejected",
      reason: "context_mismatch",
    });
    expect(
      await db.inspect.credentialLease.findUniqueOrThrow({
        where: { id: drained.id },
        select: { state: true },
      }),
    ).toEqual({ state: "RELEASED" });
  });

  it("census settlement over several sandboxes takes every S, then the complete instance set: no S/instance cycle", async () => {
    const o = await ownerWithHost();
    const { b } = await orderedPair(o);
    const deleted = () =>
      seedSandbox(db.inspect, o.owner, "DELETED", {
        sandboxHostId: o.host.id,
        hostOwnerId: o.owner,
        originHostId: o.host.id,
      });
    const [x1, x2] = [await deleted(), await deleted()].sort((p, q) => (p.id < q.id ? -1 : 1));
    await seedLease(o, x1!.id, b, "RELEASING");
    await seedLease(o, x2!.id, b, "RELEASING");
    const held = latch();
    const go = latch();
    // A DELETED settlement of x2 (e.g. a destroy result) holding S(x2) first.
    const other = db.run("other", () =>
      db.prisma.$transaction(async (tx) => {
        await lockS(tx, x2!.id);
        held.open();
        await go.opened;
        await settleCredentialsOnDeleted(tx, x2!.id);
      }),
    );
    await held.opened;
    const settled = db.run("census", () => census(o));
    await db.waitUntilBlocked("census", { by: "other" });
    go.open();
    expect(statuses(await Promise.allSettled([other, settled]))).toEqual([
      "fulfilled",
      "fulfilled",
    ]);
    expect(
      await db.inspect.credentialLease.count({
        where: { sandboxId: { in: [x1!.id, x2!.id] }, state: "RELEASING" },
      }),
    ).toBe(0);
  });
});

describe("C7b drain before rebind (pg)", () => {
  it("14 (drain): a pending capture refuses pending_drain; after its commit the reconnect is accepted; a late capture under the superseded binding is REJECTED{binding_closed}", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const instanceId = l.accounts[0]!.instances[0]!;
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l, { accountId: l.accounts[0]!.accountId, instanceId });
    const old = await recoveryLease(o, l, s.id, instanceId);
    const drain = () =>
      db.prisma.$transaction((tx) =>
        assertCredentialDrain(tx, { sandboxId: s.id, hostId: o.host.id }),
      );
    // No census on this connection yet.
    await expect(drain()).rejects.toSatisfy((e) => codeOf(e) === "credential.pending_drain");
    await census(o, {
      entries: [
        {
          leaseId: old.leaseId,
          bindingId: old.bindingId,
          sandboxId: s.id,
          state: "stopped",
          scrubbedVerified: false,
          pending: [{ captureId: "cap-pending", kidR: "0123456789abcdef", kind: "expiry" }],
        },
      ],
    });
    await expect(drain()).rejects.toSatisfy((e) => codeOf(e) === "credential.pending_drain");
    // The envelope resolves (ledger outcome): drained.
    await db.inspect.credentialCapture.create({
      data: {
        captureId: "cap-pending",
        leaseId: old.leaseId,
        bindingId: old.bindingId,
        captureSeq: 1,
        kind: "expiry",
        kidR: "0123456789abcdef",
        envelopeDigest: new Uint8Array(32),
        outcome: "UNCHANGED",
      },
    });
    expect(await drain()).toBe(true);
    // An offline host is refused even when drained.
    await db.inspect.sandboxHost.update({
      where: { id: o.host.id },
      data: { status: "DISCONNECTED" },
    });
    await expect(drain()).rejects.toSatisfy((e) => codeOf(e) === "credential.pending_drain");
    await db.inspect.sandboxHost.update({
      where: { id: o.host.id },
      data: { status: "CONNECTED" },
    });
    // Resume reuses the RECOVERY_REQUIRED lease (rule 1): RECOVER binding, old one closed.
    const [claim] = await resume(o, s.id);
    expect(claim).toMatchObject({ kind: "recovering", leaseId: old.leaseId });
    const late = await sealedCapture(o, l, { sandboxId: s.id, ...old, instanceId, kind: "stop" });
    expect(await commitCapture(late)).toEqual({ outcome: "rejected", reason: "binding_closed" });
    // The spec recovers the old residue through the RECOVER binding.
    const spec = await db.prisma.$transaction((tx) => buildSandboxCredentialSpec(tx, s.id));
    expect(spec.leases).toMatchObject([{ leaseId: old.leaseId, action: "recover" }]);
    expect(spec.residue).toMatchObject([{ bindingId: old.bindingId, action: "recover" }]);
  });

  it("15: force-release then fallback — the other instance is claimed, the old residue is `scrub`, the grant waits for verified scrub, and a recovery capture of the old binding under the new lease is REJECTED", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 2, 1);
    const [aa, ab] = l.accounts as [Login["accounts"][number], Login["accounts"][number]];
    const ia = aa.instances[0]!;
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l, { accountId: aa.accountId, instanceId: ia });
    const old = await recoveryLease(o, l, s.id, ia);
    await db.prisma.$transaction((tx) =>
      forceReleaseLease(tx, { ownerId: o.owner, leaseId: old.leaseId }),
    );
    await service.updateAccount(o.actor, {
      credentialId: l.credentialId,
      accountId: aa.accountId,
      paused: true,
    });
    await census(o);
    await db.prisma.$transaction((tx) =>
      assertCredentialDrain(tx, { sandboxId: s.id, hostId: o.host.id }),
    );
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: o.owner,
        sandboxId: s.id,
        kind: "RECONNECT_SANDBOX",
        state: "QUEUED",
        generation: 1,
        idempotencyKey: `t-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
      },
      select: { id: true },
    });
    const claims = await db.prisma.$transaction((tx) =>
      claimResumeLeases(tx, {
        principal: o.actor,
        ownerId: o.owner,
        sandboxId: s.id,
        operationId: op.id,
        hostId: o.host.id,
        generation: 1,
      }),
    );
    expect(claims).toMatchObject([{ kind: "claimed", instanceId: ab.instances[0] }]);
    const lease = claims[0]!.leaseId;
    const spec = await db.prisma.$transaction((tx) => buildSandboxCredentialSpec(tx, s.id));
    expect(spec.leases).toMatchObject([{ leaseId: lease, action: "inject" }]);
    expect(spec.residue).toMatchObject([{ bindingId: old.bindingId, action: "scrub" }]);
    const grant = (requestId: string) =>
      grantInstallBundle({
        hostId: o.host.id,
        connectionEpoch: 1,
        requestId,
        sandboxId: s.id,
        leaseId: lease,
        operationId: op.id,
      });
    expect(await grant("a")).toEqual({ kind: "refused", code: "residue_pending" });
    await recordScrubbed({
      hostId: o.host.id,
      connectionEpoch: 1,
      sandboxId: s.id,
      bindingIds: [old.bindingId],
      verifiedAbsent: true,
    });
    const granted = await grant("b");
    expect(granted).toMatchObject({ kind: "granted" });
    // A recovery capture naming A's binding under B's lease.
    const forged = await sealedCapture(o, l, {
      sandboxId: s.id,
      leaseId: lease,
      bindingId: old.bindingId,
      instanceId: ab.instances[0]!,
      kind: "recovery",
    });
    expect(await commitCapture(forged)).toMatchObject({ outcome: "rejected" });
  });

  it("25 (reconnect half): a quarantined REJECTED envelope never blocks; resume recovers from disk; with force-release the discard is returned and resume takes a fresh lease", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const instanceId = l.accounts[0]!.instances[0]!;
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l, { accountId: l.accounts[0]!.accountId, instanceId });
    const old = await recoveryLease(o, l, s.id, instanceId);
    await db.inspect.credentialCaptureRejection.create({
      data: {
        hostId: o.host.id,
        captureId: "cap-rejected",
        envelopeDigest: new Uint8Array(32),
        leaseId: old.leaseId,
        bindingId: old.bindingId,
        kidR: "0123456789abcdef",
        reason: "decrypt_failed",
      },
    });
    // The census lists it as quarantined AND (wrongly) pending: no pending row is recreated.
    await census(o, {
      quarantined: [{ captureId: "cap-rejected", leaseId: old.leaseId, kidR: "0123456789abcdef" }],
      entries: [
        {
          leaseId: old.leaseId,
          bindingId: old.bindingId,
          sandboxId: s.id,
          state: "stopped",
          scrubbedVerified: false,
          pending: [{ captureId: "cap-rejected", kidR: "0123456789abcdef", kind: "stop" }],
        },
      ],
    });
    expect(await db.inspect.credentialPendingCapture.count({ where: { hostId: o.host.id } })).toBe(
      0,
    );
    expect(
      await db.prisma.$transaction((tx) =>
        assertCredentialDrain(tx, { sandboxId: s.id, hostId: o.host.id }),
      ),
    ).toBe(true);
    expect(await resume(o, s.id)).toMatchObject([{ kind: "recovering", leaseId: old.leaseId }]);
    const recover = await db.inspect.credentialBinding.findFirstOrThrow({
      where: { leaseId: old.leaseId, purpose: "RECOVER" },
      select: { recoveryOfBindingId: true },
    });
    expect(recover.recoveryOfBindingId).toBe(old.bindingId);

    // Variant: force-release first.
    const s2 = await stoppedSandbox(o);
    await attach(o, s2.id, l, { accountId: l.accounts[0]!.accountId, instanceId });
    const o2lease = await db.inspect.credentialLease.findUniqueOrThrow({
      where: { id: old.leaseId },
    });
    expect(o2lease.state).toBe("RECOVERING");
    const released = await db.prisma.$transaction((tx) =>
      forceReleaseLease(tx, { ownerId: o.owner, leaseId: old.leaseId }),
    );
    expect(released.discards).toEqual([{ hostId: o.host.id, captureIds: ["cap-rejected"] }]);
    expect(released.revoke).toEqual({ hostId: o.host.id, leaseId: old.leaseId });
    // A census still listing the discarded id gets the discard again.
    expect(
      await census(o, {
        quarantined: [
          { captureId: "cap-rejected", leaseId: old.leaseId, kidR: "0123456789abcdef" },
        ],
      }),
    ).toEqual([{ hostId: o.host.id, captureIds: ["cap-rejected"] }]);
    expect(await resume(o, s2.id)).toMatchObject([{ kind: "claimed", instanceId }]);
  });
});

describe("C8a recovery path and launch settlement (pg)", () => {
  /** A stopped sandbox with a RECOVERY_REQUIRED lease, reused by a real reconnect operation. */
  async function recovering() {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const instanceId = l.accounts[0]!.instances[0]!;
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l, { accountId: l.accounts[0]!.accountId, instanceId });
    const old = await recoveryLease(o, l, s.id, instanceId);
    await census(o);
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: o.owner,
        sandboxId: s.id,
        kind: "RECONNECT_SANDBOX",
        state: "QUEUED",
        generation: 1,
        idempotencyKey: `t-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
      },
      select: { id: true },
    });
    const [claim] = await db.prisma.$transaction((tx) =>
      claimResumeLeases(tx, {
        principal: o.actor,
        ownerId: o.owner,
        sandboxId: s.id,
        operationId: op.id,
        hostId: o.host.id,
        generation: 1,
      }),
    );
    if (claim?.kind !== "recovering") throw new Error("expected a recovery claim");
    const residue = await db.inspect.credentialResidue.findFirstOrThrow({
      where: { bindingId: old.bindingId },
      select: { id: true },
    });
    const grant = (requestId: string) =>
      grantInstallBundle({
        hostId: o.host.id,
        connectionEpoch: 1,
        requestId,
        sandboxId: s.id,
        leaseId: old.leaseId,
        operationId: op.id,
      });
    const recoveryCapture = () =>
      sealedCapture(o, l, {
        sandboxId: s.id,
        leaseId: old.leaseId,
        bindingId: claim.bindingId,
        instanceId,
        kind: "recovery",
        residueId: residue.id,
      });
    const lease = () =>
      db.inspect.credentialLease.findUniqueOrThrow({ where: { id: old.leaseId } });
    return { o, l, s, old, op, claim, instanceId, residue, grant, recoveryCapture, lease };
  }

  it("recovery success: install waits for the recovery outcome AND the verified scrub, then RECOVERING → INSTALLING → ACTIVE", async () => {
    const r = await recovering();
    expect(await r.grant("a")).toEqual({ kind: "refused", code: "residue_pending" });
    expect(await commitCapture(await r.recoveryCapture())).toEqual({ outcome: "committed" });
    // The recovery commit keeps the lease RECOVERING (no release, no install yet).
    expect((await r.lease()).state).toBe("RECOVERING");
    expect(await db.prisma.$transaction((tx) => credentialLaunchReady(tx, r.s.id))).toBe(false);
    // Scrub-then-inject: the recovered residue must be verified absent first.
    expect(await r.grant("b")).toEqual({ kind: "refused", code: "residue_pending" });
    await recordScrubbed({
      hostId: r.o.host.id,
      connectionEpoch: 1,
      sandboxId: r.s.id,
      bindingIds: [r.old.bindingId],
      verifiedAbsent: true,
    });
    const granted = await r.grant("c");
    expect(granted).toMatchObject({ kind: "granted", storageSeq: 2 });
    if (granted.kind !== "granted") throw new Error("unreachable");
    granted.bytes.fill(0);
    expect(await r.lease()).toMatchObject({ state: "INSTALLING", baseSeq: 2 });
    expect(
      await db.inspect.credentialBinding.findUniqueOrThrow({
        where: { id: r.claim.bindingId },
        select: { closeReason: true },
      }),
    ).toEqual({ closeReason: "recovered" });
    expect(
      await recordInstalled({
        hostId: r.o.host.id,
        connectionEpoch: 1,
        leaseId: r.old.leaseId,
        bindingId: granted.bindingId,
        storageSeq: 2,
      }),
    ).toBe(true);
    expect((await r.lease()).state).toBe("ACTIVE");
    expect(await db.prisma.$transaction((tx) => credentialLaunchReady(tx, r.s.id))).toBe(true);
  });

  it("recovery failure: the launch ends RECOVERY_REQUIRED with the RECOVER binding closed and the original residue still recoverable; the next start recovers it again", async () => {
    const r = await recovering();
    await db.prisma.$transaction((tx) =>
      settleCredentialLaunch(tx, { sandboxId: r.s.id, operationId: r.op.id, succeeded: false }),
    );
    expect(await r.lease()).toMatchObject({
      state: "RECOVERY_REQUIRED",
      currentBindingId: r.old.bindingId,
    });
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: r.old.leaseId, type: "recovery_required" },
        select: { reason: true },
      }),
    ).toEqual([{ reason: "recovery_failed" }]);
    expect(
      await db.inspect.credentialBinding.findUniqueOrThrow({
        where: { id: r.claim.bindingId },
        select: { closeReason: true },
      }),
    ).toEqual({ closeReason: "recovery_failed" });
    expect(
      await db.inspect.credentialResidue.findUniqueOrThrow({
        where: { id: r.residue.id },
        select: { recoverable: true, clearedAt: true },
      }),
    ).toEqual({ recoverable: true, clearedAt: null });
    expect(
      (
        await db.inspect.credentialInstance.findUniqueOrThrow({
          where: { id: r.instanceId },
          select: { activeLeases: true },
        })
      ).activeLeases,
    ).toBe(1);
    // Next start: the same lease is reused and the original residue is `recover` again.
    expect(await resume(r.o, r.s.id)).toMatchObject([
      { kind: "recovering", leaseId: r.old.leaseId },
    ]);
    const spec = await db.prisma.$transaction((tx) => buildSandboxCredentialSpec(tx, r.s.id));
    expect(spec.residue).toMatchObject([{ bindingId: r.old.bindingId, action: "recover" }]);
  });

  it("recovery capture REJECTED: RECOVERING → RECOVERY_REQUIRED with the RECOVER binding closed and one recovery_required event", async () => {
    const r = await recovering();
    const rejected = await sealedCapture(r.o, r.l, {
      sandboxId: r.s.id,
      leaseId: r.old.leaseId,
      bindingId: r.claim.bindingId,
      instanceId: r.instanceId,
      kind: "recovery",
      residueId: "not-the-residue",
    });
    expect(await commitCapture(rejected)).toMatchObject({ outcome: "rejected" });
    expect((await r.lease()).state).toBe("RECOVERY_REQUIRED");
    expect(
      await db.inspect.credentialBinding.findUniqueOrThrow({
        where: { id: r.claim.bindingId },
        select: { closeReason: true },
      }),
    ).toEqual({ closeReason: "recovery_rejected" });
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: r.old.leaseId, type: "recovery_required" },
        select: { reason: true },
      }),
    ).toEqual([{ reason: "recovery_rejected" }]);
    // A replay of the rejected envelope neither moves the lease nor writes a second event.
    expect(await commitCapture(rejected)).toMatchObject({ outcome: "rejected" });
    expect(
      await db.inspect.credentialEvent.count({
        where: { leaseId: r.old.leaseId, type: "recovery_required" },
      }),
    ).toBe(1);
  });

  it("install failure after recovery: the recovered value is preserved and the lease is RELEASED{install_failed}", async () => {
    const r = await recovering();
    expect(await commitCapture(await r.recoveryCapture())).toEqual({ outcome: "committed" });
    await db.prisma.$transaction((tx) =>
      settleCredentialLaunch(tx, { sandboxId: r.s.id, operationId: r.op.id, succeeded: false }),
    );
    expect(await r.lease()).toMatchObject({ state: "RELEASED", endReason: "install_failed" });
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: r.instanceId },
        select: { activeLeases: true, currentSeq: true },
      }),
    ).toEqual({ activeLeases: 0, currentSeq: 2 });
    expect(
      await db.inspect.credentialResidue.findUniqueOrThrow({
        where: { id: r.residue.id },
        select: { recoverable: true },
      }),
    ).toEqual({ recoverable: false });
  });

  it("install failure settlement: RESERVED → ABANDONED, INSTALLING → RELEASED, counts back to zero, residue non-recoverable, spec dropped", async () => {
    const o = await ownerWithHost();
    const l1 = await login(o, 1, 1);
    const l2 = await login(o, 1, 1);
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l1);
    await attach(o, s.id, l2);
    await census(o);
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: o.owner,
        sandboxId: s.id,
        kind: "RECONNECT_SANDBOX",
        state: "QUEUED",
        generation: 1,
        idempotencyKey: `t-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
      },
      select: { id: true },
    });
    const claims = await db.prisma.$transaction((tx) =>
      claimResumeLeases(tx, {
        principal: o.actor,
        ownerId: o.owner,
        sandboxId: s.id,
        operationId: op.id,
        hostId: o.host.id,
        generation: 1,
      }),
    );
    const [first, second] = claims as [(typeof claims)[number], (typeof claims)[number]];
    const granted = await grantInstallBundle({
      hostId: o.host.id,
      connectionEpoch: 1,
      requestId: "r",
      sandboxId: s.id,
      leaseId: first.leaseId,
      operationId: op.id,
    });
    if (granted.kind === "granted") granted.bytes.fill(0);
    // E1-B-01: the grant appends its declared paths to the sandbox's history.
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: s.id },
        select: { credentialPathHistory: true },
      }),
    ).toEqual({
      credentialPathHistory: [first.credentialId === l1.credentialId ? l1.path : l2.path],
    });
    await db.prisma.$transaction(async (tx) => {
      const { writeLaunchSpec } = await import("./launch");
      return writeLaunchSpec(tx, { sandboxId: s.id, operationId: op.id });
    });
    await db.prisma.$transaction((tx) =>
      settleCredentialLaunch(tx, { sandboxId: s.id, operationId: op.id, succeeded: false }),
    );
    const rows = await db.inspect.credentialLease.findMany({
      where: { sandboxId: s.id },
      select: { id: true, state: true, endReason: true, instanceId: true },
    });
    expect(rows.find((row) => row.id === first.leaseId)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
    expect(rows.find((row) => row.id === second.leaseId)).toMatchObject({ state: "ABANDONED" });
    for (const row of rows)
      expect(
        (
          await db.inspect.credentialInstance.findUniqueOrThrow({
            where: { id: row.instanceId },
            select: { activeLeases: true },
          })
        ).activeLeases,
      ).toBe(0);
    expect(
      await db.inspect.credentialResidue.findMany({
        where: { sandboxId: s.id },
        select: { recoverable: true },
      }),
    ).toEqual([{ recoverable: false }]);
    expect(await db.inspect.credentialOperationSpec.count({ where: { operationId: op.id } })).toBe(
      0,
    );
  });

  it("33 (preflight half): an oversized worst-case spec is refused spec_too_large before any lease is claimed", async () => {
    const o = await ownerWithHost();
    const l = await login(o, 1, 1);
    const s = await stoppedSandbox(o);
    await attach(o, s.id, l);
    const lease = await recoveryLease(o, l, s.id, l.accounts[0]!.instances[0]!);
    // Residue rows written by other paths can never exceed the cap in
    // practice; here one row is inflated directly to cross it.
    await db.inspect.credentialResidue.updateMany({
      where: { bindingId: lease.bindingId },
      data: { paths: Array.from({ length: 6000 }, (_, i) => `.config/${"p".repeat(200)}${i}`) },
    });
    const before = await db.inspect.credentialLease.count({ where: { userId: o.owner } });
    await expect(
      db.prisma.$transaction((tx) =>
        preflightCredentialSpec(tx, { sandboxId: s.id, credentialIds: [l.credentialId] }),
      ),
    ).rejects.toSatisfy((e) => codeOf(e) === "credential.spec_too_large");
    expect(await db.inspect.credentialLease.count({ where: { userId: o.owner } })).toBe(before);
    // Without the inflated row the same logins fit.
    await db.inspect.credentialResidue.updateMany({
      where: { bindingId: lease.bindingId },
      data: { paths: [l.path] },
    });
    await db.prisma.$transaction((tx) =>
      preflightCredentialSpec(tx, { sandboxId: s.id, credentialIds: [l.credentialId] }),
    );
  });
});
