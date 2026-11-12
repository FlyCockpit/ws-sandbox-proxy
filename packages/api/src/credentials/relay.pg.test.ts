import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { encodeBundle, fromHex, parseLoginDefinition } from "@wssp/login-definition";
import { CREDENTIAL_SPEC_MAX_BYTES } from "@wssp/sandbox-contracts";
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
// Budgets are Redis-backed; their behaviour has its own tests.
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * C7a server relay fences against real PostgreSQL. Barriers are row
 * locks observed through pg_stat_activity, never sleeps.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const service = await import("./service");
const { commitCapture } = await import("./captures");
const { forceReleaseLease, finishLease } = await import("./leases");
const { grantInstallBundle, grantRestoreBundle, recordInstalled, recordScrubbed } = await import(
  "./grants"
);
const { applyReturnKeyAck, destroyReturnKey, issueCurrentReturnKey, rotateReturnKey } =
  await import("./return-keys");
const { applyCompleteCensus, newCensusAccumulator, accumulateCensusPage } = await import(
  "./census"
);
const { readOperationSpecChunks, writeOperationSpec } = await import("./specs");
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

const DOCUMENT = {
  schemaVersion: 1,
  id: "tool",
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: {
    files: { required: [".config/tool"], optional: [], exclude: [] },
    env: [{ name: "TOOL_PROFILE", required: false }],
  },
};
const parsed = parseLoginDefinition(DOCUMENT);
if (!parsed.success) throw new Error("fixture definition is invalid");
const DEFINITION = parsed.definition;

const HOST_LOCK =
  'sql:SELECT id FROM sandbox_host WHERE id = ? AND "connectionEpoch" = ? FOR UPDATE';

async function world(options: { sandboxState?: "READY" | "STOPPING" | "STOPPED" } = {}) {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const host = await db.inspect.sandboxHost.create({
    data: { userId: owner, slug: randomUUID(), label: "Own host", connectionEpoch: 1 },
    select: { id: true },
  });
  const sandbox = await seedSandbox(db.inspect, owner, options.sandboxState ?? "READY", {
    sandboxHostId: host.id,
    hostOwnerId: owner,
    originHostId: host.id,
  });
  const definition = await service.createDefinition(actor, { document: DOCUMENT });
  const login = await service.createLogin(actor, { name: "tool", definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id, name: "work" });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  await service.writeValue(actor, {
    credentialId: login.id,
    instanceId: instance.id,
    files: [
      { path: ".config/tool", kind: "dir" },
      { path: ".config/tool/token", contentBase64: Buffer.from("token-v1").toString("base64") },
    ],
    env: { TOOL_PROFILE: "work" },
  });
  const digest = (
    await db.inspect.credential.findUniqueOrThrow({
      where: { id: login.id },
      select: { definitionDigest: true },
    })
  ).definitionDigest;
  return { owner, host, sandbox, login, account, instance, digest };
}
type World = Awaited<ReturnType<typeof world>>;

async function operation(
  w: World,
  extra: {
    kind?: "CREATE_SANDBOX" | "STOP_SANDBOX";
    state?: "RUNNING" | "SUCCEEDED";
    key?: string;
    generation?: number;
  } = {},
) {
  return db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: w.owner,
      sandboxId: w.sandbox.id,
      kind: extra.kind ?? "CREATE_SANDBOX",
      state: extra.state ?? "RUNNING",
      generation: extra.generation ?? 1,
      idempotencyKey: extra.key ?? `test-${randomUUID()}`,
      requestBodyHash: "a".repeat(64),
      dispatchedHostId: w.host.id,
    },
    select: { id: true },
  });
}

/** An ACTIVE (or given-state) lease with an open INSTALL binding and residue at seq 1. */
async function activeLease(
  w: World,
  state: "ACTIVE" | "RELEASING" | "RESERVED" | "RECOVERING" = "ACTIVE",
  extra: { teardownOperationId?: string; operationId?: string } = {},
) {
  const op = extra.operationId ?? (await operation(w)).id;
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId: w.owner,
      credentialId: w.login.id,
      accountId: w.account.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      operationId: op,
      kind: "WORKLOAD",
      exclusive: true,
      state,
      hostId: w.host.id,
      baseSeq: state === "RESERVED" ? null : 1,
      teardownOperationId: extra.teardownOperationId ?? null,
    },
    select: { id: true },
  });
  await db.inspect.credentialInstance.update({
    where: { id: w.instance.id },
    data: { activeLeases: { increment: 1 } },
  });
  if (state === "RESERVED") return { leaseId: lease.id, bindingId: "", operationId: op };
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      grantGeneration: 1,
      operationId: op,
      baseSeq: 1,
      purpose: "INSTALL",
    },
    select: { id: true },
  });
  await db.inspect.credentialResidue.create({
    data: {
      sandboxId: w.sandbox.id,
      userId: w.owner,
      credentialId: w.login.id,
      instanceId: w.instance.id,
      leaseId: lease.id,
      bindingId: binding.id,
      grantGeneration: 1,
      paths: [".config/tool"],
      recoverable: true,
    },
  });
  await db.inspect.credentialLease.update({
    where: { id: lease.id },
    data: { currentBindingId: binding.id },
  });
  return { leaseId: lease.id, bindingId: binding.id, operationId: op };
}

async function currentKey(w: World) {
  const frame = await issueCurrentReturnKey({
    hostId: w.host.id,
    hostSlotEpoch: 0,
    serverOrigin: ORIGIN,
  });
  if (!frame) throw new Error("no return key");
  return { kidR: frame.kidR, publicKey: Buffer.from(frame.publicKey, "base64url") };
}

function bundle(w: World, token: string, withFile = true): Uint8Array {
  return encodeBundle(
    {
      definitionDigest: fromHex(w.digest),
      files: [
        { kind: "dir", path: ".config/tool", mode: 0o700 },
        ...(withFile
          ? [
              {
                kind: "file" as const,
                path: ".config/tool/token",
                mode: 0o600,
                data: Buffer.from(token),
              },
            ]
          : []),
      ],
      env: [],
    },
    DEFINITION,
  );
}

type SealOptions = {
  captureId?: string;
  captureSeq: number;
  kind?: "stop" | "checkpoint" | "free" | "kill" | "expiry" | "recovery" | "login";
  plaintext: Uint8Array;
  leaseId: string;
  bindingId: string;
  aadOverride?: Partial<Record<string, string>>;
  tamperSeal?: boolean;
  key?: { kidR: string; publicKey: Buffer };
};

async function submission(w: World, o: SealOptions) {
  const key = o.key ?? (await currentKey(w));
  const captureId = o.captureId ?? `cap-${randomUUID().slice(0, 12)}`;
  const kind = o.kind ?? "stop";
  const aad = {
    serverOrigin: ORIGIN,
    hostOwnerId: w.owner,
    hostId: w.host.id,
    sandboxOwnerId: w.owner,
    sandboxId: w.sandbox.id,
    leaseId: o.leaseId,
    bindingId: o.bindingId,
    instanceId: w.instance.id,
    credentialId: w.login.id,
    captureSeq: String(o.captureSeq),
    captureId,
    kind,
    residueId: "",
    ...o.aadOverride,
  } as Parameters<typeof sealToReturnKey>[2];
  const seal = sealToReturnKey(o.plaintext, key.publicKey, aad);
  if (o.tamperSeal) seal[seal.length - 1] ^= 1;
  const envelope = buildEnvelope(
    {
      kidR: key.kidR,
      recipientPubSha256: createHash("sha256").update(key.publicKey).digest("hex"),
      aad,
      sealedLen: seal.byteLength,
      sealedSha256: createHash("sha256").update(seal).digest("hex"),
      createdAt: 1,
    },
    seal,
  );
  return {
    hostId: w.host.id,
    connectionEpoch: 1,
    serverOrigin: ORIGIN,
    captureId,
    leaseId: o.leaseId,
    bindingId: o.bindingId,
    kidR: key.kidR,
    kind,
    envelopeDigest: createHash("sha256").update(envelope).digest("hex"),
    envelope,
  };
}

async function instanceState(w: World) {
  return db.inspect.credentialInstance.findUniqueOrThrow({
    where: { id: w.instance.id },
    select: { currentSeq: true, activeLeases: true, state: true, loginLeaseId: true },
  });
}
async function leaseRow(leaseId: string) {
  return db.inspect.credentialLease.findUniqueOrThrow({
    where: { id: leaseId },
    select: { state: true, baseSeq: true, captureSeqAccepted: true, endReason: true },
  });
}
const rejectionCount = (captureId: string) =>
  db.inspect.credentialCaptureRejection.count({ where: { captureId } });

describe("C7a commit fence (pg)", () => {
  it("7: capture commit vs force-release — commit first commits then releases; force-release first discards", async () => {
    // Order A: the commit holds S and the instance; force-release waits on S.
    {
      const w = await world();
      const l = await activeLease(w);
      const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "rotated-a"), ...l });
      const gate = db.pauseAt("commit", {
        after: /^sql:SELECT id FROM credential_instance WHERE id = \? FOR UPDATE$/,
      });
      const commit = db.run("commit", () => commitCapture(s));
      await gate.waitReached();
      const release = db.run("release", () =>
        db.prisma.$transaction((tx) =>
          forceReleaseLease(tx, { ownerId: w.owner, leaseId: l.leaseId }),
        ),
      );
      await db.waitUntilBlocked("release", { by: "commit" });
      gate.release();
      expect(await commit).toEqual({ outcome: "committed" });
      expect((await release).released).toBe(true);
      expect(await instanceState(w)).toMatchObject({ currentSeq: 2, activeLeases: 0 });
      expect((await leaseRow(l.leaseId)).state).toBe("FORCE_RELEASED");
    }
    // Order B: force-release holds the lease; the commit then sees FORCE_RELEASED.
    {
      const w = await world();
      const l = await activeLease(w);
      const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "rotated-b"), ...l });
      const gate = db.pauseAt("release", {
        after: /^sql:SELECT id FROM credential_lease WHERE id = \? FOR UPDATE$/,
      });
      const release = db.run("release", () =>
        db.prisma.$transaction((tx) =>
          forceReleaseLease(tx, { ownerId: w.owner, leaseId: l.leaseId }),
        ),
      );
      await gate.waitReached();
      const commit = db.run("commit", () => commitCapture(s));
      await db.waitUntilBlocked("commit", { by: "release" });
      gate.release();
      expect((await release).released).toBe(true);
      expect(await commit).toEqual({ outcome: "discarded", reason: "force_released" });
      expect(await instanceState(w)).toMatchObject({ currentSeq: 1, activeLeases: 0 });
      expect(
        await db.inspect.credentialCapture.findUniqueOrThrow({
          where: { captureId: s.captureId },
          select: { outcome: true, reason: true },
        }),
      ).toEqual({ outcome: "DISCARDED", reason: "force_released" });
    }
  });

  it("8: duplicate captureId concurrently — one storage sequence; replay after RELEASED returns the stored outcome; a different digest is REJECTED", async () => {
    const w = await world();
    const l = await activeLease(w);
    const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "rotated"), ...l });
    const gate = db.pauseAt("a", { after: HOST_LOCK });
    const a = db.run("a", () => commitCapture(s));
    await gate.waitReached();
    const b = db.run("b", () => commitCapture(s));
    await db.waitUntilBlocked("b", { by: "a" });
    gate.release();
    expect([await a, await b]).toEqual([{ outcome: "committed" }, { outcome: "committed" }]);
    const versions = await db.inspect.credentialSecretVersion.findMany({
      where: { instanceId: w.instance.id },
      select: { storageSeq: true },
      orderBy: { storageSeq: "asc" },
    });
    expect(versions.map((v) => v.storageSeq)).toEqual([1, 2]);
    await db.inspect.$transaction((tx) => finishLease(tx, l.leaseId, "RELEASED", "test"));
    expect(await commitCapture(s)).toEqual({ outcome: "committed" });
    const other = await submission(w, {
      captureId: s.captureId,
      captureSeq: 1,
      plaintext: bundle(w, "different"),
      ...l,
    });
    expect(await commitCapture(other)).toEqual({ outcome: "rejected", reason: "context_mismatch" });
    expect(await rejectionCount(s.captureId)).toBe(1);
    expect((await instanceState(w)).currentSeq).toBe(2);
  });

  it("9: UNCHANGED at seq N, then a changed capture at seq < N is DISCARDED{superseded}", async () => {
    const w = await world();
    const l = await activeLease(w);
    const same = await submission(w, { captureSeq: 5, plaintext: bundle(w, "token-v1"), ...l });
    expect(await commitCapture(same)).toEqual({ outcome: "unchanged" });
    expect((await leaseRow(l.leaseId)).captureSeqAccepted).toBe(5);
    const older = await submission(w, { captureSeq: 3, plaintext: bundle(w, "rotated"), ...l });
    expect(await commitCapture(older)).toEqual({ outcome: "discarded", reason: "superseded" });
    expect((await instanceState(w)).currentSeq).toBe(1);
  });

  it("10: repeated checkpoints get distinct storage sequences; a late checkpoint after the final capture is DISCARDED{superseded}", async () => {
    const w = await world();
    const l = await activeLease(w);
    const c1 = await submission(w, {
      captureSeq: 1,
      kind: "checkpoint",
      plaintext: bundle(w, "cp1"),
      ...l,
    });
    const c2 = await submission(w, {
      captureSeq: 2,
      kind: "checkpoint",
      plaintext: bundle(w, "cp2"),
      ...l,
    });
    expect(await commitCapture(c1)).toEqual({ outcome: "committed" });
    expect(await commitCapture(c2)).toEqual({ outcome: "committed" });
    const ledger = await db.inspect.credentialCapture.findMany({
      where: { leaseId: l.leaseId },
      select: { storageSeq: true },
    });
    expect(new Set(ledger.map((row) => row.storageSeq)).size).toBe(2);
    // Checkpoints never move the current value or the lease baseline.
    expect((await instanceState(w)).currentSeq).toBe(1);
    expect((await leaseRow(l.leaseId)).baseSeq).toBe(1);
    const final = await submission(w, { captureSeq: 4, plaintext: bundle(w, "final"), ...l });
    expect(await commitCapture(final)).toEqual({ outcome: "committed" });
    const late = await submission(w, {
      captureSeq: 3,
      kind: "checkpoint",
      plaintext: bundle(w, "cp3"),
      ...l,
    });
    expect(await commitCapture(late)).toEqual({ outcome: "discarded", reason: "superseded" });
    await db.inspect.$transaction((tx) => finishLease(tx, l.leaseId, "RELEASED", "test"));
    const afterRelease = await submission(w, {
      captureSeq: 9,
      kind: "checkpoint",
      plaintext: bundle(w, "cp9"),
      ...l,
    });
    expect(await commitCapture(afterRelease)).toEqual({
      outcome: "discarded",
      reason: "superseded",
    });
    expect((await instanceState(w)).currentSeq).toBe(4);
  });

  it("a teardown capture missing a required file is DISCARDED{incomplete}: NEEDS_LOGIN{files_missing} with a needs_login event", async () => {
    const w = await world();
    const l = await activeLease(w);
    const empty = encodeBundle(
      { definitionDigest: fromHex(w.digest), files: [], env: [] },
      DEFINITION,
    );
    const s = await submission(w, { captureSeq: 1, plaintext: empty, ...l });
    expect(await commitCapture(s)).toEqual({ outcome: "discarded", reason: "incomplete" });
    expect(await instanceState(w)).toMatchObject({ currentSeq: 1, state: "NEEDS_LOGIN" });
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: l.leaseId, type: "needs_login" },
        select: { reason: true, hostId: true },
      }),
    ).toEqual([{ reason: "files_missing", hostId: w.host.id }]);
  });

  it("17: a lease removed by account deletion acks DISCARDED{account_deleted} through its tombstone", async () => {
    const w = await world();
    const l = await activeLease(w);
    const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "x"), ...l });
    await db.inspect.credentialPendingCapture.create({
      data: {
        hostId: w.host.id,
        captureId: s.captureId,
        leaseId: l.leaseId,
        bindingId: l.bindingId,
        kidR: s.kidR,
        kind: "stop",
      },
    });
    await db.inspect.credentialLeaseTombstone.create({
      data: { hostId: w.host.id, leaseId: l.leaseId, reason: "account_deleted" },
    });
    await db.inspect.credentialResidue.deleteMany({ where: { leaseId: l.leaseId } });
    await db.inspect.credentialLease.delete({ where: { id: l.leaseId } });
    expect(await commitCapture(s)).toEqual({ outcome: "discarded", reason: "account_deleted" });
    expect(
      await db.inspect.credentialPendingCapture.count({ where: { captureId: s.captureId } }),
    ).toBe(0);
    // Without a tombstone an absent lease is REJECTED{unknown_lease}.
    const unknown = await submission(w, {
      captureSeq: 1,
      plaintext: bundle(w, "x"),
      leaseId: "no-such-lease",
      bindingId: l.bindingId,
    });
    expect(await commitCapture(unknown)).toEqual({ outcome: "rejected", reason: "unknown_lease" });
  });

  it("25 (rejection rows): every REJECTED step writes exactly one row; replay returns it; a system stop's REJECTED → RECOVERY_REQUIRED and the census never recreates its pending row", async () => {
    const w = await world();
    const stop = await operation(w, {
      kind: "STOP_SANDBOX",
      key: `lease-expire:${w.sandbox.id}:2:1:STOP`,
    });
    const l = await activeLease(w, "RELEASING", { teardownOperationId: stop.id });
    const cases: [string, Awaited<ReturnType<typeof submission>>][] = [];
    // 4: binding of another lease.
    cases.push([
      "context_mismatch",
      await submission(w, {
        captureSeq: 1,
        plaintext: bundle(w, "a"),
        leaseId: l.leaseId,
        bindingId: "no-such-binding",
      }),
    ]);
    // 9: AAD names another sandbox.
    cases.push([
      "context_mismatch",
      await submission(w, {
        captureSeq: 2,
        plaintext: bundle(w, "a"),
        ...l,
        aadOverride: { sandboxId: "other-sandbox" },
      }),
    ]);
    // 9: tampered ciphertext.
    cases.push([
      "decrypt_failed",
      await submission(w, { captureSeq: 3, plaintext: bundle(w, "a"), ...l, tamperSeal: true }),
    ]);
    // 9: sealed to a key the server never issued.
    const stranger = (await import("./vault/x25519")).generateX25519Private();
    const strangerPub = (await import("./vault/x25519")).x25519PublicKey(stranger);
    const { returnKeyId } = await import("./vault/codec");
    cases.push([
      "unknown_kid",
      await submission(w, {
        captureSeq: 4,
        plaintext: bundle(w, "a"),
        ...l,
        key: { kidR: returnKeyId(strangerPub), publicKey: strangerPub },
      }),
    ]);
    // 10: not a bundle.
    cases.push([
      "invalid_bundle",
      await submission(w, { captureSeq: 5, plaintext: Buffer.from("not a bundle"), ...l }),
    ]);
    for (const [reason, s] of cases) {
      await db.inspect.credentialPendingCapture.create({
        data: {
          hostId: w.host.id,
          captureId: s.captureId,
          leaseId: l.leaseId,
          bindingId: l.bindingId,
          kidR: s.kidR,
          kind: "stop",
        },
      });
      expect(await commitCapture(s)).toEqual({ outcome: "rejected", reason });
      expect(await commitCapture(s)).toEqual({ outcome: "rejected", reason });
      expect(await rejectionCount(s.captureId)).toBe(1);
      expect(
        await db.inspect.credentialPendingCapture.count({ where: { captureId: s.captureId } }),
      ).toBe(0);
    }
    expect(await db.inspect.credentialCapture.count({ where: { leaseId: l.leaseId } })).toBe(0);
    const lease = await leaseRow(l.leaseId);
    expect(lease).toMatchObject({ state: "RECOVERY_REQUIRED", captureSeqAccepted: 0 });
    // The transition writes exactly one recovery_required event (it fires the webhook).
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: l.leaseId, type: "recovery_required" },
        select: { reason: true },
      }),
    ).toEqual([{ reason: "capture_rejected" }]);
    // Residue stays recoverable for resume rule 1.
    expect(
      (await db.inspect.credentialResidue.findFirstOrThrow({ where: { leaseId: l.leaseId } }))
        .recoverable,
    ).toBe(true);
    // 6: a closed binding of a live lease.
    const closedLease = await world();
    const cl = await activeLease(closedLease);
    await db.inspect.credentialBinding.update({
      where: { id: cl.bindingId },
      data: { closedAt: new Date(), closeReason: "test" },
    });
    const closed = await submission(closedLease, {
      captureSeq: 1,
      plaintext: bundle(closedLease, "a"),
      ...cl,
    });
    expect(await commitCapture(closed)).toEqual({ outcome: "rejected", reason: "binding_closed" });
    expect(await rejectionCount(closed.captureId)).toBe(1);
    // A user stop (VM keeps running) leaves the lease alone.
    expect((await leaseRow(cl.leaseId)).state).toBe("ACTIVE");
    // A census still listing a rejected capture as quarantined (or pending) does not recreate it.
    const census = newCensusAccumulator();
    const [first] = cases;
    accumulateCensusPage(census, {
      type: "credential.census",
      page: 0,
      complete: true,
      keyEpoch: 1,
      quarantined: [{ captureId: first![1].captureId, leaseId: l.leaseId, kidR: first![1].kidR }],
      entries: [
        {
          leaseId: l.leaseId,
          bindingId: l.bindingId,
          sandboxId: w.sandbox.id,
          state: "stopped",
          scrubbedVerified: false,
          pending: cases
            .slice(1, 3)
            .map(([, s]) => ({ captureId: s.captureId, kidR: s.kidR, kind: "stop" as const })),
        },
      ],
    });
    expect(await applyCompleteCensus({ hostId: w.host.id, connectionEpoch: 1, census })).toEqual(
      [],
    );
    expect(await db.inspect.credentialPendingCapture.count({ where: { hostId: w.host.id } })).toBe(
      0,
    );
    expect(
      await db.inspect.credentialHostCensus.findUniqueOrThrow({
        where: { hostId: w.host.id },
        select: { connectionEpoch: true, quarantinedCount: true },
      }),
    ).toEqual({ connectionEpoch: 1n, quarantinedCount: 1 });
  });

  it("custody: another host naming a foreign lease and binding mutates nothing — capture rejection and census alike", async () => {
    const victim = await world();
    const v = await activeLease(victim);
    const attacker = await world();
    const junk = Buffer.from("not an envelope");
    const forged = {
      ...(await submission(victim, { captureSeq: 1, plaintext: bundle(victim, "x"), ...v })),
      hostId: attacker.host.id,
      kind: "expiry" as const,
      envelope: junk,
      envelopeDigest: createHash("sha256").update(junk).digest("hex"),
    };
    expect(await commitCapture(forged)).toEqual({
      outcome: "rejected",
      reason: "context_mismatch",
    });
    // The victim's lease is untouched and nothing is written under its owner.
    expect(await leaseRow(v.leaseId)).toMatchObject({ state: "ACTIVE", captureSeqAccepted: 0 });
    expect(await db.inspect.credentialEvent.count({ where: { leaseId: v.leaseId } })).toBe(0);
    // The rejection is the attacker host's quarantine only: no lease or binding named.
    expect(
      await db.inspect.credentialCaptureRejection.findMany({
        where: { captureId: forged.captureId },
        select: { hostId: true, leaseId: true, bindingId: true },
      }),
    ).toEqual([{ hostId: attacker.host.id, leaseId: null, bindingId: null }]);
    // A census entry for the foreign lease is ignored; the host's own entry is kept.
    const own = await activeLease(attacker);
    const census = newCensusAccumulator();
    accumulateCensusPage(census, {
      type: "credential.census",
      page: 0,
      complete: true,
      keyEpoch: 1,
      quarantined: [],
      entries: [
        { ...v, sandboxId: victim.sandbox.id },
        { ...own, sandboxId: attacker.sandbox.id },
      ].map((entry, n) => ({
        leaseId: entry.leaseId,
        bindingId: entry.bindingId,
        sandboxId: entry.sandboxId,
        state: "active" as const,
        scrubbedVerified: false,
        pending: [
          { captureId: `cap-census-${n}-${randomUUID()}`, kidR: "kid", kind: "stop" as const },
        ],
      })),
    });
    expect(
      await applyCompleteCensus({ hostId: attacker.host.id, connectionEpoch: 1, census }),
    ).toEqual([]);
    expect(
      await db.inspect.credentialPendingCapture.findMany({
        where: { hostId: attacker.host.id },
        select: { leaseId: true },
      }),
    ).toEqual([{ leaseId: own.leaseId }]);
  });

  it("DEFERRED without the vault key: nothing is written", async () => {
    const w = await world();
    const l = await activeLease(w);
    const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "x"), ...l });
    const key = process.env.DATA_ENCRYPTION_KEY;
    delete process.env.DATA_ENCRYPTION_KEY;
    try {
      expect(await commitCapture(s)).toEqual({ outcome: "deferred" });
    } finally {
      process.env.DATA_ENCRYPTION_KEY = key;
    }
    expect(await db.inspect.credentialCapture.count({ where: { captureId: s.captureId } })).toBe(0);
    expect(await rejectionCount(s.captureId)).toBe(0);
  });

  it("a stale connection epoch gets no ack and writes nothing", async () => {
    const w = await world();
    const l = await activeLease(w);
    const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "x"), ...l });
    expect(await commitCapture({ ...s, connectionEpoch: 7 })).toBeNull();
    expect(await db.inspect.credentialCapture.count({ where: { captureId: s.captureId } })).toBe(0);
  });

  it("a teardown capture of a STOPPED sandbox releases the RELEASING lease on commit", async () => {
    const w = await world({ sandboxState: "STOPPED" });
    const l = await activeLease(w, "RELEASING");
    const s = await submission(w, { captureSeq: 1, plaintext: bundle(w, "rotated"), ...l });
    expect(await commitCapture(s)).toEqual({ outcome: "committed" });
    expect(await leaseRow(l.leaseId)).toMatchObject({ state: "RELEASED", baseSeq: 2 });
    expect(await instanceState(w)).toMatchObject({ currentSeq: 2, activeLeases: 0 });
    const residue = await db.inspect.credentialResidue.findFirstOrThrow({
      where: { leaseId: l.leaseId },
    });
    expect(residue.recoverable).toBe(false);
  });
});

describe("C7a bundle grants (pg)", () => {
  it("28: restore grants for an ACTIVE lease with an open binding on READY; refused otherwise; restore carries no files; install retry returns the same binding", async () => {
    const w = await world();
    const l = await activeLease(w);
    const restore = (over: Partial<Parameters<typeof grantRestoreBundle>[0]> = {}) =>
      grantRestoreBundle({
        hostId: w.host.id,
        connectionEpoch: 1,
        requestId: `r-${randomUUID().slice(0, 8)}`,
        sandboxId: w.sandbox.id,
        leaseId: l.leaseId,
        bindingId: l.bindingId,
        reason: "restore_env",
        ...over,
      });
    const granted = await restore();
    expect(granted).toMatchObject({
      kind: "granted",
      bindingId: l.bindingId,
      storageSeq: 1,
      fileCount: 0,
      envCount: 1,
    });
    if (granted.kind === "granted") {
      expect(granted.bytes.includes(Buffer.from("token-v1"))).toBe(false);
      expect(granted.bytes.includes(Buffer.from("work"))).toBe(true);
    }
    // A proxy restore of a guest login is not authorized.
    expect(await restore({ reason: "proxy" })).toEqual({ kind: "refused", code: "not_authorized" });
    // Non-current connection epoch.
    expect(await restore({ connectionEpoch: 2 })).toEqual({ kind: "refused", code: "stale" });
    // Wrong host.
    const other = await db.inspect.sandboxHost.create({
      data: { userId: w.owner, slug: randomUUID(), label: "Other", connectionEpoch: 1 },
      select: { id: true },
    });
    expect(await restore({ hostId: other.id })).toEqual({
      kind: "refused",
      code: "not_authorized",
    });
    // STOPPING sandbox: a teardown in progress never re-receives values.
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "STOPPING" } });
    expect(await restore()).toEqual({ kind: "refused", code: "stale" });
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "READY" } });
    // Closed binding.
    await db.inspect.credentialBinding.update({
      where: { id: l.bindingId },
      data: { closedAt: new Date(), closeReason: "test" },
    });
    expect(await restore()).toEqual({ kind: "refused", code: "stale" });

    // Install retry with the same requestId returns the same binding.
    const w2 = await world();
    const reserved = await activeLease(w2, "RESERVED");
    const install = (requestId: string, operationId = reserved.operationId) =>
      grantInstallBundle({
        hostId: w2.host.id,
        connectionEpoch: 1,
        requestId,
        sandboxId: w2.sandbox.id,
        leaseId: reserved.leaseId,
        operationId,
      });
    const first = await install("req-1");
    const again = await install("req-1");
    expect(first).toMatchObject({ kind: "granted", storageSeq: 1, fileCount: 2, envCount: 1 });
    expect(again).toMatchObject({
      kind: "granted",
      bindingId: first.kind === "granted" ? first.bindingId : "x",
    });
    expect(await db.inspect.credentialBinding.count({ where: { leaseId: reserved.leaseId } })).toBe(
      1,
    );
    expect(await db.inspect.credentialResidue.count({ where: { leaseId: reserved.leaseId } })).toBe(
      1,
    );
    expect(await leaseRow(reserved.leaseId)).toMatchObject({ state: "INSTALLING", baseSeq: 1 });
    // A different requestId on an INSTALLING lease is stale.
    expect(await install("req-2")).toEqual({ kind: "refused", code: "stale" });
    // credential.installed → ACTIVE.
    const bindingId = first.kind === "granted" ? first.bindingId : "";
    expect(
      await recordInstalled({
        hostId: w2.host.id,
        connectionEpoch: 1,
        leaseId: reserved.leaseId,
        bindingId,
        storageSeq: 1,
      }),
    ).toBe(true);
    expect((await leaseRow(reserved.leaseId)).state).toBe("ACTIVE");
  });

  it("install fence: a superseded operation never fetches; residue of a closed binding blocks injection until verified scrubbed", async () => {
    const w = await world();
    const old = await activeLease(w);
    // A force-released earlier lease leaves non-recoverable residue on the disk.
    await db.inspect.$transaction((tx) =>
      forceReleaseLease(tx, { ownerId: w.owner, leaseId: old.leaseId }),
    );
    const reserved = await activeLease(w, "RESERVED");
    const grant = (operationId: string, requestId: string) =>
      grantInstallBundle({
        hostId: w.host.id,
        connectionEpoch: 1,
        requestId,
        sandboxId: w.sandbox.id,
        leaseId: reserved.leaseId,
        operationId,
      });
    expect(await grant(reserved.operationId, "a")).toEqual({
      kind: "refused",
      code: "residue_pending",
    });
    expect(
      await recordScrubbed({
        hostId: w.host.id,
        connectionEpoch: 1,
        sandboxId: w.sandbox.id,
        bindingIds: [old.bindingId],
        verifiedAbsent: false,
      }),
    ).toBe(0);
    expect(
      await recordScrubbed({
        hostId: w.host.id,
        connectionEpoch: 1,
        sandboxId: w.sandbox.id,
        bindingIds: [old.bindingId],
        verifiedAbsent: true,
      }),
    ).toBe(1);
    // The sandbox moved to generation 2: the generation-1 operation is superseded.
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { generation: 2 } });
    expect(await grant(reserved.operationId, "b")).toEqual({ kind: "refused", code: "stale" });
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { generation: 1 } });
    expect(await grant(reserved.operationId, "c")).toMatchObject({ kind: "granted" });
  });
});

describe("C7a return keys (pg)", () => {
  async function hostRow(owner: string) {
    return db.inspect.sandboxHost.create({
      data: { userId: owner, slug: randomUUID(), label: "Host", connectionEpoch: 1 },
      select: { id: true },
    });
  }

  it("31: issuance is blocked by rotation and then issues only the new current key; an older-epoch ack never marks the newer key", async () => {
    const owner = await seedOwner(db.inspect);
    const host = await hostRow(owner);
    const before = await issueCurrentReturnKey({
      hostId: host.id,
      hostSlotEpoch: 0,
      serverOrigin: ORIGIN,
    });
    const gate = db.pauseAt("rotate", {
      after:
        /^sql:SELECT "currentKidR", "currentEpoch" FROM credential_return_key_state WHERE id = 1 FOR UPDATE$/,
    });
    const rotating = db.run("rotate", () => rotateReturnKey());
    await gate.waitReached();
    const issuing = db.run("issue", () =>
      issueCurrentReturnKey({
        hostId: host.id,
        hostSlotEpoch: before!.epoch,
        serverOrigin: ORIGIN,
      }),
    );
    await db.waitUntilBlocked("issue", { by: "rotate" });
    gate.release();
    const rotated = await rotating;
    const issued = await issuing;
    expect(issued).toMatchObject({ kidR: rotated.kidR, epoch: Number(rotated.epoch) });
    expect(issued!.kidR).not.toBe(before!.kidR);
    // A host already at the current epoch gets nothing.
    expect(
      await issueCurrentReturnKey({
        hostId: host.id,
        hostSlotEpoch: issued!.epoch,
        serverOrigin: ORIGIN,
      }),
    ).toBeNull();
    const ack = (kidR: string, epoch: number) =>
      db.inspect.$transaction((tx) =>
        applyReturnKeyAck(tx, host.id, { kidR, epoch, currentEpoch: epoch }),
      );
    expect(await ack(issued!.kidR, issued!.epoch)).toBe("applied");
    expect(await ack(before!.kidR, before!.epoch)).toBe("ignored");
    const rows = await db.inspect.credentialHostReturnKey.findMany({
      where: { hostId: host.id },
      select: { kidR: true, ackedAt: true, drainedAt: true },
    });
    expect(rows.find((r) => r.kidR === before!.kidR)).toMatchObject({
      ackedAt: null,
      drainedAt: null,
    });
    expect(rows.find((r) => r.kidR === issued!.kidR)?.ackedAt).not.toBeNull();
    // Unknown issuance rows and refused acks change nothing.
    expect(await ack("0123456789abcdef", issued!.epoch)).toBe("ignored");
    expect(
      await db.inspect.$transaction((tx) =>
        applyReturnKeyAck(tx, host.id, {
          kidR: issued!.kidR,
          epoch: issued!.epoch,
          currentEpoch: issued!.epoch,
          refused: "substitution",
        }),
      ),
    ).toBe("substitution");
  });

  it("24: destruction is refused with an issued-but-unacked row and allowed after a higher-epoch ack plus a drained census", async () => {
    const owner = await seedOwner(db.inspect);
    const host = await hostRow(owner);
    const old = await issueCurrentReturnKey({
      hostId: host.id,
      hostSlotEpoch: 0,
      serverOrigin: ORIGIN,
    });
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: false })).toEqual({
      ok: false,
      reason: "current",
    });
    await rotateReturnKey();
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: false })).toEqual({
      ok: false,
      reason: "host_not_drained",
    });
    const next = await issueCurrentReturnKey({
      hostId: host.id,
      hostSlotEpoch: old!.epoch,
      serverOrigin: ORIGIN,
    });
    await db.inspect.$transaction((tx) =>
      applyReturnKeyAck(tx, host.id, {
        kidR: next!.kidR,
        epoch: next!.epoch,
        currentEpoch: next!.epoch,
      }),
    );
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: false })).toEqual({
      ok: false,
      reason: "host_not_drained",
    });
    // A census listing a pending envelope under the old kid does not drain it.
    const pendingCensus = newCensusAccumulator();
    accumulateCensusPage(pendingCensus, {
      type: "credential.census",
      page: 0,
      complete: true,
      keyEpoch: next!.epoch,
      quarantined: [],
      entries: [
        {
          leaseId: "l1",
          bindingId: "b1",
          sandboxId: "s1",
          state: "stopped",
          scrubbedVerified: false,
          pending: [{ captureId: "c-old", kidR: old!.kidR, kind: "stop" }],
        },
      ],
    });
    await applyCompleteCensus({ hostId: host.id, connectionEpoch: 1, census: pendingCensus });
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: false })).toEqual({
      ok: false,
      reason: "host_not_drained",
    });
    const census = newCensusAccumulator();
    accumulateCensusPage(census, {
      type: "credential.census",
      page: 0,
      complete: true,
      keyEpoch: next!.epoch,
      quarantined: [],
      entries: [],
    });
    await applyCompleteCensus({ hostId: host.id, connectionEpoch: 1, census });
    // Every OTHER host issued the old key (earlier tests) must be drained or lost too.
    await db.inspect.credentialHostReturnKey.updateMany({
      where: { kidR: old!.kidR, hostId: { not: host.id } },
      data: { declaredLostAt: new Date() },
    });
    await db.inspect.credentialCaptureRejection.create({
      data: {
        hostId: host.id,
        captureId: "q1",
        envelopeDigest: new Uint8Array(32),
        kidR: old!.kidR,
        reason: "decrypt_failed",
      },
    });
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: false })).toEqual({
      ok: false,
      reason: "quarantined_envelopes",
    });
    expect(await destroyReturnKey({ kidR: old!.kidR, destroyQuarantined: true })).toEqual({
      ok: true,
      quarantined: 1,
    });
    const destroyed = await db.inspect.credentialReturnKey.findUniqueOrThrow({
      where: { kidR: old!.kidR },
      select: { destroyedAt: true, wrappedPrivate: true },
    });
    expect(destroyed.destroyedAt).not.toBeNull();
    expect(destroyed.wrappedPrivate.byteLength).toBe(0);
  });
});

describe("C7a operation specs (pg)", () => {
  it("33: a spec of exactly the cap is stored and fetched in chunks; cap + 1 is refused before anything is written", async () => {
    const w = await world();
    const op = await operation(w);
    const exact = Buffer.alloc(CREDENTIAL_SPEC_MAX_BYTES, 0x20);
    exact.write('{"version":1}', 0);
    const stored = await db.inspect.$transaction((tx) => writeOperationSpec(tx, op.id, exact));
    expect(stored.bytes).toBe(CREDENTIAL_SPEC_MAX_BYTES);
    const chunks = await readOperationSpecChunks(db.inspect, {
      hostId: w.host.id,
      operationId: op.id,
      digest: stored.digest,
    });
    expect(Buffer.concat(chunks!).equals(exact)).toBe(true);
    expect(chunks!.every((c) => c.byteLength <= 32_768)).toBe(true);
    // Wrong digest or another host: refused.
    expect(
      await readOperationSpecChunks(db.inspect, {
        hostId: w.host.id,
        operationId: op.id,
        digest: "0".repeat(64),
      }),
    ).toBeNull();
    expect(
      await readOperationSpecChunks(db.inspect, {
        hostId: "other-host",
        operationId: op.id,
        digest: stored.digest,
      }),
    ).toBeNull();
    const op2 = await operation(w);
    await expect(
      db.inspect.$transaction((tx) =>
        writeOperationSpec(tx, op2.id, Buffer.alloc(CREDENTIAL_SPEC_MAX_BYTES + 1, 0x20)),
      ),
    ).rejects.toMatchObject({ data: { code: "credential.spec_too_large" } });
    expect(await db.inspect.credentialOperationSpec.count({ where: { operationId: op2.id } })).toBe(
      0,
    );
    // The schema CHECK holds the same cap even for a writer that skips the guard.
    await expect(
      db.inspect.credentialOperationSpec.create({
        data: {
          operationId: op2.id,
          digest: new Uint8Array(32),
          bytes: new Uint8Array(CREDENTIAL_SPEC_MAX_BYTES + 1),
        },
      }),
    ).rejects.toThrow();
  });
});
