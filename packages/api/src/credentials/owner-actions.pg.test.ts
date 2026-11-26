import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { decodeBundle, encodeBundle, fromHex, parseLoginDefinition } from "@wssp/login-definition";
import type { ServerCredentialMessage } from "@wssp/sandbox-contracts";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
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
 * C11 owner recovery actions against real PostgreSQL :
 * promotion vs a concurrent checkpoint commit in both orders, force-release
 * vs a RELEASING lease kept open for a durable envelope, idempotency, owner
 * scoping, and "Discard rejected captures". Barriers are row locks observed
 * through pg_stat_activity, never sleeps.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const service = await import("./service");
const { commitCapture } = await import("./captures");
const { issueCurrentReturnKey } = await import("./return-keys");
const { registerCredentialFrameSink } = await import("./frame-sink");
const { sealToReturnKey } = await import("./vault/sealed-box");
const { buildEnvelope } = await import("./vault/envelope");
const { openGrantBundle } = await import("./vault/store");
const { loadVerifiedLogin } = await import("./verified-login");
afterAll(() => db.close());

const ORIGIN = "https://wssp.example.test";
const savedKey = process.env.DATA_ENCRYPTION_KEY;
const frames: { hostId: string; frame: ServerCredentialMessage }[] = [];
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
  registerCredentialFrameSink((hostId, frame) => {
    frames.push({ hostId, frame });
    return true;
  });
});
afterAll(() => {
  registerCredentialFrameSink(null);
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
});
beforeEach(() => {
  frames.length = 0;
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

async function world() {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const host = await db.inspect.sandboxHost.create({
    data: { userId: owner, slug: randomUUID(), label: "Own host", connectionEpoch: 1 },
    select: { id: true },
  });
  const sandbox = await seedSandbox(db.inspect, owner, "READY", {
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
  return { owner, actor, host, sandbox, login, account, instance, digest };
}
type World = Awaited<ReturnType<typeof world>>;

/** A lease (ACTIVE by default) with an open INSTALL binding and residue at seq 1. */
async function activeLease(w: World, state: "ACTIVE" | "RELEASING" = "ACTIVE") {
  const op = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
      ...requestDigestMetadata(),

      userId: w.owner,
      sandboxId: w.sandbox.id,
      kind: "CREATE_SANDBOX",
      state: "RUNNING",
      generation: 1,
      idempotencyKey: `test-${randomUUID()}`,
      requestBodyHash: "a".repeat(64),
      dispatchedHostId: w.host.id,
    },
    select: { id: true },
  });
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId: w.owner,
      credentialId: w.login.id,
      accountId: w.account.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      operationId: op.id,
      kind: "WORKLOAD",
      exclusive: true,
      state,
      hostId: w.host.id,
      baseSeq: 1,
    },
    select: { id: true },
  });
  await db.inspect.credentialInstance.update({
    where: { id: w.instance.id },
    data: { activeLeases: { increment: 1 } },
  });
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      grantGeneration: 1,
      operationId: op.id,
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
  return { leaseId: lease.id, bindingId: binding.id };
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

function bundle(w: World, token: string): Uint8Array {
  return encodeBundle(
    {
      definitionDigest: fromHex(w.digest),
      files: [
        { kind: "dir", path: ".config/tool", mode: 0o700 },
        { kind: "file", path: ".config/tool/token", mode: 0o600, data: Buffer.from(token) },
      ],
      env: [],
    },
    DEFINITION,
  );
}

async function submission(
  w: World,
  o: {
    captureSeq: number;
    kind?: "stop" | "checkpoint";
    token: string;
    leaseId: string;
    bindingId: string;
  },
) {
  const key = await currentKey(w);
  const captureId = `cap-${randomUUID().slice(0, 12)}`;
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
  } as Parameters<typeof sealToReturnKey>[2];
  const seal = sealToReturnKey(bundle(w, o.token), key.publicKey, aad);
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
    select: { currentSeq: true, activeLeases: true, state: true },
  });
}
async function versionKind(w: World, storageSeq: number) {
  return (
    await db.inspect.credentialSecretVersion.findUnique({
      where: { instanceId_storageSeq: { instanceId: w.instance.id, storageSeq } },
      select: { kind: true },
    })
  )?.kind;
}
/** Decrypts and decodes the stored version: the token file and env as text. */
async function versionContent(w: World, storageSeq: number) {
  return db.inspect.$transaction(async (tx) => {
    const login = await loadVerifiedLogin(tx, w.login.id);
    if (!login) throw new Error("login missing");
    const grant = await openGrantBundle(tx, login, w.instance.id, storageSeq, { envOnly: false });
    if (!grant) throw new Error("version missing");
    const decoded = decodeBundle(grant.bytes, DEFINITION, fromHex(w.digest));
    const token = decoded.files.find((file) => file.path === ".config/tool/token");
    return {
      token: token?.kind === "file" ? Buffer.from(token.data).toString() : null,
      env: Object.fromEntries(
        decoded.env.map((entry) => [entry.name, Buffer.from(entry.value).toString()]),
      ),
    };
  });
}
async function rejection(w: World, leaseId: string, captureId: string) {
  await db.inspect.$executeRaw`INSERT INTO credential_capture_rejection
      ("hostId", "captureId", "envelopeDigest", "leaseId", "bindingId", "kidR", reason)
    VALUES (${w.host.id}, ${captureId}, ${randomBytes(32)}, ${leaseId}, NULL, 'kid', 'binding_closed')`;
}
const forceRelease = (
  w: World,
  leaseId: string,
  promoteCheckpoint = true,
): ReturnType<typeof service.forceRelease> =>
  service.forceRelease(w.actor, {
    credentialId: w.login.id,
    instanceId: w.instance.id,
    leaseId,
    promoteCheckpoint,
  });
const eventTypes = async (w: World) =>
  (
    await db.inspect.credentialEvent.findMany({
      where: { userId: w.owner, type: { in: ["force_released", "checkpoint_promoted"] } },
      orderBy: { at: "asc" },
      select: { type: true, storageSeq: true },
    })
  ).map((e) => [e.type, e.storageSeq]);

describe("C11 force-release with checkpoint promotion (pg)", () => {
  it("promotes the lease's newest checkpoint newer than current, closes everything, discards its quarantine and revokes", async () => {
    const w = await world();
    const l = await activeLease(w);
    for (const [seq, token] of [
      [1, "cp-old"],
      [2, "cp-new"],
    ] as const)
      expect(
        await commitCapture(
          await submission(w, { captureSeq: seq, kind: "checkpoint", token, ...l }),
        ),
      ).toEqual({ outcome: "committed" });
    await rejection(w, l.leaseId, "cap-rejected-1");
    const before = await service.listInstanceLeases(w.actor, {
      credentialId: w.login.id,
      instanceId: w.instance.id,
      limit: 10,
    });
    expect(before.items).toMatchObject([
      { id: l.leaseId, state: "ACTIVE", checkpoint: { storageSeq: 3 } },
    ]);
    expect(await forceRelease(w, l.leaseId)).toEqual({
      leaseId: l.leaseId,
      released: true,
      promoted: { storageSeq: 4, fromSeq: 3 },
    });
    expect(await instanceState(w)).toEqual({ currentSeq: 4, activeLeases: 0, state: "READY" });
    expect(await versionKind(w, 4)).toBe("PROMOTED");
    // Content, not metadata: the promoted version holds the checkpoint's bytes.
    expect(await versionContent(w, 4)).toEqual({ token: "cp-new", env: { TOOL_PROFILE: "work" } });
    const lease = await db.inspect.credentialLease.findUniqueOrThrow({
      where: { id: l.leaseId },
      select: { state: true, endReason: true },
    });
    expect(lease).toEqual({ state: "FORCE_RELEASED", endReason: "force_released" });
    expect(
      await db.inspect.credentialResidue.findFirstOrThrow({
        where: { bindingId: l.bindingId },
        select: { recoverable: true },
      }),
    ).toEqual({ recoverable: false });
    expect(
      await db.inspect.credentialBinding.findUniqueOrThrow({
        where: { id: l.bindingId },
        select: { closeReason: true },
      }),
    ).toEqual({ closeReason: "force_released" });
    expect(
      (
        await db.inspect.credentialCaptureRejection.findFirstOrThrow({
          where: { captureId: "cap-rejected-1" },
          select: { discardedAt: true },
        })
      ).discardedAt,
    ).not.toBeNull();
    expect(frames).toEqual([
      {
        hostId: w.host.id,
        frame: { type: "credential.revoke", leaseId: l.leaseId, reason: "force_released" },
      },
      {
        hostId: w.host.id,
        frame: {
          type: "credential.quarantine.discard",
          captureIds: ["cap-rejected-1"],
          reason: "force_released",
        },
      },
    ]);
    expect(await eventTypes(w)).toEqual([
      ["force_released", null],
      ["checkpoint_promoted", 4],
    ]);
    // The grant now serves the promoted value; a late capture is discarded.
    const late = await submission(w, { captureSeq: 9, token: "late", ...l });
    expect(await commitCapture(late)).toEqual({ outcome: "discarded", reason: "force_released" });
    // Idempotent: a terminal lease is not released (or promoted) again.
    frames.length = 0;
    expect(await forceRelease(w, l.leaseId)).toEqual({
      leaseId: l.leaseId,
      released: false,
      promoted: null,
    });
    expect(frames).toEqual([]);
    expect((await instanceState(w)).currentSeq).toBe(4);
  });

  it("without promotion (or with no checkpoint) the current value stays", async () => {
    const w = await world();
    const l = await activeLease(w);
    await commitCapture(
      await submission(w, { captureSeq: 1, kind: "checkpoint", token: "cp", ...l }),
    );
    expect(await forceRelease(w, l.leaseId, false)).toMatchObject({
      released: true,
      promoted: null,
    });
    expect((await instanceState(w)).currentSeq).toBe(1);
    const w2 = await world();
    const l2 = await activeLease(w2);
    expect(await forceRelease(w2, l2.leaseId)).toMatchObject({ released: true, promoted: null });
    expect(await instanceState(w2)).toEqual({ currentSeq: 1, activeLeases: 0, state: "READY" });
  });

  it("promotion vs a checkpoint commit — commit first is promoted; force-release first discards it", async () => {
    // Order A: the checkpoint commit holds S and the instance; force-release
    // waits, then promotes the checkpoint that just committed.
    {
      const w = await world();
      const l = await activeLease(w);
      const s = await submission(w, { captureSeq: 1, kind: "checkpoint", token: "cp-a", ...l });
      const gate = db.pauseAt("commit", {
        after: /^sql:SELECT id FROM credential_instance WHERE id = \? FOR UPDATE$/,
      });
      const commit = db.run("commit", () => commitCapture(s));
      await gate.waitReached();
      const release = db.run("release", () => forceRelease(w, l.leaseId));
      await db.waitUntilBlocked("release", { by: "commit" });
      gate.release();
      expect(await commit).toEqual({ outcome: "committed" });
      expect(await release).toMatchObject({
        released: true,
        promoted: { storageSeq: 3, fromSeq: 2 },
      });
      expect((await instanceState(w)).currentSeq).toBe(3);
    }
    // Order B: force-release holds the lease; the checkpoint then sees
    // FORCE_RELEASED and is discarded; nothing newer was there to promote.
    {
      const w = await world();
      const l = await activeLease(w);
      const s = await submission(w, { captureSeq: 1, kind: "checkpoint", token: "cp-b", ...l });
      const gate = db.pauseAt("release", {
        after: /^sql:SELECT id FROM credential_lease WHERE id = \? FOR UPDATE$/,
      });
      const release = db.run("release", () => forceRelease(w, l.leaseId));
      await gate.waitReached();
      const commit = db.run("commit", () => commitCapture(s));
      await db.waitUntilBlocked("commit", { by: "release" });
      gate.release();
      expect(await release).toMatchObject({ released: true, promoted: null });
      expect(await commit).toEqual({ outcome: "discarded", reason: "force_released" });
      expect(await instanceState(w)).toEqual({ currentSeq: 1, activeLeases: 0, state: "READY" });
    }
  });

  it("a RELEASING lease kept open for a durable envelope: force-release settles it and the envelope is discarded on arrival", async () => {
    const w = await world();
    const l = await activeLease(w, "RELEASING");
    await commitCapture(
      await submission(w, { captureSeq: 1, kind: "checkpoint", token: "cp", ...l }),
    );
    const stop = await submission(w, { captureSeq: 2, token: "final-lost", ...l });
    // The census listed the teardown envelope: it is unresolved.
    await db.inspect.credentialPendingCapture.create({
      data: {
        hostId: w.host.id,
        captureId: stop.captureId,
        leaseId: l.leaseId,
        bindingId: l.bindingId,
        kidR: stop.kidR,
        kind: "stop",
      },
    });
    expect(await forceRelease(w, l.leaseId)).toMatchObject({
      released: true,
      promoted: { storageSeq: 3, fromSeq: 2 },
    });
    // The envelope is an authorized discard now: no pending row blocks delete/re-pin.
    expect(await db.inspect.credentialPendingCapture.count({ where: { leaseId: l.leaseId } })).toBe(
      0,
    );
    expect(await commitCapture(stop)).toEqual({ outcome: "discarded", reason: "force_released" });
    expect((await instanceState(w)).currentSeq).toBe(3);
  });

  it("is owner-scoped: another owner's lease or a lease of another instance is not found", async () => {
    const w = await world();
    const l = await activeLease(w);
    const other = await world();
    await expect(
      service.forceRelease(other.actor, {
        credentialId: w.login.id,
        instanceId: w.instance.id,
        leaseId: l.leaseId,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.not_found" } });
    await expect(
      service.forceRelease(other.actor, {
        credentialId: other.login.id,
        instanceId: other.instance.id,
        leaseId: l.leaseId,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.lease_not_found" } });
    // E3-B-05: an unknown lease id on a real instance names the lease.
    await expect(
      service.forceRelease(w.actor, {
        credentialId: w.login.id,
        instanceId: w.instance.id,
        leaseId: "no-such-lease",
      }),
    ).rejects.toMatchObject({ data: { code: "credential.lease_not_found" } });
    expect(
      (
        await db.inspect.credentialLease.findUniqueOrThrow({
          where: { id: l.leaseId },
          select: { state: true },
        })
      ).state,
    ).toBe("ACTIVE");
  });
});

describe("C11 discard rejected captures (pg)", () => {
  it("discards every live rejection of the instance's leases, per host, and only those", async () => {
    const w = await world();
    const a = await activeLease(w);
    await forceRelease(w, a.leaseId, false);
    const b = await activeLease(w);
    await rejection(w, a.leaseId, "cap-a1");
    await rejection(w, b.leaseId, "cap-b1");
    await rejection(w, b.leaseId, "cap-b2");
    const other = await world();
    const o = await activeLease(other);
    await rejection(other, o.leaseId, "cap-other");
    const listed = await service.listRejectedCaptures(w.actor, {
      credentialId: w.login.id,
      instanceId: w.instance.id,
      limit: 2,
    });
    expect(listed.items).toHaveLength(2);
    expect(listed.nextCursor).not.toBeNull();
    const rest = await service.listRejectedCaptures(w.actor, {
      credentialId: w.login.id,
      instanceId: w.instance.id,
      limit: 2,
      cursor: listed.nextCursor ?? undefined,
    });
    expect([...listed.items, ...rest.items].map((r) => r.captureId).sort()).toEqual([
      "cap-a1",
      "cap-b1",
      "cap-b2",
    ]);
    expect(rest.items[0]).toMatchObject({ reason: "binding_closed" });
    expect(Object.keys(rest.items[0] ?? {}).sort()).toEqual([
      "at",
      "captureId",
      "leaseId",
      "reason",
    ]);
    frames.length = 0;
    expect(
      await service.discardRejectedCaptures(w.actor, {
        credentialId: w.login.id,
        instanceId: w.instance.id,
      }),
    ).toEqual({ discarded: 3 });
    expect(frames).toHaveLength(1);
    expect(frames[0]?.hostId).toBe(w.host.id);
    expect(frames[0]?.frame).toMatchObject({
      type: "credential.quarantine.discard",
      reason: "owner_discard",
    });
    const sent = frames[0]?.frame;
    expect(sent && "captureIds" in sent ? [...sent.captureIds].sort() : []).toEqual([
      "cap-a1",
      "cap-b1",
      "cap-b2",
    ]);
    expect(
      (
        await service.listRejectedCaptures(w.actor, {
          credentialId: w.login.id,
          instanceId: w.instance.id,
          limit: 10,
        })
      ).items,
    ).toEqual([]);
    // The lease state is untouched; the other owner's row is untouched.
    expect(
      (
        await db.inspect.credentialLease.findUniqueOrThrow({
          where: { id: b.leaseId },
          select: { state: true },
        })
      ).state,
    ).toBe("ACTIVE");
    expect(
      (
        await db.inspect.credentialCaptureRejection.findFirstOrThrow({
          where: { captureId: "cap-other" },
          select: { discardedAt: true },
        })
      ).discardedAt,
    ).toBeNull();
    expect(
      await db.inspect.credentialEvent.count({
        where: { userId: w.owner, type: "rejected_discarded" },
      }),
    ).toBe(1);
    // Nothing left: a second discard is a no-op with no frame or event.
    frames.length = 0;
    expect(
      await service.discardRejectedCaptures(w.actor, {
        credentialId: w.login.id,
        instanceId: w.instance.id,
      }),
    ).toEqual({ discarded: 0 });
    expect(frames).toEqual([]);
    // Another owner cannot discard or list them.
    await expect(
      service.discardRejectedCaptures(other.actor, {
        credentialId: w.login.id,
        instanceId: w.instance.id,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.not_found" } });
  });
});
