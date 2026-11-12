import { randomBytes } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
// Budgets are Redis-backed; their behaviour has its own tests.
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("../webhooks/budgets", () => ({
  consumeWebhookWrite: async () => {},
  consumeWebhookTest: async () => {},
  consumeWebhookRedeliver: async () => {},
}));

/**
 * The data-key epoch write fence against real PostgreSQL : a writer that read the old epoch blocks the switch; a
 * switch blocks writers that arrive during it; after the switch a stale
 * writer aborts `stale_writer` with nothing written; rewrap (vault DEKs,
 * return private keys, webhook secrets) drives every old-kid count to zero
 * and the counts stay zero. Barriers are row locks observed through
 * pg_stat_activity, never sleeps. The steps share one database and run in
 * order.
 */
const db = await pgTestDatabase();
const { seedOwner } = await import("../webhooks/testing/fixtures");
const service = await import("../credentials/service");
const { destroyReturnKey, rotateReturnKey } = await import("../credentials/return-keys");
const { rewrapCredentialKeys } = await import("../credentials/rewrap");
const { deriveVaultKeys } = await import("../credentials/vault/keys");
const { unwrapReturnPrivateKey } = await import("../credentials/vault/return-key");
const { decryptValue } = await import("../credentials/vault/value");
const { dataRootKey, deriveSubkey } = await import("./data-key");
const { DataKeyStaleWriter, promoteDataKey, readDataKeyEpoch } = await import("./data-key-epoch");
const { readDataKeyStatus } = await import("./data-key-status");
const { sealSecret, WEBHOOK_SECRET_PURPOSE } = await import("../webhooks/crypto");
const webhooks = await import("../webhooks/service");
const ledger = await import("../webhooks/ledger");
const { resetWebhookConfigForTests } = await import("../webhooks/config");
const { sessionPrincipal } = await import("../sandbox/contracts");
afterAll(() => db.close());

const K1_HEX = randomBytes(32).toString("hex");
const K2_HEX = randomBytes(32).toString("hex");
const K1 = dataRootKey(K1_HEX);
const K2 = dataRootKey(K2_HEX);
const WEBHOOK_K1 = deriveSubkey(K1, WEBHOOK_SECRET_PURPOSE);
const WEBHOOK_K2 = deriveSubkey(K2, WEBHOOK_SECRET_PURPOSE);

const saved = {
  current: process.env.DATA_ENCRYPTION_KEY,
  previous: process.env.DATA_ENCRYPTION_KEY_PREVIOUS,
  enabled: process.env.CREDENTIALS_ENABLED,
};
function restore(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
/** This process's keyring: what the env supplies. Never printed. */
function useKeys(current: string, previous?: string) {
  process.env.DATA_ENCRYPTION_KEY = current;
  if (previous) process.env.DATA_ENCRYPTION_KEY_PREVIOUS = previous;
  else delete process.env.DATA_ENCRYPTION_KEY_PREVIOUS;
  resetWebhookConfigForTests();
}
beforeAll(() => {
  process.env.CREDENTIALS_ENABLED = "true";
  useKeys(K1_HEX);
});
afterAll(() => {
  restore("DATA_ENCRYPTION_KEY", saved.current);
  restore("DATA_ENCRYPTION_KEY_PREVIOUS", saved.previous);
  restore("CREDENTIALS_ENABLED", saved.enabled);
  resetWebhookConfigForTests();
});

const EPOCH_SHARE = /FROM data_key_epoch WHERE id = 1 FOR SHARE$/;
const EPOCH_UPDATE = /FROM data_key_epoch WHERE id = 1 FOR UPDATE$/;
const ring = (current: typeof K1, previous: typeof K1 | null) => ({ current, previous });

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

async function world() {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const definition = await service.createDefinition(actor, { document: DOCUMENT });
  const login = await service.createLogin(actor, { name: "tool", definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id, name: "work" });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  const write = (token: string) =>
    service.writeValue(actor, {
      credentialId: login.id,
      instanceId: instance.id,
      files: [
        { path: ".config/tool", kind: "dir" },
        { path: ".config/tool/token", contentBase64: Buffer.from(token).toString("base64") },
      ],
      env: { TOOL_PROFILE: "work" },
    });
  // A webhook endpoint whose secret is sealed under K1 (the fixture path).
  const endpointId = `whe_${randomBytes(8).toString("hex")}`;
  const sealed = sealSecret(
    Buffer.alloc(32, 7),
    { endpointId, userId: owner, version: 1 },
    WEBHOOK_K1,
  );
  await db.inspect.webhookEndpoint.create({
    data: {
      id: endpointId,
      userId: owner,
      url: "https://hooks.example.com/wssp",
      events: ["sandbox.state_changed"],
      operationKinds: [],
      secretCiphertext: new Uint8Array(sealed.ciphertext),
      secretNonce: new Uint8Array(sealed.nonce),
      secretKeyId: sealed.keyId,
      secretVersion: 1,
    },
    select: { id: true },
  });
  return { owner, actor, login, instance, write, endpointId };
}
let w: Awaited<ReturnType<typeof world>>;

const versionKids = async () =>
  (
    await db.inspect.credentialSecretVersion.findMany({
      where: { instanceId: w.instance.id },
      orderBy: { storageSeq: "asc" },
      take: 10,
      select: { storageSeq: true, rootKid: true },
    })
  ).map((row) => row.rootKid);

const countFor = async (kid: string) => {
  const status = await readDataKeyStatus({ ring: null, client: db.inspect });
  return status.counts.filter((c) => c.kid === kid).reduce((sum, c) => sum + c.rows, 0);
};

describe("23: data-key epoch fence (real PostgreSQL)", () => {
  it("the first writer bootstraps the epoch with its env current kid; vault and return-key writers seal under it", async () => {
    w = await world();
    await w.write("token-v1");
    expect(await readDataKeyEpoch(db.inspect)).toMatchObject({
      currentKid: K1.id,
      previousKid: null,
      epoch: 1n,
    });
    // Return keys under K1: one retired then destroyed, one current.
    await rotateReturnKey();
    const keys = await db.inspect.credentialReturnKey.findMany({
      orderBy: { epoch: "asc" },
      take: 10,
      select: { kidR: true, rootKid: true },
    });
    expect(keys.map((key) => key.rootKid)).toEqual([K1.id, K1.id]);
    expect(await destroyReturnKey({ kidR: keys[0]!.kidR, destroyQuarantined: false })).toEqual({
      ok: true,
      quarantined: 0,
    });
    expect(await versionKids()).toEqual([K1.id]);
  });

  it("a writer that read the old epoch blocks the switch and commits under the old kid", async () => {
    // Runbook step 1: every process holds the new key as PREVIOUS.
    useKeys(K1_HEX, K2_HEX);
    const gate = db.pauseAt("writer", { after: EPOCH_SHARE });
    const writing = db.run("writer", () => w.write("token-v2"));
    await gate.waitReached();
    const promoting = db.run("promote", () => promoteDataKey(ring(K1, K2), K2.id));
    await db.waitUntilBlocked("promote", { by: "writer" });
    gate.release();
    await writing;
    expect(await promoting).toMatchObject({
      ok: true,
      changed: true,
      currentKid: K2.id,
      previousKid: K1.id,
      epoch: 2n,
    });
    // Committed before the switch: old kid. The next write follows the DB,
    // not the env current (still K1 here): it seals under K2.
    expect(await versionKids()).toEqual([K1.id, K1.id]);
    await w.write("token-v3");
    expect((await versionKids()).at(-1)).toBe(K2.id);
  });

  it("after the switch a stale writer aborts stale_writer and writes nothing", async () => {
    // A process that was never given K2.
    useKeys(K1_HEX);
    const before = await versionKids();
    const endpointBefore = await db.inspect.webhookEndpoint.findUniqueOrThrow({
      where: { id: w.endpointId },
      select: { secretKeyId: true, secretVersion: true },
    });
    const returnKeysBefore = await db.inspect.credentialReturnKey.count();
    await expect(w.write("token-stale")).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
    await expect(rotateReturnKey()).rejects.toBeInstanceOf(DataKeyStaleWriter);
    webhooks.setWebhookDestinationResolverForTests(async () => ["93.184.215.14"]);
    await expect(
      webhooks.rotateWebhookSecret(sessionPrincipal(w.owner), { id: w.endpointId }),
    ).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
    // The rewrap and the webhook rekey skip too.
    expect(await rewrapCredentialKeys()).toMatchObject({ stale: true, values: 0, returnKeys: 0 });
    expect(await versionKids()).toEqual(before);
    expect(await db.inspect.credentialReturnKey.count()).toBe(returnKeysBefore);
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({
        where: { id: w.endpointId },
        select: { secretKeyId: true, secretVersion: true },
      }),
    ).toEqual(endpointBefore);
    expect(await readDataKeyEpoch(db.inspect)).toMatchObject({ currentKid: K2.id, epoch: 2n });
  });

  it("a switch blocks writers that arrive during it; they then seal under the new kid", async () => {
    // Runbook step 3: CURRENT=new, PREVIOUS=old. Switch back to K1 and forth,
    // with the webhook rotate as the waiting writer.
    useKeys(K2_HEX, K1_HEX);
    const gate = db.pauseAt("promote", { after: EPOCH_UPDATE });
    const promoting = db.run("promote", () => promoteDataKey(ring(K2, K1), K1.id));
    await gate.waitReached();
    const writing = db.run("writer", () =>
      webhooks.rotateWebhookSecret(sessionPrincipal(w.owner), {
        id: w.endpointId,
        overlapSeconds: 0,
      }),
    );
    await db.waitUntilBlocked("writer", { by: "promote" });
    gate.release();
    expect(await promoting).toMatchObject({ ok: true, changed: true, currentKid: K1.id });
    await writing;
    expect(
      (
        await db.inspect.webhookEndpoint.findUniqueOrThrow({
          where: { id: w.endpointId },
          select: { secretKeyId: true },
        })
      ).secretKeyId,
    ).toBe(K1.id);
    expect(await promoteDataKey(ring(K2, K1), K2.id)).toMatchObject({
      ok: true,
      changed: true,
      currentKid: K2.id,
      previousKid: K1.id,
      epoch: 4n,
    });
    // Promoting the current kid again changes nothing.
    expect(await promoteDataKey(ring(K2, K1), K2.id)).toMatchObject({
      ok: true,
      changed: false,
      epoch: 4n,
    });
  });

  it("rewrap drives every old-kid count to zero, keeps destroyed keys empty, and the counts stay zero", async () => {
    useKeys(K2_HEX, K1_HEX);
    expect(await countFor(K1.id)).toBeGreaterThan(0);
    const before = await readDataKeyStatus({ ring: ring(K2, K1), client: db.inspect });
    expect(before.kids.find((kid) => kid.kid === K1.id)?.safeToRemove).toBe(false);

    expect(await rewrapCredentialKeys()).toMatchObject({ stale: false, failed: 0 });
    // The webhook rekey follows the epoch kid, not keys[0].
    const rekey = await ledger.runMaintenance({
      client: db.prisma,
      keys: [WEBHOOK_K1, WEBHOOK_K2],
    });
    expect(rekey.rekeyFailed).toBe(0);

    expect(await countFor(K1.id)).toBe(0);
    const after = await readDataKeyStatus({ ring: ring(K2, K1), client: db.inspect });
    expect(after.epoch).toMatchObject({ currentKid: K2.id, previousKid: K1.id, epoch: "4" });
    expect(after.kids.find((kid) => kid.kid === K1.id)).toMatchObject({
      rows: 0,
      current: false,
      safeToRemove: true,
    });
    expect(after.kids.find((kid) => kid.kid === K2.id)?.safeToRemove).toBe(false);

    // Everything opens with K2 alone.
    const onlyK2 = deriveVaultKeys(ring(K2, null));
    const versions = await db.inspect.credentialSecretVersion.findMany({
      where: { instanceId: w.instance.id },
      take: 10,
      select: {
        storageSeq: true,
        kind: true,
        ciphertext: true,
        nonce: true,
        wrappedDek: true,
        wrapSalt: true,
        wrapNonce: true,
        rootKid: true,
        policyDigest: true,
        sizeBytes: true,
      },
    });
    expect(versions.length).toBeGreaterThan(1);
    for (const row of versions) {
      const plain = decryptValue(
        {
          ciphertext: Buffer.from(row.ciphertext),
          nonce: Buffer.from(row.nonce),
          wrappedDek: Buffer.from(row.wrappedDek),
          wrapSalt: Buffer.from(row.wrapSalt),
          wrapNonce: Buffer.from(row.wrapNonce),
          rootKid: row.rootKid,
          policyDigest: row.policyDigest,
          sizeBytes: row.sizeBytes,
        },
        {
          userId: w.owner,
          credentialId: w.login.id,
          instanceId: w.instance.id,
          storageSeq: row.storageSeq,
          kind: row.kind,
          policyDigest: row.policyDigest,
        },
        onlyK2.dek.all,
      );
      plain.fill(0);
    }
    const returnKeys = await db.inspect.credentialReturnKey.findMany({
      orderBy: { epoch: "asc" },
      take: 10,
      select: {
        kidR: true,
        publicKey: true,
        wrappedPrivate: true,
        rwrapSalt: true,
        wrapNonce: true,
        rootKid: true,
        destroyedAt: true,
      },
    });
    const [destroyed, ...live] = returnKeys;
    expect(destroyed?.destroyedAt).not.toBeNull();
    // Destroyed: never rewrapped, still empty, not counted.
    expect(destroyed?.wrappedPrivate.byteLength).toBe(0);
    expect(destroyed?.rootKid).toBe(K1.id);
    expect(live.length).toBeGreaterThan(0);
    for (const row of live) {
      expect(row.rootKid).toBe(K2.id);
      const pair = unwrapReturnPrivateKey(
        {
          kidR: row.kidR,
          publicKey: Buffer.from(row.publicKey),
          wrappedPrivate: Buffer.from(row.wrappedPrivate),
          rwrapSalt: Buffer.from(row.rwrapSalt),
          wrapNonce: Buffer.from(row.wrapNonce),
          rootKid: row.rootKid,
        },
        onlyK2.returnKey.all,
      );
      pair.privateKey.fill(0);
    }

    // Post-switch writes by every kind of process: a current one seals under
    // K2, a stale one (K1 only) is refused. The K1 count stays zero.
    await w.write("token-v4");
    await rotateReturnKey();
    useKeys(K1_HEX);
    await expect(w.write("token-stale-2")).rejects.toMatchObject({
      code: "SERVICE_UNAVAILABLE",
    });
    expect(await countFor(K1.id)).toBe(0);
    // A second rewrap pass finds nothing to do.
    useKeys(K2_HEX, K1_HEX);
    expect(await rewrapCredentialKeys()).toMatchObject({ values: 0, returnKeys: 0, failed: 0 });
  });

  it("promote refuses a kid this process does not hold and a malformed kid", async () => {
    const stranger = dataRootKey(randomBytes(32).toString("hex"));
    expect(await promoteDataKey(ring(K2, K1), stranger.id)).toEqual({
      ok: false,
      reason: "key_not_held",
    });
    expect(await promoteDataKey(ring(K2, K1), "NOT-A-KID")).toEqual({
      ok: false,
      reason: "kid_malformed",
    });
    expect(await readDataKeyEpoch(db.inspect)).toMatchObject({ currentKid: K2.id, epoch: 4n });
  });
});
