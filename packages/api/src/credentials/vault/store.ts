import type { Prisma } from "@wssp/db";
import {
  type Bundle,
  BundleError,
  decodeBundle,
  encodeBundle,
  envValueAcceptable,
  fromHex,
  headerValueAcceptable,
  type LoginDefinition,
  missingRequiredPaths,
} from "@wssp/login-definition";
import { fenceWriteKey } from "../../crypto/data-key-epoch";
import { type DekWrapKey, readVaultKeys } from "./keys";
import {
  type CredentialDelivery,
  computePolicyDigest,
  decryptValue,
  encryptValue,
  rewrapDek,
  type SecretVersionKind,
} from "./value";

/**
 * The only module that writes or reads `CredentialSecretVersion` ciphertext
 * columns, and the only place outside the crypto core where plaintext bundles
 * exist. Every plaintext buffer is zeroed in `finally`. Callers pass verified
 * definitions (digest recomputed on load) and hold the instance row lock
 *.
 */

type Tx = Prisma.TransactionClient;

/** A value write refused against the definition. Names an entry, never a byte of the value. */
export class CredentialValueInvalid extends Error {
  /** `path`: the offending file entry (non-secret), when the bundle check names one. */
  constructor(
    readonly entry: string,
    readonly path?: string,
  ) {
    super("The login value does not match its definition.");
    this.name = "CredentialValueInvalid";
  }
}

export class CredentialVaultUnavailable extends Error {
  constructor() {
    super("The credential vault is unavailable.");
    this.name = "CredentialVaultUnavailable";
  }
}

export type PlainValueInput = {
  files: { path: string; kind: "file" | "dir"; mode?: number; data?: Uint8Array }[];
  env: { name: string; value: Uint8Array }[];
};

export type VerifiedLogin = {
  userId: string;
  credentialId: string;
  definition: LoginDefinition;
  definitionDigest: string;
  delivery: CredentialDelivery;
};

function vaultKeys() {
  const keys = readVaultKeys();
  if (!keys) throw new CredentialVaultUnavailable();
  return keys;
}

/**
 * A required file is absent: the entry names the class and `path` the file
 * (E2-B-02; joining the path onto `files.` gave `files..tool/token`).
 */
function missingRequired(path: string | undefined): CredentialValueInvalid {
  return new CredentialValueInvalid("files.missing_required", path);
}

/** Final header values (RFC 9110 field-value) for every proxied env entry, plus env bounds. */
function checkEnv(definition: LoginDefinition, env: PlainValueInput["env"]) {
  const declared = new Set((definition.credentials.env ?? []).map((entry) => entry.name));
  // An undeclared name is named (E2-B-02): env names are not secret.
  for (const value of env)
    if (!declared.has(value.name)) throw new CredentialValueInvalid(`env.${value.name}`);
  for (const entry of definition.credentials.env ?? []) {
    const value = env.find((candidate) => candidate.name === entry.name);
    if (!value) {
      if (entry.required) throw new CredentialValueInvalid(`env.${entry.name}`);
      continue;
    }
    if (!envValueAcceptable(value.value)) throw new CredentialValueInvalid(`env.${entry.name}`);
    if (entry.proxy && !headerValueAcceptable(entry.proxy.format, value.value))
      throw new CredentialValueInvalid(`env.${entry.name}`);
  }
}

function buildBundle(login: VerifiedLogin, input: PlainValueInput): Uint8Array {
  const bundle: Bundle = {
    definitionDigest: fromHex(login.definitionDigest),
    files: input.files.map((file) =>
      file.kind === "dir"
        ? { kind: "dir", path: file.path, mode: file.mode ?? 0o700 }
        : {
            kind: "file",
            path: file.path,
            mode: file.mode ?? 0o600,
            data: file.data ?? new Uint8Array(),
          },
    ),
    env: input.env.map((entry) => ({ name: entry.name, value: entry.value })),
  };
  checkEnv(login.definition, bundle.env);
  const missing = missingRequiredPaths(bundle, login.definition);
  if (missing.length > 0) throw missingRequired(missing[0]);
  try {
    return encodeBundle(bundle, login.definition);
  } catch (error) {
    if (error instanceof BundleError)
      throw new CredentialValueInvalid(`bundle.${error.reason}`, error.path);
    throw error;
  }
}

/** Keep the current version, the two previous non-checkpoint versions and the newest checkpoint. */
async function prune(tx: Tx, instanceId: string) {
  await tx.$executeRaw`DELETE FROM credential_secret_version v WHERE v."instanceId" = ${instanceId}
    AND v."storageSeq" NOT IN (
      SELECT "storageSeq" FROM credential_secret_version WHERE "instanceId" = ${instanceId}
        AND kind::text <> 'CHECKPOINT' ORDER BY "storageSeq" DESC LIMIT 3)
    AND v."storageSeq" NOT IN (
      SELECT "storageSeq" FROM credential_secret_version WHERE "instanceId" = ${instanceId}
        AND kind::text = 'CHECKPOINT' ORDER BY "storageSeq" DESC LIMIT 1)`;
}

/** Encrypts `bytes` as the instance's next storage sequence and makes it current. */
async function insertCurrent(
  tx: Tx,
  login: VerifiedLogin,
  instanceId: string,
  kind: SecretVersionKind,
  bytes: Uint8Array,
  sourceLeaseId: string | null,
  makeCurrent = true,
): Promise<{ storageSeq: number; sizeBytes: number }> {
  // The data-key epoch fence (§4.6): seal under the kid the DB names.
  const writeKey = await fenceWriteKey(tx, vaultKeys().dek.all);
  const instance = await tx.credentialInstance.findUniqueOrThrow({
    where: { id: instanceId },
    select: { nextStorageSeq: true },
  });
  const storageSeq = instance.nextStorageSeq;
  const sealed = encryptValue(
    bytes,
    {
      userId: login.userId,
      credentialId: login.credentialId,
      instanceId,
      storageSeq,
      kind,
      policyDigest: computePolicyDigest(login.definitionDigest, login.delivery),
    },
    writeKey,
  );
  await tx.credentialSecretVersion.create({
    data: {
      instanceId,
      storageSeq,
      kind,
      ciphertext: new Uint8Array(sealed.ciphertext),
      nonce: new Uint8Array(sealed.nonce),
      wrappedDek: new Uint8Array(sealed.wrappedDek),
      wrapSalt: new Uint8Array(sealed.wrapSalt),
      wrapNonce: new Uint8Array(sealed.wrapNonce),
      rootKid: sealed.rootKid,
      policyDigest: sealed.policyDigest,
      sizeBytes: sealed.sizeBytes,
      sourceLeaseId,
    },
    select: { storageSeq: true },
  });
  await tx.credentialInstance.update({
    where: { id: instanceId },
    data: makeCurrent
      ? {
          currentSeq: storageSeq,
          nextStorageSeq: storageSeq + 1,
          state: "READY",
          needsLoginReason: null,
        }
      : { nextStorageSeq: storageSeq + 1 },
    select: { id: true },
  });
  await prune(tx, instanceId);
  return { storageSeq, sizeBytes: sealed.sizeBytes };
}

/**
 * Upload (§11.4): validate files and env against the verified definition
 * (including final proxied header values), build the binary bundle, encrypt it
 * under a fresh DEK and make it current. The caller holds the instance lock.
 */
export async function writeUploadedValue(
  tx: Tx,
  login: VerifiedLogin,
  instanceId: string,
  input: PlainValueInput,
): Promise<{ storageSeq: number; sizeBytes: number }> {
  const bytes = buildBundle(login, input);
  try {
    return await insertCurrent(tx, login, instanceId, "UPLOAD", bytes, null);
  } finally {
    bytes.fill(0);
    for (const file of input.files) file.data?.fill(0);
    for (const entry of input.env) entry.value.fill(0);
  }
}

type StoredVersion = {
  storageSeq: number;
  kind: SecretVersionKind;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  wrappedDek: Uint8Array;
  wrapSalt: Uint8Array;
  wrapNonce: Uint8Array;
  rootKid: string;
  policyDigest: string;
  sizeBytes: number;
};

const versionSelect = {
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
} satisfies Prisma.CredentialSecretVersionSelect;

function openVersion(login: VerifiedLogin, instanceId: string, row: StoredVersion): Buffer {
  return decryptValue(
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
      userId: login.userId,
      credentialId: login.credentialId,
      instanceId,
      storageSeq: row.storageSeq,
      kind: row.kind,
      policyDigest: computePolicyDigest(login.definitionDigest, login.delivery),
    },
    vaultKeys().dek.all,
  );
}

export type RepinOutcome = "reencrypted" | "erased" | "empty";

/**
 * Re-pin one instance (§4.5): decrypt the current value (and a checkpoint
 * newer than it) under the OLD policy, validate it against the NEW definition
 * (bundle rules and final header values) and re-encrypt it with a fresh DEK
 * under the new policy. Every older version is dropped: its AAD names the old
 * policy digest, so it can no longer be opened. `erase` empties the instance
 * instead (PROXY login whose proxy spec changed; confirmed by the caller).
 */
export async function repinInstanceValue(
  tx: Tx,
  from: VerifiedLogin,
  to: VerifiedLogin,
  instanceId: string,
  options: { erase: boolean },
): Promise<RepinOutcome> {
  const instance = await tx.credentialInstance.findUniqueOrThrow({
    where: { id: instanceId },
    select: { currentSeq: true },
  });
  if (instance.currentSeq === null) return "empty";
  const current = await tx.credentialSecretVersion.findUnique({
    where: { instanceId_storageSeq: { instanceId, storageSeq: instance.currentSeq } },
    select: versionSelect,
  });
  const checkpoint = await tx.credentialSecretVersion.findFirst({
    where: { instanceId, kind: "CHECKPOINT", storageSeq: { gt: instance.currentSeq } },
    orderBy: { storageSeq: "desc" },
    select: versionSelect,
  });
  if (options.erase || !current) {
    await tx.credentialSecretVersion.deleteMany({ where: { instanceId } });
    await tx.credentialInstance.update({
      where: { id: instanceId },
      data: { currentSeq: null, state: "EMPTY", needsLoginReason: "repinned" },
      select: { id: true },
    });
    return "erased";
  }
  const reencrypt = async (row: StoredVersion, kind: SecretVersionKind, makeCurrent: boolean) => {
    const plain = openVersion(from, instanceId, row);
    let next: Uint8Array | undefined;
    try {
      const bundle = decodeBundle(plain, from.definition, fromHex(from.definitionDigest));
      checkEnv(to.definition, bundle.env);
      try {
        next = encodeBundle(
          { ...bundle, definitionDigest: fromHex(to.definitionDigest) },
          to.definition,
        );
      } catch (error) {
        if (error instanceof BundleError)
          throw new CredentialValueInvalid(`bundle.${error.reason}`, error.path);
        throw error;
      }
      const missing = missingRequiredPaths(bundle, to.definition);
      if (missing.length > 0) throw missingRequired(missing[0]);
      return await insertCurrent(tx, to, instanceId, kind, next, null, makeCurrent);
    } finally {
      plain.fill(0);
      next?.fill(0);
    }
  };
  // Every existing version is older than the ones written below.
  const { nextStorageSeq: firstNewSeq } = await tx.credentialInstance.findUniqueOrThrow({
    where: { id: instanceId },
    select: { nextStorageSeq: true },
  });
  // Current first; a checkpoint newer than it stays newer than the new current.
  await reencrypt(current, "REPIN", true);
  if (checkpoint) await reencrypt(checkpoint, "CHECKPOINT", false);
  await tx.credentialSecretVersion.deleteMany({
    where: { instanceId, storageSeq: { lt: firstNewSeq } },
  });
  return "reencrypted";
}

/**
 * Force-release checkpoint promotion (§7.1, R9): the newest CHECKPOINT the
 * released lease committed that is newer than the instance's current value
 * is re-encrypted under a fresh DEK as a PROMOTED version and made current.
 * It is decoded against the pinned definition first (a value that no longer
 * validates is refused, never promoted). Null when there is none. The caller
 * holds the instance row FOR UPDATE.
 */
export async function promoteLeaseCheckpoint(
  tx: Tx,
  login: VerifiedLogin,
  instanceId: string,
  sourceLeaseId: string,
): Promise<{ storageSeq: number; sizeBytes: number; fromSeq: number } | null> {
  const instance = await tx.credentialInstance.findUniqueOrThrow({
    where: { id: instanceId },
    select: { currentSeq: true },
  });
  const checkpoint = await tx.credentialSecretVersion.findFirst({
    where: {
      instanceId,
      kind: "CHECKPOINT",
      sourceLeaseId,
      ...(instance.currentSeq === null ? {} : { storageSeq: { gt: instance.currentSeq } }),
    },
    orderBy: { storageSeq: "desc" },
    select: versionSelect,
  });
  if (!checkpoint) return null;
  const plain = openVersion(login, instanceId, checkpoint);
  // The decoded file and env buffers are views into `plain`: they are wiped
  // with it, only after `plain` was encrypted (wiping first sealed zeros).
  let bundle: Bundle | null = null;
  try {
    try {
      bundle = decodeBundle(plain, login.definition, fromHex(login.definitionDigest));
    } catch (error) {
      if (error instanceof BundleError)
        throw new CredentialValueInvalid(`bundle.${error.reason}`, error.path);
      throw error;
    }
    const missing = missingRequiredPaths(bundle, login.definition);
    if (missing.length > 0) throw missingRequired(missing[0]);
    const written = await insertCurrent(
      tx,
      login,
      instanceId,
      "PROMOTED",
      plain,
      sourceLeaseId,
      true,
    );
    return { ...written, fromSeq: checkpoint.storageSeq };
  } finally {
    if (bundle) {
      for (const file of bundle.files) if (file.kind === "file") file.data.fill(0);
      for (const entry of bundle.env) entry.value.fill(0);
    }
    plain.fill(0);
  }
}

/**
 * Per lease, the newest CHECKPOINT it committed that is newer than the
 * instance's current value (metadata only: sequence and time).
 */
export async function promotableCheckpoints(
  client: Pick<Tx, "credentialInstance" | "credentialSecretVersion">,
  instanceId: string,
  leaseIds: readonly string[],
): Promise<Map<string, { storageSeq: number; createdAt: Date }>> {
  const out = new Map<string, { storageSeq: number; createdAt: Date }>();
  if (leaseIds.length === 0) return out;
  const instance = await client.credentialInstance.findUnique({
    where: { id: instanceId },
    select: { currentSeq: true },
  });
  if (!instance) return out;
  const rows = await client.credentialSecretVersion.findMany({
    where: {
      instanceId,
      kind: "CHECKPOINT",
      sourceLeaseId: { in: [...leaseIds] },
      ...(instance.currentSeq === null ? {} : { storageSeq: { gt: instance.currentSeq } }),
    },
    orderBy: { storageSeq: "desc" },
    // Pruning keeps one checkpoint per instance; the bound is defensive.
    take: leaseIds.length * 2,
    select: { storageSeq: true, createdAt: true, sourceLeaseId: true },
  });
  for (const row of rows)
    if (row.sourceLeaseId && !out.has(row.sourceLeaseId))
      out.set(row.sourceLeaseId, { storageSeq: row.storageSeq, createdAt: row.createdAt });
  return out;
}

async function currentVersion(tx: Tx, instanceId: string, storageSeq: number) {
  return tx.credentialSecretVersion.findUnique({
    where: { instanceId_storageSeq: { instanceId, storageSeq } },
    select: versionSelect,
  });
}

export type GrantBundle = {
  /** Plaintext bundle v1; the caller zeroes it once streamed. */
  bytes: Buffer;
  fileCount: number;
  envCount: number;
};

/**
 * Opens the instance's value at `storageSeq` for a bundle grant (§7.4.1). The
 * restore variant (`envOnly`) re-encodes env (and proxy values) only: files
 * are never restored through it. Null when that version no longer exists.
 */
export async function openGrantBundle(
  tx: Tx,
  login: VerifiedLogin,
  instanceId: string,
  storageSeq: number,
  options: { envOnly: boolean },
): Promise<GrantBundle | null> {
  const row = await currentVersion(tx, instanceId, storageSeq);
  if (!row) return null;
  const plain = openVersion(login, instanceId, row);
  const digest = fromHex(login.definitionDigest);
  try {
    const bundle = decodeBundle(plain, login.definition, digest);
    if (!options.envOnly) {
      const out = Buffer.from(plain);
      return { bytes: out, fileCount: bundle.files.length, envCount: bundle.env.length };
    }
    const envOnly = encodeBundle(
      { definitionDigest: digest, files: [], env: bundle.env },
      login.definition,
    );
    for (const file of bundle.files) if (file.kind === "file") file.data.fill(0);
    for (const entry of bundle.env) entry.value.fill(0);
    return { bytes: Buffer.from(envOnly), fileCount: 0, envCount: bundle.env.length };
  } finally {
    plain.fill(0);
  }
}

export type CaptureCommitOutcome =
  | { outcome: "committed"; storageSeq: number; sizeBytes: number }
  | { outcome: "unchanged" }
  | { outcome: "superseded" }
  | { outcome: "incomplete" }
  | { outcome: "invalid_bundle" };

/**
 * Commit-fence steps 10-13 (§7.4.3) for an opened capture. `captured` is the
 * plaintext bundle the host packed (files only; any env it carries is ignored:
 * env is that of the current authenticated version, or none). Order:
 * validate → merge env → compare with the current plaintext (UNCHANGED) →
 * the non-checkpoint write baseline (`expectBaseSeq`, `undefined` for
 * checkpoints) → insert under a fresh DEK. The caller holds the instance row
 * FOR UPDATE and zeroes `captured`.
 */
export async function commitCapturedValue(
  tx: Tx,
  login: VerifiedLogin,
  instanceId: string,
  input: {
    captured: Uint8Array;
    kind: SecretVersionKind;
    expectBaseSeq: number | null | undefined;
    sourceLeaseId: string;
  },
): Promise<CaptureCommitOutcome> {
  const digest = fromHex(login.definitionDigest);
  let bundle: Bundle;
  try {
    bundle = decodeBundle(input.captured, login.definition, digest);
  } catch (error) {
    if (error instanceof BundleError) return { outcome: "invalid_bundle" };
    throw error;
  }
  const wipe = (b: Bundle) => {
    for (const file of b.files) if (file.kind === "file") file.data.fill(0);
    for (const entry of b.env) entry.value.fill(0);
  };
  let current: Buffer | null = null;
  let currentBundle: Bundle | null = null;
  let merged: Uint8Array | null = null;
  try {
    if (missingRequiredPaths(bundle, login.definition).length > 0) return { outcome: "incomplete" };
    const instance = await tx.credentialInstance.findUniqueOrThrow({
      where: { id: instanceId },
      select: { currentSeq: true },
    });
    const row =
      instance.currentSeq === null
        ? null
        : await currentVersion(tx, instanceId, instance.currentSeq);
    if (row) {
      current = openVersion(login, instanceId, row);
      currentBundle = decodeBundle(current, login.definition, digest);
    }
    try {
      merged = encodeBundle(
        { definitionDigest: digest, files: bundle.files, env: currentBundle?.env ?? [] },
        login.definition,
      );
    } catch (error) {
      if (error instanceof BundleError) return { outcome: "invalid_bundle" };
      throw error;
    }
    if (current && Buffer.compare(current, Buffer.from(merged)) === 0)
      return { outcome: "unchanged" };
    if (input.expectBaseSeq !== undefined && instance.currentSeq !== input.expectBaseSeq)
      return { outcome: "superseded" };
    const written = await insertCurrent(
      tx,
      login,
      instanceId,
      input.kind,
      merged,
      input.sourceLeaseId,
      input.kind !== "CHECKPOINT",
    );
    return { outcome: "committed", ...written };
  } finally {
    wipe(bundle);
    if (currentBundle) wipe(currentBundle);
    current?.fill(0);
    merged?.fill(0);
  }
}

export type RewrapCursor = { afterInstanceId: string; afterSeq: number } | null;

/**
 * Rewrap batch (§4.6): rewrap the DEK of up to `limit` versions whose
 * `rootKid` is not `writeKey`'s, under a fresh salt and nonce; the ciphertext
 * is untouched. The caller holds the data-key epoch row FOR SHARE and got
 * `writeKey` from it. Rows are taken FOR UPDATE SKIP LOCKED in key order after
 * `cursor`; each update checks the old kid it read. The DEK AAD binds the
 * row's own policy digest, so a tampered column fails authentication rather
 * than being rewrapped. A row no configured root opens is counted, not fatal.
 */
export async function rewrapValueBatch(
  tx: Tx,
  writeKey: DekWrapKey,
  cursor: RewrapCursor,
  limit: number,
): Promise<{ rewrapped: number; failed: number; scanned: number; last: RewrapCursor }> {
  const keys = vaultKeys().dek.all;
  const after = cursor ?? { afterInstanceId: "", afterSeq: -1 };
  const rows = await tx.$queryRaw<
    {
      instanceId: string;
      storageSeq: number;
      kind: string;
      wrappedDek: Uint8Array;
      wrapSalt: Uint8Array;
      wrapNonce: Uint8Array;
      rootKid: string;
      policyDigest: string;
      userId: string;
      credentialId: string;
    }[]
  >`SELECT v."instanceId", v."storageSeq", v.kind::text AS kind, v."wrappedDek", v."wrapSalt",
      v."wrapNonce", v."rootKid", v."policyDigest", i."userId", i."credentialId"
    FROM credential_secret_version v JOIN credential_instance i ON i.id = v."instanceId"
    WHERE v."rootKid" <> ${writeKey.rootKeyId}
      AND (v."instanceId", v."storageSeq") > (${after.afterInstanceId}, ${after.afterSeq})
    ORDER BY v."instanceId", v."storageSeq" LIMIT ${limit}
    FOR UPDATE OF v SKIP LOCKED`;
  let rewrapped = 0;
  let failed = 0;
  for (const row of rows) {
    let next: ReturnType<typeof rewrapDek>;
    try {
      next = rewrapDek(
        {
          wrappedDek: Buffer.from(row.wrappedDek),
          wrapSalt: Buffer.from(row.wrapSalt),
          wrapNonce: Buffer.from(row.wrapNonce),
          rootKid: row.rootKid,
        },
        {
          userId: row.userId,
          credentialId: row.credentialId,
          instanceId: row.instanceId,
          storageSeq: row.storageSeq,
          kind: row.kind as SecretVersionKind,
          policyDigest: row.policyDigest,
        },
        keys,
        writeKey,
      );
    } catch {
      // Unopenable under every configured root: counted, never logged with ids.
      failed++;
      continue;
    }
    const updated = await tx.credentialSecretVersion.updateMany({
      where: { instanceId: row.instanceId, storageSeq: row.storageSeq, rootKid: row.rootKid },
      data: {
        wrappedDek: new Uint8Array(next.wrappedDek),
        wrapSalt: new Uint8Array(next.wrapSalt),
        wrapNonce: new Uint8Array(next.wrapNonce),
        rootKid: next.rootKid,
      },
    });
    rewrapped += updated.count;
  }
  const tail = rows.at(-1);
  return {
    rewrapped,
    failed,
    scanned: rows.length,
    last: tail ? { afterInstanceId: tail.instanceId, afterSeq: tail.storageSeq } : null,
  };
}
