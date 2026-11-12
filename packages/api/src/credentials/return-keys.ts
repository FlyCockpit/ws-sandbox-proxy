import prisma, { type Prisma } from "@wssp/db";
import { toBase64Url } from "./vault/codec";
import { destroyReturnKeyMaterial, insertReturnKey } from "./vault/return-key-store";

/**
 * Return-key epochs. Every key has an
 * immutable, strictly increasing `epoch`, assigned from the singleton
 * `credential_return_key_state`. Issuance takes the state FOR SHARE and may
 * issue only the current kid at the current epoch; rotation and destruction
 * take it FOR UPDATE, so no issuance of R1 can commit after R2 became current
 * and a retired key is never issued again. The state row is locked alone
 * (no other lock is held before it).
 */

type Tx = Prisma.TransactionClient;

type StateRow = { currentKidR: string; currentEpoch: bigint };

async function readState(tx: Tx, mode: "share" | "update"): Promise<StateRow | null> {
  const rows =
    mode === "share"
      ? await tx.$queryRaw<StateRow[]>`SELECT "currentKidR", "currentEpoch"
          FROM credential_return_key_state WHERE id = 1 FOR SHARE`
      : await tx.$queryRaw<StateRow[]>`SELECT "currentKidR", "currentEpoch"
          FROM credential_return_key_state WHERE id = 1 FOR UPDATE`;
  return rows[0] ?? null;
}

/** First key at epoch 1; concurrent bootstraps serialize on an advisory lock. */
async function bootstrapState(): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('wssp:credential-return-key-bootstrap'))`;
    if (await readState(tx, "update")) return;
    const key = await insertReturnKey(tx, 1n);
    await tx.credentialReturnKeyState.create({
      data: { id: 1, currentKidR: key.kidR, currentEpoch: 1n },
      select: { id: true },
    });
  });
}

export type ReturnKeyFrame = {
  type: "credential.return.key";
  kidR: string;
  epoch: number;
  publicKey: string;
  serverOrigin: string;
};

/**
 * Hello step (§4.3.0): when the host's slot epoch is below the current epoch,
 * commit the issuance row FIRST (every issued row counts as potentially used),
 * then return the frame to send. Null when the host is already current.
 */
export async function issueCurrentReturnKey(input: {
  hostId: string;
  hostSlotEpoch: number;
  serverOrigin: string;
}): Promise<ReturnKeyFrame | null> {
  const run = () =>
    prisma.$transaction(async (tx) => {
      const state = await readState(tx, "share");
      if (!state) return "bootstrap" as const;
      if (BigInt(input.hostSlotEpoch) >= state.currentEpoch) return null;
      const key = await tx.credentialReturnKey.findUniqueOrThrow({
        where: { kidR: state.currentKidR },
        select: { kidR: true, epoch: true, publicKey: true },
      });
      await tx.$executeRaw`INSERT INTO credential_host_return_key ("hostId", "kidR", epoch)
        VALUES (${input.hostId}, ${key.kidR}, ${key.epoch}) ON CONFLICT DO NOTHING`;
      return {
        type: "credential.return.key" as const,
        kidR: key.kidR,
        epoch: Number(key.epoch),
        publicKey: toBase64Url(key.publicKey),
        serverOrigin: input.serverOrigin,
      };
    });
  const first = await run();
  if (first !== "bootstrap") return first;
  await bootstrapState();
  const second = await run();
  return second === "bootstrap" ? null : second;
}

export type ReturnKeyAck = {
  kidR: string;
  epoch: number;
  currentEpoch: number;
  refused?: "stale" | "substitution" | undefined;
};

export type ReturnKeyAckOutcome = "applied" | "ignored" | "substitution";

/**
 * Server acceptance rule (§4.3.0): an ack applies only if `(hostId, kidR,
 * epoch)` matches an issuance row, and `ackedAt` is set only for the newest
 * acked epoch per host, so an older ack never marks anything. A refused
 * substitution changes nothing and is reported for an alert.
 */
export async function applyReturnKeyAck(
  tx: Tx,
  hostId: string,
  ack: ReturnKeyAck,
): Promise<ReturnKeyAckOutcome> {
  if (ack.refused === "substitution") return "substitution";
  if (ack.refused === "stale") return "ignored";
  const updated = await tx.$executeRaw`UPDATE credential_host_return_key k
    SET "ackedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE k."hostId" = ${hostId} AND k."kidR" = ${ack.kidR} AND k.epoch = ${BigInt(ack.epoch)}
      AND k."ackedAt" IS NULL
      AND NOT EXISTS (SELECT 1 FROM credential_host_return_key n
        WHERE n."hostId" = k."hostId" AND n."ackedAt" IS NOT NULL AND n.epoch > k.epoch)`;
  return updated === 1 ? "applied" : "ignored";
}

/**
 * Census step: an older kid is drained on a host once the host acked a
 * higher epoch and a complete census (whose `keyEpoch` is at least that
 * epoch, so it was taken after the switch) lists no pending envelope under it.
 */
export async function markDrainedReturnKeys(
  tx: Tx,
  hostId: string,
  keyEpoch: number,
  pendingKids: ReadonlySet<string>,
): Promise<void> {
  const kids = [...pendingKids];
  await tx.$executeRaw`UPDATE credential_host_return_key
    SET "drainedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE "hostId" = ${hostId} AND "drainedAt" IS NULL AND epoch < ${BigInt(keyEpoch)}
      AND NOT ("kidR" = ANY(${kids}::text[]))
      AND EXISTS (SELECT 1 FROM credential_host_return_key n WHERE n."hostId" = ${hostId}
        AND n."ackedAt" IS NOT NULL AND n.epoch > credential_host_return_key.epoch
        AND n.epoch <= ${BigInt(keyEpoch)})`;
}

async function rotateIn(tx: Tx): Promise<{ kidR: string; epoch: bigint } | null> {
  const state = await readState(tx, "update");
  if (!state) return null;
  await tx.credentialReturnKey.update({
    where: { kidR: state.currentKidR },
    data: { retiredAt: new Date() },
    select: { kidR: true },
  });
  const epoch = state.currentEpoch + 1n;
  const key = await insertReturnKey(tx, epoch);
  await tx.credentialReturnKeyState.update({
    where: { id: 1 },
    data: { currentKidR: key.kidR, currentEpoch: epoch },
    select: { id: true },
  });
  return { kidR: key.kidR, epoch };
}

/**
 * Admin rotation: retire the current key (decrypt-only) and make a new one
 * current at epoch + 1, under the state FOR UPDATE. With `tx` (the admin write
 * transaction) it runs there and returns null when no key exists yet (the
 * first issuance bootstraps one); without, it bootstraps first.
 */
export async function rotateReturnKey(): Promise<{ kidR: string; epoch: bigint }>;
export async function rotateReturnKey(tx: Tx): Promise<{ kidR: string; epoch: bigint } | null>;
export async function rotateReturnKey(tx?: Tx): Promise<{ kidR: string; epoch: bigint } | null> {
  if (tx) return rotateIn(tx);
  for (let attempt = 0; attempt < 2; attempt++) {
    const rotated = await prisma.$transaction(rotateIn);
    if (rotated) return rotated;
    await bootstrapState();
  }
  throw new Error("return key state is unavailable");
}

export type DestroyRefusal =
  | "not_found"
  | "current"
  | "already_destroyed"
  | "host_not_drained"
  | "quarantined_envelopes";

/**
 * Destruction gate (§4.3 step 4): under the state FOR UPDATE, every issuance
 * row of the kid — acked or not — must belong to a host declared lost, or to
 * a host that acked a HIGHER epoch and whose complete census after that ack
 * listed nothing pending under the kid (`drainedAt`). Deleted hosts cascade
 * their rows away. Live quarantined envelopes under the kid need an explicit,
 * audited `destroyQuarantined`. Time never authorizes destruction.
 */
export async function destroyReturnKey(
  input: { kidR: string; destroyQuarantined: boolean },
  tx?: Tx,
): Promise<{ ok: true; quarantined: number } | { ok: false; reason: DestroyRefusal }> {
  if (!tx) return prisma.$transaction((inner) => destroyReturnKey(input, inner));
  const state = await readState(tx, "update");
  const key = await tx.credentialReturnKey.findUnique({
    where: { kidR: input.kidR },
    select: { kidR: true, epoch: true, retiredAt: true, destroyedAt: true },
  });
  if (!key) return { ok: false, reason: "not_found" };
  if (key.destroyedAt) return { ok: false, reason: "already_destroyed" };
  if (!key.retiredAt || state?.currentKidR === key.kidR) return { ok: false, reason: "current" };
  if ((await blockingHosts(tx, key, null, 1)).length > 0)
    return { ok: false, reason: "host_not_drained" };
  const quarantined = await tx.credentialCaptureRejection.count({
    where: { kidR: key.kidR, discardedAt: null },
  });
  if (quarantined > 0 && !input.destroyQuarantined)
    return { ok: false, reason: "quarantined_envelopes" };
  await destroyReturnKeyMaterial(tx, key.kidR);
  return { ok: true, quarantined };
}

/**
 * Issuance rows of a retired key that still block its destruction (§4.3 step
 * 4): not declared lost, and not (drained AND the host acked a higher epoch).
 * Deleted hosts cascade their rows away. Keyset-paged by host id.
 */
async function blockingHosts(
  tx: Pick<Tx, "$queryRaw">,
  key: { kidR: string; epoch: bigint },
  afterHostId: string | null,
  limit: number,
) {
  return tx.$queryRaw<
    { hostId: string; issuedAt: Date; ackedAt: Date | null; drainedAt: Date | null }[]
  >`SELECT k."hostId", k."issuedAt", k."ackedAt", k."drainedAt"
    FROM credential_host_return_key k
    WHERE k."kidR" = ${key.kidR} AND k."declaredLostAt" IS NULL AND k."hostId" > ${afterHostId ?? ""}
      AND NOT (k."drainedAt" IS NOT NULL AND EXISTS (SELECT 1 FROM credential_host_return_key n
        WHERE n."hostId" = k."hostId" AND n.epoch > ${key.epoch} AND n."ackedAt" IS NOT NULL))
    ORDER BY k."hostId" LIMIT ${limit}`;
}

export type DeclareLostRefusal = "not_found" | "already_declared";

/**
 * Admin "declare lost" (audited by the caller): the host will never return,
 * so its issuance row of `kidR` stops blocking that key's destruction. Under
 * the state FOR UPDATE, like destruction. Irreversible for that row.
 */
export async function declareHostReturnKeyLost(
  input: { hostId: string; kidR: string },
  tx?: Tx,
): Promise<{ ok: true } | { ok: false; reason: DeclareLostRefusal }> {
  if (!tx) return prisma.$transaction((inner) => declareHostReturnKeyLost(input, inner));
  await readState(tx, "update");
  const row = await tx.credentialHostReturnKey.findUnique({
    where: { hostId_kidR: { hostId: input.hostId, kidR: input.kidR } },
    select: { declaredLostAt: true },
  });
  if (!row) return { ok: false, reason: "not_found" };
  if (row.declaredLostAt) return { ok: false, reason: "already_declared" };
  await tx.credentialHostReturnKey.update({
    where: { hostId_kidR: { hostId: input.hostId, kidR: input.kidR } },
    data: { declaredLostAt: new Date() },
    select: { hostId: true },
  });
  return { ok: true };
}

const returnKeyListSelect = {
  kidR: true,
  epoch: true,
  rootKid: true,
  createdAt: true,
  retiredAt: true,
  destroyedAt: true,
} satisfies Prisma.CredentialReturnKeySelect;

/**
 * Admin card listing, newest epoch first, keyset-paged by epoch. Each retired,
 * live key carries its blocking-host count (capped) and live quarantined
 * rejections. Metadata only: no key material, public key or wrap columns.
 */
export async function listReturnKeys(input: { afterEpoch: bigint | null; limit: number }) {
  const rows = await prisma.credentialReturnKey.findMany({
    where: input.afterEpoch === null ? {} : { epoch: { lt: input.afterEpoch } },
    orderBy: { epoch: "desc" },
    take: input.limit + 1,
    select: returnKeyListSelect,
  });
  const page = rows.slice(0, input.limit);
  const items = [];
  for (const row of page) {
    const live = row.retiredAt !== null && row.destroyedAt === null;
    const [blocking, quarantined] = live
      ? await Promise.all([
          blockingHosts(prisma, row, null, BLOCKER_COUNT_CAP + 1),
          prisma.credentialCaptureRejection.count({
            where: { kidR: row.kidR, discardedAt: null },
          }),
        ])
      : [[], 0];
    items.push({
      kidR: row.kidR,
      epoch: row.epoch.toString(),
      rootKid: row.rootKid,
      createdAt: row.createdAt,
      retiredAt: row.retiredAt,
      destroyedAt: row.destroyedAt,
      blockingHosts: Math.min(blocking.length, BLOCKER_COUNT_CAP),
      blockingHostsCapped: blocking.length > BLOCKER_COUNT_CAP,
      quarantined,
    });
  }
  return {
    items,
    nextCursor: rows.length > input.limit ? (page.at(-1)?.epoch.toString() ?? null) : null,
  };
}

const BLOCKER_COUNT_CAP = 100;

/** Hosts still blocking destruction of a retired key, keyset-paged by host id. */
export async function listReturnKeyBlockers(input: {
  kidR: string;
  afterHostId: string | null;
  limit: number;
}) {
  const key = await prisma.credentialReturnKey.findUnique({
    where: { kidR: input.kidR },
    select: { kidR: true, epoch: true },
  });
  if (!key) return { items: [], nextCursor: null };
  const rows = await blockingHosts(prisma, key, input.afterHostId, input.limit + 1);
  const page = rows.slice(0, input.limit);
  return {
    items: page,
    nextCursor: rows.length > input.limit ? (page.at(-1)?.hostId ?? null) : null,
  };
}

/** `credential.return.key.ack` under the sender's relay fence; null when the epoch is stale. */
export async function recordReturnKeyAck(input: {
  hostId: string;
  connectionEpoch: number;
  ack: ReturnKeyAck;
}): Promise<ReturnKeyAckOutcome | null> {
  const { lockHostByEpoch, RelayFenceRejected } = await import("../sandbox/relay-fence");
  try {
    return await prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, input.hostId, input.connectionEpoch);
      return applyReturnKeyAck(tx, input.hostId, input.ack);
    });
  } catch (error) {
    if (error instanceof RelayFenceRejected) return null;
    throw error;
  }
}
