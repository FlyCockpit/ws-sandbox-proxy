import { createHash, createHmac } from "node:crypto";
import type { Prisma, SandboxOperation } from "@wssp/db";
import { env } from "@wssp/env/server";
import { envSchema } from "@wssp/sandbox-contracts";

import {
  digestKeyChanged,
  digestKeyUnavailable,
  hostReconnecting,
  hostUnavailable,
  idempotencyConflict,
  sandboxNotFound,
} from "./errors";
import { encodeHmacContext } from "./hmac-context";

/** Bindings occupy distinct LP fields, including the immutable replay principal. */
export type RequestDigestContext = {
  domain?: string;
  ownerId?: string;
  hostId?: string;
  hostOwnerId?: string;
  authorizingKeyId?: string | null;
};

const REQUEST_DIGEST_SCHEME = "hmac-sha256-v1";

/**
 * MAC domain of a CREATE that entered the capacity queue: no host is bound,
 * so host fields are empty. A separate domain (same scheme, so dispatch and
 * key identity are unchanged) keeps a queued digest from ever colliding with
 * a placed one; the host only echoes `bodyHash`, it never recomputes it.
 */
export const QUEUED_CREATE_DIGEST_DOMAIN = "wssp-request-queued-v1";

export function requestDigestMetadata(): {
  requestDigestScheme: string;
  requestDigestKeyId: string;
};
export function requestDigestMetadata(kind: string): {
  requestDigestScheme: string;
  requestDigestKeyId: string | null;
};
export function requestDigestMetadata(kind?: string) {
  if (kind === "KILL_SANDBOX" || kind === "STOP_SANDBOX")
    return { requestDigestScheme: "sha256-env-free-v1", requestDigestKeyId: null };
  const master = Buffer.from(env.SANDBOX_REQUEST_HMAC_SECRET, "hex");
  const requestDigestKeyId = createHmac("sha256", master)
    .update(encodeHmacContext(["wssp-key-id-v1"]))
    .digest("hex")
    .slice(0, 32);
  return { requestDigestScheme: REQUEST_DIGEST_SCHEME, requestDigestKeyId };
}

/** Stable enrolled-host binding, identical to the CLI's canonical relay URL. */
export function hostJournalKey(hostOwnerId: string, hostId: string, serverBinding?: string) {
  const { requestDigestKeyId: keyId } = requestDigestMetadata();
  const url = new URL("/ws/sandbox-host", env.BETTER_AUTH_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.username = "";
  url.password = "";
  const server = serverBinding ?? url.toString();
  const keyHex = createHmac("sha256", Buffer.from(env.SANDBOX_REQUEST_HMAC_SECRET, "hex"))
    .update(encodeHmacContext(["wssp-host-journal-key-v2", keyId, server, hostOwnerId, hostId]))
    .digest("hex");
  return { keyVersion: 1 as const, keyId, server, hostOwnerId, hostId, keyHex };
}

/** Replay identity is retained evidence, never a grant to use a host. Placements
 * survive host retirement, so a replay hashes the original transport owner. */
export async function requestTransportIdentity(
  tx: Prisma.TransactionClient,
  sandboxOwnerId: string,
  hostId?: string | null,
  sandboxId?: string | null,
) {
  if (sandboxId) {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: sandboxId, userId: sandboxOwnerId },
      select: {
        state: true,
        originHostId: true,
        hostOwnerId: true,
        CurrentPlacement: { select: { hostOwnerId: true, originHostId: true } },
      },
    });
    if (!sandbox) throw sandboxNotFound();
    // Never placed (a capacity wait, waiting or ended) or OFFLOADED (hostless
    // by CHECK; `originHostId` is history only): no transport exists. Kill,
    // stop and cancel hash env-free bodies and a restore hashes the hostless
    // `restore-intent:v1` domain (§8.3a); nothing else is admitted.
    if (
      (!sandbox.originHostId || sandbox.state === "OFFLOADED") &&
      !sandbox.CurrentPlacement &&
      !sandbox.hostOwnerId
    )
      return { sandboxHostId: undefined, hostOwnerId: "" };
    const hostOwnerId = sandbox.CurrentPlacement?.hostOwnerId ?? sandbox.hostOwnerId;
    if (!hostOwnerId) throw digestKeyUnavailable();
    return {
      sandboxHostId:
        sandbox.CurrentPlacement?.originHostId ?? sandbox.originHostId ?? hostId ?? undefined,
      hostOwnerId,
    };
  }
  const host = hostId
    ? await tx.sandboxHost.findFirst({
        where: { id: hostId },
        select: { userId: true },
      })
    : null;
  if (hostId && !host?.userId) throw digestKeyUnavailable();
  return { sandboxHostId: hostId ?? undefined, hostOwnerId: host?.userId ?? "" };
}

/** Canonical intent MAC. No secret or env-dependent digest is public. */
export function hashRequestBody(body: unknown, context: RequestDigestContext = {}): string {
  const { requestDigestKeyId } = requestDigestMetadata();
  return createHmac("sha256", Buffer.from(env.SANDBOX_REQUEST_HMAC_SECRET, "hex"))
    .update(
      encodeHmacContext([
        context.domain ?? "wssp-request-v2",
        requestDigestKeyId,
        env.BETTER_AUTH_URL,
        context.ownerId ?? "",
        context.hostId ?? "",
        context.hostOwnerId ?? "",
        context.authorizingKeyId ?? "session",
        canonicalizeJson(body),
      ]),
    )
    .digest("hex");
}

/** Source revision defaults bind their owner in a separate MAC domain. */
export function hashRevisionDefaultsBody(body: unknown, ownerId: string): string {
  return hashOwnerOnlyBody(body, "wssp-revision-defaults-v1", ownerId, "", null);
}

function hashOwnerOnlyBody(
  body: unknown,
  domain: string,
  ownerId: string,
  hostId: string,
  keyId: string | null,
): string {
  return createHmac("sha256", Buffer.from(env.SANDBOX_REQUEST_HMAC_SECRET, "hex"))
    .update(
      encodeHmacContext([
        domain,
        requestDigestMetadata().requestDigestKeyId,
        env.BETTER_AUTH_URL,
        ownerId,
        hostId,
        keyId ?? "session",
        canonicalizeJson(body),
      ]),
    )
    .digest("hex");
}

/** Private config producer. This server MAC is opaque to the host, whose
 * local integrity checksum uses a separate derived key and LP domain. */
export function privateConfigBinding(
  input: {
    configId: string;
    sandboxId: string;
    generation: number;
    env: [string, string][];
  },
  context: {
    ownerId: string;
    hostOwnerId: string;
    hostId: string;
    authorizingKeyId: string | null;
  },
) {
  // Validate before any secret-bearing digest work.
  if (
    !envSchema.safeParse(Object.fromEntries(input.env)).success ||
    new Set(input.env.map(([key]) => key)).size !== input.env.length ||
    ![input.configId, input.sandboxId, context.ownerId, context.hostOwnerId, context.hostId].every(
      (id) => /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id),
    ) ||
    !Number.isInteger(input.generation) ||
    input.generation < 1 ||
    input.generation > 2_147_483_647
  )
    throw new Error("Invalid private config.");
  const metadata = requestDigestMetadata();
  return {
    configId: input.configId,
    bindingScheme: metadata.requestDigestScheme,
    bindingKeyId: metadata.requestDigestKeyId,
    bindingMac: hashRequestBody(
      { ...input, env: [...input.env].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)) },
      { ...context, domain: "wssp-server-config-binding-v2" },
    ),
  };
}

/** Only for env-free transfer identities which retain their existing SHA scheme. */
export function hashLegacyEnvFreeBody(body: unknown): string {
  return createHash("sha256").update(canonicalizeJson(body), "utf8").digest("hex");
}

export function hashOperationRequestBody(
  body: unknown,
  kind: string,
  context: RequestDigestContext = {},
): string {
  return kind === "KILL_SANDBOX" || kind === "STOP_SANDBOX"
    ? hashLegacyEnvFreeBody(body)
    : hashRequestBody(body, context);
}

function canonicalizeJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  const record = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(record).sort()) {
    sorted[key] = sortKeys(record[key]);
  }
  return sorted;
}

type DigestRecord = Pick<
  SandboxOperation,
  "requestBodyHash" | "requestDigestScheme" | "requestDigestKeyId"
>;
export type IdempotencyLookup<T extends DigestRecord> = T | null;

/**
 * Same owner-scoped idempotency key with an identical body returns the stored
 * operation; the same key with a different body is a conflict.
 */
export function reconcileIdempotency<T extends DigestRecord>(
  existing: IdempotencyLookup<T>,
  requestBodyHash: string | (() => string),
  metadata: {
    requestDigestScheme: string;
    requestDigestKeyId: string | null;
  } = requestDigestMetadata(),
): T | null {
  if (existing == null) {
    return null;
  }
  requireRequestDigestMetadata(existing, metadata);
  if (
    existing.requestBodyHash !==
    (typeof requestBodyHash === "function" ? requestBodyHash() : requestBodyHash)
  ) {
    throw idempotencyConflict();
  }
  return existing;
}

/** Key identity precedes kind/body equality, including cross-kind replay. */
export function requireRequestDigestMetadata(
  existing: Pick<DigestRecord, "requestDigestScheme" | "requestDigestKeyId">,
  metadata: { requestDigestScheme: string; requestDigestKeyId: string | null },
): void {
  if (
    existing.requestDigestScheme !== metadata.requestDigestScheme ||
    existing.requestDigestKeyId !== metadata.requestDigestKeyId
  )
    throw digestKeyChanged();
}

type HostKeyEvidence = {
  connectionEpoch: number;
  journalKeyVersion: number | null;
  journalKeyId: string | null;
  journalKeyAcknowledgedEpoch: number | null;
};
export function hostJournalKeyAcknowledged(host: HostKeyEvidence): boolean {
  return (
    host.connectionEpoch > 0 &&
    host.journalKeyVersion === 1 &&
    host.journalKeyId === requestDigestMetadata().requestDigestKeyId &&
    host.journalKeyAcknowledgedEpoch === host.connectionEpoch
  );
}

/**
 * How long after a hello a missing journal-key ACK reads as "still arriving".
 * The server sends `journal.key.install` right after `hello.ok`, and the daemon
 * ACKs it within one round trip; a binding mismatch (non-canonical origin) is
 * silent, so past this window the refusal is the permanent
 * `digest_key_unavailable`.
 */
export const JOURNAL_KEY_ACK_GRACE_MS = 30_000;

/**
 * Caller owns H; never reserve, mutate S, or enqueue env before this check.
 * Env-bearing work is never queued without the current connection's key ACK
 * (the daemon journals its digests under that key). Inside the post-hello
 * grace the refusal is the transient 503 `sandbox.host_reconnecting`, which
 * clients retry under the same idempotency key; it is still a refusal before
 * any receipt, reservation or outbox row.
 */
export async function requireHostJournalKeyAck(
  tx: Prisma.TransactionClient,
  hostId: string | null,
  ownerId: string,
) {
  const host = hostId
    ? await tx.sandboxHost.findFirst({
        where: { id: hostId, userId: ownerId },
        select: {
          status: true,
          connectionEpoch: true,
          journalKeyVersion: true,
          journalKeyId: true,
          journalKeyAcknowledgedEpoch: true,
          lastConnectedAt: true,
        },
      })
    : null;
  if (host?.status !== "CONNECTED") throw hostUnavailable();
  if (host.journalKeyId && host.journalKeyId !== requestDigestMetadata().requestDigestKeyId)
    throw digestKeyChanged();
  if (hostJournalKeyAcknowledged(host)) return;
  if (host.lastConnectedAt) {
    // The database clock wrote lastConnectedAt in the same hello transaction
    // that advanced the epoch; compare on that clock, never the process's.
    const [row] = await tx.$queryRaw<
      { now: Date }[]
    >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    if (row && row.now.getTime() - host.lastConnectedAt.getTime() < JOURNAL_KEY_ACK_GRACE_MS)
      throw hostReconnecting();
  }
  throw digestKeyUnavailable();
}

/** Receipt fences compare key identity before touching an env-covering digest. */
export function requestDigestKeyCurrent(
  record: Pick<SandboxOperation, "requestDigestScheme" | "requestDigestKeyId">,
): boolean {
  if (record.requestDigestScheme === "sha256-env-free-v1")
    return record.requestDigestKeyId === null;
  return (
    record.requestDigestScheme === "hmac-sha256-v1" &&
    record.requestDigestKeyId === requestDigestMetadata().requestDigestKeyId
  );
}
