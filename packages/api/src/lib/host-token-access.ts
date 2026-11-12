import { isUserBanned } from "@wssp/auth/ban";
import prisma, { type Prisma } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
  type ParsedDeviceCredential,
  type ParsedHostTokenCredential,
  parseDeviceCredentialSecret,
  parseHostTokenCredential,
  verifyProductCredentialDigest,
} from "@wssp/db/credential-security";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "./owner-credential-policy";
import { getForcedTwoFactorSettingsRecord } from "./two-factor-policy";
export type SandboxHostWebsocketIdentity = {
  hostId: string;
  userId: string;
  tokenId: string;
  credentialKind: "hostToken" | "deviceCredential";
  expiresAt: Date | null;
};

/**
 * The host a listed credential authenticates, with just enough connection
 * state for the credentials page to show whether revoking it drops a live
 * connection. Never a credential field.
 */
export const credentialHostSummarySelect = {
  id: true,
  slug: true,
  label: true,
  status: true,
  lastConnectedAt: true,
  lastHeartbeatAt: true,
  deletionRequestedAt: true,
} satisfies Prisma.SandboxHostSelect;

/** Browser list/mint/revoke projection: no `secretDigest`, no `userId`. */
export const hostTokenListSelect = {
  id: true,
  name: true,
  lookupPrefix: true,
  sandboxHostId: true,
  lastUsedAt: true,
  revokedAt: true,
  expiresAt: true,
  createdAt: true,
  SandboxHost: { select: credentialHostSummarySelect },
} satisfies Prisma.HostTokenSelect;

/** Browser list/revoke projection of `wssp login` device credentials: no `secretDigest`. */
export const hostDeviceCredentialListSelect = {
  id: true,
  lookupPrefix: true,
  sandboxHostId: true,
  lastUsedAt: true,
  revokedAt: true,
  createdAt: true,
  SandboxHost: { select: credentialHostSummarySelect },
} satisfies Prisma.HostDeviceCredentialSelect;

const hostTokenCredentialSelect = {
  id: true,
  userId: true,
  sandboxHostId: true,
  lookupPrefix: true,
  secretDigest: true,
  User: { select: ownerCredentialPolicyUserSelect },
  SandboxHost: { select: { userId: true, deletionRequestedAt: true } },
  revokedAt: true,
  expiresAt: true,
} satisfies Prisma.HostTokenSelect;

const hostDeviceCredentialSelect = {
  id: true,
  userId: true,
  sandboxHostId: true,
  lookupPrefix: true,
  secretDigest: true,
  User: { select: ownerCredentialPolicyUserSelect },
  SandboxHost: { select: { userId: true, deletionRequestedAt: true } },
  revokedAt: true,
} satisfies Prisma.HostDeviceCredentialSelect;

/**
 * The ONLY fields read before the full secret verifies: one row, no relation,
 * the same query whether or not the prefix exists. Authority data (owner,
 * host, revocation) is loaded only after verification.
 */
const credentialVerificationSelect = {
  id: true,
  secretDigest: true,
} as const satisfies Prisma.HostTokenSelect & Prisma.HostDeviceCredentialSelect;

type HostTokenRow = Prisma.HostTokenGetPayload<{ select: typeof hostTokenCredentialSelect }>;
type HostDeviceCredentialRow = Prisma.HostDeviceCredentialGetPayload<{
  select: typeof hostDeviceCredentialSelect;
}>;

export function hostTokenLookupPrefix(credential: ParsedHostTokenCredential): string {
  return credentialLookupPrefix(credential);
}

export function digestHostTokenSecret(credential: ParsedHostTokenCredential): string {
  return hmacDigestForProductPurpose({ purpose: "hostToken", value: credential.raw });
}

export function generateHostTokenSecret(): ParsedHostTokenCredential {
  return generateProductCredentialSecret("hostToken");
}

function isExpired(expiresAt: Date | null | undefined, now: Date): boolean {
  return Boolean(expiresAt && expiresAt <= now);
}

/**
 * An explicit, definitive verdict about THIS enrolled credential: it was
 * revoked, or its owner is banned or being deleted. A node daemon stops every
 * VM it runs on such a verdict (it can no longer receive stops). Only ever
 * produced after the full secret verified against the stored digest, so it
 * discloses nothing to a caller who does not hold the credential. Every other
 * refusal (unknown, malformed, wrong secret, expired, policy) stays ambiguous.
 */
export type HostCredentialRefusal = "credential_revoked" | "owner_unavailable";
export type HostWebsocketAuthentication =
  | { identity: SandboxHostWebsocketIdentity }
  | { refusal: HostCredentialRefusal }
  | null;

export async function authenticateSandboxHostWebsocketSecret(
  rawSecret: string,
  now = new Date(),
): Promise<SandboxHostWebsocketIdentity | null> {
  const result = await authenticateSandboxHostWebsocket(rawSecret, now);
  return result && "identity" in result ? result.identity : null;
}

export async function authenticateSandboxHostWebsocket(
  rawSecret: string,
  now = new Date(),
): Promise<HostWebsocketAuthentication> {
  const hostToken = parseHostTokenCredential(rawSecret);
  if (hostToken) {
    return authenticateHostTokenCredential(hostToken, now);
  }
  const deviceCredential = parseDeviceCredentialSecret(rawSecret);
  if (deviceCredential) {
    return authenticateHostDeviceCredential(deviceCredential, now);
  }
  return null;
}

/** Definitive refusal of a VERIFIED credential row, or null when not definitive. */
function definitiveRefusal(
  row: {
    revokedAt: Date | null;
    User: {
      banned?: boolean | null;
      banExpires?: Date | string | null;
      deletionRequestedAt?: Date | null;
    };
  },
  now: Date,
): HostCredentialRefusal | null {
  if (row.revokedAt) return "credential_revoked";
  if (row.User.deletionRequestedAt || isUserBanned(row.User, now)) return "owner_unavailable";
  return null;
}

/**
 * Shape of a stored digest (base64url HMAC-SHA256) that no secret produces in
 * practice. An unknown lookup prefix still runs the full HMAC and
 * constant-time comparison against it, so response timing does not reveal
 * whether a prefix exists. The result is discarded: unknown stays `null`.
 */
const UNKNOWN_PREFIX_DIGEST = "A".repeat(43);

function verifyAgainstUnknownPrefix(
  purpose: "hostToken" | "deviceCredential",
  value: string,
): void {
  verifyProductCredentialDigest({ purpose, value, digest: UNKNOWN_PREFIX_DIGEST });
}

async function authenticateHostTokenCredential(
  credential: ParsedHostTokenCredential,
  now: Date,
): Promise<HostWebsocketAuthentication> {
  const startedAt = Date.now();
  const lookupPrefix = hostTokenLookupPrefix(credential);
  const candidate = await prisma.hostToken.findUnique({
    where: { lookupPrefix },
    select: credentialVerificationSelect,
  });
  if (!candidate) {
    verifyAgainstUnknownPrefix("hostToken", credential.raw);
    return null;
  }
  // The full secret verifies FIRST: nothing below is observable without it.
  if (
    !verifyProductCredentialDigest({
      purpose: "hostToken",
      value: credential.raw,
      digest: candidate.secretDigest,
    })
  ) {
    return null;
  }
  const token: HostTokenRow | null = await prisma.hostToken.findUnique({
    where: { id: candidate.id },
    select: hostTokenCredentialSelect,
  });
  // Deleted between the two reads, or (impossibly) re-keyed: refuse.
  if (!token || token.secretDigest !== candidate.secretDigest) return null;
  const refusal = definitiveRefusal(token, now);
  if (refusal) return { refusal };
  if (isExpired(token.expiresAt, now)) return null;
  if (!token.sandboxHostId || !token.SandboxHost || token.SandboxHost.userId !== token.userId)
    return null;
  const current = authorityTicket({
    ownerId: token.userId,
    hostId: token.sandboxHostId,
    credentialId: token.id,
  });
  if (!(await isOwnerCredentialPolicySatisfied(token.User, now))) return null;

  await prisma.hostToken.update({
    where: { id: token.id },
    data: { lastUsedAt: now },
    select: { id: true },
  });

  const identity: SandboxHostWebsocketIdentity = {
    credentialKind: "hostToken",
    expiresAt: token.expiresAt,
    hostId: token.sandboxHostId,
    userId: token.userId,
    tokenId: token.id,
  };
  // Durable read AFTER the scoped ticket: a revoke/ban that committed between the
  // lookup and the ticket sample is observed here; one racing it fails the ticket.
  const verdict = await hostIdentityVerdict(identity, now);
  if (verdict === "credential_revoked" || verdict === "owner_unavailable")
    return { refusal: verdict };
  if (verdict !== "active" || !current()) return null;
  if (isExpired(token.expiresAt, new Date(now.getTime() + Date.now() - startedAt))) return null;
  return { identity };
}

async function authenticateHostDeviceCredential(
  credential: ParsedDeviceCredential,
  now: Date,
): Promise<HostWebsocketAuthentication> {
  const lookupPrefix = credentialLookupPrefix(credential);
  const candidate = await prisma.hostDeviceCredential.findUnique({
    where: { lookupPrefix },
    select: credentialVerificationSelect,
  });
  if (!candidate) {
    verifyAgainstUnknownPrefix("deviceCredential", credential.raw);
    return null;
  }
  // The full secret verifies FIRST: nothing below is observable without it.
  if (
    !verifyProductCredentialDigest({
      purpose: "deviceCredential",
      value: credential.raw,
      digest: candidate.secretDigest,
    })
  ) {
    return null;
  }
  const row: HostDeviceCredentialRow | null = await prisma.hostDeviceCredential.findUnique({
    where: { id: candidate.id },
    select: hostDeviceCredentialSelect,
  });
  if (!row || row.secretDigest !== candidate.secretDigest) return null;
  const refusal = definitiveRefusal(row, now);
  if (refusal) return { refusal };
  if (!row.SandboxHost || row.SandboxHost.userId !== row.userId) return null;
  const current = authorityTicket({
    ownerId: row.userId,
    hostId: row.sandboxHostId,
    credentialId: row.id,
  });
  if (!(await isOwnerCredentialPolicySatisfied(row.User, now))) return null;

  await prisma.hostDeviceCredential.update({
    where: { id: row.id },
    data: { lastUsedAt: now },
    select: { id: true },
  });

  const identity: SandboxHostWebsocketIdentity = {
    credentialKind: "deviceCredential",
    expiresAt: null,
    hostId: row.sandboxHostId,
    userId: row.userId,
    tokenId: row.id,
  };
  const verdict = await hostIdentityVerdict(identity, now);
  if (verdict === "credential_revoked" || verdict === "owner_unavailable")
    return { refusal: verdict };
  if (verdict !== "active" || !current()) return null;
  return { identity };
}

/** `stale`: an authority change overlapped the read. Not definitive: the change's
 * committed notification triggers another revalidation, so callers must neither
 * close nor treat the credential as active on `stale`. */
export type HostIdentityRevalidation =
  | { status: "active"; hostDeletionRequested: boolean }
  | { status: "inactive"; reason?: HostCredentialRefusal }
  | { status: "stale"; hostDeletionRequested: boolean }
  | { status: "error" };

/** Durable, definitive state only. Throws on infrastructure errors. */
export async function readHostIdentityStatus(
  identity: SandboxHostWebsocketIdentity,
  now: Date,
  client: Prisma.TransactionClient = prisma,
): Promise<"active" | "inactive"> {
  return (await hostIdentityVerdict(identity, now, client)) === "active" ? "active" : "inactive";
}

/** Like readHostIdentityStatus, naming the explicit revocation verdicts. */
export async function hostIdentityVerdict(
  identity: SandboxHostWebsocketIdentity,
  now: Date,
  client: Prisma.TransactionClient = prisma,
): Promise<"active" | "inactive" | HostCredentialRefusal> {
  return (await readHostIdentityVerdict(identity, now, client)).verdict;
}

/** The verdict plus the host tombstone read from the same credential row
 * (meaningful only when the verdict is `active`). */
async function readHostIdentityVerdict(
  identity: SandboxHostWebsocketIdentity,
  now: Date,
  client: Prisma.TransactionClient,
): Promise<{
  verdict: "active" | "inactive" | HostCredentialRefusal;
  hostDeletionRequested: boolean;
}> {
  const row =
    identity.credentialKind === "hostToken"
      ? await client.hostToken.findUnique({
          where: { id: identity.tokenId },
          select: hostTokenCredentialSelect,
        })
      : await client.hostDeviceCredential.findUnique({
          where: { id: identity.tokenId },
          select: hostDeviceCredentialSelect,
        });
  if (row && row.userId === identity.userId && row.sandboxHostId === identity.hostId) {
    const refusal = definitiveRefusal(row, now);
    if (refusal) return { verdict: refusal, hostDeletionRequested: false };
  }
  if (
    !row ||
    row.revokedAt ||
    row.userId !== identity.userId ||
    row.sandboxHostId !== identity.hostId ||
    !row.SandboxHost ||
    row.SandboxHost.userId !== identity.userId ||
    ("expiresAt" in row && isExpired(row.expiresAt, now))
  )
    return { verdict: "inactive", hostDeletionRequested: false };
  const policySatisfied = await isOwnerCredentialPolicySatisfied(
    row.User,
    now,
    client === prisma ? undefined : await getForcedTwoFactorSettingsRecord(client),
  );
  return {
    verdict: policySatisfied ? "active" : "inactive",
    hostDeletionRequested: row.SandboxHost.deletionRequestedAt !== null,
  };
}

const REVALIDATION_ATTEMPTS = 3;

/** Never authorize from the upgrade snapshot alone. No secret is retained in a session.
 * Only a durable inactive read is `inactive` (4003); infrastructure failure is `error`
 * (1011). A ticket invalidated by an overlapping change retries, then reports `stale`. */
export async function revalidateSandboxHostIdentity(
  identity: SandboxHostWebsocketIdentity,
  now = new Date(),
  client: Prisma.TransactionClient = prisma,
): Promise<HostIdentityRevalidation> {
  let hostDeletionRequested = false;
  try {
    for (let attempt = 0; attempt < REVALIDATION_ATTEMPTS; attempt += 1) {
      const current = authorityTicket({
        ownerId: identity.userId,
        hostId: identity.hostId,
        credentialId: identity.tokenId,
      });
      const read = await readHostIdentityVerdict(identity, now, client);
      const verdict = read.verdict;
      if (verdict === "credential_revoked" || verdict === "owner_unavailable")
        return { status: "inactive", reason: verdict };
      if (verdict === "inactive") return { status: "inactive" };
      hostDeletionRequested = read.hostDeletionRequested;
      if (current()) return { status: "active", hostDeletionRequested };
    }
    return { status: "stale", hostDeletionRequested };
  } catch {
    return { status: "error" };
  }
}
