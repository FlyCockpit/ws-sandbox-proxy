import type { Prisma } from "@wssp/db";
import { pathsOverlap } from "@wssp/login-definition";
import { type CredentialSpecRefV11, ENV_LIMITS } from "@wssp/sandbox-contracts";
import { insufficientScope } from "../lib/sdk-key-access";
import type { Principal } from "../sandbox/contracts";
import { loadExecutionConfig } from "../sandbox/execution-config";
import { grantOf } from "../sandbox/principal-kinds";
import { credentialAccessFilter, requireCredentials } from "./access";
import { credentialError } from "./errors";
import {
  detachAttachment,
  finishLease,
  isTerminalLeaseState,
  lockSettlementScope,
  requireLeaseRecovery,
} from "./leases";
import { credentialPlacementContextFor, requireCredentialHost } from "./placement";
import { type CredentialClaimRequest, lockCredentialForClaim } from "./selection";
import {
  buildSandboxCredentialSpec,
  encodeCredentialSpec,
  markCredentialFilesEver,
  writeOperationSpec,
} from "./specs";
import { type LoadedLogin, loadVerifiedLogin } from "./verified-login";

/**
 * Credential launch path: attachment
 * rows at create, the spec a create / cold reconnect dispatch refers to, the
 * READY gate (every lease ACTIVE) and the settlement of a launch that ended
 * without READY. Every function runs inside the caller's transaction after S.
 */

type Tx = Prisma.TransactionClient;

/**
 * Who may name logins at create (or pin them at a resume). Sessions: any of
 * the owner's logins. SDK keys: only with the `credentials:use` scope, and
 * only logins the key can see (its per-login allowlist, read live in
 * {@link requireUsableLogins} inside the transaction). The feature must be on.
 */
export function requireCreateCredentialsAllowed(
  owner: Principal,
  requests: readonly CredentialClaimRequest[] | undefined,
): void {
  if (!requests || requests.length === 0) return;
  // A session holds every scope; a build holds no `credentials:use`.
  // A missing scope is an authorization refusal like any other (E2-B-03).
  if (!grantOf(owner).has("credentials:use")) throw insufficientScope();
  requireCredentials("write");
}

/**
 * Every named login is the owner's, live and visible to the principal (an
 * allowlist key sees only its allowlisted logins; a hidden login is
 * indistinguishable from a missing one).
 */
export async function requireUsableLogins(
  tx: Tx,
  owner: Principal,
  credentialIds: readonly string[],
): Promise<void> {
  if (credentialIds.length === 0) return;
  const unique = [...new Set(credentialIds)];
  const visible = await tx.credential.count({
    where: { AND: [credentialAccessFilter(owner), { id: { in: unique } }] },
  });
  if (visible !== unique.length) throw credentialError("credential.not_found");
}

/**
 * The claim gate (§7.2, §8): every WORKLOAD claim set — create, queued
 * placement, cold resume and live attach — passes it inside the claiming
 * transaction, after S and before the first claim, naming the COMPLETE
 * effective set: every login the claims will take (`claimIds`), plus the
 * logins already attached that the host must also satisfy (`attachedIds`).
 *
 *  1. the principal may claim: `credentials:use`, the feature writable (not
 *     drain mode) and every claimed login visible to it (allowlist read live);
 *  2. every login of the set is locked FOR SHARE in sorted order (the claim
 *     order, N3). Opt-in, settings, delete and re-pin take it FOR UPDATE, so
 *     the policy read next cannot change before this transaction commits;
 *  3. the placement policy (foreign opt-in, needed capability) is rebuilt
 *     from rows read under those locks and validated against the selected
 *     host's live row (`credential.host_forbidden`);
 *  4. the effective attachment set is disjoint ({@link requireDisjointAttachmentSet}),
 *     read from the definitions pinned under those locks — so a re-pin
 *     committed after an attach is still caught here, before any claim.
 *
 * A placement context computed before the locks (the pool's SQL stages) only
 * narrows candidates; this is the decision. The LOGIN claim of the login
 * sandbox flow (§11, D10) passes it too, with `foreignConsent`: there the
 * session's own consent — never the login's workload opt-in — decides
 * whether a foreign host may hold the login.
 */
export async function authorizeCredentialClaims(
  tx: Tx,
  input: {
    principal: Principal;
    hostId: string;
    /**
     * The workload sandbox whose attachment set is validated. Null only for
     * the login flow, which installs nothing in its login sandbox.
     */
    sandboxId: string | null;
    claimIds: readonly string[];
    attachedIds?: readonly string[];
    /** The login flow: whether this session consented to a foreign host. */
    foreignConsent?: boolean;
  },
): Promise<void> {
  if (input.claimIds.length === 0) return;
  if (!grantOf(input.principal).has("credentials:use")) throw insufficientScope();
  requireCredentials("write");
  await requireUsableLogins(tx, input.principal, input.claimIds);
  const all = [...new Set([...input.claimIds, ...(input.attachedIds ?? [])])].sort();
  for (const credentialId of all)
    await lockCredentialForClaim(tx, input.principal.ownerId, credentialId);
  const host = await tx.sandboxHost.findUniqueOrThrow({
    where: { id: input.hostId },
    select: { userId: true, daemonFeatures: true },
  });
  const context = await credentialPlacementContextFor(tx, all);
  requireCredentialHost(
    input.foreignConsent === undefined
      ? context
      : { ...context, requiresOwn: !input.foreignConsent },
    {
      ownerId: input.principal.ownerId,
      hostOwnerId: host.userId,
      daemonFeatures: host.daemonFeatures,
    },
  );
  if (input.sandboxId !== null)
    await requireDisjointAttachmentSet(tx, {
      ownerId: input.principal.ownerId,
      sandboxId: input.sandboxId,
      credentialIds: all,
    });
}

/**
 * Every env name a login may claim in the guest: entry names, plus a proxied
 * entry's `baseUrlEnv` and `placeholderEnv` (the names the guest actually
 * sees in proxy mode).
 */
function envNames(login: LoadedLogin): string[] {
  const names = new Set<string>();
  for (const entry of login.definition.credentials.env ?? []) {
    names.add(entry.name);
    if (entry.proxy) {
      names.add(entry.proxy.baseUrlEnv);
      if (entry.proxy.placeholderEnv) names.add(entry.proxy.placeholderEnv);
    }
  }
  return [...names];
}

function includedPaths(login: LoadedLogin): string[] {
  const files = login.definition.credentials.files;
  return [...(files?.required ?? []), ...(files?.optional ?? [])];
}

/**
 * §3 / §10.6 set admission: the logins of one sandbox share the guest, so
 * across the COMPLETE effective set no env name is shared with the sandbox's
 * private defaults or another login (`credential.env_conflict`), the env
 * union stays within `env-limits.json` (`reason: "env_limit"`), and no file
 * path overlaps another login's (`credential.path_conflict`). A conflicting
 * set would let one login's restore overwrite another's value and copy it
 * back into the wrong vault instance at teardown.
 *
 * The claim gate runs it for every claim set (create, queued placement,
 * resume, live attach) after the definitions are locked; a STOPPED attach,
 * which claims nothing, runs it for an early refusal.
 */
export async function requireDisjointAttachmentSet(
  tx: Tx,
  input: { ownerId: string; sandboxId: string; credentialIds: readonly string[] },
): Promise<void> {
  const ids = [...new Set(input.credentialIds)].sort();
  if (ids.length === 0) return;
  const config = await loadExecutionConfig(tx, input.sandboxId, input.ownerId);
  const names = new Set((config?.env ?? []).map(([name]) => name));
  const paths: string[] = [];
  for (const credentialId of ids) {
    const login = await loadVerifiedLogin(tx, credentialId);
    if (!login) throw credentialError("credential.definition_corrupt");
    const added = envNames(login);
    if (added.some((name) => names.has(name))) throw credentialError("credential.env_conflict");
    for (const name of added) names.add(name);
    if (names.size > ENV_LIMITS.maxEntries)
      throw credentialError("credential.env_conflict", { reason: "env_limit" });
    const own = includedPaths(login);
    for (const path of own)
      if (paths.some((other) => pathsOverlap(path, other)))
        throw credentialError("credential.path_conflict");
    paths.push(...own);
  }
}

/**
 * Writes one active `SandboxCredential` per requested login. The named
 * account/instance are stored as the one-shot placement hint (N7) and are
 * cleared by the claim that uses them. The login must be the owner's and live.
 * Any proxy-delivery login sets the sandbox's `credentialProxyEnabled`.
 */
export async function writeCreateAttachments(
  tx: Tx,
  input: {
    ownerId: string;
    /** The creating principal: an SDK key may name only logins it can see. */
    principal?: Principal;
    sandboxId: string;
    requests: readonly CredentialClaimRequest[];
  },
): Promise<void> {
  if (input.principal)
    await requireUsableLogins(
      tx,
      input.principal,
      input.requests.map((request) => request.credentialId),
    );
  let proxied = false;
  for (const request of [...input.requests].sort((a, b) =>
    a.credentialId < b.credentialId ? -1 : a.credentialId > b.credentialId ? 1 : 0,
  )) {
    const login = await tx.credential.findFirst({
      where: { id: request.credentialId, userId: input.ownerId, deletedAt: null },
      select: { id: true, delivery: true },
    });
    if (!login) throw credentialError("credential.not_found");
    if (login.delivery === "PROXY") proxied = true;
    await tx.sandboxCredential.create({
      data: {
        sandboxId: input.sandboxId,
        userId: input.ownerId,
        credentialId: request.credentialId,
        requestedAccountId: request.accountId ?? null,
        requestedInstanceId: request.instanceId ?? null,
      },
      select: { id: true },
    });
  }
  // Proxy mode (§9): a sandbox created with a proxy-delivery login is
  // proxy-enabled for its whole life; only such a sandbox may later take a
  // proxy login by live attach. Never cleared.
  if (proxied)
    await tx.sandbox.updateMany({
      where: { id: input.sandboxId, userId: input.ownerId },
      data: { credentialProxyEnabled: true },
    });
  // Offload §4: a create that attaches a login (any delivery) is login
  // history from the start; its grant sets the flag again (idempotent).
  if (input.requests.length > 0) await markCredentialFilesEver(tx, input.sandboxId);
}

/**
 * After the claims and the operation row: when the sandbox has a lease to
 * launch (RESERVED inject or RECOVERING recover) or uncleared residue, build
 * the spec from rows, store it with the operation and return the dispatch
 * reference. Null when the launch carries no credential work.
 */
export async function writeLaunchSpec(
  tx: Tx,
  input: { sandboxId: string; operationId: string },
): Promise<CredentialSpecRefV11 | null> {
  const lease = await tx.credentialLease.findFirst({
    where: {
      sandboxId: input.sandboxId,
      kind: "WORKLOAD",
      state: { in: ["RESERVED", "RECOVERING"] },
    },
    select: { id: true },
  });
  const residue = await tx.credentialResidue.findFirst({
    where: { sandboxId: input.sandboxId, clearedAt: null },
    select: { id: true },
  });
  if (!lease && !residue) return null;
  const spec = await buildSandboxCredentialSpec(tx, input.sandboxId);
  if (spec.leases.length === 0 && spec.residue.length === 0) return null;
  const encoded = encodeCredentialSpec(spec);
  const stored = await writeOperationSpec(tx, input.operationId, encoded.bytes);
  return { digest: stored.digest, bytes: stored.bytes };
}

/**
 * READY gate (§7.1): a create / reconnect may publish READY only when every
 * lease it launched is ACTIVE — none is still RESERVED, INSTALLING or
 * RECOVERING. (A RECOVERY_REQUIRED lease on a running VM after a REJECTED
 * free is not a launch lease and does not block a warm reconnect.)
 */
export async function credentialLaunchReady(tx: Tx, sandboxId: string): Promise<boolean> {
  const pending = await tx.credentialLease.count({
    where: {
      sandboxId,
      state: { in: ["RESERVED", "INSTALLING", "RECOVERING"] },
    },
  });
  return pending === 0;
}

/**
 * Settles the leases a create / cold reconnect launched (§7.1):
 * - success: nothing changes (the READY gate already required ACTIVE);
 * - otherwise RESERVED → ABANDONED (no effect), INSTALLING → RELEASED
 *   {install_failed} (binding closed, residue non-recoverable; the vault is
 *   current, so no value is lost), RECOVERING → RECOVERY_REQUIRED with its
 *   RECOVER binding closed (the original residue stays recoverable).
 * The stored spec is removed either way: the operation is terminal.
 */
export async function settleCredentialLaunch(
  tx: Tx,
  input: { sandboxId: string; operationId: string; succeeded: boolean },
): Promise<void> {
  if (!input.succeeded) {
    // The COMPLETE settlement scope of the sandbox — every non-terminal
    // lease's instance, not only this launch's — in the claim order before
    // any lease lock or decrement: the same transaction may settle the
    // sandbox's other leases next (an expiry's teardown), and that phase must
    // find every instance already held (§7.3, `lockSettlementScope`).
    await lockSettlementScope(tx, { sandboxIds: [input.sandboxId] });
    const leases = await tx.$queryRaw<
      { id: string; state: string }[]
    >`SELECT l.id, l.state::text AS state
      FROM credential_lease l
      WHERE l."sandboxId" = ${input.sandboxId}
        AND l.state::text IN ('RESERVED', 'INSTALLING', 'RECOVERING')
        AND (l."operationId" = ${input.operationId} OR EXISTS (
          SELECT 1 FROM credential_binding b WHERE b.id = l."currentBindingId"
            AND b."operationId" = ${input.operationId}))
      ORDER BY l.id
      FOR UPDATE OF l`;
    for (const lease of leases) {
      if (lease.state === "RESERVED") await finishLease(tx, lease.id, "ABANDONED", "launch_failed");
      else if (lease.state === "INSTALLING")
        await finishLease(tx, lease.id, "RELEASED", "install_failed");
      else await settleFailedRecovery(tx, lease.id);
    }
  }
  await tx.credentialOperationSpec.deleteMany({ where: { operationId: input.operationId } });
}

/**
 * A RECOVERING lease whose launch ended without READY. If its recovery
 * capture already resolved (the disk's value is durable and the residue was
 * scrubbed or is about to be), the install failed after recovery → RELEASED
 * {install_failed}. Otherwise the recovery failed → RECOVERY_REQUIRED: the
 * RECOVER binding closes and the lease points back at the binding whose
 * residue is still on the disk, so the next start recovers it again.
 */
export async function settleFailedRecovery(tx: Tx, leaseId: string): Promise<void> {
  const recover = await tx.$queryRaw<
    { id: string; recoveryOfBindingId: string | null; resolved: boolean }[]
  >`SELECT b.id, b."recoveryOfBindingId", EXISTS (SELECT 1 FROM credential_capture c
        WHERE c."bindingId" = b.id
          AND c.outcome::text IN ('COMMITTED', 'UNCHANGED', 'DISCARDED')) AS resolved
      FROM credential_binding b
      WHERE b."leaseId" = ${leaseId} AND b.purpose::text = 'RECOVER' AND b."closedAt" IS NULL
      ORDER BY b."createdAt" DESC LIMIT 1`;
  const binding = recover[0];
  if (binding?.resolved) {
    await finishLease(tx, leaseId, "RELEASED", "install_failed");
    return;
  }
  if (binding) {
    await tx.$executeRaw`UPDATE credential_binding SET "closedAt" = (clock_timestamp() AT TIME ZONE 'UTC'),
        "closeReason" = 'recovery_failed'
      WHERE id = ${binding.id} AND "closedAt" IS NULL`;
    if (binding.recoveryOfBindingId)
      await tx.credentialLease.update({
        where: { id: leaseId },
        data: { currentBindingId: binding.recoveryOfBindingId },
        select: { id: true },
      });
  }
  await requireLeaseRecovery(tx, leaseId, "recovery_failed");
}

/**
 * Live-attach READY gate (§7.1): the attach's lease must be ACTIVE for the
 * attach to succeed; a host that reports success without installing it is
 * an install failure.
 */
export async function credentialAttachReady(tx: Tx, operationId: string): Promise<boolean> {
  const leases = await tx.credentialLease.findMany({
    where: { operationId },
    select: { state: true },
    take: 8,
  });
  return leases.length > 0 && leases.every((lease) => lease.state === "ACTIVE");
}

/**
 * Settles a live attach's result (§7.1): RESERVED → ABANDONED, INSTALLING →
 * RELEASED{install_failed} unless it succeeded; the stored spec is removed. A
 * FAILED attach whose lease ended ends the attachment too (nothing was
 * attached). A CANCELLED attach was superseded by a stop, which already
 * settled its lease: the attachment stays and the next start claims it.
 * UNKNOWN_OUTCOME changes nothing.
 */
export async function settleCredentialAttachResult(
  tx: Tx,
  input: {
    sandboxId: string;
    operationId: string;
    opState: "SUCCEEDED" | "FAILED" | "CANCELLED" | "UNKNOWN_OUTCOME";
  },
): Promise<void> {
  if (input.opState === "UNKNOWN_OUTCOME") return;
  await settleCredentialLaunch(tx, {
    sandboxId: input.sandboxId,
    operationId: input.operationId,
    succeeded: input.opState === "SUCCEEDED",
  });
  if (input.opState !== "FAILED") return;
  const leases = await tx.credentialLease.findMany({
    where: { operationId: input.operationId, sandboxId: input.sandboxId },
    select: { credentialId: true, state: true },
    take: 8,
  });
  for (const lease of leases)
    if (isTerminalLeaseState(lease.state))
      await detachAttachment(tx, input.sandboxId, lease.credentialId);
}
