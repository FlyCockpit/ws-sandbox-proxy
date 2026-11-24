import prisma, { type Prisma } from "@wssp/db";
import {
  CREDENTIAL_INSTALLED_RESULT_KEY,
  credentialInstalledReceiptV11Schema,
} from "@wssp/sandbox-contracts";
import { lockHostByEpoch, RelayFenceRejected } from "../sandbox/relay-fence";
import { consumeCredentialBundle } from "./budgets";
import { lockLeaseSandbox } from "./leases";
import {
  definitionResiduePaths,
  markCredentialFilesEver,
  recordCredentialPathHistory,
} from "./specs";
import { readVaultKeys } from "./vault/keys";
import { type GrantBundle, openGrantBundle } from "./vault/store";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Bundle grant fence, both request variants, in
 * the grant lock order H → S → credential FOR SHARE → instance FOR SHARE →
 * lease → binding → residue. A refusal carries a non-secret code for
 * `credential.bundle.refused`; a grant returns plaintext the caller streams
 * and then zeroes.
 */

type Tx = Prisma.TransactionClient;

const TERMINAL_OPERATION_STATES = ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"];
const UNCLEARED_RESIDUE_MAX = 16;
/** Refused re-request audit rows kept per lease; later refusals only refuse. */
const REDELIVERY_REFUSAL_AUDIT_MAX = 16;
/** Availability refusals (budget, vault) decide nothing about authority. */
const UNAUDITED_REFUSALS: readonly GrantRefusalCode[] = ["busy", "unavailable"];

type GrantRefusalCode =
  | "busy"
  | "unavailable"
  | "not_authorized"
  | "stale"
  | "needs_login"
  | "residue_pending"
  | "residue_limit";

export type GrantResult =
  | { kind: "refused"; code: GrantRefusalCode }
  | ({ kind: "granted"; bindingId: string; storageSeq: number } & GrantBundle);

class GrantRefused extends Error {
  constructor(readonly code: GrantRefusalCode) {
    super(code);
  }
}
const refuse = (code: GrantRefusalCode): never => {
  throw new GrantRefused(code);
};

export type InstallGrantRequest = {
  hostId: string;
  connectionEpoch: number;
  requestId: string;
  sandboxId: string;
  leaseId: string;
  operationId: string;
};

export type RestoreGrantRequest = {
  hostId: string;
  connectionEpoch: number;
  requestId: string;
  sandboxId: string;
  leaseId: string;
  bindingId: string;
  reason: "restore_env" | "proxy";
};

async function runGrant(hostId: string, work: (tx: Tx) => Promise<GrantResult>) {
  if (!readVaultKeys()) return { kind: "refused", code: "unavailable" } as const;
  try {
    await consumeCredentialBundle(hostId);
  } catch {
    return { kind: "refused", code: "busy" } as const;
  }
  try {
    return await prisma.$transaction(work);
  } catch (error) {
    if (error instanceof GrantRefused) return { kind: "refused", code: error.code } as const;
    if (error instanceof RelayFenceRejected) return { kind: "refused", code: "stale" } as const;
    throw error;
  }
}

async function readSandbox(tx: Tx, sandboxId: string) {
  await lockLeaseSandbox(tx, sandboxId);
  return tx.sandbox.findUnique({
    where: { id: sandboxId },
    select: { id: true, userId: true, state: true, generation: true, sandboxHostId: true },
  });
}

async function lockInstanceShare(tx: Tx, credentialId: string, instanceId: string) {
  await tx.$queryRaw`SELECT id FROM credential WHERE id = ${credentialId} AND "deletedAt" IS NULL FOR SHARE`;
  const rows = await tx.$queryRaw<{ currentSeq: number | null }[]>`SELECT "currentSeq"
    FROM credential_instance WHERE id = ${instanceId} FOR SHARE`;
  return rows[0] ?? null;
}

async function lockLease(tx: Tx, leaseId: string) {
  await tx.$queryRaw`SELECT id FROM credential_lease WHERE id = ${leaseId} FOR UPDATE`;
  return tx.credentialLease.findUnique({
    where: { id: leaseId },
    select: {
      id: true,
      userId: true,
      credentialId: true,
      instanceId: true,
      sandboxId: true,
      hostId: true,
      operationId: true,
      state: true,
      currentBindingId: true,
    },
  });
}

/**
 * Residue gate (§7.4.1 step 4, N2/R2-1): every uncleared residue row of the
 * sandbox must belong to an OPEN binding of a non-terminal lease on this
 * sandbox. Residue of a closed binding must be verified scrubbed first.
 */
async function residueGate(tx: Tx, sandboxId: string, addsResidue: boolean) {
  const rows = await tx.$queryRaw<{ pending: number; uncleared: number }[]>`SELECT
      count(*) FILTER (WHERE NOT (b."closedAt" IS NULL AND l."sandboxId" = r."sandboxId"
        AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')))::int AS pending,
      count(*)::int AS uncleared
    FROM credential_residue r
    LEFT JOIN credential_binding b ON b.id = r."bindingId"
    LEFT JOIN credential_lease l ON l.id = r."leaseId"
    WHERE r."sandboxId" = ${sandboxId} AND r."clearedAt" IS NULL`;
  const { pending = 0, uncleared = 0 } = rows[0] ?? {};
  if (pending > 0) refuse("residue_pending");
  if (addsResidue && uncleared >= UNCLEARED_RESIDUE_MAX) refuse("residue_limit");
}

/**
 * A RECOVERING lease may install only after its recovery capture resolved
 * (§7.1): COMMITTED, UNCHANGED or any authorized DISCARDED (incomplete,
 * copy_back_disabled, superseded — the vault already holds the value to
 * inject). REJECTED never resolves a recovery.
 */
async function recoveryResolved(tx: Tx, leaseId: string): Promise<{ bindingId: string } | null> {
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT b.id FROM credential_binding b
    WHERE b."leaseId" = ${leaseId} AND b.purpose::text = 'RECOVER' AND b."closedAt" IS NULL
      AND EXISTS (SELECT 1 FROM credential_capture c WHERE c."bindingId" = b.id
        AND c.outcome::text IN ('COMMITTED', 'UNCHANGED', 'DISCARDED'))
    LIMIT 1`;
  return rows[0] ? { bindingId: rows[0].id } : null;
}

/**
 * Install variant (`reason: install`): the requesting operation must be the
 * lease's (or the reconnect that moved it to RECOVERING), non-terminal at the
 * sandbox's CURRENT generation, so a superseded create/attach/reconnect never
 * fetches a value. Creates the INSTALL binding (and residue for files), sets
 * the lease write baseline, and is idempotent per `(leaseId, requestId)`.
 *
 * Re-request (the daemon re-sends a request lost with its socket, same
 * `requestId`): the same bundle is re-opened from the vault at the binding's
 * `baseSeq` only for the binding's own host on its current relay epoch, for
 * the binding's own launch (same operation, still non-terminal, same
 * sandbox generation) while the lease is still INSTALLING on that binding —
 * never after `credential.installed`, a cancel, failure, expiry or destroy.
 * Every re-request outcome is audited (metadata only).
 */
export async function grantInstallBundle(request: InstallGrantRequest): Promise<GrantResult> {
  const result = await grantInstall(request);
  if (result.kind === "refused") await auditRefusedRedelivery(request, result.code);
  return result;
}

/**
 * A refused request whose `(leaseId, requestId)` already names a binding is
 * a refused re-request: audited on the lease owner's login in its own
 * transaction (the grant's rolled back). A request naming unknown ids is a
 * plain refusal, so a stranger cannot write events; availability refusals
 * (`busy`, `unavailable`) are not audited, and at most
 * {@link REDELIVERY_REFUSAL_AUDIT_MAX} rows are kept per lease, so a host
 * replaying a closed binding cannot grow the table. Another host is
 * recorded as `other_host` without its id (it may be another owner's).
 */
async function auditRefusedRedelivery(request: InstallGrantRequest, code: GrantRefusalCode) {
  if (UNAUDITED_REFUSALS.includes(code)) return;
  const binding = await prisma.credentialBinding.findUnique({
    where: { leaseId_requestId: { leaseId: request.leaseId, requestId: request.requestId } },
    select: {
      leaseId: true,
      instanceId: true,
      sandboxId: true,
      hostId: true,
      Lease: { select: { userId: true, credentialId: true } },
    },
  });
  if (!binding) return;
  const kept = await prisma.credentialEvent.count({
    where: {
      userId: binding.Lease.userId,
      credentialId: binding.Lease.credentialId,
      leaseId: binding.leaseId,
      type: "bundle_redelivery_refused",
    },
  });
  if (kept >= REDELIVERY_REFUSAL_AUDIT_MAX) return;
  const sameHost = binding.hostId === request.hostId;
  await prisma.credentialEvent.create({
    data: {
      userId: binding.Lease.userId,
      credentialId: binding.Lease.credentialId,
      instanceId: binding.instanceId,
      leaseId: binding.leaseId,
      sandboxId: binding.sandboxId,
      hostId: sameHost ? request.hostId : null,
      type: "bundle_redelivery_refused",
      reason: sameHost ? code : "other_host",
    },
    select: { id: true },
  });
}

function grantInstall(request: InstallGrantRequest): Promise<GrantResult> {
  return runGrant(request.hostId, async (tx) => {
    await lockHostByEpoch(tx, request.hostId, request.connectionEpoch);
    const sandbox = await readSandbox(tx, request.sandboxId);
    if (!sandbox || sandbox.sandboxHostId !== request.hostId) return refuse("not_authorized");
    const peek = await tx.credentialLease.findUnique({
      where: { id: request.leaseId },
      select: { credentialId: true, instanceId: true },
    });
    if (!peek) return refuse("not_authorized");
    const instance = await lockInstanceShare(tx, peek.credentialId, peek.instanceId);
    const lease = await lockLease(tx, request.leaseId);
    if (
      !lease ||
      !instance ||
      lease.sandboxId !== request.sandboxId ||
      lease.hostId !== request.hostId ||
      lease.userId !== sandbox.userId
    )
      return refuse("not_authorized");
    const login = await loadVerifiedLogin(tx, lease.credentialId);
    if (!login) return refuse("unavailable");

    // A request lost with its socket is re-sent with the same requestId:
    // same binding, same launch, same host, still installing.
    const existing = await tx.credentialBinding.findUnique({
      where: { leaseId_requestId: { leaseId: lease.id, requestId: request.requestId } },
      select: {
        id: true,
        hostId: true,
        baseSeq: true,
        closedAt: true,
        operationId: true,
        grantGeneration: true,
      },
    });
    if (existing) {
      const launch = existing.operationId
        ? await tx.sandboxOperation.findUnique({
            where: { id: existing.operationId },
            select: { sandboxId: true, state: true, generation: true },
          })
        : null;
      if (
        existing.closedAt ||
        existing.hostId !== request.hostId ||
        existing.operationId !== request.operationId ||
        existing.grantGeneration !== sandbox.generation ||
        !launch ||
        launch.sandboxId !== sandbox.id ||
        TERMINAL_OPERATION_STATES.includes(launch.state) ||
        launch.generation !== sandbox.generation ||
        lease.state !== "INSTALLING" ||
        lease.currentBindingId !== existing.id ||
        existing.baseSeq === null
      )
        return refuse("stale");
      // Before the plaintext exists: a failed insert never strands a bundle.
      await tx.credentialEvent.create({
        data: {
          userId: lease.userId,
          credentialId: lease.credentialId,
          instanceId: lease.instanceId,
          leaseId: lease.id,
          sandboxId: sandbox.id,
          hostId: request.hostId,
          storageSeq: existing.baseSeq,
          type: "bundle_redelivered",
        },
        select: { id: true },
      });
      const bundle = await openGrantBundle(tx, login, lease.instanceId, existing.baseSeq, {
        envOnly: false,
      });
      if (!bundle) return refuse("stale");
      return { kind: "granted", bindingId: existing.id, storageSeq: existing.baseSeq, ...bundle };
    }

    const operation = await tx.sandboxOperation.findUnique({
      where: { id: request.operationId },
      select: { id: true, sandboxId: true, state: true, generation: true },
    });
    if (
      !operation ||
      operation.sandboxId !== sandbox.id ||
      TERMINAL_OPERATION_STATES.includes(operation.state) ||
      operation.generation !== sandbox.generation
    )
      return refuse("stale");
    let recoverBindingId: string | null = null;
    if (lease.state === "RESERVED") {
      if (lease.operationId !== operation.id) return refuse("stale");
    } else if (lease.state === "RECOVERING") {
      const resolved = await recoveryResolved(tx, lease.id);
      if (!resolved) return refuse("residue_pending");
      const recover = await tx.credentialBinding.findUniqueOrThrow({
        where: { id: resolved.bindingId },
        select: { operationId: true },
      });
      if (recover.operationId !== operation.id && lease.operationId !== operation.id)
        return refuse("stale");
      recoverBindingId = resolved.bindingId;
    } else return refuse("stale");

    if (instance.currentSeq === null) return refuse("needs_login");
    const paths = definitionResiduePaths(login.definition);
    await residueGate(tx, sandbox.id, paths.length > 0);

    if (recoverBindingId)
      await tx.credentialBinding.update({
        where: { id: recoverBindingId },
        data: { closedAt: new Date(), closeReason: "recovered" },
        select: { id: true },
      });
    const binding = await tx.credentialBinding.create({
      data: {
        leaseId: lease.id,
        instanceId: lease.instanceId,
        sandboxId: sandbox.id,
        hostId: request.hostId,
        grantGeneration: sandbox.generation,
        operationId: operation.id,
        requestId: request.requestId,
        baseSeq: instance.currentSeq,
        purpose: "INSTALL",
      },
      select: { id: true },
    });
    if (paths.length > 0)
      await tx.credentialResidue.create({
        data: {
          sandboxId: sandbox.id,
          userId: lease.userId,
          credentialId: lease.credentialId,
          instanceId: lease.instanceId,
          leaseId: lease.id,
          bindingId: binding.id,
          grantGeneration: sandbox.generation,
          paths,
          recoverable: true,
        },
        select: { id: true },
      });
    // §7.6: a template capture scrubs every path this sandbox ever held.
    await recordCredentialPathHistory(tx, sandbox.id, paths);
    // Offload §4: login history → own-host-only resume.
    await markCredentialFilesEver(tx, sandbox.id);
    await tx.credentialLease.update({
      where: { id: lease.id },
      data: { state: "INSTALLING", baseSeq: instance.currentSeq, currentBindingId: binding.id },
      select: { id: true },
    });
    const bundle = await openGrantBundle(tx, login, lease.instanceId, instance.currentSeq, {
      envOnly: false,
    });
    if (!bundle) return refuse("needs_login");
    return { kind: "granted", bindingId: binding.id, storageSeq: instance.currentSeq, ...bundle };
  });
}

/**
 * Restore variant (`restore_env` | `proxy`, daemon restart): the host's
 * current epoch, an ACTIVE lease whose open current binding is on this host,
 * a READY sandbox under this host's authority. No binding, no residue, no
 * operation; env (and proxy values) only — `fileCount = 0`, files are never
 * restored here. The instance's current value is sent (a shareable upload
 * reaches restores).
 */
export function grantRestoreBundle(request: RestoreGrantRequest): Promise<GrantResult> {
  return runGrant(request.hostId, async (tx) => {
    await lockHostByEpoch(tx, request.hostId, request.connectionEpoch);
    const sandbox = await readSandbox(tx, request.sandboxId);
    if (!sandbox || sandbox.sandboxHostId !== request.hostId) return refuse("not_authorized");
    if (sandbox.state !== "READY") return refuse("stale");
    const peek = await tx.credentialLease.findUnique({
      where: { id: request.leaseId },
      select: { credentialId: true, instanceId: true },
    });
    if (!peek) return refuse("not_authorized");
    const instance = await lockInstanceShare(tx, peek.credentialId, peek.instanceId);
    const lease = await lockLease(tx, request.leaseId);
    if (
      !lease ||
      !instance ||
      lease.sandboxId !== sandbox.id ||
      lease.hostId !== request.hostId ||
      lease.userId !== sandbox.userId
    )
      return refuse("not_authorized");
    if (lease.state !== "ACTIVE" || lease.currentBindingId !== request.bindingId)
      return refuse("stale");
    const binding = await tx.credentialBinding.findUnique({
      where: { id: request.bindingId },
      select: { hostId: true, closedAt: true, leaseId: true },
    });
    if (
      !binding ||
      binding.closedAt ||
      binding.hostId !== request.hostId ||
      binding.leaseId !== lease.id
    )
      return refuse("stale");
    const login = await loadVerifiedLogin(tx, lease.credentialId);
    if (!login) return refuse("unavailable");
    if ((request.reason === "proxy") !== (login.delivery === "PROXY"))
      return refuse("not_authorized");
    if (instance.currentSeq === null) return refuse("needs_login");
    const bundle = await openGrantBundle(tx, login, lease.instanceId, instance.currentSeq, {
      envOnly: true,
    });
    if (!bundle) return refuse("needs_login");
    return {
      kind: "granted",
      bindingId: request.bindingId,
      storageSeq: instance.currentSeq,
      ...bundle,
    };
  });
}

/**
 * `credential.installed`: INSTALLING → ACTIVE when the report matches the
 * lease's current open binding and the granted storage sequence.
 */
export async function recordInstalled(input: {
  hostId: string;
  connectionEpoch: number;
  leaseId: string;
  bindingId: string;
  storageSeq: number;
}): Promise<boolean> {
  try {
    return await prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, input.hostId, input.connectionEpoch);
      const peek = await tx.credentialLease.findUnique({
        where: { id: input.leaseId },
        select: { sandboxId: true },
      });
      if (!peek?.sandboxId) return false;
      await lockLeaseSandbox(tx, peek.sandboxId);
      return markInstalled(tx, { ...input, sandboxId: peek.sandboxId });
    });
  } catch (error) {
    if (error instanceof RelayFenceRejected) return false;
    throw error;
  }
}

/** INSTALLING → ACTIVE for one matching report; the caller holds H and S. */
async function markInstalled(
  tx: Tx,
  input: {
    hostId: string;
    sandboxId: string;
    leaseId: string;
    bindingId: string;
    storageSeq: number;
  },
): Promise<boolean> {
  const updated = await tx.$executeRaw`UPDATE credential_lease l SET state = 'ACTIVE',
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    FROM credential_binding b
    WHERE l.id = ${input.leaseId} AND l.state::text = 'INSTALLING' AND l."hostId" = ${input.hostId}
      AND l."sandboxId" = ${input.sandboxId}
      AND l."currentBindingId" = ${input.bindingId} AND b.id = l."currentBindingId"
      AND b."closedAt" IS NULL AND b."hostId" = ${input.hostId} AND b."baseSeq" = ${input.storageSeq}`;
  return updated === 1;
}

/**
 * The install receipt of a create / reconnect READY or an attach result
 * (`result.credentialInstalled`): each report applies exactly as its
 * `credential.installed` frame would, inside the result transaction (host
 * epoch and sandbox already locked by its fence), before the READY gate. A
 * replayed result whose frames were lost with their socket thus finds its
 * leases ACTIVE. A malformed receipt applies nothing (the gate decides).
 */
export async function applyInstalledReceipt(
  tx: Tx,
  input: { hostId: string; sandboxId: string; result: Record<string, unknown> | undefined },
): Promise<number> {
  const raw = input.result?.[CREDENTIAL_INSTALLED_RESULT_KEY];
  if (raw === undefined) return 0;
  const parsed = credentialInstalledReceiptV11Schema.safeParse(raw);
  if (!parsed.success || parsed.data.length === 0) return 0;
  await lockLeaseSandbox(tx, input.sandboxId);
  let applied = 0;
  for (const report of [...parsed.data].sort((a, b) => a.leaseId.localeCompare(b.leaseId)))
    if (
      await markInstalled(tx, {
        hostId: input.hostId,
        sandboxId: input.sandboxId,
        leaseId: report.leaseId,
        bindingId: report.bindingId,
        storageSeq: report.storageSeq,
      })
    )
      applied += 1;
  return applied;
}

/**
 * `credential.scrubbed{verifiedAbsent:true}`: clears the residue of the named
 * bindings on a sandbox under this host's authority (§7.6). Anything else
 * clears nothing.
 */
export async function recordScrubbed(input: {
  hostId: string;
  connectionEpoch: number;
  sandboxId: string;
  bindingIds: readonly string[];
  verifiedAbsent: boolean;
}): Promise<number> {
  if (!input.verifiedAbsent || input.bindingIds.length === 0) return 0;
  try {
    return await prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, input.hostId, input.connectionEpoch);
      const sandbox = await readSandbox(tx, input.sandboxId);
      if (!sandbox || sandbox.sandboxHostId !== input.hostId) return 0;
      return clearResidue(tx, sandbox.id, input.bindingIds);
    });
  } catch (error) {
    if (error instanceof RelayFenceRejected) return 0;
    throw error;
  }
}

async function clearResidue(tx: Tx, sandboxId: string, bindingIds: readonly string[]) {
  const result = await tx.credentialResidue.updateMany({
    where: { sandboxId, bindingId: { in: [...bindingIds] }, clearedAt: null },
    data: { clearedAt: new Date(), clearReason: "scrubbed" },
  });
  return result.count;
}
