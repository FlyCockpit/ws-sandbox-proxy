import type { OperationState, Prisma, SandboxOperationKind, SandboxState } from "@wssp/db";
import {
  CREDENTIAL_INSTALLED_RESULT_KEY,
  CREDENTIAL_TEARDOWN_RESULT_KEY,
  type CredentialTeardownOutcomeV11,
  credentialTeardownOutcomesV11Schema,
} from "@wssp/sandbox-contracts";
import { isReservedInternalIdempotencyKey } from "../sandbox/idempotency-key-reserved";
import {
  settleCredentialAttachResult,
  settleCredentialLaunch,
  settleFailedRecovery,
} from "./launch";
import { detachAttachment, finishLease, lockSettlementScope, requireLeaseRecovery } from "./leases";
import { definitionCapturesFiles } from "./specs";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Teardown settlement. Every helper
 * runs inside the caller's transaction with S (the sandbox row) already held,
 * then locks the logins and instances of ALL the sandbox's non-terminal
 * leases in the claim order (`lockSettlementScope`), then the leases sorted
 * `FOR UPDATE`, and only then decrements instances through `finishLease`.
 * Locking instances in lease order instead deadlocked two sandboxes that
 * share instances (their S locks do not serialize them). Locking the complete
 * set in every helper (and in `settleCredentialLaunch`) makes the FIRST
 * settlement phase of a transaction take everything a later phase needs.
 *
 * Writers (`retireSupersededOperations` callers, `advanceGeneration: true`,
 * raw generation increments and DELETED writes) are enumerated by
 * `teardown-writers.test.ts`; each maps to one of the settlement helpers here.
 */

type Tx = Prisma.TransactionClient;

const TEARDOWN_CAPTURE_KINDS = ["stop", "kill", "free", "expiry"];
const RUNNING_STATES = new Set<SandboxState>([
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "UNREACHABLE",
  "RECOVERED",
  "ERROR",
  "STOPPING",
]);

type LeaseRow = {
  id: string;
  state: string;
  kind: string;
  credentialId: string;
  instanceId: string;
  currentBindingId: string | null;
  teardownOperationId: string | null;
  bindingOpen: boolean;
  /**
   * Exclusive copy-back GUEST workload lease of a definition that declares
   * files: its teardown must capture (`definitionCapturesFiles`).
   */
  captureRequired: boolean;
};

/**
 * Non-terminal leases of S: their logins and instances locked in the claim
 * order first, then the lease rows sorted `FOR UPDATE OF`. Under S no lease
 * of the sandbox appears, and a lease's instance never changes, so the
 * unlocked read names every instance the settlement can decrement.
 */
async function lockSandboxLeases(tx: Tx, sandboxId: string): Promise<LeaseRow[]> {
  await lockSettlementScope(tx, { sandboxIds: [sandboxId] });
  const rows = await tx.$queryRaw<
    LeaseRow[]
  >`SELECT l.id, l.state::text AS state, l.kind::text AS kind,
      l."credentialId", l."instanceId", l."currentBindingId", l."teardownOperationId",
      EXISTS (SELECT 1 FROM credential_binding b
        WHERE b.id = l."currentBindingId" AND b."closedAt" IS NULL) AS "bindingOpen",
      (l.kind::text = 'WORKLOAD' AND l.exclusive AND c."copyBack"
        AND c.delivery::text = 'GUEST') AS "captureRequired"
    FROM credential_lease l JOIN credential c ON c.id = l."credentialId"
    WHERE l."sandboxId" = ${sandboxId}
      AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
    ORDER BY l.id
    FOR UPDATE OF l`;
  // Mocked clients (unit tests of the relay) return nothing: no leases.
  return captureEligibility(tx, rows ?? []);
}

/**
 * The capture requirement the node daemon applies too: an env-only login
 * (no declared file path) is never captured, so its lease settles without
 * one instead of waiting in RELEASING for a capture that cannot come. A
 * login that no longer verifies keeps the requirement (fail closed).
 */
async function captureEligibility(tx: Tx, rows: LeaseRow[]): Promise<LeaseRow[]> {
  const captures = new Map<string, boolean>();
  for (const row of rows) {
    if (!row.captureRequired) continue;
    let declared = captures.get(row.credentialId);
    if (declared === undefined) {
      const login = await loadVerifiedLogin(tx, row.credentialId);
      declared = !login || definitionCapturesFiles(login.definition);
      captures.set(row.credentialId, declared);
    }
    row.captureRequired = declared;
  }
  return rows;
}

/**
 * A launch or attach lease superseded by a new generation (§7.1, §7.5):
 * RESERVED → ABANDONED (no effect); INSTALLING → RELEASED{superseded} (binding
 * closed, residue non-recoverable; the vault is current); RECOVERING → the
 * failed-recovery rule (RECOVERY_REQUIRED unless its recovery resolved).
 * Returns true when the lease was a launch lease.
 */
async function settleSupersededLaunchLease(tx: Tx, lease: LeaseRow): Promise<boolean> {
  if (lease.state === "RESERVED") await finishLease(tx, lease.id, "ABANDONED", "superseded");
  else if (lease.state === "INSTALLING") await finishLease(tx, lease.id, "RELEASED", "superseded");
  else if (lease.state === "RECOVERING") await settleFailedRecovery(tx, lease.id);
  else return false;
  return true;
}

/**
 * A LOGIN lease never outlives its login sandbox's teardown (§10.4: LOGIN
 * leases skip capture; §11 cancel/expiry): → ABANDONED, `loginLeaseId`
 * cleared and the session ended by `finishLease`. A saved login's lease is
 * already RELEASED and never reaches here. Returns true for a LOGIN lease.
 */
async function settleLoginLease(tx: Tx, lease: LeaseRow): Promise<boolean> {
  if (lease.kind !== "LOGIN") return false;
  await finishLease(tx, lease.id, "ABANDONED", "login_ended");
  return true;
}

/** The stored dispatch specs of every superseded (older-generation) operation. */
export async function dropSupersededSpecs(tx: Tx, sandboxId: string, generation: number) {
  await tx.credentialOperationSpec.deleteMany({
    where: { Operation: { sandboxId, generation: { lt: generation } } },
  });
}

async function moveToReleasing(tx: Tx, leaseId: string, teardownOperationId: string | null) {
  await tx.$executeRaw`UPDATE credential_lease SET state = 'RELEASING',
      "teardownOperationId" = ${teardownOperationId}, "endReason" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${leaseId} AND state::text IN ('ACTIVE', 'RELEASING', 'RECOVERY_REQUIRED')`;
}

async function recordLeaseEvent(tx: Tx, leaseId: string, type: string, reason: string) {
  const lease = await tx.credentialLease.findUnique({
    where: { id: leaseId },
    select: {
      userId: true,
      credentialId: true,
      accountId: true,
      instanceId: true,
      sandboxId: true,
      hostId: true,
    },
  });
  if (!lease) return;
  await tx.credentialEvent.create({
    data: { ...lease, leaseId, type, reason },
    select: { id: true },
  });
}

/**
 * RELEASED{capture_lost} (§10.3 system kill, §7.1 DELETED settlement): the
 * previous value is kept; the instance becomes NEEDS_LOGIN{capture_lost} only
 * when a capture was required and the definition's `rotates` is not `no`.
 */
async function markCaptureLost(tx: Tx, lease: LeaseRow, reason = "capture_lost") {
  if (!(await finishLease(tx, lease.id, "RELEASED", reason))) return;
  if (lease.captureRequired) {
    const login = await loadVerifiedLogin(tx, lease.credentialId);
    const needsLogin =
      (!login || login.definition.credentials.rotates !== "no") &&
      (await tx.$executeRaw`UPDATE credential_instance SET state = 'NEEDS_LOGIN',
          "needsLoginReason" = 'capture_lost', "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
        WHERE id = ${lease.instanceId} AND state::text = 'READY'`) > 0;
    if (needsLogin) await recordLeaseEvent(tx, lease.id, "needs_login", "capture_lost");
  }
  await recordLeaseEvent(tx, lease.id, "capture_lost", reason);
}

/**
 * The lease's teardown capture resolved (COMMITTED, UNCHANGED or an
 * authorized DISCARDED ledger row for its current binding). Commits made
 * during a teardown attempt that later failed with `credential_capture_failed`
 * (and re-armed the lease) never count for a later teardown (R3-1).
 */
async function teardownCaptureResolved(
  tx: Tx,
  sandboxId: string,
  lease: LeaseRow,
): Promise<boolean> {
  if (!lease.captureRequired) return true;
  if (!lease.currentBindingId) return false;
  const rows = await tx.$queryRaw<{ resolved: boolean }[]>`SELECT EXISTS (
      SELECT 1 FROM credential_capture c
      WHERE c."leaseId" = ${lease.id} AND c."bindingId" = ${lease.currentBindingId}
        AND c.kind = ANY(${TEARDOWN_CAPTURE_KINDS}::text[])
        AND c.outcome::text IN ('COMMITTED', 'UNCHANGED', 'DISCARDED')
        AND c.at > COALESCE((SELECT max(o."completedAt") FROM sandbox_mutation_operation o
          WHERE o."sandboxId" = ${sandboxId}
            AND o.kind::text IN ('STOP_SANDBOX', 'KILL_SANDBOX')
            AND o.state::text = 'FAILED' AND o."errorCode" = 'credential_capture_failed'),
          '-infinity'::timestamp)) AS resolved`;
  return rows[0]?.resolved === true;
}

async function hasPendingEnvelope(tx: Tx, leaseId: string): Promise<boolean> {
  return (await tx.credentialPendingCapture.count({ where: { leaseId } })) > 0;
}

type CaptureStatus = "resolved" | "pending" | "failed" | "unknown";

/**
 * Classifies one RELEASING lease's teardown capture. The host's receipt is
 * evidence of WHICH capture to look at, never of its outcome: acked outcomes
 * are re-read from the server's own ledger / rejection rows.
 */
async function captureStatus(
  tx: Tx,
  sandboxId: string,
  lease: LeaseRow,
  outcome: CredentialTeardownOutcomeV11 | undefined,
): Promise<CaptureStatus> {
  if (!lease.captureRequired) return "resolved";
  const capture = outcome?.capture;
  if (capture?.status === "failed") return "failed";
  if (capture?.status === "acked") {
    const ledger = await tx.credentialCapture.findUnique({
      where: { captureId: capture.captureId },
      select: { leaseId: true, outcome: true },
    });
    if (ledger?.leaseId === lease.id && ledger.outcome !== "REJECTED") return "resolved";
    const rejected = await tx.credentialCaptureRejection.count({
      where: { captureId: capture.captureId, leaseId: lease.id },
    });
    if (rejected > 0) return "failed";
    // Deferred, or an ack the server has no row for: the envelope is still owed.
    return "pending";
  }
  if (capture?.status === "durable") return "pending";
  if (await teardownCaptureResolved(tx, sandboxId, lease)) return "resolved";
  if (await hasPendingEnvelope(tx, lease.id)) return "pending";
  return "unknown";
}

function outcomesByBinding(outcomes: readonly CredentialTeardownOutcomeV11[] | null | undefined) {
  const map = new Map<string, CredentialTeardownOutcomeV11>();
  for (const outcome of outcomes ?? []) map.set(outcome.bindingId, outcome);
  return map;
}

/** `scrub: verified` clears that binding's residue on this sandbox (§7.6). */
async function clearVerifiedScrubs(
  tx: Tx,
  sandboxId: string,
  outcomes: readonly CredentialTeardownOutcomeV11[] | null | undefined,
) {
  const verified = (outcomes ?? []).filter((o) => o.scrub === "verified").map((o) => o.bindingId);
  if (verified.length === 0) return;
  await tx.credentialResidue.updateMany({
    where: { sandboxId, bindingId: { in: verified }, clearedAt: null },
    data: { clearedAt: new Date(), clearReason: "scrubbed" },
  });
}

/** Parses `result.credentialOutcomes`; a malformed list is ignored (rows decide). */
export function teardownOutcomesFromResult(
  result: Record<string, unknown> | undefined,
): CredentialTeardownOutcomeV11[] | null {
  const raw = result?.[CREDENTIAL_TEARDOWN_RESULT_KEY];
  if (raw === undefined) return null;
  const parsed = credentialTeardownOutcomesV11Schema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

/**
 * The result record minus the credential receipts (teardown outcomes and
 * install reports; never stored on the operation).
 */
export function withoutCredentialReceipts(
  result: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (
    !result ||
    !(CREDENTIAL_TEARDOWN_RESULT_KEY in result || CREDENTIAL_INSTALLED_RESULT_KEY in result)
  )
    return result;
  const {
    [CREDENTIAL_TEARDOWN_RESULT_KEY]: _outcomes,
    [CREDENTIAL_INSTALLED_RESULT_KEY]: _installed,
    ...rest
  } = result;
  return rest;
}

/**
 * `SandboxOperation.teardownPriorState` for a new stop/kill, written with the
 * operation row (P3-3): the state it was accepted from. A teardown that
 * supersedes another (kill after stop, a stop retrying an UNKNOWN stop) is
 * accepted from STOPPING and inherits the state the first one recorded.
 */
export async function resolveTeardownPriorState(
  tx: Tx,
  sandbox: { id: string; state: SandboxState; generation: number },
): Promise<SandboxState> {
  if (sandbox.state !== "STOPPING") return sandbox.state;
  const previous = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: sandbox.id,
      generation: { lte: sandbox.generation },
      kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] },
      teardownPriorState: { not: null },
    },
    orderBy: { generation: "desc" },
    select: { teardownPriorState: true },
  });
  return previous?.teardownPriorState ?? sandbox.state;
}

/**
 * `settleCredentialTeardown` (§7.5): in every stop / kill / system-writer
 * transaction, right after `retireSupersededOperations`.
 * - launch / attach leases of superseded operations settle (see above);
 * - `skip` (user `credentialCapture: "skip"`): every held lease → RELEASED{skipped};
 * - ACTIVE, and RECOVERY_REQUIRED with an open binding on a running VM (a
 *   REJECTED free, §7.1), → RELEASING owned by the new teardown;
 * - RELEASING (a superseded free, or a stop a kill supersedes) keeps its open
 *   binding, so a capture already sealed still commits; ownership moves;
 * - RECOVERY_REQUIRED on a stopped sandbox is unchanged.
 * `priorState` is the operation's `teardownPriorState` (resolveTeardownPriorState).
 */
export async function settleCredentialTeardown(
  tx: Tx,
  input: {
    sandboxId: string;
    priorState: SandboxState;
    generation: number;
    teardownOperationId: string;
    skip?: boolean;
  },
): Promise<void> {
  const running = RUNNING_STATES.has(input.priorState);
  for (const lease of await lockSandboxLeases(tx, input.sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (await settleSupersededLaunchLease(tx, lease)) continue;
    if (input.skip) {
      await finishLease(tx, lease.id, "RELEASED", "skipped");
      continue;
    }
    if (
      lease.state === "ACTIVE" ||
      lease.state === "RELEASING" ||
      (lease.state === "RECOVERY_REQUIRED" && lease.bindingOpen && running)
    )
      await moveToReleasing(tx, lease.id, input.teardownOperationId);
  }
  await dropSupersededSpecs(tx, input.sandboxId, input.generation);
}

/**
 * `settleCredentialConvergence` (§7.5, P3-2): inventory convergence, right
 * after `retireSupersededOperations`, before `finishConvergence`.
 * - superseded launch / attach leases settle as above;
 * - `next = STOPPED`: ACTIVE → RELEASING owned by the convergence operation
 *   (or none); the commit of a census-listed envelope or census settlement
 *   resolves it, so resume rule 1 can reuse it;
 * - `next = DELETED`: `finishConvergence` runs `settleCredentialsOnDeleted`;
 * - `next = ERROR` (no stop/destroy proof): ACTIVE / RELEASING →
 *   RECOVERY_REQUIRED, residue recoverable.
 */
export async function settleCredentialConvergence(
  tx: Tx,
  input: {
    sandboxId: string;
    generation: number;
    next: SandboxState;
    operationId: string | null;
  },
): Promise<void> {
  // A census detach to OFFLOADED clears nothing.
  if (input.next === "OFFLOADED")
    return settleCredentialsOnOffloaded(tx, {
      sandboxId: input.sandboxId,
      attemptOperationId: null,
      attemptGeneration: null,
    });
  for (const lease of await lockSandboxLeases(tx, input.sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (await settleSupersededLaunchLease(tx, lease)) continue;
    if (input.next === "STOPPED" && (lease.state === "ACTIVE" || lease.state === "RELEASING"))
      await moveToReleasing(tx, lease.id, input.operationId ?? lease.teardownOperationId);
    else if (input.next === "ERROR" && (lease.state === "ACTIVE" || lease.state === "RELEASING"))
      await requireLeaseRecovery(tx, lease.id, "convergence");
  }
  await dropSupersededSpecs(tx, input.sandboxId, input.generation);
}

/**
 * `settleCredentialsOnHostLost` (§7.1 ACTIVE/RELEASING → RECOVERY_REQUIRED):
 * in the same transaction as every write of `state: "HOST_LOST"`. The host is
 * gone without stop or destroy proof, so no capture of the lease can be
 * expected: ACTIVE and RELEASING leases → RECOVERY_REQUIRED (residue stays
 * recoverable, the disk may come back); launch / attach leases settle as
 * superseded. HOST_LOST only leads to RECLAIMING or DELETED, where the
 * DELETED settlement finishes them. No writer exists yet; the writer
 * enumeration test requires any future one to call this.
 */
export async function settleCredentialsOnHostLost(
  tx: Tx,
  input: { sandboxId: string; generation: number },
): Promise<void> {
  for (const lease of await lockSandboxLeases(tx, input.sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (await settleSupersededLaunchLease(tx, lease)) continue;
    if (lease.state === "ACTIVE" || lease.state === "RELEASING")
      await requireLeaseRecovery(tx, lease.id, "host_lost");
  }
  await dropSupersededSpecs(tx, input.sandboxId, input.generation);
}

/**
 * A cold reconnect supersedes every earlier launch of its stopped disk (§7.1
 * supersession, §7.5): the leases an UNKNOWN create / cold reconnect left
 * RESERVED, INSTALLING or RECOVERING settle exactly as superseded launch
 * leases — RESERVED → ABANDONED; INSTALLING → RELEASED{superseded} (binding
 * closed, residue non-recoverable: the new launch scrubs it); RECOVERING →
 * RECOVERY_REQUIRED unless its recovery resolved, so resume rule 1 reuses it.
 * An ACTIVE lease (the predecessor installed but never reported READY) has
 * no stop proof and no capture: → RECOVERY_REQUIRED, residue recoverable,
 * and resume rule 1 recaptures the disk before injecting again.
 * Runs in its OWN committed transaction (`supersedeColdLaunch` in the
 * sandbox service), which advances the generation, retires the predecessor
 * and settles here, BEFORE the reconnect's transaction: no transaction ever
 * holds settled instances while it claims others (a claim may need an
 * instance ordered before a settled one, §7.3). The reconnect itself refuses
 * to claim while `hasSupersededLaunchLeases`, so a crash between the two
 * re-runs this settlement on retry; it is idempotent. Drain
 * (`assertCredentialDrain`) already ran: any envelope of the predecessor is
 * resolved, and nothing is RELEASING.
 */
/**
 * Whether `settleSupersededLaunchLeases` would change anything: a launch
 * lease (RESERVED, INSTALLING, RECOVERING), an ACTIVE lease, or a live LOGIN
 * lease. RECOVERY_REQUIRED leases stay as they are (resume rule 1 reuses
 * them). A plain read under S, which keeps the sandbox's lease set and states
 * stable; it takes no lease or instance lock.
 */
/** Stop/kill resolver: the sandbox still has a login lease that is not
 * finished. A failed teardown of such a sandbox is never retried by the
 * system: its leases (RECOVERY_REQUIRED, recoverable residue) wait for the
 * owner's recovery or own stop/kill, never for an automatic teardown. */
export async function hasOpenCredentialLeases(tx: Tx, sandboxId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<{ open: boolean }[]>`SELECT EXISTS (
      SELECT 1 FROM credential_lease l WHERE l."sandboxId" = ${sandboxId}
        AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
    ) AS open`;
  return rows?.[0]?.open === true;
}

export async function hasSupersededLaunchLeases(tx: Tx, sandboxId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<{ pending: boolean }[]>`SELECT EXISTS (
      SELECT 1 FROM credential_lease l WHERE l."sandboxId" = ${sandboxId}
        AND (l.state::text IN ('RESERVED', 'INSTALLING', 'RECOVERING', 'ACTIVE')
          OR (l.kind::text = 'LOGIN'
            AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')))
    ) AS pending`;
  return rows?.[0]?.pending === true;
}

export async function settleSupersededLaunchLeases(
  tx: Tx,
  input: { sandboxId: string; generation: number },
): Promise<void> {
  for (const lease of await lockSandboxLeases(tx, input.sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (await settleSupersededLaunchLease(tx, lease)) continue;
    if (lease.state === "ACTIVE") await requireLeaseRecovery(tx, lease.id, "superseded_launch");
  }
  await dropSupersededSpecs(tx, input.sandboxId, input.generation);
}

/**
 * The sandbox reached STOPPED (a stop result or convergence proof): each
 * RELEASING lease whose teardown capture resolved → RELEASED; a failed or
 * REJECTED capture → RECOVERY_REQUIRED (the VM stopped without scrubbing it;
 * when the host nonetheless verified the scrub, nothing is left to recover →
 * RELEASED{capture_lost}); a durable / census-listed envelope or no evidence
 * stays RELEASING for the commit or census settlement.
 */
export async function settleCredentialsOnStopped(
  tx: Tx,
  sandboxId: string,
  outcomes?: readonly CredentialTeardownOutcomeV11[] | null,
): Promise<void> {
  await clearVerifiedScrubs(tx, sandboxId, outcomes);
  const byBinding = outcomesByBinding(outcomes);
  for (const lease of await lockSandboxLeases(tx, sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (await settleSupersededLaunchLease(tx, lease)) continue;
    if (lease.state !== "RELEASING") continue;
    const outcome = lease.currentBindingId ? byBinding.get(lease.currentBindingId) : undefined;
    const status = await captureStatus(tx, sandboxId, lease, outcome);
    if (status === "resolved")
      await finishLease(tx, lease.id, "RELEASED", lease.captureRequired ? "captured" : "stopped");
    else if (status === "failed") {
      if (outcome?.scrub === "verified") await markCaptureLost(tx, lease);
      else await requireLeaseRecovery(tx, lease.id, "capture_failed");
    }
  }
}

/**
 * `settleCredentialsOnDeleted` (§7.1 → DELETED settlement), in the same
 * transaction as every DELETED write: RESERVED → ABANDONED; INSTALLING →
 * RELEASED{superseded}; RELEASING whose capture resolved → RELEASED; RELEASING
 * with a `durable` outcome or a census-listed envelope stays RELEASING until
 * the commit resolves it; every other non-terminal lease → RELEASED
 * {capture_lost} with the NEEDS_LOGIN rule; all residue cleared{deleted}.
 */
export async function settleCredentialsOnDeleted(
  tx: Tx,
  sandboxId: string,
  outcomes?: readonly CredentialTeardownOutcomeV11[] | null,
): Promise<void> {
  await settleLeasesWithoutDisk(tx, sandboxId, outcomes);
  await tx.credentialResidue.updateMany({
    where: { sandboxId, clearedAt: null },
    data: { clearedAt: new Date(), clearReason: "deleted", recoverable: false },
  });
  await tx.credentialOperationSpec.deleteMany({ where: { Operation: { sandboxId } } });
}

/** Per transaction: the sandboxes whose OFFLOADED settlement already ran. */
const offloadedSettled = new WeakMap<Tx, Set<string>>();

/**
 * `settleCredentialsOnOffloaded`: the credential
 * settlement of every write of the OFFLOADED state, at most once per
 * transaction (later calls are no-ops; `detachToOffloaded` calls it too).
 * The detached root is gone with proof (a no-effect proof or the
 * SYSTEM_DETACH kill's root absence, or the evict / census proof), so its
 * leases settle DELETED-equivalently — never through `requireLeaseRecovery`.
 * The STORED disk is kept, so unlike `settleCredentialsOnDeleted` it never
 * clears blanket residue or specs:
 * - residue: only rows the failed attempt granted (`grantGeneration >=
 *   attemptGeneration`); the stored disk's own residue stays;
 * - specs: only the attempt operation's own spec;
 * - evict and census (`attemptGeneration = null`) clear nothing.
 */
export async function settleCredentialsOnOffloaded(
  tx: Tx,
  input: {
    sandboxId: string;
    attemptOperationId: string | null;
    attemptGeneration: number | null;
    outcomes?: readonly CredentialTeardownOutcomeV11[] | null;
  },
): Promise<void> {
  let settled = offloadedSettled.get(tx);
  if (!settled) {
    settled = new Set();
    offloadedSettled.set(tx, settled);
  }
  if (settled.has(input.sandboxId)) return;
  settled.add(input.sandboxId);
  await settleLeasesWithoutDisk(tx, input.sandboxId, input.outcomes);
  if (input.attemptGeneration !== null)
    await tx.credentialResidue.updateMany({
      where: {
        sandboxId: input.sandboxId,
        clearedAt: null,
        grantGeneration: { gte: input.attemptGeneration },
      },
      data: { clearedAt: new Date(), clearReason: "restore_failed", recoverable: false },
    });
  if (input.attemptOperationId !== null)
    await tx.credentialOperationSpec.deleteMany({
      where: { operationId: input.attemptOperationId, Operation: { sandboxId: input.sandboxId } },
    });
}

/** The lease half of the DELETED settlement (also the OFFLOADED one's):
 * the root these leases bound is gone. */
async function settleLeasesWithoutDisk(
  tx: Tx,
  sandboxId: string,
  outcomes?: readonly CredentialTeardownOutcomeV11[] | null,
): Promise<void> {
  const byBinding = outcomesByBinding(outcomes);
  for (const lease of await lockSandboxLeases(tx, sandboxId)) {
    if (await settleLoginLease(tx, lease)) continue;
    if (lease.state === "RESERVED") {
      await finishLease(tx, lease.id, "ABANDONED", "deleted");
      continue;
    }
    if (lease.state === "INSTALLING") {
      await finishLease(tx, lease.id, "RELEASED", "superseded");
      continue;
    }
    if (lease.state === "RELEASING") {
      const outcome = lease.currentBindingId ? byBinding.get(lease.currentBindingId) : undefined;
      const status = await captureStatus(tx, sandboxId, lease, outcome);
      if (status === "resolved") {
        await finishLease(tx, lease.id, "RELEASED", lease.captureRequired ? "captured" : "deleted");
        continue;
      }
      if (status === "pending") continue;
    }
    if (!lease.captureRequired && (lease.state === "ACTIVE" || lease.state === "RELEASING"))
      await finishLease(tx, lease.id, "RELEASED", "deleted");
    else await markCaptureLost(tx, lease);
  }
}

/**
 * `settleTerminalTeardown` (§7.1 P3-5): a stop/kill became terminal WITHOUT
 * STOPPED/DELETED proof for a reason other than the credential re-arm (a
 * non-credential FAILED → ERROR; a cancelled never-dispatched access KILL).
 * Its RELEASING leases: capture resolved → RELEASED; never dispatched and the
 * sandbox is back in READY → ACTIVE; otherwise → RECOVERY_REQUIRED (residue
 * recoverable; on a running VM the open binding is re-captured by the next
 * teardown).
 */
export async function settleTerminalTeardown(
  tx: Tx,
  op: { id: string; sandboxId: string; dispatchAttempt: number },
  outcomes?: readonly CredentialTeardownOutcomeV11[] | null,
): Promise<void> {
  await clearVerifiedScrubs(tx, op.sandboxId, outcomes);
  const byBinding = outcomesByBinding(outcomes);
  const sandbox = await tx.sandbox.findUnique({
    where: { id: op.sandboxId },
    select: { state: true },
  });
  for (const lease of await lockSandboxLeases(tx, op.sandboxId)) {
    if (lease.state !== "RELEASING" || lease.teardownOperationId !== op.id) continue;
    // Never dispatched: no capture of this teardown can exist, and the VM is
    // untouched — a READY sandbox simply keeps its lease.
    if (op.dispatchAttempt === 0 && sandbox?.state === "READY") {
      await rearmLease(tx, lease.id);
      continue;
    }
    const outcome = lease.currentBindingId ? byBinding.get(lease.currentBindingId) : undefined;
    if ((await captureStatus(tx, op.sandboxId, lease, outcome)) === "resolved") {
      await finishLease(tx, lease.id, "RELEASED", lease.captureRequired ? "captured" : "teardown");
      continue;
    }
    await requireLeaseRecovery(tx, lease.id, "teardown_failed");
  }
}

async function rearmLease(tx: Tx, leaseId: string) {
  await tx.$executeRaw`UPDATE credential_lease SET state = 'ACTIVE', "teardownOperationId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${leaseId} AND state::text = 'RELEASING'`;
}

/**
 * A USER teardown owns ≥ 1 RELEASING lease (`teardownOperationId` = op),
 * under S. System teardowns (reserved internal keys) never re-arm: they never
 * fail on capture (§10.3).
 */
export async function ownsReleasingLease(
  tx: Tx,
  sandboxId: string,
  operation: { id: string; idempotencyKey: string },
): Promise<boolean> {
  if (isReservedInternalIdempotencyKey(operation.idempotencyKey)) return false;
  const leases = await lockSandboxLeases(tx, sandboxId);
  return leases.some((l) => l.state === "RELEASING" && l.teardownOperationId === operation.id);
}

/**
 * Applies a stop/kill result's credential settlement (§7.5 last paragraph,
 * §10.3), after the sandbox state was written and before a DELETED detach:
 * - the P3-3 re-arm (user stop/kill FAILED `credential_capture_failed` while
 *   owning RELEASING leases): those leases → ACTIVE; commits made during the
 *   failed attempt stand (`baseSeq` already advanced);
 * - DELETED → `settleCredentialsOnDeleted`; STOPPED → `settleCredentialsOnStopped`;
 * - any other FAILED → `settleTerminalTeardown`;
 * - CANCELLED (superseded: the superseding teardown owns the leases) and
 *   UNKNOWN_OUTCOME change nothing.
 */
export async function settleLifecycleTeardownResult(
  tx: Tx,
  input: {
    sandboxId: string;
    operation: { id: string; dispatchAttempt: number };
    opState: OperationState;
    next: SandboxState | undefined;
    rearm: boolean;
    outcomes: readonly CredentialTeardownOutcomeV11[] | null;
  },
): Promise<void> {
  if (input.rearm) {
    await clearVerifiedScrubs(tx, input.sandboxId, input.outcomes);
    for (const lease of await lockSandboxLeases(tx, input.sandboxId))
      if (lease.state === "RELEASING" && lease.teardownOperationId === input.operation.id) {
        await rearmLease(tx, lease.id);
        // The user stop/kill was refused; the login stays live (webhook N10).
        await recordLeaseEvent(tx, lease.id, "capture_failed", "credential_capture_failed");
      }
    return;
  }
  if (input.next === "OFFLOADED") {
    // A SYSTEM_DETACH kill settles the failed
    // restore attempt it carries (none for a plain detach).
    const kill = await tx.sandboxOperation.findUnique({
      where: { id: input.operation.id },
      select: { attemptOperationId: true, attemptGeneration: true },
    });
    await settleCredentialsOnOffloaded(tx, {
      sandboxId: input.sandboxId,
      attemptOperationId: kill?.attemptOperationId ?? null,
      attemptGeneration: kill?.attemptGeneration ?? null,
      outcomes: input.outcomes,
    });
  } else if (input.next === "DELETED")
    await settleCredentialsOnDeleted(tx, input.sandboxId, input.outcomes);
  else if (input.next === "STOPPED")
    await settleCredentialsOnStopped(tx, input.sandboxId, input.outcomes);
  else if (input.opState === "FAILED")
    await settleTerminalTeardown(
      tx,
      {
        id: input.operation.id,
        sandboxId: input.sandboxId,
        dispatchAttempt: input.operation.dispatchAttempt,
      },
      input.outcomes,
    );
}

/**
 * Terminal operation finalization (§7.1, §7.5, §10.4): the ONE credential
 * settlement every terminal write of a sandbox operation runs, in the same
 * transaction — a host result (with its receipt) and every server-side
 * terminal write without one (a dispatch refusal, an undelivered dispatch, a
 * failed allocation, an expiry). A never-sent operation has no host result to
 * repair it later, so skipping this strands reserved slots and RELEASING
 * leases. By kind:
 * - CREATE / RECONNECT: SUCCEEDED, FAILED or CANCELLED settle the launch's
 *   leases (`settleCredentialLaunch`); UNKNOWN_OUTCOME keeps them for the
 *   retry that supersedes it;
 * - CREDENTIAL_ATTACH: `settleCredentialAttachResult`;
 * - CREDENTIAL_FREE: `settleCredentialFreeResult` (a free refused before any
 *   guest effect re-arms its leases ACTIVE);
 * - STOP / KILL: `settleLifecycleTeardownResult` (FAILED without stop/destroy
 *   proof → `settleTerminalTeardown`);
 * - every other kind carries no credential work.
 * `terminal-writers.test.ts` enumerates the terminal writers.
 */
export async function settleOperationCredentials(
  tx: Tx,
  input: {
    sandboxId: string;
    operation: { id: string; kind: SandboxOperationKind; dispatchAttempt: number };
    opState: OperationState;
    /** The host's receipt; absent for a server-side terminal write. */
    receipt?: {
      outcomes: readonly CredentialTeardownOutcomeV11[] | null;
      /** CREDENTIAL_FREE: the stored spec asked to skip the capture. */
      skip?: boolean;
      /** STOP / KILL: the sandbox state the result wrote, and the P3-3 re-arm. */
      next?: SandboxState;
      rearm?: boolean;
    };
  },
): Promise<void> {
  const { operation, opState, sandboxId } = input;
  if (
    opState !== "SUCCEEDED" &&
    opState !== "FAILED" &&
    opState !== "CANCELLED" &&
    opState !== "UNKNOWN_OUTCOME"
  )
    return;
  const outcomes = input.receipt?.outcomes ?? null;
  switch (operation.kind) {
    case "CREATE_SANDBOX":
    case "RECONNECT_SANDBOX":
      if (opState === "SUCCEEDED" || opState === "FAILED" || opState === "CANCELLED")
        await settleCredentialLaunch(tx, {
          sandboxId,
          operationId: operation.id,
          succeeded: opState === "SUCCEEDED",
        });
      return;
    case "CREDENTIAL_ATTACH":
      await settleCredentialAttachResult(tx, { sandboxId, operationId: operation.id, opState });
      return;
    case "CREDENTIAL_FREE":
      await settleCredentialFreeResult(tx, {
        sandboxId,
        operation,
        opState,
        skip: input.receipt?.skip ?? false,
        outcomes,
      });
      return;
    case "STOP_SANDBOX":
    case "KILL_SANDBOX":
      await settleLifecycleTeardownResult(tx, {
        sandboxId,
        operation,
        opState,
        next: input.receipt?.next,
        rearm: input.receipt?.rearm ?? false,
        outcomes,
      });
      return;
    default:
      return;
  }
}

/**
 * M8 (§10.3): a user kill of a STOPPED sandbox whose disk still holds
 * uncleared RECOVERABLE residue is refused unless the caller passed `skip`.
 * Returns true when the kill must be refused.
 */
export async function killNeedsRecovery(
  tx: Tx,
  input: { sandboxId: string; state: SandboxState; skip: boolean },
): Promise<boolean> {
  if (input.skip || input.state !== "STOPPED") return false;
  return (
    (await tx.credentialResidue.count({
      where: { sandboxId: input.sandboxId, clearedAt: null, recoverable: true },
    })) > 0
  );
}

/**
 * Census settlement for one sandbox (§7.1 P3-7), S held: after a complete
 * census, each RELEASING lease with no unresolved envelope left settles —
 * RELEASED when its teardown capture resolved; otherwise RECOVERY_REQUIRED on
 * a STOPPED disk (residue recoverable) or RELEASED{capture_lost} once the
 * sandbox is DELETED (the disk is gone).
 */
export async function settleDrainedTeardowns(tx: Tx, sandboxId: string): Promise<void> {
  const sandbox = await tx.sandbox.findUnique({
    where: { id: sandboxId },
    select: { state: true },
  });
  if (sandbox?.state !== "STOPPED" && sandbox?.state !== "DELETED") return;
  for (const lease of await lockSandboxLeases(tx, sandboxId)) {
    if (lease.state !== "RELEASING" || (await hasPendingEnvelope(tx, lease.id))) continue;
    if (await teardownCaptureResolved(tx, sandboxId, lease))
      await finishLease(tx, lease.id, "RELEASED", lease.captureRequired ? "captured" : "stopped");
    else if (sandbox.state === "DELETED") await markCaptureLost(tx, lease);
    else await requireLeaseRecovery(tx, lease.id, "census_settlement");
  }
}

/**
 * The P3-3 re-arm keeps the VM running at the stop's generation N+1, so the
 * sandbox's placement — which every guest operation requires at the current
 * generation (`requireOwnedSandboxPlacement`) — is re-bound to N+1 exactly as
 * a reconnect does: an identical copy owned by the failed teardown operation.
 * The live hold and its charges are unchanged. Runs under H → S → O.
 */
export async function rebindPlacementAfterRearm(
  tx: Tx,
  input: { sandboxId: string; userId: string; generation: number; operationId: string; now: Date },
): Promise<void> {
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.userId, generation: input.generation },
    select: { currentPlacementId: true },
  });
  if (!sandbox?.currentPlacementId) return;
  const previous = await tx.sandboxPlacement.findFirst({
    where: { id: sandbox.currentPlacementId, sandboxId: input.sandboxId, userId: input.userId },
  });
  if (!previous || previous.generation >= input.generation) return;
  const {
    id: _id,
    generation: _generation,
    operationId: _operationId,
    acceptedAt: _acceptedAt,
    startedAt,
    readyAt,
    endedAt: _endedAt,
    endReason: _endReason,
    imageFetchBytes: _imageFetchBytes,
    ...kept
  } = previous;
  const placement = await tx.sandboxPlacement.create({
    data: {
      ...kept,
      generation: input.generation,
      operationId: input.operationId,
      acceptedAt: input.now,
      startedAt,
      readyAt,
    },
    select: { id: true },
  });
  await tx.sandbox.update({
    where: { id: input.sandboxId },
    data: { currentPlacementId: placement.id },
    select: { id: true },
  });
}

/**
 * A login finish's free result (§11 Save) for a LOGIN lease still RELEASING
 * (a COMMITTED / UNCHANGED login capture already RELEASED it and SAVED the
 * session in the commit fence): a durable envelope (offline, or DEFERRED)
 * stays RELEASING and its commit saves the login; anything else — no capture,
 * a failed pack, DISCARDED{incomplete|superseded}, REJECTED, a FAILED free —
 * re-arms the lease ACTIVE with its LOGIN binding open, so the user can fix
 * the login in the terminal and finish again, and the session is FAILED. The
 * sandbox is kept until cancel or expiry.
 */
async function settleLoginFinish(
  tx: Tx,
  lease: LeaseRow,
  outcome: CredentialTeardownOutcomeV11 | undefined,
): Promise<void> {
  const capture = outcome?.capture;
  let pending = capture?.status === "durable";
  if (capture?.status === "acked") {
    const resolved = await tx.credentialCapture.count({
      where: { captureId: capture.captureId, leaseId: lease.id },
    });
    const rejected = await tx.credentialCaptureRejection.count({
      where: { captureId: capture.captureId, leaseId: lease.id },
    });
    // DEFERRED (vault unavailable): the host keeps the envelope and retries.
    pending = resolved === 0 && rejected === 0;
  }
  if (pending) return;
  await rearmLease(tx, lease.id);
  const row = await tx.credentialLease.findUnique({
    where: { id: lease.id },
    select: { loginSessionId: true },
  });
  if (row?.loginSessionId)
    await tx.credentialLoginSession.updateMany({
      where: { id: row.loginSessionId, state: { in: ["READY", "SAVING"] } },
      data: { state: "FAILED" },
    });
  await recordLeaseEvent(tx, lease.id, "login_failed", loginFailureReason(capture));
}

function loginFailureReason(capture: CredentialTeardownOutcomeV11["capture"] | undefined): string {
  if (!capture || capture.status === "none") return "not_captured";
  if (capture.status === "failed") return "capture_failed";
  return "capture_not_saved";
}

/**
 * A free's result (§10.1, §10.3 Free, §10.4), in the result transaction with
 * S held. Only the RELEASING leases this free owns are touched; a stop that
 * superseded the free already took them over (`settleCredentialTeardown`).
 * - SUCCEEDED: `skip` or no capture required → RELEASED; capture resolved
 *   (ledger re-read, never the host's word) → RELEASED; a capture that
 *   failed while the host still scrubbed (pack error: the owner chose
 *   removal) → RELEASED{free_capture_failed} with the NEEDS_LOGIN rule; a
 *   REJECTED capture (no scrub) → RECOVERY_REQUIRED with the binding open
 *   (the next teardown recaptures the live files); a durable envelope stays
 *   RELEASING and is released by its commit. A released lease ends the
 *   attachment (`detachedAt`); RECOVERY_REQUIRED leaves it attached.
 * - FAILED with no capture or scrub evidence (refused before any guest
 *   effect: slot busy, env pending) → ACTIVE again; any other FAILED settles
 *   like a terminal teardown without proof.
 * - CANCELLED / UNKNOWN_OUTCOME change nothing.
 */
export async function settleCredentialFreeResult(
  tx: Tx,
  input: {
    sandboxId: string;
    operation: { id: string; dispatchAttempt: number };
    opState: OperationState;
    skip: boolean;
    outcomes: readonly CredentialTeardownOutcomeV11[] | null;
  },
): Promise<void> {
  if (input.opState === "CANCELLED" || input.opState === "UNKNOWN_OUTCOME") return;
  await clearVerifiedScrubs(tx, input.sandboxId, input.outcomes);
  const byBinding = outcomesByBinding(input.outcomes);
  for (const lease of await lockSandboxLeases(tx, input.sandboxId)) {
    if (lease.state !== "RELEASING" || lease.teardownOperationId !== input.operation.id) continue;
    const outcome = lease.currentBindingId ? byBinding.get(lease.currentBindingId) : undefined;
    if (lease.kind === "LOGIN") {
      await settleLoginFinish(tx, lease, outcome);
      continue;
    }
    if (input.opState === "FAILED") {
      const untouched =
        (!outcome || outcome.capture.status === "none") && outcome?.scrub !== "verified";
      if (untouched) await rearmLease(tx, lease.id);
      else if ((await captureStatus(tx, input.sandboxId, lease, outcome)) === "resolved") {
        await finishLease(tx, lease.id, "RELEASED", "freed");
        await detachAttachment(tx, input.sandboxId, lease.credentialId);
      } else await requireLeaseRecovery(tx, lease.id, "free_failed");
      continue;
    }
    if (input.skip) {
      await finishLease(tx, lease.id, "RELEASED", "skipped");
      await detachAttachment(tx, input.sandboxId, lease.credentialId);
      continue;
    }
    const status = await captureStatus(tx, input.sandboxId, lease, outcome);
    if (status === "resolved") {
      await finishLease(tx, lease.id, "RELEASED", lease.captureRequired ? "captured" : "freed");
      await detachAttachment(tx, input.sandboxId, lease.credentialId);
    } else if (status === "failed") {
      if (outcome?.scrub === "verified") {
        await markCaptureLost(tx, lease, "free_capture_failed");
        await detachAttachment(tx, input.sandboxId, lease.credentialId);
      } else await requireLeaseRecovery(tx, lease.id, "capture_rejected");
    }
    // pending / unknown: the commit of the durable envelope releases it.
  }
  await tx.credentialOperationSpec.deleteMany({ where: { operationId: input.operation.id } });
}
