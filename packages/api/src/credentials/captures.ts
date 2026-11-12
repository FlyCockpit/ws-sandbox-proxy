import { createHash } from "node:crypto";
import prisma, { type Prisma } from "@wssp/db";
import type { CredentialCaptureKind } from "@wssp/sandbox-contracts";
import { DataKeyStaleWriter } from "../crypto/data-key-epoch";
import { isReservedInternalIdempotencyKey } from "../sandbox/idempotency-key-reserved";
import { lockHostByEpoch, RelayFenceRejected } from "../sandbox/relay-fence";
import {
  detachAttachment,
  finishLease,
  heldCaptureClaims,
  isTerminalLeaseState,
  LOGIN_SAVED_REASON,
  lockLeaseChain,
  lockLeaseSandbox,
  lockSettlementScope,
  requireLeaseRecovery,
} from "./leases";
import { settleDrainedTeardowns } from "./teardown";
import { type ParsedEnvelope, parseEnvelope } from "./vault/envelope";
import { CredentialVaultError } from "./vault/errors";
import { readVaultKeys } from "./vault/keys";
import { openCaptureEnvelope } from "./vault/return-key-store";
import type { ReturnAad } from "./vault/sealed-box";
import { commitCapturedValue } from "./vault/store";
import type { SecretVersionKind } from "./vault/value";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Capture commit fence, one transaction in the
 * capture lock order H (epoch) → S → credential FOR SHARE → instance
 * FOR UPDATE → lease → binding → residue. Captures are authorized by their
 * BINDING, never by a sandbox generation. Order matters:
 *
 *  1 custody (H by epoch; the binding names this lease and was issued to this
 *  host — `heldCaptureClaims`, before any lease is locked or written)
 *  · 2 exact replay first · 3 absent lease (tombstone)
 *  · 4 binding identity · 5 terminal lease · 6 closed binding · 7 accepted
 *  sequence · 8 policy · 9 AAD rebuilt from rows + open · 10 validate ·
 *  11 env merge · 12 UNCHANGED, then the lease write baseline · 13 insert ·
 *  14 ledger, accepted sequence, pending row, lease transition.
 *
 * Every REJECTED outcome writes exactly one `CredentialCaptureRejection` row
 * (insert-or-return-existing) in the same transaction, deletes the pending
 * row, leaves `captureSeqAccepted` alone and applies the path's lease rule;
 * the host quarantines the envelope. DEFERRED (vault unavailable) changes
 * nothing.
 */

type Tx = Prisma.TransactionClient;

const CAPTURE_DISCARD_REASONS = [
  "force_released",
  "copy_back_disabled",
  "superseded",
  "incomplete",
  "account_deleted",
] as const;
const CAPTURE_REJECT_REASONS = [
  "context_mismatch",
  "decrypt_failed",
  "invalid_bundle",
  "unknown_kid",
  "unknown_lease",
  "binding_closed",
] as const;
type CaptureDiscardReason = (typeof CAPTURE_DISCARD_REASONS)[number];
type CaptureRejectReason = (typeof CAPTURE_REJECT_REASONS)[number];

/** Wire ack (lowercase); the DB enum is uppercase. */
export type CaptureAck =
  | { outcome: "committed" | "unchanged" | "deferred" }
  | { outcome: "discarded"; reason: CaptureDiscardReason }
  | { outcome: "rejected"; reason: CaptureRejectReason };

export type CaptureSubmission = {
  hostId: string;
  connectionEpoch: number;
  /** The origin the return key was issued with (bound in the seal AAD). */
  serverOrigin: string;
  captureId: string;
  leaseId: string;
  bindingId: string;
  kidR: string;
  kind: CredentialCaptureKind;
  /** Hex SHA-256 the host claims for the whole envelope. */
  envelopeDigest: string;
  envelope: Uint8Array;
};

const TEARDOWN_KINDS = new Set<CredentialCaptureKind>(["stop", "kill", "free", "expiry"]);
const INT4_MAX = 2_147_483_647;

function versionKind(kind: CredentialCaptureKind): SecretVersionKind {
  if (kind === "checkpoint") return "CHECKPOINT";
  if (kind === "recovery") return "RECOVERY";
  if (kind === "login") return "LOGIN";
  return "CAPTURE";
}

function storedAck(outcome: string, reason: string | null): CaptureAck {
  if (outcome === "COMMITTED") return { outcome: "committed" };
  if (outcome === "UNCHANGED") return { outcome: "unchanged" };
  if (
    outcome === "DISCARDED" &&
    (CAPTURE_DISCARD_REASONS as readonly string[]).includes(reason ?? "")
  )
    return { outcome: "discarded", reason: reason as CaptureDiscardReason };
  return { outcome: "rejected", reason: "context_mismatch" };
}

function rejectReason(reason: string): CaptureRejectReason {
  return (CAPTURE_REJECT_REASONS as readonly string[]).includes(reason)
    ? (reason as CaptureRejectReason)
    : "context_mismatch";
}

type LeaseRow = {
  id: string;
  userId: string;
  credentialId: string;
  accountId: string;
  instanceId: string;
  sandboxId: string | null;
  loginSessionId: string | null;
  kind: "WORKLOAD" | "LOGIN";
  state: string;
  baseSeq: number | null;
  captureSeqAccepted: number;
  teardownOperationId: string | null;
};

class Fence {
  constructor(
    readonly tx: Tx,
    readonly s: CaptureSubmission,
    readonly digest: Buffer,
  ) {}
  /** The binding names this lease and was issued to this host (`heldCaptureClaims`). */
  custody = false;
  lease: LeaseRow | null = null;
  captureSeq: number | null = null;

  async deletePending() {
    await this.tx.$executeRaw`DELETE FROM credential_pending_capture
      WHERE "hostId" = ${this.s.hostId} AND "captureId" = ${this.s.captureId}`;
  }

  /**
   * Every REJECTED path (P3-1): one rejection row, pending row deleted, the
   * path's lease rule. Without custody the row names no lease or binding: it
   * is the submitting host's quarantine only and never counts for, blocks or
   * is listed under a lease that host does not hold.
   */
  async reject(
    reason: CaptureRejectReason,
    options: { leaseRule: boolean } = { leaseRule: true },
  ): Promise<CaptureAck> {
    const lease = this.custody ? this.lease : null;
    await this.tx.$executeRaw`INSERT INTO credential_capture_rejection
        ("hostId", "captureId", "envelopeDigest", "leaseId", "bindingId", "kidR", reason)
      VALUES (${this.s.hostId}, ${this.s.captureId}, ${this.digest},
        ${this.custody ? this.s.leaseId : null}, ${this.custody ? this.s.bindingId : null},
        ${this.s.kidR}, ${reason})
      ON CONFLICT DO NOTHING`;
    await this.deletePending();
    if (lease && options.leaseRule && !isTerminalLeaseState(lease.state))
      await this.rejectedLeaseRule(lease);
    if (lease)
      await this.tx.credentialEvent.create({
        data: {
          userId: lease.userId,
          credentialId: lease.credentialId,
          accountId: lease.accountId,
          instanceId: lease.instanceId,
          leaseId: lease.id,
          sandboxId: lease.sandboxId,
          hostId: this.s.hostId,
          type: "capture_rejected",
          reason,
        },
        select: { id: true },
      });
    return { outcome: "rejected", reason };
  }

  /**
   * §10.3 REJECTED reconciliation: the VM keeps running (user stop/kill,
   * free) → no lease change; the VM stops (system stop, expiry, a sandbox
   * already STOPPED) → RECOVERY_REQUIRED with recoverable residue; a failed
   * recovery capture → RECOVERY_REQUIRED with the RECOVER binding closed
   * (the original residue stays recoverable).
   */
  private async rejectedLeaseRule(lease: LeaseRow) {
    const tx = this.tx;
    if (lease.state === "RECOVERING" && this.s.kind === "recovery") {
      await tx.credentialBinding.updateMany({
        where: { id: this.s.bindingId, leaseId: lease.id, purpose: "RECOVER", closedAt: null },
        data: { closedAt: new Date(), closeReason: "recovery_rejected" },
      });
      await requireLeaseRecovery(tx, lease.id, "recovery_rejected");
      return;
    }
    if (lease.state !== "ACTIVE" && lease.state !== "RELEASING") return;
    let vmStops = this.s.kind === "expiry";
    if (!vmStops && lease.sandboxId) {
      const sandbox = await tx.sandbox.findUnique({
        where: { id: lease.sandboxId },
        select: { state: true },
      });
      // A system kill already destroyed the disk: the value is lost (§10.3).
      if (sandbox?.state === "DELETED") {
        await settleDrainedTeardowns(tx, lease.sandboxId);
        return;
      }
      vmStops = sandbox?.state === "STOPPED";
    }
    if (!vmStops && lease.teardownOperationId) {
      const op = await tx.sandboxOperation.findUnique({
        where: { id: lease.teardownOperationId },
        select: { kind: true, idempotencyKey: true },
      });
      vmStops = op?.kind === "STOP_SANDBOX" && isReservedInternalIdempotencyKey(op.idempotencyKey);
    }
    if (vmStops) await requireLeaseRecovery(tx, lease.id, "capture_rejected");
  }

  /** Ledger row (ON CONFLICT: the slot is already resolved) + accepted sequence + pending row. */
  async ledger(
    outcome: "COMMITTED" | "UNCHANGED" | "DISCARDED",
    reason: string | null,
    storageSeq: number | null,
  ) {
    const seq = this.captureSeq ?? 0;
    await this.tx.$executeRaw`INSERT INTO credential_capture
        ("captureId", "leaseId", "bindingId", "captureSeq", kind, "kidR", "envelopeDigest", outcome, reason, "storageSeq")
      VALUES (${this.s.captureId}, ${this.s.leaseId}, ${this.s.bindingId}, ${seq}, ${this.s.kind},
        ${this.s.kidR}, ${this.digest}, ${outcome}::"CredentialCaptureOutcome", ${reason}, ${storageSeq})
      ON CONFLICT DO NOTHING`;
    if (this.lease)
      await this.tx.$executeRaw`UPDATE credential_lease
        SET "captureSeqAccepted" = GREATEST("captureSeqAccepted", ${seq}),
          "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
        WHERE id = ${this.lease.id}`;
    await this.deletePending();
  }

  async discard(reason: CaptureDiscardReason): Promise<CaptureAck> {
    await this.ledger("DISCARDED", reason, null);
    return { outcome: "discarded", reason };
  }
}

/**
 * Releases a RELEASING workload lease whose teardown capture just resolved,
 * when its teardown condition holds (§7.1): the sandbox reached STOPPED or
 * DELETED, or its free operation SUCCEEDED. Otherwise the result settles it.
 */
async function releaseIfTornDown(tx: Tx, lease: LeaseRow) {
  if (lease.state !== "RELEASING" || !lease.sandboxId) return;
  const sandbox = await tx.sandbox.findUnique({
    where: { id: lease.sandboxId },
    select: { state: true },
  });
  let done = sandbox?.state === "STOPPED" || sandbox?.state === "DELETED";
  let freed = false;
  if (!done && lease.teardownOperationId) {
    const op = await tx.sandboxOperation.findUnique({
      where: { id: lease.teardownOperationId },
      select: { kind: true, state: true },
    });
    freed = op?.kind === "CREDENTIAL_FREE" && op.state === "SUCCEEDED";
    done = freed;
  }
  if (done) await finishLease(tx, lease.id, "RELEASED", "captured");
  // A free whose capture resolved after its result (offline durable) ends
  // the attachment now (§10.1: `detachedAt` when the free resolves).
  if (freed) await detachAttachment(tx, lease.sandboxId, lease.credentialId);
}

async function fence(tx: Tx, s: CaptureSubmission): Promise<CaptureAck> {
  await lockHostByEpoch(tx, s.hostId, s.connectionEpoch);
  const digest = createHash("sha256").update(s.envelope).digest();
  const claimed = Buffer.from(s.envelopeDigest, "hex");
  const f = new Fence(tx, s, claimed);
  f.custody = (await heldCaptureClaims(tx, s.hostId, [s])).length === 1;

  // 2. Exact replay first (lost ACK after RELEASED), before any predicate.
  const ledger = await tx.credentialCapture.findUnique({
    where: { captureId: s.captureId },
    select: { envelopeDigest: true, outcome: true, reason: true },
  });
  if (ledger) {
    if (!Buffer.from(ledger.envelopeDigest).equals(claimed))
      return f.reject("context_mismatch", { leaseRule: false });
    await f.deletePending();
    return storedAck(ledger.outcome, ledger.reason);
  }
  const rejection = await tx.credentialCaptureRejection.findUnique({
    where: {
      hostId_captureId_envelopeDigest: {
        hostId: s.hostId,
        captureId: s.captureId,
        envelopeDigest: new Uint8Array(claimed),
      },
    },
    select: { reason: true },
  });
  if (rejection) {
    await f.deletePending();
    return { outcome: "rejected", reason: rejectReason(rejection.reason) };
  }

  // 3. Lease absent: a tombstone authorizes the discard; otherwise unknown.
  const peek = await tx.credentialLease.findUnique({
    where: { id: s.leaseId },
    select: { id: true, sandboxId: true, credentialId: true, instanceId: true },
  });
  let envelope: ParsedEnvelope | null = null;
  try {
    envelope = digest.equals(claimed) ? parseEnvelope(s.envelope) : null;
  } catch (error) {
    if (!(error instanceof CredentialVaultError)) throw error;
  }
  const seqText = envelope?.header.aad.captureSeq;
  const seq = seqText && /^[1-9][0-9]{0,9}$/.test(seqText) ? Number(seqText) : null;
  f.captureSeq = seq !== null && seq <= INT4_MAX ? seq : null;
  if (!peek) {
    const tombstone = await tx.credentialLeaseTombstone.findUnique({
      where: { hostId_leaseId: { hostId: s.hostId, leaseId: s.leaseId } },
      select: { leaseId: true },
    });
    if (tombstone) return f.discard("account_deleted");
    return f.reject("unknown_lease");
  }
  // 1. No custody: nothing of that lease is locked, read further or written.
  if (!f.custody) return f.reject("context_mismatch");

  // Lock S, then credential → instance → lease. With a sandbox, the
  // instances are the sandbox's COMPLETE settlement scope plus this lease's:
  // a REJECTED capture on a DELETED sandbox settles the sandbox's other
  // leases (`settleDrainedTeardowns`) in this transaction, and that phase
  // must not reach back for an instance ordered before this lease's (§7.3).
  if (peek.sandboxId) {
    await lockLeaseSandbox(tx, peek.sandboxId);
    await lockSettlementScope(tx, { sandboxIds: [peek.sandboxId], leases: [peek] });
    await tx.$queryRaw`SELECT id FROM credential_lease WHERE id = ${peek.id} FOR UPDATE`;
  } else await lockLeaseChain(tx, peek);
  const lease = await tx.credentialLease.findUniqueOrThrow({
    where: { id: s.leaseId },
    select: {
      id: true,
      userId: true,
      credentialId: true,
      accountId: true,
      instanceId: true,
      sandboxId: true,
      loginSessionId: true,
      kind: true,
      state: true,
      baseSeq: true,
      captureSeqAccepted: true,
      teardownOperationId: true,
    },
  });
  f.lease = lease;

  // Framing: the envelope must hash to the claimed digest and parse.
  if (!envelope || f.captureSeq === null) return f.reject("context_mismatch");

  // 4. Binding identity.
  const binding = await tx.credentialBinding.findUnique({
    where: { id: s.bindingId },
    select: {
      id: true,
      leaseId: true,
      hostId: true,
      instanceId: true,
      purpose: true,
      closedAt: true,
      recoveryOfBindingId: true,
    },
  });
  if (
    !binding ||
    binding.leaseId !== lease.id ||
    binding.hostId !== s.hostId ||
    binding.instanceId !== lease.instanceId
  )
    return f.reject("context_mismatch");

  // 5. Terminal leases: authorized discards.
  if (lease.state === "FORCE_RELEASED") return f.discard("force_released");
  if (lease.state === "RELEASED" || lease.state === "ABANDONED") return f.discard("superseded");

  // 6. A closed binding of a live lease: drain makes this a bug path.
  if (binding.closedAt) return f.reject("binding_closed");

  // 7. Accepted-sequence fence (no ledger row: the slot is already resolved).
  if (f.captureSeq <= lease.captureSeqAccepted) {
    await f.deletePending();
    return { outcome: "discarded", reason: "superseded" };
  }

  // 8. Policy, re-read inside this transaction.
  const login = await loadVerifiedLogin(tx, lease.credentialId);
  if (!login) return { outcome: "deferred" };
  if (lease.kind === "LOGIN") {
    if (s.kind !== "login") return f.reject("context_mismatch");
  } else {
    if (s.kind === "login") return f.reject("context_mismatch");
    if (s.kind === "recovery" && (lease.state !== "RECOVERING" || binding.purpose !== "RECOVER"))
      return f.reject("context_mismatch");
    if (!login.copyBack || login.delivery === "PROXY") return f.discard("copy_back_disabled");
  }

  // 9. AAD rebuilt from rows, compared field by field, then opened.
  let residueId = "";
  if (s.kind === "recovery") {
    const residue = binding.recoveryOfBindingId
      ? await tx.credentialResidue.findUnique({
          where: { bindingId: binding.recoveryOfBindingId },
          select: { id: true, clearedAt: true, recoverable: true },
        })
      : null;
    if (!residue || residue.clearedAt || !residue.recoverable) return f.reject("context_mismatch");
    residueId = residue.id;
  }
  const host = await tx.sandboxHost.findUniqueOrThrow({
    where: { id: s.hostId },
    select: { userId: true },
  });
  if (!lease.sandboxId || envelope.header.kidR !== s.kidR) return f.reject("context_mismatch");
  const expected: ReturnAad = {
    serverOrigin: s.serverOrigin,
    hostOwnerId: host.userId,
    hostId: s.hostId,
    sandboxOwnerId: lease.userId,
    sandboxId: lease.sandboxId,
    leaseId: lease.id,
    bindingId: binding.id,
    instanceId: lease.instanceId,
    credentialId: lease.credentialId,
    captureSeq: String(f.captureSeq),
    captureId: s.captureId,
    kind: s.kind,
    residueId,
  };
  const opened = await openCaptureEnvelope(tx, envelope, expected);
  if (!opened.ok) {
    if (opened.reason === "unavailable") return { outcome: "deferred" };
    return f.reject(opened.reason);
  }

  // 10-13. Validate, merge env, compare, baseline, insert.
  let result: Awaited<ReturnType<typeof commitCapturedValue>>;
  try {
    result = await commitCapturedValue(tx, login, lease.instanceId, {
      captured: opened.plaintext,
      kind: versionKind(s.kind),
      expectBaseSeq: s.kind === "checkpoint" ? undefined : lease.baseSeq,
      sourceLeaseId: lease.id,
    });
  } finally {
    opened.plaintext.fill(0);
  }
  switch (result.outcome) {
    case "invalid_bundle":
      return f.reject("invalid_bundle");
    case "incomplete":
      if (TEARDOWN_KINDS.has(s.kind)) {
        await tx.credentialInstance.update({
          where: { id: lease.instanceId },
          data: { state: "NEEDS_LOGIN", needsLoginReason: "files_missing" },
          select: { id: true },
        });
        await tx.credentialEvent.create({
          data: {
            userId: lease.userId,
            credentialId: lease.credentialId,
            accountId: lease.accountId,
            instanceId: lease.instanceId,
            leaseId: lease.id,
            sandboxId: lease.sandboxId,
            hostId: s.hostId,
            type: "needs_login",
            reason: "files_missing",
          },
          select: { id: true },
        });
      } else if (s.kind === "login" && lease.loginSessionId)
        await tx.credentialLoginSession.updateMany({
          where: { id: lease.loginSessionId, state: { in: ["READY", "SAVING"] } },
          data: { state: "FAILED" },
        });
      await f.discard("incomplete");
      await releaseIfTornDown(tx, lease);
      return { outcome: "discarded", reason: "incomplete" };
    case "superseded":
      await f.discard("superseded");
      await releaseIfTornDown(tx, lease);
      return { outcome: "discarded", reason: "superseded" };
    case "unchanged":
      // A re-login that captured exactly the current value still proves it:
      // a NEEDS_LOGIN instance with a current version becomes READY (§11).
      if (lease.kind === "LOGIN")
        await tx.credentialInstance.updateMany({
          where: { id: lease.instanceId, currentSeq: { not: null }, state: { not: "READY" } },
          data: { state: "READY", needsLoginReason: null },
        });
      await f.ledger("UNCHANGED", null, null);
      break;
    case "committed":
      if (s.kind !== "checkpoint")
        await tx.credentialLease.update({
          where: { id: lease.id },
          data: { baseSeq: result.storageSeq },
          select: { id: true },
        });
      await tx.credentialInstance.update({
        where: { id: lease.instanceId },
        data: { lastCapturedAt: new Date() },
        select: { id: true },
      });
      await f.ledger("COMMITTED", null, result.storageSeq);
      break;
  }
  // 14. Lease transition per §7.1.
  if (lease.kind === "LOGIN") {
    // Lease RELEASED, `loginLeaseId` cleared, session SAVED (finishLease).
    await finishLease(tx, lease.id, "RELEASED", LOGIN_SAVED_REASON);
    await tx.credentialEvent.create({
      data: {
        userId: lease.userId,
        credentialId: lease.credentialId,
        accountId: lease.accountId,
        instanceId: lease.instanceId,
        leaseId: lease.id,
        sandboxId: lease.sandboxId,
        hostId: s.hostId,
        type: "login_saved",
        ...(result.outcome === "committed"
          ? { storageSeq: result.storageSeq, sizeBytes: result.sizeBytes }
          : {}),
      },
      select: { id: true },
    });
  } else if (TEARDOWN_KINDS.has(s.kind)) await releaseIfTornDown(tx, lease);
  return { outcome: result.outcome };
}

/**
 * Runs the fence. Null when custody fails (the frame came on a stale
 * connection epoch): no ack is sent and nothing is written.
 */
export async function commitCapture(s: CaptureSubmission): Promise<CaptureAck | null> {
  if (!readVaultKeys()) return { outcome: "deferred" };
  try {
    const ack = await prisma.$transaction((tx) => fence(tx, s), { timeout: 30_000 });
    // §11 Save: only after the login value committed is its sandbox destroyed
    // (when the free that captured it already finished; else its result does).
    if (s.kind === "login" && (ack.outcome === "committed" || ack.outcome === "unchanged")) {
      const { destroySavedLoginSandbox } = await import("./login-relay");
      await destroySavedLoginSandbox({ leaseId: s.leaseId });
    }
    return ack;
  } catch (error) {
    if (error instanceof RelayFenceRejected) return null;
    // This process lacks the root the data-key epoch names (§4.6): nothing was
    // written; the host keeps the envelope and retries.
    if (error instanceof DataKeyStaleWriter) return { outcome: "deferred" };
    throw error;
  }
}
