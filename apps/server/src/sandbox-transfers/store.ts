import { createHash, randomUUID } from "node:crypto";
import { link, lstat, opendir, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "@wssp/api/lib/owner-credential-policy";
import { authorizeServiceAction } from "@wssp/api/lib/sdk-key-access";
import { idempotencyKey, type Principal } from "@wssp/api/sandbox/contracts";
import {
  lockHostForSandboxOperation,
  noteHostBlockerReleased,
} from "@wssp/api/sandbox/host-admission";
import { hashEnvFreeBody, requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import {
  operationDigestContext,
  operationTransaction,
  ownerKeyTransaction,
} from "@wssp/api/sandbox/operation-transaction";
import { createSandboxOutboxEvent, sandboxOutboxTransaction } from "@wssp/api/sandbox/outbox";
import {
  attributionOf,
  credentialExpiryOf,
  isBrowserSession,
  recordedKeyIdOf,
} from "@wssp/api/sandbox/principal-kinds";
import { lockTransferAdmission } from "@wssp/api/sandbox/result-locks";
import { resolveStoredPrincipal } from "@wssp/api/sandbox/stored-principal";
import {
  BUILD_CONTEXT_COMMIT_KEY,
  BUILD_CONTEXT_IMPORT_KEY,
} from "@wssp/api/template-builds/context-port";
import prisma, { type Prisma, type SandboxTransfer, type SandboxTransferState } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import {
  guestFilePathSchema,
  TRANSFER_CHUNK_BYTES,
  type TransferCreate,
  transferCreateSchema,
  transferIdSchema,
} from "@wssp/sandbox-contracts";
import {
  type CaptureChunk,
  type CaptureOwner,
  CaptureRefused,
  type CompletedCapture,
  type RelayCaptures,
} from "./captures.js";
import { checkChunk, checkReservation, type TransferLimits, transferError } from "./limits.js";
import {
  checkSpoolRoot,
  createSpoolRoot,
  digest,
  hashSpoolFile,
  ImportSourceError,
  missing,
  openImportSource,
  openSpoolFile,
  readFully,
  storageFailure,
  syncSpoolRoot,
  verifyAcknowledged,
  writeFully,
} from "./spool-io.js";

const keyId = (owner: Principal) => recordedKeyIdOf(owner);
const terminal = (state: SandboxTransferState) => ["ABORTED", "EXPIRED", "FAILED"].includes(state);
/** PUT_FILE outcomes after which the relay never reads the upload again (E-17).
 * UNKNOWN_OUTCOME is deliberately absent: an uncertain outcome keeps its slot
 * until the transfer's own expiry (C55). */
const SETTLED_OPERATION_STATES = ["SUCCEEDED", "FAILED", "CANCELLED"] as const;
// `slots` and `reapSettled` spell the same list in SQL; keep the three in sync.
/** Coverage bookkeeping per capture is bounded; past it, idle expiry settles. */
const COVERAGE_MAX_RANGES = 1024;
/**
 * How long a fully delivered capture stays readable (TQ-F1, decision D-3 (b)).
 * "Delivered" means the server handed the last bytes to the kernel, not that
 * the client has them, so a client that drops near the end can still resume
 * the tail. The content keeps charging the disk budget until it is retired.
 */
export const DELIVERED_GRACE_MS = 60_000;
function receipt(row: SandboxTransfer) {
  return {
    id: row.id,
    sandboxId: row.sandboxId,
    generation: row.generation,
    direction: row.direction,
    state: row.state,
    totalBytes: Number(row.totalBytes),
    receivedBytes: Number(row.receivedBytes),
    chunkBytes: TRANSFER_CHUNK_BYTES,
    idleExpiresAt: row.idleExpiresAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
  };
}

/** Single-server spool owner. Do not share its volume with another process.
 * DB admission order: owner -> idempotency key -> host -> sandbox -> quota -> transfer.
 * Per-transfer permits reject overlap rather than retaining waiting payloads. Disk IO
 * holds only that in-process permit, never a DB transaction or a host/sandbox lock.
 * Permits: an exclusive task (`run`) excludes every other task on its transfer;
 * sealed-content reads (`shared`) exclude only exclusive tasks, so parallel range
 * downloads of one immutable capture never conflict with each other (C30). Each
 * kind has its own `globalActive` budget of in-flight tasks; `close()` drains both.
 *
 * Slots vs disk (E-17): the disk budget charges every held reservation (its
 * spool may still exist). The owner/global ACTIVE-transfer slots count only
 * live transfers (see `slots`): a transfer gives its slot back the moment its
 * terminal state is durable — retirement, an upload whose PUT_FILE operation
 * settled, a capture whose every byte was delivered — and never while this
 * process still has bytes of it in flight. Idle expiry remains the fallback
 * for abandoned transfers only.
 *
 * Delivered captures (TQ-F1/F2): the last close of a fully delivered capture
 * starts a short grace (`graces`, `DELIVERED_GRACE_MS`) in the same tick, then
 * commits EXPIRED, which frees its slot. The spool stays, still charged to the
 * disk budget, so a resume within the grace is served. A stream opened during
 * the grace holds a slot of its own, admitted under the 270027 lock like any
 * new transfer, so graces never let an owner exceed `ownerActive`. Nothing
 * retires a spool automatically while a stream of it is open (`holds`); a
 * stream still open when the grace ends finishes first, then the capture is
 * retired.
 */
export class TransferStore implements RelayCaptures {
  private readonly root: string;
  private readonly work = new Map<string, Promise<unknown>>();
  private readonly readers = new Map<string, number>();
  private readonly reading = new Set<Promise<unknown>>();
  /** Open download response streams per capture (parallel ranges allowed). */
  private readonly streams = new Map<string, number>();
  /** The subset of `streams` counted as bytes in flight by `slots` (TQ-N1). */
  private readonly slotted = new Map<string, number>();
  /** Delivered captures whose content is kept for a resume (TQ-F1). `ended`:
   * the grace is over and the capture retires once its last stream closes. */
  private readonly graces = new Map<
    string,
    { timer?: ReturnType<typeof setTimeout>; ended: boolean }
  >();
  /** Delivered byte ranges per sealed capture, merged and sorted [start, end). */
  private readonly coverage = new Map<string, { ranges: [number, number][]; touched: boolean }>();
  /** Captures whose every byte was delivered; retired once their last stream closes. */
  private readonly delivered = new Set<string>();
  private readonly settling = new Set<Promise<void>>();
  private readonly creates = new Map<
    string,
    { hash: string; key: string | null; task: Promise<ReturnType<typeof receipt>> }
  >();
  private closed = true;
  private rootIdentity = "";
  private timer?: ReturnType<typeof setInterval>;
  private sweeping?: Promise<void>;
  private readonly graceMs: number;
  constructor(
    root: string,
    private readonly limits: TransferLimits,
  ) {
    this.root = resolve(root);
    if (Object.values(limits).some((v) => !Number.isSafeInteger(v) || v <= 0))
      throw new Error("Invalid transfer limits");
    this.graceMs = limits.deliveredGraceMs ?? DELIVERED_GRACE_MS;
  }
  private path(id: string) {
    return join(this.root, `${transferIdSchema.parse(id)}.spool`);
  }
  private async directory() {
    await checkSpoolRoot(this.root, this.rootIdentity);
  }
  private async syncDirectory() {
    await syncSpoolRoot(this.root, this.rootIdentity);
  }
  private async file(id: string, create = false) {
    return openSpoolFile(this.root, this.rootIdentity, this.path(id), create && "exclusive");
  }
  /** Startup finishes recovery before admission; shutdown drains every owned task. */
  async start() {
    if (!this.closed || this.rootIdentity) throw new Error("Transfer store already started");
    // No request chooses this path. Refuse symlinks in all configured components.
    this.rootIdentity = await createSpoolRoot(this.root);
    await this.directory();
    await this.recover();
    this.closed = false;
    this.timer = setInterval(() => {
      void this.sweep().catch(() =>
        console.error("[transfers] Cleanup incomplete; reservations retained for retry."),
      );
    }, 60_000);
    this.timer.unref();
  }
  async close() {
    this.closed = true;
    clearInterval(this.timer);
    // The kept content stays on disk; restart recovery retires terminal rows.
    for (const grace of this.graces.values()) clearTimeout(grace.timer);
    await Promise.allSettled([
      ...this.work.values(),
      ...this.reading,
      ...this.settling,
      this.sweeping,
    ]);
  }
  private busy(id: string) {
    return this.work.has(id) || this.readers.has(id);
  }
  /**
   * The one gate for automatic retirement (sweep, settle, discard, reap): a
   * task, a read, an open download stream or a delivery grace still needs this
   * spool (TQ-F2). Explicit abort and startup recovery do not consult it.
   */
  private holds(id: string) {
    return this.busy(id) || this.streams.has(id) || this.graces.has(id);
  }
  /**
   * Admission accounting, called under the 270027 admission lock (E-17).
   * `used` charges disk for every held reservation. `active`/`owned` count the
   * transfers that still hold an ACTIVE slot: held, non-terminal and not an
   * upload whose PUT_FILE operation durably settled — plus, regardless of
   * state, every transfer this single-server store has bytes in flight for
   * (a sealed-content read or an open download stream), so a slot is never
   * reusable while its bytes still move. Release is a
   * predicate over committed state, not a counter: it cannot run twice, and
   * it cannot precede the durability of the state it reads.
   */
  private async slots(tx: Prisma.TransactionClient, ownerId: string, self = "") {
    const held = await tx.sandboxTransfer.aggregate({
      where: { reservationHeld: true },
      _sum: { totalBytes: true },
    });
    // Bytes in flight are sealed-content reads and admitted download streams.
    // An admitted stream of a capture in its delivery grace is the only thing
    // that counts that (EXPIRED) capture. An exclusive task on a settled or
    // terminal row is only its own cleanup (retire/abort), which moves no
    // bytes; every other exclusive task (write, capture write, commit hashing)
    // runs on a row that is still live anyway.
    const inFlight = [...this.readers.keys(), ...this.slotted.keys()];
    const [live] = await tx.$queryRaw<{ active: number; owned: number; self: number }[]>`
      SELECT count(*)::int AS active,
             (count(*) FILTER (WHERE t."userId" = ${ownerId}))::int AS owned,
             (count(*) FILTER (WHERE t.id = ${self}))::int AS self
      FROM sandbox_stream_transfer t
      LEFT JOIN sandbox_mutation_operation o
        ON t.direction = 'UPLOAD' AND o.id = t."operationId"
      WHERE t."reservationHeld"
        AND (
          t.id = ANY(${inFlight}::text[])
          OR (
            t.state IN ('ALLOCATING', 'OPEN', 'SEALED')
            AND (o.state IS NULL OR o.state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))
          )
        )`;
    return {
      used: held._sum.totalBytes ?? 0n,
      active: live?.active ?? 0,
      owned: live?.owned ?? 0,
      self: (live?.self ?? 0) > 0,
    };
  }
  /** True when the row is an upload whose PUT_FILE operation durably settled. */
  private async uploadSettled(row: SandboxTransfer, tx: Prisma.TransactionClient = prisma) {
    if (row.direction !== "UPLOAD" || !row.operationId) return false;
    return (
      (await tx.sandboxOperation.count({
        where: { id: row.operationId, state: { in: [...SETTLED_OPERATION_STATES] } },
      })) > 0
    );
  }
  /**
   * Disk cleanup of one owner's settled uploads before a new admission (E-17).
   * Their slots are already free (`slots`); this only returns their disk
   * sooner than the sweep would. Best effort and bounded: a busy or failing
   * cleanup is left to the sweep.
   */
  private async reapSettled(ownerId: string) {
    const rows = await prisma.$queryRaw<{ id: string }[]>`
      SELECT t.id FROM sandbox_stream_transfer t
      JOIN sandbox_mutation_operation o ON o.id = t."operationId"
      WHERE t."userId" = ${ownerId}
        AND t."reservationHeld"
        AND t.direction = 'UPLOAD'
        AND o.state IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
      ORDER BY t.id
      LIMIT 32`;
    for (const { id } of rows) {
      if (this.closed || this.holds(id)) continue;
      await this.run(id, () => this.retire(id, "EXPIRED")).catch(() => undefined);
    }
  }
  /**
   * One download response stream of a sealed capture (C30 + E-17). The route
   * reports each chunk the consumer pulled past (`delivered`) and closes the
   * handle exactly when the response ends, errors or is cancelled. Once the
   * delivered ranges cover the whole capture and its last stream closed, the
   * capture is terminal: its delivery grace starts, durable EXPIRED follows
   * (its slot is free), and cleanup runs when the grace ends (TQ-F1).
   * An aborted or failed stream credits only what was pulled past, so the
   * capture stays resumable (`resumeDownload`) and holds its slot: its outcome
   * is uncertain until a resume completes it or idle expiry settles it.
   *
   * Registration is synchronous with the caller's `graces` check, and a grace
   * starts only on a last close, so a stream registered outside a grace keeps
   * one from starting until it closes (TQ-F2). `slotted` streams count in
   * `slots`; a stream opened during a grace is slotted only by `admitResume`.
   */
  private openStream(id: string, size: number, slotted: boolean) {
    this.streams.set(id, (this.streams.get(id) ?? 0) + 1);
    let open = true;
    let counted = false;
    const slot = () => {
      if (counted || !open) return;
      counted = true;
      this.slotted.set(id, (this.slotted.get(id) ?? 0) + 1);
    };
    if (slotted) slot();
    return {
      slot,
      delivered: (offset: number, length: number) => {
        if (open) this.credit(id, size, offset, offset + length);
      },
      close: () => {
        if (!open) return;
        open = false;
        if (counted) {
          const held = (this.slotted.get(id) ?? 1) - 1;
          if (held) this.slotted.set(id, held);
          else this.slotted.delete(id);
        }
        const left = (this.streams.get(id) ?? 1) - 1;
        if (left) {
          this.streams.set(id, left);
          return;
        }
        this.streams.delete(id);
        if (this.delivered.has(id)) this.beginGrace(id);
        else if (this.graces.get(id)?.ended) this.finishGrace(id);
        else if (this.coverage.has(id)) this.dropStaleCoverage(id);
      },
    };
  }
  private credit(id: string, size: number, start: number, end: number) {
    // A delivered or kept capture is already settled: nothing more to track,
    // and no entry may outlive its capture (TQ-F3).
    if (this.delivered.has(id) || this.graces.has(id)) return;
    const entry = this.coverage.get(id) ?? { ranges: [], touched: false };
    entry.touched = true;
    if (end > start) {
      const merged: [number, number][] = [];
      let next: [number, number] = [start, end];
      for (const range of entry.ranges) {
        if (range[1] < next[0] || range[0] > next[1]) merged.push(range);
        else next = [Math.min(range[0], next[0]), Math.max(range[1], next[1])];
      }
      merged.push(next);
      merged.sort((a, b) => a[0] - b[0]);
      // Unbounded fragmentation is never tracked: idle expiry settles it.
      if (merged.length > COVERAGE_MAX_RANGES) return;
      entry.ranges = merged;
    }
    this.coverage.set(id, entry);
    const [first] = entry.ranges;
    if (size === 0 || (entry.ranges.length === 1 && first![0] === 0 && first![1] >= size)) {
      this.coverage.delete(id);
      this.delivered.add(id);
    }
  }
  /** Coverage of a capture that was retired or aborted while a stream still
   * credited it is dropped once that stream closes (TQ-F3). A terminal or
   * released row never becomes SEALED again, so dropping it is always safe. */
  private dropStaleCoverage(id: string) {
    this.track(async () => {
      const row = await prisma.sandboxTransfer.findUnique({
        where: { id },
        select: { state: true, reservationHeld: true },
      });
      if (row?.state === "SEALED" && row.reservationHeld) return;
      if (!this.streams.has(id)) this.coverage.delete(id);
    });
  }
  private track(body: () => Promise<void>) {
    const task = body()
      .catch(() => undefined)
      .finally(() => {
        this.settling.delete(task);
      });
    this.settling.add(task);
  }
  /** Last close of a delivered capture: the grace starts in this same tick, so
   * any stream registered from now on takes the grace path (TQ-F2). */
  private beginGrace(id: string) {
    this.delivered.delete(id);
    const grace: { timer?: ReturnType<typeof setTimeout>; ended: boolean } = { ended: false };
    this.graces.set(id, grace);
    if (!this.closed) {
      grace.timer = setTimeout(() => this.endGrace(id), this.graceMs);
      grace.timer.unref?.();
    }
    // Durable terminal intent first: the slot is free from this commit on.
    this.track(async () => {
      await prisma.sandboxTransfer.updateMany({
        where: { id, direction: "DOWNLOAD", state: "SEALED" },
        data: { state: "EXPIRED" },
      });
    });
  }
  private endGrace(id: string) {
    const grace = this.graces.get(id);
    if (!grace) return;
    grace.ended = true;
    if (!this.streams.has(id)) this.finishGrace(id);
  }
  private finishGrace(id: string) {
    const grace = this.graces.get(id);
    clearTimeout(grace?.timer);
    this.graces.delete(id);
    this.track(async () => {
      // Repeated in case the grace's own EXPIRED write failed.
      await prisma.sandboxTransfer.updateMany({
        where: { id, direction: "DOWNLOAD", state: "SEALED" },
        data: { state: "EXPIRED" },
      });
      // A refused or failed cleanup is retried by the sweep (terminal and held).
      if (this.closed || this.holds(id)) return;
      await this.run(id, () => this.retire(id, "EXPIRED"));
    });
  }
  /**
   * A stream opened during a delivery grace needs a slot of its own: the
   * capture gave its slot back when EXPIRED committed. Same lock and budget as
   * a new transfer, so graces never let an owner exceed `ownerActive`. A
   * capture still counted (EXPIRED not yet committed, or another admitted
   * stream of it) already holds that slot, which this stream shares.
   */
  private async admitResume(owner: Principal, id: string, stream: { slot(): void }) {
    await prisma.$transaction(async (tx) => {
      await lockTransferAdmission(tx);
      const held = await this.slots(tx, owner.ownerId, id);
      // Its bytes are already charged to the disk budget.
      if (!held.self) checkReservation(0, this.limits, 0n, held.active, held.owned);
      // Counted before the lock is released: later admissions see this stream.
      stream.slot();
    });
  }
  private run<T>(id: string, body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(transferError("TRANSFER_IO"));
    if (this.busy(id)) return Promise.reject(transferError("CONFLICT"));
    if (this.work.size >= this.limits.globalActive)
      return Promise.reject(transferError("TRANSFER_QUOTA"));
    const task = Promise.resolve()
      .then(body)
      .finally(() => {
        this.work.delete(id);
      });
    this.work.set(id, task);
    return task;
  }
  /** Sealed-content reads: concurrent with each other, never with `run`. */
  private shared<T>(owner: Principal, id: string, body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(transferError("TRANSFER_IO"));
    if (this.work.has(id)) return Promise.reject(transferError("CONFLICT"));
    // A separate budget: in-flight reads never starve relay capture writes.
    if (this.reading.size >= this.limits.globalActive)
      return Promise.reject(transferError("TRANSFER_QUOTA"));
    this.readers.set(id, (this.readers.get(id) ?? 0) + 1);
    const task = Promise.resolve()
      .then(() => this.authorized(owner, body))
      .finally(() => {
        this.reading.delete(task);
        const left = (this.readers.get(id) ?? 1) - 1;
        if (left) this.readers.set(id, left);
        else this.readers.delete(id);
      });
    this.reading.add(task);
    return task;
  }
  private authorized<T>(owner: Principal, body: (check: () => void) => Promise<T>): Promise<T> {
    const credentialId = keyId(owner);
    const current = authorityTicket({
      ownerId: owner.ownerId,
      ...(credentialId !== null ? { credentialId } : {}),
    });
    const check = () => {
      if (!current()) throw transferError("FORBIDDEN");
      // Clock-based expiry moves no authority revision; fence it explicitly so a
      // chunk whose revalidation beat the deadline is never returned past it.
      const expiresAt = credentialExpiryOf(owner);
      if (expiresAt && expiresAt.getTime() <= Date.now()) throw transferError("FORBIDDEN");
    };
    return body(check).then(
      (value) => {
        check();
        return value;
      },
      (error: unknown) => {
        check();
        if (storageFailure(error)) throw transferError("TRANSFER_IO");
        throw error;
      },
    );
  }
  private ownerRun<T>(owner: Principal, id: string, body: (check: () => void) => Promise<T>) {
    return this.run(id, () => this.authorized(owner, body));
  }
  /** Browser-policy revalidation at chunk boundaries (C27/C30): a session
   * principal's ban, archival or required-2FA change must stop its stream even
   * where session principals skip per-action policy checks. */
  private async assertSessionOwnerActive(owner: Principal) {
    if (!isBrowserSession(owner)) return;
    const user = await prisma.user.findFirst({
      where: { id: owner.ownerId },
      select: ownerCredentialPolicyUserSelect,
    });
    if (!user || !(await isOwnerCredentialPolicySatisfied(user))) throw transferError("FORBIDDEN");
  }
  /** One ticket sampled when a byte source opens, checked around EVERY chunk:
   * an authority change committed between chunks invalidates the stream, which
   * a freshly re-sampled per-chunk ticket would silently accept (C27/C30). */
  private streamTicket(owner: Principal): () => boolean {
    const credentialId = keyId(owner);
    return authorityTicket({
      ownerId: owner.ownerId,
      ...(credentialId !== null ? { credentialId } : {}),
    });
  }
  private async owned(owner: Principal, id: string, tx: Prisma.TransactionClient = prisma) {
    if (!transferIdSchema.safeParse(id).success) throw transferError("BAD_REQUEST");
    const row = await tx.sandboxTransfer.findFirst({
      where: { id, userId: owner.ownerId, keyId: keyId(owner) },
    });
    if (!row) throw transferError("NOT_FOUND");
    await authorizeServiceAction(
      owner,
      row.direction === "UPLOAD" ? "files.write" : "files.read",
      { sandboxId: row.sandboxId },
      tx,
    );
    return row;
  }
  /** A delivered capture in its grace (TQ-F1): readable although EXPIRED. */
  private kept(row: SandboxTransfer) {
    return (
      row.direction === "DOWNLOAD" &&
      ["SEALED", "EXPIRED"].includes(row.state) &&
      this.graces.has(row.id)
    );
  }
  private async current(
    row: SandboxTransfer,
    tx: Prisma.TransactionClient = prisma,
    graced = false,
  ) {
    if (
      (terminal(row.state) && !(graced && this.kept(row))) ||
      !row.reservationHeld ||
      row.idleExpiresAt <= new Date() ||
      row.expiresAt <= new Date()
    )
      throw transferError("TRANSFER_EXPIRED");
    const sandbox = await tx.sandbox.findFirst({
      where: {
        id: row.sandboxId,
        userId: row.userId,
        generation: row.generation,
        state: "READY",
        OR: [{ leaseExpiresAt: null }, { leaseExpiresAt: { gt: new Date() } }],
      },
      select: { id: true },
    });
    if (!sandbox) throw transferError("CONFLICT");
  }
  private async transaction<T>(
    owner: Principal,
    id: string,
    body: (tx: Prisma.TransactionClient, row: SandboxTransfer) => Promise<T>,
  ) {
    return prisma.$transaction(async (tx) => {
      const prior = await this.owned(owner, id, tx);
      const sandbox = await tx.sandbox.findUniqueOrThrow({
        where: { id: prior.sandboxId },
        select: { id: true, sandboxHostId: true },
      });
      await lockHostForSandboxOperation(tx, sandbox.sandboxHostId, owner.ownerId, sandbox.id);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${prior.sandboxId} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${id} FOR UPDATE`;
      const row = await this.owned(owner, id, tx);
      return body(tx, row);
    });
  }
  async create(owner: Principal, input: TransferCreate) {
    if (this.closed) throw transferError("TRANSFER_IO");
    const validation = transferCreateSchema.safeParse(input);
    if (!validation.success || !idempotencyKey.safeParse(validation.data.idempotencyKey).success)
      throw transferError("BAD_REQUEST");
    const parsed = validation.data;
    const action = parsed.direction === "UPLOAD" ? "files.write" : "files.read";
    const hash = hashEnvFreeBody(parsed);
    const permit = `create:${owner.ownerId}:${parsed.idempotencyKey}`;
    const creating = this.creates.get(permit);
    if (creating) {
      return this.ownerRun(owner, `retry:${randomUUID()}`, async () => {
        await authorizeServiceAction(owner, action, { sandboxId: parsed.sandboxId });
        if (creating.hash !== hash || creating.key !== keyId(owner))
          throw transferError("CONFLICT");
        const row = await creating.task;
        return receipt(await this.owned(owner, row.id));
      });
    }
    const task = this.ownerRun(owner, permit, async () => {
      await this.reapSettled(owner.ownerId).catch(() => undefined);
      const row = await ownerKeyTransaction(
        owner,
        parsed.idempotencyKey,
        async (tx) => {
          await authorizeServiceAction(owner, action, { sandboxId: parsed.sandboxId }, tx);
          if (
            (await tx.sandboxOperation.findUnique({
              where: {
                userId_idempotencyKey: {
                  userId: owner.ownerId,
                  idempotencyKey: parsed.idempotencyKey,
                },
              },
              select: { id: true },
            })) ||
            (await tx.sandboxActionReceipt.findUnique({
              where: {
                userId_idempotencyKey: {
                  userId: owner.ownerId,
                  idempotencyKey: parsed.idempotencyKey,
                },
              },
              select: { id: true },
            }))
          )
            throw transferError("CONFLICT");
          const prior = await tx.sandboxTransfer.findUnique({
            where: {
              userId_idempotencyKey: {
                userId: owner.ownerId,
                idempotencyKey: parsed.idempotencyKey,
              },
            },
          });
          if (!prior) return null;
          if (prior.keyId !== keyId(owner) || prior.requestBodyHash !== hash)
            throw transferError("CONFLICT");
          return { value: prior };
        },
        async (tx) => {
          const sandbox = await tx.sandbox.findFirst({
            where: { id: parsed.sandboxId, userId: owner.ownerId },
            select: { id: true, sandboxHostId: true },
          });
          if (!sandbox) throw transferError("NOT_FOUND");
          if (!sandbox.sandboxHostId) throw transferError("CONFLICT");
          await lockHostForSandboxOperation(tx, sandbox.sandboxHostId, owner.ownerId, sandbox.id);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${parsed.sandboxId} FOR UPDATE`;
          const live = await tx.sandbox.findUniqueOrThrow({
            where: { id: parsed.sandboxId },
            select: { generation: true, state: true, leaseExpiresAt: true },
          });
          if (live.state !== "READY" || (live.leaseExpiresAt && live.leaseExpiresAt <= new Date()))
            throw transferError("CONFLICT");
          await lockTransferAdmission(tx);
          const held = await this.slots(tx, owner.ownerId);
          checkReservation(parsed.totalBytes, this.limits, held.used, held.active, held.owned);
          const now = Date.now();
          return tx.sandboxTransfer.create({
            data: {
              id: randomUUID(),
              userId: owner.ownerId,
              keyId: keyId(owner),
              // Offload §8.10: the transport host at acceptance.
              acceptedHostId: sandbox.sandboxHostId,
              ...parsed,
              requestBodyHash: hash,
              generation: live.generation,
              totalBytes: BigInt(parsed.totalBytes),
              idleExpiresAt: new Date(now + this.limits.idleMs),
              expiresAt: new Date(now + this.limits.absoluteMs),
            },
          });
        },
        "transfer",
      );
      if (row.state === "ALLOCATING") {
        try {
          const file = await this.file(row.id, true);
          try {
            await file.sync();
          } finally {
            await file.close();
          }
          await this.syncDirectory();
          await this.transaction(owner, row.id, async (tx, latest) => {
            await this.current(latest, tx);
            await tx.sandboxTransfer.update({ where: { id: row.id }, data: { state: "OPEN" } });
          });
        } catch (error) {
          await this.retire(row.id, "FAILED");
          throw error;
        }
      }
      return receipt(await this.owned(owner, row.id));
    });
    this.creates.set(permit, { hash, key: keyId(owner), task });
    try {
      return await task;
    } finally {
      this.creates.delete(permit);
    }
  }
  /**
   * Adopts a sealed file staged by a sibling store as an ordinary SEALED upload of a READY
   * sandbox. The transfer store stays the only writer of its root, rows, chunk
   * rows and admission:
   * 1. tx1 (the `create` shape): authorize `files.write`, replay by key, then
   *    normal slot/disk admission and an ALLOCATING row with every chunk row.
   * 2. Open the source with this store's file checks, `link` it to our spool
   *    name (copy + fsync across devices), fsync our root.
   * 3. tx2: re-check `current`, mark SEALED and call `onSealed(tx, id)` in
   *    the same transaction (the caller marks its own row adopted).
   * 4. Unlink the source name and fsync its root: our file has one name again.
   * Crash after tx1: `recover` retires the ALLOCATING row and unlinks only
   * our name; the replay returns `{stale: true}` and the caller retries with a
   * new key. Crash after tx2: the caller's recovery (before ours) unlinks the
   * source, so `recover` never sees a second name. A replay of a SEALED
   * import repeats step 4 and returns the same transfer.
   */
  async importSealed(
    owner: Principal,
    input: {
      sandboxId: string;
      generation: number;
      idempotencyKey: string;
      guestPath: string;
      sha256: string;
      totalBytes: number;
      chunks: { offset: number; length: number; digest: string }[];
      source: { root: string; name: string };
      onSealed: (tx: Prisma.TransactionClient, transferId: string) => Promise<void>;
    },
  ): Promise<{ stale: true } | { stale: false; transferId: string }> {
    if (this.closed) throw transferError("TRANSFER_IO");
    const { sandboxId, generation, guestPath, sha256, totalBytes, chunks, source } = input;
    const key = input.idempotencyKey;
    if (
      !BUILD_CONTEXT_IMPORT_KEY.test(key) ||
      !/^[a-f0-9]{64}$/.test(sha256) ||
      !Number.isSafeInteger(generation) ||
      generation < 1 ||
      !Number.isSafeInteger(totalBytes) ||
      totalBytes <= 0 ||
      !guestFilePathSchema.safeParse(guestPath).success ||
      typeof sandboxId !== "string" ||
      sandboxId.length < 1 ||
      sandboxId.length > 128 ||
      chunks.length !== Math.ceil(totalBytes / TRANSFER_CHUNK_BYTES) ||
      chunks.some(
        (chunk, index) =>
          chunk.offset !== index * TRANSFER_CHUNK_BYTES ||
          chunk.length !== Math.min(TRANSFER_CHUNK_BYTES, totalBytes - chunk.offset) ||
          !/^[a-f0-9]{64}$/.test(chunk.digest),
      )
    )
      throw transferError("BAD_REQUEST");
    const hash = hashEnvFreeBody({
      kind: "import",
      sandboxId,
      generation,
      guestPath,
      sha256,
      totalBytes,
    });
    const sourceRoot = resolve(source.root);
    return this.ownerRun(owner, `import:${owner.ownerId}:${key}`, async () => {
      const { row, fresh } = await ownerKeyTransaction(
        owner,
        key,
        async (tx) => {
          await authorizeServiceAction(owner, "files.write", { sandboxId }, tx);
          const prior = await tx.sandboxTransfer.findUnique({
            where: { userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: key } },
          });
          if (!prior) return null;
          if (prior.keyId !== keyId(owner) || prior.requestBodyHash !== hash)
            throw transferError("CONFLICT");
          return { value: { row: prior, fresh: false } };
        },
        async (tx) => {
          const sandbox = await tx.sandbox.findFirst({
            where: { id: sandboxId, userId: owner.ownerId },
            select: { id: true, sandboxHostId: true },
          });
          if (!sandbox) throw transferError("NOT_FOUND");
          if (!sandbox.sandboxHostId) throw transferError("CONFLICT");
          await lockHostForSandboxOperation(tx, sandbox.sandboxHostId, owner.ownerId, sandbox.id);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
          const live = await tx.sandbox.findUniqueOrThrow({
            where: { id: sandboxId },
            select: { generation: true, state: true, leaseExpiresAt: true },
          });
          if (
            live.state !== "READY" ||
            live.generation !== generation ||
            (live.leaseExpiresAt && live.leaseExpiresAt <= new Date())
          )
            throw transferError("CONFLICT");
          await lockTransferAdmission(tx);
          const held = await this.slots(tx, owner.ownerId);
          checkReservation(totalBytes, this.limits, held.used, held.active, held.owned);
          const now = Date.now();
          const created = await tx.sandboxTransfer.create({
            data: {
              id: randomUUID(),
              userId: owner.ownerId,
              keyId: keyId(owner),
              // Offload §8.10: the transport host at acceptance.
              acceptedHostId: sandbox.sandboxHostId,
              sandboxId,
              generation,
              direction: "UPLOAD",
              guestPath,
              idempotencyKey: key,
              requestBodyHash: hash,
              totalBytes: BigInt(totalBytes),
              idleExpiresAt: new Date(now + this.limits.idleMs),
              expiresAt: new Date(now + this.limits.absoluteMs),
            },
          });
          await tx.sandboxTransferChunk.createMany({
            data: chunks.map((chunk) => ({
              transferId: created.id,
              offset: BigInt(chunk.offset),
              length: chunk.length,
              digest: chunk.digest,
            })),
          });
          return { row: created, fresh: true };
        },
        "transfer",
      );
      if (!fresh) {
        // A committed or sealed import is the same transfer; anything else
        // (ALLOCATING left by a crash, or retired) is spent: new key.
        if (row.state !== "SEALED" || !row.reservationHeld) return { stale: true };
        await this.unlinkImportSource(sourceRoot, source.name);
        return { stale: false, transferId: row.id };
      }
      const id = row.id;
      try {
        const opened = await openImportSource(sourceRoot, source.name, totalBytes);
        try {
          await this.directory();
          try {
            await link(join(sourceRoot, source.name), this.path(id));
            // The name we linked is the inode we validated (no swap between).
            const linked = await lstat(this.path(id));
            if (linked.dev !== opened.stat.dev || linked.ino !== opened.stat.ino)
              throw transferError("TRANSFER_IO");
          } catch (error) {
            if (!(error instanceof Error && "code" in error && error.code === "EXDEV")) throw error;
            // The spool root is a different filesystem: copy, then fsync.
            const file = await this.file(id, true);
            try {
              const buffer = Buffer.alloc(TRANSFER_CHUNK_BYTES);
              for (const chunk of chunks) {
                const bytes = await readFully(
                  opened.file,
                  buffer.subarray(0, chunk.length),
                  chunk.offset,
                );
                if (digest(bytes) !== chunk.digest) throw new ImportSourceError("invalid");
                await writeFully(file, bytes, chunk.offset);
              }
              await file.sync();
            } finally {
              await file.close();
            }
          }
        } finally {
          await opened.file.close();
        }
        await this.syncDirectory();
        await this.transaction(owner, id, async (tx, latest) => {
          await this.current(latest, tx);
          if (latest.state !== "ALLOCATING") throw transferError("CONFLICT");
          await tx.sandboxTransfer.update({
            where: { id },
            data: { state: "SEALED", receivedBytes: BigInt(totalBytes), sha256 },
          });
          await input.onSealed(tx, id);
        });
      } catch (error) {
        // Retire only what never sealed: a tx2 whose commit outcome was lost
        // may have sealed (and adopted) after all.
        const latest = await prisma.sandboxTransfer
          .findUnique({ where: { id }, select: { state: true } })
          .catch(() => null);
        if (latest?.state !== "SEALED") {
          await this.retire(id, "FAILED").catch(() => undefined);
          throw error;
        }
      }
      await this.unlinkImportSource(sourceRoot, source.name);
      return { stale: false, transferId: id };
    });
  }
  /** Step 4 of `importSealed`: the source name goes, then its root is synced. */
  private async unlinkImportSource(root: string, name: string) {
    await checkSpoolRoot(root, null);
    try {
      await unlink(join(root, name));
    } catch (error) {
      if (!missing(error)) throw error;
    }
    await syncSpoolRoot(root, null);
  }
  /** Metadata-only status reads hold no permit: they never block an exclusive
   * task and never CONFLICT a sealed-content read the relay is streaming (C29).
   * HTTP admission and SDK budgets bound their concurrency at the edge. */
  private peek<T>(owner: Principal, body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(transferError("TRANSFER_IO"));
    return this.authorized(owner, body);
  }
  async status(owner: Principal, id: string) {
    return this.peek(owner, async () => receipt(await this.owned(owner, id)));
  }
  async write(
    owner: Principal,
    id: string,
    offset: number,
    bytes: Uint8Array,
    /** Optional caller-side digest; the store always hashes its own copy. */
    expectedDigest?: string,
  ) {
    // Reject before capturing/copying request bytes in an asynchronous task.
    if (bytes.byteLength > TRANSFER_CHUNK_BYTES) throw transferError("PAYLOAD_TOO_LARGE");
    return this.ownerRun(owner, id, async () => {
      bytes = Buffer.from(bytes);
      const row = await this.owned(owner, id);
      await this.current(row);
      checkChunk(Number(row.totalBytes), offset, bytes.byteLength);
      const actualDigest = digest(bytes);
      if (expectedDigest !== undefined && actualDigest !== expectedDigest)
        throw transferError("BAD_REQUEST");
      const old = await prisma.sandboxTransferChunk.findUnique({
        where: { transferId_offset: { transferId: id, offset: BigInt(offset) } },
      });
      if (old) {
        if (old.digest !== actualDigest || old.length !== bytes.byteLength)
          throw transferError("CONFLICT");
        return receipt(await this.owned(owner, id));
      }
      if (row.state !== "OPEN" || BigInt(offset) !== row.receivedBytes)
        throw transferError("CONFLICT");
      try {
        const file = await this.file(id);
        try {
          // A prior DB rollback/crash may have left an unacknowledged tail.
          await file.truncate(offset);
          await writeFully(file, bytes, offset);
          await file.sync();
        } finally {
          await file.close();
        }
      } catch {
        await this.retire(id, "FAILED");
        throw transferError("TRANSFER_IO");
      }
      const updated = await this.transaction(owner, id, async (tx, latest) => {
        await this.current(latest, tx);
        if (latest.state !== "OPEN" || latest.receivedBytes !== BigInt(offset))
          throw transferError("CONFLICT");
        await tx.sandboxTransferChunk.create({
          data: {
            transferId: id,
            offset: BigInt(offset),
            length: bytes.byteLength,
            digest: actualDigest,
          },
        });
        return tx.sandboxTransfer.update({
          where: { id },
          data: {
            receivedBytes: BigInt(offset + bytes.byteLength),
            idleExpiresAt: new Date(
              Math.min(Date.now() + this.limits.idleMs, latest.expiresAt.getTime()),
            ),
          },
        });
      });
      await this.owned(owner, id);
      return receipt(updated);
    });
  }
  /** Commit intent, operation and outbox are atomic; hashing holds only the
   * local transfer permit. Replays use the recorded generation after expiry. */
  async commit(owner: Principal, id: string, key: string, sha256: string, internal = false) {
    // `internal`: the build-context port's reserved `tb:` commit key (§3.7);
    // every route passes a public key, which the public schema validates.
    const keyValid = internal
      ? BUILD_CONTEXT_COMMIT_KEY.test(key)
      : idempotencyKey.safeParse(key).success;
    if (!keyValid || !/^[a-f0-9]{64}$/.test(sha256)) throw transferError("BAD_REQUEST");
    return this.ownerRun(owner, id, async (check) => {
      const row = await this.owned(owner, id);
      if (row.direction !== "UPLOAD") throw transferError("NOT_FOUND");
      if (!row.operationId) {
        await this.current(row);
        if (!["OPEN", "SEALED"].includes(row.state) || row.receivedBytes !== row.totalBytes)
          throw transferError("CONFLICT");
        const file = await this.file(id);
        let whole: string;
        try {
          whole = await hashSpoolFile(file, Number(row.totalBytes));
        } finally {
          await file.close();
        }
        if (whole !== sha256) throw transferError("BAD_REQUEST");
      }
      const operation = await operationTransaction(
        owner,
        {
          key,
          intent: { transferId: id, sha256 },
          kind: "PUT_FILE",
          action: "files.write",
          target: { sandboxId: row.sandboxId },
        },
        async (tx, hash) => {
          const sandbox = await tx.sandbox.findUniqueOrThrow({
            where: { id: row.sandboxId },
            select: { id: true, sandboxHostId: true },
          });
          await lockHostForSandboxOperation(tx, sandbox.sandboxHostId, owner.ownerId, sandbox.id);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${row.sandboxId} FOR UPDATE`;
          const operation = await tx.sandboxOperation.create({
            data: {
              userId: owner.ownerId,
              authorizingKeyId: keyId(owner),
              sandboxId: row.sandboxId,
              generation: row.generation,
              kind: "PUT_FILE",
              state: "QUEUED",
              idempotencyKey: key,
              requestBodyHash: hash(),
              ...requestDigestMetadata(),
              digestContext: operationDigestContext(tx),
            },
          });
          await createSandboxOutboxEvent(tx, {
            userId: owner.ownerId,
            authorizingPrincipal: attributionOf(owner),
            aggregateId: row.sandboxId,
            eventType: "sandbox.file_put_requested",
            payload: {
              sandboxId: row.sandboxId,
              sandboxHostId: sandbox.sandboxHostId,
              generation: row.generation,
              operationId: operation.id,
              dispatchAttempt: 0,
              idempotencyKey: key,
              kind: "file.put",
              incusName: `wssp-sbx-${row.sandboxId}`,
              path: row.guestPath,
              transferId: id,
            },
          });
          await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${id} FOR UPDATE`;
          const latest = await this.owned(owner, id, tx);
          await this.current(latest, tx);
          if (
            latest.operationId ||
            !["OPEN", "SEALED"].includes(latest.state) ||
            latest.receivedBytes !== latest.totalBytes
          )
            throw transferError("CONFLICT");
          await tx.sandboxTransfer.update({
            where: { id },
            data: { state: "SEALED", sha256, operationId: operation.id },
          });
          // Authorize BEFORE this transaction commits: an authority change
          // observed here rolls the operation back, so a 403/404 never conceals
          // a durable commit. (A change landing after this check but before the
          // commit's durability point is still possible; the post-commit check
          // stays, and clients treat that 403/404 as MAYBE_AFTER_COMMIT and
          // recover the receipt by replaying the idempotency key.)
          check();
          return operation;
        },
        async (tx, prior) => {
          const latest = await this.owned(owner, id, tx);
          if (latest.operationId !== prior.id) throw transferError("CONFLICT");
          return prior;
        },
      );
      await this.owned(owner, id);
      return { operationId: operation.id, state: operation.state };
    });
  }
  /** The relay calls only after durable dispatch admission; every read retains
   * transfer ownership, live key scope and generation/expiry checks. */
  async uploadSource(id: string, operationId: string) {
    const row = await prisma.sandboxTransfer.findFirst({
      where: { id, operationId, direction: "UPLOAD", state: "SEALED" },
    });
    if (!row?.sha256) throw transferError("TRANSFER_EXPIRED");
    // R1: the build fact comes from the sandbox, checked first,
    // so a build's context upload streams under the build principal.
    const sandbox = await prisma.sandbox.findFirst({
      where: { id: row.sandboxId, userId: row.userId },
      select: { buildId: true, verifyBuildId: true },
    });
    if (!sandbox) throw transferError("TRANSFER_EXPIRED");
    const owner = await resolveStoredPrincipal(prisma, {
      userId: row.userId,
      authorizingKeyId: row.keyId,
      sandboxBuildId: sandbox.buildId,
      sandboxVerifyBuildId: sandbox.verifyBuildId,
    });
    if (!owner) throw transferError("FORBIDDEN");
    await this.owned(owner, id);
    await this.current(row);
    const streaming = this.streamTicket(owner);
    return {
      size: Number(row.totalBytes),
      sha256: row.sha256,
      read: async (offset: number, length: number) => {
        if (!streaming()) throw transferError("FORBIDDEN");
        await this.assertSessionOwnerActive(owner);
        // Once the PUT_FILE operation settled its slot is free (E-17): no
        // further byte of this upload may leave the store.
        const bytes = await this.read(owner, id, offset, length, async (latest) => {
          if (await this.uploadSettled(latest)) throw transferError("TRANSFER_EXPIRED");
        });
        if (!streaming()) throw transferError("FORBIDDEN");
        return bytes;
      },
    };
  }
  /**
   * A completed GET_FILE capture as a ranged source (C30). Authority is the
   * operation's own: owner, originating credential (session or the requesting
   * key), `operations:read` + `files:read` and current resource grants. Every
   * `read` repeats the transfer's live authorization, expiry and generation checks.
   */
  async downloadSource(owner: Principal, operationId: string) {
    if (this.closed) throw transferError("TRANSFER_IO");
    await authorizeServiceAction(owner, "operations.downloadFile", { operationId });
    const operation = await prisma.sandboxOperation.findFirst({
      where: { id: operationId, userId: owner.ownerId },
      select: { kind: true, state: true, result: true, authorizingKeyId: true },
    });
    if (operation?.kind !== "GET_FILE" || operation.authorizingKeyId !== keyId(owner))
      throw transferError("NOT_FOUND");
    if (["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"].includes(operation.state))
      throw transferError("TRANSFER_NOT_READY");
    if (operation.state !== "SUCCEEDED") throw transferError("CONFLICT");
    const result = operation.result;
    const transferId =
      result && typeof result === "object" && !Array.isArray(result) ? result.transferId : null;
    if (typeof transferId !== "string" || !transferIdSchema.safeParse(transferId).success)
      throw transferError("TRANSFER_EXPIRED");
    const row = await this.owned(owner, transferId);
    if (row.direction !== "DOWNLOAD" || row.operationId !== operationId)
      throw transferError("NOT_FOUND");
    if (row.sha256 == null) throw transferError("TRANSFER_EXPIRED");
    // The grace check and the registration are one synchronous step (TQ-F2):
    // outside a grace, this open stream keeps one from starting (a grace
    // starts only on a last close), so delivery never retires under it.
    const grace = this.graces.get(transferId);
    if (grace?.ended || (!grace && row.state !== "SEALED")) throw transferError("TRANSFER_EXPIRED");
    const stream = this.openStream(transferId, Number(row.totalBytes), !grace);
    let latest: SandboxTransfer;
    try {
      if (grace) await this.admitResume(owner, transferId, stream);
      // Re-read after registering: the row seen above may predate a settlement.
      latest = await this.owned(owner, transferId);
    } catch (error) {
      stream.close();
      throw error;
    }
    try {
      if (!grace && latest.state !== "SEALED") throw transferError("TRANSFER_EXPIRED");
      await this.current(latest, prisma, Boolean(grace));
    } catch {
      stream.close();
      // Content of an ended generation or a stopped/deleted sandbox is gone for
      // good; the operation receipt remains.
      throw transferError("TRANSFER_EXPIRED");
    }
    const streaming = this.streamTicket(owner);
    return {
      size: Number(row.totalBytes),
      sha256: row.sha256,
      guestPath: row.guestPath,
      read: async (offset: number, length: number) => {
        if (!streaming()) throw transferError("FORBIDDEN");
        await this.assertSessionOwnerActive(owner);
        const bytes = await this.read(owner, transferId, offset, length);
        if (!streaming()) throw transferError("FORBIDDEN");
        return bytes;
      },
      delivered: stream.delivered,
      close: stream.close,
    };
  }
  /** Sealing only freezes the spool. Guest commit/relay is owned by C28-C30. */
  async seal(owner: Principal, id: string) {
    return this.ownerRun(owner, id, async () =>
      receipt(
        await this.transaction(owner, id, async (tx, row) => {
          await this.current(row, tx);
          if (!["OPEN", "SEALED"].includes(row.state) || row.receivedBytes !== row.totalBytes)
            throw transferError("CONFLICT");
          return tx.sandboxTransfer.update({ where: { id }, data: { state: "SEALED" } });
        }),
      ),
    );
  }
  async read(
    owner: Principal,
    id: string,
    offset: number,
    length: number,
    guard?: (row: SandboxTransfer) => Promise<void>,
  ) {
    return this.shared(owner, id, async () => {
      const row = await this.owned(owner, id);
      const graced = this.kept(row);
      await this.current(row, prisma, graced);
      await guard?.(row);
      if (
        (row.state !== "SEALED" && !graced) ||
        !Number.isSafeInteger(offset) ||
        !Number.isSafeInteger(length) ||
        offset < 0 ||
        length < 0 ||
        length > TRANSFER_CHUNK_BYTES ||
        offset + length > Number(row.totalBytes)
      )
        throw transferError("BAD_REQUEST");
      const file = await this.file(id);
      const bytes = Buffer.alloc(length);
      try {
        await readFully(file, bytes, offset);
      } finally {
        await file.close();
      }
      await this.transaction(owner, id, async (tx, latest) => {
        await this.current(latest, tx, graced);
        await tx.sandboxTransfer.update({
          where: { id },
          data: {
            idleExpiresAt: new Date(
              Math.min(Date.now() + this.limits.idleMs, latest.expiresAt.getTime()),
            ),
          },
        });
      });
      return bytes;
    });
  }
  async abort(owner: Principal, id: string) {
    return this.ownerRun(owner, id, async () => {
      await this.transaction(owner, id, async (tx, row) => {
        if (row.direction === "UPLOAD" && row.operationId) throw transferError("CONFLICT");
        await tx.sandboxTransfer.updateMany({
          where: { id, state: { in: ["ALLOCATING", "OPEN", "SEALED"] } },
          data: { state: "ABORTED" },
        });
      });
      await this.retire(id, "ABORTED");
      return receipt(await this.owned(owner, id));
    });
  }
  private async retire(id: string, state: "ABORTED" | "EXPIRED" | "FAILED") {
    // Durable terminal intent BEFORE unlink. Failed cleanup keeps charging disk
    // (the slot is already free: `slots` counts only non-terminal transfers).
    await prisma.sandboxTransfer.updateMany({
      where: { id, state: { in: ["ALLOCATING", "OPEN", "SEALED"] } },
      data: { state },
    });
    this.coverage.delete(id);
    this.delivered.delete(id);
    clearTimeout(this.graces.get(id)?.timer);
    this.graces.delete(id);
    await this.directory();
    try {
      await unlink(this.path(id));
    } catch (error) {
      if (!missing(error)) throw error;
    }
    await this.syncDirectory();
    await sandboxOutboxTransaction(async (tx) => {
      const row = await tx.sandboxTransfer.findUniqueOrThrow({
        where: { id },
        select: {
          sandboxId: true,
          userId: true,
          acceptedHostId: true,
        },
      });
      // Offload §8.10: release the blocker on the proven acceptance host,
      // even after the sandbox's current placement has detached.
      const host = await tx.sandboxHost.findFirst({
        where: { id: row.acceptedHostId, userId: row.userId },
        select: { id: true },
      });
      const hostId = host?.id;
      await lockHostForSandboxOperation(tx, hostId, row.userId, row.sandboxId);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${row.sandboxId} FOR UPDATE`;
      await tx.sandboxTransferChunk.deleteMany({ where: { transferId: id } });
      await tx.sandboxTransfer.updateMany({
        where: { id, reservationHeld: true, state: { in: ["ABORTED", "EXPIRED", "FAILED"] } },
        data: { reservationHeld: false },
      });
      noteHostBlockerReleased(tx, hostId, row.userId);
    });
  }
  private expired(row: SandboxTransfer, now = new Date()) {
    return (
      terminal(row.state) ||
      !row.reservationHeld ||
      row.idleExpiresAt <= now ||
      row.expiresAt <= now
    );
  }
  /**
   * Relay download capture admission (C28), called INSIDE the fenced relay
   * transaction (H -> S -> O already locked; the transfer row is locked last).
   * Captures share this store's persistent metadata, disk reservation, limits,
   * expiry and shutdown with user transfer sessions. A new capture reserves the
   * configured per-transfer maximum (its length is unknown until the final
   * chunk) and shrinks to the real length when sealed. Returns the post-commit
   * disk step, or null for an identical replay of an already committed chunk.
   */
  async admitCapture(
    tx: Prisma.TransactionClient,
    owner: CaptureOwner,
    chunk: CaptureChunk,
  ): Promise<(() => Promise<void>) | null> {
    if (this.closed) throw transferError("TRANSFER_IO");
    const { operationId, attempt, sequence, offset, body, ended } = chunk;
    if (
      !Number.isSafeInteger(sequence) ||
      sequence < 0 ||
      offset !== sequence * TRANSFER_CHUNK_BYTES ||
      body.byteLength > TRANSFER_CHUNK_BYTES ||
      (!ended && body.byteLength !== TRANSFER_CHUNK_BYTES) ||
      (ended && body.byteLength === 0 && offset !== 0)
    )
      throw new CaptureRefused(
        "protocol_error",
        "File chunk gap, size or final marker is invalid.",
      );
    if (offset + body.byteLength > this.limits.maxBytes)
      throw new CaptureRefused("request_too_large", "Downloaded file exceeds the transfer cap.");
    const chunkDigest = digest(body);
    const key = { operationId, operationAttempt: attempt };
    // Locate by key (id only), lock, then read the full row under the lock.
    const located = await tx.sandboxTransfer.findUnique({
      where: { operationId_operationAttempt: key },
      select: { id: true },
    });
    let row: SandboxTransfer;
    if (located) {
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${located.id} FOR UPDATE`;
      row = await tx.sandboxTransfer.findUniqueOrThrow({ where: { id: located.id } });
      if (
        row.direction !== "DOWNLOAD" ||
        row.userId !== owner.userId ||
        row.sandboxId !== owner.sandboxId ||
        row.generation !== owner.generation
      )
        throw new CaptureRefused("protocol_error", "Capture binding differs.");
      const old =
        body.byteLength > 0
          ? await tx.sandboxTransferChunk.findUnique({
              where: { transferId_offset: { transferId: row.id, offset: BigInt(offset) } },
            })
          : null;
      const sealedEmpty = row.state === "SEALED" && row.totalBytes === 0n && body.byteLength === 0;
      if (old || sealedEmpty) {
        if (
          sealedEmpty ||
          (old?.digest === chunkDigest &&
            old.length === body.byteLength &&
            (!ended || row.state === "SEALED"))
        )
          return null;
        throw new CaptureRefused("protocol_error", "Conflicting download replay.");
      }
      if (this.expired(row))
        throw new CaptureRefused("transfer_expired", "Download capture expired.");
      if (row.state === "SEALED" || BigInt(offset) !== row.receivedBytes)
        throw new CaptureRefused("protocol_error", "File chunk gap after the committed tail.");
    } else {
      if (offset !== 0)
        throw new CaptureRefused("protocol_error", "File chunk gap before the first chunk.");
      await lockTransferAdmission(tx);
      const held = await this.slots(tx, owner.userId);
      try {
        checkReservation(this.limits.maxBytes, this.limits, held.used, held.active, held.owned);
      } catch {
        throw new CaptureRefused("transfer_quota", "Transfer reservation refused.");
      }
      const now = Date.now();
      // Offload §8.10: the transport host at acceptance (the capture's host).
      const bound = await tx.sandbox.findFirst({
        where: { id: owner.sandboxId, userId: owner.userId },
        select: { sandboxHostId: true },
      });
      if (!bound?.sandboxHostId)
        throw new CaptureRefused("protocol_error", "Capture has no transport host binding.");
      row = await tx.sandboxTransfer.create({
        data: {
          id: randomUUID(),
          userId: owner.userId,
          keyId: owner.keyId,
          acceptedHostId: bound.sandboxHostId,
          sandboxId: owner.sandboxId,
          generation: owner.generation,
          direction: "DOWNLOAD",
          guestPath: owner.guestPath,
          // Unguessable: a caller-chosen key can never alias a capture row.
          idempotencyKey: `relay:${randomUUID()}`,
          requestBodyHash: digest(Buffer.from(`${operationId}:${attempt}`)),
          totalBytes: BigInt(this.limits.maxBytes),
          idleExpiresAt: new Date(now + this.limits.idleMs),
          expiresAt: new Date(now + this.limits.absoluteMs),
          operationId,
          operationAttempt: attempt,
        },
      });
    }
    const id = row.id;
    const create = row.state === "ALLOCATING";
    return () => this.run(id, () => this.writeCapture(id, create, chunk, chunkDigest));
  }
  /** Disk first (fsync), then chunk metadata; the relay ACKs only after both. */
  private async writeCapture(
    id: string,
    create: boolean,
    chunk: CaptureChunk,
    chunkDigest: string,
  ) {
    const end = chunk.offset + chunk.body.byteLength;
    let sealedDigest: string | undefined;
    try {
      const file = await this.file(id, create);
      try {
        // A prior crash or failed commit may have left an unacknowledged tail.
        await file.truncate(chunk.offset);
        await writeFully(file, chunk.body, chunk.offset);
        await file.sync();
        if (chunk.ended) {
          // Whole-content identity comes from the durable bytes themselves.
          const whole = createHash("sha256");
          const buffer = Buffer.alloc(Math.min(TRANSFER_CHUNK_BYTES, Math.max(end, 1)));
          for (let at = 0; at < end; ) {
            const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, end - at), at);
            if (!bytesRead) throw transferError("TRANSFER_IO");
            whole.update(buffer.subarray(0, bytesRead));
            at += bytesRead;
          }
          sealedDigest = whole.digest("hex");
        }
      } finally {
        await file.close();
      }
      if (create) await this.syncDirectory();
    } catch (error) {
      await this.retire(id, "FAILED");
      throw error;
    }
    await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_stream_transfer WHERE id = ${id} FOR UPDATE`;
      const row = await tx.sandboxTransfer.findUniqueOrThrow({ where: { id } });
      if (
        !["ALLOCATING", "OPEN"].includes(row.state) ||
        this.expired(row) ||
        row.receivedBytes !== BigInt(chunk.offset)
      )
        throw transferError("TRANSFER_EXPIRED");
      if (chunk.body.byteLength > 0)
        await tx.sandboxTransferChunk.create({
          data: {
            transferId: id,
            offset: BigInt(chunk.offset),
            length: chunk.body.byteLength,
            digest: chunkDigest,
          },
        });
      await tx.sandboxTransfer.update({
        where: { id },
        data: {
          state: chunk.ended ? "SEALED" : "OPEN",
          receivedBytes: BigInt(end),
          idleExpiresAt: new Date(
            Math.min(Date.now() + this.limits.idleMs, row.expiresAt.getTime()),
          ),
          // Sealing shrinks the conservative reservation to the real length.
          ...(chunk.ended ? { totalBytes: BigInt(end), sha256: sealedDigest } : {}),
        },
      });
    });
  }
  /** The sealed, unexpired capture of one operation attempt, if any. */
  async completedCapture(
    operationId: string,
    attempt: number,
    tx: Prisma.TransactionClient = prisma,
  ): Promise<CompletedCapture | undefined> {
    const row = await tx.sandboxTransfer.findUnique({
      where: { operationId_operationAttempt: { operationId, operationAttempt: attempt } },
    });
    if (row?.state !== "SEALED" || this.expired(row) || row.sha256 == null) return undefined;
    return { transferId: row.id, size: Number(row.totalBytes), sha256: row.sha256 };
  }
  /**
   * The operation did not succeed: durable FAILED intent now, then cleanup.
   * A busy or failed cleanup is retried by the sweep (terminal rows that still
   * hold a reservation), so the reservation is released exactly once.
   */
  async discardCapture(operationId: string, attempt: number) {
    const row = await prisma.sandboxTransfer.findUnique({
      where: { operationId_operationAttempt: { operationId, operationAttempt: attempt } },
      select: { id: true },
    });
    if (!row) return;
    await prisma.sandboxTransfer.updateMany({
      where: { id: row.id, state: { in: ["ALLOCATING", "OPEN", "SEALED"] } },
      data: { state: "FAILED" },
    });
    if (this.closed || this.holds(row.id)) return;
    await this.run(row.id, () => this.retire(row.id, "FAILED")).catch(() => undefined);
  }
  private async scan(visit: (row: SandboxTransfer) => Promise<void>) {
    let cursor: string | undefined;
    let failed = false;
    for (;;) {
      const rows = await prisma.sandboxTransfer.findMany({
        where: { reservationHeld: true, ...(cursor ? { id: { gt: cursor } } : {}) },
        orderBy: { id: "asc" },
        take: 32,
      });
      if (!rows.length) {
        if (failed) throw transferError("TRANSFER_IO");
        return;
      }
      for (const row of rows) {
        try {
          await visit(row);
        } catch {
          failed = true;
        }
      }
      cursor = rows.at(-1)?.id;
    }
  }
  async sweep() {
    if (this.sweeping) return this.sweeping;
    if (this.closed) return;
    this.sweeping = this.scan(async (row) => {
      if (this.holds(row.id)) return;
      // Create owns its ID before the spool is present, under the create permit.
      if (this.work.has(`create:${row.userId}:${row.idempotencyKey}`)) return;
      if (
        terminal(row.state) ||
        row.idleExpiresAt <= new Date() ||
        row.expiresAt <= new Date() ||
        (await this.uploadSettled(row)) ||
        !(await this.generationLive(row))
      ) {
        await this.run(row.id, () => this.retire(row.id, "EXPIRED"));
      }
    }).finally(() => {
      this.sweeping = undefined;
    });
    return this.sweeping;
  }
  /**
   * A transfer is bound to one sandbox generation. Once the sandbox moved to
   * another generation or was deleted, no read, write, commit or capture chunk
   * of it can ever pass `current()` or the relay fence again: its reservation
   * is released by the next sweep instead of waiting for idle expiry (C30).
   */
  private async generationLive(row: SandboxTransfer) {
    return (
      (await prisma.sandbox.count({
        where: { id: row.sandboxId, generation: row.generation, state: { not: "DELETED" } },
      })) > 0
    );
  }
  private async recover() {
    await this.scan(async (row) => {
      if (
        terminal(row.state) ||
        row.state === "ALLOCATING" ||
        row.idleExpiresAt <= new Date() ||
        row.expiresAt <= new Date() ||
        (await this.uploadSettled(row))
      ) {
        await this.retire(row.id, "EXPIRED");
        return;
      }
      // A relay capture continues only on the host connection that started it,
      // and a restart drops every connection (the host discards its download
      // window). An unsealed capture can never complete: settle it now rather
      // than after the idle sweep. The operation itself settles through the
      // relay's reconnect reconciliation; a success result needs a sealed capture.
      if (row.direction === "DOWNLOAD" && row.operationId && row.state !== "SEALED") {
        await this.retire(row.id, "FAILED");
        return;
      }
      try {
        const file = await this.file(row.id);
        try {
          // Verify every acknowledged byte against its durable fixed-chunk digest.
          await verifyAcknowledged(
            file,
            Number(row.receivedBytes),
            Number(row.totalBytes),
            (offset) =>
              prisma.sandboxTransferChunk.findUnique({
                where: { transferId_offset: { transferId: row.id, offset: BigInt(offset) } },
              }),
          );
        } finally {
          await file.close();
        }
      } catch (error) {
        // A failed metadata lookup is not evidence of corrupt payload bytes.
        // Keep the acknowledged file and reservation for the next startup.
        if (!storageFailure(error)) throw error;
        await this.retire(row.id, "FAILED");
      }
    });
    // Bounded directory iteration; only our canonical ID-derived names are unlinkable.
    for await (const entry of await opendir(this.root)) {
      const id = entry.name.endsWith(".spool") ? entry.name.slice(0, -6) : "";
      if (!transferIdSchema.safeParse(id).success) throw transferError("TRANSFER_IO");
      const row = await prisma.sandboxTransfer.findUnique({
        where: { id },
        select: { reservationHeld: true },
      });
      if (!row?.reservationHeld) await unlink(this.path(id));
    }
    await this.syncDirectory();
  }
}
