import { lockHostByEpoch, relayTransaction } from "@wssp/api/sandbox/relay-fence";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pinnedAllocationV11Schema } from "@wssp/sandbox-contracts";
import { type AllocationProof, convergeInventoryEntry } from "./inventory-reconcile.js";
import type { RelaySender } from "./operation-handlers.js";
import type { DaemonControlMessage, ServerControlMessage } from "./protocol.js";

type Answer = Extract<DaemonControlMessage, { type: "allocation.attest.result" }>;
type Request = Extract<ServerControlMessage, { type: "allocation.attest.request" }>;

/** One outstanding bounded page per session. Retries rotate through candidates;
 * elapsed time controls retry load only, never the release proof. */
export class AllocationAttestation {
  private pending?: Request;
  private cursor?: string;
  private scanHadCandidates = false;
  private timer?: ReturnType<typeof setTimeout>;
  private busy = false;
  private closed = false;
  private backoff = 1000;
  private retryAfter = 0;
  private readonly freshIds = new Set<string>();
  private freshOverflow = false;
  private sweepFresh = false;
  // A session-wide negative-answer cooldown keeps memory constant (no per-id
  // lifetime cache). Ordinary fresh triggers bypass it only for their own id;
  // overflow uses one bounded sweep to cover ids that did not fit.
  private static readonly NEGATIVE_BACKOFF = 10 * 60_000;

  constructor(
    private readonly sender: RelaySender,
    private readonly nextSequence: () => number,
    private readonly send: (request: Request) => void,
  ) {}

  close() {
    this.closed = true;
    this.pending = undefined;
    this.freshIds.clear();
    clearTimeout(this.timer);
  }

  private schedule(delay: number) {
    clearTimeout(this.timer);
    this.timer = undefined;
    if (this.closed) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      if (this.pending) {
        this.pending = undefined; // timeout invalidates the old barrier
        this.schedule(this.backoff);
        return;
      }
      const freshId = this.freshIds.values().next().value;
      if (freshId) this.freshIds.delete(freshId);
      else if (this.freshOverflow) {
        // Overflow is bounded memory too: sweep all candidates without the
        // negative cooldown so no dropped fresh trigger waits ten minutes.
        this.freshOverflow = false;
        this.sweepFresh = true;
        this.cursor = undefined;
        this.scanHadCandidates = false;
        // Preserve the deadline; sweepFresh bypasses it until every page,
        // including an exact full-page tail, has been visited.
      }
      void this.request(freshId);
    }, delay);
    this.timer.unref?.();
  }

  /** operationId is supplied only by a newly committed UNKNOWN result. */
  async request(operationId?: string) {
    if (this.closed) return;
    if (this.busy || this.pending) {
      if (operationId && !this.freshIds.has(operationId)) {
        if (this.freshIds.size < 256) this.freshIds.add(operationId);
        else this.freshOverflow = true;
      }
      return;
    }
    if (this.sender.isCurrent?.() === false) return;
    if (!operationId && !this.sweepFresh && Date.now() < this.retryAfter) {
      this.schedule(this.retryAfter - Date.now());
      return;
    }
    this.busy = true;
    let retry = false;
    try {
      // Candidate hints need no owner/H locks. In particular an idle host does
      // not take either lock or maintain a periodic timer. Settlement rechecks
      // generation, state and every dispatch under the full lock order.
      const scan = () =>
        prisma.sandbox.findMany({
          where: {
            hostOwnerId: this.sender.userId,
            sandboxHostId: this.sender.hostId,
            OR: [{ liveResourcesHeld: true }, { diskReservationHeld: true }],
            ...(!operationId && this.cursor ? { id: { gt: this.cursor } } : {}),
            Operations: { some: this.operationWhere(operationId) },
          },
          orderBy: { id: "asc" },
          take: 256,
          select: {
            id: true,
            userId: true,
            generation: true,
            CurrentPlacement: {
              select: {
                cpuCount: true,
                memoryMiB: true,
                diskGiB: true,
                storagePoolName: true,
                storageMarker: true,
                chargedMemoryMiB: true,
                chargedVcpu: true,
                rootChargeGiB: true,
              },
            },
            Operations: {
              where: this.operationWhere(operationId),
              orderBy: { generation: "desc" },
              take: 1,
              select: { generation: true },
            },
          },
        });
      let rows = await scan();
      const currentIds = () =>
        rows.filter((row) => row.Operations[0]?.generation === row.generation).map((row) => row.id);
      let ids = currentIds();
      // Skip stale-only pages now, without keeping an idle timer alive. Queries
      // and memory stay page-bounded; wrap only after a scan that saw candidates.
      while (
        !operationId &&
        !ids.length &&
        (rows.length === 256 || (this.cursor && this.scanHadCandidates))
      ) {
        if (this.closed || this.sender.isCurrent?.() === false) return;
        if (rows.length === 256) this.cursor = rows.at(-1)?.id;
        else {
          this.cursor = undefined;
          this.scanHadCandidates = false;
          this.sweepFresh = false;
          if (Date.now() < this.retryAfter) {
            this.schedule(this.retryAfter - Date.now());
            return;
          }
        }
        rows = await scan();
        ids = currentIds();
      }
      if (!operationId) {
        this.cursor = rows.length === 256 ? rows.at(-1)?.id : undefined;
        this.scanHadCandidates = this.cursor ? this.scanHadCandidates || ids.length > 0 : false;
        if (!this.cursor) this.sweepFresh = false;
      }
      if (!ids.length) {
        this.backoff = 1000;
        return;
      }
      retry = true;
      await relayTransaction(async (tx) => {
        await lockOwnerForAdmission(tx, this.sender.userId);
        await lockHostByEpoch(
          tx,
          this.sender.hostId,
          this.sender.connectionEpoch,
          this.sender.userId,
        );
        if (this.closed || this.sender.isCurrent?.() === false) return;
        const host = await tx.sandboxHost.findFirstOrThrow({
          where: { id: this.sender.hostId, userId: this.sender.userId },
          select: { relayProtocolVersion: true },
        });
        const allocations = rows
          .filter((row) => ids.includes(row.id))
          .map((row) => ({
            sandboxId: row.id,
            sandboxOwnerId: row.userId,
            allocation:
              row.CurrentPlacement === null
                ? null
                : {
                    cpuCount: row.CurrentPlacement.cpuCount,
                    memoryMiB: row.CurrentPlacement.memoryMiB,
                    diskGiB: row.CurrentPlacement.diskGiB,
                    storagePoolName: row.CurrentPlacement.storagePoolName,
                    storageMarker: row.CurrentPlacement.storageMarker,
                    chargedMemoryMiB: row.CurrentPlacement.chargedMemoryMiB,
                    chargedVcpu: row.CurrentPlacement.chargedVcpu,
                    rootChargeGiB: row.CurrentPlacement.rootChargeGiB,
                  },
          }));
        const exact = pinnedAllocationV11Schema
          .array()
          .safeParse(allocations.map((p) => p.allocation));
        if (host.relayProtocolVersion !== "1.0" || !exact.success) return;
        const request: Request = {
          type: "allocation.attest.request",
          connectionEpoch: this.sender.connectionEpoch,
          barrier: this.nextSequence(),
          sandboxIds: ids,
          allocations: allocations.map((p, i) => ({
            sandboxId: p.sandboxId,
            sandboxOwnerId: p.sandboxOwnerId,
            allocation: exact.data[i]!,
          })),
        };
        // H serializes this enqueue with each actual allocation enqueue. A
        // prepared but unsent attempt has no sequence and can never pass proof.
        // Replace the periodic deadline only when actually sending. An empty
        // targeted scan must leave that deadline intact.
        clearTimeout(this.timer);
        this.timer = undefined;
        this.pending = request;
        this.send(request);
      }, undefined);
    } catch {
      // Gathering failure is no evidence and must not tear down other work.
      this.pending = undefined;
      retry = true;
    } finally {
      this.busy = false;
      if ((this.freshIds.size || this.freshOverflow) && !this.pending) this.schedule(0);
      else if (retry) this.schedule(this.pending ? 30_000 : this.backoff);
      else if (operationId && !this.timer) {
        // A retired/superseded targeted id says nothing about other candidates.
        // Fall through to a periodic scan, which parks if the host is idle.
        this.schedule(0);
      }
      this.backoff = Math.min(this.backoff * 2, 60_000);
    }
  }

  private operationWhere(operationId?: string) {
    return {
      ...(operationId ? { id: operationId } : {}),
      state: "UNKNOWN_OUTCOME" as const,
      kind: {
        in: ["CREATE_SANDBOX" as const, "RECONNECT_SANDBOX" as const],
      },
      dispatchedHostId: this.sender.hostId,
      dispatchAttempt: { gt: 0 },
    };
  }

  async accept(answer: Answer) {
    const pending = this.pending;
    if (
      !pending ||
      answer.connectionEpoch !== pending.connectionEpoch ||
      answer.barrier !== pending.barrier ||
      answer.entries.length !== pending.sandboxIds.length ||
      answer.entries.some(
        (entry, i) =>
          entry.sandboxId !== pending.sandboxIds[i] ||
          entry.sandboxOwnerId !== pending.allocations[i]?.sandboxOwnerId,
      ) ||
      this.sender.isCurrent?.() === false
    )
      return false;
    this.pending = undefined; // duplicate/out-of-order responses prove nothing
    clearTimeout(this.timer);
    this.timer = undefined;
    this.busy = true;
    if (answer.entries.some((entry) => !entry.settledNeverIssued))
      this.retryAfter = Date.now() + AllocationAttestation.NEGATIVE_BACKOFF;
    try {
      for (const entry of answer.entries) {
        if (!entry.settledNeverIssued) continue;
        const proof: AllocationProof = {
          ...answer,
          root: pending.allocations?.find((p) => p.sandboxId === entry.sandboxId)?.allocation,
        };
        await convergeInventoryEntry(
          this.sender,
          { sandboxId: entry.sandboxId, sandboxOwnerId: entry.sandboxOwnerId, state: "absent" },
          undefined,
          proof,
        );
      }
      return true;
    } catch {
      return false;
    } finally {
      this.busy = false;
      this.schedule(
        this.freshIds.size || this.freshOverflow
          ? 0
          : this.sweepFresh
            ? this.backoff
            : Math.max(this.backoff, this.retryAfter - Date.now()),
      );
    }
  }
}
