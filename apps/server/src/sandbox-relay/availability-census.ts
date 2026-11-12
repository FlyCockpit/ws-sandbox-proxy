import { randomUUID } from "node:crypto";
import { noteCapacityChanged } from "@wssp/api/sandbox/capacity-queue-wake";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
} from "@wssp/api/sandbox/relay-fence";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { RelaySender } from "./operation-handlers.js";
import {
  type AvailabilityBinding,
  availabilityBindingSchema,
  type DaemonControlMessage,
  type ServerControlMessage,
} from "./protocol.js";

const PAGE_MAX = 100;
const TOTAL_MAX = 10_000;
const TIMEOUT_MS = 30_000;

/** One hello-time walk over registered revision/host associations. No age
 * clock or periodic refresh. Only explicit exact-bound verdicts are persisted.
 * Fresh launch admission requires exact current-epoch evidence. */
export class AvailabilityCensus {
  private cursor: string | undefined;
  private count = 0;
  private page = 0;
  private omitted = false;
  private stopped = false;
  private timer?: ReturnType<typeof setTimeout>;
  private pending?: {
    requestId: string;
    bindings: AvailabilityBinding[];
    deadline: number;
    retries: number;
  };

  stop(): void {
    this.stopped = true;
    this.pending = undefined;
    clearTimeout(this.timer);
  }

  private sendPending(): void {
    const pending = this.pending;
    if (!pending || this.stopped) return;
    pending.deadline = this.clock() + TIMEOUT_MS;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.onTimeout().catch(() => this.stop());
    }, TIMEOUT_MS);
    this.timer.unref?.();
    this.send({
      type: "availability.request",
      requestId: pending.requestId,
      page: this.page,
      connectionEpoch: this.sender.connectionEpoch,
      bindings: pending.bindings,
    });
  }

  private async onTimeout(): Promise<void> {
    const pending = this.pending;
    if (!pending || this.stopped) return;
    if (this.sender.isCurrent?.() === false) return this.stop();
    if (pending.retries < 2) {
      pending.retries += 1;
      this.sendPending();
      return;
    }
    // A dropped page proves nothing. Continue the bounded walk so one busy
    // observation queue cannot strand all subsequent registered revisions.
    this.omitted = true;
    this.advance(pending.bindings);
    await this.next();
  }

  private advance(bindings: AvailabilityBinding[]): void {
    clearTimeout(this.timer);
    this.cursor = bindings.at(-1)?.revisionId;
    this.count += bindings.length;
    this.page += 1;
    this.pending = undefined;
  }

  constructor(
    private readonly sender: RelaySender,
    private readonly send: (message: ServerControlMessage) => void,
    private readonly clock: () => number = Date.now,
  ) {}

  async next(): Promise<void> {
    if (this.stopped || this.pending || this.sender.isCurrent?.() === false) return;
    if (this.count >= TOTAL_MAX) {
      this.stopped = true;
      return;
    }
    const rows = await prisma.sandboxTemplateAvailability.findMany({
      where: {
        hostOwnerId: this.sender.userId,
        hostId: this.sender.hostId,
        Revision: { retiredAt: null },
        ...(this.cursor ? { revisionId: { gt: this.cursor } } : {}),
      },
      orderBy: { revisionId: "asc" },
      take: PAGE_MAX,
      select: {
        Revision: {
          select: { id: true, incusFingerprint: true, architecture: true, manifestDigest: true },
        },
      },
    });
    if (this.sender.isCurrent?.() === false) return;
    if (rows.length === 0) {
      this.stopped = true;
      await this.persist([], !this.omitted);
      return;
    }
    const bindings = rows.map(({ Revision: revision }) =>
      availabilityBindingSchema.parse({
        revisionId: revision.id,
        artifact: revision.incusFingerprint,
        architecture: revision.architecture,
        manifestHash: revision.manifestDigest,
      }),
    );
    const requestId = randomUUID();
    this.pending = { requestId, bindings, deadline: 0, retries: 0 };
    this.sendPending();
  }

  async accept(
    message: Extract<DaemonControlMessage, { type: "availability.result" }>,
  ): Promise<void> {
    const pending = this.pending;
    if (!pending || this.stopped || this.sender.isCurrent?.() === false) return;
    // Only the armed timer owns retries. A late reply must not race it to
    // spend another retry or move the deadline.
    if (this.clock() > pending.deadline) return;
    if (
      message.requestId !== pending.requestId ||
      message.page !== this.page ||
      message.connectionEpoch !== this.sender.connectionEpoch
    )
      return;
    const expected = new Map(pending.bindings.map((binding) => [binding.revisionId, binding]));
    if (
      message.entries.some(({ binding }) => {
        const e = expected.get(binding.revisionId);
        return (
          !e ||
          e.artifact !== binding.artifact ||
          e.manifestHash !== binding.manifestHash ||
          e.architecture !== binding.architecture
        );
      }) ||
      new Set(message.entries.map((e) => e.binding.revisionId)).size !== message.entries.length
    ) {
      throw new Error("availability binding mismatch");
    }
    clearTimeout(this.timer);
    if (!(await this.persist(message.entries, false))) {
      this.stopped = true;
      return;
    }
    this.omitted ||= message.entries.length !== pending.bindings.length;
    this.advance(pending.bindings);
    await this.next();
  }

  private async persist(
    entries: Extract<DaemonControlMessage, { type: "availability.result" }>["entries"],
    complete: boolean,
  ): Promise<boolean> {
    return relayTransaction(async (tx) => {
      await lockOwnerForAdmission(tx, this.sender.userId);
      await lockHostByEpoch(
        tx,
        this.sender.hostId,
        this.sender.connectionEpoch,
        this.sender.userId,
      );
      requireRelayFence(this.sender.isCurrent?.() !== false);
      const observedAt = await hostDatabaseNow(tx);
      // Each bounded verdict touches one registered child row, never the
      // accumulated census. A reconnect fences every old observation by epoch.
      for (const entry of entries) {
        await tx.sandboxTemplateAvailability.updateMany({
          where: {
            hostOwnerId: this.sender.userId,
            hostId: this.sender.hostId,
            revisionId: entry.binding.revisionId,
            Revision: {
              incusFingerprint: entry.binding.artifact,
              architecture: entry.binding.architecture,
              manifestDigest: entry.binding.manifestHash,
            },
          },
          data: {
            status:
              entry.status === "present"
                ? "AVAILABLE"
                : entry.status === "missing"
                  ? "MISSING"
                  : "REJECTED",
            localFingerprint: entry.binding.artifact,
            architecture: entry.binding.architecture,
            manifestDigest: entry.binding.manifestHash,
            verifiedConnectionEpoch: this.sender.connectionEpoch,
            observedAt,
            // Peer-mode placement facts (M5): the host's compressed size and
            // format for a present image; never cleared by a silent daemon.
            ...(entry.status === "present" && entry.sizeBytes
              ? { sizeBytes: BigInt(entry.sizeBytes) }
              : {}),
            ...(entry.status === "present" && entry.format ? { imageFormat: entry.format } : {}),
          },
        });
      }
      const written = await tx.sandboxHost.updateMany({
        where: {
          id: this.sender.hostId,
          userId: this.sender.userId,
          connectionEpoch: this.sender.connectionEpoch,
        },
        data: {
          availabilityEpoch: this.sender.connectionEpoch,
          availabilityCensusComplete: complete,
        },
      });
      // A template verified on this connection may let a waiting create place.
      noteCapacityChanged(tx, { hostIds: [this.sender.hostId] });
      requireRelayFence(written.count === 1 && this.sender.isCurrent?.() !== false);
      return true;
    }, false);
  }
}
