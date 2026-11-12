import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  mode: "peer" as "peer" | "s3",
  sweep: vi.fn(),
  queryRaw: vi.fn(),
  createTransfer: vi.fn(),
  updateTransfer: vi.fn(),
  hosts: new Map<string, { connectionEpoch: number; userId: string }>(),
  offloadCandidates: vi.fn(async () => [] as unknown[]),
  enqueueOffload: vi.fn(),
  failUndeliveredOffload: vi.fn(async () => {}),
  storedAckFrame: vi.fn(),
  storedOffloads: vi.fn(async () => [] as { id: string }[]),
  lost: [] as Array<{
    hostId: string;
    hostOwnerId: string;
    connectionEpoch: number;
    imageOwnerId: string;
    fingerprint: string;
  }>,
}));
vi.mock("@wssp/api/sandbox/image-store/captures", () => ({ sweepCaptures: mocks.sweep }));
vi.mock("@wssp/api/sandbox/image-store/config", () => ({
  imageDistributionMode: () => mocks.mode,
}));
vi.mock("../sandbox-relay/image-handlers.js", () => ({ onArtifactStored: vi.fn() }));
vi.mock("@wssp/api/sandbox/image-store/jobs", () => ({
  endTransfersOfEndedOperations: vi.fn(async () => []),
  originImagesToRelease: vi.fn(async () => []),
}));
vi.mock("./index.js", () => ({ reconcileImageRelaySpool: vi.fn(async () => 0) }));
vi.mock("@wssp/api/sandbox/disk-offload/enqueue", () => ({
  offloadCandidates: mocks.offloadCandidates,
  enqueueOffload: mocks.enqueueOffload,
  failUndeliveredOffload: mocks.failUndeliveredOffload,
  OFFLOAD_RELEASE_WAIT_MS: 10 * 60_000,
}));
vi.mock("@wssp/api/sandbox/disk-offload/store", () => ({ storedAckFrame: mocks.storedAckFrame }));
vi.mock("@wssp/api/sandbox/image-store/access", () => ({
  foreignImageAccessLost: vi.fn(async () => mocks.lost),
}));
vi.mock("@wssp/db", () => ({
  default: {
    sandboxHost: {
      findUnique: vi.fn(
        async ({ where }: { where: { id: string } }) => mocks.hosts.get(where.id) ?? null,
      ),
    },
    sandboxImageArtifact: { findMany: vi.fn(async () => []) },
    sandboxDiskOffload: { findMany: mocks.storedOffloads },
    sandboxImageTransfer: { create: mocks.createTransfer, update: mocks.updateTransfer },
    $queryRaw: mocks.queryRaw,
  },
}));

const {
  startImageScheduler,
  releaseLostForeignImages,
  publishBackfill,
  offloadScheduling,
  sendStoredAcks,
} = await import("./scheduler.js");

describe("image scheduler — unit (mocked sweep and DB; real-DB finalizer: captures.pg.test.ts)", () => {
  afterEach(() => vi.clearAllMocks());
  it("a capture that will never become a revision releases its origin pin with image.release(gc)", async () => {
    mocks.hosts.set("host-1", { connectionEpoch: 4, userId: "owner-1" });
    mocks.sweep.mockResolvedValue([
      {
        operationId: "op",
        outcome: {
          kind: "failed",
          fingerprint: `sha256:${"a".repeat(64)}`,
          hostId: "host-1",
          ownerId: "capturer",
        },
      },
      {
        operationId: "op2",
        outcome: { kind: "failed", fingerprint: null, hostId: "host-1", ownerId: "capturer" },
      },
    ]);
    const send = vi.fn(() => true);
    const controller = new AbortController();
    const wake = startImageScheduler(send, controller.signal);
    wake();
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    expect(send).toHaveBeenCalledWith("host-1", 4, {
      type: "image.release",
      fingerprint: `sha256:${"a".repeat(64)}`,
      imageOwnerId: "capturer",
      reason: "gc",
    });
    controller.abort();
  });

  it("P2-5: lost foreign copies the access scan returns are released with access_lost (schedule: access.pg.test.ts)", async () => {
    const fp = `sha256:${"a".repeat(64)}`;
    mocks.lost = [
      { hostId: "h", hostOwnerId: "ho", connectionEpoch: 3, imageOwnerId: "io", fingerprint: fp },
    ];
    const sent: unknown[] = [];
    const send = (hostId: string, epoch: number, frame: unknown) => {
      sent.push({ hostId, epoch, frame });
      return true;
    };
    expect(await releaseLostForeignImages(send)).toBe(1);
    expect(sent[0]).toEqual({
      hostId: "h",
      epoch: 3,
      frame: { type: "image.release", fingerprint: fp, imageOwnerId: "io", reason: "access_lost" },
    });
    expect(await releaseLostForeignImages(() => false, "h")).toBe(0);
    mocks.lost = [];
  });

  describe("publishBackfill", () => {
    const candidate = (userId: string, hostId: string, n: number, openPublishes = 0) => ({
      userId,
      fingerprint: `sha256:${String(n).repeat(64)}`,
      hostId,
      epoch: 1,
      size: 1n,
      openPublishes,
    });
    afterEach(() => {
      mocks.mode = "peer";
    });
    it("starts at most two publishes per account per tick, one per host", async () => {
      mocks.mode = "s3";
      let id = 0;
      mocks.createTransfer.mockImplementation(async () => ({ id: `t-${id++}` }));
      mocks.queryRaw.mockResolvedValue([
        candidate("a", "h1", 1),
        candidate("a", "h2", 2),
        candidate("a", "h3", 3),
        candidate("b", "h1", 4),
        candidate("b", "h4", 5, 1),
        candidate("b", "h5", 6, 1),
      ]);
      const send = vi.fn((_hostId: string, _epoch: number, _frame: unknown) => true);
      expect(await publishBackfill(send)).toBe(3);
      expect(send.mock.calls.map(([hostId]) => hostId)).toEqual(["h1", "h2", "h4"]);
      // The query itself skips accounts already at the cap across ticks.
      const [strings, ...values] = mocks.queryRaw.mock.calls[0] as [string[], ...unknown[]];
      expect(strings.join("?")).toContain('"openPublishes" < ?');
      expect(values).toContain(2);
    });
    it("a refused send frees the account's slot for its next candidate", async () => {
      mocks.mode = "s3";
      mocks.createTransfer.mockResolvedValue({ id: "t" });
      mocks.queryRaw.mockResolvedValue([
        candidate("a", "h1", 1),
        candidate("a", "h2", 2),
        candidate("a", "h3", 3),
      ]);
      const send = vi.fn((hostId: string) => hostId !== "h1");
      expect(await publishBackfill(send)).toBe(2);
      expect(mocks.updateTransfer).toHaveBeenCalledOnce();
    });
  });

  describe("disk offload (offload plan §7)", () => {
    const candidate = (sandboxId: string, hostId: string) => ({
      sandboxId,
      userId: "owner",
      generation: 3,
      hostId,
      hostOwnerId: "owner",
      epoch: 7,
    });
    it("one export per host per tick; each enqueued attempt is sent its request on the host epoch", async () => {
      mocks.offloadCandidates.mockResolvedValue([
        candidate("s1", "h1"),
        candidate("s2", "h1"),
        candidate("s3", "h2"),
      ]);
      mocks.enqueueOffload.mockImplementation(async (c: ReturnType<typeof candidate>) => ({
        offloadId: `o-${c.sandboxId}`,
        sandboxId: c.sandboxId,
        seq: 1,
        generation: c.generation,
        hostId: c.hostId,
        epoch: c.epoch,
      }));
      const sendDisk = vi.fn((_h: string, _e: number, _f: unknown) => true);
      expect(await offloadScheduling(sendDisk)).toBe(2);
      expect(mocks.enqueueOffload).toHaveBeenCalledTimes(2);
      expect(sendDisk.mock.calls).toEqual([
        [
          "h1",
          7,
          {
            type: "disk.offload.request",
            sandboxId: "s1",
            offloadId: "o-s1",
            seq: 1,
            generation: 3,
          },
        ],
        [
          "h2",
          7,
          {
            type: "disk.offload.request",
            sandboxId: "s3",
            offloadId: "o-s3",
            seq: 1,
            generation: 3,
          },
        ],
      ]);
      expect(mocks.failUndeliveredOffload).not.toHaveBeenCalled();
    });
    it("a candidate the locked re-check refuses is skipped; an undelivered request fails its attempt", async () => {
      mocks.offloadCandidates.mockResolvedValue([candidate("s1", "h1"), candidate("s2", "h2")]);
      mocks.enqueueOffload.mockImplementation(async (c: ReturnType<typeof candidate>) =>
        c.sandboxId === "s1"
          ? null
          : {
              offloadId: "o-s2",
              sandboxId: "s2",
              seq: 4,
              generation: 3,
              hostId: "h2",
              epoch: 7,
            },
      );
      expect(await offloadScheduling(() => false)).toBe(0);
      expect(mocks.failUndeliveredOffload).toHaveBeenCalledWith(
        expect.objectContaining({ offloadId: "o-s2" }),
      );
    });
    it("unreleased STORED offloads tell their source host on its current epoch", async () => {
      mocks.hosts.set("src", { connectionEpoch: 9, userId: "owner" });
      mocks.storedOffloads.mockResolvedValue([{ id: "o1" }, { id: "o2" }]);
      const frame = {
        type: "disk.offload.stored",
        sandboxId: "s",
        offloadId: "o1",
        seq: 2,
        fingerprint: `sha256:${"f".repeat(64)}`,
        generation: 5,
      };
      mocks.storedAckFrame.mockImplementation(async (id: string) =>
        id === "o1" ? { hostId: "src", frame } : null,
      );
      const sendDisk = vi.fn((_h: string, _e: number, _f: unknown) => true);
      expect(await sendStoredAcks(sendDisk)).toBe(1);
      expect(sendDisk).toHaveBeenCalledWith("src", 9, frame);
      // Review r3: every STORED row the host has not released yet, bounded.
      expect(mocks.storedOffloads).toHaveBeenLastCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ state: "STORED", sourceReleasedAt: null }),
          take: expect.any(Number),
        }),
      );
      // Once per session: the next tick sends nothing; a reconnect gets it again.
      expect(await sendStoredAcks(sendDisk)).toBe(0);
      expect(sendDisk).toHaveBeenCalledTimes(1);
      mocks.hosts.set("src", { connectionEpoch: 10, userId: "owner" });
      expect(await sendStoredAcks(sendDisk)).toBe(1);
      expect(sendDisk).toHaveBeenLastCalledWith("src", 10, frame);
    });
  });
});
