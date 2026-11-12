import type { Prisma } from "@wssp/db";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const { dispatchDiskFields } = await import("./disk-dispatch");

const DISK = `sha256:${"d".repeat(64)}`;
const BASE = `sha256:${"b".repeat(64)}`;
const sandbox = {
  id: "sbx",
  userId: "owner",
  generation: 4,
  diskOffloadId: "off-1" as string | null,
  diskBaseFingerprint: null as string | null,
  cloudInitInstanceId: "iid-1" as string | null,
};

function txWith(
  offload: { id: string; seq: number; fingerprint: string | null; sizeBytes: bigint | null } | null,
  attempt: { restoreOffloadId: string | null } | null = null,
) {
  return {
    sandboxDiskOffload: { findFirst: vi.fn().mockResolvedValue(offload) },
    sandboxOperation: { findFirst: vi.fn().mockResolvedValue(attempt) },
  } as unknown as Prisma.TransactionClient;
}

const stored = { id: "off-1", seq: 2, fingerprint: DISK, sizeBytes: 4096n };

describe("dispatchDiskFields (offload plan §7, §8.1, N1)", () => {
  it("a restore carries restore + new_root + the disk's fetch image + its base", async () => {
    expect(
      await dispatchDiskFields(txWith(stored), {
        kind: "sandbox.reconnect",
        restoreOffloadId: "off-1",
        payload: {},
        sandbox,
        diskCapable: true,
      }),
    ).toEqual({
      restore: { offloadId: "off-1", seq: 2, fingerprint: DISK, cloudInitInstanceId: "iid-1" },
      launchMode: "new_root",
      image: { fingerprint: DISK, sizeBytes: 4096, format: "unified", source: "fetch" },
      diskBaseFingerprint: DISK,
    });
  });

  it("an invalid stored cloud-init id is omitted, never sent", async () => {
    const fields = await dispatchDiskFields(txWith(stored), {
      kind: "sandbox.reconnect",
      restoreOffloadId: "off-1",
      payload: {},
      sandbox: { ...sandbox, cloudInitInstanceId: "bad id" },
      diskCapable: true,
    });
    expect(fields).toMatchObject({ restore: { offloadId: "off-1" } });
    expect(typeof fields === "object" && fields.restore?.cloudInitInstanceId).toBeUndefined();
  });

  it.each([
    ["the offload is not STORED (or gone)", null, sandbox, "sandbox.reconnect"],
    ["no verified fingerprint", { ...stored, fingerprint: null }, sandbox, "sandbox.reconnect"],
    ["no size", { ...stored, sizeBytes: null }, sandbox, "sandbox.reconnect"],
    [
      "not the sandbox's current disk",
      stored,
      { ...sandbox, diskOffloadId: "off-0" },
      "sandbox.reconnect",
    ],
    ["a restore on any other kind", stored, sandbox, "sandbox.create"],
  ])("refuses a restore when %s", async (_name, offload, row, kind) => {
    expect(
      await dispatchDiskFields(txWith(offload), {
        kind,
        restoreOffloadId: "off-1",
        payload: {},
        sandbox: row,
        diskCapable: true,
      }),
    ).toBe("restore_unavailable");
  });

  it("forwards a valid cold `expectDisk`; a malformed one never dispatches", async () => {
    const expectDisk = { seq: 2, fingerprint: DISK };
    expect(
      await dispatchDiskFields(txWith(null), {
        kind: "sandbox.reconnect",
        restoreOffloadId: null,
        payload: { expectDisk },
        sandbox: { ...sandbox, diskOffloadId: null },
        diskCapable: true,
      }),
    ).toEqual({ expectDisk });
    expect(
      await dispatchDiskFields(txWith(null), {
        kind: "sandbox.reconnect",
        restoreOffloadId: null,
        payload: { expectDisk: { seq: 0, fingerprint: DISK } },
        sandbox,
        diskCapable: true,
      }),
    ).toBe("restore_unavailable");
  });

  it("binding dispatches name the active attempt's disk, else the lineage base (S4)", async () => {
    // While restoring: the attempt's offload fingerprint.
    expect(
      await dispatchDiskFields(txWith({ ...stored }, { restoreOffloadId: "off-1" }), {
        kind: "sandbox.kill",
        restoreOffloadId: null,
        payload: {},
        sandbox: { ...sandbox, diskBaseFingerprint: BASE },
        diskCapable: true,
      }),
    ).toEqual({ diskBaseFingerprint: DISK });
    // After READY: Sandbox.diskBaseFingerprint.
    expect(
      await dispatchDiskFields(txWith(null), {
        kind: "command.run",
        restoreOffloadId: null,
        payload: {},
        sandbox: { ...sandbox, diskOffloadId: null, diskBaseFingerprint: BASE },
        diskCapable: true,
      }),
    ).toEqual({ diskBaseFingerprint: BASE });
    // A template lineage, a create, or a host without `diskOffload`: none.
    for (const [kind, row, capable] of [
      ["command.run", { ...sandbox, diskOffloadId: null }, true],
      ["sandbox.create", { ...sandbox, diskBaseFingerprint: BASE }, true],
      ["command.run", { ...sandbox, diskOffloadId: null, diskBaseFingerprint: BASE }, false],
    ] as const)
      expect(
        await dispatchDiskFields(txWith(null), {
          kind,
          restoreOffloadId: null,
          payload: {},
          sandbox: row,
          diskCapable: capable,
        }),
      ).toEqual({});
  });
});
