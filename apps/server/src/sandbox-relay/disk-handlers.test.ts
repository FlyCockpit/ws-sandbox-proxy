import {
  encryptedImageLength,
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_TAG_BYTES,
  IMAGE_SIZE_MAX,
} from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeImageGrantBudget: async () => {} }));

const { diskPartSize } = await import("./disk-handlers");

describe("disk part size (offload plan §6)", () => {
  const sealed = IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES;
  it.each([1, 64 * IMAGE_ENCRYPTION_RECORD_BYTES, 2 ** 37, IMAGE_SIZE_MAX])(
    "whole sealed records, at least 64, and at most 10000 S3 parts (%d bytes)",
    (plain) => {
      const part = diskPartSize(plain);
      expect(part % sealed).toBe(0);
      expect(part / sealed).toBeGreaterThanOrEqual(64);
      expect(Math.ceil(encryptedImageLength(plain) / part)).toBeLessThanOrEqual(10_000);
      expect(Number.isSafeInteger(part) && part < 2 ** 31).toBe(true);
    },
  );
});

describe("disk inventory budget (post-landing #1)", () => {
  it("admits one window's pages, refuses more, and replenishes after the window", async () => {
    const { admitDiskInventoryPage, DISK_INVENTORY_PAGES_PER_WINDOW, DISK_INVENTORY_WINDOW_MS } =
      await import("./disk-handlers");
    let budget: Parameters<typeof admitDiskInventoryPage>[0];
    const t0 = 1_000_000;
    for (let i = 0; i < DISK_INVENTORY_PAGES_PER_WINDOW; i++) {
      const next = admitDiskInventoryPage(budget, t0 + i);
      expect(next.admitted).toBe(true);
      budget = next.budget;
    }
    // A long-lived connection past the first window's budget: ignored now…
    const over = admitDiskInventoryPage(budget, t0 + 1_000);
    expect(over.admitted).toBe(false);
    budget = over.budget;
    // …and answered again once the window rolled over (16 passes of the
    // daemon's 10-minute reconciliation would have exhausted a per-session cap).
    for (let pass = 1; pass <= 20; pass++) {
      const next = admitDiskInventoryPage(budget, t0 + pass * DISK_INVENTORY_WINDOW_MS);
      expect(next.admitted).toBe(true);
      budget = next.budget;
    }
  });
});
