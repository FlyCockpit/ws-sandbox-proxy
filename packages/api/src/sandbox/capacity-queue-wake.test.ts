import { expect, it, vi } from "vitest";
import {
  bindCapacityQueueWake,
  noteCapacityChanged,
  notifyCapacityChanged,
  takeCapacityHints,
} from "./capacity-queue-wake";

it("per-transaction hints merge, take once, and 'all' dominates (unit; post-commit delivery: outbox.test.ts)", () => {
  const tx = {};
  expect(takeCapacityHints(tx)).toBeNull();
  noteCapacityChanged(tx, { hostIds: ["h1"] });
  noteCapacityChanged(tx, { poolIds: ["p1"], hostIds: ["h1", "h2"] });
  const hint = takeCapacityHints(tx);
  expect(hint).not.toBe("all");
  expect(hint !== "all" && [...(hint?.hostIds ?? [])].sort()).toEqual(["h1", "h2"]);
  expect(takeCapacityHints(tx)).toBeNull();
  noteCapacityChanged(tx, { poolIds: ["p1"] });
  noteCapacityChanged(tx);
  expect(takeCapacityHints(tx)).toBe("all");
});

it("notify is a no-op until bound and never throws to the committed caller", () => {
  notifyCapacityChanged();
  const wake = vi.fn(() => {
    throw new Error("scheduler down");
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  bindCapacityQueueWake(wake);
  expect(() => notifyCapacityChanged({ poolIds: ["p"] })).not.toThrow();
  expect(wake).toHaveBeenCalledWith({ poolIds: ["p"] });
  bindCapacityQueueWake(null);
});
