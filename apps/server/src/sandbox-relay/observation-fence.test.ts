import { describe, expect, it } from "vitest";
import { ObservationFence } from "./observation-fence.js";

describe("ObservationFence", () => {
  it("fences the observation possibly in flight when a result arrives, not later ones", () => {
    const fence = new ObservationFence();
    expect(fence.predates("sbx", 1)).toBe(false);
    expect(fence.accept(1)).toBe(true);
    // Observation 1 was received; 2 may be in flight when the result lands.
    fence.noteResult("sbx");
    expect(fence.predates("sbx", 1)).toBe(true);
    expect(fence.predates("sbx", 2)).toBe(true);
    expect(fence.predates("sbx", 3)).toBe(false);
    expect(fence.predates("other", 2)).toBe(false);
    // Batches of one observation share its number; it never goes back.
    expect(fence.accept(2)).toBe(true);
    expect(fence.accept(2)).toBe(true);
    expect(fence.predates("sbx", 2)).toBe(true);
    expect(fence.accept(1)).toBe(false);
  });

  /** Codex rc-fu-b r1 #1: a jump past the fenced observation would skip
   * the bound a result just set, so numbering must start at 1 and advance
   * by exactly one. */
  it("refuses a first observation other than 1 and any skipped number", () => {
    for (const jump of [0, 2, Number.MAX_SAFE_INTEGER]) {
      const fence = new ObservationFence();
      fence.noteResult("sbx");
      expect(fence.accept(jump), String(jump)).toBe(false);
      expect(fence.predates("sbx", 1)).toBe(true);
    }
    const fence = new ObservationFence();
    expect(fence.accept(1)).toBe(true);
    fence.noteResult("sbx");
    expect(fence.accept(3)).toBe(false);
    expect(fence.predates("sbx", 2)).toBe(true);
    expect(fence.accept(2)).toBe(true);
    expect(fence.accept(2)).toBe(true);
  });

  it("prunes entries that can no longer fence anything", () => {
    const fence = new ObservationFence();
    fence.noteResult("a");
    fence.accept(1);
    fence.noteResult("b");
    expect(fence.size).toBe(2);
    fence.accept(2);
    expect(fence.size).toBe(1);
    expect(fence.predates("b", 2)).toBe(true);
    fence.accept(3);
    expect(fence.size).toBe(0);
    expect(fence.predates("b", 3)).toBe(false);
  });

  it("an overflow fences more, never less", () => {
    const fence = new ObservationFence(2);
    fence.noteResult("a");
    fence.noteResult("b");
    fence.noteResult("c");
    expect(fence.size).toBe(2);
    // "a" was evicted: its bound became a session-wide floor.
    expect(fence.predates("a", 1)).toBe(true);
    expect(fence.predates("z", 1)).toBe(true);
    expect(fence.predates("z", 2)).toBe(false);
    // A repeated result moves the sandbox to the newest position.
    fence.accept(1);
    fence.noteResult("b");
    fence.noteResult("d");
    expect(fence.predates("b", 2)).toBe(true);
    expect(fence.predates("d", 2)).toBe(true);
  });
});
