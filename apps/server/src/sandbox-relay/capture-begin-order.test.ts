import { beforeEach, describe, expect, it, vi } from "vitest";

const count = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db", () => ({ default: { sandboxTemplateCapture: { count } } }));

const { CaptureBeginOrder, CAPTURE_BEGINS_HELD_MAX } = await import("./capture-begin-order.js");

const sender = { userId: "owner", hostId: "host-1", connectionEpoch: 3 } as never;
const begin = (operationId: string, attempt = 1) =>
  ({
    type: "image.upload.begin",
    requestId: `req-${operationId}`,
    operationId,
    attempt,
  }) as never;

describe("capture begin ordering", () => {
  beforeEach(() => count.mockReset());

  it("holds a begin whose capture result is pending and releases it by operation", async () => {
    count.mockResolvedValue(1);
    const order = new CaptureBeginOrder();
    expect(await order.hold(sender, begin("op-1"))).toBe("held");
    expect(order.release("op-2")).toEqual([]);
    expect(order.release("op-1")).toEqual([begin("op-1")]);
    expect(order.size).toBe(0);
  });

  it("handles a begin at once when its result is already recorded", async () => {
    count.mockResolvedValue(0);
    expect(await new CaptureBeginOrder().hold(sender, begin("op-1"))).toBe("handle");
  });

  it("a failed lookup neither handles the begin early nor holds it: retry", async () => {
    count.mockRejectedValueOnce(new Error("database unavailable"));
    const order = new CaptureBeginOrder();
    expect(await order.hold(sender, begin("op-1"))).toBe("retry");
    expect(order.size).toBe(0);
    // The daemon's retried begin is looked up again.
    count.mockResolvedValueOnce(1);
    expect(await order.hold(sender, begin("op-1"))).toBe("held");
    count.mockResolvedValueOnce(0);
    expect(await order.hold(sender, begin("op-1"))).toBe("handle");
    expect(order.size).toBe(0);
  });

  it("holds at most CAPTURE_BEGINS_HELD_MAX per connection", async () => {
    count.mockResolvedValue(1);
    const order = new CaptureBeginOrder();
    for (let i = 0; i < CAPTURE_BEGINS_HELD_MAX; i++)
      expect(await order.hold(sender, begin(`op-${i}`))).toBe("held");
    expect(await order.hold(sender, begin("op-over"))).toBe("handle");
    expect(await order.hold(sender, begin("op-0"))).toBe("held");
    expect(order.size).toBe(CAPTURE_BEGINS_HELD_MAX);
  });
});
