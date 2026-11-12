import { describe, expect, it, vi } from "vitest";

import { registerPushSubscription } from "./push-subscription";

function browserSubscription() {
  return {
    toJSON: () => ({ endpoint: "https://push.example.test/subscription" }),
    unsubscribe: vi.fn().mockResolvedValue(true),
  } as unknown as PushSubscription;
}

describe("registerPushSubscription", () => {
  it("keeps a successfully registered subscription for future notifications", async () => {
    const subscription = browserSubscription();
    const manager = {
      getSubscription: vi.fn().mockResolvedValue(null),
      subscribe: vi.fn().mockResolvedValue(subscription),
    };
    const persist = vi.fn().mockResolvedValue(undefined);
    await registerPushSubscription(manager, new Uint8Array(), persist);
    expect(persist).toHaveBeenCalledWith(subscription.toJSON());
    expect(subscription.unsubscribe).not.toHaveBeenCalled();
  });

  it("rolls back a new subscription when server registration fails", async () => {
    const subscription = browserSubscription();
    const error = new Error("registration failed");
    const manager = {
      getSubscription: vi.fn().mockResolvedValue(null),
      subscribe: vi.fn().mockResolvedValue(subscription),
    };
    await expect(
      registerPushSubscription(manager, new Uint8Array(), async () => {
        throw error;
      }),
    ).rejects.toBe(error);
    expect(subscription.unsubscribe).toHaveBeenCalledOnce();
  });

  it("preserves an existing subscription when re-registration fails", async () => {
    const subscription = browserSubscription();
    const manager = {
      getSubscription: vi.fn().mockResolvedValue(subscription),
      subscribe: vi.fn(),
    };
    await expect(
      registerPushSubscription(manager, new Uint8Array(), async () => {
        throw new Error("offline");
      }),
    ).rejects.toThrow("offline");
    expect(manager.subscribe).not.toHaveBeenCalled();
    expect(subscription.unsubscribe).not.toHaveBeenCalled();
  });
});
