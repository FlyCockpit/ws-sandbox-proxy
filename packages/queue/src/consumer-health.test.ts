import { afterEach, describe, expect, it, vi } from "vitest";
import { createConsumerHeartbeat, hasExternalConsumer } from "./consumer-health";
import { QUEUE_NAMES } from "./jobs";

afterEach(() => vi.useRealTimers());

describe("createConsumerHeartbeat", () => {
  it("expires readiness when an in-flight publication stalls", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    const connection = {
      eval: vi
        .fn()
        .mockResolvedValueOnce(1)
        .mockImplementation(() => new Promise(() => {})),
      zrem: vi.fn().mockResolvedValue(1),
    };
    const heartbeat = createConsumerHeartbeat(
      connection,
      "external",
      ["reap-expired-auth-tokens"],
      () => true,
    );
    await vi.advanceTimersByTimeAsync(1);
    await heartbeat.start();
    expect(heartbeat.isReady()).toBe(true);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(heartbeat.isReady()).toBe(false);
  });
  it("starts unhealthy, publishes only healthy consumers, and expires after a stalled loop", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
    const connection = { eval: vi.fn().mockResolvedValue(1), zrem: vi.fn().mockResolvedValue(1) };
    let healthy = true;
    const heartbeat = createConsumerHeartbeat(
      connection,
      "embedded",
      ["reap-expired-auth-tokens"],
      () => healthy,
    );
    expect(heartbeat.isReady()).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await heartbeat.start();
    expect(heartbeat.isReady()).toBe(true);
    expect(connection.eval.mock.calls[0]?.[2]).toBe(
      "wssp:consumers:v1:embedded:reap-expired-auth-tokens",
    );
    healthy = false;
    expect(heartbeat.isReady()).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(connection.eval).toHaveBeenCalledTimes(1);
    await heartbeat.stop();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(connection.eval).toHaveBeenCalledTimes(1);
  });

  it("withdraws its own UUID only after pending publication settles", async () => {
    let finish: (() => void) | undefined;
    const connection = {
      eval: vi.fn(
        (_script: string | Buffer, _numkeys: number | string, ..._args: unknown[]) =>
          new Promise<void>((resolve) => {
            finish = resolve;
          }),
      ),
      zrem: vi.fn().mockResolvedValue(1),
    };
    const heartbeat = createConsumerHeartbeat(
      connection,
      "external",
      ["reap-expired-auth-tokens"],
      () => true,
    );
    const starting = heartbeat.start();
    const rejected = expect(starting).rejects.toThrow("not running");
    const stopping = heartbeat.stop();
    expect(heartbeat.stop()).toBe(stopping);
    expect(connection.zrem).not.toHaveBeenCalled();
    finish?.();
    await rejected;
    await stopping;
    expect(connection.zrem).toHaveBeenCalledWith(
      "wssp:consumers:v1:external:reap-expired-auth-tokens",
      connection.eval.mock.calls[0]?.[3],
    );
    expect(heartbeat.isReady()).toBe(false);
    await expect(heartbeat.start()).rejects.toThrow();
  });

  it("fails closed on heartbeat failure and isolates external availability", async () => {
    const connection = {
      eval: vi.fn().mockRejectedValue(new Error("offline")),
      zrem: vi.fn().mockResolvedValue(1),
    };
    const heartbeat = createConsumerHeartbeat(
      connection,
      "external",
      ["reap-expired-auth-tokens"],
      () => true,
    );
    await expect(heartbeat.start()).rejects.toThrow("offline");
    expect(heartbeat.isReady()).toBe(false);
    await heartbeat.stop();
    connection.eval.mockResolvedValue(0);
    expect(await hasExternalConsumer(connection, ["reap-expired-auth-tokens"])).toBe(false);
    connection.eval.mockResolvedValue(1);
    expect(await hasExternalConsumer(connection, ["reap-expired-auth-tokens"])).toBe(true);
    expect(connection.eval.mock.lastCall?.[2]).toBe(
      "wssp:consumers:v1:external:reap-expired-auth-tokens",
    );
    expect(connection.eval.mock.lastCall?.[0]).toContain("redis.call('TIME')");
  });

  it("rejects an empty inventory and publishes every queue under one replica identity", async () => {
    const connection = { eval: vi.fn().mockResolvedValue(1), zrem: vi.fn().mockResolvedValue(1) };
    expect(await hasExternalConsumer(connection, [])).toBe(false);
    const empty = createConsumerHeartbeat(connection, "external", [], () => true);
    await expect(empty.start()).rejects.toThrow("not running");
    expect(connection.eval).not.toHaveBeenCalled();
    const first = createConsumerHeartbeat(
      connection,
      "external",
      ["reap-expired-auth-tokens", "new-queue"],
      () => true,
    );
    const second = createConsumerHeartbeat(
      connection,
      "external",
      ["reap-expired-auth-tokens", "new-queue"],
      () => true,
    );
    await first.start();
    await second.start();
    const firstCall = connection.eval.mock.calls[0];
    expect(firstCall?.slice(1, 4)).toEqual([
      2,
      "wssp:consumers:v1:external:reap-expired-auth-tokens",
      "wssp:consumers:v1:external:new-queue",
    ]);
    expect(firstCall?.[4]).not.toBe(connection.eval.mock.calls[1]?.[4]);
    await first.stop();
    expect(connection.zrem.mock.calls).toEqual([
      ["wssp:consumers:v1:external:reap-expired-auth-tokens", firstCall?.[4]],
      ["wssp:consumers:v1:external:new-queue", firstCall?.[4]],
    ]);
    await second.stop();
  });
});

it("includes deletion-notice consumption in external readiness", async () => {
  const connection = { eval: vi.fn().mockResolvedValue(0), zrem: vi.fn().mockResolvedValue(1) };
  expect(await hasExternalConsumer(connection, Object.values(QUEUE_NAMES))).toBe(false);
  const call = connection.eval.mock.lastCall;
  expect(call?.[1]).toBe(Object.keys(QUEUE_NAMES).length);
  expect(call?.slice(2)).toContain("wssp:consumers:v1:external:notify-data-deletions");
});
