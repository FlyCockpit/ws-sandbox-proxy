vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import type { SandboxTemplateAvailability, SandboxTemplateRevision } from "@wssp/db";
import { expect, it, vi } from "vitest";
import { mockDeep } from "vitest-mock-extended";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
const { AvailabilityCensus } = await import("./availability-census.js");
const { createFenceStore, installFenceTransaction, prismaPromise } = await import(
  "./fenced-prisma-harness.js"
);

function association(id: string) {
  return Object.assign(mockDeep<SandboxTemplateAvailability>(), {
    Revision: mockDeep<SandboxTemplateRevision>({
      id,
      incusFingerprint: `sha256:${"a".repeat(64)}`,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      manifestDigest: "a".repeat(64),
    }),
  });
}
it("availability_census_is_bounded_to_100_per_page_and_10000_total_without_full_census_claim", async () => {
  const store = createFenceStore({ hosts: [{ id: "host", userId: "owner", connectionEpoch: 1 }] });
  installFenceTransaction(db, store);
  let offset = 0;
  db.sandboxTemplateAvailability.findMany.mockImplementation((args) => {
    expect(args?.take).toBe(100);
    expect(args?.where).toMatchObject({
      hostOwnerId: "owner",
      hostId: "host",
      Revision: { retiredAt: null },
    });
    if (offset > 0)
      expect(args?.where?.revisionId).toEqual({ gt: `r-${String(offset - 1).padStart(5, "0")}` });
    const rows = Array.from({ length: 100 }, (_, i) =>
      association(`r-${String(offset + i).padStart(5, "0")}`),
    );
    offset += 100;
    return prismaPromise(Promise.resolve(rows));
  });
  const requests: Extract<
    import("./protocol.js").ServerControlMessage,
    { type: "availability.request" }
  >[] = [];
  const census = new AvailabilityCensus(
    { hostId: "host", userId: "owner", connectionEpoch: 1 },
    (message) => {
      if (message.type === "availability.request") requests.push(message);
    },
  );
  await census.next();
  for (let page = 0; page < 100; page++) {
    expect(requests).toHaveLength(page + 1);
    const request = requests[page]!;
    expect(request.bindings).toHaveLength(100);
    await census.next();
    expect(requests).toHaveLength(page + 1);
    await census.accept({
      type: "availability.result",
      requestId: request.requestId,
      page,
      connectionEpoch: 1,
      entries: [],
    });
  }
  await census.next();
  expect(requests).toHaveLength(100);
  expect(db.sandboxTemplateAvailability.findMany).toHaveBeenCalledTimes(100);
  expect(store.hosts.get("host")).toMatchObject({
    availabilityCensusComplete: false,
  });
});

it("availability retries dropped replies and advances after a bounded deadline without inventing verdicts", async () => {
  vi.useFakeTimers();
  try {
    const store = createFenceStore({
      hosts: [{ id: "host", userId: "owner", connectionEpoch: 1 }],
    });
    installFenceTransaction(db, store);
    db.sandboxTemplateAvailability.findMany.mockReset();
    db.sandboxTemplateAvailability.findMany
      .mockResolvedValueOnce([association("r-1")])
      .mockResolvedValue([]);
    const send = vi.fn();
    const census = new AvailabilityCensus(
      { hostId: "host", userId: "owner", connectionEpoch: 1 },
      send,
    );
    await census.next();
    const request = send.mock.calls[0]![0];
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(send).toHaveBeenCalledTimes(3);
    expect(send.mock.calls.map(([message]) => message.requestId)).toEqual([
      request.requestId,
      request.requestId,
      request.requestId,
    ]);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(db.sandboxTemplateAvailability.findMany).toHaveBeenCalledTimes(2);
    expect(store.hosts.get("host")).toMatchObject({
      availabilityCensusComplete: false,
    });
    await census.accept({
      ...request,
      type: "availability.result",
      entries: [{ binding: request.bindings[0], status: "present" }],
    });
    expect(db.sandboxTemplateAvailability.updateMany).not.toHaveBeenCalled();
    census.stop();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it("availability stop cancels a pending deadline and stale sessions never retry", async () => {
  vi.useFakeTimers();
  try {
    db.sandboxTemplateAvailability.findMany.mockReset();
    db.sandboxTemplateAvailability.findMany.mockResolvedValue([association("r")]);
    const send = vi.fn();
    let current = true;
    const census = new AvailabilityCensus(
      { hostId: "host", userId: "owner", connectionEpoch: 1, isCurrent: () => current },
      send,
    );
    await census.next();
    current = false;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(send).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    census.stop();
  } finally {
    vi.useRealTimers();
  }
});

it("a late census reply leaves retry accounting to the pending timer", async () => {
  vi.useFakeTimers();
  try {
    db.sandboxTemplateAvailability.findMany.mockReset();
    db.sandboxTemplateAvailability.findMany.mockResolvedValue([association("r")]);
    const send = vi.fn();
    let now = 0;
    const census = new AvailabilityCensus(
      { hostId: "host", userId: "owner", connectionEpoch: 1 },
      send,
      () => now,
    );
    await census.next();
    const request = send.mock.calls[0]![0];
    // The clock has advanced, but the event loop has not run the due timer.
    now = 30_001;
    await census.accept({ ...request, type: "availability.result", entries: [] });
    expect(send).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(send).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(send).toHaveBeenCalledTimes(3);
    census.stop();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});
