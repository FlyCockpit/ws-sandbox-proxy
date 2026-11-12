// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import common from "@wssp/locales/src/en-US/common.json";
import en from "@wssp/locales/src/en-US/hosts.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const reads = vi.hoisted(() => ({ capacity: 0, queue: 0 }));
const capacity = {
  poolId: "pool-1",
  templateRevisionId: null,
  size: null,
  aggregate: {
    free: { memoryMiB: 4096, vcpu: 6, diskGiB: 100 },
    budget: { memoryMiB: 8192, vcpu: 8, diskGiB: 200 },
  },
  fits: null,
  lease: { maxTimeoutMs: 86_400_000, timeoutZero: false },
  queue: {
    waiting: 3,
    mine: 1,
    myOldestPosition: 2,
    limits: { maxWaitMs: 3_600_000, perKey: 16, perOwner: 64 },
    preferOwnHosts: true,
  },
  hosts: [
    {
      id: "own-host",
      slug: "own",
      label: "Own host",
      status: "CONNECTED",
      draining: false,
      schedulable: true,
      memory: { budgetMiB: 8192, reservedMiB: 4096 },
      vcpu: { budget: 8, reserved: 2 },
      storagePools: [],
      liveCount: 2,
      member: { memoryCapPercent: null, vcpuCapPercent: null, maxLeaseMs: null },
      fits: null,
      dominantShareAfter: null,
      excludedBy: null,
    },
  ],
};
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirectOnError: () => {} }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxPools: {
      capacity: {
        queryOptions: ({ input }: { input: unknown }) => ({
          queryKey: ["capacity", input],
          queryFn: async () => {
            reads.capacity++;
            return capacity;
          },
        }),
      },
      queue: {
        infiniteOptions: (options: { initialPageParam: unknown; getNextPageParam: unknown }) => ({
          queryKey: ["queue"],
          initialPageParam: options.initialPageParam,
          getNextPageParam: options.getNextPageParam,
          queryFn: async () => {
            reads.queue++;
            return {
              items: [
                {
                  id: "w1",
                  requester: "Grantee",
                  cpuCount: 2,
                  memoryMiB: 4096,
                  diskGiB: 32,
                  enqueuedAt: new Date(0).toISOString(),
                  deadlineAt: null,
                  blocker: "ram",
                  position: 1,
                },
              ],
              nextCursor: null,
            };
          },
        }),
      },
    },
  },
}));

import { PoolCapacityDialog } from "./pool-capacity";

afterEach(() => {
  cleanup();
  reads.capacity = 0;
  reads.queue = 0;
});

async function mount(owner: boolean) {
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en, common } } });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <PoolCapacityDialog poolId="pool-1" owner={owner} lang="en-US" onClose={() => {}} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

it("shows schedulable aggregates, the queue and own hosts; a pool owner also sees waiting creates", async () => {
  await mount(true);
  await screen.findByText(en.poolCapacity.schedulable);
  expect(screen.getAllByRole("meter").length).toBeGreaterThanOrEqual(3);
  expect(screen.getByText(/3 waiting, 1 of them yours/)).toBeTruthy();
  expect(document.querySelector("[data-capacity-host='own-host']")).toBeTruthy();
  await waitFor(() =>
    expect(document.querySelector("[data-queue-entry]")?.textContent).toContain("Grantee"),
  );
});

it("a grantee never reads the owner's queue list", async () => {
  await mount(false);
  await screen.findByText(en.poolCapacity.schedulable);
  expect(reads.capacity).toBe(1);
  expect(reads.queue).toBe(0);
  expect(document.querySelector("[data-queue-entry]")).toBeNull();
});
