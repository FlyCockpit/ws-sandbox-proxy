vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import { useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_OBSERVABILITY_SEARCH,
  type ObservabilitySearch,
  parseObservabilitySearch,
} from "@/lib/admin-observability-search";

/**
 * Admin observability against a scripted keyset-paging server. Real TanStack
 * Query and en-US strings; the URL search is held by a test harness.
 */

type Call = { procedure: string; input: Record<string, unknown> | undefined };

const server = vi.hoisted(() => ({
  calls: [] as Call[],
  hostPages: {} as Record<string, { items: unknown[]; nextCursor: string | null }>,
  sandboxes: [] as unknown[],
  operations: [] as unknown[],
  listError: null as unknown,
  users: [] as { id: string; name: string; email: string }[],
}));

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

vi.mock("@/components/admin/maintenance-status", () => ({
  MaintenanceStatus: () => <div data-testid="maintenance" />,
}));

vi.mock("@/utils/orpc", () => {
  const list = (
    procedure: string,
    respond: (input: Record<string, unknown> | undefined) => unknown,
  ) => ({
    queryOptions: ({ input }: { input?: Record<string, unknown> } = {}) => ({
      queryKey: ["adminObservability", procedure, input],
      queryFn: async () => {
        server.calls.push({ procedure, input });
        if (server.listError) throw server.listError;
        return structuredClone(respond(input));
      },
    }),
  });
  return {
    orpc: {
      users: {
        list: {
          call: async (input: { search?: string; limit: number }) => {
            server.calls.push({ procedure: "users.list", input });
            const query = input.search?.toLowerCase() ?? "";
            return {
              users: server.users.filter(
                (user) =>
                  user.name.toLowerCase().includes(query) ||
                  user.email.toLowerCase().includes(query),
              ),
              nextCursor: null,
            };
          },
        },
      },
      adminObservability: {
        counters: list("counters", () => ({
          users: 3,
          hosts: 2,
          sandboxes: 5,
          operations: 1200,
          leases: {
            expiredPending: 11,
            unacknowledgedRenewals: 12,
            hostEnforced: 13,
            quarantinedHosts: 14,
            relayOutbox: 15,
          },
          queues: [],
          webhooks: {
            endpoints: 4,
            enabled: 3,
            disabledForFailures: 1,
            deliveries24h: { PENDING: 2, IN_FLIGHT: 0, SUCCEEDED: 9, FAILED: 1, CANCELLED: 0 },
            oldestPendingAgeSeconds: 30,
            errorClasses24h: [],
          },
        })),
        // Metadata-only webhook endpoint list (host, never path or query).
        listWebhookEndpoints: {
          infiniteOptions: (options: {
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["adminObservability", "listWebhookEndpoints"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async () => ({
              items: [
                {
                  id: "whe-1",
                  ownerId: "owner-9",
                  owner: { name: "Grace", email: "grace@example.test" },
                  createdAt: new Date(0),
                  host: "hooks.example.com",
                  state: "sustained_failures",
                  consecutiveFailures: 21,
                  failingSince: null,
                  lastSuccessAt: null,
                },
              ],
              nextCursor: null,
            }),
          }),
        },
        listHosts: list(
          "listHosts",
          (input) =>
            server.hostPages[String(input?.cursor ?? "")] ?? { items: [], nextCursor: null },
        ),
        listSandboxes: list("listSandboxes", () => ({ items: server.sandboxes, nextCursor: null })),
        listOperations: list("listOperations", () => ({
          items: server.operations,
          nextCursor: null,
        })),
      },
    },
  };
});

import { AdminObservabilityPage } from "./admin-observability-page";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin", "common", "operations", "sandboxes"],
    defaultNS: "admin",
    resources: {
      "en-US": {
        admin: enAdmin,
        common: enCommon,
        operations: enOperations,
        sandboxes: enSandboxes,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

const OWNER = { name: "Ada Lovelace", email: "ada@example.test" };

// The owner picker's command list measures itself; jsdom has neither API.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= NoopResizeObserver as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};

function host(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    userId: "owner-1",
    owner: OWNER,
    createdAt: new Date("2026-02-01T00:00:00.000Z"),
    status: "CONNECTED",
    lastHeartbeatAt: new Date("2026-02-01T00:00:00.000Z"),
    draining: false,
    quarantinedAt: null,
    liveCount: 1,
    rootCount: 2,
    daemonVcpuBudget: 8,
    vcpuReserved: 3,
    memoryReservedMiB: 3072,
    daemonMemoryBudgetMiB: 2048,
    daemonMaxCpuCount: 4,
    ...overrides,
  };
}

let currentSearch: ObservabilitySearch = DEFAULT_OBSERVABILITY_SEARCH;

function Harness({ initial }: { initial: ObservabilitySearch }) {
  const [search, setSearch] = useState(initial);
  currentSearch = search;
  return (
    <AdminObservabilityPage
      search={search}
      onSearch={(patch) =>
        // Round-trip through the real URL parser, as the route does.
        setSearch((prev) => parseObservabilitySearch({ ...prev, ...patch }))
      }
    />
  );
}

function mount(initial: Partial<ObservabilitySearch> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <Harness initial={{ ...DEFAULT_OBSERVABILITY_SEARCH, ...initial }} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const hostCalls = () => server.calls.filter((call) => call.procedure === "listHosts");
const rowIds = () =>
  [...document.querySelectorAll("tr[data-row-id]")].map((row) => row.getAttribute("data-row-id"));

beforeEach(() => {
  server.calls = [];
  server.listError = null;
  server.users = [];
  server.sandboxes = [];
  server.operations = [];
  server.hostPages = {
    "": { items: [host("h-3"), host("h-2")], nextCursor: "cursor-2" },
    "cursor-2": {
      items: [host("h-1", { status: "REVOKED", draining: true, quarantinedAt: new Date() })],
      nextCursor: null,
    },
  };
});
afterEach(() => cleanup());

describe("admin observability", () => {
  it("matches the operations loading columns to the rendered table headers", async () => {
    server.operations = [
      {
        id: "op-1",
        userId: "owner-1",
        owner: OWNER,
        kind: "CREATE_SANDBOX",
        state: "QUEUED",
        generation: 1,
        sandboxId: "sbx-1",
        updatedAt: new Date(),
      },
    ];
    mount({ tab: "operations" });
    const skeletonRows = [...document.querySelectorAll<HTMLElement>("section [style]")].filter(
      (element) => element.style.gridTemplateColumns,
    );
    expect(skeletonRows).toHaveLength(6);
    const loadingColumns = skeletonRows.map((row) => row.children.length);
    await screen.findByText("op-1");
    const headers = screen.getAllByRole("columnheader");
    expect(headers).toHaveLength(6);
    expect(loadingColumns).toEqual(Array(6).fill(headers.length));
  });

  it("shows the totals and pages hosts forward and back with keyset cursors", async () => {
    const u = userEvent.setup();
    mount();
    expect((await screen.findByText("1,200")).getAttribute("data-counter")).toBe("operations");
    const leases = screen.getByRole("region", { name: enAdmin.observability.leases.ariaLabel });
    expect(
      [...leases.querySelectorAll("[data-counter]")].map((tile) => [
        tile.getAttribute("data-counter"),
        tile.textContent,
      ]),
    ).toEqual([
      ["expiredPending", "11"],
      ["unacknowledgedRenewals", "12"],
      ["hostEnforced", "13"],
      ["quarantinedHosts", "14"],
      ["relayOutbox", "15"],
    ]);
    expect(leases.textContent).toContain(enAdmin.observability.leases.quarantinedHosts);
    await screen.findByText("h-3");
    expect(rowIds()).toEqual(["h-3", "h-2"]);
    expect(screen.getByText("Page 1")).toBeTruthy();
    const previous = screen.getByRole("button", { name: enAdmin.observability.previous });
    expect(previous).toHaveProperty("disabled", true);

    await u.click(screen.getByRole("button", { name: enAdmin.observability.next }));
    await screen.findByText("h-1");
    expect(rowIds()).toEqual(["h-1"]);
    expect(screen.getByText("Page 2")).toBeTruthy();
    expect(screen.getByText(enAdmin.observability.hostStatus.REVOKED)).toBeTruthy();
    expect(screen.getByText(enAdmin.observability.draining)).toBeTruthy();
    expect(screen.getByText(enAdmin.observability.quarantined)).toBeTruthy();
    expect(screen.getByRole("button", { name: enAdmin.observability.next })).toHaveProperty(
      "disabled",
      true,
    );
    expect(hostCalls().map((call) => call.input?.cursor)).toEqual([undefined, "cursor-2"]);

    await u.click(screen.getByRole("button", { name: enAdmin.observability.previous }));
    await waitFor(() => expect(rowIds()).toEqual(["h-3", "h-2"]));
    expect(screen.getByText("Page 1")).toBeTruthy();
    for (const call of hostCalls()) expect(call.input?.limit).toBe(25);
  });

  it("resets to the first page when a filter changes and sends only exact filters", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText("h-3");
    await u.click(screen.getByRole("button", { name: enAdmin.observability.next }));
    await screen.findByText("h-1");

    // Clicking an owner id narrows the view to that owner.
    await u.click(
      screen.getByRole("button", {
        name: enAdmin.observability.filterByOwner.replace("{{id}}", "owner-1"),
      }),
    );
    expect(currentSearch.owner).toBe("owner-1");
    await waitFor(() =>
      expect(hostCalls().at(-1)?.input).toEqual({
        limit: 25,
        cursor: undefined,
        ownerId: "owner-1",
        status: undefined,
      }),
    );
    expect(await screen.findByText("Page 1")).toBeTruthy();
  });

  it("filters by an owner picked by name or email, and shows them by name", async () => {
    server.users = [
      { id: "owner-9", name: "Grace Hopper", email: "grace@example.test" },
      { id: "owner-1", name: "Ada Lovelace", email: "ada@example.test" },
    ];
    const u = userEvent.setup();
    mount();
    await screen.findByText("h-3");
    await u.click(screen.getByRole("combobox", { name: enAdmin.observability.filters.owner }));
    await u.type(
      await screen.findByPlaceholderText(enAdmin.observability.filters.ownerSearch),
      "grace",
    );
    await u.click(await screen.findByRole("option", { name: /Grace Hopper/ }));
    expect(currentSearch.owner).toBe("owner-9");
    await waitFor(() => expect(hostCalls().at(-1)?.input?.ownerId).toBe("owner-9"));
    expect(document.querySelector('[data-owner-filter="owner-9"]')?.textContent).toContain(
      "Grace Hopper (grace@example.test)",
    );
    await u.click(screen.getByRole("button", { name: enAdmin.observability.filters.ownerClear }));
    expect(currentSearch.owner).toBe("");
  });

  it("does not query with an id no row could have, and says why", async () => {
    mount({ owner: "bad id!" });
    expect(await screen.findByText(enAdmin.observability.filters.fixToSearch)).toBeTruthy();
    expect(screen.getByText(enAdmin.observability.filters.invalidId)).toBeTruthy();
    expect(
      document.querySelector('[data-owner-filter] [aria-invalid="true"]')?.textContent,
    ).toContain("bad id!");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 400));
    });
    expect(hostCalls()).toHaveLength(0);
  });

  it("links a host to its sandboxes and renders metadata only", async () => {
    const u = userEvent.setup();
    server.sandboxes = [
      {
        id: "sbx-1",
        userId: "owner-1",
        owner: OWNER,
        createdAt: new Date("2026-02-01T00:00:00.000Z"),
        sandboxHostId: "h-3",
        templateId: "tpl-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
        state: "READY",
        generation: 7,
        cpuCount: 2,
        memoryMiB: 3072,
        diskGiB: 32,
      },
    ];
    mount();
    await screen.findByText("h-3");
    await u.click(
      screen.getByRole("button", {
        name: enAdmin.observability.showHostSandboxes.replace("{{id}}", "h-3"),
      }),
    );
    await screen.findByText("sbx-1");
    expect(currentSearch).toMatchObject({ tab: "sandboxes", host: "h-3" });
    const call = server.calls.filter((entry) => entry.procedure === "listSandboxes").at(-1);
    expect(call?.input).toEqual({
      limit: 25,
      cursor: undefined,
      ownerId: undefined,
      hostId: "h-3",
      state: undefined,
    });
    expect(screen.getByText(enSandboxes.state.READY)).toBeTruthy();
    expect(screen.getByText("Generation 7")).toBeTruthy();
    expect(screen.getByText("2 vCPU · 3072 MiB · 32 GiB")).toBeTruthy();
  });

  it("shows filter labels, not raw values, and clears one tab's filters when switching tabs (M7-S15)", async () => {
    const u = userEvent.setup();
    mount({ hostStatus: "STALE" });
    await screen.findByText("h-3");
    const trigger = screen.getByLabelText(enAdmin.observability.filters.hostStatus);
    expect(trigger.textContent).toContain(enAdmin.observability.hostStatus.STALE);
    expect(trigger.textContent).not.toContain("STALE");

    await u.click(screen.getByRole("button", { name: enAdmin.observability.tabs.sandboxes }));
    expect(currentSearch).toMatchObject({ tab: "sandboxes", hostStatus: "all" });
    const stateTrigger = screen.getByLabelText(enAdmin.observability.filters.sandboxState);
    expect(stateTrigger.textContent).toContain(enAdmin.observability.filters.allStates);
    expect(stateTrigger.textContent).not.toMatch(/\ball\b/);
  });

  it("keeps wide tables in their own horizontal scroller with touch-sized controls", async () => {
    mount();
    await screen.findByText("h-3");
    const table = document.querySelector("table")!;
    expect(table.parentElement?.className).toContain("overflow-x-auto");
    for (const name of [enAdmin.observability.previous, enAdmin.observability.next]) {
      expect(screen.getByRole("button", { name }).className).toContain("min-h-[44px]");
    }
    for (const button of within(table).getAllByRole("button")) {
      expect(button.className).toContain("min-h-[44px]");
    }
  });

  it("shows a retry instead of an empty table when a page fails", async () => {
    server.listError = new Error("network");
    mount();
    expect((await screen.findAllByText(enAdmin.observability.loadFailed)).length).toBeGreaterThan(
      0,
    );
    expect(screen.queryByText(enAdmin.observability.empty)).toBeNull();
    expect(
      screen.getAllByRole("button", { name: enCommon.actions.tryAgain }).length,
    ).toBeGreaterThan(0);
  });

  it("puts maintenance status inside observability", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText("h-3");
    await u.click(screen.getByRole("button", { name: enAdmin.observability.tabs.maintenance }));
    expect(await screen.findByTestId("maintenance")).toBeTruthy();
    expect(currentSearch.tab).toBe("maintenance");
  });
});

it("shows webhook counters and endpoint hosts as metadata only", async () => {
  mount();
  expect(await screen.findByText("hooks.example.com")).toBeTruthy();
  const row = document.querySelector('[data-webhook-endpoint="whe-1"]');
  expect(row?.textContent).toContain(enAdmin.observability.webhooks.state.sustained_failures);
  expect(row?.textContent).not.toMatch(/\/|\?|token/);
  expect(document.querySelector('[data-counter="disabledForFailures"]')?.textContent).toBe("1");
});

it("shows owners by name with ids in copy chips, full labels, durations and singular counts", async () => {
  server.hostPages = {
    "": { items: [host("h-9", { liveCount: 1, rootCount: 1 })], nextCursor: null },
  };
  const u = userEvent.setup();
  mount();
  const row = await waitFor(() => {
    const found = document.querySelector<HTMLElement>('tr[data-row-id="h-9"]');
    if (!found) throw new Error("no row");
    return found;
  });
  // The owner's name comes first and filters; the id sits in a copy chip.
  expect(within(row).getByText("Ada Lovelace")).toBeTruthy();
  expect(within(row).getByText("ada@example.test")).toBeTruthy();
  expect(within(row).getByRole("button", { name: "Copy owner ID" })).toBeTruthy();
  expect(within(row).getByRole("button", { name: "Copy host ID" })).toBeTruthy();
  expect(row.textContent).toContain("1 live sandbox · 1 stopped sandbox disk");
  // Connected is the same green as on the Hosts page.
  expect(within(row).getByText(enAdmin.observability.hostStatus.CONNECTED).className).toContain(
    "emerald",
  );
  // KPI labels wrap instead of truncating; the oldest pending delivery is a duration.
  const oldest = document.querySelector('[data-counter="oldestPending"]');
  expect(oldest?.textContent).toBe("30 sec");
  const label = oldest?.parentElement?.querySelector("p");
  expect(label?.textContent).toBe(enAdmin.observability.webhooks.oldestPending);
  expect(label?.className).not.toContain("truncate");
  // Clicking the owner's name narrows to them and the filter shows the name.
  await u.click(
    within(row).getByRole("button", {
      name: enAdmin.observability.filterByOwner.replace("{{id}}", "owner-1"),
    }),
  );
  expect(currentSearch.owner).toBe("owner-1");
  expect(document.querySelector('[data-owner-filter="owner-1"]')?.textContent).toContain(
    "Ada Lovelace (ada@example.test)",
  );
});

it("formats ages as coarse durations", async () => {
  const { formatAgeSeconds } = await import("@/lib/admin-observability-search");
  expect(formatAgeSeconds(30, "en-US")).toBe("30 sec");
  expect(formatAgeSeconds(125, "en-US")).toBe("2 min");
  expect(formatAgeSeconds(3 * 3600 + 5 * 60, "en-US")).toBe("3 hr 5 min");
  expect(formatAgeSeconds(2 * 86400 + 4 * 3600, "en-US")).toBe("2 days 4 hr");
});
