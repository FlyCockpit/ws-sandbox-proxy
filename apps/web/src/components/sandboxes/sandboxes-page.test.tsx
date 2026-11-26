vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import { type ReactNode, useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";

import {
  coded,
  type FakeSandboxServer,
  fakeHost,
  fakeTemplate,
  NOT_FOUND,
  newFakeSandboxServer,
  sandboxRow,
} from "@/test/sandbox-fake";
import { selectOption } from "@/test/select-option";

/**
 * Sandboxes list against a scripted fake server (real TanStack Query and
 * i18n): rows show exactly what the server reported — queued, unknown and
 * offline included — and every create entry links to the Create sandbox page
 * (its behaviour is covered in `create-sandbox-page.test.tsx`).
 */

const server = vi.hoisted(() => ({ current: null as unknown as FakeSandboxServer }));
const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), message: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
// CLI logins are covered by their own tests; here the server has them off.
vi.mock("@/components/logins/logins-shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/logins/logins-shared")>()),
  useLoginsAvailability: () => "unavailable",
}));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({
    children,
    className,
    to,
    params,
    ...rest
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
    "aria-label"?: string;
  }) => (
    <a
      className={className}
      aria-label={rest["aria-label"]}
      href={Object.entries(params ?? {}).reduce(
        (path, [key, value]) => path.replace(`$${key}`, value),
        to,
      )}
    >
      {children}
    </a>
  ),
}));
vi.mock("@/utils/orpc", async () => {
  const { fakeSandboxOrpc } = await import("@/test/sandbox-fake");
  return {
    orpc: new Proxy(
      {},
      {
        get: (_, key) =>
          (fakeSandboxOrpc(server.current) as Record<string, unknown>)[key as string],
      },
    ),
  };
});

import { orpc } from "@/utils/orpc";
import { SandboxesPage } from "./sandboxes-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "sandboxes", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": { common: enCommon, dashboard: enDashboard, sandboxes: enSandboxes, hosts: enHosts },
      "es-MX": { common: esCommon, dashboard: esDashboard, sandboxes: esSandboxes, hosts: esHosts },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

/** The last search the page wrote, as the route would put it in the URL. */
let lastSearch: { status: "active" | "deleted" | "all"; name?: string } | null = null;
/** Back/Forward: the route hands the page a new search without the input writing it. */
let setSearchFromUrl: (search: { status: "active" | "deleted" | "all"; name?: string }) => void =
  () => {};

/** Stands in for the route: `?status=` and `?name=` state, the way the URL holds them. */
function StatefulSandboxesPage({ lang }: { lang: string }) {
  const [search, setSearch] = useState<{
    status: "active" | "deleted" | "all";
    name?: string;
  }>({ status: "active" });
  setSearchFromUrl = setSearch;
  return (
    <SandboxesPage
      lang={lang}
      userId="user-1"
      status={search.status}
      name={search.name}
      onSearchChange={(next) => {
        lastSearch = next;
        setSearch(next);
      }}
    />
  );
}

let client: QueryClient;
async function mount(lang = "en-US") {
  await i18n.changeLanguage(lang);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <StatefulSandboxesPage lang={lang} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const row = (id: string) => document.querySelector<HTMLElement>(`li[data-sandbox-id="${id}"]`)!;
const step = (id: string) => document.querySelector<HTMLElement>(`li[data-step="${id}"]`)!;

beforeEach(() => {
  server.current = newFakeSandboxServer();
  server.current.hosts = [
    fakeHost(),
    fakeHost({ id: "host-2", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
  ];
  server.current.templates = [
    fakeTemplate(),
    fakeTemplate({
      id: "tpl-2",
      templateId: "logical-2",
      sandboxHostId: "host-2",
      slug: "debian",
      label: "Debian",
    }),
  ];
  navigate.mockReset();
  toast.success.mockReset();
  toast.message.mockReset();
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("sandboxes list", () => {
  it("loading shows a skeleton, then the getting-started checklist for a first-time user", async () => {
    const view = await mount();
    expect(view.container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    expect(await screen.findByText(enSandboxes.onboarding.title)).toBeTruthy();
    expect(screen.getByText("2 of 3 done")).toBeTruthy();
    expect(calls("list")[0]?.input).toMatchObject({ status: "active", limit: 50 });
    // Every done state is one bounded read: "any sandbox, ever" (deleted
    // included), and hosts (enough to find a ready one), pools, templates.
    expect(calls("list:first")[0]?.input).toEqual({ limit: 1, status: "all" });
    expect(calls("listHosts:first")[0]?.input).toMatchObject({ limit: 20 });
    for (const procedure of ["listPools:first", "listTemplates:first"])
      expect(calls(procedure)[0]?.input, procedure).toMatchObject({ limit: 1 });
    // The empty Active list still says what it is, below the checklist.
    expect(screen.getByText(enSandboxes.empty.activeTitle)).toBeTruthy();
  });

  it("an enrolled host that cannot take sandboxes yet points at Hosts, not at enrolling another", async () => {
    server.current.hosts = [
      fakeHost({ egressGuard: { ok: false, reason: "guard_unreachable", leaseActive: false } }),
      fakeHost({ id: "host-2", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
    ];
    server.current.pools = [];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    expect(step("host").hasAttribute("data-done")).toBe(false);
    expect(screen.getByText(enSandboxes.onboarding.host.notReady)).toBeTruthy();
    expect(screen.getByRole("link", { name: enSandboxes.onboarding.host.openHosts })).toBeTruthy();
    expect(
      screen.getByRole("link", { name: enSandboxes.onboarding.host.poolsAction }),
    ).toBeTruthy();
  });

  it("a connected host with a running egress guard completes the first step", async () => {
    server.current.hosts = [fakeHost()];
    server.current.pools = [];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    expect(step("host").hasAttribute("data-done")).toBe(true);
  });

  it("the checklist marks what is done and counts a shared pool as a place to run", async () => {
    server.current.hosts = [];
    server.current.pools = [{ id: "pool-shared", slug: "team", label: "Team pool" }] as never;
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    expect(step("host").hasAttribute("data-done")).toBe(true);
    expect(within(step("host")).getByText("(Done)", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("link", { name: enSandboxes.onboarding.host.action })).toBeNull();
  });

  it("stays above the list whatever the filter shows; Deleted keeps its own empty state", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText(enSandboxes.empty.deletedTitle)).toBeTruthy();
    expect(screen.getByText(enSandboxes.onboarding.title)).toBeTruthy();
  });

  it("a sandbox seen in the list keeps it done after switching to an empty filter", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    expect(calls("list:first")).toHaveLength(1);
    // The first sandbox is created elsewhere (the CLI); the list's polling sees
    // it, while the "any sandbox?" read still holds its cached "none".
    server.current.sandboxes = [sandboxRow({ state: "READY" })];
    await act(() => client.refetchQueries({ queryKey: ["sandboxes", "list", "infinite"] }));
    await screen.findByText("quiet-otter");
    expect(document.querySelector("[data-getting-started]")).toBeNull();
    const hostReads = calls("listHosts:first").length;
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText(enSandboxes.empty.deletedTitle)).toBeTruthy();
    // Re-asked instead of trusting the stale "none", and the answer holds.
    await waitFor(() => expect(calls("list:first")).toHaveLength(2));
    await act(async () => {});
    expect(document.querySelector("[data-getting-started]")).toBeNull();
    expect(calls("listHosts:first")).toHaveLength(hostReads);
  });

  it("on an empty filter it keeps asking, so a sandbox made elsewhere completes it", async () => {
    // Fake timers from the start: the poll is scheduled when the read first answers.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    onTestFinished(() => {
      // Timers still pending on the fake clock would be dropped by the switch
      // back, stranding module-level schedulers (a later Select never opens).
      vi.runOnlyPendingTimers();
      vi.useRealTimers();
    });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText(enSandboxes.empty.deletedTitle)).toBeTruthy();
    const asked = calls("list:first").length;
    // The first sandbox comes from the CLI while Deleted shows no rows.
    server.current.sandboxes = [sandboxRow({ state: "READY" })];
    await act(() => vi.advanceTimersByTimeAsync(15_000));
    await waitFor(() => expect(calls("list:first").length).toBeGreaterThan(asked));
    await waitFor(() => expect(document.querySelector("[data-getting-started]")).toBeNull());
  });

  it.each([
    ["an active sandbox", "READY"],
    ["only a deleted sandbox", "DELETED"],
  ])("with %s the checklist is done for good, and its step reads never run", async (_, state) => {
    server.current.sandboxes = [sandboxRow({ state })];
    await mount();
    if (state === "READY") await screen.findByText("quiet-otter");
    else await screen.findByText(enSandboxes.empty.activeTitle);
    await act(async () => {});
    expect(document.querySelector("[data-getting-started]")).toBeNull();
    for (const procedure of ["listHosts:first", "listPools:first", "listTemplates:first"])
      expect(calls(procedure), procedure).toEqual([]);
    // Rows on screen already prove a sandbox exists: not even that read.
    if (state === "READY") expect(calls("list:first")).toEqual([]);
  });

  it("Hide removes it for this user, and the toast's Undo brings it back", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    await user.click(screen.getByRole("button", { name: enCommon.gettingStarted.hideAriaLabel }));
    expect(document.querySelector("[data-getting-started]")).toBeNull();
    expect(window.localStorage.getItem("wssp.getting-started.hidden.user-1")).toBe("1");
    expect(toast.message).toHaveBeenCalledWith(enCommon.gettingStarted.hidden, {
      action: { label: enCommon.gettingStarted.undo, onClick: expect.any(Function) },
    });
    const undo = toast.message.mock.calls[0]?.[1]?.action.onClick as () => void;
    act(() => undo());
    expect(await screen.findByText(enSandboxes.onboarding.title)).toBeTruthy();
    expect(window.localStorage.getItem("wssp.getting-started.hidden.user-1")).toBeNull();
  });

  it("a user who hid it gets no checklist and no step reads", async () => {
    window.localStorage.setItem("wssp.getting-started.hidden.user-1", "1");
    await mount();
    await screen.findByText(enSandboxes.empty.activeTitle);
    await act(async () => {});
    expect(document.querySelector("[data-getting-started]")).toBeNull();
    for (const procedure of ["list:first", "listHosts:first", "listTemplates:first"])
      expect(calls(procedure), procedure).toEqual([]);
  });

  it("is collapsed below sm to its title and progress, and opens on demand", async () => {
    // A phone: `(min-width: 40rem)` does not match (jsdom has no matchMedia).
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: (query: string) => ({ matches: false, media: query }),
    });
    onTestFinished(() => {
      Reflect.deleteProperty(window, "matchMedia");
    });
    const user = userEvent.setup();
    await mount();
    const toggle = await screen.findByRole("button", { name: /Get your first sandbox running/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    const list = document.getElementById(toggle.getAttribute("aria-controls") ?? "");
    expect(list?.hidden).toBe(true);
    expect(within(toggle).getByText("2 of 3 done")).toBeTruthy();
    await user.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(list?.hidden).toBe(false);
  });

  it("a failed first load shows a retry that recovers", async () => {
    server.current.errors.list = [new Error("network")];
    const user = userEvent.setup();
    await mount();
    const retry = await screen.findByRole("button", { name: enCommon.actions.tryAgain });
    expect(screen.getByText(enDashboard.list.loadFailed)).toBeTruthy();
    server.current.sandboxes = [sandboxRow()];
    await user.click(retry);
    expect(await screen.findByText("quiet-otter")).toBeTruthy();
  });

  it.each([401, 403, 404])(
    "hides a previously loaded sandbox list after HTTP %s",
    async (status) => {
      server.current.sandboxes = [sandboxRow()];
      await mount();
      await screen.findByText("quiet-otter");
      server.current.errors.list = [Object.assign(new Error("denied"), { status })];
      await act(async () => {
        await client.refetchQueries({ queryKey: ["sandboxes", "list"] });
      });
      await screen.findByText(enDashboard.list.loadFailed);
      expect(screen.queryByText("quiet-otter")).toBeNull();
    },
  );

  it("retains real list rows with a retry after a transient failure", async () => {
    server.current.sandboxes = [sandboxRow()];
    await mount();
    await screen.findByText("quiet-otter");
    server.current.errors.list = [new Error("offline")];
    await act(async () => {
      await client.refetchQueries({ queryKey: ["sandboxes", "list"] });
    });
    await screen.findByText(enDashboard.list.loadFailed);
    expect(screen.getByText("quiet-otter")).toBeTruthy();
  });

  it("es-MX: the empty and error copy are localized", async () => {
    await mount("es-MX");
    expect(await screen.findByText(esSandboxes.onboarding.title)).toBeTruthy();
    cleanup();
    server.current.errors.list = [new Error("network")];
    await mount("es-MX");
    expect(await screen.findByText(esDashboard.list.loadFailed)).toBeTruthy();
  });

  it("shows state, host, template, labels, expiry and a link to the sandbox's page", async () => {
    server.current.sandboxes = [
      sandboxRow({
        metadata: { team: "infra", tier: "2" },
        template: { id: "tpl-old", slug: "old", label: "Old image", retiredAt: new Date() },
        leaseExpireAction: "DESTROY",
      }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const card = row("sbx-1");
    // The name is the card's heading; the id stays beneath it.
    expect(within(card).getByRole("heading").textContent).toBe("quiet-otter");
    expect(card.dataset.sandboxState).toBe("READY");
    expect(within(card).getByText(enSandboxes.state.READY)).toBeTruthy();
    expect(card.querySelector("[data-sandbox-host]")?.textContent).toBe(
      `Alpha (alpha) · ${enHosts.status.ready}`,
    );
    expect(card.querySelector("[data-sandbox-template]")?.textContent).toBe("Old image (archived)");
    expect(within(card).getByText("team=infra")).toBeTruthy();
    expect(within(card).getByText("tier=2")).toBeTruthy();
    expect(within(card).getByText(/then destroy$/)).toBeTruthy();
    const open = within(card).getByRole("link", { name: "Open sandbox sbx-1" });
    expect(open.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/sbx-1");
  });

  it("badges a stored disk (disk offload) and never a disk only on its host", async () => {
    const stored = {
      location: "host_and_store",
      offloadState: "stored",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: 1024,
      eligibility: "any_host",
      offloadPin: "ANY",
      offloadPolicy: { mode: "on_stop" },
      offloadDueAt: null,
    };
    server.current.sandboxes = [
      sandboxRow({ id: "sbx-1", state: "STOPPED", disk: stored }),
      sandboxRow({ id: "sbx-2" }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const badge = row("sbx-1").querySelector<HTMLElement>("[data-disk-location]");
    expect(badge?.dataset.diskLocation).toBe("host_and_store");
    expect(badge?.textContent).toBe(enSandboxes.disk.location.host_and_store);
    expect(row("sbx-2").querySelector("[data-disk-location]")).toBeNull();
  });

  it("a stopped sandbox has no running lifetime, as on its detail page", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPED", leaseExpiresAt: new Date(Date.now() + 24 * 3_600_000) }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const lifetime = row("sbx-1").querySelector<HTMLElement>("[data-sandbox-lifetime]");
    expect(lifetime?.textContent).toBe(enSandboxes.lifetime.stopped);
    expect(row("sbx-1").textContent).not.toMatch(/then stop/);
  });

  it("a lease from READY shows its pending start, not the provisioning backstop", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "PROVISIONING",
        leasePendingReady: true,
        leaseExpiresAt: new Date(Date.now() + 2 * 3_600_000 + 5 * 60_000),
      }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const card = row("sbx-1");
    expect(within(card).getByText(enSandboxes.lifetime.startsAtReady)).toBeTruthy();
    expect(card.textContent).not.toMatch(/in 2 hours/);
  });

  it("queued, unknown-outcome and offline-host states stay visible", async () => {
    const receipt = (id: string, kind: string, state: string) => ({
      id,
      kind,
      state,
      errorCode: null,
      createdAt: new Date(),
      completedAt: null,
    });
    server.current.sandboxes = [
      sandboxRow({
        id: "sbx-q",
        state: "REQUESTED",
        lastLifecycleOperation: receipt("op-q", "CREATE_SANDBOX", "QUEUED"),
        host: fakeHost({
          status: "DISCONNECTED",
          lastConnectedAt: new Date(Date.now() - 3_600_000),
        }),
      }),
      sandboxRow({
        id: "sbx-u",
        lastLifecycleOperation: receipt("op-u", "STOP_SANDBOX", "UNKNOWN_OUTCOME"),
        host: fakeHost({ lastHeartbeatAt: new Date(Date.now() - 5 * 60_000) }),
      }),
    ];
    await mount();
    await screen.findByText("sbx-q");
    const queued = row("sbx-q");
    expect(queued.dataset.sandboxState).toBe("REQUESTED");
    expect(within(queued).getByText(/Create: Queued/)).toBeTruthy();
    expect(queued.querySelector("[data-host-offline]")?.textContent).toContain(
      enHosts.status.offline,
    );
    const unknown = row("sbx-u");
    // A stale heartbeat is offline, never ready, even though the row says READY.
    expect(unknown.querySelector("[data-host-offline]")?.textContent).toContain(
      enHosts.status.stale,
    );
    expect(unknown.querySelector('[data-receipt-state="UNKNOWN_OUTCOME"]')?.textContent).toContain(
      "Stop: Outcome unknown",
    );
  });

  it("the Deleted filter asks the server for deleted sandboxes and offers no lifecycle action", async () => {
    server.current.sandboxes = [sandboxRow(), sandboxRow({ id: "sbx-gone", state: "DELETED" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    expect(screen.queryByText("sbx-gone")).toBeNull();
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText("sbx-gone")).toBeTruthy();
    expect(calls("list").at(-1)?.input).toMatchObject({ status: "deleted" });
    expect(within(row("sbx-gone")).queryByRole("button")).toBeNull();
  });
});

describe("name filter, quiet receipts and row Start/Stop (design review #13)", () => {
  const receipt = (kind: string, state: string) => ({
    id: `op-${kind}-${state}`,
    kind,
    state,
    errorCode: null,
    createdAt: new Date(),
    completedAt: state === "SUCCEEDED" ? new Date() : null,
  });

  it("filters by a part of the name on the server, keeps it in the search, and clears back", async () => {
    server.current.sandboxes = [
      sandboxRow(),
      sandboxRow({ id: "nightly-runner" }),
      sandboxRow({ id: "agent-scratch" }),
    ];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const input = screen.getByRole("searchbox", { name: enSandboxes.filter.name });
    await user.type(input, " Nightly");
    await vi.waitFor(() =>
      expect(calls("list").at(-1)?.input).toMatchObject({
        status: "active",
        nameContains: "nightly",
      }),
    );
    expect(await screen.findByText("nightly-runner")).toBeTruthy();
    expect(screen.queryByText("quiet-otter")).toBeNull();
    expect(lastSearch).toEqual({ status: "active", name: "nightly" });
    // The status switch keeps the name.
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.all }));
    expect(lastSearch).toEqual({ status: "all", name: "nightly" });
    // No match says so and offers the way back.
    await user.clear(input);
    await user.type(input, "zebra");
    const none = await screen.findByText(
      enSandboxes.empty.noMatchTitle.replace("{{name}}", "zebra"),
    );
    expect(none).toBeTruthy();
    await user.click(screen.getByRole("button", { name: enSandboxes.empty.clearFilter }));
    expect(await screen.findByText("quiet-otter")).toBeTruthy();
    expect((input as HTMLInputElement).value).toBe("");
    expect(lastSearch).toEqual({ status: "all", name: undefined });
  });

  it("a character no name has explains the alphabet and asks the server nothing", async () => {
    server.current.sandboxes = [sandboxRow()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const before = calls("list").length;
    const input = screen.getByRole("searchbox", { name: enSandboxes.filter.name });
    await user.type(input, "otter_1");
    expect(await screen.findByText(enSandboxes.filter.nameHint)).toBeTruthy();
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.querySelector("[data-sandbox-no-match]")).not.toBeNull();
    expect(calls("list").filter((call) => "nameContains" in (call.input as object))).toHaveLength(
      0,
    );
    expect(calls("list").length).toBe(before);
    expect(lastSearch?.name).toBeUndefined();
  });

  it("a finished request is not repeated on every card; one in flight or failed still shows", async () => {
    server.current.sandboxes = [
      sandboxRow({
        id: "sbx-done",
        state: "STOPPED",
        lastLifecycleOperation: receipt("STOP_SANDBOX", "SUCCEEDED"),
      }),
      sandboxRow({
        id: "sbx-run",
        state: "STOPPING",
        lastLifecycleOperation: receipt("STOP_SANDBOX", "RUNNING"),
      }),
      sandboxRow({
        id: "sbx-fail",
        lastLifecycleOperation: receipt("RECONNECT_SANDBOX", "FAILED"),
      }),
    ];
    await mount();
    await screen.findByText("sbx-done");
    expect(row("sbx-done").querySelector("[data-receipt-state]")).toBeNull();
    expect(row("sbx-done").textContent).not.toContain("Stop: Done");
    expect(row("sbx-run").querySelector('[data-receipt-state="RUNNING"]')).not.toBeNull();
    expect(row("sbx-fail").querySelector('[data-receipt-state="FAILED"]')).not.toBeNull();
  });

  it("Stop beside Open asks first, names the sandbox, and sends the detail page's stop", async () => {
    server.current.sandboxes = [sandboxRow()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const stop = within(row("sbx-1")).getByRole("button", { name: "Stop quiet-otter" });
    expect(stop.dataset.quickAction).toBe("stop");
    await user.click(stop);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("Stop quiet-otter?")).toBeTruthy();
    expect(calls("getSandbox")[0]?.input).toEqual({ id: "sbx-1" });
    expect(calls("stopSandbox")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.stop.confirm }));
    await vi.waitFor(() => expect(calls("stopSandbox")).toHaveLength(1));
    expect(calls("stopSandbox")[0]?.input).toMatchObject({ id: "sbx-1" });
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.stop.done);
  });

  it("Cancel sends nothing; Start on a stopped sandbox opens the lifetime dialog", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" }), sandboxRow({ id: "sbx-2" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const start = within(row("sbx-1")).getByRole("button", { name: "Start quiet-otter" });
    expect(start.textContent).toBe(enSandboxes.start.action);
    await user.click(start);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Start quiet-otter again?")).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: enCommon.actions.cancel }));
    expect(calls("reconnectSandbox")).toHaveLength(0);
    // Reopening reads the full view again first (its lease facts may have moved).
    await user.click(within(row("sbx-1")).getByRole("button", { name: "Start quiet-otter" }));
    await screen.findByRole("dialog");
    expect(calls("getSandbox")).toHaveLength(2);
  });

  it("Back/Forward to another ?name= updates the box and the server filter; its own writes do not reset typing", async () => {
    server.current.sandboxes = [sandboxRow(), sandboxRow({ id: "nightly-runner" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const input = screen.getByRole<HTMLInputElement>("searchbox", {
      name: enSandboxes.filter.name,
    });
    // A character no name has keeps what was typed (the URL drops it).
    await user.type(input, "Otter_");
    expect(input.value).toBe("Otter_");
    expect(lastSearch?.name).toBeUndefined();
    // History brings back another filter.
    act(() => setSearchFromUrl({ status: "active", name: "nightly" }));
    expect(input.value).toBe("nightly");
    await vi.waitFor(() =>
      expect(calls("list").at(-1)?.input).toMatchObject({ nameContains: "nightly" }),
    );
    expect(await screen.findByText("nightly-runner")).toBeTruthy();
    expect(screen.queryByText("quiet-otter")).toBeNull();
    act(() => setSearchFromUrl({ status: "active" }));
    expect(input.value).toBe("");
    expect(await screen.findByText("quiet-otter")).toBeTruthy();
  });

  it("Start keeps the remembered lifetime by default; a committed start whose response was lost is replayed with the same key and body", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" }), sandboxRow({ id: "sbx-2" })];
    server.current.lostResponses.reconnectSandbox = 1;
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const startOnce = async () => {
      await user.click(
        await within(row("sbx-1")).findByRole("button", { name: "Start quiet-otter" }),
      );
      const dialog = await screen.findByRole("dialog");
      // Keep: the remembered 5 minutes, sent as no lifetime at all.
      expect(within(dialog).getByLabelText(enSandboxes.lifetime.field).textContent).toContain(
        "5 minutes",
      );
      await user.click(within(dialog).getByRole("button", { name: enSandboxes.start.confirm }));
    };
    await startOnce();
    await vi.waitFor(() =>
      expect(row("sbx-1").querySelector("[data-action-problem]")?.textContent).toBe(
        enSandboxes.problem.generic,
      ),
    );
    // The server queued it; the host's answer is unknown: Start is offered again.
    Object.assign(server.current.sandboxes[0]!, { state: "STOPPED", generation: 2 });
    Object.assign(server.current.sandboxes[0]!.lastLifecycleOperation as object, {
      state: "UNKNOWN_OUTCOME",
    });
    await act(() => client.invalidateQueries());
    await startOnce();
    await vi.waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(2));
    const [lost, retried] = calls("reconnectSandbox").map(
      (call) => call.input as { id: string; mode: string; idempotencyKey: string },
    );
    expect(lost).toMatchObject({ id: "sbx-1", mode: "cold" });
    expect(lost).not.toHaveProperty("timeoutMs");
    expect(lost?.idempotencyKey).toBeTruthy();
    expect(retried).toEqual(lost);
    expect(server.current.operations.filter((op) => op.kind === "RECONNECT_SANDBOX")).toHaveLength(
      1,
    );
  });

  it("Start with a chosen lifetime sends it; the dialog reads the remembered lifetime fresh each time", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const start = () => within(row("sbx-1")).getByRole("button", { name: "Start quiet-otter" });
    await user.click(start());
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText(enSandboxes.lifetime.field).textContent).toContain(
      "5 minutes",
    );
    await user.click(within(dialog).getByRole("button", { name: enCommon.actions.cancel }));
    // Renewed elsewhere since: the next Start shows the new remembered lifetime.
    Object.assign(server.current.sandboxes[0]!, { rememberedLeaseTimeoutMs: 4 * 3_600_000 });
    await user.click(start());
    dialog = await screen.findByRole("dialog");
    const field = within(dialog).getByLabelText(enSandboxes.lifetime.field);
    expect(field.textContent).toContain("4 hours");
    await selectOption(user, field, /^1 hour$/);
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.start.confirm }));
    await vi.waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
    expect(calls("reconnectSandbox")[0]?.input).toMatchObject({
      id: "sbx-1",
      mode: "cold",
      timeoutMs: 3_600_000,
    });
  });

  it("a failed re-read offers a retry and opens nothing until a read succeeds", async () => {
    server.current.sandboxes = [sandboxRow()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    const stop = () => within(row("sbx-1")).getByRole("button", { name: "Stop quiet-otter" });
    await user.click(stop());
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enCommon.actions.cancel,
      }),
    );
    server.current.errors.getSandbox = [new Error("network")];
    await user.click(stop());
    const retry = await within(row("sbx-1")).findByRole("button", {
      name: enCommon.actions.tryAgain,
    });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await user.click(retry);
    await vi.waitFor(() =>
      expect(row("sbx-1").querySelector("[data-quick-action-problem]")).toBeNull(),
    );
    await user.click(stop());
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(calls("stopSandbox")).toHaveLength(0);
  });

  it("Restore sends a cold start of the stored sandbox: Keep sends no lifetime, a chosen one its value", async () => {
    server.current.sandboxes = [
      sandboxRow({ id: "sbx-store", state: "OFFLOADED", sandboxHostId: null, host: null }),
      sandboxRow({ id: "sbx-store2", state: "OFFLOADED", sandboxHostId: null, host: null }),
    ];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("sbx-store");
    await user.click(within(row("sbx-store")).getByRole("button", { name: "Restore sbx-store" }));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Restore sbx-store?")).toBeTruthy();
    expect(within(dialog).getByText(enSandboxes.start.restoreDescription)).toBeTruthy();
    await user.click(
      within(dialog).getByRole("button", { name: enSandboxes.start.restoreConfirm }),
    );
    await vi.waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
    expect(calls("reconnectSandbox")[0]?.input).toMatchObject({ id: "sbx-store", mode: "cold" });
    expect(calls("reconnectSandbox")[0]?.input).not.toHaveProperty("timeoutMs");
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.start.restoreDone);
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(within(row("sbx-store2")).getByRole("button", { name: "Restore sbx-store2" }));
    dialog = await screen.findByRole("dialog");
    await selectOption(user, within(dialog).getByLabelText(enSandboxes.lifetime.field), /^1 hour$/);
    await user.click(
      within(dialog).getByRole("button", { name: enSandboxes.start.restoreConfirm }),
    );
    await vi.waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(2));
    expect(calls("reconnectSandbox")[1]?.input).toMatchObject({
      id: "sbx-store2",
      mode: "cold",
      timeoutMs: 3_600_000,
    });
  });

  it("the first click never opens on a cached full view: it waits for a fresh read, and a failed one opens nothing", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" }), sandboxRow({ id: "sbx-2" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    // The detail page was visited earlier: its view (5 minutes remembered) is cached.
    await act(() =>
      client.fetchQuery(orpc.sandboxes.getSandbox.queryOptions({ input: { id: "sbx-1" } })),
    );
    await act(() =>
      client.fetchQuery(orpc.sandboxes.getSandbox.queryOptions({ input: { id: "sbx-2" } })),
    );
    Object.assign(server.current.sandboxes[0]!, { rememberedLeaseTimeoutMs: 4 * 3_600_000 });
    await user.click(within(row("sbx-1")).getByRole("button", { name: "Start quiet-otter" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText(enSandboxes.lifetime.field).textContent).toContain(
      "4 hours",
    );
    await user.click(within(dialog).getByRole("button", { name: enCommon.actions.cancel }));
    // A failed fresh read: the cached view opens nothing.
    server.current.errors.getSandbox = [new Error("network")];
    await user.click(within(row("sbx-2")).getByRole("button", { name: "Stop sbx-2" }));
    expect(await within(row("sbx-2")).findByText(enSandboxes.detail.loadFailed)).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // Trying again reads fresh and opens it.
    await user.click(within(row("sbx-2")).getByRole("button", { name: "Stop sbx-2" }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(calls("stopSandbox")).toHaveLength(0);
  });

  it("the polled row decides the button, not an older full view", async () => {
    server.current.sandboxes = [sandboxRow()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    await user.click(within(row("sbx-1")).getByRole("button", { name: "Stop quiet-otter" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enSandboxes.stop.confirm,
      }),
    );
    await vi.waitFor(() => expect(calls("stopSandbox")).toHaveLength(1));
    // The host finishes the stop; only the list is read again.
    Object.assign(server.current.sandboxes[0]!, { state: "STOPPED", lastLifecycleOperation: null });
    const reads = calls("getSandbox").length;
    await act(() => client.invalidateQueries({ queryKey: ["sandboxes", "list"] }));
    const start = await within(row("sbx-1")).findByRole("button", { name: "Start quiet-otter" });
    // The row alone decided that: no full-view read yet.
    expect(calls("getSandbox").length).toBe(reads);
    await user.click(start);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Start quiet-otter again?")).toBeTruthy();
    // Opening it read the full view once, fresh.
    expect(calls("getSandbox").length).toBe(reads + 1);
  });

  it("a sandbox that is gone or no longer ours shows no row controls", async () => {
    server.current.sandboxes = [sandboxRow()];
    server.current.errors.getSandbox = [NOT_FOUND()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    await user.click(within(row("sbx-1")).getByRole("button", { name: "Stop quiet-otter" }));
    await vi.waitFor(() => expect(row("sbx-1").querySelector("[data-quick-action]")).toBeNull());
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(calls("stopSandbox")).toHaveLength(0);
  });

  it("offers Restore for a stored disk, nothing while a start is in flight, nothing for deleted", async () => {
    server.current.sandboxes = [
      sandboxRow({ id: "sbx-store", state: "OFFLOADED", sandboxHostId: null, host: null }),
      sandboxRow({
        id: "sbx-starting",
        state: "STOPPED",
        lastLifecycleOperation: receipt("RECONNECT_SANDBOX", "RUNNING"),
      }),
      sandboxRow({ id: "sbx-gone", state: "DELETED" }),
    ];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("sbx-store");
    expect(
      within(row("sbx-store")).getByRole("button", { name: "Restore sbx-store" }).textContent,
    ).toBe(enSandboxes.start.restoreAction);
    expect(row("sbx-starting").querySelector("[data-quick-action]")).toBeNull();
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.all }));
    await screen.findByText("sbx-gone");
    expect(row("sbx-gone").querySelector("[data-quick-action]")).toBeNull();
  });

  it("a refused stop shows the server's reason on the row", async () => {
    server.current.sandboxes = [sandboxRow()];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    // The sandbox stopped elsewhere between the list read and the click.
    server.current.errors.stopSandbox = [coded("sandbox.state_conflict")];
    await user.click(within(row("sbx-1")).getByRole("button", { name: "Stop quiet-otter" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.stop.confirm }));
    const problem = await vi.waitFor(() => {
      const found = row("sbx-1").querySelector<HTMLElement>("[data-action-problem]");
      if (!found) throw new Error("no problem");
      return found;
    });
    expect(problem.getAttribute("role")).toBe("alert");
    expect(problem.dataset.actionProblem).toBe("stateChanged");
    expect(problem.textContent).toBe(enSandboxes.problem.stateChanged);
  });
});

describe("create entries", () => {
  it("the header's Create sandbox opens the Create page (no dialog)", async () => {
    server.current.sandboxes = [sandboxRow()];
    await mount();
    await screen.findByText("quiet-otter");
    const create = screen.getByRole("link", { name: enSandboxes.create.action });
    expect(create.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/new");
    expect(create.className).toMatch(/h-11|min-h-\[44px\]/);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("the checklist's Create your first sandbox links to the Create page once ready", async () => {
    server.current.hosts = [fakeHost()];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const cta = await screen.findByRole("link", { name: enSandboxes.onboarding.sandbox.action });
    expect(cta.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/new");
  });

  it("the last step waits on the earlier ones, saying so, with no dead button", async () => {
    server.current.hosts = [];
    server.current.pools = [];
    server.current.templates = [fakeTemplate()];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    expect(within(step("sandbox")).getByText(enSandboxes.onboarding.sandbox.waiting)).toBeTruthy();
    expect(screen.queryByRole("link", { name: enSandboxes.onboarding.sandbox.action })).toBeNull();
    expect(
      screen.queryByRole("button", { name: enSandboxes.onboarding.sandbox.action }),
    ).toBeNull();
  });
});
